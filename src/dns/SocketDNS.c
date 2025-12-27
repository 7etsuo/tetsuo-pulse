/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDNS.c
 * @ingroup dns
 * @brief Asynchronous DNS resolution implementation.
 *
 * Public API implementation for the DNS resolver module.
 * Contains validation functions, resolver lifecycle management,
 * and async resolution coordination.
 *
 * @see SocketDNS-internal.c for internal implementation details.
 * @see SocketDNS.h for public API declarations.
 * @see SocketDNS-private.h for internal structures.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include "core/Arena.h"
#include "dns/SocketDNS-private.h"
#include "dns/SocketDNS.h"
#include "socket/SocketCommon-private.h"

#undef T
#define T SocketDNS_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS"

const Except_T SocketDNS_Failed
    = { &SocketDNS_Failed, "SocketDNS operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketDNS);

void
validate_resolve_params (const char *host, int port)
{
  if (host != NULL)
    {
      if (!socketcommon_is_ip_address (host))
        {
          SocketCommon_validate_hostname (host, SocketDNS_Failed);
        }
    }

  SocketCommon_validate_port (port, SocketDNS_Failed);
}

static int
validate_request_ownership_locked (const struct SocketDNS_T *dns,
                                   const struct SocketDNS_Request_T *req)
{
  return req->dns_resolver == dns;
}

#define VALIDATE_OWNERSHIP_OR_RETURN(dns, req, retval)                        \
  do                                                                          \
    {                                                                         \
      if (!validate_request_ownership_locked ((dns), (req)))                  \
        {                                                                     \
          pthread_mutex_unlock (&(dns)->mutex);                               \
          return retval;                                                      \
        }                                                                     \
    }                                                                         \
  while (0)

static void
cancel_pending_state (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  cancel_pending_request (dns, req);
  req->error = dns_cancellation_error ();
}

static void
cancel_processing_state (struct SocketDNS_T *dns,
                         struct SocketDNS_Request_T *req)
{
  (void)dns;
  req->state = REQ_CANCELLED;
  req->error = dns_cancellation_error ();
}

static void
cancel_complete_state (struct SocketDNS_Request_T *req)
{
  if (req->result && !req->callback)
    {
      SocketCommon_free_addrinfo (req->result);
      req->result = NULL;
    }
  req->error = dns_cancellation_error ();
}

static void
handle_cancel_by_state (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req, int *send_signal,
                        int *cancelled)
{
  switch (req->state)
    {
    case REQ_PENDING:
      cancel_pending_state (dns, req);
      *send_signal = 1;
      *cancelled = 1;
      break;

    case REQ_PROCESSING:
      cancel_processing_state (dns, req);
      *send_signal = 1;
      *cancelled = 1;
      break;

    case REQ_COMPLETE:
      cancel_complete_state (req);
      break;

    case REQ_CANCELLED:
      if (req->error == 0)
        req->error = dns_cancellation_error ();
      break;
    }
}

static struct addrinfo *
transfer_result_ownership (struct SocketDNS_Request_T *req)
{
  struct addrinfo *result = NULL;

  if (req->state == REQ_COMPLETE)
    {
      if (!req->callback)
        {
          result = req->result;
          req->result = NULL;
        }

      hash_table_remove (req->dns_resolver, req);
    }

  return result;
}

static void
init_completed_request_fields (struct SocketDNS_Request_T *req,
                               struct SocketDNS_T *dns,
                               struct addrinfo *result, int port)
{
  req->dns_resolver = dns;
  req->host = NULL;
  req->port = port;
  req->callback = NULL;
  req->callback_data = NULL;
  req->state = REQ_COMPLETE;
  req->result = SocketCommon_copy_addrinfo (result);
  if (!req->result)
    {
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "Failed to copy address info");
    }
  SocketCommon_free_addrinfo (result);
  req->error = 0;
  req->queue_next = NULL;
  req->hash_next = NULL;
  req->submit_time_ms = Socket_get_monotonic_ms ();
  req->timeout_override_ms = -1;
}

static int wait_for_completion (struct SocketDNS_T *dns,
                                const struct SocketDNS_Request_T *req,
                                int timeout_ms);

static void handle_sync_timeout (struct SocketDNS_T *dns,
                                 struct SocketDNS_Request_T *req,
                                 int timeout_ms, const char *host);

static void handle_sync_error (struct SocketDNS_T *dns,
                               struct SocketDNS_Request_T *req, int error,
                               const char *host);

static struct addrinfo *
dns_sync_fast_path (const char *host, int port, const struct addrinfo *hints)
{
  struct addrinfo *tmp_res;
  int family = hints ? hints->ai_family : AF_UNSPEC;

  SocketCommon_resolve_address (host, port, hints, &tmp_res, SocketDNS_Failed,
                                family, 1);

  struct addrinfo *result = SocketCommon_copy_addrinfo (tmp_res);
  SocketCommon_free_addrinfo (tmp_res);

  return result;
}

static struct addrinfo *
wait_and_retrieve_result (struct SocketDNS_T *dns,
                          struct SocketDNS_Request_T *req, int timeout_ms,
                          const char *host)
{
  int error;
  struct addrinfo *result;

  pthread_mutex_lock (&dns->mutex);

  if (wait_for_completion (dns, req, timeout_ms) == ETIMEDOUT)
    handle_sync_timeout (dns, req, timeout_ms, host);

  error = req->error;
  if (error != 0)
    handle_sync_error (dns, req, error, host);

  result = req->result;
  req->result = NULL;
  hash_table_remove (dns, req);
  pthread_mutex_unlock (&dns->mutex);

  return result;
}

T
SocketDNS_new (void)
{
  struct SocketDNS_T *dns;

  dns = allocate_dns_resolver ();
  initialize_dns_fields (dns);
  initialize_dns_components (dns);
  start_dns_workers (dns);

  return dns;
}
void
SocketDNS_free (T *dns)
{
  T d;

  if (!dns || !*dns)
    return;

  d = *dns;

  shutdown_workers (d);
  drain_completion_pipe (d);
  reset_dns_state (d);
  destroy_dns_resources (d);
  *dns = NULL;
}

static void
validate_dns_instance (const struct SocketDNS_T *dns)
{
  if (!dns)
    {
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "Invalid NULL dns resolver");
    }
}

static void
check_queue_capacity (struct SocketDNS_T *dns)
{
  pthread_mutex_lock (&dns->mutex);

  if (check_queue_limit (dns))
    {
      size_t max_pending = dns->max_pending;
      pthread_mutex_unlock (&dns->mutex);
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "DNS request queue full (max %zu pending)",
                        max_pending);
    }

  pthread_mutex_unlock (&dns->mutex);
}

static Request_T
prepare_resolve_request (struct SocketDNS_T *dns, const char *host, int port,
                         SocketDNS_Callback callback, void *data)
{
  size_t host_len = host ? strlen (host) : 0;
  validate_resolve_params (host, port);
  return allocate_request (dns, host, host_len, port, callback, data);
}

static void
submit_resolve_request (struct SocketDNS_T *dns, Request_T req)
{
  pthread_mutex_lock (&dns->mutex);
  submit_dns_request (dns, req);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_SUBMITTED, 1);
  pthread_mutex_unlock (&dns->mutex);
}
Request_T
SocketDNS_resolve (struct SocketDNS_T *dns, const char *host, int port,
                   SocketDNS_Callback callback, void *data)
{
  validate_dns_instance (dns);

  /* Check queue capacity BEFORE allocation to prevent arena memory leak.
   * If queue is full, we raise exception without allocating. */
  check_queue_capacity (dns);

  Request_T req = prepare_resolve_request (dns, host, port, callback, data);
  submit_resolve_request (dns, req);
  return req;
}

void
SocketDNS_cancel (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  int send_signal = 0;
  int cancelled = 0;

  if (!dns || !req)
    return;

  pthread_mutex_lock (&dns->mutex);
  VALIDATE_OWNERSHIP_OR_RETURN (dns, req, );

  handle_cancel_by_state (dns, req, &send_signal, &cancelled);

  if (send_signal)
    SIGNAL_DNS_COMPLETION (dns);

  hash_table_remove (dns, req);

  if (cancelled)
    SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_CANCELLED, 1);

  pthread_mutex_unlock (&dns->mutex);
}

size_t
SocketDNS_getmaxpending (struct SocketDNS_T *dns)
{
  if (!dns)
    return 0;

  return DNS_LOCKED_SIZE_GETTER (dns, max_pending);
}

void
SocketDNS_setmaxpending (struct SocketDNS_T *dns, size_t max_pending)
{
  size_t queue_depth;

  if (!dns)
    {
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "Invalid NULL dns resolver");
    }

  pthread_mutex_lock (&dns->mutex);
  queue_depth = dns->queue_size;
  if (max_pending < queue_depth)
    {
      pthread_mutex_unlock (&dns->mutex);
      SOCKET_RAISE_MSG (
          SocketDNS, SocketDNS_Failed,
          "Cannot set max pending (%zu) below current queue depth (%zu)",
          max_pending, queue_depth);
    }

  dns->max_pending = max_pending;
  pthread_mutex_unlock (&dns->mutex);
}

int
SocketDNS_gettimeout (struct SocketDNS_T *dns)
{
  if (!dns)
    return 0;

  return DNS_LOCKED_INT_GETTER (dns, request_timeout_ms);
}

void
SocketDNS_settimeout (struct SocketDNS_T *dns, int timeout_ms)
{
  if (!dns)
    return;

  DNS_LOCKED_INT_SETTER (dns, request_timeout_ms,
                         SANITIZE_TIMEOUT_MS (timeout_ms));
}

int
SocketDNS_pollfd (struct SocketDNS_T *dns)
{
  if (!dns)
    return -1;
  return dns->pipefd[0];
}

int
SocketDNS_check (struct SocketDNS_T *dns)
{
  char buffer[SOCKET_DNS_PIPE_BUFFER_SIZE];
  ssize_t n;
  int count = 0;

  if (!dns)
    return 0;

  if (dns->pipefd[0] < 0)
    return 0;

  while ((n = read (dns->pipefd[0], buffer, sizeof (buffer))) > 0)
    count += n;

  if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    return count;

  return count;
}

struct addrinfo *
SocketDNS_getresult (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  struct addrinfo *result = NULL;

  if (!dns || !req)
    return NULL;

  pthread_mutex_lock (&dns->mutex);
  VALIDATE_OWNERSHIP_OR_RETURN (dns, req, NULL);

  result = transfer_result_ownership (req);
  pthread_mutex_unlock (&dns->mutex);

  return result;
}

int
SocketDNS_geterror (struct SocketDNS_T *dns,
                    const struct SocketDNS_Request_T *req)
{
  int error = 0;

  if (!dns || !req)
    return 0;

  pthread_mutex_lock (&dns->mutex);
  VALIDATE_OWNERSHIP_OR_RETURN (dns, req, 0);

  if (req->state == REQ_COMPLETE || req->state == REQ_CANCELLED)
    error = req->error;
  pthread_mutex_unlock (&dns->mutex);

  return error;
}

Request_T
SocketDNS_create_completed_request (struct SocketDNS_T *dns,
                                    struct addrinfo *result, int port)
{
  if (!dns || !result)
    {
      SOCKET_RAISE_MSG (
          SocketDNS, SocketDNS_Failed,
          "Invalid NULL dns or result in create_completed_request");
    }

  Request_T req = allocate_request_structure (dns);
  init_completed_request_fields (req, dns, result, port);

  pthread_mutex_lock (&dns->mutex);
  hash_table_insert (dns, req);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_COMPLETED, 1);
  SIGNAL_DNS_COMPLETION (dns);
  pthread_mutex_unlock (&dns->mutex);

  return req;
}

void
SocketDNS_request_settimeout (struct SocketDNS_T *dns,
                              struct SocketDNS_Request_T *req, int timeout_ms)
{
  if (!dns || !req)
    return;

  pthread_mutex_lock (&dns->mutex);
  VALIDATE_OWNERSHIP_OR_RETURN (dns, req, );

  if (req->state == REQ_PENDING || req->state == REQ_PROCESSING)
    req->timeout_override_ms = SANITIZE_TIMEOUT_MS (timeout_ms);
  pthread_mutex_unlock (&dns->mutex);
}

static void
compute_deadline (int timeout_ms, struct timespec *deadline)
{
  struct timespec timeout;
  clock_gettime (CLOCK_MONOTONIC, deadline);
  socket_util_ms_to_timespec (timeout_ms, &timeout);
  deadline->tv_sec += timeout.tv_sec;
  deadline->tv_nsec += timeout.tv_nsec;

  if (deadline->tv_nsec >= SOCKET_NS_PER_SECOND)
    {
      deadline->tv_sec++;
      deadline->tv_nsec -= SOCKET_NS_PER_SECOND;
    }
}

static int
wait_for_completion (struct SocketDNS_T *dns,
                     const struct SocketDNS_Request_T *req, int timeout_ms)
{
  struct timespec deadline;

  if (timeout_ms > 0)
    compute_deadline (timeout_ms, &deadline);

  while (req->state != REQ_COMPLETE && req->state != REQ_CANCELLED)
    {
      if (timeout_ms > 0)
        {
          int rc = pthread_cond_timedwait (&dns->result_cond, &dns->mutex,
                                           &deadline);
          if (rc == ETIMEDOUT)
            return ETIMEDOUT;
        }
      else
        {
          pthread_cond_wait (&dns->result_cond, &dns->mutex);
        }
    }

  return 0;
}

static void
handle_sync_timeout (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req,
                     int timeout_ms, const char *host)
{
  req->state = REQ_CANCELLED;
  req->error = EAI_AGAIN;
  hash_table_remove (dns, req);
  pthread_mutex_unlock (&dns->mutex);

  SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                    "DNS resolution timed out after %d ms: %s", timeout_ms,
                    host ? host : "(wildcard)");
}

static void
handle_sync_error (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req,
                   int error, const char *host)
{
  hash_table_remove (dns, req);
  pthread_mutex_unlock (&dns->mutex);

  SOCKET_RAISE_FMT (SocketDNS, SocketDNS_Failed,
                    "DNS resolution failed: %s (%s)",
                    host ? host : "(wildcard)", gai_strerror (error));
}

static struct addrinfo *
resolve_async_with_wait (struct SocketDNS_T *dns, const char *host, int port,
                         int timeout_ms)
{
  Request_T req;

  req = SocketDNS_resolve (dns, host, port, NULL, NULL);

  if (timeout_ms > 0)
    SocketDNS_request_settimeout (dns, req, timeout_ms);

  return wait_and_retrieve_result (dns, req, timeout_ms, host);
}

struct addrinfo *
SocketDNS_resolve_sync (struct SocketDNS_T *dns, const char *host, int port,
                        const struct addrinfo *hints, int timeout_ms)
{
  int effective_timeout;

  if (!dns)
    {
      SOCKET_RAISE_MSG (
          SocketDNS, SocketDNS_Failed,
          "SocketDNS_resolve_sync requires non-NULL dns resolver");
    }

  effective_timeout = (timeout_ms > 0) ? timeout_ms : dns->request_timeout_ms;

  if (host == NULL || socketcommon_is_ip_address (host))
    return dns_sync_fast_path (host, port, hints);

  return resolve_async_with_wait (dns, host, port, effective_timeout);
}

static unsigned
cache_hash_function (const char *hostname)
{
  return socket_util_hash_djb2_ci (hostname, SOCKET_DNS_CACHE_HASH_SIZE);
}

static int
cache_entry_expired (const struct SocketDNS_T *dns,
                     const struct SocketDNS_CacheEntry *entry)
{
  int64_t now_ms;
  int64_t age_ms;

  if (dns->cache_ttl_seconds <= 0)
    return 0;

  now_ms = Socket_get_monotonic_ms ();
  age_ms = now_ms - entry->insert_time_ms;

  return age_ms >= (int64_t)dns->cache_ttl_seconds * SOCKET_MS_PER_SECOND;
}

static void
cache_lru_remove (struct SocketDNS_T *dns, struct SocketDNS_CacheEntry *entry)
{
  if (entry->lru_prev)
    entry->lru_prev->lru_next = entry->lru_next;
  else
    dns->cache_lru_head = entry->lru_next;

  if (entry->lru_next)
    entry->lru_next->lru_prev = entry->lru_prev;
  else
    dns->cache_lru_tail = entry->lru_prev;

  entry->lru_prev = NULL;
  entry->lru_next = NULL;
}

static void
cache_lru_insert_front (struct SocketDNS_T *dns,
                        struct SocketDNS_CacheEntry *entry)
{
  entry->lru_prev = NULL;
  entry->lru_next = dns->cache_lru_head;

  if (dns->cache_lru_head)
    dns->cache_lru_head->lru_prev = entry;
  else
    dns->cache_lru_tail = entry;

  dns->cache_lru_head = entry;
}

static void
cache_entry_free (struct SocketDNS_CacheEntry *entry)
{
  if (entry)
    {
      if (entry->result)
        SocketCommon_free_addrinfo (entry->result);
    }
}

static void
cache_hash_remove (struct SocketDNS_T *dns, struct SocketDNS_CacheEntry *entry)
{
  unsigned hash = cache_hash_function (entry->hostname);
  struct SocketDNS_CacheEntry **pp = &dns->cache_hash[hash];

  while (*pp)
    {
      if (*pp == entry)
        {
          *pp = entry->hash_next;
          return;
        }
      pp = &(*pp)->hash_next;
    }
}

static void
cache_remove_entry (struct SocketDNS_T *dns,
                    struct SocketDNS_CacheEntry *entry)
{
  cache_lru_remove (dns, entry);
  cache_hash_remove (dns, entry);
  cache_entry_free (entry);
  dns->cache_size--;
}

static void
cache_evict_oldest (struct SocketDNS_T *dns)
{
  struct SocketDNS_CacheEntry *oldest = dns->cache_lru_tail;

  if (!oldest)
    return;

  cache_remove_entry (dns, oldest);
  dns->cache_evictions++;
}

struct SocketDNS_CacheEntry *
cache_lookup (struct SocketDNS_T *dns, const char *hostname)
{
  unsigned hash;
  struct SocketDNS_CacheEntry *entry;

  if (dns->cache_max_entries == 0)
    return NULL;

  hash = cache_hash_function (hostname);
  entry = dns->cache_hash[hash];

  while (entry)
    {
      if (strcasecmp (entry->hostname, hostname) == 0)
        {
          if (cache_entry_expired (dns, entry))
            {
              cache_remove_entry (dns, entry);
              dns->cache_evictions++;
              dns->cache_misses++; /* Expired entry counts as miss */
              return NULL;
            }

          entry->last_access_ms = Socket_get_monotonic_ms ();
          cache_lru_remove (dns, entry);
          cache_lru_insert_front (dns, entry);
          dns->cache_hits++;
          return entry;
        }
      entry = entry->hash_next;
    }

  dns->cache_misses++;
  return NULL;
}

static struct SocketDNS_CacheEntry *
cache_allocate_entry (struct SocketDNS_T *dns, const char *hostname,
                      struct addrinfo *result)
{
  struct SocketDNS_CacheEntry *entry;
  int64_t now_ms;

  entry = ALLOC (dns->arena, sizeof (*entry));
  if (!entry)
    return NULL;

  entry->hostname = socket_util_arena_strdup (dns->arena, hostname);
  if (!entry->hostname)
    return NULL;

  entry->result = SocketCommon_copy_addrinfo (result);
  if (!entry->result)
    return NULL;

  now_ms = Socket_get_monotonic_ms ();
  entry->insert_time_ms = now_ms;
  entry->last_access_ms = now_ms;
  entry->hash_next = NULL;
  entry->lru_prev = NULL;
  entry->lru_next = NULL;

  return entry;
}

void
cache_insert (struct SocketDNS_T *dns, const char *hostname,
              struct addrinfo *result)
{
  struct SocketDNS_CacheEntry *entry;
  unsigned hash;

  if (dns->cache_max_entries == 0 || !result)
    return;

  while (dns->cache_size >= dns->cache_max_entries)
    cache_evict_oldest (dns);

  entry = cache_allocate_entry (dns, hostname, result);
  if (!entry)
    return;

  hash = cache_hash_function (hostname);
  entry->hash_next = dns->cache_hash[hash];
  dns->cache_hash[hash] = entry;

  cache_lru_insert_front (dns, entry);

  dns->cache_size++;
  dns->cache_insertions++;
}

void
cache_clear_locked (struct SocketDNS_T *dns)
{
  size_t i;

  if (dns->cache_size == 0)
    return;

  for (i = 0; i < SOCKET_DNS_CACHE_HASH_SIZE; i++)
    {
      struct SocketDNS_CacheEntry *entry = dns->cache_hash[i];
      while (entry)
        {
          struct SocketDNS_CacheEntry *next = entry->hash_next;
          cache_entry_free (entry);
          entry = next;
        }
      dns->cache_hash[i] = NULL;
    }

  dns->cache_lru_head = NULL;
  dns->cache_lru_tail = NULL;
  dns->cache_size = 0;
}

void
SocketDNS_cache_clear (T dns)
{
  assert (dns);

  pthread_mutex_lock (&dns->mutex);
  cache_clear_locked (dns);
  pthread_mutex_unlock (&dns->mutex);
}

int
SocketDNS_cache_remove (T dns, const char *hostname)
{
  unsigned hash;
  struct SocketDNS_CacheEntry *entry;
  int found = 0;

  assert (dns);
  assert (hostname);

  pthread_mutex_lock (&dns->mutex);

  hash = cache_hash_function (hostname);
  entry = dns->cache_hash[hash];

  while (entry)
    {
      if (strcasecmp (entry->hostname, hostname) == 0)
        {
          cache_remove_entry (dns, entry);
          found = 1;
          break;
        }
      entry = entry->hash_next;
    }

  pthread_mutex_unlock (&dns->mutex);
  return found;
}

void
SocketDNS_cache_set_ttl (T dns, int ttl_seconds)
{
  assert (dns);

  pthread_mutex_lock (&dns->mutex);
  dns->cache_ttl_seconds = ttl_seconds >= 0 ? ttl_seconds : 0;
  pthread_mutex_unlock (&dns->mutex);
}

void
SocketDNS_cache_set_max_entries (T dns, size_t max_entries)
{
  assert (dns);

  pthread_mutex_lock (&dns->mutex);

  dns->cache_max_entries = max_entries;

  if (max_entries == 0)
    {
      cache_clear_locked (dns);
    }
  else
    {
      while (dns->cache_size > max_entries)
        cache_evict_oldest (dns);
    }

  pthread_mutex_unlock (&dns->mutex);
}

void
SocketDNS_cache_stats (T dns, SocketDNS_CacheStats *stats)
{
  uint64_t total;

  assert (dns);
  assert (stats);

  pthread_mutex_lock (&dns->mutex);

  stats->hits = dns->cache_hits;
  stats->misses = dns->cache_misses;
  stats->evictions = dns->cache_evictions;
  stats->insertions = dns->cache_insertions;
  stats->current_size = dns->cache_size;
  stats->max_entries = dns->cache_max_entries;
  stats->ttl_seconds = dns->cache_ttl_seconds;

  total = stats->hits + stats->misses;
  stats->hit_rate = (total > 0) ? (double)stats->hits / (double)total : 0.0;

  pthread_mutex_unlock (&dns->mutex);
}

void
SocketDNS_prefer_ipv6 (T dns, int prefer_ipv6)
{
  assert (dns);

  DNS_LOCKED_INT_SETTER (dns, prefer_ipv6, prefer_ipv6 ? 1 : 0);
}

int
SocketDNS_get_prefer_ipv6 (T dns)
{
  assert (dns);

  return DNS_LOCKED_INT_GETTER (dns, prefer_ipv6);
}

static int
validate_ip_address (const char *ip)
{
  struct in_addr addr4;
  struct in6_addr addr6;

  if (!ip || !*ip)
    return 0;

  if (inet_pton (AF_INET, ip, &addr4) == 1)
    return 1;

  if (inet_pton (AF_INET6, ip, &addr6) == 1)
    return 1;

  return 0;
}

static int
copy_string_array_to_arena (struct SocketDNS_T *dns, const char **src,
                            size_t count, char ***dest_array,
                            size_t *dest_count)
{
  size_t i;

  *dest_array = ALLOC (dns->arena, count * sizeof (char *));
  if (!*dest_array)
    return -1;

  for (i = 0; i < count; i++)
    {
      size_t len = strlen (src[i]);
      (*dest_array)[i] = ALLOC (dns->arena, len + 1);
      if (!(*dest_array)[i])
        {
          *dest_array = NULL;
          *dest_count = 0;
          return -1;
        }
      memcpy ((*dest_array)[i], src[i], len + 1);
    }

  *dest_count = count;
  return 0;
}

int
SocketDNS_set_nameservers (T dns, const char **servers, size_t count)
{
  int result;
  size_t i;

  assert (dns);

  if (servers != NULL && count > 0)
    {
      for (i = 0; i < count; i++)
        {
          if (!validate_ip_address (servers[i]))
            {
              SOCKET_LOG_WARN_MSG ("Invalid nameserver IP address: %s",
                                   servers[i] ? servers[i] : "(null)");
              return -1;
            }
        }
    }

  pthread_mutex_lock (&dns->mutex);

  dns->custom_nameservers = NULL;
  dns->nameserver_count = 0;

  if (servers == NULL || count == 0)
    {
      pthread_mutex_unlock (&dns->mutex);
      return 0;
    }

  result = copy_string_array_to_arena (
      dns, servers, count, &dns->custom_nameservers, &dns->nameserver_count);
  pthread_mutex_unlock (&dns->mutex);

  if (result < 0)
    return -1;

#ifdef __linux__
  return 0;
#else
  SOCKET_LOG_WARN_MSG (
      "Custom nameservers configured but not applied (platform limitation)");
  return -1;
#endif
}

int
SocketDNS_set_search_domains (T dns, const char **domains, size_t count)
{
  int result;

  assert (dns);

  pthread_mutex_lock (&dns->mutex);

  dns->search_domains = NULL;
  dns->search_domain_count = 0;

  if (domains == NULL || count == 0)
    {
      pthread_mutex_unlock (&dns->mutex);
      return 0;
    }

  result = copy_string_array_to_arena (
      dns, domains, count, &dns->search_domains, &dns->search_domain_count);
  pthread_mutex_unlock (&dns->mutex);

  if (result < 0)
    return -1;

  SOCKET_LOG_WARN_MSG (
      "Custom search domains configured but not applied (platform limitation)");
  return -1;
}

#undef T
#undef Request_T
