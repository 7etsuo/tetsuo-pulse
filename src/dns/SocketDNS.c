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
 * @see SocketDNS.h for public API declarations.
 * @see SocketDNS-private.h for internal structures.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/SocketMetrics.h"
#include "dns/SocketDNS-private.h"
#include "dns/SocketDNS.h"
#include "dns/SocketDNSResolver.h"
#include "socket/SocketCommon-private.h"

#undef T
#define T SocketDNS_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS"

const Except_T SocketDNS_Failed
    = { &SocketDNS_Failed, "SocketDNS operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketDNS);

/* Forward declarations for migrated functions */
static void cleanup_on_init_failure (struct SocketDNS_T *dns,
                                     enum DnsCleanupLevel cleanup_level);
static void cleanup_pipe (struct SocketDNS_T *dns);

/* Initialization/Cleanup Helper Macro */
#define INIT_PTHREAD_PRIMITIVE(dns, init_func, ptr, cleanup_level, error_msg) \
  do                                                                          \
    {                                                                         \
      if (init_func ((ptr), NULL) != 0)                                       \
        {                                                                     \
          cleanup_on_init_failure ((dns), (cleanup_level));                   \
          SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed, (error_msg));        \
        }                                                                     \
    }                                                                         \
  while (0)

/* Initialization Functions */

static T
allocate_dns_resolver (void)
{
  struct SocketDNS_T *dns;

  dns = calloc (1, sizeof (*dns));
  if (!dns)
    {
      SOCKET_RAISE_MSG (SocketDNS,
                        SocketDNS_Failed,
                        SOCKET_ENOMEM ": Cannot allocate DNS resolver");
    }

  return dns;
}

static void
initialize_dns_fields (struct SocketDNS_T *dns)
{
  /* num_workers removed - no worker threads in new architecture */
  dns->max_pending = SOCKET_DNS_MAX_PENDING;
  dns->pending_count = 0;
  dns->request_timeout_ms = SOCKET_DEFAULT_DNS_TIMEOUT_MS;

  dns->cache_max_entries = SOCKET_DNS_DEFAULT_CACHE_MAX_ENTRIES;
  dns->cache_ttl_seconds = SOCKET_DNS_DEFAULT_CACHE_TTL_SECONDS;

  dns->prefer_ipv6 = 1;

  /* Initialize resolver fields to NULL (Phase 2.2) */
  dns->resolver = NULL;
  dns->resolver_arena = NULL;
}

static void
initialize_mutex (struct SocketDNS_T *dns)
{
  INIT_PTHREAD_PRIMITIVE (dns,
                          pthread_mutex_init,
                          &dns->mutex,
                          DNS_CLEAN_NONE,
                          "Failed to initialize DNS resolver mutex");
}

static void
initialize_queue_condition (struct SocketDNS_T *dns)
{
  /* TODO(Phase 2.x): Removed - no queue condition needed without worker threads
   */
  (void)dns;
}

static void
initialize_result_condition (struct SocketDNS_T *dns)
{
  /* TODO(Phase 2.x): Removed - no result condition needed without worker
   * threads */
  (void)dns;
}

static void
initialize_synchronization (struct SocketDNS_T *dns)
{
  initialize_mutex (dns);
  initialize_queue_condition (dns);
  initialize_result_condition (dns);
}

static void
create_completion_pipe (struct SocketDNS_T *dns)
{
  if (pipe (dns->pipefd) < 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_MUTEX);
      SOCKET_RAISE_FMT (
          SocketDNS, SocketDNS_Failed, "Failed to create completion pipe");
    }

  if (SocketCommon_setcloexec (dns->pipefd[0], 1) < 0
      || SocketCommon_setcloexec (dns->pipefd[1], 1) < 0)
    {
      int saved_errno = errno;
      cleanup_pipe (dns);
      cleanup_on_init_failure (dns, DNS_CLEAN_MUTEX);
      errno = saved_errno;
      SOCKET_RAISE_FMT (SocketDNS,
                        SocketDNS_Failed,
                        "Failed to set close-on-exec flag on pipe");
    }
}

static void
set_pipe_nonblocking (struct SocketDNS_T *dns)
{
  int flags = fcntl (dns->pipefd[0], F_GETFL);
  if (flags < 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_ARENA);
      SOCKET_RAISE_FMT (
          SocketDNS, SocketDNS_Failed, "Failed to get pipe flags");
    }

  if (fcntl (dns->pipefd[0], F_SETFL, flags | O_NONBLOCK) < 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_ARENA);
      SOCKET_RAISE_FMT (
          SocketDNS, SocketDNS_Failed, "Failed to set pipe to non-blocking");
    }
}

static void
initialize_pipe (struct SocketDNS_T *dns)
{
  create_completion_pipe (dns);
  set_pipe_nonblocking (dns);
}

static void
initialize_dns_components (struct SocketDNS_T *dns)
{
  dns->arena = Arena_new ();
  if (!dns->arena)
    {
      free (dns);
      SOCKET_RAISE_MSG (SocketDNS,
                        SocketDNS_Failed,
                        SOCKET_ENOMEM ": Cannot allocate DNS resolver arena");
    }

  initialize_synchronization (dns);
  initialize_pipe (dns);

  /* Initialize SocketDNSResolver backend (Phase 2.2) */
  dns->resolver_arena = Arena_new ();
  if (!dns->resolver_arena)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_PIPE);
      SOCKET_RAISE_MSG (SocketDNS,
                        SocketDNS_Failed,
                        SOCKET_ENOMEM ": Cannot allocate resolver arena");
    }

  TRY
  {
    dns->resolver = SocketDNSResolver_new (dns->resolver_arena);
    SocketDNSResolver_load_resolv_conf (dns->resolver);
  }
  EXCEPT (SocketDNSResolver_Failed)
  {
    Arena_dispose (&dns->resolver_arena);
    cleanup_on_init_failure (dns, DNS_CLEAN_PIPE);
    RERAISE;
  }
  END_TRY;
}

/* Cleanup Functions */

static void
cleanup_pipe (struct SocketDNS_T *dns)
{
  for (int i = 0; i < 2; i++)
    {
      SAFE_CLOSE (dns->pipefd[i]);
      dns->pipefd[i] = -1;
    }
}

static void
cleanup_mutex_cond (struct SocketDNS_T *dns)
{
  /* condition variables removed - only destroy mutex */
  pthread_mutex_destroy (&dns->mutex);
}

static void
cleanup_on_init_failure (struct SocketDNS_T *dns,
                         enum DnsCleanupLevel cleanup_level)
{
  if (cleanup_level >= DNS_CLEAN_ARENA)
    Arena_dispose (&dns->arena);
  if (cleanup_level >= DNS_CLEAN_PIPE)
    cleanup_pipe (dns);
  if (cleanup_level >= DNS_CLEAN_MUTEX)
    {
      pthread_mutex_destroy (&dns->mutex);
    }
  free (dns);
}

static void
drain_completion_pipe (struct SocketDNS_T *dns)
{
  char buffer[SOCKET_DNS_PIPE_BUFFER_SIZE];
  ssize_t n;

  if (dns->pipefd[0] < 0)
    return;

  do
    {
      n = read (dns->pipefd[0], buffer, sizeof (buffer));
    }
  while (n > 0);
}

static void
reset_dns_state (T d)
{
  pthread_mutex_lock (&d->mutex);
  free_all_requests (d);
  cache_clear_locked (d); /* Free cache entries' malloc'd addrinfo results */
  /* queue fields removed - no queue in new architecture */
  for (int i = 0; i < SOCKET_DNS_REQUEST_HASH_SIZE; i++)
    {
      d->request_hash[i] = NULL;
    }
  pthread_mutex_unlock (&d->mutex);
}

static void
destroy_dns_resources (T d)
{
  cleanup_pipe (d);
  cleanup_mutex_cond (d);

  /* Free resolver backend - must call _free before Arena_dispose
   * so it can clean up transport sockets which have their own arenas */
  if (d->resolver)
    {
      SocketDNSResolver_free (&d->resolver);
    }
  if (d->resolver_arena)
    {
      Arena_dispose (&d->resolver_arena);
    }

  Arena_dispose (&d->arena);
  free (d);
}

/* Request Management Functions */

static void
secure_clear_memory (void *ptr, size_t len)
{
  if (!ptr || len == 0)
    return;

#ifdef __linux__
  explicit_bzero (ptr, len);
#else
  volatile unsigned char *vptr = (volatile unsigned char *)ptr;
  while (len--)
    *vptr++ = 0;
#endif
}

static void
free_request_list_results (Request_T head, size_t next_offset)
{
  Request_T curr = head;

  while (curr)
    {
      Request_T next = *(Request_T *)((char *)curr + next_offset);

      if (curr->host)
        {
          secure_clear_memory (curr->host, strlen (curr->host));
        }

      if (curr->result)
        {
          SocketCommon_free_addrinfo (curr->result);
          curr->result = NULL;
        }
      curr = next;
    }
}

void
free_all_requests (T d)
{
  /* No queue_head anymore - only free hash table requests */
  for (int i = 0; i < SOCKET_DNS_REQUEST_HASH_SIZE; i++)
    free_request_list_results (
        d->request_hash[i], offsetof (struct SocketDNS_Request_T, hash_next));
}

Request_T
allocate_request_structure (struct SocketDNS_T *dns)
{
  Request_T req;

  req = ALLOC (dns->arena, sizeof (*req));
  if (!req)
    {
      SOCKET_RAISE_MSG (SocketDNS,
                        SocketDNS_Failed,
                        SOCKET_ENOMEM ": Cannot allocate DNS request");
    }

  return req;
}

void
allocate_request_hostname (struct SocketDNS_T *dns,
                           struct SocketDNS_Request_T *req,
                           const char *host,
                           size_t host_len)
{
  if (host == NULL)
    {
      req->host = NULL;
      return;
    }

  /* Check for overflow: host_len == SIZE_MAX would cause host_len + 1 to wrap
   * to 0 */
  if (host_len >= SIZE_MAX || host_len > SOCKET_DNS_MAX_HOSTNAME_LEN)
    {
      SOCKET_RAISE_MSG (
          SocketDNS,
          SocketDNS_Failed,
          "Hostname length overflow or exceeds DNS maximum (255)");
    }

  req->host = ALLOC (dns->arena, host_len + 1);
  if (!req->host)
    {
      SOCKET_RAISE_MSG (SocketDNS,
                        SocketDNS_Failed,
                        SOCKET_ENOMEM ": Cannot allocate hostname");
    }

  memcpy (req->host, host, host_len);
  req->host[host_len] = '\0';
}

void
initialize_request_fields (struct SocketDNS_Request_T *req,
                           int port,
                           SocketDNS_Callback callback,
                           void *data)
{
  req->port = port;
  req->callback = callback;
  req->callback_data = data;
  req->state = REQ_PENDING;
  req->result = NULL;
  req->error = 0;
  req->queue_next = NULL;
  req->hash_next = NULL;
  req->submit_time_ms = Socket_get_monotonic_ms ();
  req->timeout_override_ms = -1;
}

Request_T
allocate_request (struct SocketDNS_T *dns,
                  const char *host,
                  size_t host_len,
                  int port,
                  SocketDNS_Callback callback,
                  void *data)
{
  Request_T req = allocate_request_structure (dns);
  allocate_request_hostname (dns, req, host, host_len);
  initialize_request_fields (req, port, callback, data);
  req->dns_resolver = dns;

  return req;
}

/* Forward declarations for cache coherence functions */
static struct SocketDNS_CacheEntry *
cache_lookup_l1_only (struct SocketDNS_T *dns, const char *hostname);
static struct SocketDNS_CacheEntry *
cache_lookup_coherent (struct SocketDNS_T *dns, const char *hostname);
static struct SocketDNS_CacheEntry *
cache_validate_ttl_coherent (struct SocketDNS_T *dns,
                             const char *hostname,
                             struct SocketDNS_CacheEntry *l1_entry);
static void cache_update_both_tiers (struct SocketDNS_T *dns,
                                     const char *hostname,
                                     const SocketDNSResolver_Address *addresses,
                                     size_t count,
                                     uint32_t min_ttl);
static int cache_promote_l2_to_l1 (struct SocketDNS_T *dns,
                                   const char *hostname,
                                   const SocketDNSResolver_Result *l2_result);

/* Hash table operations for request tracking */
static unsigned
request_hash_function (const struct SocketDNS_Request_T *req)
{
  return socket_util_hash_ptr (req, SOCKET_DNS_REQUEST_HASH_SIZE);
}

void
hash_table_insert (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  unsigned hash;

  hash = request_hash_function (req);
  req->hash_value = hash;
  req->hash_next = dns->request_hash[hash];
  dns->request_hash[hash] = req;

  /* Track pending count for new requests */
  dns->pending_count++;
}

void
hash_table_remove (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  unsigned hash;
  Request_T *pp;
  int found = 0;

  hash = req->hash_value;

  if (hash >= SOCKET_DNS_REQUEST_HASH_SIZE)
    {
      SOCKET_LOG_DEBUG_MSG (
          "Invalid hash_value=%u for req=%p in hash_table_remove", hash, req);
      return;
    }

  pp = &dns->request_hash[hash];
  while (*pp)
    {
      if (*pp == req)
        {
          *pp = req->hash_next;
          found = 1;
          break;
        }
      pp = &(*pp)->hash_next;
    }

  /* Decrement pending count if request was actually found and removed */
  if (found && dns->pending_count > 0)
    {
      dns->pending_count--;
    }
}

/* Utility Functions */

void
signal_completion (struct SocketDNS_T *dns)
{
  char byte = COMPLETION_SIGNAL_BYTE;
  ssize_t n;

  n = write (dns->pipefd[1], &byte, 1);
  (void)n;
}

/**
 * @brief Invoke user callback with proper mutex handling.
 * @ingroup dns
 *
 * Handles the callback invocation pattern:
 * 1. Save callback pointer and user data
 * 2. Transfer result ownership to callback
 * 3. Unlock mutex before callback (avoid deadlock)
 * 4. Invoke callback
 * 5. Lock mutex, remove request from hash table, unlock
 *
 * @param dns DNS resolver instance (mutex must be held on entry)
 * @param req Request with callback to invoke
 * @param result Result to pass to callback (ownership transferred)
 * @param error Error code to pass to callback
 * @note Mutex is unlocked on exit
 */
static void
invoke_user_callback (struct SocketDNS_T *dns,
                      struct SocketDNS_Request_T *req,
                      struct addrinfo *result,
                      int error)
{
  SocketDNS_Callback user_cb = req->callback;
  void *user_data = req->callback_data;

  req->result = NULL; /* Transfer ownership to callback */

  pthread_mutex_unlock (&dns->mutex);

  /* Invoke callback outside mutex to avoid deadlock */
  user_cb (req, result, error, user_data);

  pthread_mutex_lock (&dns->mutex);
  hash_table_remove (dns, req);
  pthread_mutex_unlock (&dns->mutex);
}

void
cancel_pending_request (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req)
{
  /* No queue_remove - queue removed */
  hash_table_remove (dns, req);
  req->state = REQ_CANCELLED;
}

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

#define VALIDATE_OWNERSHIP_OR_RETURN(dns, req, retval)       \
  do                                                         \
    {                                                        \
      if (!validate_request_ownership_locked ((dns), (req))) \
        {                                                    \
          pthread_mutex_unlock (&(dns)->mutex);              \
          return retval;                                     \
        }                                                    \
    }                                                        \
  while (0)

static void
cancel_pending_state (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  cancel_pending_request (dns, req);
  req->error = DNS_CANCELLATION_ERROR;
}

static void
cancel_processing_state (struct SocketDNS_T *dns,
                         struct SocketDNS_Request_T *req)
{
  (void)dns;
  req->state = REQ_CANCELLED;
  req->error = DNS_CANCELLATION_ERROR;
}

static void
cancel_complete_state (struct SocketDNS_Request_T *req)
{
  if (req->result && !req->callback)
    {
      SocketCommon_free_addrinfo (req->result);
      req->result = NULL;
    }
  req->error = DNS_CANCELLATION_ERROR;
}

static void
handle_cancel_by_state (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req,
                        int *send_signal,
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
        req->error = DNS_CANCELLATION_ERROR;
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
                               struct addrinfo *result,
                               int port)
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
      SOCKET_RAISE_MSG (
          SocketDNS, SocketDNS_Failed, "Failed to copy address info");
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
                                 int timeout_ms,
                                 const char *host);

static void handle_sync_error (struct SocketDNS_T *dns,
                               struct SocketDNS_Request_T *req,
                               int error,
                               const char *host);

static struct addrinfo *
dns_sync_fast_path (const char *host, int port, const struct addrinfo *hints)
{
  struct addrinfo *tmp_res;
  int family = hints ? hints->ai_family : AF_UNSPEC;

  SocketCommon_resolve_address (
      host, port, hints, &tmp_res, SocketDNS_Failed, family, 1);

  struct addrinfo *result = SocketCommon_copy_addrinfo (tmp_res);
  SocketCommon_free_addrinfo (tmp_res);

  return result;
}

static struct addrinfo *
wait_and_retrieve_result (struct SocketDNS_T *dns,
                          struct SocketDNS_Request_T *req,
                          int timeout_ms,
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

  return dns;
}
void
SocketDNS_free (T *dns)
{
  T d;

  if (!dns || !*dns)
    return;

  d = *dns;

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
      SOCKET_RAISE_MSG (
          SocketDNS, SocketDNS_Failed, "Invalid NULL dns resolver");
    }
}

static size_t
count_pending_requests (const struct SocketDNS_T *dns)
{
  size_t count = 0;
  size_t i;

  for (i = 0; i < SOCKET_DNS_REQUEST_HASH_SIZE; i++)
    {
      const struct SocketDNS_Request_T *req = dns->request_hash[i];
      while (req)
        {
          if (req->state != REQ_COMPLETE && req->state != REQ_CANCELLED)
            {
              count++;
            }
          req = req->hash_next;
        }
    }

  return count;
}

static void
check_queue_capacity (struct SocketDNS_T *dns)
{
  size_t pending;

  pthread_mutex_lock (&dns->mutex);
  pending = count_pending_requests (dns);
  pthread_mutex_unlock (&dns->mutex);

  if (pending >= dns->max_pending)
    {
      SOCKET_RAISE_FMT (SocketDNS,
                        SocketDNS_Failed,
                        "DNS queue full: %zu pending requests (max %zu)",
                        pending,
                        dns->max_pending);
    }
}

static Request_T
prepare_resolve_request (struct SocketDNS_T *dns,
                         const char *host,
                         int port,
                         SocketDNS_Callback callback,
                         void *data)
{
  size_t host_len = host ? strlen (host) : 0;
  validate_resolve_params (host, port);
  return allocate_request (dns, host, host_len, port, callback, data);
}

/**
 * @brief Callback context for SocketDNSResolver to SocketDNS bridging.
 * @ingroup dns
 */
struct SocketDNS_ResolverContext
{
  struct SocketDNS_T *dns;
  struct SocketDNS_Request_T *req;
};

/**
 * @brief Convert SocketDNSResolver_Result to addrinfo.
 * @ingroup dns
 */
static struct addrinfo *
resolver_result_to_addrinfo (const SocketDNSResolver_Result *result, int port)
{
  struct addrinfo *head = NULL;
  struct addrinfo *tail = NULL;
  size_t i;

  if (!result || result->count == 0)
    return NULL;

  for (i = 0; i < result->count; i++)
    {
      struct addrinfo *ai = calloc (1, sizeof (*ai));
      if (!ai)
        {
          SocketCommon_free_addrinfo (head);
          return NULL;
        }

      ai->ai_family = result->addresses[i].family;
      ai->ai_socktype = SOCK_STREAM;
      ai->ai_protocol = IPPROTO_TCP;

      if (ai->ai_family == AF_INET)
        {
          struct sockaddr_in *sin = calloc (1, sizeof (*sin));
          if (!sin)
            {
              free (ai);
              SocketCommon_free_addrinfo (head);
              return NULL;
            }
          sin->sin_family = AF_INET;
          sin->sin_port = htons (port);
          sin->sin_addr = result->addresses[i].addr.v4;
          ai->ai_addr = (struct sockaddr *)sin;
          ai->ai_addrlen = sizeof (*sin);
        }
      else if (ai->ai_family == AF_INET6)
        {
          struct sockaddr_in6 *sin6 = calloc (1, sizeof (*sin6));
          if (!sin6)
            {
              free (ai);
              SocketCommon_free_addrinfo (head);
              return NULL;
            }
          sin6->sin6_family = AF_INET6;
          sin6->sin6_port = htons (port);
          sin6->sin6_addr = result->addresses[i].addr.v6;
          ai->ai_addr = (struct sockaddr *)sin6;
          ai->ai_addrlen = sizeof (*sin6);
        }
      else
        {
          free (ai);
          continue;
        }

      if (!head)
        head = ai;
      else
        tail->ai_next = ai;
      tail = ai;
      ai->ai_next = NULL;
    }

  return head;
}

/**
 * @brief Convert SocketDNSResolver error to getaddrinfo error.
 * @ingroup dns
 */
static int
resolver_error_to_gai (int resolver_error)
{
  switch (resolver_error)
    {
    case RESOLVER_OK:
      return 0;
    case RESOLVER_ERROR_TIMEOUT:
      return EAI_AGAIN;
    case RESOLVER_ERROR_CANCELLED:
#ifdef EAI_CANCELLED
      return EAI_CANCELLED;
#else
      return EAI_AGAIN;
#endif
    case RESOLVER_ERROR_NXDOMAIN:
      return EAI_NONAME;
    case RESOLVER_ERROR_SERVFAIL:
    case RESOLVER_ERROR_REFUSED:
      return EAI_FAIL;
    case RESOLVER_ERROR_NO_NS:
    case RESOLVER_ERROR_NETWORK:
      return EAI_AGAIN;
    case RESOLVER_ERROR_NOMEM:
      return EAI_MEMORY;
    default:
      return EAI_FAIL;
    }
}

/**
 * @brief SocketDNSResolver callback that bridges to SocketDNS.
 * @ingroup dns
 */
static void
socketdns_resolver_callback (SocketDNSResolver_Query_T query,
                             const SocketDNSResolver_Result *result,
                             int error,
                             void *userdata)
{
  struct SocketDNS_ResolverContext *ctx
      = (struct SocketDNS_ResolverContext *)userdata;
  struct SocketDNS_T *dns = ctx->dns;
  struct SocketDNS_Request_T *req = ctx->req;
  struct addrinfo *ai_result = NULL;
  int gai_error;

  (void)query;

  pthread_mutex_lock (&dns->mutex);

  /* Check if request was cancelled while resolver was working */
  if (req->state == REQ_CANCELLED)
    {
      pthread_mutex_unlock (&dns->mutex);
      return;
    }

  /* Convert resolver result to addrinfo */
  if (error == RESOLVER_OK && result)
    {
      ai_result = resolver_result_to_addrinfo (result, req->port);
      gai_error = ai_result ? 0 : EAI_MEMORY;

      /* Populate L1 cache on success */
      if (ai_result && req->host)
        cache_insert (dns, req->host, ai_result);
    }
  else
    {
      gai_error = resolver_error_to_gai (error);
    }

  /* Store result in request */
  req->result = ai_result;
  req->error = gai_error;
  req->state = REQ_COMPLETE;

  /* Signal completion for SocketPoll integration */
  SIGNAL_DNS_COMPLETION (dns);

  /* Invoke user callback if provided */
  if (req->callback)
    {
      invoke_user_callback (dns, req, req->result, gai_error);
    }
  else
    {
      /* Polling mode - leave result for user to retrieve */
      SocketMetrics_counter_inc (SOCKET_CTR_DNS_QUERIES_COMPLETED);
      pthread_mutex_unlock (&dns->mutex);
    }
}

/**
 * @brief Check L1 cache and return immediately if hit.
 * @ingroup dns
 * @return 1 if cache hit (request completed), 0 if cache miss.
 */
static int
check_l1_cache_and_complete (struct SocketDNS_T *dns, Request_T req)
{
  struct SocketDNS_CacheEntry *entry;

  if (!req->host)
    return 0; /* Wildcard bind - no cache */

  pthread_mutex_lock (&dns->mutex);
  entry = cache_lookup_coherent (dns, req->host);
  pthread_mutex_unlock (&dns->mutex);

  if (entry)
    {
      /* Cache hit - complete request immediately */
      pthread_mutex_lock (&dns->mutex);

      req->result = SocketCommon_copy_addrinfo (entry->result);
      req->error = req->result ? 0 : EAI_MEMORY;
      req->state = REQ_COMPLETE;

      hash_table_insert (dns, req);
      SIGNAL_DNS_COMPLETION (dns);

      if (req->callback)
        {
          invoke_user_callback (dns, req, req->result, req->error);
        }
      else
        {
          SocketMetrics_counter_inc (SOCKET_CTR_DNS_QUERIES_COMPLETED);
          pthread_mutex_unlock (&dns->mutex);
        }

      return 1;
    }

  return 0;
}

/**
 * @brief Submit request to SocketDNSResolver backend.
 * @ingroup dns
 */
static void
submit_to_resolver (struct SocketDNS_T *dns, Request_T req)
{
  struct SocketDNS_ResolverContext *ctx;
  int flags = RESOLVER_FLAG_BOTH;

  /* Allocate callback context on dns arena */
  ctx = ALLOC (dns->arena, sizeof (*ctx));
  if (!ctx)
    {
      pthread_mutex_lock (&dns->mutex);
      req->error = EAI_MEMORY;
      req->state = REQ_COMPLETE;
      hash_table_insert (dns, req);
      SIGNAL_DNS_COMPLETION (dns);
      pthread_mutex_unlock (&dns->mutex);
      return;
    }

  ctx->dns = dns;
  ctx->req = req;

  /* Set IPv4/IPv6 preference */
  pthread_mutex_lock (&dns->mutex);
  if (dns->prefer_ipv6)
    flags = RESOLVER_FLAG_IPV6 | RESOLVER_FLAG_IPV4;
  else
    flags = RESOLVER_FLAG_IPV4 | RESOLVER_FLAG_IPV6;
  pthread_mutex_unlock (&dns->mutex);

  /* Insert request into hash table before async resolution */
  pthread_mutex_lock (&dns->mutex);
  hash_table_insert (dns, req);
  req->state = REQ_PROCESSING;
  SocketMetrics_counter_inc (SOCKET_CTR_DNS_QUERIES_TOTAL);
  pthread_mutex_unlock (&dns->mutex);

  /* Submit to resolver backend */
  TRY
  {
    SocketDNSResolver_resolve (
        dns->resolver, req->host, flags, socketdns_resolver_callback, ctx);
  }
  EXCEPT (SocketDNSResolver_Failed)
  {
    /* Resolver submission failed */
    pthread_mutex_lock (&dns->mutex);
    req->error = EAI_FAIL;
    req->state = REQ_COMPLETE;
    SIGNAL_DNS_COMPLETION (dns);

    if (req->callback)
      {
        invoke_user_callback (dns, req, NULL, EAI_FAIL);
      }
    else
      {
        pthread_mutex_unlock (&dns->mutex);
      }
  }
  END_TRY;
}

Request_T
SocketDNS_resolve (struct SocketDNS_T *dns,
                   const char *host,
                   int port,
                   SocketDNS_Callback callback,
                   void *data)
{
  Request_T req;

  validate_dns_instance (dns);

  /* Check queue capacity BEFORE allocating the request.
   * This prevents allocating a request that would exceed the limit,
   * which would leak memory if the exception is raised after allocation. */
  check_queue_capacity (dns);

  /* Allocate and prepare request */
  req = prepare_resolve_request (dns, host, port, callback, data);

  /* Fast path: check L1 cache first */
  if (check_l1_cache_and_complete (dns, req))
    {
      /* Cache hit - request already completed */
      return req;
    }

  /* Cache miss: submit to SocketDNSResolver backend */
  submit_to_resolver (dns, req);

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
    SocketMetrics_counter_inc (SOCKET_CTR_DNS_QUERIES_CANCELLED);

  pthread_mutex_unlock (&dns->mutex);
}

size_t
SocketDNS_getmaxpending (struct SocketDNS_T *dns)
{
  if (!dns)
    return 0;

  return DNS_LOCKED_SIZE_GETTER (dns, max_pending);
}

size_t
SocketDNS_getpendingcount (struct SocketDNS_T *dns)
{
  if (!dns)
    return 0;

  return DNS_LOCKED_SIZE_GETTER (dns, pending_count);
}

void
SocketDNS_setmaxpending (struct SocketDNS_T *dns, size_t max_pending)
{
  if (!dns)
    {
      SOCKET_RAISE_MSG (
          SocketDNS, SocketDNS_Failed, "Invalid NULL dns resolver");
    }

  pthread_mutex_lock (&dns->mutex);

  /* Validate that new limit is not less than current pending count */
  if (max_pending < dns->pending_count)
    {
      size_t current_pending = dns->pending_count;
      pthread_mutex_unlock (&dns->mutex);
      SOCKET_RAISE_FMT (
          SocketDNS,
          SocketDNS_Failed,
          "Cannot set max_pending (%zu) below current pending count (%zu)",
          max_pending,
          current_pending);
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

  DNS_LOCKED_INT_SETTER (
      dns, request_timeout_ms, SANITIZE_TIMEOUT_MS (timeout_ms));
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

  /* Process SocketDNSResolver to drive async queries */
  if (dns->resolver)
    {
      SocketDNSResolver_process (dns->resolver, 0);
    }

  /* Drain completion pipe signals */
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
SocketDNS_geterror (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
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
                                    struct addrinfo *result,
                                    int port)
{
  if (!dns || !result)
    {
      SOCKET_RAISE_MSG (
          SocketDNS,
          SocketDNS_Failed,
          "Invalid NULL dns or result in create_completed_request");
    }

  Request_T req = allocate_request_structure (dns);
  init_completed_request_fields (req, dns, result, port);

  pthread_mutex_lock (&dns->mutex);
  hash_table_insert (dns, req);
  SocketMetrics_counter_inc (SOCKET_CTR_DNS_QUERIES_COMPLETED);
  SIGNAL_DNS_COMPLETION (dns);
  pthread_mutex_unlock (&dns->mutex);

  return req;
}

void
SocketDNS_request_settimeout (struct SocketDNS_T *dns,
                              struct SocketDNS_Request_T *req,
                              int timeout_ms)
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
  timeout = socket_util_ms_to_timespec ((unsigned long)timeout_ms);
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
                     const struct SocketDNS_Request_T *req,
                     int timeout_ms)
{
  struct timespec deadline;
  struct pollfd pfd;
  int elapsed_ms = 0;

  /* Compute absolute deadline for timeout */
  if (timeout_ms > 0)
    compute_deadline (timeout_ms, &deadline);

  /* Poll on completion pipe and process resolver until request completes */
  pfd.fd = dns->pipefd[0];
  pfd.events = POLLIN;

  while (1)
    {
      int poll_timeout;
      int poll_ret;
      struct timespec now;

      /* Check if request is complete */
      if (req->state == REQ_COMPLETE || req->state == REQ_CANCELLED)
        return 0;

      /* Calculate remaining timeout */
      if (timeout_ms > 0)
        {
          clock_gettime (CLOCK_MONOTONIC, &now);
          elapsed_ms
              = (int)((now.tv_sec - (deadline.tv_sec - timeout_ms / 1000))
                          * 1000
                      + (now.tv_nsec
                         - (deadline.tv_nsec - (timeout_ms % 1000) * 1000000))
                            / 1000000);

          if (elapsed_ms >= timeout_ms)
            return ETIMEDOUT;

          poll_timeout = timeout_ms - elapsed_ms;
        }
      else
        {
          poll_timeout = SOCKET_DNS_POLL_INTERVAL_MS;
        }

      /* Release mutex before blocking operations */
      pthread_mutex_unlock (&dns->mutex);

      /* Process resolver to drive async operations */
      if (dns->resolver)
        SocketDNSResolver_process (dns->resolver, 0);

      /* Wait for completion signal on pipe */
      poll_ret = poll (&pfd,
                       1,
                       poll_timeout < SOCKET_DNS_POLL_INTERVAL_MS
                           ? poll_timeout
                           : SOCKET_DNS_POLL_INTERVAL_MS);

      /* Reacquire mutex */
      pthread_mutex_lock (&dns->mutex);

      if (poll_ret < 0)
        {
          if (errno == EINTR)
            continue; /* Interrupted by signal, retry */
          return errno;
        }

      /* Drain pipe if data is available */
      if (poll_ret > 0 && (pfd.revents & POLLIN))
        {
          char buffer[SOCKET_DNS_PIPE_BUFFER_SIZE];
          while (read (dns->pipefd[0], buffer, sizeof (buffer)) > 0)
            ;
        }
    }

  return 0;
}

static void
handle_sync_timeout (struct SocketDNS_T *dns,
                     struct SocketDNS_Request_T *req,
                     int timeout_ms,
                     const char *host)
{
  req->state = REQ_CANCELLED;
  req->error = EAI_AGAIN;
  hash_table_remove (dns, req);
  pthread_mutex_unlock (&dns->mutex);

  SOCKET_RAISE_MSG (SocketDNS,
                    SocketDNS_Failed,
                    "DNS resolution timed out after %d ms: %s",
                    timeout_ms,
                    host ? host : "(wildcard)");
}

static void
handle_sync_error (struct SocketDNS_T *dns,
                   struct SocketDNS_Request_T *req,
                   int error,
                   const char *host)
{
  hash_table_remove (dns, req);
  pthread_mutex_unlock (&dns->mutex);

  SOCKET_RAISE_FMT (SocketDNS,
                    SocketDNS_Failed,
                    "DNS resolution failed: %s (%s)",
                    host ? host : "(wildcard)",
                    gai_strerror (error));
}

static struct addrinfo *
resolve_async_with_wait (struct SocketDNS_T *dns,
                         const char *host,
                         int port,
                         int timeout_ms)
{
  Request_T req;

  req = SocketDNS_resolve (dns, host, port, NULL, NULL);

  if (timeout_ms > 0)
    SocketDNS_request_settimeout (dns, req, timeout_ms);

  return wait_and_retrieve_result (dns, req, timeout_ms, host);
}

static struct addrinfo *
resolve_via_backend (struct SocketDNS_T *dns,
                     const char *host,
                     int port,
                     const struct addrinfo *hints,
                     int timeout_ms)
{
  SocketDNSResolver_Result result = { 0 };
  struct addrinfo *addrinfo_result;
  int flags = RESOLVER_FLAG_BOTH;
  int err;

  (void)hints;

  if (!dns->resolver)
    {
      SOCKET_RAISE_MSG (SocketDNS,
                        SocketDNS_Failed,
                        "SocketDNSResolver backend not initialized");
    }

  err = SocketDNSResolver_resolve_sync (
      dns->resolver, host, flags, timeout_ms, &result);

  if (err != RESOLVER_OK)
    {
      SOCKET_RAISE_MSG (SocketDNS,
                        SocketDNS_Failed,
                        "Backend resolution failed: %s",
                        SocketDNSResolver_strerror (err));
    }

  addrinfo_result = resolver_result_to_addrinfo (&result, port);
  SocketDNSResolver_result_free (&result);

  if (!addrinfo_result)
    {
      SOCKET_RAISE_MSG (SocketDNS,
                        SocketDNS_Failed,
                        "Failed to convert resolver result to addrinfo");
    }

  return addrinfo_result;
}

struct addrinfo *
SocketDNS_resolve_sync (struct SocketDNS_T *dns,
                        const char *host,
                        int port,
                        const struct addrinfo *hints,
                        int timeout_ms)
{
  struct SocketDNS_CacheEntry *cache_entry;
  struct addrinfo *result;
  int effective_timeout;

  if (!dns)
    {
      SOCKET_RAISE_MSG (
          SocketDNS,
          SocketDNS_Failed,
          "SocketDNS_resolve_sync requires non-NULL dns resolver");
    }

  effective_timeout = (timeout_ms > 0) ? timeout_ms : dns->request_timeout_ms;

  /* Fast path for IP addresses and NULL host (wildcard bind) */
  if (host == NULL || socketcommon_is_ip_address (host))
    return dns_sync_fast_path (host, port, hints);

  /* Check L1 cache first (with L2 coherence) */
  pthread_mutex_lock (&dns->mutex);
  cache_entry = cache_lookup_coherent (dns, host);
  if (cache_entry)
    {
      result = SocketCommon_copy_addrinfo (cache_entry->result);
      pthread_mutex_unlock (&dns->mutex);
      return result;
    }
  pthread_mutex_unlock (&dns->mutex);

  /* Cache miss: use SocketDNSResolver backend */
  result = resolve_via_backend (dns, host, port, hints, effective_timeout);

  /* Store result in L1 cache */
  pthread_mutex_lock (&dns->mutex);
  cache_insert (dns, host, result);
  pthread_mutex_unlock (&dns->mutex);

  return result;
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
cache_remove_entry (struct SocketDNS_T *dns, struct SocketDNS_CacheEntry *entry)
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

/**
 * @brief Promote L2 (SocketDNSResolver) cache entry to L1 (SocketDNS) cache.
 * @ingroup dns
 *
 * @param dns DNS resolver instance
 * @param hostname Hostname to promote
 * @param l2_result L2 cache result to copy to L1
 * @return 1 if promotion succeeded, 0 if promotion failed
 */
static int
cache_promote_l2_to_l1 (struct SocketDNS_T *dns,
                        const char *hostname,
                        const SocketDNSResolver_Result *l2_result)
{
  struct addrinfo *ai_result;

  if (!dns || !hostname || !l2_result || l2_result->count == 0)
    return 0;

  /* Convert SocketDNSResolver_Result to addrinfo for L1 cache */
  ai_result = resolver_result_to_addrinfo (l2_result, 0);
  if (!ai_result)
    return 0;

  /* Insert into L1 cache */
  cache_insert (dns, hostname, ai_result);
  SocketCommon_free_addrinfo (ai_result);

  return 1;
}

/**
 * @brief Coherent cache lookup checking L1 then L2.
 * @ingroup dns
 *
 * Implements cache coherence rule: L1 miss → check L2 → populate L1.
 *
 * @param dns DNS resolver instance
 * @param hostname Hostname to lookup
 * @return L1 cache entry (may be newly promoted from L2), or NULL if not cached
 */
static struct SocketDNS_CacheEntry *
cache_lookup_coherent (struct SocketDNS_T *dns, const char *hostname)
{
  struct SocketDNS_CacheEntry *l1_entry;
  SocketDNSResolver_Result l2_result = { 0 };
  int l2_err;

  if (dns->cache_max_entries == 0)
    return NULL;

  /* Check L1 cache first (L1-only, no recursion) */
  l1_entry = cache_lookup_l1_only (dns, hostname);
  if (l1_entry)
    return l1_entry; /* L1 hit */

  /* L1 miss - check L2 cache in SocketDNSResolver */
  if (!dns->resolver)
    return NULL;

  /* Query L2 cache directly (no resolution triggered) */
  l2_err = SocketDNSResolver_cache_lookup (dns->resolver, hostname, &l2_result);
  if (l2_err == RESOLVER_OK)
    {
      /* L2 hit - promote to L1 */
      cache_promote_l2_to_l1 (dns, hostname, &l2_result);
      SocketDNSResolver_result_free (&l2_result);

      /* Return newly promoted L1 entry */
      l1_entry = cache_lookup_l1_only (dns, hostname);
      return l1_entry;
    }

  /* L2 miss - both caches empty */
  return NULL;
}

/**
 * @brief Validate L1 TTL with L2 fallback on expiry.
 * @ingroup dns
 *
 * Implements cache coherence rule: L1 expiry → check L2 (may still be valid).
 *
 * @param dns DNS resolver instance
 * @param hostname Hostname to validate
 * @param l1_entry Existing L1 entry (may be expired)
 * @return Valid cache entry (L1 refreshed if needed), or NULL if both expired
 */
static struct SocketDNS_CacheEntry *
cache_validate_ttl_coherent (struct SocketDNS_T *dns,
                             const char *hostname,
                             struct SocketDNS_CacheEntry *l1_entry)
{
  SocketDNSResolver_Result l2_result = { 0 };
  int l2_err;

  /* If L1 entry is still valid, return it */
  if (!cache_entry_expired (dns, l1_entry))
    return l1_entry;

  /* L1 expired - check if L2 has fresher data with longer TTL */
  if (!dns->resolver)
    {
      cache_remove_entry (dns, l1_entry);
      dns->cache_evictions++;
      return NULL;
    }

  /* Query L2 cache directly */
  l2_err = SocketDNSResolver_cache_lookup (dns->resolver, hostname, &l2_result);
  if (l2_err == RESOLVER_OK)
    {
      /* L2 still valid - refresh L1 from L2 */
      cache_remove_entry (dns, l1_entry);
      cache_promote_l2_to_l1 (dns, hostname, &l2_result);
      SocketDNSResolver_result_free (&l2_result);

      /* Return refreshed L1 entry */
      return cache_lookup_l1_only (dns, hostname);
    }

  /* L2 also expired - remove from L1 */
  cache_remove_entry (dns, l1_entry);
  dns->cache_evictions++;

  return NULL;
}

/**
 * @brief Update both L1 and L2 caches atomically.
 * @ingroup dns
 *
 * Implements cache coherence rule: Resolution → update both L1 and L2.
 *
 * @param dns DNS resolver instance
 * @param hostname Hostname resolved
 * @param addresses Array of resolved addresses
 * @param count Number of addresses
 * @param min_ttl Minimum TTL from DNS response
 */
static void
cache_update_both_tiers (struct SocketDNS_T *dns,
                         const char *hostname,
                         const SocketDNSResolver_Address *addresses,
                         size_t count,
                         uint32_t min_ttl)
{
  struct addrinfo *ai_result;
  SocketDNSResolver_Result l2_result = { 0 };
  size_t i;

  if (!dns || !hostname || count == 0)
    return;

  /* Build temporary L2 result structure */
  l2_result.addresses = (SocketDNSResolver_Address *)addresses;
  l2_result.count = count;
  l2_result.min_ttl = min_ttl;

  /* Update L1 cache - convert to addrinfo first */
  ai_result = resolver_result_to_addrinfo (&l2_result, 0);
  if (ai_result)
    {
      cache_insert (dns, hostname, ai_result);
      SocketCommon_free_addrinfo (ai_result);
    }

  /* L2 cache is updated automatically by SocketDNSResolver during resolution */
  /* No explicit L2 insert needed - SocketDNSResolver_resolve already caches */
}

/**
 * @brief Internal L1-only cache lookup (no L2 coherence).
 * @ingroup dns
 *
 * @param dns DNS resolver instance
 * @param hostname Hostname to lookup
 * @return L1 cache entry or NULL if not found/expired
 */
static struct SocketDNS_CacheEntry *
cache_lookup_l1_only (struct SocketDNS_T *dns, const char *hostname)
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

struct SocketDNS_CacheEntry *
cache_lookup (struct SocketDNS_T *dns, const char *hostname)
{
  /* Default to coherent lookup for external callers */
  return cache_lookup_coherent (dns, hostname);
}

static struct SocketDNS_CacheEntry *
cache_allocate_entry (struct SocketDNS_T *dns,
                      const char *hostname,
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
cache_insert (struct SocketDNS_T *dns,
              const char *hostname,
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
copy_string_array_to_arena (struct SocketDNS_T *dns,
                            const char **src,
                            size_t count,
                            char ***dest_array,
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

/* Verify ABI stability of SocketDNS_CacheStats structure */
_Static_assert (sizeof (SocketDNS_CacheStats) == 64,
                "SocketDNS_CacheStats size changed - ABI break");
_Static_assert (offsetof (SocketDNS_CacheStats, hits) == 0,
                "SocketDNS_CacheStats.hits offset changed");
_Static_assert (offsetof (SocketDNS_CacheStats, hit_rate) == 48,
                "SocketDNS_CacheStats.hit_rate offset changed");

#undef T
#undef Request_T
