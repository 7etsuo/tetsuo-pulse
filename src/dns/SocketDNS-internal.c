/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"

#include "dns/SocketDNS-private.h"
#include "dns/SocketDNS.h"
#include "dns/SocketDNSResolver.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

#ifdef __linux__
#include <arpa/inet.h>
#include <resolv.h>
#endif

#undef T
#define T SocketDNS_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS-internal"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketDNS);

/* INIT_PTHREAD_PRIMITIVE macro migrated to SocketDNS.c (Phase 2.6c) */

static inline void
mutex_unlock_cleanup (pthread_mutex_t **mutex)
{
  if (*mutex)
    pthread_mutex_unlock (*mutex);
}

#define SCOPED_MUTEX_LOCK(mutex_ptr)                                          \
  pthread_mutex_lock (mutex_ptr);                                             \
  pthread_mutex_t *SOCKET_CONCAT (_scoped_mutex_, __LINE__)                   \
      __attribute__ ((cleanup (mutex_unlock_cleanup), unused))                \
      = (mutex_ptr)

#define SOCKET_CONCAT_INNER(a, b) a##b
#define SOCKET_CONCAT(a, b) SOCKET_CONCAT_INNER (a, b)

/* Initialization functions migrated to SocketDNS.c (Phase 2.6c):
 * - initialize_mutex()
 * - initialize_queue_condition()
 * - initialize_result_condition()
 * - initialize_synchronization()
 * - create_completion_pipe()
 * - set_pipe_nonblocking()
 * - initialize_pipe()
 * - allocate_dns_resolver()
 * - initialize_dns_fields()
 * - initialize_dns_components()
 */

void
setup_thread_attributes (pthread_attr_t *attr)
{
  pthread_attr_init (attr);
  pthread_attr_setdetachstate (attr, PTHREAD_CREATE_JOINABLE);
  pthread_attr_setstacksize (attr, SOCKET_DNS_WORKER_STACK_SIZE);
}

static void
signal_shutdown_and_broadcast (struct SocketDNS_T *dns)
{
  pthread_mutex_lock (&dns->mutex);
  dns->shutdown = 1;
  /* queue_cond removed - no worker threads to signal */
  pthread_mutex_unlock (&dns->mutex);
}

static void
cleanup_partial_workers (struct SocketDNS_T *dns, int created_count)
{
  /* TODO(Phase 2.x): Removed - no worker threads to clean up */
  (void)dns;
  (void)created_count;
}

static void
set_worker_thread_name (struct SocketDNS_T *dns, int thread_index)
{
  /* TODO(Phase 2.x): Removed - no worker threads */
  (void)dns;
  (void)thread_index;
}

int
create_single_worker_thread (struct SocketDNS_T *dns, int thread_index)
{
  /* TODO(Phase 2.x): Removed - no worker threads */
  (void)dns;
  (void)thread_index;
  return 0;
}

void
create_worker_threads (struct SocketDNS_T *dns)
{
  /* TODO(Phase 2.x): Removed - no worker threads */
  (void)dns;
}

void
start_dns_workers (struct SocketDNS_T *dns)
{
  /* TODO(Phase 2.x): Removed - no worker threads */
  (void)dns;
}

/* Cleanup functions migrated to SocketDNS.c (Phase 2.6c):
 * - cleanup_mutex_cond()
 * - cleanup_pipe()
 * - cleanup_on_init_failure()
 */

void
shutdown_workers (T d)
{
  /* TODO(Phase 2.x): Removed - no worker threads to shut down */
  signal_shutdown_and_broadcast (d);
}

/* drain_completion_pipe() migrated to SocketDNS.c (Phase 2.6c) */

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

/* reset_dns_state() and destroy_dns_resources() migrated to SocketDNS.c (Phase 2.6c) */

Request_T
allocate_request_structure (struct SocketDNS_T *dns)
{
  Request_T req;

  req = ALLOC (dns->arena, sizeof (*req));
  if (!req)
    {
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        SOCKET_ENOMEM ": Cannot allocate DNS request");
    }

  return req;
}

void
allocate_request_hostname (struct SocketDNS_T *dns,
                           struct SocketDNS_Request_T *req, const char *host,
                           size_t host_len)
{
  if (host == NULL)
    {
      req->host = NULL;
      return;
    }

  /* Check for overflow: host_len == SIZE_MAX would cause host_len + 1 to wrap to 0 */
  if (host_len >= SIZE_MAX || host_len > 255)
    {
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "Hostname length overflow or exceeds DNS maximum (255)");
    }

  req->host = ALLOC (dns->arena, host_len + 1);
  if (!req->host)
    {
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        SOCKET_ENOMEM ": Cannot allocate hostname");
    }

  memcpy (req->host, host, host_len);
  req->host[host_len] = '\0';
}

void
initialize_request_fields (struct SocketDNS_Request_T *req, int port,
                           SocketDNS_Callback callback, void *data)
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
allocate_request (struct SocketDNS_T *dns, const char *host, size_t host_len,
                  int port, SocketDNS_Callback callback, void *data)
{
  Request_T req = allocate_request_structure (dns);
  allocate_request_hostname (dns, req, host, host_len);
  initialize_request_fields (req, port, callback, data);
  req->dns_resolver = dns;

  return req;
}

void
queue_append (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  /* TODO(Phase 2.x): Removed - no queue in new architecture */
  (void)dns;
  (void)req;
}

void
remove_from_queue_head (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req)
{
  /* TODO(Phase 2.x): Removed - no queue in new architecture */
  (void)dns;
  (void)req;
}

void
remove_from_queue_middle (struct SocketDNS_T *dns,
                          struct SocketDNS_Request_T *req)
{
  /* TODO(Phase 2.x): Removed - no queue in new architecture */
  (void)dns;
  (void)req;
}

void
queue_remove (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  /* TODO(Phase 2.x): Removed - no queue in new architecture */
  (void)dns;
  (void)req;
}

int
check_queue_limit (const struct SocketDNS_T *dns)
{
  /* TODO(Phase 2.x): Removed - no queue in new architecture */
  (void)dns;
  return 0; /* Never full since there's no queue */
}

void
submit_dns_request (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  /* TODO(Phase 2.x): Removed - no queue/workers in new architecture */
  hash_table_insert (dns, req);
  /* No queue_append or cond signal - worker threads removed */
}

void
cancel_pending_request (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req)
{
  /* No queue_remove - queue removed */
  hash_table_remove (dns, req);
  req->state = REQ_CANCELLED;
}

int
request_effective_timeout_ms (const struct SocketDNS_T *dns,
                              const struct SocketDNS_Request_T *req)
{
  if (req->timeout_override_ms >= 0)
    return req->timeout_override_ms;
  return dns->request_timeout_ms;
}

int
request_timed_out (const struct SocketDNS_T *dns,
                   const struct SocketDNS_Request_T *req)
{
  int timeout_ms = request_effective_timeout_ms (dns, req);
  if (timeout_ms <= 0)
    return 0;

  int64_t now_ms = Socket_get_monotonic_ms ();
  long long elapsed_ms = now_ms - req->submit_time_ms;

  if (elapsed_ms < 0)
    elapsed_ms = 0;

  if (elapsed_ms >= (long long)timeout_ms)
    return 1;

  return 0;
}

void
mark_request_timeout (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  req->state = REQ_COMPLETE;
  req->error = EAI_AGAIN;
  if (req->result)
    {
      SocketCommon_free_addrinfo (req->result);
      req->result = NULL;
    }
  SIGNAL_DNS_COMPLETION (dns);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_TIMEOUT, 1);
  SocketEvent_emit_dns_timeout (req->host ? req->host : "(wildcard)",
                                req->port);
}

void
handle_request_timeout (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req)
{
  SCOPED_MUTEX_LOCK (&dns->mutex);
  mark_request_timeout (dns, req);
}

void
initialize_addrinfo_hints (struct addrinfo *hints)
{
  memset (hints, 0, sizeof (*hints));
  hints->ai_family = AF_UNSPEC;
  hints->ai_socktype = SOCK_STREAM;
  hints->ai_protocol = 0;
}

Request_T
dequeue_request (struct SocketDNS_T *dns)
{
  /* TODO(Phase 2.x): Removed - no queue in new architecture */
  (void)dns;
  return NULL;
}

Request_T
wait_for_request (struct SocketDNS_T *dns)
{
  /* TODO(Phase 2.x): Removed - no queue/workers in new architecture */
  (void)dns;
  return NULL;
}

void
signal_completion (struct SocketDNS_T *dns)
{
  char byte = COMPLETION_SIGNAL_BYTE;
  ssize_t n;

  n = write (dns->pipefd[1], &byte, 1);
  (void)n;
}

int
dns_cancellation_error (void)
{
#ifdef EAI_CANCELLED
  return EAI_CANCELLED;
#else
  return EAI_AGAIN;
#endif
}

int
perform_dns_resolution (const struct SocketDNS_Request_T *req,
                        const struct addrinfo *hints, struct addrinfo **result)
{
  char port_str[SOCKET_DNS_PORT_STR_SIZE];
  const char *service = NULL;
  int res;

  if (req->port > 0)
    {
      int sn_res = snprintf (port_str, sizeof (port_str), "%d", req->port);
      if (sn_res < 0 || (size_t)sn_res >= sizeof (port_str))
        {
          *result = NULL;
          return EAI_FAIL;
        }
      service = port_str;
    }

  res = getaddrinfo (req->host, service, hints, result);
  return res;
}

static void
copy_and_store_result (struct SocketDNS_Request_T *req,
                       struct addrinfo *result, int error)
{
  req->state = REQ_COMPLETE;
  req->result = SocketCommon_copy_addrinfo (result);

  if (error != 0)
    req->error = error;
  else if (!req->result && result)
    req->error = EAI_MEMORY;
  else
    req->error = 0;

  if (result)
    freeaddrinfo (result);
}

static void
update_completion_metrics (int error)
{
  if (error == 0)
    SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_COMPLETED, 1);
  else
    SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_FAILED, 1);
}

static void
handle_cancelled_result (struct SocketDNS_T *dns,
                         struct SocketDNS_Request_T *req,
                         struct addrinfo *result)
{
  if (result)
    freeaddrinfo (result);

  if (req->state == REQ_CANCELLED && req->error == 0)
    req->error = dns_cancellation_error ();

  SIGNAL_DNS_COMPLETION (dns);
}

void
store_resolution_result (struct SocketDNS_T *dns,
                         struct SocketDNS_Request_T *req,
                         struct addrinfo *result, int error)
{
  if (req->state == REQ_PROCESSING)
    {
      copy_and_store_result (req, result, error);
      update_completion_metrics (error);

      /* Insert successful results into cache (mutex already held by caller) */
      if (error == 0 && req->host != NULL && req->result != NULL
          && !socketcommon_is_ip_address (req->host))
        {
          /* Validate hostname length before caching to prevent poisoning */
          size_t host_len = strnlen (req->host, 256);
          if (host_len > 0 && host_len <= 255)
            {
              cache_insert (dns, req->host, req->result);
            }
        }

      SIGNAL_DNS_COMPLETION (dns);
    }
  else
    {
      handle_cancelled_result (dns, req, result);
    }
}

void
prepare_local_hints (struct addrinfo *local_hints,
                     const struct addrinfo *base_hints,
                     const struct SocketDNS_Request_T *req)
{
  memcpy (local_hints, base_hints, sizeof (*local_hints));
  if (req->host == NULL)
    {
      local_hints->ai_flags |= AI_PASSIVE;
    }
}

void
handle_resolution_result (struct SocketDNS_T *dns,
                          struct SocketDNS_Request_T *req,
                          struct addrinfo *result, int res)
{
  SCOPED_MUTEX_LOCK (&dns->mutex);
  if (request_timed_out (dns, req))
    {
      if (result)
        {
          freeaddrinfo (result);
          result = NULL;
        }
      res = EAI_AGAIN;
    }
  store_resolution_result (dns, req, result, res);
}

void
invoke_callback (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  SocketDNS_Callback callback;
  void *callback_data;
  struct addrinfo *result;
  int error;

  pthread_mutex_lock (&dns->mutex);
  if (!req->callback || req->state != REQ_COMPLETE)
    {
      pthread_mutex_unlock (&dns->mutex);
      return;
    }

  callback = req->callback;
  callback_data = req->callback_data;
  result = req->result;
  error = req->error;
  pthread_mutex_unlock (&dns->mutex);

  callback (req, result, error, callback_data);

  pthread_mutex_lock (&dns->mutex);
  req->result = NULL;
  req->callback = NULL;
  pthread_mutex_unlock (&dns->mutex);
}

static int
check_pre_processing_timeout (struct SocketDNS_T *dns,
                              struct SocketDNS_Request_T *req)
{
  SCOPED_MUTEX_LOCK (&dns->mutex);
  if (request_timed_out (dns, req))
    {
      mark_request_timeout (dns, req);
      return 1;
    }
  return 0;
}

void
process_single_request (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req,
                        const struct addrinfo *base_hints)
{
  if (check_pre_processing_timeout (dns, req))
    return;

  /* Check cache first (skip for NULL host / IP addresses) */
  if (req->host != NULL && !socketcommon_is_ip_address (req->host))
    {
      pthread_mutex_lock (&dns->mutex);
      struct SocketDNS_CacheEntry *cached = cache_lookup (dns, req->host);
      if (cached)
        {
          /* Cache hit - copy result directly (avoid double-copy via
           * store_resolution_result which frees input with freeaddrinfo,
           * but SocketCommon_copy_addrinfo results need free_addrinfo) */
          req->result = SocketCommon_copy_addrinfo (cached->result);
          req->state = REQ_COMPLETE;
          req->error = req->result ? 0 : EAI_MEMORY;
          update_completion_metrics (req->error);
          SIGNAL_DNS_COMPLETION (dns);
          pthread_mutex_unlock (&dns->mutex);
          invoke_callback (dns, req);
          return;
        }
      pthread_mutex_unlock (&dns->mutex);
    }

  struct addrinfo local_hints;
  prepare_local_hints (&local_hints, base_hints, req);

  struct addrinfo *result = NULL;
  int res = perform_dns_resolution (req, &local_hints, &result);

  handle_resolution_result (dns, req, result, res);

  invoke_callback (dns, req);
}

#ifdef __linux__
static void
apply_custom_resolver_config (struct __res_state *res_state,
                              struct SocketDNS_T *dns)
{
  if (dns->custom_nameservers && dns->nameserver_count > 0)
    {
      res_state->nscount = 0;

      static __thread struct sockaddr_in6 ipv6_addrs[MAXNS];
      static __thread struct sockaddr_in6 *ipv6_ptrs[MAXNS];
      int ipv6_count = 0;

      for (size_t i = 0;
           i < dns->nameserver_count && res_state->nscount < MAXNS; i++)
        {
          const char *ip = dns->custom_nameservers[i];
          struct in_addr addr4;
          struct in6_addr addr6;

          if (inet_pton (AF_INET, ip, &addr4) == 1)
            {
              int idx = res_state->nscount;
              res_state->nsaddr_list[idx].sin_family = AF_INET;
              res_state->nsaddr_list[idx].sin_addr = addr4;
              res_state->nsaddr_list[idx].sin_port = htons (53);
              res_state->nscount++;
            }
          else if (inet_pton (AF_INET6, ip, &addr6) == 1)
            {
              if (ipv6_count < MAXNS)
                {
                  memset (&ipv6_addrs[ipv6_count], 0,
                          sizeof (struct sockaddr_in6));
                  ipv6_addrs[ipv6_count].sin6_family = AF_INET6;
                  ipv6_addrs[ipv6_count].sin6_addr = addr6;
                  ipv6_addrs[ipv6_count].sin6_port = htons (53);
                  ipv6_ptrs[ipv6_count] = &ipv6_addrs[ipv6_count];
                  ipv6_count++;
                }
            }
          else
            {
              SOCKET_LOG_WARN_MSG ("Invalid nameserver IP (should not happen "
                                   "after validation): "
                                   "%s",
                                   ip);
            }
        }

      if (ipv6_count > 0)
        {
          res_state->_u._ext.nscount6 = ipv6_count;
          for (int j = 0; j < ipv6_count; j++)
            res_state->_u._ext.nsaddrs[j] = ipv6_ptrs[j];
        }
    }

  (void)dns->search_domains;
  (void)dns->search_domain_count;
}
#endif

void *
worker_thread (void *arg)
{
  struct SocketDNS_T *dns = (T)arg;
  struct addrinfo hints;

  initialize_addrinfo_hints (&hints);

#ifdef __linux__
  struct __res_state res_state;
  int resolver_initialized = 0;
#endif

#ifdef __linux__
  memset (&res_state, 0, sizeof (res_state));
  if (res_ninit (&res_state) == 0)
    {
      resolver_initialized = 1;
      pthread_mutex_lock (&dns->mutex);
      apply_custom_resolver_config (&res_state, dns);
      pthread_mutex_unlock (&dns->mutex);
    }
#endif

  while (1)
    {
      struct SocketDNS_Request_T *req;

      pthread_mutex_lock (&dns->mutex);
      req = wait_for_request (dns);
      pthread_mutex_unlock (&dns->mutex);

      if (!req)
        break;

      process_single_request (dns, req, &hints);
    }

#ifdef __linux__
  if (resolver_initialized)
    res_nclose (&res_state);
#endif

  return NULL;
}

#undef T
#undef Request_T
