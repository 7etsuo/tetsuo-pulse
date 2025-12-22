/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* All includes before T macro definition to avoid redefinition warnings */
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"

#include "dns/SocketDNS-private.h"
#include "dns/SocketDNS.h"

#ifdef __linux__
#include <arpa/inet.h>
#include <resolv.h>
#endif

/* Redefine T after all includes (Arena.h and SocketDNS.h both undef T at end)
 */
#undef T
#define T SocketDNS_T
/* Request_T is now properly typedef'd in SocketDNS.h */

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS-internal"

/* Thread-local exception for formatted error messages (per-thread for safety)
 */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketDNS);

/* Helper macro for pthread init with cleanup on failure */
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

/* GCC cleanup attribute to auto-unlock mutex when scope exits */
static inline void
mutex_unlock_cleanup (pthread_mutex_t **mutex)
{
  if (*mutex)
    pthread_mutex_unlock (*mutex);
}

/* Scoped mutex lock - auto-unlocks on scope exit via GCC cleanup attribute */
#define SCOPED_MUTEX_LOCK(mutex_ptr)                                          \
  pthread_mutex_lock (mutex_ptr);                                             \
  pthread_mutex_t *SOCKET_CONCAT (_scoped_mutex_, __LINE__)                   \
      __attribute__ ((cleanup (mutex_unlock_cleanup), unused))                \
      = (mutex_ptr)

/* Helper for unique variable names */
#define SOCKET_CONCAT_INNER(a, b) a##b
#define SOCKET_CONCAT(a, b) SOCKET_CONCAT_INNER (a, b)

void
initialize_mutex (struct SocketDNS_T *dns)
{
  INIT_PTHREAD_PRIMITIVE (dns, pthread_mutex_init, &dns->mutex, DNS_CLEAN_NONE,
                          "Failed to initialize DNS resolver mutex");
}

void
initialize_queue_condition (struct SocketDNS_T *dns)
{
  INIT_PTHREAD_PRIMITIVE (dns, pthread_cond_init, &dns->queue_cond,
                          DNS_CLEAN_MUTEX,
                          "Failed to initialize DNS resolver queue condition");
}

/* Security: Uses CLOCK_MONOTONIC to prevent timing attacks via clock
 * manipulation */
void
initialize_result_condition (struct SocketDNS_T *dns)
{
  pthread_condattr_t attr;
  int rc;

  rc = pthread_condattr_init (&attr);
  if (rc != 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_CONDS);
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "Failed to initialize condition attributes");
    }

  /* Use CLOCK_MONOTONIC for immunity to system clock changes */
  rc = pthread_condattr_setclock (&attr, CLOCK_MONOTONIC);
  if (rc != 0)
    {
      pthread_condattr_destroy (&attr);
      cleanup_on_init_failure (dns, DNS_CLEAN_CONDS);
      SOCKET_RAISE_MSG (
          SocketDNS, SocketDNS_Failed,
          "Failed to set CLOCK_MONOTONIC for condition variable");
    }

  rc = pthread_cond_init (&dns->result_cond, &attr);
  pthread_condattr_destroy (&attr);

  if (rc != 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_CONDS);
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "Failed to initialize DNS resolver result condition");
    }
}

void
initialize_synchronization (struct SocketDNS_T *dns)
{
  initialize_mutex (dns);
  initialize_queue_condition (dns);
  initialize_result_condition (dns);
}

void
create_completion_pipe (struct SocketDNS_T *dns)
{
  if (pipe (dns->pipefd) < 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_CONDS);
      SOCKET_RAISE_FMT (SocketDNS, SocketDNS_Failed,
                        "Failed to create completion pipe");
    }

  /* Set CLOEXEC on both pipe ends */
  if (SocketCommon_setcloexec (dns->pipefd[0], 1) < 0
      || SocketCommon_setcloexec (dns->pipefd[1], 1) < 0)
    {
      int saved_errno = errno;
      cleanup_pipe (dns);
      cleanup_on_init_failure (dns, DNS_CLEAN_CONDS);
      errno = saved_errno;
      SOCKET_RAISE_FMT (SocketDNS, SocketDNS_Failed,
                        "Failed to set close-on-exec flag on pipe");
    }
}

void
set_pipe_nonblocking (struct SocketDNS_T *dns)
{
  int flags = fcntl (dns->pipefd[0], F_GETFL);
  if (flags < 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_ARENA);
      SOCKET_RAISE_FMT (SocketDNS, SocketDNS_Failed,
                        "Failed to get pipe flags");
    }

  if (fcntl (dns->pipefd[0], F_SETFL, flags | O_NONBLOCK) < 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_ARENA);
      SOCKET_RAISE_FMT (SocketDNS, SocketDNS_Failed,
                        "Failed to set pipe to non-blocking");
    }
}

void
initialize_pipe (struct SocketDNS_T *dns)
{
  create_completion_pipe (dns);
  set_pipe_nonblocking (dns);
}

T
allocate_dns_resolver (void)
{
  struct SocketDNS_T *dns;

  dns = calloc (1, sizeof (*dns));
  if (!dns)
    {
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        SOCKET_ENOMEM ": Cannot allocate DNS resolver");
    }

  return dns;
}

/* Only non-zero defaults; calloc zeroed the rest */
void
initialize_dns_fields (struct SocketDNS_T *dns)
{
  /* Thread pool configuration */
  dns->num_workers = SOCKET_DNS_THREAD_COUNT;
  dns->max_pending = SOCKET_DNS_MAX_PENDING;
  dns->request_timeout_ms = SOCKET_DEFAULT_DNS_TIMEOUT_MS;

  /* Cache configuration - only non-zero defaults */
  dns->cache_max_entries = SOCKET_DNS_DEFAULT_CACHE_MAX_ENTRIES;
  dns->cache_ttl_seconds = SOCKET_DNS_DEFAULT_CACHE_TTL_SECONDS;

  /* DNS preferences */
  dns->prefer_ipv6 = 1; /* Prefer IPv6 per RFC 6724 */
}

void
initialize_dns_components (struct SocketDNS_T *dns)
{
  dns->arena = Arena_new ();
  if (!dns->arena)
    {
      free (dns);
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        SOCKET_ENOMEM ": Cannot allocate DNS resolver arena");
    }

  initialize_synchronization (dns);
  initialize_pipe (dns);
}

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
  pthread_cond_broadcast (&dns->queue_cond);
  pthread_mutex_unlock (&dns->mutex);
}

static void
cleanup_partial_workers (struct SocketDNS_T *dns, int created_count)
{
  signal_shutdown_and_broadcast (dns);

  for (int i = 0; i < created_count; i++)
    pthread_join (dns->workers[i], NULL);
}

static void
set_worker_thread_name (struct SocketDNS_T *dns, int thread_index)
{
#if defined(__linux__) || defined(__APPLE__)
  char thread_name[SOCKET_DNS_THREAD_NAME_SIZE];
  snprintf (thread_name, sizeof (thread_name), "dns-worker-%d", thread_index);
#if defined(__APPLE__)
  /* macOS: pthread_setname_np takes only one argument (sets current thread) */
  (void)dns;
  pthread_setname_np (thread_name);
#else
  /* Linux: pthread_setname_np takes thread id and name */
  pthread_setname_np (dns->workers[thread_index], thread_name);
#endif
#else
  (void)dns;
  (void)thread_index;
#endif
}

int
create_single_worker_thread (struct SocketDNS_T *dns, int thread_index)
{
  pthread_attr_t attr;

  setup_thread_attributes (&attr);

  int result = pthread_create (&dns->workers[thread_index], &attr,
                               worker_thread, dns);
  pthread_attr_destroy (&attr);

  if (result != 0)
    {
      cleanup_partial_workers (dns, thread_index);
      return -1;
    }

  set_worker_thread_name (dns, thread_index);
  return 0;
}

void
create_worker_threads (struct SocketDNS_T *dns)
{
  for (int i = 0; i < dns->num_workers; i++)
    {
      if (create_single_worker_thread (dns, i) != 0)
        {
          /* Thread creation failed - cleanup and raise error */
          cleanup_on_init_failure (dns, DNS_CLEAN_ARENA);
          SOCKET_RAISE_FMT (SocketDNS, SocketDNS_Failed,
                            "Failed to create DNS worker thread %d", i);
        }
    }
}

void
start_dns_workers (struct SocketDNS_T *dns)
{
  dns->workers = ALLOC (dns->arena, dns->num_workers * sizeof (pthread_t));
  if (!dns->workers)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_ARENA);
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        SOCKET_ENOMEM ": Cannot allocate worker thread array");
    }
  create_worker_threads (dns);
}

void
cleanup_mutex_cond (struct SocketDNS_T *dns)
{
  pthread_cond_destroy (&dns->result_cond);
  pthread_cond_destroy (&dns->queue_cond);
  pthread_mutex_destroy (&dns->mutex);
}

void
cleanup_pipe (struct SocketDNS_T *dns)
{
  for (int i = 0; i < 2; i++)
    {
      SAFE_CLOSE (dns->pipefd[i]);
      dns->pipefd[i] = -1;
    }
}

void
cleanup_on_init_failure (struct SocketDNS_T *dns,
                         enum DnsCleanupLevel cleanup_level)
{
  if (cleanup_level >= DNS_CLEAN_ARENA)
    Arena_dispose (&dns->arena);
  if (cleanup_level >= DNS_CLEAN_PIPE)
    cleanup_pipe (dns);
  if (cleanup_level >= DNS_CLEAN_CONDS)
    {
      cleanup_mutex_cond (dns);
    }
  else if (cleanup_level >= DNS_CLEAN_MUTEX)
    {
      pthread_mutex_destroy (&dns->mutex);
    }
  free (dns);
}

void
shutdown_workers (T d)
{
  signal_shutdown_and_broadcast (d);

  for (int i = 0; i < d->num_workers; i++)
    pthread_join (d->workers[i], NULL);
}

void
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

/* Security: Prevents hostname/IP strings from lingering in memory */
static void
secure_clear_memory (void *ptr, size_t len)
{
  if (!ptr || len == 0)
    return;

#ifdef __linux__
  explicit_bzero (ptr, len);
#else
  /* Volatile pointer prevents compiler from optimizing away the memset */
  volatile unsigned char *vptr = (volatile unsigned char *)ptr;
  while (len--)
    *vptr++ = 0;
#endif
}

/* Security: Securely clears hostname strings before arena disposal */
static void
free_request_list_results (Request_T head, size_t next_offset)
{
  Request_T curr = head;

  while (curr)
    {
      Request_T next = *(Request_T *)((char *)curr + next_offset);

      /* Securely clear hostname before arena disposal */
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
  /* Free queue-linked requests */
  free_request_list_results (
      d->queue_head, offsetof (struct SocketDNS_Request_T, queue_next));

  /* Free hash-linked requests */
  for (int i = 0; i < SOCKET_DNS_REQUEST_HASH_SIZE; i++)
    free_request_list_results (
        d->request_hash[i], offsetof (struct SocketDNS_Request_T, hash_next));
}

void
reset_dns_state (T d)
{
  SCOPED_MUTEX_LOCK (&d->mutex);
  free_all_requests (d);
  d->queue_head = NULL;
  d->queue_tail = NULL;
  d->queue_size = 0;
  for (int i = 0; i < SOCKET_DNS_REQUEST_HASH_SIZE; i++)
    d->request_hash[i] = NULL;
}

void
destroy_dns_resources (T d)
{
  cleanup_pipe (d);
  cleanup_mutex_cond (d);
  Arena_dispose (&d->arena);
  free (d);
}

unsigned
request_hash_function (const struct SocketDNS_Request_T *req)
{
  return socket_util_hash_ptr (req, SOCKET_DNS_REQUEST_HASH_SIZE);
}

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

  /* Overflow check - defensive (already limited by validate_hostname) */
  if (host_len > SIZE_MAX - 1)
    {
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "Hostname length overflow");
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
hash_table_insert (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  unsigned hash;

  hash = request_hash_function (req);
  req->hash_value = hash;
  req->hash_next = dns->request_hash[hash];
  dns->request_hash[hash] = req;
}

/* Security: Bounds-checks hash_value to prevent out-of-bounds access */
void
hash_table_remove (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  unsigned hash;
  Request_T *pp;

  hash = req->hash_value;

  /* Defensive bounds check - prevent out-of-bounds access if
   * hash_value is corrupted or request is from different resolver */
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
          break;
        }
      pp = &(*pp)->hash_next;
    }
}

void
queue_append (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  if (dns->queue_tail)
    {
      dns->queue_tail->queue_next = req;
      dns->queue_tail = req;
    }
  else
    {
      dns->queue_head = req;
      dns->queue_tail = req;
    }
  dns->queue_size++;
}

void
remove_from_queue_head (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req)
{
  dns->queue_head = req->queue_next;
  if (!dns->queue_head)
    dns->queue_tail = NULL;
}

void
remove_from_queue_middle (struct SocketDNS_T *dns,
                          struct SocketDNS_Request_T *req)
{
  Request_T prev = dns->queue_head;
  while (prev && prev->queue_next != req)
    prev = prev->queue_next;
  if (prev)
    {
      prev->queue_next = req->queue_next;
      if (dns->queue_tail == req)
        dns->queue_tail = prev;
    }
}

void
queue_remove (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  if (dns->queue_head == req)
    remove_from_queue_head (dns, req);
  else
    remove_from_queue_middle (dns, req);
  dns->queue_size--;
}

int
check_queue_limit (const struct SocketDNS_T *dns)
{
  return dns->queue_size >= dns->max_pending;
}

void
submit_dns_request (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  hash_table_insert (dns, req);
  queue_append (dns, req);
  pthread_cond_signal (&dns->queue_cond);
}

void
cancel_pending_request (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req)
{
  queue_remove (dns, req);
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

  /* Defensive: unlikely but handle clock anomaly */
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
  struct SocketDNS_Request_T *req;

  if (!dns->queue_head)
    return NULL;

  req = dns->queue_head;

  /* Pop from queue head */
  dns->queue_head = req->queue_next;
  if (!dns->queue_head)
    dns->queue_tail = NULL;
  dns->queue_size--;

  /* Prepare for processing */
  req->queue_next = NULL;
  req->state = REQ_PROCESSING;

  return req;
}

Request_T
wait_for_request (struct SocketDNS_T *dns)
{
  while (dns->queue_head == NULL && !dns->shutdown)
    {
      pthread_cond_wait (&dns->queue_cond, &dns->mutex);
    }

  if (dns->shutdown && dns->queue_head == NULL)
    return NULL;

  return dequeue_request (dns);
}

void
signal_completion (struct SocketDNS_T *dns)
{
  char byte = COMPLETION_SIGNAL_BYTE;
  ssize_t n;

  n = write (dns->pipefd[1], &byte, 1);
  (void)n; /* Ignore result - pipe may be full, that's OK */
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

  /* Determine final error code:
   * - Use provided error if non-zero (timeout, DNS failure, etc.)
   * - Use EAI_MEMORY if copy failed and no prior error
   * - Use 0 if copy succeeded and no error */
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

/* Security: Clears callback after invocation to prevent double-invoke or
 * use-after-free */
void
invoke_callback (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  SocketDNS_Callback callback;
  void *callback_data;
  struct addrinfo *result;
  int error;

  /* Extract callback info under mutex for safe concurrent access.
   * Another thread could be calling SocketDNS_cancel concurrently. */
  pthread_mutex_lock (&dns->mutex);
  if (!req->callback || req->state != REQ_COMPLETE)
    {
      pthread_mutex_unlock (&dns->mutex);
      return;
    }

  /* Copy callback info while holding mutex */
  callback = req->callback;
  callback_data = req->callback_data;
  result = req->result;
  error = req->error;
  pthread_mutex_unlock (&dns->mutex);

  /* Invoke callback without mutex held (callback may take arbitrary time) */
  callback (req, result, error, callback_data);

  /* Clear result and callback after invocation to prevent use-after-free or
   * double invocation. Callback has taken ownership of result and freed it.
   * Clearing callback prevents potential double calls in race conditions. */
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
      /* Call mark_request_timeout directly since we already hold mutex
       * (handle_request_timeout would deadlock by trying to lock again) */
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

  struct addrinfo local_hints;
  prepare_local_hints (&local_hints, base_hints, req);

  struct addrinfo *result = NULL;
  int res = perform_dns_resolution (req, &local_hints, &result);

  handle_resolution_result (dns, req, result, res);

  invoke_callback (dns, req);
}

#ifdef __linux__
/* Security: Uses inet_pton() for safe address parsing */
static void
apply_custom_resolver_config (struct __res_state *res_state,
                              struct SocketDNS_T *dns)
{
  if (dns->custom_nameservers && dns->nameserver_count > 0)
    {
      res_state->nscount = 0;

      /* Static storage for IPv6 addresses (thread-local, one per worker) */
      static __thread struct sockaddr_in6 ipv6_addrs[MAXNS];
      static __thread struct sockaddr_in6 *ipv6_ptrs[MAXNS];
      int ipv6_count = 0;

      for (size_t i = 0;
           i < dns->nameserver_count && res_state->nscount < MAXNS; i++)
        {
          const char *ip = dns->custom_nameservers[i];
          struct in_addr addr4;
          struct in6_addr addr6;

          /* Try IPv4 first */
          if (inet_pton (AF_INET, ip, &addr4) == 1)
            {
              int idx = res_state->nscount;
              res_state->nsaddr_list[idx].sin_family = AF_INET;
              res_state->nsaddr_list[idx].sin_addr = addr4;
              res_state->nsaddr_list[idx].sin_port = htons (53);
              res_state->nscount++;
            }
          /* Try IPv6 */
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

      /* Apply IPv6 nameservers if any were configured */
      if (ipv6_count > 0)
        {
          /* The _u._ext structure holds IPv6 nameserver pointers.
           * Note: This is a glibc extension and may not be portable. */
          res_state->_u._ext.nscount6 = ipv6_count;
          for (int j = 0; j < ipv6_count; j++)
            {
              res_state->_u._ext.nsaddrs[j] = ipv6_ptrs[j];
            }
        }
    }

  /* Note: Search domains are not applied here because res_state->dnsrch
   * is an array of pointers into defdname buffer, not char arrays.
   * Implementing proper search domain support requires managing the
   * defdname buffer layout. For now, only nameservers are applied.
   * TODO: Implement search domain support with defdname buffer management.
   */
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
