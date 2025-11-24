/**
 * SocketDNS.c - Async DNS resolution
 * PLATFORM: POSIX-compliant systems (Linux, BSD, macOS)
 * - POSIX threads (pthread) for thread pool
 * - getaddrinfo() for DNS resolution
 * - pipe() for completion signaling
 */

#include "core/Arena.h"
#include "core/Except.h" /* if not already for RAISE */
#include "socket/SocketCommon-private.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "dns/SocketDNS.h"
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS"
#define T SocketDNS_T
#define Request_T SocketDNS_Request_T
#include "core/SocketError.h"
#include "core/SocketEvents.h"
#include "core/SocketMetrics.h"
#include "dns/SocketDNS-private.h"
#include "socket/SocketCommon.h"
#include <ctype.h>
#include <stdbool.h>

/* SocketDNS module exceptions and thread-local detailed exception */
const Except_T SocketDNS_Failed
    = { &SocketDNS_Failed, "SocketDNS operation failed" };

#ifdef _WIN32
__declspec (thread) Except_T SocketDNS_DetailedException;
#else
__thread Except_T SocketDNS_DetailedException;
#endif

/**
 * request_hash_function - Calculate hash for request pointer
 * @req: Request pointer to hash
 * Returns: Hash value in range [0, SOCKET_DNS_REQUEST_HASH_SIZE)
 * Uses golden ratio multiplicative hashing for good distribution.
 */
unsigned
request_hash_function (struct SocketDNS_Request_T *req)
{
  uintptr_t ptr = (uintptr_t)req;
  return ((unsigned)ptr * HASH_GOLDEN_RATIO) % SOCKET_DNS_REQUEST_HASH_SIZE;
}

/**
 * perform_dns_resolution - Perform actual DNS lookup
 * @req: Request to resolve
 * @hints: getaddrinfo hints structure
 * Returns: getaddrinfo result code
 * @result: Set to resolved addresses (or NULL on error)
 * Performs DNS resolution with optional port parameter.
 * Handles NULL host (wildcard bind) by passing NULL to getaddrinfo.
 */
/* Note: getaddrinfo() is called directly and is not interruptible.
 * Cancellation during resolution is cooperative: the worker completes the
 * query but discards the result if cancelled. For true cancellability,
 * consider using a process-per-query model or external async DNS library like
 * c-ares. Current design limits DoS exposure via bounded thread pool and
 * timeouts. */

/**
 * cleanup_mutex_cond - Cleanup mutex and condition variables
 * @dns: DNS resolver instance
 * Destroys mutex and condition variables in reverse order of creation.
 */
void
cleanup_mutex_cond (struct SocketDNS_T *dns)
{
  pthread_cond_destroy (&dns->result_cond);
  pthread_cond_destroy (&dns->queue_cond);
  pthread_mutex_destroy (&dns->mutex);
}

/**
 * cleanup_pipe - Close pipe file descriptors
 * @dns: DNS resolver instance
 * Safely closes both pipe file descriptors.
 */
void
cleanup_pipe (struct SocketDNS_T *dns)
{
  /* Close pipe file descriptors and mark as invalid */
  if (dns->pipefd[0] >= 0)
    {
      SAFE_CLOSE (dns->pipefd[0]);
      dns->pipefd[0] = -1;
    }
  if (dns->pipefd[1] >= 0)
    {
      SAFE_CLOSE (dns->pipefd[1]);
      dns->pipefd[1] = -1;
    }
}

/**
 * cleanup_on_init_failure - Cleanup resources on initialization failure
 * @dns: DNS resolver instance
 * @cleanup_level: How much cleanup needed (0=none, 1=mutex, 2=cond, 3=pipe,
 * 4=arena) Cleans up partially initialized resolver. cleanup_level indicates
 * how far initialization got before failure.
 */
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

/**
 * initialize_mutex - Initialize mutex for DNS resolver
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on initialization failure
 */
void
initialize_mutex (struct SocketDNS_T *dns)
{
  if (pthread_mutex_init (&dns->mutex, NULL) != 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_NONE);
      SOCKET_ERROR_MSG ("Failed to initialize DNS resolver mutex");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
}

/**
 * initialize_queue_condition - Initialize queue condition variable
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on initialization failure
 */
void
initialize_queue_condition (struct SocketDNS_T *dns)
{
  if (pthread_cond_init (&dns->queue_cond, NULL) != 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_MUTEX);
      SOCKET_ERROR_MSG (
          "Failed to initialize DNS resolver condition variable");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
}

/**
 * initialize_result_condition - Initialize result condition variable
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on initialization failure
 */
void
initialize_result_condition (struct SocketDNS_T *dns)
{
  if (pthread_cond_init (&dns->result_cond, NULL) != 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_CONDS);
      SOCKET_ERROR_MSG (
          "Failed to initialize DNS resolver result condition variable");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
}

/**
 * initialize_synchronization - Initialize mutex and condition variables
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on initialization failure
 */
void
initialize_synchronization (struct SocketDNS_T *dns)
{
  initialize_mutex (dns);
  initialize_queue_condition (dns);
  initialize_result_condition (dns);
}

/**
 * create_completion_pipe - Create pipe for completion signaling
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on pipe creation failure
 * Note: Both pipe ends are created with close-on-exec flag set.
 */
void
create_completion_pipe (struct SocketDNS_T *dns)
{
  if (pipe (dns->pipefd) < 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_CONDS);
      SOCKET_ERROR_FMT ("Failed to create completion pipe");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  /* Set CLOEXEC on both pipe ends */
  if (SocketCommon_setcloexec (dns->pipefd[0], 1) < 0
      || SocketCommon_setcloexec (dns->pipefd[1], 1) < 0)
    {
      int saved_errno = errno;
      SAFE_CLOSE (dns->pipefd[0]);
      SAFE_CLOSE (dns->pipefd[1]);
      dns->pipefd[0] = -1;
      dns->pipefd[1] = -1;
      cleanup_on_init_failure (dns, 3);
      errno = saved_errno;
      SOCKET_ERROR_FMT ("Failed to set close-on-exec flag on pipe");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
}

/**
 * set_pipe_nonblocking - Set pipe read end to non-blocking mode
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on fcntl failure
 */
void
set_pipe_nonblocking (struct SocketDNS_T *dns)
{
  int flags = fcntl (dns->pipefd[0], F_GETFL);
  if (flags < 0)
    {
      cleanup_on_init_failure (dns, 4);
      SOCKET_ERROR_FMT ("Failed to get pipe flags");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  if (fcntl (dns->pipefd[0], F_SETFL, flags | O_NONBLOCK) < 0)
    {
      cleanup_on_init_failure (dns, 4);
      SOCKET_ERROR_FMT ("Failed to set pipe to non-blocking");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
}

/**
 * initialize_pipe - Create pipe for completion signaling
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on pipe creation failure
 */
void
initialize_pipe (struct SocketDNS_T *dns)
{
  create_completion_pipe (dns);
  set_pipe_nonblocking (dns);
}

/**
 * allocate_dns_resolver - Allocate and initialize basic DNS resolver structure
 * Returns: Allocated DNS resolver or NULL on failure
 * Raises: SocketDNS_Failed on allocation failure
 * Allocates DNS resolver structure and sets up basic fields.
 */
T
allocate_dns_resolver (void)
{
  struct SocketDNS_T *dns;

  dns = calloc (1, sizeof (*dns));
  if (!dns)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate DNS resolver");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  return dns;
}

/**
 * initialize_dns_fields - Set default field values for DNS resolver
 * @dns: DNS resolver instance
 * Initializes configuration fields to default values.
 */
void
initialize_dns_fields (struct SocketDNS_T *dns)
{
  dns->num_workers = SOCKET_DNS_THREAD_COUNT;
  dns->max_pending = SOCKET_DNS_MAX_PENDING;
  dns->shutdown = 0;
  dns->request_counter = 0;

  dns->queue_head = NULL;
  dns->queue_tail = NULL;
  dns->queue_size = 0;
  dns->request_timeout_ms = SOCKET_DEFAULT_DNS_TIMEOUT_MS;
}

/**
 * initialize_dns_components - Initialize arena and synchronization primitives
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on initialization failure
 * Sets up arena, mutex, condition variables, and pipe for completion
 * signaling.
 */
void
initialize_dns_components (struct SocketDNS_T *dns)
{
  dns->arena = Arena_new ();
  if (!dns->arena)
    {
      free (dns);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate DNS resolver arena");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  initialize_synchronization (dns);
  initialize_pipe (dns);
}

/**
 * create_single_worker_thread - Create a single worker thread
 * @dns: DNS resolver instance
 * @thread_index: Index of thread to create
 * Returns: 0 on success, -1 on failure
 * Creates one worker thread and handles partial cleanup on failure.
 */
int
create_single_worker_thread (struct SocketDNS_T *dns, int thread_index)
{
  pthread_attr_t attr;
  char thread_name[16];

  pthread_attr_init (&attr);
  pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_JOINABLE);
  pthread_attr_setstacksize (
      &attr, SOCKET_DNS_WORKER_STACK_SIZE); /* Conservative stack size for DNS
                                               workers */

  snprintf (thread_name, sizeof (thread_name), "dns-worker-%d", thread_index);

  if (pthread_create (&dns->workers[thread_index], &attr, worker_thread, dns)
      != 0)
    {
      pthread_attr_destroy (&attr);
      /* Signal shutdown and join already created threads */
      dns->shutdown = 1;
      pthread_cond_broadcast (&dns->queue_cond);

      /* Join previously created threads */
      for (int j = 0; j < thread_index; j++)
        {
          pthread_join (dns->workers[j], NULL);
        }

      return -1; /* Signal failure */
    }

  pthread_attr_destroy (&attr);

  /* Set thread name for debugging (non-portable but useful) */
#ifdef PTHREAD_SET_NAME_SUPPORTED
  pthread_setname_np (dns->workers[thread_index], thread_name);
#endif

  return 0; /* Success */
}

/**
 * create_worker_threads - Create worker thread pool
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on thread creation failure
 * Creates all worker threads, with proper cleanup on partial failure.
 */
void
create_worker_threads (struct SocketDNS_T *dns)
{
  for (int i = 0; i < dns->num_workers; i++)
    {
      if (create_single_worker_thread (dns, i) != 0)
        {
          /* Thread creation failed - cleanup and raise error */
          cleanup_on_init_failure (dns, 4);
          SOCKET_ERROR_FMT ("Failed to create DNS worker thread %d", i);
          RAISE_DNS_ERROR (SocketDNS_Failed);
        }
    }
}

/**
 * start_dns_workers - Create and start worker thread pool
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed on thread creation failure
 * Creates worker threads and allocates thread array from arena.
 */
void
start_dns_workers (struct SocketDNS_T *dns)
{
  dns->workers = ALLOC (dns->arena, dns->num_workers * sizeof (pthread_t));
  if (!dns->workers)
    {
      cleanup_on_init_failure (dns, 4);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate worker thread array");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  memset (dns->request_hash, 0, sizeof (dns->request_hash));
  create_worker_threads (dns);
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

/**
 * free_request_list - Free all requests in a list
 * @head: Head of request list
 * Frees getaddrinfo results for all requests in list.
 * Request structures themselves are in Arena, so not freed here.
 */
void
free_request_list (Request_T head, int use_hash_next)
{
  Request_T curr = head;
  Request_T next;

  while (curr)
    {
      next = use_hash_next ? curr->hash_next : curr->queue_next;
      if (curr->result)
        {
          freeaddrinfo (curr->result);
          curr->result = NULL;
        }
      curr = next;
    }
}

/**
 * free_queued_requests - Free all requests in the request queue
 * @d: DNS resolver instance
 * Thread-safe: Must be called with mutex locked
 * Frees all requests currently in the processing queue.
 */
void
free_queued_requests (T d)
{
  free_request_list (d->queue_head, 0);
}

/**
 * free_hash_table_requests - Free all requests in hash table
 * @d: DNS resolver instance
 * Thread-safe: Must be called with mutex locked
 * Frees all requests currently registered in the hash table.
 */
void
free_hash_table_requests (T d)
{
  for (int i = 0; i < SOCKET_DNS_REQUEST_HASH_SIZE; i++)
    {
      free_request_list (d->request_hash[i], 1);
    }
}

/**
 * free_all_requests - Free all pending requests
 * @d: DNS resolver instance
 * Thread-safe: Must be called with mutex locked
 * Frees all requests from both queue and hash table.
 */
void
free_all_requests (T d)
{
  free_queued_requests (d);
  free_hash_table_requests (d);
}

/**
 * shutdown_workers - Signal and wait for worker threads
 * @d: DNS resolver instance
 * Signals shutdown and joins all worker threads.
 */
void
shutdown_workers (T d)
{
  int i;

  pthread_mutex_lock (&d->mutex);
  d->shutdown = 1;
  pthread_cond_broadcast (&d->queue_cond);
  pthread_mutex_unlock (&d->mutex);

  for (i = 0; i < d->num_workers; i++)
    {
      pthread_join (d->workers[i], NULL);
    }
}

/**
 * drain_completion_pipe - Drain completion pipe before cleanup
 * @dns: DNS resolver instance
 * Reads and discards any remaining completion notifications so that
 * subsequent close operations do not leave unread data in the pipe.
 */
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

/**
 * drain_completed_requests - Release results for completed requests
 * @dns: DNS resolver instance
 * Ensures any outstanding getaddrinfo() results owned by the resolver are
 * released prior to arena disposal. This is necessary when callers never
 * retrieve results (e.g., cancelled or overflowed requests).
 * Thread-safe: Must be called with mutex locked.
 */
void
drain_completed_requests (struct SocketDNS_T *dns)
{
  int i;

  for (i = 0; i < SOCKET_DNS_REQUEST_HASH_SIZE; i++)
    {
      struct SocketDNS_Request_T *req = dns->request_hash[i];

      while (req)
        {
          if (req->result)
            {
              freeaddrinfo (req->result);
              req->result = NULL;
            }
          req = req->hash_next;
        }
    }
}

/**
 * reset_dns_state - Reset internal DNS resolver state for shutdown
 * @d: DNS resolver instance
 * Thread-safe: Uses mutex to protect shared state
 * Drains completed requests, frees pending requests, resets queue and hash
 * table.
 */
void
reset_dns_state (T d)
{
  pthread_mutex_lock (&d->mutex);
  drain_completed_requests (d);
  free_all_requests (d);
  d->queue_head = NULL;
  d->queue_tail = NULL;
  d->queue_size = 0;
  for (int i = 0; i < SOCKET_DNS_REQUEST_HASH_SIZE; i++)
    d->request_hash[i] = NULL;
  pthread_mutex_unlock (&d->mutex);
}

/**
 * destroy_dns_resources - Destroy DNS resolver resources
 * @d: DNS resolver instance
 * Frees synchronization primitives, arena, and resolver structure itself.
 * Called after state reset and worker shutdown.
 */
void
destroy_dns_resources (T d)
{
  cleanup_pipe (d);
  cleanup_mutex_cond (d);
  Arena_dispose (&d->arena);
  free (d);
}

void
SocketDNS_free (T *dns)
{
  T d;

  if (!dns || !*dns)
    return;
  assert (dns && *dns);

  d = *dns;

  shutdown_workers (d);
  drain_completion_pipe (d);
  reset_dns_state (d);
  destroy_dns_resources (d);
  *dns = NULL;
}

/**
 * validate_resolve_params - Validate parameters for DNS resolution
 * @host: Hostname to validate (NULL allowed for wildcard bind)
 * @port: Port number to validate
 * Raises: SocketDNS_Failed on invalid parameters
 */
bool
is_ip_address (const char *host)
{
  if (!host)
    return false;

  struct in_addr ipv4;
  struct in6_addr ipv6;

  return inet_pton (AF_INET, host, &ipv4) == 1
         || inet_pton (AF_INET6, host, &ipv6) == 1;
}

int
validate_hostname (const char *hostname)
{
  if (!hostname)
    return 0;

  size_t len = strlen (hostname);
  if (len == 0 || len > SOCKET_ERROR_MAX_HOSTNAME)
    return 0;

  const char *p = hostname;
  int label_len = 0;
  bool new_label = true; /* Start of label */

  while (*p)
    {
      if (*p == '.')
        {
          if (new_label || label_len == 0
              || label_len > SOCKET_DNS_MAX_LABEL_LENGTH)
            return 0; /* Empty label or too long */
          new_label = true;
          label_len = 0;
        }
      else
        {
          if (new_label)
            {
              if (!isalnum ((unsigned char)*p))
                return 0; /* Label must start with alnum */
              new_label = false;
            }
          if (!isalnum ((unsigned char)*p) && *p != '-')
            return 0; /* Invalid char in label */
          if (*p == '-' && label_len == 0)
            return 0; /* Can't start label with - */
          label_len++;
          if (label_len > SOCKET_DNS_MAX_LABEL_LENGTH)
            return 0;
        }
      p++;
    }

  /* Final label check */
  if (new_label || label_len == 0 || label_len > SOCKET_DNS_MAX_LABEL_LENGTH)
    return 0;

  return 1;
}

void
validate_resolve_params (const char *host, int port)
{
  size_t host_len;

  if (host != NULL)
    {
      host_len = strlen (host);
      if (host_len == 0 || host_len > SOCKET_ERROR_MAX_HOSTNAME)
        {
          SOCKET_ERROR_MSG ("Invalid hostname length");
          RAISE_DNS_ERROR (SocketDNS_Failed);
        }

      if (!is_ip_address (host) && !validate_hostname (host))
        {
          SOCKET_ERROR_MSG ("Invalid hostname format");
          RAISE_DNS_ERROR (SocketDNS_Failed);
        }
    }

  if (!SOCKET_VALID_PORT (port))
    {
      SOCKET_ERROR_MSG ("Invalid port number");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
}

/**
 * allocate_request_structure - Allocate request structure
 * @dns: DNS resolver instance
 * Returns: Allocated request structure
 * Raises: SocketDNS_Failed on allocation failure
 * Allocates memory for the request structure from arena.
 */
Request_T
allocate_request_structure (struct SocketDNS_T *dns)
{

  Request_T req;
  req = ALLOC (dns->arena, sizeof (*req));
  if (!req)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate DNS request");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  return req;
}

/**
 * allocate_request_hostname - Allocate and copy hostname
 * @dns: DNS resolver instance
 * @req: Request structure to initialize
 * @host: Hostname to copy (NULL allowed for wildcard bind)
 * @host_len: Length of hostname (0 if host is NULL)
 * Raises: SocketDNS_Failed on allocation failure
 * Allocates memory for hostname and copies it. Sets req->host to NULL if host
 * is NULL.
 */
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

  req->host = ALLOC (dns->arena, host_len + 1);
  if (!req->host)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate hostname");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  strncpy (req->host, host, host_len + 1);
  req->host[host_len] = '\0';
}

/**
 * initialize_request_fields - Initialize request fields
 * @req: Request structure to initialize
 * @port: Port number
 * @callback: Completion callback
 * @data: User data for callback
 * Sets all request fields to initial values.
 */
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
  clock_gettime (CLOCK_MONOTONIC, &req->submit_time);
  req->timeout_override_ms = -1;
}

/**
 * allocate_request - Allocate and initialize request structure
 * @dns: DNS resolver instance
 * @host: Hostname to resolve
 * @host_len: Length of hostname
 * @port: Port number
 * @callback: Completion callback
 * @data: User data for callback
 * Returns: Allocated request structure
 * Raises: SocketDNS_Failed on allocation failure
 * Allocates and fully initializes a DNS request structure.
 */
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

/**
 * hash_table_insert - Insert request into hash table
 * @dns: DNS resolver instance
 * @req: Request to insert
 * Thread-safe: Must be called with mutex locked
 */
void
hash_table_insert (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  unsigned hash;

  hash = request_hash_function (req);
  req->hash_value = hash;
  req->hash_next = dns->request_hash[hash];
  dns->request_hash[hash] = req;
}

/**
 * queue_append - Append request to queue
 * @dns: DNS resolver instance
 * @req: Request to append
 * Thread-safe: Must be called with mutex locked
 */
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

/**
 * check_queue_limit - Check if queue has reached limit
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed if queue is full
 * Thread-safe: Must be called with mutex locked
 */
void
check_queue_limit (struct SocketDNS_T *dns)
{
  if (dns->queue_size >= dns->max_pending)
    {
      pthread_mutex_unlock (&dns->mutex);
      SOCKET_ERROR_MSG ("DNS request queue full (max %zu pending)",
                        dns->max_pending);
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
}

/**
 * submit_dns_request - Submit request to queue and hash table
 * @dns: DNS resolver instance
 * @req: Request to submit
 * Thread-safe: Must be called with mutex locked
 * Inserts request into hash table, appends to queue, and signals workers.
 */
void
submit_dns_request (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  hash_table_insert (dns, req);
  queue_append (dns, req);
  pthread_cond_signal (&dns->queue_cond);
}

Request_T
SocketDNS_resolve (struct SocketDNS_T *dns, const char *host, int port,
                   SocketDNS_Callback callback, void *data)
{

  size_t host_len;

  if (!dns)
    {
      SOCKET_ERROR_MSG ("Invalid NULL dns resolver");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
  assert (dns);

  host_len = host ? strlen (host) : 0;
  validate_resolve_params (host, port);
  Request_T req = allocate_request (dns, host, host_len, port, callback, data);

  pthread_mutex_lock (&dns->mutex);
  check_queue_limit (dns);
  submit_dns_request (dns, req);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_SUBMITTED, 1);
  pthread_mutex_unlock (&dns->mutex);

  return req;
}

/**
 * hash_table_remove - Remove request from hash table
 * @dns: DNS resolver instance
 * @req: Request to remove
 * Thread-safe: Must be called with mutex locked
 */
void
hash_table_remove (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  unsigned hash;
  Request_T *pp;

  hash = req->hash_value;
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

/**
 * remove_from_queue_head - Remove request from queue head
 * @dns: DNS resolver instance
 * @req: Request to remove
 */
void
remove_from_queue_head (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req)
{
  dns->queue_head = req->queue_next;
  if (!dns->queue_head)
    dns->queue_tail = NULL;
}

/**
 * remove_from_queue_middle - Remove request from queue middle/tail
 * @dns: DNS resolver instance
 * @req: Request to remove
 */
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

/**
 * queue_remove - Remove request from queue
 * @dns: DNS resolver instance
 * @req: Request to remove
 * Thread-safe: Must be called with mutex locked
 */
void
queue_remove (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  if (dns->queue_head == req)
    remove_from_queue_head (dns, req);
  else
    remove_from_queue_middle (dns, req);
  dns->queue_size--;
}

/**
 * cancel_pending_request - Cancel a pending request
 * @dns: DNS resolver instance
 * @req: Request to cancel
 * Thread-safe: Must be called with mutex locked
 */
void
cancel_pending_request (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req)
{
  queue_remove (dns, req);
  req->state = REQ_CANCELLED;
}

void
SocketDNS_cancel (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  Request_T r = req;
  int send_signal = 0;
  int cancelled = 0;

  if (!dns || !req)
    return;
  assert (dns);
  assert (req);

  pthread_mutex_lock (&dns->mutex);

  if (r->state == REQ_PENDING)
    {
      cancel_pending_request (dns, r);
      r->error = dns_cancellation_error ();
      send_signal = 1;
      cancelled = 1;
    }
  else if (r->state == REQ_PROCESSING)
    {
      r->state = REQ_CANCELLED;
      r->error = dns_cancellation_error ();
      send_signal = 1;
      cancelled = 1;
    }
  else if (r->state == REQ_COMPLETE)
    {
      if (r->result)
        {
          freeaddrinfo (r->result);
          r->result = NULL;
        }
      r->error = dns_cancellation_error ();
    }
  else if (r->state == REQ_CANCELLED)
    {
      if (r->error == 0)
        r->error = dns_cancellation_error ();
    }

  if (send_signal)
    {
      signal_completion (dns);
      pthread_cond_broadcast (&dns->result_cond);
    }

  hash_table_remove (dns, r);
  if (cancelled)
    SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_CANCELLED, 1);
  pthread_mutex_unlock (&dns->mutex);
}

size_t
SocketDNS_getmaxpending (struct SocketDNS_T *dns)
{
  size_t current;

  if (!dns)
    return 0;
  assert (dns);

  pthread_mutex_lock (&dns->mutex);
  current = dns->max_pending;
  pthread_mutex_unlock (&dns->mutex);

  return current;
}

void
SocketDNS_setmaxpending (struct SocketDNS_T *dns, size_t max_pending)
{
  size_t queue_depth;

  if (!dns)
    {
      SOCKET_ERROR_MSG ("Invalid NULL dns resolver");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
  assert (dns);

  pthread_mutex_lock (&dns->mutex);
  queue_depth = dns->queue_size;
  if (max_pending < queue_depth)
    {
      pthread_mutex_unlock (&dns->mutex);
      SOCKET_ERROR_MSG (
          "Cannot set max pending (%zu) below current queue depth (%zu)",
          max_pending, queue_depth);
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  dns->max_pending = max_pending;
  pthread_mutex_unlock (&dns->mutex);
}

int
SocketDNS_gettimeout (struct SocketDNS_T *dns)
{
  int current;

  if (!dns)
    return 0;
  assert (dns);

  pthread_mutex_lock (&dns->mutex);
  current = dns->request_timeout_ms;
  pthread_mutex_unlock (&dns->mutex);

  return current;
}

void
SocketDNS_settimeout (struct SocketDNS_T *dns, int timeout_ms)
{
  int sanitized = timeout_ms < 0 ? 0 : timeout_ms;

  if (!dns)
    return;
  assert (dns);

  pthread_mutex_lock (&dns->mutex);
  dns->request_timeout_ms = sanitized;
  pthread_mutex_unlock (&dns->mutex);
}

int
SocketDNS_pollfd (struct SocketDNS_T *dns)
{
  if (!dns)
    return -1;
  assert (dns);
  return dns->pipefd[0];
}

int
SocketDNS_check (struct SocketDNS_T *dns)
{
  char buffer[SOCKET_DNS_PIPE_BUFFER_SIZE];
  ssize_t n;
  volatile int count = 0;

  if (!dns)
    return 0;
  assert (dns);

  /* Check if pipe is still valid (may be closed during shutdown) */
  if (dns->pipefd[0] < 0)
    return 0;

  /* Read all available data from pipe (non-blocking) */
  while ((n = read (dns->pipefd[0], buffer, sizeof (buffer))) > 0)
    {
      count += n;
    }

  /* EAGAIN/EWOULDBLOCK means no data available - not an error */
  if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    {
      /* Real error - but don't raise exception, just return count */
      return count;
    }

  return count;
}

struct addrinfo *
SocketDNS_getresult (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  Request_T r = req;
  struct addrinfo *result = NULL;

  if (!dns || !req)
    return NULL;
  assert (dns);
  assert (req);

  pthread_mutex_lock (&dns->mutex);

  if (r->state == REQ_COMPLETE)
    {
      /* If callback was provided, result ownership was transferred to callback
       */
      if (r->callback)
        {
          /* Callback already received the result - it's been consumed */
          result = NULL;
        }
      else
        {
          /* No callback - transfer ownership to caller */
          result = r->result;
          r->result = NULL;
        }

      hash_table_remove (dns, r);
    }

  pthread_mutex_unlock (&dns->mutex);

  return result;
}

int
SocketDNS_geterror (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  Request_T r = req;
  int error = 0;

  if (!dns || !req)
    return 0;
  assert (dns);
  assert (req);

  pthread_mutex_lock (&dns->mutex);
  if (r->state == REQ_COMPLETE || r->state == REQ_CANCELLED)
    error = r->error;
  pthread_mutex_unlock (&dns->mutex);

  return error;
}

Request_T
SocketDNS_create_completed_request (struct SocketDNS_T *dns,
                                    struct addrinfo *result, int port)
{

  if (!dns || !result)
    {
      SOCKET_ERROR_MSG (
          "Invalid NULL dns or result in create_completed_request");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
  assert (dns);
  assert (result);

  validate_resolve_params (NULL, port);

  Request_T req = allocate_request_structure (dns);
  req->host = NULL;
  req->port = port;
  req->callback = NULL;
  req->callback_data = NULL;
  req->state = REQ_COMPLETE;
  req->result = SocketCommon_copy_addrinfo (result);
  if (!req->result)
    {
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
  freeaddrinfo (result);
  req->error = 0;
  req->queue_next = NULL;
  req->hash_next = NULL;
  clock_gettime (CLOCK_MONOTONIC, &req->submit_time);
  req->timeout_override_ms = -1;

  pthread_mutex_lock (&dns->mutex);
  hash_table_insert (dns, req);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_COMPLETED, 1);
  signal_completion (dns);
  pthread_cond_broadcast (&dns->result_cond);
  pthread_mutex_unlock (&dns->mutex);

  return req;
}

void
SocketDNS_request_settimeout (struct SocketDNS_T *dns,
                              struct SocketDNS_Request_T *req, int timeout_ms)
{
  Request_T r = req;
  int sanitized = timeout_ms < 0 ? 0 : timeout_ms;

  if (!dns || !req)
    return;
  assert (dns);
  assert (req);

  pthread_mutex_lock (&dns->mutex);
  if (r->state == REQ_PENDING || r->state == REQ_PROCESSING)
    r->timeout_override_ms = sanitized;
  pthread_mutex_unlock (&dns->mutex);
}

#undef T
#undef T
#undef Request_T
