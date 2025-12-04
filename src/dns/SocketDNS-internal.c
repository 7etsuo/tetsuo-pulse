/**
 * SocketDNS-internal.c - Internal implementation for async DNS resolution
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Contains:
 * - Initialization and allocation functions
 * - Synchronization primitives (mutex, condition variables, pipe)
 * - Cleanup and shutdown functions
 * - Request allocation and queue management
 * - Timeout handling
 * - Worker thread implementation
 */

/* All includes before T macro definition to avoid redefinition warnings */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "dns/SocketDNS.h"
#include "dns/SocketDNS-private.h"

/* Redefine T after all includes (Arena.h and SocketDNS.h both undef T at end) */
#undef T
#define T SocketDNS_T
#undef Request_T
#define Request_T SocketDNS_Request_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS-internal"

/*
 * =============================================================================
 * Synchronization - Mutex and Condition Variables
 * =============================================================================
 */

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
      cleanup_on_init_failure (dns, DNS_CLEAN_PIPE);
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
      cleanup_on_init_failure (dns, DNS_CLEAN_ARENA);
      SOCKET_ERROR_FMT ("Failed to get pipe flags");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  if (fcntl (dns->pipefd[0], F_SETFL, flags | O_NONBLOCK) < 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_ARENA);
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

/*
 * =============================================================================
 * Initialization - Resolver Allocation and Setup
 * =============================================================================
 */

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
 * Note: dns was allocated with calloc, so zero/NULL fields are already set.
 * Only non-zero defaults need explicit initialization.
 */
void
initialize_dns_fields (struct SocketDNS_T *dns)
{
  dns->num_workers = SOCKET_DNS_THREAD_COUNT;
  dns->max_pending = SOCKET_DNS_MAX_PENDING;
  dns->request_timeout_ms = SOCKET_DEFAULT_DNS_TIMEOUT_MS;
  /* shutdown, queue_head/tail/size already 0/NULL from calloc */
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
 * setup_thread_attributes - Configure pthread attributes for worker threads
 * @attr: Thread attributes to configure
 * Raises: SocketDNS_Failed on attribute setup failure
 */
void
setup_thread_attributes (pthread_attr_t *attr)
{
  pthread_attr_init (attr);
  pthread_attr_setdetachstate (attr, PTHREAD_CREATE_JOINABLE);
  pthread_attr_setstacksize (attr, SOCKET_DNS_WORKER_STACK_SIZE);
}

/**
 * cleanup_partial_workers - Join already-created workers on failure
 * @dns: DNS resolver instance
 * @created_count: Number of threads successfully created
 */
static void
cleanup_partial_workers (struct SocketDNS_T *dns, int created_count)
{
  dns->shutdown = 1;
  pthread_cond_broadcast (&dns->queue_cond);

  for (int j = 0; j < created_count; j++)
    pthread_join (dns->workers[j], NULL);
}

/**
 * set_worker_thread_name - Set thread name for debugging
 * @dns: DNS resolver instance
 * @thread_index: Index of thread to name
 */
static void
set_worker_thread_name (struct SocketDNS_T *dns, int thread_index)
{
#ifdef PTHREAD_SET_NAME_SUPPORTED
  char thread_name[SOCKET_DNS_THREAD_NAME_SIZE];
  snprintf (thread_name, sizeof (thread_name), "dns-worker-%d", thread_index);
  pthread_setname_np (dns->workers[thread_index], thread_name);
#else
  (void)dns;
  (void)thread_index;
#endif
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
          cleanup_on_init_failure (dns, DNS_CLEAN_ARENA);
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
      cleanup_on_init_failure (dns, DNS_CLEAN_ARENA);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate worker thread array");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
  create_worker_threads (dns);
}

/*
 * =============================================================================
 * Cleanup - Shutdown and Resource Deallocation
 * =============================================================================
 */

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
 * free_request_list - Free all requests in a list
 * @head: Head of request list
 * @use_hash_next: If true, traverse via hash_next; else via queue_next
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
          SocketCommon_free_addrinfo (curr->result);
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
 * reset_dns_state - Reset internal DNS resolver state for shutdown
 * @d: DNS resolver instance
 * Thread-safe: Uses mutex to protect shared state
 * Frees all requests (including their results), resets queue and hash table.
 */
void
reset_dns_state (T d)
{
  pthread_mutex_lock (&d->mutex);
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

/*
 * =============================================================================
 * Request Management - Allocation, Queue, and Hash Table
 * =============================================================================
 */

/**
 * request_hash_function - Calculate hash for request pointer
 * @req: Request pointer to hash (read-only, const)
 *
 * Returns: Hash value in range [0, SOCKET_DNS_REQUEST_HASH_SIZE)
 * Thread-safe: Yes - no shared state modified, pure function
 *
 * Uses socket_util_hash_ptr() for golden ratio multiplicative hashing.
 */
unsigned
request_hash_function (const struct SocketDNS_Request_T *req)
{
  return socket_util_hash_ptr (req, SOCKET_DNS_REQUEST_HASH_SIZE);
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
 * Raises: SocketDNS_Failed on allocation failure or overflow
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

  /* Overflow check - defensive (already limited by validate_hostname) */
  if (host_len > SIZE_MAX - 1)
    {
      SOCKET_ERROR_MSG ("Hostname length overflow");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  req->host = ALLOC (dns->arena, host_len + 1);
  if (!req->host)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate hostname");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  memcpy (req->host, host, host_len);
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
 * check_queue_limit - Check if queue has reached limit
 * @dns: DNS resolver instance
 * Returns: 1 if queue is full, 0 otherwise
 * Thread-safe: Must be called with mutex locked
 * Note: Does NOT unlock mutex - caller is responsible for cleanup
 */
int
check_queue_limit (const struct SocketDNS_T *dns)
{
  return dns->queue_size >= dns->max_pending;
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

/*
 * =============================================================================
 * Timeout Handling
 * =============================================================================
 */

/**
 * request_effective_timeout_ms - Get effective timeout for request
 * @dns: DNS resolver instance (read-only for default timeout)
 * @req: Request to check (read-only)
 *
 * Returns: Per-request timeout override if >= 0, else default resolver timeout
 * Thread-safe: Must be called with mutex locked (reads dns->request_timeout_ms)
 *
 * Allows per-request timeout customization while falling back to resolver-wide
 * default when no override is specified (timeout_override_ms < 0).
 */
int
request_effective_timeout_ms (const struct SocketDNS_T *dns,
                              const struct SocketDNS_Request_T *req)
{
  if (req->timeout_override_ms >= 0)
    return req->timeout_override_ms;
  return dns->request_timeout_ms;
}

/**
 * request_timed_out - Check if request has timed out
 * @dns: DNS resolver instance (read-only for timeout config)
 * @req: Request to check (read-only)
 *
 * Returns: 1 if timed out, 0 otherwise (including when timeout disabled)
 * Thread-safe: Yes - read-only access to req state
 *
 * Uses CLOCK_MONOTONIC for reliable elapsed time calculation that is
 * immune to system clock adjustments. Returns 0 if effective timeout <= 0
 * (timeout disabled).
 */
int
request_timed_out (const struct SocketDNS_T *dns,
                   const struct SocketDNS_Request_T *req)
{
  int timeout_ms = request_effective_timeout_ms (dns, req);
  struct timespec now;
  long long elapsed_ms;

  if (timeout_ms <= 0)
    return 0;

  clock_gettime (CLOCK_MONOTONIC, &now);

  elapsed_ms = (now.tv_sec - req->submit_time.tv_sec) * SOCKET_MS_PER_SECOND;
  elapsed_ms += (now.tv_nsec - req->submit_time.tv_nsec) / SOCKET_NS_PER_MS;

  return elapsed_ms >= timeout_ms;
}

/**
 * mark_request_timeout - Mark request as timed out
 * @dns: DNS resolver instance
 * @req: Request to mark as timed out
 * Sets state to complete with timeout error, frees result if any, signals
 * completion. Thread-safe: Must be called with mutex locked.
 */
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

/**
 * handle_request_timeout - Handle request timeout case
 * @dns: DNS resolver instance
 * @req: Request that timed out
 * Thread-safe: Uses mutex internally
 * Marks request as timed out, signals completion, emits event.
 */
void
handle_request_timeout (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req)
{
  pthread_mutex_lock (&dns->mutex);
  mark_request_timeout (dns, req);
  pthread_mutex_unlock (&dns->mutex);
}

/*
 * =============================================================================
 * Worker Thread Implementation
 * =============================================================================
 */

/**
 * initialize_addrinfo_hints - Initialize getaddrinfo hints structure
 * @hints: Hints structure to initialize
 * Sets up hints for DNS resolution with AF_UNSPEC (IPv4/IPv6).
 * Thread-safe: Yes - no shared state
 */
void
initialize_addrinfo_hints (struct addrinfo *hints)
{
  memset (hints, 0, sizeof (*hints));
  hints->ai_family = AF_UNSPEC;
  hints->ai_socktype = SOCK_STREAM;
  hints->ai_protocol = 0;
}

/**
 * dequeue_request - Dequeue next request from queue
 * @dns: DNS resolver instance
 * Returns: Next request or NULL if queue empty
 * Thread-safe: Must be called with mutex locked
 *
 * Reuses remove_from_queue_head() for queue manipulation to avoid
 * code duplication. Sets request state to REQ_PROCESSING.
 */
Request_T
dequeue_request (struct SocketDNS_T *dns)
{
  struct SocketDNS_Request_T *req;

  if (!dns->queue_head)
    return NULL;

  req = dns->queue_head;
  remove_from_queue_head (dns, req);
  dns->queue_size--;
  req->queue_next = NULL;
  req->state = REQ_PROCESSING;

  return req;
}

/**
 * wait_for_request - Wait for next request or shutdown
 * @dns: DNS resolver instance
 * Returns: Request to process, or NULL if shutdown
 * Thread-safe: Must be called with mutex locked, returns with mutex locked
 *
 * NOTE: Caller is responsible for unlocking the mutex after this returns.
 * This function does NOT unlock the mutex on any path.
 */
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

/**
 * signal_completion - Signal completion via pipe
 * @dns: DNS resolver instance
 * Writes completion signal to pipe. Non-blocking best-effort operation.
 * Pipe may be full, which is acceptable - signals are cumulative.
 * Thread-safe: Yes - write to pipe[1] is atomic for 1 byte
 */
void
signal_completion (struct SocketDNS_T *dns)
{
  char byte = COMPLETION_SIGNAL_BYTE;
  ssize_t n;

  n = write (dns->pipefd[1], &byte, 1);
  (void)n; /* Ignore result - pipe may be full, that's OK */
}

/**
 * dns_cancellation_error - Get appropriate error code for cancelled request
 * Returns: EAI_CANCELLED if defined, else EAI_AGAIN
 * Used for consistent error reporting on cancellation.
 */
int
dns_cancellation_error (void)
{
#ifdef EAI_CANCELLED
  return EAI_CANCELLED;
#else
  return EAI_AGAIN;
#endif
}

/**
 * perform_dns_resolution - Perform actual DNS lookup
 * @req: Request containing hostname and port (read-only)
 * @hints: getaddrinfo hints structure (read-only)
 * @result: Output - set to resolved addresses (caller owns) or NULL on error
 *
 * Returns: getaddrinfo result code (0 on success, EAI_* on failure)
 * Thread-safe: Yes - getaddrinfo is thread-safe per POSIX
 *
 * Performs DNS resolution with optional port parameter. Handles NULL
 * host (wildcard bind) by passing NULL to getaddrinfo with AI_PASSIVE flag.
 * Note: getaddrinfo() is a blocking call and is not interruptible.
 */
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

/**
 * copy_and_store_result - Copy result and store in request
 * @req: Request to store result in
 * @result: Original result to copy and free
 * @error: Error code from resolution (preserved if non-zero)
 *
 * Thread-safe: Must be called with mutex locked
 *
 * Error handling: If result is NULL and error is non-zero, the provided error
 * is preserved (e.g., EAI_AGAIN for timeouts). Only sets EAI_MEMORY if result
 * is NULL and error is 0 (indicating an actual allocation failure during copy).
 */
static void
copy_and_store_result (struct SocketDNS_Request_T *req,
                       struct addrinfo *result, int error)
{
  req->state = REQ_COMPLETE;
  req->result = SocketCommon_copy_addrinfo (result);

  /* Preserve non-zero error codes (e.g., EAI_AGAIN for timeout).
   * Only set EAI_MEMORY if copy failed with no prior error. */
  if (req->result)
    req->error = error;
  else if (error != 0)
    req->error = error; /* Preserve original error (timeout, etc.) */
  else
    req->error = EAI_MEMORY; /* Copy failed with no prior error */

  if (result)
    freeaddrinfo (result);
}

/**
 * update_completion_metrics - Update metrics for completed request
 * @error: Error code (0 on success)
 */
static void
update_completion_metrics (int error)
{
  if (error == 0)
    SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_COMPLETED, 1);
  else
    SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_FAILED, 1);
}

/**
 * handle_cancelled_result - Handle result for cancelled request
 * @dns: DNS resolver instance
 * @req: Cancelled request
 * @result: Result to free
 *
 * Thread-safe: Must be called with mutex locked
 */
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

/**
 * store_resolution_result - Store completed DNS resolution result
 * @dns: DNS resolver instance
 * @req: Request being completed
 * @result: Resolution result from getaddrinfo (ownership transferred)
 * @error: Error code from getaddrinfo (0 on success)
 *
 * Thread-safe: Must be called with mutex locked
 */
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

/**
 * prepare_local_hints - Prepare local hints copy with request-specific flags
 * @local_hints: Output - local hints structure to initialize
 * @base_hints: Base hints to copy from (read-only)
 * @req: Request determining flags (read-only)
 *
 * Thread-safe: Yes - no shared state
 *
 * Copies base hints and adds AI_PASSIVE flag when host is NULL (wildcard bind).
 */
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

/**
 * handle_resolution_result - Handle post-resolution logic under mutex
 * @dns: DNS resolver instance
 * @req: Request to update
 * @result: Resolution result (may be freed if timed out)
 * @res: Resolution error code (may be overridden if timed out)
 * Thread-safe: Locks mutex internally.
 * Checks for timeout after resolution, frees result if timed out, stores result.
 */
void
handle_resolution_result (struct SocketDNS_T *dns,
                          struct SocketDNS_Request_T *req,
                          struct addrinfo *result, int res)
{
  pthread_mutex_lock (&dns->mutex);
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
  pthread_mutex_unlock (&dns->mutex);
}

/**
 * invoke_callback - Invoke completion callback if provided
 * @dns: DNS resolver instance
 * @req: Completed request
 * Thread-safe: Called without mutex held (callback may take time); locks
 * briefly to clear result.
 * Note: Callback receives ownership of result. Clears req->result after to
 * prevent use-after-free. SocketDNS_getresult() returns NULL if callback provided.
 */
void
invoke_callback (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  if (req->callback && req->state == REQ_COMPLETE)
    {
      /* Callback receives ownership of result */
      struct addrinfo *result = req->result;
      req->callback (req, result, req->error, req->callback_data);

      /* Clear result pointer after callback to prevent use-after-free.
       * Callback has taken ownership and freed it. */
      pthread_mutex_lock (&dns->mutex);
      req->result = NULL;
      pthread_mutex_unlock (&dns->mutex);
    }
}

/**
 * process_single_request - Process one DNS resolution request
 * @dns: DNS resolver instance
 * @req: Request to process
 * @base_hints: Base getaddrinfo hints structure
 * Performs DNS resolution for one request: timeout check, hints prep,
 * resolution, result handling, callback invocation.
 * Thread-safe: No - called from worker thread, uses mutex for shared state.
 */
void
process_single_request (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req,
                        const struct addrinfo *base_hints)
{
  /* Acquire mutex before checking timeout to prevent race with
   * SocketDNS_request_settimeout() which modifies timeout_override_ms.
   * The main thread writes under mutex, so we must also read under mutex. */
  pthread_mutex_lock (&dns->mutex);
  if (request_timed_out (dns, req))
    {
      /* Call mark_request_timeout directly since we already hold mutex
       * (handle_request_timeout would deadlock by trying to lock again) */
      mark_request_timeout (dns, req);
      pthread_mutex_unlock (&dns->mutex);
      return;
    }
  pthread_mutex_unlock (&dns->mutex);

  struct addrinfo local_hints;
  prepare_local_hints (&local_hints, base_hints, req);

  struct addrinfo *result = NULL;
  int res = perform_dns_resolution (req, &local_hints, &result);

  handle_resolution_result (dns, req, result, res);

  invoke_callback (dns, req);
}

/**
 * worker_thread - Worker thread for DNS resolution
 * @arg: DNS resolver instance
 * Returns: NULL
 * Worker thread that processes DNS resolution requests from queue.
 * Blocks waiting for requests, performs resolution, stores results.
 * Thread-safe: Uses mutex/cond for synchronization
 */
void *
worker_thread (void *arg)
{
  struct SocketDNS_T *dns = (T)arg;
  struct addrinfo hints;

  initialize_addrinfo_hints (&hints);

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

  return NULL;
}

#undef T
#undef Request_T

