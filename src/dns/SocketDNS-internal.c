/**
 * @file SocketDNS-internal.c
 * @ingroup dns
 * @brief Internal implementation for async DNS resolution.
 *
 * Core implementation details for the DNS resolver module.
 * Contains thread pool management, request processing, synchronization,
 * and cleanup operations.
 *
 * @see SocketDNS.c for public API implementation.
 * @see SocketDNS.h for public API declarations.
 * @see SocketDNS-private.h for internal structures.
 */

/* All includes before T macro definition to avoid redefinition warnings */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/SocketSecurity.h"
#include "dns/SocketDNS-private.h"
#include "dns/SocketDNS.h"

/* Redefine T after all includes (Arena.h and SocketDNS.h both undef T at end)
 */
#undef T
#define T SocketDNS_T
/* Request_T is now properly typedef'd in SocketDNS.h */

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS-internal"

/**
 * Thread-local exception for detailed error messages.
 *
 * Each compilation unit that uses SOCKET_RAISE_MSG/FMT/MODULE_ERROR macros
 * with a module name must declare its own thread-local exception variable.
 * The 'static __thread' storage class ensures:
 * - Internal linkage (no symbol conflicts between files)
 * - Thread-local storage (safe for concurrent exception raising)
 *
 * Both SocketDNS.c and SocketDNS-internal.c need this declaration because
 * they each use SOCKET_RAISE_MSG(SocketDNS, ...) which expands to use
 * SocketDNS_DetailedException.
 */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketDNS);

/*
 * =============================================================================
 * Synchronization - Mutex and Condition Variables
 * =============================================================================
 */

/**
 * initialize_mutex - Initialize mutex for DNS resolver
 * @dns: DNS resolver instance
 *
 * Raises: SocketDNS_Failed on initialization failure
 */
void
initialize_mutex (struct SocketDNS_T *dns)
{
  if (pthread_mutex_init (&dns->mutex, NULL) != 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_NONE);
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "Failed to initialize DNS resolver mutex");
    }
}

/**
 * initialize_queue_condition - Initialize queue condition variable
 * @dns: DNS resolver instance
 *
 * Raises: SocketDNS_Failed on initialization failure
 */
void
initialize_queue_condition (struct SocketDNS_T *dns)
{
  if (pthread_cond_init (&dns->queue_cond, NULL) != 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_MUTEX);
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "Failed to initialize DNS resolver queue condition");
    }
}

/**
 * initialize_result_condition - Initialize result condition variable
 * @dns: DNS resolver instance
 *
 * Raises: SocketDNS_Failed on initialization failure
 */
void
initialize_result_condition (struct SocketDNS_T *dns)
{
  if (pthread_cond_init (&dns->result_cond, NULL) != 0)
    {
      cleanup_on_init_failure (dns, DNS_CLEAN_CONDS);
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "Failed to initialize DNS resolver result condition");
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
      SOCKET_RAISE_FMT (SocketDNS, SocketDNS_Failed,
                        "Failed to create completion pipe");
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
      SOCKET_RAISE_FMT (SocketDNS, SocketDNS_Failed,
                        "Failed to set close-on-exec flag on pipe");
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
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        SOCKET_ENOMEM ": Cannot allocate DNS resolver");
    }

  return dns;
}

/**
 * initialize_dns_fields - Set default field values for DNS resolver
 * @dns: DNS resolver instance
 *
 * Initializes configuration fields to non-zero default values.
 * Note: dns was allocated with calloc, so zero/NULL fields are already set.
 * Only non-zero defaults need explicit initialization here.
 */
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
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        SOCKET_ENOMEM ": Cannot allocate DNS resolver arena");
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
 *
 * Thread-safe: No - called during initialization before threads are fully up
 */
static void
cleanup_partial_workers (struct SocketDNS_T *dns, int created_count)
{
  dns->shutdown = 1;
  pthread_cond_broadcast (&dns->queue_cond);

  for (int i = 0; i < created_count; i++)
    pthread_join (dns->workers[i], NULL);
}

/**
 * set_worker_thread_name - Set thread name for debugging
 * @dns: DNS resolver instance
 * @thread_index: Index of thread to name
 *
 * Uses pthread_setname_np() on supported platforms (Linux, macOS).
 * Thread names aid debugging in tools like gdb, htop, and ps.
 */
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
          SOCKET_RAISE_FMT (SocketDNS, SocketDNS_Failed,
                            "Failed to create DNS worker thread %d", i);
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
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        SOCKET_ENOMEM ": Cannot allocate worker thread array");
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
 *
 * Safely closes both pipe file descriptors and marks them invalid.
 */
void
cleanup_pipe (struct SocketDNS_T *dns)
{
  for (int i = 0; i < 2; i++)
    {
      if (dns->pipefd[i] >= 0)
        {
          SAFE_CLOSE (dns->pipefd[i]);
          dns->pipefd[i] = -1;
        }
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
 *
 * Thread-safe: Yes - uses mutex internally, safe to call from main thread
 *
 * Signals shutdown and joins all worker threads. Blocks until all workers
 * have terminated.
 */
void
shutdown_workers (T d)
{
  pthread_mutex_lock (&d->mutex);
  d->shutdown = 1;
  pthread_cond_broadcast (&d->queue_cond);
  pthread_mutex_unlock (&d->mutex);

  for (int i = 0; i < d->num_workers; i++)
    pthread_join (d->workers[i], NULL);
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
 * free_queue_request_results - Free addrinfo results for queue-linked requests
 * @head: Head of queue-linked request list
 *
 * Traverses via queue_next, freeing getaddrinfo results.
 * Request structures themselves are in Arena, so not freed here.
 */
static void
free_queue_request_results (Request_T head)
{
  Request_T curr = head;

  while (curr)
    {
      Request_T next = curr->queue_next;
      if (curr->result)
        {
          SocketCommon_free_addrinfo (curr->result);
          curr->result = NULL;
        }
      curr = next;
    }
}

/**
 * free_hash_request_results - Free addrinfo results for hash-linked requests
 * @head: Head of hash-linked request list
 *
 * Traverses via hash_next, freeing getaddrinfo results.
 * Request structures themselves are in Arena, so not freed here.
 */
static void
free_hash_request_results (Request_T head)
{
  Request_T curr = head;

  while (curr)
    {
      Request_T next = curr->hash_next;
      if (curr->result)
        {
          SocketCommon_free_addrinfo (curr->result);
          curr->result = NULL;
        }
      curr = next;
    }
}

/**
 * free_all_requests - Free all pending requests
 * @d: DNS resolver instance
 *
 * Thread-safe: Must be called with mutex locked.
 * Frees getaddrinfo results from both queue and hash table.
 */
void
free_all_requests (T d)
{
  /* Free queue-linked requests */
  free_queue_request_results (d->queue_head);

  /* Free hash-linked requests */
  for (int i = 0; i < SOCKET_DNS_REQUEST_HASH_SIZE; i++)
    free_hash_request_results (d->request_hash[i]);
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
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        SOCKET_ENOMEM ": Cannot allocate DNS request");
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
 *
 * Security: Bounds-checks hash_value to prevent out-of-bounds access
 * from corrupted request handles or use-after-free scenarios.
 */
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
 * Thread-safe: Must be called with mutex locked (reads
 * dns->request_timeout_ms)
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
 * calculate_elapsed_ms - Calculate elapsed milliseconds between two monotonic
 * timestamps
 * @start: Starting timestamp (earlier in time)
 * @end: Ending timestamp (later in time)
 *
 * Returns: Elapsed milliseconds, or LLONG_MAX on overflow/clock error (treat
 * as timed out) Thread-safe: Yes - pure function, no shared state or side
 * effects
 *
 * Computes precise elapsed time using secure arithmetic to prevent overflow.
 * Assumes monotonic clock (end >= start). Handles nsec borrow from sec_delta.
 * Uses SocketSecurity_check_multiply for safe sec * 1000 conversion.
 * @see request_timed_out() for usage in timeout checks.
 */
static long long
calculate_elapsed_ms (const struct timespec *start, const struct timespec *end)
{
  long long sec_delta = (long long)end->tv_sec - (long long)start->tv_sec;
  long long nsec_delta = (long long)end->tv_nsec - (long long)start->tv_nsec;
  size_t sec_delta_u;
  size_t sec_ms_u;
  long long sec_ms;
  long long nsec_ms;

  /* Clock error - monotonic should not decrease */
  if (sec_delta < 0)
    return 0LL;

  /* Handle nanosecond borrow */
  if (nsec_delta < 0)
    {
      sec_delta--;
      nsec_delta += SOCKET_NS_PER_SECOND;
    }

  /* Safe overflow check for sec * 1000 */
  sec_delta_u = (size_t)sec_delta;
  if (!SocketSecurity_check_multiply (sec_delta_u,
                                      (size_t)SOCKET_MS_PER_SECOND, &sec_ms_u))
    return LLONG_MAX; /* Overflow: treat as very long elapsed */

  sec_ms = (long long)sec_ms_u;
  nsec_ms = nsec_delta / (long long)SOCKET_NS_PER_MS;

  return sec_ms + nsec_ms;
}

/**
 * request_timed_out - Check if request has timed out
 * @dns: DNS resolver instance (read-only for timeout config)
 * @req: Request to check (read-only)
 *
 * Returns: 1 if timed out, 0 otherwise (including when timeout disabled)
 * Thread-safe: Yes - read-only access to req state and pure elapsed
 * calculation
 *
 * Uses CLOCK_MONOTONIC via calculate_elapsed_ms() for reliable timing immune
 * to system clock adjustments. Returns 0 if effective timeout <= 0 (disabled).
 * Overflow or clock error treated as timeout for safety.
 * @see calculate_elapsed_ms() for low-level time delta computation.
 */
int
request_timed_out (const struct SocketDNS_T *dns,
                   const struct SocketDNS_Request_T *req)
{
  int timeout_ms = request_effective_timeout_ms (dns, req);
  if (timeout_ms <= 0)
    return 0;

  struct timespec now;
  clock_gettime (CLOCK_MONOTONIC, &now);

  long long elapsed_ms = calculate_elapsed_ms (&req->submit_time, &now);

  /* Overflow or timeout exceeded */
  if (elapsed_ms == LLONG_MAX || elapsed_ms >= (long long)timeout_ms)
    return 1;

  return 0;
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
 *
 * Returns: Next request or NULL if queue empty
 * Thread-safe: Must be called with mutex locked
 *
 * Pops the head request and transitions it to REQ_PROCESSING state.
 */
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
 * Error handling: Preserves non-zero error codes (e.g., EAI_AGAIN for timeout).
 * Sets EAI_MEMORY only if copy fails with no prior error.
 */
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
 * Copies base hints and adds AI_PASSIVE flag when host is NULL (wildcard
 * bind).
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
 * Checks for timeout after resolution, frees result if timed out, stores
 * result.
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
 *
 * Thread-safe: Acquires mutex briefly to safely extract callback info,
 * releases before invoking callback (which may take arbitrary time),
 * then re-acquires to clear result pointer.
 *
 * Security: Callback receives ownership of result and callback pointer is
 * cleared after invocation to prevent use-after-free or double invocation.
 * Both result and callback are NULLed post-invoke. SocketDNS_getresult()
 * returns NULL if callback was provided (ownership transferred).
 */
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

/**
 * check_pre_processing_timeout - Check timeout before starting DNS resolution
 * processing
 * @dns: DNS resolver instance
 * @req: Request to check
 *
 * Returns: 1 if timed out (marked and signaled), 0 if should proceed
 * Thread-safe: Locks mutex internally, caller does not need to hold it
 *
 * Acquires mutex, checks timeout using request_timed_out(), marks/signals if
 * timed out. Unlocks mutex before returning. Prevents race with
 * SocketDNS_request_settimeout(). Directly calls mark_request_timeout() to
 * avoid deadlock (already holds mutex).
 */
static int
check_pre_processing_timeout (struct SocketDNS_T *dns,
                              struct SocketDNS_Request_T *req)
{
  pthread_mutex_lock (&dns->mutex);
  if (request_timed_out (dns, req))
    {
      /* Call mark_request_timeout directly since we already hold mutex
       * (handle_request_timeout would deadlock by trying to lock again) */
      mark_request_timeout (dns, req);
      pthread_mutex_unlock (&dns->mutex);
      return 1;
    }
  pthread_mutex_unlock (&dns->mutex);
  return 0;
}

/**
 * process_single_request - Process one DNS resolution request
 * @dns: DNS resolver instance
 * @req: Request to process
 * @base_hints: Base getaddrinfo hints structure
 *
 * Performs DNS resolution for one request: timeout check, hints prep,
 * resolution, result handling, callback invocation.
 * Thread-safe: No - called from worker thread, uses mutex for shared state.
 * @see check_pre_processing_timeout() for initial timeout check.
 */
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
