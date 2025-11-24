/**
 * SocketDNS-init.c - Initialization and cleanup helpers for async DNS resolution
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Contains DNS resolver initialization, cleanup, and lifecycle management
 * functions.
 */

#include "core/SocketConfig.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketError.h"
#include "core/SocketEvents.h"
#include "core/SocketMetrics.h"
#include "dns/SocketDNS.h"
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS-init"
#define T SocketDNS_T
#define Request_T SocketDNS_Request_T
#include "dns/SocketDNS-private.h"
#include "socket/SocketCommon.h"

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
 * @thread_index: Thread index for naming
 * Raises: SocketDNS_Failed on attribute setup failure
 */
void
setup_thread_attributes (pthread_attr_t *attr, int thread_index)
{
  char thread_name[16];

  pthread_attr_init (attr);
  pthread_attr_setdetachstate (attr, PTHREAD_CREATE_JOINABLE);
  pthread_attr_setstacksize (
      attr, SOCKET_DNS_WORKER_STACK_SIZE); /* Conservative stack size for DNS
                                              workers */

  snprintf (thread_name, sizeof (thread_name), "dns-worker-%d", thread_index);
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

  setup_thread_attributes (&attr, thread_index);
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

#undef T
#undef Request_T
