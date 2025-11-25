/**
 * SocketDNS-init.c - Initialization helpers for async DNS resolution
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Contains DNS resolver allocation and initialization functions.
 */

/* All includes before T macro definition to avoid redefinition warnings */
#include <stdlib.h>

#include "core/Arena.h"
#include "dns/SocketDNS.h"
#include "dns/SocketDNS-private.h"

/* Redefine T after all includes (Arena.h and SocketDNS.h both undef T at end) */
#undef T
#define T SocketDNS_T
#undef Request_T
#define Request_T SocketDNS_Request_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS-init"

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
  /* shutdown, request_counter, queue_head/tail/size already 0/NULL from calloc */
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
 * create_single_worker_thread - Create a single worker thread
 * @dns: DNS resolver instance
 * @thread_index: Index of thread to create
 * Returns: 0 on success, -1 on failure
 * Creates one worker thread and handles partial cleanup on failure.
 */
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
  /* memset removed - dns was allocated with calloc, already zeroed */
  create_worker_threads (dns);
}

#undef T
#undef Request_T
