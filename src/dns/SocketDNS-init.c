/**
 * SocketDNS-init.c - Initialization helpers for async DNS resolution
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Contains DNS resolver allocation and initialization functions.
 */

#include "core/SocketConfig.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketError.h"
#include "dns/SocketDNS.h"
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS-init"
#define T SocketDNS_T
#define Request_T SocketDNS_Request_T
#include "dns/SocketDNS-private.h"

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

  memset (dns->request_hash, 0, sizeof (dns->request_hash));
  create_worker_threads (dns);
}

#undef T
#undef Request_T
