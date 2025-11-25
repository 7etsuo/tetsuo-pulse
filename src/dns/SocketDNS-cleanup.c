/**
 * SocketDNS-cleanup.c - Cleanup and shutdown functions for async DNS resolution
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Contains cleanup, shutdown, and resource deallocation functions.
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
#define SOCKET_LOG_COMPONENT "SocketDNS-cleanup"

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
 * reset_dns_state - Reset internal DNS resolver state for shutdown
 * @d: DNS resolver instance
 * Thread-safe: Uses mutex to protect shared state
 * Frees all requests (including their results), resets queue and hash table.
 * Note: drain_completed_requests was removed as redundant - free_all_requests
 * already frees results via free_request_list.
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

