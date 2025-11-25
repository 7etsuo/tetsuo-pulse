/**
 * SocketPool-tuning.c - Pool tuning and iteration functions
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Handles pre-warming, buffer size configuration, counting, and iteration.
 */

#include <assert.h>

#include "pool/SocketPool-private.h"

#define T SocketPool_T

/** Percentage divisor for pre-warm calculations */
#define PERCENTAGE_DIVISOR 100

/**
 * SocketPool_prewarm - Pre-allocate buffers for percentage of free slots
 * @pool: Pool instance
 * @percentage: Percentage of free slots to pre-warm (0-100)
 *
 * Thread-safe: Yes - uses internal mutex
 */
void
SocketPool_prewarm (T pool, int percentage)
{
  size_t prewarm_count;
  struct Connection *conn;
  size_t allocated = 0;

  assert (pool);
  assert (percentage >= 0 && percentage <= 100);

  pthread_mutex_lock (&pool->mutex);

  prewarm_count = (pool->maxconns * (size_t)percentage) / PERCENTAGE_DIVISOR;

  conn = pool->free_list;
  while (conn && allocated < prewarm_count)
    {
      if (!conn->inbuf && !conn->outbuf)
        {
          if (SocketPool_connections_alloc_buffers (pool->arena, pool->bufsize,
                                                    conn)
              == 0)
            allocated++;
        }
      conn = (struct Connection *)conn->free_next;
    }

  pthread_mutex_unlock (&pool->mutex);
}

/**
 * SocketPool_set_bufsize - Set buffer size for future connections
 * @pool: Pool instance
 * @new_bufsize: New buffer size in bytes
 *
 * Thread-safe: Yes - uses internal mutex
 */
void
SocketPool_set_bufsize (T pool, size_t new_bufsize)
{
  assert (pool);
  assert (SOCKET_VALID_BUFFER_SIZE (new_bufsize));

  if (new_bufsize < SOCKET_MIN_BUFFER_SIZE)
    new_bufsize = SOCKET_MIN_BUFFER_SIZE;
  if (new_bufsize > SOCKET_MAX_BUFFER_SIZE)
    new_bufsize = SOCKET_MAX_BUFFER_SIZE;

  pthread_mutex_lock (&pool->mutex);
  pool->bufsize = new_bufsize;
  pthread_mutex_unlock (&pool->mutex);
}

/**
 * SocketPool_count - Get active connection count
 * @pool: Pool instance
 *
 * Returns: Number of active connections
 * Thread-safe: Yes - protected by internal mutex
 */
size_t
SocketPool_count (T pool)
{
  size_t count;

  assert (pool);

  pthread_mutex_lock (&pool->mutex);
  count = pool->count;
  pthread_mutex_unlock (&pool->mutex);

  return count;
}

/**
 * SocketPool_foreach - Iterate over connections
 * @pool: Pool instance
 * @func: Callback function
 * @arg: User data for callback
 *
 * Calls func for each active connection.
 * Thread-safe: Yes - holds mutex during iteration
 * Performance: O(n) where n is maxconns
 * Warning: Callback must not modify pool structure
 */
void
SocketPool_foreach (T pool, void (*func) (Connection_T, void *), void *arg)
{
  assert (pool);
  assert (func);

  pthread_mutex_lock (&pool->mutex);

  for (size_t i = 0; i < pool->maxconns; i++)
    {
      if (pool->connections[i].active)
        func (&pool->connections[i], arg);
    }

  pthread_mutex_unlock (&pool->mutex);
}

#undef T

