/**
 * SocketPool-resize.c - Pool resize and capacity management
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Handles runtime resizing of pool capacity including connection migration.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "pool/SocketPool-private.h"

#define T SocketPool_T

/* SocketPool_Failed declared in SocketPool.h (included via private header) */

/**
 * collect_excess_connections - Collect excess active connections for closing
 * @pool: Pool instance
 * @new_maxconns: New maximum capacity
 * @excess_sockets: Output array for excess sockets (pre-allocated)
 *
 * Returns: Number of excess connections found
 * Thread-safe: Call with mutex held
 */
static size_t
collect_excess_connections (T pool, size_t new_maxconns,
                            Socket_T *excess_sockets)
{
  size_t excess_count = 0;
  size_t target = pool->count - new_maxconns;

  if (pool->count <= new_maxconns)
    return 0;

  for (size_t i = 0; i < pool->maxconns && excess_count < target; i++)
    {
      struct Connection *conn = &pool->connections[i];
      if (conn->active && conn->socket)
        excess_sockets[excess_count++] = conn->socket;
    }

  return excess_count;
}

/**
 * realloc_connections_array - Reallocate connections array
 * @pool: Pool instance
 * @new_maxconns: New size
 *
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Call with mutex held
 */
static int
realloc_connections_array (T pool, size_t new_maxconns)
{
  struct Connection *new_connections;

  new_connections
      = realloc (pool->connections, new_maxconns * sizeof (struct Connection));
  if (!new_connections)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot reallocate connections array");
      return -1;
    }

  pool->connections = new_connections;
  return 0;
}

/**
 * rehash_active_connections - Rebuild hash table after array realloc
 * @pool: Pool instance
 * @new_maxconns: New array size (limit scan)
 *
 * Thread-safe: Call with mutex held
 * Clears hash_table and re-inserts all active connections.
 */
static void
rehash_active_connections (T pool, size_t new_maxconns)
{
  memset (pool->hash_table, 0,
          sizeof (pool->hash_table[0]) * SOCKET_HASH_SIZE);

  for (size_t i = 0; i < new_maxconns; i++)
    {
      Connection_T conn = &pool->connections[i];
      if (conn->active && conn->socket)
        insert_into_hash_table (pool, conn, conn->socket);
    }
}

/**
 * relink_free_slots - Relink free slots to free_list
 * @pool: Pool instance
 * @maxconns: Limit for scanning (new effective max)
 *
 * Thread-safe: Call with mutex held
 * Scans slots, initializes and links only inactive (free) slots.
 */
static void
relink_free_slots (T pool, size_t maxconns)
{
  pool->free_list = NULL;

  for (size_t i = 0; i < maxconns; i++)
    {
      Connection_T conn = &pool->connections[i];
      if (!conn->active)
        {
          SocketPool_connections_initialize_slot (conn);
          conn->free_next = pool->free_list;
          pool->free_list = conn;
        }
    }
}

/**
 * initialize_new_slots - Initialize newly allocated connection slots
 * @pool: Pool instance
 * @old_maxconns: Old size
 * @new_maxconns: New size
 *
 * Thread-safe: Call with mutex held
 */
static void
initialize_new_slots (T pool, size_t old_maxconns, size_t new_maxconns)
{
  for (size_t i = old_maxconns; i < new_maxconns; i++)
    {
      struct Connection *conn = &pool->connections[i];
      SocketPool_connections_initialize_slot (conn);

      if (SocketPool_connections_alloc_buffers (pool->arena, pool->bufsize,
                                                conn)
          == 0)
        {
          conn->free_next = pool->free_list;
          pool->free_list = conn;
        }
    }
}

/**
 * close_excess_sockets - Close and remove excess sockets
 * @pool: Pool instance
 * @excess_sockets: Array of sockets to close
 * @excess_count: Number of sockets
 *
 * Thread-safe: Called outside lock
 */
static void
close_excess_sockets (T pool, Socket_T *excess_sockets, size_t excess_count)
{
  for (size_t i = 0; i < excess_count; i++)
    {
      if (excess_sockets[i])
        {
          SocketPool_remove (pool, excess_sockets[i]);
          Socket_free (&excess_sockets[i]);
        }
    }
}

/**
 * allocate_excess_buffer - Allocate buffer for excess sockets
 * @excess_count: Number needed
 *
 * Returns: Allocated buffer or NULL
 */
static Socket_T *
allocate_excess_buffer (size_t excess_count)
{
  return calloc (excess_count, sizeof (Socket_T));
}

/**
 * handle_shrink_excess - Handle excess connections when shrinking
 * @pool: Pool instance
 * @new_maxconns: New capacity
 *
 * Thread-safe: Releases and reacquires mutex as needed
 * Returns: 0 on success, raises exception on failure
 */
static void
handle_shrink_excess (T pool, size_t new_maxconns)
{
  size_t excess_count;
  Socket_T *excess_sockets;
  size_t collected;

  excess_count
      = pool->count > new_maxconns ? (pool->count - new_maxconns) : 0;

  if (excess_count == 0)
    return;

  excess_sockets = allocate_excess_buffer (excess_count);
  if (!excess_sockets)
    {
      pthread_mutex_unlock (&pool->mutex);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate excess buffer");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }

  collected = collect_excess_connections (pool, new_maxconns, excess_sockets);
  assert (collected == excess_count);

  pthread_mutex_unlock (&pool->mutex);
  close_excess_sockets (pool, excess_sockets, excess_count);
  free (excess_sockets);
  pthread_mutex_lock (&pool->mutex);
}

/**
 * SocketPool_resize - Resize pool capacity at runtime
 * @pool: Pool instance
 * @new_maxconns: New maximum connection capacity
 *
 * Raises: SocketPool_Failed on error
 * Thread-safe: Yes - uses internal mutex
 */
void
SocketPool_resize (T pool, size_t new_maxconns)
{
  size_t old_maxconns;

  assert (pool);

  new_maxconns = socketpool_enforce_max_connections (new_maxconns);

  pthread_mutex_lock (&pool->mutex);

  old_maxconns = pool->maxconns;

  if (new_maxconns == old_maxconns)
    {
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  if (new_maxconns < old_maxconns)
    handle_shrink_excess (pool, new_maxconns);

  if (realloc_connections_array (pool, new_maxconns) != 0)
    {
      pthread_mutex_unlock (&pool->mutex);
      RAISE_POOL_ERROR (SocketPool_Failed);
    }

  /* Rehash only valid slots: min of old and new size.
   * When growing, new slots are uninitialized until initialize_new_slots.
   * When shrinking, array was truncated to new_maxconns. */
  rehash_active_connections (pool,
                             old_maxconns < new_maxconns ? old_maxconns
                                                         : new_maxconns);

  if (new_maxconns > old_maxconns)
    initialize_new_slots (pool, old_maxconns, new_maxconns);
  else
    relink_free_slots (pool, new_maxconns);

  pool->maxconns = new_maxconns;
  pthread_mutex_unlock (&pool->mutex);
}

#undef T

