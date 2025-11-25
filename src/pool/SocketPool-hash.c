/**
 * SocketPool-hash.c - Hash table and allocation operations
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Provides hash table operations and memory allocation for the pool.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "core/SocketLog.h"
#include "pool/SocketPool-private.h"

#define T SocketPool_T

extern const Except_T SocketPool_Failed;

/**
 * socket_hash - Compute hash value for socket file descriptor
 * @socket: Socket instance to hash (const)
 *
 * Returns: Unsigned hash value in range [0, SOCKET_HASH_SIZE)
 * Thread-safe: Yes - pure function
 * Performance: O(1)
 *
 * Uses golden ratio multiplicative hashing for good distribution.
 */
unsigned
socketpool_hash (const Socket_T socket)
{
  int fd;

  assert (socket);
  fd = Socket_fd (socket);
  if (fd < 0)
    {
      SocketLog_emitf (
          SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
          "Attempt to hash closed/invalid socket (fd=%d); returning 0", fd);
      return 0;
    }

  return ((unsigned)fd * HASH_GOLDEN_RATIO) % SOCKET_HASH_SIZE;
}

/**
 * SocketPool_connections_allocate_array - Allocate connections array
 * @maxconns: Number of slots to allocate
 *
 * Returns: Allocated and zeroed array
 * Raises: SocketPool_Failed on allocation failure
 */
struct Connection *
SocketPool_connections_allocate_array (size_t maxconns)
{
  struct Connection *conns = calloc (maxconns, sizeof (struct Connection));
  if (!conns)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate connections array");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  return conns;
}

/**
 * SocketPool_connections_allocate_hash_table - Allocate hash table
 * @arena: Arena for allocation
 *
 * Returns: Allocated and zeroed hash table
 * Raises: SocketPool_Failed on allocation failure
 */
Connection_T *
SocketPool_connections_allocate_hash_table (Arena_T arena)
{
  Connection_T *table = CALLOC (arena, SOCKET_HASH_SIZE, sizeof (Connection_T));
  if (!table)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate hash table");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  return table;
}

/**
 * SocketPool_cleanup_allocate_buffer - Allocate cleanup buffer
 * @arena: Arena for allocation
 * @maxconns: Buffer size (same as max connections)
 *
 * Returns: Allocated and zeroed buffer
 * Raises: SocketPool_Failed on allocation failure
 */
Socket_T *
SocketPool_cleanup_allocate_buffer (Arena_T arena, size_t maxconns)
{
  Socket_T *buf = CALLOC (arena, maxconns, sizeof (Socket_T));
  if (!buf)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate cleanup buffer");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  return buf;
}

/**
 * SocketPool_connections_initialize_slot - Initialize connection slot
 * @conn: Slot to initialize
 *
 * Zeroes all fields and prepares slot for the free list.
 * Thread-safe: Yes - modifies only the provided slot
 */
void
SocketPool_connections_initialize_slot (struct Connection *conn)
{
  conn->socket = NULL;
  conn->inbuf = NULL;
  conn->outbuf = NULL;
  conn->data = NULL;
  conn->last_activity = 0;
  conn->active = 0;
  conn->hash_next = NULL;
}

/**
 * SocketPool_connections_alloc_buffers - Allocate I/O buffers for slot
 * @arena: Arena for allocation
 * @bufsize: Buffer size in bytes
 * @conn: Connection slot to initialize
 *
 * Returns: 0 on success, -1 on failure (with cleanup)
 */
int
SocketPool_connections_alloc_buffers (Arena_T arena, size_t bufsize,
                                      Connection_T conn)
{
  conn->inbuf = SocketBuf_new (arena, bufsize);
  if (!conn->inbuf)
    return -1;

  conn->outbuf = SocketBuf_new (arena, bufsize);
  if (!conn->outbuf)
    {
      SocketBuf_release (&conn->inbuf);
      conn->inbuf = NULL;
      return -1;
    }
  return 0;
}

/**
 * insert_into_hash_table - Insert connection into hash table
 * @pool: Pool instance
 * @conn: Connection to insert
 * @socket: Associated socket (for hash computation)
 *
 * Thread-safe: Call with mutex held
 */
void
insert_into_hash_table (T pool, Connection_T conn, Socket_T socket)
{
  unsigned hash = socketpool_hash (socket);
  conn->hash_next = pool->hash_table[hash];
  pool->hash_table[hash] = conn;
}

/**
 * remove_from_hash_table - Remove connection from hash table
 * @pool: Pool instance
 * @conn: Connection to remove
 * @socket: Associated socket (for hash computation)
 *
 * Thread-safe: Call with mutex held
 */
void
remove_from_hash_table (T pool, Connection_T conn, Socket_T socket)
{
  unsigned hash = socketpool_hash (socket);
  Connection_T *pp = &pool->hash_table[hash];

  while (*pp)
    {
      if (*pp == conn)
        {
          *pp = conn->hash_next;
          break;
        }
      pp = &(*pp)->hash_next;
    }
}

/**
 * find_slot - Look up active connection by socket
 * @pool: Pool instance
 * @socket: Socket to find
 *
 * Returns: Connection if found, NULL otherwise
 * Thread-safe: Call with mutex held
 * Performance: O(1) average, O(n) worst case (hash collision)
 */
Connection_T
find_slot (T pool, const Socket_T socket)
{
  unsigned hash = socketpool_hash (socket);
  Connection_T conn = pool->hash_table[hash];

  while (conn)
    {
      if (conn->active && conn->socket == socket)
        return conn;
      conn = conn->hash_next;
    }
  return NULL;
}

#undef T

