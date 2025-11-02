/**
 * SocketPool.c - Connection pool implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "pool/SocketPool.h"

Except_T SocketPool_Failed = { "SocketPool operation failed" };

/* This is a COPY of the base exception with thread-local reason string.
 * Each thread gets its own exception instance, preventing race conditions
 * when multiple threads raise the same exception type simultaneously. */
#ifdef _WIN32
static __declspec (thread) Except_T SocketPool_DetailedException;
#else
static __thread Except_T SocketPool_DetailedException;
#endif

/* Creates a thread-local copy of the exception with detailed reason */
#define RAISE_POOL_ERROR(exception)                                            \
  do                                                                           \
    {                                                                          \
      SocketPool_DetailedException = (exception);                              \
      SocketPool_DetailedException.reason = socket_error_buf;                  \
      RAISE (SocketPool_DetailedException);                                    \
    }                                                                          \
  while (0)

/* Safe time retrieval - fails fast on system time errors */
static time_t
safe_time (void)
{
  time_t t = time (NULL);
  if (t == (time_t)-1)
    {
      SOCKET_ERROR_MSG ("System time() call failed");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  return t;
}

#define T SocketPool_T

/* Connection structure - now opaque to users */
struct Connection
{
  Socket_T socket;
  SocketBuf_T inbuf;
  SocketBuf_T outbuf;
  void *data;
  time_t last_activity;
  int active;
  struct Connection *hash_next; /* For hash table chaining */
};

/* Use configured hash table size for socket data mapping */
#define SOCKET_HASH_SIZE SOCKET_HASH_TABLE_SIZE

/* Hash function for socket file descriptors */
static unsigned
socket_hash (const Socket_T socket)
{
  int fd;

  assert (socket);
  fd = Socket_fd (socket);

  /* Defensive check: socket FDs should never be negative */
  assert (fd >= 0);

  /* Multiplicative hash with golden ratio for good distribution */
  return ((unsigned)fd * HASH_GOLDEN_RATIO) % SOCKET_HASH_SIZE;
}

struct T
{
  struct Connection *connections; /* Array of connection structs */
  Connection_T *hash_table;       /* Hash table for O(1) lookup */
  struct Connection *free_list;   /* Free slot list for O(1) allocation */
  Socket_T *cleanup_buffer; /* Pre-allocated buffer for cleanup operations */
  size_t maxconns;
  size_t bufsize;
  size_t count;
  Arena_T arena;
  pthread_mutex_t mutex; /* Mutex for thread safety */
};

/**
 * enforce_max_connections - Enforce maximum connection limit
 * @maxconns: Requested maximum connections
 *
 * Returns: Enforced maximum connections value
 */
static size_t
enforce_max_connections (size_t maxconns)
{
  if (maxconns > SOCKET_MAX_CONNECTIONS)
    return SOCKET_MAX_CONNECTIONS;
  return maxconns;
}

/**
 * enforce_buffer_size - Enforce buffer size limits
 * @bufsize: Requested buffer size
 *
 * Returns: Enforced buffer size value
 */
static size_t
enforce_buffer_size (size_t bufsize)
{
  if (bufsize > SOCKET_MAX_BUFFER_SIZE)
    return SOCKET_MAX_BUFFER_SIZE;
  if (bufsize < SOCKET_MIN_BUFFER_SIZE)
    return SOCKET_MIN_BUFFER_SIZE;
  return bufsize;
}

/**
 * allocate_pool_structure - Allocate pool structure from arena
 * @arena: Arena for allocation
 *
 * Returns: Allocated pool structure
 * Raises: SocketPool_Failed on allocation failure
 */
static T
allocate_pool_structure (Arena_T arena)
{
  T pool;

  pool = ALLOC (arena, sizeof (*pool));
  if (!pool)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate pool structure");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  return pool;
}

/**
 * allocate_connections_array - Allocate connections array from arena
 * @arena: Arena for allocation
 * @maxconns: Number of connections to allocate
 *
 * Returns: Allocated connections array
 * Raises: SocketPool_Failed on allocation failure
 */
static struct Connection *
allocate_connections_array (Arena_T arena, size_t maxconns)
{
  struct Connection *connections;

  connections = CALLOC (arena, maxconns, sizeof (struct Connection));
  if (!connections)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate connections array");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  return connections;
}

/**
 * allocate_hash_table - Allocate hash table from arena
 * @arena: Arena for allocation
 *
 * Returns: Allocated hash table
 * Raises: SocketPool_Failed on allocation failure
 */
static Connection_T *
allocate_hash_table (Arena_T arena)
{
  Connection_T *hash_table;

  hash_table = CALLOC (arena, SOCKET_HASH_SIZE, sizeof (Connection_T));
  if (!hash_table)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate hash table");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  return hash_table;
}

/**
 * allocate_cleanup_buffer - Allocate cleanup buffer from arena
 * @arena: Arena for allocation
 * @maxconns: Number of connection slots
 *
 * Returns: Allocated cleanup buffer
 * Raises: SocketPool_Failed on allocation failure
 */
static Socket_T *
allocate_cleanup_buffer (Arena_T arena, size_t maxconns)
{
  Socket_T *cleanup_buffer;

  cleanup_buffer = CALLOC (arena, maxconns, sizeof (Socket_T));
  if (!cleanup_buffer)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate cleanup buffer");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  return cleanup_buffer;
}

/**
 * initialize_pool_mutex - Initialize pool mutex
 * @pool: Pool instance
 *
 * Raises: SocketPool_Failed on mutex initialization failure
 */
static void
initialize_pool_mutex (T pool)
{
  if (pthread_mutex_init (&pool->mutex, NULL) != 0)
    {
      SOCKET_ERROR_MSG ("Failed to initialize pool mutex");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
}

/**
 * initialize_connection_slot - Initialize a connection slot to default state
 * @conn: Connection slot to initialize
 */
static void
initialize_connection_slot (struct Connection *conn)
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
 * build_free_list - Build free list from connections array
 * @pool: Pool instance
 * @maxconns: Number of connection slots
 *
 * Initializes all connection slots and links them into free list.
 */
static void
build_free_list (T pool, size_t maxconns)
{
  size_t i;

  pool->free_list = NULL;
  for (i = maxconns; i > 0; i--)
    {
      size_t idx = i - 1;
      struct Connection *conn = &pool->connections[idx];

      initialize_connection_slot (conn);
      conn->hash_next = (struct Connection *)pool->free_list;
      pool->free_list = conn;
    }
}

/**
 * allocate_pool_components - Allocate all pool data structures
 * @arena: Arena for allocation
 * @maxconns: Maximum connections
 * @pool: Pool structure to populate
 */
static void
allocate_pool_components (Arena_T arena, size_t maxconns, T pool)
{
  pool->connections = allocate_connections_array (arena, maxconns);
  pool->hash_table = allocate_hash_table (arena);
  pool->cleanup_buffer = allocate_cleanup_buffer (arena, maxconns);
}

/**
 * initialize_pool_fields - Initialize pool structure fields
 * @pool: Pool structure to initialize
 * @arena: Arena reference
 * @maxconns: Maximum connections
 * @bufsize: Buffer size
 */
static void
initialize_pool_fields (T pool, Arena_T arena, size_t maxconns, size_t bufsize)
{
  pool->maxconns = maxconns;
  pool->bufsize = bufsize;
  pool->count = 0;
  pool->arena = arena;
}

T
SocketPool_new (Arena_T arena, size_t maxconns, size_t bufsize)
{
  T pool;

  assert (arena);
  assert (SOCKET_VALID_CONNECTION_COUNT (maxconns));
  assert (SOCKET_VALID_BUFFER_SIZE (bufsize));

  maxconns = enforce_max_connections (maxconns);
  bufsize = enforce_buffer_size (bufsize);
  pool = allocate_pool_structure (arena);
  allocate_pool_components (arena, maxconns, pool);
  initialize_pool_fields (pool, arena, maxconns, bufsize);
  initialize_pool_mutex (pool);
  build_free_list (pool, maxconns);

  return pool;
}

void
SocketPool_free (T *pool)
{
  assert (pool && *pool);

  /* Destroy mutex */
  pthread_mutex_destroy (&(*pool)->mutex);

  *pool = NULL;
}

/* find_slot - Look up active connection by socket
 * @pool: Pool instance
 * @socket: Socket to find
 *
 * Returns: Active connection or NULL if not found
 *
 * O(1) average case hash table lookup. Must be called with pool mutex held. */
static Connection_T
find_slot (T pool, Socket_T socket)
{
  unsigned hash = socket_hash (socket);
  Connection_T conn = pool->hash_table[hash];

  /* Search the hash chain */
  while (conn)
    {
      if (conn->active && conn->socket == socket)
        return conn;
      conn = conn->hash_next;
    }
  return NULL;
}

/* find_free_slot - Find an inactive connection slot in the pool
 * @pool: Pool instance
 *
 * Returns: Inactive connection slot or NULL if pool is full
 *
 * O(1) operation using free list. Must be called with pool mutex held. */
static Connection_T
find_free_slot (T pool)
{
  /* Return first free slot from free list */
  return pool->free_list;
}

Connection_T
SocketPool_get (T pool, Socket_T socket)
{
  Connection_T conn;
  time_t now;

  assert (pool);
  assert (socket);

  /* Get time before acquiring lock to minimize lock hold time */
  now = safe_time ();

  pthread_mutex_lock (&pool->mutex);
  conn = find_slot (pool, socket);
  if (conn)
    conn->last_activity = now;
  pthread_mutex_unlock (&pool->mutex);

  return conn;
}

/**
 * check_pool_full - Check if pool is at capacity
 * @pool: Pool instance
 *
 * Returns: Non-zero if pool is full, zero otherwise
 */
static int
check_pool_full (T pool)
{
  return pool->count >= pool->maxconns;
}

/**
 * remove_from_free_list - Remove connection from free list
 * @pool: Pool instance
 * @conn: Connection to remove
 */
static void
remove_from_free_list (T pool, Connection_T conn)
{
  pool->free_list = (struct Connection *)conn->hash_next;
}

/**
 * return_to_free_list - Return connection to free list
 * @pool: Pool instance
 * @conn: Connection to return
 */
static void
return_to_free_list (T pool, Connection_T conn)
{
  conn->hash_next = (struct Connection *)pool->free_list;
  pool->free_list = conn;
}

/**
 * allocate_connection_buffers - Allocate input and output buffers for connection
 * @arena: Arena for allocation
 * @bufsize: Buffer size
 * @conn: Connection to allocate buffers for
 *
 * Returns: Zero on success, non-zero on failure
 *
 * On failure, caller must handle cleanup of any partially allocated buffers.
 */
static int
allocate_connection_buffers (Arena_T arena, size_t bufsize, Connection_T conn)
{
  conn->inbuf = SocketBuf_new (arena, bufsize);
  if (!conn->inbuf)
    return -1;

  conn->outbuf = SocketBuf_new (arena, bufsize);
  if (!conn->outbuf)
    {
      SocketBuf_release (&conn->inbuf);
      return -1;
    }
  return 0;
}

/**
 * initialize_connection - Initialize connection with socket and metadata
 * @conn: Connection to initialize
 * @socket: Socket to associate
 * @now: Current time for activity tracking
 */
static void
initialize_connection (Connection_T conn, Socket_T socket, time_t now)
{
  conn->socket = socket;
  conn->data = NULL;
  conn->last_activity = now;
  conn->active = 1;
}

/**
 * insert_into_hash_table - Insert connection into hash table
 * @pool: Pool instance
 * @conn: Connection to insert
 * @socket: Socket for hash calculation
 */
static void
insert_into_hash_table (T pool, Connection_T conn, Socket_T socket)
{
  unsigned hash = socket_hash (socket);

  conn->hash_next = pool->hash_table[hash];
  pool->hash_table[hash] = conn;
}

/**
 * increment_pool_count - Increment active connection count
 * @pool: Pool instance
 */
static void
increment_pool_count (T pool)
{
  pool->count++;
}

/**
 * update_existing_slot - Update activity time for existing connection
 * @conn: Existing connection slot
 * @now: Current time
 */
static void
update_existing_slot (Connection_T conn, time_t now)
{
  conn->last_activity = now;
}

/**
 * prepare_free_slot - Prepare a free slot for new connection
 * @pool: Pool instance
 * @conn: Free connection slot
 *
 * Returns: Zero on success, non-zero on failure
 */
static int
prepare_free_slot (T pool, Connection_T conn)
{
  remove_from_free_list (pool, conn);

  if (allocate_connection_buffers (pool->arena, pool->bufsize, conn) != 0)
    {
      return_to_free_list (pool, conn);
      return -1;
    }

  return 0;
}

/**
 * finalize_slot_creation - Finalize creation of new connection slot
 * @pool: Pool instance
 * @conn: Connection slot
 * @socket: Socket to associate
 * @now: Current time
 */
static void
finalize_slot_creation (T pool, Connection_T conn, Socket_T socket, time_t now)
{
  initialize_connection (conn, socket, now);
  insert_into_hash_table (pool, conn, socket);
  increment_pool_count (pool);
}

/**
 * find_or_create_slot - Find existing slot or create new one for socket
 * @pool: Pool instance
 * @socket: Socket to add
 * @now: Current time for activity tracking
 *
 * Returns: Connection slot or NULL on failure
 *
 * Must be called with pool mutex held.
 */
static Connection_T
find_or_create_slot (T pool, Socket_T socket, time_t now)
{
  Connection_T conn;

  conn = find_slot (pool, socket);
  if (conn)
    {
      update_existing_slot (conn, now);
      return conn;
    }

  conn = find_free_slot (pool);
  if (!conn || prepare_free_slot (pool, conn) != 0)
    return NULL;

  finalize_slot_creation (pool, conn, socket, now);
  return conn;
}

Connection_T
SocketPool_add (T pool, Socket_T socket)
{
  Connection_T conn;
  time_t now;

  assert (pool);
  assert (socket);

  if (check_pool_full (pool))
    return NULL;

  now = safe_time ();

  pthread_mutex_lock (&pool->mutex);
  conn = find_or_create_slot (pool, socket, now);
  pthread_mutex_unlock (&pool->mutex);

  return conn;
}

/**
 * remove_from_hash_table - Remove connection from hash table
 * @pool: Pool instance
 * @conn: Connection to remove
 * @socket: Socket for hash calculation
 *
 * Note: Hash chain nodes are allocated from arena and are not individually
 * freed. They remain in arena memory until arena disposal. This is expected
 * arena behavior.
 */
static void
remove_from_hash_table (T pool, Connection_T conn, Socket_T socket)
{
  unsigned hash = socket_hash (socket);
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
 * cleanup_connection_buffers - Cleanup and release connection buffers
 * @conn: Connection with buffers to cleanup
 */
static void
cleanup_connection_buffers (Connection_T conn)
{
  if (conn->inbuf)
    {
      SocketBuf_secureclear (conn->inbuf);
      SocketBuf_release (&conn->inbuf);
    }

  if (conn->outbuf)
    {
      SocketBuf_secureclear (conn->outbuf);
      SocketBuf_release (&conn->outbuf);
    }
}

/**
 * reset_connection_slot - Reset connection slot to inactive state
 * @conn: Connection slot to reset
 */
static void
reset_connection_slot (Connection_T conn)
{
  conn->socket = NULL;
  conn->data = NULL;
  conn->last_activity = 0;
  conn->active = 0;
}

/**
 * decrement_pool_count - Decrement active connection count
 * @pool: Pool instance
 */
static void
decrement_pool_count (T pool)
{
  pool->count--;
}

void
SocketPool_remove (T pool, Socket_T socket)
{
  Connection_T conn;

  assert (pool);
  assert (socket);

  pthread_mutex_lock (&pool->mutex);

  conn = find_slot (pool, socket);
  if (!conn)
    {
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  remove_from_hash_table (pool, conn, socket);
  cleanup_connection_buffers (conn);
  reset_connection_slot (conn);
  return_to_free_list (pool, conn);
  decrement_pool_count (pool);

  pthread_mutex_unlock (&pool->mutex);
}

/**
 * should_close_connection - Determine if connection should be closed
 * @idle_timeout: Idle timeout in seconds (0 means close all)
 * @now: Current time
 * @last_activity: Last activity time of connection
 *
 * Returns: Non-zero if connection should be closed, zero otherwise
 *
 * Note: idle_timeout of 0 means close all connections.
 */
static int
should_close_connection (time_t idle_timeout, time_t now, time_t last_activity)
{
  if (idle_timeout == 0)
    return 1;
  return difftime (now, last_activity) > (double)idle_timeout;
}

/**
 * should_collect_socket - Check if socket should be collected for cleanup
 * @conn: Connection to check
 * @idle_timeout: Idle timeout in seconds
 * @now: Current time
 *
 * Returns: Non-zero if socket should be collected, zero otherwise
 */
static int
should_collect_socket (Connection_T conn, time_t idle_timeout, time_t now)
{
  if (!conn->active || !conn->socket)
    return 0;

  return should_close_connection (idle_timeout, now, conn->last_activity);
}

/**
 * collect_idle_sockets - Collect sockets to close into buffer
 * @pool: Pool instance
 * @idle_timeout: Idle timeout in seconds
 * @now: Current time
 *
 * Returns: Number of sockets collected for closing
 *
 * Must be called with pool mutex held. Uses pre-allocated cleanup_buffer.
 */
static size_t
collect_idle_sockets (T pool, time_t idle_timeout, time_t now)
{
  size_t i;
  size_t close_count = 0;

  for (i = 0; i < pool->maxconns; i++)
    {
      if (should_collect_socket (&pool->connections[i], idle_timeout, now))
        {
          pool->cleanup_buffer[close_count++] = pool->connections[i].socket;
        }
    }
  return close_count;
}

/**
 * close_collected_sockets - Close and remove collected sockets
 * @pool: Pool instance
 * @close_count: Number of sockets to close
 */
static void
close_collected_sockets (T pool, size_t close_count)
{
  volatile size_t i;

  for (i = 0; i < close_count; i++)
    {
      TRY
        {
          SocketPool_remove (pool, pool->cleanup_buffer[i]);
          Socket_free (&pool->cleanup_buffer[i]);
        }
      EXCEPT (SocketPool_Failed)
        {
          /* Ignore remove failures - socket may already be removed */
        }
      EXCEPT (Socket_Failed)
        {
          /* Ignore free failures - continue cleanup */
        }
      END_TRY;
    }
}

void
SocketPool_cleanup (T pool, time_t idle_timeout)
{
  volatile time_t now;
  volatile size_t close_count;

  assert (pool);
  assert (pool->cleanup_buffer);

  TRY
    {
      now = safe_time ();

      pthread_mutex_lock (&pool->mutex);
      close_count = collect_idle_sockets (pool, idle_timeout, now);
      pthread_mutex_unlock (&pool->mutex);

      close_collected_sockets (pool, close_count);
    }
  EXCEPT (SocketPool_Failed)
    {
      /* Handle cleanup failure - log error but don't corrupt exception frame */
      /* Exception already raised by safe_time() or other operations */
    }
  END_TRY;
}

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

void
SocketPool_foreach (T pool, void (*func) (Connection_T, void *), void *arg)
{
  size_t i;

  assert (pool);
  assert (func);

  pthread_mutex_lock (&pool->mutex);

  for (i = 0; i < pool->maxconns; i++)
    {
      if (pool->connections[i].active)
        {
          func (&pool->connections[i], arg);
        }
    }

  pthread_mutex_unlock (&pool->mutex);
}

/* Connection accessor functions */
Socket_T
Connection_socket (const Connection_T conn)
{
  assert (conn);
  return conn->socket;
}

SocketBuf_T
Connection_inbuf (const Connection_T conn)
{
  assert (conn);
  return conn->inbuf;
}

SocketBuf_T
Connection_outbuf (const Connection_T conn)
{
  assert (conn);
  return conn->outbuf;
}

void *
Connection_data (const Connection_T conn)
{
  assert (conn);
  return conn->data;
}

void
Connection_setdata (Connection_T conn, void *data)
{
  assert (conn);
  conn->data = data;
}

time_t
Connection_lastactivity (const Connection_T conn)
{
  assert (conn);
  return conn->last_activity;
}

int
Connection_isactive (const Connection_T conn)
{
  assert (conn);
  return conn->active;
}

#undef T
