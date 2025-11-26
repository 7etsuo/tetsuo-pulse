/**
 * SocketPool-core.c - Core pool lifecycle, hash, and allocation functions
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Consolidated from:
 * - Pool creation and destruction
 * - Hash table operations
 * - Memory allocation helpers
 * - Connection slot initialization
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/SocketUtil.h"
#include "pool/SocketPool-private.h"

#define T SocketPool_T

/* ============================================================================
 * Exception Definition
 * ============================================================================ */

const Except_T SocketPool_Failed
    = { &SocketPool_Failed, "SocketPool operation failed" };

/* Thread-local exception instance (declared extern in private header) */
#ifdef _WIN32
__declspec (thread) Except_T SocketPool_DetailedException;
#else
__thread Except_T SocketPool_DetailedException;
#endif

/* ============================================================================
 * Time Utility
 * ============================================================================ */

/**
 * safe_time - Retrieve current time with error checking
 *
 * Returns: Current time as time_t
 * Raises: SocketPool_Failed if time() call fails
 * Thread-safe: Yes - time() is thread-safe per POSIX
 */
time_t
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

/* ============================================================================
 * Hash Functions
 * ============================================================================ */

/**
 * socketpool_hash - Compute hash value for socket file descriptor
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

/* ============================================================================
 * Allocation Functions
 * ============================================================================ */

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

/* ============================================================================
 * Slot Initialization
 * ============================================================================ */

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
  conn->free_next = NULL;
#ifdef SOCKET_HAS_TLS
  conn->tls_ctx = NULL;
  conn->tls_handshake_complete = 0;
  conn->tls_session = NULL;
#endif
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

/* ============================================================================
 * Pool Creation Helpers (static)
 * ============================================================================ */

/**
 * allocate_pool_structure - Allocate the main pool structure
 * @arena: Memory arena for allocation
 *
 * Returns: Allocated pool structure
 * Raises: SocketPool_Failed on allocation failure
 */
static T
allocate_pool_structure (Arena_T arena)
{
  T pool = ALLOC (arena, sizeof (*pool));
  if (!pool)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate pool structure");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  return pool;
}

/**
 * initialize_pool_mutex - Initialize the pool's mutex
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
 * build_free_list - Build linked list of free connection slots
 * @pool: Pool instance
 * @maxconns: Number of slots to initialize and link
 *
 * Initializes all slots and chains them into free_list.
 */
static void
build_free_list (T pool, size_t maxconns)
{
  for (size_t i = maxconns; i > 0; --i)
    {
      struct Connection *conn = &pool->connections[i - 1];
      SocketPool_connections_initialize_slot (conn);
      conn->free_next = pool->free_list;
      pool->free_list = conn;
    }
}

/**
 * allocate_pool_components - Allocate core components of the pool
 * @arena: Memory arena for allocation
 * @maxconns: Maximum number of connections
 * @pool: Pool instance to initialize
 */
static void
allocate_pool_components (Arena_T arena, size_t maxconns, T pool)
{
  pool->connections = SocketPool_connections_allocate_array (maxconns);
  pool->hash_table = SocketPool_connections_allocate_hash_table (arena);
  pool->cleanup_buffer = SocketPool_cleanup_allocate_buffer (arena, maxconns);
}

/**
 * initialize_pool_fields - Initialize fields of the pool structure
 * @pool: Pool instance to initialize
 * @arena: Memory arena for allocation
 * @maxconns: Maximum number of connections
 * @bufsize: Buffer size for new connections
 */
static void
initialize_pool_fields (T pool, Arena_T arena, size_t maxconns, size_t bufsize)
{
  pool->maxconns = maxconns;
  pool->bufsize = bufsize;
  pool->count = 0;
  pool->arena = arena;
  pool->dns = NULL;      /* Lazy init on first async connect */
  pool->async_ctx = NULL; /* No pending async connects */
}

/**
 * validate_pool_params - Validate pool creation parameters
 * @arena: Arena (must not be NULL)
 * @maxconns: Maximum connections (must be valid range)
 * @bufsize: Buffer size (must be valid range)
 *
 * Raises: SocketPool_Failed on invalid parameters
 */
static void
validate_pool_params (Arena_T arena, size_t maxconns, size_t bufsize)
{
  if (!arena)
    {
      SOCKET_ERROR_MSG ("Invalid NULL arena for SocketPool_new");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  if (!SOCKET_VALID_CONNECTION_COUNT (maxconns))
    {
      SOCKET_ERROR_MSG (
          "Invalid maxconns %zu for SocketPool_new (must be 1-%zu)", maxconns,
          SOCKET_MAX_CONNECTIONS);
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  if (!SOCKET_VALID_BUFFER_SIZE (bufsize))
    {
      SOCKET_ERROR_MSG ("Invalid bufsize %zu for SocketPool_new", bufsize);
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
}

/* ============================================================================
 * Pool Lifecycle API
 * ============================================================================ */

/**
 * SocketPool_new - Create a new connection pool
 * @arena: Arena for memory allocation
 * @maxconns: Maximum number of connections
 * @bufsize: Size of I/O buffers per connection
 *
 * Returns: New pool instance (never returns NULL)
 * Raises: SocketPool_Failed on any allocation or initialization failure
 * Thread-safe: Yes - returns new instance
 * Automatically pre-warms SOCKET_POOL_DEFAULT_PREWARM_PCT slots.
 */
T
SocketPool_new (Arena_T arena, size_t maxconns, size_t bufsize)
{
  T pool;

  validate_pool_params (arena, maxconns, bufsize);

  /* Clamp to valid ranges (validation already raised on invalid)
   * Use volatile locals to prevent longjmp clobbering warnings */
  volatile size_t safe_maxconns
      = socketpool_enforce_max_connections (maxconns);
  volatile size_t safe_bufsize = socketpool_enforce_buffer_size (bufsize);

  TRY
  {
    pool = allocate_pool_structure (arena);
    allocate_pool_components (arena, safe_maxconns, pool);
    initialize_pool_fields (pool, arena, safe_maxconns, safe_bufsize);
    initialize_pool_mutex (pool);
    build_free_list (pool, safe_maxconns);
    SocketPool_prewarm (pool, SOCKET_POOL_DEFAULT_PREWARM_PCT);
    return pool;
  }
  EXCEPT (Arena_Failed)
  {
    RERAISE;
  }
  END_TRY;

  return NULL; /* Unreachable */
}

/**
 * free_tls_sessions - Free all TLS sessions in pool
 * @pool: Pool instance
 *
 * Only active when SOCKET_HAS_TLS is defined.
 */
static void
free_tls_sessions (T pool)
{
#ifdef SOCKET_HAS_TLS
  for (size_t i = 0; i < pool->maxconns; i++)
    {
      Connection_T conn = &pool->connections[i];
      if (conn->tls_session)
        {
          SSL_SESSION_free (conn->tls_session);
          conn->tls_session = NULL;
        }
    }
#else
  (void)pool;
#endif
}

/**
 * free_dns_resolver - Free pool's internal DNS resolver
 * @pool: Pool instance
 *
 * Also cancels any pending async connect operations.
 */
static void
free_dns_resolver (T pool)
{
  if (pool->dns)
    {
      /* Cancel pending async connects - their sockets will be freed
       * when DNS resolver drains, but callbacks won't be invoked */
      SocketDNS_free (&pool->dns);
    }
  pool->async_ctx = NULL; /* Contexts are arena-allocated */
}

/**
 * SocketPool_free - Free a connection pool
 * @pool: Pointer to pool (will be set to NULL)
 *
 * Note: Does not close sockets - caller must do that.
 * Thread-safe: Yes
 */
void
SocketPool_free (T *pool)
{
  if (!pool || !*pool)
    return;

  free_dns_resolver (*pool);
  free_tls_sessions (*pool);

  if ((*pool)->connections)
    {
      free ((*pool)->connections);
      (*pool)->connections = NULL;
    }

  pthread_mutex_destroy (&(*pool)->mutex);
  *pool = NULL;
}

#undef T
