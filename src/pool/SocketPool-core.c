/**
 * SocketPool-core.c - Core pool lifecycle functions
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Handles pool creation and destruction.
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#include "pool/SocketPool-private.h"

#define T SocketPool_T

/* Exception definition */
const Except_T SocketPool_Failed
    = { &SocketPool_Failed, "SocketPool operation failed" };

/* Thread-local exception instance (declared extern in private header) */
#ifdef _WIN32
__declspec (thread) Except_T SocketPool_DetailedException;
#else
__thread Except_T SocketPool_DetailedException;
#endif

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

/**
 * enforce_range - Clamp value to min/max bounds
 * @val: Value to clamp
 * @minv: Minimum allowed
 * @maxv: Maximum allowed
 *
 * Returns: Clamped value
 * Thread-safe: Yes - pure function
 */
static size_t
enforce_range (size_t val, size_t minv, size_t maxv)
{
  return val < minv ? minv : (val > maxv ? maxv : val);
}

/**
 * enforce_max_connections - Enforce the maximum connection limit
 * @maxconns: Requested maximum number of connections
 *
 * Returns: Enforced value (clamped to SOCKET_MAX_CONNECTIONS, min 1)
 * Thread-safe: Yes - pure function
 */
static size_t
enforce_max_connections (size_t maxconns)
{
  return enforce_range (maxconns, 1, SOCKET_MAX_CONNECTIONS);
}

/**
 * enforce_buffer_size - Enforce buffer size limits
 * @bufsize: Requested buffer size
 *
 * Returns: Enforced buffer size (clamped between min and max)
 * Thread-safe: Yes - pure function
 */
static size_t
enforce_buffer_size (size_t bufsize)
{
  return enforce_range (bufsize, SOCKET_MIN_BUFFER_SIZE,
                        SOCKET_MAX_BUFFER_SIZE);
}

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
      conn->free_next = (struct Connection *)pool->free_list;
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
SocketPool_new (Arena_T arena_, size_t maxconns_, size_t bufsize_)
{
  volatile Arena_T arena = arena_;
  volatile size_t maxconns = maxconns_;
  volatile size_t bufsize = bufsize_;
  T pool;

  validate_pool_params (arena, maxconns, bufsize);
  assert (arena);
  assert (SOCKET_VALID_CONNECTION_COUNT (maxconns));
  assert (SOCKET_VALID_BUFFER_SIZE (bufsize));

  maxconns = enforce_max_connections (maxconns);
  bufsize = enforce_buffer_size (bufsize);

  TRY
  {
    pool = allocate_pool_structure (arena);
    allocate_pool_components (arena, maxconns, pool);
    initialize_pool_fields (pool, arena, maxconns, bufsize);
    initialize_pool_mutex (pool);
    build_free_list (pool, maxconns);
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

  assert (pool && *pool);

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
