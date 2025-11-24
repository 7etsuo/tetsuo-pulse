/**
 * SocketPool-core.c - Core pool lifecycle and tuning functions
 * Handles pool creation, destruction, resizing, pre-warming, and iteration.
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "core/SocketMetrics.h"
#include "pool/SocketPool-private.h"
#include "pool/SocketPool.h"

#define T SocketPool_T

/* Constants for calculations */
static const size_t PCT_BASE = 100;

const Except_T SocketPool_Failed
    = { &SocketPool_Failed, "SocketPool operation failed" };

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
__declspec (thread) Except_T SocketPool_DetailedException;
#else
__thread Except_T SocketPool_DetailedException;
#endif

#define RAISE_POOL_ERROR(exception)                                           \
  do                                                                          \
    {                                                                         \
      SocketPool_DetailedException = (exception);                             \
      SocketPool_DetailedException.reason = socket_error_buf;                 \
      RAISE (SocketPool_DetailedException);                                   \
    }                                                                         \
  while (0)

/**
 * safe_time - Retrieve current time with error checking
 *
 * Returns: Current time as time_t
 * Raises: SocketPool_Failed if time() call fails (system error)
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
 * enforce_max_connections - Enforce the maximum connection limit
 * @maxconns: Requested maximum number of connections
 *
 * Returns: Enforced maximum connections value (clamped to
 * SOCKET_MAX_CONNECTIONS, min 1) Thread-safe: Yes - pure function
 */

/**
 * enforce_buffer_size - Enforce buffer size limits
 * @bufsize: Requested buffer size
 *
 * Returns: Enforced buffer size (clamped between min and max)
 * Thread-safe: Yes - pure function
 */
/**
 * enforce_range - Clamp value to min/max bounds
 * @val: Value to clamp
 * @minv: Minimum allowed
 * @maxv: Maximum allowed
 * Returns: Clamped value
 * Thread-safe: Yes - pure function
 */
static size_t
enforce_range (size_t val, size_t minv, size_t maxv)
{
  return val < minv ? minv : (val > maxv ? maxv : val);
}

static size_t
enforce_max_connections (size_t maxconns)
{
  return enforce_range (
      maxconns, 1, SOCKET_MAX_CONNECTIONS); /* Assume min 1 for valid pool */
}

static size_t
enforce_buffer_size (size_t bufsize)
{
  return enforce_range (bufsize, SOCKET_MIN_BUFFER_SIZE,
                        SOCKET_MAX_BUFFER_SIZE);
}

/**
 * allocate_pool_structure - Allocate the main pool structure from arena
 * @arena: Memory arena for allocation
 *
 * Returns: Allocated pool structure
 * Raises: SocketPool_Failed on allocation failure
 * Thread-safe: No - caller must synchronize arena access
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
 * initialize_pool_mutex - Initialize the pool's mutex
 * @pool: Pool instance
 *
 * Raises: SocketPool_Failed on mutex initialization failure
 * Thread-safe: No - caller must ensure single initialization
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
 * Initializes all slots and chains them into free_list for O(1) allocation.
 * Thread-safe: No - caller must hold mutex
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
 *
 * Thread-safe: No - caller must hold mutex
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
 *
 * Thread-safe: No - caller must hold mutex
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
 * SocketPool_new - Create a new connection pool
 * @arena: Arena for memory allocation
 * @maxconns: Maximum number of connections
 * @bufsize: Size of I/O buffers per connection
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

    /* Pre-warm SOCKET_POOL_DEFAULT_PREWARM_PCT of slots */
    SocketPool_prewarm (pool, SOCKET_POOL_DEFAULT_PREWARM_PCT);

    return pool;
  }
  EXCEPT (Arena_Failed)
  {
    /* Caller will dispose arena, freeing pool components */
    RERAISE;
  }
  END_TRY;
  return NULL; /* Unreachable: either returned success or reraised exception */
}

/**
 * SocketPool_free - Free a connection pool
 * @pool: Pointer to pool (will be set to NULL)
 * Note: Does not close sockets - caller must do that
 */
void
SocketPool_free (T *pool)
{
  if (!pool || !*pool)
    return;
  assert (pool && *pool);

  /* Free connections array (malloc'ed, not arena) */
  if ((*pool)->connections)
    {
#ifdef SOCKET_HAS_TLS
      for (size_t i = 0; i < (*pool)->maxconns; i++)
        {
          Connection_T conn = &(*pool)->connections[i];
          if (conn->tls_session)
            {
              SSL_SESSION_free (conn->tls_session);
              conn->tls_session = NULL;
            }
        }
#endif
      free ((*pool)->connections);
      (*pool)->connections = NULL;
    }

  /* Destroy mutex */
  pthread_mutex_destroy (&(*pool)->mutex);

  *pool = NULL;
}

/**
 * collect_excess_connections - Collect excess active connections for closing
 * @pool: Pool instance
 * @new_maxconns: New maximum capacity
 * @excess_sockets: Output array for excess sockets (pre-allocated)
 * Returns: Number of excess connections found
 * Thread-safe: Call with mutex held
 */
static size_t
collect_excess_connections (T pool, size_t new_maxconns,
                            Socket_T *excess_sockets)
{
  size_t excess_count = 0;
  size_t i;

  if (pool->count <= new_maxconns)
    return 0;

  for (i = 0;
       i < pool->maxconns && excess_count < (pool->count - new_maxconns); i++)
    {
      struct Connection *conn = &pool->connections[i];
      if (conn->active && conn->socket)
        {
          excess_sockets[excess_count++] = conn->socket;
        }
    }

  return excess_count;
}

/**
 * realloc_connections_array - Reallocate connections array
 * @pool: Pool instance
 * @new_maxconns: New size
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Call with mutex held
 */
static int
realloc_connections_array (T pool, size_t new_maxconns)
{
  struct Connection *new_connections
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
 * Thread-safe: Call with mutex held
 * Clears hash_table and re-inserts all active connections to fix pointers
 * after realloc
 */
static void
rehash_active_connections (T pool, size_t new_maxconns)
{
  size_t i;

  /* Clear hash table */
  memset (pool->hash_table, 0,
          sizeof (pool->hash_table[0]) * SOCKET_HASH_SIZE);

  /* Re-insert active connections */
  for (i = 0; i < new_maxconns; i++)
    {
      Connection_T conn = &pool->connections[i];
      if (conn->active && conn->socket)
        {
          insert_into_hash_table (pool, conn, conn->socket);
        }
    }
}

/**
 * relink_free_slots - Relink free slots to free_list without re-initializing
 * active ones
 * @pool: Pool instance
 * @maxconns: Limit for scanning (new effective max)
 * Thread-safe: Call with mutex held
 * Scans slots 0 to maxconns-1, initializes and links only inactive (free)
 * slots to free_list. Preserves active slots as-is.
 */
static void
relink_free_slots (T pool, size_t maxconns)
{
  size_t i;
  pool->free_list = NULL; /* Reset free list */

  for (i = 0; i < maxconns; i++)
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
 * initialize_new_slots - Initialize new connection slots
 * @pool: Pool instance
 * @old_maxconns: Old size
 * @new_maxconns: New size
 * Thread-safe: Call with mutex held
 */
static void
initialize_new_slots (T pool, size_t old_maxconns, size_t new_maxconns)
{
  size_t i;
  size_t growth = new_maxconns - old_maxconns;

  memset (&pool->connections[old_maxconns], 0,
          growth * sizeof (struct Connection));

  for (i = old_maxconns; i < new_maxconns; i++)
    {
      struct Connection *conn = &pool->connections[i];
      SocketPool_connections_initialize_slot (conn);

      if (SocketPool_connections_alloc_buffers (pool->arena, pool->bufsize,
                                                conn)
          == 0)
        {
          conn->free_next = (struct Connection *)pool->free_list;
          pool->free_list = conn;
        }
    }
}

/**
 * SocketPool_resize - Resize pool capacity at runtime
 * @pool: Pool instance
 * @new_maxconns: New maximum connection capacity
 * Raises: SocketPool_Failed on error
 * Thread-safe: Yes - uses internal mutex
 */
void
SocketPool_resize (T pool, size_t new_maxconns)
{
  size_t old_maxconns;
  size_t excess_count;
  Socket_T *excess_sockets = NULL;
  size_t i;

  assert (pool);
  assert (SOCKET_VALID_CONNECTION_COUNT (new_maxconns));

  new_maxconns = enforce_max_connections (new_maxconns);

  pthread_mutex_lock (&pool->mutex);

  old_maxconns = pool->maxconns;

  if (new_maxconns == old_maxconns)
    {
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  if (new_maxconns < old_maxconns)
    {
      excess_count
          = pool->count > new_maxconns ? (pool->count - new_maxconns) : 0;

      if (excess_count > 0)
        {
          excess_sockets = calloc (excess_count, sizeof (Socket_T));
          if (!excess_sockets)
            {
              pthread_mutex_unlock (&pool->mutex);
              SOCKET_ERROR_MSG (SOCKET_ENOMEM
                                ": Cannot allocate excess sockets buffer");
              RAISE_POOL_ERROR (SocketPool_Failed);
            }

          size_t collected = collect_excess_connections (pool, new_maxconns,
                                                         excess_sockets);
          assert (collected == excess_count);

          pthread_mutex_unlock (&pool->mutex);

          for (i = 0; i < excess_count; i++)
            {
              if (excess_sockets[i])
                {
                  SocketPool_remove (pool, excess_sockets[i]);
                  Socket_free (&excess_sockets[i]);
                }
            }

          free (excess_sockets);
          excess_sockets = NULL;

          pthread_mutex_lock (&pool->mutex);
        }
    }

  if (realloc_connections_array (pool, new_maxconns) != 0)
    {
      pthread_mutex_unlock (&pool->mutex);
      RAISE_POOL_ERROR (SocketPool_Failed);
    }

  rehash_active_connections (pool, new_maxconns);

  if (new_maxconns > old_maxconns)
    {
      initialize_new_slots (pool, old_maxconns, new_maxconns);
    }
  else
    {
      relink_free_slots (pool, new_maxconns);
    }

  pool->maxconns = new_maxconns;
  pthread_mutex_unlock (&pool->mutex);
}

/**
 * SocketPool_prewarm - Pre-allocate buffers for percentage of free slots
 * @pool: Pool instance
 * @percentage: Percentage of free slots to pre-warm (0-100)
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

  prewarm_count = (pool->maxconns * (size_t)percentage) / PCT_BASE;

  conn = pool->free_list;
  while (conn && allocated < prewarm_count)
    {
      if (!conn->inbuf && !conn->outbuf)
        {
          if (SocketPool_connections_alloc_buffers (pool->arena, pool->bufsize,
                                                    conn)
              == 0)
            {
              allocated++;
            }
        }
      conn = (struct Connection *)conn->free_next;
    }

  pthread_mutex_unlock (&pool->mutex);
}

/**
 * SocketPool_set_bufsize - Set buffer size for future connections
 * @pool: Pool instance
 * @new_bufsize: New buffer size in bytes
 * Thread-safe: Yes - uses internal mutex
 */
void
SocketPool_set_bufsize (T pool, size_t new_bufsize)
{
  assert (pool);
  assert (SOCKET_VALID_BUFFER_SIZE (new_bufsize));

  new_bufsize = enforce_buffer_size (new_bufsize);

  pthread_mutex_lock (&pool->mutex);
  pool->bufsize = new_bufsize;
  pthread_mutex_unlock (&pool->mutex);
}

/**
 * SocketPool_count - Get active connection count
 * @pool: Pool instance
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
 * Calls func for each active connection
 * Thread-safe: Yes - holds mutex during iteration
 * Performance: O(n) where n is maxconns (scans all connection slots)
 * Warning: Callback must not modify pool structure
 */
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

#undef T
