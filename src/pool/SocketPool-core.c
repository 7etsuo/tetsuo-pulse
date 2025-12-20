/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketPool-core.c - Core pool lifecycle, hash, and allocation functions
 *
 * Part of the Socket Library
 *
 * Consolidated from:
 * - Pool creation and destruction
 * - Hash table operations
 * - Memory allocation helpers
 * - Connection slot initialization
 * - Reconnection support
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pool/SocketPool-private.h"
#include "pool/SocketPoolHealth.h"
#include "socket/SocketReconnect.h"
/* SocketUtil.h included via SocketPool-private.h */

/* SOCKET_LOG_COMPONENT defined in SocketPool-private.h */

#define T SocketPool_T

/* ============================================================================
 * Exception Definition
 * ============================================================================
 */

const Except_T SocketPool_Failed
    = { &SocketPool_Failed, "SocketPool operation failed" };

/**
 * Thread-local exception for detailed error messages.
 * Definition - extern declaration in SocketPool-private.h.
 *
 * NOTE: Cannot use SOCKET_DECLARE_MODULE_EXCEPTION macro here because
 * that creates a static (file-local) variable, but SocketPool is split
 * across multiple .c files that all need to share this exception variable.
 */
#ifdef _WIN32
__declspec (thread) Except_T SocketPool_DetailedException;
#else
__thread Except_T SocketPool_DetailedException;
#endif

/* ============================================================================
 * Time Utility
 * ============================================================================
 */

/**
 * @brief Get current time with error handling.
 * @ingroup connection_mgmt
 * @return Current time as time_t.
 * @throws SocketPool_Failed on system error.
 * @threadsafe Yes.
 *
 * Safe wrapper around time() that raises exception on failure.
 * Used for connection timestamps and idle timeout tracking.
 *
 * @see Connection_lastactivity() for usage.
 * @see Connection_created_at() for creation timestamps.
 */
time_t
safe_time (void)
{
  time_t t = time (NULL);
  if (t == (time_t)-1)
    RAISE_POOL_MSG (SocketPool_Failed, "System time() call failed");
  return t;
}

/* ============================================================================
 * Hash Functions
 * ============================================================================
 */

/**
 * @brief Compute hash for socket (internal).
 * @ingroup connection_mgmt
 * @param socket Socket to hash.
 * @return Hash value for hash table lookup.
 * @threadsafe Yes - pure function.
 *
 * Uses golden ratio hash function for optimal distribution.
 *
 * @see SOCKET_HASH_SIZE for table size.
 * @see socket_util_hash_fd in SocketUtil.h.
 * @see insert_into_hash_table() for usage.
 * @see find_slot() for lookup.
 * @see HASH_GOLDEN_RATIO in SocketUtil.h.
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

  return socket_util_hash_fd (fd, SOCKET_HASH_SIZE);
}

/**
 * insert_into_hash_table - Insert connection into hash table
 * @pool: Pool instance
 * @conn: Connection to insert
 * @socket: Associated socket (for hash computation)
 *
 * Thread-safe: Call with mutex held
 * Performance: O(1) average
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
 * Performance: O(k) where k is chain length at hash bucket
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
 * ============================================================================
 */

/**
 * @brief Generic allocation helper for pool components.
 * @param arena Arena for allocation (NULL for system malloc)
 * @param count Number of elements
 * @param elem_size Size of each element
 * @param what Description for error message
 * @return Allocated zeroed memory
 * @throws SocketPool_Failed on allocation failure
 * @threadsafe Yes
 *
 * Uses CALLOC when arena provided (with debug info), calloc otherwise.
 * Common error handling extracted to reduce redundancy.
 */
static void *
pool_alloc (Arena_T arena, size_t count, size_t elem_size, const char *what)
{
  void *ptr;
  if (arena != NULL) {
    ptr = CALLOC (arena, count, elem_size);
  } else {
    ptr = calloc (count, elem_size);
  }
  if (!ptr)
    RAISE_POOL_MSG (SocketPool_Failed,
                    SOCKET_ENOMEM ": Cannot allocate %s", what);
  return ptr;
}

/**
 * SocketPool_connections_allocate_array - Allocate connections array
 * @maxconns: Number of slots to allocate
 *
 * Returns: Allocated and zeroed array
 * Raises: SocketPool_Failed on allocation failure
 *
 * Uses generic pool_alloc helper for consistency.
 */
struct Connection *
SocketPool_connections_allocate_array (size_t maxconns)
{
  return pool_alloc (NULL, maxconns, sizeof (struct Connection), "connections array");
}

/**
 * SocketPool_connections_allocate_hash_table - Allocate hash table
 * @arena: Arena for allocation
 *
 * Returns: Allocated and zeroed hash table
 * Raises: SocketPool_Failed on allocation failure
 *
 * Uses generic pool_alloc helper for consistency.
 */
Connection_T *
SocketPool_connections_allocate_hash_table (Arena_T arena)
{
  return pool_alloc (arena, SOCKET_HASH_SIZE, sizeof (Connection_T), "hash table");
}

/**
 * SocketPool_cleanup_allocate_buffer - Allocate cleanup buffer
 * @arena: Arena for allocation
 * @maxconns: Buffer size (same as max connections)
 *
 * Returns: Allocated and zeroed buffer
 * Raises: SocketPool_Failed on allocation failure
 *
 * Uses generic pool_alloc helper for consistency.
 */
Socket_T *
SocketPool_cleanup_allocate_buffer (Arena_T arena, size_t maxconns)
{
  return pool_alloc (arena, maxconns, sizeof (Socket_T), "cleanup buffer");
}

/* ============================================================================
 * Slot Initialization
 * ============================================================================
 */

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
  conn->created_at = 0;
  conn->active = 0;
  conn->hash_next = NULL;
  conn->free_next = NULL;
  conn->active_next = NULL;
  conn->active_prev = NULL;
  conn->reconnect = NULL;
  conn->tracked_ip = NULL;
#if SOCKET_HAS_TLS
  conn->tls_ctx = NULL;
  conn->tls_handshake_complete = 0;
  conn->tls_session = NULL;
  conn->last_socket_fd = -1;
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
 * ============================================================================
 */

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
    RAISE_POOL_MSG (SocketPool_Failed,
                    SOCKET_ENOMEM ": Cannot allocate pool structure");
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
    RAISE_POOL_MSG (SocketPool_Failed, "Failed to initialize pool mutex");
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
  /* CRITICAL: Initialize free_list to NULL before building the chain.
   * Without this, the first connection's free_next would be garbage,
   * causing infinite loop when iterating the free list in shrink(). */
  pool->free_list = NULL;

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

/* initialize_pool_fields inlined into construct_pool */

/* initialize_pool_rate_limiting inlined into construct_pool */

/* initialize_pool_drain inlined into construct_pool */

/* initialize_pool_reconnect inlined into construct_pool */

/* initialize_pool_idle_cleanup inlined into construct_pool (time call consolidated) */

/* initialize_pool_callbacks inlined into construct_pool */

/* initialize_pool_stats inlined into construct_pool (time call consolidated) */

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
    RAISE_POOL_MSG (SocketPool_Failed,
                    "Invalid NULL arena for SocketPool_new");

  if (!SOCKET_VALID_CONNECTION_COUNT (maxconns))
    RAISE_POOL_MSG (SocketPool_Failed,
                    "Invalid maxconns %zu for SocketPool_new (must be 1-%zu)",
                    maxconns, SOCKET_MAX_CONNECTIONS);

  if (!SOCKET_VALID_BUFFER_SIZE (bufsize))
    RAISE_POOL_MSG (SocketPool_Failed,
                    "Invalid bufsize %zu for SocketPool_new", bufsize);
}

/**
 * construct_pool - Core pool construction logic
 * @arena: Memory arena for allocation
 * @maxconns: Maximum number of connections (already validated/clamped)
 * @bufsize: Buffer size per connection (already validated/clamped)
 *
 * Returns: Fully initialized pool instance
 * Raises: SocketPool_Failed or Arena_Failed on error
 */
static T
construct_pool (Arena_T arena, size_t maxconns, size_t bufsize)
{
  T pool = allocate_pool_structure (arena);
  allocate_pool_components (arena, maxconns, pool);

  /* Inline simple field initializations to reduce redundant wrapper functions */

  /* From initialize_pool_fields */
  pool->maxconns = maxconns;
  pool->bufsize = bufsize;
  pool->count = 0;
  pool->arena = arena;
  pool->active_head = NULL;
  pool->active_tail = NULL;
  pool->dns = NULL;
  pool->async_ctx = NULL;
  pool->async_pending_count = 0;

  /* From initialize_pool_rate_limiting */
  pool->conn_limiter = NULL;
  pool->ip_tracker = NULL;

  /* From initialize_pool_drain */
  atomic_init (&pool->state, POOL_STATE_RUNNING);
  pool->drain_deadline_ms = 0;
  pool->drain_cb = NULL;
  pool->drain_cb_data = NULL;

  /* From initialize_pool_reconnect */
  pool->reconnect_enabled = 0;
  memset (&pool->reconnect_policy, 0, sizeof (pool->reconnect_policy));

  /* From initialize_pool_idle_cleanup (partial) */
  pool->idle_timeout_sec = SOCKET_POOL_DEFAULT_IDLE_TIMEOUT;
  pool->cleanup_interval_ms = SOCKET_POOL_DEFAULT_CLEANUP_INTERVAL_MS;

  /* From initialize_pool_callbacks */
  pool->validation_cb = NULL;
  pool->validation_cb_data = NULL;
  pool->resize_cb = NULL;
  pool->resize_cb_data = NULL;
  pool->pre_resize_cb = NULL;
  pool->pre_resize_cb_data = NULL;
  pool->idle_cb = NULL;
  pool->idle_cb_data = NULL;

  /* Health checking subsystem (disabled by default) */
  pool->health = NULL;

  /* From initialize_pool_stats + consolidate monotonic time call with idle_cleanup */
  int64_t now_ms = Socket_get_monotonic_ms ();
  pool->last_cleanup_ms = now_ms;
  pool->stats_start_time_ms = now_ms;
  pool->stats_total_added = 0;
  pool->stats_total_removed = 0;
  pool->stats_total_reused = 0;
  pool->stats_health_checks = 0;
  pool->stats_health_failures = 0;
  pool->stats_validation_failures = 0;
  pool->stats_idle_cleanups = 0;

  initialize_pool_mutex (pool);
  build_free_list (pool, maxconns);
  return pool;
}

/* ============================================================================
 * Pool Lifecycle API
 * ============================================================================
 */

/**
 * SocketPool_new - Create a new connection pool
 * @arena: Arena for memory allocation
 * @maxconns: Maximum number of connections
 * @bufsize: Size of I/O buffers per connection
 *
 * Returns: New pool instance (never returns NULL on success)
 * Raises: SocketPool_Failed or Arena_Failed on allocation/initialization
 * failure Thread-safe: Yes - returns new instance Automatically pre-warms
 * SOCKET_POOL_DEFAULT_PREWARM_PCT slots.
 */
T
SocketPool_new (Arena_T arena, size_t maxconns, size_t bufsize)
{
  T pool;
  size_t safe_maxconns;
  size_t safe_bufsize;

  validate_pool_params (arena, maxconns, bufsize);

  safe_maxconns = socketpool_enforce_max_connections (maxconns);
  safe_bufsize = socketpool_enforce_buffer_size (bufsize);

  /* Exceptions (Arena_Failed, SocketPool_Failed) propagate automatically */
  pool = construct_pool (arena, safe_maxconns, safe_bufsize);
  SocketPool_prewarm (pool, SOCKET_POOL_DEFAULT_PREWARM_PCT);

  return pool;
}

/* ============================================================================
 * Pool Destruction Helpers (static)
 * ============================================================================
 */

/**
 * free_tls_sessions - Free all TLS sessions in pool
 * @pool: Pool instance
 *
 * Only active when SOCKET_HAS_TLS is defined.
 */
static void
free_tls_sessions (T pool)
{
#if SOCKET_HAS_TLS
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
 * free_pending_async_contexts - Free sockets in pending async connect contexts
 * @pool: Pool instance
 *
 * Must be called AFTER freeing DNS resolver (which waits for worker threads).
 * When DNS resolver is freed, pending callbacks won't be invoked, so we
 * must manually free the sockets that were allocated for async connects.
 *
 * The callback sets ctx->socket = NULL via Socket_free(), so we only free
 * sockets that weren't already freed by completed callbacks.
 *
 * Security: Enforces ordering invariant - DNS resolver must be freed first
 * to ensure no callbacks are executing concurrently.
 */
static void
free_pending_async_contexts (T pool)
{
  struct AsyncConnectContext *ctx;

  /* Security: Assert ordering invariant - DNS resolver must be freed first.
   * This ensures no callbacks are currently executing or will execute,
   * preventing race conditions with concurrent callback execution. */
  assert (pool->dns == NULL);

  ctx = (struct AsyncConnectContext *)pool->async_ctx;
  while (ctx)
    {
      if (ctx->socket)
        Socket_free (&ctx->socket);
      ctx = ctx->next;
    }
  pool->async_ctx = NULL;
  pool->async_pending_count = 0;
}

/**
 * free_dns_resolver - Free pool's internal DNS resolver
 * @pool: Pool instance
 *
 * Also cancels any pending async connect operations.
 *
 * IMPORTANT: DNS resolver must be freed FIRST to ensure worker threads
 * have completed (including any in-progress callbacks). Only after workers
 * are joined can we safely free sockets in pending async contexts without
 * risking a data race with concurrent callback execution.
 */
static void
free_dns_resolver (T pool)
{
  /* First, shutdown DNS resolver and wait for all worker threads to complete.
   * This ensures no callbacks are currently executing or will execute. */
  if (pool->dns)
    SocketDNS_free (&pool->dns);

  /* Now safe to free sockets in pending async contexts - no race with
   * callbacks */
  free_pending_async_contexts (pool);
}

/**
 * free_reconnect_contexts - Free all reconnection contexts in pool
 * @pool: Pool instance
 */
static void
free_reconnect_contexts (T pool)
{
  for (size_t i = 0; i < pool->maxconns; i++)
    {
      Connection_T conn = &pool->connections[i];
      if (conn->reconnect)
        SocketReconnect_free (&conn->reconnect);
    }
}

/**
 * free_connections_array - Free the connections array
 * @pool: Pool instance
 */
static void
free_connections_array (T pool)
{
  if (pool->connections)
    {
      free (pool->connections);
      pool->connections = NULL;
    }
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

  /* Stop health check thread before freeing any resources */
  SocketPool_disable_health_checks (*pool);

  free_dns_resolver (*pool);
  free_reconnect_contexts (*pool);
  free_tls_sessions (*pool);
  free_connections_array (*pool);
  pthread_mutex_destroy (&(*pool)->mutex);
  *pool = NULL;
}

/* ============================================================================
 * Reconnection Support - Internal Helpers
 * ============================================================================
 */

/**
 * update_connection_socket - Update connection with new socket after reconnect
 * @conn: Connection to update
 * @conn_r: Reconnection context with new socket
 *
 * Called when reconnection succeeds to update the connection's socket.
 */
static void
update_connection_socket (Connection_T conn, SocketReconnect_T conn_r)
{
  Socket_T new_socket = SocketReconnect_socket (conn_r);

  if (new_socket && new_socket != conn->socket)
    {
      conn->socket = new_socket;
      conn->last_activity = safe_time ();
      SocketLog_emitf (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT,
                       "Connection reconnected successfully");
    }
}

/**
 * reconnect_state_callback - Internal callback for reconnection state changes
 * @conn_r: Reconnection context
 * @old_state: Previous state (unused - required by callback signature)
 * @new_state: New state
 * @userdata: Connection pointer
 *
 * Handles state transitions for automatic reconnection.
 */
static void
reconnect_state_callback (SocketReconnect_T conn_r,
                          SocketReconnect_State old_state,
                          SocketReconnect_State new_state, void *userdata)
{
  Connection_T conn = (Connection_T)userdata;

  (void)old_state; /* Required by callback signature, not used here */

  if (!conn)
    return;

  if (new_state == RECONNECT_CONNECTED)
    update_connection_socket (conn, conn_r);
}

/**
 * free_existing_reconnect - Free existing reconnection context if present
 * @conn: Connection to check
 */
static void
free_existing_reconnect (Connection_T conn)
{
  if (conn->reconnect)
    SocketReconnect_free (&conn->reconnect);
}

/**
 * get_reconnect_policy - Get effective reconnection policy
 * @pool: Pool instance
 *
 * Returns: Pointer to pool policy if enabled, NULL otherwise
 */
static SocketReconnect_Policy_T *
get_reconnect_policy (T pool)
{
  return pool->reconnect_enabled ? &pool->reconnect_policy : NULL;
}

/**
 * create_reconnect_context - Create new reconnection context for connection
 * @conn: Connection to enable reconnection for
 * @host: Hostname for reconnection
 * @port: Port for reconnection
 * @policy: Reconnection policy (may be NULL)
 *
 * Raises: SocketReconnect_Failed on error
 */
static void
create_reconnect_context (Connection_T conn, const char *host, int port,
                          const SocketReconnect_Policy_T *policy)
{
  conn->reconnect = SocketReconnect_new (host, port, policy,
                                         reconnect_state_callback, conn);
}

/**
 * log_reconnect_enabled - Log reconnection enable event
 * @host: Hostname for reconnection
 * @port: Port for reconnection
 */
static void
log_reconnect_enabled (const char *host, int port)
{
  SocketLog_emitf (SOCKET_LOG_DEBUG, "SocketPool",
                   "Enabled auto-reconnect for connection to %s:%d", host,
                   port);
}

/* ============================================================================
 * Reconnection Support - Public API
 * ============================================================================
 */

/**
 * SocketPool_set_reconnect_policy - Set default reconnection policy for pool
 * @pool: Pool instance
 * @policy: Reconnection policy (NULL to disable)
 *
 * Thread-safe: Yes
 */
void
SocketPool_set_reconnect_policy (T pool,
                                 const SocketReconnect_Policy_T *policy)
{
  assert (pool);

  POOL_LOCK (pool);

  if (policy)
    {
      pool->reconnect_policy = *policy;
      pool->reconnect_enabled = 1;
    }
  else
    {
      pool->reconnect_enabled = 0;
    }

  POOL_UNLOCK (pool);
}

/**
 * SocketPool_set_pre_resize_callback - Register pre-resize notification
 * @pool: Pool instance
 * @cb: Callback function (NULL to disable)
 * @data: User data passed to callback
 *
 * Thread-safe: Yes
 *
 * Registers a callback invoked BEFORE pool resize. Allows external code
 * to clear cached Connection_T pointers before they become invalid.
 */
void
SocketPool_set_pre_resize_callback (T pool, SocketPool_PreResizeCallback cb,
                                    void *data)
{
  assert (pool);

  POOL_LOCK (pool);
  pool->pre_resize_cb = cb;
  pool->pre_resize_cb_data = data;
  POOL_UNLOCK (pool);
}

/**
 * SocketPool_enable_reconnect - Enable auto-reconnect for a connection
 * @pool: Pool instance
 * @conn: Connection to enable reconnection for
 * @host: Original hostname for reconnection
 * @port: Original port for reconnection
 *
 * Thread-safe: Yes
 * Raises: SocketReconnect_Failed on error
 */
void
SocketPool_enable_reconnect (T pool, Connection_T conn, const char *host,
                             int port)
{
  assert (pool);
  assert (conn);
  assert (host);
  assert (port > 0 && port <= SOCKET_MAX_PORT);

  POOL_LOCK (pool);
  free_existing_reconnect (conn);
  const SocketReconnect_Policy_T *policy = get_reconnect_policy (pool);

  TRY { create_reconnect_context (conn, host, port, policy); }
  EXCEPT (SocketReconnect_Failed)
  {
    POOL_UNLOCK (pool);
    RERAISE;
  }
  END_TRY;

  POOL_UNLOCK (pool);

  log_reconnect_enabled (host, port);
}

/**
 * SocketPool_disable_reconnect - Disable auto-reconnect for a connection
 * @pool: Pool instance
 * @conn: Connection to disable reconnection for
 *
 * Thread-safe: Yes
 */
void
SocketPool_disable_reconnect (T pool, Connection_T conn)
{
  assert (pool);
  assert (conn);

  POOL_LOCK (pool);
  free_existing_reconnect (conn);
  POOL_UNLOCK (pool);
}

/**
 * process_single_reconnect - Process reconnection for single connection
 * @conn: Connection with reconnection enabled
 *
 * Processes state machine and timer tick.
 */
static void
process_single_reconnect (Connection_T conn)
{
  SocketReconnect_process (conn->reconnect);
  SocketReconnect_tick (conn->reconnect);
}

/**
 * SocketPool_process_reconnects - Process reconnection state machines
 * @pool: Pool instance
 *
 * Thread-safe: Yes
 * Must be called periodically in event loop.
 */
void
SocketPool_process_reconnects (T pool)
{
  assert (pool);

  POOL_LOCK (pool);

  for (size_t i = 0; i < pool->maxconns; i++)
    {
      Connection_T conn = &pool->connections[i];
      if (conn->active && conn->reconnect)
        process_single_reconnect (conn);
    }

  POOL_UNLOCK (pool);
}

/**
 * get_connection_timeout - Get timeout for single connection's reconnection
 * @conn: Connection to check
 *
 * Returns: Timeout in ms, or -1 if no timeout pending
 */
static int
get_connection_timeout (Connection_T conn)
{
  if (conn->active && conn->reconnect)
    return SocketReconnect_next_timeout_ms (conn->reconnect);
  return -1;
}

/**
 * update_min_timeout - Update minimum timeout tracker
 * @current_min: Current minimum timeout (-1 means none)
 * @new_timeout: New timeout to compare (-1 means none)
 *
 * Returns: New minimum timeout
 */
static int
update_min_timeout (int current_min, int new_timeout)
{
  if (new_timeout < 0)
    return current_min;
  if (current_min < 0)
    return new_timeout;
  return (new_timeout < current_min) ? new_timeout : current_min;
}

/**
 * SocketPool_reconnect_timeout_ms - Get time until next reconnection action
 * @pool: Pool instance
 *
 * Returns: Milliseconds until next timeout, or -1 if none pending
 * Thread-safe: Yes
 */
int
SocketPool_reconnect_timeout_ms (T pool)
{
  int min_timeout = -1;

  assert (pool);

  POOL_LOCK (pool);

  for (size_t i = 0; i < pool->maxconns; i++)
    {
      int timeout = get_connection_timeout (&pool->connections[i]);
      min_timeout = update_min_timeout (min_timeout, timeout);
    }

  POOL_UNLOCK (pool);

  return min_timeout;
}

/* ============================================================================
 * Connection Reconnection Accessors
 * ============================================================================
 */

/**
 * Connection_reconnect - Get reconnection context for connection
 * @conn: Connection
 *
 * Returns: SocketReconnect_T context, or NULL if not enabled
 * Thread-safe: Yes (but returned context is not thread-safe)
 */
SocketReconnect_T
Connection_reconnect (const Connection_T conn)
{
  if (!conn)
    return NULL;
  return conn->reconnect;
}

/**
 * Connection_has_reconnect - Check if connection has auto-reconnect enabled
 * @conn: Connection
 *
 * Returns: Non-zero if auto-reconnect is enabled
 * Thread-safe: Yes
 */
int
Connection_has_reconnect (const Connection_T conn)
{
  if (!conn)
    return 0;
  return conn->reconnect != NULL;
}

/* ============================================================================
 * Callback Configuration
 * ============================================================================
 */

/**
 * SocketPool_set_validation_callback - Set connection validation callback
 * @pool: Pool instance
 * @cb: Validation callback (NULL to disable)
 * @data: User data passed to callback
 *
 * Thread-safe: Yes
 */
void
SocketPool_set_validation_callback (T pool, SocketPool_ValidationCallback cb,
                                    void *data)
{
  assert (pool);

  POOL_LOCK (pool);
  pool->validation_cb = cb;
  pool->validation_cb_data = data;
  POOL_UNLOCK (pool);
}

/**
 * SocketPool_set_resize_callback - Register pool resize notification callback
 * @pool: Pool instance
 * @cb: Callback function (NULL to clear)
 * @data: User data passed to callback
 *
 * Thread-safe: Yes
 */
void
SocketPool_set_resize_callback (T pool, SocketPool_ResizeCallback cb,
                                void *data)
{
  assert (pool);

  POOL_LOCK (pool);
  pool->resize_cb = cb;
  pool->resize_cb_data = data;
  POOL_UNLOCK (pool);
}

/* ============================================================================
 * Pool Statistics
 * ============================================================================
 */

/**
 * @brief Overflow-safe uint64_t addition with saturation.
 * @param a First operand
 * @param b Second operand
 * @return Sum if no overflow, UINT64_MAX if overflow (saturated)
 * @threadsafe Yes - pure function
 *
 * Used in statistics calculations to prevent undefined behavior on overflow.
 * Returns saturated value instead of wrapping around.
 */
static uint64_t
safe_u64_add (uint64_t a, uint64_t b)
{
  if (a > UINT64_MAX - b)
    return UINT64_MAX;
  return a + b;
}

/**
 * calculate_reuse_rate - Calculate connection reuse rate
 * @added: Total connections added
 * @reused: Total connections reused
 *
 * Returns: Reuse rate (0.0 to 1.0)
 *
 * Security: Uses overflow-safe addition to prevent incorrect stats
 * on long-running servers with extremely high connection churn.
 */
static double
calculate_reuse_rate (uint64_t added, uint64_t reused)
{
  uint64_t total = safe_u64_add (added, reused);
  if (total == 0)
    return 0.0;
  return (double)reused / (double)total;
}

/**
 * calculate_avg_connection_age - Calculate average connection age
 * @pool: Pool instance (mutex must be held)
 * @now: Current time
 *
 * Returns: Average age in seconds
 */
static double
calculate_avg_connection_age (T pool, time_t now)
{
  size_t active_count = 0;
  double total_age = 0.0;

  for (size_t i = 0; i < pool->maxconns; i++)
    {
      struct Connection *conn = &pool->connections[i];
      if (conn->active && conn->created_at > 0)
        {
          total_age += difftime (now, conn->created_at);
          active_count++;
        }
    }

  if (active_count == 0)
    return 0.0;

  return total_age / (double)active_count;
}

/**
 * calculate_churn_rate - Calculate connection churn rate
 * @added: Total connections added
 * @removed: Total connections removed
 * @window_sec: Time window in seconds
 *
 * Returns: Churn rate per second
 *
 * Security: Uses overflow-safe addition to prevent incorrect stats.
 */
static double
calculate_churn_rate (uint64_t added, uint64_t removed, double window_sec)
{
  if (window_sec <= 0.0)
    return 0.0;

  uint64_t total = safe_u64_add (added, removed);

  return (double)total / window_sec;
}

/**
 * count_idle_connections - Count idle connections
 * @pool: Pool instance (mutex must be held)
 *
 * Returns: Number of connections that are active but have been idle
 *
 * Note: All active connections are considered "idle" in this simple model
 * since we don't track "in-use" state separately. For more sophisticated
 * tracking, the caller should manage borrowed/returned state externally.
 */
static size_t
count_idle_connections (T pool)
{
  /* In this simple model, active connections = idle connections
   * A more sophisticated model would track "borrowed" vs "returned" state */
  return pool->count;
}

/**
 * SocketPool_get_stats - Get pool statistics snapshot
 * @pool: Pool instance
 * @stats: Output statistics structure
 *
 * Thread-safe: Yes
 */
void
SocketPool_get_stats (T pool, SocketPool_Stats *stats)
{
  int64_t now_ms;
  time_t now;
  double window_sec;

  assert (pool);
  assert (stats);

  now_ms = Socket_get_monotonic_ms ();
  now = safe_time ();

  POOL_LOCK (pool);

  /* Cumulative counters */
  stats->total_added = pool->stats_total_added;
  stats->total_removed = pool->stats_total_removed;
  stats->total_reused = pool->stats_total_reused;
  stats->total_health_checks = pool->stats_health_checks;
  stats->total_health_failures = pool->stats_health_failures;
  stats->total_validation_failures = pool->stats_validation_failures;
  stats->total_idle_cleanups = pool->stats_idle_cleanups;

  /* Current state */
  stats->current_active = pool->count;
  stats->current_idle = count_idle_connections (pool);
  stats->max_connections = pool->maxconns;

  /* Calculated metrics */
  stats->reuse_rate = calculate_reuse_rate (pool->stats_total_added,
                                            pool->stats_total_reused);
  stats->avg_connection_age_sec = calculate_avg_connection_age (pool, now);

  /* Churn rate over stats window */
  window_sec = (double)(now_ms - pool->stats_start_time_ms) / 1000.0;
  stats->churn_rate_per_sec = calculate_churn_rate (
      pool->stats_total_added, pool->stats_total_removed, window_sec);

  POOL_UNLOCK (pool);
}

/**
 * SocketPool_reset_stats - Reset pool statistics counters
 * @pool: Pool instance
 *
 * Thread-safe: Yes
 */
void
SocketPool_reset_stats (T pool)
{
  assert (pool);

  POOL_LOCK (pool);

  pool->stats_total_added = 0;
  pool->stats_total_removed = 0;
  pool->stats_total_reused = 0;
  pool->stats_health_checks = 0;
  pool->stats_health_failures = 0;
  pool->stats_validation_failures = 0;
  pool->stats_idle_cleanups = 0;
  pool->stats_start_time_ms = Socket_get_monotonic_ms ();

  POOL_UNLOCK (pool);
}

/**
 * SocketPool_get_idle_count - Get count of idle connections
 * @pool: Pool instance
 *
 * Returns: Number of idle connections
 * Thread-safe: Yes
 */
size_t
SocketPool_get_idle_count (T pool)
{
  size_t idle;

  assert (pool);

  POOL_LOCK (pool);
  idle = count_idle_connections (pool);
  POOL_UNLOCK (pool);

  return idle;
}

/**
 * SocketPool_get_active_count - Get count of active connections
 * @pool: Pool instance
 *
 * Returns: Number of active connections
 * Thread-safe: Yes
 */
size_t
SocketPool_get_active_count (T pool)
{
  size_t active;

  assert (pool);

  POOL_LOCK (pool);
  active = pool->count;
  POOL_UNLOCK (pool);

  return active;
}

/**
 * SocketPool_get_hit_rate - Get connection reuse rate
 * @pool: Pool instance
 *
 * Returns: Reuse rate (0.0 to 1.0)
 * Thread-safe: Yes
 */
double
SocketPool_get_hit_rate (T pool)
{
  double rate;

  assert (pool);

  POOL_LOCK (pool);
  rate = calculate_reuse_rate (pool->stats_total_added, pool->stats_total_reused);
  POOL_UNLOCK (pool);

  return rate;
}

/**
 * SocketPool_shrink - Release unused pool capacity
 * @pool: Pool instance
 *
 * Returns: Number of slots released (currently returns free slot count)
 * Thread-safe: Yes
 *
 * Note: This implementation counts and clears free slots. Since memory
 * is arena-managed, actual memory isn't immediately returned to OS,
 * but the slots are marked as reusable.
 */
size_t
SocketPool_shrink (T pool)
{
  size_t released = 0;
  Connection_T curr;

  assert (pool);

  POOL_LOCK (pool);

  /* Count free slots and clear their buffers in single pass */
  curr = pool->free_list;
  while (curr)
    {
      released++;
      if (curr->inbuf)
        SocketBuf_clear (curr->inbuf);
      if (curr->outbuf)
        SocketBuf_clear (curr->outbuf);
      curr = curr->free_next;
    }

  POOL_UNLOCK (pool);

  return released;
}

/**
 * SocketPool_set_idle_callback - Register idle connection callback
 * @pool: Pool instance
 * @cb: Callback function (NULL to clear)
 * @data: User data for callback
 *
 * Thread-safe: Yes
 */
void
SocketPool_set_idle_callback (T pool, SocketPool_IdleCallback cb, void *data)
{
  assert (pool);

  POOL_LOCK (pool);
  pool->idle_cb = cb;
  pool->idle_cb_data = data;
  POOL_UNLOCK (pool);
}

#undef T
