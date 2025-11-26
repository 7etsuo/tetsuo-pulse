/**
 * SocketPool-connections.c - Connection management, accessors, and cleanup
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Consolidated from:
 * - Connection add/get/remove operations
 * - Free list management
 * - Idle connection cleanup
 * - TLS session resumption handling
 * - Connection accessor functions
 */

#include <assert.h>
#include <time.h>

#include "core/SocketUtil.h"
#include "pool/SocketPool-private.h"

#ifdef SOCKET_HAS_TLS
#include "socket/Socket-private.h"
#include "socket/SocketIO.h"
#include "tls/SocketTLS.h"
#endif

#define T SocketPool_T

/* ============================================================================
 * Free List Management
 * ============================================================================ */

/**
 * find_free_slot - Get next free slot from free list
 * @pool: Pool instance
 *
 * Returns: Free slot or NULL if none available
 * Thread-safe: Call with mutex held
 */
Connection_T
find_free_slot (const T pool)
{
  return pool->free_list;
}

/**
 * check_pool_full - Check if pool is at capacity
 * @pool: Pool instance
 *
 * Returns: Non-zero if full
 * Thread-safe: Call with mutex held
 */
int
check_pool_full (const T pool)
{
  return pool->count >= pool->maxconns;
}

/**
 * remove_from_free_list - Remove connection from free list
 * @pool: Pool instance
 * @conn: Connection to remove
 *
 * Thread-safe: Call with mutex held
 */
void
remove_from_free_list (T pool, Connection_T conn)
{
  pool->free_list = conn->free_next;
}

/**
 * return_to_free_list - Return connection to free list
 * @pool: Pool instance
 * @conn: Connection to return
 *
 * Thread-safe: Call with mutex held
 */
void
return_to_free_list (T pool, Connection_T conn)
{
  conn->free_next = pool->free_list;
  pool->free_list = conn;
}

/**
 * buffers_already_allocated - Check if connection has both buffers
 * @conn: Connection to check
 *
 * Returns: Non-zero if both buffers exist
 * Thread-safe: Call with mutex held
 */
static int
buffers_already_allocated (const Connection_T conn)
{
  return conn->inbuf && conn->outbuf;
}

/**
 * allocate_connection_buffers - Allocate buffers if needed
 * @pool: Pool instance
 * @conn: Connection requiring buffers
 *
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Call with mutex held
 */
static int
allocate_connection_buffers (T pool, Connection_T conn)
{
  if (buffers_already_allocated (conn))
    {
      /* Reuse existing buffers - just clear them securely */
      SocketPool_connections_release_buffers (conn);
      return 0;
    }

  return SocketPool_connections_alloc_buffers (pool->arena, pool->bufsize,
                                               conn);
}

/**
 * prepare_free_slot - Prepare a free slot for use
 * @pool: Pool instance
 * @conn: Slot to prepare
 *
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Call with mutex held
 */
int
prepare_free_slot (T pool, Connection_T conn)
{
  remove_from_free_list (pool, conn);

  if (allocate_connection_buffers (pool, conn) != 0)
    {
      return_to_free_list (pool, conn);
      return -1;
    }

  return 0;
}

/* ============================================================================
 * Connection Slot Operations
 * ============================================================================ */

/**
 * update_existing_slot - Update activity timestamp
 * @conn: Connection to update
 * @now: Current time
 *
 * Thread-safe: Call with mutex held
 */
void
update_existing_slot (Connection_T conn, time_t now)
{
  conn->last_activity = now;
}

/**
 * increment_pool_count - Increment active connection count
 * @pool: Pool instance
 *
 * Thread-safe: Call with mutex held
 */
void
increment_pool_count (T pool)
{
  pool->count++;
}

/**
 * decrement_pool_count - Decrement active connection count
 * @pool: Pool instance
 *
 * Thread-safe: Call with mutex held
 */
void
decrement_pool_count (T pool)
{
  pool->count--;
}

/**
 * initialize_connection - Initialize connection with socket
 * @conn: Connection to initialize
 * @socket: Socket to associate
 * @now: Current time
 *
 * Thread-safe: Call with mutex held
 */
void
initialize_connection (Connection_T conn, Socket_T socket, time_t now)
{
  conn->socket = socket;
  conn->data = NULL;
  conn->last_activity = now;
  conn->active = 1;
}

/**
 * SocketPool_connections_release_buffers - Securely clear buffers
 * @conn: Connection whose buffers to clear
 *
 * Thread-safe: Call with mutex held
 */
void
SocketPool_connections_release_buffers (Connection_T conn)
{
  if (conn->inbuf)
    SocketBuf_secureclear (conn->inbuf);
  if (conn->outbuf)
    SocketBuf_secureclear (conn->outbuf);
}

/**
 * reset_slot_base_fields - Reset base connection fields
 * @conn: Connection to reset
 *
 * Thread-safe: Call with mutex held
 */
static void
reset_slot_base_fields (Connection_T conn)
{
  conn->socket = NULL;
  conn->data = NULL;
  conn->last_activity = 0;
  conn->active = 0;
  conn->tracked_ip = NULL;
}

/**
 * reset_slot_tls_fields - Reset TLS-related connection fields
 * @conn: Connection to reset
 *
 * Thread-safe: Call with mutex held
 * No-op when TLS is disabled.
 */
static void
reset_slot_tls_fields (Connection_T conn)
{
#ifdef SOCKET_HAS_TLS
  conn->tls_ctx = NULL;
  conn->tls_handshake_complete = 0;
#else
  (void)conn;
#endif
}

/**
 * SocketPool_connections_reset_slot - Reset connection slot to inactive
 * @conn: Connection to reset
 *
 * Thread-safe: Call with mutex held
 */
void
SocketPool_connections_reset_slot (Connection_T conn)
{
  reset_slot_base_fields (conn);
  reset_slot_tls_fields (conn);
}

/* ============================================================================
 * TLS Session Management
 * ============================================================================ */

#ifdef SOCKET_HAS_TLS
/**
 * session_is_expired - Check if TLS session has expired
 * @sess: Session to check
 * @now: Current time
 *
 * Returns: Non-zero if session is expired
 * Thread-safe: Yes - uses OpenSSL thread-safe accessors
 *
 * Security: Uses subtraction instead of addition to avoid integer overflow
 * when session timestamp or timeout has extreme values. If current time is
 * before session time (clock went backwards), session is considered valid.
 */
static int
session_is_expired (SSL_SESSION *sess, time_t now)
{
  time_t sess_time;
  long sess_timeout;

  /* Suppress deprecated warnings for SSL_SESSION_get_time/get_timeout
   * These are deprecated in OpenSSL 3.x but no replacement exists yet */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
  sess_time = SSL_SESSION_get_time (sess);
  sess_timeout = SSL_SESSION_get_timeout (sess);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

  /* Security: Avoid overflow by using subtraction instead of addition.
   * If now < sess_time (clock went backwards), session is not expired. */
  if (now < sess_time)
    return 0;

  /* Safe: now >= sess_time, so subtraction won't underflow */
  return (now - sess_time) >= sess_timeout;
}

/**
 * free_expired_session - Free session and clear pointer
 * @conn: Connection with expired session
 *
 * Thread-safe: Call with mutex held
 */
static void
free_expired_session (Connection_T conn)
{
  SSL_SESSION_free (conn->tls_session);
  conn->tls_session = NULL;
}
#endif

/**
 * validate_saved_session - Validate and expire TLS session if needed
 * @conn: Connection to validate
 *
 * Thread-safe: Call with pool mutex held
 * No-op when TLS is disabled.
 */
void
validate_saved_session (Connection_T conn)
{
#ifdef SOCKET_HAS_TLS
  if (!conn->tls_session)
    return;

  time_t now = time (NULL);
  if (session_is_expired (conn->tls_session, now))
    free_expired_session (conn);
#else
  (void)conn;
#endif
}

#ifdef SOCKET_HAS_TLS
/**
 * try_set_session - Attempt to set TLS session on SSL object
 * @conn: Connection with saved session
 * @ssl: SSL object to configure
 *
 * Returns: Non-zero on success, zero on failure (cleans up session)
 * Thread-safe: Call with mutex held
 */
static int
try_set_session (Connection_T conn, SSL *ssl)
{
  if (SSL_set_session (ssl, conn->tls_session) != 1)
    {
      SSL_SESSION_free (conn->tls_session);
      conn->tls_session = NULL;
      return 0;
    }
  return 1;
}

/**
 * setup_tls_session_resumption - Try to resume saved TLS session
 * @conn: Connection with potential saved session
 * @socket: Socket to configure
 *
 * Thread-safe: Call with mutex held
 */
static void
setup_tls_session_resumption (Connection_T conn, Socket_T socket)
{
  SSL *ssl;

  if (!socket_is_tls_enabled (socket) || !conn->tls_session)
    return;

  ssl = (SSL *)socket->tls_ssl;
  if (ssl)
    try_set_session (conn, ssl);
}

/**
 * shutdown_tls_connection - Shutdown TLS gracefully
 * @socket: Socket with TLS to shutdown
 *
 * Thread-safe: Call with mutex held
 * Ignores ALL errors during shutdown - connection is closing anyway.
 * Uses ELSE to catch any exception type (not just SocketTLS_Failed).
 */
static void
shutdown_tls_connection (Socket_T socket)
{
  TRY { SocketTLS_shutdown (socket); }
  ELSE { /* Ignore all errors during cleanup */ }
  END_TRY;
}

/**
 * save_tls_session - Save TLS session for potential reuse
 * @conn: Connection to save session to
 * @socket: Socket with TLS session
 *
 * Thread-safe: Call with mutex held
 */
static void
save_tls_session (Connection_T conn, Socket_T socket)
{
  SSL *ssl = (SSL *)socket->tls_ssl;
  SSL_SESSION *sess;

  if (!ssl)
    return;

  sess = SSL_get1_session (ssl);
  if (sess)
    conn->tls_session = sess;
}

/**
 * cleanup_tls_and_save_session - Shutdown TLS and save session
 * @conn: Connection
 * @socket: Socket with TLS
 *
 * Thread-safe: Call with mutex held
 */
static void
cleanup_tls_and_save_session (Connection_T conn, Socket_T socket)
{
  if (!socket_is_tls_enabled (socket))
    return;

  shutdown_tls_connection (socket);
  save_tls_session (conn, socket);
}
#endif

/* ============================================================================
 * Connection Add/Get/Remove API
 * ============================================================================ */

/**
 * handle_existing_slot - Handle case when socket already exists in pool
 * @conn: Existing connection
 * @now: Current time
 *
 * Returns: The connection after updating activity time
 * Thread-safe: Call with mutex held
 */
static Connection_T
handle_existing_slot (Connection_T conn, time_t now)
{
  update_existing_slot (conn, now);
  SocketMetrics_increment (SOCKET_METRIC_POOL_CONNECTIONS_REUSED, 1);
  return conn;
}

/**
 * setup_new_connection - Initialize a newly allocated connection slot
 * @pool: Pool instance
 * @conn: Connection to setup
 * @socket: Socket to associate
 * @now: Current time
 *
 * Returns: The initialized connection
 * Thread-safe: Call with mutex held
 */
static Connection_T
setup_new_connection (T pool, Connection_T conn, Socket_T socket, time_t now)
{
  initialize_connection (conn, socket, now);
  insert_into_hash_table (pool, conn, socket);
  increment_pool_count (pool);
  SocketMetrics_increment (SOCKET_METRIC_POOL_CONNECTIONS_ADDED, 1);
  return conn;
}

/**
 * find_or_create_slot - Find existing or create new slot
 * @pool: Pool instance
 * @socket: Socket to find/add
 * @now: Current time
 *
 * Returns: Connection or NULL if pool full/error
 * Thread-safe: Call with mutex held
 */
Connection_T
find_or_create_slot (T pool, Socket_T socket, time_t now)
{
  Connection_T conn = find_slot (pool, socket);

  if (conn)
    return handle_existing_slot (conn, now);

  conn = find_free_slot (pool);
  if (!conn || prepare_free_slot (pool, conn) != 0)
    return NULL;

  return setup_new_connection (pool, conn, socket, now);
}

/**
 * add_unlocked - Add socket to pool without locking
 * @pool: Pool instance
 * @socket: Socket to add
 * @now: Current time
 *
 * Returns: Connection or NULL if pool is full
 * Thread-safe: Call with mutex held
 */
static Connection_T
add_unlocked (T pool, Socket_T socket, time_t now)
{
  Connection_T conn;

  if (check_pool_full (pool))
    return NULL;

  conn = find_or_create_slot (pool, socket, now);

#ifdef SOCKET_HAS_TLS
  if (conn)
    setup_tls_session_resumption (conn, socket);
#endif

  return conn;
}

/**
 * SocketPool_add - Add socket to pool
 * @pool: Pool instance
 * @socket: Socket to add
 *
 * Returns: Connection or NULL if pool is full
 * Thread-safe: Yes - uses internal mutex
 *
 * Note: Pool full check is performed under mutex to prevent race conditions.
 */
Connection_T
SocketPool_add (T pool, Socket_T socket)
{
  Connection_T conn;
  time_t now;

  assert (pool);
  assert (socket);

  now = safe_time ();

  pthread_mutex_lock (&pool->mutex);
  conn = add_unlocked (pool, socket, now);
  pthread_mutex_unlock (&pool->mutex);

  return conn;
}

/**
 * get_unlocked - Look up connection without locking
 * @pool: Pool instance
 * @socket: Socket to find
 * @now: Current time
 *
 * Returns: Connection or NULL if not found
 * Thread-safe: Call with mutex held
 */
static Connection_T
get_unlocked (T pool, Socket_T socket, time_t now)
{
  Connection_T conn = find_slot (pool, socket);

  if (conn)
    {
      conn->last_activity = now;
      validate_saved_session (conn);
    }

  return conn;
}

/**
 * SocketPool_get - Look up connection by socket
 * @pool: Pool instance
 * @socket: Socket to find
 *
 * Returns: Connection or NULL if not found
 * Thread-safe: Yes - uses internal mutex
 */
Connection_T
SocketPool_get (T pool, Socket_T socket)
{
  Connection_T conn;
  time_t now;

  assert (pool);
  assert (socket);

  now = safe_time ();

  pthread_mutex_lock (&pool->mutex);
  conn = get_unlocked (pool, socket, now);
  pthread_mutex_unlock (&pool->mutex);

  return conn;
}

/**
 * release_ip_tracking - Release IP tracking for connection
 * @pool: Pool instance
 * @conn: Connection with potential IP tracking
 *
 * Thread-safe: Call with mutex held
 */
static void
release_ip_tracking (T pool, Connection_T conn)
{
  if (conn->tracked_ip && pool->ip_tracker)
    {
      SocketIPTracker_release (pool->ip_tracker, conn->tracked_ip);
      conn->tracked_ip = NULL;
    }
}

/**
 * release_connection_resources - Release all connection resources
 * @pool: Pool instance
 * @conn: Connection to release
 * @socket: Associated socket
 *
 * Thread-safe: Call with mutex held
 *
 * Handles TLS cleanup, IP tracking release, buffer clearing, and slot reset.
 */
static void
release_connection_resources (T pool, Connection_T conn, Socket_T socket)
{
#ifdef SOCKET_HAS_TLS
  cleanup_tls_and_save_session (conn, socket);
#else
  (void)socket;
#endif

  release_ip_tracking (pool, conn);
  SocketPool_connections_release_buffers (conn);
  SocketPool_connections_reset_slot (conn);
}

/**
 * remove_unlocked - Remove socket from pool without locking
 * @pool: Pool instance
 * @socket: Socket to remove
 *
 * Thread-safe: Call with mutex held
 */
static void
remove_unlocked (T pool, Socket_T socket)
{
  Connection_T conn = find_slot (pool, socket);

  if (!conn)
    return;

  remove_from_hash_table (pool, conn, socket);
  release_connection_resources (pool, conn, socket);
  return_to_free_list (pool, conn);
  decrement_pool_count (pool);
  SocketMetrics_increment (SOCKET_METRIC_POOL_CONNECTIONS_REMOVED, 1);
}

/**
 * SocketPool_remove - Remove socket from pool
 * @pool: Pool instance
 * @socket: Socket to remove
 *
 * Thread-safe: Yes - uses internal mutex
 *
 * Handles TLS session save, IP tracking release, buffer clearing,
 * and returns slot to free list.
 */
void
SocketPool_remove (T pool, Socket_T socket)
{
  assert (pool);
  assert (socket);

  pthread_mutex_lock (&pool->mutex);
  remove_unlocked (pool, socket);
  pthread_mutex_unlock (&pool->mutex);
}

/* ============================================================================
 * Idle Connection Cleanup
 * ============================================================================ */

/**
 * should_close_connection - Determine if connection should be closed
 * @idle_timeout: Idle timeout in seconds (0 means close all)
 * @now: Current time
 * @last_activity: Last activity time
 *
 * Returns: 1 if connection should be closed, 0 otherwise
 * Thread-safe: Yes - pure function
 */
static int
should_close_connection (time_t idle_timeout, time_t now, time_t last_activity)
{
  if (idle_timeout == 0)
    return 1;
  return difftime (now, last_activity) > (double)idle_timeout;
}

/**
 * is_connection_idle - Check if connection is active and idle
 * @conn: Connection to check
 * @idle_timeout: Idle timeout in seconds
 * @now: Current time
 *
 * Returns: 1 if connection should be collected for cleanup
 * Thread-safe: Call with mutex held
 */
static int
is_connection_idle (const Connection_T conn, time_t idle_timeout, time_t now)
{
  if (!conn->active || !conn->socket)
    return 0;

  return should_close_connection (idle_timeout, now, conn->last_activity);
}

/**
 * process_connection_for_cleanup - Process single connection for cleanup
 * @pool: Pool instance
 * @conn: Connection to check
 * @idle_timeout: Idle timeout in seconds
 * @now: Current time
 * @close_count: Pointer to count of sockets collected
 *
 * Thread-safe: Call with mutex held
 */
static void
process_connection_for_cleanup (T pool, Connection_T conn, time_t idle_timeout,
                                time_t now, size_t *close_count)
{
  validate_saved_session (conn);

  if (is_connection_idle (conn, idle_timeout, now))
    pool->cleanup_buffer[(*close_count)++] = conn->socket;
}

/**
 * collect_idle_sockets - Collect idle sockets into buffer
 * @pool: Pool instance
 * @idle_timeout: Idle timeout in seconds
 * @now: Current time
 *
 * Returns: Number of sockets collected
 * Thread-safe: Call with mutex held
 */
static size_t
collect_idle_sockets (T pool, time_t idle_timeout, time_t now)
{
  size_t close_count = 0;

  for (size_t i = 0; i < pool->maxconns; i++)
    process_connection_for_cleanup (pool, &pool->connections[i], idle_timeout,
                                    now, &close_count);

  return close_count;
}

/**
 * close_single_socket - Close and remove a single socket from pool
 * @pool: Pool instance
 * @socket: Socket to close
 *
 * Thread-safe: Yes - acquires mutex internally
 * Logs errors at DEBUG level rather than propagating.
 */
static void
close_single_socket (T pool, Socket_T socket)
{
  TRY
  {
    SocketPool_remove (pool, socket);
    Socket_free (&socket);
  }
  ELSE
  {
    /* Ignore SocketPool_Failed or Socket_Failed during cleanup -
     * socket may already be removed or closed */
    SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                     "Cleanup: socket close/remove failed (may be stale)");
  }
  END_TRY;
}

/**
 * close_collected_sockets - Close and remove collected sockets
 * @pool: Pool instance
 * @close_count: Number of sockets to close
 *
 * Thread-safe: Yes - each socket operation is thread-safe
 */
static void
close_collected_sockets (T pool, size_t close_count)
{
  for (size_t i = 0; i < close_count; i++)
    close_single_socket (pool, pool->cleanup_buffer[i]);
}

/**
 * SocketPool_cleanup - Remove idle connections
 * @pool: Pool instance
 * @idle_timeout: Seconds idle before removal (0 = remove all)
 *
 * Thread-safe: Yes
 * Performance: O(n) scan of all connection slots
 *
 * Collects idle sockets under mutex, then closes them outside mutex
 * to avoid deadlock with socket operations.
 */
void
SocketPool_cleanup (T pool, time_t idle_timeout)
{
  time_t now;
  size_t close_count;

  assert (pool);
  assert (pool->cleanup_buffer);

  now = safe_time ();

  pthread_mutex_lock (&pool->mutex);
  close_count = collect_idle_sockets (pool, idle_timeout, now);
  pthread_mutex_unlock (&pool->mutex);

  close_collected_sockets (pool, close_count);
}

/* ============================================================================
 * Connection Accessor Functions
 * ============================================================================ */

/**
 * Connection_socket - Get connection's socket
 * @conn: Connection instance
 *
 * Returns: Associated socket
 * Thread-safe: Yes - read-only access
 */
Socket_T
Connection_socket (const Connection_T conn)
{
  assert (conn);
  return conn->socket;
}

/**
 * Connection_inbuf - Get input buffer
 * @conn: Connection instance
 *
 * Returns: Input buffer
 * Thread-safe: Yes - read-only access
 */
SocketBuf_T
Connection_inbuf (const Connection_T conn)
{
  assert (conn);
  return conn->inbuf;
}

/**
 * Connection_outbuf - Get output buffer
 * @conn: Connection instance
 *
 * Returns: Output buffer
 * Thread-safe: Yes - read-only access
 */
SocketBuf_T
Connection_outbuf (const Connection_T conn)
{
  assert (conn);
  return conn->outbuf;
}

/**
 * Connection_data - Get user data
 * @conn: Connection instance
 *
 * Returns: User data pointer
 * Thread-safe: Yes - read-only access
 */
void *
Connection_data (const Connection_T conn)
{
  assert (conn);
  return conn->data;
}

/**
 * Connection_setdata - Set user data
 * @conn: Connection instance
 * @data: User data pointer to store
 *
 * Thread-safe: No - caller must synchronize
 */
void
Connection_setdata (Connection_T conn, void *data)
{
  assert (conn);
  conn->data = data;
}

/**
 * Connection_lastactivity - Get last activity time
 * @conn: Connection instance
 *
 * Returns: Last activity timestamp
 * Thread-safe: Yes - read-only access
 */
time_t
Connection_lastactivity (const Connection_T conn)
{
  assert (conn);
  return conn->last_activity;
}

/**
 * Connection_isactive - Check if connection is active
 * @conn: Connection instance
 *
 * Returns: Non-zero if active
 * Thread-safe: Yes - read-only access
 */
int
Connection_isactive (const Connection_T conn)
{
  assert (conn);
  return conn->active;
}

#undef T
