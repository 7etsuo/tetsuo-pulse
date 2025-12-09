/**
 * SocketPool-connections.c - Connection management, accessors, and cleanup
 *
 * Part of the Socket Library
 *
 * Consolidated from:
 * - Connection add/get/remove operations
 * - Free list management
 * - Idle connection cleanup
 * - TLS session resumption handling
 * - Connection accessor functions
 */

#include <assert.h>
#include <errno.h>
#include <sys/socket.h>
#include <time.h>

#include "pool/SocketPool-private.h"
/* SocketUtil.h included via SocketPool-private.h */

/* Override default log component (SocketUtil.h sets "Socket") */
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketPool"

#if SOCKET_HAS_TLS
#include "socket/Socket-private.h"
#include "socket/SocketIO.h"
#include "tls/SocketTLS.h"
#endif

#define T SocketPool_T

/* Forward declarations */
static void release_connection_resources (T pool, Connection_T conn,
                                          Socket_T socket);

/* ============================================================================
 * Free List Management
 * ============================================================================
 */

/**
 * @brief Get next free slot from free list.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @return Free slot or NULL if none available.
 * @threadsafe Call with mutex held.
 *
 * @see find_free_slot() for public interface.
 * @see return_to_free_list() for adding slots back.
 */
Connection_T
find_free_slot (const T pool)
{
  return pool->free_list;
}

/**
 * @brief Check if pool is at capacity.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @return Non-zero if pool is at maximum capacity.
 * @threadsafe Call with mutex held.
 *
 * Fast check to determine if pool has reached its maximum connection limit.
 *
 * @see SocketPool_count() for current connection count.
 * @see SocketPool_resize() for changing pool capacity.
 */
int
check_pool_full (const T pool)
{
  return pool->count >= pool->maxconns;
}

/**
 * @brief Remove connection from free list.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param conn Connection to remove from free list.
 * @threadsafe Call with mutex held.
 *
 * Updates free list pointers when a slot becomes active.
 *
 * @see return_to_free_list() for reverse operation.
 * @see find_free_slot() for finding available slots.
 */
void
remove_from_free_list (T pool, Connection_T conn)
{
  pool->free_list = conn->free_next;
}

/**
 * @brief Return connection to free list.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param conn Connection to return to free list.
 * @threadsafe Call with mutex held.
 *
 * Updates free list pointers when a slot becomes inactive.
 *
 * @see remove_from_free_list() for reverse operation.
 * @see SocketPool_remove() for connection removal.
 */
void
return_to_free_list (T pool, Connection_T conn)
{
  conn->free_next = pool->free_list;
  pool->free_list = conn;
}

/**
 * @brief Check if connection has both buffers allocated.
 * @ingroup connection_mgmt
 * @param conn Connection to check.
 * @return Non-zero if both input and output buffers exist.
 * @threadsafe Call with mutex held.
 *
 * @see SocketPool_connections_alloc_buffers() for buffer allocation.
 * @see Connection_inbuf() and Connection_outbuf() for buffer access.
 */
static int
buffers_already_allocated (const Connection_T conn)
{
  return conn->inbuf && conn->outbuf;
}

/**
 * @brief Allocate buffers for connection if needed.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param conn Connection requiring buffers.
 * @return 0 on success, -1 on allocation failure.
 * @threadsafe Call with mutex held.
 *
 * @see SocketPool_connections_alloc_buffers() for buffer allocation.
 * @see SocketPool_new() for initial buffer setup.
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
 * @brief Prepare a free slot for use.
 * @pool Pool instance
 * @conn Slot to prepare
 *
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Call with mutex held
 */
int
prepare_free_slot (T pool, Connection_T conn)
{
  remove_from_free_list (pool, conn);

  /* Reuse existing buffers if available, otherwise allocate new ones */
  if (!conn->inbuf || !conn->outbuf)
    {
      if (SocketPool_connections_alloc_buffers (pool->arena, pool->bufsize, conn) != 0)
        {
          return_to_free_list (pool, conn);
          return -1;
        }
    }
  else
    {
      /* Clear existing buffers for reuse */
      SocketBuf_secureclear (conn->inbuf);
      SocketBuf_secureclear (conn->outbuf);
    }

  return 0;
}

/* ============================================================================
 * Connection Slot Operations
 * ============================================================================
 */

/**
 * @brief Update activity timestamp.
 * @conn Connection to update
 * @now Current time
 *
 * Thread-safe: Call with mutex held
 */
void
update_existing_slot (Connection_T conn, time_t now)
{
  conn->last_activity = now;
}

/**
 * @brief Increment active connection count.
 * @pool Pool instance
 *
 * Thread-safe: Call with mutex held
 */
void
increment_pool_count (T pool)
{
  pool->count++;
}

/**
 * @brief Decrement active connection count.
 * @pool Pool instance
 *
 * Thread-safe: Call with mutex held
 */
void
decrement_pool_count (T pool)
{
  pool->count--;
}

/**
 * @brief Initialize connection with socket.
 * @conn Connection to initialize
 * @socket Socket to associate
 * @now Current time
 *
 * Thread-safe: Call with mutex held
 */
void
initialize_connection (Connection_T conn, Socket_T socket, time_t now)
{
  conn->socket = socket;
  conn->data = NULL;
  conn->last_activity = now;
  conn->created_at = now;
  conn->active = 1;
#if SOCKET_HAS_TLS
  {
    int new_fd = socket ? Socket_fd (socket) : -1;
    /* Clear TLS session only if this is a different socket (security).
     * Same socket re-added: preserve session for resumption. */
    if (conn->last_socket_fd != new_fd || conn->last_socket_fd < 0)
      {
        if (conn->tls_session)
          {
            SSL_SESSION_free (conn->tls_session);
            conn->tls_session = NULL;
          }
      }
    conn->last_socket_fd = new_fd;
  }
  conn->tls_ctx = NULL;
  conn->tls_handshake_complete = 0;
#endif
}

/**
 * @brief Securely clear buffers.
 * @conn Connection whose buffers to clear
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
 * @brief Reset base connection fields.
 * @conn Connection to reset
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
 * @brief Reset TLS-related connection fields.
 * @conn Connection to reset
 *
 * Thread-safe: Call with mutex held
 * No-op when TLS is disabled.
 */
static void
reset_slot_tls_fields (Connection_T conn)
{
#if SOCKET_HAS_TLS
  conn->tls_ctx = NULL;
  conn->tls_handshake_complete = 0;
  /* NOTE: tls_session is intentionally NOT cleared here to allow
   * session resumption. It is cleared in initialize_connection when
   * a new/different socket is assigned to the slot. */
#else
  (void)conn;
#endif
}

/**
 * @brief Reset connection slot to inactive.
 * @conn Connection to reset
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
 * ============================================================================
 */

#if SOCKET_HAS_TLS
/**
 * @brief Check if TLS session has expired.
 * @sess Session to check
 * @now Current time
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
 * @brief Free session and clear pointer.
 * @conn Connection with expired session
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
 * @brief Validate and expire TLS session if needed.
 * @conn Connection to validate
 * @now Current time for expiration check
 *
 * Thread-safe: Call with pool mutex held
 * No-op when TLS is disabled.
 */
void
validate_saved_session (Connection_T conn, time_t now)
{
#if SOCKET_HAS_TLS
  if (!conn->tls_session)
    return;

  if (session_is_expired (conn->tls_session, now))
    free_expired_session (conn);
#else
  (void)conn;
  (void)now;
#endif
}

#if SOCKET_HAS_TLS
/**
 * @brief Attempt to set TLS session on SSL object.
 * @conn Connection with saved session
 * @ssl SSL object to configure
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
 * @brief Try to resume saved TLS session.
 * @conn Connection with potential saved session
 * @socket Socket to configure
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
 * @brief Shutdown TLS gracefully.
 * @socket Socket with TLS to shutdown
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
 * @brief Save TLS session for potential reuse.
 * @conn Connection to save session to
 * @socket Socket with TLS session
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

  /* Free any existing session before saving new one to avoid leaks */
  if (conn->tls_session)
    {
      SSL_SESSION_free (conn->tls_session);
      conn->tls_session = NULL;
    }

  sess = SSL_get1_session (ssl);
  if (sess)
    conn->tls_session = sess;
}

/**
 * @brief Shutdown TLS and save session.
 * @conn Connection
 * @socket Socket with TLS
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
 * ============================================================================
 */

/**
 * @brief Handle case when socket already exists in pool.
 * @conn Existing connection
 * @now Current time
 *
 * Returns: The connection after updating activity time
 * Thread-safe: Call with mutex held
 */
static Connection_T
handle_existing_slot (Connection_T conn, time_t now)
{
  /* Secure clear buffers on reuse to prevent data leakage (security.md Section
   * 20) */
  SocketBuf_secureclear (conn->inbuf);
  SocketBuf_secureclear (conn->outbuf);
  update_existing_slot (conn, now);
  SocketMetrics_increment (SOCKET_METRIC_POOL_CONNECTIONS_REUSED, 1);
  return conn;
}

/**
 * @brief Initialize a newly allocated connection slot.
 * @pool Pool instance
 * @conn Connection to setup
 * @socket Socket to associate
 * @now Current time
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
  pool->stats_total_added++;
  SocketMetrics_increment (SOCKET_METRIC_POOL_CONNECTIONS_ADDED, 1);
  return conn;
}

/**
 * @brief Find existing or create new slot.
 * @pool Pool instance
 * @socket Socket to find/add
 * @now Current time
 *
 * Returns: Connection or NULL if pool full/error
 * Thread-safe: Call with mutex held
 */
Connection_T
find_or_create_slot (T pool, Socket_T socket, time_t now)
{
  Connection_T conn = find_slot (pool, socket);

  if (conn)
    {
      pool->stats_total_reused++;
      return handle_existing_slot (conn, now);
    }

  conn = find_free_slot (pool);
  if (!conn || prepare_free_slot (pool, conn) != 0)
    return NULL;

  return setup_new_connection (pool, conn, socket, now);
}

/**
 * @brief Check if pool is accepting new connections.
 * @pool Pool instance
 *
 * Returns: 1 if accepting (RUNNING state), 0 if draining or stopped
 * Thread-safe: Call with mutex held
 */
static int
check_pool_accepting (const T pool)
{
  return atomic_load_explicit (&pool->state, memory_order_acquire)
         == POOL_STATE_RUNNING;
}

/**
 * @brief Add socket to pool without locking.
 * @pool Pool instance
 * @socket Socket to add
 * @now Current time
 *
 * Returns: Connection or NULL if pool is full or draining
 * Thread-safe: Call with mutex held
 */
static Connection_T
add_unlocked (T pool, Socket_T socket, time_t now)
{
  Connection_T conn;

  /* Reject if draining or stopped */
  if (!check_pool_accepting (pool))
    return NULL;

  if (check_pool_full (pool))
    return NULL;

  conn = find_or_create_slot (pool, socket, now);

#if SOCKET_HAS_TLS
  if (conn)
    setup_tls_session_resumption (conn, socket);
#endif

  return conn;
}

/**
 * @brief Add socket to pool.
 * @pool Pool instance
 * @socket Socket to add
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

  if (!pool || !socket)
    {
      RAISE_POOL_MSG (SocketPool_Failed,
                      "Invalid NULL pool or socket in SocketPool_add");
    }
  assert (pool);
  assert (socket);

  now = safe_time ();

  pthread_mutex_lock (&pool->mutex);
  conn = add_unlocked (pool, socket, now);
  pthread_mutex_unlock (&pool->mutex);

  return conn;
}

/**
 * @brief Look up connection without locking (internal).
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param socket Socket to find in pool.
 * @param now Current timestamp for activity updates.
 * @return Connection_T if found and valid, NULL otherwise.
 * @threadsafe Call with mutex held.
 *
 * Internal version of SocketPool_get() that assumes mutex is already held.
 * Updates connection activity timestamp and validates TLS sessions.
 *
 * @see SocketPool_get() for public interface.
 * @see find_slot() for hash table lookup.
 * @see update_existing_slot() for activity tracking.
 */
static Connection_T
get_unlocked (T pool, Socket_T socket, time_t now)
{
  Connection_T conn = find_slot (pool, socket);

  if (conn)
    {
      update_existing_slot (conn, now);
      validate_saved_session (conn, now);
    }

  return conn;
}

/**
 * @brief Run validation callback if set (internal).
 * @ingroup connection_mgmt
 * @param pool Pool instance (mutex held).
 * @param conn Connection to validate.
 * @return 1 if connection is valid (or no callback set), 0 if invalid.
 * @threadsafe Call with mutex held.
 *
 * Executes the validation callback with temporary mutex release to avoid
 * deadlock. Re-acquires mutex and re-validates connection state.
 *
 * @see SocketPool_set_validation_callback() for setting callback.
 * @see SocketPool_ValidationCallback for callback signature.
 * @see SocketPool_get() for when validation occurs.
 */
static void remove_known_connection (T pool, Connection_T conn,
                                     Socket_T socket);

static int
run_validation_callback_unlocked (T pool, Connection_T conn)
{
  SocketPool_ValidationCallback cb;
  void *cb_data;
  int valid;
  Connection_T current_conn;

  cb = pool->validation_cb;
  cb_data = pool->validation_cb_data;

  if (!cb)
    return 1; /* No callback = always valid */

  /* Temporarily release mutex for callback to avoid deadlock/long holds.
   * Re-acquire to safely remove if invalid. Races handled by re-validation. */
  pthread_mutex_unlock (&pool->mutex);

  valid = cb (conn, cb_data);

  pthread_mutex_lock (&pool->mutex);

  /* Re-validate: Check if connection still exists and matches */
  current_conn = find_slot (pool, Connection_socket (conn));
  if (!current_conn || current_conn != conn)
    {
      /* Already removed by another thread - assume handled */
      if (!valid)
        {
          SocketLog_emitf (
              SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
              "Validation invalid but connection already removed");
        }
      return 1; /* Treat as valid (gone) */
    }

  if (valid)
    return 1;

  /* Still invalid and present - remove it */
  pool->stats_validation_failures++;
  SocketLog_emitf (
      SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
      "Connection validation callback returned invalid - removing");
  remove_known_connection (pool, conn, conn->socket);
  return 0;
}

/**
 * @brief Look up connection by socket.
 * @pool Pool instance
 * @socket Socket to find
 *
 * Returns: Connection or NULL if not found or validation failed
 * Thread-safe: Yes - uses internal mutex
 *
 * If a validation callback is set, it is called before returning the
 * connection. If the callback returns 0, the connection is removed
 * from the pool and NULL is returned.
 */
static void remove_known_connection (T pool, Connection_T conn,
                                     Socket_T socket);

Connection_T
SocketPool_get (T pool, Socket_T socket)
{
  Connection_T conn;
  time_t now;

  if (!pool || !socket)
    {
      RAISE_POOL_MSG (SocketPool_Failed,
                      "Invalid NULL pool or socket in SocketPool_get");
    }
  assert (pool);
  assert (socket);

  now = safe_time ();

  pthread_mutex_lock (&pool->mutex);
  conn = get_unlocked (pool, socket, now);

  /* Run validation callback if connection found (now handles removal
   * internally) */
  if (conn)
    {
      if (!run_validation_callback_unlocked (pool, conn))
        {
          /* Callback indicated invalid; re-check and remove if still present
           */
          conn = find_slot (pool, socket);
          if (conn)
            {
              remove_known_connection (pool, conn, socket);
            }
          pthread_mutex_unlock (&pool->mutex);
          return NULL;
        }
      /* Valid connection - update stats */
      pool->stats_total_reused++;
      SocketMetrics_increment (SOCKET_METRIC_POOL_CONNECTIONS_REUSED, 1);
    }

  pthread_mutex_unlock (&pool->mutex);

  return conn;
}

/**
 * @brief Release IP tracking for connection.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param conn Connection with potential IP tracking.
 * @threadsafe Call with mutex held.
 *
 * Releases IP address from per-IP connection tracker if tracking was enabled.
 *
 * @see SocketPool_track_ip() for IP tracking.
 * @see SocketPool_release_ip() for manual IP release.
 * @see SocketIPTracker_release() for tracker operations.
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
 * @brief Release all connection resources.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param conn Connection to release.
 * @param socket Associated socket.
 * @threadsafe Call with mutex held.
 *
 * Handles TLS cleanup, IP tracking release, buffer clearing, and slot reset.
 * Called during connection removal to ensure clean resource deallocation.
 *
 * @see remove_known_connection() for connection removal.
 * @see SocketPool_connections_release_buffers() for buffer cleanup.
 * @see SocketPool_connections_reset_slot() for slot reset.
 */
static void
release_connection_resources (T pool, Connection_T conn, Socket_T socket)
{
#if SOCKET_HAS_TLS
  cleanup_tls_and_save_session (conn, socket);
#else
  (void)socket;
#endif

  release_ip_tracking (pool, conn);
  SocketPool_connections_release_buffers (conn);
  SocketPool_connections_reset_slot (conn);
}

/**
 * @brief Remove a known connection from pool.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param conn Connection to remove (must be valid and in pool).
 * @param socket Associated socket for hash table removal.
 * @threadsafe Call with pool mutex held.
 *
 * Performs hash removal, resource release, free list return, count decrement,
 * and stats update. Assumes connection is valid and present in pool.
 *
 * @see SocketPool_remove() for public interface.
 * @see remove_from_hash_table() for hash table operations.
 * @see release_connection_resources() for resource cleanup.
 */
static void
remove_known_connection (T pool, Connection_T conn, Socket_T socket)
{
  remove_from_hash_table (pool, conn, socket);
  release_connection_resources (pool, conn, socket);
  return_to_free_list (pool, conn);
  decrement_pool_count (pool);
  pool->stats_total_removed++;
  SocketMetrics_increment (SOCKET_METRIC_POOL_CONNECTIONS_REMOVED, 1);
}

/**
 * @brief Remove socket from pool without locking.
 * @pool Pool instance
 * @socket Socket to remove
 *
 * Thread-safe: Call with mutex held
 */
static void
remove_unlocked (T pool, Socket_T socket)
{
  Connection_T conn = find_slot (pool, socket);

  if (!conn)
    return;

  remove_known_connection (pool, conn, socket);
}

/**
 * @brief Remove socket from pool.
 * @pool Pool instance
 * @socket Socket to remove
 *
 * Thread-safe: Yes - uses internal mutex
 *
 * Handles TLS session save, IP tracking release, buffer clearing,
 * and returns slot to free list.
 */
void
SocketPool_remove (T pool, Socket_T socket)
{
  if (!pool || !socket)
    {
      RAISE_POOL_MSG (SocketPool_Failed,
                      "Invalid NULL pool or socket in SocketPool_remove");
      return;
    }
  assert (pool);
  assert (socket);

  pthread_mutex_lock (&pool->mutex);
  remove_unlocked (pool, socket);
  pthread_mutex_unlock (&pool->mutex);
}

/* ============================================================================
 * Idle Connection Cleanup
 * ============================================================================
 */

/**
 * @brief Check if time difference exceeds timeout.
 * @now Current time
 * @last_activity Last activity time
 * @timeout Timeout in seconds
 *
 * Returns: Non-zero if (now - last_activity) > timeout
 * Thread-safe: Yes - pure function
 */
static int
is_timed_out (time_t now, time_t last_activity, time_t timeout)
{
  return difftime (now, last_activity) > (double)timeout;
}

/**
 * @brief Determine if connection should be closed.
 * @idle_timeout Idle timeout in seconds (0 means close all)
 * @now Current time
 * @last_activity Last activity time
 *
 * Returns: 1 if connection should be closed, 0 otherwise
 * Thread-safe: Yes - pure function
 */
static int
should_close_connection (time_t idle_timeout, time_t now, time_t last_activity)
{
  if (idle_timeout == 0)
    return 1;
  return is_timed_out (now, last_activity, idle_timeout);
}

/**
 * @brief Check if connection is active and idle.
 * @conn Connection to check
 * @idle_timeout Idle timeout in seconds
 * @now Current time
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
 * @brief Process single connection for cleanup.
 * @pool Pool instance
 * @conn Connection to check
 * @idle_timeout Idle timeout in seconds
 * @now Current time
 * @close_count Pointer to count of sockets collected
 *
 * Thread-safe: Call with mutex held
 */
static void
process_connection_for_cleanup (T pool, Connection_T conn, time_t idle_timeout,
                                time_t now, size_t *close_count)
{
  validate_saved_session (conn, now);

  if (is_connection_idle (conn, idle_timeout, now))
    pool->cleanup_buffer[(*close_count)++] = conn->socket;
}

/**
 * @brief Collect idle sockets into buffer.
 * @pool Pool instance
 * @idle_timeout Idle timeout in seconds
 * @now Current time
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
 * @brief Close and remove a single socket from pool.
 * @pool Pool instance
 * @socket Socket to close
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
 * @brief Close and remove collected sockets.
 * @pool Pool instance
 * @close_count Number of sockets to close
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
 * @brief Remove idle connections.
 * @pool Pool instance
 * @idle_timeout Seconds idle before removal (0 = remove all)
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

  if (!pool || !pool->cleanup_buffer)
    {
      SOCKET_LOG_ERROR_MSG (
          "Invalid pool or missing cleanup_buffer in SocketPool_cleanup");
      return;
    }
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
 * ============================================================================
 */

/**
 * @brief Get connection's socket.
 * @conn Connection instance
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
 * @brief Get input buffer.
 * @conn Connection instance
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
 * @brief Get output buffer.
 * @conn Connection instance
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
 * @brief Get user data.
 * @conn Connection instance
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
 * @brief Set user data.
 * @conn Connection instance
 * @data User data pointer to store
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
 * @brief Get last activity time.
 * @conn Connection instance
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
 * @brief Check if connection is active.
 * @conn Connection instance
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

/**
 * @brief Get connection creation timestamp.
 * @conn Connection instance
 *
 * Returns: Creation timestamp (time_t)
 * Thread-safe: Yes - read-only access
 */
time_t
Connection_created_at (const Connection_T conn)
{
  assert (conn);
  return conn->created_at;
}

/* ============================================================================
 * Connection Health Check
 * ============================================================================
 */

/**
 * @brief Check socket for errors via SO_ERROR.
 * @fd File descriptor to check
 *
 * Returns: 0 if no error, non-zero error code otherwise
 * Thread-safe: Yes - pure system call
 */
static int
check_socket_error (int fd)
{
  int error = 0;
  socklen_t len = sizeof (error);

  if (fd < 0)
    return EBADF;

  if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
    return errno;

  return error;
}

/**
 * @brief Check basic socket health (error and connected state).
 * @conn Connection to check
 *
 * Performs SO_ERROR check and connection validity check.
 *
 * Returns: POOL_CONN_HEALTHY if healthy, else specific error code
 * Thread-safe: Yes
 */
static SocketPool_ConnHealth
check_socket_health (const Connection_T conn)
{
  if (!conn->active || !conn->socket)
    return POOL_CONN_DISCONNECTED;

  int fd = Socket_fd (conn->socket);
  if (fd < 0)
    return POOL_CONN_DISCONNECTED;

  int error = check_socket_error (fd);
  if (error != 0)
    {
      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "Connection health check: SO_ERROR=%d (%s)", error,
                       Socket_safe_strerror (error));
      return POOL_CONN_ERROR;
    }

  if (!Socket_isconnected (conn->socket))
    return POOL_CONN_DISCONNECTED;

  return POOL_CONN_HEALTHY;
}

/**
 * @brief Check health of a connection.
 * @pool Pool instance
 * @conn Connection to check
 *
 * Returns: Health status of the connection
 * Thread-safe: Yes
 */
SocketPool_ConnHealth
SocketPool_check_connection (T pool, Connection_T conn)
{
  time_t idle_timeout;

  if (!pool || !conn)
    {
      RAISE_POOL_MSG (
          SocketPool_Failed,
          "Invalid NULL pool or conn in SocketPool_check_connection");
    }
  assert (pool);
  assert (conn);

  SocketPool_ConnHealth res = check_socket_health (conn);
  if (res != POOL_CONN_HEALTHY)
    return res;

  /* Check for staleness */
  pthread_mutex_lock (&pool->mutex);
  pool->stats_health_checks++;
  idle_timeout = pool->idle_timeout_sec;
  time_t check_now = safe_time ();
  int is_stale
      = (idle_timeout > 0
         && is_timed_out (check_now, conn->last_activity, idle_timeout));
  if (is_stale)
    {
      pool->stats_health_failures++;
      pthread_mutex_unlock (&pool->mutex);
      return POOL_CONN_STALE;
    }
  pthread_mutex_unlock (&pool->mutex);

  return POOL_CONN_HEALTHY;
}

#undef T
