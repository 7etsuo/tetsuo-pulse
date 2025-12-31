/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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

/* SOCKET_LOG_COMPONENT defined in SocketPool-private.h */

#if SOCKET_HAS_TLS
#include "socket/Socket-private.h"
#include "socket/SocketIO.h"
#include "tls/SocketTLS.h"
#endif

#define T SocketPool_T

/* Forward declarations - grouped at top for clarity */
static void
release_connection_resources (T pool, Connection_T conn, Socket_T socket);
static void SocketPool_connections_release_buffers (Connection_T conn);
static void
remove_known_connection (T pool, Connection_T conn, Socket_T socket);

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
 */
void
return_to_free_list (T pool, Connection_T conn)
{
  conn->free_next = pool->free_list;
  pool->free_list = conn;
}

/* ============================================================================
 * Active List Management
 * ============================================================================
 */

/**
 * @brief Add connection to active list (O(1) append to tail).
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param conn Connection to add to active list.
 * @threadsafe Call with mutex held.
 *
 * Maintains doubly-linked list of active connections for O(active_count)
 * iteration instead of O(maxconns).
 */
void
add_to_active_list (T pool, Connection_T conn)
{
  conn->active_prev = pool->active_tail;
  conn->active_next = NULL;

  if (pool->active_tail)
    pool->active_tail->active_next = conn;
  else
    pool->active_head = conn;

  pool->active_tail = conn;
}

/**
 * @brief Remove connection from active list (O(1) unlink).
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param conn Connection to remove from active list.
 * @threadsafe Call with mutex held.
 *
 * Uses prev/next pointers for O(1) removal without traversal.
 */
void
remove_from_active_list (T pool, Connection_T conn)
{
  if (conn->active_prev)
    conn->active_prev->active_next = conn->active_next;
  else
    pool->active_head = conn->active_next;

  if (conn->active_next)
    conn->active_next->active_prev = conn->active_prev;
  else
    pool->active_tail = conn->active_prev;

  conn->active_prev = NULL;
  conn->active_next = NULL;
}

/**
 * @brief Prepare a free slot for use.
 * @param pool Pool instance.
 * @param conn Slot to prepare.
 * @return 0 on success, -1 on failure.
 * @threadsafe Call with mutex held.
 */
int
prepare_free_slot (T pool, Connection_T conn)
{
  remove_from_free_list (pool, conn);

  /* Reuse existing buffers if available, otherwise allocate new ones */
  if (conn->inbuf && conn->outbuf)
    {
      SocketPool_connections_release_buffers (conn);
      return 0;
    }

  if (SocketPool_connections_alloc_buffers (pool->arena, pool->bufsize, conn)
      != 0)
    {
      return_to_free_list (pool, conn);
      return -1;
    }

  return 0;
}

/* ============================================================================
 * Connection Slot Operations
 * ============================================================================
 */

/**
 * @brief Update activity timestamp.
 * @param conn Connection to update.
 * @param now Current time.
 * @threadsafe Call with mutex held.
 */
void
update_existing_slot (Connection_T conn, time_t now)
{
  conn->last_activity = now;
}

/**
 * @brief Increment active connection count.
 * @param pool Pool instance.
 * @threadsafe Call with mutex held.
 */
void
increment_pool_count (T pool)
{
  pool->count++;
}

/**
 * @brief Decrement active connection count.
 * @param pool Pool instance.
 * @threadsafe Call with mutex held.
 */
void
decrement_pool_count (T pool)
{
  pool->count--;
}

#if SOCKET_HAS_TLS
/**
 * @brief Clear TLS session if socket changed.
 * @param conn Connection to check.
 * @param new_fd New socket file descriptor.
 * @threadsafe Call with mutex held.
 */
static void
clear_stale_tls_session (Connection_T conn, int new_fd)
{
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
#endif

/**
 * @brief Initialize connection with socket.
 * @param conn Connection to initialize.
 * @param socket Socket to associate.
 * @param now Current time.
 * @threadsafe Call with mutex held.
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
  clear_stale_tls_session (conn, socket ? Socket_fd (socket) : -1);
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
 * @param sess Session to check.
 * @param now Current time.
 * @return Non-zero if session is expired.
 * @threadsafe Yes - uses OpenSSL thread-safe accessors.
 *
 * Security: Uses subtraction instead of addition to avoid integer overflow
 * when session timestamp or timeout has extreme values. If current time is
 * before session time (clock went backwards), session is considered valid.
 */
static int
session_is_expired (const SSL_SESSION *sess, time_t now)
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

  /* Safe: now >= sess_time, so subtraction won't underflow
   * Cast sess_timeout to time_t to ensure type consistency in comparison */
  return (now - sess_time) >= (time_t)sess_timeout;
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
  TRY
  {
    SocketTLS_shutdown (socket);
  }
  ELSE
  { /* Ignore all errors during cleanup */
  }
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
  SocketPool_connections_release_buffers (conn);
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
  add_to_active_list (pool, conn);
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
 * @brief Check if pool is accepting new connections (unlocked version).
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @return 1 if accepting (RUNNING state), 0 if draining or stopped.
 * @threadsafe Call with mutex held.
 *
 * Internal version that assumes mutex is already held by caller.
 * Uses atomic load with acquire semantics for state visibility.
 *
 * @see SocketPool_state() for public state query.
 * @see SocketPool_is_draining() for drain status check.
 */
static int
is_pool_accepting_unlocked (const T pool)
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
  if (!is_pool_accepting_unlocked (pool))
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
 * @param pool Pool instance.
 * @param socket Socket to add.
 * @return Connection or NULL if pool is full.
 * @throws SocketPool_Failed on NULL parameters.
 * @threadsafe Yes - uses internal mutex.
 *
 * Pool full check is performed under mutex to prevent race conditions.
 */
Connection_T
SocketPool_add (T pool, Socket_T socket)
{
  if (!pool || !socket)
    SOCKET_RAISE_MSG (SocketPool,
                      SocketPool_Failed,
                      "Invalid NULL pool or socket in SocketPool_add");

  time_t now = safe_time ();

  POOL_LOCK (pool);
  Connection_T conn = add_unlocked (pool, socket, now);
  POOL_UNLOCK (pool);

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
 * @return 1 if connection is valid (or no callback set), 0 if invalid and
 * removed.
 * @threadsafe Call with mutex held.
 *
 * Executes the validation callback with temporary mutex release to avoid
 * deadlock. Re-acquires mutex and re-validates connection state. Removes
 * connection internally if invalid.
 */
static int
run_validation_callback_unlocked (T pool, Connection_T conn)
{
  SocketPool_ValidationCallback cb = pool->validation_cb;
  void *cb_data = pool->validation_cb_data;
  Socket_T socket;

  if (!cb)
    return 1; /* No callback = always valid */

  /* Save socket identity while mutex is held. The connection may be removed
   * concurrently while the callback runs (mutex temporarily released), and
   * removal resets conn->socket to NULL. */
  socket = Connection_socket (conn);

  /* Temporarily release mutex for callback to avoid deadlock/long holds.
   * Re-acquire to safely remove if invalid. Races handled by re-validation. */
  POOL_UNLOCK (pool);

  int valid = cb (conn, cb_data);

  POOL_LOCK (pool);

  /* Re-validate: Check if connection still exists and matches */
  Connection_T current_conn = find_slot (pool, socket);
  if (!current_conn || current_conn != conn)
    {
      /* Already removed by another thread - assume handled */
      if (!valid)
        SocketLog_emitf (SOCKET_LOG_DEBUG,
                         SOCKET_LOG_COMPONENT,
                         "Validation invalid but connection already removed");
      return 1; /* Treat as valid (gone) */
    }

  if (valid)
    return 1;

  /* Still invalid and present - remove it */
  pool->stats_validation_failures++;
  SocketLog_emitf (SOCKET_LOG_DEBUG,
                   SOCKET_LOG_COMPONENT,
                   "Connection validation callback returned invalid - "
                   "removing");
  remove_known_connection (pool, conn, conn->socket);
  return 0;
}

/**
 * @brief Look up connection by socket.
 * @param pool Pool instance.
 * @param socket Socket to find.
 * @return Connection or NULL if not found or validation failed.
 * @threadsafe Yes - uses internal mutex.
 *
 * If a validation callback is set, it is called before returning the
 * connection. If the callback returns 0, the connection is removed
 * from the pool and NULL is returned.
 */
Connection_T
SocketPool_get (T pool, Socket_T socket)
{
  if (!pool || !socket)
    SOCKET_RAISE_MSG (SocketPool,
                      SocketPool_Failed,
                      "Invalid NULL pool or socket in SocketPool_get");

  time_t now = safe_time ();

  POOL_LOCK (pool);
  Connection_T conn = get_unlocked (pool, socket, now);

  /* Run validation callback if connection found */
  if (conn)
    {
      if (!run_validation_callback_unlocked (pool, conn))
        {
          /* Callback returned invalid and already removed connection */
          POOL_UNLOCK (pool);
          return NULL;
        }
      /* Valid connection - update stats */
    }

  POOL_UNLOCK (pool);
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
  remove_from_active_list (pool, conn);
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
 * @param pool Pool instance.
 * @param socket Socket to remove.
 * @throws SocketPool_Failed on NULL parameters.
 * @threadsafe Yes - uses internal mutex.
 *
 * Handles TLS session save, IP tracking release, buffer clearing,
 * and returns slot to free list.
 */
void
SocketPool_remove (T pool, Socket_T socket)
{
  if (!pool || !socket)
    SOCKET_RAISE_MSG (SocketPool,
                      SocketPool_Failed,
                      "Invalid NULL pool or socket in SocketPool_remove");

  POOL_LOCK (pool);
  remove_unlocked (pool, socket);
  POOL_UNLOCK (pool);
}

/* ============================================================================
 * Idle Connection Cleanup
 * ============================================================================
 */

/**
 * @brief Check if connection has exceeded idle timeout (overflow-safe).
 * @param last_activity Last activity timestamp
 * @param idle_timeout Idle timeout in seconds
 * @param now Current time
 * @return Non-zero if idle, zero otherwise
 * @threadsafe Yes - pure computation
 *
 * Security: Uses subtraction instead of difftime() to avoid overflow.
 * Handles clock going backwards gracefully.
 */
static int
is_idle_time_exceeded (time_t last_activity, time_t idle_timeout, time_t now)
{
  /* Security: Avoid overflow by using subtraction instead of difftime().
   * If now < last_activity (clock went backwards), not idle. */
  if (now < last_activity)
    return 0;

  /* Safe: now >= last_activity, so subtraction won't underflow */
  return (now - last_activity) >= idle_timeout;
}

/**
 * @brief Check if connection is active and has exceeded idle timeout.
 * @conn Connection to check
 * @idle_timeout Idle timeout in seconds (0 means close all active connections)
 * @now Current time
 *
 * Returns: 1 if connection should be collected for cleanup, 0 otherwise
 * Thread-safe: Call with mutex held
 *
 * Consolidates active check, socket validity check, and idle timeout check
 * into a single function. Idle timeout of 0 indicates all active connections
 * should be closed.
 */
static int
is_connection_idle (const Connection_T conn, time_t idle_timeout, time_t now)
{
  if (!conn->active || !conn->socket)
    return 0;

  /* Idle timeout of 0 means close all active connections */
  if (idle_timeout == 0)
    return 1;

  return is_idle_time_exceeded (conn->last_activity, idle_timeout, now);
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
process_connection_for_cleanup (T pool,
                                Connection_T conn,
                                time_t idle_timeout,
                                time_t now,
                                size_t *close_count)
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
 * Complexity: O(active_connections) instead of O(maxconns)
 */
static size_t
collect_idle_sockets (T pool, time_t idle_timeout, time_t now)
{
  size_t close_count = 0;

  for (Connection_T conn = pool->active_head; conn != NULL;
       conn = conn->active_next)
    process_connection_for_cleanup (
        pool, conn, idle_timeout, now, &close_count);

  return close_count;
}

/**
 * @brief Close and remove collected sockets.
 * @pool Pool instance
 * @close_count Number of sockets to close
 *
 * Thread-safe: Yes - each socket operation is thread-safe
 * Uses shared socketpool_close_socket_safe() helper directly.
 */
static void
close_collected_sockets (T pool, size_t close_count)
{
  for (size_t i = 0; i < close_count; i++)
    socketpool_close_socket_safe (pool, &pool->cleanup_buffer[i], "Cleanup");
}

/**
 * @brief Remove idle connections.
 * @param pool Pool instance.
 * @param idle_timeout Seconds idle before removal (0 = remove all).
 * @threadsafe Yes.
 * @complexity O(active_connections) - scans only active connections via active
 * list.
 *
 * Collects idle sockets under mutex, then closes them outside mutex
 * to avoid deadlock with socket operations.
 */
void
SocketPool_cleanup (T pool, time_t idle_timeout)
{
  if (!pool || !pool->cleanup_buffer)
    {
      SOCKET_LOG_ERROR_MSG (
          "Invalid pool or missing cleanup_buffer in SocketPool_cleanup");
      return;
    }

  time_t now = safe_time ();

  POOL_LOCK (pool);
  size_t close_count = collect_idle_sockets (pool, idle_timeout, now);
  POOL_UNLOCK (pool);

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
    {
      int saved_errno = errno;
      return saved_errno;
    }

  return error;
}

/**
 * @brief Check basic socket health (error and connected state).
 * @param conn Connection to check.
 * @return POOL_CONN_HEALTHY if healthy, else specific error code.
 * @threadsafe Yes.
 *
 * Performs SO_ERROR check and connection validity check.
 */
static SocketPool_ConnHealth
check_socket_health (const Connection_T conn)
{
  if (!conn->active || !conn->socket)
    return POOL_CONN_DISCONNECTED;

  const int fd = Socket_fd (conn->socket);
  if (fd < 0)
    return POOL_CONN_DISCONNECTED;

  const int error = check_socket_error (fd);
  if (error != 0)
    {
      SocketLog_emitf (SOCKET_LOG_DEBUG,
                       SOCKET_LOG_COMPONENT,
                       "Connection health check: SO_ERROR=%d (%s)",
                       error,
                       Socket_safe_strerror (error));
      return POOL_CONN_ERROR;
    }

  if (!Socket_isconnected (conn->socket))
    return POOL_CONN_DISCONNECTED;

  return POOL_CONN_HEALTHY;
}

/**
 * @brief Check if connection is stale (exceeded idle timeout).
 * @param pool Pool instance (mutex held).
 * @param conn Connection to check.
 * @param now Current time.
 * @return Non-zero if connection is stale.
 * @threadsafe Call with mutex held.
 */
static int
check_connection_staleness (T pool, Connection_T conn, time_t now)
{
  time_t idle_timeout = pool->idle_timeout_sec;
  if (idle_timeout <= 0)
    return 0;

  return is_idle_time_exceeded (conn->last_activity, idle_timeout, now);
}

/**
 * @brief Check health of a connection.
 * @param pool Pool instance.
 * @param conn Connection to check.
 * @return Health status of the connection.
 * @throws SocketPool_Failed on NULL parameters.
 * @threadsafe Yes.
 */
SocketPool_ConnHealth
SocketPool_check_connection (T pool, Connection_T conn)
{
  if (!pool || !conn)
    SOCKET_RAISE_MSG (
        SocketPool,
        SocketPool_Failed,
        "Invalid NULL pool or conn in SocketPool_check_connection");

  SocketPool_ConnHealth res = check_socket_health (conn);
  if (res != POOL_CONN_HEALTHY)
    return res;

  /* Check for staleness */
  POOL_LOCK (pool);
  pool->stats_health_checks++;
  time_t now = safe_time ();
  int is_stale = check_connection_staleness (pool, conn, now);
  if (is_stale)
    pool->stats_health_failures++;
  POOL_UNLOCK (pool);

  return is_stale ? POOL_CONN_STALE : POOL_CONN_HEALTHY;
}

#undef T
