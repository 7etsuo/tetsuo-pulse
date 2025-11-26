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
#include <errno.h>
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
find_free_slot (T pool)
{
  return pool->free_list;
}

/**
 * check_pool_full - Check if pool is at capacity
 * @pool: Pool instance
 *
 * Returns: Non-zero if full
 */
int
check_pool_full (T pool)
{
  return pool->count >= pool->maxconns;
}

/**
 * remove_from_free_list - Remove connection from free list
 * @pool: Pool instance
 * @conn: Connection to remove
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
 */
void
return_to_free_list (T pool, Connection_T conn)
{
  conn->free_next = pool->free_list;
  pool->free_list = conn;
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

  if (conn->inbuf && conn->outbuf)
    {
      SocketBuf_secureclear (conn->inbuf);
      SocketBuf_secureclear (conn->outbuf);
    }
  else
    {
      if (SocketPool_connections_alloc_buffers (pool->arena, pool->bufsize,
                                                conn)
          != 0)
        {
          return_to_free_list (pool, conn);
          return -1;
        }
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
 */
void
update_existing_slot (Connection_T conn, time_t now)
{
  conn->last_activity = now;
}

/**
 * increment_pool_count - Increment active connection count
 * @pool: Pool instance
 */
void
increment_pool_count (T pool)
{
  pool->count++;
}

/**
 * decrement_pool_count - Decrement active connection count
 * @pool: Pool instance
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
 * SocketPool_connections_reset_slot - Reset connection slot to inactive
 * @conn: Connection to reset
 */
void
SocketPool_connections_reset_slot (Connection_T conn)
{
  conn->socket = NULL;
  conn->data = NULL;
  conn->last_activity = 0;
  conn->active = 0;
#ifdef SOCKET_HAS_TLS
  conn->tls_ctx = NULL;
  conn->tls_handshake_complete = 0;
#endif
}

/* ============================================================================
 * TLS Session Management
 * ============================================================================ */

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
  if (conn->tls_session)
    {
      time_t now = time (NULL);
      time_t sess_time = SSL_SESSION_get_time (conn->tls_session);
      long sess_timeout = SSL_SESSION_get_timeout (conn->tls_session);

      if (now >= sess_time + sess_timeout)
        {
          SSL_SESSION_free (conn->tls_session);
          conn->tls_session = NULL;
        }
    }
#else
  (void)conn;
#endif
}

#ifdef SOCKET_HAS_TLS
/**
 * setup_tls_session_resumption - Try to resume saved TLS session
 * @conn: Connection with potential saved session
 * @socket: Socket to configure
 */
static void
setup_tls_session_resumption (Connection_T conn, Socket_T socket)
{
  if (socket_is_tls_enabled (socket) && conn->tls_session)
    {
      SSL *ssl = (SSL *)socket->tls_ssl;
      if (ssl && SSL_set_session (ssl, conn->tls_session) != 1)
        {
          SSL_SESSION_free (conn->tls_session);
          conn->tls_session = NULL;
        }
    }
}

/**
 * cleanup_tls_and_save_session - Shutdown TLS and save session
 * @conn: Connection
 * @socket: Socket with TLS
 */
static void
cleanup_tls_and_save_session (Connection_T conn, Socket_T socket)
{
  if (socket_is_tls_enabled (socket))
    {
      TRY { SocketTLS_shutdown (socket); }
      ELSE { /* Ignore errors during cleanup */ }
      END_TRY;

      SSL *ssl = (SSL *)socket->tls_ssl;
      if (ssl)
        {
          SSL_SESSION *sess = SSL_get1_session (ssl);
          if (sess)
            conn->tls_session = sess;
        }
    }
}
#endif

/* ============================================================================
 * Connection Add/Get/Remove API
 * ============================================================================ */

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
    {
      update_existing_slot (conn, now);
      SocketMetrics_increment (SOCKET_METRIC_POOL_CONNECTIONS_REUSED, 1);
      return conn;
    }

  conn = find_free_slot (pool);
  if (!conn || prepare_free_slot (pool, conn) != 0)
    return NULL;

  initialize_connection (conn, socket, now);
  insert_into_hash_table (pool, conn, socket);
  increment_pool_count (pool);
  SocketMetrics_increment (SOCKET_METRIC_POOL_CONNECTIONS_ADDED, 1);
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

  /* Check pool full under mutex to prevent race condition */
  if (check_pool_full (pool))
    {
      pthread_mutex_unlock (&pool->mutex);
      return NULL;
    }

  conn = find_or_create_slot (pool, socket, now);
#ifdef SOCKET_HAS_TLS
  if (conn)
    setup_tls_session_resumption (conn, socket);
#endif
  pthread_mutex_unlock (&pool->mutex);

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
  conn = find_slot (pool, socket);
  if (conn)
    {
      conn->last_activity = now;
      validate_saved_session (conn);
    }
  pthread_mutex_unlock (&pool->mutex);

  return conn;
}

/**
 * SocketPool_remove - Remove socket from pool
 * @pool: Pool instance
 * @socket: Socket to remove
 *
 * Thread-safe: Yes - uses internal mutex
 */
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

#ifdef SOCKET_HAS_TLS
  cleanup_tls_and_save_session (conn, socket);
#endif

  SocketPool_connections_release_buffers (conn);
  SocketPool_connections_reset_slot (conn);
  return_to_free_list (pool, conn);
  decrement_pool_count (pool);
  SocketMetrics_increment (SOCKET_METRIC_POOL_CONNECTIONS_REMOVED, 1);

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
 * Returns: 1 if close, 0 otherwise
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
 * should_collect_socket - Check if socket should be collected
 * @conn: Connection
 * @idle_timeout: Timeout
 * @now: Time
 *
 * Returns: 1 if collect
 */
static int
should_collect_socket (const Connection_T conn, time_t idle_timeout,
                       time_t now)
{
  if (!conn->active || !conn->socket)
    return 0;

  return should_close_connection (idle_timeout, now, conn->last_activity);
}

/**
 * collect_idle_sockets - Collect idle sockets into buffer
 * @pool: Pool
 * @idle_timeout: Timeout
 * @now: Time
 *
 * Returns: Count collected
 * Thread-safe: Mutex held
 */
static size_t
collect_idle_sockets (T pool, time_t idle_timeout, time_t now)
{
  size_t i;
  size_t close_count = 0;

  for (i = 0; i < pool->maxconns; i++)
    {
      validate_saved_session (&pool->connections[i]);
      if (should_collect_socket (&pool->connections[i], idle_timeout, now))
        {
          pool->cleanup_buffer[close_count++] = pool->connections[i].socket;
        }
    }
  return close_count;
}

/**
 * close_collected_sockets - Close and remove collected
 * @pool: Pool
 * @close_count: Count
 *
 * Thread-safe: No mutex - call outside lock
 * Logs errors at DEBUG level rather than silently ignoring them.
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
        SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                         "Cleanup: socket already removed from pool");
      }
      EXCEPT (Socket_Failed)
      {
        SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                         "Cleanup: socket free failed (may be closed)");
      }
      END_TRY;
    }
}

/**
 * SocketPool_cleanup - Remove idle connections
 * @pool: Pool
 * @idle_timeout: Seconds idle before removal (0 = all)
 *
 * Thread-safe: Yes
 * Performance: O(n) scan
 */
void
SocketPool_cleanup (T pool, time_t idle_timeout)
{
  time_t now;
  size_t close_count;

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
  EXCEPT (SocketPool_Failed) { /* Already raised */ }
  END_TRY;
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
