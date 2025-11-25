/**
 * SocketPool-connections.c - Connection management operations
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Handles adding sockets to pool, retrieving connections, and removal.
 */

#include <assert.h>
#include <errno.h>
#include <time.h>

#include "core/SocketMetrics.h"
#include "pool/SocketPool-private.h"

#ifdef SOCKET_HAS_TLS
#include "socket/Socket-private.h"
#include "socket/SocketIO.h"
#include "tls/SocketTLS.h"
#endif

#define T SocketPool_T

/* SocketPool_Failed declared in SocketPool.h (included via private header) */

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
#endif

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

/**
 * decrement_pool_count - Decrement active connection count
 * @pool: Pool instance
 */
void
decrement_pool_count (T pool)
{
  pool->count--;
}

#ifdef SOCKET_HAS_TLS
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

#undef T
