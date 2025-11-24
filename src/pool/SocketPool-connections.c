/**
 * SocketPool-connections.c - Connection add/get/remove and hash management
 * Handles adding sockets to pool, retrieving connections, removing, and hash
 * operations.
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
#include "dns/SocketDNS.h"
#include "pool/SocketPool-private.h"
#include "pool/SocketPool.h"
#include "socket/SocketBuf.h"

#include "pool/SocketPool-core.h" /* For safe_time */

#ifdef SOCKET_HAS_TLS
#include "socket/SocketIO.h"
#include "tls/SocketTLS.h"
#include "socket/Socket-private.h"
#endif

#define T SocketPool_T

extern const Except_T SocketPool_Failed;
extern __thread Except_T SocketPool_DetailedException; /* From core */

#define RAISE_POOL_ERROR(exception)                                           \
  do                                                                          \
    {                                                                         \
      SocketPool_DetailedException = (exception);                             \
      SocketPool_DetailedException.reason = socket_error_buf;                 \
      RAISE (SocketPool_DetailedException);                                   \
    }                                                                         \
  while (0)

#define SOCKET_HASH_SIZE 1021
#define HASH_GOLDEN_RATIO 2654435761u

/**
 * socket_hash - Compute hash value for socket file descriptor
 * @socket: Socket instance to hash (const)
 *
 * Returns: Unsigned hash value
 * Thread-safe: Yes - pure function
 * Performance: O(1)
 */
static unsigned
socket_hash (const Socket_T socket)
{
  int fd;

  assert (socket);
  fd = Socket_fd (socket);
  if (fd < 0) {
    SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                     "Attempt to hash closed/invalid socket (fd=%d); returning 0", fd);
    return 0;
  }

  return ((unsigned)fd * HASH_GOLDEN_RATIO) % SOCKET_HASH_SIZE;
}

/**
 * SocketPool_connections_allocate_array - Allocate connections array
 * @maxconns: Number of slots
 *
 * Returns: Allocated array or NULL
 * Raises: SocketPool_Failed on failure
 */
struct Connection *
SocketPool_connections_allocate_array (size_t maxconns)
{
  struct Connection *connections
      = calloc (maxconns, sizeof (struct Connection));
  if (!connections)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate connections array");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  return connections;
}

/**
 * SocketPool_connections_allocate_hash_table - Allocate hash table
 * @arena: Arena
 *
 * Returns: Allocated table (Connection_T *)
 * Raises: On failure
 */
Connection_T *
SocketPool_connections_allocate_hash_table (Arena_T arena)
{
  Connection_T *hash_table
      = CALLOC (arena, SOCKET_HASH_SIZE, sizeof (Connection_T));
  if (!hash_table)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate hash table");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  return hash_table;
}

/**
 * SocketPool_cleanup_allocate_buffer - Allocate cleanup buffer
 * @arena: Arena
 * @maxconns: Size
 *
 * Returns: Buffer
 * Raises: On failure
 */
Socket_T *
SocketPool_cleanup_allocate_buffer (Arena_T arena, size_t maxconns)
{
  Socket_T *cleanup_buffer = CALLOC (arena, maxconns, sizeof (Socket_T));
  if (!cleanup_buffer)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate cleanup buffer");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  return cleanup_buffer;
}

/**
 * SocketPool_connections_initialize_slot - Initialize slot
 * @conn: Slot
 *
 * Thread-safe: Yes
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
  // Removed unused TLS fields - state managed by Socket_T
}

/**
 * SocketPool_connections_alloc_buffers - Alloc buffers for slot
 * @arena: Arena
 * @bufsize: Size
 * @conn: Slot
 *
 * Returns: 0 success, -1 fail (partial cleanup)
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

/**
 * find_slot - Look up active connection by socket
 * @pool: Pool
 * @socket: Socket (const)
 * Returns: Conn or NULL
 * Thread-safe: Mutex held
 */
Connection_T
find_slot (T pool, const Socket_T socket)
{
  unsigned hash = socket_hash (socket);
  Connection_T conn = pool->hash_table[hash];

  while (conn)
    {
      if (conn->active && conn->socket == socket)
        return conn;
      conn = conn->hash_next;
    }
  return NULL;
}

/**
 * find_free_slot - Find free slot
 * @pool: Pool
 * Returns: Slot or NULL
 * Thread-safe: Mutex held
 */
Connection_T
find_free_slot (T pool)
{
  return pool->free_list;
}

/**
 * check_pool_full - Check if pool full
 * @pool: Pool
 * Returns: Non-zero if full
 */
int
check_pool_full (T pool)
{
  return pool->count >= pool->maxconns;
}

/**
 * remove_from_free_list - Remove from free list
 * @pool: Pool
 * @conn: Conn
 */
void
remove_from_free_list (T pool, Connection_T conn)
{
  pool->free_list = (struct Connection *)conn->free_next;
}

/**
 * return_to_free_list - Return to free list
 * @pool: Pool
 * @conn: Conn
 */
void
return_to_free_list (T pool, Connection_T conn)
{
  conn->free_next = (struct Connection *)pool->free_list;
  pool->free_list = conn;
}

/**
 * prepare_free_slot - Prepare slot for use
 * @pool: Pool
 * @conn: Slot
 * Returns: 0 success, -1 fail
 * Thread-safe: Mutex held
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
 * update_existing_slot - Update activity for existing
 * @conn: Conn
 * @now: Time
 */
void
update_existing_slot (Connection_T conn, time_t now)
{
  conn->last_activity = now;
}

/**
 * insert_into_hash_table - Insert conn into hash
 * @pool: Pool
 * @conn: Conn
 * @socket: Socket
 * Thread-safe: Mutex held
 */
void
insert_into_hash_table (T pool, Connection_T conn, Socket_T socket)
{
  unsigned hash = socket_hash (socket);
  conn->hash_next = pool->hash_table[hash];
  pool->hash_table[hash] = conn;
}

/**
 * increment_pool_count - Increment count
 * @pool: Pool
 */
void
increment_pool_count (T pool)
{
  pool->count++;
}

/**
 * initialize_connection - Init conn with socket
 * @conn: Conn
 * @socket: Socket
 * @now: Time
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
 * find_or_create_slot - Find or create slot
 * @pool: Pool
 * @socket: Socket
 * @now: Time
 * Returns: Conn or NULL
 * Thread-safe: Mutex held
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
 * SocketPool_get - Look up connection by socket
 * @pool: Pool
 * @socket: Socket
 * Returns: Conn or NULL
 * Thread-safe: Yes
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
#endif
}

/**
 * SocketPool_add - Add socket to pool
 * @pool: Pool
 * @socket: Socket
 * Returns: Conn or NULL if full
 * Thread-safe: Yes
 */
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

#ifdef SOCKET_HAS_TLS
  if (conn && socket_is_tls_enabled (socket) && conn->tls_session)
    {
      SSL *ssl = (SSL *) socket->tls_ssl;
      if (ssl)
        {
          if (SSL_set_session (ssl, conn->tls_session) != 1)
            {
              SSL_SESSION_free (conn->tls_session);
              conn->tls_session = NULL;
            }
          // else resumption setup successful
        }
    }
#endif

  pthread_mutex_unlock (&pool->mutex);

  return conn;
}

/**
 * remove_from_hash_table - Remove from hash
 * @pool: Pool
 * @conn: Conn
 * @socket: Socket
 * Thread-safe: Mutex held
 */
void
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
 * SocketPool_connections_release_buffers - Release buffers
 * @conn: Conn
 */
void
SocketPool_connections_release_buffers (Connection_T conn)
{
  if (conn->inbuf)
    {
      SocketBuf_secureclear (conn->inbuf);
    }

  if (conn->outbuf)
    {
      SocketBuf_secureclear (conn->outbuf);
    }
}

/**
 * SocketPool_connections_reset_slot - Reset slot
 * @conn: Conn
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
  /* Keep tls_session for potential reuse in future socket on this slot */
#endif
}

/**
 * decrement_pool_count - Decrement count
 * @pool: Pool
 */
void
decrement_pool_count (T pool)
{
  pool->count--;
}

/**
 * SocketPool_remove - Remove socket from pool
 * @pool: Pool
 * @socket: Socket
 * Thread-safe: Yes
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
  /* Cleanup TLS state if present */
  /* TLS shutdown should happen before socket close */
  if (socket_is_tls_enabled (socket))
    {
      /* Ignore shutdown errors during cleanup */
      TRY { SocketTLS_shutdown (socket); }
      ELSE { /* Consume exception - we are closing anyway */ }
      END_TRY;

      /* Save session for potential reuse in future connections */
      SSL *ssl = (SSL *) socket->tls_ssl;
      if (ssl) {
        SSL_SESSION *sess = SSL_get1_session(ssl);
        if (sess) {
          conn->tls_session = sess;
        }
      }
    }
#endif

  SocketPool_connections_release_buffers (conn);
  SocketPool_connections_reset_slot (conn);
  return_to_free_list (pool, conn);
  decrement_pool_count (pool);
  SocketMetrics_increment (SOCKET_METRIC_POOL_CONNECTIONS_REMOVED, 1);

  pthread_mutex_unlock (&pool->mutex);
}

/* Accessors */
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

/* Internal data for async pool connection */
struct PoolConnectUdata
{
  T pool;
  SocketPool_ConnectCallback cb;
  void *data;
  Socket_T socket;
};

/* Internal callback for DNS completion in async connect - #if 0 until implemented/used
 * Enables async DNS for connect; currently sync Socket_connect blocks or uses SocketDNS for non-blocking.
 */
#if 0
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
static void __attribute__((unused))
pool_dns_connect_completion (SocketDNS_Request_T req, struct addrinfo *result,
                             int dns_error, void *user_data)
{
  (void)pool_dns_connect_completion;  /* Suppress unused function warning until called */
  (void)req;  /* Unused param for now; future use for request cleanup */
  struct PoolConnectUdata *udata = user_data;
  Connection_T conn = NULL;
  int error = 0;

  if (dns_error || !result)
    {
      error = dns_error ? dns_error : EAI_FAIL;
    }
  else
    {
      TRY
      {
        Socket_connect_with_addrinfo (udata->socket, result);
        freeaddrinfo (result);
        conn = SocketPool_add (udata->pool, udata->socket);
        if (!conn)
          {
            error = errno ? errno : ENOMEM;
            Socket_free (&udata->socket);
          }
      }
      EXCEPT (Socket_Failed)
      {
        error = errno ? errno : ECONNREFUSED;
        if (result)
          freeaddrinfo (result);
        Socket_free (&udata->socket);
      }
      END_TRY;
    }
}
#pragma GCC diagnostic pop
#endif /* 0 - Enable when async DNS connect implemented */
  /* TODO: Call completion cb in sync mode or when async enabled 
   * udata->cb (conn, error, udata->data);
   */

  /* udata lifetime managed by pool arena - freed on pool disposal or manual
   * cleanup if needed 
   * Note: DNS callback stubbed; cb call in sync path above
   */

int
SocketPool_prepare_connection (T pool, SocketDNS_T dns, const char *host,
                               int port, Socket_T *out_socket,
                               SocketDNS_Request_T *out_req)
{
  Socket_T socket = NULL;
  SocketDNS_Request_T req = NULL;

  if (!pool || !dns || !host || !SOCKET_VALID_PORT (port) || !out_socket
      || !out_req)
    {
      RAISE_POOL_ERROR (SocketPool_Failed);
    }

  TRY
  {
    socket = Socket_new (AF_UNSPEC, SOCK_STREAM, 0);
    if (!socket)
      RAISE_POOL_ERROR (SocketPool_Failed);

    Socket_setnonblocking (socket);
    Socket_setreuseaddr (socket); /* Pool default */

    /* Apply pool defaults (nodelay, keepalive, timeouts, etc.) from config */
    SocketTimeouts_T timeouts;
    Socket_timeouts_getdefaults (&timeouts);
    Socket_timeouts_set (socket, &timeouts);

    req = Socket_connect_async (dns, socket, host, port);
    if (!req)
      {
        Socket_free (&socket);
        RAISE_POOL_ERROR (SocketPool_Failed);
      }

    *out_socket = socket;
    *out_req = req;
  }
  EXCEPT (Socket_Failed)
  {
    if (socket)
      Socket_free (&socket);
    RERAISE;
  }
  END_TRY;

  return 0;
}

#undef T
