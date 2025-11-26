/**
 * SocketPool-ops.c - Pool operations: resize, tuning, accept, async
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Consolidated from:
 * - Pool resize and capacity management
 * - Pre-warming, buffer configuration, iteration
 * - Batch connection acceptance
 * - Async DNS connection preparation
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dns/SocketDNS.h"
#include "pool/SocketPool-private.h"
#include "socket/SocketCommon.h"

#define T SocketPool_T

/** Percentage divisor for pre-warm calculations */
#define PERCENTAGE_DIVISOR 100

/* ============================================================================
 * Pool Resize Operations
 * ============================================================================ */

/**
 * collect_excess_connections - Collect excess active connections for closing
 * @pool: Pool instance
 * @new_maxconns: New maximum capacity
 * @excess_sockets: Output array for excess sockets (pre-allocated)
 *
 * Returns: Number of excess connections found
 * Thread-safe: Call with mutex held
 */
static size_t
collect_excess_connections (T pool, size_t new_maxconns,
                            Socket_T *excess_sockets)
{
  size_t excess_count = 0;
  size_t target = pool->count - new_maxconns;

  if (pool->count <= new_maxconns)
    return 0;

  for (size_t i = 0; i < pool->maxconns && excess_count < target; i++)
    {
      struct Connection *conn = &pool->connections[i];
      if (conn->active && conn->socket)
        excess_sockets[excess_count++] = conn->socket;
    }

  return excess_count;
}

/**
 * realloc_connections_array - Reallocate connections array
 * @pool: Pool instance
 * @new_maxconns: New size
 *
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Call with mutex held
 */
static int
realloc_connections_array (T pool, size_t new_maxconns)
{
  struct Connection *new_connections;

  new_connections
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
 *
 * Thread-safe: Call with mutex held
 * Clears hash_table and re-inserts all active connections.
 */
static void
rehash_active_connections (T pool, size_t new_maxconns)
{
  memset (pool->hash_table, 0,
          sizeof (pool->hash_table[0]) * SOCKET_HASH_SIZE);

  for (size_t i = 0; i < new_maxconns; i++)
    {
      Connection_T conn = &pool->connections[i];
      if (conn->active && conn->socket)
        insert_into_hash_table (pool, conn, conn->socket);
    }
}

/**
 * relink_free_slots - Relink free slots to free_list
 * @pool: Pool instance
 * @maxconns: Limit for scanning (new effective max)
 *
 * Thread-safe: Call with mutex held
 * Scans slots, initializes and links only inactive (free) slots.
 */
static void
relink_free_slots (T pool, size_t maxconns)
{
  pool->free_list = NULL;

  for (size_t i = 0; i < maxconns; i++)
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
 * initialize_new_slots - Initialize newly allocated connection slots
 * @pool: Pool instance
 * @old_maxconns: Old size
 * @new_maxconns: New size
 *
 * Thread-safe: Call with mutex held
 */
static void
initialize_new_slots (T pool, size_t old_maxconns, size_t new_maxconns)
{
  for (size_t i = old_maxconns; i < new_maxconns; i++)
    {
      struct Connection *conn = &pool->connections[i];
      SocketPool_connections_initialize_slot (conn);

      if (SocketPool_connections_alloc_buffers (pool->arena, pool->bufsize,
                                                conn)
          == 0)
        {
          conn->free_next = pool->free_list;
          pool->free_list = conn;
        }
    }
}

/**
 * close_excess_sockets - Close and remove excess sockets
 * @pool: Pool instance
 * @excess_sockets: Array of sockets to close
 * @excess_count: Number of sockets
 *
 * Thread-safe: Called outside lock
 */
static void
close_excess_sockets (T pool, Socket_T *excess_sockets, size_t excess_count)
{
  for (size_t i = 0; i < excess_count; i++)
    {
      if (excess_sockets[i])
        {
          SocketPool_remove (pool, excess_sockets[i]);
          Socket_free (&excess_sockets[i]);
        }
    }
}

/**
 * allocate_excess_buffer - Allocate buffer for excess sockets
 * @excess_count: Number needed
 *
 * Returns: Allocated buffer or NULL
 */
static Socket_T *
allocate_excess_buffer (size_t excess_count)
{
  return calloc (excess_count, sizeof (Socket_T));
}

/**
 * handle_shrink_excess - Handle excess connections when shrinking
 * @pool: Pool instance
 * @new_maxconns: New capacity
 *
 * Thread-safe: Releases and reacquires mutex as needed
 * Returns: 0 on success, raises exception on failure
 */
static void
handle_shrink_excess (T pool, size_t new_maxconns)
{
  size_t excess_count;
  Socket_T *excess_sockets;
  size_t collected;

  excess_count
      = pool->count > new_maxconns ? (pool->count - new_maxconns) : 0;

  if (excess_count == 0)
    return;

  excess_sockets = allocate_excess_buffer (excess_count);
  if (!excess_sockets)
    {
      pthread_mutex_unlock (&pool->mutex);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate excess buffer");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }

  collected = collect_excess_connections (pool, new_maxconns, excess_sockets);
  assert (collected == excess_count);

  pthread_mutex_unlock (&pool->mutex);
  close_excess_sockets (pool, excess_sockets, excess_count);
  free (excess_sockets);
  pthread_mutex_lock (&pool->mutex);
}

/**
 * SocketPool_resize - Resize pool capacity at runtime
 * @pool: Pool instance
 * @new_maxconns: New maximum connection capacity
 *
 * Raises: SocketPool_Failed on error
 * Thread-safe: Yes - uses internal mutex
 */
void
SocketPool_resize (T pool, size_t new_maxconns)
{
  size_t old_maxconns;

  assert (pool);

  new_maxconns = socketpool_enforce_max_connections (new_maxconns);

  pthread_mutex_lock (&pool->mutex);

  old_maxconns = pool->maxconns;

  if (new_maxconns == old_maxconns)
    {
      pthread_mutex_unlock (&pool->mutex);
      return;
    }

  if (new_maxconns < old_maxconns)
    handle_shrink_excess (pool, new_maxconns);

  if (realloc_connections_array (pool, new_maxconns) != 0)
    {
      pthread_mutex_unlock (&pool->mutex);
      RAISE_POOL_ERROR (SocketPool_Failed);
    }

  /* Rehash only valid slots: min of old and new size.
   * When growing, new slots are uninitialized until initialize_new_slots.
   * When shrinking, array was truncated to new_maxconns. */
  rehash_active_connections (pool,
                             old_maxconns < new_maxconns ? old_maxconns
                                                         : new_maxconns);

  if (new_maxconns > old_maxconns)
    initialize_new_slots (pool, old_maxconns, new_maxconns);
  else
    relink_free_slots (pool, new_maxconns);

  pool->maxconns = new_maxconns;
  pthread_mutex_unlock (&pool->mutex);
}

/* ============================================================================
 * Pool Tuning Operations
 * ============================================================================ */

/**
 * SocketPool_prewarm - Pre-allocate buffers for percentage of free slots
 * @pool: Pool instance
 * @percentage: Percentage of free slots to pre-warm (0-100)
 *
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

  prewarm_count = (pool->maxconns * (size_t)percentage) / PERCENTAGE_DIVISOR;

  conn = pool->free_list;
  while (conn && allocated < prewarm_count)
    {
      if (!conn->inbuf && !conn->outbuf)
        {
          if (SocketPool_connections_alloc_buffers (pool->arena, pool->bufsize,
                                                    conn)
              == 0)
            allocated++;
        }
      conn = conn->free_next;
    }

  pthread_mutex_unlock (&pool->mutex);
}

/**
 * SocketPool_set_bufsize - Set buffer size for future connections
 * @pool: Pool instance
 * @new_bufsize: New buffer size in bytes
 *
 * Thread-safe: Yes - uses internal mutex
 */
void
SocketPool_set_bufsize (T pool, size_t new_bufsize)
{
  assert (pool);

  new_bufsize = socketpool_enforce_buffer_size (new_bufsize);

  pthread_mutex_lock (&pool->mutex);
  pool->bufsize = new_bufsize;
  pthread_mutex_unlock (&pool->mutex);
}

/**
 * SocketPool_count - Get active connection count
 * @pool: Pool instance
 *
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
 *
 * Calls func for each active connection.
 * Thread-safe: Yes - holds mutex during iteration
 * Performance: O(n) where n is maxconns
 * Warning: Callback must not modify pool structure
 */
void
SocketPool_foreach (T pool, void (*func) (Connection_T, void *), void *arg)
{
  assert (pool);
  assert (func);

  pthread_mutex_lock (&pool->mutex);

  for (size_t i = 0; i < pool->maxconns; i++)
    {
      if (pool->connections[i].active)
        func (&pool->connections[i], arg);
    }

  pthread_mutex_unlock (&pool->mutex);
}

/* ============================================================================
 * Batch Accept Operations
 * ============================================================================ */

/**
 * accept_connection_direct - Accept connection directly using accept4/accept
 * @server_fd: Server socket file descriptor
 *
 * Returns: New file descriptor or -1 on error/would block
 * Thread-safe: Yes - pure system call
 * Note: Uses accept4() with SOCK_CLOEXEC | SOCK_NONBLOCK on Linux,
 * falls back to accept() + fcntl() on other platforms.
 */
static int
accept_connection_direct (int server_fd)
{
  int newfd;

#if SOCKET_HAS_ACCEPT4 && defined(SOCK_NONBLOCK)
  newfd = accept4 (server_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
#elif SOCKET_HAS_ACCEPT4
  newfd = accept4 (server_fd, NULL, NULL, SOCK_CLOEXEC);
#else
  newfd = accept (server_fd, NULL, NULL);
#endif

  if (newfd < 0)
    return -1;

#if !SOCKET_HAS_ACCEPT4 || !defined(SOCK_NONBLOCK)
  if (SocketCommon_setcloexec (newfd, 1) < 0)
    {
      SAFE_CLOSE (newfd);
      return -1;
    }

  int flags = fcntl (newfd, F_GETFL, 0);
  if (flags >= 0)
    {
      fcntl (newfd, F_SETFL, flags | O_NONBLOCK);
    }
#endif

  return newfd;
}

/**
 * SocketPool_accept_batch - Accept multiple connections from server socket
 * @pool: Pool instance
 * @server: Server socket to accept from (must be listening and non-blocking)
 * @max_accepts: Maximum number of connections to accept
 *               (1-SOCKET_POOL_MAX_BATCH_ACCEPTS)
 * @accepted: Output array of accepted sockets (must be pre-allocated,
 *            size >= max_accepts)
 *
 * Returns: Number of connections actually accepted (0 to max_accepts)
 * Raises: SocketPool_Failed on error
 * Thread-safe: Yes - uses internal mutex
 *
 * Accepts up to max_accepts connections from server socket in a single call.
 * Uses accept4() on Linux (SOCK_CLOEXEC | SOCK_NONBLOCK) for efficiency.
 * Falls back to accept() + fcntl() on other platforms.
 * All accepted sockets are automatically added to the pool.
 *
 * Performance: O(n) where n is number accepted, but much faster than
 * individual SocketPool_add() calls due to reduced mutex contention.
 */
int
SocketPool_accept_batch (T pool, Socket_T server, int max_accepts,
                         Socket_T *accepted)
{
  int count = 0;
  int server_fd;
  int available;
  volatile int local_max_accepts = max_accepts;

  if (!pool || !server || !accepted)
    return 0;

  if (max_accepts <= 0 || max_accepts > SOCKET_POOL_MAX_BATCH_ACCEPTS)
    {
      SOCKET_ERROR_MSG ("Invalid max_accepts %d (must be 1-%d)", max_accepts,
                        SOCKET_POOL_MAX_BATCH_ACCEPTS);
      return 0;
    }

  server_fd = Socket_fd (server);

  /* Check available pool slots */
  pthread_mutex_lock (&pool->mutex);
  available = (int)(pool->maxconns - pool->count);
  pthread_mutex_unlock (&pool->mutex);

  if (available <= 0)
    return 0;

  if (local_max_accepts > available)
    local_max_accepts = available;

  /* Accept loop - minimize lock time */
  for (int i = 0; i < local_max_accepts; i++)
    {
      int newfd = accept_connection_direct (server_fd);
      if (newfd < 0)
        {
          if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
              SOCKET_ERROR_MSG (
                  "accept() failed during batch (accepted %d so far)", count);
            }
          break;
        }

      Socket_T sock = NULL;
      TRY { sock = Socket_new_from_fd (newfd); }
      EXCEPT (Socket_Failed)
      {
        SAFE_CLOSE (newfd);
        break;
      }
      END_TRY;

      /* sock is valid here - Socket_new_from_fd raises on failure */
      Connection_T conn = SocketPool_add (pool, sock);
      if (conn)
        {
          accepted[count++] = sock;
        }
      else
        {
          Socket_free (&sock);
          break;
        }
    }

  return count;
}

/* ============================================================================
 * Async Connection Preparation
 * ============================================================================ */

/**
 * validate_prepare_params - Validate parameters for prepare_connection
 * @pool: Pool instance
 * @dns: DNS resolver
 * @host: Target hostname
 * @port: Target port
 * @out_socket: Output socket pointer
 * @out_req: Output request pointer
 *
 * Raises: SocketPool_Failed on invalid parameters
 */
static void
validate_prepare_params (T pool, SocketDNS_T dns, const char *host, int port,
                         Socket_T *out_socket, SocketDNS_Request_T *out_req)
{
  if (!pool || !dns || !host || !SOCKET_VALID_PORT (port) || !out_socket
      || !out_req)
    {
      SOCKET_ERROR_MSG ("Invalid parameters for prepare_connection");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
}

/**
 * create_pool_socket - Create and configure socket for pool use
 *
 * Returns: Configured socket
 * Raises: SocketPool_Failed on error
 */
static Socket_T
create_pool_socket (void)
{
  Socket_T socket = Socket_new (AF_UNSPEC, SOCK_STREAM, 0);
  if (!socket)
    {
      SOCKET_ERROR_MSG ("Failed to create socket for pool");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }

  Socket_setnonblocking (socket);
  Socket_setreuseaddr (socket);

  return socket;
}

/**
 * apply_pool_timeouts - Apply default timeouts to socket
 * @socket: Socket to configure
 */
static void
apply_pool_timeouts (Socket_T socket)
{
  SocketTimeouts_T timeouts;
  Socket_timeouts_getdefaults (&timeouts);
  Socket_timeouts_set (socket, &timeouts);
}

/**
 * start_async_connect - Start async DNS resolution and connect
 * @dns: DNS resolver
 * @socket: Socket to connect
 * @host: Target hostname
 * @port: Target port
 *
 * Returns: DNS request handle
 * Raises: SocketPool_Failed on error
 */
static SocketDNS_Request_T
start_async_connect (SocketDNS_T dns, Socket_T socket, const char *host,
                     int port)
{
  SocketDNS_Request_T req = Socket_connect_async (dns, socket, host, port);
  if (!req)
    {
      SOCKET_ERROR_MSG ("Failed to start async connect");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  return req;
}

/**
 * SocketPool_prepare_connection - Prepare async connection using DNS
 * @pool: Pool instance (used for configuration)
 * @dns: DNS resolver instance
 * @host: Remote hostname or IP
 * @port: Remote port (1-65535)
 * @out_socket: Output - new Socket_T instance
 * @out_req: Output - SocketDNS_Request_T for monitoring
 *
 * Returns: 0 on success, -1 on error
 * Raises: SocketPool_Failed on error
 * Thread-safe: Yes
 *
 * Creates a new Socket_T, configures with pool defaults, starts async DNS.
 * User must monitor out_req, then call Socket_connect_with_addrinfo() and
 * SocketPool_add() on completion.
 */
int
SocketPool_prepare_connection (T pool, SocketDNS_T dns, const char *host,
                               int port, Socket_T *out_socket,
                               SocketDNS_Request_T *out_req)
{
  Socket_T socket = NULL;

  validate_prepare_params (pool, dns, host, port, out_socket, out_req);

  TRY
  {
    socket = create_pool_socket ();
    apply_pool_timeouts (socket);
    *out_req = start_async_connect (dns, socket, host, port);
    *out_socket = socket;
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

