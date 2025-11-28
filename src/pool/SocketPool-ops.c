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
#include <time.h>
#include <unistd.h>

#include "dns/SocketDNS.h"
#include "pool/SocketPool-private.h"
#include "socket/SocketCommon.h"

#define T SocketPool_T

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
 *
 * Security: Checks for integer overflow before size calculation to prevent
 * heap buffer overflow from undersized allocation.
 */
static int
realloc_connections_array (T pool, size_t new_maxconns)
{
  struct Connection *new_connections;
  size_t alloc_size;

  /* Security: Check for integer overflow before multiplication */
  if (new_maxconns > SIZE_MAX / sizeof (struct Connection))
    {
      SOCKET_ERROR_MSG ("Overflow in connections array size calculation");
      return -1;
    }

  alloc_size = new_maxconns * sizeof (struct Connection);
  new_connections = realloc (pool->connections, alloc_size);
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
 * close_single_excess_socket - Close and remove single excess socket
 * @pool: Pool instance
 * @socket: Socket to close
 *
 * Thread-safe: Called outside lock
 * Handles errors gracefully - logs and continues on failure.
 */
static void
close_single_excess_socket (T pool, Socket_T *socket)
{
  TRY
  {
    SocketPool_remove (pool, *socket);
    Socket_free (socket);
  }
  ELSE
  {
    /* Ignore SocketPool_Failed or Socket_Failed during resize cleanup -
     * socket may already be removed or closed */
    SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                     "Resize: socket close/remove failed (may be stale)");
  }
  END_TRY;
}

/**
 * close_excess_sockets - Close and remove excess sockets
 * @pool: Pool instance
 * @excess_sockets: Array of sockets to close
 * @excess_count: Number of sockets
 *
 * Thread-safe: Called outside lock
 * Handles errors gracefully - logs and continues on failure.
 */
static void
close_excess_sockets (T pool, Socket_T *excess_sockets, size_t excess_count)
{
  /* volatile prevents clobbering when close_single_excess_socket is inlined */
  volatile size_t i;
  for (i = 0; i < excess_count; i++)
    {
      if (excess_sockets[i])
        close_single_excess_socket (pool, &excess_sockets[i]);
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

  size_t collected
      = collect_excess_connections (pool, new_maxconns, excess_sockets);
  assert (collected == excess_count);
  (void)collected; /* Suppress warning when NDEBUG disables assert */

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
  size_t allocated = 0;

  assert (pool);
  assert (percentage >= 0 && percentage <= 100);

  pthread_mutex_lock (&pool->mutex);

  prewarm_count
      = (pool->maxconns * (size_t)percentage) / SOCKET_PERCENTAGE_DIVISOR;

  /* Safer: iterate by index over the authoritative connections array
   * to avoid following possibly-stale pointers in free_list.
   * This prevents heap-use-after-free if the array is reallocated elsewhere. */
  for (size_t i = 0; i < pool->maxconns && allocated < prewarm_count; i++)
    {
      struct Connection *c = &pool->connections[i];
      /* Only prewarm truly free slots (inactive and no buffers allocated) */
      if (!c->active && !c->inbuf && !c->outbuf)
        {
          if (SocketPool_connections_alloc_buffers (pool->arena, pool->bufsize,
                                                    c)
              == 0)
            allocated++;
        }
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
 * validate_batch_params - Validate batch accept parameters
 * @pool: Pool instance
 * @server: Server socket
 * @max_accepts: Maximum to accept
 * @accepted: Output array
 *
 * Returns: 1 if valid, 0 if invalid
 */
static int
validate_batch_params (T pool, Socket_T server, int max_accepts,
                       Socket_T *accepted)
{
  if (!pool || !server || !accepted)
    return 0;

  if (max_accepts <= 0 || max_accepts > SOCKET_POOL_MAX_BATCH_ACCEPTS)
    {
      SOCKET_ERROR_MSG ("Invalid max_accepts %d (must be 1-%d)", max_accepts,
                        SOCKET_POOL_MAX_BATCH_ACCEPTS);
      return 0;
    }
  return 1;
}

/**
 * get_available_slots - Get available pool slots
 * @pool: Pool instance
 *
 * Returns: Number of available slots (>= 0)
 * Thread-safe: Yes - uses internal mutex
 */
static int
get_available_slots (T pool)
{
  int available;
  pthread_mutex_lock (&pool->mutex);
  available = (int)(pool->maxconns - pool->count);
  pthread_mutex_unlock (&pool->mutex);
  return available > 0 ? available : 0;
}

/**
 * wrap_fd_as_socket - Create Socket_T from file descriptor
 * @newfd: File descriptor to wrap
 *
 * Returns: Socket_T on success, NULL on failure (fd closed on error)
 */
static Socket_T
wrap_fd_as_socket (int newfd)
{
  volatile Socket_T sock = NULL;
  TRY { sock = Socket_new_from_fd (newfd); }
  EXCEPT (Socket_Failed)
  {
    SAFE_CLOSE (newfd);
    return NULL;
  }
  END_TRY;
  return sock;
}

/**
 * try_add_socket_to_pool - Add socket to pool
 * @pool: Pool instance
 * @sock: Socket to add
 *
 * Returns: 1 on success, 0 on failure (socket freed on error)
 */
static int
try_add_socket_to_pool (T pool, Socket_T *sock)
{
  const Connection_T conn = SocketPool_add (pool, *sock);
  if (!conn)
    {
      Socket_free (sock);
      return 0;
    }
  return 1;
}

/**
 * accept_one_connection - Accept and add one connection
 * @pool: Pool instance
 * @server_fd: Server file descriptor
 * @accepted: Output socket pointer
 * @count: Current accepted count (for error messages)
 *
 * Returns: 1 on success, 0 on would-block, -1 on error
 */
static int
accept_one_connection (T pool, int server_fd, Socket_T *accepted, int count)
{
  int newfd = accept_connection_direct (server_fd);
  if (newfd < 0)
    {
      if (errno != EAGAIN && errno != EWOULDBLOCK)
        SOCKET_ERROR_MSG ("accept() failed (accepted %d so far)", count);
      return 0;
    }

  Socket_T sock = wrap_fd_as_socket (newfd);
  if (!sock)
    return -1;

  if (!try_add_socket_to_pool (pool, &sock))
    return -1;

  *accepted = sock;
  return 1;
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
 */
int
SocketPool_accept_batch (T pool, Socket_T server, int max_accepts,
                         Socket_T *accepted)
{
  int count = 0;
  int limit;

  if (!validate_batch_params (pool, server, max_accepts, accepted))
    return 0;

  limit = get_available_slots (pool);
  if (limit <= 0)
    return 0;

  if (max_accepts < limit)
    limit = max_accepts;

  int server_fd = Socket_fd (server);
  for (int i = 0; i < limit; i++)
    {
      int result = accept_one_connection (pool, server_fd, &accepted[count],
                                          count);
      if (result <= 0)
        break;
      count++;
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
 *
 * Note: Uses AF_INET by default. For IPv6-only connections, the socket
 * family will be updated during Socket_connect_with_addrinfo if the
 * resolved address is IPv6 and the connection attempt requires it.
 */
static Socket_T
create_pool_socket (void)
{
  Socket_T socket = Socket_new (AF_INET, SOCK_STREAM, 0);
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

/* ============================================================================
 * Async Connect with Callback
 * ============================================================================ */

/* AsyncConnectContext structure is defined in SocketPool-private.h */

/**
 * alloc_async_context - Allocate async connect context
 * @pool: Pool instance
 *
 * Returns: New context or NULL on failure
 */
static AsyncConnectContext_T
alloc_async_context (T pool)
{
  return ALLOC (pool->arena, sizeof (struct AsyncConnectContext));
}

/**
 * check_async_limit - Check if async pending limit reached
 * @pool: Pool instance
 *
 * Returns: 1 if under limit, 0 if limit reached
 * Thread-safe: Call with mutex held
 *
 * Security: Prevents resource exhaustion from excessive concurrent
 * async connect operations.
 */
static int
check_async_limit (const T pool)
{
  return pool->async_pending_count < SOCKET_POOL_MAX_ASYNC_PENDING;
}

/**
 * add_async_context - Add context to pool's list
 * @pool: Pool instance
 * @ctx: Context to add
 *
 * Returns: 1 on success, 0 if limit reached
 * Thread-safe: Call with mutex held
 *
 * Security: Enforces SOCKET_POOL_MAX_ASYNC_PENDING limit to prevent
 * resource exhaustion attacks via excessive concurrent connections.
 */
static int
add_async_context (T pool, AsyncConnectContext_T ctx)
{
  if (!check_async_limit (pool))
    return 0;

  ctx->next = pool->async_ctx;
  pool->async_ctx = ctx;
  pool->async_pending_count++;
  return 1;
}

/**
 * remove_async_context - Remove context from pool's list
 * @pool: Pool instance
 * @ctx: Context to remove
 *
 * Thread-safe: Call with mutex held
 */
static void
remove_async_context (T pool, AsyncConnectContext_T ctx)
{
  AsyncConnectContext_T *pp = &pool->async_ctx;
  while (*pp)
    {
      if (*pp == ctx)
        {
          *pp = ctx->next;
          pool->async_pending_count--;
          return;
        }
      pp = &(*pp)->next;
    }
}

/**
 * get_or_create_dns - Get or lazily create pool's DNS resolver
 * @pool: Pool instance
 *
 * Returns: DNS resolver
 * Raises: SocketPool_Failed on error
 * Thread-safe: Call with mutex held
 */
static SocketDNS_T
get_or_create_dns (T pool)
{
  if (!pool->dns)
    {
      TRY { pool->dns = SocketDNS_new (); }
      EXCEPT (SocketDNS_Failed)
      {
        SOCKET_ERROR_MSG ("Failed to create DNS resolver for pool");
        RAISE_POOL_ERROR (SocketPool_Failed);
      }
      END_TRY;
    }
  return pool->dns;
}

/**
 * async_connect_dns_callback - Callback for DNS completion
 * @req: DNS request handle (unused)
 * @result: Resolved address or NULL on error
 * @error: Error code (0 on success)
 * @data: AsyncConnectContext
 */
static void
async_connect_dns_callback (SocketDNS_Request_T req, struct addrinfo *result,
                            int error, void *data)
{
  AsyncConnectContext_T ctx = data;
  T pool = ctx->pool;
  volatile Connection_T conn = NULL;
  volatile int callback_error = error;

  (void)req; /* Unused parameter */

  if (error != 0 || result == NULL)
    {
      /* DNS resolution failed - free the socket that was allocated */
      if (ctx->socket)
        Socket_free (&ctx->socket);
      callback_error = error ? error : EAI_FAIL;
      goto invoke_callback;
    }

  /* Try to connect and add to pool */
  TRY
  {
    Socket_connect_with_addrinfo (ctx->socket, result);
    conn = SocketPool_add (pool, ctx->socket);
    if (!conn)
      {
        callback_error = ENOSPC; /* Pool full */
        Socket_free (&ctx->socket);
      }
  }
  EXCEPT (Socket_Failed)
  {
    callback_error = Socket_geterrno () ? Socket_geterrno () : ECONNREFUSED;
    Socket_free (&ctx->socket);
  }
  END_TRY;

  SocketCommon_free_addrinfo (result);

invoke_callback:
  /* Remove context from list */
  pthread_mutex_lock (&pool->mutex);
  remove_async_context (pool, ctx);
  pthread_mutex_unlock (&pool->mutex);

  /* Invoke user callback */
  if (ctx->cb)
    ctx->cb (conn, callback_error, ctx->user_data);
}

/**
 * validate_connect_async_params - Validate connect_async parameters
 * @pool: Pool instance
 * @host: Target hostname
 * @port: Target port
 * @callback: User callback
 *
 * Raises: SocketPool_Failed on invalid parameters
 */
static void
validate_connect_async_params (T pool, const char *host, int port,
                               SocketPool_ConnectCallback callback)
{
  if (!pool || !host || !SOCKET_VALID_PORT (port))
    {
      SOCKET_ERROR_MSG ("Invalid parameters for connect_async");
      RAISE_POOL_ERROR (SocketPool_Failed);
    }
  (void)callback; /* Callback may be NULL for poll-mode */
}

/**
 * SocketPool_connect_async - Create async connection to remote host
 * @pool: Pool instance
 * @host: Remote hostname or IP address
 * @port: Remote port number
 * @callback: Completion callback
 * @data: User data passed to callback
 *
 * Returns: SocketDNS_Request_T for monitoring completion
 * Raises: SocketPool_Failed on invalid params or allocation error
 * Thread-safe: Yes
 *
 * Starts async DNS resolution + connect + pool add. On completion:
 * - Success: callback(conn, 0, data) with Connection_T added to pool
 * - Failure: callback(NULL, error_code, data)
 */
SocketDNS_Request_T
SocketPool_connect_async (T pool, const char *host, int port,
                          SocketPool_ConnectCallback callback, void *data)
{
  SocketDNS_T dns;
  volatile Socket_T socket = NULL;
  AsyncConnectContext_T ctx = NULL;
  volatile SocketDNS_Request_T req = NULL;

  validate_connect_async_params (pool, host, port, callback);

  pthread_mutex_lock (&pool->mutex);

  TRY
  {
    dns = get_or_create_dns (pool);
    ctx = alloc_async_context (pool);
    if (!ctx)
      {
        SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate async context");
        RAISE_POOL_ERROR (SocketPool_Failed);
      }

    socket = create_pool_socket ();
    apply_pool_timeouts (socket);

    /* Initialize context BEFORE DNS resolve - callback may fire immediately
     * for IP addresses that don't need actual DNS lookup (e.g. "127.0.0.1") */
    ctx->pool = pool;
    ctx->socket = socket;
    ctx->cb = callback;
    ctx->user_data = data;
    ctx->next = NULL;

    /* Security: Check async pending limit before starting DNS */
    if (!add_async_context (pool, ctx))
      {
        SOCKET_ERROR_MSG ("Async connect limit reached (%d pending)",
                          SOCKET_POOL_MAX_ASYNC_PENDING);
        RAISE_POOL_ERROR (SocketPool_Failed);
      }

    req = SocketDNS_resolve (dns, host, port, async_connect_dns_callback, ctx);
    if (!req)
      {
        /* Remove context from list since DNS resolve failed */
        remove_async_context (pool, ctx);
        SOCKET_ERROR_MSG ("Failed to start DNS resolution");
        RAISE_POOL_ERROR (SocketPool_Failed);
      }

    /* Store request handle after successful DNS resolve */
    ctx->req = req;
  }
  ELSE
  {
    /* Cleanup on any exception (Socket_Failed or SocketPool_Failed) */
    if (ctx && ctx->socket)
      {
        /* Context was added to list - remove it first */
        remove_async_context (pool, ctx);
        ctx->socket = NULL;
      }
    if (socket)
      Socket_free ((Socket_T *)&socket);
    pthread_mutex_unlock (&pool->mutex);
    RERAISE;
  }
  END_TRY;

  pthread_mutex_unlock (&pool->mutex);
  return req;
}

/* ============================================================================
 * SYN Flood Protection
 * ============================================================================ */

/**
 * SocketPool_set_syn_protection - Enable SYN flood protection for pool
 * @pool: Pool instance
 * @protect: SYN protection instance (NULL to disable)
 *
 * Thread-safe: Yes
 */
void
SocketPool_set_syn_protection (T pool, SocketSYNProtect_T protect)
{
  assert (pool);

  pthread_mutex_lock (&pool->mutex);
  pool->syn_protect = protect;
  pthread_mutex_unlock (&pool->mutex);
}

/**
 * SocketPool_get_syn_protection - Get current SYN protection module
 * @pool: Pool instance
 *
 * Returns: Current SYN protection instance, or NULL if disabled
 * Thread-safe: Yes
 */
SocketSYNProtect_T
SocketPool_get_syn_protection (T pool)
{
  SocketSYNProtect_T protect;

  assert (pool);

  pthread_mutex_lock (&pool->mutex);
  protect = pool->syn_protect;
  pthread_mutex_unlock (&pool->mutex);

  return protect;
}

/**
 * apply_syn_throttle - Apply throttle delay if needed
 * @action: SYN protection action
 * @protect: Protection instance (for config)
 *
 * Blocks briefly for throttled connections to slow down attack rate.
 */
static void
apply_syn_throttle (SocketSYN_Action action, SocketSYNProtect_T protect)
{
  if (action != SYN_ACTION_THROTTLE || protect == NULL)
    return;

  /* Get config for throttle delay - use default if not accessible */
  int delay_ms = SOCKET_SYN_DEFAULT_THROTTLE_DELAY_MS;

  if (delay_ms > 0)
    {
      struct timespec ts;
      ts.tv_sec = delay_ms / 1000;
      ts.tv_nsec = (delay_ms % 1000) * 1000000L;
      nanosleep (&ts, NULL);
    }
}

/**
 * apply_syn_challenge - Apply TCP_DEFER_ACCEPT for challenged connections
 * @socket: Accepted socket
 * @action: SYN protection action
 * @protect: Protection instance (for config)
 */
static void
apply_syn_challenge (Socket_T socket, SocketSYN_Action action,
                     SocketSYNProtect_T protect)
{
  if (action != SYN_ACTION_CHALLENGE || protect == NULL || socket == NULL)
    return;

  /* Note: TCP_DEFER_ACCEPT is typically set on listening socket, but
   * for per-connection challenge we apply it to accepted socket to
   * ensure data is received before proceeding. This is less effective
   * than listener-level defer but still adds a challenge. */
  TRY { Socket_setdeferaccept (socket, SOCKET_SYN_DEFAULT_DEFER_SEC); }
  ELSE
  {
    /* Ignore failures - best effort protection */
    SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                     "SYN challenge: TCP_DEFER_ACCEPT failed (continuing)");
  }
  END_TRY;
}

/**
 * SocketPool_accept_protected - Accept with full SYN flood protection
 * @pool: Pool instance
 * @server: Server socket (listening, non-blocking)
 * @action_out: Output - action taken (optional, may be NULL)
 *
 * Returns: New socket if allowed, NULL if blocked/would block
 * Raises: SocketPool_Failed on actual errors
 * Thread-safe: Yes
 */
Socket_T
SocketPool_accept_protected (T pool, Socket_T server,
                             SocketSYN_Action *action_out)
{
  Socket_T client = NULL;
  SocketSYNProtect_T protect;
  SocketSYN_Action action = SYN_ACTION_ALLOW;
  const char *client_ip = NULL;

  assert (pool);
  assert (server);

  /* Get current protection instance */
  pthread_mutex_lock (&pool->mutex);
  protect = pool->syn_protect;
  pthread_mutex_unlock (&pool->mutex);

  /* If no SYN protection, fall back to rate-limited accept */
  if (protect == NULL)
    {
      if (action_out)
        *action_out = SYN_ACTION_ALLOW;
      return SocketPool_accept_limited (pool, server);
    }

  /* Accept the connection first to get client IP */
  TRY { client = Socket_accept (server); }
  EXCEPT (Socket_Failed)
  {
    /* Actual error - propagate */
    RERAISE;
  }
  END_TRY;

  if (client == NULL)
    {
      /* Would block - not an error */
      if (action_out)
        *action_out = SYN_ACTION_ALLOW;
      return NULL;
    }

  /* Get client IP for SYN protection check */
  client_ip = Socket_getpeeraddr (client);

  /* Check with SYN protection module */
  action = SocketSYNProtect_check (protect, client_ip, NULL);

  if (action_out)
    *action_out = action;

  /* Handle action */
  switch (action)
    {
    case SYN_ACTION_ALLOW:
      /* Normal accept - check rate limits still */
      if (!SocketPool_accept_allowed (pool, client_ip))
        {
          SocketSYNProtect_report_failure (protect, client_ip, ECONNREFUSED);
          Socket_free (&client);
          return NULL;
        }
      /* Track IP for per-IP limiting */
      SocketPool_track_ip (pool, client_ip);
      SocketSYNProtect_report_success (protect, client_ip);
      break;

    case SYN_ACTION_THROTTLE:
      /* Apply throttle delay, then allow */
      apply_syn_throttle (action, protect);
      if (!SocketPool_accept_allowed (pool, client_ip))
        {
          SocketSYNProtect_report_failure (protect, client_ip, ECONNREFUSED);
          Socket_free (&client);
          return NULL;
        }
      SocketPool_track_ip (pool, client_ip);
      SocketSYNProtect_report_success (protect, client_ip);
      break;

    case SYN_ACTION_CHALLENGE:
      /* Apply TCP_DEFER_ACCEPT challenge */
      apply_syn_challenge (client, action, protect);
      if (!SocketPool_accept_allowed (pool, client_ip))
        {
          SocketSYNProtect_report_failure (protect, client_ip, ECONNREFUSED);
          Socket_free (&client);
          return NULL;
        }
      SocketPool_track_ip (pool, client_ip);
      /* Report success only after challenge - caller should verify data received */
      break;

    case SYN_ACTION_BLOCK:
      /* Reject connection immediately */
      SocketSYNProtect_report_failure (protect, client_ip, ECONNREFUSED);
      Socket_free (&client);
      return NULL;
    }

  return client;
}

#undef T

