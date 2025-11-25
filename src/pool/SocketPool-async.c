/**
 * SocketPool-async.c - Async connection preparation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Provides async DNS resolution and connection preparation for the pool.
 */

#include <assert.h>
#include <errno.h>

#include "dns/SocketDNS.h"
#include "pool/SocketPool-private.h"

#define T SocketPool_T

/* SocketPool_Failed declared in SocketPool.h (included via private header) */

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

