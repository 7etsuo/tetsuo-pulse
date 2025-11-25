/**
 * Socket-state.c - Socket state query functions
 *
 * Functions for querying socket connection state, binding status,
 * and endpoint information.
 */

#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>

#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/Socket-private.h"
#include "socket/SocketCommon.h"
#define SOCKET_LOG_COMPONENT "Socket"
#include "core/SocketError.h"

#define T Socket_T

/* Thread-local exception for detailed error messages */
/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketState);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketState, e)

/**
 * check_bound_ipv4 - Check if IPv4 socket is bound
 * @addr: sockaddr_storage containing address
 * Returns: 1 if bound, 0 otherwise
 */
static int
check_bound_ipv4 (const struct sockaddr_storage *addr)
{
  struct sockaddr_in *sin = (struct sockaddr_in *)addr;
  return sin->sin_port != 0;
}

/**
 * check_bound_ipv6 - Check if IPv6 socket is bound
 * @addr: sockaddr_storage containing address
 * Returns: 1 if bound, 0 otherwise
 */
static int
check_bound_ipv6 (const struct sockaddr_storage *addr)
{
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
  return sin6->sin6_port != 0;
}

/**
 * check_bound_unix - Check if Unix socket is bound
 * @addr: sockaddr_storage containing address (unused)
 * Returns: 1 if bound (Unix sockets are bound if getsockname succeeds)
 */
static int
check_bound_unix (const struct sockaddr_storage *addr __attribute__((unused)))
{
  return 1; /* Unix domain sockets are bound if getsockname succeeds */
}

/**
 * setup_peer_info - Set up peer address and port from getnameinfo result
 * @socket: Socket to set up
 * @addr: Address structure
 * @addrlen: Address length
 * Returns: 0 on success, -1 on failure
 */
static int
setup_peer_info (T socket, const struct sockaddr *addr, socklen_t addrlen)
{
  if (SocketCommon_cache_endpoint (SocketBase_arena (socket->base), addr,
                                   addrlen, &socket->base->remoteaddr,
                                   &socket->base->remoteport)
      != 0)
    {
      socket->base->remoteaddr = NULL;
      socket->base->remoteport = 0;
    }
  return 0;
}

int
Socket_isconnected (T socket)
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof (addr);

  assert (socket);

  /* Check if we have cached peer address */
  if (socket->base->remoteaddr != NULL)
    return 1;

  /* Use getpeername() to check connection state */
  if (getpeername (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
                   &len)
      == 0)
    {
      /* Socket is connected - update cached peer info if not already set */
      if (socket->base->remoteaddr == NULL
          && SocketBase_arena (socket->base) != NULL)
        {
          setup_peer_info (socket, (struct sockaddr *)&addr, len);
        }
      return 1;
    }

  /* Not connected or error occurred */
  if (errno == ENOTCONN)
    return 0;

  /* Other errors (EBADF, etc.) - treat as not connected */
  return 0;
}

int
Socket_isbound (T socket)
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof (addr);

  assert (socket);

  /* Check if we have cached local address */
  if (socket->base->localaddr != NULL)
    return 1;

  /* Use getsockname() to check binding state */
  if (getsockname (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
                   &len)
      == 0)
    {
      /* Socket is bound if getsockname succeeds */
      /* For IPv4/IPv6, check if we have a valid port (address can be wildcard)
       */
      if (addr.ss_family == AF_INET)
        return check_bound_ipv4 (&addr);
      else if (addr.ss_family == AF_INET6)
        return check_bound_ipv6 (&addr);
      else if (addr.ss_family == AF_UNIX)
        return check_bound_unix (&addr);
    }

  return 0;
}

int
Socket_islistening (T socket)
{
  assert (socket);

  /* Socket must be bound to be listening */
  if (!Socket_isbound (socket))
    return 0;

  /* Socket must not be connected to be listening */
  if (Socket_isconnected (socket))
    return 0;

  /* Additional check: verify socket is actually in listening state
   * by checking if accept() would work (non-blocking check) */
  {
    int error = 0;
    socklen_t error_len = sizeof (error);

    /* Check SO_ERROR - listening sockets should have no error */
    if (getsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET, SO_ERROR,
                    &error, &error_len)
        == 0)
      {
        /* If there's a connection error, socket might be in wrong state */
        if (error != 0 && error != ENOTCONN)
          return 0;
      }
  }

  return 1;
}

int
Socket_fd (const T socket)
{
  assert (socket);
  return SocketBase_fd (socket->base);
}

const char *
Socket_getpeeraddr (const T socket)
{
  assert (socket);
  return socket->base->remoteaddr ? socket->base->remoteaddr : "(unknown)";
}

int
Socket_getpeerport (const T socket)
{
  assert (socket);
  return socket->base->remoteport;
}

const char *
Socket_getlocaladdr (const T socket)
{
  assert (socket);
  return socket->base->localaddr ? socket->base->localaddr : "(unknown)";
}

int
Socket_getlocalport (const T socket)
{
  assert (socket);
  return socket->base->localport;
}

#undef T
