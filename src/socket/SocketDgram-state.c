/**
 * SocketDgram-state.c - UDP/datagram socket state queries
 *
 * Implements socket state query functions for UDP sockets including connection
 * status, binding status, and accessor functions for file descriptor, addresses,
 * ports, timeouts, broadcast settings, and other socket state information.
 *
 * Features:
 * - Connection state queries (isconnected)
 * - Binding state queries (isbound)
 * - Socket accessor functions (fd, localaddr, localport)
 * - Timeout query functions (gettimeout)
 * - Broadcast setting queries (getbroadcast)
 * - Thread-safe state access
 * - Cached endpoint information
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig-limits.h"
#include "core/SocketConfig.h"
#include "socket/SocketDgram.h"
#include "socket/SocketDgram-private.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#define SOCKET_LOG_COMPONENT "SocketDgram"
#include "core/SocketError.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"
#define T SocketDgram_T
/* Port string buffer size for snprintf */
/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec (thread) Except_T SocketDgram_DetailedException;
#else
static __thread Except_T SocketDgram_DetailedException;
#endif

/** Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e)                                                 \
  do                                                                          \
    {                                                                         \
      SocketDgram_DetailedException = (e);                                    \
      SocketDgram_DetailedException.reason = socket_error_buf;               \
      RAISE (SocketDgram_DetailedException);                                  \
    }                                                                         \
  while (0)

int
SocketDgram_fd (const T socket)
{
  assert (socket);
  return SocketBase_fd (socket->base);
}

const char *
SocketDgram_getlocaladdr (const T socket)
{
  assert (socket);
  return socket->base->localaddr ? socket->base->localaddr : "(unknown)";
}

int
SocketDgram_getlocalport (const T socket)
{
  assert (socket);
  return socket->base->localport;
}

/**
 * SocketDgram_gettimeout - Get socket timeout
 * @socket: Socket to query
 * Returns: Timeout in seconds (0 if disabled)
 * Raises: SocketDgram_Failed on error
 * Note: Returns receive timeout (send timeout may differ)
 */

int
SocketDgram_gettimeout (T socket)
{
  struct timeval tv;
  assert (socket);
  if (SocketCommon_getoption_timeval (SocketBase_fd (socket->base),
                                      SOCKET_SOL_SOCKET, SOCKET_SO_RCVTIMEO,
                                      &tv, SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);
  return (int)tv.tv_sec;
}

/**
 * SocketDgram_getbroadcast - Get broadcast setting
 * @socket: Socket to query
 * Returns: 1 if broadcast is enabled, 0 if disabled
 * Raises: SocketDgram_Failed on error
 * Note: On macOS, getsockopt() may return 0 even after successfully setting
 * SO_BROADCAST to 1. This is a known macOS quirk - the option is set
 * correctly, but getsockopt() doesn't always reflect the set value.
 */

int
SocketDgram_getbroadcast (T socket)
{
  int broadcast = 0;
  assert (socket);
  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_SOL_SOCKET, SOCKET_SO_BROADCAST,
                                  &broadcast, SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);
  return broadcast;
}

/**
 * SocketDgram_isconnected - Check if datagram socket is connected
 * @socket: Socket to check
 * Returns: 1 if connected, 0 if not connected
 * Thread-safe: Yes (operates on single socket)
 * Note: Uses getpeername() to determine connection state.
 * For UDP sockets, "connected" means a default destination is set.
 */

int
SocketDgram_isconnected (T socket)
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof (addr);
  assert (socket);
  /* Use getpeername() to check connection state */
  if (getpeername (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
                   &len)
      == 0)
    return 1;
  /* Not connected or error occurred */
  if (errno == ENOTCONN)
    return 0;
  /* Other errors (EBADF, etc.) - treat as not connected */
  return 0;
}
/**
 * SocketDgram_isbound - Check if datagram socket is bound to an address
 * @socket: Socket to check
 * Returns: 1 if bound, 0 if not bound
 * Thread-safe: Yes (operates on single socket)
 * Note: Uses getsockname() to determine binding state.
 * A socket is bound if getsockname() succeeds and returns a valid address.
 * Wildcard addresses (0.0.0.0 or ::) still count as bound.
 */

int
SocketDgram_isbound (T socket)
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
      /* Socket is bound if getsockname succeeds. For IPv4/IPv6,
       * check if we have a valid port (address can be wildcard) */
      if (addr.ss_family == AF_INET)
        {
          struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
          if (sin->sin_port != 0)
            return 1;
        }
      else if (addr.ss_family == AF_INET6)
        {
          struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
          if (sin6->sin6_port != 0)
            return 1;
        }
    }
  return 0;
}

#undef T
