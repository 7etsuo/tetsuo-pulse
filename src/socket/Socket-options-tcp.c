/**
 * Socket-options-tcp.c - TCP-specific socket options
 *
 * Implements TCP-specific socket options including Nagle's algorithm,
 * congestion control, buffer sizes, TCP fast open, and user timeout.
 * Provides comprehensive TCP configuration with platform-specific handling.
 *
 * Features:
 * - TCP_NODELAY (Nagle's algorithm control)
 * - TCP congestion control algorithms
 * - Socket buffer size management
 * - TCP fast open support
 * - TCP user timeout configuration
 * - Platform-specific TCP options
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <assert.h>
#include <unistd.h>

#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/Socket.h"
#include "core/SocketMetrics.h"
#include "socket/Socket-private.h"

#define T Socket_T

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketOptions);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketOptions, e)

/* ==================== TCP Options ==================== */

void
Socket_setnodelay (T socket, int nodelay)
{
  assert (socket);

  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_NODELAY, &nodelay, sizeof (nodelay))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set TCP_NODELAY");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

int
Socket_getnodelay (T socket)
{
  int nodelay = 0;

  assert (socket);

  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_IPPROTO_TCP, SOCKET_TCP_NODELAY,
                                  &nodelay, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  return nodelay;
}

void
Socket_setcongestion (T socket, const char *algorithm)
{
  assert (socket);
  assert (algorithm);

#if SOCKET_HAS_TCP_CONGESTION
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_CONGESTION, algorithm, strlen (algorithm) + 1)
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set TCP_CONGESTION (algorithm=%s)",
                        algorithm);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#else
  SOCKET_ERROR_MSG ("TCP_CONGESTION not supported on this platform");
  RAISE_MODULE_ERROR (Socket_Failed);
#endif
}

int
Socket_getcongestion (T socket, char *algorithm, size_t len)
{
  socklen_t optlen;

  assert (socket);
  assert (algorithm);
  assert (len > 0);

#if SOCKET_HAS_TCP_CONGESTION
  optlen = (socklen_t)len;
  if (getsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_CONGESTION, algorithm, &optlen)
      < 0)
    {
      return -1;
    }
  return 0;
#else
  (void)optlen;
  return -1;
#endif
}

/* ==================== Buffer Size Operations ==================== */

void
Socket_setrcvbuf (T socket, int size)
{
  assert (socket);
  assert (size > 0);

  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                  SOCKET_SO_RCVBUF, &size, sizeof (size))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set SO_RCVBUF (size=%d)", size);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

void
Socket_setsndbuf (T socket, int size)
{
  assert (socket);
  assert (size > 0);

  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                  SOCKET_SO_SNDBUF, &size, sizeof (size))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set SO_SNDBUF (size=%d)", size);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

int
Socket_getrcvbuf (T socket)
{
  int bufsize = 0;

  assert (socket);

  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_SOL_SOCKET, SOCKET_SO_RCVBUF,
                                  &bufsize, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  return bufsize;
}

int
Socket_getsndbuf (T socket)
{
  int bufsize = 0;

  assert (socket);

  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_SOL_SOCKET, SOCKET_SO_SNDBUF,
                                  &bufsize, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  return bufsize;
}

/* ==================== Platform-Specific TCP Options ==================== */

void
Socket_setfastopen (T socket, int enable)
{
  int opt = enable ? 1 : 0;

  assert (socket);

#if SOCKET_HAS_TCP_FASTOPEN
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_FASTOPEN, &opt, sizeof (opt))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set TCP_FASTOPEN (enable=%d)", enable);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#else
  (void)opt;
  SOCKET_ERROR_MSG ("TCP_FASTOPEN not supported on this platform");
  RAISE_MODULE_ERROR (Socket_Failed);
#endif
}

int
Socket_getfastopen (T socket)
{
  int opt = 0;
  socklen_t optlen = sizeof (opt);

  assert (socket);

#if SOCKET_HAS_TCP_FASTOPEN
  if (getsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_FASTOPEN, &opt, &optlen)
      < 0)
    {
      return -1;
    }
  return opt;
#else
  return -1;
#endif
}

void
Socket_setusertimeout (T socket, unsigned int timeout_ms)
{
  assert (socket);
  assert (timeout_ms > 0);

#if SOCKET_HAS_TCP_USER_TIMEOUT
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_USER_TIMEOUT, &timeout_ms, sizeof (timeout_ms))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set TCP_USER_TIMEOUT (timeout_ms=%u)",
                        timeout_ms);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#else
  (void)timeout_ms;
  SOCKET_ERROR_MSG ("TCP_USER_TIMEOUT not supported on this platform");
  RAISE_MODULE_ERROR (Socket_Failed);
#endif
}

unsigned int
Socket_getusertimeout (T socket)
{
  unsigned int timeout_ms = 0;
  socklen_t optlen = sizeof (timeout_ms);

  assert (socket);

#if SOCKET_HAS_TCP_USER_TIMEOUT
  if (getsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_USER_TIMEOUT, &timeout_ms, &optlen)
      < 0)
    {
      return 0;
    }
  return timeout_ms;
#else
  (void)optlen;
  return 0;
#endif
}

#undef T
