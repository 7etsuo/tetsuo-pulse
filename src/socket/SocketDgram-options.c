/**
 * SocketDgram-options.c - UDP/datagram socket options
 *
 * Implements socket option management for UDP sockets including reuseaddr,
 * reuseport, broadcast, multicast, TTL, timeout, buffer sizes, and cloexec
 * settings. Provides comprehensive socket configuration with proper error
 * handling.
 *
 * Features:
 * - Socket flag management (reuseaddr, reuseport, broadcast)
 * - Multicast group management (join/leave)
 * - TTL/hop limit configuration
 * - Socket buffer size management
 * - Timeout configuration
 * - Close-on-exec flag control
 * - Platform-specific option handling
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

void
SocketDgram_setnonblocking (T socket)
{
  assert (socket);
  SocketCommon_set_nonblock (socket->base, true, SocketDgram_Failed);
}

void
SocketDgram_setreuseaddr (T socket)
{
  int opt = 1;

  assert (socket);

  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                  SOCKET_SO_REUSEADDR, &opt, sizeof (opt))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set SO_REUSEADDR");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
}

void
SocketDgram_setreuseport (T socket)
{
  int opt = 1;

  assert (socket);

#if SOCKET_HAS_SO_REUSEPORT
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                  SOCKET_SO_REUSEPORT, &opt, sizeof (opt))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set SO_REUSEPORT");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
#else
  (void)opt;
  SOCKET_ERROR_MSG ("SO_REUSEPORT not supported on this platform");
  RAISE_MODULE_ERROR (SocketDgram_Failed);
#endif
}

void
SocketDgram_setbroadcast (T socket, int enable)
{
  int optval = enable ? 1 : 0;
  assert (socket);
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                  SOCKET_SO_BROADCAST, &optval, sizeof (optval))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set SO_BROADCAST");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
}

void
SocketDgram_joinmulticast (T socket, const char *group, const char *interface)
{
  assert (socket);
  assert (group);
  SocketCommon_join_multicast (socket->base, group, interface,
                               SocketDgram_Failed);
}

void
SocketDgram_leavemulticast (T socket, const char *group, const char *interface)
{
  assert (socket);
  assert (group);
  SocketCommon_leave_multicast (socket->base, group, interface,
                                SocketDgram_Failed);
}

/**
 * get_socket_domain - Get socket domain/family (private helper)
 * Uses SO_DOMAIN on Linux, falls back to getsockname() on other platforms.
 * Raises: SocketDgram_Failed if getsockname() fails (only on error path).
 */

static int
get_socket_domain (T socket)
{
  return SocketCommon_get_family (
      socket->base, true,
      SocketDgram_Failed); /* raises on fail - comment removed to fix compiler
                              warning */
}

/**
 * set_ttl_by_family
 * Raises: SocketDgram_Failed on unsupported family or failure
 */

static void
set_ttl_by_family (T socket, int socket_family, int ttl)
{
  SocketCommon_set_ttl (socket->base, socket_family, ttl, SocketDgram_Failed);
}

/** validate_ttl_value - Validate TTL value range; raises on invalid */
static void
validate_ttl_value (int ttl)
{
  if (ttl < 1 || ttl > 255)
    {
      SOCKET_ERROR_MSG ("Invalid TTL value: %d (must be 1-255)", ttl);
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
}

void
SocketDgram_setttl (T socket, int ttl)
{
  int socket_family;
  assert (socket);
  validate_ttl_value (ttl);
  socket_family = get_socket_domain (socket);
  set_ttl_by_family (socket, socket_family, ttl);
}

void
SocketDgram_settimeout (T socket, int timeout_sec)
{
  struct timeval tv;
  assert (socket);
  tv.tv_sec = timeout_sec;
  tv.tv_usec = 0;
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                  SOCKET_SO_RCVTIMEO, &tv, sizeof (tv))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set receive timeout");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                  SOCKET_SO_SNDTIMEO, &tv, sizeof (tv))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set send timeout");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
}

/**
 * SocketDgram_getrcvbuf - Get receive buffer size
 * @socket: Socket to query
 * Returns: Receive buffer size in bytes
 * Raises: SocketDgram_Failed on error
 */

int
SocketDgram_getrcvbuf (T socket)
{
  int bufsize = 0;

  assert (socket);

  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_SOL_SOCKET, SOCKET_SO_RCVBUF,
                                  &bufsize, SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);

  return bufsize;
}

/**
 * SocketDgram_getsndbuf - Get send buffer size
 * @socket: Socket to query
 * Returns: Send buffer size in bytes
 * Raises: SocketDgram_Failed on error
 */

int
SocketDgram_getsndbuf (T socket)
{
  int bufsize = 0;

  assert (socket);

  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_SOL_SOCKET, SOCKET_SO_SNDBUF,
                                  &bufsize, SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);

  return bufsize;
}

/**
 * SocketDgram_setcloexec - Control close-on-exec flag
 * @socket: Socket to modify
 * @enable: 1 to enable CLOEXEC, 0 to disable
 * Raises: SocketDgram_Failed on error
 */

void
SocketDgram_setcloexec (T socket, int enable)
{
  assert (socket);
  if (SocketCommon_setcloexec (SocketBase_fd (socket->base), enable) < 0)
    {
      SOCKET_ERROR_FMT ("Failed to %s close-on-exec flag",
                        enable ? "set" : "clear");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
}

/**
 * get_ipv4_ttl - Get IPv4 TTL
 * @socket: Socket to query
 * @ttl: Output pointer for TTL value
 * Raises: SocketDgram_Failed on failure
 */

static void
get_ipv4_ttl (T socket, int *ttl)
{
  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_IPPROTO_IP, SOCKET_IP_TTL, ttl,
                                  SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);
}

/**
 * get_ipv6_hop_limit - Get IPv6 hop limit
 * @socket: Socket to query
 * @ttl: Output pointer for hop limit value
 * Raises: SocketDgram_Failed on failure
 */

static void
get_ipv6_hop_limit (T socket, int *ttl)
{
  if (SocketCommon_getoption_int (
          SocketBase_fd (socket->base), SOCKET_IPPROTO_IPV6,
          SOCKET_IPV6_UNICAST_HOPS, ttl, SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);
}

/**
 * get_ttl_by_family - Get TTL by address family
 * @socket: Socket to query
 * @socket_family: Address family
 * @ttl: Output pointer for TTL value
 * Raises: SocketDgram_Failed on unsupported family or failure
 */

static void
get_ttl_by_family (T socket, int socket_family, int *ttl)
{
  if (socket_family == SOCKET_AF_INET)
    get_ipv4_ttl (socket, ttl);
  else if (socket_family == SOCKET_AF_INET6)
    get_ipv6_hop_limit (socket, ttl);
  else
    {
      SOCKET_ERROR_MSG ("Unsupported address family for TTL");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
}

/**
 * SocketDgram_getttl - Get time-to-live (hop limit)
 * @socket: Socket to query
 * Returns: TTL value (1 to SOCKET_MAX_TTL)
 * Raises: SocketDgram_Failed on error
 */

int
SocketDgram_getttl (T socket)
{
  int socket_family;
  int ttl = 0;
  assert (socket);
  socket_family = get_socket_domain (socket);
  get_ttl_by_family (socket, socket_family, &ttl);
  return ttl;
}

#undef T
