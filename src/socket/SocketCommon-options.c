/**
 * SocketCommon-options.c - Socket option helpers
 *
 * Contains socket option get/set operations and file descriptor utilities
 * extracted from the main SocketCommon.c file.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/SocketConfig.h"
#define SOCKET_LOG_COMPONENT "SocketCommon"
#include "core/SocketError.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketCommon);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketCommon, e)

/**
 * SocketCommon_create_fd - Create socket file descriptor with CLOEXEC
 * @domain: Address domain
 * @type: Socket type
 * @protocol: Protocol
 * @exc_type: Exception type to raise on failure
 * Returns: File descriptor on success, raises exception on failure
 * Note: Moved from Socket.c create_socket_fd and unified with Dgram logic
 * Thread-safe: Yes
 * Allocates: No memory allocation
 */
int
SocketCommon_create_fd (int domain, int type, int protocol, Except_T exc_type)
{
  int fd;

#if SOCKET_HAS_SOCK_CLOEXEC
  fd = socket (domain, type | SOCK_CLOEXEC, protocol);
#else
  fd = socket (domain, type, protocol);
#endif

  if (fd < 0)
    {
      SOCKET_ERROR_FMT (
          "Failed to create socket (domain=%d, type=%d, protocol=%d)", domain,
          type, protocol);
      RAISE_MODULE_ERROR (exc_type);
    }

#if !SOCKET_HAS_SOCK_CLOEXEC
  /* Fallback: Set CLOEXEC via fcntl */
  if (fcntl (fd, F_SETFD, FD_CLOEXEC) < 0)
    {
      int saved_errno = errno;
      SAFE_CLOSE (fd);
      errno = saved_errno;
      SOCKET_ERROR_MSG ("Failed to set close-on-exec flag");
      RAISE_MODULE_ERROR (exc_type);
    }
#endif

  return fd;
}

/**
 * SocketCommon_setcloexec - Set CLOEXEC flag on file descriptor
 * @fd: File descriptor
 * @enable: 1 to enable, 0 to disable
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Yes (operates on single fd)
 */
int
SocketCommon_setcloexec (int fd, int enable)
{
  int flags;
  int new_flags;

  assert (fd >= 0);

  flags = fcntl (fd, F_GETFD);
  if (flags < 0)
    return -1;

  if (enable)
    new_flags = flags | SOCKET_FD_CLOEXEC;
  else
    new_flags = flags & ~SOCKET_FD_CLOEXEC;

  if (new_flags == flags)
    return 0; /* Already in desired state */

  if (fcntl (fd, F_SETFD, new_flags) < 0)
    return -1;

  return 0;
}

/**
 * SocketCommon_has_cloexec - Check if CLOEXEC flag is set
 * @fd: File descriptor
 * Returns: 1 if set, 0 if not set, -1 on error
 * Thread-safe: Yes (operates on single fd)
 */
int
SocketCommon_has_cloexec (int fd)
{
  int flags;

  assert (fd >= 0);

  flags = fcntl (fd, F_GETFD);
  if (flags < 0)
    return -1;

  return (flags & SOCKET_FD_CLOEXEC) ? 1 : 0;
}

/**
 * SocketCommon_set_cloexec_fd - Set FD_CLOEXEC on file descriptor
 * Unifies fallback fcntl calls after socket creation (e.g., socketpair,
 * accept)
 * @fd: FD to set
 * @enable: Enable/disable
 * @exc_type: Raise type on fail
 */
void
SocketCommon_set_cloexec_fd (int fd, bool enable, Except_T exc_type)
{
  int flags = fcntl (fd, F_GETFD, 0);
  if (flags < 0)
    {
      SOCKET_ERROR_MSG ("Failed to get FD flags for CLOEXEC set");
      RAISE_MODULE_ERROR (exc_type);
    }

  if (enable)
    {
      flags |= FD_CLOEXEC;
    }
  else
    {
      flags &= ~FD_CLOEXEC;
    }

  if (fcntl (fd, F_SETFD, flags) < 0)
    {
      SOCKET_ERROR_MSG ("Failed to set FD_CLOEXEC %s on fd %d: %s",
                        enable ? "enable" : "disable", fd, strerror (errno));
      RAISE_MODULE_ERROR (exc_type);
    }
}

/**
 * SocketCommon_set_nonblock - Set socket to non-blocking mode
 * @base: Socket base
 * @enable: Enable/disable non-blocking
 * @exc_type: Exception type to raise on failure
 */
void
SocketCommon_set_nonblock (SocketBase_T base, bool enable, Except_T exc_type)
{
  int flags = fcntl (SocketBase_fd (base), F_GETFL, 0);
  if (flags < 0)
    {
      SOCKET_ERROR_MSG ("Failed to get file flags");
      RAISE_MODULE_ERROR (exc_type);
    }

  if (enable)
    flags |= O_NONBLOCK;
  else
    flags &= ~O_NONBLOCK;

  if (fcntl (SocketBase_fd (base), F_SETFL, flags) < 0)
    {
      SOCKET_ERROR_MSG ("Failed to set non-blocking mode");
      RAISE_MODULE_ERROR (exc_type);
    }
}

/**
 * SocketCommon_getoption_int - Get integer socket option
 * @fd: File descriptor
 * @level: Option level (SOL_SOCKET, IPPROTO_TCP, etc.)
 * @optname: Option name (SO_KEEPALIVE, TCP_NODELAY, etc.)
 * @value: Output pointer for option value
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type on failure
 * Thread-safe: Yes (operates on single fd)
 */
int
SocketCommon_getoption_int (int fd, int level, int optname, int *value,
                            Except_T exception_type)
{
  socklen_t len = sizeof (*value);

  assert (fd >= 0);
  assert (value);

  if (getsockopt (fd, level, optname, value, &len) < 0)
    {
      SOCKET_ERROR_FMT ("Failed to get socket option (level=%d, optname=%d)",
                        level, optname);
      RAISE_MODULE_ERROR (exception_type);
      return -1;
    }

  return 0;
}

/**
 * SocketCommon_getoption_timeval - Get timeval socket option
 * @fd: File descriptor
 * @level: Option level (SOL_SOCKET)
 * @optname: Option name (SO_RCVTIMEO, SO_SNDTIMEO)
 * @tv: Output pointer for timeval structure
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type on failure
 * Thread-safe: Yes (operates on single fd)
 */
int
SocketCommon_getoption_timeval (int fd, int level, int optname,
                                struct timeval *tv, Except_T exception_type)
{
  socklen_t len = sizeof (*tv);

  assert (fd >= 0);
  assert (tv);

  if (getsockopt (fd, level, optname, tv, &len) < 0)
    {
      SOCKET_ERROR_FMT (
          "Failed to get socket timeout option (level=%d, optname=%d)", level,
          optname);
      RAISE_MODULE_ERROR (exception_type);
      return -1;
    }

  return 0;
}

/**
 * SocketCommon_get_family - Get socket address family from fd
 * @base: Base with fd
 * @raise_on_fail: If true, raise exc_type on failure; else return AF_UNSPEC
 * @exc_type: Exception for failure case
 * Returns: Address family or AF_UNSPEC
 * Thread-safe: Yes
 * Unifies duplicated logic from get_socket_family and
 * get_dgram_socket_family
 */
int
SocketCommon_get_family (SocketBase_T base, bool raise_on_fail,
                         Except_T exc_type)
{
  int family = AF_UNSPEC;
  socklen_t len = sizeof (family);

#if SOCKET_HAS_SO_DOMAIN
  if (getsockopt (SocketBase_fd (base), SOL_SOCKET, SO_DOMAIN, &family, &len)
      == 0)
    return family;
#endif

  /* Fallback getsockname */
  struct sockaddr_storage addr;
  len = sizeof (addr);
  if (getsockname (SocketBase_fd (base), (struct sockaddr *)&addr, &len) == 0)
    return addr.ss_family;

  if (raise_on_fail)
    {
      SOCKET_ERROR_MSG (
          "Failed to get socket family via SO_DOMAIN or getsockname");
      RAISE_MODULE_ERROR (exc_type);
    }

  return AF_UNSPEC;
}

/**
 * SocketCommon_get_socket_family - Get socket's address family (no exception)
 * @base: Socket base to query
 * Returns: Socket family or AF_UNSPEC on error
 *
 * Convenience wrapper around SocketCommon_get_family for callers that
 * don't want exceptions raised on failure.
 */
int
SocketCommon_get_socket_family (SocketBase_T base)
{
  /* Dummy exception - never raised because raise_on_fail is false */
  Except_T dummy = { NULL, NULL };
  return SocketCommon_get_family (base, false, dummy);
}

/**
 * SocketCommon_set_option_int - Generic setsockopt for int options
 * @base: Base with fd
 * @level: SOL_SOCKET etc.
 * @optname: SO_REUSEADDR etc.
 * @value: int value (bool as 0/1)
 * @exc_type: Raise on fail
 * Handles common options, logs details
 */
void
SocketCommon_set_option_int (SocketBase_T base, int level, int optname,
                             int value, Except_T exc_type)
{
  if (setsockopt (SocketBase_fd (base), level, optname, &value, sizeof (value))
      < 0)
    {
      SOCKET_ERROR_FMT (
          "Failed to set socket option level=%d optname=%d value=%d: %s",
          level, optname, value, strerror (errno));
      RAISE_MODULE_ERROR (exc_type);
    }
}

/**
 * SocketCommon_setreuseaddr - Set SO_REUSEADDR socket option
 * @base: Socket base
 * @exc_type: Exception type to raise on failure
 * Thread-safe: Yes
 */
void
SocketCommon_setreuseaddr (SocketBase_T base, Except_T exc_type)
{
  assert (base);
  SocketCommon_set_option_int (base, SOCKET_SOL_SOCKET, SOCKET_SO_REUSEADDR, 1,
                               exc_type);
}

/**
 * SocketCommon_setreuseport - Set SO_REUSEPORT socket option
 * @base: Socket base
 * @exc_type: Exception type to raise on failure
 * Thread-safe: Yes
 */
void
SocketCommon_setreuseport (SocketBase_T base, Except_T exc_type)
{
  assert (base);

#if SOCKET_HAS_SO_REUSEPORT
  SocketCommon_set_option_int (base, SOCKET_SOL_SOCKET, SOCKET_SO_REUSEPORT, 1,
                               exc_type);
#else
  SOCKET_ERROR_MSG ("SO_REUSEPORT not supported on this platform");
  RAISE_MODULE_ERROR (exc_type);
#endif
}

/**
 * SocketCommon_settimeout - Set socket send/receive timeouts
 * @base: Socket base
 * @timeout_sec: Timeout in seconds (must be >= 0)
 * @exc_type: Exception type to raise on failure
 * Thread-safe: Yes
 */
void
SocketCommon_settimeout (SocketBase_T base, int timeout_sec, Except_T exc_type)
{
  struct timeval tv;

  assert (base);

  if (timeout_sec < 0)
    {
      SOCKET_ERROR_MSG ("Invalid timeout value: %d (must be >= 0)",
                        timeout_sec);
      RAISE_MODULE_ERROR (exc_type);
    }

  tv.tv_sec = timeout_sec;
  tv.tv_usec = 0;

  if (setsockopt (SocketBase_fd (base), SOCKET_SOL_SOCKET, SOCKET_SO_RCVTIMEO,
                  &tv, sizeof (tv))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set receive timeout");
      RAISE_MODULE_ERROR (exc_type);
    }

  if (setsockopt (SocketBase_fd (base), SOCKET_SOL_SOCKET, SOCKET_SO_SNDTIMEO,
                  &tv, sizeof (tv))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set send timeout");
      RAISE_MODULE_ERROR (exc_type);
    }
}

/**
 * SocketCommon_setcloexec_with_error - Set CLOEXEC with exception on failure
 * @base: Socket base
 * @enable: 1 to enable, 0 to disable
 * @exc_type: Exception type to raise on failure
 * Thread-safe: Yes
 */
void
SocketCommon_setcloexec_with_error (SocketBase_T base, int enable,
                                    Except_T exc_type)
{
  assert (base);

  if (SocketCommon_setcloexec (SocketBase_fd (base), enable) < 0)
    {
      SOCKET_ERROR_FMT ("Failed to %s close-on-exec flag",
                        enable ? "set" : "clear");
      RAISE_MODULE_ERROR (exc_type);
    }
}
