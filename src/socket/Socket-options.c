/**
 * Socket-options.c - Socket flag and timeout options
 *
 * Implements socket flag management (non-blocking, reuseaddr, reuseport,
 * cloexec) and timeout configuration including socket timeouts, timeout
 * API functions, and shutdown operations.
 *
 * Features:
 * - Socket flag operations (non-blocking, reuseaddr, reuseport, cloexec)
 * - Timeout configuration (set/get timeout)
 * - Socket timeout API (timeouts get/set/defaults)
 * - Socket shutdown operations
 * - Thread-safe timeout management
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
#include "core/SocketUtil.h"
#include "socket/Socket.h"
#include "socket/SocketCommon.h"
#include "socket/Socket-private.h"

#define T Socket_T

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketOptions);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketOptions, e)

/* sanitize_timeout is defined in SocketCommon.c - use extern declaration */
extern int socketcommon_sanitize_timeout (int timeout_ms);

/* ==================== Socket Flags ==================== */

void
Socket_setnonblocking (T socket)
{
  SocketCommon_set_nonblock (socket->base, true, Socket_Failed);
}

void
Socket_setreuseaddr (T socket)
{
  assert (socket);
  SocketCommon_setreuseaddr (socket->base, Socket_Failed);
}

void
Socket_setreuseport (T socket)
{
  assert (socket);
  SocketCommon_setreuseport (socket->base, Socket_Failed);
}

void
Socket_setcloexec (T socket, int enable)
{
  assert (socket);
  SocketCommon_setcloexec_with_error (socket->base, enable, Socket_Failed);
}

/* ==================== Timeout Operations ==================== */

void
Socket_settimeout (T socket, int timeout_sec)
{
  assert (socket);
  SocketCommon_settimeout (socket->base, timeout_sec, Socket_Failed);
}

int
Socket_gettimeout (T socket)
{
  struct timeval tv;

  assert (socket);

  if (SocketCommon_getoption_timeval (SocketBase_fd (socket->base),
                                      SOCKET_SOL_SOCKET, SOCKET_SO_RCVTIMEO,
                                      &tv, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  return (int)tv.tv_sec;
}

/* ==================== Socket Timeouts API ==================== */

void
Socket_timeouts_get (const T socket, SocketTimeouts_T *timeouts)
{
  assert (socket);
  assert (timeouts);

  *timeouts = socket->base->timeouts;
}

void
Socket_timeouts_set (T socket, const SocketTimeouts_T *timeouts)
{
  assert (socket);

  if (timeouts == NULL)
    {
      /* Thread-safe copy of default timeouts */
      pthread_mutex_lock (&socket_default_timeouts_mutex);
      socket->base->timeouts = socket_default_timeouts;
      pthread_mutex_unlock (&socket_default_timeouts_mutex);
      return;
    }

  socket->base->timeouts.connect_timeout_ms
      = socketcommon_sanitize_timeout (timeouts->connect_timeout_ms);
  socket->base->timeouts.dns_timeout_ms
      = socketcommon_sanitize_timeout (timeouts->dns_timeout_ms);
  socket->base->timeouts.operation_timeout_ms
      = socketcommon_sanitize_timeout (timeouts->operation_timeout_ms);
}

void
Socket_timeouts_getdefaults (SocketTimeouts_T *timeouts)
{
  /* Delegate to SocketCommon - single source of truth */
  SocketCommon_timeouts_getdefaults (timeouts);
}

void
Socket_timeouts_setdefaults (const SocketTimeouts_T *timeouts)
{
  /* Delegate to SocketCommon - single source of truth */
  SocketCommon_timeouts_setdefaults (timeouts);
}

/* ==================== Shutdown ==================== */

/**
 * socket_shutdown_mode_valid - Validate shutdown mode argument
 * @how: Shutdown mode (SHUT_RD, SHUT_WR, or SHUT_RDWR)
 *
 * Returns: Non-zero if valid, 0 if invalid
 */
static int
socket_shutdown_mode_valid (int how)
{
  return (how == SOCKET_SHUT_RD || how == SOCKET_SHUT_WR
          || how == SOCKET_SHUT_RDWR);
}

void
Socket_shutdown (T socket, int how)
{
  assert (socket);

  if (!socket_shutdown_mode_valid (how))
    {
      SOCKET_ERROR_MSG ("Invalid shutdown mode: %d", how);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  if (shutdown (SocketBase_fd (socket->base), how) < 0)
    {
      SOCKET_ERROR_FMT ("Failed to shutdown socket (how=%d)", how);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

/* ==================== Keepalive Operations ====================
 * Moved from Socket-options-keepalive.c for consolidation */

/**
 * validate_keepalive_parameters - Validate keepalive configuration
 * @idle: Time before first probe (seconds)
 * @interval: Interval between probes (seconds)
 * @count: Number of failed probes before disconnect
 *
 * Raises: Socket_Failed if any parameter is <= 0
 */
static void
validate_keepalive_parameters (int idle, int interval, int count)
{
  if (idle <= 0 || interval <= 0 || count <= 0)
    {
      SOCKET_ERROR_MSG ("Invalid keepalive parameters (idle=%d, interval=%d, "
                        "count=%d): all must be > 0",
                        idle, interval, count);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

/**
 * enable_socket_keepalive - Enable SO_KEEPALIVE option
 * @socket: Socket instance
 *
 * Raises: Socket_Failed on setsockopt failure
 */
static void
enable_socket_keepalive (T socket)
{
  SocketCommon_set_option_int (socket->base, SOCKET_SOL_SOCKET,
                               SOCKET_SO_KEEPALIVE, 1, Socket_Failed);
}

/**
 * set_keepalive_idle_time - Set TCP_KEEPIDLE option
 * @socket: Socket instance
 * @idle: Idle time in seconds
 *
 * Raises: Socket_Failed on setsockopt failure
 * Note: No-op on platforms without TCP_KEEPIDLE
 */
static void
set_keepalive_idle_time (T socket, int idle)
{
#ifdef TCP_KEEPIDLE
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_KEEPIDLE, &idle, sizeof (idle))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set keepalive idle time");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#else
  (void)socket;
  (void)idle;
#endif
}

/**
 * set_keepalive_interval - Set TCP_KEEPINTVL option
 * @socket: Socket instance
 * @interval: Probe interval in seconds
 *
 * Raises: Socket_Failed on setsockopt failure
 * Note: No-op on platforms without TCP_KEEPINTVL
 */
static void
set_keepalive_interval (T socket, int interval)
{
#ifdef TCP_KEEPINTVL
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_KEEPINTVL, &interval, sizeof (interval))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set keepalive interval");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#else
  (void)socket;
  (void)interval;
#endif
}

/**
 * set_keepalive_count - Set TCP_KEEPCNT option
 * @socket: Socket instance
 * @count: Number of probes before disconnect
 *
 * Raises: Socket_Failed on setsockopt failure
 * Note: No-op on platforms without TCP_KEEPCNT
 */
static void
set_keepalive_count (T socket, int count)
{
#ifdef TCP_KEEPCNT
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_KEEPCNT, &count, sizeof (count))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set keepalive count");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#else
  (void)socket;
  (void)count;
#endif
}

void
Socket_setkeepalive (T socket, int idle, int interval, int count)
{
  assert (socket);
  validate_keepalive_parameters (idle, interval, count);
  enable_socket_keepalive (socket);
  set_keepalive_idle_time (socket, idle);
  set_keepalive_interval (socket, interval);
  set_keepalive_count (socket, count);
}

void
Socket_getkeepalive (T socket, int *idle, int *interval, int *count)
{
  int keepalive_enabled = 0;
  int fd;

  assert (socket);
  assert (idle);
  assert (interval);
  assert (count);

  fd = SocketBase_fd (socket->base);

  /* Get SO_KEEPALIVE flag */
  if (SocketCommon_getoption_int (fd, SOCKET_SOL_SOCKET, SOCKET_SO_KEEPALIVE,
                                  &keepalive_enabled, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  if (!keepalive_enabled)
    {
      *idle = 0;
      *interval = 0;
      *count = 0;
      return;
    }

    /* Get TCP_KEEPIDLE */
#ifdef TCP_KEEPIDLE
  if (SocketCommon_getoption_int (fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPIDLE,
                                  idle, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);
#else
  *idle = 0;
#endif

    /* Get TCP_KEEPINTVL */
#ifdef TCP_KEEPINTVL
  if (SocketCommon_getoption_int (fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPINTVL,
                                  interval, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);
#else
  *interval = 0;
#endif

    /* Get TCP_KEEPCNT */
#ifdef TCP_KEEPCNT
  if (SocketCommon_getoption_int (fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPCNT,
                                  count, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);
#else
  *count = 0;
#endif
}


/* ==================== TCP Options ====================
 * Moved from Socket-options-tcp.c for consolidation */

void
Socket_setnodelay (T socket, int nodelay)
{
  assert (socket);
  SocketCommon_set_option_int (socket->base, SOCKET_IPPROTO_TCP,
                               SOCKET_TCP_NODELAY, nodelay, Socket_Failed);
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
  SocketCommon_set_option_int (socket->base, SOCKET_SOL_SOCKET,
                               SOCKET_SO_RCVBUF, size, Socket_Failed);
}

void
Socket_setsndbuf (T socket, int size)
{
  assert (socket);
  assert (size > 0);
  SocketCommon_set_option_int (socket->base, SOCKET_SOL_SOCKET,
                               SOCKET_SO_SNDBUF, size, Socket_Failed);
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
