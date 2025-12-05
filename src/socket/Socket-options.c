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

  /* Note: SocketCommon_getoption_timeval raises Socket_Failed on error */
  SocketCommon_getoption_timeval (SocketBase_fd (socket->base),
                                  SOCKET_SOL_SOCKET, SOCKET_SO_RCVTIMEO, &tv,
                                  Socket_Failed);

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

void
Socket_timeouts_set_extended (T socket, const SocketTimeouts_Extended_T *extended)
{
  assert (socket);
  assert (extended);

  /* Map extended timeouts to basic structure
   * Extended provides more granular control with the same underlying storage */

  /* DNS timeout */
  if (extended->dns_timeout_ms != 0)
    socket->base->timeouts.dns_timeout_ms
        = socketcommon_sanitize_timeout (extended->dns_timeout_ms);

  /* Connect timeout */
  if (extended->connect_timeout_ms != 0)
    socket->base->timeouts.connect_timeout_ms
        = socketcommon_sanitize_timeout (extended->connect_timeout_ms);

  /* Operation timeout (used for TLS and general operations) */
  if (extended->operation_timeout_ms != 0)
    socket->base->timeouts.operation_timeout_ms
        = socketcommon_sanitize_timeout (extended->operation_timeout_ms);
  else if (extended->tls_timeout_ms != 0)
    /* If TLS timeout set but not operation, use TLS timeout for operations */
    socket->base->timeouts.operation_timeout_ms
        = socketcommon_sanitize_timeout (extended->tls_timeout_ms);

  /* Note: request_timeout_ms is handled at the HTTP client level, not socket */
}

void
Socket_timeouts_get_extended (const T socket, SocketTimeouts_Extended_T *extended)
{
  assert (socket);
  assert (extended);

  /* Map basic timeouts to extended structure */
  extended->dns_timeout_ms = socket->base->timeouts.dns_timeout_ms;
  extended->connect_timeout_ms = socket->base->timeouts.connect_timeout_ms;
  extended->tls_timeout_ms = socket->base->timeouts.operation_timeout_ms;
  extended->request_timeout_ms = 0; /* Not tracked at socket level */
  extended->operation_timeout_ms = socket->base->timeouts.operation_timeout_ms;
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
      /* LCOV_EXCL_START - Defensive: TCP_KEEPIDLE fails first on same socket types */
      SOCKET_ERROR_FMT ("Failed to set keepalive interval");
      RAISE_MODULE_ERROR (Socket_Failed);
      /* LCOV_EXCL_STOP */
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
      /* LCOV_EXCL_START - Defensive: TCP_KEEPIDLE fails first on same socket types */
      SOCKET_ERROR_FMT ("Failed to set keepalive count");
      RAISE_MODULE_ERROR (Socket_Failed);
      /* LCOV_EXCL_STOP */
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

  /* Note: SocketCommon_getoption_int raises Socket_Failed on error */
  SocketCommon_getoption_int (fd, SOCKET_SOL_SOCKET, SOCKET_SO_KEEPALIVE,
                              &keepalive_enabled, Socket_Failed);

  if (!keepalive_enabled)
    {
      *idle = 0;
      *interval = 0;
      *count = 0;
      return;
    }

    /* Get TCP_KEEPIDLE */
#ifdef TCP_KEEPIDLE
  SocketCommon_getoption_int (fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPIDLE, idle,
                              Socket_Failed);
#else
  *idle = 0;
#endif

    /* Get TCP_KEEPINTVL */
#ifdef TCP_KEEPINTVL
  SocketCommon_getoption_int (fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPINTVL,
                              interval, Socket_Failed);
#else
  *interval = 0;
#endif

    /* Get TCP_KEEPCNT */
#ifdef TCP_KEEPCNT
  SocketCommon_getoption_int (fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPCNT, count,
                              Socket_Failed);
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

  /* Note: SocketCommon_getoption_int raises Socket_Failed on error */
  SocketCommon_getoption_int (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                              SOCKET_TCP_NODELAY, &nodelay, Socket_Failed);

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
  assert (socket);
  assert (algorithm);
  assert (len > 0);

#if SOCKET_HAS_TCP_CONGESTION
  socklen_t optlen = (socklen_t)len;
  if (getsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_CONGESTION, algorithm, &optlen)
      < 0)
    {
      return -1;
    }
  return 0;
#else
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

  /* Note: SocketCommon_getoption_int raises Socket_Failed on error */
  SocketCommon_getoption_int (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                              SOCKET_SO_RCVBUF, &bufsize, Socket_Failed);

  return bufsize;
}

int
Socket_getsndbuf (T socket)
{
  int bufsize = 0;

  assert (socket);

  /* Note: SocketCommon_getoption_int raises Socket_Failed on error */
  SocketCommon_getoption_int (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                              SOCKET_SO_SNDBUF, &bufsize, Socket_Failed);

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
  assert (socket);

#if SOCKET_HAS_TCP_FASTOPEN
  int opt = 0;
  socklen_t optlen = sizeof (opt);
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

/* ==================== SYN Flood Protection Options ==================== */

void
Socket_setdeferaccept (T socket, int timeout_sec)
{
  assert (socket);

  /* Validate timeout */
  if (timeout_sec < 0)
    {
      SOCKET_ERROR_MSG ("Invalid defer accept timeout: %d (must be >= 0)",
                        timeout_sec);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

#if SOCKET_HAS_TCP_DEFER_ACCEPT
  /* Linux: TCP_DEFER_ACCEPT takes timeout in seconds */
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_DEFER_ACCEPT, &timeout_sec, sizeof (timeout_sec))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set TCP_DEFER_ACCEPT (timeout_sec=%d)",
                        timeout_sec);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#elif SOCKET_HAS_SO_ACCEPTFILTER
  /* BSD/macOS: Use SO_ACCEPTFILTER with "dataready" filter */
  if (timeout_sec > 0)
    {
      struct accept_filter_arg afa;
      memset (&afa, 0, sizeof (afa));
      strncpy (afa.af_name, "dataready", sizeof (afa.af_name) - 1);
      if (setsockopt (SocketBase_fd (socket->base), SOL_SOCKET, SO_ACCEPTFILTER,
                      &afa, sizeof (afa))
          < 0)
        {
          SOCKET_ERROR_FMT ("Failed to set SO_ACCEPTFILTER dataready");
          RAISE_MODULE_ERROR (Socket_Failed);
        }
    }
  else
    {
      /* Disable: Remove accept filter by setting empty filter */
      struct accept_filter_arg afa;
      memset (&afa, 0, sizeof (afa));
      /* Removing filter may fail if none set - ignore EINVAL */
      if (setsockopt (SocketBase_fd (socket->base), SOL_SOCKET, SO_ACCEPTFILTER,
                      &afa, sizeof (afa))
              < 0
          && errno != EINVAL)
        {
          SOCKET_ERROR_FMT ("Failed to clear SO_ACCEPTFILTER");
          RAISE_MODULE_ERROR (Socket_Failed);
        }
    }
#else
  (void)timeout_sec;
  SOCKET_ERROR_MSG ("TCP_DEFER_ACCEPT/SO_ACCEPTFILTER not supported on this "
                    "platform");
  RAISE_MODULE_ERROR (Socket_Failed);
#endif
}

int
Socket_getdeferaccept (T socket)
{
  assert (socket);

#if SOCKET_HAS_TCP_DEFER_ACCEPT
  int timeout_sec = 0;
  socklen_t optlen = sizeof (timeout_sec);
  if (getsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_DEFER_ACCEPT, &timeout_sec, &optlen)
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to get TCP_DEFER_ACCEPT");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  return timeout_sec;
#elif SOCKET_HAS_SO_ACCEPTFILTER
  /* BSD/macOS: Can only check if filter is set, not timeout */
  struct accept_filter_arg afa;
  socklen_t optlen = sizeof (afa);
  memset (&afa, 0, sizeof (afa));
  if (getsockopt (SocketBase_fd (socket->base), SOL_SOCKET, SO_ACCEPTFILTER,
                  &afa, &optlen)
      < 0)
    {
      if (errno == EINVAL)
        return 0; /* No filter set */
      SOCKET_ERROR_FMT ("Failed to get SO_ACCEPTFILTER");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  /* Return 1 if filter is set (can't get actual timeout on BSD) */
  return (afa.af_name[0] != '\0') ? 1 : 0;
#else
  SOCKET_ERROR_MSG ("TCP_DEFER_ACCEPT/SO_ACCEPTFILTER not supported on this "
                    "platform");
  RAISE_MODULE_ERROR (Socket_Failed);
  return 0; /* Unreachable but silences compiler */
#endif
}

#undef T
