/**
 * Socket-options.c - Socket flag and timeout options
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
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
 * - TCP keepalive configuration
 * - TCP options (nodelay, congestion, buffer sizes)
 * - Platform-specific TCP options (fastopen, user timeout, defer accept)
 * - Thread-safe timeout management
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>

#include <netinet/tcp.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include "socket/Socket-private.h"
#include "socket/Socket.h"
#include "socket/SocketCommon.h"

#define T Socket_T

/* ============================================================================
 * MODULE EXCEPTION INFRASTRUCTURE
 * ============================================================================
 */

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketOptions);

/* Convenience macros for cleaner code */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketOptions, e)
#define RAISE_FMT(e, fmt, ...)                                                \
  SOCKET_RAISE_FMT (SocketOptions, e, fmt, ##__VA_ARGS__)
#define RAISE_MSG(e, fmt, ...)                                                \
  SOCKET_RAISE_MSG (SocketOptions, e, fmt, ##__VA_ARGS__)

/* sanitize_timeout is defined in SocketCommon.c - use extern declaration */
extern int socketcommon_sanitize_timeout (int timeout_ms);

/* ============================================================================
 * SOCKET FLAGS
 * ============================================================================
 */

/**
 * Socket_setnonblocking - Set socket to non-blocking mode
 * @socket: Socket instance
 *
 * Enables non-blocking I/O operations on the socket using fcntl/O_NONBLOCK.
 * This is essential for event-driven I/O with SocketPoll or async operations.
 *
 * Raises: Socket_Failed if fcntl fails
 * Thread-safe: Yes (atomic fcntl operation)
 */
void
Socket_setnonblocking (T socket)
{
  assert (socket);
  SocketCommon_set_nonblock (socket->base, true, Socket_Failed);
}

/**
 * Socket_setreuseaddr - Enable SO_REUSEADDR socket option
 * @socket: Socket instance
 *
 * Allows reuse of local address/port for bind after close.
 * Recommended for servers to avoid TIME_WAIT delays.
 *
 * Raises: Socket_Failed on setsockopt failure
 * Thread-safe: Yes
 */
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
  int val = (enable != 0) ? 1 : 0;
  SocketCommon_setcloexec_with_error (socket->base, val, Socket_Failed);
}

/* ============================================================================
 * TIMEOUT OPERATIONS
 * ============================================================================
 */

/**
 * Socket_settimeout - Set socket I/O timeout
 * @socket: Socket instance
 * @timeout_sec: Timeout in seconds (0 = infinite)
 *
 * Sets both SO_RCVTIMEO and SO_SNDTIMEO to the specified value.
 * Negative values raise Socket_Failed.
 *
 * Raises: Socket_Failed on setsockopt failure or invalid timeout
 * Thread-safe: Yes
 */
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

  SocketCommon_getoption_timeval (SocketBase_fd (socket->base),
                                  SOCKET_SOL_SOCKET, SOCKET_SO_RCVTIMEO, &tv,
                                  Socket_Failed);

  return (int)tv.tv_sec;
}

/* ============================================================================
 * SOCKET TIMEOUTS API
 * ============================================================================
 */

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
  SocketCommon_timeouts_getdefaults (timeouts);
}

void
Socket_timeouts_setdefaults (const SocketTimeouts_T *timeouts)
{
  SocketCommon_timeouts_setdefaults (timeouts);
}

void
Socket_timeouts_set_extended (T socket,
                              const SocketTimeouts_Extended_T *extended)
{
  assert (socket);
  assert (extended);

  if (extended->dns_timeout_ms != 0)
    socket->base->timeouts.dns_timeout_ms
        = socketcommon_sanitize_timeout (extended->dns_timeout_ms);

  if (extended->connect_timeout_ms != 0)
    socket->base->timeouts.connect_timeout_ms
        = socketcommon_sanitize_timeout (extended->connect_timeout_ms);

  if (extended->operation_timeout_ms != 0)
    socket->base->timeouts.operation_timeout_ms
        = socketcommon_sanitize_timeout (extended->operation_timeout_ms);
  else if (extended->tls_timeout_ms != 0)
    socket->base->timeouts.operation_timeout_ms
        = socketcommon_sanitize_timeout (extended->tls_timeout_ms);

  /* Note: request_timeout_ms is handled at the HTTP client level */
}

void
Socket_timeouts_get_extended (const T socket,
                              SocketTimeouts_Extended_T *extended)
{
  assert (socket);
  assert (extended);

  extended->dns_timeout_ms = socket->base->timeouts.dns_timeout_ms;
  extended->connect_timeout_ms = socket->base->timeouts.connect_timeout_ms;
  extended->tls_timeout_ms = socket->base->timeouts.operation_timeout_ms;
  extended->request_timeout_ms = 0;
  extended->operation_timeout_ms = socket->base->timeouts.operation_timeout_ms;
}

/* ============================================================================
 * SHUTDOWN
 * ============================================================================
 */

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
    RAISE_MSG (Socket_Failed, "Invalid shutdown mode: %d", how);

  if (shutdown (SocketBase_fd (socket->base), how) < 0)
    RAISE_FMT (Socket_Failed, "Failed to shutdown socket (how=%d)", how);
}

/* ============================================================================
 * KEEPALIVE OPERATIONS
 * ============================================================================
 */

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
    RAISE_MSG (Socket_Failed,
               "Invalid keepalive parameters (idle=%d, interval=%d, "
               "count=%d): all must be > 0",
               idle, interval, count);
  if (idle > SOCKET_KEEPALIVE_MAX_IDLE || interval > SOCKET_KEEPALIVE_MAX_INTERVAL
      || count > SOCKET_KEEPALIVE_MAX_COUNT)
    {
      RAISE_MSG (Socket_Failed,
                 "Unreasonable keepalive parameters (idle=%d, interval=%d, "
                 "count=%d): values too large (max idle=%d, interval=%d, "
                 "count=%d)",
                 idle, interval, count, SOCKET_KEEPALIVE_MAX_IDLE,
                 SOCKET_KEEPALIVE_MAX_INTERVAL, SOCKET_KEEPALIVE_MAX_COUNT);
    }
}

/**
 * socket_options_get_option_no_raise - Get socket option without raising
 * exception
 * @fd: File descriptor
 * @level: Option level
 * @optname: Option name
 * @optval: Output buffer for option value
 * @optlen: Input/output length of optval
 *
 * Returns: 0 on success, -1 on failure (errno set)
 * Thread-safe: Yes
 */
static int
socket_options_get_option_no_raise (int fd, int level, int optname,
                                    void *optval, socklen_t *optlen)
{
  assert (fd >= 0);
  assert (optval);
  assert (optlen);

  errno = 0;
  return getsockopt (fd, level, optname, optval, optlen) == 0 ? 0 : -1;
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
  SocketCommon_set_option_int (socket->base, SOCKET_IPPROTO_TCP,
                               SOCKET_TCP_KEEPIDLE, idle, Socket_Failed);
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
  SocketCommon_set_option_int (socket->base, SOCKET_IPPROTO_TCP,
                               SOCKET_TCP_KEEPINTVL, interval, Socket_Failed);
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
  SocketCommon_set_option_int (socket->base, SOCKET_IPPROTO_TCP,
                               SOCKET_TCP_KEEPCNT, count, Socket_Failed);
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

  SocketCommon_getoption_int (fd, SOCKET_SOL_SOCKET, SOCKET_SO_KEEPALIVE,
                              &keepalive_enabled, Socket_Failed);

  *idle = 0;
  *interval = 0;
  *count = 0;

  if (!keepalive_enabled)
    return;

#ifdef TCP_KEEPIDLE
  SocketCommon_getoption_int (fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPIDLE,
                              idle, Socket_Failed);
#endif

#ifdef TCP_KEEPINTVL
  SocketCommon_getoption_int (fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPINTVL,
                              interval, Socket_Failed);
#endif

#ifdef TCP_KEEPCNT
  SocketCommon_getoption_int (fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPCNT,
                              count, Socket_Failed);
#endif
}

/* ============================================================================
 * TCP OPTIONS
 * ============================================================================
 */

void
Socket_setnodelay (T socket, int nodelay)
{
  assert (socket);
  int val = (nodelay != 0) ? 1 : 0;
  SocketCommon_set_option_int (socket->base, SOCKET_IPPROTO_TCP,
                               SOCKET_TCP_NODELAY, val, Socket_Failed);
}

int
Socket_getnodelay (T socket)
{
  int nodelay = 0;

  assert (socket);

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
  if (algorithm == NULL || *algorithm == '\0')
    {
      RAISE_MSG (Socket_Failed,
                 "Invalid congestion algorithm: null or empty string");
    }
  size_t alen = strnlen (algorithm, SOCKET_MAX_CONGESTION_ALGO_LEN + 1);
  if (alen > SOCKET_MAX_CONGESTION_ALGO_LEN)
    {
      RAISE_MSG (Socket_Failed,
                 "Congestion algorithm name too long (maximum %d characters)",
                 SOCKET_MAX_CONGESTION_ALGO_LEN);
    }
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_CONGESTION, algorithm, (socklen_t)(alen + 1))
      < 0)
    RAISE_FMT (Socket_Failed, "Failed to set TCP_CONGESTION (algorithm=%.*s)",
               (int)alen, algorithm);
#else
  RAISE_MSG (Socket_Failed, "TCP_CONGESTION not supported on this platform");
#endif
}

int
Socket_getcongestion (T socket, char *algorithm, size_t len)
{
  int fd = SocketBase_fd (socket->base);
  socklen_t optlen = (socklen_t)len;

  assert (socket);
  assert (algorithm);
  assert (len > 0);

#if SOCKET_HAS_TCP_CONGESTION
  if (socket_options_get_option_no_raise (
          fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_CONGESTION, algorithm, &optlen)
      < 0)
    return -1;
  if (optlen > (socklen_t)len)
    {
      errno = EMSGSIZE;
      return -1;
    }
  algorithm[(size_t)len - 1] = '\0'; /* Ensure null termination */
  return 0;
#else
  (void)fd;
  return -1;
#endif
}

/* ============================================================================
 * BUFFER SIZE OPERATIONS
 * ============================================================================
 */

void
Socket_setrcvbuf (T socket, int size)
{
  assert (socket);
  assert (size > 0);
  if (!SOCKET_VALID_BUFFER_SIZE ((size_t)size))
    {
      RAISE_FMT (Socket_Failed,
                 "Invalid receive buffer size %d (min=%d, max=%d)", size,
                 (int)SOCKET_MIN_BUFFER_SIZE, (int)SOCKET_MAX_BUFFER_SIZE);
    }
  SocketCommon_set_option_int (socket->base, SOCKET_SOL_SOCKET,
                               SOCKET_SO_RCVBUF, size, Socket_Failed);
}

void
Socket_setsndbuf (T socket, int size)
{
  assert (socket);
  assert (size > 0);
  if (!SOCKET_VALID_BUFFER_SIZE ((size_t)size))
    {
      RAISE_FMT (Socket_Failed, "Invalid send buffer size %d (min=%d, max=%d)",
                 size, (int)SOCKET_MIN_BUFFER_SIZE,
                 (int)SOCKET_MAX_BUFFER_SIZE);
    }
  SocketCommon_set_option_int (socket->base, SOCKET_SOL_SOCKET,
                               SOCKET_SO_SNDBUF, size, Socket_Failed);
}

int
Socket_getrcvbuf (T socket)
{
  int bufsize = 0;

  assert (socket);

  SocketCommon_getoption_int (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                              SOCKET_SO_RCVBUF, &bufsize, Socket_Failed);

  return bufsize;
}

int
Socket_getsndbuf (T socket)
{
  int bufsize = 0;

  assert (socket);

  SocketCommon_getoption_int (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                              SOCKET_SO_SNDBUF, &bufsize, Socket_Failed);

  return bufsize;
}

/* ============================================================================
 * PLATFORM-SPECIFIC TCP OPTIONS
 * ============================================================================
 */

void
Socket_setfastopen (T socket, int enable)
{
  assert (socket);
  int val = (enable != 0) ? 1 : 0;
#if SOCKET_HAS_TCP_FASTOPEN
  SocketCommon_set_option_int (socket->base, SOCKET_IPPROTO_TCP,
                               SOCKET_TCP_FASTOPEN, val, Socket_Failed);
#else
  RAISE_MSG (Socket_Failed, "TCP_FASTOPEN not supported on this platform");
#endif
}

int
Socket_getfastopen (T socket)
{
  int fd = SocketBase_fd (socket->base);
  int opt = 0;
  socklen_t optlen = sizeof (opt);

  assert (socket);

#if SOCKET_HAS_TCP_FASTOPEN
  if (socket_options_get_option_no_raise (fd, SOCKET_IPPROTO_TCP,
                                          SOCKET_TCP_FASTOPEN, &opt, &optlen)
      < 0)
    return -1;
  return opt;
#else
  (void)fd;
  return -1;
#endif
}

void
Socket_setusertimeout (T socket, unsigned int timeout_ms)
{
  assert (socket);
  assert (timeout_ms > 0);
  if (timeout_ms > INT_MAX)
    {
      RAISE_MSG (Socket_Failed,
                 "User timeout value %u exceeds maximum supported %d",
                 timeout_ms, INT_MAX);
    }

#if SOCKET_HAS_TCP_USER_TIMEOUT
  SocketCommon_set_option_int (socket->base, SOCKET_IPPROTO_TCP,
                               SOCKET_TCP_USER_TIMEOUT, (int)timeout_ms,
                               Socket_Failed);
#else
  RAISE_MSG (Socket_Failed, "TCP_USER_TIMEOUT not supported on this platform");
#endif
}

unsigned int
Socket_getusertimeout (T socket)
{
  int fd = SocketBase_fd (socket->base);
  unsigned int timeout_ms = 0;
  socklen_t optlen = sizeof (timeout_ms);

  assert (socket);

#if SOCKET_HAS_TCP_USER_TIMEOUT
  if (socket_options_get_option_no_raise (fd, SOCKET_IPPROTO_TCP,
                                          SOCKET_TCP_USER_TIMEOUT, &timeout_ms,
                                          &optlen)
      < 0)
    return 0;
  return timeout_ms;
#else
  (void)fd;
  return 0;
#endif
}

/* ============================================================================
 * SYN FLOOD PROTECTION OPTIONS
 * ============================================================================
 */

/**
 * set_deferaccept_linux - Set TCP_DEFER_ACCEPT on Linux
 * @fd: Socket file descriptor
 * @timeout_sec: Timeout in seconds
 *
 * Raises: Socket_Failed on setsockopt failure
 */
#if SOCKET_HAS_TCP_DEFER_ACCEPT
static void
set_deferaccept_linux (int fd, int timeout_sec)
{
  if (setsockopt (fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_DEFER_ACCEPT,
                  &timeout_sec, sizeof (timeout_sec))
      < 0)
    RAISE_FMT (Socket_Failed,
               "Failed to set TCP_DEFER_ACCEPT (timeout_sec=%d)", timeout_sec);
}
#endif

/**
 * set_acceptfilter_bsd - Set SO_ACCEPTFILTER on BSD/macOS
 * @fd: Socket file descriptor
 * @enable: Non-zero to enable, zero to disable
 *
 * Raises: Socket_Failed on setsockopt failure
 */
#if SOCKET_HAS_SO_ACCEPTFILTER
static void
set_acceptfilter_bsd (int fd, int enable)
{
  struct accept_filter_arg afa;
  memset (&afa, 0, sizeof (afa));

  if (enable)
    {
      strncpy (afa.af_name, "dataready", sizeof (afa.af_name) - 1);
      if (setsockopt (fd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof (afa)) < 0)
        RAISE_FMT (Socket_Failed, "Failed to set SO_ACCEPTFILTER dataready");
    }
  else
    {
      /* Removing filter may fail if none set - ignore EINVAL */
      if (setsockopt (fd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof (afa)) < 0
          && errno != EINVAL)
        RAISE_FMT (Socket_Failed, "Failed to clear SO_ACCEPTFILTER");
    }
}
#endif

void
Socket_setdeferaccept (T socket, int timeout_sec)
{
  assert (socket);

  if (timeout_sec < 0)
    RAISE_MSG (Socket_Failed,
               "Invalid defer accept timeout: %d (must be >= 0)", timeout_sec);
  if (timeout_sec > SOCKET_MAX_DEFER_ACCEPT_SEC)
    {
      RAISE_MSG (Socket_Failed,
                 "Defer accept timeout too large: %d (maximum %d seconds)",
                 timeout_sec, SOCKET_MAX_DEFER_ACCEPT_SEC);
    }

#if SOCKET_HAS_TCP_DEFER_ACCEPT
  set_deferaccept_linux (SocketBase_fd (socket->base), timeout_sec);
#elif SOCKET_HAS_SO_ACCEPTFILTER
  set_acceptfilter_bsd (SocketBase_fd (socket->base), timeout_sec > 0);
#else
  RAISE_MSG (
      Socket_Failed,
      "TCP_DEFER_ACCEPT/SO_ACCEPTFILTER not supported on this platform");
#endif
}

/**
 * get_deferaccept_linux - Get TCP_DEFER_ACCEPT value on Linux
 * @fd: Socket file descriptor
 *
 * Returns: Timeout in seconds
 * Raises: Socket_Failed on getsockopt failure
 */
#if SOCKET_HAS_TCP_DEFER_ACCEPT
static int
get_deferaccept_linux (int fd)
{
  int timeout_sec = 0;

  SocketCommon_getoption_int (fd, SOCKET_IPPROTO_TCP, SOCKET_TCP_DEFER_ACCEPT,
                              &timeout_sec, Socket_Failed);

  return timeout_sec;
}
#endif

/**
 * get_acceptfilter_bsd - Get SO_ACCEPTFILTER status on BSD/macOS
 * @fd: Socket file descriptor
 *
 * Returns: 1 if filter set, 0 if not
 * Raises: Socket_Failed on getsockopt failure (except EINVAL)
 */
#if SOCKET_HAS_SO_ACCEPTFILTER
static int
get_acceptfilter_bsd (int fd)
{
  struct accept_filter_arg afa;
  socklen_t optlen = sizeof (afa);

  memset (&afa, 0, sizeof (afa));

  if (getsockopt (fd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, &optlen) < 0)
    {
      if (errno == EINVAL)
        return 0; /* No filter set */
      RAISE_FMT (Socket_Failed, "Failed to get SO_ACCEPTFILTER");
    }

  return (afa.af_name[0] != '\0') ? 1 : 0;
}
#endif

int
Socket_getdeferaccept (T socket)
{
  assert (socket);

#if SOCKET_HAS_TCP_DEFER_ACCEPT
  return get_deferaccept_linux (SocketBase_fd (socket->base));
#elif SOCKET_HAS_SO_ACCEPTFILTER
  return get_acceptfilter_bsd (SocketBase_fd (socket->base));
#else
  RAISE_MSG (
      Socket_Failed,
      "TCP_DEFER_ACCEPT/SO_ACCEPTFILTER not supported on this platform");
  return 0; /* Unreachable but silences compiler */
#endif
}

#undef T
