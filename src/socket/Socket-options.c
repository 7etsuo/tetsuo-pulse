/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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

/* Internal helper prototypes */
static int socket_get_tcp_int_quiet (int fd, int optname, int *out);
static int socket_get_tcp_uint_quiet (int fd, int optname, unsigned int *out);
static int socket_get_tcp_string_quiet (int fd, int optname, char *buf, size_t buflen);
static int socket_getbuf_size (T socket, int optname);
static void socket_setbuf_size (T socket, int optname, int size, const char *buf_type);

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

/**
 * Socket_setreuseport - Enable SO_REUSEPORT socket option
 * @socket: Socket instance
 *
 * Allows multiple sockets to bind to the same port for load balancing.
 * Available on Linux 3.9+ and BSD systems.
 *
 * Raises: Socket_Failed on setsockopt failure or unsupported platform
 * Thread-safe: Yes
 */
void
Socket_setreuseport (T socket)
{
  assert (socket);
  SocketCommon_setreuseport (socket->base, Socket_Failed);
}

/**
 * Socket_setcloexec - Set close-on-exec flag for socket
 * @socket: Socket instance
 * @enable: Non-zero to enable, zero to disable
 *
 * Controls whether the socket file descriptor is closed automatically
 * when the process calls exec(). Prevents fd leaks to child processes.
 *
 * Raises: Socket_Failed on fcntl failure
 * Thread-safe: Yes
 */
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

/**
 * Socket_gettimeout - Get socket I/O timeout
 * @socket: Socket instance
 *
 * Retrieves the current receive timeout (SO_RCVTIMEO) in seconds.
 *
 * Returns: Timeout in seconds (0 = infinite)
 * Raises: Socket_Failed on getsockopt failure
 * Thread-safe: Yes
 */
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

/**
 * Socket_timeouts_get - Get socket timeout configuration
 * @socket: Socket instance
 * @timeouts: Output parameter for timeout configuration
 *
 * Retrieves the current timeout configuration (connect, DNS, operation)
 * from the socket instance.
 *
 * Thread-safe: Yes (reads immutable after set)
 */
void
Socket_timeouts_get (const T socket, SocketTimeouts_T *timeouts)
{
  assert (socket);
  assert (timeouts);

  *timeouts = socket->base->timeouts;
}

/**
 * Socket_timeouts_set - Set socket timeout configuration
 * @socket: Socket instance
 * @timeouts: Timeout configuration to apply (NULL = reset to defaults)
 *
 * Configures the timeout values for connect, DNS, and operation phases.
 * If timeouts is NULL, resets to global default values. All timeout
 * values are sanitized (negative values treated as 0 = infinite).
 *
 * Thread-safe: Yes (mutex-protected default access)
 */
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

/**
 * Socket_timeouts_getdefaults - Get global default timeout configuration
 * @timeouts: Output parameter for default timeout values
 *
 * Retrieves the global default timeout configuration used for new sockets.
 *
 * Thread-safe: Yes
 */
void
Socket_timeouts_getdefaults (SocketTimeouts_T *timeouts)
{
  SocketCommon_timeouts_getdefaults (timeouts);
}

/**
 * Socket_timeouts_setdefaults - Set global default timeout configuration
 * @timeouts: Timeout configuration to set as global defaults
 *
 * Updates the global default timeout configuration that will be applied
 * to newly created sockets.
 *
 * Thread-safe: Yes (internally synchronized)
 */
void
Socket_timeouts_setdefaults (const SocketTimeouts_T *timeouts)
{
  SocketCommon_timeouts_setdefaults (timeouts);
}

/**
 * Socket_timeouts_set_extended - Set extended per-phase timeout configuration
 * @socket: Socket instance
 * @extended: Extended timeout configuration with per-phase values
 *
 * Configures granular timeouts for specific operation phases (DNS, connect,
 * TLS, operation). Non-zero values override the corresponding basic timeout.
 * The tls_timeout_ms falls back to operation_timeout_ms if not explicitly set.
 * Note: request_timeout_ms is handled at the HTTP client level, not here.
 *
 * Thread-safe: No (caller must ensure exclusive access)
 */
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
}

/**
 * Socket_timeouts_get_extended - Get extended per-phase timeout configuration
 * @socket: Socket instance
 * @extended: Output parameter for extended timeout values
 *
 * Retrieves the current timeout configuration in extended format with
 * per-phase breakdown. The tls_timeout_ms is derived from operation_timeout_ms.
 * request_timeout_ms is always 0 (handled at HTTP client level).
 *
 * Thread-safe: Yes (reads immutable after set)
 */
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


void
Socket_shutdown (T socket, int how)
{
  assert (socket);

  if (how != SOCKET_SHUT_RD && how != SOCKET_SHUT_WR && how != SOCKET_SHUT_RDWR)
    RAISE_MSG (Socket_Failed, "Invalid shutdown mode %d: must be SHUT_RD (0), SHUT_WR (1), or SHUT_RDWR (2)", how);

  if (shutdown (SocketBase_fd (socket->base), how) < 0)
    RAISE_FMT (Socket_Failed, "shutdown failed on fd %d (how=%d): %s", SocketBase_fd (socket->base), how, Socket_safe_strerror(errno));
}

/* ============================================================================
 * KEEPALIVE OPERATIONS
 * ============================================================================
 */

/**
 * socket_get_option_quiet - Get socket option without raising exception
 * @fd: File descriptor
 * @level: Option level (e.g., SOCKET_SOL_SOCKET, SOCKET_IPPROTO_TCP)
 * @optname: Option name (e.g., SOCKET_TCP_FASTOPEN)
 * @optval: Output buffer for option value
 * @optlen: Input/output length of optval
 *
 * Wrapper around getsockopt(2) that returns success/failure without
 * raising exceptions. Used for optional platform-specific options where
 * failure is acceptable (e.g., querying TCP_FASTOPEN on unsupported systems).
 *
 * Returns: 0 on success, -1 on failure (errno set)
 * Thread-safe: Yes
 */
static int
socket_get_option_quiet (int fd, int level, int optname, void *optval,
                         socklen_t *optlen)
{
  assert (fd >= 0);
  assert (optval);
  assert (optlen);

  return getsockopt (fd, level, optname, optval, optlen) == 0 ? 0 : -1;
}

/**
 * socket_get_tcp_int_quiet - Get TCP integer option quietly
 * @fd: File descriptor
 * @optname: Option name (e.g. TCP_NODELAY)
 * @out: Pointer to output int
 *
 * Performs getsockopt for TCP option, initializes *out to 0.
 * Returns 0 on success, -1 on failure (errno set).
 */
static int
socket_get_tcp_int_quiet (int fd, int optname, int *out)
{
  socklen_t len = sizeof (*out);
  *out = 0;
  return socket_get_option_quiet (fd, SOCKET_IPPROTO_TCP, optname, out, &len);
}

/**
 * socket_get_tcp_uint_quiet - Get TCP unsigned int option quietly
 * @fd: File descriptor
 * @optname: Option name (e.g. TCP_USER_TIMEOUT)
 * @out: Pointer to output unsigned int
 *
 * Similar to socket_get_tcp_int_quiet for unsigned values.
 */
static int
socket_get_tcp_uint_quiet (int fd, int optname, unsigned int *out)
{
  socklen_t len = sizeof (*out);
  *out = 0;
  return socket_get_option_quiet (fd, SOCKET_IPPROTO_TCP, optname, out, &len);
}

/**
 * socket_get_tcp_string_quiet - Get TCP string option quietly
 * @fd: File descriptor
 * @optname: Option name (e.g. TCP_CONGESTION)
 * @buf: Output buffer
 * @buflen: Size of buffer (including space for null terminator)
 *
 * Performs getsockopt into buf, null-terminates, checks for truncation.
 * Returns 0 on success, -1 on failure.
 */
static int
socket_get_tcp_string_quiet (int fd, int optname, char *buf, size_t buflen)
{
  assert (fd >= 0);
  assert (buf);
  assert (buflen > 0);
  socklen_t len = (socklen_t) buflen;
  if (socket_get_option_quiet (fd, SOCKET_IPPROTO_TCP, optname, buf, &len) < 0)
    return -1;
  if (len > (socklen_t) buflen) {
    errno = EMSGSIZE;
    return -1;
  }
  buf[buflen - 1] = '\0';
  return 0;
}


void
Socket_setkeepalive (T socket, int idle, int interval, int count)
{
  assert (socket);
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
  SocketCommon_set_option_int (socket->base, SOCKET_SOL_SOCKET,
                               SOCKET_SO_KEEPALIVE, 1, Socket_Failed);
#ifdef TCP_KEEPIDLE
  SocketCommon_set_option_int (socket->base, SOCKET_IPPROTO_TCP,
                               SOCKET_TCP_KEEPIDLE, idle, Socket_Failed);
#endif
#ifdef TCP_KEEPINTVL
  SocketCommon_set_option_int (socket->base, SOCKET_IPPROTO_TCP,
                               SOCKET_TCP_KEEPINTVL, interval, Socket_Failed);
#endif
#ifdef TCP_KEEPCNT
  SocketCommon_set_option_int (socket->base, SOCKET_IPPROTO_TCP,
                               SOCKET_TCP_KEEPCNT, count, Socket_Failed);
#endif
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

/**
 * Socket_setnodelay - Enable or disable TCP_NODELAY (Nagle's algorithm)
 * @socket: Socket instance
 * @nodelay: Non-zero to disable Nagle (enable nodelay), zero to enable Nagle
 *
 * Disabling Nagle's algorithm (nodelay=1) reduces latency for small packets
 * at the cost of potentially higher bandwidth usage. Recommended for
 * interactive or real-time protocols.
 *
 * Raises: Socket_Failed on setsockopt failure
 * Thread-safe: Yes
 */
void
Socket_setnodelay (T socket, int nodelay)
{
  assert (socket);
  int val = (nodelay != 0) ? 1 : 0;
  SocketCommon_set_option_int (socket->base, SOCKET_IPPROTO_TCP,
                               SOCKET_TCP_NODELAY, val, Socket_Failed);
}

/**
 * Socket_getnodelay - Get TCP_NODELAY setting
 * @socket: Socket instance
 *
 * Returns: Non-zero if TCP_NODELAY is enabled, 0 if disabled
 * Raises: Socket_Failed on getsockopt failure
 * Thread-safe: Yes
 */
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
  assert (socket);
  assert (algorithm);
  assert (len > 0);

#if SOCKET_HAS_TCP_CONGESTION
  int fd = SocketBase_fd (socket->base);
  return socket_get_tcp_string_quiet (fd, SOCKET_TCP_CONGESTION, algorithm, len);
#else
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
  socket_setbuf_size (socket, SOCKET_SO_RCVBUF, size, "receive");
}

void
Socket_setsndbuf (T socket, int size)
{
  socket_setbuf_size (socket, SOCKET_SO_SNDBUF, size, "send");
}

int
Socket_getrcvbuf (T socket)
{
  return socket_getbuf_size (socket, SOCKET_SO_RCVBUF);
}

int
Socket_getsndbuf (T socket)
{
  return socket_getbuf_size (socket, SOCKET_SO_SNDBUF);
}

/**
 * socket_getbuf_size - Get socket buffer size option
 * @socket: Socket instance
 * @optname: SO_RCVBUF or SO_SNDBUF
 *
 * Uses SocketCommon_getoption_int, raises Socket_Failed on error.
 */
static int
socket_getbuf_size (T socket, int optname)
{
  assert (socket);
  int fd = SocketBase_fd (socket->base);
  int bufsize = 0;
  SocketCommon_getoption_int (fd, SOCKET_SOL_SOCKET, optname, &bufsize, Socket_Failed);
  return bufsize;
}

/**
 * socket_setbuf_size - Set socket buffer size option
 * @socket: Socket instance
 * @optname: SO_RCVBUF or SO_SNDBUF
 * @size: Buffer size
 * @buf_type: "receive" or "send" for error message
 *
 * Validates size, sets option, raises on invalid or failure.
 */
static void
socket_setbuf_size (T socket, int optname, int size, const char *buf_type)
{
  assert (socket);
  assert (size > 0);
  if (!SOCKET_VALID_BUFFER_SIZE ((size_t)size))
    {
      RAISE_FMT (Socket_Failed,
                 "Invalid %s buffer size %d (min=%zu, max=%zu)",
                 buf_type, size,
                 (size_t)SOCKET_MIN_BUFFER_SIZE, (size_t)SOCKET_MAX_BUFFER_SIZE);
    }
  SocketCommon_set_option_int (socket->base, SOCKET_SOL_SOCKET, optname, size, Socket_Failed);
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
  assert (socket);

#if SOCKET_HAS_TCP_FASTOPEN
  int fd = SocketBase_fd (socket->base);
  int opt;
  if (socket_get_tcp_int_quiet (fd, SOCKET_TCP_FASTOPEN, &opt) < 0)
    return -1;
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
  assert (socket);

#if SOCKET_HAS_TCP_USER_TIMEOUT
  int fd = SocketBase_fd (socket->base);
  unsigned int timeout_ms;
  if (socket_get_tcp_uint_quiet (fd, SOCKET_TCP_USER_TIMEOUT, &timeout_ms) < 0)
    return 0;
  return timeout_ms;
#else
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
