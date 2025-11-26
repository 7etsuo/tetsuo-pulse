/**
 * SocketUtil.c - Core utility subsystems
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This file consolidates the core utility and observability modules:
 * - Error handling (thread-local error buffers, errno mapping)
 * - Logging subsystem (configurable callbacks, multiple log levels)
 * - Metrics collection (thread-safe counters, atomic snapshots)
 * - Event dispatching (connection events, DNS timeouts, poll wakeups)
 *
 * FEATURES:
 * - Thread-local error message storage with errno capture
 * - Configurable log callback with default stderr/stdout output
 * - Thread-safe metrics with atomic snapshot capability
 * - Event notification system for socket library operations
 * - Multiple log levels (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)
 *
 * THREAD SAFETY:
 * - Error handling: Uses thread-local storage (no mutex needed)
 * - Logging: Callback get/set operations are mutex protected
 * - Metrics: All operations are mutex protected
 * - Events: Handler registration is mutex protected; callbacks invoked outside
 */

#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "core/SocketConfig.h"
#include "core/SocketUtil.h"

/* ===========================================================================
 * TIME UTILITIES SUBSYSTEM
 * ===========================================================================*/

/**
 * socket_time_try_monotonic - Try to get monotonic clock time
 * @ts: Output timespec structure
 *
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Yes (no shared state)
 */
static int
socket_time_try_monotonic (struct timespec *ts)
{
  return clock_gettime (CLOCK_MONOTONIC, ts);
}

/**
 * socket_time_try_realtime - Fallback to realtime clock
 * @ts: Output timespec structure
 *
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Yes (no shared state)
 */
static int
socket_time_try_realtime (struct timespec *ts)
{
  return clock_gettime (CLOCK_REALTIME, ts);
}

/**
 * socket_time_to_ms - Convert timespec to milliseconds
 * @ts: Timespec to convert
 *
 * Returns: Time in milliseconds
 * Thread-safe: Yes (pure function)
 */
static int64_t
socket_time_to_ms (const struct timespec *ts)
{
  return (int64_t)ts->tv_sec * SOCKET_MS_PER_SECOND
         + (int64_t)ts->tv_nsec / SOCKET_NS_PER_MS;
}

/**
 * Socket_get_monotonic_ms - Get current monotonic time in milliseconds
 *
 * Returns: Current monotonic time in milliseconds, or 0 on failure
 * Thread-safe: Yes (no shared state)
 *
 * Uses CLOCK_MONOTONIC with CLOCK_REALTIME fallback. Returns 0 if both
 * clocks fail (should never happen on POSIX systems).
 */
int64_t
Socket_get_monotonic_ms (void)
{
  struct timespec ts;

  if (socket_time_try_monotonic (&ts) == 0)
    return socket_time_to_ms (&ts);

  if (socket_time_try_realtime (&ts) == 0)
    return socket_time_to_ms (&ts);

  return 0;
}

/* ===========================================================================
 * ERROR HANDLING SUBSYSTEM
 * ===========================================================================*/

/**
 * socket_errno_to_errorcode - Map errno value to SocketErrorCode
 * @errno_val: errno value to map
 *
 * Returns: Corresponding SocketErrorCode enum value
 * Thread-safe: Yes (pure function)
 *
 * Maps common POSIX errno values to structured SocketErrorCode values
 * for programmatic error handling.
 */
static SocketErrorCode
socket_errno_to_errorcode (int errno_val)
{
  switch (errno_val)
    {
    case 0:
      return SOCKET_ERROR_NONE;
    case EINVAL:
      return SOCKET_ERROR_EINVAL;
    case EACCES:
      return SOCKET_ERROR_EACCES;
    case EADDRINUSE:
      return SOCKET_ERROR_EADDRINUSE;
    case EADDRNOTAVAIL:
      return SOCKET_ERROR_EADDRNOTAVAIL;
    case EAFNOSUPPORT:
      return SOCKET_ERROR_EAFNOSUPPORT;
    case EAGAIN:
      return SOCKET_ERROR_EAGAIN;
#if EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
      return SOCKET_ERROR_EWOULDBLOCK;
#endif
    case EALREADY:
      return SOCKET_ERROR_EALREADY;
    case EBADF:
      return SOCKET_ERROR_EBADF;
    case ECONNREFUSED:
      return SOCKET_ERROR_ECONNREFUSED;
    case ECONNRESET:
      return SOCKET_ERROR_ECONNRESET;
    case EFAULT:
      return SOCKET_ERROR_EFAULT;
    case EHOSTUNREACH:
      return SOCKET_ERROR_EHOSTUNREACH;
    case EINPROGRESS:
      return SOCKET_ERROR_EINPROGRESS;
    case EINTR:
      return SOCKET_ERROR_EINTR;
    case EISCONN:
      return SOCKET_ERROR_EISCONN;
    case EMFILE:
      return SOCKET_ERROR_EMFILE;
    case ENETUNREACH:
      return SOCKET_ERROR_ENETUNREACH;
    case ENOBUFS:
      return SOCKET_ERROR_ENOBUFS;
    case ENOMEM:
      return SOCKET_ERROR_ENOMEM;
    case ENOTCONN:
      return SOCKET_ERROR_ENOTCONN;
    case ENOTSOCK:
      return SOCKET_ERROR_ENOTSOCK;
    case EOPNOTSUPP:
      return SOCKET_ERROR_EOPNOTSUPP;
    case EPIPE:
      return SOCKET_ERROR_EPIPE;
    case EPROTONOSUPPORT:
      return SOCKET_ERROR_EPROTONOSUPPORT;
    case ETIMEDOUT:
      return SOCKET_ERROR_ETIMEDOUT;
    default:
      return SOCKET_ERROR_UNKNOWN;
    }
}

/* Thread-local error buffer for detailed error messages */
#ifdef _WIN32
__declspec (thread) char socket_error_buf[SOCKET_ERROR_BUFSIZE] = { 0 };
__declspec (thread) int socket_last_errno = 0;
#else
__thread char socket_error_buf[SOCKET_ERROR_BUFSIZE] = { 0 };
__thread int socket_last_errno = 0;
#endif

/**
 * Socket_GetLastError - Get the last error message
 *
 * Returns: Pointer to thread-local error message buffer
 * Thread-safe: Yes (returns thread-local data)
 *
 * Returns the most recent error message set by SOCKET_ERROR_FMT or
 * SOCKET_ERROR_MSG macros.
 */
const char *
Socket_GetLastError (void)
{
  return socket_error_buf;
}

/**
 * Socket_geterrno - Get the last captured errno value
 *
 * Returns: Last errno value captured by error macros (0 if no error)
 * Thread-safe: Yes (uses thread-local storage)
 *
 * Returns the errno value that was captured when the last error message
 * was formatted.
 */
int
Socket_geterrno (void)
{
  return socket_last_errno;
}

/**
 * Socket_geterrorcode - Get the last error as a SocketErrorCode enum
 *
 * Returns: SocketErrorCode enum value corresponding to last captured errno
 * Thread-safe: Yes (uses thread-local storage)
 *
 * Converts the last captured errno to a structured SocketErrorCode
 * for programmatic error handling.
 */
SocketErrorCode
Socket_geterrorcode (void)
{
  return socket_errno_to_errorcode (socket_last_errno);
}

/**
 * Socket_safe_strerror - Thread-safe strerror implementation
 * @errnum: Error number to convert
 *
 * Returns: Pointer to thread-local string describing the error
 * Thread-safe: Yes (uses thread-local buffer and strerror_r)
 *
 * Provides a thread-safe alternative to strerror() which is not
 * guaranteed to be thread-safe on all platforms.
 */
const char *
Socket_safe_strerror (int errnum)
{
  static __thread char errbuf[SOCKET_STRERROR_BUFSIZE] = { 0 };

  if (errnum == 0)
    {
      strcpy (errbuf, "No error");
      return errbuf;
    }

#ifdef _GNU_SOURCE
  /* GNU extension: returns char* */
  return strerror_r (errnum, errbuf, sizeof (errbuf));
#else
  /* POSIX: returns int, 0 on success */
  if (strerror_r (errnum, errbuf, sizeof (errbuf)) != 0)
    strcpy (errbuf, "Unknown error");
  return errbuf;
#endif
}

/* ===========================================================================
 * LOGGING SUBSYSTEM
 * ===========================================================================*/

/* Mutex protecting callback and userdata */
static pthread_mutex_t socketlog_mutex = PTHREAD_MUTEX_INITIALIZER;
static SocketLogCallback socketlog_callback = NULL;
static void *socketlog_userdata = NULL;

/* Level names for display */
static const char *default_level_names[]
    = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL" };

/* Timestamp formatting constants */
#define SOCKETLOG_DEFAULT_TIMESTAMP "1970-01-01 00:00:00"
#define SOCKETLOG_TIMESTAMP_FORMAT "%Y-%m-%d %H:%M:%S"
#define SOCKETLOG_TIMESTAMP_BUFSIZE 32

/**
 * socketlog_format_timestamp - Format current time as timestamp string
 * @buf: Buffer to write timestamp to
 * @bufsize: Size of buffer
 *
 * Returns: Pointer to buf with formatted timestamp
 * Thread-safe: Yes
 *
 * Uses localtime_r/localtime_s for thread-safe time conversion.
 * Falls back to default timestamp on failure.
 */
static const char *
socketlog_format_timestamp (char *buf, size_t bufsize)
{
  time_t raw;
  struct tm tm_buf;
  int time_ok = 0;

  raw = time (NULL);

#ifdef _WIN32
  time_ok = (localtime_s (&tm_buf, &raw) == 0);
#else
  time_ok = (localtime_r (&raw, &tm_buf) != NULL);
#endif

  if (!time_ok
      || strftime (buf, bufsize, SOCKETLOG_TIMESTAMP_FORMAT, &tm_buf) == 0)
    strncpy (buf, SOCKETLOG_DEFAULT_TIMESTAMP, bufsize);

  return buf;
}

/**
 * socketlog_get_stream - Get appropriate output stream for log level
 * @level: Log level
 *
 * Returns: stderr for ERROR/FATAL, stdout otherwise
 * Thread-safe: Yes
 */
static FILE *
socketlog_get_stream (SocketLogLevel level)
{
  return level >= SOCKET_LOG_ERROR ? stderr : stdout;
}

/**
 * default_logger - Default logging implementation
 * @userdata: User data (unused)
 * @level: Log level
 * @component: Component name
 * @message: Log message
 *
 * Thread-safe: Yes
 *
 * Writes formatted log messages to stdout (INFO and below) or stderr
 * (WARN and above) with timestamp, level, and component prefix.
 */
static void
default_logger (void *userdata, SocketLogLevel level, const char *component,
                const char *message)
{
  char ts[SOCKETLOG_TIMESTAMP_BUFSIZE];

  (void)userdata;

  fprintf (socketlog_get_stream (level), "%s [%s] %s: %s\n",
           socketlog_format_timestamp (ts, sizeof (ts)),
           SocketLog_levelname (level),
           component ? component : "(unknown)",
           message ? message : "(null)");
}

/**
 * SocketLog_setcallback - Set custom logging callback
 * @callback: Callback function or NULL for default logger
 * @userdata: User data passed to callback
 *
 * Thread-safe: Yes (mutex protected)
 *
 * Replaces the current logging callback. Pass NULL to restore default.
 */
void
SocketLog_setcallback (SocketLogCallback callback, void *userdata)
{
  pthread_mutex_lock (&socketlog_mutex);
  socketlog_callback = callback;
  socketlog_userdata = userdata;
  pthread_mutex_unlock (&socketlog_mutex);
}

/**
 * SocketLog_getcallback - Get current logging callback
 * @userdata: Output pointer for user data (may be NULL)
 *
 * Returns: Current callback, or default_logger if none set
 * Thread-safe: Yes (mutex protected)
 */
SocketLogCallback
SocketLog_getcallback (void **userdata)
{
  SocketLogCallback callback;

  pthread_mutex_lock (&socketlog_mutex);
  callback = socketlog_callback ? socketlog_callback : default_logger;
  if (userdata)
    *userdata = socketlog_userdata;
  pthread_mutex_unlock (&socketlog_mutex);

  return callback;
}

/**
 * SocketLog_levelname - Get string name for log level
 * @level: Log level
 *
 * Returns: Static string with level name
 * Thread-safe: Yes (returns static data)
 */
const char *
SocketLog_levelname (SocketLogLevel level)
{
  if (level < SOCKET_LOG_TRACE || level > SOCKET_LOG_FATAL)
    return "UNKNOWN";
  return default_level_names[level];
}

/**
 * SocketLog_emit - Emit a log message
 * @level: Log level
 * @component: Component name (may be NULL)
 * @message: Log message (may be NULL)
 *
 * Thread-safe: Yes
 *
 * Invokes the current logging callback with the provided message.
 */
void
SocketLog_emit (SocketLogLevel level, const char *component,
                const char *message)
{
  void *userdata = NULL;
  SocketLogCallback callback = SocketLog_getcallback (&userdata);

  callback (userdata, level, component, message);
}

/**
 * SocketLog_emitf - Emit formatted log message
 * @level: Log level
 * @component: Component name
 * @fmt: Printf-style format string
 * @...: Format arguments
 *
 * Thread-safe: Yes
 *
 * WARNING: fmt must be a compile-time literal to prevent format string
 * attacks. Do not use user-controlled format strings.
 */
void
SocketLog_emitf (SocketLogLevel level, const char *component, const char *fmt,
                 ...)
{
  va_list args;

  va_start (args, fmt);
  SocketLog_emitfv (level, component, fmt, args);
  va_end (args);
}

/**
 * SocketLog_emitfv - Emit formatted log message with va_list
 * @level: Log level
 * @component: Component name
 * @fmt: Printf-style format string
 * @args: Format arguments as va_list
 *
 * Thread-safe: Yes
 *
 * WARNING: fmt must be a compile-time literal to prevent format string
 * attacks. Do not use user-controlled format strings.
 */
void
SocketLog_emitfv (SocketLogLevel level, const char *component, const char *fmt,
                  va_list args)
{
  char buffer[SOCKET_LOG_BUFFER_SIZE];

  if (!fmt)
    {
      SocketLog_emit (level, component, NULL);
      return;
    }

  vsnprintf (buffer, sizeof (buffer), fmt, args);
  SocketLog_emit (level, component, buffer);
}

/* ===========================================================================
 * METRICS SUBSYSTEM
 * ===========================================================================*/

/* Mutex protecting metric values */
static pthread_mutex_t socketmetrics_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Metric values array */
static unsigned long long socketmetrics_values[SOCKET_METRIC_COUNT] = { 0ULL };

/* Metric names for display/debugging */
static const char *socketmetrics_names[SOCKET_METRIC_COUNT]
    = { "socket.connect_success", "socket.connect_failure",
        "socket.shutdown_calls",  "dns.request_submitted",
        "dns.request_completed",  "dns.request_failed",
        "dns.request_cancelled",  "dns.request_timeout",
        "poll.wakeups",           "poll.events_dispatched",
        "pool.connections_added", "pool.connections_removed",
        "pool.connections_reused" };

/**
 * SocketMetrics_increment - Increment a metric counter
 * @metric: Metric to increment (from SocketMetric enum)
 * @value: Amount to add to the metric
 *
 * Thread-safe: Yes (mutex protected)
 *
 * Increments the specified metric by the given value. Invalid metric
 * indices are logged and ignored.
 */
void
SocketMetrics_increment (SocketMetric metric, unsigned long value)
{
  if (metric < 0 || metric >= (SocketMetric)SOCKET_METRIC_COUNT)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, "SocketMetrics",
                       "Invalid metric %d in increment ignored", (int)metric);
      return;
    }

  pthread_mutex_lock (&socketmetrics_mutex);
  socketmetrics_values[metric] += value;
  pthread_mutex_unlock (&socketmetrics_mutex);
}

/**
 * SocketMetrics_getsnapshot - Get atomic snapshot of all metrics
 * @snapshot: Output structure to receive metric values
 *
 * Thread-safe: Yes (mutex protected)
 *
 * Copies all current metric values atomically to the provided snapshot
 * structure. NULL snapshots are logged and ignored.
 */
void
SocketMetrics_getsnapshot (SocketMetricsSnapshot *snapshot)
{
  if (snapshot == NULL)
    {
      SocketLog_emit (SOCKET_LOG_WARN, "SocketMetrics",
                      "NULL snapshot in getsnapshot ignored");
      return;
    }

  pthread_mutex_lock (&socketmetrics_mutex);
  memcpy (snapshot->values, socketmetrics_values,
          sizeof (socketmetrics_values));
  pthread_mutex_unlock (&socketmetrics_mutex);
}

/**
 * SocketMetrics_reset - Reset all metrics to zero
 *
 * Thread-safe: Yes (mutex protected)
 *
 * Clears all metric values. Useful for testing or periodic resets.
 */
void
SocketMetrics_reset (void)
{
  pthread_mutex_lock (&socketmetrics_mutex);
  memset (socketmetrics_values, 0, sizeof (socketmetrics_values));
  pthread_mutex_unlock (&socketmetrics_mutex);
}

/**
 * SocketMetrics_name - Get human-readable name for a metric
 * @metric: Metric to get name for
 *
 * Returns: Static string with metric name, or "unknown" for invalid metrics
 * Thread-safe: Yes (returns static data)
 */
const char *
SocketMetrics_name (SocketMetric metric)
{
  if (metric < 0 || metric >= SOCKET_METRIC_COUNT)
    return "unknown";
  return socketmetrics_names[metric];
}

/**
 * SocketMetrics_count - Get total number of defined metrics
 *
 * Returns: Number of metrics in the SocketMetric enum
 * Thread-safe: Yes (returns constant)
 */
size_t
SocketMetrics_count (void)
{
  return SOCKET_METRIC_COUNT;
}

/* ===========================================================================
 * EVENTS SUBSYSTEM
 * ===========================================================================*/

/**
 * SocketEventHandler - Internal handler registration structure
 */
typedef struct SocketEventHandler
{
  SocketEventCallback callback;
  void *userdata;
} SocketEventHandler;

/* Mutex protecting handler array */
static pthread_mutex_t socketevent_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Registered handlers */
static SocketEventHandler socketevent_handlers[SOCKET_EVENT_MAX_HANDLERS];
static size_t socketevent_handler_count = 0;

/**
 * socketevent_copy_handlers_unlocked - Copy handlers (caller holds mutex)
 * @local_handlers: Destination array for handler copies
 *
 * Returns: Number of handlers copied
 * Thread-safe: No (caller must hold socketevent_mutex)
 */
static size_t
socketevent_copy_handlers_unlocked (SocketEventHandler *local_handlers)
{
  memcpy (local_handlers, socketevent_handlers,
          sizeof (SocketEventHandler) * socketevent_handler_count);
  return socketevent_handler_count;
}

/**
 * socketevent_invoke_handlers - Invoke all handler callbacks
 * @local_handlers: Array of handlers to invoke
 * @count: Number of handlers
 * @event: Event to pass to callbacks
 *
 * Thread-safe: Yes (no mutex needed - operates on local copy)
 */
static void
socketevent_invoke_handlers (const SocketEventHandler *local_handlers,
                             size_t count, const SocketEventRecord *event)
{
  size_t i;

  for (i = 0; i < count; i++)
    {
      if (local_handlers[i].callback)
        local_handlers[i].callback (local_handlers[i].userdata, event);
    }
}

/**
 * socketevent_dispatch - Dispatch event to all registered handlers
 * @event: Event record to dispatch
 *
 * Thread-safe: Yes
 *
 * Copies handlers under mutex, then invokes each callback outside mutex
 * to prevent deadlocks. Callbacks must not block indefinitely.
 */
static void
socketevent_dispatch (const SocketEventRecord *event)
{
  SocketEventHandler local_handlers[SOCKET_EVENT_MAX_HANDLERS];
  size_t count;

  assert (event);

  pthread_mutex_lock (&socketevent_mutex);
  count = socketevent_copy_handlers_unlocked (local_handlers);
  pthread_mutex_unlock (&socketevent_mutex);

  socketevent_invoke_handlers (local_handlers, count, event);
}

/**
 * socketevent_find_handler_unlocked - Find handler in array (mutex held)
 * @callback: Callback to find
 * @userdata: User data to match
 *
 * Returns: Index of handler if found, -1 otherwise
 * Thread-safe: No (caller must hold socketevent_mutex)
 */
static ssize_t
socketevent_find_handler_unlocked (SocketEventCallback callback, void *userdata)
{
  size_t i;

  for (i = 0; i < socketevent_handler_count; i++)
    {
      if (socketevent_handlers[i].callback == callback
          && socketevent_handlers[i].userdata == userdata)
        return (ssize_t)i;
    }
  return -1;
}

/**
 * socketevent_add_handler_unlocked - Add handler to array (mutex held)
 * @callback: Callback to add
 * @userdata: User data for callback
 *
 * Thread-safe: No (caller must hold socketevent_mutex)
 */
static void
socketevent_add_handler_unlocked (SocketEventCallback callback, void *userdata)
{
  socketevent_handlers[socketevent_handler_count].callback = callback;
  socketevent_handlers[socketevent_handler_count].userdata = userdata;
  socketevent_handler_count++;
}

/**
 * SocketEvent_register - Register an event handler
 * @callback: Callback function to register
 * @userdata: User data passed to callback
 *
 * Thread-safe: Yes (mutex protected)
 *
 * Registers a callback to receive socket events. Duplicate registrations
 * (same callback and userdata) are silently ignored. If the handler limit
 * is reached, the registration is logged and ignored.
 */
void
SocketEvent_register (SocketEventCallback callback, void *userdata)
{
  if (callback == NULL)
    {
      SocketLog_emit (SOCKET_LOG_WARN, "SocketEvents",
                      "NULL callback in register ignored");
      return;
    }

  pthread_mutex_lock (&socketevent_mutex);

  if (socketevent_find_handler_unlocked (callback, userdata) >= 0)
    {
      pthread_mutex_unlock (&socketevent_mutex);
      return;
    }

  if (socketevent_handler_count >= SOCKET_EVENT_MAX_HANDLERS)
    {
      pthread_mutex_unlock (&socketevent_mutex);
      SocketLog_emit (SOCKET_LOG_WARN, "SocketEvents",
                      "Handler limit reached; ignoring registration");
      return;
    }

  socketevent_add_handler_unlocked (callback, userdata);
  pthread_mutex_unlock (&socketevent_mutex);
}

/**
 * socketevent_remove_at_index_unlocked - Remove handler at index (mutex held)
 * @index: Index of handler to remove
 *
 * Thread-safe: No (caller must hold socketevent_mutex)
 */
static void
socketevent_remove_at_index_unlocked (size_t index)
{
  size_t remaining = socketevent_handler_count - index - 1;

  if (remaining > 0)
    {
      memmove (&socketevent_handlers[index], &socketevent_handlers[index + 1],
               remaining * sizeof (SocketEventHandler));
    }
  socketevent_handler_count--;
}

/**
 * SocketEvent_unregister - Unregister an event handler
 * @callback: Callback function to unregister
 * @userdata: User data that was passed to register
 *
 * Thread-safe: Yes (mutex protected)
 *
 * Removes a previously registered handler. Both callback and userdata
 * must match. If not found, the call is silently ignored.
 */
void
SocketEvent_unregister (SocketEventCallback callback, void *userdata)
{
  ssize_t idx;

  if (callback == NULL)
    {
      SocketLog_emit (SOCKET_LOG_WARN, "SocketEvents",
                      "NULL callback in unregister ignored");
      return;
    }

  pthread_mutex_lock (&socketevent_mutex);

  idx = socketevent_find_handler_unlocked (callback, userdata);
  if (idx >= 0)
    socketevent_remove_at_index_unlocked ((size_t)idx);

  pthread_mutex_unlock (&socketevent_mutex);
}

/**
 * socketevent_init_connection - Initialize connection event record
 * @event: Event record to initialize
 * @type: Event type (ACCEPTED or CONNECTED)
 * @component: Component name
 * @fd: File descriptor
 * @peer_addr: Peer IP address string
 * @peer_port: Peer port number
 * @local_addr: Local IP address string
 * @local_port: Local port number
 *
 * Thread-safe: Yes
 *
 * Helper to eliminate duplication in emit_accept and emit_connect.
 */
static void
socketevent_init_connection (SocketEventRecord *event, SocketEventType type,
                             const char *component, int fd,
                             const char *peer_addr, int peer_port,
                             const char *local_addr, int local_port)
{
  event->type = type;
  event->component = component;
  event->data.connection.fd = fd;
  event->data.connection.peer_addr = peer_addr;
  event->data.connection.peer_port = peer_port;
  event->data.connection.local_addr = local_addr;
  event->data.connection.local_port = local_port;
}

/**
 * SocketEvent_emit_accept - Emit connection accepted event
 * @fd: File descriptor of accepted socket
 * @peer_addr: Peer IP address string
 * @peer_port: Peer port number
 * @local_addr: Local IP address string
 * @local_port: Local port number
 *
 * Thread-safe: Yes
 */
void
SocketEvent_emit_accept (int fd, const char *peer_addr, int peer_port,
                         const char *local_addr, int local_port)
{
  SocketEventRecord event;

  socketevent_init_connection (&event, SOCKET_EVENT_ACCEPTED, "Socket", fd,
                               peer_addr, peer_port, local_addr, local_port);
  socketevent_dispatch (&event);
}

/**
 * SocketEvent_emit_connect - Emit connection established event
 * @fd: File descriptor of connected socket
 * @peer_addr: Peer IP address string
 * @peer_port: Peer port number
 * @local_addr: Local IP address string
 * @local_port: Local port number
 *
 * Thread-safe: Yes
 */
void
SocketEvent_emit_connect (int fd, const char *peer_addr, int peer_port,
                          const char *local_addr, int local_port)
{
  SocketEventRecord event;

  socketevent_init_connection (&event, SOCKET_EVENT_CONNECTED, "Socket", fd,
                               peer_addr, peer_port, local_addr, local_port);
  socketevent_dispatch (&event);
}

/**
 * SocketEvent_emit_dns_timeout - Emit DNS resolution timeout event
 * @host: Hostname that timed out
 * @port: Port number being resolved
 *
 * Thread-safe: Yes
 */
void
SocketEvent_emit_dns_timeout (const char *host, int port)
{
  SocketEventRecord event;

  event.type = SOCKET_EVENT_DNS_TIMEOUT;
  event.component = "SocketDNS";
  event.data.dns.host = host;
  event.data.dns.port = port;

  socketevent_dispatch (&event);
}

/**
 * SocketEvent_emit_poll_wakeup - Emit poll wakeup event
 * @nfds: Number of file descriptors with events
 * @timeout_ms: Timeout that was used for poll
 *
 * Thread-safe: Yes
 */
void
SocketEvent_emit_poll_wakeup (int nfds, int timeout_ms)
{
  SocketEventRecord event;

  event.type = SOCKET_EVENT_POLL_WAKEUP;
  event.component = "SocketPoll";
  event.data.poll.nfds = nfds;
  event.data.poll.timeout_ms = timeout_ms;

  socketevent_dispatch (&event);
}
