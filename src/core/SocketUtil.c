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

/* Flag for one-time CLOCK_MONOTONIC fallback warning */
static volatile int monotonic_fallback_warned = 0;

/**
 * socket_timespec_to_ms - Convert timespec to milliseconds
 * @ts: Pointer to timespec structure
 *
 * Returns: Time in milliseconds
 * Thread-safe: Yes (pure function)
 */
static int64_t
socket_timespec_to_ms (const struct timespec *ts)
{
  return (int64_t)ts->tv_sec * SOCKET_MS_PER_SECOND
         + (int64_t)ts->tv_nsec / SOCKET_NS_PER_MS;
}

/**
 * socket_try_clock - Attempt to get time from specified clock
 * @clock_id: Clock to query (CLOCK_MONOTONIC or CLOCK_REALTIME)
 * @result_ms: Output pointer for result in milliseconds
 *
 * Returns: 1 on success, 0 on failure
 * Thread-safe: Yes
 */
static int
socket_try_clock (clockid_t clock_id, int64_t *result_ms)
{
  struct timespec ts;

  if (clock_gettime (clock_id, &ts) == 0)
    {
      *result_ms = socket_timespec_to_ms (&ts);
      return 1;
    }
  return 0;
}

/**
 * socket_warn_monotonic_fallback - Emit one-time warning for clock fallback
 *
 * Thread-safe: Yes (benign race on flag)
 */
static void
socket_warn_monotonic_fallback (void)
{
  if (!monotonic_fallback_warned)
    {
      monotonic_fallback_warned = 1;
      SocketLog_emit (SOCKET_LOG_WARN, "Socket",
                      "CLOCK_MONOTONIC unavailable, using CLOCK_REALTIME "
                      "(vulnerable to time manipulation)");
    }
}

/**
 * Socket_get_monotonic_ms - Get current monotonic time in milliseconds
 *
 * Returns: Current monotonic time in milliseconds, or 0 on failure
 * Thread-safe: Yes (no shared state modified except one-time warning flag)
 *
 * Uses CLOCK_MONOTONIC with CLOCK_REALTIME fallback. Returns 0 if both
 * clocks fail (should never happen on POSIX systems).
 *
 * Security: CLOCK_REALTIME fallback is vulnerable to time manipulation
 * attacks. A one-time warning is emitted if fallback occurs.
 */
int64_t
Socket_get_monotonic_ms (void)
{
  int64_t result_ms;

  if (socket_try_clock (CLOCK_MONOTONIC, &result_ms))
    return result_ms;

  if (socket_try_clock (CLOCK_REALTIME, &result_ms))
    {
      socket_warn_monotonic_fallback ();
      return result_ms;
    }

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
      snprintf (errbuf, sizeof (errbuf), "No error");
      return errbuf;
    }

#if defined(__GLIBC__) && defined(_GNU_SOURCE)
  /* GNU extension (glibc only): returns char* */
  return strerror_r (errnum, errbuf, sizeof (errbuf));
#else
  /* XSI-compliant (POSIX, macOS, BSD): returns int, 0 on success */
  if (strerror_r (errnum, errbuf, sizeof (errbuf)) != 0)
    snprintf (errbuf, sizeof (errbuf), "Unknown error %d", errnum);
  return errbuf;
#endif
}

/* ===========================================================================
 * LOGGING SUBSYSTEM
 * ===========================================================================*/

/* Mutex protecting callback, userdata, and log level */
static pthread_mutex_t socketlog_mutex = PTHREAD_MUTEX_INITIALIZER;
static SocketLogCallback socketlog_callback = NULL;
static void *socketlog_userdata = NULL;
static SocketLogLevel socketlog_min_level = SOCKET_LOG_INFO;

/* Level names for display */
static const char *const default_level_names[] = {
  "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

/* Timestamp formatting constants - use SocketConfig.h naming */
#define SOCKETLOG_TIMESTAMP_BUFSIZE 32
#define SOCKETLOG_TIMESTAMP_FORMAT "%Y-%m-%d %H:%M:%S"
#define SOCKETLOG_DEFAULT_TIMESTAMP "1970-01-01 00:00:00"

/* Truncation indicator for log messages */
#define SOCKETLOG_TRUNCATION_SUFFIX "..."
#define SOCKETLOG_TRUNCATION_SUFFIX_LEN 4 /* 3 dots + NUL terminator */

/**
 * socketlog_format_timestamp - Format current time as timestamp string
 * @buf: Buffer to write timestamp to
 * @bufsize: Size of buffer
 *
 * Returns: Pointer to buf with formatted timestamp
 * Thread-safe: Yes (uses localtime_r/localtime_s)
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
    {
      strncpy (buf, SOCKETLOG_DEFAULT_TIMESTAMP, bufsize);
      buf[bufsize - 1] = '\0';
    }

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
           SocketLog_levelname (level), component ? component : "(unknown)",
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
 * SocketLog_setlevel - Set minimum log level for filtering
 * @min_level: Minimum level to emit (messages below this are suppressed)
 *
 * Thread-safe: Yes (mutex protected)
 *
 * Sets the global minimum log level. Log messages with severity below
 * min_level will be silently discarded. Default is SOCKET_LOG_INFO.
 */
void
SocketLog_setlevel (SocketLogLevel min_level)
{
  pthread_mutex_lock (&socketlog_mutex);
  socketlog_min_level = min_level;
  pthread_mutex_unlock (&socketlog_mutex);
}

/**
 * SocketLog_getlevel - Get current minimum log level
 *
 * Returns: Current minimum log level
 * Thread-safe: Yes (mutex protected)
 */
SocketLogLevel
SocketLog_getlevel (void)
{
  SocketLogLevel level;

  pthread_mutex_lock (&socketlog_mutex);
  level = socketlog_min_level;
  pthread_mutex_unlock (&socketlog_mutex);

  return level;
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
 * Messages with level below the configured minimum are suppressed.
 */
void
SocketLog_emit (SocketLogLevel level, const char *component,
                const char *message)
{
  void *userdata = NULL;
  SocketLogCallback callback;
  SocketLogLevel min_level;

  /* Read level and callback under single lock to avoid:
   * 1. Double mutex acquisition overhead
   * 2. Race condition between level check and callback retrieval */
  pthread_mutex_lock (&socketlog_mutex);
  min_level = socketlog_min_level;
  callback = socketlog_callback ? socketlog_callback : default_logger;
  userdata = socketlog_userdata;
  pthread_mutex_unlock (&socketlog_mutex);

  /* Early exit if level is below minimum */
  if (level < min_level)
    return;

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
 * socketlog_apply_truncation - Apply truncation indicator to buffer
 * @buffer: Buffer to modify
 * @bufsize: Size of buffer
 *
 * Thread-safe: Yes
 *
 * Appends "..." to indicate message was truncated.
 */
static void
socketlog_apply_truncation (char *buffer, size_t bufsize)
{
  if (bufsize >= SOCKETLOG_TRUNCATION_SUFFIX_LEN)
    {
      size_t start = bufsize - SOCKETLOG_TRUNCATION_SUFFIX_LEN;
      buffer[start] = '.';
      buffer[start + 1] = '.';
      buffer[start + 2] = '.';
      buffer[bufsize - 1] = '\0';
    }
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
 *
 * If the formatted message is truncated, appends "..." indicator.
 */
void
SocketLog_emitfv (SocketLogLevel level, const char *component, const char *fmt,
                  va_list args)
{
  char buffer[SOCKET_LOG_BUFFER_SIZE];
  int written;

  if (!fmt)
    {
      SocketLog_emit (level, component, NULL);
      return;
    }

  written = vsnprintf (buffer, sizeof (buffer), fmt, args);

  if (written >= (int)sizeof (buffer))
    socketlog_apply_truncation (buffer, sizeof (buffer));

  SocketLog_emit (level, component, buffer);
}

/* ===========================================================================
 * LOGGING CONTEXT SUBSYSTEM
 * ===========================================================================*/

/* Thread-local logging context for correlation IDs */
#ifdef _WIN32
static __declspec (thread) SocketLogContext socketlog_context = { "", "", -1 };
static __declspec (thread) int socketlog_context_set = 0;
#else
static __thread SocketLogContext socketlog_context = { "", "", -1 };
static __thread int socketlog_context_set = 0;
#endif

/**
 * SocketLog_setcontext - Set thread-local logging context
 * @ctx: Context to copy (NULL clears context)
 *
 * Thread-safe: Yes (uses thread-local storage)
 *
 * Sets the logging context for the current thread. The context is
 * copied, so the caller may free or modify ctx after this call.
 */
void
SocketLog_setcontext (const SocketLogContext *ctx)
{
  if (ctx == NULL)
    {
      SocketLog_clearcontext ();
      return;
    }

  memcpy (&socketlog_context, ctx, sizeof (SocketLogContext));

  /* Ensure null termination of ID strings */
  socketlog_context.trace_id[SOCKET_LOG_ID_SIZE - 1] = '\0';
  socketlog_context.request_id[SOCKET_LOG_ID_SIZE - 1] = '\0';

  socketlog_context_set = 1;
}

/**
 * SocketLog_getcontext - Get thread-local logging context
 *
 * Returns: Pointer to thread-local context, or NULL if not set
 * Thread-safe: Yes (uses thread-local storage)
 *
 * Returns pointer to internal thread-local storage. Do not modify
 * the returned pointer; use SocketLog_setcontext to update.
 */
const SocketLogContext *
SocketLog_getcontext (void)
{
  if (!socketlog_context_set)
    return NULL;

  return &socketlog_context;
}

/**
 * SocketLog_clearcontext - Clear thread-local logging context
 *
 * Thread-safe: Yes (uses thread-local storage)
 *
 * Clears the logging context for the current thread.
 */
void
SocketLog_clearcontext (void)
{
  memset (&socketlog_context, 0, sizeof (SocketLogContext));
  socketlog_context.connection_fd = -1;
  socketlog_context_set = 0;
}

/* ===========================================================================
 * STRUCTURED LOGGING SUBSYSTEM
 * ===========================================================================*/

/* Structured logging callback and userdata */
static SocketLogStructuredCallback socketlog_structured_callback = NULL;
static void *socketlog_structured_userdata = NULL;

/**
 * SocketLog_setstructuredcallback - Set structured logging callback
 * @callback: Callback function or NULL to disable structured logging
 * @userdata: User data passed to callback
 *
 * Thread-safe: Yes (mutex protected)
 */
void
SocketLog_setstructuredcallback (SocketLogStructuredCallback callback,
                                 void *userdata)
{
  pthread_mutex_lock (&socketlog_mutex);
  socketlog_structured_callback = callback;
  socketlog_structured_userdata = userdata;
  pthread_mutex_unlock (&socketlog_mutex);
}

/**
 * socketlog_format_fields - Format structured fields as key=value string
 * @buffer: Output buffer
 * @bufsize: Buffer size
 * @fields: Array of fields
 * @field_count: Number of fields
 *
 * Returns: Number of characters written (excluding NUL)
 * Thread-safe: Yes
 *
 * Formats fields as " key1=value1 key2=value2" (with leading space).
 */
static size_t
socketlog_format_fields (char *buffer, size_t bufsize,
                         const SocketLogField *fields, size_t field_count)
{
  size_t pos = 0;
  size_t i;

  for (i = 0; i < field_count && pos < bufsize - 1; i++)
    {
      int written;

      if (fields[i].key == NULL || fields[i].value == NULL)
        continue;

      written = snprintf (buffer + pos, bufsize - pos, " %s=%s", fields[i].key,
                          fields[i].value);

      if (written < 0)
        break;

      if ((size_t)written >= bufsize - pos)
        {
          /* Truncated - stop adding fields */
          pos = bufsize - 1;
          break;
        }

      pos += (size_t)written;
    }

  return pos;
}

/**
 * SocketLog_emit_structured - Emit log message with structured fields
 * @level: Log level
 * @component: Component name
 * @message: Log message
 * @fields: Array of key-value pairs (may be NULL)
 * @field_count: Number of fields
 *
 * Thread-safe: Yes
 *
 * Emits a log message with structured key-value pairs. If a structured
 * callback is set, it receives the fields directly. Otherwise, fields
 * are formatted as "key=value" pairs appended to the message.
 */
void
SocketLog_emit_structured (SocketLogLevel level, const char *component,
                           const char *message, const SocketLogField *fields,
                           size_t field_count)
{
  SocketLogStructuredCallback structured_cb;
  void *structured_userdata;
  SocketLogLevel min_level;

  /* Read level and structured callback under single lock to avoid:
   * 1. Double mutex acquisition overhead
   * 2. Race condition between level check and callback retrieval */
  pthread_mutex_lock (&socketlog_mutex);
  min_level = socketlog_min_level;
  structured_cb = socketlog_structured_callback;
  structured_userdata = socketlog_structured_userdata;
  pthread_mutex_unlock (&socketlog_mutex);

  /* Early exit if level is below minimum */
  if (level < min_level)
    return;

  if (structured_cb != NULL)
    {
      /* Use structured callback - provides direct field access */
      structured_cb (structured_userdata, level, component, message, fields,
                     field_count, SocketLog_getcontext ());
    }
  else if (fields != NULL && field_count > 0)
    {
      /* Fallback: format fields as string and use regular logging */
      char buffer[SOCKET_LOG_BUFFER_SIZE];
      size_t msg_len;
      size_t remaining;

      msg_len = message ? strlen (message) : 0;

      if (msg_len >= sizeof (buffer))
        msg_len = sizeof (buffer) - 1;

      if (message)
        memcpy (buffer, message, msg_len);

      remaining = sizeof (buffer) - msg_len;
      socketlog_format_fields (buffer + msg_len, remaining, fields,
                               field_count);

      buffer[sizeof (buffer) - 1] = '\0';
      SocketLog_emit (level, component, buffer);
    }
  else
    {
      /* No fields - use regular emit */
      SocketLog_emit (level, component, message);
    }
}

/* ===========================================================================
 * LEGACY METRICS SUBSYSTEM
 * ===========================================================================
 *
 * NOTE: This is the legacy basic metrics system. For production use, prefer
 * the comprehensive SocketMetrics system in SocketMetrics.h which provides:
 * - Counter, gauge, and histogram metrics
 * - Latency percentile calculations (p50, p95, p99)
 * - Prometheus, StatsD, and JSON export formats
 *
 * This legacy system is kept for backward compatibility with existing code.
 */

/* Mutex protecting metric values */
static pthread_mutex_t socketmetrics_legacy_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Metric values array */
static unsigned long long socketmetrics_legacy_values[SOCKET_METRIC_COUNT] = { 0ULL };

/* Metric names for display/debugging */
static const char *const socketmetrics_legacy_names[SOCKET_METRIC_COUNT] = {
  "socket.connect_success",
  "socket.connect_failure",
  "socket.shutdown_calls",
  "dns.request_submitted",
  "dns.request_completed",
  "dns.request_failed",
  "dns.request_cancelled",
  "dns.request_timeout",
  "poll.wakeups",
  "poll.events_dispatched",
  "pool.connections_added",
  "pool.connections_removed",
  "pool.connections_reused",
  "pool.drain_initiated",
  "pool.drain_completed",
  "pool.health_checks",
  "pool.health_failures",
  "pool.validation_failures",
  "pool.idle_cleanups"
};

/**
 * socketmetrics_legacy_is_valid - Check if metric index is valid
 * @metric: Metric to validate
 *
 * Returns: 1 if valid, 0 otherwise
 * Thread-safe: Yes (pure function)
 */
static int
socketmetrics_legacy_is_valid (SocketMetric metric)
{
  return metric >= 0 && metric < (SocketMetric)SOCKET_METRIC_COUNT;
}

/**
 * SocketMetrics_increment - Increment a legacy metric counter
 * @metric: Metric to increment (from SocketMetric enum)
 * @value: Amount to add to the metric
 *
 * Thread-safe: Yes (mutex protected)
 *
 * NOTE: This is the legacy API. For new code, use SocketMetrics_counter_inc()
 * from SocketMetrics.h.
 */
void
SocketMetrics_increment (SocketMetric metric, unsigned long value)
{
  if (!socketmetrics_legacy_is_valid (metric))
    {
      SocketLog_emitf (SOCKET_LOG_WARN, "SocketMetrics",
                       "Invalid metric %d in increment ignored", (int)metric);
      return;
    }

  pthread_mutex_lock (&socketmetrics_legacy_mutex);
  socketmetrics_legacy_values[metric] += value;
  pthread_mutex_unlock (&socketmetrics_legacy_mutex);
}

/**
 * SocketMetrics_getsnapshot - Get atomic snapshot of legacy metrics
 * @snapshot: Output structure to receive metric values
 *
 * Thread-safe: Yes (mutex protected)
 *
 * NOTE: This is the legacy API. For new code, use SocketMetrics_get()
 * from SocketMetrics.h.
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

  pthread_mutex_lock (&socketmetrics_legacy_mutex);
  memcpy (snapshot->values, socketmetrics_legacy_values, sizeof (socketmetrics_legacy_values));
  pthread_mutex_unlock (&socketmetrics_legacy_mutex);
}

/**
 * SocketMetrics_legacy_reset - Reset legacy metrics to zero
 *
 * Thread-safe: Yes (mutex protected)
 *
 * NOTE: This is the legacy API. For new code, use SocketMetrics_reset()
 * from SocketMetrics.h.
 */
void
SocketMetrics_legacy_reset (void)
{
  pthread_mutex_lock (&socketmetrics_legacy_mutex);
  memset (socketmetrics_legacy_values, 0, sizeof (socketmetrics_legacy_values));
  pthread_mutex_unlock (&socketmetrics_legacy_mutex);
}

/**
 * SocketMetrics_name - Get human-readable name for a legacy metric
 * @metric: Metric to get name for
 *
 * Returns: Static string with metric name, or "unknown" for invalid metrics
 * Thread-safe: Yes (returns static data)
 */
const char *
SocketMetrics_name (SocketMetric metric)
{
  if (!socketmetrics_legacy_is_valid (metric))
    return "unknown";
  return socketmetrics_legacy_names[metric];
}

/**
 * SocketMetrics_count - Get total number of legacy metrics
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
socketevent_find_handler_unlocked (SocketEventCallback callback,
                                   const void *userdata)
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
 * socketevent_can_register_unlocked - Check if registration is possible
 * @callback: Callback to register
 * @userdata: User data for callback
 *
 * Returns: 1 if can register, 0 if duplicate or limit reached
 * Thread-safe: No (caller must hold socketevent_mutex)
 *
 * Logs warnings for duplicate or limit-reached conditions.
 */
static int
socketevent_can_register_unlocked (SocketEventCallback callback,
                                   const void *userdata)
{
  if (socketevent_find_handler_unlocked (callback, userdata) >= 0)
    return 0;

  if (socketevent_handler_count >= SOCKET_EVENT_MAX_HANDLERS)
    {
      SocketLog_emit (SOCKET_LOG_WARN, "SocketEvents",
                      "Handler limit reached; ignoring registration");
      return 0;
    }

  return 1;
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

  if (socketevent_can_register_unlocked (callback, userdata))
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
SocketEvent_unregister (SocketEventCallback callback, const void *userdata)
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
