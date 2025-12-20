/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketUtil.c - Core utility subsystems
 *
 * Part of the Socket Library
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
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <time.h>

#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include "core/SocketMetrics.h"

/* ===========================================================================
 * TIME UTILITIES SUBSYSTEM
 * ===========================================================================*/

/* Flag for one-time CLOCK_MONOTONIC fallback warning */
static volatile int monotonic_fallback_warned = 0;

/**
 * SOCKET_MONOTONIC_STRICT - Fail instead of falling back to CLOCK_REALTIME
 *
 * When 1, Socket_get_monotonic_ms() returns 0 if no monotonic clock is
 * available, instead of falling back to CLOCK_REALTIME.
 *
 * Security: CLOCK_REALTIME can be manipulated by attackers with system
 * access, potentially bypassing time-based security controls like rate
 * limiting and SYN flood protection.
 *
 * Default: 0 (allow fallback for compatibility)
 */
#ifndef SOCKET_MONOTONIC_STRICT
#define SOCKET_MONOTONIC_STRICT 0
#endif

/**
 * Preferred monotonic clock sources in priority order.
 *
 * These clocks are immune to system time adjustments (NTP, manual changes):
 * - CLOCK_MONOTONIC_RAW: Unaffected by NTP adjustments (Linux 2.6.28+)
 * - CLOCK_MONOTONIC: Standard monotonic, may have NTP slewing
 * - CLOCK_BOOTTIME: Includes suspend time (Linux 2.6.39+)
 * - CLOCK_UPTIME_RAW: Like MONOTONIC_RAW but stops during sleep (macOS)
 */
static const clockid_t preferred_clocks[] = {
#ifdef CLOCK_MONOTONIC_RAW
  CLOCK_MONOTONIC_RAW,
#endif
  CLOCK_MONOTONIC,
#ifdef CLOCK_BOOTTIME
  CLOCK_BOOTTIME,
#endif
#ifdef CLOCK_UPTIME_RAW
  CLOCK_UPTIME_RAW,
#endif
};

#define PREFERRED_CLOCKS_COUNT                                                \
  (sizeof (preferred_clocks) / sizeof (preferred_clocks[0]))

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
 * Tries multiple monotonic clock sources in priority order:
 * 1. CLOCK_MONOTONIC_RAW (Linux, immune to NTP)
 * 2. CLOCK_MONOTONIC (standard, may have NTP slewing)
 * 3. CLOCK_BOOTTIME (Linux, includes suspend time)
 * 4. CLOCK_UPTIME_RAW (macOS)
 *
 * Falls back to CLOCK_REALTIME only if all monotonic clocks fail and
 * SOCKET_MONOTONIC_STRICT is 0 (default).
 *
 * Security: CLOCK_REALTIME fallback is vulnerable to time manipulation
 * attacks. A one-time warning is emitted if fallback occurs. Set
 * SOCKET_MONOTONIC_STRICT=1 to disable fallback in security-critical
 * deployments.
 */
int64_t
Socket_get_monotonic_ms (void)
{
  int64_t result_ms;
  size_t i;

  /* Try all preferred monotonic clocks first */
  for (i = 0; i < PREFERRED_CLOCKS_COUNT; i++)
    {
      if (socket_try_clock (preferred_clocks[i], &result_ms))
        return result_ms;
    }

#if SOCKET_MONOTONIC_STRICT
  /* Strict mode: fail instead of using CLOCK_REALTIME */
  SocketLog_emit (SOCKET_LOG_ERROR, "Socket",
                  "No monotonic clock available and SOCKET_MONOTONIC_STRICT "
                  "is enabled");
  return 0;
#else
  /* Fallback to CLOCK_REALTIME with security warning */
  if (socket_try_clock (CLOCK_REALTIME, &result_ms))
    {
      socket_warn_monotonic_fallback ();
      return result_ms;
    }

  return 0;
#endif
}

/* ===========================================================================
 * ERROR MAPPING TABLE
 * ===========================================================================*/

/**
 * SocketErrorMapping - Comprehensive errno to error info mapping
 *
 * Single source of truth for errno classification across all error functions.
 * Data-driven approach eliminates code duplication in switch statements.
 */
typedef struct SocketErrorMapping
{
  int err;
  SocketErrorCode code;
  SocketErrorCategory category;
  int retryable;
} SocketErrorMapping;

static const SocketErrorMapping error_mappings[] = {
  { 0, SOCKET_ERROR_NONE, SOCKET_ERROR_CATEGORY_UNKNOWN, 0 },
  { EINVAL, SOCKET_ERROR_EINVAL, SOCKET_ERROR_CATEGORY_PROTOCOL, 0 },
  { EACCES, SOCKET_ERROR_EACCES, SOCKET_ERROR_CATEGORY_APPLICATION, 0 },
  { EADDRINUSE, SOCKET_ERROR_EADDRINUSE, SOCKET_ERROR_CATEGORY_APPLICATION,
    0 },
  { EADDRNOTAVAIL, SOCKET_ERROR_EADDRNOTAVAIL,
    SOCKET_ERROR_CATEGORY_APPLICATION, 0 },
  { EAFNOSUPPORT, SOCKET_ERROR_EAFNOSUPPORT, SOCKET_ERROR_CATEGORY_PROTOCOL,
    0 },
  { EAGAIN, SOCKET_ERROR_EAGAIN, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
#ifdef EWOULDBLOCK
  { EWOULDBLOCK, SOCKET_ERROR_EWOULDBLOCK, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
#endif
  { EALREADY, SOCKET_ERROR_EALREADY, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
  { EBADF, SOCKET_ERROR_EBADF, SOCKET_ERROR_CATEGORY_PROTOCOL, 0 },
  { ECONNREFUSED, SOCKET_ERROR_ECONNREFUSED, SOCKET_ERROR_CATEGORY_NETWORK,
    1 },
  { ECONNRESET, SOCKET_ERROR_ECONNRESET, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
  { EFAULT, SOCKET_ERROR_EFAULT, SOCKET_ERROR_CATEGORY_PROTOCOL, 0 },
  { EHOSTUNREACH, SOCKET_ERROR_EHOSTUNREACH, SOCKET_ERROR_CATEGORY_NETWORK,
    1 },
  { EINPROGRESS, SOCKET_ERROR_EINPROGRESS, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
  { EINTR, SOCKET_ERROR_EINTR, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
  { EISCONN, SOCKET_ERROR_EISCONN, SOCKET_ERROR_CATEGORY_PROTOCOL, 0 },
  { EMFILE, SOCKET_ERROR_EMFILE, SOCKET_ERROR_CATEGORY_RESOURCE, 0 },
  { ENETUNREACH, SOCKET_ERROR_ENETUNREACH, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
  { ENOBUFS, SOCKET_ERROR_ENOBUFS, SOCKET_ERROR_CATEGORY_RESOURCE, 0 },
  { ENOMEM, SOCKET_ERROR_ENOMEM, SOCKET_ERROR_CATEGORY_RESOURCE, 0 },
  { ENOTCONN, SOCKET_ERROR_ENOTCONN, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
  { ENOTSOCK, SOCKET_ERROR_ENOTSOCK, SOCKET_ERROR_CATEGORY_PROTOCOL, 0 },
  { EOPNOTSUPP, SOCKET_ERROR_EOPNOTSUPP, SOCKET_ERROR_CATEGORY_PROTOCOL, 0 },
  { EPIPE, SOCKET_ERROR_EPIPE, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
  { EPROTONOSUPPORT, SOCKET_ERROR_EPROTONOSUPPORT,
    SOCKET_ERROR_CATEGORY_PROTOCOL, 0 },
  { ETIMEDOUT, SOCKET_ERROR_ETIMEDOUT, SOCKET_ERROR_CATEGORY_TIMEOUT, 1 },
  /* Additional errnos from categorize and retryable functions */
  { ECONNABORTED, SOCKET_ERROR_UNKNOWN, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
#ifdef ENETDOWN
  { ENETDOWN, SOCKET_ERROR_UNKNOWN, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
#endif
#ifdef ENETRESET
  { ENETRESET, SOCKET_ERROR_UNKNOWN, SOCKET_ERROR_CATEGORY_NETWORK, 1 },
#endif
  { ENFILE, SOCKET_ERROR_UNKNOWN, SOCKET_ERROR_CATEGORY_RESOURCE, 0 },
#ifdef ENOSPC
  { ENOSPC, SOCKET_ERROR_UNKNOWN, SOCKET_ERROR_CATEGORY_RESOURCE, 0 },
#endif
#ifdef EPROTO
  { EPROTO, SOCKET_ERROR_UNKNOWN, SOCKET_ERROR_CATEGORY_PROTOCOL, 0 },
#endif
  { EPERM, SOCKET_ERROR_UNKNOWN, SOCKET_ERROR_CATEGORY_APPLICATION, 0 },
};

/** Number of entries in error_mappings table */
#define NUM_ERROR_MAPPINGS                                                    \
  (sizeof (error_mappings) / sizeof (error_mappings[0]))

/** Number of entries in category names table (defined below) */
#define NUM_ERROR_CATEGORIES 6

/** Number of entries in log level names table (defined below) */
#define NUM_LOG_LEVELS 6

/**
 * socket_find_error_mapping - Find error mapping entry for given errno
 * @err: errno value to look up
 *
 * Returns: Pointer to mapping entry if found, NULL otherwise
 * Thread-safe: Yes (pure function, const data)
 * Complexity: O(n) linear scan of ~30 entries - acceptable for small table
 */
static const SocketErrorMapping *
socket_find_error_mapping (const int err)
{
  for (size_t i = 0; i < NUM_ERROR_MAPPINGS; i++)
    {
      if (error_mappings[i].err == err)
        {
          return &error_mappings[i];
        }
    }
  return NULL;
}

/* ===========================================================================
 * ERROR HANDLING SUBSYSTEM
 * ===========================================================================*/

/**
 * socket_errno_to_errorcode - Map errno value to SocketErrorCode via table
 * lookup
 * @errno_val: errno value to map
 *
 * Returns: Corresponding SocketErrorCode enum value from error_mappings table
 * Thread-safe: Yes (pure function, const data)
 *
 * Table-driven mapping of POSIX errno to SocketErrorCode using centralized
 * error_mappings table. Unknown errnos map to SOCKET_ERROR_UNKNOWN.
 */
static SocketErrorCode
socket_errno_to_errorcode (int errno_val)
{
  const SocketErrorMapping *m = socket_find_error_mapping (errno_val);
  return m ? m->code : SOCKET_ERROR_UNKNOWN;
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
 * ERROR CATEGORIZATION SUBSYSTEM
 * ===========================================================================*/

/* Category names for display (indexed by SocketErrorCategory) */
static const char *const socket_error_category_names[] = {
  "NETWORK", "PROTOCOL", "APPLICATION", "TIMEOUT", "RESOURCE", "UNKNOWN"
};

/* Uses NUM_ERROR_CATEGORIES defined above for bounds checking */

/**
 * SocketError_categorize_errno - Categorize errno using centralized table
 * @err: errno value to categorize
 *
 * Returns: SocketErrorCategory from error_mappings table or UNKNOWN
 * Thread-safe: Yes (pure function, const data)
 *
 * Table-driven categorization using error_mappings. Covers all previously
 * switch-mapped errnos plus additional ones for completeness.
 */
SocketErrorCategory
SocketError_categorize_errno (int err)
{
  const SocketErrorMapping *m = socket_find_error_mapping (err);
  return m ? m->category : SOCKET_ERROR_CATEGORY_UNKNOWN;
}

/**
 * SocketError_category_name - Get string name for error category
 * @category: Error category
 *
 * Returns: Static string with category name
 * Thread-safe: Yes (returns static data)
 */
const char *
SocketError_category_name (SocketErrorCategory category)
{
  if (category < 0 || (size_t)category >= NUM_ERROR_CATEGORIES)
    return "UNKNOWN";
  return socket_error_category_names[category];
}

/**
 * SocketError_is_retryable_errno - Check if errno is retryable using table
 * @err: errno value to check
 *
 * Returns: 1 if retryable per error_mappings table, 0 otherwise
 * Thread-safe: Yes (pure function, const data)
 *
 * Table-driven retryability check using centralized error_mappings.
 * Unknown errnos default to non-retryable for safety.
 */
int
SocketError_is_retryable_errno (int err)
{
  const SocketErrorMapping *m = socket_find_error_mapping (err);
  return m ? m->retryable : 0;
}

/* ===========================================================================
 * LOGGING SUBSYSTEM
 * ===========================================================================*/

/* Mutex protecting callback, userdata, and log level */
static pthread_mutex_t socketlog_mutex = PTHREAD_MUTEX_INITIALIZER;
static SocketLogCallback socketlog_callback = NULL;
static void *socketlog_userdata = NULL;
static SocketLogLevel socketlog_min_level = SOCKET_LOG_INFO;

static SocketLogStructuredCallback socketlog_structured_callback = NULL;
static void *socketlog_structured_userdata = NULL;

/* Level names for display (indexed by SocketLogLevel) */
static const char *const default_level_names[]
    = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL" };

/* Uses NUM_LOG_LEVELS defined in error mapping section for bounds checking */

/* Timestamp formatting constants - defined in SocketConfig.h */

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
      || strftime (buf, bufsize, SOCKET_LOG_TIMESTAMP_FORMAT, &tm_buf) == 0)
    {
      strncpy (buf, SOCKET_LOG_DEFAULT_TIMESTAMP, bufsize);
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
  char ts[SOCKET_LOG_TIMESTAMP_BUFSIZE];

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
  if (level < 0 || (size_t)level >= NUM_LOG_LEVELS)
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
 * SocketLogAllInfo - All logging configuration info acquired under single lock
 *
 * Contains fallback and structured callbacks/userdata plus should_log flag.
 * Used internally to consolidate mutex acquisitions across logging subsystems.
 */
typedef struct SocketLogAllInfo
{
  SocketLogCallback fallback_callback;
  void *fallback_userdata;
  SocketLogStructuredCallback structured_callback;
  void *structured_userdata;
  int should_log;
} SocketLogAllInfo;

/* SocketLogCallbackInfo removed - use SocketLogAllInfo instead for
 * consolidated callback acquisition */

/**
 * socketlog_acquire_all_info - Acquire all logging configuration under mutex
 *
 * @level: Log level to check against minimum for should_log
 *
 * Returns: Structure containing all protected log state
 * Thread-safe: Yes (mutex protected)
 *
 * Copies all logging callbacks, userdata, and computes should_log under
 * single mutex acquisition to minimize lock contention.
 */
static SocketLogAllInfo
socketlog_acquire_all_info (SocketLogLevel level)
{
  SocketLogAllInfo info;

  pthread_mutex_lock (&socketlog_mutex);
  info.should_log = (level >= socketlog_min_level);
  info.fallback_callback
      = socketlog_callback ? socketlog_callback : default_logger;
  info.fallback_userdata = socketlog_userdata;
  info.structured_callback = socketlog_structured_callback;
  info.structured_userdata = socketlog_structured_userdata;
  pthread_mutex_unlock (&socketlog_mutex);

  return info;
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
  SocketLogAllInfo all = socketlog_acquire_all_info (level);
  if (!all.should_log)
    return;

  all.fallback_callback (all.fallback_userdata, level, component, message);
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
 * Uses memcpy for efficiency instead of character-by-character assignment.
 */
static void
socketlog_apply_truncation (char *buffer, size_t bufsize)
{
  if (bufsize >= SOCKET_LOG_TRUNCATION_SUFFIX_LEN + 1)
    {
      size_t start = bufsize - SOCKET_LOG_TRUNCATION_SUFFIX_LEN - 1;
      memcpy (buffer + start, SOCKET_LOG_TRUNCATION_SUFFIX,
              SOCKET_LOG_TRUNCATION_SUFFIX_LEN + 1);
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

/* SocketLogStructuredInfo removed - use SocketLogAllInfo which includes
 * structured fields */

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
 * socketlog_append_field_if_space - Append single field if space available
 * @buffer: Output buffer
 * @pos: Current position in buffer (updated on success)
 * @bufsize: Total buffer size
 * @field: Field to append
 *
 * Returns: 1 on success, 0 if truncated or null field, -1 on snprintf error
 * Thread-safe: Yes (pure function)
 *
 * Appends " key=value" if field valid and space available. Updates pos on
 * success.
 */
static int
socketlog_append_field_if_space (char *buffer, size_t *pos, size_t bufsize,
                                 const SocketLogField *field)
{
  if (field->key == NULL || field->value == NULL)
    return 0;

  size_t remaining = bufsize - *pos;
  int written = snprintf (buffer + *pos, remaining, " %s=%s", field->key,
                          field->value);

  if (written < 0)
    return -1;

  if ((size_t)written >= remaining)
    {
      *pos = bufsize - 1; /* Indicate truncation */
      return 0;
    }

  *pos += (size_t)written;
  return 1;
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
 * Uses socketlog_append_field_if_space for modular field appending.
 */
static size_t
socketlog_format_fields (char *buffer, size_t bufsize,
                         const SocketLogField *fields, size_t field_count)
{
  size_t pos = 0;
  size_t i;

  for (i = 0; i < field_count && pos < bufsize - 1; i++)
    {
      int res = socketlog_append_field_if_space (buffer, &pos, bufsize,
                                                 &fields[i]);
      if (res < 0)
        break; /* snprintf error */
      if (res == 0)
        break; /* null field or truncated */
    }

  return pos;
}

/**
 * socketlog_call_structured - Invoke structured logging callback
 * @all: All info structure
 * @level: Log level
 * @component: Component name
 * @message: Log message
 * @fields: Structured fields
 * @field_count: Number of fields
 *
 * Thread-safe: Yes (delegates to callback)
 */
static void
socketlog_call_structured (const SocketLogAllInfo *all, SocketLogLevel level,
                           const char *component, const char *message,
                           const SocketLogField *fields, size_t field_count)
{
  all->structured_callback (all->structured_userdata, level, component,
                            message, fields, field_count,
                            SocketLog_getcontext ());
}

/**
 * socketlog_call_fallback - Invoke fallback logging callback
 * @all: All info structure
 * @level: Log level
 * @component: Component name
 * @message: Log message
 *
 * Thread-safe: Yes (delegates to callback)
 */
static void
socketlog_call_fallback (const SocketLogAllInfo *all, SocketLogLevel level,
                         const char *component, const char *message)
{
  all->fallback_callback (all->fallback_userdata, level, component, message);
}

/**
 * socketlog_format_and_call_fallback - Format fields and invoke fallback
 * callback
 * @all: All info structure
 * @level: Log level
 * @component: Component name
 * @message: Original log message
 * @fields: Structured fields to format
 * @field_count: Number of fields
 *
 * Formats fields as " key=value" appended to message copy, then calls
 * fallback. Thread-safe: Yes
 */
static void
socketlog_format_and_call_fallback (const SocketLogAllInfo *all,
                                    SocketLogLevel level,
                                    const char *component, const char *message,
                                    const SocketLogField *fields,
                                    size_t field_count)
{
  char buffer[SOCKET_LOG_BUFFER_SIZE];
  size_t msg_len = message ? strlen (message) : 0;
  size_t remaining;

  if (msg_len >= sizeof (buffer))
    msg_len = sizeof (buffer) - 1;

  if (message)
    memcpy (buffer, message, msg_len);

  /* Null-terminate after message to ensure valid string even if no fields
   * are written. This fixes potential uninitialized buffer when message is
   * NULL and all fields have NULL key/value. */
  buffer[msg_len] = '\0';

  remaining = sizeof (buffer) - msg_len;
  socketlog_format_fields (buffer + msg_len, remaining, fields, field_count);

  /* Safety fallback: ensure final null-termination */
  buffer[sizeof (buffer) - 1] = '\0';
  socketlog_call_fallback (all, level, component, buffer);
}

/**
 * socketlog_emit_structured_with_all - Emit structured log using all info
 * @all: Acquired all logging info
 * @level: Log level
 * @component: Component name
 * @message: Log message
 * @fields: Structured fields (may be NULL)
 * @field_count: Number of fields
 *
 * Thread-safe: Yes
 *
 * Dispatches to structured callback if available, otherwise formats fields
 * into fallback message or uses message directly.
 */
static void
socketlog_emit_structured_with_all (const SocketLogAllInfo *all,
                                    SocketLogLevel level,
                                    const char *component, const char *message,
                                    const SocketLogField *fields,
                                    size_t field_count)
{
  if (all->structured_callback != NULL)
    {
      socketlog_call_structured (all, level, component, message, fields,
                                 field_count);
    }
  else if (fields != NULL && field_count > 0)
    {
      socketlog_format_and_call_fallback (all, level, component, message,
                                          fields, field_count);
    }
  else
    {
      socketlog_call_fallback (all, level, component, message);
    }
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
  SocketLogAllInfo all = socketlog_acquire_all_info (level);
  if (!all.should_log)
    return;

  socketlog_emit_structured_with_all (&all, level, component, message, fields,
                                      field_count);
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

/* ===========================================================================
 * LEGACY TO NEW METRICS MAPPING
 * ===========================================================================
 */
static const SocketCounterMetric legacy_to_counter[SOCKET_METRIC_COUNT] = {
    [SOCKET_METRIC_SOCKET_CONNECT_SUCCESS] = SOCKET_CTR_SOCKET_CONNECT_SUCCESS,
    [SOCKET_METRIC_SOCKET_CONNECT_FAILURE] = SOCKET_CTR_SOCKET_CONNECT_FAILED,
    [SOCKET_METRIC_SOCKET_SHUTDOWN_CALL] = SOCKET_CTR_SOCKET_CLOSED, /* approximate */
    [SOCKET_METRIC_DNS_REQUEST_SUBMITTED] = SOCKET_CTR_DNS_QUERIES_TOTAL,
    [SOCKET_METRIC_DNS_REQUEST_COMPLETED] = SOCKET_CTR_DNS_QUERIES_COMPLETED,
    [SOCKET_METRIC_DNS_REQUEST_FAILED] = SOCKET_CTR_DNS_QUERIES_FAILED,
    [SOCKET_METRIC_DNS_REQUEST_CANCELLED] = SOCKET_CTR_DNS_QUERIES_CANCELLED,
    [SOCKET_METRIC_DNS_REQUEST_TIMEOUT] = SOCKET_CTR_DNS_QUERIES_TIMEOUT,
    [SOCKET_METRIC_POLL_WAKEUPS] = SOCKET_CTR_POLL_WAKEUPS,
    [SOCKET_METRIC_POLL_EVENTS_DISPATCHED] = SOCKET_CTR_POLL_EVENTS_DISPATCHED,
    [SOCKET_METRIC_POOL_CONNECTIONS_ADDED] = SOCKET_CTR_POOL_CONNECTIONS_CREATED,
    [SOCKET_METRIC_POOL_CONNECTIONS_REMOVED] = SOCKET_CTR_POOL_CONNECTIONS_DESTROYED,
    [SOCKET_METRIC_POOL_CONNECTIONS_REUSED] = SOCKET_CTR_POOL_CONNECTIONS_REUSED,
    [SOCKET_METRIC_POOL_DRAIN_INITIATED] = SOCKET_CTR_POOL_DRAIN_STARTED,
    [SOCKET_METRIC_POOL_DRAIN_COMPLETED] = SOCKET_CTR_POOL_DRAIN_COMPLETED,
    [SOCKET_METRIC_POOL_HEALTH_CHECKS] = (SocketCounterMetric)-1, /* unmapped, add if needed */
    [SOCKET_METRIC_POOL_HEALTH_FAILURES] = (SocketCounterMetric)-1,
    [SOCKET_METRIC_POOL_VALIDATION_FAILURES] = (SocketCounterMetric)-1,
    [SOCKET_METRIC_POOL_IDLE_CLEANUPS] = (SocketCounterMetric)-1,
};

/* No mutex needed - new system handles thread safety */

/* No local storage - forwards to new SocketMetrics system */

/* Metric names for display/debugging */
static const char *const socketmetrics_legacy_names[SOCKET_METRIC_COUNT]
    = { "socket.connect_success",
        "socket.connect_failure",
        "socket.shutdown_calls",
        "dns.request_submitted",
        "dns.request_completed",
        "dns.request_failed",
        "dns.request_cancelled",
        "dns.request_timeout",
        "dns.cache_hit",
        "dns.cache_miss",
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
        "pool.idle_cleanups" };

/**
 * socketmetrics_legacy_is_valid - Check if metric index is valid
 * @metric: Metric to validate
 *
 * Returns: 1 if valid, 0 otherwise
 * Thread-safe: Yes (pure function, no shared state)
 */
static inline int
socketmetrics_legacy_is_valid (const SocketMetric metric)
{
  return metric >= 0 && metric < SOCKET_METRIC_COUNT;
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

  SocketCounterMetric new_metric = legacy_to_counter[metric];
  if (new_metric != (SocketCounterMetric)-1) {
    SocketMetrics_counter_add (new_metric, (uint64_t)value);
  } else {
    SocketLog_emitf (SOCKET_LOG_WARN, "SocketMetrics",
                     "Unmapped legacy metric %s (%d) ignored; consider migrating to new API",
                     socketmetrics_legacy_names[metric], (int)metric);
    // Legacy behavior preserved if needed by adding mapping
  }
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
  int i;
  if (snapshot == NULL)
    {
      SocketLog_emit (SOCKET_LOG_WARN, "SocketMetrics",
                      "NULL snapshot in getsnapshot ignored");
      return;
    }

  for (i = 0; i < SOCKET_METRIC_COUNT; i++)
    {
      SocketCounterMetric new_metric = legacy_to_counter[i];
      if (new_metric != (SocketCounterMetric)-1)
        {
          snapshot->values[i] = SocketMetrics_counter_get (new_metric);
        }
      else
        {
          snapshot->values[i] = 0ULL;  /* Unmapped legacy metrics return 0 */
        }
    }
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
  /* Legacy reset forwards to new system reset_counters (resets all counters) */
  SocketMetrics_reset_counters ();
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

  SocketCounterMetric new_metric = legacy_to_counter[metric];
  if (new_metric != (SocketCounterMetric)-1)
    return SocketMetrics_counter_name (new_metric);
  else
    return socketmetrics_legacy_names[metric];  /* Keep legacy name for unmapped */
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
 * @handlers: Array of handlers to invoke (const - not modified)
 * @count: Number of handlers
 * @event: Event to pass to callbacks
 *
 * Thread-safe: Yes (no mutex needed - operates on local copy)
 */
static void
socketevent_invoke_handlers (const SocketEventHandler *handlers, size_t count,
                             const SocketEventRecord *event)
{
  size_t i;

  for (i = 0; i < count; i++)
    {
      if (handlers[i].callback != NULL)
        handlers[i].callback (handlers[i].userdata, event);
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
 * @callback: Callback to find (must not be NULL)
 * @userdata: User data to match (may be NULL)
 *
 * Returns: Index of handler if found, -1 otherwise
 * Thread-safe: No (caller must hold socketevent_mutex)
 */
static ssize_t
socketevent_find_handler_unlocked (const SocketEventCallback callback,
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
