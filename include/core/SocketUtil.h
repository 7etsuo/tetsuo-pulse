/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_INCLUDED
#define SOCKETUTIL_INCLUDED

/**
 * @file SocketUtil.h
 * @ingroup foundation
 * @brief Consolidated utility header for logging, metrics, events, and error
 * handling.
 *
 * This header consolidates the observability, instrumentation, and error
 * handling utilities into a single include for cleaner dependencies.
 *
 * Provides:
 * - Logging subsystem (configurable callbacks, multiple log levels)
 * - Metrics collection (thread-safe counters, atomic snapshots)
 * - Event dispatching (connection events, DNS timeouts, poll wakeups)
 * - Error handling (thread-local buffers, errno mapping, exception macros)
 * - Hash functions (golden ratio, DJB2 variants for various use cases)
 * - Timeout utilities (monotonic clock timing, deadline calculations)
 *
 * @see SocketLogLevel for logging API.
 * @see SocketMetrics for metrics collection.
 * @see SocketError for error handling utilities.
 * @see @ref foundation for other core utilities.
 * @see @ref core_io for socket modules that use these utilities.
 */

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"

/* ============================================================================
 * LOGGING SUBSYSTEM
 * ============================================================================
 */

/**
 * @brief Log severity levels.
 * @ingroup foundation
 */
typedef enum SocketLogLevel
{
  SOCKET_LOG_TRACE = 0,
  SOCKET_LOG_DEBUG,
  SOCKET_LOG_INFO,
  SOCKET_LOG_WARN,
  SOCKET_LOG_ERROR,
  SOCKET_LOG_FATAL
} SocketLogLevel;

/**
 * @brief Custom logging callback function type.
 * @ingroup foundation
 * @param userdata User-provided context.
 * @param level Log severity level.
 * @param component Module/component name.
 * @param message Log message.
 * @see SocketLog_setcallback() for registration.
 */
typedef void (*SocketLogCallback) (void *userdata, SocketLogLevel level,
                                   const char *component, const char *message);

/**
 * @brief Register a custom callback for all library log emissions.
 * @ingroup foundation
 *
 * @param callback Callback function or NULL for default logger.
 * @param userdata Opaque user data passed to callback.
 *
 * Overrides default stdout/stderr logging. Callback invoked synchronously
 * from emitting thread after level filtering. Keep callbacks non-blocking.
 *
 * @threadsafe Yes
 */
void SocketLog_setcallback (SocketLogCallback callback, void *userdata);

/**
 * @brief Retrieve the currently registered logging callback and userdata.
 * @ingroup foundation
 *
 * @param userdata Output for userdata (may be NULL).
 * @return Current SocketLogCallback, or internal default if none registered.
 *
 * @threadsafe Yes
 */
SocketLogCallback SocketLog_getcallback (void **userdata);

/**
 * @brief Get human-readable string for a log level.
 * @ingroup foundation
 *
 * @param level Log level enum value.
 * @return Static string ("TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL").
 *
 * @threadsafe Yes
 */
const char *SocketLog_levelname (SocketLogLevel level);

/**
 * @brief Emit a plain log message.
 * @ingroup foundation
 *
 * @param level Log severity level.
 * @param component Module name (may be NULL).
 * @param message Log message (may be NULL).
 *
 * @threadsafe Yes
 */
void SocketLog_emit (SocketLogLevel level, const char *component,
                     const char *message);

/**
 * @brief Emit a formatted log message (printf-style).
 * @ingroup foundation
 *
 * @param level Log level.
 * @param component Component name.
 * @param fmt Printf-style format string.
 * @param ... Format arguments.
 *
 * @warning fmt must be a compile-time literal to prevent format string attacks.
 * @threadsafe Yes
 */
void SocketLog_emitf (SocketLogLevel level, const char *component,
                      const char *fmt, ...)
    __attribute__ ((format (printf, 3, 4)));

/**
 * @brief Emit formatted log message using va_list.
 * @ingroup foundation
 *
 * @param level Log level.
 * @param component Component name.
 * @param fmt Printf-style format string.
 * @param args Format arguments as va_list.
 *
 * @threadsafe Yes
 */
void SocketLog_emitfv (SocketLogLevel level, const char *component,
                       const char *fmt, va_list args)
    __attribute__ ((format (printf, 3, 0)));

/**
 * @brief Configure global minimum log level threshold.
 * @ingroup foundation
 *
 * @param min_level Minimum level (SOCKET_LOG_TRACE = most verbose).
 *
 * Logs below this level are suppressed. Default: SOCKET_LOG_INFO.
 *
 * @threadsafe Yes
 */
extern void SocketLog_setlevel (SocketLogLevel min_level);

/**
 * @brief Get the current global minimum log level threshold.
 * @ingroup foundation
 *
 * @return Current SocketLogLevel threshold.
 *
 * @threadsafe Yes
 */
extern SocketLogLevel SocketLog_getlevel (void);

/* Default log component - modules should override before including this header
 */
#ifndef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "Socket"
#endif

/* ----------------------------------------------------------------------------
 * Convenience Logging Macros
 * ----------------------------------------------------------------------------
 *
 * These macros provide ergonomic logging that automatically uses the
 * SOCKET_LOG_COMPONENT macro defined by each module. Each module should
 * define SOCKET_LOG_COMPONENT before including this header:
 *
 *   #undef SOCKET_LOG_COMPONENT
 *   #define SOCKET_LOG_COMPONENT "MyModule"
 *
 * Usage:
 *   SOCKET_LOG_DEBUG_MSG("Connection established fd=%d", fd);
 *   SOCKET_LOG_ERROR_MSG("Failed to bind: %s", strerror(errno));
 */

/* Log at TRACE level (most verbose, detailed tracing) */
#define SOCKET_LOG_TRACE_MSG(fmt, ...)                                        \
  SocketLog_emitf (SOCKET_LOG_TRACE, SOCKET_LOG_COMPONENT, fmt, ##__VA_ARGS__)

/* Log at DEBUG level (debugging information) */
#define SOCKET_LOG_DEBUG_MSG(fmt, ...)                                        \
  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT, fmt, ##__VA_ARGS__)

/* Log at INFO level (normal operational messages) */
#define SOCKET_LOG_INFO_MSG(fmt, ...)                                         \
  SocketLog_emitf (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT, fmt, ##__VA_ARGS__)

/* Log at WARN level (warning conditions) */
#define SOCKET_LOG_WARN_MSG(fmt, ...)                                         \
  SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT, fmt, ##__VA_ARGS__)

/* Log at ERROR level (error conditions) */
#define SOCKET_LOG_ERROR_MSG(fmt, ...)                                        \
  SocketLog_emitf (SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT, fmt, ##__VA_ARGS__)

/* Log at FATAL level (critical errors, typically before abort) */
#define SOCKET_LOG_FATAL_MSG(fmt, ...)                                        \
  SocketLog_emitf (SOCKET_LOG_FATAL, SOCKET_LOG_COMPONENT, fmt, ##__VA_ARGS__)

/* ----------------------------------------------------------------------------
 * Safe Logging Macros (for untrusted/user-controlled messages)
 * ----------------------------------------------------------------------------
 *
 * These macros use SocketLog_emit() with a fixed "%s" format to safely log
 * user-controlled strings without format string vulnerabilities.
 *
 * Use these when logging data that may come from untrusted sources.
 *
 * Usage:
 *   const char *user_input = get_user_input();
 *   SOCKET_LOG_INFO_SAFE(user_input);  // Safe - no format string attack
 */

/* Log untrusted string at TRACE level */
#define SOCKET_LOG_TRACE_SAFE(msg)                                            \
  SocketLog_emit (SOCKET_LOG_TRACE, SOCKET_LOG_COMPONENT, (msg))

/* Log untrusted string at DEBUG level */
#define SOCKET_LOG_DEBUG_SAFE(msg)                                            \
  SocketLog_emit (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT, (msg))

/* Log untrusted string at INFO level */
#define SOCKET_LOG_INFO_SAFE(msg)                                             \
  SocketLog_emit (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT, (msg))

/* Log untrusted string at WARN level */
#define SOCKET_LOG_WARN_SAFE(msg)                                             \
  SocketLog_emit (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT, (msg))

/* Log untrusted string at ERROR level */
#define SOCKET_LOG_ERROR_SAFE(msg)                                            \
  SocketLog_emit (SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT, (msg))

/* Log untrusted string at FATAL level */
#define SOCKET_LOG_FATAL_SAFE(msg)                                            \
  SocketLog_emit (SOCKET_LOG_FATAL, SOCKET_LOG_COMPONENT, (msg))

/* ----------------------------------------------------------------------------
 * Thread-Local Logging Context
 * ----------------------------------------------------------------------------
 *
 * Provides correlation IDs for distributed tracing and request tracking.
 * Each thread can set its own context that will be available to custom
 * logging callbacks for inclusion in log output.
 *
 * Usage:
 *   SocketLogContext ctx = {0};
 *   strncpy(ctx.trace_id, "abc-123-def", sizeof(ctx.trace_id) - 1);
 *   ctx.connection_fd = client_fd;
 *   SocketLog_setcontext(&ctx);
 *
 *   // ... handle request - all logs will have context available ...
 *
 *   SocketLog_clearcontext();
 */

/* UUID size: 36 chars (8-4-4-4-12) + NUL */
#define SOCKET_LOG_ID_SIZE 37

/**
 * @brief Thread-local logging context for distributed tracing.
 * @ingroup foundation
 */
typedef struct SocketLogContext
{
  char trace_id[SOCKET_LOG_ID_SIZE]; /**< Distributed trace ID (e.g., UUID) */
  char request_id[SOCKET_LOG_ID_SIZE]; /**< Request-specific ID */
  int connection_fd; /**< Associated file descriptor (-1 if none) */
} SocketLogContext;

/**
 * @brief Set thread-local logging context.
 * @ingroup foundation
 *
 * @param ctx Context to copy (NULL clears context).
 *
 * @threadsafe Yes (thread-local storage)
 */
extern void SocketLog_setcontext (const SocketLogContext *ctx);

/**
 * @brief Get current thread's logging context.
 * @ingroup foundation
 *
 * @return Pointer to thread-local SocketLogContext or NULL if unset.
 *
 * @threadsafe Yes
 */
extern const SocketLogContext *SocketLog_getcontext (void);

/**
 * @brief Clear thread-local logging context.
 * @ingroup foundation
 *
 * @threadsafe Yes
 */
extern void SocketLog_clearcontext (void);

/* ----------------------------------------------------------------------------
 * Structured Logging
 * ----------------------------------------------------------------------------
 *
 * Provides key-value pair logging for machine-parseable output.
 * Custom callbacks can format these fields as JSON, logfmt, etc.
 *
 * Usage:
 *   SocketLogField fields[] = {
 *       {"fd", "42"},
 *       {"bytes", "1024"},
 *       {"peer", "192.168.1.1"}
 *   };
 *   SocketLog_emit_structured(SOCKET_LOG_INFO, "Socket",
 *                             "Connection established",
 *                             fields, 3);
 *
 * Or with the convenience macro:
 *   SocketLog_emit_structured(SOCKET_LOG_INFO, "Socket",
 *                             "Connection established",
 *                             SOCKET_LOG_FIELDS(
 *                                 {"fd", "42"},
 *                                 {"bytes", "1024"}
 *                             ));
 */

/**
 * @brief Key-value pair for structured logging.
 * @ingroup foundation
 */
typedef struct SocketLogField
{
  const char *key;   /**< Field name (e.g., "fd", "bytes", "peer") */
  const char *value; /**< Field value as string */
} SocketLogField;

/**
 * @brief Callback for structured logging with key-value fields.
 * @ingroup foundation
 *
 * @param userdata User-provided context.
 * @param level Log severity level.
 * @param component Module name.
 * @param message Log message.
 * @param fields Array of key-value pairs (may be NULL).
 * @param field_count Number of fields.
 * @param context Thread logging context (may be NULL).
 */
typedef void (*SocketLogStructuredCallback) (
    void *userdata, SocketLogLevel level, const char *component,
    const char *message, const SocketLogField *fields, size_t field_count,
    const SocketLogContext *context);

/**
 * @brief Register callback for handling structured log emissions with fields.
 * @ingroup foundation

 * @callback: Callback function or NULL to disable structured logging
 * @userdata: User data passed to callback
 *
 * @brief Thread-safe: Yes (mutex protected)

 *
 * When set, SocketLog_emit_structured() will invoke this callback
 * instead of the regular callback, providing access to structured fields.
 */
extern void
SocketLog_setstructuredcallback (SocketLogStructuredCallback callback,
                                 void *userdata);

/**
 * @brief Emit log message with attached structured key-value metadata fields.
 * @ingroup foundation

 * @level: Log level
 * @component: Component name
 * @message: Log message
 * @fields: Array of key-value pairs (may be NULL)
 * @field_count: Number of fields
 *
 * @threadsafe Yes

 *
 * Emits a log message with structured key-value pairs. If a structured
 * callback is set, it receives the fields directly. Otherwise, fields
 * are formatted as "key=value" pairs appended to the message.
 */
extern void SocketLog_emit_structured (SocketLogLevel level,
                                       const char *component,
                                       const char *message,
                                       const SocketLogField *fields,
                                       size_t field_count);

/**
 * @brief SOCKET_LOG_FIELDS - Convenience macro for creating field arrays

 *
 * Usage:
 *   SocketLog_emit_structured(level, component, message,
 *                             SOCKET_LOG_FIELDS({"key1", "val1"},
 *                                               {"key2", "val2"}));
 */
#define SOCKET_LOG_FIELDS(...)                                                \
  (SocketLogField[]){ __VA_ARGS__ },                                          \
      (sizeof ((SocketLogField[]){ __VA_ARGS__ }) / sizeof (SocketLogField))

/* ============================================================================
 * METRICS SUBSYSTEM
 * ============================================================================
 */

/**
 * @brief Library-wide performance metrics.
 * @ingroup foundation
 *
 * @threadsafe Yes (atomic operations)
 */
typedef enum SocketMetric
{
  SOCKET_METRIC_SOCKET_CONNECT_SUCCESS = 0,
  SOCKET_METRIC_SOCKET_CONNECT_FAILURE,
  SOCKET_METRIC_SOCKET_SHUTDOWN_CALL,
  SOCKET_METRIC_DNS_REQUEST_SUBMITTED,
  SOCKET_METRIC_DNS_REQUEST_COMPLETED,
  SOCKET_METRIC_DNS_REQUEST_FAILED,
  SOCKET_METRIC_DNS_REQUEST_CANCELLED,
  SOCKET_METRIC_DNS_REQUEST_TIMEOUT,
  SOCKET_METRIC_DNS_CACHE_HIT,
  SOCKET_METRIC_DNS_CACHE_MISS,
  SOCKET_METRIC_POLL_WAKEUPS,
  SOCKET_METRIC_POLL_EVENTS_DISPATCHED,
  SOCKET_METRIC_POOL_CONNECTIONS_ADDED,
  SOCKET_METRIC_POOL_CONNECTIONS_REMOVED,
  SOCKET_METRIC_POOL_CONNECTIONS_REUSED,
  SOCKET_METRIC_POOL_DRAIN_INITIATED,
  SOCKET_METRIC_POOL_DRAIN_COMPLETED,
  SOCKET_METRIC_POOL_HEALTH_CHECKS,
  SOCKET_METRIC_POOL_HEALTH_FAILURES,
  SOCKET_METRIC_POOL_VALIDATION_FAILURES,
  SOCKET_METRIC_POOL_IDLE_CLEANUPS,
  SOCKET_METRIC_COUNT
} SocketMetric;

/**
 * @brief Thread-safe snapshot of all library metrics.
 * @ingroup foundation
 */
typedef struct SocketMetricsSnapshot
{
  unsigned long long values[SOCKET_METRIC_COUNT];
} SocketMetricsSnapshot;

/**
 * @brief SocketMetrics_increment - Legacy metric increment (forwards to new system)
 * @ingroup foundation
 * @deprecated Use SocketMetrics_counter_inc(SocketCounterMetric) from SocketMetrics.h
 * @param metric Legacy metric enum
 * @param value Amount to add (uint64_t in new API)
 * @threadsafe Yes - forwards to atomic new system
 * @note For backward compatibility; forwards to new counters where mapped.
 * @see SocketMetrics.h for full metrics suite (gauges, histograms, exports)
 */
void SocketMetrics_increment (SocketMetric metric, unsigned long value);

/**
 * @brief SocketMetrics_getsnapshot - Legacy snapshot (populated from new system)
 * @ingroup foundation
 * @deprecated Use SocketMetrics_get(SocketMetrics_Snapshot *) from SocketMetrics.h for full data
 * @param snapshot Legacy snapshot struct (counters only)
 * @threadsafe Yes - reads from new atomic/thread-safe system
 * @note Populates legacy values from mapped new counters; unmapped are 0.
 * @see SocketMetrics.h SocketMetrics_Snapshot for gauges/histograms too
 */
void SocketMetrics_getsnapshot (SocketMetricsSnapshot *snapshot);

/**
 * @brief SocketMetrics_legacy_reset - Reset (forwards to new system)
 * @ingroup foundation
 * @deprecated Use SocketMetrics_reset() from SocketMetrics.h
 * @threadsafe Yes - calls new reset_counters (resets all counters)
 * @note For compatibility; resets all new counters, not just legacy mapped.
 */
void SocketMetrics_legacy_reset (void);

/**
 * @brief SocketMetrics_name - Get name (forwards to new or legacy)
 * @ingroup foundation
 * @deprecated Use SocketMetrics_counter_name(SocketCounterMetric) etc. from SocketMetrics.h
 * @param metric Legacy metric enum
 * @return Mapped new name or legacy name for unmapped
 * @threadsafe Yes
 * @note For compatibility; prefer new API names for consistency.
 */
const char *SocketMetrics_name (SocketMetric metric);

/**
 * @brief SocketMetrics_count - Get total number of defined metrics
 * @ingroup foundation
 * @return Number of metrics
 * @threadsafe Yes
 */
size_t SocketMetrics_count (void);

/**
 * @brief Get a specific value from metrics snapshot.
 * @ingroup foundation
 * @param snapshot Snapshot to read from.
 * @param metric Metric to retrieve.
 * @return Metric value, or 0 for invalid inputs.
 * @threadsafe Yes (read-only operation)
 */
static inline unsigned long long
SocketMetrics_snapshot_value (const SocketMetricsSnapshot *snapshot,
                              SocketMetric metric)
{
  if (!snapshot)
    return 0ULL;
  if (metric < 0 || metric >= SOCKET_METRIC_COUNT)
    return 0ULL;
  return snapshot->values[metric];
}

/* ============================================================================
 * EVENTS SUBSYSTEM
 * ============================================================================
 */

/**
 * @brief SocketEventType - Event type enumeration

 */
typedef enum SocketEventType
{
  SOCKET_EVENT_ACCEPTED = 0,
  SOCKET_EVENT_CONNECTED,
  SOCKET_EVENT_DNS_TIMEOUT,
  SOCKET_EVENT_POLL_WAKEUP
} SocketEventType;

/**
 * @brief SocketEventRecord - Event data structure

 */
typedef struct SocketEventRecord
{
  SocketEventType type;
  const char *component;
  union
  {
    struct
    {
      int fd;
      const char *peer_addr;
      int peer_port;
      const char *local_addr;
      int local_port;
    } connection;
    struct
    {
      const char *host;
      int port;
    } dns;
    struct
    {
      int nfds;
      int timeout_ms;
    } poll;
  } data;
} SocketEventRecord;

/**
 * @brief SocketEventCallback - Event handler callback type

 * @userdata: User-provided context
 * @event: Event record
 */
typedef void (*SocketEventCallback) (void *userdata,
                                     const SocketEventRecord *event);

/**
 * @brief SocketEvent_register - Register an event handler
 * @ingroup foundation
 * @param callback Callback function to register
 * @param userdata User data passed to callback
 * @threadsafe Yes
 */
void SocketEvent_register (SocketEventCallback callback, void *userdata);

/**
 * @brief SocketEvent_unregister - Unregister an event handler
 * @ingroup foundation
 * @param callback Callback function to unregister
 * @param userdata User data that was passed to register
 * @threadsafe Yes
 */
void SocketEvent_unregister (SocketEventCallback callback,
                             const void *userdata);

/**
 * @brief Emit connection accept event.
 * @ingroup foundation
 *
 * @param fd Client file descriptor.
 * @param peer_addr Peer IP address.
 * @param peer_port Peer port.
 * @param local_addr Local IP address.
 * @param local_port Local port.
 *
 * @threadsafe Yes
 */
void SocketEvent_emit_accept (int fd, const char *peer_addr, int peer_port,
                              const char *local_addr, int local_port);

/**
 * @brief Emit outbound connection event.
 * @ingroup foundation
 *
 * @param fd Socket file descriptor.
 * @param peer_addr Peer IP address.
 * @param peer_port Peer port.
 * @param local_addr Local IP address.
 * @param local_port Local port.
 *
 * @threadsafe Yes
 */
void SocketEvent_emit_connect (int fd, const char *peer_addr, int peer_port,
                               const char *local_addr, int local_port);

/**
 * @brief Emit DNS resolution timeout event.
 * @ingroup foundation
 *
 * @param host Hostname that timed out.
 * @param port Destination port.
 *
 * @threadsafe Yes
 */
void SocketEvent_emit_dns_timeout (const char *host, int port);

/**
 * @brief Emit poll wakeup event.
 * @ingroup foundation
 *
 * @param nfds Number of monitored file descriptors.
 * @param timeout_ms Poll timeout (-1 = infinite).
 *
 * @threadsafe Yes
 */
void SocketEvent_emit_poll_wakeup (int nfds, int timeout_ms);

/* ============================================================================
 * ERROR HANDLING SUBSYSTEM
 * ============================================================================
 */

/**
 * @brief Normalized error codes mapping POSIX errno values.
 * @ingroup foundation
 */
typedef enum SocketErrorCode
{
  SOCKET_ERROR_NONE = 0,
  SOCKET_ERROR_EINVAL,
  SOCKET_ERROR_EACCES,
  SOCKET_ERROR_EADDRINUSE,
  SOCKET_ERROR_EADDRNOTAVAIL,
  SOCKET_ERROR_EAFNOSUPPORT,
  SOCKET_ERROR_EAGAIN,
  SOCKET_ERROR_EALREADY,
  SOCKET_ERROR_EBADF,
  SOCKET_ERROR_ECONNREFUSED,
  SOCKET_ERROR_ECONNRESET,
  SOCKET_ERROR_EFAULT,
  SOCKET_ERROR_EHOSTUNREACH,
  SOCKET_ERROR_EINPROGRESS,
  SOCKET_ERROR_EINTR,
  SOCKET_ERROR_EISCONN,
  SOCKET_ERROR_EMFILE,
  SOCKET_ERROR_ENETUNREACH,
  SOCKET_ERROR_ENOBUFS,
  SOCKET_ERROR_ENOMEM,
  SOCKET_ERROR_ENOTCONN,
  SOCKET_ERROR_ENOTSOCK,
  SOCKET_ERROR_EOPNOTSUPP,
  SOCKET_ERROR_EPIPE,
  SOCKET_ERROR_EPROTONOSUPPORT,
  SOCKET_ERROR_ETIMEDOUT,
  SOCKET_ERROR_EWOULDBLOCK,
  SOCKET_ERROR_UNKNOWN
} SocketErrorCode;

/* Thread-local error buffer for detailed messages */
#ifdef _WIN32
extern __declspec (thread) char socket_error_buf[SOCKET_ERROR_BUFSIZE];
extern __declspec (thread) int socket_last_errno;
#else
extern __thread char socket_error_buf[SOCKET_ERROR_BUFSIZE];
extern __thread int socket_last_errno;
#endif

/**
 * @brief SOCKET_ERROR_APPLY_TRUNCATION - Apply truncation marker if message
 was cut

 * @ret: Return value from snprintf
 *
 * Internal helper macro to eliminate duplication in error formatting.
 */
#define SOCKET_ERROR_APPLY_TRUNCATION(ret)                                    \
  do                                                                          \
    {                                                                         \
      if ((ret) >= (int)SOCKET_ERROR_BUFSIZE)                                 \
        {                                                                     \
          socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';                  \
          if (SOCKET_ERROR_BUFSIZE >= SOCKET_ERROR_TRUNCATION_SIZE + 1)       \
            {                                                                 \
              memcpy (socket_error_buf + SOCKET_ERROR_BUFSIZE                 \
                          - SOCKET_ERROR_TRUNCATION_SIZE,                     \
                      SOCKET_ERROR_TRUNCATION_MARKER,                         \
                      SOCKET_ERROR_TRUNCATION_SIZE - 1);                      \
              socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';              \
            }                                                                 \
        }                                                                     \
    }                                                                         \
  while (0)

/**
 * @brief SOCKET_ERROR_FMT - Format error message with errno information

 * Includes truncation protection for long messages.
 */
#define SOCKET_ERROR_FMT(fmt, ...)                                            \
  do                                                                          \
    {                                                                         \
      socket_last_errno = errno;                                              \
      char tmp_buf[SOCKET_ERROR_BUFSIZE];                                     \
      int _socket_error_ret = snprintf (                                      \
          tmp_buf, sizeof (tmp_buf), fmt " (errno: %d - %s)", ##__VA_ARGS__,  \
          socket_last_errno, Socket_safe_strerror (socket_last_errno));       \
      memcpy (socket_error_buf, tmp_buf, SOCKET_ERROR_BUFSIZE);               \
      socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';                      \
      SOCKET_ERROR_APPLY_TRUNCATION (_socket_error_ret);                      \
      (void)_socket_error_ret;                                                \
      SocketLog_emit (SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT,                 \
                      socket_error_buf);                                      \
    }                                                                         \
  while (0)

/**
 * @brief SOCKET_ERROR_MSG - Format error message without errno

 * Includes truncation protection for long messages.
 */
#define SOCKET_ERROR_MSG(fmt, ...)                                            \
  do                                                                          \
    {                                                                         \
      socket_last_errno = errno;                                              \
      char tmp_buf[SOCKET_ERROR_BUFSIZE];                                     \
      int _socket_error_ret                                                   \
          = snprintf (tmp_buf, sizeof (tmp_buf), fmt, ##__VA_ARGS__);         \
      memcpy (socket_error_buf, tmp_buf, SOCKET_ERROR_BUFSIZE);               \
      socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';                      \
      SOCKET_ERROR_APPLY_TRUNCATION (_socket_error_ret);                      \
      (void)_socket_error_ret;                                                \
      SocketLog_emit (SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT,                 \
                      socket_error_buf);                                      \
    }                                                                         \
  while (0)

/**
 * @brief Get the last formatted error message.
 * @ingroup foundation
 *
 * @return Thread-local error string (never NULL).
 *
 * @threadsafe Yes
 */
extern const char *Socket_GetLastError (void);

/**
 * @brief Get the raw errno from the last error.
 * @ingroup foundation
 *
 * @return Last errno value.
 *
 * @threadsafe Yes
 */
extern int Socket_geterrno (void);

/**
 * @brief Convert last errno to normalized SocketErrorCode.
 * @ingroup foundation
 *
 * @return Mapped SocketErrorCode (SOCKET_ERROR_UNKNOWN if unmapped).
 *
 * @threadsafe Yes
 */
extern SocketErrorCode Socket_geterrorcode (void);

/**
 * @brief Thread-safe errno to string conversion.
 * @ingroup foundation
 *
 * @param errnum errno value to convert.
 * @return Descriptive error string.
 *
 * @threadsafe Yes
 */
const char *Socket_safe_strerror (int errnum);

/* Common error conditions with descriptive messages */
#define SOCKET_ENOMEM "Out of memory"
#define SOCKET_EINVAL "Invalid argument"
#define SOCKET_ECONNREFUSED "Connection refused"
#define SOCKET_ETIMEDOUT "Operation timed out"
#define SOCKET_EADDRINUSE "Address already in use"
#define SOCKET_ENETUNREACH "Network unreachable"
#define SOCKET_EHOSTUNREACH "Host unreachable"
#define SOCKET_EPIPE "Broken pipe"
#define SOCKET_ECONNRESET "Connection reset by peer"

/* ============================================================================
 * ERROR CATEGORIZATION
 * ============================================================================
 *
 * Provides error classification for determining retry eligibility and
 * appropriate error handling strategies.
 *
 * Categories:
 * - NETWORK: Transient network errors (usually retryable)
 * - PROTOCOL: Protocol/format errors (usually not retryable)
 * - APPLICATION: Application-level errors (context-dependent)
 * - TIMEOUT: Timeout errors (usually retryable with backoff)
 * - RESOURCE: Resource exhaustion (may be retryable after delay)
 * - UNKNOWN: Unclassified errors
 */

/**
 * @brief High-level classification of error types.
 * @ingroup foundation
 */
typedef enum SocketErrorCategory
{
  SOCKET_ERROR_CATEGORY_NETWORK
  = 0, /**< Network-level: ECONNRESET, ECONNREFUSED, etc. */
  SOCKET_ERROR_CATEGORY_PROTOCOL,    /**< Protocol-level: Parse errors, invalid
                                        responses */
  SOCKET_ERROR_CATEGORY_APPLICATION, /**< App-level: Auth failures, 4xx
                                        responses */
  SOCKET_ERROR_CATEGORY_TIMEOUT,     /**< Timeout errors: ETIMEDOUT, deadline
                                        exceeded */
  SOCKET_ERROR_CATEGORY_RESOURCE, /**< Resource exhaustion: OOM, fd limits */
  SOCKET_ERROR_CATEGORY_UNKNOWN   /**< Unclassified errors */
} SocketErrorCategory;

/**
 * @brief Classify errno into SocketErrorCategory.
 * @ingroup foundation
 *
 * @param err errno value to classify.
 * @return Appropriate SocketErrorCategory.
 *
 * @threadsafe Yes
 */
extern SocketErrorCategory SocketError_categorize_errno (int err);

/**
 * @brief Get string name for error category.
 * @param category Error category.
 * @return Static string with category name.
 * @threadsafe Yes (returns static data)
 */
extern const char *SocketError_category_name (SocketErrorCategory category);

/**
 * @brief SocketError_is_retryable_errno - Check if errno indicates retryable
 error

 * @err: errno value to check
 *
 * Returns: 1 if error is typically retryable, 0 if fatal
 * @brief Thread-safe: Yes (pure function)

 *
 * Retryable errors include:
 * - Network transient: ECONNREFUSED, ECONNRESET, ENETUNREACH, EHOSTUNREACH
 * - Timeout: ETIMEDOUT
 * - Temporary resource: EAGAIN, EWOULDBLOCK, EINTR
 *
 * @brief Non-retryable errors include:

 * - Configuration: EACCES, EADDRINUSE, EADDRNOTAVAIL, EPERM
 * - Programming: EBADF, ENOTSOCK, EINVAL, EFAULT
 * - Permanent resource: ENOMEM, EMFILE, ENFILE
 */
extern int SocketError_is_retryable_errno (int err);

/* ============================================================================
 * Centralized Exception Infrastructure
 * ============================================================================
 */

/**
 * @brief SOCKET_DECLARE_MODULE_EXCEPTION - Declare thread-local exception

 * @module_name: Module name (e.g., Socket, SocketBuf, SocketPoll)
 */
#define SOCKET_DECLARE_MODULE_EXCEPTION(module_name)                          \
  static __thread Except_T module_name##_DetailedException

/**
 * @brief SOCKET_RAISE_MODULE_ERROR - Raise module-specific exception

 * @module_name: Module name
 * @exception: Exception to raise
 * @brief Thread-safe: Creates thread-local copy with detailed reason

 */
#define SOCKET_RAISE_MODULE_ERROR(module_name, exception)                     \
  do                                                                          \
    {                                                                         \
      module_name##_DetailedException = (exception);                          \
      module_name##_DetailedException.reason = socket_error_buf;              \
      RAISE (module_name##_DetailedException);                                \
    }                                                                         \
  while (0)

/* ============================================================================
 * Unified Error + Raise Macros (Eliminates Redundant Patterns)
 * ============================================================================
 */

/**
 * @brief SOCKET_RAISE_FMT - Format error with errno and raise exception in one
 step

 * @module_name: Module name for exception
 * @exception: Exception to raise
 * @fmt: Printf-style format string
 * @...: Format arguments
 *
 * Combines SOCKET_ERROR_FMT + RAISE_MODULE_ERROR into single macro.
 * @brief Thread-safe: Yes (uses thread-local buffers)

 */
#define SOCKET_RAISE_FMT(module_name, exception, fmt, ...)                    \
  do                                                                          \
    {                                                                         \
      SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__);                                  \
      SOCKET_RAISE_MODULE_ERROR (module_name, exception);                     \
    }                                                                         \
  while (0)

/**
 * @brief SOCKET_RAISE_MSG - Format error message and raise exception in one
 step

 * @module_name: Module name for exception
 * @exception: Exception to raise
 * @fmt: Printf-style format string (without errno)
 * @...: Format arguments
 *
 * Combines SOCKET_ERROR_MSG + RAISE_MODULE_ERROR into single macro.
 * @brief Thread-safe: Yes (uses thread-local buffers)

 */
#define SOCKET_RAISE_MSG(module_name, exception, fmt, ...)                    \
  do                                                                          \
    {                                                                         \
      SOCKET_ERROR_MSG (fmt, ##__VA_ARGS__);                                  \
      SOCKET_RAISE_MODULE_ERROR (module_name, exception);                     \
    }                                                                         \
  while (0)

/**
 * Helper macros for common module patterns - use RAISE_MODULE_ERROR macro
 * defined in each module that sets module_name appropriately.
 *
 * Example module setup:
 *   SOCKET_DECLARE_MODULE_EXCEPTION(MyModule);
 *   #define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(MyModule, e)
 *   #define RAISE_FMT(e, fmt, ...) SOCKET_RAISE_FMT(MyModule, e, fmt,
 * ##__VA_ARGS__) #define RAISE_MSG(e, fmt, ...) SOCKET_RAISE_MSG(MyModule, e,
 * fmt, ##__VA_ARGS__)
 */

/* ============================================================================
 * TIME UTILITIES (Consolidated monotonic clock functions)
 * ============================================================================
 */

/**
 * @brief Socket_get_monotonic_ms - Get current monotonic time in milliseconds
 * @ingroup foundation
 * @return Current monotonic time in milliseconds since arbitrary epoch
 * @threadsafe Yes (no shared state)
 *
 * Uses CLOCK_MONOTONIC with CLOCK_REALTIME fallback. Immune to wall-clock
 * changes (NTP adjustments, manual time changes). Returns 0 on failure.
 *
 * Use for:
 * - Rate limiting timestamps
 * - Timer expiry calculations
 * - Elapsed time measurements
 */
int64_t Socket_get_monotonic_ms (void);

/* ============================================================================
 * HASH UTILITIES (Consolidated from multiple modules)
 * ============================================================================
 */

/**
 * @brief Hash file descriptor using golden ratio multiplicative.
 * @ingroup foundation
 * @param fd File descriptor to hash (non-negative).
 * @param table_size Hash table size (should be prime for best distribution).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function, no shared state)
 *
 * Uses the golden ratio constant (2^32 * (sqrt(5)-1)/2) for excellent
 * distribution properties. Suitable for file descriptors, socket IDs,
 * and other small integer keys.
 */
static inline unsigned
socket_util_hash_fd (int fd, unsigned table_size)
{
  return ((unsigned)fd * HASH_GOLDEN_RATIO) % table_size;
}

/**
 * @brief Hash pointer using golden ratio multiplicative.
 * @ingroup foundation
 * @param ptr Pointer to hash (may be NULL).
 * @param table_size Hash table size (should be prime for best distribution).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function, no shared state)
 *
 * Converts pointer to integer and applies golden ratio hash.
 * Suitable for hashing opaque handles and memory addresses.
 */
static inline unsigned
socket_util_hash_ptr (const void *ptr, unsigned table_size)
{
  return ((unsigned)(uintptr_t)ptr * HASH_GOLDEN_RATIO) % table_size;
}

/**
 * @brief Hash unsigned integer using golden ratio.
 * @ingroup foundation
 * @param value Unsigned integer to hash.
 * @param table_size Hash table size (should be prime for best distribution).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function, no shared state)
 *
 * General-purpose hash for unsigned integers including request IDs.
 */
static inline unsigned
socket_util_hash_uint (unsigned value, unsigned table_size)
{
  return (value * HASH_GOLDEN_RATIO) % table_size;
}

/**
 * @brief Seeded hash for collision resistance in security contexts.
 * @ingroup foundation
 * @param value Unsigned integer to hash.
 * @param table_size Hash table size (should be prime).
 * @param seed Per-instance random seed (e.g., from SocketCrypto_random_bytes).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function)
 *
 * Adds seed to prevent predictable collisions in tables like HTTP/2 streams.
 * Use for security-sensitive lookups where attacker may control keys.
 */
static inline unsigned
socket_util_hash_uint_seeded (unsigned value, unsigned table_size,
                              uint32_t seed)
{
  uint64_t h = (uint64_t)value * HASH_GOLDEN_RATIO + (uint64_t)seed;
  return (unsigned)(h % table_size);
}

/** DJB2 hash algorithm seed value (Daniel J. Bernstein) */
#define SOCKET_UTIL_DJB2_SEED 5381u

/**
 * @brief Hash string using DJB2 algorithm.
 * @ingroup foundation
 * @param str String to hash (must not be NULL).
 * @param table_size Hash table size (should be prime for best distribution).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function, no shared state)
 *
 * DJB2 hash: hash = hash * 33 + c
 * The multiplication by 33 is optimized as (hash << 5) + hash.
 * Provides good distribution for string keys like IP addresses.
 *
 * Security note: DJB2 is a fast, simple hash for load distribution.
 * NOT cryptographic - do not use for security-sensitive purposes.
 */
static inline unsigned
socket_util_hash_djb2 (const char *str, unsigned table_size)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;
  int c;

  while ((c = *str++) != '\0')
    hash = ((hash << 5) + hash) + (unsigned)c;

  return hash % table_size;
}

/**
 * @brief Hash string with explicit length using DJB2.
 * @ingroup foundation
 * @param str String to hash (may contain null bytes).
 * @param len Length of string.
 * @param table_size Hash table size (should be prime for best distribution).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function, no shared state)
 *
 * Length-aware variant for non-null-terminated strings.
 * Useful for parsing buffers where strings aren't null-terminated.
 */
static inline unsigned
socket_util_hash_djb2_len (const char *str, size_t len, unsigned table_size)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;
  size_t i;

  for (i = 0; i < len; i++)
    hash = ((hash << 5) + hash) + (unsigned char)str[i];

  return hash % table_size;
}

/**
 * @brief Case-insensitive DJB2 hash.
 * @ingroup foundation
 * @param str String to hash (must not be NULL).
 * @param table_size Hash table size (should be prime for best distribution).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function, no shared state)
 *
 * Case-insensitive variant for HTTP headers and similar keys.
 * Converts ASCII uppercase to lowercase before hashing.
 */
static inline unsigned
socket_util_hash_djb2_ci (const char *str, unsigned table_size)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;
  int c;

  while ((c = *str++) != '\0')
    {
      /* Convert ASCII uppercase to lowercase */
      if (c >= 'A' && c <= 'Z')
        c += 32;
      hash = ((hash << 5) + hash) + (unsigned)c;
    }

  return hash % table_size;
}

/**
 * @brief Case-insensitive length-aware DJB2 hash.
 * @ingroup foundation
 * @param str String to hash (may contain null bytes).
 * @param len Length of string.
 * @param table_size Hash table size (should be prime for best distribution).
 * @return Hash value in range [0, table_size).
 * @threadsafe Yes (pure function, no shared state)
 *
 * Combines length-aware and case-insensitive variants.
 * Ideal for HTTP header name hashing where names aren't null-terminated.
 */
static inline unsigned
socket_util_hash_djb2_ci_len (const char *str, size_t len, unsigned table_size)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;
  size_t i;

  for (i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)str[i];
      /* Convert ASCII uppercase to lowercase */
      if (c >= 'A' && c <= 'Z')
        c += 32;
      hash = ((hash << 5) + hash) + c;
    }

  return hash % table_size;
}

/**
 * @brief Round up to next power of 2.
 * @ingroup foundation
 * @param n Value to round up (must be > 0).
 * @return Smallest power of 2 >= n.
 * @threadsafe Yes (pure function)
 *
 * Useful for hash table sizing and circular buffer capacities
 * where power-of-2 sizes allow efficient modulo via bitwise AND.
 */
static inline size_t
socket_util_round_up_pow2 (size_t n)
{
  if (n == 0)
    return 1;
  n--;
  n |= n >> 1;
  n |= n >> 2;
  n |= n >> 4;
  n |= n >> 8;
  n |= n >> 16;
#if SIZE_MAX > 0xFFFFFFFF
  n |= n >> 32;
#endif
  return n + 1;
}

/* ============================================================================
 * String Utilities
 * ============================================================================
 */

/**
 * @brief Duplicate string into arena.
 * @ingroup foundation
 * @param arena Arena for allocation.
 * @param str String to duplicate (may be NULL).
 * @return Duplicated string in arena, or NULL if str is NULL or alloc fails.
 * @threadsafe Yes (if arena is thread-safe)
 *
 * Convenience function to duplicate a string into an arena.
 * Avoids repeated strlen+alloc+memcpy pattern in calling code.
 */
static inline char *
socket_util_arena_strdup (Arena_T arena, const char *str)
{
  size_t len;
  char *copy;

  if (str == NULL)
    return NULL;

  len = strlen (str);
  copy = Arena_alloc (arena, len + 1, __FILE__, __LINE__);
  if (copy != NULL)
    memcpy (copy, str, len + 1);

  return copy;
}

/**
 * @brief Duplicate string with max length into arena.
 * @ingroup foundation
 * @param arena Arena for allocation.
 * @param str String to duplicate (may be NULL).
 * @param maxlen Maximum characters to copy (excluding null terminator).
 * @return Duplicated string in arena, or NULL if str is NULL or alloc fails.
 * @threadsafe Yes (if arena is thread-safe)
 *
 * Duplicates at most maxlen characters from str. Always null-terminates.
 */
static inline char *
socket_util_arena_strndup (Arena_T arena, const char *str, size_t maxlen)
{
  size_t len;
  char *copy;

  if (str == NULL)
    return NULL;

  len = strlen (str);
  if (len > maxlen)
    len = maxlen;

  copy = Arena_alloc (arena, len + 1, __FILE__, __LINE__);
  if (copy != NULL)
    {
      memcpy (copy, str, len);
      copy[len] = '\0';
    }

  return copy;
}

/* ============================================================================
 * TIMEOUT CALCULATION HELPERS
 * ============================================================================
 *
 * These helpers provide consistent timeout calculation across all modules.
 * They use CLOCK_MONOTONIC for reliable timing that isn't affected by
 * system clock changes.
 */

/**
 * @brief Get current monotonic time in milliseconds.
 * @ingroup foundation
 * @return Current time in milliseconds from monotonic clock.
 * @threadsafe Yes
 */
static inline int64_t
SocketTimeout_now_ms (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/**
 * @brief Create deadline from timeout.
 * @ingroup foundation
 * @param timeout_ms Timeout in milliseconds (0 or negative = no deadline).
 * @return Absolute deadline in milliseconds, or 0 if no timeout.
 * @threadsafe Yes
 */
static inline int64_t
SocketTimeout_deadline_ms (int timeout_ms)
{
  if (timeout_ms <= 0)
    return 0;
  return SocketTimeout_now_ms () + timeout_ms;
}

/**
 * @brief Calculate remaining time until deadline.
 * @ingroup foundation
 * @param deadline_ms Deadline from SocketTimeout_deadline_ms() (0 = no
 * deadline).
 * @return Remaining milliseconds (0 if expired, -1 if no deadline).
 * @threadsafe Yes
 */
static inline int64_t
SocketTimeout_remaining_ms (int64_t deadline_ms)
{
  int64_t remaining;

  if (deadline_ms == 0)
    return -1; /* No deadline = infinite */

  remaining = deadline_ms - SocketTimeout_now_ms ();
  return (remaining > 0) ? remaining : 0;
}

/**
 * @brief Check if deadline has passed.
 * @ingroup foundation
 * @param deadline_ms Deadline from SocketTimeout_deadline_ms() (0 = no
 * deadline).
 * @return 1 if expired, 0 if not expired or no deadline.
 * @threadsafe Yes
 */
static inline int
SocketTimeout_expired (int64_t deadline_ms)
{
  if (deadline_ms == 0)
    return 0; /* No deadline = never expires */

  return SocketTimeout_now_ms () >= deadline_ms;
}

/**
 * @brief Adjust poll timeout to not exceed deadline.
 * @ingroup foundation
 * @param current_timeout_ms Current poll timeout (-1 = infinite).
 * @param deadline_ms Deadline from SocketTimeout_deadline_ms() (0 = no
 * deadline).
 * @return Adjusted timeout for poll() (minimum of current and remaining).
 * @threadsafe Yes
 *
 * Usage: Use as the timeout argument to poll() when you need to respect
 * both a regular poll interval and an overall operation deadline.
 */
static inline int
SocketTimeout_poll_timeout (int current_timeout_ms, int64_t deadline_ms)
{
  int64_t remaining;

  if (deadline_ms == 0)
    return current_timeout_ms; /* No deadline */

  remaining = SocketTimeout_remaining_ms (deadline_ms);
  if (remaining == 0)
    return 0; /* Already expired */

  if (remaining == -1)
    return current_timeout_ms; /* No deadline (shouldn't happen here) */

  /* Cap remaining to INT_MAX for poll() */
  if (remaining > INT_MAX)
    remaining = INT_MAX;

  /* Return minimum of current timeout and remaining */
  if (current_timeout_ms < 0)
    return (int)remaining;

  return (current_timeout_ms < (int)remaining) ? current_timeout_ms
                                               : (int)remaining;
}

/**
 * @brief Calculate elapsed time since start.
 * @ingroup foundation
 * @param start_ms Start time from SocketTimeout_now_ms().
 * @return Elapsed milliseconds since start.
 * @threadsafe Yes
 */
static inline int64_t
SocketTimeout_elapsed_ms (int64_t start_ms)
{
  return SocketTimeout_now_ms () - start_ms;
}

/* ============================================================================
 * MUTEX + ARENA MANAGER PATTERN
 * ============================================================================
 *
 * Standard pattern for modules with mutex-protected arena allocation.
 * Embed SOCKET_MUTEX_ARENA_FIELDS in struct, use SOCKET_MUTEX_ARENA_*() macros.
 *
 * Example usage:
 *   struct MyModule_T {
 *     SOCKET_MUTEX_ARENA_FIELDS;
 *     // ... module-specific fields
 *   };
 *
 *   MyModule_T MyModule_new(Arena_T arena) {
 *     MyModule_T m = arena ? CALLOC(arena, 1, sizeof(*m)) : calloc(1, sizeof(*m));
 *     if (!m) SOCKET_RAISE_MSG(...);
 *     m->arena = arena;
 *     SOCKET_MUTEX_ARENA_INIT(m, MyModule, MyModule_Failed);
 *     return m;
 *   }
 *
 *   void MyModule_free(MyModule_T *m) {
 *     if (!m || !*m) return;
 *     SOCKET_MUTEX_ARENA_DESTROY(*m);
 *     if (!(*m)->arena) free(*m);
 *     *m = NULL;
 *   }
 */

/** Mutex initialization states */
#define SOCKET_MUTEX_UNINITIALIZED 0
#define SOCKET_MUTEX_INITIALIZED 1
#define SOCKET_MUTEX_SHUTDOWN (-1)

/**
 * @brief SOCKET_MUTEX_ARENA_FIELDS - Fields to embed in managed structs
 *
 * Provides the standard pattern for modules that need:
 * - pthread_mutex_t for thread-safe operations
 * - Arena_T for optional arena-based allocation
 * - Initialization state tracking for safe cleanup
 *
 * Usage:
 *   struct MyModule_T {
 *     SOCKET_MUTEX_ARENA_FIELDS;
 *     // ... other fields
 *   };
 */
#define SOCKET_MUTEX_ARENA_FIELDS                                             \
        pthread_mutex_t mutex;                                                \
        Arena_T arena;                                                        \
        int initialized

/**
 * @brief SOCKET_MUTEX_ARENA_INIT - Initialize mutex and set state
 * @param obj Pointer to struct containing SOCKET_MUTEX_ARENA_FIELDS
 * @param module_name Module name for exception (e.g., SocketRateLimit)
 * @param exc_var Exception variable to raise on failure
 *
 * Prerequisites: obj->arena must already be set by caller.
 * Initializes mutex and sets initialized = SOCKET_MUTEX_INITIALIZED.
 * Raises exception on mutex init failure.
 *
 * Usage:
 *   limiter->arena = arena;
 *   SOCKET_MUTEX_ARENA_INIT(limiter, SocketRateLimit, SocketRateLimit_Failed);
 */
#define SOCKET_MUTEX_ARENA_INIT(obj, module_name, exc_var)                    \
        do                                                                    \
          {                                                                   \
            (obj)->initialized = SOCKET_MUTEX_UNINITIALIZED;                  \
            if (pthread_mutex_init (&(obj)->mutex, NULL) != 0)                \
              {                                                               \
                SOCKET_RAISE_MSG (module_name, exc_var,                       \
                                  "Failed to initialize mutex");              \
              }                                                               \
            (obj)->initialized = SOCKET_MUTEX_INITIALIZED;                    \
          }                                                                   \
        while (0)

/**
 * @brief SOCKET_MUTEX_ARENA_DESTROY - Cleanup mutex if initialized
 * @param obj Pointer to struct containing SOCKET_MUTEX_ARENA_FIELDS
 *
 * Destroys mutex only if initialized == SOCKET_MUTEX_INITIALIZED.
 * Sets initialized = SOCKET_MUTEX_UNINITIALIZED after cleanup.
 * Safe to call multiple times (idempotent).
 */
#define SOCKET_MUTEX_ARENA_DESTROY(obj)                                       \
        do                                                                    \
          {                                                                   \
            if ((obj)->initialized == SOCKET_MUTEX_INITIALIZED)               \
              {                                                               \
                pthread_mutex_destroy (&(obj)->mutex);                        \
                (obj)->initialized = SOCKET_MUTEX_UNINITIALIZED;              \
              }                                                               \
          }                                                                   \
        while (0)

/**
 * @brief SOCKET_MUTEX_ARENA_ALLOC - Allocate from arena or malloc
 * @param obj Pointer to struct containing SOCKET_MUTEX_ARENA_FIELDS
 * @param size Bytes to allocate
 *
 * Returns: Allocated pointer (uninitialized) or NULL on failure
 */
#define SOCKET_MUTEX_ARENA_ALLOC(obj, size)                                   \
        ((obj)->arena ? Arena_alloc ((obj)->arena, (size), __FILE__, __LINE__)\
                      : malloc (size))

/**
 * @brief SOCKET_MUTEX_ARENA_CALLOC - Allocate zeroed memory
 * @param obj Pointer to struct containing SOCKET_MUTEX_ARENA_FIELDS
 * @param count Number of elements
 * @param size Size per element
 *
 * Returns: Allocated zeroed pointer or NULL on failure
 */
#define SOCKET_MUTEX_ARENA_CALLOC(obj, count, size)                           \
        ((obj)->arena ? Arena_calloc ((obj)->arena, (count), (size),          \
                                      __FILE__, __LINE__)                     \
                      : calloc ((count), (size)))

/**
 * @brief SOCKET_MUTEX_ARENA_FREE - Free if malloc mode (no-op for arena)
 * @param obj Pointer to struct containing SOCKET_MUTEX_ARENA_FIELDS
 * @param ptr Pointer to free
 *
 * Only frees if arena == NULL (malloc mode). Arena memory is freed
 * when the arena is disposed.
 */
#define SOCKET_MUTEX_ARENA_FREE(obj, ptr)                                     \
        do                                                                    \
          {                                                                   \
            if ((obj)->arena == NULL && (ptr) != NULL)                        \
              {                                                               \
                free (ptr);                                                   \
              }                                                               \
          }                                                                   \
        while (0)

/* ============================================================================
 * IP ADDRESS UTILITY FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Safely copy IP address string with null termination
 * @ingroup utilities
 *
 * Copies IP address from src to dest with guaranteed null-termination.
 * Prevents buffer overflows by limiting copy to max_len-1 bytes and
 * always null-terminating the result.
 *
 * @param[out] dest Destination buffer (must be at least max_len bytes)
 * @param[in] src Source IP string to copy
 * @param[in] max_len Maximum size of destination buffer
 *
 * @threadsafe Yes - no shared state
 *
 * @complexity O(min(strlen(src), max_len)) - linear in string length
 *
 * Usage:
 *   char ip_buf[SOCKET_IP_MAX_LEN];
 *   socket_util_safe_copy_ip(ip_buf, client_ip, sizeof(ip_buf));
 *
 * @note Truncates src if it exceeds max_len-1 characters
 * @warning dest must be at least max_len bytes to avoid buffer overflow
 *
 * @see SOCKET_IP_MAX_LEN for standard IP buffer size
 * @see strncpy(3) for underlying copy mechanism
 */
static inline void
socket_util_safe_copy_ip (char *dest, const char *src, size_t max_len)
{
  if (max_len == 0)
    return;
  strncpy (dest, src, max_len - 1);
  dest[max_len - 1] = '\0';
}

/**
 * socket_util_safe_strncpy - Safe string copy with guaranteed null-termination
 * @dest: Destination buffer
 * @src: Source string to copy
 * @max_len: Maximum size of destination buffer (including null terminator)
 *
 * Copies up to max_len-1 characters from src to dest and always null-terminates.
 * Prevents buffer overflow by design. Truncates if source exceeds max_len-1.
 *
 * @threadsafe Yes - no shared state
 *
 * @complexity O(min(strlen(src), max_len)) - linear in string length
 *
 * Usage:
 *   char buf[256];
 *   socket_util_safe_strncpy(buf, user_input, sizeof(buf));
 *
 * @note Truncates src if it exceeds max_len-1 characters
 * @warning dest must be at least max_len bytes to avoid buffer overflow
 *
 * @see strncpy(3) for underlying copy mechanism
 */
static inline void
socket_util_safe_strncpy (char *dest, const char *src, size_t max_len)
{
  if (max_len == 0)
    return;
  strncpy (dest, src, max_len - 1);
  dest[max_len - 1] = '\0';
}

#endif /* SOCKETUTIL_INCLUDED */
