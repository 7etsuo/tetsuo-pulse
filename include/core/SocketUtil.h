#ifndef SOCKETUTIL_INCLUDED
#define SOCKETUTIL_INCLUDED

/**
 * SocketUtil.h - Consolidated utility header (Logging, Metrics, Events, Error)
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This header consolidates the observability, instrumentation, and error
 * handling utilities into a single include for cleaner dependencies.
 *
 * Provides:
 * - Logging subsystem (configurable callbacks, multiple log levels)
 * - Metrics collection (thread-safe counters, atomic snapshots)
 * - Event dispatching (connection events, DNS timeouts, poll wakeups)
 * - Error handling (thread-local buffers, errno mapping, exception macros)
 */

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"

/* ============================================================================
 * LOGGING SUBSYSTEM
 * ============================================================================ */

/**
 * SocketLogLevel - Log severity levels
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
 * SocketLogCallback - Custom logging callback function type
 * @userdata: User-provided context
 * @level: Log severity level
 * @component: Module/component name
 * @message: Log message
 */
typedef void (*SocketLogCallback) (void *userdata, SocketLogLevel level,
                                   const char *component, const char *message);

/**
 * SocketLog_setcallback - Set custom logging callback
 * @callback: Callback function or NULL for default logger
 * @userdata: User data passed to callback
 * Thread-safe: Yes
 */
void SocketLog_setcallback (SocketLogCallback callback, void *userdata);

/**
 * SocketLog_getcallback - Get current logging callback
 * @userdata: Output pointer for user data (may be NULL)
 * Returns: Current callback, or default_logger if none set
 * Thread-safe: Yes
 */
SocketLogCallback SocketLog_getcallback (void **userdata);

/**
 * SocketLog_levelname - Get string name for log level
 * @level: Log level
 * Returns: Static string with level name
 * Thread-safe: Yes
 */
const char *SocketLog_levelname (SocketLogLevel level);

/**
 * SocketLog_emit - Emit a log message
 * @level: Log level
 * @component: Component name (may be NULL)
 * @message: Log message (may be NULL)
 * Thread-safe: Yes
 */
void SocketLog_emit (SocketLogLevel level, const char *component,
                     const char *message);

/**
 * SocketLog_emitf - Emit formatted log message
 * @level: Log level
 * @component: Component name
 * @fmt: Printf-style format string
 * Thread-safe: Yes
 *
 * WARNING: fmt must be a compile-time literal to prevent format string
 * attacks. Do not use user-controlled format strings.
 */
void SocketLog_emitf (SocketLogLevel level, const char *component,
                      const char *fmt, ...);

/**
 * SocketLog_emitfv - Emit formatted log message with va_list
 * @level: Log level
 * @component: Component name
 * @fmt: Printf-style format string
 * @args: Format arguments as va_list
 * Thread-safe: Yes
 */
void SocketLog_emitfv (SocketLogLevel level, const char *component,
                       const char *fmt, va_list args);

/**
 * SocketLog_setlevel - Set minimum log level for filtering
 * @min_level: Minimum level to emit (messages below this are suppressed)
 *
 * Thread-safe: Yes (mutex protected)
 *
 * Sets the global minimum log level. Log messages with severity below
 * min_level will be silently discarded. Default is SOCKET_LOG_INFO.
 *
 * Example:
 *   SocketLog_setlevel(SOCKET_LOG_DEBUG);  // Enable debug logging
 *   SocketLog_setlevel(SOCKET_LOG_WARN);   // Only warnings and above
 */
extern void SocketLog_setlevel (SocketLogLevel min_level);

/**
 * SocketLog_getlevel - Get current minimum log level
 *
 * Returns: Current minimum log level
 * Thread-safe: Yes (mutex protected)
 */
extern SocketLogLevel SocketLog_getlevel (void);

/* Default log component - modules should override before including this header */
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
#define SOCKET_LOG_TRACE_MSG(fmt, ...)                                         \
  SocketLog_emitf (SOCKET_LOG_TRACE, SOCKET_LOG_COMPONENT, fmt, ##__VA_ARGS__)

/* Log at DEBUG level (debugging information) */
#define SOCKET_LOG_DEBUG_MSG(fmt, ...)                                         \
  SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT, fmt, ##__VA_ARGS__)

/* Log at INFO level (normal operational messages) */
#define SOCKET_LOG_INFO_MSG(fmt, ...)                                          \
  SocketLog_emitf (SOCKET_LOG_INFO, SOCKET_LOG_COMPONENT, fmt, ##__VA_ARGS__)

/* Log at WARN level (warning conditions) */
#define SOCKET_LOG_WARN_MSG(fmt, ...)                                          \
  SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT, fmt, ##__VA_ARGS__)

/* Log at ERROR level (error conditions) */
#define SOCKET_LOG_ERROR_MSG(fmt, ...)                                         \
  SocketLog_emitf (SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT, fmt, ##__VA_ARGS__)

/* Log at FATAL level (critical errors, typically before abort) */
#define SOCKET_LOG_FATAL_MSG(fmt, ...)                                         \
  SocketLog_emitf (SOCKET_LOG_FATAL, SOCKET_LOG_COMPONENT, fmt, ##__VA_ARGS__)

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
 * SocketLogContext - Thread-local logging context for correlation
 *
 * Custom logging callbacks can access this via SocketLog_getcontext()
 * to include correlation IDs in structured log output.
 */
typedef struct SocketLogContext
{
  char trace_id[SOCKET_LOG_ID_SIZE];   /**< Distributed trace ID (e.g., UUID) */
  char request_id[SOCKET_LOG_ID_SIZE]; /**< Request-specific ID */
  int connection_fd;                   /**< Associated file descriptor (-1 if none) */
} SocketLogContext;

/**
 * SocketLog_setcontext - Set thread-local logging context
 * @ctx: Context to copy (NULL clears context)
 *
 * Thread-safe: Yes (uses thread-local storage)
 *
 * Sets the logging context for the current thread. The context is
 * copied, so the caller may free or modify ctx after this call.
 */
extern void SocketLog_setcontext (const SocketLogContext *ctx);

/**
 * SocketLog_getcontext - Get thread-local logging context
 *
 * Returns: Pointer to thread-local context, or NULL if not set
 * Thread-safe: Yes (uses thread-local storage)
 *
 * Returns pointer to internal thread-local storage. Do not modify
 * the returned pointer; use SocketLog_setcontext to update.
 */
extern const SocketLogContext *SocketLog_getcontext (void);

/**
 * SocketLog_clearcontext - Clear thread-local logging context
 *
 * Thread-safe: Yes (uses thread-local storage)
 *
 * Equivalent to SocketLog_setcontext(NULL).
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
 * SocketLogField - Key-value pair for structured logging
 *
 * Both key and value must be valid for the duration of the log call.
 * Values should be pre-formatted as strings.
 */
typedef struct SocketLogField
{
  const char *key;   /**< Field name (e.g., "fd", "bytes", "peer") */
  const char *value; /**< Field value as string */
} SocketLogField;

/**
 * SocketLogStructuredCallback - Extended callback with structured fields
 * @userdata: User-provided context
 * @level: Log severity level
 * @component: Module/component name
 * @message: Log message
 * @fields: Array of key-value pairs (may be NULL)
 * @field_count: Number of fields in array
 * @context: Thread-local context (may be NULL)
 *
 * Callbacks should check for NULL fields/context before accessing.
 */
typedef void (*SocketLogStructuredCallback) (
    void *userdata, SocketLogLevel level, const char *component,
    const char *message, const SocketLogField *fields, size_t field_count,
    const SocketLogContext *context);

/**
 * SocketLog_setstructuredcallback - Set structured logging callback
 * @callback: Callback function or NULL to disable structured logging
 * @userdata: User data passed to callback
 *
 * Thread-safe: Yes (mutex protected)
 *
 * When set, SocketLog_emit_structured() will invoke this callback
 * instead of the regular callback, providing access to structured fields.
 */
extern void SocketLog_setstructuredcallback (SocketLogStructuredCallback callback,
                                             void *userdata);

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
extern void SocketLog_emit_structured (SocketLogLevel level,
                                       const char *component,
                                       const char *message,
                                       const SocketLogField *fields,
                                       size_t field_count);

/**
 * SOCKET_LOG_FIELDS - Convenience macro for creating field arrays
 *
 * Usage:
 *   SocketLog_emit_structured(level, component, message,
 *                             SOCKET_LOG_FIELDS({"key1", "val1"},
 *                                               {"key2", "val2"}));
 */
#define SOCKET_LOG_FIELDS(...)                                                 \
  (SocketLogField[]){ __VA_ARGS__ },                                           \
      (sizeof ((SocketLogField[]){ __VA_ARGS__ }) / sizeof (SocketLogField))

/* ============================================================================
 * METRICS SUBSYSTEM
 * ============================================================================ */

/**
 * SocketMetric - Metrics enumeration
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
 * SocketMetricsSnapshot - Atomic snapshot of all metric values
 */
typedef struct SocketMetricsSnapshot
{
  unsigned long long values[SOCKET_METRIC_COUNT];
} SocketMetricsSnapshot;

/**
 * SocketMetrics_increment - Increment a metric counter
 * @metric: Metric to increment
 * @value: Amount to add
 * Thread-safe: Yes
 */
void SocketMetrics_increment (SocketMetric metric, unsigned long value);

/**
 * SocketMetrics_getsnapshot - Get atomic snapshot of all metrics
 * @snapshot: Output structure to receive metric values
 * Thread-safe: Yes
 */
void SocketMetrics_getsnapshot (SocketMetricsSnapshot *snapshot);

/**
 * SocketMetrics_legacy_reset - Reset legacy metrics to zero
 * Thread-safe: Yes
 *
 * NOTE: This is the legacy API. For new code, use SocketMetrics_reset()
 * from SocketMetrics.h.
 */
void SocketMetrics_legacy_reset (void);

/**
 * SocketMetrics_name - Get human-readable name for a metric
 * @metric: Metric to get name for
 * Returns: Static string with metric name
 * Thread-safe: Yes
 */
const char *SocketMetrics_name (SocketMetric metric);

/**
 * SocketMetrics_count - Get total number of defined metrics
 * Returns: Number of metrics
 * Thread-safe: Yes
 */
size_t SocketMetrics_count (void);

/**
 * SocketMetrics_snapshot_value - Get a specific value from snapshot
 * @snapshot: Snapshot to read from
 * @metric: Metric to retrieve
 * Returns: Metric value, or 0 for invalid inputs
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
 * ============================================================================ */

/**
 * SocketEventType - Event type enumeration
 */
typedef enum SocketEventType
{
  SOCKET_EVENT_ACCEPTED = 0,
  SOCKET_EVENT_CONNECTED,
  SOCKET_EVENT_DNS_TIMEOUT,
  SOCKET_EVENT_POLL_WAKEUP
} SocketEventType;

/**
 * SocketEventRecord - Event data structure
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
 * SocketEventCallback - Event handler callback type
 * @userdata: User-provided context
 * @event: Event record
 */
typedef void (*SocketEventCallback) (void *userdata,
                                     const SocketEventRecord *event);

/**
 * SocketEvent_register - Register an event handler
 * @callback: Callback function to register
 * @userdata: User data passed to callback
 * Thread-safe: Yes
 */
void SocketEvent_register (SocketEventCallback callback, void *userdata);

/**
 * SocketEvent_unregister - Unregister an event handler
 * @callback: Callback function to unregister
 * @userdata: User data that was passed to register
 * Thread-safe: Yes
 */
void SocketEvent_unregister (SocketEventCallback callback, const void *userdata);

/**
 * Event emission functions - Thread-safe
 */
void SocketEvent_emit_accept (int fd, const char *peer_addr, int peer_port,
                              const char *local_addr, int local_port);
void SocketEvent_emit_connect (int fd, const char *peer_addr, int peer_port,
                               const char *local_addr, int local_port);
void SocketEvent_emit_dns_timeout (const char *host, int port);
void SocketEvent_emit_poll_wakeup (int nfds, int timeout_ms);

/* ============================================================================
 * ERROR HANDLING SUBSYSTEM
 * ============================================================================ */

/**
 * SocketErrorCode - Error code enumeration mapping common errno values
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
 * SOCKET_ERROR_APPLY_TRUNCATION - Apply truncation marker if message was cut
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
 * SOCKET_ERROR_FMT - Format error message with errno information
 * Includes truncation protection for long messages.
 */
#define SOCKET_ERROR_FMT(fmt, ...)                                            \
  do                                                                          \
    {                                                                         \
      socket_last_errno = errno;                                              \
      int _socket_error_ret = snprintf (                                      \
          socket_error_buf, SOCKET_ERROR_BUFSIZE, fmt " (errno: %d - %s)",    \
          ##__VA_ARGS__, socket_last_errno,                                   \
          Socket_safe_strerror (socket_last_errno));                          \
      SOCKET_ERROR_APPLY_TRUNCATION (_socket_error_ret);                      \
      (void)_socket_error_ret;                                                \
      SocketLog_emit (SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT,                 \
                      socket_error_buf);                                      \
    }                                                                         \
  while (0)

/**
 * SOCKET_ERROR_MSG - Format error message without errno
 * Includes truncation protection for long messages.
 */
#define SOCKET_ERROR_MSG(fmt, ...)                                            \
  do                                                                          \
    {                                                                         \
      socket_last_errno = errno;                                              \
      int _socket_error_ret = snprintf (                                      \
          socket_error_buf, SOCKET_ERROR_BUFSIZE, fmt, ##__VA_ARGS__);        \
      SOCKET_ERROR_APPLY_TRUNCATION (_socket_error_ret);                      \
      (void)_socket_error_ret;                                                \
      SocketLog_emit (SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT,                 \
                      socket_error_buf);                                      \
    }                                                                         \
  while (0)

/**
 * Socket_GetLastError - Get the last error message
 * Returns: Pointer to thread-local error message buffer
 * Thread-safe: Yes
 */
extern const char *Socket_GetLastError (void);

/**
 * Socket_geterrno - Get the last captured errno value
 * Returns: Last errno value (0 if no error)
 * Thread-safe: Yes
 */
extern int Socket_geterrno (void);

/**
 * Socket_geterrorcode - Get the last error as SocketErrorCode
 * Returns: SocketErrorCode enum value
 * Thread-safe: Yes
 */
extern SocketErrorCode Socket_geterrorcode (void);

/**
 * Socket_safe_strerror - Thread-safe strerror implementation
 * @errnum: Error number to convert
 * Returns: Thread-local string describing the error
 * Thread-safe: Yes
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
 * Centralized Exception Infrastructure
 * ============================================================================ */

/**
 * SOCKET_DECLARE_MODULE_EXCEPTION - Declare thread-local exception
 * @module_name: Module name (e.g., Socket, SocketBuf, SocketPoll)
 */
#define SOCKET_DECLARE_MODULE_EXCEPTION(module_name)                           \
  static __thread Except_T module_name##_DetailedException

/**
 * SOCKET_RAISE_MODULE_ERROR - Raise module-specific exception
 * @module_name: Module name
 * @exception: Exception to raise
 * Thread-safe: Creates thread-local copy with detailed reason
 */
#define SOCKET_RAISE_MODULE_ERROR(module_name, exception)                      \
  do                                                                           \
    {                                                                          \
      module_name##_DetailedException = (exception);                           \
      module_name##_DetailedException.reason = socket_error_buf;               \
      RAISE (module_name##_DetailedException);                                 \
    }                                                                          \
  while (0)

/* ============================================================================
 * Unified Error + Raise Macros (Eliminates Redundant Patterns)
 * ============================================================================ */

/**
 * SOCKET_RAISE_FMT - Format error with errno and raise exception in one step
 * @module_name: Module name for exception
 * @exception: Exception to raise
 * @fmt: Printf-style format string
 * @...: Format arguments
 *
 * Combines SOCKET_ERROR_FMT + RAISE_MODULE_ERROR into single macro.
 * Thread-safe: Yes (uses thread-local buffers)
 */
#define SOCKET_RAISE_FMT(module_name, exception, fmt, ...)                     \
  do                                                                           \
    {                                                                          \
      SOCKET_ERROR_FMT (fmt, ##__VA_ARGS__);                                   \
      SOCKET_RAISE_MODULE_ERROR (module_name, exception);                      \
    }                                                                          \
  while (0)

/**
 * SOCKET_RAISE_MSG - Format error message and raise exception in one step
 * @module_name: Module name for exception
 * @exception: Exception to raise
 * @fmt: Printf-style format string (without errno)
 * @...: Format arguments
 *
 * Combines SOCKET_ERROR_MSG + RAISE_MODULE_ERROR into single macro.
 * Thread-safe: Yes (uses thread-local buffers)
 */
#define SOCKET_RAISE_MSG(module_name, exception, fmt, ...)                     \
  do                                                                           \
    {                                                                          \
      SOCKET_ERROR_MSG (fmt, ##__VA_ARGS__);                                   \
      SOCKET_RAISE_MODULE_ERROR (module_name, exception);                      \
    }                                                                          \
  while (0)

/**
 * Helper macros for common module patterns - use RAISE_MODULE_ERROR macro
 * defined in each module that sets module_name appropriately.
 *
 * Example module setup:
 *   SOCKET_DECLARE_MODULE_EXCEPTION(MyModule);
 *   #define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(MyModule, e)
 *   #define RAISE_FMT(e, fmt, ...) SOCKET_RAISE_FMT(MyModule, e, fmt, ##__VA_ARGS__)
 *   #define RAISE_MSG(e, fmt, ...) SOCKET_RAISE_MSG(MyModule, e, fmt, ##__VA_ARGS__)
 */

/* ============================================================================
 * TIME UTILITIES (Consolidated monotonic clock functions)
 * ============================================================================ */

/**
 * Socket_get_monotonic_ms - Get current monotonic time in milliseconds
 *
 * Returns: Current monotonic time in milliseconds since arbitrary epoch
 * Thread-safe: Yes (no shared state)
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
 * ============================================================================ */

/**
 * socket_util_hash_fd - Hash file descriptor using golden ratio multiplicative
 * @fd: File descriptor to hash (non-negative)
 * @table_size: Hash table size (should be prime for best distribution)
 *
 * Returns: Hash value in range [0, table_size)
 * Thread-safe: Yes (pure function, no shared state)
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
 * socket_util_hash_ptr - Hash pointer using golden ratio multiplicative
 * @ptr: Pointer to hash (may be NULL)
 * @table_size: Hash table size (should be prime for best distribution)
 *
 * Returns: Hash value in range [0, table_size)
 * Thread-safe: Yes (pure function, no shared state)
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
 * socket_util_hash_uint - Hash unsigned integer using golden ratio
 * @value: Unsigned integer to hash
 * @table_size: Hash table size (should be prime for best distribution)
 *
 * Returns: Hash value in range [0, table_size)
 * Thread-safe: Yes (pure function, no shared state)
 *
 * General-purpose hash for unsigned integers including request IDs.
 */
static inline unsigned
socket_util_hash_uint (unsigned value, unsigned table_size)
{
  return (value * HASH_GOLDEN_RATIO) % table_size;
}

/** DJB2 hash algorithm seed value (Daniel J. Bernstein) */
#define SOCKET_UTIL_DJB2_SEED 5381u

/**
 * socket_util_hash_djb2 - Hash string using DJB2 algorithm
 * @str: String to hash (must not be NULL)
 * @table_size: Hash table size (should be prime for best distribution)
 *
 * Returns: Hash value in range [0, table_size)
 * Thread-safe: Yes (pure function, no shared state)
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
 * socket_util_hash_djb2_len - Hash string with explicit length using DJB2
 * @str: String to hash (may contain null bytes)
 * @len: Length of string
 * @table_size: Hash table size (should be prime for best distribution)
 *
 * Returns: Hash value in range [0, table_size)
 * Thread-safe: Yes (pure function, no shared state)
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
 * socket_util_hash_djb2_ci - Case-insensitive DJB2 hash
 * @str: String to hash (must not be NULL)
 * @table_size: Hash table size (should be prime for best distribution)
 *
 * Returns: Hash value in range [0, table_size)
 * Thread-safe: Yes (pure function, no shared state)
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
 * socket_util_hash_djb2_ci_len - Case-insensitive length-aware DJB2 hash
 * @str: String to hash (may contain null bytes)
 * @len: Length of string
 * @table_size: Hash table size (should be prime for best distribution)
 *
 * Returns: Hash value in range [0, table_size)
 * Thread-safe: Yes (pure function, no shared state)
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
 * socket_util_round_up_pow2 - Round up to next power of 2
 * @n: Value to round up (must be > 0)
 *
 * Returns: Smallest power of 2 >= n
 * Thread-safe: Yes (pure function)
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
 * ============================================================================ */

/**
 * socket_util_arena_strdup - Duplicate string into arena
 * @arena: Arena for allocation
 * @str: String to duplicate (may be NULL)
 *
 * Returns: Duplicated string in arena, or NULL if str is NULL or alloc fails
 * Thread-safe: Yes (if arena is thread-safe)
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
 * socket_util_arena_strndup - Duplicate string with max length into arena
 * @arena: Arena for allocation
 * @str: String to duplicate (may be NULL)
 * @maxlen: Maximum characters to copy (excluding null terminator)
 *
 * Returns: Duplicated string in arena, or NULL if str is NULL or alloc fails
 * Thread-safe: Yes (if arena is thread-safe)
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

#endif /* SOCKETUTIL_INCLUDED */

