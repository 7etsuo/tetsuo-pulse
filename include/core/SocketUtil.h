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
#include <string.h>

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
 * SocketMetrics_reset - Reset all metrics to zero
 * Thread-safe: Yes
 */
void SocketMetrics_reset (void);

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
void SocketEvent_unregister (SocketEventCallback callback, void *userdata);

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

/* Default log component (overridable before including this header) */
#ifndef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "Socket"
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

#endif /* SOCKETUTIL_INCLUDED */

