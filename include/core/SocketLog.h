/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETLOG_INCLUDED
#define SOCKETLOG_INCLUDED

/**
 * @file SocketLog.h
 * @ingroup foundation
 * @brief Logging subsystem with configurable callbacks and structured logging.
 *
 * Provides:
 * - Configurable logging callbacks
 * - Multiple log levels (TRACE through FATAL)
 * - Structured logging with key-value fields
 * - Thread-local context for distributed tracing
 *
 * @see SocketLogLevel for severity levels
 * @see SocketLogCallback for custom log handlers
 * @see @ref foundation for other core utilities
 */

#include <stdarg.h>
#include <stddef.h>

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
 *
 * @callback: Callback function or NULL to disable structured logging
 * @userdata: User data passed to callback
 *
 * @brief Thread-safe: Yes (mutex protected)
 *
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
 *
 * @level: Log level
 * @component: Component name
 * @message: Log message
 * @fields: Array of key-value pairs (may be NULL)
 * @field_count: Number of fields
 *
 * @threadsafe Yes
 *
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
 *
 * Usage:
 *   SocketLog_emit_structured(level, component, message,
 *                             SOCKET_LOG_FIELDS({"key1", "val1"},
 *                                               {"key2", "val2"}));
 */
#define SOCKET_LOG_FIELDS(...)                                                \
  (SocketLogField[]){ __VA_ARGS__ },                                          \
      (sizeof ((SocketLogField[]){ __VA_ARGS__ }) / sizeof (SocketLogField))

#endif /* SOCKETLOG_INCLUDED */
