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
 * Allows applications to override the default stdout/stderr logging with a
 custom
 * handler for integration with file systems, syslog, structured logging
 (JSON),
 * or monitoring tools like ELK or Splunk. The callback receives every log
 message
 * emitted by the library across all modules and threads.
 *
 * Key behaviors:
 * - Global effect: Affects all SocketLog_emit*() calls after registration.
 * - Synchronous invocation: Called directly from emitting thread; must be
 non-blocking.
 * - Filtering integration: Respects global SocketLog_getlevel() threshold.
 * - Context enrichment: Callbacks can access thread-local SocketLogContext for
 *   trace IDs, request IDs, and connection FDs to correlate logs.
 *
 * Edge cases and best practices:
 * - Heavy callbacks may block event loops; use async queues or batching for
 production.
 * - No reentrancy guarantee; avoid logging from within callback to prevent
 recursion.
 * - Userdata is passed verbatim; application owns memory management and
 lifetime.
 * - Default fallback: If NULL, uses timestamped console output with level
 prefixes.
 *
 * Typical usage: Register early in application init after parsing config
 (e.g., log file path).
 * For structured logging, also set SocketLog_setstructuredcallback() for field
 support.

 * @param[in] callback Callback function or NULL for default logger.
 * @param[in] userdata Opaque user data passed unchanged to callback on every
 invocation.
 *
 * @threadsafe Yes - internal lock protects registration; effective immediately
 across threads.
 *
 * @return void
 *
 * @threadsafe Yes - internal lock protects registration; effective immediately
 across threads.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Custom logger to file with timestamps
 * static void file_logger(void *userdata, SocketLogLevel level,
 *                         const char *component, const char *message) {
 *   FILE *logfile = (FILE *)userdata;
 *   if (!logfile) return;  // Safety check
 *
 *   time_t now = time(NULL);
 *   struct tm *tm_info = localtime(&now);
 *   char timebuf[32];
 *   strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);
 *
 *   const SocketLogContext *ctx = SocketLog_getcontext();
 *   fprintf(logfile, "[%s] [%s] %s %s: %s", timebuf,
 SocketLog_levelname(level),
 *           component ? component : "unknown", ctx && ctx->trace_id[0] ?
 ctx->trace_id : "no-trace",
 *           message ? message : "(null)");
 *   fputc('\n', logfile);
 *   fflush(logfile);
 * }
 *
 * // Registration in application startup
 * TRY {
 *   FILE *logf = fopen("app_socket.log", "a");
 *   if (logf) {
 *     SocketLog_setcallback(file_logger, logf);
 *     SocketLog_setlevel(SOCKET_LOG_INFO);  // Production level
 *     SOCKET_LOG_INFO_MSG("Custom logging initialized to file");
 *   }
 * } EXCEPT (Socket_Failed) {
 *   // Handle file open failure
 *   fprintf(stderr, "Failed to open log file: %s\n", Socket_GetLastError());
 * } END_TRY;
 * @endcode
 *
 * ## Advanced Usage with Error Handling and Cleanup
 *
 * @code{.c}
 * // With cleanup in shutdown
 * static FILE *g_logfile = NULL;
 *
 * static void shutdown_logger(void) {
 *   if (g_logfile) {
 *     SocketLog_setcallback(NULL, NULL);  // Restore default
 *     fclose(g_logfile);
 *     g_logfile = NULL;
 *   }
 * }
 *
 * // In main: atexit(shutdown_logger);
 * // Register as above
 * @endcode
 *
 * @note The default logger outputs to stderr for ERROR/FATAL, stdout for
 others.
 * @note Callback invoked even for filtered levels? No, filtered before
 callback.
 * @warning Manage userdata lifetime; library won't free it or track ownership.
 * @warning Synchronous calls: Slow callbacks can impact library performance.
 * @complexity O(1) - constant time registration, no allocation or loops.
 *
 * @see SocketLogCallback for the exact function signature and parameters.
 * @see SocketLog_getcallback() to retrieve or verify the current registered
 callback.
 * @see SocketLogContext for accessing trace and connection info inside
 callback.
 * @see SocketLog_setlevel() to control which levels reach the callback.
 * @see SocketLog_setstructuredcallback() for separate handling of structured
 logs.
 * @see SocketLog_emitf() and SOCKET_LOG_*_MSG macros that trigger the
 callback.
 * @see docs/LOGGING.md for full logging subsystem guide and best practices.
 * @see @ref foundation for metrics and error utilities integrated with
 logging.
 */
void SocketLog_setcallback (SocketLogCallback callback, void *userdata);

/**
 * @brief Retrieve the currently registered custom logging callback and its
 * userdata.
 * @ingroup foundation
 *
 * Queries the global logging callback previously set via
 * SocketLog_setcallback(). Useful for verification, dynamic reconfiguration,
 * or integration with config systems. Returns the active callback function and
 * optionally populates userdata pointer. If no custom callback set, returns
 * the internal default logger reference.
 *
 * Behavior details:
 * - Thread-safe read: Safe to call from any thread without blocking.
 * - Default return: Points to static default_logger; do not free or modify.
 * - Userdata output: If provided, sets to the userdata passed in
 * setcallback(); may be NULL.
 * - Immediate reflection: Sees changes from SocketLog_setcallback()
 * atomically.
 *
 * Edge cases: Calling before any setcallback() returns default. Userdata NULL
 * if not set. Typical use: In config reload to check/restore state, or logging
 * system introspection.
 *
 * @param[out] userdata Pointer to receive the userdata associated with current
 * callback (may be NULL; not modified if param NULL).
 *
 * @return Pointer to current SocketLogCallback, or internal default if none
 * registered.
 *
 * @throws None - pure query function, no allocations or side effects.
 *
 * @threadsafe Yes - atomic read or lock-free; no blocking or state change.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Verify logging configuration at startup or reload
 * void verify_logging_config(void) {
 *   void **ud_ptr = NULL;  // Not interested in userdata
 *   SocketLogCallback cb = SocketLog_getcallback(&ud_ptr);
 *   if (cb == default_logger) {  // Assume default_logger defined or check
 *     SOCKET_LOG_WARN_MSG("No custom logger set; using default console
 * output");
 *     // Optionally set one
 *     SocketLog_setcallback(custom_logger, some_ud);
 *   } else {
 *     void *ud = ud_ptr ? *ud_ptr : NULL;
 *     SOCKET_LOG_INFO_MSG("Custom logger active with userdata %p", ud);
 *   }
 * }
 *
 * // In main after potential config changes
 * verify_logging_config();
 * @endcode
 *
 * ## Retrieving Userdata for Dynamic Behavior
 *
 * @code{.c}
 * // Get userdata to access logger-specific config
 * void *logger_ud = NULL;
 * SocketLogCallback cb = SocketLog_getcallback(&logger_ud);
 * if (logger_ud) {
 *   // Cast to app-specific struct, e.g., LoggerConfig *cfg = logger_ud;
 *   // Adjust levels or rotate files based on cfg
 *   if (cfg->max_size_reached) rotate_log_file(cfg);
 * }
 * @endcode
 *
 * @note Returned callback pointer remains valid until next setcallback(); do
 * not free.
 * @note Default logger is static internal; applications should not call it
 * directly.
 * @note Userdata is exactly as passed to setcallback(); may be NULL even if cb
 * custom.
 * @warning Do not modify userdata through output param; it's read-only view.
 * @complexity O(1) - direct access to global state, no loops or allocations.
 *
 * @see SocketLog_setcallback() complementary setter function.
 * @see SocketLogCallback type definition for signature.
 * @see default_logger internal fallback (not public).
 * @see SocketLogContext usable in callbacks retrieved this way.
 * @see docs/LOGGING.md for logging configuration management.
 */
SocketLogCallback SocketLog_getcallback (void **userdata);

/**
 * @brief SocketLog_levelname - Human-readable string for SocketLogLevel enum.
 * @ingroup foundation

 *
 * Converts log level enum to static string for logging, UI display, or config
 * parsing. Enables readable output in logs, metrics labels, or error messages.
 *
 * Returns:
 * - "TRACE" for SOCKET_LOG_TRACE
 * - "DEBUG" for SOCKET_LOG_DEBUG
 * - "INFO" for SOCKET_LOG_INFO
 * - "WARN" for SOCKET_LOG_WARN
 * - "ERROR" for SOCKET_LOG_ERROR
 * - "FATAL" for SOCKET_LOG_FATAL
 *
 * Usage:
 *   SocketLogLevel lvl = SocketLog_getlevel();
 *   const char *name = SocketLog_levelname(lvl);
 *   SocketLog_emit_structured(SOCKET_LOG_INFO, "Config", "Log level set",
 *                             SOCKET_LOG_FIELDS({"level", name}));
 *
 * @param level Log level enum value.
 * @return Static const string (e.g., "INFO"); never NULL.
 * @threadsafe Yes - returns static readonly data.
 * @note Strings are uppercase English; extend for i18n if needed.
 * @see SocketLogLevel enum for values and semantics.
 * @see SocketLog_setlevel() for level configuration.
 * @see SocketLog_getlevel() to get current level.
 * @see SocketLog_emit*() functions that may use level names internally.
 * @see docs/LOGGING.md for logging configuration and levels.
 */
const char *SocketLog_levelname (SocketLogLevel level);

/**
 * @brief Emit a log message.

 * @param level Log level.
 * @param component Component name (may be NULL).
 * @param message Log message (may be NULL).
 * @threadsafe Yes
 */
/**
 * @brief Emit a plain log message without formatting or variable arguments.
 * @ingroup foundation
 *
 * @param level Log severity level (e.g., SOCKET_LOG_INFO).
 * @param component Component or module name for categorization (may be NULL
 * for default "Socket").
 * @param message Fixed log message string (may be NULL, logged as empty
 * string).
 * @threadsafe Yes - synchronized emission to callback or default handler.
 *
 * Dispatches the message to the registered SocketLogCallback or default stdout
 * logger. Automatically filtered by global minimum level from
 * SocketLog_setlevel(). Includes thread-local SocketLogContext data if set,
 * for correlation.
 *
 * Best for static messages; use SocketLog_emitf() for dynamic content.
 *
 * @return void
 * @see SocketLog_emitf() for formatted variant.
 * @see SocketLog_emit_structured() for key-value metadata.
 * @see SocketLog_setlevel() to control filtering.
 * @see SocketLogCallback for custom handling.
 * @see SocketLogContext for auto-included thread metadata.
 * @see docs/LOGGING.md for subsystem overview and examples.
 * @note No formatting performed; message should be pre-formatted if needed.
 * @note Integrates with SocketMetrics for log-related counters if emitted.
 */
void SocketLog_emit (SocketLogLevel level, const char *component,
                     const char *message);

/**
 * @brief Emit a formatted log message using printf-style variable arguments.
 * @ingroup foundation

 * @param level Log level.
 * @param component Component name.
 * @param fmt Printf-style format string.
 * @param ... Format arguments.
 * @threadsafe Yes
 * @return void
 *
 * Performs safe formatting using internal buffer, then emits to registered
 callback
 * or default logger. Supports common printf specifiers; limits length to
 prevent
 * DoS from excessive args. Automatically includes thread-local
 SocketLogContext
 * for tracing and correlation IDs.
 *
 * Use via convenience macros like SOCKET_LOG_INFO_MSG() which define component
 * and expand to this function. Essential for dynamic logging in hot paths.
 *
 * @warning fmt must be a compile-time literal string to prevent format string
 * vulnerabilities (e.g., %x, %n exploits with user input). Validate or escape
 * user data in arguments, not fmt.
 * @note Truncates long messages; failure in formatting logs internal error.
 * @note Filtered by global SocketLog_getlevel(); lower levels suppressed.
 * @see SocketLog_emit() for non-formatted logs.
 * @see SocketLog_emitfv() va_list variant for wrappers.
 * @see SocketLog_emit_structured() for structured/metadata logs.
 * @see SOCKET_LOG_*_MSG macros for module-specific usage.
 * @see SocketLog_setcallback() for output customization.
 * @see SocketLogContext auto-appended metadata.
 * @see docs/LOGGING.md security and performance guidelines.
 * @see @ref foundation for related utilities like SocketMetrics.
 */
void SocketLog_emitf (SocketLogLevel level, const char *component,
                      const char *fmt, ...);

/**
 * @brief Emit formatted log message using va_list for arguments.
 * @ingroup foundation

 * @param level Log level.
 * @param component Component name.
 * @param fmt Printf-style format string.
 * @param args Format arguments as va_list.
 * @threadsafe Yes
 * @return void
 *
 * Identical to SocketLog_emitf() but accepts pre-prepared va_list for
 * functions that need to forward variable arguments (e.g., logging wrappers,
 * error handlers). Performs formatting and emission with same safety checks,
 * filtering, and context integration.
 *
 * Use when va_list is available from caller; avoids variadic overhead.
 * Same security requirement: fmt literal only.
 *
 * @warning fmt must be compile-time literal; same risks as emitf().
 * @note Does not consume or modify args; valid until callback completes.
 * @see SocketLog_emitf() primary variadic version.
 * @see SocketLog_emit() non-formatted.
 * @see SocketLog_emit_structured() structured alternative.
 * @see docs/LOGGING.md for advanced usage.
 * @see SocketLog_setcallback() for output routing.
 */
void SocketLog_emitfv (SocketLogLevel level, const char *component,
                       const char *fmt, va_list args);

/**
 * @brief SocketLog_setlevel - Configure global minimum log level threshold.
 * @ingroup foundation

 *
 * Filters log emissions by severity, suppressing verbose messages in
 production
 * while enabling detailed tracing in development. Thread-safe update with
 * immediate effect on all subsequent logs across threads (via atomic or
 mutex).
 *
 * Levels from verbose to critical:
 * - SOCKET_LOG_TRACE: Ultra-verbose (internal state changes)
 * - SOCKET_LOG_DEBUG: Debugging info (function entry/exit, params)
 * - SOCKET_LOG_INFO: Normal operations (connections, requests)
 * - SOCKET_LOG_WARN: Recoverable issues (retries, timeouts)
 * - SOCKET_LOG_ERROR: Errors (failed ops, exceptions)
 * - SOCKET_LOG_FATAL: Critical failures (abort imminent)
 *
 * Global effect: Applies to all modules using SocketLog_emit*(). Change via
 * config file, env var, or runtime API. Persists until changed or process
 exit.
 *
 * Best Practices:
 * - Production: SOCKET_LOG_WARN or higher to reduce noise.
 * - Development: SOCKET_LOG_DEBUG for troubleshooting.
 * - Use SocketLog_getlevel() to read current for conditional logging.
 * - Integrate with SocketHTTPClient_config for per-client levels if needed.
 *
 * Example:
 *   // Runtime adjustment
 *   SocketLog_setlevel(SOCKET_LOG_DEBUG);  // Verbose mode
 *   // Or from config/env
 *   if (getenv("SOCKET_LOG_LEVEL")) {
 *     SocketLogLevel lvl = SocketLog_method_parse(getenv("SOCKET_LOG_LEVEL"));
 // Assume parse func
 *     SocketLog_setlevel(lvl);
 *   }
 *   const char *current = SocketLog_levelname(SocketLog_getlevel());
 *   SocketLog_emit(SOCKET_LOG_INFO, "Config", "Log level set to %s", current);
 *
 * @param min_level New minimum level (SOCKET_LOG_TRACE = most verbose).
 * @threadsafe Yes - atomic update or mutex-protected.
 * @return void (no return; errors logged internally).
 * @note Default: SOCKET_LOG_INFO; set early in main() or init.
 * @note Dynamic change safe; no restart needed.
 * @see SocketLog_getlevel() to query current threshold.
 * @see SocketLog_levelname() for string representation.
 * @see SocketLogLevel enum for level definitions.
 * @see SocketLog_emit*() functions affected by this setting.
 * @see docs/LOGGING.md for advanced configuration and integration.
 * @see @ref SocketConfig for global config management including logs.
 * @note Affects SocketLog_emit*() calls after invocation; pending buffered
 logs unaffected.
 */
extern void SocketLog_setlevel (SocketLogLevel min_level);

/**
 * @brief Retrieve the active global minimum log level threshold.
 * @ingroup foundation

 * @return Current global SocketLogLevel threshold (e.g., SOCKET_LOG_WARN).
 * @threadsafe Yes - atomic or mutex-protected read.
 * @return Current global SocketLogLevel threshold (e.g., SOCKET_LOG_WARN).
 *
 * Queries the minimum severity for log emission. Logs below this level are
 suppressed.
 * Useful for runtime configuration checks or conditional detailed logging.
 * Reflects last call to SocketLog_setlevel() or default (SOCKET_LOG_INFO).
 *
 * Example:
 *   if (SocketLog_getlevel() <= SOCKET_LOG_DEBUG) {
 *     SOCKET_LOG_DEBUG_MSG("Detailed state: %d", state);
 *   }
 *
 * @see SocketLog_setlevel() to configure.
 * @see SocketLogLevel enum definitions.
 * @see SocketLog_levelname() for string conversion.
 * @see docs/LOGGING.md configuration details.
 * @note Global value; changes affect all threads immediately.
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
 * @brief SocketLogContext - Thread-local logging context for correlation.
 * @ingroup foundation

 *
 * Thread-local structure for adding correlation data to logs, enabling
 * distributed tracing, request tracking, and connection-specific logging.
 * Custom logging callbacks (SocketLogCallback or SocketLogStructuredCallback)
 * can access this structure via SocketLog_getcontext() to include fields
 * like trace_id, request_id, and connection_fd in log output (e.g., as JSON).
 *
 * Usage pattern:
 *   SocketLogContext ctx = {0};
 *   strncpy(ctx.trace_id, trace_uuid, sizeof(ctx.trace_id) - 1);
 *   ctx.connection_fd = sock_fd;
 *   SocketLog_setcontext(&ctx);
 *   // ... perform operations - logs now include context ...
 *   SocketLog_clearcontext();  // Or let it persist for thread lifetime
 *
 * @see SocketLog_setcontext() to establish context for current thread.
 * @see SocketLog_getcontext() to retrieve current context in callbacks.
 * @see SocketLog_clearcontext() to reset context.
 * @see SocketLogStructuredCallback for structured logging integration.
 * @see SocketEvent_emit_*() functions automatically set connection_fd.
 */
typedef struct SocketLogContext
{
  char trace_id[SOCKET_LOG_ID_SIZE]; /**< Distributed trace ID (e.g., UUID) */
  char request_id[SOCKET_LOG_ID_SIZE]; /**< Request-specific ID */
  int connection_fd; /**< Associated file descriptor (-1 if none) */
} SocketLogContext;

/**
 * @brief Set thread-local logging context for request tracing and metadata.
 * @ingroup foundation

 * @param ctx Context to copy (NULL clears context).
 * @threadsafe Yes - thread-local storage (TLS), no locks or races.
 * @return void
 *
 * Copies ctx into per-thread storage for use by subsequent SocketLog_emit*()
 * calls in this thread. Custom callbacks can access via SocketLog_getcontext()
 * to enrich logs with trace_id (e.g., UUID), request_id, or connection_fd.
 * NULL ctx clears to defaults (empty strings, fd=-1).
 *
 * Pattern for request handling:
 *   SocketLogContext ctx = { .connection_fd = sock_fd };
 *   snprintf(ctx.trace_id, sizeof(ctx.trace_id), "%llx", generate_trace());
 *   SocketLog_setcontext(&ctx);
 *   // ... process request with contextual logs ...
 *   SocketLog_clearcontext(); // Or let persist per thread
 *
 * @note Fixed-size strings; caller must null-terminate and fit within limits.
 * @note Context visible only to current thread; inter-thread via app logic.
 * @see SocketLog_getcontext() retrieval in callbacks.
 * @see SocketLog_clearcontext() reset equivalent to set(NULL).
 * @see SocketLogContext fields details.
 * @see SocketLogStructuredCallback for field usage in structured logs.
 * @see docs/LOGGING.md tracing integration.
 * @see SocketEvent_emit_* auto-setting connection_fd for events.
 */
extern void SocketLog_setcontext (const SocketLogContext *ctx);

/**
 * @brief Retrieve pointer to current thread's logging context.
 * @ingroup foundation

 * @return Const pointer to thread-local SocketLogContext or NULL if unset.
 * @threadsafe Yes - direct read from TLS, read-only access.
 * @return Const pointer to thread-local SocketLogContext or NULL if unset.
 *
 * For use in custom SocketLogCallback or SocketLogStructuredCallback to
 * append context fields (trace_id, request_id, connection_fd) to log output.
 * Enables distributed tracing, request correlation, and per-connection
 logging.
 * Returned pointer remains valid until next set/clear in this thread.
 * Do not free or mutate; structure owned by logging subsystem.
 *
 * Example in callback:
 *   const SocketLogContext *ctx = SocketLog_getcontext();
 *   if (ctx) {
 *     fprintf(stream, "[%s] fd=%d %s\n", ctx->trace_id ?: "none",
 *             ctx->connection_fd, message);
 *   }
 *
 * @note NULL if never set or cleared; check before deref.
 * @note Fields may be empty strings or -1; validate as needed.
 * @see SocketLog_setcontext() to populate.
 * @see SocketLog_clearcontext() to NULLify.
 * @see SocketLogContext field semantics.
 * @see docs/LOGGING.md for callback patterns.
 * @see SocketLogStructuredCallback context param.
 */
extern const SocketLogContext *SocketLog_getcontext (void);

/**
 * @brief Reset thread-local logging context to default state.
 * @ingroup foundation

 * @threadsafe Yes - local TLS update, no synchronization.
 * @return void
 *
 * Clears current thread's logging context by setting all fields to defaults:
 * trace_id and request_id to empty strings, connection_fd to -1.
 * Ensures no leakage of previous request data to subsequent logs.
 * Idempotent; safe to call multiple times.
 *
 * Recommended after completing request/connection handling to isolate logs.
 * Alternative to SocketLog_setcontext(NULL); slightly more explicit.
 *
 * @see SocketLog_setcontext(NULL) functional equivalent.
 * @see SocketLog_getcontext() to verify cleared (returns non-NULL but empty).
 * @see SocketLogContext default values.
 * @see docs/LOGGING.md context management patterns.
 * @note Does not affect global log level or callbacks.
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
 * @brief SocketLogField - Key-value pair for structured logging.
 * @ingroup foundation

 *
 * Simple key-value structure for attaching metadata to log messages.
 * Used by SocketLog_emit_structured() to enable machine-readable output.
 * Keys are field names (e.g., "status_code", "response_time_ms", "user_id").
 * Values are pre-formatted strings (numbers as strings, escaped JSON if
 needed).
 *
 * Lifetime: Keys and values must remain valid until the structured log
 callback
 * completes. Do not pass stack strings that may go out of scope.
 *
 * Example usage with SOCKET_LOG_FIELDS macro:
 *   SocketLog_emit_structured(SOCKET_LOG_INFO, "HTTP", "Request processed",
 *                             SOCKET_LOG_FIELDS(
 *                                 {"method", "GET"},
 *                                 {"status", "200"},
 *                                 {"bytes", "1024"},
 *                                 {"user_agent", ua_str}
 *                             ));
 *
 * @see SocketLog_emit_structured() for emitting structured logs.
 * @see SocketLogStructuredCallback for processing fields in callbacks.
 * @see SOCKET_LOG_FIELDS() convenience macro for array initialization.
 * @see SocketLogContext for additional thread-local metadata.
 * @note For security, avoid logging sensitive data in fields (use
 secureclear).
 * @note Integrates with SocketMetrics for performance fields like latencies.
 */
typedef struct SocketLogField
{
  const char *key;   /**< Field name (e.g., "fd", "bytes", "peer") */
  const char *value; /**< Field value as string */
} SocketLogField;

/**
 * @brief Typedef for callback handling structured logs with key-value fields
 and context.
 * @ingroup foundation

 *
 * Extended variant of SocketLogCallback that receives metadata fields
 separately
 * for machine-readable output formats like JSON or logfmt. Invoked by
 * SocketLog_emit_structured() when registered via
 SocketLog_setstructuredcallback().
 *
 * @param userdata User-provided opaque context passed during registration.
 * @param level Log severity level (SOCKET_LOG_TRACE to SOCKET_LOG_FATAL).
 * @param component String identifying emitting module or subsystem (non-NULL).
 * @param message Descriptive event string (non-NULL, may be empty).
 * @param fields Pointer to array of SocketLogField structs or NULL if none.
 * @param field_count Number of valid fields in array (0 if fields NULL).
 * @param context Pointer to current thread's SocketLogContext or NULL.
 * @threadsafe Conditional - implementor must handle concurrency if userdata
 shared.
 *
 * Guidelines:
 * - Validate NULL fields/context before access to avoid crashes.
 * - Fields values are caller-provided strings; lifetime until callback
 returns.
 * - Format output as needed (JSON, key=value pairs, etc.); no default
 formatting.
 * - Integrate with external systems like ELK stack or Prometheus for
 observability.
 *
 * @see SocketLog_setstructuredcallback() to register this callback.
 * @see SocketLog_emit_structured() emission trigger.
 * @see SocketLogField for field structure.
 * @see SocketLogContext for context details.
 * @see SocketLogCallback base callback fallback.
 * @see docs/LOGGING.md for examples and integration.
 * @note Fields array not copied; valid only during call.
 * @note Prefer for new code; enables better tooling and analysis.
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
 * @brief SocketMetric - Enumeration of library-wide performance and
 operational metrics.
 * @ingroup foundation

 *
 * These metrics track key events across all modules for monitoring, alerting,
 * and performance analysis. Use SocketMetrics_increment() to update counters
 * from module code. Snapshots via SocketMetrics_getsnapshot() provide atomic
 * reads for reporting.
 *
 * Categories:
 * - Socket connections (success/failure, shutdowns)
 * - DNS resolution (requests, completions, failures, timeouts)
 * - Event polling (wakeups, dispatched events)
 * - Connection pooling (adds, removes, reuses, health checks, drains)
 *
 * Integration: Emit metrics in hot paths with minimal overhead (atomic ops).
 * Export snapshots to Prometheus, StatsD, or custom telemetry systems.
 *
 * @see SocketMetrics_increment() to update counters.
 * @see SocketMetrics_getsnapshot() for atomic reads.
 * @see SocketMetrics_name() for human-readable labels.
 * @see SocketMetrics_count() for enum size.
 * @see @ref utilities for related retry and rate-limit metrics.
 * @see docs/METRICS.md for usage guidelines and best practices.
 * @note Thread-safe; use in async callbacks and worker threads.
 * @note SOCKET_METRIC_COUNT must match values[] size in snapshot.
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
 * @brief SocketMetricsSnapshot - Thread-safe snapshot of all library metrics.
 * @ingroup foundation

 *
 * Structure holding atomic copies of all SocketMetric counters. Obtained via
 * SocketMetrics_getsnapshot() for reporting without contention. Array values[]
 * indexed by SocketMetric enum (size SOCKET_METRIC_COUNT).
 *
 * Usage:
 *   SocketMetricsSnapshot snap;
 *   SocketMetrics_getsnapshot(&snap);
 *   // Export snap.values[SOCKET_METRIC_SOCKET_CONNECT_SUCCESS] etc.
 *   // Or use SocketMetrics_snapshot_value(&snap, metric) helper.
 *
 * Thread Safety: Snapshot is atomic read; safe to access from any thread
 * after acquisition. No locking needed for reading snapshot contents.
 *
 * Export Patterns:
 * - Prometheus: Counter metrics with labels for module/component.
 * - StatsD: Increment during runtime, flush snapshots periodically.
 * - Logging: Structured logs with snapshot deltas for audits.
 *
 * @see SocketMetrics_getsnapshot() to capture current state.
 * @see SocketMetrics_snapshot_value() inline accessor.
 * @see SocketMetric for counter indices and descriptions.
 * @see SocketMetrics_increment() for updating underlying counters.
 * @see docs/METRICS.md for integration examples and best practices.
 * @note Size fixed by SOCKET_METRIC_COUNT; adding metrics requires
 recompilation.
 * @note Use unsigned long long for 64-bit counters supporting high-volume
 systems.
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
 * @brief Event emission functions - Thread-safe notification of key socket
 * events.
 * @ingroup foundation
 *
 * These functions emit events to registered callbacks for observability,
 * metrics, tracing, and alerting integration. Events are dispatched
 * asynchronously from worker threads or main event loops to avoid blocking.
 *
 * @see SocketEvent_register() to register global event handlers.
 * @see SocketEventCallback for the callback signature.
 * @see SocketEventRecord for the event data structure.
 * @see SocketEvent_unregister() to remove handlers.
 * @see SocketLogContext for correlating events with per-connection logs.
 */

/**
 * @brief Emit new connection accept event.
 * @ingroup foundation
 * @param fd Newly accepted client file descriptor.
 * @param peer_addr Peer IP address as null-terminated C string (IPv4/IPv6).
 * @param peer_port Peer port number (host byte order).
 * @param local_addr Local bound IP address as null-terminated C string.
 * @param local_port Local listening port number (host byte order).
 * @threadsafe Yes - invokes callbacks with mutex protection.
 * @note Caller must ensure strings remain valid until all callbacks complete.
 * @note Automatically sets SocketLogContext.connection_fd for the event.
 * @see SocketEvent_register() to handle accept events (e.g., for metrics).
 * @see SocketPool_add() to immediately add connection to managed pool.
 * @see Socket_accept() for the underlying accept operation.
 * @see Socket_getpeeraddr() and Socket_getpeerport() for address queries.
 */
void SocketEvent_emit_accept (int fd, const char *peer_addr, int peer_port,
                              const char *local_addr, int local_port);

/**
 * @brief Emit successful outbound connection event.
 * @ingroup foundation
 * @param fd Connected socket file descriptor.
 * @param peer_addr Remote peer IP address as null-terminated C string.
 * @param peer_port Remote peer port number (host byte order).
 * @param local_addr Local source IP address as null-terminated C string.
 * @param local_port Local ephemeral source port (host byte order).
 * @threadsafe Yes - invokes callbacks with mutex protection.
 * @note Caller must ensure strings remain valid until callbacks complete.
 * @note Sets SocketLogContext.connection_fd for event correlation.
 * @see SocketEvent_register() to handle connect events.
 * @see SocketReconnect_state() integration for auto-reconnect scenarios.
 * @see Socket_connect() or SocketTLS_handshake() for connection establishment.
 * @see Socket_getlocaladdr() for local address retrieval.
 */
void SocketEvent_emit_connect (int fd, const char *peer_addr, int peer_port,
                               const char *local_addr, int local_port);

/**
 * @brief Emit DNS resolution timeout event.
 * @ingroup foundation
 * @param host Hostname or address that timed out during resolution.
 * @param port Destination port associated with the DNS request (for context).
 * @threadsafe Yes
 * @see SocketEvent_register() to handle DNS timeout events.
 * @see SocketDNS_resolve() for initiating async DNS lookups.
 * @see SocketDNS_settimeout() to configure DNS operation timeouts.
 * @see SocketHappyEyeballs for parallel resolution strategies.
 * @see SocketMetrics_increment(SOCKET_METRIC_DNS_REQUEST_TIMEOUT) for metrics.
 */
void SocketEvent_emit_dns_timeout (const char *host, int port);

/**
 * @brief Emit poll/epoll/kqueue wakeup event (for performance monitoring).
 * @ingroup foundation
 * @param nfds Number of file descriptors monitored in the poll set.
 * @param timeout_ms Timeout value passed to poll() or equivalent ( -1 =
 * infinite).
 * @threadsafe Yes
 * @note Primarily for debugging high-frequency wakeups or timeout tuning.
 * @see SocketEvent_register() to monitor poll performance.
 * @see SocketPoll_wait() for the underlying polling mechanism.
 * @see SocketPoll_getregisteredcount() to correlate with registered FDs.
 * @see SocketTimer for timer-driven wakeups.
 * @see SocketMetrics_increment(SOCKET_METRIC_POLL_WAKEUPS) for metrics
 * tracking.
 */
void SocketEvent_emit_poll_wakeup (int nfds, int timeout_ms);

/* ============================================================================
 * ERROR HANDLING SUBSYSTEM
 * ============================================================================
 */

/**
 * @brief SocketErrorCode - Normalized error codes mapping POSIX errno values.
 * @ingroup foundation

 *
 * Enumeration providing a library-specific abstraction over platform errno
 * values. Maps common socket-related errors to consistent codes for uniform
 * handling across modules. Enables retry logic, categorization, and logging
 * without direct errno dependencies.
 *
 * Key Mappings:
 * - SOCKET_ERROR_EAGAIN / SOCKET_ERROR_EWOULDBLOCK: Non-blocking operation
 would block (retryable)
 * - SOCKET_ERROR_ECONNREFUSED: Connection refused (network/transient)
 * - SOCKET_ERROR_ETIMEDOUT: Operation timed out (retryable with backoff)
 * - SOCKET_ERROR_ENOMEM: Memory allocation failed (resource exhaustion)
 * - SOCKET_ERROR_EADDRINUSE: Address already in use (configuration)
 * - SOCKET_ERROR_EINVAL: Invalid argument (programming error)
 * - And others for network, protocol, resource errors.
 *
 * Usage:
 *   if (Socket_geterrorcode() == SOCKET_ERROR_ECONNREFUSED) {
 *       // Implement exponential backoff retry
 *   }
 *   SocketErrorCategory cat = SocketError_categorize_errno(errno);
 *
 * @see Socket_geterrorcode() to retrieve normalized code from last error.
 * @see SocketError_categorize_errno() for high-level classification.
 * @see SocketError_is_retryable_errno() to check retry eligibility.
 * @see Socket_safe_strerror() for safe error string conversion.
 * @see docs/ERROR_HANDLING.md for error patterns and exception raising.
 * @note Extensible: Add new codes for library-specific errors (e.g., TLS
 errors).
 * @note Platform-agnostic: Abstracts Windows WSA errors to POSIX equivalents.
 * @note Integrates with SOCKET_RAISE_* macros for exception throwing.
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
      strncpy (socket_error_buf, tmp_buf, SOCKET_ERROR_BUFSIZE - 1);          \
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
      strncpy (socket_error_buf, tmp_buf, SOCKET_ERROR_BUFSIZE - 1);          \
      socket_error_buf[SOCKET_ERROR_BUFSIZE - 1] = '\0';                      \
      SOCKET_ERROR_APPLY_TRUNCATION (_socket_error_ret);                      \
      (void)_socket_error_ret;                                                \
      SocketLog_emit (SOCKET_LOG_ERROR, SOCKET_LOG_COMPONENT,                 \
                      socket_error_buf);                                      \
    }                                                                         \
  while (0)

/**
 * @brief Socket_GetLastError - Retrieve the most recent formatted error
 message.
 * @ingroup foundation

 *
 * Returns pointer to thread-local buffer containing the last error
 description,
 * formatted via SOCKET_ERROR_FMT() or SOCKET_ERROR_MSG() macros. Includes
 errno
 * details, system messages, and custom context (e.g., "bind failed on fd=3:
 Address in use").
 *
 * Buffer Management:
 * - Thread-local: Each thread has independent buffer, no synchronization
 needed.
 * - Overwritten on next error: Capture immediately after error condition.
 * - Truncation-safe: Long messages append "[truncated]" marker.
 * - Lifetime: Buffer valid until next error in same thread.
 *
 * Typical Usage:
 *   if (some_socket_op() < 0) {
 *       const char *err = Socket_GetLastError();
 *       SocketLog_emit(SOCKET_LOG_ERROR, MODULE, "%s", err);
 *       // Or raise exception with SOCKET_RAISE_MSG()
 *   }
 *
 * @return Const pointer to null-terminated error string (never NULL, empty on
 no error).
 * @threadsafe Yes - returns thread-local static buffer.
 * @note Do not free or modify returned string.
 * @note Integrates with Except_T for detailed exception reasons.
 * @see Socket_geterrno() for raw errno value.
 * @see Socket_geterrorcode() for normalized SocketErrorCode.
 * @see Socket_safe_strerror() for raw errno strings.
 * @see SOCKET_ERROR_FMT() / SOCKET_ERROR_MSG() macros for formatting.
 * @see SOCKET_RAISE_FMT() / SOCKET_RAISE_MSG() for exception integration.
 * @see docs/ERROR_HANDLING.md for full error patterns.
 */
extern const char *Socket_GetLastError (void);

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
#endif
/**
 * @brief Socket_geterrno - Retrieve the raw POSIX errno from the last system
 * call error.
 * @ingroup foundation
 * Returns the errno value captured at the last error condition (via
 * SOCKET_ERROR_* macros or manual socket_last_errno = errno). Thread-local
 * storage ensures per-thread isolation without locks.
 *
 * Use after failed system calls, library functions, or when errno is set.
 * Example:
 *   int err = Socket_geterrno();
 *   if (err == EAGAIN) {
 *     // Handle non-blocking case (retryable)
 *   } else {
 *     SocketLog_error("Error: %s", Socket_safe_strerror(err));
 *   }
 *
 * @return Last errno (platform-specific, 0 if no error recorded).
 * @threadsafe Yes - thread-local.
 * @note Persists until overwritten; not auto-reset.
 * @note Windows: Maps WSAGetLastError() to POSIX errno equivalents.
 * @see Socket_GetLastError() for descriptive message.
 * @see Socket_geterrorcode() for SocketErrorCode mapping.
 * @see Socket_safe_strerror(err) for string conversion.
 * @see SocketError_categorize_errno(err) for category.
 * @see SocketError_is_retryable_errno(err) for retry logic.
 * @see docs/ERROR_HANDLING.md for errno best practices.
 */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
extern int Socket_geterrno (void);

/**
 * @brief Socket_geterrorcode - Convert last errno to normalized
 SocketErrorCode.
 * @ingroup foundation

 *
 * Maps the raw errno from Socket_geterrno() to SocketErrorCode enum for
 * platform-agnostic error handling. Facilitates switch statements, policy
 * decisions, and logging without errno-specific code.
 *
 * Example policy logic:
 *   SocketErrorCode code = Socket_geterrorcode();
 *   switch (code) {
 *     case SOCKET_ERROR_ETIMEDOUT:
 *       // Exponential backoff retry via SocketRetry
 *       break;
 *     case SOCKET_ERROR_EINVAL:
 *       RAISE(Socket_InvalidArg);  // Using SOCKET_RAISE_MSG
 *       break;
 *     case SOCKET_ERROR_ENOMEM:
 *       Arena_clear(global_arena); // Mitigate resource issue
 *       break;
 *     default:
 *       SocketLog_emitf(SOCKET_LOG_WARN, "Unhandled error code %d", code);
 *   }
 *
 * @return Mapped SocketErrorCode (SOCKET_ERROR_UNKNOWN if no mapping).
 * @threadsafe Yes - stateless mapping.
 * @see Socket_geterrno() source of raw errno.
 * @see SocketErrorCode for enum values and errno mappings.
 * @see SocketError_categorize_errno() higher-level abstraction.
 * @see SocketError_is_retryable_errno() quick retry check.
 * @see SOCKET_RAISE_FMT() macros that integrate error codes.
 * @see @ref SocketHTTP and @ref SocketTLS for protocol-specific extensions.
 * @see docs/ERROR_HANDLING.md for mapping tables and patterns.
 * @note Covers 90%+ of socket errnos; unmapped fall to UNKNOWN.
 * @note Windows compatibility: WSA to POSIX translation.
 */

extern SocketErrorCode Socket_geterrorcode (void);

/**
 * @brief Socket_safe_strerror - Secure, thread-safe errno to string
 conversion.
 * @ingroup foundation

 *
 * Provides strerror_r-like functionality with thread-local buffer to prevent
 * races and buffer overflows common in strerror(). Handles invalid/unknown
 * errnos gracefully, supports Windows WSA errors, and avoids locale
 dependencies.
 *
 * Key Features:
 * - Thread-safe: Per-thread buffer, no shared state or locks.
 * - Overflow-safe: Fixed buffer with truncation handling.
 * - Portable: POSIX errno + Windows WSA error translation.
 * - Defensive: Returns "Unknown error" for invalid errnum (<0 or excessive).
 *
 * Example:
 *   int err = errno;
 *   const char *msg = Socket_safe_strerror(err);
 *   SocketLog_emitf(SOCKET_LOG_ERROR, "Operation failed: %s (errno=%d)", msg,
 err);
 *   // Safe in multi-threaded servers, signal handlers (if no malloc needed).
 *
 * Performance: Faster than strerror_r in contended scenarios; suitable for hot
 paths.
 *
 * @param errnum errno or WSA error code to convert (0 = "Success").
 * @return Const pointer to descriptive string (e.g., "No such file or
 directory").
 * @threadsafe Yes - thread-local buffer.
 * @note Buffer overwritten on next call in thread; copy if needed.
 * @note Does not modify errno; pure function.
 * @see Socket_GetLastError() for rich, contextual messages.
 * @see Socket_geterrno() to obtain current errno.
 * @see Socket_geterrorcode() for enum abstraction.
 * @see SocketError_categorize_errno(errnum) for error type.
 * @see docs/ERROR_HANDLING.md for strerror patterns and alternatives.
 * @note Avoid dynamic allocation in signal-safe contexts on some platforms.
 * @note Customizable buffer size via SOCKET_ERROR_BUFSIZE (default 256).
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
 * @brief SocketErrorCategory - High-level classification of error types for
 policy decisions.
 * @ingroup foundation

 *
 * Abstracts errno and SocketErrorCode into semantic categories to guide error
 * handling, retry policies, alerting, and logging strategies across modules.
 * Enables uniform treatment of similar errors regardless of platform or cause.
 *
 * Category Behaviors:
 * - @ref SOCKET_ERROR_CATEGORY_NETWORK: Transient network issues (e.g.,
 ECONNRESET,
 *   ENETUNREACH) - usually retryable with backoff.
 * - @ref SOCKET_ERROR_CATEGORY_PROTOCOL: Malformed data or unsupported
 protocols
 *   (e.g., EINVAL in parsing) - typically fatal or requires client fix.
 * - @ref SOCKET_ERROR_CATEGORY_APPLICATION: Business logic errors (e.g., auth
 failures,
 *   4xx HTTP) - propagate to app layer.
 * - @ref SOCKET_ERROR_CATEGORY_TIMEOUT: Time-bound operations exceeded
 (ETIMEDOUT)
 *   - retryable, but watch for cascading failures.
 * - @ref SOCKET_ERROR_CATEGORY_RESOURCE: System limits hit (ENOMEM, EMFILE) -
 may
 *   self-resolve or require scaling.
 * - @ref SOCKET_ERROR_CATEGORY_UNKNOWN: Uncategorized (log and handle
 conservatively).
 *
 * Usage in Modules:
 *   SocketErrorCategory cat = SocketError_categorize_errno(errno);
 *   if (cat == SOCKET_ERROR_CATEGORY_NETWORK) {
 *       SocketRetry_attempt_with_backoff(...);
 *   } else if (cat == SOCKET_ERROR_CATEGORY_RESOURCE) {
 *       SocketLog_emit(SOCKET_LOG_WARN, "Resource limit hit", fields);
 *       // Trigger pool drain or config alert
 *   }
 *
 * @see SocketError_categorize_errno() to classify raw errno values.
 * @see SocketError_is_retryable_errno() for quick retry checks.
 * @see Socket_geterrorcode() for normalized error codes.
 * @see SOCKET_RAISE_* macros to raise categorized exceptions.
 * @see @ref SocketRetry for backoff policies based on category.
 * @see docs/ERROR_HANDLING.md for comprehensive error strategies.
 * @see docs/SECURITY.md for security implications of error categories.
 * @note Categories are conservative; custom modules can extend via
 SocketErrorCode.
 * @note Thread-safe pure functions; use in signal handlers if needed.
 * @note Maps Windows WSA errors to equivalent POSIX categories.
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
 * @brief SocketError_categorize_errno - Classify errno into
 SocketErrorCategory.
 * @ingroup foundation

 *
 * Pure function mapping raw errno to high-level SocketErrorCategory for policy
 * decisions like retry, alert, or propagate. Conservative classification
 * prioritizing safety and observability.
 *
 * Detailed Mappings (POSIX errno examples):
 * - NETWORK (retryable/transient): ECONNREFUSED, ECONNRESET, ECONNABORTED,
 *   ENETUNREACH, EHOSTUNREACH, ENETDOWN, EPIPE, ENOTCONN, EHOSTDOWN
 * - TIMEOUT (backoff retry): ETIMEDOUT, operation deadline exceeded
 * - RESOURCE (scale/relieve): ENOMEM, EMFILE, ENFILE, ENOBUFS, ENOSPC, EAGAIN
 (resource form)
 * - PROTOCOL (fix input/config): EINVAL, EPROTO, EPROTONOSUPPORT,
 EAFNOSUPPORT, EISCONN, EALREADY
 * - APPLICATION: Passed through for module-specific (e.g., HTTP 4xx)
 * - UNKNOWN: Rare or platform-specific; log for analysis
 *
 * Usage in Error Handling:
 *   int err = errno;  // Or Socket_geterrno()
 *   SocketErrorCategory cat = SocketError_categorize_errno(err);
 *   if (cat == SOCKET_ERROR_CATEGORY_NETWORK || cat ==
 SOCKET_ERROR_CATEGORY_TIMEOUT) {
 *     // Retry with backoff using SocketRetry_policy
 *   } else if (cat == SOCKET_ERROR_CATEGORY_RESOURCE) {
 *     SocketMetrics_increment(SOCKET_METRIC_RESOURCE_EXHAUSTED);
 *     // Alert or drain pools
 *   }
 *   SocketLog_emit_structured(SOCKET_LOG_WARN, MODULE, "Error categorized",
 *                             SOCKET_LOG_FIELDS({"category",
 SocketError_category_name(cat)},
 *                                               {"errno", "%d", err}));
 *
 * Extension: Modules can use category in custom exceptions or rate limiting.
 *
 * @param err errno value to classify (0 or positive; negative treated as
 UNKNOWN).
 * @return Appropriate SocketErrorCategory (UNKNOWN for unmapped).
 * @threadsafe Yes - pure function, no state.
 * @note Optimizes common cases with switch or table lookup for speed.
 * @note Windows: Translates WSA errors to POSIX errno before classification.
 * @see SocketErrorCategory for category behaviors and retry guidelines.
 * @see SocketError_is_retryable_errno(err) complementary check.
 * @see Socket_geterrorcode() for finer-grained enum.
 * @see SocketError_category_name(cat) for string representation.
 * @see @ref SocketRateLimit for category-based throttling.
 * @see @ref SocketPool for resource error handling in pools.
 * @see docs/ERROR_HANDLING.md for full categorization table and strategies.
 * @see docs/SECURITY.md for secure error handling (avoid info leaks).
 * @note Pure function: Deterministic, side-effect free, suitable for
 fuzzing/tests.
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

#endif /* SOCKETUTIL_INCLUDED */
