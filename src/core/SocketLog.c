/**
 * SocketLog.c - Logging subsystem
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Provides configurable logging with callback support. Allows applications
 * to integrate socket library logging with their own logging infrastructure.
 *
 * FEATURES:
 * - Configurable log callback
 * - Multiple log levels (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)
 * - Default stderr/stdout logging
 * - Thread-safe callback management
 * - Format string support
 *
 * THREAD SAFETY:
 * - Callback get/set operations are mutex protected
 * - Logging operations are thread-safe
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/SocketConfig.h"
#include "core/SocketLog.h"

/* Mutex protecting callback and userdata */
static pthread_mutex_t socketlog_mutex = PTHREAD_MUTEX_INITIALIZER;
static SocketLogCallback socketlog_callback = NULL;
static void *socketlog_userdata = NULL;

/* Level names for display */
static const char *default_level_names[]
    = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL" };

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
  FILE *stream = level >= SOCKET_LOG_ERROR ? stderr : stdout;
  time_t raw = time (NULL);
  struct tm tm_buf;
  char ts[32];
  int time_ok = 0;

  (void)userdata;

#ifdef _WIN32
  if (localtime_s (&tm_buf, &raw) == 0)
    time_ok = 1;
#else
  if (localtime_r (&raw, &tm_buf) != NULL)
    time_ok = 1;
#endif

  if (time_ok)
    {
      if (strftime (ts, sizeof (ts), "%Y-%m-%d %H:%M:%S", &tm_buf) == 0)
        strncpy (ts, "1970-01-01 00:00:00", sizeof (ts));
    }
  else
    {
      strncpy (ts, "1970-01-01 00:00:00", sizeof (ts));
    }

  fprintf (stream, "%s [%s] %s: %s\n", ts, SocketLog_levelname (level),
           component ? component : "(unknown)", message ? message : "(null)");
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

  if (!callback)
    callback = default_logger;

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
