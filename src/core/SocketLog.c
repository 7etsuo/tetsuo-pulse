#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/SocketLog.h"

static pthread_mutex_t socketlog_mutex = PTHREAD_MUTEX_INITIALIZER;
static SocketLogCallback socketlog_callback = NULL;
static void *socketlog_userdata = NULL;

static const char *default_level_names[]
    = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL" };

static void
default_logger (void *userdata, SocketLogLevel level, const char *component,
                const char *message)
{
  FILE *stream = level >= SOCKET_LOG_ERROR ? stderr : stdout;
  time_t raw = time (NULL);
  struct tm tm_buf;
  char ts[32];

  (void)userdata;

  int time_ok = 0;
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

void
SocketLog_setcallback (SocketLogCallback callback, void *userdata)
{
  pthread_mutex_lock (&socketlog_mutex);
  socketlog_callback = callback;
  socketlog_userdata = userdata;
  pthread_mutex_unlock (&socketlog_mutex);
}

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

const char *
SocketLog_levelname (SocketLogLevel level)
{
  if (level < SOCKET_LOG_TRACE || level > SOCKET_LOG_FATAL)
    return "UNKNOWN";
  return default_level_names[level];
}

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

void
SocketLog_emitf (SocketLogLevel level, const char *component, const char *fmt,
                 ...)
{
  va_list args;

  va_start (args, fmt);
  SocketLog_emitfv (level, component, fmt, args);
  va_end (args);
}

void
SocketLog_emitfv (SocketLogLevel level, const char *component, const char *fmt,
                  va_list args)
{
  char buffer[1024];

  if (!fmt)
    {
      SocketLog_emit (level, component, NULL);
      return;
    }

  vsnprintf (buffer, sizeof (buffer), fmt, args);
  SocketLog_emit (level, component, buffer);
}
