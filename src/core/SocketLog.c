/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* Logging subsystem: callbacks, levels, structured logging, context */

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "core/SocketConfig.h"
#include "core/SocketLog.h"

/* Mutex protecting callback, userdata, and log level */
static pthread_mutex_t socketlog_mutex = PTHREAD_MUTEX_INITIALIZER;
static SocketLogCallback socketlog_callback = NULL;
static void *socketlog_userdata = NULL;
static SocketLogLevel socketlog_min_level = SOCKET_LOG_INFO;

static SocketLogStructuredCallback socketlog_structured_callback = NULL;
static void *socketlog_structured_userdata = NULL;

static const char *const default_level_names[]
    = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL" };

#define NUM_LOG_LEVELS (sizeof(default_level_names)/sizeof(default_level_names[0]))

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
      /* Safe strncpy equivalent - defined in SocketUtil.h but we can't include it here */
      if (bufsize > 0)
        {
          strncpy (buf, SOCKET_LOG_DEFAULT_TIMESTAMP, bufsize - 1);
          buf[bufsize - 1] = '\0';
        }
    }

  return buf;
}

/* stderr for ERROR/FATAL, stdout otherwise */
static FILE *
socketlog_get_stream (SocketLogLevel level)
{
  return level >= SOCKET_LOG_ERROR ? stderr : stdout;
}

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
  if (level < 0 || (size_t)level >= NUM_LOG_LEVELS)
    return "UNKNOWN";
  return default_level_names[level];
}

void
SocketLog_setlevel (SocketLogLevel min_level)
{
  pthread_mutex_lock (&socketlog_mutex);
  socketlog_min_level = min_level;
  pthread_mutex_unlock (&socketlog_mutex);
}

/* All logging config acquired under single lock to consolidate mutex calls */
typedef struct SocketLogAllInfo
{
  SocketLogCallback fallback_callback;
  void *fallback_userdata;
  SocketLogStructuredCallback structured_callback;
  void *structured_userdata;
  int should_log;
} SocketLogAllInfo;

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

SocketLogLevel
SocketLog_getlevel (void)
{
  SocketLogLevel level;

  pthread_mutex_lock (&socketlog_mutex);
  level = socketlog_min_level;
  pthread_mutex_unlock (&socketlog_mutex);

  return level;
}

void
SocketLog_emit (SocketLogLevel level, const char *component,
                const char *message)
{
  SocketLogAllInfo all = socketlog_acquire_all_info (level);
  if (!all.should_log)
    return;

  all.fallback_callback (all.fallback_userdata, level, component, message);
}

/* WARNING: fmt must be a compile-time literal to prevent format string attacks
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

/* WARNING: fmt must be a compile-time literal to prevent format string attacks
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

#ifdef _WIN32
static __declspec (thread) SocketLogContext socketlog_context = { "", "", -1 };
static __declspec (thread) int socketlog_context_set = 0;
#else
static __thread SocketLogContext socketlog_context = { "", "", -1 };
static __thread int socketlog_context_set = 0;
#endif

void
SocketLog_setcontext (const SocketLogContext *ctx)
{
  if (ctx == NULL)
    {
      SocketLog_clearcontext ();
      return;
    }

  memcpy (&socketlog_context, ctx, sizeof (SocketLogContext));

  /* Ensure null termination */
  socketlog_context.trace_id[SOCKET_LOG_ID_SIZE - 1] = '\0';
  socketlog_context.request_id[SOCKET_LOG_ID_SIZE - 1] = '\0';

  socketlog_context_set = 1;
}

const SocketLogContext *
SocketLog_getcontext (void)
{
  if (!socketlog_context_set)
    return NULL;

  return &socketlog_context;
}

void
SocketLog_clearcontext (void)
{
  memset (&socketlog_context, 0, sizeof (SocketLogContext));
  socketlog_context.connection_fd = -1;
  socketlog_context_set = 0;
}

void
SocketLog_setstructuredcallback (SocketLogStructuredCallback callback,
                                 void *userdata)
{
  pthread_mutex_lock (&socketlog_mutex);
  socketlog_structured_callback = callback;
  socketlog_structured_userdata = userdata;
  pthread_mutex_unlock (&socketlog_mutex);
}

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

static void
socketlog_call_structured (const SocketLogAllInfo *all, SocketLogLevel level,
                           const char *component, const char *message,
                           const SocketLogField *fields, size_t field_count)
{
  all->structured_callback (all->structured_userdata, level, component,
                            message, fields, field_count,
                            SocketLog_getcontext ());
}

static void
socketlog_call_fallback (const SocketLogAllInfo *all, SocketLogLevel level,
                         const char *component, const char *message)
{
  all->fallback_callback (all->fallback_userdata, level, component, message);
}

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
