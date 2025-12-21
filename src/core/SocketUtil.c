/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* Core utility subsystems: error handling, logging, metrics, events */

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


/* Flag for one-time CLOCK_MONOTONIC fallback warning */
static volatile int monotonic_fallback_warned = 0;

/* Fail instead of falling back to CLOCK_REALTIME (default: 0 for compat) */
#ifndef SOCKET_MONOTONIC_STRICT
#define SOCKET_MONOTONIC_STRICT 0
#endif

/* Preferred monotonic clock sources in priority order */
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

static int64_t
socket_timespec_to_ms (const struct timespec *ts)
{
  return (int64_t)ts->tv_sec * SOCKET_MS_PER_SECOND
         + (int64_t)ts->tv_nsec / SOCKET_NS_PER_MS;
}

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

/* Emit one-time warning for clock fallback (benign race on flag) */
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

#define NUM_ERROR_MAPPINGS                                                    \
  (sizeof (error_mappings) / sizeof (error_mappings[0]))
#define NUM_ERROR_CATEGORIES 6
#define NUM_LOG_LEVELS 6

/* O(n) linear scan of ~30 entries - acceptable for small table */
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

const char *
Socket_GetLastError (void)
{
  return socket_error_buf;
}

int
Socket_geterrno (void)
{
  return socket_last_errno;
}

SocketErrorCode
Socket_geterrorcode (void)
{
  return socket_errno_to_errorcode (socket_last_errno);
}

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


static const char *const socket_error_category_names[] = {
  "NETWORK", "PROTOCOL", "APPLICATION", "TIMEOUT", "RESOURCE", "UNKNOWN"
};

SocketErrorCategory
SocketError_categorize_errno (int err)
{
  const SocketErrorMapping *m = socket_find_error_mapping (err);
  return m ? m->category : SOCKET_ERROR_CATEGORY_UNKNOWN;
}

const char *
SocketError_category_name (SocketErrorCategory category)
{
  if (category < 0 || (size_t)category >= NUM_ERROR_CATEGORIES)
    return "UNKNOWN";
  return socket_error_category_names[category];
}

int
SocketError_is_retryable_errno (int err)
{
  const SocketErrorMapping *m = socket_find_error_mapping (err);
  return m ? m->retryable : 0;
}


/* Mutex protecting callback, userdata, and log level */
static pthread_mutex_t socketlog_mutex = PTHREAD_MUTEX_INITIALIZER;
static SocketLogCallback socketlog_callback = NULL;
static void *socketlog_userdata = NULL;
static SocketLogLevel socketlog_min_level = SOCKET_LOG_INFO;

static SocketLogStructuredCallback socketlog_structured_callback = NULL;
static void *socketlog_structured_userdata = NULL;

static const char *const default_level_names[]
    = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL" };

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

/* WARNING: fmt must be a compile-time literal to prevent format string attacks */
void
SocketLog_emitf (SocketLogLevel level, const char *component, const char *fmt,
                 ...)
{
  va_list args;

  va_start (args, fmt);
  SocketLog_emitfv (level, component, fmt, args);
  va_end (args);
}

/* Appends "..." to indicate message was truncated */
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

/* WARNING: fmt must be a compile-time literal to prevent format string attacks */
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

/* Appends " key=value" if field valid and space available */
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

/* Formats fields as " key1=value1 key2=value2" (with leading space) */
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

/* Formats fields as " key=value" appended to message copy, then calls fallback */
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

/* Dispatches to structured callback if available, else formats fields into fallback */
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

 * NOTE: Legacy system for backward compatibility. Prefer SocketMetrics.h.
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

static inline int
socketmetrics_legacy_is_valid (const SocketMetric metric)
{
  return metric >= 0 && metric < SOCKET_METRIC_COUNT;
}

/* NOTE: Legacy API. For new code, use SocketMetrics_counter_inc() */
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

  }
}

/* NOTE: Legacy API. For new code, use SocketMetrics_get() */
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

/* NOTE: Legacy API. For new code, use SocketMetrics_reset() */
void
SocketMetrics_legacy_reset (void)
{
  SocketMetrics_reset_counters ();
}

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

size_t
SocketMetrics_count (void)
{
  return SOCKET_METRIC_COUNT;
}


typedef struct SocketEventHandler
{
  SocketEventCallback callback;
  void *userdata;
} SocketEventHandler;

static pthread_mutex_t socketevent_mutex = PTHREAD_MUTEX_INITIALIZER;
static SocketEventHandler socketevent_handlers[SOCKET_EVENT_MAX_HANDLERS];
static size_t socketevent_handler_count = 0;

/* Caller must hold socketevent_mutex */
static size_t
socketevent_copy_handlers_unlocked (SocketEventHandler *local_handlers)
{
  memcpy (local_handlers, socketevent_handlers,
          sizeof (SocketEventHandler) * socketevent_handler_count);
  return socketevent_handler_count;
}

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

/* Copies handlers under mutex, then invokes callbacks outside mutex */
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

/* Caller must hold socketevent_mutex */
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

/* Caller must hold socketevent_mutex */
static void
socketevent_add_handler_unlocked (SocketEventCallback callback, void *userdata)
{
  socketevent_handlers[socketevent_handler_count].callback = callback;
  socketevent_handlers[socketevent_handler_count].userdata = userdata;
  socketevent_handler_count++;
}

/* Caller must hold socketevent_mutex */
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

/* Caller must hold socketevent_mutex */
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

/* Helper to eliminate duplication in emit_accept and emit_connect */
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

void
SocketEvent_emit_accept (int fd, const char *peer_addr, int peer_port,
                         const char *local_addr, int local_port)
{
  SocketEventRecord event;

  socketevent_init_connection (&event, SOCKET_EVENT_ACCEPTED, "Socket", fd,
                               peer_addr, peer_port, local_addr, local_port);
  socketevent_dispatch (&event);
}

void
SocketEvent_emit_connect (int fd, const char *peer_addr, int peer_port,
                          const char *local_addr, int local_port)
{
  SocketEventRecord event;

  socketevent_init_connection (&event, SOCKET_EVENT_CONNECTED, "Socket", fd,
                               peer_addr, peer_port, local_addr, local_port);
  socketevent_dispatch (&event);
}

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
