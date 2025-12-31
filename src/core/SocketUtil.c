/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* Core utility subsystems: time utilities and legacy metrics bridge */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "core/SocketConfig.h"
#include "core/SocketLog.h"
#include "core/SocketMetrics.h"
#include "core/SocketUtil.h"

/* ============================================================================
 * TIME UTILITIES
 * ============================================================================
 */

/* Flag for one-time CLOCK_MONOTONIC fallback warning */
static volatile int monotonic_fallback_warned = 0;

/* Fail instead of falling back to CLOCK_REALTIME (default: 0 for compat) */
#ifndef SOCKET_MONOTONIC_STRICT
#define SOCKET_MONOTONIC_STRICT 0
#endif

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

#define PREFERRED_CLOCKS_COUNT \
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
      SocketLog_emit (SOCKET_LOG_WARN,
                      "Socket",
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
  SocketLog_emit (SOCKET_LOG_ERROR,
                  "Socket",
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

/* ============================================================================
 * LEGACY METRICS BRIDGE
 * ============================================================================
 */

/* NOTE: Legacy system for backward compatibility. Prefer SocketMetrics.h. */

static const SocketCounterMetric legacy_to_counter[SOCKET_METRIC_COUNT] = {
  [SOCKET_METRIC_SOCKET_CONNECT_SUCCESS] = SOCKET_CTR_SOCKET_CONNECT_SUCCESS,
  [SOCKET_METRIC_SOCKET_CONNECT_FAILURE] = SOCKET_CTR_SOCKET_CONNECT_FAILED,
  [SOCKET_METRIC_SOCKET_SHUTDOWN_CALL]
  = SOCKET_CTR_SOCKET_CLOSED, /* approximate */
  [SOCKET_METRIC_DNS_REQUEST_SUBMITTED] = SOCKET_CTR_DNS_QUERIES_TOTAL,
  [SOCKET_METRIC_DNS_REQUEST_COMPLETED] = SOCKET_CTR_DNS_QUERIES_COMPLETED,
  [SOCKET_METRIC_DNS_REQUEST_FAILED] = SOCKET_CTR_DNS_QUERIES_FAILED,
  [SOCKET_METRIC_DNS_REQUEST_CANCELLED] = SOCKET_CTR_DNS_QUERIES_CANCELLED,
  [SOCKET_METRIC_DNS_REQUEST_TIMEOUT] = SOCKET_CTR_DNS_QUERIES_TIMEOUT,
  [SOCKET_METRIC_POLL_WAKEUPS] = SOCKET_CTR_POLL_WAKEUPS,
  [SOCKET_METRIC_POLL_EVENTS_DISPATCHED] = SOCKET_CTR_POLL_EVENTS_DISPATCHED,
  [SOCKET_METRIC_POOL_CONNECTIONS_ADDED] = SOCKET_CTR_POOL_CONNECTIONS_CREATED,
  [SOCKET_METRIC_POOL_CONNECTIONS_REMOVED]
  = SOCKET_CTR_POOL_CONNECTIONS_DESTROYED,
  [SOCKET_METRIC_POOL_CONNECTIONS_REUSED] = SOCKET_CTR_POOL_CONNECTIONS_REUSED,
  [SOCKET_METRIC_POOL_DRAIN_INITIATED] = SOCKET_CTR_POOL_DRAIN_STARTED,
  [SOCKET_METRIC_POOL_DRAIN_COMPLETED] = SOCKET_CTR_POOL_DRAIN_COMPLETED,
  [SOCKET_METRIC_POOL_HEALTH_CHECKS]
  = SOCKET_COUNTER_UNMAPPED, /* unmapped, add if needed */
  [SOCKET_METRIC_POOL_HEALTH_FAILURES] = SOCKET_COUNTER_UNMAPPED,
  [SOCKET_METRIC_POOL_VALIDATION_FAILURES] = SOCKET_COUNTER_UNMAPPED,
  [SOCKET_METRIC_POOL_IDLE_CLEANUPS] = SOCKET_COUNTER_UNMAPPED,
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
      SocketLog_emitf (SOCKET_LOG_WARN,
                       "SocketMetrics",
                       "Invalid metric %d in increment ignored",
                       (int)metric);
      return;
    }

  SocketCounterMetric new_metric = legacy_to_counter[metric];
  if (new_metric != SOCKET_COUNTER_UNMAPPED)
    {
      SocketMetrics_counter_add (new_metric, (uint64_t)value);
    }
  else
    {
      SocketLog_emitf (SOCKET_LOG_WARN,
                       "SocketMetrics",
                       "Unmapped legacy metric %s (%d) ignored; consider "
                       "migrating to new API",
                       socketmetrics_legacy_names[metric],
                       (int)metric);
    }
}

/* NOTE: Legacy API. For new code, use SocketMetrics_get() */
void
SocketMetrics_getsnapshot (SocketMetricsSnapshot *snapshot)
{
  int i;
  if (snapshot == NULL)
    {
      SocketLog_emit (SOCKET_LOG_WARN,
                      "SocketMetrics",
                      "NULL snapshot in getsnapshot ignored");
      return;
    }

  for (i = 0; i < SOCKET_METRIC_COUNT; i++)
    {
      SocketCounterMetric new_metric = legacy_to_counter[i];
      if (new_metric != SOCKET_COUNTER_UNMAPPED)
        {
          snapshot->values[i] = SocketMetrics_counter_get (new_metric);
        }
      else
        {
          snapshot->values[i] = 0ULL; /* Unmapped legacy metrics return 0 */
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
  if (new_metric != SOCKET_COUNTER_UNMAPPED)
    return SocketMetrics_counter_name (new_metric);
  else
    return socketmetrics_legacy_names[metric]; /* Keep legacy name for unmapped
                                                */
}

size_t
SocketMetrics_count (void)
{
  return SOCKET_METRIC_COUNT;
}
