/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* Core utility subsystems: time utilities */

#include <errno.h>
#include <time.h>

#include "core/SocketConfig.h"
#include "core/SocketLog.h"
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
