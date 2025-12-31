/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_TIME_H
#define SOCKETUTIL_TIME_H

/**
 * @file SocketUtil/Time.h
 * @ingroup foundation
 * @brief Time utilities for monotonic clock and timespec conversions.
 *
 * Provides:
 * - Monotonic time in milliseconds
 * - Milliseconds <-> timespec conversion
 * - Timespec arithmetic
 */

#include <stdint.h>
#include <time.h>

#include "core/SocketConfig.h"

/* ============================================================================
 * MONOTONIC TIME
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
 * TIME CONVERSION UTILITIES
 * ============================================================================
 */

/**
 * @brief Convert milliseconds to timespec structure.
 * @ingroup foundation
 * @param ms Milliseconds value to convert
 * @return Populated timespec structure
 * @threadsafe Yes (pure function, no shared state)
 *
 * Converts milliseconds to a timespec structure suitable for nanosleep(),
 * clock_nanosleep(), and other POSIX time functions.
 *
 * @see socket_util_timespec_to_ms() for inverse conversion
 */
static inline struct timespec
socket_util_ms_to_timespec (unsigned long ms)
{
  struct timespec ts;
  ts.tv_sec = ms / SOCKET_MS_PER_SECOND;
  ts.tv_nsec = (ms % SOCKET_MS_PER_SECOND) * SOCKET_NS_PER_MS;
  return ts;
}

/**
 * @brief Convert timespec structure to milliseconds.
 * @ingroup foundation
 * @param ts Timespec structure to convert
 * @return Milliseconds value
 * @threadsafe Yes (pure function, no shared state)
 *
 * Converts a timespec structure to milliseconds.
 *
 * @see socket_util_ms_to_timespec() for inverse conversion
 */
static inline unsigned long
socket_util_timespec_to_ms (struct timespec ts)
{
  return (unsigned long)ts.tv_sec * SOCKET_MS_PER_SECOND
         + ts.tv_nsec / SOCKET_NS_PER_MS;
}

/**
 * @brief Add two timespec structures together.
 * @ingroup foundation
 * @param ts1 First timespec structure
 * @param ts2 Second timespec structure to add
 * @return Sum of the two timespec structures, normalized
 * @threadsafe Yes (pure function, no shared state)
 *
 * Adds two timespec structures together, properly handling nanosecond overflow.
 * The result is normalized so that tv_nsec is always in [0, 999999999].
 */
static inline struct timespec
socket_util_timespec_add (struct timespec ts1, struct timespec ts2)
{
  struct timespec result;
  result.tv_sec = ts1.tv_sec + ts2.tv_sec;
  result.tv_nsec = ts1.tv_nsec + ts2.tv_nsec;
  if (result.tv_nsec >= SOCKET_NS_PER_SECOND)
    {
      result.tv_sec++;
      result.tv_nsec -= SOCKET_NS_PER_SECOND;
    }
  return result;
}

#endif /* SOCKETUTIL_TIME_H */
