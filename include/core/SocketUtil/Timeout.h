/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETUTIL_TIMEOUT_H
#define SOCKETUTIL_TIMEOUT_H

/**
 * @file SocketUtil/Timeout.h
 * @ingroup foundation
 * @brief Timeout and deadline calculation utilities.
 *
 * Provides consistent timeout calculation across all modules using
 * CLOCK_MONOTONIC for reliable timing.
 */

#include <limits.h>
#include <stdint.h>

#include "core/SocketUtil/Time.h"

/**
 * @brief Get current monotonic time in milliseconds.
 * @ingroup foundation
 * @return Current time in milliseconds from monotonic clock, or 0 on failure.
 * @threadsafe Yes
 */
static inline int64_t
SocketTimeout_now_ms (void)
{
  return Socket_get_monotonic_ms ();
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

#endif /* SOCKETUTIL_TIMEOUT_H */
