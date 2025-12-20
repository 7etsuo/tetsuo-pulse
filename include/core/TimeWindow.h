/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef TIMEWINDOW_INCLUDED
#define TIMEWINDOW_INCLUDED

/**
 * @file TimeWindow.h
 * @ingroup foundation
 * @brief Sliding time window for rate measurement and event counting
 *
 * Provides a time-based sliding window counter that smoothly interpolates
 * between the current and previous window periods. This creates a more
 * accurate rate measurement compared to fixed time windows.
 *
 * Features:
 * - Automatic window rotation when period expires
 * - Linear interpolation between current and previous counts
 * - Weighted effective count calculation
 * - Configurable window duration
 *
 * Usage pattern:
 * @code{.c}
 *   TimeWindow_T window;
 *   int64_t now_ms = get_current_time_ms();
 *
 *   // Initialize with 60-second window
 *   TimeWindow_init(&window, 60000, now_ms);
 *
 *   // Record events
 *   TimeWindow_record(&window, now_ms);
 *
 *   // Get effective count (interpolated)
 *   uint32_t count = TimeWindow_effective_count(&window, now_ms);
 *
 *   // Reset if needed
 *   TimeWindow_reset(&window, now_ms);
 * @endcode
 *
 * @see SocketSYNProtect for usage example in rate limiting
 */

#include <stdint.h>

/**
 * @brief Time window structure for sliding window counting
 *
 * Tracks events across two consecutive time periods to provide
 * smooth interpolation of event rates. The effective count is
 * weighted based on progress through the current window.
 */
typedef struct TimeWindow_T
{
  int64_t window_start_ms;   /**< Start time of current window */
  uint32_t current_count;    /**< Events in current window */
  uint32_t previous_count;   /**< Events in previous window */
  int duration_ms;           /**< Window duration in milliseconds */
} TimeWindow_T;

/**
 * @brief Initialize a time window
 * @param tw Time window to initialize
 * @param duration_ms Window duration in milliseconds (must be > 0)
 * @param now_ms Current timestamp in milliseconds
 *
 * Sets up the window with zero counts starting at the given time.
 * Duration is clamped to minimum of 1ms if invalid.
 */
extern void TimeWindow_init (TimeWindow_T *tw, int duration_ms, int64_t now_ms);

/**
 * @brief Record an event in the time window
 * @param tw Time window instance
 * @param now_ms Current timestamp in milliseconds
 *
 * Automatically rotates the window if the duration has elapsed,
 * then increments the current count. Previous count is preserved
 * during rotation for interpolation.
 */
extern void TimeWindow_record (TimeWindow_T *tw, int64_t now_ms);

/**
 * @brief Calculate effective count with interpolation
 * @param tw Time window instance
 * @param now_ms Current timestamp in milliseconds
 *
 * Returns: Weighted count combining current and previous windows
 *
 * The effective count uses linear interpolation based on progress
 * through the current window:
 *
 *   effective = current + floor( previous * remaining / duration )
 *
 * Where remaining = duration - clamp(now - window_start, 0, duration)
 *
 * This uses precise integer arithmetic for exact results without
 * floating-point precision loss. Provides smooth rate measurement
 * without sudden jumps at window boundaries.
 *
 * @note Clamping handles clock skew and ensures progress in [0,1].
 */
extern uint32_t TimeWindow_effective_count (const TimeWindow_T *tw,
                                            int64_t now_ms);

/**
 * @brief Reset time window to empty state
 * @param tw Time window to reset
 * @param now_ms Current timestamp for new window start
 *
 * Clears both current and previous counts, restarts the window
 * at the given timestamp.
 */
extern void TimeWindow_reset (TimeWindow_T *tw, int64_t now_ms);

/**
 * @brief Rotate window if duration has elapsed
 * @param tw Time window instance
 * @param now_ms Current timestamp in milliseconds
 *
 * Returns: 1 if window was rotated, 0 if not
 *
 * Explicitly rotate the window without recording an event.
 * Useful when you need to update the window state before
 * querying the effective count.
 */
extern int TimeWindow_rotate_if_needed (TimeWindow_T *tw, int64_t now_ms);

/**
 * @brief Get progress through current window
 * @param tw Time window instance
 * @param now_ms Current timestamp in milliseconds
 *
 * Returns: Progress as float from 0.0 (start) to 1.0 (end)
 *
 * Useful for custom interpolation or debugging.
 */
extern float TimeWindow_progress (const TimeWindow_T *tw, int64_t now_ms);

#endif /* TIMEWINDOW_INCLUDED */
