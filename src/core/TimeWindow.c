/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * TimeWindow.c - Sliding Time Window Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Provides a time-based sliding window counter with smooth
 * interpolation between consecutive periods for accurate rate
 * measurement.
 *
 * Algorithm:
 * - Maintains counts for current and previous time periods
 * - On rotation, previous = current, current = 0
 * - Effective count interpolates based on window progress
 *
 * Thread Safety:
 * - NOT built-in (caller must provide synchronization)
 * - All functions are reentrant when called on separate instances
 */

#include <assert.h>
#include <stddef.h>

#include "core/TimeWindow.h"

#define T TimeWindow_T

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * timewindow_clamp_to_duration - Clamp elapsed time to [0, duration]
 * @elapsed: Raw elapsed time (may be negative or oversized)
 * @duration: Positive window duration
 *
 * Returns: Clamped value for consistent progress calculations
 *
 * Used internally by progress tracking functions to handle clock skew
 * and overflow cases uniformly.
 */
static inline int64_t
timewindow_clamp_to_duration(int64_t elapsed, int duration) {
    if (duration <= 0)
        return 0;
    if (elapsed < 0)
        return 0;
    int64_t d = duration;
    if (elapsed > d)
        return d;
    return elapsed;
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================
 */

void
TimeWindow_init (T *tw, int duration_ms, int64_t now_ms)
{
        assert (tw != NULL);

        tw->duration_ms = (duration_ms > 0) ? duration_ms : 1;
        tw->window_start_ms = now_ms;
        tw->current_count = 0;
        tw->previous_count = 0;
}

int
TimeWindow_rotate_if_needed (T *tw, int64_t now_ms)
{
        assert (tw != NULL);

        int64_t elapsed = now_ms - tw->window_start_ms;
        int64_t clamped_elapsed = timewindow_clamp_to_duration(elapsed, tw->duration_ms);

        if (clamped_elapsed >= tw->duration_ms) {
                tw->previous_count = tw->current_count;
                tw->current_count = 0;
                tw->window_start_ms = now_ms;
                return 1;
        }

        return 0;
}

void
TimeWindow_record (T *tw, int64_t now_ms)
{
        assert (tw != NULL);

        TimeWindow_rotate_if_needed (tw, now_ms);
        tw->current_count++;
}

uint32_t
TimeWindow_effective_count (const T *tw, int64_t now_ms)
{
        assert (tw != NULL);

        int duration_ms = tw->duration_ms;
        if (duration_ms <= 0)
                return tw->current_count;

        int64_t elapsed = now_ms - tw->window_start_ms;
        int64_t clamped_elapsed = timewindow_clamp_to_duration(elapsed, duration_ms);

        int64_t remaining = (int64_t)duration_ms - clamped_elapsed;
        uint32_t weighted_previous = 0;
        if (remaining > 0) {
                uint64_t temp = ((uint64_t)tw->previous_count * (uint64_t)remaining) / (uint64_t)duration_ms;
                weighted_previous = (uint32_t)temp;
        }

        return tw->current_count + weighted_previous;
}

void
TimeWindow_reset (T *tw, int64_t now_ms)
{
        assert (tw != NULL);

        tw->window_start_ms = now_ms;
        tw->current_count = 0;
        tw->previous_count = 0;
}

float
TimeWindow_progress (const T *tw, int64_t now_ms)
{
        assert (tw != NULL);

        int duration_ms = tw->duration_ms;
        if (duration_ms <= 0)
                return 1.0f;

        int64_t elapsed = now_ms - tw->window_start_ms;
        int64_t clamped_elapsed = timewindow_clamp_to_duration(elapsed, duration_ms);

        return (float)clamped_elapsed / (float)duration_ms;
}

#undef T
