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
 * timewindow_clamp_elapsed - Clamp elapsed time to valid range
 * @elapsed: Time elapsed since window start
 * @duration: Window duration
 *
 * Returns: Clamped elapsed time in [0, duration]
 */
static int64_t
timewindow_clamp_elapsed (int64_t elapsed, int duration)
{
        if (elapsed < 0)
                return 0;
        if (elapsed > duration)
                return duration;
        return elapsed;
}

/**
 * timewindow_calculate_progress - Calculate progress through window as float
 * @elapsed: Time elapsed since window start
 * @duration_ms: Window duration
 *
 * Returns: Progress in [0.0, 1.0]
 */
static float
timewindow_calculate_progress (int64_t elapsed, int duration_ms)
{
        if (duration_ms <= 0)
                return 1.0f;

        elapsed = timewindow_clamp_elapsed (elapsed, duration_ms);
        return (float)elapsed / (float)duration_ms;
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
        int64_t elapsed;

        assert (tw != NULL);

        elapsed = now_ms - tw->window_start_ms;

        if (elapsed >= tw->duration_ms) {
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
        float progress;
        float previous_weight;
        int64_t elapsed;

        assert (tw != NULL);

        if (tw->duration_ms <= 0)
                return tw->current_count;

        elapsed = now_ms - tw->window_start_ms;
        progress = timewindow_calculate_progress (elapsed, tw->duration_ms);
        previous_weight = 1.0f - progress;

        return tw->current_count
               + (uint32_t)(tw->previous_count * previous_weight);
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
        int64_t elapsed;

        assert (tw != NULL);

        elapsed = now_ms - tw->window_start_ms;
        return timewindow_calculate_progress (elapsed, tw->duration_ms);
}

#undef T
