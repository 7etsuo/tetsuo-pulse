/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_timewindow.c - Time window unit tests
 * Tests for the TimeWindow module.
 * Covers initialization, recording, rotation, interpolation, and edge cases.
 */

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

#include "core/TimeWindow.h"
#include "test/Test.h"

/* ============================================================================
 * Basic Lifecycle Tests
 * ============================================================================
 */

TEST (timewindow_init_basic)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 60000, now);

  ASSERT_EQ (tw.duration_ms, 60000);
  ASSERT_EQ (tw.window_start_ms, now);
  ASSERT_EQ (tw.current_count, 0u);
  ASSERT_EQ (tw.previous_count, 0u);
}

TEST (timewindow_init_clamps_invalid_duration)
{
  TimeWindow_T tw;

  /* Zero duration should be clamped to 1 */
  TimeWindow_init (&tw, 0, 0);
  ASSERT_EQ (tw.duration_ms, 1);

  /* Negative duration should be clamped to 1 */
  TimeWindow_init (&tw, -100, 0);
  ASSERT_EQ (tw.duration_ms, 1);
}

TEST (timewindow_init_different_valid_durations)
{
  TimeWindow_T tw;
  int64_t now_ms = 5000;

  /* Test 1ms duration */
  TimeWindow_init (&tw, 1, now_ms);
  ASSERT_EQ (tw.duration_ms, 1);
  ASSERT_EQ (tw.window_start_ms, now_ms);
  ASSERT_EQ (tw.current_count, 0u);
  ASSERT_EQ (tw.previous_count, 0u);

  /* Test 1000ms (1 second) duration */
  TimeWindow_init (&tw, 1000, now_ms);
  ASSERT_EQ (tw.duration_ms, 1000);
  ASSERT_EQ (tw.window_start_ms, now_ms);
  ASSERT_EQ (tw.current_count, 0u);
  ASSERT_EQ (tw.previous_count, 0u);

  /* Test 86400000ms (1 day) duration */
  TimeWindow_init (&tw, 86400000, now_ms);
  ASSERT_EQ (tw.duration_ms, 86400000);
  ASSERT_EQ (tw.window_start_ms, now_ms);
  ASSERT_EQ (tw.current_count, 0u);
  ASSERT_EQ (tw.previous_count, 0u);
}

TEST (timewindow_init_zero_now_ms)
{
  TimeWindow_T tw;
  int64_t duration_ms = 5000;

  TimeWindow_init (&tw, duration_ms, 0);

  ASSERT_EQ (tw.duration_ms, duration_ms);
  ASSERT_EQ (tw.window_start_ms, 0);
  ASSERT_EQ (tw.current_count, 0u);
  ASSERT_EQ (tw.previous_count, 0u);
}

TEST (timewindow_init_large_now_ms)
{
  TimeWindow_T tw;
  int64_t duration_ms = 10000;
  int64_t large_now = INT64_MAX - 1000000;

  TimeWindow_init (&tw, duration_ms, large_now);

  ASSERT_EQ (tw.duration_ms, duration_ms);
  ASSERT_EQ (tw.window_start_ms, large_now);
  ASSERT_EQ (tw.current_count, 0u);
  ASSERT_EQ (tw.previous_count, 0u);
}

TEST (timewindow_init_negative_now_ms)
{
  TimeWindow_T tw;
  int64_t duration_ms = 5000;
  int64_t negative_now = -1000;

  TimeWindow_init (&tw, duration_ms, negative_now);

  ASSERT_EQ (tw.duration_ms, duration_ms);
  ASSERT_EQ (tw.window_start_ms, negative_now);
  ASSERT_EQ (tw.current_count, 0u);
  ASSERT_EQ (tw.previous_count, 0u);
}

TEST (timewindow_init_very_negative_duration)
{
  TimeWindow_T tw;
  int64_t now_ms = 1000;

  TimeWindow_init (&tw, INT64_MIN, now_ms);

  /* Should clamp to TIMEWINDOW_MIN_DURATION_MS */
  ASSERT_EQ (tw.duration_ms, 1);
  ASSERT_EQ (tw.window_start_ms, now_ms);
  ASSERT_EQ (tw.current_count, 0u);
  ASSERT_EQ (tw.previous_count, 0u);
}

/* ============================================================================
 * Recording Tests
 * ============================================================================
 */

TEST (timewindow_record_increments_count)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 60000, now);

  TimeWindow_record (&tw, now);
  ASSERT_EQ (tw.current_count, 1u);

  TimeWindow_record (&tw, now + 100);
  ASSERT_EQ (tw.current_count, 2u);

  TimeWindow_record (&tw, now + 200);
  ASSERT_EQ (tw.current_count, 3u);
}

TEST (timewindow_record_rotates_when_expired)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now); /* 1 second window */

  /* Record in first window */
  TimeWindow_record (&tw, now);
  TimeWindow_record (&tw, now + 500);
  ASSERT_EQ (tw.current_count, 2u);
  ASSERT_EQ (tw.previous_count, 0u);

  /* Record after window expires - should rotate */
  TimeWindow_record (&tw, now + 1000);
  ASSERT_EQ (tw.current_count, 1u);
  ASSERT_EQ (tw.previous_count, 2u);
}

/* ============================================================================
 * Rotation Tests
 * ============================================================================
 */

TEST (timewindow_rotate_before_expiry)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 10000, now);
  tw.current_count = 5;

  /* Should not rotate before duration */
  int rotated = TimeWindow_rotate_if_needed (&tw, now + 5000);
  ASSERT_EQ (rotated, 0);
  ASSERT_EQ (tw.current_count, 5u);
  ASSERT_EQ (tw.previous_count, 0u);
}

TEST (timewindow_rotate_at_expiry)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 10000, now);
  tw.current_count = 5;

  /* Should rotate exactly at duration */
  int rotated = TimeWindow_rotate_if_needed (&tw, now + 10000);
  ASSERT_EQ (rotated, 1);
  ASSERT_EQ (tw.current_count, 0u);
  ASSERT_EQ (tw.previous_count, 5u);
}

TEST (timewindow_rotate_past_duration)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 10000, now);
  tw.current_count = 7;
  tw.previous_count = 3;

  /* Should rotate when elapsed > duration */
  int rotated = TimeWindow_rotate_if_needed (&tw, now + 15000);
  ASSERT_EQ (rotated, 1);
  ASSERT_EQ (tw.current_count, 0u);
  ASSERT_EQ (tw.previous_count, 7u);
  ASSERT_EQ (tw.window_start_ms, now + 15000);
}

TEST (timewindow_rotate_resets_current_count)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 5000, now);
  tw.current_count = 42;
  tw.previous_count = 10;

  /* Verify current_count is zeroed after rotation */
  int rotated = TimeWindow_rotate_if_needed (&tw, now + 5000);
  ASSERT_EQ (rotated, 1);
  ASSERT_EQ (tw.current_count, 0u);
}

TEST (timewindow_rotate_updates_window_start)
{
  TimeWindow_T tw;
  int64_t now = 1000;
  int64_t new_now = now + 10000;

  TimeWindow_init (&tw, 10000, now);
  tw.current_count = 5;

  /* Verify window_start_ms is updated to now_ms after rotation */
  int rotated = TimeWindow_rotate_if_needed (&tw, new_now);
  ASSERT_EQ (rotated, 1);
  ASSERT_EQ (tw.window_start_ms, new_now);
}

TEST (timewindow_rotate_preserves_previous)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now);

  /* First window: 3 events */
  TimeWindow_record (&tw, now);
  TimeWindow_record (&tw, now + 100);
  TimeWindow_record (&tw, now + 200);
  ASSERT_EQ (tw.current_count, 3u);

  /* Second window: 2 events */
  TimeWindow_rotate_if_needed (&tw, now + 1000);
  TimeWindow_record (&tw, now + 1100);
  TimeWindow_record (&tw, now + 1200);
  ASSERT_EQ (tw.current_count, 2u);
  ASSERT_EQ (tw.previous_count, 3u);
}

TEST (timewindow_rotate_time_backwards)
{
  TimeWindow_T tw;
  int64_t now = 5000;

  TimeWindow_init (&tw, 1000, now);
  tw.current_count = 10;
  tw.previous_count = 5;

  /* Time goes backwards - should clamp elapsed to 0, no rotation */
  int rotated = TimeWindow_rotate_if_needed (&tw, now - 500);
  ASSERT_EQ (rotated, 0);
  ASSERT_EQ (tw.current_count, 10u);
  ASSERT_EQ (tw.previous_count, 5u);
  ASSERT_EQ (tw.window_start_ms, now); /* Unchanged */
}

TEST (timewindow_rotate_time_same)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now);
  tw.current_count = 8;

  /* Time stays the same - elapsed = 0, no rotation */
  int rotated = TimeWindow_rotate_if_needed (&tw, now);
  ASSERT_EQ (rotated, 0);
  ASSERT_EQ (tw.current_count, 8u);
  ASSERT_EQ (tw.window_start_ms, now);
}

TEST (timewindow_rotate_large_time_jump)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now);
  tw.current_count = 15;
  tw.previous_count = 7;

  /* Large time jump: elapsed >> duration */
  int rotated = TimeWindow_rotate_if_needed (&tw, now + 1000000);
  ASSERT_EQ (rotated, 1);
  ASSERT_EQ (tw.current_count, 0u);
  ASSERT_EQ (tw.previous_count, 15u);
  ASSERT_EQ (tw.window_start_ms, now + 1000000);
}

TEST (timewindow_rotate_sequence)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now);

  /* First rotation */
  tw.current_count = 5;
  int rotated1 = TimeWindow_rotate_if_needed (&tw, now + 1000);
  ASSERT_EQ (rotated1, 1);
  ASSERT_EQ (tw.current_count, 0u);
  ASSERT_EQ (tw.previous_count, 5u);

  /* Second rotation */
  tw.current_count = 8;
  int rotated2 = TimeWindow_rotate_if_needed (&tw, now + 2000);
  ASSERT_EQ (rotated2, 1);
  ASSERT_EQ (tw.current_count, 0u);
  ASSERT_EQ (tw.previous_count, 8u);

  /* Third rotation */
  tw.current_count = 3;
  int rotated3 = TimeWindow_rotate_if_needed (&tw, now + 3000);
  ASSERT_EQ (rotated3, 1);
  ASSERT_EQ (tw.current_count, 0u);
  ASSERT_EQ (tw.previous_count, 3u);
}

/* ============================================================================
 * Effective Count (Interpolation) Tests
 * ============================================================================
 */

TEST (timewindow_effective_count_at_start)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now);
  tw.current_count = 5;
  tw.previous_count = 10;

  /* At start of window (progress = 0), previous_weight = 1.0 */
  /* effective = 5 + 10 * 1.0 = 15 */
  uint32_t effective = TimeWindow_effective_count (&tw, now);
  ASSERT_EQ (effective, 15u);
}

TEST (timewindow_effective_count_at_middle)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now);
  tw.current_count = 5;
  tw.previous_count = 10;

  /* At middle of window (progress = 0.5), previous_weight = 0.5 */
  /* effective = 5 + 10 * 0.5 = 10 */
  uint32_t effective = TimeWindow_effective_count (&tw, now + 500);
  ASSERT_EQ (effective, 10u);
}

TEST (timewindow_effective_count_at_end)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now);
  tw.current_count = 5;
  tw.previous_count = 10;

  /* At end of window (progress = 1.0), previous_weight = 0.0 */
  /* effective = 5 + 10 * 0.0 = 5 */
  uint32_t effective = TimeWindow_effective_count (&tw, now + 1000);
  ASSERT_EQ (effective, 5u);
}

TEST (timewindow_effective_count_quarter)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now);
  tw.current_count = 4;
  tw.previous_count = 8;

  /* At 25% through window, previous_weight = 0.75 */
  /* effective = 4 + 8 * 0.75 = 4 + 6 = 10 */
  uint32_t effective = TimeWindow_effective_count (&tw, now + 250);
  ASSERT_EQ (effective, 10u);
}

TEST (timewindow_effective_count_no_previous)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now);
  tw.current_count = 7;
  tw.previous_count = 0;

  /* No previous count - should just return current */
  uint32_t effective = TimeWindow_effective_count (&tw, now + 500);
  ASSERT_EQ (effective, 7u);
}

/* ============================================================================
 * Progress Tests
 * ============================================================================
 */

TEST (timewindow_progress_at_start)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now);

  float progress = TimeWindow_progress (&tw, now);
  ASSERT (progress < 0.001f);
}

TEST (timewindow_progress_at_middle)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now);

  float progress = TimeWindow_progress (&tw, now + 500);
  ASSERT (fabsf (progress - 0.5f) < 0.001f);
}

TEST (timewindow_progress_at_end)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now);

  float progress = TimeWindow_progress (&tw, now + 1000);
  ASSERT (fabsf (progress - 1.0f) < 0.001f);
}

TEST (timewindow_progress_clamped_beyond_end)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now);

  /* Even if past duration, should clamp to 1.0 */
  float progress = TimeWindow_progress (&tw, now + 2000);
  ASSERT (fabsf (progress - 1.0f) < 0.001f);
}

TEST (timewindow_progress_clamped_negative)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now);

  /* Negative elapsed should clamp to 0 */
  float progress = TimeWindow_progress (&tw, now - 500);
  ASSERT (progress < 0.001f);
}

/* ============================================================================
 * Reset Tests
 * ============================================================================
 */

TEST (timewindow_reset_clears_counts)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now);
  tw.current_count = 10;
  tw.previous_count = 20;

  TimeWindow_reset (&tw, now + 5000);

  ASSERT_EQ (tw.current_count, 0u);
  ASSERT_EQ (tw.previous_count, 0u);
  ASSERT_EQ (tw.window_start_ms, now + 5000);
}

TEST (timewindow_reset_keeps_duration)
{
  TimeWindow_T tw;

  TimeWindow_init (&tw, 5000, 0);
  TimeWindow_reset (&tw, 1000);

  ASSERT_EQ (tw.duration_ms, 5000);
}

/* ============================================================================
 * Edge Cases
 * ============================================================================
 */

TEST (timewindow_multiple_rotations)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 100, now);

  /* Record in window 1 */
  TimeWindow_record (&tw, now);
  ASSERT_EQ (tw.current_count, 1u);

  /* Window 2 */
  TimeWindow_record (&tw, now + 100);
  ASSERT_EQ (tw.current_count, 1u);
  ASSERT_EQ (tw.previous_count, 1u);

  /* Window 3 */
  TimeWindow_record (&tw, now + 200);
  ASSERT_EQ (tw.current_count, 1u);
  ASSERT_EQ (tw.previous_count, 1u);

  /* Window 4 - multiple without recording */
  TimeWindow_rotate_if_needed (&tw, now + 300);
  TimeWindow_rotate_if_needed (&tw, now + 400);
  ASSERT_EQ (tw.current_count, 0u);
  ASSERT_EQ (tw.previous_count, 0u);
}

TEST (timewindow_large_count)
{
  TimeWindow_T tw;
  int64_t now = 1000;

  TimeWindow_init (&tw, 1000, now);
  tw.current_count = 1000000;
  tw.previous_count = 1000000;

  uint32_t effective = TimeWindow_effective_count (&tw, now + 500);
  ASSERT_EQ (effective, 1500000u); /* 1M + 1M * 0.5 */
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
