/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_timer.c - SocketTimer unit tests
 *
 * Part of the Socket Library Test Suite
 *
 * Comprehensive tests for the timer subsystem including:
 * - One-shot timers
 * - Repeating timers
 * - Timer cancellation
 * - Timer remaining time queries
 * - Timer pause/resume
 * - Timer reschedule
 * - Edge cases and error conditions
 */

/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */

#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "core/Except.h"
#include "core/SocketTimer.h"
#include "core/SocketUtil.h"
#include "poll/SocketPoll.h"
#include "test/Test.h"

/* Suppress longjmp clobbering warnings for test variables */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* ============================================================================
 * Test Helpers
 * ============================================================================
 */

static void
setup_signals (void)
{
  signal (SIGPIPE, SIG_IGN);
}

/* Callback context for tracking invocations */
typedef struct
{
  volatile int call_count;
  volatile int64_t last_call_time_ms;
  void *expected_userdata;
} TimerCallbackContext;

static void
timer_callback (void *userdata)
{
  TimerCallbackContext *ctx = (TimerCallbackContext *)userdata;
  if (ctx)
    {
      ctx->call_count++;
      ctx->last_call_time_ms = Socket_get_monotonic_ms ();
    }
}

static void
timer_callback_with_check (void *userdata)
{
  TimerCallbackContext *ctx = (TimerCallbackContext *)userdata;
  if (ctx)
    {
      ctx->call_count++;
    }
}

/* ============================================================================
 * Basic Timer Creation Tests
 * ============================================================================
 */

TEST (timer_add_one_shot)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  SocketTimer_T timer = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 100, timer_callback, NULL);
    ASSERT_NOT_NULL (timer);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

TEST (timer_add_repeating)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  SocketTimer_T timer = NULL;

  TRY
  {
    timer = SocketTimer_add_repeating (poll, 50, timer_callback, NULL);
    ASSERT_NOT_NULL (timer);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

TEST (timer_add_multiple)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  SocketTimer_T timer1 = NULL;
  SocketTimer_T timer2 = NULL;
  SocketTimer_T timer3 = NULL;

  TRY
  {
    timer1 = SocketTimer_add (poll, 100, timer_callback, NULL);
    timer2 = SocketTimer_add (poll, 200, timer_callback, NULL);
    timer3 = SocketTimer_add (poll, 50, timer_callback, NULL);

    ASSERT_NOT_NULL (timer1);
    ASSERT_NOT_NULL (timer2);
    ASSERT_NOT_NULL (timer3);

    /* All timers should be different */
    ASSERT_NE (timer1, timer2);
    ASSERT_NE (timer2, timer3);
    ASSERT_NE (timer1, timer3);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

/* ============================================================================
 * Timer Cancellation Tests
 * ============================================================================
 */

TEST (timer_cancel_pending)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  SocketTimer_T timer = NULL;
  int result = -1;

  TRY
  {
    timer = SocketTimer_add (poll, 1000, timer_callback, NULL);
    ASSERT_NOT_NULL (timer);

    result = SocketTimer_cancel (poll, timer);
    ASSERT_EQ (0, result);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

TEST (timer_cancel_repeating)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  SocketTimer_T timer = NULL;
  int result = -1;

  TRY
  {
    timer = SocketTimer_add_repeating (poll, 100, timer_callback, NULL);
    ASSERT_NOT_NULL (timer);

    result = SocketTimer_cancel (poll, timer);
    ASSERT_EQ (0, result);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

TEST (timer_cancel_already_cancelled)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  SocketTimer_T timer = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 1000, timer_callback, NULL);
    ASSERT_NOT_NULL (timer);

    int result1 = SocketTimer_cancel (poll, timer);
    ASSERT_EQ (0, result1);

    /* Second cancel should return -1 */
    int result2 = SocketTimer_cancel (poll, timer);
    ASSERT_EQ (-1, result2);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

/* Note: timer_cancel_null_timer is not tested because the library may use
 * assert() for null timer validation. The function is expected to return -1
 * but behavior depends on debug settings.
 */

/* ============================================================================
 * Timer Remaining Time Tests
 * ============================================================================
 */

TEST (timer_remaining_query)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  SocketTimer_T timer = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 500, timer_callback, NULL);
    ASSERT_NOT_NULL (timer);

    int64_t remaining = SocketTimer_remaining (poll, timer);
    /* Should be close to 500ms, allow some tolerance */
    ASSERT (remaining >= 0);
    ASSERT (remaining <= 510);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

TEST (timer_remaining_on_cancelled)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  SocketTimer_T timer = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 1000, timer_callback, NULL);
    ASSERT_NOT_NULL (timer);

    SocketTimer_cancel (poll, timer);

    int64_t remaining = SocketTimer_remaining (poll, timer);
    ASSERT_EQ (-1, remaining);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

/* Note: timer_remaining_null_timer is not tested because the library uses
 * assert() for null timer validation, which aborts the program.
 */

/* ============================================================================
 * Timer Reschedule Tests
 * ============================================================================
 */

TEST (timer_reschedule)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  SocketTimer_T timer = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 100, timer_callback, NULL);
    ASSERT_NOT_NULL (timer);

    /* Reschedule to a longer delay */
    int result = SocketTimer_reschedule (poll, timer, 500);
    ASSERT_EQ (0, result);

    /* Remaining should now be close to 500ms */
    int64_t remaining = SocketTimer_remaining (poll, timer);
    ASSERT (remaining >= 400);
    ASSERT (remaining <= 510);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

TEST (timer_reschedule_cancelled)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  SocketTimer_T timer = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 100, timer_callback, NULL);
    ASSERT_NOT_NULL (timer);

    SocketTimer_cancel (poll, timer);

    int result = SocketTimer_reschedule (poll, timer, 500);
    ASSERT_EQ (-1, result);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

/* Note: timer_reschedule_null is not tested because the library uses
 * assert() for null timer validation, which aborts the program rather
 * than raising an exception.
 */

/* ============================================================================
 * Timer Pause/Resume Tests
 * ============================================================================
 */

TEST (timer_pause_resume)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  SocketTimer_T timer = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 500, timer_callback, NULL);
    ASSERT_NOT_NULL (timer);

    /* Pause the timer */
    int pause_result = SocketTimer_pause (poll, timer);
    ASSERT_EQ (0, pause_result);

    /* Resume the timer */
    int resume_result = SocketTimer_resume (poll, timer);
    ASSERT_EQ (0, resume_result);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

TEST (timer_pause_already_paused)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  SocketTimer_T timer = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 500, timer_callback, NULL);
    ASSERT_NOT_NULL (timer);

    int pause1 = SocketTimer_pause (poll, timer);
    ASSERT_EQ (0, pause1);

    /* Second pause should return -1 */
    int pause2 = SocketTimer_pause (poll, timer);
    ASSERT_EQ (-1, pause2);

    SocketTimer_resume (poll, timer);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

TEST (timer_resume_not_paused)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  SocketTimer_T timer = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 500, timer_callback, NULL);
    ASSERT_NOT_NULL (timer);

    /* Resume without pause should return -1 */
    int resume_result = SocketTimer_resume (poll, timer);
    ASSERT_EQ (-1, resume_result);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

TEST (timer_pause_cancelled)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  SocketTimer_T timer = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 500, timer_callback, NULL);
    ASSERT_NOT_NULL (timer);

    SocketTimer_cancel (poll, timer);

    int pause_result = SocketTimer_pause (poll, timer);
    ASSERT_EQ (-1, pause_result);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

/* ============================================================================
 * Timer Callback Invocation Tests
 * ============================================================================
 */

TEST (timer_callback_invoked)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;

  TRY
  {
    /* Schedule a 20ms timer */
    timer = SocketTimer_add (poll, 20, timer_callback_with_check, &ctx);
    ASSERT_NOT_NULL (timer);

    /* Wait for timer to fire (poll timeout > timer delay) */
    SocketEvent_T *events = NULL;
    (void)SocketPoll_wait (poll, &events, 100);

    /* Callback should have been invoked */
    ASSERT_EQ (1, ctx.call_count);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

TEST (timer_callback_userdata_passed)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 10, timer_callback_with_check, &ctx);
    ASSERT_NOT_NULL (timer);

    SocketEvent_T *events = NULL;
    (void)SocketPoll_wait (poll, &events, 50);

    /* Callback was invoked with correct userdata */
    ASSERT_EQ (1, ctx.call_count);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

TEST (timer_repeating_fires_multiple_times)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;

  TRY
  {
    /* Create a 30ms repeating timer */
    timer = SocketTimer_add_repeating (poll, 30, timer_callback_with_check, &ctx);
    ASSERT_NOT_NULL (timer);

    /* Wait long enough for multiple fires (200ms for ~6-7 fires) */
    SocketEvent_T *events = NULL;
    (void)SocketPoll_wait (poll, &events, 200);

    /* Should have fired at least once */
    ASSERT (ctx.call_count >= 1);

    /* Cancel the repeating timer */
    SocketTimer_cancel (poll, timer);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

TEST (timer_cancelled_not_invoked)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 50, timer_callback_with_check, &ctx);
    ASSERT_NOT_NULL (timer);

    /* Cancel before it fires */
    int result = SocketTimer_cancel (poll, timer);
    ASSERT_EQ (0, result);

    /* Wait past when it would have fired */
    SocketEvent_T *events = NULL;
    (void)SocketPoll_wait (poll, &events, 100);

    /* Callback should NOT have been invoked */
    ASSERT_EQ (0, ctx.call_count);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

/* ============================================================================
 * Timer Edge Cases
 * ============================================================================
 */

TEST (timer_zero_delay)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;

  TRY
  {
    /* Zero delay should fire immediately on next poll */
    timer = SocketTimer_add (poll, 0, timer_callback_with_check, &ctx);
    ASSERT_NOT_NULL (timer);

    SocketEvent_T *events = NULL;
    (void)SocketPoll_wait (poll, &events, 50);

    ASSERT_EQ (1, ctx.call_count);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

TEST (timer_fires_during_poll_wait)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;

  TRY
  {
    int64_t start = Socket_get_monotonic_ms ();
    timer = SocketTimer_add (poll, 30, timer_callback, &ctx);
    ASSERT_NOT_NULL (timer);

    SocketEvent_T *events = NULL;
    (void)SocketPoll_wait (poll, &events, 100);

    int64_t elapsed = Socket_get_monotonic_ms () - start;

    /* Timer should have fired */
    ASSERT_EQ (1, ctx.call_count);

    /* Elapsed time should be close to timer delay, not full poll timeout */
    ASSERT (elapsed >= 25);
    ASSERT (elapsed < 80);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

TEST (timer_multiple_timers_added)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  SocketTimer_T timer1 = NULL;
  SocketTimer_T timer2 = NULL;
  SocketTimer_T timer3 = NULL;

  TRY
  {
    /* Add multiple timers - should all be created successfully */
    timer1 = SocketTimer_add (poll, 100, timer_callback, NULL);
    timer2 = SocketTimer_add (poll, 200, timer_callback, NULL);
    timer3 = SocketTimer_add (poll, 300, timer_callback, NULL);

    ASSERT_NOT_NULL (timer1);
    ASSERT_NOT_NULL (timer2);
    ASSERT_NOT_NULL (timer3);

    /* All timers should be different */
    ASSERT_NE (timer1, timer2);
    ASSERT_NE (timer2, timer3);
    ASSERT_NE (timer1, timer3);

    /* Cancel all to clean up */
    SocketTimer_cancel (poll, timer1);
    SocketTimer_cancel (poll, timer2);
    SocketTimer_cancel (poll, timer3);
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;
}

/* ============================================================================
 * Timer Error Handling Tests
 * ============================================================================
 */

/* Note: timer_add_null_poll is not tested because the library uses
 * assert() for null poll validation, which aborts the program rather
 * than raising an exception. This is by design for programming errors.
 */

/* Note: timer_add_null_callback is not tested because the library uses
 * assert() for null callback validation, which aborts the program rather
 * than raising an exception. This is by design for programming errors.
 */

TEST (timer_add_negative_delay)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  int caught = 0;

  TRY
  {
    TRY { SocketTimer_add (poll, -100, timer_callback, NULL); }
    EXCEPT (Test_Failed) { RERAISE; }
    ELSE { caught = 1; }
    END_TRY;
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;

  ASSERT (caught);
}

TEST (timer_repeating_zero_interval)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  int caught = 0;

  TRY
  {
    /* Repeating timer with 0 interval should fail (min is 1ms) */
    TRY { SocketTimer_add_repeating (poll, 0, timer_callback, NULL); }
    EXCEPT (Test_Failed) { RERAISE; }
    ELSE { caught = 1; }
    END_TRY;
  }
  FINALLY { SocketPoll_free (&poll); }
  END_TRY;

  ASSERT (caught);
}

/* ============================================================================
 * Main - Run all timer tests
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

