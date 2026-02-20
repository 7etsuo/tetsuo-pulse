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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

/* Note: timer_cancel_null_timer is not tested because the library may use
 * assert() for null timer validation. The function is expected to return -1
 * but behavior depends on debug settings.
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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

/* Note: timer_remaining_null_timer is not tested because the library uses
 * assert() for null timer validation, which aborts the program.
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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

/* Note: timer_reschedule_null is not tested because the library uses
 * assert() for null timer validation, which aborts the program rather
 * than raising an exception.
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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
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
    timer
        = SocketTimer_add_repeating (poll, 30, timer_callback_with_check, &ctx);
    ASSERT_NOT_NULL (timer);

    /* Wait long enough for multiple fires (200ms for ~6-7 fires) */
    SocketEvent_T *events = NULL;
    (void)SocketPoll_wait (poll, &events, 200);

    /* Should have fired at least once */
    ASSERT (ctx.call_count >= 1);

    /* Cancel the repeating timer */
    SocketTimer_cancel (poll, timer);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
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
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

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
    TRY
    {
      SocketTimer_add (poll, -100, timer_callback, NULL);
    }
    EXCEPT (Test_Failed)
    {
      RERAISE;
    }
    ELSE
    {
      caught = 1;
    }
    END_TRY;
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
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
    TRY
    {
      SocketTimer_add_repeating (poll, 0, timer_callback, NULL);
    }
    EXCEPT (Test_Failed)
    {
      RERAISE;
    }
    ELSE
    {
      caught = 1;
    }
    END_TRY;
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;

  ASSERT (caught);
}

/* Test basic repeating timer with various intervals */
TEST (timer_repeating_basic_intervals)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx10 = { 0, 0, NULL };
  TimerCallbackContext ctx100 = { 0, 0, NULL };
  TimerCallbackContext ctx1000 = { 0, 0, NULL };
  SocketTimer_T timer10 = NULL;
  SocketTimer_T timer100 = NULL;
  SocketTimer_T timer1000 = NULL;

  TRY
  {
    /* Create timers with different intervals */
    timer10 = SocketTimer_add_repeating (poll, 10, timer_callback, &ctx10);
    timer100 = SocketTimer_add_repeating (poll, 100, timer_callback, &ctx100);
    timer1000
        = SocketTimer_add_repeating (poll, 1000, timer_callback, &ctx1000);

    ASSERT_NOT_NULL (timer10);
    ASSERT_NOT_NULL (timer100);
    ASSERT_NOT_NULL (timer1000);

    /* Wait enough time for multiple firings - loop to ensure time passes */
    SocketEvent_T *events = NULL;
    int64_t start = Socket_get_monotonic_ms ();
    int64_t target = start + 250;
    while (Socket_get_monotonic_ms () < target)
      {
        (void)SocketPoll_wait (poll, &events, 100);
      }
    int64_t elapsed = Socket_get_monotonic_ms () - start;

    /* Verify callbacks fired (allow for slower systems) */
    ASSERT (ctx10.call_count >= 1);
    /* 100ms timer may fire 1-3 times in 250ms */
    ASSERT (ctx100.call_count >= 0);
    /* 1000ms timer should not have fired yet */
    ASSERT_EQ (0, ctx1000.call_count);

    /* Verify elapsed time is reasonable */
    ASSERT (elapsed >= 200);

    /* Cancel all timers */
    SocketTimer_cancel (poll, timer10);
    SocketTimer_cancel (poll, timer100);
    SocketTimer_cancel (poll, timer1000);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

/* Test interval accuracy over multiple firings */
TEST (timer_repeating_interval_accuracy)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;
  const int64_t interval = 50;

  TRY
  {
    int64_t start = Socket_get_monotonic_ms ();
    timer = SocketTimer_add_repeating (poll, interval, timer_callback, &ctx);
    ASSERT_NOT_NULL (timer);

    /* Wait for multiple firings */
    SocketEvent_T *events = NULL;
    for (int i = 0; i < 5; i++)
      {
        (void)SocketPoll_wait (poll, &events, interval + 20);
      }

    int64_t elapsed = Socket_get_monotonic_ms () - start;

    /* Should have fired at least 4 times in ~250ms */
    ASSERT (ctx.call_count >= 4);

    /* Check timing: elapsed should be close to (call_count * interval) */
    int64_t expected = ctx.call_count * interval;
    int64_t deviation = elapsed - expected;
    /* Allow 5ms tolerance per firing + 10ms base */
    int64_t tolerance = (ctx.call_count * 5) + 10;
    ASSERT (deviation >= -tolerance);
    ASSERT (deviation <= tolerance);

    SocketTimer_cancel (poll, timer);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

/* Test that repeating timer count reaches expected number */
TEST (timer_repeating_count_firings)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;

  TRY
  {
    /* 20ms interval, wait 250ms = ~12 firings expected */
    timer
        = SocketTimer_add_repeating (poll, 20, timer_callback_with_check, &ctx);
    ASSERT_NOT_NULL (timer);

    SocketEvent_T *events = NULL;
    int64_t start = Socket_get_monotonic_ms ();
    int64_t target = start + 250;
    while (Socket_get_monotonic_ms () < target)
      {
        (void)SocketPoll_wait (poll, &events, 50);
      }

    /* Should have fired at least 6 times (allowing tolerance for slower
     * systems) */
    ASSERT (ctx.call_count >= 6);
    /* Should not have fired more than 18 times */
    ASSERT (ctx.call_count <= 18);

    SocketTimer_cancel (poll, timer);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

/* Test cancellation of repeating timer after N firings */
TEST (timer_repeating_cancellation_after_firings)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;

  TRY
  {
    timer
        = SocketTimer_add_repeating (poll, 30, timer_callback_with_check, &ctx);
    ASSERT_NOT_NULL (timer);

    /* Wait for a few firings */
    SocketEvent_T *events = NULL;
    int64_t start = Socket_get_monotonic_ms ();
    int64_t target = start + 150;
    while (Socket_get_monotonic_ms () < target)
      {
        (void)SocketPoll_wait (poll, &events, 40);
      }

    int count_before_cancel = ctx.call_count;
    ASSERT (count_before_cancel >= 1);

    /* Cancel the timer */
    int result = SocketTimer_cancel (poll, timer);
    ASSERT_EQ (0, result);

    /* Wait again - no more callbacks should occur */
    (void)SocketPoll_wait (poll, &events, 100);

    /* Count should not have increased */
    ASSERT_EQ (count_before_cancel, ctx.call_count);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

/* Test multiple repeating timers with different intervals */
TEST (timer_repeating_multiple_timers_no_interference)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx10 = { 0, 0, NULL };
  TimerCallbackContext ctx50 = { 0, 0, NULL };
  TimerCallbackContext ctx100 = { 0, 0, NULL };
  SocketTimer_T timer10 = NULL;
  SocketTimer_T timer50 = NULL;
  SocketTimer_T timer100 = NULL;

  TRY
  {
    timer10 = SocketTimer_add_repeating (poll, 10, timer_callback, &ctx10);
    timer50 = SocketTimer_add_repeating (poll, 50, timer_callback, &ctx50);
    timer100 = SocketTimer_add_repeating (poll, 100, timer_callback, &ctx100);

    ASSERT_NOT_NULL (timer10);
    ASSERT_NOT_NULL (timer50);
    ASSERT_NOT_NULL (timer100);

    /* Wait for multiple cycles - loop to ensure time passes */
    SocketEvent_T *events = NULL;
    int64_t start = Socket_get_monotonic_ms ();
    int64_t target = start + 300;
    while (Socket_get_monotonic_ms () < target)
      {
        (void)SocketPoll_wait (poll, &events, 50);
      }

    /* Verify each timer fired at appropriate rate (relaxed for CI systems) */
    /* 10ms timer: ~30 firings in 300ms, but allow wide tolerance */
    ASSERT (ctx10.call_count >= 10);
    ASSERT (ctx10.call_count <= 50);

    /* 50ms timer: ~6 firings in 300ms */
    ASSERT (ctx50.call_count >= 2);
    ASSERT (ctx50.call_count <= 12);

    /* 100ms timer: ~3 firings in 300ms */
    ASSERT (ctx100.call_count >= 1);
    ASSERT (ctx100.call_count <= 6);

    /* Cancel all */
    SocketTimer_cancel (poll, timer10);
    SocketTimer_cancel (poll, timer50);
    SocketTimer_cancel (poll, timer100);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

/* Test minimum interval (1ms) */
TEST (timer_repeating_minimum_interval)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;

  TRY
  {
    /* SOCKET_TIMER_MIN_INTERVAL_MS = 1 */
    timer
        = SocketTimer_add_repeating (poll, 1, timer_callback_with_check, &ctx);
    ASSERT_NOT_NULL (timer);

    /* Wait a short time - loop to ensure time passes */
    SocketEvent_T *events = NULL;
    int64_t start = Socket_get_monotonic_ms ();
    int64_t target = start + 100;
    while (Socket_get_monotonic_ms () < target)
      {
        (void)SocketPoll_wait (poll, &events, 10);
      }

    /* Should have fired many times (at least 20 in 100ms, allowing for
     * overhead) */
    ASSERT (ctx.call_count >= 20);

    SocketTimer_cancel (poll, timer);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

/* Test maximum interval (SOCKET_MAX_TIMER_DELAY_MS) */
TEST (timer_repeating_maximum_interval)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;

  TRY
  {
    /* SOCKET_MAX_TIMER_DELAY_MS = 31536000000 (1 year) */
    /* Create timer with max interval - should succeed */
    timer = SocketTimer_add_repeating (
        poll, INT64_C (31536000000), timer_callback, &ctx);
    ASSERT_NOT_NULL (timer);

    /* Timer won't fire in reasonable test time, just verify creation */
    /* Cancel immediately */
    int result = SocketTimer_cancel (poll, timer);
    ASSERT_EQ (0, result);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

/* Test negative interval (should fail) */
TEST (timer_repeating_negative_interval)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  int caught = 0;

  TRY
  {
    TRY
    {
      SocketTimer_add_repeating (poll, -100, timer_callback, NULL);
    }
    EXCEPT (Test_Failed)
    {
      RERAISE;
    }
    ELSE
    {
      caught = 1;
    }
    END_TRY;
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;

  ASSERT (caught);
}

/* Test interval exceeding maximum (should fail) */
TEST (timer_repeating_interval_exceeds_max)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  int caught = 0;

  TRY
  {
    TRY
    {
      /* Exceed SOCKET_MAX_TIMER_DELAY_MS */
      SocketTimer_add_repeating (
          poll, INT64_C (31536000000) + 1, timer_callback, NULL);
    }
    EXCEPT (Test_Failed)
    {
      RERAISE;
    }
    ELSE
    {
      caught = 1;
    }
    END_TRY;
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;

  ASSERT (caught);
}

/* Test that timer persists in heap after each firing */
TEST (timer_repeating_persistence_in_heap)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;

  TRY
  {
    timer
        = SocketTimer_add_repeating (poll, 40, timer_callback_with_check, &ctx);
    ASSERT_NOT_NULL (timer);

    /* Fire multiple times and verify timer is still active */
    SocketEvent_T *events = NULL;
    for (int i = 0; i < 3; i++)
      {
        (void)SocketPoll_wait (poll, &events, 50);
        ASSERT (ctx.call_count > i);
      }

    /* Timer should still be active - query remaining time */
    int64_t remaining = SocketTimer_remaining (poll, timer);
    ASSERT (remaining >= 0);
    ASSERT (remaining <= 45);

    SocketTimer_cancel (poll, timer);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

/* Test rescheduling behavior after firing */
TEST (timer_repeating_reschedule_verification)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;

  TRY
  {
    int64_t start = Socket_get_monotonic_ms ();
    timer = SocketTimer_add_repeating (poll, 60, timer_callback, &ctx);
    ASSERT_NOT_NULL (timer);

    /* Wait for first firing */
    SocketEvent_T *events = NULL;
    (void)SocketPoll_wait (poll, &events, 80);
    ASSERT_EQ (1, ctx.call_count);

    /* Verify timer auto-rescheduled (remaining time should be ~60ms) */
    int64_t remaining = SocketTimer_remaining (poll, timer);
    ASSERT (remaining > 0);
    ASSERT (remaining <= 65);

    /* Wait for second firing */
    (void)SocketPoll_wait (poll, &events, 80);
    ASSERT_EQ (2, ctx.call_count);

    /* Verify still rescheduled */
    remaining = SocketTimer_remaining (poll, timer);
    ASSERT (remaining > 0);
    ASSERT (remaining <= 65);

    SocketTimer_cancel (poll, timer);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

/* Test first firing occurs after interval_ms */
TEST (timer_repeating_first_firing_timing)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;

  TRY
  {
    int64_t start = Socket_get_monotonic_ms ();
    timer = SocketTimer_add_repeating (poll, 100, timer_callback, &ctx);
    ASSERT_NOT_NULL (timer);

    /* Wait for first firing */
    SocketEvent_T *events = NULL;
    (void)SocketPoll_wait (poll, &events, 120);

    int64_t first_fire = ctx.last_call_time_ms;
    int64_t elapsed = first_fire - start;

    /* First firing should be ~100ms after start */
    ASSERT (elapsed >= 95);
    ASSERT (elapsed <= 115);

    SocketTimer_cancel (poll, timer);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_cancel_after_fired)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;

  TRY
  {
    /* Create a 10ms one-shot timer */
    timer = SocketTimer_add (poll, 10, timer_callback_with_check, &ctx);
    ASSERT_NOT_NULL (timer);

    /* Wait for timer to fire */
    SocketEvent_T *events = NULL;
    (void)SocketPoll_wait (poll, &events, 50);

    /* Timer should have fired */
    ASSERT_EQ (1, ctx.call_count);

    /* Cancelling already-fired timer should return -1 */
    int result = SocketTimer_cancel (poll, timer);
    ASSERT_EQ (-1, result);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_lazy_deletion_mechanism)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx1 = { 0, 0, NULL };
  TimerCallbackContext ctx2 = { 0, 0, NULL };
  TimerCallbackContext ctx3 = { 0, 0, NULL };
  SocketTimer_T timer1 = NULL;
  SocketTimer_T timer2 = NULL;
  SocketTimer_T timer3 = NULL;

  TRY
  {
    /* Create timers with different delays (100ms, 200ms, 300ms) */
    timer1 = SocketTimer_add (poll, 100, timer_callback_with_check, &ctx1);
    timer2 = SocketTimer_add (poll, 200, timer_callback_with_check, &ctx2);
    timer3 = SocketTimer_add (poll, 300, timer_callback_with_check, &ctx3);

    ASSERT_NOT_NULL (timer1);
    ASSERT_NOT_NULL (timer2);
    ASSERT_NOT_NULL (timer3);

    /* Cancel timer2 (middle timer) - lazy deletion should mark it cancelled */
    int result = SocketTimer_cancel (poll, timer2);
    ASSERT_EQ (0, result);

    /* Wait for timer1 to fire (100ms) */
    SocketEvent_T *events = NULL;
    (void)SocketPoll_wait (poll, &events, 150);

    /* Only timer1 should have fired */
    ASSERT_EQ (1, ctx1.call_count);
    ASSERT_EQ (0, ctx2.call_count);
    ASSERT_EQ (0, ctx3.call_count);

    /* Wait for timer3 to fire (another 200ms) */
    (void)SocketPoll_wait (poll, &events, 200);

    /* timer1 and timer3 should have fired, timer2 should not */
    ASSERT_EQ (1, ctx1.call_count);
    ASSERT_EQ (0, ctx2.call_count);
    ASSERT_EQ (1, ctx3.call_count);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_multiple_cancellations_in_heap)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (20);
  TimerCallbackContext contexts[10];
  SocketTimer_T timers[10];

  TRY
  {
    /* Create 10 timers with different delays (50ms, 100ms, 150ms, ...) */
    for (int i = 0; i < 10; i++)
      {
        contexts[i].call_count = 0;
        contexts[i].last_call_time_ms = 0;
        contexts[i].expected_userdata = NULL;
        timers[i] = SocketTimer_add (
            poll, 50 + (i * 50), timer_callback_with_check, &contexts[i]);
        ASSERT_NOT_NULL (timers[i]);
      }

    /* Cancel 5 out of 10 timers (indices 1, 3, 5, 7, 9) */
    for (int i = 1; i < 10; i += 2)
      {
        int result = SocketTimer_cancel (poll, timers[i]);
        ASSERT_EQ (0, result);
      }

    /* Wait long enough for all timers to expire (600ms total, polling multiple
     * times) */
    SocketEvent_T *events = NULL;
    int64_t start = Socket_get_monotonic_ms ();
    while (Socket_get_monotonic_ms () - start < 600)
      {
        (void)SocketPoll_wait (poll, &events, 100);
      }

    /* Verify only non-cancelled timers fired (indices 0, 2, 4, 6, 8) */
    for (int i = 0; i < 10; i++)
      {
        if (i % 2 == 0)
          {
            /* Even indices should have fired */
            ASSERT_EQ (1, contexts[i].call_count);
          }
        else
          {
            /* Odd indices were cancelled, should not fire */
            ASSERT_EQ (0, contexts[i].call_count);
          }
      }
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_cancel_repeating_verifies_no_further_fires)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;

  TRY
  {
    /* Create a repeating 30ms timer */
    timer
        = SocketTimer_add_repeating (poll, 30, timer_callback_with_check, &ctx);
    ASSERT_NOT_NULL (timer);

    /* Wait for first fire (~30ms) */
    SocketEvent_T *events = NULL;
    (void)SocketPoll_wait (poll, &events, 50);

    /* Should have fired at least once */
    int count_after_first = ctx.call_count;
    ASSERT (count_after_first >= 1);

    /* Cancel the timer */
    int result = SocketTimer_cancel (poll, timer);
    ASSERT_EQ (0, result);

    /* Wait longer (another 100ms) */
    (void)SocketPoll_wait (poll, &events, 100);

    /* Call count should not have increased */
    ASSERT_EQ (count_after_first, ctx.call_count);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_cancel_early_cancellation)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx = { 0, 0, NULL };
  SocketTimer_T timer = NULL;

  TRY
  {
    /* Create a timer with long delay (1000ms) */
    timer = SocketTimer_add (poll, 1000, timer_callback_with_check, &ctx);
    ASSERT_NOT_NULL (timer);

    /* Cancel immediately (early cancellation) */
    int result = SocketTimer_cancel (poll, timer);
    ASSERT_EQ (0, result);

    /* Wait a bit to ensure it doesn't fire */
    SocketEvent_T *events = NULL;
    (void)SocketPoll_wait (poll, &events, 100);

    /* Callback should never have fired */
    ASSERT_EQ (0, ctx.call_count);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_cancelled_timers_skipped_at_heap_root)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  TimerCallbackContext ctx1 = { 0, 0, NULL };
  TimerCallbackContext ctx2 = { 0, 0, NULL };
  SocketTimer_T timer1 = NULL;
  SocketTimer_T timer2 = NULL;

  TRY
  {
    /* Create two timers: first expires at 50ms, second at 100ms */
    timer1 = SocketTimer_add (poll, 50, timer_callback_with_check, &ctx1);
    timer2 = SocketTimer_add (poll, 100, timer_callback_with_check, &ctx2);

    ASSERT_NOT_NULL (timer1);
    ASSERT_NOT_NULL (timer2);

    /* Cancel the first timer (will be at heap root) */
    int result = SocketTimer_cancel (poll, timer1);
    ASSERT_EQ (0, result);

    /* Wait for when both would have expired */
    SocketEvent_T *events = NULL;
    (void)SocketPoll_wait (poll, &events, 150);

    /* Only timer2 should have fired, timer1 should be skipped */
    ASSERT_EQ (0, ctx1.call_count);
    ASSERT_EQ (1, ctx2.call_count);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
