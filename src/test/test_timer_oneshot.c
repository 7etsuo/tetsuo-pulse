/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_timer_oneshot.c - Comprehensive one-shot timer unit tests
 * Tests for SocketTimer_add() and related one-shot timer operations.
 * Covers basic timers, edge cases, timing accuracy, overflow protection,
 * and SocketPoll integration as specified in issue #3040.
 */

#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketTimer.h"
#include "core/SocketUtil.h"
#include "poll/SocketPoll.h"
#include "test/Test.h"

/* Suppress clobbering warnings for volatile test variables */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Test helper structures */
typedef struct
{
  volatile int fired;
  volatile int count;
  volatile int64_t fire_time;
} TimerContext;

static void
timer_callback (void *userdata)
{
  TimerContext *ctx = (TimerContext *)userdata;
  ctx->fired = 1;
  ctx->count++;
  ctx->fire_time = Socket_get_monotonic_ms ();
}

static void
setup_signals (void)
{
  signal (SIGPIPE, SIG_IGN);
}

TEST (timer_add_zero_delay)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  ASSERT_NOT_NULL (poll);

  volatile TimerContext ctx = { 0, 0, 0 };
  volatile int64_t start = Socket_get_monotonic_ms ();
  volatile SocketTimer_T timer = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 0, timer_callback, (void *)&ctx);
    ASSERT_NOT_NULL (timer);

    /* Zero delay timers should fire immediately */
    SocketEvent_T *events = NULL;
    int ready = SocketPoll_wait (poll, &events, 100);
    ASSERT (ready >= 0);

    /* Verify callback fired */
    ASSERT_EQ (ctx.fired, 1);
    ASSERT_EQ (ctx.count, 1);

    /* Verify timing - should be very close to start time */
    volatile int64_t elapsed = ctx.fire_time - start;
    ASSERT (elapsed >= 0 && elapsed <= 10); /* Within 10ms tolerance */
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_add_100ms_delay)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  ASSERT_NOT_NULL (poll);

  volatile TimerContext ctx = { 0, 0, 0 };
  volatile int64_t start = Socket_get_monotonic_ms ();
  volatile SocketTimer_T timer = NULL;
  volatile SocketEvent_T *events = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 100, timer_callback, (void *)&ctx);
    ASSERT_NOT_NULL (timer);

    /* Wait for timer to fire */
    events = NULL;
    int ready = SocketPoll_wait (poll, (SocketEvent_T **)&events, 200);
    ASSERT (ready >= 0);

    /* Verify callback fired exactly once */
    ASSERT_EQ (ctx.fired, 1);
    ASSERT_EQ (ctx.count, 1);

    /* Verify timing accuracy within ±5ms */
    volatile int64_t elapsed = ctx.fire_time - start;
    ASSERT (elapsed >= 95 && elapsed <= 105);

    /* Verify timer doesn't fire again */
    ctx.fired = 0;
    events = NULL;
    ready = SocketPoll_wait (poll, (SocketEvent_T **)&events, 100);
    ASSERT (ready >= 0);
    ASSERT_EQ (ctx.fired, 0); /* Should not fire again */
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_add_1000ms_delay)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  ASSERT_NOT_NULL (poll);

  volatile TimerContext ctx = { 0, 0, 0 };
  volatile int64_t start = Socket_get_monotonic_ms ();
  volatile SocketTimer_T timer = NULL;
  volatile SocketEvent_T *events = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 1000, timer_callback, (void *)&ctx);
    ASSERT_NOT_NULL (timer);

    /* Wait for timer to fire */
    events = NULL;
    int ready = SocketPoll_wait (poll, (SocketEvent_T **)&events, 1200);
    ASSERT (ready >= 0);

    /* Verify callback fired exactly once */
    ASSERT_EQ (ctx.fired, 1);
    ASSERT_EQ (ctx.count, 1);

    /* Verify timing accuracy within ±5ms */
    volatile int64_t elapsed = ctx.fire_time - start;
    ASSERT (elapsed >= 995 && elapsed <= 1005);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_add_multiple_different_delays)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  ASSERT_NOT_NULL (poll);

  volatile TimerContext ctx1 = { 0, 0, 0 };
  volatile TimerContext ctx2 = { 0, 0, 0 };
  volatile TimerContext ctx3 = { 0, 0, 0 };
  volatile SocketTimer_T timer1 = NULL;
  volatile SocketTimer_T timer2 = NULL;
  volatile SocketTimer_T timer3 = NULL;
  volatile SocketEvent_T *events = NULL;

  TRY
  {
    /* Add timers with different delays: 50ms, 100ms, 150ms */
    timer1 = SocketTimer_add (poll, 50, timer_callback, (void *)&ctx1);
    timer2 = SocketTimer_add (poll, 100, timer_callback, (void *)&ctx2);
    timer3 = SocketTimer_add (poll, 150, timer_callback, (void *)&ctx3);

    ASSERT_NOT_NULL (timer1);
    ASSERT_NOT_NULL (timer2);
    ASSERT_NOT_NULL (timer3);

    /* Wait for first timer */
    events = NULL;
    SocketPoll_wait (poll, (SocketEvent_T **)&events, 60);
    ASSERT_EQ (ctx1.fired, 1);
    ASSERT_EQ (ctx2.fired, 0);
    ASSERT_EQ (ctx3.fired, 0);

    /* Wait for second timer */
    events = NULL;
    SocketPoll_wait (poll, (SocketEvent_T **)&events, 60);
    ASSERT_EQ (ctx1.fired, 1);
    ASSERT_EQ (ctx2.fired, 1);
    ASSERT_EQ (ctx3.fired, 0);

    /* Wait for third timer */
    events = NULL;
    SocketPoll_wait (poll, (SocketEvent_T **)&events, 60);
    ASSERT_EQ (ctx1.fired, 1);
    ASSERT_EQ (ctx2.fired, 1);
    ASSERT_EQ (ctx3.fired, 1);

    /* Verify ordering: timer1 < timer2 < timer3 */
    ASSERT (ctx1.fire_time < ctx2.fire_time);
    ASSERT (ctx2.fire_time < ctx3.fire_time);

    /* Verify each timer fired exactly once */
    ASSERT_EQ (ctx1.count, 1);
    ASSERT_EQ (ctx2.count, 1);
    ASSERT_EQ (ctx3.count, 1);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_add_max_delay)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  ASSERT_NOT_NULL (poll);

  volatile TimerContext ctx = { 0, 0, 0 };
  volatile SocketTimer_T timer = NULL;
  volatile SocketEvent_T *events = NULL;

  TRY
  {
    /* Add timer with maximum allowed delay */
    timer = SocketTimer_add (
        poll, SOCKET_MAX_TIMER_DELAY_MS, timer_callback, (void *)&ctx);
    ASSERT_NOT_NULL (timer);

    /* Timer shouldn't fire in short time */
    events = NULL;
    int ready = SocketPoll_wait (poll, (SocketEvent_T **)&events, 10);
    ASSERT (ready >= 0);
    ASSERT_EQ (ctx.fired, 0);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_add_exceeds_max_delay)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  ASSERT_NOT_NULL (poll);

  volatile TimerContext ctx = { 0, 0, 0 };
  volatile int exception_caught = 0;

  TRY
  {
    /* Try to add timer exceeding max delay - should raise exception */
    SocketTimer_add (
        poll, SOCKET_MAX_TIMER_DELAY_MS + 1, timer_callback, (void *)&ctx);
    ASSERT (0); /* Should not reach here */
  }
  EXCEPT (SocketTimer_Failed)
  {
    exception_caught = 1;
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;

  ASSERT_EQ (exception_caught, 1);
}

TEST (timer_add_negative_delay)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  ASSERT_NOT_NULL (poll);

  volatile TimerContext ctx = { 0, 0, 0 };
  volatile int exception_caught = 0;

  TRY
  {
    /* Try to add timer with negative delay - should raise exception */
    SocketTimer_add (poll, -1, timer_callback, (void *)&ctx);
    ASSERT (0); /* Should not reach here */
  }
  EXCEPT (SocketTimer_Failed)
  {
    exception_caught = 1;
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;

  ASSERT_EQ (exception_caught, 1);
}

TEST (timer_accuracy_within_tolerance)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  ASSERT_NOT_NULL (poll);

  /* Test multiple delays for accuracy */
  int delays[] = { 50, 100, 200, 500 };
  int num_tests = sizeof (delays) / sizeof (delays[0]);

  for (int i = 0; i < num_tests; i++)
    {
      volatile TimerContext ctx = { 0, 0, 0 };
      volatile int64_t start = Socket_get_monotonic_ms ();
      volatile SocketTimer_T timer = NULL;
      volatile SocketEvent_T *events = NULL;

      TRY
      {
        timer = SocketTimer_add (poll, delays[i], timer_callback, (void *)&ctx);
        ASSERT_NOT_NULL (timer);

        /* Wait with some margin */
        events = NULL;
        SocketPoll_wait (poll, (SocketEvent_T **)&events, delays[i] + 50);

        /* Verify timing is within ±5ms */
        volatile int64_t elapsed = ctx.fire_time - start;
        ASSERT (elapsed >= delays[i] - 5 && elapsed <= delays[i] + 5);
      }
      FINALLY
      {
        /* Poll is cleaned up outside loop */
      }
      END_TRY;
    }

  SocketPoll_free (&poll);
}

TEST (timer_add_overflow_clamping)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  ASSERT_NOT_NULL (poll);

  volatile TimerContext ctx = { 0, 0, 0 };
  volatile SocketTimer_T timer = NULL;
  volatile SocketEvent_T *events = NULL;

  TRY
  {
    /* Add timer with maximum allowed delay
     * The implementation should handle this without overflow
     */
    int64_t max_delay = SOCKET_MAX_TIMER_DELAY_MS;
    timer = SocketTimer_add (poll, max_delay, timer_callback, (void *)&ctx);
    ASSERT_NOT_NULL (timer);

    /* Timer shouldn't fire immediately */
    events = NULL;
    int ready = SocketPoll_wait (poll, (SocketEvent_T **)&events, 10);
    ASSERT (ready >= 0);
    ASSERT_EQ (ctx.fired, 0);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_add_then_cancel)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  ASSERT_NOT_NULL (poll);

  volatile TimerContext ctx = { 0, 0, 0 };
  volatile SocketTimer_T timer = NULL;
  volatile SocketEvent_T *events = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 100, timer_callback, (void *)&ctx);
    ASSERT_NOT_NULL (timer);

    /* Cancel the timer before it fires */
    int result = SocketTimer_cancel (poll, (SocketTimer_T)timer);
    ASSERT_EQ (result, 0);

    /* Wait past the timer delay */
    events = NULL;
    SocketPoll_wait (poll, (SocketEvent_T **)&events, 150);

    /* Verify callback never fired */
    ASSERT_EQ (ctx.fired, 0);
    ASSERT_EQ (ctx.count, 0);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_add_cancel_after_fire)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  ASSERT_NOT_NULL (poll);

  volatile TimerContext ctx = { 0, 0, 0 };
  volatile SocketTimer_T timer = NULL;
  volatile SocketEvent_T *events = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 50, timer_callback, (void *)&ctx);
    ASSERT_NOT_NULL (timer);

    /* Wait for timer to fire */
    events = NULL;
    SocketPoll_wait (poll, (SocketEvent_T **)&events, 100);
    ASSERT_EQ (ctx.fired, 1);

    /* Try to cancel already-fired timer - should return -1 */
    int result = SocketTimer_cancel (poll, (SocketTimer_T)timer);
    ASSERT_EQ (result, -1);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_add_check_remaining)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  ASSERT_NOT_NULL (poll);

  volatile TimerContext ctx = { 0, 0, 0 };
  volatile SocketTimer_T timer = NULL;
  volatile SocketEvent_T *events = NULL;

  TRY
  {
    timer = SocketTimer_add (poll, 500, timer_callback, (void *)&ctx);
    ASSERT_NOT_NULL (timer);

    /* Check remaining time shortly after creation */
    usleep (10000); /* 10ms */
    int64_t remaining = SocketTimer_remaining (poll, (SocketTimer_T)timer);
    ASSERT (remaining > 0 && remaining <= 500);

    /* Wait half the delay */
    usleep (250000); /* 250ms */
    remaining = SocketTimer_remaining (poll, (SocketTimer_T)timer);
    ASSERT (remaining >= 200 && remaining <= 260);

    /* Wait for timer to fire */
    events = NULL;
    SocketPoll_wait (poll, (SocketEvent_T **)&events, 300);
    ASSERT_EQ (ctx.fired, 1);

    /* After firing, remaining should return -1 */
    remaining = SocketTimer_remaining (poll, (SocketTimer_T)timer);
    ASSERT_EQ (remaining, -1);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_integration_with_poll)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  ASSERT_NOT_NULL (poll);

  volatile TimerContext ctx1 = { 0, 0, 0 };
  volatile TimerContext ctx2 = { 0, 0, 0 };
  volatile SocketTimer_T timer1 = NULL;
  volatile SocketTimer_T timer2 = NULL;
  volatile SocketEvent_T *events = NULL;

  TRY
  {
    /* Add multiple timers to the same poll instance */
    timer1 = SocketTimer_add (poll, 50, timer_callback, (void *)&ctx1);
    timer2 = SocketTimer_add (poll, 100, timer_callback, (void *)&ctx2);

    ASSERT_NOT_NULL (timer1);
    ASSERT_NOT_NULL (timer2);

    /* Wait for both timers to fire with multiple poll calls */
    events = NULL;
    SocketPoll_wait (poll, (SocketEvent_T **)&events, 60);
    events = NULL;
    SocketPoll_wait (poll, (SocketEvent_T **)&events, 60);

    /* Both timers should have fired */
    ASSERT_EQ (ctx1.fired, 1);
    ASSERT_EQ (ctx2.fired, 1);

    /* Verify proper ordering */
    ASSERT (ctx1.fire_time <= ctx2.fire_time);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_poll_respects_timer_deadline)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (10);
  ASSERT_NOT_NULL (poll);

  volatile TimerContext ctx = { 0, 0, 0 };
  volatile int64_t start = Socket_get_monotonic_ms ();
  volatile SocketTimer_T timer = NULL;
  volatile SocketEvent_T *events = NULL;

  TRY
  {
    /* Add timer with short delay */
    timer = SocketTimer_add (poll, 100, timer_callback, (void *)&ctx);
    ASSERT_NOT_NULL (timer);

    /* Wait with longer timeout - should return when timer fires */
    events = NULL;
    int ready = SocketPoll_wait (poll, (SocketEvent_T **)&events, 1000);
    ASSERT (ready >= 0);

    /* Verify timer fired close to its deadline, not the full wait timeout */
    volatile int64_t elapsed = Socket_get_monotonic_ms () - start;
    ASSERT (elapsed >= 95 && elapsed <= 150);
    ASSERT_EQ (ctx.fired, 1);
  }
  FINALLY
  {
    SocketPoll_free (&poll);
  }
  END_TRY;
}

TEST (timer_add_many_timers)
{
  setup_signals ();
  SocketPoll_T poll = SocketPoll_new (100);
  ASSERT_NOT_NULL (poll);

  /* Create multiple timer contexts */
  volatile int num_timers = 50;
  TimerContext contexts[50];
  memset ((void *)contexts, 0, sizeof (contexts));
  volatile SocketEvent_T *events = NULL;

  TRY
  {
    /* Add many timers with different delays */
    for (int i = 0; i < num_timers; i++)
      {
        int delay = (i + 1) * 10; /* 10ms, 20ms, 30ms, ... */
        SocketTimer_T timer = SocketTimer_add (
            poll, delay, timer_callback, (void *)&contexts[i]);
        ASSERT_NOT_NULL (timer);
      }

    /* Wait for all timers to fire - may need multiple poll calls */
    for (int i = 0; i < num_timers + 5; i++)
      {
        events = NULL;
        SocketPoll_wait (poll, (SocketEvent_T **)&events, 20);
      }

    /* Verify all timers fired exactly once */
    for (int i = 0; i < num_timers; i++)
      {
        ASSERT_EQ (contexts[i].fired, 1);
        ASSERT_EQ (contexts[i].count, 1);
      }
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
  return Test_get_failures () > 0 ? 1 : 0;
}
