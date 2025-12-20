/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * timer_demo.c - High-Performance Timer Demonstration
 *
 * Demonstrates the SocketTimer API integrated with the event loop.
 * Shows one-shot timers, repeating timers, cancellation, pause/resume,
 * and querying remaining time.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_timer_demo
 *
 * Usage:
 *   ./example_timer_demo
 *
 * Features demonstrated:
 *   - Creating one-shot timers with SocketTimer_add()
 *   - Creating repeating timers with SocketTimer_add_repeating()
 *   - Timer callbacks firing during SocketPoll_wait()
 *   - Cancelling timers with SocketTimer_cancel()
 *   - Pausing and resuming timers
 *   - Querying remaining time with SocketTimer_remaining()
 */

#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/Except.h"
#include "core/SocketTimer.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"

/* Global flag for graceful shutdown */
static volatile sig_atomic_t running = 1;

/* Context structure for timer callbacks */
typedef struct TimerContext
{
  const char *name;
  int fire_count;
  int max_fires;
} TimerContext;

static void
signal_handler (int signo)
{
  (void)signo;
  running = 0;
}

/* One-shot timer callback */
static void
oneshot_callback (void *userdata)
{
  TimerContext *ctx = (TimerContext *)userdata;
  ctx->fire_count++;
  printf ("   [TIMER] '%s' fired (one-shot, count=%d)\n", ctx->name,
          ctx->fire_count);
}

/* Repeating timer callback */
static void
repeating_callback (void *userdata)
{
  TimerContext *ctx = (TimerContext *)userdata;
  ctx->fire_count++;
  printf ("   [TIMER] '%s' fired (repeating, count=%d/%d)\n", ctx->name,
          ctx->fire_count, ctx->max_fires);
}

/* Cancellable timer callback */
static void
cancellable_callback (void *userdata)
{
  TimerContext *ctx = (TimerContext *)userdata;
  ctx->fire_count++;
  printf ("   [TIMER] '%s' fired (should not see this!)\n", ctx->name);
}

/* Pausable timer callback */
static void
pausable_callback (void *userdata)
{
  TimerContext *ctx = (TimerContext *)userdata;
  ctx->fire_count++;
  printf ("   [TIMER] '%s' fired after resume (count=%d)\n", ctx->name,
          ctx->fire_count);
}

int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  SocketPoll_T poll = NULL;
  volatile int result = 0;

  /* Timer contexts */
  TimerContext ctx_oneshot_1 = { "OneShot-1s", 0, 1 };
  TimerContext ctx_oneshot_3 = { "OneShot-3s", 0, 1 };
  TimerContext ctx_repeating = { "Repeating-2s", 0, 3 };
  TimerContext ctx_cancel = { "ToBeCancelled", 0, 0 };
  TimerContext ctx_pause = { "PauseResume-4s", 0, 1 };

  /* Timer handles */
  SocketTimer_T timer_oneshot_1 = NULL;
  SocketTimer_T timer_oneshot_3 = NULL;
  SocketTimer_T timer_repeating = NULL;
  SocketTimer_T timer_cancel = NULL;
  SocketTimer_T timer_pause = NULL;

  /* Setup signal handling */
  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);
  signal (SIGPIPE, SIG_IGN);

  printf ("SocketTimer Demo\n");
  printf ("================\n\n");
  printf ("This demo showcases the high-performance timer API.\n");
  printf ("Press Ctrl+C to exit early\n\n");

  TRY
  {
    /* Step 1: Create SocketPoll instance */
    printf ("1. Creating SocketPoll instance...\n");
    poll = SocketPoll_new (64);
    printf ("   [OK] Poll instance created (backend: %s)\n\n",
            SocketPoll_get_backend_name (poll));

    /* Step 2: Add one-shot timers */
    printf ("2. Adding one-shot timers...\n");

    timer_oneshot_1 = SocketTimer_add (poll, 1000, oneshot_callback,
                                       (void *)&ctx_oneshot_1);
    printf ("   [OK] Added 1-second one-shot timer\n");

    timer_oneshot_3 = SocketTimer_add (poll, 3000, oneshot_callback,
                                       (void *)&ctx_oneshot_3);
    printf ("   [OK] Added 3-second one-shot timer\n\n");

    /* Step 3: Add repeating timer */
    printf ("3. Adding repeating timer...\n");
    timer_repeating = SocketTimer_add_repeating (
        poll, 2000, repeating_callback, (void *)&ctx_repeating);
    printf ("   [OK] Added 2-second repeating timer (will fire 3 times)\n\n");

    /* Step 4: Add timer that will be cancelled */
    printf ("4. Adding timer to be cancelled...\n");
    timer_cancel = SocketTimer_add (poll, 5000, cancellable_callback,
                                    (void *)&ctx_cancel);
    printf (
        "   [OK] Added 5-second timer (will be cancelled before firing)\n\n");

    /* Step 5: Add timer that will be paused and resumed */
    printf ("5. Adding timer for pause/resume demo...\n");
    timer_pause
        = SocketTimer_add (poll, 4000, pausable_callback, (void *)&ctx_pause);
    printf ("   [OK] Added 4-second timer (will be paused and resumed)\n\n");

    /* Step 6: Query remaining time before event loop */
    printf ("6. Querying initial remaining times...\n");
    int64_t rem1 = SocketTimer_remaining (poll, timer_oneshot_1);
    int64_t rem3 = SocketTimer_remaining (poll, timer_oneshot_3);
    int64_t rem_rep = SocketTimer_remaining (poll, timer_repeating);
    int64_t rem_cancel = SocketTimer_remaining (poll, timer_cancel);
    int64_t rem_pause = SocketTimer_remaining (poll, timer_pause);

    printf ("   [INFO] OneShot-1s remaining: %" PRId64 " ms\n", rem1);
    printf ("   [INFO] OneShot-3s remaining: %" PRId64 " ms\n", rem3);
    printf ("   [INFO] Repeating-2s remaining: %" PRId64 " ms\n", rem_rep);
    printf ("   [INFO] ToBeCancelled remaining: %" PRId64 " ms\n", rem_cancel);
    printf ("   [INFO] PauseResume-4s remaining: %" PRId64 " ms\n\n",
            rem_pause);

    /* Step 7: Event loop with timer demonstrations */
    printf ("7. Starting event loop (timers will fire automatically)...\n\n");

    int loop_count = 0;
    int paused_at_loop = -1;
    int resumed_at_loop = -1;
    int cancelled_at_loop = -1;

    while (running && loop_count < 20)
      {
        SocketEvent_T *events;
        int nev = SocketPoll_wait (poll, &events, 500); /* 500ms timeout */

        loop_count++;
        printf ("[LOOP %d] Poll returned %d events\n", loop_count, nev);

        /* Pause timer after 1.5 seconds (around loop 3) */
        if (loop_count == 3 && timer_pause && paused_at_loop == -1)
          {
            printf ("\n8. Pausing 4-second timer...\n");
            int pause_result = SocketTimer_pause (poll, timer_pause);
            if (pause_result == 0)
              {
                int64_t remaining = SocketTimer_remaining (poll, timer_pause);
                printf ("   [OK] Timer paused with %" PRId64 " ms remaining\n",
                        remaining);
                paused_at_loop = loop_count;
              }
            else
              {
                printf ("   [FAIL] Failed to pause timer\n");
              }
            printf ("\n");
          }

        /* Resume timer after 3 seconds (around loop 6) */
        if (loop_count == 6 && timer_pause && paused_at_loop != -1
            && resumed_at_loop == -1)
          {
            printf ("\n9. Resuming paused timer...\n");
            int resume_result = SocketTimer_resume (poll, timer_pause);
            if (resume_result == 0)
              {
                int64_t remaining = SocketTimer_remaining (poll, timer_pause);
                printf ("   [OK] Timer resumed with %" PRId64
                        " ms remaining\n",
                        remaining);
                resumed_at_loop = loop_count;
              }
            else
              {
                printf ("   [FAIL] Failed to resume timer\n");
              }
            printf ("\n");
          }

        /* Cancel the 5-second timer before it fires (around loop 4) */
        if (loop_count == 4 && timer_cancel && cancelled_at_loop == -1)
          {
            printf ("\n10. Cancelling 5-second timer before it fires...\n");
            int cancel_result = SocketTimer_cancel (poll, timer_cancel);
            if (cancel_result == 0)
              {
                printf ("   [OK] Timer cancelled successfully\n");
                timer_cancel = NULL; /* Mark as invalid */
                cancelled_at_loop = loop_count;
              }
            else
              {
                printf ("   [FAIL] Failed to cancel timer (may have already "
                        "fired)\n");
              }
            printf ("\n");
          }

        /* Cancel repeating timer after 3 fires */
        if (ctx_repeating.fire_count >= ctx_repeating.max_fires
            && timer_repeating)
          {
            printf ("\n11. Cancelling repeating timer after %d fires...\n",
                    ctx_repeating.max_fires);
            int cancel_result = SocketTimer_cancel (poll, timer_repeating);
            if (cancel_result == 0)
              {
                printf ("   [OK] Repeating timer cancelled\n");
                timer_repeating = NULL;
              }
            else
              {
                printf ("   [WARN] Repeating timer already invalid\n");
              }
            printf ("\n");
          }

        /* Check if we're done with all demonstrations */
        if (ctx_oneshot_1.fire_count >= 1 && ctx_oneshot_3.fire_count >= 1
            && ctx_repeating.fire_count >= ctx_repeating.max_fires
            && cancelled_at_loop != -1 && ctx_pause.fire_count >= 1)
          {
            printf ("\n[INFO] All timer demonstrations completed!\n");
            break;
          }

        /* Brief sleep to avoid spinning too fast */
        usleep (100000); /* 100ms */
      }

    printf ("\n");

    /* Step 8: Display results */
    printf ("12. Timer Demonstration Results:\n");
    printf ("   OneShot-1s fires:       %d (expected: 1)\n",
            ctx_oneshot_1.fire_count);
    printf ("   OneShot-3s fires:       %d (expected: 1)\n",
            ctx_oneshot_3.fire_count);
    printf ("   Repeating-2s fires:     %d (expected: 3)\n",
            ctx_repeating.fire_count);
    printf ("   ToBeCancelled fires:    %d (expected: 0 - cancelled)\n",
            ctx_cancel.fire_count);
    printf ("   PauseResume-4s fires:   %d (expected: 1 - after resume)\n",
            ctx_pause.fire_count);
    printf ("\n");

    /* Verify results */
    int all_passed = 1;

    if (ctx_oneshot_1.fire_count != 1)
      {
        printf ("   [FAIL] OneShot-1s: expected 1 fire, got %d\n",
                ctx_oneshot_1.fire_count);
        all_passed = 0;
      }
    else
      {
        printf ("   [OK] OneShot-1s test passed\n");
      }

    if (ctx_oneshot_3.fire_count != 1)
      {
        printf ("   [FAIL] OneShot-3s: expected 1 fire, got %d\n",
                ctx_oneshot_3.fire_count);
        all_passed = 0;
      }
    else
      {
        printf ("   [OK] OneShot-3s test passed\n");
      }

    if (ctx_repeating.fire_count != ctx_repeating.max_fires)
      {
        printf ("   [FAIL] Repeating-2s: expected %d fires, got %d\n",
                ctx_repeating.max_fires, ctx_repeating.fire_count);
        all_passed = 0;
      }
    else
      {
        printf ("   [OK] Repeating-2s test passed\n");
      }

    if (ctx_cancel.fire_count != 0)
      {
        printf ("   [FAIL] ToBeCancelled: expected 0 fires (cancelled), got "
                "%d\n",
                ctx_cancel.fire_count);
        all_passed = 0;
      }
    else
      {
        printf ("   [OK] Cancellation test passed\n");
      }

    if (ctx_pause.fire_count != 1)
      {
        printf ("   [FAIL] PauseResume-4s: expected 1 fire, got %d\n",
                ctx_pause.fire_count);
        all_passed = 0;
      }
    else
      {
        printf ("   [OK] Pause/Resume test passed\n");
      }

    printf ("\n");

    if (all_passed)
      {
        printf ("[OK] All timer tests passed!\n\n");
      }
    else
      {
        printf ("[FAIL] Some timer tests failed\n\n");
        result = 1;
      }
  }
  EXCEPT (SocketTimer_Failed)
  {
    fprintf (stderr, "\n[ERROR] Timer operation failed\n");
    result = 1;
  }
  EXCEPT (SocketPoll_Failed)
  {
    fprintf (stderr, "\n[ERROR] Poll operation failed\n");
    result = 1;
  }
  ELSE
  {
    fprintf (stderr, "\n[ERROR] Unknown error occurred\n");
    result = 1;
  }
  END_TRY;

  /* Cleanup */
  printf ("13. Cleaning up...\n");
  if (poll)
    {
      SocketPoll_free (&poll);
      printf ("   [OK] Poll instance freed\n");
    }

  printf ("\n%s\n", result == 0 ? "[OK] Timer demo completed successfully!"
                                : "[FAIL] Timer demo completed with errors");

  return result;
}
