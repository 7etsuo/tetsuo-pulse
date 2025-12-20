/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * rate_limit.c - Rate Limiting Example
 *
 * Demonstrates token bucket rate limiting using the SocketRateLimit API.
 * Shows rate limiter creation, token acquisition, wait time calculation,
 * dynamic reconfiguration, and bucket reset.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_rate_limit
 *
 * Usage:
 *   ./example_rate_limit [tokens_per_sec] [bucket_size]
 *   ./example_rate_limit 10 20
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketRateLimit.h"

/* Simulate an operation that requires rate limiting */
static void
perform_operation (int op_num)
{
  printf ("[INFO] Performing operation %d\n", op_num);
  usleep (50000); /* Simulate 50ms of work */
}

int
main (int argc, char **argv)
{
  /* Variables that might be clobbered by longjmp must be volatile */
  volatile size_t tokens_per_sec = 10;
  volatile size_t bucket_size = 20;
  Arena_T arena = NULL;
  SocketRateLimit_T limiter = NULL;
  volatile int result = 0;

  /* Parse command line arguments */
  if (argc > 1)
    tokens_per_sec = (size_t)atoi (argv[1]);
  if (argc > 2)
    bucket_size = (size_t)atoi (argv[2]);

  if (tokens_per_sec == 0)
    {
      fprintf (stderr, "Invalid parameters: tokens_per_sec must be > 0\n");
      return 1;
    }

  printf ("Rate Limiting Example\n");
  printf ("=====================\n\n");
  printf ("Configuration:\n");
  printf ("  Tokens per second: %zu\n", tokens_per_sec);
  printf ("  Bucket size: %zu\n\n", bucket_size);

  TRY
  {
    /* Create arena and rate limiter */
    arena = Arena_new ();
    limiter = SocketRateLimit_new (arena, tokens_per_sec, bucket_size);

    printf ("[OK] Rate limiter created\n");
    printf ("[INFO] Initial tokens available: %zu\n\n",
            SocketRateLimit_available (limiter));

    /* Test 1: Basic token acquisition */
    printf ("=== Test 1: Basic Token Acquisition ===\n");

    for (volatile int i = 0; i < 15; i++)
      {
        if (SocketRateLimit_try_acquire (limiter, 1))
          {
            printf ("[OK] Operation %d: Token acquired (available: %zu)\n",
                    i + 1, SocketRateLimit_available (limiter));
            perform_operation (i + 1);
          }
        else
          {
            printf ("[FAIL] Operation %d: Rate limited (available: %zu)\n",
                    i + 1, SocketRateLimit_available (limiter));
          }
      }

    printf ("\n");

    /* Test 2: Wait time calculation and polite backoff */
    printf ("=== Test 2: Wait Time Calculation ===\n");

    for (volatile int i = 0; i < 5; i++)
      {
        if (!SocketRateLimit_try_acquire (limiter, 1))
          {
            int64_t wait_ms = SocketRateLimit_wait_time_ms (limiter, 1);
            printf ("[INFO] Operation %d: Need to wait %ld ms\n", i + 1,
                    (long)wait_ms);

            if (wait_ms > 0 && wait_ms < 1000)
              {
                printf ("[INFO] Waiting %ld ms before retry...\n",
                        (long)wait_ms);
                usleep (wait_ms * 1000);

                if (SocketRateLimit_try_acquire (limiter, 1))
                  {
                    printf ("[OK] Operation %d: Token acquired after wait\n",
                            i + 1);
                    perform_operation (i + 1);
                  }
              }
          }
        else
          {
            printf ("[OK] Operation %d: Token acquired immediately\n", i + 1);
            perform_operation (i + 1);
          }
      }

    printf ("\n");

    /* Test 3: Query current configuration */
    printf ("=== Test 3: Query Configuration ===\n");
    printf ("[INFO] Current rate: %zu tokens/sec\n",
            SocketRateLimit_get_rate (limiter));
    printf ("[INFO] Current bucket size: %zu\n",
            SocketRateLimit_get_bucket_size (limiter));
    printf ("[INFO] Available tokens: %zu\n\n",
            SocketRateLimit_available (limiter));

    /* Test 4: Dynamic reconfiguration */
    printf ("=== Test 4: Dynamic Reconfiguration ===\n");
    printf ("[INFO] Reconfiguring to 5 tokens/sec, bucket size 10\n");

    SocketRateLimit_configure (limiter, 5, 10);

    printf ("[OK] Configuration updated\n");
    printf ("[INFO] New rate: %zu tokens/sec\n",
            SocketRateLimit_get_rate (limiter));
    printf ("[INFO] New bucket size: %zu\n",
            SocketRateLimit_get_bucket_size (limiter));
    printf ("[INFO] Available tokens after reconfigure: %zu\n\n",
            SocketRateLimit_available (limiter));

    /* Test 5: Bucket reset */
    printf ("=== Test 5: Bucket Reset ===\n");
    printf ("[INFO] Available tokens before reset: %zu\n",
            SocketRateLimit_available (limiter));

    SocketRateLimit_reset (limiter);

    printf ("[OK] Bucket reset to full capacity\n");
    printf ("[INFO] Available tokens after reset: %zu\n\n",
            SocketRateLimit_available (limiter));

    /* Test 6: Burst handling */
    printf ("=== Test 6: Burst Handling ===\n");
    printf ("[INFO] Attempting burst of 8 operations...\n");

    volatile int burst_success = 0;
    volatile int burst_failed = 0;

    for (volatile int i = 0; i < 8; i++)
      {
        if (SocketRateLimit_try_acquire (limiter, 1))
          {
            burst_success++;
            perform_operation (i + 1);
          }
        else
          {
            burst_failed++;
          }
      }

    printf ("[INFO] Burst complete: %d succeeded, %d failed\n", burst_success,
            burst_failed);
    printf ("[INFO] Remaining tokens: %zu\n\n",
            SocketRateLimit_available (limiter));

    /* Test 7: Multi-token acquisition */
    printf ("=== Test 7: Multi-Token Acquisition ===\n");

    SocketRateLimit_reset (limiter);
    printf ("[INFO] Reset bucket (available: %zu)\n",
            SocketRateLimit_available (limiter));

    volatile size_t tokens_needed = 5;
    printf ("[INFO] Attempting to acquire %zu tokens at once...\n",
            tokens_needed);

    if (SocketRateLimit_try_acquire (limiter, tokens_needed))
      {
        printf ("[OK] Acquired %zu tokens (remaining: %zu)\n", tokens_needed,
                SocketRateLimit_available (limiter));
      }
    else
      {
        printf ("[FAIL] Could not acquire %zu tokens\n", tokens_needed);
        int64_t wait_ms
            = SocketRateLimit_wait_time_ms (limiter, tokens_needed);
        printf ("[INFO] Need to wait %ld ms for %zu tokens\n", (long)wait_ms,
                tokens_needed);
      }

    printf ("\n");

    /* Test 8: Impossible acquisition */
    printf ("=== Test 8: Impossible Token Request ===\n");

    volatile size_t impossible_tokens = 100;
    int64_t impossible_wait
        = SocketRateLimit_wait_time_ms (limiter, impossible_tokens);

    if (impossible_wait == -1)
      {
        printf ("[OK] Correctly identified impossible request (%zu tokens > "
                "bucket size %zu)\n",
                impossible_tokens, SocketRateLimit_get_bucket_size (limiter));
      }
    else
      {
        printf ("[FAIL] Should have returned -1 for impossible request\n");
      }

    printf ("\n");

    /* Final statistics */
    printf ("=== Final Statistics ===\n");
    printf ("[INFO] Rate: %zu tokens/sec\n",
            SocketRateLimit_get_rate (limiter));
    printf ("[INFO] Bucket size: %zu\n",
            SocketRateLimit_get_bucket_size (limiter));
    printf ("[INFO] Available tokens: %zu\n",
            SocketRateLimit_available (limiter));
    printf ("[INFO] Live rate limiter instances: %d\n",
            SocketRateLimit_debug_live_count ());
  }
  EXCEPT (SocketRateLimit_Failed)
  {
    fprintf (stderr, "[FAIL] Rate limiter error\n");
    result = 1;
  }
  END_TRY;

  /* Cleanup */
  if (limiter)
    SocketRateLimit_free (&limiter);
  if (arena)
    Arena_dispose (&arena);

  printf ("\n[INFO] Live instances after cleanup: %d\n",
          SocketRateLimit_debug_live_count ());
  printf ("\nRate limiting example complete.\n");

  return result;
}
