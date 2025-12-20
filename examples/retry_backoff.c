/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * retry_backoff.c - Exponential Backoff Retry Example
 *
 * Demonstrates the SocketRetry API for handling transient failures with
 * exponential backoff, jitter, and custom retry policies.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_retry_backoff
 *
 * Usage:
 *   ./example_retry_backoff
 *
 * This example shows:
 *   - Creating retry contexts with custom policies
 *   - Executing retryable operations with SocketRetry_execute()
 *   - Exponential backoff with jitter
 *   - Success after transient failures
 *   - Retry statistics and monitoring
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/Except.h"
#include "core/SocketRetry.h"

/* ============================================================================
 * Simulated Operations
 * ============================================================================
 */

/* Context for simulated network operation */
typedef struct
{
  int attempts_before_success; /* Fail this many times before succeeding */
  int current_attempt;         /* Current attempt counter */
  const char *operation_name;  /* Name for logging */
} SimulatedOp_Context;

/**
 * Simulated unreliable operation that fails transiently.
 * Succeeds after a configured number of failures.
 */
static int
simulated_network_op (void *context, int attempt)
{
  SimulatedOp_Context *ctx = (SimulatedOp_Context *)context;

  printf ("   [ATTEMPT %d] %s (attempt %d)\n", attempt, ctx->operation_name,
          ctx->current_attempt + 1);

  ctx->current_attempt++;

  /* Simulate transient failures */
  if (ctx->current_attempt < ctx->attempts_before_success)
    {
      /* Simulate different error types */
      int errors[] = { ETIMEDOUT, ECONNREFUSED, EAGAIN, ENETUNREACH };
      int error_code = errors[ctx->current_attempt % 4];

      printf ("      [FAIL] Transient error: %s (errno=%d)\n",
              strerror (error_code), error_code);
      return error_code;
    }

  /* Success! */
  printf ("      [OK] Operation succeeded\n");
  return 0;
}

/**
 * Custom should_retry callback - only retry specific error codes
 */
static int
should_retry_network_errors (int error, int attempt, void *context)
{
  (void)context; /* Unused */

  /* Only retry transient network errors */
  switch (error)
    {
    case ETIMEDOUT:
    case ECONNREFUSED:
    case EAGAIN: /* EWOULDBLOCK is same as EAGAIN on Linux */
    case ENETUNREACH:
    case EHOSTUNREACH:
      printf ("      [INFO] Error is retryable (attempt %d)\n", attempt);
      return 1; /* Retry */

    default:
      printf ("      [INFO] Error is NOT retryable\n");
      return 0; /* Don't retry */
    }
}

/* ============================================================================
 * Helper Functions
 * ============================================================================
 */

static void
print_policy (const SocketRetry_Policy *policy)
{
  printf ("   Max attempts:       %d\n", policy->max_attempts);
  printf ("   Initial delay:      %d ms\n", policy->initial_delay_ms);
  printf ("   Max delay:          %d ms\n", policy->max_delay_ms);
  printf ("   Backoff multiplier: %.1f\n", policy->multiplier);
  printf ("   Jitter factor:      %.0f%%\n", policy->jitter * 100);
}

static void
print_stats (const SocketRetry_Stats *stats)
{
  printf ("   Total attempts:     %d\n", stats->attempts);
  printf ("   Last error:         %d (%s)\n", stats->last_error,
          stats->last_error == 0 ? "SUCCESS" : strerror (stats->last_error));
  printf ("   Total delay:        %lld ms\n",
          (long long)stats->total_delay_ms);
  printf ("   Total time:         %lld ms\n", (long long)stats->total_time_ms);
}

static void
print_separator (void)
{
  printf ("\n");
  for (int i = 0; i < 70; i++)
    printf ("-");
  printf ("\n\n");
}

/* ============================================================================
 * Example Scenarios
 * ============================================================================
 */

/**
 * Example 1: Default retry policy
 */
static void
example_default_policy (void)
{
  printf ("Example 1: Default Retry Policy\n");
  printf ("================================\n\n");

  TRY
  {
    /* Create retry context with default policy */
    printf ("1. Creating retry context with default policy...\n");
    SocketRetry_T retry = SocketRetry_new (NULL);
    printf ("   [OK] Retry context created\n\n");

    /* Show default policy */
    printf ("2. Default policy settings:\n");
    SocketRetry_Policy policy;
    SocketRetry_get_policy (retry, &policy);
    print_policy (&policy);
    printf ("\n");

    /* Execute operation that fails twice, then succeeds */
    printf ("3. Executing operation (fails 2 times, then succeeds)...\n");
    SimulatedOp_Context ctx
        = { .attempts_before_success = 3,
            .current_attempt = 0,
            .operation_name = "Network request with default policy" };

    int result
        = SocketRetry_execute_simple (retry, simulated_network_op, &ctx);

    printf ("\n4. Operation result: %s\n",
            result == 0 ? "[OK] Success" : "[FAIL] Failed");

    /* Show statistics */
    printf ("\n5. Retry statistics:\n");
    SocketRetry_Stats stats;
    SocketRetry_get_stats (retry, &stats);
    print_stats (&stats);

    /* Cleanup */
    SocketRetry_free (&retry);

    printf ("\n   [OK] Example 1 completed\n");
  }
  EXCEPT (SocketRetry_Failed)
  {
    fprintf (stderr, "   [FAIL] Retry error in Example 1\n");
  }
  END_TRY;

  print_separator ();
}

/**
 * Example 2: Custom aggressive retry policy
 */
static void
example_custom_policy (void)
{
  printf ("Example 2: Custom Aggressive Retry Policy\n");
  printf ("==========================================\n\n");

  TRY
  {
    /* Create custom policy for aggressive retries */
    printf ("1. Creating custom retry policy...\n");

    SocketRetry_Policy custom_policy;
    SocketRetry_policy_defaults (&custom_policy);

    /* Customize for more aggressive retries */
    custom_policy.max_attempts = 5;      /* Try up to 5 times */
    custom_policy.initial_delay_ms = 50; /* Start with 50ms */
    custom_policy.max_delay_ms = 2000;   /* Cap at 2 seconds */
    custom_policy.multiplier = 1.5;      /* Gentler backoff */
    custom_policy.jitter = 0.3;          /* More randomization */

    printf ("   Custom policy:\n");
    print_policy (&custom_policy);
    printf ("\n");

    /* Create retry context with custom policy */
    printf ("2. Creating retry context with custom policy...\n");
    SocketRetry_T retry = SocketRetry_new (&custom_policy);
    printf ("   [OK] Retry context created\n\n");

    /* Execute operation that fails 3 times, then succeeds */
    printf ("3. Executing operation (fails 3 times, then succeeds)...\n");
    SimulatedOp_Context ctx
        = { .attempts_before_success = 4,
            .current_attempt = 0,
            .operation_name = "Network request with aggressive policy" };

    int result
        = SocketRetry_execute_simple (retry, simulated_network_op, &ctx);

    printf ("\n4. Operation result: %s\n",
            result == 0 ? "[OK] Success" : "[FAIL] Failed");

    /* Show statistics */
    printf ("\n5. Retry statistics:\n");
    SocketRetry_Stats stats;
    SocketRetry_get_stats (retry, &stats);
    print_stats (&stats);

    /* Cleanup */
    SocketRetry_free (&retry);

    printf ("\n   [OK] Example 2 completed\n");
  }
  EXCEPT (SocketRetry_Failed)
  {
    fprintf (stderr, "   [FAIL] Retry error in Example 2\n");
  }
  END_TRY;

  print_separator ();
}

/**
 * Example 3: Custom should_retry logic
 */
static void
example_should_retry (void)
{
  printf ("Example 3: Custom Should-Retry Logic\n");
  printf ("=====================================\n\n");

  TRY
  {
    /* Create retry context with default policy */
    printf ("1. Creating retry context...\n");
    SocketRetry_T retry = SocketRetry_new (NULL);
    printf ("   [OK] Retry context created\n\n");

    /* Execute with custom should_retry callback */
    printf ("2. Executing with custom should_retry (only retries network "
            "errors)...\n");
    SimulatedOp_Context ctx
        = { .attempts_before_success = 3,
            .current_attempt = 0,
            .operation_name = "Operation with selective retry" };

    int result = SocketRetry_execute (retry, simulated_network_op,
                                      should_retry_network_errors, &ctx);

    printf ("\n3. Operation result: %s\n",
            result == 0 ? "[OK] Success" : "[FAIL] Failed");

    /* Show statistics */
    printf ("\n4. Retry statistics:\n");
    SocketRetry_Stats stats;
    SocketRetry_get_stats (retry, &stats);
    print_stats (&stats);

    /* Cleanup */
    SocketRetry_free (&retry);

    printf ("\n   [OK] Example 3 completed\n");
  }
  EXCEPT (SocketRetry_Failed)
  {
    fprintf (stderr, "   [FAIL] Retry error in Example 3\n");
  }
  END_TRY;

  print_separator ();
}

/**
 * Example 4: Exhausting retry attempts
 */
static void
example_exhausted_retries (void)
{
  printf ("Example 4: Exhausting Retry Attempts\n");
  printf ("=====================================\n\n");

  TRY
  {
    /* Create policy with limited attempts */
    printf ("1. Creating retry context with limited attempts...\n");

    SocketRetry_Policy limited_policy;
    SocketRetry_policy_defaults (&limited_policy);
    limited_policy.max_attempts = 3; /* Only try 3 times */

    SocketRetry_T retry = SocketRetry_new (&limited_policy);
    printf ("   [OK] Retry context created (max 3 attempts)\n\n");

    /* Execute operation that never succeeds */
    printf ("2. Executing operation (always fails)...\n");
    SimulatedOp_Context ctx
        = { .attempts_before_success = 100, /* Never succeeds */
            .current_attempt = 0,
            .operation_name = "Operation that always fails" };

    int result
        = SocketRetry_execute_simple (retry, simulated_network_op, &ctx);

    printf ("\n3. Operation result: %s\n",
            result == 0 ? "[OK] Success" : "[FAIL] Failed after all retries");

    /* Show statistics */
    printf ("\n4. Retry statistics:\n");
    SocketRetry_Stats stats;
    SocketRetry_get_stats (retry, &stats);
    print_stats (&stats);

    /* Cleanup */
    SocketRetry_free (&retry);

    printf ("\n   [OK] Example 4 completed (expected failure)\n");
  }
  EXCEPT (SocketRetry_Failed)
  {
    fprintf (stderr, "   [FAIL] Retry error in Example 4\n");
  }
  END_TRY;

  print_separator ();
}

/**
 * Example 5: Delay calculation preview
 */
static void
example_delay_calculation (void)
{
  printf ("Example 5: Exponential Backoff Delay Preview\n");
  printf ("=============================================\n\n");

  printf ("1. Preview of backoff delays for different policies:\n\n");

  /* Default policy */
  SocketRetry_Policy default_policy;
  SocketRetry_policy_defaults (&default_policy);

  printf ("   Default Policy:\n");
  print_policy (&default_policy);
  printf ("\n   Calculated delays (with jitter, approximate):\n");

  /* Seed for consistent jitter demo */
  srand (12345);

  for (int attempt = 1; attempt <= 5; attempt++)
    {
      int delay = SocketRetry_calculate_delay (&default_policy, attempt);
      printf ("      Attempt %d: %d ms\n", attempt, delay);
    }

  printf ("\n");

  /* Custom policy with higher multiplier */
  SocketRetry_Policy aggressive_backoff;
  SocketRetry_policy_defaults (&aggressive_backoff);
  aggressive_backoff.initial_delay_ms = 200;
  aggressive_backoff.multiplier = 3.0;
  aggressive_backoff.max_delay_ms = 10000;
  aggressive_backoff.jitter = 0.1;

  printf ("   Aggressive Backoff Policy:\n");
  print_policy (&aggressive_backoff);
  printf ("\n   Calculated delays (with jitter, approximate):\n");

  /* Reset seed for consistent comparison */
  srand (12345);

  for (int attempt = 1; attempt <= 5; attempt++)
    {
      int delay = SocketRetry_calculate_delay (&aggressive_backoff, attempt);
      printf ("      Attempt %d: %d ms\n", attempt, delay);
    }

  printf ("\n   [OK] Example 5 completed\n");

  print_separator ();
}

/**
 * Example 6: Reusing retry context with reset
 */
static void
example_context_reuse (void)
{
  printf ("Example 6: Reusing Retry Context\n");
  printf ("=================================\n\n");

  TRY
  {
    /* Create retry context */
    printf ("1. Creating retry context...\n");
    SocketRetry_T retry = SocketRetry_new (NULL);
    printf ("   [OK] Retry context created\n\n");

    /* First operation */
    printf ("2. First operation (fails 2 times, then succeeds)...\n");
    SimulatedOp_Context ctx1 = { .attempts_before_success = 3,
                                 .current_attempt = 0,
                                 .operation_name = "First operation" };

    int result1
        = SocketRetry_execute_simple (retry, simulated_network_op, &ctx1);

    printf ("\n   Result: %s\n",
            result1 == 0 ? "[OK] Success" : "[FAIL] Failed");

    SocketRetry_Stats stats1;
    SocketRetry_get_stats (retry, &stats1);
    printf ("   Stats: %d attempts, %lld ms total time\n", stats1.attempts,
            (long long)stats1.total_time_ms);

    /* Reset for second operation */
    printf ("\n3. Resetting retry context for reuse...\n");
    SocketRetry_reset (retry);
    printf ("   [OK] Context reset\n\n");

    /* Second operation with fresh stats */
    printf ("4. Second operation (fails 1 time, then succeeds)...\n");
    SimulatedOp_Context ctx2 = { .attempts_before_success = 2,
                                 .current_attempt = 0,
                                 .operation_name = "Second operation" };

    int result2
        = SocketRetry_execute_simple (retry, simulated_network_op, &ctx2);

    printf ("\n   Result: %s\n",
            result2 == 0 ? "[OK] Success" : "[FAIL] Failed");

    SocketRetry_Stats stats2;
    SocketRetry_get_stats (retry, &stats2);
    printf ("   Stats: %d attempts, %lld ms total time\n", stats2.attempts,
            (long long)stats2.total_time_ms);

    printf ("\n5. Verifying stats are independent:\n");
    printf ("   First op:  %d attempts\n", stats1.attempts);
    printf ("   Second op: %d attempts\n", stats2.attempts);

    /* Cleanup */
    SocketRetry_free (&retry);

    printf ("\n   [OK] Example 6 completed\n");
  }
  EXCEPT (SocketRetry_Failed)
  {
    fprintf (stderr, "   [FAIL] Retry error in Example 6\n");
  }
  END_TRY;

  print_separator ();
}

/* ============================================================================
 * Main Entry Point
 * ============================================================================
 */

int
main (void)
{
  printf ("\n");
  printf ("╔════════════════════════════════════════════════════════════════"
          "════╗\n");
  printf ("║  SocketRetry API - Exponential Backoff Retry Examples            "
          " ║\n");
  printf ("╚════════════════════════════════════════════════════════════════"
          "════╝\n");
  printf ("\n");

  /* Seed random for jitter */
  srand ((unsigned int)time (NULL));

  /* Run all examples */
  example_default_policy ();
  example_custom_policy ();
  example_should_retry ();
  example_exhausted_retries ();
  example_delay_calculation ();
  example_context_reuse ();

  printf ("╔════════════════════════════════════════════════════════════════"
          "════╗\n");
  printf ("║  [OK] All examples completed successfully!                       "
          " ║\n");
  printf ("╚════════════════════════════════════════════════════════════════"
          "════╝\n");
  printf ("\n");

  return 0;
}
