/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_socketretry.c - SocketRetry Module Tests
 *
 * Part of the Socket Library Test Suite
 *
 * Tests for:
 * - Policy defaults and customization
 * - Context creation/destruction
 * - Execute with/without should_retry callback
 * - Statistics collection
 * - Reset functionality
 * - Backoff delay calculation
 * - Error handling and edge cases
 */

#include <errno.h>
#include <math.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "core/Except.h"
#include "core/SocketRetry.h"
#include "core/SocketUtil.h"
#include "test/Test.h"

/* ============================================================================
 * Test Operation Callbacks
 * ============================================================================
 */

/* Context for test operations */
typedef struct
{
  int attempts_made;
  int succeed_on_attempt;
  int error_code;
} TestOpContext;

/* Operation that always succeeds */
static int
op_always_succeed (void *ctx, int attempt)
{
  TestOpContext *tctx = (TestOpContext *)ctx;
  if (tctx)
    tctx->attempts_made = attempt;
  return 0;
}

/* Operation that always fails */
static int
op_always_fail (void *ctx, int attempt)
{
  TestOpContext *tctx = (TestOpContext *)ctx;
  if (tctx)
    {
      tctx->attempts_made = attempt;
      return tctx->error_code ? tctx->error_code : ETIMEDOUT;
    }
  return ETIMEDOUT;
}

/* Operation that succeeds on specified attempt */
static int
op_succeed_on_attempt (void *ctx, int attempt)
{
  TestOpContext *tctx = (TestOpContext *)ctx;
  tctx->attempts_made = attempt;
  if (attempt >= tctx->succeed_on_attempt)
    return 0;
  return EAGAIN;
}

/* Should retry callback that denies retries */
static int
should_retry_never (int error, int attempt, void *ctx)
{
  (void)error;
  (void)attempt;
  (void)ctx;
  return 0; /* Never retry */
}

/* Should retry callback that allows only EAGAIN */
static int
should_retry_eagain_only (int error, int attempt, void *ctx)
{
  (void)attempt;
  (void)ctx;
  return error == EAGAIN;
}

/* ============================================================================
 * Policy Defaults Tests
 * ============================================================================
 */

TEST (socketretry_policy_defaults)
{
  SocketRetry_Policy policy;
  memset (&policy, 0xFF, sizeof (policy)); /* Dirty memory */

  SocketRetry_policy_defaults (&policy);

  ASSERT_EQ (policy.max_attempts, SOCKET_RETRY_DEFAULT_MAX_ATTEMPTS);
  ASSERT_EQ (policy.initial_delay_ms, SOCKET_RETRY_DEFAULT_INITIAL_DELAY_MS);
  ASSERT_EQ (policy.max_delay_ms, SOCKET_RETRY_DEFAULT_MAX_DELAY_MS);
  ASSERT (policy.multiplier == SOCKET_RETRY_DEFAULT_MULTIPLIER);
  ASSERT (policy.jitter == SOCKET_RETRY_DEFAULT_JITTER);
}

/* ============================================================================
 * Context Creation Tests
 * ============================================================================
 */

TEST (socketretry_new_default_policy)
{
  SocketRetry_T retry = NULL;

  TRY
  {
    retry = SocketRetry_new (NULL);
    ASSERT_NOT_NULL (retry);

    /* Verify default policy is set */
    SocketRetry_Policy policy;
    SocketRetry_get_policy (retry, &policy);
    ASSERT_EQ (policy.max_attempts, SOCKET_RETRY_DEFAULT_MAX_ATTEMPTS);
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;

  ASSERT_NULL (retry);
}

TEST (socketretry_new_custom_policy)
{
  SocketRetry_T retry = NULL;
  SocketRetry_Policy custom;

  SocketRetry_policy_defaults (&custom);
  custom.max_attempts = 5;
  custom.initial_delay_ms = 50;
  custom.max_delay_ms = 1000;
  custom.multiplier = 1.5;
  custom.jitter = 0.1;

  TRY
  {
    retry = SocketRetry_new (&custom);
    ASSERT_NOT_NULL (retry);

    /* Verify custom policy is set */
    SocketRetry_Policy result;
    SocketRetry_get_policy (retry, &result);
    ASSERT_EQ (result.max_attempts, 5);
    ASSERT_EQ (result.initial_delay_ms, 50);
    ASSERT_EQ (result.max_delay_ms, 1000);
    ASSERT (result.multiplier == 1.5);
    ASSERT (result.jitter == 0.1);
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;
}

TEST (socketretry_new_invalid_policy_negative_attempts)
{
  volatile int raised = 0;
  SocketRetry_Policy bad;

  SocketRetry_policy_defaults (&bad);
  bad.max_attempts = 0; /* Invalid: must be >= 1 */

  TRY
  {
    SocketRetry_T retry = SocketRetry_new (&bad);
    (void)retry;
  }
  EXCEPT (SocketRetry_Failed)
  {
    raised = 1;
  }
  END_TRY;

  ASSERT_EQ (raised, 1);
}

TEST (socketretry_new_invalid_policy_bad_multiplier)
{
  volatile int raised = 0;
  SocketRetry_Policy bad;

  SocketRetry_policy_defaults (&bad);
  bad.multiplier = 0.5; /* Invalid: must be >= 1.0 */

  TRY
  {
    SocketRetry_T retry = SocketRetry_new (&bad);
    (void)retry;
  }
  EXCEPT (SocketRetry_Failed)
  {
    raised = 1;
  }
  END_TRY;

  ASSERT_EQ (raised, 1);
}

TEST (socketretry_new_invalid_policy_bad_jitter)
{
  volatile int raised = 0;
  SocketRetry_Policy bad;

  SocketRetry_policy_defaults (&bad);
  bad.jitter = 1.5; /* Invalid: must be 0.0 - 1.0 */

  TRY
  {
    SocketRetry_T retry = SocketRetry_new (&bad);
    (void)retry;
  }
  EXCEPT (SocketRetry_Failed)
  {
    raised = 1;
  }
  END_TRY;

  ASSERT_EQ (raised, 1);
}

TEST (socketretry_new_invalid_policy_nan_multiplier)
{
  volatile int raised = 0;
  SocketRetry_Policy bad;

  SocketRetry_policy_defaults (&bad);
  bad.multiplier = NAN; /* Invalid: NaN not allowed */

  TRY
  {
    SocketRetry_T retry = SocketRetry_new (&bad);
    (void)retry;
  }
  EXCEPT (SocketRetry_Failed)
  {
    raised = 1;
  }
  END_TRY;

  ASSERT_EQ (raised, 1);
}

TEST (socketretry_new_invalid_policy_inf_multiplier)
{
  volatile int raised = 0;
  SocketRetry_Policy bad;

  SocketRetry_policy_defaults (&bad);
  bad.multiplier = INFINITY; /* Invalid: Inf not allowed */

  TRY
  {
    SocketRetry_T retry = SocketRetry_new (&bad);
    (void)retry;
  }
  EXCEPT (SocketRetry_Failed)
  {
    raised = 1;
  }
  END_TRY;

  ASSERT_EQ (raised, 1);
}

TEST (socketretry_new_invalid_policy_nan_jitter)
{
  volatile int raised = 0;
  SocketRetry_Policy bad;

  SocketRetry_policy_defaults (&bad);
  bad.jitter = NAN; /* Invalid: NaN not allowed */

  TRY
  {
    SocketRetry_T retry = SocketRetry_new (&bad);
    (void)retry;
  }
  EXCEPT (SocketRetry_Failed)
  {
    raised = 1;
  }
  END_TRY;

  ASSERT_EQ (raised, 1);
}

TEST (socketretry_new_invalid_policy_inf_jitter)
{
  volatile int raised = 0;
  SocketRetry_Policy bad;

  SocketRetry_policy_defaults (&bad);
  bad.jitter = INFINITY; /* Invalid: Inf not allowed */

  TRY
  {
    SocketRetry_T retry = SocketRetry_new (&bad);
    (void)retry;
  }
  EXCEPT (SocketRetry_Failed)
  {
    raised = 1;
  }
  END_TRY;

  ASSERT_EQ (raised, 1);
}

TEST (socketretry_free_null_safe)
{
  SocketRetry_T retry = NULL;
  SocketRetry_free (&retry); /* Should not crash */
  SocketRetry_free (NULL);   /* Should not crash */
}

/* ============================================================================
 * Execute Tests
 * ============================================================================
 */

TEST (socketretry_execute_immediate_success)
{
  SocketRetry_T retry = NULL;
  TestOpContext ctx = { 0 };

  TRY
  {
    retry = SocketRetry_new (NULL);
    int result = SocketRetry_execute (retry, op_always_succeed, NULL, &ctx);

    ASSERT_EQ (result, 0);
    ASSERT_EQ (ctx.attempts_made, 1);

    SocketRetry_Stats stats;
    SocketRetry_get_stats (retry, &stats);
    ASSERT_EQ (stats.attempts, 1);
    ASSERT_EQ (stats.last_error, 0);
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;
}

TEST (socketretry_execute_always_fails)
{
  SocketRetry_T retry = NULL;
  SocketRetry_Policy policy;
  TestOpContext ctx = { .error_code = ECONNREFUSED };

  SocketRetry_policy_defaults (&policy);
  policy.max_attempts = 3;
  policy.initial_delay_ms = 10; /* Short delays for test */
  policy.max_delay_ms = 50;
  policy.jitter = 0.0; /* No jitter for predictable tests */

  TRY
  {
    retry = SocketRetry_new (&policy);
    int result = SocketRetry_execute (retry, op_always_fail, NULL, &ctx);

    ASSERT_EQ (result, ECONNREFUSED);
    ASSERT_EQ (ctx.attempts_made, 3);

    SocketRetry_Stats stats;
    SocketRetry_get_stats (retry, &stats);
    ASSERT_EQ (stats.attempts, 3);
    ASSERT_EQ (stats.last_error, ECONNREFUSED);
    ASSERT (stats.total_delay_ms > 0);
    ASSERT (stats.total_time_ms > 0);
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;
}

TEST (socketretry_execute_succeeds_after_retries)
{
  SocketRetry_T retry = NULL;
  SocketRetry_Policy policy;
  TestOpContext ctx = { .succeed_on_attempt = 3 };

  SocketRetry_policy_defaults (&policy);
  policy.max_attempts = 5;
  policy.initial_delay_ms = 10;
  policy.max_delay_ms = 100;
  policy.jitter = 0.0;

  TRY
  {
    retry = SocketRetry_new (&policy);
    int result = SocketRetry_execute (retry, op_succeed_on_attempt, NULL, &ctx);

    ASSERT_EQ (result, 0);
    ASSERT_EQ (ctx.attempts_made, 3);

    SocketRetry_Stats stats;
    SocketRetry_get_stats (retry, &stats);
    ASSERT_EQ (stats.attempts, 3);
    /* last_error retains the error from failed attempts before success */
    ASSERT_EQ (stats.last_error, EAGAIN);
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;
}

TEST (socketretry_execute_simple)
{
  SocketRetry_T retry = NULL;
  TestOpContext ctx = { .succeed_on_attempt = 2 };
  SocketRetry_Policy policy;

  SocketRetry_policy_defaults (&policy);
  policy.max_attempts = 5;
  policy.initial_delay_ms = 10;
  policy.jitter = 0.0;

  TRY
  {
    retry = SocketRetry_new (&policy);
    int result
        = SocketRetry_execute_simple (retry, op_succeed_on_attempt, &ctx);

    ASSERT_EQ (result, 0);
    ASSERT_EQ (ctx.attempts_made, 2);
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;
}

/* ============================================================================
 * Should Retry Callback Tests
 * ============================================================================
 */

TEST (socketretry_execute_with_should_retry_never)
{
  SocketRetry_T retry = NULL;
  SocketRetry_Policy policy;
  TestOpContext ctx = { .error_code = EAGAIN };

  SocketRetry_policy_defaults (&policy);
  policy.max_attempts = 5;
  policy.initial_delay_ms = 10;

  TRY
  {
    retry = SocketRetry_new (&policy);
    int result
        = SocketRetry_execute (retry, op_always_fail, should_retry_never, &ctx);

    ASSERT_EQ (result, EAGAIN);
    ASSERT_EQ (ctx.attempts_made, 1); /* Only one attempt, no retry */

    SocketRetry_Stats stats;
    SocketRetry_get_stats (retry, &stats);
    ASSERT_EQ (stats.attempts, 1);
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;
}

TEST (socketretry_execute_with_should_retry_selective)
{
  SocketRetry_T retry = NULL;
  SocketRetry_Policy policy;
  TestOpContext ctx = { .error_code = ECONNREFUSED }; /* Not EAGAIN */

  SocketRetry_policy_defaults (&policy);
  policy.max_attempts = 5;
  policy.initial_delay_ms = 10;

  TRY
  {
    retry = SocketRetry_new (&policy);
    int result = SocketRetry_execute (
        retry, op_always_fail, should_retry_eagain_only, &ctx);

    ASSERT_EQ (result, ECONNREFUSED);
    ASSERT_EQ (ctx.attempts_made, 1); /* Stopped after first - not EAGAIN */
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;
}

/* ============================================================================
 * Statistics Tests
 * ============================================================================
 */

TEST (socketretry_stats_initial_zero)
{
  SocketRetry_T retry = NULL;

  TRY
  {
    retry = SocketRetry_new (NULL);

    SocketRetry_Stats stats;
    SocketRetry_get_stats (retry, &stats);

    ASSERT_EQ (stats.attempts, 0);
    ASSERT_EQ (stats.last_error, 0);
    ASSERT_EQ (stats.total_delay_ms, 0);
    ASSERT_EQ (stats.total_time_ms, 0);
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;
}

TEST (socketretry_stats_after_execution)
{
  SocketRetry_T retry = NULL;
  SocketRetry_Policy policy;
  TestOpContext ctx = { .succeed_on_attempt = 3 };

  SocketRetry_policy_defaults (&policy);
  policy.max_attempts = 5;
  policy.initial_delay_ms = 20;
  policy.jitter = 0.0;

  TRY
  {
    retry = SocketRetry_new (&policy);
    int64_t start = SocketTimeout_now_ms ();
    int result = SocketRetry_execute (retry, op_succeed_on_attempt, NULL, &ctx);
    int64_t elapsed = SocketTimeout_now_ms () - start;

    ASSERT_EQ (result, 0);

    SocketRetry_Stats stats;
    SocketRetry_get_stats (retry, &stats);

    ASSERT_EQ (stats.attempts, 3);
    /* last_error retains the error from failed attempts before success */
    ASSERT_EQ (stats.last_error, EAGAIN);
    /* Should have slept twice (between attempt 1-2 and 2-3) */
    ASSERT (stats.total_delay_ms >= 20);
    ASSERT (stats.total_time_ms > 0);
    ASSERT (stats.total_time_ms <= elapsed + 50); /* Allow some margin */
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;
}

/* ============================================================================
 * Reset Tests
 * ============================================================================
 */

TEST (socketretry_reset_clears_stats)
{
  SocketRetry_T retry = NULL;
  SocketRetry_Policy policy;
  TestOpContext ctx = { .succeed_on_attempt = 2 };

  SocketRetry_policy_defaults (&policy);
  policy.max_attempts = 5;
  policy.initial_delay_ms = 10;
  policy.jitter = 0.0;

  TRY
  {
    retry = SocketRetry_new (&policy);

    /* First execution */
    SocketRetry_execute (retry, op_succeed_on_attempt, NULL, &ctx);

    SocketRetry_Stats stats1;
    SocketRetry_get_stats (retry, &stats1);
    ASSERT_EQ (stats1.attempts, 2);

    /* Reset */
    SocketRetry_reset (retry);

    /* Stats should be cleared */
    SocketRetry_Stats stats2;
    SocketRetry_get_stats (retry, &stats2);
    ASSERT_EQ (stats2.attempts, 0);
    ASSERT_EQ (stats2.last_error, 0);
    ASSERT_EQ (stats2.total_delay_ms, 0);
    ASSERT_EQ (stats2.total_time_ms, 0);

    /* Policy should be preserved */
    SocketRetry_Policy preserved;
    SocketRetry_get_policy (retry, &preserved);
    ASSERT_EQ (preserved.max_attempts, 5);
    ASSERT_EQ (preserved.initial_delay_ms, 10);
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;
}

TEST (socketretry_reset_allows_reuse)
{
  SocketRetry_T retry = NULL;
  SocketRetry_Policy policy;

  SocketRetry_policy_defaults (&policy);
  policy.max_attempts = 3;
  policy.initial_delay_ms = 10;
  policy.jitter = 0.0;

  TRY
  {
    retry = SocketRetry_new (&policy);

    /* First use */
    TestOpContext ctx1 = { .succeed_on_attempt = 2 };
    int result1
        = SocketRetry_execute (retry, op_succeed_on_attempt, NULL, &ctx1);
    ASSERT_EQ (result1, 0);

    /* Reset and reuse */
    SocketRetry_reset (retry);

    TestOpContext ctx2 = { .succeed_on_attempt = 3 };
    int result2
        = SocketRetry_execute (retry, op_succeed_on_attempt, NULL, &ctx2);
    ASSERT_EQ (result2, 0);

    SocketRetry_Stats stats;
    SocketRetry_get_stats (retry, &stats);
    ASSERT_EQ (stats.attempts, 3);
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;
}

/* ============================================================================
 * Set Policy Tests
 * ============================================================================
 */

TEST (socketretry_set_policy)
{
  SocketRetry_T retry = NULL;

  TRY
  {
    retry = SocketRetry_new (NULL);

    /* Change policy */
    SocketRetry_Policy new_policy;
    SocketRetry_policy_defaults (&new_policy);
    new_policy.max_attempts = 10;
    new_policy.initial_delay_ms = 200;

    SocketRetry_set_policy (retry, &new_policy);

    /* Verify changed */
    SocketRetry_Policy result;
    SocketRetry_get_policy (retry, &result);
    ASSERT_EQ (result.max_attempts, 10);
    ASSERT_EQ (result.initial_delay_ms, 200);
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;
}

TEST (socketretry_set_policy_invalid_raises)
{
  SocketRetry_T retry = NULL;
  volatile int raised = 0;

  TRY
  {
    retry = SocketRetry_new (NULL);

    SocketRetry_Policy bad;
    SocketRetry_policy_defaults (&bad);
    bad.max_attempts = -1; /* Invalid */

    TRY
    {
      SocketRetry_set_policy (retry, &bad);
    }
    EXCEPT (SocketRetry_Failed)
    {
      raised = 1;
    }
    END_TRY;
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;

  ASSERT_EQ (raised, 1);
}

/* ============================================================================
 * Calculate Delay Tests
 * ============================================================================
 */

TEST (socketretry_calculate_delay_basic)
{
  SocketRetry_Policy policy;
  SocketRetry_policy_defaults (&policy);
  policy.initial_delay_ms = 100;
  policy.max_delay_ms = 10000;
  policy.multiplier = 2.0;
  policy.jitter = 0.0; /* No jitter for predictable results */

  /* Attempt 1: 100 * 2^0 = 100 */
  int delay1 = SocketRetry_calculate_delay (&policy, 1);
  ASSERT_EQ (delay1, 100);

  /* Attempt 2: 100 * 2^1 = 200 */
  int delay2 = SocketRetry_calculate_delay (&policy, 2);
  ASSERT_EQ (delay2, 200);

  /* Attempt 3: 100 * 2^2 = 400 */
  int delay3 = SocketRetry_calculate_delay (&policy, 3);
  ASSERT_EQ (delay3, 400);
}

TEST (socketretry_calculate_delay_capped)
{
  SocketRetry_Policy policy;
  SocketRetry_policy_defaults (&policy);
  policy.initial_delay_ms = 100;
  policy.max_delay_ms = 500;
  policy.multiplier = 2.0;
  policy.jitter = 0.0;

  /* Attempt 4: 100 * 2^3 = 800, capped to 500 */
  int delay4 = SocketRetry_calculate_delay (&policy, 4);
  ASSERT_EQ (delay4, 500);

  /* Attempt 10: exponential would be huge, still capped to 500 */
  int delay10 = SocketRetry_calculate_delay (&policy, 10);
  ASSERT_EQ (delay10, 500);
}

TEST (socketretry_calculate_delay_with_jitter)
{
  SocketRetry_Policy policy;
  SocketRetry_policy_defaults (&policy);
  policy.initial_delay_ms = 100;
  policy.max_delay_ms = 10000;
  policy.multiplier = 2.0;
  policy.jitter = 0.25;

  /* With 25% jitter, delay should be base +/- 25% */
  int delay1 = SocketRetry_calculate_delay (&policy, 1);
  /* Base is 100, with 25% jitter: 75 to 125 */
  ASSERT (delay1 >= 75 && delay1 <= 125);

  /* Run multiple times to verify randomness (probabilistic test) */
  int last_delay = delay1;
  for (int i = 0; i < 10; i++)
    {
      int d = SocketRetry_calculate_delay (&policy, 1);
      /* Just ensure we can call it multiple times without crashing */
      ASSERT (d >= 75 && d <= 125);
      last_delay = d;
    }
  (void)last_delay;
}

TEST (socketretry_calculate_delay_invalid_params)
{
  SocketRetry_Policy policy;
  SocketRetry_policy_defaults (&policy);

  /* NULL policy returns 0 */
  int delay_null = SocketRetry_calculate_delay (NULL, 1);
  ASSERT_EQ (delay_null, 0);

  /* Attempt < 1 returns 0 */
  int delay_zero = SocketRetry_calculate_delay (&policy, 0);
  ASSERT_EQ (delay_zero, 0);

  int delay_neg = SocketRetry_calculate_delay (&policy, -1);
  ASSERT_EQ (delay_neg, 0);
}

/* ============================================================================
 * Edge Case Tests
 * ============================================================================
 */

TEST (socketretry_single_attempt)
{
  SocketRetry_T retry = NULL;
  SocketRetry_Policy policy;
  TestOpContext ctx = { .error_code = ETIMEDOUT };

  SocketRetry_policy_defaults (&policy);
  policy.max_attempts = 1; /* Only one attempt */
  policy.initial_delay_ms = 10;

  TRY
  {
    retry = SocketRetry_new (&policy);
    int result = SocketRetry_execute (retry, op_always_fail, NULL, &ctx);

    ASSERT_EQ (result, ETIMEDOUT);
    ASSERT_EQ (ctx.attempts_made, 1);

    SocketRetry_Stats stats;
    SocketRetry_get_stats (retry, &stats);
    ASSERT_EQ (stats.attempts, 1);
    /* No delay since no retry occurred */
    ASSERT_EQ (stats.total_delay_ms, 0);
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;
}

TEST (socketretry_max_attempts_boundary)
{
  SocketRetry_T retry = NULL;
  SocketRetry_Policy policy;

  SocketRetry_policy_defaults (&policy);
  policy.max_attempts = 2;
  policy.initial_delay_ms = 10;
  policy.jitter = 0.0;

  /* Operation that succeeds exactly on max_attempts */
  TestOpContext ctx = { .succeed_on_attempt = 2 };

  TRY
  {
    retry = SocketRetry_new (&policy);
    int result = SocketRetry_execute (retry, op_succeed_on_attempt, NULL, &ctx);

    ASSERT_EQ (result, 0);
    ASSERT_EQ (ctx.attempts_made, 2);
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;
}

TEST (socketretry_no_jitter)
{
  SocketRetry_Policy policy;
  SocketRetry_policy_defaults (&policy);
  policy.initial_delay_ms = 100;
  policy.max_delay_ms = 1000;
  policy.multiplier = 2.0;
  policy.jitter = 0.0; /* Zero jitter */

  /* Without jitter, delays should be deterministic */
  int delay1a = SocketRetry_calculate_delay (&policy, 1);
  int delay1b = SocketRetry_calculate_delay (&policy, 1);
  ASSERT_EQ (delay1a, delay1b);
  ASSERT_EQ (delay1a, 100);
}

/* ============================================================================
 * Boundary Validation Tests
 * ============================================================================
 */

TEST (socketretry_validate_max_delay_boundaries)
{
  SocketRetry_T retry = NULL;
  SocketRetry_Policy policy;

  /* Test upper boundary: max_delay_ms == SOCKET_RETRY_MAX_DELAY_VALUE_MS */
  SocketRetry_policy_defaults (&policy);
  policy.max_delay_ms = 3600000; /* SOCKET_RETRY_MAX_DELAY_VALUE_MS */
  policy.initial_delay_ms = 100;

  TRY
  {
    retry = SocketRetry_new (&policy);
    ASSERT_NOT_NULL (retry);
    SocketRetry_free (&retry);
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;

  /* Test lower boundary: max_delay_ms == initial_delay_ms */
  SocketRetry_policy_defaults (&policy);
  policy.initial_delay_ms = 500;
  policy.max_delay_ms = 500; /* Equal to initial_delay_ms */

  TRY
  {
    retry = SocketRetry_new (&policy);
    ASSERT_NOT_NULL (retry);
    SocketRetry_free (&retry);
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;

  /* Test invalid: max_delay_ms < initial_delay_ms */
  volatile int raised = 0;
  SocketRetry_policy_defaults (&policy);
  policy.initial_delay_ms = 500;
  policy.max_delay_ms = 400; /* Less than initial - invalid */

  TRY
  {
    retry = SocketRetry_new (&policy);
    (void)retry;
  }
  EXCEPT (SocketRetry_Failed)
  {
    raised = 1;
  }
  END_TRY;

  ASSERT_EQ (raised, 1);

  /* Test invalid: max_delay_ms > SOCKET_RETRY_MAX_DELAY_VALUE_MS */
  raised = 0;
  SocketRetry_policy_defaults (&policy);
  policy.max_delay_ms = 3600001; /* Above max allowed */
  policy.initial_delay_ms = 100;

  TRY
  {
    retry = SocketRetry_new (&policy);
    (void)retry;
  }
  EXCEPT (SocketRetry_Failed)
  {
    raised = 1;
  }
  END_TRY;

  ASSERT_EQ (raised, 1);
}

TEST (socketretry_validate_multiplier_max_boundary)
{
  SocketRetry_T retry = NULL;
  SocketRetry_Policy policy;

  /* Test max multiplier boundary: multiplier == SOCKET_RETRY_MAX_MULTIPLIER
   * (16.0) */
  SocketRetry_policy_defaults (&policy);
  policy.multiplier = 16.0; /* SOCKET_RETRY_MAX_MULTIPLIER */

  TRY
  {
    retry = SocketRetry_new (&policy);
    ASSERT_NOT_NULL (retry);
    SocketRetry_free (&retry);
  }
  FINALLY
  {
    if (retry)
      SocketRetry_free (&retry);
  }
  END_TRY;

  /* Test invalid: multiplier > SOCKET_RETRY_MAX_MULTIPLIER */
  volatile int raised = 0;
  SocketRetry_policy_defaults (&policy);
  policy.multiplier = 16.1; /* Above max allowed */

  TRY
  {
    retry = SocketRetry_new (&policy);
    (void)retry;
  }
  EXCEPT (SocketRetry_Failed)
  {
    raised = 1;
  }
  END_TRY;

  ASSERT_EQ (raised, 1);
}

/* ============================================================================
 * retry_power_double Edge Case Tests (CPU DoS & Overflow Prevention)
 * ============================================================================
 */

TEST (socketretry_power_double_cpu_dos_prevention)
{
  SocketRetry_Policy policy;
  SocketRetry_policy_defaults (&policy);
  policy.max_attempts = 2000; /* Allow large attempt numbers */
  policy.initial_delay_ms = 1;
  policy.max_delay_ms = 3600000; /* Maximum allowed: 1 hour */
  policy.multiplier = 2.0;
  policy.jitter = 0.0;

  /* Attempt 1001 should trigger RETRY_MAX_EXPONENT (1000) limit
   * With base (multiplier) 2.0 > 1.0, should return INFINITY,
   * which gets capped to max_delay_ms */
  int delay = SocketRetry_calculate_delay (&policy, 1001);
  ASSERT_EQ (delay, 3600000);
}

TEST (socketretry_power_double_base_greater_than_one_large_exp)
{
  SocketRetry_Policy policy;
  SocketRetry_policy_defaults (&policy);
  policy.max_attempts = 2000; /* Allow large attempt numbers */
  policy.initial_delay_ms = 1;
  policy.max_delay_ms = 3600000; /* Maximum allowed: 1 hour */
  policy.multiplier = 1.5; /* Base > 1.0 */
  policy.jitter = 0.0;

  /* With exponent > RETRY_MAX_EXPONENT (1000) and base > 1.0,
   * retry_power_double returns INFINITY, capped to max_delay_ms */
  int delay = SocketRetry_calculate_delay (&policy, 1001);
  ASSERT_EQ (delay, 3600000);
}

TEST (socketretry_power_double_base_less_than_one_large_exp)
{
  SocketRetry_Policy policy;
  SocketRetry_policy_defaults (&policy);
  policy.max_attempts = 2000; /* Allow large attempt numbers */
  policy.initial_delay_ms = 1000;
  policy.max_delay_ms = 10000;
  policy.multiplier = 1.0; /* Base == 1.0 exactly */
  policy.jitter = 0.0;

  /* With base == 1.0 and large exponent > RETRY_MAX_EXPONENT,
   * retry_power_double returns 1.0, so delay = initial_delay * 1.0 */
  int delay = SocketRetry_calculate_delay (&policy, 1001);
  ASSERT_EQ (delay, 1000);

  /* Note: Testing base < 1.0 would violate policy validation (multiplier >= 1.0)
   * The issue description mentions it, but policy validation prevents it */
}

TEST (socketretry_power_double_overflow_detection)
{
  SocketRetry_Policy policy;
  SocketRetry_policy_defaults (&policy);
  policy.max_attempts = 2000; /* Allow large attempt numbers */
  policy.initial_delay_ms = 1;
  policy.max_delay_ms = 3600000; /* Maximum allowed: 1 hour */
  policy.multiplier = 2.0;
  policy.jitter = 0.0;

  /* Attempt with exponent that causes overflow within loop
   * retry_power_double should detect result > DBL_MAX / base and return INFINITY */
  /* Attempt 1024: 2^1023 overflows double precision */
  int delay = SocketRetry_calculate_delay (&policy, 1024);
  ASSERT_EQ (delay, 3600000); /* INFINITY capped to max_delay_ms */
}

TEST (socketretry_power_double_large_multiplier_no_hang)
{
  SocketRetry_Policy policy;
  SocketRetry_policy_defaults (&policy);
  policy.max_attempts = 1000; /* Allow large attempt numbers */
  policy.initial_delay_ms = 1;
  policy.max_delay_ms = 3600000; /* Maximum allowed: 1 hour */
  policy.multiplier = 10.0; /* Large multiplier */
  policy.jitter = 0.0;

  /* Verify large multiplier doesn't cause infinite loop
   * Should complete quickly due to early overflow detection or exp capping */
  int64_t start = SocketTimeout_now_ms ();
  int delay = SocketRetry_calculate_delay (&policy, 500);
  int64_t elapsed = SocketTimeout_now_ms () - start;

  /* Should complete within 100ms (generous margin) */
  ASSERT (elapsed < 100);
  /* Result should be capped to max_delay_ms */
  ASSERT_EQ (delay, 3600000);
}

TEST (socketretry_power_double_exp_exactly_at_limit)
{
  SocketRetry_Policy policy;
  SocketRetry_policy_defaults (&policy);
  policy.max_attempts = 2000; /* Allow large attempt numbers */
  policy.initial_delay_ms = 1;
  policy.max_delay_ms = 3600000; /* Maximum allowed: 1 hour */
  policy.multiplier = 2.0;
  policy.jitter = 0.0;

  /* Test exponent exactly at RETRY_MAX_EXPONENT (1000)
   * Should still compute normally (only > 1000 triggers early return) */
  int delay1000 = SocketRetry_calculate_delay (&policy, 1000);
  /* 2^999 will overflow to INFINITY, capped to max_delay_ms */
  ASSERT_EQ (delay1000, 3600000);

  /* Test exponent at 1001 (just over the limit) */
  int delay1001 = SocketRetry_calculate_delay (&policy, 1001);
  ASSERT_EQ (delay1001, 3600000);
}

/* ============================================================================
 * retry_sleep_ms Tests (EINTR handling)
 * ============================================================================
 */

/* Signal handler for EINTR tests - does nothing but interrupt nanosleep */
static volatile sig_atomic_t signal_count = 0;

static void
test_signal_handler (int sig)
{
  (void)sig;
  signal_count++;
}

/* Test helper that calls retry_sleep_ms - exposed for testing */
extern void retry_sleep_ms_test (int ms);

/* Weak symbol wrapper to expose static retry_sleep_ms for testing */
__attribute__ ((weak)) void
retry_sleep_ms_test (int ms)
{
  struct timespec req;
  struct timespec rem;

  if (ms <= 0)
    return;

  req = socket_util_ms_to_timespec ((unsigned long)ms);

  while (nanosleep (&req, &rem) == -1)
    {
      if (errno != EINTR)
        break;
      req = rem;
    }
}

TEST (retry_sleep_ms_zero_duration)
{
  /* Should return immediately without calling nanosleep */
  int64_t start = SocketTimeout_now_ms ();
  retry_sleep_ms_test (0);
  int64_t elapsed = SocketTimeout_now_ms () - start;

  /* Should complete almost instantly (< 10ms) */
  ASSERT (elapsed < 10);
}

TEST (retry_sleep_ms_negative_duration)
{
  /* Should return immediately without calling nanosleep */
  int64_t start = SocketTimeout_now_ms ();
  retry_sleep_ms_test (-1);
  int64_t elapsed = SocketTimeout_now_ms () - start;

  /* Should complete almost instantly (< 10ms) */
  ASSERT (elapsed < 10);
}

TEST (retry_sleep_ms_normal_sleep)
{
  /* Normal sleep without interruption */
  int64_t start = SocketTimeout_now_ms ();
  retry_sleep_ms_test (50);
  int64_t elapsed = SocketTimeout_now_ms () - start;

  /* Should sleep approximately 50ms (allow +/- 30ms tolerance) */
  ASSERT (elapsed >= 40 && elapsed <= 100);
}

TEST (retry_sleep_ms_eintr_handling)
{
  struct sigaction sa;
  struct sigaction old_sa;
  int64_t start;
  int64_t elapsed;

  /* Set up signal handler for SIGUSR1 */
  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = test_signal_handler;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0; /* No SA_RESTART - allow EINTR */

  signal_count = 0;

  if (sigaction (SIGUSR1, &sa, &old_sa) == -1)
    {
      /* Skip test if signal setup fails */
      return;
    }

  /* Fork a child process to send signals during sleep */
  pid_t child = fork ();
  if (child == -1)
    {
      /* Restore old handler and skip test */
      sigaction (SIGUSR1, &old_sa, NULL);
      return;
    }

  if (child == 0)
    {
      /* Child process: send SIGUSR1 signals to parent */
      pid_t parent = getppid ();
      usleep (10000);  /* 10ms delay */
      kill (parent, SIGUSR1);
      usleep (10000);  /* 10ms delay */
      kill (parent, SIGUSR1);
      usleep (10000);  /* 10ms delay */
      kill (parent, SIGUSR1);
      _exit (0);
    }

  /* Parent process: sleep with EINTR interruptions */
  start = SocketTimeout_now_ms ();
  retry_sleep_ms_test (100); /* Try to sleep 100ms */
  elapsed = SocketTimeout_now_ms () - start;

  /* Wait for child to complete */
  int status;
  waitpid (child, &status, 0);

  /* Restore old signal handler */
  sigaction (SIGUSR1, &old_sa, NULL);

  /* Verify we received signals */
  ASSERT (signal_count > 0);

  /* Despite interruptions, total sleep should still be ~100ms */
  /* Allow wider tolerance due to signal handling overhead */
  ASSERT (elapsed >= 80 && elapsed <= 200);
}

TEST (retry_sleep_ms_eintr_with_alarm)
{
  struct sigaction sa;
  struct sigaction old_sa;
  int64_t start;
  int64_t elapsed;

  /* Alternative EINTR test using alarm() */
  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = test_signal_handler;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;

  signal_count = 0;

  if (sigaction (SIGALRM, &sa, &old_sa) == -1)
    {
      return; /* Skip if setup fails */
    }

  /* Schedule alarm to interrupt sleep */
  alarm (0); /* Clear any existing alarm */
  start = SocketTimeout_now_ms ();

  /* Set alarm for 50ms in future (can't be sub-second, so use 1 sec) */
  /* For this test, we'll just verify behavior with one interruption */
  pid_t child = fork ();
  if (child == -1)
    {
      sigaction (SIGALRM, &old_sa, NULL);
      return;
    }

  if (child == 0)
    {
      /* Child: send SIGALRM after 50ms */
      usleep (50000);
      kill (getppid (), SIGALRM);
      _exit (0);
    }

  /* Parent: sleep 200ms, should be interrupted at ~50ms but resume */
  retry_sleep_ms_test (200);
  elapsed = SocketTimeout_now_ms () - start;

  /* Wait for child */
  int status;
  waitpid (child, &status, 0);

  /* Restore signal handler */
  sigaction (SIGALRM, &old_sa, NULL);
  alarm (0); /* Clear alarm */

  /* Should have been interrupted but completed full sleep */
  ASSERT (signal_count > 0);
  ASSERT (elapsed >= 180 && elapsed <= 300);
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  signal (SIGPIPE, SIG_IGN);
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
