/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_simple_ratelimit.c - Rate limiter unit tests
 * Tests for the Simple API rate limiter module.
 */

#include <unistd.h>

#include "simple/SocketSimple-ratelimit.h"
#include "simple/SocketSimple.h"
#include "test/Test.h"

/* Test basic rate limiter creation */
TEST (ratelimit_new_creates_limiter)
{
  SocketSimple_RateLimit_T limiter
      = Socket_simple_ratelimit_new (100, 10);
  ASSERT_NOT_NULL (limiter);
  Socket_simple_ratelimit_free (&limiter);
  ASSERT_NULL (limiter);
}

/* Test try_acquire basic operation */
TEST (ratelimit_try_acquire_basic)
{
  SocketSimple_RateLimit_T limiter
      = Socket_simple_ratelimit_new (100, 10);
  ASSERT_NOT_NULL (limiter);

  /* Should succeed - bucket starts full */
  int result = Socket_simple_ratelimit_try_acquire (limiter, 5);
  ASSERT_EQ (1, result);

  /* Check available tokens decreased */
  int available = Socket_simple_ratelimit_available (limiter);
  ASSERT_EQ (5, available);

  Socket_simple_ratelimit_free (&limiter);
}

/* Test acquire blocks when tokens unavailable */
TEST (ratelimit_acquire_blocks_and_succeeds)
{
  SocketSimple_RateLimit_T limiter
      = Socket_simple_ratelimit_new (10, 5); /* 10 tokens/sec, burst of 5 */
  ASSERT_NOT_NULL (limiter);

  /* Drain the bucket */
  int result = Socket_simple_ratelimit_try_acquire (limiter, 5);
  ASSERT_EQ (1, result);

  /* Now acquire 3 tokens - should block briefly and succeed */
  result = Socket_simple_ratelimit_acquire (limiter, 3);
  ASSERT_EQ (0, result); /* Success */

  Socket_simple_ratelimit_free (&limiter);
}

/* Test Issue #1985: acquire should reject tokens > bucket_size */
TEST (ratelimit_acquire_rejects_excessive_tokens)
{
  SocketSimple_RateLimit_T limiter
      = Socket_simple_ratelimit_new (100, 10); /* Bucket size = 10 */
  ASSERT_NOT_NULL (limiter);

  /* Try to acquire more tokens than bucket can ever hold */
  int result = Socket_simple_ratelimit_acquire (limiter, 20);

  /* Should fail with -1, not hang */
  ASSERT_EQ (-1, result);

  /* Error should be set */
  const char *error = Socket_simple_error ();
  ASSERT_NOT_NULL (error);

  Socket_simple_ratelimit_free (&limiter);
}

/* Test Issue #1985: acquire_timeout should reject excessive tokens */
TEST (ratelimit_acquire_timeout_rejects_excessive_tokens)
{
  SocketSimple_RateLimit_T limiter
      = Socket_simple_ratelimit_new (100, 10); /* Bucket size = 10 */
  ASSERT_NOT_NULL (limiter);

  /* Try to acquire more tokens than bucket can ever hold, with timeout */
  int result = Socket_simple_ratelimit_acquire_timeout (limiter, 20, 1000);

  /* Should fail with -1, not timeout */
  ASSERT_EQ (-1, result);

  /* Error should be set */
  const char *error = Socket_simple_error ();
  ASSERT_NOT_NULL (error);

  Socket_simple_ratelimit_free (&limiter);
}

/* Test acquire_timeout with valid tokens that requires waiting */
TEST (ratelimit_acquire_timeout_succeeds_with_wait)
{
  SocketSimple_RateLimit_T limiter
      = Socket_simple_ratelimit_new (10, 5); /* 10 tokens/sec, burst of 5 */
  ASSERT_NOT_NULL (limiter);

  /* Drain the bucket */
  int result = Socket_simple_ratelimit_try_acquire (limiter, 5);
  ASSERT_EQ (1, result);

  /* Acquire 3 tokens with 1 second timeout - should succeed */
  result = Socket_simple_ratelimit_acquire_timeout (limiter, 3, 1000);
  ASSERT_EQ (1, result); /* Success (acquired) */

  Socket_simple_ratelimit_free (&limiter);
}

/* Test acquire_timeout actually times out */
TEST (ratelimit_acquire_timeout_times_out)
{
  SocketSimple_RateLimit_T limiter
      = Socket_simple_ratelimit_new (1, 5); /* Very slow refill: 1 token/sec */
  ASSERT_NOT_NULL (limiter);

  /* Drain the bucket */
  int result = Socket_simple_ratelimit_try_acquire (limiter, 5);
  ASSERT_EQ (1, result);

  /* Try to acquire 5 tokens with only 100ms timeout - should timeout */
  result = Socket_simple_ratelimit_acquire_timeout (limiter, 5, 100);
  ASSERT_EQ (0, result); /* Timeout (not acquired) */

  Socket_simple_ratelimit_free (&limiter);
}

/* Test reset functionality */
TEST (ratelimit_reset_refills_bucket)
{
  SocketSimple_RateLimit_T limiter
      = Socket_simple_ratelimit_new (100, 10);
  ASSERT_NOT_NULL (limiter);

  /* Drain the bucket */
  int result = Socket_simple_ratelimit_try_acquire (limiter, 10);
  ASSERT_EQ (1, result);
  ASSERT_EQ (0, Socket_simple_ratelimit_available (limiter));

  /* Reset */
  result = Socket_simple_ratelimit_reset (limiter);
  ASSERT_EQ (0, result);

  /* Should be full again */
  ASSERT_EQ (10, Socket_simple_ratelimit_available (limiter));

  Socket_simple_ratelimit_free (&limiter);
}

/* Test statistics tracking */
TEST (ratelimit_statistics_tracking)
{
  SocketSimple_RateLimit_T limiter
      = Socket_simple_ratelimit_new (100, 10);
  ASSERT_NOT_NULL (limiter);

  /* Acquire some tokens */
  Socket_simple_ratelimit_try_acquire (limiter, 5);
  Socket_simple_ratelimit_try_acquire (limiter, 3);

  /* Try to acquire when not enough available */
  Socket_simple_ratelimit_try_acquire (limiter, 10);

  /* Get stats */
  SocketSimple_RateLimitStats stats;
  int result = Socket_simple_ratelimit_get_stats (limiter, &stats);
  ASSERT_EQ (0, result);

  /* Check acquired count */
  ASSERT_EQ (8, stats.total_acquired); /* 5 + 3 */

  /* Check rejected count */
  ASSERT_EQ (10, stats.total_rejected); /* Last failed attempt */

  Socket_simple_ratelimit_free (&limiter);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
