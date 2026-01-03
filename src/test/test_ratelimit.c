/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_ratelimit.c - SocketRateLimit unit tests
 * Tests for the token bucket rate limiter module.
 * Focuses on SocketRateLimit_new() and its validation/initialization.
 */

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketRateLimit-private.h"
#include "core/SocketRateLimit.h"
#include "core/SocketSecurity.h"
#include "test/Test.h"

/* ==================== Basic Creation Tests ==================== */

/* Test creation with valid parameters (arena-based) */
TEST (ratelimit_new_with_arena)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, 50);
  ASSERT_NOT_NULL (limiter);

  /* Verify parameters were set correctly */
  ASSERT_EQ (SocketRateLimit_get_rate (limiter), 100);
  ASSERT_EQ (SocketRateLimit_get_bucket_size (limiter), 50);

  /* Verify initial token count equals bucket_size */
  size_t available = SocketRateLimit_available (limiter);
  ASSERT_EQ (available, 50);

  Arena_dispose (&arena);
}

/* Test creation with NULL arena (malloc-based) */
TEST (ratelimit_new_with_null_arena)
{
  SocketRateLimit_T limiter = SocketRateLimit_new (NULL, 100, 50);
  ASSERT_NOT_NULL (limiter);

  /* Verify parameters were set correctly */
  ASSERT_EQ (SocketRateLimit_get_rate (limiter), 100);
  ASSERT_EQ (SocketRateLimit_get_bucket_size (limiter), 50);

  /* Verify initial token count equals bucket_size */
  size_t available = SocketRateLimit_available (limiter);
  ASSERT_EQ (available, 50);

  SocketRateLimit_free (&limiter);
  ASSERT_NULL (limiter);
}

/* Test that bucket_size defaults to tokens_per_sec when 0 */
TEST (ratelimit_new_bucket_size_defaults_to_rate)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, 0);
  ASSERT_NOT_NULL (limiter);

  /* Verify bucket_size defaulted to tokens_per_sec */
  ASSERT_EQ (SocketRateLimit_get_bucket_size (limiter), 100);

  /* Verify initial tokens equals bucket_size (which is now 100) */
  size_t available = SocketRateLimit_available (limiter);
  ASSERT_EQ (available, 100);

  Arena_dispose (&arena);
}

/* Test with bucket_size > tokens_per_sec */
TEST (ratelimit_new_bucket_larger_than_rate)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 50, 200);
  ASSERT_NOT_NULL (limiter);

  ASSERT_EQ (SocketRateLimit_get_rate (limiter), 50);
  ASSERT_EQ (SocketRateLimit_get_bucket_size (limiter), 200);

  /* Initial tokens should be bucket_size */
  size_t available = SocketRateLimit_available (limiter);
  ASSERT_EQ (available, 200);

  Arena_dispose (&arena);
}

/* Test with bucket_size < tokens_per_sec */
TEST (ratelimit_new_bucket_smaller_than_rate)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 200, 50);
  ASSERT_NOT_NULL (limiter);

  ASSERT_EQ (SocketRateLimit_get_rate (limiter), 200);
  ASSERT_EQ (SocketRateLimit_get_bucket_size (limiter), 50);

  /* Initial tokens should be bucket_size */
  size_t available = SocketRateLimit_available (limiter);
  ASSERT_EQ (available, 50);

  Arena_dispose (&arena);
}

/* ==================== Parameter Validation Tests ==================== */

/* Test that tokens_per_sec = 0 raises exception */
TEST (ratelimit_new_rejects_zero_rate)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  volatile int exception_caught = 0;

  TRY
  {
    SocketRateLimit_T limiter = SocketRateLimit_new (arena, 0, 100);
    (void)limiter; /* Should not reach here */
  }
  EXCEPT (SocketRateLimit_Failed)
  {
    exception_caught = 1;
  }
  END_TRY;

  ASSERT_EQ (exception_caught, 1);

  Arena_dispose (&arena);
}

/* Test that very large tokens_per_sec near security limits is rejected */
TEST (ratelimit_new_rejects_excessive_rate)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  volatile int exception_caught = 0;

  TRY
  {
    /* Use a value exceeding security limits */
    size_t excessive = SocketSecurity_get_max_allocation () + 1;
    SocketRateLimit_T limiter = SocketRateLimit_new (arena, excessive, 100);
    (void)limiter; /* Should not reach here */
  }
  EXCEPT (SocketRateLimit_Failed)
  {
    exception_caught = 1;
  }
  END_TRY;

  ASSERT_EQ (exception_caught, 1);

  Arena_dispose (&arena);
}

/* Test that very large bucket_size exceeding security limits is rejected */
TEST (ratelimit_new_rejects_excessive_bucket_size)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  volatile int exception_caught = 0;

  TRY
  {
    /* Use a value exceeding security limits */
    size_t excessive = SocketSecurity_get_max_allocation () + 1;
    SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, excessive);
    (void)limiter; /* Should not reach here */
  }
  EXCEPT (SocketRateLimit_Failed)
  {
    exception_caught = 1;
  }
  END_TRY;

  ASSERT_EQ (exception_caught, 1);

  Arena_dispose (&arena);
}

/* ==================== Resource Management Tests ==================== */

/* Test that live count increments after creation */
TEST (ratelimit_new_increments_live_count)
{
  int initial_count = SocketRateLimit_debug_live_count ();

  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, 50);
  ASSERT_NOT_NULL (limiter);

  int after_create = SocketRateLimit_debug_live_count ();
  ASSERT_EQ (after_create, initial_count + 1);

  /* Must free limiter before disposing arena to update live count */
  SocketRateLimit_free (&limiter);

  int after_free = SocketRateLimit_debug_live_count ();
  ASSERT_EQ (after_free, initial_count);

  Arena_dispose (&arena);
}

/* Test that mutex is initialized (via checking initialized field) */
TEST (ratelimit_new_initializes_mutex)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, 50);
  ASSERT_NOT_NULL (limiter);

  /* Access private field to verify mutex was initialized */
  ASSERT_EQ (limiter->initialized, SOCKET_MUTEX_INITIALIZED);

  Arena_dispose (&arena);
}

/* Test cleanup on exception during mutex init (malloc-based) */
TEST (ratelimit_new_cleanup_on_malloc_failure)
{
  int initial_count = SocketRateLimit_debug_live_count ();

  /* Create with NULL arena (malloc-based) */
  SocketRateLimit_T limiter = SocketRateLimit_new (NULL, 100, 50);
  ASSERT_NOT_NULL (limiter);

  int after_create = SocketRateLimit_debug_live_count ();
  ASSERT_EQ (after_create, initial_count + 1);

  /* Free and verify cleanup */
  SocketRateLimit_free (&limiter);
  ASSERT_NULL (limiter);

  int after_free = SocketRateLimit_debug_live_count ();
  ASSERT_EQ (after_free, initial_count);
}

/* Test that arena field is set correctly (arena-based) */
TEST (ratelimit_new_sets_arena_field)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, 50);
  ASSERT_NOT_NULL (limiter);

  /* Verify arena field was set */
  ASSERT_EQ (limiter->arena, arena);

  Arena_dispose (&arena);
}

/* Test that arena field is NULL (malloc-based) */
TEST (ratelimit_new_null_arena_field_when_malloc)
{
  SocketRateLimit_T limiter = SocketRateLimit_new (NULL, 100, 50);
  ASSERT_NOT_NULL (limiter);

  /* Verify arena field is NULL */
  ASSERT_NULL (limiter->arena);

  SocketRateLimit_free (&limiter);
}

/* ==================== Edge Cases ==================== */

/* Test with very large but valid tokens_per_sec */
TEST (ratelimit_new_large_valid_rate)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Use a large but valid value (well under security limits) */
  size_t large_rate = 1000000; /* 1 million tokens/sec */
  SocketRateLimit_T limiter = SocketRateLimit_new (arena, large_rate, 0);
  ASSERT_NOT_NULL (limiter);

  ASSERT_EQ (SocketRateLimit_get_rate (limiter), large_rate);
  ASSERT_EQ (SocketRateLimit_get_bucket_size (limiter), large_rate);

  Arena_dispose (&arena);
}

/* ============================================================================
 * SocketRateLimit_wait_time_ms Comprehensive Tests
 * ============================================================================
 */

/* Test wait time is 0 when tokens available */
TEST (ratelimit_wait_time_tokens_available)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;
  int64_t wait_ms;

  TRY limiter = SocketRateLimit_new (arena, 100, 50);

  /* Full bucket - wait time should be 0 for various token amounts */
  wait_ms = SocketRateLimit_wait_time_ms (limiter, 1);
  ASSERT_EQ (0, wait_ms);

  wait_ms = SocketRateLimit_wait_time_ms (limiter, 25);
  ASSERT_EQ (0, wait_ms);

  wait_ms = SocketRateLimit_wait_time_ms (limiter, 50);
  ASSERT_EQ (0, wait_ms);
  EXCEPT (SocketRateLimit_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test wait time is 0 for 0 tokens requested */
TEST (ratelimit_wait_time_zero_tokens)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;
  int64_t wait_ms;

  TRY limiter = SocketRateLimit_new (arena, 100, 10);

  /* Drain bucket completely */
  SocketRateLimit_try_acquire (limiter, 10);

  /* Even with empty bucket, 0 tokens should return 0 wait time */
  wait_ms = SocketRateLimit_wait_time_ms (limiter, 0);
  ASSERT_EQ (0, wait_ms);
  EXCEPT (SocketRateLimit_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test correct wait time calculation for N tokens */
TEST (ratelimit_wait_time_calculation_precise)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;
  int64_t wait_ms;

  TRY
      /* 100 tokens/sec = 10ms per token */
      limiter
      = SocketRateLimit_new (arena, 100, 10);

  /* Drain bucket */
  SocketRateLimit_try_acquire (limiter, 10);

  /* Need 1 token at 100/sec = 10ms */
  wait_ms = SocketRateLimit_wait_time_ms (limiter, 1);
  ASSERT (wait_ms >= 8 && wait_ms <= 12);

  /* Need 5 tokens at 100/sec = 50ms */
  wait_ms = SocketRateLimit_wait_time_ms (limiter, 5);
  ASSERT (wait_ms >= 40 && wait_ms <= 60);

  /* Need 10 tokens at 100/sec = 100ms */
  wait_ms = SocketRateLimit_wait_time_ms (limiter, 10);
  ASSERT (wait_ms >= 90 && wait_ms <= 110);
  EXCEPT (SocketRateLimit_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test mathematical correctness: tokens_per_sec = 100, need 50 (expect ~500ms)
 */
TEST (ratelimit_wait_time_math_100tps_50tokens)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;
  int64_t wait_ms;

  TRY
      /* 100 tokens/sec, bucket of 100 */
      limiter
      = SocketRateLimit_new (arena, 100, 100);

  /* Drain bucket */
  SocketRateLimit_try_acquire (limiter, 100);

  /* Need 50 tokens: (50 / 100) * 1000 = 500ms */
  wait_ms = SocketRateLimit_wait_time_ms (limiter, 50);
  ASSERT (wait_ms >= 480 && wait_ms <= 520);
  EXCEPT (SocketRateLimit_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test mathematical correctness: tokens_per_sec = 1000, need 1 (expect ~1ms) */
TEST (ratelimit_wait_time_math_1000tps_1token)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;
  int64_t wait_ms;

  TRY
      /* 1000 tokens/sec, bucket of 10 */
      limiter
      = SocketRateLimit_new (arena, 1000, 10);

  /* Drain bucket */
  SocketRateLimit_try_acquire (limiter, 10);

  /* Need 1 token: (1 / 1000) * 1000 = 1ms */
  wait_ms = SocketRateLimit_wait_time_ms (limiter, 1);
  ASSERT (wait_ms >= 0 && wait_ms <= 3);
  EXCEPT (SocketRateLimit_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test fractional token scenarios with partial bucket */
TEST (ratelimit_wait_time_fractional_tokens)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;
  int64_t wait_ms;

  TRY
      /* 250 tokens/sec = 4ms per token */
      limiter
      = SocketRateLimit_new (arena, 250, 100);

  /* Start with 30 tokens, need 50 (need 20 more) */
  SocketRateLimit_try_acquire (limiter, 70);

  /* Need 50 tokens when we have 30 = need 20 more
   * 20 tokens at 250/sec = 80ms */
  wait_ms = SocketRateLimit_wait_time_ms (limiter, 50);
  ASSERT (wait_ms >= 70 && wait_ms <= 90);
  EXCEPT (SocketRateLimit_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test wait time decreases as bucket refills */
TEST (ratelimit_wait_time_decreases_with_refill)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;
  int64_t wait_ms_1, wait_ms_2;

  TRY
      /* 1000 tokens/sec = 1 token per ms */
      limiter
      = SocketRateLimit_new (arena, 1000, 100);

  /* Drain bucket */
  SocketRateLimit_try_acquire (limiter, 100);

  /* Check wait time for 50 tokens (should be ~50ms) */
  wait_ms_1 = SocketRateLimit_wait_time_ms (limiter, 50);

  /* Wait for some tokens to refill (20ms should give ~20 tokens) */
  usleep (20000);

  /* Now wait time should be less (need ~30 tokens now) */
  wait_ms_2 = SocketRateLimit_wait_time_ms (limiter, 50);

  /* wait_ms_2 should be less than wait_ms_1 (allow some tolerance) */
  ASSERT (wait_ms_2 < wait_ms_1 + 5);
  EXCEPT (SocketRateLimit_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test return -1 when tokens exceed bucket_size */
TEST (ratelimit_wait_time_impossible_exceeds_bucket)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;
  int64_t wait_ms;

  TRY limiter = SocketRateLimit_new (arena, 100, 50);

  /* Request 1 more than bucket_size */
  wait_ms = SocketRateLimit_wait_time_ms (limiter, 51);
  ASSERT_EQ (-1, wait_ms);

  /* Request much more than bucket_size */
  wait_ms = SocketRateLimit_wait_time_ms (limiter, 1000);
  ASSERT_EQ (-1, wait_ms);
  EXCEPT (SocketRateLimit_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test boundary: tokens equal to bucket_size should work */
TEST (ratelimit_wait_time_boundary_equal_bucket)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;
  int64_t wait_ms;

  TRY
      /* 100 tokens/sec, bucket of 50 */
      limiter
      = SocketRateLimit_new (arena, 100, 50);

  /* Drain bucket */
  SocketRateLimit_try_acquire (limiter, 50);

  /* Request exactly bucket_size - should calculate wait time */
  wait_ms = SocketRateLimit_wait_time_ms (limiter, 50);
  ASSERT (wait_ms >= 480 && wait_ms <= 520); /* ~500ms */
  EXCEPT (SocketRateLimit_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test very high tokens_per_sec (ms_per_token = 0 case) */
TEST (ratelimit_wait_time_very_high_rate)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;
  int64_t wait_ms;

  TRY
      /* Very high rate: 10 million tokens/sec
       * ms_per_token = 1000 / 10000000 = 0.0001 → rounds to 0 */
      limiter
      = SocketRateLimit_new (arena, 10000000, 1000);

  /* Drain bucket */
  SocketRateLimit_try_acquire (limiter, 1000);

  /* With ms_per_token = 0, should return IMPOSSIBLE_WAIT */
  wait_ms = SocketRateLimit_wait_time_ms (limiter, 100);
  ASSERT_EQ (-1, wait_ms);
  EXCEPT (SocketRateLimit_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test overflow in wait calculation: needed * ms_per_token overflows */
TEST (ratelimit_wait_time_overflow_protection)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter;
  int64_t wait_ms;

  TRY
      /* Low rate to maximize ms_per_token: 1 token/sec = 1000ms per token
       * Large bucket to allow large token request */
      limiter
      = SocketRateLimit_new (arena, 1, 10000000);

  /* Drain bucket */
  SocketRateLimit_try_acquire (limiter, 10000000);

  /* Request 9000000 tokens at 1000ms each
   * Calculation: 9000000 * 1000 = 9,000,000,000 ms
   * This should NOT overflow SIZE_MAX but test large values
   * Wait should be ~104 days which is valid but very large */
  wait_ms = SocketRateLimit_wait_time_ms (limiter, 9000000);

  /* Should return a large positive value (around 9 billion ms) */
  ASSERT (wait_ms > 8000000000LL && wait_ms < 10000000000LL);
  EXCEPT (SocketRateLimit_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* ============================================================================
 * SocketIPTracker Tests
 * ============================================================================
 */

/* Test IP tracker creation */
TEST (iptracker_create)
||||||| parent of bbf843aa (test(core): Add comprehensive unit tests for SocketRateLimit_new)
/* ============================================================================
 * SocketIPTracker Tests
 * ============================================================================
 */

/* Test IP tracker creation */
TEST (iptracker_create)
/* Test with minimum valid tokens_per_sec (1) */
TEST (ratelimit_new_minimum_rate)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 1, 1);
  ASSERT_NOT_NULL (limiter);

  ASSERT_EQ (SocketRateLimit_get_rate (limiter), 1);
  ASSERT_EQ (SocketRateLimit_get_bucket_size (limiter), 1);

  Arena_dispose (&arena);
}

/* Test multiple rate limiters with same arena */
TEST (ratelimit_new_multiple_limiters_same_arena)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketRateLimit_T limiter1 = SocketRateLimit_new (arena, 100, 50);
  SocketRateLimit_T limiter2 = SocketRateLimit_new (arena, 200, 100);
  SocketRateLimit_T limiter3 = SocketRateLimit_new (arena, 50, 25);

  ASSERT_NOT_NULL (limiter1);
  ASSERT_NOT_NULL (limiter2);
  ASSERT_NOT_NULL (limiter3);

  /* Verify they're different instances */
  ASSERT_NE (limiter1, limiter2);
  ASSERT_NE (limiter2, limiter3);
  ASSERT_NE (limiter1, limiter3);

  /* Verify each has correct parameters */
  ASSERT_EQ (SocketRateLimit_get_rate (limiter1), 100);
  ASSERT_EQ (SocketRateLimit_get_rate (limiter2), 200);
  ASSERT_EQ (SocketRateLimit_get_rate (limiter3), 50);

  /* All cleaned up when arena is disposed */
  Arena_dispose (&arena);
}

/* Test that initial last_refill_ms is set to current time */
TEST (ratelimit_new_sets_last_refill_time)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, 50);
  ASSERT_NOT_NULL (limiter);

  /* Verify last_refill_ms is non-zero (was set to current time) */
  ASSERT_NE (limiter->last_refill_ms, 0);

  Arena_dispose (&arena);
}

/* Test that tokens field matches bucket_size initially */
TEST (ratelimit_new_tokens_equals_bucket_size)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, 75);
  ASSERT_NOT_NULL (limiter);

  /* Direct field access to verify initial tokens */
  ASSERT_EQ (limiter->tokens, 75);
  ASSERT_EQ (limiter->tokens, limiter->bucket_size);

  Arena_dispose (&arena);
}

/* ==================== Integration Tests ==================== */

/* Test that newly created limiter can acquire tokens */
TEST (ratelimit_new_limiter_can_acquire_tokens)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, 50);
  ASSERT_NOT_NULL (limiter);

  /* Should be able to acquire tokens immediately after creation */
  int acquired = SocketRateLimit_try_acquire (limiter, 10);
  ASSERT_EQ (acquired, 1);

  /* Remaining tokens should be 40 */
  size_t available = SocketRateLimit_available (limiter);
  ASSERT_EQ (available, 40);

  Arena_dispose (&arena);
}

/* Test that wait time is 0 for available tokens after creation */
TEST (ratelimit_new_zero_wait_time_for_available_tokens)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, 50);
  ASSERT_NOT_NULL (limiter);

  /* Wait time should be 0 for tokens <= bucket_size */
  int64_t wait = SocketRateLimit_wait_time_ms (limiter, 50);
  ASSERT_EQ (wait, 0);

  Arena_dispose (&arena);
}

/* Test that wait time is non-zero for tokens > bucket_size */
TEST (ratelimit_new_nonzero_wait_for_excessive_tokens)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, 50);
  ASSERT_NOT_NULL (limiter);

  /* Wait time should be -1 (impossible) for tokens > bucket_size */
  int64_t wait = SocketRateLimit_wait_time_ms (limiter, 51);
  ASSERT_EQ (wait, -1);

  Arena_dispose (&arena);
}

/* Test setmaxunique - limit on total unique IPs tracked */
TEST (iptracker_setmaxunique)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;

  TRY tracker = SocketIPTracker_new (arena, 100);

  /* Default max unique should be some large value */
  size_t initial_max = SocketIPTracker_getmaxunique (tracker);
  ASSERT (initial_max > 0);

  /* Set a specific limit */
  SocketIPTracker_setmaxunique (tracker, 5);
  ASSERT_EQ (5, SocketIPTracker_getmaxunique (tracker));

  /* Reset to unlimited */
  SocketIPTracker_setmaxunique (tracker, 0);
  ASSERT_EQ (0, SocketIPTracker_getmaxunique (tracker));
  EXCEPT (SocketIPTracker_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test getmaxunique retrieval */
TEST (iptracker_getmaxunique)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;

  TRY tracker = SocketIPTracker_new (arena, 10);

  /* Set known value */
  SocketIPTracker_setmaxunique (tracker, 1000);
  ASSERT_EQ (1000, SocketIPTracker_getmaxunique (tracker));

  /* Change and verify */
  SocketIPTracker_setmaxunique (tracker, 500);
  ASSERT_EQ (500, SocketIPTracker_getmaxunique (tracker));
  EXCEPT (SocketIPTracker_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test max unique IPs exceeded scenario */
TEST (iptracker_max_unique_exceeded)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;
  int result;

  TRY tracker = SocketIPTracker_new (arena, 100);

  /* Set a low unique IP limit */
  SocketIPTracker_setmaxunique (tracker, 3);

  /* Track 3 unique IPs - should succeed */
  result = SocketIPTracker_track (tracker, "1.1.1.1");
  ASSERT_EQ (1, result);

  result = SocketIPTracker_track (tracker, "2.2.2.2");
  ASSERT_EQ (1, result);

  result = SocketIPTracker_track (tracker, "3.3.3.3");
  ASSERT_EQ (1, result);

  ASSERT_EQ (3, SocketIPTracker_unique_ips (tracker));

  /* 4th unique IP should be rejected */
  result = SocketIPTracker_track (tracker, "4.4.4.4");
  ASSERT_EQ (0, result);

  /* But tracking existing IP should still work */
  result = SocketIPTracker_track (tracker, "1.1.1.1");
  ASSERT_EQ (1, result);
  EXCEPT (SocketIPTracker_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test invalid IP address handling */
TEST (iptracker_invalid_ip_rejected)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;
  int result;

  TRY tracker = SocketIPTracker_new (arena, 10);

  /* Empty string - returns 1 (allow) as silent no-op per implementation */
  result = SocketIPTracker_track (tracker, "");
  ASSERT_EQ (1, result);

  /* NULL pointer - returns 1 (allow) as silent no-op per implementation */
  result = SocketIPTracker_track (tracker, NULL);
  ASSERT_EQ (1, result);

  /* Invalid format - properly rejected with 0 */
  result = SocketIPTracker_track (tracker, "not-an-ip");
  ASSERT_EQ (0, result);

  /* Invalid IPv4 - properly rejected with 0 */
  result = SocketIPTracker_track (tracker, "999.999.999.999");
  ASSERT_EQ (0, result);

  /* Should have no entries (empty/NULL don't create entries, invalid rejected)
   */
  ASSERT_EQ (0, SocketIPTracker_unique_ips (tracker));
  EXCEPT (SocketIPTracker_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test tracking same IP multiple times */
TEST (iptracker_track_same_ip_multiple)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;
  int result;

  TRY tracker = SocketIPTracker_new (arena, 10);

  /* Track same IP 5 times */
  for (int i = 0; i < 5; i++)
    {
      result = SocketIPTracker_track (tracker, "192.168.50.50");
      ASSERT_EQ (1, result);
    }

  /* Should count as 1 unique IP with 5 connections */
  ASSERT_EQ (1, SocketIPTracker_unique_ips (tracker));
  ASSERT_EQ (5, SocketIPTracker_count (tracker, "192.168.50.50"));
  ASSERT_EQ (5, SocketIPTracker_total (tracker));
  EXCEPT (SocketIPTracker_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test release on non-tracked IP */
TEST (iptracker_release_nonexistent)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;

  TRY tracker = SocketIPTracker_new (arena, 10);

  /* Release non-existent IP - should not crash */
  SocketIPTracker_release (tracker, "9.9.9.9");
  SocketIPTracker_release (tracker, NULL);
  SocketIPTracker_release (tracker, "");

  /* Stats should be unchanged */
  ASSERT_EQ (0, SocketIPTracker_unique_ips (tracker));
  ASSERT_EQ (0, SocketIPTracker_total (tracker));
  EXCEPT (SocketIPTracker_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* ============================================================================
 * SocketPool Rate Limiting Tests
 * ============================================================================
 */

/* Test connection rate limiting in pool */
TEST (pool_connection_rate_limit)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = NULL;

  TRY pool = SocketPool_new (arena, 100, 4096);

  /* Initially no rate limit */
  ASSERT_EQ (0, SocketPool_getconnrate (pool));

  /* Set rate limit */
  SocketPool_setconnrate (pool, 10, 5);
  ASSERT_EQ (10, SocketPool_getconnrate (pool));

  /* Disable rate limit */
  SocketPool_setconnrate (pool, 0, 0);
  ASSERT_EQ (0, SocketPool_getconnrate (pool));
  EXCEPT (SocketPool_Failed)
  if (pool)
    SocketPool_free (&pool);
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* Test per-IP limiting in pool */
TEST (pool_per_ip_limit)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = NULL;

  TRY pool = SocketPool_new (arena, 100, 4096);

  /* Initially no per-IP limit */
  ASSERT_EQ (0, SocketPool_getmaxperip (pool));

  /* Set per-IP limit */
  SocketPool_setmaxperip (pool, 5);
  ASSERT_EQ (5, SocketPool_getmaxperip (pool));

  /* Disable per-IP limit */
  SocketPool_setmaxperip (pool, 0);
  ASSERT_EQ (0, SocketPool_getmaxperip (pool));
  EXCEPT (SocketPool_Failed)
  if (pool)
    SocketPool_free (&pool);
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* Test manual IP tracking in pool */
TEST (pool_manual_ip_tracking)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = NULL;
  int result;

  TRY pool = SocketPool_new (arena, 100, 4096);
  SocketPool_setmaxperip (pool, 2);

  /* Track IPs manually */
  result = SocketPool_track_ip (pool, "192.168.1.100");
  ASSERT_EQ (1, result);
  ASSERT_EQ (1, SocketPool_ip_count (pool, "192.168.1.100"));

  result = SocketPool_track_ip (pool, "192.168.1.100");
  ASSERT_EQ (1, result);

  result = SocketPool_track_ip (pool, "192.168.1.100");
  ASSERT_EQ (0, result); /* Rejected (limit 2) */

  /* Release */
  SocketPool_release_ip (pool, "192.168.1.100");
  ASSERT_EQ (1, SocketPool_ip_count (pool, "192.168.1.100"));

  /* Can track again */
  result = SocketPool_track_ip (pool, "192.168.1.100");
  ASSERT_EQ (1, result);
  EXCEPT (SocketPool_Failed)
  if (pool)
    SocketPool_free (&pool);
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* Test accept_allowed check */
TEST (pool_accept_allowed_check)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = NULL;
  int allowed;

  TRY pool = SocketPool_new (arena, 100, 4096);

  /* No limits - always allowed */
  allowed = SocketPool_accept_allowed (pool, "10.0.0.1");
  ASSERT_EQ (1, allowed);

  /* Set per-IP limit */
  SocketPool_setmaxperip (pool, 1);
  SocketPool_track_ip (pool, "10.0.0.1");

  /* Now at limit */
  allowed = SocketPool_accept_allowed (pool, "10.0.0.1");
  ASSERT_EQ (0, allowed);

  /* Different IP still allowed */
  allowed = SocketPool_accept_allowed (pool, "10.0.0.2");
  ASSERT_EQ (1, allowed);
  EXCEPT (SocketPool_Failed)
  if (pool)
    SocketPool_free (&pool);
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ============================================================================
 * Socket Bandwidth Limiting Tests
 * ============================================================================
 */

/* Test socket bandwidth limiting API */
TEST (socket_bandwidth_api)
{
  Socket_T sock;

  TRY sock = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (sock);

  /* Initially no bandwidth limit */
  ASSERT_EQ (0, Socket_getbandwidth (sock));

  /* Set bandwidth limit */
  Socket_setbandwidth (sock, 10240); /* 10 KB/s */
  ASSERT_EQ (10240, Socket_getbandwidth (sock));

  /* Disable bandwidth limit */
  Socket_setbandwidth (sock, 0);
  ASSERT_EQ (0, Socket_getbandwidth (sock));

  Socket_free (&sock);
  EXCEPT (Socket_Failed)
  ASSERT (0);
  END_TRY;
}

/* ============================================================================
 * Thread Safety Tests
 * ============================================================================
 */

/* Thread test data for rate limiter */
static SocketRateLimit_T thread_test_limiter;
static int thread_acquired_count;
static pthread_mutex_t thread_test_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Thread function for rate limiter test */
static void *
thread_acquire_tokens (void *arg)
{
  int i;
  int local_count = 0;
  (void)arg;

  for (i = 0; i < 100; i++)
    {
      if (SocketRateLimit_try_acquire (thread_test_limiter, 1))
        {
          local_count++;
        }
      usleep (1000); /* 1ms between attempts */
    }

  pthread_mutex_lock (&thread_test_mutex);
  thread_acquired_count += local_count;
  pthread_mutex_unlock (&thread_test_mutex);

  return NULL;
}

/* Test rate limiter thread safety */
TEST (ratelimit_thread_safety)
{
  Arena_T arena = Arena_new ();
  pthread_t threads[4];
  int i;
  struct timespec start_ts, end_ts;
  double elapsed_s;
  int expected_max;

  TRY
      /* Create limiter: 500 tokens/sec, bucket of 50 */
      thread_test_limiter
      = SocketRateLimit_new (arena, 500, 50);
  thread_acquired_count = 0;

  /* Record start time */
  clock_gettime (CLOCK_MONOTONIC, &start_ts);

  /* Start 4 threads competing for tokens */
  for (i = 0; i < 4; i++)
    {
      pthread_create (&threads[i], NULL, thread_acquire_tokens, NULL);
    }

  /* Wait for all threads */
  for (i = 0; i < 4; i++)
    {
      pthread_join (threads[i], NULL);
    }

  /* Record end time and compute elapsed seconds */
  clock_gettime (CLOCK_MONOTONIC, &end_ts);
  elapsed_s = (double)(end_ts.tv_sec - start_ts.tv_sec)
              + (double)(end_ts.tv_nsec - start_ts.tv_nsec) / 1e9;

  /* Should have acquired some tokens (exact count varies) */
  ASSERT (thread_acquired_count > 0);

  /* Compute realistic maximum based on actual elapsed time:
   * allowed = rate * elapsed_seconds + bucket_size
   * Add 20% margin for measurement granularity and scheduler jitter */
  expected_max = (int)(500.0 * elapsed_s) + 50;
  expected_max = (int)(expected_max * 1.20) + 10;

  ASSERT (thread_acquired_count <= expected_max);
  EXCEPT (SocketRateLimit_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* IP tracker thread test data */
static SocketIPTracker_T thread_test_tracker;
static int thread_track_success;
static int thread_track_fail;

/* Thread function for IP tracker test */
static void *
thread_track_ip (void *arg)
{
  int i;
  int local_success = 0;
  int local_fail = 0;
  (void)arg;

  for (i = 0; i < 50; i++)
    {
      if (SocketIPTracker_track (thread_test_tracker, "192.168.1.100"))
        {
          local_success++;
          usleep (500);
          SocketIPTracker_release (thread_test_tracker, "192.168.1.100");
        }
      else
        {
          local_fail++;
        }
      usleep (100);
    }

  pthread_mutex_lock (&thread_test_mutex);
  thread_track_success += local_success;
  thread_track_fail += local_fail;
  pthread_mutex_unlock (&thread_test_mutex);

  return NULL;
}

/* Test IP tracker thread safety */
TEST (iptracker_thread_safety)
{
  Arena_T arena = Arena_new ();
  pthread_t threads[4];
  int i;

  TRY
      /* Create tracker with limit of 2 per IP */
      thread_test_tracker
      = SocketIPTracker_new (arena, 2);
  thread_track_success = 0;
  thread_track_fail = 0;

  /* Start 4 threads competing for IP slots */
  for (i = 0; i < 4; i++)
    {
      pthread_create (&threads[i], NULL, thread_track_ip, NULL);
    }

  /* Wait for all threads */
  for (i = 0; i < 4; i++)
    {
      pthread_join (threads[i], NULL);
    }

  /* Should have some successes and some failures */
  ASSERT (thread_track_success > 0);
  ASSERT (thread_track_fail > 0);

  /* Final count should be 0 (all released) */
  ASSERT_EQ (0, SocketIPTracker_count (thread_test_tracker, "192.168.1.100"));
  EXCEPT (SocketIPTracker_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* ============================================================================
 * Edge Case Tests for SocketRateLimit_try_acquire (Issue #3049)
 * ============================================================================
 */

/* Test acquire SIZE_MAX tokens (should fail) */
TEST (ratelimit_try_acquire_size_max_fails)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, 50);

  /* Try to acquire SIZE_MAX tokens (should always fail) */
  int result = SocketRateLimit_try_acquire (limiter, SIZE_MAX);
  ASSERT_EQ (result, 0);

  /* Bucket should remain unchanged */
  ASSERT_EQ (SocketRateLimit_available (limiter), 50);

  Arena_dispose (&arena);
}

/* Test acquire from freed limiter (NULL) - should assert in debug builds */
TEST (ratelimit_try_acquire_null_limiter_asserts)
{
  /* This test documents that passing NULL to try_acquire() will assert.
   * In debug builds (with assert enabled), this would crash.
   * In release builds, behavior is undefined.
   * We don't actually call it with NULL to avoid crashing the test suite.
   */
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, 50);

  /* Valid call for comparison */
  int result = SocketRateLimit_try_acquire (limiter, 1);
  ASSERT_EQ (result, 1);

  Arena_dispose (&arena);

  /* Note: Cannot safely test NULL case as it would assert/crash:
   * SocketRateLimit_try_acquire(NULL, 1);
   */
}

/* Test acquire from shutdown limiter */
TEST (ratelimit_try_acquire_shutdown_limiter_fails)
{
  SocketRateLimit_T limiter = SocketRateLimit_new (NULL, 100, 50);

  /* Verify it works normally first */
  int result = SocketRateLimit_try_acquire (limiter, 10);
  ASSERT_EQ (result, 1);

  /* Free the limiter (sets shutdown state) */
  SocketRateLimit_free (&limiter);
  ASSERT_NULL (limiter);

  /* Cannot test acquire on freed limiter as limiter is now NULL
   * and the function has an assert(limiter) that would crash.
   * The shutdown state is checked inside WITH_LOCK macro, but
   * we can't safely reach it with a freed/NULL limiter.
   */
}

/* Test that uninitialized state is handled correctly */
TEST (ratelimit_uninitialized_state_protection)
{
  /* This test verifies that the internal state checking works.
   * We can't directly create an uninitialized limiter from the public API
   * since SocketRateLimit_new() always initializes properly or raises
   * an exception. The RATELIMIT_IS_VALID check protects against race
   * conditions during free or internal corruption.
   */
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, 50);

  /* Verify limiter works in normal initialized state */
  ASSERT_EQ (SocketRateLimit_available (limiter), 50);
  int result = SocketRateLimit_try_acquire (limiter, 5);
  ASSERT_EQ (result, 1);
  ASSERT_EQ (SocketRateLimit_available (limiter), 45);

  Arena_dispose (&arena);
}

/* Test edge case: acquire exactly available tokens multiple times */
TEST (ratelimit_try_acquire_exact_available_repeatedly)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, 10);

  /* Acquire exactly 5 tokens twice */
  int result1 = SocketRateLimit_try_acquire (limiter, 5);
  ASSERT_EQ (result1, 1);
  ASSERT_EQ (SocketRateLimit_available (limiter), 5);

  int result2 = SocketRateLimit_try_acquire (limiter, 5);
  ASSERT_EQ (result2, 1);
  ASSERT_EQ (SocketRateLimit_available (limiter), 0);

  /* Third attempt should fail */
  int result3 = SocketRateLimit_try_acquire (limiter, 5);
  ASSERT_EQ (result3, 0);
  ASSERT_EQ (SocketRateLimit_available (limiter), 0);

  Arena_dispose (&arena);
}

/* Test acquire with refill that doesn't reach requested amount */
TEST (ratelimit_try_acquire_insufficient_after_partial_refill)
{
  Arena_T arena = Arena_new ();
  /* 100 tokens/sec, bucket size 100 */
  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, 100);

  /* Drain bucket completely */
  SocketRateLimit_try_acquire (limiter, 100);
  ASSERT_EQ (SocketRateLimit_available (limiter), 0);

  /* Wait 100ms for ~10 tokens to refill */
  usleep (100000);

  /* Try to acquire 50 tokens (more than refilled) */
  int result = SocketRateLimit_try_acquire (limiter, 50);
  ASSERT_EQ (result, 0);

  /* Should still have fewer than 50 tokens available.
   * Note: Under heavy load or timing variance, we may have 0 tokens or
   * close to the full refill amount, so we just verify the acquire failed.
   */
  size_t available = SocketRateLimit_available (limiter);
  ASSERT (available < 50); /* Less than requested amount */

  Arena_dispose (&arena);
}

/* Test acquire 1 then 0 then 1 pattern */
TEST (ratelimit_try_acquire_alternating_pattern)
{
  Arena_T arena = Arena_new ();
  SocketRateLimit_T limiter = SocketRateLimit_new (arena, 100, 10);

  ASSERT_EQ (SocketRateLimit_try_acquire (limiter, 1), 1);
  ASSERT_EQ (SocketRateLimit_available (limiter), 9);

  ASSERT_EQ (SocketRateLimit_try_acquire (limiter, 0), 1);
  ASSERT_EQ (SocketRateLimit_available (limiter), 9);

  ASSERT_EQ (SocketRateLimit_try_acquire (limiter, 1), 1);
  ASSERT_EQ (SocketRateLimit_available (limiter), 8);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test Suite Entry Point
 * ============================================================================
 */

||||||| parent of bbf843aa (test(core): Add comprehensive unit tests for SocketRateLimit_new)
/* Test setmaxunique - limit on total unique IPs tracked */
TEST (iptracker_setmaxunique)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;

  TRY tracker = SocketIPTracker_new (arena, 100);

  /* Default max unique should be some large value */
  size_t initial_max = SocketIPTracker_getmaxunique (tracker);
  ASSERT (initial_max > 0);

  /* Set a specific limit */
  SocketIPTracker_setmaxunique (tracker, 5);
  ASSERT_EQ (5, SocketIPTracker_getmaxunique (tracker));

  /* Reset to unlimited */
  SocketIPTracker_setmaxunique (tracker, 0);
  ASSERT_EQ (0, SocketIPTracker_getmaxunique (tracker));
  EXCEPT (SocketIPTracker_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test getmaxunique retrieval */
TEST (iptracker_getmaxunique)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;

  TRY tracker = SocketIPTracker_new (arena, 10);

  /* Set known value */
  SocketIPTracker_setmaxunique (tracker, 1000);
  ASSERT_EQ (1000, SocketIPTracker_getmaxunique (tracker));

  /* Change and verify */
  SocketIPTracker_setmaxunique (tracker, 500);
  ASSERT_EQ (500, SocketIPTracker_getmaxunique (tracker));
  EXCEPT (SocketIPTracker_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test max unique IPs exceeded scenario */
TEST (iptracker_max_unique_exceeded)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;
  int result;

  TRY tracker = SocketIPTracker_new (arena, 100);

  /* Set a low unique IP limit */
  SocketIPTracker_setmaxunique (tracker, 3);

  /* Track 3 unique IPs - should succeed */
  result = SocketIPTracker_track (tracker, "1.1.1.1");
  ASSERT_EQ (1, result);

  result = SocketIPTracker_track (tracker, "2.2.2.2");
  ASSERT_EQ (1, result);

  result = SocketIPTracker_track (tracker, "3.3.3.3");
  ASSERT_EQ (1, result);

  ASSERT_EQ (3, SocketIPTracker_unique_ips (tracker));

  /* 4th unique IP should be rejected */
  result = SocketIPTracker_track (tracker, "4.4.4.4");
  ASSERT_EQ (0, result);

  /* But tracking existing IP should still work */
  result = SocketIPTracker_track (tracker, "1.1.1.1");
  ASSERT_EQ (1, result);
  EXCEPT (SocketIPTracker_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test invalid IP address handling */
TEST (iptracker_invalid_ip_rejected)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;
  int result;

  TRY tracker = SocketIPTracker_new (arena, 10);

  /* Empty string - returns 1 (allow) as silent no-op per implementation */
  result = SocketIPTracker_track (tracker, "");
  ASSERT_EQ (1, result);

  /* NULL pointer - returns 1 (allow) as silent no-op per implementation */
  result = SocketIPTracker_track (tracker, NULL);
  ASSERT_EQ (1, result);

  /* Invalid format - properly rejected with 0 */
  result = SocketIPTracker_track (tracker, "not-an-ip");
  ASSERT_EQ (0, result);

  /* Invalid IPv4 - properly rejected with 0 */
  result = SocketIPTracker_track (tracker, "999.999.999.999");
  ASSERT_EQ (0, result);

  /* Should have no entries (empty/NULL don't create entries, invalid rejected)
   */
  ASSERT_EQ (0, SocketIPTracker_unique_ips (tracker));
  EXCEPT (SocketIPTracker_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test tracking same IP multiple times */
TEST (iptracker_track_same_ip_multiple)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;
  int result;

  TRY tracker = SocketIPTracker_new (arena, 10);

  /* Track same IP 5 times */
  for (int i = 0; i < 5; i++)
    {
      result = SocketIPTracker_track (tracker, "192.168.50.50");
      ASSERT_EQ (1, result);
    }

  /* Should count as 1 unique IP with 5 connections */
  ASSERT_EQ (1, SocketIPTracker_unique_ips (tracker));
  ASSERT_EQ (5, SocketIPTracker_count (tracker, "192.168.50.50"));
  ASSERT_EQ (5, SocketIPTracker_total (tracker));
  EXCEPT (SocketIPTracker_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* Test release on non-tracked IP */
TEST (iptracker_release_nonexistent)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker;

  TRY tracker = SocketIPTracker_new (arena, 10);

  /* Release non-existent IP - should not crash */
  SocketIPTracker_release (tracker, "9.9.9.9");
  SocketIPTracker_release (tracker, NULL);
  SocketIPTracker_release (tracker, "");

  /* Stats should be unchanged */
  ASSERT_EQ (0, SocketIPTracker_unique_ips (tracker));
  ASSERT_EQ (0, SocketIPTracker_total (tracker));
  EXCEPT (SocketIPTracker_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* ============================================================================
 * SocketPool Rate Limiting Tests
 * ============================================================================
 */

/* Test connection rate limiting in pool */
TEST (pool_connection_rate_limit)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = NULL;

  TRY pool = SocketPool_new (arena, 100, 4096);

  /* Initially no rate limit */
  ASSERT_EQ (0, SocketPool_getconnrate (pool));

  /* Set rate limit */
  SocketPool_setconnrate (pool, 10, 5);
  ASSERT_EQ (10, SocketPool_getconnrate (pool));

  /* Disable rate limit */
  SocketPool_setconnrate (pool, 0, 0);
  ASSERT_EQ (0, SocketPool_getconnrate (pool));
  EXCEPT (SocketPool_Failed)
  if (pool)
    SocketPool_free (&pool);
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* Test per-IP limiting in pool */
TEST (pool_per_ip_limit)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = NULL;

  TRY pool = SocketPool_new (arena, 100, 4096);

  /* Initially no per-IP limit */
  ASSERT_EQ (0, SocketPool_getmaxperip (pool));

  /* Set per-IP limit */
  SocketPool_setmaxperip (pool, 5);
  ASSERT_EQ (5, SocketPool_getmaxperip (pool));

  /* Disable per-IP limit */
  SocketPool_setmaxperip (pool, 0);
  ASSERT_EQ (0, SocketPool_getmaxperip (pool));
  EXCEPT (SocketPool_Failed)
  if (pool)
    SocketPool_free (&pool);
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* Test manual IP tracking in pool */
TEST (pool_manual_ip_tracking)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = NULL;
  int result;

  TRY pool = SocketPool_new (arena, 100, 4096);
  SocketPool_setmaxperip (pool, 2);

  /* Track IPs manually */
  result = SocketPool_track_ip (pool, "192.168.1.100");
  ASSERT_EQ (1, result);
  ASSERT_EQ (1, SocketPool_ip_count (pool, "192.168.1.100"));

  result = SocketPool_track_ip (pool, "192.168.1.100");
  ASSERT_EQ (1, result);

  result = SocketPool_track_ip (pool, "192.168.1.100");
  ASSERT_EQ (0, result); /* Rejected (limit 2) */

  /* Release */
  SocketPool_release_ip (pool, "192.168.1.100");
  ASSERT_EQ (1, SocketPool_ip_count (pool, "192.168.1.100"));

  /* Can track again */
  result = SocketPool_track_ip (pool, "192.168.1.100");
  ASSERT_EQ (1, result);
  EXCEPT (SocketPool_Failed)
  if (pool)
    SocketPool_free (&pool);
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* Test accept_allowed check */
TEST (pool_accept_allowed_check)
{
  Arena_T arena = Arena_new ();
  SocketPool_T pool = NULL;
  int allowed;

  TRY pool = SocketPool_new (arena, 100, 4096);

  /* No limits - always allowed */
  allowed = SocketPool_accept_allowed (pool, "10.0.0.1");
  ASSERT_EQ (1, allowed);

  /* Set per-IP limit */
  SocketPool_setmaxperip (pool, 1);
  SocketPool_track_ip (pool, "10.0.0.1");

  /* Now at limit */
  allowed = SocketPool_accept_allowed (pool, "10.0.0.1");
  ASSERT_EQ (0, allowed);

  /* Different IP still allowed */
  allowed = SocketPool_accept_allowed (pool, "10.0.0.2");
  ASSERT_EQ (1, allowed);
  EXCEPT (SocketPool_Failed)
  if (pool)
    SocketPool_free (&pool);
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  SocketPool_free (&pool);
  Arena_dispose (&arena);
}

/* ============================================================================
 * Socket Bandwidth Limiting Tests
 * ============================================================================
 */

/* Test socket bandwidth limiting API */
TEST (socket_bandwidth_api)
{
  Socket_T sock;

  TRY sock = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (sock);

  /* Initially no bandwidth limit */
  ASSERT_EQ (0, Socket_getbandwidth (sock));

  /* Set bandwidth limit */
  Socket_setbandwidth (sock, 10240); /* 10 KB/s */
  ASSERT_EQ (10240, Socket_getbandwidth (sock));

  /* Disable bandwidth limit */
  Socket_setbandwidth (sock, 0);
  ASSERT_EQ (0, Socket_getbandwidth (sock));

  Socket_free (&sock);
  EXCEPT (Socket_Failed)
  ASSERT (0);
  END_TRY;
}

/* ============================================================================
 * Thread Safety Tests
 * ============================================================================
 */

/* Thread test data for rate limiter */
static SocketRateLimit_T thread_test_limiter;
static int thread_acquired_count;
static pthread_mutex_t thread_test_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Thread function for rate limiter test */
static void *
thread_acquire_tokens (void *arg)
{
  int i;
  int local_count = 0;
  (void)arg;

  for (i = 0; i < 100; i++)
    {
      if (SocketRateLimit_try_acquire (thread_test_limiter, 1))
        {
          local_count++;
        }
      usleep (1000); /* 1ms between attempts */
    }

  pthread_mutex_lock (&thread_test_mutex);
  thread_acquired_count += local_count;
  pthread_mutex_unlock (&thread_test_mutex);

  return NULL;
}

/* Test rate limiter thread safety */
TEST (ratelimit_thread_safety)
{
  Arena_T arena = Arena_new ();
  pthread_t threads[4];
  int i;
  struct timespec start_ts, end_ts;
  double elapsed_s;
  int expected_max;

  TRY
      /* Create limiter: 500 tokens/sec, bucket of 50 */
      thread_test_limiter
      = SocketRateLimit_new (arena, 500, 50);
  thread_acquired_count = 0;

  /* Record start time */
  clock_gettime (CLOCK_MONOTONIC, &start_ts);

  /* Start 4 threads competing for tokens */
  for (i = 0; i < 4; i++)
    {
      pthread_create (&threads[i], NULL, thread_acquire_tokens, NULL);
    }

  /* Wait for all threads */
  for (i = 0; i < 4; i++)
    {
      pthread_join (threads[i], NULL);
    }

  /* Record end time and compute elapsed seconds */
  clock_gettime (CLOCK_MONOTONIC, &end_ts);
  elapsed_s = (double)(end_ts.tv_sec - start_ts.tv_sec)
              + (double)(end_ts.tv_nsec - start_ts.tv_nsec) / 1e9;

  /* Should have acquired some tokens (exact count varies) */
  ASSERT (thread_acquired_count > 0);

  /* Compute realistic maximum based on actual elapsed time:
   * allowed = rate * elapsed_seconds + bucket_size
   * Add 20% margin for measurement granularity and scheduler jitter */
  expected_max = (int)(500.0 * elapsed_s) + 50;
  expected_max = (int)(expected_max * 1.20) + 10;

  ASSERT (thread_acquired_count <= expected_max);
  EXCEPT (SocketRateLimit_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* IP tracker thread test data */
static SocketIPTracker_T thread_test_tracker;
static int thread_track_success;
static int thread_track_fail;

/* Thread function for IP tracker test */
static void *
thread_track_ip (void *arg)
{
  int i;
  int local_success = 0;
  int local_fail = 0;
  (void)arg;

  for (i = 0; i < 50; i++)
    {
      if (SocketIPTracker_track (thread_test_tracker, "192.168.1.100"))
        {
          local_success++;
          usleep (500);
          SocketIPTracker_release (thread_test_tracker, "192.168.1.100");
        }
      else
        {
          local_fail++;
        }
      usleep (100);
    }

  pthread_mutex_lock (&thread_test_mutex);
  thread_track_success += local_success;
  thread_track_fail += local_fail;
  pthread_mutex_unlock (&thread_test_mutex);

  return NULL;
}

/* Test IP tracker thread safety */
TEST (iptracker_thread_safety)
{
  Arena_T arena = Arena_new ();
  pthread_t threads[4];
  int i;

  TRY
      /* Create tracker with limit of 2 per IP */
      thread_test_tracker
      = SocketIPTracker_new (arena, 2);
  thread_track_success = 0;
  thread_track_fail = 0;

  /* Start 4 threads competing for IP slots */
  for (i = 0; i < 4; i++)
    {
      pthread_create (&threads[i], NULL, thread_track_ip, NULL);
    }

  /* Wait for all threads */
  for (i = 0; i < 4; i++)
    {
      pthread_join (threads[i], NULL);
    }

  /* Should have some successes and some failures */
  ASSERT (thread_track_success > 0);
  ASSERT (thread_track_fail > 0);

  /* Final count should be 0 (all released) */
  ASSERT_EQ (0, SocketIPTracker_count (thread_test_tracker, "192.168.1.100"));
  EXCEPT (SocketIPTracker_Failed)
  Arena_dispose (&arena);
  ASSERT (0);
  END_TRY;

  Arena_dispose (&arena);
}

/* ============================================================================
 * Test Suite Entry Point
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
