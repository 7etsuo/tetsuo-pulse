/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketRateLimit.c - Token Bucket Rate Limiter Implementation
 *
 * Part of the Socket Library
 *
 * Implements the token bucket algorithm for rate limiting:
 * - Tokens are added at a constant rate (tokens_per_sec)
 * - Bucket has a maximum capacity (bucket_size) for burst handling
 * - Operations consume tokens; insufficient tokens means rate limited
 *
 * Thread Safety:
 * - All public functions use mutex protection
 * - Internal helpers document whether caller must hold mutex
 * - Thread-local exception pattern for safe error reporting
 */

#include <assert.h>
#include <stdlib.h>

#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketRateLimit-private.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "socket/SocketCommon.h"

#define T SocketRateLimit_T

/**
 * WITH_LOCK - Macro to execute code with mutex acquired
 * @limiter: Rate limiter instance
 * @code: Code block to execute while mutex is held
 *
 * Simplifies common lock/unlock patterns across public API functions.
 * Does not perform refill - add ratelimit_refill_bucket(limiter) inside code
 * if needed. For cases requiring early unlock, use manual locking.
 *
 * Example:
 *   WITH_LOCK(limiter, {
 *     ratelimit_refill_bucket(limiter);
 *     result = ratelimit_try_consume(limiter, tokens);
 *   });
 *
 * Thread-safe: Yes
 */
#define WITH_LOCK(limiter, code)                                              \
  do                                                                          \
    {                                                                         \
      T _l = (T)(limiter);                                                    \
      int lock_err = pthread_mutex_lock (&_l->mutex);                         \
      if (lock_err != 0)                                                      \
        SOCKET_RAISE_MSG (SocketRateLimit, SocketRateLimit_Failed,            \
                          "pthread_mutex_lock failed: %s",                    \
                          Socket_safe_strerror (lock_err));                   \
      TRY{ code } FINALLY { (void)pthread_mutex_unlock (&_l->mutex); }        \
      END_TRY;                                                                \
    }                                                                         \
  while (0)

/**
 * RATELIMIT_IS_VALID - Check if limiter is properly initialized
 * @_l: Limiter instance (must be within WITH_LOCK scope)
 *
 * Returns: Non-zero if limiter is valid and initialized.
 * Used inside WITH_LOCK blocks to guard operations.
 */
#define RATELIMIT_IS_VALID(_l)                                                \
  ((_l)->initialized == SOCKET_RATELIMIT_MUTEX_INITIALIZED)

/* Live instance count for debugging and leak detection */
static struct SocketLiveCount ratelimit_live_tracker
    = SOCKETLIVECOUNT_STATIC_INIT;

#define ratelimit_live_inc()                                                  \
  SocketLiveCount_increment (&ratelimit_live_tracker)
#define ratelimit_live_dec()                                                  \
  SocketLiveCount_decrement (&ratelimit_live_tracker)

/* ============================================================================
 * Exception Definitions
 * ============================================================================
 */

const Except_T SocketRateLimit_Failed
    = { &SocketRateLimit_Failed, "Rate limiter operation failed" };

/* Thread-local exception using centralized macro */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketRateLimit);

/* ============================================================================
 * Pure Helper Functions (No Mutex Required, No Side Effects)
 * ============================================================================
 */

/**
 * ratelimit_calculate_tokens_to_add - Calculate tokens from elapsed time
 * @elapsed_ms: Elapsed time in milliseconds
 * @tokens_per_sec: Token refill rate
 *
 * Returns: Number of tokens to add (0 if elapsed_ms <= 0)
 */
static size_t
ratelimit_calculate_tokens_to_add (int64_t elapsed_ms, size_t tokens_per_sec)
{
  if (elapsed_ms <= 0)
    return 0;

  size_t tokens_per_ms = tokens_per_sec / SOCKET_MS_PER_SECOND;
  size_t safe_tokens
      = SocketSecurity_safe_multiply ((size_t)elapsed_ms, tokens_per_ms);
  if (safe_tokens == 0) /* Overflow or zero */
    return 0;
  return safe_tokens;
}

/**
 * ratelimit_calculate_wait_ms - Calculate wait time for needed tokens
 * @needed: Number of additional tokens needed
 * @tokens_per_sec: Token refill rate (must be > 0)
 *
 * Returns: Milliseconds to wait (minimum SOCKET_RATELIMIT_MIN_WAIT_MS)
 */
static int64_t
ratelimit_calculate_wait_ms (size_t needed, size_t tokens_per_sec)
{
  assert (tokens_per_sec > 0);

  size_t ms_per_token = SOCKET_MS_PER_SECOND / tokens_per_sec;
  if (ms_per_token == 0) /* tokens_per_sec too large */
    return SOCKET_RATELIMIT_IMPOSSIBLE_WAIT;

  size_t safe_wait_ms;
  if (!SocketSecurity_check_multiply (needed, ms_per_token, &safe_wait_ms))
    return INT64_MAX;  /* Overflow: treat as very long wait */

  int64_t wait_ms = (int64_t) safe_wait_ms;
  return wait_ms;  /* Guaranteed > 0 and no overflow */
}

/* ============================================================================
 * Bucket Operations (Caller Must Hold Mutex)
 * ============================================================================
 */

/**
 * ratelimit_calculate_elapsed - Calculate elapsed time since last refill
 * @limiter: Rate limiter instance
 * @now_ms: Current time in milliseconds
 *
 * Returns: Elapsed milliseconds clamped to SOCKET_MS_PER_SECOND max
 *
 * Security: Clamps elapsed time to prevent token burst attacks via clock
 * manipulation (NTP adjustments, VM time changes).
 */
static int64_t
ratelimit_calculate_elapsed (const T limiter, int64_t now_ms)
{
  int64_t elapsed_ms;

  assert (limiter);

  elapsed_ms = now_ms - limiter->last_refill_ms;

  /* Clamp to prevent token burst from clock jumps */
  if (elapsed_ms > SOCKET_MS_PER_SECOND)
    elapsed_ms = SOCKET_MS_PER_SECOND;

  return (elapsed_ms > 0) ? elapsed_ms : 0;
}

/**
 * ratelimit_add_tokens - Add calculated tokens to the bucket (caller holds
 * lock)
 * @limiter: Rate limiter instance
 * @tokens_to_add: Number of tokens to add (may cause overflow check)
 * @now_ms: Current monotonic timestamp to record as last_refill_ms
 *
 * Safely adds tokens using SocketSecurity_check_add to prevent overflow.
 * Caps at bucket_size if addition would exceed.
 * Updates last_refill_ms to now.
 *
 * Thread-safe: Caller must hold limiter->mutex
 */
static void
ratelimit_add_tokens (T limiter, size_t tokens_to_add, int64_t now_ms)
{
  assert (limiter);

  size_t new_tokens;
  if (SocketSecurity_check_add (limiter->tokens, tokens_to_add, &new_tokens))
    {
      if (new_tokens > limiter->bucket_size)
        new_tokens = limiter->bucket_size;
      limiter->tokens = new_tokens;
    }
  else
    {
      limiter->tokens = limiter->bucket_size;
    }

  limiter->last_refill_ms = now_ms;
}

/**
 * ratelimit_refill_bucket - Refill bucket based on elapsed time
 * @limiter: Rate limiter instance
 */
static void
ratelimit_refill_bucket (T limiter)
{
  int64_t now_ms;
  int64_t elapsed_ms;
  size_t tokens_to_add;

  assert (limiter);

  now_ms = Socket_get_monotonic_ms ();
  elapsed_ms = ratelimit_calculate_elapsed (limiter, now_ms);

  if (elapsed_ms == 0)
    return;

  tokens_to_add = ratelimit_calculate_tokens_to_add (elapsed_ms,
                                                     limiter->tokens_per_sec);

  if (tokens_to_add > 0)
    ratelimit_add_tokens (limiter, tokens_to_add, now_ms);
}

/**
 * ratelimit_try_consume - Try to consume tokens from bucket
 * @limiter: Rate limiter instance
 * @tokens: Number of tokens to consume
 *
 * Returns: 1 if tokens consumed, 0 if insufficient tokens
 */
static int
ratelimit_try_consume (T limiter, size_t tokens)
{
  assert (limiter);

  if (limiter->tokens >= tokens)
    {
      limiter->tokens -= tokens;
      return 1;
    }
  return 0;
}

/**
 * ratelimit_compute_wait_time - Compute wait time for needed tokens
 * @limiter: Rate limiter instance
 * @tokens: Number of tokens needed
 *
 * Returns: Wait time in milliseconds (0 if tokens available)
 */
static int64_t
ratelimit_compute_wait_time (const T limiter, size_t tokens)
{
  size_t needed;

  assert (limiter);

  if (limiter->tokens >= tokens)
    return 0;

  needed = tokens - limiter->tokens;
  return ratelimit_calculate_wait_ms (needed, limiter->tokens_per_sec);
}

/* ============================================================================
 * Private Helper Functions for Public API Patterns
 * ============================================================================
 */

/**
 * ratelimit_try_consume_with_refill - Internal helper for try_acquire logic
 * @limiter: Rate limiter instance
 * @tokens: Number of tokens to try consume
 *
 * Performs lock, initialized check, refill, and try consume atomically.
 * Returns: 1 success, 0 limited or invalid state
 * Thread-safe: Yes
 */
static int
ratelimit_try_consume_with_refill (T limiter, size_t tokens)
{
  volatile int result = 0;

  WITH_LOCK (limiter, {
    if (!RATELIMIT_IS_VALID (_l))
      {
        result = 0;
      }
    else
      {
        ratelimit_refill_bucket (_l);
        result = ratelimit_try_consume (_l, tokens);
      }
  });

  return result;
}

/**
 * ratelimit_available_with_refill - Internal helper for available logic
 * @limiter: Rate limiter instance
 *
 * Performs lock, check, refill, get tokens.
 * Returns: Available tokens or 0 if invalid
 */
static size_t
ratelimit_available_with_refill (T limiter)
{
  volatile size_t available = 0;

  WITH_LOCK (limiter, {
    if (!RATELIMIT_IS_VALID (_l))
      {
        available = 0;
      }
    else
      {
        ratelimit_refill_bucket (_l);
        available = _l->tokens;
      }
  });

  return available;
}

/**
 * ratelimit_wait_time_with_refill - Internal helper for wait_time_ms logic
 * @limiter: Rate limiter instance
 * @tokens: Tokens needed
 *
 * Performs lock, check, bucket check, refill, compute wait.
 * Returns: wait ms or impossible
 */
static int64_t
ratelimit_wait_time_with_refill (T limiter, size_t tokens)
{
  volatile int64_t wait_ms = SOCKET_RATELIMIT_IMPOSSIBLE_WAIT;

  WITH_LOCK (limiter, {
    if (!RATELIMIT_IS_VALID (_l))
      {
        wait_ms = SOCKET_RATELIMIT_IMPOSSIBLE_WAIT;
      }
    else if (tokens > _l->bucket_size)
      {
        wait_ms = SOCKET_RATELIMIT_IMPOSSIBLE_WAIT;
      }
    else
      {
        ratelimit_refill_bucket (_l);
        wait_ms = ratelimit_compute_wait_time (_l, tokens);
      }
  });

  return wait_ms;
}

/**
 * ratelimit_get_rate_locked - Internal helper for get_rate logic
 * @limiter: Rate limiter instance
 *
 * Performs lock, initialized check, return tokens_per_sec or 0
 * Returns: Current rate or 0 if invalid
 */
static size_t
ratelimit_get_rate_locked (T limiter)
{
  volatile size_t rate = 0;

  WITH_LOCK (limiter, {
    if (!RATELIMIT_IS_VALID (_l))
      {
        rate = 0;
      }
    else
      {
        rate = _l->tokens_per_sec;
      }
  });

  return rate;
}

/**
 * ratelimit_get_bucket_size_locked - Internal helper for get_bucket_size logic
 * @limiter: Rate limiter instance
 *
 * Performs lock, initialized check, return bucket_size or 0
 * Returns: Current bucket size or 0 if invalid
 */
static size_t
ratelimit_get_bucket_size_locked (T limiter)
{
  volatile size_t size = 0;

  WITH_LOCK (limiter, {
    if (!RATELIMIT_IS_VALID (_l))
      {
        size = 0;
      }
    else
      {
        size = _l->bucket_size;
      }
  });

  return size;
}

/* ============================================================================
 * Lifecycle Helpers
 * ============================================================================
 */

/**
 * ratelimit_allocate - Allocate limiter structure
 * @arena: Arena for allocation (NULL to use malloc)
 *
 * Returns: Allocated structure or NULL on failure
 */
static T
ratelimit_allocate (Arena_T arena)
{
  if (arena)
    return CALLOC (arena, 1, sizeof (struct T));
  return calloc (1, sizeof (struct T));
}

/**
 * ratelimit_init_fields - Initialize limiter structure fields
 * @limiter: Rate limiter instance to initialize
 * @tokens_per_sec: Token refill rate
 * @bucket_size: Maximum bucket capacity
 * @arena: Arena for allocation (may be NULL)
 */
static void
ratelimit_init_fields (T limiter, size_t tokens_per_sec, size_t bucket_size,
                       Arena_T arena)
{
  assert (limiter);
  assert (tokens_per_sec > 0);
  assert (bucket_size > 0);

  limiter->tokens_per_sec = tokens_per_sec;
  limiter->bucket_size = bucket_size;
  limiter->tokens = bucket_size;
  limiter->last_refill_ms = Socket_get_monotonic_ms ();
  limiter->arena = arena;
  limiter->initialized = SOCKET_RATELIMIT_MUTEX_UNINITIALIZED;
}

/**
 * ratelimit_init_mutex - Initialize the limiter's mutex
 * @limiter: Rate limiter instance
 *
 * Uses SOCKET_MUTEX_ARENA_INIT macro for consistent pattern.
 * Raises: SocketRateLimit_Failed if pthread_mutex_init fails
 */
static void
ratelimit_init_mutex (T limiter)
{
  assert (limiter);
  SOCKET_MUTEX_ARENA_INIT (limiter, SocketRateLimit, SocketRateLimit_Failed);
}

/**
 * ratelimit_validate_params - Validate and normalize rate limiter parameters
 * @tokens_per_sec: Token refill rate (must be > 0)
 * @bucket_size: Pointer to bucket size (updated if 0 to tokens_per_sec)
 *
 * Validates and normalizes parameters. Raises on invalid.
 *
 * Raises: SocketRateLimit_Failed on invalid parameters
 */
static void
ratelimit_validate_params (size_t tokens_per_sec, size_t *bucket_size)
{
  if (tokens_per_sec == 0)
    SOCKET_RAISE_MSG (SocketRateLimit, SocketRateLimit_Failed,
                      "tokens_per_sec must be > 0");

  if (*bucket_size == 0)
    *bucket_size = tokens_per_sec;

  if (!SOCKET_SECURITY_VALID_SIZE (tokens_per_sec)
      || !SOCKET_SECURITY_VALID_SIZE (*bucket_size))
    SOCKET_RAISE_MSG (SocketRateLimit, SocketRateLimit_Failed,
                      "Rate limiter parameters exceed security limits");
}

/* ============================================================================
 * Mutex Helper Macro
 * ============================================================================
 */

/* ============================================================================
 * Public API - Lifecycle
 * ============================================================================
 */

/**
 * SocketRateLimit_new - Create a new token bucket rate limiter
 * @arena: Arena for memory allocation (NULL to use malloc)
 * @tokens_per_sec: Token refill rate (tokens added per second)
 * @bucket_size: Maximum bucket capacity (burst limit, 0 = use tokens_per_sec)
 *
 * Returns: New rate limiter instance
 * Raises: SocketRateLimit_Failed on allocation failure or invalid parameters
 * Thread-safe: Yes - returns new independent instance
 */
T
SocketRateLimit_new (Arena_T arena, size_t tokens_per_sec, size_t bucket_size)
{
  T limiter;
  size_t normalized_bucket = bucket_size;

  ratelimit_validate_params (tokens_per_sec, &normalized_bucket);

  /* Allocate structure */
  limiter = ratelimit_allocate (arena);
  if (!limiter)
    SOCKET_RAISE_MSG (SocketRateLimit, SocketRateLimit_Failed,
                      "Failed to allocate rate limiter");

  /* Initialize fields */
  ratelimit_init_fields (limiter, tokens_per_sec, normalized_bucket, arena);

  TRY
  {
    ratelimit_init_mutex (limiter);
    ratelimit_live_inc ();
  }
  FINALLY
  {
    if (Except_frame.exception != NULL && !limiter->arena)
      free (limiter);
  }
  END_TRY;

  return limiter;
}

/**
 * SocketRateLimit_free - Free a rate limiter
 * @limiter: Pointer to limiter (will be set to NULL)
 *
 * Thread-safe: Yes (acquires mutex during cleanup)
 *
 * Note: Only frees memory if allocated with malloc (arena == NULL).
 * Arena-allocated limiters are freed when arena is disposed.
 * Always destroys the mutex regardless of allocation method.
 */
void
SocketRateLimit_free (T *limiter)
{
  T l;

  if (!limiter || !*limiter)
    return;

  l = *limiter;

  if (l->initialized == SOCKET_RATELIMIT_MUTEX_INITIALIZED)
    {
      /* Set shutdown flag while holding lock to synchronize and prevent new
       * operations */
      WITH_LOCK (l, l->initialized = SOCKET_RATELIMIT_SHUTDOWN;);

      /* Wait for concurrent operations to complete before destroying mutex */
      int retries = SOCKET_RATELIMIT_FREE_MAX_RETRIES;
      while (retries-- > 0)
        {
          if (pthread_mutex_trylock (&l->mutex) == 0)
            {
              pthread_mutex_unlock (&l->mutex);
              break; /* No holder, safe to destroy */
            }
          struct timespec ts = { 0, SOCKET_NS_PER_MS }; /* 1ms */
          nanosleep (&ts, NULL);
        }
      if (retries < 0)
        {
          SOCKET_RATELIMIT_WARN ("SocketRateLimit_free: destroying potentially "
                                 "locked mutex after timeout");
        }

      pthread_mutex_destroy (&l->mutex);
      ratelimit_live_dec ();
    }

  if (!l->arena)
    free (l);

  *limiter = NULL;
}

/* ============================================================================
 * Public API - Token Acquisition
 * ============================================================================
 */

/**
 * SocketRateLimit_try_acquire - Try to consume tokens (non-blocking)
 * @limiter: Rate limiter instance
 * @tokens: Number of tokens to consume
 *
 * Returns: 1 if tokens acquired successfully, 0 if rate limited
 * Thread-safe: Yes - uses internal mutex
 *
 * Refills bucket based on elapsed time, then attempts to consume tokens.
 * Does not block - returns immediately with result.
 * Requesting 0 tokens always succeeds.
 */
int
SocketRateLimit_try_acquire (T limiter, size_t tokens)
{
  assert (limiter);

  if (tokens == 0)
    return 1;

  return ratelimit_try_consume_with_refill (limiter, tokens);
}

/**
 * SocketRateLimit_wait_time_ms - Calculate wait time for tokens
 * @limiter: Rate limiter instance
 * @tokens: Number of tokens needed
 *
 * Returns: Milliseconds to wait, 0 if immediate, -1 if impossible
 * Thread-safe: Yes - uses internal mutex
 *
 * Does not consume tokens - just calculates wait time.
 * Returns 0 if tokens are already available.
 * Returns SOCKET_RATELIMIT_IMPOSSIBLE_WAIT (-1) if tokens > bucket_size.
 */
int64_t
SocketRateLimit_wait_time_ms (T limiter, size_t tokens)
{
  assert (limiter);

  if (tokens == 0)
    return 0;

  return ratelimit_wait_time_with_refill (limiter, tokens);
}

/**
 * SocketRateLimit_available - Get current available tokens
 * @limiter: Rate limiter instance
 *
 * Returns: Number of tokens currently available
 * Thread-safe: Yes - uses internal mutex
 *
 * Refills bucket based on elapsed time before returning count.
 */
size_t
SocketRateLimit_available (T limiter)
{
  assert (limiter);

  return ratelimit_available_with_refill (limiter);
}

/**
 * ratelimit_update_rate_locked - Update tokens_per_sec if valid (caller holds
 * lock)
 * @limiter: Rate limiter instance (locked)
 * @new_rate: New rate (>0 to set, <=0 ignore)
 *
 * Validates and sets tokens_per_sec if new_rate > 0.
 *
 * Raises: SocketRateLimit_Failed if new_rate invalid (security limits)
 * Thread-safe: Caller must hold mutex
 */
static void
ratelimit_update_rate_locked (T limiter, size_t new_rate)
{
  if (new_rate > 0)
    {
      if (!SOCKET_SECURITY_VALID_SIZE (new_rate))
        SOCKET_RAISE_MSG (SocketRateLimit, SocketRateLimit_Failed,
                          "Invalid tokens_per_sec - exceeds security limits");
      limiter->tokens_per_sec = new_rate;
    }
}

/**
 * ratelimit_update_bucket_locked - Update bucket_size and cap tokens if needed
 * (caller holds lock)
 * @limiter: Rate limiter instance (locked)
 * @new_size: New bucket size (>0 to set, <=0 ignore)
 *
 * Validates and sets bucket_size if new_size > 0, caps current tokens.
 *
 * Raises: SocketRateLimit_Failed if new_size invalid
 * Thread-safe: Caller must hold mutex
 */
static void
ratelimit_update_bucket_locked (T limiter, size_t new_size)
{
  if (new_size > 0)
    {
      if (!SOCKET_SECURITY_VALID_SIZE (new_size))
        SOCKET_RAISE_MSG (SocketRateLimit, SocketRateLimit_Failed,
                          "Invalid bucket_size - exceeds security limits");
      limiter->bucket_size = new_size;
      if (limiter->tokens > new_size)
        limiter->tokens = new_size;
    }
}

/* ============================================================================
 * Public API - Configuration
 * ============================================================================
 */

/**
 * ratelimit_reset_locked - Reset bucket to full under lock
 * @limiter: Rate limiter instance (locked by caller)
 *
 * Sets tokens = bucket_size and updates last_refill_ms to now.
 *
 * Thread-safe: Caller must hold mutex
 */
static void
ratelimit_reset_locked (T limiter)
{
  limiter->tokens = limiter->bucket_size;
  limiter->last_refill_ms = Socket_get_monotonic_ms ();
}

/**
 * SocketRateLimit_reset - Reset limiter to full bucket
 * @limiter: Rate limiter instance
 *
 * Thread-safe: Yes - uses internal mutex
 *
 * Resets tokens to bucket_size and updates refill timestamp.
 * Useful after configuration changes or manual intervention.
 */
void
SocketRateLimit_reset (T limiter)
{
  assert (limiter);

  WITH_LOCK (limiter, {
    if (!RATELIMIT_IS_VALID (_l))
      SOCKET_RAISE_MSG (SocketRateLimit, SocketRateLimit_Failed,
                        "Cannot reset shutdown or uninitialized rate limiter");

    ratelimit_reset_locked (_l);
  });
}

/**
 * SocketRateLimit_configure - Reconfigure rate limiter
 * @limiter: Rate limiter instance
 * @tokens_per_sec: New token refill rate (0 to keep current)
 * @bucket_size: New bucket capacity (0 to keep current)
 *
 * Thread-safe: Yes - uses internal mutex
 *
 * Allows runtime reconfiguration. Current tokens are capped to new
 * bucket_size.
 */
void
SocketRateLimit_configure (T limiter, size_t tokens_per_sec,
                           size_t bucket_size)
{
  assert (limiter);

  WITH_LOCK (limiter, {
    if (!RATELIMIT_IS_VALID (_l))
      SOCKET_RAISE_MSG (
          SocketRateLimit, SocketRateLimit_Failed,
          "Cannot configure shutdown or uninitialized rate limiter");

    ratelimit_update_rate_locked (_l, tokens_per_sec);
    ratelimit_update_bucket_locked (_l, bucket_size);
  });
}

/**
 * SocketRateLimit_get_rate - Get current tokens per second rate
 * @limiter: Rate limiter instance
 *
 * Returns: Tokens per second rate
 * Thread-safe: Yes - uses internal mutex
 */
size_t
SocketRateLimit_get_rate (T limiter)
{
  assert (limiter);

  return ratelimit_get_rate_locked (limiter);
}

/**
 * SocketRateLimit_get_bucket_size - Get current bucket size
 * @limiter: Rate limiter instance
 *
 * Returns: Maximum bucket capacity
 * Thread-safe: Yes - uses internal mutex
 */
size_t
SocketRateLimit_get_bucket_size (T limiter)
{
  assert (limiter);

  return ratelimit_get_bucket_size_locked (limiter);
}

/**
 * SocketRateLimit_debug_live_count - Get number of live rate limiter instances
 *
 * Returns: Current number of allocated instances (for debugging and leak
 * detection) Thread-safe: Yes
 */
int
SocketRateLimit_debug_live_count (void)
{
  return SocketLiveCount_get (&ratelimit_live_tracker);
}

#undef T
