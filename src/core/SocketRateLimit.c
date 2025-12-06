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

#include "core/SocketRateLimit-private.h"
#include "core/SocketConfig.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define T SocketRateLimit_T

/* ============================================================================
 * Exception Definitions
 * ============================================================================ */

const Except_T SocketRateLimit_Failed
    = { &SocketRateLimit_Failed, "Rate limiter operation failed" };

/* Thread-local exception using centralized macro */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketRateLimit);

/* ============================================================================
 * Pure Helper Functions (No Mutex Required, No Side Effects)
 * ============================================================================ */

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

  return (size_t)(((uint64_t)elapsed_ms * tokens_per_sec)
                  / SOCKET_MS_PER_SECOND);
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
  int64_t wait_ms;

  assert (tokens_per_sec > 0);

  wait_ms
      = (int64_t)(((uint64_t)needed * SOCKET_MS_PER_SECOND) / tokens_per_sec);

  return (wait_ms > 0) ? wait_ms : SOCKET_RATELIMIT_MIN_WAIT_MS;
}

/* ============================================================================
 * Bucket Operations (Caller Must Hold Mutex)
 * ============================================================================ */

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
 * ratelimit_add_tokens - Add calculated tokens to bucket
 * @limiter: Rate limiter instance
 * @tokens_to_add: Number of tokens to add
 * @now_ms: Current timestamp to record
 */
static void
ratelimit_add_tokens (T limiter, size_t tokens_to_add, int64_t now_ms)
{
  assert (limiter);

  limiter->tokens += tokens_to_add;

  if (limiter->tokens > limiter->bucket_size)
    limiter->tokens = limiter->bucket_size;

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

  tokens_to_add
      = ratelimit_calculate_tokens_to_add (elapsed_ms, limiter->tokens_per_sec);

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
 * Lifecycle Helpers
 * ============================================================================ */

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
    return Arena_alloc (arena, sizeof (struct T), __FILE__, __LINE__);
  return malloc (sizeof (struct T));
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

  memset (limiter, 0, sizeof (*limiter));
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
 * Returns: 0 on success, -1 on failure
 */
static int
ratelimit_init_mutex (T limiter)
{
  assert (limiter);

  if (pthread_mutex_init (&limiter->mutex, NULL) != 0)
    return -1;

  limiter->initialized = SOCKET_RATELIMIT_MUTEX_INITIALIZED;
  return 0;
}

/* ============================================================================
 * Public API - Lifecycle
 * ============================================================================ */

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

  /* Validate tokens_per_sec */
  if (tokens_per_sec == 0)
    SOCKET_RAISE_MSG (SocketRateLimit, SocketRateLimit_Failed,
                      "tokens_per_sec must be > 0");

  /* Normalize bucket_size: 0 means use tokens_per_sec */
  if (bucket_size == 0)
    bucket_size = tokens_per_sec;

  /* Allocate structure */
  limiter = ratelimit_allocate (arena);
  if (!limiter)
    SOCKET_RAISE_MSG (SocketRateLimit, SocketRateLimit_Failed,
                      "Failed to allocate rate limiter");

  /* Initialize fields */
  ratelimit_init_fields (limiter, tokens_per_sec, bucket_size, arena);

  /* Initialize mutex */
  if (ratelimit_init_mutex (limiter) != 0)
    {
      if (!arena)
        free (limiter);
      SOCKET_RAISE_FMT (SocketRateLimit, SocketRateLimit_Failed,
                        "Failed to initialize rate limiter mutex");
    }

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
    pthread_mutex_destroy (&l->mutex);

  if (!l->arena)
    free (l);

  *limiter = NULL;
}

/* ============================================================================
 * Public API - Token Acquisition
 * ============================================================================ */

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
  int result;

  assert (limiter);

  if (tokens == 0)
    return 1;

  pthread_mutex_lock (&limiter->mutex);
  ratelimit_refill_bucket (limiter);
  result = ratelimit_try_consume (limiter, tokens);
  pthread_mutex_unlock (&limiter->mutex);

  return result;
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
  int64_t wait_ms;

  assert (limiter);

  if (tokens == 0)
    return 0;

  pthread_mutex_lock (&limiter->mutex);

  /* Check if request is impossible (exceeds bucket size) */
  if (tokens > limiter->bucket_size)
    {
      pthread_mutex_unlock (&limiter->mutex);
      return SOCKET_RATELIMIT_IMPOSSIBLE_WAIT;
    }

  ratelimit_refill_bucket (limiter);
  wait_ms = ratelimit_compute_wait_time (limiter, tokens);

  pthread_mutex_unlock (&limiter->mutex);
  return wait_ms;
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
  size_t available;

  assert (limiter);

  pthread_mutex_lock (&limiter->mutex);
  ratelimit_refill_bucket (limiter);
  available = limiter->tokens;
  pthread_mutex_unlock (&limiter->mutex);

  return available;
}

/* ============================================================================
 * Public API - Configuration
 * ============================================================================ */

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

  pthread_mutex_lock (&limiter->mutex);
  limiter->tokens = limiter->bucket_size;
  limiter->last_refill_ms = Socket_get_monotonic_ms ();
  pthread_mutex_unlock (&limiter->mutex);
}

/**
 * SocketRateLimit_configure - Reconfigure rate limiter
 * @limiter: Rate limiter instance
 * @tokens_per_sec: New token refill rate (0 to keep current)
 * @bucket_size: New bucket capacity (0 to keep current)
 *
 * Thread-safe: Yes - uses internal mutex
 *
 * Allows runtime reconfiguration. Current tokens are capped to new bucket_size.
 */
void
SocketRateLimit_configure (T limiter, size_t tokens_per_sec, size_t bucket_size)
{
  assert (limiter);

  pthread_mutex_lock (&limiter->mutex);

  if (tokens_per_sec > 0)
    limiter->tokens_per_sec = tokens_per_sec;

  if (bucket_size > 0)
    {
      limiter->bucket_size = bucket_size;
      if (limiter->tokens > bucket_size)
        limiter->tokens = bucket_size;
    }

  pthread_mutex_unlock (&limiter->mutex);
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
  size_t rate;

  assert (limiter);

  pthread_mutex_lock (&limiter->mutex);
  rate = limiter->tokens_per_sec;
  pthread_mutex_unlock (&limiter->mutex);

  return rate;
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
  size_t size;

  assert (limiter);

  pthread_mutex_lock (&limiter->mutex);
  size = limiter->bucket_size;
  pthread_mutex_unlock (&limiter->mutex);

  return size;
}

#undef T
