/**
 * SocketRateLimit.c - Token Bucket Rate Limiter Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements the token bucket algorithm for rate limiting:
 * - Tokens are added at a constant rate (tokens_per_sec)
 * - Bucket has a maximum capacity (bucket_size) for burst handling
 * - Operations consume tokens; insufficient tokens means rate limited
 *
 * Thread Safety:
 * - All public functions use mutex protection
 * - Internal helpers assume mutex is held by caller
 */

#include "core/SocketRateLimit-private.h"
#include "core/SocketConfig.h"
#include "core/SocketRateLimit.h"
#include "core/SocketUtil.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define T SocketRateLimit_T

/* ============================================================================
 * Exception Definitions
 * ============================================================================ */

const Except_T SocketRateLimit_Failed
    = { &SocketRateLimit_Failed, "Rate limiter operation failed" };

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
__declspec (thread) Except_T SocketRateLimit_DetailedException;
#else
__thread Except_T SocketRateLimit_DetailedException;
#endif

/* ============================================================================
 * Internal Helper Functions - Time Operations
 * ============================================================================ */

/**
 * ratelimit_get_monotonic_ms - Get monotonic timestamp in milliseconds
 *
 * Returns: Current monotonic time in milliseconds, or 0 on failure
 */
int64_t
ratelimit_get_monotonic_ms (void)
{
  struct timespec ts;

  if (clock_gettime (CLOCK_MONOTONIC, &ts) < 0)
    {
      if (clock_gettime (CLOCK_REALTIME, &ts) < 0)
        return 0;
    }

  return (int64_t)ts.tv_sec * SOCKET_MS_PER_SECOND
         + (int64_t)ts.tv_nsec / SOCKET_NS_PER_MS;
}

/* ============================================================================
 * Internal Helper Functions - Token Calculations
 * ============================================================================ */

/**
 * ratelimit_calculate_tokens_to_add - Calculate tokens from elapsed time
 */
size_t
ratelimit_calculate_tokens_to_add (int64_t elapsed_ms, size_t tokens_per_sec)
{
  /* Use 64-bit math to avoid overflow: (elapsed_ms * tokens_per_sec) / 1000 */
  return (size_t)(((uint64_t)elapsed_ms * tokens_per_sec)
                  / SOCKET_MS_PER_SECOND);
}

/**
 * ratelimit_calculate_wait_ms - Calculate wait time for needed tokens
 */
int64_t
ratelimit_calculate_wait_ms (size_t needed, size_t tokens_per_sec)
{
  int64_t wait_ms;

  /* Use 64-bit math: (needed * 1000) / tokens_per_sec */
  wait_ms
      = (int64_t)(((uint64_t)needed * SOCKET_MS_PER_SECOND) / tokens_per_sec);

  /* Ensure minimum wait time if any wait is needed */
  if (wait_ms == 0)
    wait_ms = SOCKET_RATELIMIT_MIN_WAIT_MS;

  return wait_ms;
}

/* ============================================================================
 * Internal Helper Functions - Bucket Operations
 * ============================================================================ */

/**
 * ratelimit_refill_bucket - Refill bucket based on elapsed time
 * @limiter: Rate limiter instance (caller must hold mutex)
 */
void
ratelimit_refill_bucket (T limiter)
{
  int64_t now_ms;
  int64_t elapsed_ms;
  size_t tokens_to_add;

  assert (limiter);

  now_ms = ratelimit_get_monotonic_ms ();
  elapsed_ms = now_ms - limiter->last_refill_ms;

  if (elapsed_ms <= 0)
    return; /* No time elapsed or clock went backwards */

  tokens_to_add
      = ratelimit_calculate_tokens_to_add (elapsed_ms, limiter->tokens_per_sec);

  if (tokens_to_add > 0)
    {
      limiter->tokens += tokens_to_add;
      if (limiter->tokens > limiter->bucket_size)
        limiter->tokens = limiter->bucket_size;
      limiter->last_refill_ms = now_ms;
    }
}

/* ============================================================================
 * Internal Helper Functions - Structure Initialization
 * ============================================================================ */

/**
 * ratelimit_init_structure - Initialize limiter structure fields
 */
void
ratelimit_init_structure (T limiter, size_t tokens_per_sec, size_t bucket_size,
                          Arena_T arena)
{
  assert (limiter);

  memset (limiter, 0, sizeof (*limiter));
  limiter->tokens_per_sec = tokens_per_sec;
  limiter->bucket_size = bucket_size;
  limiter->tokens = bucket_size; /* Start with full bucket */
  limiter->last_refill_ms = ratelimit_get_monotonic_ms ();
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
 * ratelimit_free_on_error - Free limiter on allocation/init error
 * @limiter: Limiter to free
 * @arena: Arena used for allocation (NULL if malloc)
 */
static void
ratelimit_free_on_error (T limiter, Arena_T arena)
{
  if (!arena && limiter)
    free (limiter);
  /* Arena-allocated memory freed when arena disposed */
}

/* ============================================================================
 * Public API Implementation - Lifecycle
 * ============================================================================ */

/**
 * SocketRateLimit_new - Create a new token bucket rate limiter
 */
T
SocketRateLimit_new (Arena_T arena, size_t tokens_per_sec, size_t bucket_size)
{
  T limiter;

  /* Validate parameters */
  if (tokens_per_sec == 0)
    {
      SOCKET_ERROR_MSG ("tokens_per_sec must be > 0");
      RAISE_RATELIMIT_ERROR (SocketRateLimit_Failed);
    }

  /* Default burst capacity to 1 second of tokens */
  if (bucket_size == 0)
    bucket_size = tokens_per_sec;

  /* Allocate structure */
  limiter = ratelimit_allocate (arena);
  if (!limiter)
    {
      SOCKET_ERROR_MSG ("Failed to allocate rate limiter");
      RAISE_RATELIMIT_ERROR (SocketRateLimit_Failed);
    }

  /* Initialize structure fields */
  ratelimit_init_structure (limiter, tokens_per_sec, bucket_size, arena);

  /* Initialize mutex */
  if (ratelimit_init_mutex (limiter) != 0)
    {
      ratelimit_free_on_error (limiter, arena);
      SOCKET_ERROR_FMT ("Failed to initialize rate limiter mutex");
      RAISE_RATELIMIT_ERROR (SocketRateLimit_Failed);
    }

  return limiter;
}

/**
 * SocketRateLimit_free - Free a rate limiter
 */
void
SocketRateLimit_free (T *limiter)
{
  T l;

  if (!limiter || !*limiter)
    return;

  l = *limiter;

  /* Destroy mutex if initialized */
  if (l->initialized == SOCKET_RATELIMIT_MUTEX_INITIALIZED)
    pthread_mutex_destroy (&l->mutex);

  /* Free memory only if allocated with malloc */
  if (!l->arena)
    free (l);

  *limiter = NULL;
}

/* ============================================================================
 * Public API Implementation - Token Operations
 * ============================================================================ */

/**
 * SocketRateLimit_try_acquire - Try to consume tokens (non-blocking)
 */
int
SocketRateLimit_try_acquire (T limiter, size_t tokens)
{
  int result = 0;

  assert (limiter);

  /* Zero tokens always succeeds */
  if (tokens == 0)
    return 1;

  pthread_mutex_lock (&limiter->mutex);

  ratelimit_refill_bucket (limiter);

  if (limiter->tokens >= tokens)
    {
      limiter->tokens -= tokens;
      result = 1;
    }

  pthread_mutex_unlock (&limiter->mutex);
  return result;
}

/**
 * SocketRateLimit_wait_time_ms - Calculate wait time for tokens
 */
int64_t
SocketRateLimit_wait_time_ms (T limiter, size_t tokens)
{
  int64_t wait_ms = 0;

  assert (limiter);

  /* Zero tokens - no wait needed */
  if (tokens == 0)
    return 0;

  pthread_mutex_lock (&limiter->mutex);

  /* Check if request is impossible */
  if (tokens > limiter->bucket_size)
    {
      pthread_mutex_unlock (&limiter->mutex);
      return SOCKET_RATELIMIT_IMPOSSIBLE_WAIT;
    }

  ratelimit_refill_bucket (limiter);

  /* Calculate wait time if insufficient tokens */
  if (limiter->tokens < tokens)
    {
      size_t needed = tokens - limiter->tokens;
      wait_ms = ratelimit_calculate_wait_ms (needed, limiter->tokens_per_sec);
    }

  pthread_mutex_unlock (&limiter->mutex);
  return wait_ms;
}

/**
 * SocketRateLimit_available - Get current available tokens
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
 * Public API Implementation - Configuration
 * ============================================================================ */

/**
 * SocketRateLimit_reset - Reset limiter to full bucket
 */
void
SocketRateLimit_reset (T limiter)
{
  assert (limiter);

  pthread_mutex_lock (&limiter->mutex);
  limiter->tokens = limiter->bucket_size;
  limiter->last_refill_ms = ratelimit_get_monotonic_ms ();
  pthread_mutex_unlock (&limiter->mutex);
}

/**
 * SocketRateLimit_configure - Reconfigure rate limiter
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
      /* Cap current tokens to new bucket size */
      if (limiter->tokens > bucket_size)
        limiter->tokens = bucket_size;
    }

  pthread_mutex_unlock (&limiter->mutex);
}

/**
 * SocketRateLimit_get_rate - Get current tokens per second rate
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
