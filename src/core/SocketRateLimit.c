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
#include "core/SocketRateLimit.h"
#include "core/SocketUtil.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * Exception Definitions
 * ============================================================================ */

const Except_T SocketRateLimit_Failed = { &SocketRateLimit_Failed, "Rate limiter operation failed" };

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
__declspec (thread) Except_T SocketRateLimit_DetailedException;
#else
__thread Except_T SocketRateLimit_DetailedException;
#endif

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * ratelimit_get_monotonic_ms - Get monotonic timestamp in milliseconds
 *
 * Returns: Current monotonic time in milliseconds
 */
int64_t
ratelimit_get_monotonic_ms (void)
{
  struct timespec ts;

  if (clock_gettime (CLOCK_MONOTONIC, &ts) < 0)
    {
      /* Fallback to realtime if monotonic unavailable */
      if (clock_gettime (CLOCK_REALTIME, &ts) < 0)
        {
          return 0;
        }
    }

  return (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / 1000000;
}

/**
 * ratelimit_refill_bucket - Refill bucket based on elapsed time
 * @limiter: Rate limiter instance (caller must hold mutex)
 *
 * Calculates tokens to add based on elapsed time since last refill.
 * Caps tokens at bucket_size to enforce burst limit.
 */
void
ratelimit_refill_bucket (SocketRateLimit_T limiter)
{
  int64_t now_ms;
  int64_t elapsed_ms;
  size_t tokens_to_add;

  assert (limiter);

  now_ms = ratelimit_get_monotonic_ms ();
  elapsed_ms = now_ms - limiter->last_refill_ms;

  if (elapsed_ms <= 0)
    {
      return; /* No time elapsed or clock went backwards */
    }

  /* Calculate tokens to add: (elapsed_ms * tokens_per_sec) / 1000 */
  /* Use 64-bit math to avoid overflow */
  tokens_to_add
      = (size_t)(((uint64_t)elapsed_ms * limiter->tokens_per_sec) / 1000);

  if (tokens_to_add > 0)
    {
      /* Add tokens, cap at bucket size */
      limiter->tokens += tokens_to_add;
      if (limiter->tokens > limiter->bucket_size)
        {
          limiter->tokens = limiter->bucket_size;
        }
      limiter->last_refill_ms = now_ms;
    }
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

/**
 * SocketRateLimit_new - Create a new token bucket rate limiter
 */
SocketRateLimit_T
SocketRateLimit_new (Arena_T arena, size_t tokens_per_sec, size_t bucket_size)
{
  SocketRateLimit_T limiter;

  /* Validate parameters */
  if (tokens_per_sec == 0)
    {
      SOCKET_ERROR_MSG ("tokens_per_sec must be > 0");
      RAISE_RATELIMIT_ERROR (SocketRateLimit_Failed);
    }

  if (bucket_size == 0)
    {
      bucket_size = tokens_per_sec; /* Default burst = 1 second of tokens */
    }

  /* Allocate structure */
  if (arena)
    {
      limiter = Arena_alloc (arena, sizeof (*limiter), __FILE__, __LINE__);
    }
  else
    {
      limiter = malloc (sizeof (*limiter));
    }

  if (!limiter)
    {
      SOCKET_ERROR_MSG ("Failed to allocate rate limiter");
      RAISE_RATELIMIT_ERROR (SocketRateLimit_Failed);
    }

  /* Initialize structure */
  memset (limiter, 0, sizeof (*limiter));
  limiter->tokens_per_sec = tokens_per_sec;
  limiter->bucket_size = bucket_size;
  limiter->tokens = bucket_size; /* Start with full bucket */
  limiter->last_refill_ms = ratelimit_get_monotonic_ms ();
  limiter->arena = arena;
  limiter->initialized = 0;

  /* Initialize mutex */
  if (pthread_mutex_init (&limiter->mutex, NULL) != 0)
    {
      if (!arena)
        {
          free (limiter);
        }
      SOCKET_ERROR_FMT ("Failed to initialize rate limiter mutex");
      RAISE_RATELIMIT_ERROR (SocketRateLimit_Failed);
    }

  limiter->initialized = 1;
  return limiter;
}

/**
 * SocketRateLimit_free - Free a rate limiter
 */
void
SocketRateLimit_free (SocketRateLimit_T *limiter)
{
  SocketRateLimit_T l;

  if (!limiter || !*limiter)
    {
      return;
    }

  l = *limiter;

  /* Destroy mutex */
  if (l->initialized)
    {
      pthread_mutex_destroy (&l->mutex);
    }

  /* Free memory only if allocated with malloc */
  if (!l->arena)
    {
      free (l);
    }

  *limiter = NULL;
}

/**
 * SocketRateLimit_try_acquire - Try to consume tokens (non-blocking)
 */
int
SocketRateLimit_try_acquire (SocketRateLimit_T limiter, size_t tokens)
{
  int result = 0;

  assert (limiter);

  if (tokens == 0)
    {
      return 1; /* Zero tokens always succeeds */
    }

  pthread_mutex_lock (&limiter->mutex);

  /* Refill bucket based on elapsed time */
  ratelimit_refill_bucket (limiter);

  /* Check if we have enough tokens */
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
SocketRateLimit_wait_time_ms (SocketRateLimit_T limiter, size_t tokens)
{
  int64_t wait_ms = 0;
  size_t needed;

  assert (limiter);

  if (tokens == 0)
    {
      return 0;
    }

  pthread_mutex_lock (&limiter->mutex);

  /* Check if request is impossible */
  if (tokens > limiter->bucket_size)
    {
      pthread_mutex_unlock (&limiter->mutex);
      return -1; /* Impossible to acquire */
    }

  /* Refill bucket based on elapsed time */
  ratelimit_refill_bucket (limiter);

  /* Calculate wait time if insufficient tokens */
  if (limiter->tokens < tokens)
    {
      needed = tokens - limiter->tokens;
      /* wait_ms = (needed * 1000) / tokens_per_sec */
      /* Use 64-bit math to avoid overflow */
      wait_ms = (int64_t)(((uint64_t)needed * 1000) / limiter->tokens_per_sec);
      if (wait_ms == 0)
        {
          wait_ms = 1; /* Minimum 1ms if any wait needed */
        }
    }

  pthread_mutex_unlock (&limiter->mutex);
  return wait_ms;
}

/**
 * SocketRateLimit_available - Get current available tokens
 */
size_t
SocketRateLimit_available (SocketRateLimit_T limiter)
{
  size_t available;

  assert (limiter);

  pthread_mutex_lock (&limiter->mutex);

  /* Refill bucket first */
  ratelimit_refill_bucket (limiter);
  available = limiter->tokens;

  pthread_mutex_unlock (&limiter->mutex);
  return available;
}

/**
 * SocketRateLimit_reset - Reset limiter to full bucket
 */
void
SocketRateLimit_reset (SocketRateLimit_T limiter)
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
SocketRateLimit_configure (SocketRateLimit_T limiter, size_t tokens_per_sec,
                           size_t bucket_size)
{
  assert (limiter);

  pthread_mutex_lock (&limiter->mutex);

  if (tokens_per_sec > 0)
    {
      limiter->tokens_per_sec = tokens_per_sec;
    }

  if (bucket_size > 0)
    {
      limiter->bucket_size = bucket_size;
      /* Cap current tokens to new bucket size */
      if (limiter->tokens > bucket_size)
        {
          limiter->tokens = bucket_size;
        }
    }

  pthread_mutex_unlock (&limiter->mutex);
}

/**
 * SocketRateLimit_get_rate - Get current tokens per second rate
 */
size_t
SocketRateLimit_get_rate (SocketRateLimit_T limiter)
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
SocketRateLimit_get_bucket_size (SocketRateLimit_T limiter)
{
  size_t size;

  assert (limiter);

  pthread_mutex_lock (&limiter->mutex);
  size = limiter->bucket_size;
  pthread_mutex_unlock (&limiter->mutex);

  return size;
}

