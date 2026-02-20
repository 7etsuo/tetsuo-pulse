/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-ratelimit.c
 * @brief Simple token bucket rate limiter implementation.
 */

#include "SocketSimple-internal.h"
#include "simple/SocketSimple-ratelimit.h"

#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define NANOSECONDS_PER_SECOND 1000000000ULL
#define NANOSECONDS_PER_MILLISECOND 1000000ULL

struct SocketSimple_RateLimit
{
  pthread_mutex_t mutex;
  int tokens_per_sec;
  int bucket_size;
  double tokens;
  uint64_t last_refill_ns;

  /* Statistics */
  uint64_t total_acquired;
  uint64_t total_rejected;
  uint64_t total_waited_ms;
};

static uint64_t
get_monotonic_ns (void)
{
  struct timespec ts;
  if (clock_gettime (CLOCK_MONOTONIC, &ts) != 0)
    {
      /* CLOCK_MONOTONIC should never fail on properly configured systems,
         but handle it defensively to avoid using uninitialized values.
         Returning 0 is safe for rate limiting - it will just cause
         a single-time delay calculation issue which will self-correct. */
      return 0;
    }
  return (uint64_t)ts.tv_sec * NANOSECONDS_PER_SECOND + (uint64_t)ts.tv_nsec;
}

/**
 * @brief Get random jitter to add unpredictability to refill timing.
 *
 * Uses /dev/urandom for cryptographically secure randomness.
 * Returns 0 on failure (fail-safe: no jitter is still secure).
 *
 * @return Random jitter in nanoseconds (0 to ~1ms range)
 */
static uint64_t
get_random_jitter_ns (void)
{
  uint32_t rand_val = 0;
  FILE *f = fopen ("/dev/urandom", "rb");
  if (f)
    {
      size_t read_count = fread (&rand_val, sizeof (rand_val), 1, f);
      fclose (f);
      if (read_count != 1)
        return 0;
    }
  /* Return jitter in 0-1ms range to prevent timing attacks */
  return (uint64_t)(rand_val % NANOSECONDS_PER_MILLISECOND);
}

static void
refill_tokens (SocketSimple_RateLimit_T limit)
{
  uint64_t now = get_monotonic_ns ();
  uint64_t elapsed_ns = now - limit->last_refill_ns;

  if (elapsed_ns > 0)
    {
      /*
       * Use fixed-point arithmetic to avoid floating-point precision issues.
       * Calculate: new_tokens = elapsed_ns * tokens_per_sec /
       * NANOSECONDS_PER_SECOND To prevent overflow with large elapsed times,
       * cap elapsed_ns.
       */
      uint64_t max_elapsed
          = NANOSECONDS_PER_SECOND * 60; /* Cap at 60 seconds */
      if (elapsed_ns > max_elapsed)
        elapsed_ns = max_elapsed;

      /* Fixed-point calculation: (elapsed_ns * tokens_per_sec) / 1e9 */
      uint64_t new_tokens_fixed = (elapsed_ns * (uint64_t)limit->tokens_per_sec)
                                  / NANOSECONDS_PER_SECOND;

      limit->tokens += (double)new_tokens_fixed;
      if (limit->tokens > limit->bucket_size)
        {
          limit->tokens = limit->bucket_size;
        }

      /*
       * Add random jitter to refill timing to prevent timing attacks.
       * This makes it harder for attackers to predict exact refill moments.
       */
      uint64_t jitter = get_random_jitter_ns ();
      limit->last_refill_ns = now + jitter;
    }
}

SocketSimple_RateLimit_T
Socket_simple_ratelimit_new (int tokens_per_sec, int burst)
{
  Socket_simple_clear_error ();

  if (tokens_per_sec <= 0 || burst <= 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "tokens_per_sec and burst must be positive");
      return NULL;
    }

  struct SocketSimple_RateLimit *limit = calloc (1, sizeof (*limit));
  if (!limit)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      return NULL;
    }

  if (pthread_mutex_init (&limit->mutex, NULL) != 0)
    {
      free (limit);
      simple_set_error_errno (SOCKET_SIMPLE_ERR_MEMORY,
                              "Failed to initialize mutex");
      return NULL;
    }

  limit->tokens_per_sec = tokens_per_sec;
  limit->bucket_size = burst;
  limit->tokens = burst; /* Start full */
  limit->last_refill_ns = get_monotonic_ns ();
  limit->total_acquired = 0;
  limit->total_rejected = 0;
  limit->total_waited_ms = 0;

  return limit;
}

void
Socket_simple_ratelimit_free (SocketSimple_RateLimit_T *limit)
{
  if (!limit || !*limit)
    return;

  pthread_mutex_destroy (&(*limit)->mutex);
  free (*limit);
  *limit = NULL;
}

int
Socket_simple_ratelimit_try_acquire (SocketSimple_RateLimit_T limit, int tokens)
{
  if (!limit || tokens <= 0)
    return 0;

  pthread_mutex_lock (&limit->mutex);
  refill_tokens (limit);

  int acquired = 0;
  if (limit->tokens >= tokens)
    {
      limit->tokens -= tokens;
      limit->total_acquired += tokens;
      acquired = 1;
    }
  else
    {
      limit->total_rejected += tokens;
    }

  pthread_mutex_unlock (&limit->mutex);
  return acquired;
}

int
Socket_simple_ratelimit_wait_ms (SocketSimple_RateLimit_T limit, int tokens)
{
  if (!limit)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid rate limiter");
      return -1;
    }

  if (tokens <= 0)
    return 0;

  pthread_mutex_lock (&limit->mutex);
  refill_tokens (limit);

  int wait_ms = 0;
  if (limit->tokens < tokens)
    {
      double needed = tokens - limit->tokens;
      double seconds = needed / limit->tokens_per_sec;
      wait_ms = (int)ceil (seconds * 1000.0);
    }

  pthread_mutex_unlock (&limit->mutex);
  return wait_ms;
}

int
Socket_simple_ratelimit_acquire (SocketSimple_RateLimit_T limit, int tokens)
{
  if (!limit)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid rate limiter");
      return -1;
    }

  if (tokens <= 0)
    return 0;

  /* Prevent infinite loop: tokens must not exceed bucket size */
  if (tokens > limit->bucket_size)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Requested tokens exceeds bucket size");
      return -1;
    }

  while (!Socket_simple_ratelimit_try_acquire (limit, tokens))
    {
      int wait_ms = Socket_simple_ratelimit_wait_ms (limit, tokens);
      if (wait_ms > 0)
        {
          struct timespec ts;
          ts.tv_sec = wait_ms / 1000;
          ts.tv_nsec = (wait_ms % 1000) * NANOSECONDS_PER_MILLISECOND;
          nanosleep (&ts, NULL);
          pthread_mutex_lock (&limit->mutex);
          limit->total_waited_ms += wait_ms;
          pthread_mutex_unlock (&limit->mutex);
        }
    }

  return 0;
}

int
Socket_simple_ratelimit_acquire_timeout (SocketSimple_RateLimit_T limit,
                                         int tokens,
                                         int timeout_ms)
{
  if (!limit)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid rate limiter");
      return -1;
    }

  if (tokens <= 0)
    return 1;

  /* Validate tokens against bucket size to prevent long/infinite wait */
  if (tokens > limit->bucket_size)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Requested tokens exceeds bucket size");
      return -1;
    }

  uint64_t start = get_monotonic_ns ();
  uint64_t deadline
      = start + (uint64_t)timeout_ms * NANOSECONDS_PER_MILLISECOND;

  while (!Socket_simple_ratelimit_try_acquire (limit, tokens))
    {
      uint64_t now = get_monotonic_ns ();
      if (now >= deadline)
        {
          return 0; /* Timeout */
        }

      int wait_ms = Socket_simple_ratelimit_wait_ms (limit, tokens);
      int64_t remaining = (deadline - now) / NANOSECONDS_PER_MILLISECOND;
      /* Clamp to INT_MAX to prevent truncation */
      if (remaining > INT_MAX)
        {
          remaining = INT_MAX;
        }
      if (wait_ms > remaining)
        {
          wait_ms = (int)remaining;
        }

      if (wait_ms > 0)
        {
          struct timespec ts;
          ts.tv_sec = wait_ms / 1000;
          ts.tv_nsec = (wait_ms % 1000) * NANOSECONDS_PER_MILLISECOND;
          nanosleep (&ts, NULL);
          pthread_mutex_lock (&limit->mutex);
          limit->total_waited_ms += wait_ms;
          pthread_mutex_unlock (&limit->mutex);
        }
    }

  return 1;
}

int
Socket_simple_ratelimit_available (SocketSimple_RateLimit_T limit)
{
  if (!limit)
    return 0;

  pthread_mutex_lock (&limit->mutex);
  refill_tokens (limit);
  int available = (int)limit->tokens;
  pthread_mutex_unlock (&limit->mutex);

  return available;
}

int
Socket_simple_ratelimit_reset (SocketSimple_RateLimit_T limit)
{
  if (!limit)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid rate limiter");
      return -1;
    }

  pthread_mutex_lock (&limit->mutex);
  limit->tokens = limit->bucket_size;
  limit->last_refill_ns = get_monotonic_ns ();
  pthread_mutex_unlock (&limit->mutex);

  return 0;
}

int
Socket_simple_ratelimit_set_rate (SocketSimple_RateLimit_T limit,
                                  int tokens_per_sec,
                                  int burst)
{
  if (!limit)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid rate limiter");
      return -1;
    }

  if (tokens_per_sec <= 0 || burst <= 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "tokens_per_sec and burst must be positive");
      return -1;
    }

  pthread_mutex_lock (&limit->mutex);
  limit->tokens_per_sec = tokens_per_sec;
  limit->bucket_size = burst;
  if (limit->tokens > burst)
    {
      limit->tokens = burst;
    }
  pthread_mutex_unlock (&limit->mutex);

  return 0;
}

int
Socket_simple_ratelimit_get_stats (SocketSimple_RateLimit_T limit,
                                   SocketSimple_RateLimitStats *stats)
{
  if (!limit || !stats)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid rate limiter or stats");
      return -1;
    }

  pthread_mutex_lock (&limit->mutex);
  stats->total_acquired = limit->total_acquired;
  stats->total_rejected = limit->total_rejected;
  stats->total_waited_ms = limit->total_waited_ms;
  pthread_mutex_unlock (&limit->mutex);

  return 0;
}

int
Socket_simple_ratelimit_reset_stats (SocketSimple_RateLimit_T limit)
{
  if (!limit)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid rate limiter");
      return -1;
    }

  pthread_mutex_lock (&limit->mutex);
  limit->total_acquired = 0;
  limit->total_rejected = 0;
  limit->total_waited_ms = 0;
  pthread_mutex_unlock (&limit->mutex);

  return 0;
}
