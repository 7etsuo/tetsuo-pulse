/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
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

#define WITH_LOCK(limiter, code)                                      \
  do                                                                  \
    {                                                                 \
      T _l = (T)(limiter);                                            \
      SOCKET_WITH_MUTEX (                                             \
          &_l->mutex, SocketRateLimit, SocketRateLimit_Failed, code); \
    }                                                                 \
  while (0)

#define RATELIMIT_IS_VALID(_l) ((_l)->initialized == SOCKET_MUTEX_INITIALIZED)

static struct SocketLiveCount ratelimit_live_tracker
    = SOCKETLIVECOUNT_STATIC_INIT;

#define ratelimit_live_inc() SocketLiveCount_increment (&ratelimit_live_tracker)
#define ratelimit_live_dec() SocketLiveCount_decrement (&ratelimit_live_tracker)

const Except_T SocketRateLimit_Failed
    = { &SocketRateLimit_Failed, "Rate limiter operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketRateLimit);

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

static int64_t
ratelimit_calculate_wait_ms (size_t needed, size_t tokens_per_sec)
{
  assert (tokens_per_sec > 0);

  size_t ms_per_token = SOCKET_MS_PER_SECOND / tokens_per_sec;
  if (ms_per_token == 0) /* tokens_per_sec too large */
    return SOCKET_RATELIMIT_IMPOSSIBLE_WAIT;

  size_t safe_wait_ms;
  if (!SocketSecurity_check_multiply (needed, ms_per_token, &safe_wait_ms))
    return INT64_MAX; /* Overflow: treat as very long wait */

  int64_t wait_ms = (int64_t)safe_wait_ms;
  return wait_ms; /* Guaranteed > 0 and no overflow */
}

/* Calculate elapsed time since last refill, clamped to prevent clock jump
 * attacks */
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

/* Add tokens to bucket with overflow protection (caller must hold mutex) */
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

static T
ratelimit_allocate (Arena_T arena)
{
  if (arena)
    return CALLOC (arena, 1, sizeof (struct T));
  return calloc (1, sizeof (struct T));
}

static void
ratelimit_init_fields (T limiter,
                       size_t tokens_per_sec,
                       size_t bucket_size,
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
  limiter->initialized = SOCKET_MUTEX_UNINITIALIZED;
}

static void
ratelimit_init_mutex (T limiter)
{
  assert (limiter);
  SOCKET_MUTEX_ARENA_INIT (limiter, SocketRateLimit, SocketRateLimit_Failed);
}

static void
ratelimit_validate_params (size_t tokens_per_sec, size_t *bucket_size)
{
  if (tokens_per_sec == 0)
    SOCKET_RAISE_MSG (
        SocketRateLimit, SocketRateLimit_Failed, "tokens_per_sec must be > 0");

  if (*bucket_size == 0)
    *bucket_size = tokens_per_sec;

  if (!SocketSecurity_check_size (tokens_per_sec)
      || !SocketSecurity_check_size (*bucket_size))
    SOCKET_RAISE_MSG (SocketRateLimit,
                      SocketRateLimit_Failed,
                      "Rate limiter parameters exceed security limits");
}

T
SocketRateLimit_new (Arena_T arena, size_t tokens_per_sec, size_t bucket_size)
{
  T limiter;
  size_t normalized_bucket = bucket_size;

  ratelimit_validate_params (tokens_per_sec, &normalized_bucket);

  limiter = ratelimit_allocate (arena);
  if (!limiter)
    SOCKET_RAISE_MSG (SocketRateLimit,
                      SocketRateLimit_Failed,
                      "Failed to allocate rate limiter");

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

void
SocketRateLimit_free (T *limiter)
{
  T l;

  if (!limiter || !*limiter)
    return;

  l = *limiter;

  if (l->initialized == SOCKET_MUTEX_INITIALIZED)
    {
      /* Set shutdown flag while holding lock to synchronize and prevent new
       * operations */
      WITH_LOCK (l, l->initialized = SOCKET_MUTEX_SHUTDOWN;);

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

int
SocketRateLimit_try_acquire (T limiter, size_t tokens)
{
  assert (limiter);

  if (tokens == 0)
    return 1;

  return ratelimit_try_consume_with_refill (limiter, tokens);
}

int64_t
SocketRateLimit_wait_time_ms (T limiter, size_t tokens)
{
  assert (limiter);

  if (tokens == 0)
    return 0;

  return ratelimit_wait_time_with_refill (limiter, tokens);
}

size_t
SocketRateLimit_available (T limiter)
{
  assert (limiter);

  return ratelimit_available_with_refill (limiter);
}

static void
ratelimit_update_rate_locked (T limiter, size_t new_rate)
{
  if (new_rate > 0)
    {
      if (!SocketSecurity_check_size (new_rate))
        SOCKET_RAISE_MSG (SocketRateLimit,
                          SocketRateLimit_Failed,
                          "Invalid tokens_per_sec - exceeds security limits");
      limiter->tokens_per_sec = new_rate;
    }
}

static void
ratelimit_update_bucket_locked (T limiter, size_t new_size)
{
  if (new_size > 0)
    {
      if (!SocketSecurity_check_size (new_size))
        SOCKET_RAISE_MSG (SocketRateLimit,
                          SocketRateLimit_Failed,
                          "Invalid bucket_size - exceeds security limits");
      limiter->bucket_size = new_size;
      if (limiter->tokens > new_size)
        limiter->tokens = new_size;
    }
}

static void
ratelimit_reset_locked (T limiter)
{
  limiter->tokens = limiter->bucket_size;
  limiter->last_refill_ms = Socket_get_monotonic_ms ();
}

void
SocketRateLimit_reset (T limiter)
{
  assert (limiter);

  WITH_LOCK (limiter, {
    if (!RATELIMIT_IS_VALID (_l))
      SOCKET_RAISE_MSG (SocketRateLimit,
                        SocketRateLimit_Failed,
                        "Cannot reset shutdown or uninitialized rate limiter");

    ratelimit_reset_locked (_l);
  });
}

void
SocketRateLimit_configure (T limiter, size_t tokens_per_sec, size_t bucket_size)
{
  assert (limiter);

  WITH_LOCK (limiter, {
    if (!RATELIMIT_IS_VALID (_l))
      SOCKET_RAISE_MSG (
          SocketRateLimit,
          SocketRateLimit_Failed,
          "Cannot configure shutdown or uninitialized rate limiter");

    ratelimit_update_rate_locked (_l, tokens_per_sec);
    ratelimit_update_bucket_locked (_l, bucket_size);
  });
}

size_t
SocketRateLimit_get_rate (T limiter)
{
  assert (limiter);

  return ratelimit_get_rate_locked (limiter);
}

size_t
SocketRateLimit_get_bucket_size (T limiter)
{
  assert (limiter);

  return ratelimit_get_bucket_size_locked (limiter);
}

int
SocketRateLimit_debug_live_count (void)
{
  return SocketLiveCount_get (&ratelimit_live_tracker);
}

#undef T
