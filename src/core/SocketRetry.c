/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* Generic retry framework with exponential backoff and jitter */

#include <assert.h>
#include <errno.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/Except.h"
#include "core/SocketCrypto.h"
#include "core/SocketRetry.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"


#define RETRY_MIN_DELAY_MS 1.0
#define SOCKET_RETRY_MAX_MULTIPLIER 16.0
#define SOCKET_RETRY_MAX_DELAY_VALUE_MS 3600000
#define RETRY_MAX_EXPONENT 1000 /* Prevent CPU DoS from excessive loops */
#define MILLISECONDS_PER_SECOND 1000
#define NANOSECONDS_PER_MILLISECOND 1000000L
#define UINT32_MAX_DOUBLE ((double)0xFFFFFFFFU)

#define T SocketRetry_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "Retry"

const Except_T SocketRetry_Failed
    = { &SocketRetry_Failed, "Retry operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketRetry);


struct T
{
  SocketRetry_Policy policy;
  SocketRetry_Stats stats;
  unsigned int random_state; /* xorshift32 PRNG state */
};


static int
try_crypto_random (unsigned int *out)
{
  if (!SocketSecurity_has_tls ())
    return 0;

  return SocketCrypto_random_bytes (out, sizeof (*out)) == 0;
}

/* Crypto random with xorshift32 fallback */
static double
retry_random_double (unsigned int *state)
{
  unsigned int value;

  if (try_crypto_random (&value))
    return (double)value / UINT32_MAX_DOUBLE;

  /* Fallback: xorshift32 PRNG */
  if (*state == 0)
    {
      unsigned int temp = 0;
      if (try_crypto_random (&temp))
        *state = temp;
      else
        *state = (unsigned int)Socket_get_monotonic_ms ();
    }

  *state ^= *state << 13;
  *state ^= *state >> 17;
  *state ^= *state << 5;

  return (double)*state / UINT32_MAX_DOUBLE;
}


void
SocketRetry_policy_defaults (SocketRetry_Policy *policy)
{
  assert (policy != NULL);

  policy->max_attempts = SOCKET_RETRY_DEFAULT_MAX_ATTEMPTS;
  policy->initial_delay_ms = SOCKET_RETRY_DEFAULT_INITIAL_DELAY_MS;
  policy->max_delay_ms = SOCKET_RETRY_DEFAULT_MAX_DELAY_MS;
  policy->multiplier = SOCKET_RETRY_DEFAULT_MULTIPLIER;
  policy->jitter = SOCKET_RETRY_DEFAULT_JITTER;
}

static int
validate_policy (const SocketRetry_Policy *policy)
{
  if (policy == NULL)
    return 0;

  /* Check for NaN/Inf in floating point fields */
  if (isnan (policy->multiplier) || isinf (policy->multiplier)
      || isnan (policy->jitter) || isinf (policy->jitter))
    return 0;

  if (policy->max_attempts < 1
      || policy->max_attempts > SOCKET_RETRY_MAX_ATTEMPTS)
    return 0;

  if (policy->initial_delay_ms < 1
      || policy->initial_delay_ms > SOCKET_RETRY_MAX_DELAY_VALUE_MS)
    return 0;

  if (policy->max_delay_ms < policy->initial_delay_ms
      || policy->max_delay_ms > SOCKET_RETRY_MAX_DELAY_VALUE_MS)
    return 0;

  if (policy->multiplier < 1.0
      || policy->multiplier > SOCKET_RETRY_MAX_MULTIPLIER)
    return 0;

  if (policy->jitter < 0.0 || policy->jitter > 1.0)
    return 0;

  return 1;
}


/* Compute base^exp iteratively to avoid pow() overhead */
static double
power_double (double base, int exp)
{
  double result = 1.0;

  if (exp <= 0)
    return 1.0;
  if (base == 0.0)
    return 0.0;

  /* Cap exponent to prevent CPU DoS from excessive loop iterations */
  if (exp > RETRY_MAX_EXPONENT)
    {
      if (base > 1.0)
        return INFINITY;
      if (base < 1.0)
        return 0.0;
      return 1.0;
    }

  for (int i = 0; i < exp; ++i)
    {
      if (isinf (result) || result > DBL_MAX / base)
        {
          result = INFINITY;
          break;
        }
      result *= base;
    }

  return result;
}

static double
exponential_backoff (const SocketRetry_Policy *policy, int attempt)
{
  double base_delay;
  double multiplier_pow;

  if (attempt < 1)
    return 0.0;

  multiplier_pow = power_double (policy->multiplier, attempt - 1);
  base_delay = (double)policy->initial_delay_ms * multiplier_pow;

  if (isinf (base_delay) || isnan (base_delay))
    base_delay = (double)policy->max_delay_ms;

  if (base_delay > (double)policy->max_delay_ms)
    base_delay = (double)policy->max_delay_ms;

  return base_delay;
}

static double
apply_jitter_to_delay (double base_delay, const SocketRetry_Policy *policy,
                       unsigned int *random_state)
{
  double jittered_delay = base_delay;

  /* Add jitter: delay * (1 + jitter * (2*random - 1)) */
  if (policy->jitter > 0.0)
    {
      double jitter_range = base_delay * policy->jitter;
      double r = retry_random_double (random_state);
      double jitter_offset = jitter_range * (2.0 * r - 1.0);
      jittered_delay += jitter_offset;
    }

  if (isinf (jittered_delay) || isnan (jittered_delay) || jittered_delay < 0.0)
    jittered_delay = (double)policy->max_delay_ms;

  return jittered_delay;
}

static double
clamp_final_delay (double delay)
{
  if (delay < RETRY_MIN_DELAY_MS)
    delay = RETRY_MIN_DELAY_MS;

  if (delay > INT_MAX)
    delay = INT_MAX;

  return delay;
}

static int
calculate_backoff_delay (const SocketRetry_Policy *policy, int attempt,
                         unsigned int *random_state)
{
  double delay;

  delay = exponential_backoff (policy, attempt);
  delay = apply_jitter_to_delay (delay, policy, random_state);
  delay = clamp_final_delay (delay);

  return (int)delay;
}

int
SocketRetry_calculate_delay (const SocketRetry_Policy *policy, int attempt)
{
  unsigned int state = 0;

  if (policy == NULL || attempt < 1 || !validate_policy (policy))
    {
      SOCKET_LOG_WARN_MSG ("Invalid parameters for calculate_delay "
                           "(policy=%p, attempt=%d), returning 0",
                           (const void *)policy, attempt);
      return 0;
    }

  return calculate_backoff_delay (policy, attempt, &state);
}


/* Sleep with EINTR handling via nanosleep */
static void
retry_sleep_ms (int ms)
{
  struct timespec req;
  struct timespec rem;

  if (ms <= 0)
    return;

  req.tv_sec = ms / MILLISECONDS_PER_SECOND;
  req.tv_nsec = (ms % MILLISECONDS_PER_SECOND) * NANOSECONDS_PER_MILLISECOND;

  while (nanosleep (&req, &rem) == -1)
    {
      if (errno != EINTR)
        break;
      req = rem;
    }
}


static unsigned int
init_random_state (void)
{
  unsigned int seed = 0;

  if (try_crypto_random (&seed))
    return seed;

  seed = (unsigned int)Socket_get_monotonic_ms ();
  return seed;
}

T
SocketRetry_new (const SocketRetry_Policy *policy)
{
  T retry;

  retry = calloc (1, sizeof (*retry));
  if (retry == NULL)
    SOCKET_RAISE_MSG (SocketRetry, SocketRetry_Failed,
                      "Failed to allocate retry context");

  if (policy != NULL)
    {
      if (!validate_policy (policy))
        {
          free (retry);
          SOCKET_RAISE_MSG (SocketRetry, SocketRetry_Failed,
                            "Invalid retry policy parameters");
        }
      retry->policy = *policy;
    }
  else
    {
      SocketRetry_policy_defaults (&retry->policy);
    }

  retry->random_state = init_random_state ();

  return retry;
}

void
SocketRetry_free (T *retry)
{
  if (retry == NULL || *retry == NULL)
    return;

  free (*retry);
  *retry = NULL;
}


static void
reset_retry_stats (T retry)
{
  memset (&retry->stats, 0, sizeof (retry->stats));
}

static int
should_continue_retry (const T retry, int result, int attempt,
                       SocketRetry_ShouldRetry should_retry, void *context)
{
  if (should_retry != NULL && !should_retry (result, attempt, context))
    {
      SOCKET_LOG_DEBUG_MSG ("Retry aborted by callback for error %d", result);
      return 0;
    }

  if (attempt >= retry->policy.max_attempts)
    {
      SOCKET_LOG_DEBUG_MSG ("Max attempts (%d) reached",
                            retry->policy.max_attempts);
      return 0;
    }

  return 1;
}

static void
apply_backoff_delay (T retry, int attempt)
{
  int delay_ms;

  delay_ms = calculate_backoff_delay (&retry->policy, attempt,
                                      &retry->random_state);
  retry->stats.total_delay_ms += delay_ms;

  SOCKET_LOG_DEBUG_MSG ("Sleeping %d ms before attempt %d", delay_ms,
                        attempt + 1);

  retry_sleep_ms (delay_ms);
}

static int
perform_single_attempt (T retry, SocketRetry_Operation operation,
                        void *context, int attempt_num,
                        const int64_t start_time)
{
  int result;

  retry->stats.attempts = attempt_num;
  result = operation (context, attempt_num);

  if (result == 0)
    {
      retry->stats.total_time_ms = SocketTimeout_now_ms () - start_time;
      SOCKET_LOG_DEBUG_MSG ("Operation succeeded on attempt %d", attempt_num);
      return 0;
    }

  retry->stats.last_error = result;
  SOCKET_LOG_DEBUG_MSG ("Attempt %d failed with error %d", attempt_num,
                        result);

  return result;
}


int
SocketRetry_execute (T retry, SocketRetry_Operation operation,
                     SocketRetry_ShouldRetry should_retry, void *context)
{
  int64_t start_time;
  int attempt;
  int result;

  assert (retry != NULL);
  assert (operation != NULL);

  reset_retry_stats (retry);
  start_time = SocketTimeout_now_ms ();

  for (attempt = 1; attempt <= retry->policy.max_attempts; ++attempt)
    {
      result = perform_single_attempt (retry, operation, context, attempt,
                                       start_time);

      if (result == 0)
        return 0;

      if (!should_continue_retry (retry, result, attempt, should_retry,
                                  context))
        break;

      apply_backoff_delay (retry, attempt);
    }

  retry->stats.total_time_ms = SocketTimeout_now_ms () - start_time;
  return retry->stats.last_error;
}

int
SocketRetry_execute_simple (T retry, SocketRetry_Operation operation,
                            void *context)
{
  return SocketRetry_execute (retry, operation, NULL, context);
}


void
SocketRetry_get_stats (const T retry, SocketRetry_Stats *stats)
{
  assert (retry != NULL);
  assert (stats != NULL);

  *stats = retry->stats;
}

void
SocketRetry_reset (T retry)
{
  assert (retry != NULL);

  reset_retry_stats (retry);
  retry->random_state = init_random_state ();
}

void
SocketRetry_get_policy (const T retry, SocketRetry_Policy *policy)
{
  assert (retry != NULL);
  assert (policy != NULL);

  *policy = retry->policy;
}

void
SocketRetry_set_policy (T retry, const SocketRetry_Policy *policy)
{
  if (retry == NULL || policy == NULL)
    SOCKET_RAISE_MSG (SocketRetry, SocketRetry_Failed,
                      "Invalid arguments to set_policy");

  if (!validate_policy (policy))
    SOCKET_RAISE_MSG (SocketRetry, SocketRetry_Failed,
                      "Invalid retry policy parameters");

  retry->policy = *policy;
}

#undef T
