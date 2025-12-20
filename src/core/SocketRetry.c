/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketRetry.c - Generic Retry Framework Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements exponential backoff retry logic with jitter.
 * Algorithm matches SocketReconnect for consistency.
 *
 * Backoff Formula:
 *   base_delay = initial_delay * multiplier^(attempt - 1)
 *   capped_delay = min(base_delay, max_delay)
 *   jittered_delay = capped_delay * (1 + jitter * (2 * random - 1))
 */

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

/* ============================================================================
 * Constants
 * ============================================================================
 */

/** Minimum delay to avoid zero/negative delays after jitter */
#define RETRY_MIN_DELAY_MS 1.0

/** Policy validation: maximum allowed multiplier */
#define SOCKET_RETRY_MAX_MULTIPLIER 16.0

/** Policy validation: maximum delay value in milliseconds (1 hour) */
#define SOCKET_RETRY_MAX_DELAY_VALUE_MS 3600000

/** Maximum exponent to prevent CPU DoS from excessive loop iterations */
#define RETRY_MAX_EXPONENT 1000

/** Time conversion: milliseconds per second */
#define MILLISECONDS_PER_SECOND 1000

/** Time conversion: nanoseconds per millisecond */
#define NANOSECONDS_PER_MILLISECOND 1000000L

/** Double representation of UINT32_MAX for random value normalization */
#define UINT32_MAX_DOUBLE ((double)0xFFFFFFFFU)

#define T SocketRetry_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "Retry"

/* Exception definition */
const Except_T SocketRetry_Failed
    = { &SocketRetry_Failed, "Retry operation failed" };

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketRetry);

/* ============================================================================
 * Internal Structure
 * ============================================================================
 */

struct T
{
  SocketRetry_Policy policy; /**< Current retry policy */
  SocketRetry_Stats stats;   /**< Statistics from last execution */
  unsigned int random_state; /**< Random state for jitter (xorshift32) */
};

/* ============================================================================
 * Common Random Helper
 * ============================================================================
 */

/**
 * try_crypto_random - Attempt to fill output with cryptographically secure random bytes
 * @out: Pointer to unsigned int to fill
 *
 * Returns: 1 if successful (crypto available and bytes generated), 0 otherwise
 * Thread-safe: Yes
 */
static int
try_crypto_random (unsigned int *out)
{
  if (!SocketSecurity_has_tls ())
    return 0;

  return SocketCrypto_random_bytes (out, sizeof (*out)) == 0;
}

/* ============================================================================
 * Random Number Generation (for jitter)
 * ============================================================================
 *
 * Uses SocketCrypto_random_bytes() as primary source with xorshift32 PRNG
 * fallback. Matches pattern from SocketReconnect-private.h for consistency.
 */

/**
 * retry_random_double - Generate random double in [0, 1)
 * @state: Random state for fallback PRNG (modified on fallback path)
 *
 * Returns: Random value in [0, 1)
 * Thread-safe: Yes (crypto path is reentrant, fallback uses instance state)
 *
 * Primary: SocketCrypto_random_bytes() for cryptographic randomness
 * Fallback: xorshift32 PRNG for performance when crypto unavailable
 */
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

/* ============================================================================
 * Policy Defaults and Validation
 * ============================================================================
 */

/**
 * SocketRetry_policy_defaults - Initialize policy with defaults
 * @policy: Policy structure to initialize
 *
 * Thread-safe: Yes
 */
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

/**
 * validate_policy - Validate retry policy parameters
 * @policy: Policy to validate
 *
 * Returns: 1 if valid, 0 if invalid
 * Thread-safe: Yes
 *
 * Validates policy parameters are within safe ranges to prevent DoS.
 */
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

/* ============================================================================
 * Backoff Calculation
 * ============================================================================
 */

/**
 * power_double - Compute base^exp for double (iterative to avoid pow overhead)
 * @base: Base value (multiplier)
 * @exp: Exponent (non-negative integer)
 *
 * Returns: base^exp, or INFINITY on overflow
 * Thread-safe: Yes
 */
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

/**
 * exponential_backoff - Compute exponential backoff delay before jitter
 * @policy: Policy containing backoff parameters
 * @attempt: Current attempt number (1-based)
 *
 * Returns: Base exponential delay in ms (double)
 * Thread-safe: Yes
 */
static double
exponential_backoff (const SocketRetry_Policy *policy, int attempt)
{
  double base_delay;
  double multiplier_pow;

  if (attempt < 1)
    return 0.0;

  /* Compute multiplier^(attempt-1) iteratively for precision */
  multiplier_pow = power_double (policy->multiplier, attempt - 1);

  /* Exponential backoff: initial * multiplier^(attempt-1) */
  base_delay = (double)policy->initial_delay_ms * multiplier_pow;

  /* Handle FP overflow/NaN */
  if (isinf (base_delay) || isnan (base_delay))
    base_delay = (double)policy->max_delay_ms;

  /* Cap at max delay */
  if (base_delay > (double)policy->max_delay_ms)
    base_delay = (double)policy->max_delay_ms;

  return base_delay;
}

/**
 * apply_jitter_to_delay - Apply jitter to base delay
 * @base_delay: Base delay in ms
 * @policy: Policy containing jitter factor
 * @random_state: Random state for jitter (modified)
 *
 * Returns: Jittered delay in ms
 * Thread-safe: No (modifies random_state)
 */
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

  /* Handle FP overflow/NaN after jitter */
  if (isinf (jittered_delay) || isnan (jittered_delay) || jittered_delay < 0.0)
    jittered_delay = (double)policy->max_delay_ms;

  return jittered_delay;
}

/**
 * clamp_final_delay - Clamp delay to valid range
 * @delay: Delay to clamp
 *
 * Returns: Clamped delay in ms (double, safe for int cast)
 * Thread-safe: Yes
 */
static double
clamp_final_delay (double delay)
{
  /* Ensure positive delay after jitter */
  if (delay < RETRY_MIN_DELAY_MS)
    delay = RETRY_MIN_DELAY_MS;

  /* Clamp to safe int range */
  if (delay > INT_MAX)
    delay = INT_MAX;

  return delay;
}

/**
 * calculate_backoff_delay - Calculate delay with jitter
 * @policy: Policy containing backoff parameters
 * @attempt: Current attempt number (1-based)
 * @random_state: Random state for jitter (modified)
 *
 * Returns: Delay in milliseconds
 * Thread-safe: No (modifies random_state)
 */
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

/**
 * SocketRetry_calculate_delay - Public delay calculation
 * @policy: Policy to use
 * @attempt: Attempt number (1-based)
 *
 * Returns: Delay in milliseconds (with jitter), or 0 if invalid parameters
 * Thread-safe: Yes (creates temporary random state)
 *
 * Logs warning if policy invalid or attempt <1.
 */
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

/* ============================================================================
 * Sleep Helper
 * ============================================================================
 */

/**
 * retry_sleep_ms - Sleep for specified milliseconds
 * @ms: Milliseconds to sleep
 *
 * Thread-safe: Yes
 *
 * Uses nanosleep for better precision than usleep.
 * Handles EINTR by continuing the sleep.
 */
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

/* ============================================================================
 * Context Management
 * ============================================================================
 */

/**
 * init_random_state - Initialize random state for jitter
 *
 * Returns: Initial random state value
 * Thread-safe: Yes
 */
static unsigned int
init_random_state (void)
{
  unsigned int seed = 0;

  if (try_crypto_random (&seed))
    return seed;

  seed = (unsigned int)Socket_get_monotonic_ms ();
  return seed;
}

/**
 * SocketRetry_new - Create a new retry context
 * @policy: Retry policy (NULL for defaults)
 *
 * Returns: New retry context
 * Raises: SocketRetry_Failed on allocation failure or invalid policy
 * Thread-safe: Yes (each instance independent)
 */
T
SocketRetry_new (const SocketRetry_Policy *policy)
{
  T retry;

  /* Use calloc for zero-initialization of stats */
  retry = calloc (1, sizeof (*retry));
  if (retry == NULL)
    SOCKET_RAISE_MSG (SocketRetry, SocketRetry_Failed,
                      "Failed to allocate retry context");

  /* Initialize policy */
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

/**
 * SocketRetry_free - Free a retry context
 * @retry: Pointer to context (will be set to NULL)
 */
void
SocketRetry_free (T *retry)
{
  if (retry == NULL || *retry == NULL)
    return;

  free (*retry);
  *retry = NULL;
}

/* ============================================================================
 * Retry Execution Helpers
 * ============================================================================
 */

/**
 * reset_retry_stats - Reset statistics for new execution
 * @retry: Retry context
 *
 * Thread-safe: No
 */
static void
reset_retry_stats (T retry)
{
  memset (&retry->stats, 0, sizeof (retry->stats));
}

/**
 * should_continue_retry - Check if retry should continue after failure
 * @retry: Retry context
 * @result: Operation result code
 * @attempt: Current attempt number
 * @should_retry: User callback (may be NULL)
 * @context: User context
 *
 * Returns: 1 if should retry, 0 if should stop
 */
static int
should_continue_retry (const T retry, int result, int attempt,
                       SocketRetry_ShouldRetry should_retry, void *context)
{
  /* Check user callback */
  if (should_retry != NULL && !should_retry (result, attempt, context))
    {
      SOCKET_LOG_DEBUG_MSG ("Retry aborted by callback for error %d", result);
      return 0;
    }

  /* Check if we've exhausted attempts */
  if (attempt >= retry->policy.max_attempts)
    {
      SOCKET_LOG_DEBUG_MSG ("Max attempts (%d) reached",
                            retry->policy.max_attempts);
      return 0;
    }

  return 1;
}

/**
 * apply_backoff_delay - Calculate and apply backoff delay
 * @retry: Retry context (stats updated)
 * @attempt: Current attempt number
 */
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

/**
 * perform_single_attempt - Perform single retry attempt and log result
 * @retry: Retry context
 * @operation: Operation callback
 * @context: User context
 * @attempt_num: Current attempt number
 * @start_time: Execution start time (for total_time calc on success)
 *
 * Returns: 0 on success (sets total_time_ms), non-zero on failure
 * Thread-safe: No
 */
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

  /* Operation failed */
  retry->stats.last_error = result;
  SOCKET_LOG_DEBUG_MSG ("Attempt %d failed with error %d", attempt_num,
                        result);

  return result;
}

/* ============================================================================
 * Retry Execution
 * ============================================================================
 */

/**
 * SocketRetry_execute - Execute operation with retries
 * @retry: Retry context
 * @operation: Operation to execute
 * @should_retry: Retry decision callback (NULL = retry all)
 * @context: User context
 *
 * Returns: 0 on success, last error code on failure
 * Thread-safe: No (instance not thread-safe)
 */
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

/**
 * SocketRetry_execute_simple - Execute with default retry logic
 * @retry: Retry context
 * @operation: Operation to execute
 * @context: User context
 *
 * Returns: 0 on success, last error code on failure
 */
int
SocketRetry_execute_simple (T retry, SocketRetry_Operation operation,
                            void *context)
{
  return SocketRetry_execute (retry, operation, NULL, context);
}

/* ============================================================================
 * Statistics and State
 * ============================================================================
 */

/**
 * SocketRetry_get_stats - Get statistics from last execution
 * @retry: Retry context
 * @stats: Output structure
 */
void
SocketRetry_get_stats (const T retry, SocketRetry_Stats *stats)
{
  assert (retry != NULL);
  assert (stats != NULL);

  *stats = retry->stats;
}

/**
 * SocketRetry_reset - Reset context for reuse
 * @retry: Retry context
 */
void
SocketRetry_reset (T retry)
{
  assert (retry != NULL);

  reset_retry_stats (retry);
  /* Preserve policy and re-seed random state with better entropy */
  retry->random_state = init_random_state ();
}

/**
 * SocketRetry_get_policy - Get current policy
 * @retry: Retry context
 * @policy: Output structure
 */
void
SocketRetry_get_policy (const T retry, SocketRetry_Policy *policy)
{
  assert (retry != NULL);
  assert (policy != NULL);

  *policy = retry->policy;
}

/**
 * SocketRetry_set_policy - Update policy
 * @retry: Retry context
 * @policy: New policy settings
 *
 * Raises: SocketRetry_Failed on NULL arguments or invalid policy
 */
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
