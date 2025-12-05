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
 *   base_delay = initial_delay * multiplier^(attempt-1)
 *   capped_delay = min(base_delay, max_delay)
 *   jittered_delay = capped_delay * (1 + jitter * (2*random - 1))
 */

#include "core/SocketRetry.h"

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketUtil.h"

#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define T SocketRetry_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "Retry"

/* Exception definition */
const Except_T SocketRetry_Failed
    = { &SocketRetry_Failed, "Retry operation failed" };

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketRetry);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketRetry, e)

/* ============================================================================
 * Internal Structure
 * ============================================================================ */

struct T
{
  SocketRetry_Policy policy;    /**< Current retry policy */
  SocketRetry_Stats stats;      /**< Statistics from last execution */
  unsigned int random_state;    /**< Random state for jitter */
};

/* ============================================================================
 * Random Number Generation (for jitter)
 * ============================================================================ */

/**
 * retry_random_seed - Initialize random state
 *
 * Returns: Seed value based on time and address
 * Thread-safe: Yes
 */
static unsigned int
retry_random_seed (void)
{
  struct timespec ts;

  if (clock_gettime (CLOCK_MONOTONIC, &ts) == 0)
    return (unsigned int)(ts.tv_sec ^ ts.tv_nsec);

  return (unsigned int)time (NULL);
}

/**
 * retry_random_double - Generate random double in [0, 1)
 * @state: Random state (modified)
 *
 * Returns: Random value in [0, 1)
 * Thread-safe: No (modifies state)
 *
 * Uses simple LCG for reproducibility and speed.
 */
static double
retry_random_double (unsigned int *state)
{
  /* LCG parameters from Numerical Recipes */
  *state = (*state * 1103515245u + 12345u) & 0x7fffffffu;
  return (double)*state / (double)0x80000000u;
}

/* ============================================================================
 * Policy Defaults
 * ============================================================================ */

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

/* ============================================================================
 * Backoff Calculation
 * ============================================================================ */

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
  double jitter_range;
  double jitter_offset;

  /* Exponential backoff: initial * multiplier^(attempt-1) */
  delay = (double)policy->initial_delay_ms
          * pow (policy->multiplier, (double)(attempt - 1));

  /* Cap at max delay */
  if (delay > (double)policy->max_delay_ms)
    delay = (double)policy->max_delay_ms;

  /* Add jitter: delay * (1 + jitter * (2*random - 1)) */
  if (policy->jitter > 0.0)
    {
      jitter_range = delay * policy->jitter;
      jitter_offset = jitter_range * (2.0 * retry_random_double (random_state) - 1.0);
      delay += jitter_offset;
    }

  /* Ensure positive delay */
  if (delay < 1.0)
    delay = 1.0;

  return (int)delay;
}

/**
 * SocketRetry_calculate_delay - Public delay calculation
 * @policy: Policy to use
 * @attempt: Attempt number (1-based)
 *
 * Returns: Delay in milliseconds (with jitter)
 * Thread-safe: Yes (creates temporary random state)
 */
int
SocketRetry_calculate_delay (const SocketRetry_Policy *policy, int attempt)
{
  unsigned int state;

  assert (policy != NULL);
  assert (attempt >= 1);

  state = retry_random_seed ();
  return calculate_backoff_delay (policy, attempt, &state);
}

/* ============================================================================
 * Sleep Helper
 * ============================================================================ */

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

  req.tv_sec = ms / 1000;
  req.tv_nsec = (ms % 1000) * 1000000L;

  while (nanosleep (&req, &rem) == -1)
    {
      if (errno != EINTR)
        break;
      req = rem;
    }
}

/* ============================================================================
 * Context Management
 * ============================================================================ */

/**
 * SocketRetry_new - Create a new retry context
 * @policy: Retry policy (NULL for defaults)
 *
 * Returns: New retry context
 * Raises: SocketRetry_Failed on allocation failure
 */
T
SocketRetry_new (const SocketRetry_Policy *policy)
{
  T retry;

  retry = malloc (sizeof (*retry));
  if (retry == NULL)
    {
      SOCKET_ERROR_MSG ("Failed to allocate retry context");
      RAISE_MODULE_ERROR (SocketRetry_Failed);
    }

  memset (retry, 0, sizeof (*retry));

  if (policy != NULL)
    retry->policy = *policy;
  else
    SocketRetry_policy_defaults (&retry->policy);

  retry->random_state = retry_random_seed ();

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
 * Retry Execution
 * ============================================================================ */

/**
 * SocketRetry_execute - Execute operation with retries
 * @retry: Retry context
 * @operation: Operation to execute
 * @should_retry: Retry decision callback (NULL = retry all)
 * @context: User context
 *
 * Returns: 0 on success, last error code on failure
 */
int
SocketRetry_execute (T retry, SocketRetry_Operation operation,
                     SocketRetry_ShouldRetry should_retry, void *context)
{
  int64_t start_time;
  int attempt;
  int result;
  int delay_ms;

  assert (retry != NULL);
  assert (operation != NULL);

  /* Reset statistics */
  memset (&retry->stats, 0, sizeof (retry->stats));
  start_time = SocketTimeout_now_ms ();

  for (attempt = 1; attempt <= retry->policy.max_attempts; attempt++)
    {
      retry->stats.attempts = attempt;

      /* Execute operation */
      result = operation (context, attempt);

      if (result == 0)
        {
          /* Success */
          retry->stats.total_time_ms = SocketTimeout_now_ms () - start_time;
          SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                           "Operation succeeded on attempt %d", attempt);
          return 0;
        }

      /* Operation failed */
      retry->stats.last_error = result;

      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "Attempt %d failed with error %d", attempt, result);

      /* Check if we should retry */
      if (should_retry != NULL && !should_retry (result, attempt, context))
        {
          SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                           "Retry aborted by callback for error %d", result);
          break;
        }

      /* Check if we've exhausted attempts */
      if (attempt >= retry->policy.max_attempts)
        {
          SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                           "Max attempts (%d) reached", retry->policy.max_attempts);
          break;
        }

      /* Calculate and apply backoff delay */
      delay_ms = calculate_backoff_delay (&retry->policy, attempt,
                                          &retry->random_state);
      retry->stats.total_delay_ms += delay_ms;

      SocketLog_emitf (SOCKET_LOG_DEBUG, SOCKET_LOG_COMPONENT,
                       "Sleeping %d ms before attempt %d", delay_ms, attempt + 1);

      retry_sleep_ms (delay_ms);
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
 * ============================================================================ */

/**
 * SocketRetry_get_stats - Get statistics from last execution
 * @retry: Retry context
 * @stats: Output structure
 */
void
SocketRetry_get_stats (T retry, SocketRetry_Stats *stats)
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

  memset (&retry->stats, 0, sizeof (retry->stats));
  /* Preserve policy and re-seed random state */
  retry->random_state = retry_random_seed ();
}

/**
 * SocketRetry_get_policy - Get current policy
 * @retry: Retry context
 * @policy: Output structure
 */
void
SocketRetry_get_policy (T retry, SocketRetry_Policy *policy)
{
  assert (retry != NULL);
  assert (policy != NULL);

  *policy = retry->policy;
}

/**
 * SocketRetry_set_policy - Update policy
 * @retry: Retry context
 * @policy: New policy settings
 */
void
SocketRetry_set_policy (T retry, const SocketRetry_Policy *policy)
{
  assert (retry != NULL);
  assert (policy != NULL);

  retry->policy = *policy;
}

#undef T
