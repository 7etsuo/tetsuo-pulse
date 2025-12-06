#ifndef SOCKETRETRY_INCLUDED
#define SOCKETRETRY_INCLUDED

/**
 * SocketRetry.h - Generic Retry Framework with Exponential Backoff
 *
 * Part of the Socket Library
 *
 * Provides a generic retry mechanism with exponential backoff and jitter.
 * Can be used for any operation that may fail transiently.
 *
 * Features:
 * - Configurable exponential backoff (initial delay, max delay, multiplier)
 * - Jitter to prevent thundering herd
 * - Pluggable retry decision callback
 * - Attempt counting and statistics
 *
 * Usage:
 *   SocketRetry_Policy policy;
 *   SocketRetry_policy_defaults(&policy);
 *   policy.max_attempts = 5;
 *
 *   SocketRetry_T retry = SocketRetry_new(&policy);
 *   int result = SocketRetry_execute(retry, my_operation, should_retry, ctx);
 *   SocketRetry_free(&retry);
 *
 * Thread Safety:
 * - SocketRetry_T instances are NOT thread-safe
 * - Multiple instances can be used from different threads
 * - Policy configuration functions are thread-safe
 */

#include <stddef.h>
#include <stdint.h>

#include "core/Except.h"

#define T SocketRetry_T
typedef struct T *T;

/* Exception for retry failures */
extern const Except_T SocketRetry_Failed;

/* ============================================================================
 * Retry Policy Configuration
 * ============================================================================ */

/**
 * SocketRetry_Policy - Retry behavior configuration
 *
 * Controls retry timing, limits, and backoff behavior.
 */
typedef struct SocketRetry_Policy
{
  int max_attempts;       /**< Maximum retry attempts (default: 3) */
  int initial_delay_ms;   /**< Initial backoff delay (default: 100ms) */
  int max_delay_ms;       /**< Maximum backoff delay cap (default: 30000ms) */
  double multiplier;      /**< Backoff multiplier per attempt (default: 2.0) */
  double jitter;          /**< Jitter factor 0.0-1.0 (default: 0.25) */
} SocketRetry_Policy;

/* Default policy values - can be overridden at compile time */
#ifndef SOCKET_RETRY_DEFAULT_MAX_ATTEMPTS
#define SOCKET_RETRY_DEFAULT_MAX_ATTEMPTS 3
#endif

#ifndef SOCKET_RETRY_DEFAULT_INITIAL_DELAY_MS
#define SOCKET_RETRY_DEFAULT_INITIAL_DELAY_MS 100
#endif

#ifndef SOCKET_RETRY_DEFAULT_MAX_DELAY_MS
#define SOCKET_RETRY_DEFAULT_MAX_DELAY_MS 30000
#endif

#ifndef SOCKET_RETRY_DEFAULT_MULTIPLIER
#define SOCKET_RETRY_DEFAULT_MULTIPLIER 2.0
#endif

#ifndef SOCKET_RETRY_DEFAULT_JITTER
#define SOCKET_RETRY_DEFAULT_JITTER 0.25
#endif

#ifndef SOCKET_RETRY_MAX_ATTEMPTS
#define SOCKET_RETRY_MAX_ATTEMPTS 10000
#endif

/* ============================================================================
 * Callback Types
 * ============================================================================ */

/**
 * SocketRetry_Operation - Operation to retry
 * @context: User-provided context
 * @attempt: Current attempt number (1-based)
 *
 * Returns: 0 on success, non-zero error code on failure
 *
 * The operation will be called repeatedly until it succeeds (returns 0),
 * max_attempts is reached, or should_retry returns 0.
 *
 * Example:
 *   int connect_op(void *ctx, int attempt) {
 *     ConnectionCtx *c = ctx;
 *     return connect(c->fd, c->addr, c->addrlen) < 0 ? errno : 0;
 *   }
 */
typedef int (*SocketRetry_Operation) (void *context, int attempt);

/**
 * SocketRetry_ShouldRetry - Decide whether to retry after failure
 * @error: Error code returned by operation
 * @attempt: Attempt number that failed (1-based)
 * @context: User-provided context
 *
 * Returns: 1 to retry, 0 to stop retrying
 *
 * Use to implement custom retry logic based on error type.
 * If NULL is passed to SocketRetry_execute(), all non-zero errors
 * will be retried up to max_attempts.
 *
 * Example:
 *   int should_retry_connect(int err, int attempt, void *ctx) {
 *     return SocketError_is_retryable_errno(err);
 *   }
 */
typedef int (*SocketRetry_ShouldRetry) (int error, int attempt, void *context);

/* ============================================================================
 * Retry Statistics
 * ============================================================================ */

/**
 * SocketRetry_Stats - Statistics from retry execution
 */
typedef struct SocketRetry_Stats
{
  int attempts;           /**< Total attempts made */
  int last_error;         /**< Last error code (0 if succeeded) */
  int64_t total_delay_ms; /**< Total time spent in backoff delays */
  int64_t total_time_ms;  /**< Total execution time including operations */
} SocketRetry_Stats;

/* ============================================================================
 * Context Creation and Destruction
 * ============================================================================ */

/**
 * SocketRetry_new - Create a new retry context
 * @policy: Retry policy (NULL for defaults)
 *
 * Returns: New retry context
 * Raises: SocketRetry_Failed on allocation failure or invalid policy parameters
 * Thread-safe: Yes (creates new instance)
 */
extern T SocketRetry_new (const SocketRetry_Policy *policy);

/**
 * SocketRetry_free - Free a retry context
 * @retry: Pointer to context (will be set to NULL)
 *
 * Thread-safe: No
 */
extern void SocketRetry_free (T *retry);

/* ============================================================================
 * Retry Execution
 * ============================================================================ */

/**
 * SocketRetry_execute - Execute operation with retries
 * @retry: Retry context
 * @operation: Operation to execute (must not be NULL)
 * @should_retry: Retry decision callback (NULL = retry all errors)
 * @context: User context passed to callbacks
 *
 * Returns: 0 on success, last error code on failure
 * Thread-safe: No
 *
 * Executes operation repeatedly with exponential backoff until:
 * - Operation succeeds (returns 0)
 * - max_attempts is reached
 * - should_retry returns 0
 *
 * Backoff delay calculation:
 *   delay = min(initial * multiplier^attempt, max_delay)
 *   jittered_delay = delay * (1 + jitter * (2*random - 1))
 */
extern int SocketRetry_execute (T retry, SocketRetry_Operation operation,
                                SocketRetry_ShouldRetry should_retry,
                                void *context);

/**
 * SocketRetry_execute_simple - Execute operation with default retry logic
 * @retry: Retry context
 * @operation: Operation to execute
 * @context: User context passed to operation
 *
 * Returns: 0 on success, last error code on failure
 * Thread-safe: No
 *
 * Convenience function that retries all non-zero returns.
 * Equivalent to SocketRetry_execute(retry, op, NULL, ctx).
 */
extern int SocketRetry_execute_simple (T retry, SocketRetry_Operation operation,
                                       void *context);

/* ============================================================================
 * Statistics and State
 * ============================================================================ */

/**
 * SocketRetry_get_stats - Get statistics from last execution
 * @retry: Retry context
 * @stats: Output structure for statistics
 *
 * Thread-safe: No
 *
 * Returns statistics from the most recent SocketRetry_execute() call.
 */
extern void SocketRetry_get_stats (T retry, SocketRetry_Stats *stats);

/**
 * SocketRetry_reset - Reset retry context for reuse
 * @retry: Retry context
 *
 * Thread-safe: No
 *
 * Clears statistics and prepares context for new execution.
 * Policy settings are preserved.
 */
extern void SocketRetry_reset (T retry);

/**
 * SocketRetry_get_policy - Get current policy
 * @retry: Retry context
 * @policy: Output structure for policy
 *
 * Thread-safe: No
 */
extern void SocketRetry_get_policy (T retry, SocketRetry_Policy *policy);

/**
 * SocketRetry_set_policy - Update policy
 * @retry: Retry context
 * @policy: New policy settings
 *
 * Raises: SocketRetry_Failed on NULL arguments or invalid policy parameters
 * Thread-safe: No
 */
extern void SocketRetry_set_policy (T retry, const SocketRetry_Policy *policy);

/* ============================================================================
 * Policy Helpers
 * ============================================================================ */

/**
 * SocketRetry_policy_defaults - Initialize policy with defaults
 * @policy: Policy structure to initialize
 *
 * Thread-safe: Yes
 *
 * Fills policy with recommended defaults:
 * - max_attempts: 3
 * - initial_delay_ms: 100ms
 * - max_delay_ms: 30000ms (30s)
 * - multiplier: 2.0
 * - jitter: 0.25 (25%)
 */
extern void SocketRetry_policy_defaults (SocketRetry_Policy *policy);

/**
 * SocketRetry_calculate_delay - Calculate backoff delay for attempt
 * @policy: Policy to use for calculation
 * @attempt: Attempt number (1-based)
 *
 * Returns: Delay in milliseconds (with jitter applied)
 * Thread-safe: Yes
 *
 * Utility function to calculate delay without executing retries.
 * Useful for logging or external scheduling.
 */
extern int SocketRetry_calculate_delay (const SocketRetry_Policy *policy,
                                        int attempt);

#undef T
#endif /* SOCKETRETRY_INCLUDED */
