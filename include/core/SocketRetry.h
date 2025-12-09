#ifndef SOCKETRETRY_INCLUDED
#define SOCKETRETRY_INCLUDED

/**
 * @file SocketRetry.h
 * @ingroup utilities
 * @brief Generic retry framework with exponential backoff and jitter for transient failures.
 *
 * Standalone utility module providing configurable retry logic for operations prone to
 * temporary failures, such as network I/O, DNS resolution, or resource acquisition.
 *
 * Key capabilities:
 * - Exponential backoff with configurable initial delay, multiplier, max cap.
 * - Randomized jitter to avoid synchronized retries (thundering herd prevention).
 * - Optional custom retry decision based on error codes and attempt count.
 * - Built-in statistics tracking for monitoring and debugging.
 *
 * Integrates with @ref foundation module for exception handling and memory management.
 * Commonly used in conjunction with @ref connection_mgmt (e.g., SocketReconnect) and
 * @ref core_io modules for robust I/O operations.
 *
 * Thread safety notes:
 * - SocketRetry_T instances: NOT thread-safe (internal state mutation).
 * - Multiple instances: Safe across threads.
 * - Pure functions (e.g., policy helpers, calculate_delay): Thread-safe.
 *
 * @see SocketRetry_T opaque context type.
 * @see SocketRetry_Policy configuration structure.
 * @see SocketRetry_execute() primary execution function.
 * @see SocketRetry_calculate_delay() for manual backoff computation.
 * @see @ref utilities "Utility Modules" group.
 * @see docs/ERROR_HANDLING.md for exception patterns.
 * @see SocketError_is_retryable_errno() for common retry decisions.
 */

#include <stddef.h>
#include <stdint.h>

#include "core/Except.h"

/**
 * @brief Opaque handle for a retry context.
 * @ingroup utilities
 *
 * Manages retry policy, state, statistics, and backoff logic for retryable operations.
 * Created via SocketRetry_new(), used in execute() functions, and freed with SocketRetry_free().
 *
 * Internal implementation uses Arena for memory management and tracks execution metrics.
 * Not thread-safe; designed for single-threaded use per instance.
 *
 * @see SocketRetry_new() for allocation.
 * @see SocketRetry_execute() for usage.
 * @see SocketRetry_Stats for performance metrics.
 */
#define T SocketRetry_T
typedef struct T *T;

/**
 * @brief Exception raised on critical retry operation failures.
 * @ingroup utilities
 *
 * Thrown in cases such as:
 * - Memory allocation failure during context creation.
 * - Invalid policy parameters (e.g., negative delays).
 * - Maximum retry attempts reached without success.
 *
 * @see Except_T base exception type.
 * @see SocketRetry_new() for context creation.
 * @see SocketRetry_execute() for retry execution.
 * @see docs/ERROR_HANDLING.md for handling patterns.
 */
extern const Except_T SocketRetry_Failed;

/* ============================================================================
 * Retry Policy Configuration
 * ============================================================================
 */

/**
 * @brief Configuration structure for retry policy.
 * @ingroup utilities
 *
 * Defines parameters for exponential backoff with jitter, controlling retry timing,
 * attempt limits, and backoff behavior.
 *
 * Default values can be overridden via compile-time macros or SocketRetry_policy_defaults().
 *
 * @see SocketRetry_new() to create retry context with policy.
 * @see SocketRetry_set_policy() to update policy on existing context.
 */
typedef struct SocketRetry_Policy
{
  int max_attempts;     /**< Maximum retry attempts (default: 3) */
  int initial_delay_ms; /**< Initial backoff delay in ms (default: 100ms) */
  int max_delay_ms;     /**< Maximum backoff delay cap in ms (default: 30000ms) */
  double multiplier;    /**< Backoff multiplier per attempt (default: 2.0) */
  double jitter;        /**< Jitter factor 0.0-1.0 to randomize delays (default: 0.25) */
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
 * ============================================================================
 */

/**
 * @brief Callback type for the operation to be retried.
 * @ingroup utilities
 * @param context User-provided context pointer, passed unchanged from SocketRetry_execute().
 * @param attempt Current attempt number (1-based, starts at 1).
 * @return 0 on success, non-zero error code (typically errno) on failure.
 *
 * This callback implements the retryable operation. It will be invoked repeatedly
 * until it returns 0 (success), the maximum attempts are reached, or the should_retry
 * callback decides against further retries.
 *
 * @note The operation should be idempotent or handle partial states appropriately.
 * @note Error codes should be consistent with system errors (e.g., errno values).
 *
 * Example usage for a connection attempt:
 * @code{c}
 * int connect_operation(void *ctx, int attempt) {
 *   ConnectionCtx *conn = (ConnectionCtx *)ctx;
 *   int res = connect(conn->fd, conn->addr, conn->addrlen);
 *   return (res < 0) ? errno : 0;
 * }
 * @endcode
 *
 * @see SocketRetry_ShouldRetry for deciding on retries.
 * @see SocketRetry_execute() for execution context.
 */
typedef int (*SocketRetry_Operation) (void *context, int attempt);

/**
 * @brief Callback type to decide whether to retry after an operation failure.
 * @ingroup utilities
 * @param error Non-zero error code returned by the operation.
 * @param attempt Attempt number that just failed (1-based).
 * @param context User-provided context pointer, same as passed to operation.
 * @return 1 to continue retrying, 0 to stop and propagate the error.
 *
 * This optional callback allows custom logic to determine retry eligibility based
 * on error type, attempt count, or context-specific state. If not provided (NULL),
 * the framework retries all non-zero error returns up to max_attempts.
 *
 * Typical usage filters retryable errors like timeouts or temporary network issues.
 *
 * Example for connection retries:
 * @code{c}
 * int should_retry_connect(int err, int attempt, void *ctx) {
 *   (void)ctx; (void)attempt;  // Unused parameters
 *   return SocketError_is_retryable_errno(err);
 * }
 * @endcode
 *
 * @see SocketError_is_retryable_errno() for common retryable errors.
 * @see SocketRetry_execute() for integration.
 * @see SocketRetry_Operation for the operation being retried.
 */
typedef int (*SocketRetry_ShouldRetry) (int error, int attempt, void *context);

/* ============================================================================
 * Retry Statistics
 * ============================================================================
 */

/**
 * @brief Structure holding statistics from a retry execution.
 * @ingroup utilities
 *
 * Captures metrics from the last SocketRetry_execute() or SocketRetry_execute_simple() call,
 * useful for monitoring, logging, or performance analysis.
 *
 * Fields are updated after each execution and can be reset via SocketRetry_reset().
 *
 * @see SocketRetry_get_stats() to retrieve these statistics.
 * @see SocketRetry_reset() to clear for next use.
 */
typedef struct SocketRetry_Stats
{
  int attempts;           /**< Total number of operation attempts made (including successful one if applicable). */
  int last_error;         /**< Last error code from operation (0 if succeeded, else error code). */
  int64_t total_delay_ms; /**< Cumulative time spent in backoff delays between attempts (ms). */
  int64_t total_time_ms;  /**< Total wall-clock time from start to end of execution, including ops and delays (ms). */
} SocketRetry_Stats;

/* ============================================================================
 * Context Creation and Destruction
 * ============================================================================
 */

/**
 * @brief Create a new retry context instance.
 * @ingroup utilities
 * @param policy Optional retry policy configuration (NULL uses defaults).
 *
 * Allocates and initializes a new SocketRetry_T instance with the given policy.
 * If policy is NULL, default values are applied (see SocketRetry_policy_defaults()).
 *
 * @return New opaque SocketRetry_T instance, or NULL on failure.
 * @throws SocketRetry_Failed if memory allocation fails or policy parameters are invalid (e.g., negative values).
 * @threadsafe Yes - creation is thread-safe and produces independent instances.
 *
 * @see SocketRetry_policy_defaults() for default policy values.
 * @see SocketRetry_free() for destruction.
 * @see SocketRetry_set_policy() to modify policy after creation.
 */
extern T SocketRetry_new (const SocketRetry_Policy *policy);

/**
 * @brief Free a retry context instance.
 * @ingroup utilities
 * @param retry Pointer to the SocketRetry_T instance (set to NULL on success).
 *
 * Releases all resources associated with the retry context, including internal state and statistics.
 * The pointer is set to NULL to prevent use-after-free.
 *
 * @note Must be called to avoid memory leaks; arenas used internally are cleared.
 * @threadsafe No - instance must not be accessed concurrently.
 *
 * @see SocketRetry_new() for creation.
 * @see Arena_T for memory management details.
 */
extern void SocketRetry_free (T *retry);

/* ============================================================================
 * Retry Execution
 * ============================================================================
 */

/**
 * @brief Execute a retryable operation with exponential backoff.
 * @ingroup utilities
 * @param retry Initialized retry context holding policy and state.
 * @param operation Non-NULL callback implementing the retryable operation.
 * @param should_retry Optional callback to decide retry eligibility (NULL retries all errors).
 * @param context Arbitrary user context passed to operation and should_retry callbacks.
 * @return 0 if operation succeeded eventually, otherwise the last error code returned by operation.
 *
 * Performs the operation callback repeatedly according to the policy:
 * - Initial attempt (attempt=1) without delay.
 * - On failure (non-zero return), optional should_retry check.
 * - If retry approved, sleep with jittered exponential backoff.
 * - Continues until success, max_attempts reached, or should_retry denies.
 *
 * Backoff formula:
 * - base_delay = initial_delay_ms * pow(multiplier, attempt-1)
 * - capped_delay = min(base_delay, max_delay_ms)
 * - jittered_delay = capped_delay * (1 + jitter * (2*rand() - 1))  [full jitter]
 *
 * Updates internal statistics accessible via SocketRetry_get_stats().
 * Does not throw exceptions; errors are returned as codes.
 *
 * @note Delays use monotonic clock for accuracy; interrupted sleeps resume.
 * @note Context pointer remains unchanged across calls.
 * @threadsafe No - modifies retry instance state.
 *
 * @see SocketRetry_execute_simple() for simplified version without should_retry.
 * @see SocketRetry_Operation for callback details.
 * @see SocketRetry_ShouldRetry for custom retry logic.
 * @see SocketRetry_Policy for backoff configuration.
 * @see Socket_get_monotonic_ms() for timing implementation.
 */
extern int SocketRetry_execute (T retry, SocketRetry_Operation operation,
                                SocketRetry_ShouldRetry should_retry,
                                void *context);

/**
 * @brief Simplified retry execution that retries all operation failures.
 * @ingroup utilities
 * @param retry Initialized retry context.
 * @param operation Non-NULL retryable operation callback.
 * @param context User context passed to the operation.
 * @return 0 on eventual success, last error code on final failure.
 *
 * Convenience wrapper around SocketRetry_execute() with should_retry set to NULL,
 * meaning all non-zero returns from operation are considered retryable up to max_attempts.
 *
 * Ideal for simple cases without custom error filtering.
 *
 * @note Updates statistics in the retry context.
 * @threadsafe No - modifies instance state.
 *
 * @see SocketRetry_execute() for full control with should_retry callback.
 * @see SocketRetry_Operation for operation requirements.
 */
extern int SocketRetry_execute_simple (T retry,
                                       SocketRetry_Operation operation,
                                       void *context);

/* ============================================================================
 * Statistics and State
 * ============================================================================
 */

/**
 * @brief Retrieve statistics from the most recent retry execution.
 * @ingroup utilities
 * @param retry Retry context to query.
 * @param stats Pointer to SocketRetry_Stats structure to populate.
 *
 * Copies current statistics into the provided structure. Stats reflect the last
 * SocketRetry_execute() or SocketRetry_execute_simple() call, or zeros if none executed.
 *
 * @note Does not reset statistics; use SocketRetry_reset() for that.
 * @note stats must not be NULL.
 * @threadsafe No - reads instance state, but concurrent modifications may race.
 *
 * @see SocketRetry_Stats for field details.
 * @see SocketRetry_reset() to clear stats.
 * @see SocketRetry_execute() which updates stats.
 */
extern void SocketRetry_get_stats (const T retry, SocketRetry_Stats *stats);

/**
 * @brief Reset retry context state for reuse.
 * @ingroup utilities
 * @param retry Retry context to reset.
 *
 * Clears accumulated statistics, attempt counters, and internal state,
 * preparing the context for a new execution sequence.
 *
 * Policy configuration remains unchanged.
 *
 * @note Does not free or deallocate the context; use SocketRetry_free() for that.
 * @threadsafe No - modifies instance state.
 *
 * @see SocketRetry_get_stats() for pre-reset statistics.
 * @see SocketRetry_execute() for next use.
 * @see SocketRetry_set_policy() if policy change needed.
 */
extern void SocketRetry_reset (T retry);

/**
 * @brief Retrieve the current policy configuration from retry context.
 * @ingroup utilities
 * @param retry Retry context to query.
 * @param policy Pointer to SocketRetry_Policy structure to fill with current settings.
 *
 * Copies the active policy (set at creation or via set_policy) into the provided structure.
 *
 * @note policy must not be NULL.
 * @note Returned policy reflects effective values, including defaults if not customized.
 * @threadsafe No - but read-only operation; safe if no concurrent modifications.
 *
 * @see SocketRetry_Policy for structure details.
 * @see SocketRetry_set_policy() for updating.
 * @see SocketRetry_policy_defaults() for defaults.
 */
extern void SocketRetry_get_policy (const T retry, SocketRetry_Policy *policy);

/**
 * @brief Update the policy configuration of an existing retry context.
 * @ingroup utilities
 * @param retry Retry context to update.
 * @param policy New policy settings to apply (NULL not allowed).
 *
 * Reconfigures the retry behavior dynamically. Validates parameters and applies
 * changes immediately for future executions. Does not affect ongoing executions.
 *
 * @throws SocketRetry_Failed if retry or policy is NULL, or policy contains invalid values
 * (e.g., negative delays, multiplier <=0, jitter <0 or >1).
 * @threadsafe No - modifies instance state; call only when not executing.
 *
 * @note Existing statistics and state remain; use SocketRetry_reset() to start fresh.
 * @see SocketRetry_Policy for valid parameter ranges.
 * @see SocketRetry_get_policy() to verify changes.
 * @see SocketRetry_new() which sets initial policy.
 */
extern void SocketRetry_set_policy (T retry, const SocketRetry_Policy *policy);

/* ============================================================================
 * Policy Helpers
 * ============================================================================
 */

/**
 * @brief Initialize a SocketRetry_Policy structure with recommended defaults.
 * @ingroup utilities
 * @param policy Pointer to policy structure to populate.
 *
 * Sets conservative defaults suitable for most transient failure scenarios:
 * - max_attempts = SOCKET_RETRY_DEFAULT_MAX_ATTEMPTS (3)
 * - initial_delay_ms = SOCKET_RETRY_DEFAULT_INITIAL_DELAY_MS (100)
 * - max_delay_ms = SOCKET_RETRY_DEFAULT_MAX_DELAY_MS (30000)
 * - multiplier = SOCKET_RETRY_DEFAULT_MULTIPLIER (2.0)
 * - jitter = SOCKET_RETRY_DEFAULT_JITTER (0.25)
 *
 * These can be overridden before passing to SocketRetry_new().
 *
 * @note policy must not be NULL.
 * @threadsafe Yes - pure function, no side effects.
 *
 * @see SocketRetry_Policy for field details.
 * @see Compile-time macros (e.g., SOCKET_RETRY_DEFAULT_MAX_ATTEMPTS) for customization.
 * @see SocketRetry_new() for using the policy.
 */
extern void SocketRetry_policy_defaults (SocketRetry_Policy *policy);

/**
 * @brief Calculate the jittered backoff delay for a specific attempt.
 * @ingroup utilities
 * @param policy Policy containing backoff parameters.
 * @param attempt Attempt number for which to compute delay (1-based).
 * @return Computed delay in milliseconds (>=0), or -1 on invalid input.
 *
 * Standalone utility to compute the backoff delay as used in execute() for preview,
 * logging, or integration with external schedulers/timers.
 *
 * Formula:
 * - base = initial_delay_ms * pow(multiplier, attempt - 1)
 * - capped = min(base, max_delay_ms)
 * - jittered = capped * (1 + jitter * (2 * rand_uniform() - 1))  // full jitter range [-jitter, +jitter]
 *
 * Random jitter requires seeding; internally uses high-quality RNG.
 *
 * @note attempt <=0 or > SOCKET_RETRY_MAX_ATTEMPTS returns -1.
 * @note policy NULL returns -1.
 * @threadsafe Yes - pure function, but rand() may not be if unseeded.
 *
 * @see SocketRetry_Policy for parameter effects.
 * @see SocketRetry_execute() for runtime usage.
 * @see rand() or equivalent for jitter randomness.
 */
extern int SocketRetry_calculate_delay (const SocketRetry_Policy *policy,
                                        int attempt);

#undef T
#endif /* SOCKETRETRY_INCLUDED */
