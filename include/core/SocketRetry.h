/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETRETRY_INCLUDED
#define SOCKETRETRY_INCLUDED

/**
 * @defgroup utilities Utilities
 * @brief Utility modules for retry, rate limiting, and metrics.
 * @{
 */

/**
 * @file SocketRetry.h
 * @ingroup utilities
 * @brief Generic retry framework with exponential backoff and jitter.
 *
 * Example usage:
 * @code{.c}
 * SocketRetry_T retry = SocketRetry_new(NULL);
 * int result = SocketRetry_execute_simple(retry, my_operation, ctx);
 * SocketRetry_free(&retry);
 * @endcode
 */

#include <stddef.h>
#include <stdint.h>

#include "core/Except.h"

/**
 * @brief Opaque handle for a retry context.
 *
 * @threadsafe No
 */
#define T SocketRetry_T
typedef struct T *T;

/**
 * @brief Exception raised on critical retry operation failures.
 */
extern const Except_T SocketRetry_Failed;

/**
 * @brief Configuration structure for retry policy.
 */
typedef struct SocketRetry_Policy
{
  int max_attempts;         /**< Maximum retry attempts (0=unlimited, capped internally) */
  int initial_delay_ms;     /**< Initial backoff delay in ms */
  int max_delay_ms;         /**< Maximum cap for backoff delays in ms */
  double multiplier;        /**< Exponential backoff multiplier (>1.0 recommended) */
  double jitter;            /**< Jitter factor for randomizing delays (0.0-1.0) */
} SocketRetry_Policy;

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

/**
 * @brief User-defined callback implementing the core retryable operation.
 *
 * @param context  Opaque userdata from execute() call
 * @param attempt  Current invocation count (1=initial, 2+=retries)
 * Returns: 0 on success, non-zero error code on failure
 *
 * @threadsafe Caller ensures
 */
typedef int (*SocketRetry_Operation) (void *context, int attempt);

/**
 * @brief Callback to decide whether to retry after operation failure.
 *
 * @param error    Error code returned by operation
 * @param attempt  Attempt number that failed (1-based)
 * @param context  User-provided context pointer
 * Returns: 1 to continue retrying, 0 to stop
 *
 * @threadsafe Caller ensures
 */
typedef int (*SocketRetry_ShouldRetry) (int error, int attempt, void *context);

/**
 * @brief Retry execution metrics and outcomes.
 */
typedef struct SocketRetry_Stats
{
  int attempts;              /**< Total operation invocations */
  int last_error;            /**< Final error code (0=success) */
  int64_t total_delay_ms;    /**< Sum of backoff sleeps (excludes op time) */
  int64_t total_time_ms;     /**< Wall-clock from start to end */
} SocketRetry_Stats;

/**
 * @brief Create a new retry context with optional custom policy.
 *
 * @param policy  Optional retry policy (NULL for defaults)
 * Returns: New SocketRetry_T instance
 * Raises: SocketRetry_Failed on allocation failure or invalid policy
 *
 * @threadsafe Yes
 * @complexity O(1)
 */
extern T SocketRetry_new (const SocketRetry_Policy *policy);

/**
 * @brief Dispose of retry context and release resources.
 *
 * @param retry  Pointer to SocketRetry_T (set to NULL on success)
 *
 * @threadsafe No
 * @complexity O(1)
 */
extern void SocketRetry_free (T *retry);

/**
 * @brief Execute a retryable operation with configurable backoff.
 *
 * @param retry         Initialized SocketRetry_T context
 * @param operation     Callback implementing retryable operation
 * @param should_retry  Optional callback for retry decisions (NULL = retry all)
 * @param context       User data passed to callbacks
 * Returns: 0 on success, last error code on exhaustion
 *
 * @threadsafe No
 * @complexity O(max_attempts * operation_time + total_delay)
 */
extern int SocketRetry_execute (T retry, SocketRetry_Operation operation,
                                SocketRetry_ShouldRetry should_retry,
                                void *context);

/**
 * @brief Execute operation with default retry logic (retries all failures).
 *
 * @param retry      Initialized SocketRetry_T context
 * @param operation  Callback for retryable operation
 * @param context    User data passed to operation
 * Returns: 0 on success, final error code on exhaustion
 *
 * @threadsafe No
 * @complexity O(max_attempts * op_time + delays)
 */
extern int SocketRetry_execute_simple (T retry, SocketRetry_Operation operation,
                                       void *context);

/**
 * @brief Copy retry statistics from last execution.
 *
 * @param retry  SocketRetry_T to query
 * @param stats  Output for statistics
 *
 * @threadsafe Partial (read-only; unsafe with concurrent execute/reset)
 * @complexity O(1)
 */
extern void SocketRetry_get_stats (const T retry, SocketRetry_Stats *stats);

/**
 * @brief Reset internal state and statistics for fresh retry sequences.
 *
 * @param retry  SocketRetry_T to reset
 *
 * @threadsafe No
 * @complexity O(1)
 */
extern void SocketRetry_reset (T retry);

/**
 * @brief Copy current active policy settings.
 *
 * @param retry   SocketRetry_T to query
 * @param policy  Output for current policy
 *
 * @threadsafe Partial (const read; unsafe with concurrent set_policy)
 * @complexity O(1)
 */
extern void SocketRetry_get_policy (const T retry, SocketRetry_Policy *policy);

/**
 * @brief Update retry policy on existing context.
 *
 * @param retry   SocketRetry_T to reconfigure
 * @param policy  New policy settings
 * Raises: SocketRetry_Failed on NULL inputs or invalid policy
 *
 * @threadsafe No
 * @complexity O(1)
 */
extern void SocketRetry_set_policy (T retry, const SocketRetry_Policy *policy);

/**
 * @brief Populate SocketRetry_Policy with default values.
 *
 * @param policy  Output for default policy
 *
 * @threadsafe Yes
 * @complexity O(1)
 */
extern void SocketRetry_policy_defaults (SocketRetry_Policy *policy);

/**
 * @brief Compute jittered exponential backoff delay for given attempt.
 *
 * @param policy   Retry policy with backoff parameters
 * @param attempt  1-based attempt number
 * Returns: Delay in ms (>=0) or -1 on error
 *
 * @threadsafe Yes (if rand() implementation is)
 * @complexity O(1)
 */
extern int SocketRetry_calculate_delay (const SocketRetry_Policy *policy,
                                        int attempt);

/** @} */

#undef T
#endif /* SOCKETRETRY_INCLUDED */
