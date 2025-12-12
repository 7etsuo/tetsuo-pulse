/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETRETRY_INCLUDED
#define SOCKETRETRY_INCLUDED

/**
 * @defgroup utilities Utilities
 * @brief Comprehensive utility modules for retry, rate limiting, metrics, and
 * more.
 *
 * This group encompasses helper functionalities essential for robust network
 * applications:
 * - @ref retry "Retry Framework" (SocketRetry): Exponential backoff with
 * jitter for transient failures.
 * - @ref ratelimit "Rate Limiting" (SocketRateLimit): Token bucket for
 * connection/byte throttling.
 * - Metrics collection and UTF-8 utilities.
 *
 * ## Architecture Overview
 *
 * ```
 * ┌─────────────────────┐
 * │   Application       │  <-- HTTP clients, pools, reconnect
 * │   Layer             │
 * └──────────┬──────────┘
 *            │ Uses
 * ┌──────────▼──────────┐
 * │   Utilities         │  <-- Retry, RateLimit, Metrics
 * │   (this group)      │
 * └──────────┬──────────┘
 *            │ Depends on
 * ┌──────────▼──────────┐
 * │   Foundation        │  <-- Arena, Except, Timer
 * └─────────────────────┘
 * ```
 *
 * ## Key Integration Patterns
 *
 * - **Retry in Reconnect**: SocketReconnect uses SocketRetry internally for
 * backoff.
 * - **Rate Limit in Pool**: SocketPool integrates SocketRateLimit for per-IP
 * limits.
 * - **Metrics Everywhere**: All modules emit to SocketMetrics for
 * observability.
 *
 * ## Thread Safety
 *
 * - Instances: Generally not thread-safe (stateful).
 * - Pure functions: Thread-safe (e.g., calculate_delay).
 * - Use one instance per thread or external locking.
 *
 * ## Platform Notes
 *
 * - Requires <time.h> CLOCK_MONOTONIC for accurate delays.
 * - POSIX rand()/srand() for jitter; high-quality RNG recommended.
 *
 * @see @ref foundation Core foundation dependencies.
 * @see @ref connection_mgmt Higher-level consumers.
 * @see docs/ERROR_HANDLING.md Exception usage in utilities.
 * @{
 */

/**
 * @file SocketRetry.h
 * @ingroup utilities
 * @brief Generic retry framework with exponential backoff and jitter for
 * transient failures.
 *
 * Standalone utility module providing configurable retry logic for operations
 * prone to temporary failures, such as network I/O, DNS resolution, or
 * resource acquisition.
 */

#include <stddef.h>
#include <stdint.h>

#include "core/Except.h"

/**
 * @brief Opaque handle for a retry context.
 * @ingroup utilities
 *
 * Manages retry policy, state, statistics, and backoff logic for retryable
 * operations. Created via SocketRetry_new(), used in execute() functions, and
 * freed with SocketRetry_free().
 *
 * Internal implementation uses Arena for memory management and tracks
 * execution metrics. Not thread-safe; designed for single-threaded use per
 * instance.
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
 * Defines parameters for exponential backoff with jitter, controlling retry
 * timing, attempt limits, and backoff behavior.
 *
 * Default values can be overridden via compile-time macros or
 * SocketRetry_policy_defaults().
 *
 * @see SocketRetry_new() to create retry context with policy.
 * @see SocketRetry_set_policy() to update policy on existing context.
 */
typedef struct SocketRetry_Policy
{
  /**
   * @brief Maximum number of retry attempts before giving up.
   *
   * Default: SOCKET_RETRY_DEFAULT_MAX_ATTEMPTS (3).
   * Set to 0 for unlimited (but capped internally by
   * SOCKET_RETRY_MAX_ATTEMPTS).
   *
   * @note Values <=0 are treated as unlimited but hard-capped for safety.
   */
  int max_attempts;

  /**
   * @brief Initial backoff delay in milliseconds for the first retry.
   *
   * Default: SOCKET_RETRY_DEFAULT_INITIAL_DELAY_MS (100 ms).
   * Subsequent delays grow exponentially via multiplier.
   *
   * @note Must be positive; 0 disables delays (immediate retries).
   */
  int initial_delay_ms;

  /**
   * @brief Maximum cap for backoff delays in milliseconds.
   *
   * Default: SOCKET_RETRY_DEFAULT_MAX_DELAY_MS (30 seconds).
   * Exponential growth is capped at this value.
   *
   * @note Must be >= initial_delay_ms; larger values allow longer waits.
   */
  int max_delay_ms;

  /**
   * @brief Multiplier for exponential backoff (recommended >1.0).
   *
   * Default: SOCKET_RETRY_DEFAULT_MULTIPLIER (2.0).
   * Formula: delay_n = initial * pow(multiplier, n-1)
   *
   * @note Values <=1.0 disable exponential growth (constant delay).
   * @warning multiplier >10 may lead to excessively long delays quickly.
   */
  double multiplier;

  /**
   * @brief Jitter factor for randomizing delays (0.0=no jitter, 1.0=full).
   *
   * Default: SOCKET_RETRY_DEFAULT_JITTER (0.25).
   * jittered = capped * (1 + jitter * (2*uniform_rand() - 1))
   * Prevents synchronized retries (thundering herd).
   *
   * @note 0.0-1.0 range; values outside clamped.
   * @warning High jitter (>0.5) may cause unpredictable timing.
   */
  double jitter;
} SocketRetry_Policy;

/**
 * @brief Compile-time configurable default values for SocketRetry_Policy
 * fields.
 * @ingroup utilities
 *
 * These macros allow customization of retry policy defaults without modifying
 * source code. Override them before including SocketRetry.h.
 *
 * @see SocketRetry_policy_defaults() which uses these values.
 * @see SocketRetry_Policy for structure details.
 */

/**
 * @brief Default maximum number of retry attempts.
 * @ingroup utilities
 * @note Override before inclusion to change default in SocketRetry_new(NULL)
 * and policy_defaults().
 * @see SocketRetry_Policy::max_attempts
 */
#ifndef SOCKET_RETRY_DEFAULT_MAX_ATTEMPTS
#define SOCKET_RETRY_DEFAULT_MAX_ATTEMPTS 3
#endif

/**
 * @brief Default initial backoff delay in milliseconds.
 * @ingroup utilities
 * @note Conservative starting delay for first retry.
 * @see SocketRetry_Policy::initial_delay_ms
 */
#ifndef SOCKET_RETRY_DEFAULT_INITIAL_DELAY_MS
#define SOCKET_RETRY_DEFAULT_INITIAL_DELAY_MS 100
#endif

/**
 * @brief Default maximum backoff delay cap in milliseconds.
 * @ingroup utilities
 * @note Prevents excessively long delays in prolonged failure scenarios.
 * @see SocketRetry_Policy::max_delay_ms
 */
#ifndef SOCKET_RETRY_DEFAULT_MAX_DELAY_MS
#define SOCKET_RETRY_DEFAULT_MAX_DELAY_MS 30000
#endif

/**
 * @brief Default exponential backoff multiplier.
 * @ingroup utilities
 * @note Standard value of 2.0 for doubling delay per attempt.
 * @see SocketRetry_Policy::multiplier
 */
#ifndef SOCKET_RETRY_DEFAULT_MULTIPLIER
#define SOCKET_RETRY_DEFAULT_MULTIPLIER 2.0
#endif

/**
 * @brief Default jitter factor for randomized backoff (0.0 to 1.0).
 * @ingroup utilities
 * @note 0.25 provides moderate randomization to avoid thundering herd.
 * @see SocketRetry_Policy::jitter
 */
#ifndef SOCKET_RETRY_DEFAULT_JITTER
#define SOCKET_RETRY_DEFAULT_JITTER 0.25
#endif

/**
 * @brief Hard maximum attempts limit to prevent infinite retries.
 * @ingroup utilities
 * @note Internal safety cap; policy max_attempts cannot exceed this.
 * Used in validation and delay calculations.
 * @see SocketRetry_calculate_delay()
 * @see SocketRetry_Policy::max_attempts
 */
#ifndef SOCKET_RETRY_MAX_ATTEMPTS
#define SOCKET_RETRY_MAX_ATTEMPTS 10000
#endif

/* ============================================================================
 * Callback Types
 * ============================================================================
 */

/**
 * @brief User-defined callback implementing the core retryable operation.
 * @ingroup utilities
 *
 * Invoked by SocketRetry_execute() to perform the actual work that may fail
 * transiently. Must be idempotent: safe to call multiple times with same
 * state, handling partial progress. Return 0 signals success (retry loop
 * exits); non-zero triggers potential retry.
 *
 * Design guidelines:
 * - Keep lightweight; heavy ops better wrapped in async or pooled.
 * - Use attempt param for logging/progressive behavior (e.g., increasing
 * timeouts).
 * - Context carries all needed state (e.g., socket fd, buffers, config).
 * - Errors: Prefer system errno values for compatibility with should_retry
 * logic.
 *
 * @param[in] context Opaque userdata from execute() call, unchanged.
 * @param[in] attempt Current invocation count (1=initial, 2+=retries).
 *
 * @return 0 = success (complete), >0 = retryable error code (e.g., ETIMEDOUT),
 * <0 = fatal (but still checked by should_retry).
 *
 * ## Usage Example
 *
 * @code{.c}
 * // TCP connect with logging
 * static int tcp_connect_op(void *ctx_, int attempt) {
 *     ConnectCtx *ctx = (ConnectCtx*)ctx_;
 *     SOCKET_LOG_DEBUG_MSG("Connect attempt %d for %s:%d", attempt, ctx->host,
 * ctx->port);
 *
 *     Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 *     if (!sock) return ENOMEM;
 *
 *     int res = Socket_connect(sock, ctx->host, ctx->port);
 *     if (res < 0) {
 *         int err = Socket_geterrno();
 *         Socket_free(&sock);
 *         return err;  // Retryable? e.g., ECONNREFUSED
 *     }
 *
 *     ctx->socket = sock;  // Store for later use
 *     return 0;  // Success
 * }
 *
 * // Usage in execute
 * ConnectCtx ctx = { .host = "example.com", .port = 443 };
 * int res = SocketRetry_execute(retry, tcp_connect_op, should_retry, &ctx);
 * if (res == 0 && ctx.socket) {
 *     // Use ctx.socket...
 * }
 * @endcode
 *
 * ## Advanced: Progressive Timeouts
 *
 * @code{.c}
 * static int db_query_op(void *ctx, int attempt) {
 *     QueryCtx *qctx = (QueryCtx*)ctx;
 *     int timeout = 1000 * attempt;  // Increase per attempt
 *     return db_execute_with_timeout(qctx->db, qctx->query, timeout);
 * }
 * @endcode
 *
 * @note Non-idempotent ops risk data corruption/duplication; prefer stateless.
 * @warning Returning 0 prematurely aborts retries; ensure true completion.
 * @threadsafe Caller ensures; context may need locks if shared.
 *
 * @see SocketRetry_ShouldRetry pairing for error decisions.
 * @see SocketRetry_execute() invoker and loop logic.
 * @see SocketError_is_retryable_errno() common retryable codes.
 * @see docs/ERROR_HANDLING.md error code conventions.
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
 * This optional callback allows custom logic to determine retry eligibility
 * based on error type, attempt count, or context-specific state. If not
 * provided (NULL), the framework retries all non-zero error returns up to
 * max_attempts.
 *
 * Typical usage filters retryable errors like timeouts or temporary network
 * issues.
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
 * @brief Opaque structure capturing retry execution metrics and outcomes.
 * @ingroup utilities
 *
 * Aggregates key performance indicators from a single retry sequence, enabling
 * observability, alerting, and debugging. Populated by execute() functions,
 * zero-initialized otherwise. Thread-safe for read if no concurrent writes.
 *
 * ## Fields Table
 *
 * | Field | Type | Description |
 * |-------|------|-------------|
 * | attempts | int | Total calls to operation (includes final success; min=1
 * if executed) | | last_error | int | Final operation return (0=success, else
 * errno-like code) | | total_delay_ms | int64_t | Sum of all backoff sleeps
 * (monotonic ms; excludes op time) | | total_time_ms | int64_t | Wall-clock
 * from start to end (ops + delays + overhead) |
 *
 * Usage: Retrieve via get_stats(), analyze for high retry rates or long
 * delays.
 *
 * ## Interpretation Notes
 *
 * - attempts ==1: No retries needed (immediate success or single failure)
 * - total_delay_ms >0 indicates backoffs occurred
 * - total_time_ms includes variability from op execution time
 * - For success: last_error=0, attempts >=1
 * - For failure: last_error !=0, attempts == policy.max_attempts or
 * should_retry denied
 *
 * @note Fields zeroed on creation/reset; non-negative always.
 * @note int64_t timings use Socket_get_monotonic_ms() for precision.
 * @threadsafe Read: Yes (atomic snapshot via get_stats()); Write: No
 *
 * @see SocketRetry_get_stats() accessor function.
 * @see SocketRetry_execute() or SocketRetry_simple() for updating fields.
 * @see SocketRetry_reset() clears to zero.
 * @see SocketRetry_Policy influencing attempt counts/delays.
 */
typedef struct SocketRetry_Stats
{
  /**
   * @brief Total operation invocations during the retry sequence.
   *
   * Includes initial attempt + retries up to success or limit.
   * Range: 1+ (if executed); 0 (pre-execution or reset).
   * High values indicate persistent failures or conservative policy.
   */
  int attempts;

  /**
   * @brief Final error code from last operation call.
   *
   * 0 on success; non-zero errno-like value on exhaustion/failure.
   * Use strerror() or Socket_safe_strerror() for human-readable.
   */
  int last_error;

  /**
   * @brief Aggregate backoff delay time across all retries (ms).
   *
   * Sum of jittered exponential delays slept between attempts.
   * Monotonic clock; excludes operation execution time.
   * Useful for latency attribution to retries.
   */
  int64_t total_delay_ms;

  /**
   * @brief Total wall-clock duration of entire execution (ms).
   *
   * From execute() entry to return: ops time + delays + overhead.
   * Monotonic; accounts for real-world variability.
   * Compare to policy expectations for performance tuning.
   */
  int64_t total_time_ms;
} SocketRetry_Stats;

/* ============================================================================
 * Context Creation and Destruction
 * ============================================================================
 */

/**
 * @brief Create a new retry context instance with optional custom policy.
 * @ingroup utilities
 *
 * Allocates and initializes a new SocketRetry_T instance for managing retry
 * logic with exponential backoff and jitter. The instance tracks state,
 * statistics, and policy for retryable operations.
 *
 * If policy is NULL, conservative defaults are applied suitable for most
 * transient failures (e.g., network timeouts, resource contention). Custom
 * policies allow tuning for specific use cases like aggressive retries or long
 * backoffs.
 *
 * @param[in] policy Optional retry policy (NULL for defaults). Must contain
 * valid values if provided; invalid parameters raise exception.
 *
 * @return New SocketRetry_T instance.
 *
 * @throws SocketRetry_Failed on allocation failure (ENOMEM) or invalid policy
 * (e.g., negative delays, multiplier <=0, jitter out of [0,1]).
 *
 * @threadsafe Yes - allocation is atomic; produces independent, isolated
 * instances. Multiple threads may create instances concurrently without
 * synchronization.
 *
 * ## Usage Example
 *
 * @code{.c}
 * TRY {
 *     // Default policy for general use
 *     SocketRetry_T retry = SocketRetry_new(NULL);
 *
 *     // Custom policy for more aggressive retries
 *     SocketRetry_Policy custom;
 *     SocketRetry_policy_defaults(&custom);
 *     custom.max_attempts = 5;
 *     custom.initial_delay_ms = 50;
 *     custom.multiplier = 1.5;  // Gentler backoff
 *     SocketRetry_T aggressive = SocketRetry_new(&custom);
 *
 *     // Use: e.g., SocketRetry_execute(aggressive, operation, NULL, ctx);
 *
 *     SocketRetry_free(&aggressive);
 *     SocketRetry_free(&retry);
 * } EXCEPT(SocketRetry_Failed) {
 *     // Handle allocation/policy error
 *     fprintf(stderr, "Retry context creation failed\n");
 * } END_TRY;
 * @endcode
 *
 * ## Error Handling Patterns
 *
 * Wrap creation in TRY/EXCEPT for production code:
 *
 * @code{.c}
 * TRY {
 *     SocketRetry_T retry = SocketRetry_new(NULL);
 *     // Proceed with retries...
 *     SocketRetry_free(&retry);
 *     RETURN;  // Success path
 * } EXCEPT(SocketRetry_Failed) {
 *     // Log or propagate error
 *     RERAISE;
 * } END_TRY;
 * @endcode
 *
 * @complexity O(1) - constant time initialization and memory allocation.
 *
 * @note Internal Arena allocation; lifetime tied to SocketRetry_free().
 * @warning Policy validation occurs at creation; invalid values not partially
 * applied.
 *
 * @see SocketRetry_policy_defaults() to initialize policy structure.
 * @see SocketRetry_free() for proper cleanup to avoid leaks.
 * @see SocketRetry_set_policy() for runtime policy updates.
 * @see SocketRetry_execute() primary usage entry point.
 * @see docs/ERROR_HANDLING.md for exception best practices.
 */

/**
 * @brief Dispose of a retry context and release all associated resources.
 * @ingroup utilities
 *
 * Frees the SocketRetry_T instance, clearing internal arenas, statistics,
 * timers, and any allocated state. The provided pointer is set to NULL
 * post-free to prevent accidental use-after-free errors.
 *
 * Always pair with SocketRetry_new() for resource lifecycle management.
 * Omitting this leads to memory leaks and potential resource exhaustion.
 *
 * @param[in,out] retry Pointer to SocketRetry_T (set to NULL on success).
 *
 * @threadsafe No - the instance must not be accessed by other threads during
 * free. Caller responsible for synchronization if multi-threaded.
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketRetry_T retry = SocketRetry_new(NULL);
 * if (retry) {
 *     // Perform retries...
 *     int result = SocketRetry_execute_simple(retry, my_operation, ctx);
 *     // Check result...
 * }
 * SocketRetry_free(&retry);  // Always free, even if new() succeeded
 * assert(retry == NULL);     // Verified nullified
 * @endcode
 *
 * ## Safe Cleanup in TRY Blocks
 *
 * @code{.c}
 * TRY {
 *     SocketRetry_T retry = SocketRetry_new(NULL);
 *     // Operations...
 *     RETURN;  // Success - free in FINALLY
 * } EXCEPT(SocketRetry_Failed) {
 *     // Error path
 * } FINALLY {
 *     SocketRetry_free(&retry);  // Ensures cleanup regardless of path
 * } END_TRY;
 * @endcode
 *
 * @complexity O(1) - constant time, but may involve O(n) arena clear if many
 * allocations.
 *
 * @note Internal arenas are disposed; no need for manual Arena_clear/dispose.
 * @warning Do not access retry after free; segfault or undefined behavior.
 * @warning Freeing NULL is safe (no-op).
 *
 * @see SocketRetry_new() counterpart allocation function.
 * @see Arena_dispose() underlying mechanism for memory cleanup.
 * @see SocketRetry_reset() for reusing without full free (statistics only).
 * @see docs/MEMORY.md for arena-based allocation patterns (if exists).
 */

/* ============================================================================
 * Retry Execution
 * ============================================================================
 */

/**
 * @brief Execute a retryable operation with configurable backoff and retry
 * logic.
 * @ingroup utilities
 *
 * Invokes the provided operation callback repeatedly until success or policy
 * limits are exceeded. Implements full exponential backoff with jitter to
 * handle transient failures gracefully, preventing overload during outage
 * storms.
 *
 * Execution flow:
 * 1. Call operation with attempt=1 (no initial delay).
 * 2. On failure (non-zero return), invoke should_retry (if provided).
 * 3. If retry approved, compute and sleep jittered backoff delay.
 * 4. Repeat up to max_attempts or until should_retry denies further attempts.
 * 5. Update statistics for monitoring.
 *
 * Does not throw exceptions; failures propagate as return codes from
 * operation. Suitable for network ops, locks, or any idempotent retryable
 * action.
 *
 * Backoff computation:
 * - base = policy.initial_delay_ms * pow(policy.multiplier, attempt-1)
 * - capped = MIN(base, policy.max_delay_ms)
 * - jittered = capped * (1 + policy.jitter * (2*rand_uniform() - 1))  //
 * [-jitter, +jitter]
 *
 * @param[in] retry Initialized SocketRetry_T context (non-NULL).
 * @param[in] operation Non-NULL callback implementing the retryable operation.
 * Must return 0 on success, errno-like code on failure.
 * @param[in] should_retry Optional NULL callback for custom retry decisions.
 * If NULL, all failures retry up to max_attempts.
 * @param[in] context Opaque user data passed unchanged to callbacks.
 *
 * @return 0 on eventual success, or last operation error code on
 * exhaustion/failure.
 *
 * @threadsafe No - modifies internal state (stats, counters); serialize calls
 * per instance.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Define operation (e.g., connect with retry)
 * int connect_op(void *ctx, int attempt) {
 *     ConnectCtx *cctx = (ConnectCtx*)ctx;
 *     SOCKET_LOG_DEBUG_MSG("Connect attempt %d", attempt);
 *     int res = connect(cctx->fd, cctx->addr, cctx->addrlen);
 *     return (res < 0) ? errno : 0;
 * }
 *
 * // Optional should-retry (e.g., only retryable errors)
 * int should_retry_connect(int err, int attempt, void *ctx) {
 *     (void)ctx; (void)attempt;
 *     return SocketError_is_retryable_errno(err);  // e.g., ETIMEDOUT,
 * ECONNREFUSED
 * }
 *
 * // Execute
 * SocketRetry_T retry = SocketRetry_new(NULL);
 * ConnectCtx ctx = { .fd = sockfd, .addr = &addr, .addrlen = addrlen };
 * int result = SocketRetry_execute(retry, connect_op, should_retry_connect,
 * &ctx); if (result != 0) { SOCKET_LOG_ERROR_MSG("Connect failed after
 * retries: %s", strerror(result));
 * }
 * SocketRetry_get_stats(retry, &stats);  // Log metrics
 * SocketRetry_free(&retry);
 * @endcode
 *
 * ## Simple Without Custom Retry Logic
 *
 * Use SocketRetry_execute_simple() for always-retry cases:
 *
 * @code{.c}
 * int simple_result = SocketRetry_execute_simple(retry, connect_op, &ctx);
 * @endcode
 *
 * @complexity O(max_attempts * operation_time + total_delay) - bounded by
 * policy. Worst case: policy.max_attempts loops + sleeps.
 *
 * @note Sleeps use nanosleep with monotonic time; EINTR handled by resuming.
 * @note Random jitter seeded internally; uniform distribution for fairness.
 * @warning Operation must be idempotent; partial states may accumulate.
 * @warning Long max_delay_ms + high attempts can block thread significantly.
 *
 * @see SocketRetry_execute_simple() convenience wrapper (always retries).
 * @see SocketRetry_Operation callback requirements and examples.
 * @see SocketRetry_ShouldRetry for advanced error filtering.
 * @see SocketRetry_Policy tuning parameters and defaults.
 * @see SocketRetry_get_stats() post-execution metrics.
 * @see SocketError_is_retryable_errno() helper for should_retry.
 * @see Socket_get_monotonic_ms() timing backend.
 * @see docs/ERROR_HANDLING.md exception-free error propagation.
 */

/**
 * @brief Simplified execution of retryable operation, retrying all failures.
 * @ingroup utilities
 *
 * Wrapper for SocketRetry_execute() that automatically retries every non-zero
 * return from operation up to max_attempts, without custom should_retry logic.
 * Useful for operations where all errors are potentially transient (e.g.,
 * simple I/O retries without distinguishing error types).
 *
 * Behaves identically to SocketRetry_execute(retry, operation, NULL, context).
 *
 * @param[in] retry Initialized non-NULL SocketRetry_T context.
 * @param[in] operation Non-NULL callback for the retryable operation.
 * @param[in] context User data passed to operation (unchanged).
 *
 * @return 0 on success after retries, or final error code from operation.
 *
 * @threadsafe No - updates retry state; concurrent calls undefined.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Simple DNS resolution retry (all failures retryable)
 * int dns_resolve_op(void *ctx, int attempt) {
 *     DNSCtx *dctx = (DNSCtx*)ctx;
 *     return SocketDNS_resolve_sync(dctx->dns, dctx->host, dctx->port, NULL,
 * 5000);
 *     // Returns 0 success, error code failure
 * }
 *
 * SocketRetry_T retry = SocketRetry_new(NULL);
 * DNSCtx ctx = { .dns = dns, .host = "example.com", .port = 443 };
 * int dns_err = SocketRetry_execute_simple(retry, dns_resolve_op, &ctx);
 * if (dns_err != 0) {
 *     // Final failure after retries
 * }
 * SocketRetry_Stats stats;
 * SocketRetry_get_stats(retry, &stats);
 * SOCKET_LOG_INFO_MSG("DNS retries: %d attempts, %lld ms total",
 * stats.attempts, stats.total_time_ms); SocketRetry_free(&retry);
 * @endcode
 *
 * @complexity O(max_attempts * op_time + delays) - same as full execute.
 *
 * @note Equivalent to passing NULL should_retry; all errors retried.
 * @warning Lacks error filtering; non-retryable errors (e.g., EINVAL) wasted
 * attempts. Use full SocketRetry_execute() for selective retries.
 *
 * @see SocketRetry_execute() for advanced control with should_retry.
 * @see SocketRetry_Operation defining idempotent operations.
 * @see SocketRetry_ShouldRetry when custom logic needed.
 * @see SocketRetry_get_stats() to inspect retry outcomes.
 */

/* ============================================================================
 * Statistics and State
 * ============================================================================
 */

/**
 * @brief Copy retry statistics from the last execution into user structure.
 * @ingroup utilities
 *
 * Captures performance and outcome metrics from the most recent
 * SocketRetry_execute() or _simple() invocation. Useful for logging,
 * monitoring, alerting on high retry counts, or debugging failure patterns.
 *
 * Stats include attempts made, final error, delay time, and total execution
 * time. Initialized to zero if no prior execution or after reset().
 *
 * @param[in] retry Non-NULL SocketRetry_T to query (const access).
 * @param[out] stats Non-NULL pointer to SocketRetry_Stats to populate.
 *
 * @threadsafe Partial - read-only; safe if no concurrent execute/reset.
 * Concurrent modifications (e.g., execute running) may yield inconsistent
 * snapshot.
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketRetry_T retry = SocketRetry_new(NULL);
 * // ... execute retries ...
 * int result = SocketRetry_execute_simple(retry, op, ctx);
 *
 * SocketRetry_Stats stats;
 * SocketRetry_get_stats(retry, &stats);
 *
 * if (result != 0) {
 *     SOCKET_LOG_WARN_MSG("Retry failed: %d attempts, last err=%d, total
 * time=%lld ms", stats.attempts, stats.last_error, stats.total_time_ms); }
 * else { SOCKET_LOG_INFO_MSG("Success after %d attempts, delays totaled %lld
 * ms", stats.attempts - 1, stats.total_delay_ms);
 * }
 * SocketRetry_free(&retry);
 * @endcode
 *
 * ## Monitoring Integration
 *
 * @code{.c}
 * SocketRetry_Stats stats;
 * SocketRetry_get_stats(retry, &stats);
 * SocketMetrics_increment(METRIC_RETRY_ATTEMPTS, stats.attempts);
 * if (stats.attempts > policy.max_attempts / 2) {
 *     // Alert on high retry rate
 * }
 * @endcode
 *
 * @complexity O(1) - simple memory copy of fixed-size struct.
 *
 * @note stats populated atomically but reflects snapshot; use reset() for
 * baselines.
 * @note Zeroed fields indicate no execution or reset state.
 * @warning Do not modify stats struct; it's output-only.
 *
 * @see SocketRetry_Stats structure fields and semantics.
 * @see SocketRetry_execute() or SocketRetry_execute_simple() populating the
 * stats.
 * @see SocketRetry_reset() to clear for next measurement cycle.
 * @see SocketMetrics_increment() for integrating with library metrics.
 */

/**
 * @brief Reset internal state and statistics for fresh retry sequences.
 * @ingroup utilities
 *
 * Clears counters, error states, timing accumulators, and transient data
 * from previous executions, restoring the context to "newly created" state
 * minus policy (which persists). Enables reusing the same instance across
 * multiple independent retry operations without full reallocation.
 *
 * What is reset:
 * - attempts = 0
 * - last_error = 0
 * - total_delay_ms = 0
 * - total_time_ms = 0
 * - Any internal attempt trackers or RNG state
 *
 * Policy unchanged; combine with set_policy() for full reconfiguration.
 *
 * @param[in] retry Non-NULL SocketRetry_T to reset.
 *
 * @threadsafe No - modifies state; call only when idle (no concurrent
 * execute).
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketRetry_T retry = SocketRetry_new(NULL);
 *
 * // First retry sequence (e.g., connect)
 * int connect_res = SocketRetry_execute_simple(retry, connect_op, &ctx1);
 * SocketRetry_Stats stats1;
 * SocketRetry_get_stats(retry, &stats1);  // Capture first metrics
 *
 * // Reset for second independent sequence (e.g., DNS)
 * SocketRetry_reset(retry);
 *
 * int dns_res = SocketRetry_execute_simple(retry, dns_op, &ctx2);
 * SocketRetry_Stats stats2;
 * SocketRetry_get_stats(retry, &stats2);  // Fresh metrics
 *
 * SocketRetry_free(&retry);
 * @endcode
 *
 * ## With Policy Change
 *
 * @code{.c}
 * SocketRetry_reset(retry);  // Clear stats
 * SocketRetry_set_policy(retry, &new_policy);  // Update behavior
 * // Now execute with new config and clean slate
 * @endcode
 *
 * @complexity O(1) - zeroing fixed structures and counters.
 *
 * @note Policy preserved; use set_policy() + reset() for complete refresh.
 * @note Does not deallocate; cheaper than new/free cycle for frequent reuse.
 * @warning Reset during execute() corrupts state; ensure serialization.
 *
 * @see SocketRetry_get_stats() read stats before reset.
 * @see SocketRetry_execute() benefits from reset between sequences.
 * @see SocketRetry_set_policy() pair for dynamic reconfiguration.
 * @see SocketRetry_free() for full lifecycle end.
 */

/**
 * @brief Copy current active policy settings into user-provided structure.
 * @ingroup utilities
 *
 * Reads the policy currently in effect on the retry context (from new(),
 * set_policy(), or defaults) and populates the output structure. Allows
 * inspection for logging, configuration verification, or dynamic adaptation
 * logic.
 *
 * Output reflects validated, effective values (e.g., clamped jitter).
 *
 * @param[in] retry Non-NULL const SocketRetry_T to query.
 * @param[out] policy Non-NULL SocketRetry_Policy to populate with current
 * config.
 *
 * @threadsafe Partial - const read; safe unless concurrent set_policy()/new().
 * Races may yield inconsistent but valid policy snapshot.
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketRetry_T retry = SocketRetry_new(NULL);
 *
 * // Verify or log current policy
 * SocketRetry_Policy current;
 * SocketRetry_get_policy(retry, &current);
 * SOCKET_LOG_INFO_MSG("Current max_attempts: %d, jitter: %.2f",
 * current.max_attempts, current.jitter);
 *
 * // Adaptive logic example
 * if (current.max_attempts < 5 && load_is_low()) {
 *     SocketRetry_Policy lenient;
 *     SocketRetry_policy_defaults(&lenient);
 *     lenient.max_attempts = 10;
 *     SocketRetry_set_policy(retry, &lenient);
 * }
 *
 * SocketRetry_free(&retry);
 * @endcode
 *
 * @complexity O(1) - struct copy.
 *
 * @note policy filled with runtime values, not compile-time defaults.
 * @note No validation on output; values guaranteed valid by prior sets.
 * @warning Concurrent set_policy() may change during copy (rare race).
 *
 * @see SocketRetry_Policy populated structure details.
 * @see SocketRetry_set_policy() to modify policy.
 * @see SocketRetry_new() initial policy source.
 * @see SocketRetry_policy_defaults() for default initialization.
 */

/**
 * @brief Dynamically update retry policy on an existing context.
 * @ingroup utilities
 *
 * Replaces current policy with new settings, validating and applying
 * immediately. Affects all future SocketRetry_execute() calls but not
 * in-progress ones. Useful for adaptive behavior, e.g., tightening limits
 * during high load.
 *
 * Validation checks:
 * - policy non-NULL
 * - max_attempts >=0
 * - delays >0
 * - multiplier >0
 * - 0 <= jitter <=1
 * Invalid configs raise exception without partial application.
 *
 * @param[in] retry Non-NULL SocketRetry_T to reconfigure.
 * @param[in] policy Non-NULL new SocketRetry_Policy settings.
 *
 * @throws SocketRetry_Failed on NULL inputs or invalid policy values.
 * Examples: negative delays, multiplier <=0, jitter out of [0,1].
 *
 * @threadsafe No - state mutation; ensure no concurrent execute()/get_stats().
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketRetry_T retry = SocketRetry_new(NULL);
 * // Initial use...
 *
 * // Adapt policy based on load
 * if (high_load_detected()) {
 *     TRY {
 *         SocketRetry_Policy strict;
 *         SocketRetry_policy_defaults(&strict);
 *         strict.max_attempts = 1;  // No retries during overload
 *         strict.initial_delay_ms = 1000;  // Longer initial wait
 *         SocketRetry_set_policy(retry, &strict);
 *     } EXCEPT(SocketRetry_Failed) {
 *         // Invalid policy or other error
 *     } END_TRY;
 * }
 *
 * // Continue using updated retry...
 * SocketRetry_free(&retry);
 * @endcode
 *
 * @complexity O(1) - parameter validation and assignment.
 *
 * @note Ongoing executions use old policy; new starts fresh.
 * @note Statistics unchanged; reset() if needed for new baseline.
 * @warning Frequent updates in hot path may impact performance.
 *
 * @see SocketRetry_Policy valid ranges and field docs.
 * @see SocketRetry_get_policy() to read current config.
 * @see SocketRetry_new() initial policy setting.
 * @see SocketRetry_reset() complement for full refresh.
 * @see SocketRetry_policy_defaults() source for base values.
 */

/* ============================================================================
 * Policy Helpers
 * ============================================================================
 */

/**
 * @brief Populate SocketRetry_Policy with safe, conservative default values.
 * @ingroup utilities
 *
 * Initializes the policy structure with parameters tuned for typical transient
 * failures in network or resource operations. Defaults balance responsiveness
 * and stability: quick initial retries with gradual backoff to avoid overload.
 *
 * Defaults sourced from compile-time macros (overridable before inclusion).
 * After init, customize as needed before passing to SocketRetry_new() or
 * set_policy().
 *
 * ## Default Values Table
 *
 * | Field              | Default Value | Description |
 * |--------------------|---------------|-------------|
 * | max_attempts       | 3             | Limited retries prevent infinite
 * loops | | initial_delay_ms   | 100 ms        | Quick first retry for fast
 * recovery | | max_delay_ms       | 30000 ms (30s)| Cap prevents indefinite
 * blocking | | multiplier         | 2.0           | Standard exponential
 * growth | | jitter             | 0.25          | Moderate randomization vs
 * thundering herd |
 *
 * @param[out] policy Non-NULL pointer to SocketRetry_Policy to initialize.
 *
 * @threadsafe Yes - pure function; no state mutation or allocation.
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketRetry_Policy policy;
 * SocketRetry_policy_defaults(&policy);
 *
 * // Customize for aggressive DNS retries
 * policy.max_attempts = 10;
 * policy.initial_delay_ms = 200;
 * policy.jitter = 0.5;  // More randomization
 *
 * SocketRetry_T retry = SocketRetry_new(&policy);
 * // Use retry...
 * SocketRetry_free(&retry);
 * @endcode
 *
 * @complexity O(1) - simple assignment.
 *
 * @note Does not validate values; validation deferred to
 * SocketRetry_new()/set_policy().
 * @note Compile-time overrides affect these defaults globally.
 *
 * @see SocketRetry_Policy structure and field documentation.
 * @see SOCKET_RETRY_DEFAULT_* macros for overriding defaults.
 * @see SocketRetry_new() consumer of initialized policy.
 * @see SocketRetry_set_policy() for runtime application.
 * @see SocketRetry_calculate_delay() using policy params.
 */

/**
 * @brief Compute jittered exponential backoff delay for a given retry attempt.
 * @ingroup utilities
 *
 * Standalone function mirroring the delay calculation in
 * SocketRetry_execute(). Useful for pre-computing delays, logging expected
 * wait times, or integrating with custom schedulers/timers outside the full
 * retry framework.
 *
 * Applies full policy: exponential growth, capping, and randomization.
 * Returns -1 for invalid inputs to signal errors without exceptions.
 *
 * Detailed formula:
 * 1. base_delay = policy->initial_delay_ms * pow(policy->multiplier, attempt
 * - 1.0)
 * 2. capped_delay = MIN(base_delay, policy->max_delay_ms)
 * 3. jitter_factor = 1.0 + policy->jitter * (2.0 * rand_uniform_01() - 1.0) //
 * [-jitter, +jitter]
 * 4. final_delay = capped_delay * jitter_factor  (always >=0)
 *
 * Uses high-quality uniform random [0,1) for jitter; seed via srand() or
 * equivalent.
 *
 * @param[in] policy Non-NULL SocketRetry_Policy with valid parameters.
 * @param[in] attempt 1-based attempt number (1=first retry delay).
 *
 * @return Delay in ms (>=0) or -1 on error (NULL policy, attempt <=0 or
 * >SOCKET_RETRY_MAX_ATTEMPTS).
 *
 * @threadsafe Yes - pure function; thread-safe if rand() implementation is.
 * Note: shared rand() state requires external synchronization if unseeded.
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketRetry_Policy policy;
 * SocketRetry_policy_defaults(&policy);
 *
 * // Preview delays for attempts 1-3
 * for (int att = 1; att <= 3; ++att) {
 *     int delay = SocketRetry_calculate_delay(&policy, att);
 *     if (delay >= 0) {
 *         SOCKET_LOG_INFO_MSG("Attempt %d delay: %d ms", att, delay);
 *     } else {
 *         SOCKET_LOG_WARN_MSG("Invalid attempt %d", att);
 *     }
 * }
 *
 * // Expected approx: att1 ~100ms +/- jitter, att2 ~200ms, att3 ~400ms
 * capped/randomized
 * @endcode
 *
 * ## Custom Policy Preview
 *
 * @code{.c}
 * SocketRetry_Policy aggressive = { .max_attempts=5, .initial_delay_ms=10,
 * .max_delay_ms=1000, .multiplier=1.5, .jitter=0.1 }; int delay3 =
 * SocketRetry_calculate_delay(&aggressive, 3);  // ~22.5 ms base + jitter
 * @endcode
 *
 * @complexity O(1) - fixed math operations + pow() and rand() calls.
 *
 * @note pow() may have floating-point precision issues for large exponents;
 * capped mitigates.
 * @note rand_uniform_01() internal; equivalent to rand()/RAND_MAX.
 * @warning Negative policy values yield undefined (but clamped) results.
 * @warning High multiplier + attempts can cause pow() overflow; use double
 * safely.
 *
 * @see SocketRetry_Policy fields affecting computation.
 * @see SocketRetry_execute() consumer of this logic in loop.
 * @see <math.h> pow() and <stdlib.h> rand() dependencies.
 * @see Socket_get_monotonic_ms() for measuring actual delays.
 */

/** @} */

/* ============================================================================
 * Function Declarations
 * ============================================================================
 */

/**
 * Initialize a SocketRetry_Policy with default values.
 */
extern void SocketRetry_policy_defaults (SocketRetry_Policy *policy);

/**
 * Create a new retry context.
 */
extern T SocketRetry_new (const SocketRetry_Policy *policy);

/**
 * Free a retry context.
 */
extern void SocketRetry_free (T *retry);

/**
 * Execute an operation with retries.
 */
extern int SocketRetry_execute (T retry, SocketRetry_Operation operation,
                                SocketRetry_ShouldRetry should_retry,
                                void *context);

/**
 * Execute an operation with default retry logic.
 */
extern int SocketRetry_execute_simple (T retry, SocketRetry_Operation operation,
                                       void *context);

/**
 * Get statistics from last execution.
 */
extern void SocketRetry_get_stats (const T retry, SocketRetry_Stats *stats);

/**
 * Reset context for reuse.
 */
extern void SocketRetry_reset (T retry);

/**
 * Get current policy.
 */
extern void SocketRetry_get_policy (const T retry, SocketRetry_Policy *policy);

/**
 * Update policy.
 */
extern void SocketRetry_set_policy (T retry, const SocketRetry_Policy *policy);

/**
 * Calculate delay for a given attempt.
 */
extern int SocketRetry_calculate_delay (const SocketRetry_Policy *policy,
                                        int attempt);

#undef T
#endif /* SOCKETRETRY_INCLUDED */
