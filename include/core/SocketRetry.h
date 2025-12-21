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
 * @ingroup utilities
 *
 * Opaque handle for a retry context. Manages retry policy, state, statistics,
 * and backoff logic for retryable operations.
 *
 * @note Not thread-safe; designed for single-threaded use per instance.
 */
#define T SocketRetry_T
typedef struct T *T;

/**
 * @ingroup utilities
 *
 * Exception raised on allocation failures, invalid policy parameters, or
 * maximum retry attempts exhaustion.
 */
extern const Except_T SocketRetry_Failed;

/**
 * @ingroup utilities
 *
 * Configuration structure for retry policy. Defines parameters for exponential
 * backoff with jitter, controlling retry timing, attempt limits, and backoff
 * behavior.
 */
typedef struct SocketRetry_Policy
{
  int max_attempts;       /* Set to 0 for unlimited (hard-capped internally) */
  int initial_delay_ms;   /* First retry delay; 0 disables delays */
  int max_delay_ms;       /* Cap for exponential growth */
  double multiplier;      /* Exponential backoff factor (>1.0 recommended) */
  double jitter;          /* Randomization factor [0.0, 1.0] to prevent thundering herd */
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
#define SOCKET_RETRY_MAX_ATTEMPTS 10000  /* Hard safety cap to prevent infinite retries */
#endif

/**
 * @ingroup utilities
 *
 * User-defined callback implementing the core retryable operation. Invoked by
 * SocketRetry_execute() to perform the actual work that may fail transiently.
 *
 * @param context Opaque userdata from execute() call
 * @param attempt Current invocation count (1=initial, 2+=retries)
 * @return 0 on success, errno-like code on failure
 *
 * @note Must be idempotent; may be called multiple times with same state.
 * @note Use attempt parameter for progressive behavior (e.g., increasing timeouts).
 */
typedef int (*SocketRetry_Operation) (void *context, int attempt);

/**
 * @ingroup utilities
 *
 * Callback to decide whether to retry after an operation failure. If NULL,
 * all non-zero error returns are retried up to max_attempts.
 *
 * @param error Non-zero error code from the operation
 * @param attempt Attempt number that just failed (1-based)
 * @param context User-provided context pointer
 * @return 1 to continue retrying, 0 to stop
 */
typedef int (*SocketRetry_ShouldRetry) (int error, int attempt, void *context);

/**
 * @ingroup utilities
 *
 * Retry execution metrics and outcomes from a single retry sequence.
 */
typedef struct SocketRetry_Stats
{
  int attempts;           /* Total operation invocations (initial + retries) */
  int last_error;         /* Final error code (0 on success) */
  int64_t total_delay_ms; /* Sum of backoff delays (excludes op execution time) */
  int64_t total_time_ms;  /* Wall-clock from start to end (ops + delays + overhead) */
} SocketRetry_Stats;

extern void SocketRetry_policy_defaults (SocketRetry_Policy *policy);
extern T SocketRetry_new (const SocketRetry_Policy *policy);
extern void SocketRetry_free (T *retry);
extern int SocketRetry_execute (T retry, SocketRetry_Operation operation,
                                SocketRetry_ShouldRetry should_retry,
                                void *context);
extern int SocketRetry_execute_simple (T retry, SocketRetry_Operation operation,
                                       void *context);
extern void SocketRetry_get_stats (const T retry, SocketRetry_Stats *stats);
extern void SocketRetry_reset (T retry);
extern void SocketRetry_get_policy (const T retry, SocketRetry_Policy *policy);
extern void SocketRetry_set_policy (T retry, const SocketRetry_Policy *policy);
extern int SocketRetry_calculate_delay (const SocketRetry_Policy *policy,
                                        int attempt);

#undef T
#endif /* SOCKETRETRY_INCLUDED */
