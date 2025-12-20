/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_RATELIMIT_INCLUDED
#define SOCKETSIMPLE_RATELIMIT_INCLUDED

/**
 * @file SocketSimple-ratelimit.h
 * @brief Simple token bucket rate limiting.
 *
 * Thread-safe rate limiter using the token bucket algorithm.
 *
 * Example:
 * @code
 * // Create a limiter: 100 requests/sec with burst of 10
 * SocketSimple_RateLimit_T limiter = Socket_simple_ratelimit_new(100, 10);
 * if (!limiter) {
 *     fprintf(stderr, "Error: %s\n", Socket_simple_error());
 *     return 1;
 * }
 *
 * // Try to acquire (non-blocking)
 * if (Socket_simple_ratelimit_try_acquire(limiter, 1)) {
 *     // Request allowed
 *     handle_request();
 * } else {
 *     // Rate limited - get wait time
 *     int wait = Socket_simple_ratelimit_wait_ms(limiter, 1);
 *     if (wait > 0) {
 *         usleep(wait * 1000);
 *         Socket_simple_ratelimit_try_acquire(limiter, 1);
 *         handle_request();
 *     }
 * }
 *
 * Socket_simple_ratelimit_free(&limiter);
 * @endcode
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Opaque Handle Types
 *============================================================================*/

/**
 * @brief Opaque rate limiter handle.
 */
typedef struct SocketSimple_RateLimit *SocketSimple_RateLimit_T;

/*============================================================================
 * Rate Limiter Lifecycle
 *============================================================================*/

/**
 * @brief Create a new rate limiter.
 *
 * Uses token bucket algorithm. Tokens refill at rate tokens_per_sec.
 * Bucket can hold up to burst tokens for handling bursts.
 *
 * @param tokens_per_sec Token refill rate.
 * @param burst Maximum bucket size (burst capacity).
 * @return Rate limiter handle on success, NULL on error.
 */
extern SocketSimple_RateLimit_T Socket_simple_ratelimit_new(int tokens_per_sec,
                                                             int burst);

/**
 * @brief Free rate limiter.
 *
 * Sets *limit to NULL after freeing.
 *
 * @param limit Pointer to limiter handle.
 */
extern void Socket_simple_ratelimit_free(SocketSimple_RateLimit_T *limit);

/*============================================================================
 * Token Operations
 *============================================================================*/

/**
 * @brief Try to acquire tokens (non-blocking).
 *
 * Returns immediately whether tokens were acquired.
 *
 * @param limit Rate limiter handle.
 * @param tokens Number of tokens to acquire.
 * @return 1 if acquired, 0 if not enough tokens.
 */
extern int Socket_simple_ratelimit_try_acquire(SocketSimple_RateLimit_T limit,
                                                int tokens);

/**
 * @brief Get time to wait for tokens to become available.
 *
 * Does not consume tokens; just calculates wait time.
 *
 * @param limit Rate limiter handle.
 * @param tokens Number of tokens needed.
 * @return Milliseconds to wait, 0 if available now, -1 on error.
 */
extern int Socket_simple_ratelimit_wait_ms(SocketSimple_RateLimit_T limit,
                                            int tokens);

/**
 * @brief Acquire tokens, blocking until available.
 *
 * Blocks until enough tokens are available, then consumes them.
 *
 * @param limit Rate limiter handle.
 * @param tokens Number of tokens to acquire.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_ratelimit_acquire(SocketSimple_RateLimit_T limit,
                                            int tokens);

/**
 * @brief Acquire with timeout.
 *
 * @param limit Rate limiter handle.
 * @param tokens Number of tokens to acquire.
 * @param timeout_ms Maximum time to wait.
 * @return 1 if acquired, 0 if timeout, -1 on error.
 */
extern int Socket_simple_ratelimit_acquire_timeout(
    SocketSimple_RateLimit_T limit,
    int tokens,
    int timeout_ms);

/*============================================================================
 * Rate Limiter State
 *============================================================================*/

/**
 * @brief Get current available tokens.
 *
 * @param limit Rate limiter handle.
 * @return Number of available tokens.
 */
extern int Socket_simple_ratelimit_available(SocketSimple_RateLimit_T limit);

/**
 * @brief Reset rate limiter to full bucket.
 *
 * @param limit Rate limiter handle.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_ratelimit_reset(SocketSimple_RateLimit_T limit);

/**
 * @brief Update rate limiter parameters.
 *
 * @param limit Rate limiter handle.
 * @param tokens_per_sec New refill rate.
 * @param burst New burst capacity.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_ratelimit_set_rate(SocketSimple_RateLimit_T limit,
                                             int tokens_per_sec,
                                             int burst);

/*============================================================================
 * Statistics
 *============================================================================*/

/**
 * @brief Rate limiter statistics.
 */
typedef struct SocketSimple_RateLimitStats {
    uint64_t total_acquired;     /**< Total tokens acquired */
    uint64_t total_rejected;     /**< Total acquire attempts rejected */
    uint64_t total_waited_ms;    /**< Total time spent waiting */
} SocketSimple_RateLimitStats;

/**
 * @brief Get rate limiter statistics.
 *
 * @param limit Rate limiter handle.
 * @param stats Output statistics.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_ratelimit_get_stats(SocketSimple_RateLimit_T limit,
                                              SocketSimple_RateLimitStats *stats);

/**
 * @brief Reset statistics counters.
 *
 * @param limit Rate limiter handle.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_ratelimit_reset_stats(SocketSimple_RateLimit_T limit);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_RATELIMIT_INCLUDED */
