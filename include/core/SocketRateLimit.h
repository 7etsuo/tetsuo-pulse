/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETRATELIMIT_INCLUDED
#define SOCKETRATELIMIT_INCLUDED

/**
 * @defgroup utilities Utilities
 * @brief Helper modules for rate limiting, retry logic, and metrics.
 * @{
 */

/**
 * @file SocketRateLimit.h
 * @ingroup utilities
 * @brief Token bucket rate limiter for controlling operation rates.
 *
 * Implements a token bucket rate limiter for controlling connection rates
 * and bandwidth throttling. The token bucket algorithm allows bursting
 * while enforcing average rates over time.
 *
 * Usage Example:
 * @code
 *   Arena_T arena = Arena_new();
 *   SocketRateLimit_T limiter = SocketRateLimit_new(arena, 100, 50);
 *
 *   if (SocketRateLimit_try_acquire(limiter, 1)) {
 *       // Proceed with rate-limited operation
 *   } else {
 *       int64_t wait_ms = SocketRateLimit_wait_time_ms(limiter, 1);
 *       if (wait_ms > 0) usleep(wait_ms * 1000);
 *   }
 *
 *   Arena_dispose(&arena);
 * @endcode
 */

#include "core/Arena.h"
#include "core/Except.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Opaque token bucket rate limiter instance.
 */
#define T SocketRateLimit_T
typedef struct T *T;

/**
 * @brief Exception type for rate limiter operation failures.
 */
extern const Except_T SocketRateLimit_Failed;

/**
 * @brief Create a new token bucket rate limiter.
 *
 * @param arena          Arena for memory allocation (NULL to use malloc)
 * @param tokens_per_sec Token refill rate (tokens added per second)
 * @param bucket_size    Maximum bucket capacity (0 = use tokens_per_sec)
 * Returns: New rate limiter instance
 * Raises: SocketRateLimit_Failed on allocation failure or invalid parameters
 *
 * @threadsafe Yes
 */
extern T SocketRateLimit_new (Arena_T arena, size_t tokens_per_sec,
                              size_t bucket_size);

/**
 * @brief Dispose of a rate limiter instance.
 *
 * @param limiter Pointer to the rate limiter handle (set to NULL on success)
 * Returns: void
 *
 * @threadsafe Conditional - safe from one thread at a time
 */
extern void SocketRateLimit_free (T *limiter);

/**
 * @brief Non-blocking attempt to acquire and consume tokens.
 *
 * @param limiter The rate limiter instance
 * @param tokens  Number of tokens required (0 always succeeds)
 * Returns: 1 if tokens were available and consumed, 0 if insufficient
 *
 * @threadsafe Yes
 */
extern int SocketRateLimit_try_acquire (T limiter, size_t tokens);

/**
 * @brief Calculate the time to wait until specified tokens are available.
 *
 * @param limiter The rate limiter instance
 * @param tokens  Number of tokens required
 * Returns: Milliseconds to wait (0 = available now, -1 if tokens exceed bucket capacity)
 *
 * @threadsafe Yes
 */
extern int64_t SocketRateLimit_wait_time_ms (T limiter, size_t tokens);

/**
 * @brief Get the number of currently available tokens in the bucket.
 *
 * @param limiter The rate limiter instance
 * Returns: Number of tokens available after time-based refill (capped at bucket_size)
 *
 * @threadsafe Yes
 */
extern size_t SocketRateLimit_available (T limiter);

/**
 * @brief Reset the token bucket to full capacity.
 *
 * @param limiter The rate limiter instance
 * Returns: void
 *
 * @threadsafe Yes
 */
extern void SocketRateLimit_reset (T limiter);

/**
 * @brief Dynamically reconfigure refill rate and bucket capacity.
 *
 * @param limiter        The rate limiter instance
 * @param tokens_per_sec New tokens per second rate (0 to leave unchanged)
 * @param bucket_size    New maximum bucket size (0 to leave unchanged)
 * Returns: void
 * Raises: SocketRateLimit_Failed if parameters invalid
 *
 * @threadsafe Yes
 */
extern void SocketRateLimit_configure (T limiter, size_t tokens_per_sec,
                                       size_t bucket_size);

/**
 * @brief Get the configured token refill rate in tokens per second.
 *
 * @param limiter The rate limiter instance
 * Returns: Current tokens_per_sec value (0 if instance invalid)
 *
 * @threadsafe Yes
 */
extern size_t SocketRateLimit_get_rate (T limiter);

/**
 * @brief Get the configured maximum bucket capacity (burst size).
 *
 * @param limiter The rate limiter instance
 * Returns: Current bucket_size value (0 if instance invalid)
 *
 * @threadsafe Yes
 */
extern size_t SocketRateLimit_get_bucket_size (T limiter);

/**
 * @brief Debug utility: count of live (allocated) rate limiter instances.
 *
 * Returns: Positive count of unfreed instances; 0 indicates no leaks
 *
 * @threadsafe Yes
 */
extern int SocketRateLimit_debug_live_count (void);

#undef T

/** @} */

#endif /* SOCKETRATELIMIT_INCLUDED */
