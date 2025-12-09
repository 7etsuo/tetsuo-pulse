#ifndef SOCKETRATELIMIT_INCLUDED
#define SOCKETRATELIMIT_INCLUDED

/**
 * @defgroup utilities Utility Modules
 * @brief Helper modules for rate limiting, retry logic, and metrics.
 *
 * The Utilities group provides supporting functionality used across
 * the socket library. Key components include:
 * - SocketRateLimit (rate-limit): Token bucket rate limiting
 * - SocketRetry (retry): Exponential backoff retry logic
 * - SocketMetrics (metrics): Performance metrics collection
 * - SocketSYNProtect (syn-protect): SYN flood protection
 * - SocketIPTracker (ip-tracker): IP-based filtering
 *
 * @see foundation for core utilities.
 * @see connection_mgmt for connection-level rate limiting.
 * @see SocketRateLimit_T for token bucket implementation.
 * @see SocketRetry_T for retry logic.
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
 * Algorithm:
 * - Bucket holds tokens up to bucket_size (burst capacity)
 * - Tokens are added at tokens_per_sec rate
 * - Operations consume tokens; if insufficient, they are rate-limited
 * - Allows short bursts while maintaining average rate
 *
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - CLOCK_MONOTONIC support for timing
 * - POSIX threads (pthread) for thread safety
 *
 * Thread Safety:
 * - All operations are thread-safe via internal mutex
 * - Safe to share a single limiter across threads
 *
 * Debugging:
 * - Live instance count tracking for leak detection
 *   Use SocketRateLimit_debug_live_count() == 0 after cleanup
 *
 * Usage:
 *   Arena_T arena = Arena_new();
 *   SocketRateLimit_T limiter = SocketRateLimit_new(arena, 100, 50);
 *   // 100 tokens/sec, burst capacity of 50
 *
 *   if (SocketRateLimit_try_acquire(limiter, 1)) {
 *       // Allowed - proceed with operation
 *   } else {
 *       // Rate limited - wait or reject
 *       int64_t wait_ms = SocketRateLimit_wait_time_ms(limiter, 1);
 *   }
 *
 * @see SocketRateLimit_new() for limiter creation.
 * @see SocketRateLimit_try_acquire() for rate checking.
 */

#include "core/Arena.h"
#include "core/Except.h"
#include <stddef.h>
#include <stdint.h>

#define T SocketRateLimit_T
typedef struct T *T;

/* Exception types */
extern const Except_T SocketRateLimit_Failed; /**< Rate limiter operation failure */

/**
 * SocketRateLimit_new - Create a new token bucket rate limiter
 * @arena: Arena for memory allocation (NULL to use malloc)
 * @tokens_per_sec: Token refill rate (tokens added per second)
 * @bucket_size: Maximum bucket capacity (burst limit, 0 = use tokens_per_sec)
 *
 * Returns: New rate limiter instance
 * Raises: SocketRateLimit_Failed on allocation failure or invalid parameters
 * Thread-safe: Yes - returns new independent instance
 *
 * The bucket starts full (at bucket_size tokens).
 * Use bucket_size >= tokens_per_sec for reasonable burst handling.
 * If bucket_size is 0, defaults to tokens_per_sec (1 second burst).
 */
extern T SocketRateLimit_new (Arena_T arena, size_t tokens_per_sec,
                              size_t bucket_size);

/**
 * SocketRateLimit_free - Free a rate limiter
 * @limiter: Pointer to limiter (will be set to NULL)
 *
 * Thread-safe: Yes (acquires mutex during cleanup)
 *
 * Note: Only frees memory if allocated with malloc (arena == NULL).
 * Arena-allocated limiters are freed when arena is disposed.
 * Always destroys the mutex regardless of allocation method.
 */
extern void SocketRateLimit_free (T *limiter);

/**
 * SocketRateLimit_try_acquire - Try to consume tokens (non-blocking)
 * @limiter: Rate limiter instance
 * @tokens: Number of tokens to consume
 *
 * Returns: 1 if tokens acquired successfully, 0 if rate limited
 * Thread-safe: Yes - uses internal mutex
 *
 * Refills bucket based on elapsed time, then attempts to consume tokens.
 * Does not block - returns immediately with result.
 * Requesting 0 tokens always succeeds.
 */
extern int SocketRateLimit_try_acquire (T limiter, size_t tokens);

/**
 * SocketRateLimit_wait_time_ms - Calculate wait time for tokens
 * @limiter: Rate limiter instance
 * @tokens: Number of tokens needed
 *
 * Returns: Milliseconds to wait before tokens available, or 0 if immediate
 *          Returns -1 if tokens > bucket_size (impossible to acquire)
 * Thread-safe: Yes - uses internal mutex
 *
 * Does not consume tokens - just calculates wait time.
 * Returns 0 if tokens are already available.
 */
extern int64_t SocketRateLimit_wait_time_ms (T limiter, size_t tokens);

/**
 * SocketRateLimit_available - Get current available tokens
 * @limiter: Rate limiter instance
 *
 * Returns: Number of tokens currently available
 * Thread-safe: Yes - uses internal mutex
 *
 * Refills bucket based on elapsed time before returning count.
 */
extern size_t SocketRateLimit_available (T limiter);

/**
 * SocketRateLimit_reset - Reset limiter to full bucket
 * @limiter: Rate limiter instance
 *
 * Thread-safe: Yes - uses internal mutex
 *
 * Resets tokens to bucket_size and updates refill timestamp.
 * Useful after configuration changes or manual intervention.
 */
extern void SocketRateLimit_reset (T limiter);

/**
 * SocketRateLimit_configure - Reconfigure rate limiter
 * @limiter: Rate limiter instance
 * @tokens_per_sec: New token refill rate (0 to keep current)
 * @bucket_size: New bucket capacity (0 to keep current)
 *
 * Thread-safe: Yes - uses internal mutex
 *
 * Allows runtime reconfiguration. Current tokens are capped to new bucket_size.
 */
extern void SocketRateLimit_configure (T limiter, size_t tokens_per_sec,
                                       size_t bucket_size);

/**
 * SocketRateLimit_get_rate - Get current tokens per second rate
 * @limiter: Rate limiter instance
 *
 * Returns: Tokens per second rate (0 if invalid/shutdown)
 * Thread-safe: Yes - uses internal mutex
 */
extern size_t SocketRateLimit_get_rate (T limiter);

/**
 * SocketRateLimit_get_bucket_size - Get current bucket size
 * @limiter: Rate limiter instance
 *
 * Returns: Maximum bucket capacity (0 if invalid/shutdown)
 * Thread-safe: Yes - uses internal mutex
 */
extern size_t SocketRateLimit_get_bucket_size (T limiter);

/**
 * SocketRateLimit_debug_live_count - Debug function to get live instance count
 *
 * Returns: Number of currently allocated rate limiter instances
 * Thread-safe: Yes
 *
 * Use for leak detection and debugging. Should be 0 after all instances freed.
 */
extern int SocketRateLimit_debug_live_count (void);

#undef T

/** @} */ /* end of utilities group */

#endif /* SOCKETRATELIMIT_INCLUDED */
