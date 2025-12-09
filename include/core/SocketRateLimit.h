#ifndef SOCKETRATELIMIT_INCLUDED
#define SOCKETRATELIMIT_INCLUDED

/**
 * @defgroup utilities Utility Modules
 * @brief Helper modules for rate limiting, retry logic, and metrics.
 *
 * The Utilities group provides supporting functionality used across
 * the socket library for rate limiting, retry logic, metrics, and more.
 * Key components:
 * - SocketRateLimit (rate-limit): Token bucket rate limiting
 * - SocketRetry (retry): Exponential backoff retry logic
 * - SocketMetrics (metrics): Performance metrics collection
 *
 * Related modules for security features like SYN protection and IP tracking
 * are documented under @ref security.
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
 * Usage Example:
 * @code
 *   Arena_T arena = Arena_new();
 *   SocketRateLimit_T limiter = SocketRateLimit_new(arena, 100, 50);  // 100/sec, burst=50
 *   Arena_dispose(&arena);  // Don't forget cleanup!
 *
 *   // In a loop or before operation:
 *   if (SocketRateLimit_try_acquire(limiter, 1)) {
 *       // Proceed with rate-limited operation (e.g., accept connection)
 *   } else {
 *       // Rate limited: compute wait or reject
 *       int64_t wait_ms = SocketRateLimit_wait_time_ms(limiter, 1);
 *       if (wait_ms > 0 && wait_ms < 1000) {  // Avoid long sleeps
 * #include <unistd.h>  // For usleep
 *           usleep(wait_ms * 1000);  // Sleep in microseconds
 *           // Optionally retry: SocketRateLimit_try_acquire(limiter, 1)
 *       } else {
 *           // Reject or use longer backoff strategy
 *       }
 *   }
 * @endcode
 *
 * @note This example uses standard POSIX usleep(); integrate with your event loop's sleep.
 * @see SocketTimer in @ref event_system for timed events instead of sleeping.
 *
 * @see SocketRateLimit_new() for limiter creation.
 * @see SocketRateLimit_try_acquire() for rate checking.
 * @see @ref connection_mgmt for connection pool rate limiting integration.
 * @see @ref utilities for other rate limiting utilities.
 */

#include "core/Arena.h"
#include "core/Except.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Opaque handle for a token bucket rate limiter.
 * @ingroup utilities
 *
 * Represents a thread-safe rate limiter instance implementing the token bucket
 * algorithm for controlling rates of operations like connections or bandwidth.
 *
 * @see SocketRateLimit_new() to create an instance.
 * @see SocketRateLimit_free() to dispose of an instance.
 * @see @ref utilities "Utilities module" for related helpers.
 */
/**
 * @brief Opaque token bucket rate limiter instance.
 * @ingroup utilities
 *
 * Thread-safe rate limiter using token bucket algorithm for controlling
 * operation rates with support for bursting.
 *
 * @see SocketRateLimit_new() for creating instances.
 * @see SocketRateLimit_try_acquire() for token consumption.
 * @see SocketRateLimit_free() for cleanup.
 */
#define T SocketRateLimit_T
typedef struct T *T;

/**
 * @brief Exception type for rate limiter operation failures.
 * @ingroup utilities
 *
 * Raised on critical errors such as memory allocation failure, invalid
 * configuration parameters, or internal state corruption.
 *
 * @see Except_T in @ref foundation for exception handling.
 * @see SocketRateLimit_new() which may raise this.
 */
extern const Except_T SocketRateLimit_Failed;

/**
 * @brief Create a new token bucket rate limiter.
 * @ingroup utilities
 * @param arena Arena for memory allocation (NULL to use malloc).
 * @param tokens_per_sec Token refill rate (tokens added per second).
 * @param bucket_size Maximum bucket capacity (burst limit; 0 = use tokens_per_sec).
 * @return New rate limiter instance or NULL on failure.
 * @throws SocketRateLimit_Failed on allocation failure or invalid parameters (e.g., tokens_per_sec == 0).
 * @threadsafe Yes - creation is thread-safe; returns independent instance.
 *
 * The bucket starts full with bucket_size tokens (or defaults to tokens_per_sec if 0).
 * Recommend bucket_size >= tokens_per_sec to allow reasonable bursts without excessive limiting.
 *
 * @see SocketRateLimit_free() for disposal.
 * @see SocketRateLimit_T for type details.
 * @see Arena_T in @ref foundation for arena-based memory management.
 * @see @ref connection_mgmt "Connection Management" for pool integration examples.
 */
extern T SocketRateLimit_new (Arena_T arena, size_t tokens_per_sec,
                              size_t bucket_size);

/**
 * @brief Dispose of a rate limiter instance.
 * @ingroup utilities
 * @param limiter Pointer to the rate limiter handle (set to NULL on success).
 * @throws None.
 * @threadsafe Conditional - safe from one thread at a time; acquires internal mutex for cleanup.
 *
 * Releases resources held by the limiter, including the internal mutex.
 * If the instance was allocated via malloc (arena==NULL in new()), memory is freed;
 * otherwise, only the handle is cleared (arena will free on dispose).
 *
 * @note Always call after use to prevent resource leaks and allow accurate live count debugging.
 * @see SocketRateLimit_new() for allocation details.
 * @see Arena_dispose() for arena-managed cleanup.
 * @see SocketRateLimit_debug_live_count() for verifying no leaks.
 */
extern void SocketRateLimit_free (T *limiter);

/**
 * @brief Non-blocking attempt to acquire and consume tokens.
 * @ingroup utilities
 * @param limiter The rate limiter instance.
 * @param tokens Number of tokens required (0 always succeeds).
 * @return 1 if tokens were available and consumed, 0 if insufficient (rate-limited).
 * @throws None.
 * @threadsafe Yes - protected by internal mutex.
 *
 * Refills the token bucket based on wall-clock time elapsed since last operation.
 * If current tokens >= requested, deducts them and succeeds; otherwise fails immediately.
 * Ideal for high-throughput scenarios where blocking is unacceptable.
 *
 * @note Use in loops with backoff if frequent failures occur.
 * @see SocketRateLimit_wait_time_ms() for calculating delay before retry.
 * @see SocketRateLimit_available() to peek without consuming.
 * @see SocketRateLimit_new() for configuration impacting refill rate.
 */
extern int SocketRateLimit_try_acquire (T limiter, size_t tokens);

/**
 * @brief Calculate the time to wait until specified tokens are available.
 * @ingroup utilities
 * @param limiter The rate limiter instance.
 * @param tokens Number of tokens required.
 * @return Non-negative milliseconds to wait (0 = available now);

 *         -1 if impossible because tokens exceed maximum bucket capacity.
 * @throws None.
 * @threadsafe Yes - protected by internal mutex.
 *
 * Refills bucket virtually based on current time but does not consume tokens.

 * Useful for implementing polite backoff in retry loops without busy-waiting.
 *
 * @example
 *   if (!SocketRateLimit_try_acquire(limiter, 1)) {
 *     int64_t wait = SocketRateLimit_wait_time_ms(limiter, 1);
 *     if (wait > 0) Socket_usleep(wait * 1000);  // Sleep in us
 *   }
 *
 * @see SocketRateLimit_try_acquire() for actual consumption.
 * @see SocketRateLimit_available() for immediate check.
 * @see Socket_get_monotonic_ms() in @ref foundation for precise timing.
 */
extern int64_t SocketRateLimit_wait_time_ms (T limiter, size_t tokens);

/**
 * @brief Get the number of currently available tokens in the bucket.
 * @ingroup utilities
 * @param limiter The rate limiter instance.
 * @return Number of tokens available after time-based refill (capped at bucket_size).
 * @throws None.
 * @threadsafe Yes - protected by internal mutex.
 *
 * Updates token count based on elapsed time since last operation/refill.
 * Does not modify the bucket; purely observational.
 * Tokens accumulate at tokens_per_sec rate up to bucket_size.
 *
 * @note Value may change immediately after due to concurrent acquires.
 * @see SocketRateLimit_try_acquire() to consume tokens.
 * @see SocketRateLimit_wait_time_ms() if you need to wait for more.
 * @see SocketRateLimit_get_rate() for refill rate.
 */
extern size_t SocketRateLimit_available (T limiter);

/**
 * @brief Reset the token bucket to full capacity.
 * @ingroup utilities
 * @param limiter The rate limiter instance.
 * @throws None.
 * @threadsafe Yes - protected by internal mutex.
 *
 * Immediately sets available tokens to the configured bucket_size and
 * updates the refill timestamp to current time, simulating a fresh start.
 *
 * Use case: Recover from underutilization or after reconfiguring rates.
 *
 * @warning Can lead to burst traffic; use judiciously in production.
 * @see SocketRateLimit_configure() to change bucket_size or rate.
 * @see SocketRateLimit_available() to verify post-reset count.
 */
extern void SocketRateLimit_reset (T limiter);

/**
 * @brief Dynamically reconfigure refill rate and bucket capacity.
 * @ingroup utilities
 * @param limiter The rate limiter instance.
 * @param tokens_per_sec New tokens per second rate (0 to leave unchanged).
 * @param bucket_size New maximum bucket size (0 to leave unchanged).
 * @throws SocketRateLimit_Failed if parameters invalid (e.g., new rate == 0).
 * @threadsafe Yes - atomic update under mutex protection.
 *
 * Applies changes immediately. If bucket_size decreased, excess tokens are discarded.
 * If increased, current tokens remain until consumed/refilled.
 * Refill rate change affects future additions proportionally.
 *
 * @note Best used during low activity; may temporarily alter effective rate.
 * @see SocketRateLimit_reset() to refill to new capacity immediately.
 * @see SocketRateLimit_get_rate() and SocketRateLimit_get_bucket_size() to query current config.
 * @see SocketRateLimit_new() for static initial setup.
 */
extern void SocketRateLimit_configure (T limiter, size_t tokens_per_sec,
                                       size_t bucket_size);

/**
 * @brief Get the configured token refill rate in tokens per second.
 * @ingroup utilities
 * @param limiter The rate limiter instance.
 * @return Current tokens_per_sec value, or 0 if instance invalid.
 * @throws None.
 * @threadsafe Yes - mutex-protected read.
 *
 * Returns the rate set by SocketRateLimit_new() or last SocketRateLimit_configure().
 * Used for monitoring or dynamic adjustments.
 *
 * @see SocketRateLimit_get_bucket_size() companion getter.
 * @see SocketRateLimit_configure() to update rate.
 * @see SocketRateLimit_wait_time_ms() which uses this rate for calculations.
 */
extern size_t SocketRateLimit_get_rate (T limiter);

/**
 * @brief Get the configured maximum bucket capacity (burst size).
 * @ingroup utilities
 * @param limiter The rate limiter instance.
 * @return Current bucket_size value, or 0 if instance invalid.
 * @throws None.
 * @threadsafe Yes - mutex-protected read.
 *
 * Returns the maximum tokens the bucket can hold, set by new() or configure().
 * Determines burst allowance before rate limiting kicks in.
 *
 * @see SocketRateLimit_get_rate() companion getter.
 * @see SocketRateLimit_configure() to update capacity.
 * @see SocketRateLimit_available() which is always <= this value.
 */
extern size_t SocketRateLimit_get_bucket_size (T limiter);

/**
 * @brief Debug utility: count of live (allocated) rate limiter instances.
 * @ingroup utilities
 * @return Positive count of unfreed instances; 0 indicates no leaks.
 * @throws None.
 * @threadsafe Yes - uses atomic operations.
 *
 * Internal counter incremented in SocketRateLimit_new(), decremented in free().
 * Intended for test suites to verify complete cleanup.
 * Production code should not rely on this; use sanitizers/valgrind instead.
 *
 * @note Similar to Socket_debug_live_count() in core socket modules.
 * @see Test framework in src/test/ for usage examples.
 * @warning Debug-only; API may change without notice.
 */
extern int SocketRateLimit_debug_live_count (void);

#undef T

/** @} */ /* end of utilities group */

#endif /* SOCKETRATELIMIT_INCLUDED */
