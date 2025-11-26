#ifndef SOCKETRATELIMIT_PRIVATE_INCLUDED
#define SOCKETRATELIMIT_PRIVATE_INCLUDED

/**
 * SocketRateLimit-private.h - Private declarations for SocketRateLimit module
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Internal structure definitions for the token bucket rate limiter.
 * Include only from SocketRateLimit.c and related implementation files.
 * Do NOT include from public headers or user code.
 */

#include "core/Arena.h"
#include "core/SocketRateLimit.h"
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * Rate Limiter Constants
 * ============================================================================ */

/**
 * SOCKET_RATELIMIT_MIN_WAIT_MS - Minimum wait time in milliseconds
 *
 * When tokens are needed but calculated wait is zero, return this minimum
 * to ensure callers always wait at least a small amount.
 */
#ifndef SOCKET_RATELIMIT_MIN_WAIT_MS
#define SOCKET_RATELIMIT_MIN_WAIT_MS 1
#endif

/**
 * SOCKET_RATELIMIT_IMPOSSIBLE_WAIT - Return value for impossible token requests
 *
 * Returned by SocketRateLimit_wait_time_ms() when requested tokens exceed
 * bucket_size, making the request impossible to fulfill.
 */
#ifndef SOCKET_RATELIMIT_IMPOSSIBLE_WAIT
#define SOCKET_RATELIMIT_IMPOSSIBLE_WAIT (-1)
#endif

/**
 * SOCKET_RATELIMIT_MUTEX_INITIALIZED - Flag indicating mutex is ready
 */
#define SOCKET_RATELIMIT_MUTEX_INITIALIZED 1

/**
 * SOCKET_RATELIMIT_MUTEX_UNINITIALIZED - Flag indicating mutex not ready
 */
#define SOCKET_RATELIMIT_MUTEX_UNINITIALIZED 0

/* ============================================================================
 * Thread-Local Exception Handling
 * ============================================================================ */

/**
 * Thread-local exception for detailed error messages.
 * Each thread gets its own copy to prevent race conditions.
 */
#ifdef _WIN32
extern __declspec (thread) Except_T SocketRateLimit_DetailedException;
#else
extern __thread Except_T SocketRateLimit_DetailedException;
#endif

/**
 * RAISE_RATELIMIT_ERROR - Raise exception with thread-local detailed message
 * @exception: Base exception type to raise
 *
 * Creates a thread-local copy of the exception with the current error buffer
 * as the reason string, then raises it. This pattern ensures thread safety.
 */
#define RAISE_RATELIMIT_ERROR(exception)                                       \
  do                                                                           \
    {                                                                          \
      SocketRateLimit_DetailedException = (exception);                         \
      SocketRateLimit_DetailedException.reason = socket_error_buf;             \
      RAISE (SocketRateLimit_DetailedException);                               \
    }                                                                          \
  while (0)

/* ============================================================================
 * Rate Limiter Structure
 * ============================================================================ */

#define T SocketRateLimit_T

/**
 * struct T - Token bucket rate limiter internal structure
 *
 * Implements the token bucket algorithm with thread-safe operations.
 * All time values use monotonic clock to avoid issues with system time changes.
 */
struct T
{
  size_t tokens_per_sec;   /**< Token refill rate (tokens added per second) */
  size_t bucket_size;      /**< Maximum bucket capacity (burst limit) */
  size_t tokens;           /**< Current available tokens */
  int64_t last_refill_ms;  /**< Last refill timestamp (monotonic milliseconds) */
  pthread_mutex_t mutex;   /**< Thread safety mutex for all operations */
  Arena_T arena;           /**< Arena used for allocation (NULL if malloc) */
  int initialized;         /**< 1 if mutex initialized, 0 otherwise */
};

#undef T

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * ratelimit_get_monotonic_ms - Get monotonic timestamp in milliseconds
 *
 * Returns: Current monotonic time in milliseconds, or 0 on failure
 *
 * Uses CLOCK_MONOTONIC for timing to avoid issues with system time changes.
 * Falls back to CLOCK_REALTIME if monotonic unavailable (rare).
 */
extern int64_t ratelimit_get_monotonic_ms (void);

/**
 * ratelimit_refill_bucket - Refill bucket based on elapsed time
 * @limiter: Rate limiter instance (caller must hold mutex)
 *
 * Calculates tokens to add based on elapsed time since last refill.
 * Caps tokens at bucket_size to enforce burst limit.
 * Called internally before token operations.
 */
extern void ratelimit_refill_bucket (SocketRateLimit_T limiter);

/**
 * ratelimit_init_structure - Initialize limiter structure fields
 * @limiter: Rate limiter instance to initialize
 * @tokens_per_sec: Token refill rate
 * @bucket_size: Maximum bucket capacity
 * @arena: Arena for allocation (may be NULL)
 *
 * Initializes all fields except mutex. Called after allocation.
 */
extern void ratelimit_init_structure (SocketRateLimit_T limiter,
                                      size_t tokens_per_sec, size_t bucket_size,
                                      Arena_T arena);

/**
 * ratelimit_calculate_tokens_to_add - Calculate tokens from elapsed time
 * @elapsed_ms: Elapsed time in milliseconds
 * @tokens_per_sec: Token refill rate
 *
 * Returns: Number of tokens to add (may be 0 if elapsed time too short)
 *
 * Uses 64-bit arithmetic to prevent overflow during calculation.
 */
extern size_t ratelimit_calculate_tokens_to_add (int64_t elapsed_ms,
                                                 size_t tokens_per_sec);

/**
 * ratelimit_calculate_wait_ms - Calculate wait time for needed tokens
 * @needed: Number of additional tokens needed
 * @tokens_per_sec: Token refill rate
 *
 * Returns: Milliseconds to wait, minimum SOCKET_RATELIMIT_MIN_WAIT_MS
 *
 * Uses 64-bit arithmetic to prevent overflow during calculation.
 */
extern int64_t ratelimit_calculate_wait_ms (size_t needed, size_t tokens_per_sec);

#endif /* SOCKETRATELIMIT_PRIVATE_INCLUDED */
