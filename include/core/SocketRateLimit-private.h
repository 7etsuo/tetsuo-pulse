#ifndef SOCKETRATELIMIT_PRIVATE_INCLUDED
#define SOCKETRATELIMIT_PRIVATE_INCLUDED

/**
 * SocketRateLimit-private.h - Private declarations for SocketRateLimit module
 *
 * Part of the Socket Library
 *
 * Internal structure definitions for the token bucket rate limiter.
 * Include only from SocketRateLimit.c and related implementation files.
 * Do NOT include from public headers or user code.
 */

#include "core/Arena.h"
#include "core/SocketRateLimit.h"
#include "core/SocketUtil.h"
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
 * SOCKET_RATELIMIT_SHUTDOWN - Flag indicating instance is shutdown (being freed)
 */
#define SOCKET_RATELIMIT_SHUTDOWN (-1)

/**
 * SOCKET_RATELIMIT_MUTEX_UNINITIALIZED - Flag indicating mutex not initialized
 */
#define SOCKET_RATELIMIT_MUTEX_UNINITIALIZED 0

/**
 * SOCKET_RATELIMIT_MUTEX_INITIALIZED - Flag indicating mutex is initialized and ready
 */
#define SOCKET_RATELIMIT_MUTEX_INITIALIZED 1

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
  int initialized;         /**< -1 shutdown (being freed), 0 uninitialized, 1 mutex initialized and ready */
};

#undef T

/* ============================================================================
 * Internal Helper Functions
 *
 * NOTE: All internal helper functions are declared static in SocketRateLimit.c
 * and are not exposed through this private header. This header only exposes:
 * - The structure definition (for implementation files)
 * - Constants and macros
 * - Thread-local exception infrastructure
 *
 * This design keeps the implementation details hidden while allowing the
 * structure to be accessed for direct field access where needed (e.g., tests).
 * ============================================================================ */

#endif /* SOCKETRATELIMIT_PRIVATE_INCLUDED */
