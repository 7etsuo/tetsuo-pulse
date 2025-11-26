#ifndef SOCKETRATELIMIT_PRIVATE_INCLUDED
#define SOCKETRATELIMIT_PRIVATE_INCLUDED

/**
 * SocketRateLimit-private.h - Private declarations for SocketRateLimit module
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

struct T
{
  size_t tokens_per_sec;   /**< Token refill rate */
  size_t bucket_size;      /**< Maximum bucket capacity (burst limit) */
  size_t tokens;           /**< Current available tokens (scaled by 1000) */
  int64_t last_refill_ms;  /**< Last refill timestamp (monotonic ms) */
  pthread_mutex_t mutex;   /**< Thread safety mutex */
  Arena_T arena;           /**< Arena used for allocation (NULL if malloc) */
  int initialized;         /**< 1 if mutex initialized */
};

#undef T

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * ratelimit_get_monotonic_ms - Get monotonic timestamp in milliseconds
 *
 * Returns: Current monotonic time in milliseconds
 */
extern int64_t ratelimit_get_monotonic_ms (void);

/**
 * ratelimit_refill_bucket - Refill bucket based on elapsed time
 * @limiter: Rate limiter instance (must hold mutex)
 *
 * Called internally before token operations.
 * Updates tokens and last_refill_ms.
 */
extern void ratelimit_refill_bucket (SocketRateLimit_T limiter);

#endif /* SOCKETRATELIMIT_PRIVATE_INCLUDED */

