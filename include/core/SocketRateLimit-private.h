#ifndef SOCKETRATELIMIT_PRIVATE_INCLUDED
#define SOCKETRATELIMIT_PRIVATE_INCLUDED

/**
 * @file SocketRateLimit-private.h
 * @brief Private implementation details for the token bucket rate limiter module.
 * @ingroup utilities
 * @internal
 *
 * Contains internal structures, constants, and flags used by SocketRateLimit.c.
 * Not part of the public API - do not include directly from user code.
 *
 * Key sections:
 * - @ref ratelimit_consts "Rate Limiter Constants"
 * - @ref ratelimit_struct "Rate Limiter Structure"
 * - @ref internal_helpers "Internal Helper Functions"
 *
 * PLATFORM REQUIREMENTS: POSIX threads (pthread) and CLOCK_MONOTONIC.
 *
 * @note Include only from SocketRateLimit.c and related files.
 * @warning Do NOT use in public headers or application code.
 * @see SocketRateLimit.h for the public API.
 * @see @ref utilities "Utilities Group" for related modules.
 */

#include "core/Arena.h"
#include "core/SocketRateLimit.h"
#include "core/SocketUtil.h"
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @section ratelimit_consts Rate Limiter Constants
 * @ingroup utilities
 * @internal
 *
 * Defines internal constants used by the token bucket algorithm,
 * including wait values, state flags, and mutex states.
 */

/**
 * @brief Minimum wait time in milliseconds for rate limiting operations.
 * @ingroup utilities
 * @internal
 *
 * When tokens are needed but calculated wait is zero, return this minimum
 * to ensure callers always wait at least a small amount.
 * @see SocketRateLimit_wait_time_ms() in SocketRateLimit.h
 */
#ifndef SOCKET_RATELIMIT_MIN_WAIT_MS
#define SOCKET_RATELIMIT_MIN_WAIT_MS 1
#endif

/**
 * @brief Return value indicating impossible token requests.
 * @ingroup utilities
 * @internal
 *
 * Returned by SocketRateLimit_wait_time_ms() when requested tokens exceed
 * bucket_size, making the request impossible to fulfill.
 * @see SocketRateLimit_wait_time_ms()
 * @see SocketRateLimit_get_bucket_size()
 */
#ifndef SOCKET_RATELIMIT_IMPOSSIBLE_WAIT
#define SOCKET_RATELIMIT_IMPOSSIBLE_WAIT (-1)
#endif

/**
 * @brief Internal flag indicating rate limiter instance is shutdown.
 * @ingroup utilities
 * @internal
 *
 * Used in initialized field: -1 means being freed, do not use after this.
 * @see SocketRateLimit_free()
 */
#define SOCKET_RATELIMIT_SHUTDOWN (-1)

/**
 * @brief Internal flag indicating mutex is not yet initialized.
 * @ingroup utilities
 * @internal
 *
 * Value 0 in initialized field before mutex creation.
 */
#define SOCKET_RATELIMIT_MUTEX_UNINITIALIZED 0

/**
 * @brief Internal flag indicating mutex is initialized and ready.
 * @ingroup utilities
 * @internal
 *
 * Value 1 in initialized field after successful mutex_init().
 */
#define SOCKET_RATELIMIT_MUTEX_INITIALIZED 1

/**
 * @section ratelimit_struct Rate Limiter Structure
 * @ingroup utilities
 * @internal
 *
 * Definition of the internal SocketRateLimit_T structure.
 * Opaque to public users; access via public API functions only.
 *
 * @see SocketRateLimit_T
 */

#define T SocketRateLimit_T

/**
 * @brief Internal structure implementing the token bucket rate limiter.
 * @ingroup utilities
 * @internal
 *
 * Supports thread-safe operations via mutex protection.
 * Uses monotonic time (CLOCK_MONOTONIC) for refill calculations to handle
 * system clock adjustments gracefully.
 *
 * @var SocketRateLimit_T::tokens_per_sec Configured token refill rate in tokens per second.
 * @var SocketRateLimit_T::bucket_size Configured maximum bucket capacity (burst allowance).
 * @var SocketRateLimit_T::tokens Current number of available tokens (refilled over time).
 * @var SocketRateLimit_T::last_refill_ms Monotonic timestamp (ms) of last refill/acquire.
 * @var SocketRateLimit_T::mutex Mutex protecting all operations and fields.
 * @var SocketRateLimit_T::arena Arena for this instance's memory allocation (NULL for malloc).
 * @var SocketRateLimit_T::initialized State flag: -1=shutdown (during free), 0=uninitialized, 1=ready.
 *
 * @see SocketRateLimit_T public opaque type.
 * @see SocketRateLimit_new() for creation and initialization.
 * @see SocketRateLimit.c for static internal helper functions.
 */
struct T
{
  size_t tokens_per_sec; /**< Token refill rate (tokens added per second) */
  size_t bucket_size;    /**< Maximum bucket capacity (burst limit) */
  size_t tokens;         /**< Current available tokens */
  int64_t
      last_refill_ms;    /**< Last refill timestamp (monotonic milliseconds) */
  pthread_mutex_t mutex; /**< Thread safety mutex for all operations */
  Arena_T arena;         /**< Arena used for allocation (NULL if malloc) */
  int initialized; /**< State flag: -1=shutdown (freeing), 0=uninitialized, 1=ready.
                      *   Protects against concurrent access during init/destroy.
                      * @internal
                      */
};

#undef T

/**
 * @section internal_helpers Internal Helper Functions
 * @ingroup utilities
 * @internal
 *
 * NOTE: All internal helper functions are declared static in SocketRateLimit.c
 * and are not exposed through this private header. This header only exposes:
 * - The structure definition (for implementation files)
 * - Constants and macros
 * - Thread-local exception infrastructure
 *
 * This design keeps the implementation details hidden while allowing the
 * structure to be accessed for direct field access where needed (e.g., tests).
 *
 * @see SocketRateLimit.c for static function implementations.
 */

#endif /* SOCKETRATELIMIT_PRIVATE_INCLUDED */
