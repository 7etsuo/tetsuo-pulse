#ifndef SOCKETRECONNECT_PRIVATE_INCLUDED
#define SOCKETRECONNECT_PRIVATE_INCLUDED

/**
 * @file SocketReconnect-private.h
 * @brief Internal implementation details for automatic reconnection framework.
 * @ingroup connection_mgmt
 * @defgroup reconnect_private SocketReconnect Private Implementation Details
 * @ingroup connection_mgmt
 * @internal
 *
 * This header contains private structures and helper functions for the
 * SocketReconnect module. Not intended for public use or direct inclusion.
 *
 * @see SocketReconnect.h for the public API.
 * @see @ref connection_mgmt Connection Management Modules.
 */

#include "core/Arena.h"
#include "core/SocketCrypto.h"
#include "core/SocketUtil.h"
#include "socket/Socket.h"
#include "socket/SocketReconnect.h"
#include <stdint.h>

/* ============================================================================
 * Internal Constants
 * ============================================================================
 */

/**
 * @brief Maximum length for internal error messages.
 * @internal
 * @note Fixed size to avoid dynamic allocation in hot paths.
 */
#ifndef SOCKET_RECONNECT_ERROR_BUFSIZE
#define SOCKET_RECONNECT_ERROR_BUFSIZE 256
#endif

/**
 * @brief Maximum length for hostname strings (excluding null terminator).
 * @internal
 * @note Matches standard DNS name limits, sufficient for IPv6 literals.
 */
#ifndef SOCKET_RECONNECT_MAX_HOST_LEN
#define SOCKET_RECONNECT_MAX_HOST_LEN 255
#endif

/* ============================================================================
 * Circuit Breaker State
 * ============================================================================
 */

/**
 * @brief Internal circuit breaker states used in reconnection logic.
 * @ingroup connection_mgmt
 * @internal
 *
 * These states manage the circuit breaker pattern to prevent cascading failures
 * during outage conditions.
 *
 * @see SocketReconnect_State for the public-facing state enumeration.
 * @see SocketReconnect_T::circuit_state for usage in context structure.
 */
typedef enum
{
  CIRCUIT_CLOSED = 0, /**< Normal operation, connections allowed */
  CIRCUIT_OPEN,       /**< Blocking connections, too many failures */
  CIRCUIT_HALF_OPEN   /**< Allowing probe connection */
} SocketReconnect_CircuitState;

/* ============================================================================
 * Main Context Structure
 * ============================================================================
 */

/**
 * @brief Opaque context for managing reconnecting socket connections.
 * @ingroup connection_mgmt
 * @internal
 *
 * This structure holds all state and configuration for a single reconnecting
 * connection instance. It implements exponential backoff, circuit breaker,
 * health checks, and transparent I/O with automatic reconnection.
 *
 * @see SocketReconnect.h for public interface and creation functions.
 * @see SocketReconnect_Policy_T for configuration options.
 */
struct SocketReconnect_T
{
  /* Configuration */
  SocketReconnect_Policy_T policy; /**< Reconnection policy */
  char *host;                      /**< Target hostname (copied) */
  int port;                        /**< Target port */

  /* Internal resources */
  Arena_T arena;   /**< Memory arena for allocations */
  Socket_T socket; /**< Current socket (NULL if disconnected) */

  /* Callbacks */
  SocketReconnect_Callback callback;        /**< State change callback */
  SocketReconnect_HealthCheck health_check; /**< Custom health check */
  void *userdata;                           /**< User data for callbacks */

  /* State machine */
  SocketReconnect_State state;                /**< Current state */
  SocketReconnect_CircuitState circuit_state; /**< Circuit breaker state */

  /* Connection tracking */
  int attempt_count;        /**< Attempts since last success/reset */
  int consecutive_failures; /**< Consecutive failures (for circuit breaker) */
  int total_attempts;       /**< Total attempts lifetime */
  int total_successes;      /**< Total successful connections lifetime */

  /* Timing */
  int64_t state_start_time_ms;  /**< When current state started */
  int64_t last_attempt_time_ms; /**< When last attempt was made */
  int64_t last_success_time_ms; /**< When last successful connection */
  int64_t backoff_until_ms;     /**< Time when backoff expires */
  int64_t circuit_open_time_ms; /**< When circuit breaker opened */
  int64_t last_health_check_ms; /**< When last health check ran */
  int current_backoff_delay_ms; /**< Current computed backoff delay */

  /* Connection state */
  int connect_in_progress; /**< Non-blocking connect pending */

  /* Error tracking */
  char error_buf[SOCKET_RECONNECT_ERROR_BUFSIZE]; /**< Last error message */
  int last_error;                                 /**< Last errno value */
};

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * @brief Get current monotonic time in milliseconds.
 * @internal
 * @threadsafe Yes - reentrant system clock query.
 * @return Current monotonic time in milliseconds (int64_t).
 *
 * Internal helper using Socket_get_monotonic_ms() to ensure monotonic time
 * resistant to system clock adjustments.
 *
 * @see Socket_get_monotonic_ms() in SocketUtil for details.
 * @see socketreconnect_elapsed_ms() for elapsed time calculation.
 */
static inline int64_t
socketreconnect_get_time_ms(void)
{
  return Socket_get_monotonic_ms();
}

/**
 * @brief Calculate elapsed time since a start timestamp.
 * @internal
 * @threadsafe Yes - simple arithmetic on input values.
 * @param start_ms Start time from socketreconnect_get_time_ms().
 * @return Elapsed milliseconds since start (non-negative).
 *
 * Uses monotonic time to ensure accurate, non-decreasing measurements.
 *
 * @see socketreconnect_get_time_ms() for timestamp acquisition.
 */
static inline int64_t
socketreconnect_elapsed_ms(int64_t start_ms)
{
  int64_t now = socketreconnect_get_time_ms();
  return (now > start_ms) ? (now - start_ms) : 0;
}

/**
 * @brief Generate a random double in [0.0, 1.0) for backoff jitter.
 * @internal
 * @return Random double value in [0.0, 1.0).
 *
 * Prefers cryptographically secure randomness via SocketCrypto_random_bytes().
 * Falls back to thread-local xorshift PRNG seeded by monotonic time.
 * Intended only for non-cryptographic use like exponential backoff jitter.
 *
 * @note Thread-safe: Uses thread-local storage for fallback PRNG seed.
 * @warning Not suitable for security-sensitive randomness.
 *
 * @see SocketCrypto_random_bytes() for secure source.
 * @see SocketReconnect_Policy_T::jitter for policy integration.
 * @see socketreconnect_get_time_ms() for time-based seeding.
 */
static inline double
socketreconnect_random_double(void)
{
  unsigned int value;
  if (SocketCrypto_random_bytes(&value, sizeof(value)) == 0) {
    return (double)value / (double)0xFFFFFFFFU;
  } else {
    /* Fallback to time-based PRNG */
#ifdef _WIN32
    static __declspec(thread) unsigned int seed = 0;
#else
    static __thread unsigned int seed = 0;
#endif
    if (seed == 0) {
      seed = (unsigned int)Socket_get_monotonic_ms();
    }
    /* xorshift32 */
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return (double)seed / (double)0xFFFFFFFFU;
  }
}

/**
 * @} -- reconnect_private
 */

#endif /* SOCKETRECONNECT_PRIVATE_INCLUDED */
