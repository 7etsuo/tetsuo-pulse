#ifndef SOCKETRECONNECT_PRIVATE_INCLUDED
#define SOCKETRECONNECT_PRIVATE_INCLUDED

/**
 * SocketReconnect-private.h - Internal structures for Reconnection Framework
 *
 * This header contains internal implementation details for the SocketReconnect
 * module. Not for public use.
 */

#include "core/Arena.h"
#include "socket/Socket.h"
#include "socket/SocketReconnect.h"
#include <stdint.h>
#include <sys/time.h>

/* ============================================================================
 * Internal Constants
 * ============================================================================ */

/* Error buffer size */
#ifndef SOCKET_RECONNECT_ERROR_BUFSIZE
#define SOCKET_RECONNECT_ERROR_BUFSIZE 256
#endif

/* Maximum hostname length */
#ifndef SOCKET_RECONNECT_MAX_HOST_LEN
#define SOCKET_RECONNECT_MAX_HOST_LEN 255
#endif

/* ============================================================================
 * Circuit Breaker State
 * ============================================================================ */

/**
 * SocketReconnect_CircuitState - Internal circuit breaker state
 */
typedef enum
{
  CIRCUIT_CLOSED = 0,   /**< Normal operation, connections allowed */
  CIRCUIT_OPEN,         /**< Blocking connections, too many failures */
  CIRCUIT_HALF_OPEN     /**< Allowing probe connection */
} SocketReconnect_CircuitState;

/* ============================================================================
 * Main Context Structure
 * ============================================================================ */

/**
 * SocketReconnect_T - Reconnecting connection context
 *
 * Manages the full reconnection lifecycle including backoff timing,
 * circuit breaker state, and health monitoring.
 */
struct SocketReconnect_T
{
  /* Configuration */
  SocketReconnect_Policy_T policy;    /**< Reconnection policy */
  char *host;                          /**< Target hostname (copied) */
  int port;                            /**< Target port */

  /* Internal resources */
  Arena_T arena;                       /**< Memory arena for allocations */
  Socket_T socket;                     /**< Current socket (NULL if disconnected) */

  /* Callbacks */
  SocketReconnect_Callback callback;   /**< State change callback */
  SocketReconnect_HealthCheck health_check; /**< Custom health check */
  void *userdata;                      /**< User data for callbacks */

  /* State machine */
  SocketReconnect_State state;         /**< Current state */
  SocketReconnect_CircuitState circuit_state; /**< Circuit breaker state */

  /* Connection tracking */
  int attempt_count;                   /**< Attempts since last success/reset */
  int consecutive_failures;            /**< Consecutive failures (for circuit breaker) */
  int total_attempts;                  /**< Total attempts lifetime */
  int total_successes;                 /**< Total successful connections lifetime */

  /* Timing */
  int64_t state_start_time_ms;         /**< When current state started */
  int64_t last_attempt_time_ms;        /**< When last attempt was made */
  int64_t last_success_time_ms;        /**< When last successful connection */
  int64_t backoff_until_ms;            /**< Time when backoff expires */
  int64_t circuit_open_time_ms;        /**< When circuit breaker opened */
  int64_t last_health_check_ms;        /**< When last health check ran */
  int current_backoff_delay_ms;        /**< Current computed backoff delay */

  /* Connection state */
  int connect_in_progress;             /**< Non-blocking connect pending */

  /* Error tracking */
  char error_buf[SOCKET_RECONNECT_ERROR_BUFSIZE]; /**< Last error message */
  int last_error;                      /**< Last errno value */
};

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * socketreconnect_get_time_ms - Get current time in milliseconds
 * Returns: Current time in milliseconds since epoch
 */
static inline int64_t
socketreconnect_get_time_ms (void)
{
  struct timeval tv;
  gettimeofday (&tv, NULL);
  return (int64_t)tv.tv_sec * 1000 + (int64_t)tv.tv_usec / 1000;
}

/**
 * socketreconnect_elapsed_ms - Calculate elapsed time in milliseconds
 * @start_ms: Start time from socketreconnect_get_time_ms()
 * Returns: Elapsed milliseconds
 */
static inline int64_t
socketreconnect_elapsed_ms (int64_t start_ms)
{
  return socketreconnect_get_time_ms () - start_ms;
}

/**
 * socketreconnect_random_double - Get random double in [0.0, 1.0)
 * Returns: Random double value
 *
 * Uses a simple xorshift-based PRNG for jitter calculation.
 * Not cryptographically secure, but sufficient for timing jitter.
 * Thread-safe: Uses thread-local storage for the PRNG seed.
 */
static inline double
socketreconnect_random_double (void)
{
#ifdef _WIN32
  static __declspec (thread) unsigned int seed = 0;
#else
  static __thread unsigned int seed = 0;
#endif
  if (seed == 0)
    {
      seed = (unsigned int)socketreconnect_get_time_ms ();
    }
  /* xorshift32 */
  seed ^= seed << 13;
  seed ^= seed >> 17;
  seed ^= seed << 5;
  return (double)seed / (double)0xFFFFFFFFU;
}

#endif /* SOCKETRECONNECT_PRIVATE_INCLUDED */

