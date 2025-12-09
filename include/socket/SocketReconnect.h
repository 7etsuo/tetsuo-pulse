#ifndef SOCKETRECONNECT_INCLUDED
#define SOCKETRECONNECT_INCLUDED

#include "core/Except.h"
#include "socket/Socket.h"
#include <stddef.h>
#include <sys/types.h>

/**
 * @file SocketReconnect.h
 * @ingroup connection_mgmt
 * @brief Automatic reconnection framework with exponential backoff and circuit
 * breaker.
 *
 * Provides automatic reconnection with exponential backoff, circuit breaker
 * pattern, and health monitoring for resilient network connections.
 *
 * Features:
 * - Exponential backoff with configurable jitter
 * - Circuit breaker pattern to prevent connection storms
 * - Health monitoring with configurable checks
 * - State machine with event callbacks
 * - Transparent I/O passthrough with auto-reconnect on error
 * - Event loop integration via poll fd and timers
 *
 * State Machine:
 *   DISCONNECTED -> CONNECTING -> CONNECTED -> DISCONNECTED
 *                       |              |
 *                       v              v
 *                 BACKOFF <-----> CIRCUIT_OPEN
 *
 * Thread Safety:
 * - SocketReconnect_T instances are NOT thread-safe
 * - Multiple instances can be used from different threads
 * - Callbacks are invoked from the same thread that calls process/tick
 *
 * Usage (I/O Passthrough):
 *   SocketReconnect_T conn = SocketReconnect_new("example.com", 443, NULL,
 * NULL, NULL); SocketReconnect_connect(conn);
 *   // Use SocketReconnect_send/recv - auto-reconnects on error
 *   ssize_t n = SocketReconnect_send(conn, data, len);
 *
 * @see SocketReconnect_new() for creating reconnection instances.
 * @see SocketReconnect_connect() for initiating connection.
 * @see SocketReconnect_send() for transparent I/O operations.
 * @see @ref SocketPool_T for integration with connection pools.
 * @see @ref SocketHTTPClient_T for HTTP client reconnection.
 * @see @ref core_io::SocketProxy_Conn_T for proxy reconnection scenarios.
 */

#define T SocketReconnect_T
/**
 * @brief Opaque handle for a reconnecting socket connection.
 * @ingroup connection_mgmt
 *
 * Manages the connection state machine, exponential backoff timers, circuit breaker,
 * health checks, and provides transparent I/O with automatic reconnection on failure.
 *
 * Instances are not thread-safe and should be accessed from a single thread.
 * Integrate with event loops using SocketReconnect_pollfd(), process(), and tick().
 *
 * @threadsafe No
 * @see SocketReconnect_new() to create an instance.
 * @see SocketReconnect_free() to destroy.
 * @see SocketReconnect_state() to query current state.
 * @see SocketReconnect_socket() to access underlying socket when connected.
 */
typedef struct T *T;

/**
 * @brief Exception raised for reconnection module failures.
 * @ingroup connection_mgmt
 *
 * Thrown on errors such as invalid policy parameters, allocation failures,
 * or unrecoverable state transitions.
 * @see SocketReconnect_new()
 * @see Except_T for handling.
 */
extern const Except_T SocketReconnect_Failed;

/* ============================================================================
 * Reconnection State
 * ============================================================================
 */

/**
 * @brief Enumeration of possible states in the reconnection state machine.
 * @ingroup connection_mgmt
 */
typedef enum
{
  RECONNECT_DISCONNECTED = 0, /**< Not connected, not attempting */
  RECONNECT_CONNECTING,       /**< Connection attempt in progress */
  RECONNECT_CONNECTED,        /**< Successfully connected */
  RECONNECT_BACKOFF,     /**< Waiting before retry (exponential backoff) */
  RECONNECT_CIRCUIT_OPEN /**< Circuit breaker open, blocking attempts */
} SocketReconnect_State;

/* ============================================================================
 * Backoff Policy Configuration
 * ============================================================================
 */

/**
 * @brief Configuration structure for reconnection backoff and circuit breaker policy.
 * @ingroup connection_mgmt
 *
 * Controls exponential backoff timing, circuit breaker thresholds, and health monitoring intervals.
 * Use SocketReconnect_policy_defaults() to initialize with recommended values.
 * @see SocketReconnect_policy_defaults()
 */
typedef struct SocketReconnect_Policy
{
  /* Exponential backoff settings */
  int initial_delay_ms; /**< First retry delay (default: 100ms) */
  int max_delay_ms;     /**< Maximum backoff cap (default: 30000ms) */
  double multiplier;    /**< Backoff multiplier (default: 2.0) */
  double jitter;        /**< Jitter factor 0.0-1.0 (default: 0.25) */
  int max_attempts; /**< Max attempts before giving up, 0=unlimited (default:
                       10) */

  /* Circuit breaker settings */
  int circuit_failure_threshold; /**< Consecutive failures before opening
                                    (default: 5) */
  int circuit_reset_timeout_ms;  /**< Time before half-open probe (default:
                                    60000ms) */

  /* Health monitoring settings */
  int health_check_interval_ms; /**< Interval between health checks, 0=disabled
                                   (default: 30000ms) */
  int health_check_timeout_ms;  /**< Timeout for health check (default: 5000ms)
                                 */
} SocketReconnect_Policy_T;

/* Default policy values */
#ifndef SOCKET_RECONNECT_DEFAULT_INITIAL_DELAY_MS
#define SOCKET_RECONNECT_DEFAULT_INITIAL_DELAY_MS 100
#endif

#ifndef SOCKET_RECONNECT_DEFAULT_MAX_DELAY_MS
#define SOCKET_RECONNECT_DEFAULT_MAX_DELAY_MS 30000
#endif

#ifndef SOCKET_RECONNECT_DEFAULT_MULTIPLIER
#define SOCKET_RECONNECT_DEFAULT_MULTIPLIER 2.0
#endif

#ifndef SOCKET_RECONNECT_DEFAULT_JITTER
#define SOCKET_RECONNECT_DEFAULT_JITTER 0.25
#endif

#ifndef SOCKET_RECONNECT_DEFAULT_MAX_ATTEMPTS
#define SOCKET_RECONNECT_DEFAULT_MAX_ATTEMPTS 10
#endif

#ifndef SOCKET_RECONNECT_DEFAULT_CIRCUIT_THRESHOLD
#define SOCKET_RECONNECT_DEFAULT_CIRCUIT_THRESHOLD 5
#endif

#ifndef SOCKET_RECONNECT_DEFAULT_CIRCUIT_RESET_MS
#define SOCKET_RECONNECT_DEFAULT_CIRCUIT_RESET_MS 60000
#endif

#ifndef SOCKET_RECONNECT_DEFAULT_HEALTH_INTERVAL_MS
#define SOCKET_RECONNECT_DEFAULT_HEALTH_INTERVAL_MS 30000
#endif

#ifndef SOCKET_RECONNECT_DEFAULT_HEALTH_TIMEOUT_MS
#define SOCKET_RECONNECT_DEFAULT_HEALTH_TIMEOUT_MS 5000
#endif

/* ============================================================================
 * Event Callbacks
 * ============================================================================
 */

/**
 * @brief Type for state change notification callback.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 * @param old_state Previous state before transition.
 * @param new_state New state after transition.
 * @param userdata User-provided data from SocketReconnect_new().
 *
 * Called when the reconnection state changes. Can be used for logging,
 * metrics, or custom reconnection logic.
 *
 * NOTE: Do not call SocketReconnect_free() from within the callback.
 */
typedef void (*SocketReconnect_Callback) (T conn,
                                          SocketReconnect_State old_state,
                                          SocketReconnect_State new_state,
                                          void *userdata);

/**
 * @brief Type for custom health check callback.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 * @param socket Currently connected underlying socket.
 * @param timeout_ms Maximum time to block for the check (ms); 0 for non-blocking.
 * @param userdata User-provided data from SocketReconnect_new().
 *
 * @return 1 if connection is healthy, 0 if unhealthy (triggers reconnect).
 *
 * Optional callback for custom health checks during connected state.
 * Must complete within timeout_ms to avoid blocking the event loop or causing DoS.
 * Default implementation polls the socket for readability within the timeout (min 100ms).
 * @note Respect timeout_ms to prevent denial-of-service from malicious checks.
 * @see SocketReconnect_set_health_check()
 */
typedef int (*SocketReconnect_HealthCheck) (T conn, Socket_T socket,
                                            int timeout_ms, void *userdata);
/* Additional note: timeout_ms added in v1.1 for DoS protection.
 * Custom implementations must respect this limit.
 */
/* ============================================================================
 * Context Creation and Destruction
 * ============================================================================
 */

/**
 * @brief Create a new reconnecting connection
 * @ingroup connection_mgmt
 * @param host Target hostname or IP address.
 * @param port Target port number (1-65535).
 * @param policy Optional policy configuration (NULL uses defaults). @see SocketReconnect_policy_defaults() for recommended initialization.
 * @param callback Optional state change callback (NULL disables).
 * @param userdata Arbitrary user data passed to callbacks.
 *
 * @return New SocketReconnect_T instance, or raises exception.
 * @throws SocketReconnect_Failed If unable to allocate resources or validate parameters.
 * @threadsafe Yes - creates independent instance.
 *
 * Creates a reconnecting connection context. The connection is not
 * started automatically - call SocketReconnect_connect() to begin.
 */
extern T SocketReconnect_new (const char *host, int port,
                              const SocketReconnect_Policy_T *policy,
                              SocketReconnect_Callback callback,
                              void *userdata);

/**
 * @brief Free a reconnecting connection.
 * @ingroup connection_mgmt
 * @param conn Pointer to context (will be set to NULL).
 * @threadsafe No.
 * @note Disconnects if connected and frees all resources.
 * @see SocketReconnect_new() for creating connections.
 * @see SocketReconnect_disconnect() for graceful disconnection.
 */
extern void SocketReconnect_free (T *conn);

/* ============================================================================
 * Connection Control
 * ============================================================================
 */

/**
 * @brief Start connection process or queue for retry.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 * @threadsafe No.
 * @note Initiates connection. If already connected or connecting, this is a no-op.
 * @note If in backoff or circuit-open state, respects those constraints.
 * @see SocketReconnect_new() for creating connections.
 * @see SocketReconnect_disconnect() for stopping connections.
 * @see SocketReconnect_state() for current state.
 */
extern void SocketReconnect_connect (T conn);

/**
 * @brief Gracefully disconnect without triggering reconnect.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 * @threadsafe No.
 * @note Disconnects without triggering reconnection logic. Resets attempt counter.
 * @note Use this for intentional disconnection (e.g., shutdown).
 * @see SocketReconnect_connect() for starting connections.
 * @see SocketReconnect_free() for complete cleanup.
 */
extern void SocketReconnect_disconnect (T conn);

/**
 * @brief Reset reconnection statistics and state machine.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 * @threadsafe No.
 * @note Clears attempt counter, consecutive failures, and circuit breaker state.
 * @note Does not disconnect if connected. Use after external recovery.
 * @see SocketReconnect_connect() for initiating reconnection.
 * @see SocketReconnect_state() for current state.
 */
extern void SocketReconnect_reset (T conn);

/* ============================================================================
 * Socket Access
 * ============================================================================
 */

/**
 * @brief Get the underlying Socket_T when connected.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 * @return Connected socket, or NULL if not connected.
 * @threadsafe No.
 * @note Returns the underlying socket only when in RECONNECT_CONNECTED state.
 * @note Do not close or free the returned socket directly.
 * @see SocketReconnect_state() for connection state.
 * @see SocketReconnect_isconnected() for boolean check.
 */
extern Socket_T SocketReconnect_socket (T conn);

/* ============================================================================
 * State Query
 * ============================================================================
 */

/**
 * @brief Get current reconnection state.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 *
 * @return Current reconnection state
 * @threadsafe No
 */
extern SocketReconnect_State SocketReconnect_state (T conn);

/**
 * @brief Check if reconnection is currently in connected state.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 *
 * @return 1 if connected, 0 otherwise
 * @threadsafe No
 */
extern int SocketReconnect_isconnected (T conn);

/**
 * @brief Get number of connection attempts since last success or reset.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 *
 * @return Number of connection attempts since last success or reset
 * @threadsafe No
 */
extern int SocketReconnect_attempts (T conn);

/**
 * @brief Get count of consecutive connection failures.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 *
 * @return Number of consecutive failures (for circuit breaker)
 * @threadsafe No
 */
extern int SocketReconnect_failures (T conn);

/* ============================================================================
 * Event Loop Integration
 * ============================================================================
 */

/**
 * @brief Get file descriptor for integration with poll/epoll/kqueue.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 *
 * @return File descriptor to poll for read/write events, or -1 if none
 * @threadsafe No
 *
 * Returns the underlying socket fd when connecting or connected.
 * Add this to your poll set and call SocketReconnect_process() on events.
 */
extern int SocketReconnect_pollfd (T conn);

/**
 * @brief Process I/O events from poll loop.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 *
 * @threadsafe No
 *
 * Call when SocketReconnect_pollfd() becomes readable/writable.
 * Handles connection completion, detects disconnection, etc.
 */
extern void SocketReconnect_process (T conn);

/**
 * @brief Calculate milliseconds until next timer event or action.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 *
 * @return Milliseconds until next timeout, or -1 if none pending
 * @threadsafe No
 *
 * Returns the time until:
 * - Next backoff retry
 * - Circuit breaker probe
 * - Health check
 *
 * Use as timeout for poll/select.
 */
extern int SocketReconnect_next_timeout_ms (T conn);

/**
 * @brief Advance internal timers and check for state transitions.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 *
 * @threadsafe No
 *
 * Call periodically or when SocketReconnect_next_timeout_ms() expires.
 * Handles backoff retry, circuit breaker state transitions, health checks.
 */
extern void SocketReconnect_tick (T conn);

/* ============================================================================
 * Health Check Configuration
 * ============================================================================
 */

/**
 * @brief Configure custom health check callback.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 * @param check Health check function (NULL for default poll-based check).
 *
 * @threadsafe No
 *
 * Sets a custom health check function. Custom checks must respect
 * policy.health_check_timeout_ms to avoid blocking the calling thread.
 * Default health check polls socket with configurable timeout.
 */
extern void
SocketReconnect_set_health_check (T conn, SocketReconnect_HealthCheck check);

/* ============================================================================
 * Policy Helpers
 * ============================================================================
 */

/**
 * @brief Initialize SocketReconnect_Policy_T with default values.
 * @ingroup connection_mgmt
 * @param policy Pointer to policy structure to populate.
 *
 * @threadsafe Yes
 *
 * Fills policy with recommended defaults:
 * - initial_delay_ms: 100ms
 * - max_delay_ms: 30000ms (30s)
 * - multiplier: 2.0
 * - jitter: 0.25 (25%)
 * - max_attempts: 10
 * - circuit_failure_threshold: 5
 * - circuit_reset_timeout_ms: 60000ms (60s)
 * - health_check_interval_ms: 30000ms (30s)
 * - health_check_timeout_ms: 5000ms (5s)
 */
extern void SocketReconnect_policy_defaults (SocketReconnect_Policy_T *policy);

/* ============================================================================
 * I/O Passthrough (Auto-Reconnect on Error)
 * ============================================================================
 */

/**
 * @brief Send data, automatically reconnecting on connection loss.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 * @param buf Data buffer to send.
 * @param len Number of bytes to send.
 *
 * @return Bytes sent (>0), 0 if not connected, -1 on error
 * @threadsafe No
 *
 * Sends data if connected. On connection error, triggers reconnection
 * and returns -1 with errno set to ENOTCONN.
 *
 * NOTE: This is a convenience wrapper. For more control, get the socket
 * with SocketReconnect_socket() and use Socket_send() directly.
 */
extern ssize_t SocketReconnect_send (T conn, const void *buf, size_t len);

/**
 * @brief Receive data, triggering reconnect on EOF or error.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 * @param buf Buffer to receive into.
 * @param len Maximum bytes to receive.
 *
 * @return Bytes received (>0), 0 if EOF/disconnected, -1 on error
 * @threadsafe No
 *
 * Receives data if connected. On connection error or EOF, triggers
 * reconnection and returns 0.
 *
 * NOTE: This is a convenience wrapper. For more control, get the socket
 * with SocketReconnect_socket() and use Socket_recv() directly.
 */
extern ssize_t SocketReconnect_recv (T conn, void *buf, size_t len);

/* ============================================================================
 * State Names (for logging/debugging)
 * ============================================================================
 */

/**
 * @brief Get human-readable name for a reconnection state.
 * @ingroup connection_mgmt
 * @param state Reconnection state enum value.
 *
 * @return Static string with state name
 * @threadsafe Yes
 */
extern const char *SocketReconnect_state_name (SocketReconnect_State state);

#undef T
#endif /* SOCKETRECONNECT_INCLUDED */
