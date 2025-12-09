#ifndef SOCKETRECONNECT_INCLUDED
#define SOCKETRECONNECT_INCLUDED

#include "core/Except.h"
#include "socket/Socket.h"
#include <stddef.h>
#include <sys/types.h>

/**
 * @file SocketReconnect.h
 * @ingroup core_io
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
 *   @brief DISCONNECTED -> CONNECTING -> CONNECTED -> DISCONNECTED
 *   @ingroup core_io
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
 * @see connection_mgmt for integration with connection pools.
 */

#define T SocketReconnect_T
typedef struct T *T;

/* Exception for reconnection failures */
extern const Except_T SocketReconnect_Failed;

/* ============================================================================
 * Reconnection State
 * ============================================================================
 */

/**
 * @brief SocketReconnect_State - State of reconnection connection
 * @ingroup core_io
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
 * @brief SocketReconnect_Policy_T - Reconnection policy configuration
 * @ingroup core_io
 *
 * Controls backoff timing, circuit breaker behavior, and health monitoring.
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
 * @brief SocketReconnect_Callback - State change callback function
 * @ingroup core_io
 * @conn: Reconnection context
 * @old_state: Previous state
 * @new_state: New state
 * @userdata: User data passed to SocketReconnect_new()
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
 * @brief SocketReconnect_HealthCheck - Custom health check function
 * @ingroup core_io
 * @conn: Reconnection context
 * @socket: Current connected socket
 * @timeout_ms: Maximum block time in ms (0=non-blocking check)
 * @userdata: User data passed to SocketReconnect_new()
 *
 * Returns: 1 if healthy, 0 if unhealthy (triggers reconnect)
 *
 * Optional custom health check. Must respect timeout_ms to prevent DoS.
 * Default check uses poll with timeout_ms or 100ms min.
 * If not provided, default is used.
 */
typedef int (*SocketReconnect_HealthCheck) (T conn, Socket_T socket,
                                            int timeout_ms, void *userdata);
/**
 * @timeout_ms: Maximum time to block in ms, 0=no timeout (use with caution)
 *
 * New in v1.1: timeout_ms parameter for DoS protection.
 * Custom checks should respect this limit to prevent blocking.
 */
/* ============================================================================
 * Context Creation and Destruction
 * ============================================================================
 */

/**
 * @brief SocketReconnect_new - Create a new reconnecting connection
 * @ingroup core_io
 * @host: Hostname or IP address to connect to
 * @port: Port number (1-65535)
 * @policy: Reconnection policy (NULL for defaults)
 * @callback: State change callback (NULL for no callbacks)
 * @userdata: User data passed to callbacks
 *
 * Returns: New reconnection context
 * Raises: SocketReconnect_Failed on initialization failure
 * @note Thread-safe: Yes (creates new instance)
 * @ingroup core_io
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
 * @ingroup core_io
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
 * @brief Start connecting.
 * @ingroup core_io
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
 * @brief Gracefully disconnect.
 * @ingroup core_io
 * @param conn Reconnection context.
 * @threadsafe No.
 * @note Disconnects without triggering reconnection logic. Resets attempt counter.
 * @note Use this for intentional disconnection (e.g., shutdown).
 * @see SocketReconnect_connect() for starting connections.
 * @see SocketReconnect_free() for complete cleanup.
 */
extern void SocketReconnect_disconnect (T conn);

/**
 * @brief Reset backoff and circuit breaker state.
 * @ingroup core_io
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
 * @brief Get underlying socket.
 * @ingroup core_io
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
 * @brief SocketReconnect_state - Get current state
 * @ingroup core_io
 * @conn: Reconnection context
 *
 * Returns: Current reconnection state
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern SocketReconnect_State SocketReconnect_state (T conn);

/**
 * @brief SocketReconnect_isconnected - Check if currently connected
 * @ingroup core_io
 * @conn: Reconnection context
 *
 * Returns: 1 if connected, 0 otherwise
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern int SocketReconnect_isconnected (T conn);

/**
 * @brief SocketReconnect_attempts - Get current attempt count
 * @ingroup core_io
 * @conn: Reconnection context
 *
 * Returns: Number of connection attempts since last success or reset
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern int SocketReconnect_attempts (T conn);

/**
 * @brief SocketReconnect_failures - Get consecutive failure count
 * @ingroup core_io
 * @conn: Reconnection context
 *
 * Returns: Number of consecutive failures (for circuit breaker)
 * @note Thread-safe: No
 * @ingroup core_io
 */
extern int SocketReconnect_failures (T conn);

/* ============================================================================
 * Event Loop Integration
 * ============================================================================
 */

/**
 * @brief SocketReconnect_pollfd - Get file descriptor for poll integration
 * @ingroup core_io
 * @conn: Reconnection context
 *
 * Returns: File descriptor to poll for read/write events, or -1 if none
 * @note Thread-safe: No
 * @ingroup core_io
 *
 * Returns the underlying socket fd when connecting or connected.
 * Add this to your poll set and call SocketReconnect_process() on events.
 */
extern int SocketReconnect_pollfd (T conn);

/**
 * @brief SocketReconnect_process - Process poll events
 * @ingroup core_io
 * @conn: Reconnection context
 *
 * @note Thread-safe: No
 * @ingroup core_io
 *
 * Call when SocketReconnect_pollfd() becomes readable/writable.
 * Handles connection completion, detects disconnection, etc.
 */
extern void SocketReconnect_process (T conn);

/**
 * @brief SocketReconnect_next_timeout_ms - Get time until next action
 * @ingroup core_io
 * @conn: Reconnection context
 *
 * Returns: Milliseconds until next timeout, or -1 if none pending
 * @note Thread-safe: No
 * @ingroup core_io
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
 * @brief SocketReconnect_tick - Process timers
 * @ingroup core_io
 * @conn: Reconnection context
 *
 * @note Thread-safe: No
 * @ingroup core_io
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
 * @brief SocketReconnect_set_health_check - Set custom health check function
 * @ingroup core_io
 * @conn: Reconnection context
 * @check: Health check function (NULL to use default)
 *
 * @note Thread-safe: No
 * @ingroup core_io
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
 * @brief SocketReconnect_policy_defaults - Initialize policy with defaults
 * @ingroup core_io
 * @policy: Policy structure to initialize
 *
 * @note Thread-safe: Yes
 * @ingroup core_io
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
 * @brief SocketReconnect_send - Send data with auto-reconnect on error
 * @ingroup core_io
 * @conn: Reconnection context
 * @buf: Data buffer to send
 * @len: Number of bytes to send
 *
 * Returns: Bytes sent (>0), 0 if not connected, -1 on error
 * @note Thread-safe: No
 * @ingroup core_io
 *
 * Sends data if connected. On connection error, triggers reconnection
 * and returns -1 with errno set to ENOTCONN.
 *
 * NOTE: This is a convenience wrapper. For more control, get the socket
 * with SocketReconnect_socket() and use Socket_send() directly.
 */
extern ssize_t SocketReconnect_send (T conn, const void *buf, size_t len);

/**
 * @brief SocketReconnect_recv - Receive data with auto-reconnect on error
 * @ingroup core_io
 * @conn: Reconnection context
 * @buf: Buffer to receive data into
 * @len: Maximum bytes to receive
 *
 * Returns: Bytes received (>0), 0 if EOF/disconnected, -1 on error
 * @note Thread-safe: No
 * @ingroup core_io
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
 * @brief SocketReconnect_state_name - Get string name for state
 * @ingroup core_io
 * @state: Reconnection state
 *
 * Returns: Static string with state name
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern const char *SocketReconnect_state_name (SocketReconnect_State state);

#undef T
#endif /* SOCKETRECONNECT_INCLUDED */
