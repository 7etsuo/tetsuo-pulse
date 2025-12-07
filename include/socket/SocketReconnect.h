#ifndef SOCKETRECONNECT_INCLUDED
#define SOCKETRECONNECT_INCLUDED

#include "core/Except.h"
#include "socket/Socket.h"
#include <stddef.h>
#include <sys/types.h>

/**
 * SocketReconnect.h - Automatic Reconnection Framework
 *
 * Part of the Socket Library
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
 * Usage (Event-driven):
 *   SocketReconnect_T conn = SocketReconnect_new("example.com", 443, NULL, callback, data);
 *   SocketReconnect_connect(conn);
 *   while (running) {
 *       int timeout = SocketReconnect_next_timeout_ms(conn);
 *       SocketPoll_wait(poll, &events, timeout);
 *       SocketReconnect_process(conn);  // On poll events
 *       SocketReconnect_tick(conn);     // Process timers
 *   }
 *   SocketReconnect_free(&conn);
 *
 * Usage (I/O Passthrough):
 *   SocketReconnect_T conn = SocketReconnect_new("example.com", 443, NULL, NULL, NULL);
 *   SocketReconnect_connect(conn);
 *   // Use SocketReconnect_send/recv - auto-reconnects on error
 *   ssize_t n = SocketReconnect_send(conn, data, len);
 */

#define T SocketReconnect_T
typedef struct T *T;

/* Exception for reconnection failures */
extern const Except_T SocketReconnect_Failed;

/* ============================================================================
 * Reconnection State
 * ============================================================================ */

/**
 * SocketReconnect_State - State of reconnection connection
 */
typedef enum
{
  RECONNECT_DISCONNECTED = 0, /**< Not connected, not attempting */
  RECONNECT_CONNECTING,       /**< Connection attempt in progress */
  RECONNECT_CONNECTED,        /**< Successfully connected */
  RECONNECT_BACKOFF,          /**< Waiting before retry (exponential backoff) */
  RECONNECT_CIRCUIT_OPEN      /**< Circuit breaker open, blocking attempts */
} SocketReconnect_State;

/* ============================================================================
 * Backoff Policy Configuration
 * ============================================================================ */

/**
 * SocketReconnect_Policy_T - Reconnection policy configuration
 *
 * Controls backoff timing, circuit breaker behavior, and health monitoring.
 */
typedef struct SocketReconnect_Policy
{
  /* Exponential backoff settings */
  int initial_delay_ms;  /**< First retry delay (default: 100ms) */
  int max_delay_ms;      /**< Maximum backoff cap (default: 30000ms) */
  double multiplier;     /**< Backoff multiplier (default: 2.0) */
  double jitter;         /**< Jitter factor 0.0-1.0 (default: 0.25) */
  int max_attempts;      /**< Max attempts before giving up, 0=unlimited (default: 10) */

  /* Circuit breaker settings */
  int circuit_failure_threshold; /**< Consecutive failures before opening (default: 5) */
  int circuit_reset_timeout_ms;  /**< Time before half-open probe (default: 60000ms) */

  /* Health monitoring settings */
  int health_check_interval_ms;  /**< Interval between health checks, 0=disabled (default: 30000ms) */
  int health_check_timeout_ms;   /**< Timeout for health check (default: 5000ms) */
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
 * ============================================================================ */

/**
 * SocketReconnect_Callback - State change callback function
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
 * SocketReconnect_HealthCheck - Custom health check function
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
 * ============================================================================ */

/**
 * SocketReconnect_new - Create a new reconnecting connection
 * @host: Hostname or IP address to connect to
 * @port: Port number (1-65535)
 * @policy: Reconnection policy (NULL for defaults)
 * @callback: State change callback (NULL for no callbacks)
 * @userdata: User data passed to callbacks
 *
 * Returns: New reconnection context
 * Raises: SocketReconnect_Failed on initialization failure
 * Thread-safe: Yes (creates new instance)
 *
 * Creates a reconnecting connection context. The connection is not
 * started automatically - call SocketReconnect_connect() to begin.
 */
extern T SocketReconnect_new (const char *host, int port,
                              const SocketReconnect_Policy_T *policy,
                              SocketReconnect_Callback callback,
                              void *userdata);

/**
 * SocketReconnect_free - Free a reconnecting connection
 * @conn: Pointer to context (will be set to NULL)
 *
 * Thread-safe: No
 *
 * Disconnects if connected and frees all resources.
 */
extern void SocketReconnect_free (T *conn);

/* ============================================================================
 * Connection Control
 * ============================================================================ */

/**
 * SocketReconnect_connect - Start connecting
 * @conn: Reconnection context
 *
 * Thread-safe: No
 *
 * Initiates connection. If already connected or connecting, this is a no-op.
 * If in backoff or circuit-open state, respects those constraints.
 */
extern void SocketReconnect_connect (T conn);

/**
 * SocketReconnect_disconnect - Gracefully disconnect
 * @conn: Reconnection context
 *
 * Thread-safe: No
 *
 * Disconnects without triggering reconnection logic. Resets attempt counter.
 * Use this for intentional disconnection (e.g., shutdown).
 */
extern void SocketReconnect_disconnect (T conn);

/**
 * SocketReconnect_reset - Reset backoff and circuit breaker state
 * @conn: Reconnection context
 *
 * Thread-safe: No
 *
 * Clears attempt counter, consecutive failures, and circuit breaker state.
 * Does not disconnect if connected. Use after external recovery.
 */
extern void SocketReconnect_reset (T conn);

/* ============================================================================
 * Socket Access
 * ============================================================================ */

/**
 * SocketReconnect_socket - Get underlying socket
 * @conn: Reconnection context
 *
 * Returns: Connected socket, or NULL if not connected
 * Thread-safe: No
 *
 * Returns the underlying socket only when in RECONNECT_CONNECTED state.
 * Do not close or free the returned socket directly.
 */
extern Socket_T SocketReconnect_socket (T conn);

/* ============================================================================
 * State Query
 * ============================================================================ */

/**
 * SocketReconnect_state - Get current state
 * @conn: Reconnection context
 *
 * Returns: Current reconnection state
 * Thread-safe: No
 */
extern SocketReconnect_State SocketReconnect_state (T conn);

/**
 * SocketReconnect_isconnected - Check if currently connected
 * @conn: Reconnection context
 *
 * Returns: 1 if connected, 0 otherwise
 * Thread-safe: No
 */
extern int SocketReconnect_isconnected (T conn);

/**
 * SocketReconnect_attempts - Get current attempt count
 * @conn: Reconnection context
 *
 * Returns: Number of connection attempts since last success or reset
 * Thread-safe: No
 */
extern int SocketReconnect_attempts (T conn);

/**
 * SocketReconnect_failures - Get consecutive failure count
 * @conn: Reconnection context
 *
 * Returns: Number of consecutive failures (for circuit breaker)
 * Thread-safe: No
 */
extern int SocketReconnect_failures (T conn);

/* ============================================================================
 * Event Loop Integration
 * ============================================================================ */

/**
 * SocketReconnect_pollfd - Get file descriptor for poll integration
 * @conn: Reconnection context
 *
 * Returns: File descriptor to poll for read/write events, or -1 if none
 * Thread-safe: No
 *
 * Returns the underlying socket fd when connecting or connected.
 * Add this to your poll set and call SocketReconnect_process() on events.
 */
extern int SocketReconnect_pollfd (T conn);

/**
 * SocketReconnect_process - Process poll events
 * @conn: Reconnection context
 *
 * Thread-safe: No
 *
 * Call when SocketReconnect_pollfd() becomes readable/writable.
 * Handles connection completion, detects disconnection, etc.
 */
extern void SocketReconnect_process (T conn);

/**
 * SocketReconnect_next_timeout_ms - Get time until next action
 * @conn: Reconnection context
 *
 * Returns: Milliseconds until next timeout, or -1 if none pending
 * Thread-safe: No
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
 * SocketReconnect_tick - Process timers
 * @conn: Reconnection context
 *
 * Thread-safe: No
 *
 * Call periodically or when SocketReconnect_next_timeout_ms() expires.
 * Handles backoff retry, circuit breaker state transitions, health checks.
 */
extern void SocketReconnect_tick (T conn);

/* ============================================================================
 * Health Check Configuration
 * ============================================================================ */

/**
 * SocketReconnect_set_health_check - Set custom health check function
 * @conn: Reconnection context
 * @check: Health check function (NULL to use default)
 *
 * Thread-safe: No
 *
 * Sets a custom health check function. Custom checks must respect
 * policy.health_check_timeout_ms to avoid blocking the calling thread.
 * Default health check polls socket with configurable timeout.
 */
extern void SocketReconnect_set_health_check (T conn,
                                              SocketReconnect_HealthCheck check);

/* ============================================================================
 * Policy Helpers
 * ============================================================================ */

/**
 * SocketReconnect_policy_defaults - Initialize policy with defaults
 * @policy: Policy structure to initialize
 *
 * Thread-safe: Yes
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
 * ============================================================================ */

/**
 * SocketReconnect_send - Send data with auto-reconnect on error
 * @conn: Reconnection context
 * @buf: Data buffer to send
 * @len: Number of bytes to send
 *
 * Returns: Bytes sent (>0), 0 if not connected, -1 on error
 * Thread-safe: No
 *
 * Sends data if connected. On connection error, triggers reconnection
 * and returns -1 with errno set to ENOTCONN.
 *
 * NOTE: This is a convenience wrapper. For more control, get the socket
 * with SocketReconnect_socket() and use Socket_send() directly.
 */
extern ssize_t SocketReconnect_send (T conn, const void *buf, size_t len);

/**
 * SocketReconnect_recv - Receive data with auto-reconnect on error
 * @conn: Reconnection context
 * @buf: Buffer to receive data into
 * @len: Maximum bytes to receive
 *
 * Returns: Bytes received (>0), 0 if EOF/disconnected, -1 on error
 * Thread-safe: No
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
 * ============================================================================ */

/**
 * SocketReconnect_state_name - Get string name for state
 * @state: Reconnection state
 *
 * Returns: Static string with state name
 * Thread-safe: Yes
 */
extern const char *SocketReconnect_state_name (SocketReconnect_State state);

#undef T
#endif /* SOCKETRECONNECT_INCLUDED */

