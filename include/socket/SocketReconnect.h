#ifndef SOCKETRECONNECT_INCLUDED
#define SOCKETRECONNECT_INCLUDED

#include "core/Except.h"
#include "socket/Socket.h"
#include <stddef.h>
#include <sys/types.h>

/**
 * @file SocketReconnect.h
 * @ingroup connection_mgmt
 * @brief Automatic reconnection framework for resilient TCP connections with
 * backoff and circuit breaker patterns.
 *
 * This header provides a robust reconnection mechanism for network
 * applications, implementing exponential backoff, jitter to avoid thundering
 * herd, circuit breaker to prevent cascading failures, and optional health
 * checks. The module integrates seamlessly with event loops and provides
 * transparent I/O wrappers that automatically handle disconnections and
 * reconnections.
 *
 * ## Features
 * - Exponential backoff with configurable initial delay, multiplier, max
 * delay, and jitter
 * - Circuit breaker pattern with failure threshold and reset timeout
 * - Periodic health checks with custom callback support
 * - State machine tracking connection lifecycle
 * - Event callbacks for state transitions
 * - Transparent send/recv with auto-reconnect on errors
 * - Event loop integration via pollfd, process, and tick functions
 * - Statistics query for attempts and failures
 *
 * ## Architecture Overview
 *
 * ```
 * ┌─────────────────────────────┐
 * │    Application Layer        │
 * │ SocketPool, HTTPClient, etc.│
 * └─────────────┬───────────────┘
 *               │ Uses
 * ┌─────────────▼───────────────┐
 * │   SocketReconnect_T         │
 * │  - State Machine            │
 * │  - Backoff Timer            │
 * │  - Circuit Breaker          │
 * │  - Health Check             │
 * └─────────────┬───────────────┘
 *               │ Uses
 * ┌─────────────▼───────────────┐
 * │     Core I/O Layer          │
 * │     Socket_T                │
 * └─────────────────────────────┘
 *               │ Uses
 * ┌─────────────▼───────────────┐
 * │   Foundation Layer          │
 * │   Arena, Except, Timer      │
 * └─────────────────────────────┘
 * ```
 *
 * ## Module Relationships
 * - **Depends on**: @ref core_io (Socket_T for underlying connections), @ref
 * foundation (Arena for memory, Except for error handling, SocketTimer for
 * internal timing)
 * - **Used by**: @ref connection_mgmt (SocketPool for pooled reconnections),
 * @ref http (SocketHTTPClient for resilient HTTP requests)
 * - **Integrates with**: @ref event_system (SocketPoll for event handling)
 *
 * ## Platform Requirements
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - Support for non-blocking sockets and poll/epoll/kqueue
 * - CLOCK_MONOTONIC for accurate timing
 * - No external dependencies beyond standard library and socket primitives
 *
 * ## Typical Usage Patterns
 *
 * ### Simple I/O Passthrough
 *
 * @code{.c}
 * SocketReconnect_Policy_T policy;
 * SocketReconnect_policy_defaults(&policy);
 * SocketReconnect_T conn = SocketReconnect_new("example.com", 443, &policy,
 * NULL, NULL); SocketReconnect_connect(conn);
 *
 * // Send/Recv automatically handle reconnections
 * ssize_t sent = SocketReconnect_send(conn, data, len);
 * ssize_t recv = SocketReconnect_recv(conn, buf, buflen);
 *
 * SocketReconnect_free(&conn);
 * @endcode
 *
 * ### Event Loop Integration
 *
 * @code{.c}
 * // In event loop
 * int fd = SocketReconnect_pollfd(conn);
 * if (fd >= 0) {
 *     // Poll fd for events
 *     SocketReconnect_process(conn);  // On events
 * }
 *
 * int timeout = SocketReconnect_next_timeout_ms(conn);
 * // Use timeout for poll
 *
 * SocketReconnect_tick(conn);  // Periodic call
 * @endcode
 *
 * ## Thread Safety
 * - Individual SocketReconnect_T instances must be accessed from a single
 * thread
 * - Multiple independent instances can run concurrently from different threads
 * - Callbacks execute in the thread that calls process() or tick()
 *
 * @warning Do not call free() from within callbacks to avoid use-after-free
 * @note Host resolution is synchronous; for async DNS use SocketDNS
 * integration externally
 * @complexity Most operations O(1); connection attempts O(1) per attempt
 *
 * @see SocketReconnect_new() Primary entry point
 * @see SocketReconnect_policy_defaults() For policy configuration
 * @see docs/RECONNECT.md for advanced configuration guide
 */

#define T SocketReconnect_T
/**
 * @brief Opaque handle for a reconnecting socket connection.
 * @ingroup connection_mgmt
 *
 * Represents a resilient TCP connection that automatically manages
 * reconnections using a state machine with exponential backoff, circuit
 * breaker protection, and health monitoring.
 *
 * The handle encapsulates:
 * - Internal state machine tracking DISCONNECTED, CONNECTING, CONNECTED,
 * BACKOFF, CIRCUIT_OPEN states
 * - Timers for backoff delays, circuit reset, and health checks
 * - Underlying Socket_T instance when connected
 * - Statistics for attempts and failures
 * - Optional callbacks for state changes and custom health checks
 *
 * ## Lifecycle Management
 *
 * 1. Create with SocketReconnect_new()
 * 2. Configure policy, callbacks, health check if needed
 * 3. Call SocketReconnect_connect() to start
 * 4. Integrate with event loop or use passthrough I/O
 * 5. Call SocketReconnect_free() to cleanup
 *
 * @code{.c}
 * // Full lifecycle
 * SocketReconnect_T conn = SocketReconnect_new(host, port, NULL, state_cb,
 * userdata); SocketReconnect_connect(conn);
 *
 * while (SocketReconnect_isconnected(conn)) {
 *     // Use conn...
 * }
 *
 * SocketReconnect_free(&conn);
 * @endcode
 *
 * ## Thread Safety Characteristics
 * - Not thread-safe: All operations must occur from the same thread
 * - Callbacks execute in the caller's thread context
 * - Internal state protected by non-reentrant design
 *
 * ## Integration Notes
 * - For event-driven apps: Use pollfd(), process(), tick(), next_timeout_ms()
 * - For simple apps: Use send()/recv() wrappers for auto-reconnect
 * - Combine with SocketPool for managing multiple reconnections
 * - Host/port are fixed at creation; for dynamic endpoints create new
 * instances
 *
 * @note Underlying socket is created/destroyed internally; do not access
 * directly except via SocketReconnect_socket()
 * @warning Frequent state changes may indicate network issues; monitor via
 * callbacks and statistics
 * @complexity State queries and timers O(1); connection establishment depends
 * on network latency
 *
 * @see SocketReconnect_new() Creation
 * @see SocketReconnect_free() Destruction
 * @see SocketReconnect_state() Current state
 * @see SocketReconnect_socket() Underlying socket access
 * @see SocketReconnect_Policy_T Configuration options
 */
typedef struct T *T;

/**
 * @brief Exception type for errors in the reconnection module.
 * @ingroup connection_mgmt
 *
 * This exception is raised for configuration errors, resource allocation
 * failures, or internal state inconsistencies. Common triggers include:
 * - Invalid policy values (negative delays, multiplier <=1.0, jitter <0 or >1)
 * - Arena allocation failure during initialization
 * - Invalid host/port parameters
 * - Unrecoverable state machine errors (rare)
 *
 * ## Handling Pattern
 *
 * @code{.c}
 * TRY {
 *     SocketReconnect_T conn = SocketReconnect_new(host, port, &policy, NULL,
 * NULL);
 *     // Use conn...
 * } EXCEPT(SocketReconnect_Failed) {
 *     fprintf(stderr, "Reconnect failed: %s\n",
 * Except_message(&Except_stack));
 *     // Log or retry with different params
 * } END_TRY;
 * @endcode
 *
 * @note Always check Socket_GetLastError() or Except_message() for detailed
 * error information
 * @see SocketReconnect_new() Primary raise point
 * @see core/Except.h Base exception handling framework
 * @see Socket_GetLastError() For system error details if applicable
 */
extern const Except_T SocketReconnect_Failed;

/* ============================================================================
 * Reconnection State
 * ============================================================================
 */

/**
 * @brief States of the reconnection state machine for tracking connection
 * lifecycle and backoff status.
 * @ingroup connection_mgmt
 *
 * The state machine transitions as follows:
 * - DISCONNECTED: Idle state, ready for connect() or after graceful disconnect
 * - CONNECTING: Active connection attempt in progress (non-blocking connect)
 * - CONNECTED: Successfully established and healthy connection
 * - BACKOFF: Waiting exponential delay before next retry after failure
 * - CIRCUIT_OPEN: Circuit breaker tripped, blocking attempts until reset
 * timeout
 *
 * Transitions are triggered by connect(), process(), tick(), send/recv errors,
 * health checks, and timeouts.
 *
 * ## State Transition Diagram
 *
 * ```
 * +-------------+     connect()     +-------------+
 * | DISCONNECTED| ----------------> | CONNECTING  |
 * +-------------+                  +-------------+
 *      ^                                   |
 *      | disconnect()                      | success/fail
 *      |                                   v
 * +-------------+    timeout/error    +-------------+    health fail
 * | CIRCUIT_OPEN| <-------------------|   BACKOFF   | <-------------- |
 * +-------------+                     +-------------+                 |
 *      ^                                             |                |
 *      | timeout                                     |                |
 *      |                                             |                |
 *      +--------------------------- reset() ---------+                |
 *                                                             failure |
 *                                                              |     |
 *                                                              v     |
 *                                                       +-------------+
 *                                                       | CONNECTED   |
 *                                                       +-------------+
 *                                                              |
 *                                                         send/recv |
 *                                                              |
 *                                                       disconnect() |
 *                                                              v
 *                                                       DISCONNECTED
 * ```
 *
 * ## State Properties Table
 *
 * | State | Description | pollfd() | send/recv | Actions |
 * |-------|-------------|----------|-----------|---------|
 * | DISCONNECTED | Not connected, idle | -1 | Block/0 | connect() starts
 * transition | | CONNECTING | Non-blocking connect in progress | Valid FD |
 * Block | process() completes | | CONNECTED | Active connection | Valid FD |
 * Available | Errors trigger BACKOFF | | BACKOFF | Exponential wait | -1 |
 * Block | tick() advances timer | | CIRCUIT_OPEN | Breaker open, no attempts |
 * -1 | Block | tick() resets after timeout |
 *
 * @note Use SocketReconnect_state_name() for logging/debugging state strings
 * @warning Avoid direct state manipulation; use public API functions
 *
 * @see SocketReconnect_state() Query current state
 * @see SocketReconnect_state_name() Human-readable names
 * @see SocketReconnect_Callback() For state change notifications
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
 * @brief Configuration structure defining backoff policy, circuit breaker
 * thresholds, and health check parameters for SocketReconnect_T.
 * @ingroup connection_mgmt
 *
 * This structure allows fine-tuning of the reconnection behavior:
 * - **Backoff Settings**: Control retry timing with exponential growth and
 * randomization
 * - **Circuit Breaker**: Prevent connection storms after repeated failures
 * - **Health Monitoring**: Periodic checks to detect connection degradation
 * early
 *
 * All fields are optional if using defaults via
 * SocketReconnect_policy_defaults(). Invalid values (e.g., negative delays,
 * multiplier <= 1.0) may raise SocketReconnect_Failed.
 *
 * ## Field Documentation
 *
 * See individual field comments for details. Recommended to start with
 * defaults and tune based on application needs.
 *
 * ## Default Values Table
 *
 * | Field | Default Value | Range/Notes |
 * |-------|---------------|-------------|
 * | initial_delay_ms | 100 | >0, first retry delay |
 * | max_delay_ms | 30000 | > initial, cap for backoff |
 * | multiplier | 2.0 | >1.0, exponential factor |
 * | jitter | 0.25 | 0.0-1.0, randomization % |
 * | max_attempts | 10 | >0 or 0=unlimited |
 * | circuit_failure_threshold | 5 | >0, consecutive fails to open |
 * | circuit_reset_timeout_ms | 60000 | >0, time to attempt recovery |
 * | health_check_interval_ms | 30000 | >0 or 0=disabled |
 * | health_check_timeout_ms | 5000 | >0, max block time for check |
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketReconnect_Policy_T policy;
 * SocketReconnect_policy_defaults(&policy);
 *
 * // Customize for aggressive retry
 * policy.initial_delay_ms = 50;
 * policy.max_delay_ms = 10000;
 * policy.multiplier = 1.5;
 * policy.max_attempts = 0;  // Unlimited
 *
 * SocketReconnect_T conn = SocketReconnect_new(host, port, &policy, NULL,
 * NULL);
 * @endcode
 *
 * @note Changes take effect only at creation; recreate instance to apply new
 * policy
 * @threadsafe Yes - plain struct, safe to initialize concurrently
 * @warning Setting jitter=0 may cause thundering herd in multi-instance
 * scenarios
 * @see SocketReconnect_policy_defaults() Initialize with safe defaults
 * @see SocketReconnect_new() Apply policy during creation
 */
typedef struct SocketReconnect_Policy
{
  /* Exponential backoff settings */
  int initial_delay_ms; /**< @brief Initial delay before first retry after
                         * failure (default: 100ms). Must be positive (>0).
                         * This is the starting point for exponential backoff:
                         * delay = initial * (multiplier ^ attempt) +/- jitter.
                         * @note Too small values may overload the target
                         * during recovery.
                         */
  int max_delay_ms; /**< @brief Maximum delay cap for backoff (default: 30000ms
                     * / 30s). Prevents unbounded growth. Actual delay clamped
                     * to this value.
                     * @warning Set higher than typical outage duration but low
                     * enough to meet SLA.
                     */
  double multiplier; /**< @brief Multiplier for exponential backoff
                      * (default: 2.0). New delay = previous * multiplier. Must
                      * be >1.0 for growth. Common values: 1.5
                      * (aggressive), 2.0 (standard), 3.0 (conservative).
                      * @note Values <=1.0 will raise SocketReconnect_Failed.
                      */
  double jitter; /**< @brief Jitter factor for randomization (default: 0.25 /
                  * 25%). Adds +/- jitter * delay randomness to avoid
                  * synchronized retries (thundering herd). Range: 0.0 (no
                  * jitter) to 1.0 (full randomization).
                  * @warning Jitter=0 with multiple instances may cause retry
                  * storms.
                  */
  int max_attempts; /**< @brief Maximum retry attempts before permanent failure
                     * (default: 10). 0 means unlimited retries (use with
                     * caution to avoid infinite loops). Counts only connection
                     * attempts, not health check failures.
                     * @note Reset via SocketReconnect_reset() to retry
                     * indefinitely.
                     */

  /* Circuit breaker settings */
  int circuit_failure_threshold; /**< @brief Consecutive failures to trigger
                                  * circuit open (default: 5). After this many
                                  * rapid failures, enters CIRCUIT_OPEN state
                                  * blocking further attempts. Helps prevent
                                  * cascading failures during outages.
                                  * @note Failures include connect errors and
                                  * immediate post-connect issues.
                                  */
  int circuit_reset_timeout_ms;  /**< @brief Time in CIRCUIT_OPEN before
                                  * attempting recovery probe (default: 60000ms
                                  * / 60s).  During this period, all connect()
                                  * calls are ignored.  After timeout,
                                  * transitions to CONNECTING for one probe
                                  * attempt.
                                  * @warning Too short may retry into ongoing
                                  * outage; too long delays recovery.
                                  */

  /* Health monitoring settings */
  int health_check_interval_ms; /**< @brief Interval between health checks when
                                 * CONNECTED (default: 30000ms / 30s). 0
                                 * disables health checks entirely. Checks run
                                 * via tick() or internal timer. Failed check
                                 * triggers transition to BACKOFF.
                                 * @note Overhead: Each check blocks briefly
                                 * (up to health_check_timeout_ms).
                                 */
  int health_check_timeout_ms;  /**< @brief Maximum time a health check may
                                 * block (default: 5000ms / 5s).  Custom health
                                 * callbacks must respect this limit to avoid
                                 * DoS.  Default check polls socket for
                                 * readability.
                                 * @warning Exceeding this may cause
                                 * tick()/process() to hang.
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
 * @brief Callback invoked on reconnection state transitions for monitoring and
 * custom logic.
 * @ingroup connection_mgmt
 * @param[in] conn The SocketReconnect_T instance changing state
 * @param[in] old_state State before the transition
 * @param[in] new_state State after the transition
 * @param[in] userdata User data provided at SocketReconnect_new()
 *
 * This callback is invoked synchronously from the thread calling process(),
 * tick(), or I/O functions that trigger state changes. Useful for:
 * - Logging state transitions for debugging
 * - Updating metrics (e.g., increment failure counters)
 * - Triggering application-level actions (e.g., alert on CIRCUIT_OPEN)
 * - Custom backoff adjustments (but avoid blocking)
 *
 * ## Invocation Guarantees
 * - Called exactly once per state transition
 * - Non-reentrant: No nested calls from within callback
 * - Short-lived: Should complete quickly to avoid delaying I/O processing
 *
 * ## Usage Example
 *
 * @code{.c}
 * static void
 * state_change_cb(SocketReconnect_T conn, SocketReconnect_State old,
 * SocketReconnect_State new, void *ud) { const char *old_name =
 * SocketReconnect_state_name(old); const char *new_name =
 * SocketReconnect_state_name(new); SOCKET_LOG_INFO_MSG("Reconnect %p: %s ->
 * %s", conn, old_name, new_name);
 *
 *     if (new == RECONNECT_CIRCUIT_OPEN) {
 *         // Alert or log outage
 *         // ud might be app context
 *     } else if (new == RECONNECT_CONNECTED) {
 *         // Resume operations
 *     }
 * }
 *
 * // Register at creation
 * SocketReconnect_T conn = SocketReconnect_new(host, port, NULL,
 * state_change_cb, app_context);
 * @endcode
 *
 * @note Do not call SocketReconnect_free(), connect(), or other mutating
 * functions from within the callback to avoid recursion or use-after-free
 * @warning Blocking operations (e.g., I/O, sleeps) in callback may stall the
 * event loop
 * @threadsafe No - executes in caller's thread; ensure caller is
 * single-threaded per instance
 *
 * @see SocketReconnect_new() Register callback during creation
 * @see SocketReconnect_state() Query state directly
 * @see SocketReconnect_state_name() String names for logging
 */
typedef void (*SocketReconnect_Callback) (T conn,
                                          SocketReconnect_State old_state,
                                          SocketReconnect_State new_state,
                                          void *userdata);

/**
 * @brief Custom health check callback to verify connection liveness beyond
 * basic connectivity.
 * @ingroup connection_mgmt
 * @param[in] conn Reconnection context performing the check
 * @param[in] socket Underlying connected Socket_T to test
 * @param[in] timeout_ms Maximum milliseconds to block/wait for the check;
 * 0=non-blocking
 * @param[in] userdata User data from SocketReconnect_new() or
 * set_health_check()
 *
 * @return 1 if healthy (connection responsive), 0 if unhealthy (triggers
 * BACKOFF transition)
 *
 * Invoked periodically (per policy.health_check_interval_ms) during CONNECTED
 * state to proactively detect issues like high latency or partial failures.
 * The check should verify application-level health if possible (e.g., ping
 * endpoint, read heartbeat).
 *
 * ## Requirements
 * - Must complete within timeout_ms or risk blocking the event loop
 * - Non-blocking preferred when timeout_ms=0
 * - Return 0 on any failure to err on side of caution
 * - Default: Polls socket for readability (detects dead peers)
 *
 * ## Security Considerations
 * - Respect timeout to prevent DoS from slow/malicious health checks
 * - Avoid external calls (DNS, HTTP) that could be exploited
 * - Use Socket_set_timeout() on socket if needed for check operations
 *
 * ## Usage Example
 *
 * @code{.c}
 * static int
 * my_health_check(SocketReconnect_T conn, Socket_T sock, int timeout_ms, void
 * *ud) {
 *     // Simple ping: send heartbeat, expect response within timeout
 *     char ping[] = "PING";
 *     char buf[64];
 *
 *     ssize_t sent = Socket_send(sock, ping, sizeof(ping)-1);
 *     if (sent < 0) return 0;
 *
 *     struct pollfd pfd = { Socket_fd(sock), POLLIN, 0 };
 *     int ready = poll(&pfd, 1, timeout_ms);
 *     if (ready <= 0) return 0;  // Timeout or error
 *
 *     ssize_t rcvd = Socket_recv(sock, buf, sizeof(buf)-1);
 *     return (rcvd > 0 && strncmp(buf, "PONG", 4) == 0);
 * }
 *
 * // Set after creation
 * SocketReconnect_set_health_check(conn, my_health_check);
 * @endcode
 *
 * @warning Exceeding timeout_ms may cause overall system hangs; always check
 * time remaining
 * @note Custom checks run in caller's thread; ensure non-blocking where
 * possible
 * @threadsafe No - executes in tick()/process() caller's context
 *
 * @see SocketReconnect_set_health_check() Register custom check
 * @see SocketReconnect_Policy_T::health_check_interval_ms Control frequency
 * @see SocketReconnect_Policy_T::health_check_timeout_ms Set max block time
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
 * @brief Create a new SocketReconnect_T instance configured for a specific
 * host and port.
 * @ingroup connection_mgmt
 * @param[in] host Target hostname (e.g., "example.com") or IP address
 * (IPv4/IPv6)
 * @param[in] port Target port (1-65535); 0 invalid and will raise exception
 * @param[in] policy Optional custom policy (NULL uses defaults from
 * SocketReconnect_policy_defaults())
 * @param[in] callback Optional state transition callback (NULL to disable)
 * @param[in] userdata User data passed unchanged to callbacks (may be NULL)
 *
 * @return New opaque SocketReconnect_T handle in DISCONNECTED state
 * @throws SocketReconnect_Failed On invalid parameters (null host, invalid
 * port, bad policy values), Arena allocation failure, or internal init errors
 *
 * Initializes a reconnection context with the specified endpoint. Hostname is
 * resolved synchronously using getaddrinfo(); for async resolution integrate
 * with SocketDNS externally. The instance starts in RECONNECT_DISCONNECTED
 * state. No connection attempt is made until SocketReconnect_connect() is
 * called. Resources (timers, state) are allocated from internal Arena; freed
 * on SocketReconnect_free().
 *
 * ## Validation Rules
 * - host must be non-null and valid (checked via getaddrinfo)
 * - port 1-65535
 * - policy values validated (positive delays, multiplier >1, etc.)
 * - callback may be NULL
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Basic creation with defaults
 * TRY {
 *     SocketReconnect_T conn = SocketReconnect_new("api.example.com", 443,
 * NULL, NULL, NULL); SocketReconnect_connect(conn);
 *     // Now integrate with loop or use I/O wrappers
 * } EXCEPT(SocketReconnect_Failed) {
 *     // Handle init failure (e.g., invalid host)
 * } END_TRY;
 * @endcode
 *
 * ## Advanced Configuration
 *
 * @code{.c}
 * SocketReconnect_Policy_T policy;
 * SocketReconnect_policy_defaults(&policy);
 * policy.max_attempts = 0;  // Unlimited retries
 * policy.health_check_interval_ms = 10000;  // Check every 10s
 *
 * static void state_cb(SocketReconnect_T c, SocketReconnect_State o,
 * SocketReconnect_State n, void *ud) {
 *     // Log transition
 * }
 *
 * SocketReconnect_T conn = SocketReconnect_new("db.internal", 5432, &policy,
 * state_cb, app_ctx);
 * @endcode
 *
 * @threadsafe Yes - each instance independent; safe from any thread but use
 * single-thread per instance thereafter
 * @complexity O(1) setup + O(n) getaddrinfo() where n=address families
 * @note Host/port fixed at creation; for dynamic targets create new instances
 * or use SocketProxy
 * @warning Synchronous DNS may block briefly; consider caching resolved
 * addresses for performance
 * @see SocketReconnect_policy_defaults() Safe default policy
 * @see SocketReconnect_connect() Start connection process
 * @see SocketReconnect_free() Cleanup resources
 * @see SocketReconnect_set_health_check() Post-creation health customization
 */
extern T SocketReconnect_new (const char *host, int port,
                              const SocketReconnect_Policy_T *policy,
                              SocketReconnect_Callback callback,
                              void *userdata);

/**
 * @brief Destroy a SocketReconnect_T instance and release all associated
 * resources.
 * @ingroup connection_mgmt
 * @param[in,out] conn Pointer to the SocketReconnect_T handle (set to NULL on
 * success)
 *
 * Performs immediate cleanup:
 * - If CONNECTED or CONNECTING: Calls underlying socket shutdown/close
 * - Cancels any pending timers or health checks
 * - Releases internal memory allocations
 * - Invokes no callbacks (safe during destruction)
 * - Sets *conn to NULL to prevent use-after-free
 *
 * ## Cleanup Guarantees
 * - Graceful shutdown of socket if possible (SOCKET_SHUT_RDWR)
 * - All resources returned to system (no leaks)
 * - Underlying Socket_T freed internally
 * - Statistics reset (not preserved)
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketReconnect_T conn = SocketReconnect_new(host, port, NULL, NULL, NULL);
 * // ... use connection ...
 *
 * SocketReconnect_disconnect(conn);  // Optional graceful close
 * SocketReconnect_free(&conn);       // Required cleanup
 * assert(conn == NULL);
 * @endcode
 *
 * @threadsafe No - must be called from the thread managing the instance
 * @complexity O(1) - socket close is O(1), timers cancelled instantly
 * @note Always pair with SocketReconnect_new(); unpaired frees undefined
 * @warning Calling on NULL or already-freed pointer is safe (no-op)
 * @see SocketReconnect_new() Creation counterpart
 * @see SocketReconnect_disconnect() Graceful disconnect without full cleanup
 * @see Socket_debug_live_count() Verify no leaks in tests (should be 0 after
 * free)
 */
extern void SocketReconnect_free (T *conn);

/* ============================================================================
 * Connection Control
 * ============================================================================
 */

/**
 * @brief Initiate or queue a connection attempt according to current state and
 * policy.
 * @ingroup connection_mgmt
 * @param[in] conn SocketReconnect_T instance to connect
 *
 * Triggers transition from DISCONNECTED to CONNECTING if possible.
 * Behavior based on current state:
 * - DISCONNECTED: Starts non-blocking connect to resolved host/port
 * - CONNECTING: No-op (already attempting)
 * - CONNECTED: No-op (already connected)
 * - BACKOFF: Queues retry after current backoff timer expires (via tick())
 * - CIRCUIT_OPEN: Ignored until reset timeout elapses
 *
 * Success/failure detected via SocketReconnect_process() on poll events or
 * timeouts. Failed attempts increment statistics and may trigger backoff or
 * circuit open.
 *
 * ## State Transitions Triggered
 * - DISCONNECTED -> CONNECTING (immediate)
 * - BACKOFF -> CONNECTING (after delay)
 * - CIRCUIT_OPEN -> ignored
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketReconnect_T conn = SocketReconnect_new("example.com", 80, NULL, NULL,
 * NULL);
 *
 * SocketReconnect_connect(conn);  // Start first attempt
 *
 * // In event loop:
 * int fd = SocketReconnect_pollfd(conn);
 * if (event on fd ) { // e.g., POLLOUT or POLLIN
 *     SocketReconnect_process(conn);
 * }
 *
 * // After failure, auto-retries per policy
 * @endcode
 *
 * @threadsafe No - state mutation not safe across threads
 * @complexity O(1) - defers actual connect to non-blocking socket call
 * @note getaddrinfo() cached from creation; no repeated DNS lookups
 * @warning Calling repeatedly in rapid succession wastes CPU; rely on
 * auto-retry
 * @see SocketReconnect_state() Check if connect was accepted
 * @see SocketReconnect_process() Handle connection completion events
 * @see SocketReconnect_tick() Advance timers for queued retries
 * @see SocketReconnect_disconnect() Stop and reset without retry
 */
extern void SocketReconnect_connect (T conn);

/**
 * @brief Gracefully disconnect without triggering reconnect.
 * @ingroup connection_mgmt
 * @param conn Reconnection context.
 * @threadsafe No.
 * @note Disconnects without triggering reconnection logic. Resets attempt
 * counter.
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
 * @note Clears attempt counter, consecutive failures, and circuit breaker
 * state.
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
 * @brief Query the current state of the reconnection instance.
 * @ingroup connection_mgmt
 * @param[in] conn SocketReconnect_T to query
 *
 * @return Current SocketReconnect_State (e.g., RECONNECT_CONNECTED)
 * @threadsafe No - but read-only, safe if no concurrent mutations
 *
 * Provides snapshot of internal state machine for decision making or logging.
 * States reflect connection status, backoff timers, and circuit breaker.
 * Use in conditionals to gate operations (e.g., only send when CONNECTED).
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketReconnect_State st = SocketReconnect_state(conn);
 * switch (st) {
 *     case RECONNECT_CONNECTED:
 *         // Safe to send/recv
 *         break;
 *     case RECONNECT_CIRCUIT_OPEN:
 *         // Outage detected, alert
 *         break;
 *     default:
 *         // Wait or retry
 * }
 *
 * // Log with name
 * SOCKET_LOG_DEBUG_MSG("State: %s", SocketReconnect_state_name(st));
 * @endcode
 *
 * @complexity O(1)
 * @note State may change immediately after call due to async nature; check in
 * event handlers
 * @see SocketReconnect_isconnected() Convenience for CONNECTED check
 * @see SocketReconnect_state_name() String representation for logs
 * @see SocketReconnect_Callback() Asynchronous state notifications
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
 * @brief Retrieve file descriptor for event loop integration
 * (poll/epoll/kqueue/select).
 * @ingroup connection_mgmt
 * @param[in] conn SocketReconnect_T instance
 *
 * @return Valid FD (>=0) during CONNECTING/CONNECTED states for polling
 * read/write events, -1 otherwise (no polling needed)
 *
 * Provides the underlying socket file descriptor for multiplexing with other
 * FDs in event loops. Usage:
 * - During CONNECTING: Poll for write (connect completion) or error
 * - During CONNECTED: Poll for read (data available) or write (send buffer
 * ready)
 * - Other states: -1 (no FD to poll; use next_timeout_ms() for timers)
 *
 * Always pair with SocketReconnect_process() when events occur on this FD.
 * FD changes on reconnect (new socket created); re-add to epoll etc. after
 * state change callbacks.
 *
 * ## Event Loop Integration Example
 *
 * @code{.c}
 * // Single instance loop example
 * SocketReconnect_T conn = SocketReconnect_new(...);
 * SocketReconnect_connect(conn);
 *
 * while (running) {
 *     int fd = SocketReconnect_pollfd(conn);
 *     int timeout = SocketReconnect_next_timeout_ms(conn);
 *
 *     // Poll setup (pseudocode)
 *     if (fd >= 0) poll_add(fd, POLLIN | POLLOUT | POLLERR | POLLHUP);
 *
 *     int ready = poll_events(timeout);  // Implement poll loop
 *
 *     if (fd >= 0 && event_on_fd(ready)) {
 *         SocketReconnect_process(conn);
 *     }
 *
 *     SocketReconnect_tick(conn);  // Advance timers
 * }
 * @endcode
 *
 * @threadsafe No - FD may change concurrently if multi-threaded (avoid)
 * @complexity O(1)
 * @note FD valid only while returned >=0; do not close or modify directly
 * @warning In epoll/kqueue, use edge-triggered mode carefully; level-triggered
 * safer
 * @see SocketReconnect_process() Process events on this FD
 * @see SocketReconnect_next_timeout_ms() Timer integration
 * @see SocketReconnect_tick() Periodic timer advancement
 * @see poll/SocketPoll.h For high-performance multiplexing
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
 * @brief Advance timers and perform periodic maintenance for state transitions
 * and checks.
 * @ingroup connection_mgmt
 * @param[in] conn SocketReconnect_T to tick
 *
 * Essential function for timer-driven operations:
 * - Advances backoff timers (may trigger CONNECTING from BACKOFF)
 * - Checks circuit reset timeout (may allow new attempts)
 * - Performs health checks if interval elapsed (in CONNECTED)
 * - Detects timeouts for ongoing connects
 * - No-op if no timers pending
 *
 * Call this:
 * - Periodically in main loop (e.g., every 100ms or after poll timeout)
 * - Immediately after SocketReconnect_next_timeout_ms() returns <=0
 * - Does not block; quick execution unless health check active
 *
 * ## Integration Patterns
 *
 * ### With Event Loop
 *
 * @code{.c}
 * while (running) {
 *     int timeout = SocketReconnect_next_timeout_ms(conn);
 *     timeout = MIN(timeout, 100);  // Cap for responsiveness
 *
 *     // Poll with timeout
 *     poll_wait(timeout);
 *
 *     SocketReconnect_tick(conn);  // Handle expired timers
 *
 *     int fd = SocketReconnect_pollfd(conn);
 *     if (event_on_fd(fd)) {
 *         SocketReconnect_process(conn);
 *     }
 * }
 * @endcode
 *
 * ### Standalone Periodic Call
 *
 * @code{.c}
 * // In timer thread or main loop
 * static int64_t last_tick = 0;
 * int64_t now = Socket_get_monotonic_ms();
 * if (now - last_tick >= 50) {  // 50ms granularity
 *     SocketReconnect_tick(conn);
 *     last_tick = now;
 * }
 * @endcode
 *
 * @threadsafe No - modifies timers and may change state
 * @complexity O(1) average; O(health check time) if check runs
 * @note Use Socket_get_monotonic_ms() internally for precision
 * @warning Infrequent calls (> policy intervals) may delay detections; call
 * regularly
 * @see SocketReconnect_next_timeout_ms() Determine optimal call frequency
 * @see SocketReconnect_process() Handle FD events (complement)
 * @see SocketReconnect_HealthCheck Custom check during tick
 */
extern void SocketReconnect_tick (T conn);

/* ============================================================================
 * Health Check Configuration
 * ============================================================================
 */

/**
 * @brief Register a custom health check callback for proactive connection
 * validation.
 * @ingroup connection_mgmt
 * @param[in] conn SocketReconnect_T to configure
 * @param[in] check Custom health check function (NULL to revert to default)
 *
 * Overrides the default health check behavior used during CONNECTED state.
 * The default check simply polls the socket for readability within the
 * configured timeout to detect dead peers. Custom checks can perform
 * application-specific validation (e.g., send ping, check latency).
 *
 * Changes take effect on next health check interval (no immediate invocation).
 * If health checks disabled (interval=0), this has no effect.
 *
 * ## Default vs Custom
 * - **Default**: Socket_poll for POLLIN within timeout_ms (lightweight,
 * detects closes)
 * - **Custom**: Caller-defined; must return 1=healthy, 0=unhealthy quickly
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Set custom check after creation
 * SocketReconnect_set_health_check(conn, my_app_ping_check);
 *
 * // Or revert to default
 * SocketReconnect_set_health_check(conn, NULL);
 * @endcode
 *
 * @threadsafe No - modifies instance configuration
 * @complexity O(1) - simple assignment
 * @note Callback userdata is from creation (not set here); for per-check data
 * use conn context
 * @warning Custom checks blocking > timeout_ms will hang tick()/process();
 * always respect limit
 * @see SocketReconnect_HealthCheck Callback type definition and requirements
 * @see SocketReconnect_Policy_T::health_check_interval_ms Enable/disable
 * checks
 * @see SocketReconnect_Policy_T::health_check_timeout_ms Set timeout limit
 */
extern void
SocketReconnect_set_health_check (T conn, SocketReconnect_HealthCheck check);

/* ============================================================================
 * Policy Helpers
 * ============================================================================
 */

/**
 * @brief Populate a SocketReconnect_Policy_T with safe, production-recommended
 * default values.
 * @ingroup connection_mgmt
 * @param[out] policy Pointer to structure to initialize (overwritten)
 *
 * Sets balanced defaults suitable for most TCP services:
 * - Conservative backoff to avoid overload
 * - Circuit breaker to prevent storms
 * - Health checks for proactive failure detection
 *
 * ## Defaults Table
 *
 * | Setting | Value | Rationale |
 * |---------|-------|-----------|
 * | initial_delay_ms | 100 | Quick first retry without overwhelming |
 * | max_delay_ms | 30000 | 30s cap prevents long hangs |
 * | multiplier | 2.0 | Standard exponential growth |
 * | jitter | 0.25 | 25% randomization avoids herd |
 * | max_attempts | 10 | Limit retries to prevent infinite loops |
 * | circuit_failure_threshold | 5 | Quick detection of outages |
 * | circuit_reset_timeout_ms | 60000 | 1min cooldown before probe |
 * | health_check_interval_ms | 30000 | Check every 30s, low overhead |
 * | health_check_timeout_ms | 5000 | 5s max to avoid blocking |
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketReconnect_Policy_T policy;
 * SocketReconnect_policy_defaults(&policy);
 *
 * // Optional tweaks
 * policy.initial_delay_ms = 200;  // Slower start for busy servers
 *
 * SocketReconnect_T conn = SocketReconnect_new(host, port, &policy, NULL,
 * NULL);
 * @endcode
 *
 * @return void (populates policy in place)
 * @threadsafe Yes - pure function, no side effects
 * @complexity O(1) - simple assignment
 * @note Always use this before custom modifications to ensure valid base
 * @warning Modifying after SocketReconnect_new() requires new instance
 * @see SocketReconnect_Policy_T Full field documentation
 * @see SocketReconnect_new() Apply initialized policy
 */
extern void SocketReconnect_policy_defaults (SocketReconnect_Policy_T *policy);

/* ============================================================================
 * I/O Passthrough (Auto-Reconnect on Error)
 * ============================================================================
 */

/**
 * @brief Send data over the reconnection-managed connection with automatic
 * retry on transient errors.
 * @ingroup connection_mgmt
 * @param[in] conn Reconnection context
 * @param[in] buf Buffer containing data to send
 * @param[in] len Number of bytes from buf to send (0 valid, no-op)
 *
 * @return Number of bytes sent (>0 success), 0 if not connected
 * (DISCONNECTED/BACKOFF/CIRCUIT_OPEN), -1 on error
 *
 * Convenience wrapper providing transparent I/O over the managed connection.
 * Behavior:
 * - If CONNECTED: Delegates to Socket_send() on underlying socket
 * - If not connected: Returns 0 immediately (no blocking)
 * - On send error or disconnection: Triggers reconnect logic, sets errno to
 * ENOTCONN, returns -1
 * - Partial sends possible (like Socket_send); caller must handle retries if
 * needed
 *
 * Does not buffer unsent data; for reliability use higher-level protocols (TCP
 * ensures delivery if connected).
 *
 * ## Error Handling
 * - errno=ENOTCONN: Not connected or lost connection (reconnect queued)
 * - errno=ECONNRESET/EPIPE: Peer closed, triggers reconnect
 * - Other errnos propagated from underlying socket
 *
 * ## Usage Example - Transparent Send
 *
 * @code{.c}
 * // Assume conn connected
 * const char *msg = "Hello Server";
 * ssize_t sent = SocketReconnect_send(conn, msg, strlen(msg));
 * if (sent < 0) {
 *     if (errno == ENOTCONN) {
 *         // Reconnect will happen automatically
 *         SOCKET_LOG_WARN_MSG("Send failed, reconnecting...");
 *     } else {
 *         // Handle other errors
 *     }
 * } else {
 *     // sent bytes transmitted or queued in TCP
 * }
 * @endcode
 *
 * ## When to Use vs Direct Socket
 * - Use this for simple apps wanting auto-reconnect without event loop
 * - For performance/control: Get socket with SocketReconnect_socket() and use
 * Socket_sendv() etc.
 * - Buffering? Use SocketPool or application-level queues
 *
 * @threadsafe No - modifies internal state
 * @complexity O(len) - underlying send syscall
 * @note SIGPIPE handled internally (no signal sent)
 * @warning Not for large data; consider Socket_sendfile() or chunking for big
 * transfers
 * @see SocketReconnect_recv() Counterpart receive wrapper
 * @see SocketReconnect_socket() Direct access for advanced I/O
 * @see Socket_send() Underlying primitive
 */
extern ssize_t SocketReconnect_send (T conn, const void *buf, size_t len);

/**
 * @brief Receive data from the reconnection-managed connection,
 * auto-reconnecting on close or errors.
 * @ingroup connection_mgmt
 * @param[in] conn Reconnection context
 * @param[out] buf Buffer to receive data into
 * @param[in] len Maximum bytes to receive into buf (must >0)
 *
 * @return Bytes received (>0), 0 on EOF/disconnect (triggers reconnect), -1 on
 * error
 *
 * Symmetric to SocketReconnect_send(): Provides transparent recv with
 * auto-recovery. Behavior:
 * - If CONNECTED: Delegates to Socket_recv() on underlying socket
 * - If not connected: Returns 0 immediately (would block)
 * - On recv error, EOF (0 bytes), or disconnect: Triggers reconnection,
 * returns 0
 * - Partial receives possible; loop until 0 for full messages
 *
 * TCP ensures ordered delivery when connected; 0 indicates clean close or
 * abrupt disconnect.
 *
 * ## Error Handling
 * - Return 0: EOF or error triggering reconnect (check state after)
 * - errno=EAGAIN: Would block (non-blocking mode); try again later
 * - Other errnos from underlying recv propagated
 *
 * ## Usage Example - Transparent Recv Loop
 *
 * @code{.c}
 * char buf[1024];
 * while (running && SocketReconnect_isconnected(conn)) {
 *     ssize_t rcvd = SocketReconnect_recv(conn, buf, sizeof(buf));
 *     if (rcvd > 0) {
 *         // Process data
 *         process_data(buf, rcvd);
 *     } else if (rcvd == 0) {
 *         SOCKET_LOG_INFO_MSG("Connection closed, reconnecting...");
 *         // Auto-reconnect happens
 *         break;  // Or continue to wait
 *     } else {  // -1
 *         if (errno != EAGAIN) {
 *             // Handle error
 *         }
 *     }
 * }
 * @endcode
 *
 * ## Performance Notes
 * - For high-throughput: Use recvv() variants via direct socket access
 * - Buffering: No internal queue; data lost on disconnect before recv
 * - Non-blocking: Safe in event loops; returns EAGAIN if no data
 *
 * @threadsafe No - may trigger state changes
 * @complexity O(len) - underlying recv syscall
 * @note Handles partial reads; application must loop for complete messages
 * @warning Recv in non-connected state wastes CPU; check isconnected() first
 * @see SocketReconnect_send() Send counterpart
 * @see SocketReconnect_socket() For recvv, peek, etc.
 * @see Socket_recv() Underlying primitive
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
