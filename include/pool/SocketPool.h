#ifndef SOCKETPOOL_INCLUDED
#define SOCKETPOOL_INCLUDED

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketSYNProtect.h"
#include "core/SocketUtil.h" /* For socket_error_buf in macros */
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketReconnect.h"
#include <stddef.h>
#include <time.h>
#include "dns/SocketDNS.h"

/**
 * Socket Connection Pool
 * Manages a pool of socket connections with associated buffers and
 * metadata. Provides O(1) connection lookup using hash tables and
 * automatic cleanup of idle connections.
 * Features:
 * - Pre-allocated connection slots for predictable memory usage
 * - Hash table for O(1) socket lookup
 * - Automatic idle connection cleanup
 * - Per-connection input/output buffers
 * - User data storage per connection
 * - Dynamic resize and pre-warming for performance
 * The Connection_T type is opaque - use accessor functions to
 * access connection properties.
 * Thread Safety: All operations are thread-safe via internal mutex.
 * The pool can be used from multiple threads simultaneously.
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - POSIX threads (pthread) for mutex synchronization
 * - NOT portable to Windows without pthreads adaptation
 */

#define T SocketPool_T
typedef struct T *T;

/* Opaque connection type - use accessor functions */
typedef struct Connection *Connection_T;

/* Forward declarations for callback types used in pool structure */
typedef int (*SocketPool_ValidationCallback) (Connection_T conn, void *data);
typedef void (*SocketPool_ResizeCallback) (T pool, size_t old_size,
                                           size_t new_size, void *data);

/**
 * SocketPool_ConnectCallback - Callback for async connection completion
 * @conn: Completed connection or NULL on error
 * @error: 0 on success, error code on failure
 * @data: User data from SocketPool_connect_async
 *
 * Called when async connection (DNS resolve + connect + pool add) completes.
 *
 * THREAD SAFETY WARNING:
 * This callback is invoked from a DNS worker thread, NOT the main thread.
 * Callback implementations MUST be thread-safe and MUST NOT:
 * - Access thread-local storage from the main thread
 * - Call non-thread-safe functions
 * - Modify shared state without proper synchronization
 *
 * Common safe patterns:
 * - Use mutex protection when accessing shared data
 * - Use atomic operations for simple counters/flags
 * - Queue work items for main thread processing
 * - Signal condition variables or write to self-pipes
 *
 * The pool mutex is NOT held during callback invocation, so the callback
 * MAY safely call other SocketPool functions.
 */
typedef void (*SocketPool_ConnectCallback) (Connection_T conn, int error, void *data);

/* ============================================================================
 * Exception Types
 * ============================================================================ */

/**
 * SocketPool_Failed - Pool operation failure
 *
 * Category: RESOURCE or APPLICATION
 * Retryable: Depends on specific operation
 *
 * Raised for:
 * - Pool capacity exhaustion (RESOURCE, retryable after drain)
 * - Invalid parameters (APPLICATION, not retryable)
 * - Memory allocation failures (RESOURCE, not retryable)
 * - Connection validation failures (NETWORK, retryable)
 *
 * Check errno or context for specific failure reason.
 */
extern const Except_T SocketPool_Failed;

/**
 * SocketPool_new - Create a new connection pool
 * @arena: Arena for memory allocation
 * @maxconns: Maximum number of connections
 * @bufsize: Size of I/O buffers per connection
 * Returns: New pool instance (never returns NULL)
 * Raises: SocketPool_Failed on any allocation or initialization failure
 * Thread-safe: Yes - returns new instance
 * Automatically pre-warms SOCKET_POOL_DEFAULT_PREWARM_PCT slots.
 */
extern T SocketPool_new (Arena_T arena, size_t maxconns, size_t bufsize);

/**
 * SocketPool_prepare_connection - Prepare async connection using DNS
 * @pool: Pool instance (used for configuration and cleanup)
 * @dns: DNS resolver instance
 * @host: Remote hostname or IP
 * @port: Remote port (1-65535)
 * @out_socket: Output - new Socket_T instance
 * @out_req: Output - SocketDNS_Request_T for monitoring
 * Returns: 0 on success, -1 on error (out_socket/out_req undefined)
 * Raises: SocketPool_Failed on error
 * Thread-safe: Yes
 * Creates a new Socket_T, configures pool defaults (non-blocking, reuseaddr, etc.),
 * starts async DNS resolution + connect preparation via Socket_connect_async.
 * User must monitor out_req with SocketDNS (check/pollfd/getresult), then
 * call Socket_connect_with_addrinfo(out_socket, res) on completion, then
 * SocketPool_add(pool, out_socket) to add to pool.
 * On error/cancel, Socket_free(&out_socket) and handle.
 * Integrates SocketDNS for non-blocking hostname resolution in pooled connections.
 */
extern int SocketPool_prepare_connection (T pool, SocketDNS_T dns, const char *host, int port, Socket_T *out_socket, SocketDNS_Request_T *out_req);

/**
 * SocketPool_free - Free a connection pool
 * @pool: Pointer to pool (will be set to NULL)
 * Note: Does not close sockets - caller must do that
 * Thread-safe: Yes
 */
extern void SocketPool_free (T *pool);

/**
 * SocketPool_connect_async - Create async connection to remote host
 * @pool: Pool instance
 * @host: Remote hostname or IP address
 * @port: Remote port number
 * @callback: Completion callback (see SocketPool_ConnectCallback for thread safety)
 * @data: User data passed to callback
 *
 * Returns: SocketDNS_Request_T for monitoring completion
 * Raises: SocketPool_Failed on invalid params, allocation error, or limit reached
 * Thread-safe: Yes
 *
 * Starts async DNS resolution + connect + pool add. On completion:
 * - Success: callback(conn, 0, data) with Connection_T added to pool
 * - Failure: callback(NULL, error_code, data)
 *
 * IMPORTANT: The callback is invoked from a DNS worker thread, not the calling
 * thread. See SocketPool_ConnectCallback documentation for thread safety requirements.
 *
 * Security: Limited to SOCKET_POOL_MAX_ASYNC_PENDING concurrent operations
 * to prevent resource exhaustion attacks.
 *
 * Integrates with SocketDNS for non-blocking resolution.
 * SocketPool_add is called internally on successful connect.
 * Caller owns no resources; pool manages connection lifecycle.
 */
extern SocketDNS_Request_T SocketPool_connect_async (T pool, const char *host, int port, SocketPool_ConnectCallback callback, void *data);

/**
 * SocketPool_get - Look up connection by socket
 * @pool: Pool instance
 * @socket: Socket to find
 * Returns: Connection or NULL if not found
 * Thread-safe: Yes
 * O(1) hash lookup. Updates last_activity timestamp.
 */
extern Connection_T SocketPool_get (T pool, Socket_T socket);

/**
 * SocketPool_add - Add socket to pool
 * @pool: Pool instance
 * @socket: Socket to add
 * Returns: New connection or NULL if pool is full
 * Thread-safe: Yes
 * Allocates I/O buffers and initializes connection metadata.
 */
extern Connection_T SocketPool_add (T pool, Socket_T socket);

/**
 * SocketPool_accept_batch - Accept multiple connections from server socket
 * @pool: Pool instance
 * @server: Server socket (listening, non-blocking)
 * @max_accepts: Max to accept (1-SOCKET_POOL_MAX_BATCH_ACCEPTS)
 * @max_accepts: Maximum number to accept (1 to SOCKET_POOL_MAX_BATCH_ACCEPTS)
 * @accepted_capacity: Size of accepted array provided by caller (must be >= max_accepts to avoid overflow)
 * @accepted: Output array for accepted Socket_T pointers (caller-allocated, filled up to count returned)
 *
 * Returns: Number of sockets accepted and added to pool (0 to min(max_accepts, accepted_capacity, available_slots))
 * Note: Validates accepted_capacity >= max_accepts; raises SocketPool_Failed if not.
 *
 * Returns: Number accepted (0 to max_accepts)
 * Raises: SocketPool_Failed on error
 * Thread-safe: Yes
 *
 * Efficient batch accept using accept4() where available.
 * Automatically adds accepted sockets to pool.
 *
 * CALLER RESPONSIBILITY - Array Size:
 * The @accepted array MUST be pre-allocated by the caller with at least
 * @max_accepts elements. No bounds checking is performed on the array -
 * providing an undersized array will cause buffer overflow.
 *
 * Example safe usage:
 *   Socket_T accepted[100];  // Array of at least max_accepts size
 *   int count = SocketPool_accept_batch(pool, server, 100, accepted);
 *
 * Example UNSAFE usage (DO NOT DO THIS):
 *   Socket_T accepted[10];   // Array too small!
 *   int count = SocketPool_accept_batch(pool, server, 100, accepted); // OVERFLOW!
 */
extern int SocketPool_accept_batch (T pool, Socket_T server, int max_accepts, size_t accepted_capacity,
                                    Socket_T *accepted);

/**
 * SocketPool_remove - Remove socket from pool
 * @pool: Pool instance
 * @socket: Socket to remove
 * Clears buffers but does not close socket
 * Thread-safe: Yes
 */
extern void SocketPool_remove (T pool, Socket_T socket);

/**
 * SocketPool_cleanup - Remove idle connections
 * @pool: Pool instance
 * @idle_timeout: Seconds inactive before removal (0 = remove all)
 * Thread-safe: Yes
 * O(n) scan of all slots; closes/removes idle ones.
 */
extern void SocketPool_cleanup (T pool, time_t idle_timeout);

/**
 * SocketPool_count - Get active connection count
 * @pool: Pool instance
 * Returns: Number of active connections
 * Thread-safe: Yes
 */
extern size_t SocketPool_count (T pool);

/**
 * SocketPool_resize - Resize pool capacity at runtime
 * @pool: Pool instance
 * @new_maxconns: New maximum
 * Raises: SocketPool_Failed on error
 * Thread-safe: Yes
 * Grows/shrinks pool; closes excess on shrink.
 */
extern void SocketPool_resize (T pool, size_t new_maxconns);

/**
 * SocketPool_prewarm - Pre-allocate buffers for % of free slots
 * @pool: Pool instance
 * @percentage: % of free slots (0-100)
 * Thread-safe: Yes
 * Reduces latency by pre-allocating buffers.
 */
extern void SocketPool_prewarm (T pool, int percentage);

/**
 * SocketPool_set_bufsize - Set buffer size for future connections
 * @pool: Pool instance
 * @new_bufsize: New size
 * Thread-safe: Yes
 * Existing connections keep old size.
 */
extern void SocketPool_set_bufsize (T pool, size_t new_bufsize);

/**
 * SocketPool_foreach - Iterate over active connections
 * @pool: Pool instance
 * @func: Callback (Connection_T, void*)
 * @arg: User data
 * Thread-safe: Yes - holds mutex
 * O(n) scan; callback must not modify pool.
 */
extern void SocketPool_foreach (T pool, void (*func) (Connection_T, void *),
                                void *arg);

/* Connection accessors */

/**
 * Connection_socket - Get connection's socket
 * @conn: Connection
 * Returns: Socket
 */
extern Socket_T Connection_socket (const Connection_T conn);

/**
 * Connection_inbuf - Get input buffer
 * @conn: Connection
 * Returns: Input buffer
 */
extern SocketBuf_T Connection_inbuf (const Connection_T conn);

/**
 * Connection_outbuf - Get output buffer
 * @conn: Connection
 * Returns: Output buffer
 */
extern SocketBuf_T Connection_outbuf (const Connection_T conn);

/**
 * Connection_data - Get user data
 * @conn: Connection
 * Returns: User data
 */
extern void *Connection_data (const Connection_T conn);

/**
 * Connection_setdata - Set user data
 * @conn: Connection (must not be NULL)
 * @data: Data pointer to store
 *
 * Thread-safe: NO - caller must synchronize access when multiple threads
 * may access the same connection simultaneously. Other Connection_*
 * accessor functions are read-only and thread-safe, but setdata modifies
 * state and requires external synchronization if called concurrently.
 */
extern void Connection_setdata (Connection_T conn, void *data);

/**
 * Connection_lastactivity - Get last activity time
 * @conn: Connection
 * Returns: time_t
 */
extern time_t Connection_lastactivity (const Connection_T conn);

/**
 * Connection_isactive - Check if active
 * @conn: Connection
 * Returns: Non-zero if active
 */
extern int Connection_isactive (const Connection_T conn);

/* ============================================================================
 * Reconnection Support
 * ============================================================================ */

/**
 * SocketPool_set_reconnect_policy - Set default reconnection policy for pool
 * @pool: Pool instance
 * @policy: Reconnection policy (NULL to disable auto-reconnect)
 *
 * Thread-safe: Yes
 *
 * Sets the default reconnection policy for connections in this pool.
 * Does not affect existing connections - use SocketPool_enable_reconnect()
 * for those.
 */
extern void SocketPool_set_reconnect_policy (T pool,
                                             const SocketReconnect_Policy_T *policy);

/**
 * SocketPool_enable_reconnect - Enable auto-reconnect for a connection
 * @pool: Pool instance
 * @conn: Connection to enable reconnection for
 * @host: Original hostname for reconnection
 * @port: Original port for reconnection
 *
 * Thread-safe: Yes
 *
 * Enables automatic reconnection for the specified connection using
 * the pool's reconnection policy. When the connection fails, it will
 * be automatically reconnected.
 *
 * NOTE: The original host/port must be provided since the socket may
 * have been created with just an IP address from DNS resolution.
 */
extern void SocketPool_enable_reconnect (T pool, Connection_T conn,
                                         const char *host, int port);

/**
 * SocketPool_disable_reconnect - Disable auto-reconnect for a connection
 * @pool: Pool instance
 * @conn: Connection to disable reconnection for
 *
 * Thread-safe: Yes
 *
 * Disables automatic reconnection for the specified connection.
 */
extern void SocketPool_disable_reconnect (T pool, Connection_T conn);

/**
 * SocketPool_process_reconnects - Process reconnection state machines
 * @pool: Pool instance
 *
 * Thread-safe: Yes
 *
 * Must be called periodically (e.g., in event loop) to process
 * reconnection timers and state transitions for all connections
 * with auto-reconnect enabled.
 */
extern void SocketPool_process_reconnects (T pool);

/**
 * SocketPool_reconnect_timeout_ms - Get time until next reconnection action
 * @pool: Pool instance
 *
 * Returns: Milliseconds until next timeout, or -1 if none pending
 * Thread-safe: Yes
 *
 * Use as timeout hint for poll/select when reconnections are active.
 */
extern int SocketPool_reconnect_timeout_ms (T pool);

/**
 * Connection_reconnect - Get reconnection context for connection
 * @conn: Connection
 *
 * Returns: SocketReconnect_T context, or NULL if reconnection not enabled
 * Thread-safe: Yes (but returned context is not thread-safe)
 */
extern SocketReconnect_T Connection_reconnect (const Connection_T conn);

/**
 * Connection_has_reconnect - Check if connection has auto-reconnect enabled
 * @conn: Connection
 *
 * Returns: Non-zero if auto-reconnect is enabled
 * Thread-safe: Yes
 */
extern int Connection_has_reconnect (const Connection_T conn);

/* ============================================================================
 * Rate Limiting
 * ============================================================================ */

/**
 * SocketPool_setconnrate - Set connection rate limit
 * @pool: Pool instance
 * @conns_per_sec: Maximum new connections per second (0 to disable)
 * @burst: Burst capacity (0 for default = conns_per_sec)
 *
 * Thread-safe: Yes
 *
 * Enables connection rate limiting using token bucket algorithm.
 * New connections via SocketPool_add() or SocketPool_accept_limited()
 * will be rejected if rate is exceeded.
 */
extern void SocketPool_setconnrate (T pool, int conns_per_sec, int burst);

/**
 * SocketPool_getconnrate - Get connection rate limit
 * @pool: Pool instance
 *
 * Returns: Connections per second limit (0 if disabled)
 * Thread-safe: Yes
 */
extern int SocketPool_getconnrate (T pool);

/**
 * SocketPool_setmaxperip - Set maximum connections per IP
 * @pool: Pool instance
 * @max_conns: Maximum connections per IP (0 = unlimited)
 *
 * Thread-safe: Yes
 *
 * Enables per-IP connection limiting to prevent single-source attacks.
 * New connections from IPs that exceed the limit will be rejected.
 */
extern void SocketPool_setmaxperip (T pool, int max_conns);

/**
 * SocketPool_getmaxperip - Get maximum connections per IP
 * @pool: Pool instance
 *
 * Returns: Maximum connections per IP (0 = unlimited)
 * Thread-safe: Yes
 */
extern int SocketPool_getmaxperip (T pool);

/**
 * SocketPool_accept_allowed - Check if accepting is allowed
 * @pool: Pool instance
 * @client_ip: Client IP address (NULL to skip IP check)
 *
 * Returns: 1 if allowed, 0 if rate limited or IP limit reached
 * Thread-safe: Yes
 *
 * Checks both connection rate and per-IP limits.
 * Does NOT consume rate limit tokens - use SocketPool_accept_limited() for that.
 */
extern int SocketPool_accept_allowed (T pool, const char *client_ip);

/**
 * SocketPool_accept_limited - Rate-limited accept
 * @pool: Pool instance
 * @server: Server socket to accept from
 *
 * Returns: Accepted socket, or NULL if draining/stopped, rate limited, or accept failed
 * Thread-safe: Yes - acquires pool mutex for rate checks
 *
 * Returns NULL immediately if pool is draining or stopped.
 * Consumes a rate token before attempting accept. If accept fails,
 * the token is NOT refunded (prevents DoS via rapid accept failures).
 *
 * If per-IP limiting enabled (SocketPool_setmaxperip > 0), automatically tracks
 * client IP after successful accept. If subsequent SocketPool_add fails,
 * caller MUST call SocketPool_release_ip(pool, Socket_getpeeraddr(client))
 * and Socket_free(&client) to avoid IP slot/FD leaks (DoS vector).
 *
 * Like Socket_accept() but with rate limiting and optional SYN protection.
 */
extern Socket_T SocketPool_accept_limited (T pool, Socket_T server);

/**
 * SocketPool_track_ip - Manually track IP for per-IP limiting
 * @pool: Pool instance
 * @ip: IP address to track
 *
 * Returns: 1 if under limit and tracked, 0 if limit reached
 * Thread-safe: Yes
 *
 * Use when manually managing connections not via SocketPool_accept_limited().
 * Call SocketPool_release_ip() when connection closes.
 */
extern int SocketPool_track_ip (T pool, const char *ip);

/**
 * SocketPool_release_ip - Release tracked IP when connection closes
 * @pool: Pool instance
 * @ip: IP address to release
 *
 * Thread-safe: Yes
 *
 * Decrements the connection count for the IP address.
 * Safe to call with NULL or untracked IP.
 */
extern void SocketPool_release_ip (T pool, const char *ip);

/**
 * SocketPool_ip_count - Get connection count for IP
 * @pool: Pool instance
 * @ip: IP address to query
 *
 * Returns: Number of tracked connections from this IP
 * Thread-safe: Yes
 */
extern int SocketPool_ip_count (T pool, const char *ip);

/* ============================================================================
 * SYN Flood Protection
 * ============================================================================ */

/**
 * SocketPool_set_syn_protection - Enable SYN flood protection for pool
 * @pool: Pool instance
 * @protect: SYN protection instance (NULL to disable)
 *
 * Thread-safe: Yes
 *
 * When enabled, SocketPool_accept_protected() will check with the
 * protection module and apply appropriate actions (throttle, challenge,
 * or block) before accepting connections.
 *
 * The protection module is NOT owned by the pool - caller must ensure
 * it remains valid and must free it after the pool is freed.
 */
extern void SocketPool_set_syn_protection (T pool, SocketSYNProtect_T protect);

/**
 * SocketPool_get_syn_protection - Get current SYN protection module
 * @pool: Pool instance
 *
 * Returns: Current SYN protection instance, or NULL if disabled
 * Thread-safe: Yes
 */
extern SocketSYNProtect_T SocketPool_get_syn_protection (T pool);

/**
 * SocketPool_accept_protected - Accept with full SYN flood protection
 * @pool: Pool instance
 * @server: Server socket (listening, non-blocking)
 * @action_out: Output - action taken (optional, may be NULL)
 *
 * Returns: New socket if allowed, NULL if blocked/would block
 * Raises: SocketPool_Failed on actual errors (not protection blocking)
 * Thread-safe: Yes
 *
 * Combines rate limiting, per-IP limits, and SYN protection into a
 * single accept operation. Actions taken depend on SYN protection result:
 *
 * - SYN_ACTION_ALLOW: Accept normally (fastest path)
 * - SYN_ACTION_THROTTLE: Accept after artificial delay (congestion control)
 * - SYN_ACTION_CHALLENGE: Set TCP_DEFER_ACCEPT on socket (require data)
 * - SYN_ACTION_BLOCK: Close connection immediately, return NULL
 *
 * If SYN protection is not enabled, behaves like SocketPool_accept_limited().
 *
 * Reports success/failure to SYN protection module automatically based on
 * whether connection completes or fails.
 */
extern Socket_T SocketPool_accept_protected (T pool, Socket_T server,
                                             SocketSYN_Action *action_out);

/* ============================================================================
 * Graceful Shutdown (Drain) API
 * ============================================================================
 *
 * Industry-standard graceful shutdown following patterns from nginx, HAProxy,
 * and Go http.Server. Provides clean state machine transitions, non-blocking
 * APIs for event loop integration, and timeout-guaranteed completion.
 *
 * State Machine:
 *                     drain(timeout)
 *     +---------+    ───────────────>    +----------+
 *     | RUNNING |                        | DRAINING |
 *     +---------+                        +----------+
 *          ^                                  │
 *          │                                  │ (count == 0 OR timeout)
 *          │            +----------+          │
 *          +────────────| STOPPED  |<─────────+
 *           (restart)   +----------+
 *
 * Typical usage:
 *   SocketPool_drain(pool, 30000);  // Start 30s drain
 *   while (SocketPool_drain_poll(pool) > 0) {
 *       // Continue event loop, connections closing naturally
 *       SocketPoll_wait(poll, &events, SocketPool_drain_remaining_ms(pool));
 *   }
 *   SocketPool_free(&pool);
 */

/**
 * Pool lifecycle states
 */
typedef enum
{
  POOL_STATE_RUNNING = 0,   /**< Normal operation - accepting connections */
  POOL_STATE_DRAINING,      /**< Rejecting new, waiting for existing to close */
  POOL_STATE_STOPPED        /**< Fully stopped - safe to free */
} SocketPool_State;

/**
 * Health status for load balancer integration
 */
typedef enum
{
  POOL_HEALTH_HEALTHY = 0,  /**< Accept traffic normally */
  POOL_HEALTH_DRAINING,     /**< Finishing existing connections, reject new */
  POOL_HEALTH_STOPPED       /**< Not accepting any traffic */
} SocketPool_Health;

/**
 * SocketPool_DrainCallback - Callback invoked when drain completes
 * @pool: Pool instance that completed draining
 * @timed_out: 1 if drain timed out and forced, 0 if graceful
 * @data: User data from SocketPool_set_drain_callback
 *
 * Called exactly once when pool transitions to STOPPED state.
 * Safe to call SocketPool_free() from within this callback.
 * Thread-safe: Invoked from the thread calling drain_poll/drain_wait.
 */
typedef void (*SocketPool_DrainCallback) (T pool, int timed_out, void *data);

/**
 * SocketPool_state - Get current pool lifecycle state
 * @pool: Pool instance
 *
 * Returns: Current SocketPool_State
 * Thread-safe: Yes - atomic read
 * Complexity: O(1)
 */
extern SocketPool_State SocketPool_state (T pool);

/**
 * SocketPool_health - Get pool health status for load balancers
 * @pool: Pool instance
 *
 * Returns: Current SocketPool_Health
 * Thread-safe: Yes - atomic read
 * Complexity: O(1)
 *
 * Maps state to health:
 * - RUNNING -> HEALTHY
 * - DRAINING -> DRAINING
 * - STOPPED -> STOPPED
 */
extern SocketPool_Health SocketPool_health (T pool);

/**
 * SocketPool_is_draining - Check if pool is currently draining
 * @pool: Pool instance
 *
 * Returns: Non-zero if state is DRAINING
 * Thread-safe: Yes - atomic read
 * Complexity: O(1)
 */
extern int SocketPool_is_draining (T pool);

/**
 * SocketPool_is_stopped - Check if pool is fully stopped
 * @pool: Pool instance
 *
 * Returns: Non-zero if state is STOPPED
 * Thread-safe: Yes - atomic read
 * Complexity: O(1)
 */
extern int SocketPool_is_stopped (T pool);

/**
 * SocketPool_drain - Initiate graceful shutdown
 * @pool: Pool instance
 * @timeout_ms: Maximum time to wait for connections to close (milliseconds)
 *              Use 0 for immediate force-close, -1 for infinite wait
 *
 * Thread-safe: Yes
 * Complexity: O(1)
 *
 * Transitions pool from RUNNING to DRAINING state:
 * 1. Rejects all new connection attempts (accept_* return NULL)
 * 2. Allows existing connections to continue until closed
 * 3. After timeout_ms, remaining connections are force-closed
 *
 * Call drain_poll() or drain_wait() to complete the shutdown.
 * Multiple calls are idempotent - only first call has effect.
 *
 * Emits: SOCKET_EVENT_POOL_DRAINING event
 * Logs: "Pool drain initiated" at INFO level
 */
extern void SocketPool_drain (T pool, int timeout_ms);

/**
 * SocketPool_drain_poll - Poll drain progress (non-blocking)
 * @pool: Pool instance
 *
 * Returns:
 *   >0 - Number of connections still active (keep polling)
 *    0 - Drain complete, pool is STOPPED (graceful)
 *   -1 - Drain timed out, connections force-closed, pool is STOPPED
 *
 * Thread-safe: Yes
 * Complexity: O(1) normally, O(n) on timeout (force close)
 *
 * Call periodically in event loop to:
 * - Check if all connections have closed
 * - Trigger force-close when timeout expires
 * - Invoke drain callback on completion
 *
 * If pool is not draining (RUNNING or already STOPPED), returns count or 0.
 */
extern int SocketPool_drain_poll (T pool);

/**
 * SocketPool_drain_remaining_ms - Get time until forced shutdown
 * @pool: Pool instance
 *
 * Returns: Milliseconds until timeout, 0 if already expired, -1 if not draining
 * Thread-safe: Yes - atomic read
 * Complexity: O(1)
 *
 * Use as timeout hint for poll/select during drain.
 */
extern int64_t SocketPool_drain_remaining_ms (T pool);

/**
 * SocketPool_drain_force - Force immediate shutdown
 * @pool: Pool instance
 *
 * Thread-safe: Yes
 * Complexity: O(n) where n = active connections
 *
 * Immediately closes all connections and transitions to STOPPED.
 * Can be called at any time, regardless of current state.
 * Invokes drain callback with timed_out=1.
 *
 * Logs: "Pool drain forced" at WARN level
 */
extern void SocketPool_drain_force (T pool);

/**
 * SocketPool_drain_wait - Blocking drain with internal poll loop
 * @pool: Pool instance
 * @timeout_ms: Maximum wait time (milliseconds), -1 for infinite
 *
 * Returns: 0 if graceful drain completed, -1 if timed out (forced)
 * Thread-safe: Yes
 *
 * Convenience function that:
 * 1. Calls SocketPool_drain(timeout_ms)
 * 2. Polls with exponential backoff (1ms -> 100ms cap)
 * 3. Returns when pool reaches STOPPED state
 *
 * For event-driven applications, prefer drain() + drain_poll() pattern.
 */
extern int SocketPool_drain_wait (T pool, int timeout_ms);

/**
 * SocketPool_set_drain_callback - Register drain completion callback
 * @pool: Pool instance
 * @cb: Callback function (NULL to clear)
 * @data: User data passed to callback
 *
 * Thread-safe: Yes
 *
 * Callback is invoked exactly once when drain completes (transitions to STOPPED).
 * Safe to call SocketPool_free() from callback.
 */
extern void SocketPool_set_drain_callback (T pool, SocketPool_DrainCallback cb,
                                           void *data);

/* ============================================================================
 * Idle Connection Cleanup
 * ============================================================================ */

/**
 * SocketPool_set_idle_timeout - Set idle connection timeout
 * @pool: Pool instance
 * @timeout_sec: Idle timeout in seconds (0 to disable automatic cleanup)
 *
 * Thread-safe: Yes
 *
 * When enabled, connections idle longer than timeout_sec will be removed
 * during periodic cleanup. Use SocketPool_idle_cleanup_due_ms() to get
 * the time until next cleanup for poll timeout integration.
 */
extern void SocketPool_set_idle_timeout (T pool, time_t timeout_sec);

/**
 * SocketPool_get_idle_timeout - Get idle connection timeout
 * @pool: Pool instance
 *
 * Returns: Current idle timeout in seconds (0 = disabled)
 * Thread-safe: Yes
 */
extern time_t SocketPool_get_idle_timeout (T pool);

/**
 * SocketPool_idle_cleanup_due_ms - Get time until next idle cleanup
 * @pool: Pool instance
 *
 * Returns: Milliseconds until next cleanup, -1 if disabled
 * Thread-safe: Yes
 *
 * Use as timeout hint for poll/select to ensure timely cleanup.
 * Returns -1 if idle timeout is disabled (timeout_sec == 0).
 */
extern int64_t SocketPool_idle_cleanup_due_ms (T pool);

/**
 * SocketPool_run_idle_cleanup - Run idle connection cleanup if due
 * @pool: Pool instance
 *
 * Returns: Number of connections cleaned up
 * Thread-safe: Yes
 *
 * Call periodically (e.g., after each poll iteration) to remove
 * idle connections. Only performs cleanup if cleanup interval has passed.
 * Does nothing if idle timeout is disabled.
 */
extern size_t SocketPool_run_idle_cleanup (T pool);

/* ============================================================================
 * Connection Health Check
 * ============================================================================ */

/**
 * Connection health status
 */
typedef enum
{
  POOL_CONN_HEALTHY = 0,    /**< Connection is healthy and usable */
  POOL_CONN_DISCONNECTED,   /**< Connection has been disconnected */
  POOL_CONN_ERROR,          /**< Connection has a socket error */
  POOL_CONN_STALE           /**< Connection has exceeded max age */
} SocketPool_ConnHealth;

/**
 * SocketPool_check_connection - Check health of a connection
 * @pool: Pool instance
 * @conn: Connection to check
 *
 * Returns: Health status of the connection
 * Thread-safe: Yes
 *
 * Checks:
 * - Socket is still connected (SO_ERROR check)
 * - Socket is not in error state
 * - Connection has not exceeded idle timeout
 */
extern SocketPool_ConnHealth SocketPool_check_connection (T pool,
                                                          Connection_T conn);

/* ============================================================================
 * Connection Validation Callback
 * ============================================================================ */

/**
 * SocketPool_ValidationCallback - Callback to validate connection before reuse
 * (Type defined earlier in header)
 * @conn: Connection being validated
 * @data: User data from SocketPool_set_validation_callback
 *
 * Returns: Non-zero if connection is valid, 0 if connection should be removed
 *
 * Called during SocketPool_get() before returning a connection.
 * If callback returns 0, connection is removed from pool and NULL is returned.
 *
 * CRITICAL THREAD SAFETY REQUIREMENTS:
 *
 * The callback is invoked with the pool mutex HELD. The callback:
 *
 * - MUST NOT call any SocketPool_* functions (DEADLOCK will occur)
 * - MUST NOT call functions that may acquire the pool mutex
 * - MUST NOT block for extended periods (degrades pool performance)
 * - SHOULD complete execution in < 1ms
 * - MAY read connection data via Connection_* accessors (thread-safe reads)
 * - MAY perform quick socket health checks (e.g., poll with 0 timeout)
 *
 * Violating these requirements will cause deadlock or severe performance
 * degradation. For complex validation logic, consider:
 * - Using a separate validation thread with async notification
 * - Performing validation after SocketPool_get() returns
 * - Using SocketPool_check_connection() instead of custom callback
 */

/**
 * SocketPool_set_validation_callback - Set connection validation callback
 * @pool: Pool instance
 * @cb: Validation callback (NULL to disable)
 * @data: User data passed to callback
 *
 * Thread-safe: Yes
 *
 * When set, callback is invoked during SocketPool_get() to validate
 * connections before reuse. Use for application-level health checks.
 */
extern void SocketPool_set_validation_callback (T pool,
                                                SocketPool_ValidationCallback cb,
                                                void *data);

/* ============================================================================
 * Pool Resize Callback
 * ============================================================================ */

/**
 * SocketPool_ResizeCallback - Callback invoked after pool resize
 * (Type defined earlier in header)
 * @pool: Pool instance
 * @old_size: Previous maximum connections
 * @new_size: New maximum connections
 * @data: User data from SocketPool_set_resize_callback
 *
 * Thread-safe: Callback is invoked outside pool mutex.
 */

/**
 * SocketPool_set_resize_callback - Register pool resize notification callback
 * @pool: Pool instance
 * @cb: Callback function (NULL to clear)
 * @data: User data passed to callback
 *
 * Thread-safe: Yes
 *
 * Callback is invoked after successful pool resize operations.
 */
extern void SocketPool_set_resize_callback (T pool, SocketPool_ResizeCallback cb,
                                            void *data);

/* ============================================================================
 * Pool Statistics
 * ============================================================================ */

/**
 * SocketPool_Stats - Pool statistics snapshot
 *
 * All counters are cumulative since pool creation or last reset.
 * Rates are calculated over the configured statistics window.
 */
typedef struct SocketPool_Stats
{
  /* Cumulative counters */
  uint64_t total_added;             /**< Total connections added to pool */
  uint64_t total_removed;           /**< Total connections removed from pool */
  uint64_t total_reused;            /**< Total connections reused (returned via get) */
  uint64_t total_health_checks;     /**< Total health checks performed */
  uint64_t total_health_failures;   /**< Total health check failures */
  uint64_t total_validation_failures; /**< Total validation callback failures */
  uint64_t total_idle_cleanups;     /**< Connections removed due to idle timeout */
  
  /* Current state */
  size_t current_active;            /**< Current active connection count */
  size_t current_idle;              /**< Current idle connection count (active but not in use) */
  size_t max_connections;           /**< Maximum connection capacity */
  
  /* Calculated metrics */
  double reuse_rate;                /**< Reuse rate: reused / (added + reused) */
  double avg_connection_age_sec;    /**< Average age of active connections (seconds) */
  double churn_rate_per_sec;        /**< Churn rate: (added + removed) / window_sec */
} SocketPool_Stats;

/**
 * SocketPool_get_stats - Get pool statistics snapshot
 * @pool: Pool instance
 * @stats: Output statistics structure
 *
 * Thread-safe: Yes
 *
 * Fills stats with current pool statistics. Calculated metrics
 * (reuse_rate, avg_connection_age, churn_rate) are computed at call time.
 */
extern void SocketPool_get_stats (T pool, SocketPool_Stats *stats);

/**
 * SocketPool_reset_stats - Reset pool statistics counters
 * @pool: Pool instance
 *
 * Thread-safe: Yes
 *
 * Resets all cumulative counters to zero and restarts the statistics window.
 * Current state values (active, idle, max) are not affected.
 */
extern void SocketPool_reset_stats (T pool);

/**
 * Connection_created_at - Get connection creation timestamp
 * @conn: Connection instance
 *
 * Returns: Creation timestamp (time_t)
 * Thread-safe: Yes - read-only access
 */
extern time_t Connection_created_at (const Connection_T conn);

#undef T
#endif
