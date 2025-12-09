#ifndef SOCKETPOOL_INCLUDED
#define SOCKETPOOL_INCLUDED

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketSYNProtect.h"
#include "core/SocketUtil.h" /* For socket_error_buf in macros */
#include "dns/SocketDNS.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketReconnect.h"
#include <stddef.h>
#include <time.h>

/**
 * @defgroup connection_mgmt Connection Management Modules
 * @brief Connection lifecycle management with pooling and rate limiting.
 *
 * The Connection Management group handles connection lifecycle, pooling,
 * and resilience patterns. Key components include:
 * - SocketPool (pooling): Connection pooling with automatic lifecycle
 * management
 * - SocketReconnect (reconnection): Auto-reconnection with circuit breaker
 * - SocketRateLimit (rate-limit): Token bucket rate limiting
 * - SocketSYNProtect (syn-flood): SYN flood protection
 *
 * @see core_io for socket primitives.
 * @see event_system for event notification.
 * @see SocketPool_T for connection pooling.
 * @see SocketReconnect_T for auto-reconnection.
 * @{
 */

/**
 * @file SocketPool.h
 * @ingroup connection_mgmt
 * @brief Connection pooling with automatic lifecycle management.
 *
 * Manages a pool of socket connections with associated buffers and
 * metadata. Provides O(1) connection lookup using hash tables and
 * automatic cleanup of idle connections.
 *
 * Features:
 * - Pre-allocated connection slots for predictable memory usage
 * - Hash table for O(1) socket lookup
 * - Automatic idle connection cleanup
 * - Per-connection input/output buffers
 * - User data storage per connection
 * - Dynamic resize and pre-warming for performance
 *
 * The Connection_T type is opaque - use accessor functions to
 * access connection properties.
 *
 * Thread Safety: All operations are thread-safe via internal mutex.
 * The pool can be used from multiple threads simultaneously.
 *
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - POSIX threads (pthread) for mutex synchronization
 * - NOT portable to Windows without pthreads adaptation
 *
 * @see SocketPool_new() for pool creation.
 * @see SocketPool_add() for connection registration.
 * @see Connection_T for connection accessors.
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
 * @brief SocketPool_ConnectCallback - Callback for async connection completion
 * @ingroup connection_mgmt
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
typedef void (*SocketPool_ConnectCallback) (Connection_T conn, int error,
                                            void *data);

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @brief SocketPool_Failed - Pool operation failure
 * @ingroup connection_mgmt
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
 * @brief Create a new connection pool.
 * @ingroup connection_mgmt
 * @param arena Arena for memory allocation.
 * @param maxconns Maximum number of connections.
 * @param bufsize Size of I/O buffers per connection.
 * @return New pool instance (never returns NULL).
 * @throws SocketPool_Failed on any allocation or initialization failure.
 * @threadsafe Yes - returns new instance.
 * @note Automatically pre-warms SOCKET_POOL_DEFAULT_PREWARM_PCT slots.
 * @see SocketPool_free() for cleanup.
 * @see SocketPool_add() for adding connections.
 */
extern T SocketPool_new (Arena_T arena, size_t maxconns, size_t bufsize);

/**
 * @brief SocketPool_prepare_connection - Prepare async connection using DNS
 * @ingroup connection_mgmt
 * @pool: Pool instance (used for configuration and cleanup)
 * @dns: DNS resolver instance
 * @host: Remote hostname or IP
 * @port: Remote port (1-65535)
 * @out_socket: Output - new Socket_T instance
 * @out_req: Output - SocketDNS_Request_T for monitoring
 * Returns: 0 on success, -1 on error (out_socket/out_req undefined)
 * Raises: SocketPool_Failed on error
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 * Creates a new Socket_T, configures pool defaults (non-blocking, reuseaddr,
 * etc.), starts async DNS resolution + connect preparation via
 * Socket_connect_async. User must monitor out_req with SocketDNS
 * (check/pollfd/getresult), then call Socket_connect_with_addrinfo(out_socket,
 * res) on completion, then SocketPool_add(pool, out_socket) to add to pool. On
 * error/cancel, Socket_free(&out_socket) and handle. Integrates SocketDNS for
 * non-blocking hostname resolution in pooled connections.
 */
extern int SocketPool_prepare_connection (T pool, SocketDNS_T dns,
                                          const char *host, int port,
                                          Socket_T *out_socket,
                                          Request_T *out_req);

/**
 * @brief Free a connection pool.
 * @ingroup connection_mgmt
 * @param pool Pointer to pool (will be set to NULL).
 * @threadsafe Yes.
 * @note Does not close sockets - caller must do that.
 * @see SocketPool_new() for creation.
 * @see SocketPool_remove() for removing connections.
 */
extern void SocketPool_free (T *pool);

/**
 * @brief SocketPool_connect_async - Create async connection to remote host
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @host: Remote hostname or IP address
 * @port: Remote port number
 * @callback: Completion callback (see SocketPool_ConnectCallback for thread
 * safety)
 * @data: User data passed to callback
 *
 * Returns: SocketDNS_Request_T for monitoring completion
 * Raises: SocketPool_Failed on invalid params, allocation error, or limit
 * reached Thread-safe: Yes
 *
 * Starts async DNS resolution + connect + pool add. On completion:
 * - Success: callback(conn, 0, data) with Connection_T added to pool
 * - Failure: callback(NULL, error_code, data)
 *
 * IMPORTANT: The callback is invoked from a DNS worker thread, not the calling
 * thread. See SocketPool_ConnectCallback documentation for thread safety
 * requirements.
 *
 * Security: Limited to SOCKET_POOL_MAX_ASYNC_PENDING concurrent operations
 * to prevent resource exhaustion attacks.
 *
 * Integrates with SocketDNS for non-blocking resolution.
 * SocketPool_add is called internally on successful connect.
 * Caller owns no resources; pool manages connection lifecycle.
 */
extern Request_T
SocketPool_connect_async (T pool, const char *host, int port,
                          SocketPool_ConnectCallback callback, void *data);

/**
 * @brief Look up connection by socket.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param socket Socket to find.
 * @return Connection or NULL if not found.
 * @threadsafe Yes.
 * @note O(1) hash lookup. Updates last_activity timestamp.
 * @see SocketPool_add() for adding connections.
 * @see Connection_T for connection accessors.
 */
extern Connection_T SocketPool_get (T pool, Socket_T socket);

/**
 * @brief Add socket to pool.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param socket Socket to add.
 * @return New connection or NULL if pool is full.
 * @threadsafe Yes.
 * @note Allocates I/O buffers and initializes connection metadata.
 * @see SocketPool_get() for looking up connections.
 * @see SocketPool_remove() for removing connections.
 */
extern Connection_T SocketPool_add (T pool, Socket_T socket);

/**
 * @brief SocketPool_accept_batch - Accept multiple connections from server socket
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @server: Server socket (listening, non-blocking)
 * @max_accepts: Max to accept (1-SOCKET_POOL_MAX_BATCH_ACCEPTS)
 * @max_accepts: Maximum number to accept (1 to SOCKET_POOL_MAX_BATCH_ACCEPTS)
 * @accepted_capacity: Size of accepted array provided by caller (must be >=
 * max_accepts to avoid overflow)
 * @accepted: Output array for accepted Socket_T pointers (caller-allocated,
 * filled up to count returned)
 *
 * Returns: Number of sockets accepted and added to pool (0 to min(max_accepts,
 * accepted_capacity, available_slots)) Note: Validates accepted_capacity >=
 * max_accepts; raises SocketPool_Failed if not.
 *
 * Returns: Number accepted (0 to max_accepts)
 * Raises: SocketPool_Failed on error
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
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
 *   int count = SocketPool_accept_batch(pool, server, 100, accepted); //
 * OVERFLOW!
 */
extern int SocketPool_accept_batch (T pool, Socket_T server, int max_accepts,
                                    size_t accepted_capacity,
                                    Socket_T *accepted);

/**
 * @brief Remove socket from pool.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param socket Socket to remove.
 * @threadsafe Yes.
 * @note Clears buffers but does not close socket.
 * @see SocketPool_add() for adding connections.
 * @see SocketPool_cleanup() for bulk removal.
 */
extern void SocketPool_remove (T pool, Socket_T socket);

/**
 * @brief Remove idle connections.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @param idle_timeout Seconds inactive before removal (0 = remove all).
 * @threadsafe Yes.
 * @note O(n) scan of all slots; closes/removes idle ones.
 * @see SocketPool_count() for counting connections.
 * @see SocketPool_set_idle_timeout() for configuring timeout.
 */
extern void SocketPool_cleanup (T pool, time_t idle_timeout);

/**
 * @brief Get active connection count.
 * @ingroup connection_mgmt
 * @param pool Pool instance.
 * @return Number of active connections.
 * @threadsafe Yes.
 * @see SocketPool_resize() for changing capacity.
 * @see SocketPool_cleanup() for removing idle connections.
 */
extern size_t SocketPool_count (T pool);

/**
 * @brief SocketPool_resize - Resize pool capacity at runtime
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @new_maxconns: New maximum
 * Raises: SocketPool_Failed on error
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 * Grows/shrinks pool; closes excess on shrink.
 */
extern void SocketPool_resize (T pool, size_t new_maxconns);

/**
 * @brief SocketPool_prewarm - Pre-allocate buffers for % of free slots
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @percentage: % of free slots (0-100)
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 * Reduces latency by pre-allocating buffers.
 */
extern void SocketPool_prewarm (T pool, int percentage);

/**
 * @brief SocketPool_set_bufsize - Set buffer size for future connections
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @new_bufsize: New size
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 * Existing connections keep old size.
 */
extern void SocketPool_set_bufsize (T pool, size_t new_bufsize);

/**
 * @brief SocketPool_foreach - Iterate over active connections
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @func: Callback (Connection_T, void*)
 * @arg: User data
 * @note Thread-safe: Yes - holds mutex
 * @ingroup connection_mgmt
 * O(n) scan; callback must not modify pool.
 */
extern void SocketPool_foreach (T pool, void (*func) (Connection_T, void *),
                                void *arg);

/* Connection accessors */

/**
 * @brief Connection_socket - Get connection's socket
 * @ingroup connection_mgmt
 * @conn: Connection
 * Returns: Socket
 */
extern Socket_T Connection_socket (const Connection_T conn);

/**
 * @brief Connection_inbuf - Get input buffer
 * @ingroup connection_mgmt
 * @conn: Connection
 * Returns: Input buffer
 */
extern SocketBuf_T Connection_inbuf (const Connection_T conn);

/**
 * @brief Connection_outbuf - Get output buffer
 * @ingroup connection_mgmt
 * @conn: Connection
 * Returns: Output buffer
 */
extern SocketBuf_T Connection_outbuf (const Connection_T conn);

/**
 * @brief Connection_data - Get user data
 * @ingroup connection_mgmt
 * @conn: Connection
 * Returns: User data
 */
extern void *Connection_data (const Connection_T conn);

/**
 * @brief Connection_setdata - Set user data
 * @ingroup connection_mgmt
 * @conn: Connection (must not be NULL)
 * @data: Data pointer to store
 *
 * @note Thread-safe: NO - caller must synchronize access when multiple threads
 * @ingroup connection_mgmt
 * may access the same connection simultaneously. Other Connection_*
 * accessor functions are read-only and thread-safe, but setdata modifies
 * state and requires external synchronization if called concurrently.
 */
extern void Connection_setdata (Connection_T conn, void *data);

/**
 * @brief Connection_lastactivity - Get last activity time
 * @ingroup connection_mgmt
 * @conn: Connection
 * Returns: time_t
 */
extern time_t Connection_lastactivity (const Connection_T conn);

/**
 * @brief Connection_isactive - Check if active
 * @ingroup connection_mgmt
 * @conn: Connection
 * Returns: Non-zero if active
 */
extern int Connection_isactive (const Connection_T conn);

/* ============================================================================
 * Reconnection Support
 * ============================================================================
 */

/**
 * @brief SocketPool_set_reconnect_policy - Set default reconnection policy for pool
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @policy: Reconnection policy (NULL to disable auto-reconnect)
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * Sets the default reconnection policy for connections in this pool.
 * Does not affect existing connections - use SocketPool_enable_reconnect()
 * for those.
 */
extern void
SocketPool_set_reconnect_policy (T pool,
                                 const SocketReconnect_Policy_T *policy);

/**
 * @brief SocketPool_enable_reconnect - Enable auto-reconnect for a connection
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @conn: Connection to enable reconnection for
 * @host: Original hostname for reconnection
 * @port: Original port for reconnection
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
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
 * @brief SocketPool_disable_reconnect - Disable auto-reconnect for a connection
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @conn: Connection to disable reconnection for
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * Disables automatic reconnection for the specified connection.
 */
extern void SocketPool_disable_reconnect (T pool, Connection_T conn);

/**
 * @brief SocketPool_process_reconnects - Process reconnection state machines
 * @ingroup connection_mgmt
 * @pool: Pool instance
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * Must be called periodically (e.g., in event loop) to process
 * reconnection timers and state transitions for all connections
 * with auto-reconnect enabled.
 */
extern void SocketPool_process_reconnects (T pool);

/**
 * @brief SocketPool_reconnect_timeout_ms - Get time until next reconnection action
 * @ingroup connection_mgmt
 * @pool: Pool instance
 *
 * Returns: Milliseconds until next timeout, or -1 if none pending
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * Use as timeout hint for poll/select when reconnections are active.
 */
extern int SocketPool_reconnect_timeout_ms (T pool);

/**
 * @brief Connection_reconnect - Get reconnection context for connection
 * @ingroup connection_mgmt
 * @conn: Connection
 *
 * Returns: SocketReconnect_T context, or NULL if reconnection not enabled
 * @note Thread-safe: Yes (but returned context is not thread-safe)
 * @ingroup connection_mgmt
 */
extern SocketReconnect_T Connection_reconnect (const Connection_T conn);

/**
 * @brief Connection_has_reconnect - Check if connection has auto-reconnect enabled
 * @ingroup connection_mgmt
 * @conn: Connection
 *
 * Returns: Non-zero if auto-reconnect is enabled
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 */
extern int Connection_has_reconnect (const Connection_T conn);

/* ============================================================================
 * Rate Limiting
 * ============================================================================
 */

/**
 * @brief SocketPool_setconnrate - Set connection rate limit
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @conns_per_sec: Maximum new connections per second (0 to disable)
 * @burst: Burst capacity (0 for default = conns_per_sec)
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * Enables connection rate limiting using token bucket algorithm.
 * New connections via SocketPool_add() or SocketPool_accept_limited()
 * will be rejected if rate is exceeded.
 */
extern void SocketPool_setconnrate (T pool, int conns_per_sec, int burst);

/**
 * @brief SocketPool_getconnrate - Get connection rate limit
 * @ingroup connection_mgmt
 * @pool: Pool instance
 *
 * Returns: Connections per second limit (0 if disabled)
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 */
extern int SocketPool_getconnrate (T pool);

/**
 * @brief SocketPool_setmaxperip - Set maximum connections per IP
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @max_conns: Maximum connections per IP (0 = unlimited)
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * Enables per-IP connection limiting to prevent single-source attacks.
 * New connections from IPs that exceed the limit will be rejected.
 */
extern void SocketPool_setmaxperip (T pool, int max_conns);

/**
 * @brief SocketPool_getmaxperip - Get maximum connections per IP
 * @ingroup connection_mgmt
 * @pool: Pool instance
 *
 * Returns: Maximum connections per IP (0 = unlimited)
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 */
extern int SocketPool_getmaxperip (T pool);

/**
 * @brief SocketPool_accept_allowed - Check if accepting is allowed
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @client_ip: Client IP address (NULL to skip IP check)
 *
 * Returns: 1 if allowed, 0 if rate limited or IP limit reached
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * Checks both connection rate and per-IP limits.
 * Does NOT consume rate limit tokens - use SocketPool_accept_limited() for
 * that.
 */
extern int SocketPool_accept_allowed (T pool, const char *client_ip);

/**
 * @brief SocketPool_accept_limited - Rate-limited accept
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @server: Server socket to accept from
 *
 * Returns: Accepted socket, or NULL if draining/stopped, rate limited, or
 * accept failed Thread-safe: Yes - acquires pool mutex for rate checks
 *
 * Returns NULL immediately if pool is draining or stopped.
 * Consumes a rate token before attempting accept. If accept fails,
 * the token is NOT refunded (prevents DoS via rapid accept failures).
 *
 * If per-IP limiting enabled (SocketPool_setmaxperip > 0), automatically
 * tracks client IP after successful accept. If subsequent SocketPool_add
 * fails, caller MUST call SocketPool_release_ip(pool,
 * Socket_getpeeraddr(client)) and Socket_free(&client) to avoid IP slot/FD
 * leaks (DoS vector).
 *
 * Like Socket_accept() but with rate limiting and optional SYN protection.
 */
extern Socket_T SocketPool_accept_limited (T pool, Socket_T server);

/**
 * @brief SocketPool_track_ip - Manually track IP for per-IP limiting
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @ip: IP address to track
 *
 * Returns: 1 if under limit and tracked, 0 if limit reached
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * Use when manually managing connections not via SocketPool_accept_limited().
 * Call SocketPool_release_ip() when connection closes.
 */
extern int SocketPool_track_ip (T pool, const char *ip);

/**
 * @brief SocketPool_release_ip - Release tracked IP when connection closes
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @ip: IP address to release
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * Decrements the connection count for the IP address.
 * Safe to call with NULL or untracked IP.
 */
extern void SocketPool_release_ip (T pool, const char *ip);

/**
 * @brief SocketPool_ip_count - Get connection count for IP
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @ip: IP address to query
 *
 * Returns: Number of tracked connections from this IP
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 */
extern int SocketPool_ip_count (T pool, const char *ip);

/* ============================================================================
 * SYN Flood Protection
 * ============================================================================
 */

/**
 * @brief SocketPool_set_syn_protection - Enable SYN flood protection for pool
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @protect: SYN protection instance (NULL to disable)
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
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
 * @brief SocketPool_get_syn_protection - Get current SYN protection module
 * @ingroup connection_mgmt
 * @pool: Pool instance
 *
 * Returns: Current SYN protection instance, or NULL if disabled
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 */
extern SocketSYNProtect_T SocketPool_get_syn_protection (T pool);

/**
 * @brief SocketPool_accept_protected - Accept with full SYN flood protection
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @server: Server socket (listening, non-blocking)
 * @action_out: Output - action taken (optional, may be NULL)
 *
 * Returns: New socket if allowed, NULL if blocked/would block
 * Raises: SocketPool_Failed on actual errors (not protection blocking)
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
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
  POOL_STATE_RUNNING = 0, /**< Normal operation - accepting connections */
  POOL_STATE_DRAINING,    /**< Rejecting new, waiting for existing to close */
  POOL_STATE_STOPPED      /**< Fully stopped - safe to free */
} SocketPool_State;

/**
 * Health status for load balancer integration
 */
typedef enum
{
  POOL_HEALTH_HEALTHY = 0, /**< Accept traffic normally */
  POOL_HEALTH_DRAINING,    /**< Finishing existing connections, reject new */
  POOL_HEALTH_STOPPED      /**< Not accepting any traffic */
} SocketPool_Health;

/**
 * @brief SocketPool_DrainCallback - Callback invoked when drain completes
 * @ingroup connection_mgmt
 * @pool: Pool instance that completed draining
 * @timed_out: 1 if drain timed out and forced, 0 if graceful
 * @data: User data from SocketPool_set_drain_callback
 *
 * Called exactly once when pool transitions to STOPPED state.
 * Safe to call SocketPool_free() from within this callback.
 * @note Thread-safe: Invoked from the thread calling drain_poll/drain_wait.
 * @ingroup connection_mgmt
 */
typedef void (*SocketPool_DrainCallback) (T pool, int timed_out, void *data);

/**
 * @brief SocketPool_state - Get current pool lifecycle state
 * @ingroup connection_mgmt
 * @pool: Pool instance
 *
 * Returns: Current SocketPool_State
 * @note Thread-safe: Yes - atomic read
 * @ingroup connection_mgmt
 * Complexity: O(1)
 */
extern SocketPool_State SocketPool_state (T pool);

/**
 * @brief SocketPool_health - Get pool health status for load balancers
 * @ingroup connection_mgmt
 * @pool: Pool instance
 *
 * Returns: Current SocketPool_Health
 * @note Thread-safe: Yes - atomic read
 * @ingroup connection_mgmt
 * Complexity: O(1)
 *
 * Maps state to health:
 * - RUNNING -> HEALTHY
 * - DRAINING -> DRAINING
 * - STOPPED -> STOPPED
 */
extern SocketPool_Health SocketPool_health (T pool);

/**
 * @brief SocketPool_is_draining - Check if pool is currently draining
 * @ingroup connection_mgmt
 * @pool: Pool instance
 *
 * Returns: Non-zero if state is DRAINING
 * @note Thread-safe: Yes - atomic read
 * @ingroup connection_mgmt
 * Complexity: O(1)
 */
extern int SocketPool_is_draining (T pool);

/**
 * @brief SocketPool_is_stopped - Check if pool is fully stopped
 * @ingroup connection_mgmt
 * @pool: Pool instance
 *
 * Returns: Non-zero if state is STOPPED
 * @note Thread-safe: Yes - atomic read
 * @ingroup connection_mgmt
 * Complexity: O(1)
 */
extern int SocketPool_is_stopped (T pool);

/**
 * @brief SocketPool_drain - Initiate graceful shutdown
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @timeout_ms: Maximum time to wait for connections to close (milliseconds)
 *              Use 0 for immediate force-close, -1 for infinite wait
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
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
 * @brief SocketPool_drain_poll - Poll drain progress (non-blocking)
 * @ingroup connection_mgmt
 * @pool: Pool instance
 *
 * Returns:
 *   >0 - Number of connections still active (keep polling)
 *    0 - Drain complete, pool is STOPPED (graceful)
 *   -1 - Drain timed out, connections force-closed, pool is STOPPED
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
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
 * @brief SocketPool_drain_remaining_ms - Get time until forced shutdown
 * @ingroup connection_mgmt
 * @pool: Pool instance
 *
 * Returns: Milliseconds until timeout, 0 if already expired, -1 if not
 * draining Thread-safe: Yes - atomic read Complexity: O(1)
 *
 * Use as timeout hint for poll/select during drain.
 */
extern int64_t SocketPool_drain_remaining_ms (T pool);

/**
 * @brief SocketPool_drain_force - Force immediate shutdown
 * @ingroup connection_mgmt
 * @pool: Pool instance
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
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
 * @brief SocketPool_drain_wait - Blocking drain with internal poll loop
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @timeout_ms: Maximum wait time (milliseconds), -1 for infinite
 *
 * Returns: 0 if graceful drain completed, -1 if timed out (forced)
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
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
 * @brief SocketPool_set_drain_callback - Register drain completion callback
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @cb: Callback function (NULL to clear)
 * @data: User data passed to callback
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * Callback is invoked exactly once when drain completes (transitions to
 * STOPPED). Safe to call SocketPool_free() from callback.
 */
extern void SocketPool_set_drain_callback (T pool, SocketPool_DrainCallback cb,
                                           void *data);

/* ============================================================================
 * Idle Connection Cleanup
 * ============================================================================
 */

/**
 * @brief SocketPool_set_idle_timeout - Set idle connection timeout
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @timeout_sec: Idle timeout in seconds (0 to disable automatic cleanup)
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * When enabled, connections idle longer than timeout_sec will be removed
 * during periodic cleanup. Use SocketPool_idle_cleanup_due_ms() to get
 * the time until next cleanup for poll timeout integration.
 */
extern void SocketPool_set_idle_timeout (T pool, time_t timeout_sec);

/**
 * @brief SocketPool_get_idle_timeout - Get idle connection timeout
 * @ingroup connection_mgmt
 * @pool: Pool instance
 *
 * Returns: Current idle timeout in seconds (0 = disabled)
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 */
extern time_t SocketPool_get_idle_timeout (T pool);

/**
 * @brief SocketPool_idle_cleanup_due_ms - Get time until next idle cleanup
 * @ingroup connection_mgmt
 * @pool: Pool instance
 *
 * Returns: Milliseconds until next cleanup, -1 if disabled
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * Use as timeout hint for poll/select to ensure timely cleanup.
 * @brief Returns -1 if idle timeout is disabled (timeout_sec == 0).
 * @ingroup connection_mgmt
 */
extern int64_t SocketPool_idle_cleanup_due_ms (T pool);

/**
 * @brief SocketPool_run_idle_cleanup - Run idle connection cleanup if due
 * @ingroup connection_mgmt
 * @pool: Pool instance
 *
 * Returns: Number of connections cleaned up
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * Call periodically (e.g., after each poll iteration) to remove
 * idle connections. Only performs cleanup if cleanup interval has passed.
 * Does nothing if idle timeout is disabled.
 */
extern size_t SocketPool_run_idle_cleanup (T pool);

/* ============================================================================
 * Connection Health Check
 * ============================================================================
 */

/**
 * Connection health status
 */
typedef enum
{
  POOL_CONN_HEALTHY = 0,  /**< Connection is healthy and usable */
  POOL_CONN_DISCONNECTED, /**< Connection has been disconnected */
  POOL_CONN_ERROR,        /**< Connection has a socket error */
  POOL_CONN_STALE         /**< Connection has exceeded max age */
} SocketPool_ConnHealth;

/**
 * @brief SocketPool_check_connection - Check health of a connection
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @conn: Connection to check
 *
 * Returns: Health status of the connection
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
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
 * ============================================================================
 */

/**
 * @brief SocketPool_ValidationCallback - Callback to validate connection before reuse
 * @ingroup connection_mgmt
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
 * @brief SocketPool_set_validation_callback - Set connection validation callback
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @cb: Validation callback (NULL to disable)
 * @data: User data passed to callback
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * When set, callback is invoked during SocketPool_get() to validate
 * connections before reuse. Use for application-level health checks.
 */
extern void
SocketPool_set_validation_callback (T pool, SocketPool_ValidationCallback cb,
                                    void *data);

/* ============================================================================
 * Pool Resize Callback
 * ============================================================================
 */

/**
 * @brief SocketPool_ResizeCallback - Callback invoked after pool resize
 * @ingroup connection_mgmt
 * (Type defined earlier in header)
 * @pool: Pool instance
 * @old_size: Previous maximum connections
 * @new_size: New maximum connections
 * @data: User data from SocketPool_set_resize_callback
 *
 * @note Thread-safe: Callback is invoked outside pool mutex.
 * @ingroup connection_mgmt
 */

/**
 * @brief SocketPool_set_resize_callback - Register pool resize notification callback
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @cb: Callback function (NULL to clear)
 * @data: User data passed to callback
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * Callback is invoked after successful pool resize operations.
 */
extern void SocketPool_set_resize_callback (T pool,
                                            SocketPool_ResizeCallback cb,
                                            void *data);

/* ============================================================================
 * Pool Statistics
 * ============================================================================
 */

/**
 * @brief SocketPool_Stats - Pool statistics snapshot
 * @ingroup connection_mgmt
 *
 * All counters are cumulative since pool creation or last reset.
 * Rates are calculated over the configured statistics window.
 */
typedef struct SocketPool_Stats
{
  /* Cumulative counters */
  uint64_t total_added;   /**< Total connections added to pool */
  uint64_t total_removed; /**< Total connections removed from pool */
  uint64_t total_reused;  /**< Total connections reused (returned via get) */
  uint64_t total_health_checks;   /**< Total health checks performed */
  uint64_t total_health_failures; /**< Total health check failures */
  uint64_t
      total_validation_failures; /**< Total validation callback failures */
  uint64_t total_idle_cleanups; /**< Connections removed due to idle timeout */

  /* Current state */
  size_t current_active;  /**< Current active connection count */
  size_t current_idle;    /**< Current idle connection count (active but not in
                             use) */
  size_t max_connections; /**< Maximum connection capacity */

  /* Calculated metrics */
  double reuse_rate;             /**< Reuse rate: reused / (added + reused) */
  double avg_connection_age_sec; /**< Average age of active connections
                                    (seconds) */
  double churn_rate_per_sec; /**< Churn rate: (added + removed) / window_sec */
} SocketPool_Stats;

/**
 * @brief SocketPool_get_stats - Get pool statistics snapshot
 * @ingroup connection_mgmt
 * @pool: Pool instance
 * @stats: Output statistics structure
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * Fills stats with current pool statistics. Calculated metrics
 * (reuse_rate, avg_connection_age, churn_rate) are computed at call time.
 */
extern void SocketPool_get_stats (T pool, SocketPool_Stats *stats);

/**
 * @brief SocketPool_reset_stats - Reset pool statistics counters
 * @ingroup connection_mgmt
 * @pool: Pool instance
 *
 * @note Thread-safe: Yes
 * @ingroup connection_mgmt
 *
 * Resets all cumulative counters to zero and restarts the statistics window.
 * Current state values (active, idle, max) are not affected.
 */
extern void SocketPool_reset_stats (T pool);

/**
 * @brief Connection_created_at - Get connection creation timestamp
 * @ingroup connection_mgmt
 * @conn: Connection instance
 *
 * Returns: Creation timestamp (time_t)
 * @note Thread-safe: Yes - read-only access
 * @ingroup connection_mgmt
 */
extern time_t Connection_created_at (const Connection_T conn);

#undef T

/** @} */ /* end of connection_mgmt group */

#endif
