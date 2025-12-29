/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETPOOL_INCLUDED
#define SOCKETPOOL_INCLUDED

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketSYNProtect.h"
#include "dns/SocketDNS.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketReconnect.h"
#include <stddef.h>
#include <time.h>

/**
 * @defgroup connection_mgmt Connection Management Modules
 * @brief Connection lifecycle management with pooling, reconnection, and
 * resilience patterns.
 * @{
 *
 * The Connection Management group handles connection lifecycle, pooling,
 * and resilience patterns. Key components include:
 * - SocketPool (pooling): Connection pooling with automatic lifecycle
 * management
 * - SocketReconnect (reconnection): Auto-reconnection with circuit breaker
 * - SocketRateLimit (rate-limit): Token bucket rate limiting
 * - SocketSYNProtect (syn-flood): SYN flood protection
 *
 * @see @ref core_io for socket primitives.
 * @see @ref event_system for event notification.
 * @see @ref foundation for memory management and exceptions.
 * @see @ref dns for DNS resolution support.
 * @see SocketPool_T for connection pooling.
 * @see @ref connection_mgmt::SocketReconnect_T for auto-reconnection.
 * @see Connection_T for connection accessors.
 * @see @ref utilities::SocketRateLimit_T for rate limiting.
 * @see @ref security::SocketSYNProtect_T for SYN flood protection.
 */

/**
 * @file SocketPool.h
 * @brief Connection pooling with automatic lifecycle management.
 * @ingroup connection_mgmt
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
 * - Rate limiting and SYN flood protection
 * - Graceful shutdown (drain) support
 * - Auto-reconnection capabilities
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
 * @see @ref event_system for event-driven I/O integration.
 * @see @ref core_io for underlying socket primitives.
 */

/**
 * @brief High-level connection pool with lifecycle management.
 * @ingroup connection_mgmt
 *
 * Opaque type representing a pool of socket connections with automatic
 * lifecycle management, rate limiting, SYN flood protection, and health
 * monitoring.
 *
 * @see SocketPool_new() for creation.
 * @see SocketPool_add() for adding connections.
 * @see SocketPool_drain() for graceful shutdown.
 * @see SocketPool_setconnrate() for rate limiting.
 * @see SocketPool_set_syn_protection() for SYN flood protection.
 */
#define T SocketPool_T
typedef struct T *T;

/**
 * @brief Opaque connection handle within a pool.
 * @ingroup connection_mgmt
 *
 * Represents a single socket connection within a pool, including associated
 * buffers, metadata, and lifecycle state. Use accessor functions to read/write
 * connection properties. All connection operations are thread-safe.
 *
 * @see Connection_socket() for socket access.
 * @see Connection_inbuf() and Connection_outbuf() for buffer access.
 * @see Connection_data() and Connection_setdata() for user data storage.
 * @see Connection_lastactivity() for activity tracking.
 * @see Connection_isactive() for connection state.
 * @see SocketPool_add() for connection creation.
 * @see SocketPool_get() for connection lookup.
 * @see SocketPool_remove() for connection removal.
 */
typedef struct Connection *Connection_T;

/**
 * @brief Callback to validate connection before reuse.
 * @ingroup connection_mgmt
 * @param conn Connection being validated for reuse.
 * @param[in] data User data from SocketPool_set_validation_callback().
 * @return Non-zero if connection is valid for reuse, 0 to remove it (forces
 * removal from pool).
 *
 * Called during SocketPool_get() before returning the connection to the
 * caller. If returns 0, the connection is automatically removed from the pool
 * and NULL is returned to the caller.
 *
 * THREAD SAFETY NOTES:
 * The pool mutex is RELEASED before invoking this callback and re-acquired
 * after it returns. This prevents deadlock but has important implications:
 *
 * - MAY safely call SocketPool_add/remove/get on OTHER sockets (not conn)
 * - MAY safely read via Connection_* accessors (thread-safe)
 * - MAY perform I/O operations like poll(), recv(MSG_PEEK), etc.
 * - SHOULD complete reasonably quickly (degrades get() latency for caller)
 *
 * RACE CONDITIONS:
 * Because the mutex is released, the connection may be concurrently removed
 * by another thread while validation runs. The pool handles this safely:
 * - After callback returns, pool re-validates that conn still exists
 * - If conn was removed, the return value is ignored (connection gone)
 * - The Connection_T pointer passed to callback remains valid during the call
 *
 * WARNING: Do NOT cache the Connection_T pointer beyond the callback return.
 * After returning, the connection may be removed and the pointer invalidated.
 *
 * Use for application-specific health checks beyond built-in validation.
 *
 * @see SocketPool_set_validation_callback() for registration.
 * @see SocketPool_check_connection() for built-in health checks.
 * @see SocketPool_get() for invocation context.
 * @see @ref connection_mgmt for connection management patterns.
 */
typedef int (*SocketPool_ValidationCallback) (Connection_T conn, void *data);

/**
 * @brief Callback invoked after pool resize.
 * @ingroup connection_mgmt
 * @param pool Pool instance that was resized.
 * @param old_size Previous maximum connection capacity.
 * @param new_size New maximum connection capacity.
 * @param[in] data User data from SocketPool_set_resize_callback().
 *
 * Called after successful pool resize operations for monitoring/logging.
 *
 * @threadsafe Yes - callback is invoked outside pool mutex.
 *
 * @see SocketPool_set_resize_callback() for registration.
 * @see SocketPool_resize() for resize operations.
 */
typedef void (*SocketPool_ResizeCallback) (T pool, size_t old_size,
                                           size_t new_size, void *data);

/**
 * @brief Callback invoked BEFORE pool resize for pointer invalidation.
 * @ingroup connection_mgmt
 * @param pool Pool instance about to be resized.
 * @param old_size Current maximum connection capacity.
 * @param new_size New maximum connection capacity.
 * @param[in] data User data from SocketPool_set_pre_resize_callback().
 *
 * CRITICAL: After this callback returns, all Connection_T pointers
 * obtained from this pool become INVALID due to internal array reallocation.
 * Callers MUST:
 * 1. Clear all cached Connection_T pointers
 * 2. Re-acquire them via SocketPool_get() after resize completes
 *
 * THREAD SAFETY REQUIREMENTS:
 * - Called with pool mutex HELD - keep operations quick (&lt;1ms)
 * - MUST NOT call SocketPool_add/remove/get (will deadlock)
 * - MAY safely clear external pointer caches
 * - MAY safely update external state
 *
 * WARNING: Long-running callbacks (>1ms) will block ALL pool operations
 * (add/remove/get/foreach) for all threads. For complex cleanup:
 * - Schedule work to be done after resize completes (use ResizeCallback)
 * - Use async notification patterns (work queue, condition variable)
 * - Keep this callback to simple pointer clearing only
 *
 * @see SocketPool_set_pre_resize_callback() for registration.
 * @see SocketPool_resize() for resize operations.
 * @see SocketPool_ResizeCallback for post-resize notification.
 */
typedef void (*SocketPool_PreResizeCallback) (T pool, size_t old_size,
                                              size_t new_size, void *data);

/**
 * @brief Callback invoked when a connection becomes idle.
 * @ingroup connection_mgmt
 * @param conn Connection that became idle.
 * @param[in] data User data from SocketPool_set_idle_callback().
 *
 * Called when a connection transitions to idle state (e.g., after being
 * returned to the pool or after activity timeout). Useful for connection
 * monitoring, logging, or cleanup of per-connection state.
 *
 * THREAD SAFETY REQUIREMENTS:
 * - MAY be called from pool operations with pool mutex held
 * - MUST NOT call SocketPool_add/remove/get (will deadlock)
 * - SHOULD complete quickly (&lt;1ms) to avoid blocking pool ops
 * - MAY use Connection_* accessors safely
 *
 * @see SocketPool_set_idle_callback() for registration.
 * @see SocketPool_set_idle_timeout() for automatic idle cleanup.
 */
typedef void (*SocketPool_IdleCallback) (Connection_T conn, void *data);

/**
 * @brief Predicate callback for filtering connections.
 * @ingroup connection_mgmt
 * @param conn Connection to test.
 * @param[in] data User data from SocketPool_find/filter().
 * @return Non-zero if connection matches criteria, 0 otherwise.
 *
 * Used with SocketPool_find() and SocketPool_filter() to select connections
 * based on custom criteria. Called with pool mutex held.
 *
 * THREAD SAFETY REQUIREMENTS:
 * - Called with pool mutex held - keep operations quick
 * - MUST NOT call SocketPool_add/remove (will deadlock)
 * - MAY use Connection_* accessors safely
 *
 * @see SocketPool_find() for finding first matching connection.
 * @see SocketPool_filter() for finding all matching connections.
 */
typedef int (*SocketPool_Predicate) (Connection_T conn, void *data);

/**
 * @brief Completion callback for async connections.
 * @ingroup connection_mgmt
 * @param conn Completed connection or NULL on error/failure.
 * @param error 0 on success, error code on failure.
 * @param[in] data User data from SocketPool_connect_async().
 *
 * Called when async connection (DNS + connect + pool add) completes.
 * Invoked from DNS worker thread - MUST be thread-safe.
 *
 * THREAD SAFETY REQUIREMENTS:
 * - MUST NOT access thread-local storage from main thread
 * - MUST NOT call non-thread-safe functions without synchronization
 * - Pool mutex is NOT held - MAY safely call other SocketPool functions
 * - MAY call SocketPool_free() if connection failed
 *
 * Safe patterns: mutex protection, atomic operations, work queueing,
 * condition variables, self-pipes, event loop signaling.
 *
 * Error codes: ENOTFOUND (DNS), ECONNREFUSED (connect), ETIMEDOUT (timeout),
 * EHOSTUNREACH (routing), ECONNRESET (reset), or other socket errors.
 *
 * @see SocketPool_connect_async() for initiation.
 * @see @ref SocketDNS_T for DNS resolution details.
 * @see @ref async_dns for async DNS patterns.
 * @see SocketPool_ConnectCallback for callback requirements.
 */
typedef void (*SocketPool_ConnectCallback) (Connection_T conn, int error,
                                            void *data);

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @brief Pool operation failure.
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
 * - Socket operation failures (NETWORK, retryable)
 * - DNS resolution failures (NETWORK, retryable)
 *
 * Check errno or context for specific failure reason.
 * Thread-safe: Uses thread-local error buffers.
 *
 * @see SocketPool_Failed exception type.
 * @see @ref error-handling for exception handling patterns.
 * @see socket_error_buf in SocketUtil.h for error message formatting.
 */
extern const Except_T SocketPool_Failed;

/**
 * @brief Create a new connection pool.
 * @ingroup connection_mgmt
 * @param[in] arena Arena_T for memory allocation (NULL uses default arena).
 * @param[in] maxconns Maximum number of connections (enforced to
 * 1-SOCKET_MAX_CONNECTIONS).
 * @param[in] bufsize Size of I/O buffers per connection (enforced to min-max
 * bounds).
 * @return New pool instance (never returns NULL on success).
 * @throws SocketPool_Failed on any allocation or initialization failure.
 * @threadsafe Yes - pool operations are thread-safe after creation.
 *
 * ## Usage Example
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * TRY {
 *     SocketPool_T pool = SocketPool_new(arena, 1000, 8192);
 *     // Use pool for connections...
 *     SocketPool_free(&pool);
 * } EXCEPT (SocketPool_Failed) {
 *     // Handle allocation failure
 * } FINALLY {
 *     Arena_dispose(&arena);
 * } END_TRY;
 * @endcode
 *
 * @complexity O(maxconns) - initializes hash table and pre-allocates buffers
 *
 * @note Automatically pre-warms SOCKET_POOL_DEFAULT_PREWARM_PCT slots for
 * performance.
 * @note All connections share the same arena for memory management.
 * @see SocketPool_free() for cleanup.
 * @see SocketPool_add() for adding connections.
 * @see SocketPool_prewarm() for runtime pre-warming.
 * @see Arena_new() for arena creation.
 * @see SOCKET_MAX_CONNECTIONS for global limits.
 * @see SOCKET_MIN_BUFFER_SIZE and SOCKET_MAX_BUFFER_SIZE for buffer limits.
 */
extern T SocketPool_new (Arena_T arena, size_t maxconns, size_t bufsize);

/**
 * @brief Prepare async connection using DNS resolution.
 * @ingroup connection_mgmt
 * @param pool Pool instance (used for configuration and cleanup).
 * @param dns DNS resolver instance.
 * @param host Remote hostname or IP address.
 * @param port Remote port (1-65535).
 * @param[out] out_socket New Socket_T instance.
 * @param[out] out_req Pointer to Request_T (DNS request handle) for
 * monitoring.
 * @return 0 on success, -1 on error (out_socket/out_req undefined).
 * @throws SocketPool_Failed on error.
 * @threadsafe Yes.
 *
 * Creates Socket_T with pool defaults, starts async DNS resolution.
 * Monitor out_req, then complete with Socket_connect_with_addrinfo()
 * and SocketPool_add(). On error, Socket_free() the socket.
 *
 * @see SocketPool_connect_async() for higher-level async connection.
 * @see @ref SocketDNS_T for DNS resolution details.
 * @see SocketPool_add() for adding completed connections.
 * @see Socket_connect_with_addrinfo() for completing the connection.
 * @see Socket_free() for cleanup on error.
 */
extern int SocketPool_prepare_connection (T pool, SocketDNS_T dns,
                                          const char *host, int port,
                                          Socket_T *out_socket,
                                          Request_T *out_req);

/**
 * @brief Free a connection pool and release all resources.
 * @ingroup connection_mgmt
 * @param[in,out] pool Pointer to pool (set to NULL on success).
 * @threadsafe Yes.
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketPool_free(&pool);  // Automatically closes pool resources
 * // pool == NULL after call
 * @endcode
 *
 * @note Does NOT close underlying sockets - caller must close them explicitly
 * or use SocketPool_drain_force() before freeing.
 * @warning If draining, ensure SocketPool_drain_wait() or
 * SocketPool_drain_poll() completes first to avoid resource leaks.
 * @see SocketPool_new() for creation.
 * @see SocketPool_drain() for graceful shutdown before freeing.
 * @see SocketPool_remove() for individual connection cleanup.
 * @complexity O(1) - quick resource release, no socket operations
 */
extern void SocketPool_free (T *pool);

/**
 * @brief Create async connection to remote host.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param host Remote hostname or IP address.
 * @param port Remote port number (1-65535).
 * @param callback Completion callback (see SocketPool_ConnectCallback).
 * @param[in] data User data passed to callback.
 * @return Request_T (DNS request handle) for monitoring completion.
 * @throws SocketPool_Failed on invalid params, allocation error, or limit
 * reached.
 * @threadsafe Yes.
 *
 * Starts async DNS resolution + connect + pool add. On completion:
 * - Success: callback(conn, 0, data) with Connection_T added to pool
 * - Failure: callback(NULL, error_code, data)
 *
 * Callback invoked from DNS worker thread - see SocketPool_ConnectCallback
 * for thread safety requirements. Limited to SOCKET_POOL_MAX_ASYNC_PENDING
 * concurrent operations for security.
 *
 * @see SocketPool_prepare_connection() for lower-level control.
 * @see SocketPool_ConnectCallback for callback requirements.
 * @see @ref SocketDNS_T for DNS resolution details.
 * @see SocketPool_add() for adding completed connections to pool.
 */
extern Request_T SocketPool_connect_async (T pool, const char *host, int port,
                                           SocketPool_ConnectCallback callback,
                                           void *data);

/**
 * @brief Retrieve Connection_T wrapper for a socket in the pool.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param[in] socket Socket_T to look up (must be valid file descriptor).
 * @return Connection_T if found and valid, NULL if not in pool, invalid, or
 * validation failed.
 * @threadsafe Yes - acquires pool mutex for duration of lookup.
 *
 * Performs hash table lookup using socket FD hashed with golden ratio
 * function. If found, runs built-in health check
 * (SocketPool_check_connection()) and optional user validation callback.
 * Updates last_activity timestamp to prevent idle timeout. Returns NULL
 * without exception if:
 * - Socket not in pool
 * - Connection unhealthy (disconnected, error, stale)
 * - Validation callback returns 0
 *
 * ## Usage Example
 *
 * @code{.c}
 * // In event loop, after poll indicates readable socket
 * Connection_T conn = SocketPool_get(pool, sock);
 * if (conn != NULL) {
 *     SocketBuf_T inbuf = Connection_inbuf(conn);
 *     size_t avail = SocketBuf_available(inbuf);
 *     if (avail > 0) {
 *         // Read data from buffer
 *         char buf[1024];
 *         size_t read_len = SocketBuf_read(inbuf, buf, sizeof(buf));
 *         // Process data...
 *     }
 *     // Update activity implicitly via get()
 * } else {
 *     // Socket not managed by pool - handle directly or close
 *     Socket_free(&sock);
 * }
 * @endcode
 *
 * @note Automatically refreshes connection activity timestamp.
 * @note Validation failures increment failure counters in pool stats.
 * @warning Returned Connection_T remains valid until SocketPool_remove() or
 * pool free.
 * @complexity O(1) average case - hash lookup; O(n) worst case - hash
 * collisions
 *
 * @see SocketPool_add() for adding connections to pool.
 * @see SocketPool_set_validation_callback() for custom validation before
 * return.
 * @see SocketPool_check_connection() for manual health checks.
 * @see Connection_T accessors like Connection_socket(), Connection_inbuf().
 * @see socket_util_hash_fd() for underlying hash function.
 * @see @ref connection_mgmt for full connection lifecycle.
 */
extern Connection_T SocketPool_get (T pool, Socket_T socket);

/**
 * @brief Add a connected socket to the pool, creating a Connection_T wrapper.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param[in] socket Connected Socket_T (must not be NULL or already in pool).
 * @return Connection_T wrapper or NULL if pool full, socket invalid, or
 * allocation failed.
 * @throws SocketPool_Failed on invalid parameters or internal allocation
 * failures.
 * @threadsafe Yes - acquires pool mutex internally.
 *
 * Allocates per-connection I/O buffers, initializes metadata (timestamps, user
 * data = NULL), adds to hash table for O(1) lookup, and increments active
 * count/statistics.
 *
 * Failure cases:
 * - Pool at capacity: Returns NULL (no exception)
 * - Socket already in pool: Returns NULL (no exception)
 * - Invalid socket (not connected): Returns NULL (no exception)
 * - Allocation failure: Raises SocketPool_Failed
 * - Mutex deadlock (rare): Raises SocketPool_Failed
 *
 * ## Usage Example
 *
 * @code{.c}
 * Socket_T client_sock = Socket_accept(server_sock);
 * if (client_sock != NULL) {
 *     TRY {
 *         Connection_T conn = SocketPool_add(pool, client_sock);
 *         if (conn != NULL) {
 *             // Connection successfully added - use conn->socket, buffers,
 * etc. Connection_setdata(conn, my_user_data); } else {
 *             // Pool full or invalid - close socket
 *             Socket_free(&client_sock);
 *         }
 *     } EXCEPT (SocketPool_Failed) {
 *         // Allocation or param error - cleanup
 *         Socket_free(&client_sock);
 *     } END_TRY;
 * }
 * @endcode
 *
 * @note Socket must be connected and valid before adding.
 * @note Buffers are allocated from pool's arena - share lifecycle with pool.
 * @warning Do not add the same socket twice - results in undefined behavior.
 * @complexity O(1) average - hash insertion, buffer allocation is amortized
 * constant
 *
 * @see SocketPool_get() for looking up connections by socket.
 * @see SocketPool_remove() for removing connections.
 * @see SocketPool_accept_limited() for rate-limited server accepting.
 * @see SocketPool_resize() for changing pool capacity.
 * @see SocketPool_count() for current connection statistics.
 * @see Connection_T for connection wrapper details.
 */
extern Connection_T SocketPool_add (T pool, Socket_T socket);

/**
 * @brief Accept multiple connections from server socket.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param server Server socket (listening, non-blocking).
 * @param max_accepts Maximum number to accept (1 to
 * SOCKET_POOL_MAX_BATCH_ACCEPTS).
 * @param accepted_capacity Size of accepted array (must be >= max_accepts).
 * @param[out] accepted Output array for accepted Socket_T pointers
 * (caller-allocated).
 * @return Number accepted (0 to max_accepts).
 * @throws SocketPool_Failed on error.
 * @threadsafe Yes.
 *
 * Efficient batch accept using accept4() where available.
 * Automatically adds accepted sockets to pool.
 *
 * CALLER RESPONSIBILITY: The accepted array MUST be pre-allocated with at
 * least max_accepts elements. No bounds checking - undersized array causes
 * overflow.
 *
 * Safe usage: Socket_T accepted[100]; int count =
 * SocketPool_accept_batch(pool, server, 100, 100, accepted);
 *
 * @see SocketPool_accept_limited() for rate-limited single accept.
 * @see SocketPool_accept_protected() for SYN protection.
 */
extern int SocketPool_accept_batch (T pool, Socket_T server, int max_accepts,
                                    size_t accepted_capacity,
                                    Socket_T *accepted);

/**
 * @brief Remove socket from pool.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
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
 * @param[in] pool Pool instance.
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
 * @param[in] pool Pool instance.
 * @return Number of active connections.
 * @threadsafe Yes.
 * @see SocketPool_resize() for changing capacity.
 * @see SocketPool_cleanup() for removing idle connections.
 */
extern size_t SocketPool_count (T pool);

/**
 * @brief Resize pool capacity at runtime.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param new_maxconns New maximum connections.
 * @throws SocketPool_Failed on error.
 * @threadsafe Yes.
 * @note Grows/shrinks pool; closes excess connections on shrink.
 * @see SocketPool_set_resize_callback() for notifications.
 */
extern void SocketPool_resize (T pool, size_t new_maxconns);

/**
 * @brief Register callback for pre-resize notification.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param cb Callback function (NULL to disable).
 * @param[in] data User data passed to callback.
 * @threadsafe Yes.
 *
 * Registers a callback invoked BEFORE pool resize operations. This allows
 * external code to clear cached Connection_T pointers before they become
 * invalid due to internal array reallocation.
 *
 * @warning After callback returns, ALL Connection_T pointers from this pool
 * are invalid. Re-acquire them via SocketPool_get() after resize completes.
 *
 * @see SocketPool_PreResizeCallback for callback requirements.
 * @see SocketPool_resize() for resize operations.
 */
extern void SocketPool_set_pre_resize_callback (T pool,
                                                 SocketPool_PreResizeCallback cb,
                                                 void *data);

/**
 * @brief Pre-allocate buffers for percentage of free slots.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param percentage Percentage of free slots to prewarm (0-100).
 * @threadsafe Yes.
 * @note Reduces latency by pre-allocating buffers.
 * @see SocketPool_new() for initial prewarming.
 */
extern void SocketPool_prewarm (T pool, int percentage);

/**
 * @brief Set buffer size for future connections.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param new_bufsize New buffer size for future connections.
 * @threadsafe Yes.
 * @note Existing connections keep their current buffer size.
 * @see SocketPool_new() for initial buffer size.
 * @see SocketBuf_T for buffer operations.
 */
extern void SocketPool_set_bufsize (T pool, size_t new_bufsize);

/**
 * @brief Iterate over active connections.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param func Callback function (Connection_T, void*).
 * @param arg User data passed to callback.
 * @threadsafe Yes - holds mutex during iteration.
 * @note O(n) scan; callback must not modify pool structure.
 * @see SocketPool_count() for getting connection count.
 */
extern void SocketPool_foreach (T pool, void (*func) (Connection_T, void *),
                                void *arg);

/**
 * @brief Find first connection matching a predicate.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param predicate Callback that returns non-zero for matching connections.
 * @param[in] userdata User data passed to predicate.
 * @return First matching Connection_T or NULL if none found.
 * @threadsafe Yes - holds mutex during search.
 *
 * Iterates through active connections and returns the first one for which
 * predicate returns non-zero. Stops immediately on first match.
 *
 * ## Example
 *
 * @code{.c}
 * int is_client_ip(Connection_T conn, void *data) {
 *     const char *target_ip = (const char *)data;
 *     Socket_T sock = Connection_socket(conn);
 *     return strcmp(Socket_getpeeraddr(sock), target_ip) == 0;
 * }
 *
 * Connection_T conn = SocketPool_find(pool, is_client_ip, "192.168.1.100");
 * if (conn) {
 *     // Found connection from that IP
 * }
 * @endcode
 *
 * @complexity O(n) worst case - scans until match or end
 *
 * @see SocketPool_Predicate for predicate requirements.
 * @see SocketPool_filter() for finding all matching connections.
 * @see SocketPool_foreach() for iterating all connections.
 */
extern Connection_T SocketPool_find (T pool, SocketPool_Predicate predicate,
                                     void *userdata);

/**
 * @brief Find all connections matching a predicate.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param predicate Callback that returns non-zero for matching connections.
 * @param[in] userdata User data passed to predicate.
 * @param[out] results Array to receive matching connections.
 * @param max_results Maximum number of results to return.
 * @return Number of matching connections found (may be less than max_results).
 * @threadsafe Yes - holds mutex during search.
 *
 * Iterates through active connections and returns all that match the predicate,
 * up to max_results. Results array must be pre-allocated by caller.
 *
 * ## Example
 *
 * @code{.c}
 * int is_idle(Connection_T conn, void *data) {
 *     time_t threshold = *(time_t *)data;
 *     return time(NULL) - Connection_lastactivity(conn) > threshold;
 * }
 *
 * Connection_T idle_conns[100];
 * time_t threshold = 300;  // 5 minutes
 * size_t count = SocketPool_filter(pool, is_idle, &threshold, idle_conns, 100);
 * for (size_t i = 0; i < count; i++) {
 *     // Process idle connection
 * }
 * @endcode
 *
 * @complexity O(n) - scans all active connections
 *
 * @see SocketPool_Predicate for predicate requirements.
 * @see SocketPool_find() for finding first matching connection.
 * @see SocketPool_foreach() for iterating all connections.
 */
extern size_t SocketPool_filter (T pool, SocketPool_Predicate predicate,
                                 void *userdata, Connection_T *results,
                                 size_t max_results);

/* Connection accessors */

/**
 * @brief Get connection's socket.
 * @ingroup connection_mgmt
 * @param conn Connection_T instance (must not be NULL).
 * @return Associated Socket_T (never NULL for valid connections).
 * @threadsafe Yes - read-only accessor, no synchronization needed.
 * @note Socket remains valid until connection is removed from pool.
 * @see Connection_inbuf() and Connection_outbuf() for buffer access.
 * @see Connection_data() for user data access.
 * @see Socket_T for socket operations.
 * @see Socket_fd() for getting file descriptor.
 */
extern Socket_T Connection_socket (const Connection_T conn);

/**
 * @brief Get connection's input buffer.
 * @ingroup connection_mgmt
 * @param[in] conn Connection instance.
 * @return Input buffer for reading data.
 * @threadsafe Yes - read-only accessor.
 * @see Connection_outbuf() for output buffer.
 * @see SocketBuf_T for buffer operations.
 */
extern SocketBuf_T Connection_inbuf (const Connection_T conn);

/**
 * @brief Get connection's output buffer.
 * @ingroup connection_mgmt
 * @param[in] conn Connection instance.
 * @return Output buffer for writing data.
 * @threadsafe Yes - read-only accessor.
 * @see Connection_inbuf() for input buffer.
 * @see SocketBuf_T for buffer operations.
 */
extern SocketBuf_T Connection_outbuf (const Connection_T conn);

/**
 * @brief Get connection's user data.
 * @ingroup connection_mgmt
 * @param[in] conn Connection instance.
 * @return User data pointer.
 * @threadsafe Yes - read-only accessor.
 * @see Connection_setdata() for setting user data.
 */
extern void *Connection_data (const Connection_T conn);

/**
 * @brief Set connection's user data.
 * @ingroup connection_mgmt
 * @param conn Connection_T instance (must not be NULL).
 * @param data void* data pointer to store (may be NULL).
 * @threadsafe No - requires external synchronization for concurrent access.
 * @note Other Connection_* accessors are thread-safe, but this modifies state.
 * @note Data is not freed automatically - caller responsible for cleanup.
 * @warning Concurrent calls to Connection_setdata() without synchronization
 *          will cause data races. Use mutex or atomic operations if needed.
 * @see Connection_data() for reading user data.
 * @see Connection_T for connection management.
 */
extern void Connection_setdata (Connection_T conn, void *data);

/**
 * @brief Get connection's last activity timestamp.
 * @ingroup connection_mgmt
 * @param[in] conn Connection instance.
 * @return Last activity time as time_t.
 * @threadsafe Yes - read-only accessor.
 * @see Connection_created_at() for creation timestamp.
 * @see SocketPool_cleanup() for idle connection removal.
 */
extern time_t Connection_lastactivity (const Connection_T conn);

/**
 * @brief Check if connection is active.
 * @ingroup connection_mgmt
 * @param[in] conn Connection instance.
 * @return Non-zero if connection is active.
 * @threadsafe Yes - read-only accessor.
 * @see SocketPool_get() for automatic activity timestamp updates.
 * @see SocketPool_cleanup() for inactive connection removal.
 */
extern int Connection_isactive (const Connection_T conn);

/* ============================================================================
 * Reconnection Support
 * ============================================================================
 */

/**
 * @brief Set default reconnection policy for pool.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param policy Reconnection policy (NULL to disable auto-reconnect).
 * @threadsafe Yes.
 *
 * Sets the default reconnection policy for connections in this pool.
 * Does not affect existing connections - use SocketPool_enable_reconnect()
 * for those.
 *
 * @see SocketReconnect_Policy_T for policy configuration.
 * @see SocketPool_enable_reconnect() for enabling on existing connections.
 */
extern void
SocketPool_set_reconnect_policy (T pool,
                                 const SocketReconnect_Policy_T *policy);

/**
 * @brief Enable auto-reconnect for a connection.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param conn Connection to enable reconnection for.
 * @param host Original hostname for reconnection.
 * @param port Original port for reconnection.
 * @threadsafe Yes.
 *
 * Enables automatic reconnection for the specified connection using
 * the pool's reconnection policy. When the connection fails, it will
 * be automatically reconnected.
 *
 * NOTE: The original host/port must be provided since the socket may
 * have been created with just an IP address from DNS resolution.
 *
 * @see SocketPool_set_reconnect_policy() for setting the policy.
 * @see SocketPool_disable_reconnect() for disabling reconnection.
 * @see @ref reconnection for reconnection patterns.
 */
extern void SocketPool_enable_reconnect (T pool, Connection_T conn,
                                         const char *host, int port);

/**
 * @brief Disable auto-reconnect for a connection.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param conn Connection to disable reconnection for.
 * @threadsafe Yes.
 *
 * Disables automatic reconnection for the specified connection.
 *
 * @see SocketPool_enable_reconnect() for enabling reconnection.
 */
extern void SocketPool_disable_reconnect (T pool, Connection_T conn);

/**
 * @brief Process reconnection state machines.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @threadsafe Yes.
 *
 * Must be called periodically (e.g., in event loop) to process
 * reconnection timers and state transitions for all connections
 * with auto-reconnect enabled.
 *
 * @see SocketPool_reconnect_timeout_ms() for timeout hints.
 * @see SocketPool_enable_reconnect() for enabling reconnection.
 */
extern void SocketPool_process_reconnects (T pool);

/**
 * @brief Get time until next reconnection action.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return Milliseconds until next timeout, or -1 if none pending.
 * @threadsafe Yes.
 *
 * Use as timeout hint for poll/select when reconnections are active.
 *
 * @see SocketPool_process_reconnects() for processing reconnections.
 */
extern int SocketPool_reconnect_timeout_ms (T pool);

/**
 * @brief Get reconnection context for connection.
 * @ingroup connection_mgmt
 * @param[in] conn Connection instance.
 * @return SocketReconnect_T context, or NULL if reconnection not enabled.
 * @threadsafe Yes - returned context is not thread-safe.
 * @see Connection_has_reconnect() to check if enabled.
 * @see SocketPool_enable_reconnect() to enable reconnection.
 */
extern SocketReconnect_T Connection_reconnect (const Connection_T conn);

/**
 * @brief Check if connection has auto-reconnect enabled.
 * @ingroup connection_mgmt
 * @param[in] conn Connection instance.
 * @return Non-zero if auto-reconnect is enabled.
 * @threadsafe Yes.
 * @see SocketPool_enable_reconnect() to enable reconnection.
 * @see Connection_reconnect() to get context.
 */
extern int Connection_has_reconnect (const Connection_T conn);

/* ============================================================================
 * Rate Limiting
 * ============================================================================
 */

/**
 * @brief Set connection rate limit.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param conns_per_sec Maximum new connections per second (0 to disable).
 * @param burst Burst capacity (0 for default = conns_per_sec).
 * @threadsafe Yes.
 *
 * Enables connection rate limiting using token bucket algorithm.
 * New connections via SocketPool_add() or SocketPool_accept_limited()
 * will be rejected if rate is exceeded.
 *
 * @see SocketPool_accept_limited() for rate-limited accepting.
 * @see SocketPool_getconnrate() to check current limit.
 * @see SocketPool_setmaxperip() for per-IP limits.
 * @see @ref utilities::SocketRateLimit_T for token bucket implementation.
 */
extern void SocketPool_setconnrate (T pool, int conns_per_sec, int burst);

/**
 * @brief Get connection rate limit.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return Connections per second limit (0 if disabled).
 * @threadsafe Yes.
 * @see SocketPool_setconnrate() for setting the limit.
 */
extern int SocketPool_getconnrate (T pool);

/**
 * @brief Set maximum connections per IP.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param max_conns Maximum connections per IP (0 = unlimited).
 * @threadsafe Yes.
 *
 * Enables per-IP connection limiting to prevent single-source attacks.
 * New connections from IPs that exceed the limit will be rejected.
 *
 * @see SocketPool_getmaxperip() for reading the limit.
 * @see SocketPool_accept_limited() for rate-limited accepting.
 */
extern void SocketPool_setmaxperip (T pool, int max_conns);

/**
 * @brief Get maximum connections per IP.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return Maximum connections per IP (0 = unlimited).
 * @threadsafe Yes.
 * @see SocketPool_setmaxperip() for setting the limit.
 */
extern int SocketPool_getmaxperip (T pool);

/**
 * @brief Check if accepting is allowed.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param client_ip Client IP address (NULL to skip IP check).
 * @return 1 if allowed, 0 if rate limited or IP limit reached.
 * @threadsafe Yes.
 *
 * Checks both connection rate and per-IP limits.
 * Does NOT consume rate limit tokens - use SocketPool_accept_limited() for
 * that.
 *
 * @see SocketPool_accept_limited() for actual accepting with rate limiting.
 */
extern int SocketPool_accept_allowed (T pool, const char *client_ip);

/**
 * @brief Accept connection with rate limiting.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param server Server Socket_T to accept from (must be listening).
 * @return Socket_T or NULL if draining/stopped, rate limited, or accept
 * failed.
 * @threadsafe Yes - acquires pool mutex internally.
 *
 * Comprehensive accept function combining multiple protection mechanisms:
 * - Returns NULL immediately if pool is draining or stopped
 * - Consumes rate token before attempting accept
 * - If per-IP limiting enabled, automatically tracks client IP
 * - On SocketPool_add failure, caller MUST call SocketPool_release_ip() and
 * Socket_free()
 *
 * FAILURE MODES:
 * - Pool draining/stopped: Returns NULL immediately
 * - Rate limited: Returns NULL, no tokens consumed
 * - IP limit reached: Returns NULL, tracked IP remains blocked
 * - Accept failed: Returns NULL (network error)
 * - Pool full: Returns Socket_T but SocketPool_add() returns NULL
 *
 * @see SocketPool_setconnrate() to configure rate limits.
 * @see SocketPool_setmaxperip() for per-IP limits.
 * @see SocketPool_accept_protected() for SYN protection.
 * @see SocketPool_release_ip() for cleanup on SocketPool_add() failure.
 * @see Socket_free() for socket cleanup.
 * @see @ref utilities::SocketRateLimit_T for token bucket implementation.
 */
extern Socket_T SocketPool_accept_limited (T pool, Socket_T server);

/**
 * @brief Manually track IP for per-IP limiting.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param ip IP address to track.
 * @return 1 if under limit and tracked, 0 if limit reached.
 * @threadsafe Yes.
 *
 * Use when manually managing connections not via SocketPool_accept_limited().
 * Call SocketPool_release_ip() when connection closes.
 *
 * @see SocketPool_release_ip() for releasing tracked IPs.
 * @see SocketPool_ip_count() for checking IP connection count.
 */
extern int SocketPool_track_ip (T pool, const char *ip);

/**
 * @brief Release tracked IP when connection closes.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param ip IP address to release.
 * @threadsafe Yes.
 *
 * Decrements the connection count for the IP address.
 * Safe to call with NULL or untracked IP.
 *
 * @see SocketPool_track_ip() for tracking IPs.
 */
extern void SocketPool_release_ip (T pool, const char *ip);

/**
 * @brief Get connection count for IP.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param ip IP address to query.
 * @return Number of tracked connections from this IP.
 * @threadsafe Yes.
 * @see SocketPool_track_ip() for tracking IPs.
 * @see SocketPool_release_ip() for releasing tracked IPs.
 */
extern int SocketPool_ip_count (T pool, const char *ip);

/* ============================================================================
 * SYN Flood Protection
 * ============================================================================
 */

/**
 * @brief Enable SYN flood protection for pool.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param protect SYN protection instance (NULL to disable).
 * @threadsafe Yes.
 *
 * When enabled, SocketPool_accept_protected() will check with the
 * protection module and apply appropriate actions (throttle, challenge,
 * or block) before accepting connections.
 *
 * The protection module is NOT owned by the pool - caller must ensure
 * it remains valid and must free it after the pool is freed.
 *
 * @see SocketPool_accept_protected() for protected accepting.
 * @see @ref security::SocketSYNProtect for SYN flood protection details.
 */
extern void SocketPool_set_syn_protection (T pool, SocketSYNProtect_T protect);

/**
 * @brief Get current SYN protection module.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return Current SYN protection instance, or NULL if disabled.
 * @threadsafe Yes.
 * @see SocketPool_set_syn_protection() for setting protection.
 */
extern SocketSYNProtect_T SocketPool_get_syn_protection (T pool);

/**
 * @brief Accept with full SYN flood protection.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param server Server socket (listening, non-blocking).
 * @param action_out Output - action taken (optional, may be NULL).
 * @return New socket if allowed, NULL if blocked/would block.
 * @throws SocketPool_Failed on actual errors (not protection blocking).
 * @threadsafe Yes.
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
 * @brief Industry-standard graceful shutdown following patterns from nginx,
 * HAProxy, and Go http.Server. Provides clean state machine transitions,
 * non-blocking APIs for event loop integration, and timeout-guaranteed
 * completion.
 *
 * @ingroup connection_mgmt
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
 *
 * @see SocketPool_drain() to initiate drain.
 * @see SocketPool_drain_poll() for non-blocking completion.
 * @see SocketPool_drain_wait() for blocking completion.
 */

/**
 * @brief Pool lifecycle states for graceful shutdown.
 * @ingroup connection_mgmt
 */
typedef enum
{
  POOL_STATE_RUNNING = 0, /**< Normal operation - accepting connections */
  POOL_STATE_DRAINING,    /**< Rejecting new, waiting for existing to close */
  POOL_STATE_STOPPED      /**< Fully stopped - safe to free */
} SocketPool_State;

/**
 * @brief Health status for load balancer integration.
 * @ingroup connection_mgmt
 */
typedef enum
{
  POOL_HEALTH_HEALTHY = 0, /**< Accept traffic normally */
  POOL_HEALTH_DRAINING,    /**< Finishing existing connections, reject new */
  POOL_HEALTH_STOPPED      /**< Not accepting any traffic */
} SocketPool_Health;

/**
 * @brief Notification callback when drain completes.
 * @ingroup connection_mgmt
 * @param pool Pool instance that completed draining.
 * @param timed_out 1 if drain timed out (forced), 0 if graceful completion.
 * @param[in] data User data from SocketPool_set_drain_callback().
 *
 * Called exactly once when pool transitions to STOPPED state.
 * Safe to call SocketPool_free() from within this callback.
 * Invoked from thread calling drain_poll/drain_wait.
 *
 * @see SocketPool_drain() for initiating drain.
 * @see SocketPool_set_drain_callback() for registration.
 * @see SocketPool_drain_poll() for non-blocking drain monitoring.
 */
typedef void (*SocketPool_DrainCallback) (T pool, int timed_out, void *data);

/**
 * @brief Get current pool lifecycle state.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return Current SocketPool_State.
 * @threadsafe Yes - atomic read.
 * @note Complexity: O(1).
 * @see SocketPool_State for state definitions.
 * @see SocketPool_drain() for state transitions.
 */
extern SocketPool_State SocketPool_state (T pool);

/**
 * @brief Get pool health status for load balancers.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return Current SocketPool_Health.
 * @threadsafe Yes - atomic read.
 * @note Complexity: O(1). Maps state to health: RUNNING -> HEALTHY, DRAINING
 * -> DRAINING, STOPPED -> STOPPED.
 * @see SocketPool_Health for health status definitions.
 * @see SocketPool_state() for raw state.
 */
extern SocketPool_Health SocketPool_health (T pool);

/**
 * @brief Check if pool is currently draining.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return Non-zero if state is DRAINING.
 * @threadsafe Yes - atomic read.
 * @note Complexity: O(1).
 * @see SocketPool_state() for full state information.
 */
extern int SocketPool_is_draining (T pool);

/**
 * @brief Check if pool is fully stopped.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return Non-zero if state is STOPPED.
 * @threadsafe Yes - atomic read.
 * @note Complexity: O(1).
 * @see SocketPool_state() for full state information.
 */
extern int SocketPool_is_stopped (T pool);

/**
 * @brief Initiate graceful shutdown.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param timeout_ms Maximum time to wait for connections to close
 * (milliseconds). Use 0 for immediate force-close, -1 for infinite wait.
 * @threadsafe Yes - atomic state transitions.
 * @note Transitions pool from RUNNING to DRAINING state.
 * @note Rejects new connections, allows existing to close naturally.
 * @note Force-closes remaining connections after timeout.
 * @note Multiple calls are idempotent - extends timeout if already draining.
 *
 * STATE TRANSITIONS:
 * - RUNNING -> DRAINING: Start rejecting new connections
 * - DRAINING -> STOPPED: When all connections closed or timeout reached
 * - STOPPED: Final state, pool can be safely freed
 *
 * @see SocketPool_drain_poll() for non-blocking completion.
 * @see SocketPool_drain_wait() for blocking completion.
 * @see SocketPool_drain_force() for immediate shutdown.
 * @see SocketPool_state() to check current state.
 * @see SocketPool_State for state definitions.
 * @see SocketPool_DrainCallback for completion notifications.
 */
extern void SocketPool_drain (T pool, int timeout_ms);

/**
 * @brief Poll drain progress (non-blocking).
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return >0 active connections (keep polling), 0 graceful completion, -1
 * timeout.
 * @threadsafe Yes.
 *
 * Call periodically to check drain progress and trigger force-close on
 * timeout. Invokes drain callback on completion. If not draining, returns
 * current count.
 *
 * @see SocketPool_drain() to initiate drain.
 * @see SocketPool_drain_wait() for blocking version.
 * @see SocketPool_drain_remaining_ms() for timeout info.
 */
extern int SocketPool_drain_poll (T pool);

/**
 * @brief Get time until forced shutdown.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return Milliseconds until timeout, 0 if already expired, -1 if not
 * draining.
 * @threadsafe Yes - atomic state check; deadline read may be stale.
 * @note Complexity: O(1). Use as timeout hint for poll/select during drain.
 *
 * Returns a best-effort ESTIMATE for timeout hints in event loops. The state
 * check is atomic, but the deadline read is non-atomic and may observe stale
 * values. This is acceptable because the returned value is inherently racy
 * (time advances continuously) and intended for advisory use only.
 *
 * Callers MUST treat the return value as a hint, not an exact deadline.
 * Critical drain decisions (force-close on timeout) are made by
 * SocketPool_drain_poll() which synchronizes access to both state and
 * deadline fields under mutex protection.
 *
 * @see SocketPool_drain() for drain initiation.
 * @see SocketPool_drain_poll() for progress monitoring with mutex protection.
 */
extern int64_t SocketPool_drain_remaining_ms (T pool);

/**
 * @brief Force immediate shutdown.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @threadsafe Yes.
 * @note Complexity: O(n) where n = active connections.
 *
 * Immediately closes all connections and transitions to STOPPED.
 * Can be called at any time, regardless of current state.
 * Invokes drain callback with timed_out=1.
 *
 * Logs: "Pool drain forced" at WARN level.
 *
 * @see SocketPool_drain() for graceful shutdown.
 */
extern void SocketPool_drain_force (T pool);

/**
 * @brief Blocking drain with internal poll loop.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param timeout_ms Maximum wait time (milliseconds), -1 for infinite.
 * @return 0 if graceful completion, -1 if timed out (forced).
 * @threadsafe Yes.
 *
 * Convenience function: calls drain(), polls with backoff, returns on
 * completion. For event-driven apps, prefer drain() + drain_poll() pattern.
 *
 * @see SocketPool_drain() for manual control.
 * @see SocketPool_drain_poll() for non-blocking polling.
 */
extern int SocketPool_drain_wait (T pool, int timeout_ms);

/**
 * @brief Register drain completion callback.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param cb Callback function (NULL to clear).
 * @param[in] data User data passed to callback.
 * @threadsafe Yes.
 *
 * Callback is invoked exactly once when drain completes (transitions to
 * STOPPED). Safe to call SocketPool_free() from callback.
 *
 * @see SocketPool_DrainCallback for callback signature.
 * @see SocketPool_drain() for initiating drain.
 */
extern void SocketPool_set_drain_callback (T pool, SocketPool_DrainCallback cb,
                                           void *data);

/* ============================================================================
 * Idle Connection Cleanup
 * ============================================================================
 */

/**
 * @brief Set idle connection timeout.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param timeout_sec Idle timeout in seconds (0 to disable automatic cleanup).
 * @threadsafe Yes.
 *
 * When enabled, connections idle longer than timeout_sec will be removed
 * during periodic cleanup. Use SocketPool_idle_cleanup_due_ms() to get
 * the time until next cleanup for poll timeout integration.
 *
 * @see SocketPool_get_idle_timeout() for reading the timeout.
 * @see SocketPool_idle_cleanup_due_ms() for cleanup timing.
 */
extern void SocketPool_set_idle_timeout (T pool, time_t timeout_sec);

/**
 * @brief Get idle connection timeout.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return Current idle timeout in seconds (0 = disabled).
 * @threadsafe Yes.
 * @see SocketPool_set_idle_timeout() for setting the timeout.
 */
extern time_t SocketPool_get_idle_timeout (T pool);

/**
 * @brief Get time until next idle cleanup.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return Milliseconds until next cleanup, -1 if disabled.
 * @threadsafe Yes.
 *
 * Use as timeout hint for poll/select to ensure timely cleanup.
 * Returns -1 if idle timeout is disabled (timeout_sec == 0).
 *
 * @see SocketPool_set_idle_timeout() for configuring cleanup.
 * @see SocketPool_run_idle_cleanup() for manual cleanup.
 */
extern int64_t SocketPool_idle_cleanup_due_ms (T pool);

/**
 * @brief Run idle connection cleanup if due.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return Number of connections cleaned up.
 * @threadsafe Yes.
 *
 * Call periodically (e.g., after each poll iteration) to remove
 * idle connections. Only performs cleanup if cleanup interval has passed.
 * Does nothing if idle timeout is disabled.
 *
 * @see SocketPool_set_idle_timeout() for configuring cleanup.
 * @see SocketPool_idle_cleanup_due_ms() for timing information.
 */
extern size_t SocketPool_run_idle_cleanup (T pool);

/* ============================================================================
 * Connection Health Check
 * ============================================================================
 */

/**
 * @brief Connection health status enumeration.
 * @ingroup connection_mgmt
 */
typedef enum
{
  POOL_CONN_HEALTHY = 0,  /**< Connection is healthy and usable */
  POOL_CONN_DISCONNECTED, /**< Connection has been disconnected */
  POOL_CONN_ERROR,        /**< Connection has a socket error */
  POOL_CONN_STALE         /**< Connection has exceeded max age */
} SocketPool_ConnHealth;

/**
 * @brief Check health of a connection.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param conn Connection to check.
 * @return Health status of the connection.
 * @threadsafe Yes.
 *
 * Checks:
 * - Socket is still connected (SO_ERROR check)
 * - Socket is not in error state
 * - Connection has not exceeded idle timeout.
 *
 * @see SocketPool_ConnHealth for health status values.
 * @see SocketPool_set_validation_callback() for custom validation.
 */
extern SocketPool_ConnHealth SocketPool_check_connection (T pool,
                                                          Connection_T conn);

/* ============================================================================
 * Connection Validation Callback
 * ============================================================================
 */

/* See SocketPool_ValidationCallback typedef above for full callback details
 * and thread safety requirements. */

/**
 * @brief Set connection validation callback.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param cb Validation callback (NULL to disable).
 * @param[in] data User data passed to callback.
 * @threadsafe Yes.
 *
 * Callback invoked during SocketPool_get() to validate connections
 * before reuse. Use for application-level health checks.
 *
 * @see SocketPool_ValidationCallback for callback signature.
 * @see SocketPool_check_connection() for built-in health checks.
 * @see SocketPool_get() for when validation occurs.
 */
extern void
SocketPool_set_validation_callback (T pool, SocketPool_ValidationCallback cb,
                                    void *data);

/* ============================================================================
 * Pool Resize Callback
 * ============================================================================
 */

/* See SocketPool_ResizeCallback typedef for details. */

/**
 * @brief Register pool resize notification callback.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param cb Callback function (NULL to clear).
 * @param[in] data User data passed to callback.
 * @threadsafe Yes.
 *
 * Callback is invoked after successful pool resize operations.
 *
 * @see SocketPool_ResizeCallback for callback signature.
 * @see SocketPool_resize() for resize operations.
 */
extern void SocketPool_set_resize_callback (T pool,
                                            SocketPool_ResizeCallback cb,
                                            void *data);

/* ============================================================================
 * Pool Statistics
 * ============================================================================
 */

/**
 * @brief Pool statistics snapshot structure.
 * @ingroup connection_mgmt
 *
 * All counters are cumulative since pool creation or last reset.
 * Rates are calculated over the configured statistics window.
 * Thread-safe: All fields are read atomically during snapshot.
 *
 * @see SocketPool_get_stats() for retrieving statistics.
 * @see SocketPool_reset_stats() for resetting counters.
 * @see SocketPool_Stats for field descriptions.
 */
typedef struct SocketPool_Stats
{
  /* Cumulative counters since creation/reset */
  uint64_t total_added;   /**< Total connections added to pool */
  uint64_t total_removed; /**< Total connections removed from pool */
  uint64_t total_reused;  /**< Total connections reused (returned via get) */
  uint64_t total_health_checks;   /**< Total health checks performed */
  uint64_t total_health_failures; /**< Total health check failures */
  uint64_t
      total_validation_failures; /**< Total validation callback failures */
  uint64_t total_idle_cleanups; /**< Connections removed due to idle timeout */

  /* Current state snapshot */
  size_t current_active;  /**< Current active connection count */
  size_t current_idle;    /**< Current idle connection count (active but not in
                             use) */
  size_t max_connections; /**< Maximum connection capacity */

  /* Calculated metrics (computed at snapshot time) */
  double reuse_rate;             /**< Reuse rate: reused / (added + reused) */
  double avg_connection_age_sec; /**< Average age of active connections
                                    (seconds) */
  double churn_rate_per_sec; /**< Churn rate: (added + removed) / window_sec */
} SocketPool_Stats;

/**
 * @brief Get pool statistics snapshot.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param stats Output statistics structure.
 * @threadsafe Yes.
 *
 * Fills stats with current pool statistics. Calculated metrics
 * (reuse_rate, avg_connection_age, churn_rate) are computed at call time.
 *
 * @see SocketPool_Stats for statistics structure.
 * @see SocketPool_reset_stats() for resetting counters.
 */
extern void SocketPool_get_stats (T pool, SocketPool_Stats *stats);

/**
 * @brief Reset pool statistics counters.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @threadsafe Yes.
 *
 * Resets all cumulative counters to zero and restarts the statistics window.
 * Current state values (active, idle, max) are not affected.
 *
 * @see SocketPool_get_stats() for reading statistics.
 */
extern void SocketPool_reset_stats (T pool);

/**
 * @brief Get count of currently idle connections.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return Number of idle connections (active but not currently in use).
 * @threadsafe Yes - atomic read.
 * @complexity O(1).
 *
 * Convenience wrapper around SocketPool_get_stats().current_idle.
 *
 * @see SocketPool_get_active_count() for active connections.
 * @see SocketPool_get_stats() for full statistics.
 */
extern size_t SocketPool_get_idle_count (T pool);

/**
 * @brief Get count of currently active connections.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return Number of active connections in the pool.
 * @threadsafe Yes - atomic read.
 * @complexity O(1).
 *
 * Convenience wrapper around SocketPool_get_stats().current_active.
 *
 * @see SocketPool_get_idle_count() for idle connections.
 * @see SocketPool_count() for same functionality (alias).
 * @see SocketPool_get_stats() for full statistics.
 */
extern size_t SocketPool_get_active_count (T pool);

/**
 * @brief Get connection reuse rate (hit rate).
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return Reuse rate as fraction (0.0 to 1.0), or 0.0 if no connections.
 * @threadsafe Yes.
 * @complexity O(1).
 *
 * Returns the ratio of reused connections to total connection acquisitions.
 * Higher values indicate better pool efficiency. Calculated as:
 *   reused / (added + reused)
 *
 * ## Example
 *
 * @code{.c}
 * double hit_rate = SocketPool_get_hit_rate(pool);
 * printf("Connection reuse: %.1f%%\n", hit_rate * 100.0);
 * @endcode
 *
 * @see SocketPool_get_stats() for full statistics.
 * @see SocketPool_reset_stats() to start fresh measurement window.
 */
extern double SocketPool_get_hit_rate (T pool);

/**
 * @brief Release unused pool capacity.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @return Number of connection slots released.
 * @threadsafe Yes.
 *
 * Shrinks the pool by releasing unused (free) connection slots, reducing
 * memory footprint. Only affects slots that have never been used or have
 * been freed. Does not affect currently active connections.
 *
 * ## Example
 *
 * @code{.c}
 * // After peak traffic subsides, reclaim unused memory
 * size_t released = SocketPool_shrink(pool);
 * printf("Released %zu unused slots\n", released);
 * @endcode
 *
 * @note Does not reduce maxconns - pool can still grow back to original size.
 * @note Memory is not immediately returned to OS; managed by arena.
 *
 * @see SocketPool_resize() for changing pool capacity.
 * @see SocketPool_prewarm() for pre-allocating capacity.
 */
extern size_t SocketPool_shrink (T pool);

/**
 * @brief Register callback for when connections become idle.
 * @ingroup connection_mgmt
 * @param[in] pool Pool instance.
 * @param cb Callback function (NULL to clear).
 * @param[in] data User data passed to callback.
 * @threadsafe Yes.
 *
 * The callback is invoked when a connection transitions to idle state.
 * Useful for monitoring, logging, or cleaning up per-connection resources.
 *
 * ## Example
 *
 * @code{.c}
 * void on_idle(Connection_T conn, void *data) {
 *     Socket_T sock = Connection_socket(conn);
 *     printf("Connection from %s went idle\n", Socket_getpeeraddr(sock));
 * }
 *
 * SocketPool_set_idle_callback(pool, on_idle, NULL);
 * @endcode
 *
 * @see SocketPool_IdleCallback for callback requirements.
 * @see SocketPool_set_idle_timeout() for automatic idle cleanup.
 */
extern void SocketPool_set_idle_callback (T pool, SocketPool_IdleCallback cb,
                                          void *data);

/**
 * @brief Get connection creation timestamp.
 * @ingroup connection_mgmt
 * @param[in] conn Connection instance.
 * @return Creation timestamp as time_t.
 * @threadsafe Yes.
 * @see Connection_lastactivity() for last activity time.
 */
extern time_t Connection_created_at (const Connection_T conn);

/* ============================================================================
 * Health Checking API
 * ============================================================================ */

/* Full API documentation in SocketPoolHealth.h */
#include "pool/SocketPoolHealth.h"

#undef T

/** @} */ /* end of connection_mgmt group */

#endif
