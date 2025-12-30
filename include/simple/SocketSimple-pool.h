/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_POOL_INCLUDED
#define SOCKETSIMPLE_POOL_INCLUDED

/**
 * @file SocketSimple-pool.h
 * @brief Simple connection pool management.
 *
 * Provides connection pooling with rate limiting, per-IP limits,
 * and graceful shutdown support.
 *
 * Example:
 * @code
 * // Create a pool for a server
 * SocketSimple_Pool_T pool = Socket_simple_pool_new(1024);
 * if (!pool) {
 *     fprintf(stderr, "Pool error: %s\n", Socket_simple_error());
 *     return 1;
 * }
 *
 * // Configure rate limiting
 * Socket_simple_pool_set_conn_rate(pool, 100);   // 100 conn/sec max
 * Socket_simple_pool_set_max_per_ip(pool, 10);   // 10 per IP max
 *
 * // Accept with rate limiting
 * SocketSimple_Conn_T conn = Socket_simple_pool_accept_limited(pool, listener);
 * if (conn) {
 *     SocketSimple_Socket_T client = Socket_simple_conn_socket(conn);
 *     // Handle client...
 *     Socket_simple_pool_remove(pool, client);
 * }
 *
 * // Graceful shutdown
 * Socket_simple_pool_drain(pool, 5000);  // 5 second drain
 * Socket_simple_pool_free(&pool);
 * @endcode
 */

#include "SocketSimple-tcp.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Opaque Handle Types
 *============================================================================*/

/**
 * @brief Opaque connection pool handle.
 */
typedef struct SocketSimple_Pool *SocketSimple_Pool_T;

/**
 * @brief Opaque connection handle within a pool.
 */
typedef struct SocketSimple_Conn *SocketSimple_Conn_T;

/*============================================================================
 * Pool State Enum
 *============================================================================*/

/**
 * @brief Pool lifecycle states.
 */
typedef enum {
    SOCKET_SIMPLE_POOL_RUNNING,   /**< Normal operation */
    SOCKET_SIMPLE_POOL_DRAINING,  /**< Graceful shutdown in progress */
    SOCKET_SIMPLE_POOL_STOPPED    /**< Shutdown complete */
} SocketSimple_PoolState;

/*============================================================================
 * Configuration Structures
 *============================================================================*/

/**
 * @brief Pool configuration options.
 */
typedef struct SocketSimple_PoolOptions {
    int max_connections;      /**< Maximum connections (default: 1024) */
    int buffer_size;          /**< Per-connection buffer size (default: 4096) */
    int idle_timeout_ms;      /**< Idle timeout in ms, rounded up to seconds, 0=none (default: 0) */
    int conn_rate_limit;      /**< Max connections/sec, 0=unlimited (default: 0) */
    int max_per_ip;           /**< Max connections per IP, 0=unlimited (default: 0) */
} SocketSimple_PoolOptions;

/**
 * @brief Pool statistics snapshot.
 */
typedef struct SocketSimple_PoolStats {
    int active_connections;   /**< Current active connection count */
    int total_accepted;       /**< Total connections accepted */
    int total_rejected;       /**< Total connections rejected (rate/IP limit) */
    int total_closed;         /**< Total connections closed */
    double hit_rate;          /**< Connection reuse rate (0.0-1.0) */
    uint64_t bytes_in;        /**< Total bytes received */
    uint64_t bytes_out;       /**< Total bytes sent */
} SocketSimple_PoolStats;

/*============================================================================
 * Pool Lifecycle
 *============================================================================*/

/**
 * @brief Initialize pool options with defaults.
 *
 * @param opts Options struct to initialize.
 */
extern void Socket_simple_pool_options_init(SocketSimple_PoolOptions *opts);

/**
 * @brief Create a new connection pool.
 *
 * @param max_connections Maximum number of connections.
 * @return Pool handle on success, NULL on error.
 */
extern SocketSimple_Pool_T Socket_simple_pool_new(int max_connections);

/**
 * @brief Create a new connection pool with options.
 *
 * @param opts Configuration options.
 * @return Pool handle on success, NULL on error.
 */
extern SocketSimple_Pool_T Socket_simple_pool_new_ex(
    const SocketSimple_PoolOptions *opts);

/**
 * @brief Free pool and close all connections.
 *
 * Sets *pool to NULL after freeing.
 *
 * @param pool Pointer to pool handle.
 */
extern void Socket_simple_pool_free(SocketSimple_Pool_T *pool);

/*============================================================================
 * Connection Management
 *============================================================================*/

/**
 * @brief Add an existing socket to the pool.
 *
 * @param pool Pool handle.
 * @param sock Socket to add.
 * @return Connection handle on success, NULL on error.
 */
extern SocketSimple_Conn_T Socket_simple_pool_add(SocketSimple_Pool_T pool,
                                                   SocketSimple_Socket_T sock);

/**
 * @brief Get connection handle for a socket.
 *
 * @param pool Pool handle.
 * @param sock Socket to look up.
 * @return Connection handle, or NULL if not found.
 */
extern SocketSimple_Conn_T Socket_simple_pool_get(SocketSimple_Pool_T pool,
                                                   SocketSimple_Socket_T sock);

/**
 * @brief Remove a socket from the pool.
 *
 * The socket is closed and resources freed.
 *
 * @param pool Pool handle.
 * @param sock Socket to remove.
 * @return 0 on success, -1 if not found.
 */
extern int Socket_simple_pool_remove(SocketSimple_Pool_T pool,
                                      SocketSimple_Socket_T sock);

/**
 * @brief Remove idle connections older than timeout.
 *
 * Note: Milliseconds are rounded up to the nearest second internally
 * (e.g., 1999ms becomes 2s). This ensures connections are not prematurely
 * removed due to truncation.
 *
 * @param pool Pool handle.
 * @param max_idle_ms Maximum idle time in milliseconds.
 * @return Number of connections removed.
 */
extern int Socket_simple_pool_cleanup(SocketSimple_Pool_T pool,
                                       int max_idle_ms);

/*============================================================================
 * Accept with Rate Limiting
 *============================================================================*/

/**
 * @brief Accept a connection and add to pool.
 *
 * @param pool Pool handle.
 * @param listener Listening socket.
 * @return Connection handle on success, NULL on error.
 */
extern SocketSimple_Conn_T Socket_simple_pool_accept(
    SocketSimple_Pool_T pool,
    SocketSimple_Socket_T listener);

/**
 * @brief Accept with rate limiting enforcement.
 *
 * Respects both connection rate and per-IP limits.
 * Returns NULL if limits exceeded (check Socket_simple_code()).
 *
 * @param pool Pool handle.
 * @param listener Listening socket.
 * @return Connection handle on success, NULL on error or limit exceeded.
 */
extern SocketSimple_Conn_T Socket_simple_pool_accept_limited(
    SocketSimple_Pool_T pool,
    SocketSimple_Socket_T listener);

/*============================================================================
 * Rate Limiting Configuration
 *============================================================================*/

/**
 * @brief Set maximum connection rate.
 *
 * @param pool Pool handle.
 * @param conns_per_sec Maximum connections per second, 0 for unlimited.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_pool_set_conn_rate(SocketSimple_Pool_T pool,
                                             int conns_per_sec);

/**
 * @brief Set maximum connections per IP address.
 *
 * @param pool Pool handle.
 * @param max Maximum per IP, 0 for unlimited.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_pool_set_max_per_ip(SocketSimple_Pool_T pool,
                                              int max);

/*============================================================================
 * Graceful Shutdown (Drain)
 *============================================================================*/

/**
 * @brief Initiate graceful shutdown.
 *
 * Stops accepting new connections. Existing connections continue
 * until they close or timeout expires.
 *
 * @param pool Pool handle.
 * @param timeout_ms Maximum time to wait for connections to close.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_pool_drain(SocketSimple_Pool_T pool, int timeout_ms);

/**
 * @brief Check drain progress (non-blocking).
 *
 * @param pool Pool handle.
 * @return 1 if drain complete, 0 if still draining, -1 on error.
 */
extern int Socket_simple_pool_drain_poll(SocketSimple_Pool_T pool);

/**
 * @brief Wait for drain to complete (blocking).
 *
 * @param pool Pool handle.
 * @param timeout_ms Maximum wait time.
 * @return 1 if complete, 0 if timeout, -1 on error.
 */
extern int Socket_simple_pool_drain_wait(SocketSimple_Pool_T pool,
                                          int timeout_ms);

/**
 * @brief Get current pool state.
 *
 * @param pool Pool handle.
 * @return Pool state enum value.
 */
extern SocketSimple_PoolState Socket_simple_pool_state(
    SocketSimple_Pool_T pool);

/*============================================================================
 * Statistics
 *============================================================================*/

/**
 * @brief Get pool statistics snapshot.
 *
 * @param pool Pool handle.
 * @param stats Output: statistics struct.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_pool_get_stats(SocketSimple_Pool_T pool,
                                         SocketSimple_PoolStats *stats);

/**
 * @brief Get current connection count.
 *
 * @param pool Pool handle.
 * @return Active connection count, or -1 on error.
 */
extern int Socket_simple_pool_count(SocketSimple_Pool_T pool);

/**
 * @brief Reset pool statistics.
 *
 * @param pool Pool handle.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_pool_reset_stats(SocketSimple_Pool_T pool);

/*============================================================================
 * Connection Accessors
 *============================================================================*/

/**
 * @brief Get socket from connection handle.
 *
 * @param conn Connection handle.
 * @return Socket handle.
 */
extern SocketSimple_Socket_T Socket_simple_conn_socket(SocketSimple_Conn_T conn);

/**
 * @brief Get user data attached to connection.
 *
 * @param conn Connection handle.
 * @return User data pointer, or NULL if none set.
 */
extern void *Socket_simple_conn_data(SocketSimple_Conn_T conn);

/**
 * @brief Set user data on connection.
 *
 * @param conn Connection handle.
 * @param data User data pointer.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_conn_set_data(SocketSimple_Conn_T conn, void *data);

/**
 * @brief Get connection last activity timestamp.
 *
 * @param conn Connection handle.
 * @return Unix timestamp of last I/O, or 0 on error.
 */
extern uint64_t Socket_simple_conn_last_activity(SocketSimple_Conn_T conn);

/**
 * @brief Check if connection is active.
 *
 * @param conn Connection handle.
 * @return 1 if active, 0 if not.
 */
extern int Socket_simple_conn_is_active(SocketSimple_Conn_T conn);

/**
 * @brief Get peer IP address.
 *
 * @param conn Connection handle.
 * @param buf Output buffer for IP string.
 * @param len Buffer length (at least 46 for IPv6).
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_conn_peer_ip(SocketSimple_Conn_T conn,
                                       char *buf,
                                       size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_POOL_INCLUDED */
