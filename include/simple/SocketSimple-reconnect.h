/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_RECONNECT_INCLUDED
#define SOCKETSIMPLE_RECONNECT_INCLUDED

/**
 * @file SocketSimple-reconnect.h
 * @brief Automatic reconnection with exponential backoff and circuit breaker.
 *
 * Provides resilient TCP connections that automatically reconnect on failure
 * with configurable retry policies and circuit breaker protection.
 *
 * ## Quick Start
 *
 * ```c
 * #include <simple/SocketSimple.h>
 *
 * // Create reconnecting connection
 * SocketSimple_Reconnect_T conn = Socket_simple_reconnect_new(
 *     "database.example.com", 5432, NULL);
 *
 * // Connect (will auto-reconnect on failure)
 * if (Socket_simple_reconnect_connect(conn) < 0) {
 *     fprintf(stderr, "Initial connect failed\n");
 * }
 *
 * // Use passthrough I/O (auto-reconnects on error)
 * const char *query = "SELECT 1";
 * ssize_t n = Socket_simple_reconnect_send(conn, query, strlen(query));
 *
 * // Event loop integration
 * while (running) {
 *     int timeout = Socket_simple_reconnect_next_timeout(conn);
 *     // ... poll for events with timeout ...
 *     Socket_simple_reconnect_tick(conn);
 * }
 *
 * Socket_simple_reconnect_free(&conn);
 * ```
 */

#include "SocketSimple-tcp.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Opaque Handle Type
 *============================================================================*/

/**
 * @brief Opaque reconnecting connection handle.
 */
typedef struct SocketSimple_Reconnect *SocketSimple_Reconnect_T;

/*============================================================================
 * Connection States
 *============================================================================*/

/**
 * @brief Reconnection state machine states.
 */
typedef enum {
    SIMPLE_RECONNECT_DISCONNECTED = 0, /**< Not connected */
    SIMPLE_RECONNECT_CONNECTING,       /**< Connection in progress */
    SIMPLE_RECONNECT_CONNECTED,        /**< Successfully connected */
    SIMPLE_RECONNECT_BACKOFF,          /**< Waiting before retry */
    SIMPLE_RECONNECT_CIRCUIT_OPEN      /**< Circuit breaker open */
} SocketSimple_Reconnect_State;

/*============================================================================
 * Policy Configuration
 *============================================================================*/

/**
 * @brief Reconnection policy configuration.
 */
typedef struct SocketSimple_Reconnect_Policy {
    /* Exponential backoff */
    int initial_delay_ms;     /**< First retry delay (default: 100) */
    int max_delay_ms;         /**< Maximum retry delay (default: 30000) */
    double multiplier;        /**< Backoff multiplier (default: 2.0) */
    double jitter;            /**< Jitter factor 0.0-1.0 (default: 0.25) */
    int max_attempts;         /**< Max attempts, 0=unlimited (default: 10) */

    /* Circuit breaker */
    int circuit_threshold;    /**< Failures to open circuit (default: 5) */
    int circuit_reset_ms;     /**< Time before circuit probe (default: 60000) */

    /* Health checking */
    int health_interval_ms;   /**< Health check interval (default: 30000) */
    int health_timeout_ms;    /**< Health check timeout (default: 5000) */
} SocketSimple_Reconnect_Policy;

/*============================================================================
 * Callbacks
 *============================================================================*/

/**
 * @brief State change callback.
 *
 * @param conn Reconnection handle.
 * @param old_state Previous state.
 * @param new_state New state.
 * @param userdata User data from creation.
 */
typedef void (*SocketSimple_Reconnect_Callback)(
    SocketSimple_Reconnect_T conn,
    SocketSimple_Reconnect_State old_state,
    SocketSimple_Reconnect_State new_state,
    void *userdata);

/**
 * @brief Custom health check callback.
 *
 * @param conn Reconnection handle.
 * @param sock Underlying socket to check.
 * @param timeout_ms Maximum time for check.
 * @param userdata User data.
 * @return 1 if healthy, 0 if unhealthy.
 */
typedef int (*SocketSimple_Reconnect_HealthCheck)(
    SocketSimple_Reconnect_T conn,
    SocketSimple_Socket_T sock,
    int timeout_ms,
    void *userdata);

/*============================================================================
 * Lifecycle Functions
 *============================================================================*/

/**
 * @brief Create a reconnecting connection.
 *
 * @param host Target hostname.
 * @param port Target port.
 * @param policy Custom policy (NULL for defaults).
 * @return Handle on success, NULL on error.
 */
extern SocketSimple_Reconnect_T Socket_simple_reconnect_new(
    const char *host,
    int port,
    const SocketSimple_Reconnect_Policy *policy);

/**
 * @brief Free a reconnection handle.
 *
 * @param conn Pointer to handle (set to NULL after freeing).
 */
extern void Socket_simple_reconnect_free(SocketSimple_Reconnect_T *conn);

/**
 * @brief Initialize policy with default values.
 *
 * @param policy Policy structure to initialize.
 */
extern void Socket_simple_reconnect_policy_defaults(
    SocketSimple_Reconnect_Policy *policy);

/*============================================================================
 * Connection Control
 *============================================================================*/

/**
 * @brief Start connection (or queue retry if in backoff).
 *
 * @param conn Reconnection handle.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_reconnect_connect(SocketSimple_Reconnect_T conn);

/**
 * @brief Disconnect gracefully (no auto-reconnect).
 *
 * @param conn Reconnection handle.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_reconnect_disconnect(SocketSimple_Reconnect_T conn);

/**
 * @brief Reset state machine and statistics.
 *
 * @param conn Reconnection handle.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_reconnect_reset(SocketSimple_Reconnect_T conn);

/*============================================================================
 * State Query
 *============================================================================*/

/**
 * @brief Get current connection state.
 *
 * @param conn Reconnection handle.
 * @return Current state.
 */
extern SocketSimple_Reconnect_State Socket_simple_reconnect_state(
    SocketSimple_Reconnect_T conn);

/**
 * @brief Get state name for logging.
 *
 * @param state State value.
 * @return Static string name.
 */
extern const char *Socket_simple_reconnect_state_name(
    SocketSimple_Reconnect_State state);

/**
 * @brief Check if currently connected.
 *
 * @param conn Reconnection handle.
 * @return 1 if connected, 0 otherwise.
 */
extern int Socket_simple_reconnect_is_connected(SocketSimple_Reconnect_T conn);

/**
 * @brief Get number of connection attempts.
 *
 * @param conn Reconnection handle.
 * @return Attempt count.
 */
extern int Socket_simple_reconnect_attempts(SocketSimple_Reconnect_T conn);

/**
 * @brief Get consecutive failure count.
 *
 * @param conn Reconnection handle.
 * @return Failure count.
 */
extern int Socket_simple_reconnect_failures(SocketSimple_Reconnect_T conn);

/*============================================================================
 * Event Loop Integration
 *============================================================================*/

/**
 * @brief Get file descriptor for polling.
 *
 * @param conn Reconnection handle.
 * @return FD if connected/connecting, -1 otherwise.
 */
extern int Socket_simple_reconnect_fd(SocketSimple_Reconnect_T conn);

/**
 * @brief Get timeout until next event.
 *
 * Use as timeout for poll/select.
 *
 * @param conn Reconnection handle.
 * @return Milliseconds until next event, -1 if none.
 */
extern int Socket_simple_reconnect_next_timeout(SocketSimple_Reconnect_T conn);

/**
 * @brief Process timers and state transitions.
 *
 * Call periodically in event loop.
 *
 * @param conn Reconnection handle.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_reconnect_tick(SocketSimple_Reconnect_T conn);

/**
 * @brief Process I/O events.
 *
 * Call when fd becomes readable/writable.
 *
 * @param conn Reconnection handle.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_reconnect_process(SocketSimple_Reconnect_T conn);

/*============================================================================
 * Passthrough I/O (Auto-reconnect on error)
 *============================================================================*/

/**
 * @brief Send data with auto-reconnect on error.
 *
 * @param conn Reconnection handle.
 * @param data Data to send.
 * @param len Data length.
 * @return Bytes sent, 0 if not connected, -1 on error.
 */
extern ssize_t Socket_simple_reconnect_send(SocketSimple_Reconnect_T conn,
                                             const void *data,
                                             size_t len);

/**
 * @brief Receive data with auto-reconnect on error.
 *
 * @param conn Reconnection handle.
 * @param buf Receive buffer.
 * @param len Buffer size.
 * @return Bytes received, 0 on disconnect/not connected, -1 on error.
 */
extern ssize_t Socket_simple_reconnect_recv(SocketSimple_Reconnect_T conn,
                                             void *buf,
                                             size_t len);

/*============================================================================
 * Configuration
 *============================================================================*/

/**
 * @brief Set state change callback.
 *
 * @param conn Reconnection handle.
 * @param callback Callback function (NULL to disable).
 * @param userdata User data passed to callback.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_reconnect_set_callback(
    SocketSimple_Reconnect_T conn,
    SocketSimple_Reconnect_Callback callback,
    void *userdata);

/**
 * @brief Set custom health check.
 *
 * @param conn Reconnection handle.
 * @param check Health check function (NULL for default).
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_reconnect_set_health_check(
    SocketSimple_Reconnect_T conn,
    SocketSimple_Reconnect_HealthCheck check);

/*============================================================================
 * Underlying Socket Access
 *============================================================================*/

/**
 * @brief Get underlying socket when connected.
 *
 * @param conn Reconnection handle.
 * @return Socket handle if connected, NULL otherwise.
 *
 * @note Do not close the returned socket directly.
 */
extern SocketSimple_Socket_T Socket_simple_reconnect_get_socket(
    SocketSimple_Reconnect_T conn);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_RECONNECT_INCLUDED */
