/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketReconnect.h
 * @ingroup connection_mgmt
 * @brief Automatic reconnection with exponential backoff and circuit breaker.
 *
 * Provides resilient TCP connections with:
 * - Exponential backoff with jitter
 * - Circuit breaker pattern
 * - Periodic health checks
 * - Event loop integration
 * - Transparent send/recv with auto-reconnect
 *
 * Thread safety: Instances are NOT thread-safe. Use one per thread.
 *
 * @see SocketReconnect_new() for creation
 * @see docs/RECONNECT.md for configuration guide
 */

#ifndef SOCKETRECONNECT_INCLUDED
#define SOCKETRECONNECT_INCLUDED

#include "core/Except.h"
#include "socket/Socket.h"
#include <stddef.h>
#include <sys/types.h>

#define T SocketReconnect_T

/**
 * @brief Opaque handle for a reconnecting socket connection.
 * @ingroup connection_mgmt
 */
typedef struct T *T;

/**
 * @brief Exception for reconnection module errors.
 * @ingroup connection_mgmt
 */
extern const Except_T SocketReconnect_Failed;

/* ============================================================================
 * Reconnection State
 * ============================================================================
 */

/**
 * @brief Reconnection state machine states.
 * @ingroup connection_mgmt
 */
typedef enum
{
  RECONNECT_DISCONNECTED = 0, /**< Not connected, not attempting */
  RECONNECT_CONNECTING,       /**< Connection attempt in progress */
  RECONNECT_CONNECTED,        /**< Successfully connected */
  RECONNECT_BACKOFF,          /**< Waiting before retry */
  RECONNECT_CIRCUIT_OPEN      /**< Circuit breaker open */
} SocketReconnect_State;

/* ============================================================================
 * Backoff Policy Configuration
 * ============================================================================
 */

/**
 * @brief Backoff policy and circuit breaker configuration.
 * @ingroup connection_mgmt
 *
 * Use SocketReconnect_policy_defaults() to initialize with safe defaults.
 */
typedef struct SocketReconnect_Policy
{
  /* Exponential backoff settings */
  int initial_delay_ms; /**< First retry delay (default: 100ms) */
  int max_delay_ms;     /**< Maximum delay cap (default: 30000ms) */
  double multiplier;    /**< Backoff multiplier (default: 2.0, must be >1.0) */
  double jitter;        /**< Randomization factor 0.0-1.0 (default: 0.25) */
  int max_attempts;     /**< Max retries, 0=unlimited (default: 10) */

  /* Circuit breaker settings */
  int circuit_failure_threshold; /**< Failures to open circuit (default: 5) */
  int circuit_reset_timeout_ms;  /**< Cooldown before probe (default: 60000ms) */

  /* Health monitoring settings */
  int health_check_interval_ms; /**< Check interval, 0=disabled (default: 30000ms) */
  int health_check_timeout_ms;  /**< Check timeout (default: 5000ms) */
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

/* Minimum validation thresholds */
#ifndef SOCKET_RECONNECT_MIN_CIRCUIT_RESET_MS
#define SOCKET_RECONNECT_MIN_CIRCUIT_RESET_MS 1000
#endif

#ifndef SOCKET_RECONNECT_MIN_HEALTH_TIMEOUT_MS
#define SOCKET_RECONNECT_MIN_HEALTH_TIMEOUT_MS 100
#endif

/* ============================================================================
 * Event Callbacks
 * ============================================================================
 */

/**
 * @brief State transition callback.
 * @ingroup connection_mgmt
 * @param conn Reconnection instance
 * @param old_state Previous state
 * @param new_state New state
 * @param userdata User data from creation
 *
 * @warning Do not call free() or connect() from within callback.
 */
typedef void (*SocketReconnect_Callback) (T conn,
                                          SocketReconnect_State old_state,
                                          SocketReconnect_State new_state,
                                          void *userdata);

/**
 * @brief Custom health check callback.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @param socket Connected socket to test
 * @param timeout_ms Maximum time to block
 * @param userdata User data
 * @return 1 if healthy, 0 if unhealthy (triggers BACKOFF)
 */
typedef int (*SocketReconnect_HealthCheck) (T conn, Socket_T socket,
                                            int timeout_ms, void *userdata);

/* ============================================================================
 * Context Creation and Destruction
 * ============================================================================
 */

/**
 * @brief Create reconnection context for a host:port endpoint.
 * @ingroup connection_mgmt
 * @param host Target hostname or IP address
 * @param port Target port (1-65535)
 * @param policy Optional policy (NULL for defaults)
 * @param callback Optional state change callback
 * @param userdata User data for callbacks
 * @return New handle in DISCONNECTED state
 * @throws SocketReconnect_Failed on invalid parameters or allocation failure
 */
extern T SocketReconnect_new (const char *host, int port,
                              const SocketReconnect_Policy_T *policy,
                              SocketReconnect_Callback callback,
                              void *userdata);

/**
 * @brief Destroy reconnection context and release resources.
 * @ingroup connection_mgmt
 * @param conn Pointer to handle (set to NULL after cleanup)
 */
extern void SocketReconnect_free (T *conn);

/* ============================================================================
 * Connection Control
 * ============================================================================
 */

/**
 * @brief Initiate connection attempt.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 *
 * Transitions DISCONNECTED -> CONNECTING. No-op if already connecting/connected.
 * Ignored if CIRCUIT_OPEN until reset timeout elapses.
 */
extern void SocketReconnect_connect (T conn);

/**
 * @brief Gracefully disconnect without triggering reconnect.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 */
extern void SocketReconnect_disconnect (T conn);

/**
 * @brief Reset statistics and circuit breaker state.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 */
extern void SocketReconnect_reset (T conn);

/* ============================================================================
 * Socket Access
 * ============================================================================
 */

/**
 * @brief Get underlying socket when connected.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @return Connected socket, or NULL if not connected
 * @warning Do not close or free the returned socket directly.
 */
extern Socket_T SocketReconnect_socket (T conn);

/* ============================================================================
 * State Query
 * ============================================================================
 */

/**
 * @brief Get current state.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @return Current state
 */
extern SocketReconnect_State SocketReconnect_state (T conn);

/**
 * @brief Check if currently connected.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @return 1 if connected, 0 otherwise
 */
extern int SocketReconnect_isconnected (T conn);

/**
 * @brief Get connection attempt count since last success/reset.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @return Number of attempts
 */
extern int SocketReconnect_attempts (T conn);

/**
 * @brief Get consecutive failure count.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @return Number of consecutive failures
 */
extern int SocketReconnect_failures (T conn);

/* ============================================================================
 * Event Loop Integration
 * ============================================================================
 */

/**
 * @brief Get file descriptor for polling.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @return Valid FD (>=0) during CONNECTING/CONNECTED, -1 otherwise
 */
extern int SocketReconnect_pollfd (T conn);

/**
 * @brief Process I/O events.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 *
 * Call when pollfd() becomes readable/writable.
 */
extern void SocketReconnect_process (T conn);

/**
 * @brief Get milliseconds until next timer event.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @return Milliseconds until next timeout, or -1 if none pending
 */
extern int SocketReconnect_next_timeout_ms (T conn);

/**
 * @brief Advance timers and perform periodic maintenance.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 *
 * Call periodically or after poll timeout. Handles backoff timers,
 * circuit reset, and health checks.
 */
extern void SocketReconnect_tick (T conn);

/* ============================================================================
 * Health Check Configuration
 * ============================================================================
 */

/**
 * @brief Register custom health check callback.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @param check Custom check function (NULL for default)
 */
extern void
SocketReconnect_set_health_check (T conn, SocketReconnect_HealthCheck check);

/* ============================================================================
 * Policy Helpers
 * ============================================================================
 */

/**
 * @brief Initialize policy with production-safe defaults.
 * @ingroup connection_mgmt
 * @param policy Policy structure to initialize
 */
extern void SocketReconnect_policy_defaults (SocketReconnect_Policy_T *policy);

/* ============================================================================
 * I/O Passthrough (Auto-Reconnect on Error)
 * ============================================================================
 */

/**
 * @brief Send data with automatic reconnect on error.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @param buf Data to send
 * @param len Length in bytes
 * @return Bytes sent (>0), 0 if not connected, -1 on error
 */
extern ssize_t SocketReconnect_send (T conn, const void *buf, size_t len);

/**
 * @brief Receive data with automatic reconnect on disconnect.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @param buf Buffer to receive into
 * @param len Buffer size
 * @return Bytes received (>0), 0 on EOF/disconnect, -1 on error
 */
extern ssize_t SocketReconnect_recv (T conn, void *buf, size_t len);

/* ============================================================================
 * State Names (for logging/debugging)
 * ============================================================================
 */

/**
 * @brief Get human-readable state name.
 * @ingroup connection_mgmt
 * @param state State enum value
 * @return Static string
 */
extern const char *SocketReconnect_state_name (SocketReconnect_State state);

/* ============================================================================
 * TLS Integration (Conditional)
 * ============================================================================
 */

#if SOCKET_HAS_TLS
#undef T
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"
#define T SocketReconnect_T

/**
 * @brief Configure TLS for reconnecting connections.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @param ctx TLS context (caller retains ownership)
 * @param hostname SNI hostname for verification
 * @throws SocketReconnect_Failed if hostname is NULL or too long
 */
extern void SocketReconnect_set_tls (T conn, SocketTLSContext_T ctx,
                                     const char *hostname);

/**
 * @brief Disable TLS for future connections.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 */
extern void SocketReconnect_disable_tls (T conn);

/**
 * @brief Check if TLS is configured.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @return 1 if TLS configured, 0 otherwise
 */
extern int SocketReconnect_tls_enabled (T conn);

/**
 * @brief Get configured TLS hostname.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @return SNI hostname or NULL if TLS not configured
 */
extern const char *SocketReconnect_get_tls_hostname (T conn);

/**
 * @brief Get TLS handshake state.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @return Current handshake state
 */
extern TLSHandshakeState SocketReconnect_tls_handshake_state (T conn);

/**
 * @brief Enable/disable TLS session resumption.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @param enable 1 to enable, 0 to disable
 */
extern void SocketReconnect_set_session_resumption (T conn, int enable);

/**
 * @brief Check if last connection used session resumption.
 * @ingroup connection_mgmt
 * @param conn Reconnection context
 * @return 1 if resumed, 0 if full handshake, -1 if not connected
 */
extern int SocketReconnect_is_session_reused (T conn);

#endif /* SOCKET_HAS_TLS */

#undef T
#endif /* SOCKETRECONNECT_INCLUDED */
