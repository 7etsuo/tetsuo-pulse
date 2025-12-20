/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETPOOLHEALTH_INCLUDED
#define SOCKETPOOLHEALTH_INCLUDED

#include "core/SocketConfig.h"
#include <stdint.h>

/**
 * @file SocketPoolHealth.h
 * @brief Active health checking and circuit breaker for connection pools.
 * @ingroup connection_mgmt
 *
 * Provides production-grade resilience patterns for SocketPool:
 * - **Per-host Circuit Breaker**: Tracks failures per host:port endpoint,
 *   automatically blocking connections to unhealthy backends.
 * - **Background Health Probes**: Periodically validates idle connections
 *   without blocking pool operations.
 * - **Custom Health Callbacks**: Application-defined probe logic executed
 *   from the background thread.
 *
 * Circuit Breaker State Machine:
 * @code
 *                      failures >= threshold
 *     [CLOSED] ─────────────────────────────────> [OPEN]
 *         ^                                          │
 *         │                                          │ reset_timeout
 *         │ probe success                            │ elapsed
 *         │                                          v
 *         └────────────────────────────────── [HALF_OPEN]
 *                                                    │
 *                                                    │ probe failure
 *                                                    └──────> back to [OPEN]
 * @endcode
 *
 * Usage Example:
 * @code
 * // Configure health checking
 * SocketPoolHealth_Config config;
 * SocketPoolHealth_config_defaults(&config);
 * config.failure_threshold = 3;
 * config.probe_interval_ms = 5000;
 *
 * // Enable on existing pool
 * SocketPool_enable_health_checks(pool, &config);
 *
 * // Optional: custom probe callback
 * SocketPool_set_health_callback(pool, my_probe_func, user_data);
 *
 * // Check before connecting
 * if (SocketPool_circuit_allows(pool, "api.example.com", 443)) {
 *     // Safe to connect
 * }
 *
 * // Report connection outcomes
 * if (connection_succeeded)
 *     SocketPool_circuit_report_success(pool, host, port);
 * else
 *     SocketPool_circuit_report_failure(pool, host, port);
 *
 * // Cleanup happens automatically in SocketPool_free()
 * @endcode
 *
 * Thread Safety:
 * - All functions are thread-safe.
 * - Circuit state reads use lock-free atomics for fast path.
 * - Health probe callback is invoked WITHOUT pool mutex for blocking probes.
 *
 * Memory Management:
 * - Health subsystem uses pool's arena for allocations.
 * - No explicit cleanup required (handled by SocketPool_free()).
 *
 * @see SocketPool_T for connection pool.
 * @see SocketReconnect_T for per-connection circuit breaker.
 */

/* Forward declaration - full definition in SocketPool.h */
#ifndef T
#define T SocketPool_T
typedef struct T *T;
#undef T
#endif

/* Forward declaration for connection handle */
typedef struct Connection *Connection_T;

/**
 * @brief Circuit breaker states for per-host tracking.
 * @ingroup connection_mgmt
 *
 * The circuit breaker uses a three-state model:
 * - CLOSED: Normal operation, connections allowed.
 * - OPEN: Backend is unhealthy, connections blocked.
 * - HALF_OPEN: Testing recovery, limited probe connections allowed.
 */
typedef enum {
    /**
     * @brief Normal state - connections allowed.
     *
     * The circuit is healthy. All connection attempts proceed normally.
     * Transitions to OPEN when consecutive failures reach threshold.
     */
    POOL_CIRCUIT_CLOSED = 0,

    /**
     * @brief Blocked state - connections rejected.
     *
     * Too many consecutive failures detected. All connection attempts
     * are immediately rejected without attempting connection.
     * Transitions to HALF_OPEN after reset_timeout_ms elapses.
     */
    POOL_CIRCUIT_OPEN = 1,

    /**
     * @brief Probe state - limited connections for testing recovery.
     *
     * Testing if backend has recovered. A limited number of probe
     * connections are allowed (half_open_max_probes).
     * - Success: transitions to CLOSED.
     * - Failure: transitions back to OPEN.
     */
    POOL_CIRCUIT_HALF_OPEN = 2
} SocketPoolCircuit_State;

/**
 * @brief Configuration for health checking subsystem.
 * @ingroup connection_mgmt
 *
 * All timing values are in milliseconds. Use SocketPoolHealth_config_defaults()
 * to initialize with sensible production defaults before customizing.
 *
 * @see SocketPoolHealth_config_defaults() for default values.
 * @see SocketPool_enable_health_checks() for enabling.
 */
typedef struct SocketPoolHealth_Config {
    /**
     * @brief Consecutive failures to open circuit.
     *
     * Number of consecutive connection failures before circuit transitions
     * from CLOSED to OPEN. Must be >= 1.
     * Default: SOCKET_HEALTH_DEFAULT_FAILURE_THRESHOLD (5)
     */
    int failure_threshold;

    /**
     * @brief Delay before OPEN -> HALF_OPEN transition (ms).
     *
     * Time to wait in OPEN state before attempting recovery probes.
     * Longer values reduce load on failing backends.
     * Default: SOCKET_HEALTH_DEFAULT_RESET_TIMEOUT_MS (30000)
     */
    int reset_timeout_ms;

    /**
     * @brief Max probe attempts in HALF_OPEN state.
     *
     * Maximum concurrent probe connections allowed while in HALF_OPEN.
     * Prevents thundering herd when backend recovers.
     * Default: SOCKET_HEALTH_DEFAULT_HALF_OPEN_MAX_PROBES (3)
     */
    int half_open_max_probes;

    /**
     * @brief Background probe interval (ms).
     *
     * How often the health worker thread runs a probe cycle.
     * Lower values detect failures faster but increase overhead.
     * Default: SOCKET_HEALTH_DEFAULT_PROBE_INTERVAL_MS (10000)
     */
    int probe_interval_ms;

    /**
     * @brief Per-probe timeout (ms).
     *
     * Maximum time to wait for a single probe operation to complete.
     * Passed to the health probe callback.
     * Default: SOCKET_HEALTH_DEFAULT_PROBE_TIMEOUT_MS (5000)
     */
    int probe_timeout_ms;

    /**
     * @brief Connections to probe per cycle.
     *
     * Maximum number of connections to probe in each background cycle.
     * Limits CPU/network impact per cycle.
     * Default: SOCKET_HEALTH_DEFAULT_PROBES_PER_CYCLE (10)
     */
    int probes_per_cycle;
} SocketPoolHealth_Config;

/**
 * @brief Health probe callback type.
 * @ingroup connection_mgmt
 *
 * Application-defined function to check if a connection is healthy.
 * Called from the background health worker thread WITHOUT pool mutex.
 *
 * @param pool       The connection pool (read-only).
 * @param conn       Connection to probe (do not modify pool state).
 * @param timeout_ms Maximum time for probe operation.
 * @param data       User data from SocketPool_set_health_callback().
 *
 * @return Non-zero if connection is healthy, 0 if unhealthy.
 *
 * Thread Safety Requirements:
 * - Callback is invoked from background thread, NOT main thread.
 * - Pool mutex is NOT held - safe to perform blocking I/O.
 * - MUST NOT call SocketPool_add/remove/get (undefined behavior).
 * - MUST NOT modify connection state directly.
 * - MAY read connection info via Connection_* accessors.
 * - MAY perform blocking network operations (up to timeout_ms).
 *
 * Implementation Guidelines:
 * - Use poll/select with timeout for socket operations.
 * - Check for graceful close (recv returns 0).
 * - Send application-level ping if protocol supports it.
 * - Return 0 on any error or timeout to mark unhealthy.
 *
 * Example:
 * @code
 * int my_probe(SocketPool_T pool, Connection_T conn,
 *              int timeout_ms, void *data) {
 *     int fd = Connection_socket(conn);
 *     struct pollfd pfd = {fd, POLLIN, 0};
 *
 *     // Check for readable data or errors
 *     int ret = poll(&pfd, 1, timeout_ms);
 *     if (ret < 0) return 0;  // Error
 *     if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
 *         return 0;  // Connection broken
 *
 *     return 1;  // Healthy
 * }
 * @endcode
 *
 * @see SocketPool_set_health_callback() for registration.
 */
typedef int (*SocketPool_HealthProbeCallback)(
    struct SocketPool_T *pool,
    Connection_T conn,
    int timeout_ms,
    void *data
);

/**
 * @brief Initialize configuration with production defaults.
 * @ingroup connection_mgmt
 *
 * Sets all configuration fields to sensible defaults:
 * - failure_threshold: 5
 * - reset_timeout_ms: 30000 (30 seconds)
 * - half_open_max_probes: 3
 * - probe_interval_ms: 10000 (10 seconds)
 * - probe_timeout_ms: 5000 (5 seconds)
 * - probes_per_cycle: 10
 *
 * @param[out] config Configuration to initialize.
 *
 * @pre config != NULL
 *
 * Example:
 * @code
 * SocketPoolHealth_Config config;
 * SocketPoolHealth_config_defaults(&config);
 * config.failure_threshold = 3;  // More aggressive
 * @endcode
 */
void SocketPoolHealth_config_defaults(SocketPoolHealth_Config *config);

/**
 * @brief Enable health checking on a pool.
 * @ingroup connection_mgmt
 *
 * Initializes the health subsystem with circuit breaker and starts
 * the background probe thread. Safe to call multiple times (subsequent
 * calls update configuration).
 *
 * @param pool   Connection pool.
 * @param config Health configuration (copied, caller may free).
 *
 * @return 0 on success, -1 on failure.
 *
 * @exception Memory_Failed   Arena allocation failed.
 * @exception Thread_Failed   Could not start worker thread.
 *
 * Thread Safety: Thread-safe. Acquires pool mutex.
 *
 * @pre pool != NULL
 * @pre config != NULL
 * @pre config->failure_threshold >= 1
 * @pre config->reset_timeout_ms >= 0
 * @pre config->probe_interval_ms >= 100
 *
 * @see SocketPool_disable_health_checks() for cleanup.
 * @see SocketPoolHealth_config_defaults() for defaults.
 */
int SocketPool_enable_health_checks(
    struct SocketPool_T *pool,
    const SocketPoolHealth_Config *config
);

/**
 * @brief Disable health checking and stop background thread.
 * @ingroup connection_mgmt
 *
 * Gracefully shuts down the health subsystem:
 * 1. Signals background thread to stop.
 * 2. Waits for current probe cycle to complete.
 * 3. Joins worker thread.
 * 4. Clears circuit breaker state.
 *
 * Safe to call if health checks were never enabled (no-op).
 * Memory is reclaimed when pool arena is disposed.
 *
 * @param pool Connection pool.
 *
 * Thread Safety: Thread-safe. Acquires pool mutex.
 *
 * @pre pool != NULL
 *
 * @see SocketPool_enable_health_checks() for enabling.
 */
void SocketPool_disable_health_checks(struct SocketPool_T *pool);

/**
 * @brief Set custom health probe callback.
 * @ingroup connection_mgmt
 *
 * Registers an application-defined callback for health probes.
 * The callback is invoked from the background thread for each
 * connection selected for probing.
 *
 * If no callback is set, a default poll-based check is used that
 * detects closed connections but not application-level issues.
 *
 * @param pool     Connection pool.
 * @param callback Probe function (NULL to use default).
 * @param data     User data passed to callback.
 *
 * Thread Safety: Thread-safe. Acquires pool mutex.
 *
 * @pre pool != NULL
 * @pre Health checks must be enabled.
 *
 * @see SocketPool_HealthProbeCallback for callback requirements.
 */
void SocketPool_set_health_callback(
    struct SocketPool_T *pool,
    SocketPool_HealthProbeCallback callback,
    void *data
);

/**
 * @brief Get current circuit state for a host:port.
 * @ingroup connection_mgmt
 *
 * Returns the current circuit breaker state for the specified endpoint.
 * Uses lock-free atomics for fast path - safe to call frequently.
 *
 * @param pool Pool with health checks enabled.
 * @param host Hostname or IP address.
 * @param port Port number.
 *
 * @return Circuit state, or POOL_CIRCUIT_CLOSED if not tracked.
 *
 * Thread Safety: Lock-free. Uses atomic operations.
 *
 * @pre pool != NULL
 * @pre host != NULL
 *
 * @see SocketPool_circuit_allows() for connection gating.
 */
SocketPoolCircuit_State SocketPool_circuit_state(
    struct SocketPool_T *pool,
    const char *host,
    int port
);

/**
 * @brief Check if circuit allows new connections.
 * @ingroup connection_mgmt
 *
 * Fast check to determine if a new connection attempt should proceed.
 * Handles HALF_OPEN probe counting automatically.
 *
 * @param pool Pool with health checks enabled.
 * @param host Hostname or IP address.
 * @param port Port number.
 *
 * @return Non-zero if connection allowed, 0 if blocked.
 *
 * Return values:
 * - 1: CLOSED state, proceed normally.
 * - 1: HALF_OPEN state, probe slot available.
 * - 0: OPEN state, connection blocked.
 * - 0: HALF_OPEN state, max probes reached.
 * - 1: Health checks not enabled (always allow).
 *
 * Thread Safety: Lock-free read, may acquire mutex for HALF_OPEN.
 *
 * @pre pool != NULL
 * @pre host != NULL
 *
 * Example:
 * @code
 * if (!SocketPool_circuit_allows(pool, host, port)) {
 *     // Fast-fail: backend is known unhealthy
 *     return ECONNREFUSED;
 * }
 * // Proceed with connection attempt
 * @endcode
 *
 * @see SocketPool_circuit_state() for state inspection.
 * @see SocketPool_circuit_report_success() for recording outcomes.
 */
int SocketPool_circuit_allows(
    struct SocketPool_T *pool,
    const char *host,
    int port
);

/**
 * @brief Report successful connection/operation.
 * @ingroup connection_mgmt
 *
 * Call after a successful connection or operation to update circuit state.
 * In HALF_OPEN state, a success transitions the circuit to CLOSED.
 * Resets consecutive failure counter.
 *
 * @param pool Pool with health checks enabled.
 * @param host Hostname or IP address.
 * @param port Port number.
 *
 * Thread Safety: Acquires circuit mutex.
 *
 * @pre pool != NULL
 * @pre host != NULL
 *
 * @see SocketPool_circuit_report_failure() for failure reporting.
 */
void SocketPool_circuit_report_success(
    struct SocketPool_T *pool,
    const char *host,
    int port
);

/**
 * @brief Report failed connection/operation.
 * @ingroup connection_mgmt
 *
 * Call after a connection failure to update circuit state.
 * Increments consecutive failure counter. When threshold is reached,
 * transitions circuit from CLOSED to OPEN.
 *
 * In HALF_OPEN state, a failure transitions back to OPEN.
 *
 * @param pool Pool with health checks enabled.
 * @param host Hostname or IP address.
 * @param port Port number.
 *
 * Thread Safety: Acquires circuit mutex.
 *
 * @pre pool != NULL
 * @pre host != NULL
 *
 * @see SocketPool_circuit_report_success() for success reporting.
 */
void SocketPool_circuit_report_failure(
    struct SocketPool_T *pool,
    const char *host,
    int port
);

/**
 * @brief Manually reset circuit to CLOSED state.
 * @ingroup connection_mgmt
 *
 * Forces circuit back to CLOSED state, clearing failure counters.
 * Use for administrative override or after external recovery verification.
 *
 * @param pool Pool with health checks enabled.
 * @param host Hostname or IP address.
 * @param port Port number.
 *
 * @return 0 on success, -1 if entry not found.
 *
 * Thread Safety: Acquires circuit mutex.
 *
 * @pre pool != NULL
 * @pre host != NULL
 *
 * @see SocketPool_circuit_state() for current state.
 */
int SocketPool_circuit_reset(
    struct SocketPool_T *pool,
    const char *host,
    int port
);

/**
 * @brief Get health subsystem statistics.
 * @ingroup connection_mgmt
 *
 * Returns counters from the health subsystem for monitoring.
 *
 * @param pool           Pool with health checks enabled.
 * @param probes_sent    [out] Total probes executed (may be NULL).
 * @param probes_passed  [out] Probes that succeeded (may be NULL).
 * @param probes_failed  [out] Probes that failed (may be NULL).
 * @param circuits_opened [out] Times circuits transitioned to OPEN (may be NULL).
 *
 * Thread Safety: Uses atomic reads.
 *
 * @pre pool != NULL
 */
void SocketPool_health_stats(
    struct SocketPool_T *pool,
    uint64_t *probes_sent,
    uint64_t *probes_passed,
    uint64_t *probes_failed,
    uint64_t *circuits_opened
);

#endif /* SOCKETPOOLHEALTH_INCLUDED */
