/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketPool-ratelimit.c - Rate Limiting Implementation for SocketPool
 *
 * Part of the Socket Library
 *
 * Implements connection rate limiting and per-IP connection limits:
 * - Connection rate limiting using token bucket algorithm
 * - Per-IP connection limits using hash table tracking
 * - Integration with SocketPool_add() and SocketPool_remove()
 *
 * Thread Safety:
 * - All functions acquire pool mutex for rate limiting operations
 * - Rate limiter and IP tracker have their own internal mutexes
 */

#include "core/SocketSecurity.h"
#include <assert.h>
#include <limits.h>

#include "core/SocketIPTracker.h"
#include "core/SocketRateLimit.h"
#include "pool/SocketPool-private.h"
/* SocketUtil.h included via SocketPool-private.h */

/* SOCKET_LOG_COMPONENT defined in SocketPool-private.h */

#define T SocketPool_T

/* POOL_LOCK/POOL_UNLOCK defined in SocketPool-private.h */

/* Rate limit constants from SocketConfig.h:
 * - SOCKET_POOL_MAX_RATE_PER_SEC
 * - SOCKET_POOL_MAX_BURST_MULTIPLIER
 * - SOCKET_POOL_MAX_CONNECTIONS_PER_IP
 * - SOCKET_POOL_TOKENS_PER_ACCEPT
 */

/* ============================================================================
 * Static Helper Functions - Rate Limit Checks
 * ============================================================================
 */

/**
 * rate_limit_allows - Check if connection rate limit allows operation
 * @pool: Connection pool (mutex must be held)
 *
 * Returns: 1 if rate limit allows, 0 if rate limited
 *
 * Checks if tokens are available without consuming them.
 * Must be called with pool mutex held.
 */
static int
rate_limit_allows (const T pool)
{
  return !pool->conn_limiter
         || SocketRateLimit_available (pool->conn_limiter) > 0;
}

/**
 * ip_limit_allows - Check if per-IP limit allows connection
 * @pool: Connection pool (mutex must be held)
 * @client_ip: Client IP address (may be NULL)
 *
 * Returns: 1 if IP limit allows, 0 if IP limit reached
 *
 * If IP is invalid or tracker disabled, always allows.
 * Must be called with pool mutex held.
 */
static int
ip_limit_allows (const T pool, const char *client_ip)
{
  if (!pool->ip_tracker || !pool_is_valid_ip (client_ip))
    return 1;

  return SocketIPTracker_count (pool->ip_tracker, client_ip)
         < SocketIPTracker_getmax (pool->ip_tracker);
}

/* ============================================================================
 * Static Helper Functions - Component Management
 * ============================================================================
 */

/**
 * pool_disable_component - Safely disable a pool component under lock.
 * @pool: The connection pool instance.
 * @component: Address of the component pointer to nullify (e.g., &pool->conn_limiter).
 *
 * Acquires the pool mutex, sets the referenced component pointer to NULL,
 * and releases the mutex. This helper centralizes the common disable pattern
 * used when configuration parameters indicate disabling a feature (e.g., rate=0).
 *
 * Reduces code duplication in setter functions like SocketPool_setconnrate()
 * and SocketPool_setmaxperip().
 *
 * @threadsafe Yes - mutex protected operation.
 *
 * @note Component destruction is handled lazily during pool cleanup or next
 * reconfiguration. No explicit free() called here.
 * @note Suitable only for arena-allocated components managed by the pool.
 *
 * @see SocketPool-core.c for pool lifecycle management.
 * @see POOL_LOCK/POOL_UNLOCK macros in SocketPool-private.h.
 */
static void
pool_disable_component (T pool, void **component)
{
  POOL_LOCK (pool);
  *component = NULL;
  POOL_UNLOCK (pool);
}

/* ============================================================================
 * Static Helper Functions - Generic IP Tracker Operations
 * ============================================================================
 */

/**
 * locked_ip_op_void - Perform void operation on IP tracker under lock
 * @pool: Connection pool
 * @ip: IP address
 * @op: Operation to perform if tracker exists and IP valid
 *
 * Performs the operation atomically under pool mutex.
 * Skips if IP invalid or no tracker.
 *
 * @threadsafe Yes
 *
 * @see SocketPool_track_ip() for track operation
 * @see SocketPool_release_ip() for release operation
 */
static void
locked_ip_op_void (T pool, const char *ip,
                   void (*op) (SocketIPTracker_T, const char *))
{
  if (!pool_is_valid_ip (ip))
    return;

  POOL_LOCK (pool);
  if (pool->ip_tracker)
    op (pool->ip_tracker, ip);
  POOL_UNLOCK (pool);
}

/**
 * locked_ip_op_int - Perform int-returning operation on IP tracker under lock
 * @pool: Connection pool
 * @ip: IP address
 * @op: Operation to perform if tracker exists and IP valid
 * @no_tracker_retval: Return value if no tracker or invalid IP
 *                     (typically 1 for "success/noop" ops like track,
 *                      0 for query ops like count)
 *
 * Returns: Operation result or no_tracker_retval
 *
 * @threadsafe Yes
 */
static int
locked_ip_op_int (T pool, const char *ip,
                  int (*op) (SocketIPTracker_T, const char *),
                  int no_tracker_retval)
{
  int res;

  if (!pool_is_valid_ip (ip))
    return no_tracker_retval;

  POOL_LOCK (pool);
  res = no_tracker_retval;
  if (pool->ip_tracker)
    res = op (pool->ip_tracker, ip);
  POOL_UNLOCK (pool);

  return res;
}

/* ============================================================================
 * Static Helper Functions - Component Configuration
 * ============================================================================
 */

/**
 * Generic macro for pool component configuration (create or reconfigure).
 * Eliminates code duplication between rate limiter and IP tracker setup.
 *
 * @param POOL Connection pool instance
 * @param FIELD Pool field name (conn_limiter or ip_tracker)
 * @param RECONFIG_CALL Reconfiguration function call
 * @param CREATE_CALL Creation function call (must return new component)
 * @param EXCEPTION Exception type to catch
 *
 * Returns: 1 on success, 0 on failure
 * Thread-safe: Caller must hold pool mutex
 */
#define CONFIGURE_POOL_COMPONENT(POOL, FIELD, RECONFIG_CALL, CREATE_CALL,    \
                                 EXCEPTION)                                   \
  do                                                                          \
    {                                                                         \
      if ((POOL)->FIELD)                                                      \
        {                                                                     \
          RECONFIG_CALL;                                                      \
          return 1;                                                           \
        }                                                                     \
      TRY (POOL)->FIELD = (CREATE_CALL);                                      \
      EXCEPT (EXCEPTION)                                                      \
      return 0;                                                               \
      END_TRY;                                                                \
      return 1;                                                               \
    }                                                                         \
  while (0)

/* ============================================================================
 * Static Helper Functions - Rate Limiter Management
 * ============================================================================
 */

/**
 * configure_rate_limiter - Configure rate limiter (create or reconfigure)
 * @pool: Connection pool (must hold mutex)
 * @rate: Connections per second
 * @burst: Burst capacity
 *
 * Returns: 1 on success, 0 on failure
 */
static int
configure_rate_limiter (T pool, size_t rate, size_t burst)
{
  CONFIGURE_POOL_COMPONENT (
      pool, conn_limiter, SocketRateLimit_configure (pool->conn_limiter, rate, burst),
      SocketRateLimit_new (pool->arena, rate, burst), SocketRateLimit_Failed);
}

/* ============================================================================
 * Static Helper Functions - IP Tracker Management
 * ============================================================================
 */

/**
 * configure_ip_tracker - Configure IP tracker (create or reconfigure)
 * @pool: Connection pool (must hold mutex)
 * @max_conns: Maximum connections per IP
 *
 * Returns: 1 on success, 0 on failure
 */
static int
configure_ip_tracker (T pool, int max_conns)
{
  CONFIGURE_POOL_COMPONENT (
      pool, ip_tracker, SocketIPTracker_setmax (pool->ip_tracker, max_conns),
      SocketIPTracker_new (pool->arena, max_conns), SocketIPTracker_Failed);
}



/* ============================================================================
 * Connection Rate Limiting - Public API
 * ============================================================================
 */

/**
 * @brief Configure the global connection acceptance rate limit for the pool.
 * @ingroup connection_mgmt
 *
 * Applies token bucket rate limiting to incoming connections via SocketPool_accept_limited().
 * Limits the rate of new connections added to the pool to prevent overload from SYN floods
 * or rapid client bursts. Each accepted connection consumes SOCKET_POOL_TOKENS_PER_ACCEPT
 * tokens (typically 1).
 *
 * When conns_per_sec <= 0, rate limiting is disabled by nullifying the internal
 * SocketRateLimit_T instance. Burst capacity allows temporary spikes; defaults to
 * conns_per_sec if unspecified (<=0).
 *
 * Parameter validation enforces security limits: conns_per_sec <= SOCKET_POOL_MAX_RATE_PER_SEC
 * and burst <= rate * SOCKET_POOL_MAX_BURST_MULTIPLIER to avoid excessive memory allocation
 * or DoS vectors.
 *
 * Dynamic reconfiguration is supported; changes take effect immediately for subsequent
 * accepts without disrupting existing connections.
 *
 * @param[in] pool The connection pool to configure.
 * @param[in] conns_per_sec Maximum connections per second (tokens replenished/sec). 0 disables.
 * @param[in] burst Maximum burst tokens (defaults to conns_per_sec if <=0).
 *
 * @throws SocketPool_Failed
 * - Invalid parameters (e.g., conns_per_sec > max allowed, unsafe burst size via SocketSecurity_check_multiply).
 * - Internal allocation failure when creating the rate limiter (Arena_Failed propagated).
 *
 * @threadsafe Yes - acquires pool mutex internally. Concurrent calls are safe and serialized.
 *
 * ## Basic Usage Example
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * SocketPool_T pool = SocketPool_new(arena, 1000, 4096);  // max 1000 conns, 4KB buffers
 *
 * // Limit to 100 new connections per second, burst up to 200
 * SocketPool_setconnrate(pool, 100, 200);
 *
 * // In accept loop:
 * Socket_T client = SocketPool_accept_limited(pool, server);
 * if (client) {
 *     // Add to pool or handle...
 * }
 *
 * // Disable limiting (unlimited, subject to maxconns)
 * SocketPool_setconnrate(pool, 0, 0);
 *
 * int current = SocketPool_getconnrate(pool);  // 0 if disabled
 * @endcode
 *
 * ## Advanced Configuration
 *
 * Combine with per-IP limits and SYN protection for layered defense:
 *
 * @code{.c}
 * SocketPool_setmaxperip(pool, 10);  // Max 10 conns per IP
 * SocketPool_setconnrate(pool, 1000, 5000);  // High rate for trusted networks
 * @endcode
 *
 * @note Refill uses monotonic time (CLOCK_MONOTONIC); resistant to time skew attacks.
 * @warning No automatic token refund on accept() failures (intentional anti-DoS measure).
 * @warning Excessive burst may lead to temporary overload; tune based on server capacity.
 * @complexity O(1) - either reconfigures existing limiter or allocates new one.
 *
 * @see SocketPool_getconnrate() for querying current limits.
 * @see SocketPool_accept_limited() where limiting is enforced.
 * @see SocketRateLimit_T (@ref utilities) for token bucket algorithm details.
 * @see SocketPool_setmaxperip() for per-client IP connection limits.
 * @see docs/SECURITY.md#rate-limiting for security considerations.
 */
void
SocketPool_setconnrate (T pool, int conns_per_sec, int burst)
{
  int config_ok;
  int safe_burst;
  size_t max_burst_check;

  assert (pool);

  /* Disable if rate is zero or negative */
  if (conns_per_sec <= 0)
    {
      pool_disable_component (pool, (void **)&pool->conn_limiter);
      return;
    }

  safe_burst = (burst <= 0) ? conns_per_sec : burst;

  /* Validate parameters to prevent resource exhaustion */
  if (conns_per_sec > SOCKET_POOL_MAX_RATE_PER_SEC
      || !SocketSecurity_check_multiply ((size_t)conns_per_sec,
                                         SOCKET_POOL_MAX_BURST_MULTIPLIER,
                                         &max_burst_check)
      || (size_t)safe_burst > max_burst_check || safe_burst <= 0)
    {
      RAISE_POOL_MSG (SocketPool_Failed,
                      "Invalid connection rate: rate=%d burst=%d (max %d/sec, "
                      "burst <=%dx rate)",
                      conns_per_sec, safe_burst, SOCKET_POOL_MAX_RATE_PER_SEC,
                      SOCKET_POOL_MAX_BURST_MULTIPLIER);
    }

  POOL_LOCK (pool);
  config_ok = configure_rate_limiter (pool, (size_t)conns_per_sec,
                                      (size_t)safe_burst);
  POOL_UNLOCK (pool);

  if (!config_ok)
    RAISE_POOL_MSG (SocketPool_Failed,
                    "Failed to create connection rate limiter");
}

/**
 * @brief Retrieve the currently configured connection rate limit.
 * @ingroup connection_mgmt
 *
 * Returns the conns_per_sec value last set via SocketPool_setconnrate(), or 0 if
 * rate limiting is disabled. The return value reflects the token replenishment
 * rate in connections per second.
 *
 * Internal size_t is capped at INT_MAX for int return compatibility; values
 * exceeding INT_MAX (rare, due to config limits) are clamped to INT_MAX.
 *
 * Useful for monitoring, logging, or dynamic adjustment logic (e.g., scale
 * based on load).
 *
 * @param[in] pool The connection pool to query.
 *
 * @return Current connections per second limit (>=0), or 0 if disabled.
 *         Clamped to INT_MAX if internal value exceeds int range.
 *
 * @throws None - query operation only; no exceptions raised.
 *
 * @threadsafe Yes - acquires pool mutex briefly for atomic read of limiter state.
 * Concurrent queries safe; does not block accept operations significantly.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // After configuration
 * int rate = SocketPool_getconnrate(pool);
 * if (rate == 0) {
 *     SOCKET_LOG_INFO_MSG("Rate limiting disabled");
 * } else {
 *     SOCKET_LOG_INFO_MSG("Current rate limit: %d conn/sec", rate);
 * }
 *
 * // Dynamic adjustment based on metrics
 * SocketMetricsSnapshot snap;
 * SocketMetrics_getsnapshot(&snap);
 * if (snap.active_connections > threshold) {
 *     SocketPool_setconnrate(pool, current_rate / 2, burst / 2);
 * }
 * @endcode
 *
 * @note Does not return burst capacity; use SocketRateLimit APIs directly if needed
 *       (not exposed publicly for pool).
 * @note Value is 0 after SocketPool_new() until explicitly set.
 * @complexity O(1) - simple mutex-protected field read.
 *
 * @see SocketPool_setconnrate() for setting the limit.
 * @see SocketRateLimit_get_rate() underlying query (clamped to int).
 * @see SocketPool_stats() for broader pool metrics including rate limiter stats.
 */
int
SocketPool_getconnrate (T pool)
{
  size_t raw_rate;
  int rate;

  assert (pool);

  POOL_LOCK (pool);
  raw_rate
      = pool->conn_limiter ? SocketRateLimit_get_rate (pool->conn_limiter) : 0;
  rate = (raw_rate > (size_t)INT_MAX) ? INT_MAX : (int)raw_rate;
  POOL_UNLOCK (pool);

  return rate;
}

/* ============================================================================
 * Per-IP Connection Limiting - Public API
 * ============================================================================
 */

/**
 * @brief Configure the maximum number of concurrent connections per client IP address.
 * @ingroup connection_mgmt
 *
 * Enforces per-IP connection limits to mitigate abuse from single sources (e.g., bots,
 * scanners, or compromised hosts). Uses internal SocketIPTracker_T to track active
 * connections by IP address string obtained via Socket_getpeeraddr().
 *
 * When max_conns <= 0, per-IP limiting is disabled (unlimited per IP, subject to global
 * maxconns and rate limits). Tracking begins automatically on successful SocketPool_add()
 * or manual SocketPool_track_ip() calls, and decrements on SocketPool_remove() or
 * SocketPool_release_ip().
 *
 * Validation caps max_conns <= SOCKET_POOL_MAX_CONNECTIONS_PER_IP to prevent hash table
 * memory exhaustion from excessive state (e.g., millions of IPs).
 *
 * Integrates with SocketPool_accept_limited() and SocketPool_add(): rejects if limit reached.
 * Dynamic changes affect new connections only; existing exceedances persist until closed.
 *
 * @param[in] pool The connection pool to configure.
 * @param[in] max_conns Maximum concurrent connections allowed per IP (0 disables).
 *
 * @throws SocketPool_Failed
 * - Invalid max_conns (> configured maximum).
 * - Allocation failure for internal IP tracker.
 *
 * @threadsafe Yes - acquires pool mutex; safe for concurrent configuration.
 *
 * ## Basic Usage
 *
 * @code{.c}
 * SocketPool_T pool = SocketPool_new(arena, 5000, 8192);
 *
 * // Allow max 5 connections per IP
 * SocketPool_setmaxperip(pool, 5);
 *
 * // Whitelist trusted IPs (unlimited for them)
 * SocketPool_iptracker_whitelist_add(pool->ip_tracker, "192.168.1.1");  // If exposed
 *
 * // In server loop:
 * Socket_T client = SocketPool_accept_limited(pool, listener);
 * const char *ip = Socket_getpeeraddr(client);
 * if (SocketPool_ip_count(pool, ip) > 5) {  // Would be checked internally
 *     // Rejected already
 * }
 * @endcode
 *
 * ## Disable Per-IP Limiting
 *
 * @code{.c}
 * SocketPool_setmaxperip(pool, 0);  // Unlimited per IP
 * @endcode
 *
 * ## Monitoring
 *
 * @code{.c}
 * int max_per_ip = SocketPool_getmaxperip(pool);
 * int count_for_ip = SocketPool_ip_count(pool, "10.0.0.1");
 * @endcode
 *
 * @note IP tracking uses string representation (IPv4/IPv6); Unix domain sockets skipped (NULL ip).
 * @note Whitelist/blacklist via underlying SocketIPTracker (if public API exposed).
 * @note Counts persist until release; manual track/release for non-pooled sockets.
 * @warning Without rate limiting, vulnerable to connection exhaustion per IP.
 * @complexity O(1) - reconfigures or creates tracker.
 *
 * @see SocketPool_getmaxperip() for current limit.
 * @see SocketPool_track_ip() / SocketPool_release_ip() for manual counting.
 * @see SocketPool_ip_count() for querying specific IP usage.
 * @see SocketIPTracker_T (@ref utilities) for tracking implementation.
 * @see SocketPool_setconnrate() for global rate complement.
 */
void
SocketPool_setmaxperip (T pool, int max_conns)
{
  int config_ok;

  assert (pool);

  /* Disable if max is zero or negative */
  if (max_conns <= 0)
    {
      pool_disable_component (pool, (void **)&pool->ip_tracker);
      return;
    }

  /* Validate parameters to prevent resource exhaustion */
  if (max_conns > SOCKET_POOL_MAX_CONNECTIONS_PER_IP)
    {
      RAISE_POOL_MSG (SocketPool_Failed,
                      "Invalid max per IP: %d (range 1-%d)", max_conns,
                      SOCKET_POOL_MAX_CONNECTIONS_PER_IP);
    }

  POOL_LOCK (pool);
  config_ok = configure_ip_tracker (pool, max_conns);
  POOL_UNLOCK (pool);

  if (!config_ok)
    RAISE_POOL_MSG (SocketPool_Failed, "Failed to create IP tracker");
}

/**
 * @brief Retrieve the currently configured maximum connections per client IP.
 * @ingroup connection_mgmt
 *
 * Returns the max_conns value last set via SocketPool_setmaxperip(), or 0 if
 * per-IP limiting is disabled. This is the threshold enforced by internal
 * SocketIPTracker_T for each client IP address.
 *
 * Value of 0 after SocketPool_new() until configured. Used for monitoring,
 * alerting on limits, or adaptive policy (e.g., tighten during attacks).
 *
 * @param[in] pool The connection pool to query.
 *
 * @return Configured max connections per IP (>=0), or 0 if disabled.
 *
 * @throws None - read-only query; no state modification.
 *
 * @threadsafe Yes - brief mutex acquisition for safe read of tracker state.
 *
 * ## Usage Example
 *
 * @code{.c}
 * int max_per_ip = SocketPool_getmaxperip(pool);
 * if (max_per_ip == 0) {
 *     SOCKET_LOG_WARN_MSG("Per-IP limiting disabled; potential DoS vector");
 * } else {
 *     SOCKET_LOG_DEBUG_MSG("Max %d conns per IP enforced", max_per_ip);
 * }
 * @endcode
 *
 * Combine with ip_count for runtime checks:
 *
 * @code{.c}
 * const char *client_ip = Socket_getpeeraddr(client);
 * int current_count = SocketPool_ip_count(pool, client_ip);
 * int limit = SocketPool_getmaxperip(pool);
 * if (current_count >= limit) {
 *     // Log or alert on saturated IP
 * }
 * @endcode
 *
 * @note Complements global limits; does not affect whitelisted IPs if supported.
 * @note IPv6 addresses tracked separately from IPv4.
 * @complexity O(1) - direct field access under mutex.
 *
 * @see SocketPool_setmaxperip() for configuration.
 * @see SocketPool_ip_count() for specific IP current usage.
 * @see SocketIPTracker_getmax() underlying getter.
 */
int
SocketPool_getmaxperip (T pool)
{
  int max;

  assert (pool);

  POOL_LOCK (pool);
  max = pool->ip_tracker ? SocketIPTracker_getmax (pool->ip_tracker) : 0;
  POOL_UNLOCK (pool);

  return max;
}

/* ============================================================================
 * Rate Limit Checking - Public API
 * ============================================================================
 */

/**
 * @brief Non-consuming pre-check if a new connection acceptance would be allowed.
 * @ingroup connection_mgmt
 *
 * Performs atomic checks under pool mutex for: pool state (must be RUNNING),
 * global rate limit availability (tokens > 0), and per-IP limit (if client_ip provided
 * and tracking enabled). Returns 1 only if all checks pass, indicating SocketPool_accept_limited()
 * has a high likelihood of succeeding (subject to concurrent changes and accept() outcome).
 *
 * Does NOT consume rate tokens or increment IP counts - purely advisory for load
 * shedding, logging, or conditional accept logic (e.g., before expensive operations).
 *
 * If client_ip is NULL or invalid, per-IP check is skipped (always allows).
 * Immediate 0 return if pool state is DRAINING or STOPPED (graceful shutdown in progress).
 *
 * Use before Socket_accept() in custom loops, or integrate with SYN protection for
 * early rejection.
 *
 * @param[in] pool The connection pool to check.
 * @param[in] client_ip Optional client IP (from e.g., getsockname or SYN data). NULL skips per-IP check.
 *
 * @return 1 if acceptance likely allowed (state OK + rate available + IP under limit),
 *         0 otherwise (draining/stopped/rate exhausted/IP saturated).
 *
 * @throws None - read-only checks; no modifications or allocations.
 *
 * @threadsafe Yes - single mutex acquisition for consistent state snapshot.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Custom accept loop with pre-check
 * while (running) {
 *     if (!SocketPoll_wait(poll, &events, timeout)) continue;
 *
 *     for each event on server_fd:
 *         if (SocketPool_accept_allowed(pool, NULL)) {  // No IP yet
 *             Socket_T client = Socket_accept(server);
 *             if (client) {
 *                 const char *ip = Socket_getpeeraddr(client);
 *                 if (SocketPool_accept_allowed(pool, ip)) {  // Double-check with IP
 *                     SocketPool_add(pool, client);
 *                 } else {
 *                     Socket_free(&client);  // Reject due to IP limit
 *                 }
 *             }
 *         } else {
 *             // Pool full/draining/rate limited: sleep or backoff
 *             usleep(1000);  // 1ms backoff
 *         }
 * }
 * @endcode
 *
 * ## With SYN Protection
 *
 * @code{.c}
 * SocketSYNProtect_T syn = SocketSYNProtect_new(arena, NULL);
 * SocketPool_set_syn_protection(pool, syn);
 *
 * // Pre-check before protected accept
 * SocketSYN_Action action;
 * if (SocketPool_accept_allowed(pool, NULL) &&
 *     SocketSYNProtect_check(syn, remote_ip, NULL) != SYN_ACTION_BLOCK) {
 *     Socket_T client = SocketPool_accept_protected(pool, server, &action);
 *     // ...
 * }
 * @endcode
 *
 * @note Concurrent calls may race: another thread may consume token between check and accept_limited().
 * @note For IPv6, provide full address string; tracking distinguishes v4/v6.
 * @note Performance: O(1) hash lookup for IP count if tracking enabled.
 * @warning Not a guarantee - use SocketPool_accept_limited() for actual enforcement.
 *
 * @see SocketPool_accept_limited() for token-consuming accept with limits.
 * @see SocketPool_setconnrate() / SocketPool_setmaxperip() for configuring checks.
 * @see rate_limit_allows() / ip_limit_allows() internal helpers (private).
 */
int
SocketPool_accept_allowed (T pool, const char *client_ip)
{
  int allowed;

  assert (pool);

  POOL_LOCK (pool);

  /* Reject if draining or stopped */
  if (atomic_load_explicit (&pool->state, memory_order_acquire)
      != POOL_STATE_RUNNING)
    {
      POOL_UNLOCK (pool);
      return 0;
    }

  allowed = rate_limit_allows (pool) && ip_limit_allows (pool, client_ip);

  POOL_UNLOCK (pool);

  return allowed;
}

/**
 * @brief Perform rate-limited and state-aware Socket_accept() with integrated protections.
 * @ingroup connection_mgmt
 *
 * Combines pool state verification, global rate token consumption, per-IP limit check,
 * and Socket_accept() into a single operation. Returns accepted client socket only if
 * all preconditions pass; otherwise NULL (with partial consumption as noted).
 *
 * Sequence:
 * 1. Acquire pool mutex.
 * 2. Verify pool state == POOL_STATE_RUNNING (else unlock, return NULL).
 * 3. Attempt to consume rate token (SOCKET_POOL_TOKENS_PER_ACCEPT, default 1).
 * 4. Release mutex.
 * 5. If token consumed successfully, call Socket_accept(server).
 * 6. On successful accept: get peer IP, track it via internal IP tracker (if enabled).
 * 7. On IP track failure (limit reached): free socket, return NULL.
 *
 * Key Behaviors:
 * - Immediate NULL if pool draining/stopped (supports graceful shutdown).
 * - Token consumed before accept(); no refund on accept() failure (anti-DoS: prevents
 *   rapid invalid accepts depleting tokens).
 * - Automatic IP tracking post-accept (if SocketPool_setmaxperip() > 0); failure
 *   closes socket and returns NULL.
 * - Races minimized: state and rate checks combined under mutex.
 *
 * CRITICAL CALLER RESPONSIBILITY: After successful return, if SocketPool_add(pool, client)
 * fails (e.g., pool full, state changed, exception), MUST:
 * - SocketPool_release_ip(pool, Socket_getpeeraddr(client)) to decrement IP count.
 * - Socket_free(&client) to close FD and free resources.
 * Failure causes IP "leak": permanent ban for that IP until manual release or pool clear,
 * enabling DoS. Always wrap in TRY/EXCEPT/FINALLY for safety.
 *
 * Integrates with SocketSYNProtect: use SocketPool_accept_protected() variant for SYN flood defense.
 *
 * @param[in] pool The connection pool enforcing limits.
 * @param[in] server Listening server socket (must be bound/listening).
 *
 * @return New client Socket_T on success (caller owns; add to pool or handle).
 * @return NULL if:
 *         - Pool draining/stopped.
 *         - Rate limit exhausted (token unavailable).
 *         - Socket_accept() failed (errno set; e.g., EAGAIN, EMFILE).
 *         - Per-IP limit reached post-accept (socket auto-closed).
 *
 * @throws Propagates exceptions from Socket_accept() (e.g., Socket_Failed on sys errors)
 *         or internal tracking (rare, e.g., Arena_Failed).
 *
 * @threadsafe Yes - mutex for checks/consume; Socket_accept() not locked (standard concurrent accept safe on Unix).
 *
 * ## Standard Usage in Server Loop
 *
 * @code{.c}
 * Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
 * Socket_bind(server, "0.0.0.0", 8080);
 * Socket_listen(server, 128);
 *
 * SocketPool_T pool = SocketPool_new(arena, 1024, 16384);
 * SocketPool_setconnrate(pool, 100, 200);  // Configure limits
 * SocketPool_setmaxperip(pool, 10);
 *
 * while (running) {
 *     Socket_T client = SocketPool_accept_limited(pool, server);
 *     if (client) {
 *         TRY {
 *             Connection_T conn = SocketPool_add(pool, client);
 *             // Process request, e.g., http_handle(conn)...
 *         } EXCEPT(SocketPool_Failed) {
 *             // Pool full, etc. - already tracked, but release if needed? No, add failed means not added
 *             const char *ip = Socket_getpeeraddr(client);
 *             SocketPool_release_ip(pool, ip);  // Decrement count
 *             Socket_free(&client);  // Close
 *             SOCKET_LOG_WARN_MSG("Failed to add client %s: pool full?", ip);
 *         } END_TRY;
 *     }
 * }
 * @endcode
 *
 * ## Error Handling Pattern
 *
 * @code{.c}
 * Socket_T client = SocketPool_accept_limited(pool, server);
 * if (!client) {
 *     if (errno == EAGAIN) continue;  // Try again
 *     // Log rate limit or other errno
 *     continue;
 * }
 *
 * TRY {
 *     SocketPool_add(pool, client);
 * } EXCEPT(SocketPool_Failed) {
 *     SocketPool_release_ip(pool, Socket_getpeeraddr(client));
 *     Socket_free(&client);
 *     // Retry logic or alert
 * } END_TRY;
 * @endcode
 *
 * ## With SYN Protection
 *
 * @code{.c}
 * SocketSYNProtect_T protect = SocketSYNProtect_new(arena, config);
 * SocketPool_set_syn_protection(pool, protect);
 *
 * Socket_T client = SocketPool_accept_protected(pool, server, &action);
 * if (client && action == SYN_ACTION_ALLOW) {
 *     // Add to pool...
 * } else {
 *     Socket_free(&client);  // Rejected or challenged
 * }
 * @endcode
 *
 * @note Socket_accept() may return NULL with EAGAIN (non-blocking server); loop accordingly.
 * @warning Caller must handle post-accept add failure to avoid IP count leaks.
 * @security No refund on accept fail prevents token exhaustion attacks.
 * @complexity O(1) amortized - checks + accept() + optional hash insert for IP track.
 *
 * @see SocketPool_accept_allowed() for non-consuming pre-check.
 * @see SocketPool_add() for adding accepted socket to pool (with error handling).
 * @see SocketPool_release_ip() critical for cleanup on add failure.
 * @see SocketPool_accept_protected() for SYN flood integration.
 * @see docs/POOL.md#error-handling for full patterns.
 */
Socket_T
SocketPool_accept_limited (T pool, Socket_T server)
{
  Socket_T client;
  const char *client_ip;
  int rate_ok;

  assert (pool);
  assert (server);

  /* Check pool state and consume rate token under single lock to minimize race
   * condition window: state may change between separate checks, leading to
   * unnecessary token consumption during drain.
   */
  POOL_LOCK (pool);
  if (atomic_load_explicit (&pool->state, memory_order_acquire)
      != POOL_STATE_RUNNING)
    {
      POOL_UNLOCK (pool);
      return NULL;
    }
  rate_ok = !pool->conn_limiter
            || SocketRateLimit_try_acquire (pool->conn_limiter,
                                            SOCKET_POOL_TOKENS_PER_ACCEPT);
  POOL_UNLOCK (pool);

  if (!rate_ok)
    return NULL;

  /* Accept the connection */
  client = Socket_accept (server);
  if (!client)
    return NULL;

  /* Check per-IP limit and track */
  client_ip = Socket_getpeeraddr (client);

  if (!locked_ip_op_int (pool, client_ip, SocketIPTracker_track, 1))
    {
      Socket_free (&client);
      return NULL;
    }

  return client;
}

/* ============================================================================
 * Manual IP Tracking - Public API
 * ============================================================================
 */

/**
 * SocketPool_track_ip - Manually track IP for per-IP limiting
 * @pool: Connection pool
 * @ip: IP address to track (NULL or empty always allowed)
 *
 * Returns: 1 if tracked successfully, 0 if IP limit reached
 *
 * @threadsafe Yes - acquires pool mutex
 */
int
SocketPool_track_ip (T pool, const char *ip)
{
  assert (pool);

  return locked_ip_op_int (pool, ip, SocketIPTracker_track, 1);
}

/**
 * SocketPool_release_ip - Release tracked IP when connection closes
 * @pool: Connection pool
 * @ip: IP address to release (NULL or empty is no-op)
 *
 * @threadsafe Yes - acquires pool mutex
 */
void
SocketPool_release_ip (T pool, const char *ip)
{
  assert (pool);

  locked_ip_op_void (pool, ip, SocketIPTracker_release);
}

/**
 * SocketPool_ip_count - Get connection count for IP
 * @pool: Connection pool
 * @ip: IP address to query (NULL or empty returns 0)
 *
 * Returns: Current connection count for the IP
 *
 * @threadsafe Yes - acquires pool mutex
 */
int
SocketPool_ip_count (T pool, const char *ip)
{
  assert (pool);

  return locked_ip_op_int (pool, ip, SocketIPTracker_count, 0);
}

#undef T
