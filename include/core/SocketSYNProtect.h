/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSYNPROTECT_INCLUDED
#define SOCKETSYNPROTECT_INCLUDED

/**
 * @defgroup security Security Modules
 * @brief Comprehensive security protections for network applications
 *
 * The Security group provides layered protection against network attacks and
 * abuse patterns. Key components include SYN flood protection, IP filtering,
 * and adaptive rate limiting mechanisms.
 *
 * ## Architecture Overview
 *
 * ```
 * ┌───────────────────────────────────────────────────────────┐
 * │                    Application Layer                      │
 * │  HTTP Servers, TCP Services, Connection Pools, etc.       │
 * └─────────────────────┬─────────────────────────────────────┘
 *                       │ Uses                                │
 * ┌─────────────────────▼─────────────────────────────────────┘
 * │                 Security Layer                            │
 * │  SYN Protection, TLS, IP Filtering, Rate Limiting         │
 * │  ┌────────────────────────────────────────────────────┐   │
 * │  │            SocketSYNProtect                        │   │
 * │  │  ┌─────────────────────────────────────────────┐   │   │
 * │  │  │ IP Reputation Engine                        │   │   │
 * │  │  │ • Rate limiting per IP                      │   │   │
 * │  │  │ • Success/failure tracking                  │   │   │
 * │  │  │ • Adaptive scoring                          │   │   │
 * │  │  └─────────────────────────────────────────────┘   │   │
 * │  │                                                    │   │
 * │  │  ┌─────────────────────────────────────────────┐   │   │
 * │  │  │ Protection Actions                          │   │   │
 * │  │  │ • ALLOW: Normal processing                  │   │   │
 * │  │  │ • THROTTLE: Accept with delay               │   │   │
 * │  │  │ • CHALLENGE: TCP_DEFER_ACCEPT               │   │   │
 * │  │  │ • BLOCK: Immediate rejection                │   │   │
 * │  │  └─────────────────────────────────────────────┘   │   │
 * │  └────────────────────────────────────────────────────┘   │
 * └─────────────────────┬─────────────────────────────────────┘
 *                       │ Uses                                │
 * ┌─────────────────────▼─────────────────────────────────────┘
 * │              Foundation Layer                             │
 * │  Arena, Except, SocketConfig, SocketUtil, SocketTimer     │
 * └───────────────────────────────────────────────────────────┘
 * ```
 *
 * ## Module Relationships
 *
 * - **Depends on**: Foundation modules (Arena, Except, SocketConfig)
 * - **Used by**: SocketPool for integrated protection
 * - **Integrates with**: SocketTimer for cleanup scheduling
 *
 * @see @ref foundation for base infrastructure
 * @see @ref connection_mgmt for connection lifecycle management
 * @{
 */

/**
 * @file SocketSYNProtect.h
 * @ingroup security
 * @brief SYN flood protection using IP reputation and adaptive rate limiting.
 *
 * This header provides comprehensive defense against SYN flood DDoS attacks
 * through intelligent IP reputation management and multi-layered protection
 * strategies.
 *
 * ## Protection Mechanisms
 *
 * ### 1. Rate Limiting
 * - Sliding window counters per IP address
 * - Configurable thresholds with burst allowances
 * - Global rate limiting across all IPs
 *
 * ### 2. Reputation Scoring
 * - Dynamic scoring based on connection success/failure ratios
 * - Time-decayed reputation with configurable half-life
 * - Multi-level reputation tiers (Trusted → Neutral → Suspect → Hostile)
 *
 * ### 3. Response Actions
 * - **ALLOW**: Normal connection processing
 * - **THROTTLE**: Accept with artificial delay to slow attacks
 * - **CHALLENGE**: Require immediate data payload (TCP_DEFER_ACCEPT)
 * - **BLOCK**: Immediate connection rejection
 *
 * ### 4. List Management
 * - CIDR-aware whitelist for trusted networks
 * - Temporary/permanent blacklist for malicious IPs
 * - Automatic expiration of temporary blocks
 *
 * ## Platform Requirements
 *
 * - POSIX-compliant system with CLOCK_MONOTONIC support
 * - pthreads for thread-safe operations
 * - Optional: TCP_DEFER_ACCEPT kernel support for challenge mode
 *
 * ## Thread Safety
 *
 * All APIs are fully thread-safe with internal mutex protection:
 * - Share protection instances across multiple threads
 * - Concurrent operations from different threads safe
 * - All state modifications atomic and consistent
 *
 * ## Usage Patterns
 *
 * ### Basic Integration
 * @code{.c}
 * // Initialize protection
 * SocketSYNProtect_T protect = SocketSYNProtect_new(NULL, NULL);
 *
 * // In connection loop
 * SocketSYN_Action action = SocketSYNProtect_check(protect, client_ip, NULL);
 * switch (action) {
 *     case SYN_ACTION_ALLOW:
 *     case SYN_ACTION_THROTTLE:
 *         Socket_T conn = Socket_accept(server);
 *         if (connection_successful(conn)) {
 *             SocketSYNProtect_report_success(protect, client_ip);
 *         } else {
 *             SocketSYNProtect_report_failure(protect, client_ip, errno);
 *         }
 *         break;
 *     case SYN_ACTION_BLOCK:
 *         SocketSYNProtect_report_failure(protect, client_ip, ECONNREFUSED);
 *         break;
 * }
 * @endcode
 *
 * ### SocketPool Integration
 * @code{.c}
 * SocketPool_T pool = SocketPool_new(arena, max_conns, bufsize);
 * SocketPool_set_syn_protection(pool, protect);
 * // Protection now automatic on all SocketPool_accept_limited() calls
 * @endcode
 *
 * @see SocketSYNProtect_new() for initialization
 * @see SocketSYNProtect_check() for core protection evaluation
 * @see SocketSYNProtect_Config for configuration options
 * @see SocketPool_set_syn_protection() for automatic pool integration
 * @see docs/SECURITY.md for security best practices
 * @see docs/SYN-PROTECT.md for detailed configuration and tuning guide
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include <stddef.h>
#include <stdint.h>

#define T SocketSYNProtect_T
typedef struct T *T;

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @brief General SYN protection operation failure.
 * @ingroup security
 *
 * Category: SYSTEM
 * Retryable: DEPENDS - often due to resource exhaustion; retry after cleanup.
 *
 * Raised in cases such as:
 * - Memory allocation failure (arena exhaustion or malloc failure)
 * - Invalid configuration parameters (e.g., negative window duration)
 * - Internal data structure corruption or hash collisions
 * - Mutex acquisition failures under extreme contention
 *
 * @see Except_T for exception handling patterns.
 * @see Socket_GetLastError() for detailed error string.
 * @see docs/ERROR_HANDLING.md for module exception guidelines.
 */
extern const Except_T SocketSYNProtect_Failed;

/* ============================================================================
 * Action and Reputation Enums
 * ============================================================================
 */

/**
 * @brief Protection response actions for SYN connection attempts.
 * @ingroup security
 *
 * Enum values determine the handling strategy for incoming connections
 * based on IP reputation, rate limiting, whitelist/blacklist status, and
 * current load.
 *
 * @see SocketSYNProtect_check() returns the action for a given client IP.
 * @see SocketSYNProtect_action_name() for human-readable names.
 * @see SocketPool_accept_protected() for integration with connection pools.
 */
typedef enum SocketSYN_Action
{
  SYN_ACTION_ALLOW = 0, /**< Allow: Normal acceptance without restrictions. */
  SYN_ACTION_THROTTLE,  /**< Throttle: Accept but introduce artificial delay to
                           slow attacks. */
  SYN_ACTION_CHALLENGE, /**< Challenge: Apply TCP_DEFER_ACCEPT to require
                           immediate data payload. */
  SYN_ACTION_BLOCK /**< Block: Immediately reject the connection attempt. */
} SocketSYN_Action;

/**
 * @brief IP reputation levels based on behavior history.
 * @ingroup security
 *
 * Reputation evolves dynamically based on connection success rates,
 * attempt frequencies, and manual list status. Lower reputation triggers
 * stricter actions.
 *
 * @see SocketSYNProtect_check() uses reputation to decide actions.
 * @see SocketSYNProtect_reputation_name() for string names.
 * @see SocketSYN_IPState::rep for per-IP reputation storage.
 */
typedef enum SocketSYN_Reputation
{
  SYN_REP_TRUSTED
  = 0, /**< Trusted: Whitelisted or consistently successful behavior. */
  SYN_REP_NEUTRAL, /**< Neutral: New or unknown IP with no suspicious activity.
                    */
  SYN_REP_SUSPECT, /**< Suspect: Elevated attempt rates or low success ratio.
                    */
  SYN_REP_HOSTILE /**< Hostile: Detected attack patterns, repeated failures, or
                     blacklisted. */
} SocketSYN_Reputation;

/* ============================================================================
 * Per-IP State Structure
 * ============================================================================
 */

/**
 * @brief Per-IP address tracking and reputation state.
 * @ingroup security
 *
 * Opaque structure holding all metrics and state for a single tracked IP.
 * Updated atomically for thread safety. Not for direct modification;
 * use reporting functions to update state.
 *
 * Fields:
 * - Timestamps use CLOCK_MONOTONIC for accuracy.
 * - Counters are uint32_t to prevent overflow under DDoS.
 * - Score is float [0.0,1.0] with decay over time.
 *
 * @see SocketSYNProtect_get_ip_state() to query state without modification.
 * @see SocketSYNProtect_report_success() and report_failure() to update
 * counters.
 * @see SocketSYNProtect_cleanup() for eviction of stale states.
 */
typedef struct SocketSYN_IPState
{
  char ip[SOCKET_IP_MAX_LEN]; /**< Null-terminated IP address string
                                 (IPv4/IPv6). */
  int64_t window_start_ms; /**< Start timestamp (ms) of current rate window. */
  uint32_t
      attempts_current; /**< Connection attempts in current sliding window. */
  uint32_t attempts_previous; /**< Attempts from previous window (used for
                                 decay calculation). */
  uint32_t successes; /**< Cumulative successful handshakes/connections. */
  uint32_t failures;  /**< Cumulative failed or aborted connections. */
  int64_t last_attempt_ms;  /**< Timestamp (ms) of most recent connection
                               attempt. */
  int64_t block_until_ms;   /**< Block expiration timestamp (0 = not blocked;
                               CLOCK_MONOTONIC ms). */
  SocketSYN_Reputation rep; /**< Current computed reputation level. */
  float score; /**< Dynamic reputation score (0.0 = hostile, 1.0 = trusted). */
} SocketSYN_IPState;

/* ============================================================================
 * Configuration Structure
 * ============================================================================
 */

/**
 * @brief Configuration parameters for SYN flood protection.
 * @ingroup security
 *
 * Defines behavior for rate limiting, reputation scoring, response actions,
 * and resource constraints. Use SocketSYNProtect_config_defaults() to
 * initialize. Timing values in ms (except challenge_defer_sec in seconds).
 * Scores in [0.0f, 1.0f].
 *
 * @warning Invalid configs (e.g., zero/negative durations, scores out of
 * range) may lead to undefined behavior or SocketSYNProtect_Failed exceptions.
 *
 * @see SocketSYNProtect_config_defaults() for safe initialization.
 * @see SocketSYNProtect_new() consumes this config.
 * @see SocketSYNProtect_configure() for dynamic reconfiguration.
 */
typedef struct SocketSYNProtect_Config
{
  /* Window Settings */
  int window_duration_ms; /**< Sliding window size (default: 10000ms). */

  /* Rate Thresholds */
  int max_attempts_per_window; /**< Per-IP attempt limit per window. */
  int max_global_per_second;   /**< Global rate limit (all IPs). */
  float min_success_ratio; /**< Min success/attempt ratio before suspect. */

  /* Response Tuning */
  int throttle_delay_ms;   /**< Artificial delay for THROTTLE action. */
  int block_duration_ms;   /**< Duration of automatic blocks. */
  int challenge_defer_sec; /**< TCP_DEFER_ACCEPT timeout in seconds. */

  /* Score Thresholds */
  float score_throttle;  /**< Score below this triggers THROTTLE. */
  float score_challenge; /**< Score below this triggers CHALLENGE. */
  float score_block;     /**< Score below this triggers BLOCK. */

  /* Score Adjustment Rates */
  float score_decay_per_sec;   /**< Score recovery rate per second. */
  float score_penalty_attempt; /**< Score penalty per new attempt. */
  float score_penalty_failure; /**< Score penalty per failure. */
  float score_reward_success;  /**< Score reward per successful connection. */

  /* Memory Management */
  size_t max_tracked_ips; /**< Maximum IPs to track (LRU eviction). */
  size_t max_whitelist;   /**< Maximum whitelist entries. */
  size_t max_blacklist;   /**< Maximum blacklist entries. */
  unsigned
      hash_seed; /**< Hash randomization seed (0 = auto-generate crypto random
                    for collision resistance; affects synprotect_hash_ip). */
} SocketSYNProtect_Config;

/* ============================================================================
 * Statistics Structure
 * ============================================================================
 */

/**
 * @brief Statistics snapshot for SYN protection activity.
 * @ingroup security
 *
 * Thread-safe atomic snapshot of counters and metrics. Does not include
 * per-IP details or whitelist/blacklist contents for privacy.
 *
 * @note Counters wrap around at UINT64_MAX; suitable for 100+ years of
 * activity.
 * @see SocketSYNProtect_stats() to populate this structure.
 * @see SocketSYNProtect_stats_reset() to zero counters (except uptime).
 */
typedef struct SocketSYNProtect_Stats
{
  uint64_t total_attempts;      /**< Total connection attempts checked. */
  uint64_t total_allowed;       /**< Attempts allowed (SYN_ACTION_ALLOW). */
  uint64_t total_throttled;     /**< Attempts throttled. */
  uint64_t total_challenged;    /**< Attempts challenged (TCP_DEFER_ACCEPT). */
  uint64_t total_blocked;       /**< Attempts blocked. */
  uint64_t total_whitelisted;   /**< Attempts from whitelisted IPs. */
  uint64_t total_blacklisted;   /**< Attempts from blacklisted IPs. */
  uint64_t current_tracked_ips; /**< Currently tracked unique IPs. */
  uint64_t current_blocked_ips; /**< Currently blocked IPs. */
  uint64_t lru_evictions;       /**< Number of LRU evictions. */
  int64_t uptime_ms;            /**< Time since initialization. */
} SocketSYNProtect_Stats;

/* ============================================================================
 * Lifecycle Functions
 * ============================================================================
 */

/**
 * @brief Create a new instance of SYN protection.
 * @ingroup security
 *
 * Allocates and initializes a new SYN flood protection instance with the
 * specified configuration. Creates internal data structures for IP tracking,
 * rate limiting, reputation scoring, and whitelist/blacklist management.
 *
 * @param[in] arena Memory arena for allocations (NULL uses malloc/free)
 * @param[in] config Protection configuration (NULL uses defaults)
 *
 * @return New SocketSYNProtect_T instance, or NULL on failure
 *
 * @throws SocketSYNProtect_Failed on allocation or initialization failure
 *
 * @threadsafe Yes - creates independent instance safe to use from any thread
 *
 * ## Basic Usage
 *
 * @code{.c}
 * // Create with default configuration
 * SocketSYNProtect_T protect = SocketSYNProtect_new(NULL, NULL);
 *
 * // Create with custom config
 * SocketSYNProtect_Config config;
 * SocketSYNProtect_config_defaults(&config);
 * config.max_attempts_per_window = 50; // Tighter limits
 * protect = SocketSYNProtect_new(NULL, &config);
 *
 * // Use in connection acceptance
 * SocketSYN_Action action = SocketSYNProtect_check(protect, client_ip, NULL);
 * if (action == SYN_ACTION_ALLOW) {
 *     // Accept connection
 *     Socket_T conn = Socket_accept(server_socket);
 *     SocketSYNProtect_report_success(protect, client_ip);
 * } else {
 *     // Handle throttling/blocking
 * }
 *
 * SocketSYNProtect_free(&protect);
 * @endcode
 *
 * ## Arena Usage
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * SocketSYNProtect_T protect = SocketSYNProtect_new(arena, NULL);
 * // ... use protect ...
 * // All memory freed when arena is disposed
 * Arena_dispose(&arena); // Also frees protect
 * @endcode
 *
 * @complexity O(1) - constant time initialization
 *
 * @see SocketSYNProtect_config_defaults() for configuration setup
 * @see SocketSYNProtect_free() for cleanup
 * @see SocketSYNProtect_check() for protection evaluation
 * @see docs/SECURITY.md for security considerations
 * @see docs/SYN-PROTECT.md for detailed configuration guide
 */
extern T SocketSYNProtect_new (Arena_T arena,
                               const SocketSYNProtect_Config *config);

/**
 * @brief Dispose of a SYN protection instance and release all resources.
 * @ingroup security
 *
 * Releases all internal resources including hash tables, mutexes,
 * whitelist/blacklist entries, and tracked IP states. For malloc-based
 * instances, frees all memory. For arena-based instances, clears internal
 * pointers (arena dispose handles memory).
 *
 * @param[in,out] protect Pointer to instance (set to NULL on success)
 *
 * @threadsafe Yes - acquires internal mutex during cleanup
 *
 * ## Usage Examples
 *
 * @code{.c}
 * // Standard cleanup
 * SocketSYNProtect_T protect = SocketSYNProtect_new(NULL, NULL);
 * // ... use protect ...
 * SocketSYNProtect_free(&protect); // protect is now NULL
 *
 * // Safe to call on NULL
 * SocketSYNProtect_T maybe_null = NULL;
 * SocketSYNProtect_free(&maybe_null); // No-op, safe
 *
 * // Arena-managed cleanup
 * Arena_T arena = Arena_new();
 * SocketSYNProtect_T protect = SocketSYNProtect_new(arena, NULL);
 * // Option 1: Explicit free
 * SocketSYNProtect_free(&protect);
 * // Option 2: Arena dispose handles everything
 * Arena_dispose(&arena); // Also frees protect if not already freed
 * @endcode
 *
 * @note Safe to call on NULL pointer (no-op)
 *
 * @note After this call, the pointer is set to NULL to prevent use-after-free
 *
 * @complexity O(n) - must clean up all tracked IPs and list entries
 *
 * @see SocketSYNProtect_new() for creation
 * @see SocketSYNProtect_clear_all() to clear state without freeing
 * @see Arena_dispose() for arena-managed cleanup patterns
 */
extern void SocketSYNProtect_free (T *protect);

/**
 * @brief Initialize configuration structure with safe defaults.
 * @ingroup security
 *
 * Populates a SocketSYNProtect_Config structure with conservative,
 * production-ready default values suitable for most applications. The defaults
 * provide good protection against SYN floods while allowing reasonable
 * connection rates for legitimate traffic.
 *
 * @param[out] config Pointer to config structure to populate with defaults
 *
 * @threadsafe Yes - pure function with no shared state
 *
 * ## Default Values
 *
 * | Setting | Default | Description |
 * |---------|---------|-------------|
 * | window_duration_ms | 10000 | 10 second sliding window |
 * | max_attempts_per_window | 100 | Max attempts per IP per window |
 * | max_global_per_second | 1000 | Global rate limit |
 * | min_success_ratio | 0.1 | Minimum 10% success rate |
 * | throttle_delay_ms | 100 | 100ms delay for throttling |
 * | block_duration_ms | 300000 | 5 minute automatic blocks |
 * | challenge_defer_sec | 10 | 10 second TCP_DEFER_ACCEPT |
 * | score_throttle | 0.7 | Throttle below 70% score |
 * | score_challenge | 0.5 | Challenge below 50% score |
 * | score_block | 0.3 | Block below 30% score |
 * | max_tracked_ips | 10000 | Track up to 10k IPs |
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Use all defaults
 * SocketSYNProtect_Config config;
 * SocketSYNProtect_config_defaults(&config);
 * SocketSYNProtect_T protect = SocketSYNProtect_new(NULL, &config);
 *
 * // Customize for high-traffic service
 * SocketSYNProtect_config_defaults(&config);
 * config.max_attempts_per_window = 500;     // Higher limit
 * config.max_global_per_second = 5000;      // Higher global rate
 * config.max_tracked_ips = 50000;           // Track more IPs
 * config.window_duration_ms = 5000;         // Shorter windows
 *
 * // Customize for low-resource device
 * SocketSYNProtect_config_defaults(&config);
 * config.max_attempts_per_window = 20;      // Lower limit
 * config.max_tracked_ips = 1000;            // Track fewer IPs
 * config.window_duration_ms = 30000;        // Longer windows
 * @endcode
 *
 * @note Tune these values based on your expected legitimate traffic patterns
 *
 * @note Defaults are conservative - you may need to increase limits for
 * high-traffic services
 *
 * @complexity O(1) - simple structure population
 *
 * @see SocketSYNProtect_Config for all available configuration options
 * @see SocketSYNProtect_new() for creating instances with config
 * @see SocketSYNProtect_configure() for runtime reconfiguration
 * @see docs/SYN-PROTECT.md for detailed tuning guidance
 */
extern void SocketSYNProtect_config_defaults (SocketSYNProtect_Config *config);

/**
 * @brief Update protection configuration during runtime.
 * @ingroup security
 *
 * Atomically updates the configuration of an active protection instance.
 * Changes take effect immediately for all future @c SocketSYNProtect_check()
 * calls. Existing tracked IP states, whitelist/blacklist entries, and active
 * blocks are preserved.
 *
 * @param[in] protect Active protection instance
 * @param[in] config New configuration to apply
 *
 * @throws SocketSYNProtect_Failed if config contains invalid values
 *
 * @threadsafe Yes - mutex-protected atomic update
 *
 * ## Usage Examples
 *
 * @code{.c}
 * // Tighten limits during detected attack
 * void on_attack_detected(SocketSYNProtect_T protect) {
 *     SocketSYNProtect_Config config;
 *     SocketSYNProtect_config_defaults(&config);
 *     config.max_attempts_per_window = 10;  // Much stricter
 *     config.score_block = 0.5;             // Block at higher score
 *     config.block_duration_ms = 600000;    // 10 minute blocks
 *     SocketSYNProtect_configure(protect, &config);
 * }
 *
 * // Relax limits after attack subsides
 * void on_attack_ended(SocketSYNProtect_T protect) {
 *     SocketSYNProtect_Config config;
 *     SocketSYNProtect_config_defaults(&config); // Back to defaults
 *     SocketSYNProtect_configure(protect, &config);
 * }
 *
 * // Dynamic adjustment based on load
 * void adjust_for_load(SocketSYNProtect_T protect, int current_connections) {
 *     SocketSYNProtect_Config config;
 *     SocketSYNProtect_config_defaults(&config);
 *
 *     if (current_connections > 8000) {
 *         // High load - be more aggressive
 *         config.max_attempts_per_window = 20;
 *         config.score_throttle = 0.8;
 *     }
 *     SocketSYNProtect_configure(protect, &config);
 * }
 * @endcode
 *
 * @note Reducing @c max_tracked_ips may trigger immediate LRU eviction
 *
 * @note Changing score thresholds affects all future checks but not existing
 * blocks
 *
 * @complexity O(n) if max_tracked_ips reduced (triggers eviction), O(1)
 * otherwise
 *
 * @see SocketSYNProtect_new() for initial configuration
 * @see SocketSYNProtect_config_defaults() for baseline values
 * @see SocketSYNProtect_Config for all tunable parameters
 */
extern void SocketSYNProtect_configure (T protect,
                                        const SocketSYNProtect_Config *config);

/* ============================================================================
 * Core Protection Functions
 * ============================================================================
 */

/**
 * @brief Evaluate client IP and determine protection action.
 * @ingroup security
 *
 * Performs comprehensive SYN flood protection evaluation for an incoming
 * connection attempt. Checks whitelist/blacklist status, rate limits,
 * reputation scores, and applies appropriate protection actions. This is the
 * core function called before accepting any connection.
 *
 * The evaluation process:
 * 1. Check whitelist/blacklist (immediate ALLOW/BLOCK)
 * 2. Verify rate limits for the IP and globally
 * 3. Assess reputation based on success/failure history
 * 4. Determine action: ALLOW, THROTTLE, CHALLENGE, or BLOCK
 * 5. Update attempt counters for rate limiting
 *
 * @param[in] protect Active protection instance
 * @param[in] client_ip Client IP address (IPv4/IPv6) or NULL/empty for
 * unconditional ALLOW
 * @param[out] state_out Optional output for detailed IP state information (may
 * be NULL)
 *
 * @return Protection action: SYN_ACTION_ALLOW, THROTTLE, CHALLENGE, or BLOCK
 *
 * @threadsafe Yes - internal mutex protects all shared state modifications
 *
 * ## Usage Pattern
 *
 * @code{.c}
 * // In connection acceptance loop
 * struct sockaddr_in client_addr;
 * socklen_t addr_len = sizeof(client_addr);
 *
 * int fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
 * if (fd >= 0) {
 *     char client_ip[INET6_ADDRSTRLEN];
 *     inet_ntop(client_addr.sin_family,
 *               client_addr.sin_family == AF_INET ?
 *                   (void*)&client_addr.sin_addr :
 *                   (void*)&((struct sockaddr_in6*)&client_addr)->sin6_addr,
 *               client_ip, sizeof(client_ip));
 *
 *     SocketSYN_Action action = SocketSYNProtect_check(protect, client_ip,
 * NULL);
 *
 *     switch (action) {
 *         case SYN_ACTION_ALLOW:
 *             // Normal processing
 *             handle_connection(fd, client_ip);
 *             SocketSYNProtect_report_success(protect, client_ip);
 *             break;
 *
 *         case SYN_ACTION_THROTTLE:
 *             // Accept but add delay
 *             usleep(100000); // 100ms delay
 *             handle_connection(fd, client_ip);
 *             SocketSYNProtect_report_success(protect, client_ip);
 *             break;
 *
 *         case SYN_ACTION_CHALLENGE:
 *             // Use TCP_DEFER_ACCEPT if available, or accept normally
 *             handle_connection(fd, client_ip);
 *             SocketSYNProtect_report_success(protect, client_ip);
 *             break;
 *
 *         case SYN_ACTION_BLOCK:
 *             // Reject connection
 *             close(fd);
 *             SocketSYNProtect_report_failure(protect, client_ip,
 * ECONNREFUSED); break;
 *     }
 * }
 * @endcode
 *
 * ## Integration with SocketPool
 *
 * @code{.c}
 * // SocketPool handles the check automatically
 * SocketPool_T pool = SocketPool_new(arena, 1000, 4096);
 * SocketPool_set_syn_protection(pool, protect);
 *
 * // This internally calls SocketSYNProtect_check()
 * Connection_T conn = SocketPool_accept_limited(pool, server_socket);
 * if (conn) {
 *     // Connection accepted and tracked
 *     SocketSYNProtect_report_success(protect,
 *         Socket_getpeeraddr(Connection_socket(conn)));
 * }
 * @endcode
 *
 * @note Always call @c SocketSYNProtect_report_success() or
 * @c SocketSYNProtect_report_failure() after connection outcome is known
 *
 * @note NULL or empty client_ip always returns SYN_ACTION_ALLOW
 *
 * @complexity O(1) average case - hash table lookups
 *
 * @see SocketSYN_Action for action meanings and handling
 * @see SocketSYNProtect_report_success() for successful connections
 * @see SocketSYNProtect_report_failure() for failed connections
 * @see SocketSYN_IPState for detailed state information
 * @see SocketPool_set_syn_protection() for automatic integration
 * @see docs/SYN-PROTECT.md for protection algorithms and tuning
 */
extern SocketSYN_Action SocketSYNProtect_check (T protect,
                                                const char *client_ip,
                                                SocketSYN_IPState *state_out);

/**
 * @brief Report successful connection completion for IP reputation update.
 * @ingroup security
 *
 * Updates the reputation system with a successful connection outcome for the
 * specified IP address. This improves the IP's reputation score, potentially
 * allowing more lenient rate limits and reducing throttling in future checks.
 *
 * Call this function after a connection has completed successfully:
 * - TCP handshake established
 * - Initial protocol handshake (if any) completed
 * - Connection is ready for normal data exchange
 *
 * @param[in] protect Active protection instance
 * @param[in] client_ip IP address of the successful connection (IPv4/IPv6)
 *
 * @threadsafe Yes - mutex-protected update operation
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketSYN_Action action = SocketSYNProtect_check(protect, client_ip, NULL);
 * if (action != SYN_ACTION_BLOCK) {
 *     Socket_T conn = Socket_accept(server_socket);
 *     if (conn && perform_initial_handshake(conn)) {
 *         // Connection fully established
 *         SocketSYNProtect_report_success(protect, client_ip);
 *         handle_normal_connection(conn);
 *     } else {
 *         // Connection failed after accept
 *         SocketSYNProtect_report_failure(protect, client_ip, errno);
 *         Socket_free(&conn);
 *     }
 * }
 * @endcode
 *
 * @note No-op if IP is not currently tracked or is whitelisted
 *
 * @note Call this only after successful connection establishment
 *
 * @complexity O(1) - hash table lookup and atomic update
 *
 * @see SocketSYNProtect_report_failure() for failed connections
 * @see SocketSYNProtect_check() for initial evaluation
 * @see SocketSYN_IPState::successes for success counter tracking
 * @see SocketSYNProtect_Config::score_reward_success for score adjustment
 */
extern void SocketSYNProtect_report_success (T protect, const char *client_ip);

/**
 * @brief Report connection failure for IP reputation update.
 * @ingroup security
 *
 * Updates the reputation system with a failed connection outcome for the
 * specified IP address. This reduces the IP's reputation score, potentially
 * triggering stricter rate limits, throttling, or blocking in future checks.
 *
 * Call this function when a connection attempt fails at any stage:
 * - TCP handshake failure (ECONNREFUSED, ETIMEDOUT, ECONNRESET)
 * - Immediate disconnect after accept
 * - Protocol handshake failure
 * - Any other connection establishment error
 *
 * @param[in] protect Active protection instance
 * @param[in] client_ip IP address of the failed connection (IPv4/IPv6)
 * @param[in] error_code errno value from failed operation (0 if unknown)
 *
 * @threadsafe Yes - mutex-protected update operation
 *
 * ## Usage Examples
 *
 * @code{.c}
 * // Connection failure during accept
 * int fd = accept(server_fd, NULL, NULL);
 * if (fd < 0) {
 *     // Accept failed - report failure if we have client IP
 *     if (client_ip_known) {
 *         SocketSYNProtect_report_failure(protect, client_ip, errno);
 *     }
 * }
 *
 * // Connection accepted but fails immediately
 * SocketSYN_Action action = SocketSYNProtect_check(protect, client_ip, NULL);
 * if (action != SYN_ACTION_BLOCK) {
 *     Socket_T conn = Socket_accept(server_socket);
 *     if (conn) {
 *         if (!perform_initial_handshake(conn)) {
 *             // Handshake failed
 *             SocketSYNProtect_report_failure(protect, client_ip, EPROTO);
 *             Socket_free(&conn);
 *         } else {
 *             // Success
 *             SocketSYNProtect_report_success(protect, client_ip);
 *         }
 *     }
 * }
 * @endcode
 *
 * @note No-op if IP is not currently tracked or is whitelisted
 *
 * @note The error_code parameter helps with debugging but doesn't affect
 * reputation scoring - all failures are treated equally
 *
 * @complexity O(1) - hash table lookup and atomic update
 *
 * @see SocketSYNProtect_report_success() for successful connections
 * @see SocketSYNProtect_check() which evaluates reputation
 * @see SocketSYN_IPState::failures for failure counter tracking
 * @see SocketSYNProtect_Config::score_penalty_failure for penalty tuning
 */
extern void SocketSYNProtect_report_failure (T protect, const char *client_ip,
                                             int error_code);

/* ============================================================================
 * Whitelist Management
 * ============================================================================
 */

/**
 * @brief Add an IP address to the whitelist.
 * @ingroup security
 *
 * Adds an IP address to the whitelist, causing all future connection attempts
 * from this IP to bypass SYN flood protection entirely. Whitelisted IPs always
 * receive SYN_ACTION_ALLOW regardless of rate limits, reputation scores, or
 * blacklist status.
 *
 * @param[in] protect Active protection instance
 * @param[in] ip Null-terminated IP address string (IPv4: "192.168.1.1", IPv6:
 * "2001:db8::1")
 *
 * @return 1 on success (added or already present), 0 if whitelist is full
 *
 * @threadsafe Yes - mutex-protected update operation
 *
 * ## Usage Examples
 *
 * @code{.c}
 * // Whitelist trusted internal network
 * SocketSYNProtect_whitelist_add(protect, "10.0.0.1");
 * SocketSYNProtect_whitelist_add(protect, "10.0.0.2");
 *
 * // Whitelist IPv6 address
 * SocketSYNProtect_whitelist_add(protect, "2001:db8::1");
 *
 * // Check before adding (optional)
 * if (!SocketSYNProtect_whitelist_contains(protect, "192.168.1.100")) {
 *     if (!SocketSYNProtect_whitelist_add(protect, "192.168.1.100")) {
 *         fprintf(stderr, "Whitelist full, could not add IP\n");
 *     }
 * }
 * @endcode
 *
 * ## Integration with Monitoring
 *
 * @code{.c}
 * // Add IP that just authenticated successfully
 * int login_successful = authenticate_user(username, password);
 * if (login_successful) {
 *     // Trust this IP for future connections
 *     SocketSYNProtect_whitelist_add(protect, client_ip);
 *     SocketSYNProtect_report_success(protect, client_ip);
 * }
 * @endcode
 *
 * @note Whitelisted IPs completely bypass all protection mechanisms
 *
 * @note Use CIDR ranges with @c SocketSYNProtect_whitelist_add_cidr() for
 * networks
 *
 * @complexity O(1) average case - hash table insertion
 *
 * @see SocketSYNProtect_whitelist_add_cidr() for CIDR range whitelisting
 * @see SocketSYNProtect_whitelist_contains() to check membership
 * @see SocketSYNProtect_whitelist_remove() to remove entries
 * @see SocketSYNProtect_Config::max_whitelist for capacity limits
 * @see docs/SECURITY.md for whitelist security considerations
 */
extern int SocketSYNProtect_whitelist_add (T protect, const char *ip);

/**
 * @brief Add a CIDR range to the whitelist.
 * @ingroup security
 *
 * Adds an entire IP address range to the whitelist using CIDR notation. Any IP
 * address falling within the specified range will bypass all SYN flood
 * protection and receive SYN_ACTION_ALLOW.
 *
 * @param[in] protect Active protection instance
 * @param[in] cidr CIDR notation string (e.g., "10.0.0.0/8", "192.168.1.0/24",
 * "2001:db8::/32")
 *
 * @return 1 on success (added or already present), 0 on parse error or
 * whitelist full
 *
 * @threadsafe Yes - mutex-protected update operation
 *
 * ## Usage Examples
 *
 * @code{.c}
 * // Whitelist internal networks
 * SocketSYNProtect_whitelist_add_cidr(protect, "10.0.0.0/8");      // Class A
 * private SocketSYNProtect_whitelist_add_cidr(protect, "172.16.0.0/12");   //
 * Class B private SocketSYNProtect_whitelist_add_cidr(protect,
 * "192.168.0.0/16");  // Class C private
 *
 * // Whitelist IPv6 network
 * SocketSYNProtect_whitelist_add_cidr(protect, "2001:db8::/32");
 *
 * // Whitelist localhost
 * SocketSYNProtect_whitelist_add_cidr(protect, "127.0.0.0/8");
 * SocketSYNProtect_whitelist_add_cidr(protect, "::1/128");
 *
 * // Whitelist specific subnet
 * if (!SocketSYNProtect_whitelist_add_cidr(protect, "203.0.113.0/24")) {
 *     fprintf(stderr, "Failed to add CIDR (invalid or whitelist full)\n");
 * }
 * @endcode
 *
 * @note CIDR ranges are more memory-efficient than individual IP entries
 *
 * @note Invalid CIDR notation (e.g., "10.0.0.0/33") returns 0
 *
 * @complexity O(1) - constant time insertion
 *
 * @see SocketSYNProtect_whitelist_add() for individual IP addresses
 * @see SocketSYNProtect_whitelist_contains() for membership checking
 * @see SocketSYNProtect_Config::max_whitelist for capacity limits
 */
extern int SocketSYNProtect_whitelist_add_cidr (T protect, const char *cidr);

/**
 * @brief Remove an IP address from the whitelist.
 * @ingroup security
 *
 * Removes a specific IP address from the whitelist. Future connection attempts
 * from this IP will be subject to normal rate limiting and reputation checks.
 * Also removes any CIDR entries that would match this IP.
 *
 * @param[in] protect Active protection instance
 * @param[in] ip Null-terminated IP address string to remove (IPv4 or IPv6)
 *
 * @threadsafe Yes - mutex-protected update operation
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Remove previously whitelisted IP
 * SocketSYNProtect_whitelist_remove(protect, "10.0.0.5");
 *
 * // Verify removal
 * if (!SocketSYNProtect_whitelist_contains(protect, "10.0.0.5")) {
 *     printf("IP successfully removed from whitelist\n");
 * }
 * @endcode
 *
 * @note No-op if IP not found in whitelist
 *
 * @note This also removes CIDR entries containing the IP
 *
 * @complexity O(n) - may need to search CIDR entries
 *
 * @see SocketSYNProtect_whitelist_add() for adding entries
 * @see SocketSYNProtect_whitelist_contains() to verify removal
 * @see SocketSYNProtect_whitelist_clear() to remove all entries
 */
extern void SocketSYNProtect_whitelist_remove (T protect, const char *ip);

/**
 * @brief Check if an IP address is whitelisted.
 * @ingroup security
 *
 * Determines whether a specific IP address is in the whitelist, either as an
 * exact match or within a whitelisted CIDR range. Whitelisted IPs bypass all
 * SYN protection mechanisms.
 *
 * @param[in] protect Active protection instance
 * @param[in] ip Null-terminated IP address string to check (IPv4 or IPv6)
 *
 * @return 1 if whitelisted (exact match or within CIDR range), 0 otherwise
 *
 * @threadsafe Yes - read-only operation with mutex protection
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Check before manual processing
 * if (SocketSYNProtect_whitelist_contains(protect, client_ip)) {
 *     // Skip protection checks for whitelisted IPs
 *     handle_trusted_connection(client_ip);
 * } else {
 *     // Normal protection evaluation
 *     SocketSYN_Action action = SocketSYNProtect_check(protect, client_ip,
 * NULL);
 *     // ... handle action ...
 * }
 *
 * // Verify CIDR matching
 * SocketSYNProtect_whitelist_add_cidr(protect, "10.0.0.0/8");
 * assert(SocketSYNProtect_whitelist_contains(protect, "10.1.2.3") == 1);
 * assert(SocketSYNProtect_whitelist_contains(protect, "192.168.1.1") == 0);
 * @endcode
 *
 * @note This is called internally by @c SocketSYNProtect_check()
 *
 * @complexity O(n) worst case - checks exact matches then CIDR ranges
 *
 * @see SocketSYNProtect_whitelist_add() for adding IP addresses
 * @see SocketSYNProtect_whitelist_add_cidr() for adding CIDR ranges
 * @see SocketSYNProtect_check() which uses this internally
 */
extern int SocketSYNProtect_whitelist_contains (T protect, const char *ip);

/**
 * @brief Clear all whitelist entries.
 * @ingroup security
 *
 * Removes all entries from the whitelist, including individual IP addresses
 * and CIDR ranges. After this call, all IPs will be subject to normal SYN
 * protection evaluation regardless of previous whitelist status.
 *
 * @param[in] protect Active protection instance
 *
 * @threadsafe Yes - mutex-protected update operation
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Clear whitelist during security incident
 * void on_security_incident(SocketSYNProtect_T protect) {
 *     // Remove all trusted IPs - trust no one during incident
 *     SocketSYNProtect_whitelist_clear(protect);
 *
 *     // Optionally, tighten overall protection
 *     SocketSYNProtect_Config config;
 *     SocketSYNProtect_config_defaults(&config);
 *     config.max_attempts_per_window = 5;
 *     SocketSYNProtect_configure(protect, &config);
 * }
 *
 * // Reset whitelist to new set
 * SocketSYNProtect_whitelist_clear(protect);
 * SocketSYNProtect_whitelist_add_cidr(protect, "10.0.0.0/8");
 * SocketSYNProtect_whitelist_add(protect, "trusted.example.com");
 * @endcode
 *
 * @complexity O(n) - must free all whitelist entries
 *
 * @see SocketSYNProtect_whitelist_add() to add new entries
 * @see SocketSYNProtect_whitelist_remove() for individual removal
 * @see SocketSYNProtect_blacklist_clear() for clearing blacklists
 * @see SocketSYNProtect_reset() for full instance reset
 */
extern void SocketSYNProtect_whitelist_clear (T protect);

/* ============================================================================
 * Blacklist Management
 * ============================================================================
 */

/**
 * @brief Add an IP address to the blacklist.
 * @ingroup security
 *
 * Adds an IP address to the blacklist, causing all future connection attempts
 * from this IP to immediately receive SYN_ACTION_BLOCK. Supports both
 * temporary (auto-expiring) and permanent blocks.
 *
 * @param[in] protect Active protection instance
 * @param[in] ip Null-terminated IP address string (IPv4 or IPv6)
 * @param[in] duration_ms Block duration: positive = temporary (auto-expires),
 * 0 = permanent
 *
 * @return 1 on success (added or duration extended), 0 if blacklist is full
 *
 * @threadsafe Yes - mutex-protected update operation
 *
 * ## Usage Examples
 *
 * @code{.c}
 * // Permanent block for known malicious IP
 * SocketSYNProtect_blacklist_add(protect, "192.0.2.1", 0);
 *
 * // Temporary 5-minute block
 * SocketSYNProtect_blacklist_add(protect, "203.0.113.50", 300000);
 *
 * // 24-hour block for suspected attacker
 * SocketSYNProtect_blacklist_add(protect, "198.51.100.10", 86400000);
 *
 * // Automatic blocking based on behavior
 * void on_suspicious_activity(SocketSYNProtect_T protect, const char *ip) {
 *     // Progressive blocking: longer each time
 *     static int block_duration = 60000; // Start at 1 minute
 *     SocketSYNProtect_blacklist_add(protect, ip, block_duration);
 *     block_duration = (block_duration < 3600000) ? block_duration * 2 :
 * 3600000;
 * }
 *
 * // Handle blacklist full condition
 * if (!SocketSYNProtect_blacklist_add(protect, attacker_ip, 0)) {
 *     // Blacklist full - run cleanup or increase max_blacklist
 *     SocketSYNProtect_cleanup(protect);
 *     SocketSYNProtect_blacklist_add(protect, attacker_ip, 0);
 * }
 * @endcode
 *
 * @note If IP already blacklisted with temporary block, duration is extended
 *
 * @note Permanent blocks (duration_ms=0) persist until manual removal or reset
 *
 * @complexity O(1) average case - hash table insertion
 *
 * @see SocketSYNProtect_blacklist_contains() to check block status
 * @see SocketSYNProtect_blacklist_remove() for manual unblocking
 * @see SocketSYNProtect_cleanup() for automatic expiration of temporary blocks
 * @see SocketSYNProtect_Config::max_blacklist for capacity limits
 */
extern int SocketSYNProtect_blacklist_add (T protect, const char *ip,
                                           int duration_ms);

/**
 * @brief Remove an IP address from the blacklist.
 * @ingroup security
 *
 * Immediately removes an IP address from the blacklist, allowing future
 * connection attempts to be processed through normal rate limiting and
 * reputation evaluation. This can be used for manual unblocking or
 * administrative override.
 *
 * @param[in] protect Active protection instance
 * @param[in] ip Null-terminated IP address string to unblock (IPv4 or IPv6)
 *
 * @threadsafe Yes - mutex-protected update operation
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Admin override - unblock a false positive
 * void admin_unblock(SocketSYNProtect_T protect, const char *ip) {
 *     SocketSYNProtect_blacklist_remove(protect, ip);
 *     printf("IP %s removed from blacklist\n", ip);
 *
 *     // Optionally whitelist to prevent re-blocking
 *     SocketSYNProtect_whitelist_add(protect, ip);
 * }
 *
 * // Verify removal succeeded
 * SocketSYNProtect_blacklist_remove(protect, "192.0.2.1");
 * if (!SocketSYNProtect_blacklist_contains(protect, "192.0.2.1")) {
 *     printf("IP successfully unblocked\n");
 * }
 * @endcode
 *
 * @note No-op if IP not currently blacklisted
 *
 * @note IP reputation state (if tracked) is preserved after unblocking
 *
 * @complexity O(1) average case - hash table lookup and removal
 *
 * @see SocketSYNProtect_blacklist_add() for blocking IPs
 * @see SocketSYNProtect_blacklist_contains() to verify removal
 * @see SocketSYNProtect_cleanup() for automatic expiration
 */
extern void SocketSYNProtect_blacklist_remove (T protect, const char *ip);

/**
 * @brief Check if an IP address is currently blacklisted.
 * @ingroup security
 *
 * Determines whether a specific IP address is actively blocked in the
 * blacklist. Expired temporary blocks are not considered active and return 0.
 *
 * @param[in] protect Active protection instance
 * @param[in] ip Null-terminated IP address string to check (IPv4 or IPv6)
 *
 * @return 1 if actively blacklisted (not expired), 0 otherwise
 *
 * @threadsafe Yes - read-only operation with mutex protection
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Check status for logging
 * if (SocketSYNProtect_blacklist_contains(protect, client_ip)) {
 *     log_warn("Connection attempt from blacklisted IP: %s", client_ip);
 * }
 *
 * // Verify block is active before external action
 * if (SocketSYNProtect_blacklist_contains(protect, attacker_ip)) {
 *     // Report to external threat intelligence
 *     report_to_threat_intel(attacker_ip);
 * }
 * @endcode
 *
 * @note This is called internally by @c SocketSYNProtect_check()
 *
 * @note Expired temporary blocks return 0 (considered not blacklisted)
 *
 * @complexity O(1) average case - hash table lookup
 *
 * @see SocketSYNProtect_blacklist_add() for blocking IPs
 * @see SocketSYNProtect_blacklist_remove() for manual unblocking
 * @see SocketSYNProtect_check() which uses this internally
 */
extern int SocketSYNProtect_blacklist_contains (T protect, const char *ip);

/**
 * @brief Clear all blacklist entries.
 * @ingroup security
 *
 * Removes all entries from the blacklist, including both temporary and
 * permanent blocks. After this call, all previously blocked IPs will be
 * subject to normal SYN protection evaluation.
 *
 * @param[in] protect Active protection instance
 *
 * @threadsafe Yes - mutex-protected update operation
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Clear blacklist after attack investigation concludes
 * void on_attack_resolved(SocketSYNProtect_T protect) {
 *     printf("Attack resolved, clearing blacklist\n");
 *     SocketSYNProtect_blacklist_clear(protect);
 *
 *     // Optionally reset stats for fresh monitoring
 *     SocketSYNProtect_stats_reset(protect);
 * }
 *
 * // Replace blacklist with new set
 * SocketSYNProtect_blacklist_clear(protect);
 * SocketSYNProtect_blacklist_add(protect, "192.0.2.1", 0);
 * SocketSYNProtect_blacklist_add(protect, "198.51.100.0", 0);
 * @endcode
 *
 * @note Use with caution - may allow previously blocked attackers
 *
 * @complexity O(n) - must free all blacklist entries
 *
 * @see SocketSYNProtect_blacklist_add() to add new blocks
 * @see SocketSYNProtect_blacklist_remove() for individual removal
 * @see SocketSYNProtect_whitelist_clear() for clearing whitelists
 * @see SocketSYNProtect_reset() for full instance reset
 */
extern void SocketSYNProtect_blacklist_clear (T protect);

/* ============================================================================
 * Query and Statistics Functions
 * ============================================================================
 */

/**
 * @brief Retrieve the current state and reputation metrics for a specific IP
 * address.
 * @ingroup security
 *
 * Retrieves a read-only snapshot of the tracking data for a specific IP
 * address, including attempt counts, success/failure ratios, reputation score,
 * and block status. This is useful for debugging, monitoring dashboards, or
 * administrative interfaces.
 *
 * @param[in] protect Active protection instance
 * @param[in] ip IP address string to query (IPv4 or IPv6)
 * @param[out] state Output structure populated with IP state if found
 *
 * @return 1 if IP found and state populated, 0 if IP not currently tracked
 *
 * @threadsafe Yes - mutex-protected atomic snapshot
 *
 * ## Usage Examples
 *
 * @code{.c}
 * // Query IP state for debugging
 * SocketSYN_IPState state;
 * if (SocketSYNProtect_get_ip_state(protect, client_ip, &state)) {
 *     printf("IP: %s\n", state.ip);
 *     printf("  Attempts (current window): %u\n", state.attempts_current);
 *     printf("  Successes: %u, Failures: %u\n", state.successes,
 * state.failures); printf("  Score: %.2f\n", state.score); printf("
 * Reputation: %s\n", SocketSYNProtect_reputation_name(state.rep)); if
 * (state.block_until_ms > 0) { printf("  Blocked until: %lld ms\n",
 * state.block_until_ms);
 *     }
 * } else {
 *     printf("IP %s not currently tracked\n", client_ip);
 * }
 *
 * // Build monitoring dashboard data
 * void populate_dashboard(SocketSYNProtect_T protect, const char **ips, size_t
 * count) { for (size_t i = 0; i < count; i++) { SocketSYN_IPState state; if
 * (SocketSYNProtect_get_ip_state(protect, ips[i], &state)) {
 *             dashboard_update_ip(ips[i], state.score, state.rep);
 *         }
 *     }
 * }
 * @endcode
 *
 * @note This is a read-only operation - does not modify counters or state
 *
 * @note State may become stale immediately after return due to concurrent
 * updates
 *
 * @complexity O(1) average case - hash table lookup
 *
 * @see SocketSYN_IPState for structure field details
 * @see SocketSYNProtect_check() for state updates during evaluation
 * @see SocketSYNProtect_report_success() and @c report_failure() for counter
 * updates
 */
extern int SocketSYNProtect_get_ip_state (T protect, const char *ip,
                                          SocketSYN_IPState *state);

/**
 * @brief Retrieve aggregate statistics snapshot for the SYN protection module.
 * @ingroup security
 *
 * Retrieves a consistent snapshot of all protection counters and metrics. The
 * snapshot is suitable for monitoring dashboards, logging, alerting, and
 * capacity planning. Privacy-safe: excludes per-IP details and list contents.
 *
 * @param[in] protect Active protection instance
 * @param[out] stats Output structure populated with current metrics
 *
 * @threadsafe Yes - uses atomic operations for consistent concurrent reads
 *
 * ## Usage Examples
 *
 * @code{.c}
 * // Periodic monitoring
 * void log_protection_stats(SocketSYNProtect_T protect) {
 *     SocketSYNProtect_Stats stats;
 *     SocketSYNProtect_stats(protect, &stats);
 *
 *     printf("SYN Protection Stats:\n");
 *     printf("  Uptime: %lld ms\n", stats.uptime_ms);
 *     printf("  Total attempts: %lu\n", stats.total_attempts);
 *     printf("  Allowed: %lu (%.1f%%)\n", stats.total_allowed,
 *            100.0 * stats.total_allowed / (stats.total_attempts ?: 1));
 *     printf("  Throttled: %lu\n", stats.total_throttled);
 *     printf("  Challenged: %lu\n", stats.total_challenged);
 *     printf("  Blocked: %lu\n", stats.total_blocked);
 *     printf("  Whitelisted: %lu\n", stats.total_whitelisted);
 *     printf("  Blacklisted: %lu\n", stats.total_blacklisted);
 *     printf("  Currently tracking: %lu IPs\n", stats.current_tracked_ips);
 *     printf("  Currently blocked: %lu IPs\n", stats.current_blocked_ips);
 *     printf("  LRU evictions: %lu\n", stats.lru_evictions);
 * }
 *
 * // Alert on attack detection
 * void check_for_attack(SocketSYNProtect_T protect) {
 *     SocketSYNProtect_Stats stats;
 *     SocketSYNProtect_stats(protect, &stats);
 *
 *     // Alert if block rate exceeds threshold
 *     double block_rate = (double)stats.total_blocked / (stats.total_attempts
 * ?: 1); if (block_rate > 0.5 && stats.total_attempts > 100) {
 *         alert_security_team("Possible SYN flood attack detected");
 *     }
 * }
 *
 * // Export to metrics system (e.g., Prometheus)
 * void export_to_prometheus(SocketSYNProtect_T protect) {
 *     SocketSYNProtect_Stats stats;
 *     SocketSYNProtect_stats(protect, &stats);
 *
 *     prometheus_gauge_set("syn_protect_tracked_ips",
 * stats.current_tracked_ips);
 *     prometheus_counter_set("syn_protect_total_blocked",
 * stats.total_blocked); prometheus_counter_set("syn_protect_total_allowed",
 * stats.total_allowed);
 * }
 * @endcode
 *
 * @note Counters may wrap at UINT64_MAX (sufficient for 100+ years of
 * activity)
 *
 * @complexity O(1) - atomic reads of pre-computed values
 *
 * @see SocketSYNProtect_Stats for all available metrics
 * @see SocketSYNProtect_stats_reset() to reset counters
 * @see SocketSYNProtect_cleanup() which updates eviction stats
 */
extern void SocketSYNProtect_stats (T protect, SocketSYNProtect_Stats *stats);

/**
 * @brief Reset all resettable statistics counters to zero.
 * @ingroup security
 *
 * Clears cumulative counters (attempts, actions, evictions) while preserving
 * all tracked IP states, whitelists, blacklists, and uptime. Useful for
 * starting fresh reporting periods without affecting protection behavior.
 *
 * @param[in] protect Active protection instance
 *
 * @threadsafe Yes - mutex-protected update operation
 *
 * ## Counters Reset
 *
 * - total_attempts → 0
 * - total_allowed → 0
 * - total_throttled → 0
 * - total_challenged → 0
 * - total_blocked → 0
 * - total_whitelisted → 0
 * - total_blacklisted → 0
 * - lru_evictions → 0
 *
 * ## Counters Preserved
 *
 * - uptime_ms (continues counting)
 * - current_tracked_ips (reflects actual state)
 * - current_blocked_ips (reflects actual state)
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Reset stats at start of new reporting period
 * void start_new_period(SocketSYNProtect_T protect) {
 *     // Log final stats from previous period
 *     SocketSYNProtect_Stats stats;
 *     SocketSYNProtect_stats(protect, &stats);
 *     log_period_summary(&stats);
 *
 *     // Reset for new period
 *     SocketSYNProtect_stats_reset(protect);
 * }
 *
 * // Daily rotation for metrics
 * void on_midnight(SocketSYNProtect_T protect) {
 *     SocketSYNProtect_stats_reset(protect);
 *     printf("Protection stats reset for new day\n");
 * }
 * @endcode
 *
 * @complexity O(1) - atomic counter resets
 *
 * @see SocketSYNProtect_stats() to view statistics
 * @see SocketSYNProtect_reset() for full instance reset
 */
extern void SocketSYNProtect_stats_reset (T protect);

/**
 * @brief Convert SYN action enum to human-readable string.
 * @ingroup security
 *
 * Converts an action enum value to its string representation for logging,
 * debugging, monitoring dashboards, or user-facing display.
 *
 * @param[in] action Action enum value to convert
 *
 * @return Pointer to static null-terminated string ("ALLOW", "THROTTLE",
 * "CHALLENGE", "BLOCK")
 *
 * @threadsafe Yes - pure function returning constant data
 *
 * ## Return Values
 *
 * | Input | Output |
 * |-------|--------|
 * | SYN_ACTION_ALLOW | "ALLOW" |
 * | SYN_ACTION_THROTTLE | "THROTTLE" |
 * | SYN_ACTION_CHALLENGE | "CHALLENGE" |
 * | SYN_ACTION_BLOCK | "BLOCK" |
 * | (invalid) | "UNKNOWN" |
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketSYN_Action action = SocketSYNProtect_check(protect, client_ip, NULL);
 * printf("Action for %s: %s\n", client_ip,
 * SocketSYNProtect_action_name(action));
 *
 * // Logging pattern
 * log_info("SYN check: ip=%s action=%s", client_ip,
 *          SocketSYNProtect_action_name(action));
 * @endcode
 *
 * @note Returns static string - do not free or modify
 *
 * @complexity O(1) - constant time lookup
 *
 * @see SocketSYN_Action for enum values and meanings
 * @see SocketSYNProtect_reputation_name() for reputation level strings
 */
extern const char *SocketSYNProtect_action_name (SocketSYN_Action action);

/**
 * @brief Convert reputation enum to human-readable string.
 * @ingroup security
 *
 * Converts a reputation enum value to its string representation for logging,
 * debugging, monitoring dashboards, or user-facing display.
 *
 * @param[in] rep Reputation enum value to convert
 *
 * @return Pointer to static null-terminated string ("TRUSTED", "NEUTRAL",
 * "SUSPECT", "HOSTILE")
 *
 * @threadsafe Yes - pure function returning constant data
 *
 * ## Return Values
 *
 * | Input | Output | Description |
 * |-------|--------|-------------|
 * | SYN_REP_TRUSTED | "TRUSTED" | Whitelisted or consistently good behavior |
 * | SYN_REP_NEUTRAL | "NEUTRAL" | New or unknown IP |
 * | SYN_REP_SUSPECT | "SUSPECT" | Elevated rates or low success ratio |
 * | SYN_REP_HOSTILE | "HOSTILE" | Detected attack patterns |
 * | (invalid) | "UNKNOWN" | Invalid enum value |
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketSYN_IPState state;
 * if (SocketSYNProtect_get_ip_state(protect, client_ip, &state)) {
 *     printf("IP %s reputation: %s (score: %.2f)\n",
 *            client_ip, SocketSYNProtect_reputation_name(state.rep),
 * state.score);
 * }
 *
 * // Monitoring dashboard
 * const char *rep_str = SocketSYNProtect_reputation_name(state.rep);
 * dashboard_update(client_ip, rep_str);
 * @endcode
 *
 * @note Returns static string - do not free or modify
 *
 * @complexity O(1) - constant time lookup
 *
 * @see SocketSYN_Reputation for enum values and criteria
 * @see SocketSYNProtect_action_name() for action strings
 * @see SocketSYN_IPState::rep for per-IP reputation storage
 */
extern const char *SocketSYNProtect_reputation_name (SocketSYN_Reputation rep);

/* ============================================================================
 * Maintenance Functions
 * ============================================================================
 */

/**
 * @brief Perform periodic cleanup of expired and stale protection state.
 * @ingroup security
 *
 * Performs maintenance operations to keep the protection system efficient and
 * up-to-date. This function should be called regularly (every 1-10 seconds)
 * to:
 *
 * - Expire temporary blacklists and blocks based on duration settings
 * - Evict least-recently-used IP states when approaching max_tracked_ips limit
 * - Apply reputation score decay over time
 * - Advance sliding windows for rate limiting calculations
 * - Remove stale entries to maintain performance
 *
 * @param[in] protect Active protection instance
 *
 * @return Number of IP entries cleaned up (evicted or expired)
 *
 * @threadsafe Yes - mutex-protected operation
 *
 * ## Integration with Event Loops
 *
 * @code{.c}
 * // Using SocketTimer for periodic cleanup
 * void cleanup_callback(void *userdata) {
 *     SocketSYNProtect_T protect = (SocketSYNProtect_T)userdata;
 *     size_t cleaned = SocketSYNProtect_cleanup(protect);
 *     if (cleaned > 0) {
 *         printf("Cleaned up %zu stale entries\n", cleaned);
 *     }
 * }
 *
 * // Set up 5-second periodic cleanup
 * SocketTimer_add(poll, 5000, cleanup_callback, protect);
 * @endcode
 *
 * ## Manual Cleanup in Simple Loops
 *
 * @code{.c}
 * time_t last_cleanup = time(NULL);
 * while (running) {
 *     // Check connections...
 *
 *     // Periodic cleanup every 10 seconds
 *     if (time(NULL) - last_cleanup >= 10) {
 *         size_t cleaned = SocketSYNProtect_cleanup(protect);
 *         last_cleanup = time(NULL);
 *         if (cleaned > 0) {
 *             log_info("Cleaned up %zu protection entries", cleaned);
 *         }
 *     }
 * }
 * @endcode
 *
 * @note Call frequency affects memory usage and responsiveness:
 * - Too frequent: unnecessary CPU overhead
 * - Too infrequent: stale data accumulation, delayed expirations
 *
 * @complexity O(n) worst case - must scan all tracked IPs, but typically much
 * faster due to early termination and efficient data structures
 *
 * @see SocketSYNProtect_Config::max_tracked_ips for eviction threshold
 * @see SocketSYNProtect_Config::block_duration_ms for expiration timing
 * @see SocketSYNProtect_Config::window_duration_ms for window management
 * @see SocketSYNProtect_Config::score_decay_per_sec for reputation decay
 * @see SocketSYNProtect_clear_all() for immediate full cleanup
 */
extern size_t SocketSYNProtect_cleanup (T protect);

/**
 * @brief Clear all tracked IP states without affecting lists or stats.
 * @ingroup security
 *
 * Evicts all per-IP tracking data including rate counters, reputation scores,
 * and temporary blocks. Whitelists, blacklists, and global statistics are
 * preserved. Useful for reducing memory usage during idle periods or after
 * resolving attack situations.
 *
 * @param[in] protect Active protection instance
 *
 * @threadsafe Yes - mutex-protected update operation
 *
 * ## What Gets Cleared
 *
 * - All per-IP tracking state
 * - Rate limit counters
 * - Reputation scores
 * - Temporary blocks (from reputation system)
 *
 * ## What Is Preserved
 *
 * - Whitelist entries
 * - Blacklist entries (manual blocks)
 * - Global statistics counters
 * - Configuration settings
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Clear tracking during maintenance window
 * void on_maintenance_start(SocketSYNProtect_T protect) {
 *     printf("Clearing IP tracking state during maintenance\n");
 *     SocketSYNProtect_clear_all(protect);
 *     // Whitelists and blacklists preserved
 * }
 *
 * // Memory cleanup after attack subsides
 * void after_attack_resolved(SocketSYNProtect_T protect) {
 *     SocketSYNProtect_Stats stats;
 *     SocketSYNProtect_stats(protect, &stats);
 *
 *     if (stats.current_tracked_ips > 5000) {
 *         // Clear stale tracking data
 *         SocketSYNProtect_clear_all(protect);
 *         printf("Cleared %lu tracked IPs\n", stats.current_tracked_ips);
 *     }
 * }
 * @endcode
 *
 * @complexity O(n) - must free all tracked IP entries
 *
 * @see SocketSYNProtect_cleanup() for incremental cleanup
 * @see SocketSYNProtect_reset() for complete reset including lists
 * @see SocketSYNProtect_whitelist_clear() for whitelist management
 * @see SocketSYNProtect_blacklist_clear() for blacklist management
 */
extern void SocketSYNProtect_clear_all (T protect);

/**
 * @brief Perform full reset of the SYN protection instance to initial state.
 * @ingroup security
 *
 * Completely resets all internal state to as-if-newly-created condition. This
 * includes clearing all tracked IPs, whitelists, blacklists, temporary blocks,
 * and statistics counters. The current configuration is retained. Uptime
 * counter is preserved for operational tracking.
 *
 * @param[in] protect Active protection instance
 *
 * @threadsafe Yes - mutex-protected update operation
 *
 * ## What Gets Cleared
 *
 * - All per-IP tracking state
 * - All whitelist entries
 * - All blacklist entries
 * - All temporary blocks
 * - All statistics counters
 *
 * ## What Is Preserved
 *
 * - Configuration settings
 * - Uptime counter
 * - Internal data structures (hash tables, etc.)
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Complete reset for testing
 * void reset_for_test(SocketSYNProtect_T protect) {
 *     SocketSYNProtect_reset(protect);
 *     // Instance now behaves as if newly created
 *     // but configuration is preserved
 * }
 *
 * // Emergency reset during security incident
 * void emergency_reset(SocketSYNProtect_T protect) {
 *     printf("Performing emergency protection reset\n");
 *     SocketSYNProtect_reset(protect);
 *
 *     // Re-establish known-good whitelist
 *     SocketSYNProtect_whitelist_add_cidr(protect, "10.0.0.0/8");
 *     SocketSYNProtect_whitelist_add_cidr(protect, "127.0.0.0/8");
 *
 *     printf("Protection reset complete, core whitelists restored\n");
 * }
 *
 * // Clean slate for new deployment
 * void prepare_for_deployment(SocketSYNProtect_T protect) {
 *     SocketSYNProtect_reset(protect);
 *     load_production_whitelist(protect);
 *     load_known_bad_actors(protect);
 * }
 * @endcode
 *
 * @warning This is a destructive operation - all accumulated reputation and
 * block data is lost
 *
 * @complexity O(n) - must free all entries from all internal tables
 *
 * @see SocketSYNProtect_new() for creating new instances
 * @see SocketSYNProtect_free() for disposing instances
 * @see SocketSYNProtect_clear_all() for partial clear (preserves lists)
 * @see SocketSYNProtect_configure() to update config without clearing state
 */
extern void SocketSYNProtect_reset (T protect);

/** @} */ /* end of security group */

#undef T
#endif /* SOCKETSYNPROTECT_INCLUDED */
