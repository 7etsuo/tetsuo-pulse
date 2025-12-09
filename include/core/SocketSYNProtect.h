#ifndef SOCKETSYNPROTECT_INCLUDED
#define SOCKETSYNPROTECT_INCLUDED

/**
 * @file SocketSYNProtect.h
 * @ingroup security
 * @brief SYN flood protection using IP reputation and adaptive rate limiting.
 *
 * Part of the @ref security "Security Modules" group.
 *
 * Provides defense against SYN flood DDoS attacks via:
 * - Pre-accept connection attempt tracking
 * - Sliding window rate counters per IP
 * - Dynamic reputation scoring with success/failure feedback
 * - Tiered responses: allow/throttle/challenge/block
 * - CIDR-aware whitelist/blacklist
 * - Optional TCP_DEFER_ACCEPT kernel integration
 *
 * Platform: POSIX systems with CLOCK_MONOTONIC and pthreads.
 * Thread-safe: All APIs protected by internal mutexes; share instances freely.
 *
 * @see SocketSYNProtect_new() to initialize.
 * @see SocketSYNProtect_check() core evaluation function.
 * @see SocketSYNProtect_Config for tuning parameters.
 * @see SocketPool_set_syn_protection() pool integration.
 * @see docs/SECURITY.md SYN protection best practices.
 * @see docs/SYN-PROTECT.md detailed protocol and config guide.
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
typedef enum SocketSYN_Action {
  SYN_ACTION_ALLOW = 0, /**< Allow: Normal acceptance without restrictions. */
  SYN_ACTION_THROTTLE,  /**< Throttle: Accept but introduce artificial delay to slow attacks. */
  SYN_ACTION_CHALLENGE, /**< Challenge: Apply TCP_DEFER_ACCEPT to require immediate data payload. */
  SYN_ACTION_BLOCK      /**< Block: Immediately reject the connection attempt. */
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
typedef enum SocketSYN_Reputation {
  SYN_REP_TRUSTED = 0, /**< Trusted: Whitelisted or consistently successful behavior. */
  SYN_REP_NEUTRAL,     /**< Neutral: New or unknown IP with no suspicious activity. */
  SYN_REP_SUSPECT,     /**< Suspect: Elevated attempt rates or low success ratio. */
  SYN_REP_HOSTILE      /**< Hostile: Detected attack patterns, repeated failures, or blacklisted. */
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
 * @see SocketSYNProtect_report_success() and report_failure() to update counters.
 * @see SocketSYNProtect_cleanup() for eviction of stale states.
 */
typedef struct SocketSYN_IPState {
  char ip[SOCKET_IP_MAX_LEN];           /**< Null-terminated IP address string (IPv4/IPv6). */
  int64_t window_start_ms;              /**< Start timestamp (ms) of current rate window. */
  uint32_t attempts_current;            /**< Connection attempts in current sliding window. */
  uint32_t attempts_previous;           /**< Attempts from previous window (used for decay calculation). */
  uint32_t successes;                   /**< Cumulative successful handshakes/connections. */
  uint32_t failures;                    /**< Cumulative failed or aborted connections. */
  int64_t last_attempt_ms;              /**< Timestamp (ms) of most recent connection attempt. */
  int64_t block_until_ms;               /**< Block expiration timestamp (0 = not blocked; CLOCK_MONOTONIC ms). */
  SocketSYN_Reputation rep;             /**< Current computed reputation level. */
  float score;                          /**< Dynamic reputation score (0.0 = hostile, 1.0 = trusted). */
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
 * and resource constraints. Use SocketSYNProtect_config_defaults() to initialize.
 * Timing values in ms (except challenge_defer_sec in seconds). Scores in [0.0f, 1.0f].
 *
 * @warning Invalid configs (e.g., zero/negative durations, scores out of range)
 * may lead to undefined behavior or SocketSYNProtect_Failed exceptions.
 *
 * @see SocketSYNProtect_config_defaults() for safe initialization.
 * @see SocketSYNProtect_new() consumes this config.
 * @see SocketSYNProtect_configure() for dynamic reconfiguration.
 */
typedef struct SocketSYNProtect_Config
{
  /* === Window Settings === */
  int window_duration_ms; /**< Sliding window size (default: 10000ms) */

  /* === Rate Thresholds === */
  int max_attempts_per_window; /**< Per-IP attempt limit per window */
  int max_global_per_second;   /**< Global rate limit (all IPs) */
  float min_success_ratio;     /**< Min success/attempt ratio before suspect */

  /* === Response Tuning === */
  int throttle_delay_ms;   /**< Artificial delay for THROTTLE action */
  int block_duration_ms;   /**< Duration of automatic blocks */
  int challenge_defer_sec; /**< TCP_DEFER_ACCEPT timeout in seconds */

  /* === Score Thresholds === */
  float score_throttle;  /**< Score below this triggers THROTTLE */
  float score_challenge; /**< Score below this triggers CHALLENGE */
  float score_block;     /**< Score below this triggers BLOCK */

  /* === Score Adjustment Rates === */
  float score_decay_per_sec;   /**< Score recovery rate per second */
  float score_penalty_attempt; /**< Score penalty per new attempt */
  float score_penalty_failure; /**< Score penalty per failure */
  float score_reward_success;  /**< Score reward per successful connection */

  /* === Memory Management === */
  size_t max_tracked_ips; /**< Maximum IPs to track (LRU eviction) */
  size_t max_whitelist;   /**< Maximum whitelist entries */
  size_t max_blacklist;   /**< Maximum blacklist entries */
  unsigned
      hash_seed; /**< Hash randomization seed (0 = auto-generate crypto random
                    for collision resistance; affects synprotect_hash_ip) */
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
 * @note Counters wrap around at UINT64_MAX; suitable for 100+ years of activity.
 * @see SocketSYNProtect_stats() to populate this structure.
 * @see SocketSYNProtect_stats_reset() to zero counters (except uptime).
 */
typedef struct SocketSYNProtect_Stats
{
  uint64_t total_attempts;      /**< Total connection attempts checked */
  uint64_t total_allowed;       /**< Attempts allowed (SYN_ACTION_ALLOW) */
  uint64_t total_throttled;     /**< Attempts throttled */
  uint64_t total_challenged;    /**< Attempts challenged (TCP_DEFER_ACCEPT) */
  uint64_t total_blocked;       /**< Attempts blocked */
  uint64_t total_whitelisted;   /**< Attempts from whitelisted IPs */
  uint64_t total_blacklisted;   /**< Attempts from blacklisted IPs */
  uint64_t current_tracked_ips; /**< Currently tracked unique IPs */
  uint64_t current_blocked_ips; /**< Currently blocked IPs */
  uint64_t lru_evictions;       /**< Number of LRU evictions */
  int64_t uptime_ms;            /**< Time since initialization */
} SocketSYNProtect_Stats;

/* ============================================================================
 * Lifecycle Functions
 * ============================================================================
 */

/**
 * @brief Create a new instance of SYN protection.
 * @ingroup security
 * @param arena Memory arena for internal allocations (NULL = use malloc/free).
 * @param config Protection configuration (NULL = defaults).
 *
 * Allocates internal structures: hash tables for IP tracking, mutexes for thread safety,
 * timer wheels for window management, and lists for whitelists/blacklists.
 *
 * @return New SocketSYNProtect_T or NULL on failure.
 * @throws SocketSYNProtect_Failed Allocation or initialization failure.
 * @threadsafe Yes - creates independent instance; safe from any thread.
 *
 * @see SocketSYNProtect_config_defaults() to set up config.
 * @see SocketSYNProtect_free() for disposal.
 * @see SocketSYNProtect_configure() for runtime config changes.
 * @see docs/SECURITY.md for security considerations.
 */
extern T SocketSYNProtect_new(Arena_T arena, const SocketSYNProtect_Config *config);

/**
 * @brief Dispose of a SYN protection instance.
 * @ingroup security
 * @param protect Pointer to instance (set to NULL on success).
 *
 * Releases all internal resources: hash tables, mutexes, lists.
 * If created with arena=NULL (malloc), frees memory; otherwise, just clears pointers
 * (arena dispose will free).
 *
 * @note Safe to call on NULL pointer (no-op).
 * @threadsafe Yes - locks internal mutex during cleanup.
 *
 * @see SocketSYNProtect_new() for creation.
 * @see Arena_dispose() for arena-managed cleanup.
 * @see SocketSYNProtect_clear_all() to clear state without freeing instance.
 */
extern void SocketSYNProtect_free(T *protect);

/**
 * @brief Initialize configuration structure with safe defaults.
 * @ingroup security
 * @param config Pointer to config structure to populate.
 *
 * Sets reasonable defaults for production use:
 * - window_duration_ms = 10000
 * - max_attempts_per_window = 100
 * - ... (see SocketSYNProtect_Config fields for values)
 *
 * @note Defaults are conservative; tune for your traffic patterns.
 * @threadsafe Yes - pure function, no shared state.
 *
 * @see SocketSYNProtect_Config for parameter details.
 * @see SocketSYNProtect_new() which uses these defaults if config=NULL.
 */
extern void SocketSYNProtect_config_defaults(SocketSYNProtect_Config *config);

/**
 * @brief Update protection configuration during runtime.
 * @ingroup security
 * @param protect Active protection instance.
 * @param config New configuration to apply.
 *
 * Atomically updates internal parameters like thresholds, delays, and limits.
 * Existing tracked IPs, blocks, and whitelists unchanged; new behavior applies
 * to future checks.
 *
 * @note Some changes (e.g., max_tracked_ips) may trigger cleanup/eviction.
 * @threadsafe Yes - mutex-protected update.
 *
 * @throws SocketSYNProtect_Failed if invalid config values.
 * @see SocketSYNProtect_new() initial config.
 * @see SocketSYNProtect_config_defaults() for base values.
 * @see SocketSYNProtect_Config for tunable parameters.
 */
extern void SocketSYNProtect_configure(T protect, const SocketSYNProtect_Config *config);

/* ============================================================================
 * Core Protection Functions
 * ============================================================================
 */

/**
 * @brief Evaluate client IP and determine protection action.
 * @ingroup security
 * @param protect Protection instance.
 * @param client_ip Null-terminated IP string (IPv4/IPv6) or NULL.
 * @param state_out Optional output for detailed IP state (may be NULL).
 *
 * Performs comprehensive check: whitelist/blacklist lookup, rate limiting,
 * reputation scoring, global limits. Increments attempt counter.
 *
 * Returns SYN_ACTION_ALLOW if client_ip NULL/empty or whitelisted.
 *
 * @return Recommended action: ALLOW, THROTTLE, CHALLENGE, or BLOCK.
 * @threadsafe Yes - internal mutex protects shared state.
 *
 * @note Call before Socket_accept() or SocketPool_accept_limited().
 * @see SocketSYNProtect_report_success() after successful handshake.
 * @see SocketSYNProtect_report_failure() on connection errors.
 * @see SocketSYN_Action for action meanings.
 * @see SocketPool_set_syn_protection() for pool integration.
 */
extern SocketSYN_Action SocketSYNProtect_check(T protect, const char *client_ip, SocketSYN_IPState *state_out);

/**
 * @brief Report successful connection completion for IP reputation update.
 * @ingroup security
 * @param protect Protection instance.
 * @param client_ip IP of the successful connection.
 *
 * Increments success counter, applies score reward, potentially improves
 * reputation, and may lift blocks or reduce throttling for the IP.
 *
 * Call after full TCP handshake and initial data exchange succeeds.
 * No-op if IP not tracked or whitelisted.
 *
 * @threadsafe Yes - mutex protected.
 *
 * @see SocketSYNProtect_report_failure() for failures.
 * @see SocketSYN_IPState::successes for tracking.
 * @see SocketSYNProtect_Config::score_reward_success tuning.
 */
extern void SocketSYNProtect_report_success(T protect, const char *client_ip);

/**
 * @brief SocketSYNProtect_report_failure - Report connection failure
 * @protect: Protection instance
 * @client_ip: Client IP address string
 * @error_code: errno value from failed operation (0 if unknown)
 *
 * @brief Thread-safe: Yes - uses internal mutex
 *
 * Call this when a connection fails during or after accept (e.g., ECONNRESET,
 * ETIMEDOUT, or immediate disconnect). Penalizes the IP's reputation score.
 */
extern void SocketSYNProtect_report_failure (T protect, const char *client_ip,
                                             int error_code);

/* ============================================================================
 * Whitelist Management
 * ============================================================================
 */

/**
 * @brief SocketSYNProtect_whitelist_add - Add IP to whitelist
 * @protect: Protection instance
 * @ip: IP address string (IPv4 or IPv6)
 *
 * Returns: 1 on success, 0 if whitelist is full
 * @brief Thread-safe: Yes
 *
 * Whitelisted IPs always receive SYN_ACTION_ALLOW.
 */
extern int SocketSYNProtect_whitelist_add (T protect, const char *ip);

/**
 * @brief SocketSYNProtect_whitelist_add_cidr - Add CIDR range to whitelist
 * @protect: Protection instance
 * @cidr: CIDR notation (e.g., "10.0.0.0/8", "2001:db8::/32")
 *
 * Returns: 1 on success, 0 on error or whitelist full
 * @brief Thread-safe: Yes
 */
extern int SocketSYNProtect_whitelist_add_cidr (T protect, const char *cidr);

/**
 * @brief SocketSYNProtect_whitelist_remove - Remove IP from whitelist
 * @protect: Protection instance
 * @ip: IP address string
 *
 * @brief Thread-safe: Yes
 */
extern void SocketSYNProtect_whitelist_remove (T protect, const char *ip);

/**
 * @brief SocketSYNProtect_whitelist_contains - Check if IP is whitelisted
 * @protect: Protection instance
 * @ip: IP address string to check
 *
 * Returns: 1 if whitelisted, 0 otherwise
 * @brief Thread-safe: Yes
 */
extern int SocketSYNProtect_whitelist_contains (T protect, const char *ip);

/**
 * @brief SocketSYNProtect_whitelist_clear - Clear all whitelist entries
 * @protect: Protection instance
 *
 * @brief Thread-safe: Yes
 */
extern void SocketSYNProtect_whitelist_clear (T protect);

/* ============================================================================
 * Blacklist Management
 * ============================================================================
 */

/**
 * @brief SocketSYNProtect_blacklist_add - Add IP to blacklist
 * @protect: Protection instance
 * @ip: IP address string
 * @duration_ms: Block duration (0 = permanent until removed)
 *
 * Returns: 1 on success, 0 if blacklist is full
 * @brief Thread-safe: Yes
 *
 * Blacklisted IPs always receive SYN_ACTION_BLOCK.
 */
extern int SocketSYNProtect_blacklist_add (T protect, const char *ip,
                                           int duration_ms);

/**
 * @brief SocketSYNProtect_blacklist_remove - Remove IP from blacklist
 * @protect: Protection instance
 * @ip: IP address string
 *
 * @brief Thread-safe: Yes
 */
extern void SocketSYNProtect_blacklist_remove (T protect, const char *ip);

/**
 * @brief SocketSYNProtect_blacklist_contains - Check if IP is blacklisted
 * @protect: Protection instance
 * @ip: IP address string to check
 *
 * Returns: 1 if blacklisted, 0 otherwise
 * @brief Thread-safe: Yes
 *
 * Returns 0 if blacklist entry has expired.
 */
extern int SocketSYNProtect_blacklist_contains (T protect, const char *ip);

/**
 * @brief SocketSYNProtect_blacklist_clear - Clear all blacklist entries
 * @protect: Protection instance
 *
 * @brief Thread-safe: Yes
 */
extern void SocketSYNProtect_blacklist_clear (T protect);

/* ============================================================================
 * Query and Statistics Functions
 * ============================================================================
 */

/**
 * @brief SocketSYNProtect_get_ip_state - Get current state for an IP
 * @protect: Protection instance
 * @ip: IP address string
 * @state: Output structure for IP state
 *
 * Returns: 1 if IP found and state populated, 0 if not tracked
 * @brief Thread-safe: Yes
 */
extern int SocketSYNProtect_get_ip_state (T protect, const char *ip,
                                          SocketSYN_IPState *state);

/**
 * @brief SocketSYNProtect_stats - Get protection statistics
 * @protect: Protection instance
 * @stats: Output structure for statistics
 *
 * @brief Thread-safe: Yes - returns atomic snapshot
 */
extern void SocketSYNProtect_stats (T protect, SocketSYNProtect_Stats *stats);

/**
 * @brief SocketSYNProtect_stats_reset - Reset statistics counters
 * @protect: Protection instance
 *
 * @brief Thread-safe: Yes
 *
 * Resets all counters except uptime and current_tracked_ips.
 */
extern void SocketSYNProtect_stats_reset (T protect);

/**
 * @brief SocketSYNProtect_action_name - Get string name for action
 * @action: Action enum value
 *
 * Returns: Static string with action name
 * @brief Thread-safe: Yes
 */
extern const char *SocketSYNProtect_action_name (SocketSYN_Action action);

/**
 * @brief SocketSYNProtect_reputation_name - Get string name for reputation
 * @rep: Reputation enum value
 *
 * Returns: Static string with reputation name
 * @brief Thread-safe: Yes
 */
extern const char *SocketSYNProtect_reputation_name (SocketSYN_Reputation rep);

/* ============================================================================
 * Maintenance Functions
 * ============================================================================
 */

/**
 * @brief SocketSYNProtect_cleanup - Remove expired entries
 * @protect: Protection instance
 *
 * Returns: Number of entries removed
 * @brief Thread-safe: Yes
 *
 * Call periodically to:
 * - Remove expired blacklist entries
 * - Evict stale IP entries (LRU) when at capacity
 * - Clear temporary blocks
 *
 * Recommended: Call every 1-10 seconds in your event loop.
 */
extern size_t SocketSYNProtect_cleanup (T protect);

/**
 * @brief SocketSYNProtect_clear_all - Clear all tracked state
 * @protect: Protection instance
 *
 * @brief Thread-safe: Yes
 *
 * Clears all IP tracking entries but preserves whitelist and blacklist.
 */
extern void SocketSYNProtect_clear_all (T protect);

/**
 * @brief SocketSYNProtect_reset - Full reset to initial state
 * @protect: Protection instance
 *
 * @brief Thread-safe: Yes
 *
 * Clears everything: tracked IPs, whitelist, blacklist, and statistics.
 */
extern void SocketSYNProtect_reset (T protect);

#undef T
#endif /* SOCKETSYNPROTECT_INCLUDED */
