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
 * ============================================================================ */

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
 * ============================================================================ */

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
 * ============================================================================ */

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
 * ============================================================================ */

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
 /* Window Settings */
  int window_duration_ms; /**< Sliding window size (default: 10000ms). */

 /* Rate Thresholds */
  int max_attempts_per_window; /**< Per-IP attempt limit per window. */
  int max_global_per_second;   /**< Global rate limit (all IPs). */
  float min_success_ratio;     /**< Min success/attempt ratio before suspect. */

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
 * ============================================================================ */

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
 * ============================================================================ */

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
 * ============================================================================ */

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
 * @brief Report connection failure for IP reputation update.
 * @ingroup security
 * @param protect Protection instance.
 * @param client_ip IP of the failed connection.
 * @param error_code errno value from failed operation (0 if unknown).
 *
 * Increments failure counter, applies score penalty, potentially degrades
 * reputation, and may trigger blocks or increased throttling for the IP.
 *
 * Call after connection failure during or after accept (e.g., ECONNRESET,
 * ETIMEDOUT, or immediate disconnect). No-op if IP not tracked or whitelisted.
 *
 * @threadsafe Yes - mutex protected.
 *
 * @see SocketSYNProtect_report_success() for successful connections.
 * @see SocketSYNProtect_check() which may block based on accumulated failures.
 * @see SocketSYN_IPState::failures for cumulative failure count.
 * @see SocketSYNProtect_Config::score_penalty_failure for tuning the penalty.
 */
extern void SocketSYNProtect_report_failure(T protect, const char *client_ip,
                                            int error_code);

/* ============================================================================
 * Whitelist Management
 * ============================================================================ */

/**
 * @brief Add an IP address to the whitelist.
 * @ingroup security
 * @param protect Protection instance.
 * @param ip Null-terminated IP address string (IPv4 or IPv6).
 *
 * Whitelisted IPs bypass rate limits, reputation checks, and always receive
 * SYN_ACTION_ALLOW regardless of behavior.
 *
 * @return 1 on success (added or already present), 0 if whitelist is full.
 * @threadsafe Yes - mutex protected update.
 *
 * @see SocketSYNProtect_whitelist_contains() to verify membership.
 * @see SocketSYNProtect_whitelist_remove() to remove an entry.
 * @see SocketSYNProtect_whitelist_add_cidr() for adding CIDR ranges.
 * @see SocketSYNProtect_Config::max_whitelist for maximum size.
 */
extern int SocketSYNProtect_whitelist_add(T protect, const char *ip);

/**
 * @brief Add a CIDR range to the whitelist.
 * @ingroup security
 * @param protect Protection instance.
 * @param cidr CIDR notation string (e.g., "10.0.0.0/8", "2001:db8::/32").
 *
 * Matches any IP within the specified prefix length for IPv4/IPv6.
 * Whitelisted ranges bypass rate limits and reputation checks, always allowing connections.
 *
 * @return 1 on success (added or already present), 0 on parse error or if full.
 * @threadsafe Yes - mutex protected.
 *
 * @see SocketSYNProtect_whitelist_add() for single IP addresses.
 * @see SocketSYNProtect_whitelist_contains() for membership check with CIDR support.
 * @see SocketSYNProtect_Config::max_whitelist for capacity limit.
 */
extern int SocketSYNProtect_whitelist_add_cidr(T protect, const char *cidr);

/**
 * @brief Remove an IP address from the whitelist.
 * @ingroup security
 * @param protect Protection instance.
 * @param ip Null-terminated IP address string to remove (IPv4 or IPv6).
 *
 * Removes exact IP match or any CIDR entry containing this IP.
 * No-op if IP not found in whitelist.
 *
 * @threadsafe Yes - mutex protected.
 *
 * @see SocketSYNProtect_whitelist_add() and SocketSYNProtect_whitelist_add_cidr() for adding.
 * @see SocketSYNProtect_whitelist_contains() to verify removal.
 */
extern void SocketSYNProtect_whitelist_remove(T protect, const char *ip);

/**
 * @brief Check if an IP address is whitelisted.
 * @ingroup security
 * @param protect Protection instance.
 * @param ip Null-terminated IP address string to check.
 *
 * Returns true if IP matches any whitelist entry (exact or CIDR range),
 * meaning it bypasses all SYN protection checks.
 *
 * @return 1 if whitelisted, 0 otherwise.
 * @threadsafe Yes - read-only, mutex protected.
 *
 * @see SocketSYNProtect_whitelist_add() and SocketSYNProtect_whitelist_add_cidr() for adding entries.
 * @see SocketSYNProtect_whitelist_remove() for removal.
 * @see SocketSYNProtect_check() which uses this internally.
 */
extern int SocketSYNProtect_whitelist_contains(T protect, const char *ip);

/**
 * @brief Clear all whitelist entries.
 * @ingroup security
 * @param protect Protection instance.
 *
 * Removes all individual IPs and CIDR ranges from the whitelist.
 * Future connections from previously whitelisted sources will now be subject
 * to rate limiting and reputation checks.
 *
 * @threadsafe Yes - mutex protected.
 *
 * @see SocketSYNProtect_whitelist_add() and SocketSYNProtect_whitelist_add_cidr() to add new entries.
 * @see SocketSYNProtect_blacklist_clear() for clearing blacklists.
 * @see SocketSYNProtect_clear_all() which clears tracking state but preserves lists unless specified.
 */
extern void SocketSYNProtect_whitelist_clear(T protect);

/* ============================================================================
 * Blacklist Management
 * ============================================================================ */

/**
 * @brief Add an IP address to the blacklist.
 * @ingroup security
 * @param protect Protection instance.
 * @param ip Null-terminated IP address string (IPv4 or IPv6).
 * @param duration_ms Block duration in milliseconds (0 = permanent until removed).
 *
 * Blacklisted IPs receive SYN_ACTION_BLOCK immediately on check(), preventing
 * connection acceptance. Supports temporary blocks that auto-expire.
 *
 * @return 1 on success (added or extended if temporary), 0 if full.
 * @threadsafe Yes - mutex protected.
 *
 * @see SocketSYNProtect_blacklist_contains() to check if still blacklisted.
 * @see SocketSYNProtect_blacklist_remove() for manual removal.
 * @see SocketSYNProtect_Config::max_blacklist for maximum entries.
 * @see SocketSYNProtect_cleanup() which expires temporary blocks.
 */
extern int SocketSYNProtect_blacklist_add(T protect, const char *ip,
                                          int duration_ms);

/**
 * @brief Remove an IP address from the blacklist.
 * @ingroup security
 * @param protect Protection instance.
 * @param ip Null-terminated IP address string to remove (IPv4 or IPv6).
 *
 * Immediately unblocks the IP, allowing subsequent connection attempts to
 * be processed through normal rate limiting and reputation scoring.
 * No-op if IP not currently blacklisted.
 *
 * @threadsafe Yes - mutex protected.
 *
 * @see SocketSYNProtect_blacklist_add() to block IPs.
 * @see SocketSYNProtect_blacklist_contains() to check status post-removal.
 * @see SocketSYNProtect_cleanup() for automatic expiration of temporary blocks.
 */
extern void SocketSYNProtect_blacklist_remove(T protect, const char *ip);

/**
 * @brief Check if an IP address is currently blacklisted.
 * @ingroup security
 * @param protect Protection instance.
 * @param ip Null-terminated IP address string to check (IPv4 or IPv6).
 *
 * Determines if the IP is actively blacklisted, which would cause
 * SocketSYNProtect_check() to return SYN_ACTION_BLOCK.
 * Expired temporary blocks return false.
 *
 * @return 1 if blacklisted and not expired, 0 otherwise.
 * @threadsafe Yes - read-only, mutex protected.
 *
 * @see SocketSYNProtect_blacklist_add() to add with optional expiration.
 * @see SocketSYNProtect_blacklist_remove() for immediate unblock.
 * @see SocketSYNProtect_cleanup() for periodic expiration checks.
 * @see SocketSYNProtect_check() which consults blacklist first.
 */
extern int SocketSYNProtect_blacklist_contains(T protect, const char *ip);

/**
 * @brief Clear all blacklist entries.
 * @ingroup security
 * @param protect Protection instance.
 *
 * Removes all individual IP blocks, both temporary and permanent.
 * Previously blacklisted IPs can now be accepted based on other criteria
 * like rate limits and reputation.
 *
 * @threadsafe Yes - mutex protected.
 *
 * @see SocketSYNProtect_blacklist_add() to add new blocks.
 * @see SocketSYNProtect_whitelist_clear() for whitelist clearing.
 * @see SocketSYNProtect_reset() for full reset including lists.
 * @see SocketSYNProtect_clear_all() which may also affect blacklists.
 */
extern void SocketSYNProtect_blacklist_clear(T protect);

/* ============================================================================
 * Query and Statistics Functions
 * ============================================================================ */

/**
 * @brief Retrieve the current state and reputation metrics for a specific IP address.
 * @ingroup security
 * @param protect Protection instance.
 * @param ip IP address string (IPv4 or IPv6).
 * @param state Output structure for IP state (populated if tracked).
 *
 * Provides read-only snapshot of tracked data including attempt counts, score, and block status.
 * Does not modify internal state or counters.
 * No-op (returns 0, state unchanged) if IP not currently tracked.
 *
 * @return 1 if IP was found and state populated, 0 otherwise.
 * @threadsafe Yes - mutex-protected read snapshot.
 *
 * @see SocketSYNProtect_check() for state updates during evaluation.
 * @see SocketSYNProtect_report_success() and SocketSYNProtect_report_failure() for counter updates.
 * @see SocketSYN_IPState for structure details and interpretation.
 * @see SocketSYNProtect_cleanup() which may evict old states.
 */
extern int SocketSYNProtect_get_ip_state (T protect, const char *ip,
                                          SocketSYN_IPState *state);

/**
 * @brief Retrieve aggregate statistics snapshot for the SYN protection module.
 * @ingroup security
 * @param protect Protection instance.
 * @param stats Output structure populated with current metrics.
 *
 * Provides lock-free atomic snapshot of key counters: attempts, actions, tracked/blocked IPs,
 * evictions, and uptime. Excludes sensitive per-IP data and list contents for privacy.
 * Suitable for monitoring and logging.
 *
 * @threadsafe Yes - uses atomic variables for concurrent-safe reads.
 *
 * @see SocketSYNProtect_Stats structure for detailed field descriptions.
 * @see SocketSYNProtect_stats_reset() to reset counters (uptime preserved).
 * @see SocketSYNProtect_cleanup() which updates eviction and cleanup-related stats.
 */
extern void SocketSYNProtect_stats (T protect, SocketSYNProtect_Stats *stats);

/**
 * @brief Reset all resettable statistics counters to zero.
 * @ingroup security
 * @param protect Protection instance.
 *
 * Clears all cumulative counters (attempts, actions, evictions, etc.) but does not
 * affect uptime_ms, current_tracked_ips, or any tracked state/whitelists/blacklists.
 * Used for clean reporting periods or test resets.
 *
 * @threadsafe Yes - mutex protected.
 *
 * @see SocketSYNProtect_stats() to view affected fields.
 * @see SocketSYNProtect_Stats structure for reset behavior.
 * @see SocketSYNProtect_reset() for full instance reset including state.
 */
extern void SocketSYNProtect_stats_reset (T protect);

/**
 * @brief Convert SYN action enum to human-readable string.
 * @ingroup security
 * @param action Action enum value to name.
 *
 * Returns static constant string for logging, debugging, or display purposes.
 * Examples: "ALLOW", "THROTTLE", "CHALLENGE", "BLOCK".
 * No memory allocation or deallocation required.
 *
 * @return Pointer to static null-terminated string name.
 * @threadsafe Yes - returns constant data, pure function.
 *
 * @see SocketSYN_Action for enum values and meanings.
 * @see SocketSYNProtect_reputation_name() analogous for reputation levels.
 * @see SocketSYNProtect_check() produces actions used with this function.
 */
extern const char *SocketSYNProtect_action_name (SocketSYN_Action action);

/**
 * @brief Convert reputation enum to human-readable string.
 * @ingroup security
 * @param rep Reputation enum value to name.
 *
 * Returns static constant string for logging or display.
 * Examples: "TRUSTED", "NEUTRAL", "SUSPECT", "HOSTILE".
 *
 * @return Pointer to static null-terminated string name.
 * @threadsafe Yes - pure function returning constants.
 *
 * @see SocketSYN_Reputation for enum values and criteria.
 * @see SocketSYNProtect_action_name() analogous for actions.
 * @see SocketSYN_IPState::rep for per-IP reputation storage.
 */
extern const char *SocketSYNProtect_reputation_name (SocketSYN_Reputation rep);

/* ============================================================================
 * Maintenance Functions
 * ============================================================================ */

/**
 * @brief Perform periodic cleanup of expired and stale protection state.
 * @ingroup security
 * @param protect Protection instance.
 *
 * Handles:
 * - Expiration of temporary blacklists and blocks
 * - LRU eviction of IP states when max_tracked_ips reached
 * - Reputation score decay
 * - Sliding window advancement for rate limits
 *
 * Returns count of IP states removed or evicted.
 *
 * Recommended frequency: every 1-10 seconds via timer or event loop tick.
 *
 * @return Number of IP entries cleaned up (evicted or expired).
 * @threadsafe Yes - mutex protected.
 *
 * @see SocketSYNProtect_Config::max_tracked_ips for eviction threshold.
 * @see SocketSYNProtect_clear_all() for immediate full cleanup.
 * @see SocketSYNProtect_Config::window_duration_ms for window sliding.
 * @see SocketSYNProtect_Config::score_decay_per_sec for decay application.
 */
extern size_t SocketSYNProtect_cleanup(T protect);

/**
 * @brief Clear all tracked IP states without affecting lists or stats.
 * @ingroup security
 * @param protect Protection instance.
 *
 * Evicts all per-IP state data (rates, reputation, blocks) from internal tables.
 * Whitelists, blacklists, and global statistics remain unchanged.
 * Helps reduce memory usage during idle periods or after attacks.
 *
 * @threadsafe Yes - mutex protected.
 *
 * @see SocketSYNProtect_cleanup() for incremental cleanup.
 * @see SocketSYNProtect_reset() for total reset.
 * @see SocketSYNProtect_whitelist_clear() and SocketSYNProtect_blacklist_clear() for list management.
 * @see SocketSYNProtect_stats_reset() for stats only.
 */
extern void SocketSYNProtect_clear_all(T protect);

/**
 * @brief Perform full reset of the SYN protection instance to initial state.
 * @ingroup security
 * @param protect Protection instance.
 *
 * Clears all internal state including IP tracking, whitelists, blacklists,
 * temporary blocks, and resets all statistics counters (uptime preserved).
 * After reset, behavior reverts to current config as if newly created.
 *
 * @threadsafe Yes - mutex protected.
 *
 * @see SocketSYNProtect_new() and SocketSYNProtect_free() for lifecycle management.
 * @see SocketSYNProtect_clear_all() for partial clear (keeps lists).
 * @see SocketSYNProtect_configure() to update config without clearing state.
 * @see SocketSYNProtect_stats_reset() for stats only.
 */
extern void SocketSYNProtect_reset(T protect);

#undef T
#endif /* SOCKETSYNPROTECT_INCLUDED */
