#ifndef SOCKETSYNPROTECT_INCLUDED
#define SOCKETSYNPROTECT_INCLUDED

/**
 * SocketSYNProtect.h - SYN Flood Protection Module
 *
 * Part of the Socket Library
 *
 * Provides comprehensive SYN flood attack protection through:
 * - Connection attempt tracking (not just established connections)
 * - Time-windowed sliding counters for accurate rate measurement
 * - Adaptive IP reputation scoring with decay
 * - Automatic response actions (allow/throttle/challenge/block)
 * - Whitelist/blacklist support with CIDR notation
 * - Integration with kernel-level socket options (TCP_DEFER_ACCEPT)
 *
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - CLOCK_MONOTONIC support for timing
 * - POSIX threads (pthread) for thread safety
 *
 * Thread Safety:
 * - All operations are thread-safe via internal mutex
 * - Safe to share a single instance across threads
 *
 * Usage:
 *   SocketSYNProtect_Config config;
 *   SocketSYNProtect_config_defaults(&config);
 *   config.max_attempts_per_window = 30;
 *
 *   SocketSYNProtect_T protect = SocketSYNProtect_new(arena, &config);
 *   SocketSYNProtect_whitelist_add_cidr(protect, "10.0.0.0/8");
 *
 *   // Before accept():
 *   SocketSYN_Action action = SocketSYNProtect_check(protect, client_ip, NULL);
 *   if (action == SYN_ACTION_BLOCK) {
 *       close(client_fd);
 *       continue;
 *   }
 *
 *   // After successful accept:
 *   SocketSYNProtect_report_success(protect, client_ip);
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

extern const Except_T SocketSYNProtect_Failed; /**< SYN protection failure */

/* ============================================================================
 * Action and Reputation Enums
 * ============================================================================ */

/**
 * SocketSYN_Action - Protection response actions
 *
 * Determines how to handle an incoming connection attempt based on
 * the IP's reputation and current rate limits.
 */
typedef enum SocketSYN_Action
{
  SYN_ACTION_ALLOW = 0,   /**< Normal accept - no restrictions */
  SYN_ACTION_THROTTLE,    /**< Accept with artificial delay */
  SYN_ACTION_CHALLENGE,   /**< Use TCP_DEFER_ACCEPT (require data) */
  SYN_ACTION_BLOCK        /**< Reject connection immediately */
} SocketSYN_Action;

/**
 * SocketSYN_Reputation - IP reputation states
 *
 * Tracks the trustworthiness of an IP based on historical behavior.
 */
typedef enum SocketSYN_Reputation
{
  SYN_REP_TRUSTED = 0, /**< Whitelisted or proven good behavior */
  SYN_REP_NEUTRAL,     /**< Unknown/new IP - default state */
  SYN_REP_SUSPECT,     /**< Elevated attempt rate detected */
  SYN_REP_HOSTILE      /**< Attack pattern detected */
} SocketSYN_Reputation;

/* ============================================================================
 * Per-IP State Structure
 * ============================================================================ */

/**
 * SocketSYN_IPState - Per-IP tracking state
 *
 * Contains all tracked information for a single IP address including
 * sliding window counters, success/failure ratios, and reputation score.
 */
typedef struct SocketSYN_IPState
{
  char ip[SOCKET_IP_MAX_LEN]; /**< IP address string */
  int64_t window_start_ms;    /**< Current sliding window start time */
  uint32_t attempts_current;  /**< Attempts in current window */
  uint32_t attempts_previous; /**< Attempts in previous window (for decay) */
  uint32_t successes;         /**< Total completed handshakes */
  uint32_t failures;          /**< Total failed/incomplete handshakes */
  int64_t last_attempt_ms;    /**< Timestamp of last attempt */
  int64_t block_until_ms;     /**< Block expiry timestamp (0 = not blocked) */
  SocketSYN_Reputation rep;   /**< Current reputation state */
  float score;                /**< Reputation score (0.0=hostile, 1.0=trusted) */
} SocketSYN_IPState;

/* ============================================================================
 * Configuration Structure
 * ============================================================================ */

/**
 * SocketSYNProtect_Config - Protection configuration
 *
 * All timing values are in milliseconds unless otherwise noted.
 * Threshold scores are floats in range [0.0, 1.0].
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
} SocketSYNProtect_Config;

/* ============================================================================
 * Statistics Structure
 * ============================================================================ */

/**
 * SocketSYNProtect_Stats - Protection statistics
 *
 * Thread-safe snapshot of protection activity counters.
 */
typedef struct SocketSYNProtect_Stats
{
  uint64_t total_attempts;     /**< Total connection attempts checked */
  uint64_t total_allowed;      /**< Attempts allowed (SYN_ACTION_ALLOW) */
  uint64_t total_throttled;    /**< Attempts throttled */
  uint64_t total_challenged;   /**< Attempts challenged (TCP_DEFER_ACCEPT) */
  uint64_t total_blocked;      /**< Attempts blocked */
  uint64_t total_whitelisted;  /**< Attempts from whitelisted IPs */
  uint64_t total_blacklisted;  /**< Attempts from blacklisted IPs */
  uint64_t current_tracked_ips; /**< Currently tracked unique IPs */
  uint64_t current_blocked_ips; /**< Currently blocked IPs */
  uint64_t lru_evictions;      /**< Number of LRU evictions */
  int64_t uptime_ms;           /**< Time since initialization */
} SocketSYNProtect_Stats;

/* ============================================================================
 * Lifecycle Functions
 * ============================================================================ */

/**
 * SocketSYNProtect_new - Create a new SYN protection instance
 * @arena: Arena for memory allocation (NULL to use malloc)
 * @config: Configuration (NULL for defaults)
 *
 * Returns: New protection instance
 * Raises: SocketSYNProtect_Failed on allocation failure
 * Thread-safe: Yes - returns new independent instance
 */
extern T SocketSYNProtect_new (Arena_T arena,
                               const SocketSYNProtect_Config *config);

/**
 * SocketSYNProtect_free - Free a SYN protection instance
 * @protect: Pointer to instance (will be set to NULL)
 *
 * Thread-safe: Yes
 *
 * Note: Only frees memory if allocated with malloc (arena == NULL).
 * Arena-allocated instances are freed when arena is disposed.
 */
extern void SocketSYNProtect_free (T *protect);

/**
 * SocketSYNProtect_config_defaults - Initialize config with defaults
 * @config: Configuration structure to initialize
 *
 * Thread-safe: Yes (no shared state)
 */
extern void SocketSYNProtect_config_defaults (SocketSYNProtect_Config *config);

/**
 * SocketSYNProtect_configure - Update configuration at runtime
 * @protect: Protection instance
 * @config: New configuration
 *
 * Thread-safe: Yes - uses internal mutex
 *
 * Does not affect currently blocked IPs or tracked states.
 */
extern void SocketSYNProtect_configure (T protect,
                                        const SocketSYNProtect_Config *config);

/* ============================================================================
 * Core Protection Functions
 * ============================================================================ */

/**
 * SocketSYNProtect_check - Check IP and determine action
 * @protect: Protection instance
 * @client_ip: Client IP address string
 * @state_out: Output for IP state (optional, may be NULL)
 *
 * Returns: Action to take (ALLOW, THROTTLE, CHALLENGE, or BLOCK)
 * Thread-safe: Yes - uses internal mutex
 *
 * Call this BEFORE accepting a connection to determine the appropriate
 * action. This increments the attempt counter for the IP.
 *
 * If client_ip is NULL or empty, returns SYN_ACTION_ALLOW.
 */
extern SocketSYN_Action SocketSYNProtect_check (T protect, const char *client_ip,
                                                SocketSYN_IPState *state_out);

/**
 * SocketSYNProtect_report_success - Report successful connection
 * @protect: Protection instance
 * @client_ip: Client IP address string
 *
 * Thread-safe: Yes - uses internal mutex
 *
 * Call this after a connection successfully completes the TCP handshake
 * and becomes usable. Rewards the IP's reputation score.
 */
extern void SocketSYNProtect_report_success (T protect, const char *client_ip);

/**
 * SocketSYNProtect_report_failure - Report connection failure
 * @protect: Protection instance
 * @client_ip: Client IP address string
 * @error_code: errno value from failed operation (0 if unknown)
 *
 * Thread-safe: Yes - uses internal mutex
 *
 * Call this when a connection fails during or after accept (e.g., ECONNRESET,
 * ETIMEDOUT, or immediate disconnect). Penalizes the IP's reputation score.
 */
extern void SocketSYNProtect_report_failure (T protect, const char *client_ip,
                                             int error_code);

/* ============================================================================
 * Whitelist Management
 * ============================================================================ */

/**
 * SocketSYNProtect_whitelist_add - Add IP to whitelist
 * @protect: Protection instance
 * @ip: IP address string (IPv4 or IPv6)
 *
 * Returns: 1 on success, 0 if whitelist is full
 * Thread-safe: Yes
 *
 * Whitelisted IPs always receive SYN_ACTION_ALLOW.
 */
extern int SocketSYNProtect_whitelist_add (T protect, const char *ip);

/**
 * SocketSYNProtect_whitelist_add_cidr - Add CIDR range to whitelist
 * @protect: Protection instance
 * @cidr: CIDR notation (e.g., "10.0.0.0/8", "2001:db8::/32")
 *
 * Returns: 1 on success, 0 on error or whitelist full
 * Thread-safe: Yes
 */
extern int SocketSYNProtect_whitelist_add_cidr (T protect, const char *cidr);

/**
 * SocketSYNProtect_whitelist_remove - Remove IP from whitelist
 * @protect: Protection instance
 * @ip: IP address string
 *
 * Thread-safe: Yes
 */
extern void SocketSYNProtect_whitelist_remove (T protect, const char *ip);

/**
 * SocketSYNProtect_whitelist_contains - Check if IP is whitelisted
 * @protect: Protection instance
 * @ip: IP address string to check
 *
 * Returns: 1 if whitelisted, 0 otherwise
 * Thread-safe: Yes
 */
extern int SocketSYNProtect_whitelist_contains (T protect, const char *ip);

/**
 * SocketSYNProtect_whitelist_clear - Clear all whitelist entries
 * @protect: Protection instance
 *
 * Thread-safe: Yes
 */
extern void SocketSYNProtect_whitelist_clear (T protect);

/* ============================================================================
 * Blacklist Management
 * ============================================================================ */

/**
 * SocketSYNProtect_blacklist_add - Add IP to blacklist
 * @protect: Protection instance
 * @ip: IP address string
 * @duration_ms: Block duration (0 = permanent until removed)
 *
 * Returns: 1 on success, 0 if blacklist is full
 * Thread-safe: Yes
 *
 * Blacklisted IPs always receive SYN_ACTION_BLOCK.
 */
extern int SocketSYNProtect_blacklist_add (T protect, const char *ip,
                                           int duration_ms);

/**
 * SocketSYNProtect_blacklist_remove - Remove IP from blacklist
 * @protect: Protection instance
 * @ip: IP address string
 *
 * Thread-safe: Yes
 */
extern void SocketSYNProtect_blacklist_remove (T protect, const char *ip);

/**
 * SocketSYNProtect_blacklist_contains - Check if IP is blacklisted
 * @protect: Protection instance
 * @ip: IP address string to check
 *
 * Returns: 1 if blacklisted, 0 otherwise
 * Thread-safe: Yes
 *
 * Returns 0 if blacklist entry has expired.
 */
extern int SocketSYNProtect_blacklist_contains (T protect, const char *ip);

/**
 * SocketSYNProtect_blacklist_clear - Clear all blacklist entries
 * @protect: Protection instance
 *
 * Thread-safe: Yes
 */
extern void SocketSYNProtect_blacklist_clear (T protect);

/* ============================================================================
 * Query and Statistics Functions
 * ============================================================================ */

/**
 * SocketSYNProtect_get_ip_state - Get current state for an IP
 * @protect: Protection instance
 * @ip: IP address string
 * @state: Output structure for IP state
 *
 * Returns: 1 if IP found and state populated, 0 if not tracked
 * Thread-safe: Yes
 */
extern int SocketSYNProtect_get_ip_state (T protect, const char *ip,
                                          SocketSYN_IPState *state);

/**
 * SocketSYNProtect_stats - Get protection statistics
 * @protect: Protection instance
 * @stats: Output structure for statistics
 *
 * Thread-safe: Yes - returns atomic snapshot
 */
extern void SocketSYNProtect_stats (T protect, SocketSYNProtect_Stats *stats);

/**
 * SocketSYNProtect_stats_reset - Reset statistics counters
 * @protect: Protection instance
 *
 * Thread-safe: Yes
 *
 * Resets all counters except uptime and current_tracked_ips.
 */
extern void SocketSYNProtect_stats_reset (T protect);

/**
 * SocketSYNProtect_action_name - Get string name for action
 * @action: Action enum value
 *
 * Returns: Static string with action name
 * Thread-safe: Yes
 */
extern const char *SocketSYNProtect_action_name (SocketSYN_Action action);

/**
 * SocketSYNProtect_reputation_name - Get string name for reputation
 * @rep: Reputation enum value
 *
 * Returns: Static string with reputation name
 * Thread-safe: Yes
 */
extern const char *SocketSYNProtect_reputation_name (SocketSYN_Reputation rep);

/* ============================================================================
 * Maintenance Functions
 * ============================================================================ */

/**
 * SocketSYNProtect_cleanup - Remove expired entries
 * @protect: Protection instance
 *
 * Returns: Number of entries removed
 * Thread-safe: Yes
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
 * SocketSYNProtect_clear_all - Clear all tracked state
 * @protect: Protection instance
 *
 * Thread-safe: Yes
 *
 * Clears all IP tracking entries but preserves whitelist and blacklist.
 */
extern void SocketSYNProtect_clear_all (T protect);

/**
 * SocketSYNProtect_reset - Full reset to initial state
 * @protect: Protection instance
 *
 * Thread-safe: Yes
 *
 * Clears everything: tracked IPs, whitelist, blacklist, and statistics.
 */
extern void SocketSYNProtect_reset (T protect);

#undef T
#endif /* SOCKETSYNPROTECT_INCLUDED */

