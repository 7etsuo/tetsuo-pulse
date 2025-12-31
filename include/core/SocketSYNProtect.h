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
 * @{
 */

/**
 * @file SocketSYNProtect.h
 * @ingroup security
 * @brief SYN flood protection using IP reputation and adaptive rate limiting.
 *
 * @code{.c}
 * SocketSYNProtect_T protect = SocketSYNProtect_new(NULL, NULL);
 *
 * SocketSYN_Action action = SocketSYNProtect_check(protect, client_ip, NULL);
 * if (action != SYN_ACTION_BLOCK) {
 *     Socket_T conn = Socket_accept(server);
 *     if (connection_successful(conn)) {
 *         SocketSYNProtect_report_success(protect, client_ip);
 *     } else {
 *         SocketSYNProtect_report_failure(protect, client_ip, errno);
 *     }
 * }
 * @endcode
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include <stddef.h>
#include <stdint.h>

#define T SocketSYNProtect_T
typedef struct T *T;

/**
 * @brief General SYN protection operation failure.
 *
 * Category: SYSTEM
 * Retryable: DEPENDS - often due to resource exhaustion; retry after cleanup.
 *
 * Raised for memory allocation failure, invalid configuration, internal data
 * structure corruption, or mutex acquisition failures.
 */
extern const Except_T SocketSYNProtect_Failed;

/**
 * @brief Protection response actions for SYN connection attempts.
 */
typedef enum SocketSYN_Action
{
  SYN_ACTION_ALLOW = 0,
  SYN_ACTION_THROTTLE,
  SYN_ACTION_CHALLENGE,
  SYN_ACTION_BLOCK
} SocketSYN_Action;

/**
 * @brief IP reputation levels based on behavior history.
 */
typedef enum SocketSYN_Reputation
{
  SYN_REP_TRUSTED = 0,
  SYN_REP_NEUTRAL,
  SYN_REP_SUSPECT,
  SYN_REP_HOSTILE
} SocketSYN_Reputation;

/**
 * @brief Per-IP address tracking and reputation state.
 *
 * Opaque structure holding all metrics and state for a single tracked IP.
 * Updated atomically for thread safety. Use reporting functions to update.
 */
typedef struct SocketSYN_IPState
{
  char ip[SOCKET_IP_MAX_LEN];
  int64_t window_start_ms;
  uint32_t attempts_current;
  uint32_t attempts_previous;
  uint32_t successes;
  uint32_t failures;
  int64_t last_attempt_ms;
  int64_t block_until_ms;
  SocketSYN_Reputation rep;
  float score;
} SocketSYN_IPState;

/**
 * @brief Configuration parameters for SYN flood protection.
 *
 * Timing values in ms (except challenge_defer_sec in seconds).
 * Scores in [0.0f, 1.0f].
 */
typedef struct SocketSYNProtect_Config
{
  int window_duration_ms;
  int max_attempts_per_window;
  int max_global_per_second;
  float min_success_ratio;
  int throttle_delay_ms;
  int block_duration_ms;
  int challenge_defer_sec;
  float score_throttle;
  float score_challenge;
  float score_block;
  float score_decay_per_sec;
  float score_penalty_attempt;
  float score_penalty_failure;
  float score_reward_success;
  size_t max_tracked_ips;
  size_t max_whitelist;
  size_t max_blacklist;
  unsigned hash_seed;
} SocketSYNProtect_Config;

/**
 * @brief Statistics snapshot for SYN protection activity.
 */
typedef struct SocketSYNProtect_Stats
{
  uint64_t total_attempts;
  uint64_t total_allowed;
  uint64_t total_throttled;
  uint64_t total_challenged;
  uint64_t total_blocked;
  uint64_t total_whitelisted;
  uint64_t total_blacklisted;
  uint64_t current_tracked_ips;
  uint64_t current_blocked_ips;
  uint64_t lru_evictions;
  int64_t uptime_ms;
} SocketSYNProtect_Stats;

/**
 * @brief Create a new instance of SYN protection.
 *
 * @param arena  Memory arena for allocations (NULL uses malloc/free)
 * @param config Protection configuration (NULL uses defaults)
 * Returns: New SocketSYNProtect_T instance
 * Raises: SocketSYNProtect_Failed on allocation or initialization failure
 *
 * @threadsafe Yes - creates independent instance
 * @complexity O(1)
 */
extern T
SocketSYNProtect_new (Arena_T arena, const SocketSYNProtect_Config *config);

/**
 * @brief Dispose of a SYN protection instance and release all resources.
 *
 * @param protect  Pointer to instance (set to NULL on success)
 *
 * @threadsafe Yes - acquires internal mutex during cleanup
 * @complexity O(n) - must clean up all tracked IPs and list entries
 */
extern void SocketSYNProtect_free (T *protect);

/**
 * @brief Initialize configuration structure with safe defaults.
 *
 * @param config  Pointer to config structure to populate with defaults
 *
 * @threadsafe Yes - pure function
 * @complexity O(1)
 */
extern void SocketSYNProtect_config_defaults (SocketSYNProtect_Config *config);

/**
 * @brief Update protection configuration during runtime.
 *
 * @param protect  Active protection instance
 * @param config   New configuration to apply
 * Raises: SocketSYNProtect_Failed if config contains invalid values
 *
 * @threadsafe Yes - mutex-protected atomic update
 * @complexity O(n) if max_tracked_ips reduced (triggers eviction), O(1)
 * otherwise
 */
extern void
SocketSYNProtect_configure (T protect, const SocketSYNProtect_Config *config);

/**
 * @brief Evaluate client IP and determine protection action.
 *
 * Performs comprehensive SYN flood protection evaluation for an incoming
 * connection attempt. Checks whitelist/blacklist, rate limits, reputation
 * scores, and applies appropriate protection actions.
 *
 * @param protect    Active protection instance
 * @param client_ip  Client IP address (IPv4/IPv6) or NULL/empty for
 * unconditional ALLOW
 * @param state_out  Optional output for detailed IP state information (may be
 * NULL) Returns: Protection action: SYN_ACTION_ALLOW, THROTTLE, CHALLENGE, or
 * BLOCK
 *
 * @threadsafe Yes - internal mutex protects all shared state modifications
 * @complexity O(1) average case - hash table lookups
 */
extern SocketSYN_Action SocketSYNProtect_check (T protect,
                                                const char *client_ip,
                                                SocketSYN_IPState *state_out);

/**
 * @brief Report successful connection completion for IP reputation update.
 *
 * @param protect    Active protection instance
 * @param client_ip  IP address of the successful connection (IPv4/IPv6)
 *
 * @threadsafe Yes - mutex-protected update operation
 * @complexity O(1) - hash table lookup and atomic update
 */
extern void SocketSYNProtect_report_success (T protect, const char *client_ip);

/**
 * @brief Report connection failure for IP reputation update.
 *
 * @param protect    Active protection instance
 * @param client_ip  IP address of the failed connection (IPv4/IPv6)
 * @param error_code errno value from failed operation (0 if unknown)
 *
 * @threadsafe Yes - mutex-protected update operation
 * @complexity O(1) - hash table lookup and atomic update
 */
extern void SocketSYNProtect_report_failure (T protect,
                                             const char *client_ip,
                                             int error_code);

/**
 * @brief Add an IP address to the whitelist.
 *
 * @param protect  Active protection instance
 * @param ip       Null-terminated IP address string (IPv4: "192.168.1.1", IPv6:
 * "2001:db8::1") Returns: 1 on success (added or already present), 0 if
 * whitelist is full
 *
 * @threadsafe Yes - mutex-protected update operation
 * @complexity O(1) average case - hash table insertion
 */
extern int SocketSYNProtect_whitelist_add (T protect, const char *ip);

/**
 * @brief Add a CIDR range to the whitelist.
 *
 * @param protect  Active protection instance
 * @param cidr     CIDR notation string (e.g., "10.0.0.0/8", "192.168.1.0/24",
 * "2001:db8::/32") Returns: 1 on success (added or already present), 0 on parse
 * error or whitelist full
 *
 * @threadsafe Yes - mutex-protected update operation
 * @complexity O(1)
 */
extern int SocketSYNProtect_whitelist_add_cidr (T protect, const char *cidr);

/**
 * @brief Remove an IP address from the whitelist.
 *
 * @param protect  Active protection instance
 * @param ip       Null-terminated IP address string to remove (IPv4 or IPv6)
 *
 * @threadsafe Yes - mutex-protected update operation
 * @complexity O(n) - may need to search CIDR entries
 */
extern void SocketSYNProtect_whitelist_remove (T protect, const char *ip);

/**
 * @brief Check if an IP address is whitelisted.
 *
 * @param protect  Active protection instance
 * @param ip       Null-terminated IP address string to check (IPv4 or IPv6)
 * Returns: 1 if whitelisted (exact match or within CIDR range), 0 otherwise
 *
 * @threadsafe Yes - read-only operation with mutex protection
 * @complexity O(n) worst case - checks exact matches then CIDR ranges
 */
extern int SocketSYNProtect_whitelist_contains (T protect, const char *ip);

/**
 * @brief Clear all whitelist entries.
 *
 * @param protect  Active protection instance
 *
 * @threadsafe Yes - mutex-protected update operation
 * @complexity O(n) - must free all whitelist entries
 */
extern void SocketSYNProtect_whitelist_clear (T protect);

/**
 * @brief Add an IP address to the blacklist.
 *
 * @param protect     Active protection instance
 * @param ip          Null-terminated IP address string (IPv4 or IPv6)
 * @param duration_ms Block duration: positive = temporary (auto-expires), 0 =
 * permanent Returns: 1 on success (added or duration extended), 0 if blacklist
 * is full
 *
 * @threadsafe Yes - mutex-protected update operation
 * @complexity O(1) average case - hash table insertion
 */
extern int
SocketSYNProtect_blacklist_add (T protect, const char *ip, int duration_ms);

/**
 * @brief Remove an IP address from the blacklist.
 *
 * @param protect  Active protection instance
 * @param ip       Null-terminated IP address string to unblock (IPv4 or IPv6)
 *
 * @threadsafe Yes - mutex-protected update operation
 * @complexity O(1) average case - hash table lookup and removal
 */
extern void SocketSYNProtect_blacklist_remove (T protect, const char *ip);

/**
 * @brief Check if an IP address is currently blacklisted.
 *
 * @param protect  Active protection instance
 * @param ip       Null-terminated IP address string to check (IPv4 or IPv6)
 * Returns: 1 if actively blacklisted (not expired), 0 otherwise
 *
 * @threadsafe Yes - read-only operation with mutex protection
 * @complexity O(1) average case - hash table lookup
 */
extern int SocketSYNProtect_blacklist_contains (T protect, const char *ip);

/**
 * @brief Clear all blacklist entries.
 *
 * @param protect  Active protection instance
 *
 * @threadsafe Yes - mutex-protected update operation
 * @complexity O(n) - must free all blacklist entries
 */
extern void SocketSYNProtect_blacklist_clear (T protect);

/**
 * @brief Retrieve the current state and reputation metrics for a specific IP
 * address.
 *
 * @param protect  Active protection instance
 * @param ip       IP address string to query (IPv4 or IPv6)
 * @param state    Output structure populated with IP state if found
 * Returns: 1 if IP found and state populated, 0 if IP not currently tracked
 *
 * @threadsafe Yes - mutex-protected atomic snapshot
 * @complexity O(1) average case - hash table lookup
 */
extern int SocketSYNProtect_get_ip_state (T protect,
                                          const char *ip,
                                          SocketSYN_IPState *state);

/**
 * @brief Retrieve aggregate statistics snapshot for the SYN protection module.
 *
 * @param protect  Active protection instance
 * @param stats    Output structure populated with current metrics
 *
 * @threadsafe Yes - atomic operations for consistent concurrent reads
 * @complexity O(1) - atomic reads of pre-computed values
 */
extern void SocketSYNProtect_stats (T protect, SocketSYNProtect_Stats *stats);

/**
 * @brief Reset all resettable statistics counters to zero.
 *
 * Clears cumulative counters (attempts, actions, evictions) while preserving
 * all tracked IP states, whitelists, blacklists, and uptime.
 *
 * @param protect  Active protection instance
 *
 * @threadsafe Yes - mutex-protected update operation
 * @complexity O(1) - atomic counter resets
 */
extern void SocketSYNProtect_stats_reset (T protect);

/**
 * @brief Convert SYN action enum to human-readable string.
 *
 * @param action  Action enum value to convert
 * Returns: Pointer to static null-terminated string ("ALLOW", "THROTTLE",
 * "CHALLENGE", "BLOCK")
 *
 * @threadsafe Yes - pure function returning constant data
 * @complexity O(1)
 */
extern const char *SocketSYNProtect_action_name (SocketSYN_Action action);

/**
 * @brief Convert reputation enum to human-readable string.
 *
 * @param rep  Reputation enum value to convert
 * Returns: Pointer to static null-terminated string ("TRUSTED", "NEUTRAL",
 * "SUSPECT", "HOSTILE")
 *
 * @threadsafe Yes - pure function returning constant data
 * @complexity O(1)
 */
extern const char *SocketSYNProtect_reputation_name (SocketSYN_Reputation rep);

/**
 * @brief Perform periodic cleanup of expired and stale protection state.
 *
 * Performs maintenance operations to keep the protection system efficient:
 * - Expire temporary blacklists and blocks
 * - Evict least-recently-used IP states when approaching max_tracked_ips
 * - Apply reputation score decay over time
 * - Advance sliding windows for rate limiting
 *
 * Call regularly (every 1-10 seconds) in event loops or background tasks.
 *
 * @param protect  Active protection instance
 * Returns: Number of IP entries cleaned up (evicted or expired)
 *
 * @threadsafe Yes - mutex-protected operation
 * @complexity O(n) worst case - must scan all tracked IPs, but typically much
 * faster
 */
extern size_t SocketSYNProtect_cleanup (T protect);

/**
 * @brief Clear all tracked IP states without affecting lists or stats.
 *
 * Evicts all per-IP tracking data including rate counters, reputation scores,
 * and temporary blocks. Whitelists, blacklists, and global statistics are
 * preserved.
 *
 * @param protect  Active protection instance
 *
 * @threadsafe Yes - mutex-protected update operation
 * @complexity O(n) - must free all tracked IP entries
 */
extern void SocketSYNProtect_clear_all (T protect);

/**
 * @brief Perform full reset of the SYN protection instance to initial state.
 *
 * Completely resets all internal state to as-if-newly-created condition.
 * Clears all tracked IPs, whitelists, blacklists, temporary blocks, and
 * statistics counters. Configuration and uptime are preserved.
 *
 * @param protect  Active protection instance
 *
 * @threadsafe Yes - mutex-protected update operation
 * @complexity O(n) - must free all entries from all internal tables
 */
extern void SocketSYNProtect_reset (T protect);

/** @} */

#undef T
#endif /* SOCKETSYNPROTECT_INCLUDED */
