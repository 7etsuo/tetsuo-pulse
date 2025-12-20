/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_SECURITY_INCLUDED
#define SOCKETSIMPLE_SECURITY_INCLUDED

/**
 * @file SocketSimple-security.h
 * @brief Simple security operations: SYN protection and IP tracking.
 *
 * Provides return-code based wrappers around SocketSYNProtect and
 * SocketIPTracker modules for SYN flood protection and per-IP
 * connection limiting.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * SYN Protection Types
 *============================================================================*/

/**
 * @brief Opaque SYN protection handle.
 */
typedef struct SocketSimple_SYNProtect *SocketSimple_SYNProtect_T;

/**
 * @brief Protection actions returned by check function.
 */
typedef enum {
    SOCKET_SIMPLE_SYN_ALLOW = 0,    /**< Allow: normal acceptance */
    SOCKET_SIMPLE_SYN_THROTTLE = 1, /**< Throttle: accept with delay */
    SOCKET_SIMPLE_SYN_CHALLENGE = 2, /**< Challenge: require data */
    SOCKET_SIMPLE_SYN_BLOCK = 3      /**< Block: reject connection */
} SocketSimple_SYNAction;

/**
 * @brief IP reputation levels.
 */
typedef enum {
    SOCKET_SIMPLE_REP_TRUSTED = 0,  /**< Whitelisted or good behavior */
    SOCKET_SIMPLE_REP_NEUTRAL = 1,  /**< New or unknown IP */
    SOCKET_SIMPLE_REP_SUSPECT = 2,  /**< Elevated rates or low success */
    SOCKET_SIMPLE_REP_HOSTILE = 3   /**< Detected attack patterns */
} SocketSimple_Reputation;

/**
 * @brief SYN protection configuration.
 */
typedef struct {
    int window_duration_ms;       /**< Sliding window size (default: 10000) */
    int max_attempts_per_window;  /**< Per-IP attempts per window (default: 100) */
    int max_global_per_second;    /**< Global rate limit (default: 1000) */
    float min_success_ratio;      /**< Min success ratio (default: 0.1) */
    int throttle_delay_ms;        /**< Throttle delay (default: 100) */
    int block_duration_ms;        /**< Auto-block duration (default: 300000) */
    float score_throttle;         /**< Score threshold for throttle (default: 0.7) */
    float score_challenge;        /**< Score threshold for challenge (default: 0.5) */
    float score_block;            /**< Score threshold for block (default: 0.3) */
    size_t max_tracked_ips;       /**< Max IPs to track (default: 10000) */
} SocketSimple_SYNConfig;

/**
 * @brief SYN protection statistics.
 */
typedef struct {
    uint64_t total_attempts;      /**< Total connection attempts checked */
    uint64_t total_allowed;       /**< Attempts allowed */
    uint64_t total_throttled;     /**< Attempts throttled */
    uint64_t total_challenged;    /**< Attempts challenged */
    uint64_t total_blocked;       /**< Attempts blocked */
    uint64_t total_whitelisted;   /**< Attempts from whitelisted IPs */
    uint64_t total_blacklisted;   /**< Attempts from blacklisted IPs */
    uint64_t current_tracked_ips; /**< Currently tracked unique IPs */
    uint64_t current_blocked_ips; /**< Currently blocked IPs */
    int64_t uptime_ms;            /**< Time since initialization */
} SocketSimple_SYNStats;

/**
 * @brief Per-IP state information.
 */
typedef struct {
    char ip[64];                  /**< IP address string */
    uint32_t attempts_current;    /**< Attempts in current window */
    uint32_t successes;           /**< Successful connections */
    uint32_t failures;            /**< Failed connections */
    SocketSimple_Reputation rep;  /**< Current reputation */
    float score;                  /**< Reputation score (0.0-1.0) */
    int is_blocked;               /**< 1 if currently blocked */
} SocketSimple_IPState;

/*============================================================================
 * SYN Protection Functions
 *============================================================================*/

/**
 * @brief Initialize SYN protection config with defaults.
 *
 * @param config Config structure to initialize.
 */
extern void Socket_simple_syn_config_init(SocketSimple_SYNConfig *config);

/**
 * @brief Create a new SYN protection instance.
 *
 * @param config Configuration (NULL for defaults).
 * @return Protection handle on success, NULL on error.
 *
 * Example:
 * @code
 * SocketSimple_SYNConfig config;
 * Socket_simple_syn_config_init(&config);
 * config.max_attempts_per_window = 50;
 *
 * SocketSimple_SYNProtect_T protect = Socket_simple_syn_new(&config);
 * if (!protect) {
 *     fprintf(stderr, "Failed: %s\n", Socket_simple_error());
 *     return 1;
 * }
 *
 * // Check incoming connection
 * SocketSimple_SYNAction action = Socket_simple_syn_check(protect, client_ip);
 * if (action == SOCKET_SIMPLE_SYN_BLOCK) {
 *     // Reject connection
 * }
 *
 * Socket_simple_syn_free(&protect);
 * @endcode
 */
extern SocketSimple_SYNProtect_T Socket_simple_syn_new(
    const SocketSimple_SYNConfig *config);

/**
 * @brief Free SYN protection instance.
 *
 * @param protect Pointer to protection handle.
 */
extern void Socket_simple_syn_free(SocketSimple_SYNProtect_T *protect);

/**
 * @brief Check if connection should be allowed.
 *
 * @param protect Protection handle.
 * @param client_ip Client IP address string.
 * @return Action to take (ALLOW, THROTTLE, CHALLENGE, BLOCK).
 */
extern SocketSimple_SYNAction Socket_simple_syn_check(
    SocketSimple_SYNProtect_T protect, const char *client_ip);

/**
 * @brief Report successful connection for reputation update.
 *
 * @param protect Protection handle.
 * @param client_ip Client IP address.
 */
extern void Socket_simple_syn_report_success(
    SocketSimple_SYNProtect_T protect, const char *client_ip);

/**
 * @brief Report failed connection for reputation update.
 *
 * @param protect Protection handle.
 * @param client_ip Client IP address.
 */
extern void Socket_simple_syn_report_failure(
    SocketSimple_SYNProtect_T protect, const char *client_ip);

/**
 * @brief Add IP to whitelist (always allowed).
 *
 * @param protect Protection handle.
 * @param ip IP address to whitelist.
 * @return 1 on success, 0 if whitelist full.
 */
extern int Socket_simple_syn_whitelist_add(
    SocketSimple_SYNProtect_T protect, const char *ip);

/**
 * @brief Add CIDR range to whitelist.
 *
 * @param protect Protection handle.
 * @param cidr CIDR notation (e.g., "10.0.0.0/8").
 * @return 1 on success, 0 on error.
 */
extern int Socket_simple_syn_whitelist_add_cidr(
    SocketSimple_SYNProtect_T protect, const char *cidr);

/**
 * @brief Remove IP from whitelist.
 *
 * @param protect Protection handle.
 * @param ip IP address to remove.
 */
extern void Socket_simple_syn_whitelist_remove(
    SocketSimple_SYNProtect_T protect, const char *ip);

/**
 * @brief Check if IP is whitelisted.
 *
 * @param protect Protection handle.
 * @param ip IP address to check.
 * @return 1 if whitelisted, 0 otherwise.
 */
extern int Socket_simple_syn_whitelist_contains(
    SocketSimple_SYNProtect_T protect, const char *ip);

/**
 * @brief Add IP to blacklist (always blocked).
 *
 * @param protect Protection handle.
 * @param ip IP address to block.
 * @param duration_ms Block duration (0 = permanent).
 * @return 1 on success, 0 if blacklist full.
 */
extern int Socket_simple_syn_blacklist_add(
    SocketSimple_SYNProtect_T protect, const char *ip, int duration_ms);

/**
 * @brief Remove IP from blacklist.
 *
 * @param protect Protection handle.
 * @param ip IP address to unblock.
 */
extern void Socket_simple_syn_blacklist_remove(
    SocketSimple_SYNProtect_T protect, const char *ip);

/**
 * @brief Check if IP is blacklisted.
 *
 * @param protect Protection handle.
 * @param ip IP address to check.
 * @return 1 if blacklisted, 0 otherwise.
 */
extern int Socket_simple_syn_blacklist_contains(
    SocketSimple_SYNProtect_T protect, const char *ip);

/**
 * @brief Get statistics snapshot.
 *
 * @param protect Protection handle.
 * @param stats Output statistics structure.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_syn_stats(
    SocketSimple_SYNProtect_T protect, SocketSimple_SYNStats *stats);

/**
 * @brief Get state for specific IP.
 *
 * @param protect Protection handle.
 * @param ip IP address to query.
 * @param state Output state structure.
 * @return 1 if IP found, 0 if not tracked.
 */
extern int Socket_simple_syn_get_ip_state(
    SocketSimple_SYNProtect_T protect, const char *ip,
    SocketSimple_IPState *state);

/**
 * @brief Perform cleanup of expired entries.
 *
 * Call periodically (e.g., every 5-10 seconds) to expire temporary
 * blocks and clean up stale tracking data.
 *
 * @param protect Protection handle.
 * @return Number of entries cleaned up.
 */
extern size_t Socket_simple_syn_cleanup(SocketSimple_SYNProtect_T protect);

/**
 * @brief Reset all protection state.
 *
 * Clears all tracked IPs, whitelists, and blacklists.
 *
 * @param protect Protection handle.
 */
extern void Socket_simple_syn_reset(SocketSimple_SYNProtect_T protect);

/**
 * @brief Get action name as string.
 *
 * @param action Action enum value.
 * @return Static string ("ALLOW", "THROTTLE", "CHALLENGE", "BLOCK").
 */
extern const char *Socket_simple_syn_action_name(SocketSimple_SYNAction action);

/**
 * @brief Get reputation name as string.
 *
 * @param rep Reputation enum value.
 * @return Static string ("TRUSTED", "NEUTRAL", "SUSPECT", "HOSTILE").
 */
extern const char *Socket_simple_syn_reputation_name(
    SocketSimple_Reputation rep);

/*============================================================================
 * IP Tracker Types
 *============================================================================*/

/**
 * @brief Opaque IP tracker handle.
 */
typedef struct SocketSimple_IPTracker *SocketSimple_IPTracker_T;

/*============================================================================
 * IP Tracker Functions
 *============================================================================*/

/**
 * @brief Create a new IP connection tracker.
 *
 * Tracks concurrent connections per IP address for rate limiting.
 *
 * @param max_per_ip Maximum connections per IP (0 = unlimited).
 * @return Tracker handle on success, NULL on error.
 *
 * Example:
 * @code
 * SocketSimple_IPTracker_T tracker = Socket_simple_ip_tracker_new(10);
 * if (!tracker) {
 *     fprintf(stderr, "Failed: %s\n", Socket_simple_error());
 *     return 1;
 * }
 *
 * // On new connection
 * if (Socket_simple_ip_tracker_track(tracker, client_ip)) {
 *     // Connection allowed
 * } else {
 *     // Too many connections from this IP
 * }
 *
 * // On disconnect
 * Socket_simple_ip_tracker_release(tracker, client_ip);
 *
 * Socket_simple_ip_tracker_free(&tracker);
 * @endcode
 */
extern SocketSimple_IPTracker_T Socket_simple_ip_tracker_new(int max_per_ip);

/**
 * @brief Free IP tracker instance.
 *
 * @param tracker Pointer to tracker handle.
 */
extern void Socket_simple_ip_tracker_free(SocketSimple_IPTracker_T *tracker);

/**
 * @brief Track a new connection from IP.
 *
 * Increments connection count for IP. If max_per_ip is set and
 * limit is reached, returns 0 to reject the connection.
 *
 * @param tracker Tracker handle.
 * @param ip Client IP address.
 * @return 1 if allowed, 0 if rejected (limit reached).
 */
extern int Socket_simple_ip_tracker_track(
    SocketSimple_IPTracker_T tracker, const char *ip);

/**
 * @brief Release a connection from IP.
 *
 * Decrements connection count for IP. Call on disconnect.
 *
 * @param tracker Tracker handle.
 * @param ip Client IP address.
 */
extern void Socket_simple_ip_tracker_release(
    SocketSimple_IPTracker_T tracker, const char *ip);

/**
 * @brief Get connection count for IP.
 *
 * @param tracker Tracker handle.
 * @param ip IP address to query.
 * @return Current connection count (0 if not tracked).
 */
extern int Socket_simple_ip_tracker_count(
    SocketSimple_IPTracker_T tracker, const char *ip);

/**
 * @brief Set maximum connections per IP.
 *
 * @param tracker Tracker handle.
 * @param max_per_ip New maximum (0 = unlimited).
 */
extern void Socket_simple_ip_tracker_set_max(
    SocketSimple_IPTracker_T tracker, int max_per_ip);

/**
 * @brief Get maximum connections per IP.
 *
 * @param tracker Tracker handle.
 * @return Current maximum (0 = unlimited).
 */
extern int Socket_simple_ip_tracker_get_max(SocketSimple_IPTracker_T tracker);

/**
 * @brief Get total tracked connections.
 *
 * @param tracker Tracker handle.
 * @return Total connections across all IPs.
 */
extern size_t Socket_simple_ip_tracker_total(SocketSimple_IPTracker_T tracker);

/**
 * @brief Get number of unique IPs being tracked.
 *
 * @param tracker Tracker handle.
 * @return Number of unique IPs with connections.
 */
extern size_t Socket_simple_ip_tracker_unique_ips(
    SocketSimple_IPTracker_T tracker);

/**
 * @brief Clear all tracked connections.
 *
 * @param tracker Tracker handle.
 */
extern void Socket_simple_ip_tracker_clear(SocketSimple_IPTracker_T tracker);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_SECURITY_INCLUDED */
