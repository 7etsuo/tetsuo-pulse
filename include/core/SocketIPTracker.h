/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETIPTRACKER_INCLUDED
#define SOCKETIPTRACKER_INCLUDED

/**
 * @file SocketIPTracker.h
 * @ingroup security
 * @brief Per-IP connection tracking for rate limiting and DoS protection.
 *
 * Thread-safe hash table tracking concurrent connections per IP address.
 * Enforces configurable per-IP limits to prevent single-source DoS attacks.
 *
 * Features:
 * - O(1) average lookup via DJB2 hash with random seed
 * - IPv4/IPv6 validation via inet_pton
 * - Configurable max per IP and max unique IPs
 * - Auto-removes entries when count reaches zero
 *
 * @code{.c}
 * SocketIPTracker_T tracker = SocketIPTracker_new(arena, 10);
 * if (SocketIPTracker_track(tracker, client_ip)) {
 *     // Connection allowed
 * }
 * SocketIPTracker_release(tracker, client_ip);  // On disconnect
 * SocketIPTracker_free(&tracker);
 * @endcode
 *
 * @see SocketPool_setmaxperip() for pool integration.
 */

#include "core/Arena.h"
#include "core/Except.h"
#include <stddef.h>

/**
 * @brief Opaque IP connection tracker type.
 *
 * Thread-safe hash table tracking per-IP connection counts.
 * Use provided API functions for all operations.
 */
#define T SocketIPTracker_T
typedef struct T *T;

/**
 * @brief Exception for IP tracker failures.
 *
 * Raised on allocation errors, mutex failures, or config errors.
 */
extern const Except_T SocketIPTracker_Failed;

/**
 * @brief Create a new IP connection tracker.
 *
 * @param arena  Arena for allocations (NULL for malloc)
 * @param max_per_ip  Maximum connections per IP (0 = unlimited)
 *
 * Returns: New tracker instance
 * Raises: SocketIPTracker_Failed on allocation or mutex init failure
 *
 * @threadsafe Yes
 */
extern T SocketIPTracker_new (Arena_T arena, int max_per_ip);

/**
 * @brief Free IP tracker and release resources.
 *
 * @param tracker  Pointer to tracker (set to NULL after)
 *
 * For arena-allocated trackers, only nullifies pointer.
 * Actual memory freed by Arena_dispose().
 *
 * @threadsafe Partial - avoid concurrent operations during free
 */
extern void SocketIPTracker_free (T *tracker);

/**
 * @brief Track a new connection from an IP.
 *
 * @param tracker  Tracker instance
 * @param ip  Null-terminated IP string (IPv4 or IPv6)
 *
 * Returns: 1 if allowed and tracked, 0 if rejected (limit exceeded or error)
 *
 * Creates entry if IP not tracked. Validates IP format via inet_pton.
 * Invalid or empty IPs return 1 (no tracking, safe default).
 *
 * @threadsafe Yes
 * @complexity O(1) average
 */
extern int SocketIPTracker_track (T tracker, const char *ip);

/**
 * @brief Release a connection from an IP.
 *
 * @param tracker  Tracker instance
 * @param ip  IP string of disconnecting client
 *
 * Decrements count; removes entry when zero. No-op for untracked IPs.
 *
 * @threadsafe Yes
 * @complexity O(1) average
 */
extern void SocketIPTracker_release (T tracker, const char *ip);

/**
 * @brief Get current connection count for an IP.
 *
 * @param tracker  Tracker instance
 * @param ip  IP address string
 *
 * Returns: Connection count (0 if not tracked)
 *
 * @threadsafe Yes
 */
extern int SocketIPTracker_count (T tracker, const char *ip);

/**
 * @brief Set maximum connections per IP.
 *
 * @param tracker  Tracker instance
 * @param max_per_ip  New maximum (0 = unlimited)
 *
 * Does not affect existing connections over the new limit.
 *
 * @threadsafe Yes
 */
extern void SocketIPTracker_setmax (T tracker, int max_per_ip);

/**
 * @brief Get maximum connections per IP.
 *
 * @param tracker  Tracker instance
 *
 * Returns: Current maximum (0 = unlimited)
 *
 * @threadsafe Yes
 */
extern int SocketIPTracker_getmax (T tracker);

/**
 * @brief Set maximum unique IPs to track.
 *
 * @param tracker  Tracker instance
 * @param max_unique  New maximum (0 = unlimited)
 *
 * Limits memory by rejecting new unique IPs when reached.
 *
 * @threadsafe Yes
 */
extern void SocketIPTracker_setmaxunique (T tracker, size_t max_unique);

/**
 * @brief Get maximum unique IPs limit.
 *
 * @param tracker  Tracker instance
 *
 * Returns: Current limit (0 = unlimited)
 *
 * @threadsafe Yes
 */
extern size_t SocketIPTracker_getmaxunique (T tracker);

/**
 * @brief Get total tracked connections across all IPs.
 *
 * @param tracker  Tracker instance
 *
 * Returns: Total connection count
 *
 * @threadsafe Yes
 */
extern size_t SocketIPTracker_total (T tracker);

/**
 * @brief Get number of unique IPs being tracked.
 *
 * @param tracker  Tracker instance
 *
 * Returns: Unique IP count
 *
 * @threadsafe Yes
 */
extern size_t SocketIPTracker_unique_ips (T tracker);

/**
 * @brief Clear all tracked connections.
 *
 * @param tracker  Tracker instance
 *
 * Removes all entries. Useful for testing or reset.
 *
 * @threadsafe Yes
 */
extern void SocketIPTracker_clear (T tracker);

#undef T
#endif /* SOCKETIPTRACKER_INCLUDED */
