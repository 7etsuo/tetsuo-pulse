#ifndef SOCKETIPTRACKER_INCLUDED
#define SOCKETIPTRACKER_INCLUDED

/**
 * @file SocketIPTracker.h
 * @brief Per-IP connection tracking for rate limiting and DoS protection.
 * @ingroup security
 *
 * Tracks the number of concurrent connections from each IP address.
 * Used to enforce per-IP connection limits to prevent single-source
 * denial of service attacks.
 *
 * Features:
 * - O(1) average lookup/insert/delete via hash table
 * - Automatic cleanup of zero-count entries
 * - Thread-safe implementation
 * - IPv4 and IPv6 address support
 *
 * @see SocketRateLimit_T for bandwidth rate limiting.
 * @see SocketPool_T for connection pool integration.
 * @see SocketPool_setmaxperip() for configuring per-IP connection limits in pools.
 * @see SocketPool_track_ip() and SocketPool_release_ip() for pool-managed IP tracking.
 * @see @ref connection_mgmt for connection management modules.
 *
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - POSIX threads (pthread) for thread safety
 *
 * Thread Safety:
 * - All operations are thread-safe via internal mutex
 * - Safe to share a single tracker across threads
 *
 * Usage:
 *   Arena_T arena = Arena_new();
 *   SocketIPTracker_T tracker = SocketIPTracker_new(arena, 10);
 *   // Max 10 connections per IP
 *   SocketIPTracker_setmaxunique(tracker, 5000); // Optional: limit unique IPs to 5000
 *
 *   const char *client_ip = Socket_getpeeraddr(client);
 *   if (SocketIPTracker_track(tracker, client_ip)) {
 *       // Allowed - connection tracked
 *   } else {
 *       // Limit reached - reject connection
 *   }
 *
 *   // When connection closes:
 *   SocketIPTracker_release(tracker, client_ip);
 */

#include "core/Arena.h"
#include "core/Except.h"
#include <stddef.h>

/**
 * @brief Opaque IP connection tracker type.
 * @ingroup security
 *
 * Tracks concurrent connections per IP address for rate limiting and
 * DoS protection. Thread-safe and efficient with hash table lookups.
 *
 * @see SocketIPTracker_new() for creation.
 * @see SocketIPTracker_free() for cleanup.
 * @see @ref foundation for base infrastructure modules.
 */
#define T SocketIPTracker_T
typedef struct T *T;

/* Exception types */
extern const Except_T
    SocketIPTracker_Failed; /**< IP tracker operation failure */

/**
 * @brief Create a new IP connection tracker.
 * @ingroup security
 * @param arena Arena for memory allocation (NULL to use malloc).
 * @param max_per_ip Maximum connections allowed per IP (0 = unlimited).
 *
 * Note: Defaults max_unique_ips to SOCKET_MAX_CONNECTIONS to prevent memory
 * exhaustion. Adjustable via SocketIPTracker_setmaxunique().
 *
 * @return New IP tracker instance.
 * @throws SocketIPTracker_Failed on allocation failure.
 * @threadsafe Yes - returns new instance.
 * @see SocketIPTracker_free() for cleanup.
 * @see SocketIPTracker_track() for usage.
 */
extern T SocketIPTracker_new (Arena_T arena, int max_per_ip);

/**
 * @brief Free an IP tracker.
 * @ingroup security
 * @param tracker Pointer to tracker (set to NULL on success).
 *
 * Releases all resources associated with the tracker if heap-allocated.
 * For arena-allocated trackers, this sets the pointer to NULL but actual cleanup occurs via Arena_dispose().
 * Idempotent and safe for concurrent calls due to internal locking.
 *
 * @threadsafe Yes - uses internal mutex.
 * @see SocketIPTracker_new() to create a tracker.
 * @see Arena_dispose() for arena-based resource management.
 */
extern void SocketIPTracker_free (T *tracker);

/**
 * @brief Track a new connection from an IP address.
 * @ingroup security
 * @param tracker IP tracker instance.
 * @param ip IP address string (IPv4 or IPv6).
 *
 * Increments the connection count for the IP address.
 * If max_per_ip is 0 (unlimited), always returns 1.
 * If IP is NULL or empty, always returns 1 (no tracking).
 *
 * @return 1 if allowed (under limit), 0 if limit reached.
 * @threadsafe Yes - uses internal mutex.
 * @see SocketIPTracker_release() to decrement count.
 * @see SocketPool_track_ip() for equivalent pool-integrated operation.
 */
extern int SocketIPTracker_track (T tracker, const char *ip);

/**
 * @brief Release a connection from an IP address.
 * @ingroup security
 * @param tracker IP tracker instance.
 * @param ip IP address string (IPv4 or IPv6).
 *
 * Decrements the connection count for the IP address.
 * Automatically removes entry when count reaches zero.
 * Safe to call with NULL or empty IP (no-op).
 *
 * @threadsafe Yes - uses internal mutex.
 * @see SocketIPTracker_track() to increment count.
 * @see SocketPool_release_ip() for equivalent pool-integrated operation.
 */
extern void SocketIPTracker_release (T tracker, const char *ip);

/**
 * @brief Get current connection count for an IP address.
 * @ingroup security
 * @param tracker IP tracker instance.
 * @param ip IP address string (IPv4 or IPv6).
 *
 * @return Current connection count (0 if not tracked).
 * @threadsafe Yes - uses internal mutex.
 * @see SocketIPTracker_track() for incrementing.
 * @see SocketIPTracker_release() for decrementing.
 */
extern int SocketIPTracker_count (T tracker, const char *ip);

/**
 * @brief Set maximum connections per IP address.
 * @ingroup security
 * @param tracker IP tracker instance.
 * @param max_per_ip New maximum (0 = unlimited).
 *
 * Note: Does not affect existing connections over the new limit.
 * New connections will be rejected until count drops below limit.
 *
 * @threadsafe Yes - uses internal mutex.
 * @see SocketIPTracker_getmax() to retrieve current limit.
 * @see SocketPool_setmaxperip() for pool equivalent configuration.
 */
extern void SocketIPTracker_setmax (T tracker, int max_per_ip);

/**
 * @brief Get maximum connections per IP address.
 * @ingroup security
 * @param tracker IP tracker instance.
 *
 * @return Maximum connections per IP (0 = unlimited).
 * @threadsafe Yes.
 * @see SocketIPTracker_setmax() to change the limit.
 */
extern int SocketIPTracker_getmax (T tracker);

/**
 * @brief Set maximum unique IPs to track.
 * @ingroup security
 * @param tracker IP tracker instance.
 * @param max_unique New maximum (0 = unlimited).
 *
 * Limits memory usage by rejecting new unique IPs when limit reached.
 * Does not evict existing entries.
 *
 * @threadsafe Yes.
 * @see SocketIPTracker_getmaxunique() to retrieve current limit.
 */
extern void SocketIPTracker_setmaxunique (T tracker, size_t max_unique);

/**
 * @brief Get maximum unique IPs limit.
 * @ingroup security
 * @param tracker IP tracker instance.
 *
 * @return Current maximum unique IPs (0 = unlimited).
 * @threadsafe Yes.
 * @see SocketIPTracker_setmaxunique() to change the limit.
 */
extern size_t SocketIPTracker_getmaxunique (T tracker);

/**
 * @brief Get total tracked connections across all IPs.
 * @ingroup security
 * @param tracker IP tracker instance.
 *
 * @return Total number of tracked connections across all IPs.
 * @threadsafe Yes - uses internal mutex.
 * @see SocketIPTracker_unique_ips() for unique IP count.
 */
extern size_t SocketIPTracker_total (T tracker);

/**
 * @brief Get number of unique IPs being tracked.
 * @ingroup security
 * @param tracker IP tracker instance.
 *
 * @return Number of unique IP addresses with at least one connection.
 * @threadsafe Yes - uses internal mutex.
 * @see SocketIPTracker_total() for total connection count.
 */
extern size_t SocketIPTracker_unique_ips (T tracker);

/**
 * @brief Clear all tracked connections.
 * @ingroup security
 * @param tracker IP tracker instance.
 *
 * @threadsafe Yes - uses internal mutex.
 * @see SocketIPTracker_free() for complete cleanup.
 *
 * Removes all entries from the tracker.
 * Useful for testing or administrative reset.
 */
extern void SocketIPTracker_clear (T tracker);

#undef T
#endif /* SOCKETIPTRACKER_INCLUDED */
