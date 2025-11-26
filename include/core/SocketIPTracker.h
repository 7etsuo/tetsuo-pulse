#ifndef SOCKETIPTRACKER_INCLUDED
#define SOCKETIPTRACKER_INCLUDED

/**
 * SocketIPTracker.h - Per-IP Connection Tracking
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
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

#define T SocketIPTracker_T
typedef struct T *T;

/* Exception types */
extern const Except_T SocketIPTracker_Failed; /**< IP tracker operation failure */

/**
 * SocketIPTracker_new - Create a new IP connection tracker
 * @arena: Arena for memory allocation (NULL to use malloc)
 * @max_per_ip: Maximum connections allowed per IP (0 = unlimited)
 *
 * Returns: New IP tracker instance
 * Raises: SocketIPTracker_Failed on allocation failure
 * Thread-safe: Yes - returns new instance
 */
extern T SocketIPTracker_new (Arena_T arena, int max_per_ip);

/**
 * SocketIPTracker_free - Free an IP tracker
 * @tracker: Pointer to tracker (will be set to NULL)
 *
 * Thread-safe: Yes
 *
 * Note: Only frees if allocated with malloc (arena == NULL).
 * Arena-allocated trackers are freed when arena is disposed.
 */
extern void SocketIPTracker_free (T *tracker);

/**
 * SocketIPTracker_track - Track a new connection from IP
 * @tracker: IP tracker instance
 * @ip: IP address string (IPv4 or IPv6)
 *
 * Returns: 1 if allowed (under limit), 0 if limit reached
 * Thread-safe: Yes - uses internal mutex
 *
 * Increments the connection count for the IP address.
 * If max_per_ip is 0 (unlimited), always returns 1.
 * If IP is NULL or empty, always returns 1 (no tracking).
 */
extern int SocketIPTracker_track (T tracker, const char *ip);

/**
 * SocketIPTracker_release - Release a connection from IP
 * @tracker: IP tracker instance
 * @ip: IP address string (IPv4 or IPv6)
 *
 * Thread-safe: Yes - uses internal mutex
 *
 * Decrements the connection count for the IP address.
 * Automatically removes entry when count reaches zero.
 * Safe to call with NULL or empty IP (no-op).
 */
extern void SocketIPTracker_release (T tracker, const char *ip);

/**
 * SocketIPTracker_count - Get current connection count for IP
 * @tracker: IP tracker instance
 * @ip: IP address string (IPv4 or IPv6)
 *
 * Returns: Current connection count (0 if not tracked)
 * Thread-safe: Yes - uses internal mutex
 */
extern int SocketIPTracker_count (T tracker, const char *ip);

/**
 * SocketIPTracker_setmax - Set maximum connections per IP
 * @tracker: IP tracker instance
 * @max_per_ip: New maximum (0 = unlimited)
 *
 * Thread-safe: Yes - uses internal mutex
 *
 * Note: Does not affect existing connections over the new limit.
 * New connections will be rejected until count drops below limit.
 */
extern void SocketIPTracker_setmax (T tracker, int max_per_ip);

/**
 * SocketIPTracker_getmax - Get maximum connections per IP
 * @tracker: IP tracker instance
 *
 * Returns: Maximum connections per IP (0 = unlimited)
 * Thread-safe: Yes
 */
extern int SocketIPTracker_getmax (T tracker);

/**
 * SocketIPTracker_total - Get total tracked connections
 * @tracker: IP tracker instance
 *
 * Returns: Total number of tracked connections across all IPs
 * Thread-safe: Yes - uses internal mutex
 */
extern size_t SocketIPTracker_total (T tracker);

/**
 * SocketIPTracker_unique_ips - Get number of unique IPs being tracked
 * @tracker: IP tracker instance
 *
 * Returns: Number of unique IP addresses with at least one connection
 * Thread-safe: Yes - uses internal mutex
 */
extern size_t SocketIPTracker_unique_ips (T tracker);

/**
 * SocketIPTracker_clear - Clear all tracked connections
 * @tracker: IP tracker instance
 *
 * Thread-safe: Yes - uses internal mutex
 *
 * Removes all entries from the tracker.
 * Useful for testing or administrative reset.
 */
extern void SocketIPTracker_clear (T tracker);

#undef T
#endif /* SOCKETIPTRACKER_INCLUDED */
