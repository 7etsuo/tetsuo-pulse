/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDNSDEADSERVER_INCLUDED
#define SOCKETDNSDEADSERVER_INCLUDED

/**
 * @file SocketDNSDeadServer.h
 * @brief Dead Server Tracking (RFC 2308 Section 7.2).
 * @ingroup dns
 *
 * Implements RFC 2308 Section 7.2 compliant dead/unreachable server tracking.
 * Servers that fail to respond (timeout) are temporarily blacklisted to avoid
 * waiting for known-dead servers during DNS resolution.
 *
 * ## RFC Reference
 *
 * RFC 2308 Section 7.2:
 * > "Dead / Unreachable servers are a special class of server failure."
 *
 * > "A server MAY cache that a server has timed out. This cached
 * > indication MUST NOT be kept beyond five (5) minutes."
 *
 * > "When a server does not respond it may or may not be reachable and
 * > may or may not be able to answer the query."
 *
 * ## Difference from SERVFAIL Caching
 *
 * | Condition   | Detection              | Cache Scope               |
 * |-------------|------------------------|---------------------------|
 * | SERVFAIL    | RCODE=2 in response    | Per query + nameserver    |
 * | Dead Server | Timeout / no response  | Per nameserver (all queries) |
 *
 * Dead server = no response at all (timeout)
 * SERVFAIL = server responded but with error
 *
 * ## Features
 *
 * - RFC 2308 compliant 5-minute maximum blacklist duration
 * - Per-nameserver tracking (not per-query)
 * - Consecutive failure counting
 * - Automatic recovery when server responds
 * - Thread-safe operations
 *
 * @see SocketDNSServfailCache.h for SERVFAIL caching (different from dead server).
 * @see SocketDNSTransport.h for transport layer integration.
 */

#include "core/Arena.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @defgroup dns_dead_server Dead Server Tracking
 * @brief RFC 2308 Section 7.2 compliant dead server tracking.
 * @ingroup dns
 * @{
 */

/** Maximum nameserver address length (IPv6 + scope). */
#define DNS_DEAD_SERVER_MAX_ADDR 64

/** Maximum tracked dead servers. */
#define DNS_DEAD_SERVER_MAX_TRACKED 32

/**
 * RFC 2308 Section 7.2: Dead server indication MUST NOT be kept beyond 5 minutes.
 */
#define DNS_DEAD_SERVER_MAX_TTL 300

/** Default threshold for marking a server as dead (consecutive timeouts). */
#define DNS_DEAD_SERVER_DEFAULT_THRESHOLD 2

#define T SocketDNSDeadServer_T
typedef struct T *T;

/**
 * @brief Dead server entry information.
 * @ingroup dns_dead_server
 *
 * Returned by lookup functions to provide details about tracked servers.
 */
typedef struct
{
  /** Seconds remaining until server is retried. */
  uint32_t ttl_remaining;

  /** Number of consecutive failures. */
  int consecutive_failures;

  /** Timestamp when server was marked dead (monotonic ms). */
  int64_t marked_dead_ms;
} SocketDNS_DeadServerEntry;

/**
 * @brief Dead server tracker statistics.
 * @ingroup dns_dead_server
 */
typedef struct
{
  uint64_t checks;           /**< Total is_dead checks */
  uint64_t dead_hits;        /**< Times a dead server was skipped */
  uint64_t alive_marks;      /**< Times a server was marked alive */
  uint64_t dead_marks;       /**< Times a server was marked dead */
  uint64_t expirations;      /**< Times a dead marking expired */
  size_t current_dead;       /**< Currently tracked dead servers */
  size_t max_tracked;        /**< Maximum capacity */
} SocketDNS_DeadServerStats;

/* Lifecycle functions */

/**
 * @brief Create a new dead server tracker instance.
 * @ingroup dns_dead_server
 *
 * Creates a tracker with default settings:
 * - max_tracked: 32 servers
 * - threshold: 2 consecutive failures to mark dead
 * - max_ttl: 300 seconds (5 minutes, RFC 2308 mandated)
 *
 * @param arena Arena for memory allocation (must outlive tracker).
 * @return New tracker instance, or NULL on allocation failure.
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new(arena);
 * @endcode
 */
extern T SocketDNSDeadServer_new (Arena_T arena);

/**
 * @brief Dispose of a dead server tracker instance.
 * @ingroup dns_dead_server
 *
 * Clears all entries and releases resources.
 * The tracker pointer is set to NULL.
 *
 * @param tracker Pointer to tracker instance.
 */
extern void SocketDNSDeadServer_free (T *tracker);

/* Core operations */

/**
 * @brief Check if a nameserver is currently marked as dead.
 * @ingroup dns_dead_server
 *
 * Returns true if the server has exceeded the failure threshold and the
 * dead marking hasn't expired (< 5 minutes). Expired entries are pruned.
 *
 * @param tracker Tracker instance.
 * @param address Nameserver address (e.g., "8.8.8.8" or "2001:4860:4860::8888").
 * @param entry   Output entry details (may be NULL if not needed).
 * @return true if server is dead and should be skipped, false otherwise.
 *
 * @code{.c}
 * if (SocketDNSDeadServer_is_dead(tracker, "8.8.8.8", NULL)) {
 *     // Skip this nameserver, try next one
 *     continue;
 * }
 * @endcode
 */
extern bool SocketDNSDeadServer_is_dead (T tracker, const char *address,
                                          SocketDNS_DeadServerEntry *entry);

/**
 * @brief Record a timeout/failure for a nameserver.
 * @ingroup dns_dead_server
 *
 * Increments the consecutive failure count. When the count reaches the
 * threshold, the server is marked dead for up to 5 minutes.
 *
 * @param tracker Tracker instance.
 * @param address Nameserver address that timed out.
 *
 * @code{.c}
 * if (query_result == DNS_ERROR_TIMEOUT) {
 *     SocketDNSDeadServer_mark_failure(tracker, nameserver);
 * }
 * @endcode
 */
extern void SocketDNSDeadServer_mark_failure (T tracker, const char *address);

/**
 * @brief Mark a nameserver as alive (received a response).
 * @ingroup dns_dead_server
 *
 * Clears any dead status and resets the failure counter. Call this when
 * a server responds successfully to indicate it's back online.
 *
 * @param tracker Tracker instance.
 * @param address Nameserver address that responded.
 *
 * @code{.c}
 * if (query_result == DNS_ERROR_SUCCESS) {
 *     SocketDNSDeadServer_mark_alive(tracker, nameserver);
 * }
 * @endcode
 */
extern void SocketDNSDeadServer_mark_alive (T tracker, const char *address);

/**
 * @brief Prune expired dead server entries.
 * @ingroup dns_dead_server
 *
 * Removes entries older than 5 minutes. This is called automatically
 * during is_dead checks, but can be called explicitly for maintenance.
 *
 * @param tracker Tracker instance.
 * @return Number of entries pruned.
 */
extern int SocketDNSDeadServer_prune (T tracker);

/**
 * @brief Clear all tracked dead servers.
 * @ingroup dns_dead_server
 *
 * Removes all entries, effectively marking all servers as potentially alive.
 *
 * @param tracker Tracker instance.
 */
extern void SocketDNSDeadServer_clear (T tracker);

/* Configuration */

/**
 * @brief Set the failure threshold for marking a server dead.
 * @ingroup dns_dead_server
 *
 * A server must fail this many consecutive times before being marked dead.
 * Default is 2 (to avoid marking servers dead on transient failures).
 *
 * @param tracker  Tracker instance.
 * @param threshold Number of consecutive failures (minimum 1).
 */
extern void SocketDNSDeadServer_set_threshold (T tracker, int threshold);

/**
 * @brief Get the failure threshold.
 * @ingroup dns_dead_server
 *
 * @param tracker Tracker instance.
 * @return Current failure threshold.
 */
extern int SocketDNSDeadServer_get_threshold (T tracker);

/**
 * @brief Get tracker statistics.
 * @ingroup dns_dead_server
 *
 * @param tracker Tracker instance.
 * @param stats   Output statistics structure.
 */
extern void SocketDNSDeadServer_stats (T tracker,
                                        SocketDNS_DeadServerStats *stats);

/** @} */ /* End of dns_dead_server group */

#undef T

#endif /* SOCKETDNSDEADSERVER_INCLUDED */
