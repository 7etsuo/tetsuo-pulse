/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDNSSERVFAILCACHE_INCLUDED
#define SOCKETDNSSERVFAILCACHE_INCLUDED

/**
 * @file SocketDNSServfailCache.h
 * @brief DNS Server Failure Cache (RFC 2308 Section 7.1).
 * @ingroup dns
 *
 * Implements RFC 2308 Section 7.1 compliant SERVFAIL caching.
 * Server failures are cached for a maximum of 5 minutes to reduce
 * query storms against failing servers while ensuring timely recovery.
 *
 * ## RFC Reference
 *
 * RFC 2308 Section 7.1:
 * > "A server MAY cache a server failure response... However, this
 * > cached indication MUST NOT be retained longer than five (5) minutes."
 *
 * ## Cache Key Tuple
 *
 * SERVFAIL is server-specific, so the cache key includes the nameserver:
 * - `<QNAME, QTYPE, QCLASS, nameserver>` (4-tuple)
 *
 * This allows the resolver to try alternate nameservers when one fails.
 *
 * ## Features
 *
 * - RFC 2308 compliant 5-minute maximum TTL
 * - Server-specific caching (same query can succeed on different NS)
 * - LRU eviction when cache is full
 * - Thread-safe operations
 *
 * @see SocketDNSNegCache.h for NXDOMAIN/NODATA caching.
 * @see SocketDNSResolver.h for the async resolver API.
 */

#include "core/Arena.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @defgroup dns_servfail_cache DNS SERVFAIL Cache
 * @brief RFC 2308 Section 7.1 compliant server failure caching.
 * @ingroup dns
 * @{
 */

/** Maximum hostname length in cache key. */
#define DNS_SERVFAIL_MAX_NAME 255

/** Maximum nameserver address length (IPv6 + port). */
#define DNS_SERVFAIL_MAX_NS 64

/** Default maximum cache entries. */
#define DNS_SERVFAIL_DEFAULT_MAX 500

/**
 * RFC 2308 Section 7.1: SERVFAIL MUST NOT be cached longer than 5 minutes.
 */
#define DNS_SERVFAIL_MAX_TTL 300

/** Default QCLASS for Internet class. */
#define DNS_SERVFAIL_QCLASS_IN 1

#define T SocketDNSServfailCache_T
typedef struct T *T;

/**
 * @brief SERVFAIL cache lookup result.
 * @ingroup dns_servfail_cache
 */
typedef enum
{
  /** No cached SERVFAIL entry found. */
  DNS_SERVFAIL_MISS = 0,

  /** Cached SERVFAIL entry found - this nameserver is known to fail. */
  DNS_SERVFAIL_HIT = 1
} SocketDNS_ServfailCacheResult;

/**
 * @brief SERVFAIL cache entry information.
 * @ingroup dns_servfail_cache
 *
 * Returned by lookup functions to provide details about cached entries.
 */
typedef struct
{
  /** TTL remaining in seconds. */
  uint32_t ttl_remaining;

  /** Original TTL when inserted. */
  uint32_t original_ttl;

  /** Timestamp when entry was inserted (monotonic ms). */
  int64_t insert_time_ms;
} SocketDNS_ServfailCacheEntry;

/**
 * @brief SERVFAIL cache statistics.
 * @ingroup dns_servfail_cache
 */
typedef struct
{
  uint64_t hits;        /**< Cache hits (known failing server) */
  uint64_t misses;      /**< Cache misses */
  uint64_t insertions;  /**< Total insertions */
  uint64_t evictions;   /**< LRU evictions */
  uint64_t expirations; /**< TTL expirations */
  size_t current_size;  /**< Current entry count */
  size_t max_entries;   /**< Maximum capacity */
  double hit_rate;      /**< Calculated hit rate */
} SocketDNS_ServfailCacheStats;

/* Lifecycle functions */

/**
 * @brief Create a new SERVFAIL cache instance.
 * @ingroup dns_servfail_cache
 *
 * Creates a cache with default settings:
 * - max_entries: 500
 * - max_ttl: 300 seconds (5 minutes, RFC 2308 mandated)
 *
 * @param arena Arena for memory allocation (must outlive cache).
 * @return New cache instance, or NULL on allocation failure.
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * SocketDNSServfailCache_T cache = SocketDNSServfailCache_new(arena);
 * @endcode
 */
extern T SocketDNSServfailCache_new (Arena_T arena);

/**
 * @brief Dispose of a SERVFAIL cache instance.
 * @ingroup dns_servfail_cache
 *
 * Clears all entries and releases resources.
 * The cache pointer is set to NULL.
 *
 * @param cache Pointer to cache instance.
 */
extern void SocketDNSServfailCache_free (T *cache);

/* Cache operations */

/**
 * @brief Look up a SERVFAIL cache entry.
 * @ingroup dns_servfail_cache
 *
 * Checks if a query to a specific nameserver has recently failed.
 * Uses the 4-tuple key: `<QNAME, QTYPE, QCLASS, nameserver>`.
 *
 * @param cache      Cache instance.
 * @param qname      Query name (case-insensitive lookup).
 * @param qtype      Query type (e.g., DNS_TYPE_A, DNS_TYPE_AAAA).
 * @param qclass     Query class (typically DNS_CLASS_IN = 1).
 * @param nameserver Nameserver address (e.g., "8.8.8.8" or
 * "2001:4860:4860::8888").
 * @param entry      Output entry details (may be NULL if not needed).
 * @return DNS_SERVFAIL_HIT if cached failure, DNS_SERVFAIL_MISS otherwise.
 *
 * @code{.c}
 * SocketDNS_ServfailCacheEntry info;
 * SocketDNS_ServfailCacheResult result = SocketDNSServfailCache_lookup(
 *     cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN, "8.8.8.8", &info);
 *
 * if (result == DNS_SERVFAIL_HIT) {
 *     printf("Nameserver 8.8.8.8 failed for this query, TTL=%u\n",
 *            info.ttl_remaining);
 *     // Try a different nameserver
 * }
 * @endcode
 */
extern SocketDNS_ServfailCacheResult
SocketDNSServfailCache_lookup (T cache,
                               const char *qname,
                               uint16_t qtype,
                               uint16_t qclass,
                               const char *nameserver,
                               SocketDNS_ServfailCacheEntry *entry);

/**
 * @brief Insert a SERVFAIL entry into the cache.
 * @ingroup dns_servfail_cache
 *
 * Caches a SERVFAIL response with key `<QNAME, QTYPE, QCLASS, nameserver>`.
 * The TTL is capped at DNS_SERVFAIL_MAX_TTL (5 minutes) per RFC 2308.
 *
 * @param cache      Cache instance.
 * @param qname      Query name (normalized to lowercase internally).
 * @param qtype      Query type.
 * @param qclass     Query class (typically DNS_CLASS_IN = 1).
 * @param nameserver Nameserver address that returned SERVFAIL.
 * @param ttl        Desired TTL (capped at 300 seconds).
 * @return 0 on success, -1 on error.
 *
 * @code{.c}
 * // Cache SERVFAIL from 8.8.8.8 for example.com A query
 * SocketDNSServfailCache_insert(cache, "example.com", DNS_TYPE_A,
 *                                DNS_CLASS_IN, "8.8.8.8", 300);
 *
 * // Future lookups for this query to 8.8.8.8 will hit cache
 * // But queries to 8.8.4.4 will miss (try alternate nameserver)
 * @endcode
 */
extern int SocketDNSServfailCache_insert (T cache,
                                          const char *qname,
                                          uint16_t qtype,
                                          uint16_t qclass,
                                          const char *nameserver,
                                          uint32_t ttl);

/**
 * @brief Remove a specific SERVFAIL entry.
 * @ingroup dns_servfail_cache
 *
 * Removes the entry for the exact 4-tuple.
 *
 * @param cache      Cache instance.
 * @param qname      Query name.
 * @param qtype      Query type.
 * @param qclass     Query class.
 * @param nameserver Nameserver address.
 * @return 1 if entry was found and removed, 0 if not found.
 */
extern int SocketDNSServfailCache_remove (T cache,
                                          const char *qname,
                                          uint16_t qtype,
                                          uint16_t qclass,
                                          const char *nameserver);

/**
 * @brief Remove all SERVFAIL entries for a nameserver.
 * @ingroup dns_servfail_cache
 *
 * Useful when a nameserver comes back online and all cached
 * failures should be cleared.
 *
 * @param cache      Cache instance.
 * @param nameserver Nameserver address to clear.
 * @return Number of entries removed.
 */
extern int
SocketDNSServfailCache_remove_nameserver (T cache, const char *nameserver);

/**
 * @brief Clear all entries from the cache.
 * @ingroup dns_servfail_cache
 *
 * @param cache Cache instance.
 */
extern void SocketDNSServfailCache_clear (T cache);

/* Configuration */

/**
 * @brief Set maximum cache entries.
 * @ingroup dns_servfail_cache
 *
 * @param cache       Cache instance.
 * @param max_entries Maximum entries (0 = unlimited).
 */
extern void
SocketDNSServfailCache_set_max_entries (T cache, size_t max_entries);

/**
 * @brief Get cache statistics.
 * @ingroup dns_servfail_cache
 *
 * @param cache Cache instance.
 * @param stats Output statistics structure.
 */
extern void
SocketDNSServfailCache_stats (T cache, SocketDNS_ServfailCacheStats *stats);

/* Utility functions */

/**
 * @brief Get result name as string.
 * @ingroup dns_servfail_cache
 *
 * @param result Lookup result.
 * @return "MISS" or "HIT".
 */
extern const char *
SocketDNSServfailCache_result_name (SocketDNS_ServfailCacheResult result);

/** @} */ /* End of dns_servfail_cache group */

#undef T

#endif /* SOCKETDNSSERVFAILCACHE_INCLUDED */
