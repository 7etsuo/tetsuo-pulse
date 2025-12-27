/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDNSNEGCACHE_INCLUDED
#define SOCKETDNSNEGCACHE_INCLUDED

/**
 * @file SocketDNSNegCache.h
 * @brief DNS Negative Response Cache (RFC 2308).
 * @ingroup dns
 *
 * Implements RFC 2308 compliant negative caching for DNS responses.
 * Caches NXDOMAIN and NODATA responses with proper cache key tuples
 * as specified in RFC 2308 Section 5.
 *
 * ## RFC References
 *
 * - RFC 2308 Section 5: Caching Negative Answers
 * - RFC 2308 Section 3: Negative Answers from Authoritative Servers
 *
 * ## Cache Key Tuples
 *
 * Per RFC 2308 Section 5:
 *
 * - **NXDOMAIN**: Cached against `<QNAME, QCLASS>` tuple.
 *   The domain does not exist at all, so any query type for that name
 *   should return the cached NXDOMAIN.
 *
 * - **NODATA**: Cached against `<QNAME, QTYPE, QCLASS>` tuple.
 *   The name exists but has no records of the requested type.
 *   Other record types for the same name may still exist.
 *
 * ## TTL Handling
 *
 * Per RFC 2308 Section 5, negative response TTL comes from the SOA
 * MINIMUM field in the authority section. Responses without SOA
 * records should not be cached.
 *
 * ## Features
 *
 * - RFC 2308 compliant cache key tuples
 * - Separate handling for NXDOMAIN vs NODATA
 * - LRU eviction when cache is full
 * - TTL-based expiration
 * - Thread-safe operations
 *
 * @see SocketDNSResolver.h for the async resolver API.
 * @see SocketDNSWire.h for DNS record types and classes.
 */

#include "core/Arena.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @defgroup dns_negcache DNS Negative Cache
 * @brief RFC 2308 compliant negative response caching.
 * @ingroup dns
 * @{
 */

/** Maximum hostname length in cache key (RFC 1035 §2.3.4). */
#define DNS_NEGCACHE_MAX_NAME 255

/** Maximum SOA RDATA length (typical SOA is ~100 bytes). */
#define DNS_NEGCACHE_MAX_SOA_RDATA 512

/** Maximum SOA owner name length (RFC 1035 §2.3.4). */
#define DNS_NEGCACHE_MAX_SOA_NAME 255

/** Default maximum cache entries. */
#define DNS_NEGCACHE_DEFAULT_MAX 1000

/** Default maximum TTL in seconds (1 hour per RFC 2308 recommendation). */
#define DNS_NEGCACHE_DEFAULT_MAX_TTL 3600

/** Minimum TTL in seconds (prevent excessive caching). */
#define DNS_NEGCACHE_MIN_TTL 0

/** QTYPE value used for NXDOMAIN entries (matches any type). */
#define DNS_NEGCACHE_QTYPE_ANY 0

/** Default QCLASS for Internet class. */
#define DNS_NEGCACHE_QCLASS_IN 1

#define T SocketDNSNegCache_T
typedef struct T *T;

/**
 * @brief Type of negative cache entry.
 * @ingroup dns_negcache
 *
 * Distinguishes between NXDOMAIN (name does not exist) and
 * NODATA (name exists but has no records of requested type).
 */
typedef enum
{
  /** Name Error - domain does not exist (RCODE 3). */
  DNS_NEG_NXDOMAIN = 0,

  /** No Data - name exists but has no records of requested type. */
  DNS_NEG_NODATA = 1
} SocketDNS_NegCacheType;

/**
 * @brief Negative cache lookup result.
 * @ingroup dns_negcache
 */
typedef enum
{
  /** No cached entry found. */
  DNS_NEG_MISS = 0,

  /** Cached NXDOMAIN entry found. */
  DNS_NEG_HIT_NXDOMAIN = 1,

  /** Cached NODATA entry found. */
  DNS_NEG_HIT_NODATA = 2
} SocketDNS_NegCacheResult;

/**
 * @brief Cached SOA record data for RFC 2308 Section 6 compliance.
 * @ingroup dns_negcache
 *
 * When serving cached negative responses, RFC 2308 Section 6 requires
 * including the SOA record in the authority section with decremented TTL.
 * This structure holds the cached SOA data needed to reconstruct the response.
 */
typedef struct
{
  /** SOA owner name (e.g., "example.com"). */
  char name[DNS_NEGCACHE_MAX_SOA_NAME + 1];

  /** Raw SOA RDATA (MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM). */
  unsigned char rdata[DNS_NEGCACHE_MAX_SOA_RDATA];

  /** Length of SOA RDATA. */
  size_t rdlen;

  /** Original TTL from SOA record (for decrement calculation). */
  uint32_t original_ttl;

  /** Whether SOA data is present (1) or not (0). */
  int has_soa;
} SocketDNS_CachedSOA;

/**
 * @brief Negative cache entry information.
 * @ingroup dns_negcache
 *
 * Returned by lookup functions to provide details about cached entries.
 * Includes SOA data for RFC 2308 Section 6 compliant response serving.
 */
typedef struct
{
  /** Type of negative response (NXDOMAIN or NODATA). */
  SocketDNS_NegCacheType type;

  /** TTL remaining in seconds. */
  uint32_t ttl_remaining;

  /** Original TTL from SOA MINIMUM. */
  uint32_t original_ttl;

  /** Timestamp when entry was inserted (monotonic ms). */
  int64_t insert_time_ms;

  /** Cached SOA data for authority section (RFC 2308 Section 6). */
  SocketDNS_CachedSOA soa;
} SocketDNS_NegCacheEntry;

/**
 * @brief Negative cache statistics.
 * @ingroup dns_negcache
 */
typedef struct
{
  uint64_t hits;             /**< Total cache hits */
  uint64_t misses;           /**< Total cache misses */
  uint64_t nxdomain_hits;    /**< NXDOMAIN-specific hits */
  uint64_t nodata_hits;      /**< NODATA-specific hits */
  uint64_t insertions;       /**< Total insertions */
  uint64_t evictions;        /**< LRU evictions */
  uint64_t expirations;      /**< TTL expirations */
  size_t current_size;       /**< Current entry count */
  size_t max_entries;        /**< Maximum capacity */
  uint32_t max_ttl;          /**< Maximum allowed TTL */
  double hit_rate;           /**< Calculated hit rate */
} SocketDNS_NegCacheStats;

/* Lifecycle functions */

/**
 * @brief Create a new negative cache instance.
 * @ingroup dns_negcache
 *
 * Creates a cache with default settings:
 * - max_entries: 1000
 * - max_ttl: 3600 seconds (1 hour)
 *
 * @param arena Arena for memory allocation (must outlive cache).
 * @return New cache instance, or NULL on allocation failure.
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * SocketDNSNegCache_T cache = SocketDNSNegCache_new(arena);
 * SocketDNSNegCache_set_max_entries(cache, 500);
 * @endcode
 */
extern T SocketDNSNegCache_new (Arena_T arena);

/**
 * @brief Dispose of a negative cache instance.
 * @ingroup dns_negcache
 *
 * Clears all entries and releases resources.
 * The cache pointer is set to NULL.
 *
 * @param cache Pointer to cache instance.
 */
extern void SocketDNSNegCache_free (T *cache);

/* Cache operations */

/**
 * @brief Look up a negative cache entry.
 * @ingroup dns_negcache
 *
 * Checks for cached NXDOMAIN or NODATA responses. Per RFC 2308:
 * - First checks for NXDOMAIN (qtype=0 matches any type)
 * - Then checks for type-specific NODATA
 *
 * @param cache   Cache instance.
 * @param qname   Query name (case-insensitive lookup).
 * @param qtype   Query type (e.g., DNS_TYPE_A, DNS_TYPE_AAAA).
 * @param qclass  Query class (typically DNS_CLASS_IN = 1).
 * @param entry   Output entry details (may be NULL if not needed).
 * @return Lookup result (MISS, HIT_NXDOMAIN, or HIT_NODATA).
 *
 * @code{.c}
 * SocketDNS_NegCacheEntry info;
 * SocketDNS_NegCacheResult result = SocketDNSNegCache_lookup(
 *     cache, "nonexistent.example.com", DNS_TYPE_A, DNS_CLASS_IN, &info);
 *
 * switch (result) {
 * case DNS_NEG_HIT_NXDOMAIN:
 *     printf("Cached NXDOMAIN, TTL=%u\n", info.ttl_remaining);
 *     break;
 * case DNS_NEG_HIT_NODATA:
 *     printf("Cached NODATA for type, TTL=%u\n", info.ttl_remaining);
 *     break;
 * case DNS_NEG_MISS:
 *     printf("Not cached, need to query DNS\n");
 *     break;
 * }
 * @endcode
 */
extern SocketDNS_NegCacheResult SocketDNSNegCache_lookup (
    T cache, const char *qname, uint16_t qtype, uint16_t qclass,
    SocketDNS_NegCacheEntry *entry);

/**
 * @brief Insert an NXDOMAIN entry into the cache.
 * @ingroup dns_negcache
 *
 * Caches an NXDOMAIN response with key `<QNAME, QCLASS>`.
 * This entry will match lookups for ANY query type.
 *
 * @param cache    Cache instance.
 * @param qname    Query name (normalized to lowercase internally).
 * @param qclass   Query class (typically DNS_CLASS_IN = 1).
 * @param ttl      TTL from SOA MINIMUM field.
 * @return 0 on success, -1 on error.
 *
 * @code{.c}
 * // Cache NXDOMAIN for nonexistent.example.com
 * SocketDNSNegCache_insert_nxdomain(cache, "nonexistent.example.com",
 *                                    DNS_CLASS_IN, 300);
 *
 * // Subsequent lookups for ANY type will hit:
 * // - nonexistent.example.com A
 * // - nonexistent.example.com AAAA
 * // - nonexistent.example.com MX
 * // etc.
 * @endcode
 */
extern int SocketDNSNegCache_insert_nxdomain (T cache, const char *qname,
                                               uint16_t qclass, uint32_t ttl);

/**
 * @brief Insert a NODATA entry into the cache.
 * @ingroup dns_negcache
 *
 * Caches a NODATA response with key `<QNAME, QTYPE, QCLASS>`.
 * This entry only matches lookups for the specific query type.
 *
 * @param cache    Cache instance.
 * @param qname    Query name (normalized to lowercase internally).
 * @param qtype    Query type that returned NODATA.
 * @param qclass   Query class (typically DNS_CLASS_IN = 1).
 * @param ttl      TTL from SOA MINIMUM field.
 * @return 0 on success, -1 on error.
 *
 * @code{.c}
 * // Cache NODATA for example.com AAAA (name exists, but no AAAA records)
 * SocketDNSNegCache_insert_nodata(cache, "example.com",
 *                                  DNS_TYPE_AAAA, DNS_CLASS_IN, 300);
 *
 * // Only example.com AAAA lookups will hit cache
 * // example.com A lookups will miss (and may succeed)
 * @endcode
 */
extern int SocketDNSNegCache_insert_nodata (T cache, const char *qname,
                                             uint16_t qtype, uint16_t qclass,
                                             uint32_t ttl);

/**
 * @brief Insert an NXDOMAIN entry with SOA data (RFC 2308 Section 6).
 * @ingroup dns_negcache
 *
 * Caches an NXDOMAIN response with associated SOA record data.
 * The SOA data is stored for RFC 2308 Section 6 compliant response serving.
 *
 * @param cache      Cache instance.
 * @param qname      Query name (normalized to lowercase internally).
 * @param qclass     Query class (typically DNS_CLASS_IN = 1).
 * @param ttl        TTL from SOA MINIMUM field.
 * @param soa        Cached SOA data (may be NULL if no SOA available).
 * @return 0 on success, -1 on error.
 *
 * @code{.c}
 * SocketDNS_CachedSOA soa = {0};
 * strncpy(soa.name, "example.com", sizeof(soa.name) - 1);
 * // ... fill soa.rdata from parsed response ...
 * soa.original_ttl = 3600;
 * soa.has_soa = 1;
 *
 * SocketDNSNegCache_insert_nxdomain_with_soa(cache, "nonexistent.example.com",
 *                                             DNS_CLASS_IN, 300, &soa);
 * @endcode
 */
extern int SocketDNSNegCache_insert_nxdomain_with_soa (
    T cache, const char *qname, uint16_t qclass, uint32_t ttl,
    const SocketDNS_CachedSOA *soa);

/**
 * @brief Insert a NODATA entry with SOA data (RFC 2308 Section 6).
 * @ingroup dns_negcache
 *
 * Caches a NODATA response with associated SOA record data.
 * The SOA data is stored for RFC 2308 Section 6 compliant response serving.
 *
 * @param cache      Cache instance.
 * @param qname      Query name (normalized to lowercase internally).
 * @param qtype      Query type that returned NODATA.
 * @param qclass     Query class (typically DNS_CLASS_IN = 1).
 * @param ttl        TTL from SOA MINIMUM field.
 * @param soa        Cached SOA data (may be NULL if no SOA available).
 * @return 0 on success, -1 on error.
 */
extern int SocketDNSNegCache_insert_nodata_with_soa (
    T cache, const char *qname, uint16_t qtype, uint16_t qclass, uint32_t ttl,
    const SocketDNS_CachedSOA *soa);

/* Response Building (RFC 2308 Section 6) */

/**
 * @brief Build a DNS response for a cached negative entry.
 * @ingroup dns_negcache
 *
 * Constructs a proper DNS response message for a cached negative entry,
 * including the SOA record in the authority section with decremented TTL
 * as required by RFC 2308 Section 6.
 *
 * ## RFC 2308 Section 6 Compliance
 *
 * > "A cached SOA record MUST be added to the authority section when
 * > serving the negative answer. The TTL of this record MUST be decremented
 * > from its original value."
 *
 * @param entry      Cached entry from lookup (must include SOA data).
 * @param qname      Original query name.
 * @param qtype      Original query type.
 * @param qclass     Original query class.
 * @param query_id   ID from original query (for response matching).
 * @param buf        Output buffer for DNS response.
 * @param buflen     Size of output buffer.
 * @param written    Number of bytes written (may be NULL).
 * @return 0 on success, -1 on error (buffer too small, no SOA data).
 *
 * @code{.c}
 * SocketDNS_NegCacheEntry entry;
 * SocketDNS_NegCacheResult result = SocketDNSNegCache_lookup(
 *     cache, "nonexistent.example.com", DNS_TYPE_A, DNS_CLASS_IN, &entry);
 *
 * if (result == DNS_NEG_HIT_NXDOMAIN && entry.soa.has_soa) {
 *     unsigned char response[512];
 *     size_t resplen;
 *     if (SocketDNSNegCache_build_response(&entry, "nonexistent.example.com",
 *                                           DNS_TYPE_A, DNS_CLASS_IN,
 *                                           query_id, response, sizeof(response),
 *                                           &resplen) == 0) {
 *         // Send response with SOA in authority section
 *     }
 * }
 * @endcode
 */
extern int SocketDNSNegCache_build_response (const SocketDNS_NegCacheEntry *entry,
                                              const char *qname, uint16_t qtype,
                                              uint16_t qclass, uint16_t query_id,
                                              unsigned char *buf, size_t buflen,
                                              size_t *written);

/**
 * @brief Remove all entries for a specific name.
 * @ingroup dns_negcache
 *
 * Removes both NXDOMAIN and all NODATA entries for the given name.
 *
 * @param cache  Cache instance.
 * @param qname  Query name to remove.
 * @return Number of entries removed.
 */
extern int SocketDNSNegCache_remove (T cache, const char *qname);

/**
 * @brief Remove a specific NODATA entry.
 * @ingroup dns_negcache
 *
 * Removes only the NODATA entry for the specific name/type/class tuple.
 *
 * @param cache   Cache instance.
 * @param qname   Query name.
 * @param qtype   Query type.
 * @param qclass  Query class.
 * @return 1 if entry was found and removed, 0 if not found.
 */
extern int SocketDNSNegCache_remove_nodata (T cache, const char *qname,
                                             uint16_t qtype, uint16_t qclass);

/**
 * @brief Clear all entries from the cache.
 * @ingroup dns_negcache
 *
 * Removes all cached negative responses.
 *
 * @param cache Cache instance.
 */
extern void SocketDNSNegCache_clear (T cache);

/* Configuration */

/**
 * @brief Set maximum cache entries.
 * @ingroup dns_negcache
 *
 * @param cache       Cache instance.
 * @param max_entries Maximum entries (0 = unlimited).
 */
extern void SocketDNSNegCache_set_max_entries (T cache, size_t max_entries);

/**
 * @brief Set maximum TTL for cached entries.
 * @ingroup dns_negcache
 *
 * Per RFC 2308, one to three hours is recommended.
 * Values exceeding one day are problematic.
 *
 * @param cache   Cache instance.
 * @param max_ttl Maximum TTL in seconds.
 */
extern void SocketDNSNegCache_set_max_ttl (T cache, uint32_t max_ttl);

/**
 * @brief Get cache statistics.
 * @ingroup dns_negcache
 *
 * @param cache Cache instance.
 * @param stats Output statistics structure.
 */
extern void SocketDNSNegCache_stats (T cache, SocketDNS_NegCacheStats *stats);

/* Utility functions */

/**
 * @brief Get type name as string.
 * @ingroup dns_negcache
 *
 * @param type Cache entry type.
 * @return "NXDOMAIN" or "NODATA".
 */
extern const char *SocketDNSNegCache_type_name (SocketDNS_NegCacheType type);

/**
 * @brief Get result name as string.
 * @ingroup dns_negcache
 *
 * @param result Lookup result.
 * @return "MISS", "HIT_NXDOMAIN", or "HIT_NODATA".
 */
extern const char *SocketDNSNegCache_result_name (SocketDNS_NegCacheResult result);

/** @} */ /* End of dns_negcache group */

#undef T

#endif /* SOCKETDNSNEGCACHE_INCLUDED */
