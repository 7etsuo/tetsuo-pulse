/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDNSRESOLVER_INCLUDED
#define SOCKETDNSRESOLVER_INCLUDED

/**
 * @file SocketDNSResolver.h
 * @brief Async DNS resolver with query multiplexing (RFC 1035 Section 7).
 * @ingroup dns
 *
 * Event-loop driven DNS resolver using wire-format DNS directly.
 * Provides proper query ID management, multiplexing, CNAME chain following,
 * and integrates with SocketPoll for async operation.
 *
 * ## RFC References
 *
 * - RFC 1035 Section 7: Resolver implementation
 * - RFC 1035 Section 4.1: Message format
 * - RFC 2308: Negative caching (future)
 *
 * ## Features
 *
 * - Multiple queries in flight (multiplexing)
 * - Query ID generation and response matching
 * - CNAME chain following (max depth 8)
 * - LRU cache with TTL-based expiration
 * - Automatic retry with exponential backoff
 * - TCP fallback on truncation
 * - Event loop integration via SocketPoll
 *
 * ## Usage
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * SocketDNSResolver_T resolver = SocketDNSResolver_new(arena);
 *
 * // Load system nameservers or add manually
 * SocketDNSResolver_load_resolv_conf(resolver);
 * // Or: SocketDNSResolver_add_nameserver(resolver, "8.8.8.8", 53);
 *
 * // Async resolution with callback
 * SocketDNSResolver_resolve(resolver, "example.com", RESOLVER_FLAG_BOTH,
 *                           my_callback, my_userdata);
 *
 * // Event loop
 * while (has_pending_queries) {
 *     SocketDNSResolver_process(resolver, 100);
 * }
 *
 * SocketDNSResolver_free(&resolver);
 * Arena_dispose(&arena);
 * @endcode
 *
 * @see SocketDNSWire.h for wire format encoding/decoding.
 * @see SocketDNSTransport.h for UDP/TCP transport.
 */

#include "core/Arena.h"
#include "core/Except.h"
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @defgroup dns_resolver DNS Resolver
 * @brief Async DNS resolver with query multiplexing.
 * @ingroup dns
 * @{
 */

/* Resolution flags */

/** Query for A records (IPv4). */
#define RESOLVER_FLAG_IPV4 (1 << 0)

/** Query for AAAA records (IPv6). */
#define RESOLVER_FLAG_IPV6 (1 << 1)

/** Query for both A and AAAA records. */
#define RESOLVER_FLAG_BOTH (RESOLVER_FLAG_IPV4 | RESOLVER_FLAG_IPV6)

/** Bypass cache for this query. */
#define RESOLVER_FLAG_NO_CACHE (1 << 2)

/** Force TCP transport (skip UDP). */
#define RESOLVER_FLAG_TCP (1 << 3)

/* Error codes */

/** Resolution completed successfully. */
#define RESOLVER_OK 0

/** All retries exhausted (timeout). */
#define RESOLVER_ERROR_TIMEOUT -1

/** Query was cancelled. */
#define RESOLVER_ERROR_CANCELLED -2

/** Domain does not exist (NXDOMAIN). */
#define RESOLVER_ERROR_NXDOMAIN -3

/** Server failure (SERVFAIL). */
#define RESOLVER_ERROR_SERVFAIL -4

/** Server refused query (REFUSED). */
#define RESOLVER_ERROR_REFUSED -5

/** No nameservers configured. */
#define RESOLVER_ERROR_NO_NS -6

/** Network/socket error. */
#define RESOLVER_ERROR_NETWORK -7

/** CNAME chain too deep (max 8). */
#define RESOLVER_ERROR_CNAME_LOOP -8

/** Invalid response format. */
#define RESOLVER_ERROR_INVALID -9

/** Memory allocation failed. */
#define RESOLVER_ERROR_NOMEM -10

/* Configuration defaults */

/** Default query timeout in milliseconds. */
#define RESOLVER_DEFAULT_TIMEOUT_MS 5000

/** Default maximum retry attempts. */
#define RESOLVER_DEFAULT_MAX_RETRIES 3

/** Default cache TTL in seconds. */
#define RESOLVER_DEFAULT_CACHE_TTL 300

/** Default maximum cache entries. */
#define RESOLVER_DEFAULT_CACHE_MAX 1000

/** Maximum CNAME chain depth. */
#define RESOLVER_MAX_CNAME_DEPTH 8

/** Maximum addresses per result. */
#define RESOLVER_MAX_ADDRESSES 32

/**
 * @brief DNS resolver operation failure exception.
 * @ingroup dns_resolver
 *
 * Raised for initialization failures, invalid parameters, or resource
 * exhaustion.
 */
extern const Except_T SocketDNSResolver_Failed;

#define T SocketDNSResolver_T
typedef struct T *T;

/**
 * @brief Opaque handle for a pending DNS query.
 * @ingroup dns_resolver
 */
typedef struct SocketDNSResolver_Query *SocketDNSResolver_Query_T;

/**
 * @brief Resolved address entry.
 * @ingroup dns_resolver
 *
 * Contains a single resolved IP address with its address family and TTL.
 */
typedef struct
{
  int family; /**< AF_INET or AF_INET6 */
  union
  {
    struct in_addr v4;  /**< IPv4 address (network byte order) */
    struct in6_addr v6; /**< IPv6 address (network byte order) */
  } addr;
  uint32_t ttl; /**< TTL from DNS response (seconds) */
} SocketDNSResolver_Address;

/**
 * @brief Resolution result containing resolved addresses.
 * @ingroup dns_resolver
 *
 * Contains an array of resolved addresses with the minimum TTL.
 * The result must be freed with SocketDNSResolver_result_free().
 */
typedef struct
{
  SocketDNSResolver_Address *addresses; /**< Array of resolved addresses */
  size_t count;                         /**< Number of addresses */
  uint32_t min_ttl;                     /**< Minimum TTL for caching */
} SocketDNSResolver_Result;

/**
 * @brief Query completion callback function type.
 * @ingroup dns_resolver
 *
 * Invoked when a DNS query completes (success or error).
 * The callback is invoked during SocketDNSResolver_process().
 *
 * @param query    Query handle that completed.
 * @param result   Resolution result (NULL on error).
 * @param error    Error code (RESOLVER_OK on success).
 * @param userdata User data passed to resolve function.
 *
 * @note Result is only valid during callback; copy if needed.
 * @note Do not call SocketDNSResolver_free() from within callback.
 */
typedef void (*SocketDNSResolver_Callback) (SocketDNSResolver_Query_T query,
                                            const SocketDNSResolver_Result *result,
                                            int error, void *userdata);

/**
 * @brief Cache statistics structure.
 * @ingroup dns_resolver
 */
typedef struct
{
  uint64_t hits;        /**< Number of cache hits */
  uint64_t misses;      /**< Number of cache misses */
  uint64_t evictions;   /**< Number of LRU evictions */
  uint64_t insertions;  /**< Number of cache insertions */
  size_t current_size;  /**< Current number of cached entries */
  size_t max_entries;   /**< Maximum cache entries */
  int ttl_seconds;      /**< Default TTL for cached entries */
  double hit_rate;      /**< Cache hit rate (0.0 - 1.0) */
} SocketDNSResolver_CacheStats;

/* Lifecycle functions */

/**
 * @brief Create a new DNS resolver instance.
 * @ingroup dns_resolver
 *
 * Creates a resolver with default configuration. Use configuration
 * functions to customize before resolving.
 *
 * @param arena Arena for memory allocation (must outlive resolver).
 * @return New resolver instance.
 * @throws SocketDNSResolver_Failed on allocation or socket creation failure.
 *
 * @code{.c}
 * Arena_T arena = Arena_new();
 * SocketDNSResolver_T resolver = SocketDNSResolver_new(arena);
 * SocketDNSResolver_load_resolv_conf(resolver);
 * @endcode
 */
extern T SocketDNSResolver_new (Arena_T arena);

/**
 * @brief Dispose of a DNS resolver instance.
 * @ingroup dns_resolver
 *
 * Cancels all pending queries (callbacks invoked with RESOLVER_ERROR_CANCELLED)
 * and releases resources. The resolver pointer is set to NULL.
 *
 * @param resolver Pointer to resolver instance.
 */
extern void SocketDNSResolver_free (T *resolver);

/* Configuration functions */

/**
 * @brief Load nameservers from /etc/resolv.conf.
 * @ingroup dns_resolver
 *
 * Parses the system resolver configuration and adds nameservers.
 * Clears any previously configured nameservers.
 *
 * @param resolver Resolver instance.
 * @return Number of nameservers loaded, or -1 on error.
 */
extern int SocketDNSResolver_load_resolv_conf (T resolver);

/**
 * @brief Add a nameserver to the resolver.
 * @ingroup dns_resolver
 *
 * @param resolver Resolver instance.
 * @param address  IPv4 or IPv6 address string.
 * @param port     Port number (typically 53).
 * @return 0 on success, -1 if max nameservers reached or invalid address.
 *
 * @code{.c}
 * SocketDNSResolver_add_nameserver(resolver, "8.8.8.8", 53);
 * SocketDNSResolver_add_nameserver(resolver, "2001:4860:4860::8888", 53);
 * @endcode
 */
extern int SocketDNSResolver_add_nameserver (T resolver, const char *address,
                                             int port);

/**
 * @brief Remove all configured nameservers.
 * @ingroup dns_resolver
 *
 * @param resolver Resolver instance.
 */
extern void SocketDNSResolver_clear_nameservers (T resolver);

/**
 * @brief Get configured nameserver count.
 * @ingroup dns_resolver
 *
 * @param resolver Resolver instance.
 * @return Number of configured nameservers.
 */
extern int SocketDNSResolver_nameserver_count (T resolver);

/**
 * @brief Set query timeout.
 * @ingroup dns_resolver
 *
 * @param resolver   Resolver instance.
 * @param timeout_ms Timeout in milliseconds (default: 5000).
 */
extern void SocketDNSResolver_set_timeout (T resolver, int timeout_ms);

/**
 * @brief Set maximum retry attempts.
 * @ingroup dns_resolver
 *
 * @param resolver    Resolver instance.
 * @param max_retries Maximum retries (default: 3).
 */
extern void SocketDNSResolver_set_retries (T resolver, int max_retries);

/* Resolution functions */

/**
 * @brief Resolve a hostname asynchronously.
 * @ingroup dns_resolver
 *
 * Starts an async DNS resolution. The callback is invoked when complete.
 * If the hostname is cached and valid, the callback may be invoked
 * immediately (before this function returns).
 *
 * @param resolver Resolver instance.
 * @param hostname Hostname to resolve (must not be NULL).
 * @param flags    Resolution flags (RESOLVER_FLAG_*).
 * @param callback Completion callback (required).
 * @param userdata User data passed to callback.
 * @return Query handle on success, NULL on error.
 *
 * @code{.c}
 * void my_callback(SocketDNSResolver_Query_T query,
 *                  const SocketDNSResolver_Result *result,
 *                  int error, void *userdata) {
 *     if (error == RESOLVER_OK) {
 *         for (size_t i = 0; i < result->count; i++) {
 *             // Use result->addresses[i]
 *         }
 *     }
 * }
 *
 * SocketDNSResolver_resolve(resolver, "example.com", RESOLVER_FLAG_BOTH,
 *                           my_callback, NULL);
 * @endcode
 */
extern SocketDNSResolver_Query_T SocketDNSResolver_resolve (
    T resolver, const char *hostname, int flags,
    SocketDNSResolver_Callback callback, void *userdata);

/**
 * @brief Cancel a pending query.
 * @ingroup dns_resolver
 *
 * The callback will be invoked with RESOLVER_ERROR_CANCELLED during the
 * next SocketDNSResolver_process() call.
 *
 * @param resolver Resolver instance.
 * @param query    Query handle to cancel.
 * @return 0 on success, -1 if query not found or already completed.
 */
extern int SocketDNSResolver_cancel (T resolver, SocketDNSResolver_Query_T query);

/**
 * @brief Get the hostname being resolved by a query.
 * @ingroup dns_resolver
 *
 * @param query Query handle.
 * @return Hostname string (valid while query is pending).
 */
extern const char *SocketDNSResolver_query_hostname (SocketDNSResolver_Query_T query);

/* Event loop integration */

/**
 * @brief Get the IPv4 socket file descriptor.
 * @ingroup dns_resolver
 *
 * For external poll integration with SocketPoll.
 *
 * @param resolver Resolver instance.
 * @return File descriptor (>= 0) or -1 if not initialized.
 */
extern int SocketDNSResolver_fd_v4 (T resolver);

/**
 * @brief Get the IPv6 socket file descriptor.
 * @ingroup dns_resolver
 *
 * For external poll integration with SocketPoll.
 *
 * @param resolver Resolver instance.
 * @return File descriptor (>= 0) or -1 if not initialized.
 */
extern int SocketDNSResolver_fd_v6 (T resolver);

/**
 * @brief Process pending queries.
 * @ingroup dns_resolver
 *
 * Receives DNS responses, handles timeouts, fires callbacks.
 * Must be called regularly in the event loop.
 *
 * @param resolver   Resolver instance.
 * @param timeout_ms Maximum time to wait for events (0 = non-blocking).
 * @return Number of queries completed, or -1 on error.
 *
 * @code{.c}
 * // Event loop
 * while (SocketDNSResolver_pending_count(resolver) > 0) {
 *     SocketDNSResolver_process(resolver, 100);
 * }
 * @endcode
 */
extern int SocketDNSResolver_process (T resolver, int timeout_ms);

/**
 * @brief Get number of pending queries.
 * @ingroup dns_resolver
 *
 * @param resolver Resolver instance.
 * @return Number of queries awaiting response.
 */
extern int SocketDNSResolver_pending_count (T resolver);

/* Cache functions */

/**
 * @brief Clear all cached entries.
 * @ingroup dns_resolver
 *
 * @param resolver Resolver instance.
 */
extern void SocketDNSResolver_cache_clear (T resolver);

/**
 * @brief Set cache TTL.
 * @ingroup dns_resolver
 *
 * @param resolver    Resolver instance.
 * @param ttl_seconds TTL in seconds (0 = use response TTL).
 */
extern void SocketDNSResolver_cache_set_ttl (T resolver, int ttl_seconds);

/**
 * @brief Set maximum cache entries.
 * @ingroup dns_resolver
 *
 * @param resolver    Resolver instance.
 * @param max_entries Maximum entries (0 = disable cache).
 */
extern void SocketDNSResolver_cache_set_max (T resolver, size_t max_entries);

/**
 * @brief Get cache statistics.
 * @ingroup dns_resolver
 *
 * @param resolver Resolver instance.
 * @param stats    Output statistics structure.
 */
extern void SocketDNSResolver_cache_stats (T resolver,
                                           SocketDNSResolver_CacheStats *stats);

/* Utility functions */

/**
 * @brief Free a resolution result.
 * @ingroup dns_resolver
 *
 * Frees the addresses array in the result. Safe to call with NULL.
 *
 * @param result Result to free (may be NULL).
 */
extern void SocketDNSResolver_result_free (SocketDNSResolver_Result *result);

/**
 * @brief Convert resolver error code to string.
 * @ingroup dns_resolver
 *
 * @param error Error code (RESOLVER_ERROR_*).
 * @return Human-readable error string.
 */
extern const char *SocketDNSResolver_strerror (int error);

/** @} */ /* End of dns_resolver group */

#undef T

#endif /* SOCKETDNSRESOLVER_INCLUDED */
