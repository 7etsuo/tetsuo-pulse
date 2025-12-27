/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDNS_INCLUDED
#define SOCKETDNS_INCLUDED

#include "core/Except.h"
#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/**
 * @defgroup dns Asynchronous DNS Resolution
 * @brief Thread pool-based DNS resolution with guaranteed timeouts and
 * SocketPoll integration.
 * @ingroup core_io
 *
 * Provides asynchronous DNS resolution using a thread pool to eliminate
 * blocking getaddrinfo() calls that can take 30+ seconds during DNS failures.
 * This addresses DoS vulnerabilities and enables truly non-blocking socket
 * operations.
 *
 * ## Architecture Overview
 *
 * ```
 * ┌─────────────────────────────┐
 * │     Application Thread      │
 * │ SocketDNS_resolve() calls   │
 * └─────────┬───────────────────┘
 *           │ queue request
 * ┌─────────▼───────────────────┐
 * │   SocketDNS_T (Main)        │
 * │  - Mutex-protected queue    │
 * │  - Hash table (requests)    │
 * │  - Completion pipe FD       │
 * │  - Condition vars (sync)    │
 * └─────────┬───────────────────┘
 *           │ signal workers
 * ┌─────────▼───────────────────┐   ┌─────────────────┐
 * │   Worker Threads Pool       │──▶│ getaddrinfo()   │
 * │  - Process queue items      │   │ - System call   │
 * │  - Perform getaddrinfo()    │   │ - Timeout check │
 * │  - Signal completion        │   └─────────────────┘
 * └─────────┬───────────────────┘
 *           │ write pipe
 * ┌─────────▼───────────────────┐
 * │ Completion Pipe (pollfd)    │ ──▶ SocketPoll integration
 * └─────────────────────────────┘
 * ```
 *
 * ## Key Features
 *
 * - **Non-blocking**: No main-thread blocking; workers handle slow DNS.
 * - **Thread-safe**: Mutex protects shared state; callbacks in workers.
 * - **DoS Protection**: Bounded queue, timeouts prevent resource exhaustion.
 * - **Flexible**: Callback or poll mode for completion handling.
 * - **Sync Wrapper**: SocketDNS_resolve_sync() with guaranteed timeout.
 *
 * ## Module Relationships
 *
 * - **Depends on**: @ref foundation (Arena_T, Except_T), core/SocketUtil
 * (logging/metrics), socket/SocketCommon (address resolution utils).
 * - **Used by**: @ref connection_mgmt (SocketPool::prepare_connection,
 * SocketReconnect), @ref core_io (Socket::connect helpers).
 * - **Integrates with**: @ref event_system (SocketPoll via completion pipe
 * FD).
 *
 * ## Configuration Parameters
 *
 * | Parameter | Default | Description |
 * |-----------|---------|-------------|
 * | num_workers | CPU cores | Thread pool size
 * (SOCKET_DNS_DEFAULT_NUM_WORKERS) | | max_pending | 1000 | Queue capacity
 * (SOCKET_DNS_MAX_PENDING) | | timeout_ms | 5000 | Default request timeout
 * (SOCKET_DNS_DEFAULT_TIMEOUT_MS) |
 *
 * ## Error Handling
 *
 * - **Exceptions**: SocketDNS_Failed for init, queue full, invalid params.
 * - **getaddrinfo() Codes**: Passed via SocketDNS_geterror(); retryable:
 * EAI_AGAIN.
 * - **Cancellation**: EAI_CANCELED for user-cancelled requests.
 *
 * @warning Callbacks execute in **worker threads**, NOT main thread! Ensure
 * thread-safety; avoid shared mutable state without locks.
 *
 * @see SocketDNS_new() for creation.
 * @see SocketDNS_resolve() for async requests.
 * @see SocketDNS_resolve_sync() for synchronous with timeout.
 * @see SocketDNS_pollfd() and SocketDNS_check() for event loop.
 * @see docs/ASYNC_IO.md for detailed async patterns.
 * @see docs/SECURITY.md for DoS protection details.
 * @see docs/ERROR_HANDLING.md for exception and error codes.
 * @{
 */

#define T SocketDNS_T
/**
 * @brief Opaque type for DNS resolver instances.
 * @ingroup dns
 */
typedef struct T *T;

/**
 * @brief Opaque type for DNS resolution requests.
 * @ingroup dns
 */
typedef struct SocketDNS_Request_T SocketDNS_Request_T;
/**
 * @brief Pointer to DNS resolution request structure.
 * @ingroup dns
 */
typedef SocketDNS_Request_T *Request_T;

/**
 * @brief DNS resolution operation failure exception.
 * @ingroup dns
 *
 * Category: NETWORK
 * Retryable: YES - DNS servers may recover, cache may refresh
 *
 * Raised when DNS resolution fails:
 * - Server unreachable (transient)
 * - Query timeout (transient)
 * - Invalid hostname (permanent)
 * - NXDOMAIN (permanent)
 * - Resource allocation failure
 * - Thread pool initialization failure
 *
 * Check the error code from callback for specific failure reason.
 * Transient failures (EAI_AGAIN, EAI_NODATA) are worth retrying.
 * Permanent failures (EAI_NONAME, EAI_FAIL) should not be retried.
 *
 * @see SocketDNS_resolve() for resolution operations.
 * @see SocketDNS_new() for initialization operations.
 * @see @ref foundation::Except_T for exception base type.
 */
extern const Except_T SocketDNS_Failed;

/**
 * @brief Callback function for async DNS resolution.
 * @ingroup dns
 * @param req Request handle for this resolution.
 * @param result Completed addrinfo result (NULL on error).
 * @param error Error code from getaddrinfo() (0 on success).
 * @param data User data passed to SocketDNS_resolve().
 *
 * Called when DNS resolution completes. If result is NULL, error contains
 * the getaddrinfo() error code.
 *
 * OWNERSHIP: The callback receives ownership of the result addrinfo structure
 * and MUST call freeaddrinfo() when done with it.
 *
 * THREAD SAFETY WARNING: Callbacks are invoked from DNS WORKER THREADS,
 * NOT from the application thread. The callback implementation MUST:
 *
 * - Be thread-safe if accessing shared application data structures
 * - Use proper synchronization (mutexes) when modifying shared state
 * - NOT store the @req pointer (it becomes invalid after callback returns)
 * - NOT call SocketDNS_free() from within the callback (deadlock)
 * - NOT perform long-running or blocking operations (blocks DNS workers)
 * - Take ownership of @result immediately (copy if needed for later use)
 *
 * For applications that cannot safely handle worker-thread callbacks,
 * use the SocketPoll integration pattern instead (pass NULL callback to
 * SocketDNS_resolve and use SocketDNS_check/SocketDNS_getresult).
 */
typedef void (*SocketDNS_Callback) (SocketDNS_Request_T *req,
                                    struct addrinfo *result, int error,
                                    void *data);

/**
 * @brief Create a new asynchronous DNS resolver.
 * @ingroup dns
 *
 * Initializes a thread pool-based DNS resolver that offloads getaddrinfo()
 * calls to worker threads. Supports callback and polling completion modes
 * with DoS protection via queue limits and timeouts.
 *
 * @return New DNS resolver instance.
 * @throws SocketDNS_Failed on allocation/thread/pipe initialization failure.
 * @threadsafe Yes.
 *
 * @see SocketDNS_free() for cleanup.
 * @see SocketDNS_resolve() for submitting requests.
 */
extern T SocketDNS_new (void);

/**
 * @brief Dispose of DNS resolver and release all resources.
 * @ingroup dns
 *
 * Signals workers to stop, cancels pending requests, drains completion pipe,
 * joins threads, and frees all internal resources. Safe to call on NULL.
 *
 * @param[in,out] dns Pointer to resolver instance (set to NULL on success).
 * @threadsafe Conditional - ensure no concurrent resolve/getresult calls.
 *
 * @warning Unretrieved completed results are lost. Drain pending before free.
 *
 * @see SocketDNS_new() for paired creation.
 * @see SocketDNS_check() for draining before shutdown.
 */
extern void SocketDNS_free (T *dns);

/**
 * @brief Start asynchronous DNS resolution.
 * @ingroup dns
 *
 * Submits a DNS resolution request to the thread pool. Supports callback mode
 * (provide callback) or polling mode (NULL callback, use pollfd/check/getresult).
 *
 * @param[in] dns Resolver instance.
 * @param[in] host Hostname/IP or NULL (wildcard bind).
 * @param[in] port Port (0-65535).
 * @param[in] callback Completion callback or NULL (polling mode).
 * @param[in] data User data passed to callback.
 * @return Request handle.
 * @throws SocketDNS_Failed on invalid params, queue full, or allocation failure.
 * @threadsafe Yes.
 *
 * @warning Callbacks run in worker threads - must be thread-safe.
 *
 * @see SocketDNS_Callback for callback safety rules.
 * @see SocketDNS_pollfd() and SocketDNS_check() for polling mode.
 */
extern Request_T SocketDNS_resolve (T dns, const char *host, int port,
                                    SocketDNS_Callback callback, void *data);

/**
 * @brief Cancel a pending DNS resolution.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request handle to cancel.
 * @threadsafe Yes - protected by internal mutex.
 *
 * Cancels a pending request. If resolution has already completed, this
 * has no effect. The request handle becomes invalid after cancellation.
 * Callbacks will not be invoked for cancelled requests.
 *
 * @see SocketDNS_resolve() for creating requests.
 * @see SocketDNS_getresult() for retrieving completed results.
 */
extern void SocketDNS_cancel (T dns, Request_T req);

/**
 * @brief Get maximum pending request capacity.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @return Current pending request limit.
 * @threadsafe Yes.
 * @see SocketDNS_setmaxpending() for setting the limit.
 */
extern size_t SocketDNS_getmaxpending (T dns);

/**
 * @brief Set maximum pending request capacity.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param max_pending New pending request limit (0 allows no pending requests).
 * @throws SocketDNS_Failed if max_pending < current queue depth.
 * @threadsafe Yes.
 * @see SocketDNS_getmaxpending() for retrieving the current limit.
 */
extern void SocketDNS_setmaxpending (T dns, size_t max_pending);

/**
 * @brief Get resolver request timeout in milliseconds.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @return Timeout in milliseconds (0 disables timeout).
 * @threadsafe Yes.
 * @see SocketDNS_settimeout() for setting the timeout.
 */
extern int SocketDNS_gettimeout (T dns);

/**
 * @brief Set resolver request timeout in milliseconds.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param timeout_ms Timeout in milliseconds (0 disables timeout).
 * @threadsafe Yes.
 * @see SocketDNS_gettimeout() for retrieving the current timeout.
 */
extern void SocketDNS_settimeout (T dns, int timeout_ms);

/**
 * @brief Get file descriptor for integration with SocketPoll.
 * @ingroup dns
 *
 * Returns the read end of the completion pipe. Becomes readable when requests
 * complete, cancel, or timeout. Use with SocketPoll for event loop integration.
 *
 * @param[in] dns Resolver instance.
 * @return Valid FD (>=0) or -1 on error.
 * @threadsafe Yes.
 *
 * @see SocketDNS_check() for draining signals.
 */
extern int SocketDNS_pollfd (T dns);

/**
 * @brief Check for completed requests (non-blocking).
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @return Number of completion signals drained (1 byte per
 * completed/cancelled/timeout request).
 * @threadsafe Yes - safe to call from any thread.
 *
 * Drains the signal pipe for completed DNS events. Does not automatically
 * retrieve results. For poll-mode requests (no callback), track your Request_T
 * handles and call SocketDNS_getresult() after draining to fetch completed
 * results. Call when SocketDNS_pollfd() is readable.
 *
 * @see SocketDNS_pollfd() for the file descriptor to monitor.
 * @see SocketDNS_getresult() for retrieving completed results.
 */
extern int SocketDNS_check (T dns);

/**
 * @brief Retrieve completed DNS resolution result.
 * @ingroup dns
 *
 * Fetches addrinfo for completed polling-mode requests. Transfers ownership
 * to caller and invalidates the request handle.
 *
 * @param[in] dns Resolver owning the request.
 * @param[in] req Request handle.
 * @return addrinfo chain (caller must freeaddrinfo()) or NULL if pending/failed.
 * @threadsafe Yes.
 *
 * @see SocketDNS_geterror() for error code on failure.
 */
extern struct addrinfo *SocketDNS_getresult (T dns, Request_T req);

/**
 * @brief Get error code for completed request.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request handle (must have been returned by SocketDNS_resolve() on
 * this same resolver instance).
 * @return getaddrinfo() error code, or 0 on success, or 0 if request does not
 * belong to this resolver (invalid handle).
 * @threadsafe Yes - protected by internal mutex.
 *
 * IMPORTANT: Only use request handles returned by SocketDNS_resolve() or
 * SocketDNS_create_completed_request() on the SAME resolver instance.
 *
 * @see SocketDNS_getresult() for retrieving successful results.
 * @see SocketDNS_resolve() for creating requests.
 */
extern int SocketDNS_geterror (T dns, Request_T req);

/**
 * @brief Override timeout for specific request.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request handle.
 * @param timeout_ms Timeout in milliseconds (0 disables timeout for this
 * request).
 * @threadsafe Yes.
 * @see SocketDNS_settimeout() for setting the default timeout.
 * @see SocketDNS_resolve() for creating requests.
 */
extern void SocketDNS_request_settimeout (T dns, Request_T req,
                                          int timeout_ms);

/**
 * @brief Create a completed request from pre-resolved addrinfo.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param result Pre-resolved addrinfo result (caller transfers ownership).
 * @param port Port number.
 * @return Request handle for completed request.
 * @throws SocketDNS_Failed on allocation failure.
 * @threadsafe Yes - protected by internal mutex.
 *
 * Creates a request that is already marked as complete with the provided
 * result. Useful for synchronous resolution (e.g., wildcard bind) that doesn't
 * need async DNS. The caller transfers ownership of the addrinfo result to the
 * request.
 *
 * @see SocketDNS_getresult() for retrieving the result.
 * @see SocketDNS_resolve_sync() for synchronous resolution.
 */
extern Request_T
SocketDNS_create_completed_request (T dns, struct addrinfo *result, int port);

/**
 * @brief Synchronous DNS resolution with timeout guarantee.
 * @ingroup dns
 *
 * Performs blocking DNS resolution with configurable timeout. Uses async
 * machinery internally to enforce timeout, preventing unbounded blocking.
 *
 * @param[in] dns Resolver (NULL = direct getaddrinfo, no timeout protection).
 * @param[in] host Host/IP or NULL (wildcard bind).
 * @param[in] port Port number.
 * @param[in] hints getaddrinfo hints or NULL for defaults.
 * @param[in] timeout_ms Max wait (0 = use resolver default).
 * @return addrinfo (caller must freeaddrinfo()).
 * @throws SocketDNS_Failed on resolution failure or timeout.
 * @threadsafe Yes.
 *
 * @see SocketDNS_resolve() for asynchronous resolution.
 */
extern struct addrinfo *SocketDNS_resolve_sync (T dns, const char *host,
                                                int port,
                                                const struct addrinfo *hints,
                                                int timeout_ms);

/**
 * @brief Cache statistics structure.
 * @ingroup dns
 *
 * Statistics about DNS resolution cache performance. Used to monitor
 * cache efficiency and tune TTL/size parameters.
 *
 * @see SocketDNS_cache_stats() to retrieve statistics.
 * @see SocketDNS_cache_clear() to reset cache.
 */
typedef struct SocketDNS_CacheStats
{
  uint64_t hits;        /**< Cache hits (result found in cache) */
  uint64_t misses;      /**< Cache misses (resolution required) */
  uint64_t evictions;   /**< Entries evicted due to TTL or size limits */
  uint64_t insertions;  /**< Total entries inserted into cache */
  size_t current_size;  /**< Current number of cached entries */
  size_t max_entries;   /**< Maximum cache capacity */
  int ttl_seconds;      /**< Current TTL setting */
  double hit_rate;      /**< Calculated hit rate (hits / (hits + misses)) */
} SocketDNS_CacheStats;

/**
 * @brief Clear the entire DNS result cache.
 * @ingroup dns
 * @param[in] dns DNS resolver instance.
 * @threadsafe Yes - protected by internal mutex.
 *
 * Removes all cached DNS resolution results, forcing fresh lookups
 * for subsequent requests. Useful when DNS records are known to have
 * changed or when troubleshooting resolution issues.
 *
 * ## Example
 *
 * @code{.c}
 * // DNS records changed, force fresh lookups
 * SocketDNS_cache_clear(dns);
 *
 * // Now all resolutions will query DNS servers
 * SocketDNS_resolve(dns, "example.com", 443, callback, data);
 * @endcode
 *
 * @complexity O(n) where n is number of cached entries.
 *
 * @see SocketDNS_cache_remove() to remove specific entries.
 * @see SocketDNS_cache_stats() to check cache state.
 */
extern void SocketDNS_cache_clear (T dns);

/**
 * @brief Remove a specific hostname from the DNS cache.
 * @ingroup dns
 * @param[in] dns DNS resolver instance.
 * @param[in] hostname Hostname to remove from cache.
 * @return 1 if entry was found and removed, 0 if not found.
 * @threadsafe Yes - protected by internal mutex.
 *
 * Removes a specific hostname's cached result, forcing a fresh DNS lookup
 * on the next resolution request for that hostname.
 *
 * ## Example
 *
 * @code{.c}
 * // Known DNS change for specific host
 * if (SocketDNS_cache_remove(dns, "api.example.com")) {
 *     printf("Removed stale cache entry\n");
 * }
 * @endcode
 *
 * @complexity O(1) average - hash table lookup.
 *
 * @see SocketDNS_cache_clear() to clear entire cache.
 */
extern int SocketDNS_cache_remove (T dns, const char *hostname);

/**
 * @brief Set the TTL (time-to-live) for cached DNS results.
 * @ingroup dns
 * @param[in] dns DNS resolver instance.
 * @param[in] ttl_seconds TTL in seconds (0 disables caching).
 * @threadsafe Yes - protected by internal mutex.
 *
 * Controls how long resolved DNS results are cached before being considered
 * stale and requiring re-resolution. Setting to 0 effectively disables
 * caching (all requests go to DNS servers).
 *
 * ## Default
 *
 * Default TTL is SOCKET_DNS_DEFAULT_CACHE_TTL_SECONDS (300 = 5 minutes).
 *
 * ## Example
 *
 * @code{.c}
 * // Short TTL for frequently changing DNS
 * SocketDNS_cache_set_ttl(dns, 60);  // 1 minute
 *
 * // Disable caching entirely
 * SocketDNS_cache_set_ttl(dns, 0);
 *
 * // Long TTL for stable DNS
 * SocketDNS_cache_set_ttl(dns, 3600);  // 1 hour
 * @endcode
 *
 * @note Does not affect existing cached entries; only new insertions.
 *
 * @see SocketDNS_cache_stats() to check current TTL.
 */
extern void SocketDNS_cache_set_ttl (T dns, int ttl_seconds);

/**
 * @brief Set the maximum number of entries in the DNS cache.
 * @ingroup dns
 * @param[in] dns DNS resolver instance.
 * @param[in] max_entries Maximum cache entries (0 disables caching).
 * @threadsafe Yes - protected by internal mutex.
 *
 * Limits memory usage by capping the number of cached DNS results.
 * When the limit is reached, oldest entries are evicted (LRU).
 *
 * ## Default
 *
 * Default max is SOCKET_DNS_DEFAULT_CACHE_MAX_ENTRIES (1000).
 *
 * ## Example
 *
 * @code{.c}
 * // Limit cache for memory-constrained environments
 * SocketDNS_cache_set_max_entries(dns, 100);
 *
 * // Large cache for high-traffic servers
 * SocketDNS_cache_set_max_entries(dns, 10000);
 * @endcode
 *
 * @note If new limit is less than current size, excess entries are evicted.
 *
 * @see SocketDNS_cache_stats() to check current size.
 */
extern void SocketDNS_cache_set_max_entries (T dns, size_t max_entries);

/**
 * @brief Get DNS cache statistics.
 * @ingroup dns
 * @param[in] dns DNS resolver instance.
 * @param[out] stats Output statistics structure.
 * @threadsafe Yes - atomic snapshot.
 *
 * Retrieves current cache statistics including hit/miss rates, size,
 * and configuration. Useful for monitoring and tuning cache parameters.
 *
 * ## Example
 *
 * @code{.c}
 * SocketDNS_CacheStats stats;
 * SocketDNS_cache_stats(dns, &stats);
 *
 * printf("Cache hit rate: %.1f%% (%lu hits, %lu misses)\n",
 *        stats.hit_rate * 100.0,
 *        (unsigned long)stats.hits,
 *        (unsigned long)stats.misses);
 * printf("Cache size: %zu / %zu entries\n",
 *        stats.current_size, stats.max_entries);
 * printf("Evictions: %lu\n", (unsigned long)stats.evictions);
 * @endcode
 *
 * @complexity O(1).
 *
 * @see SocketDNS_CacheStats for field descriptions.
 * @see SocketDNS_cache_clear() to reset cache.
 */
extern void SocketDNS_cache_stats (T dns, SocketDNS_CacheStats *stats);

/**
 * @brief Set IPv6 preference for DNS resolution.
 * @ingroup dns
 * @param[in] dns DNS resolver instance.
 * @param[in] prefer_ipv6 1 to prefer IPv6, 0 to prefer IPv4.
 * @threadsafe Yes - protected by internal mutex.
 *
 * Controls whether IPv6 (AAAA records) or IPv4 (A records) addresses
 * are preferred when both are available. Affects the ordering of
 * addresses in resolution results.
 *
 * ## Default
 *
 * Default is 1 (prefer IPv6) per RFC 6724 recommendations.
 *
 * ## Example
 *
 * @code{.c}
 * // Prefer IPv4 (legacy compatibility)
 * SocketDNS_prefer_ipv6(dns, 0);
 *
 * // Prefer IPv6 (modern default)
 * SocketDNS_prefer_ipv6(dns, 1);
 * @endcode
 *
 * @note This sets AI_ADDRCONFIG hints appropriately. System resolver
 *       may still return both address families.
 *
 * @see SocketHappyEyeballs for RFC 8305 dual-stack connection racing.
 */
extern void SocketDNS_prefer_ipv6 (T dns, int prefer_ipv6);

/**
 * @brief Get current IPv6 preference setting.
 * @ingroup dns
 * @param[in] dns DNS resolver instance.
 * @return 1 if IPv6 preferred, 0 if IPv4 preferred.
 * @threadsafe Yes.
 *
 * @see SocketDNS_prefer_ipv6() to set preference.
 */
extern int SocketDNS_get_prefer_ipv6 (T dns);

/**
 * @brief Set custom nameservers for DNS resolution.
 * @ingroup dns
 * @param[in] dns DNS resolver instance.
 * @param[in] servers Array of nameserver IP addresses (NULL-terminated).
 * @param[in] count Number of servers in array.
 * @return 0 on success, -1 if custom nameservers not supported.
 * @threadsafe Yes - protected by internal mutex.
 *
 * Configures custom DNS nameservers instead of using system resolv.conf.
 * This is useful for applications that need to use specific DNS servers
 * (e.g., DNS-over-HTTPS, private DNS, or fallback servers).
 *
 * ## Platform Support
 *
 * This function requires platform-specific resolver configuration:
 * - **Linux**: Uses res_init() with modified _res structure
 * - **macOS/BSD**: Limited support via dns_open()/dns_search()
 * - **Windows**: Requires different API (not supported)
 *
 * If custom nameservers are not supported on the platform, this function
 * returns -1 and the system resolver continues to be used.
 *
 * ## Example
 *
 * @code{.c}
 * const char *servers[] = {"8.8.8.8", "8.8.4.4", NULL};
 * if (SocketDNS_set_nameservers(dns, servers, 2) < 0) {
 *     printf("Custom nameservers not supported, using system resolver\n");
 * }
 * @endcode
 *
 * @note Changes affect only this resolver instance, not system-wide.
 * @note Pass NULL and count=0 to revert to system nameservers.
 *
 * @see SocketDNS_set_search_domains() for search path configuration.
 */
extern int SocketDNS_set_nameservers (T dns, const char **servers,
                                      size_t count);

/**
 * @brief Set DNS search domains for hostname resolution.
 * @ingroup dns
 * @param[in] dns DNS resolver instance.
 * @param[in] domains Array of search domain strings (NULL-terminated).
 * @param[in] count Number of domains in array.
 * @return 0 on success, -1 if custom search domains not supported.
 * @threadsafe Yes - protected by internal mutex.
 *
 * Configures DNS search domains for resolving unqualified hostnames.
 * When resolving a name like "myserver", the resolver will try
 * "myserver.domain1", "myserver.domain2", etc.
 *
 * ## Platform Support
 *
 * Similar to SocketDNS_set_nameservers(), this requires platform support.
 *
 * ## Example
 *
 * @code{.c}
 * const char *domains[] = {"internal.company.com", "company.com", NULL};
 * if (SocketDNS_set_search_domains(dns, domains, 2) < 0) {
 *     printf("Custom search domains not supported\n");
 * }
 *
 * // Now "myserver" resolves as "myserver.internal.company.com" first
 * SocketDNS_resolve(dns, "myserver", 80, callback, data);
 * @endcode
 *
 * @note Pass NULL and count=0 to revert to system search domains.
 *
 * @see SocketDNS_set_nameservers() for nameserver configuration.
 */
extern int SocketDNS_set_search_domains (T dns, const char **domains,
                                         size_t count);

#undef T
#undef Request_T

/** @} */ // Close dns group
#endif
