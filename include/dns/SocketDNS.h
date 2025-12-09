#ifndef SOCKETDNS_INCLUDED
#define SOCKETDNS_INCLUDED

#include "core/Except.h"
#include <netdb.h>
#include <stddef.h>
#include <sys/socket.h>

/**
 * @defgroup dns Asynchronous DNS Resolution
 * @brief Thread pool-based DNS resolution with guaranteed timeouts and SocketPoll integration.
 * @ingroup core_io
 *
 * Provides asynchronous DNS resolution using a thread pool to eliminate blocking getaddrinfo()
 * calls that can take 30+ seconds during DNS failures. This addresses DoS vulnerabilities
 * and enables truly non-blocking socket operations.
 *
 * Key components:
 * - SocketDNS_T: Main resolver with thread pool and queue management
 * - SocketDNS_Request_T: Individual DNS resolution request structure
 * - Thread pool for concurrent resolution with O(1) hash table lookup
 * - Completion pipe for SocketPoll integration
 * - Guaranteed timeouts to prevent DoS attacks
 *
 * Requires @ref foundation (Arena_T, Except_T)
 * Used by @ref core_io (Socket_T for hostname resolution), @ref connection_mgmt (SocketPool, SocketReconnect)
 *
 * @see @ref event_system for SocketPoll integration.
 * @see SocketDNS_new() for resolver creation.
 * @see SocketDNS_resolve() for async resolution.
 * @see SocketDNS_pollfd() for event loop integration.
 * @warning Callbacks execute in worker threads, not main thread!
 * @{
 */

/**
 * @file SocketDNS.h
 * @brief Asynchronous DNS resolution API.
 * @ingroup dns
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

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

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
typedef void (*SocketDNS_Callback)(SocketDNS_Request_T *req, struct addrinfo *result,
                                   int error, void *data);

/**
 * @brief Create a new asynchronous DNS resolver.
 * @ingroup dns
 * @return New DNS resolver instance.
 * @throws SocketDNS_Failed on initialization failure.
 * @note Thread-safe: Yes - returns new instance.
 *
 * Creates a thread pool for DNS resolution. Default thread count is
 * SOCKET_DNS_THREAD_COUNT (configurable via SocketConfig.h).
 *
 * @see SocketDNS_free() for cleanup.
 * @see SocketDNS_resolve() for starting resolution requests.
 * @see @ref dns for module overview and usage patterns.
 */
extern T SocketDNS_new(void);

/**
 * @brief Free a DNS resolver.
 * @ingroup dns
 * @param dns Pointer to resolver (will be set to NULL).
 *
 * Drains pending requests, signals worker threads to stop, and joins threads.
 * Any pending requests that have not been retrieved are cancelled.
 *
 * @note Thread-safe: Yes - safely shuts down thread pool.
 * @see SocketDNS_new() for creation.
 * @see SocketDNS_cancel() for cancelling individual requests.
 */
extern void SocketDNS_free(T *dns);

/**
 * @brief Start asynchronous DNS resolution.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param host Hostname or IP address to resolve (NULL for wildcard bind with AI_PASSIVE).
 * @param port Port number (0 = no service/port in resolution, 1-65535 for specific port).
 * @param callback Completion callback (NULL for SocketPoll integration).
 * @param data User data passed to callback.
 * @return Request handle (never NULL).
 * @throws SocketDNS_Failed on queue full or invalid parameters.
 * @note Thread-safe: Yes - protected by internal mutex.
 *
 * Starts asynchronous DNS resolution. If callback is NULL, use SocketPoll
 * integration: add SocketDNS_pollfd() to SocketPoll and call SocketDNS_check()
 * on events. If callback is provided, it will be called from a worker thread
 * when resolution completes (see SocketDNS_Callback documentation for safety).
 *
 * When host is NULL, AI_PASSIVE flag is automatically set for wildcard bind
 * operations. The request handle remains valid until:
 * - Result retrieved via SocketDNS_getresult() (poll mode)
 * - Callback invoked (callback mode - req invalid after callback returns)
 * - Request cancelled via SocketDNS_cancel()
 * - Resolver freed via SocketDNS_free()
 *
 * Performance: O(1) queue insertion.
 *
 * @see SocketDNS_Callback for callback safety requirements.
 * @see SocketDNS_pollfd() for event loop integration.
 * @see SocketDNS_check() for polling completion.
 * @see SocketDNS_getresult() for retrieving results.
 */
extern Request_T SocketDNS_resolve(T dns, const char *host, int port,
                                   SocketDNS_Callback callback, void *data);

/**
 * @brief Cancel a pending DNS resolution.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request handle to cancel.
 * @note Thread-safe: Yes - protected by internal mutex.
 *
 * Cancels a pending request. If resolution has already completed, this
 * has no effect. The request handle becomes invalid after cancellation.
 * Callbacks will not be invoked for cancelled requests.
 *
 * @see SocketDNS_resolve() for creating requests.
 * @see SocketDNS_getresult() for retrieving completed results.
 */
extern void SocketDNS_cancel(T dns, Request_T req);

/**
 * @brief Get maximum pending request capacity.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @return Current pending request limit.
 * @note Thread-safe: Yes.
 * @see SocketDNS_setmaxpending() for setting the limit.
 */
extern size_t SocketDNS_getmaxpending(T dns);

/**
 * @brief Set maximum pending request capacity.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param max_pending New pending request limit (0 allows no pending requests).
 * @throws SocketDNS_Failed if max_pending < current queue depth.
 * @note Thread-safe: Yes.
 * @see SocketDNS_getmaxpending() for retrieving the current limit.
 */
extern void SocketDNS_setmaxpending(T dns, size_t max_pending);

/**
 * @brief Get resolver request timeout in milliseconds.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @return Timeout in milliseconds (0 disables timeout).
 * @note Thread-safe: Yes.
 * @see SocketDNS_settimeout() for setting the timeout.
 */
extern int SocketDNS_gettimeout(T dns);

/**
 * @brief Set resolver request timeout in milliseconds.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param timeout_ms Timeout in milliseconds (0 disables timeout).
 * @note Thread-safe: Yes.
 * @see SocketDNS_gettimeout() for retrieving the current timeout.
 */
extern void SocketDNS_settimeout(T dns, int timeout_ms);

/**
 * @brief Get pollable file descriptor for SocketPoll integration.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @return File descriptor ready for reading when requests complete.
 * @note Thread-safe: Yes - returns stable file descriptor.
 *
 * Returns a file descriptor (pipe or eventfd) that becomes readable when
 * DNS resolution requests complete. Add this to SocketPoll with POLL_READ
 * and call SocketDNS_check() when events occur.
 * The file descriptor remains valid for the lifetime of the resolver.
 *
 * @see SocketPoll_T for event polling.
 * @see @ref event_system for SocketPoll integration patterns.
 * @see SocketDNS_check() for processing completion events.
 */
extern int SocketDNS_pollfd(T dns);

/**
 * @brief Check for completed requests (non-blocking).
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @return Number of completion signals drained (1 byte per completed/cancelled/timeout request).
 * @note Thread-safe: Yes - safe to call from any thread.
 *
 * Drains the signal pipe for completed DNS events. Does not automatically
 * retrieve results. For poll-mode requests (no callback), track your Request_T
 * handles and call SocketDNS_getresult() after draining to fetch completed
 * results. Call when SocketDNS_pollfd() is readable.
 *
 * @see SocketDNS_pollfd() for the file descriptor to monitor.
 * @see SocketDNS_getresult() for retrieving completed results.
 */
extern int SocketDNS_check(T dns);

/**
 * @brief Get result of completed request.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request handle (must have been returned by SocketDNS_resolve() on this same resolver instance).
 * @return Completed addrinfo result or NULL if pending/error/cancelled/invalid.
 * @note Thread-safe: Yes - protected by internal mutex.
 *
 * Retrieves the result of a completed DNS resolution. Returns NULL if:
 * - Request is still pending
 * - Request was cancelled
 * - Resolution failed (check error via SocketDNS_geterror())
 * - Request does not belong to this resolver (invalid handle)
 * - Callback was provided (callback already consumed the result)
 *
 * The caller owns the returned addrinfo structure and must call
 * freeaddrinfo() when done. The request handle becomes invalid after
 * the result is retrieved.
 *
 * IMPORTANT: Only use request handles returned by SocketDNS_resolve() or
 * SocketDNS_create_completed_request() on the SAME resolver instance.
 * Passing request handles from a different resolver is undefined behavior.
 *
 * Performance: O(1) hash table lookup.
 *
 * @see SocketDNS_resolve() for creating requests.
 * @see SocketDNS_geterror() for checking error status.
 * @see SocketDNS_check() for poll-mode completion detection.
 */
extern struct addrinfo *SocketDNS_getresult(T dns, Request_T req);

/**
 * @brief Get error code for completed request.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request handle (must have been returned by SocketDNS_resolve() on this same resolver instance).
 * @return getaddrinfo() error code, or 0 on success, or 0 if request does not belong to this resolver (invalid handle).
 * @note Thread-safe: Yes - protected by internal mutex.
 *
 * IMPORTANT: Only use request handles returned by SocketDNS_resolve() or
 * SocketDNS_create_completed_request() on the SAME resolver instance.
 *
 * @see SocketDNS_getresult() for retrieving successful results.
 * @see SocketDNS_resolve() for creating requests.
 */
extern int SocketDNS_geterror(T dns, const struct SocketDNS_Request_T *req);

/**
 * @brief Override timeout for specific request.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param req Request handle.
 * @param timeout_ms Timeout in milliseconds (0 disables timeout for this request).
 * @note Thread-safe: Yes.
 * @see SocketDNS_settimeout() for setting the default timeout.
 * @see SocketDNS_resolve() for creating requests.
 */
extern void SocketDNS_request_settimeout(T dns, Request_T req, int timeout_ms);

/**
 * @brief Create a completed request from pre-resolved addrinfo.
 * @ingroup dns
 * @param dns DNS resolver instance.
 * @param result Pre-resolved addrinfo result (caller transfers ownership).
 * @param port Port number.
 * @return Request handle for completed request.
 * @throws SocketDNS_Failed on allocation failure.
 * @note Thread-safe: Yes - protected by internal mutex.
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
SocketDNS_create_completed_request(T dns, struct addrinfo *result, int port);

/**
 * @brief Synchronous DNS resolution with timeout guarantee.
 * @ingroup dns
 * @param dns DNS resolver instance (NULL uses global default - not yet implemented).
 * @param host Hostname to resolve (NULL for wildcard bind).
 * @param port Port number.
 * @param hints Address hints (may be NULL for defaults).
 * @param timeout_ms Timeout in milliseconds (0 = use resolver default).
 * @return addrinfo result (caller must call freeaddrinfo()).
 * @throws SocketDNS_Failed on error or timeout.
 * @note Thread-safe: Yes - uses internal synchronization.
 *
 * This function provides synchronous DNS resolution with GUARANTEED timeout.
 * Unlike raw getaddrinfo() which can block for 30+ seconds, this function
 * uses the async DNS worker thread pool internally and enforces the specified
 * timeout using condition variable wait.
 *
 * Use this function when you need blocking DNS resolution but cannot afford
 * unbounded blocking time (e.g., in network servers handling untrusted input).
 *
 * For IP addresses, resolution is instant (no DNS lookup needed).
 *
 * Usage:
 *   struct addrinfo *res = SocketDNS_resolve_sync(dns, "example.com", 80,
 *                                                  NULL, 5000);
 *   // Use res...
 *   freeaddrinfo(res);
 *
 * @see SocketDNS_resolve() for asynchronous resolution.
 * @see @ref foundation for arena allocation patterns.
 * @see @ref dns for asynchronous DNS resolution overview.
 */
extern struct addrinfo *SocketDNS_resolve_sync(T dns, const char *host,
                                               int port,
                                               const struct addrinfo *hints,
                                               int timeout_ms);

#undef T
#undef Request_T

/** @} */ // Close dns group
#endif
