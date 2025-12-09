#ifndef SOCKETDNS_INCLUDED
#define SOCKETDNS_INCLUDED

#include "core/Except.h"
#include <netdb.h>
#include <stddef.h>
#include <sys/socket.h>

/**
 * @file SocketDNS.h
 * @ingroup core_io
 * @brief Asynchronous DNS resolution with thread pool.
 *
 * Provides asynchronous DNS resolution using a thread pool to eliminate
 * blocking getaddrinfo() calls that can take 30+ seconds during DNS failures.
 * This addresses DoS vulnerabilities and enables truly non-blocking socket
 * operations.
 *
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS, etc.)
 * - POSIX threads (pthread) for thread pool
 * - getaddrinfo() for DNS resolution (POSIX.1-2001)
 * - NOT portable to Windows without Winsock adaptation
 *
 * Features:
 * - Thread pool-based async DNS resolution
 * - Callback-based completion notification
 * - SocketPoll integration for event-driven completion
 * - Request cancellation support with explicit error reporting
 * - Configurable per-resolver and per-request timeouts
 * - Thread-safe implementation
 * - Automatic request lifecycle management
 *
 * Usage Pattern (Callback-based):
 *   SocketDNS_T dns = SocketDNS_new();
 *   SocketDNS_resolve(dns, "example.com", 80, callback, user_data);
 *   // callback invoked when resolution completes
 *
 * Usage Pattern (SocketPoll integration):
 *   SocketDNS_T dns = SocketDNS_new();
 *   SocketPoll_T poll = SocketPoll_new(100);
 *   int dns_fd = SocketDNS_pollfd(dns);
 *   SocketPoll_add(poll, dns_fd, POLL_READ, dns);
 *   // In event loop: SocketDNS_check(dns) processes completed requests
 *
 * Error Handling:
 * - SocketDNS_Failed: DNS resolution errors
 * - Request handles remain valid until result retrieved or cancelled
 *
 * @see SocketDNS_new() for resolver creation.
 * @see SocketDNS_resolve() for async resolution.
 * @see SocketDNS_pollfd() for event loop integration.
 * @warning Callbacks execute in worker threads, not main thread!
 */

#define T SocketDNS_T
typedef struct T *T;

typedef struct SocketDNS_Request_T SocketDNS_Request_T;
typedef SocketDNS_Request_T *Request_T;

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @brief SocketDNS_Failed - DNS resolution operation failure
 * @ingroup core_io
 *
 * Category: NETWORK
 * Retryable: YES - DNS servers may recover, cache may refresh
 *
 * Raised when DNS resolution fails:
 * - Server unreachable (transient)
 * - Query timeout (transient)
 * - Invalid hostname (permanent)
 * - NXDOMAIN (permanent)
 *
 * Check the error code from callback for specific failure reason.
 * Transient failures (EAI_AGAIN, EAI_NODATA) are worth retrying.
 * Permanent failures (EAI_NONAME, EAI_FAIL) should not be retried.
 */
extern const Except_T SocketDNS_Failed;

/**
 * @brief SocketDNS_Callback - Callback function for async DNS resolution
 * @ingroup core_io
 * @req: Request handle for this resolution
 * @result: Completed addrinfo result (NULL on error)
 * @error: Error code from getaddrinfo() (0 on success)
 * @data: User data passed to SocketDNS_resolve()
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
 * @brief SocketDNS_new - Create a new async DNS resolver
 * @ingroup core_io
 * Returns: New DNS resolver instance
 * Raises: SocketDNS_Failed on initialization failure
 * @note Thread-safe: Yes - returns new instance
 * @ingroup core_io
 * Creates a thread pool for DNS resolution. Default thread count is
 * SOCKET_DNS_THREAD_COUNT (configurable via SocketConfig.h).
 */
extern T SocketDNS_new(void);

/**
 * @brief SocketDNS_free - Free a DNS resolver
 * @ingroup core_io
 * @dns: Pointer to resolver (will be set to NULL)
 * Drains pending requests, signals worker threads to stop, and joins threads.
 * Any pending requests that have not been retrieved are cancelled.
 * @note Thread-safe: Yes - safely shuts down thread pool
 * @ingroup core_io
 */
extern void SocketDNS_free(T *dns);

/**
 * @brief SocketDNS_resolve - Start async DNS resolution
 * @ingroup core_io
 * @dns: DNS resolver instance
 * @host: Hostname or IP address to resolve (NULL for wildcard bind with
 *        AI_PASSIVE)
 * @port: Port number (0 = no service/port in resolution, 1-65535 for specific
 *        port). When port is 0, getaddrinfo() is called with NULL service,
 *        which is valid for address-only lookups.
 * @callback: Completion callback (NULL for SocketPoll integration)
 * @data: User data passed to callback
 *
 * Returns: Request handle (never NULL)
 * Raises: SocketDNS_Failed on queue full or invalid parameters
 * @note Thread-safe: Yes - protected by internal mutex
 * @ingroup core_io
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
 * Performance: O(1) queue insertion
 */
extern Request_T SocketDNS_resolve(T dns, const char *host, int port,
                                   SocketDNS_Callback callback, void *data);

/**
 * @brief SocketDNS_cancel - Cancel a pending DNS resolution
 * @ingroup core_io
 * @dns: DNS resolver instance
 * @req: Request handle to cancel
 * @note Thread-safe: Yes - protected by internal mutex
 * @ingroup core_io
 * Cancels a pending request. If resolution has already completed, this
 * has no effect. The request handle becomes invalid after cancellation.
 * Callbacks will not be invoked for cancelled requests.
 */
extern void SocketDNS_cancel(T dns, Request_T req);

/**
 * @brief SocketDNS_getmaxpending - Get maximum pending request capacity
 * @ingroup core_io
 * @dns: DNS resolver instance
 * Returns: Current pending request limit
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern size_t SocketDNS_getmaxpending(T dns);

/**
 * @brief SocketDNS_setmaxpending - Set maximum pending request capacity
 * @ingroup core_io
 * @dns: DNS resolver instance
 * @max_pending: New pending request limit (0 allows no pending requests)
 * Raises: SocketDNS_Failed if max_pending < current queue depth
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern void SocketDNS_setmaxpending(T dns, size_t max_pending);

/**
 * @brief SocketDNS_gettimeout - Get resolver request timeout in milliseconds
 * @ingroup core_io
 * @dns: DNS resolver instance
 * Returns: Timeout in milliseconds (0 disables timeout)
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern int SocketDNS_gettimeout(T dns);

/**
 * @brief SocketDNS_settimeout - Set resolver request timeout in milliseconds
 * @ingroup core_io
 * @dns: DNS resolver instance
 * @timeout_ms: Timeout in milliseconds (0 disables timeout)
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern void SocketDNS_settimeout(T dns, int timeout_ms);

/**
 * @brief SocketDNS_pollfd - Get pollable file descriptor for SocketPoll integration
 * @ingroup core_io
 * @dns: DNS resolver instance
 * Returns: File descriptor ready for reading when requests complete
 * @note Thread-safe: Yes - returns stable file descriptor
 * @ingroup core_io
 * Returns a file descriptor (pipe or eventfd) that becomes readable when
 * DNS resolution requests complete. Add this to SocketPoll with POLL_READ
 * and call SocketDNS_check() when events occur.
 * The file descriptor remains valid for the lifetime of the resolver.
 */
extern int SocketDNS_pollfd(T dns);

/**
 * @brief SocketDNS_check - Check for completed requests (non-blocking)
 * @ingroup core_io
 * @dns: DNS resolver instance
 * Returns: Number of completion signals drained (1 byte per
 * completed/cancelled/timeout request) Thread-safe: Yes - safe to call from
 * any thread Drains the signal pipe for completed DNS events. Does not
 * automatically retrieve results. For poll-mode requests (no callback), track
 * your Request_T handles and call SocketDNS_getresult() after draining to
 * fetch completed results. Call when SocketDNS_pollfd() is readable.
 */
extern int SocketDNS_check(T dns);

/**
 * @brief SocketDNS_getresult - Get result of completed request
 * @ingroup core_io
 * @dns: DNS resolver instance
 * @req: Request handle (must have been returned by SocketDNS_resolve() on
 *       this same resolver instance)
 *
 * Returns: Completed addrinfo result or NULL if
 * pending/error/cancelled/invalid Thread-safe: Yes - protected by internal
 * mutex
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
 * Performance: O(1) hash table lookup
 */
extern struct addrinfo *SocketDNS_getresult(T dns, Request_T req);

/**
 * @brief SocketDNS_geterror - Get error code for completed request
 * @ingroup core_io
 * @dns: DNS resolver instance
 * @req: Request handle (must have been returned by SocketDNS_resolve() on
 *       this same resolver instance)
 *
 * Returns: getaddrinfo() error code, or 0 on success, or 0 if request
 *          does not belong to this resolver (invalid handle)
 * @note Thread-safe: Yes - protected by internal mutex
 * @ingroup core_io
 *
 * IMPORTANT: Only use request handles returned by SocketDNS_resolve() or
 * SocketDNS_create_completed_request() on the SAME resolver instance.
 */
extern int SocketDNS_geterror(T dns, const struct SocketDNS_Request_T *req);

/**
 * @brief SocketDNS_request_settimeout - Override timeout for specific request
 * @ingroup core_io
 * @dns: DNS resolver instance
 * @req: Request handle
 * @timeout_ms: Timeout in milliseconds (0 disables timeout for this request)
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern void SocketDNS_request_settimeout(T dns, Request_T req, int timeout_ms);

/**
 * @brief SocketDNS_create_completed_request - Create a completed request from
 * @ingroup core_io
 * pre-resolved addrinfo
 * @dns: DNS resolver instance
 * @result: Pre-resolved addrinfo result (caller transfers ownership)
 * @port: Port number
 * Returns: Request handle for completed request
 * Raises: SocketDNS_Failed on allocation failure
 * @note Thread-safe: Yes - protected by internal mutex
 * @ingroup core_io
 * Creates a request that is already marked as complete with the provided
 * result. Useful for synchronous resolution (e.g., wildcard bind) that doesn't
 * need async DNS. The caller transfers ownership of the addrinfo result to the
 * request.
 */
extern Request_T
SocketDNS_create_completed_request(T dns, struct addrinfo *result, int port);

/**
 * @brief SocketDNS_resolve_sync - Synchronous DNS resolution with timeout guarantee
 * @ingroup core_io
 * @dns: DNS resolver instance (NULL uses global default - not yet implemented)
 * @host: Hostname to resolve (NULL for wildcard bind)
 * @port: Port number
 * @hints: Address hints (may be NULL for defaults)
 * @timeout_ms: Timeout in milliseconds (0 = use resolver default)
 *
 * Returns: addrinfo result (caller must call freeaddrinfo())
 * Raises: SocketDNS_Failed on error or timeout
 *
 * @note Thread-safe: Yes - uses internal synchronization
 * @ingroup core_io
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
 */
extern struct addrinfo *SocketDNS_resolve_sync(T dns, const char *host,
                                               int port,
                                               const struct addrinfo *hints,
                                               int timeout_ms);

#undef T
#undef Request_T
#endif
