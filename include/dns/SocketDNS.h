#ifndef SOCKETDNS_INCLUDED
#define SOCKETDNS_INCLUDED

#include "core/Except.h"
#include <netdb.h>
#include <stddef.h>
#include <sys/socket.h>

/**
 * Async DNS Resolution
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
 * Usage Pattern (Callback-based):
 *   SocketDNS_T dns = SocketDNS_new();
 *   SocketDNS_resolve(dns, "example.com", 80, callback, user_data);
 *   // callback invoked when resolution completes
 * Usage Pattern (SocketPoll integration):
 *   SocketDNS_T dns = SocketDNS_new();
 *   SocketPoll_T poll = SocketPoll_new(100);
 *   int dns_fd = SocketDNS_pollfd(dns);
 *   SocketPoll_add(poll, dns_fd, POLL_READ, dns);
 *   // In event loop: SocketDNS_check(dns) processes completed requests
 * Error Handling:
 * - SocketDNS_Failed: DNS resolution errors
 * - Request handles remain valid until result retrieved or cancelled
 */

#define T SocketDNS_T
typedef struct T *T;

#define Request_T SocketDNS_Request_T
typedef struct Request_T *Request_T;

/* Exception types */
extern Except_T SocketDNS_Failed; /**< DNS resolution operation failure */

/**
 * SocketDNS_Callback - Callback function for async DNS resolution
 * @req: Request handle for this resolution
 * @result: Completed addrinfo result (NULL on error)
 * @error: Error code from getaddrinfo() (0 on success)
 * @data: User data passed to SocketDNS_resolve()
 * Called when DNS resolution completes. If result is NULL, error contains
 * the getaddrinfo() error code. The caller owns the result addrinfo structure
 * and must call freeaddrinfo() when done.
 * Thread-safe: Called from DNS worker thread, not application thread
 */
typedef void (*SocketDNS_Callback)(Request_T req, struct addrinfo *result, int error, void *data);

/**
 * SocketDNS_new - Create a new async DNS resolver
 * Returns: New DNS resolver instance
 * Raises: SocketDNS_Failed on initialization failure
 * Thread-safe: Yes - returns new instance
 * Creates a thread pool for DNS resolution. Default thread count is
 * SOCKET_DNS_THREAD_COUNT (configurable via SocketConfig.h).
 */
extern T SocketDNS_new(void);

/**
 * SocketDNS_free - Free a DNS resolver
 * @dns: Pointer to resolver (will be set to NULL)
 * Drains pending requests, signals worker threads to stop, and joins threads.
 * Any pending requests that have not been retrieved are cancelled.
 * Thread-safe: Yes - safely shuts down thread pool
 */
extern void SocketDNS_free(T *dns);

/**
 * SocketDNS_resolve - Start async DNS resolution
 * @dns: DNS resolver instance
 * @host: Hostname or IP address to resolve (NULL for wildcard bind with AI_PASSIVE)
 * @port: Port number (0 if not needed)
 * @callback: Completion callback (NULL for SocketPoll integration)
 * @data: User data passed to callback
 * Returns: Request handle (never NULL)
 * Raises: SocketDNS_Failed on queue full or invalid parameters
 * Thread-safe: Yes - protected by internal mutex
 * Starts asynchronous DNS resolution. If callback is NULL, use SocketPoll
 * integration: add SocketDNS_pollfd() to SocketPoll and call SocketDNS_check()
 * on events. If callback is provided, it will be called from a worker thread
 * when resolution completes.
 * When host is NULL, AI_PASSIVE flag is automatically set for wildcard bind operations.
 * The request handle remains valid until:
 * - Result retrieved via SocketDNS_getresult() (callback mode)
 * - Request cancelled via SocketDNS_cancel()
 * - Resolver freed via SocketDNS_free()
 * Performance: O(1) queue insertion
 */
extern Request_T SocketDNS_resolve(T dns, const char *host, int port, SocketDNS_Callback callback, void *data);

/**
 * SocketDNS_cancel - Cancel a pending DNS resolution
 * @dns: DNS resolver instance
 * @req: Request handle to cancel
 * Thread-safe: Yes - protected by internal mutex
 * Cancels a pending request. If resolution has already completed, this
 * has no effect. The request handle becomes invalid after cancellation.
 * Callbacks will not be invoked for cancelled requests.
 */
extern void SocketDNS_cancel(T dns, Request_T req);

/**
 * SocketDNS_getmaxpending - Get maximum pending request capacity
 * @dns: DNS resolver instance
 * Returns: Current pending request limit
 * Thread-safe: Yes
 */
extern size_t SocketDNS_getmaxpending(T dns);

/**
 * SocketDNS_setmaxpending - Set maximum pending request capacity
 * @dns: DNS resolver instance
 * @max_pending: New pending request limit (0 allows no pending requests)
 * Raises: SocketDNS_Failed if max_pending < current queue depth
 * Thread-safe: Yes
 */
extern void SocketDNS_setmaxpending(T dns, size_t max_pending);

/**
 * SocketDNS_gettimeout - Get resolver request timeout in milliseconds
 * @dns: DNS resolver instance
 * Returns: Timeout in milliseconds (0 disables timeout)
 * Thread-safe: Yes
 */
extern int SocketDNS_gettimeout(T dns);

/**
 * SocketDNS_settimeout - Set resolver request timeout in milliseconds
 * @dns: DNS resolver instance
 * @timeout_ms: Timeout in milliseconds (0 disables timeout)
 * Thread-safe: Yes
 */
extern void SocketDNS_settimeout(T dns, int timeout_ms);

/**
 * SocketDNS_pollfd - Get pollable file descriptor for SocketPoll integration
 * @dns: DNS resolver instance
 * Returns: File descriptor ready for reading when requests complete
 * Thread-safe: Yes - returns stable file descriptor
 * Returns a file descriptor (pipe or eventfd) that becomes readable when
 * DNS resolution requests complete. Add this to SocketPoll with POLL_READ
 * and call SocketDNS_check() when events occur.
 * The file descriptor remains valid for the lifetime of the resolver.
 */
extern int SocketDNS_pollfd(T dns);

/**
 * SocketDNS_check - Check for completed requests (non-blocking)
 * @dns: DNS resolver instance
 * Returns: Number of completed requests processed
 * Thread-safe: Yes - safe to call from any thread
 * Processes completed DNS resolution requests. For requests submitted
 * without callbacks, the caller must poll for completion and call this
 * function to retrieve results via SocketDNS_getresult().
 * Should be called when SocketDNS_pollfd() becomes readable.
 */
extern int SocketDNS_check(T dns);

/**
 * SocketDNS_getresult - Get result of completed request
 * @dns: DNS resolver instance
 * @req: Request handle
 * Returns: Completed addrinfo result or NULL if pending/error/cancelled
 * Thread-safe: Yes - protected by internal mutex
 * Retrieves the result of a completed DNS resolution. Returns NULL if:
 * - Request is still pending
 * - Request was cancelled
 * - Resolution failed (check error via SocketDNS_geterror())
 * The caller owns the returned addrinfo structure and must call
 * freeaddrinfo() when done. The request handle becomes invalid after
 * the result is retrieved.
 * Performance: O(1) hash table lookup
 */
extern struct addrinfo *SocketDNS_getresult(T dns, Request_T req);

/**
 * SocketDNS_geterror - Get error code for completed request
 * @dns: DNS resolver instance
 * @req: Request handle
 * Returns: getaddrinfo() error code or 0 on success
 * Thread-safe: Yes
 */
extern int SocketDNS_geterror(T dns, Request_T req);

/**
 * SocketDNS_request_settimeout - Override timeout for specific request
 * @dns: DNS resolver instance
 * @req: Request handle
 * @timeout_ms: Timeout in milliseconds (0 disables timeout for this request)
 * Thread-safe: Yes
 */
extern void SocketDNS_request_settimeout(T dns, Request_T req, int timeout_ms);

/**
 * SocketDNS_create_completed_request - Create a completed request from pre-resolved addrinfo
 * @dns: DNS resolver instance
 * @result: Pre-resolved addrinfo result (caller transfers ownership)
 * @port: Port number
 * Returns: Request handle for completed request
 * Raises: SocketDNS_Failed on allocation failure
 * Thread-safe: Yes - protected by internal mutex
 * Creates a request that is already marked as complete with the provided result.
 * Useful for synchronous resolution (e.g., wildcard bind) that doesn't need async DNS.
 * The caller transfers ownership of the addrinfo result to the request.
 */
extern Request_T SocketDNS_create_completed_request(T dns, struct addrinfo *result, int port);

#undef T
#undef Request_T
#endif
