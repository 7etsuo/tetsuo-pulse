#ifndef SOCKET_INCLUDED
#define SOCKET_INCLUDED

/**
 * @defgroup core_io Core I/O Modules
 * @brief Fundamental socket primitives for TCP, UDP, Unix domain, and DNS
 * operations.
 *
 * This group forms the foundation for all networking in the library, providing
 * low-level but safe abstractions over POSIX sockets. It handles
 * cross-platform differences, error mapping to exceptions, and common patterns
 * like partial I/O.
 *
 * ## Architecture Overview
 *
 * ```
 * ┌─────────────────────────────┐
 * │   Application Modules       │
 * │ HTTP, TLS, Pool, Poll, etc. │
 * └─────────────┬───────────────┘
 *               │ Uses
 * ┌─────────────▼───────────────┐
 * │     Core I/O Modules        │
 * │ Socket_T, DNS, Proxy, Buf   │
 * └─────────────┬───────────────┘
 *               │ Uses
 * ┌─────────────▼───────────────┐
 * │    Foundation Modules       │
 * │ Arena, Except, Config, Util │
 * └─────────────────────────────┘
 * ```
 *
 * ## Module Breakdown
 *
 * | Module | Purpose | Key Features | Dependencies |
 * |--------|---------|--------------|--------------|
 * | Socket_T | TCP/Unix sockets | Bind/connect/I/O/options/fd passing |
 * Foundation | | SocketDgram_T | UDP/Datagram |
 * Sendto/recvfrom/multicast/broadcast | Foundation | | SocketBuf_T | Circular
 * buffers | Zero-copy read/write/secure clear | Arena | | SocketDNS_T | Async
 * DNS | Worker threads/non-blocking resolve | Socket, Timer | | SocketProxy_T
 * | Proxy tunneling | HTTP CONNECT/SOCKS4/5 | Socket, DNS |
 *
 * ## Relationships
 *
 * - **Depends on**: @ref foundation (memory, exceptions, utils)
 * - **Used by**: @ref event_system (poll integration), @ref connection_mgmt
 * (pooling),
 *   @ref http (HTTP over sockets), @ref security (protections), @ref async_io
 * (happy eyeballs)
 * - **Thread Safety**: Operations marked @threadsafe; instances not shared
 * without locks
 * - **Performance**: O(1) most ops; DNS may block unless async
 *
 * @see @ref foundation Base infrastructure
 * @see @ref event_system Event system built on Core I/O
 * @see Socket_T Primary TCP/Unix abstraction
 * @see SocketDgram_T UDP abstraction
 * @see docs/ASYNC_IO.md Integration guide
 * @{
 */

/**
 * @file Socket.h
 * @ingroup core_io
 * @brief High-level TCP/IP and Unix domain socket interface.
 *
 * This header provides a comprehensive, exception-safe API for creating,
 * configuring, and using TCP/IP and Unix domain sockets. It abstracts
 * low-level POSIX socket operations while adding production features like
 * automatic SIGPIPE handling, bandwidth limiting, timeouts, and async DNS
 * integration.
 *
 * ## Key Features
 *
 * - **Core Operations**: Creation, bind, connect, listen, accept, send/recv
 * with partial handling
 * - **Advanced I/O**: Zero-copy sendfile, scatter/gather (sendv/recvv),
 * ancillary data (sendmsg/recvmsg)
 * - **Configuration**: Non-blocking mode, reuseaddr/port, keepalive, nodelay,
 * buffers, congestion control
 * - **Unix Domain**: Path binding, fd passing (SCM_RIGHTS), peer credentials
 * (pid/uid/gid on Linux)
 * - **Security**: SYN defer accept, bandwidth throttling, timeout enforcement
 * - **Integration**: Async DNS, event loop compatibility, connection pooling
 * ready
 * - **Error Handling**: Detailed exceptions with retryability checks,
 * thread-local errno
 *
 * ## Platform Requirements
 *
 * | Requirement | Details |
 * |-------------|---------|
 * | OS | POSIX-compliant (Linux, FreeBSD, macOS, Solaris) |
 * | Network | IPv4/IPv6 kernel support for dual-stack |
 * | Threads | pthreads for thread-safe operations |
 * | Limits | Standard fd limits; Unix paths <= UNIX_PATH_MAX (~108 bytes) |
 * | Portability | Not Windows-native; requires Winsock porting |
 *
 * ## SIGPIPE Handling
 *
 * Automatic and transparent:
 * - Linux/FreeBSD: All sends use MSG_NOSIGNAL
 * - BSD/macOS: SO_NOSIGPIPE set at socket creation
 * - No application signal handlers needed
 *
 * Optional: Socket_ignore_sigpipe() for raw socket compatibility
 *
 * ## Error Model
 *
 * - **Exceptions**: Socket_Failed (general), Socket_Closed (peer disconnect),
 * SocketUnix_Failed (Unix errors)
 * - **Non-blocking**: EAGAIN/EWOULDBLOCK return 0/NULL, not exceptions
 * - **Retryability**: Socket_error_is_retryable() classifies errors for
 * backoff logic
 * - **Diagnostics**: Socket_geterrno(), Socket_GetLastError(),
 * Socket_safe_strerror()
 *
 * ## Timeout Configuration
 *
 * Granular control via SocketTimeouts_T:
 * - Global defaults: Socket_timeouts_setdefaults()
 * - Per-socket: Socket_timeouts_set(), Socket_timeouts_set_extended()
 * - Phases: DNS, connect, TLS handshake, I/O operations
 *
 * ## Usage Patterns
 *
 * ### Simple Client
 * @code{.c}
 * Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 * Socket_connect(sock, "api.example.com", 443);
 * Socket_sendall(sock, request, len);
 * Socket_free(&sock);
 * @endcode
 *
 * ### Echo Server
 * @code{.c}
 * Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
 * Socket_bind(server, "0.0.0.0", 8080);
 * Socket_listen(server, 128);
 * while (running) {
 *     Socket_T client = Socket_accept(server);
 *     if (client) {
 *         // Handle client...
 *         Socket_free(&client);
 *     }
 * }
 * Socket_free(&server);
 * @endcode
 *
 * ## Related Headers and Modules
 *
 * - core/Except.h: Exception framework (TRY/EXCEPT)
 * - core/SocketConfig.h: Global limits and timeouts
 * - dns/SocketDNS.h: Asynchronous hostname resolution
 * - socket/SocketCommon.h: Shared enums and structs
 * - pool/SocketPool.h: @ref connection_mgmt Connection pooling
 * - poll/SocketPoll.h: @ref event_system Event multiplexing
 * - tls/SocketTLS.h: #if SOCKET_HAS_TLS TLS/SSL support
 *
 * @see @ref core_io for full module overview
 * @see Socket_T for opaque type details
 * @see Socket_new() entry point for creation
 * @see docs/ASYNC_IO.md asynchronous I/O guide
 * @see docs/SECURITY.md secure socket configuration
 * @see docs/UNIX_DOMAIN.md Unix socket specifics
 */

#include "core/Except.h"
#include "core/SocketConfig.h"
#include "dns/SocketDNS.h"
#include "socket/SocketCommon.h"

#define T Socket_T
/**
 * @brief Opaque handle representing a TCP/IP or Unix domain socket connection.
 * @ingroup core_io
 *
 * Socket_T provides a safe, high-level abstraction over POSIX socket file
 * descriptors (int fd). It encapsulates:
 * - File descriptor management (auto-close on free)
 * - Socket options configuration (reuseaddr, nodelay, keepalive, etc.)
 * - I/O operations (send/recv with partial handling, sendfile, sendmsg)
 * - State tracking (connected, bound, listening)
 * - Unix domain specific features (fd passing via SCM_RIGHTS)
 * - Bandwidth limiting and timeout controls
 * - Automatic SIGPIPE suppression
 * - Exception-based error handling
 *
 * Lifecycle:
 * 1. Create: Socket_new() or Socket_new_from_fd()
 * 2. Configure: setnonblocking, setreuseaddr, settimeout, etc.
 * 3. Use: bind/connect/listen/accept/send/recv
 * 4. Cleanup: Socket_free(&sock) - always pass address to nullify pointer
 *
 * Thread Safety:
 * - Individual operations are thread-safe where documented (@threadsafe
 * Yes/No)
 * - Socket instances should not be shared across threads without external
 * synchronization
 * - State queries (isconnected, getpeeraddr) are atomic but reflect last
 * operation
 * - For concurrent access, use mutex or SocketPool for managed sharing
 *
 * Related Types:
 * - SocketDgram_T: For UDP and datagram sockets
 * - SocketPool_T: For managing multiple connections
 * - SocketBuf_T: For efficient buffering
 *
 * @note Sockets start in blocking mode; enable non-blocking for event loops
 * @note All I/O functions handle EINTR and EAGAIN appropriately
 * @note For TLS, use SocketTLS_enable() after creation but before
 * connect/handshake
 * @warning Never close underlying fd directly - use Socket_free()
 * @warning Check Socket_error_is_retryable() for transient errors
 *
 * @see Socket_new() for creation from scratch
 * @see Socket_new_from_fd() for wrapping existing fds
 * @see Socket_free() for proper cleanup
 * @see Socket_connect(), Socket_bind(), Socket_listen(), Socket_accept() for
 * lifecycle ops
 * @see Socket_send(), Socket_recv(), Socket_sendfile() for I/O
 * @see SocketPool_T @ref connection_mgmt for pooling
 * @see @ref event_system for integration with SocketPoll_T
 * @see docs/ASYNC_IO.md for advanced async patterns
 * @see docs/SECURITY.md for secure configuration guidelines
 */
typedef struct T *T;

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @brief General socket operation failure exception.
 * @ingroup core_io
 *
 * Indicates failure in any socket-related system call or library operation.
 * This is the primary exception for most Socket_T API errors.
 *
 * Error Category:
 * - NETWORK: Transient issues like timeouts, resets, unreachable hosts
 * - PROTOCOL: Invalid configuration or state (e.g., bind on used port)
 * - SYSTEM: Resource exhaustion or permission issues
 *
 * Retryability: Use Socket_error_is_retryable(Socket_geterrno()) to determine
 * if safe to retry the operation. Examples:
 * - Retryable: ECONNREFUSED, ETIMEDOUT, EAGAIN
 * - Non-retryable: EACCES, EINVAL, EMFILE
 *
 * Always check Socket_geterrno() and Socket_GetLastError() in EXCEPT block for
 * details.
 *
 * Common triggers:
 * - socket(2), bind(2), listen(2), accept(4), connect(2) failures
 * - send(2), recv(2), sendmsg(2), recvmsg(2) errors
 * - setsockopt(2), getsockopt(2) failures
 * - Internal allocation failures (ENOMEM)
 *
 * @see Socket_geterrno() to retrieve errno value
 * @see Socket_GetLastError() for human-readable error string
 * @see Socket_error_is_retryable() to check if operation can be retried
 *
 * ## Handling Example
 *
 * @code{.c}
 * TRY {
 *     Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 *     Socket_connect(sock, "invalid-host", 80);
 * } EXCEPT(Socket_Failed) {
 *     int err = Socket_geterrno();
 *     if (Socket_error_is_retryable(err)) {
 *         SOCKET_LOG_WARN_MSG("Retryable socket error %d: %s", err,
 * Socket_GetLastError());
 *         // Implement backoff and retry logic
 *     } else {
 *         SOCKET_LOG_ERROR_MSG("Fatal socket error %d: %s", err,
 * Socket_GetLastError());
 *         // Abort or fallback
 *     }
 * } END_TRY;
 * @endcode
 *
 * @note errno is preserved thread-locally; safe in multithreaded contexts
 * @note Use Socket_safe_strerror() for safe strerror() wrapper
 * @warning Do not assume all Socket_Failed are network errors - check errno
 * @warning In non-blocking mode, EAGAIN may not raise exception (returns 0
 * instead)
 *
 * @see Socket_Closed for peer disconnection cases
 * @see SocketUnix_Failed for Unix-specific errors
 */
extern const Except_T Socket_Failed;

/**
 * @brief Connection closed by peer exception.
 * @ingroup core_io
 *
 * Category: NETWORK
 * Retryable: Yes - indicates graceful close or reset, reconnect may succeed
 *
 * Raised when:
 * - recv() returns 0 (graceful close)
 * - ECONNRESET during I/O (connection reset)
 * - EPIPE during send (broken pipe)
 *
 * This is a normal condition for connection-oriented sockets.
 *
 * @see Socket_recv() for read operations that may raise this.
 * @see Socket_send() for write operations that may raise this.
 */
extern const Except_T Socket_Closed;

/**
 * @brief Unix domain socket operation failure.
 * @ingroup core_io
 *
 * Category: NETWORK or APPLICATION
 * Retryable: Depends on errno
 *
 * Raised for Unix domain socket specific errors:
 * - Path too long
 * - Socket file doesn't exist (ENOENT)
 * - Permission denied (EACCES)
 */
extern const Except_T SocketUnix_Failed;

/* ============================================================================
 * Error Retryability Helpers
 * ============================================================================
 */

/**
 * @brief Check if an errno indicates a retryable error.
 * @ingroup core_io
 * @param err errno value to check.
 * @return 1 if retryable, 0 if not.
 * @threadsafe Yes
 * @see Socket_geterrno() for getting current errno.
 * @see Socket_Failed exception for when this is used.
 *
 * This is a convenience wrapper around SocketError_is_retryable_errno()
 * for socket-specific error handling.
 *
 * Retryable errors (return 1):
 * - ECONNREFUSED: Server not listening, may start later
 * - ECONNRESET: Connection dropped, can reconnect
 * - ETIMEDOUT: Timeout, may succeed on retry
 * - ENETUNREACH: Network route may recover
 * - EHOSTUNREACH: Host may become reachable
 * - EAGAIN/EWOULDBLOCK: Resource temporarily unavailable
 * - EINTR: Interrupted by signal
 *
 * Fatal errors (return 0):
 * - EACCES: Permission denied (won't change)
 * - EADDRINUSE: Address in use (won't change)
 * - EBADF: Bad file descriptor (programming error)
 * - EINVAL: Invalid argument (programming error)
 * - ENOMEM: Out of memory (system issue)
 * - EMFILE/ENFILE: Too many open files (system limit)
 *
 * Usage:
 *   TRY
 *     Socket_connect(sock, host, port);
 *   EXCEPT(Socket_Failed)
 *     if (Socket_error_is_retryable(Socket_geterrno()))
 *       // Schedule retry with backoff
 *     else
 *       // Log error and give up
 *   END_TRY;
 */
extern int Socket_error_is_retryable (int err);

/* ============================================================================
 * Socket Creation and Lifecycle
 * ============================================================================
 */

/**
 * @brief Create a new socket with specified domain, type, and protocol.
 * @ingroup core_io
 *
 * Creates and initializes a new socket instance using the socket(2) system
 * call. The socket is created in blocking mode by default. SIGPIPE is
 * automatically handled internally via platform-specific mechanisms
 * (MSG_NOSIGNAL on Linux, SO_NOSIGPIPE on BSD/macOS). The library sets
 * reasonable default socket options including close-on-exec and non-SIGPIPE
 * behavior.
 *
 * Supported domains: AF_INET (IPv4), AF_INET6 (IPv6), AF_UNIX (Unix domain).
 * Supported types: SOCK_STREAM (TCP), SOCK_DGRAM (UDP), SOCK_SEQPACKET (SCTP).
 * Protocol is usually 0 to select default for the domain/type combination.
 *
 * Edge cases:
 * - Invalid domain/type/protocol combinations raise Socket_Failed immediately.
 * - Resource limits (EMFILE, ENFILE) raise Socket_Failed.
 * - Permission issues (EACCES) raise Socket_Failed.
 *
 * For UDP, use SocketDgram_new() instead for datagram-specific features.
 *
 * @param[in] domain Address family (AF_INET, AF_INET6, AF_UNIX)
 * @param[in] type Socket type (SOCK_STREAM for TCP, SOCK_DGRAM for UDP)
 * @param[in] protocol Protocol number (0 for default)
 *
 * @return New Socket_T instance on success, raises exception on failure.
 *
 * @throws Socket_Failed System call failed (EACCES permission denied,
 * EMFILE/ENFILE too many files, ENOMEM out of memory, EINVAL invalid
 * arguments)
 *
 * @threadsafe Yes - creates independent instance safe from concurrent calls
 *
 * ## Basic Usage
 *
 * @code{.c}
 * // Create TCP IPv4 socket
 * Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 * Socket_connect(sock, "example.com", 80);
 * // ... use socket ...
 * Socket_free(&sock);
 * @endcode
 *
 * ## With Error Handling and Options
 *
 * @code{.c}
 * TRY {
 *     Socket_T sock = Socket_new(AF_INET6, SOCK_STREAM, 0);
 *     Socket_setreuseaddr(sock);  // Allow address reuse
 *     Socket_setnonblocking(sock);  // Non-blocking mode
 *     Socket_bind(sock, "::", 8080);
 *     Socket_listen(sock, 128);
 *     // Server loop...
 * } EXCEPT(Socket_Failed) {
 *     fprintf(stderr, "Socket creation failed: %s\n", Socket_GetLastError());
 *     // Handle error (e.g., retry or exit)
 * } FINALLY {
 *     Socket_free(&sock);
 * } END_TRY;
 * @endcode
 *
 * @note Socket is blocking by default; use Socket_setnonblocking() for async
 * I/O.
 * @note For Unix domain sockets, use AF_UNIX domain.
 * @warning Ensure proper cleanup with Socket_free() to avoid fd leaks.
 * @warning SOCK_DGRAM with this function creates basic UDP socket; use
 * SocketDgram_new() for full UDP features like multicast.
 *
 * @complexity O(1) - single socket(2) system call plus option setup
 *
 * @see Socket_free() for resource cleanup
 * @see Socket_connect() for client connections
 * @see Socket_bind() and Socket_listen() for servers
 * @see SocketDgram_new() for UDP/datagram sockets
 * @see Socket_new_from_fd() for wrapping existing fds
 * @see docs/ASYNC_IO.md for non-blocking patterns
 */
extern T Socket_new (int domain, int type, int protocol);

/**
 * @brief Create a pair of connected Unix domain sockets for inter-process
 * communication.
 * @ingroup core_io
 *
 * Creates two connected Unix domain sockets using socketpair(2) system call.
 * The sockets are of the specified type (SOCK_STREAM or SOCK_DGRAM) and are
 * immediately connected to each other. No bind() or connect() is needed.
 * Both sockets are created in blocking mode with default options (CLOEXEC, no
 * SIGPIPE). This is useful for parent-child process communication after
 * fork(), or for thread-to-thread IPC without network stack overhead.
 *
 * Supported types: SOCK_STREAM (reliable byte stream), SOCK_DGRAM (datagrams).
 * Domain is always AF_UNIX internally.
 *
 * Edge cases:
 * - Unsupported type raises Socket_Failed (EINVAL)
 * - Resource limits raise Socket_Failed (EMFILE, ENFILE)
 * - On success, both *socket1 and *socket2 are non-NULL and connected.
 *
 * After use, free both sockets with Socket_free().
 *
 * @param[in] type Socket type (SOCK_STREAM or SOCK_DGRAM)
 * @param[out] socket1 First socket of the pair (set to new Socket_T or NULL on
 * error)
 * @param[out] socket2 Second socket of the pair (set to new Socket_T or NULL
 * on error)
 *
 * @throws Socket_Failed System call failed (EINVAL invalid type, EMFILE/ENFILE
 * too many files, ENOMEM, EAFNOSUPPORT)
 *
 * @threadsafe Yes - creates independent socket pair safe from concurrent calls
 *
 * ## Basic Usage
 *
 * @code{.c}
 * Socket_T sock1, sock2;
 * SocketPair_new(SOCK_STREAM, &sock1, &sock2);
 * // Now sock1 and sock2 are connected
 * // Send from sock1, receive on sock2, etc.
 * Socket_free(&sock1);
 * Socket_free(&sock2);
 * @endcode
 *
 * ## With Error Handling for Fork IPC
 *
 * @code{.c}
 * TRY {
 *     Socket_T parent_sock, child_sock;
 *     SocketPair_new(SOCK_STREAM, &parent_sock, &child_sock);
 *     pid_t pid = fork();
 *     if (pid == 0) {  // Child
 *         Socket_free(&parent_sock);  // Close unused
 *         // Use child_sock for IPC
 *     } else {  // Parent
 *         Socket_free(&child_sock);
 *         // Use parent_sock for IPC
 *     }
 * } EXCEPT(Socket_Failed) {
 *     perror("Socket pair creation failed");
 * } END_TRY;
 * @endcode
 *
 * @note Sockets are bidirectional: data sent on one can be received on the
 * other.
 * @note For DGRAM type, it's like connected UDP - sendto not needed.
 * @warning Always free both sockets to avoid fd leaks.
 * @warning After fork(), close the unused socket in both parent and child to
 * avoid deadlocks.
 *
 * @complexity O(1) - single socketpair(2) call
 *
 * @see Socket_new() for single socket creation
 * @see Socket_free() for cleanup
 * @see Socket_sendfd() for passing fds over Unix sockets
 * @see man socketpair(2) for low-level details
 */
extern void SocketPair_new (int type, T *socket1, T *socket2);

/**
 * @brief Dispose of a socket instance and close the underlying file
 * descriptor.
 * @ingroup core_io
 *
 * Closes the socket's file descriptor using close(2) and frees all associated
 * resources including internal state, buffers, and timers. The pointer *socket
 * is set to NULL after successful cleanup to prevent use-after-free.
 *
 * This function is idempotent: calling on NULL does nothing. It handles
 * partial cleanup if socket is in inconsistent state (e.g., after exception).
 *
 * IMPORTANT: Always pass pointer to socket (&sock) so it can be nulled.
 * Failing to do so may lead to use-after-free bugs.
 *
 * For testing, use Socket_debug_live_count() to ensure all sockets freed.
 *
 * Edge cases:
 * - Already freed socket (NULL): no-op
 * - Socket in connect/bind state: aborts operations gracefully
 * - TLS-enabled socket: performs TLS shutdown if connected
 *
 * @param[in,out] socket Pointer to Socket_T (set to NULL on success)
 *
 * @throws None - errors during close are logged but not raised (Socket_Failed
 * would be swallowed)
 *
 * @threadsafe Yes - per-socket cleanup, no shared state modification
 *
 * ## Basic Usage
 *
 * @code{.c}
 * Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 * // ... use sock ...
 * Socket_free(&sock);  // Pass address to nullify
 * @endcode
 *
 * ## In TRY/EXCEPT Block
 *
 * @code{.c}
 * Socket_T sock = NULL;
 * TRY {
 *     sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 *     // Operations that may fail
 * } EXCEPT(Socket_Failed) {
 *     // Error handling
 * } FINALLY {
 *     Socket_free(&sock);  // Safe even if sock NULL
 * } END_TRY;
 * @endcode
 *
 * @note Always use &sock in Socket_free(&sock) to enable nulling.
 * @note For pooled sockets, use SocketPool_remove() before free.
 * @warning Do not access socket after free - undefined behavior.
 * @warning In multithreaded code, ensure no other thread uses socket during
 * free.
 *
 * @complexity O(1) - close(2) call plus resource cleanup
 *
 * @see Socket_new() for creation
 * @see Socket_debug_live_count() for leak detection in tests
 * @see SocketPool_T for connection pooling alternatives
 */
extern void Socket_free (T *socket);

/**
 * @brief Create Socket_T from existing file descriptor.
 * @ingroup core_io
 * @param fd File descriptor (must be valid socket, will be set to
 * non-blocking).
 * @return New Socket_T instance or NULL on failure.
 * @throws Socket_Failed on error.
 * @threadsafe Yes - returns new instance without modifying shared state.
 * @see Socket_new() for creating new sockets.
 * @see Socket_fd() for getting file descriptors from Socket_T instances.
 */
extern T Socket_new_from_fd (int fd);

/**
 * @brief Get number of live socket instances (test-only).
 * @ingroup core_io
 * @return Current count of allocated Socket_T instances.
 * @note For testing and leak detection.
 */
extern int Socket_debug_live_count (void);

/* ============================================================================
 * Connection Operations
 * ============================================================================
 */

/**
 * @brief Bind a socket to a local IP address and port.
 * @ingroup core_io
 *
 * Associates the socket with a local network address and port using bind(2).
 * This is required for servers (before listen()) and clients wanting specific
 * local endpoints (e.g., source IP selection). Hostnames trigger synchronous
 * DNS resolution, which may block; use IP literals or async DNS for
 * non-blocking.
 *
 * Supported formats for host:
 * - NULL or "0.0.0.0": Bind to all IPv4 interfaces
 * - "::": Bind to all IPv6 interfaces (dual-stack if possible)
 * - Specific IP: "192.168.1.100" or "[2001:db8::1]"
 * - Hostname: Resolves via getaddrinfo(3), blocks up to ~30s on failure
 *
 * Port range: 1-65535 (SOCKET_MAX_PORT); 0 for kernel-assigned ephemeral port.
 *
 * Edge cases:
 * - Port 0: OS assigns available port; query with Socket_getlocalport()
 * - Already bound: Raises Socket_Failed (EINVAL or EADDRINUSE)
 * - Permission denied on privileged ports (<1024): Socket_Failed (EACCES)
 * - Address not local: Socket_Failed (EADDRNOTAVAIL)
 *
 * For non-blocking bind, resolve hostname first with SocketDNS_resolve_sync()
 * or async.
 *
 * @param[in,out] socket Unbound socket to bind (updated with local addr/port
 * state)
 * @param[in] host Local address string (IP or hostname; NULL for any)
 * @param[in] port Local port (1-65535; 0 for ephemeral)
 *
 * @throws Socket_Failed Bind failed: EADDRINUSE (port busy), EADDRNOTAVAIL
 * (invalid local addr), EACCES (permission), ENETDOWN (interface down),
 * getaddrinfo errors for hostnames
 *
 * @threadsafe Yes - binds specific socket instance atomically
 *
 * ## Basic Server Bind
 *
 * @code{.c}
 * Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
 * Socket_bind(server, NULL, 8080);  // Bind to any IP on port 8080
 * Socket_listen(server, SOMAXCONN);
 * @endcode
 *
 * ## Client Bind to Specific Interface
 *
 * @code{.c}
 * TRY {
 *     Socket_T client = Socket_new(AF_INET6, SOCK_STREAM, 0);
 *     Socket_bind(client, "::1", 0);  // Bind to loopback, ephemeral port
 *     Socket_connect(client, "example.com", 80);
 *     int local_port = Socket_getlocalport(client);  // Query assigned port
 * } EXCEPT(Socket_Failed) {
 *     // Handle bind/connect failure
 * } END_TRY;
 * @endcode
 *
 * ## Async DNS for Non-Blocking
 *
 * @code{.c}
 * SocketDNS_T dns = SocketDNS_new();
 * Request_T req = Socket_bind_async(dns, sock, "localhost", 8080);
 * // Poll dns fd or integrate with event loop
 * struct addrinfo *res = SocketDNS_getresult(dns, req);
 * if (res) Socket_bind_with_addrinfo(sock, res);
 * freeaddrinfo(res);
 * @endcode
 *
 * @note After bind, use Socket_getlocaladdr() and Socket_getlocalport() to
 * confirm
 * @note For IPv6, prefer "::" for dual-stack; use SocketConfig_set_ipv6only()
 * for v6-only
 * @warning Hostname resolution blocks; use Socket_bind_async() or IP for async
 * apps
 * @warning Privileged ports require root or cap_net_bind_service; use setcap
 * or non-privileged
 * @warning In containers/Docker, ensure --cap-add=NET_BIND_SERVICE or run as
 * root
 *
 * @complexity O(1) for IP bind; O(n) for hostname resolution where n=lookup
 * time
 *
 * @see Socket_listen() next step for servers
 * @see Socket_getlocaladdr(), Socket_getlocalport() for bound address query
 * @see Socket_bind_unix() for Unix domain binding
 * @see Socket_bind_async(), Socket_bind_with_addrinfo() for async variant
 * @see SocketDNS_T @ref core_io for async resolution
 * @see docs/SECURITY.md bind security considerations
 */
extern void Socket_bind (T socket, const char *host, int port);

/**
 * @brief Listen for incoming connections.
 * @ingroup core_io
 * @param socket Bound socket.
 * @param backlog Maximum pending connections.
 * @throws Socket_Failed on error.
 * @see Socket_bind() for binding sockets.
 * @see Socket_accept() for accepting connections.
 */
extern void Socket_listen (T socket, int backlog);

/**
 * @brief Accept incoming connection.
 * @ingroup core_io
 * @param socket Listening socket.
 * @return New socket or NULL if would block (EAGAIN/EWOULDBLOCK).
 * @throws Socket_Failed on error.
 * @note Returns NULL for non-blocking sockets when no connection is pending.
 * @see Socket_listen() for setting up listening sockets.
 */
extern T Socket_accept (T socket);

/**
 * @brief Establish a connection to a remote host and port.
 * @ingroup core_io
 *
 * Initiates a connection to the remote endpoint using connect(2). For TCP
 * sockets, this performs the 3-way handshake; for UDP, sets default peer
 * address for send(). Hostnames trigger synchronous DNS via getaddrinfo(3),
 * potentially blocking.
 *
 * Supported host formats:
 * - IP address: "192.168.1.1", "[2001:db8::1]"
 * - Hostname: "example.com" - resolves A/AAAA records
 * - IPv6 literals require [] brackets
 *
 * Port: 1-65535; common services like 80 (HTTP), 443 (HTTPS)
 *
 * Behavior:
 * - Blocking mode: Waits for handshake completion or timeout/failure
 * - Non-blocking: Returns immediately; use Socket_isconnected() or poll for
 * completion
 *
 * Edge cases:
 * - Unreachable host: Socket_Failed (ETIMEDOUT or ENETUNREACH)
 * - Refused connection: Socket_Failed (ECONNREFUSED)
 * - DNS failure: Socket_Failed with EAI_* mapped to errno
 * - Already connected: Socket_Failed (EISCONN)
 *
 * For non-blocking connect, pair with SocketPoll for writable event.
 *
 * @param[in,out] socket Unconnected socket (updated with peer addr/port on
 * success)
 * @param[in] host Remote address (IP or hostname)
 * @param[in] port Remote port (1-65535)
 *
 * @throws Socket_Failed Connect failed: ECONNREFUSED (no listener), ETIMEDOUT
 * (no route/response), ENETUNREACH/EHOSTUNREACH (routing), getaddrinfo/DNS
 * errors, EMSGSIZE (MTU issue)
 *
 * @threadsafe Yes - connects specific socket instance
 *
 * ## Basic Client Connect
 *
 * @code{.c}
 * Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 * Socket_connect(sock, "www.example.com", 80);
 * // Now connected; send HTTP request
 * ssize_t n = Socket_sendall(sock, "GET / HTTP/1.1\r\nHost:
 * example.com\r\n\r\n", len); Socket_free(&sock);
 * @endcode
 *
 * ## Non-Blocking Connect
 *
 * @code{.c}
 * Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 * Socket_setnonblocking(sock);
 * TRY {
 *     Socket_connect(sock, "example.com", 443);
 * } EXCEPT(Socket_Failed) {
 *     if (Socket_geterrno() == EINPROGRESS) {
 *         // Poll for writable
 *         SocketPoll_T poll = SocketPoll_new(1);
 *         SocketPoll_add(poll, sock, POLL_WRITE, sock);
 *         SocketEvent_T *ev = NULL;
 *         if (SocketPoll_wait(poll, &ev, timeout) > 0) {
 *             // Check getsockopt SO_ERROR for connect result
 *         }
 *     }
 * }
 * @endcode
 *
 * ## With Local Bind and Timeout
 *
 * @code{.c}
 * SocketTimeouts_T to = { .connect_ms = 5000 };
 * Socket_timeouts_set(sock, &to);
 * Socket_bind(sock, "192.168.1.10", 0);  // Specific source IP
 * Socket_connect(sock, "::1", 8080);  // IPv6 loopback
 * @endcode
 *
 * @note Success sets peer address; query with Socket_getpeeraddr/port()
 * @note For UDP, connect sets default peer for send() without addr
 * @note Dual-stack: Prefers IPv6 if available; configure via hints in async
 * DNS
 * @warning Synchronous DNS blocks; use Socket_connect_async() for event loops
 * @warning Firewalls/NAT may affect connectivity; test with real networks
 * @warning In non-blocking, EINPROGRESS means pending - check SO_ERROR later
 *
 * @complexity O(1) handshake time; O(n) for DNS where n=resolution latency
 *
 * @see Socket_isconnected() to verify connection status
 * @see Socket_getpeeraddr(), Socket_getpeerport() for remote endpoint
 * @see Socket_bind() for local address binding before connect
 * @see Socket_connect_async(), Socket_connect_with_addrinfo() for async
 * @see Socket_timeouts_set() for connect timeout control
 * @see docs/ASYNC_IO.md non-blocking connect patterns
 * @see docs/SECURITY.md secure connect practices (TLS, verify host)
 */
extern void Socket_connect (T socket, const char *host, int port);

/* ============================================================================
 * Basic I/O Operations
 * ============================================================================
 */

/**
 * @brief Send data.
 * @ingroup core_io
 * @param socket Connected socket.
 * @param buf Data to send.
 * @param len Length of data (> 0).
 * @return Bytes sent (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK).
 * @throws Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors.
 * @see Socket_sendall() for guaranteed complete transmission.
 * @see Socket_recv() for receiving data.
 */
extern ssize_t Socket_send (T socket, const void *buf, size_t len);

/**
 * @brief Receive data.
 * @ingroup core_io
 * @param socket Connected socket.
 * @param buf Buffer for received data.
 * @param len Buffer size (> 0).
 * @return Bytes received (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK).
 * @throws Socket_Closed on peer close or ECONNRESET, Socket_Failed on other
 * errors.
 * @see Socket_recvall() for guaranteed complete reception.
 * @see Socket_send() for sending data.
 */
extern ssize_t Socket_recv (T socket, void *buf, size_t len);

/**
 * @brief Send all data (handles partial sends).
 * @ingroup core_io
 * @param socket Connected socket.
 * @param buf Data to send.
 * @param len Length of data (> 0).
 * @return Total bytes sent (always equals len on success).
 * @throws Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors.
 * @see Socket_send() for partial send operations.
 * @see Socket_recvall() for receiving all data.
 */
extern ssize_t Socket_sendall (T socket, const void *buf, size_t len);

/**
 * @brief Receive all requested data (handles partial receives).
 * @ingroup core_io
 * @param socket Connected socket.
 * @param buf Buffer for received data.
 * @param len Buffer size (> 0).
 * @return Total bytes received (always equals len on success).
 * @throws Socket_Closed on peer close or ECONNRESET, Socket_Failed on other
 * errors.
 * @see Socket_recv() for partial receive operations.
 * @see Socket_sendall() for sending all data.
 */
extern ssize_t Socket_recvall (T socket, void *buf, size_t len);

/* ============================================================================
 * Scatter/Gather I/O Operations
 * ============================================================================
 */

/**
 * @brief Scatter/gather send (writev wrapper).
 * @ingroup core_io
 * @param socket Connected socket.
 * @param iov Array of iovec structures.
 * @param iovcnt Number of iovec structures (> 0, <= IOV_MAX).
 * @return Total bytes sent (> 0) or 0 if would block.
 * @throws Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors.
 * @see Socket_sendvall() for guaranteed complete scatter/gather send.
 * @see Socket_recvv() for scatter/gather receive.
 */
extern ssize_t Socket_sendv (T socket, const struct iovec *iov, int iovcnt);

/**
 * @brief Scatter/gather receive (readv wrapper).
 * @ingroup core_io
 * @param socket Connected socket.
 * @param iov Array of iovec structures.
 * @param iovcnt Number of iovec structures (> 0, <= IOV_MAX).
 * @return Total bytes received (> 0) or 0 if would block.
 * @throws Socket_Closed on peer close or ECONNRESET, Socket_Failed on other
 * errors.
 * @see Socket_recvvall() for guaranteed complete scatter/gather receive.
 * @see Socket_sendv() for scatter/gather send.
 */
extern ssize_t Socket_recvv (T socket, struct iovec *iov, int iovcnt);

/**
 * @brief Scatter/gather send all (handles partial sends).
 * @ingroup core_io
 * @param socket Connected socket.
 * @param iov Array of iovec structures.
 * @param iovcnt Number of iovec structures (> 0, <= IOV_MAX).
 * @return Total bytes sent (always equals sum of all iov_len on success).
 * @throws Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors.
 * @see Socket_sendv() for partial scatter/gather send.
 * @see Socket_recvvall() for receiving all scatter/gather data.
 */
extern ssize_t Socket_sendvall (T socket, const struct iovec *iov, int iovcnt);

/**
 * @brief Scatter/gather receive all (handles partial receives).
 * @ingroup core_io
 * @param socket Connected socket.
 * @param iov Array of iovec structures.
 * @param iovcnt Number of iovec structures (> 0, <= IOV_MAX).
 * @return Total bytes received (always equals sum of all iov_len on success).
 * @throws Socket_Closed on peer close or ECONNRESET, Socket_Failed on other
 * errors.
 * @see Socket_recvv() for partial scatter/gather receive.
 * @see Socket_sendvall() for sending all scatter/gather data.
 */
extern ssize_t Socket_recvvall (T socket, struct iovec *iov, int iovcnt);

/* ============================================================================
 * @brief Zero-Copy and Advanced I/O
 * ============================================================================
 */

/**
 * @brief Zero-copy file-to-socket transfer.
 * @ingroup core_io
 * @param socket Connected socket to send to.
 * @param file_fd File descriptor to read from (must be a regular file).
 * @param offset File offset to start reading from (NULL for current position).
 * @param count Number of bytes to transfer (0 for entire file from offset).
 * @return Total bytes transferred (> 0) or 0 if would block.
 * @throws Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors.
 * @see Socket_sendfileall() for guaranteed complete transfer.
 * @see Socket_send() for buffer-based sending.
 */
extern ssize_t Socket_sendfile (T socket, int file_fd, off_t *offset,
                                size_t count);

/**
 * @brief Zero-copy file-to-socket transfer (handles partial transfers).
 * @ingroup core_io
 * @param socket Connected socket to send to.
 * @param file_fd File descriptor to read from (must be a regular file).
 * @param offset File offset to start reading from (NULL for current position).
 * @param count Number of bytes to transfer (0 for entire file from offset).
 * @return Total bytes transferred (always equals count on success).
 * @throws Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors.
 * @see Socket_sendfile() for partial transfer operations.
 * @see Socket_sendall() for buffer-based guaranteed sending.
 */
extern ssize_t Socket_sendfileall (T socket, int file_fd, off_t *offset,
                                   size_t count);

/**
 * @brief Send message with ancillary data (sendmsg wrapper).
 * @ingroup core_io
 * @param socket Connected socket.
 * @param msg Message structure with data, address, and ancillary data.
 * @param flags Message flags (MSG_NOSIGNAL, MSG_DONTWAIT, etc.).
 * @return Total bytes sent (> 0) or 0 if would block.
 * @throws Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors.
 * @see Socket_recvmsg() for receiving messages with ancillary data.
 * @see Socket_sendfd() for sending file descriptors.
 */
extern ssize_t Socket_sendmsg (T socket, const struct msghdr *msg, int flags);

/**
 * @brief Receive message with ancillary data (recvmsg wrapper).
 * @ingroup core_io
 * @param socket Connected socket.
 * @param msg Message structure for data, address, and ancillary data.
 * @param flags Message flags (MSG_DONTWAIT, MSG_PEEK, etc.).
 * @return Total bytes received (> 0) or 0 if would block.
 * @throws Socket_Closed on peer close or ECONNRESET, Socket_Failed on other
 * errors.
 * @see Socket_sendmsg() for sending messages with ancillary data.
 * @see Socket_recvfd() for receiving file descriptors.
 */
extern ssize_t Socket_recvmsg (T socket, struct msghdr *msg, int flags);

/* ============================================================================
 * Socket State Query Functions
 * ============================================================================
 */

/**
 * @brief Check if socket is connected.
 * @ingroup core_io
 * @param socket Socket to check.
 * @return 1 if connected, 0 if not connected.
 * @threadsafe Yes.
 * @see Socket_connect() for establishing connections.
 * @see Socket_isbound() for checking binding state.
 */
extern int Socket_isconnected (T socket);

/**
 * @brief Check if socket is bound to an address.
 * @ingroup core_io
 * @param socket Socket to check.
 * @return 1 if bound, 0 if not bound.
 * @threadsafe Yes.
 * @see Socket_bind() for binding sockets.
 * @see Socket_isconnected() for checking connection state.
 */
extern int Socket_isbound (T socket);

/**
 * @brief Check if socket is listening for connections.
 * @ingroup core_io
 * @param socket Socket to check.
 * @return 1 if listening, 0 if not listening.
 * @threadsafe Yes.
 * @see Socket_listen() for setting up listening sockets.
 * @see Socket_accept() for accepting connections.
 */
extern int Socket_islistening (T socket);

/**
 * @brief Get underlying file descriptor.
 * @ingroup core_io
 * @param socket Socket instance.
 * @return File descriptor.
 * @see Socket_new_from_fd() for creating sockets from file descriptors.
 */
extern int Socket_fd (const T socket);

/**
 * @brief Get peer IP address.
 * @ingroup core_io
 * @param socket Connected socket.
 * @return IP address string (IPv4/IPv6) or "(unknown)" if unavailable.
 * @note String is owned by socket, valid until socket freed.
 * @see Socket_getpeerport() for peer port.
 * @see Socket_connect() for establishing connections.
 */
extern const char *Socket_getpeeraddr (const T socket);

/**
 * @brief Get peer port number.
 * @ingroup core_io
 * @param socket Connected socket.
 * @return Port number (1 to SOCKET_MAX_PORT) or 0 if unavailable.
 * @see Socket_getpeeraddr() for peer address.
 * @see Socket_connect() for establishing connections.
 */
extern int Socket_getpeerport (const T socket);

/**
 * @brief Get local IP address.
 * @ingroup core_io
 * @param socket Socket instance.
 * @return IP address string (IPv4/IPv6) or "(unknown)" if unavailable.
 * @note String is owned by socket, valid until socket freed.
 * @see Socket_getlocalport() for local port.
 * @see Socket_bind() for binding to addresses.
 */
extern const char *Socket_getlocaladdr (const T socket);

/**
 * @brief Get local port number.
 * @ingroup core_io
 * @param socket Socket instance.
 * @return Port number (1 to SOCKET_MAX_PORT) or 0 if unavailable.
 * @see Socket_getlocaladdr() for local address.
 * @see Socket_bind() for binding to ports.
 */
extern int Socket_getlocalport (const T socket);

/* ============================================================================
 * Socket Options Configuration
 * ============================================================================
 */

/**
 * @brief Enable non-blocking mode.
 * @ingroup core_io
 * @param socket Socket to modify.
 * @throws Socket_Failed on error.
 * @see Socket_accept() for non-blocking accept behavior.
 * @see Socket_send() for non-blocking send behavior.
 */
extern void Socket_setnonblocking (T socket);

/**
 * @brief Enable address reuse.
 * @ingroup core_io
 * @param socket Socket to modify.
 * @throws Socket_Failed on error.
 * @see Socket_bind() for binding operations.
 * @see Socket_setreuseport() for port reuse.
 */
extern void Socket_setreuseaddr (T socket);

/**
 * @brief Enable port reuse across sockets.
 * @ingroup core_io
 * @param socket Socket to modify.
 * @throws Socket_Failed on error (or if SO_REUSEPORT unsupported).
 * @see Socket_setreuseaddr() for address reuse.
 * @see Socket_bind() for binding operations.
 */
extern void Socket_setreuseport (T socket);

/**
 * @brief Set socket timeout.
 * @ingroup core_io
 * @param socket Socket to modify.
 * @param timeout_sec Timeout in seconds (0 to disable).
 * @throws Socket_Failed on error.
 * @note Sets both send and receive timeouts.
 * @see Socket_gettimeout() for retrieving current timeout.
 */
extern void Socket_settimeout (T socket, int timeout_sec);

/**
 * @brief Enable TCP keepalive.
 * @ingroup core_io
 * @param socket Socket to modify.
 * @param idle Seconds before sending keepalive probes.
 * @param interval Interval between keepalive probes.
 * @param count Number of probes before declaring dead.
 * @throws Socket_Failed on error.
 * @see Socket_getkeepalive() for retrieving keepalive settings.
 */
extern void Socket_setkeepalive (T socket, int idle, int interval, int count);

/**
 * @brief Disable Nagle's algorithm.
 * @ingroup core_io
 * @param socket Socket to modify.
 * @param nodelay 1 to disable Nagle, 0 to enable.
 * @throws Socket_Failed on error.
 * @see Socket_getnodelay() for retrieving Nagle setting.
 */
extern void Socket_setnodelay (T socket, int nodelay);

/**
 * @brief Get socket timeout.
 * @ingroup core_io
 * @param socket Socket to query.
 * @return Timeout in seconds (0 if disabled).
 * @throws Socket_Failed on error.
 * @see Socket_settimeout() for setting timeout.
 */
extern int Socket_gettimeout (T socket);

/**
 * @brief Get TCP keepalive configuration.
 * @ingroup core_io
 * @param socket Socket to query.
 * @param idle Output - idle timeout in seconds.
 * @param interval Output - interval between probes in seconds.
 * @param count Output - number of probes before declaring dead.
 * @throws Socket_Failed on error.
 * @see Socket_setkeepalive() for setting keepalive parameters.
 */
extern void Socket_getkeepalive (T socket, int *idle, int *interval,
                                 int *count);

/**
 * @brief Get TCP_NODELAY setting.
 * @ingroup core_io
 * @param socket Socket to query.
 * @return 1 if Nagle's algorithm is disabled, 0 if enabled.
 * @throws Socket_Failed on error.
 * @see Socket_setnodelay() for setting Nagle algorithm.
 */
extern int Socket_getnodelay (T socket);

/**
 * @brief Get receive buffer size.
 * @ingroup core_io
 * @param socket Socket to query.
 * @return Receive buffer size in bytes.
 * @throws Socket_Failed on error.
 * @see Socket_setrcvbuf() for setting receive buffer size.
 */
extern int Socket_getrcvbuf (T socket);

/**
 * @brief Get send buffer size.
 * @ingroup core_io
 * @param socket Socket to query.
 * @return Send buffer size in bytes.
 * @throws Socket_Failed on error.
 * @see Socket_setsndbuf() for setting send buffer size.
 */
extern int Socket_getsndbuf (T socket);

/**
 * @brief Set receive buffer size.
 * @ingroup core_io
 * @param socket Socket to modify.
 * @param size Buffer size in bytes (> 0).
 * @throws Socket_Failed on error.
 * @see Socket_getrcvbuf() for retrieving receive buffer size.
 */
extern void Socket_setrcvbuf (T socket, int size);

/**
 * @brief Set send buffer size.
 * @ingroup core_io
 * @param socket Socket to modify.
 * @param size Buffer size in bytes (> 0).
 * @throws Socket_Failed on error.
 * @see Socket_getsndbuf() for retrieving send buffer size.
 */
extern void Socket_setsndbuf (T socket, int size);

/**
 * @brief Set TCP congestion control algorithm.
 * @ingroup core_io
 * @param socket Socket to modify.
 * @param algorithm Algorithm name (e.g., "cubic", "reno", "bbr").
 * @throws Socket_Failed on error or if not supported.
 * @note Only available on Linux 2.6.13+.
 * @see Socket_getcongestion() for retrieving current algorithm.
 */
extern void Socket_setcongestion (T socket, const char *algorithm);

/**
 * @brief Get TCP congestion control algorithm.
 * @ingroup core_io
 * @param socket Socket to query.
 * @param algorithm Output buffer for algorithm name.
 * @param len Buffer length.
 * @return 0 on success, -1 on error or if not supported.
 * @see Socket_setcongestion() for setting algorithm.
 */
extern int Socket_getcongestion (T socket, char *algorithm, size_t len);

/**
 * @brief Enable TCP Fast Open.
 * @ingroup core_io
 * @param socket Socket to modify.
 * @param enable 1 to enable, 0 to disable.
 * @throws Socket_Failed on error or if not supported.
 * @see Socket_getfastopen() for retrieving Fast Open setting.
 */
extern void Socket_setfastopen (T socket, int enable);

/**
 * @brief Get TCP Fast Open setting.
 * @ingroup core_io
 * @param socket Socket to query.
 * @return 1 if enabled, 0 if disabled, -1 on error.
 * @see Socket_setfastopen() for enabling Fast Open.
 */
extern int Socket_getfastopen (T socket);

/**
 * @brief Set TCP user timeout.
 * @ingroup core_io
 * @param socket Socket to modify.
 * @param timeout_ms Timeout in milliseconds (> 0).
 * @throws Socket_Failed on error or if not supported.
 * @note Only available on Linux 2.6.37+.
 * @see Socket_getusertimeout() for retrieving user timeout.
 */
extern void Socket_setusertimeout (T socket, unsigned int timeout_ms);

/**
 * @brief Get TCP user timeout.
 * @ingroup core_io
 * @param socket Socket to query.
 * @return Timeout in milliseconds, or 0 on error.
 * @see Socket_setusertimeout() for setting user timeout.
 */
extern unsigned int Socket_getusertimeout (T socket);

/**
 * @brief Disable further sends and/or receives.
 * @ingroup core_io
 * @param socket Connected socket.
 * @param how Shutdown mode (SHUT_RD, SHUT_WR, or SHUT_RDWR).
 * @throws Socket_Failed on error.
 * @see Socket_close() for full connection teardown.
 */
extern void Socket_shutdown (T socket, int how);

/**
 * @brief Control close-on-exec flag.
 * @ingroup core_io
 * @param socket Socket to modify.
 * @param enable 1 to enable CLOEXEC, 0 to disable.
 * @throws Socket_Failed on error.
 * @note By default, sockets have CLOEXEC enabled.
 */
extern void Socket_setcloexec (T socket, int enable);

/* ============================================================================
 * SYN Flood Protection Socket Options
 * ============================================================================
 */

/**
 * @brief Enable TCP_DEFER_ACCEPT.
 * @ingroup core_io
 * @param socket Listening socket.
 * @param timeout_sec Seconds to wait for data before completing accept (0 to
 * disable, max platform-specific).
 *
 * Delays accept() completion until client sends data, preventing
 * @brief SYN-only connections from consuming application resources.
 * This is a key defense against SYN flood attacks.
 *
 * Linux: Uses TCP_DEFER_ACCEPT socket option
 * BSD/macOS: Uses SO_ACCEPTFILTER with "dataready" filter
 *
 * @throws Socket_Failed on error or if unsupported.
 * @threadsafe Yes.
 * @see Socket_getdeferaccept() for retrieving current setting.
 * @see Socket_accept() for accepting connections.
 */
extern void Socket_setdeferaccept (T socket, int timeout_sec);

/**
 * @brief Get TCP_DEFER_ACCEPT timeout.
 * @ingroup core_io
 * @param socket Listening socket.
 * @return Current defer accept timeout in seconds, 0 if disabled.
 * @throws Socket_Failed on error.
 * @threadsafe Yes.
 * @see Socket_setdeferaccept() for setting defer accept.
 */
extern int Socket_getdeferaccept (T socket);

/* ============================================================================
 * Timeout Configuration
 * ============================================================================
 */

/**
 * @brief Retrieve per-socket timeout configuration.
 * @ingroup core_io
 * @param socket Socket instance.
 * @param timeouts Output timeout structure.
 * @see Socket_timeouts_set() for setting timeouts.
 * @see Socket_timeouts_getdefaults() for global defaults.
 */
extern void Socket_timeouts_get (const T socket, SocketTimeouts_T *timeouts);

/**
 * @brief Set per-socket timeout configuration.
 * @ingroup core_io
 * @param socket Socket instance.
 * @param timeouts Timeout configuration (NULL to reset to defaults).
 * @see Socket_timeouts_get() for retrieving timeouts.
 * @see Socket_timeouts_setdefaults() for changing global defaults.
 */
extern void Socket_timeouts_set (T socket, const SocketTimeouts_T *timeouts);

/**
 * @brief Get global default timeouts.
 * @ingroup core_io
 * @param timeouts Output timeout structure containing current defaults.
 * @see Socket_timeouts_setdefaults() for changing defaults.
 * @see Socket_timeouts_get() for per-socket timeouts.
 */
extern void Socket_timeouts_getdefaults (SocketTimeouts_T *timeouts);

/**
 * @brief Set global default timeouts.
 * @ingroup core_io
 * @param timeouts New default timeout configuration.
 * @see Socket_timeouts_getdefaults() for retrieving defaults.
 * @see Socket_timeouts_set() for per-socket overrides.
 */
extern void Socket_timeouts_setdefaults (const SocketTimeouts_T *timeouts);

/**
 * @brief Set per-socket extended timeout configuration.
 * @param socket Socket to modify.
 * @param extended Extended per-phase timeout configuration.
 *
 * Sets granular per-phase timeouts for advanced use cases. The extended
 * timeouts provide finer control than SocketTimeouts_T, allowing different
 * timeouts for DNS, connect, TLS, and request phases.
 *
 * Values of 0 in the extended structure mean "inherit from basic timeouts".
 * Values of -1 mean "no timeout (infinite)".
 *
 * @threadsafe No - caller must ensure exclusive access to socket.
 * @see Socket_timeouts_get_extended() for retrieving extended timeouts.
 * @see SocketTimeouts_Extended_T for timeout structure details.
 */
extern void
Socket_timeouts_set_extended (T socket,
                              const SocketTimeouts_Extended_T *extended);

/**
 * @brief Retrieve per-socket extended timeout configuration.
 * @ingroup core_io
 * @param socket Socket to query.
 * @param extended Output structure for extended timeouts.
 *
 * Retrieves the current extended timeout configuration. If extended timeouts
 * haven't been set, returns the basic timeouts mapped to the extended
 * structure.
 *
 * @threadsafe No - caller must ensure exclusive access to socket.
 * @see Socket_timeouts_set_extended() for setting extended timeouts.
 */
extern void Socket_timeouts_get_extended (const T socket,
                                          SocketTimeouts_Extended_T *extended);

/* ============================================================================
 * Bandwidth Limiting
 * ============================================================================
 */

/**
 * @brief Set bandwidth limit for socket.
 * @ingroup core_io
 * @param socket Socket to modify.
 * @param bytes_per_sec Maximum bytes per second (0 to disable limiting).
 * @throws Socket_Failed on allocation failure.
 * @threadsafe Yes - uses internal mutex for synchronization.
 *
 * Enables bandwidth throttling using a token bucket algorithm.
 * The burst capacity is set to bytes_per_sec (1 second of data).
 * Use Socket_send_limited() for rate-limited sending.
 *
 * @see Socket_getbandwidth() for retrieving current limit.
 * @see Socket_send_limited() for rate-limited operations.
 */
extern void Socket_setbandwidth (T socket, size_t bytes_per_sec);

/**
 * @brief Get bandwidth limit for socket.
 * @ingroup core_io
 * @param socket Socket to query.
 * @return Bandwidth limit in bytes per second (0 if unlimited).
 * @threadsafe Yes.
 * @see Socket_setbandwidth() for setting bandwidth limit.
 */
extern size_t Socket_getbandwidth (T socket);

/**
 * @brief Send data with bandwidth limiting.
 * @ingroup core_io
 * @param socket Connected socket.
 * @param buf Data to send.
 * @param len Length of data (> 0).
 * @return Bytes sent (> 0), 0 if rate limited (try again later), or raises.
 * @throws Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors.
 * @threadsafe Yes - uses per-socket bandwidth limiter with internal locking.
 *
 * Like Socket_send() but respects bandwidth limit set by
 * Socket_setbandwidth(). If bandwidth limiting is disabled (0), behaves like
 * Socket_send(). If rate limited, returns 0 and caller should wait before
 * retrying. Use Socket_bandwidth_wait_ms() to get recommended wait time.
 *
 * @see Socket_recv_limited() for bandwidth-limited receiving.
 * @see Socket_bandwidth_wait_ms() for wait time calculation.
 */
extern ssize_t Socket_send_limited (T socket, const void *buf, size_t len);

/**
 * @brief Receive data with bandwidth limiting.
 * @ingroup core_io
 * @param socket Connected socket.
 * @param buf Buffer for received data.
 * @param len Buffer size (> 0).
 * @return Bytes received (> 0), 0 if rate limited or would block, or raises.
 * @throws Socket_Closed on peer close, Socket_Failed on other errors.
 * @threadsafe Yes - uses per-socket bandwidth limiter with internal locking.
 *
 * Like Socket_recv() but respects bandwidth limit set by
 * Socket_setbandwidth(). If bandwidth limiting is disabled (0), behaves like
 * Socket_recv().
 *
 * @see Socket_send_limited() for bandwidth-limited sending.
 */
extern ssize_t Socket_recv_limited (T socket, void *buf, size_t len);

/**
 * @brief Get wait time until bandwidth available.
 * @ingroup core_io
 * @param socket Socket to query.
 * @param bytes Number of bytes needed.
 * @return Milliseconds to wait, 0 if immediate, -1 if impossible.
 * @threadsafe Yes.
 *
 * Useful for event loop integration - use as poll timeout.
 *
 * @see Socket_send_limited() for bandwidth-limited operations.
 */
extern int64_t Socket_bandwidth_wait_ms (T socket, size_t bytes);

/* ============================================================================
 * Unix Domain Socket Operations
 * ============================================================================
 */

/**
 * @brief Bind to Unix domain socket path.
 * @ingroup core_io
 * @param socket Socket to bind (AF_UNIX).
 * @param path Socket file path.
 * @throws Socket_Failed on error.
 * @note Fails with EADDRINUSE if path exists. Max path length ~108 bytes.
 * @note Supports abstract namespace sockets on Linux (path starting with '@').
 * @see Socket_connect_unix() for connecting to Unix sockets.
 */
extern void Socket_bind_unix (T socket, const char *path);

/**
 * @brief Connect to Unix domain socket path.
 * @ingroup core_io
 * @param socket Socket to connect (AF_UNIX).
 * @param path Socket file path.
 * @throws Socket_Failed on error.
 * @note Supports abstract namespace sockets on Linux (path starting with '@').
 * @see Socket_bind_unix() for binding Unix sockets.
 */
extern void Socket_connect_unix (T socket, const char *path);

/**
 * @brief Get peer process ID (Linux only).
 * @ingroup core_io
 * @param socket Connected Unix domain socket.
 * @return Peer process ID, or -1 if unavailable.
 * @see Socket_getpeeruid() for peer user ID.
 * @see Socket_getpeergid() for peer group ID.
 */
extern int Socket_getpeerpid (const T socket);

/**
 * @brief Get peer user ID (Linux only).
 * @ingroup core_io
 * @param socket Connected Unix domain socket.
 * @return Peer user ID, or (uid_t)-1 if unavailable.
 * @see Socket_getpeerpid() for peer process ID.
 * @see Socket_getpeergid() for peer group ID.
 */
extern int Socket_getpeeruid (const T socket);

/**
 * @brief Get peer group ID (Linux only).
 * @ingroup core_io
 * @param socket Connected Unix domain socket.
 * @return Peer group ID, or (gid_t)-1 if unavailable.
 * @see Socket_getpeerpid() for peer process ID.
 * @see Socket_getpeeruid() for peer user ID.
 */
extern int Socket_getpeergid (const T socket);

/* ============================================================================
 * File Descriptor Passing (SCM_RIGHTS)
 * ============================================================================
 */

/**
 * @brief Send a file descriptor over Unix domain socket.
 * @ingroup core_io
 * @param socket Connected Unix domain socket (AF_UNIX).
 * @param fd_to_pass File descriptor to pass (must be >= 0).
 * @return 1 on success, 0 if would block (EAGAIN/EWOULDBLOCK).
 * @throws Socket_Failed on error, Socket_Closed on disconnect.
 *
 * Passes a single file descriptor to the peer process using SCM_RIGHTS.
 * The receiving process gets a new fd referring to the same kernel object.
 *
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant Unix domain socket (AF_UNIX)
 * - NOT available on Windows
 *
 * SECURITY NOTES:
 * - Only works with connected Unix domain sockets
 * - Receiving process should validate the fd type before use
 *
 * @threadsafe Yes - uses thread-local error buffers for safe concurrent
 * operation.
 * @see Socket_recvfd() for receiving file descriptors.
 * @see Socket_sendfds() for sending multiple descriptors.
 */
extern int Socket_sendfd (T socket, int fd_to_pass);

/**
 * @brief Receive a file descriptor over Unix domain socket.
 * @ingroup core_io
 * @param socket Connected Unix domain socket (AF_UNIX).
 * @param fd_received Output pointer for received file descriptor.
 * @return 1 on success, 0 if would block (EAGAIN/EWOULDBLOCK).
 * @throws Socket_Failed on error, Socket_Closed on disconnect.
 *
 * Receives a file descriptor from the peer process via SCM_RIGHTS.
 * The received fd is owned by this process and must be closed when done.
 *
 * OWNERSHIP: Caller takes ownership of the received fd and MUST close it.
 *
 * @threadsafe Yes - uses thread-local error buffers for safe concurrent
 * operation.
 * @see Socket_sendfd() for sending file descriptors.
 * @see Socket_recvfds() for receiving multiple descriptors.
 */
extern int Socket_recvfd (T socket, int *fd_received);

/**
 * @brief Send multiple file descriptors.
 * @ingroup core_io
 * @param socket Connected Unix domain socket (AF_UNIX).
 * @param fds Array of file descriptors to pass (all must be >= 0).
 * @param count Number of descriptors (1 to SOCKET_MAX_FDS_PER_MSG).
 * @return 1 on success, 0 if would block (EAGAIN/EWOULDBLOCK).
 * @throws Socket_Failed on error, Socket_Closed on disconnect.
 *
 * Passes multiple file descriptors atomically in a single message.
 * All descriptors are either sent together or none are sent.
 *
 * @threadsafe Yes - uses thread-local error buffers for safe concurrent
 * operation.
 * @see Socket_recvfds() for receiving multiple descriptors.
 * @see Socket_sendfd() for sending single descriptor.
 */
extern int Socket_sendfds (T socket, const int *fds, size_t count);

/**
 * @brief Receive multiple file descriptors.
 * @ingroup core_io
 * @param socket Connected Unix domain socket (AF_UNIX).
 * @param fds Output array for received descriptors (must have max_count
 * capacity).
 * @param max_count Maximum descriptors to receive.
 * @param received_count Output for actual count received.
 * @return 1 on success, 0 if would block (EAGAIN/EWOULDBLOCK).
 * @throws Socket_Failed on error, Socket_Closed on disconnect.
 *
 * Receives multiple file descriptors from a single message.
 * On success, *received_count contains the number of fds received.
 *
 * OWNERSHIP: Caller takes ownership of all received fds and MUST close them.
 *
 * @threadsafe Yes - uses thread-local error buffers for safe concurrent
 * operation.
 * @see Socket_sendfds() for sending multiple descriptors.
 * @see Socket_recvfd() for receiving single descriptor.
 */
extern int Socket_recvfds (T socket, int *fds, size_t max_count,
                           size_t *received_count);

/**
 * @brief Bind Unix domain socket to a filesystem path.
 * @ingroup core_io
 * @internal
 * @param base The socket base structure containing the file descriptor and
 * domain.
 * @param path Null-terminated string specifying the Unix socket path.
 * @param exc_type Exception type to raise on failure.
 * @throws exc_type On bind errors such as EADDRINUSE, ENOENT, or EACCES.
 *
 * Internal helper function that performs Unix domain socket binding.
 * Validates the path and calls bind(2) system call.
 * Supports both filesystem paths and abstract sockets (Linux).
 *
 * @see Socket_bind_unix() for the public high-level interface.
 * @see SocketUnix_connect() for the connect counterpart.
 * @see SocketUnix_validate_unix_path() for path validation.
 * @threadsafe Conditional - safe if base fd is not shared across threads
 * without locking.
 */
extern void SocketUnix_bind (SocketBase_T base, const char *path,
                             Except_T exc_type);

/**
 * @brief Connect Unix domain socket to a filesystem path.
 * @ingroup core_io
 * @internal
 * @param base The socket base structure containing the file descriptor and
 * domain.
 * @param path Null-terminated string specifying the remote Unix socket path.
 * @param exc_type Exception type to raise on failure.
 * @throws exc_type On connect errors such as ECONNREFUSED, ENOENT, or EACCES.
 *
 * Internal helper function that performs Unix domain socket connection.
 * Validates the path and calls connect(2) system call.
 * Supports both filesystem paths and abstract sockets (Linux).
 *
 * @see Socket_connect_unix() for the public high-level interface.
 * @see SocketUnix_bind() for the bind counterpart.
 * @see SocketUnix_validate_unix_path() for path validation.
 * @threadsafe Conditional - safe if base fd is not shared across threads
 * without locking.
 */
extern void SocketUnix_connect (SocketBase_T base, const char *path,
                                Except_T exc_type);

/**
 * @brief Validate a Unix domain socket path.
 * @ingroup core_io
 * @internal
 * @param path The path string to validate.
 * @param path_len Length of the path string (excluding null terminator).
 * @return 1 if the path is valid for Unix socket operations, 0 otherwise.
 *
 * Checks path constraints:
 * - Length <= UNIX_PATH_MAX (typically 108 bytes)
 * - Not empty
 * - Supports abstract socket prefix (\0 on Linux)
 *
 * Used by bind and connect helpers to ensure valid paths before system calls.
 *
 * @see SocketUnix_bind()
 * @see SocketUnix_connect()
 * @threadsafe Yes - pure function, no side effects.
 */
extern int SocketUnix_validate_unix_path (const char *path, size_t path_len);

/* ============================================================================
 * Async DNS Operations
 * ============================================================================
 */

/**
 * @brief Start async DNS resolution for bind.
 * @ingroup core_io
 * @param dns DNS resolver instance.
 * @param socket Socket to bind.
 * @param host IP address or hostname (NULL for any).
 * @param port Port number (1 to SOCKET_MAX_PORT).
 * @return DNS request handle.
 * @throws Socket_Failed on error.
 * @see Socket_bind_async_cancel() for canceling the request.
 * @see Socket_bind_with_addrinfo() for binding with resolved address.
 */
extern Request_T Socket_bind_async (SocketDNS_T dns, T socket,
                                    const char *host, int port);

/**
 * @brief Cancel pending async bind resolution.
 * @ingroup core_io
 * @param dns DNS resolver instance.
 * @param req Request handle returned by Socket_bind_async.
 * @see Socket_bind_async() for starting async bind.
 */
extern void Socket_bind_async_cancel (SocketDNS_T dns, Request_T req);

/**
 * @brief Start async DNS resolution for connect.
 * @ingroup core_io
 * @param dns DNS resolver instance.
 * @param socket Socket to connect.
 * @param host Remote IP address or hostname.
 * @param port Remote port (1 to SOCKET_MAX_PORT).
 * @return DNS request handle.
 * @throws Socket_Failed on error.
 * @see Socket_connect_async_cancel() for canceling the request.
 * @see Socket_connect_with_addrinfo() for connecting with resolved address.
 */
extern Request_T Socket_connect_async (SocketDNS_T dns, T socket,
                                       const char *host, int port);

/**
 * @brief Cancel pending async connect resolution.
 * @ingroup core_io
 * @param dns DNS resolver instance.
 * @param req Request handle returned by Socket_connect_async.
 * @see Socket_connect_async() for starting async connect.
 */
extern void Socket_connect_async_cancel (SocketDNS_T dns, Request_T req);

/**
 * @brief Bind socket using resolved address.
 * @ingroup core_io
 * @param socket Socket to bind.
 * @param res Resolved addrinfo result from DNS resolution.
 * @throws Socket_Failed on error.
 * @see Socket_bind_async() for async DNS resolution.
 * @see Socket_bind() for direct binding.
 */
extern void Socket_bind_with_addrinfo (T socket, struct addrinfo *res);

/**
 * @brief Connect socket using resolved address.
 * @ingroup core_io
 * @param socket Socket to connect.
 * @param res Resolved addrinfo result from DNS resolution.
 * @throws Socket_Failed on error.
 * @see Socket_connect_async() for async DNS resolution.
 * @see Socket_connect() for direct connection.
 */
extern void Socket_connect_with_addrinfo (T socket, struct addrinfo *res);

/* ============================================================================
 * Signal Handling Utilities
 * ============================================================================
 */

/**
 * @brief Globally ignore SIGPIPE signal.
 * @ingroup core_io
 * @return 0 on success, -1 on error (sets errno).
 * @threadsafe Yes - can be called from any thread, idempotent operation.
 *
 * NOTE: This function is NOT required when using this library. The library
 * handles SIGPIPE internally via:
 * - MSG_NOSIGNAL flag on send operations (Linux/FreeBSD)
 * - SO_NOSIGPIPE socket option at creation (BSD/macOS)
 *
 * This convenience function is provided for:
 * - Legacy code migration (applications that previously handled SIGPIPE)
 * - Applications mixing this library with raw socket code
 * - Defense-in-depth preference
 *
 * Usage:
 *   // Optional - call once at program startup if desired
 *   Socket_ignore_sigpipe();
 *
 * IMPORTANT: Do not call this if your application needs to handle SIGPIPE
 * for other purposes (e.g., detecting broken pipes in shell pipelines).
 *
 * @see Socket_send() for SIGPIPE-safe sending operations.
 */
extern int Socket_ignore_sigpipe (void);

#undef T

/** @} */ /* end of core_io group */

#endif /* SOCKET_INCLUDED */
