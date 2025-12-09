#ifndef SOCKETDGRAM_INCLUDED
#define SOCKETDGRAM_INCLUDED

#include "core/Except.h"
#include "socket/SocketCommon.h" /* For SocketBase_T and Unix support */
#include <stddef.h>
#include <sys/socket.h>

/**
 * @defgroup socket_dgram Datagram Sockets
 * @brief Comprehensive API for UDP and datagram sockets including multicast,
 * broadcast, and scatter/gather support.
 * @ingroup socket_dgram
 *
 * The Datagram Sockets module offers a high-level, exception-based interface
 * for connectionless protocols like UDP. It abstracts low-level socket
 * operations, providing features for reliable messaging over unreliable
 * transports. Supports IPv4, IPv6, and Unix domain datagrams with advanced
 * capabilities for network discovery, streaming, and IPC.
 *
 * ## Architecture Overview
 *
 * ```
 * ┌───────────────────────────────────────────────────────────┐
 * │                    Application Layer                      │
 * │  UDP Echo Servers, mDNS Clients, Game Networking, etc.    │
 * └─────────────────────┬─────────────────────────────────────┘
 *                       │ Uses
 * ┌─────────────────────▼─────────────────────────────────────┐
 * │               Datagram Module                             │
 * │  SocketDgram_T + sendto/recvfrom, joinmulticast, etc.     │
 * └─────────────────────┬─────────────────────────────────────┘
 *                       │ Depends on
 * ┌─────────────────────▼─────────────────────────────────────┐
 * │              Core I/O Foundation                          │
 * │  SocketBase_T, Except_T, SocketUtil hash & timeouts       │
 * └───────────────────────────────────────────────────────────┘
 * ```
 *
 * ## Key Features
 * - **Connectionless & Connected Modes**: Use sendto/recvfrom for arbitrary
 * peers or connect for default destination optimization.
 * - **Multicast/Broadcast**: Join groups, send to broadcast addresses for
 * discovery protocols (e.g., mDNS, SSDP).
 * - **Scatter/Gather I/O**: Efficient sendv/recvv for zero-copy from multiple
 * buffers.
 * - **Non-Blocking & Timeouts**: Full support for async I/O with SocketPoll
 * integration.
 * - **Exception Safety**: TRY/EXCEPT for clean error handling without error
 * code propagation.
 * - **Thread Safety**: Individual socket operations are thread-safe; no global
 * state.
 * - **Platform Agnostic**: Auto-detects backends (epoll, kqueue, poll) for
 * performance.
 *
 * ## Module Relationships
 * - **Dependencies**: core/Except.h (exceptions), socket/SocketCommon.h (base
 * socket), sys/socket.h (POSIX)
 * - **Used By**: Higher-level modules like dns/SocketDNS.h (UDP DNS queries),
 * tls/SocketDTLS.h (DTLS over UDP)
 * - **Integration**: poll/SocketPoll.h for event multiplexing,
 * pool/SocketPool.h for UDP connection pooling (rare)
 * - **Utilities**: Uses core/SocketUtil for hashing, timeouts, logging;
 * core/Arena_T for internal allocations
 *
 * ## Platform Requirements & Limitations
 * | Requirement | Details |
 * |------------|---------|
 * | OS | POSIX (Linux, BSD, macOS); Windows requires Winsock port |
 * | Network | IPv6 kernel support for dual-stack; multicast routing enabled |
 * | Threads | pthreads for error reporting and internal locks |
 * | Limits | Subject to ulimit -n (open files), SO_MAXCONN |
 *
 * ## Error Handling
 * - Primary exception: SocketDgram_Failed for syscalls, invalid params,
 * resource issues
 * - Return conventions: ssize_t functions return bytes or 0
 * (EAGAIN/would-block)
 * - Use Socket_GetLastError() for human-readable messages post-exception
 * - See docs/ERROR_HANDLING.md for TRY/EXCEPT patterns
 *
 * ## Performance Notes
 * - O(1) for most operations (syscalls)
 * - Avoid DNS in hot paths; resolve addresses upfront or use SocketDNS async
 * - Buffer sizes tunable via getsockopt (default OS-dependent, often 212KB)
 * - For high-throughput, use recvvall/sendvall to minimize copies
 *
 * ## Security Considerations
 * - CLOEXEC enabled by default to prevent fd leaks in forks
 * - Validate sender addresses in recvfrom to prevent spoofing
 * - Use TTL=1 for link-local multicast to limit scope
 * - Integrate with security/SocketSYNProtect.h for rate limiting (though UDP
 * stateless)
 *
 * @see SocketDgram_new() for initialization
 * @see SocketDgram_bind() for server-side binding
 * @see SocketDgram_sendto() / SocketDgram_recvfrom() for core I/O
 * @see docs/SECURITY.md for network security
 * @see docs/ASYNC_IO.md for non-blocking integration
 * @{
 */

/**
 * @file SocketDgram.h
 * @brief High-level UDP/datagram socket interface with multicast and broadcast
 * support.
 * @ingroup socket_dgram
 *
 * Provides a high-level, exception-based interface for UDP/datagram sockets.
 * All functions use exceptions for error handling, making code cleaner
 * and more robust than traditional error code checking.
 *
 * Platform Requirements:
 * - POSIX-compliant system (Linux, BSD, macOS, etc.)
 * - IPv6 support in kernel (for dual-stack sockets)
 * - POSIX threads (pthread) for thread-safe error reporting
 * - NOT portable to Windows without Winsock adaptation layer
 *
 * Features:
 * - Connectionless (sendto/recvfrom) and connected (send/recv) modes
 * - Non-blocking I/O support
 * - Thread-safe error reporting
 * - IPv4 and IPv6 dual-stack support
 * - Broadcast and multicast support
 *
 * UDP vs TCP:
 * - Connectionless: No three-way handshake required
 * - Unreliable: Packets may be lost, duplicated, or reordered
 * - Message-oriented: Preserves message boundaries
 * - Lower latency: No connection setup or ACK delays
 * - Use cases: DNS, gaming, streaming, service discovery
 *
 * Error Handling:
 * - Most functions raise SocketDgram_Failed on errors
 * - Some functions (recvfrom, sendto) may return 0 for would-block (EAGAIN)
 * - Check individual function documentation for specific behavior
 *
 * @see @ref socket_dgram for module overview.
 * @see Socket_T for TCP and Unix domain sockets.
 * @see SocketDgram_new() for socket creation.
 * @see SocketDgram_sendto() for connectionless sending.
 */

#define T SocketDgram_T
/**
 * @brief Opaque type representing a datagram socket instance.
 * @ingroup socket_dgram
 *
 * SocketDgram_T encapsulates a low-level socket FD with additional state for
 * datagram-specific features like connected peer, multicast memberships, TTL,
 * and buffer configurations. The internal structure extends SocketBase_T with
 * UDP-specific fields (e.g., addrinfo cache for connect). Opaque to users;
 * access via accessor functions only. Lifetime managed by new/free pair.
 * Thread safety: Individual instances are safe for concurrent read/write if
 * synchronized externally. No global state; each socket independent.
 *
 * Key internal behaviors:
 * - Automatic FD tracking for leak detection via debug_live_count()
 * - Lazy initialization of options on first use
 * - Exception propagation via module's SocketDgram_Failed
 * - Integration hooks for poll backends and timers
 *
 * Usage: Create with SocketDgram_new(), configure, use for I/O, free when
 * done. For high-performance, combine with SocketBuf for buffering and
 * SocketPoll for multiplexing.
 *
 * @note Do not cast or access internals; violates opaque abstraction.
 * @note Sockets use Arena_T internally if passed during advanced config
 * (future extension).
 * @warning Freeing while in use by poll or timer callbacks leads to crashes;
 * remove from loops first.
 * @warning FD is closed on free; do not use raw fd after free.
 *
 * ## Example Declaration and Use
 *
 * @code{.c}
 * typedef struct SocketDgram_T *SocketDgram_T;  // Opaque pointer
 * SocketDgram_T sock;  // Declare
 * sock = SocketDgram_new(...);  // Initialize
 * // Accessors: SocketDgram_fd(sock), SocketDgram_getlocaladdr(sock)
 * SocketDgram_free(&sock);  // Cleanup
 * @endcode
 *
 * @complexity Accessors O(1); creation O(1)
 *
 * @see SocketBase_T base class for common fields (FD, flags)
 * @see SocketDgram_new() / SocketDgram_free() lifecycle functions
 * @see SocketDgram_fd() for underlying descriptor
 * @see SocketDgram_isbound() / SocketDgram_isconnected() state queries
 * @see @ref socket_dgram for full API
 * @see docs/MODULE-PATTERNS.md for opaque type patterns
 */
typedef struct T *T;

/* Exception types */
/**
 * @brief Exception type for general failures in datagram socket operations.
 * @ingroup socket_dgram
 *
 * This is the primary exception raised by SocketDgram functions for errors
 * such as:
 * - System call failures (bind, connect, sendto, etc.)
 * - Invalid parameters (null pointers, invalid ports, buffer overflows)
 * - Resource exhaustion (out of FDs, memory)
 * - Protocol violations (e.g., invalid multicast address)
 *
 * It wraps errno and provides context via Socket_GetLastError() for
 * diagnostics. Use in EXCEPT blocks to catch and handle specific conditions,
 * or SocketError_categorize_errno() to classify as retryable/transient vs
 * permanent.
 *
 * Hierarchy: Extends Except_T base with module-specific message formatting.
 * Thread-local stack via Except_stack for propagation.
 *
 * Best practice: Catch in FINALLY-free patterns; log with SOCKET_LOG_ERROR_MSG
 * including errno.
 *
 * ## Handling Example
 *
 * @code{.c}
 * TRY {
 *     SocketDgram_T sock = SocketDgram_new(AF_INET, 0);
 *     SocketDgram_bind(sock, NULL, 80);  // May fail without root
 * } EXCEPT(SocketDgram_Failed) {
 *     int err = Socket_geterrno();
 *     const char *msg = Socket_GetLastError();
 *     SOCKET_LOG_ERROR_MSG("Datagram error: %s (errno=%d)", msg, err);
 *     if (SocketError_is_retryable_errno(err)) {
 *         // Retry logic
 *     } else {
 *         // Fatal error handling
 *     }
 * } END_TRY;
 * @endcode
 *
 * @note Message includes file/line/context from raise site for debugging.
 * @warning Suppress only in cleanup; always log for production monitoring.
 *
 * @see Except_T base exception type and TRY/EXCEPT syntax.
 * @see Socket_GetLastError() / Socket_geterrno() for details.
 * @see SocketError_is_retryable_errno() for classification.
 * @see docs/ERROR_HANDLING.md for comprehensive guide.
 * @see docs/LOGGING.md for logging integration.
 */
extern const Except_T SocketDgram_Failed;

/**
 * @brief Create a new UDP/datagram socket with specified domain and protocol.
 * @ingroup socket_dgram
 *
 * Creates and initializes a new datagram socket using the underlying socket()
 * system call. The socket is created in blocking mode by default, unbound, and
 * unconnected. It supports standard socket options and inherits OS defaults
 * for buffers and TTL. Automatic handling of SIGPIPE and EINTR ensures robust
 * operation in multi-threaded environments. Exception-based error handling
 * simplifies code by eliminating manual errno checks.
 *
 * Edge cases and considerations:
 * - Invalid domain/protocol combinations may fail immediately.
 * - System resource limits (e.g., max open files via ulimit -n) can cause
 * failures.
 * - For AF_UNIX, ensure the path directory exists and has write permissions.
 * - IPv6 sockets can handle IPv4 mappings if V6_V6ONLY is not set (default
 * behavior).
 *
 * Typical usage patterns include creating a server socket for recvfrom loops
 * or a client socket for sendto with optional connect for optimized repeated
 * sends.
 *
 * @param[in] domain Address family specifying the protocol family.
 *   Common values: AF_INET (IPv4), AF_INET6 (IPv6), AF_UNIX (Unix domain
 * datagrams).
 * @param[in] protocol Protocol number within the domain. Usually 0 to
 * auto-select IPPROTO_UDP for SOCK_DGRAM type (implicit).
 *
 * @return A new opaque SocketDgram_T handle representing the created socket.
 *
 * @throws SocketDgram_Failed If the socket creation fails, typically due to:
 *   - EACCES: Insufficient privileges (e.g., binding privileged ports <1024
 * without root)
 *   - EMFILE: Process file descriptor limit exceeded
 *   - ENFILE: System-wide file descriptor limit exceeded
 *   - ENOMEM: Insufficient memory for socket structures
 *   - EPROTONOSUPPORT: Specified protocol not supported
 *   - Other system errors mapped via internal SocketError_categorize_errno()
 *   Use Socket_GetLastError() post-exception for detailed message and errno.
 *
 * @threadsafe Yes - Each call creates an independent socket instance with no
 * shared state. Safe to invoke concurrently from multiple threads.
 *
 * ## Basic Usage
 *
 * @code{.c}
 * TRY {
 *     SocketDgram_T sock = SocketDgram_new(AF_INET, 0);  // IPv4 UDP socket
 *     if (sock) {
 *         SocketDgram_bind(sock, "0.0.0.0", 0);  // Bind to ephemeral port
 *         // Use sock for sendto/recvfrom
 *     }
 * } EXCEPT(SocketDgram_Failed) {
 *     SOCKET_LOG_ERROR_MSG("Socket creation failed: %s",
 * Socket_GetLastError());
 *     // Handle (e.g., retry, exit)
 * } FINALLY {
 *     SocketDgram_free(&sock);
 * } END_TRY;
 * @endcode
 *
 * ## Advanced Usage: IPv6 Multicast Receiver
 *
 * @code{.c}
 * TRY {
 *     SocketDgram_T sock = SocketDgram_new(AF_INET6, 0);
 *     SocketDgram_setreuseaddr(sock);
 *     SocketDgram_setreuseport(sock);  // Allow multiple instances on same
 * port SocketDgram_bind(sock, "::", 5353);  // Bind to IPv6 any, mDNS port
 *     SocketDgram_joinmulticast(sock, "ff02::fb", "::");  // Join mDNS group
 * on default interface SocketDgram_setttl(sock, 255);  // Full network reach
 *     SocketDgram_setnonblocking(sock);  // For SocketPoll integration
 *     // Add to SocketPoll_add(poll, sock, POLL_READ, userdata);
 * } EXCEPT(SocketDgram_Failed) {
 *     // Error handling with logging
 * } END_TRY;
 * @endcode
 *
 * @note The protocol parameter defaults to IPPROTO_UDP when 0 and domain
 * supports it. Specify explicitly for custom protocols (e.g., IPPROTO_SCTP for
 * SCTP datagrams).
 * @note Newly created sockets have SO_REUSEADDR disabled, blocking mode
 * enabled, and default buffer sizes (tunable via
 * getsockopt/SocketDgram_getrcvbuf).
 * @warning Do not use large datagrams (>64KB) as they may fail or fragment
 * unpredictably.
 * @warning For security, always validate parameters; user input should be
 * sanitized before passing.
 * @warning In production, monitor SocketDgram_debug_live_count() in tests to
 * ensure no leaks.
 *
 * @complexity O(1) - Involves a single socket() system call plus minimal
 * initialization.
 *
 * @see SocketDgram_free() for destruction and FD close.
 * @see SocketDgram_bind() to associate with local address/port.
 * @see SocketDgram_connect() to set default peer for send/recv optimization.
 * @see SocketDgram_setnonblocking() for asynchronous operation.
 * @see SocketDgram_setreuseaddr() / SocketDgram_setreuseport() for binding
 * options.
 * @see Socket_T::Socket_new() counterpart for stream sockets.
 * @see SocketPoll_T::SocketPoll_add() for event loop integration.
 * @see SocketDNS_resolve_sync() for resolving hostnames before connect/bind.
 * @see docs/ERROR_HANDLING.md for advanced exception patterns.
 * @see docs/SECURITY.md for socket permission and firewall considerations.
 */
extern T SocketDgram_new (int domain, int protocol);

/**
 * @brief Dispose of a datagram socket, closing the underlying file descriptor
 * and freeing resources.
 * @ingroup socket_dgram
 *
 * This function closes the socket FD using close() system call, releases any
 * internal state, and sets the pointer to NULL to prevent use-after-free. It
 * is idempotent if called on NULL. Any pending operations (e.g., in-flight
 * sends) may complete or fail depending on OS. Always pair with
 * SocketDgram_new() in TRY/FINALLY for resource safety.
 *
 * Edge cases:
 * - Calling on NULL pointer is safe (no-op).
 * - If socket is in use by another thread, behavior is undefined (POSIX not
 * thread-safe for close).
 * - Unclosed multicast memberships are automatically left by kernel on close.
 *
 * @param[in,out] socket Pointer to the SocketDgram_T handle. Set to NULL on
 * success.
 *
 * @return Void - no return value; errors during close are logged but not
 * raised (to avoid complicating cleanup).
 *
 * @throws None - Designed for FINALLY blocks; suppresses exceptions during
 * disposal.
 *
 * @threadsafe Conditional - Safe if no concurrent use of this socket instance.
 * Caller must ensure exclusive access or use mutex. Idempotent for NULL.
 *
 * ## Basic Usage
 *
 * @code{.c}
 * SocketDgram_T sock = NULL;
 * TRY {
 *     sock = SocketDgram_new(AF_INET, 0);
 *     // ... use sock ...
 * } EXCEPT(SocketDgram_Failed) {
 *     // handle
 * } FINALLY {
 *     SocketDgram_free(&sock);  // Always call, even on error or NULL
 * } END_TRY;
 * @endcode
 *
 * ## In Pool or Array Management
 *
 * @code{.c}
 * SocketDgram_T sockets[10] = {0};
 * // ... populate some sockets ...
 * for (int i = 0; i < 10; i++) {
 *     SocketDgram_free(&sockets[i]);  // Safe for uninitialized (NULL)
 * }
 * @endcode
 *
 * @note Internal resources (e.g., buffers allocated from Arena) are freed if
 * associated.
 * @note Decrements global live count for leak detection in
 * SocketDgram_debug_live_count().
 * @warning Do not access socket after free; leads to undefined behavior
 * (double free, invalid FD).
 * @warning Close is not atomic; avoid calling while other threads read/write
 * the socket.
 *
 * @complexity O(1) - Single close() call and pointer cleanup.
 *
 * @see SocketDgram_new() for paired creation.
 * @see Arena_dispose() for arena cleanup if sockets use custom allocator.
 * @see SocketDgram_debug_live_count() for verifying all sockets freed in
 * tests.
 * @see docs/ERROR_HANDLING.md#finally-blocks for cleanup patterns.
 */
extern void SocketDgram_free (T *socket);

/**
 * @brief Bind a datagram socket to a local IP address and port.
 * @ingroup socket_dgram
 *
 * Associates the socket with a specific local endpoint using bind() system
 * call. Required for servers to receive datagrams (recvfrom). For clients,
 * optional but recommended for getting local port or SO_REUSEPORT load
 * balancing. Supports wildcard addresses (NULL or "0.0.0.0"::) to bind to all
 * interfaces. Performs DNS resolution if host is hostname, which may block.
 * Validates port (1-65535) and host format; raises on invalid input.
 *
 * Edge cases:
 * - Port 0 binds to ephemeral port (OS assigns available).
 * - Privileged ports (<1024) require root or CAP_NET_BIND_SERVICE.
 * - Already bound sockets raise error.
 * - Hostname resolution timeouts after system default (~30s); use IP for
 * speed.
 *
 * After bind, socket can receive on specified port; use isbound() to check.
 *
 * @param[in] socket The SocketDgram_T to bind (must be newly created, not
 * already bound).
 * @param[in] host Local IP address string ("127.0.0.1", "::1", "0.0.0.0" for
 * any) or hostname. NULL defaults to wildcard any-address.
 * @param[in] port Local port number: 0-65535, where 0 = ephemeral (recommended
 * for clients).
 *
 * @return Void on success.
 *
 * @throws SocketDgram_Failed On bind failure or validation errors, including:
 *   - EACCES/EADDRINUSE: Address/port in use or privileged port without perms
 *   - EADDRNOTAVAIL: Invalid host address
 *   - EINVAL: Invalid port (<0 or >65535) or already bound
 *   - ENETDOWN: Network interface down
 *   - getaddrinfo failure for hostnames (ENOMEM, HOST_NOT_FOUND)
 *   Log and retry or fallback to ephemeral port.
 *
 * @threadsafe Conditional - Safe if socket not concurrently accessed.
 * Bind is not reentrant on same socket; synchronize if multi-threaded init.
 *
 * ## Basic Usage: Server Bind
 *
 * @code{.c}
 * TRY {
 *     SocketDgram_T sock = SocketDgram_new(AF_INET, 0);
 *     SocketDgram_bind(sock, NULL, 12345);  // Bind to any IP, port 12345
 *     // Now recvfrom will receive on port 12345
 * } EXCEPT(SocketDgram_Failed) {
 *     // Handle bind failure (e.g., port in use)
 * } FINALLY {
 *     SocketDgram_free(&sock);
 * } END_TRY;
 * @endcode
 *
 * ## Client Bind to Ephemeral Port with Reuse
 *
 * @code{.c}
 * TRY {
 *     SocketDgram_T sock = SocketDgram_new(AF_INET6, 0);
 *     SocketDgram_setreuseaddr(sock);  // Allow reuse if port busy
 *     SocketDgram_bind(sock, "::", 0);  // Ephemeral port, all IPv6 interfaces
 *     int local_port = SocketDgram_getlocalport(sock);  // Query assigned port
 *     SOCKET_LOG_INFO_MSG("Bound to port %d", local_port);
 * } EXCEPT(SocketDgram_Failed) {
 *     // Fallback to unbind mode if needed
 * } END_TRY;
 * @endcode
 *
 * @note Wildcard bind (NULL host) receives from any interface; specify IP for
 * specific NIC.
 * @note For IPv6, "::" binds to all; use specific [2001:db8::1] for scoped.
 * @warning DNS resolution in host can block; resolve beforehand with
 * getaddrinfo or SocketDNS.
 * @warning Binding privileged ports requires elevated privileges; catch EACCES
 * and fallback.
 * @warning Multiple binds to same port possible with SO_REUSEPORT (load
 * balance).
 *
 * @complexity O(1) average - bind() syscall + optional getaddrinfo (O(n) for
 * DNS)
 *
 * @see SocketDgram_new() prerequisite creation.
 * @see SocketDgram_isbound() to verify binding success.
 * @see SocketDgram_getlocaladdr() / SocketDgram_getlocalport() query bound
 * endpoint.
 * @see SocketDgram_setreuseaddr() / SocketDgram_setreuseport() options for
 * reuse.
 * @see SocketDgram_connect() complementary for remote endpoint.
 * @see getaddrinfo(3) for address resolution details.
 * @see docs/SECURITY.md#privileged-ports for permission advice.
 * @see docs/ERROR_HANDLING.md for bind-specific errors.
 */
extern void SocketDgram_bind (T socket, const char *host, int port);

/**
 * @ingroup socket_dgram
 * @brief Set default destination for socket.
 * @param socket Socket to connect.
 * @param host Remote IP address or hostname.
 * @param port Remote port.
 * @throws SocketDgram_Failed on error.
 * @warning This function may block during DNS resolution if hostname is
 * provided.
 * @note "Connect" for UDP means setting a default destination. After
 * connecting, you can use send/recv instead of sendto/recvfrom.
 * @note The socket only accepts packets from the connected address. You can
 * still use sendto/recvfrom to override the default destination.
 * @see SocketDgram_bind() for binding to a local address.
 * @see SocketDgram_send() for sending to connected destination.
 */
extern void SocketDgram_connect (T socket, const char *host, int port);

/**
 * @ingroup socket_dgram
 * @brief Send datagram to specific address.
 * @param socket Socket to send from.
 * @param buf Data to send.
 * @param len Length of data (must be > 0).
 * @param host Destination IP address or hostname.
 * @param port Destination port.
 * @return Number of bytes sent (> 0), or 0 if would block
 * (EAGAIN/EWOULDBLOCK).
 * @throws SocketDgram_Failed on error.
 * @warning This function may block during DNS resolution if hostname is
 * provided.
 * @note UDP sends complete datagrams. If len > MTU, fragmentation may occur.
 * @note Recommended to keep len <= 1472 bytes to avoid fragmentation (1500 MTU
 * - headers).
 * @note Unlike TCP, send may return less than len only on would-block, not
 * partial sends.
 * @see SocketDgram_recvfrom() for receiving datagrams.
 * @see SocketDgram_connect() for setting default destination.
 */
extern ssize_t SocketDgram_sendto (T socket, const void *buf, size_t len,
                                   const char *host, int port);

/**
 * @ingroup socket_dgram
 * @brief Receive datagram and get sender address.
 * @param socket Socket to receive from.
 * @param buf Buffer for received data.
 * @param len Buffer size (must be > 0).
 * @param host Output - sender IP address (buffer must be >= 46 bytes for
 * IPv6).
 * @param host_len Size of host buffer.
 * @param port Output - sender port number.
 * @return Number of bytes received (> 0), or 0 if would block
 * (EAGAIN/EWOULDBLOCK).
 * @throws SocketDgram_Failed on error.
 * @note UDP is message-oriented. If buffer is too small, data is truncated.
 * @note Recommended buffer size >= 65507 bytes (max UDP payload) to avoid
 * truncation.
 * @note Common buffer sizes: 8192 (8KB), 65536 (64KB).
 * @note The host parameter receives the sender's IP address as a string.
 * @note The port parameter receives the sender's port number.
 * @see SocketDgram_sendto() for sending datagrams.
 * @see SocketDgram_recv() for receiving from connected sockets.
 */
extern ssize_t SocketDgram_recvfrom (T socket, void *buf, size_t len,
                                     char *host, size_t host_len, int *port);

/**
 * @ingroup socket_dgram
 * @brief Send to default destination (connected socket).
 * @param socket Connected socket.
 * @param buf Data to send.
 * @param len Length of data (must be > 0).
 * @return Number of bytes sent (> 0), or 0 if would block
 * (EAGAIN/EWOULDBLOCK).
 * @throws SocketDgram_Failed on error.
 * @note Socket must be connected via SocketDgram_connect() first.
 * @see SocketDgram_recv() for receiving from connected sockets.
 * @see SocketDgram_sendto() for sending to arbitrary addresses.
 */
extern ssize_t SocketDgram_send (T socket, const void *buf, size_t len);

/**
 * @ingroup socket_dgram
 * @brief Receive from default source (connected socket).
 * @param socket Connected socket.
 * @param buf Buffer for received data.
 * @param len Buffer size (must be > 0).
 * @return Number of bytes received (> 0), or 0 if would block
 * (EAGAIN/EWOULDBLOCK).
 * @throws SocketDgram_Failed on error.
 * @note Socket must be connected via SocketDgram_connect() first. Only accepts
 * packets from the connected address.
 * @see SocketDgram_send() for sending to connected sockets.
 * @see SocketDgram_recvfrom() for receiving with sender info.
 */
extern ssize_t SocketDgram_recv (T socket, void *buf, size_t len);

/**
 * @ingroup socket_dgram
 * @brief Send all data (handles partial sends).
 * @param socket Connected socket.
 * @param buf Data to send.
 * @param len Length of data (> 0).
 * @return Total bytes sent (always equals len on success).
 * @throws SocketDgram_Failed on error.
 * @threadsafe Yes (operates on single socket).
 * @note Loops until all data is sent or an error occurs.
 * @note For non-blocking sockets, returns 0 if would block
 * (EAGAIN/EWOULDBLOCK).
 * @note Use SocketDgram_isconnected() to verify connection state before
 * calling.
 * @see SocketDgram_send() for partial send operations.
 * @see SocketDgram_recvall() for receiving all data.
 */
extern ssize_t SocketDgram_sendall (T socket, const void *buf, size_t len);

/**
 * @ingroup socket_dgram
 * @brief Receive all requested data (handles partial receives).
 * @param socket Connected socket.
 * @param buf Buffer for received data.
 * @param len Buffer size (> 0).
 * @return Total bytes received (always equals len on success).
 * @throws SocketDgram_Failed on error.
 * @threadsafe Yes (operates on single socket).
 * @note Loops until len bytes are received or an error occurs.
 * @note For non-blocking sockets, returns 0 if would block
 * (EAGAIN/EWOULDBLOCK).
 * @note Use SocketDgram_isconnected() to verify connection state before
 * calling.
 * @see SocketDgram_recv() for partial receive operations.
 * @see SocketDgram_sendall() for sending all data.
 */
extern ssize_t SocketDgram_recvall (T socket, void *buf, size_t len);

/**
 * @ingroup socket_dgram
 * @brief Scatter/gather send (writev wrapper).
 * @param socket Connected socket.
 * @param iov Array of iovec structures.
 * @param iovcnt Number of iovec structures (> 0, <= IOV_MAX).
 * @return Total bytes sent (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK).
 * @throws SocketDgram_Failed on error.
 * @threadsafe Yes (operates on single socket).
 * @note Sends data from multiple buffers in a single system call.
 * @note May send less than requested. Use SocketDgram_sendvall() for
 * guaranteed complete send.
 * @see SocketDgram_recvv() for scatter/gather receive.
 * @see SocketDgram_sendvall() for guaranteed complete scatter/gather send.
 */
extern ssize_t SocketDgram_sendv (T socket, const struct iovec *iov,
                                  int iovcnt);

/**
 * @ingroup socket_dgram
 * @brief Scatter/gather receive (readv wrapper).
 * @param socket Connected socket.
 * @param iov Array of iovec structures.
 * @param iovcnt Number of iovec structures (> 0, <= IOV_MAX).
 * @return Total bytes received (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK).
 * @throws SocketDgram_Failed on error.
 * @threadsafe Yes (operates on single socket).
 * @note Receives data into multiple buffers in a single system call.
 * @note May receive less than requested. Use SocketDgram_recvvall() for
 * guaranteed complete receive.
 * @see SocketDgram_sendv() for scatter/gather send.
 * @see SocketDgram_recvvall() for guaranteed complete scatter/gather receive.
 */
extern ssize_t SocketDgram_recvv (T socket, struct iovec *iov, int iovcnt);

/**
 * @ingroup socket_dgram
 * @brief Scatter/gather send all (handles partial sends).
 * @param socket Connected socket.
 * @param iov Array of iovec structures.
 * @param iovcnt Number of iovec structures (> 0, <= IOV_MAX).
 * @return Total bytes sent (always equals sum of all iov_len on success).
 * @throws SocketDgram_Failed on error.
 * @threadsafe Yes (operates on single socket).
 * @note Loops until all data from all buffers is sent or an error occurs.
 * @note For non-blocking sockets, returns partial progress if would block.
 * @note Use SocketDgram_isconnected() to verify connection state before
 * calling.
 * @see SocketDgram_sendv() for partial scatter/gather send.
 * @see SocketDgram_recvvall() for receiving all scatter/gather data.
 */
extern ssize_t SocketDgram_sendvall (T socket, const struct iovec *iov,
                                     int iovcnt);

/**
 * @ingroup socket_dgram
 * @brief Scatter/gather receive all (handles partial receives).
 * @param socket Connected socket.
 * @param iov Array of iovec structures.
 * @param iovcnt Number of iovec structures (> 0, <= IOV_MAX).
 * @return Total bytes received (always equals sum of all iov_len on success).
 * @throws SocketDgram_Failed on error.
 * @threadsafe Yes (operates on single socket).
 * @note Loops until all requested data is received into all buffers or an
 * error occurs.
 * @note For non-blocking sockets, returns partial progress if would block.
 * @note Use SocketDgram_isconnected() to verify connection state before
 * calling.
 * @see SocketDgram_recvv() for partial scatter/gather receive.
 * @see SocketDgram_sendvall() for sending all scatter/gather data.
 */
extern ssize_t SocketDgram_recvvall (T socket, struct iovec *iov, int iovcnt);

/**
 * @ingroup socket_dgram
 * @brief Enable non-blocking mode.
 * @param socket Socket to modify.
 * @throws SocketDgram_Failed on error.
 * @see SocketDgram_setreuseaddr() for address reuse.
 * @see Socket_bind() for binding operations.
 */
extern void SocketDgram_setnonblocking (T socket);

/**
 * @ingroup socket_dgram
 * @brief Enable address reuse.
 * @param socket Socket to modify.
 * @throws SocketDgram_Failed on error.
 * @see SocketDgram_setreuseport() for port reuse.
 * @see SocketDgram_bind() for binding operations.
 */
extern void SocketDgram_setreuseaddr (T socket);

/**
 * @ingroup socket_dgram
 * @brief Enable port reuse across sockets.
 * @param socket Socket to modify.
 * @throws SocketDgram_Failed on error (or if SO_REUSEPORT unsupported).
 * @see SocketDgram_setreuseaddr() for address reuse.
 * @see Socket_bind() for binding operations.
 */
extern void SocketDgram_setreuseport (T socket);

/**
 * @ingroup socket_dgram
 * @brief Enable broadcast.
 * @param socket Socket to modify.
 * @param enable 1 to enable, 0 to disable.
 * @throws SocketDgram_Failed on error.
 * @note Required to send broadcast datagrams to 255.255.255.255 or subnet
 * broadcast addresses.
 * @see SocketDgram_joinmulticast() for multicast operations.
 * @see SocketDgram_sendto() for sending broadcast datagrams.
 */
extern void SocketDgram_setbroadcast (T socket, int enable);

/**
 * @ingroup socket_dgram
 * @brief Join multicast group.
 * @param socket Socket to modify.
 * @param group Multicast group address (e.g., "224.0.0.1" for IPv4).
 * @param interface Interface address or NULL for default.
 * @throws SocketDgram_Failed on error.
 * @note For IPv4, group should be in range 224.0.0.0 - 239.255.255.255.
 * @note For IPv6, group should start with ff00::/8.
 * @see SocketDgram_leavemulticast() for leaving multicast groups.
 * @see SocketDgram_setttl() for controlling multicast reach.
 */
extern void SocketDgram_joinmulticast (T socket, const char *group,
                                       const char *interface);

/**
 * @ingroup socket_dgram
 * @brief Leave multicast group.
 * @param socket Socket to modify.
 * @param group Multicast group address.
 * @param interface Interface address or NULL for default.
 * @throws SocketDgram_Failed on error.
 * @see SocketDgram_joinmulticast() for joining multicast groups.
 */
extern void SocketDgram_leavemulticast (T socket, const char *group,
                                        const char *interface);

/**
 * @ingroup socket_dgram
 * @brief Set time-to-live (hop limit).
 * @param socket Socket to modify.
 * @param ttl TTL value (1-255).
 * @throws SocketDgram_Failed on error.
 * @note TTL controls how many network hops a packet can traverse.
 * @note Default is usually 64. Use 1 for link-local only.
 * @see SocketDgram_joinmulticast() for multicast group operations.
 * @see SocketDgram_sendto() for sending datagrams.
 */
extern void SocketDgram_setttl (T socket, int ttl);

/**
 * @ingroup socket_dgram
 * @brief Set socket timeout.
 * @param socket Socket to modify.
 * @param timeout_sec Timeout in seconds (0 to disable).
 * @throws SocketDgram_Failed on error.
 * @note Sets receive timeout to prevent blocking indefinitely.
 * @note Useful for signal-responsive servers. With timeout, recvfrom returns 0
 * (would-block) after timeout.
 * @note Allows the event loop to check for shutdown signals.
 * @see SocketDgram_gettimeout() for retrieving the current timeout.
 * @see SocketDgram_recvfrom() for timeout behavior.
 */
extern void SocketDgram_settimeout (T socket, int timeout_sec);

/**
 * @ingroup socket_dgram
 * @brief Get socket timeout.
 * @param socket Socket to query.
 * @return Timeout in seconds (0 if disabled).
 * @throws SocketDgram_Failed on error.
 * @note Returns receive timeout (send timeout may differ).
 * @see SocketDgram_settimeout() for setting the timeout.
 */
extern int SocketDgram_gettimeout (T socket);

/**
 * @ingroup socket_dgram
 * @brief Get broadcast setting.
 * @param socket Socket to query.
 * @return 1 if broadcast is enabled, 0 if disabled.
 * @throws SocketDgram_Failed on error.
 * @see SocketDgram_setbroadcast() for setting broadcast mode.
 */
extern int SocketDgram_getbroadcast (T socket);

/**
 * @ingroup socket_dgram
 * @brief Get time-to-live (hop limit).
 * @param socket Socket to query.
 * @return TTL value (1-255).
 * @throws SocketDgram_Failed on error.
 * @see SocketDgram_setttl() for setting TTL.
 */
extern int SocketDgram_getttl (T socket);

/**
 * @ingroup socket_dgram
 * @brief Get receive buffer size.
 * @param socket Socket to query.
 * @return Receive buffer size in bytes.
 * @throws SocketDgram_Failed on error.
 * @see SocketDgram_getsndbuf() for send buffer size.
 */
extern int SocketDgram_getrcvbuf (T socket);

/**
 * @ingroup socket_dgram
 * @brief Get send buffer size.
 * @param socket Socket to query.
 * @return Send buffer size in bytes.
 * @throws SocketDgram_Failed on error.
 * @see SocketDgram_getrcvbuf() for receive buffer size.
 */
extern int SocketDgram_getsndbuf (T socket);

/**
 * @ingroup socket_dgram
 * @brief Check if datagram socket is connected.
 * @param socket Socket to check.
 * @return 1 if connected, 0 if not connected.
 * @threadsafe Yes (operates on single socket).
 * @note Uses getpeername() to determine connection state.
 * @note For UDP sockets, "connected" means a default destination is set.
 * @see SocketDgram_connect() for connecting sockets.
 * @see SocketDgram_isbound() for checking binding state.
 */
extern int SocketDgram_isconnected (T socket);

/**
 * @ingroup socket_dgram
 * @brief Check if datagram socket is bound to an address.
 * @param socket Socket to check.
 * @return 1 if bound, 0 if not bound.
 * @threadsafe Yes (operates on single socket).
 * @note Uses getsockname() to determine binding state.
 * @note A socket is bound if getsockname() succeeds and returns a valid
 * address.
 * @note Wildcard addresses (0.0.0.0 or ::) still count as bound.
 * @see SocketDgram_bind() for binding sockets.
 * @see SocketDgram_isconnected() for checking connection state.
 */
extern int SocketDgram_isbound (T socket);

/**
 * @ingroup socket_dgram
 * @brief Get underlying file descriptor.
 * @param socket Socket instance.
 * @return File descriptor.
 * @see Socket_fd() for TCP socket file descriptors.
 */
extern int SocketDgram_fd (const T socket);

/**
 * @ingroup socket_dgram
 * @brief Get local IP address.
 * @param socket Socket instance.
 * @return IP address string (IPv4/IPv6) or "(unknown)" if unavailable.
 * @note Returns "(unknown)" if address info unavailable. String is owned by
 * socket, must not be freed/modified.
 * @note Valid until socket freed.
 * @see SocketDgram_getlocalport() for local port.
 * @see SocketDgram_bind() for binding operations.
 */
extern const char *SocketDgram_getlocaladdr (const T socket);

/**
 * @ingroup socket_dgram
 * @brief Get local port number.
 * @param socket Socket instance.
 * @return Port number (1 to SOCKET_MAX_PORT) or 0 if unavailable.
 * @see SocketDgram_getlocaladdr() for local address.
 * @see SocketDgram_bind() for binding operations.
 */
extern int SocketDgram_getlocalport (const T socket);

/**
 * @ingroup socket_dgram
 * @brief Control close-on-exec flag.
 * @param socket Socket to modify.
 * @param enable 1 to enable CLOEXEC, 0 to disable.
 * @throws SocketDgram_Failed on error.
 * @threadsafe Yes (operates on single socket).
 * @note By default, all sockets have CLOEXEC enabled. This function allows
 * disabling it if you need to pass the socket to a child process.
 * @see Socket_setcloexec() for TCP socket CLOEXEC control.
 */
extern void SocketDgram_setcloexec (T socket, int enable);

/**
 * @ingroup socket_dgram
 * @brief Get number of live datagram socket instances.
 * @return Number of currently allocated SocketDgram instances.
 * @threadsafe Yes.
 * @note Test/debug function for leak detection. Returns count of sockets that
 * have been created but not yet freed.
 * @see Socket_debug_live_count() for TCP socket count.
 */
extern int SocketDgram_debug_live_count (void);

/* End SocketDgram group */

#undef T
#endif
