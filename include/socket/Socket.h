#ifndef SOCKET_INCLUDED
#define SOCKET_INCLUDED

/**
 * @defgroup core_io Core I/O Modules
 * @brief Fundamental socket operations for TCP, UDP, and Unix domain sockets.
 * @{
 * The Core I/O group provides the basic socket primitives used by all
 * higher-level networking modules. Key components include:
 * - Socket (tcp/unix): High-level TCP/Unix socket abstraction with I/O
 * operations
 * - SocketBuf (buffers): Circular buffer for efficient socket I/O
 * - SocketDgram (udp): UDP datagram sockets with multicast/broadcast support
 * - SocketDNS (dns): Asynchronous DNS resolution with worker threads
 * - SocketProxy (proxy): Transparent proxy tunneling for HTTP CONNECT and SOCKS protocols
 * - SocketIO (io): Low-level socket I/O primitives
 *
 * @see foundation for base infrastructure.
 * @see event_system for multiplexing built on core I/O.
 * @see Socket_T for TCP socket operations.
 * @see SocketDgram_T for UDP operations.
 */

/**
 * @file Socket.h
 * @ingroup core_io
 * @brief High-level TCP/IP and Unix domain socket interface.
 *
 * This header consolidates all socket operations including:
 * - Core socket creation and I/O
 * - State query functions
 * - Socket options configuration
 * - Async DNS operations
 * - Unix domain socket support
 *
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS, etc.)
 * - IPv6 support in kernel (for dual-stack sockets)
 * - POSIX threads (pthread) for thread-safe error reporting
 * - NOT portable to Windows without Winsock adaptation
 *
 * SIGPIPE HANDLING (automatic - no application action required):
 * The library handles SIGPIPE internally. All send operations use MSG_NOSIGNAL
 * (Linux/FreeBSD), and SO_NOSIGPIPE is set at socket creation (BSD/macOS).
 * Applications do NOT need to call signal(SIGPIPE, SIG_IGN).
 *
 * Error Handling:
 * - Socket_Failed: General socket errors
 * - Socket_Closed: Connection terminated by peer
 * - Some functions return NULL/0 for non-blocking EAGAIN/EWOULDBLOCK
 *
 * Timeouts:
 * - Global defaults configurable via Socket_timeouts_setdefaults()
 * - Per-socket overrides via Socket_timeouts_set()
 * - Applied to DNS resolution and blocking connect() paths
 *
 * @see Socket_new() for socket creation.
 * @see Socket_connect() for connection establishment.
 * @see Socket_send() and Socket_recv() for I/O operations.
 */

#include "core/Except.h"
#include "core/SocketConfig.h"
#include "dns/SocketDNS.h"
#include "socket/SocketCommon.h"

#define T Socket_T
/**
 * @ingroup core_io
 * @brief Opaque handle for TCP/IP and Unix domain sockets.
 *
 * This type represents a high-level abstraction over low-level socket file
 * descriptors, providing:
 * - Automatic SIGPIPE handling
 * - Non-blocking mode support
 * - Timeout configuration
 * - Bandwidth limiting
 * - Unix domain socket operations including fd passing
 * - Thread-safe state queries
 *
 * Sockets are created with Socket_new() or Socket_new_from_fd() and freed with
 * Socket_free(). All operations are exception-safe using Except_T.
 *
 * @note All sockets are created in blocking mode by default. Use
 * Socket_setnonblocking() to enable non-blocking I/O.
 *
 * @see SocketDgram_T for UDP/datagram sockets.
 * @see SocketBuf_T for buffering support.
 * @see SocketPool_T for connection pooling.
 * @see @ref event_system for event-driven I/O integration.
 * @see docs/ASYNC_IO.md for asynchronous patterns.
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
 * Category: NETWORK (usually) or PROTOCOL (configuration errors)
 * Retryable: Depends on errno - use Socket_error_is_retryable() to check
 *
 * Raised for:
 * - Socket creation failures (socket(), bind(), listen(), accept())
 * - Connection failures (connect())
 * - I/O failures (send(), recv())
 * - Option setting failures (setsockopt())
 *
 * Check errno via Socket_geterrno() for specific error code.
 *
 * @see Socket_error_is_retryable() for retryability checking.
 * @see Socket_geterrno() for errno access.
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
 * @brief Create a new socket.
 * @ingroup core_io
 * @param domain Address family (AF_INET, AF_INET6, etc.).
 * @param type Socket type (SOCK_STREAM, SOCK_DGRAM, etc.).
 * @param protocol Protocol (usually 0 for default).
 * @return New socket instance.
 * @throws Socket_Failed on error.
 * @threadsafe Yes - creates new socket without accessing shared resources.
 * @see Socket_free() for cleanup.
 * @see Socket_connect() for establishing connections.
 * @see Socket_bind() for server-side binding.
 */
extern T Socket_new (int domain, int type, int protocol);

/**
 * @brief Create a pair of connected Unix domain sockets.
 * @ingroup core_io
 * @param type Socket type (SOCK_STREAM or SOCK_DGRAM).
 * @param socket1 Output - first socket of the pair.
 * @param socket2 Output - second socket of the pair.
 * @throws Socket_Failed on error.
 * @threadsafe Yes - creates new sockets without modifying any shared state.
 * @note Creates two connected Unix domain sockets for IPC. Both sockets are ready to use - no bind/connect needed.
 * @see Socket_new() for individual socket creation.
 */
extern void SocketPair_new (int type, T *socket1, T *socket2);

/**
 * @brief Free a socket and close the connection.
 * @ingroup core_io
 * @param socket Pointer to socket (will be set to NULL on success).
 * @threadsafe Yes - operates only on the specified socket instance.
 * @note Closes the underlying file descriptor and frees resources.
 * @see Socket_new() for socket creation.
 * @see Socket_debug_live_count() for verifying no leaks in tests.
 */
extern void Socket_free (T *socket);

/**
 * @brief Create Socket_T from existing file descriptor.
 * @ingroup core_io
 * @param fd File descriptor (must be valid socket, will be set to non-blocking).
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
 * @brief Bind socket to address and port.
 * @ingroup core_io
 * @param socket Socket to bind.
 * @param host IP address or NULL/"0.0.0.0" for any.
 * @param port Port number (1 to SOCKET_MAX_PORT).
 * @throws Socket_Failed on error.
 * @warning May block 30+ seconds during DNS resolution if hostname provided.
 * @note For non-blocking operation, use IP addresses directly.
 * @see Socket_listen() for listening on bound sockets.
 * @see Socket_connect() for client-side connection.
 * @see @ref SocketDNS_T "Async DNS resolution" for non-blocking hostname resolution.
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
 * @brief Connect to remote host.
 * @ingroup core_io
 * @param socket Socket to connect.
 * @param host Remote IP address or hostname.
 * @param port Remote port.
 * @throws Socket_Failed on error.
 * @warning May block 30+ seconds during DNS resolution if hostname provided.
 * @note For non-blocking operation, use IP addresses directly.
 * @see Socket_bind() for binding to local addresses.
 * @see @ref SocketDNS_T "Async DNS resolution" for non-blocking hostname resolution.
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
 * @throws Socket_Closed on peer close or ECONNRESET, Socket_Failed on other errors.
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
 * @throws Socket_Closed on peer close or ECONNRESET, Socket_Failed on other errors.
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
 * @throws Socket_Closed on peer close or ECONNRESET, Socket_Failed on other errors.
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
 * @throws Socket_Closed on peer close or ECONNRESET, Socket_Failed on other errors.
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
 * @throws Socket_Closed on peer close or ECONNRESET, Socket_Failed on other errors.
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
 * @param timeout_sec Seconds to wait for data before completing accept (0 to disable, max platform-specific).
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
 * @threadsafe Yes - uses thread-local error buffers for safe concurrent operation.
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
 * @threadsafe Yes - uses thread-local error buffers for safe concurrent operation.
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
 * @threadsafe Yes - uses thread-local error buffers for safe concurrent operation.
 * @see Socket_recvfds() for receiving multiple descriptors.
 * @see Socket_sendfd() for sending single descriptor.
 */
extern int Socket_sendfds (T socket, const int *fds, size_t count);

/**
 * @brief Receive multiple file descriptors.
 * @ingroup core_io
 * @param socket Connected Unix domain socket (AF_UNIX).
 * @param fds Output array for received descriptors (must have max_count capacity).
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
 * @threadsafe Yes - uses thread-local error buffers for safe concurrent operation.
 * @see Socket_sendfds() for sending multiple descriptors.
 * @see Socket_recvfd() for receiving single descriptor.
 */
extern int Socket_recvfds (T socket, int *fds, size_t max_count,
                           size_t *received_count);

/**
 * @brief Bind Unix domain socket to a filesystem path.
 * @ingroup core_io
 * @internal
 * @param base The socket base structure containing the file descriptor and domain.
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
 * @threadsafe Conditional - safe if base fd is not shared across threads without locking.
 */
extern void SocketUnix_bind (SocketBase_T base, const char *path,
                             Except_T exc_type);

/**
 * @brief Connect Unix domain socket to a filesystem path.
 * @ingroup core_io
 * @internal
 * @param base The socket base structure containing the file descriptor and domain.
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
 * @threadsafe Conditional - safe if base fd is not shared across threads without locking.
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
