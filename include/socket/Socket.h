#ifndef SOCKET_INCLUDED
#define SOCKET_INCLUDED

/**
 * @defgroup core_io Core I/O Modules
 * @brief Fundamental socket operations for TCP, UDP, and Unix domain sockets.
 *
 * The Core I/O group provides the basic socket primitives used by all
 * higher-level networking modules. Key components include:
 * - Socket (tcp/unix): High-level TCP/Unix socket abstraction with I/O
 * operations
 * - SocketBuf (buffers): Circular buffer for efficient socket I/O
 * - SocketDgram (udp): UDP datagram sockets with multicast/broadcast support
 * - SocketDNS (dns): Asynchronous DNS resolution with worker threads
 * - SocketIO (io): Low-level socket I/O primitives
 *
 * @see foundation for base infrastructure.
 * @see event_system for multiplexing built on core I/O.
 * @see Socket_T for TCP socket operations.
 * @see SocketDgram_T for UDP operations.
 * @{
 */

/**
 * @file Socket.h
 * @ingroup core_io
 * @brief High-level TCP/IP and Unix domain socket interface.
 *
 * @brief High-level, exception-based TCP/IP/Unix domain socket interface.
 * @ingroup core_io
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
 * @brief SocketUnix_Failed - Unix domain socket operation failure
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
 * @err: errno value to check
 *
 * Returns: 1 if error is typically retryable, 0 if fatal
 * @note Thread-safe: Yes (pure function)
 * @ingroup core_io
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
 * @brief Socket_new - Create a new socket
 * @ingroup core_io
 * @domain: Address family (AF_INET, AF_INET6, etc.)
 * @type: Socket type (SOCK_STREAM, SOCK_DGRAM, etc.)
 * @protocol: Protocol (usually 0 for default)
 * Returns: New socket instance
 * Raises: Socket_Failed on error
 */
extern T Socket_new (int domain, int type, int protocol);

/**
 * @brief SocketPair_new - Create a pair of connected Unix domain sockets
 * @ingroup core_io
 * @type: Socket type (SOCK_STREAM or SOCK_DGRAM)
 * @socket1: Output - first socket of the pair
 * @socket2: Output - second socket of the pair
 * Raises: Socket_Failed on error
 * @note Thread-safe: Yes (creates new sockets)
 * @ingroup core_io
 * Note: Creates two connected Unix domain sockets for IPC.
 * Both sockets are ready to use - no bind/connect needed.
 */
extern void SocketPair_new (int type, T *socket1, T *socket2);

/**
 * @brief Socket_free - Free a socket and close the connection
 * @ingroup core_io
 * @socket: Pointer to socket (will be set to NULL)
 */
extern void Socket_free (T *socket);

/**
 * @brief Socket_new_from_fd - Create Socket_T from existing file descriptor
 * @ingroup core_io
 * @fd: File descriptor (must be valid socket, will be set to non-blocking)
 * Returns: New Socket_T instance or NULL on failure
 * Raises: Socket_Failed on error
 * @note Thread-safe: Yes - returns new instance
 * @ingroup core_io
 */
extern T Socket_new_from_fd (int fd);

/**
 * @brief Socket_debug_live_count - Get number of live socket instances (test-only)
 * @ingroup core_io
 * Returns: Current count of allocated Socket_T instances
 */
extern int Socket_debug_live_count (void);

/* ============================================================================
 * Connection Operations
 * ============================================================================
 */

/**
 * @brief Socket_bind - Bind socket to address and port
 * @ingroup core_io
 * @socket: Socket to bind
 * @host: IP address or NULL/"0.0.0.0" for any
 * @port: Port number (1 to SOCKET_MAX_PORT)
 * WARNING: May block 30+ seconds during DNS resolution if hostname provided.
 * Raises: Socket_Failed on error
 */
extern void Socket_bind (T socket, const char *host, int port);

/**
 * @brief Socket_listen - Listen for incoming connections
 * @ingroup core_io
 * @socket: Bound socket
 * @backlog: Maximum pending connections
 * Raises: Socket_Failed on error
 */
extern void Socket_listen (T socket, int backlog);

/**
 * @brief Socket_accept - Accept incoming connection
 * @ingroup core_io
 * @socket: Listening socket
 * Returns: New socket or NULL if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Failed on error
 */
extern T Socket_accept (T socket);

/**
 * @brief Socket_connect - Connect to remote host
 * @ingroup core_io
 * @socket: Socket to connect
 * @host: Remote IP address or hostname
 * @port: Remote port
 * WARNING: May block 30+ seconds during DNS resolution if hostname provided.
 * Raises: Socket_Failed on error
 */
extern void Socket_connect (T socket, const char *host, int port);

/* ============================================================================
 * Basic I/O Operations
 * ============================================================================
 */

/**
 * @brief Socket_send - Send data
 * @ingroup core_io
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (> 0)
 * Returns: Bytes sent (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 */
extern ssize_t Socket_send (T socket, const void *buf, size_t len);

/**
 * @brief Socket_recv - Receive data
 * @ingroup core_io
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (> 0)
 * Returns: Bytes received (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on peer close or ECONNRESET, Socket_Failed on other
 */
extern ssize_t Socket_recv (T socket, void *buf, size_t len);

/**
 * @brief Socket_sendall - Send all data (handles partial sends)
 * @ingroup core_io
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (> 0)
 * Returns: Total bytes sent (always equals len on success)
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 */
extern ssize_t Socket_sendall (T socket, const void *buf, size_t len);

/**
 * @brief Socket_recvall - Receive all requested data (handles partial receives)
 * @ingroup core_io
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (> 0)
 * Returns: Total bytes received (always equals len on success)
 * Raises: Socket_Closed on peer close or ECONNRESET, Socket_Failed on other
 */
extern ssize_t Socket_recvall (T socket, void *buf, size_t len);

/* ============================================================================
 * Scatter/Gather I/O Operations
 * ============================================================================
 */

/**
 * @brief Socket_sendv - Scatter/gather send (writev wrapper)
 * @ingroup core_io
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes sent (> 0) or 0 if would block
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 */
extern ssize_t Socket_sendv (T socket, const struct iovec *iov, int iovcnt);

/**
 * @brief Socket_recvv - Scatter/gather receive (readv wrapper)
 * @ingroup core_io
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes received (> 0) or 0 if would block
 * Raises: Socket_Closed on peer close or ECONNRESET, Socket_Failed on other
 */
extern ssize_t Socket_recvv (T socket, struct iovec *iov, int iovcnt);

/**
 * @brief Socket_sendvall - Scatter/gather send all (handles partial sends)
 * @ingroup core_io
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes sent (always equals sum of all iov_len on success)
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 */
extern ssize_t Socket_sendvall (T socket, const struct iovec *iov, int iovcnt);

/**
 * @brief Socket_recvvall - Scatter/gather receive all (handles partial receives)
 * @ingroup core_io
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes received (always equals sum of all iov_len on success)
 * Raises: Socket_Closed on peer close or ECONNRESET, Socket_Failed on other
 */
extern ssize_t Socket_recvvall (T socket, struct iovec *iov, int iovcnt);

/* ============================================================================
 * Zero-Copy and Advanced I/O
 * ============================================================================
 */

/**
 * @brief Socket_sendfile - Zero-copy file-to-socket transfer
 * @ingroup core_io
 * @socket: Connected socket to send to
 * @file_fd: File descriptor to read from (must be a regular file)
 * @offset: File offset to start reading from (NULL for current position)
 * @count: Number of bytes to transfer (0 for entire file from offset)
 * Returns: Total bytes transferred (> 0) or 0 if would block
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 */
extern ssize_t Socket_sendfile (T socket, int file_fd, off_t *offset,
                                size_t count);

/**
 * @brief Socket_sendfileall - Zero-copy file-to-socket transfer (handles partial)
 * @ingroup core_io
 * @socket: Connected socket to send to
 * @file_fd: File descriptor to read from (must be a regular file)
 * @offset: File offset to start reading from (NULL for current position)
 * @count: Number of bytes to transfer (0 for entire file from offset)
 * Returns: Total bytes transferred (always equals count on success)
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 */
extern ssize_t Socket_sendfileall (T socket, int file_fd, off_t *offset,
                                   size_t count);

/**
 * @brief Socket_sendmsg - Send message with ancillary data (sendmsg wrapper)
 * @ingroup core_io
 * @socket: Connected socket
 * @msg: Message structure with data, address, and ancillary data
 * @flags: Message flags (MSG_NOSIGNAL, MSG_DONTWAIT, etc.)
 * Returns: Total bytes sent (> 0) or 0 if would block
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 */
extern ssize_t Socket_sendmsg (T socket, const struct msghdr *msg, int flags);

/**
 * @brief Socket_recvmsg - Receive message with ancillary data (recvmsg wrapper)
 * @ingroup core_io
 * @socket: Connected socket
 * @msg: Message structure for data, address, and ancillary data
 * @flags: Message flags (MSG_DONTWAIT, MSG_PEEK, etc.)
 * Returns: Total bytes received (> 0) or 0 if would block
 * Raises: Socket_Closed on peer close or ECONNRESET, Socket_Failed on other
 */
extern ssize_t Socket_recvmsg (T socket, struct msghdr *msg, int flags);

/* ============================================================================
 * Socket State Query Functions
 * ============================================================================
 */

/**
 * @brief Socket_isconnected - Check if socket is connected
 * @ingroup core_io
 * @socket: Socket to check
 * Returns: 1 if connected, 0 if not connected
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern int Socket_isconnected (T socket);

/**
 * @brief Socket_isbound - Check if socket is bound to an address
 * @ingroup core_io
 * @socket: Socket to check
 * Returns: 1 if bound, 0 if not bound
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern int Socket_isbound (T socket);

/**
 * @brief Socket_islistening - Check if socket is listening for connections
 * @ingroup core_io
 * @socket: Socket to check
 * Returns: 1 if listening, 0 if not listening
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern int Socket_islistening (T socket);

/**
 * @brief Socket_fd - Get underlying file descriptor
 * @ingroup core_io
 * @socket: Socket instance
 * Returns: File descriptor
 */
extern int Socket_fd (const T socket);

/**
 * @brief Socket_getpeeraddr - Get peer IP address
 * @ingroup core_io
 * @socket: Connected socket
 * Returns: IP address string (IPv4/IPv6) or "(unknown)" if unavailable
 * Note: String is owned by socket, valid until socket freed.
 */
extern const char *Socket_getpeeraddr (const T socket);

/**
 * @brief Socket_getpeerport - Get peer port number
 * @ingroup core_io
 * @socket: Connected socket
 * Returns: Port number (1 to SOCKET_MAX_PORT) or 0 if unavailable
 */
extern int Socket_getpeerport (const T socket);

/**
 * @brief Socket_getlocaladdr - Get local IP address
 * @ingroup core_io
 * @socket: Socket instance
 * Returns: IP address string (IPv4/IPv6) or "(unknown)" if unavailable
 * Note: String is owned by socket, valid until socket freed.
 */
extern const char *Socket_getlocaladdr (const T socket);

/**
 * @brief Socket_getlocalport - Get local port number
 * @ingroup core_io
 * @socket: Socket instance
 * Returns: Port number (1 to SOCKET_MAX_PORT) or 0 if unavailable
 */
extern int Socket_getlocalport (const T socket);

/* ============================================================================
 * Socket Options Configuration
 * ============================================================================
 */

/**
 * @brief Socket_setnonblocking - Enable non-blocking mode
 * @ingroup core_io
 * @socket: Socket to modify
 * Raises: Socket_Failed on error
 */
extern void Socket_setnonblocking (T socket);

/**
 * @brief Socket_setreuseaddr - Enable address reuse
 * @ingroup core_io
 * @socket: Socket to modify
 * Raises: Socket_Failed on error
 */
extern void Socket_setreuseaddr (T socket);

/**
 * @brief Socket_setreuseport - Enable port reuse across sockets
 * @ingroup core_io
 * @socket: Socket to modify
 * Raises: Socket_Failed on error (or if SO_REUSEPORT unsupported)
 */
extern void Socket_setreuseport (T socket);

/**
 * @brief Socket_settimeout - Set socket timeout
 * @ingroup core_io
 * @socket: Socket to modify
 * @timeout_sec: Timeout in seconds (0 to disable)
 * Sets both send and receive timeouts
 * Raises: Socket_Failed on error
 */
extern void Socket_settimeout (T socket, int timeout_sec);

/**
 * @brief Socket_setkeepalive - Enable TCP keepalive
 * @ingroup core_io
 * @socket: Socket to modify
 * @idle: Seconds before sending keepalive probes
 * @interval: Interval between keepalive probes
 * @count: Number of probes before declaring dead
 * Raises: Socket_Failed on error
 */
extern void Socket_setkeepalive (T socket, int idle, int interval, int count);

/**
 * @brief Socket_setnodelay - Disable Nagle's algorithm
 * @ingroup core_io
 * @socket: Socket to modify
 * @nodelay: 1 to disable Nagle, 0 to enable
 * Raises: Socket_Failed on error
 */
extern void Socket_setnodelay (T socket, int nodelay);

/**
 * @brief Socket_gettimeout - Get socket timeout
 * @ingroup core_io
 * @socket: Socket to query
 * Returns: Timeout in seconds (0 if disabled)
 * Raises: Socket_Failed on error
 */
extern int Socket_gettimeout (T socket);

/**
 * @brief Socket_getkeepalive - Get TCP keepalive configuration
 * @ingroup core_io
 * @socket: Socket to query
 * @idle: Output - idle timeout in seconds
 * @interval: Output - interval between probes in seconds
 * @count: Output - number of probes before declaring dead
 * Raises: Socket_Failed on error
 */
extern void Socket_getkeepalive (T socket, int *idle, int *interval,
                                 int *count);

/**
 * @brief Socket_getnodelay - Get TCP_NODELAY setting
 * @ingroup core_io
 * @socket: Socket to query
 * Returns: 1 if Nagle's algorithm is disabled, 0 if enabled
 * Raises: Socket_Failed on error
 */
extern int Socket_getnodelay (T socket);

/**
 * @brief Socket_getrcvbuf - Get receive buffer size
 * @ingroup core_io
 * @socket: Socket to query
 * Returns: Receive buffer size in bytes
 * Raises: Socket_Failed on error
 */
extern int Socket_getrcvbuf (T socket);

/**
 * @brief Socket_getsndbuf - Get send buffer size
 * @ingroup core_io
 * @socket: Socket to query
 * Returns: Send buffer size in bytes
 * Raises: Socket_Failed on error
 */
extern int Socket_getsndbuf (T socket);

/**
 * @brief Socket_setrcvbuf - Set receive buffer size
 * @ingroup core_io
 * @socket: Socket to modify
 * @size: Buffer size in bytes (> 0)
 * Raises: Socket_Failed on error
 */
extern void Socket_setrcvbuf (T socket, int size);

/**
 * @brief Socket_setsndbuf - Set send buffer size
 * @ingroup core_io
 * @socket: Socket to modify
 * @size: Buffer size in bytes (> 0)
 * Raises: Socket_Failed on error
 */
extern void Socket_setsndbuf (T socket, int size);

/**
 * @brief Socket_setcongestion - Set TCP congestion control algorithm
 * @ingroup core_io
 * @socket: Socket to modify
 * @algorithm: Algorithm name (e.g., "cubic", "reno", "bbr")
 * Raises: Socket_Failed on error or if not supported
 * Note: Only available on Linux 2.6.13+.
 */
extern void Socket_setcongestion (T socket, const char *algorithm);

/**
 * @brief Socket_getcongestion - Get TCP congestion control algorithm
 * @ingroup core_io
 * @socket: Socket to query
 * @algorithm: Output buffer for algorithm name
 * @len: Buffer length
 * Returns: 0 on success, -1 on error or if not supported
 */
extern int Socket_getcongestion (T socket, char *algorithm, size_t len);

/**
 * @brief Socket_setfastopen - Enable TCP Fast Open
 * @ingroup core_io
 * @socket: Socket to modify
 * @enable: 1 to enable, 0 to disable
 * Raises: Socket_Failed on error or if not supported
 */
extern void Socket_setfastopen (T socket, int enable);

/**
 * @brief Socket_getfastopen - Get TCP Fast Open setting
 * @ingroup core_io
 * @socket: Socket to query
 * Returns: 1 if enabled, 0 if disabled, -1 on error
 */
extern int Socket_getfastopen (T socket);

/**
 * @brief Socket_setusertimeout - Set TCP user timeout
 * @ingroup core_io
 * @socket: Socket to modify
 * @timeout_ms: Timeout in milliseconds (> 0)
 * Raises: Socket_Failed on error or if not supported
 * Note: Only available on Linux 2.6.37+.
 */
extern void Socket_setusertimeout (T socket, unsigned int timeout_ms);

/**
 * @brief Socket_getusertimeout - Get TCP user timeout
 * @ingroup core_io
 * @socket: Socket to query
 * Returns: Timeout in milliseconds, or 0 on error
 */
extern unsigned int Socket_getusertimeout (T socket);

/**
 * @brief Socket_shutdown - Disable further sends and/or receives
 * @ingroup core_io
 * @socket: Connected socket
 * @how: Shutdown mode (SHUT_RD, SHUT_WR, or SHUT_RDWR)
 * Raises: Socket_Failed on error
 */
extern void Socket_shutdown (T socket, int how);

/**
 * @brief Socket_setcloexec - Control close-on-exec flag
 * @ingroup core_io
 * @socket: Socket to modify
 * @enable: 1 to enable CLOEXEC, 0 to disable
 * Raises: Socket_Failed on error
 */
extern void Socket_setcloexec (T socket, int enable);

/* ============================================================================
 * SYN Flood Protection Socket Options
 * ============================================================================
 */

/**
 * @brief Socket_setdeferaccept - Enable TCP_DEFER_ACCEPT
 * @ingroup core_io
 * @socket: Listening socket
 * @timeout_sec: Seconds to wait for data before completing accept
 *               (0 to disable, max platform-specific)
 *
 * Delays accept() completion until client sends data, preventing
 * @brief SYN-only connections from consuming application resources.
 * @ingroup core_io
 * This is a key defense against SYN flood attacks.
 *
 * Linux: Uses TCP_DEFER_ACCEPT socket option
 * BSD/macOS: Uses SO_ACCEPTFILTER with "dataready" filter
 *
 * Raises: Socket_Failed on error or if unsupported
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern void Socket_setdeferaccept (T socket, int timeout_sec);

/**
 * @brief Socket_getdeferaccept - Get TCP_DEFER_ACCEPT timeout
 * @ingroup core_io
 * @socket: Listening socket
 *
 * Returns: Current defer accept timeout in seconds, 0 if disabled
 * Raises: Socket_Failed on error
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern int Socket_getdeferaccept (T socket);

/* ============================================================================
 * Timeout Configuration
 * ============================================================================
 */

/**
 * @brief Socket_timeouts_get - Retrieve per-socket timeout configuration
 * @ingroup core_io
 * @socket: Socket instance
 * @timeouts: Output timeout structure
 */
extern void Socket_timeouts_get (const T socket, SocketTimeouts_T *timeouts);

/**
 * @brief Socket_timeouts_set - Set per-socket timeout configuration
 * @ingroup core_io
 * @socket: Socket instance
 * @timeouts: Timeout configuration (NULL to reset to defaults)
 */
extern void Socket_timeouts_set (T socket, const SocketTimeouts_T *timeouts);

/**
 * @brief Socket_timeouts_getdefaults - Get global default timeouts
 * @ingroup core_io
 * @timeouts: Output timeout structure containing current defaults
 */
extern void Socket_timeouts_getdefaults (SocketTimeouts_T *timeouts);

/**
 * @brief Socket_timeouts_setdefaults - Set global default timeouts
 * @ingroup core_io
 * @timeouts: New default timeout configuration
 */
extern void Socket_timeouts_setdefaults (const SocketTimeouts_T *timeouts);

/**
 * @brief Socket_timeouts_set_extended - Set per-socket extended timeout configuration
 * @ingroup core_io
 * @socket: Socket to modify
 * @extended: Extended per-phase timeout configuration
 *
 * Sets granular per-phase timeouts for advanced use cases. The extended
 * timeouts provide finer control than SocketTimeouts_T, allowing different
 * timeouts for DNS, connect, TLS, and request phases.
 *
 * Values of 0 in the extended structure mean "inherit from basic timeouts".
 * Values of -1 mean "no timeout (infinite)".
 *
 * @note Thread-safe: No - caller must ensure exclusive access
 * @ingroup core_io
 */
extern void
Socket_timeouts_set_extended (T socket,
                              const SocketTimeouts_Extended_T *extended);

/**
 * @brief Socket_timeouts_get_extended - Retrieve per-socket extended timeout
 * @ingroup core_io
 * configuration
 * @socket: Socket to query
 * @extended: Output structure for extended timeouts
 *
 * Retrieves the current extended timeout configuration. If extended timeouts
 * haven't been set, returns the basic timeouts mapped to the extended
 * structure.
 *
 * @note Thread-safe: No - caller must ensure exclusive access
 * @ingroup core_io
 */
extern void Socket_timeouts_get_extended (const T socket,
                                          SocketTimeouts_Extended_T *extended);

/* ============================================================================
 * Bandwidth Limiting
 * ============================================================================
 */

/**
 * @brief Socket_setbandwidth - Set bandwidth limit for socket
 * @ingroup core_io
 * @socket: Socket to modify
 * @bytes_per_sec: Maximum bytes per second (0 to disable limiting)
 *
 * Raises: Socket_Failed on allocation failure
 * @note Thread-safe: Yes - uses internal mutex
 * @ingroup core_io
 *
 * Enables bandwidth throttling using a token bucket algorithm.
 * The burst capacity is set to bytes_per_sec (1 second of data).
 * Use Socket_send_limited() for rate-limited sending.
 */
extern void Socket_setbandwidth (T socket, size_t bytes_per_sec);

/**
 * @brief Socket_getbandwidth - Get bandwidth limit for socket
 * @ingroup core_io
 * @socket: Socket to query
 *
 * Returns: Bandwidth limit in bytes per second (0 if unlimited)
 * @note Thread-safe: Yes
 * @ingroup core_io
 */
extern size_t Socket_getbandwidth (T socket);

/**
 * @brief Socket_send_limited - Send data with bandwidth limiting
 * @ingroup core_io
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (> 0)
 *
 * Returns: Bytes sent (> 0), 0 if rate limited (try again later), or raises
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 * @note Thread-safe: Yes - uses socket's bandwidth limiter
 * @ingroup core_io
 *
 * Like Socket_send() but respects bandwidth limit set by
 * Socket_setbandwidth(). If bandwidth limiting is disabled (0), behaves like
 * Socket_send(). If rate limited, returns 0 and caller should wait before
 * retrying. Use Socket_bandwidth_wait_ms() to get recommended wait time.
 */
extern ssize_t Socket_send_limited (T socket, const void *buf, size_t len);

/**
 * @brief Socket_recv_limited - Receive data with bandwidth limiting
 * @ingroup core_io
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (> 0)
 *
 * Returns: Bytes received (> 0), 0 if rate limited or would block, or raises
 * Raises: Socket_Closed on peer close, Socket_Failed on other errors
 * @note Thread-safe: Yes - uses socket's bandwidth limiter
 * @ingroup core_io
 *
 * Like Socket_recv() but respects bandwidth limit set by
 * Socket_setbandwidth(). If bandwidth limiting is disabled (0), behaves like
 * Socket_recv().
 */
extern ssize_t Socket_recv_limited (T socket, void *buf, size_t len);

/**
 * @brief Socket_bandwidth_wait_ms - Get wait time until bandwidth available
 * @ingroup core_io
 * @socket: Socket to query
 * @bytes: Number of bytes needed
 *
 * Returns: Milliseconds to wait, 0 if immediate, -1 if impossible
 * @note Thread-safe: Yes
 * @ingroup core_io
 *
 * Useful for event loop integration - use as poll timeout.
 */
extern int64_t Socket_bandwidth_wait_ms (T socket, size_t bytes);

/* ============================================================================
 * Unix Domain Socket Operations
 * ============================================================================
 */

/**
 * @brief Socket_bind_unix - Bind to Unix domain socket path
 * @ingroup core_io
 * @socket: Socket to bind (AF_UNIX)
 * @path: Socket file path
 * Raises: Socket_Failed on error
 * Note: Fails with EADDRINUSE if path exists. Max path length ~108 bytes.
 * Supports abstract namespace sockets on Linux (path starting with '@').
 */
extern void Socket_bind_unix (T socket, const char *path);

/**
 * @brief Socket_connect_unix - Connect to Unix domain socket path
 * @ingroup core_io
 * @socket: Socket to connect (AF_UNIX)
 * @path: Socket file path
 * Raises: Socket_Failed on error
 * Note: Supports abstract namespace sockets on Linux (path starting with '@').
 */
extern void Socket_connect_unix (T socket, const char *path);

/**
 * @brief Socket_getpeerpid - Get peer process ID (Linux only)
 * @ingroup core_io
 * @socket: Connected Unix domain socket
 * Returns: Peer process ID, or -1 if unavailable
 */
extern int Socket_getpeerpid (const T socket);

/**
 * @brief Socket_getpeeruid - Get peer user ID (Linux only)
 * @ingroup core_io
 * @socket: Connected Unix domain socket
 * Returns: Peer user ID, or (uid_t)-1 if unavailable
 */
extern int Socket_getpeeruid (const T socket);

/**
 * @brief Socket_getpeergid - Get peer group ID (Linux only)
 * @ingroup core_io
 * @socket: Connected Unix domain socket
 * Returns: Peer group ID, or (gid_t)-1 if unavailable
 */
extern int Socket_getpeergid (const T socket);

/* ============================================================================
 * File Descriptor Passing (SCM_RIGHTS)
 * ============================================================================
 */

/**
 * @brief Socket_sendfd - Send a file descriptor over Unix domain socket
 * @ingroup core_io
 * @socket: Connected Unix domain socket (AF_UNIX)
 * @fd_to_pass: File descriptor to pass (must be >= 0)
 *
 * Returns: 1 on success, 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Failed on error, Socket_Closed on disconnect
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
 * @note Thread-safe: Yes (uses thread-local error buffers)
 * @ingroup core_io
 */
extern int Socket_sendfd (T socket, int fd_to_pass);

/**
 * @brief Socket_recvfd - Receive a file descriptor over Unix domain socket
 * @ingroup core_io
 * @socket: Connected Unix domain socket (AF_UNIX)
 * @fd_received: Output pointer for received file descriptor
 *
 * Returns: 1 on success, 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Failed on error, Socket_Closed on disconnect
 *
 * Receives a file descriptor from the peer process via SCM_RIGHTS.
 * The received fd is owned by this process and must be closed when done.
 *
 * OWNERSHIP: Caller takes ownership of the received fd and MUST close it.
 *
 * @note Thread-safe: Yes (uses thread-local error buffers)
 * @ingroup core_io
 */
extern int Socket_recvfd (T socket, int *fd_received);

/**
 * @brief Socket_sendfds - Send multiple file descriptors
 * @ingroup core_io
 * @socket: Connected Unix domain socket (AF_UNIX)
 * @fds: Array of file descriptors to pass (all must be >= 0)
 * @count: Number of descriptors (1 to SOCKET_MAX_FDS_PER_MSG)
 *
 * Returns: 1 on success, 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Failed on error, Socket_Closed on disconnect
 *
 * Passes multiple file descriptors atomically in a single message.
 * All descriptors are either sent together or none are sent.
 *
 * @note Thread-safe: Yes (uses thread-local error buffers)
 * @ingroup core_io
 */
extern int Socket_sendfds (T socket, const int *fds, size_t count);

/**
 * @brief Socket_recvfds - Receive multiple file descriptors
 * @ingroup core_io
 * @socket: Connected Unix domain socket (AF_UNIX)
 * @fds: Output array for received descriptors (must have max_count capacity)
 * @max_count: Maximum descriptors to receive
 * @received_count: Output for actual count received
 *
 * Returns: 1 on success, 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Failed on error, Socket_Closed on disconnect
 *
 * Receives multiple file descriptors from a single message.
 * On success, *received_count contains the number of fds received.
 *
 * OWNERSHIP: Caller takes ownership of all received fds and MUST close them.
 *
 * @note Thread-safe: Yes (uses thread-local error buffers)
 * @ingroup core_io
 */
extern int Socket_recvfds (T socket, int *fds, size_t max_count,
                           size_t *received_count);

/* Unix domain socket internal helpers */
extern void SocketUnix_bind (SocketBase_T base, const char *path,
                             Except_T exc_type);
extern void SocketUnix_connect (SocketBase_T base, const char *path,
                                Except_T exc_type);
extern int SocketUnix_validate_unix_path (const char *path, size_t path_len);

/* ============================================================================
 * Async DNS Operations
 * ============================================================================
 */

/**
 * @brief Socket_bind_async - Start async DNS resolution for bind
 * @ingroup core_io
 * @dns: DNS resolver instance
 * @socket: Socket to bind
 * @host: IP address or hostname (NULL for any)
 * @port: Port number (1 to SOCKET_MAX_PORT)
 * Returns: DNS request handle
 * Raises: Socket_Failed on error
 */
extern Request_T Socket_bind_async (SocketDNS_T dns, T socket,
                                     const char *host, int port);

/**
 * @brief Socket_bind_async_cancel - Cancel pending async bind resolution
 * @ingroup core_io
 * @dns: DNS resolver instance
 * @req: Request handle returned by Socket_bind_async
 */
extern void Socket_bind_async_cancel (SocketDNS_T dns, Request_T req);

/**
 * @brief Socket_connect_async - Start async DNS resolution for connect
 * @ingroup core_io
 * @dns: DNS resolver instance
 * @socket: Socket to connect
 * @host: Remote IP address or hostname
 * @port: Remote port (1 to SOCKET_MAX_PORT)
 * Returns: DNS request handle
 * Raises: Socket_Failed on error
 */
extern Request_T Socket_connect_async (SocketDNS_T dns, T socket,
                                       const char *host, int port);

/**
 * @brief Socket_connect_async_cancel - Cancel pending async connect resolution
 * @ingroup core_io
 * @dns: DNS resolver instance
 * @req: Request handle returned by Socket_connect_async
 */
extern void Socket_connect_async_cancel (SocketDNS_T dns, Request_T req);

/**
 * @brief Socket_bind_with_addrinfo - Bind socket using resolved address
 * @ingroup core_io
 * @socket: Socket to bind
 * @res: Resolved addrinfo result from DNS resolution
 * Raises: Socket_Failed on error
 */
extern void Socket_bind_with_addrinfo (T socket, struct addrinfo *res);

/**
 * @brief Socket_connect_with_addrinfo - Connect socket using resolved address
 * @ingroup core_io
 * @socket: Socket to connect
 * @res: Resolved addrinfo result from DNS resolution
 * Raises: Socket_Failed on error
 */
extern void Socket_connect_with_addrinfo (T socket, struct addrinfo *res);

/* ============================================================================
 * Signal Handling Utilities
 * ============================================================================
 */

/**
 * @brief Socket_ignore_sigpipe - Globally ignore SIGPIPE signal
 * @ingroup core_io
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
 * Returns: 0 on success, -1 on error (sets errno)
 * @note Thread-safe: Yes (can be called from any thread, idempotent)
 * @ingroup core_io
 *
 * Usage:
 *   // Optional - call once at program startup if desired
 *   Socket_ignore_sigpipe();
 *
 * IMPORTANT: Do not call this if your application needs to handle SIGPIPE
 * for other purposes (e.g., detecting broken pipes in shell pipelines).
 */
extern int Socket_ignore_sigpipe (void);

#undef T

/** @} */ /* end of core_io group */

#endif /* SOCKET_INCLUDED */
