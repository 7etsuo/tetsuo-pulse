#ifndef SOCKET_INCLUDED
#define SOCKET_INCLUDED

/**
 * Socket.h - Socket Abstraction Layer
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * High-level, exception-based TCP/IP/Unix domain socket interface.
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
 */

#include "core/Except.h"
#include "core/SocketConfig.h"
#include "dns/SocketDNS.h"
#include "socket/SocketCommon.h"

#define T Socket_T
typedef struct T *T;

/* ============================================================================
 * Exception Types
 * ============================================================================ */

extern const Except_T Socket_Failed; /**< General socket operation failure */
extern const Except_T Socket_Closed; /**< Connection closed by peer */
extern const Except_T SocketUnix_Failed; /**< Unix socket operation failure */

/* ============================================================================
 * Socket Creation and Lifecycle
 * ============================================================================ */

/**
 * Socket_new - Create a new socket
 * @domain: Address family (AF_INET, AF_INET6, etc.)
 * @type: Socket type (SOCK_STREAM, SOCK_DGRAM, etc.)
 * @protocol: Protocol (usually 0 for default)
 * Returns: New socket instance
 * Raises: Socket_Failed on error
 */
extern T Socket_new (int domain, int type, int protocol);

/**
 * SocketPair_new - Create a pair of connected Unix domain sockets
 * @type: Socket type (SOCK_STREAM or SOCK_DGRAM)
 * @socket1: Output - first socket of the pair
 * @socket2: Output - second socket of the pair
 * Raises: Socket_Failed on error
 * Thread-safe: Yes (creates new sockets)
 * Note: Creates two connected Unix domain sockets for IPC.
 * Both sockets are ready to use - no bind/connect needed.
 */
extern void SocketPair_new (int type, T *socket1, T *socket2);

/**
 * Socket_free - Free a socket and close the connection
 * @socket: Pointer to socket (will be set to NULL)
 */
extern void Socket_free (T *socket);

/**
 * Socket_new_from_fd - Create Socket_T from existing file descriptor
 * @fd: File descriptor (must be valid socket, will be set to non-blocking)
 * Returns: New Socket_T instance or NULL on failure
 * Raises: Socket_Failed on error
 * Thread-safe: Yes - returns new instance
 */
extern T Socket_new_from_fd (int fd);

/**
 * Socket_debug_live_count - Get number of live socket instances (test-only)
 * Returns: Current count of allocated Socket_T instances
 */
extern int Socket_debug_live_count (void);

/* ============================================================================
 * Connection Operations
 * ============================================================================ */

/**
 * Socket_bind - Bind socket to address and port
 * @socket: Socket to bind
 * @host: IP address or NULL/"0.0.0.0" for any
 * @port: Port number (1 to SOCKET_MAX_PORT)
 * WARNING: May block 30+ seconds during DNS resolution if hostname provided.
 * Raises: Socket_Failed on error
 */
extern void Socket_bind (T socket, const char *host, int port);

/**
 * Socket_listen - Listen for incoming connections
 * @socket: Bound socket
 * @backlog: Maximum pending connections
 * Raises: Socket_Failed on error
 */
extern void Socket_listen (T socket, int backlog);

/**
 * Socket_accept - Accept incoming connection
 * @socket: Listening socket
 * Returns: New socket or NULL if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Failed on error
 */
extern T Socket_accept (T socket);

/**
 * Socket_connect - Connect to remote host
 * @socket: Socket to connect
 * @host: Remote IP address or hostname
 * @port: Remote port
 * WARNING: May block 30+ seconds during DNS resolution if hostname provided.
 * Raises: Socket_Failed on error
 */
extern void Socket_connect (T socket, const char *host, int port);

/* ============================================================================
 * Basic I/O Operations
 * ============================================================================ */

/**
 * Socket_send - Send data
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (> 0)
 * Returns: Bytes sent (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 */
extern ssize_t Socket_send (T socket, const void *buf, size_t len);

/**
 * Socket_recv - Receive data
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (> 0)
 * Returns: Bytes received (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on peer close or ECONNRESET, Socket_Failed on other
 */
extern ssize_t Socket_recv (T socket, void *buf, size_t len);

/**
 * Socket_sendall - Send all data (handles partial sends)
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (> 0)
 * Returns: Total bytes sent (always equals len on success)
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 */
extern ssize_t Socket_sendall (T socket, const void *buf, size_t len);

/**
 * Socket_recvall - Receive all requested data (handles partial receives)
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (> 0)
 * Returns: Total bytes received (always equals len on success)
 * Raises: Socket_Closed on peer close or ECONNRESET, Socket_Failed on other
 */
extern ssize_t Socket_recvall (T socket, void *buf, size_t len);

/* ============================================================================
 * Scatter/Gather I/O Operations
 * ============================================================================ */

/**
 * Socket_sendv - Scatter/gather send (writev wrapper)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes sent (> 0) or 0 if would block
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 */
extern ssize_t Socket_sendv (T socket, const struct iovec *iov, int iovcnt);

/**
 * Socket_recvv - Scatter/gather receive (readv wrapper)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes received (> 0) or 0 if would block
 * Raises: Socket_Closed on peer close or ECONNRESET, Socket_Failed on other
 */
extern ssize_t Socket_recvv (T socket, struct iovec *iov, int iovcnt);

/**
 * Socket_sendvall - Scatter/gather send all (handles partial sends)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes sent (always equals sum of all iov_len on success)
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 */
extern ssize_t Socket_sendvall (T socket, const struct iovec *iov, int iovcnt);

/**
 * Socket_recvvall - Scatter/gather receive all (handles partial receives)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes received (always equals sum of all iov_len on success)
 * Raises: Socket_Closed on peer close or ECONNRESET, Socket_Failed on other
 */
extern ssize_t Socket_recvvall (T socket, struct iovec *iov, int iovcnt);

/* ============================================================================
 * Zero-Copy and Advanced I/O
 * ============================================================================ */

/**
 * Socket_sendfile - Zero-copy file-to-socket transfer
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
 * Socket_sendfileall - Zero-copy file-to-socket transfer (handles partial)
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
 * Socket_sendmsg - Send message with ancillary data (sendmsg wrapper)
 * @socket: Connected socket
 * @msg: Message structure with data, address, and ancillary data
 * @flags: Message flags (MSG_NOSIGNAL, MSG_DONTWAIT, etc.)
 * Returns: Total bytes sent (> 0) or 0 if would block
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 */
extern ssize_t Socket_sendmsg (T socket, const struct msghdr *msg, int flags);

/**
 * Socket_recvmsg - Receive message with ancillary data (recvmsg wrapper)
 * @socket: Connected socket
 * @msg: Message structure for data, address, and ancillary data
 * @flags: Message flags (MSG_DONTWAIT, MSG_PEEK, etc.)
 * Returns: Total bytes received (> 0) or 0 if would block
 * Raises: Socket_Closed on peer close or ECONNRESET, Socket_Failed on other
 */
extern ssize_t Socket_recvmsg (T socket, struct msghdr *msg, int flags);

/* ============================================================================
 * Socket State Query Functions
 * ============================================================================ */

/**
 * Socket_isconnected - Check if socket is connected
 * @socket: Socket to check
 * Returns: 1 if connected, 0 if not connected
 * Thread-safe: Yes
 */
extern int Socket_isconnected (T socket);

/**
 * Socket_isbound - Check if socket is bound to an address
 * @socket: Socket to check
 * Returns: 1 if bound, 0 if not bound
 * Thread-safe: Yes
 */
extern int Socket_isbound (T socket);

/**
 * Socket_islistening - Check if socket is listening for connections
 * @socket: Socket to check
 * Returns: 1 if listening, 0 if not listening
 * Thread-safe: Yes
 */
extern int Socket_islistening (T socket);

/**
 * Socket_fd - Get underlying file descriptor
 * @socket: Socket instance
 * Returns: File descriptor
 */
extern int Socket_fd (const T socket);

/**
 * Socket_getpeeraddr - Get peer IP address
 * @socket: Connected socket
 * Returns: IP address string (IPv4/IPv6) or "(unknown)" if unavailable
 * Note: String is owned by socket, valid until socket freed.
 */
extern const char *Socket_getpeeraddr (const T socket);

/**
 * Socket_getpeerport - Get peer port number
 * @socket: Connected socket
 * Returns: Port number (1 to SOCKET_MAX_PORT) or 0 if unavailable
 */
extern int Socket_getpeerport (const T socket);

/**
 * Socket_getlocaladdr - Get local IP address
 * @socket: Socket instance
 * Returns: IP address string (IPv4/IPv6) or "(unknown)" if unavailable
 * Note: String is owned by socket, valid until socket freed.
 */
extern const char *Socket_getlocaladdr (const T socket);

/**
 * Socket_getlocalport - Get local port number
 * @socket: Socket instance
 * Returns: Port number (1 to SOCKET_MAX_PORT) or 0 if unavailable
 */
extern int Socket_getlocalport (const T socket);

/* ============================================================================
 * Socket Options Configuration
 * ============================================================================ */

/**
 * Socket_setnonblocking - Enable non-blocking mode
 * @socket: Socket to modify
 * Raises: Socket_Failed on error
 */
extern void Socket_setnonblocking (T socket);

/**
 * Socket_setreuseaddr - Enable address reuse
 * @socket: Socket to modify
 * Raises: Socket_Failed on error
 */
extern void Socket_setreuseaddr (T socket);

/**
 * Socket_setreuseport - Enable port reuse across sockets
 * @socket: Socket to modify
 * Raises: Socket_Failed on error (or if SO_REUSEPORT unsupported)
 */
extern void Socket_setreuseport (T socket);

/**
 * Socket_settimeout - Set socket timeout
 * @socket: Socket to modify
 * @timeout_sec: Timeout in seconds (0 to disable)
 * Sets both send and receive timeouts
 * Raises: Socket_Failed on error
 */
extern void Socket_settimeout (T socket, int timeout_sec);

/**
 * Socket_setkeepalive - Enable TCP keepalive
 * @socket: Socket to modify
 * @idle: Seconds before sending keepalive probes
 * @interval: Interval between keepalive probes
 * @count: Number of probes before declaring dead
 * Raises: Socket_Failed on error
 */
extern void Socket_setkeepalive (T socket, int idle, int interval, int count);

/**
 * Socket_setnodelay - Disable Nagle's algorithm
 * @socket: Socket to modify
 * @nodelay: 1 to disable Nagle, 0 to enable
 * Raises: Socket_Failed on error
 */
extern void Socket_setnodelay (T socket, int nodelay);

/**
 * Socket_gettimeout - Get socket timeout
 * @socket: Socket to query
 * Returns: Timeout in seconds (0 if disabled)
 * Raises: Socket_Failed on error
 */
extern int Socket_gettimeout (T socket);

/**
 * Socket_getkeepalive - Get TCP keepalive configuration
 * @socket: Socket to query
 * @idle: Output - idle timeout in seconds
 * @interval: Output - interval between probes in seconds
 * @count: Output - number of probes before declaring dead
 * Raises: Socket_Failed on error
 */
extern void Socket_getkeepalive (T socket, int *idle, int *interval,
                                 int *count);

/**
 * Socket_getnodelay - Get TCP_NODELAY setting
 * @socket: Socket to query
 * Returns: 1 if Nagle's algorithm is disabled, 0 if enabled
 * Raises: Socket_Failed on error
 */
extern int Socket_getnodelay (T socket);

/**
 * Socket_getrcvbuf - Get receive buffer size
 * @socket: Socket to query
 * Returns: Receive buffer size in bytes
 * Raises: Socket_Failed on error
 */
extern int Socket_getrcvbuf (T socket);

/**
 * Socket_getsndbuf - Get send buffer size
 * @socket: Socket to query
 * Returns: Send buffer size in bytes
 * Raises: Socket_Failed on error
 */
extern int Socket_getsndbuf (T socket);

/**
 * Socket_setrcvbuf - Set receive buffer size
 * @socket: Socket to modify
 * @size: Buffer size in bytes (> 0)
 * Raises: Socket_Failed on error
 */
extern void Socket_setrcvbuf (T socket, int size);

/**
 * Socket_setsndbuf - Set send buffer size
 * @socket: Socket to modify
 * @size: Buffer size in bytes (> 0)
 * Raises: Socket_Failed on error
 */
extern void Socket_setsndbuf (T socket, int size);

/**
 * Socket_setcongestion - Set TCP congestion control algorithm
 * @socket: Socket to modify
 * @algorithm: Algorithm name (e.g., "cubic", "reno", "bbr")
 * Raises: Socket_Failed on error or if not supported
 * Note: Only available on Linux 2.6.13+.
 */
extern void Socket_setcongestion (T socket, const char *algorithm);

/**
 * Socket_getcongestion - Get TCP congestion control algorithm
 * @socket: Socket to query
 * @algorithm: Output buffer for algorithm name
 * @len: Buffer length
 * Returns: 0 on success, -1 on error or if not supported
 */
extern int Socket_getcongestion (T socket, char *algorithm, size_t len);

/**
 * Socket_setfastopen - Enable TCP Fast Open
 * @socket: Socket to modify
 * @enable: 1 to enable, 0 to disable
 * Raises: Socket_Failed on error or if not supported
 */
extern void Socket_setfastopen (T socket, int enable);

/**
 * Socket_getfastopen - Get TCP Fast Open setting
 * @socket: Socket to query
 * Returns: 1 if enabled, 0 if disabled, -1 on error
 */
extern int Socket_getfastopen (T socket);

/**
 * Socket_setusertimeout - Set TCP user timeout
 * @socket: Socket to modify
 * @timeout_ms: Timeout in milliseconds (> 0)
 * Raises: Socket_Failed on error or if not supported
 * Note: Only available on Linux 2.6.37+.
 */
extern void Socket_setusertimeout (T socket, unsigned int timeout_ms);

/**
 * Socket_getusertimeout - Get TCP user timeout
 * @socket: Socket to query
 * Returns: Timeout in milliseconds, or 0 on error
 */
extern unsigned int Socket_getusertimeout (T socket);

/**
 * Socket_shutdown - Disable further sends and/or receives
 * @socket: Connected socket
 * @how: Shutdown mode (SHUT_RD, SHUT_WR, or SHUT_RDWR)
 * Raises: Socket_Failed on error
 */
extern void Socket_shutdown (T socket, int how);

/**
 * Socket_setcloexec - Control close-on-exec flag
 * @socket: Socket to modify
 * @enable: 1 to enable CLOEXEC, 0 to disable
 * Raises: Socket_Failed on error
 */
extern void Socket_setcloexec (T socket, int enable);

/* ============================================================================
 * SYN Flood Protection Socket Options
 * ============================================================================ */

/**
 * Socket_setdeferaccept - Enable TCP_DEFER_ACCEPT
 * @socket: Listening socket
 * @timeout_sec: Seconds to wait for data before completing accept
 *               (0 to disable, max platform-specific)
 *
 * Delays accept() completion until client sends data, preventing
 * SYN-only connections from consuming application resources.
 * This is a key defense against SYN flood attacks.
 *
 * Linux: Uses TCP_DEFER_ACCEPT socket option
 * BSD/macOS: Uses SO_ACCEPTFILTER with "dataready" filter
 *
 * Raises: Socket_Failed on error or if unsupported
 * Thread-safe: Yes
 */
extern void Socket_setdeferaccept (T socket, int timeout_sec);

/**
 * Socket_getdeferaccept - Get TCP_DEFER_ACCEPT timeout
 * @socket: Listening socket
 *
 * Returns: Current defer accept timeout in seconds, 0 if disabled
 * Raises: Socket_Failed on error
 * Thread-safe: Yes
 */
extern int Socket_getdeferaccept (T socket);

/* ============================================================================
 * Timeout Configuration
 * ============================================================================ */

/**
 * Socket_timeouts_get - Retrieve per-socket timeout configuration
 * @socket: Socket instance
 * @timeouts: Output timeout structure
 */
extern void Socket_timeouts_get (const T socket, SocketTimeouts_T *timeouts);

/**
 * Socket_timeouts_set - Set per-socket timeout configuration
 * @socket: Socket instance
 * @timeouts: Timeout configuration (NULL to reset to defaults)
 */
extern void Socket_timeouts_set (T socket, const SocketTimeouts_T *timeouts);

/**
 * Socket_timeouts_getdefaults - Get global default timeouts
 * @timeouts: Output timeout structure containing current defaults
 */
extern void Socket_timeouts_getdefaults (SocketTimeouts_T *timeouts);

/**
 * Socket_timeouts_setdefaults - Set global default timeouts
 * @timeouts: New default timeout configuration
 */
extern void Socket_timeouts_setdefaults (const SocketTimeouts_T *timeouts);

/* ============================================================================
 * Bandwidth Limiting
 * ============================================================================ */

/**
 * Socket_setbandwidth - Set bandwidth limit for socket
 * @socket: Socket to modify
 * @bytes_per_sec: Maximum bytes per second (0 to disable limiting)
 *
 * Raises: Socket_Failed on allocation failure
 * Thread-safe: Yes - uses internal mutex
 *
 * Enables bandwidth throttling using a token bucket algorithm.
 * The burst capacity is set to bytes_per_sec (1 second of data).
 * Use Socket_send_limited() for rate-limited sending.
 */
extern void Socket_setbandwidth (T socket, size_t bytes_per_sec);

/**
 * Socket_getbandwidth - Get bandwidth limit for socket
 * @socket: Socket to query
 *
 * Returns: Bandwidth limit in bytes per second (0 if unlimited)
 * Thread-safe: Yes
 */
extern size_t Socket_getbandwidth (T socket);

/**
 * Socket_send_limited - Send data with bandwidth limiting
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (> 0)
 *
 * Returns: Bytes sent (> 0), 0 if rate limited (try again later), or raises
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 * Thread-safe: Yes - uses socket's bandwidth limiter
 *
 * Like Socket_send() but respects bandwidth limit set by Socket_setbandwidth().
 * If bandwidth limiting is disabled (0), behaves like Socket_send().
 * If rate limited, returns 0 and caller should wait before retrying.
 * Use Socket_bandwidth_wait_ms() to get recommended wait time.
 */
extern ssize_t Socket_send_limited (T socket, const void *buf, size_t len);

/**
 * Socket_recv_limited - Receive data with bandwidth limiting
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (> 0)
 *
 * Returns: Bytes received (> 0), 0 if rate limited or would block, or raises
 * Raises: Socket_Closed on peer close, Socket_Failed on other errors
 * Thread-safe: Yes - uses socket's bandwidth limiter
 *
 * Like Socket_recv() but respects bandwidth limit set by Socket_setbandwidth().
 * If bandwidth limiting is disabled (0), behaves like Socket_recv().
 */
extern ssize_t Socket_recv_limited (T socket, void *buf, size_t len);

/**
 * Socket_bandwidth_wait_ms - Get wait time until bandwidth available
 * @socket: Socket to query
 * @bytes: Number of bytes needed
 *
 * Returns: Milliseconds to wait, 0 if immediate, -1 if impossible
 * Thread-safe: Yes
 *
 * Useful for event loop integration - use as poll timeout.
 */
extern int64_t Socket_bandwidth_wait_ms (T socket, size_t bytes);

/* ============================================================================
 * Unix Domain Socket Operations
 * ============================================================================ */

/**
 * Socket_bind_unix - Bind to Unix domain socket path
 * @socket: Socket to bind (AF_UNIX)
 * @path: Socket file path
 * Raises: Socket_Failed on error
 * Note: Fails with EADDRINUSE if path exists. Max path length ~108 bytes.
 * Supports abstract namespace sockets on Linux (path starting with '@').
 */
extern void Socket_bind_unix (T socket, const char *path);

/**
 * Socket_connect_unix - Connect to Unix domain socket path
 * @socket: Socket to connect (AF_UNIX)
 * @path: Socket file path
 * Raises: Socket_Failed on error
 * Note: Supports abstract namespace sockets on Linux (path starting with '@').
 */
extern void Socket_connect_unix (T socket, const char *path);

/**
 * Socket_getpeerpid - Get peer process ID (Linux only)
 * @socket: Connected Unix domain socket
 * Returns: Peer process ID, or -1 if unavailable
 */
extern int Socket_getpeerpid (const T socket);

/**
 * Socket_getpeeruid - Get peer user ID (Linux only)
 * @socket: Connected Unix domain socket
 * Returns: Peer user ID, or (uid_t)-1 if unavailable
 */
extern int Socket_getpeeruid (const T socket);

/**
 * Socket_getpeergid - Get peer group ID (Linux only)
 * @socket: Connected Unix domain socket
 * Returns: Peer group ID, or (gid_t)-1 if unavailable
 */
extern int Socket_getpeergid (const T socket);

/* ============================================================================
 * File Descriptor Passing (SCM_RIGHTS)
 * ============================================================================ */

/**
 * Socket_sendfd - Send a file descriptor over Unix domain socket
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
 * Thread-safe: Yes (uses thread-local error buffers)
 */
extern int Socket_sendfd (T socket, int fd_to_pass);

/**
 * Socket_recvfd - Receive a file descriptor over Unix domain socket
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
 * Thread-safe: Yes (uses thread-local error buffers)
 */
extern int Socket_recvfd (T socket, int *fd_received);

/**
 * Socket_sendfds - Send multiple file descriptors
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
 * Thread-safe: Yes (uses thread-local error buffers)
 */
extern int Socket_sendfds (T socket, const int *fds, size_t count);

/**
 * Socket_recvfds - Receive multiple file descriptors
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
 * Thread-safe: Yes (uses thread-local error buffers)
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
 * ============================================================================ */

/**
 * Socket_bind_async - Start async DNS resolution for bind
 * @dns: DNS resolver instance
 * @socket: Socket to bind
 * @host: IP address or hostname (NULL for any)
 * @port: Port number (1 to SOCKET_MAX_PORT)
 * Returns: DNS request handle
 * Raises: Socket_Failed on error
 */
extern SocketDNS_Request_T Socket_bind_async (SocketDNS_T dns, T socket,
                                              const char *host, int port);

/**
 * Socket_bind_async_cancel - Cancel pending async bind resolution
 * @dns: DNS resolver instance
 * @req: Request handle returned by Socket_bind_async
 */
extern void Socket_bind_async_cancel (SocketDNS_T dns,
                                      SocketDNS_Request_T req);

/**
 * Socket_connect_async - Start async DNS resolution for connect
 * @dns: DNS resolver instance
 * @socket: Socket to connect
 * @host: Remote IP address or hostname
 * @port: Remote port (1 to SOCKET_MAX_PORT)
 * Returns: DNS request handle
 * Raises: Socket_Failed on error
 */
extern SocketDNS_Request_T Socket_connect_async (SocketDNS_T dns, T socket,
                                                 const char *host, int port);

/**
 * Socket_connect_async_cancel - Cancel pending async connect resolution
 * @dns: DNS resolver instance
 * @req: Request handle returned by Socket_connect_async
 */
extern void Socket_connect_async_cancel (SocketDNS_T dns,
                                         SocketDNS_Request_T req);

/**
 * Socket_bind_with_addrinfo - Bind socket using resolved address
 * @socket: Socket to bind
 * @res: Resolved addrinfo result from DNS resolution
 * Raises: Socket_Failed on error
 */
extern void Socket_bind_with_addrinfo (T socket, struct addrinfo *res);

/**
 * Socket_connect_with_addrinfo - Connect socket using resolved address
 * @socket: Socket to connect
 * @res: Resolved addrinfo result from DNS resolution
 * Raises: Socket_Failed on error
 */
extern void Socket_connect_with_addrinfo (T socket, struct addrinfo *res);

#undef T
#endif /* SOCKET_INCLUDED */
