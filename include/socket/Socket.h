#ifndef SOCKET_INCLUDED
#define SOCKET_INCLUDED

#include "core/Except.h"
#include "dns/SocketDNS.h"

/**
 * Socket Abstraction Layer
 * High-level, exception-based TCP/IP socket interface.
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - IPv6 support in kernel for dual-stack sockets
 * - POSIX threads for thread-safe error reporting
 * - NOT portable to Windows without Winsock adaptation
 * CRITICAL: Applications MUST call signal(SIGPIPE, SIG_IGN) during initialization
 * to prevent process termination on broken pipe errors (required on macOS/BSD).
 * Error Handling:
 * - Socket_Failed: General socket errors
 * - Socket_Closed: Connection terminated by peer
 * - Some functions return NULL/0 for non-blocking EAGAIN/EWOULDBLOCK
 * Timeouts:
 * - Global defaults configurable via Socket_timeouts_setdefaults()
 * - Per-socket overrides via Socket_timeouts_set()
 * - Applied to DNS resolution and blocking connect() paths
 */

#define T Socket_T
typedef struct T *T;

/**
 * SocketTimeouts_T - Timeout configuration for socket operations
 * @connect_timeout_ms: Connect timeout in milliseconds (0 = infinite)
 * @dns_timeout_ms: DNS resolution timeout in milliseconds (0 = infinite)
 * @operation_timeout_ms: General operation timeout in milliseconds (reserved for future use)
 */
typedef struct SocketTimeouts
{
    int connect_timeout_ms;
    int dns_timeout_ms;
    int operation_timeout_ms;
} SocketTimeouts_T;

/* Exception types */
extern Except_T Socket_Failed; /**< General socket operation failure */
extern Except_T Socket_Closed; /**< Connection closed by peer */

/**
 * Socket_new - Create a new socket
 * @domain: Address family (AF_INET, AF_INET6, etc.)
 * @type: Socket type (SOCK_STREAM, SOCK_DGRAM, etc.)
 * @protocol: Protocol (usually 0 for default)
 * Returns: New socket instance
 * Raises: Socket_Failed on error
 */
extern T Socket_new(int domain, int type, int protocol);

/**
 * SocketPair_new - Create a pair of connected Unix domain sockets
 * @type: Socket type (SOCK_STREAM or SOCK_DGRAM)
 * @socket1: Output - first socket of the pair
 * @socket2: Output - second socket of the pair
 * Raises: Socket_Failed on error
 * Thread-safe: Yes (creates new sockets)
 * Note: Creates two connected Unix domain sockets for IPC.
 * Both sockets are ready to use - no bind/connect needed.
 * Typically used for parent-child or thread communication.
 * Only supports AF_UNIX (Unix domain sockets).
 */
extern void SocketPair_new(int type, T *socket1, T *socket2);

/**
 * Socket_free - Free a socket and close the connection
 * @socket: Pointer to socket (will be set to NULL)
 */
extern void Socket_free(T *socket);

/**
 * Socket_debug_live_count - Get number of live socket instances (test-only)
 * Returns: Current count of allocated Socket_T instances that have not been freed.
 * Notes: Intended for debugging and test instrumentation to detect leaks.
 */
extern int Socket_debug_live_count(void);

/**
 * Socket_bind - Bind socket to address and port
 * @socket: Socket to bind
 * @host: IP address or NULL/"0.0.0.0" for any
 * @port: Port number (1-65535)
 * WARNING: May block 30+ seconds during DNS resolution if hostname provided.
 * Use IP addresses for non-blocking operation.
 * Raises: Socket_Failed on error
 */
extern void Socket_bind(T socket, const char *host, int port);

/**
 * Socket_listen - Listen for incoming connections
 * @socket: Bound socket
 * @backlog: Maximum pending connections
 * Raises: Socket_Failed on error
 */
extern void Socket_listen(T socket, int backlog);

/**
 * Socket_accept - Accept incoming connection
 * @socket: Listening socket
 * Returns: New socket or NULL if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Failed on error
 * Note: Socket must be non-blocking for NULL return on EAGAIN/EWOULDBLOCK
 */
extern T Socket_accept(T socket);

/**
 * Socket_connect - Connect to remote host
 * @socket: Socket to connect
 * @host: Remote IP address or hostname
 * @port: Remote port
 * WARNING: May block 30+ seconds during DNS resolution if hostname provided.
 * Use IP addresses for non-blocking operation. Can be exploited for DoS attacks
 * if untrusted hostnames are accepted.
 * Raises: Socket_Failed on error
 */
extern void Socket_connect(T socket, const char *host, int port);

/**
 * Socket_send - Send data
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (> 0)
 * Returns: Bytes sent (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 * Note: May send less than requested. Check return value.
 */
extern ssize_t Socket_send(T socket, const void *buf, size_t len);

/**
 * Socket_recv - Receive data
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (> 0)
 * Returns: Bytes received (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on peer close (recv returns 0) or ECONNRESET
 * Raises: Socket_Failed on other errors
 * Note: Return value 0 means would-block, NOT connection closed (raises exception)
 */
extern ssize_t Socket_recv(T socket, void *buf, size_t len);

/**
 * Socket_sendall - Send all data (handles partial sends)
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (> 0)
 * Returns: Total bytes sent (always equals len on success)
 * Raises: Socket_Closed on EPIPE/ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until all data is sent or an error occurs.
 * For non-blocking sockets, returns 0 if would block (EAGAIN/EWOULDBLOCK).
 * Use Socket_isconnected() to verify connection state before calling.
 */
extern ssize_t Socket_sendall(T socket, const void *buf, size_t len);

/**
 * Socket_recvall - Receive all requested data (handles partial receives)
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (> 0)
 * Returns: Total bytes received (always equals len on success)
 * Raises: Socket_Closed on peer close (recv returns 0) or ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until len bytes are received or an error occurs.
 * For non-blocking sockets, returns 0 if would block (EAGAIN/EWOULDBLOCK).
 * Use Socket_isconnected() to verify connection state before calling.
 */
extern ssize_t Socket_recvall(T socket, void *buf, size_t len);

/**
 * Socket_sendv - Scatter/gather send (writev wrapper)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes sent (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on EPIPE/ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Sends data from multiple buffers in a single system call.
 * May send less than requested. Use Socket_sendvall() for guaranteed complete send.
 */
extern ssize_t Socket_sendv(T socket, const struct iovec *iov, int iovcnt);

/**
 * Socket_recvv - Scatter/gather receive (readv wrapper)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes received (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on peer close (recv returns 0) or ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Receives data into multiple buffers in a single system call.
 * May receive less than requested. Use Socket_recvvall() for guaranteed complete receive.
 */
extern ssize_t Socket_recvv(T socket, struct iovec *iov, int iovcnt);

/**
 * Socket_sendvall - Scatter/gather send all (handles partial sends)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes sent (always equals sum of all iov_len on success)
 * Raises: Socket_Closed on EPIPE/ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until all data from all buffers is sent or an error occurs.
 * For non-blocking sockets, returns partial progress if would block.
 * Use Socket_isconnected() to verify connection state before calling.
 */
extern ssize_t Socket_sendvall(T socket, const struct iovec *iov, int iovcnt);

/**
 * Socket_recvvall - Scatter/gather receive all (handles partial receives)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes received (always equals sum of all iov_len on success)
 * Raises: Socket_Closed on peer close (recv returns 0) or ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until all requested data is received into all buffers or an error occurs.
 * For non-blocking sockets, returns partial progress if would block.
 * Use Socket_isconnected() to verify connection state before calling.
 */
extern ssize_t Socket_recvvall(T socket, struct iovec *iov, int iovcnt);

/**
 * Socket_sendfile - Zero-copy file-to-socket transfer
 * @socket: Connected socket to send to
 * @file_fd: File descriptor to read from (must be a regular file)
 * @offset: File offset to start reading from (NULL for current position)
 * @count: Number of bytes to transfer (0 for entire file from offset)
 * Returns: Total bytes transferred (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on EPIPE/ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Uses platform-specific zero-copy mechanism (sendfile/splice).
 * Falls back to read/write loop on platforms without sendfile support.
 * May transfer less than requested. Use Socket_sendfileall() for guaranteed complete transfer.
 * Platform support:
 * - Linux: Uses sendfile() system call
 * - BSD/macOS: Uses sendfile() system call (different signature)
 * - Other: Falls back to read/write loop
 */
extern ssize_t Socket_sendfile(T socket, int file_fd, off_t *offset, size_t count);

/**
 * Socket_sendfileall - Zero-copy file-to-socket transfer (handles partial transfers)
 * @socket: Connected socket to send to
 * @file_fd: File descriptor to read from (must be a regular file)
 * @offset: File offset to start reading from (NULL for current position)
 * @count: Number of bytes to transfer (0 for entire file from offset)
 * Returns: Total bytes transferred (always equals count on success)
 * Raises: Socket_Closed on EPIPE/ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until all data is transferred or an error occurs.
 * For non-blocking sockets, returns partial progress if would block.
 * Uses platform-specific zero-copy mechanism when available.
 */
extern ssize_t Socket_sendfileall(T socket, int file_fd, off_t *offset, size_t count);

/**
 * Socket_sendmsg - Send message with ancillary data (sendmsg wrapper)
 * @socket: Connected socket
 * @msg: Message structure with data, address, and ancillary data
 * @flags: Message flags (MSG_NOSIGNAL, MSG_DONTWAIT, etc.)
 * Returns: Total bytes sent (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on EPIPE/ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Allows sending data with control messages (CMSG) for advanced features
 * like file descriptor passing, credentials, IP options, etc.
 * May send less than requested. Use Socket_sendmsgall() for guaranteed complete send.
 */
extern ssize_t Socket_sendmsg(T socket, const struct msghdr *msg, int flags);

/**
 * Socket_recvmsg - Receive message with ancillary data (recvmsg wrapper)
 * @socket: Connected socket
 * @msg: Message structure for data, address, and ancillary data
 * @flags: Message flags (MSG_DONTWAIT, MSG_PEEK, etc.)
 * Returns: Total bytes received (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on peer close (recv returns 0) or ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Allows receiving data with control messages (CMSG) for advanced features
 * like file descriptor passing, credentials, IP options, etc.
 * May receive less than requested. Use Socket_recvmsgall() for guaranteed complete receive.
 */
extern ssize_t Socket_recvmsg(T socket, struct msghdr *msg, int flags);

/**
 * Socket_setnonblocking - Enable non-blocking mode
 * @socket: Socket to modify
 * Raises: Socket_Failed on error
 */
extern void Socket_setnonblocking(T socket);

/**
 * Socket_setreuseaddr - Enable address reuse
 * @socket: Socket to modify
 * Raises: Socket_Failed on error
 */
extern void Socket_setreuseaddr(T socket);

/**
 * Socket_setreuseport - Enable port reuse across sockets
 * @socket: Socket to modify
 * Raises: Socket_Failed on error (or if SO_REUSEPORT unsupported)
 */
extern void Socket_setreuseport(T socket);

/**
 * Socket_settimeout - Set socket timeout
 * @socket: Socket to modify
 * @timeout_sec: Timeout in seconds (0 to disable)
 * Sets both send and receive timeouts
 * Raises: Socket_Failed on error
 */
extern void Socket_settimeout(T socket, int timeout_sec);

/**
 * Socket_setkeepalive - Enable TCP keepalive
 * @socket: Socket to modify
 * @idle: Seconds before sending keepalive probes
 * @interval: Interval between keepalive probes
 * @count: Number of probes before declaring dead
 * Raises: Socket_Failed on error
 */
extern void Socket_setkeepalive(T socket, int idle, int interval, int count);

/**
 * Socket_setnodelay - Disable Nagle's algorithm
 * @socket: Socket to modify
 * @nodelay: 1 to disable Nagle, 0 to enable
 * Raises: Socket_Failed on error
 */
extern void Socket_setnodelay(T socket, int nodelay);

/**
 * Socket_gettimeout - Get socket timeout
 * @socket: Socket to query
 * Returns: Timeout in seconds (0 if disabled)
 * Raises: Socket_Failed on error
 * Note: Returns receive timeout (send timeout may differ)
 */
extern int Socket_gettimeout(T socket);

/**
 * Socket_getkeepalive - Get TCP keepalive configuration
 * @socket: Socket to query
 * @idle: Output - idle timeout in seconds
 * @interval: Output - interval between probes in seconds
 * @count: Output - number of probes before declaring dead
 * Raises: Socket_Failed on error
 * Note: Returns 0 for parameters not supported on this platform
 */
extern void Socket_getkeepalive(T socket, int *idle, int *interval, int *count);

/**
 * Socket_getnodelay - Get TCP_NODELAY setting
 * @socket: Socket to query
 * Returns: 1 if Nagle's algorithm is disabled, 0 if enabled
 * Raises: Socket_Failed on error
 */
extern int Socket_getnodelay(T socket);

/**
 * Socket_getrcvbuf - Get receive buffer size
 * @socket: Socket to query
 * Returns: Receive buffer size in bytes
 * Raises: Socket_Failed on error
 */
extern int Socket_getrcvbuf(T socket);

/**
 * Socket_getsndbuf - Get send buffer size
 * @socket: Socket to query
 * Returns: Send buffer size in bytes
 * Raises: Socket_Failed on error
 */
extern int Socket_getsndbuf(T socket);

/**
 * Socket_setrcvbuf - Set receive buffer size
 * @socket: Socket to modify
 * @size: Buffer size in bytes (> 0)
 * Raises: Socket_Failed on error
 * Note: The kernel may adjust the value to be within system limits.
 * Use Socket_getrcvbuf() to verify the actual size set.
 */
extern void Socket_setrcvbuf(T socket, int size);

/**
 * Socket_setsndbuf - Set send buffer size
 * @socket: Socket to modify
 * @size: Buffer size in bytes (> 0)
 * Raises: Socket_Failed on error
 * Note: The kernel may adjust the value to be within system limits.
 * Use Socket_getsndbuf() to verify the actual size set.
 */
extern void Socket_setsndbuf(T socket, int size);

/**
 * Socket_setcongestion - Set TCP congestion control algorithm
 * @socket: Socket to modify
 * @algorithm: Algorithm name (e.g., "cubic", "reno", "bbr")
 * Raises: Socket_Failed on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: Only available on Linux 2.6.13+. Common algorithms:
 * - "cubic" (default on many Linux systems)
 * - "reno" (classic TCP)
 * - "bbr" (Google BBR, Linux 4.9+)
 * - "bbr2" (BBR v2, Linux 4.20+)
 * Use Socket_getcongestion() to query current algorithm.
 */
extern void Socket_setcongestion(T socket, const char *algorithm);

/**
 * Socket_getcongestion - Get TCP congestion control algorithm
 * @socket: Socket to query
 * @algorithm: Output buffer for algorithm name
 * @len: Buffer length
 * Returns: 0 on success, -1 on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: Only available on Linux 2.6.13+.
 * The algorithm name is written to the provided buffer.
 */
extern int Socket_getcongestion(T socket, char *algorithm, size_t len);

/**
 * Socket_setfastopen - Enable TCP Fast Open
 * @socket: Socket to modify
 * @enable: 1 to enable, 0 to disable
 * Raises: Socket_Failed on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: TCP Fast Open allows sending data in SYN packet.
 * Only available on Linux 3.7+, FreeBSD 10.0+, macOS 10.11+.
 * Must be set before connect() or listen().
 * Use Socket_getfastopen() to query current setting.
 */
extern void Socket_setfastopen(T socket, int enable);

/**
 * Socket_getfastopen - Get TCP Fast Open setting
 * @socket: Socket to query
 * Returns: 1 if enabled, 0 if disabled, -1 on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: Only available on platforms that support TCP Fast Open.
 */
extern int Socket_getfastopen(T socket);

/**
 * Socket_setusertimeout - Set TCP user timeout
 * @socket: Socket to modify
 * @timeout_ms: Timeout in milliseconds (> 0)
 * Raises: Socket_Failed on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: TCP user timeout controls how long to wait for ACK before
 * closing connection. Only available on Linux 2.6.37+.
 * Use Socket_getusertimeout() to query current timeout.
 */
extern void Socket_setusertimeout(T socket, unsigned int timeout_ms);

/**
 * Socket_getusertimeout - Get TCP user timeout
 * @socket: Socket to query
 * Returns: Timeout in milliseconds, or 0 on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: Only available on Linux 2.6.37+.
 */
extern unsigned int Socket_getusertimeout(T socket);

/**
 * Socket_isconnected - Check if socket is connected
 * @socket: Socket to check
 * Returns: 1 if connected, 0 if not connected
 * Thread-safe: Yes (operates on single socket)
 * Note: Uses getpeername() to determine connection state.
 * For TCP sockets, checks if peer address is available.
 */
extern int Socket_isconnected(T socket);

/**
 * Socket_isbound - Check if socket is bound to an address
 * @socket: Socket to check
 * Returns: 1 if bound, 0 if not bound
 * Thread-safe: Yes (operates on single socket)
 * Note: Uses getsockname() to determine binding state.
 * A socket is bound if getsockname() succeeds and returns a valid address.
 * Wildcard addresses (0.0.0.0 or ::) still count as bound.
 */
extern int Socket_isbound(T socket);

/**
 * Socket_islistening - Check if socket is listening for connections
 * @socket: Socket to check
 * Returns: 1 if listening, 0 if not listening
 * Thread-safe: Yes (operates on single socket)
 * Note: Checks if socket is bound and not connected.
 * A socket is listening if it's bound but has no peer address.
 */
extern int Socket_islistening(T socket);

/**
 * Socket_shutdown - Disable further sends and/or receives
 * @socket: Connected socket
 * @how: Shutdown mode (SHUT_RD, SHUT_WR, or SHUT_RDWR)
 * Raises: Socket_Failed on error
 * Thread-safe: No (callers must synchronize concurrent access to the socket)
 */
extern void Socket_shutdown(T socket, int how);

/**
 * Socket_setcloexec - Control close-on-exec flag
 * @socket: Socket to modify
 * @enable: 1 to enable CLOEXEC, 0 to disable
 * Raises: Socket_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: By default, all sockets have CLOEXEC enabled. This function
 * allows disabling it if you need to pass the socket to a child process.
 */
extern void Socket_setcloexec(T socket, int enable);

/**
 * Socket_timeouts_get - Retrieve per-socket timeout configuration
 * @socket: Socket instance
 * @timeouts: Output timeout structure
 * Returns: Nothing
 */
extern void Socket_timeouts_get(const T socket, SocketTimeouts_T *timeouts);

/**
 * Socket_timeouts_set - Set per-socket timeout configuration
 * @socket: Socket instance
 * @timeouts: Timeout configuration (NULL to reset to defaults)
 * Returns: Nothing
 */
extern void Socket_timeouts_set(T socket, const SocketTimeouts_T *timeouts);

/**
 * Socket_timeouts_getdefaults - Get global default timeouts
 * @timeouts: Output timeout structure containing current defaults
 * Returns: Nothing
 */
extern void Socket_timeouts_getdefaults(SocketTimeouts_T *timeouts);

/**
 * Socket_timeouts_setdefaults - Set global default timeouts
 * @timeouts: New default timeout configuration
 * Returns: Nothing
 */
extern void Socket_timeouts_setdefaults(const SocketTimeouts_T *timeouts);

/**
 * Socket_fd - Get underlying file descriptor
 * @socket: Socket instance
 * Returns: File descriptor
 */
extern int Socket_fd(const T socket);

/**
 * Socket_getpeeraddr - Get peer IP address
 * @socket: Connected socket
 * Returns: IP address string (IPv4/IPv6) or "(unknown)" if unavailable
 * Note: Returns "(unknown)" if address info unavailable during accept/connect.
 * String is owned by socket, must not be freed/modified. Valid until socket freed.
 */
extern const char *Socket_getpeeraddr(const T socket);

/**
 * Socket_getpeerport - Get peer port number
 * @socket: Connected socket
 * Returns: Port number (1-65535) or 0 if unavailable
 * Note: Returns 0 if port info unavailable during accept/connect.
 */
extern int Socket_getpeerport(const T socket);

/**
 * Socket_getlocaladdr - Get local IP address
 * @socket: Socket instance
 * Returns: IP address string (IPv4/IPv6) or "(unknown)" if unavailable
 * Note: Returns "(unknown)" if address info unavailable. String is owned by
 * socket, must not be freed/modified. Valid until socket freed.
 */
extern const char *Socket_getlocaladdr(const T socket);

/**
 * Socket_getlocalport - Get local port number
 * @socket: Socket instance
 * Returns: Port number (1-65535) or 0 if unavailable
 */
extern int Socket_getlocalport(const T socket);

/**
 * Socket_bind_unix - Bind to Unix domain socket path
 * @socket: Socket to bind (AF_UNIX)
 * @path: Socket file path
 * Raises: Socket_Failed on error
 * Note: Fails with EADDRINUSE if path exists. Max path length ~108 bytes.
 * Supports abstract namespace sockets on Linux (path starting with '@').
 */
extern void Socket_bind_unix(T socket, const char *path);

/**
 * Socket_connect_unix - Connect to Unix domain socket path
 * @socket: Socket to connect (AF_UNIX)
 * @path: Socket file path
 * Raises: Socket_Failed on error
 * Note: Supports abstract namespace sockets on Linux (path starting with '@').
 */
extern void Socket_connect_unix(T socket, const char *path);

/**
 * Socket_getpeerpid - Get peer process ID (Linux only)
 * @socket: Connected Unix domain socket
 * Returns: Peer process ID, or -1 if unavailable
 * Note: Only works on Linux with SO_PEERCRED.
 * Returns -1 on other platforms or non-Unix sockets.
 */
extern int Socket_getpeerpid(const T socket);

/**
 * Socket_getpeeruid - Get peer user ID (Linux only)
 * @socket: Connected Unix domain socket
 * Returns: Peer user ID, or (uid_t)-1 if unavailable
 * Note: Only works on Linux with SO_PEERCRED.
 * Returns -1 on other platforms or non-Unix sockets.
 */
extern int Socket_getpeeruid(const T socket);

/**
 * Socket_getpeergid - Get peer group ID (Linux only)
 * @socket: Connected Unix domain socket
 * Returns: Peer group ID, or (gid_t)-1 if unavailable
 * Note: Only works on Linux with SO_PEERCRED.
 * Returns -1 on other platforms or non-Unix sockets.
 */
extern int Socket_getpeergid(const T socket);

/**
 * Socket_bind_async - Start async DNS resolution for bind
 * @dns: DNS resolver instance
 * @socket: Socket to bind
 * @host: IP address or hostname (NULL for any)
 * @port: Port number (1-65535)
 * Returns: DNS request handle
 * Raises: Socket_Failed on error
 * Starts async DNS resolution. Use SocketDNS_getresult() to check completion,
 * then call Socket_bind_with_addrinfo() to perform bind.
 * For non-blocking operation with SocketPoll:
 *   SocketDNS_Request_T req = Socket_bind_async(dns, socket, host, port);
 *   // In event loop when DNS completes:
 *   struct addrinfo *res = SocketDNS_getresult(dns, req);
 *   if (res) Socket_bind_with_addrinfo(socket, res);
 */
extern SocketDNS_Request_T Socket_bind_async(SocketDNS_T dns, T socket, const char *host, int port);

/**
 * Socket_bind_async_cancel - Cancel pending async bind resolution
 * @dns: DNS resolver instance
 * @req: Request handle returned by Socket_bind_async
 * Returns: Nothing
 */
extern void Socket_bind_async_cancel(SocketDNS_T dns, SocketDNS_Request_T req);

/**
 * Socket_connect_async - Start async DNS resolution for connect
 * @dns: DNS resolver instance
 * @socket: Socket to connect
 * @host: Remote IP address or hostname
 * @port: Remote port (1-65535)
 * Returns: DNS request handle
 * Raises: Socket_Failed on error
 * Starts async DNS resolution. Use SocketDNS_getresult() to check completion,
 * then call Socket_connect_with_addrinfo() to perform connect.
 */
extern SocketDNS_Request_T Socket_connect_async(SocketDNS_T dns, T socket, const char *host, int port);

/**
 * Socket_connect_async_cancel - Cancel pending async connect resolution
 * @dns: DNS resolver instance
 * @req: Request handle returned by Socket_connect_async
 * Returns: Nothing
 */
extern void Socket_connect_async_cancel(SocketDNS_T dns, SocketDNS_Request_T req);

/**
 * Socket_bind_with_addrinfo - Bind socket using resolved address
 * @socket: Socket to bind
 * @res: Resolved addrinfo result from DNS resolution
 * Raises: Socket_Failed on error
 * Performs bind operation using pre-resolved address. Tries each address
 * in the result list until one succeeds.
 */
extern void Socket_bind_with_addrinfo(T socket, struct addrinfo *res);

/**
 * Socket_connect_with_addrinfo - Connect socket using resolved address
 * @socket: Socket to connect
 * @res: Resolved addrinfo result from DNS resolution
 * Raises: Socket_Failed on error
 * Performs connect operation using pre-resolved address. Tries each address
 * in the result list until one succeeds.
 */
extern void Socket_connect_with_addrinfo(T socket, struct addrinfo *res);

#undef T
#endif
