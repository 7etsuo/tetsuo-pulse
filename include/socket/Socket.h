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
