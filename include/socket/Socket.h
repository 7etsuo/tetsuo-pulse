#ifndef SOCKET_INCLUDED
#define SOCKET_INCLUDED

#include "core/Except.h"
#include "dns/SocketDNS.h"

/**
 * Socket Abstraction Layer
 *
 * High-level, exception-based TCP/IP socket interface.
 *
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - IPv6 support in kernel for dual-stack sockets
 * - POSIX threads for thread-safe error reporting
 * - NOT portable to Windows without Winsock adaptation
 *
 * CRITICAL: Applications MUST call signal(SIGPIPE, SIG_IGN) during initialization
 * to prevent process termination on broken pipe errors (required on macOS/BSD).
 *
 * Error Handling:
 * - Socket_Failed: General socket errors
 * - Socket_Closed: Connection terminated by peer
 * - Some functions return NULL/0 for non-blocking EAGAIN/EWOULDBLOCK
 */

#define T Socket_T
typedef struct T *T;

/* Exception types */
extern Except_T Socket_Failed; /**< General socket operation failure */
extern Except_T Socket_Closed; /**< Connection closed by peer */

/**
 * Socket_new - Create a new socket
 * @domain: Address family (AF_INET, AF_INET6, etc.)
 * @type: Socket type (SOCK_STREAM, SOCK_DGRAM, etc.)
 * @protocol: Protocol (usually 0 for default)
 *
 * Returns: New socket instance
 * Raises: Socket_Failed on error
 */
extern T Socket_new(int domain, int type, int protocol);

/**
 * Socket_free - Free a socket and close the connection
 * @socket: Pointer to socket (will be set to NULL)
 */
extern void Socket_free(T *socket);

/**
 * Socket_bind - Bind socket to address and port
 * @socket: Socket to bind
 * @host: IP address or NULL/"0.0.0.0" for any
 * @port: Port number (1-65535)
 *
 * WARNING: May block 30+ seconds during DNS resolution if hostname provided.
 * Use IP addresses for non-blocking operation.
 *
 * Raises: Socket_Failed on error
 */
extern void Socket_bind(T socket, const char *host, int port);

/**
 * Socket_listen - Listen for incoming connections
 * @socket: Bound socket
 * @backlog: Maximum pending connections
 *
 * Raises: Socket_Failed on error
 */
extern void Socket_listen(T socket, int backlog);

/**
 * Socket_accept - Accept incoming connection
 * @socket: Listening socket
 *
 * Returns: New socket or NULL if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Failed on error
 *
 * Note: Socket must be non-blocking for NULL return on EAGAIN/EWOULDBLOCK
 */
extern T Socket_accept(T socket);

/**
 * Socket_connect - Connect to remote host
 * @socket: Socket to connect
 * @host: Remote IP address or hostname
 * @port: Remote port
 *
 * WARNING: May block 30+ seconds during DNS resolution if hostname provided.
 * Use IP addresses for non-blocking operation. Can be exploited for DoS attacks
 * if untrusted hostnames are accepted.
 *
 * Raises: Socket_Failed on error
 */
extern void Socket_connect(T socket, const char *host, int port);

/**
 * Socket_send - Send data
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (> 0)
 *
 * Returns: Bytes sent (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 *
 * Note: May send less than requested. Check return value.
 */
extern ssize_t Socket_send(T socket, const void *buf, size_t len);

/**
 * Socket_recv - Receive data
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (> 0)
 *
 * Returns: Bytes received (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on peer close (recv returns 0) or ECONNRESET
 * Raises: Socket_Failed on other errors
 *
 * Note: Return value 0 means would-block, NOT connection closed (raises exception)
 */
extern ssize_t Socket_recv(T socket, void *buf, size_t len);

/**
 * Socket_setnonblocking - Enable non-blocking mode
 * @socket: Socket to modify
 *
 * Raises: Socket_Failed on error
 */
extern void Socket_setnonblocking(T socket);

/**
 * Socket_setreuseaddr - Enable address reuse
 * @socket: Socket to modify
 *
 * Raises: Socket_Failed on error
 */
extern void Socket_setreuseaddr(T socket);

/**
 * Socket_settimeout - Set socket timeout
 * @socket: Socket to modify
 * @timeout_sec: Timeout in seconds (0 to disable)
 *
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
 *
 * Raises: Socket_Failed on error
 */
extern void Socket_setkeepalive(T socket, int idle, int interval, int count);

/**
 * Socket_setnodelay - Disable Nagle's algorithm
 * @socket: Socket to modify
 * @nodelay: 1 to disable Nagle, 0 to enable
 *
 * Raises: Socket_Failed on error
 */
extern void Socket_setnodelay(T socket, int nodelay);

/**
 * Socket_fd - Get underlying file descriptor
 * @socket: Socket instance
 *
 * Returns: File descriptor
 */
extern int Socket_fd(const T socket);

/**
 * Socket_getpeeraddr - Get peer IP address
 * @socket: Connected socket
 *
 * Returns: IP address string (IPv4/IPv6) or "(unknown)" if unavailable
 *
 * Note: Returns "(unknown)" if address info unavailable during accept/connect.
 * String is owned by socket, must not be freed/modified. Valid until socket freed.
 */
extern const char *Socket_getpeeraddr(const T socket);

/**
 * Socket_getpeerport - Get peer port number
 * @socket: Connected socket
 *
 * Returns: Port number (1-65535) or 0 if unavailable
 *
 * Note: Returns 0 if port info unavailable during accept/connect.
 */
extern int Socket_getpeerport(const T socket);

/**
 * Socket_bind_unix - Bind to Unix domain socket path
 * @socket: Socket to bind (AF_UNIX)
 * @path: Socket file path
 *
 * Raises: Socket_Failed on error
 *
 * Note: Fails with EADDRINUSE if path exists. Max path length ~108 bytes.
 * Supports abstract namespace sockets on Linux (path starting with '@').
 */
extern void Socket_bind_unix(T socket, const char *path);

/**
 * Socket_connect_unix - Connect to Unix domain socket path
 * @socket: Socket to connect (AF_UNIX)
 * @path: Socket file path
 *
 * Raises: Socket_Failed on error
 *
 * Note: Supports abstract namespace sockets on Linux (path starting with '@').
 */
extern void Socket_connect_unix(T socket, const char *path);

/**
 * Socket_getpeerpid - Get peer process ID (Linux only)
 * @socket: Connected Unix domain socket
 *
 * Returns: Peer process ID, or -1 if unavailable
 *
 * Note: Only works on Linux with SO_PEERCRED.
 * Returns -1 on other platforms or non-Unix sockets.
 */
extern int Socket_getpeerpid(const T socket);

/**
 * Socket_getpeeruid - Get peer user ID (Linux only)
 * @socket: Connected Unix domain socket
 *
 * Returns: Peer user ID, or (uid_t)-1 if unavailable
 *
 * Note: Only works on Linux with SO_PEERCRED.
 * Returns -1 on other platforms or non-Unix sockets.
 */
extern int Socket_getpeeruid(const T socket);

/**
 * Socket_getpeergid - Get peer group ID (Linux only)
 * @socket: Connected Unix domain socket
 *
 * Returns: Peer group ID, or (gid_t)-1 if unavailable
 *
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
 *
 * Returns: DNS request handle
 * Raises: Socket_Failed on error
 *
 * Starts async DNS resolution. Use SocketDNS_getresult() to check completion,
 * then call Socket_bind_with_addrinfo() to perform bind.
 *
 * For non-blocking operation with SocketPoll:
 *   SocketDNS_Request_T req = Socket_bind_async(dns, socket, host, port);
 *   // In event loop when DNS completes:
 *   struct addrinfo *res = SocketDNS_getresult(dns, req);
 *   if (res) Socket_bind_with_addrinfo(socket, res);
 */
extern SocketDNS_Request_T Socket_bind_async(SocketDNS_T dns, T socket, const char *host, int port);

/**
 * Socket_connect_async - Start async DNS resolution for connect
 * @dns: DNS resolver instance
 * @socket: Socket to connect
 * @host: Remote IP address or hostname
 * @port: Remote port (1-65535)
 *
 * Returns: DNS request handle
 * Raises: Socket_Failed on error
 *
 * Starts async DNS resolution. Use SocketDNS_getresult() to check completion,
 * then call Socket_connect_with_addrinfo() to perform connect.
 */
extern SocketDNS_Request_T Socket_connect_async(SocketDNS_T dns, T socket, const char *host, int port);

/**
 * Socket_bind_with_addrinfo - Bind socket using resolved address
 * @socket: Socket to bind
 * @res: Resolved addrinfo result from DNS resolution
 *
 * Raises: Socket_Failed on error
 *
 * Performs bind operation using pre-resolved address. Tries each address
 * in the result list until one succeeds.
 */
extern void Socket_bind_with_addrinfo(T socket, struct addrinfo *res);

/**
 * Socket_connect_with_addrinfo - Connect socket using resolved address
 * @socket: Socket to connect
 * @res: Resolved addrinfo result from DNS resolution
 *
 * Raises: Socket_Failed on error
 *
 * Performs connect operation using pre-resolved address. Tries each address
 * in the result list until one succeeds.
 */
extern void Socket_connect_with_addrinfo(T socket, struct addrinfo *res);

#undef T
#endif
