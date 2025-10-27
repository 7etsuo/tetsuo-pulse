#ifndef SOCKET_INCLUDED
#define SOCKET_INCLUDED

#include "Except.h"

/**
 * Socket Abstraction Layer
 *
 * Provides a high-level, exception-based interface for TCP/IP sockets.
 * All functions use exceptions for error handling, making code cleaner
 * and more robust than traditional error code checking.
 *
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS, etc.)
 * - IPv6 support in kernel (for dual-stack sockets)
 * - POSIX threads (pthread) for thread-safe error reporting
 * - NOT portable to Windows without Winsock adaptation layer
 * - getaddrinfo() for DNS resolution (POSIX.1-2001)
 *
 * Features:
 * - Automatic resource management
 * - Non-blocking I/O support
 * - Thread-safe error reporting
 * - IPv4 and IPv6 dual-stack support
 *
 * CRITICAL SETUP REQUIREMENTS:
 * =============================================================================
 * Applications MUST ignore SIGPIPE by calling signal(SIGPIPE, SIG_IGN) during
 * initialization. This prevents process termination on broken pipe errors.
 *
 * Example:
 *   signal(SIGPIPE, SIG_IGN);  // Add to main() before using sockets
 *
 * This is REQUIRED for correct operation on platforms where MSG_NOSIGNAL is
 * not available (e.g., macOS, older BSD). Failure to ignore SIGPIPE will cause
 * the process to terminate when writing to a closed socket.
 * =============================================================================
 *
 * Error Handling:
 * - Most functions raise Socket_Failed on errors or Socket_Closed when
 *   the connection is terminated by the peer
 * - Some functions (Socket_accept, Socket_send, Socket_recv) may return
 *   NULL/0 for non-blocking operations when they would block (EAGAIN/EWOULDBLOCK)
 * - Check individual function documentation for specific behavior
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
 * Raises: Socket_Failed on error
 *
 * WARNING: This function may block for extended periods (30+ seconds) during
 * DNS resolution if hostname is provided. For non-blocking operation, use
 * IP addresses directly or perform DNS resolution separately.
 *
 * All parameters are validated at runtime for safety with user input.
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
 * Returns: New socket for the connection, or NULL if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Failed on error (other than EAGAIN/EWOULDBLOCK)
 *
 * Note: Socket must be in non-blocking mode for NULL return on would-block
 */
extern T Socket_accept(T socket);

/**
 * Socket_connect - Connect to remote host
 * @socket: Socket to connect
 * @host: Remote IP address or hostname
 * @port: Remote port
 *
 * Raises: Socket_Failed on error
 *
 * WARNING: This function may block for extended periods (30+ seconds) during
 * DNS resolution if hostname is provided. For non-blocking operation, use
 * IP addresses directly or perform DNS resolution separately. This blocking
 * can be exploited for DoS attacks if untrusted hostnames are accepted.
 *
 * Note: This function validates all user input at runtime (external API).
 *       Host and port are checked before use. Safe for untrusted input.
 */
extern void Socket_connect(T socket, const char *host, int port);

/**
 * Socket_send - Send data
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (must be > 0)
 *
 * Returns: Number of bytes sent (> 0), or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on EPIPE or ECONNRESET
 * Raises: Socket_Failed on other errors
 *
 * Note: May send less than requested length. Caller should check return value.
 */
extern ssize_t Socket_send(T socket, const void *buf, size_t len);

/**
 * Socket_recv - Receive data
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (must be > 0)
 *
 * Returns: Number of bytes received (> 0), or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed if peer closes connection (recv returns 0) or on ECONNRESET
 * Raises: Socket_Failed on other errors
 *
 * Note: Return value of 0 means would-block, NOT connection closed (that raises exception)
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
 * Returns: IP address string (IPv4 or IPv6), or "(unknown)" if unavailable
 *
 * Note: Returns "(unknown)" if address info could not be obtained during accept/connect.
 *       Always returns a valid non-NULL string - safe to use directly in printf.
 *       The returned string is owned by the socket and must NOT be freed or modified.
 *       It remains valid until the socket is freed.
 */
extern const char *Socket_getpeeraddr(const T socket);

/**
 * Socket_getpeerport - Get peer port number
 * @socket: Connected socket
 *
 * Returns: Port number (1-65535), or 0 if unavailable
 *
 * Note: Returns 0 if port info could not be obtained during accept/connect.
 *       0 is a valid return value indicating unknown port.
 */
extern int Socket_getpeerport(const T socket);

/**
 * Socket_bind_unix - Bind to Unix domain socket path
 * @socket: Socket to bind (must be AF_UNIX)
 * @path: Socket file path
 *
 * Raises: Socket_Failed on error
 *
 * Note: If path already exists, bind will fail with EADDRINUSE.
 * Consider unlinking the path first if you want to reuse it.
 * Maximum path length is typically 108 bytes (UNIX_PATH_MAX).
 * Supports abstract namespace sockets on Linux (path starting with '@').
 */
extern void Socket_bind_unix(T socket, const char *path);

/**
 * Socket_connect_unix - Connect to Unix domain socket path
 * @socket: Socket to connect (must be AF_UNIX)
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

#undef T
#endif
