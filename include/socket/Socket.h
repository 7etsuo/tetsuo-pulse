#ifndef SOCKET_INCLUDED
#define SOCKET_INCLUDED

#include "core/Except.h"
#include "core/SocketConfig.h"  /* For SocketTimeouts_T */
#include "dns/SocketDNS.h"
#include "socket/SocketUnix.h"  /* For Unix domain ops */
#include "socket/Socket-state.h"   /* State query functions */
#include "socket/Socket-options.h" /* Socket option functions */
#include "socket/Socket-async.h"   /* Async DNS operations */

/**
 * Socket Abstraction Layer
 * High-level, exception-based TCP/IP/Unix domain socket interface.
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant system (Linux, BSD, macOS, etc.)
 * - IPv6 support in kernel (for dual-stack sockets)
 * - POSIX threads (pthread) for thread-safe error reporting
 * - NOT portable to Windows without Winsock adaptation
 * CRITICAL: Applications MUST call signal(SIGPIPE, SIG_IGN) during
 * initialization to prevent process termination on broken pipe errors
 * (required on macOS/BSD). Error Handling:
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

/* SocketTimeouts_T defined in SocketConfig.h */

/* Exception types */
extern const Except_T Socket_Failed; /**< General socket operation failure */
extern const Except_T Socket_Closed; /**< Connection closed by peer */

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
 * Typically used for parent-child or thread communication.
 * Only supports AF_UNIX (Unix domain sockets).
 * Abstract namespace paths (starting with '@') are Linux-only.
 * On macOS/BSD, use regular filesystem paths; attempts with '@' will log a
 * warning and fail.
 */
extern void SocketPair_new (int type, T *socket1, T *socket2);

/**
 * Socket_free - Free a socket and close the connection
 * @socket: Pointer to socket (will be set to NULL)
 */
extern void Socket_free (T *socket);

/**
 * Socket_debug_live_count - Get number of live socket instances (test-only)
 * Returns: Current count of allocated Socket_T instances that have not been
 * freed. Notes: Intended for debugging and test instrumentation to detect
 * leaks.
 */
extern int Socket_debug_live_count (void);

/**
 * Socket_bind - Bind socket to address and port
 * @socket: Socket to bind
 * @host: IP address or NULL/"0.0.0.0" for any
 * @port: Port number (1 to SOCKET_MAX_PORT)
 * WARNING: May block 30+ seconds during DNS resolution if hostname provided.
 * Use IP addresses for non-blocking operation.
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
 * Socket_new_from_fd - Create Socket_T from existing file descriptor
 * @fd: File descriptor (must be valid socket, will be set to non-blocking)
 * Returns: New Socket_T instance or NULL on failure
 * Raises: Socket_Failed on error
 * Thread-safe: Yes - returns new instance
 * Note: Used internally for batch accept operations. The socket must
 * already be a valid socket file descriptor. Sets socket to non-blocking mode.
 */
extern T Socket_new_from_fd (int fd);

/**
 * Socket_accept - Accept incoming connection
 * @socket: Listening socket
 * Returns: New socket or NULL if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Failed on error
 * Note: Socket must be non-blocking for NULL return on EAGAIN/EWOULDBLOCK
 */
extern T Socket_accept (T socket);

/**
 * Socket_connect - Connect to remote host
 * @socket: Socket to connect
 * @host: Remote IP address or hostname
 * @port: Remote port
 * WARNING: May block 30+ seconds during DNS resolution if hostname provided.
 * Use IP addresses for non-blocking operation. Can be exploited for DoS
 * attacks if untrusted hostnames are accepted. Raises: Socket_Failed on error
 */
extern void Socket_connect (T socket, const char *host, int port);

/**
 * Socket_send - Send data
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (> 0)
 * Returns: Bytes sent (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on other errors
 * Note: May send less than requested. Check return value.
 */
extern ssize_t Socket_send (T socket, const void *buf, size_t len);

/**
 * Socket_recv - Receive data
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (> 0)
 * Returns: Bytes received (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on peer close (recv returns 0) or ECONNRESET
 * Raises: Socket_Failed on other errors
 * Note: Return value 0 means would-block, NOT connection closed (raises
 * exception)
 */
extern ssize_t Socket_recv (T socket, void *buf, size_t len);

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
extern ssize_t Socket_sendall (T socket, const void *buf, size_t len);

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
extern ssize_t Socket_recvall (T socket, void *buf, size_t len);

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
 * May send less than requested. Use Socket_sendvall() for guaranteed complete
 * send.
 */
extern ssize_t Socket_sendv (T socket, const struct iovec *iov, int iovcnt);

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
 * May receive less than requested. Use Socket_recvvall() for guaranteed
 * complete receive.
 */
extern ssize_t Socket_recvv (T socket, struct iovec *iov, int iovcnt);

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
extern ssize_t Socket_sendvall (T socket, const struct iovec *iov, int iovcnt);

/**
 * Socket_recvvall - Scatter/gather receive all (handles partial receives)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes received (always equals sum of all iov_len on success)
 * Raises: Socket_Closed on peer close (recv returns 0) or ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until all requested data is received into all buffers or an
 * error occurs. For non-blocking sockets, returns partial progress if would
 * block. Use Socket_isconnected() to verify connection state before calling.
 */
extern ssize_t Socket_recvvall (T socket, struct iovec *iov, int iovcnt);

/**
 * Socket_sendfile - Zero-copy file-to-socket transfer
 * @socket: Connected socket to send to
 * @file_fd: File descriptor to read from (must be a regular file)
 * @offset: File offset to start reading from (NULL for current position)
 * @count: Number of bytes to transfer (0 for entire file from offset)
 * Returns: Total bytes transferred (> 0) or 0 if would block
 * (EAGAIN/EWOULDBLOCK) Raises: Socket_Closed on EPIPE/ECONNRESET Raises:
 * Socket_Failed on other errors Thread-safe: Yes (operates on single socket)
 * Note: Uses platform-specific zero-copy mechanism (sendfile/splice).
 * Falls back to read/write loop on platforms without sendfile support.
 * May transfer less than requested. Use Socket_sendfileall() for guaranteed
 * complete transfer. Platform support:
 * - Linux: Uses sendfile() system call
 * - BSD/macOS: Uses sendfile() system call (different signature)
 * - Other: Falls back to read/write loop
 */
extern ssize_t Socket_sendfile (T socket, int file_fd, off_t *offset,
                                size_t count);

/**
 * Socket_sendfileall - Zero-copy file-to-socket transfer (handles partial
 * transfers)
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
extern ssize_t Socket_sendfileall (T socket, int file_fd, off_t *offset,
                                   size_t count);

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
 * May send less than requested. Use Socket_sendmsgall() for guaranteed
 * complete send.
 */
extern ssize_t Socket_sendmsg (T socket, const struct msghdr *msg, int flags);

/**
 * Socket_recvmsg - Receive message with ancillary data (recvmsg wrapper)
 * @socket: Connected socket
 * @msg: Message structure for data, address, and ancillary data
 * @flags: Message flags (MSG_DONTWAIT, MSG_PEEK, etc.)
 * Returns: Total bytes received (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on peer close (recv returns 0) or ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Allows receiving data with control messages (CMSG) for advanced
 * features like file descriptor passing, credentials, IP options, etc. May
 * receive less than requested. Use Socket_recvmsgall() for guaranteed complete
 * receive.
 */
extern ssize_t Socket_recvmsg (T socket, struct msghdr *msg, int flags);




#undef T
#endif
