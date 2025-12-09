#ifndef SOCKETDGRAM_INCLUDED
#define SOCKETDGRAM_INCLUDED

#include "core/Except.h"
#include "socket/SocketCommon.h" /* For SocketBase_T and Unix support */
#include <stddef.h>
#include <sys/socket.h>

/**
 * @file SocketDgram.h
 * @ingroup core_io
 * @brief High-level UDP/datagram socket interface with multicast and broadcast
 * support.
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
 * @see Socket_T for TCP and Unix domain sockets.
 * @see SocketDgram_new() for socket creation.
 * @see SocketDgram_sendto() for connectionless sending.
 */

#define T SocketDgram_T
typedef struct T *T;

/* Exception types */
extern const Except_T
    SocketDgram_Failed; /**< General datagram socket operation failure */

/**
 * SocketDgram_new - Create a new UDP socket
 * @domain: Address family (AF_INET, AF_INET6, etc.)
 * @protocol: Protocol (usually 0 for default UDP)
 * Returns: New datagram socket instance
 * Raises: SocketDgram_Failed on error
 * Note: domain is typically AF_INET (IPv4) or AF_INET6 (IPv6)
 */
extern T SocketDgram_new (int domain, int protocol);

/**
 * SocketDgram_free - Free a socket and close the connection
 * @socket: Pointer to socket (will be set to NULL)
 */
extern void SocketDgram_free (T *socket);

/**
 * SocketDgram_bind - Bind socket to address and port
 * @socket: Socket to bind
 * @host: IP address or NULL/"0.0.0.0" for any
 * @port: Port number (1 to SOCKET_MAX_PORT)
 * Raises: SocketDgram_Failed on error
 * WARNING: This function may block during DNS resolution if hostname is
 * provided. For non-blocking operation, use IP addresses directly. All
 * parameters are validated at runtime for safety with user input.
 */
extern void SocketDgram_bind (T socket, const char *host, int port);

/**
 * SocketDgram_connect - Set default destination for socket
 * @socket: Socket to connect
 * @host: Remote IP address or hostname
 * @port: Remote port
 * Raises: SocketDgram_Failed on error
 * WARNING: This function may block during DNS resolution if hostname is
 * provided. Note: "Connect" for UDP means setting a default destination. After
 * connecting, you can use send/recv instead of sendto/recvfrom. The socket
 * only accepts packets from the connected address. You can still use
 * sendto/recvfrom to override the default destination.
 */
extern void SocketDgram_connect (T socket, const char *host, int port);

/**
 * SocketDgram_sendto - Send datagram to specific address
 * @socket: Socket to send from
 * @buf: Data to send
 * @len: Length of data (must be > 0)
 * @host: Destination IP address or hostname
 * @port: Destination port
 * Returns: Number of bytes sent (> 0), or 0 if would block
 * (EAGAIN/EWOULDBLOCK) Raises: SocketDgram_Failed on error WARNING: This
 * function may block during DNS resolution if hostname is provided. Note: UDP
 * sends complete datagrams. If len > MTU, fragmentation may occur. Recommended
 * to keep len <= 1472 bytes to avoid fragmentation (1500 MTU - headers).
 * Unlike TCP, send may return less than len only on would-block, not partial
 * sends.
 */
extern ssize_t SocketDgram_sendto (T socket, const void *buf, size_t len,
                                   const char *host, int port);

/**
 * SocketDgram_recvfrom - Receive datagram and get sender address
 * @socket: Socket to receive from
 * @buf: Buffer for received data
 * @len: Buffer size (must be > 0)
 * @host: Output - sender IP address (buffer must be >= 46 bytes for IPv6)
 * @host_len: Size of host buffer
 * @port: Output - sender port number
 * Returns: Number of bytes received (> 0), or 0 if would block
 * (EAGAIN/EWOULDBLOCK) Raises: SocketDgram_Failed on error Note: UDP is
 * message-oriented. If buffer is too small, data is truncated. Recommended
 * buffer size >= 65507 bytes (max UDP payload) to avoid truncation. Common
 * buffer sizes: 8192 (8KB), 65536 (64KB). The host parameter receives the
 * sender's IP address as a string. The port parameter receives the sender's
 * port number.
 */
extern ssize_t SocketDgram_recvfrom (T socket, void *buf, size_t len,
                                     char *host, size_t host_len, int *port);

/**
 * SocketDgram_send - Send to default destination (connected socket)
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (must be > 0)
 * Returns: Number of bytes sent (> 0), or 0 if would block
 * (EAGAIN/EWOULDBLOCK) Raises: SocketDgram_Failed on error Note: Socket must
 * be connected via SocketDgram_connect() first.
 */
extern ssize_t SocketDgram_send (T socket, const void *buf, size_t len);

/**
 * SocketDgram_recv - Receive from default source (connected socket)
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (must be > 0)
 * Returns: Number of bytes received (> 0), or 0 if would block
 * (EAGAIN/EWOULDBLOCK) Raises: SocketDgram_Failed on error Note: Socket must
 * be connected via SocketDgram_connect() first. Only accepts packets from the
 * connected address.
 */
extern ssize_t SocketDgram_recv (T socket, void *buf, size_t len);

/**
 * SocketDgram_sendall - Send all data (handles partial sends)
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (> 0)
 * Returns: Total bytes sent (always equals len on success)
 * Raises: SocketDgram_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until all data is sent or an error occurs.
 * For non-blocking sockets, returns 0 if would block (EAGAIN/EWOULDBLOCK).
 * Use SocketDgram_isconnected() to verify connection state before calling.
 */
extern ssize_t SocketDgram_sendall (T socket, const void *buf, size_t len);

/**
 * SocketDgram_recvall - Receive all requested data (handles partial receives)
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (> 0)
 * Returns: Total bytes received (always equals len on success)
 * Raises: SocketDgram_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until len bytes are received or an error occurs.
 * For non-blocking sockets, returns 0 if would block (EAGAIN/EWOULDBLOCK).
 * Use SocketDgram_isconnected() to verify connection state before calling.
 */
extern ssize_t SocketDgram_recvall (T socket, void *buf, size_t len);

/**
 * SocketDgram_sendv - Scatter/gather send (writev wrapper)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes sent (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: SocketDgram_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: Sends data from multiple buffers in a single system call.
 * May send less than requested. Use SocketDgram_sendvall() for guaranteed
 * complete send.
 */
extern ssize_t SocketDgram_sendv (T socket, const struct iovec *iov,
                                  int iovcnt);

/**
 * SocketDgram_recvv - Scatter/gather receive (readv wrapper)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes received (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: SocketDgram_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: Receives data into multiple buffers in a single system call.
 * May receive less than requested. Use SocketDgram_recvvall() for guaranteed
 * complete receive.
 */
extern ssize_t SocketDgram_recvv (T socket, struct iovec *iov, int iovcnt);

/**
 * SocketDgram_sendvall - Scatter/gather send all (handles partial sends)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes sent (always equals sum of all iov_len on success)
 * Raises: SocketDgram_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until all data from all buffers is sent or an error occurs.
 * For non-blocking sockets, returns partial progress if would block.
 * Use SocketDgram_isconnected() to verify connection state before calling.
 */
extern ssize_t SocketDgram_sendvall (T socket, const struct iovec *iov,
                                     int iovcnt);

/**
 * SocketDgram_recvvall - Scatter/gather receive all (handles partial receives)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes received (always equals sum of all iov_len on success)
 * Raises: SocketDgram_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until all requested data is received into all buffers or an
 * error occurs. For non-blocking sockets, returns partial progress if would
 * block. Use SocketDgram_isconnected() to verify connection state before
 * calling.
 */
extern ssize_t SocketDgram_recvvall (T socket, struct iovec *iov, int iovcnt);

/**
 * SocketDgram_setnonblocking - Enable non-blocking mode
 * @socket: Socket to modify
 * Raises: SocketDgram_Failed on error
 */
extern void SocketDgram_setnonblocking (T socket);

/**
 * SocketDgram_setreuseaddr - Enable address reuse
 * @socket: Socket to modify
 * Raises: SocketDgram_Failed on error
 */
extern void SocketDgram_setreuseaddr (T socket);

/**
 * SocketDgram_setreuseport - Enable port reuse across sockets
 * @socket: Socket to modify
 * Raises: SocketDgram_Failed on error (or if SO_REUSEPORT unsupported)
 */
extern void SocketDgram_setreuseport (T socket);

/**
 * SocketDgram_setbroadcast - Enable broadcast
 * @socket: Socket to modify
 * @enable: 1 to enable, 0 to disable
 * Raises: SocketDgram_Failed on error
 * Note: Required to send broadcast datagrams to 255.255.255.255
 * or subnet broadcast addresses.
 */
extern void SocketDgram_setbroadcast (T socket, int enable);

/**
 * SocketDgram_joinmulticast - Join multicast group
 * @socket: Socket to modify
 * @group: Multicast group address (e.g., "224.0.0.1" for IPv4)
 * @interface: Interface address or NULL for default
 * Raises: SocketDgram_Failed on error
 * Note: For IPv4, group should be in range 224.0.0.0 - 239.255.255.255
 * For IPv6, group should start with ff00::/8
 */
extern void SocketDgram_joinmulticast (T socket, const char *group,
                                       const char *interface);

/**
 * SocketDgram_leavemulticast - Leave multicast group
 * @socket: Socket to modify
 * @group: Multicast group address
 * @interface: Interface address or NULL for default
 * Raises: SocketDgram_Failed on error
 */
extern void SocketDgram_leavemulticast (T socket, const char *group,
                                        const char *interface);

/**
 * SocketDgram_setttl - Set time-to-live (hop limit)
 * @socket: Socket to modify
 * @ttl: TTL value (1-255)
 * Raises: SocketDgram_Failed on error
 * Note: TTL controls how many network hops a packet can traverse
 * Default is usually 64. Use 1 for link-local only.
 */
extern void SocketDgram_setttl (T socket, int ttl);

/**
 * SocketDgram_settimeout - Set socket timeout
 * @socket: Socket to modify
 * @timeout_sec: Timeout in seconds (0 to disable)
 * Sets receive timeout to prevent blocking indefinitely
 * Raises: SocketDgram_Failed on error
 * Note: Useful for signal-responsive servers. With timeout,
 * recvfrom returns 0 (would-block) after timeout, allowing
 * the event loop to check for shutdown signals.
 */
extern void SocketDgram_settimeout (T socket, int timeout_sec);

/**
 * SocketDgram_gettimeout - Get socket timeout
 * @socket: Socket to query
 * Returns: Timeout in seconds (0 if disabled)
 * Raises: SocketDgram_Failed on error
 * Note: Returns receive timeout (send timeout may differ)
 */
extern int SocketDgram_gettimeout (T socket);

/**
 * SocketDgram_getbroadcast - Get broadcast setting
 * @socket: Socket to query
 * Returns: 1 if broadcast is enabled, 0 if disabled
 * Raises: SocketDgram_Failed on error
 */
extern int SocketDgram_getbroadcast (T socket);

/**
 * SocketDgram_getttl - Get time-to-live (hop limit)
 * @socket: Socket to query
 * Returns: TTL value (1-255)
 * Raises: SocketDgram_Failed on error
 */
extern int SocketDgram_getttl (T socket);

/**
 * SocketDgram_getrcvbuf - Get receive buffer size
 * @socket: Socket to query
 * Returns: Receive buffer size in bytes
 * Raises: SocketDgram_Failed on error
 */
extern int SocketDgram_getrcvbuf (T socket);

/**
 * SocketDgram_getsndbuf - Get send buffer size
 * @socket: Socket to query
 * Returns: Send buffer size in bytes
 * Raises: SocketDgram_Failed on error
 */
extern int SocketDgram_getsndbuf (T socket);

/**
 * SocketDgram_isconnected - Check if datagram socket is connected
 * @socket: Socket to check
 * Returns: 1 if connected, 0 if not connected
 * Thread-safe: Yes (operates on single socket)
 * Note: Uses getpeername() to determine connection state.
 * For UDP sockets, "connected" means a default destination is set.
 */
extern int SocketDgram_isconnected (T socket);

/**
 * SocketDgram_isbound - Check if datagram socket is bound to an address
 * @socket: Socket to check
 * Returns: 1 if bound, 0 if not bound
 * Thread-safe: Yes (operates on single socket)
 * Note: Uses getsockname() to determine binding state.
 * A socket is bound if getsockname() succeeds and returns a valid address.
 * Wildcard addresses (0.0.0.0 or ::) still count as bound.
 */
extern int SocketDgram_isbound (T socket);

/**
 * SocketDgram_fd - Get underlying file descriptor
 * @socket: Socket instance
 * Returns: File descriptor
 */
extern int SocketDgram_fd (const T socket);

/**
 * SocketDgram_getlocaladdr - Get local IP address
 * @socket: Socket instance
 * Returns: IP address string (IPv4/IPv6) or "(unknown)" if unavailable
 * Note: Returns "(unknown)" if address info unavailable. String is owned by
 * socket, must not be freed/modified. Valid until socket freed.
 */
extern const char *SocketDgram_getlocaladdr (const T socket);

/**
 * SocketDgram_getlocalport - Get local port number
 * @socket: Socket instance
 * Returns: Port number (1 to SOCKET_MAX_PORT) or 0 if unavailable
 */
extern int SocketDgram_getlocalport (const T socket);

/**
 * SocketDgram_setcloexec - Control close-on-exec flag
 * @socket: Socket to modify
 * @enable: 1 to enable CLOEXEC, 0 to disable
 * Raises: SocketDgram_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: By default, all sockets have CLOEXEC enabled. This function
 * allows disabling it if you need to pass the socket to a child process.
 */
extern void SocketDgram_setcloexec (T socket, int enable);

/**
 * SocketDgram_debug_live_count - Get number of live datagram socket instances
 * Returns: Number of currently allocated SocketDgram instances
 * Thread-safe: Yes
 * Note: Test/debug function for leak detection. Returns count of sockets
 * that have been created but not yet freed.
 */
extern int SocketDgram_debug_live_count (void);

#undef T
#endif
