#ifndef SOCKETDGRAM_INCLUDED
#define SOCKETDGRAM_INCLUDED

#include "core/Except.h"
#include "socket/SocketCommon.h" /* For SocketBase_T and Unix support */
#include <stddef.h>
#include <sys/socket.h>

/**
 * @file SocketDgram.h
 * @ingroup core_io
 * @ingroup core_io
* @brief High-level UDP/datagram socket interface with multicast and broadcast support.
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
/**
 * @ingroup core_io
 * @ingroup core_io
* @brief Opaque handle for UDP/datagram sockets.
 *
 * Provides connectionless messaging capabilities for IPv4 and IPv6,
 * including support for broadcast, multicast, and standard socket options.
 * Builds on SocketBase_T for common functionality.
 *
 * @see Socket_T for connection-oriented (TCP) sockets.
 * @see SocketDgram_new() for creation.
 * @see SocketDgram_free() for destruction.
 * @see @ref core_io "Core I/O module" for related primitives.
 */
typedef struct T *T;

/* Exception types */
/**
 * @ingroup core_io
 * @ingroup core_io
* @brief Exception raised on general datagram socket operation failures.
 *
 * Covers system call errors (e.g., bind, connect, send, recv failures),
 * invalid parameters, and resource exhaustion.
 *
 * @see docs/ERROR_HANDLING.md for exception handling guidelines.
 * @see Except_T for the base exception type.
 * @see SocketDgram_Failed usage in function @throws tags.
 */
extern const Except_T SocketDgram_Failed;

/**
 * @ingroup core_io
* @brief Create a new UDP socket.
 * @param domain Address family (AF_INET, AF_INET6, etc.).
 * @param protocol Protocol (usually 0 for default UDP).
 * @return New datagram socket instance.
 * @throws SocketDgram_Failed on error.
 * @note domain is typically AF_INET (IPv4) or AF_INET6 (IPv6).
 * @see SocketDgram_free() for cleanup.
 * @see SocketDgram_bind() for binding to an address.
 * @see @ref Socket_T for TCP socket operations.
 * @see @ref SocketDNS_T for DNS resolution integration.
 */
extern T SocketDgram_new (int domain, int protocol);

/**
 * @ingroup core_io
* @brief Free a socket and close the connection.
 * @param socket Pointer to socket (will be set to NULL).
 * @see SocketDgram_new() for socket creation.
 */
extern void SocketDgram_free (T *socket);

/**
 * @ingroup core_io
* @brief Bind socket to address and port.
 * @param socket Socket to bind.
 * @param host IP address or NULL/"0.0.0.0" for any.
 * @param port Port number (1 to SOCKET_MAX_PORT).
 * @throws SocketDgram_Failed on error.
 * @warning This function may block during DNS resolution if hostname is provided. For non-blocking operation, use IP addresses directly.
 * @note All parameters are validated at runtime for safety with user input.
 * @see SocketDgram_new() for socket creation.
 * @see SocketDgram_connect() for setting default destination.
 */
extern void SocketDgram_bind (T socket, const char *host, int port);

/**
 * @ingroup core_io
* @brief Set default destination for socket.
 * @param socket Socket to connect.
 * @param host Remote IP address or hostname.
 * @param port Remote port.
 * @throws SocketDgram_Failed on error.
 * @warning This function may block during DNS resolution if hostname is provided.
 * @note "Connect" for UDP means setting a default destination. After connecting, you can use send/recv instead of sendto/recvfrom.
 * @note The socket only accepts packets from the connected address. You can still use sendto/recvfrom to override the default destination.
 * @see SocketDgram_bind() for binding to a local address.
 * @see SocketDgram_send() for sending to connected destination.
 */
extern void SocketDgram_connect (T socket, const char *host, int port);

/**
 * @ingroup core_io
* @brief Send datagram to specific address.
 * @param socket Socket to send from.
 * @param buf Data to send.
 * @param len Length of data (must be > 0).
 * @param host Destination IP address or hostname.
 * @param port Destination port.
 * @return Number of bytes sent (> 0), or 0 if would block (EAGAIN/EWOULDBLOCK).
 * @throws SocketDgram_Failed on error.
 * @warning This function may block during DNS resolution if hostname is provided.
 * @note UDP sends complete datagrams. If len > MTU, fragmentation may occur.
 * @note Recommended to keep len <= 1472 bytes to avoid fragmentation (1500 MTU - headers).
 * @note Unlike TCP, send may return less than len only on would-block, not partial sends.
 * @see SocketDgram_recvfrom() for receiving datagrams.
 * @see SocketDgram_connect() for setting default destination.
 */
extern ssize_t SocketDgram_sendto (T socket, const void *buf, size_t len,
                                   const char *host, int port);

/**
 * @ingroup core_io
* @brief Receive datagram and get sender address.
 * @param socket Socket to receive from.
 * @param buf Buffer for received data.
 * @param len Buffer size (must be > 0).
 * @param host Output - sender IP address (buffer must be >= 46 bytes for IPv6).
 * @param host_len Size of host buffer.
 * @param port Output - sender port number.
 * @return Number of bytes received (> 0), or 0 if would block (EAGAIN/EWOULDBLOCK).
 * @throws SocketDgram_Failed on error.
 * @note UDP is message-oriented. If buffer is too small, data is truncated.
 * @note Recommended buffer size >= 65507 bytes (max UDP payload) to avoid truncation.
 * @note Common buffer sizes: 8192 (8KB), 65536 (64KB).
 * @note The host parameter receives the sender's IP address as a string.
 * @note The port parameter receives the sender's port number.
 * @see SocketDgram_sendto() for sending datagrams.
 * @see SocketDgram_recv() for receiving from connected sockets.
 */
extern ssize_t SocketDgram_recvfrom (T socket, void *buf, size_t len,
                                     char *host, size_t host_len, int *port);

/**
 * @ingroup core_io
* @brief Send to default destination (connected socket).
 * @param socket Connected socket.
 * @param buf Data to send.
 * @param len Length of data (must be > 0).
 * @return Number of bytes sent (> 0), or 0 if would block (EAGAIN/EWOULDBLOCK).
 * @throws SocketDgram_Failed on error.
 * @note Socket must be connected via SocketDgram_connect() first.
 * @see SocketDgram_recv() for receiving from connected sockets.
 * @see SocketDgram_sendto() for sending to arbitrary addresses.
 */
extern ssize_t SocketDgram_send (T socket, const void *buf, size_t len);

/**
 * @ingroup core_io
* @brief Receive from default source (connected socket).
 * @param socket Connected socket.
 * @param buf Buffer for received data.
 * @param len Buffer size (must be > 0).
 * @return Number of bytes received (> 0), or 0 if would block (EAGAIN/EWOULDBLOCK).
 * @throws SocketDgram_Failed on error.
 * @note Socket must be connected via SocketDgram_connect() first. Only accepts packets from the connected address.
 * @see SocketDgram_send() for sending to connected sockets.
 * @see SocketDgram_recvfrom() for receiving with sender info.
 */
extern ssize_t SocketDgram_recv (T socket, void *buf, size_t len);

/**
 * @ingroup core_io
* @brief Send all data (handles partial sends).
 * @param socket Connected socket.
 * @param buf Data to send.
 * @param len Length of data (> 0).
 * @return Total bytes sent (always equals len on success).
 * @throws SocketDgram_Failed on error.
 * @threadsafe Yes (operates on single socket).
 * @note Loops until all data is sent or an error occurs.
 * @note For non-blocking sockets, returns 0 if would block (EAGAIN/EWOULDBLOCK).
 * @note Use SocketDgram_isconnected() to verify connection state before calling.
 * @see SocketDgram_send() for partial send operations.
 * @see SocketDgram_recvall() for receiving all data.
 */
extern ssize_t SocketDgram_sendall (T socket, const void *buf, size_t len);

/**
 * @ingroup core_io
* @brief Receive all requested data (handles partial receives).
 * @param socket Connected socket.
 * @param buf Buffer for received data.
 * @param len Buffer size (> 0).
 * @return Total bytes received (always equals len on success).
 * @throws SocketDgram_Failed on error.
 * @threadsafe Yes (operates on single socket).
 * @note Loops until len bytes are received or an error occurs.
 * @note For non-blocking sockets, returns 0 if would block (EAGAIN/EWOULDBLOCK).
 * @note Use SocketDgram_isconnected() to verify connection state before calling.
 * @see SocketDgram_recv() for partial receive operations.
 * @see SocketDgram_sendall() for sending all data.
 */
extern ssize_t SocketDgram_recvall (T socket, void *buf, size_t len);

/**
 * @ingroup core_io
* @brief Scatter/gather send (writev wrapper).
 * @param socket Connected socket.
 * @param iov Array of iovec structures.
 * @param iovcnt Number of iovec structures (> 0, <= IOV_MAX).
 * @return Total bytes sent (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK).
 * @throws SocketDgram_Failed on error.
 * @threadsafe Yes (operates on single socket).
 * @note Sends data from multiple buffers in a single system call.
 * @note May send less than requested. Use SocketDgram_sendvall() for guaranteed complete send.
 * @see SocketDgram_recvv() for scatter/gather receive.
 * @see SocketDgram_sendvall() for guaranteed complete scatter/gather send.
 */
extern ssize_t SocketDgram_sendv (T socket, const struct iovec *iov,
                                  int iovcnt);

/**
 * @ingroup core_io
* @brief Scatter/gather receive (readv wrapper).
 * @param socket Connected socket.
 * @param iov Array of iovec structures.
 * @param iovcnt Number of iovec structures (> 0, <= IOV_MAX).
 * @return Total bytes received (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK).
 * @throws SocketDgram_Failed on error.
 * @threadsafe Yes (operates on single socket).
 * @note Receives data into multiple buffers in a single system call.
 * @note May receive less than requested. Use SocketDgram_recvvall() for guaranteed complete receive.
 * @see SocketDgram_sendv() for scatter/gather send.
 * @see SocketDgram_recvvall() for guaranteed complete scatter/gather receive.
 */
extern ssize_t SocketDgram_recvv (T socket, struct iovec *iov, int iovcnt);

/**
 * @ingroup core_io
* @brief Scatter/gather send all (handles partial sends).
 * @param socket Connected socket.
 * @param iov Array of iovec structures.
 * @param iovcnt Number of iovec structures (> 0, <= IOV_MAX).
 * @return Total bytes sent (always equals sum of all iov_len on success).
 * @throws SocketDgram_Failed on error.
 * @threadsafe Yes (operates on single socket).
 * @note Loops until all data from all buffers is sent or an error occurs.
 * @note For non-blocking sockets, returns partial progress if would block.
 * @note Use SocketDgram_isconnected() to verify connection state before calling.
 * @see SocketDgram_sendv() for partial scatter/gather send.
 * @see SocketDgram_recvvall() for receiving all scatter/gather data.
 */
extern ssize_t SocketDgram_sendvall (T socket, const struct iovec *iov,
                                     int iovcnt);

/**
 * @ingroup core_io
* @brief Scatter/gather receive all (handles partial receives).
 * @param socket Connected socket.
 * @param iov Array of iovec structures.
 * @param iovcnt Number of iovec structures (> 0, <= IOV_MAX).
 * @return Total bytes received (always equals sum of all iov_len on success).
 * @throws SocketDgram_Failed on error.
 * @threadsafe Yes (operates on single socket).
 * @note Loops until all requested data is received into all buffers or an error occurs.
 * @note For non-blocking sockets, returns partial progress if would block.
 * @note Use SocketDgram_isconnected() to verify connection state before calling.
 * @see SocketDgram_recvv() for partial scatter/gather receive.
 * @see SocketDgram_sendvall() for sending all scatter/gather data.
 */
extern ssize_t SocketDgram_recvvall (T socket, struct iovec *iov, int iovcnt);

/**
 * @ingroup core_io
* @brief Enable non-blocking mode.
 * @param socket Socket to modify.
 * @throws SocketDgram_Failed on error.
 * @see SocketDgram_setreuseaddr() for address reuse.
 * @see Socket_bind() for binding operations.
 */
extern void SocketDgram_setnonblocking (T socket);

/**
 * @ingroup core_io
* @brief Enable address reuse.
 * @param socket Socket to modify.
 * @throws SocketDgram_Failed on error.
 * @see SocketDgram_setreuseport() for port reuse.
 * @see SocketDgram_bind() for binding operations.
 */
extern void SocketDgram_setreuseaddr (T socket);

/**
 * @ingroup core_io
* @brief Enable port reuse across sockets.
 * @param socket Socket to modify.
 * @throws SocketDgram_Failed on error (or if SO_REUSEPORT unsupported).
 * @see SocketDgram_setreuseaddr() for address reuse.
 * @see Socket_bind() for binding operations.
 */
extern void SocketDgram_setreuseport (T socket);

/**
 * @ingroup core_io
* @brief Enable broadcast.
 * @param socket Socket to modify.
 * @param enable 1 to enable, 0 to disable.
 * @throws SocketDgram_Failed on error.
 * @note Required to send broadcast datagrams to 255.255.255.255 or subnet broadcast addresses.
 * @see SocketDgram_joinmulticast() for multicast operations.
 * @see SocketDgram_sendto() for sending broadcast datagrams.
 */
extern void SocketDgram_setbroadcast (T socket, int enable);

/**
 * @ingroup core_io
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
 * @ingroup core_io
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
 * @ingroup core_io
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
 * @ingroup core_io
* @brief Set socket timeout.
 * @param socket Socket to modify.
 * @param timeout_sec Timeout in seconds (0 to disable).
 * @throws SocketDgram_Failed on error.
 * @note Sets receive timeout to prevent blocking indefinitely.
 * @note Useful for signal-responsive servers. With timeout, recvfrom returns 0 (would-block) after timeout.
 * @note Allows the event loop to check for shutdown signals.
 * @see SocketDgram_gettimeout() for retrieving the current timeout.
 * @see SocketDgram_recvfrom() for timeout behavior.
 */
extern void SocketDgram_settimeout (T socket, int timeout_sec);

/**
 * @ingroup core_io
* @brief Get socket timeout.
 * @param socket Socket to query.
 * @return Timeout in seconds (0 if disabled).
 * @throws SocketDgram_Failed on error.
 * @note Returns receive timeout (send timeout may differ).
 * @see SocketDgram_settimeout() for setting the timeout.
 */
extern int SocketDgram_gettimeout (T socket);

/**
 * @ingroup core_io
* @brief Get broadcast setting.
 * @param socket Socket to query.
 * @return 1 if broadcast is enabled, 0 if disabled.
 * @throws SocketDgram_Failed on error.
 * @see SocketDgram_setbroadcast() for setting broadcast mode.
 */
extern int SocketDgram_getbroadcast (T socket);

/**
 * @ingroup core_io
* @brief Get time-to-live (hop limit).
 * @param socket Socket to query.
 * @return TTL value (1-255).
 * @throws SocketDgram_Failed on error.
 * @see SocketDgram_setttl() for setting TTL.
 */
extern int SocketDgram_getttl (T socket);

/**
 * @ingroup core_io
* @brief Get receive buffer size.
 * @param socket Socket to query.
 * @return Receive buffer size in bytes.
 * @throws SocketDgram_Failed on error.
 * @see SocketDgram_getsndbuf() for send buffer size.
 */
extern int SocketDgram_getrcvbuf (T socket);

/**
 * @ingroup core_io
* @brief Get send buffer size.
 * @param socket Socket to query.
 * @return Send buffer size in bytes.
 * @throws SocketDgram_Failed on error.
 * @see SocketDgram_getrcvbuf() for receive buffer size.
 */
extern int SocketDgram_getsndbuf (T socket);

/**
 * @ingroup core_io
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
 * @ingroup core_io
* @brief Check if datagram socket is bound to an address.
 * @param socket Socket to check.
 * @return 1 if bound, 0 if not bound.
 * @threadsafe Yes (operates on single socket).
 * @note Uses getsockname() to determine binding state.
 * @note A socket is bound if getsockname() succeeds and returns a valid address.
 * @note Wildcard addresses (0.0.0.0 or ::) still count as bound.
 * @see SocketDgram_bind() for binding sockets.
 * @see SocketDgram_isconnected() for checking connection state.
 */
extern int SocketDgram_isbound (T socket);

/**
 * @ingroup core_io
* @brief Get underlying file descriptor.
 * @param socket Socket instance.
 * @return File descriptor.
 * @see Socket_fd() for TCP socket file descriptors.
 */
extern int SocketDgram_fd (const T socket);

/**
 * @ingroup core_io
* @brief Get local IP address.
 * @param socket Socket instance.
 * @return IP address string (IPv4/IPv6) or "(unknown)" if unavailable.
 * @note Returns "(unknown)" if address info unavailable. String is owned by socket, must not be freed/modified.
 * @note Valid until socket freed.
 * @see SocketDgram_getlocalport() for local port.
 * @see SocketDgram_bind() for binding operations.
 */
extern const char *SocketDgram_getlocaladdr (const T socket);

/**
 * @ingroup core_io
* @brief Get local port number.
 * @param socket Socket instance.
 * @return Port number (1 to SOCKET_MAX_PORT) or 0 if unavailable.
 * @see SocketDgram_getlocaladdr() for local address.
 * @see SocketDgram_bind() for binding operations.
 */
extern int SocketDgram_getlocalport (const T socket);

/**
 * @ingroup core_io
* @brief Control close-on-exec flag.
 * @param socket Socket to modify.
 * @param enable 1 to enable CLOEXEC, 0 to disable.
 * @throws SocketDgram_Failed on error.
 * @threadsafe Yes (operates on single socket).
 * @note By default, all sockets have CLOEXEC enabled. This function allows disabling it if you need to pass the socket to a child process.
 * @see Socket_setcloexec() for TCP socket CLOEXEC control.
 */
extern void SocketDgram_setcloexec (T socket, int enable);

/**
 * @ingroup core_io
* @brief Get number of live datagram socket instances.
 * @return Number of currently allocated SocketDgram instances.
 * @threadsafe Yes.
 * @note Test/debug function for leak detection. Returns count of sockets that have been created but not yet freed.
 * @see Socket_debug_live_count() for TCP socket count.
 */
extern int SocketDgram_debug_live_count (void);

#undef T
#endif
