/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_TCP_INCLUDED
#define SOCKETSIMPLE_TCP_INCLUDED

/**
 * @file SocketSimple-tcp.h
 * @brief Simple TCP/UDP socket operations.
 */

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Opaque Handle Types
 *============================================================================*/

/**
 * @brief Opaque socket handle.
 */
typedef struct SocketSimple_Socket *SocketSimple_Socket_T;

/*============================================================================
 * TCP Client Functions
 *============================================================================*/

/**
 * @brief Connect to a TCP server.
 *
 * @param host Hostname or IP address.
 * @param port Port number (1-65535).
 * @return Socket handle on success, NULL on error.
 *
 * Example:
 * @code
 * SocketSimple_Socket_T sock = Socket_simple_connect("example.com", 80);
 * if (!sock) {
 *     fprintf(stderr, "Error: %s\n", Socket_simple_error());
 *     return 1;
 * }
 * @endcode
 */
extern SocketSimple_Socket_T Socket_simple_connect(const char *host, int port);

/**
 * @brief Connect to a TCP server with timeout.
 *
 * @param host Hostname or IP address.
 * @param port Port number.
 * @param timeout_ms Connection timeout in milliseconds.
 * @return Socket handle on success, NULL on error/timeout.
 */
extern SocketSimple_Socket_T Socket_simple_connect_timeout(const char *host,
                                                            int port,
                                                            int timeout_ms);

/*============================================================================
 * TCP Server Functions
 *============================================================================*/

/**
 * @brief Create a listening TCP server socket.
 *
 * @param host Bind address (NULL or "0.0.0.0" for any interface).
 * @param port Port number to listen on.
 * @param backlog Listen queue size (use 128 for typical servers).
 * @return Socket handle on success, NULL on error.
 */
extern SocketSimple_Socket_T Socket_simple_listen(const char *host,
                                                   int port,
                                                   int backlog);

/**
 * @brief Accept an incoming connection.
 *
 * @param server Listening socket from Socket_simple_listen().
 * @return Client socket handle on success, NULL on error.
 */
extern SocketSimple_Socket_T Socket_simple_accept(SocketSimple_Socket_T server);

/**
 * @brief Accept with timeout.
 *
 * @param server Listening socket.
 * @param timeout_ms Timeout in milliseconds (-1 for infinite).
 * @return Client socket, or NULL on error/timeout.
 */
extern SocketSimple_Socket_T Socket_simple_accept_timeout(
    SocketSimple_Socket_T server, int timeout_ms);

/*============================================================================
 * I/O Functions
 *============================================================================*/

/**
 * @brief Send all data (loops until complete).
 *
 * @param sock Socket handle.
 * @param data Data to send.
 * @param len Data length.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_send(SocketSimple_Socket_T sock,
                               const void *data,
                               size_t len);

/**
 * @brief Receive up to len bytes.
 *
 * @param sock Socket handle.
 * @param buf Output buffer.
 * @param len Buffer size.
 * @return Bytes received (>0), 0 on connection close, -1 on error.
 */
extern ssize_t Socket_simple_recv(SocketSimple_Socket_T sock,
                                   void *buf,
                                   size_t len);

/**
 * @brief Receive with timeout.
 *
 * @param sock Socket handle.
 * @param buf Output buffer.
 * @param len Buffer size.
 * @param timeout_ms Timeout in milliseconds.
 * @return Bytes received, 0 on close, -1 on error/timeout.
 */
extern ssize_t Socket_simple_recv_timeout(SocketSimple_Socket_T sock,
                                           void *buf,
                                           size_t len,
                                           int timeout_ms);

/**
 * @brief Receive exactly len bytes (blocks until complete).
 *
 * @param sock Socket handle.
 * @param buf Output buffer.
 * @param len Exact number of bytes to receive.
 * @return 0 on success, -1 on error or early close.
 */
extern int Socket_simple_recv_all(SocketSimple_Socket_T sock,
                                   void *buf,
                                   size_t len);

/**
 * @brief Receive a line (up to newline or max length).
 *
 * @param sock Socket handle.
 * @param buf Output buffer.
 * @param maxlen Maximum bytes to read.
 * @return Line length (excluding null), -1 on error.
 */
extern ssize_t Socket_simple_recv_line(SocketSimple_Socket_T sock,
                                        char *buf,
                                        size_t maxlen);

/*============================================================================
 * Socket Options
 *============================================================================*/

/**
 * @brief Set send/receive timeouts.
 *
 * @param sock Socket handle.
 * @param send_ms Send timeout in milliseconds (0 = infinite).
 * @param recv_ms Receive timeout in milliseconds (0 = infinite).
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_set_timeout(SocketSimple_Socket_T sock,
                                      int send_ms,
                                      int recv_ms);

/**
 * @brief Get underlying file descriptor.
 *
 * Useful for integration with poll/select or other I/O multiplexing.
 *
 * @param sock Socket handle.
 * @return File descriptor, or -1 if invalid.
 */
extern int Socket_simple_fd(SocketSimple_Socket_T sock);

/**
 * @brief Check if socket is connected.
 *
 * @param sock Socket handle.
 * @return 1 if connected, 0 if not.
 */
extern int Socket_simple_is_connected(SocketSimple_Socket_T sock);

/*============================================================================
 * Cleanup
 *============================================================================*/

/**
 * @brief Close socket and release resources.
 *
 * Sets *sock to NULL after closing.
 *
 * @param sock Pointer to socket handle.
 */
extern void Socket_simple_close(SocketSimple_Socket_T *sock);

/*============================================================================
 * UDP Functions
 *============================================================================*/

/**
 * @brief Create a UDP socket bound to address.
 *
 * @param host Bind address (NULL for any).
 * @param port Port number.
 * @return Socket handle on success, NULL on error.
 */
extern SocketSimple_Socket_T Socket_simple_udp_bind(const char *host, int port);

/**
 * @brief Create an unbound UDP socket for sending.
 *
 * @return Socket handle on success, NULL on error.
 */
extern SocketSimple_Socket_T Socket_simple_udp_new(void);

/**
 * @brief Send UDP datagram.
 *
 * @param sock UDP socket handle.
 * @param data Data to send.
 * @param len Data length.
 * @param host Destination hostname or IP.
 * @param port Destination port.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_udp_sendto(SocketSimple_Socket_T sock,
                                     const void *data,
                                     size_t len,
                                     const char *host,
                                     int port);

/**
 * @brief Receive UDP datagram.
 *
 * @param sock UDP socket handle.
 * @param buf Output buffer.
 * @param len Buffer size.
 * @param from_host Output: sender IP (caller provides buffer, at least 46 bytes).
 * @param host_len Size of from_host buffer.
 * @param from_port Output: sender port.
 * @return Bytes received, -1 on error.
 */
extern ssize_t Socket_simple_udp_recvfrom(SocketSimple_Socket_T sock,
                                           void *buf,
                                           size_t len,
                                           char *from_host,
                                           size_t host_len,
                                           int *from_port);

/*============================================================================
 * UDP Advanced Features (Multicast, Broadcast)
 *============================================================================*/

/**
 * @brief Join a multicast group.
 *
 * @param sock UDP socket handle.
 * @param group Multicast group address (e.g., "224.0.0.1").
 * @param iface Local interface address (NULL for default).
 * @return 0 on success, -1 on error.
 *
 * Example:
 * @code
 * SocketSimple_Socket_T sock = Socket_simple_udp_bind("0.0.0.0", 5000);
 * if (Socket_simple_udp_join_multicast(sock, "239.255.0.1", NULL) < 0) {
 *     fprintf(stderr, "Error: %s\n", Socket_simple_error());
 * }
 * @endcode
 */
extern int Socket_simple_udp_join_multicast(SocketSimple_Socket_T sock,
                                             const char *group,
                                             const char *iface);

/**
 * @brief Leave a multicast group.
 *
 * @param sock UDP socket handle.
 * @param group Multicast group address.
 * @param iface Local interface (NULL for default).
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_udp_leave_multicast(SocketSimple_Socket_T sock,
                                              const char *group,
                                              const char *iface);

/**
 * @brief Set multicast TTL (Time To Live).
 *
 * @param sock UDP socket handle.
 * @param ttl TTL value (1-255, typically 1 for LAN only).
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_udp_set_multicast_ttl(SocketSimple_Socket_T sock,
                                                int ttl);

/**
 * @brief Enable/disable multicast loopback.
 *
 * @param sock UDP socket handle.
 * @param enable 1 to enable, 0 to disable.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_udp_set_multicast_loopback(SocketSimple_Socket_T sock,
                                                     int enable);

/**
 * @brief Set the interface for outgoing multicast packets.
 *
 * @param sock UDP socket handle.
 * @param iface Interface address (NULL for default).
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_udp_set_multicast_interface(SocketSimple_Socket_T sock,
                                                      const char *iface);

/**
 * @brief Enable UDP broadcast.
 *
 * @param sock UDP socket handle.
 * @param enable 1 to enable, 0 to disable.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_udp_set_broadcast(SocketSimple_Socket_T sock,
                                            int enable);

/**
 * @brief Set TTL for unicast packets.
 *
 * @param sock UDP socket handle.
 * @param ttl TTL value (1-255).
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_udp_set_ttl(SocketSimple_Socket_T sock, int ttl);

/**
 * @brief Connect UDP socket to a specific peer.
 *
 * After connecting, can use send/recv instead of sendto/recvfrom.
 *
 * @param sock UDP socket handle.
 * @param host Peer hostname or IP address.
 * @param port Peer port.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_udp_connect(SocketSimple_Socket_T sock,
                                      const char *host,
                                      int port);

/**
 * @brief Send data on a connected UDP socket.
 *
 * @param sock UDP socket handle (must be connected).
 * @param data Data to send.
 * @param len Data length.
 * @return Bytes sent, or -1 on error.
 */
extern ssize_t Socket_simple_udp_send(SocketSimple_Socket_T sock,
                                       const void *data,
                                       size_t len);

/**
 * @brief Receive data on a connected UDP socket.
 *
 * @param sock UDP socket handle (must be connected).
 * @param buf Receive buffer.
 * @param len Buffer size.
 * @return Bytes received, or -1 on error.
 */
extern ssize_t Socket_simple_udp_recv(SocketSimple_Socket_T sock,
                                       void *buf,
                                       size_t len);

/*============================================================================
 * Unix Domain Socket Functions
 *============================================================================*/

/**
 * @brief Connect to a Unix domain socket.
 *
 * @param path Socket path (e.g., "/var/run/app.sock").
 * @return Socket handle on success, NULL on error.
 *
 * Example:
 * @code
 * SocketSimple_Socket_T sock = Socket_simple_connect_unix("/var/run/docker.sock");
 * if (!sock) {
 *     fprintf(stderr, "Error: %s\n", Socket_simple_error());
 * }
 * @endcode
 */
extern SocketSimple_Socket_T Socket_simple_connect_unix(const char *path);

/**
 * @brief Create a listening Unix domain socket.
 *
 * @param path Socket path to bind.
 * @param backlog Listen queue size.
 * @return Socket handle on success, NULL on error.
 *
 * @note Removes any existing socket file at the path before binding.
 */
extern SocketSimple_Socket_T Socket_simple_listen_unix(const char *path,
                                                        int backlog);

/*============================================================================
 * TCP Socket Options
 *============================================================================*/

/**
 * @brief Enable/disable TCP_NODELAY (Nagle's algorithm).
 *
 * Disabling Nagle's algorithm reduces latency for small messages.
 *
 * @param sock Socket handle.
 * @param enable 1 to disable Nagle (low latency), 0 to enable Nagle.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_set_nodelay(SocketSimple_Socket_T sock, int enable);

/**
 * @brief Get TCP_NODELAY state.
 *
 * @param sock Socket handle.
 * @return 1 if Nagle disabled, 0 if enabled, -1 on error.
 */
extern int Socket_simple_get_nodelay(SocketSimple_Socket_T sock);

/**
 * @brief Configure TCP keepalive.
 *
 * @param sock Socket handle.
 * @param enable 1 to enable, 0 to disable.
 * @param idle_secs Seconds before first probe (0 for system default).
 * @param interval_secs Seconds between probes (0 for system default).
 * @param count Number of failed probes before disconnect (0 for system default).
 * @return 0 on success, -1 on error.
 *
 * Example:
 * @code
 * // Enable keepalive: probe after 60s idle, every 10s, fail after 3 misses
 * Socket_simple_set_keepalive(sock, 1, 60, 10, 3);
 * @endcode
 */
extern int Socket_simple_set_keepalive(SocketSimple_Socket_T sock,
                                        int enable,
                                        int idle_secs,
                                        int interval_secs,
                                        int count);

/**
 * @brief Get keepalive settings.
 *
 * @param sock Socket handle.
 * @param enabled Output: 1 if enabled, 0 if disabled.
 * @param idle_secs Output: idle time (may be NULL).
 * @param interval_secs Output: interval (may be NULL).
 * @param count Output: probe count (may be NULL).
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_get_keepalive(SocketSimple_Socket_T sock,
                                        int *enabled,
                                        int *idle_secs,
                                        int *interval_secs,
                                        int *count);

/**
 * @brief Set send buffer size.
 *
 * @param sock Socket handle.
 * @param size Buffer size in bytes.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_set_sndbuf(SocketSimple_Socket_T sock, int size);

/**
 * @brief Get send buffer size.
 *
 * @param sock Socket handle.
 * @return Buffer size, or -1 on error.
 */
extern int Socket_simple_get_sndbuf(SocketSimple_Socket_T sock);

/**
 * @brief Set receive buffer size.
 *
 * @param sock Socket handle.
 * @param size Buffer size in bytes.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_set_rcvbuf(SocketSimple_Socket_T sock, int size);

/**
 * @brief Get receive buffer size.
 *
 * @param sock Socket handle.
 * @return Buffer size, or -1 on error.
 */
extern int Socket_simple_get_rcvbuf(SocketSimple_Socket_T sock);

/**
 * @brief Set socket to blocking or non-blocking mode.
 *
 * @param sock Socket handle.
 * @param blocking 1 for blocking, 0 for non-blocking.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_set_blocking(SocketSimple_Socket_T sock, int blocking);

/**
 * @brief Check if socket is in blocking mode.
 *
 * @param sock Socket handle.
 * @return 1 if blocking, 0 if non-blocking, -1 on error.
 */
extern int Socket_simple_is_blocking(SocketSimple_Socket_T sock);

/**
 * @brief Enable/disable SO_REUSEADDR.
 *
 * Allows reusing local addresses for bind.
 *
 * @param sock Socket handle.
 * @param enable 1 to enable, 0 to disable.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_set_reuseaddr(SocketSimple_Socket_T sock, int enable);

/**
 * @brief Enable/disable SO_REUSEPORT.
 *
 * Allows multiple sockets to bind to the same port.
 *
 * @param sock Socket handle.
 * @param enable 1 to enable, 0 to disable.
 * @return 0 on success, -1 on error.
 *
 * @note Not available on all platforms.
 */
extern int Socket_simple_set_reuseport(SocketSimple_Socket_T sock, int enable);

/*============================================================================
 * Socket Address Information
 *============================================================================*/

/**
 * @brief Get local address of socket.
 *
 * @param sock Socket handle.
 * @param host Output buffer for IP address (at least 46 bytes for IPv6).
 * @param host_len Size of host buffer.
 * @param port Output: local port number.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_get_local_addr(SocketSimple_Socket_T sock,
                                         char *host,
                                         size_t host_len,
                                         int *port);

/**
 * @brief Get peer address of connected socket.
 *
 * @param sock Socket handle.
 * @param host Output buffer for IP address.
 * @param host_len Size of host buffer.
 * @param port Output: peer port number.
 * @return 0 on success, -1 on error.
 */
extern int Socket_simple_get_peer_addr(SocketSimple_Socket_T sock,
                                        char *host,
                                        size_t host_len,
                                        int *port);

/**
 * @brief Get peer credentials for Unix domain socket.
 *
 * @param sock Unix domain socket handle.
 * @param pid Output: peer process ID (may be NULL).
 * @param uid Output: peer user ID (may be NULL).
 * @param gid Output: peer group ID (may be NULL).
 * @return 0 on success, -1 on error or not a Unix socket.
 */
extern int Socket_simple_get_peer_creds(SocketSimple_Socket_T sock,
                                         int *pid,
                                         int *uid,
                                         int *gid);

/*============================================================================
 * Scatter-Gather I/O
 *============================================================================*/

#include <sys/uio.h>

/**
 * @brief Send data from multiple buffers (gather write).
 *
 * @param sock Socket handle.
 * @param iov Array of iovec structures.
 * @param iovcnt Number of iovec entries.
 * @return Bytes sent, or -1 on error.
 */
extern ssize_t Socket_simple_sendv(SocketSimple_Socket_T sock,
                                    const struct iovec *iov,
                                    int iovcnt);

/**
 * @brief Receive data into multiple buffers (scatter read).
 *
 * @param sock Socket handle.
 * @param iov Array of iovec structures.
 * @param iovcnt Number of iovec entries.
 * @return Bytes received, 0 on close, -1 on error.
 */
extern ssize_t Socket_simple_recvv(SocketSimple_Socket_T sock,
                                    struct iovec *iov,
                                    int iovcnt);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_TCP_INCLUDED */
