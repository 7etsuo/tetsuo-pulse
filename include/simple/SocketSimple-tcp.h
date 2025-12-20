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

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_TCP_INCLUDED */
