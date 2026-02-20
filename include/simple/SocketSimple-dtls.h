/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_DTLS_INCLUDED
#define SOCKETSIMPLE_DTLS_INCLUDED

/**
 * @file SocketSimple-dtls.h
 * @brief Simple API for DTLS (Datagram TLS) over UDP.
 *
 * Provides a return-code based interface for secure UDP communication
 * using DTLS. Wraps the exception-based SocketDTLS API.
 *
 * ## Quick Start
 *
 * ```c
 * #include <simple/SocketSimple.h>
 *
 * // Client: connect with DTLS
 * SocketSimple_Socket_T sock = Socket_simple_dtls_connect("server.example.com",
 * 4433); if (!sock) { fprintf(stderr, "DTLS connect failed: %s\n",
 * Socket_simple_error()); return 1;
 * }
 *
 * // Send/receive encrypted datagrams
 * Socket_simple_dtls_send(sock, "Hello", 5);
 * char buf[1024];
 * ssize_t n = Socket_simple_dtls_recv(sock, buf, sizeof(buf));
 *
 * Socket_simple_dtls_shutdown(sock);
 * Socket_simple_close(&sock);
 * ```
 */

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Default MTU for DTLS connections.
 *
 * The default Maximum Transmission Unit for DTLS is 1400 bytes,
 * which accounts for typical IPv6 overhead and ensures the DTLS
 * record plus UDP/IP headers fit within the path MTU.
 */
#define SOCKET_SIMPLE_DTLS_DEFAULT_MTU 1400

  /**
   * @brief DTLS connection options.
   */
  typedef struct SocketSimple_DTLSOptions
  {
    int timeout_ms;          /**< Handshake timeout (default: 30000) */
    int verify_cert;         /**< Verify peer certificate (default: 1) */
    const char *ca_file;     /**< CA certificate file for verification */
    const char *ca_path;     /**< CA certificate directory */
    const char *client_cert; /**< Client certificate file (for mTLS) */
    const char *client_key;  /**< Client private key file (for mTLS) */
    size_t mtu; /**< MTU size, 0 for default (SOCKET_SIMPLE_DTLS_DEFAULT_MTU) */
    const char **alpn; /**< ALPN protocol list (NULL-terminated) */
    size_t alpn_count; /**< Number of ALPN protocols */
  } SocketSimple_DTLSOptions;

  /**
   * @brief Connect to a DTLS server with default options.
   *
   * Creates a UDP socket, connects to the server, performs DTLS handshake.
   *
   * @param host Server hostname or IP address.
   * @param port Server port number.
   * @return Socket handle on success, NULL on error.
   */
  extern SocketSimple_Socket_T
  Socket_simple_dtls_connect (const char *host, int port);

  /**
   * @brief Connect to a DTLS server with custom options.
   *
   * @param host Server hostname or IP address.
   * @param port Server port number.
   * @param opts Connection options (NULL for defaults).
   * @return Socket handle on success, NULL on error.
   */
  extern SocketSimple_Socket_T
  Socket_simple_dtls_connect_ex (const char *host,
                                 int port,
                                 const SocketSimple_DTLSOptions *opts);

  /**
   * @brief Enable DTLS on an existing UDP socket.
   *
   * The socket should already be connected (for clients) or bound (for
   * servers). Performs the DTLS handshake.
   *
   * @param sock UDP socket to upgrade.
   * @param hostname Hostname for SNI and verification (can be NULL).
   * @param opts DTLS options (NULL for defaults).
   * @return 0 on success, -1 on error.
   */
  extern int Socket_simple_dtls_enable (SocketSimple_Socket_T sock,
                                        const char *hostname,
                                        const SocketSimple_DTLSOptions *opts);

  /**
   * @brief Create a DTLS server socket.
   *
   * Binds to the specified address/port and prepares for DTLS connections.
   *
   * @param host Bind address (NULL or "0.0.0.0" for any).
   * @param port Port number.
   * @param cert_file Server certificate file.
   * @param key_file Server private key file.
   * @return Socket handle on success, NULL on error.
   */
  extern SocketSimple_Socket_T Socket_simple_dtls_listen (const char *host,
                                                          int port,
                                                          const char *cert_file,
                                                          const char *key_file);

  /**
   * @brief Accept a DTLS client connection.
   *
   * For connectionless DTLS servers, this waits for a client handshake.
   *
   * @param server_sock Server socket.
   * @param timeout_ms Timeout in milliseconds (-1 for blocking).
   * @return New client socket on success, NULL on error/timeout.
   */
  extern SocketSimple_Socket_T
  Socket_simple_dtls_accept (SocketSimple_Socket_T server_sock, int timeout_ms);

  /**
   * @brief Send encrypted data over DTLS.
   *
   * @param sock DTLS socket.
   * @param data Data to send.
   * @param len Data length.
   * @return Bytes sent, or -1 on error.
   */
  extern ssize_t Socket_simple_dtls_send (SocketSimple_Socket_T sock,
                                          const void *data,
                                          size_t len);

  /**
   * @brief Receive encrypted data over DTLS.
   *
   * @param sock DTLS socket.
   * @param buf Receive buffer.
   * @param len Buffer size.
   * @return Bytes received, 0 on shutdown, -1 on error.
   */
  extern ssize_t
  Socket_simple_dtls_recv (SocketSimple_Socket_T sock, void *buf, size_t len);

  /**
   * @brief Send datagram to specific peer (unconnected mode).
   *
   * @param sock DTLS socket.
   * @param data Data to send.
   * @param len Data length.
   * @param host Destination host.
   * @param port Destination port.
   * @return Bytes sent, or -1 on error.
   */
  extern ssize_t Socket_simple_dtls_sendto (SocketSimple_Socket_T sock,
                                            const void *data,
                                            size_t len,
                                            const char *host,
                                            int port);

  /**
   * @brief Receive datagram with peer info (unconnected mode).
   *
   * @param sock DTLS socket.
   * @param buf Receive buffer.
   * @param len Buffer size.
   * @param host Buffer for peer hostname (can be NULL).
   * @param host_len Size of host buffer.
   * @param port Pointer to receive peer port (can be NULL).
   * @return Bytes received, 0 on shutdown, -1 on error.
   */
  extern ssize_t Socket_simple_dtls_recvfrom (SocketSimple_Socket_T sock,
                                              void *buf,
                                              size_t len,
                                              char *host,
                                              size_t host_len,
                                              int *port);

  /**
   * @brief Perform DTLS handshake (blocking).
   *
   * Call this after Socket_simple_dtls_enable() if using manual handshake.
   *
   * @param sock DTLS socket.
   * @param timeout_ms Handshake timeout (-1 for default).
   * @return 0 on success, -1 on error.
   */
  extern int
  Socket_simple_dtls_handshake (SocketSimple_Socket_T sock, int timeout_ms);

  /**
   * @brief Gracefully shutdown DTLS connection.
   *
   * Sends close_notify alert to peer.
   *
   * @param sock DTLS socket.
   * @return 0 on success, -1 on error.
   */
  extern int Socket_simple_dtls_shutdown (SocketSimple_Socket_T sock);

  /**
   * @brief Set MTU for DTLS connection.
   *
   * @param sock DTLS socket.
   * @param mtu MTU size (typically 1400 for IPv6).
   * @return 0 on success, -1 on error.
   */
  extern int
  Socket_simple_dtls_set_mtu (SocketSimple_Socket_T sock, size_t mtu);

  /**
   * @brief Check if socket has DTLS enabled.
   *
   * @param sock Socket to check.
   * @return 1 if DTLS enabled, 0 if not, -1 on error.
   */
  extern int Socket_simple_is_dtls (SocketSimple_Socket_T sock);

  /**
   * @brief Check if DTLS handshake is complete.
   *
   * @param sock DTLS socket.
   * @return 1 if complete, 0 if not, -1 on error.
   */
  extern int Socket_simple_dtls_is_handshake_done (SocketSimple_Socket_T sock);

  /**
   * @brief Get negotiated cipher suite name.
   *
   * @param sock DTLS socket.
   * @return Cipher name string, or NULL on error.
   */
  extern const char *Socket_simple_dtls_cipher (SocketSimple_Socket_T sock);

  /**
   * @brief Get DTLS protocol version.
   *
   * @param sock DTLS socket.
   * @return Version string (e.g., "DTLSv1.2"), or NULL on error.
   */
  extern const char *Socket_simple_dtls_version (SocketSimple_Socket_T sock);

  /**
   * @brief Get current MTU.
   *
   * @param sock DTLS socket.
   * @return MTU size, or 0 on error.
   */
  extern size_t Socket_simple_dtls_mtu (SocketSimple_Socket_T sock);

  /**
   * @brief Get ALPN protocol selected during handshake.
   *
   * @param sock DTLS socket.
   * @return ALPN protocol string, or NULL if none/error.
   */
  extern const char *Socket_simple_dtls_alpn (SocketSimple_Socket_T sock);

  /**
   * @brief Check if session was reused.
   *
   * @param sock DTLS socket.
   * @return 1 if reused, 0 if new session, -1 on error.
   */
  extern int Socket_simple_dtls_is_session_reused (SocketSimple_Socket_T sock);

  /**
   * @brief Initialize DTLS options with defaults.
   *
   * @param opts Options structure to initialize.
   */
  extern void
  Socket_simple_dtls_options_defaults (SocketSimple_DTLSOptions *opts);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_DTLS_INCLUDED */
