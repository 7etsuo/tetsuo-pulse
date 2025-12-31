/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETSIMPLE_TLS_INCLUDED
#define SOCKETSIMPLE_TLS_INCLUDED

/**
 * @file SocketSimple-tls.h
 * @brief Simple TLS/SSL connection operations.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

  /* Forward declaration from SocketSimple-tcp.h */
  typedef struct SocketSimple_Socket *SocketSimple_Socket_T;

/*============================================================================
 * TLS Options
 *============================================================================*/

/**
 * @brief Default TLS handshake timeout (30 seconds).
 */
#define SOCKET_TLS_HANDSHAKE_TIMEOUT_MS 30000

  /**
   * @brief TLS connection options.
   */
  typedef struct
  {
    int timeout_ms;          /**< Connection timeout (0 = default 30s) */
    int verify_cert;         /**< Verify server certificate (default: 1) */
    const char *ca_file;     /**< Custom CA file path (NULL = system default) */
    const char *ca_path;     /**< Custom CA directory (NULL = system default) */
    const char *client_cert; /**< Client certificate path (NULL = none) */
    const char *client_key;  /**< Client private key path (NULL = none) */
    const char *alpn; /**< ALPN protocols, comma-separated (NULL = none) */
    int min_version;  /**< Minimum TLS version: 0=default, 12=1.2, 13=1.3 */
  } SocketSimple_TLSOptions;

  /**
   * @brief Initialize TLS options to defaults.
   *
   * @param opts Options structure to initialize.
   */
  extern void Socket_simple_tls_options_init (SocketSimple_TLSOptions *opts);

  /*============================================================================
   * TLS Client Functions
   *============================================================================*/

  /**
   * @brief Connect to a TLS server (one-liner).
   *
   * Performs TCP connect, TLS handshake, and certificate verification.
   * Uses system CA certificates for verification.
   *
   * @param host Hostname (used for SNI and certificate verification).
   * @param port Port number (typically 443).
   * @return Socket handle on success, NULL on error.
   *
   * Example:
   * @code
   * SocketSimple_Socket_T sock = Socket_simple_connect_tls("api.example.com",
   * 443); if (!sock) { fprintf(stderr, "TLS error: %s\n",
   * Socket_simple_error()); return 1;
   * }
   * Socket_simple_send(sock, request, strlen(request));
   * Socket_simple_close(&sock);
   * @endcode
   */
  extern SocketSimple_Socket_T
  Socket_simple_connect_tls (const char *host, int port);

  /**
   * @brief Connect to a TLS server with options.
   *
   * @param host Hostname.
   * @param port Port number.
   * @param opts TLS options (NULL for defaults).
   * @return Socket handle on success, NULL on error.
   */
  extern SocketSimple_Socket_T
  Socket_simple_connect_tls_ex (const char *host,
                                int port,
                                const SocketSimple_TLSOptions *opts);

  /**
   * @brief Upgrade existing socket to TLS.
   *
   * The socket must already be connected via Socket_simple_connect().
   *
   * @param sock Connected socket handle.
   * @param hostname Hostname for SNI and verification.
   * @return 0 on success, -1 on error.
   */
  extern int
  Socket_simple_enable_tls (SocketSimple_Socket_T sock, const char *hostname);

  /**
   * @brief Upgrade existing socket to TLS with options.
   *
   * @param sock Connected socket handle.
   * @param hostname Hostname for SNI and verification.
   * @param opts TLS options (NULL for defaults).
   * @return 0 on success, -1 on error.
   */
  extern int Socket_simple_enable_tls_ex (SocketSimple_Socket_T sock,
                                          const char *hostname,
                                          const SocketSimple_TLSOptions *opts);

  /*============================================================================
   * TLS Server Functions
   *============================================================================*/

  /**
   * @brief Create a TLS server socket.
   *
   * @param host Bind address (NULL for any).
   * @param port Port number.
   * @param backlog Listen queue size.
   * @param cert_file Path to server certificate (PEM).
   * @param key_file Path to private key (PEM).
   * @return Socket handle on success, NULL on error.
   */
  extern SocketSimple_Socket_T Socket_simple_listen_tls (const char *host,
                                                         int port,
                                                         int backlog,
                                                         const char *cert_file,
                                                         const char *key_file);

  /**
   * @brief Accept TLS connection (performs handshake).
   *
   * @param server Listening TLS socket.
   * @return Client socket with TLS enabled, NULL on error.
   */
  extern SocketSimple_Socket_T
  Socket_simple_accept_tls (SocketSimple_Socket_T server);

  /*============================================================================
   * TLS Information
   *============================================================================*/

  /**
   * @brief Check if socket has TLS enabled.
   *
   * @param sock Socket handle.
   * @return 1 if TLS enabled, 0 if plain TCP.
   */
  extern int Socket_simple_is_tls (SocketSimple_Socket_T sock);

  /**
   * @brief Get negotiated ALPN protocol.
   *
   * @param sock TLS socket handle.
   * @return Protocol string (e.g., "h2", "http/1.1"), or NULL if not
   * negotiated.
   */
  extern const char *Socket_simple_get_alpn (SocketSimple_Socket_T sock);

  /**
   * @brief Get TLS version string.
   *
   * @param sock TLS socket handle.
   * @return Version string (e.g., "TLSv1.3"), or NULL if not TLS.
   */
  extern const char *Socket_simple_get_tls_version (SocketSimple_Socket_T sock);

  /**
   * @brief Get peer certificate information.
   *
   * @param sock TLS socket handle.
   * @param buf Output buffer for certificate info.
   * @param len Buffer length.
   * @return 0 on success, -1 on error.
   */
  extern int Socket_simple_get_cert_info (SocketSimple_Socket_T sock,
                                          char *buf,
                                          size_t len);

  /**
   * @brief Get peer certificate subject common name.
   *
   * @param sock TLS socket handle.
   * @param buf Output buffer.
   * @param len Buffer length.
   * @return 0 on success, -1 on error.
   */
  extern int
  Socket_simple_get_cert_cn (SocketSimple_Socket_T sock, char *buf, size_t len);

  /*============================================================================
   * TLS Cipher Information
   *============================================================================*/

  /**
   * @brief Get negotiated cipher suite name.
   *
   * @param sock TLS socket handle.
   * @return Cipher name string (e.g., "TLS_AES_256_GCM_SHA384"), or NULL on
   * error.
   */
  extern const char *Socket_simple_get_cipher (SocketSimple_Socket_T sock);

  /*============================================================================
   * TLS Session Resumption
   *============================================================================*/

  /**
   * @brief Check if TLS session was reused (abbreviated handshake).
   *
   * @param sock TLS socket handle after handshake.
   * @return 1 if session was reused, 0 if full handshake, -1 on error.
   */
  extern int Socket_simple_is_session_reused (SocketSimple_Socket_T sock);

  /**
   * @brief Export TLS session for later resumption.
   *
   * Exports the current TLS session in DER format. This can be saved and
   * restored later for abbreviated handshakes.
   *
   * @param sock TLS socket after successful handshake.
   * @param buf Output buffer (NULL to query required size).
   * @param len On input: buffer size. On output: actual/required size.
   * @return 1 on success, 0 if buffer too small, -1 on error.
   *
   * Example:
   * @code
   * // Query required size
   * size_t len = 0;
   * Socket_simple_session_save(sock, NULL, &len);
   *
   * // Allocate and save
   * unsigned char *session = malloc(len);
   * if (Socket_simple_session_save(sock, session, &len) == 1) {
   *     // Store session for later use
   * }
   * @endcode
   */
  extern int Socket_simple_session_save (SocketSimple_Socket_T sock,
                                         unsigned char *buf,
                                         size_t *len);

  /**
   * @brief Restore TLS session for resumption.
   *
   * Must be called after Socket_simple_enable_tls() but BEFORE handshake.
   *
   * @param sock TLS socket with TLS enabled, before handshake.
   * @param buf Previously saved session data.
   * @param len Session data length.
   * @return 1 on success, 0 if session invalid/expired, -1 on error.
   */
  extern int Socket_simple_session_restore (SocketSimple_Socket_T sock,
                                            const unsigned char *buf,
                                            size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SOCKETSIMPLE_TLS_INCLUDED */
