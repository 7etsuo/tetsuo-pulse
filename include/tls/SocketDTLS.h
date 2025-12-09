#ifndef SOCKETDTLS_INCLUDED
#define SOCKETDTLS_INCLUDED

/**
 * @file SocketDTLS.h
 * @ingroup security
 * @addtogroup security
 * @brief Datagram TLS (DTLS) protocol implementation for UDP sockets.
 *
 * Enables secure, encrypted communication over UDP using DTLS 1.2+, providing
 * TLS-equivalent security with datagram semantics. API parallels @ref SocketTLS
 * but for @ref SocketDgram_T, supporting non-blocking I/O and event integration.
 *
 * Core capabilities include:
 * - Strict DTLS 1.2+ enforcement with PFS and secure ciphers
 * - Cookie-based DoS protection for servers
 * - SNI, hostname verification, and ALPN negotiation
 * - Session resumption and configurable timeouts/MTU
 * - Transparent integration with @ref SocketPoll "SocketPoll"
 *
 * Requires OpenSSL/LibreSSL with DTLS support on POSIX platforms.
 *
 * @warning DTLS does not guarantee delivery; applications must handle loss/reordering.
 *
 * References:
 * - RFC 6347 (DTLS 1.2)
 * - RFC 9147 (DTLS 1.3)
 *
 * @see SocketDTLS_enable()
 * @see SocketDTLSContext_T
 * @see SocketDgram_T (@ref core_io)
 * @see SocketTLS_T (@ref security)
 * @see @ref event_system for async handshake handling.
 * @see docs/SECURITY.md
 * @see docs/ASYNC_IO.md
 */

#include "core/Except.h"
#include "socket/SocketDgram.h"

#if SOCKET_HAS_TLS

/**
 * @ingroup security
 * @brief Opaque DTLS context type.
 *
 * Used for configuring certificates, keys, protocol versions, ciphers, and other
 * DTLS parameters. See SocketDTLSContext.h for creation and configuration APIs.
 *
 * @see SocketDTLSContext_new_client()
 * @see SocketDTLSContext_new_server()
 * @see SocketDTLS_enable() to associate context with a socket.
 */
typedef struct SocketDTLSContext_T *SocketDTLSContext_T;

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @ingroup security
 * @brief General DTLS operation failure.
 *
 * Raised for generic errors in DTLS operations, such as invalid state or SSL
 * library failures not covered by specific exceptions.
 *
 * @see socket_error_buf in SocketUtil.h for detailed error message (thread-local).
 */
extern const Except_T SocketDTLS_Failed;

/**
 * @ingroup security
 * @brief DTLS handshake failure.
 *
 * Occurs during DTLS handshake due to protocol errors, incompatible versions,
 * or peer rejection.
 *
 * @see SocketDTLS_handshake()
 * @see SocketDTLS_handshake_loop()
 * @see SocketDTLSContext_set_min_protocol()
 */
extern const Except_T SocketDTLS_HandshakeFailed;

/**
 * @ingroup security
 * @brief Certificate verification failure.
 *
 * Triggered when peer certificate fails validation (e.g., untrusted CA, expired,
 * hostname mismatch).
 *
 * @see SocketDTLSContext_set_verify_mode()
 * @see SocketDTLS_get_verify_result()
 * @see SocketDTLS_set_hostname()
 */
extern const Except_T SocketDTLS_VerifyFailed;

/**
 * @ingroup security
 * @brief Cookie exchange failure.
 *
 * Raised during server-side cookie verification or generation errors in DoS
 * protection mode.
 *
 * @see SocketDTLSContext_enable_cookie_exchange()
 * @see SocketDTLSContext_set_cookie_secret()
 */
extern const Except_T SocketDTLS_CookieFailed;

/**
 * @ingroup security
 * @brief Handshake timeout expired.
 *
 * Thrown when handshake_loop() exceeds the specified timeout without completing.
 *
 * @see SocketDTLS_handshake_loop()
 */
extern const Except_T SocketDTLS_TimeoutExpired;

/**
 * @ingroup security
 * @brief DTLS shutdown failure.
 *
 * Error during graceful shutdown (close_notify alert transmission or reception).
 *
 * @see SocketDTLS_shutdown()
 */
extern const Except_T SocketDTLS_ShutdownFailed;

/* ============================================================================
 * Handshake State Machine
 * ============================================================================
 */

/**
 * @brief DTLS handshake progress states.
 * @ingroup security
 *
 * Enum values track the state of non-blocking DTLS handshakes for integration
 * with event loops like SocketPoll. States DTLS_HANDSHAKE_WANT_READ and
 * DTLS_HANDSHAKE_WANT_WRITE indicate the socket needs to be polled for the
 * corresponding event before retrying the handshake.
 *
 * @see SocketDTLS_handshake()
 * @see SocketDTLS_handshake_loop()
 * @see @ref event_system for event loop integration.
 */
typedef enum
{
  DTLS_HANDSHAKE_NOT_STARTED = 0,     /**< Handshake not yet initiated */
  DTLS_HANDSHAKE_IN_PROGRESS = 1,     /**< Handshake in progress */
  DTLS_HANDSHAKE_WANT_READ = 2,       /**< Need to read from socket */
  DTLS_HANDSHAKE_WANT_WRITE = 3,      /**< Need to write to socket */
  DTLS_HANDSHAKE_COOKIE_EXCHANGE = 4, /**< Cookie exchange in progress */
  DTLS_HANDSHAKE_COMPLETE = 5,        /**< Handshake completed successfully */
  DTLS_HANDSHAKE_ERROR = 6            /**< Handshake failed */
} DTLSHandshakeState;

/* ============================================================================
 * DTLS Enable and Configuration
 * ============================================================================
 */

/**
 * @brief Enable DTLS encryption on a datagram socket.
 * @ingroup security
 * @param socket The datagram socket instance (@ref SocketDgram_T).
 * @param ctx The DTLS context to use for this connection (@ref SocketDTLSContext_T).
 *
 * Enables DTLS on the specified datagram socket using the provided context.
 * The socket should be connected (clients) or bound (servers) prior to calling.
 * Associates an SSL object with the socket and initializes DTLS-specific state.
 *
 * @throws SocketDTLS_Failed if enabling fails (e.g., already enabled, invalid socket or context).
 * @threadsafe No - directly modifies socket internal state.
 *
 * @note Call after @ref SocketDgram_connect() (client) or @ref SocketDgram_bind() (server),
 * but before any DTLS I/O operations. Handshake is separate via @ref SocketDTLS_handshake().
 *
 * @see SocketDTLSContext_new_client()
 * @see SocketDTLSContext_new_server()
 * @see @ref core_io "Core I/O" for socket primitives.
 * @see docs/SECURITY.md for TLS configuration guidelines.
 */
extern void SocketDTLS_enable (SocketDgram_T socket, SocketDTLSContext_T ctx);

/**
 * @brief Set the peer address for a DTLS connection.
 * @ingroup security
 * @param socket The datagram socket instance (@ref SocketDgram_T).
 * @param host Peer hostname or IP address string.
 * @param port Peer port number (1-65535).
 *
 * Configures the destination address for DTLS packets. Clients typically set
 * this via @ref SocketDgram_connect() before enabling DTLS. Servers use this
 * to target responses to specific clients on unbound sockets.
 *
 * @throws SocketDTLS_Failed on invalid address format or resolution failure.
 * @threadsafe No - updates socket DTLS state.
 *
 * @note For servers handling multiple peers, call before each handshake or I/O.
 * Supports hostname resolution via getaddrinfo() if not numeric IP.
 *
 * @see SocketDgram_connect()
 * @see SocketDTLS_enable()
 * @see SocketDNS for async resolution (@ref core_io).
 */
extern void SocketDTLS_set_peer (SocketDgram_T socket, const char *host,
                                 int port);

/**
 * @brief Set SNI hostname for client DTLS connections
 * @ingroup security
 * @param socket The datagram socket instance
 * @param hostname Null-terminated hostname string for SNI and verification
 *
 * Sets the Server Name Indication (SNI) hostname for the DTLS connection.
 * Required for virtual hosting and enables hostname verification. Should be
 * called after SocketDTLS_enable() but before SocketDTLS_handshake().
 *
 * @throws SocketDTLS_Failed if DTLS not enabled or invalid hostname
 * @threadsafe No - modifies socket and SSL state
 */
extern void SocketDTLS_set_hostname (SocketDgram_T socket,
                                     const char *hostname);

/**
 * @brief Set link MTU for this connection
 * @ingroup security
 * @param socket The datagram socket instance
 * @param mtu Maximum Transmission Unit in bytes
 *
 * Overrides the context-level MTU for this specific connection.
 * Use for path-specific MTU optimization.
 *
 * @throws SocketDTLS_Failed if MTU invalid or DTLS not enabled
 * @threadsafe No
 */
extern void SocketDTLS_set_mtu (SocketDgram_T socket, size_t mtu);

/* ============================================================================
 * DTLS Handshake
 * ============================================================================
 */

/**
 * @brief Perform non-blocking DTLS handshake step
 * @ingroup security
 * @param socket The datagram socket instance with DTLS enabled
 *
 * Performs one step of the DTLS handshake. For non-blocking sockets, may
 * return WANT_READ or WANT_WRITE indicating more data or writability needed.
 * Call repeatedly in a poll loop until DTLS_HANDSHAKE_COMPLETE is returned.
 *
 * @return DTLSHandshakeState indicating progress
 * @throws SocketDTLS_HandshakeFailed on fatal errors
 * @threadsafe No - modifies socket DTLS state
 *
 * Note For servers with cookie exchange enabled, the first handshake step
 * will return COOKIE_EXCHANGE state until client echoes valid cookie.
 */
extern DTLSHandshakeState SocketDTLS_handshake (SocketDgram_T socket);

/**
 * @brief Complete handshake with timeout (blocking helper)
 * @ingroup security
 * @param socket The datagram socket instance with DTLS enabled
 * @param timeout_ms Maximum time to wait for handshake (0 for non-blocking single step)
 *
 * Convenience function to run the handshake loop until complete or timeout.
 * Uses poll internally for non-blocking operation.
 *
 * @return DTLSHandshakeState (COMPLETE on success, ERROR on failure/timeout)
 * @throws SocketDTLS_HandshakeFailed on error, SocketDTLS_TimeoutExpired on
 * timeout Thread-safe No
 */
extern DTLSHandshakeState SocketDTLS_handshake_loop (SocketDgram_T socket,
                                                     int timeout_ms);

/**
 * @brief Server Wait for incoming DTLS connection
 * @ingroup security
 * @param socket Bound datagram socket with DTLS enabled
 *
 * For servers, performs initial receive to get ClientHello and initiates
 * cookie exchange if enabled. Returns when a valid handshake can proceed.
 * Should be followed by SocketDTLS_handshake() calls.
 *
 * @return DTLSHandshakeState (WANT_READ if waiting, IN_PROGRESS if ready)
 * @throws SocketDTLS_Failed on error
 * @threadsafe No
 */
extern DTLSHandshakeState SocketDTLS_listen (SocketDgram_T socket);

/* ============================================================================
 * DTLS I/O Operations
 * ============================================================================
 */

/**
 * @brief Send data over DTLS-encrypted connection
 * @ingroup security
 * @param socket The datagram socket instance with completed DTLS handshake
 * @param buf Buffer containing data to send
 * @param len Number of bytes to send from buf
 *
 * Sends data using SSL_write(). For non-blocking sockets, returns 0 and sets
 * errno=EAGAIN if would block. Handshake must be complete before calling.
 *
 * Note Unlike TCP/TLS, DTLS preserves message boundaries - each send() is
 * received as a complete datagram by recv(). Data larger than MTU may be
 * fragmented at DTLS layer.
 *
 * @return Number of bytes sent, or 0 if would block
 * @throws SocketDTLS_Failed on errors
 * @threadsafe No - modifies SSL buffers
 */
extern ssize_t SocketDTLS_send (SocketDgram_T socket, const void *buf,
                                size_t len);

/**
 * @brief Receive data from DTLS-encrypted connection
 * @ingroup security
 * @param socket The datagram socket instance with completed DTLS handshake
 * @param buf Buffer to receive data into
 * @param len Maximum number of bytes to receive
 *
 * Receives data using SSL_read(). For non-blocking sockets, returns 0 and
 * sets errno=EAGAIN if would block.
 *
 * Note DTLS preserves message boundaries - each recv() returns exactly
 * one application datagram (or partial if buffer too small).
 *
 * @return Number of bytes received, or 0 if would block or EOF
 * @throws SocketDTLS_Failed on errors, Socket_Closed on clean shutdown
 * @threadsafe No - modifies SSL buffers
 */
extern ssize_t SocketDTLS_recv (SocketDgram_T socket, void *buf, size_t len);

/**
 * @brief Send DTLS datagram to specific address
 * @ingroup security
 * @param socket The datagram socket instance with DTLS enabled
 * @param buf Data to send
 * @param len Length of data
 * @param host Destination IP address or hostname
 * @param port Destination port
 *
 * For unconnected DTLS sockets (e.g., server responding to multiple clients).
 * Must have completed handshake with this peer.
 *
 * @return Number of bytes sent, or 0 if would block
 * @throws SocketDTLS_Failed on errors
 * @threadsafe No
 */
extern ssize_t SocketDTLS_sendto (SocketDgram_T socket, const void *buf,
                                  size_t len, const char *host, int port);

/**
 * @brief Receive DTLS datagram with sender address
 * @ingroup security
 * @param socket The datagram socket instance with DTLS enabled
 * @param buf Buffer for received data
 * @param len Buffer size
 * @param host Output buffer for sender IP address (>= 46 bytes for IPv6)
 * @param host_len Size of host buffer
 * @param port Output for sender port
 *
 * Receives DTLS datagram and provides sender address info.
 *
 * @return Number of bytes received, or 0 if would block
 * @throws SocketDTLS_Failed on errors
 * @threadsafe No
 */
extern ssize_t SocketDTLS_recvfrom (SocketDgram_T socket, void *buf,
                                    size_t len, char *host, size_t host_len,
                                    int *port);

/* ============================================================================
 * DTLS Connection Information
 * ============================================================================
 */

/**
 * @brief Get negotiated cipher suite name
 * @ingroup security
 * @param socket The datagram socket instance with completed handshake
 *
 * Returns the name of the cipher suite negotiated during handshake.
 *
 * @return Const string with cipher name, or NULL if unavailable
 * @threadsafe Yes - reads immutable post-handshake state
 */
extern const char *SocketDTLS_get_cipher (SocketDgram_T socket);

/**
 * @brief Get negotiated DTLS protocol version
 * @ingroup security
 * @param socket The datagram socket instance with completed handshake
 *
 * Returns the DTLS protocol version string (e.g., "DTLSv1.2").
 *
 * @return Const string with version, or NULL if unavailable
 * @threadsafe Yes
 */
extern const char *SocketDTLS_get_version (SocketDgram_T socket);

/**
 * @brief Get peer certificate verification result
 * @ingroup security
 * @param socket The datagram socket instance with completed handshake
 *
 * Returns OpenSSL's X509 verify result code. 0 (X509_V_OK) indicates
 * successful verification.
 *
 * @return long verify result code
 * @threadsafe Yes (read-only post-handshake)
 */
extern long SocketDTLS_get_verify_result (SocketDgram_T socket);

/**
 * @brief Check if DTLS session was resumed
 * @ingroup security
 * @param socket The datagram socket instance with completed handshake
 *
 * Determines if the connection used a resumed session (faster 1-RTT
 * handshake).
 *
 * @return 1 if reused, 0 if full handshake, -1 if unavailable
 * @threadsafe Yes
 */
extern int SocketDTLS_is_session_reused (SocketDgram_T socket);

/**
 * @brief Get the negotiated ALPN protocol
 * @ingroup security
 * @param socket Datagram socket instance with completed handshake
 *
 * Returns the ALPN protocol negotiated during handshake.
 *
 * @return Protocol string, or NULL if none negotiated
 * @threadsafe Yes - reads immutable post-handshake state
 */
extern const char *SocketDTLS_get_alpn_selected (SocketDgram_T socket);

/**
 * @brief Get current effective MTU
 * @ingroup security
 * @param socket The datagram socket instance
 *
 * Returns the MTU being used for DTLS record sizing.
 *
 * @return MTU in bytes
 * @threadsafe Yes
 */
extern size_t SocketDTLS_get_mtu (SocketDgram_T socket);

/* ============================================================================
 * DTLS Shutdown
 * ============================================================================
 */

/**
 * @brief Perform graceful DTLS connection shutdown
 * @ingroup security
 * @param socket The datagram socket instance with DTLS enabled
 *
 * Initiates DTLS shutdown (close_notify alert). May need multiple calls
 * for full shutdown in non-blocking mode. Call before closing socket.
 *
 * @throws SocketDTLS_ShutdownFailed on error
 * @threadsafe No - modifies SSL state
 */
extern void SocketDTLS_shutdown (SocketDgram_T socket);

/**
 * @brief Check if DTLS shutdown completed
 * @ingroup security
 * @param socket The datagram socket instance
 *
 * @return 1 if shutdown complete, 0 if not
 * @threadsafe Yes
 * @ingroup security
 */
extern int SocketDTLS_is_shutdown (SocketDgram_T socket);

/* ============================================================================
 * DTLS State Queries
 * ============================================================================
 */

/**
 * @brief Check if DTLS is enabled on socket
 * @ingroup security
 * @param socket The datagram socket instance
 *
 * @return 1 if DTLS enabled, 0 if not
 * @threadsafe Yes
 */
extern int SocketDTLS_is_enabled (SocketDgram_T socket);

/**
 * @brief Check if DTLS handshake is complete
 * @ingroup security
 * @param socket The datagram socket instance
 *
 * @return 1 if complete, 0 if not
 * @threadsafe Yes
 */
extern int SocketDTLS_is_handshake_done (SocketDgram_T socket);

/**
 * @brief Get last handshake state
 * @ingroup security
 * @param socket The datagram socket instance
 *
 * @return Last DTLSHandshakeState value
 * @threadsafe Yes
 */
extern DTLSHandshakeState SocketDTLS_get_last_state (SocketDgram_T socket);

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETDTLS_INCLUDED */
