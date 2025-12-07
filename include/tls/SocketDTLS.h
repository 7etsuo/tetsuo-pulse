#ifndef SOCKETDTLS_INCLUDED
#define SOCKETDTLS_INCLUDED

/**
 * SocketDTLS.h - DTLS/SSL Socket Integration (DTLS 1.2 Minimum)
 *
 * Provides DTLS (Datagram TLS) encryption for UDP sockets, enabling secure
 * communication over unreliable datagram transport. Mirrors the SocketTLS
 * API but operates on SocketDgram_T instead of Socket_T.
 *
 * Features:
 * - DTLS 1.2 minimum (strict PFS, no legacy vulns)
 * - Transparent I/O integration with SocketDgram
 * - Non-blocking handshake with poll integration
 * - Cookie exchange for DoS protection
 * - SNI + hostname verification
 * - ALPN support for protocol negotiation
 * - Session resumption for reduced latency
 *
 * Usage:
 *   // Client
 *   SocketDgram_T sock = SocketDgram_new(AF_INET, 0);
 *   SocketDgram_connect(sock, "server.example.com", 5684);
 *   SocketDTLSContext_T ctx = SocketDTLSContext_new_client("ca.pem");
 *   SocketDTLS_enable(sock, ctx);
 *   SocketDTLS_handshake_loop(sock, 5000); // 5 second timeout
 *   SocketDTLS_send(sock, data, len);
 *
 *   // Server
 *   SocketDgram_T server = SocketDgram_new(AF_INET, 0);
 *   SocketDgram_bind(server, "0.0.0.0", 5684);
 *   SocketDTLSContext_T ctx = SocketDTLSContext_new_server("cert.pem", "key.pem", NULL);
 *   SocketDTLSContext_enable_cookie_exchange(ctx);
 *   SocketDTLS_enable(server, ctx);
 *   // Handle incoming with SocketDTLS_listen() + SocketDTLS_handshake()
 *
 * PLATFORM REQUIREMENTS:
 * - OpenSSL 1.1.1+ or LibreSSL with DTLS support
 * - POSIX-compliant system (Linux, BSD, macOS)
 * - POSIX threads (pthread) for thread-safe error reporting
 *
 * References:
 * - RFC 6347: Datagram Transport Layer Security Version 1.2
 * - RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
 */

#include "core/Except.h"
#include "socket/SocketDgram.h"

#if SOCKET_HAS_TLS

/* DTLS error buffer for cross-module error reporting */
#ifdef _WIN32
extern __declspec (thread) char dtls_error_buf[];
#else
extern __thread char dtls_error_buf[];
#endif

/* Forward declaration for context type */
typedef struct SocketDTLSContext_T *SocketDTLSContext_T;

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

extern const Except_T SocketDTLS_Failed;          /**< General DTLS operation failure */
extern const Except_T SocketDTLS_HandshakeFailed; /**< DTLS handshake failure */
extern const Except_T SocketDTLS_VerifyFailed;    /**< Certificate verification failure */
extern const Except_T SocketDTLS_CookieFailed;    /**< Cookie exchange failure */
extern const Except_T SocketDTLS_TimeoutExpired;  /**< Handshake timeout */
extern const Except_T SocketDTLS_ShutdownFailed;  /**< DTLS shutdown failure */

/* ============================================================================
 * Handshake State Machine
 * ============================================================================
 */

/**
 * DTLSHandshakeState - DTLS handshake progress states
 *
 * Used to track non-blocking handshake progress and integrate with event loops.
 * WANT_READ/WANT_WRITE indicate socket should be added to poll for the
 * corresponding event before calling handshake again.
 */
typedef enum
{
  DTLS_HANDSHAKE_NOT_STARTED = 0, /**< Handshake not yet initiated */
  DTLS_HANDSHAKE_IN_PROGRESS = 1, /**< Handshake in progress */
  DTLS_HANDSHAKE_WANT_READ = 2,   /**< Need to read from socket */
  DTLS_HANDSHAKE_WANT_WRITE = 3,  /**< Need to write to socket */
  DTLS_HANDSHAKE_COOKIE_EXCHANGE = 4, /**< Cookie exchange in progress */
  DTLS_HANDSHAKE_COMPLETE = 5,    /**< Handshake completed successfully */
  DTLS_HANDSHAKE_ERROR = 6        /**< Handshake failed */
} DTLSHandshakeState;

/* ============================================================================
 * DTLS Enable and Configuration
 * ============================================================================
 */

/**
 * SocketDTLS_enable - Enable DTLS on a datagram socket
 * @socket: The datagram socket instance to enable DTLS on
 * @ctx: The DTLS context to use for this connection
 *
 * Enables DTLS encryption on the specified datagram socket. The socket
 * should be connected (for clients) or bound (for servers) before calling.
 * Creates an SSL object from the context, associates it with the socket,
 * and initializes DTLS state.
 *
 * Returns: void
 * Raises: SocketDTLS_Failed if DTLS cannot be enabled (e.g., already enabled,
 *         invalid socket, context error)
 * Thread-safe: No - modifies socket state directly
 *
 * Usage note: Call after SocketDgram_connect() (client) or SocketDgram_bind()
 * (server) but before any DTLS I/O. The handshake must be performed separately
 * using SocketDTLS_handshake().
 */
extern void SocketDTLS_enable (SocketDgram_T socket, SocketDTLSContext_T ctx);

/**
 * SocketDTLS_set_peer - Set peer address for DTLS connection
 * @socket: The datagram socket instance
 * @host: Peer hostname or IP address
 * @port: Peer port number
 *
 * Sets the peer address for DTLS. For clients, this is typically handled
 * by SocketDgram_connect() before enable. For servers accepting multiple
 * clients on a single socket, use this to switch peer context.
 *
 * Returns: void
 * Raises: SocketDTLS_Failed on invalid address or DNS failure
 * Thread-safe: No
 */
extern void SocketDTLS_set_peer (SocketDgram_T socket, const char *host,
                                 int port);

/**
 * SocketDTLS_set_hostname - Set SNI hostname for client DTLS connections
 * @socket: The datagram socket instance
 * @hostname: Null-terminated hostname string for SNI and verification
 *
 * Sets the Server Name Indication (SNI) hostname for the DTLS connection.
 * Required for virtual hosting and enables hostname verification. Should be
 * called after SocketDTLS_enable() but before SocketDTLS_handshake().
 *
 * Returns: void
 * Raises: SocketDTLS_Failed if DTLS not enabled or invalid hostname
 * Thread-safe: No - modifies socket and SSL state
 */
extern void SocketDTLS_set_hostname (SocketDgram_T socket,
                                     const char *hostname);

/**
 * SocketDTLS_set_mtu - Set link MTU for this connection
 * @socket: The datagram socket instance
 * @mtu: Maximum Transmission Unit in bytes
 *
 * Overrides the context-level MTU for this specific connection.
 * Use for path-specific MTU optimization.
 *
 * Returns: void
 * Raises: SocketDTLS_Failed if MTU invalid or DTLS not enabled
 * Thread-safe: No
 */
extern void SocketDTLS_set_mtu (SocketDgram_T socket, size_t mtu);

/* ============================================================================
 * DTLS Handshake
 * ============================================================================
 */

/**
 * SocketDTLS_handshake - Perform non-blocking DTLS handshake step
 * @socket: The datagram socket instance with DTLS enabled
 *
 * Performs one step of the DTLS handshake. For non-blocking sockets, may
 * return WANT_READ or WANT_WRITE indicating more data or writability needed.
 * Call repeatedly in a poll loop until DTLS_HANDSHAKE_COMPLETE is returned.
 *
 * Returns: DTLSHandshakeState indicating progress
 * Raises: SocketDTLS_HandshakeFailed on fatal errors
 * Thread-safe: No - modifies socket DTLS state
 *
 * Note: For servers with cookie exchange enabled, the first handshake step
 * will return COOKIE_EXCHANGE state until client echoes valid cookie.
 */
extern DTLSHandshakeState SocketDTLS_handshake (SocketDgram_T socket);

/**
 * SocketDTLS_handshake_loop - Complete handshake with timeout (blocking helper)
 * @socket: The datagram socket instance with DTLS enabled
 * @timeout_ms: Maximum time to wait for handshake (0 for non-blocking single
 * step)
 *
 * Convenience function to run the handshake loop until complete or timeout.
 * Uses poll internally for non-blocking operation.
 *
 * Returns: DTLSHandshakeState (COMPLETE on success, ERROR on failure/timeout)
 * Raises: SocketDTLS_HandshakeFailed on error, SocketDTLS_TimeoutExpired on
 * timeout Thread-safe: No
 */
extern DTLSHandshakeState SocketDTLS_handshake_loop (SocketDgram_T socket,
                                                     int timeout_ms);

/**
 * SocketDTLS_listen - Server: Wait for incoming DTLS connection
 * @socket: Bound datagram socket with DTLS enabled
 *
 * For servers, performs initial receive to get ClientHello and initiates
 * cookie exchange if enabled. Returns when a valid handshake can proceed.
 * Should be followed by SocketDTLS_handshake() calls.
 *
 * Returns: DTLSHandshakeState (WANT_READ if waiting, IN_PROGRESS if ready)
 * Raises: SocketDTLS_Failed on error
 * Thread-safe: No
 */
extern DTLSHandshakeState SocketDTLS_listen (SocketDgram_T socket);

/* ============================================================================
 * DTLS I/O Operations
 * ============================================================================
 */

/**
 * SocketDTLS_send - Send data over DTLS-encrypted connection
 * @socket: The datagram socket instance with completed DTLS handshake
 * @buf: Buffer containing data to send
 * @len: Number of bytes to send from buf
 *
 * Sends data using SSL_write(). For non-blocking sockets, returns 0 and sets
 * errno=EAGAIN if would block. Handshake must be complete before calling.
 *
 * Note: Unlike TCP/TLS, DTLS preserves message boundaries - each send() is
 * received as a complete datagram by recv(). Data larger than MTU may be
 * fragmented at DTLS layer.
 *
 * Returns: Number of bytes sent, or 0 if would block
 * Raises: SocketDTLS_Failed on errors
 * Thread-safe: No - modifies SSL buffers
 */
extern ssize_t SocketDTLS_send (SocketDgram_T socket, const void *buf,
                                size_t len);

/**
 * SocketDTLS_recv - Receive data from DTLS-encrypted connection
 * @socket: The datagram socket instance with completed DTLS handshake
 * @buf: Buffer to receive data into
 * @len: Maximum number of bytes to receive
 *
 * Receives data using SSL_read(). For non-blocking sockets, returns 0 and
 * sets errno=EAGAIN if would block.
 *
 * Note: DTLS preserves message boundaries - each recv() returns exactly
 * one application datagram (or partial if buffer too small).
 *
 * Returns: Number of bytes received, or 0 if would block or EOF
 * Raises: SocketDTLS_Failed on errors, Socket_Closed on clean shutdown
 * Thread-safe: No - modifies SSL buffers
 */
extern ssize_t SocketDTLS_recv (SocketDgram_T socket, void *buf, size_t len);

/**
 * SocketDTLS_sendto - Send DTLS datagram to specific address
 * @socket: The datagram socket instance with DTLS enabled
 * @buf: Data to send
 * @len: Length of data
 * @host: Destination IP address or hostname
 * @port: Destination port
 *
 * For unconnected DTLS sockets (e.g., server responding to multiple clients).
 * Must have completed handshake with this peer.
 *
 * Returns: Number of bytes sent, or 0 if would block
 * Raises: SocketDTLS_Failed on errors
 * Thread-safe: No
 */
extern ssize_t SocketDTLS_sendto (SocketDgram_T socket, const void *buf,
                                  size_t len, const char *host, int port);

/**
 * SocketDTLS_recvfrom - Receive DTLS datagram with sender address
 * @socket: The datagram socket instance with DTLS enabled
 * @buf: Buffer for received data
 * @len: Buffer size
 * @host: Output buffer for sender IP address (>= 46 bytes for IPv6)
 * @host_len: Size of host buffer
 * @port: Output for sender port
 *
 * Receives DTLS datagram and provides sender address info.
 *
 * Returns: Number of bytes received, or 0 if would block
 * Raises: SocketDTLS_Failed on errors
 * Thread-safe: No
 */
extern ssize_t SocketDTLS_recvfrom (SocketDgram_T socket, void *buf, size_t len,
                                    char *host, size_t host_len, int *port);

/* ============================================================================
 * DTLS Connection Information
 * ============================================================================
 */

/**
 * SocketDTLS_get_cipher - Get negotiated cipher suite name
 * @socket: The datagram socket instance with completed handshake
 *
 * Returns the name of the cipher suite negotiated during handshake.
 *
 * Returns: Const string with cipher name, or NULL if unavailable
 * Thread-safe: Yes - reads immutable post-handshake state
 */
extern const char *SocketDTLS_get_cipher (SocketDgram_T socket);

/**
 * SocketDTLS_get_version - Get negotiated DTLS protocol version
 * @socket: The datagram socket instance with completed handshake
 *
 * Returns the DTLS protocol version string (e.g., "DTLSv1.2").
 *
 * Returns: Const string with version, or NULL if unavailable
 * Thread-safe: Yes
 */
extern const char *SocketDTLS_get_version (SocketDgram_T socket);

/**
 * SocketDTLS_get_verify_result - Get peer certificate verification result
 * @socket: The datagram socket instance with completed handshake
 *
 * Returns OpenSSL's X509 verify result code. 0 (X509_V_OK) indicates
 * successful verification.
 *
 * Returns: long verify result code
 * Thread-safe: Yes (read-only post-handshake)
 */
extern long SocketDTLS_get_verify_result (SocketDgram_T socket);

/**
 * SocketDTLS_is_session_reused - Check if DTLS session was resumed
 * @socket: The datagram socket instance with completed handshake
 *
 * Determines if the connection used a resumed session (faster 1-RTT handshake).
 *
 * Returns: 1 if reused, 0 if full handshake, -1 if unavailable
 * Thread-safe: Yes
 */
extern int SocketDTLS_is_session_reused (SocketDgram_T socket);

/**
 * SocketDTLS_get_alpn_selected - Get the negotiated ALPN protocol
 * @socket: Datagram socket instance with completed handshake
 *
 * Returns the ALPN protocol negotiated during handshake.
 *
 * Returns: Protocol string, or NULL if none negotiated
 * Thread-safe: Yes - reads immutable post-handshake state
 */
extern const char *SocketDTLS_get_alpn_selected (SocketDgram_T socket);

/**
 * SocketDTLS_get_mtu - Get current effective MTU
 * @socket: The datagram socket instance
 *
 * Returns the MTU being used for DTLS record sizing.
 *
 * Returns: MTU in bytes
 * Thread-safe: Yes
 */
extern size_t SocketDTLS_get_mtu (SocketDgram_T socket);

/* ============================================================================
 * DTLS Shutdown
 * ============================================================================
 */

/**
 * SocketDTLS_shutdown - Perform graceful DTLS connection shutdown
 * @socket: The datagram socket instance with DTLS enabled
 *
 * Initiates DTLS shutdown (close_notify alert). May need multiple calls
 * for full shutdown in non-blocking mode. Call before closing socket.
 *
 * Returns: void
 * Raises: SocketDTLS_ShutdownFailed on error
 * Thread-safe: No - modifies SSL state
 */
extern void SocketDTLS_shutdown (SocketDgram_T socket);

/**
 * SocketDTLS_is_shutdown - Check if DTLS shutdown completed
 * @socket: The datagram socket instance
 *
 * Returns: 1 if shutdown complete, 0 if not
 * Thread-safe: Yes
 */
extern int SocketDTLS_is_shutdown (SocketDgram_T socket);

/* ============================================================================
 * DTLS State Queries
 * ============================================================================
 */

/**
 * SocketDTLS_is_enabled - Check if DTLS is enabled on socket
 * @socket: The datagram socket instance
 *
 * Returns: 1 if DTLS enabled, 0 if not
 * Thread-safe: Yes
 */
extern int SocketDTLS_is_enabled (SocketDgram_T socket);

/**
 * SocketDTLS_is_handshake_done - Check if DTLS handshake is complete
 * @socket: The datagram socket instance
 *
 * Returns: 1 if complete, 0 if not
 * Thread-safe: Yes
 */
extern int SocketDTLS_is_handshake_done (SocketDgram_T socket);

/**
 * SocketDTLS_get_last_state - Get last handshake state
 * @socket: The datagram socket instance
 *
 * Returns: Last DTLSHandshakeState value
 * Thread-safe: Yes
 */
extern DTLSHandshakeState SocketDTLS_get_last_state (SocketDgram_T socket);

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETDTLS_INCLUDED */

