/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDTLS_INCLUDED
#define SOCKETDTLS_INCLUDED

/**
 * @defgroup dtls Datagram TLS (DTLS) Module
 * @ingroup security
 * @brief Secure datagram communication using DTLS over UDP sockets.
 *
 * Provides DTLS 1.2+ protocol implementation paralleling @ref tls "SocketTLS"
 * but optimized for unreliable datagram transport (@ref SocketDgram_T).
 * Enables encrypted, authenticated UDP with forward secrecy, cookie anti-DoS,
 * and full async I/O support via @ref event_system.
 *
 * ## Architecture Overview
 *
 * ```
 * ┌───────────────────────────────────────────────────────────┐
 * │              Application Layer (e.g., CoAP, QUIC)          │
 * │                    ↑↓ I/O & Events                         │
 * ├───────────────────────────────────────────────────────────┤
 * │             DTLS Layer (this module)                      │
 * │  Handshake, Record Encrypt/Decrypt, Fragment/Reassembly    │
 * │                    ↑↓                                     │
 * ├───────────────────────────────────────────────────────────┤
 * │          UDP Transport (@ref core_io SocketDgram)         │
 * │                    ↑↓                                     │
 * └─────────┬────────────────────────────────────────────────┘
 *           │ Sends/Receives
 * ┌─────────▼────────────────────────────────────────────────┐
 * │        Foundation (@ref foundation: Arena, Except)        │
 * └───────────────────────────────────────────────────────────┘
 * ```
 *
 * ## Module Relationships
 *
 * - **Depends on**: @ref core_io (SocketDgram), @ref foundation
 * (memory/error), @ref event_system (async)
 * - **Optional**: @ref connection_mgmt (SocketPool for multi-client), @ref
 * security (SYNProtect integration)
 * - **Used by**: Applications needing secure UDP (IoT, gaming, media
 * streaming)
 * - **TLS Integration**: Shares contexts/certs with @ref tls "SocketTLS" where
 * possible
 *
 * ## Key Features
 *
 * - Non-blocking handshake with poll integration and cookie DoS protection
 * - Message boundary preservation (no TCP stream semantics)
 * - Configurable MTU, timeouts, ALPN, session resumption
 * - Certificate verification, SNI, secure cipher enforcement
 * - Cross-platform (OpenSSL/LibreSSL backends)
 *
 * Requires `SOCKET_HAS_TLS=ON` and DTLS library support. See CMake options.
 *
 * @warning DTLS offers no delivery/reorder guarantees; layer reliability if
 * required. Vulnerable to DoS without cookie exchange; always enable on public
 * servers.
 *
 * References:
 * - RFC 6347: DTLS 1.2 Transport Protocol
 * - RFC 9147: DTLS 1.3 Protocol
 * - RFC 6347 Appendix: Security Considerations
 *
 * @see SocketDTLS_enable() for setup
 * @see SocketDTLSContext_T for configuration
 * @see SocketDgram_T (@ref core_io) for base transport
 * @see SocketTLS_T (@ref tls) for stream counterpart
 * @see @ref event_system for event-driven usage
 * @see docs/SECURITY.md for hardening
 * @see docs/ASYNC_IO.md for integration patterns
 * @{
 */

/**
 * @file SocketDTLS.h
 * @ingroup dtls
 * @brief Core DTLS API for secure UDP sockets.
 *
 * Header defining opaque types, states, and functions for DTLS operations.
 * See module docs for architecture and usage.
 *
 * @see @ref dtls for full module guide
 */

#include "core/Except.h"
#include "socket/SocketDgram.h"

#if SOCKET_HAS_TLS

/**
 * @ingroup security
 * @brief Opaque DTLS context type.
 *
 * Used for configuring certificates, keys, protocol versions, ciphers, and
 * other DTLS parameters. See SocketDTLSContext.h for creation and
 * configuration APIs.
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
 * @see socket_error_buf in SocketUtil.h for detailed error message
 * (thread-local).
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
 * Triggered when peer certificate fails validation (e.g., untrusted CA,
 * expired, hostname mismatch).
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
 * Thrown when handshake_loop() exceeds the specified timeout without
 * completing.
 *
 * @see SocketDTLS_handshake_loop()
 */
extern const Except_T SocketDTLS_TimeoutExpired;

/**
 * @ingroup security
 * @brief DTLS shutdown failure.
 *
 * Error during graceful shutdown (close_notify alert transmission or
 * reception).
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
 *
 * Enables DTLS on the specified datagram socket using the provided context.
 * The socket should be connected (clients) or bound (servers) prior to
 * calling. Associates an SSL object with the socket and initializes
 * DTLS-specific state. This function consumes the reference to the context; it
 * will be freed when the socket is freed.
 *
 * @param[in] socket The datagram socket instance (@ref SocketDgram_T).
 * @param[in] ctx The DTLS context to use for this connection (@ref
 * SocketDTLSContext_T).
 *
 * @throws SocketDTLS_Failed if enabling fails (e.g., already enabled, invalid
 * socket or context).
 *
 * @threadsafe No - directly modifies socket internal state.
 *
 * @complexity O(1) - single SSL object creation and initialization.
 *
 * ## Usage Example
 *
 * ### Client Setup
 *
 * @code{.c}
 * TRY {
 *   SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
 *   SocketDgram_connect(socket, "example.com", 4433);  // Connect to DTLS
 * server
 *
 *   SocketDTLSContext_T ctx = SocketDTLSContext_new_client(NULL);
 *   SocketDTLSContext_set_verify_mode(ctx, SOCKET_DTLS_VERIFY_PEER);
 *   SocketDTLS_set_hostname(socket, "example.com");  // For SNI and
 * verification
 *
 *   SocketDTLS_enable(socket, ctx);  // Enable DTLS, ctx now owned by socket
 *
 *   // Proceed to handshake...
 * } EXCEPT(SocketDTLS_Failed) {
 *   // Handle error
 * } END_TRY;
 * @endcode
 *
 * ### Server Setup
 *
 * @code{.c}
 * TRY {
 *   SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
 *   SocketDgram_bind(socket, NULL, 4433);  // Bind to port
 *
 *   const char *cert = "server.crt", *key = "server.key";
 *   SocketDTLSContext_T ctx = SocketDTLSContext_new_server(cert, key, NULL);
 *   SocketDTLSContext_enable_cookie_exchange(ctx);  // Optional DoS protection
 *
 *   SocketDTLS_enable(socket, ctx);
 *
 *   // Now accept incoming handshakes via SocketDTLS_listen() or poll loop
 * } EXCEPT(SocketDTLS_Failed) {
 *   // Handle error
 * } END_TRY;
 * @endcode
 *
 * @note Call after @ref SocketDgram_connect() (client) or @ref
 * SocketDgram_bind() (server), but before any DTLS I/O operations. Handshake
 * is separate via @ref SocketDTLS_handshake(). The context is now owned by the
 * socket and will be cleaned up automatically.
 *
 * @warning Enabling DTLS on an already-enabled socket will raise
 * SocketDTLS_Failed. Do not free the context after enabling; it's managed by
 * the socket.
 *
 * @see SocketDTLSContext_new_client()
 * @see SocketDTLSContext_new_server()
 * @see SocketDTLSContext_free() - not needed after enable
 * @see @ref core_io "Core I/O" for socket primitives.
 * @see docs/SECURITY.md for TLS configuration guidelines.
 * @see docs/ASYNC_IO.md for non-blocking integration.
 */
extern void SocketDTLS_enable (SocketDgram_T socket, SocketDTLSContext_T ctx);

/**
 * @brief Set the peer address for a DTLS connection.
 * @ingroup security
 *
 * Configures the destination address for DTLS packets sent and received.
 * For connected sockets, this overrides the connected peer address.
 * Essential for unconnected server sockets handling multiple clients.
 * Performs synchronous hostname resolution if host is not numeric IP.
 *
 * @param[in] socket The datagram socket instance with DTLS enabled (@ref
 * SocketDgram_T).
 * @param[in] host Peer hostname or IP address string (e.g., "192.0.2.1" or
 * "example.com").
 * @param[in] port Peer port number (1-65535).
 *
 * @throws SocketDTLS_Failed on invalid address format, resolution failure, or
 * if DTLS not enabled.
 *
 * @threadsafe No - updates socket internal peer address state.
 *
 * @complexity O(1) for IP addresses, O(n) for hostname resolution via
 * getaddrinfo().
 *
 * ## Usage Example
 *
 * ### Client (Alternative to SocketDgram_connect)
 *
 * @code{.c}
 * SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
 * SocketDTLSContext_T ctx = SocketDTLSContext_new_client(NULL);
 * SocketDTLS_enable(socket, ctx);
 *
 * // Set peer explicitly (useful if not calling connect)
 * SocketDTLS_set_peer(socket, "dtls.example.com", 4433);
 * SocketDTLS_set_hostname(socket, "dtls.example.com");  // SNI
 *
 * // Now handshake...
 * DTLSHandshakeState state = SocketDTLS_handshake(socket);
 * @endcode
 *
 * ### Server Handling Multiple Clients
 *
 * @code{.c}
 * // Unconnected server socket bound to port
 * SocketDgram_T server = SocketDgram_new(AF_INET, 0);
 * SocketDgram_bind(server, NULL, 4433);
 * SocketDTLS_enable(server, server_ctx);
 *
 * // When receiving from a client (in recvfrom callback)
 * char client_host[INET6_ADDRSTRLEN];
 * int client_port;
 * // ... recvfrom to get client_host and client_port ...
 *
 * // Set peer for response/handshake
 * SocketDTLS_set_peer(server, client_host, client_port);
 * DTLSHandshakeState state = SocketDTLS_handshake(server);  // Or listen
 * @endcode
 *
 * @note For high-performance servers, consider async resolution with @ref
 * SocketDNS to avoid blocking in getaddrinfo(). Call this before each
 * handshake or I/O for multi-client support. IPv6 addresses are supported;
 * host buffer should accommodate INET6_ADDRSTRLEN.
 *
 * @warning Synchronous resolution may block; use @ref SocketDNS for async
 * alternative in event loops.
 *
 * @see SocketDgram_connect() - preferred for clients to set peer implicitly
 * @see SocketDTLS_enable() - must be called before set_peer
 * @see SocketDNS_resolve_sync() for manual async-integrated resolution
 * @see @ref core_io "Core I/O" for datagram socket primitives.
 * @see docs/SECURITY.md#dns-resolution for best practices.
 */
extern void SocketDTLS_set_peer (SocketDgram_T socket, const char *host,
                                 int port);

/**
 * @brief Set SNI hostname for client DTLS connections.
 * @ingroup security
 *
 * Sets the Server Name Indication (SNI) extension value and configures
 * hostname verification for certificate validation. Essential for clients
 * connecting to virtual hosts and ensuring correct certificate matching.
 *
 * Call after @ref SocketDTLS_enable() but before @ref SocketDTLS_handshake().
 * Affects both SNI sent in ClientHello and post-handshake peer verification.
 *
 * @param[in] socket The datagram socket instance with DTLS enabled (@ref
 * SocketDgram_T).
 * @param[in] hostname Null-terminated hostname string (e.g.,
 * "www.example.com").
 *
 * @throws SocketDTLS_Failed if DTLS not enabled on socket, invalid hostname
 * (too long, invalid chars), or SSL state error.
 *
 * @threadsafe No - modifies socket internal SSL configuration and hostname
 * state.
 *
 * @complexity O(1) - string copy and SSL_set_tlsext_host_name() call.
 *
 * ## Usage Example
 *
 * Typically used in client setup after enabling DTLS:
 *
 * @code{.c}
 * SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
 * SocketDgram_connect(socket, "example.com", 4433);
 *
 * SocketDTLSContext_T ctx = SocketDTLSContext_new_client(NULL);
 * SocketDTLSContext_set_verify_mode(ctx, SOCKET_DTLS_VERIFY_PEER);  // Enable
 * verification SocketDTLS_enable(socket, ctx);
 *
 * // Set hostname for SNI and cert verification
 * SocketDTLS_set_hostname(socket, "www.example.com");
 *
 * // Now perform handshake - will verify cert matches hostname
 * DTLSHandshakeState state;
 * while ((state = SocketDTLS_handshake(socket)) == DTLS_HANDSHAKE_WANT_READ ||
 *        state == DTLS_HANDSHAKE_WANT_WRITE) {
 *   // Poll socket for events and retry
 * }
 * if (state != DTLS_HANDSHAKE_COMPLETE) {
 *   // Handle failure, check SocketDTLS_get_verify_result(socket)
 * }
 * @endcode
 *
 * @note Hostname must be valid domain name per RFC 1034/6066. IP addresses are
 * not recommended for SNI. If peer verification fails due to hostname
 * mismatch, @ref SocketDTLS_VerifyFailed is raised during handshake. For
 * servers, this function has no effect (SNI is received, not sent).
 *
 * @warning Without setting hostname and enabling peer verification,
 * connections are vulnerable to MITM attacks. Always set for production
 * clients accessing named services.
 *
 * @see SocketDTLSContext_set_verify_mode() to control verification behavior
 * @see SocketDTLS_get_verify_result() to check verification outcome
 * @see SocketDTLS_handshake() - must follow this call
 * @see docs/SECURITY.md#certificate-verification for hardening guidelines.
 */
extern void SocketDTLS_set_hostname (SocketDgram_T socket,
                                     const char *hostname);

/**
 * @brief Set per-connection MTU for DTLS record sizing.
 * @ingroup security
 *
 * Overrides the global MTU setting from the DTLS context for this specific
 * socket. Controls the maximum size of DTLS records to avoid IP fragmentation.
 * Useful for path MTU discovery or network-specific optimizations.
 *
 * Must be called after @ref SocketDTLS_enable() but before handshake or I/O.
 * Valid MTU range: typically 256-9000 bytes, enforced by SOCKET_DTLS_MIN_MTU
 * and MAX.
 *
 * ## Valid MTU Ranges
 *
 * | Parameter | Value | Description |
 * |-----------|-------|-------------|
 * | Minimum   | 256   | Smallest supported for embedded networks |
 * | Default   | 1500  | Standard Ethernet MTU (adjust for overhead) |
 * | Maximum   | 9000  | Jumbo frames support |
 *
 * @param[in] socket The datagram socket instance with DTLS enabled (@ref
 * SocketDgram_T).
 * @param[in] mtu Maximum Transmission Unit in bytes (must be valid range).
 *
 * @throws SocketDTLS_Failed if DTLS not enabled or mtu outside valid range.
 *
 * @threadsafe No - updates socket-specific DTLS bio and record parameters.
 *
 * @complexity O(1) - simple parameter update.
 *
 * ## Usage Example
 *
 * Set custom MTU after enabling DTLS:
 *
 * @code{.c}
 * SocketDgram_T socket = SocketDgram_new(AF_INET, 0);
 * SocketDTLSContext_T ctx = SocketDTLSContext_new_client(NULL);
 * SocketDTLS_enable(socket, ctx);
 *
 * // Set MTU for low-bandwidth network (e.g., mobile)
 * SocketDTLS_set_mtu(socket, 576);  // Conservative value avoiding
 * fragmentation
 *
 * // Verify setting
 * assert(SocketDTLS_get_mtu(socket) == 576);
 *
 * // Proceed with handshake and I/O - records will respect this MTU
 * @endcode
 *
 * @note DTLS adds ~50-100 bytes overhead (headers + auth); effective app
 * payload is MTU minus overhead. Incorrect MTU may cause fragmentation or
 * packet drops. Use path MTU discovery for optimal. Changing MTU
 * mid-connection is supported but may trigger record re-segmentation.
 *
 * @warning Setting MTU too small wastes bandwidth on overhead; too large
 * causes fragmentation. Test with network conditions or use default unless
 * specific needs.
 *
 * @see SocketDTLSContext_set_mtu() - set global context MTU (before enable)
 * @see SocketDTLS_get_mtu() - query current effective MTU
 * @see SocketDTLSConfig.h for compile-time MTU constants
 * @see docs/SECURITY.md#dtls-mtu for fragmentation guidelines.
 */
extern void SocketDTLS_set_mtu (SocketDgram_T socket, size_t mtu);

/* ============================================================================
 * DTLS Handshake
 * ============================================================================
 */

/**
 * @brief Perform one step of the non-blocking DTLS handshake.
 * @ingroup security
 *
 * Advances the DTLS handshake state machine by processing incoming packets
 * and sending handshake messages as needed. Designed for integration with
 * event loops like @ref SocketPoll. Returns intermediate states to allow
 * polling the socket for required I/O before retrying.
 *
 * Supports both client and server roles, including cookie exchange for DoS
 * protection on servers. Call in a loop until DTLS_HANDSHAKE_COMPLETE or
 * error.
 *
 * @param[in,out] socket The datagram socket instance with DTLS enabled and
 * peer set (@ref SocketDgram_T).
 *
 * @return DTLSHandshakeState:
 *   - DTLS_HANDSHAKE_COMPLETE: Success, ready for I/O
 *   - DTLS_HANDSHAKE_WANT_READ: Poll for POLL_READ and retry
 *   - DTLS_HANDSHAKE_WANT_WRITE: Poll for POLL_WRITE and retry
 *   - DTLS_HANDSHAKE_COOKIE_EXCHANGE: Server waiting for client cookie
 * response
 *   - DTLS_HANDSHAKE_ERROR: Fatal error (check errno or
 * SocketDTLS_get_verify_result)
 *
 * @throws SocketDTLS_HandshakeFailed on protocol errors, version mismatch, or
 * crypto failures.
 * @throws SocketDTLS_VerifyFailed if certificate verification fails (clients).
 * @throws SocketDTLS_CookieFailed on server cookie generation/verification
 * issues.
 *
 * @threadsafe No - advances shared SSL handshake state.
 *
 * @complexity O(n) where n is handshake message size - processes crypto
 * operations.
 *
 * ## Usage Example: Event Loop Integration
 *
 * Non-blocking handshake with @ref SocketPoll:
 *
 * @code{.c}
 * SocketPoll_T poll = SocketPoll_new(10);
 * SocketDgram_setnonblocking(socket, 1);  // Ensure non-blocking
 * SocketPoll_add(poll, Socket_fd(socket), POLL_READ | POLL_WRITE, socket);
 *
 * DTLSHandshakeState state = DTLS_HANDSHAKE_NOT_STARTED;
 * while (state != DTLS_HANDSHAKE_COMPLETE && state != DTLS_HANDSHAKE_ERROR) {
 *   state = SocketDTLS_handshake(socket);
 *
 *   switch (state) {
 *     case DTLS_HANDSHAKE_WANT_READ:
 *       // Wait for incoming handshake messages
 *       SocketPoll_wait(poll, NULL, -1);  // Or integrate with timeout
 *       break;
 *     case DTLS_HANDSHAKE_WANT_WRITE:
 *       // Send handshake messages (e.g., ServerHello)
 *       SocketPoll_wait(poll, NULL, -1);
 *       break;
 *     case DTLS_HANDSHAKE_COOKIE_EXCHANGE:
 *       // Server: Cookie sent, wait for client echo (POLL_READ)
 *       SocketPoll_wait(poll, NULL, SOCKET_DTLS_COOKIE_LIFETIME_SEC * 1000);
 *       break;
 *     case DTLS_HANDSHAKE_IN_PROGRESS:
 *       // Continue polling
 *       break;
 *     default:
 *       break;
 *   }
 * }
 *
 * if (state == DTLS_HANDSHAKE_COMPLETE) {
 *   // Handshake done, start application I/O
 * } else {
 *   // Handle error, possibly retry or close
 * }
 * @endcode
 *
 * ## Server Cookie Exchange
 *
 * With cookies enabled in context, initial calls return COOKIE_EXCHANGE until
 * client responds:
 *
 * @code{.c}
 * SocketDTLSContext_enable_cookie_exchange(ctx);
 * // ... enable on socket ...
 *
 * state = SocketDTLS_handshake(socket);  // May send HelloVerifyRequest
 * if (state == DTLS_HANDSHAKE_COOKIE_EXCHANGE) {
 *   // Poll for client response with cookie
 *   // On receipt, next handshake() advances to full handshake
 * }
 * @endcode
 *
 * @note For servers, call @ref SocketDTLS_listen() first to receive
 * ClientHello. Ensure socket is non-blocking for event integration. Timeouts
 * handled via poll timeouts. Metrics: Increments
 * SOCKET_CTR_DTLS_HANDSHAKES_TOTAL/Failed on completion/error.
 *
 * @warning Do not call during active I/O; handshake must complete before
 * send/recv. Failed handshakes leave socket in error state; recreate for
 * retry.
 *
 * @see SocketDTLS_handshake_loop() for blocking convenience wrapper
 * @see SocketDTLS_listen() for server initial receive
 * @see DTLSHandshakeState enum for all states
 * @see @ref event_system "Event System" for poll/timer integration
 * @see docs/ASYNC_IO.md#handshake-patterns for advanced patterns
 * @see docs/SECURITY.md#dtls-handshake for security considerations.
 */
extern DTLSHandshakeState SocketDTLS_handshake (SocketDgram_T socket);

/**
 * @brief Blocking DTLS handshake with configurable timeout.
 * @ingroup security
 *
 * Convenience wrapper that repeatedly calls @ref SocketDTLS_handshake() until
 * completion, error, or timeout. Internally uses @ref SocketPoll for waiting
 * on socket events in non-blocking mode. Suitable for synchronous code paths.
 *
 * Handles WANT_READ/WANT_WRITE states by polling with the remaining timeout.
 * For timeout_ms=0, performs single non-blocking step (equivalent to
 * handshake()).
 *
 * @param[in,out] socket The datagram socket instance with DTLS enabled (@ref
 * SocketDgram_T).
 * @param[in] timeout_ms Maximum milliseconds to wait (0=single step,
 * -1=infinite).
 *
 * @return DTLSHandshakeState: COMPLETE on success, ERROR on failure/timeout.
 *
 * @throws SocketDTLS_HandshakeFailed on protocol/crypto errors.
 * @throws SocketDTLS_TimeoutExpired if timeout reached without completion.
 * @throws SocketDTLS_VerifyFailed on certificate issues.
 *
 * @threadsafe No - performs blocking operations on socket state.
 *
 * @complexity O(h) where h is number of handshake round-trips; blocks up to
 * timeout_ms.
 *
 * ## Usage Examples
 *
 * ### Synchronous Client Handshake
 *
 * @code{.c}
 * // After enable, set_peer, set_hostname
 * TRY {
 *   DTLSHandshakeState state = SocketDTLS_handshake_loop(socket, 5000);  // 5s
 * timeout if (state == DTLS_HANDSHAKE_COMPLETE) { printf("DTLS handshake
 * succeeded\n");
 *     // Now safe to send/recv
 *   } else {
 *     // Handle timeout or error
 *     long verify = SocketDTLS_get_verify_result(socket);
 *     if (verify != X509_V_OK) {
 *       // Cert issue
 *     }
 *   }
 * } EXCEPT(SocketDTLS_TimeoutExpired) {
 *   // Specific timeout handling
 * } END_TRY;
 * @endcode
 *
 * ### Single Non-Blocking Step
 *
 * @code{.c}
 * // In event loop, for finer control
 * DTLSHandshakeState state = SocketDTLS_handshake_loop(socket, 0);
 * if (state == DTLS_HANDSHAKE_WANT_READ) {
 *   // Schedule read event
 * }
 * @endcode
 *
 * ### Server with Infinite Timeout
 *
 * @code{.c}
 * // For servers where timeout not critical
 * DTLSHandshakeState state = SocketDTLS_handshake_loop(socket, -1);
 * @endcode
 *
 * @note Uses internal temporary @ref SocketPoll; does not interfere with
 * external polls. Recommended timeout: 3000-10000ms for typical networks.
 * Adjust based on RTT. On servers with cookies, includes wait for cookie
 * round-trip. After success, check @ref SocketDTLS_get_cipher() and version
 * for negotiated params.
 *
 * @warning Blocks calling thread; avoid in hot event loops. Use plain
 * handshake() for async. Infinite timeout (-1) risks hangs on network issues;
 * prefer finite values.
 *
 * @see SocketDTLS_handshake() for low-level non-blocking control
 * @see Socket_get_monotonic_ms() for custom timeouts
 * @see @ref event_system for full async patterns
 * @see docs/ASYNC_IO.md#blocking-vs-nonblocking for tradeoffs.
 */
extern DTLSHandshakeState SocketDTLS_handshake_loop (SocketDgram_T socket,
                                                     int timeout_ms);

/**
 * @brief Server-side initial DTLS handshake receive.
 * @ingroup security
 *
 * For DTLS servers, waits for and processes the initial ClientHello packet.
 * Triggers cookie exchange if enabled in context for DoS protection.
 * Non-blocking: returns WANT_READ if no data, or advances to cookie
 * exchange/in progress.
 *
 * Call in server event loop after binding and enabling DTLS on listening
 * socket. Follow with @ref SocketDTLS_handshake() to complete the handshake.
 * Supports multi-client via per-peer state (set peer addr before continuing).
 *
 * @param[in,out] socket Bound datagram socket with DTLS enabled (@ref
 * SocketDgram_T).
 *
 * @return DTLSHandshakeState:
 *   - DTLS_HANDSHAKE_WANT_READ: No ClientHello received yet, poll again
 *   - DTLS_HANDSHAKE_COOKIE_EXCHANGE: Cookie sent, wait for client response
 *   - DTLS_HANDSHAKE_IN_PROGRESS: ClientHello processed, proceed to
 * handshake()
 *   - Other states: Error or unexpected
 *
 * @throws SocketDTLS_Failed on recv errors or invalid ClientHello.
 * @throws SocketDTLS_CookieFailed if cookie generation fails.
 *
 * @threadsafe No - receives into and updates socket SSL state.
 *
 * @complexity O(1) + crypto time for cookie if enabled.
 *
 * ## Usage Example: Server Event Loop
 *
 * Integrate with poll for accepting new connections:
 *
 * @code{.c}
 * SocketDgram_T listen_sock = SocketDgram_new(AF_INET, 0);
 * SocketDgram_bind(listen_sock, NULL, 4433);
 * SocketDgram_setnonblocking(listen_sock, 1);
 * SocketDTLSContext_T ctx = SocketDTLSContext_new_server(cert, key, NULL);
 * SocketDTLSContext_enable_cookie_exchange(ctx);  // Optional DoS protection
 * SocketDTLS_enable(listen_sock, ctx);
 *
 * SocketPoll_T poll = SocketPoll_new(1);
 * SocketPoll_add(poll, Socket_fd(listen_sock), POLL_READ, listen_sock);
 *
 * while (server_running) {
 *   SocketEvent_T events[1];
 *   int nfds = SocketPoll_wait(poll, events, 1000);  // 1s timeout
 *
 *   if (nfds > 0 && events[0].events & POLL_READ) {
 *     DTLSHandshakeState state = SocketDTLS_listen(listen_sock);
 *
 *     if (state == DTLS_HANDSHAKE_COOKIE_EXCHANGE ||
 *         state == DTLS_HANDSHAKE_IN_PROGRESS) {
 *       // New client detected, create per-client socket or continue on this
 *       // Set peer addr if needed via recvfrom info
 *       // Then call SocketDTLS_handshake() in loop until complete
 *       SocketDTLS_set_peer(listen_sock, client_ip, client_port);
 *       // ... complete handshake ...
 *     }
 *   }
 * }
 * @endcode
 *
 * @note For multi-client servers, typically fork per-client state or use
 * connection pool. Call on listening socket or per-client socket. Integrates
 * with @ref SocketPool for management. Cookie exchange adds 1-RTT delay but
 * protects against floods.
 *
 * @warning Listening socket must be non-blocking. Does not handle multiple
 * simultaneous hellos; use select/poll. After listen, immediately follow with
 * handshake loop for full completion.
 *
 * @see SocketDTLSContext_enable_cookie_exchange() for DoS protection
 * @see SocketDTLS_handshake() to continue after listen
 * @see SocketDgram_recvfrom() for manual packet handling if needed
 * @see @ref connection_mgmt for pooling multiple DTLS connections
 * @see docs/SECURITY.md#syn-protect equivalent for DTLS DoS
 * @see docs/ASYNC_IO.md#server-patterns for scalable servers.
 */
extern DTLSHandshakeState SocketDTLS_listen (SocketDgram_T socket);

/* ============================================================================
 * DTLS I/O Operations
 * ============================================================================
 */

/**
 * @brief Send application data over established DTLS connection.
 * @ingroup security
 *
 * Encrypts and transmits data as a single DTLS application record.
 * For non-blocking sockets, returns < len on partial send or 0/-1 on
 * EAGAIN/block. Requires completed handshake (@ref
 * SocketDTLS_is_handshake_done() == 1). Automatically handles record layering,
 * sequencing, and retransmission.
 *
 * Critical: DTLS is datagram-oriented - each send() generates one logical
 * message preserved at receiver (unlike stream-oriented TLS). Large payloads
 * (> MTU) are automatically fragmented and reassembled by DTLS.
 *
 * @param[in] socket The datagram socket with completed DTLS handshake (@ref
 * SocketDgram_T).
 * @param[in] buf Buffer containing plaintext data to send.
 * @param[in] len Number of bytes from buf to send (must respect MTU for
 * efficiency).
 *
 * @return Number of bytes sent (may be partial), 0 on would-block
 * (non-blocking), -1 on error.
 *
 * @throws SocketDTLS_Failed on encryption errors, sequence anomalies, or peer
 * close.
 * @throws SocketDTLS_ShutdownFailed if connection shutting down.
 *
 * @threadsafe No - updates SSL send buffers and sequence numbers.
 *
 * @complexity O(len) - symmetric encryption/decryption time.
 *
 * ## Usage Example
 *
 * Basic send after handshake:
 *
 * @code{.c}
 * // Assume handshake complete
 * if (SocketDTLS_is_handshake_done(socket)) {
 *   const char *msg = "Hello, secure DTLS world!";
 *   ssize_t sent = SocketDTLS_send(socket, msg, strlen(msg));
 *   if (sent > 0) {
 *     // Success, message sent as atomic datagram
 *   } else if (sent == 0 || errno == EAGAIN) {
 *     // Non-blocking: retry after POLL_WRITE
 *   } else {
 *     // Error: check Socket_GetLastError()
 *   }
 * }
 * @endcode
 *
 * ## Non-Blocking with Poll
 *
 * @code{.c}
 * SocketPoll_T poll = SocketPoll_new(1);
 * SocketPoll_add(poll, Socket_fd(socket), POLL_WRITE, NULL);
 *
 * ssize_t total_sent = 0;
 * const char *data = large_buffer;
 * size_t to_send = large_size;
 *
 * while (total_sent < to_send) {
 *   ssize_t sent = SocketDTLS_send(socket, data + total_sent, to_send -
 * total_sent); if (sent > 0) { total_sent += sent; } else if (errno == EAGAIN)
 * { SocketPoll_wait(poll, NULL, -1);  // Wait for writability } else {
 *     // Handle error
 *     break;
 *   }
 * }
 * @endcode
 *
 * @note Respects socket @ref Socket_set_timeout(); may raise Socket_Timeout.
 * For efficiency, batch small messages or use @ref SocketBuf for buffering.
 * Sender must handle retransmission timeouts via app-level ACKs (DTLS only
 * retransmits handshake). Metrics: Increments bytes sent counters.
 *
 * @warning Sending before handshake complete or after shutdown raises error.
 * Large sends (> MTU) fragment; receiver gets complete message or none
 * (best-effort). No delivery guarantee - UDP semantics apply; use reliability
 * on top if needed.
 *
 * @see SocketDTLS_recv() - counterpart for receiving
 * @see SocketDTLS_sendto() for unconnected multi-peer sends
 * @see SocketDgram_setnonblocking() for async mode
 * @see @ref utilities "Utilities" for rate limiting large transfers
 * @see docs/SECURITY.md#dtls-io for performance tuning.
 */
extern ssize_t SocketDTLS_send (SocketDgram_T socket, const void *buf,
                                size_t len);

/**
 * @brief Receive application data from established DTLS connection.
 * @ingroup security
 *
 * Decrypts and delivers one complete application message from the DTLS record
 * layer. For non-blocking sockets, returns 0 on EAGAIN/no data or partial
 * message. Requires completed handshake; checks for close_notify or errors.
 *
 * Key property: Message-oriented - recv() delivers entire sent datagram
 * (reassembled from fragments if needed) or blocks/partials. No stream merging
 * like TCP/TLS. Handles out-of-order packets, duplicates, and losses via DTLS
 * sequencing.
 *
 * @param[in] socket The datagram socket with completed DTLS handshake (@ref
 * SocketDgram_T).
 * @param[out] buf Buffer to receive decrypted plaintext data.
 * @param[in] len Maximum bytes to receive into buf (suggest >= MTU for full
 * messages).
 *
 * @return Number of bytes received (>0 complete/partial message), 0 on
 * EOF/close or would-block, -1 on error.
 *
 * @throws SocketDTLS_Failed on decryption errors, bad records, or peer errors.
 * @throws Socket_Closed on clean remote shutdown (close_notify received).
 *
 * @threadsafe No - advances SSL receive buffers and sequence state.
 *
 * @complexity O(len) - symmetric decryption and integrity checks.
 *
 * ## Usage Example
 *
 * Basic receive after handshake:
 *
 * @code{.c}
 * char recv_buf[4096];  // Larger than typical MTU
 * ssize_t recvd = SocketDTLS_recv(socket, recv_buf, sizeof(recv_buf));
 * if (recvd > 0) {
 *   // Process complete message of recvd bytes
 *   // Note: One logical app datagram, may be fragmented under DTLS
 * } else if (recvd == 0 || errno == EAGAIN) {
 *   // No data or non-blocking wait needed (POLL_READ)
 * } else {
 *   // Error or clean close
 *   if (SocketDTLS_is_shutdown(socket)) {
 *     // Peer closed connection
 *   }
 * }
 * @endcode
 *
 * ## Non-Blocking Loop with Poll
 *
 * @code{.c}
 * SocketPoll_T poll = SocketPoll_new(1);
 * SocketPoll_add(poll, Socket_fd(socket), POLL_READ, NULL);
 *
 * while (expected_messages) {
 *   ssize_t recvd = SocketDTLS_recv(socket, recv_buf, sizeof(recv_buf));
 *   if (recvd > 0) {
 *     process_message(recv_buf, recvd);  // Handle full datagram
 *   } else if (errno == EAGAIN) {
 *     SocketPoll_wait(poll, NULL, timeout_ms);  // Wait for data
 *   } else {
 *     // Handle error/close
 *     break;
 *   }
 * }
 * @endcode
 *
 * @note Buffer size should accommodate max expected message + margin; partial
 * receives possible in non-blocking. Integrates with @ref SocketPool for
 * connection mgmt. App must handle message loss (no reliability). On
 * close_notify (0 return, errno=0), initiate local shutdown. Metrics: Tracks
 * recv bytes/errors.
 *
 * @warning Receiving before handshake raises error. Lost/partial messages
 * require app retransmit. Buffer overflow truncates message; always check
 * return vs requested len. For multi-peer, use recvfrom variant.
 *
 * @see SocketDTLS_send() - sending counterpart
 * @see SocketDTLS_recvfrom() for address info
 * @see SocketBuf for buffering multiple messages
 * @see @ref event_system for poll integration
 * @see docs/SECURITY.md#dtls-io for best practices on message sizes.
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
 * @brief Get name of negotiated cipher suite.
 * @ingroup security
 *
 * Returns human-readable name of the symmetric cipher suite agreed upon during
 * handshake (e.g., "TLS_AES_256_GCM_SHA384" for DTLS 1.3). Post-handshake
 * only.
 *
 * Useful for logging, debugging, and security auditing.
 *
 * @param[in] socket The datagram socket with completed handshake (@ref
 * SocketDgram_T).
 *
 * @return Const null-terminated string (do not free), or NULL
 * pre-handshake/unavailable.
 *
 * @threadsafe Yes - reads immutable negotiated parameters.
 *
 * ## Usage Example
 *
 * @code{.c}
 * if (SocketDTLS_is_handshake_done(socket)) {
 *   const char *cipher = SocketDTLS_get_cipher(socket);
 *   if (cipher) {
 *     SOCKET_LOG_INFO_MSG("DTLS cipher: %s", cipher);
 *   }
 *   // Audit or select protocol features based on cipher strength
 * }
 * @endcode
 *
 * @note String owned by SSL library; valid until shutdown/free.
 * Common values: AES-GCM for modern secure, ChaCha20-Poly for mobile
 * efficiency. Check against @ref SocketDTLSContext_set_ciphers() for
 * configured suites.
 *
 * @see SocketDTLS_get_version() for protocol version
 * @see SocketDTLSContext_set_ciphers() for configuration
 * @see docs/SECURITY.md#ciphersuites for security recommendations.
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
 * @brief Initiate graceful DTLS connection shutdown.
 * @ingroup security
 *
 * Sends close_notify alert to peer and transitions to shutdown state.
 * For non-blocking sockets, may return after sending alert; call repeatedly
 * until @ref SocketDTLS_is_shutdown() == 1. Always call before @ref
 * SocketDgram_free(). Peer may continue sending data until alert processed;
 * drain recv if needed.
 *
 * Supports half-close (send shutdown without recv close).
 *
 * @param[in,out] socket The datagram socket with active DTLS connection (@ref
 * SocketDgram_T).
 *
 * @throws SocketDTLS_ShutdownFailed if already shutting down, handshake
 * incomplete, or send error.
 *
 * @threadsafe No - sends alert and updates SSL shutdown state.
 *
 * @complexity O(1) - sends fixed-size alert record.
 *
 * ## Usage Example
 *
 * Graceful close after application logic:
 *
 * @code{.c}
 * // Signal intent to close
 * TRY {
 *   SocketDTLS_shutdown(socket);
 * } EXCEPT(SocketDTLS_ShutdownFailed) {
 *   // Log but continue (best-effort)
 * } END_TRY;
 *
 * // Drain any remaining recv data (optional)
 * char buf[1024];
 * while (SocketDTLS_recv(socket, buf, sizeof(buf)) > 0) {
 *   // Process lingering data
 * }
 *
 * // Wait for shutdown complete in non-blocking
 * while (!SocketDTLS_is_shutdown(socket)) {
 *   DTLSHandshakeState state = SocketDTLS_handshake(socket);  // Processes
 * peer close_notify if (state == DTLS_HANDSHAKE_WANT_READ || state ==
 * DTLS_HANDSHAKE_WANT_WRITE) {
 *     // Poll and retry
 *   } else {
 *     break;
 *   }
 * }
 *
 * SocketDgram_free(&socket);  // Safe now
 * @endcode
 *
 * ## Non-Blocking Shutdown Loop
 *
 * @code{.c}
 * SocketPoll_T poll = SocketPoll_new(1);
 * SocketPoll_add(poll, Socket_fd(socket), POLL_READ | POLL_WRITE, NULL);
 *
 * SocketDTLS_shutdown(socket);
 * int attempts = 0;
 * while (!SocketDTLS_is_shutdown(socket) && attempts++ < 10) {
 *   SocketPoll_wait(poll, NULL, 100);  // Short timeout
 *   SocketDTLS_handshake(socket);  // Drive shutdown state
 * }
 * @endcode
 *
 * @note Unlike TLS, DTLS shutdown is best-effort due to UDP lossiness.
 * No bidirectional close guarantee; peer may not receive alert.
 * After shutdown, further send/recv raise errors.
 * Metrics: Tracks shutdown events.
 *
 * @warning Abrupt @ref SocketDgram_free() without shutdown leaks state and
 * skips alert. In pools, coordinate with @ref SocketPool_drain() for graceful.
 *
 * @see SocketDTLS_is_shutdown() to check completion
 * @see SocketDTLS_handshake() to drive shutdown in non-blocking
 * @see SocketDgram_free() - follow after shutdown
 * @see @ref connection_mgmt for pool-aware shutdown
 * @see docs/SECURITY.md#graceful-shutdown for protocols.
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

/** @} */

#endif /* SOCKETDTLS_INCLUDED */
