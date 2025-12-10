/**
 * @defgroup security Security Modules
 * @brief Comprehensive security protections for network applications with
 * TLS 1.3 hardening and DDoS mitigation.
 *
 * The Security modules provide production-grade defenses against common
 * threats including man-in-the-middle attacks, SYN floods, and IP-based abuse.
 * Key focus areas: strict TLS configuration, certificate validation, adaptive
 * rate limiting, and connection filtering. Designed for seamless integration
 * with Socket core without performance penalties.
 *
 * ## Architecture Overview
 *
 * ```
 * ┌───────────────────────────────────────────────────────────┐
 * │                    Application Layer                      │
 * │  SocketPool, SocketHTTPClient, SocketHTTPServer, Custom   │
 * │  Services, etc.                                           │
 * └─────────────┬─────────────────────────────────────────────┘
 *               │ Uses / Integrates
 * ┌─────────────▼─────────────────────────────────────────────┐
 * │                 Security Layer                            │
 * │  ┌────────────┐  ┌────────────┐  ┌──────────────────┐    │
 * │  │ SocketTLS  │  │SocketSYN   │  │ SocketDTLS       │    │
 * │  │/DTLS       │◄►│Protect     │  │/IPTracker        │    │
 * │  └────────────┘  └────────────┘  └──────────────────┘    │
 * │              │         │                │                 │
 * │   TLS Crypto │  SYN    │     UDP/DTLS   │  Rate Limits    │
 * └──────────────┼─────────┼────────────────┼─────────────────┘
 *                │         │                │
 * ┌─────────────▼─────────▼────────────────▼─────────────────┐
 * │              Foundation + Core I/O Layer                  │
 * │  Arena, Except, Socket, SocketConfig, SocketUtil          │
 * └───────────────────────────────────────────────────────────┘
 * ```
 *
 * ## Module Relationships
 *
 * - **Depends on**: @ref foundation (memory, exceptions, config), @ref core_io
 * (Socket primitives)
 * - **Used by**: @ref connection_mgmt (protected pools), @ref http (secure
 * HTTP/2), @ref async_io (non-blocking TLS)
 * - **Integrates with**: @ref event_system (poll during handshake), @ref
 * utilities (timers, rate limits)
 *
 * ## Protection Mechanisms
 *
 * ### TLS/SSL Encryption
 * - TLS 1.3 exclusive: PFS, secure ciphers, anti-downgrade
 * - Client/server auth, SNI, ALPN, session resumption
 * - Non-blocking handshake + secure I/O wrappers
 *
 * ### SYN Flood & DDoS Defense
 * - Adaptive black/whitelisting with reputation scoring
 * - Sliding window rate limiting per IP
 * - Challenge-response cookies for UDP/DTLS
 *
 * ### IP & Traffic Control
 * - Per-IP connection limits and tracking
 * - Geoblocking, anomaly detection
 * - Integration with SocketPool for server protection
 *
 * ## Security Philosophy
 *
 * - **Secure by Default**: No weak configs; TLS 1.3 only, verify peers
 * - **Minimal Attack Surface**: No global state, thread-local errors
 * - **Performance Oriented**: Zero-copy where possible, async-friendly
 * - **Auditable**: Detailed logging, metrics, error categorization
 *
 * ## Configuration Best Practices
 *
 * | Aspect | Recommendation | Rationale |
 * |--------|----------------|-----------|
 * | TLS Version | TLS 1.3 only | Eliminates legacy vulns |
 * | Cipher Suites | Modern PFS | Forward secrecy |
 * | Verify Mode | TLS_VERIFY_PEER | Prevent MITM |
 * | CA Store | System + custom | Trust chain validation |
 * | Session Cache | Enabled with tickets | Performance without security loss |
 *
 * @warning Disable only for testing; production requires full verification
 * @note Requires OpenSSL/LibreSSL; enabled via -DENABLE_TLS=ON in CMake
 *
 * @see @ref foundation "Foundation Modules" for base infrastructure
 * @see @ref core_io "Core I/O Modules" for sockets secured by TLS
 * @see @ref http "HTTP Modules" for TLS-secured protocols
 * @see docs/SECURITY.md for hardening guide
 * @see docs/TLS-CONFIG.md for detailed TLS setup
 * @see docs/SYN-PROTECT.md for DDoS protection details
 * @{
 */

/**
 * @file SocketTLS.h
 * @ingroup security
 * @brief High-level TLS/SSL integration for secure Socket I/O with TLS 1.3
 * enforcement.
 *
 * This header provides the core API for enabling and managing TLS encryption
 * on TCP sockets. It abstracts OpenSSL/LibreSSL complexities, offering
 * non-blocking handshakes, secure send/recv, and post-handshake queries
 * (ciphers, cert status). Exclusively supports TLS 1.3 for maximum security:
 * PFS, secure defaults, no legacy support. Integrates seamlessly with
 * SocketPoll for event-driven applications.
 *
 * ## Core Features
 *
 * - **TLS 1.3 Exclusive**: Enforced PFS, modern ciphers (AES-GCM, ChaCha20),
 * anti-downgrade protection
 * - **Async-Friendly**: Non-blocking handshake states for poll/epoll/kqueue
 * integration
 * - **Transparent I/O**: Drop-in SocketTLS_send/recv replacing
 * Socket_send/recv post-handshake
 * - **Certificate Handling**: Automatic verification, SNI, hostname checks,
 * error details
 * - **Protocol Negotiation**: ALPN for HTTP/2, WebSocket; session resumption
 * support
 * - **Error Reporting**: Thread-local tls_error_buf + exceptions for detailed
 * diagnostics
 * - **Graceful Shutdown**: Bidirectional close_notify to prevent truncation
 * attacks
 *
 * ## Typical Workflow
 *
 * 1. Create Socket and connect/accept
 * 2. Create SocketTLSContext (client/server config)
 * 3. SocketTLS_enable(socket, ctx)
 * 4. Set hostname (client) or certs (server)
 * 5. Perform handshake (auto or manual)
 * 6. Use secure I/O
 * 7. Shutdown TLS before closing socket
 *
 * ## Client Usage Example
 *
 * @code{.c}
 * #include "socket/Socket.h"
 * #include "tls/SocketTLS.h"
 * #include "tls/SocketTLSContext.h"
 *
 * TRY {
 *     Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 *     Socket_setnonblocking(sock);
 *     Socket_connect(sock, "www.example.com", 443);
 *
 *     SocketTLSContext_T ctx = SocketTLSContext_new_client(NULL); // Secure
 * defaults SocketTLS_enable(sock, ctx); SocketTLS_set_hostname(sock,
 * "www.example.com");
 *
 *     // Non-blocking handshake in event loop
 *     TLSHandshakeState state = TLS_HANDSHAKE_NOT_STARTED;
 *     while (state != TLS_HANDSHAKE_COMPLETE && state != TLS_HANDSHAKE_ERROR)
 * { state = SocketTLS_handshake(sock); if (state == TLS_HANDSHAKE_WANT_READ ||
 * state == TLS_HANDSHAKE_WANT_WRITE) {
 *             // Add to poll, wait for events, then retry
 *             // SocketPoll_wait(poll, ...)
 *         }
 *     }
 *     REQUIRE(state == TLS_HANDSHAKE_COMPLETE);
 *
 *     // Verify cert
 *     long verify = SocketTLS_get_verify_result(sock);
 *     REQUIRE(verify == X509_V_OK);
 *
 *     // Secure I/O
 *     const char *req = "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
 *     SocketTLS_send(sock, req, strlen(req));
 *     char buf[4096];
 *     ssize_t n = SocketTLS_recv(sock, buf, sizeof(buf));
 *
 * } EXCEPT(SocketTLS_Failed) {
 *     SOCKET_LOG_ERROR_MSG("TLS failed: %s", tls_error_buf);
 *     // Cleanup
 * } FINALLY {
 *     SocketTLS_shutdown(sock);
 *     Socket_close(sock);
 *     SocketTLSContext_free(&ctx);
 * } END_TRY;
 * @endcode
 *
 * ## Server Usage Example
 *
 * @code{.c}
 * Socket_T listener = Socket_new(AF_INET, SOCK_STREAM, 0);
 * Socket_bind(listener, "0.0.0.0", 443);
 * Socket_listen(listener, SOMAXCONN);
 * Socket_setnonblocking(listener);
 *
 * SocketTLSContext_T ctx = SocketTLSContext_new_server("server.crt",
 * "server.key", NULL); SocketTLSContext_set_min_protocol(ctx, TLS1_3_VERSION);
 * SocketTLSContext_load_ca(ctx, "ca-bundle.pem"); // Optional for client auth
 *
 * SocketPoll_T poll = SocketPoll_new(1024);
 * SocketPoll_add(poll, listener, POLL_READ, listener);
 *
 * while (running) {
 *     SocketEvent_T *evs; int nfds = SocketPoll_wait(poll, &evs, 100);
 *     for (int i = 0; i < nfds; ++i) {
 *         if (evs[i].socket == listener) {
 *             Socket_T client = Socket_accept(listener);
 *             Socket_setnonblocking(client);
 *             SocketTLS_enable(client, ctx);
 *             SocketPoll_add(poll, client, POLL_READ | POLL_WRITE, client);
 *             // Handshake will occur on next events
 *         } else {
 *             // Handle events, including handshake progress
 *             if (SocketTLS_enabled(evs[i].socket)) {
 *                 TLSHandshakeState state =
 * SocketTLS_handshake(evs[i].socket);
 *                 // Update poll events based on WANT_READ/WRITE
 *             }
 *             // Process app data...
 *         }
 *     }
 * }
 * @endcode
 *
 * ## Error Handling & Best Practices
 *
 * - Always check SocketTLS_get_verify_result() after handshake; raise
 * SocketTLS_VerifyFailed if != X509_V_OK
 * - Use SocketTLS_handshake_auto() for simple cases with default timeouts
 * - For production servers: Enable session tickets/cache, set cipher
 * preferences, load system CAs
 * - Monitor SocketTLS_get_alpn_selected() to route to HTTP/2 vs 1.1 handlers
 * - Log tls_error_buf on exceptions for debugging
 * - Integrate with SocketPool for connection limiting + SYNProtect
 *
 * ## Platform & Build Requirements
 *
 * - **TLS Backend**: OpenSSL >=1.1.1 or LibreSSL >=3.0 (CMake auto-detect)
 * - **OS**: Linux, macOS, BSD, Windows (with WinTLS fallback planned)
 * - **Build**: `cmake .. -DENABLE_TLS=ON`; requires libssl-dev/libressl-dev
 * - **Headers**: #include "tls/SocketTLS.h" after "socket/Socket.h"
 * - **Conditional**: #if SOCKET_HAS_TLS guards all TLS code
 *
 * @note Thread-safe for concurrent use on different sockets; avoid sharing
 * contexts without refcounting
 * @warning Incomplete shutdown may leak session state or allow truncation;
 * always SocketTLS_shutdown()
 * @warning Non-blocking mode requires proper event loop; blocking calls may
 * deadlock
 * @complexity
 *   - Enable/Disable: O(1)
 *   - Handshake: O(1) crypto ops + network RTTs
 *   - Send/Recv: Amortized O(1) with buffering
 *
 * @see SocketTLSContext.h for advanced configuration (certs, protocols, ALPN,
 * OCSP)
 * @see SocketDTLS.h for DTLS/UDP variant with anti-DoS cookies
 * @see SocketSYNProtect.h for integrating SYN flood protection
 * @see docs/SECURITY.md#tls for TLS-specific security guidelines
 * @see docs/ERROR_HANDLING.md for exception patterns
 * @see docs/ASYNC_IO.md for poll integration details
 */

#ifndef SOCKETTLS_INCLUDED
#define SOCKETTLS_INCLUDED

#include "core/Except.h"
#include "socket/Socket.h"

#if SOCKET_HAS_TLS

/**
 * @brief Thread-local buffer for comprehensive TLS/OpenSSL error diagnostics
 * and reporting.
 * @ingroup security
 * @var tls_error_buf
 *
 * Dedicated per-thread buffer for storing formatted error strings from TLS
 * operations. Combines OpenSSL ERR codes, X509 verify results, system errno,
 * and contextual details (e.g., "SSL_connect: error:0A0C0103:SSL
 * routines::certificate verify failed; hostname mismatch"). Enables
 * consistent, detailed logging without repeated OpenSSL calls in error
 * handlers.
 *
 * Fixed-size to avoid allocations under stress:
 * SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE (256 bytes default). Automatically managed
 * by library macros; thread-safe via TLS storage.
 *
 * ## Error String Format
 *
 * Typical contents:
 * - Function name (e.g., SSL_read, X509_verify_cert)
 * - OpenSSL error code (hex) and reason string
 * - Verify errors (e.g., X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)
 * - Socket errno if applicable
 * - Custom context from macros (e.g., fd, hostname)
 *
 * ## Access Patterns
 *
 * - **Automatic**: Populated on all SocketTLS_* exceptions
 * - **Manual**: Use TLS_FORMAT_ERROR() macro for custom errors
 * - **Logging**: Safe in EXCEPT blocks or callbacks
 * - **Inspection**: Read-only during error handling; cleared post-recovery
 *
 * ## Usage in Error Handling
 *
 * @code{.c}
 * #include "tls/SocketTLS.h"
 * #include "core/Except.h"
 *
 * TRY {
 *     SocketTLSContext_T ctx = SocketTLSContext_new_client("ca.pem");
 *     SocketTLS_enable(sock, ctx);
 *     SocketTLS_handshake_auto(sock);
 * } EXCEPT(SocketTLS_VerifyFailed) {
 *     // tls_error_buf contains verify details
 *     const char *err = tls_error_buf;
 *     SOCKET_LOG_ERROR_MSG("Cert verify failed: %s", err);
 *     // Optional: Parse for specific X509 errors
 *     long vresult = SocketTLS_get_verify_result(sock);
 *     fprintf(stderr, "Verify code: %ld (%s)\n", vresult,
 * SocketTLS_get_verify_error_string(sock, buf, sizeof(buf)));
 *     // Decide: retry? blacklist peer? etc.
 * } EXCEPT(SocketTLS_HandshakeFailed) {
 *     SOCKET_LOG_ERROR_MSG("Handshake error details: %s", tls_error_buf);
 *     // Analyze for protocol/cipher issues
 * } FINALLY {
 *     // Cleanup regardless
 * } END_TRY;
 * @endcode
 *
 * ## Thread Safety & Limitations
 *
 * - **Thread-Local**: Each thread has isolated buffer; no mutex needed
 * - **Size Limit**: Truncates if > BUFSIZE; sufficient for most errors
 * - **Persistence**: Overwritten on next error in thread; copy if needed
 * - **Platform**: __thread (GCC/Clang) or __declspec(thread) (MSVC)
 *
 * @note Define SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE before including headers to
 * customize size
 * @warning Buffer not null-terminated if truncated; use snprintf-safe reads
 * @warning Avoid long-lived reads across async ops; use Socket_GetLastError()
 * for snapshots
 *
 * @complexity O(1) - direct string formatting from ERR queue
 *
 * @see Socket_GetLastError() - high-level error string (leverages this buffer)
 * @see SocketTLS_get_verify_error_string() - cert-specific details
 * @see RAISE_TLS_ERROR() / TLS_RAISE_VERIFY_ERROR() - macros populating buffer
 * @see SocketTLS-private.h - internal error macros and defines
 * @see docs/ERROR_HANDLING.md - exception patterns and logging
 * @see docs/SECURITY.md#tls-errors - TLS-specific error categorization
 */
#ifdef _WIN32
extern __declspec (thread) char tls_error_buf[];
#else
extern __thread char tls_error_buf[];
#endif

#define T SocketTLS_T
typedef struct T *T;

/* ============================================================================
 * Exception Types
 * ============================================================================
 *
 * RETRYABILITY: TLS errors are generally NOT retryable as they indicate
 * configuration issues, certificate problems, or protocol mismatches.
 */

/**
 * @brief General TLS operation failure.
 * @ingroup security
 *
 * Category: PROTOCOL
 * Retryable: NO - Usually indicates configuration or setup error.
 *
 * Used for generic TLS errors not covered by more specific exceptions like
 * handshake or verification failures.
 *
 * @see tls_error_buf for detailed OpenSSL error information.
 * @see Socket_GetLastError() for formatted error string.
 * @see SocketError_categorize_errno() for system error classification.
 */
extern const Except_T SocketTLS_Failed;

/**
 * @brief TLS handshake could not complete.
 * @ingroup security
 *
 * Category: PROTOCOL
 * Retryable: NO - Protocol/version mismatch or server rejection.
 *
 * Raised when the TLS handshake fails due to:
 * - Protocol version mismatch
 * - Cipher suite negotiation failure
 * - Server rejection of connection parameters
 *
 * @see SocketTLS_handshake(), SocketTLS_handshake_loop(),
 * SocketTLS_handshake_auto() for handshake APIs.
 * @see SocketTLS_VerifyFailed for certificate issues during handshake.
 * @see tls_error_buf for OpenSSL-specific error details.
 */
extern const Except_T SocketTLS_HandshakeFailed;

/**
 * @brief Peer certificate verification failure.
 * @ingroup security
 *
 * Category: PROTOCOL
 * Retryable: NO - Certificate validation failure persists on retry.
 *
 * Raised during handshake when peer certificate or chain fails validation:
 * - Expired or not-yet-valid certificate
 * - Invalid signature or malformed chain
 * - Hostname or SNI mismatch
 * - Unknown or untrusted CA
 * - Revocation detected (CRL/OCSP)
 *
 * @see SocketTLS_get_verify_result() for X509 verification error code.
 * @see SocketTLS_get_verify_error_string() for human-readable description.
 * @see SocketTLSContext_set_verify_mode() to configure verification policy.
 * @see SocketTLSContext_load_ca() for CA trust store management.
 */
extern const Except_T SocketTLS_VerifyFailed;

/**
 * @brief TLS protocol violation or internal state error.
 * @ingroup security
 *
 * Category: PROTOCOL
 * Retryable: NO - Indicates malformed messages or desynchronization.
 *
 * Raised for errors in TLS record layer, handshake messages, or application
 * data, such as invalid records, decryption failures, or unexpected alerts.
 *
 * @see SocketTLS_send(), SocketTLS_recv() for I/O functions that can trigger
 * this.
 * @see tls_error_buf for specific protocol alert codes and details.
 * @see SocketTLS_HandshakeFailed for handshake-specific protocol issues.
 */
extern const Except_T SocketTLS_ProtocolError;

/**
 * @brief TLS graceful shutdown failure.
 * @ingroup security
 *
 * Category: PROTOCOL
 * Retryable: NO - Shutdown alert exchange failed; connection may be
 * compromised.
 *
 * Raised when the bidirectional close_notify alert cannot be completed,
 * typically due to peer abrupt disconnect, network errors, or prior protocol
 * issues.
 *
 * @see SocketTLS_shutdown() for performing the shutdown sequence.
 * @see Socket_close() for underlying socket cleanup after shutdown attempt.
 * @see tls_error_buf for low-level error details.
 */
extern const Except_T SocketTLS_ShutdownFailed;

/**
 * @brief TLS handshake progress states for non-blocking and event-driven
 * operations.
 * @ingroup security
 *
 * Enum values indicate the current phase and required action during the TLS
 * handshake process. Used by SocketTLS_handshake() family to signal status in
 * async environments. Facilitates correct polling: WANT_READ/WRITE states
 * guide SocketPoll event masks. ERROR state triggers cleanup and exception
 * raising. COMPLETE enables secure data transfer.
 *
 * Directly corresponds to OpenSSL's internal handshake states and
 * SSL_get_error() WANT_* codes. Typical sequence: NOT_STARTED → IN_PROGRESS →
 * (WANT_* loops) → COMPLETE or ERROR.
 *
 * ## State Table
 *
 * | Value | State              | Description | Recommended Action |
 * |-------|--------------------|--------------------------------------------------|---------------------------------------------|
 * | 0     | NOT_STARTED        | No handshake initiated yet | Invoke
 * SocketTLS_handshake() first time     | | 1     | IN_PROGRESS        |
 * Handshake messages exchanging (crypto active)    | Continue calling
 * handshake in loop          | | 2     | WANT_READ          | Awaiting peer
 * data (e.g., ServerHello, certs)    | Poll for POLL_READ, then retry
 * handshake    | | 3     | WANT_WRITE         | Ready to send data (e.g.,
 * ClientHello, keys)     | Poll for POLL_WRITE, then retry handshake   | | 4
 * | COMPLETE           | Full auth + key exchange done; session secure    |
 * Transition to app I/O (send/recv TLS)       | | 5     | ERROR              |
 * Irrecoverable failure (check tls_error_buf)      | Raise exception,
 * shutdown, close socket     |
 *
 * ## Async Event Loop Example
 *
 * @code{.c}
 * #include "poll/SocketPoll.h"
 * #include "tls/SocketTLS.h"
 *
 * static void handle_handshake(Socket_T sock, SocketPoll_T poll, void
 * *userdata) { TLSHandshakeState state = SocketTLS_handshake(sock); unsigned
 * events = 0;
 *
 *     switch (state) {
 *     case TLS_HANDSHAKE_COMPLETE:
 *         // Success: enable app events
 *         SocketPoll_mod(poll, sock, POLL_READ | POLL_WRITE | POLL_ERROR |
 * POLL_HUP, app_handler); SOCKET_LOG_INFO_MSG("TLS handshake complete for
 * fd=%d", Socket_fd(sock)); break;
 *
 *     case TLS_HANDSHAKE_ERROR:
 *         // Failure: log details, cleanup
 *         SOCKET_LOG_ERROR_MSG("TLS handshake failed: %s", tls_error_buf);
 *         SocketTLS_shutdown(sock);
 *         Socket_close(sock);
 *         break;
 *
 *     case TLS_HANDSHAKE_WANT_READ:
 *         events = POLL_READ;
 *         break;
 *     case TLS_HANDSHAKE_WANT_WRITE:
 *         events = POLL_WRITE;
 *         break;
 *     default: // IN_PROGRESS or NOT_STARTED
 *         events = POLL_READ | POLL_WRITE; // Continue monitoring
 *         break;
 *     }
 *
 *     if (events) {
 *         SocketPoll_mod(poll, sock, events | POLL_ERROR | POLL_HUP,
 * handle_handshake);
 *     }
 * }
 *
 * // Usage: After SocketTLS_enable()
 * SocketPoll_add(poll, sock, POLL_READ | POLL_WRITE, handle_handshake);
 * @endcode
 *
 * @note Loop until COMPLETE or ERROR; avoid busy-waiting by polling
 * @note For blocking sockets, prefer SocketTLS_handshake_auto() wrapper
 * @warning Mismanaging WANT_* states causes hangs or infinite loops
 * @warning ERROR may leave partial keys; always shutdown + close immediately
 *
 * @complexity O(1) per invocation; full handshake involves multiple crypto ops
 * (DH/ECDH, sig verify)
 *
 * @see SocketTLS_handshake() - returns this enum per step
 * @see SocketTLS_handshake_loop() - automated loop with timeout
 * @see SocketTLS_handshake_auto() - timeout from socket config
 * @see @ref event_system "Event System" for SocketPoll and async patterns
 * @see SocketPoll_mod() - update events based on state
 * @see docs/ASYNC_IO.md#tls-handshake for advanced async TLS
 * @see SSL_get_error() / SSL_state() in OpenSSL for low-level details
 */
typedef enum
{
  TLS_HANDSHAKE_NOT_STARTED = 0, /**< Initial state: handshake not initiated */
  TLS_HANDSHAKE_IN_PROGRESS = 1, /**< Active exchange of handshake messages */
  TLS_HANDSHAKE_WANT_READ = 2,  /**< Blocked waiting for inbound TLS records */
  TLS_HANDSHAKE_WANT_WRITE = 3, /**< Blocked waiting to send TLS records */
  TLS_HANDSHAKE_COMPLETE = 4, /**< Successful completion; ready for app data */
  TLS_HANDSHAKE_ERROR = 5     /**< Fatal error; abort connection */
} TLSHandshakeState;

/**
 * @brief Peer certificate verification policies configurable for TLS contexts.
 * @ingroup security
 *
 * Specifies the level of certificate validation during TLS handshakes.
 * Controls whether to request/require peer certs, perform chain validation
 * against trusted CAs, and handle missing certs. Bit flags allow combinations
 * (e.g., PEER | FAIL_IF_NO_PEER_CERT for mTLS). Defaults to PEER mode in
 * client/server contexts for balanced security/performance. Directly maps to
 * OpenSSL SSL_VERIFY_* constants for compatibility.
 *
 * ## Mode Details & Recommendations
 *
 * | Mode                      | Value | Requires Cert? | Validates Chain? |
 * Fails No Cert? | Best For                  |
 * |---------------------------|-------|----------------|------------------|----------------|---------------------------|
 * | TLS_VERIFY_NONE           | 0x00  | No             | No               | No
 * | Testing, internal proxies | | TLS_VERIFY_PEER           | 0x01  | Yes
 * (request)  | Yes              | No (warn)      | Standard client/server    |
 * | TLS_VERIFY_FAIL_IF_NO_PEER_CERT | 0x02 | Yes (require) | Yes | Yes |
 * Mutual TLS (mTLS)         | | TLS_VERIFY_CLIENT_ONCE    | 0x04  | Yes (once)
 * | Yes (once)       | Per config     | Servers with resumption   |
 *
 * - **NONE**: Bypasses all checks; vulnerable to MITM, spoofing - avoid in
 * prod
 * - **PEER**: Requests cert, verifies if provided; allows anon for flexibility
 * - **FAIL_IF_NO_PEER_CERT**: Enforces cert provision; ideal for auth-heavy
 * apps
 * - **CLIENT_ONCE**: Server opt - reuses prior verification on session resume
 * (tickets)
 *
 * ## Server Configuration Example (mTLS)
 *
 * @code{.c}
 * SocketTLSContext_T ctx = SocketTLSContext_new_server("server.crt",
 * "server.key", NULL);
 *
 * // Require client certs with full validation
 * SocketTLSContext_set_verify_mode(ctx,
 *     TLS_VERIFY_PEER | TLS_VERIFY_FAIL_IF_NO_PEER_CERT);
 *
 * // Load trusted client CAs
 * SocketTLSContext_load_verify_locations(ctx, "client-cas.pem", NULL);
 *
 * // Optional: depth limit (e.g., 2 for short chains)
 * SocketTLSContext_set_verify_depth(ctx, 5);
 *
 * // Custom callback for revocation/pinning checks
 * SocketTLSContext_set_verify_callback(ctx, verify_peer_cert, ctx);
 *
 * // Enable client cert request
 * SocketTLSContext_set_client_ca_list(ctx, client_ca_list);
 * @endcode
 *
 * ## Client Configuration Example
 *
 * @code{.c}
 * SocketTLSContext_T ctx = SocketTLSContext_new_client(NULL); // System CAs
 * default
 *
 * // Standard server verification
 * SocketTLSContext_set_verify_mode(ctx, TLS_VERIFY_PEER);
 *
 * // Strict: fail if server provides no/ invalid cert
 * SocketTLSContext_set_verify_mode(ctx,
 *     TLS_VERIFY_PEER | TLS_VERIFY_FAIL_IF_NO_PEER_CERT);
 *
 * // Load additional CAs (e.g., enterprise)
 * SocketTLSContext_load_ca(ctx, "/etc/ssl/custom-ca.pem");
 * @endcode
 *
 * ## Advanced Considerations
 *
 * - Combine with SocketTLSContext_set_verify_depth() to limit chain length
 * - Use custom verify callback for OCSP stapling, CRL checks, cert pinning
 * - For session resumption, CLIENT_ONCE optimizes but requires secure tickets
 * - Always log verification failures via tls_error_buf and
 * SocketTLS_get_verify_result()
 *
 * @note Default: TLS_VERIFY_PEER; override explicitly for custom policies
 * @warning NONE exposes to active attacks; use TLS_VERIFY_PEER minimum in
 * production
 * @warning FAIL_IF_NO_PEER_CERT breaks compat with non-cert peers (e.g., some
 * CDNs)
 * @warning CLIENT_ONCE assumes secure resumption; vulnerable if tickets
 * compromised
 *
 * @complexity O(chain length) for validation; cached in sessions
 *
 * @see SocketTLSContext_set_verify_mode() - set on context before enabling
 * sockets
 * @see SocketTLSContext_load_ca() - populate trust store
 * @see SocketTLSContext_set_verify_callback() - hook for custom logic (e.g.,
 * hostname)
 * @see SocketTLSContext_set_verify_depth() - chain validation limits
 * @see SocketTLS_VerifyFailed - exception triggered on failures
 * @see SocketTLS_get_verify_result() - query result post-handshake
 * @see docs/SECURITY.md#cert-validation for revocation, pinning guides
 * @see X509_verify_cert() / SSL_CTX_set_verify() in OpenSSL docs
 */
typedef enum
{
  TLS_VERIFY_NONE
  = 0, /**< Disable all cert verification (INSECURE - testing only) */
  TLS_VERIFY_PEER = 1, /**< Request and validate peer cert if provided */
  TLS_VERIFY_FAIL_IF_NO_PEER_CERT
  = 2, /**< Fail handshake if no peer cert presented */
  TLS_VERIFY_CLIENT_ONCE
  = 4 /**< Servers: verify client cert once per logical session */
} TLSVerifyMode;

/**
 * @brief Opaque TLS context type for managing certificates, keys, and
 * configuration.
 * @ingroup security
 *
 * Handles OpenSSL SSL_CTX lifecycle, security policies, ALPN protocols,
 * session caching, certificate pinning, CT validation, and more.
 * Created via dedicated functions in SocketTLSContext.h and passed to
 * SocketTLS_enable() to secure sockets.
 *
 * @see SocketTLSContext.h for complete API and creation functions like
 * SocketTLSContext_new_client().
 * @see SocketTLSContext_new_server() for server contexts.
 * @see SocketTLS_enable() to apply context to a socket.
 * @see @ref security "Security Modules" for related protection features.
 */
typedef struct SocketTLSContext_T *SocketTLSContext_T;

/* TLS socket operations */
/**
 * @brief Enable TLS on a socket using the provided context
 * @ingroup security
 * @param socket The socket instance to enable TLS on
 * @param ctx The TLS context to use for this connection
 *
 * Enables TLS/SSL encryption on the specified socket. The socket must be
 * connected before calling this function. Creates an SSL object from the
 * context, associates it with the socket's file descriptor, sets client/server
 * mode, and initializes TLS buffers and state.
 *
 * @return void
 * @throws SocketTLS_Failed if TLS cannot be enabled (e.g., already enabled,
 * invalid socket, context error)
 * @threadsafe No - modifies socket state directly
 *
 * @see Socket_connect() for establishing connections before enabling TLS
 * @see Socket_accept() for accepting connections before enabling TLS
 * @see SocketTLS_handshake() for performing the TLS handshake
 * @see SocketTLSContext_new_client() for creating client contexts
 */
extern void SocketTLS_enable (Socket_T socket, SocketTLSContext_T ctx);

/**
 * @brief Disable TLS on a socket, reverting to plain TCP communication
 * @ingroup security
 * @param socket The socket instance with TLS enabled
 *
 * Performs a graceful TLS teardown without closing the underlying socket,
 * allowing continued use as a plain TCP connection. This is useful for:
 * - STARTTLS reversal (downgrade from TLS to plain)
 * - Protocol-level TLS renegotiation with mode switch
 * - Graceful cleanup before connection handoff
 *
 * The function:
 * 1. Attempts SSL_shutdown() to exchange close_notify alerts (best-effort)
 * 2. Cleans up SSL object and TLS buffers securely
 * 3. Resets socket to non-TLS mode for plain I/O
 *
 * Unlike SocketTLS_shutdown(), this function:
 * - Does NOT raise exceptions on shutdown failure (best-effort)
 * - Always leaves the socket in a usable non-TLS state
 * - Returns success/failure status for logging purposes
 *
 * @return 1 on clean TLS shutdown, 0 if shutdown was incomplete but socket
 *         is now in plain mode, -1 if TLS was not enabled
 *
 * @throws None - best-effort operation, always cleans up
 * @threadsafe No - modifies socket state directly
 *
 * ## Usage Example (STARTTLS Reversal)
 *
 * @code{.c}
 * // After TLS session, revert to plain for protocol reasons
 * int result = SocketTLS_disable(sock);
 * if (result >= 0) {
 *     // Socket is now in plain TCP mode
 *     Socket_send(sock, "PLAIN DATA", 10);
 * }
 * @endcode
 *
 * @warning After calling this, all I/O must use Socket_send/recv, not
 *          SocketTLS_send/recv
 * @warning Peer must also be expecting the TLS-to-plain transition
 * @note Sensitive TLS buffers are securely cleared before deallocation
 *
 * @see SocketTLS_enable() to re-enable TLS after disable
 * @see SocketTLS_shutdown() for strict shutdown that raises on failure
 * @see Socket_send() / Socket_recv() for plain I/O after disable
 */
extern int SocketTLS_disable (Socket_T socket);

/**
 * @brief Set SNI hostname for client TLS connections
 * @ingroup security
 * @param socket The socket instance
 * @param hostname Null-terminated hostname string for SNI and verification
 *
 * Sets the Server Name Indication (SNI) hostname for the TLS connection. This
 * is required for virtual hosting on servers and enables hostname verification
 * for clients. The hostname is validated and allocated in the socket's arena.
 * Should be called after SocketTLS_enable() but before SocketTLS_handshake().
 *
 * @return void
 * @throws SocketTLS_Failed if TLS not enabled, invalid hostname, or OpenSSL
 * @threadsafe No - modifies socket and SSL state
 */
extern void SocketTLS_set_hostname (Socket_T socket, const char *hostname);

/**
 * @brief Perform non-blocking TLS handshake
 * @ingroup security
 * @param socket The socket instance with TLS enabled
 *
 * Performs one step of the TLS handshake. For non-blocking sockets, this may
 * return WANT_READ or WANT_WRITE indicating more data or writability is
 * needed. Call repeatedly in a poll loop until TLS_HANDSHAKE_COMPLETE is
 * returned.
 *
 * @return TLSHandshakeState indicating progress (COMPLETE, WANT_READ,
 * WANT_WRITE, ERROR)
 * @throws SocketTLS_HandshakeFailed on fatal handshake errors (e.g., protocol
 * mismatch, cert verify fail)
 * @threadsafe No - modifies socket TLS state and SSL object
 *
 * @see SocketPoll_T for event-driven handshake completion
 * @see SocketTLS_handshake_loop() for timeout-based completion
 * @see SocketTLS_handshake_auto() for automatic timeout handling
 */
extern TLSHandshakeState SocketTLS_handshake (Socket_T socket);

/**
 * @brief Complete handshake with timeout (non-blocking)
 * @ingroup security
 * @param socket The socket instance with TLS enabled
 * @param timeout_ms Maximum time to wait for handshake completion (0 for
 * non-blocking)
 *
 * Convenience function to run the handshake loop until complete or timeout.
 * Uses SocketPoll internally for non-blocking operation if timeout > 0.
 * Uses the default poll interval (SOCKET_TLS_POLL_INTERVAL_MS, typically 100ms).
 *
 * @return TLSHandshakeState (COMPLETE on success, ERROR on failure/timeout)
 * @throws SocketTLS_HandshakeFailed on error or timeout (includes elapsed time
 *         in error message for diagnostics)
 * @threadsafe No
 *
 * ## Metrics Updated
 * - SOCKET_CTR_TLS_HANDSHAKES_TOTAL: Incremented on success or failure
 * - SOCKET_CTR_TLS_HANDSHAKES_FAILED: Incremented on failure/timeout
 * - SOCKET_HIST_TLS_HANDSHAKE_TIME_MS: Records handshake duration on success
 *
 * Note: This is a higher-level helper; low-level code should use
 * SocketTLS_handshake() directly.
 *
 * @see SocketTLS_handshake_loop_ex() for configurable poll interval
 */
extern TLSHandshakeState SocketTLS_handshake_loop (Socket_T socket,
                                                   int timeout_ms);

/**
 * @brief Complete handshake with timeout and configurable poll interval
 * @ingroup security
 * @param socket The socket instance with TLS enabled
 * @param timeout_ms Maximum time to wait for handshake completion (0 for
 * non-blocking)
 * @param poll_interval_ms Interval between poll attempts (defaults to
 * SOCKET_TLS_POLL_INTERVAL_MS if <= 0)
 *
 * Extended version of SocketTLS_handshake_loop() with configurable poll
 * interval. Use smaller intervals (10-50ms) for latency-sensitive applications,
 * larger intervals (200-500ms) for resource-constrained environments.
 *
 * @return TLSHandshakeState (COMPLETE on success, ERROR on failure/timeout)
 * @throws SocketTLS_HandshakeFailed on error or timeout (includes elapsed time)
 * @threadsafe No
 *
 * ## Example
 *
 * @code{.c}
 * // Low-latency handshake with 25ms polling
 * TLSHandshakeState state = SocketTLS_handshake_loop_ex(sock, 5000, 25);
 *
 * // Resource-efficient handshake with 500ms polling
 * TLSHandshakeState state = SocketTLS_handshake_loop_ex(sock, 30000, 500);
 * @endcode
 *
 * @see SocketTLS_handshake_loop() for default poll interval
 * @see SOCKET_TLS_POLL_INTERVAL_MS for the default value (100ms)
 */
extern TLSHandshakeState SocketTLS_handshake_loop_ex (Socket_T socket,
                                                      int timeout_ms,
                                                      int poll_interval_ms);

/**
 * @brief Complete handshake using socket's timeout config
 * @ingroup security
 * @param socket The socket instance with TLS enabled
 *
 * Convenience function that performs a TLS handshake using the socket's
 * configured operation_timeout_ms. If operation_timeout_ms is 0 or not set,
 * uses SOCKET_DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS (30 seconds).
 *
 * This is the recommended function for production code as it automatically
 * uses the socket's timeout configuration, ensuring consistent timeout
 * behavior across the application.
 *
 * @return TLSHandshakeState (COMPLETE on success, ERROR on failure/timeout)
 * @throws SocketTLS_HandshakeFailed on error or timeout
 * @threadsafe No
 */
extern TLSHandshakeState SocketTLS_handshake_auto (Socket_T socket);

/**
 * @brief Perform graceful TLS connection shutdown
 * @ingroup security
 * @param socket The socket instance with TLS enabled
 *
 * Initiates a bidirectional TLS shutdown by sending close_notify and waiting
 * for the peer's close_notify response. This ensures a clean termination of
 * the TLS session. Uses the socket's operation timeout or defaults to
 * SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS.
 *
 * ## Shutdown Behavior
 *
 * - **Blocking mode**: Waits up to timeout for peer's close_notify response
 * - **Non-blocking mode**: Uses internal polling to complete shutdown
 * - **Timeout**: If peer doesn't respond, sends close_notify (best effort)
 *   and raises SocketTLS_ShutdownFailed
 * - **Error handling**: Only raises exceptions on protocol errors, not on
 *   EAGAIN/EWOULDBLOCK (handled internally via polling)
 *
 * ## When to Use
 *
 * Call before Socket_close() for:
 * - Clean session termination (enables session resumption)
 * - Preventing truncation attacks (receiver knows no more data coming)
 * - Protocol compliance (TLS spec requires close_notify)
 *
 * For faster shutdown without waiting, use SocketTLS_shutdown_send().
 *
 * @return void
 * @throws SocketTLS_ShutdownFailed on protocol error or timeout
 * @threadsafe No - modifies SSL object state
 *
 * @see SocketTLS_shutdown_send() for unidirectional (half-close) shutdown
 * @see SocketTLS_disable() for best-effort shutdown without exceptions
 */
extern void SocketTLS_shutdown (Socket_T socket);

/**
 * @brief Send close_notify without waiting for peer response (half-close)
 * @ingroup security
 * @param socket The socket instance with TLS enabled
 *
 * Performs a unidirectional TLS shutdown by sending the close_notify alert
 * without waiting for the peer's response. This is faster than full shutdown
 * and suitable when:
 * - The socket will be closed immediately after
 * - You don't need session resumption
 * - Quick teardown is more important than protocol compliance
 *
 * ## Non-blocking Behavior
 *
 * For non-blocking sockets, if the close_notify cannot be sent immediately:
 * - Returns 0 with errno=EAGAIN
 * - Caller can poll for POLL_WRITE and retry, or proceed to close
 *
 * @return 1 on success (close_notify sent),
 *         0 if would block (errno=EAGAIN) - retry after polling,
 *         -1 if TLS not enabled or already shutdown
 *
 * @throws SocketTLS_ShutdownFailed on protocol error (rare)
 * @threadsafe No - modifies SSL object state
 *
 * ## Example
 *
 * @code{.c}
 * // Quick shutdown - don't wait for peer response
 * int ret = SocketTLS_shutdown_send(sock);
 * if (ret == 0 && errno == EAGAIN) {
 *     // Optional: poll and retry, or just proceed to close
 * }
 * Socket_close(sock);  // Close underlying socket
 * @endcode
 *
 * @see SocketTLS_shutdown() for full bidirectional shutdown
 */
extern int SocketTLS_shutdown_send (Socket_T socket);

/* TLS I/O operations */
/**
 * @brief Send data over TLS-encrypted connection
 * @ingroup security
 * @param[in] socket The socket instance with completed TLS handshake
 * @param[in] buf Buffer containing data to send
 * @param[in] len Number of bytes to send from buf (0 returns immediately)
 *
 * Sends data using SSL_write() with proper partial write handling when
 * SSL_MODE_ENABLE_PARTIAL_WRITE is enabled (default). For non-blocking sockets,
 * returns 0 and sets errno=EAGAIN if the operation would block.
 *
 * ## Partial Write Behavior
 *
 * With SSL_MODE_ENABLE_PARTIAL_WRITE (enabled by default), the function may
 * return a value less than `len`. The caller must loop to send remaining data:
 *
 * @code{.c}
 * size_t sent = 0;
 * while (sent < len) {
 *     ssize_t n = SocketTLS_send(sock, buf + sent, len - sent);
 *     if (n == 0) {
 *         // Would block - poll for POLL_WRITE and retry
 *         poll_for_write(sock);
 *         continue;
 *     }
 *     sent += n;
 * }
 * @endcode
 *
 * ## Zero-Length Operations
 *
 * Sending zero bytes (len=0) returns 0 immediately without invoking SSL_write.
 * This matches POSIX send() semantics.
 *
 * ## Large Buffer Handling
 *
 * Buffers larger than INT_MAX are capped to INT_MAX per call since OpenSSL
 * uses int for lengths. Caller should loop for complete transmission.
 *
 * @return Number of bytes sent (may be < len with partial writes),
 *         0 if would block (errno=EAGAIN for non-blocking sockets)
 *
 * @throws SocketTLS_Failed on TLS protocol errors or SSL_ERROR_SSL
 * @throws Socket_Closed if peer sent close_notify during send
 *
 * @threadsafe No - modifies SSL buffers and state
 *
 * @see SocketTLS_recv() for receiving data
 * @see Socket_sendall() for fully blocking send semantics
 */
extern ssize_t SocketTLS_send (Socket_T socket, const void *buf, size_t len);

/**
 * @brief Receive data from TLS-encrypted connection
 * @ingroup security
 * @param[in] socket The socket instance with completed TLS handshake
 * @param[out] buf Buffer to receive data into
 * @param[in] len Maximum number of bytes to receive (0 returns immediately)
 *
 * Receives data using SSL_read() with proper handling of all shutdown cases.
 * Distinguishes between clean peer shutdown and abrupt connection close.
 *
 * ## Shutdown Handling
 *
 * - **Clean shutdown (SSL_ERROR_ZERO_RETURN)**: Peer sent close_notify alert.
 *   Raises Socket_Closed with errno=0. This is graceful termination.
 *
 * - **Abrupt close (SSL_ERROR_SYSCALL with EOF)**: Peer closed without sending
 *   close_notify. Raises Socket_Closed with errno=ECONNRESET. This may indicate
 *   data truncation or network failure.
 *
 * Callers can distinguish these cases by checking errno after catching
 * Socket_Closed:
 *
 * @code{.c}
 * TRY {
 *     n = SocketTLS_recv(sock, buf, sizeof(buf));
 * } EXCEPT(Socket_Closed) {
 *     if (errno == 0) {
 *         // Clean shutdown - peer sent close_notify
 *     } else if (errno == ECONNRESET) {
 *         // Abrupt close - possible truncation attack
 *     }
 * } END_TRY;
 * @endcode
 *
 * ## Non-blocking Behavior
 *
 * For non-blocking sockets, returns 0 with errno=EAGAIN when the operation
 * would block. Note that WANT_WRITE can occur during renegotiation.
 *
 * ## Zero-Length Operations
 *
 * Receiving with len=0 returns 0 immediately without invoking SSL_read.
 * This matches POSIX recv() semantics.
 *
 * ## Large Buffer Handling
 *
 * Buffers larger than INT_MAX are capped to INT_MAX per call. This is typically
 * not an issue since TLS records are limited to 16KB.
 *
 * @return Number of bytes received (> 0 on success),
 *         0 if would block (errno=EAGAIN for non-blocking sockets)
 *
 * @throws Socket_Closed on clean shutdown (errno=0) or abrupt close
 * (errno=ECONNRESET)
 * @throws SocketTLS_Failed on TLS protocol errors (errno=EPROTO)
 *
 * @threadsafe No - modifies SSL buffers and state
 *
 * @see SocketTLS_send() for sending data
 * @see Socket_recvall() for fully blocking recv semantics
 */
extern ssize_t SocketTLS_recv (Socket_T socket, void *buf, size_t len);

/* TLS information */
/**
 * @brief Get negotiated cipher suite name
 * @ingroup security
 * @param socket The socket instance with completed handshake
 *
 * Returns the name of the cipher suite negotiated during handshake (e.g.,
 * "TLS_AES_256_GCM_SHA384").
 *
 * @return Const string with cipher name, or NULL if unavailable
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake state - reads immutable
 * post-handshake state
 *
 * @see SocketTLS_get_version() for protocol version.
 * @see SocketTLSContext_set_cipher_list() for configuring ciphers.
 * @see docs/SECURITY_GUIDE.md for cipher security recommendations.
 */
extern const char *SocketTLS_get_cipher (Socket_T socket);

/**
 * @brief Get negotiated TLS protocol version
 * @ingroup security
 * @param socket The socket instance with completed handshake
 *
 * Returns the TLS protocol version string (e.g., "TLSv1.3").
 *
 * @return Const string with version, or NULL if unavailable
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake state
 *
 * @see SocketTLS_get_cipher() for negotiated cipher suite.
 * @see SocketTLSContext_set_min_protocol() for minimum version.
 * @see SocketTLSContext_set_max_protocol() for maximum version.
 */
extern const char *SocketTLS_get_version (Socket_T socket);

/**
 * @brief Get peer certificate verification result
 * @ingroup security
 * @param socket The socket instance with completed handshake
 *
 * Returns OpenSSL's X509 verify result code. 0 (X509_V_OK) indicates
 * successful verification. Non-zero codes detail failures (e.g., untrusted
 * CA).
 *
 * @return long verify result code (X509_V_OK = 0 on success)
 * @throws None (caller checks and may raise SocketTLS_VerifyFailed)
 * @threadsafe Yes - reads immutable post-handshake state (read-only
 * post-handshake)
 *
 * @see SocketTLS_VerifyFailed exception for handling verification failures.
 * @see SocketTLS_get_verify_error_string() for detailed error description.
 * @see SocketTLSContext_set_verify_mode() to configure verification policy.
 * @see X509_verify_cert_error_string() for OpenSSL error code meanings.
 *
 * Requires: tls_enabled and tls_handshake_done
 */
extern long SocketTLS_get_verify_result (Socket_T socket);

/**
 * @brief Get detailed verification error string
 * @ingroup security
 * @param socket TLS socket
 * @param buf Output buffer for error description
 * @param size Buffer size (including null terminator)
 *
 * Provides human-readable string for the last verification error (from
 * CRL/OCSP/custom verify). Uses X509_verify_cert_error_string or OpenSSL ERR
 * queue.
 *
 * @return buf if error found, NULL if no error or invalid args
 * @throws None
 * @threadsafe No (ERR queue shared)
 *
 * @see SocketTLS_get_verify_result() for the numeric error code.
 * @see SocketTLS_VerifyFailed for when verification fails.
 * @see ERR_get_error() for accessing OpenSSL error queue directly.
 *
 * Requires: tls_handshake_done
 */
extern const char *SocketTLS_get_verify_error_string (Socket_T socket,
                                                      char *buf, size_t size);

/**
 * @brief Check if TLS session was resumed
 * @ingroup security
 * @param socket The socket instance with completed handshake
 *
 * After a successful handshake, determines if the connection used session
 * resumption (abbreviated handshake) or a full handshake.
 *
 * ## TLS 1.3 Session Resumption
 *
 * In TLS 1.3, session resumption uses Pre-Shared Keys (PSK):
 * - Returns 1 if a valid session was restored and server accepted it
 * - Resumed sessions provide the same security as full handshakes
 * - 0-RTT early data (if enabled) is a separate feature
 *
 * ## When to Call
 *
 * Call after handshake completion to verify resumption success:
 * @code{.c}
 * SocketTLS_session_restore(sock, session_data, len);
 * SocketTLS_handshake_auto(sock);
 *
 * if (SocketTLS_is_session_reused(sock) == 1) {
 *     printf("Fast resumed connection!\n");
 * } else {
 *     printf("Full handshake (save new session for next time)\n");
 *     SocketTLS_session_save(sock, new_session, &new_len);
 * }
 * @endcode
 *
 * @return 1 if session was reused (abbreviated handshake),
 *         0 if full handshake was performed,
 *         -1 if TLS not enabled or handshake not complete
 *
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake state
 *
 * @see SocketTLS_session_save() to export session for future use
 * @see SocketTLS_session_restore() to restore session before handshake
 * @see SocketTLSContext_enable_session_cache() for server-side caching
 * @see SocketTLSContext_enable_session_tickets() for ticket-based resumption
 */
extern int SocketTLS_is_session_reused (Socket_T socket);

/**
 * @brief Get the negotiated ALPN protocol
 * @ingroup security
 * @param socket Socket instance with completed handshake
 *
 * Returns the ALPN protocol that was negotiated during the TLS handshake.
 * This is useful for determining which application protocol to use (e.g.,
 * "h2", "http/1.1").
 *
 * @return Negotiated protocol string, or NULL if none negotiated or
 * unavailable
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake state - reads immutable
 * post-handshake state
 *
 * @see SocketTLSContext_set_alpn_protos() for advertising supported protocols.
 * @see SocketTLSContext_set_alpn_callback() for custom protocol selection.
 * @see @ref http for examples like "h2" (HTTP/2) and "http/1.1".
 */
extern const char *SocketTLS_get_alpn_selected (Socket_T socket);

/* ============================================================================
 * TLS Session Management
 * ============================================================================
 */

/**
 * @brief Export TLS session for later resumption
 * @ingroup security
 * @param[in] socket Socket with completed TLS handshake
 * @param[out] buffer Buffer to store serialized session (NULL to query size)
 * @param[in,out] len On input: buffer size; On output: actual/required size
 *
 * Exports the current TLS session data in DER format suitable for persistent
 * storage or transfer. The session can later be restored with
 * SocketTLS_session_restore() for abbreviated handshakes.
 *
 * ## TLS 1.3 Session Handling
 *
 * TLS 1.3 delivers sessions asynchronously via NewSessionTicket messages
 * AFTER handshake completion. Important considerations:
 *
 * - **Timing**: For TLS 1.3, calling immediately after handshake may return -1.
 *   Session tickets are typically sent shortly after handshake completes.
 *   Perform some I/O or wait briefly before saving.
 *
 * - **Multiple tickets**: Servers may send multiple tickets. Only the most
 *   recent is captured.
 *
 * - **Lifetime**: TLS 1.3 sessions have server-enforced expiration. This
 *   function checks validity before export.
 *
 * ## Buffer Sizing
 *
 * To determine required buffer size:
 * @code{.c}
 * size_t required_len = 0;
 * SocketTLS_session_save(sock, NULL, &required_len);
 * // Now required_len contains the needed buffer size
 * @endcode
 *
 * @return 1 on success (session saved),
 *         0 if buffer too small or querying size (len updated),
 *         -1 on error (no session, expired, TLS not enabled, handshake
 * incomplete)
 *
 * @throws None
 * @threadsafe No - must synchronize access to same socket
 *
 * ## Example
 *
 * @code{.c}
 * // Perform some I/O first to receive TLS 1.3 session tickets
 * SocketTLS_recv(sock, buf, sizeof(buf));
 *
 * // Query required size
 * size_t len = 0;
 * SocketTLS_session_save(sock, NULL, &len);
 *
 * // Allocate and save
 * unsigned char *session_data = malloc(len);
 * if (SocketTLS_session_save(sock, session_data, &len) == 1) {
 *     write_session_cache(host, session_data, len);
 * }
 * free(session_data);
 * @endcode
 *
 * @note Session data is sensitive - store encrypted at rest
 * @note Session validity depends on server policy (typically 24h-7d)
 * @warning For TLS 1.3, wait for I/O activity before saving to ensure ticket
 * receipt
 *
 * @see SocketTLS_session_restore() to import saved session
 * @see SocketTLS_is_session_reused() to verify resumption worked
 * @see SocketTLSContext_enable_session_cache() for server-side caching
 */
extern int SocketTLS_session_save (Socket_T socket, unsigned char *buffer,
                                   size_t *len);

/**
 * @brief Import previously saved TLS session for resumption
 * @ingroup security
 * @param[in] socket Socket with TLS enabled but BEFORE handshake
 * @param[in] buffer Buffer containing serialized session
 * @param[in] len Length of session data
 *
 * Restores a previously exported TLS session to enable session resumption.
 * When the handshake is performed, OpenSSL will attempt to resume the session.
 *
 * ## Critical Timing Requirement
 *
 * This function MUST be called in this order:
 * 1. SocketTLS_enable(sock, ctx)
 * 2. SocketTLS_set_hostname(sock, hostname) // if needed
 * 3. **SocketTLS_session_restore(sock, data, len)** ← HERE
 * 4. SocketTLS_handshake*()
 *
 * Calling after handshake has no effect and returns -1.
 *
 * ## Graceful Failure Handling
 *
 * Session restoration fails gracefully in these cases:
 * - Session data is corrupted or invalid (returns 0)
 * - Session has expired (returns 0)
 * - Server no longer accepts the session (handshake proceeds normally)
 *
 * In all cases, the handshake falls back to full negotiation automatically.
 * Use SocketTLS_is_session_reused() after handshake to verify success.
 *
 * @return 1 on success (session set for resumption attempt),
 *         0 on invalid/expired session data (full handshake will occur),
 *         -1 on error (TLS not enabled, handshake already done)
 *
 * @throws None
 * @threadsafe No - must synchronize access to same socket
 *
 * ## Example
 *
 * @code{.c}
 * // Restore session for faster reconnect
 * SocketTLS_enable(sock, ctx);
 * SocketTLS_set_hostname(sock, "example.com");
 *
 * size_t len;
 * unsigned char *session_data = read_session_cache("example.com", &len);
 * if (session_data) {
 *     int ret = SocketTLS_session_restore(sock, session_data, len);
 *     free(session_data);
 *     if (ret == 0) {
 *         // Session expired/invalid - will do full handshake
 *     }
 * }
 *
 * SocketTLS_handshake_auto(sock);
 * if (SocketTLS_is_session_reused(sock)) {
 *     printf("Session resumed!\n");
 * } else {
 *     printf("Full handshake performed\n");
 * }
 * @endcode
 *
 * @note Session may be rejected by server even if restore succeeds
 * @note Only valid for same server the session was created with
 *
 * @see SocketTLS_session_save() to export session
 * @see SocketTLS_is_session_reused() to verify resumption
 */
extern int SocketTLS_session_restore (Socket_T socket,
                                      const unsigned char *buffer, size_t len);

/* ============================================================================
 * TLS Renegotiation Control
 * ============================================================================
 */

/**
 * @brief Check for and process pending renegotiation
 * @ingroup security
 * @param socket TLS socket
 *
 * Checks if the peer has requested a renegotiation and handles it if
 * renegotiation is allowed. TLS 1.3 does not support renegotiation.
 *
 * @return 1 if renegotiation was processed, 0 if none pending,
 *         -1 if renegotiation rejected/disabled
 *
 * @throws SocketTLS_ProtocolError if renegotiation fails
 * @threadsafe No - modifies SSL state
 *
 * @note TLS 1.3 uses key update instead of renegotiation
 * @note Renegotiation can be a DoS vector - consider disabling
 *
 * @see SocketTLS_disable_renegotiation() to prevent renegotiation
 */
extern int SocketTLS_check_renegotiation (Socket_T socket);

/**
 * @brief Disable TLS renegotiation on socket
 * @ingroup security
 * @param socket TLS socket
 *
 * Prevents the peer from initiating renegotiation. Renegotiation can be
 * exploited for DoS attacks (CPU exhaustion) and has had security
 * vulnerabilities (CVE-2009-3555).
 *
 * @return 0 on success, -1 on error (TLS not enabled)
 *
 * @throws None
 * @threadsafe No - modifies SSL configuration
 *
 * ## Security Note
 *
 * Client-initiated renegotiation is a known attack vector:
 * - CVE-2009-3555: Renegotiation injection attack
 * - CPU exhaustion by forcing repeated handshakes
 *
 * TLS 1.3 removed renegotiation entirely. For TLS 1.2 and earlier,
 * disabling renegotiation is recommended unless specifically needed.
 *
 * @code{.c}
 * SocketTLS_enable(sock, ctx);
 * SocketTLS_disable_renegotiation(sock);  // Prevent DoS
 * SocketTLS_handshake_auto(sock);
 * @endcode
 *
 * @see SocketTLS_check_renegotiation() for processing requests
 */
extern int SocketTLS_disable_renegotiation (Socket_T socket);

/* ============================================================================
 * TLS Certificate Information
 * ============================================================================
 */

/**
 * @brief Peer certificate information structure
 * @ingroup security
 */
typedef struct SocketTLS_CertInfo
{
  char subject[256];   /**< Certificate subject (CN, O, etc) */
  char issuer[256];    /**< Issuer DN string */
  time_t not_before;   /**< Certificate validity start (UTC) */
  time_t not_after;    /**< Certificate validity end (UTC) */
  int version;         /**< X.509 version (typically 3) */
  char serial[64];     /**< Serial number (hex string) */
  char fingerprint[65]; /**< SHA256 fingerprint (hex string) */
} SocketTLS_CertInfo;

/**
 * @brief Get peer certificate details
 * @ingroup security
 * @param[in] socket Socket with completed TLS handshake
 * @param[out] info Certificate information structure
 *
 * Extracts detailed information from the peer's certificate including
 * subject, issuer, validity period, and fingerprint.
 *
 * @return 1 on success, 0 if no peer certificate, -1 on error
 *
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake data
 *
 * ## Example
 *
 * @code{.c}
 * SocketTLS_CertInfo info;
 * if (SocketTLS_get_peer_cert_info(sock, &info) == 1) {
 *     printf("Subject: %s\n", info.subject);
 *     printf("Issuer: %s\n", info.issuer);
 *     printf("Expires: %s", ctime(&info.not_after));
 *     printf("Fingerprint: %s\n", info.fingerprint);
 * }
 * @endcode
 *
 * @see SocketTLS_get_cert_expiry() for just expiration time
 * @see SocketTLS_get_cert_subject() for just subject
 */
extern int SocketTLS_get_peer_cert_info (Socket_T socket,
                                         SocketTLS_CertInfo *info);

/**
 * @brief Get peer certificate expiration time
 * @ingroup security
 * @param socket Socket with completed TLS handshake
 *
 * Returns the expiration timestamp of the peer's certificate.
 *
 * @return Expiration time (time_t), or (time_t)-1 on error/no cert
 *
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake data
 *
 * ## Example
 *
 * @code{.c}
 * time_t expiry = SocketTLS_get_cert_expiry(sock);
 * if (expiry != (time_t)-1) {
 *     time_t now = time(NULL);
 *     int days_left = (expiry - now) / 86400;
 *     if (days_left < 30) {
 *         printf("Warning: Certificate expires in %d days\n", days_left);
 *     }
 * }
 * @endcode
 *
 * @see SocketTLS_get_peer_cert_info() for full certificate details
 */
extern time_t SocketTLS_get_cert_expiry (Socket_T socket);

/**
 * @brief Get peer certificate subject string
 * @ingroup security
 * @param[in] socket Socket with completed TLS handshake
 * @param[out] buf Buffer for subject string
 * @param[in] len Buffer size
 *
 * Retrieves the subject distinguished name (DN) of the peer's certificate
 * in OpenSSL one-line format (e.g., "CN=example.com,O=Example Inc,C=US").
 *
 * @return Length written on success (excluding NUL), 0 if no cert,
 *         -1 on error
 *
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake data
 *
 * ## Example
 *
 * @code{.c}
 * char subject[256];
 * if (SocketTLS_get_cert_subject(sock, subject, sizeof(subject)) > 0) {
 *     printf("Connected to: %s\n", subject);
 * }
 * @endcode
 *
 * @see SocketTLS_get_peer_cert_info() for full certificate details
 */
extern int SocketTLS_get_cert_subject (Socket_T socket, char *buf, size_t len);

/* ============================================================================
 * OCSP Status (Client-side)
 * ============================================================================
 */

/**
 * @brief Get OCSP stapling status from server response
 * @ingroup security
 * @param socket Socket with completed TLS handshake
 *
 * Retrieves the status from the OCSP response stapled by the server.
 * This is a client-side function to verify server certificate revocation
 * status without making a separate OCSP request.
 *
 * @return OCSP status:
 *         - 1: Certificate is good (OCSP_CERTSTATUS_GOOD)
 *         - 0: Certificate is revoked (OCSP_CERTSTATUS_REVOKED)
 *         - -1: No OCSP response or unknown status
 *         - -2: OCSP response verification failed
 *
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake data
 *
 * ## Example
 *
 * @code{.c}
 * // After handshake, verify OCSP status
 * int ocsp_status = SocketTLS_get_ocsp_response_status(sock);
 * switch (ocsp_status) {
 *     case 1:
 *         printf("Certificate verified via OCSP\n");
 *         break;
 *     case 0:
 *         printf("Certificate REVOKED!\n");
 *         Socket_free(&sock);
 *         return;
 *     case -1:
 *         printf("No OCSP response (server doesn't support stapling)\n");
 *         break;
 *     case -2:
 *         printf("OCSP response verification failed\n");
 *         break;
 * }
 * @endcode
 *
 * @note Requires server to have OCSP stapling enabled
 *
 * @see SocketTLSContext_enable_ocsp_stapling() for server-side setup
 * @see SocketTLS_get_ocsp_status() for simpler boolean check
 */
extern int SocketTLS_get_ocsp_response_status (Socket_T socket);

#undef T

/** @} */ /* end of security group */

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLS_INCLUDED */
