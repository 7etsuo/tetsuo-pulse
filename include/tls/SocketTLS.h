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

#include <openssl/x509.h> /* For X509, X509_NAME, etc. */
#include <time.h>         /* For time_t */

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

/**
 * @brief Get the number of renegotiations processed on this socket
 * @ingroup security
 * @param socket TLS socket
 *
 * Returns the count of TLS renegotiations that have been successfully
 * processed on this socket. Useful for monitoring and detecting potential
 * DoS attempts via excessive renegotiation.
 *
 * @return Number of renegotiations (>= 0), or -1 if TLS not enabled
 *
 * @throws None
 * @threadsafe Yes - reads simple counter
 *
 * ## DoS Protection
 *
 * The socket library limits renegotiations to SOCKET_TLS_MAX_RENEGOTIATIONS
 * (default 3) per connection. Once exceeded, further renegotiation requests
 * are rejected. Monitor this counter to detect potential attacks:
 *
 * @code{.c}
 * int reneg_count = SocketTLS_get_renegotiation_count(sock);
 * if (reneg_count >= 2) {
 *     SOCKET_LOG_WARN_MSG("Excessive renegotiations from peer");
 * }
 * @endcode
 *
 * @note TLS 1.3 always returns 0 (renegotiation not supported)
 *
 * @see SocketTLS_check_renegotiation() for processing requests
 * @see SocketTLS_disable_renegotiation() to block renegotiation
 */
extern int SocketTLS_get_renegotiation_count (Socket_T socket);

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
 * If the buffer is too small, the string is truncated but always
 * null-terminated. Check the return value against len-1 to detect truncation.
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
 * int written = SocketTLS_get_cert_subject(sock, subject, sizeof(subject));
 * if (written > 0) {
 *     printf("Connected to: %s\n", subject);
 *     if ((size_t)written >= sizeof(subject) - 1) {
 *         printf("Warning: subject was truncated\n");
 *     }
 * }
 * @endcode
 *
 * @see SocketTLS_get_peer_cert_info() for full certificate details
 */
extern int SocketTLS_get_cert_subject (Socket_T socket, char *buf, size_t len);

/**
 * @brief Get the full peer certificate chain
 * @ingroup security
 * @param[in] socket Socket with completed TLS handshake
 * @param[out] chain_out Pointer to receive array of X509 certificate pointers
 * @param[out] chain_len Pointer to receive number of certificates in chain
 *
 * Retrieves the complete certificate chain presented by the peer during
 * the TLS handshake. This includes intermediate certificates but may or may
 * not include the peer's end-entity certificate depending on client/server
 * role (OpenSSL behavior).
 *
 * The returned array is allocated from the socket's arena and is valid
 * until the socket is freed. Individual X509 pointers reference OpenSSL's
 * internal certificates and must NOT be freed by the caller.
 *
 * @return 1 on success (chain returned),
 *         0 if no chain available,
 *         -1 on error (TLS not enabled, allocation failure)
 *
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake data
 *
 * ## Example
 *
 * @code{.c}
 * X509 **chain;
 * int chain_len;
 * if (SocketTLS_get_peer_cert_chain(sock, &chain, &chain_len) == 1) {
 *     printf("Certificate chain has %d certificates\n", chain_len);
 *     for (int i = 0; i < chain_len; i++) {
 *         char subject[256];
 *         X509_NAME_oneline(X509_get_subject_name(chain[i]),
 *                           subject, sizeof(subject));
 *         printf("  [%d] %s\n", i, subject);
 *     }
 * }
 * // Note: Do NOT free chain or individual certs - managed by socket/OpenSSL
 * @endcode
 *
 * @note For clients, OpenSSL's SSL_get_peer_cert_chain() includes the peer
 *       certificate. For servers, it does NOT include the peer certificate.
 * @warning Do not free the returned certificates or array
 *
 * @see SocketTLS_get_peer_cert_info() for peer certificate details
 * @see SocketTLS_get_cert_subject() for peer subject string
 */
extern int SocketTLS_get_peer_cert_chain (Socket_T socket, X509 ***chain_out,
                                          int *chain_len);

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
 * This function performs full OCSP response validation:
 * 1. Parses the stapled OCSP response
 * 2. Verifies the OCSP response signature against the issuer certificate
 * 3. Checks response freshness (thisUpdate/nextUpdate fields)
 * 4. Returns the certificate status
 *
 * @return OCSP status:
 *         - 1: Certificate is good (OCSP_CERTSTATUS_GOOD)
 *         - 0: Certificate is revoked (OCSP_CERTSTATUS_REVOKED)
 *         - -1: No OCSP response, unknown status, or stale response
 *         - -2: OCSP response verification failed (invalid signature, etc.)
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
 * @note Response freshness is validated with SOCKET_TLS_OCSP_MAX_AGE_SECONDS
 *       tolerance (default 300 seconds)
 *
 * @see SocketTLS_get_ocsp_next_update() for checking when response expires
 * @see SocketTLSContext_enable_ocsp_stapling() for server-side setup
 */
extern int SocketTLS_get_ocsp_response_status (Socket_T socket);

/**
 * @brief Get the nextUpdate time from the OCSP response
 * @ingroup security
 * @param[in] socket Socket with completed TLS handshake
 * @param[out] next_update Pointer to receive the nextUpdate time
 *
 * Retrieves the nextUpdate timestamp from the stapled OCSP response.
 * This indicates when the OCSP responder recommends fetching a fresh
 * response. Useful for caching and planning certificate status refreshes.
 *
 * @return 1 on success (next_update set),
 *         -1 if no OCSP response, no nextUpdate field, or error
 *
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake data
 *
 * ## Example
 *
 * @code{.c}
 * time_t next_update;
 * if (SocketTLS_get_ocsp_next_update(sock, &next_update) == 1) {
 *     time_t now = time(NULL);
 *     int seconds_until = (int)difftime(next_update, now);
 *     if (seconds_until < 3600) {
 *         printf("OCSP response expires soon (%d seconds)\n", seconds_until);
 *     }
 * }
 * @endcode
 *
 * @note The nextUpdate field is optional in OCSP responses
 *
 * @see SocketTLS_get_ocsp_response_status() for certificate revocation check
 */
extern int SocketTLS_get_ocsp_next_update (Socket_T socket, time_t *next_update);

/* ============================================================================
 * Kernel TLS (kTLS) Offload Support
 * ============================================================================
 *
 * kTLS offloads TLS record encryption/decryption to the Linux kernel,
 * reducing context switches and improving performance for high-throughput
 * applications. When kTLS is active, SSL_write/SSL_read continue to work
 * normally - OpenSSL handles the kernel offload internally through its
 * BIO layer.
 *
 * ## Kernel Requirements
 *
 * | Feature | Minimum Kernel | Notes |
 * |---------|----------------|-------|
 * | TLS_TX (transmit offload) | Linux 4.13+ | send() uses kernel crypto |
 * | TLS_RX (receive offload) | Linux 4.17+ | recv() uses kernel crypto |
 * | ChaCha20-Poly1305 | Linux 5.11+ | In addition to AES-GCM |
 * | CONFIG_TLS | Required | Kernel TLS module |
 *
 * ## OpenSSL Requirements
 *
 * - OpenSSL 3.0+ compiled with `enable-ktls` option
 * - Check with: `openssl version -a | grep KTLS`
 * - At runtime: `#ifndef OPENSSL_NO_KTLS`
 *
 * ## Supported Cipher Suites
 *
 * | Cipher | kTLS Support | Notes |
 * |--------|--------------|-------|
 * | TLS_AES_128_GCM_SHA256 | Yes | Most widely supported |
 * | TLS_AES_256_GCM_SHA384 | Yes | Highest security |
 * | TLS_CHACHA20_POLY1305_SHA256 | Linux 5.11+ | ARM-friendly |
 *
 * ## Performance Characteristics
 *
 * - **Reduced syscalls**: Single syscall vs user/kernel copies per record
 * - **Zero-copy sendfile**: SSL_sendfile() for file transfers when TX active
 * - **CPU savings**: 10-30% reduction in TLS overhead on supported hardware
 * - **Best for**: High-throughput bulk transfers (file serving, streaming)
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Check system support first
 * if (SocketTLS_ktls_available()) {
 *     printf("kTLS is available on this system\n");
 * }
 *
 * // Enable kTLS before handshake
 * Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 * Socket_connect(sock, "example.com", 443);
 *
 * SocketTLSContext_T ctx = SocketTLSContext_new_client(NULL);
 * SocketTLS_enable(sock, ctx);
 * SocketTLS_enable_ktls(sock);  // Request kTLS offload
 * SocketTLS_set_hostname(sock, "example.com");
 *
 * // Handshake - kTLS activated automatically if possible
 * SocketTLS_handshake_auto(sock);
 *
 * // Check what was activated
 * if (SocketTLS_is_ktls_tx_active(sock)) {
 *     printf("TX offload active - using kernel encryption\n");
 * }
 * if (SocketTLS_is_ktls_rx_active(sock)) {
 *     printf("RX offload active - using kernel decryption\n");
 * }
 *
 * // I/O works normally - OpenSSL uses kernel internally
 * SocketTLS_send(sock, data, len);
 * SocketTLS_recv(sock, buf, sizeof(buf));
 *
 * // Zero-copy file transfer when TX offload active
 * if (SocketTLS_is_ktls_tx_active(sock)) {
 *     SocketTLS_sendfile(sock, file_fd, 0, file_size);
 * }
 * @endcode
 *
 * @note kTLS is opportunistic - falls back to userspace if unavailable
 * @warning kTLS does not support TLS renegotiation (TLS 1.2 only)
 * @warning kTLS may not work with all OpenSSL features (e.g., custom BIOs)
 */

/**
 * @brief Check if kTLS support is available on this system
 * @ingroup security
 *
 * Performs compile-time and runtime checks to determine if kTLS can
 * potentially be used. Checks include:
 * - OpenSSL compiled with kTLS support (not OPENSSL_NO_KTLS)
 * - Linux kernel with TLS module available
 * - Socket can be configured for TLS ULP
 *
 * This is a quick check that doesn't require an active TLS connection.
 * Even if this returns 1, actual kTLS activation depends on the
 * negotiated cipher suite and socket configuration.
 *
 * @return 1 if kTLS is potentially available,
 *         0 if kTLS is definitely not available
 *
 * @throws None
 * @threadsafe Yes - pure function with no side effects
 *
 * ## Example
 *
 * @code{.c}
 * if (SocketTLS_ktls_available()) {
 *     printf("kTLS available - enabling for new connections\n");
 *     config.use_ktls = 1;
 * } else {
 *     printf("kTLS not available - using userspace TLS\n");
 * }
 * @endcode
 *
 * @see SocketTLS_enable_ktls() to request kTLS for a socket
 * @see SocketTLS_is_ktls_tx_active() to check actual activation
 */
extern int SocketTLS_ktls_available (void);

/**
 * @brief Enable kTLS offload for a TLS-enabled socket
 * @ingroup security
 * @param[in] socket Socket with TLS enabled but before handshake
 *
 * Requests kernel TLS offload for this socket. The actual offload
 * activation occurs during the TLS handshake if all conditions are met:
 * - OpenSSL 3.0+ with kTLS support
 * - Compatible Linux kernel (4.13+ for TX, 4.17+ for RX)
 * - Supported cipher suite negotiated (AES-GCM or ChaCha20-Poly1305)
 *
 * This function sets SSL_OP_ENABLE_KTLS on the SSL object. OpenSSL
 * then handles all kernel interaction automatically during handshake.
 *
 * ## Call Timing
 *
 * MUST be called in this order:
 * 1. SocketTLS_enable(sock, ctx)
 * 2. **SocketTLS_enable_ktls(sock)** <- HERE
 * 3. SocketTLS_set_hostname(sock, hostname)  // if client
 * 4. SocketTLS_handshake*()
 *
 * Calling after handshake has no effect.
 *
 * ## Graceful Fallback
 *
 * If kTLS cannot be activated (unsupported kernel, cipher, etc.),
 * the handshake proceeds normally with userspace TLS. No exception
 * is raised. Use SocketTLS_is_ktls_tx_active() after handshake to
 * verify activation.
 *
 * @return void
 *
 * @throws SocketTLS_Failed if TLS not enabled on socket
 * @threadsafe No - modifies SSL object state
 *
 * ## Example
 *
 * @code{.c}
 * SocketTLS_enable(sock, ctx);
 * SocketTLS_enable_ktls(sock);  // Request kTLS
 * SocketTLS_handshake_auto(sock);
 *
 * // Check activation after handshake
 * if (SocketTLS_is_ktls_tx_active(sock)) {
 *     printf("Using kernel TLS for encryption\n");
 * }
 * @endcode
 *
 * @see SocketTLS_ktls_available() to check system support first
 * @see SocketTLS_is_ktls_tx_active() / SocketTLS_is_ktls_rx_active()
 */
extern void SocketTLS_enable_ktls (Socket_T socket);

/**
 * @brief Check if kTLS TX (transmit) offload is active
 * @ingroup security
 * @param[in] socket Socket with completed TLS handshake
 *
 * After a successful TLS handshake with kTLS enabled, checks if the
 * kernel is handling encryption for outbound data. When TX offload
 * is active:
 * - SSL_write() internally uses kernel crypto
 * - SSL_sendfile() is available for zero-copy file transfer
 * - Performance is improved for bulk data transmission
 *
 * @return 1 if TX offload is active,
 *         0 if using userspace TLS or kTLS not enabled,
 *         -1 if TLS not enabled or handshake not complete
 *
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake state
 *
 * ## Example
 *
 * @code{.c}
 * if (SocketTLS_is_ktls_tx_active(sock)) {
 *     // Use zero-copy sendfile for large file transfers
 *     SocketTLS_sendfile(sock, file_fd, offset, size);
 * } else {
 *     // Fall back to regular send
 *     SocketTLS_send(sock, buffer, size);
 * }
 * @endcode
 *
 * @see SocketTLS_enable_ktls() to enable kTLS before handshake
 * @see SocketTLS_is_ktls_rx_active() for receive offload status
 * @see SocketTLS_sendfile() for zero-copy file transfer
 */
extern int SocketTLS_is_ktls_tx_active (Socket_T socket);

/**
 * @brief Check if kTLS RX (receive) offload is active
 * @ingroup security
 * @param[in] socket Socket with completed TLS handshake
 *
 * After a successful TLS handshake with kTLS enabled, checks if the
 * kernel is handling decryption for inbound data. When RX offload
 * is active:
 * - SSL_read() internally uses kernel crypto
 * - Performance is improved for bulk data reception
 *
 * Note: RX offload requires Linux 4.17+ while TX requires only 4.13+.
 * It's possible for TX to be active but RX not on older kernels.
 *
 * @return 1 if RX offload is active,
 *         0 if using userspace TLS or kTLS not enabled,
 *         -1 if TLS not enabled or handshake not complete
 *
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake state
 *
 * @see SocketTLS_enable_ktls() to enable kTLS before handshake
 * @see SocketTLS_is_ktls_tx_active() for transmit offload status
 */
extern int SocketTLS_is_ktls_rx_active (Socket_T socket);

/**
 * @brief Send file data over TLS using zero-copy when kTLS TX is active
 * @ingroup security
 * @param[in] socket Socket with completed TLS handshake
 * @param[in] file_fd File descriptor to read from
 * @param[in] offset Starting offset in file (0 for beginning)
 * @param[in] size Number of bytes to send
 *
 * Efficiently sends file data over a TLS connection. When kTLS TX offload
 * is active, this uses SSL_sendfile() for true zero-copy transmission -
 * data goes directly from page cache to network without user/kernel copies.
 *
 * When kTLS is not active, falls back to regular read+send operations.
 *
 * ## Zero-Copy Behavior (kTLS Active)
 *
 * - Data transferred directly from kernel page cache to network
 * - No user-space buffering or memory copies
 * - Optimal for serving static files (web servers, file transfer)
 * - File should not be modified during transmission
 *
 * ## Fallback Behavior (kTLS Not Active)
 *
 * - Uses internal buffer to read from file and send via SSL_write
 * - Still works correctly, just without zero-copy optimization
 *
 * @return Number of bytes sent on success (may be < size for partial),
 *         0 if would block (non-blocking socket),
 *         -1 on error
 *
 * @throws SocketTLS_Failed on TLS protocol errors
 * @throws Socket_Closed if connection closed during transfer
 * @threadsafe No - modifies SSL state
 *
 * ## Example
 *
 * @code{.c}
 * int fd = open("large_file.bin", O_RDONLY);
 * struct stat st;
 * fstat(fd, &st);
 *
 * // Send entire file
 * off_t offset = 0;
 * size_t remaining = st.st_size;
 * while (remaining > 0) {
 *     ssize_t sent = SocketTLS_sendfile(sock, fd, offset, remaining);
 *     if (sent > 0) {
 *         offset += sent;
 *         remaining -= sent;
 *     } else if (sent == 0) {
 *         // Would block - poll and retry
 *         poll_for_write(sock);
 *     }
 * }
 * close(fd);
 * @endcode
 *
 * @warning Do not modify the file during transmission (undefined behavior)
 * @note Returns partial count if file read/send is interrupted
 *
 * @see SocketTLS_is_ktls_tx_active() to check if zero-copy is available
 * @see SocketTLS_send() for sending buffer data
 */
extern ssize_t SocketTLS_sendfile (Socket_T socket, int file_fd, off_t offset,
                                   size_t size);

/* ============================================================================
 * TLS Performance Optimizations
 * ============================================================================
 *
 * These functions provide performance optimizations for TLS connections:
 * - TCP tuning for handshake latency reduction
 * - TLS 1.3 0-RTT early data support
 * - Session cache sharding for multi-threaded servers
 * - Buffer pooling for high-connection scenarios
 */

/**
 * @brief Optimize TCP settings for faster TLS handshake
 * @ingroup security
 * @param[in] socket Socket with TLS enabled but before handshake
 *
 * Applies TCP-level optimizations to reduce handshake latency:
 * 1. TCP_NODELAY: Disable Nagle's algorithm for immediate sends
 * 2. TCP_QUICKACK (Linux): Disable delayed ACKs during handshake
 *
 * These optimizations are beneficial for high-latency connections where
 * the TLS handshake RTT is significant. Call after SocketTLS_enable()
 * but before SocketTLS_handshake().
 *
 * @return 0 on success, -1 on error (TLS not enabled, invalid socket)
 *
 * @throws None
 * @threadsafe No - modifies socket options
 *
 * ## Example
 *
 * @code{.c}
 * SocketTLS_enable(sock, ctx);
 * SocketTLS_optimize_handshake(sock);  // Apply TCP optimizations
 * SocketTLS_set_hostname(sock, "example.com");
 * SocketTLS_handshake_auto(sock);
 * @endcode
 *
 * @see SocketTLS_restore_tcp_defaults() to revert for bulk transfers
 */
extern int SocketTLS_optimize_handshake (Socket_T socket);

/**
 * @brief Restore TCP settings after handshake for bulk transfers
 * @ingroup security
 * @param[in] socket Socket with completed TLS handshake
 *
 * Restores TCP settings to favor bulk data transfer efficiency:
 * - Re-enables Nagle's algorithm (TCP_NODELAY=0)
 *
 * Most applications keep TCP_NODELAY enabled throughout the connection.
 * Call this only if your application does bulk transfers and wants
 * Nagle's algorithm re-enabled for improved throughput.
 *
 * @return 0 on success, -1 on error
 *
 * @throws None
 * @threadsafe No - modifies socket options
 *
 * @see SocketTLS_optimize_handshake() to apply handshake optimizations
 */
extern int SocketTLS_restore_tcp_defaults (Socket_T socket);

/* ============================================================================
 * TLS 1.3 0-RTT Early Data Support
 * ============================================================================
 *
 * 0-RTT (Zero Round Trip Time) allows sending data in the first handshake
 * flight, reducing latency by one RTT. Available in TLS 1.3 with session
 * resumption.
 *
 * ## Security Warning
 *
 * Early data is NOT replay-protected by the TLS protocol. Applications MUST:
 * - Only use early data for idempotent operations (GET, not POST)
 * - Implement application-level replay detection
 * - Never include sensitive state-changing operations
 *
 * ## Recommended Use Cases
 * - HTTP GET requests
 * - DNS queries
 * - Heartbeat/ping messages
 *
 * ## NOT Recommended For
 * - POST requests that modify state
 * - Financial transactions
 * - Any non-idempotent operation
 */

/**
 * @brief Early data status codes for TLS 1.3 0-RTT
 * @ingroup security
 */
typedef enum
{
  SOCKET_EARLY_DATA_NOT_SENT = 0, /**< No early data was sent */
  SOCKET_EARLY_DATA_ACCEPTED = 1, /**< Server accepted early data */
  SOCKET_EARLY_DATA_REJECTED = 2  /**< Server rejected early data (resend needed) */
} SocketTLS_EarlyDataStatus;

/**
 * @brief Enable TLS 1.3 0-RTT early data on context
 * @ingroup security
 * @param[in] ctx TLS context
 * @param[in] max_early_data Maximum early data size (0 = default 16KB)
 *
 * Enables TLS 1.3 early data (0-RTT) on the context:
 * - For servers: Sets maximum early data to accept
 * - For clients: Enables sending early data on session resumption
 *
 * @throws SocketTLS_Failed on configuration error
 * @threadsafe No - call before sharing context
 *
 * @warning Early data is vulnerable to replay attacks. Only use for
 *          idempotent operations.
 *
 * @see SocketTLS_write_early_data() to send early data (client)
 * @see SocketTLS_read_early_data() to receive early data (server)
 */
extern void SocketTLSContext_enable_early_data (SocketTLSContext_T ctx,
                                                uint32_t max_early_data);

/**
 * @brief Disable TLS 1.3 0-RTT early data
 * @ingroup security
 * @param[in] ctx TLS context
 *
 * Disables 0-RTT early data support. Call this if replay protection
 * cannot be implemented at the application level.
 *
 * @threadsafe No - call before sharing context
 */
extern void SocketTLSContext_disable_early_data (SocketTLSContext_T ctx);

/**
 * @brief Send early data during TLS 1.3 handshake (client)
 * @ingroup security
 * @param[in] socket Socket with TLS enabled, during handshake
 * @param[in] buf Data buffer to send
 * @param[in] len Length of data
 * @param[out] written Bytes actually written
 *
 * Sends application data during the initial handshake flight (0-RTT).
 * Only works when:
 * 1. TLS 1.3 is negotiated
 * 2. Session resumption is being attempted
 * 3. Server accepts early data
 *
 * @return 1 on success (data written),
 *         0 if early data not accepted (retry with normal send),
 *         -1 on error
 *
 * @throws SocketTLS_Failed on TLS protocol error
 * @threadsafe No - modifies SSL state
 *
 * ## Example
 *
 * @code{.c}
 * // Client with session resumption
 * SocketTLS_enable(sock, ctx);
 * SocketTLS_session_restore(sock, session_data, session_len);
 *
 * // Try to send early data during handshake
 * size_t written;
 * const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
 * int ret = SocketTLS_write_early_data(sock, req, strlen(req), &written);
 *
 * // Complete handshake
 * SocketTLS_handshake_auto(sock);
 *
 * // Check if early data was accepted
 * if (SocketTLS_get_early_data_status(sock) == SOCKET_EARLY_DATA_REJECTED) {
 *     // Resend via normal channel
 *     SocketTLS_send(sock, req, strlen(req));
 * }
 * @endcode
 *
 * @warning Early data is NOT replay-protected. Only send idempotent operations.
 */
extern int SocketTLS_write_early_data (Socket_T socket, const void *buf,
                                       size_t len, size_t *written);

/**
 * @brief Receive early data during TLS 1.3 handshake (server)
 * @ingroup security
 * @param[in] socket Socket with TLS enabled (server-side), during handshake
 * @param[out] buf Buffer to receive data
 * @param[in] len Buffer size
 * @param[out] readbytes Bytes actually read
 *
 * Reads application data sent by client in initial handshake flight (0-RTT).
 * Only works when:
 * 1. This is a server socket
 * 2. TLS 1.3 is negotiated
 * 3. Client sent early data with session resumption
 *
 * @return 1 on success (data read),
 *         0 if no early data available,
 *         -1 on error
 *
 * @throws SocketTLS_Failed on TLS protocol error
 * @threadsafe No - modifies SSL state
 *
 * @warning Early data is NOT replay-protected. Server MUST implement
 *          application-level replay protection.
 */
extern int SocketTLS_read_early_data (Socket_T socket, void *buf, size_t len,
                                      size_t *readbytes);

/**
 * @brief Check early data status after handshake
 * @ingroup security
 * @param[in] socket Socket with completed TLS handshake
 *
 * Returns the status of early data after handshake completion.
 *
 * For clients: Check if early data needs to be retransmitted.
 * For servers: Check if early data was received.
 *
 * @return Early data status code
 *
 * @throws None
 * @threadsafe Yes - reads immutable post-handshake state
 *
 * @see SocketTLS_EarlyDataStatus for status values
 */
extern SocketTLS_EarlyDataStatus SocketTLS_get_early_data_status (Socket_T socket);

/* ============================================================================
 * TLS 1.3 KeyUpdate Support
 * ============================================================================
 *
 * TLS 1.3 replaces renegotiation with KeyUpdate, a lightweight mechanism to
 * rotate encryption keys without a full handshake. This provides forward
 * secrecy for long-lived connections.
 *
 * ## Use Cases
 *
 * - Long-lived database connections
 * - VPN tunnels
 * - Persistent WebSocket connections
 * - Any connection open for hours/days
 *
 * ## Comparison to Renegotiation
 *
 * | Aspect | KeyUpdate (TLS 1.3) | Renegotiation (TLS 1.2) |
 * |--------|---------------------|-------------------------|
 * | Overhead | Very light | Full handshake |
 * | Cert change | No | Yes |
 * | Cipher change | No | Yes |
 * | Security | Forward secrecy | Vulnerable to attacks |
 *
 * ## Recommended Usage
 *
 * For connections lasting hours or processing large data volumes, call
 * SocketTLS_request_key_update() periodically (e.g., every hour or every
 * 1GB of data transferred) to maintain forward secrecy.
 */

/**
 * @brief Request TLS 1.3 key rotation
 * @ingroup security
 * @param[in] socket Socket with completed TLS 1.3 handshake
 * @param[in] request_peer_update If 1, request peer to also update their keys
 *
 * Initiates a TLS 1.3 KeyUpdate to rotate encryption keys. This provides
 * forward secrecy for long-lived connections by generating new keys
 * derived from the current traffic secrets.
 *
 * The update is queued and executes on the next I/O operation. For
 * immediate effect, perform a send or recv after calling this function.
 *
 * @return 1 on success (KeyUpdate queued),
 *         0 if not applicable (not TLS 1.3, or handshake not done),
 *         -1 on error
 *
 * @throws SocketTLS_Failed on OpenSSL error
 * @threadsafe No - modifies SSL state
 *
 * ## Example
 *
 * @code{.c}
 * // Rotate keys every hour on long-lived connection
 * if (time(NULL) - last_key_update > 3600) {
 *     int ret = SocketTLS_request_key_update(sock, 1);
 *     if (ret == 1) {
 *         printf("KeyUpdate #%d queued\n",
 *                SocketTLS_get_key_update_count(sock));
 *         last_key_update = time(NULL);
 *     }
 * }
 * @endcode
 *
 * @note Only available for TLS 1.3 connections
 * @note KeyUpdate cannot change certificates or cipher suites
 *
 * @see SocketTLS_get_key_update_count() for monitoring
 * @see SocketTLS_check_renegotiation() for TLS 1.2 key changes
 */
extern int SocketTLS_request_key_update (Socket_T socket, int request_peer_update);

/**
 * @brief Get number of KeyUpdate operations performed
 * @ingroup security
 * @param[in] socket Socket with TLS enabled
 *
 * Returns the count of successful KeyUpdate operations on this connection.
 * Useful for monitoring key rotation frequency on long-lived connections.
 *
 * @return Number of KeyUpdates performed, or 0 if TLS not enabled
 *
 * @throws None
 * @threadsafe Yes - reads counter
 *
 * @see SocketTLS_request_key_update() to initiate key rotation
 */
extern int SocketTLS_get_key_update_count (Socket_T socket);

/* ============================================================================
 * Session Cache Optimization
 * ============================================================================
 */

/**
 * @brief Create sharded session cache for multi-threaded servers
 * @ingroup security
 * @param[in] ctx TLS context
 * @param[in] num_shards Number of cache shards (rounded to power of 2, max 256)
 * @param[in] sessions_per_shard Maximum sessions per shard
 * @param[in] timeout_seconds Session timeout
 *
 * Creates a sharded session cache for improved concurrency. Each shard
 * has independent locking, reducing contention in multi-threaded servers.
 *
 * @throws SocketTLS_Failed on configuration error
 * @threadsafe No - call before sharing context
 *
 * @see SocketTLSContext_get_sharded_stats() for aggregate statistics
 */
extern void SocketTLSContext_create_sharded_cache (SocketTLSContext_T ctx,
                                                   size_t num_shards,
                                                   size_t sessions_per_shard,
                                                   long timeout_seconds);

/**
 * @brief Get aggregate statistics from sharded session cache
 * @ingroup security
 * @param[in] ctx TLS context
 * @param[out] total_hits Total cache hits (may be NULL)
 * @param[out] total_misses Total cache misses (may be NULL)
 * @param[out] total_stores Total sessions stored (may be NULL)
 *
 * @threadsafe Yes - uses per-shard locking
 */
extern void SocketTLSContext_get_sharded_stats (SocketTLSContext_T ctx,
                                                size_t *total_hits,
                                                size_t *total_misses,
                                                size_t *total_stores);

/* ============================================================================
 * TLS Buffer Pool for High-Connection Scenarios
 * ============================================================================
 *
 * Pre-allocated buffer pool for servers with thousands of concurrent TLS
 * connections. Reduces allocation overhead and memory fragmentation.
 */

/**
 * @brief Opaque TLS buffer pool type
 * @ingroup security
 */
typedef struct TLSBufferPool *TLSBufferPool_T;

/**
 * @brief Create a TLS buffer pool
 * @ingroup security
 * @param[in] buffer_size Size of each buffer (typically SOCKET_TLS_BUFFER_SIZE)
 * @param[in] num_buffers Number of pre-allocated buffers
 * @param[in] arena Memory arena (NULL to create internal arena)
 *
 * Creates a pool of reusable TLS buffers to reduce per-connection
 * allocation overhead.
 *
 * @return New buffer pool, or NULL on error
 *
 * @threadsafe Yes - fully thread-safe once created
 */
extern TLSBufferPool_T TLSBufferPool_new (size_t buffer_size, size_t num_buffers,
                                          Arena_T arena);

/**
 * @brief Acquire a buffer from the pool
 * @ingroup security
 * @param[in] pool Buffer pool
 *
 * @return Buffer pointer, or NULL if pool exhausted
 *
 * @threadsafe Yes
 */
extern void *TLSBufferPool_acquire (TLSBufferPool_T pool);

/**
 * @brief Release a buffer back to the pool
 * @ingroup security
 * @param[in] pool Buffer pool
 * @param[in] buffer Buffer to release (must be from this pool)
 *
 * Buffer is NOT cleared; use SocketCrypto_secure_clear() first if it
 * contained sensitive data.
 *
 * @threadsafe Yes
 */
extern void TLSBufferPool_release (TLSBufferPool_T pool, void *buffer);

/**
 * @brief Get pool statistics
 * @ingroup security
 * @param[in] pool Buffer pool
 * @param[out] total Total buffers (may be NULL)
 * @param[out] in_use Buffers currently allocated (may be NULL)
 * @param[out] available Available buffers (may be NULL)
 *
 * @threadsafe Yes
 */
extern void TLSBufferPool_stats (TLSBufferPool_T pool, size_t *total,
                                 size_t *in_use, size_t *available);

/**
 * @brief Destroy a buffer pool
 * @ingroup security
 * @param[in,out] pool Pointer to pool (set to NULL on success)
 *
 * @threadsafe No - ensure all buffers are released first
 */
extern void TLSBufferPool_free (TLSBufferPool_T *pool);

#undef T

/** @} */ /* end of security group */

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLS_INCLUDED */
