/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDTLSCONTEXT_INCLUDED
#define SOCKETDTLSCONTEXT_INCLUDED

/**
 * @file SocketDTLSContext.h
 * @ingroup dtls_context
 * @brief DTLS context management with cookie protection and secure defaults.
 *
 * Manages OpenSSL SSL_CTX objects for DTLS with socket library integration.
 * Provides secure defaults (DTLS 1.2 minimum, modern ciphers), certificate
 * loading, cookie-based DoS protection, and session caching.
 *
 * Features:
 * - DTLS 1.2 enforcement for forward secrecy and security
 * - Modern cipher suites (ECDHE + AES-GCM/ChaCha20-Poly1305)
 * - Cookie exchange for DoS protection (RFC 6347)
 * - Certificate verification with CA loading and hostname validation
 * - ALPN protocol negotiation support
 * - Session resumption via cache for performance
 * - MTU configuration for UDP path optimization
 * - Non-blocking compatible configuration
 * - Exception-based error handling with detailed OpenSSL error messages
 *
 * Thread safety Contexts are not thread-safe for modification after creation.
 * Share read-only after full setup, or use per-thread contexts.
 * SSL objects created from context are per-connection and thread-safe.
 *
 * Platform Requirements:
 * - OpenSSL 1.1.1+ or LibreSSL with DTLS support
 * - POSIX threads (pthread) for thread-safe error reporting
 *
 * @see SocketDTLSContext_new_server() for server context creation.
 * @see SocketDTLSContext_new_client() for client context creation.
 * @see SocketDTLS_enable() for applying DTLS to UDP sockets.
 * @see @ref SocketTLSContext_T for TLS context management on TCP sockets.
 * @see @ref SocketDTLSConfig.h for DTLS configuration constants.
 * @ingroup dtls_context
 */

/**
 * @defgroup dtls_context DTLS Context Management
 * @ingroup security
 * @brief Secure DTLS context configuration and lifecycle management.
 *
 * Wraps OpenSSL SSL_CTX with socket library integration, providing secure
 * defaults (DTLS 1.2+, ECDHE ciphers), certificate handling, cookie DoS
 * protection (RFC 6347), ALPN, MTU config, and session caching for UDP/TLS.
 *
 * Thread safety: Creation thread-safe; modifications not safe after sharing.
 * Use per-thread contexts or mutex-protect config phase.
 *
 * @see SocketDTLS_T for applying contexts to UDP sockets.
 * @see SocketDTLSConfig.h for constants (e.g., ciphersuites, timeouts).
 * @see security for TLS/SYN protection modules.
 * @{
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "tls/SocketTLS.h" /* For TLSVerifyMode */

#if SOCKET_HAS_TLS

#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <stddef.h>

#define T SocketDTLSContext_T
/**
 * @brief Opaque handle for a DTLS security context.
 * @ingroup dtls_context
 *
 * Encapsulates an OpenSSL SSL_CTX configured for DTLS with secure defaults,
 * including protocol version enforcement, cipher selection, certificate
 * management, cookie generation for DoS mitigation, ALPN protocols, and
 * session caching.
 *
 * Lifecycle: Create via new_server() or new_client(), configure options,
 * load certs/CA, then associate with UDP sockets using SocketDTLS_enable().
 * Dispose with free() to release resources including arena allocations.
 *
 * Threading: Thread-safe for creation and read-only access after full setup.
 * Avoid concurrent modifications (e.g., set_verify_mode) without external
 * locking.
 *
 * @note All internal allocations use an embedded Arena_T for lifecycle
 * management.
 * @note Exceptions raised via SocketDTLS_Failed include detailed OpenSSL error
 * info.
 *
 * @see SocketDTLSContext_new_server() to create server contexts.
 * @see SocketDTLSContext_new_client() to create client contexts.
 * @see SocketDTLSContext_free() for disposal.
 * @see SocketDTLS_enable() to apply context to a SocketDgram_T.
 * @see @ref dtls_config for related constants and limits.
 */
typedef struct T *T;

/**
 * @brief Forward declaration of the opaque UDP datagram socket type.
 * @ingroup core_io
 *
 * Required for DTLS operations over UDP. Full definition and operations
 * provided in SocketDgram.h and socket/SocketDgram.h.
 *
 * DTLS contexts are applied to SocketDgram_T instances via
 * SocketDTLS_enable().
 *
 * @see SocketDgram.h for UDP socket creation, bind, send/recv, etc.
 * @see SocketDTLS_enable() for enabling DTLS on UDP sockets.
 */
typedef struct SocketDgram_T *SocketDgram_T;

/**
 * @brief Create a server-side DTLS context with certificate and key loading.
 * @ingroup dtls_context
 *
 * Initializes an OpenSSL SSL_CTX for DTLS server use, enforcing DTLS 1.2
 * minimum protocol, configuring modern secure cipher suites (ECDHE with
 * AES-GCM or ChaCha20-Poly1305), loading the provided server certificate and
 * private key, and optionally setting up CA certificates for client
 * authentication. This function performs all initial setup required for secure
 * DTLS server operation over UDP sockets.
 *
 * Key features enabled by default:
 * - Protocol versions: DTLS 1.2 only (forward secrecy enforced)
 * - Ciphers: High-security suites with perfect forward secrecy (PFS)
 * - Certificate verification: Optional client cert auth via CA
 * - Non-blocking compatible: Supports non-blocking socket I/O
 *
 * Cookie exchange for DoS protection (RFC 6347) is disabled by default to
 * avoid compatibility issues with legacy clients. Enable explicitly with
 * SocketDTLSContext_enable_cookie_exchange() for production servers under
 * attack risk.
 *
 * After creation, further customize with set_mtu(), set_alpn_protos(),
 * enable_session_cache(), or load additional certificates. Then apply to UDP
 * sockets using SocketDTLS_enable().
 *
 * @param[in] cert_file Path to the server certificate file in PEM format. Must
 * contain the full certificate chain if intermediate CAs are needed.
 * @param[in] key_file Path to the corresponding private key file in PEM or
 * PKCS#8 format. The key must match the certificate; mismatch raises
 * exception.
 * @param[in] ca_file Optional path to CA bundle file or directory containing
 * PEM-encoded trusted CA certificates for verifying client certificates. Pass
 * NULL to disable client authentication.
 *
 * @return Newly created SocketDTLSContext_T instance, ready for further
 * configuration or immediate use. Returns NULL only if exception is raised.
 *
 * @throws SocketDTLS_Failed If:
 *                           - OpenSSL initialization or SSL_CTX creation fails
 *                           - Certificate or key file cannot be read (ENOENT,
 * EACCES)
 *                           - Invalid PEM format in cert/key files
 *                           - Private key does not match certificate public
 * key
 *                           - CA file/directory invalid or unreadable
 *                           - Memory allocation failure in internal arena
 *
 * @threadsafe Yes - Each call creates an independent context instance with its
 * own internal arena and SSL_CTX. Safe to call concurrently from multiple
 *                 threads.
 *
 * ## Basic Server Setup
 *
 * @code{.c}
 * TRY {
 *     SocketDTLSContext_T ctx = SocketDTLSContext_new_server("server.crt",
 * "server.key", "ca-bundle.pem");
 *
 *     // Optional: Enable DoS protection
 *     SocketDTLSContext_enable_cookie_exchange(ctx);
 *
 *     // Optional: Set MTU for path
 *     SocketDTLSContext_set_mtu(ctx, 1400);
 *
 *     // Create UDP socket and enable DTLS
 *     SocketDgram_T sock = SocketDgram_new(AF_INET, IPPROTO_UDP);
 *     SocketDgram_bind(sock, "0.0.0.0", 4433);
 *     SocketDTLS_enable(sock, ctx);
 *
 *     // Now accept DTLS connections via SocketDTLS_accept() or similar
 * } EXCEPT(SocketDTLS_Failed) {
 *     SOCKET_LOG_ERROR_MSG("Failed to create DTLS context: %s",
 * Socket_GetLastError()); } FINALLY { SocketDTLSContext_free(&ctx); } END_TRY;
 * @endcode
 *
 * ## With Session Caching
 *
 * @code{.c}
 * SocketDTLSContext_T ctx = SocketDTLSContext_new_server("cert.pem",
 * "key.pem", NULL); SocketDTLSContext_enable_session_cache(ctx, 1000, 3600);
 * // 1000 sessions, 1hr timeout
 * // ... rest of setup ...
 * @endcode
 *
 * @note This function internally creates an Arena_T for all allocations
 * related to the context, including temporary buffers, ALPN data, and session
 * cache. The arena is disposed automatically on SocketDTLSContext_free().
 * @note For production, always enable cookie exchange on public-facing servers
 * to mitigate SYN flood-like attacks adapted for UDP (hello flood).
 * @warning Ensure cert_file and key_file permissions are 0600; readable by
 * server process only. Exposing private keys risks compromise.
 * @warning Client authentication (non-NULL ca_file) increases handshake
 * latency; use only when required for security policy.
 *
 * @complexity O(1) for creation, plus O(n) for file I/O and PEM parsing where
 * n is file size. Certificate validation is O(1) but CPU-intensive for large
 * chains.
 *
 * @see SocketDTLSContext_new_client() for client-side context creation.
 * @see SocketDTLSContext_load_certificate() for loading certs after initial
 * creation.
 * @see SocketDTLSContext_enable_cookie_exchange() for DoS protection.
 * @see SocketDTLS_enable() for applying context to UDP sockets.
 * @see SocketDTLSContext_free() for cleanup.
 * @see docs/SECURITY.md for TLS best practices and cipher recommendations.
 */
extern T SocketDTLSContext_new_server (const char *cert_file,
                                       const char *key_file,
                                       const char *ca_file);

/**
 * @brief Create a client-side DTLS context with optional CA for server
 * verification.
 * @ingroup dtls_context
 *
 * Initializes an OpenSSL SSL_CTX for DTLS client use, enforcing DTLS 1.2
 * minimum protocol and configuring secure modern cipher suites prioritizing
 * perfect forward secrecy (PFS) such as ECDHE with AES-GCM or
 * ChaCha20-Poly1305. If a CA file or directory is provided, loads trusted CA
 * certificates and enables server certificate verification, including hostname
 * matching when applied to sockets.
 *
 * This function sets up the context for secure outbound DTLS connections over
 * UDP, suitable for applications like secure IoT communication (CoAP/DTLS),
 * VPNs, or real-time media streaming. By default, hostname verification is not
 * enforced at context level but can be set per-socket via
 * SocketDTLS_set_hostname().
 *
 * Further customization post-creation includes setting ALPN protocols for
 * negotiation (e.g., "coap"), enabling session resumption for performance, or
 * adjusting MTU for path MTU discovery. Apply the context to UDP sockets using
 * SocketDTLS_enable() before initiating handshakes.
 *
 * @param[in] ca_file Optional path to a CA bundle file (PEM format) or
 * directory containing trusted CA certificates for verifying the server's
 *                    identity. Pass NULL to disable server verification (not
 * recommended for production; vulnerable to MITM attacks).
 *
 * @return Newly created SocketDTLSContext_T instance, configured for client
 * use. Returns NULL only if an exception is raised.
 *
 * @throws SocketDTLS_Failed If:
 *                           - OpenSSL SSL_CTX creation or initialization fails
 *                           - Provided CA file/directory cannot be read or
 * parsed (ENOENT, invalid PEM, permission denied)
 *                           - Memory allocation fails in internal arena
 *                           - Internal OpenSSL errors (e.g., insufficient
 * entropy)
 *
 * @threadsafe Yes - Creates an independent context with private state.
 * Concurrent calls from multiple threads are safe and produce isolated
 * contexts.
 *
 * ## Basic Client Usage
 *
 * @code{.c}
 * TRY {
 *     SocketDTLSContext_T ctx = SocketDTLSContext_new_client("ca-bundle.pem");
 * // Verify servers
 *
 *     // Optional: Advertise ALPN for protocol negotiation
 *     const char *protos[] = {"coap", NULL};
 *     SocketDTLSContext_set_alpn_protos(ctx, protos, 1);
 *
 *     // Optional: Enable session cache for repeated connections
 *     SocketDTLSContext_enable_session_cache(ctx, 500, 1800);  // 500
 * sessions, 30min
 *
 *     // Create UDP socket, enable DTLS, connect
 *     SocketDgram_T sock = SocketDgram_new(AF_INET, IPPROTO_UDP);
 *     SocketDTLS_enable(sock, ctx);
 *     SocketDTLS_set_hostname(sock, "example.com");  // For SNI and
 * verification SocketDgram_connect(sock, "example.com", 5684);  // CoAP
 * default
 *
 *     // Perform handshake
 *     TLSHandshakeState state = SocketDTLS_handshake(sock);
 *     while (state == TLS_HANDSHAKE_WANT_READ || state ==
 * TLS_HANDSHAKE_WANT_WRITE) {
 *         // Handle I/O in event loop
 *         state = SocketDTLS_handshake_loop(sock, 1000);  // 1s timeout
 *     }
 *
 *     if (state == TLS_HANDSHAKE_COMPLETE) {
 *         // Socket ready for encrypted send/recv
 *         ssize_t sent = SocketDTLS_send(sock, data, len);
 *     }
 *
 * } EXCEPT(SocketDTLS_Failed) {
 *     SOCKET_LOG_ERROR_MSG("DTLS client setup failed: %s",
 * Socket_GetLastError()); } FINALLY { SocketDTLSContext_free(&ctx); } END_TRY;
 * @endcode
 *
 * ## Without Server Verification (Development Only)
 *
 * @code{.c}
 * SocketDTLSContext_T ctx = SocketDTLSContext_new_client(NULL);  // No
 * verification
 * // WARNING: Insecure; use only for testing internal networks
 * @endcode
 *
 * @note The internal Arena_T manages all context-related memory, including
 * loaded CA certs and temporary buffers. Freed automatically on context
 * disposal.
 * @note For client auth (mutual TLS), load client cert/key separately using
 *       SocketDTLSContext_load_certificate() after creation.
 * @warning Disabling verification (ca_file=NULL) exposes connections to
 * man-in-the-middle attacks. Always use trusted CAs in production.
 * @warning Ensure the CA bundle includes all necessary root and intermediate
 * certificates to avoid verification failures.
 *
 * @complexity O(1) for context creation, O(n) for CA loading/parsing where n
 * is CA bundle size. OpenSSL initialization is O(1) but may block briefly for
 * entropy gathering.
 *
 * @see SocketDTLSContext_new_server() for server-side contexts.
 * @see SocketDTLSContext_load_ca() for additional CA loading post-creation.
 * @see SocketDTLSContext_set_alpn_protos() for protocol negotiation.
 * @see SocketDTLS_enable() and SocketDTLS_set_hostname() for socket
 * integration.
 * @see SocketDTLS_handshake() for performing the DTLS handshake.
 * @see docs/SECURITY.md#tls-client-configuration for secure client setup
 * guidelines.
 */
extern T SocketDTLSContext_new_client (const char *ca_file);

/**
 * @brief Dispose of a DTLS context, freeing all associated resources.
 * @ingroup dtls_context
 *
 * Releases the underlying OpenSSL SSL_CTX, internal Arena_T allocations
 * (including loaded certificates, CA stores, cookie secrets, ALPN protocol
 * lists, and session cache if enabled), and any other context-specific
 * resources. Sets the provided pointer to NULL to prevent use-after-free
 * errors. This is the counterpart to SocketDTLSContext_new_server() or
 * new_client().
 *
 * All SSL/DTLS objects created from this context (via SocketDTLS_enable())
 * must be freed separately before or after context disposal, as they hold
 * references to shared state. However, disposing the context invalidates those
 * objects immediately, so free sockets first in production code for graceful
 * shutdowns.
 *
 * Safe to call with NULL pointer (no-op). Idempotent: repeated calls on same
 * pointer (already NULL) do nothing.
 *
 * @param[in,out] ctx_p Pointer to the SocketDTLSContext_T handle. Set to NULL
 * on success.
 *
 * @return void
 *
 * @throws None - Errors during cleanup (e.g., OpenSSL internal) are logged but
 * do not raise exceptions to avoid complicating cleanup paths.
 *
 * @threadsafe Yes - But avoid concurrent calls on the same context pointer
 * without external synchronization. Read-only after full setup; disposal is
 *                 atomic but may block briefly during resource release.
 *
 * ## Basic Cleanup Pattern
 *
 * @code{.c}
 * // In normal operation
 * SocketDTLSContext_free(&ctx);  // Sets ctx to NULL
 *
 * // Safe for NULL
 * SocketDTLSContext_free(NULL);
 *
 * // In TRY/FINALLY for error safety
 * TRY {
 *     SocketDTLSContext_T ctx = SocketDTLSContext_new_server(...);
 *     // ... use ctx to enable DTLS on sockets ...
 *     // Free sockets first
 *     SocketDgram_free(&sock);
 * } FINALLY {
 *     SocketDTLSContext_free(&ctx);
 * } END_TRY;
 * @endcode
 *
 * @note This function does not flush or invalidate active sessions in the
 * cache; ongoing handshakes or data exchanges on associated sockets may fail
 * post-disposal.
 * @note For servers handling many connections, consider graceful drain: stop
 * accepting new connections, wait for existing to complete, then free context.
 * @warning Do not use the context or any derived SSL objects after calling
 * free(). Undefined behavior, potential crashes or leaks.
 * @warning In multi-threaded environments, ensure no threads are using the
 * context during disposal; use synchronization primitives if necessary.
 *
 * @complexity O(1) average, O(n) worst case where n is number of cached
 * sessions or loaded certs to free. Arena clear is O(allocated bytes) but
 * fast.
 *
 * @see SocketDTLSContext_new_server() and SocketDTLSContext_new_client() for
 * creation.
 * @see Arena_dispose() for underlying memory management details.
 * @see SocketDTLS_free() for cleaning up per-socket DTLS state.
 * @see docs/SECURITY.md#resource-management for best practices on TLS context
 * lifecycle.
 */
extern void SocketDTLSContext_free (T *ctx_p);

/**
 * @brief Increment the reference count on a DTLS context.
 * @ingroup dtls_context
 *
 * Increments the internal reference count, allowing the context to be shared
 * safely across multiple sockets. Each call to SocketDTLSContext_ref() must be
 * balanced by a call to SocketDTLSContext_free() when the socket no longer
 * needs the context.
 *
 * This function is called automatically by SocketDTLS_enable() when a context
 * is attached to a socket. Manual calls are typically not needed unless
 * implementing custom context sharing patterns.
 *
 * @param[in] ctx The context to retain. If NULL, this is a no-op.
 *
 * @threadsafe Yes - Uses atomic operations for the reference count.
 *
 * @see SocketDTLSContext_free() to release a reference.
 * @see SocketDTLS_enable() which automatically retains the context.
 */
extern void SocketDTLSContext_ref (T ctx);

/**
 * @brief Load and configure server certificate and private key into the DTLS
 * context.
 * @ingroup dtls_context
 *
 * Reads the specified certificate and private key files in PEM format, parses
 * them using OpenSSL, validates that the private key corresponds to the
 * certificate's public key, and installs them into the context's SSL_CTX for
 * use in server-side DTLS handshakes. Supports certificate chains (multiple
 * certs in file) for intermediate CA inclusion.
 *
 * This function is useful for dynamic certificate reloading without recreating
 * the entire context, e.g., for certificate rotation in long-running servers.
 * It replaces any previously loaded server certificate/key pair.
 *
 * Note: Client contexts can also use this for mutual TLS (client
 * authentication), though new_client() does not load them by default.
 *
 * @param[in] ctx The SocketDTLSContext_T instance to configure.
 * @param[in] cert_file Path to the server/client certificate file(s) in PEM
 * format. May contain certificate chain (server cert first, then
 * intermediates).
 * @param[in] key_file Path to the private key file in PEM, PKCS#8, or
 * traditional format. Encrypted keys prompt for passphrase via OpenSSL
 * callback (not supported in non-interactive mode; exception raised).
 *
 * @return void
 *
 * @throws SocketDTLS_Failed If:
 *                           - ctx is NULL or invalid
 *                           - File read errors (ENOENT, EACCES, EISDIR)
 *                           - Invalid PEM/PKCS format or parsing failure
 *                           - Private key does not match certificate (key
 * mismatch)
 *                           - OpenSSL X509/SSL installation fails
 *                           - Memory allocation error during parsing
 *
 * @threadsafe No - Modifies shared SSL_CTX and internal state. Caller must
 * synchronize if context is shared across threads. Prefer per-thread contexts
 * for high-contention scenarios.
 *
 * ## Dynamic Certificate Reload
 *
 * @code{.c}
 * TRY {
 *     // Existing context from new_server() or new_client()
 *     SocketDTLSContext_load_certificate(ctx, "new-server.crt",
 * "new-server.key");
 *
 *     // Context now uses new cert/key for subsequent handshakes
 *     // Existing connections unaffected (use SSL_CTX_set_session_id_context
 * or reload sockets)
 *
 * } EXCEPT(SocketDTLS_Failed) {
 *     SOCKET_LOG_ERROR_MSG("Cert load failed: %s", Socket_GetLastError());
 *     // Rollback or retry logic here
 * } END_TRY;
 * @endcode
 *
 * ## Client Certificate for Mutual TLS
 *
 * @code{.c}
 * SocketDTLSContext_T client_ctx = SocketDTLSContext_new_client("ca.pem");
 * SocketDTLSContext_load_certificate(client_ctx, "client.crt", "client.key");
 * // Now client presents cert during handshake if server requests
 * @endcode
 *
 * @note Previously loaded certificates are replaced; no support for multiple
 * certs (SNI-based selection requires custom OpenSSL extensions not
 * implemented here).
 * @note Key files with passphrases are not supported in this library; use
 * unencrypted keys or external decryption.
 * @warning Verify file permissions: cert/key files should be 0600, owned by
 * server process. Leaked keys compromise security.
 * @warning After loading, test with a handshake to confirm validity; silent
 * failures possible if OpenSSL accepts but peer rejects.
 *
 * @complexity O(n) where n is combined size of cert and key files for parsing
 * and validation. Key-cert matching involves cryptographic operations (O(1)
 * but compute-heavy).
 *
 * @see SocketDTLSContext_new_server() which calls this internally during
 * creation.
 * @see SocketDTLSContext_load_ca() for loading trust anchors.
 * @see SSL_CTX_use_certificate_chain_file() and SSL_CTX_use_PrivateKey_file()
 * for OpenSSL equivalents.
 * @see docs/SECURITY.md#certificate-management for rotation strategies and
 * best practices.
 */
extern void SocketDTLSContext_load_certificate (T ctx,
                                                const char *cert_file,
                                                const char *key_file);

/**
 * @brief Load trusted CA certificates
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 * @param ca_file Path to CA file or directory containing PEM CA certs
 *
 * Loads CA certs for peer verification. Tries as file then directory.
 *
 * @return void
 * @throws SocketDTLS_Failed on load errors
 * @threadsafe No
 */
extern void SocketDTLSContext_load_ca (T ctx, const char *ca_file);

/**
 * @brief Set certificate verification policy
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 * @param mode Verification mode enum (TLS_VERIFY_NONE, PEER, etc.)
 *
 * Configures peer cert verification behavior, mapping to OpenSSL SSL_VERIFY_*
 * flags.
 *
 * @return void
 * @note Maps provided flags to OpenSSL SSL_VERIFY_* constants; invalid or
 * unsupported flags are ignored without error.
 * @threadsafe No
 */
extern void SocketDTLSContext_set_verify_mode (T ctx, TLSVerifyMode mode);

/**
 * @brief Enable cookie exchange mechanism for stateless DoS protection in DTLS
 * servers.
 * @ingroup dtls_context
 *
 * Activates the RFC 6347 "stateless cookie" mechanism to mitigate
 * denial-of-service attacks via forged ClientHello messages (DTLS equivalent
 * of SYN floods). When enabled on a server context, upon receiving a
 * ClientHello, the server generates a cryptographically signed cookie (using
 * HMAC with a secret key) and responds with a HelloVerifyRequest instead of
 * allocating server-side handshake state. The client must include the cookie
 * in its second ClientHello to prove reachability (round-trip validation),
 * preventing resource exhaustion from spoofed IPs.
 *
 * This adds one extra round-trip to successful handshakes (increased latency
 * ~1 RTT) but drastically reduces server memory/CPU usage under attack.
 * Cookies are short-lived and stateless on server side until valid handshake
 * proceeds.
 *
 * Automatic secret key generation occurs on enable (random 32-byte key). For
 * load-balanced or clustered servers, set a shared secret via
 * SocketDTLSContext_set_cookie_secret() before or after enabling to ensure
 * cookie compatibility across instances. Rotate periodically with
 * SocketDTLSContext_rotate_cookie_secret() to limit replay attacks.
 *
 * Client contexts ignore this setting. Only applicable to server-mode
 * contexts.
 *
 * @param[in] ctx The server-side SocketDTLSContext_T instance.
 *
 * @return void
 *
 * @throws SocketDTLS_Failed If:
 *                           - ctx is NULL or not server-mode (use is_server()
 * to check)
 *                           - OpenSSL DTLS cookie callbacks cannot be
 * installed
 *                           - Internal random number generation for initial
 * secret fails
 *                           - Context already finalized or incompatible state
 *
 * @threadsafe No - Installs OpenSSL callbacks and generates/stores secret key,
 * modifying shared context state. Synchronize access if shared across threads.
 *
 * ## Enabling DoS Protection in Server Setup
 *
 * @code{.c}
 * TRY {
 *     SocketDTLSContext_T ctx = SocketDTLSContext_new_server("server.crt",
 * "server.key", NULL);
 *
 *     // Enable cookie exchange for production DoS resistance
 *     SocketDTLSContext_enable_cookie_exchange(ctx);
 *
 *     // Optional: Set shared secret for cluster (before or after enable)
 *     unsigned char secret[32];  // SOCKET_DTLS_COOKIE_SECRET_LEN
 *     RAND_bytes(secret, sizeof(secret));  // Or load from secure storage
 *     SocketDTLSContext_set_cookie_secret(ctx, secret, sizeof(secret));
 *
 *     // Apply to UDP listener
 *     SocketDgram_T listener = SocketDgram_new(AF_INET, IPPROTO_UDP);
 *     SocketDgram_bind(listener, "0.0.0.0", 4433);
 *     SocketDTLS_enable(listener, ctx);
 *
 *     // In event loop: accept with cookie validation handled internally by
 * OpenSSL while (running) { SocketDgram_T client_sock =
 * SocketDTLS_accept(listener);  // Blocks until valid handshake if
 * (client_sock) { handle_secure_client(client_sock);
 *             SocketDgram_free(&client_sock);
 *         }
 *     }
 *
 * } EXCEPT(SocketDTLS_Failed) {
 *     // Handle error
 * } FINALLY {
 *     SocketDTLSContext_free(&ctx);
 * } END_TRY;
 * @endcode
 *
 * ## Periodic Secret Rotation
 *
 * @code{.c}
 * // In timer callback or cron job
 * SocketDTLSContext_rotate_cookie_secret(ctx);  // Generates new secret,
 * invalidates old cookies
 * // Clients will retry handshake automatically
 * @endcode
 *
 * @note Cookies include client IP, timestamp, and opaque data, signed with
 * HMAC-SHA256. Secret rotation invalidates existing cookies, forcing client
 * retries (harmless).
 * @note Adds ~100-200 bytes to HelloVerifyRequest; minimal bandwidth overhead.
 * @note Compatible with DTLS 1.2 clients; older versions may fail handshake.
 * @warning Without cookies, servers vulnerable to UDP amplification/reflection
 * attacks. Always enable on internet-facing DTLS servers.
 * @warning Shared secrets must be securely distributed and identical across
 * cluster nodes; mismatch causes handshake failures.
 *
 * @complexity O(1) - Configuration and callback registration; secret gen is
 * O(1) crypto.
 *
 * @see SocketDTLSContext_set_cookie_secret() for manual secret configuration.
 * @see SocketDTLSContext_rotate_cookie_secret() for key rotation.
 * @see SocketDTLSContext_new_server() which creates compatible server
 * contexts.
 * @see RFC 6347 Section 4.2.1 for protocol details on hello verification.
 * @see docs/SYN-PROTECT.md for complementary TCP SYN protection strategies.
 * @see docs/SECURITY.md#dos-mitigation for broader DoS defense in socket
 * library.
 */
extern void SocketDTLSContext_enable_cookie_exchange (T ctx);

/**
 * @brief Configure the HMAC secret key for DTLS cookie generation.
 * @ingroup dtls_context
 *
 * Specifies the cryptographic secret key used by OpenSSL for HMAC-SHA256
 * signing of DTLS cookies in the hello verification exchange. This key ensures
 * cookies generated by one server instance are verifiable by others in a
 * cluster or load-balanced setup, enabling consistent DoS protection across
 * multiple servers.
 *
 * The key must be exactly SOCKET_DTLS_COOKIE_SECRET_LEN (typically 32 bytes)
 * long for security and compatibility. Calling this after
 * SocketDTLSContext_enable_cookie_exchange() overrides the auto-generated
 * random secret. For security, use cryptographically secure random bytes or
 * derive from a master key with rotation.
 *
 * Secret is stored in the internal arena and zeroed on context free. Rotation
 * via SocketDTLSContext_rotate_cookie_secret() generates a new random key
 * while preserving the length.
 *
 * Only meaningful if cookie exchange is enabled; ignored otherwise. Client
 * contexts do not use cookies.
 *
 * @param[in] ctx The server-side SocketDTLSContext_T instance with cookies
 * enabled.
 * @param[in] secret Buffer containing the secret key bytes. Copied internally;
 * original can be zeroed after call for security.
 * @param[in] len Length of secret buffer in bytes. Must match
 * SOCKET_DTLS_COOKIE_SECRET_LEN exactly or exception raised.
 *
 * @return void
 *
 * @throws SocketDTLS_Failed If:
 *                           - ctx is NULL or not server-mode
 *                           - len != SOCKET_DTLS_COOKIE_SECRET_LEN
 * (compile-time constant)
 *                           - Cookie exchange not enabled on ctx
 *                           - Memory copy or storage fails (arena alloc)
 *                           - OpenSSL callback update fails
 *
 * @threadsafe No - Modifies shared secret and OpenSSL context state. External
 * locking required if context shared. Best called during setup before sharing.
 *
 * ## Cluster Secret Configuration
 *
 * @code{.c}
 * TRY {
 *     SocketDTLSContext_T ctx = SocketDTLSContext_new_server("cert.pem",
 * "key.pem", NULL); SocketDTLSContext_enable_cookie_exchange(ctx);
 *
 *     // Load shared secret from secure storage or config
 *     unsigned char shared_secret[32];
 *     load_secure_key(shared_secret, sizeof(shared_secret));  // e.g., from
 * HSM or file SocketDTLSContext_set_cookie_secret(ctx, shared_secret,
 * sizeof(shared_secret)); secure_zero(shared_secret, sizeof(shared_secret));
 * // Erase from memory
 *
 *     // All cluster nodes must use same secret for compatibility
 * } EXCEPT(SocketDTLS_Failed) {
 *     // Log and handle
 * } END_TRY;
 * @endcode
 *
 * ## Rotation with Shared Secret
 *
 * @code{.c}
 * // After enable and set, rotate periodically
 * SocketDTLSContext_rotate_cookie_secret(ctx);  // Generates new random,
 * invalidates old
 * // Update cluster nodes synchronously or use key derivation with timestamps
 * @endcode
 *
 * @note Secret is used in HMAC(cookie_data, secret) where cookie_data includes
 * client IP, port, timestamp to prevent replay. Length 32 bytes for SHA256
 * security margin.
 * @note For high-security, rotate secrets every 1-24 hours and distribute
 * securely (e.g., via KMS or encrypted config).
 * @warning Weak or short secrets reduce HMAC security; use full-length random
 * bytes.
 * @warning Mismatched secrets across cluster cause client handshake failures
 * (retry ok but increases load).
 * @warning Secret stored in memory until context free; use mlock or similar
 * for sensitive deployments.
 *
 * @complexity O(1) - Key copy and OpenSSL update; no crypto computation here.
 *
 * @see SocketDTLSContext_enable_cookie_exchange() prerequisite.
 * @see SocketDTLSContext_rotate_cookie_secret() for auto-rotation.
 * @see RFC 6347 for cookie format and security considerations.
 * @see docs/SECURITY.md#key-management for best practices on secret handling.
 */
extern void SocketDTLSContext_set_cookie_secret (T ctx,
                                                 const unsigned char *secret,
                                                 size_t len);

/**
 * @brief Rotate the DTLS cookie HMAC secret key to a new random value.
 * @ingroup dtls_context
 *
 * Generates a new cryptographically secure random secret key
 * (SOCKET_DTLS_COOKIE_SECRET_LEN bytes) and updates the OpenSSL cookie
 * generation callbacks to use it for subsequent HMAC operations. This limits
 * the window for cookie replay attacks by invalidating previously issued
 * cookies.
 *
 * Recommended for production servers to call periodically (e.g., every 1-24
 * hours via timer) or on security events. Clients using old cookies will
 * receive handshake failure and retry with a new ClientHello, incurring
 * minimal extra latency under normal load but preventing long-term replay.
 *
 * Requires cookie exchange enabled and a server context. The old secret is
 * overwritten immediately; no fallback mechanism. For clustered setups,
 * synchronize rotation across all nodes to avoid verification failures.
 *
 * @param[in] ctx The server-side SocketDTLSContext_T instance with cookies
 * enabled.
 *
 * @return void
 *
 * @throws SocketDTLS_Failed If:
 *                           - ctx is NULL or not server-mode
 *                           - Cookie exchange not enabled
 *                           - Random number generation fails (low entropy,
 * OpenSSL error)
 *                           - Key storage or callback update fails
 *
 * @threadsafe No - Generates and stores new secret, updates shared OpenSSL
 * state. Lock if context shared; call during low-traffic periods.
 *
 * ## Periodic Rotation Setup
 *
 * @code{.c}
 * // Using SocketTimer for hourly rotation
 * void rotation_cb(void *userdata) {
 *     SocketDTLSContext_T *ctx = userdata;
 *     TRY {
 *         SocketDTLSContext_rotate_cookie_secret(*ctx);
 *         SOCKET_LOG_INFO_MSG("Cookie secret rotated for DoS protection.");
 *     } EXCEPT(SocketDTLS_Failed) {
 *         SOCKET_LOG_ERROR_MSG("Secret rotation failed: %s",
 * Socket_GetLastError()); } END_TRY;
 * }
 *
 * // In server init after enable_cookie_exchange(ctx)
 * SocketTimer_T timer = SocketTimer_add_repeating(poll, 3600000, rotation_cb,
 * &ctx);  // 1hr
 * @endcode
 *
 * ## Manual Rotation on Signal
 *
 * @code{.c}
 * // In signal handler or admin command
 * SocketDTLSContext_rotate_cookie_secret(ctx);
 * // Notify cluster nodes to rotate synchronously
 * broadcast_rotation_signal();
 * @endcode
 *
 * @note New secret affects only new cookies; existing valid cookies (with old
 * secret) remain verifiable until expiry (typically short, ~5-10 min per RFC).
 * @note OpenSSL RAND_bytes() used for randomness; blocks if entropy low (rare
 * on modern systems).
 * @note Rotation increases brief handshake failures for in-flight clients, but
 * enhances security.
 * @warning In clusters, unsynchronized rotation causes widespread handshake
 * failures; use coordinated timing or key version in cookie.
 * @warning Frequent rotation ( <1hr) increases client retries under load;
 * balance security vs perf.
 *
 * @complexity O(1) - Random gen and update; RAND_bytes is O(1) amortized.
 *
 * @see SocketDTLSContext_set_cookie_secret() for manual shared keys.
 * @see SocketDTLSContext_enable_cookie_exchange() prerequisite.
 * @see SocketTimer for scheduling rotations.
 * @see RFC 6347 Section 4.2.1 for cookie security and replay protection.
 * @see docs/SECURITY.md#rotation for key rotation best practices.
 */
extern void SocketDTLSContext_rotate_cookie_secret (T ctx);

/**
 * @brief Configure the path MTU for DTLS record fragmentation and padding.
 * @ingroup dtls_context
 *
 * Sets the maximum transmission unit (MTU) value used by OpenSSL to fragment
 * DTLS records and add IP/UDP headers in path MTU discovery. This prevents IP
 * fragmentation on the network path, reducing overhead and avoiding blackhole
 * routers that drop fragmented packets.
 *
 * Default (if not set) is a conservative 1200 bytes to accommodate IPv6
 * headers (40B), UDP (8B), DTLS record overhead (~13B), and common VPN/tunnel
 * encapsulations. For known paths (e.g., LAN 1500 MTU), set higher for better
 * throughput. Values below 512 or above 65535 raise exception.
 *
 * Applies to all SSL objects created from this context. Per-socket override
 * possible via SocketDTLS_set_mtu() if needed. Recommended to probe actual
 * path MTU using ICMP or packet traces for optimal setting.
 *
 * @param[in] ctx The SocketDTLSContext_T instance.
 * @param[in] mtu MTU in bytes (512-65535). Should include IP+UDP headers;
 * OpenSSL subtracts them internally for record sizing.
 *
 * @return void
 *
 * @throws SocketDTLS_Failed If mtu out of valid range ( <512 or >65535) or ctx
 * invalid.
 *
 * @threadsafe No - Updates shared SSL_CTX MTU configuration. Synchronize if
 * shared.
 *
 * ## MTU Setup for Different Networks
 *
 * @code{.c}
 * TRY {
 *     SocketDTLSContext_T ctx = SocketDTLSContext_new_server(...);
 *
 *     // LAN: full Ethernet MTU
 *     SocketDTLSContext_set_mtu(ctx, 1472);  // 1500 - IP(20) - UDP(8)
 *
 *     // VPN or IPv6: conservative
 *     // SocketDTLSContext_set_mtu(ctx, 1200); // Default safe
 *
 *     // Custom probe
 *     size_t probed_mtu = probe_path_mtu("remote.ip", port);
 *     SocketDTLSContext_set_mtu(ctx, probed_mtu - DTLS_OVERHEAD);
 *
 * } EXCEPT(SocketDTLS_Failed) {
 *     // Fallback to default
 * } END_TRY;
 * @endcode
 *
 * @note OpenSSL uses mtu for DTLS1_RECORD_OVERHEAD calculation; too low causes
 * excessive fragmentation, too high risks packet drops.
 * @note For UDP, actual path MTU includes IP+UDP headers (~28B IPv4, 48B
 * IPv6); set accordingly.
 * @note Change invalidates any pre-allocated buffers; test handshakes after
 * set.
 * @warning Incorrect MTU causes performance degradation or connection
 * failures; always test on target network.
 * @warning Larger MTU improves throughput but increases latency if
 * fragmentation occurs.
 *
 * @complexity O(1) - Simple config set on SSL_CTX.
 *
 * @see SocketDTLSContext_get_mtu() to query current value.
 * @see SocketDTLS_set_mtu() for per-socket override.
 * @see RFC 6347 Section 4.2.3 for DTLS fragmentation details.
 * @see docs/ASYNC_IO.md for UDP path considerations in async I/O.
 */
extern void SocketDTLSContext_set_mtu (T ctx, size_t mtu);

/**
 * @brief Retrieve the currently configured path MTU from the DTLS context.
 * @ingroup dtls_context
 *
 * Returns the MTU value set via SocketDTLSContext_set_mtu() or the internal
 * default. Useful for logging, debugging, or dynamic adjustment logic.
 * Read-only operation.
 *
 * @param[in] ctx The SocketDTLSContext_T instance.
 *
 * @return Configured MTU in bytes (512-65535 or default).
 *
 * @throws None
 *
 * @threadsafe Yes - Pure read access to immutable config value; safe
 * concurrent.
 *
 * @note Default value is 1200 if not explicitly set.
 *
 * @complexity O(1) - Direct field access.
 *
 * @see SocketDTLSContext_set_mtu() for setting.
 * @see SocketDTLS_get_mtu() for per-socket value (may override).
 */
extern size_t SocketDTLSContext_get_mtu (T ctx);

/**
 * @brief Set minimum supported DTLS version
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 * @param version OpenSSL version constant (e.g., DTLS1_2_VERSION)
 *
 * Sets minimum DTLS version. Default is DTLS 1.2.
 *
 * @return void
 * @throws SocketDTLS_Failed if cannot set
 * @threadsafe No
 */
extern void SocketDTLSContext_set_min_protocol (T ctx, int version);

/**
 * @brief Set maximum supported DTLS version
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 * @param version OpenSSL version constant (e.g., DTLS1_2_VERSION)
 *
 * Sets maximum DTLS version.
 *
 * @return void
 * @throws SocketDTLS_Failed if cannot set
 * @threadsafe No
 */
extern void SocketDTLSContext_set_max_protocol (T ctx, int version);

/**
 * @brief Set allowed cipher suites
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 * @param ciphers Cipher list string in OpenSSL format, or NULL for defaults
 *
 * Configures allowed ciphers. Defaults to secure modern list if NULL.
 *
 * @return void
 * @throws SocketDTLS_Failed if invalid list
 * @threadsafe No
 */
extern void SocketDTLSContext_set_cipher_list (T ctx, const char *ciphers);

/**
 * @brief Advertise ALPN protocols
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 * @param protos Array of null-terminated protocol strings (e.g., "coap", "h3")
 * @param count Number of protocols
 *
 * Sets list of supported ALPN protocols in wire format, allocated from context
 * arena. Validates lengths and formats for TLS compliance.
 *
 * @return void
 * @throws SocketDTLS_Failed on invalid protos or allocation error
 * @threadsafe No

 *
 * Note Protocols advertised in preference order (first preferred).
 */
extern void
SocketDTLSContext_set_alpn_protos (T ctx, const char **protos, size_t count);

/**
 * @brief Enable session caching
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 * @param max_sessions Maximum number of sessions to cache (>0), 0 for default
 * @param timeout_seconds Session timeout in seconds, 0 for OpenSSL default
 * (300s)
 *
 * Enables session resumption for reduced handshake latency (1-RTT vs 2-RTT).
 *
 * @return void
 * @throws SocketDTLS_Failed if cannot enable or configure
 * @threadsafe No - modifies shared context during setup
 */
extern void SocketDTLSContext_enable_session_cache (T ctx,
                                                    size_t max_sessions,
                                                    long timeout_seconds);

/**
 * @brief Get session cache statistics
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 * @param hits Output number of cache hits
 * @param misses Output number of cache misses
 * @param stores Output number of sessions stored
 *
 * Fills provided pointers with current session cache statistics.
 * Statistics are thread-safe and cumulative since cache enable.
 * If pointers NULL, skipped.
 *
 * @return void
 * @throws None
 * @threadsafe Yes
 */
extern void SocketDTLSContext_get_cache_stats (T ctx,
                                               size_t *hits,
                                               size_t *misses,
                                               size_t *stores);

/**
 * @brief Set handshake timeout parameters
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 * @param initial_ms Initial retransmission timeout in milliseconds
 * @param max_ms Maximum timeout after exponential backoff
 *
 * Configures DTLS handshake retransmission timer. OpenSSL handles
 * retransmission internally using these parameters.
 *
 * @return void
 * @throws SocketDTLS_Failed on invalid parameters
 * @threadsafe No
 */
extern void SocketDTLSContext_set_timeout (T ctx, int initial_ms, int max_ms);

/**
 * @brief Internal accessor for the underlying OpenSSL SSL_CTX pointer.
 * @ingroup dtls_context
 * @internal
 *
 * Provides direct access to the OpenSSL SSL_CTX* managed by this wrapper,
 * intended solely for internal library use such as SocketDTLS_enable() which
 * needs to create SSL* instances and associate them with sockets.
 *
 * End users should not call this; use high-level APIs like
 * SocketDTLS_enable(). Violates encapsulation; raw pointer management risks
 * misuse.
 *
 * @param[in] ctx The SocketDTLSContext_T instance.
 *
 * @return void* castable to SSL_CTX* (non-NULL if ctx valid).
 *
 * @throws None
 *
 * @threadsafe Yes - Returns const pointer to immutable SSL_CTX after setup.
 *
 * @warning Internal API; subject to change. Do not use in application code.
 *
 * @complexity O(1) - Direct field return.
 *
 * @see SocketDTLS_enable() internal user.
 * @see SocketDTLSContext_new_server() creates the SSL_CTX.
 */
extern void *SocketDTLSContext_get_ssl_ctx (T ctx);

/**
 * @brief Determine if the DTLS context is configured for server role.
 * @ingroup dtls_context
 * @internal
 *
 * Internal utility to query whether the context was created with server
 * options (e.g., via new_server, loaded cert/key) or client (new_client). Used
 * by library internals like SocketDTLS_accept() vs connect logic.
 *
 * End users typically do not need this; role is implicit in usage.
 *
 * @param[in] ctx The SocketDTLSContext_T instance.
 *
 * @return 1 if server-mode, 0 if client-mode.
 *
 * @throws None
 *
 * @threadsafe Yes - Reads immutable role flag set at creation.
 *
 * @complexity O(1) - Direct flag check.
 *
 * @see SocketDTLSContext_new_server() sets server mode.
 * @see SocketDTLSContext_new_client() sets client mode.
 * @see SocketDTLS_is_server() for per-socket role query.
 */
extern int SocketDTLSContext_is_server (T ctx);

/**
 * @brief Query if cookie exchange (DoS protection) is enabled on the context.
 * @ingroup dtls_context
 * @internal
 *
 * Returns whether SocketDTLSContext_enable_cookie_exchange() has been called
 * and callbacks installed for hello verification. Used internally to
 * conditionalize server behavior or logging.
 *
 * @param[in] ctx The SocketDTLSContext_T instance (server preferred).
 *
 * @return 1 if enabled, 0 if disabled or client context.
 *
 * @throws None
 *
 * @threadsafe Yes - Reads immutable flag set at enable time.
 *
 * @complexity O(1) - Flag check.
 *
 * @see SocketDTLSContext_enable_cookie_exchange() sets this flag.
 * @see SocketDTLS_has_cookie_exchange() for per-socket query.
 */
extern int SocketDTLSContext_has_cookie_exchange (T ctx);

/** @} */ /* dtls_context */

/*
 * @} */
/* security */ // Optional, if wanted, but since defined elsewhere
#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETDTLSCONTEXT_INCLUDED */
