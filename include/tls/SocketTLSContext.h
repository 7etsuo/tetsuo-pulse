#ifndef SOCKETTLSCONTEXT_INCLUDED
#define SOCKETTLSCONTEXT_INCLUDED

#include "core/Arena.h"
#include "core/Except.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"

#if SOCKET_HAS_TLS

#include <openssl/ssl.h>      /* For SSL_VERIFY_* and X509_STORE_CTX */
#include <openssl/x509_vfy.h> /* For X509_STORE_CTX */

#define T SocketTLSContext_T
typedef struct T *T; /* Opaque pointer to TLS context */

/**
 * @file SocketTLSContext.h
 * @ingroup security
 * @brief TLS context management with secure defaults and certificate handling.
 *
 * Manages OpenSSL SSL_CTX objects with socket library integration. Provides
 * secure defaults (TLS1.3-only, modern ciphers), certificate loading, protocol
 * configuration, and session caching. Supports both client and server contexts
 * with Arena-based memory management for zero-leak operation.
 *
 * Features:
 * - TLS1.3-only enforcement for forward secrecy and security
 * - Modern cipher suites (ECDHE + AES-GCM/ChaCha20-Poly1305)
 * - Certificate verification with CA loading and hostname validation
 * - ALPN protocol negotiation support
 * - Session resumption via cache for performance
 * - Non-blocking compatible configuration
 * - Exception-based error handling with detailed OpenSSL error messages
 *
 * Thread safety: Contexts are not thread-safe for modification after creation.
 * Share read-only after full setup, or use per-thread contexts.
 * SSL objects created from context are per-connection and thread-safe.
 *
 * @see SocketTLSContext_new_server() for server context creation.
 * @see SocketTLSContext_new_client() for client context creation.
 * @see SocketTLS_enable() for applying TLS to sockets.
 * @see @ref SocketDTLSContext_T for DTLS context management on UDP sockets.
 * @see @ref SocketTLSConfig.h for TLS configuration constants.
 */

/* TLS context creation */
/**
 * @brief Create server TLS context with cert/key.
 * @ingroup security
 * @param cert_file Path to server certificate file (PEM format)
 * @param key_file Path to private key file (PEM format)
 * @param ca_file Optional path to CA file/directory for client auth (NULL to
 * disable)
 *
 * Creates a server-side TLS context, loads server cert/key, sets TLS1.3-only,
 * modern ciphers (ECDHE + AES-GCM/ChaCha20-Poly1305 for PFS), and optionally
 * CA for client verification. Security: Enforces TLS 1.3-only protocol;
 * disables renegotiation, compression, and legacy features; server cipher
 * preference; peer verification configurable; securely clears sensitive
 * keys/material on free.
 *
 * @return New opaque SocketTLSContext_T instance
 * @throws SocketTLS_Failed on OpenSSL errors, file I/O, or invalid cert/key
 * @see SocketTLSContext_free() for disposing the context.
 * @see SocketTLSContext_new_client() for client-side context.
 * @see SocketTLSContext_load_ca() for additional CA configuration.
 * @see SocketTLS_enable() to apply context to a socket.
 * @see @ref foundation for Arena-based memory management used internally.
 * @see @ref core_io "Socket" for base socket operations secured by TLS.
 * @threadsafe Yes - each call creates independent context
 */
extern T SocketTLSContext_new_server (const char *cert_file,
                                      const char *key_file,
                                      const char *ca_file);

/**
 * @brief Create client TLS context.
 * @ingroup security
 * @param ca_file Optional path to CA file/directory for server verification (NULL
 * to disable)
 *
 * Creates a client-side TLS context with TLS1.3-only and modern ciphers (ECDHE
 * + AES-GCM/ChaCha20-Poly1305). Loads CA if provided and enables peer
 * verification by default. Security: Enforces TLS 1.3-only protocol; disables
 * renegotiation and compression; warns on missing CA (MITM risk); peer
 * verification required; securely clears sensitive data on free.
 *
 * @return New opaque SocketTLSContext_T instance
 * @throws SocketTLS_Failed on OpenSSL errors or invalid CA
 * @see SocketTLSContext_free() for disposal.
 * @see SocketTLSContext_new_server() for server context.
 * @see SocketTLSContext_set_verify_mode() to adjust verification.
 * @see @ref security for other TLS security features like pinning and OCSP.
 * @threadsafe Yes
 */
extern T SocketTLSContext_new_client (const char *ca_file);

/**
 * @brief Create client TLS context with custom config.
 * @ingroup security
 * @param config Custom TLS configuration (or NULL for defaults)
 *
 * Creates a client-side TLS context with provided configuration.
 * If config NULL, uses secure defaults.
 *
 * @return New opaque SocketTLSContext_T instance
 * @throws SocketTLS_Failed on OpenSSL errors
 * @threadsafe Yes
 */
extern T SocketTLSContext_new (const SocketTLSConfig_T *config);

/* Certificate management */
/**
 * @brief Load server certificate and private key.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param cert_file Path to certificate file (PEM)
 * @param key_file Path to private key file (PEM)
 *
 * Loads and validates server certificate/private key pair. Verifies key
 * matches cert.
 *
 * @return void
 * @throws SocketTLS_Failed on file errors, format issues, or mismatch
 * @threadsafe Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_load_certificate (T ctx, const char *cert_file,
                                               const char *key_file);

/**
 * @brief Add certificate mapping for SNI virtual hosting.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param hostname Hostname this certificate is for (NULL for default certificate)
 * @param cert_file Certificate file path (PEM format)
 * @param key_file Private key file path (PEM format)
 *
 * Adds a certificate/key pair for SNI-based virtual hosting. Multiple
 * certificates can be loaded for different hostnames. The first certificate
 * loaded becomes the default if no hostname match is found.
 *
 * @return void
 * @throws SocketTLS_Failed on error (file not found, invalid cert/key,
 * allocation) @threadsafe No - modifies shared context
 */
extern void SocketTLSContext_add_certificate (T ctx, const char *hostname,
                                              const char *cert_file,
                                              const char *key_file);

/**
 * @brief Load trusted CA certificates.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param ca_file Path to CA file or directory containing PEM CA certs
 *
 * Loads CA certs for peer verification. Tries as file then directory.
 *
 * @return void
 * @throws SocketTLS_Failed on load errors
 * @threadsafe Yes (mutex protected)
 */
extern void SocketTLSContext_load_ca (T ctx, const char *ca_file);

/**
 * @brief Set certificate verification policy.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param mode Verification mode enum (TLS_VERIFY_NONE, PEER, etc.)
 *
 * Configures peer cert verification behavior, mapping to OpenSSL SSL_VERIFY_*
 * flags.
 *
 * @return void
 * @throws SocketTLS_Failed on invalid mode
 * @threadsafe Yes (mutex protected)
 */
extern void SocketTLSContext_set_verify_mode (T ctx, TLSVerifyMode mode);

/* Custom Verification Support */

/**
 * @brief User-defined certificate verification callback.
 * @ingroup security
 * @param preverify_ok OpenSSL pre-verification result (1=OK, 0=fail)
 * @param x509_ctx OpenSSL certificate store context (access cert chain via
 * X509_STORE_CTX_get_current_cert())
 * @param tls_ctx TLS context for shared configuration/data
 * @param socket Associated socket for connection-specific info (e.g., hostname)
 * @param user_data Opaque user data from SocketTLSContext_set_verify_callback
 *
 * Called during TLS verification to allow custom logic (e.g., pinning, policy
 * checks). Return 1 to accept/continue verification, 0 to fail (aborts
 * handshake). Can raise exceptions for detailed errors.
 */
typedef int (*SocketTLSVerifyCallback) (int preverify_ok,
                                        X509_STORE_CTX *x509_ctx, T tls_ctx,
                                        Socket_T socket, void *user_data);

/**
 * @brief Dispose of TLS context and resources.
 * @ingroup security
 * @param ctx_p Pointer to context pointer (set to NULL on success)
 *
 * Frees the SSL_CTX, Arena (internal allocations), SNI arrays/certs/keys, ALPN
 * data, and securely wipes sensitive material (e.g., session ticket keys via
 * OPENSSL_cleanse, pinning data via SocketCrypto_secure_clear). Caller must
 * not use context after free. Reverse of new_server/client. Security: Ensures
 * no residual sensitive data in memory; thread-safe but avoid concurrent
 * access.
 *
 * @return void
 * @throws None (safe for NULL)
 * @see SocketTLSContext_new_server(), SocketTLSContext_new_client(), SocketTLSContext_new() for context creation.
 * @see @ref foundation "Except_T" and Arena for exception and memory handling integrated here.
 * @threadsafe Yes (but avoid concurrent use)
 */
extern void SocketTLSContext_free (T *ctx_p);
/**
 * @brief Register custom verification callback.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param callback User callback function (NULL to disable custom and use default)
 * @param user_data Opaque data passed to callback (lifetime managed by caller)
 *
 * Sets a custom verification callback, overriding default OpenSSL behavior
 * while respecting current verify_mode. The wrapper ensures thread-safety and
 * error propagation via exceptions.
 *
 * @return void
 * @throws SocketTLS_Failed if OpenSSL configuration fails
 * @threadsafe Yes (mutex protected) - modifies shared context; call before sharing
 *
 * @see SocketTLSVerifyCallback for the callback function signature and usage.
 * @see SocketTLSContext_set_verify_mode() for configuring base verification policy.
 * @see @ref security for other TLS verification features like CRL and OCSP.
 */
extern void
SocketTLSContext_set_verify_callback (T ctx, SocketTLSVerifyCallback callback,
                                      void *user_data);

/**
 * @brief Load CRL file or directory into verification store.
 * @ingroup security
 * @param ctx TLS context instance
 * @param crl_path Path to CRL file (PEM/DER) or directory of CRL files (hashed
 * names)
 *
 * Loads CRL data into the context's X509_STORE for revocation checking during
 * peer verification. Supports single file or directory (auto-detect via stat).
 * Multiple calls append additional CRLs. Enables CRL_CHECK flags
 * automatically. CRL refresh not implemented (manual reload via re-call).
 *
 * @return void
 * @throws SocketTLS_Failed if load/path invalid or OpenSSL error
 * @threadsafe Yes (mutex protected) - modifies shared store; call during
 * setup Note: Effective only if verify_mode requires peer cert check
 * (PEER/FAIL_IF_NO_PEER)
 */
extern void SocketTLSContext_load_crl (T ctx, const char *crl_path);

/**
 * @brief Refresh a specific CRL (re-load).
 * @ingroup security
 * @param ctx TLS context
 * @param crl_path Path to refresh
 *
 * @brief Re-loads the CRL from path (appends to store). Use for periodic refresh.
 * For full store refresh, recreate context (CRLs accumulate).
 * @threadsafe Yes (mutex protected)
 * @throws SocketTLS_Failed on load error
 */
extern void SocketTLSContext_refresh_crl (T ctx, const char *crl_path);

/**
 * @brief Reload CRL from path (alias for refresh_crl).
 * @ingroup security
 * @param ctx TLS context
 * @param crl_path Path to CRL file or directory
 *
 * Reloads the CRL from the specified path. This is an alias for
 * SocketTLSContext_refresh_crl() provided for semantic clarity.
 * Use when you have downloaded an updated CRL and want to reload it.
 *
 * @threadsafe Yes (mutex protected)
 * @throws SocketTLS_Failed on load error
 */
extern void SocketTLSContext_reload_crl (T ctx, const char *crl_path);

/* ============================================================================
 * CRL Auto-Refresh Support
 * ============================================================================
 *
 * Automatic CRL refresh for long-running applications. The library will
 * attempt to reload the CRL file at the specified interval. A callback
 * notifies the application of success or failure.
 *
 * IMPORTANT: Auto-refresh requires the application to call
 * SocketTLSContext_crl_check_refresh() periodically (e.g., from event loop).
 * The library does not spawn background threads for refresh.
 *
 * Usage:
 *   SocketTLSContext_set_crl_auto_refresh(ctx, "/path/to/crl.pem",
 *                                          3600, my_callback, data);
 *   // In event loop:
 *   SocketTLSContext_crl_check_refresh(ctx);
 */

/**
 * @brief CRL refresh notification callback.
 * @ingroup security
 * @param ctx TLS context that was refreshed
 * @param path Path to CRL file
 * @param success 1 if refresh succeeded, 0 if failed
 * @param user_data User data from set_crl_auto_refresh
 *
 * Called after each refresh attempt. On failure, the old CRL remains
 * in effect. Application should log failures and potentially alert.
 */
typedef void (*SocketTLSCrlCallback) (T ctx, const char *path, int success,
                                      void *user_data);

/**
 * @brief Enable automatic CRL refresh.
 * @ingroup security
 * @param ctx TLS context instance
 * @param crl_path Path to CRL file (copied to context)
 * @param interval_seconds Refresh interval (minimum 60, 0 to disable)
 * @param callback Optional callback for refresh notifications (may be NULL)
 * @param user_data User data passed to callback
 *
 * Configures automatic CRL refresh. The CRL will be reloaded every
 * interval_seconds. Call SocketTLSContext_crl_check_refresh() from
 * your event loop to trigger scheduled refreshes.
 *
 * @return void
 * @throws SocketTLS_Failed on invalid parameters
 * @threadsafe Yes (mutex protected) - configure before sharing context
 */
extern void SocketTLSContext_set_crl_auto_refresh (
    T ctx, const char *crl_path, long interval_seconds,
    SocketTLSCrlCallback callback, void *user_data);

/**
 * @brief Disable automatic CRL refresh.
 * @ingroup security
 * @param ctx TLS context instance
 *
 * Cancels any configured automatic refresh. The current CRL remains loaded.
 *
 * @return void
 * @throws None
 * @threadsafe Yes (mutex protected)
 */
extern void SocketTLSContext_cancel_crl_auto_refresh (T ctx);

/**
 * @brief Check and perform CRL refresh if due.
 * @ingroup security
 * @param ctx TLS context instance
 *
 * Call this periodically from your event loop. If a refresh is scheduled
 * and due, it will reload the CRL and invoke the callback.
 *
 * @return 1 if refresh was performed, 0 if not due or not configured
 * @throws None (errors reported via callback)
 * @threadsafe Yes (mutex protected)
 */
extern int SocketTLSContext_crl_check_refresh (T ctx);

/**
 * @brief Get milliseconds until next refresh.
 * @ingroup security
 * @param ctx TLS context instance
 *
 * Returns time until next scheduled CRL refresh. Useful for setting
 * poll/select timeouts in event loops.
 *
 * @return -1 if disabled, 0 if due now/past, positive ms until next, LONG_MAX
 * if far future (overflow prot.) @throws None
 * @threadsafe Yes - read-only
 */
extern long SocketTLSContext_crl_next_refresh_ms (T ctx);

/* OCSP Stapling Support */

/**
 * @brief Set static OCSP response for stapling.
 * @ingroup security
 * (server)
 * @param ctx TLS context instance
 * @param response OCSP response bytes (DER encoded)
 * @param len Length of response
 *
 * Sets a static OCSP response to staple in server handshakes. Multiple calls
 * override. Validates basic response format.
 *
 * @return void
 * @throws SocketTLS_Failed if invalid response (len=0 or parse fail)
 * @threadsafe Yes (mutex protected)
 * Note: For dynamic, use set_ocsp_callback.
 */
extern void SocketTLSContext_set_ocsp_response (T ctx,
                                                const unsigned char *response,
                                                size_t len);

/**
 * @brief OCSP response generation callback for dynamic stapling on server-side TLS handshakes.
 * @ingroup security
 *
 * @param ssl OpenSSL SSL connection object during handshake.
 * @param arg User-provided data from SocketTLSContext_set_ocsp_gen_callback().
 *
 * This callback is invoked by OpenSSL during the TLS handshake when OCSP stapling is requested
 * by the client (via status_request extension). It should generate and return a valid,
 * DER-encoded OCSP response for the server's certificate, allowing the client to verify revocation
 * status without additional round-trips.
 *
 * Return a freshly allocated OCSP_RESPONSE* (OpenSSL takes ownership and frees it after use),
 * or NULL on error (no stapling provided, client may fallback or fail based on policy).
 *
 * Best practices:
 * - Use cached or freshly fetched OCSP from CA.
 * - Ensure response is not expired (clients reject old responses).
 * - Handle generation errors gracefully (log, return NULL).
 * - For performance, pre-generate responses or use short-lived cache.
 * - Support multiple certificates via SNI (check ssl->s3->tmp.cert or similar).
 *
 * Errors in generation do not abort handshake but may reduce security (no revocation check).
 *
 * @return OCSP_RESPONSE* (valid DER-encoded response, owned by OpenSSL) or NULL on failure.
 * @throws None - handle errors internally; use SocketLog for logging.
 * @threadsafe Conditional - must be reentrant/thread-safe if context shared across threads.
 *
 * @see SocketTLSContext_set_ocsp_gen_callback() to register and enable this callback.
 * @see SocketTLSContext_set_ocsp_response() for simpler static response configuration.
 * @see SocketTLS_get_ocsp_status() on client side to verify stapled response.
 * @see @ref security for broader TLS security features including CRL and pinning.
 * @see docs/SECURITY.md#ocsp-stapling for setup and troubleshooting.
 */
typedef OCSP_RESPONSE *(*SocketTLSOcspGenCallback) (SSL *ssl, void *arg);

/**
 * @brief Register dynamic OCSP response generator.
 * @ingroup security
 * @param ctx TLS context (server)
 * @param cb Callback to generate OCSP response during handshake
 * @param arg User data passed to cb
 *
 * Enables dynamic OCSP stapling. Called during handshake to generate response.
 * Wrapper handles serialization and SSL_set_tlsext_status_ocsp_resp.
 * @threadsafe cb must be; called in handshake thread.
 * @throws SocketTLS_Failed if OpenSSL cb set fails
 */
extern void
SocketTLSContext_set_ocsp_gen_callback (T ctx, SocketTLSOcspGenCallback cb,
                                        void *arg);

/**
 * @brief Get OCSP status after handshake (client).
 * @ingroup security
 * @param socket TLS socket with completed handshake
 *
 * Parses stapled OCSP response from server, validates, returns status.
 * Returns OCSP_STATUS_GOOD=1, REVOKED=2, UNKNOWN=3, NONE=0 if no response.
 * Caller can check for revocation.
 *
 * @return int (OCSP status code)
 * @throws None (returns error code on parse fail)
 * @threadsafe Yes (post-handshake)
 */
extern int SocketTLS_get_ocsp_status (Socket_T socket);

/**
 * @brief Enable OCSP stapling request (client).
 * @ingroup security
 * @param ctx TLS context instance (client only)
 *
 * Configures client context to request OCSP stapled responses from servers
 * during TLS handshake. After handshake, use SocketTLS_get_ocsp_status()
 * to check the stapled response.
 *
 * Note: This enables the STATUS_REQUEST TLS extension. The server must
 * support OCSP stapling and have a valid OCSP response configured.
 *
 * @return void
 * @throws SocketTLS_Failed if server context or OpenSSL error
 * @threadsafe Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_enable_ocsp_stapling (T ctx);

/**
 * @brief Check if OCSP stapling is enabled.
 * @ingroup security
 * @param ctx TLS context instance
 *
 * @return 1 if OCSP stapling request enabled, 0 otherwise
 * @throws None
 * @threadsafe Yes (read-only)
 */
extern int SocketTLSContext_ocsp_stapling_enabled (T ctx);

/* ============================================================================
 * Custom Certificate Store Callback
 * ============================================================================
 *
 * For advanced use cases where certificates are loaded from non-filesystem
 * sources (e.g., database, HSM, remote service).
 *
 * Usage:
 *   X509 *my_cert_lookup(X509_STORE_CTX *ctx, X509_NAME *name, void *data) {
 *       // Lookup certificate by subject name
 *       return load_cert_from_database(name);
 *   }
 *   SocketTLSContext_set_cert_lookup_callback(ctx, my_cert_lookup, db_conn);
 */

/**
 * @brief Custom certificate lookup function.
 * @ingroup security
 * @param store_ctx OpenSSL store context for current verification
 * @param name Subject name being looked up
 * @param user_data User data from set_cert_lookup_callback
 *
 * @return X509 certificate if found (caller takes ownership), NULL otherwise
 * @threadsafe Must be thread-safe if context is shared
 */
typedef X509 *(*SocketTLSCertLookupCallback) (X509_STORE_CTX *store_ctx,
                                              X509_NAME *name,
                                              void *user_data);

/**
 * @brief Register custom cert lookup.
 * @ingroup security
 * @param ctx TLS context instance
 * @param callback Lookup function (NULL to disable)
 * @param user_data User data passed to callback
 *
 * Sets a custom callback for certificate lookup during verification.
 * This allows loading certificates from databases, HSMs, or other sources
 * instead of the filesystem.
 *
 * Note: Requires OpenSSL 1.1.0+ for X509_STORE_set_lookup_certs_cb.
 *
 * @return void
 * @throws SocketTLS_Failed if not supported or OpenSSL error
 * @threadsafe Yes (mutex protected) - configure before sharing context
 */
extern void SocketTLSContext_set_cert_lookup_callback (
    T ctx, SocketTLSCertLookupCallback callback, void *user_data);

/* Protocol configuration */
/**
 * @brief Set minimum supported TLS version.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param version OpenSSL version constant (e.g., TLS1_3_VERSION)
 *
 * Sets min TLS version using set_min_proto_version() with fallback to options.
 *
 * @return void
 * @throws SocketTLS_Failed if cannot set
 * @threadsafe Yes (mutex protected)
 */
extern void SocketTLSContext_set_min_protocol (T ctx, int version);

/**
 * @brief Set maximum supported TLS version.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param version OpenSSL version constant (e.g., TLS1_3_VERSION)
 *
 * Sets max TLS version using set_max_proto_version().
 *
 * @return void
 * @throws SocketTLS_Failed if cannot set
 * @threadsafe Yes (mutex protected)
 */
extern void SocketTLSContext_set_max_protocol (T ctx, int version);

/**
 * @brief Set allowed cipher suites.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param ciphers Cipher list string in OpenSSL format, or NULL for defaults
 *
 * Configures allowed ciphers. Defaults to secure modern list if NULL.
 *
 * @return void
 * @throws SocketTLS_Failed if invalid list
 * @threadsafe Yes (mutex protected)
 */
extern void SocketTLSContext_set_cipher_list (T ctx, const char *ciphers);

/* ALPN support */
/**
 * @brief Advertise ALPN protocols.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param protos Array of null-terminated protocol strings (e.g., "h2", "http/1.1")
 * @param count Number of protocols
 *
 * Sets list of supported ALPN protocols in wire format, allocated from context
 * arena. Validates lengths (1-255 bytes per protocol, max
 * SOCKET_TLS_MAX_ALPN_PROTOCOLS) and contents (full RFC 7301 Section 3.2:
 * printable ASCII 0x21-0x7E only, rejects invalid lists/entries). Invalid
 * names raise SocketTLS_Failed. Uses SocketSecurity limits at runtime.
 *
 * @return void
 * @throws SocketTLS_Failed on invalid protos or allocation error
 * @threadsafe Yes (mutex protected)
 *
 * Note: Protocols advertised in preference order (first preferred).
 */
extern void SocketTLSContext_set_alpn_protos (T ctx, const char **protos,
                                              size_t count);

/* ALPN callback type for customizable protocol selection */
typedef const char *(*SocketTLSAlpnCallback) (const char **client_protos,
                                              size_t client_count,
                                              void *user_data);

/**
 * @brief Set custom ALPN protocol selection callback.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param callback Function to call for ALPN protocol selection
 * @param user_data User data passed to callback function
 *
 * Sets a custom callback for ALPN protocol selection instead of using default
 * priority order. The callback receives parsed and validated client-offered
 * protocols (library rejects malformed lists per RFC 7301 Section 3.2). Return
 * a const char* to a persistent matching protocol string or NULL to decline.
 * Library validates return (must match offered list, valid length/chars),
 * internally allocates a copy for OpenSSL (avoids UAF if returning temporary
 * ptr), and uses it during handshake.
 *
 * @return void
 * @throws SocketTLS_Failed on invalid parameters
 * @threadsafe Yes (mutex protected)
 *
 * Note: Callback is called during TLS handshake, must be thread-safe if
 * context is shared.
 */
extern void SocketTLSContext_set_alpn_callback (T ctx,
                                                SocketTLSAlpnCallback callback,
                                                void *user_data);

/* Session management */
/**
 * @brief Enable session caching.
 * @ingroup security
 * infrastructure
 * @param ctx The TLS context instance
 * @param max_sessions Maximum number of sessions to cache (>0), 0 for default
 * @param timeout_seconds Session timeout in seconds, 0 for OpenSSL default (300s)
 *
 * Extends `SocketTLSContext_T` with session cache configuration.
 * Implements session cache using OpenSSL's built-in caching with thread-safe
 * storage. Adds cache size and timeout configuration. Enables statistics
 * tracking.
 *
 * @return void
 * @throws SocketTLS_Failed if cannot enable or configure
 * @threadsafe Yes (mutex protected) - modifies shared context during setup
 */
extern void SocketTLSContext_enable_session_cache (T ctx, size_t max_sessions,
                                                   long timeout_seconds);

/**
 * @brief Limit cached sessions.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param size Max number of sessions to cache (>0)
 *
 * Controls memory usage of session cache.
 *
 * @return void
 * @throws SocketTLS_Failed if invalid size or cannot set
 * @threadsafe Yes (mutex protected)
 */
extern void SocketTLSContext_set_session_cache_size (T ctx, size_t size);

/**
 * @brief Get session cache statistics.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param hits Output: number of cache hits
 * @param misses Output: number of cache misses
 * @param stores Output: number of sessions stored
 *
 * Fills provided pointers with current session cache statistics.
 * Statistics are thread-safe and cumulative since cache enable.
 * If pointers NULL, skipped.
 *
 * @return void
 * @throws None
 * @threadsafe Yes
 */
extern void SocketTLSContext_get_cache_stats (T ctx, size_t *hits,
                                              size_t *misses, size_t *stores);

/**
 * @brief Enable stateless session.
 * @ingroup security
 * resumption using tickets
 * @param ctx The TLS context instance
 * @param key Ticket encryption key material (SOCKET_TLS_TICKET_KEY_LEN bytes
 * required)
 * @param key_len Length of key (must be SOCKET_TLS_TICKET_KEY_LEN = 80 bytes)
 *
 * Implements stateless session resumption using encrypted session tickets.
 * OpenSSL requires 80 bytes: 16 (name) + 32 (AES) + 32 (HMAC).
 * Configures ticket key management, encryption/decryption using provided key.
 * Supports ticket lifetime matching session timeout, and basic rotation.
 * Requires cache enabled for full effect.
 *
 * @return void
 * @throws SocketTLS_Failed if invalid key length or OpenSSL config fails
 * @threadsafe Yes (mutex protected)
 */
extern void SocketTLSContext_enable_session_tickets (T ctx,
                                                     const unsigned char *key,
                                                     size_t key_len);

/* ============================================================================
 * Certificate Pinning (SPKI SHA256)
 * ============================================================================
 *
 * OWASP-recommended approach: Pin the Subject Public Key Info (SPKI) hash.
 * SPKI pinning survives certificate renewal when the same key is reused,
 * making it more maintainable than full certificate pinning.
 *
 * Usage:
 *   // Create client context
 *   SocketTLSContext_T ctx = SocketTLSContext_new_client("ca-bundle.pem");
 *
 *   // Pin by hex-encoded SHA256 hash
 *   SocketTLSContext_add_pin_hex(ctx,
 *     "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c");
 *
 *   // Or extract from certificate file
 *   SocketTLSContext_add_pin_from_cert(ctx, "server.crt");
 *
 *   // Enable strict enforcement (default, fail if no match)
 *   SocketTLSContext_set_pin_enforcement(ctx, 1);
 *
 * Generate pin from certificate:
 *   openssl x509 -in cert.pem -pubkey -noout | \
 *     openssl pkey -pubin -outform DER | \
 *     openssl dgst -sha256 -hex
 *
 * Thread safety: Pin configuration is NOT thread-safe. Configure all pins
 * before sharing the context across threads. Verification is read-only
 * and thread-safe.
 */

/**
 * @brief Add SPKI SHA256 pin (binary format).
 * @ingroup security
 * @param ctx The TLS context instance
 * @param sha256_hash 32-byte SHA256 hash of the SPKI DER encoding
 *
 * Adds a certificate pin using raw binary hash. The hash is copied to
 * context-owned storage. Duplicate pins are silently ignored.
 *
 * @return void
 * @throws SocketTLS_Failed if hash is NULL or max pins exceeded
 * @see SocketTLS_PinVerifyFailed for the exception raised on mismatch.
 * @see SocketTLSContext_add_pin_hex() for hex-encoded input.
 * @see SocketTLSContext_add_pin_from_cert() to generate from file.
 * @see SocketTLSContext_set_pin_enforcement() to control failure behavior.
 * @threadsafe Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_add_pin (T ctx, const unsigned char *sha256_hash);

/**
 * @brief Add SPKI SHA256 pin (hex string).
 * @ingroup security
 * @param ctx The TLS context instance
 * @param hex_hash 64-character hex string (optionally prefixed with "sha256//")
 *
 * Adds a certificate pin using hex-encoded hash. Accepts both uppercase
 * and lowercase hex. Optional "sha256//" prefix is stripped for HPKP
 * compatibility.
 *
 * @return void
 * @throws SocketTLS_Failed if format invalid or max pins exceeded
 * @threadsafe Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_add_pin_hex (T ctx, const char *hex_hash);

/**
 * @brief Extract and add pin from certificate.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param cert_file Path to PEM-encoded certificate file
 *
 * Loads certificate, extracts SPKI, computes SHA256, and adds as pin.
 * Useful for pinning leaf certificates or intermediate CAs.
 *
 * @return void
 * @throws SocketTLS_Failed if file invalid, parse error, or max pins exceeded
 * @threadsafe Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_add_pin_from_cert (T ctx, const char *cert_file);

/**
 * @brief Add pin from X509 certificate object.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param cert OpenSSL X509 certificate object
 *
 * Extracts SPKI hash from provided X509 and adds as pin. The certificate
 * is not freed by this function; caller retains ownership.
 *
 * @return void
 * @throws SocketTLS_Failed if cert NULL, extraction fails, or max exceeded
 * @threadsafe Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_add_pin_from_x509 (T ctx, const X509 *cert);

/**
 * @brief Remove all certificate pins.
 * @ingroup security
 * @param ctx The TLS context instance
 *
 * Securely clears all configured pins. Memory is zeroed before release.
 * Pin enforcement mode is preserved.
 *
 * @return void
 * @throws None
 * @threadsafe Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_clear_pins (T ctx);

/**
 * @brief Set pin enforcement mode.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param enforce 1 = strict (fail on mismatch), 0 = warn only
 *
 * Controls behavior when no pin matches during verification:
 * - enforce=1 (default): Handshake fails with
 * X509_V_ERR_APPLICATION_VERIFICATION
 * - enforce=0: Verification continues, mismatch is logged
 *
 * @return void
 * @throws None
 * @threadsafe Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_set_pin_enforcement (T ctx, int enforce);

/**
 * @brief Get current enforcement mode.
 * @ingroup security
 * @param ctx The TLS context instance
 *
 * @return 1 if strict enforcement, 0 if warn-only
 * @throws None
 * @threadsafe Yes (read-only)
 */
extern int SocketTLSContext_get_pin_enforcement (T ctx);

/**
 * @brief Get number of configured pins.
 * @ingroup security
 * @param ctx The TLS context instance
 *
 * @return Number of pins currently configured
 * @throws None
 * @threadsafe Yes (read-only)
 */
extern size_t SocketTLSContext_get_pin_count (T ctx);

/**
 * @brief Check if any pins are configured.
 * @ingroup security
 * @param ctx The TLS context instance
 *
 * @return 1 if pins configured, 0 if none
 * @throws None
 * @threadsafe Yes (read-only)
 */
extern int SocketTLSContext_has_pins (T ctx);

/**
 * @brief Check if hash matches any pin.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param sha256_hash 32-byte hash to check
 *
 * Manual verification without full handshake. Useful for testing
 * or custom verification logic.
 *
 * @return 1 if match found, 0 if no match
 * @throws None
 * @threadsafe Yes (read-only)
 */
extern int SocketTLSContext_verify_pin (T ctx,
                                        const unsigned char *sha256_hash);

/**
 * @brief Check if certificate matches any pin.
 * @ingroup security
 * @param ctx The TLS context instance
 * @param cert X509 certificate to verify
 *
 * Extracts SPKI hash from certificate and checks against pins.
 * Useful for manual chain verification.
 *
 * @return 1 if match found, 0 if no match
 * @throws None
 * @threadsafe Yes (read-only)
 */
extern int SocketTLSContext_verify_cert_pin (T ctx, const X509 *cert);

/* Pinning exception type */
/**
 * @brief Exception raised when certificate pin verification fails during TLS handshake or manual check.
 * @ingroup security
 *
 * Thrown by pin verification functions when no configured SPKI hash matches the peer certificate's public key.
 * Indicates potential man-in-the-middle attack or misconfiguration.
 *
 * @see SocketTLSContext_add_pin() for adding pins.
 * @see SocketTLSContext_set_pin_enforcement() for enforcement mode.
 * @see SocketTLSContext_verify_pin() for manual checks.
 * @see @ref foundation for exception handling with Except_T.
 */
extern const Except_T SocketTLS_PinVerifyFailed;

/* ============================================================================
 * Certificate Transparency (RFC 6962)
 * ============================================================================
 *
 * CT helps detect mis-issued certificates by requiring them to be logged
 * in publicly auditable CT logs. Clients verify Signed Certificate
 * Timestamps (SCTs) embedded in certificates, TLS extensions, or OCSP.
 *
 * Requires OpenSSL 1.1.0+ with CT support compiled in.
 *
 * Usage:
 *   SocketTLSContext_T ctx = SocketTLSContext_new_client("ca-bundle.pem");
 *   SocketTLSContext_enable_ct(ctx, CT_VALIDATION_STRICT);
 *   // ... connections will require valid SCTs
 *
 * Thread safety: Configuration is NOT thread-safe - perform before sharing.
 */

/**
 * @brief Certificate Transparency validation mode enumeration.
 * @ingroup security
 *
 * Controls how Certificate Transparency (RFC 6962) Signed Certificate
 * Timestamps (SCTs) are validated during TLS handshake.
 */
typedef enum
{
  CT_VALIDATION_PERMISSIVE = 0, /**< Log missing SCTs but don't fail handshake */
  CT_VALIDATION_STRICT = 1      /**< Require valid SCTs, fail handshake otherwise */
} CTValidationMode;

/**
 * @brief Enable Certificate Transparency verification.
 * @ingroup security
 * @param ctx The TLS context instance (client only)
 * @param mode Validation mode (strict or permissive)
 *
 * Enables CT verification for client connections. In strict mode,
 * connections fail if no valid SCTs are present. In permissive mode,
 * missing SCTs are logged but don't cause failure.
 *
 * @return void
 * @throws SocketTLS_Failed if CT not supported or server context
 * @threadsafe Yes (mutex protected) - modifies shared context
 * @ingroup security
 */
extern void SocketTLSContext_enable_ct (T ctx, CTValidationMode mode);

/**
 * @brief Check if CT verification is enabled.
 * @ingroup security
 * @param ctx The TLS context instance
 *
 * @return 1 if CT enabled, 0 if disabled
 * @throws None
 * @threadsafe Yes (read-only)
 */
extern int SocketTLSContext_ct_enabled (T ctx);

/**
 * @brief Get current CT validation mode.
 * @ingroup security
 * @param ctx The TLS context instance
 *
 * @return CT validation mode (strict or permissive) if enabled, or
 * CT_VALIDATION_PERMISSIVE if disabled @throws None
 * @threadsafe Yes - read-only
 * (read-only)
 */
extern CTValidationMode SocketTLSContext_get_ct_mode (T ctx);

/**
 * @brief Load custom CT log list.
 * @ingroup security
 * @param ctx The TLS context instance (client only)
 * @param log_file Path to CT log list file (OpenSSL format)
 *
 * Loads a custom list of trusted CT logs from file, overriding OpenSSL
 * defaults. Validates file path and format. Call before enable_ct for effect.
 *
 * @return void
 * @throws SocketTLS_Failed if file invalid, load fails, or server context
 * @threadsafe No (config phase only)
 */
extern void SocketTLSContext_set_ctlog_list_file (T ctx, const char *log_file);

/* Internal functions (not part of public API) */
/**
 * @brief Get underlying OpenSSL SSL_CTX*.
 * @ingroup security
 * @param ctx The TLS context instance
 *
 * Internal access to raw SSL_CTX for SocketTLS_enable() etc.
 *
 * @return void* to SSL_CTX (cast as needed)
 * @throws None
 * @threadsafe Yes
 */
extern void *SocketTLSContext_get_ssl_ctx (T ctx);

/**
 * @brief Check if context is server-mode.
 * @ingroup security
 * @param ctx The TLS context instance
 *
 * Internal helper to determine client vs server configuration.
 *
 * @return 1 if server, 0 if client
 * @throws None
 * @threadsafe Yes
 */
extern int SocketTLSContext_is_server (T ctx);

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLSCONTEXT_INCLUDED */
