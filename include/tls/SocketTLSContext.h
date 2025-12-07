#ifndef SOCKETTLSCONTEXT_INCLUDED
#define SOCKETTLSCONTEXT_INCLUDED

#include "core/Arena.h"
#include "core/Except.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"

#if SOCKET_HAS_TLS

#include <openssl/ssl.h>  /* For SSL_VERIFY_* and X509_STORE_CTX */
#include <openssl/x509_vfy.h>  /* For X509_STORE_CTX */

#define T SocketTLSContext_T
typedef struct T *T; /* Opaque pointer to TLS context */



/**
 * SocketTLSContext - TLS Context Management Module
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
 * Usage:
 *   // Server context
 *   SocketTLSContext_T server_ctx = SocketTLSContext_new_server("server.crt",
 * "server.key", "ca-bundle.pem"); SocketTLSContext_set_alpn_protos(server_ctx,
 * (const char*[]){"h2", "http/1.1"}, 2);
 *   SocketTLSContext_enable_session_cache(server_ctx, SOCKET_TLS_SESSION_CACHE_SIZE, 300);
 *
 *   // Client context
 *   SocketTLSContext_T client_ctx =
 * SocketTLSContext_new_client("ca-bundle.pem");
 *   SocketTLSContext_set_verify_mode(client_ctx, TLS_VERIFY_PEER);
 *
 * Thread safety: Contexts are not thread-safe for modification after creation.
 * Share read-only after full setup, or use per-thread contexts.
 * SSL objects created from context are per-connection and thread-safe for
 * their lifetime.
 */

/* TLS context creation */
/**
 * SocketTLSContext_new_server - Create server TLS context with cert/key
 * loading
 * @cert_file: Path to server certificate file (PEM format)
 * @key_file: Path to private key file (PEM format)
 * @ca_file: Optional path to CA file/directory for client auth (NULL to
 * disable)
 *
 * Creates a server-side TLS context, loads server cert/key, sets TLS1.3-only,
 * modern ciphers (ECDHE + AES-GCM/ChaCha20-Poly1305 for PFS), and optionally CA for client verification.
 * Security: Enforces TLS 1.3-only protocol; disables renegotiation, compression, and legacy features;
 * server cipher preference; peer verification configurable; securely clears sensitive keys/material on free.
 *
 * Returns: New opaque SocketTLSContext_T instance
 * Raises: SocketTLS_Failed on OpenSSL errors, file I/O, or invalid cert/key
 * Thread-safe: Yes - each call creates independent context
 */
extern T SocketTLSContext_new_server (const char *cert_file,
                                      const char *key_file,
                                      const char *ca_file);

/**
 * SocketTLSContext_new_client - Create client TLS context
 * @ca_file: Optional path to CA file/directory for server verification (NULL
 * to disable)
 *
 * Creates a client-side TLS context with TLS1.3-only and modern ciphers (ECDHE + AES-GCM/ChaCha20-Poly1305).
 * Loads CA if provided and enables peer verification by default.
 * Security: Enforces TLS 1.3-only protocol; disables renegotiation and compression; warns on missing CA (MITM risk);
 * peer verification required; securely clears sensitive data on free.
 *
 * Returns: New opaque SocketTLSContext_T instance
 * Raises: SocketTLS_Failed on OpenSSL errors or invalid CA
 * Thread-safe: Yes
 */
extern T SocketTLSContext_new_client (const char *ca_file);

/**
 * SocketTLSContext_new - Create client TLS context with custom config
 * @config: Custom TLS configuration (or NULL for defaults)
 *
 * Creates a client-side TLS context with provided configuration.
 * If config NULL, uses secure defaults.
 *
 * Returns: New opaque SocketTLSContext_T instance
 * Raises: SocketTLS_Failed on OpenSSL errors
 * Thread-safe: Yes
 */
extern T SocketTLSContext_new (const SocketTLSConfig_T *config);

/* Certificate management */
/**
 * SocketTLSContext_load_certificate - Load server certificate and private key
 * @ctx: The TLS context instance
 * @cert_file: Path to certificate file (PEM)
 * @key_file: Path to private key file (PEM)
 *
 * Loads and validates server certificate/private key pair. Verifies key
 * matches cert.
 *
 * Returns: void
 * Raises: SocketTLS_Failed on file errors, format issues, or mismatch
 * Thread-safe: Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_load_certificate (T ctx, const char *cert_file,
                                               const char *key_file);

/**
 * SocketTLSContext_add_certificate - Add certificate mapping for SNI virtual
 * hosting
 * @ctx: The TLS context instance
 * @hostname: Hostname this certificate is for (NULL for default certificate)
 * @cert_file: Certificate file path (PEM format)
 * @key_file: Private key file path (PEM format)
 *
 * Adds a certificate/key pair for SNI-based virtual hosting. Multiple
 * certificates can be loaded for different hostnames. The first certificate
 * loaded becomes the default if no hostname match is found.
 *
 * Returns: void
 * Raises: SocketTLS_Failed on error (file not found, invalid cert/key,
 * allocation) Thread-safe: No (modifies shared context)
 */
extern void SocketTLSContext_add_certificate (T ctx, const char *hostname,
                                              const char *cert_file,
                                              const char *key_file);

/**
 * SocketTLSContext_load_ca - Load trusted CA certificates
 * @ctx: The TLS context instance
 * @ca_file: Path to CA file or directory containing PEM CA certs
 *
 * Loads CA certs for peer verification. Tries as file then directory.
 *
 * Returns: void
 * Raises: SocketTLS_Failed on load errors
 * Thread-safe: Yes (mutex protected)
 */
extern void SocketTLSContext_load_ca (T ctx, const char *ca_file);

/**
 * SocketTLSContext_set_verify_mode - Set certificate verification policy
 * @ctx: The TLS context instance
 * @mode: Verification mode enum (TLS_VERIFY_NONE, PEER, etc.)
 *
 * Configures peer cert verification behavior, mapping to OpenSSL SSL_VERIFY_*
 * flags.
 *
 * Returns: void
 * Raises: SocketTLS_Failed on invalid mode
 * Thread-safe: Yes (mutex protected)
 */
extern void SocketTLSContext_set_verify_mode (T ctx, TLSVerifyMode mode);

/* Custom Verification Support */

/**
 * SocketTLSVerifyCallback - User-defined certificate verification callback
 * @preverify_ok: OpenSSL pre-verification result (1=OK, 0=fail)
 * @x509_ctx: OpenSSL certificate store context (access cert chain via X509_STORE_CTX_get_current_cert())
 * @tls_ctx: TLS context for shared configuration/data
 * @socket: Associated socket for connection-specific info (e.g., hostname)
 * @user_data: Opaque user data from SocketTLSContext_set_verify_callback
 *
 * Called during TLS verification to allow custom logic (e.g., pinning, policy checks).
 * Return 1 to accept/continue verification, 0 to fail (aborts handshake).
 * Can raise exceptions for detailed errors.
 */
typedef int (*SocketTLSVerifyCallback)(int preverify_ok, X509_STORE_CTX *x509_ctx,
                                       T tls_ctx, Socket_T socket, void *user_data);

/**
 * SocketTLSContext_set_verify_callback - Register custom verification callback
 * @ctx: The TLS context instance
 * @callback: User callback function (NULL to disable custom and use default)
 * @user_data: Opaque data passed to callback (lifetime managed by caller)
 *
 * Sets a custom verification callback, overriding default OpenSSL behavior while
 * respecting current verify_mode. The wrapper ensures thread-safety and error
 * propagation via exceptions.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if OpenSSL configuration fails
 * Thread-safe: Yes (mutex protected) (modifies shared context; call before sharing)
 */

/**
 * SocketTLSContext_free - Dispose of TLS context and resources
 * @ctx_p: Pointer to context pointer (set to NULL on success)
 *
 * Frees the SSL_CTX, Arena (internal allocations), SNI arrays/certs/keys, ALPN data, and securely wipes
 * sensitive material (e.g., session ticket keys via OPENSSL_cleanse, pinning data via SocketCrypto_secure_clear).
 * Caller must not use context after free. Reverse of new_server/client.
 * Security: Ensures no residual sensitive data in memory; thread-safe but avoid concurrent access.
 *
 * Returns: void
 * Raises: None (safe for NULL)
 * Thread-safe: Yes (but avoid concurrent use)
 */
extern void SocketTLSContext_free (T *ctx_p);
extern void SocketTLSContext_set_verify_callback(T ctx, SocketTLSVerifyCallback callback, void *user_data);

/**
 * SocketTLSContext_load_crl - Load CRL file or directory into verification store
 * @ctx: TLS context instance
 * @crl_path: Path to CRL file (PEM/DER) or directory of CRL files (hashed names)
 *
 * Loads CRL data into the context's X509_STORE for revocation checking during peer
 * verification. Supports single file or directory (auto-detect via stat). Multiple
 * calls append additional CRLs. Enables CRL_CHECK flags automatically.
 * CRL refresh not implemented (manual reload via re-call).
 *
 * Returns: void
 * Raises: SocketTLS_Failed if load/path invalid or OpenSSL error
 * Thread-safe: Yes (mutex protected) - modifies shared store; call during setup
 * Note: Effective only if verify_mode requires peer cert check (PEER/FAIL_IF_NO_PEER)
 */
extern void SocketTLSContext_load_crl(T ctx, const char *crl_path);

/**
 * SocketTLSContext_refresh_crl - Refresh a specific CRL (re-load)
 * @ctx: TLS context
 * @crl_path: Path to refresh
 *
 * Re-loads the CRL from path (appends to store). Use for periodic refresh.
 * For full store refresh, recreate context (CRLs accumulate).
 * Thread-safe: Yes (mutex protected)
 * Raises: SocketTLS_Failed on load error
 */
extern void SocketTLSContext_refresh_crl(T ctx, const char *crl_path);

/**
 * SocketTLSContext_reload_crl - Reload CRL from path (alias for refresh_crl)
 * @ctx: TLS context
 * @crl_path: Path to CRL file or directory
 *
 * Reloads the CRL from the specified path. This is an alias for
 * SocketTLSContext_refresh_crl() provided for semantic clarity.
 * Use when you have downloaded an updated CRL and want to reload it.
 *
 * Thread-safe: Yes (mutex protected)
 * Raises: SocketTLS_Failed on load error
 */
extern void SocketTLSContext_reload_crl(T ctx, const char *crl_path);

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
 * SocketTLSCrlCallback - CRL refresh notification callback
 * @ctx: TLS context that was refreshed
 * @path: Path to CRL file
 * @success: 1 if refresh succeeded, 0 if failed
 * @user_data: User data from set_crl_auto_refresh
 *
 * Called after each refresh attempt. On failure, the old CRL remains
 * in effect. Application should log failures and potentially alert.
 */
typedef void (*SocketTLSCrlCallback)(T ctx, const char *path, 
                                      int success, void *user_data);

/**
 * SocketTLSContext_set_crl_auto_refresh - Enable automatic CRL refresh
 * @ctx: TLS context instance
 * @crl_path: Path to CRL file (copied to context)
 * @interval_seconds: Refresh interval (minimum 60, 0 to disable)
 * @callback: Optional callback for refresh notifications (may be NULL)
 * @user_data: User data passed to callback
 *
 * Configures automatic CRL refresh. The CRL will be reloaded every
 * interval_seconds. Call SocketTLSContext_crl_check_refresh() from
 * your event loop to trigger scheduled refreshes.
 *
 * Returns: void
 * Raises: SocketTLS_Failed on invalid parameters
 * Thread-safe: Yes (mutex protected) - configure before sharing context
 */
extern void SocketTLSContext_set_crl_auto_refresh(T ctx, const char *crl_path,
                                                   long interval_seconds,
                                                   SocketTLSCrlCallback callback,
                                                   void *user_data);

/**
 * SocketTLSContext_cancel_crl_auto_refresh - Disable automatic CRL refresh
 * @ctx: TLS context instance
 *
 * Cancels any configured automatic refresh. The current CRL remains loaded.
 *
 * Returns: void
 * Raises: None
 * Thread-safe: Yes (mutex protected)
 */
extern void SocketTLSContext_cancel_crl_auto_refresh(T ctx);

/**
 * SocketTLSContext_crl_check_refresh - Check and perform CRL refresh if due
 * @ctx: TLS context instance
 *
 * Call this periodically from your event loop. If a refresh is scheduled
 * and due, it will reload the CRL and invoke the callback.
 *
 * Returns: 1 if refresh was performed, 0 if not due or not configured
 * Raises: None (errors reported via callback)
 * Thread-safe: Yes (mutex protected)
 */
extern int SocketTLSContext_crl_check_refresh(T ctx);

/**
 * SocketTLSContext_crl_next_refresh_ms - Get milliseconds until next refresh
 * @ctx: TLS context instance
 *
 * Returns time until next scheduled CRL refresh. Useful for setting
 * poll/select timeouts in event loops.
 *
 * Returns: -1 if disabled, 0 if due now/past, positive ms until next, LONG_MAX if far future (overflow prot.)
 * Raises: None
 * Thread-safe: Yes (read-only)
 */
extern long SocketTLSContext_crl_next_refresh_ms(T ctx);

/* OCSP Stapling Support */

/**
 * SocketTLSContext_set_ocsp_response - Set static OCSP response for stapling (server)
 * @ctx: TLS context instance
 * @response: OCSP response bytes (DER encoded)
 * @len: Length of response
 *
 * Sets a static OCSP response to staple in server handshakes. Multiple calls override.
 * Validates basic response format.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if invalid response (len=0 or parse fail)
 * Thread-safe: Yes (mutex protected)
 * Note: For dynamic, use set_ocsp_callback.
 */
extern void SocketTLSContext_set_ocsp_response(T ctx, const unsigned char *response, size_t len);

/* OCSP generation callback for dynamic stapling (server) */
typedef OCSP_RESPONSE *(*SocketTLSOcspGenCallback)(SSL *ssl, void *arg);

/**
 * SocketTLSContext_set_ocsp_gen_callback - Register dynamic OCSP response generator
 * @ctx: TLS context (server)
 * @cb: Callback to generate OCSP response during handshake
 * @arg: User data passed to cb
 *
 * Enables dynamic OCSP stapling. Called during handshake to generate response.
 * Wrapper handles serialization and SSL_set_tlsext_status_ocsp_resp.
 * Thread-safe: cb must be; called in handshake thread.
 * Raises: SocketTLS_Failed if OpenSSL cb set fails
 */
extern void SocketTLSContext_set_ocsp_gen_callback(T ctx, SocketTLSOcspGenCallback cb, void *arg);

/**
 * SocketTLS_get_ocsp_status - Get OCSP status after handshake (client)
 * @socket: TLS socket with completed handshake
 *
 * Parses stapled OCSP response from server, validates, returns status.
 * Returns OCSP_STATUS_GOOD=1, REVOKED=2, UNKNOWN=3, NONE=0 if no response.
 * Caller can check for revocation.
 *
 * Returns: int (OCSP status code)
 * Raises: None (returns error code on parse fail)
 * Thread-safe: Yes (post-handshake)
 */
extern int SocketTLS_get_ocsp_status(Socket_T socket);

/**
 * SocketTLSContext_enable_ocsp_stapling - Enable OCSP stapling request (client)
 * @ctx: TLS context instance (client only)
 *
 * Configures client context to request OCSP stapled responses from servers
 * during TLS handshake. After handshake, use SocketTLS_get_ocsp_status()
 * to check the stapled response.
 *
 * Note: This enables the STATUS_REQUEST TLS extension. The server must
 * support OCSP stapling and have a valid OCSP response configured.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if server context or OpenSSL error
 * Thread-safe: Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_enable_ocsp_stapling(T ctx);

/**
 * SocketTLSContext_ocsp_stapling_enabled - Check if OCSP stapling is enabled
 * @ctx: TLS context instance
 *
 * Returns: 1 if OCSP stapling request enabled, 0 otherwise
 * Raises: None
 * Thread-safe: Yes (read-only)
 */
extern int SocketTLSContext_ocsp_stapling_enabled(T ctx);

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
 * SocketTLSCertLookupCallback - Custom certificate lookup function
 * @store_ctx: OpenSSL store context for current verification
 * @name: Subject name being looked up
 * @user_data: User data from set_cert_lookup_callback
 *
 * Returns: X509 certificate if found (caller takes ownership), NULL otherwise
 * Thread-safe: Must be thread-safe if context is shared
 */
typedef X509 *(*SocketTLSCertLookupCallback)(X509_STORE_CTX *store_ctx,
                                              X509_NAME *name, 
                                              void *user_data);

/**
 * SocketTLSContext_set_cert_lookup_callback - Register custom cert lookup
 * @ctx: TLS context instance
 * @callback: Lookup function (NULL to disable)
 * @user_data: User data passed to callback
 *
 * Sets a custom callback for certificate lookup during verification.
 * This allows loading certificates from databases, HSMs, or other sources
 * instead of the filesystem.
 *
 * Note: Requires OpenSSL 1.1.0+ for X509_STORE_set_lookup_certs_cb.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if not supported or OpenSSL error
 * Thread-safe: Yes (mutex protected) - configure before sharing context
 */
extern void SocketTLSContext_set_cert_lookup_callback(T ctx,
                                                       SocketTLSCertLookupCallback callback,
                                                       void *user_data);

/* Protocol configuration */
/**
 * SocketTLSContext_set_min_protocol - Set minimum supported TLS version
 * @ctx: The TLS context instance
 * @version: OpenSSL version constant (e.g., TLS1_3_VERSION)
 *
 * Sets min TLS version using set_min_proto_version() with fallback to options.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if cannot set
 * Thread-safe: Yes (mutex protected)
 */
extern void SocketTLSContext_set_min_protocol (T ctx, int version);

/**
 * SocketTLSContext_set_max_protocol - Set maximum supported TLS version
 * @ctx: The TLS context instance
 * @version: OpenSSL version constant (e.g., TLS1_3_VERSION)
 *
 * Sets max TLS version using set_max_proto_version().
 *
 * Returns: void
 * Raises: SocketTLS_Failed if cannot set
 * Thread-safe: Yes (mutex protected)
 */
extern void SocketTLSContext_set_max_protocol (T ctx, int version);

/**
 * SocketTLSContext_set_cipher_list - Set allowed cipher suites
 * @ctx: The TLS context instance
 * @ciphers: Cipher list string in OpenSSL format, or NULL for defaults
 *
 * Configures allowed ciphers. Defaults to secure modern list if NULL.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if invalid list
 * Thread-safe: Yes (mutex protected)
 */
extern void SocketTLSContext_set_cipher_list (T ctx, const char *ciphers);

/* ALPN support */
/**
 * SocketTLSContext_set_alpn_protos - Advertise ALPN protocols
 * @ctx: The TLS context instance
 * @protos: Array of null-terminated protocol strings (e.g., "h2", "http/1.1")
 * @count: Number of protocols
 *
 * Sets list of supported ALPN protocols in wire format, allocated from context
 * arena. Validates lengths (1-255 bytes per protocol, max SOCKET_TLS_MAX_ALPN_PROTOCOLS) and contents
 * (full RFC 7301 Section 3.2: printable ASCII 0x21-0x7E only, rejects invalid lists/entries).
 * Invalid names raise SocketTLS_Failed. Uses SocketSecurity limits at runtime.
 *
 * Returns: void
 * Raises: SocketTLS_Failed on invalid protos or allocation error
 * Thread-safe: Yes (mutex protected)
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
 * SocketTLSContext_set_alpn_callback - Set custom ALPN protocol selection
 * callback
 * @ctx: The TLS context instance
 * @callback: Function to call for ALPN protocol selection
 * @user_data: User data passed to callback function
 *
 * Sets a custom callback for ALPN protocol selection instead of using default
 * priority order. The callback receives parsed and validated client-offered protocols (library
 * rejects malformed lists per RFC 7301 Section 3.2). Return a const char* to a persistent matching
 * protocol string or NULL to decline. Library validates return (must match offered list, valid length/chars),
 * internally allocates a copy for OpenSSL (avoids UAF if returning temporary ptr), and uses it during handshake.
 *
 * Returns: void
 * Raises: SocketTLS_Failed on invalid parameters
 * Thread-safe: Yes (mutex protected)
 *
 * Note: Callback is called during TLS handshake, must be thread-safe if
 * context is shared.
 */
extern void SocketTLSContext_set_alpn_callback (T ctx,
                                                SocketTLSAlpnCallback callback,
                                                void *user_data);

/* Session management */
/**
 * SocketTLSContext_enable_session_cache - Enable session caching infrastructure
 * @ctx: The TLS context instance
 * @max_sessions: Maximum number of sessions to cache (>0), 0 for default
 * @timeout_seconds: Session timeout in seconds, 0 for OpenSSL default (300s)
 *
 * Extends `SocketTLSContext_T` with session cache configuration.
 * Implements session cache using OpenSSL's built-in caching with thread-safe storage.
 * Adds cache size and timeout configuration. Enables statistics tracking.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if cannot enable or configure
 * Thread-safe: Yes (mutex protected) - modifies shared context during setup
 */
extern void SocketTLSContext_enable_session_cache(T ctx, size_t max_sessions, long timeout_seconds);

/**
 * SocketTLSContext_set_session_cache_size - Limit cached sessions
 * @ctx: The TLS context instance
 * @size: Max number of sessions to cache (>0)
 *
 * Controls memory usage of session cache.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if invalid size or cannot set
 * Thread-safe: Yes (mutex protected)
 */
extern void SocketTLSContext_set_session_cache_size (T ctx, size_t size);

/**
 * SocketTLSContext_get_cache_stats - Get session cache statistics
 * @ctx: The TLS context instance
 * @hits: Output: number of cache hits
 * @misses: Output: number of cache misses
 * @stores: Output: number of sessions stored
 *
 * Fills provided pointers with current session cache statistics.
 * Statistics are thread-safe and cumulative since cache enable.
 * If pointers NULL, skipped.
 *
 * Returns: void
 * Raises: None
 * Thread-safe: Yes
 */
extern void SocketTLSContext_get_cache_stats(T ctx, size_t *hits, size_t *misses, size_t *stores);

/**
 * SocketTLSContext_enable_session_tickets - Enable stateless session resumption using tickets
 * @ctx: The TLS context instance
 * @key: Ticket encryption key material (SOCKET_TLS_TICKET_KEY_LEN bytes required)
 * @key_len: Length of key (must be SOCKET_TLS_TICKET_KEY_LEN = 80 bytes)
 *
 * Implements stateless session resumption using encrypted session tickets.
 * OpenSSL requires 80 bytes: 16 (name) + 32 (AES) + 32 (HMAC).
 * Configures ticket key management, encryption/decryption using provided key.
 * Supports ticket lifetime matching session timeout, and basic rotation.
 * Requires cache enabled for full effect.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if invalid key length or OpenSSL config fails
 * Thread-safe: Yes (mutex protected)
 */
extern void SocketTLSContext_enable_session_tickets(T ctx, const unsigned char *key, size_t key_len);

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
 * SocketTLSContext_add_pin - Add SPKI SHA256 pin (binary format)
 * @ctx: The TLS context instance
 * @sha256_hash: 32-byte SHA256 hash of the SPKI DER encoding
 *
 * Adds a certificate pin using raw binary hash. The hash is copied to
 * context-owned storage. Duplicate pins are silently ignored.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if hash is NULL or max pins exceeded
 * Thread-safe: Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_add_pin (T ctx, const unsigned char *sha256_hash);

/**
 * SocketTLSContext_add_pin_hex - Add SPKI SHA256 pin (hex string)
 * @ctx: The TLS context instance
 * @hex_hash: 64-character hex string (optionally prefixed with "sha256//")
 *
 * Adds a certificate pin using hex-encoded hash. Accepts both uppercase
 * and lowercase hex. Optional "sha256//" prefix is stripped for HPKP
 * compatibility.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if format invalid or max pins exceeded
 * Thread-safe: Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_add_pin_hex (T ctx, const char *hex_hash);

/**
 * SocketTLSContext_add_pin_from_cert - Extract and add pin from certificate
 * @ctx: The TLS context instance
 * @cert_file: Path to PEM-encoded certificate file
 *
 * Loads certificate, extracts SPKI, computes SHA256, and adds as pin.
 * Useful for pinning leaf certificates or intermediate CAs.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if file invalid, parse error, or max pins exceeded
 * Thread-safe: Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_add_pin_from_cert (T ctx, const char *cert_file);

/**
 * SocketTLSContext_add_pin_from_x509 - Add pin from X509 certificate object
 * @ctx: The TLS context instance
 * @cert: OpenSSL X509 certificate object
 *
 * Extracts SPKI hash from provided X509 and adds as pin. The certificate
 * is not freed by this function; caller retains ownership.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if cert NULL, extraction fails, or max exceeded
 * Thread-safe: Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_add_pin_from_x509 (T ctx, const X509 *cert);

/**
 * SocketTLSContext_clear_pins - Remove all certificate pins
 * @ctx: The TLS context instance
 *
 * Securely clears all configured pins. Memory is zeroed before release.
 * Pin enforcement mode is preserved.
 *
 * Returns: void
 * Raises: None
 * Thread-safe: Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_clear_pins (T ctx);

/**
 * SocketTLSContext_set_pin_enforcement - Set pin enforcement mode
 * @ctx: The TLS context instance
 * @enforce: 1 = strict (fail on mismatch), 0 = warn only
 *
 * Controls behavior when no pin matches during verification:
 * - enforce=1 (default): Handshake fails with X509_V_ERR_APPLICATION_VERIFICATION
 * - enforce=0: Verification continues, mismatch is logged
 *
 * Returns: void
 * Raises: None
 * Thread-safe: Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_set_pin_enforcement (T ctx, int enforce);

/**
 * SocketTLSContext_get_pin_enforcement - Get current enforcement mode
 * @ctx: The TLS context instance
 *
 * Returns: 1 if strict enforcement, 0 if warn-only
 * Raises: None
 * Thread-safe: Yes (read-only)
 */
extern int SocketTLSContext_get_pin_enforcement (T ctx);

/**
 * SocketTLSContext_get_pin_count - Get number of configured pins
 * @ctx: The TLS context instance
 *
 * Returns: Number of pins currently configured
 * Raises: None
 * Thread-safe: Yes (read-only)
 */
extern size_t SocketTLSContext_get_pin_count (T ctx);

/**
 * SocketTLSContext_has_pins - Check if any pins are configured
 * @ctx: The TLS context instance
 *
 * Returns: 1 if pins configured, 0 if none
 * Raises: None
 * Thread-safe: Yes (read-only)
 */
extern int SocketTLSContext_has_pins (T ctx);

/**
 * SocketTLSContext_verify_pin - Check if hash matches any pin
 * @ctx: The TLS context instance
 * @sha256_hash: 32-byte hash to check
 *
 * Manual verification without full handshake. Useful for testing
 * or custom verification logic.
 *
 * Returns: 1 if match found, 0 if no match
 * Raises: None
 * Thread-safe: Yes (read-only)
 */
extern int SocketTLSContext_verify_pin (T ctx, const unsigned char *sha256_hash);

/**
 * SocketTLSContext_verify_cert_pin - Check if certificate matches any pin
 * @ctx: The TLS context instance
 * @cert: X509 certificate to verify
 *
 * Extracts SPKI hash from certificate and checks against pins.
 * Useful for manual chain verification.
 *
 * Returns: 1 if match found, 0 if no match
 * Raises: None
 * Thread-safe: Yes (read-only)
 */
extern int SocketTLSContext_verify_cert_pin (T ctx, const X509 *cert);

/* Pinning exception type */
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
 * CTValidationMode - Certificate Transparency validation mode
 */
typedef enum
{
  CT_VALIDATION_PERMISSIVE = 0, /**< Log but don't fail on missing SCTs */
  CT_VALIDATION_STRICT = 1      /**< Require valid SCTs, fail otherwise */
} CTValidationMode;

/**
 * SocketTLSContext_enable_ct - Enable Certificate Transparency verification
 * @ctx: The TLS context instance (client only)
 * @mode: Validation mode (strict or permissive)
 *
 * Enables CT verification for client connections. In strict mode,
 * connections fail if no valid SCTs are present. In permissive mode,
 * missing SCTs are logged but don't cause failure.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if CT not supported or server context
 * Thread-safe: Yes (mutex protected) - modifies shared context
 */
extern void SocketTLSContext_enable_ct (T ctx, CTValidationMode mode);

/**
 * SocketTLSContext_ct_enabled - Check if CT verification is enabled
 * @ctx: The TLS context instance
 *
 * Returns: 1 if CT enabled, 0 if disabled
 * Raises: None
 * Thread-safe: Yes (read-only)
 */
extern int SocketTLSContext_ct_enabled (T ctx);

/**
 * SocketTLSContext_get_ct_mode - Get current CT validation mode
 * @ctx: The TLS context instance
 *
 * Returns: CT validation mode (strict or permissive) if enabled, or CT_VALIDATION_PERMISSIVE if disabled
 * Raises: None
 * Thread-safe: Yes (read-only)
 */
extern CTValidationMode SocketTLSContext_get_ct_mode (T ctx);

/**
 * SocketTLSContext_set_ctlog_list_file - Load custom CT log list
 * @ctx: The TLS context instance (client only)
 * @log_file: Path to CT log list file (OpenSSL format)
 *
 * Loads a custom list of trusted CT logs from file, overriding OpenSSL defaults.
 * Validates file path and format. Call before enable_ct for effect.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if file invalid, load fails, or server context
 * Thread-safe: No (config phase only)
 */
extern void SocketTLSContext_set_ctlog_list_file (T ctx, const char *log_file);

/* Internal functions (not part of public API) */
/**
 * SocketTLSContext_get_ssl_ctx - Get underlying OpenSSL SSL_CTX*
 * @ctx: The TLS context instance
 *
 * Internal access to raw SSL_CTX for SocketTLS_enable() etc.
 *
 * Returns: void* to SSL_CTX (cast as needed)
 * Raises: None
 * Thread-safe: Yes
 */
extern void *SocketTLSContext_get_ssl_ctx (T ctx);

/**
 * SocketTLSContext_is_server - Check if context is server-mode
 * @ctx: The TLS context instance
 *
 * Internal helper to determine client vs server configuration.
 *
 * Returns: 1 if server, 0 if client
 * Raises: None
 * Thread-safe: Yes
 */
extern int SocketTLSContext_is_server (T ctx);

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLSCONTEXT_INCLUDED */
