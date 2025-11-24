#ifndef SOCKETTLSCONTEXT_INCLUDED
#define SOCKETTLSCONTEXT_INCLUDED

#include "core/Arena.h"
#include "core/Except.h"
#include "tls/SocketTLS.h"

#ifdef SOCKET_HAS_TLS

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
 * modern ciphers, and optionally CA for client verification.
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
 * Creates a client-side TLS context with TLS1.3-only and modern ciphers.
 * Loads CA if provided and enables peer verification.
 *
 * Returns: New opaque SocketTLSContext_T instance
 * Raises: SocketTLS_Failed on OpenSSL errors or invalid CA
 * Thread-safe: Yes
 */
extern T SocketTLSContext_new_client (const char *ca_file);

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
 * Thread-safe: No - modifies shared context
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
 * Thread-safe: No
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
 * Thread-safe: No
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
 * Thread-safe: No (modifies shared context; call before sharing)
 */

/**
 * SocketTLSContext_free - Dispose of TLS context and resources
 * @ctx_p: Pointer to context pointer (set to NULL on success)
 *
 * Frees the SSL_CTX, Arena (internal allocations), SNI arrays/certs/keys, ALPN data.
 * Caller must not use context after free. Reverse of new_server/client.
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
 * Thread-safe: No - modifies shared store; call during setup
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
 * Thread-safe: No
 * Raises: SocketTLS_Failed on load error
 */
extern void SocketTLSContext_refresh_crl(T ctx, const char *crl_path);

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
 * Thread-safe: No
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
 * SocketTLS_get_verify_result - Get TLS verification result after handshake
 * @sock: The TLS-enabled socket
 *
 * Returns the OpenSSL verification result code (X509_V_OK = 0 on success).
 * Call after handshake to check peer cert status. Maps to SocketTLS_VerifyFailed
 * exception if failed and auto-raise option enabled (future).
 *
 * Returns: long (X509 verify result code)
 * Raises: None (caller checks return != X509_V_OK)
 * Thread-safe: Yes (read-only after handshake)
 */
extern long SocketTLS_get_verify_result (Socket_T sock);

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
 * Thread-safe: No
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
 * Thread-safe: No
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
 * Thread-safe: No
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
 * arena. Validates lengths and formats for TLS compliance.
 *
 * Returns: void
 * Raises: SocketTLS_Failed on invalid protos or allocation error
 * Thread-safe: No
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
 * priority order. The callback receives client-offered protocols and should
 * return the selected protocol string.
 *
 * Returns: void
 * Raises: SocketTLS_Failed on invalid parameters
 * Thread-safe: No
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
 * Thread-safe: No - modifies shared context during setup
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
 * Thread-safe: No
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
 * @key: Ticket encryption key material (48 bytes for AES256 + HMAC recommended)
 * @key_len: Length of key (must be 48 for basic support)
 *
 * Implements stateless session resumption using encrypted session tickets.
 * Configures ticket key management, encryption/decryption using provided key.
 * Supports ticket lifetime matching session timeout, and basic rotation.
 * Requires cache enabled for full effect.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if invalid key length or OpenSSL config fails
 * Thread-safe: No
 */
extern void SocketTLSContext_enable_session_tickets(T ctx, const unsigned char *key, size_t key_len);

/* Context lifecycle */
/**
 * SocketTLSContext_free - Destroy TLS context
 * @ctx: Pointer to context pointer (set to NULL on free)
 *
 * Frees SSL_CTX, arena (all allocations), and struct. Safe to call on NULL.
 *
 * Returns: void
 * Raises: None
 * Thread-safe: No - do not free while in use by connections
 */
extern void SocketTLSContext_free (T *ctx);

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
