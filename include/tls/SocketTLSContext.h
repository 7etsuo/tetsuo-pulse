#ifndef SOCKETTLSCONTEXT_INCLUDED
#define SOCKETTLSCONTEXT_INCLUDED

#include "core/Arena.h"
#include "core/Except.h"
#include "tls/SocketTLS.h"

#ifdef SOCKET_HAS_TLS

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
 *   SocketTLSContext_enable_session_cache(server_ctx);
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
 * SocketTLSContext_enable_session_cache - Enable session resumption cache
 * @ctx: The TLS context instance
 *
 * Enables server or client session cache for faster handshakes on reconnects.
 * Sets appropriate mode based on context type.
 *
 * Returns: void
 * Raises: SocketTLS_Failed if cannot enable
 * Thread-safe: No
 */
extern void SocketTLSContext_enable_session_cache (T ctx);

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
