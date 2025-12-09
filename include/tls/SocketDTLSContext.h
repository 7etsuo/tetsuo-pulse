#ifndef SOCKETDTLSCONTEXT_INCLUDED
#define SOCKETDTLSCONTEXT_INCLUDED

/**
 * @file SocketDTLSContext.h
 * @ingroup security
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
 * Thread safety: Contexts are not thread-safe for modification after creation.
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
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "tls/SocketTLS.h" /* For TLSVerifyMode */

#if SOCKET_HAS_TLS

#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <stddef.h>

#define T SocketDTLSContext_T
typedef struct T *T; /* Opaque pointer to DTLS context */

/* Forward declaration for socket type */
typedef struct SocketDgram_T *SocketDgram_T;

/* ============================================================================
 * DTLS Context Creation and Destruction
 * ============================================================================
 */

/**
 * SocketDTLSContext_new_server - Create server DTLS context with cert/key
 * @cert_file: Path to server certificate file (PEM format)
 * @key_file: Path to private key file (PEM format)
 * @ca_file: Optional path to CA file/directory for client auth (NULL to
 * disable)
 *
 * Creates a server-side DTLS context, loads server cert/key, sets DTLS 1.2
 * minimum, modern ciphers, and optionally CA for client verification.
 * Cookie exchange is NOT enabled by default - call
 * SocketDTLSContext_enable_cookie_exchange() for DoS protection.
 *
 * Returns: New opaque SocketDTLSContext_T instance
 * Raises: SocketDTLS_Failed on OpenSSL errors, file I/O, or invalid cert/key
 * Thread-safe: Yes - each call creates independent context
 */
extern T SocketDTLSContext_new_server (const char *cert_file,
                                       const char *key_file,
                                       const char *ca_file);

/**
 * SocketDTLSContext_new_client - Create client DTLS context
 * @ca_file: Optional path to CA file/directory for server verification (NULL
 * to disable)
 *
 * Creates a client-side DTLS context with DTLS 1.2 minimum and modern ciphers.
 * Loads CA if provided and enables peer verification.
 *
 * Returns: New opaque SocketDTLSContext_T instance
 * Raises: SocketDTLS_Failed on OpenSSL errors or invalid CA
 * Thread-safe: Yes
 */
extern T SocketDTLSContext_new_client (const char *ca_file);

/**
 * SocketDTLSContext_free - Dispose of DTLS context and resources
 * @ctx_p: Pointer to context pointer (set to NULL on success)
 *
 * Frees the SSL_CTX, Arena (internal allocations), cookie secret, ALPN data.
 * Caller must not use context after free. Reverse of new_server/client.
 *
 * Returns: void
 * Raises: None (safe for NULL)
 * Thread-safe: Yes (but avoid concurrent use)
 */
extern void SocketDTLSContext_free (T *ctx_p);

/* ============================================================================
 * Certificate Management
 * ============================================================================
 */

/**
 * SocketDTLSContext_load_certificate - Load server certificate and private key
 * @ctx: The DTLS context instance
 * @cert_file: Path to certificate file (PEM)
 * @key_file: Path to private key file (PEM)
 *
 * Loads and validates server certificate/private key pair. Verifies key
 * matches cert.
 *
 * Returns: void
 * Raises: SocketDTLS_Failed on file errors, format issues, or mismatch
 * Thread-safe: No - modifies shared context
 */
extern void SocketDTLSContext_load_certificate (T ctx, const char *cert_file,
                                                const char *key_file);

/**
 * SocketDTLSContext_load_ca - Load trusted CA certificates
 * @ctx: The DTLS context instance
 * @ca_file: Path to CA file or directory containing PEM CA certs
 *
 * Loads CA certs for peer verification. Tries as file then directory.
 *
 * Returns: void
 * Raises: SocketDTLS_Failed on load errors
 * Thread-safe: No
 */
extern void SocketDTLSContext_load_ca (T ctx, const char *ca_file);

/**
 * SocketDTLSContext_set_verify_mode - Set certificate verification policy
 * @ctx: The DTLS context instance
 * @mode: Verification mode enum (TLS_VERIFY_NONE, PEER, etc.)
 *
 * Configures peer cert verification behavior, mapping to OpenSSL SSL_VERIFY_*
 * flags.
 *
 * Returns: void
 * Raises: SocketDTLS_Failed on invalid mode
 * Thread-safe: No
 */
extern void SocketDTLSContext_set_verify_mode (T ctx, TLSVerifyMode mode);

/* ============================================================================
 * Cookie Exchange (DoS Protection) - DTLS-Specific
 * ============================================================================
 */

/**
 * SocketDTLSContext_enable_cookie_exchange - Enable stateless cookie DoS
 * protection
 * @ctx: The DTLS context instance (server only)
 *
 * Enables RFC 6347 cookie exchange. Server sends HelloVerifyRequest with
 * cookie before allocating per-client state. Client must echo cookie to
 * prove address ownership. Prevents memory exhaustion from spoofed sources.
 *
 * A random secret is generated automatically. Use
 * SocketDTLSContext_set_cookie_secret() for deterministic/clustered setups.
 *
 * Returns: void
 * Raises: SocketDTLS_Failed on configuration error
 * Thread-safe: No - modifies shared context
 */
extern void SocketDTLSContext_enable_cookie_exchange (T ctx);

/**
 * SocketDTLSContext_set_cookie_secret - Set cookie HMAC secret key
 * @ctx: The DTLS context instance
 * @secret: Secret key bytes (must be SOCKET_DTLS_COOKIE_SECRET_LEN bytes)
 * @len: Length of secret (must be SOCKET_DTLS_COOKIE_SECRET_LEN)
 *
 * Sets the secret key used for cookie HMAC generation. Required for
 * clustered deployments where all servers must generate compatible cookies.
 * Call after enable_cookie_exchange() or it will be overwritten.
 *
 * Returns: void
 * Raises: SocketDTLS_Failed if invalid length or context not configured
 * Thread-safe: No - modifies shared context
 */
extern void SocketDTLSContext_set_cookie_secret (T ctx,
                                                 const unsigned char *secret,
                                                 size_t len);

/**
 * SocketDTLSContext_rotate_cookie_secret - Generate new cookie secret
 * @ctx: The DTLS context instance
 *
 * Generates a new random secret for cookie HMAC. Call periodically
 * (e.g., every hour) to limit cookie replay window. In-flight handshakes
 * with old cookie will fail and retry automatically.
 *
 * Returns: void
 * Raises: SocketDTLS_Failed on random generation failure
 * Thread-safe: No - modifies shared context
 */
extern void SocketDTLSContext_rotate_cookie_secret (T ctx);

/* ============================================================================
 * MTU Configuration
 * ============================================================================
 */

/**
 * SocketDTLSContext_set_mtu - Set link MTU for DTLS record sizing
 * @ctx: The DTLS context instance
 * @mtu: Maximum Transmission Unit in bytes
 *
 * Sets the MTU used for DTLS record fragmentation. Conservative default
 * is 1400 bytes (safe for IPv6 tunnels/VPNs). Use larger values on known
 * LAN environments for better performance.
 *
 * Returns: void
 * Raises: SocketDTLS_Failed if MTU out of valid range
 * Thread-safe: No
 */
extern void SocketDTLSContext_set_mtu (T ctx, size_t mtu);

/**
 * SocketDTLSContext_get_mtu - Get configured MTU
 * @ctx: The DTLS context instance
 *
 * Returns: Current MTU setting in bytes
 * Raises: None
 * Thread-safe: Yes (read-only)
 */
extern size_t SocketDTLSContext_get_mtu (T ctx);

/* ============================================================================
 * Protocol Configuration
 * ============================================================================
 */

/**
 * SocketDTLSContext_set_min_protocol - Set minimum supported DTLS version
 * @ctx: The DTLS context instance
 * @version: OpenSSL version constant (e.g., DTLS1_2_VERSION)
 *
 * Sets minimum DTLS version. Default is DTLS 1.2.
 *
 * Returns: void
 * Raises: SocketDTLS_Failed if cannot set
 * Thread-safe: No
 */
extern void SocketDTLSContext_set_min_protocol (T ctx, int version);

/**
 * SocketDTLSContext_set_max_protocol - Set maximum supported DTLS version
 * @ctx: The DTLS context instance
 * @version: OpenSSL version constant (e.g., DTLS1_2_VERSION)
 *
 * Sets maximum DTLS version.
 *
 * Returns: void
 * Raises: SocketDTLS_Failed if cannot set
 * Thread-safe: No
 */
extern void SocketDTLSContext_set_max_protocol (T ctx, int version);

/**
 * SocketDTLSContext_set_cipher_list - Set allowed cipher suites
 * @ctx: The DTLS context instance
 * @ciphers: Cipher list string in OpenSSL format, or NULL for defaults
 *
 * Configures allowed ciphers. Defaults to secure modern list if NULL.
 *
 * Returns: void
 * Raises: SocketDTLS_Failed if invalid list
 * Thread-safe: No
 */
extern void SocketDTLSContext_set_cipher_list (T ctx, const char *ciphers);

/* ============================================================================
 * ALPN Support
 * ============================================================================
 */

/**
 * SocketDTLSContext_set_alpn_protos - Advertise ALPN protocols
 * @ctx: The DTLS context instance
 * @protos: Array of null-terminated protocol strings (e.g., "coap", "h3")
 * @count: Number of protocols
 *
 * Sets list of supported ALPN protocols in wire format, allocated from context
 * arena. Validates lengths and formats for TLS compliance.
 *
 * Returns: void
 * Raises: SocketDTLS_Failed on invalid protos or allocation error
 * Thread-safe: No
 *
 * Note: Protocols advertised in preference order (first preferred).
 */
extern void SocketDTLSContext_set_alpn_protos (T ctx, const char **protos,
                                               size_t count);

/* ============================================================================
 * Session Management
 * ============================================================================
 */

/**
 * SocketDTLSContext_enable_session_cache - Enable session caching
 * @ctx: The DTLS context instance
 * @max_sessions: Maximum number of sessions to cache (>0), 0 for default
 * @timeout_seconds: Session timeout in seconds, 0 for OpenSSL default (300s)
 *
 * Enables session resumption for reduced handshake latency (1-RTT vs 2-RTT).
 *
 * Returns: void
 * Raises: SocketDTLS_Failed if cannot enable or configure
 * Thread-safe: No - modifies shared context during setup
 */
extern void SocketDTLSContext_enable_session_cache (T ctx, size_t max_sessions,
                                                    long timeout_seconds);

/**
 * SocketDTLSContext_get_cache_stats - Get session cache statistics
 * @ctx: The DTLS context instance
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
extern void SocketDTLSContext_get_cache_stats (T ctx, size_t *hits,
                                               size_t *misses, size_t *stores);

/* ============================================================================
 * Timeout Configuration
 * ============================================================================
 */

/**
 * SocketDTLSContext_set_timeout - Set handshake timeout parameters
 * @ctx: The DTLS context instance
 * @initial_ms: Initial retransmission timeout in milliseconds
 * @max_ms: Maximum timeout after exponential backoff
 *
 * Configures DTLS handshake retransmission timer. OpenSSL handles
 * retransmission internally using these parameters.
 *
 * Returns: void
 * Raises: SocketDTLS_Failed on invalid parameters
 * Thread-safe: No
 */
extern void SocketDTLSContext_set_timeout (T ctx, int initial_ms, int max_ms);

/* ============================================================================
 * Internal Access (for SocketDTLS module)
 * ============================================================================
 */

/**
 * SocketDTLSContext_get_ssl_ctx - Get underlying OpenSSL SSL_CTX*
 * @ctx: The DTLS context instance
 *
 * Internal access to raw SSL_CTX for SocketDTLS_enable() etc.
 *
 * Returns: void* to SSL_CTX (cast as needed)
 * Raises: None
 * Thread-safe: Yes
 */
extern void *SocketDTLSContext_get_ssl_ctx (T ctx);

/**
 * SocketDTLSContext_is_server - Check if context is server-mode
 * @ctx: The DTLS context instance
 *
 * Internal helper to determine client vs server configuration.
 *
 * Returns: 1 if server, 0 if client
 * Raises: None
 * Thread-safe: Yes
 */
extern int SocketDTLSContext_is_server (T ctx);

/**
 * SocketDTLSContext_has_cookie_exchange - Check if cookie exchange enabled
 * @ctx: The DTLS context instance
 *
 * Returns: 1 if enabled, 0 if disabled
 * Raises: None
 * Thread-safe: Yes (read-only)
 */
extern int SocketDTLSContext_has_cookie_exchange (T ctx);

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETDTLSCONTEXT_INCLUDED */

