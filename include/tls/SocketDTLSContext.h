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
 * Avoid concurrent modifications (e.g., set_verify_mode) without external locking.
 *
 * @note All internal allocations use an embedded Arena_T for lifecycle management.
 * @note Exceptions raised via SocketDTLS_Failed include detailed OpenSSL error info.
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
 * DTLS contexts are applied to SocketDgram_T instances via SocketDTLS_enable().
 *
 * @see SocketDgram.h for UDP socket creation, bind, send/recv, etc.
 * @see SocketDTLS_enable() for enabling DTLS on UDP sockets.
 */
typedef struct SocketDgram_T *SocketDgram_T;

/* ============================================================================
 * DTLS Context Creation and Destruction
 * ============================================================================
 */

/**
 * @brief Create server DTLS context with cert/key
 * @ingroup dtls_context
 * @param cert_file Path to server certificate file (PEM format)
 * @param key_file Path to private key file (PEM format)
 * @param ca_file Optional path to CA file/directory for client auth (NULL to
 * disable)
 *
 * Creates a server-side DTLS context, loads server cert/key, sets DTLS 1.2
 * minimum, modern ciphers, and optionally CA for client verification.
 * Cookie exchange is NOT enabled by default - call
 * SocketDTLSContext_enable_cookie_exchange() for DoS protection.
 *
 * @return New opaque SocketDTLSContext_T instance
 * @throws SocketDTLS_Failed on OpenSSL errors, file I/O, or invalid cert/key
 * @threadsafe Yes - each call creates independent context
 */
extern T SocketDTLSContext_new_server (const char *cert_file,
                                       const char *key_file,
                                       const char *ca_file);

/**
 * @brief Create client DTLS context
 * @ingroup dtls_context
 * @param ca_file Optional path to CA file/directory for server verification (NULL
 * to disable)
 *
 * Creates a client-side DTLS context with DTLS 1.2 minimum and modern ciphers.
 * Loads CA if provided and enables peer verification.
 *
 * @return New opaque SocketDTLSContext_T instance
 * @throws SocketDTLS_Failed on OpenSSL errors or invalid CA
 * @threadsafe Yes
 */
extern T SocketDTLSContext_new_client (const char *ca_file);

/**
 * @brief Dispose of DTLS context and resources
 * @ingroup dtls_context
 * @param ctx_p Pointer to context pointer (set to NULL on success)
 *
 * Frees the SSL_CTX, Arena (internal allocations), cookie secret, ALPN data.
 * Caller must not use context after free. Reverse of new_server/client.
 *
 * @return void
 * @throws None (safe for NULL)
 * @threadsafe Yes (but avoid concurrent use)
 */
extern void SocketDTLSContext_free (T *ctx_p);

/* ============================================================================
 * Certificate Management
 * ============================================================================
 */

/**
 * @brief Load server certificate and private key
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 * @param cert_file Path to certificate file (PEM)
 * @param key_file Path to private key file (PEM)
 *
 * Loads and validates server certificate/private key pair. Verifies key
 * matches cert.
 *
 * @return void
 * @throws SocketDTLS_Failed on file errors, format issues, or mismatch
 * @threadsafe No - modifies shared context
 */
extern void SocketDTLSContext_load_certificate (T ctx, const char *cert_file,
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
 * @note Maps provided flags to OpenSSL SSL_VERIFY_* constants; invalid or unsupported flags are ignored without error.
 * @threadsafe No
 */
extern void SocketDTLSContext_set_verify_mode (T ctx, TLSVerifyMode mode);

/* ============================================================================
 * Cookie Exchange (DoS Protection) - DTLS-Specific
 * ============================================================================
 */

/**
 * @brief Enable stateless cookie DoS protection
 * @ingroup dtls_context
 * @param ctx The DTLS context instance (server only)
 *
 * Enables RFC 6347 cookie exchange. Server sends HelloVerifyRequest with
 * cookie before allocating per-client state. Client must echo cookie to
 * prove address ownership. Prevents memory exhaustion from spoofed sources.
 *
 * A random secret is generated automatically. Use
 * SocketDTLSContext_set_cookie_secret() for deterministic/clustered setups.
 *
 * @return void
 * @throws SocketDTLS_Failed on configuration error
 * @threadsafe No - modifies shared context
 */
extern void SocketDTLSContext_enable_cookie_exchange (T ctx);

/**
 * @brief Set cookie HMAC secret key
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 * @param secret Secret key bytes (must be SOCKET_DTLS_COOKIE_SECRET_LEN bytes)
 * @param len Length of secret (must be SOCKET_DTLS_COOKIE_SECRET_LEN)
 *
 * Sets the secret key used for cookie HMAC generation. Required for
 * clustered deployments where all servers must generate compatible cookies.
 * Call after enable_cookie_exchange() or it will be overwritten.
 *
 * @return void
 * @throws SocketDTLS_Failed if invalid length or context not configured
 * @threadsafe No - modifies shared context
 */
extern void SocketDTLSContext_set_cookie_secret (T ctx,
                                                 const unsigned char *secret,
                                                 size_t len);

/**
 * @brief Generate new cookie secret
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 *
 * Generates a new random secret for cookie HMAC. Call periodically
 * (e.g., every hour) to limit cookie replay window. In-flight handshakes
 * with old cookie will fail and retry automatically.
 *
 * @return void
 * @throws SocketDTLS_Failed on random generation failure
 * @threadsafe No - modifies shared context
 */
extern void SocketDTLSContext_rotate_cookie_secret (T ctx);

/* ============================================================================
 * MTU Configuration
 * ============================================================================
 */

/**
 * @brief Set link MTU for DTLS record sizing
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 * @param mtu Maximum Transmission Unit in bytes
 *
 * Sets the MTU used for DTLS record fragmentation. Conservative default
 * is 1400 bytes (safe for IPv6 tunnels/VPNs). Use larger values on known
 * LAN environments for better performance.
 *
 * @return void
 * @throws SocketDTLS_Failed if MTU out of valid range
 * @threadsafe No
 */
extern void SocketDTLSContext_set_mtu (T ctx, size_t mtu);

/**
 * @brief Get configured MTU
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 *
 * @return Current MTU setting in bytes
 * @throws None
 * @threadsafe Yes (read-only)
 */
extern size_t SocketDTLSContext_get_mtu (T ctx);

/* ============================================================================
 * Protocol Configuration
 * ============================================================================
 */

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

/* ============================================================================
 * ALPN Support
 * ============================================================================
 */

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
extern void SocketDTLSContext_set_alpn_protos (T ctx, const char **protos,
                                               size_t count);

/* ============================================================================
 * Session Management
 * ============================================================================
 */

/**
 * @brief Enable session caching
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 * @param max_sessions Maximum number of sessions to cache (>0), 0 for default
 * @param timeout_seconds Session timeout in seconds, 0 for OpenSSL default (300s)
 *
 * Enables session resumption for reduced handshake latency (1-RTT vs 2-RTT).
 *
 * @return void
 * @throws SocketDTLS_Failed if cannot enable or configure
 * @threadsafe No - modifies shared context during setup
 */
extern void SocketDTLSContext_enable_session_cache (T ctx, size_t max_sessions,
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
extern void SocketDTLSContext_get_cache_stats (T ctx, size_t *hits,
                                               size_t *misses, size_t *stores);

/* ============================================================================
 * Timeout Configuration
 * ============================================================================
 */

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

/* ============================================================================
 * Internal Access (for SocketDTLS module)
 * ============================================================================
 */

/**
 * @brief Get underlying OpenSSL SSL_CTX*
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 *
 * Internal access to raw SSL_CTX for SocketDTLS_enable() etc.
 *
 * @return void* to SSL_CTX (cast as needed)
 * @throws None
 * @threadsafe Yes
 */
extern void *SocketDTLSContext_get_ssl_ctx (T ctx);

/**
 * @brief Check if context is server-mode
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 *
 * Internal helper to determine client vs server configuration.
 *
 * @return 1 if server, 0 if client
 * @throws None
 * @threadsafe Yes
 */
extern int SocketDTLSContext_is_server (T ctx);

/**
 * @brief Check if cookie exchange enabled
 * @ingroup dtls_context
 * @param ctx The DTLS context instance
 *
 * @return 1 if enabled, 0 if disabled
 * @throws None
 * @threadsafe Yes (read-only)
 */
extern int SocketDTLSContext_has_cookie_exchange (T ctx);

/** @} */ /* dtls_context */

/*
 * @} */ /* security */  // Optional, if wanted, but since defined elsewhere
#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETDTLSCONTEXT_INCLUDED */
