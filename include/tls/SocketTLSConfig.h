#ifndef SOCKETTLSCONFIG_INCLUDED
#define SOCKETTLSCONFIG_INCLUDED

/**
 * @file SocketTLSConfig.h
 * @ingroup security
 * @brief TLS configuration constants, structure, and secure defaults.
 *
 * Defines secure defaults for TLS operations: TLS1.3-only protocols, modern cipher suites,
 * buffer sizes, timeouts, limits, and configuration structure (SocketTLSConfig_T).
 * Provides stub typedefs when TLS is disabled for compilation without OpenSSL/LibreSSL.
 * Includes initialization function SocketTLS_config_defaults() for the config struct.
 *
 * All constants can be overridden before including this header to customize security parameters.
 * Enforces high-security posture by default: no legacy protocols/ciphers, strict version pinning.
 *
 * @threadsafe Yes - compile-time constants and pure functions.
 *
 * @see SocketTLSConfig_T for customizable TLS parameters.
 * @see SocketTLS_config_defaults() for secure initialization.
 * @see @ref SocketTLSContext_T for applying config to contexts.
 * @see @ref SocketTLS_T for TLS I/O operations.
 * @see SocketDTLSConfig.h for DTLS-specific constants.
 * @see @ref security "Security Modules" group.
 */

/**
 * @defgroup tls_config TLS Configuration Constants
 * @ingroup security
 * @brief Secure default constants for TLS protocol versions, cipher suites, timeouts, buffers, and security limits.
 *
 * These constants define secure defaults for TLS operations and can be overridden before including this header.
 * Enforces TLS 1.3-only policy, modern ciphers, and protection against common attacks (DoS, overflows).
 * Provides stubs when TLS support is disabled (@ref SOCKET_HAS_TLS).
 *
 * @{
 *
 * @see SocketTLSConfig_T for the configuration structure.
 * @see SocketTLS_config_defaults() for initializing configurations.
 * @see @ref SocketTLSContext_T for applying configurations to contexts.
 * @see SocketDTLSConfig.h for DTLS-specific constants.
 */

/**
 * @brief TLS configuration parameters for customizing TLS protocol versions and other settings.
 * @ingroup security
 *
 * This structure allows fine-grained control over TLS behavior, starting with protocol version limits.
 * Additional fields for cipher suites, timeouts, certificate policies, etc., will be added in future releases.
 * Always initialize with SocketTLS_config_defaults() before use to ensure secure defaults.
 *
 * @see SocketTLS_config_defaults() for initialization.
 * @see SocketTLSContext_new() for creating contexts with custom config.
 */struct SocketTLSConfig_T{
  /** Minimum supported TLS protocol version (e.g., TLS1_3_VERSION).
   * Default value set by SocketTLS_config_defaults() to SOCKET_TLS_MIN_VERSION (TLS1_3_VERSION).
   * @see SOCKET_TLS_MIN_VERSION
   */
  int min_version;
  /** Maximum supported TLS protocol version (e.g., TLS1_3_VERSION).
   * Default value set by SocketTLS_config_defaults() to SOCKET_TLS_MAX_VERSION (TLS1_3_VERSION).
   * @see SOCKET_TLS_MAX_VERSION
   */
  int max_version;
  /* Expand with ciphers, timeouts, etc. as API evolves */

};

typedef struct SocketTLSConfig_T SocketTLSConfig_T;
/**
 * @brief Initialize the TLS configuration with secure library defaults.
 * @ingroup security
 *
 * Populates the structure with safe defaults: sets min_version and max_version to
 * TLS 1.3 (SOCKET_TLS_MIN_VERSION == SOCKET_TLS_MAX_VERSION), zero-initializes other fields.
 * This enforces a strict TLS 1.3-only policy by default, disabling legacy protocols
 * for enhanced security against downgrade attacks.
 *
 * No-op if config is NULL (no exception raised).
 *
 * @param config Pointer to SocketTLSConfig_T structure to initialize. Ignored if NULL.
 * @return void
 * @note Future versions will set additional defaults for ciphers, timeouts, etc.
 *
 * @see SocketTLSConfig_T for structure details.
 * @see SocketTLSContext_new() to create a TLS context using this configuration.
 * @see @ref security "Security Modules" for overview.
 */
extern void SocketTLS_config_defaults (SocketTLSConfig_T *config);

#if SOCKET_HAS_TLS

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* ============================================================================
 * TLS Protocol Versions
 * ============================================================================ */

/**
 * @brief Minimum TLS protocol version - STRICT TLS 1.3 ONLY
 * @ingroup tls_config
 *
 * Enforces TLS 1.3 minimum for perfect forward secrecy and modern security.
 * Legacy protocols (SSL 2.0/3.0, TLS 1.0/1.1/1.2) are disabled to prevent
 * downgrade attacks and ensure high security posture.
 *
 * @see SOCKET_TLS_MAX_VERSION for maximum version
 * @see https://owasp.org/www-project-cheat-sheets/cheat_sheets/TLS_Cipher_String_Cheat_Sheet
 */
#define SOCKET_TLS_MIN_VERSION TLS1_3_VERSION

/**
 * @brief Maximum TLS protocol version - STRICT TLS 1.3 ONLY
 * @ingroup tls_config
 *
 * Limits maximum protocol to TLS 1.3 for security. TLS 1.4+ not yet defined.
 * This ensures consistent security guarantees across all connections.
 *
 * @see SOCKET_TLS_MIN_VERSION for minimum version
 */
#define SOCKET_TLS_MAX_VERSION TLS1_3_VERSION

/* ============================================================================
 * TLS Cipher Suites
 * ============================================================================ */

/**
 * @brief TLS 1.3 Modern Cipher Suites (ECDHE-PFS only, AEAD ciphers)
 * @ingroup tls_config
 *
 * Modern cipher suites providing perfect forward secrecy and authenticated
 * encryption with associated data (AEAD). Prioritizes ChaCha20-Poly1305
 * for performance on systems without AES hardware acceleration.
 *
 * Order: AES-256-GCM (highest security), ChaCha20-Poly1305 (performance),
 * AES-128-GCM (compatibility).
 *
 * Excludes: CBC mode (vulnerable to padding attacks), RC4 (broken),
 * 3DES (weak), non-PFS ciphers (RSA key exchange).
 *
 * @see https://wiki.mozilla.org/Security/Server_Side_TLS
 * @see https://www.ssllabs.com/ssltest/
 */
#define SOCKET_TLS13_CIPHERSUITES                                             \
  "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_"      \
  "SHA256"

/* ============================================================================
 * TLS Timeout Configuration
 * ============================================================================ */

/**
 * @brief Default TLS handshake timeout in milliseconds
 * @ingroup tls_config
 *
 * Maximum time allowed for TLS handshake completion. 30 seconds provides
 * reasonable security (prevents slowloris-style attacks) while allowing
 * for network latency and certificate validation time.
 *
 * Override before including this header to customize for your environment.
 */
#ifndef SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS
#define SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS 30000 /* 30 seconds */
#endif

/**
 * @brief Default TLS shutdown timeout in milliseconds
 * @ingroup tls_config
 *
 * Maximum time to wait for graceful TLS connection shutdown. Shorter than
 * handshake timeout since shutdown should complete quickly. 5 seconds
 * prevents hanging on non-responsive peers.
 */
#ifndef SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS
#define SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS 5000 /* 5 seconds */
#endif

/**
 * @brief TLS handshake poll interval for non-blocking operations
 * @ingroup tls_config
 *
 * Polling interval used by SocketTLS_handshake_loop() for event-driven
 * handshake completion. 100ms balances responsiveness with CPU usage.
 * Smaller values increase responsiveness but consume more CPU.
 */
#ifndef SOCKET_TLS_POLL_INTERVAL_MS
#define SOCKET_TLS_POLL_INTERVAL_MS 100 /* 100ms polling interval */
#endif

/**
 * @brief TLS read/write buffer size
 * @ingroup tls_config
 *
 * Buffer size for TLS record I/O operations. Set to maximum TLS record
 * size (16384 bytes) to ensure complete records can be processed in
 * single operations. Larger buffers don't provide benefit since TLS
 * records cannot exceed this size.
 */
#ifndef SOCKET_TLS_BUFFER_SIZE
#define SOCKET_TLS_BUFFER_SIZE 16384 /* 16KB - TLS record max */
#endif

/**
 * @brief Maximum certificate chain depth for verification
 * @ingroup tls_config
 *
 * Maximum depth of certificate chains accepted during verification.
 * Prevents excessive memory usage from maliciously long chains.
 * 10 levels allows for typical commercial CA hierarchies.
 */
#ifndef SOCKET_TLS_MAX_CERT_CHAIN_DEPTH
#define SOCKET_TLS_MAX_CERT_CHAIN_DEPTH 10
#endif

/**
 * @brief Maximum ALPN protocol name length
 * @ingroup tls_config
 *
 * Maximum length for individual ALPN protocol names in bytes.
 * Conforms to RFC 7301 Section 3.2 protocol identifier limits.
 * 255 bytes provides ample space for protocol names.
 */
#ifndef SOCKET_TLS_MAX_ALPN_LEN
#define SOCKET_TLS_MAX_ALPN_LEN 255
#endif

/**
 * @brief Maximum total bytes for ALPN protocol list
 * @ingroup tls_config
 *
 * Maximum total size of ALPN protocol list to prevent DoS attacks
 * during parsing. Limits memory allocation and processing time.
 * 1024 bytes allows reasonable number of protocols.
 */
#ifndef SOCKET_TLS_MAX_ALPN_TOTAL_BYTES
#define SOCKET_TLS_MAX_ALPN_TOTAL_BYTES 1024
#endif

/**
 * @brief SNI hostname length limit
 * @ingroup tls_config
 *
 * Maximum length for Server Name Indication hostnames.
 * Conforms to DNS hostname limits (253 chars) with padding.
 * Prevents buffer overflow in SNI processing.
 */
#ifndef SOCKET_TLS_MAX_SNI_LEN
#define SOCKET_TLS_MAX_SNI_LEN 255
#endif

/**
 * @brief TLS session cache size (number of cached sessions)
 * @ingroup tls_config
 *
 * Maximum number of TLS sessions to cache for resumption.
 * Larger caches improve performance for frequent reconnections
 * but consume more memory. 1000 sessions is reasonable for
 * moderate-traffic servers.
 */
#ifndef SOCKET_TLS_SESSION_CACHE_SIZE
#define SOCKET_TLS_SESSION_CACHE_SIZE 1000
#endif

/**
 * @brief TLS error buffer size for detailed error messages
 * @ingroup tls_config
 *
 * Buffer size for thread-local error messages used in exception handling.
 * Must accommodate detailed OpenSSL error strings and context information.
 * 512 bytes provides ample space for comprehensive error reporting.
 */
#ifndef SOCKET_TLS_ERROR_BUFSIZE
#define SOCKET_TLS_ERROR_BUFSIZE 512
#endif

/**
 * @brief OpenSSL error string buffer size for temporary formatting
 * @ingroup tls_config
 *
 * Temporary buffer for formatting individual OpenSSL error strings.
 * Used during error queue processing. 256 bytes accommodates typical
 * OpenSSL error message lengths with room for formatting.
 */
#ifndef SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE
#define SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE 256
#endif

/**
 * @brief Maximum number of SNI certificates per context
 * @ingroup tls_config
 *
 * Maximum number of certificate/key pairs that can be configured
 * for Server Name Indication (SNI) virtual hosting. 100 certificates
 * supports large-scale virtual hosting deployments.
 */
#ifndef SOCKET_TLS_MAX_SNI_CERTS
#define SOCKET_TLS_MAX_SNI_CERTS 100
#endif

/**
 * @brief Initial SNI certificate array capacity
 * @ingroup tls_config
 *
 * Starting capacity for SNI certificate array. Array doubles in size
 * when capacity is exceeded. 4 provides reasonable starting point
 * with minimal memory overhead.
 */
#ifndef SOCKET_TLS_SNI_INITIAL_CAPACITY
#define SOCKET_TLS_SNI_INITIAL_CAPACITY 4
#endif

/**
 * @brief Maximum number of ALPN protocols per context
 * @ingroup tls_config
 *
 * Maximum number of Application-Layer Protocol Negotiation (ALPN)
 * protocols that can be advertised. 16 protocols covers all
 * typical use cases (HTTP/1.1, HTTP/2, WebSocket, etc.).
 */
#ifndef SOCKET_TLS_MAX_ALPN_PROTOCOLS
#define SOCKET_TLS_MAX_ALPN_PROTOCOLS 16
#endif

/**
 * @brief Session ticket encryption key length
 * @ingroup tls_config
 *
 * Length of the key used for encrypting TLS session tickets.
 * OpenSSL uses 80 bytes: 16 bytes for name, 32 bytes AES key,
 * 32 bytes HMAC key. This provides strong encryption for
 * stateless session resumption.
 */
#ifndef SOCKET_TLS_TICKET_KEY_LEN
#define SOCKET_TLS_TICKET_KEY_LEN 80
#endif

/**
 * @brief Default TLS session cache timeout in seconds
 * @ingroup tls_config
 *
 * Default lifetime for cached TLS sessions. 300 seconds (5 minutes)
 * balances security (prevents stale sessions) with performance
 * (allows reasonable session reuse window).
 */
#ifndef SOCKET_TLS_SESSION_TIMEOUT_DEFAULT
#define SOCKET_TLS_SESSION_TIMEOUT_DEFAULT 300L
#endif

/**
 * @brief Maximum OCSP response size
 * @ingroup tls_config
 *
 * Maximum size for Online Certificate Status Protocol (OCSP) responses.
 * 64KB accommodates large OCSP responses while preventing memory exhaustion.
 * Typical responses are much smaller (< 4KB) but this provides safety margin.
 */
#ifndef SOCKET_TLS_MAX_OCSP_RESPONSE_LEN
#define SOCKET_TLS_MAX_OCSP_RESPONSE_LEN (64 * 1024)
#endif

/**
 * @brief Maximum file path length for certificates/keys
 * @ingroup tls_config
 *
 * Maximum length for certificate and key file paths.
 * 4096 bytes accommodates long paths in complex directory structures
 * while preventing buffer overflow in path processing.
 */
#ifndef SOCKET_TLS_MAX_PATH_LEN
#define SOCKET_TLS_MAX_PATH_LEN 4096
#endif

/**
 * @brief Maximum DNS label length per RFC 1035
 * @ingroup tls_config
 *
 * Maximum length for individual DNS hostname labels.
 * RFC 1035 specifies 63 characters maximum for DNS labels.
 * Enforced during hostname validation for security.
 */
#ifndef SOCKET_TLS_MAX_LABEL_LEN
#define SOCKET_TLS_MAX_LABEL_LEN 63
#endif

/**
 * @brief Certificate pinning configuration
 * @ingroup tls_config
 */

/**
 * @brief Maximum number of certificate pins per context
 * @ingroup tls_config
 *
 * Maximum number of Subject Public Key Info (SPKI) SHA256 pins
 * that can be configured per TLS context. 32 pins supports
 * complex pinning policies for enterprise deployments.
 */
#ifndef SOCKET_TLS_MAX_PINS
#define SOCKET_TLS_MAX_PINS 32 /* Max pinned certificates per context */
#endif

/**
 * @brief Certificate pin hash length (SHA256)
 * @ingroup tls_config
 *
 * Length of SHA256 hash used for certificate pinning.
 * SHA256 produces 32-byte (256-bit) hashes for strong collision
 * resistance and security.
 */
#ifndef SOCKET_TLS_PIN_HASH_LEN
#define SOCKET_TLS_PIN_HASH_LEN 32 /* SHA256 = 32 bytes */
#endif

/**
 * @brief Initial certificate pin array capacity
 * @ingroup tls_config
 *
 * Starting capacity for pin array. Array doubles when capacity
 * is exceeded. 4 provides reasonable starting point for most
 * applications that use 1-2 pins.
 */
#ifndef SOCKET_TLS_PIN_INITIAL_CAPACITY
#define SOCKET_TLS_PIN_INITIAL_CAPACITY 4 /* Initial pin array capacity */
#endif

/**
 * @brief CRL auto-refresh configuration
 * @ingroup tls_config
 */

/**
 * @brief Minimum CRL refresh interval in seconds
 * @ingroup tls_config
 *
 * Minimum time between CRL refresh attempts. 60 seconds prevents
 * excessive refresh attempts that could overwhelm CRL distribution
 * points or cause performance issues.
 */
#ifndef SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL
#define SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL 60 /* Minimum 60 seconds */
#endif

/**
 * @brief Maximum CRL refresh interval in seconds
 * @ingroup tls_config
 *
 * Maximum time between CRL refresh attempts. 1 year (365*24*3600 seconds)
 * ensures CRLs don't become stale even with very long intervals.
 * Applications should use shorter intervals for better security.
 */
#ifndef SOCKET_TLS_CRL_MAX_REFRESH_INTERVAL
#define SOCKET_TLS_CRL_MAX_REFRESH_INTERVAL                                   \
  (365LL * 24 * 3600) /* Max 1 year in seconds */
#endif

/**
 * @brief Maximum CRL file size
 * @ingroup tls_config
 *
 * Maximum size allowed for Certificate Revocation List (CRL) files.
 * 10MB accommodates large CRLs from major CAs while preventing
 * memory exhaustion attacks. Also limits number of CRL files
 * in directories to prevent exhaustion.
 */
#ifndef SOCKET_TLS_MAX_CRL_SIZE
#define SOCKET_TLS_MAX_CRL_SIZE                                               \
  (10 * 1024 * 1024) /* Max 10MB for CRL files                                \
                      */
#define SOCKET_TLS_MAX_CRL_FILES_IN_DIR                                       \
  1000 /* Max CRL files in directory to prevent exhaustion */
#endif

/**
 * @brief Maximum CRL path length
 * @ingroup tls_config
 *
 * Maximum length for CRL file paths. Same as certificate paths
 * for consistency. 4096 bytes accommodates complex directory structures.
 */
#ifndef SOCKET_TLS_CRL_MAX_PATH_LEN
#define SOCKET_TLS_CRL_MAX_PATH_LEN 4096 /* Max CRL path length */
#endif

#else /* SOCKET_HAS_TLS not defined */

/* Stub definitions when TLS is disabled */
#ifndef SSL_CTX
typedef void SSL_CTX;
#endif
#ifndef SSL
typedef void SSL;
#endif
#ifndef X509
typedef void X509;
#endif
#ifndef X509_STORE
typedef void X509_STORE;
#endif

#endif /* SOCKET_HAS_TLS */

/**
 * @} tls_config
 */
#endif /* SOCKETTLSCONFIG_INCLUDED */
