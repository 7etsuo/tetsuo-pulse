#ifndef SOCKETTLSCONFIG_INCLUDED
#define SOCKETTLSCONFIG_INCLUDED

/**
 * @file SocketTLSConfig.h
 * @ingroup security
 * @brief TLS configuration constants, structure, and secure defaults.
 *
 * Defines secure defaults for TLS operations: TLS1.3-only protocols, modern
 * cipher suites, buffer sizes, timeouts, limits, and configuration structure
 * (SocketTLSConfig_T). Provides stub typedefs when TLS is disabled for
 * compilation without OpenSSL/LibreSSL. Includes initialization function
 * SocketTLS_config_defaults() for the config struct.
 *
 * All constants can be overridden before including this header to customize
 * security parameters. Enforces high-security posture by default: no legacy
 * protocols/ciphers, strict version pinning.
 *
 * ## Quick Start Example
 *
 * @code{.c}
 * #include "tls/SocketTLSConfig.h"
 * #include "tls/SocketTLSContext.h"
 * #include "socket/Socket.h"
 *
 * // Initialize secure config
 * SocketTLSConfig_T cfg;
 * SocketTLS_config_defaults(&cfg);
 *
 * // Create context
 * SocketTLSContext_T ctx = SocketTLSContext_new(&cfg);
 *
 * // Secure a socket
 * TRY {
 *     Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 *     Socket_connect(sock, "example.com", 443);
 *     SocketTLS_enable(sock, ctx);
 *     // ... perform TLS handshake and I/O ...
 *     Socket_free(&sock);
 * } EXCEPT(SocketTLS_Failed) {
 *     // Handle TLS errors
 * } END_TRY;
 *
 * SocketTLSContext_free(&ctx);
 * @endcode
 *
 * @note Build with `cmake .. -DENABLE_TLS=ON` and link against
 * OpenSSL/LibreSSL.
 * @warning Always pair with proper certificate validation and key management.
 * @threadsafe Yes - compile-time constants and pure functions.
 *
 * @see SocketTLSConfig_T for customizable TLS parameters.
 * @see SocketTLS_config_defaults() for secure initialization.
 * @see @ref SocketTLSContext_T for applying config to contexts.
 * @see @ref SocketTLS_T for TLS I/O operations.
 * @see SocketDTLSConfig.h for DTLS-specific constants.
 * @see examples/https_client.c for full TLS client example.
 * @see @ref security "Security Modules" group.
 */

/**
 * @defgroup tls_config TLS Configuration Constants
 * @ingroup security
 * @brief Secure default constants for TLS protocol versions, cipher suites,
 * timeouts, buffers, and security limits.
 *
 * These constants define secure defaults for TLS operations and can be
 * overridden before including this header. Enforces TLS 1.3-only policy,
 * modern ciphers, and protection against common attacks (DoS, overflows).
 * Provides stubs when TLS support is disabled (@ref SOCKET_HAS_TLS).
 *
 * ## Key Categories
 *
 * ### Protocol Control
 * - Protocol versions pinned to TLS 1.3 for forward secrecy and anti-downgrade
 * protection
 *
 * ### Cipher Security
 * - Modern AEAD+PFS cipher suites (ECDHE with AES-GCM/ChaCha20-Poly1305)
 *
 * ### Timeout & Resource Limits
 * - Defaults prevent slowloris attacks, buffer overflows, excessive memory use
 * - Configurable via #define overrides
 *
 * ### Customization
 * - Override constants before #include for environment-specific tuning
 *
 * ## Override Pattern
 *
 * @code{.c}
 * // Example: Faster handshake for internal networks, prefer ChaCha20
 * #define SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS 10000
 * #define SOCKET_TLS13_CIPHERSUITES
 * "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256" #include
 * "SocketTLSConfig.h"
 * @endcode
 *
 * @note Overrides are compile-time; changes require recompilation.
 * @warning Validate custom settings with tools like testssl.sh or Qualys SSL
 * Labs; improper config weakens security.
 * @complexity Compile-time constants - no runtime overhead
 *
 * @{
 *
 * @see SocketTLSConfig_T for runtime configuration structure.
 * @see SocketTLS_config_defaults() for initializing structures with these
 * defaults.
 * @see @ref SocketTLSContext_T for applying configs to TLS contexts.
 * @see SocketDTLSConfig.h for DTLS variant constants.
 * @see Individual @ref tls_config constants for detailed security rationale
 * and usage.
 */

/**
 * @brief TLS configuration parameters for customizing TLS protocol versions
 * and other settings.
 * @ingroup security
 *
 * This structure allows fine-grained control over TLS behavior, starting with
 * protocol version limits. Additional fields for cipher suites, timeouts,
 * certificate policies, etc., will be added in future releases. Always
 * initialize with SocketTLS_config_defaults() before use to ensure secure
 * defaults.
 *
 * Fields are set to secure defaults by SocketTLS_config_defaults(), but can be
 * overridden for custom policies. Use with SocketTLSContext_new() for applying
 * to new contexts.
 *
 * @threadsafe Yes - plain value struct; safe to read, copy, or assign between
 * threads.
 *
 * ## Fields
 *
 * | Field       | Type | Description                                      |
 * Default                          |
 * |-------------|------|--------------------------------------------------|----------------------------------|
 * | min_version | int  | Minimum supported TLS protocol version (OpenSSL
 * constant like TLS1_3_VERSION) | SOCKET_TLS_MIN_VERSION | | max_version | int
 * | Maximum supported TLS protocol version           | SOCKET_TLS_MAX_VERSION
 * |
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Secure defaults (recommended)
 * SocketTLSConfig_T config;
 * SocketTLS_config_defaults(&config);
 *
 * // Optional customization (use cautiously)
 * // config.min_version = TLS1_2_VERSION; // Only if required for legacy
 *
 * SocketTLSContext_T ctx = SocketTLSContext_new(&config);
 * // ... use ctx to secure sockets ...
 * SocketTLSContext_free(&ctx);
 * @endcode
 *
 * @note Current API focuses on protocol versions; expansions planned for
 * ciphers, timeouts, etc.
 * @warning Lowering version limits exposes to known vulnerabilities; maintain
 * TLS1.3 where possible.
 * @complexity O(1) - simple struct assignment
 *
 * @see SocketTLS_config_defaults() for setting secure defaults.
 * @see SocketTLSContext_new() for context creation with this config.
 * @see @ref tls_config for constants used in defaults and overrides.
 * @see @ref security for comprehensive TLS security features.
 */
struct SocketTLSConfig_T
{
  /** Minimum supported TLS protocol version (e.g., TLS1_3_VERSION).
   * Default value set by SocketTLS_config_defaults() to SOCKET_TLS_MIN_VERSION
   * (TLS1_3_VERSION).
   * @see SOCKET_TLS_MIN_VERSION
   */
  int min_version;
  /** Maximum supported TLS protocol version (e.g., TLS1_3_VERSION).
   * Default value set by SocketTLS_config_defaults() to SOCKET_TLS_MAX_VERSION
   * (TLS1_3_VERSION).
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
 * Populates the structure with safe defaults: sets min_version and max_version
 * to TLS 1.3 (SOCKET_TLS_MIN_VERSION == SOCKET_TLS_MAX_VERSION),
 * zero-initializes other fields. This enforces a strict TLS 1.3-only policy by
 * default, disabling legacy protocols for enhanced security against downgrade
 * attacks.
 *
 * No-op if config is NULL (no exception raised).
 *
 * @param[in] config Pointer to SocketTLSConfig_T structure to initialize.
 * Ignored if NULL.
 * @return void
 *
 * @throws None - no exceptions raised, handles invalid input gracefully.
 *
 * @threadsafe Yes - pure function with no shared state or side effects; safe
 * from any thread.
 *
 * ## Defaults Set
 *
 * | Field       | Value Set                             |
 * |-------------|---------------------------------------|
 * | min_version | SOCKET_TLS_MIN_VERSION (TLS1_3_VERSION)|
 * | max_version | SOCKET_TLS_MAX_VERSION (TLS1_3_VERSION)|
 * | other fields| 0 (zero-initialized)                  |
 *
 * ## Usage Example
 *
 * @code{.c}
 * SocketTLSConfig_T config;
 * SocketTLS_config_defaults(&config);
 *
 * // Create custom context with secure defaults
 * SocketTLSContext_T ctx = SocketTLSContext_new(&config);
 * if (ctx) {
 *     // Use context to secure sockets, e.g.:
 *     // SocketTLS_enable(sock, ctx);
 *     SocketTLSContext_free(&ctx);
 * }
 * @endcode
 *
 * @note Future versions will set additional defaults for ciphers, timeouts,
 * cert policies, etc.
 * @warning Defaults prioritize security; custom changes may reduce protection
 * if not careful.
 * @complexity O(1) - simple struct field assignments
 *
 * @see SocketTLSConfig_T for structure details and fields.
 * @see SocketTLSContext_new() to create contexts using this configuration.
 * @see @ref tls_config for constants defining the secure defaults.
 * @see @ref security "Security Modules" for TLS security overview.
 */
extern void SocketTLS_config_defaults (SocketTLSConfig_T *config);

#if SOCKET_HAS_TLS

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* ============================================================================
 * TLS Protocol Versions
 * ============================================================================
 */

/**
 * @brief Minimum TLS protocol version - STRICT TLS 1.3 ONLY
 * @ingroup tls_config
 *
 * Enforces TLS 1.3 minimum for perfect forward secrecy (PFS) and modern
 * cryptographic primitives. Legacy protocols (SSL 2.0/3.0, TLS 1.0/1.1/1.2)
 * are explicitly disabled to prevent downgrade attacks (e.g., Logjam, FREAK)
 * and ensure high security posture against known vulnerabilities.
 *
 * Used as default for SocketTLSConfig_T::min_version and applied via
 * SocketTLSContext_set_min_protocol().
 *
 * ## Override Example
 *
 * @code{.c}
 * // Allow TLS 1.2+ for legacy server compatibility (less secure)
 * #define SOCKET_TLS_MIN_VERSION TLS1_2_VERSION
 * #include "SocketTLSConfig.h"
 * @endcode
 *
 * @warning Overriding to versions below TLS1.3 exposes connections to
 * deprecated ciphers, weaker key exchanges, and known attacks (e.g., POODLE,
 * Lucky13, BEAST). Use only for unavoidable legacy interop; prefer upgrades.
 * @note TLS1.3 provides 0-RTT resumption (with caveats), improved handshake,
 * and mandatory PFS.
 * @complexity Compile-time constant
 *
 * @see SOCKET_TLS_MAX_VERSION for maximum version pairing.
 * @see SocketTLSConfig_T::min_version for runtime configuration field.
 * @see SocketTLSContext_set_min_protocol() for context-specific setting.
 * @see
 * https://owasp.org/www-project-cheat-sheets/cheat_sheets/TLS_Cipher_String_Cheat_Sheet
 * for cipher guidance.
 * @see docs/SECURITY.md#tls-versions for detailed version security analysis.
 */
#define SOCKET_TLS_MIN_VERSION TLS1_3_VERSION

/**
 * @brief Maximum TLS protocol version - STRICT TLS 1.3 ONLY
 * @ingroup tls_config
 *
 * Limits maximum protocol to TLS 1.3 to ensure consistent security and prevent
 * use of future potentially insecure versions until vetted. Currently TLS 1.4
 * is undefined in OpenSSL. Paired with min_version for strict TLS1.3-only
 * enforcement by default.
 *
 * Used as default for SocketTLSConfig_T::max_version and applied via
 * SocketTLSContext_set_max_protocol().
 *
 * ## Override Example
 *
 * @code{.c}
 * // Not typically needed, but for future-proofing (hypothetical)
 * #define SOCKET_TLS_MAX_VERSION 0x0304  // TLS 1.4 if defined later
 * #include "SocketTLSConfig.h"
 * @endcode
 *
 * @note Raising max_version requires OpenSSL support and security review of
 * new protocols.
 * @warning Allowing future versions without validation risks unknown
 * vulnerabilities.
 * @complexity Compile-time constant
 *
 * @see SOCKET_TLS_MIN_VERSION for minimum version pairing.
 * @see SocketTLSConfig_T::max_version for runtime field.
 * @see SocketTLSContext_set_max_protocol() for context setting.
 * @see docs/SECURITY.md#tls-versions for version policy recommendations.
 */
#define SOCKET_TLS_MAX_VERSION TLS1_3_VERSION

/* ============================================================================
 * TLS Cipher Suites
 * ============================================================================
 */

/**
 * @brief TLS 1.3 Modern Cipher Suites (ECDHE-PFS only, AEAD ciphers)
 * @ingroup tls_config
 *
 * Modern cipher suites providing perfect forward secrecy (ECDHE key exchange)
 * and authenticated encryption with associated data (AEAD modes). Prioritizes
 * ChaCha20-Poly1305 for systems without AES-NI hardware acceleration, ensuring
 * strong performance and security across devices.
 *
 * Order preference: AES-256-GCM (maximum security), ChaCha20-Poly1305
 * (mobile/ARM optimized), AES-128-GCM (balanced compatibility).
 *
 * Excludes legacy/insecure options:
 * - CBC modes (padding oracle attacks like Lucky13)
 * - RC4 (broken stream cipher)
 * - 3DES (weak, small key size)
 * - Static RSA key exchange (no PFS)
 * - Weak hashes (MD5, SHA1)
 *
 * Used internally by SocketTLSContext_new*() functions as default cipher list.
 *
 * ## Override Example
 *
 * @code{.c}
 * // Prefer ChaCha20 for non-AES hardware (e.g., embedded/mobile)
 * #define SOCKET_TLS13_CIPHERSUITES
 * "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
 * #include "SocketTLSConfig.h"
 * @endcode
 *
 * ## Security Properties Table
 *
 * | Suite                      | Key Exchange | Encryption | Integrity | Notes
 * |
 * |----------------------------|--------------|------------|-----------|-------|
 * | TLS_AES_256_GCM_SHA384     | ECDHE        | AES-256-GCM| GCM       |
 * Highest security, AES-NI accelerated | | TLS_CHACHA20_POLY1305_SHA256 |
 * ECDHE      | ChaCha20   | Poly1305  | Software-friendly, resistant to timing
 * attacks | | TLS_AES_128_GCM_SHA256     | ECDHE        | AES-128-GCM| GCM |
 * Good balance, widely supported |
 *
 * @warning Custom orders/lists must maintain PFS+AEAD; validate with openssl
 * ciphers -v or ssllabs.com. Removing suites may reduce compatibility; adding
 * insecure ones compromises security.
 * @note TLS1.3 mandates PFS and AEAD, eliminating many legacy issues.
 * @complexity Compile-time string constant
 *
 * @see SocketTLSContext_set_cipher_list() for runtime override on contexts.
 * @see https://wiki.mozilla.org/Security/Server_Side_TLS for Mozilla
 * guidelines (intermediate+ profile).
 * @see https://www.ssllabs.com/ssltest/ for server configuration testing.
 * @see docs/SECURITY.md#ciphersuites for library-specific recommendations.
 * @see @ref tls_config for related constants like timeouts and buffers.
 */
#define SOCKET_TLS13_CIPHERSUITES                                             \
  "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_"      \
  "SHA256"

/* ============================================================================
 * TLS Timeout Configuration
 * ============================================================================
 */

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
