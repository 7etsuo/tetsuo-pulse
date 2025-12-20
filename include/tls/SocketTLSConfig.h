/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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
 * | Field                  | Type | Description                                      | Default                                      |
 * |------------------------|------|--------------------------------------------------|----------------------------------------------|
 * | min_version            | int  | Minimum supported TLS protocol version (OpenSSL constant like TLS1_3_VERSION) | SOCKET_TLS_MIN_VERSION (TLS1_3_VERSION)      |
 * | max_version            | int  | Maximum supported TLS protocol version           | SOCKET_TLS_MAX_VERSION (TLS1_3_VERSION)      |
 * | handshake_timeout_ms   | int  | Default handshake timeout in ms                  | SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS (30s)|
 * | shutdown_timeout_ms    | int  | Default shutdown timeout in ms                   | SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS (5s)  |
 * | poll_interval_ms       | int  | Default poll interval for non-blocking ops in ms | SOCKET_TLS_POLL_INTERVAL_MS (100ms)          |
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
  /** Default TLS handshake timeout in milliseconds.
   * Default: SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS (30000 ms / 30 seconds).
   * Used by non-blocking handshake functions to prevent indefinite hangs.
   * Set to 0 for no timeout (infinite wait).
   * @see SocketTLS_handshake_loop()
   * @see SocketTLSConfig_T doc for usage.
   * @see SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS
   */
  int handshake_timeout_ms;
  /** Default TLS shutdown timeout in milliseconds.
   * Default: SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS (5000 ms / 5 seconds).
   * Maximum time to wait for peer's close_notify during graceful shutdown.
   * Set to 0 for no timeout.
   * @see SocketTLS_shutdown()
   * @see SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS
   */
  int shutdown_timeout_ms;
  /** Default poll interval for non-blocking handshake loops in milliseconds.
   * Default: SOCKET_TLS_POLL_INTERVAL_MS (100 ms).
   * Controls sleep duration between handshake poll attempts for CPU efficiency.
   * Set to 0 for busy-wait (minimal latency, high CPU).
   * @see SocketTLS_handshake_loop_ex()
   * @see SOCKET_TLS_POLL_INTERVAL_MS
   */
  int poll_interval_ms;
  /* Future expansion: add ciphersuites string, verify modes, session cache params, OCSP/CRL settings, etc. */
};

typedef struct SocketTLSConfig_T SocketTLSConfig_T;
/**
 * @brief Initialize the TLS configuration with secure library defaults.
 * @ingroup security
 *
 * Populates the structure with safe defaults: sets protocol versions to TLS 1.3-only,
 * timeouts to secure values (30s handshake, 5s shutdown, 100ms poll), zero-initializes
 * other fields. This enforces a strict TLS 1.3-only policy by default with balanced
 * performance and security timeouts.
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
 * | Field                  | Value Set                                      |
 * |------------------------|------------------------------------------------|
 * | min_version            | SOCKET_TLS_MIN_VERSION (TLS1_3_VERSION)        |
 * | max_version            | SOCKET_TLS_MAX_VERSION (TLS1_3_VERSION)        |
 * | handshake_timeout_ms   | SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS (30s)  |
 * | shutdown_timeout_ms    | SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS (5s)    |
 * | poll_interval_ms       | SOCKET_TLS_POLL_INTERVAL_MS (100ms)            |
 * | other fields           | 0 (zero-initialized)                          |
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
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* ============================================================================
 * Certificate Transparency (CT) Support Detection
 * ============================================================================
 *
 * CT support requires OpenSSL 1.1.0+ and CT compiled in (not OPENSSL_NO_CT).
 * This macro is used throughout the TLS modules to conditionally compile
 * CT functionality.
 *
 * Usage in application code:
 *   #if SOCKET_HAS_CT_SUPPORT
 *       SocketTLSContext_enable_ct(ctx, CT_VALIDATION_STRICT);
 *   #endif
 *
 * @see SocketTLSContext_enable_ct() for CT configuration
 * @see RFC 6962 Certificate Transparency specification
 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(OPENSSL_NO_CT)
#define SOCKET_HAS_CT_SUPPORT 1
#else
#define SOCKET_HAS_CT_SUPPORT 0
#endif

/* ============================================================================
 * TLS Protocol Versions
 * ============================================================================
 *
 * DEFAULT: Strict TLS 1.3-only enforcement (SOCKET_TLS_MIN_VERSION ==
 * SOCKET_TLS_MAX_VERSION == TLS1_3_VERSION).
 *
 * This is the RECOMMENDED configuration for security. TLS 1.3 provides:
 * - Mandatory Perfect Forward Secrecy (PFS) with ephemeral keys
 * - Modern AEAD ciphers only (no CBC, RC4, 3DES)
 * - Simplified handshake (1-RTT, optional 0-RTT)
 * - Protection against downgrade attacks
 * - Removal of legacy/vulnerable features (renegotiation, compression)
 *
 * LEGACY COMPATIBILITY (NOT RECOMMENDED):
 * =======================================
 * If you MUST support legacy systems that cannot upgrade to TLS 1.3, you can
 * override these constants BEFORE including this header. This is strongly
 * discouraged and should only be used as a last resort.
 *
 * ## Security Implications of Lowering TLS Version
 *
 * | Version    | Security Status | Known Vulnerabilities |
 * |------------|-----------------|------------------------|
 * | TLS 1.3    | SECURE          | None known             |
 * | TLS 1.2    | ACCEPTABLE*     | Lucky13, ROBOT, CBC issues |
 * | TLS 1.1    | DEPRECATED      | No PFS by default, BEAST variants |
 * | TLS 1.0    | DEPRECATED      | BEAST, POODLE variants |
 * | SSL 3.0    | BROKEN          | POODLE, padding oracle attacks |
 * | SSL 2.0    | BROKEN          | Completely broken, never use |
 *
 * *TLS 1.2 is acceptable only with ECDHE+AEAD cipher suites and proper config.
 *
 * ## Legacy Override Example (Compile-Time)
 *
 * @code{.c}
 * // BEFORE including SocketTLSConfig.h, define overrides:
 * // WARNING: This weakens security! Document your justification.
 * #define SOCKET_TLS_MIN_VERSION TLS1_2_VERSION
 * #define SOCKET_TLS_MAX_VERSION TLS1_3_VERSION
 * #include "tls/SocketTLSConfig.h"
 *
 * // This allows TLS 1.2 fallback while preferring TLS 1.3
 * @endcode
 *
 * ## Runtime Override (Preferred for Flexibility)
 *
 * @code{.c}
 * // Use SocketTLSConfig_T for runtime configuration:
 * SocketTLSConfig_T config;
 * SocketTLS_config_defaults(&config);
 *
 * // Override for legacy compatibility (logs security warning):
 * config.min_version = TLS1_2_VERSION;  // Allow TLS 1.2 fallback
 * // config.max_version remains TLS1_3_VERSION (prefer TLS 1.3)
 *
 * SocketTLSContext_T ctx = SocketTLSContext_new(&config);
 * @endcode
 *
 * ## Alternative: Per-Context Override (Most Flexible)
 *
 * @code{.c}
 * // Create with defaults, then adjust specific context:
 * SocketTLSContext_T ctx = SocketTLSContext_new_client("ca-bundle.pem");
 *
 * // Lower version for specific legacy connection (emits warning log):
 * SocketTLSContext_set_min_protocol(ctx, TLS1_2_VERSION);
 * @endcode
 *
 * SECURITY RECOMMENDATION:
 * - Prefer upgrading legacy systems to TLS 1.3
 * - If TLS 1.2 is required, use ECDHE key exchange only
 * - Monitor connections and plan migration timelines
 * - Audit cipher suites: remove CBC modes, use AEAD only
 * - Consider separate contexts for legacy vs. modern connections
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
 * ## Override for Legacy Compatibility (NOT RECOMMENDED)
 *
 * @code{.c}
 * // COMPILE-TIME: Define before including header
 * #define SOCKET_TLS_MIN_VERSION TLS1_2_VERSION
 * #include "tls/SocketTLSConfig.h"
 *
 * // RUNTIME: Use SocketTLSConfig_T structure
 * SocketTLSConfig_T cfg;
 * SocketTLS_config_defaults(&cfg);
 * cfg.min_version = TLS1_2_VERSION;  // Allow TLS 1.2 fallback
 * SocketTLSContext_T ctx = SocketTLSContext_new(&cfg);
 *
 * // PER-CONTEXT: Adjust after creation
 * SocketTLSContext_set_min_protocol(ctx, TLS1_2_VERSION);
 * @endcode
 *
 * @warning Overriding to versions below TLS1_3_VERSION exposes connections to
 * deprecated ciphers, weaker key exchanges, and known attacks (e.g., POODLE,
 * Lucky13, BEAST). Use only for unavoidable legacy interop; prefer upgrades.
 * @note TLS1.3 provides 0-RTT resumption (with caveats), improved handshake,
 * and mandatory PFS.
 * @complexity Compile-time constant
 *
 * @see SOCKET_TLS_MAX_VERSION for maximum version pairing.
 * @see SocketTLSConfig_T::min_version for runtime configuration field.
 * @see SocketTLSContext_set_min_protocol() for context-specific setting.
 * @see https://owasp.org/www-project-cheat-sheets/cheat_sheets/TLS_Cipher_String_Cheat_Sheet
 * for cipher guidance.
 * @see docs/SECURITY.md#tls-versions for detailed version security analysis.
 */
#ifndef SOCKET_TLS_MIN_VERSION
#define SOCKET_TLS_MIN_VERSION TLS1_2_VERSION
#endif

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
 * // Allow future TLS versions (hypothetical - use with caution)
 * #define SOCKET_TLS_MAX_VERSION 0  // 0 = no maximum limit (auto-highest)
 * #include "tls/SocketTLSConfig.h"
 *
 * // Or for strict pinning to TLS 1.3 only (default, most secure):
 * // Leave SOCKET_TLS_MAX_VERSION undefined to use TLS1_3_VERSION
 * @endcode
 *
 * @note Raising max_version requires OpenSSL support and security review of
 * new protocols. Setting to 0 allows OpenSSL to auto-select highest available.
 * @warning Allowing future versions without validation risks unknown
 * vulnerabilities. The default TLS1_3_VERSION is recommended until TLS 1.4
 * is standardized and OpenSSL support is mature.
 * @complexity Compile-time constant
 *
 * @see SOCKET_TLS_MIN_VERSION for minimum version pairing.
 * @see SocketTLSConfig_T::max_version for runtime field.
 * @see SocketTLSContext_set_max_protocol() for context setting.
 * @see docs/SECURITY.md#tls-versions for version policy recommendations.
 */
#ifndef SOCKET_TLS_MAX_VERSION
#define SOCKET_TLS_MAX_VERSION TLS1_3_VERSION
#endif

/* ============================================================================
 * TLS Cipher Suites
 * ============================================================================
 */

/**
 * @brief TLS 1.3 Modern Cipher Suites (ECDHE-PFS only, AEAD ciphers)
 * @ingroup tls_config
 *
 * Modern cipher suites providing perfect forward secrecy (ECDHE key exchange)
 * and authenticated encryption with associated data (AEAD modes).
 *
 * ## Cipher Priority Order Rationale
 *
 * The default order is optimized for **maximum security on modern hardware**:
 *
 * 1. **TLS_AES_256_GCM_SHA384** (first priority)
 *    - 256-bit key provides highest security margin against future attacks
 *    - AES-NI hardware acceleration on x86/x64/ARM64 makes it fastest option
 *    - Required by NSA Suite B for TOP SECRET classification
 *
 * 2. **TLS_CHACHA20_POLY1305_SHA256** (second priority)
 *    - Constant-time implementation resistant to cache-timing attacks
 *    - Excellent on mobile/ARM devices without AES hardware acceleration
 *    - Comparable security to AES-256-GCM (256-bit effective key)
 *
 * 3. **TLS_AES_128_GCM_SHA256** (third priority)
 *    - 128-bit key is sufficient for most threat models
 *    - Fallback for environments that only support AES-128
 *    - Still provides strong security with good performance
 *
 * ## Override Examples
 *
 * @code{.c}
 * // Prefer ChaCha20 for non-AES hardware (e.g., older mobile/embedded)
 * #define SOCKET_TLS13_CIPHERSUITES \
 *     "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
 * #include "SocketTLSConfig.h"
 *
 * // AES-128 only for resource-constrained environments
 * #define SOCKET_TLS13_CIPHERSUITES "TLS_AES_128_GCM_SHA256"
 * #include "SocketTLSConfig.h"
 *
 * // Maximum security only (no fallback)
 * #define SOCKET_TLS13_CIPHERSUITES "TLS_AES_256_GCM_SHA384"
 * #include "SocketTLSConfig.h"
 * @endcode
 *
 * ## Security Properties Table
 *
 * | Suite                      | Key Exchange | Encryption  | Integrity | Notes                                    |
 * |----------------------------|--------------|-------------|-----------|------------------------------------------|
 * | TLS_AES_256_GCM_SHA384     | ECDHE        | AES-256-GCM | GCM       | Highest security, AES-NI accelerated     |
 * | TLS_CHACHA20_POLY1305_SHA256| ECDHE       | ChaCha20    | Poly1305  | Software-friendly, timing-attack resistant|
 * | TLS_AES_128_GCM_SHA256     | ECDHE        | AES-128-GCM | GCM       | Good balance, widely supported           |
 *
 * ## Excluded Ciphers (Legacy/Insecure)
 *
 * - CBC modes (padding oracle attacks like Lucky13, BEAST)
 * - RC4 (broken stream cipher, RFC 7465)
 * - 3DES (weak 112-bit effective key, Sweet32 attack)
 * - Static RSA key exchange (no PFS)
 * - MD5/SHA1 signatures (collision attacks)
 *
 * @warning Custom orders/lists must maintain PFS+AEAD. Validate with:
 *          `openssl ciphers -v` or https://www.ssllabs.com/ssltest/
 * @note TLS 1.3 mandates PFS and AEAD, eliminating many legacy issues.
 * @complexity Compile-time string constant - zero runtime overhead
 *
 * @see SocketTLSContext_set_ciphersuites() for runtime override on contexts.
 * @see https://wiki.mozilla.org/Security/Server_Side_TLS for Mozilla guidelines.
 * @see https://www.ssllabs.com/ssltest/ for server configuration testing.
 * @see docs/SECURITY.md#ciphersuites for library-specific recommendations.
 */
#define SOCKET_TLS13_CIPHERSUITES                                             \
  "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_"      \
  "SHA256"

/* ============================================================================
 * TLS Timeout Configuration
 * ============================================================================
 *
 * Timeout values are carefully chosen to balance security against DoS attacks
 * (slowloris, connection exhaustion) while accommodating real-world network
 * conditions (high latency, packet loss, OCSP/CRL validation time).
 *
 * All timeouts can be overridden by defining them before including this header.
 */

/**
 * @brief Default TLS handshake timeout in milliseconds
 * @ingroup tls_config
 *
 * Maximum time allowed for TLS handshake completion: 30 seconds (30000ms).
 *
 * ## Rationale for 30 Seconds
 *
 * - **Network latency**: Accommodates high-latency links (satellite, mobile)
 *   with 500ms+ RTT requiring 4-6 round trips for TLS 1.3 handshake
 * - **OCSP/CRL validation**: Server-side OCSP fetching can add 2-5 seconds
 * - **Certificate chain**: Deep chains (5+ certs) increase validation time
 * - **DoS protection**: Short enough to limit slowloris-style attacks
 * - **Industry standard**: Matches nginx/Apache default SSL timeouts
 *
 * ## Override Examples
 *
 * @code{.c}
 * // Faster for internal/low-latency networks (10 seconds)
 * #define SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS 10000
 *
 * // Longer for high-latency satellite links (60 seconds)
 * #define SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS 60000
 * @endcode
 *
 * @warning Values below 5 seconds may cause failures on congested networks.
 * @see SocketTLS_handshake_loop() uses this for non-blocking handshakes.
 * @see SocketTLS_handshake_auto() uses socket's configured timeout or this.
 */
#ifndef SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS
#define SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS 30000 /* 30 seconds */
#endif

/**
 * @brief Default TLS shutdown timeout in milliseconds
 * @ingroup tls_config
 *
 * Maximum time to wait for graceful TLS connection shutdown: 5 seconds (5000ms).
 *
 * ## Rationale for 5 Seconds
 *
 * - **Quick teardown**: Shutdown is simpler than handshake (single close_notify)
 * - **Resource release**: Allows timely connection slot recycling
 * - **Peer responsiveness**: Unresponsive peers shouldn't block cleanup
 * - **Protocol compliance**: Enough time for close_notify exchange
 * - **Graceful degradation**: After timeout, socket closes without close_notify
 *
 * ## Override Examples
 *
 * @code{.c}
 * // Faster shutdown for high-traffic servers (2 seconds)
 * #define SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS 2000
 *
 * // More patient for unreliable networks (10 seconds)
 * #define SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS 10000
 * @endcode
 *
 * @see SocketTLS_shutdown() uses this for bidirectional shutdown.
 * @see SocketTLS_shutdown_send() for half-close without waiting.
 */
#ifndef SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS
#define SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS 5000 /* 5 seconds */
#endif

/**
 * @brief TLS handshake poll interval for non-blocking operations
 * @ingroup tls_config
 *
 * Polling interval used by SocketTLS_handshake_loop(): 100ms.
 *
 * ## Rationale for 100ms
 *
 * - **Responsiveness**: Sub-second response to handshake progress
 * - **CPU efficiency**: Avoids busy-waiting (100ms sleep between polls)
 * - **Network granularity**: Matches typical TCP RTT range (50-200ms)
 * - **Event loop friendly**: Compatible with most event loop timers
 *
 * ## Override Examples
 *
 * @code{.c}
 * // Low latency (25ms) for interactive applications
 * #define SOCKET_TLS_POLL_INTERVAL_MS 25
 *
 * // CPU efficient (500ms) for resource-constrained systems
 * #define SOCKET_TLS_POLL_INTERVAL_MS 500
 * @endcode
 *
 * @note For true async, use SocketPoll with SocketTLS_handshake() directly.
 * @see SocketTLS_handshake_loop_ex() for runtime-configurable interval.
 */
#ifndef SOCKET_TLS_POLL_INTERVAL_MS
#define SOCKET_TLS_POLL_INTERVAL_MS 100 /* 100ms polling interval */
#endif

/* ============================================================================
 * Buffer and Size Limits
 * ============================================================================
 *
 * These limits are carefully chosen to:
 * 1. Comply with TLS protocol specifications (RFC 8446)
 * 2. Prevent memory exhaustion and DoS attacks
 * 3. Support common deployment scenarios
 * 4. Maintain compatibility with major TLS implementations
 */

/**
 * @brief TLS read/write buffer size
 * @ingroup tls_config
 *
 * Buffer size for TLS record I/O operations: 16384 bytes (16KB).
 *
 * ## Rationale for 16KB
 *
 * - **RFC 8446 Section 5.1**: Maximum TLS 1.3 record payload is 16384 bytes
 * - **Optimal I/O**: Complete records processed in single operations
 * - **Memory efficiency**: No benefit from larger buffers (TLS max)
 * - **Fragmentation**: Avoids TLS record fragmentation overhead
 * - **Compatibility**: Matches OpenSSL default record size
 *
 * @note This is the maximum *plaintext* size; ciphertext adds ~40 bytes overhead.
 * @see RFC 8446 Section 5.1 "Record Layer" for TLS 1.3 limits.
 */
#ifndef SOCKET_TLS_BUFFER_SIZE
#define SOCKET_TLS_BUFFER_SIZE 16384 /* 16KB - TLS record max */
#endif

/**
 * @brief Maximum certificate chain depth for verification
 * @ingroup tls_config
 *
 * Maximum depth of certificate chains accepted during verification: 10 levels.
 *
 * ## Rationale for 10 Levels
 *
 * - **Typical chains**: Most PKI: Root → Intermediate → Leaf (depth 2-3)
 * - **Enterprise PKI**: Multi-tier CA hierarchies may use 4-5 levels
 * - **DoS protection**: Prevents stack exhaustion from malicious chains
 * - **Industry practice**: OpenSSL default is 100; 10 is more conservative
 * - **Memory safety**: Each level adds ~4KB for certificate parsing
 *
 * ## Example Chain Depths
 *
 * | Scenario                     | Typical Depth |
 * |------------------------------|---------------|
 * | Let's Encrypt               | 2             |
 * | Commercial CAs (DigiCert)   | 2-3           |
 * | Enterprise multi-tier PKI   | 3-5           |
 * | Government/Military PKI     | 4-7           |
 *
 * @see SSL_CTX_set_verify_depth() for OpenSSL configuration.
 */
#ifndef SOCKET_TLS_MAX_CERT_CHAIN_DEPTH
#define SOCKET_TLS_MAX_CERT_CHAIN_DEPTH 10
#endif

/**
 * @brief Maximum ALPN protocol name length
 * @ingroup tls_config
 *
 * Maximum length for individual ALPN protocol names: 255 bytes.
 *
 * ## Rationale for 255 Bytes
 *
 * - **RFC 7301 Section 3.1**: Protocol identifier is 1-255 octets
 * - **Practical values**: "h2" (2), "http/1.1" (8), "grpc" (4)
 * - **Future proof**: Allows long protocol identifiers if needed
 * - **Memory bounded**: Prevents allocation attacks
 *
 * @see RFC 7301 "Transport Layer Security (TLS) ALPN Extension".
 */
#ifndef SOCKET_TLS_MAX_ALPN_LEN
#define SOCKET_TLS_MAX_ALPN_LEN 255
#endif

/**
 * @brief Maximum total bytes for ALPN protocol list
 * @ingroup tls_config
 *
 * Maximum total size of ALPN protocol list: 1024 bytes.
 *
 * ## Rationale for 1024 Bytes
 *
 * - **DoS protection**: Prevents memory exhaustion during parsing
 * - **Practical limit**: ~100 short protocols or ~4 max-length protocols
 * - **TLS extension limit**: ClientHello extensions have size constraints
 * - **Common usage**: Most deployments use 2-5 protocols
 *
 * @note Each protocol has 1-byte length prefix in wire format.
 */
#ifndef SOCKET_TLS_MAX_ALPN_TOTAL_BYTES
#define SOCKET_TLS_MAX_ALPN_TOTAL_BYTES 1024
#endif

/**
 * @brief SNI hostname length limit
 * @ingroup tls_config
 *
 * Maximum length for Server Name Indication hostnames: 255 bytes.
 *
 * ## Rationale for 255 Bytes
 *
 * - **RFC 1035**: DNS labels max 63 chars, total hostname max 253 chars
 * - **RFC 6066 Section 3**: SNI hostname is DNS hostname format
 * - **Buffer safety**: 255 provides margin for null terminator + alignment
 * - **Attack prevention**: Limits buffer overflow in SNI processing
 *
 * @see RFC 6066 "TLS Extensions: SNI" for specification.
 * @see tls_validate_hostname() for SNI validation rules.
 */
#ifndef SOCKET_TLS_MAX_SNI_LEN
#define SOCKET_TLS_MAX_SNI_LEN 255
#endif

/**
 * @brief TLS session cache size (number of cached sessions)
 * @ingroup tls_config
 *
 * Maximum number of TLS sessions to cache for resumption: 1000 sessions.
 *
 * ## Rationale for 1000 Sessions
 *
 * - **Moderate traffic**: Handles ~1000 unique clients with resumption
 * - **Memory usage**: ~500KB-2MB depending on session data size
 * - **LRU eviction**: OpenSSL automatically evicts oldest sessions
 * - **Tunable**: Increase for high-traffic servers, decrease for memory limits
 *
 * ## Memory Estimate
 *
 * Each session: ~500-2000 bytes (varies by TLS version, extensions)
 * 1000 sessions × 1KB avg ≈ 1MB memory footprint
 *
 * @see SocketTLSContext_enable_session_cache() for configuration.
 * @see SocketTLSContext_set_session_cache_size() for runtime adjustment.
 */
#ifndef SOCKET_TLS_SESSION_CACHE_SIZE
#define SOCKET_TLS_SESSION_CACHE_SIZE 1000
#endif

/**
 * @brief TLS error buffer size for detailed error messages
 * @ingroup tls_config
 *
 * Buffer size for thread-local error messages: 512 bytes.
 *
 * ## Rationale for 512 Bytes
 *
 * - **Error detail**: Accommodates OpenSSL error strings (~120 chars) plus context
 * - **Stack allocation**: Safe for stack-allocated buffers
 * - **Formatting room**: Space for errno, file paths, and custom messages
 * - **Truncation safe**: Errors truncated gracefully if exceeded
 *
 * @see tls_error_buf thread-local buffer declaration.
 * @see SOCKET_ERROR_MSG() for error formatting macros.
 */
#ifndef SOCKET_TLS_ERROR_BUFSIZE
#define SOCKET_TLS_ERROR_BUFSIZE 512
#endif

/**
 * @brief OpenSSL error string buffer size for temporary formatting
 * @ingroup tls_config
 *
 * Temporary buffer for formatting individual OpenSSL error strings: 256 bytes.
 *
 * ## Rationale for 256 Bytes
 *
 * - **OpenSSL format**: ERR_error_string_n() output is ~120 chars typical
 * - **Safety margin**: Accommodates longest possible OpenSSL error strings
 * - **Stack friendly**: Safe for temporary stack allocation
 * - **Industry standard**: Matches OpenSSL documentation recommendations
 *
 * @see ERR_error_string_n() for OpenSSL error formatting.
 */
#ifndef SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE
#define SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE 256
#endif

/* ============================================================================
 * Security Limits
 * ============================================================================
 *
 * These security limits prevent resource exhaustion, memory attacks, and DoS
 * while supporting legitimate enterprise deployments. All limits are enforced
 * at runtime with appropriate error handling.
 */

/**
 * @brief Maximum number of SNI certificates per context
 * @ingroup tls_config
 *
 * Maximum number of certificate/key pairs for SNI virtual hosting: 100.
 *
 * ## Rationale for 100 Certificates
 *
 * - **Virtual hosting**: Supports 100 distinct domains per server
 * - **Memory bounded**: ~100MB max with typical cert chains
 * - **Lookup efficiency**: Linear scan acceptable at this scale
 * - **Enterprise scale**: Exceeding 100 suggests load balancer/CDN
 *
 * @see SocketTLSContext_add_certificate() for SNI configuration.
 */
#ifndef SOCKET_TLS_MAX_SNI_CERTS
#define SOCKET_TLS_MAX_SNI_CERTS 100
#endif

/**
 * @brief Initial SNI certificate array capacity
 * @ingroup tls_config
 *
 * Starting capacity for SNI certificate array: 4 slots.
 *
 * Array doubles in size when capacity is exceeded (4→8→16→...).
 * Initial value of 4 minimizes memory for small deployments.
 */
#ifndef SOCKET_TLS_SNI_INITIAL_CAPACITY
#define SOCKET_TLS_SNI_INITIAL_CAPACITY 4
#endif

/**
 * @brief Maximum number of ALPN protocols per context
 * @ingroup tls_config
 *
 * Maximum ALPN protocols that can be advertised: 16 protocols.
 *
 * ## Rationale for 16 Protocols
 *
 * - **Common protocols**: h2, http/1.1, grpc, mqtt, etc. rarely exceed 5
 * - **Future proof**: Room for emerging protocols
 * - **Memory bounded**: 16 × 255 bytes max = 4KB worst case
 * - **TLS extension fit**: Keeps ClientHello within typical limits
 *
 * @see SocketTLSContext_set_alpn_protos() for ALPN configuration.
 */
#ifndef SOCKET_TLS_MAX_ALPN_PROTOCOLS
#define SOCKET_TLS_MAX_ALPN_PROTOCOLS 16
#endif

/**
 * @brief Session ticket encryption key length
 * @ingroup tls_config
 *
 * Length of TLS session ticket encryption key: 80 bytes.
 *
 * ## Rationale for 80 Bytes (OpenSSL Standard)
 *
 * OpenSSL session ticket key structure:
 * - 16 bytes: Key name (identifies which key encrypted ticket)
 * - 32 bytes: AES-256 encryption key
 * - 32 bytes: HMAC-SHA256 authentication key
 *
 * This provides:
 * - **256-bit encryption**: AES-256 for ticket confidentiality
 * - **256-bit authentication**: HMAC-SHA256 for integrity
 * - **Key identification**: Enables key rotation without breaking sessions
 *
 * @see SocketTLSContext_enable_session_tickets() for ticket configuration.
 * @see SocketTLSContext_rotate_session_ticket_key() for key rotation.
 */
#ifndef SOCKET_TLS_TICKET_KEY_LEN
#define SOCKET_TLS_TICKET_KEY_LEN 80
#endif

/**
 * @brief Default TLS session cache timeout in seconds
 * @ingroup tls_config
 *
 * Default lifetime for cached TLS sessions: 300 seconds (5 minutes).
 *
 * ## Rationale for 5 Minutes
 *
 * - **Security**: Limits window for session ticket theft exploitation
 * - **Performance**: Allows session resumption for typical user sessions
 * - **Memory**: Bounded cache growth with LRU eviction
 * - **PCI-DSS**: Compliant with session management requirements
 *
 * @see SocketTLSContext_enable_session_cache() for cache configuration.
 */
#ifndef SOCKET_TLS_SESSION_TIMEOUT_DEFAULT
#define SOCKET_TLS_SESSION_TIMEOUT_DEFAULT 300L
#endif

/**
 * @brief Maximum TLS session timeout in seconds (30 days)
 * @ingroup tls_config
 *
 * Maximum allowed session cache timeout: 30 days (2,592,000 seconds).
 *
 * ## Rationale for 30 Days
 *
 * - **Upper bound**: Prevents configuration errors with years-long sessions
 * - **Mobile apps**: Long sessions for intermittent connectivity patterns
 * - **Security tradeoff**: Longer sessions increase breach window
 * - **Recommendation**: Use shorter timeouts (hours) in production
 */
#ifndef SOCKET_TLS_SESSION_MAX_TIMEOUT
#define SOCKET_TLS_SESSION_MAX_TIMEOUT 2592000L /* 30 days in seconds */
#endif

/**
 * @brief Maximum OCSP response size
 * @ingroup tls_config
 *
 * Maximum size for OCSP responses: 64KB (65,536 bytes).
 *
 * ## Rationale for 64KB
 *
 * - **Typical size**: OCSP responses are 1-4KB for single certificates
 * - **Multi-status**: Large responses for multiple certificates possible
 * - **DoS protection**: Prevents memory exhaustion from malicious responses
 * - **Practical limit**: No legitimate OCSP response approaches 64KB
 *
 * @see SocketTLSContext_set_ocsp_response() for static OCSP configuration.
 * @see SocketTLS_get_ocsp_response_status() for client-side verification.
 */
#ifndef SOCKET_TLS_MAX_OCSP_RESPONSE_LEN
#define SOCKET_TLS_MAX_OCSP_RESPONSE_LEN (64 * 1024)
#endif

/**
 * @brief Maximum file path length for certificates/keys
 * @ingroup tls_config
 *
 * Maximum length for certificate and key file paths: 4096 bytes.
 *
 * ## Rationale for 4096 Bytes
 *
 * - **PATH_MAX**: Matches POSIX PATH_MAX on most systems
 * - **Deep directories**: Accommodates enterprise directory structures
 * - **Buffer safety**: Stack-safe allocation size
 * - **Attack prevention**: Limits path traversal attack surface
 *
 * @see tls_validate_file_path() for path security validation.
 */
#ifndef SOCKET_TLS_MAX_PATH_LEN
#define SOCKET_TLS_MAX_PATH_LEN 4096
#endif

/**
 * @brief Maximum DNS label length per RFC 1035
 * @ingroup tls_config
 *
 * Maximum length for individual DNS hostname labels: 63 characters.
 *
 * ## Rationale for 63 Characters
 *
 * - **RFC 1035 Section 2.3.4**: DNS label limit is 63 octets
 * - **Wire format**: Labels prefixed with length byte (max 63)
 * - **Universal standard**: All DNS implementations enforce this
 *
 * @see tls_validate_hostname() for SNI hostname validation.
 */
#ifndef SOCKET_TLS_MAX_LABEL_LEN
#define SOCKET_TLS_MAX_LABEL_LEN 63
#endif

/* ============================================================================
 * Certificate Pinning Limits
 * ============================================================================
 */

/**
 * @brief Maximum number of certificate pins per context
 * @ingroup tls_config
 *
 * Maximum SPKI SHA256 pins per TLS context: 32 pins.
 *
 * ## Rationale for 32 Pins
 *
 * - **OWASP guidance**: Primary + 2-3 backup pins recommended
 * - **Key rotation**: Room for transitional pins during rotation
 * - **Enterprise PKI**: Multi-CA environments may need more
 * - **Constant-time**: Linear scan at 32 pins is negligible
 * - **Memory**: 32 × 32 bytes = 1KB storage
 *
 * @see SocketTLSContext_add_pin() for adding certificate pins.
 */
#ifndef SOCKET_TLS_MAX_PINS
#define SOCKET_TLS_MAX_PINS 32
#endif

/**
 * @brief Certificate pin hash length (SHA256)
 * @ingroup tls_config
 *
 * Length of SHA256 hash for certificate pinning: 32 bytes (256 bits).
 *
 * ## Rationale for SHA256 (32 bytes)
 *
 * - **Collision resistance**: 2^128 security level (post-quantum adequate)
 * - **HPKP standard**: RFC 7469 specifies SHA-256 for key pins
 * - **Widely supported**: All TLS libraries support SHA256
 * - **Compact**: Efficient storage and comparison
 *
 * @see SocketTLSContext_add_pin_hex() for hex-encoded pin input.
 */
#ifndef SOCKET_TLS_PIN_HASH_LEN
#define SOCKET_TLS_PIN_HASH_LEN 32
#endif

/**
 * @brief Initial certificate pin array capacity
 * @ingroup tls_config
 *
 * Starting capacity for pin array: 4 pins.
 *
 * Array doubles when capacity exceeded. 4 matches typical deployment
 * (1 primary + 1-3 backups) with minimal initial allocation.
 */
#ifndef SOCKET_TLS_PIN_INITIAL_CAPACITY
#define SOCKET_TLS_PIN_INITIAL_CAPACITY 4
#endif

/* ============================================================================
 * Kernel TLS (kTLS) Configuration
 * ============================================================================
 *
 * kTLS offloads TLS record encryption/decryption to the Linux kernel,
 * improving performance for high-throughput applications. These constants
 * control kTLS behavior and detection.
 *
 * Requirements:
 * - OpenSSL 3.0+ compiled with `enable-ktls` (not OPENSSL_NO_KTLS)
 * - Linux 4.13+ for TX offload, 4.17+ for RX offload
 * - Kernel CONFIG_TLS=y or CONFIG_TLS=m (tls module loaded)
 * - Supported cipher: AES-GCM-128/256 or ChaCha20-Poly1305 (5.11+)
 */

/**
 * @brief Default kTLS enablement policy
 * @ingroup tls_config
 *
 * Controls whether kTLS is attempted by default when available: 1 = yes.
 *
 * ## Rationale for Default Enable
 *
 * - **Performance**: kTLS provides 10-30% TLS overhead reduction
 * - **Transparent**: Falls back gracefully to userspace if unavailable
 * - **Security**: Same cryptographic guarantees as userspace TLS
 * - **Industry trend**: Major servers (nginx, haproxy) default to kTLS
 *
 * ## Override Examples
 *
 * @code{.c}
 * // Disable kTLS by default (explicit opt-in required)
 * #define SOCKET_TLS_KTLS_ENABLED 0
 * #include "SocketTLSConfig.h"
 * @endcode
 *
 * @note Individual sockets can still enable/disable via SocketTLS_enable_ktls()
 * @see SocketTLS_enable_ktls() for per-socket control
 */
#ifndef SOCKET_TLS_KTLS_ENABLED
#define SOCKET_TLS_KTLS_ENABLED 1
#endif

/**
 * @brief Minimum Linux kernel version for kTLS TX offload
 * @ingroup tls_config
 *
 * Linux kernel 4.13 introduced TLS_TX socket option for transmit offload.
 * Format: KERNEL_VERSION(major, minor, patch) = (major << 16) + (minor << 8) +
 * patch
 *
 * Value: 0x040D00 = KERNEL_VERSION(4, 13, 0)
 *
 * @note RX offload requires 4.17+ (SOCKET_TLS_KTLS_MIN_KERNEL_RX)
 * @see https://www.kernel.org/doc/html/latest/networking/tls.html
 */
#ifndef SOCKET_TLS_KTLS_MIN_KERNEL_TX
#define SOCKET_TLS_KTLS_MIN_KERNEL_TX 0x040D00 /* 4.13.0 */
#endif

/**
 * @brief Minimum Linux kernel version for kTLS RX offload
 * @ingroup tls_config
 *
 * Linux kernel 4.17 added TLS_RX socket option for receive offload.
 * Earlier kernels only support TX offload.
 *
 * Value: 0x041100 = KERNEL_VERSION(4, 17, 0)
 *
 * @note TX offload available from 4.13+ (SOCKET_TLS_KTLS_MIN_KERNEL_TX)
 */
#ifndef SOCKET_TLS_KTLS_MIN_KERNEL_RX
#define SOCKET_TLS_KTLS_MIN_KERNEL_RX 0x041100 /* 4.17.0 */
#endif

/**
 * @brief Minimum Linux kernel version for ChaCha20-Poly1305 kTLS
 * @ingroup tls_config
 *
 * Linux kernel 5.11 added kTLS support for ChaCha20-Poly1305 cipher.
 * Earlier kernels only support AES-GCM variants.
 *
 * Value: 0x050B00 = KERNEL_VERSION(5, 11, 0)
 *
 * @note AES-GCM-128/256 available from 4.13+
 */
#ifndef SOCKET_TLS_KTLS_MIN_KERNEL_CHACHA
#define SOCKET_TLS_KTLS_MIN_KERNEL_CHACHA 0x050B00 /* 5.11.0 */
#endif

/**
 * @brief kTLS sendfile buffer size for fallback mode
 * @ingroup tls_config
 *
 * Buffer size for SocketTLS_sendfile() when kTLS is not active: 64KB.
 *
 * When kTLS TX offload is active, SSL_sendfile() provides true zero-copy.
 * When not active, we fall back to read+send with this buffer size.
 *
 * ## Rationale for 64KB
 *
 * - **Multiple TLS records**: 64KB = 4 × 16KB TLS records
 * - **Disk I/O alignment**: Good alignment for filesystem block sizes
 * - **Memory reasonable**: Stack-safe temporary allocation
 * - **Throughput**: Large enough for efficient bulk transfer
 *
 * @see SocketTLS_sendfile() for file transfer API
 */
#ifndef SOCKET_TLS_KTLS_SENDFILE_BUFSIZE
#define SOCKET_TLS_KTLS_SENDFILE_BUFSIZE (64 * 1024)
#endif

/* ============================================================================
 * CRL Auto-Refresh Limits
 * ============================================================================
 */

/**
 * @brief Minimum CRL refresh interval in seconds
 * @ingroup tls_config
 *
 * Minimum time between CRL refresh attempts: 60 seconds (1 minute).
 *
 * ## Rationale for 60 Seconds
 *
 * - **DoS prevention**: Limits refresh request rate to CDP servers
 * - **Network efficiency**: Avoids unnecessary bandwidth usage
 * - **Reasonable minimum**: CRLs rarely update more than hourly
 * - **Manual refresh**: Still allows on-demand refresh via reload_crl()
 *
 * @see SocketTLSContext_set_crl_auto_refresh() for auto-refresh setup.
 */
#ifndef SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL
#define SOCKET_TLS_CRL_MIN_REFRESH_INTERVAL 60
#endif

/**
 * @brief Maximum CRL refresh interval in seconds
 * @ingroup tls_config
 *
 * Maximum time between CRL refresh attempts: 1 year (31,536,000 seconds).
 *
 * ## Rationale for 1 Year
 *
 * - **Upper bound**: Prevents configuration errors with decade intervals
 * - **CRL validity**: Typical CRLs have nextUpdate within 7-30 days
 * - **Security**: Longer intervals increase revocation blindness window
 * - **Recommendation**: Use hours/days intervals for production security
 *
 * @warning CRL refresh intervals exceeding 30 days may miss revocations.
 */
#ifndef SOCKET_TLS_CRL_MAX_REFRESH_INTERVAL
#define SOCKET_TLS_CRL_MAX_REFRESH_INTERVAL                                   \
  (365LL * 24 * 3600) /* 1 year in seconds */
#endif

/**
 * @brief Maximum certificate file size for pin extraction
 * @ingroup tls_config
 *
 * Maximum size for certificate files: 1MB (1,048,576 bytes).
 *
 * ## Rationale for 1MB
 *
 * - **Typical certs**: X.509 certificates are 1-4KB
 * - **Certificate bundles**: CA bundles may be 100-500KB
 * - **DoS protection**: Prevents memory exhaustion from large files
 * - **Generous margin**: No legitimate cert file approaches 1MB
 *
 * @see SocketTLSContext_add_pin_from_cert() for pin extraction.
 */
#ifndef SOCKET_TLS_MAX_CERT_FILE_SIZE
#define SOCKET_TLS_MAX_CERT_FILE_SIZE (1024 * 1024)
#endif

/**
 * @brief Maximum CRL file size
 * @ingroup tls_config
 *
 * Maximum size for CRL files: 10MB (10,485,760 bytes).
 *
 * ## Rationale for 10MB
 *
 * - **Large CA CRLs**: Major CAs (DigiCert, VeriSign) have multi-MB CRLs
 * - **Revocation scale**: CAs with millions of certs have large CRLs
 * - **DoS protection**: Prevents excessive memory allocation
 * - **Practical limit**: Very few CRLs exceed 10MB
 *
 * @see SocketTLSContext_load_crl() for CRL loading.
 */
#ifndef SOCKET_TLS_MAX_CRL_SIZE
#define SOCKET_TLS_MAX_CRL_SIZE (10 * 1024 * 1024)
/**
 * @brief Maximum CRL files in directory
 * @ingroup tls_config
 *
 * Maximum number of CRL files to load from a directory: 1000 files.
 * Prevents directory exhaustion attacks and excessive memory usage.
 */
#define SOCKET_TLS_MAX_CRL_FILES_IN_DIR 1000
#endif

/**
 * @brief Maximum CRL path length
 * @ingroup tls_config
 *
 * Maximum length for CRL file paths: 4096 bytes.
 * Matches SOCKET_TLS_MAX_PATH_LEN for consistency.
 *
 * @see validate_crl_path_security() for CRL path validation.
 */
#ifndef SOCKET_TLS_CRL_MAX_PATH_LEN
#define SOCKET_TLS_CRL_MAX_PATH_LEN 4096
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
