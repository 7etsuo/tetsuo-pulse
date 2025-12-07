#ifndef SOCKETDTLSCONFIG_INCLUDED
#define SOCKETDTLSCONFIG_INCLUDED

/**
 * SocketDTLSConfig.h - DTLS Configuration Constants
 *
 * Defines secure defaults for DTLS operations: protocol versions, MTU settings,
 * cookie protection parameters, timeouts, and limits. Provides stub typedefs
 * when TLS disabled for compilation without OpenSSL.
 *
 * All constants can be overridden before including this header.
 * Enforces DTLS 1.2 minimum for security (DTLS 1.3 when OpenSSL 3.2+ widely available).
 *
 * Thread-safe: Yes - compile-time constants
 *
 * References:
 * - RFC 6347: Datagram Transport Layer Security Version 1.2
 * - RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
 */

#if SOCKET_HAS_TLS

#include <openssl/ssl.h>

/* ============================================================================
 * DTLS Protocol Versions
 * ============================================================================
 * DTLS 1.2 minimum (RFC 6347) - equivalent security to TLS 1.2
 * DTLS 1.3 (RFC 9147) requires OpenSSL 3.2+ which is not yet widely deployed
 */

#ifndef SOCKET_DTLS_MIN_VERSION
#define SOCKET_DTLS_MIN_VERSION DTLS1_2_VERSION
#endif

#ifndef SOCKET_DTLS_MAX_VERSION
#if defined(DTLS1_3_VERSION)
#define SOCKET_DTLS_MAX_VERSION DTLS1_3_VERSION
#else
#define SOCKET_DTLS_MAX_VERSION DTLS1_2_VERSION
#endif
#endif

/* ============================================================================
 * DTLS Ciphersuites
 * ============================================================================
 * Modern AEAD ciphers with forward secrecy (ECDHE key exchange)
 * Excludes legacy ciphers (CBC, RC4, 3DES, non-PFS)
 */

#ifndef SOCKET_DTLS_CIPHERSUITES
#define SOCKET_DTLS_CIPHERSUITES                                               \
  "ECDHE-ECDSA-AES256-GCM-SHA384:"                                             \
  "ECDHE-RSA-AES256-GCM-SHA384:"                                               \
  "ECDHE-ECDSA-CHACHA20-POLY1305:"                                             \
  "ECDHE-RSA-CHACHA20-POLY1305:"                                               \
  "ECDHE-ECDSA-AES128-GCM-SHA256:"                                             \
  "ECDHE-RSA-AES128-GCM-SHA256"
#endif

/* ============================================================================
 * MTU and Buffer Sizes
 * ============================================================================
 * DTLS requires careful MTU management to avoid IP fragmentation
 * which can cause packet loss and performance degradation.
 *
 * Path MTU discovery is recommended but not always reliable over UDP.
 * Conservative defaults ensure interoperability.
 */

/* Default MTU - conservative for IPv6 tunnels and VPNs */
#ifndef SOCKET_DTLS_DEFAULT_MTU
#define SOCKET_DTLS_DEFAULT_MTU 1400
#endif

/* Minimum MTU - IPv4 minimum reassembly buffer (RFC 791) */
#ifndef SOCKET_DTLS_MIN_MTU
#define SOCKET_DTLS_MIN_MTU 576
#endif

/* Maximum MTU - jumbo frames (rare but supported) */
#ifndef SOCKET_DTLS_MAX_MTU
#define SOCKET_DTLS_MAX_MTU 9000
#endif

/* Maximum DTLS record size (same as TLS) */
#ifndef SOCKET_DTLS_MAX_RECORD_SIZE
#define SOCKET_DTLS_MAX_RECORD_SIZE 16384
#endif

/* DTLS record overhead (header + MAC + padding worst case) */
#ifndef SOCKET_DTLS_RECORD_OVERHEAD
#define SOCKET_DTLS_RECORD_OVERHEAD 64
#endif

/* Maximum application data per record (MTU - overhead - IP/UDP headers) */
#ifndef SOCKET_DTLS_MAX_PAYLOAD
#define SOCKET_DTLS_MAX_PAYLOAD                                                \
  (SOCKET_DTLS_DEFAULT_MTU - SOCKET_DTLS_RECORD_OVERHEAD - 28)
#endif

/* ============================================================================
 * Cookie Protection (RFC 6347 Section 4.2.1)
 * ============================================================================
 * Stateless cookie exchange prevents memory exhaustion DoS attacks.
 * Server sends HelloVerifyRequest with cookie before allocating state.
 * Client must echo cookie to prove address ownership.
 *
 * Cookie = HMAC-SHA256(server_secret, client_addr || client_port || timestamp)
 */

/* Cookie length - HMAC-SHA256 truncated output */
#ifndef SOCKET_DTLS_COOKIE_LEN
#define SOCKET_DTLS_COOKIE_LEN 32
#endif

/* Secret key length for cookie HMAC */
#ifndef SOCKET_DTLS_COOKIE_SECRET_LEN
#define SOCKET_DTLS_COOKIE_SECRET_LEN 32
#endif

/* Cookie validity period in seconds
 * Short enough to prevent replay, long enough for slow clients */
#ifndef SOCKET_DTLS_COOKIE_LIFETIME_SEC
#define SOCKET_DTLS_COOKIE_LIFETIME_SEC 60
#endif

/* Maximum number of simultaneous pending cookie exchanges */
#ifndef SOCKET_DTLS_MAX_PENDING_COOKIES
#define SOCKET_DTLS_MAX_PENDING_COOKIES 1000
#endif

/* ============================================================================
 * Handshake Timeouts and Retransmission
 * ============================================================================
 * DTLS handshake uses exponential backoff retransmission timer.
 * RFC 6347 recommends initial timeout of 1 second.
 * OpenSSL handles retransmission internally, but we expose for configuration.
 */

/* Initial retransmission timeout in milliseconds */
#ifndef SOCKET_DTLS_INITIAL_TIMEOUT_MS
#define SOCKET_DTLS_INITIAL_TIMEOUT_MS 1000
#endif

/* Maximum retransmission timeout (after exponential backoff) */
#ifndef SOCKET_DTLS_MAX_TIMEOUT_MS
#define SOCKET_DTLS_MAX_TIMEOUT_MS 60000
#endif

/* Default handshake timeout (total time allowed for handshake) */
#ifndef SOCKET_DTLS_DEFAULT_HANDSHAKE_TIMEOUT_MS
#define SOCKET_DTLS_DEFAULT_HANDSHAKE_TIMEOUT_MS 30000
#endif

/* Maximum number of retransmissions before giving up */
#ifndef SOCKET_DTLS_MAX_RETRANSMITS
#define SOCKET_DTLS_MAX_RETRANSMITS 12
#endif

/* ============================================================================
 * Session Management
 * ============================================================================
 * Session resumption reduces handshake latency (1-RTT vs 2-RTT).
 * Similar to TLS session caching.
 */

/* Maximum number of cached sessions */
#ifndef SOCKET_DTLS_SESSION_CACHE_SIZE
#define SOCKET_DTLS_SESSION_CACHE_SIZE 1000
#endif

/* Default session timeout in seconds */
#ifndef SOCKET_DTLS_SESSION_TIMEOUT_DEFAULT
#define SOCKET_DTLS_SESSION_TIMEOUT_DEFAULT 300L
#endif

/* ============================================================================
 * Error Buffer and Limits
 * ============================================================================
 */

/* DTLS error buffer size for detailed error messages */
#ifndef SOCKET_DTLS_ERROR_BUFSIZE
#define SOCKET_DTLS_ERROR_BUFSIZE 512
#endif

/* OpenSSL error string buffer size for temporary error formatting */
#ifndef SOCKET_DTLS_OPENSSL_ERRSTR_BUFSIZE
#define SOCKET_DTLS_OPENSSL_ERRSTR_BUFSIZE 256
#endif

/* Maximum certificate chain depth */
#ifndef SOCKET_DTLS_MAX_CERT_CHAIN_DEPTH
#define SOCKET_DTLS_MAX_CERT_CHAIN_DEPTH 10
#endif

/* Maximum SNI hostname length */
#ifndef SOCKET_DTLS_MAX_SNI_LEN
#define SOCKET_DTLS_MAX_SNI_LEN 255
#endif

/* Maximum ALPN protocol string length */
#ifndef SOCKET_DTLS_MAX_ALPN_LEN
#define SOCKET_DTLS_MAX_ALPN_LEN 255
#endif

/* Maximum number of ALPN protocols */
#ifndef SOCKET_DTLS_MAX_ALPN_PROTOCOLS
#define SOCKET_DTLS_MAX_ALPN_PROTOCOLS 16
#endif

/* Maximum file path length for certificates/keys */
#ifndef SOCKET_DTLS_MAX_PATH_LEN
#define SOCKET_DTLS_MAX_PATH_LEN 4096
#endif

/* ============================================================================
 * File Size Limits (DoS Protection)
 * ============================================================================
 */
/* Maximum size for certificate/key/CA files (prevents memory exhaustion from oversized inputs) */
#ifndef SOCKET_DTLS_MAX_FILE_SIZE
#define SOCKET_DTLS_MAX_FILE_SIZE ((size_t)(1ULL << 20))  /* 1MB */
#endif

/* ============================================================================
 * Validation Macros
 * ============================================================================
 */

#define SOCKET_DTLS_VALID_MTU(mtu)                                             \
  ((size_t) (mtu) >= SOCKET_DTLS_MIN_MTU                                       \
   && (size_t) (mtu) <= SOCKET_DTLS_MAX_MTU)

#define SOCKET_DTLS_VALID_TIMEOUT(ms)                                          \
  ((int) (ms) >= 0 && (int) (ms) <= SOCKET_DTLS_MAX_TIMEOUT_MS)

#else /* SOCKET_HAS_TLS not defined */

/* Stub definitions when DTLS is disabled */
#define SOCKET_DTLS_MIN_VERSION 0
#define SOCKET_DTLS_MAX_VERSION 0
#define SOCKET_DTLS_DEFAULT_MTU 1400
#define SOCKET_DTLS_COOKIE_LEN 32
#define SOCKET_DTLS_ERROR_BUFSIZE 512

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETDTLSCONFIG_INCLUDED */

