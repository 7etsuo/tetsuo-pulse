/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDTLSCONFIG_INCLUDED
#define SOCKETDTLSCONFIG_INCLUDED

/**
 * @file SocketDTLSConfig.h
 * @ingroup security
 * @brief DTLS configuration constants and secure defaults.
 *
 * Defines secure defaults for DTLS operations: protocol versions, MTU
 * settings, cookie protection parameters, timeouts, and limits. Provides stub
 * definitions when TLS disabled for compilation without OpenSSL.
 *
 * All constants can be overridden before including this header.
 * Enforces DTLS 1.2 minimum for security (DTLS 1.3 when OpenSSL 3.2+ widely
 * available).
 *
 * @threadsafe Yes - compile-time constants
 *
 * @see @ref SocketDTLSContext_T for DTLS context management.
 * @see @ref SocketDTLS_T for DTLS socket operations.
 * @see @ref SocketTLSConfig.h for TLS configuration constants.
 *
 * References:
 * - RFC 6347: Datagram Transport Layer Security Version 1.2
 * - RFC 9147: The Datagram Transport Layer Security (DTLS) Protocol
 * Version 1.3
 */

/**
 * @defgroup dtls_config DTLS Configuration Constants
 * @ingroup security
 * @brief Secure default constants for DTLS protocol parameters, MTU
 * management, cookie protection, timeouts, and DoS protection limits.
 *
 * These constants can be overridden before including this header and provide
 * stubs when TLS is disabled. Enforces DTLS 1.2 minimum with support for 1.3
 * when available.
 *
 * @see SocketDTLS.h for the DTLS socket API.
 * @see SocketDTLSContext.h for context configuration.
 * @{
 */

#if SOCKET_HAS_TLS

#include <openssl/ssl.h>

/**
 * @brief Minimum supported DTLS protocol version.
 * @ingroup dtls_config
 * @details Enforces DTLS 1.2 minimum (DTLS1_2_VERSION) for security equivalent
 * to TLS 1.2. Override only for legacy compatibility (not recommended).
 * @see SOCKET_DTLS_MAX_VERSION
 * @see RFC 6347 for DTLS 1.2 specification.
 */
#ifndef SOCKET_DTLS_MIN_VERSION
#define SOCKET_DTLS_MIN_VERSION DTLS1_2_VERSION
#endif

/**
 * @brief Maximum supported DTLS protocol version.
 * @ingroup dtls_config
 * @details Defaults to highest available (DTLS 1.3 if supported by OpenSSL,
 * else 1.2).
 * @see SOCKET_DTLS_MIN_VERSION
 * @see DTLS1_3_VERSION OpenSSL constant for DTLS 1.3.
 */
#ifndef SOCKET_DTLS_MAX_VERSION
#if defined(DTLS1_3_VERSION)
#define SOCKET_DTLS_MAX_VERSION DTLS1_3_VERSION
#else
#define SOCKET_DTLS_MAX_VERSION DTLS1_2_VERSION
#endif
#endif

/**
 * @brief Preferred DTLS ciphersuites string for secure configuration.
 * @ingroup dtls_config
 * @details Prioritizes ECDHE with AEAD ciphers (GCM, ChaCha20-Poly1305) for
 * forward secrecy and performance. Excludes legacy CBC, RC4, 3DES, and non-PFS
 * ciphers for security. Format compatible with OpenSSL
 * SSL_CTX_set_cipher_list() or SSL_set_cipher_list().
 * @see "ECDHE-ECDSA-AES256-GCM-SHA384" etc. for individual suites.
 * @see OpenSSL documentation for ciphersuite strings.
 */
#ifndef SOCKET_DTLS_CIPHERSUITES
#define SOCKET_DTLS_CIPHERSUITES   \
  "ECDHE-ECDSA-AES256-GCM-SHA384:" \
  "ECDHE-RSA-AES256-GCM-SHA384:"   \
  "ECDHE-ECDSA-CHACHA20-POLY1305:" \
  "ECDHE-RSA-CHACHA20-POLY1305:"   \
  "ECDHE-ECDSA-AES128-GCM-SHA256:" \
  "ECDHE-RSA-AES128-GCM-SHA256"
#endif

/* Default MTU - conservative for IPv6 tunnels and VPNs */
/**
 * @brief Default MTU for DTLS path.
 * @ingroup dtls_config
 * @details Conservative value (1400 bytes) to avoid fragmentation in IPv6
 * tunnels, VPNs, and networks with overhead. Adjust based on path MTU
 * discovery for optimal performance.
 * @see SOCKET_DTLS_MIN_MTU
 * @see SOCKET_DTLS_MAX_MTU
 * @see RFC 6347 Section 4.2.5 for MTU recommendations.
 */
#ifndef SOCKET_DTLS_DEFAULT_MTU
#define SOCKET_DTLS_DEFAULT_MTU 1400
#endif

/* Minimum MTU - IPv4 minimum reassembly buffer (RFC 791) */
/**
 * @brief Minimum allowable MTU value.
 * @ingroup dtls_config
 * @details IPv4 minimum reassembly buffer size (576 bytes) per RFC 791.
 * Ensures compatibility with legacy networks.
 * @see SOCKET_DTLS_DEFAULT_MTU
 */
#ifndef SOCKET_DTLS_MIN_MTU
#define SOCKET_DTLS_MIN_MTU 576
#endif

/* Maximum MTU - jumbo frames (rare but supported) */
/**
 * @brief Maximum allowable MTU value.
 * @ingroup dtls_config
 * @details Supports jumbo frames (9000 bytes), though rare in practice.
 * Used for validation of user-provided MTU values.
 * @see SOCKET_DTLS_MIN_MTU
 * @see socket_util_round_up_pow2() for power-of-2 alignment if needed.
 */
#ifndef SOCKET_DTLS_MAX_MTU
#define SOCKET_DTLS_MAX_MTU 9000
#endif

/**
 * @brief Maximum size of a single DTLS record in bytes.
 * @ingroup dtls_config
 * @details Matches TLS maximum record size of 16384 bytes per RFC 6347
 * Section 4.2.3. Used for internal buffer sizing to accommodate full records
 * without truncation.
 * @see SOCKET_DTLS_MAX_PAYLOAD for effective application data limit after
 * overhead.
 * @see RFC 6347 "Datagram Transport Layer Security Version 1.2" for record
 * layer details.
 */
#ifndef SOCKET_DTLS_MAX_RECORD_SIZE
#define SOCKET_DTLS_MAX_RECORD_SIZE 16384
#endif

/**
 * @brief Estimated overhead bytes per DTLS record for conservative buffer
 * sizing.
 * @ingroup dtls_config
 * @details Includes 13-byte record header, variable MAC (up to 20 bytes),
 * explicit IV, padding, etc. Conservative 64-byte estimate accounts for
 * worst-case scenarios across ciphersuites. Used in payload calculations to
 * prevent fragmentation.
 * @see SOCKET_DTLS_MAX_PAYLOAD for computed max application data.
 * @see RFC 6347 Section 4.2.3 for record format and overhead details.
 */
#ifndef SOCKET_DTLS_RECORD_OVERHEAD
#define SOCKET_DTLS_RECORD_OVERHEAD 64
#endif

/**
 * @brief Maximum application data payload per DTLS record using default MTU.
 * @ingroup dtls_config
 * @details Computed as (default MTU - record overhead - 28 bytes for IPv4/UDP
 * headers). Ensures packets fit within default MTU without IP fragmentation.
 * Actual value depends on network path MTU; use path MTU discovery for
 * optimization.
 * @see SOCKET_DTLS_DEFAULT_MTU
 * @see SOCKET_DTLS_RECORD_OVERHEAD
 * @see RFC 6347 Section 4.2.5 "Path MTU" for fragmentation avoidance.
 */
#ifndef SOCKET_DTLS_MAX_PAYLOAD
#define SOCKET_DTLS_MAX_PAYLOAD \
  (SOCKET_DTLS_DEFAULT_MTU - SOCKET_DTLS_RECORD_OVERHEAD - 28)
#endif

/* Cookie length - HMAC-SHA256 truncated output */
/**
 * @brief Length of DTLS hello cookie in bytes.
 * @ingroup dtls_config
 * @details Fixed to 32 bytes (4-byte timestamp + truncated HMAC-SHA256 tag) for
 * security and compatibility.
 * @see RFC 6347 Section 4.2.1 for cookie exchange mechanism.
 */
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

/* Initial retransmission timeout in milliseconds */
/**
 * @brief Initial retransmission timeout for DTLS handshake packets (ms).
 * @ingroup dtls_config
 * @details Starts at 1000ms with exponential backoff per RFC 6347.
 * Used by OpenSSL internal timer for lost packet retransmission.
 * @see SOCKET_DTLS_MAX_TIMEOUT_MS
 */
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

/* Default shutdown timeout (total time allowed for graceful shutdown) */
/**
 * @brief Default timeout for DTLS shutdown operation (ms).
 * @ingroup dtls_config
 * @details Timeout for graceful close_notify exchange during shutdown.
 * Conservative 5000ms (5 seconds) accounts for network latency and
 * retransmissions. Used by SocketDTLS_shutdown() internal timeout.
 * @see SocketDTLS_shutdown() for shutdown operation details.
 * @see SOCKET_DTLS_MAX_TIMEOUT_MS for maximum retransmission timeout.
 */
#ifndef SOCKET_DTLS_DEFAULT_SHUTDOWN_TIMEOUT_MS
#define SOCKET_DTLS_DEFAULT_SHUTDOWN_TIMEOUT_MS 5000
#endif

/**
 * @brief Poll interval during DTLS shutdown (ms).
 * @details Interval between poll() calls when waiting for close_notify
 * during graceful shutdown. Shorter intervals provide faster response
 * but increase CPU usage.
 */
#ifndef SOCKET_DTLS_SHUTDOWN_POLL_INTERVAL_MS
#define SOCKET_DTLS_SHUTDOWN_POLL_INTERVAL_MS 1000
#endif

/* Maximum number of retransmissions before giving up */
#ifndef SOCKET_DTLS_MAX_RETRANSMITS
#define SOCKET_DTLS_MAX_RETRANSMITS 12
#endif

/* Maximum number of cached sessions */
#ifndef SOCKET_DTLS_SESSION_CACHE_SIZE
#define SOCKET_DTLS_SESSION_CACHE_SIZE 1000
#endif

/* Default session timeout in seconds */
#ifndef SOCKET_DTLS_SESSION_TIMEOUT_DEFAULT
#define SOCKET_DTLS_SESSION_TIMEOUT_DEFAULT 300L
#endif

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

/* Peer resolution cache TTL in milliseconds */
#ifndef SOCKET_DTLS_PEER_CACHE_TTL_MS
#define SOCKET_DTLS_PEER_CACHE_TTL_MS 30000
#endif

/* Maximum size for certificate/key/CA files (prevents memory exhaustion from
 * oversized inputs) */
#ifndef SOCKET_DTLS_MAX_FILE_SIZE
#define SOCKET_DTLS_MAX_FILE_SIZE ((size_t)(1ULL << 20)) /* 1MB */
#endif

/**
 * @brief Validate if given MTU value is within acceptable range.
 * @ingroup dtls_config
 * @param mtu The MTU value to validate.
 * @return 1 if valid (between SOCKET_DTLS_MIN_MTU and SOCKET_DTLS_MAX_MTU), 0
 * otherwise.
 * @see SOCKET_DTLS_MIN_MTU
 * @see SOCKET_DTLS_MAX_MTU
 */
#define SOCKET_DTLS_VALID_MTU(mtu) \
  ((size_t)(mtu) >= SOCKET_DTLS_MIN_MTU && (size_t)(mtu) <= SOCKET_DTLS_MAX_MTU)

/**
 * @brief Validate if given timeout value is reasonable.
 * @ingroup dtls_config
 * @param ms Timeout in milliseconds.
 * @return 1 if valid (>=0 and <= SOCKET_DTLS_MAX_TIMEOUT_MS), 0 otherwise.
 * @see SOCKET_DTLS_MAX_TIMEOUT_MS
 */
#define SOCKET_DTLS_VALID_TIMEOUT(ms) \
  ((int)(ms) >= 0 && (int)(ms) <= SOCKET_DTLS_MAX_TIMEOUT_MS)

#else /* SOCKET_HAS_TLS not defined */

/**
 * @brief Stub definitions for DTLS configuration constants when TLS support is
 * disabled.
 * @ingroup security
 * @details These compile-time stubs enable header inclusion and conditional
 * compilation without OpenSSL dependency. Values are set to safe zeros or
 * minimal defaults to prevent misuse in disabled mode. Do not use these values
 * for protocol operations.
 * @see dtls_config group documentation for enabled-mode constants and details.
 * @see SocketDTLSConfig.h main documentation for full configuration reference.
 */
#define SOCKET_DTLS_MIN_VERSION 0
#define SOCKET_DTLS_MAX_VERSION 0
#define SOCKET_DTLS_DEFAULT_MTU 1400
#define SOCKET_DTLS_COOKIE_LEN 32
#define SOCKET_DTLS_ERROR_BUFSIZE 512

#endif /* SOCKET_HAS_TLS */
/**
 * @} */ /* dtls_config */

#endif
