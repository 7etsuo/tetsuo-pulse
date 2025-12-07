/**
 * SocketSecurity.h - Centralized Security Configuration and Utilities
 *
 * Part of the Socket Library
 *
 * This header consolidates all security-related configuration, limits,
 * and validation utilities from across the socket library into a single
 * reference point.
 *
 * Features:
 * - Comprehensive documentation of all security limits
 * - Runtime limit query API
 * - Size validation utilities with overflow protection
 * - Security configuration structure for runtime inspection
 *
 * Security Posture:
 * - All limits are compile-time configurable via #ifndef guards
 * - TLS 1.3 only (no legacy protocols)
 * - Strict input validation throughout
 * - Integer overflow protection on all size calculations
 * - Constant-time comparison for security-sensitive operations
 * - Secure memory clearing (resistant to compiler optimization)
 *
 * Thread safety: All functions are thread-safe (no global mutable state).
 *
 * Usage:
 *   #include "core/SocketSecurity.h"
 *
 *   // Query limits at runtime
 *   SocketSecurityLimits limits;
 *   SocketSecurity_get_limits(&limits);
 *
 *   // Validate allocation size
 *   if (!SocketSecurity_check_size(requested_size)) {
 *       // Reject oversized allocation
 *   }
 */

#ifndef SOCKETSECURITY_INCLUDED
#define SOCKETSECURITY_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Except.h"
#include "core/SocketConfig.h"

/* ============================================================================
 * Security Configuration Overview
 * ============================================================================
 *
 * This section documents where security limits are defined. All limits can be
 * overridden at compile time by defining them before including headers.
 *
 * CORE LIMITS (SocketConfig.h):
 *   SOCKET_MAX_CONNECTIONS        - Max connections in pool (10000)
 *   SOCKET_MAX_BUFFER_SIZE        - Max buffer per connection (1MB)
 *   SOCKET_MIN_BUFFER_SIZE        - Min buffer size (512)
 *   SOCKET_MAX_POLL_EVENTS        - Max events per poll (10000)
 *   SOCKET_MAX_LISTEN_BACKLOG     - Max listen backlog (1024)
 *   ARENA_MAX_ALLOC_SIZE          - Max arena allocation (see SOCKET_SECURITY_MAX_ALLOCATION, default 256MB)
 *
 * DNS LIMITS (SocketConfig.h):
 *   SOCKET_DNS_MAX_PENDING        - Max pending DNS requests (1000)
 *   SOCKET_DNS_MAX_LABEL_LENGTH   - Max DNS label length (63)
 *
 * RATE LIMITING (SocketConfig.h):
 *   SOCKET_RATELIMIT_DEFAULT_CONN_PER_SEC  - Connection rate limit (100/s)
 *   SOCKET_RATELIMIT_DEFAULT_BURST         - Burst capacity (50)
 *   SOCKET_RATELIMIT_DEFAULT_MAX_PER_IP    - Per-IP connection limit (10)
 *
 * SYN FLOOD PROTECTION (SocketConfig.h):
 *   SOCKET_SYN_DEFAULT_WINDOW_MS           - Rate measurement window (10s)
 *   SOCKET_SYN_DEFAULT_MAX_PER_WINDOW      - Max attempts per IP (50)
 *   SOCKET_SYN_DEFAULT_GLOBAL_PER_SEC      - Global rate limit (1000/s)
 *   SOCKET_SYN_DEFAULT_MAX_TRACKED_IPS     - Max tracked IPs (100000)
 *
 * TIMEOUT DEFAULTS (SocketConfig.h):
 *   SOCKET_DEFAULT_CONNECT_TIMEOUT_MS      - Connect timeout (30s)
 *   SOCKET_DEFAULT_DNS_TIMEOUT_MS          - DNS timeout (5s)
 *   SOCKET_DEFAULT_IDLE_TIMEOUT            - Idle timeout (5min)
 *   SOCKET_DEFAULT_POLL_TIMEOUT            - Poll timeout (1s)
 *
 * HTTP CORE LIMITS (SocketHTTP.h):
 *   SOCKETHTTP_MAX_HEADER_NAME             - Max header name (256)
 *   SOCKETHTTP_MAX_HEADER_VALUE            - Max header value (8KB)
 *   SOCKETHTTP_MAX_HEADER_SIZE             - Max total headers (64KB)
 *   SOCKETHTTP_MAX_HEADERS                 - Max header count (100)
 *   SOCKETHTTP_MAX_URI_LEN                 - Max URI length (8KB)
 *
 * HTTP/1.1 LIMITS (SocketHTTP1.h):
 *   SOCKETHTTP1_MAX_REQUEST_LINE           - Max request line (8KB)
 *   SOCKETHTTP1_MAX_CHUNK_SIZE             - Max chunk size (16MB)
 *   SOCKETHTTP1_MAX_TRAILER_SIZE           - Max trailer size (4KB)
 *
 * HTTP/2 LIMITS (SocketHTTP2.h):
 *   SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS  - Max streams (100)
 *   SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE          - Max frame (16KB)
 *   SOCKETHTTP2_MAX_MAX_FRAME_SIZE              - Max allowed frame (16MB)
 *   SOCKETHTTP2_DEFAULT_MAX_HEADER_LIST_SIZE    - Max header list (16KB)
 *
 * HPACK LIMITS (SocketHPACK.h):
 *   SOCKETHPACK_MAX_TABLE_SIZE             - Max dynamic table (64KB default)
 *
 * WEBSOCKET LIMITS (SocketWS-private.h):
 *   SOCKETWS_MAX_FRAME_SIZE                - Max frame size (16MB)
 *   SOCKETWS_MAX_MESSAGE_SIZE              - Max message size (64MB)
 *
 * TLS LIMITS (SocketTLSConfig.h):
 *   SOCKET_TLS_MAX_CERT_CHAIN_DEPTH        - Max cert chain (10)
 *   SOCKET_TLS_MAX_ALPN_LEN                - Max ALPN string (255)
 *   SOCKET_TLS_MAX_SNI_LEN                 - Max SNI hostname (255)
 *   SOCKET_TLS_MAX_PINS                    - Max cert pins (32)
 *   SOCKET_TLS_SESSION_CACHE_SIZE          - Session cache (1000)
 *
 * PROXY LIMITS (SocketProxy.h):
 *   SOCKET_PROXY_MAX_HOSTNAME_LEN          - Max proxy hostname (255)
 *   SOCKET_PROXY_MAX_USERNAME_LEN          - Max proxy username (255)
 *   SOCKET_PROXY_MAX_PASSWORD_LEN          - Max proxy password (255)
 */

/* ============================================================================
 * Centralized Security Limits
 * ============================================================================
 * These are convenience aliases that reference the canonical definitions.
 */

/** Maximum allocation size for security checks (256MB default) */
#ifndef SOCKET_SECURITY_MAX_ALLOCATION
#define SOCKET_SECURITY_MAX_ALLOCATION (256UL * 1024 * 1024)
#endif

/** Maximum body size for HTTP requests/responses (100MB default) */
#ifndef SOCKET_SECURITY_MAX_BODY_SIZE
#define SOCKET_SECURITY_MAX_BODY_SIZE (100 * 1024 * 1024)
#endif

/** Maximum request timeout in milliseconds (60s default) */
#ifndef SOCKET_SECURITY_MAX_REQUEST_TIMEOUT_MS
#define SOCKET_SECURITY_MAX_REQUEST_TIMEOUT_MS 60000
#endif

/* ============================================================================
 * Exception Types
 * ============================================================================ */

/**
 * SocketSecurity_SizeExceeded - Allocation or buffer size exceeds limits
 *
 * Raised when:
 * - Requested allocation exceeds SOCKET_SECURITY_MAX_ALLOCATION
 * - Buffer operation would exceed configured limits
 * - Integer overflow detected in size calculation
 */
extern const Except_T SocketSecurity_SizeExceeded;

/**
 * SocketSecurity_ValidationFailed - Input validation failure
 *
 * Raised when:
 * - Input fails security validation checks
 * - Invalid characters detected in protocol data
 */
extern const Except_T SocketSecurity_ValidationFailed;

/* ============================================================================
 * Security Limits Structure
 * ============================================================================ */

/**
 * SocketSecurityLimits - Runtime-queryable security limits
 *
 * Contains all security-relevant limits currently configured in the library.
 * Use SocketSecurity_get_limits() to populate.
 */
typedef struct SocketSecurityLimits
{
  /* Memory limits */
  size_t max_allocation;       /**< Maximum single allocation */
  size_t max_buffer_size;      /**< Maximum buffer size */
  size_t max_connections;      /**< Maximum connections in pool */
  size_t arena_max_alloc_size;      /**< Maximum arena allocation size */

  /* HTTP limits */
  size_t http_max_uri_length;     /**< Maximum URI length */
  size_t http_max_header_name;    /**< Maximum header name length */
  size_t http_max_header_value;   /**< Maximum header value length */
  size_t http_max_header_size;    /**< Maximum total header size */
  size_t http_max_headers;        /**< Maximum header count */
  size_t http_max_body_size;      /**< Maximum body size */

  /* HTTP/1.1 limits */
  size_t http1_max_request_line;  /**< Maximum request/status line */
  size_t http1_max_chunk_size;    /**< Maximum chunk size */

  /* HTTP/2 limits */
  size_t http2_max_concurrent_streams; /**< Maximum concurrent streams */
  size_t http2_max_frame_size;         /**< Maximum frame size */
  size_t http2_max_header_list_size;   /**< Maximum header list size */

  /* TLS ALPN limits (SocketTLSConfig.h) */
  size_t tls_max_alpn_protocols;   /**< Max number of ALPN protocols (SOCKET_TLS_MAX_ALPN_PROTOCOLS=16) */
  size_t tls_max_alpn_len;         /**< Max ALPN protocol string length (SOCKET_TLS_MAX_ALPN_LEN=255) */
  size_t tls_max_alpn_total_bytes; /**< Max total ALPN list size (custom, e.g., 1024 for DoS protection) */
  size_t hpack_max_table_size;   /**< Maximum HPACK dynamic table size */

  /* WebSocket limits */
  size_t ws_max_frame_size;    /**< Maximum WebSocket frame size */
  size_t ws_max_message_size;  /**< Maximum WebSocket message size */

  /* TLS limits */
  size_t tls_max_cert_chain_depth; /**< Maximum certificate chain depth */
  size_t tls_session_cache_size;   /**< TLS session cache size */

  /* Rate limiting */
  size_t ratelimit_conn_per_sec;   /**< Connection rate per second */
  size_t ratelimit_burst;          /**< Burst capacity */
  size_t ratelimit_max_per_ip;     /**< Per-IP connection limit */

  /* Timeouts (milliseconds) */
  int timeout_connect_ms;      /**< Connect timeout */
  int timeout_dns_ms;          /**< DNS resolution timeout */
  int timeout_idle_ms;         /**< Idle connection timeout */
  int timeout_request_ms;      /**< Request timeout */

} SocketSecurityLimits;

/* ============================================================================
 * Limit Query Functions
 * ============================================================================ */

/**
 * SocketSecurity_get_limits - Get current security limits
 * @limits: Output structure to populate
 *
 * Populates the limits structure with all current security-relevant limits.
 * Thread-safe: Yes (reads compile-time constants)
 */
extern void SocketSecurity_get_limits (SocketSecurityLimits *limits);

/**
 * SocketSecurity_get_max_allocation - Get maximum allocation size
 *
 * Returns: Maximum safe allocation size in bytes
 * Thread-safe: Yes
 */
extern size_t SocketSecurity_get_max_allocation (void);

/**
 * SocketSecurity_get_http_limits - Get HTTP-specific limits
 * @max_uri: Output for max URI length (may be NULL)
 * @max_header_size: Output for max header size (may be NULL)
 * @max_headers: Output for max header count (may be NULL)
 * @max_body: Output for max body size (may be NULL)
 *
 * Thread-safe: Yes
 */
extern void SocketSecurity_get_http_limits (size_t *max_uri,
                                            size_t *max_header_size,
                                            size_t *max_headers,
                                            size_t *max_body);

/**
 * SocketSecurity_get_ws_limits - Get WebSocket-specific limits
 * @max_frame: Output for max frame size (may be NULL)
 * @max_message: Output for max message size (may be NULL)
 *
 * Thread-safe: Yes
 */
extern void SocketSecurity_get_ws_limits (size_t *max_frame,
                                          size_t *max_message);

/**
 * SocketSecurity_get_arena_limits - Get arena memory limits
 * @max_alloc: Output for max arena allocation size (may be NULL)
 *
 * Thread-safe: Yes
 */
extern void SocketSecurity_get_arena_limits (size_t *max_alloc);

/**
 * SocketSecurity_get_hpack_limits - Get HPACK-specific limits
 * @max_table: Output for max dynamic table size (may be NULL)
 *
 * Thread-safe: Yes
 */
extern void SocketSecurity_get_hpack_limits (size_t *max_table);

/* ============================================================================
 * Size Validation Functions
 * ============================================================================ */

/**
 * SocketSecurity_check_size - Validate allocation size
 * @size: Requested allocation size
 *
 * Checks if the requested size is within safe limits and doesn't indicate
 * an integer overflow (e.g., negative size cast to size_t).
 *
 * Returns: 1 if size is valid, 0 if invalid
 * Thread-safe: Yes
 */
extern int SocketSecurity_check_size (size_t size);

/**
 * SocketSecurity_check_multiply - Check for multiplication overflow
 * @a: First operand
 * @b: Second operand
 * @result: Output for product (may be NULL if just checking)
 *
 * Safely multiplies two sizes, detecting overflow before it occurs.
 *
 * Returns: 1 if multiplication is safe, 0 if would overflow
 * Thread-safe: Yes
 */
extern int SocketSecurity_check_multiply (size_t a, size_t b, size_t *result);

/**
 * SocketSecurity_check_add - Check for addition overflow
 * @a: First operand
 * @b: Second operand
 * @result: Output for sum (may be NULL if just checking)
 *
 * Safely adds two sizes, detecting overflow before it occurs.
 *
 * Returns: 1 if addition is safe, 0 if would overflow
 * Thread-safe: Yes
 */
extern int SocketSecurity_check_add (size_t a, size_t b, size_t *result);

/**
 * SocketSecurity_safe_multiply - Multiply with overflow check
 * @a: First operand
 * @b: Second operand
 *
 * Multiplies two sizes, returning 0 on overflow.
 *
 * Returns: Product, or 0 if overflow would occur
 * Thread-safe: Yes
 */
static inline size_t
SocketSecurity_safe_multiply (size_t a, size_t b)
{
  if (a == 0 || b == 0)
    return 0;
  if (a > SIZE_MAX / b)
    return 0; /* Would overflow */
  return a * b;
}

/**
 * SocketSecurity_safe_add - Add with overflow check
 * @a: First operand
 * @b: Second operand
 *
 * Adds two sizes, returning SIZE_MAX on overflow.
 *
 * Returns: Sum, or SIZE_MAX if overflow would occur
 * Thread-safe: Yes
 */
static inline size_t
SocketSecurity_safe_add (size_t a, size_t b)
{
  if (a > SIZE_MAX - b)
    return SIZE_MAX; /* Would overflow */
  return a + b;
}

/* ============================================================================
 * Validation Macros
 * ============================================================================ */

/**
 * SOCKET_SECURITY_VALID_SIZE - Check if size is within safe limits
 */
#define SOCKET_SECURITY_VALID_SIZE(s)                                          \
  ((size_t) (s) > 0 && (size_t) (s) <= SOCKET_SECURITY_MAX_ALLOCATION)

/**
 * SOCKET_SECURITY_CHECK_OVERFLOW_MUL - Check multiplication overflow
 */
#define SOCKET_SECURITY_CHECK_OVERFLOW_MUL(a, b)                               \
  ((b) == 0 || (a) <= SIZE_MAX / (b))

/**
 * SOCKET_SECURITY_CHECK_OVERFLOW_ADD - Check addition overflow
 */
#define SOCKET_SECURITY_CHECK_OVERFLOW_ADD(a, b) ((a) <= SIZE_MAX - (b))

/* ============================================================================
 * Security Feature Detection
 * ============================================================================ */

/**
 * SocketSecurity_has_tls - Check if TLS support is compiled in
 *
 * Returns: 1 if TLS available, 0 otherwise
 * Thread-safe: Yes
 */
static inline int
SocketSecurity_has_tls (void)
{
#if SOCKET_HAS_TLS
  return 1;
#else
  return 0;
#endif
}

/**
 * SocketSecurity_has_compression - Check if HTTP compression is available
 *
 * Returns: 1 if compression available, 0 otherwise
 * Thread-safe: Yes
 */
static inline int
SocketSecurity_has_compression (void)
{
#ifdef SOCKETHTTP1_HAS_COMPRESSION
  return 1;
#else
  return 0;
#endif
}

/* ============================================================================
 * Security Utility References
 * ============================================================================
 *
 * The following security utilities are provided by other modules.
 * This section documents their existence for reference.
 *
 * CRYPTOGRAPHIC (SocketCrypto.h):
 *   SocketCrypto_secure_compare()  - Constant-time memory comparison
 *   SocketCrypto_secure_clear()    - Secure memory clearing
 *   SocketCrypto_random_bytes()    - CSPRNG
 *   SocketCrypto_sha256()          - SHA-256 hash
 *   SocketCrypto_hmac_sha256()     - HMAC-SHA256
 *
 * UTF-8 VALIDATION (SocketUTF8.h):
 *   SocketUTF8_validate()          - One-shot validation
 *   SocketUTF8_init/update/finish() - Incremental validation
 *
 * RATE LIMITING (SocketRateLimit.h):
 *   SocketRateLimit_try_acquire()  - Token bucket check
 *   SocketRateLimit_configure()    - Set rate limits
 *
 * SYN FLOOD PROTECTION (SocketSYNProtect.h):
 *   SocketSYNProtect_check()       - Check connection attempt
 *   SocketSYNProtect_report_*()    - Report success/failure
 *
 * IP TRACKING (SocketIPTracker.h):
 *   SocketIPTracker_check()        - Per-IP connection tracking
 *   SocketIPTracker_add/remove()   - Connection lifecycle
 *
 * BUFFER SAFETY (SocketBuf.h):
 *   SocketBuf_secureclear()        - Clear sensitive buffer data
 */

#endif /* SOCKETSECURITY_INCLUDED */

