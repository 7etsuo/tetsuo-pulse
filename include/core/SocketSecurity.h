/**
 * @file SocketSecurity.h
 * @ingroup foundation
 * @brief Centralized security configuration, limits, and validation utilities.
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
 * @see SocketSecurity_get_limits() for querying security limits.
 * @see SocketSecurity_check_size() for size validation.
 * @see @ref security for other security-related modules.
 * @see SocketConfig.h for security configuration constants.
 * @see SocketTLSContext_new_server() for TLS 1.3 enforcement.
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
 *   ARENA_MAX_ALLOC_SIZE          - Max arena allocation (see
 * SOCKET_SECURITY_MAX_ALLOCATION, default 256MB)
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
 * ============================================================================
 */

/**
 * @brief Exception raised when allocation or buffer size exceeds security limits.
 * @ingroup foundation
 *
 * Raised when:
 * - Requested allocation exceeds SOCKET_SECURITY_MAX_ALLOCATION
 * - Buffer operation would exceed configured limits
 * - Integer overflow detected in size calculation
 * @see SocketSecurity_check_size() for size validation utilities.
 * @see @ref error-handling.mdc "Error Handling Guide" for exception patterns.
 */
extern const Except_T SocketSecurity_SizeExceeded;

/**
 * @brief Exception raised on input validation failure in security checks.
 * @ingroup foundation
 *
 * Raised when:
 * - Input fails security validation checks
 * - Invalid characters detected in protocol data
 * @see SocketSecurity_check_size() for size-related validations.
 * @see SocketUTF8_validate() for UTF-8 specific validation.
 * @see @ref error-handling.mdc "Error Handling Guide" for exception patterns.
 */
extern const Except_T SocketSecurity_ValidationFailed;

/* ============================================================================
 * Security Limits Structure
 * ============================================================================
 */

/**
 * @brief Structure containing runtime-queryable security limits.
 * @ingroup foundation
 *
 * This structure aggregates all security-relevant configuration limits from the
 * library, allowing runtime inspection of maximum sizes, timeouts, and other
 * security parameters.
 *
 * Use SocketSecurity_get_limits() to populate an instance of this structure.
 *
 * @see SocketSecurity_get_limits() to fill this structure.
 * @see SocketConfig.h for compile-time limit definitions.
 * @see @ref security for modules enforcing these limits.
 */
typedef struct SocketSecurityLimits
{
  /* Memory limits */
  size_t max_allocation;       /**< Maximum single allocation */
  size_t max_buffer_size;      /**< Maximum buffer size */
  size_t max_connections;      /**< Maximum connections in pool */
  size_t arena_max_alloc_size; /**< Maximum arena allocation size */

  /* HTTP limits */
  size_t http_max_uri_length;   /**< Maximum URI length */
  size_t http_max_header_name;  /**< Maximum header name length */
  size_t http_max_header_value; /**< Maximum header value length */
  size_t http_max_header_size;  /**< Maximum total header size */
  size_t http_max_headers;      /**< Maximum header count */
  size_t http_max_body_size;    /**< Maximum body size */

  /* HTTP/1.1 limits */
  size_t http1_max_request_line; /**< Maximum request/status line */
  size_t http1_max_chunk_size;   /**< Maximum chunk size */

  /* HTTP/2 limits */
  size_t http2_max_concurrent_streams; /**< Maximum concurrent streams */
  size_t http2_max_frame_size;         /**< Maximum frame size */
  size_t http2_max_header_list_size;   /**< Maximum header list size */

  /* TLS ALPN limits (SocketTLSConfig.h) */
  size_t tls_max_alpn_protocols;   /**< Max number of ALPN protocols
                                      (SOCKET_TLS_MAX_ALPN_PROTOCOLS=16) */
  size_t tls_max_alpn_len;         /**< Max ALPN protocol string length
                                      (SOCKET_TLS_MAX_ALPN_LEN=255) */
  size_t tls_max_alpn_total_bytes; /**< Max total ALPN list size (custom, e.g.,
                                      1024 for DoS protection) */
  size_t hpack_max_table_size;     /**< Maximum HPACK dynamic table size */

  /* WebSocket limits */
  size_t ws_max_frame_size;   /**< Maximum WebSocket frame size */
  size_t ws_max_message_size; /**< Maximum WebSocket message size */

  /* TLS limits */
  size_t tls_max_cert_chain_depth; /**< Maximum certificate chain depth */
  size_t tls_session_cache_size;   /**< TLS session cache size */

  /* Rate limiting */
  size_t ratelimit_conn_per_sec; /**< Connection rate per second */
  size_t ratelimit_burst;        /**< Burst capacity */
  size_t ratelimit_max_per_ip;   /**< Per-IP connection limit */

  /* Timeouts (milliseconds) */
  int timeout_connect_ms; /**< Connect timeout */
  int timeout_dns_ms;     /**< DNS resolution timeout */
  int timeout_idle_ms;    /**< Idle connection timeout */
  int timeout_request_ms; /**< Request timeout */

} SocketSecurityLimits;

/* ============================================================================
 * Limit Query Functions
 * ============================================================================
 */

/**
 * @brief Get the currently configured security limits.
 * @ingroup foundation
 * @param limits Pointer to SocketSecurityLimits structure to populate.
 *
 * Populates the provided structure with all security-relevant limits derived
 * from compile-time configuration constants.
 * @threadsafe Yes (purely reads compile-time constants, no state mutation).
 * @see SocketSecurityLimits for structure members.
 * @see SocketSecurity_get_max_allocation() for specific limit queries.
 */
extern void SocketSecurity_get_limits (SocketSecurityLimits *limits);

/**
 * @brief Get the maximum permitted single allocation size.
 * @ingroup foundation
 * @return The maximum safe allocation size in bytes (SOCKET_SECURITY_MAX_ALLOCATION).
 * @threadsafe Yes.
 * @see SocketSecurity_check_size() to validate a size against this limit.
 * @see SOCKET_SECURITY_MAX_ALLOCATION for the compile-time constant.
 */
extern size_t SocketSecurity_get_max_allocation (void);

/**
 * @brief Get HTTP protocol-specific security limits.
 * @ingroup foundation
 * @param max_uri [out] Maximum URI length, or NULL if not needed.
 * @param max_header_size [out] Maximum total header size, or NULL if not needed.
 * @param max_headers [out] Maximum number of headers, or NULL if not needed.
 * @param max_body [out] Maximum body size, or NULL if not needed.
 *
 * Queries individual HTTP-related limits for validation and configuration checks.
 * @threadsafe Yes.
 * @see SocketHTTP.h for defining HTTP limit constants.
 * @see @ref http "HTTP Module" for protocol implementation details.
 */
extern void SocketSecurity_get_http_limits (size_t *max_uri,
                                            size_t *max_header_size,
                                            size_t *max_headers,
                                            size_t *max_body);

/**
 * @brief Get WebSocket protocol-specific security limits.
 * @ingroup foundation
 * @param max_frame [out] Maximum WebSocket frame size, or NULL if not needed.
 * @param max_message [out] Maximum WebSocket message size, or NULL if not needed.
 *
 * These limits help prevent denial-of-service attacks via oversized frames or messages.
 * @threadsafe Yes.
 * @see SocketWS.h for WebSocket implementation.
 * @see @ref utilities for rate limiting integration.
 */
extern void SocketSecurity_get_ws_limits (size_t *max_frame,
                                          size_t *max_message);

/**
 * @brief Get arena-specific memory allocation limits.
 * @ingroup foundation
 * @param max_alloc [out] Maximum arena allocation size, or NULL if not needed.
 *
 * Queries the limit on individual allocations within arenas for security.
 * @threadsafe Yes.
 * @see Arena_alloc() in Arena.h for allocation function.
 * @see ARENA_MAX_ALLOC_SIZE for compile-time constant (if defined).
 */
extern void SocketSecurity_get_arena_limits (size_t *max_alloc);

/**
 * @brief Get HPACK header compression limits.
 * @ingroup foundation
 * @param max_table [out] Maximum dynamic table size for HPACK, or NULL if not needed.
 *
 * Limits the HPACK dynamic table size to mitigate memory exhaustion in HTTP/2 decompression.
 * @threadsafe Yes.
 * @see SocketHPACK.h for HPACK module.
 * @see @ref http "HTTP Module" for HTTP/2 integration.
 */
extern void SocketSecurity_get_hpack_limits (size_t *max_table);

/* ============================================================================
 * Size Validation Functions
 * ============================================================================
 */

/**
 * @brief Validate a requested allocation size against security limits.
 * @ingroup foundation
 * @param size Requested size in bytes.
 *
 * Checks if the size is positive, within SOCKET_SECURITY_MAX_ALLOCATION, and
 * not indicative of integer overflow (e.g., from negative cast to size_t).
 * @return 1 if the size is valid and safe, 0 otherwise.
 * @threadsafe Yes.
 * @see SocketSecurity_get_max_allocation() for the current limit value.
 * @see SOCKET_SECURITY_VALID_SIZE() macro for compile-time inline validation.
 * @see SocketSecurity_SizeExceeded exception for raising on failure.
 */
extern int SocketSecurity_check_size (size_t size);

/**
 * @brief Check for safe multiplication of two sizes without overflow.
 * @ingroup foundation
 * @param a First size operand.
 * @param b Second size operand.
 * @param result [out] Pointer to store the product if safe, or NULL to just check.
 *
 * Performs safe multiplication check, optionally computing and storing the result
 * if no overflow would occur.
 * @return 1 if multiplication is safe (no overflow), 0 if it would overflow.
 * @threadsafe Yes.
 * @see SocketSecurity_safe_multiply() for inline safe multiplication.
 * @see SocketSecurity_check_add() for addition overflow checks.
 * @see SocketSecurity_SizeExceeded for exception on failure in other contexts.
 */
extern int SocketSecurity_check_multiply (size_t a, size_t b, size_t *result);

/**
 * @brief Check for safe addition of two sizes without overflow.
 * @ingroup foundation
 * @param a First size operand.
 * @param b Second size operand.
 * @param result [out] Pointer to store the sum if safe, or NULL to just check.
 *
 * Performs safe addition check, optionally storing the result if no overflow occurs.
 * @return 1 if addition is safe (no overflow), 0 if it would overflow.
 * @threadsafe Yes.
 * @see SocketSecurity_safe_add() for inline safe addition function.
 * @see SocketSecurity_check_multiply() for multiplication checks.
 */
extern int SocketSecurity_check_add (size_t a, size_t b, size_t *result);

/**
 * @brief Perform safe multiplication with overflow protection.
 * @ingroup foundation
 * @param a First operand.
 * @param b Second operand.
 *
 * Computes the product a * b, returning 0 if either operand is 0 or if the
 * multiplication would cause integer overflow.
 * @return The product if safe and non-zero operands, 0 otherwise.
 * @threadsafe Yes (pure arithmetic, no side effects).
 * @note This function returns 0 for zero operands or overflow; use
 *       SocketSecurity_check_multiply() if distinction is needed.
 * @see SocketSecurity_check_multiply() for validation without computation.
 * @see SocketSecurity_safe_add() for safe addition.
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
 * @brief Perform safe addition with overflow protection.
 * @ingroup foundation
 * @param a First operand.
 * @param b Second operand.
 *
 * Computes the sum a + b, returning SIZE_MAX if the addition would cause integer overflow.
 * @return The sum if safe, SIZE_MAX otherwise (indicating overflow).
 * @threadsafe Yes (pure arithmetic, no side effects).
 * @note Distinguish overflow from valid SIZE_MAX sum by context or prior check.
 * @see SocketSecurity_check_add() for validation before computation.
 * @see SocketSecurity_safe_multiply() for safe multiplication.
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
 * ============================================================================
 */

/**
 * @brief Macro to check if a size is within security allocation limits.
 * @ingroup foundation
 * @param s The size value to validate.
 * @return Non-zero if valid (s > 0 && s <= SOCKET_SECURITY_MAX_ALLOCATION), zero otherwise.
 *
 * Provides a fast, inline check for safe allocation sizes at compile or runtime.
 * @see SocketSecurity_check_size() for the equivalent function call.
 * @see SocketSecurity_get_max_allocation() for retrieving the limit value.
 */
#define SOCKET_SECURITY_VALID_SIZE(s)                                         \
  ((size_t)(s) > 0 && (size_t)(s) <= SOCKET_SECURITY_MAX_ALLOCATION)

/**
 * @brief Macro to check if multiplication of two sizes would overflow.
 * @ingroup foundation
 * @param a First operand.
 * @param b Second operand.
 * @return Non-zero if safe (b == 0 || a <= SIZE_MAX / b), zero if overflow risk.
 *
 * Inline overflow check for size multiplications, returns true for zero b (safe, result 0).
 * @see SocketSecurity_check_multiply() for function version with optional result storage.
 * @see SocketSecurity_safe_multiply() for computing safe product.
 */
#define SOCKET_SECURITY_CHECK_OVERFLOW_MUL(a, b)                              \
  ((b) == 0 || (a) <= SIZE_MAX / (b))

/**
 * @brief Macro to check if addition of two sizes would overflow.
 * @ingroup foundation
 * @param a First operand.
 * @param b Second operand.
 * @return Non-zero if safe (a <= SIZE_MAX - b), zero if overflow risk.
 *
 * Inline overflow check for size additions.
 * @see SocketSecurity_check_add() for function version with optional result.
 * @see SocketSecurity_safe_add() for computing safe sum.
 */
#define SOCKET_SECURITY_CHECK_OVERFLOW_ADD(a, b) ((a) <= SIZE_MAX - (b))

/* ============================================================================
 * Security Feature Detection
 * ============================================================================
 */

/**
 * @brief Check if TLS support is enabled in the build.
 * @ingroup foundation
 * @return 1 if the library was compiled with TLS support (SOCKET_HAS_TLS), 0 otherwise.
 * @threadsafe Yes (compile-time constant check).
 * @see #if SOCKET_HAS_TLS for conditional code inclusion.
 * @see @ref security "Security Module" for TLS-related functionality.
 * @see SocketTLS.h for TLS APIs when available.
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
 * @brief Check if HTTP compression support is compiled in.
 * @ingroup foundation
 * @return 1 if HTTP/1.1 compression (gzip/deflate) is available, 0 otherwise.
 * @threadsafe Yes (compile-time constant).
 * @see SOCKETHTTP1_HAS_COMPRESSION for the build configuration macro.
 * @see SocketHTTP1.h for using compression in HTTP/1.1 transfers.
 * @see @ref http "HTTP Module" for protocol-level compression details.
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
