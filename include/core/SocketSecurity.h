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

/**
 * @brief Maximum single allocation size permitted by security policy.
 * @ingroup foundation
 *
 * Limits individual allocations (e.g., malloc, Arena_alloc, SocketBuf_new) to
 * mitigate denial-of-service attacks from excessively large requests.
 *
 * Default: 256 MiB (268435456 bytes). Override by defining this macro to a
 * different value before including SocketSecurity.h or any header that
 * includes it.
 *
 * This limit is enforced in memory allocation hotspots and buffer creations
 * across the library.
 *
 * @see SocketSecurity_get_max_allocation() for runtime query.
 * @see SocketSecurity_check_size() for validating sizes against this limit.
 * @see SocketSecurity_SizeExceeded exception raised when exceeded.
 * @see ARENA_MAX_ALLOC_SIZE related arena-specific limit.
 */
#ifndef SOCKET_SECURITY_MAX_ALLOCATION
#define SOCKET_SECURITY_MAX_ALLOCATION (256UL * 1024 * 1024)
#endif

/**
 * @brief Maximum permitted size for HTTP request/response bodies.
 * @ingroup foundation
 *
 * Limits HTTP body payloads to prevent memory exhaustion from large
 * uploads/downloads. Default: 100 MiB. Override via compile-time definition.
 *
 * Enforced in SocketHTTPClient, SocketHTTPServer, and protocol parsers.
 * Exceeding this triggers truncation or rejection with 413 Payload Too Large.
 *
 * @see SocketSecurity_get_limits() -> http_max_body_size runtime value.
 * @see SocketHTTP_Headers_get("Content-Length") for body size indication.
 * @see @ref http "HTTP Module" for protocol limits.
 */
#ifndef SOCKET_SECURITY_MAX_BODY_SIZE
#define SOCKET_SECURITY_MAX_BODY_SIZE (100 * 1024 * 1024)
#endif

/**
 * @brief Maximum allowed request timeout value in milliseconds.
 * @ingroup foundation
 *
 * Caps the maximum timeout for operations like connect, read, write to prevent
 * indefinite resource holds. Default: 60 seconds (60000 ms).
 * Override by defining before inclusion.
 *
 * Used in Socket_connect, SocketHTTPClient config, etc., to bound timeout
 * parameters. Values exceeding this are clamped or rejected.
 *
 * @see SocketSecurity_get_limits() -> timeout_request_ms (related).
 * @see SocketConfig.h for other timeout defaults.
 * @see SocketTimeouts_T for timeout structures.
 */
#ifndef SOCKET_SECURITY_MAX_REQUEST_TIMEOUT_MS
#define SOCKET_SECURITY_MAX_REQUEST_TIMEOUT_MS 60000
#endif

/* ============================================================================
 * Exception Types
 * ============================================================================
 */

/**
 * @brief Exception indicating security limit violation on size/ allocation.
 * @ingroup foundation
 *
 * Thrown by library modules when a requested size exceeds configured security
 * limits or when size computations detect potential overflow/invalidity.
 *
 * Common triggers:
 * - Arena_alloc() / SocketBuf_new() with size > max_allocation
 * - Buffer appends exceeding capacity limits
 * - Detected integer overflow in safe arithmetic wrappers
 *
 * Applications should catch and handle by reducing request size, logging,
 * or rejecting client input (e.g., 413/400 responses).
 *
 * @see SocketSecurity_SizeExceeded for exception instance.
 *
 * ## Handling Example
 *
 * @code{.c}
 * TRY {
 *     SocketBuf_T buf = SocketBuf_new(arena, too_large_size);
 * } EXCEPT(SocketSecurity_SizeExceeded) {
 *     SOCKET_LOG_ERROR_MSG("Size %zu exceeds max %zu; rejecting request",
 *                          too_large_size,
 * SocketSecurity_get_max_allocation());
 *     // Send error response to client
 *     return send_http_error(client, 413, "Payload Too Large");
 * } END_TRY;
 * @endcode
 *
 * @note Message includes context like "Allocation exceeds security limits".
 * @see SocketSecurity_check_size() to preemptively validate.
 * @see SocketSecurity_get_max_allocation() for current limit.
 * @see Except.h for TRY/EXCEPT/FINALLY usage.
 * @see docs/ERROR_HANDLING.md for patterns.
 */
extern const Except_T SocketSecurity_SizeExceeded;

/**
 * @brief Exception for general input validation failures in security contexts.
 * @ingroup foundation
 *
 * Indicates invalid or malicious input detected during security-related
 * validations, such as NULL pointers in required params, malformed protocol
 * data, or invalid characters/formats.
 *
 * Examples:
 * - SocketSecurity_get_limits(NULL) - invalid param
 * - UTF-8 validation fails in headers/URIs
 * - Protocol-specific checks (e.g., invalid HTTP methods)
 *
 * Differentiates from SizeExceeded (quantitative limits) for better error
 * handling.
 *
 * @see SocketSecurity_ValidationFailed instance.
 *
 * ## Handling Example
 *
 * @code{.c}
 * SocketSecurityLimits *lim = NULL; // Bad input
 * TRY {
 *     SocketSecurity_get_limits(lim);
 * } EXCEPT(SocketSecurity_ValidationFailed) {
 *     fprintf(stderr, "%s\n", Except_message(Except_stack)); // "Input
 * validation failed"
 *     // Validate pointers before calls
 *     lim = &local_limits;
 *     SocketSecurity_get_limits(lim); // Now safe
 * } END_TRY;
 * @endcode
 *
 * @note Generic message; specific raisers may append details via RAISE_FMT.
 * @see SocketSecurity_check_size() / other validators to prevent.
 * @see SocketUTF8_validate() for string validations.
 * @see Except_stack for current exception details.
 * @see docs/ERROR_HANDLING.md exception best practices.
 */
extern const Except_T SocketSecurity_ValidationFailed;

/* ============================================================================
 * Security Limits Structure
 * ============================================================================
 */

/**
 * @brief Aggregated security limits for runtime configuration inspection.
 * @ingroup foundation
 *
 * Opaque structure holding all library security limits: memory caps, protocol
 * sizes, rate limits, timeouts, etc. Populated by get_limits(); fields are
 * read-only constants derived from compile-time macros and feature flags.
 *
 * Enables applications to query and log security posture, validate inputs
 * dynamically, or adapt behavior based on build configuration (e.g., TLS
 * enabled?). No mutable state; thread-safe to read after population.
 *
 * ## Field Categories
 *
 * - **Memory**: Allocation/buffer/connection limits
 * - **HTTP**: URI/headers/body for HTTP/1 & 2
 * - **Protocols**: WS, TLS, HPACK specifics
 * - **Controls**: Rate limits, timeouts
 *
 * Full list in members below. When features disabled (e.g., no TLS), fields
 * set to 0.
 *
 * ## Usage Example
 *
 * See SocketSecurity_get_limits() for population and field access example.
 *
 * @note Fields map directly to macros in SocketConfig.h, SocketHTTP.h, etc.
 * @threadsafe Yes (immutable after get_limits())
 * @see SocketSecurity_get_limits() primary accessor.
 * @see Individual get_*_limits() for partial queries.
 * @see SocketConfig.h source of truth for limits.
 * @see @ref foundation for base security infrastructure.
 */
typedef struct SocketSecurityLimits
{
  /* Memory limits */

  /** Maximum bytes for any single memory allocation anywhere in library.

   * Applies to malloc, Arena_alloc, SocketBuf_new, etc. Core DoS protection.

   * Default: 256 MiB (SOCKET_SECURITY_MAX_ALLOCATION)

   * @see SocketSecurity_get_max_allocation()

   * @see SocketSecurity_check_size()

   */

  size_t max_allocation;

  /** Maximum capacity for per-connection I/O buffers (SocketBuf instances).

   * Limits memory per Socket/Connection to prevent exhaustion.

   * Default: 1 MiB (SOCKET_MAX_BUFFER_SIZE)

   * @see SocketPool_new() bufsize param

   * @see SocketBuf_new()

   */

  size_t max_buffer_size;

  /** Maximum number of connections allowed in SocketPool.

   * Caps concurrent resource usage (FDs, buffers, threads).

   * Default: 10000 (SOCKET_MAX_CONNECTIONS)

   * @see SocketPool_new() maxconns param

   * @see SocketPool_resize()

   */

  size_t max_connections;

  /** Maximum single allocation permitted within Arena instances.

   * Subset of global max_allocation for pooled memory control.

   * Default: same as max_allocation (ARENA_MAX_ALLOC_SIZE)

   * @see Arena_alloc()

   * @see Arena.h

   */

  size_t arena_max_alloc_size;

  /* HTTP limits (SocketHTTP.h) */

  /** Max length of HTTP URI/path in bytes.

   * Prevents long URI DoS/header injection.

   * Default: 8 KiB (SOCKETHTTP_MAX_URI_LEN)

   * @see SocketHTTP_URI_parse()

   */

  size_t http_max_uri_length;

  /** Max length for individual HTTP header names.

   * Default: 256 bytes (SOCKETHTTP_MAX_HEADER_NAME)

   * @see SocketHTTP_Headers_add()

   */

  size_t http_max_header_name;

  /** Max length for individual HTTP header values.

   * Default: 8 KiB (SOCKETHTTP_MAX_HEADER_VALUE)

   * @see SocketHTTP_Headers_set()

   */

  size_t http_max_header_value;

  /** Total size limit for all HTTP headers in a message.

   * Includes names/values/CRLF. Default: 64 KiB (SOCKETHTTP_MAX_HEADER_SIZE)

   * @see SocketHTTP1_Parser_execute()

   */

  size_t http_max_header_size;

  /** Maximum number of HTTP headers per message.

   * Prevents DoS via many tiny headers. Default: 100 (SOCKETHTTP_MAX_HEADERS)

   */

  size_t http_max_headers;

  /** Maximum HTTP request/response body size.

   * Large upload/download protection. Default: 100 MiB
   (SOCKET_SECURITY_MAX_BODY_SIZE)

   * @see SocketHTTPClient_get() etc.

   * @see SocketSecurity_get_http_limits()

   */

  size_t http_max_body_size;

  /* HTTP/1.1 specific (SocketHTTP1.h) */

  /** Max length of HTTP/1.1 request or status line.

   * Includes method/URI/version or status/reason. Default: 8 KiB

   * @see SocketHTTP1_Parser_new()

   */

  size_t http1_max_request_line;

  /** Maximum size of a single chunk in chunked transfer-encoding.

   * Default: 16 MiB (SOCKETHTTP1_MAX_CHUNK_SIZE)

   */

  size_t http1_max_chunk_size;

  /* HTTP/2 specific (SocketHTTP2.h) */

  /** Default max concurrent streams per HTTP/2 connection.

   * SETTINGS_MAX_CONCURRENT_STREAMS. Default: 100

   * @see SocketHTTP2_config_defaults()

   */

  size_t http2_max_concurrent_streams;

  /** Default max HTTP/2 frame size (16 KiB nominal).

   * SETTINGS_MAX_FRAME_SIZE lower bound.

   * @see SocketHTTP2_Conn_process()

   */

  size_t http2_max_frame_size;

  /** Max size for HTTP/2 header list (compressed via HPACK).

   * SETTINGS_MAX_HEADER_LIST_SIZE. Default: 16 KiB

   * @see SocketHTTP2_Stream_send_headers()

   */

  size_t http2_max_header_list_size;

  /* TLS/ALPN and HPACK limits */

  /** Max number of ALPN protocol identifiers in TLS extension list.

   * Limits negotiation options. Default: 16 (SOCKET_TLS_MAX_ALPN_PROTOCOLS)

   * @see SocketTLSContext_add_alpn_protocol()

   */

  size_t tls_max_alpn_protocols;

  /** Max length of a single ALPN protocol string (e.g., "h2", "http/1.1").

   * Per RFC, <=255. (SOCKET_TLS_MAX_ALPN_LEN)

   * @see SocketTLS_set_alpn_protocols()

   */

  size_t tls_max_alpn_len;

  /** Total byte limit for entire ALPN protocol list wire encoding.

   * Additional DoS protection beyond per-protocol limits. Custom, e.g., 1024
   bytes.

   */

  size_t tls_max_alpn_total_bytes;

  /** Maximum size for HPACK dynamic header table in HTTP/2 decompression.

   * Prevents memory exhaustion from header floods. Default: 64 KiB
   (SOCKETHPACK_MAX_TABLE_SIZE)

   * @see SocketHPACK_Decoder_new()

   * @see SocketSecurity_get_hpack_limits()

   */

  size_t hpack_max_table_size;

  /* WebSocket limits (SocketWS-private.h) */

  /** Max size for single WebSocket frame payload (RFC 6455).

   * Prevents large frame DoS. Default: 16 MiB (SOCKETWS_MAX_FRAME_SIZE)

   * @see SocketSecurity_get_ws_limits()

   */

  size_t ws_max_frame_size;

  /** Max aggregated size for multi-frame WebSocket messages (text/binary).

   * Covers fragmented messages. Default: 64 MiB (SOCKETWS_MAX_MESSAGE_SIZE)

   * @see SocketWS_handle_frame()

   */

  size_t ws_max_message_size;

  /* TLS general limits (SocketTLSConfig.h) */

  /** Max depth for X.509 certificate chain validation during handshake.

   * Prevents DoS from deeply nested chains. Default: 10
   (SOCKET_TLS_MAX_CERT_CHAIN_DEPTH)

   * @see SocketTLSContext_set_verify_depth()

   * @see SocketTLS_handshake()

   */

  size_t tls_max_cert_chain_depth;

  /** Number of resumable TLS sessions in internal cache.

   * Improves performance on reconnects. Default: 1000
   (SOCKET_TLS_SESSION_CACHE_SIZE)

   * @see SocketTLSContext_set_session_cache_size()

   */

  size_t tls_session_cache_size;

  /* Rate limiting defaults (SocketConfig.h / SocketPool.h) */

  /** Default connections per second global rate limit for pools/servers.

   * Token bucket rate. Default: 100/s (SOCKET_RATELIMIT_DEFAULT_CONN_PER_SEC)

   * @see SocketPool_setconnrate()

   * @see SocketRateLimit.h

   */

  size_t ratelimit_conn_per_sec;

  /** Allowed burst capacity for connection rate limiting (tokens).

   * Allows short spikes. Default: 50 (SOCKET_RATELIMIT_DEFAULT_BURST)

   * @see SocketPool_setconnrate() burst param

   */

  size_t ratelimit_burst;

  /** Default maximum concurrent connections per client IP.

   * Per-IP flood protection. Default: 10 (SOCKET_RATELIMIT_DEFAULT_MAX_PER_IP)

   * @see SocketPool_setmaxperip()

   */

  size_t ratelimit_max_per_ip;

  /* Default timeouts in milliseconds (SocketConfig.h) */

  /** Default timeout for Socket_connect() and TLS handshakes.

   * Prevents hanging connections. Default: 30s
   (SOCKET_DEFAULT_CONNECT_TIMEOUT_MS)

   * @see Socket_connect()

   * @see SocketTLS_handshake()

   */

  int timeout_connect_ms;

  /** Default timeout for DNS resolutions (SocketDNS).

   * Default: 5s (SOCKET_DEFAULT_DNS_TIMEOUT_MS)

   * @see SocketDNS_resolve_sync()

   */

  int timeout_dns_ms;

  /** Default idle timeout for connections (ms).

   * Converted from seconds * 1000. Closes inactive conns.

   * Default: 5min (SOCKET_DEFAULT_IDLE_TIMEOUT)

   * @see SocketPool_cleanup()

   * @see Connection_lastactivity()

   */

  int timeout_idle_ms;

  /** Maximum permitted value for request timeouts.

   * Caps user-configured timeouts to prevent indefinite holds.

   * Default: 60s (SOCKET_SECURITY_MAX_REQUEST_TIMEOUT_MS)

   * @see Socket_set_timeout()

   */

  int timeout_request_ms;

} SocketSecurityLimits;

/* ============================================================================
 * Limit Query Functions
 * ============================================================================
 */

/**
 * @brief Retrieve all configured security limits into a structure for
 * inspection.
 * @ingroup foundation
 *
 * This function populates a SocketSecurityLimits structure with the current
 * security configuration limits from across the library. These limits include
 * memory allocation caps, HTTP payload sizes, TLS parameters, rate limiting
 * defaults, and timeouts. Limits are derived from compile-time constants and
 * feature flags (e.g., SOCKET_HAS_TLS, SOCKET_HAS_HTTP).
 *
 * Useful for runtime validation, logging security posture, or dynamic
 * configuration checks in applications. No allocations or state changes occur.
 * Edge cases: When optional modules (TLS, HTTP, WebSocket) are disabled at
 * compile-time, corresponding limits are set to 0 or safe minimal values.
 *
 * @param[out] limits Pointer to a SocketSecurityLimits structure to populate.
 *                    Must not be NULL; validated before use.
 *
 * @throws SocketSecurity_ValidationFailed If limits is NULL (input validation
 * failure).
 *
 * @threadsafe Yes - reads only compile-time constants; no shared state or
 * locks.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Query security limits for logging or validation
 * SocketSecurityLimits limits;
 * TRY {
 *     SocketSecurity_get_limits(&limits);
 *     printf("Max allocation: %zu bytes\n", limits.max_allocation);
 *     printf("Max HTTP body: %zu bytes\n", limits.http_max_body_size);
 *     if (SocketSecurity_has_tls()) {
 *         printf("TLS cert chain depth: %zu\n",
 * limits.tls_max_cert_chain_depth);
 *     }
 * } EXCEPT(SocketSecurity_ValidationFailed) {
 *     fprintf(stderr, "Invalid limits pointer provided\n");
 * } END_TRY;
 * @endcode
 *
 * ## Limit Categories
 *
 * The structure groups limits into categories for easy inspection:
 *
 * | Category       | Key Limits                          | Purpose |
 * |----------------|-------------------------------------|----------------------------------|
 * | Memory         | max_allocation, max_buffer_size     | DoS prevention via
 * size caps     | | HTTP           | http_max_body_size, http_max_headers|
 * Payload and header validation    | | HTTP/2         |
 * http2_max_concurrent_streams        | Stream multiplexing limits       | |
 * TLS            | tls_max_cert_chain_depth            | Certificate
 * validation bounds    | | Rate Limiting  | ratelimit_conn_per_sec |
 * Connection flood protection      | | Timeouts       | timeout_connect_ms |
 * Prevent indefinite hangs         |
 *
 * @note Limits reflect compile-time configuration via CMake options and
 * macros; no runtime reconfiguration supported to maintain security
 * guarantees.
 * @warning Applications should respect these limits; exceeding them in custom
 *          code may lead to exceptions or undefined behavior in library
 * modules.
 * @complexity O(1) - direct assignment of pre-defined constants
 *
 * @see SocketSecurityLimits for detailed field documentation and types.
 * @see SocketSecurity_get_max_allocation() for querying individual limits.
 * @see SocketSecurity_check_size() for validating user-provided sizes.
 * @see SocketSecurity_has_tls() to check feature availability.
 * @see docs/SECURITY_GUIDE.md for comprehensive security configuration.
 */
extern void SocketSecurity_get_limits (SocketSecurityLimits *limits);

/**
 * @brief Query the maximum allowed size for single memory allocations.
 * @ingroup foundation
 *
 * Returns the compile-time configured limit on individual memory allocations
 * (e.g., via malloc, Arena_alloc, SocketBuf_new). This cap prevents
 * denial-of-service from oversized requests and memory exhaustion attacks.
 *
 * Default value: 256 MiB (268435456 bytes). Overridable via
 * -DSOCKET_SECURITY_MAX_ALLOCATION=<value> at compile time.
 *
 * Used internally for validation in allocation hotspots; applications can
 * use this for preemptive checks or logging. Edge case: Returns the limit
 * even if overridden to 0 (disabled protection).
 *
 * @return Maximum permitted allocation size in bytes.
 *
 * @threadsafe Yes - returns compile-time constant; no side effects or locks.
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Pre-validate large buffer allocation
 * size_t max_alloc = SocketSecurity_get_max_allocation();
 * size_t buf_size = 100 * 1024 * 1024; // 100 MiB buffer
 *
 * TRY {
 *     if (buf_size > max_alloc) {
 *         RAISE(SocketSecurity_SizeExceeded);
 *     }
 *     SocketBuf_T buf = SocketBuf_new(arena, buf_size);
 *     // Use buffer...
 *     SocketBuf_release(&buf);
 * } EXCEPT(SocketSecurity_SizeExceeded) {
 *     fprintf(stderr, "Buffer size %zu exceeds security limit %zu\n",
 * buf_size, max_alloc); } END_TRY;
 * @endcode
 *
 * ## Configuration
 *
 * | Macro                      | Default Value | Purpose |
 * |----------------------------|---------------|----------------------------------|
 * | SOCKET_SECURITY_MAX_ALLOCATION | 256 MiB     | Single allocation DoS
 * protection |
 *
 * @note Applies to all single allocations; multi-allocation structures
 *       (e.g., arenas) have separate aggregate limits.
 * @warning Overriding to excessively large values (>1GB) may expose to
 *          memory exhaustion; use system ulimit for additional protection.
 * @complexity O(1) - simple constant return
 *
 * @see SocketSecurity_check_size() for comprehensive validation including
 * zero-check.
 * @see SocketSecurity_SizeExceeded exception raised on violations.
 * @see Arena.h for arena-specific allocation with integrated checks.
 * @see SocketBuf.h for buffer creation limits.
 * @see SOCKET_SECURITY_MAX_ALLOCATION for macro definition and override.
 */
extern size_t SocketSecurity_get_max_allocation (void);

/**
 * @brief Query specific HTTP protocol security limits.
 * @ingroup foundation
 *
 * Retrieves individual HTTP-related limits such as maximum URI length, header
 * sizes, header count, and body payload size. These optional output parameters
 * allow selective querying without populating the full SocketSecurityLimits
 * structure.
 *
 * Limits are enforced in SocketHTTP, SocketHTTPClient, and SocketHTTPServer
 * modules to prevent buffer overflows and DoS attacks via malformed requests.
 * NULL pointers are ignored, allowing partial queries.
 *
 * When SOCKET_HAS_HTTP=0, returns 0 for all values (feature disabled).
 *
 * @param[out] max_uri Maximum URI length in bytes (SOCKETHTTP_MAX_URI_LEN), or
 * NULL.
 * @param[out] max_header_size Maximum total headers size in bytes
 * (SOCKETHTTP_MAX_HEADER_SIZE), or NULL.
 * @param[out] max_headers Maximum number of HTTP headers allowed
 * (SOCKETHTTP_MAX_HEADERS), or NULL.
 * @param[out] max_body Maximum HTTP body size in bytes
 * (SOCKET_SECURITY_MAX_BODY_SIZE), or NULL.
 *
 * @threadsafe Yes - constant reads; no side effects.
 *
 * ## Usage Example
 *
 * @code{.c}
 * size_t max_uri, max_body;
 * SocketSecurity_get_http_limits(&max_uri, NULL, NULL, &max_body);
 *
 * // Validate incoming request URI
 * if (strlen(request_uri) > max_uri) {
 *     // Reject with 414 URI Too Long
 *     return send_error_response(client, 414);
 * }
 *
 * // Check Content-Length header
 * const char *clen = SocketHTTP_Headers_get(headers, "Content-Length");
 * size_t body_size = clen ? atol(clen) : 0;
 * if (body_size > max_body) {
 *     // Reject with 413 Payload Too Large
 *     return send_error_response(client, 413);
 * }
 * @endcode
 *
 * ## HTTP Limits Table
 *
 * | Limit              | Default     | Enforced In              | Rationale |
 * |--------------------|-------------|--------------------------|----------------------------|
 * | max_uri            | 8KB         | URI parsing              | Prevent
 * header injection   | | max_header_size    | 64KB        | Header parsing |
 * Buffer overflow protection | | max_headers        | 100         | Header
 * list              | DoS via many small headers | | max_body           | 100
 * MiB     | Body reading             | Large upload DoS prevention|
 *
 * @note These limits can be overridden in SocketHTTP.h via compile-time
 * macros.
 * @warning Disabling HTTP module sets limits to 0; always check
 * SOCKET_HAS_HTTP.
 * @complexity O(1) - direct constant assignments
 *
 * @see SocketSecurity_get_limits() for all limits including HTTP.
 * @see SocketHTTP_Headers_add() which respects header limits.
 * @see SocketHTTP_URI_parse() which checks URI length.
 * @see @ref http "HTTP Modules" for full protocol security features.
 * @see docs/HTTP_SECURITY.md for HTTP-specific hardening guide.
 */
extern void SocketSecurity_get_http_limits (size_t *max_uri,
                                            size_t *max_header_size,
                                            size_t *max_headers,
                                            size_t *max_body);

/**
 * @brief Query WebSocket-specific security limits for frame and message sizes.
 * @ingroup foundation
 *
 * Retrieves limits on WebSocket frame and message sizes to mitigate DoS
 * attacks from oversized payloads. Frames are individual WebSocket data units;
 * messages may span multiple frames (e.g., fragmented text/binary messages).
 *
 * Enforced in SocketWS module during frame parsing and message reassembly.
 * When SOCKET_HAS_WEBSOCKET=0, returns 0 (disabled).
 *
 * @param[out] max_frame Maximum single WebSocket frame size in bytes
 * (SOCKETWS_MAX_FRAME_SIZE), or NULL.
 * @param[out] max_message Maximum aggregated message size in bytes
 * (SOCKETWS_MAX_MESSAGE_SIZE), or NULL.
 *
 * @threadsafe Yes - constant reads only.
 *
 * ## Usage Example
 *
 * @code{.c}
 * size_t max_frame, max_msg;
 * SocketSecurity_get_ws_limits(&max_frame, &max_msg);
 *
 * // In WebSocket handler, before processing incoming frame
 * if (incoming_frame_size > max_frame) {
 *     // Close connection with protocol error (1002)
 *     SocketWS_close(conn, WS_STATUS_PROTOCOL_ERROR, "Oversized frame");
 *     return;
 * }
 *
 * // Track message size across fragments
 * static size_t current_msg_size = 0;
 * current_msg_size += incoming_frame_size;
 * if (current_msg_size > max_msg) {
 *     // Close with message too big (1009)
 *     SocketWS_close(conn, WS_STATUS_MESSAGE_TOO_BIG, "Message exceeds
 * limit"); current_msg_size = 0; return;
 * }
 * @endcode
 *
 * ## WebSocket Limits
 *
 * | Limit        | Default   | Purpose                          |
 * |--------------|-----------|----------------------------------|
 * | max_frame    | 16 MiB    | Single frame DoS protection      |
 * | max_message  | 64 MiB    | Aggregated message safety        |
 *
 * @note Limits configurable via macros in SocketWS-private.h.
 * @warning Large limits increase memory usage; tune based on application
 * needs.
 * @complexity O(1)
 *
 * @see SocketSecurity_get_limits() for broader limits including WS.
 * @see SocketWS.h for WebSocket API and error codes.
 * @see @ref utilities "Utilities" for integration with rate limiting.
 * @see docs/WEBSOCKET_SECURITY.md for WebSocket hardening.
 */
extern void SocketSecurity_get_ws_limits (size_t *max_frame,
                                          size_t *max_message);

/**
 * @brief Query the maximum allocation size limit for arenas.
 * @ingroup foundation
 *
 * Returns the limit on single allocations from an Arena instance. This
 * provides an additional layer of protection within arena-managed memory,
 * complementing the global SOCKET_SECURITY_MAX_ALLOCATION.
 *
 * Defined via ARENA_MAX_ALLOC_SIZE macro (defaults to
 * SOCKET_SECURITY_MAX_ALLOCATION if undefined). Enforced in Arena_alloc and
 * Arena_calloc to prevent large allocations within pooled memory.
 *
 * @param[out] max_alloc Maximum allowed allocation from arena in bytes
 * (ARENA_MAX_ALLOC_SIZE), or NULL.
 *
 * @threadsafe Yes - constant query.
 *
 * ## Usage Example
 *
 * @code{.c}
 * size_t arena_max;
 * SocketSecurity_get_arena_limits(&arena_max);
 *
 * Arena_T arena = Arena_new();
 * size_t large_alloc = arena_max + 1;
 * TRY {
 *     void *ptr = Arena_alloc(arena, large_alloc, __FILE__, __LINE__);
 *     // Unreachable - raises exception
 * } EXCEPT(Arena_Failed) {
 *     // Handle: allocation exceeded arena limit
 *     fprintf(stderr, "Arena alloc %zu > limit %zu\n", large_alloc,
 * arena_max); } FINALLY { Arena_dispose(&arena); } END_TRY;
 * @endcode
 *
 * @note Arena limits apply per-allocation within an arena; total arena size
 *       limited by system memory and configuration.
 * @complexity O(1)
 *
 * @see SocketSecurity_get_max_allocation() for global allocation limit.
 * @see Arena_alloc() / Arena_calloc() which enforce this limit.
 * @see ARENA_MAX_ALLOC_SIZE macro for configuration.
 * @see @ref foundation "Foundation Modules" for memory management.
 */
extern void SocketSecurity_get_arena_limits (size_t *max_alloc);

/**
 * @brief Query HPACK dynamic table size limit for HTTP/2 header compression.
 * @ingroup foundation
 *
 * Returns the maximum size allowed for the dynamic header table in HPACK
 * (HTTP/2 header compression). This limit prevents memory exhaustion attacks
 * via maliciously crafted headers that force large table growth during
 * decompression.
 *
 * Enforced in SocketHPACK_Decoder during table updates. Default: 64KB.
 * When SOCKET_HAS_HTTP=0, returns 0.
 *
 * @param[out] max_table Maximum dynamic table size in bytes
 * (SOCKETHPACK_MAX_TABLE_SIZE), or NULL.
 *
 * @threadsafe Yes.
 *
 * ## Usage Example
 *
 * @code{.c}
 * size_t hpack_max_table;
 * SocketSecurity_get_hpack_limits(&hpack_max_table);
 *
 * // Configure HTTP/2 connection with safe table size
 * SocketHTTP2_Config config;
 * SocketHTTP2_config_defaults(&config, HTTP2_CLIENT);
 * config.hpack_max_table_size = hpack_max_table; // Respect security limit
 *
 * SocketHTTP2_Conn_T conn = SocketHTTP2_Conn_new(socket, &config, arena);
 * // Proceed with HTTP/2 handshake...
 * @endcode
 *
 * @note HPACK table size affects compression efficiency vs memory usage
 * tradeoff.
 * @warning Large tables (>1MB) increase vulnerability to decompression bombs.
 * @complexity O(1)
 *
 * @see SocketHPACK_DecoderConfig for table configuration.
 * @see SocketHTTP2_Conn_new() which uses this limit.
 * @see SOCKETHPACK_MAX_TABLE_SIZE macro.
 * @see @ref http "HTTP Modules" for HTTP/2 details.
 */
extern void SocketSecurity_get_hpack_limits (size_t *max_table);

/* ============================================================================
 * Size Validation Functions
 * ============================================================================
 */

/**
 * @brief Validate a size value for safe memory allocation or buffer
 * operations.
 * @ingroup foundation
 *
 * Performs comprehensive validation of a size parameter before use in
 * allocations, buffer creations, or size calculations. Checks include:
 *
 * - Non-zero (rejects zero-size as likely error)
 * - Within global max allocation limit
 * - Defense-in-depth: rejects sizes > SIZE_MAX/2 to catch overflows
 *
 * Used internally by Arena, SocketBuf, and other modules; applications can
 * call directly for custom validations.
 *
 * @param[in] size Proposed size in bytes to validate.
 *
 * @return 1 if size is safe (positive, within limits, no overflow risk), 0
 * otherwise.
 *
 * @threadsafe Yes - pure function, no state.
 *
 * ## Usage Example
 *
 * @code{.c}
 * size_t user_size = get_user_input_size(); // From untrusted source
 *
 * if (!SocketSecurity_check_size(user_size)) {
 *     fprintf(stderr, "Invalid size %zu: exceeds security limits\n",
 * user_size); return -1;
 * }
 *
 * // Safe to allocate
 * void *buf = malloc(user_size);
 * if (!buf) {
 *     perror("malloc");
 *     return -1;
 * }
 * // Use buf...
 * free(buf);
 * @endcode
 *
 * ## Validation Criteria
 *
 * | Check                  | Condition                  | Rationale |
 * |------------------------|----------------------------|-------------------------------|
 * | Non-zero               | size > 0                   | Avoid zero-alloc
 * bugs         | | Within limit           | size <= max_allocation     | DoS
 * protection                | | Overflow defense       | size <= SIZE_MAX/2 |
 * Catch signed->unsigned casts  |
 *
 * @note For performance-critical code, use SOCKET_SECURITY_VALID_SIZE macro
 * inline.
 * @warning Failing validation should trigger user-friendly errors, not silent
 * clamps.
 * @complexity O(1) - simple comparisons
 *
 * @see SocketSecurity_get_max_allocation() to retrieve current limit.
 * @see SOCKET_SECURITY_VALID_SIZE() inline macro equivalent.
 * @see SocketSecurity_SizeExceeded for raising exceptions on failure.
 * @see SocketSecurity_check_multiply() for compound size checks.
 */
extern int SocketSecurity_check_size (size_t size);

/**
 * @brief Validate multiplication of two sizes for potential overflow.
 * @ingroup foundation
 *
 * Checks if multiplying two size_t values would overflow before performing the
 * operation. Optionally computes and stores the result in *result if safe.
 *
 * Critical for safe size calculations like buffer sizing (e.g., count *
 * element_size) or capacity computations. Uses division-based check: safe if a
 * <= SIZE_MAX / b (b != 0).
 *
 * @param[in] a First multiplier (size_t operand).
 * @param[in] b Second multiplier (size_t operand).
 * @param[out] result Optional pointer to store a * b if no overflow, or NULL
 * to check only.
 *
 * @return 1 if multiplication safe (no overflow, including b==0 case), 0 if
 * overflow risk.
 *
 * @threadsafe Yes - pure arithmetic function.
 *
 * ## Usage Example
 *
 * @code{.c}
 * size_t count = 1000;
 * size_t elem_size = 1024;
 * size_t product;
 *
 * if (SocketSecurity_check_multiply(count, elem_size, &product)) {
 *     // Safe: allocate buffer of product bytes
 *     void *array = Arena_alloc(arena, product, __FILE__, __LINE__);
 * } else {
 *     fprintf(stderr, "%zu * %zu would overflow\n", count, elem_size);
 *     // Handle: reduce size, use smaller type, or error
 * }
 * @endcode
 *
 * ## Edge Cases
 *
 * - b == 0: Returns 1 (safe, product=0)
 * - a == 0: Returns 1 (safe, product=0)
 * - Overflow: e.g., SIZE_MAX * 2 -> 0
 *
 * @note Equivalent to SOCKET_SECURITY_CHECK_OVERFLOW_MUL macro for inline use.
 * @complexity O(1)
 *
 * @see SocketSecurity_safe_multiply() computes product or 0 on failure.
 * @see SocketSecurity_check_add() for addition validation.
 * @see SocketSecurity_check_size() for single size validation.
 * @see docs/SAFE_ARITHMETIC.md for secure coding practices.
 */
extern int SocketSecurity_check_multiply (size_t a, size_t b, size_t *result);

/**
 * @brief Validate addition of two sizes for potential overflow.
 * @ingroup foundation
 *
 * Checks if adding two size_t values would overflow size_t before performing
 * the operation. Optionally computes and stores the result in *result if safe.
 *
 * Essential for safe buffer expansions, offset calculations, or total size
 * computations (e.g., current_size + additional). Check: safe if a <= SIZE_MAX
 * - b.
 *
 * @param[in] a First addend (size_t operand).
 * @param[in] b Second addend (size_t operand).
 * @param[out] result Optional pointer to store a + b if no overflow, or NULL
 * to check only.
 *
 * @return 1 if addition safe (no overflow), 0 if would overflow.
 *
 * @threadsafe Yes - pure function.
 *
 * ## Usage Example
 *
 * @code{.c}
 * size_t current_buf = SocketBuf_available(buf);
 * size_t incoming = recv_len;
 * size_t new_total;
 *
 * if (SocketSecurity_check_add(current_buf, incoming, &new_total)) {
 *     if (new_total > SocketSecurity_get_max_allocation()) {
 *         // Still too large, even if no overflow
 *         return -1;
 *     }
 *     // Safe to append to buffer
 *     SocketBuf_write(buf, data, incoming);
 * } else {
 *     // Overflow: handle by truncating or error
 *     fprintf(stderr, "Buffer expansion %zu + %zu overflows\n", current_buf,
 * incoming);
 * }
 * @endcode
 *
 * @note For inline use, SOCKET_SECURITY_CHECK_OVERFLOW_ADD macro available.
 * @complexity O(1)
 *
 * @see SocketSecurity_safe_add() computes sum or SIZE_MAX on failure.
 * @see SocketSecurity_check_multiply() companion for multiplication.
 * @see SocketSecurity_check_size() for validating the resulting size.
 */
extern int SocketSecurity_check_add (size_t a, size_t b, size_t *result);

/**
 * @brief Compute product of two sizes with overflow protection (inline).
 * @ingroup foundation
 *
 * Inline function for safe size_t multiplication. Returns exact product if
 * safe, 0 on zero operands or detected overflow. Does not distinguish between
 * zero input and overflow (use check_multiply for that).
 *
 * Optimized for performance in hot paths; compiler may inline the checks.
 *
 * @param[in] a First size_t operand.
 * @param[in] b Second size_t operand.
 *
 * @return a * b if safe and both non-zero, else 0 (overflow or zero input).
 *
 * @threadsafe Yes - pure function, no state.
 *
 * ## Usage Example
 *
 * @code{.c}
 * size_t rows = 100;
 * size_t cols = 100;
 * size_t matrix_size = SocketSecurity_safe_multiply(rows, cols);
 *
 * if (matrix_size == 0) {
 *     // Overflow or zero: handle error
 *     return ERROR_BUFFER_TOO_LARGE;
 * }
 *
 * // Also validate against allocation limit
 * if (!SocketSecurity_check_size(matrix_size)) {
 *     return ERROR_SECURITY_LIMIT;
 * }
 *
 * double *matrix = calloc(matrix_size, sizeof(double)); // Safe now
 * @endcode
 *
 * @note Returns 0 for zero inputs (mathematically correct, but check if
 * needed).
 * @warning Cannot distinguish overflow from zero; pair with check_multiply if
 * required.
 * @complexity O(1)
 *
 * @see SocketSecurity_check_multiply() for separate validation and result
 * storage.
 * @see SocketSecurity_safe_add() companion for addition.
 * @see SOCKET_SECURITY_CHECK_OVERFLOW_MUL macro for check-only inline.
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
 * @brief Compute sum of two sizes with overflow protection (inline).
 * @ingroup foundation
 *
 * Inline safe addition for size_t values. Returns exact sum if no overflow,
 * SIZE_MAX on overflow detection. Useful for buffer growth or offset
 * calculations.
 *
 * Check condition: overflow if a > SIZE_MAX - b. Does not validate individual
 * sizes (use check_size separately).
 *
 * @param[in] a First size_t addend.
 * @param[in] b Second size_t addend.
 *
 * @return a + b if safe, SIZE_MAX if overflow would occur.
 *
 * @threadsafe Yes - pure inline arithmetic.
 *
 * ## Usage Example
 *
 * @code{.c}
 * size_t buf_used = 4096;
 * size_t append_len = 1024;
 * size_t new_used = SocketSecurity_safe_add(buf_used, append_len);
 *
 * if (new_used == SIZE_MAX) {
 *     // Overflow detected
 *     return ERROR_OVERFLOW;
 * }
 *
 * // Check if still within limits
 * if (!SocketSecurity_check_size(new_used)) {
 *     return ERROR_TOO_LARGE;
 * }
 *
 * // Safe to resize or append
 * // e.g., SocketBuf_reserve(buf, new_used);
 * @endcode
 *
 * @note To distinguish valid SIZE_MAX sum from overflow, use check_add first.
 * @warning SIZE_MAX may be valid in some contexts (e.g., unlimited buffers);
 * validate.
 * @complexity O(1)
 *
 * @see SocketSecurity_check_add() for prior validation with optional result.
 * @see SocketSecurity_safe_multiply() for multiplication analog.
 * @see SOCKET_SECURITY_CHECK_OVERFLOW_ADD for check-only macro.
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
 * @brief Inline macro for validating a size against allocation security
 * limits.
 * @ingroup foundation
 *
 * Fast compile-time or runtime check for safe sizes. Expands to expression
 * checking non-zero and <= max allocation. Casts to size_t for safety.
 *
 * Preferred in performance-sensitive code over function call; equivalent to
 * SocketSecurity_check_size but without the SIZE_MAX/2 defense check (use
 * function for full).
 *
 * @param[in] s Size value to validate (any integer type, cast to size_t).
 *
 * @return Non-zero (true) if valid: (size_t)s > 0 && <=
 * SOCKET_SECURITY_MAX_ALLOCATION, else zero (false).
 *
 * ## Usage Example
 *
 * @code{.c}
 * #define MAX_ITEMS 1000
 *
 * if (!SOCKET_SECURITY_VALID_SIZE(MAX_ITEMS * sizeof(ItemStruct))) {
 *     compile_error_or_runtime_fail("Array size too large");
 * }
 *
 * ItemStruct *items = Arena_calloc(arena, MAX_ITEMS, sizeof(ItemStruct));
 * @endcode
 *
 * @note Does not check overflow in expression; validate operands first with
 * check_multiply.
 * @warning Macro expands directly; avoid side effects in (s) (e.g., no
 * function calls).
 * @complexity O(1) - compile-time if possible
 *
 * @see SocketSecurity_check_size() for runtime function with additional
 * defenses.
 * @see SOCKET_SECURITY_CHECK_OVERFLOW_MUL for multiplication checks.
 * @see SocketSecurity_get_max_allocation() for dynamic limit retrieval.
 */
#define SOCKET_SECURITY_VALID_SIZE(s)                                         \
  ((size_t)(s) > 0 && (size_t)(s) <= SOCKET_SECURITY_MAX_ALLOCATION)

/**
 * @brief Inline macro to check size multiplication for overflow risk.
 * @ingroup foundation
 *
 * Expands to expression checking if a * b would overflow size_t. Safe if b==0
 * (product 0) or a <= SIZE_MAX / b. Division-based check avoids overflow.
 *
 * Use before multiplication in hot paths for zero-cost validation.
 *
 * @param[in] a First operand for multiplication.
 * @param[in] b Second operand for multiplication.
 *
 * @return Non-zero (true) if safe to multiply, zero (false) if overflow risk.
 *
 * ## Usage Example
 *
 * @code{.c}
 * size_t num_elements = parse_count(input);
 * size_t struct_size = sizeof(MyStruct);
 *
 * if (SOCKET_SECURITY_CHECK_OVERFLOW_MUL(num_elements, struct_size)) {
 *     size_t total = num_elements * struct_size; // Safe
 *     if (SOCKET_SECURITY_VALID_SIZE(total)) {
 *         MyStruct *arr = Arena_alloc(arena, total, __FILE__, __LINE__);
 *     }
 * } else {
 *     // Overflow risk: limit or error
 * }
 * @endcode
 *
 * @note Parenthesizes arguments; safe for expressions but avoid side effects.
 * @warning Does not compute product; use safe_multiply or check_multiply for
 * that.
 * @complexity O(1) compile-time expandable
 *
 * @see SocketSecurity_check_multiply() function version with result output.
 * @see SOCKET_SECURITY_CHECK_OVERFLOW_ADD for addition check.
 * @see SocketSecurity_safe_multiply() for computing with protection.
 */
#define SOCKET_SECURITY_CHECK_OVERFLOW_MUL(a, b)                              \
  ((b) == 0 || (a) <= SIZE_MAX / (b))

/**
 * @brief Inline macro to check size addition for overflow risk.
 * @ingroup foundation
 *
 * Expands to subtraction-based check: safe if a <= SIZE_MAX - b. Detects
 * overflow before addition, preventing wrap-around.
 *
 * Ideal for buffer appends, index offsets, or cumulative sizes in loops.
 *
 * @param[in] a First addend.
 * @param[in] b Second addend.
 *
 * @return Non-zero (true) if safe to add, zero (false) if overflow.
 *
 * ## Usage Example
 *
 * @code{.c}
 * size_t offset = current_position;
 * size_t len = data_length;
 *
 * if (SOCKET_SECURITY_CHECK_OVERFLOW_ADD(offset, len)) {
 *     // Safe to compute new offset
 *     size_t new_offset = offset + len;
 *     // Further validate new_offset if needed
 * } else {
 *     // Overflow: cap or error
 *     new_offset = SIZE_MAX; // Or handle appropriately
 * }
 * @endcode
 *
 * @note No zero-check; complements VALID_SIZE for full validation.
 * @warning Avoid in expressions with side effects due to macro expansion.
 * @complexity O(1)
 *
 * @see SocketSecurity_check_add() function with result computation.
 * @see SOCKET_SECURITY_CHECK_OVERFLOW_MUL for multiplication.
 * @see SocketSecurity_safe_add() for protected computation.
 */
#define SOCKET_SECURITY_CHECK_OVERFLOW_ADD(a, b) ((a) <= SIZE_MAX - (b))

/* ============================================================================
 * Security Feature Detection
 * ============================================================================
 */

/**
 * @brief Determine if the library was compiled with TLS support.
 * @ingroup foundation
 *
 * Returns whether OpenSSL/LibreSSL was detected and TLS features enabled
 * during build (via CMake -DENABLE_TLS=ON). When false, all TLS-related
 * code is excluded, headers not included, and functions stubbed or absent.
 *
 * Applications use this to conditionally enable/disable TLS features
 * or provide fallbacks.
 *
 * @return 1 if TLS enabled (SOCKET_HAS_TLS=1), 0 if disabled.
 *
 * @threadsafe Yes - compile-time constant evaluation.
 *
 * ## Usage Example
 *
 * @code{.c}
 * if (SocketSecurity_has_tls()) {
 *     // TLS available: configure secure connections
 *     SocketTLSContext_T ctx = SocketTLSContext_new_server(certs, key);
 *     SocketTLS_enable(sock, ctx);
 * } else {
 *     // Fallback to plain TCP
 *     SOCKET_LOG_WARN_MSG("TLS disabled at compile-time; using insecure
 * connections");
 *     // Proceed without TLS...
 * }
 * @endcode
 *
 * ## Build Configuration
 *
 * | CMake Option    | Effect                  | Dependencies     |
 * |-----------------|-------------------------|------------------|
 * | ENABLE_TLS=ON   | Enables TLS modules     | OpenSSL/LibreSSL |
 * | ENABLE_TLS=OFF  | Disables TLS (smaller binary) | None         |
 *
 * @note Defined as #if SOCKET_HAS_TLS in code paths.
 * @warning When disabled, TLS functions unavailable; link errors if used.
 * @complexity O(1)
 *
 * @see SocketSecurity_has_compression() for compression feature check.
 * @see SOCKET_HAS_TLS macro definition.
 * @see @ref security "Security Modules" for TLS implementation.
 * @see CMakeLists.txt build instructions.
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
 * @brief Determine if HTTP/1.1 content compression/decompression is supported.
 * @ingroup foundation
 *
 * Checks if zlib, libbrotli, etc., were detected during build and compression
 * feature enabled (CMake ENABLE_HTTP_COMPRESSION=ON). Supports gzip, deflate,
 * brotli for HTTP Content-Encoding.
 *
 * When disabled, compression headers ignored, no encode/decode APIs available.
 * Reduces binary size and dependencies.
 *
 * @return 1 if compression enabled (SOCKETHTTP1_HAS_COMPRESSION=1), 0
 * otherwise.
 *
 * @threadsafe Yes - constant.
 *
 * ## Usage Example
 *
 * @code{.c}
 * if (SocketSecurity_has_compression()) {
 *     // Enable compression in HTTP server config
 *     SocketHTTPServer_set_compress_response(server, true);
 *     // Or client: request Accept-Encoding: gzip,deflate
 * } else {
 *     SOCKET_LOG_INFO_MSG("HTTP compression disabled; larger payloads
 * expected");
 *     // Disable compression-related features
 * }
 * @endcode
 *
 * ## Dependencies
 *
 * | Library   | Algorithms Supported | CMake Detection |
 * |-----------|----------------------|-----------------|
 * | zlib      | gzip, deflate        | find_package(ZLIB) |
 * | libbrotli | brotli              | find_package(Brotli) |
 *
 * @note Only HTTP/1.1; HTTP/2 uses built-in HPACK compression.
 * @warning Compressed data may amplify certain attacks; validate limits.
 * @complexity O(1)
 *
 * @see SocketSecurity_has_tls() for TLS feature check.
 * @see SOCKETHTTP1_HAS_COMPRESSION macro.
 * @see SocketHTTP1_config_defaults() compression config.
 * @see @ref http "HTTP Modules" for encoding details.
 */
static inline int
SocketSecurity_has_compression (void)
{
#if SOCKETHTTP1_HAS_COMPRESSION
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
