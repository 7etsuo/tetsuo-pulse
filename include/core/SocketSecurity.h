/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSecurity.h
 * @ingroup foundation
 * @brief Centralized security configuration, limits, and validation utilities.
 *
 * Example:
 * @code{.c}
 * SocketSecurityLimits limits;
 * SocketSecurity_get_limits(&limits);
 * if (request_size > limits.max_allocation) {
 *     return send_http_error(client, 413, "Payload Too Large");
 * }
 * @endcode
 *
 * Thread safety: All functions are thread-safe (no global mutable state).
 */

#ifndef SOCKETSECURITY_INCLUDED
#define SOCKETSECURITY_INCLUDED

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "core/Except.h"
#include "core/SocketConfig.h"

/**
 * @brief Maximum single allocation size permitted by security policy.
 *
 * Default: 256 MiB (268435456 bytes). Override by defining this macro to a
 * different value before including SocketSecurity.h or any header that
 * includes it.
 */
#ifndef SOCKET_SECURITY_MAX_ALLOCATION
#define SOCKET_SECURITY_MAX_ALLOCATION (256UL * 1024 * 1024)
#endif

/**
 * @brief Maximum permitted size for HTTP request/response bodies.
 *
 * Default: 100 MiB. Override via compile-time definition.
 */
#ifndef SOCKET_SECURITY_MAX_BODY_SIZE
#define SOCKET_SECURITY_MAX_BODY_SIZE (100 * 1024 * 1024)
#endif

/**
 * @brief Maximum allowed request timeout value in milliseconds.
 *
 * Default: 60 seconds (60000 ms). Override by defining before inclusion.
 */
#ifndef SOCKET_SECURITY_MAX_REQUEST_TIMEOUT_MS
#define SOCKET_SECURITY_MAX_REQUEST_TIMEOUT_MS 60000
#endif

/**
 * @brief Exception indicating security limit violation on size/allocation.
 *
 * Raised when requested size exceeds configured security limits or when size
 * computations detect potential overflow/invalidity.
 */
extern const Except_T SocketSecurity_SizeExceeded;

/**
 * @brief Exception for general input validation failures in security contexts.
 *
 * Raised for invalid or malicious input detected during security-related
 * validations, such as NULL pointers in required params, malformed protocol
 * data, or invalid characters/formats.
 */
extern const Except_T SocketSecurity_ValidationFailed;

/**
 * @brief Aggregated security limits for runtime configuration inspection.
 *
 * @threadsafe Yes (immutable after get_limits())
 */
typedef struct SocketSecurityLimits
{
  size_t max_allocation;
  size_t max_buffer_size;
  size_t max_connections;
  size_t arena_max_alloc_size;
  size_t http_max_uri_length;
  size_t http_max_header_name;
  size_t http_max_header_value;
  size_t http_max_header_size;
  size_t http_max_headers;
  size_t http_max_body_size;
  size_t http1_max_request_line;
  size_t http1_max_chunk_size;
  size_t http2_max_concurrent_streams;
  size_t http2_max_frame_size;
  size_t http2_max_header_list_size;
  size_t tls_max_alpn_protocols;
  size_t tls_max_alpn_len;
  size_t tls_max_alpn_total_bytes;
  size_t hpack_max_table_size;
  size_t ws_max_frame_size;
  size_t ws_max_message_size;
  size_t tls_max_cert_chain_depth;
  size_t tls_session_cache_size;
  size_t ratelimit_conn_per_sec;
  size_t ratelimit_burst;
  size_t ratelimit_max_per_ip;
  int    timeout_connect_ms;
  int    timeout_dns_ms;
  int    timeout_idle_ms;
  int    timeout_request_ms;
} SocketSecurityLimits;

/**
 * @brief Retrieve all configured security limits into a structure for
 * inspection.
 *
 * @param limits  Pointer to a SocketSecurityLimits structure to populate (must
 * not be NULL)
 *
 * Raises: SocketSecurity_ValidationFailed if limits is NULL
 *
 * @threadsafe Yes
 * @complexity O(1)
 */
extern void SocketSecurity_get_limits (SocketSecurityLimits *limits);

/**
 * @brief Query the maximum allowed size for single memory allocations.
 *
 * Returns: Maximum permitted allocation size in bytes
 *
 * @threadsafe Yes
 * @complexity O(1)
 */
extern size_t SocketSecurity_get_max_allocation (void);

/**
 * @brief Query specific HTTP protocol security limits.
 *
 * @param max_uri          Maximum URI length in bytes, or NULL
 * @param max_header_size  Maximum total headers size in bytes, or NULL
 * @param max_headers      Maximum number of HTTP headers allowed, or NULL
 * @param max_body         Maximum HTTP body size in bytes, or NULL
 *
 * @threadsafe Yes
 * @complexity O(1)
 */
extern void SocketSecurity_get_http_limits (size_t *max_uri,
                                             size_t *max_header_size,
                                             size_t *max_headers,
                                             size_t *max_body);

/**
 * @brief Query WebSocket-specific security limits for frame and message sizes.
 *
 * @param max_frame    Maximum single WebSocket frame size in bytes, or NULL
 * @param max_message  Maximum aggregated message size in bytes, or NULL
 *
 * @threadsafe Yes
 * @complexity O(1)
 */
extern void SocketSecurity_get_ws_limits (size_t *max_frame,
                                           size_t *max_message);

/**
 * @brief Query the maximum allocation size limit for arenas.
 *
 * @param max_alloc  Maximum allowed allocation from arena in bytes, or NULL
 *
 * @threadsafe Yes
 * @complexity O(1)
 */
extern void SocketSecurity_get_arena_limits (size_t *max_alloc);

/**
 * @brief Query HPACK dynamic table size limit for HTTP/2 header compression.
 *
 * @param max_table  Maximum dynamic table size in bytes, or NULL
 *
 * @threadsafe Yes
 * @complexity O(1)
 */
extern void SocketSecurity_get_hpack_limits (size_t *max_table);

/**
 * @brief Validate a size value for safe memory allocation or buffer
 * operations.
 *
 * Checks: non-zero, within global max allocation limit, not > SIZE_MAX/2
 *
 * @param size  Proposed size in bytes to validate
 *
 * Returns: 1 if size is safe, 0 otherwise
 *
 * @threadsafe Yes
 * @complexity O(1)
 */
extern int SocketSecurity_check_size (size_t size);

/**
 * @brief Validate multiplication of two sizes for potential overflow.
 *
 * @param a       First multiplier
 * @param b       Second multiplier
 * @param result  Optional pointer to store a * b if no overflow, or NULL
 *
 * Returns: 1 if multiplication safe (no overflow), 0 if overflow risk
 *
 * @threadsafe Yes
 * @complexity O(1)
 */
extern int SocketSecurity_check_multiply (size_t a, size_t b, size_t *result);

/**
 * @brief Validate addition of two sizes for potential overflow.
 *
 * @param a       First addend
 * @param b       Second addend
 * @param result  Optional pointer to store a + b if no overflow, or NULL
 *
 * Returns: 1 if addition safe (no overflow), 0 if would overflow
 *
 * @threadsafe Yes
 * @complexity O(1)
 */
extern int SocketSecurity_check_add (size_t a, size_t b, size_t *result);

/**
 * @brief Compute product of two sizes with overflow protection (inline).
 *
 * @param a  First size_t operand
 * @param b  Second size_t operand
 *
 * Returns: a * b if safe and both non-zero, else 0 (overflow or zero input)
 *
 * @threadsafe Yes
 * @complexity O(1)
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
 *
 * @param a  First size_t addend
 * @param b  Second size_t addend
 *
 * Returns: a + b if safe, SIZE_MAX if overflow would occur
 *
 * @threadsafe Yes
 * @complexity O(1)
 */
static inline size_t
SocketSecurity_safe_add (size_t a, size_t b)
{
  if (a > SIZE_MAX - b)
    return SIZE_MAX; /* Would overflow */
  return a + b;
}

/**
 * @brief Inline macro for validating a size against allocation security
 * limits.
 *
 * @param s  Size value to validate
 *
 * Returns: Non-zero if valid (size_t)s > 0 && <= max_allocation, else zero
 */
#define SOCKET_SECURITY_VALID_SIZE(s)                                         \
  ((size_t)(s) > 0 && (size_t)(s) <= SOCKET_SECURITY_MAX_ALLOCATION)

/**
 * @brief Inline macro to check size multiplication for overflow risk.
 *
 * @param a  First operand for multiplication
 * @param b  Second operand for multiplication
 *
 * Returns: Non-zero if safe to multiply, zero if overflow risk
 */
#define SOCKET_SECURITY_CHECK_OVERFLOW_MUL(a, b)                              \
  ((b) == 0 || (a) <= SIZE_MAX / (b))

/**
 * @brief Inline macro to check size addition for overflow risk.
 *
 * @param a  First addend
 * @param b  Second addend
 *
 * Returns: Non-zero if safe to add, zero if overflow
 */
#define SOCKET_SECURITY_CHECK_OVERFLOW_ADD(a, b) ((a) <= SIZE_MAX - (b))

/**
 * @brief Determine if the library was compiled with TLS support.
 *
 * Returns: 1 if TLS enabled (SOCKET_HAS_TLS=1), 0 if disabled
 *
 * @threadsafe Yes
 * @complexity O(1)
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
 *
 * Returns: 1 if compression enabled (SOCKETHTTP1_HAS_COMPRESSION=1), 0
 * otherwise
 *
 * @threadsafe Yes
 * @complexity O(1)
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

/**
 * @brief Check if string contains prohibited control characters.
 *
 * Detects NUL (0x00), CR (0x0D), and LF (0x0A) which are prohibited in
 * HTTP header values and other protocol contexts. Used for header injection
 * prevention.
 *
 * @param data  String to check (must not be NULL).
 * @param len   Length of string to check.
 *
 * Returns: 1 if control characters found, 0 if clean.
 *
 * @threadsafe Yes (pure function)
 * @complexity O(n) where n is len
 *
 * @note This is a performance-critical inline function. The data parameter
 *       MUST NOT be NULL - this is validated by assertion in debug builds only.
 *       Callers are responsible for NULL validation in production code.
 *
 * Example usage:
 * @code{.c}
 * // Always validate data pointer before calling
 * if (header_value && SocketSecurity_has_control_chars(header_value, len)) {
 *     return HTTP_400_BAD_REQUEST;
 * }
 * @endcode
 */
static inline int
SocketSecurity_has_control_chars (const char *data, size_t len)
{
  assert (data != NULL);
  for (size_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char)data[i];
      if (c == 0x00 || c == 0x0D || c == 0x0A)
        return 1;
    }
  return 0;
}

#endif /* SOCKETSECURITY_INCLUDED */
