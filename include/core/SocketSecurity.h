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
 * Consolidates security configuration, limits, and validation from across the
 * library. Provides runtime limit queries, size validation with overflow
 * protection, and security configuration inspection.
 *
 * Security Posture:
 * - TLS 1.3 only (no legacy protocols)
 * - Strict input validation with integer overflow protection
 * - Constant-time comparison for security-sensitive operations
 * - Secure memory clearing (resistant to compiler optimization)
 *
 * Thread safety: All functions are thread-safe (no global mutable state).
 */

#ifndef SOCKETSECURITY_INCLUDED
#define SOCKETSECURITY_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Except.h"
#include "core/SocketConfig.h"


/**
 * @brief Maximum single allocation size permitted by security policy.
 * @ingroup foundation
 *
 * Limits individual allocations to mitigate denial-of-service from oversized
 * requests. Default: 256 MiB. Override at compile time.
 */
#ifndef SOCKET_SECURITY_MAX_ALLOCATION
#define SOCKET_SECURITY_MAX_ALLOCATION (256UL * 1024 * 1024)
#endif

/**
 * @brief Maximum permitted size for HTTP request/response bodies.
 * @ingroup foundation
 *
 * Prevents memory exhaustion from large uploads/downloads. Default: 100 MiB.
 */
#ifndef SOCKET_SECURITY_MAX_BODY_SIZE
#define SOCKET_SECURITY_MAX_BODY_SIZE (100 * 1024 * 1024)
#endif

/**
 * @brief Maximum allowed request timeout value in milliseconds.
 * @ingroup foundation
 *
 * Caps timeout values to prevent indefinite resource holds. Default: 60s.
 */
#ifndef SOCKET_SECURITY_MAX_REQUEST_TIMEOUT_MS
#define SOCKET_SECURITY_MAX_REQUEST_TIMEOUT_MS 60000
#endif

/**
 * @brief Exception for security limit violations on size/allocation.
 * @ingroup foundation
 *
 * Raised when requested size exceeds security limits or overflow detected.
 */
extern const Except_T SocketSecurity_SizeExceeded;

/**
 * @brief Exception for input validation failures.
 * @ingroup foundation
 *
 * Raised for invalid input in security contexts (NULL pointers, malformed data).
 */
extern const Except_T SocketSecurity_ValidationFailed;

/**
 * @brief Aggregated security limits for runtime configuration inspection.
 * @ingroup foundation
 *
 * Read-only structure populated by SocketSecurity_get_limits() containing all
 * library security limits derived from compile-time configuration.
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

  int timeout_connect_ms;
  int timeout_dns_ms;
  int timeout_idle_ms;
  int timeout_request_ms;

} SocketSecurityLimits;

/**
 * @brief Retrieve all configured security limits.
 * @ingroup foundation
 *
 * Populates structure with compile-time security limits from across the
 * library. When optional modules are disabled, limits are set to 0.
 *
 * @param[out] limits Structure to populate (must not be NULL).
 *
 * @throws SocketSecurity_ValidationFailed If limits is NULL.
 */
extern void SocketSecurity_get_limits (SocketSecurityLimits *limits);

/**
 * @brief Query the maximum allowed size for single memory allocations.
 * @ingroup foundation
 *
 * @return Maximum permitted allocation size in bytes (default: 256 MiB).
 */
extern size_t SocketSecurity_get_max_allocation (void);

/**
 * @brief Query specific HTTP protocol security limits.
 * @ingroup foundation
 *
 * Allows selective querying of HTTP limits. NULL pointers are ignored.
 * Returns 0 when HTTP support is disabled.
 *
 * @param[out] max_uri Maximum URI length (or NULL).
 * @param[out] max_header_size Maximum total headers size (or NULL).
 * @param[out] max_headers Maximum number of headers (or NULL).
 * @param[out] max_body Maximum HTTP body size (or NULL).
 */
extern void SocketSecurity_get_http_limits (size_t *max_uri,
                                            size_t *max_header_size,
                                            size_t *max_headers,
                                            size_t *max_body);

/**
 * @brief Query WebSocket frame and message size limits.
 * @ingroup foundation
 *
 * Returns 0 when WebSocket support is disabled.
 *
 * @param[out] max_frame Maximum single frame size (or NULL).
 * @param[out] max_message Maximum aggregated message size (or NULL).
 */
extern void SocketSecurity_get_ws_limits (size_t *max_frame,
                                          size_t *max_message);

/**
 * @brief Query the maximum allocation size limit for arenas.
 * @ingroup foundation
 *
 * @param[out] max_alloc Maximum arena allocation size (or NULL).
 */
extern void SocketSecurity_get_arena_limits (size_t *max_alloc);

/**
 * @brief Query HPACK dynamic table size limit for HTTP/2.
 * @ingroup foundation
 *
 * Prevents memory exhaustion from malicious header compression attacks.
 * Returns 0 when HTTP support is disabled.
 *
 * @param[out] max_table Maximum dynamic table size (or NULL).
 */
extern void SocketSecurity_get_hpack_limits (size_t *max_table);

/**
 * @brief Validate a size value for safe memory allocation.
 * @ingroup foundation
 *
 * Checks: non-zero, within limits, and SIZE_MAX/2 overflow defense.
 *
 * @param[in] size Size in bytes to validate.
 * @return 1 if safe, 0 otherwise.
 */
extern int SocketSecurity_check_size (size_t size);

/**
 * @brief Validate multiplication of two sizes for overflow.
 * @ingroup foundation
 *
 * @param[in] a First multiplier.
 * @param[in] b Second multiplier.
 * @param[out] result Optional pointer to store product (or NULL).
 * @return 1 if safe, 0 if overflow would occur.
 */
extern int SocketSecurity_check_multiply (size_t a, size_t b, size_t *result);

/**
 * @brief Validate addition of two sizes for overflow.
 * @ingroup foundation
 *
 * @param[in] a First addend.
 * @param[in] b Second addend.
 * @param[out] result Optional pointer to store sum (or NULL).
 * @return 1 if safe, 0 if overflow would occur.
 */
extern int SocketSecurity_check_add (size_t a, size_t b, size_t *result);

/**
 * @brief Compute product with overflow protection.
 * @ingroup foundation
 *
 * @param[in] a First operand.
 * @param[in] b Second operand.
 * @return a * b if safe, else 0 (cannot distinguish overflow from zero input).
 */
static inline size_t
SocketSecurity_safe_multiply (size_t a, size_t b)
{
  if (a == 0 || b == 0)
    return 0;
  if (a > SIZE_MAX / b)
    return 0;
  return a * b;
}

/**
 * @brief Compute sum with overflow protection.
 * @ingroup foundation
 *
 * @param[in] a First addend.
 * @param[in] b Second addend.
 * @return a + b if safe, SIZE_MAX if overflow would occur.
 */
static inline size_t
SocketSecurity_safe_add (size_t a, size_t b)
{
  if (a > SIZE_MAX - b)
    return SIZE_MAX;
  return a + b;
}

/**
 * @brief Validate size against allocation limits (macro).
 * @ingroup foundation
 *
 * @param[in] s Size to validate.
 * @return Non-zero if valid, zero otherwise.
 */
#define SOCKET_SECURITY_VALID_SIZE(s)                                         \
  ((size_t)(s) > 0 && (size_t)(s) <= SOCKET_SECURITY_MAX_ALLOCATION)

/**
 * @brief Check multiplication for overflow (macro).
 * @ingroup foundation
 *
 * @param[in] a First operand.
 * @param[in] b Second operand.
 * @return Non-zero if safe, zero if overflow risk.
 */
#define SOCKET_SECURITY_CHECK_OVERFLOW_MUL(a, b)                              \
  ((b) == 0 || (a) <= SIZE_MAX / (b))

/**
 * @brief Check addition for overflow (macro).
 * @ingroup foundation
 *
 * @param[in] a First addend.
 * @param[in] b Second addend.
 * @return Non-zero if safe, zero if overflow.
 */
#define SOCKET_SECURITY_CHECK_OVERFLOW_ADD(a, b) ((a) <= SIZE_MAX - (b))

/**
 * @brief Check if library was compiled with TLS support.
 * @ingroup foundation
 *
 * @return 1 if TLS enabled, 0 if disabled.
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
 * @brief Check if HTTP/1.1 content compression is supported.
 * @ingroup foundation
 *
 * @return 1 if compression enabled, 0 otherwise.
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


#endif /* SOCKETSECURITY_INCLUDED */
