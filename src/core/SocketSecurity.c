/**
 * SocketSecurity.c - Centralized Security Configuration and Utilities
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This module consolidates security limit queries and validation utilities
 * from across the socket library. All functions are thread-safe as they
 * only access compile-time constants.
 */
#include <assert.h>

#include "core/SocketSecurity.h"

#include "core/SocketConfig.h"

#include "core/SocketConfig.h"

/* Conditional includes for optional modules */
#ifdef SOCKET_HAS_HTTP

#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTP2.h"
#endif

#ifdef SOCKET_HAS_WEBSOCKET
#include "socket/SocketWS-private.h"
#endif

#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLSConfig.h"
#endif

/* ============================================================================
 * Exception Definitions
 * ============================================================================
 *
 * Exception pattern: { &ExceptionName, "reason" }
 * The first field is a self-reference used for type identification when
 * catching exceptions. The EXCEPT(e) macro compares exception->type == &(e).
 */

const Except_T SocketSecurity_SizeExceeded
    = { &SocketSecurity_SizeExceeded,
        "Allocation or buffer size exceeds security limits" };

const Except_T SocketSecurity_ValidationFailed
    = { &SocketSecurity_ValidationFailed, "Input validation failed" };

/* ============================================================================
 * Default Values for Optional Modules
 * ============================================================================
 *
 * These provide sensible defaults when optional modules aren't compiled in.
 * Values match the defaults in their respective headers.
 */

/* HTTP defaults (if SocketHTTP.h not included) */
#ifndef SOCKETHTTP_MAX_HEADER_NAME
#define SOCKETHTTP_MAX_HEADER_NAME 256
#endif

#ifndef SOCKETHTTP_MAX_HEADER_VALUE
#define SOCKETHTTP_MAX_HEADER_VALUE (8 * 1024)
#endif

#ifndef SOCKETHTTP_MAX_HEADER_SIZE
#define SOCKETHTTP_MAX_HEADER_SIZE (64 * 1024)
#endif

#ifndef SOCKETHTTP_MAX_HEADERS
#define SOCKETHTTP_MAX_HEADERS 100
#endif

#ifndef SOCKETHTTP_MAX_URI_LEN
#define SOCKETHTTP_MAX_URI_LEN (8 * 1024)
#endif

/* HTTP/1.1 defaults (if SocketHTTP1.h not included) */
#ifndef SOCKETHTTP1_MAX_REQUEST_LINE
#define SOCKETHTTP1_MAX_REQUEST_LINE (8 * 1024)
#endif

#ifndef SOCKETHTTP1_MAX_CHUNK_SIZE
#define SOCKETHTTP1_MAX_CHUNK_SIZE (16 * 1024 * 1024)
#endif

/* HTTP/2 defaults (if SocketHTTP2.h not included) */
#ifndef SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS
#define SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS 100
#endif

#ifndef SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE
#define SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE 16384
#endif

#ifndef SOCKETHTTP2_DEFAULT_MAX_HEADER_LIST_SIZE
#define SOCKETHTTP2_DEFAULT_MAX_HEADER_LIST_SIZE (16 * 1024)
#endif

/* WebSocket defaults (if SocketWS-private.h not included) */
#ifndef SOCKETWS_MAX_FRAME_SIZE
#define SOCKETWS_MAX_FRAME_SIZE (16 * 1024 * 1024)
#endif

#ifndef SOCKETWS_MAX_MESSAGE_SIZE
#define SOCKETWS_MAX_MESSAGE_SIZE (64 * 1024 * 1024)
#endif

/* TLS defaults (if SocketTLSConfig.h not included) */
#ifndef SOCKET_TLS_MAX_CERT_CHAIN_DEPTH
#define SOCKET_TLS_MAX_CERT_CHAIN_DEPTH 10
#endif

#ifndef SOCKET_TLS_SESSION_CACHE_SIZE
#define SOCKET_TLS_SESSION_CACHE_SIZE 1000
#endif

/* ============================================================================
 * Static Helper Functions - Populate Limit Categories
 * ============================================================================
 *
 * Each helper populates a specific category of limits. This keeps functions
 * small and single-purpose per GNU/CII guidelines.
 */

/* Removed redundant populate functions - inlined into get_limits for reduced duplication */

/* ============================================================================
 * Public Limit Query Functions
 * ============================================================================ */

/**
 * set_size_ptr - Set optional size_t output parameter
 * @ptr: Pointer to size_t (may be NULL)
 * @value: Value to set if ptr not NULL
 *
 * Internal helper to set optional output parameters with null check.
 * Thread-safe: Yes
 */
#define set_size_ptr(ptr, val) do { if (ptr) *(ptr) = (val); } while (0)


/**
 * SocketSecurity_get_limits - Populate all security limits
 * @limits: Output structure to fill with current limits
 *
 * Populates the provided structure with all security-related limits
 * from across the socket library modules. This provides a single point
 * of reference for security configuration inspection.
 *
 * Thread-safe: Yes (reads compile-time constants only)
 */
void
SocketSecurity_get_limits (SocketSecurityLimits *limits)
{
        assert (limits != NULL);

        /* Memory limits */
        limits->max_allocation = SOCKET_SECURITY_MAX_ALLOCATION;
        limits->max_buffer_size = SOCKET_MAX_BUFFER_SIZE;
        limits->max_connections = SOCKET_MAX_CONNECTIONS;

        /* HTTP limits */
        limits->http_max_uri_length = SOCKETHTTP_MAX_URI_LEN;
        limits->http_max_header_name = SOCKETHTTP_MAX_HEADER_NAME;
        limits->http_max_header_value = SOCKETHTTP_MAX_HEADER_VALUE;
        limits->http_max_header_size = SOCKETHTTP_MAX_HEADER_SIZE;
        limits->http_max_headers = SOCKETHTTP_MAX_HEADERS;
        limits->http_max_body_size = SOCKET_SECURITY_MAX_BODY_SIZE;

        /* HTTP/1.1 limits */
        limits->http1_max_request_line = SOCKETHTTP1_MAX_REQUEST_LINE;
        limits->http1_max_chunk_size = SOCKETHTTP1_MAX_CHUNK_SIZE;

        /* HTTP/2 limits */
        limits->http2_max_concurrent_streams = SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS;
        limits->http2_max_frame_size = SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE;
        limits->http2_max_header_list_size = SOCKETHTTP2_DEFAULT_MAX_HEADER_LIST_SIZE;

        /* WebSocket limits */
        limits->ws_max_frame_size = SOCKETWS_MAX_FRAME_SIZE;
        limits->ws_max_message_size = SOCKETWS_MAX_MESSAGE_SIZE;

        /* TLS limits */
        limits->tls_max_cert_chain_depth = SOCKET_TLS_MAX_CERT_CHAIN_DEPTH;
        limits->tls_session_cache_size = SOCKET_TLS_SESSION_CACHE_SIZE;

        /* Rate limiting defaults */
        limits->ratelimit_conn_per_sec = SOCKET_RATELIMIT_DEFAULT_CONN_PER_SEC;
        limits->ratelimit_burst = SOCKET_RATELIMIT_DEFAULT_BURST;
        limits->ratelimit_max_per_ip = SOCKET_RATELIMIT_DEFAULT_MAX_PER_IP;

        /* Timeout defaults (in milliseconds) */
        limits->timeout_connect_ms = SOCKET_DEFAULT_CONNECT_TIMEOUT_MS;
        limits->timeout_dns_ms = SOCKET_DEFAULT_DNS_TIMEOUT_MS;
        limits->timeout_idle_ms = SOCKET_DEFAULT_IDLE_TIMEOUT * SOCKET_MS_PER_SECOND;
        limits->timeout_request_ms = SOCKET_SECURITY_MAX_REQUEST_TIMEOUT_MS;
}

/**
 * SocketSecurity_get_max_allocation - Get maximum safe allocation size
 *
 * Returns: Maximum allocation size in bytes (SOCKET_SECURITY_MAX_ALLOCATION)
 * Thread-safe: Yes
 */
size_t
SocketSecurity_get_max_allocation (void)
{
        return SOCKET_SECURITY_MAX_ALLOCATION;
}

/**
 * SocketSecurity_get_http_limits - Get HTTP-specific limits
 * @max_uri: Output for max URI length (may be NULL to skip)
 * @max_header_size: Output for max total header size (may be NULL to skip)
 * @max_headers: Output for max header count (may be NULL to skip)
 * @max_body: Output for max body size (may be NULL to skip)
 *
 * Thread-safe: Yes
 */
void
SocketSecurity_get_http_limits (size_t *max_uri, size_t *max_header_size,
                                size_t *max_headers, size_t *max_body)
{
        set_size_ptr (max_uri, SOCKETHTTP_MAX_URI_LEN);
        set_size_ptr (max_header_size, SOCKETHTTP_MAX_HEADER_SIZE);
        set_size_ptr (max_headers, SOCKETHTTP_MAX_HEADERS);
        set_size_ptr (max_body, SOCKET_SECURITY_MAX_BODY_SIZE);
}



/**
 * SocketSecurity_get_ws_limits - Get WebSocket-specific limits
 * @max_frame: Output for max frame size (may be NULL to skip)
 * @max_message: Output for max message size (may be NULL to skip)
 *
 * Thread-safe: Yes
 */
void
SocketSecurity_get_ws_limits (size_t *max_frame, size_t *max_message)
{
        set_size_ptr (max_frame, SOCKETWS_MAX_FRAME_SIZE);
        set_size_ptr (max_message, SOCKETWS_MAX_MESSAGE_SIZE);
}

/* ============================================================================
 * Size Validation Functions
 * ============================================================================ */

/**
 * SocketSecurity_check_size - Validate allocation size for safety
 * @size: Requested size to validate
 *
 * Validates that size is:
 * 1. Non-zero (zero-size allocations rejected as likely errors)
 * 2. Within SOCKET_SECURITY_MAX_ALLOCATION limit
 * 3. Not suspiciously large (defense-in-depth against overflow)
 *
 * The SIZE_MAX/2 check provides defense-in-depth protection even if
 * SOCKET_SECURITY_MAX_ALLOCATION is overridden to an unsafe value at
 * compile time. On 64-bit systems this is ~9 exabytes.
 *
 * Returns: 1 if size is valid, 0 if invalid
 * Thread-safe: Yes
 */
int
SocketSecurity_check_size (size_t size)
{
        /* Reject zero-size allocations as likely programmer error */
        if (size == 0)
                return 0;

        /* Check against configured maximum */
        if (size > SOCKET_SECURITY_MAX_ALLOCATION)
                return 0;

        /* Defense-in-depth: reject sizes > SIZE_MAX/2 as likely overflow */
        if (size > SIZE_MAX / 2)
                return 0;

        return 1;
}

/**
 * SocketSecurity_check_multiply - Check multiplication for overflow
 * @a: First operand
 * @b: Second operand
 * @result: Output for product if no overflow (may be NULL if just checking)
 *
 * Safely checks if a * b would overflow before performing the operation.
 * Uses SOCKET_SECURITY_CHECK_OVERFLOW_MUL macro for consistency with other modules.
 *
 * Returns: 1 if multiplication is safe, 0 if would overflow
 * Thread-safe: Yes
 */
int
SocketSecurity_check_multiply (size_t a, size_t b, size_t *result)
{
        if (!SOCKET_SECURITY_CHECK_OVERFLOW_MUL(a, b))
                return 0;

        if (result != NULL)
                *result = a * b;

        return 1;
}

/**
 * SocketSecurity_check_add - Check addition for overflow
 * @a: First operand
 * @b: Second operand
 * @result: Output for sum if no overflow (may be NULL if just checking)
 *
 * Safely checks if a + b would overflow before performing the operation.
 * Uses SOCKET_SECURITY_CHECK_OVERFLOW_ADD macro for consistency with other modules.
 *
 * Returns: 1 if addition is safe, 0 if would overflow
 * Thread-safe: Yes
 */
int
SocketSecurity_check_add (size_t a, size_t b, size_t *result)
{
        if (!SOCKET_SECURITY_CHECK_OVERFLOW_ADD(a, b))
                return 0;

        if (result != NULL)
                *result = a + b;

        return 1;
}
