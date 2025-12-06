/**
 * SocketSecurity.c - Centralized Security Configuration and Utilities
 *
 * Part of the Socket Library
 *
 * Implementation of security limit queries and validation utilities.
 */

#include "core/SocketSecurity.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

/* Include headers that define the limits we're consolidating */
#include "core/SocketConfig.h"

/* Conditional includes for optional modules */
#ifdef SOCKET_HAS_HTTP
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTP2.h"
#include "http/SocketHPACK.h"
#endif

#ifdef SOCKET_HAS_WEBSOCKET
#include "socket/SocketWS-private.h"
#endif

#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLSConfig.h"
#endif

/* ============================================================================
 * Exception Definitions
 * ============================================================================ */

const Except_T SocketSecurity_SizeExceeded
    = { &SocketSecurity_SizeExceeded,
        "Allocation or buffer size exceeds security limits" };

const Except_T SocketSecurity_ValidationFailed
    = { &SocketSecurity_ValidationFailed, "Input validation failed" };

/* ============================================================================
 * Default Values for Optional Modules
 * ============================================================================
 * These provide sensible defaults when optional modules aren't compiled in.
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
 * Limit Query Functions
 * ============================================================================ */

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
  limits->http2_max_concurrent_streams
      = SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS;
  limits->http2_max_frame_size = SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE;
  limits->http2_max_header_list_size
      = SOCKETHTTP2_DEFAULT_MAX_HEADER_LIST_SIZE;

  /* WebSocket limits */
  limits->ws_max_frame_size = SOCKETWS_MAX_FRAME_SIZE;
  limits->ws_max_message_size = SOCKETWS_MAX_MESSAGE_SIZE;

  /* TLS limits */
  limits->tls_max_cert_chain_depth = SOCKET_TLS_MAX_CERT_CHAIN_DEPTH;
  limits->tls_session_cache_size = SOCKET_TLS_SESSION_CACHE_SIZE;

  /* Rate limiting */
  limits->ratelimit_conn_per_sec = SOCKET_RATELIMIT_DEFAULT_CONN_PER_SEC;
  limits->ratelimit_burst = SOCKET_RATELIMIT_DEFAULT_BURST;
  limits->ratelimit_max_per_ip = SOCKET_RATELIMIT_DEFAULT_MAX_PER_IP;

  /* Timeouts */
  limits->timeout_connect_ms = SOCKET_DEFAULT_CONNECT_TIMEOUT_MS;
  limits->timeout_dns_ms = SOCKET_DEFAULT_DNS_TIMEOUT_MS;
  limits->timeout_idle_ms = SOCKET_DEFAULT_IDLE_TIMEOUT * SOCKET_MS_PER_SECOND;
  limits->timeout_request_ms = SOCKET_SECURITY_MAX_REQUEST_TIMEOUT_MS;
}

size_t
SocketSecurity_get_max_allocation (void)
{
  return SOCKET_SECURITY_MAX_ALLOCATION;
}

void
SocketSecurity_get_http_limits (size_t *max_uri, size_t *max_header_size,
                                size_t *max_headers, size_t *max_body)
{
  if (max_uri)
    *max_uri = SOCKETHTTP_MAX_URI_LEN;
  if (max_header_size)
    *max_header_size = SOCKETHTTP_MAX_HEADER_SIZE;
  if (max_headers)
    *max_headers = SOCKETHTTP_MAX_HEADERS;
  if (max_body)
    *max_body = SOCKET_SECURITY_MAX_BODY_SIZE;
}

void
SocketSecurity_get_ws_limits (size_t *max_frame, size_t *max_message)
{
  if (max_frame)
    *max_frame = SOCKETWS_MAX_FRAME_SIZE;
  if (max_message)
    *max_message = SOCKETWS_MAX_MESSAGE_SIZE;
}

/* ============================================================================
 * Size Validation Functions
 * ============================================================================ */

int
SocketSecurity_check_size (size_t size)
{
  /* Zero size is often valid (empty allocations) but we reject it for safety */
  if (size == 0)
    return 0;

  /* Check against maximum allocation limit */
  if (size > SOCKET_SECURITY_MAX_ALLOCATION)
    return 0;

  /* Check for likely overflow (very large size_t that looks like negative) */
  /* On 64-bit, SIZE_MAX/2 is still ~9 exabytes, so this is a sanity check */
  if (size > SIZE_MAX / 2)
    return 0;

  return 1;
}

int
SocketSecurity_check_multiply (size_t a, size_t b, size_t *result)
{
  /* Handle zero cases */
  if (a == 0 || b == 0)
    {
      if (result)
        *result = 0;
      return 1;
    }

  /* Check if multiplication would overflow */
  if (a > SIZE_MAX / b)
    return 0;

  if (result)
    *result = a * b;

  return 1;
}

int
SocketSecurity_check_add (size_t a, size_t b, size_t *result)
{
  /* Check if addition would overflow */
  if (a > SIZE_MAX - b)
    return 0;

  if (result)
    *result = a + b;

  return 1;
}

