/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* Centralized security configuration and validation utilities */
#include <assert.h>

#include "core/SocketConfig.h"
#include "core/SocketSecurity.h"

/* Fallback definitions for disabled optional modules */

#if !SOCKET_HAS_HTTP
#define SOCKETHTTP_MAX_URI_LEN 0
#define SOCKETHTTP_MAX_HEADER_NAME 0
#define SOCKETHTTP_MAX_HEADER_VALUE 0
#define SOCKETHTTP_MAX_HEADER_SIZE 0
#define SOCKETHTTP_MAX_HEADERS 0
#define SOCKETHTTP1_MAX_REQUEST_LINE 0
#define SOCKETHTTP1_MAX_CHUNK_SIZE 0
#define SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS 0
#define SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE 0
#define SOCKETHTTP2_DEFAULT_MAX_HEADER_LIST_SIZE 0
#define SOCKETHPACK_MAX_TABLE_SIZE 0
#endif

#if !SOCKET_HAS_WEBSOCKET
#define SOCKETWS_MAX_FRAME_SIZE 0
#define SOCKETWS_MAX_MESSAGE_SIZE 0
#endif

#if !SOCKET_HAS_TLS
#define SOCKET_TLS_MAX_CERT_CHAIN_DEPTH 0
#define SOCKET_TLS_SESSION_CACHE_SIZE 0
#endif

#if SOCKET_HAS_HTTP

#include "http/SocketHPACK.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTP2.h"
#endif

#if SOCKET_HAS_WEBSOCKET
#include "socket/SocketWS-private.h"
#endif

#if SOCKET_HAS_TLS
#include "tls/SocketTLSConfig.h"
#endif

 */

const Except_T SocketSecurity_SizeExceeded
    = { &SocketSecurity_SizeExceeded,
        "Allocation or buffer size exceeds security limits" };

const Except_T SocketSecurity_ValidationFailed
    = { &SocketSecurity_ValidationFailed, "Input validation failed" };


 */
static void
populate_memory_limits (SocketSecurityLimits *limits)
{
  assert (limits != NULL);
  limits->max_allocation = SOCKET_SECURITY_MAX_ALLOCATION;
  limits->max_buffer_size = SOCKET_MAX_BUFFER_SIZE;
  limits->max_connections = SOCKET_MAX_CONNECTIONS;
  limits->arena_max_alloc_size = ARENA_MAX_ALLOC_SIZE;
}

static void
populate_http_limits (SocketSecurityLimits *limits)
{
  assert (limits != NULL);
  limits->http_max_uri_length = SOCKETHTTP_MAX_URI_LEN;
  limits->http_max_header_name = SOCKETHTTP_MAX_HEADER_NAME;
  limits->http_max_header_value = SOCKETHTTP_MAX_HEADER_VALUE;
  limits->http_max_header_size = SOCKETHTTP_MAX_HEADER_SIZE;
  limits->http_max_headers = SOCKETHTTP_MAX_HEADERS;
  limits->http_max_body_size = SOCKET_SECURITY_MAX_BODY_SIZE;
}

static void
populate_http1_limits (SocketSecurityLimits *limits)
{
  assert (limits != NULL);
  limits->http1_max_request_line = SOCKETHTTP1_MAX_REQUEST_LINE;
  limits->http1_max_chunk_size = SOCKETHTTP1_MAX_CHUNK_SIZE;
}

static void
populate_http2_limits (SocketSecurityLimits *limits)
{
  assert (limits != NULL);
  limits->http2_max_concurrent_streams
      = SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS;
  limits->http2_max_frame_size = SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE;
  limits->http2_max_header_list_size
      = SOCKETHTTP2_DEFAULT_MAX_HEADER_LIST_SIZE;
}

static void
populate_hpack_limits (SocketSecurityLimits *limits)
{
  assert (limits != NULL);
  limits->hpack_max_table_size = SOCKETHPACK_MAX_TABLE_SIZE;
}

static void
populate_ws_limits (SocketSecurityLimits *limits)
{
  assert (limits != NULL);
  limits->ws_max_frame_size = SOCKETWS_MAX_FRAME_SIZE;
  limits->ws_max_message_size = SOCKETWS_MAX_MESSAGE_SIZE;
}

static void
populate_tls_limits (SocketSecurityLimits *limits)
{
  assert (limits != NULL);
#if SOCKET_HAS_TLS
  limits->tls_max_cert_chain_depth = SOCKET_TLS_MAX_CERT_CHAIN_DEPTH;
  limits->tls_session_cache_size = SOCKET_TLS_SESSION_CACHE_SIZE;
  limits->tls_max_alpn_protocols = SOCKET_TLS_MAX_ALPN_PROTOCOLS;
  limits->tls_max_alpn_len = SOCKET_TLS_MAX_ALPN_LEN;
  limits->tls_max_alpn_total_bytes = SOCKET_TLS_MAX_ALPN_TOTAL_BYTES;
#endif
}

static void
populate_ratelimit_limits (SocketSecurityLimits *limits)
{
  assert (limits != NULL);
  limits->ratelimit_conn_per_sec = SOCKET_RATELIMIT_DEFAULT_CONN_PER_SEC;
  limits->ratelimit_burst = SOCKET_RATELIMIT_DEFAULT_BURST;
  limits->ratelimit_max_per_ip = SOCKET_RATELIMIT_DEFAULT_MAX_PER_IP;
}

static void
populate_timeout_limits (SocketSecurityLimits *limits)
{
  assert (limits != NULL);
  limits->timeout_connect_ms = SOCKET_DEFAULT_CONNECT_TIMEOUT_MS;
  limits->timeout_dns_ms = SOCKET_DEFAULT_DNS_TIMEOUT_MS;
  limits->timeout_idle_ms = SOCKET_DEFAULT_IDLE_TIMEOUT * SOCKET_MS_PER_SECOND;
  limits->timeout_request_ms = SOCKET_SECURITY_MAX_REQUEST_TIMEOUT_MS;
}

 */

/* Set optional output parameter if not NULL */
#define set_size_ptr(ptr, val)                                                \
  do                                                                          \
    {                                                                         \
      if (ptr)                                                                \
        *(ptr) = (val);                                                       \
    }                                                                         \
  while (0)

void
SocketSecurity_get_limits (SocketSecurityLimits *limits)
{
  if (!limits)
    {
      RAISE (SocketSecurity_ValidationFailed);
    }

  populate_memory_limits (limits);
  populate_http_limits (limits);
  populate_http1_limits (limits);
  populate_http2_limits (limits);
  populate_hpack_limits (limits);
  populate_ws_limits (limits);
  populate_tls_limits (limits);
  populate_ratelimit_limits (limits);
  populate_timeout_limits (limits);
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
  set_size_ptr (max_uri, SOCKETHTTP_MAX_URI_LEN);
  set_size_ptr (max_header_size, SOCKETHTTP_MAX_HEADER_SIZE);
  set_size_ptr (max_headers, SOCKETHTTP_MAX_HEADERS);
  set_size_ptr (max_body, SOCKET_SECURITY_MAX_BODY_SIZE);
}

void
SocketSecurity_get_ws_limits (size_t *max_frame, size_t *max_message)
{
  set_size_ptr (max_frame, SOCKETWS_MAX_FRAME_SIZE);
  set_size_ptr (max_message, SOCKETWS_MAX_MESSAGE_SIZE);
}

void
SocketSecurity_get_arena_limits (size_t *max_alloc)
{
  set_size_ptr (max_alloc, ARENA_MAX_ALLOC_SIZE);
}

void
SocketSecurity_get_hpack_limits (size_t *max_table)
{
  set_size_ptr (max_table, SOCKETHPACK_MAX_TABLE_SIZE);
}

 */

int
SocketSecurity_check_size (size_t size)
{
  if (size == 0)
    return 0;
  if (size > SOCKET_SECURITY_MAX_ALLOCATION)
    return 0;
  if (size > SIZE_MAX / 2) /* Defense-in-depth against overflow */
    return 0;
  return 1;
}

int
SocketSecurity_check_multiply (size_t a, size_t b, size_t *result)
{
  if (!SOCKET_SECURITY_CHECK_OVERFLOW_MUL (a, b))
    return 0;
  if (result != NULL)
    *result = a * b;
  return 1;
}

int
SocketSecurity_check_add (size_t a, size_t b, size_t *result)
{
  if (!SOCKET_SECURITY_CHECK_OVERFLOW_ADD (a, b))
    return 0;
  if (result != NULL)
    *result = a + b;
  return 1;
}
