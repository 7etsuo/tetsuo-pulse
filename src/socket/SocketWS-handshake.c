/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketWS-handshake.c - WebSocket Handshake (RFC 6455 Section 4)
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * HTTP upgrade handshake for WebSocket connections.
 *
 * Module Reuse (zero duplication):
 * - SocketCrypto: websocket_key(), websocket_accept(), secure_compare()
 * - SocketHTTP1: Parser for response parsing, serialize for request
 * - SocketHTTP: Headers management
 *
 * Client Handshake:
 *   1. Generate random Sec-WebSocket-Key (SocketCrypto_websocket_key)
 *   2. Send HTTP upgrade request
 *   3. Receive and parse HTTP response (SocketHTTP1_Parser)
 *   4. Validate Sec-WebSocket-Accept (SocketCrypto_websocket_accept)
 *
 * Server Handshake:
 *   1. Parse HTTP upgrade request (already done by caller)
 *   2. Validate required headers
 *   3. Compute Sec-WebSocket-Accept (SocketCrypto_websocket_accept)
 *   4. Send HTTP 101 response
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/SocketCrypto.h"
#define SOCKET_LOG_COMPONENT "SocketWS"
#include "core/SocketUtil.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketWS-private.h"

/* ============================================================================
 * Safe snprintf Helper
 * ============================================================================
 */

/**
 * ws_snprintf_checked - Write formatted string with overflow check
 * @buf: Output buffer
 * @size: Buffer size
 * @offset: Current offset (updated on success)
 * @fmt: Format string
 *
 * Returns: 0 on success, -1 if buffer overflow would occur
 */
static int ws_snprintf_checked (char *buf, size_t size, size_t *offset,
                                const char *fmt, ...)
    __attribute__ ((format (printf, 4, 5)));

static int
ws_snprintf_checked (char *buf, size_t size, size_t *offset, const char *fmt,
                     ...)
{
  va_list ap;
  int written;
  size_t remaining;

  assert (buf && offset && fmt);

  if (*offset >= size)
    return -1;

  remaining = size - *offset;
  va_start (ap, fmt);
  written = vsnprintf (buf + *offset, remaining, fmt, ap);
  va_end (ap);

  if (written < 0 || (size_t)written >= remaining)
    return -1;

  *offset += (size_t)written;
  return 0;
}

/* ============================================================================
 * Client Request Building - Helper Functions
 * ============================================================================
 */

/**
 * ws_generate_handshake_keys - Generate client key and expected accept
 * @ws: WebSocket context
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_generate_handshake_keys (SocketWS_T ws)
{
  assert (ws);

  if (SocketCrypto_websocket_key (ws->handshake.client_key) != 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Failed to generate WebSocket key");
      return -1;
    }

  if (SocketCrypto_websocket_accept (ws->handshake.client_key,
                                     ws->handshake.expected_accept)
      != 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Failed to compute expected accept");
      return -1;
    }

  return 0;
}

/**
 * ws_write_request_line - Write HTTP GET request line
 * @buf: Output buffer
 * @size: Buffer size
 * @offset: Current offset
 * @path: Request path
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_write_request_line (char *buf, size_t size, size_t *offset,
                       const char *path)
{
  return ws_snprintf_checked (buf, size, offset, "GET %s HTTP/1.1\r\n",
                              path ? path : "/");
}

/**
 * ws_write_host_header - Write Host header with optional port
 * @buf: Output buffer
 * @size: Buffer size
 * @offset: Current offset
 * @host: Hostname
 * @port: Port number
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_write_host_header (char *buf, size_t size, size_t *offset, const char *host,
                      int port)
{
  int omit_port;

  assert (host);

  omit_port
      = (port == SOCKETWS_DEFAULT_HTTP_PORT
         || port == SOCKETWS_DEFAULT_HTTPS_PORT || port == SOCKETWS_NO_PORT);

  if (omit_port)
    return ws_snprintf_checked (buf, size, offset, "Host: %s\r\n", host);

  return ws_snprintf_checked (buf, size, offset, "Host: %s:%d\r\n", host,
                              port);
}

/**
 * ws_write_websocket_headers - Write required WebSocket upgrade headers
 * @buf: Output buffer
 * @size: Buffer size
 * @offset: Current offset
 * @client_key: Generated Sec-WebSocket-Key
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_write_websocket_headers (char *buf, size_t size, size_t *offset,
                            const char *client_key)
{
  return ws_snprintf_checked (buf, size, offset,
                              "Upgrade: %s\r\n"
                              "Connection: %s\r\n"
                              "Sec-WebSocket-Key: %s\r\n"
                              "Sec-WebSocket-Version: %s\r\n",
                              SOCKETWS_UPGRADE_VALUE,
                              SOCKETWS_CONNECTION_VALUE, client_key,
                              SOCKETWS_PROTOCOL_VERSION);
}

/**
 * ws_write_subprotocol_header - Write Sec-WebSocket-Protocol header
 * @buf: Output buffer
 * @size: Buffer size
 * @offset: Current offset
 * @subprotocols: NULL-terminated array of subprotocols
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_write_subprotocol_header (char *buf, size_t size, size_t *offset,
                             const char *const *subprotocols)
{
  const char *const *proto;

  if (!subprotocols || !subprotocols[0])
    return 0;

  if (ws_snprintf_checked (buf, size, offset, "Sec-WebSocket-Protocol: ") < 0)
    return -1;

  for (proto = subprotocols; *proto; proto++)
    {
      /* Add comma separator after first element */
      if (proto != subprotocols)
        {
          if (ws_snprintf_checked (buf, size, offset, ", ") < 0)
            return -1;
        }
      if (ws_snprintf_checked (buf, size, offset, "%s", *proto) < 0)
        return -1;
    }

  return ws_snprintf_checked (buf, size, offset, "\r\n");
}

/**
 * ws_write_compression_header - Write permessage-deflate extension header
 * @buf: Output buffer
 * @size: Buffer size
 * @offset: Current offset
 * @config: WebSocket configuration
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_write_compression_header (char *buf, size_t size, size_t *offset,
                             const SocketWS_Config *config)
{
  if (!config->enable_permessage_deflate)
    return 0;

  if (ws_snprintf_checked (buf, size, offset,
                           "Sec-WebSocket-Extensions: permessage-deflate")
      < 0)
    return -1;

  if (config->deflate_no_context_takeover)
    {
      if (ws_snprintf_checked (buf, size, offset,
                               "; client_no_context_takeover")
          < 0)
        return -1;
    }

  if (config->deflate_max_window_bits < SOCKETWS_DEFAULT_DEFLATE_WINDOW_BITS)
    {
      if (ws_snprintf_checked (buf, size, offset,
                               "; client_max_window_bits=%d",
                               config->deflate_max_window_bits)
          < 0)
        return -1;
    }

  return ws_snprintf_checked (buf, size, offset, "\r\n");
}

/**
 * ws_build_client_request - Build HTTP upgrade request
 * @ws: WebSocket context
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_build_client_request (SocketWS_T ws)
{
  char *buf;
  size_t offset = 0;

  assert (ws && ws->host);

  buf = ALLOC (ws->arena, SOCKETWS_HANDSHAKE_REQUEST_SIZE);
  if (!buf)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Failed to allocate request buffer");
      return -1;
    }

  if (ws_generate_handshake_keys (ws) < 0)
    return -1;

  if (ws_write_request_line (buf, SOCKETWS_HANDSHAKE_REQUEST_SIZE, &offset,
                             ws->path)
      < 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "Request line too long");
      return -1;
    }

  if (ws_write_host_header (buf, SOCKETWS_HANDSHAKE_REQUEST_SIZE, &offset,
                            ws->host, ws->port)
      < 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "Host header too long");
      return -1;
    }

  if (ws_write_websocket_headers (buf, SOCKETWS_HANDSHAKE_REQUEST_SIZE,
                                  &offset, ws->handshake.client_key)
      < 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "WebSocket headers too long");
      return -1;
    }

  if (ws_write_subprotocol_header (buf, SOCKETWS_HANDSHAKE_REQUEST_SIZE,
                                   &offset, ws->config.subprotocols)
      < 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "Subprotocol header too long");
      return -1;
    }

  if (ws_write_compression_header (buf, SOCKETWS_HANDSHAKE_REQUEST_SIZE,
                                   &offset, &ws->config)
      < 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "Compression header too long");
      return -1;
    }

  if (ws_snprintf_checked (buf, SOCKETWS_HANDSHAKE_REQUEST_SIZE, &offset,
                           "\r\n")
      < 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "Request too long");
      return -1;
    }

  ws->handshake.request_buf = buf;
  ws->handshake.request_len = offset;
  ws->handshake.request_sent = 0;

  return 0;
}

/* ============================================================================
 * Client Response Validation - Helper Functions
 * ============================================================================
 */

/**
 * ws_validate_status_101 - Validate HTTP 101 status code
 * @ws: WebSocket context
 * @response: HTTP response
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_validate_status_101 (SocketWS_T ws, const SocketHTTP_Response *response)
{
  if (response->status_code != 101)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Unexpected status code: %d (expected 101)",
                    response->status_code);
      return -1;
    }
  return 0;
}

/**
 * ws_validate_upgrade_header - Validate Upgrade header value
 * @ws: WebSocket context
 * @headers: HTTP headers
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_validate_upgrade_header (SocketWS_T ws, SocketHTTP_Headers_T headers)
{
  const char *upgrade;

  upgrade = SocketHTTP_Headers_get (headers, "Upgrade");
  if (!upgrade || strcasecmp (upgrade, SOCKETWS_UPGRADE_VALUE) != 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Missing or invalid Upgrade header: %s",
                    upgrade ? upgrade : "(null)");
      return -1;
    }
  return 0;
}

/**
 * ws_validate_connection_upgrade - Validate Connection header contains Upgrade
 * @ws: WebSocket context
 * @headers: HTTP headers
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_validate_connection_upgrade (SocketWS_T ws, SocketHTTP_Headers_T headers)
{
  const char *connection;

  connection = SocketHTTP_Headers_get (headers, "Connection");
  if (!connection
      || strcasestr (connection, SOCKETWS_CONNECTION_VALUE) == NULL)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Missing or invalid Connection header: %s",
                    connection ? connection : "(null)");
      return -1;
    }
  return 0;
}

/**
 * ws_validate_accept_value - Validate Sec-WebSocket-Accept header
 * @ws: WebSocket context
 * @headers: HTTP headers
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_validate_accept_value (SocketWS_T ws, SocketHTTP_Headers_T headers)
{
  const char *accept;
  size_t accept_len;
  size_t expected_len;

  accept = SocketHTTP_Headers_get (headers, "Sec-WebSocket-Accept");
  if (!accept)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Missing Sec-WebSocket-Accept header");
      return -1;
    }

  accept_len = strlen (accept);
  expected_len = strlen (ws->handshake.expected_accept);

  if (accept_len != expected_len)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Invalid Sec-WebSocket-Accept length: %zu (expected %zu)",
                    accept_len, expected_len);
      return -1;
    }

  unsigned char temp_hash[SOCKET_CRYPTO_SHA1_SIZE];
  ssize_t decoded_len = SocketCrypto_base64_decode (
      accept, accept_len, temp_hash, sizeof (temp_hash));
  if (decoded_len != SOCKET_CRYPTO_SHA1_SIZE)
    {
      SocketCrypto_secure_clear (temp_hash, sizeof (temp_hash));
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Invalid Sec-WebSocket-Accept format (base64 decode "
                    "failed or wrong length: %zd)",
                    decoded_len);
      return -1;
    }
  SocketCrypto_secure_clear (temp_hash, sizeof (temp_hash));

  if (SocketCrypto_secure_compare (accept, ws->handshake.expected_accept,
                                   accept_len)
      != 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Invalid Sec-WebSocket-Accept value");
      return -1;
    }

  return 0;
}

/**
 * ws_validate_negotiated_subprotocol - Validate server-selected subprotocol
 * @ws: WebSocket context
 * @headers: HTTP headers
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_validate_negotiated_subprotocol (SocketWS_T ws,
                                    SocketHTTP_Headers_T headers)
{
  const char *protocol;
  const char *const *p;
  int found;

  protocol = SocketHTTP_Headers_get (headers, "Sec-WebSocket-Protocol");
  if (!protocol)
    return 0;

  if (!ws->config.subprotocols)
    return 0;

  found = 0;
  for (p = ws->config.subprotocols; *p; p++)
    {
      if (strcasecmp (protocol, *p) == 0)
        {
          found = 1;
          break;
        }
    }

  if (!found)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Server selected unknown subprotocol: %s", protocol);
      return -1;
    }

  ws->handshake.selected_subprotocol = ws_copy_string (ws->arena, protocol);
  return 0;
}

/**
 * ws_parse_window_bits - Parse window bits parameter from extension string
 * @extensions: Extension header value
 * @param_name: Parameter name to look for
 *
 * Returns: Parsed value (8-15), or default if not found
 */
static int
ws_parse_window_bits (const char *extensions, const char *param_name)
{
  const char *pos;
  const char *eq;
  int value;

  pos = strstr (extensions, param_name);
  if (!pos)
    return SOCKETWS_DEFAULT_DEFLATE_WINDOW_BITS;

  eq = strchr (pos, '=');
  if (!eq)
    return SOCKETWS_DEFAULT_DEFLATE_WINDOW_BITS;

  {
    char *endptr;
    long v = strtol (eq + 1, &endptr, 10);
    value
        = (v >= 8 && v <= 15) ? (int)v : SOCKETWS_DEFAULT_DEFLATE_WINDOW_BITS;
  }
  if (value < 8 || value > 15)
    return SOCKETWS_DEFAULT_DEFLATE_WINDOW_BITS;

  return value;
}

/**
 * ws_parse_compression_extension - Parse permessage-deflate parameters
 * @ws: WebSocket context
 * @extensions: Extension header value
 */
static void
ws_parse_compression_extension (SocketWS_T ws, const char *extensions)
{
  if (!strstr (extensions, "permessage-deflate"))
    return;

  ws->handshake.compression_negotiated = 1;

  if (strstr (extensions, "server_no_context_takeover"))
    ws->handshake.server_no_context_takeover = 1;

  if (strstr (extensions, "client_no_context_takeover"))
    ws->handshake.client_no_context_takeover = 1;

  ws->handshake.server_max_window_bits
      = ws_parse_window_bits (extensions, "server_max_window_bits");

  ws->handshake.client_max_window_bits
      = ws_parse_window_bits (extensions, "client_max_window_bits");
}

/**
 * ws_parse_negotiated_extensions - Parse extension negotiation results
 * @ws: WebSocket context
 * @headers: HTTP headers
 */
static void
ws_parse_negotiated_extensions (SocketWS_T ws, SocketHTTP_Headers_T headers)
{
  const char *extensions;

  extensions = SocketHTTP_Headers_get (headers, "Sec-WebSocket-Extensions");
  if (!extensions)
    return;

  ws_parse_compression_extension (ws, extensions);
}

/**
 * ws_validate_upgrade_response - Validate server's upgrade response
 * @ws: WebSocket context
 * @response: Parsed HTTP response
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_validate_upgrade_response (SocketWS_T ws,
                              const SocketHTTP_Response *response)
{
  assert (ws && response);

  if (ws_validate_status_101 (ws, response) < 0)
    return -1;

  if (ws_validate_upgrade_header (ws, response->headers) < 0)
    return -1;

  if (ws_validate_connection_upgrade (ws, response->headers) < 0)
    return -1;

  if (ws_validate_accept_value (ws, response->headers) < 0)
    return -1;

  if (ws_validate_negotiated_subprotocol (ws, response->headers) < 0)
    return -1;

  ws_parse_negotiated_extensions (ws, response->headers);

#ifdef SOCKETWS_HAS_DEFLATE
  if (ws->handshake.compression_negotiated)
    {
      if (ws_compression_init (ws) < 0)
        {
          SocketLog_emit (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                          "Compression init failed, continuing without");
        }
      else
        {
          ws->compression_enabled = 1;
        }
    }
#endif

  /* Clear sensitive handshake data after successful validation */
  SocketCrypto_secure_clear (ws->handshake.client_key,
                             sizeof (ws->handshake.client_key));
  SocketCrypto_secure_clear (ws->handshake.expected_accept,
                             sizeof (ws->handshake.expected_accept));

  return 0;
}

/* ============================================================================
 * Client Handshake - State Machine
 * ============================================================================
 */

int
ws_handshake_client_init (SocketWS_T ws)
{
  assert (ws);
  assert (ws->role == WS_ROLE_CLIENT);

  ws->handshake.state = WS_HANDSHAKE_INIT;

  if (ws_build_client_request (ws) < 0)
    return -1;

  ws->handshake.http_parser
      = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, ws->arena);
  if (!ws->handshake.http_parser)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "Failed to create HTTP parser");
      return -1;
    }

  ws->handshake.state = WS_HANDSHAKE_SENDING_REQUEST;
  return 0;
}

/**
 * ws_send_request_data - Send pending request data
 * @ws: WebSocket context
 *
 * Returns: 0 if complete, 1 if would block, -1 on error
 */
static int
ws_send_request_data (SocketWS_T ws)
{
  ssize_t n;

  while (ws->handshake.request_sent < ws->handshake.request_len)
    {
      n = Socket_send (ws->socket,
                       ws->handshake.request_buf + ws->handshake.request_sent,
                       ws->handshake.request_len - ws->handshake.request_sent);
      if (n < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 1;
          ws_set_error (ws, WS_ERROR_HANDSHAKE, "Send failed");
          return -1;
        }
      ws->handshake.request_sent += (size_t)n;
    }
  return 0;
}

/**
 * ws_read_and_parse_response - Read and parse HTTP response
 * @ws: WebSocket context
 *
 * Returns: 0 if complete, 1 if need more data, -1 on error
 */
static int
ws_read_and_parse_response (SocketWS_T ws)
{
  ssize_t n;
  size_t available;
  const char *data;
  size_t consumed;
  SocketHTTP1_Result result;

  n = ws_fill_recv_buffer (ws);
  if (n < 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "Recv failed");
      return -1;
    }

  available = SocketBuf_available (ws->recv_buf);
  if (available == 0)
    return 1;

  data = (const char *)SocketBuf_readptr (ws->recv_buf, &available);
  result = SocketHTTP1_Parser_execute (ws->handshake.http_parser, data,
                                       available, &consumed);
  SocketBuf_consume (ws->recv_buf, consumed);

  if (result == HTTP1_INCOMPLETE)
    return 1;

  if (result != HTTP1_OK)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "HTTP parse error: %s",
                    SocketHTTP1_result_string (result));
      return -1;
    }

  return 0;
}

/**
 * ws_finalize_client_handshake - Finalize successful client handshake
 * @ws: WebSocket context
 *
 * Returns: 0 on success, -1 on error
 *
 * Note: Compression initialization is handled in ws_validate_upgrade_response()
 */
static int
ws_finalize_client_handshake (SocketWS_T ws)
{
  const SocketHTTP_Response *response;

  response = SocketHTTP1_Parser_get_response (ws->handshake.http_parser);
  if (!response)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "No response parsed");
      return -1;
    }

  return ws_validate_upgrade_response (ws, response);
}

int
ws_handshake_client_process (SocketWS_T ws)
{
  int result;

  assert (ws);
  assert (ws->role == WS_ROLE_CLIENT);

  switch (ws->handshake.state)
    {
    case WS_HANDSHAKE_SENDING_REQUEST:
      result = ws_send_request_data (ws);
      if (result < 0)
        {
          ws->handshake.state = WS_HANDSHAKE_FAILED;
          return -1;
        }
      if (result > 0)
        return 1;
      ws->handshake.state = WS_HANDSHAKE_READING_RESPONSE;
      /* Fall through */

    case WS_HANDSHAKE_READING_RESPONSE:
      result = ws_read_and_parse_response (ws);
      if (result < 0)
        {
          ws->handshake.state = WS_HANDSHAKE_FAILED;
          return -1;
        }
      if (result > 0)
        return 1;

      if (ws_finalize_client_handshake (ws) < 0)
        {
          ws->handshake.state = WS_HANDSHAKE_FAILED;
          return -1;
        }

      ws->handshake.state = WS_HANDSHAKE_COMPLETE;
      return 0;

    case WS_HANDSHAKE_COMPLETE:
      return 0;

    case WS_HANDSHAKE_FAILED:
    case WS_HANDSHAKE_INIT:
    default:
      return -1;
    }
}

/* ============================================================================
 * Server Response Building - Helper Functions
 * ============================================================================
 */

/**
 * ws_write_101_status_line - Write HTTP 101 status and core headers
 * @buf: Output buffer
 * @size: Buffer size
 * @offset: Current offset
 * @accept_value: Computed Sec-WebSocket-Accept value
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_write_101_status_line (char *buf, size_t size, size_t *offset,
                          const char *accept_value)
{
  return ws_snprintf_checked (buf, size, offset,
                              "HTTP/1.1 101 Switching Protocols\r\n"
                              "Upgrade: %s\r\n"
                              "Connection: %s\r\n"
                              "Sec-WebSocket-Accept: %s\r\n",
                              SOCKETWS_UPGRADE_VALUE,
                              SOCKETWS_CONNECTION_VALUE, accept_value);
}

/**
 * ws_write_negotiated_subprotocol - Write selected subprotocol header
 * @buf: Output buffer
 * @size: Buffer size
 * @offset: Current offset
 * @subprotocol: Selected subprotocol (may be NULL)
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_write_negotiated_subprotocol (char *buf, size_t size, size_t *offset,
                                 const char *subprotocol)
{
  if (!subprotocol)
    return 0;

  return ws_snprintf_checked (buf, size, offset,
                              "Sec-WebSocket-Protocol: %s\r\n", subprotocol);
}

/**
 * ws_write_negotiated_compression - Write compression extension header
 * @buf: Output buffer
 * @size: Buffer size
 * @offset: Current offset
 * @handshake: Handshake state with compression params
 *
 * Returns: 0 on success, -1 on error
 */
#ifdef SOCKETWS_HAS_DEFLATE
static int
ws_write_negotiated_compression (char *buf, size_t size, size_t *offset,
                                 const SocketWS_Handshake *handshake)
{
  if (!handshake->compression_negotiated)
    return 0;

  if (ws_snprintf_checked (buf, size, offset,
                           "Sec-WebSocket-Extensions: permessage-deflate")
      < 0)
    return -1;

  if (handshake->server_no_context_takeover)
    {
      if (ws_snprintf_checked (buf, size, offset,
                               "; server_no_context_takeover")
          < 0)
        return -1;
    }

  if (handshake->client_no_context_takeover)
    {
      if (ws_snprintf_checked (buf, size, offset,
                               "; client_no_context_takeover")
          < 0)
        return -1;
    }

  return ws_snprintf_checked (buf, size, offset, "\r\n");
}
#endif

/**
 * ws_build_server_response - Build HTTP 101 response
 * @ws: WebSocket context
 * @client_key: Sec-WebSocket-Key from client
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_build_server_response (SocketWS_T ws, const char *client_key)
{
  char accept_value[SOCKET_CRYPTO_WEBSOCKET_ACCEPT_SIZE];
  char *buf;
  size_t offset = 0;

  assert (ws && client_key);

  if (SocketCrypto_websocket_accept (client_key, accept_value) != 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "Failed to compute accept value");
      return -1;
    }

  buf = ALLOC (ws->arena, SOCKETWS_HANDSHAKE_RESPONSE_SIZE);
  if (!buf)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Failed to allocate response buffer");
      SocketCrypto_secure_clear (accept_value, sizeof (accept_value));
      return -1;
    }

  if (ws_write_101_status_line (buf, SOCKETWS_HANDSHAKE_RESPONSE_SIZE, &offset,
                                accept_value)
      < 0)
    {
      SocketCrypto_secure_clear (accept_value, sizeof (accept_value));
      return -1;
    }

  if (ws_write_negotiated_subprotocol (buf, SOCKETWS_HANDSHAKE_RESPONSE_SIZE,
                                       &offset,
                                       ws->handshake.selected_subprotocol)
      < 0)
    {
      SocketCrypto_secure_clear (accept_value, sizeof (accept_value));
      return -1;
    }

#ifdef SOCKETWS_HAS_DEFLATE
  if (ws_write_negotiated_compression (buf, SOCKETWS_HANDSHAKE_RESPONSE_SIZE,
                                       &offset, &ws->handshake)
      < 0)
    {
      SocketCrypto_secure_clear (accept_value, sizeof (accept_value));
      return -1;
    }
#endif

  if (ws_snprintf_checked (buf, SOCKETWS_HANDSHAKE_RESPONSE_SIZE, &offset,
                           "\r\n")
      < 0)
    {
      SocketCrypto_secure_clear (accept_value, sizeof (accept_value));
      return -1;
    }

  ws->handshake.request_buf = buf;
  ws->handshake.request_len = offset;
  ws->handshake.request_sent = 0;

  SocketCrypto_secure_clear (accept_value, sizeof (accept_value));
  return 0;
}

/* ============================================================================
 * Server Handshake - Validation Helper Functions
 * ============================================================================
 */

/**
 * ws_validate_client_upgrade_header - Validate Upgrade header from client
 * @ws: WebSocket context
 * @headers: HTTP headers
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_validate_client_upgrade_header (SocketWS_T ws, SocketHTTP_Headers_T headers)
{
  const char *upgrade;

  upgrade = SocketHTTP_Headers_get (headers, "Upgrade");
  if (!upgrade || strcasecmp (upgrade, SOCKETWS_UPGRADE_VALUE) != 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Missing or invalid Upgrade header");
      return -1;
    }
  return 0;
}

/**
 * ws_validate_client_connection_header - Validate Connection header from
 * client
 * @ws: WebSocket context
 * @headers: HTTP headers
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_validate_client_connection_header (SocketWS_T ws,
                                      SocketHTTP_Headers_T headers)
{
  const char *connection;

  connection = SocketHTTP_Headers_get (headers, "Connection");
  if (!connection
      || strcasestr (connection, SOCKETWS_CONNECTION_VALUE) == NULL)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Missing or invalid Connection header");
      return -1;
    }
  return 0;
}

/**
 * ws_validate_client_key - Validate Sec-WebSocket-Key from client
 * @ws: WebSocket context
 * @headers: HTTP headers
 * @key_out: Output - pointer to key value
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_validate_client_key (SocketWS_T ws, SocketHTTP_Headers_T headers,
                        const char **key_out)
{
  const char *key;

  key = SocketHTTP_Headers_get (headers, "Sec-WebSocket-Key");
  if (!key)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "Missing Sec-WebSocket-Key");
      return -1;
    }

  size_t key_len = strlen (key);
  if (key_len != SOCKETWS_KEY_BASE64_LENGTH)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Invalid Sec-WebSocket-Key length: %zu (expected %d)",
                    key_len, SOCKETWS_KEY_BASE64_LENGTH);
      return -1;
    }

  unsigned char temp[SOCKETWS_KEY_RAW_SIZE];
  ssize_t decoded_len
      = SocketCrypto_base64_decode (key, key_len, temp, sizeof (temp));
  if (decoded_len != SOCKETWS_KEY_RAW_SIZE)
    {
      SocketCrypto_secure_clear (temp, sizeof (temp));
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Invalid Sec-WebSocket-Key format (base64 decode failed "
                    "or wrong length: %zd)",
                    decoded_len);
      return -1;
    }
  SocketCrypto_secure_clear (temp, sizeof (temp));

  *key_out = key;
  return 0;
}

/**
 * ws_validate_client_version - Validate Sec-WebSocket-Version from client
 * @ws: WebSocket context
 * @headers: HTTP headers
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_validate_client_version (SocketWS_T ws, SocketHTTP_Headers_T headers)
{
  const char *version;

  version = SocketHTTP_Headers_get (headers, "Sec-WebSocket-Version");
  if (!version || strcmp (version, SOCKETWS_PROTOCOL_VERSION) != 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Unsupported WebSocket version: %s",
                    version ? version : "(null)");
      return -1;
    }
  return 0;
}

/**
 * ws_validate_client_upgrade_request - Validate all required upgrade headers
 * @ws: WebSocket context
 * @request: HTTP request
 * @key_out: Output - pointer to client key
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_validate_client_upgrade_request (SocketWS_T ws,
                                    const SocketHTTP_Request *request,
                                    const char **key_out)
{
  if (ws_validate_client_upgrade_header (ws, request->headers) < 0)
    return -1;

  if (ws_validate_client_connection_header (ws, request->headers) < 0)
    return -1;

  if (ws_validate_client_key (ws, request->headers, key_out) < 0)
    return -1;

  if (ws_validate_client_version (ws, request->headers) < 0)
    return -1;

  return 0;
}

/**
 * ws_negotiate_server_subprotocol - Negotiate subprotocol with client
 * @ws: WebSocket context
 * @headers: HTTP headers
 */
static void
ws_negotiate_server_subprotocol (SocketWS_T ws, SocketHTTP_Headers_T headers)
{
  const char *protocol;
  const char *const *p;
  char *proto_copy;
  char *token;
  char *saveptr = NULL;

  protocol = SocketHTTP_Headers_get (headers, "Sec-WebSocket-Protocol");
  if (!protocol || !ws->config.subprotocols)
    return;

  proto_copy = ws_copy_string (ws->arena, protocol);
  if (!proto_copy)
    return;

  token = strtok_r (proto_copy, ", ", &saveptr);
  while (token)
    {
      for (p = ws->config.subprotocols; *p; p++)
        {
          if (strcasecmp (token, *p) == 0)
            {
              ws->handshake.selected_subprotocol
                  = ws_copy_string (ws->arena, *p);
              return;
            }
        }
      token = strtok_r (NULL, ", ", &saveptr);
    }
}

/**
 * ws_negotiate_server_compression - Negotiate compression with client
 * @ws: WebSocket context
 * @headers: HTTP headers
 */
static void
ws_negotiate_server_compression (SocketWS_T ws, SocketHTTP_Headers_T headers)
{
  const char *extensions;

  if (!ws->config.enable_permessage_deflate)
    return;

  extensions = SocketHTTP_Headers_get (headers, "Sec-WebSocket-Extensions");
  if (!extensions || !strstr (extensions, "permessage-deflate"))
    return;

  ws->handshake.compression_negotiated = 1;

  if (strstr (extensions, "server_no_context_takeover"))
    ws->handshake.server_no_context_takeover = 1;

  if (strstr (extensions, "client_no_context_takeover"))
    ws->handshake.client_no_context_takeover = 1;

  if (ws->config.deflate_no_context_takeover)
    {
      ws->handshake.server_no_context_takeover = 1;
      ws->handshake.client_no_context_takeover = 1;
    }

  ws->handshake.server_max_window_bits
      = ws_parse_window_bits (extensions, "server_max_window_bits");

  ws->handshake.client_max_window_bits
      = ws_parse_window_bits (extensions, "client_max_window_bits");
}

int
ws_handshake_server_init (SocketWS_T ws, const SocketHTTP_Request *request)
{
  const char *key = NULL;

  assert (ws);
  assert (ws->role == WS_ROLE_SERVER);
  assert (request);

  ws->handshake.state = WS_HANDSHAKE_INIT;

  if (ws_validate_client_upgrade_request (ws, request, &key) < 0)
    return -1;

  ws_negotiate_server_subprotocol (ws, request->headers);
  ws_negotiate_server_compression (ws, request->headers);

  if (ws_build_server_response (ws, key) < 0)
    return -1;

  ws->handshake.state = WS_HANDSHAKE_SENDING_REQUEST;
  return 0;
}

/**
 * ws_finalize_server_handshake - Finalize successful server handshake
 * @ws: WebSocket context
 */
static void
ws_finalize_server_handshake (SocketWS_T ws)
{
#ifdef SOCKETWS_HAS_DEFLATE
  if (ws->handshake.compression_negotiated)
    {
      if (ws_compression_init (ws) < 0)
        {
          SocketLog_emit (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                          "Compression init failed, continuing without");
        }
      else
        {
          ws->compression_enabled = 1;
        }
    }
#else
  (void)ws;
#endif
}

int
ws_handshake_server_process (SocketWS_T ws)
{
  int result;

  assert (ws);
  assert (ws->role == WS_ROLE_SERVER);

  switch (ws->handshake.state)
    {
    case WS_HANDSHAKE_SENDING_REQUEST:
      result = ws_send_request_data (ws);
      if (result < 0)
        {
          ws->handshake.state = WS_HANDSHAKE_FAILED;
          return -1;
        }
      if (result > 0)
        return 1;

      ws->handshake.state = WS_HANDSHAKE_COMPLETE;
      ws_finalize_server_handshake (ws);
      return 0;

    case WS_HANDSHAKE_COMPLETE:
      return 0;

    case WS_HANDSHAKE_READING_RESPONSE:
    case WS_HANDSHAKE_FAILED:
    case WS_HANDSHAKE_INIT:
    default:
      return -1;
    }
}

int
ws_handshake_validate_accept (SocketWS_T ws, const char *accept)
{
  assert (ws && accept);

  if (strlen (accept) != strlen (ws->handshake.expected_accept))
    return -1;

  return SocketCrypto_secure_compare (accept, ws->handshake.expected_accept,
                                      strlen (accept));
}

/* ============================================================================
 * Helper - Copy String to Arena
 * ============================================================================
 */

char *
ws_copy_string (Arena_T arena, const char *str)
{
  size_t len;
  char *copy;

  if (!str)
    return NULL;

  len = strlen (str);
  copy = ALLOC (arena, len + 1);
  if (copy)
    memcpy (copy, str, len + 1);

  return copy;
}

/* ============================================================================
 * Public API - Check WebSocket Upgrade
 * ============================================================================
 */

/**
 * SocketWS_is_upgrade - Check if HTTP request is WebSocket upgrade
 * @request: Parsed HTTP request
 *
 * Returns: 1 if WebSocket upgrade request, 0 otherwise
 */
int
SocketWS_is_upgrade (const SocketHTTP_Request *request)
{
  const char *upgrade;
  const char *connection;
  const char *version;

  if (!request || !request->headers)
    return 0;

  upgrade = SocketHTTP_Headers_get (request->headers, "Upgrade");
  if (!upgrade || strcasecmp (upgrade, SOCKETWS_UPGRADE_VALUE) != 0)
    return 0;

  connection = SocketHTTP_Headers_get (request->headers, "Connection");
  if (!connection
      || strcasestr (connection, SOCKETWS_CONNECTION_VALUE) == NULL)
    return 0;

  version = SocketHTTP_Headers_get (request->headers, "Sec-WebSocket-Version");
  if (!version)
    return 0;

  return 1;
}

/**
 * ws_copy_status_phrase - Safely copy status phrase with length limit
 * @dest: Destination buffer
 * @dest_size: Size of destination buffer
 * @reason: Source string (may be NULL)
 * @default_phrase: Default phrase if reason is NULL or too long
 */
static void
ws_copy_status_phrase (char *dest, size_t dest_size, const char *reason,
                       const char *default_phrase)
{
  const char *source;
  size_t max_len;

  assert (dest && dest_size > 0 && default_phrase);

  /* Use reason if short enough, otherwise use default */
  max_len = dest_size - 1;
  if (reason && strlen (reason) < max_len)
    source = reason;
  else
    source = default_phrase;

  /* Safe copy with guaranteed null termination */
  snprintf (dest, dest_size, "%s", source);
}

/**
 * SocketWS_server_reject - Reject WebSocket upgrade with HTTP response
 * @socket: TCP socket
 * @status_code: HTTP status code (e.g., 400, 403)
 * @reason: Rejection reason
 */
void
SocketWS_server_reject (Socket_T socket, int status_code, const char *reason)
{
  char buf[SOCKETWS_REJECT_RESPONSE_SIZE];
  char status_phrase[SOCKETWS_REJECT_STATUS_PHRASE_SIZE];
  const char *body_text;
  size_t body_len;
  int written;

  if (!socket)
    return;

  body_text = reason ? reason : "WebSocket upgrade rejected";

  /* Prepare status phrase (short version of reason or default) */
  ws_copy_status_phrase (status_phrase, sizeof (status_phrase), reason,
                         "WebSocket Error");

  body_len = strlen (body_text);
  /* Cap body length to prevent oversized responses */
  if (body_len > SOCKETWS_REJECT_BODY_MAX_SIZE)
    body_len = SOCKETWS_REJECT_BODY_MAX_SIZE;

  /* Format response with exact body length */
  written = snprintf (buf, sizeof (buf),
                      "HTTP/1.1 %d %s\r\n"
                      "Content-Type: text/plain\r\n"
                      "Content-Length: %zu\r\n"
                      "Connection: close\r\n"
                      "\r\n"
                      "%.*s",
                      status_code, status_phrase, body_len, (int)body_len,
                      body_text);

  if (written > 0 && (size_t)written <= sizeof (buf))
    {
      Socket_send (socket, buf, (size_t)written);
    }
  else
    {
      /* Fallback minimal response on format error */
      const char *fallback = "HTTP/1.1 400 Bad Request\r\n\r\n";
      Socket_send (socket, fallback, strlen (fallback));
    }
}
