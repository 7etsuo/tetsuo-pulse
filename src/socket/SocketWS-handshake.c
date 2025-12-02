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
 * Constants
 * ============================================================================ */

#define WS_VERSION "13"
#define WS_UPGRADE "websocket"
#define WS_CONNECTION "Upgrade"
#define WS_MAX_REQUEST_SIZE 4096
#define WS_MAX_RESPONSE_SIZE 4096

/* ============================================================================
 * Client Handshake - Request Building
 * ============================================================================ */

/**
 * ws_build_client_request - Build HTTP upgrade request
 * @ws: WebSocket context
 *
 * Builds the HTTP GET request for WebSocket upgrade.
 * Uses SocketHTTP types for proper header formatting.
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_build_client_request (SocketWS_T ws)
{
  char *buf;
  int written;
  int offset = 0;
  const char *const *proto;

  assert (ws);
  assert (ws->host);

  /* Allocate request buffer */
  buf = ALLOC (ws->arena, WS_MAX_REQUEST_SIZE);
  if (!buf)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "Failed to allocate request buffer");
      return -1;
    }

  /* Generate WebSocket key using SocketCrypto */
  if (SocketCrypto_websocket_key (ws->handshake.client_key) != 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "Failed to generate WebSocket key");
      return -1;
    }

  /* Pre-compute expected accept value */
  if (SocketCrypto_websocket_accept (ws->handshake.client_key,
                                     ws->handshake.expected_accept)
      != 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Failed to compute expected accept");
      return -1;
    }

  /* Build request line */
  written = snprintf (buf + offset, WS_MAX_REQUEST_SIZE - offset,
                      "GET %s HTTP/1.1\r\n", ws->path ? ws->path : "/");
  if (written < 0 || written >= (int)(WS_MAX_REQUEST_SIZE - offset))
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "Request line too long");
      return -1;
    }
  offset += written;

  /* Host header */
  if (ws->port == 80 || ws->port == 443 || ws->port == 0)
    {
      written = snprintf (buf + offset, WS_MAX_REQUEST_SIZE - offset,
                          "Host: %s\r\n", ws->host);
    }
  else
    {
      written = snprintf (buf + offset, WS_MAX_REQUEST_SIZE - offset,
                          "Host: %s:%d\r\n", ws->host, ws->port);
    }
  if (written < 0 || written >= (int)(WS_MAX_REQUEST_SIZE - offset))
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "Host header too long");
      return -1;
    }
  offset += written;

  /* Required WebSocket headers */
  written = snprintf (buf + offset, WS_MAX_REQUEST_SIZE - offset,
                      "Upgrade: websocket\r\n"
                      "Connection: Upgrade\r\n"
                      "Sec-WebSocket-Key: %s\r\n"
                      "Sec-WebSocket-Version: %s\r\n",
                      ws->handshake.client_key, WS_VERSION);
  if (written < 0 || written >= (int)(WS_MAX_REQUEST_SIZE - offset))
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "WebSocket headers too long");
      return -1;
    }
  offset += written;

  /* Optional subprotocol header */
  if (ws->config.subprotocols && ws->config.subprotocols[0])
    {
      written = snprintf (buf + offset, WS_MAX_REQUEST_SIZE - offset,
                          "Sec-WebSocket-Protocol: ");
      offset += written;

      for (proto = ws->config.subprotocols; *proto; proto++)
        {
          if (proto != ws->config.subprotocols)
            {
              written = snprintf (buf + offset, WS_MAX_REQUEST_SIZE - offset,
                                  ", ");
              offset += written;
            }
          written = snprintf (buf + offset, WS_MAX_REQUEST_SIZE - offset,
                              "%s", *proto);
          offset += written;
        }
      written = snprintf (buf + offset, WS_MAX_REQUEST_SIZE - offset, "\r\n");
      offset += written;
    }

  /* Optional permessage-deflate extension */
  if (ws->config.enable_permessage_deflate)
    {
      written = snprintf (buf + offset, WS_MAX_REQUEST_SIZE - offset,
                          "Sec-WebSocket-Extensions: permessage-deflate");
      offset += written;

      if (ws->config.deflate_no_context_takeover)
        {
          written = snprintf (buf + offset, WS_MAX_REQUEST_SIZE - offset,
                              "; client_no_context_takeover");
          offset += written;
        }
      if (ws->config.deflate_max_window_bits
          < SOCKETWS_DEFAULT_DEFLATE_WINDOW_BITS)
        {
          written = snprintf (buf + offset, WS_MAX_REQUEST_SIZE - offset,
                              "; client_max_window_bits=%d",
                              ws->config.deflate_max_window_bits);
          offset += written;
        }
      written = snprintf (buf + offset, WS_MAX_REQUEST_SIZE - offset, "\r\n");
      offset += written;
    }

  /* End of headers */
  written = snprintf (buf + offset, WS_MAX_REQUEST_SIZE - offset, "\r\n");
  offset += written;

  ws->handshake.request_buf = buf;
  ws->handshake.request_len = (size_t)offset;
  ws->handshake.request_sent = 0;

  return 0;
}

/* ============================================================================
 * Client Handshake - Response Validation
 * ============================================================================ */

/**
 * ws_validate_upgrade_response - Validate server's upgrade response
 * @ws: WebSocket context
 * @response: Parsed HTTP response
 *
 * Validates:
 * - Status code is 101
 * - Upgrade header is "websocket"
 * - Connection header contains "Upgrade"
 * - Sec-WebSocket-Accept matches expected value
 *
 * Returns: 0 on success, -1 on error
 */
static int
ws_validate_upgrade_response (SocketWS_T ws, const SocketHTTP_Response *response)
{
  const char *upgrade;
  const char *connection;
  const char *accept;
  const char *protocol;
  const char *extensions;

  assert (ws);
  assert (response);

  /* Check status code */
  if (response->status_code != 101)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Unexpected status code: %d (expected 101)",
                    response->status_code);
      return -1;
    }

  /* Check Upgrade header */
  upgrade = SocketHTTP_Headers_get (response->headers, "Upgrade");
  if (!upgrade || strcasecmp (upgrade, WS_UPGRADE) != 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Missing or invalid Upgrade header: %s",
                    upgrade ? upgrade : "(null)");
      return -1;
    }

  /* Check Connection header */
  connection = SocketHTTP_Headers_get (response->headers, "Connection");
  if (!connection || strcasestr (connection, "Upgrade") == NULL)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Missing or invalid Connection header: %s",
                    connection ? connection : "(null)");
      return -1;
    }

  /* Check Sec-WebSocket-Accept */
  accept = SocketHTTP_Headers_get (response->headers, "Sec-WebSocket-Accept");
  if (!accept)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Missing Sec-WebSocket-Accept header");
      return -1;
    }

  /* Validate accept value using constant-time comparison */
  if (strlen (accept) != strlen (ws->handshake.expected_accept)
      || SocketCrypto_secure_compare (accept, ws->handshake.expected_accept,
                                      strlen (accept))
             != 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Invalid Sec-WebSocket-Accept value");
      return -1;
    }

  /* Check optional Sec-WebSocket-Protocol */
  protocol = SocketHTTP_Headers_get (response->headers, "Sec-WebSocket-Protocol");
  if (protocol)
    {
      /* Verify server selected one of our proposed protocols */
      if (ws->config.subprotocols)
        {
          const char *const *p;
          int found = 0;

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
        }

      ws->handshake.selected_subprotocol = ws_copy_string (ws->arena, protocol);
    }

  /* Check optional Sec-WebSocket-Extensions */
  extensions
      = SocketHTTP_Headers_get (response->headers, "Sec-WebSocket-Extensions");
  if (extensions)
    {
      /* Parse permessage-deflate parameters */
      if (strstr (extensions, "permessage-deflate"))
        {
          ws->handshake.compression_negotiated = 1;

          if (strstr (extensions, "server_no_context_takeover"))
            ws->handshake.server_no_context_takeover = 1;
          if (strstr (extensions, "client_no_context_takeover"))
            ws->handshake.client_no_context_takeover = 1;

          /* TODO: Parse server_max_window_bits, client_max_window_bits */
        }
    }

  return 0;
}

/* ============================================================================
 * Client Handshake - State Machine
 * ============================================================================ */

int
ws_handshake_client_init (SocketWS_T ws)
{
  assert (ws);
  assert (ws->role == WS_ROLE_CLIENT);

  ws->handshake.state = WS_HANDSHAKE_INIT;

  /* Build the request */
  if (ws_build_client_request (ws) < 0)
    return -1;

  /* Create HTTP parser for response */
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

int
ws_handshake_client_process (SocketWS_T ws)
{
  ssize_t n;
  size_t consumed;
  SocketHTTP1_Result result;
  const SocketHTTP_Response *response;
  size_t available;
  const char *data;

  assert (ws);
  assert (ws->role == WS_ROLE_CLIENT);

  switch (ws->handshake.state)
    {
    case WS_HANDSHAKE_SENDING_REQUEST:
      /* Send request data */
      while (ws->handshake.request_sent < ws->handshake.request_len)
        {
          n = Socket_send (ws->socket,
                           ws->handshake.request_buf + ws->handshake.request_sent,
                           ws->handshake.request_len - ws->handshake.request_sent);
          if (n < 0)
            {
              if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 1; /* Would block */
              ws_set_error (ws, WS_ERROR_HANDSHAKE, "Send failed");
              ws->handshake.state = WS_HANDSHAKE_FAILED;
              return -1;
            }
          ws->handshake.request_sent += (size_t)n;
        }

      /* Request sent, now read response */
      ws->handshake.state = WS_HANDSHAKE_READING_RESPONSE;
      /* Fall through */

    case WS_HANDSHAKE_READING_RESPONSE:
      /* Read response data into buffer */
      n = ws_fill_recv_buffer (ws);
      if (n < 0)
        {
          ws_set_error (ws, WS_ERROR_HANDSHAKE, "Recv failed");
          ws->handshake.state = WS_HANDSHAKE_FAILED;
          return -1;
        }

      /* Parse response using SocketHTTP1 parser */
      available = SocketBuf_available (ws->recv_buf);
      if (available == 0)
        return 1; /* Need more data */

      data = (const char *)SocketBuf_readptr (ws->recv_buf, &available);
      result = SocketHTTP1_Parser_execute (ws->handshake.http_parser, data,
                                           available, &consumed);

      SocketBuf_consume (ws->recv_buf, consumed);

      if (result == HTTP1_INCOMPLETE)
        return 1; /* Need more data */

      if (result != HTTP1_OK)
        {
          ws_set_error (ws, WS_ERROR_HANDSHAKE, "HTTP parse error: %s",
                        SocketHTTP1_result_string (result));
          ws->handshake.state = WS_HANDSHAKE_FAILED;
          return -1;
        }

      /* Get parsed response */
      response = SocketHTTP1_Parser_get_response (ws->handshake.http_parser);
      if (!response)
        {
          ws_set_error (ws, WS_ERROR_HANDSHAKE, "No response parsed");
          ws->handshake.state = WS_HANDSHAKE_FAILED;
          return -1;
        }

      /* Validate response */
      if (ws_validate_upgrade_response (ws, response) < 0)
        {
          ws->handshake.state = WS_HANDSHAKE_FAILED;
          return -1;
        }

      /* Success! */
      ws->handshake.state = WS_HANDSHAKE_COMPLETE;

#ifdef SOCKETWS_HAS_DEFLATE
      /* Initialize compression if negotiated */
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

      return 0; /* Complete */

    case WS_HANDSHAKE_COMPLETE:
      return 0;

    case WS_HANDSHAKE_FAILED:
    case WS_HANDSHAKE_INIT:
    default:
      return -1;
    }
}

/* ============================================================================
 * Server Handshake
 * ============================================================================ */

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
  int written;
  int offset = 0;

  assert (ws);
  assert (client_key);

  /* Compute accept value using SocketCrypto */
  if (SocketCrypto_websocket_accept (client_key, accept_value) != 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "Failed to compute accept value");
      return -1;
    }

  /* Allocate response buffer */
  buf = ALLOC (ws->arena, WS_MAX_RESPONSE_SIZE);
  if (!buf)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Failed to allocate response buffer");
      return -1;
    }

  /* Build response */
  written = snprintf (buf + offset, WS_MAX_RESPONSE_SIZE - offset,
                      "HTTP/1.1 101 Switching Protocols\r\n"
                      "Upgrade: websocket\r\n"
                      "Connection: Upgrade\r\n"
                      "Sec-WebSocket-Accept: %s\r\n",
                      accept_value);
  offset += written;

  /* Add selected subprotocol if any */
  if (ws->handshake.selected_subprotocol)
    {
      written = snprintf (buf + offset, WS_MAX_RESPONSE_SIZE - offset,
                          "Sec-WebSocket-Protocol: %s\r\n",
                          ws->handshake.selected_subprotocol);
      offset += written;
    }

  /* Add compression extension if negotiated */
#ifdef SOCKETWS_HAS_DEFLATE
  if (ws->handshake.compression_negotiated)
    {
      written = snprintf (buf + offset, WS_MAX_RESPONSE_SIZE - offset,
                          "Sec-WebSocket-Extensions: permessage-deflate");
      offset += written;

      if (ws->handshake.server_no_context_takeover)
        {
          written = snprintf (buf + offset, WS_MAX_RESPONSE_SIZE - offset,
                              "; server_no_context_takeover");
          offset += written;
        }
      if (ws->handshake.client_no_context_takeover)
        {
          written = snprintf (buf + offset, WS_MAX_RESPONSE_SIZE - offset,
                              "; client_no_context_takeover");
          offset += written;
        }
      written = snprintf (buf + offset, WS_MAX_RESPONSE_SIZE - offset, "\r\n");
      offset += written;
    }
#endif

  /* End of headers */
  written = snprintf (buf + offset, WS_MAX_RESPONSE_SIZE - offset, "\r\n");
  offset += written;

  ws->handshake.request_buf = buf; /* Reuse field for response */
  ws->handshake.request_len = (size_t)offset;
  ws->handshake.request_sent = 0;

  /* Clear accept value from stack */
  SocketCrypto_secure_clear (accept_value, sizeof (accept_value));

  return 0;
}

int
ws_handshake_server_init (SocketWS_T ws, const SocketHTTP_Request *request)
{
  const char *upgrade;
  const char *connection;
  const char *key;
  const char *version;
  const char *protocol;
  const char *extensions;

  assert (ws);
  assert (ws->role == WS_ROLE_SERVER);
  assert (request);

  ws->handshake.state = WS_HANDSHAKE_INIT;

  /* Validate upgrade request */
  upgrade = SocketHTTP_Headers_get (request->headers, "Upgrade");
  if (!upgrade || strcasecmp (upgrade, WS_UPGRADE) != 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE, "Missing or invalid Upgrade header");
      return -1;
    }

  connection = SocketHTTP_Headers_get (request->headers, "Connection");
  if (!connection || strcasestr (connection, "Upgrade") == NULL)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Missing or invalid Connection header");
      return -1;
    }

  key = SocketHTTP_Headers_get (request->headers, "Sec-WebSocket-Key");
  if (!key || strlen (key) != 24)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Missing or invalid Sec-WebSocket-Key");
      return -1;
    }

  version = SocketHTTP_Headers_get (request->headers, "Sec-WebSocket-Version");
  if (!version || strcmp (version, WS_VERSION) != 0)
    {
      ws_set_error (ws, WS_ERROR_HANDSHAKE,
                    "Unsupported WebSocket version: %s",
                    version ? version : "(null)");
      return -1;
    }

  /* Handle optional subprotocol */
  protocol = SocketHTTP_Headers_get (request->headers, "Sec-WebSocket-Protocol");
  if (protocol && ws->config.subprotocols)
    {
      /* Find first matching subprotocol */
      const char *const *p;
      char *proto_copy;
      char *token;
      char *saveptr = NULL;

      proto_copy = ws_copy_string (ws->arena, protocol);
      token = strtok_r (proto_copy, ", ", &saveptr);

      while (token)
        {
          for (p = ws->config.subprotocols; *p; p++)
            {
              if (strcasecmp (token, *p) == 0)
                {
                  ws->handshake.selected_subprotocol
                      = ws_copy_string (ws->arena, *p);
                  goto protocol_found;
                }
            }
          token = strtok_r (NULL, ", ", &saveptr);
        }
    protocol_found:;
    }

  /* Handle optional extensions */
  extensions
      = SocketHTTP_Headers_get (request->headers, "Sec-WebSocket-Extensions");
  if (extensions && ws->config.enable_permessage_deflate)
    {
      if (strstr (extensions, "permessage-deflate"))
        {
          ws->handshake.compression_negotiated = 1;

          /* Parse and accept parameters */
          if (strstr (extensions, "server_no_context_takeover"))
            ws->handshake.server_no_context_takeover = 1;
          if (strstr (extensions, "client_no_context_takeover"))
            ws->handshake.client_no_context_takeover = 1;

          /* Apply our preferences */
          if (ws->config.deflate_no_context_takeover)
            {
              ws->handshake.server_no_context_takeover = 1;
              ws->handshake.client_no_context_takeover = 1;
            }
        }
    }

  /* Build response */
  if (ws_build_server_response (ws, key) < 0)
    return -1;

  ws->handshake.state = WS_HANDSHAKE_SENDING_REQUEST;
  return 0;
}

int
ws_handshake_server_process (SocketWS_T ws)
{
  ssize_t n;

  assert (ws);
  assert (ws->role == WS_ROLE_SERVER);

  switch (ws->handshake.state)
    {
    case WS_HANDSHAKE_SENDING_REQUEST:
      /* Send response data */
      while (ws->handshake.request_sent < ws->handshake.request_len)
        {
          n = Socket_send (ws->socket,
                           ws->handshake.request_buf + ws->handshake.request_sent,
                           ws->handshake.request_len - ws->handshake.request_sent);
          if (n < 0)
            {
              if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 1; /* Would block */
              ws_set_error (ws, WS_ERROR_HANDSHAKE, "Send failed");
              ws->handshake.state = WS_HANDSHAKE_FAILED;
              return -1;
            }
          ws->handshake.request_sent += (size_t)n;
        }

      /* Response sent */
      ws->handshake.state = WS_HANDSHAKE_COMPLETE;

#ifdef SOCKETWS_HAS_DEFLATE
      /* Initialize compression if negotiated */
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

      return 0; /* Complete */

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
  assert (ws);
  assert (accept);

  if (strlen (accept) != strlen (ws->handshake.expected_accept))
    return -1;

  return SocketCrypto_secure_compare (accept, ws->handshake.expected_accept,
                                      strlen (accept));
}

/* ============================================================================
 * Helper - Copy String to Arena
 * ============================================================================ */

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
 * ============================================================================ */

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
  if (!upgrade || strcasecmp (upgrade, "websocket") != 0)
    return 0;

  connection = SocketHTTP_Headers_get (request->headers, "Connection");
  if (!connection || strcasestr (connection, "Upgrade") == NULL)
    return 0;

  version = SocketHTTP_Headers_get (request->headers, "Sec-WebSocket-Version");
  if (!version)
    return 0;

  return 1;
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
  char buf[512];
  int len;

  if (!socket)
    return;

  len = snprintf (buf, sizeof (buf),
                  "HTTP/1.1 %d %s\r\n"
                  "Content-Type: text/plain\r\n"
                  "Content-Length: %zu\r\n"
                  "Connection: close\r\n"
                  "\r\n"
                  "%s",
                  status_code, reason ? reason : "Rejected",
                  reason ? strlen (reason) : 8,
                  reason ? reason : "Rejected");

  if (len > 0 && (size_t)len < sizeof (buf))
    Socket_send (socket, buf, (size_t)len);
}

