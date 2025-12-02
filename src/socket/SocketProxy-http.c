/**
 * SocketProxy-http.c - HTTP CONNECT Protocol Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements HTTP CONNECT method for proxy tunneling (RFC 7231 Section 4.3.6).
 *
 * HTTP CONNECT Protocol:
 * 1. Client sends: CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n\r\n
 * 2. Optionally includes Proxy-Authorization header for Basic auth
 * 3. Server responds with HTTP status line (200 = success)
 * 4. After 200, connection is upgraded to raw TCP tunnel
 *
 * The implementation reuses:
 * - SocketHTTP1_Parser_T for response parsing (strict mode prevents smuggling)
 * - SocketCrypto_base64_encode() for Basic auth encoding
 * - SocketHTTP_Headers_T for extra headers (if provided)
 */

#include "socket/SocketProxy-private.h"
#include "socket/SocketProxy.h"

#include "core/SocketCrypto.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * HTTP CONNECT Request Building
 * ============================================================================
 *
 * Request format:
 * CONNECT host:port HTTP/1.1\r\n
 * Host: host:port\r\n
 * [Proxy-Authorization: Basic base64(user:pass)\r\n]
 * [Extra-Headers]\r\n
 * \r\n
 *
 * Note: Use target host:port, not the proxy address
 */

/**
 * Build Basic auth header value
 * Output: "Basic base64(user:pass)"
 */
static int
build_basic_auth (const char *username, const char *password, char *output,
                  size_t output_size)
{
  char credentials[512];
  size_t cred_len;
  ssize_t encoded_len;
  size_t prefix_len;

  /* Format credentials as "username:password" */
  cred_len = (size_t)snprintf (credentials, sizeof (credentials), "%s:%s",
                               username, password);
  if (cred_len >= sizeof (credentials))
    {
      SocketCrypto_secure_clear (credentials, sizeof (credentials));
      return -1; /* Credentials too long */
    }

  /* Calculate required size: "Basic " + base64 */
  prefix_len = 6; /* strlen("Basic ") */
  size_t base64_size = SocketCrypto_base64_encoded_size (cred_len);

  if (prefix_len + base64_size > output_size)
    {
      SocketCrypto_secure_clear (credentials, sizeof (credentials));
      return -1; /* Output buffer too small */
    }

  /* Write prefix */
  memcpy (output, "Basic ", prefix_len);

  /* Encode credentials */
  encoded_len = SocketCrypto_base64_encode (credentials, cred_len,
                                            output + prefix_len,
                                            output_size - prefix_len);

  /* Clear sensitive credentials regardless of result */
  SocketCrypto_secure_clear (credentials, sizeof (credentials));

  if (encoded_len < 0)
    return -1;

  return 0;
}

int
proxy_http_send_connect (struct SocketProxy_Conn_T *conn)
{
  char *buf = (char *)conn->send_buf;
  size_t len = 0;
  size_t remaining = sizeof (conn->send_buf);
  int n;
  char auth_header[768];

  /* Request line: CONNECT host:port HTTP/1.1 */
  n = snprintf (buf + len, remaining, "CONNECT %s:%d HTTP/1.1\r\n",
                conn->target_host, conn->target_port);
  if (n < 0 || (size_t)n >= remaining)
    {
      snprintf (conn->error_buf, sizeof (conn->error_buf),
                "Request line too long");
      return -1;
    }
  len += (size_t)n;
  remaining -= (size_t)n;

  /* Host header (required) */
  n = snprintf (buf + len, remaining, "Host: %s:%d\r\n", conn->target_host,
                conn->target_port);
  if (n < 0 || (size_t)n >= remaining)
    {
      snprintf (conn->error_buf, sizeof (conn->error_buf),
                "Host header too long");
      return -1;
    }
  len += (size_t)n;
  remaining -= (size_t)n;

  /* Proxy-Authorization header (if credentials provided) */
  if (conn->username != NULL && conn->password != NULL)
    {
      if (build_basic_auth (conn->username, conn->password, auth_header,
                            sizeof (auth_header))
          < 0)
        {
          snprintf (conn->error_buf, sizeof (conn->error_buf),
                    "Failed to build auth header");
          return -1;
        }

      n = snprintf (buf + len, remaining, "Proxy-Authorization: %s\r\n",
                    auth_header);

      /* Clear auth header after use */
      SocketCrypto_secure_clear (auth_header, sizeof (auth_header));

      if (n < 0 || (size_t)n >= remaining)
        {
          snprintf (conn->error_buf, sizeof (conn->error_buf),
                    "Auth header too long");
          return -1;
        }
      len += (size_t)n;
      remaining -= (size_t)n;
    }

  /* Extra headers (if provided) */
  if (conn->extra_headers != NULL)
    {
      /* Serialize extra headers using SocketHTTP1 */
      ssize_t headers_len = SocketHTTP1_serialize_headers (
          conn->extra_headers, buf + len, remaining);
      if (headers_len < 0)
        {
          snprintf (conn->error_buf, sizeof (conn->error_buf),
                    "Extra headers too long");
          return -1;
        }
      len += (size_t)headers_len;
      remaining -= (size_t)headers_len;
    }

  /* End of headers */
  if (remaining < 3)
    {
      snprintf (conn->error_buf, sizeof (conn->error_buf), "Request too long");
      return -1;
    }
  memcpy (buf + len, "\r\n", 2);
  len += 2;

  conn->send_len = len;
  conn->send_offset = 0;
  conn->proto_state = PROTO_STATE_HTTP_REQUEST_SENT;

  return 0;
}

/* ============================================================================
 * HTTP CONNECT Response Parsing
 * ============================================================================
 *
 * Response format:
 * HTTP/1.1 200 Connection established\r\n
 * [Optional headers]\r\n
 * \r\n
 *
 * Success status codes: 200 OK
 * Auth required: 407 Proxy Authentication Required
 * Forbidden: 403 Forbidden
 * Bad gateway: 502 Bad Gateway
 * Service unavailable: 503 Service Unavailable
 *
 * Uses SocketHTTP1_Parser_T for safe parsing (prevents smuggling attacks).
 */

SocketProxy_Result
proxy_http_recv_response (struct SocketProxy_Conn_T *conn)
{
  SocketHTTP1_Result parse_result;
  size_t consumed;
  const SocketHTTP_Response *response;
  SocketHTTP1_Config config;

  /* Create parser on first call */
  if (conn->http_parser == NULL)
    {
      SocketHTTP1_config_defaults (&config);
      config.strict_mode = 1; /* Strict mode for security */

      conn->http_parser
          = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, &config, conn->arena);
      if (conn->http_parser == NULL)
        {
          snprintf (conn->error_buf, sizeof (conn->error_buf),
                    "Failed to create HTTP parser");
          return PROXY_ERROR_PROTOCOL;
        }
    }

  /* Feed data to parser */
  parse_result = SocketHTTP1_Parser_execute (
      conn->http_parser, (const char *)conn->recv_buf, conn->recv_len, &consumed);

  /* Shift consumed data out of buffer */
  if (consumed > 0)
    {
      memmove (conn->recv_buf, conn->recv_buf + consumed,
               conn->recv_len - consumed);
      conn->recv_len -= consumed;
    }

  switch (parse_result)
    {
    case HTTP1_INCOMPLETE:
      return PROXY_IN_PROGRESS;

    case HTTP1_OK:
      /* Headers complete - check status */
      response = SocketHTTP1_Parser_get_response (conn->http_parser);
      if (response == NULL)
        {
          snprintf (conn->error_buf, sizeof (conn->error_buf),
                    "Failed to get parsed response");
          return PROXY_ERROR_PROTOCOL;
        }

      return proxy_http_status_to_result (response->status_code);

    case HTTP1_ERROR_SMUGGLING_DETECTED:
      snprintf (conn->error_buf, sizeof (conn->error_buf),
                "HTTP response smuggling detected");
      return PROXY_ERROR_PROTOCOL;

    default:
      snprintf (conn->error_buf, sizeof (conn->error_buf),
                "HTTP parse error: %s", SocketHTTP1_result_string (parse_result));
      return PROXY_ERROR_PROTOCOL;
    }
}

/* ============================================================================
 * HTTP Status Code Mapping
 * ============================================================================ */

SocketProxy_Result
proxy_http_status_to_result (int status)
{
  /* 2xx Success */
  if (status >= 200 && status < 300)
    {
      return PROXY_OK;
    }

  /* Specific error codes */
  switch (status)
    {
    case 400: /* Bad Request */
      snprintf (proxy_error_buf, SOCKET_PROXY_ERROR_BUFSIZE,
                "HTTP 400 Bad Request");
      return PROXY_ERROR_PROTOCOL;

    case 403: /* Forbidden */
      snprintf (proxy_error_buf, SOCKET_PROXY_ERROR_BUFSIZE,
                "HTTP 403 Forbidden");
      return PROXY_ERROR_FORBIDDEN;

    case 404: /* Not Found */
      snprintf (proxy_error_buf, SOCKET_PROXY_ERROR_BUFSIZE,
                "HTTP 404 Not Found");
      return PROXY_ERROR_HOST_UNREACHABLE;

    case 407: /* Proxy Authentication Required */
      snprintf (proxy_error_buf, SOCKET_PROXY_ERROR_BUFSIZE,
                "HTTP 407 Proxy Authentication Required");
      return PROXY_ERROR_AUTH_REQUIRED;

    case 500: /* Internal Server Error */
      snprintf (proxy_error_buf, SOCKET_PROXY_ERROR_BUFSIZE,
                "HTTP 500 Internal Server Error");
      return PROXY_ERROR;

    case 502: /* Bad Gateway */
      snprintf (proxy_error_buf, SOCKET_PROXY_ERROR_BUFSIZE,
                "HTTP 502 Bad Gateway");
      return PROXY_ERROR_HOST_UNREACHABLE;

    case 503: /* Service Unavailable */
      snprintf (proxy_error_buf, SOCKET_PROXY_ERROR_BUFSIZE,
                "HTTP 503 Service Unavailable");
      return PROXY_ERROR;

    case 504: /* Gateway Timeout */
      snprintf (proxy_error_buf, SOCKET_PROXY_ERROR_BUFSIZE,
                "HTTP 504 Gateway Timeout");
      return PROXY_ERROR_TIMEOUT;

    default:
      if (status >= 400 && status < 500)
        {
          snprintf (proxy_error_buf, SOCKET_PROXY_ERROR_BUFSIZE,
                    "HTTP %d Client Error", status);
          return PROXY_ERROR;
        }
      if (status >= 500)
        {
          snprintf (proxy_error_buf, SOCKET_PROXY_ERROR_BUFSIZE,
                    "HTTP %d Server Error", status);
          return PROXY_ERROR;
        }
      snprintf (proxy_error_buf, SOCKET_PROXY_ERROR_BUFSIZE,
                "Unexpected HTTP status: %d", status);
      return PROXY_ERROR_PROTOCOL;
    }
}

