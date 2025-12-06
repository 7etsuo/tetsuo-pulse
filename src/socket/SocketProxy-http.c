/**
 * SocketProxy-http.c - HTTP CONNECT Protocol Implementation
 *
 * Part of the Socket Library
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

#include "http/SocketHTTP1.h"



#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Internal Constants
 * ============================================================================ */

/** Buffer size for Basic auth credentials (username:password) */
#define SOCKET_PROXY_CREDENTIALS_BUFSIZE (SOCKET_PROXY_MAX_USERNAME_LEN + SOCKET_PROXY_MAX_PASSWORD_LEN + 2)

/** Buffer size for Base64-encoded auth header value */
#define SOCKET_PROXY_AUTH_HEADER_BUFSIZE ((SOCKET_PROXY_CREDENTIALS_BUFSIZE * 4 / 3) + SOCKET_PROXY_BASIC_AUTH_PREFIX_LEN + 32)

/** Length of "Basic " prefix for Proxy-Authorization header */
#define SOCKET_PROXY_BASIC_AUTH_PREFIX_LEN (sizeof("Basic ") - 1)

/** CRLF size for HTTP line endings */
#define SOCKET_PROXY_CRLF_SIZE (sizeof("\r\n") - 1)

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/**
 * append_formatted - Append formatted string to request buffer with bounds check
 * @buf: Buffer start pointer
 * @len: Pointer to current length (updated on success)
 * @remaining: Pointer to remaining space (updated on success)
 * @error_buf: Connection error buffer for error messages
 * @error_size: Size of error buffer
 * @error_msg: Error message to set on failure
 * @fmt: printf-style format string
 *
 * Returns: 0 on success, -1 on truncation/error
 *
 * Consolidates the repeated pattern of snprintf + bounds check + error handling.
 */
static int
append_formatted (char *buf, size_t *len, size_t *remaining, char *error_buf,
                  size_t error_size, const char *error_msg, const char *fmt,
                  ...)
{
  va_list args;
  int n;

  va_start (args, fmt);
  n = vsnprintf (buf + *len, *remaining, fmt, args);
  va_end (args);

  if (n < 0 || (size_t)n >= *remaining)
    {
      snprintf (error_buf, error_size, "%s", error_msg);
      return -1;
    }

  *len += (size_t)n;
  *remaining -= (size_t)n;
  return 0;
}

/**
 * build_basic_auth - Build Basic auth header value
 * @username: Username for authentication
 * @password: Password for authentication
 * @output: Output buffer for "Basic base64(user:pass)"
 * @output_size: Size of output buffer
 *
 * Returns: 0 on success, -1 on error
 *
 * Securely builds Basic authentication header and clears credentials
 * from memory after encoding.
 */
static int
build_basic_auth (const char *username, const char *password, char *output,
                  size_t output_size)
{
  char credentials[SOCKET_PROXY_CREDENTIALS_BUFSIZE];
  size_t cred_len;
  ssize_t encoded_len;
  size_t base64_size;

  /* Format credentials as "username:password" */
  cred_len = (size_t)snprintf (credentials, sizeof (credentials), "%s:%s",
                               username, password);
  if (cred_len >= sizeof (credentials))
    {
      SocketCrypto_secure_clear (credentials, sizeof (credentials));
      return -1;
    }

  /* Calculate required size: "Basic " + base64 */
  base64_size = SocketCrypto_base64_encoded_size (cred_len);
  if (SOCKET_PROXY_BASIC_AUTH_PREFIX_LEN + base64_size > output_size)
    {
      SocketCrypto_secure_clear (credentials, sizeof (credentials));
      return -1;
    }

  /* Write prefix */
  memcpy (output, "Basic ", SOCKET_PROXY_BASIC_AUTH_PREFIX_LEN);

  /* Encode credentials */
  encoded_len = SocketCrypto_base64_encode (
      credentials, cred_len, output + SOCKET_PROXY_BASIC_AUTH_PREFIX_LEN,
      output_size - SOCKET_PROXY_BASIC_AUTH_PREFIX_LEN);

  /* Clear sensitive credentials regardless of result */
  SocketCrypto_secure_clear (credentials, sizeof (credentials));

  return (encoded_len < 0) ? -1 : 0;
}

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
 * append_request_line - Append CONNECT request line
 */
static int
append_request_line (struct SocketProxy_Conn_T *conn, char *buf, size_t *len,
                     size_t *remaining)
{
  return append_formatted (buf, len, remaining, conn->error_buf,
                           sizeof (conn->error_buf), "Request line too long",
                           "CONNECT %s:%d HTTP/1.1\r\n", conn->target_host,
                           conn->target_port);
}

/**
 * append_host_header - Append Host header
 */
static int
append_host_header (struct SocketProxy_Conn_T *conn, char *buf, size_t *len,
                    size_t *remaining)
{
  return append_formatted (buf, len, remaining, conn->error_buf,
                           sizeof (conn->error_buf), "Host header too long",
                           "Host: %s:%d\r\n", conn->target_host,
                           conn->target_port);
}

/**
 * append_auth_header - Append Proxy-Authorization header if credentials present
 */
static int
append_auth_header (struct SocketProxy_Conn_T *conn, char *buf, size_t *len,
                    size_t *remaining)
{
  char auth_header[SOCKET_PROXY_AUTH_HEADER_BUFSIZE];
  int result;

  if (conn->username == NULL || conn->password == NULL)
    return 0;

  if (build_basic_auth (conn->username, conn->password, auth_header,
                        sizeof (auth_header))
      < 0)
    {
      snprintf (conn->error_buf, sizeof (conn->error_buf),
                "Failed to build auth header");
      return -1;
    }

  result = append_formatted (buf, len, remaining, conn->error_buf,
                             sizeof (conn->error_buf), "Auth header too long",
                             "Proxy-Authorization: %s\r\n", auth_header);

  /* Clear auth header after use */
  SocketCrypto_secure_clear (auth_header, sizeof (auth_header));

  return result;
}

/**
 * append_extra_headers - Append extra headers if provided
 */
static int
append_extra_headers (struct SocketProxy_Conn_T *conn, char *buf, size_t *len,
                      size_t *remaining)
{
  ssize_t headers_len;

  if (conn->extra_headers == NULL)
    return 0;

  headers_len
      = SocketHTTP1_serialize_headers (conn->extra_headers, buf + *len,
                                       *remaining);
  if (headers_len < 0)
    {
      snprintf (conn->error_buf, sizeof (conn->error_buf),
                "Extra headers too long");
      return -1;
    }

  *len += (size_t)headers_len;
  *remaining -= (size_t)headers_len;
  return 0;
}

/**
 * append_request_terminator - Append final CRLF to end headers
 */
static int
append_request_terminator (struct SocketProxy_Conn_T *conn, char *buf,
                           size_t *len, size_t *remaining)
{
  if (*remaining < SOCKET_PROXY_CRLF_SIZE + 1)
    {
      snprintf (conn->error_buf, sizeof (conn->error_buf), "Request too long");
      return -1;
    }

  /* Copy CRLF with null terminator; send_len controls actual bytes sent */
  memcpy (buf + *len, "\r\n", SOCKET_PROXY_CRLF_SIZE + 1);
  *len += SOCKET_PROXY_CRLF_SIZE;
  return 0;
}

int
proxy_http_send_connect (struct SocketProxy_Conn_T *conn)
{
  char *buf = (char *)conn->send_buf;
  size_t len = 0;
  size_t remaining = sizeof (conn->send_buf);

  /* Build request line: CONNECT host:port HTTP/1.1 */
  if (append_request_line (conn, buf, &len, &remaining) < 0)
    return -1;

  /* Host header (required) */
  if (append_host_header (conn, buf, &len, &remaining) < 0)
    return -1;

  /* Proxy-Authorization header (if credentials provided) */
  if (append_auth_header (conn, buf, &len, &remaining) < 0)
    return -1;

  /* Extra headers (if provided) */
  if (append_extra_headers (conn, buf, &len, &remaining) < 0)
    return -1;

  /* End of headers */
  if (append_request_terminator (conn, buf, &len, &remaining) < 0)
    return -1;

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

/**
 * create_http_parser - Create HTTP parser on first call
 */
static int
create_http_parser (struct SocketProxy_Conn_T *conn)
{
  SocketHTTP1_Config config;

  if (conn->http_parser != NULL)
    return 0;

  SocketHTTP1_config_defaults (&config);
  config.strict_mode = 1; /* Strict mode for security */

  conn->http_parser
      = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, &config, conn->arena);
  if (conn->http_parser == NULL)
    {
      snprintf (conn->error_buf, sizeof (conn->error_buf),
                "Failed to create HTTP parser");
      return -1;
    }

  return 0;
}

/**
 * parse_http_response - Feed data to parser and handle result
 */
static SocketProxy_Result
parse_http_response (struct SocketProxy_Conn_T *conn)
{
  SocketHTTP1_Result parse_result;
  size_t consumed;
  const SocketHTTP_Response *response;

  parse_result = SocketHTTP1_Parser_execute (
      conn->http_parser, (const char *)conn->recv_buf, conn->recv_len,
      &consumed);

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

SocketProxy_Result
proxy_http_recv_response (struct SocketProxy_Conn_T *conn)
{
  if (create_http_parser (conn) < 0)
    return PROXY_ERROR_PROTOCOL;

  return parse_http_response (conn);
}

/* ============================================================================
 * HTTP Status Code Mapping
 * ============================================================================ */

/**
 * map_4xx_status - Map 4xx client error to result
 */
static SocketProxy_Result
map_4xx_status (int status)
{
  switch (status)
    {
    case 400:
      PROXY_ERROR_MSG ("HTTP 400 Bad Request");
      return PROXY_ERROR_PROTOCOL;

    case 403:
      PROXY_ERROR_MSG ("HTTP 403 Forbidden");
      return PROXY_ERROR_FORBIDDEN;

    case 404:
      PROXY_ERROR_MSG ("HTTP 404 Not Found");
      return PROXY_ERROR_HOST_UNREACHABLE;

    case 407:
      PROXY_ERROR_MSG ("HTTP 407 Proxy Authentication Required");
      return PROXY_ERROR_AUTH_REQUIRED;

    default:
      PROXY_ERROR_MSG ("HTTP %d Client Error", status);
      return PROXY_ERROR;
    }
}

/**
 * map_5xx_status - Map 5xx server error to result
 */
static SocketProxy_Result
map_5xx_status (int status)
{
  switch (status)
    {
    case 500:
      PROXY_ERROR_MSG ("HTTP 500 Internal Server Error");
      return PROXY_ERROR;

    case 502:
      PROXY_ERROR_MSG ("HTTP 502 Bad Gateway");
      return PROXY_ERROR_HOST_UNREACHABLE;

    case 503:
      PROXY_ERROR_MSG ("HTTP 503 Service Unavailable");
      return PROXY_ERROR;

    case 504:
      PROXY_ERROR_MSG ("HTTP 504 Gateway Timeout");
      return PROXY_ERROR_TIMEOUT;

    default:
      PROXY_ERROR_MSG ("HTTP %d Server Error", status);
      return PROXY_ERROR;
    }
}

SocketProxy_Result
proxy_http_status_to_result (int status)
{
  /* 2xx Success */
  if (status >= 200 && status < 300)
    return PROXY_OK;

  /* 4xx Client Error */
  if (status >= 400 && status < 500)
    return map_4xx_status (status);

  /* 5xx Server Error */
  if (status >= 500)
    return map_5xx_status (status);

  /* Unexpected status (1xx, 3xx, or invalid) */
  PROXY_ERROR_MSG ("Unexpected HTTP status: %d", status);
  return PROXY_ERROR_PROTOCOL;
}
