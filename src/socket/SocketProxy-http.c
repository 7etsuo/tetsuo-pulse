/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

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
 * Security:
 * - Uses SocketHTTP1_Parser_T in strict mode to prevent request smuggling
 * - Credentials are securely cleared after Base64 encoding via SocketCrypto
 * - All buffer operations are bounds-checked to prevent overflows
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
 * ============================================================================
 */

/** Buffer size for Basic auth credentials (username:password) */
#define SOCKET_PROXY_CREDENTIALS_BUFSIZE                                      \
  (SOCKET_PROXY_MAX_USERNAME_LEN + SOCKET_PROXY_MAX_PASSWORD_LEN + 2)

/** Length of "Basic " prefix for Proxy-Authorization header */
#define SOCKET_PROXY_BASIC_AUTH_PREFIX_LEN (sizeof ("Basic ") - 1)

/** Base64 encoding padding allowance for header value */
#define SOCKET_PROXY_BASE64_PADDING 32

/** Buffer size for Base64-encoded auth header value */
#define SOCKET_PROXY_AUTH_HEADER_BUFSIZE                                      \
  ((SOCKET_PROXY_CREDENTIALS_BUFSIZE * 4 / 3)                                 \
   + SOCKET_PROXY_BASIC_AUTH_PREFIX_LEN + SOCKET_PROXY_BASE64_PADDING)

/** CRLF size for HTTP line endings */
#define SOCKET_PROXY_CRLF_SIZE (sizeof ("\r\n") - 1)

/* HTTP status code range boundaries */
#define HTTP_STATUS_SUCCESS_MIN 200
#define HTTP_STATUS_SUCCESS_MAX 299
#define HTTP_STATUS_CLIENT_ERROR_MIN 400
#define HTTP_STATUS_CLIENT_ERROR_MAX 499
#define HTTP_STATUS_SERVER_ERROR_MIN 500

/* Specific HTTP status codes for proxy responses */
#define HTTP_STATUS_BAD_REQUEST 400
#define HTTP_STATUS_FORBIDDEN 403
#define HTTP_STATUS_NOT_FOUND 404
#define HTTP_STATUS_PROXY_AUTH_REQUIRED 407
#define HTTP_STATUS_INTERNAL_SERVER_ERROR 500
#define HTTP_STATUS_BAD_GATEWAY 502
#define HTTP_STATUS_SERVICE_UNAVAILABLE 503
#define HTTP_STATUS_GATEWAY_TIMEOUT 504

/* ============================================================================
 * Helper Functions
 * ============================================================================
 */

/**
 * proxy_http_append_formatted - Append formatted HTTP line to request buffer using connection error buf
 * @conn: Proxy connection context for error reporting
 * @buf: Buffer start pointer
 * @len: Pointer to current length (updated on success)
 * @remaining: Pointer to remaining space (updated on success)
 * @error_msg: Error message to set in conn->error_buf on failure
 * @fmt: printf-style format string for the header line (must end with \r\n)
 *
 * Returns: 0 on success, -1 on truncation/error (error in conn->error_buf)
 * Thread-safe: No (modifies conn buffers)
 *
 * Simplified helper for HTTP request building. Uses conn->error_buf automatically.
 * Consolidates bounds-checked formatting for headers like "Host: %s:%d\r\n".
 * Assumes fmt includes \r\n termination.
 *
 * @see append_request_terminator() for final CRLF if needed.
 */
static int
proxy_http_append_formatted (struct SocketProxy_Conn_T *conn, char *buf, size_t *len, size_t *remaining, const char *error_msg, const char *fmt,
                  ...)
{
  va_list args;
  int n;

  va_start (args, fmt);
  n = vsnprintf (buf + *len, *remaining, fmt, args);
  va_end (args);

  if (n < 0 || (size_t)n >= *remaining)
    {
      snprintf (conn->error_buf, sizeof (conn->error_buf), "%s", error_msg);
      return -1;
    }

  *len += (size_t)n;
  *remaining -= (size_t)n;
  return 0;
}

/**
 * build_basic_auth - Build Basic auth header value
 * @username: Username for authentication (must not be NULL)
 * @password: Password for authentication (must not be NULL)
 * @output: Output buffer for "Basic base64(user:pass)"
 * @output_size: Size of output buffer
 *
 * Returns: 0 on success, -1 on error (credentials truncated or encoding failed)
 * Thread-safe: Yes (uses stack-local buffer, secure clear)
 *
 * Securely builds Basic authentication header and clears credentials
 * from memory after encoding using SocketCrypto_secure_clear() to prevent
 * sensitive data from being left in memory.
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
 * append_request_line - Append CONNECT request line to buffer
 * @conn: Proxy connection context with target host/port
 * @buf: Output buffer
 * @len: Pointer to current buffer length (updated)
 * @remaining: Pointer to remaining buffer space (updated)
 *
 * Returns: 0 on success, -1 if buffer too small
 *
 * Formats: "CONNECT host:port HTTP/1.1\r\n"
 */
static int
append_request_line (struct SocketProxy_Conn_T *conn, char *buf, size_t *len,
                     size_t *remaining)
{
  return proxy_http_append_formatted (conn, buf, len, remaining, "Request line too long",
                           "CONNECT %s:%d HTTP/1.1\r\n", conn->target_host,
                           conn->target_port);
}

/**
 * append_host_header - Append Host header to buffer
 * @conn: Proxy connection context with target host/port
 * @buf: Output buffer
 * @len: Pointer to current buffer length (updated)
 * @remaining: Pointer to remaining buffer space (updated)
 *
 * Returns: 0 on success, -1 if buffer too small
 *
 * Formats: "Host: host:port\r\n"
 */
static int
append_host_header (struct SocketProxy_Conn_T *conn, char *buf, size_t *len,
                    size_t *remaining)
{
  return proxy_http_append_formatted (conn, buf, len, remaining, "Host header too long",
                           "Host: %s:%d\r\n", conn->target_host,
                           conn->target_port);
}

/**
 * append_auth_header - Append Proxy-Authorization header if credentials present
 * @conn: Proxy connection context with optional username/password
 * @buf: Output buffer
 * @len: Pointer to current buffer length (updated)
 * @remaining: Pointer to remaining buffer space (updated)
 *
 * Returns: 0 on success (or no credentials), -1 on encoding/buffer error
 *
 * If credentials are present, formats: "Proxy-Authorization: Basic <b64>\r\n"
 * Securely clears the encoded auth header after use.
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

  result = proxy_http_append_formatted (conn, buf, len, remaining, "Auth header too long",
                             "Proxy-Authorization: %s\r\n", auth_header);

  /* Clear auth header after use - security best practice */
  SocketCrypto_secure_clear (auth_header, sizeof (auth_header));

  return result;
}

/**
 * append_extra_headers - Append user-provided extra headers to buffer
 * @conn: Proxy connection context with optional extra_headers
 * @buf: Output buffer
 * @len: Pointer to current buffer length (updated)
 * @remaining: Pointer to remaining buffer space (updated)
 *
 * Returns: 0 on success (or no extra headers), -1 if buffer too small
 *
 * Serializes extra HTTP headers using SocketHTTP1_serialize_headers.
 */
static int
append_extra_headers (struct SocketProxy_Conn_T *conn, char *buf, size_t *len,
                      size_t *remaining)
{
  ssize_t headers_len;

  if (conn->extra_headers == NULL)
    return 0;

  headers_len = SocketHTTP1_serialize_headers (conn->extra_headers, buf + *len,
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
 * append_request_terminator - Append final CRLF to end HTTP headers
 * @conn: Proxy connection context for error reporting
 * @buf: Output buffer
 * @len: Pointer to current buffer length (updated)
 * @remaining: Pointer to remaining buffer space (updated)
 *
 * Returns: 0 on success, -1 if buffer too small
 *
 * Appends "\r\n" to terminate the HTTP header section.
 * Uses proxy_http_append_formatted for consistency and bounds check.
 */
static int
append_request_terminator (struct SocketProxy_Conn_T *conn, char *buf,
                           size_t *len, size_t *remaining)
{
  return proxy_http_append_formatted (conn, buf, len, remaining, "Request terminator too small", "\r\n");
}

/**
 * proxy_http_send_connect - Build HTTP CONNECT request for proxy tunneling
 * @conn: Proxy connection context with target host/port and optional auth
 *
 * Returns: 0 on success (request in send_buf), -1 on error
 * Thread-safe: No (modifies conn->send_buf and conn->proto_state)
 *
 * Builds a complete HTTP CONNECT request in the connection's send buffer:
 * - Request line: CONNECT target:port HTTP/1.1
 * - Host header (required by HTTP/1.1)
 * - Proxy-Authorization header (if credentials configured)
 * - Extra headers (if configured)
 * - Empty line to terminate headers
 *
 * After success, caller should send conn->send_buf[0..send_len-1].
 */
int
proxy_http_send_connect (struct SocketProxy_Conn_T *conn)
{
  char *buf = (char *)conn->send_buf;
  size_t len = 0;
  size_t remaining = sizeof (conn->send_buf);

  /* Build request line: CONNECT host:port HTTP/1.1 */
  if (append_request_line (conn, buf, &len, &remaining) < 0)
    return -1;

  /* Host header (required by HTTP/1.1) */
  if (append_host_header (conn, buf, &len, &remaining) < 0)
    return -1;

  /* Proxy-Authorization header (if credentials provided) */
  if (append_auth_header (conn, buf, &len, &remaining) < 0)
    return -1;

  /* Extra headers (if provided) */
  if (append_extra_headers (conn, buf, &len, &remaining) < 0)
    return -1;

  /* Empty line to terminate headers */
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
 * create_http_parser - Lazily create HTTP parser for response parsing
 * @conn: Proxy connection context
 *
 * Returns: 0 on success (parser ready), -1 on allocation failure
 * Thread-safe: No (modifies conn->http_parser)
 *
 * Creates the HTTP/1.1 parser on first call using strict mode to prevent
 * request smuggling attacks. Parser is allocated from conn->arena.
 */
static int
create_http_parser (struct SocketProxy_Conn_T *conn)
{
  SocketHTTP1_Config config;

  if (conn->http_parser != NULL)
    return 0;

  SocketHTTP1_config_defaults (&config);
  config.strict_mode = 1; /* Strict mode prevents request smuggling */

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
 * parse_http_response - Feed received data to parser and interpret result
 * @conn: Proxy connection context with data in recv_buf
 *
 * Returns: PROXY_OK on success, PROXY_IN_PROGRESS if more data needed,
 *          or error result on parse/protocol failure
 * Thread-safe: No (modifies conn->recv_buf and conn->recv_len)
 *
 * Feeds buffered data to the HTTP parser, shifts consumed bytes out of
 * the buffer, and interprets the parsed response. Detects smuggling
 * attacks via strict parser mode.
 */
static SocketProxy_Result
parse_http_response (struct SocketProxy_Conn_T *conn)
{
  SocketHTTP1_Result parse_result;
  size_t consumed;
  const SocketHTTP_Response *response;

  parse_result = SocketHTTP1_Parser_execute (conn->http_parser,
                                             (const char *)conn->recv_buf,
                                             conn->recv_len, &consumed);

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
                "HTTP parse error: %s",
                SocketHTTP1_result_string (parse_result));
      return PROXY_ERROR_PROTOCOL;
    }
}

/**
 * proxy_http_recv_response - Parse HTTP CONNECT response from proxy
 * @conn: Proxy connection context with received data in recv_buf
 *
 * Returns: PROXY_OK on successful 2xx response, PROXY_IN_PROGRESS if more
 *          data needed, or error result on parse/protocol/auth failure
 * Thread-safe: No (modifies connection state)
 *
 * Creates HTTP parser on first call (lazy initialization), then feeds
 * buffered data to parser. On complete response, maps HTTP status to
 * proxy result code.
 */
SocketProxy_Result
proxy_http_recv_response (struct SocketProxy_Conn_T *conn)
{
  if (create_http_parser (conn) < 0)
    return PROXY_ERROR_PROTOCOL;

  return parse_http_response (conn);
}

/* ============================================================================
 * HTTP Status Code Mapping
 * ============================================================================
 */



/**
 * proxy_http_status_to_result - Convert HTTP status code to proxy result
 * @status: HTTP status code from proxy response
 *
 * Returns: SocketProxy_Result corresponding to the HTTP status
 * Thread-safe: No (uses thread-local error buffer for error messages)
 *
 * Maps HTTP status codes to semantic proxy results:
 * - 2xx: Success (tunnel established)
 * - 4xx: Client errors (auth required, forbidden, etc.)
 * - 5xx: Server errors (bad gateway, timeout, etc.)
 * - Other: Protocol error (unexpected response)
 */
SocketProxy_Result
proxy_http_status_to_result (int status)
{
  /* 2xx Success - tunnel established */
  if (status >= HTTP_STATUS_SUCCESS_MIN && status <= HTTP_STATUS_SUCCESS_MAX)
    return PROXY_OK;

  /* 4xx Client Error */
  if (status >= HTTP_STATUS_CLIENT_ERROR_MIN
      && status <= HTTP_STATUS_CLIENT_ERROR_MAX)
    {
      switch (status)
        {
        case HTTP_STATUS_BAD_REQUEST:
          PROXY_ERROR_MSG ("HTTP 400 Bad Request");
          return PROXY_ERROR_PROTOCOL;

        case HTTP_STATUS_FORBIDDEN:
          PROXY_ERROR_MSG ("HTTP 403 Forbidden");
          return PROXY_ERROR_FORBIDDEN;

        case HTTP_STATUS_NOT_FOUND:
          PROXY_ERROR_MSG ("HTTP 404 Not Found");
          return PROXY_ERROR_HOST_UNREACHABLE;

        case HTTP_STATUS_PROXY_AUTH_REQUIRED:
          PROXY_ERROR_MSG ("HTTP 407 Proxy Authentication Required");
          return PROXY_ERROR_AUTH_REQUIRED;

        default:
          PROXY_ERROR_MSG ("HTTP %d Client Error", status);
          return PROXY_ERROR;
        }
    }

  /* 5xx Server Error */
  if (status >= HTTP_STATUS_SERVER_ERROR_MIN)
    {
      switch (status)
        {
        case HTTP_STATUS_INTERNAL_SERVER_ERROR:
          PROXY_ERROR_MSG ("HTTP 500 Internal Server Error");
          return PROXY_ERROR;

        case HTTP_STATUS_BAD_GATEWAY:
          PROXY_ERROR_MSG ("HTTP 502 Bad Gateway");
          return PROXY_ERROR_HOST_UNREACHABLE;

        case HTTP_STATUS_SERVICE_UNAVAILABLE:
          PROXY_ERROR_MSG ("HTTP 503 Service Unavailable");
          return PROXY_ERROR;

        case HTTP_STATUS_GATEWAY_TIMEOUT:
          PROXY_ERROR_MSG ("HTTP 504 Gateway Timeout");
          return PROXY_ERROR_TIMEOUT;

        default:
          PROXY_ERROR_MSG ("HTTP %d Server Error", status);
          return PROXY_ERROR;
        }
    }

  /* Unexpected status (1xx, 3xx, or invalid) */
  PROXY_ERROR_MSG ("Unexpected HTTP status: %d", status);
  return PROXY_ERROR_PROTOCOL;
}
