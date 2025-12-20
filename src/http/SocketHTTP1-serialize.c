/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketHTTP1-serialize.c - HTTP/1.1 Request/Response Serialization
 *
 * Part of the Socket Library
 *
 * Implements RFC 9112 HTTP/1.1 message serialization:
 * - Request line: METHOD SP Request-Target SP HTTP-Version CRLF
 * - Status line: HTTP-Version SP Status-Code SP Reason-Phrase CRLF
 * - Headers: Field-Name ":" OWS Field-Value OWS CRLF
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "http/SocketHTTP1.h"
#include "http/SocketHTTP1-private.h"

#include "core/SocketUtil.h"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketHTTP1);

const Except_T SocketHTTP1_SerializeError
    = { &SocketHTTP1_SerializeError, "HTTP/1.1 serialize error" };

/* ============================================================================
 * HTTP Serialization Constants
 * ============================================================================
 */

/* Use shared constants from SocketHTTP1-private.h */
#define HTTP_SP HTTP1_SP_STR
#define HTTP_SP_LEN HTTP1_SP_LEN
#define HTTP_CRLF HTTP1_CRLF_STR
#define HTTP_CRLF_LEN HTTP1_CRLF_LEN
#define HTTP_HEADER_SEP HTTP1_HEADER_SEP_STR
#define HTTP_HEADER_SEP_LEN HTTP1_HEADER_SEP_LEN

/* Serialize-specific constants */
#define HTTP_HOST_PREFIX "Host: "
#define HTTP_HOST_PREFIX_LEN (sizeof (HTTP_HOST_PREFIX) - 1)
#define HTTP_CONTENT_LENGTH_PREFIX "Content-Length: "
#define HTTP_CONTENT_LENGTH_PREFIX_LEN (sizeof (HTTP_CONTENT_LENGTH_PREFIX) - 1)

/* ============================================================================
 * Buffer Append Helpers
 * ============================================================================
 */

/**
 * safe_append - Append data to buffer with bounds checking
 * @buf: Buffer pointer (updated on success)
 * @remaining: Remaining space (updated on success)
 * @str: Data to append
 * @len: Data length
 *
 * Returns: 0 on success, -1 if buffer too small
 * Thread-safe: Yes (pure function)
 */
static int
safe_append (char **buf, size_t *remaining, const char *str, size_t len)
{
  if (len > *remaining)
    return -1;

  memcpy (*buf, str, len);
  *buf += len;
  *remaining -= len;
  return 0;
}

/**
 * safe_append_str - Append null-terminated string
 * @buf: Buffer pointer (updated)
 * @remaining: Remaining space (updated)
 * @str: Null-terminated string
 *
 * Returns: 0 on success, -1 if buffer too small
 * Thread-safe: Yes
 */
static int
safe_append_str (char **buf, size_t *remaining, const char *str)
{
  return safe_append (buf, remaining, str, strlen (str));
}

/**
 * safe_append_sp - Append single space separator
 * @buf: Buffer pointer (updated)
 * @remaining: Remaining space (updated)
 *
 * Returns: 0 on success, -1 if buffer too small
 * Thread-safe: Yes
 */
static int
safe_append_sp (char **buf, size_t *remaining)
{
  return safe_append (buf, remaining, HTTP_SP, HTTP_SP_LEN);
}

/**
 * safe_append_crlf - Append CRLF line terminator
 * @buf: Buffer pointer (updated)
 * @remaining: Remaining space (updated)
 *
 * Returns: 0 on success, -1 if buffer too small
 * Thread-safe: Yes
 */
static int
safe_append_crlf (char **buf, size_t *remaining)
{
  return safe_append (buf, remaining, HTTP_CRLF, HTTP_CRLF_LEN);
}

/**
 * safe_append_int64 - Append 64-bit integer as decimal string
 * @buf: Buffer pointer (updated)
 * @remaining: Remaining space (updated)
 * @value: Integer to append
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: Yes
 */
static int
safe_append_int64 (char **buf, size_t *remaining, int64_t value)
{
  char num[SOCKETHTTP1_INT_STRING_BUFSIZE];
  int len;

  len = snprintf (num, sizeof (num), "%lld", (long long)value);
  if (len < 0 || (size_t)len >= sizeof (num))
    return -1;

  return safe_append (buf, remaining, num, (size_t)len);
}

/* ============================================================================
 * Header Serialization
 * ============================================================================
 */

/**
 * serialize_ctx - Context for header serialization callback
 */
struct serialize_ctx
{
  char *buf;
  size_t remaining;
  int error;
};

/**
 * serialize_header_cb - Callback for header iteration during serialization
 * @name: Header name
 * @name_len: Header name length
 * @value: Header value
 * @value_len: Header value length
 * @userdata: serialize_ctx pointer
 *
 * Serializes a single header as: Name: Value\r\n
 *
 * Returns: 0 to continue, 1 to stop iteration
 */
static int
serialize_header_cb (const char *name, size_t name_len, const char *value,
                     size_t value_len, void *userdata)
{
  struct serialize_ctx *ctx = userdata;

  if (!SocketHTTP_header_name_valid (name, name_len)
      || !SocketHTTP_header_value_valid (value, value_len))
    {
      SOCKET_RAISE_MSG (SocketHTTP1, SocketHTTP1_SerializeError,
                        "Invalid header name or value");
    }

  /* Append: name ": " value "\r\n" */
  if (safe_append (&ctx->buf, &ctx->remaining, name, name_len) < 0
      || safe_append (&ctx->buf, &ctx->remaining, HTTP_HEADER_SEP,
                      HTTP_HEADER_SEP_LEN)
             < 0
      || safe_append (&ctx->buf, &ctx->remaining, value, value_len) < 0
      || safe_append_crlf (&ctx->buf, &ctx->remaining) < 0)
    {
      ctx->error = 1;
      return 1; /* Stop iteration */
    }

  return 0; /* Continue */
}

/**
 * serialize_headers_section - Serialize all headers from collection
 * @headers: Headers to serialize (may be NULL)
 * @buf: Buffer pointer (updated)
 * @remaining: Remaining space (updated)
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: Yes
 */
static int
serialize_headers_section (SocketHTTP_Headers_T headers, char **buf,
                           size_t *remaining)
{
  struct serialize_ctx ctx = { .buf = *buf, .remaining = *remaining, .error
                               = 0 };

  if (!headers)
    return 0;

  SocketHTTP_Headers_iterate (headers, serialize_header_cb, &ctx);

  if (ctx.error)
    return -1;

  *buf = ctx.buf;
  *remaining = ctx.remaining;
  return 0;
}

/**
 * append_content_length_header - Append Content-Length if needed
 * @buf: Buffer pointer (updated)
 * @remaining: Remaining space (updated)
 * @headers: Existing headers (may be NULL)
 * @has_body: Whether message has body
 * @content_length: Content length (-1 if unknown)
 *
 * Only appends if:
 * - has_body is true AND content_length >= 0
 * - No Content-Length or Transfer-Encoding already present
 *
 * Returns: 0 on success, -1 if buffer too small
 * Thread-safe: Yes
 */
static int
append_content_length_header (char **buf, size_t *remaining,
                              SocketHTTP_Headers_T headers, int has_body,
                              int64_t content_length)
{
  if (!has_body || content_length < 0)
    return 0;

  if (headers
      && (SocketHTTP_Headers_has (headers, "Content-Length")
          || SocketHTTP_Headers_has (headers, "Transfer-Encoding")))
    return 0;

  if (safe_append (buf, remaining, HTTP_CONTENT_LENGTH_PREFIX,
                   HTTP_CONTENT_LENGTH_PREFIX_LEN)
      < 0)
    return -1;

  if (safe_append_int64 (buf, remaining, content_length) < 0)
    return -1;

  return safe_append_crlf (buf, remaining);
}

/* ============================================================================
 * Request Line Serialization
 * ============================================================================
 */

/**
 * validate_request_target - Validate request target for forbidden chars
 * @target: Request target string
 *
 * Raises: SocketHTTP1_SerializeError if invalid
 */
static void
validate_request_target (const char *target)
{
  size_t target_len = strlen (target);
  if (!SocketHTTP_header_value_valid (target, target_len))
    {
      SOCKET_RAISE_MSG (SocketHTTP1, SocketHTTP1_SerializeError,
                        "Invalid request target contains forbidden "
                        "characters (CR/LF/NUL)");
    }
}

/**
 * serialize_request_line - Serialize HTTP request line
 * @request: Request structure
 * @buf: Buffer pointer (updated)
 * @remaining: Remaining space (updated)
 *
 * Serializes: METHOD SP Request-Target SP HTTP-Version CRLF
 *
 * Returns: 0 on success, -1 if buffer too small
 * Raises: SocketHTTP1_SerializeError on invalid input
 * Thread-safe: Yes
 */
static int
serialize_request_line (const SocketHTTP_Request *request, char **buf,
                        size_t *remaining)
{
  const char *method_name;
  const char *version_str;
  const char *target;

  method_name = SocketHTTP_method_name (request->method);
  if (!method_name)
    {
      SOCKET_RAISE_MSG (SocketHTTP1, SocketHTTP1_SerializeError,
                        "Unknown HTTP method: %d", (int)request->method);
    }

  if (safe_append_str (buf, remaining, method_name) < 0)
    return -1;

  if (safe_append_sp (buf, remaining) < 0)
    return -1;

  target = request->path && request->path[0] ? request->path : "/";
  validate_request_target (target);

  if (safe_append_str (buf, remaining, target) < 0)
    return -1;

  if (safe_append_sp (buf, remaining) < 0)
    return -1;

  version_str = SocketHTTP_version_string (request->version);
  if (!version_str)
    {
      SOCKET_RAISE_MSG (SocketHTTP1, SocketHTTP1_SerializeError,
                        "Unknown HTTP version: %d", (int)request->version);
    }

  if (safe_append_str (buf, remaining, version_str) < 0)
    return -1;

  return safe_append_crlf (buf, remaining);
}

/* ============================================================================
 * Response Line Serialization
 * ============================================================================
 */

/**
 * serialize_response_line - Serialize HTTP response line
 * @response: Response structure
 * @buf: Buffer pointer (updated)
 * @remaining: Remaining space (updated)
 *
 * Serializes: HTTP-Version SP Status-Code SP Reason-Phrase CRLF
 *
 * Returns: 0 on success, -1 if buffer too small
 * Raises: SocketHTTP1_SerializeError on invalid input
 * Thread-safe: Yes
 */
static int
serialize_response_line (const SocketHTTP_Response *response, char **buf,
                         size_t *remaining)
{
  const char *version_str;
  const char *reason;

  if (!SocketHTTP_status_valid (response->status_code))
    {
      SOCKET_RAISE_MSG (SocketHTTP1, SocketHTTP1_SerializeError,
                        "Invalid status code: %d", response->status_code);
    }

  version_str = SocketHTTP_version_string (response->version);
  if (!version_str)
    {
      SOCKET_RAISE_MSG (SocketHTTP1, SocketHTTP1_SerializeError,
                        "Unknown HTTP version: %d", (int)response->version);
    }

  if (safe_append_str (buf, remaining, version_str) < 0)
    return -1;

  if (safe_append_sp (buf, remaining) < 0)
    return -1;

  if (safe_append_int64 (buf, remaining, response->status_code) < 0)
    return -1;

  if (safe_append_sp (buf, remaining) < 0)
    return -1;

  reason = response->reason_phrase && response->reason_phrase[0]
               ? response->reason_phrase
               : SocketHTTP_status_reason (response->status_code);

  if (reason)
    {
      size_t reason_len = strlen (reason);
      if (!SocketHTTP_header_value_valid (reason, reason_len))
        {
          SOCKET_RAISE_MSG (SocketHTTP1, SocketHTTP1_SerializeError,
                            "Invalid reason phrase contains forbidden "
                            "characters (CR/LF/NUL)");
        }
      if (safe_append_str (buf, remaining, reason) < 0)
        return -1;
    }

  return safe_append_crlf (buf, remaining);
}

/* ============================================================================
 * Request Extras (Host Header, Content-Length)
 * ============================================================================
 */

/**
 * add_optional_host_header - Add Host header if missing
 * @request: Request structure
 * @buf: Buffer pointer (updated)
 * @remaining: Remaining space (updated)
 *
 * Adds "Host: authority\r\n" if authority present and no existing Host header.
 *
 * Returns: 0 on success, -1 if buffer too small
 * Thread-safe: Yes
 */
static int
add_optional_host_header (const SocketHTTP_Request *request, char **buf,
                          size_t *remaining)
{
  size_t auth_len;

  if (!request->authority || request->authority[0] == '\0')
    return 0;

  if (request->headers && SocketHTTP_Headers_has (request->headers, "Host"))
    return 0;

  if (safe_append (buf, remaining, HTTP_HOST_PREFIX, HTTP_HOST_PREFIX_LEN) < 0)
    return -1;

  auth_len = strlen (request->authority);
  if (!SocketHTTP_header_value_valid (request->authority, auth_len))
    {
      SOCKET_RAISE_MSG (
          SocketHTTP1, SocketHTTP1_SerializeError,
          "Invalid authority contains forbidden characters (CR/LF/NUL)");
    }

  if (safe_append_str (buf, remaining, request->authority) < 0)
    return -1;

  return safe_append_crlf (buf, remaining);
}

/**
 * add_request_extras - Add post-headers for request
 * @request: Request structure
 * @buf: Buffer pointer (updated)
 * @remaining: Remaining space (updated)
 *
 * Adds Host header (if needed), Content-Length (if needed), and final CRLF.
 *
 * Returns: 0 on success, -1 if buffer too small
 * Thread-safe: Yes
 */
static int
add_request_extras (const SocketHTTP_Request *request, char **buf,
                    size_t *remaining)
{
  if (add_optional_host_header (request, buf, remaining) < 0)
    return -1;

  if (append_content_length_header (buf, remaining, request->headers,
                                    request->has_body, request->content_length)
      < 0)
    return -1;

  return safe_append_crlf (buf, remaining);
}

/**
 * add_response_extras - Add post-headers for response
 * @response: Response structure
 * @buf: Buffer pointer (updated)
 * @remaining: Remaining space (updated)
 *
 * Adds Content-Length (if needed) and final CRLF.
 *
 * Returns: 0 on success, -1 if buffer too small
 * Thread-safe: Yes
 */
static int
add_response_extras (const SocketHTTP_Response *response, char **buf,
                     size_t *remaining)
{
  if (append_content_length_header (buf, remaining, response->headers,
                                    response->has_body,
                                    response->content_length)
      < 0)
    return -1;

  return safe_append_crlf (buf, remaining);
}

/* ============================================================================
 * Public API - Request Serialization
 * ============================================================================
 */

ssize_t
SocketHTTP1_serialize_request (const SocketHTTP_Request *request, char *output,
                               size_t output_size)
{
  char *p;
  size_t remaining;

  assert (request);
  assert (output || output_size == 0);

  if (output_size == 0)
    return -1;

  p = output;
  remaining = output_size - 1; /* Reserve space for null terminator */

  if (serialize_request_line (request, &p, &remaining) < 0)
    return -1;

  if (serialize_headers_section (request->headers, &p, &remaining) < 0)
    return -1;

  if (add_request_extras (request, &p, &remaining) < 0)
    return -1;

  *p = '\0';
  return (ssize_t)(p - output);
}

/* ============================================================================
 * Public API - Response Serialization
 * ============================================================================
 */

ssize_t
SocketHTTP1_serialize_response (const SocketHTTP_Response *response,
                                char *output, size_t output_size)
{
  char *p;
  size_t remaining;

  assert (response);
  assert (output || output_size == 0);

  if (output_size == 0)
    return -1;

  p = output;
  remaining = output_size - 1;

  if (serialize_response_line (response, &p, &remaining) < 0)
    return -1;

  if (serialize_headers_section (response->headers, &p, &remaining) < 0)
    return -1;

  if (add_response_extras (response, &p, &remaining) < 0)
    return -1;

  *p = '\0';
  return (ssize_t)(p - output);
}

/* ============================================================================
 * Public API - Headers-Only Serialization
 * ============================================================================
 */

ssize_t
SocketHTTP1_serialize_headers (SocketHTTP_Headers_T headers, char *output,
                               size_t output_size)
{
  struct serialize_ctx ctx;
  char *start;

  assert (output || output_size == 0);

  if (output_size == 0)
    return -1;

  start = output;
  ctx.buf = output;
  ctx.remaining = output_size - 1;
  ctx.error = 0;

  if (!headers)
    {
      *output = '\0';
      return 0;
    }

  SocketHTTP_Headers_iterate (headers, serialize_header_cb, &ctx);

  if (ctx.error)
    return -1;

  *ctx.buf = '\0';
  return (ssize_t)(ctx.buf - start);
}
