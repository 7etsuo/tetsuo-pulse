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

#include "core/SocketUtil.h"

SOCKET_DECLARE_MODULE_EXCEPTION(SocketHTTP1);

const Except_T SocketHTTP1_SerializeError
    = { &SocketHTTP1_SerializeError, "HTTP/1.1 serialize error" };

/* HTTP serialization constants */
#define HTTP_SP " "
#define HTTP_SP_LEN 1
#define HTTP_CRLF "\r\n"
#define HTTP_CRLF_LEN 2
#define HTTP_HOST_PREFIX "Host: "
#define HTTP_HOST_PREFIX_LEN 6
#define HTTP_CONTENT_LENGTH_PREFIX "Content-Length: "
#define HTTP_CONTENT_LENGTH_PREFIX_LEN 16

#define HTTP_HEADER_SEP ": "
#define HTTP_HEADER_SEP_LEN 2

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/**
 * safe_append - Safely append string to buffer
 * @buf: Buffer pointer (updated)
 * @remaining: Remaining space (updated)
 * @str: String to append
 * @len: String length
 *
 * Returns: 0 on success, -1 if buffer too small
 * Thread-safe: Yes
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
 * safe_append_str - Safely append null-terminated string
 * @buf: Buffer pointer (updated)
 * @remaining: Remaining space (updated)
 * @str: String to append
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
 * safe_append_int - Append integer as decimal string
 * @buf: Buffer pointer (updated)
 * @remaining: Remaining space (updated)
 * @value: Integer to append
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: Yes
 */
static int
safe_append_int (char **buf, size_t *remaining, int value)
{
  char num[SOCKETHTTP1_INT_STRING_BUFSIZE];
  int len;

  len = snprintf (num, sizeof (num), "%d", value);
  if (len < 0 || (size_t)len >= sizeof (num))
    return -1;

  return safe_append (buf, remaining, num, (size_t)len);
}

/**
 * append_content_length_header - Append Content-Length header if needed
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
  char num_buf[SOCKETHTTP1_INT_STRING_BUFSIZE];
  int num_len;

  if (!has_body || content_length < 0)
    return 0;

  if (headers && (SocketHTTP_Headers_has (headers, "Content-Length")
                  || SocketHTTP_Headers_has (headers, "Transfer-Encoding")))
    return 0;

  if (safe_append (buf, remaining, HTTP_CONTENT_LENGTH_PREFIX, HTTP_CONTENT_LENGTH_PREFIX_LEN) < 0)
    return -1;

  num_len = snprintf (num_buf, sizeof (num_buf), "%lld", (long long)content_length);
  if (num_len < 0 || (size_t)num_len >= sizeof (num_buf))
    return -1;

  if (safe_append (buf, remaining, num_buf, (size_t)num_len) < 0)
    return -1;

  return safe_append_crlf (buf, remaining);
}

/* ============================================================================
 * Request Serialization
 * ============================================================================ */

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
add_optional_host_header (const SocketHTTP_Request *request, char **buf, size_t *remaining)
{
  if (!request->authority || request->authority[0] == '\0')
    return 0;

  if (request->headers && SocketHTTP_Headers_has (request->headers, "Host"))
    return 0;

  if (safe_append (buf, remaining, HTTP_HOST_PREFIX, HTTP_HOST_PREFIX_LEN) < 0)
    return -1;

  {
    size_t auth_len = strlen(request->authority);
    if (!SocketHTTP_header_value_valid(request->authority, auth_len)) {
      SOCKET_RAISE_MSG (SocketHTTP1, SocketHTTP1_SerializeError,
                        "Invalid authority contains forbidden characters (CR/LF/NUL)");
    }
  }

  if (safe_append_str (buf, remaining, request->authority) < 0)
    return -1;

  return safe_append_crlf (buf, remaining);
}

/**
 * add_response_extras - Add post-headers for response (Content-Length, final CRLF)
 * @response: Response structure
 * @buf: Buffer pointer (updated)
 * @remaining: Remaining space (updated)
 *
 * Returns: 0 on success, -1 if buffer too small
 * Thread-safe: Yes
 */
static int
add_response_extras (const SocketHTTP_Response *response, char **buf, size_t *remaining)
{
  if (append_content_length_header (buf, remaining, response->headers,
                                    response->has_body, response->content_length) < 0)
    return -1;

  return safe_append_crlf (buf, remaining);
}

/**
 * add_request_extras - Add post-headers for request (Host, Content-Length, final CRLF)
 * @request: Request structure
 * @buf: Buffer pointer (updated)
 * @remaining: Remaining space (updated)
 *
 * Returns: 0 on success, -1 if buffer too small
 * Thread-safe: Yes
 */
static int
add_request_extras (const SocketHTTP_Request *request, char **buf, size_t *remaining)
{
  if (add_optional_host_header (request, buf, remaining) < 0)
    return -1;

  if (append_content_length_header (buf, remaining, request->headers,
                                    request->has_body, request->content_length) < 0)
    return -1;

  return safe_append_crlf (buf, remaining);
}

/**
 * serialize_request_line - Serialize request line
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
serialize_request_line (const SocketHTTP_Request *request, char **buf, size_t *remaining)
{
  const char *method_name;
  const char *version_str;
  const char *target;

  method_name = SocketHTTP_method_name (request->method);
  if (!method_name) {
    SOCKET_RAISE_MSG (SocketHTTP1, SocketHTTP1_SerializeError,
                      "Unknown HTTP method: %d", (int)request->method);
  }

  if (safe_append_str (buf, remaining, method_name) < 0)
    return -1;

  if (safe_append (buf, remaining, HTTP_SP, HTTP_SP_LEN) < 0)
    return -1;

  target = request->path && request->path[0] ? request->path : "/";

  {
    size_t target_len = strlen(target);
    if (!SocketHTTP_header_value_valid(target, target_len)) {
      SOCKET_RAISE_MSG (SocketHTTP1, SocketHTTP1_SerializeError,
                        "Invalid request target contains forbidden characters (CR/LF/NUL)");
    }
  }

  if (safe_append_str (buf, remaining, target) < 0)
    return -1;

  if (safe_append (buf, remaining, HTTP_SP, HTTP_SP_LEN) < 0)
    return -1;

  version_str = SocketHTTP_version_string (request->version);
  if (!version_str) {
    SOCKET_RAISE_MSG (SocketHTTP1, SocketHTTP1_SerializeError,
                      "Unknown HTTP version: %d", (int)request->version);
  }

  if (safe_append_str (buf, remaining, version_str) < 0)
    return -1;

  return safe_append_crlf (buf, remaining);
}

static int
serialize_headers_section (const SocketHTTP_Headers_T headers, char **buf, size_t *remaining);

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

  /* Request line */
  if (serialize_request_line (request, &p, &remaining) < 0)
    return -1;

  /* Headers */
  if (serialize_headers_section (request->headers, &p, &remaining) < 0)
    return -1;

  /* Post-headers extras (Host, Content-Length, final CRLF) */
  if (add_request_extras (request, &p, &remaining) < 0)
    return -1;

  /* Null terminate */
  *p = '\0';

  return (ssize_t)(p - output);
}



/* ============================================================================
 * Response Serialization
 * ============================================================================ */

/**
 * serialize_response_line - Serialize response line
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
serialize_response_line (const SocketHTTP_Response *response, char **buf, size_t *remaining)
{
  const char *version_str;
  const char *reason;

  if (!SocketHTTP_status_valid (response->status_code)) {
    SOCKET_RAISE_MSG (SocketHTTP1, SocketHTTP1_SerializeError,
                      "Invalid status code: %d", response->status_code);
  }

  version_str = SocketHTTP_version_string (response->version);
  if (!version_str) {
    SOCKET_RAISE_MSG (SocketHTTP1, SocketHTTP1_SerializeError,
                      "Unknown HTTP version: %d", (int)response->version);
  }

  if (safe_append_str (buf, remaining, version_str) < 0)
    return -1;

  if (safe_append (buf, remaining, HTTP_SP, HTTP_SP_LEN) < 0)
    return -1;

  if (safe_append_int (buf, remaining, response->status_code) < 0)
    return -1;

  if (safe_append (buf, remaining, HTTP_SP, HTTP_SP_LEN) < 0)
    return -1;

  reason = response->reason_phrase && response->reason_phrase[0] ?
    response->reason_phrase : SocketHTTP_status_reason (response->status_code);

  if (reason) {
    size_t reason_len = strlen(reason);
    if (!SocketHTTP_header_value_valid(reason, reason_len)) {
      SOCKET_RAISE_MSG (SocketHTTP1, SocketHTTP1_SerializeError,
                        "Invalid reason phrase contains forbidden characters (CR/LF/NUL)");
    }
    if (safe_append_str (buf, remaining, reason) < 0)
      return -1;
  }

  return safe_append_crlf (buf, remaining);
}

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

  /* Response line */
  if (serialize_response_line (response, &p, &remaining) < 0)
    return -1;

  /* Headers */
  if (serialize_headers_section (response->headers, &p, &remaining) < 0)
    return -1;

  /* Post-headers extras (Content-Length, final CRLF) */
  if (add_response_extras (response, &p, &remaining) < 0)
    return -1;

  /* Null terminate */
  *p = '\0';

  return (ssize_t)(p - output);
}

/* ============================================================================
 * Header Serialization
 * ============================================================================ */

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
 * serialize_header_cb - Callback for iterating headers during serialization
 * @name: Header name
 * @name_len: Header name length
 * @value: Header value
 * @value_len: Header value length
 * @userdata: serialize_ctx pointer
 *
 * Returns: 0 to continue, 1 to stop
 */
static int
serialize_header_cb (const char *name, size_t name_len, const char *value,
                     size_t value_len, void *userdata)
{
  struct serialize_ctx *ctx = userdata;

  if (!SocketHTTP_header_name_valid (name, name_len)
      || !SocketHTTP_header_value_valid (value, value_len)) {
    SOCKET_RAISE_MSG (SocketHTTP1, SocketHTTP1_SerializeError,
                      "Invalid header name or value");
  }

  /* Name */
  if (safe_append (&ctx->buf, &ctx->remaining, name, name_len) < 0)
    {
      ctx->error = 1;
      return 1; /* Stop iteration */
    }

  /* ": " */
  if (safe_append (&ctx->buf, &ctx->remaining, HTTP_HEADER_SEP, HTTP_HEADER_SEP_LEN) < 0)
    {
      ctx->error = 1;
      return 1;
    }

  /* Value */
  if (safe_append (&ctx->buf, &ctx->remaining, value, value_len) < 0)
    {
      ctx->error = 1;
      return 1;
    }

  /* CRLF */
  if (safe_append_crlf (&ctx->buf, &ctx->remaining) < 0)
    {
      ctx->error = 1;
      return 1;
    }

  return 0; /* Continue */
}

/**
 * do_serialize_headers - Common headers iteration logic
 * @headers: Headers to iterate
 * @ctx: Serialization context
 *
 * Performs iteration and checks error. Handles NULL headers safely.
 *
 * Returns: 0 on success, -1 on error
 * Thread-safe: Yes
 */
static int
do_serialize_headers (const SocketHTTP_Headers_T headers, struct serialize_ctx *ctx)
{
  if (!headers)
    return 0;

  SocketHTTP_Headers_iterate (headers, serialize_header_cb, ctx);
  return ctx->error ? -1 : 0;
}



static int
serialize_headers_section (const SocketHTTP_Headers_T headers, char **buf, size_t *remaining)
{
  struct serialize_ctx ctx = {0};
  ctx.buf = *buf;
  ctx.remaining = *remaining;
  ctx.error = 0;
  if (do_serialize_headers (headers, &ctx) < 0)
    return -1;
  *buf = ctx.buf;
  *remaining = ctx.remaining;
  return 0;
}

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
  ctx.remaining = output_size > 0 ? output_size - 1 : 0;
  ctx.error = 0;

  if (do_serialize_headers (headers, &ctx) < 0)
    return -1;

  /* Null terminate */
  *ctx.buf = '\0';

  return (ssize_t)(ctx.buf - start);
}
