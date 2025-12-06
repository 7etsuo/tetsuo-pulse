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

#include "http/SocketHTTP1.h"
#include "http/SocketHTTP1-private.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

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
 */
static int
safe_append_str (char **buf, size_t *remaining, const char *str)
{
  return safe_append (buf, remaining, str, strlen (str));
}

/**
 * safe_append_crlf - Append CRLF
 */
static int
safe_append_crlf (char **buf, size_t *remaining)
{
  return safe_append (buf, remaining, "\r\n", 2);
}

/**
 * safe_append_int - Append integer as decimal
 */
static int
safe_append_int (char **buf, size_t *remaining, int value)
{
  char num[16];
  int len;

  len = snprintf (num, sizeof (num), "%d", value);
  if (len < 0 || (size_t)len >= sizeof (num))
    return -1;

  return safe_append (buf, remaining, num, (size_t)len);
}

/* ============================================================================
 * Request Serialization
 * ============================================================================ */

ssize_t
SocketHTTP1_serialize_request (const SocketHTTP_Request *request, char *output,
                               size_t output_size)
{
  char *p;
  size_t remaining;
  const char *method_name;
  const char *version_str;

  assert (request);
  assert (output || output_size == 0);

  if (output_size == 0)
    return -1;

  p = output;
  remaining = output_size - 1; /* Reserve space for null terminator */

  /* Method */
  method_name = SocketHTTP_method_name (request->method);
  if (!method_name)
    method_name = "GET"; /* Default */

  if (safe_append_str (&p, &remaining, method_name) < 0)
    return -1;

  /* SP */
  if (safe_append (&p, &remaining, " ", 1) < 0)
    return -1;

  /* Request-Target */
  if (request->path && request->path[0])
    {
      if (safe_append_str (&p, &remaining, request->path) < 0)
        return -1;
    }
  else
    {
      /* Default to "/" */
      if (safe_append (&p, &remaining, "/", 1) < 0)
        return -1;
    }

  /* SP */
  if (safe_append (&p, &remaining, " ", 1) < 0)
    return -1;

  /* HTTP-Version */
  version_str = SocketHTTP_version_string (request->version);
  if (safe_append_str (&p, &remaining, version_str) < 0)
    return -1;

  /* CRLF */
  if (safe_append_crlf (&p, &remaining) < 0)
    return -1;

  /* Headers */
  if (request->headers)
    {
      ssize_t headers_len;

      headers_len = SocketHTTP1_serialize_headers (request->headers, p,
                                                   remaining + 1);
      if (headers_len < 0)
        return -1;

      p += headers_len;
      remaining -= (size_t)headers_len;
    }

  /* Add Host header if not present and authority is available */
  if (request->authority && request->authority[0])
    {
      if (!request->headers
          || !SocketHTTP_Headers_has (request->headers, "Host"))
        {
          if (safe_append_str (&p, &remaining, "Host: ") < 0)
            return -1;
          if (safe_append_str (&p, &remaining, request->authority) < 0)
            return -1;
          if (safe_append_crlf (&p, &remaining) < 0)
            return -1;
        }
    }

  /* Add Content-Length if body present and not chunked */
  if (request->has_body && request->content_length >= 0)
    {
      if (!request->headers
          || (!SocketHTTP_Headers_has (request->headers, "Content-Length")
              && !SocketHTTP_Headers_has (request->headers,
                                          "Transfer-Encoding")))
        {
          char cl_buf[32];
          int cl_len;

          cl_len = snprintf (cl_buf, sizeof (cl_buf), "Content-Length: %lld",
                             (long long)request->content_length);
          if (cl_len < 0 || (size_t)cl_len >= sizeof (cl_buf))
            return -1;

          if (safe_append (&p, &remaining, cl_buf, (size_t)cl_len) < 0)
            return -1;
          if (safe_append_crlf (&p, &remaining) < 0)
            return -1;
        }
    }

  /* Final CRLF */
  if (safe_append_crlf (&p, &remaining) < 0)
    return -1;

  /* Null terminate */
  *p = '\0';

  return (ssize_t)(p - output);
}

/* ============================================================================
 * Response Serialization
 * ============================================================================ */

ssize_t
SocketHTTP1_serialize_response (const SocketHTTP_Response *response,
                                char *output, size_t output_size)
{
  char *p;
  size_t remaining;
  const char *version_str;
  const char *reason;

  assert (response);
  assert (output || output_size == 0);

  if (output_size == 0)
    return -1;

  p = output;
  remaining = output_size - 1;

  /* HTTP-Version */
  version_str = SocketHTTP_version_string (response->version);
  if (safe_append_str (&p, &remaining, version_str) < 0)
    return -1;

  /* SP */
  if (safe_append (&p, &remaining, " ", 1) < 0)
    return -1;

  /* Status-Code */
  if (safe_append_int (&p, &remaining, response->status_code) < 0)
    return -1;

  /* SP */
  if (safe_append (&p, &remaining, " ", 1) < 0)
    return -1;

  /* Reason-Phrase */
  reason = response->reason_phrase;
  if (!reason || !reason[0])
    {
      reason = SocketHTTP_status_reason (response->status_code);
    }
  if (reason)
    {
      if (safe_append_str (&p, &remaining, reason) < 0)
        return -1;
    }

  /* CRLF */
  if (safe_append_crlf (&p, &remaining) < 0)
    return -1;

  /* Headers */
  if (response->headers)
    {
      ssize_t headers_len;

      headers_len = SocketHTTP1_serialize_headers (response->headers, p,
                                                   remaining + 1);
      if (headers_len < 0)
        return -1;

      p += headers_len;
      remaining -= (size_t)headers_len;
    }

  /* Add Content-Length if body present */
  if (response->has_body && response->content_length >= 0)
    {
      if (!response->headers
          || (!SocketHTTP_Headers_has (response->headers, "Content-Length")
              && !SocketHTTP_Headers_has (response->headers,
                                          "Transfer-Encoding")))
        {
          char cl_buf[32];
          int cl_len;

          cl_len = snprintf (cl_buf, sizeof (cl_buf), "Content-Length: %lld",
                             (long long)response->content_length);
          if (cl_len < 0 || (size_t)cl_len >= sizeof (cl_buf))
            return -1;

          if (safe_append (&p, &remaining, cl_buf, (size_t)cl_len) < 0)
            return -1;
          if (safe_append_crlf (&p, &remaining) < 0)
            return -1;
        }
    }

  /* Final CRLF */
  if (safe_append_crlf (&p, &remaining) < 0)
    return -1;

  /* Null terminate */
  *p = '\0';

  return (ssize_t)(p - output);
}

/* ============================================================================
 * Header Serialization
 * ============================================================================ */

/**
 * Header serialization callback
 */
struct serialize_ctx
{
  char *buf;
  size_t remaining;
  int error;
};

static int
serialize_header_cb (const char *name, size_t name_len, const char *value,
                     size_t value_len, void *userdata)
{
  struct serialize_ctx *ctx = userdata;

  /* Name */
  if (safe_append (&ctx->buf, &ctx->remaining, name, name_len) < 0)
    {
      ctx->error = 1;
      return 1; /* Stop iteration */
    }

  /* ": " */
  if (safe_append (&ctx->buf, &ctx->remaining, ": ", 2) < 0)
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

ssize_t
SocketHTTP1_serialize_headers (SocketHTTP_Headers_T headers, char *output,
                               size_t output_size)
{
  struct serialize_ctx ctx;
  char *start;

  assert (output || output_size == 0);

  if (output_size == 0)
    return -1;

  if (!headers || SocketHTTP_Headers_count (headers) == 0)
    {
      output[0] = '\0';
      return 0;
    }

  start = output;
  ctx.buf = output;
  ctx.remaining = output_size - 1;
  ctx.error = 0;

  SocketHTTP_Headers_iterate (headers, serialize_header_cb, &ctx);

  if (ctx.error)
    return -1;

  /* Null terminate */
  *ctx.buf = '\0';

  return (ssize_t)(ctx.buf - start);
}

