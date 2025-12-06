/**
 * SocketHTTP1-chunked.c - HTTP/1.1 Chunked Transfer Encoding
 *
 * Part of the Socket Library
 *
 * Implements RFC 9112 Section 7.1 chunked transfer coding:
 * - Chunk encoding for requests/responses
 * - Chunk decoding for body reading
 * - Trailer header support
 */

#include "http/SocketHTTP1.h"
#include "http/SocketHTTP1-private.h"
#include "http/SocketHTTP-private.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Chunk Encoding
 * ============================================================================ */

size_t
SocketHTTP1_chunk_encode_size (size_t data_len)
{
  size_t size_chars;

  /* Calculate hex digits needed for size */
  if (data_len == 0)
    {
      size_chars = 1; /* "0" */
    }
  else
    {
      size_t tmp = data_len;
      size_chars = 0;
      while (tmp > 0)
        {
          size_chars++;
          tmp >>= 4;
        }
    }

  /* size_hex + CRLF + data + CRLF */
  return size_chars + 2 + data_len + 2;
}

ssize_t
SocketHTTP1_chunk_encode (const void *data, size_t len, char *output,
                          size_t output_size)
{
  size_t required;
  char *p;
  int hex_len;

  assert (output || output_size == 0);

  required = SocketHTTP1_chunk_encode_size (len);
  if (output_size < required)
    return -1;

  p = output;

  /* Chunk size in hex */
  hex_len = snprintf (p, output_size, "%zx", len);
  if (hex_len < 0)
    return -1;

  p += hex_len;

  /* CRLF after size */
  *p++ = '\r';
  *p++ = '\n';

  /* Chunk data */
  if (len > 0 && data)
    {
      memcpy (p, data, len);
      p += len;
    }

  /* CRLF after data */
  *p++ = '\r';
  *p++ = '\n';

  return (ssize_t)(p - output);
}

ssize_t
SocketHTTP1_chunk_final (char *output, size_t output_size,
                         SocketHTTP_Headers_T trailers)
{
  char *p;
  size_t remaining;

  assert (output || output_size == 0);

  if (output_size < 5) /* "0\r\n\r\n" */
    return -1;

  p = output;
  remaining = output_size;

  /* Zero-length chunk */
  *p++ = '0';
  *p++ = '\r';
  *p++ = '\n';
  remaining -= 3;

  /* Optional trailers */
  if (trailers && SocketHTTP_Headers_count (trailers) > 0)
    {
      ssize_t trailers_len;

      trailers_len = SocketHTTP1_serialize_headers (trailers, p, remaining);
      if (trailers_len < 0)
        return -1;

      p += trailers_len;
      remaining -= (size_t)trailers_len;
    }

  /* Final CRLF */
  if (remaining < 2)
    return -1;

  *p++ = '\r';
  *p++ = '\n';

  return (ssize_t)(p - output);
}

/* ============================================================================
 * Body Reading (Content-Length and Chunked)
 * ============================================================================ */

/**
 * Read body with Content-Length
 */
static SocketHTTP1_Result
read_body_content_length (SocketHTTP1_Parser_T parser, const char *input,
                          size_t input_len, size_t *consumed, char *output,
                          size_t output_len, size_t *written)
{
  size_t to_read;

  *consumed = 0;
  *written = 0;

  if (parser->body_remaining <= 0)
    {
      parser->body_complete = 1;
      parser->state = HTTP1_STATE_COMPLETE;
      parser->internal_state = HTTP1_PS_COMPLETE;
      return HTTP1_OK;
    }

  /* Calculate how much to read */
  to_read = (size_t)parser->body_remaining;
  if (to_read > input_len)
    to_read = input_len;
  if (to_read > output_len)
    to_read = output_len;

  /* Copy data */
  if (to_read > 0)
    {
      memcpy (output, input, to_read);
      *consumed = to_read;
      *written = to_read;
      parser->body_remaining -= (int64_t)to_read;
    }

  if (parser->body_remaining <= 0)
    {
      parser->body_complete = 1;
      parser->state = HTTP1_STATE_COMPLETE;
      parser->internal_state = HTTP1_PS_COMPLETE;
      return HTTP1_OK;
    }

  return HTTP1_INCOMPLETE;
}

/**
 * Read body until connection close (HTTP/1.0 style)
 */
static SocketHTTP1_Result
read_body_until_close (SocketHTTP1_Parser_T parser, const char *input,
                       size_t input_len, size_t *consumed, char *output,
                       size_t output_len, size_t *written)
{
  size_t to_read;

  (void)parser; /* Unused - body mode determined, just copy data */

  *consumed = 0;
  *written = 0;

  /* Read as much as possible */
  to_read = input_len;
  if (to_read > output_len)
    to_read = output_len;

  if (to_read > 0)
    {
      memcpy (output, input, to_read);
      *consumed = to_read;
      *written = to_read;
    }

  /* Never complete until connection closes */
  return HTTP1_INCOMPLETE;
}

/**
 * Parse chunk size line
 * Returns: Size on success, -1 on error, -2 if incomplete
 */
static int64_t
parse_chunk_size (const char *input, size_t len, size_t *line_len)
{
  const char *p = input;
  const char *end = input + len;
  uint64_t size = 0;
  int has_digit = 0;

  *line_len = 0;

  /* Parse hex digits */
  while (p < end && http1_is_hex (*p))
    {
      uint64_t digit = (uint64_t)http1_hex_value (*p);

      /* Check overflow */
      if (size > (UINT64_MAX - digit) / 16)
        return -1;

      size = size * 16 + digit;
      has_digit = 1;
      p++;
    }

  if (!has_digit)
    return -1; /* No digits */

  /* Skip chunk extension (semicolon followed by anything until CRLF) */
  if (p < end && *p == ';')
    {
      while (p < end && *p != '\r' && *p != '\n')
        p++;
    }

  /* Expect CRLF */
  if (p >= end)
    return -2; /* Incomplete */

  if (*p == '\r')
    {
      p++;
      if (p >= end)
        return -2;
      if (*p != '\n')
        return -1; /* Invalid */
      p++;
    }
  else if (*p == '\n')
    {
      /* Bare LF - lenient */
      p++;
    }
  else
    {
      return -1; /* Invalid */
    }

  *line_len = (size_t)(p - input);

  /* Check size limit */
  if (size > SIZE_MAX)
    return -1;

  return (int64_t)size;
}

/**
 * Read chunked body
 */
static SocketHTTP1_Result
read_body_chunked (SocketHTTP1_Parser_T parser, const char *input,
                   size_t input_len, size_t *consumed, char *output,
                   size_t output_len, size_t *written)
{
  const char *p = input;
  const char *end = input + input_len;
  char *out = output;
  size_t out_remaining = output_len;
  int64_t chunk_size;
  size_t line_len;

  *consumed = 0;
  *written = 0;

  while (p < end && out_remaining > 0)
    {
      switch (parser->internal_state)
        {
        case HTTP1_PS_CHUNK_SIZE:
          /* Parse chunk size */
          chunk_size = parse_chunk_size (p, (size_t)(end - p), &line_len);

          if (chunk_size == -2)
            {
              /* Incomplete - need more data */
              *consumed = (size_t)(p - input);
              *written = (size_t)(out - output);
              return HTTP1_INCOMPLETE;
            }

          if (chunk_size == -1)
            {
              return HTTP1_ERROR_INVALID_CHUNK_SIZE;
            }

          p += line_len;
          parser->chunk_size = (size_t)chunk_size;
          parser->chunk_remaining = (size_t)chunk_size;

          if (chunk_size == 0)
            {
              /* Last chunk - expect trailers or final CRLF */
              parser->internal_state = HTTP1_PS_TRAILER_START;
              parser->state = HTTP1_STATE_TRAILERS;
            }
          else
            {
              /* Check chunk size limit */
              if ((size_t)chunk_size > parser->config.max_chunk_size)
                {
                  return HTTP1_ERROR_CHUNK_TOO_LARGE;
                }
              parser->internal_state = HTTP1_PS_CHUNK_DATA;
              parser->state = HTTP1_STATE_CHUNK_DATA;
            }
          break;

        case HTTP1_PS_CHUNK_DATA:
          {
            size_t to_read = parser->chunk_remaining;
            if (to_read > (size_t)(end - p))
              to_read = (size_t)(end - p);
            if (to_read > out_remaining)
              to_read = out_remaining;

            if (to_read > 0)
              {
                memcpy (out, p, to_read);
                p += to_read;
                out += to_read;
                out_remaining -= to_read;
                parser->chunk_remaining -= to_read;
              }

            if (parser->chunk_remaining == 0)
              {
                parser->internal_state = HTTP1_PS_CHUNK_DATA_CR;
              }
            else
              {
                /* Need more data or output space */
                *consumed = (size_t)(p - input);
                *written = (size_t)(out - output);
                return HTTP1_INCOMPLETE;
              }
          }
          break;

        case HTTP1_PS_CHUNK_DATA_CR:
          if (*p == '\r')
            {
              p++;
              parser->internal_state = HTTP1_PS_CHUNK_DATA_LF;
            }
          else if (*p == '\n')
            {
              /* Bare LF - lenient */
              p++;
              parser->internal_state = HTTP1_PS_CHUNK_SIZE;
              parser->state = HTTP1_STATE_CHUNK_SIZE;
            }
          else
            {
              return HTTP1_ERROR_INVALID_CHUNK_SIZE;
            }
          break;

        case HTTP1_PS_CHUNK_DATA_LF:
          if (*p != '\n')
            {
              return HTTP1_ERROR_INVALID_CHUNK_SIZE;
            }
          p++;
          parser->internal_state = HTTP1_PS_CHUNK_SIZE;
          parser->state = HTTP1_STATE_CHUNK_SIZE;
          break;

        case HTTP1_PS_TRAILER_START:
          /* Check for empty line (end of trailers) or trailer header */
          if (*p == '\r')
            {
              p++;
              parser->internal_state = HTTP1_PS_TRAILERS_END_LF;
            }
          else if (*p == '\n')
            {
              /* Bare LF - end of message */
              p++;
              parser->body_complete = 1;
              parser->state = HTTP1_STATE_COMPLETE;
              parser->internal_state = HTTP1_PS_COMPLETE;
              *consumed = (size_t)(p - input);
              *written = (size_t)(out - output);
              return HTTP1_OK;
            }
          else if (http1_is_tchar (*p))
            {
              /* Trailer header - skip for now (simplified) */
              /* A full implementation would parse trailers like headers */
              while (p < end && *p != '\n')
                p++;
              if (p < end)
                p++; /* Skip LF */
            }
          else
            {
              return HTTP1_ERROR_INVALID_TRAILER;
            }
          break;

        case HTTP1_PS_TRAILERS_END_LF:
          if (*p != '\n')
            {
              return HTTP1_ERROR_INVALID_TRAILER;
            }
          p++;
          parser->body_complete = 1;
          parser->state = HTTP1_STATE_COMPLETE;
          parser->internal_state = HTTP1_PS_COMPLETE;
          *consumed = (size_t)(p - input);
          *written = (size_t)(out - output);
          return HTTP1_OK;

        case HTTP1_PS_COMPLETE:
          *consumed = (size_t)(p - input);
          *written = (size_t)(out - output);
          return HTTP1_OK;

        default:
          return HTTP1_ERROR;
        }
    }

  *consumed = (size_t)(p - input);
  *written = (size_t)(out - output);

  if (parser->body_complete)
    return HTTP1_OK;

  return HTTP1_INCOMPLETE;
}

/* ============================================================================
 * Public Body Reading API
 * ============================================================================ */

SocketHTTP1_Result
SocketHTTP1_Parser_read_body (SocketHTTP1_Parser_T parser, const char *input,
                              size_t input_len, size_t *consumed, char *output,
                              size_t output_len, size_t *written)
{
  assert (parser);
  assert (input || input_len == 0);
  assert (consumed);
  assert (output || output_len == 0);
  assert (written);

  *consumed = 0;
  *written = 0;

  /* Check if body is already complete */
  if (parser->body_complete)
    {
      return HTTP1_OK;
    }

  /* Check if we're in error state */
  if (parser->state == HTTP1_STATE_ERROR)
    {
      return parser->error;
    }

  switch (parser->body_mode)
    {
    case HTTP1_BODY_NONE:
      parser->body_complete = 1;
      parser->state = HTTP1_STATE_COMPLETE;
      parser->internal_state = HTTP1_PS_COMPLETE;
      return HTTP1_OK;

    case HTTP1_BODY_CONTENT_LENGTH:
      return read_body_content_length (parser, input, input_len, consumed,
                                       output, output_len, written);

    case HTTP1_BODY_CHUNKED:
      return read_body_chunked (parser, input, input_len, consumed, output,
                                output_len, written);

    case HTTP1_BODY_UNTIL_CLOSE:
      return read_body_until_close (parser, input, input_len, consumed, output,
                                    output_len, written);

    default:
      return HTTP1_ERROR;
    }
}

