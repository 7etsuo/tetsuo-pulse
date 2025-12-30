/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* SocketHTTP1-chunked.c - HTTP/1.1 Chunked Transfer Encoding (RFC 9112 Section 7.1) */

#include "http/SocketHTTP1-private.h"
#include "http/SocketHTTP1.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const unsigned char HTTP1_CRLF_BYTES[HTTP1_CRLF_LEN] = { '\r', '\n' };

/** Zero chunk size line "0\r\n" as byte array (not null-terminated - wire
 * format) */
static const unsigned char HTTP1_ZERO_CHUNK_BYTES[3] = { '0', '\r', '\n' };
#define HTTP1_ZERO_CHUNK_SIZE_LINE_LEN 3

/** Minimum buffer size for final zero chunk + final CRLF (no trailers) */
#define HTTP1_FINAL_CHUNK_MIN_SIZE                                            \
  (HTTP1_ZERO_CHUNK_SIZE_LINE_LEN + HTTP1_CRLF_LEN)

/* Note: HTTP1_CRLF_LEN and HTTP1_HEX_RADIX defined in SocketHTTP1-private.h */

/**
 * Forbidden trailer header names with pre-computed lengths.
 * Per RFC 9110 Section 6.5.1, certain headers MUST NOT appear in trailers.
 */
static const struct
{
  const char *name;
  size_t len;
} forbidden_trailers[] = {
  { "transfer-encoding", 17 },
  { "content-length", 14 },
  { "trailer", 7 },
};

/** Number of forbidden trailer headers */
#define HTTP1_NUM_FORBIDDEN_TRAILERS                                          \
  (sizeof (forbidden_trailers) / sizeof (forbidden_trailers[0]))

static int
is_forbidden_trailer (const char *name, size_t name_len)
{
  if (!name || name_len == 0)
    return 0;

  for (size_t i = 0; i < HTTP1_NUM_FORBIDDEN_TRAILERS; i++)
    {
      if (name_len == forbidden_trailers[i].len
          && strncasecmp (name, forbidden_trailers[i].name, name_len) == 0)
        return 1;
    }

  return 0;
}

static inline void
mark_body_complete (SocketHTTP1_Parser_T parser)
{
  parser->body_complete = 1;
  parser->state = HTTP1_STATE_COMPLETE;
  parser->internal_state = HTTP1_PS_COMPLETE;
}

static SocketHTTP1_Result
complete_trailer_header (SocketHTTP1_Parser_T parser)
{
  /* Terminate value buffer */
  char *value = http1_tokenbuf_terminate (&parser->value_buf, parser->arena,
                                          parser->config.max_header_value);
  if (value == NULL)
    return HTTP1_ERROR_HEADER_TOO_LARGE;

  /* Get name from parser buffer */
  const char *trailer_name = parser->name_buf.data;
  if (trailer_name == NULL)
    return HTTP1_ERROR_HEADER_TOO_LARGE;

  /* Calculate entry size for limit enforcement */
  size_t trailer_name_len = parser->name_buf.len;

  /* Check forbidden trailers per RFC 9110 Section 6.5.1 */
  if (is_forbidden_trailer (trailer_name, trailer_name_len))
    return HTTP1_ERROR_INVALID_TRAILER;
  size_t value_len = parser->value_buf.len;

  /**
   * Calculate entry size for limit enforcement using configurable overhead.
   * The overhead accounts for HeaderEntry struct, null terminators, and
   * wire format delimiters (see SOCKETHTTP1_TRAILER_ENTRY_OVERHEAD docs).
   */
  size_t entry_size = trailer_name_len + value_len
                      + parser->config.trailer_entry_overhead;

  /* Check trailer limits */
  if (parser->trailer_count >= parser->config.max_headers
      || parser->total_trailer_size + entry_size
             > parser->config.max_trailer_size)
    return HTTP1_ERROR_HEADER_TOO_LARGE;

  /* Add to trailers collection */
  if (SocketHTTP_Headers_add (parser->trailers, trailer_name, value) < 0)
    return HTTP1_ERROR_HEADER_TOO_LARGE;

  /* Update counters */
  parser->trailer_count++;
  parser->total_trailer_size += entry_size;

  /* Reset for next header */
  http1_tokenbuf_reset (&parser->name_buf);
  http1_tokenbuf_reset (&parser->value_buf);
  parser->internal_state = HTTP1_PS_TRAILER_START;
  parser->line_length = 0;

  return HTTP1_OK;
}

static size_t
copy_data (const char **input_pos, const char *input_end, char **output_pos,
           size_t *output_remaining, size_t max_bytes)
{
  size_t input_avail = (size_t)(input_end - *input_pos);
  size_t to_copy = max_bytes;
  if (to_copy > input_avail)
    to_copy = input_avail;
  if (to_copy > *output_remaining)
    to_copy = *output_remaining;

  if (to_copy > 0)
    {
      memcpy (*output_pos, *input_pos, to_copy);
      *input_pos += to_copy;
      *output_pos += to_copy;
      *output_remaining -= to_copy;
    }

  return to_copy;
}

static inline void
update_progress (const char *const input_start, const char *const input_pos,
                 const char *const output_start, const char *const output_pos,
                 size_t *consumed, size_t *written)
{
  *consumed = (size_t)(input_pos - input_start);
  *written = (size_t)(output_pos - output_start);
}

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
  return size_chars + HTTP1_CRLF_LEN + data_len + HTTP1_CRLF_LEN;
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
  memcpy (p, HTTP1_CRLF_BYTES, HTTP1_CRLF_LEN);
  p += HTTP1_CRLF_LEN;

  /* Chunk data */
  if (len > 0 && data)
    {
      memcpy (p, data, len);
      p += len;
    }

  /* CRLF after data */
  memcpy (p, HTTP1_CRLF_BYTES, HTTP1_CRLF_LEN);
  p += HTTP1_CRLF_LEN;

  return (ssize_t)(p - output);
}

ssize_t
SocketHTTP1_chunk_final (char *output, size_t output_size,
                         SocketHTTP_Headers_T trailers)
{
  char *p;
  size_t remaining;

  assert (output || output_size == 0);

  if (output_size < HTTP1_FINAL_CHUNK_MIN_SIZE)
    return -1;

  p = output;
  remaining = output_size;

  /* Zero-length chunk */
  memcpy (p, HTTP1_ZERO_CHUNK_BYTES, HTTP1_ZERO_CHUNK_SIZE_LINE_LEN);
  p += HTTP1_ZERO_CHUNK_SIZE_LINE_LEN;
  remaining -= HTTP1_ZERO_CHUNK_SIZE_LINE_LEN;

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
  if (remaining < HTTP1_CRLF_LEN)
    return -1;

  memcpy (p, HTTP1_CRLF_BYTES, HTTP1_CRLF_LEN);
  p += HTTP1_CRLF_LEN;

  return (ssize_t)(p - output);
}

static SocketHTTP1_Result
read_body_content_length (SocketHTTP1_Parser_T parser, const char *const input,
                          size_t input_len, size_t *consumed, char *output,
                          size_t output_len, size_t *written)
{
  *consumed = 0;
  *written = 0;

  if (parser->body_remaining <= 0)
    {
      mark_body_complete (parser);
      return HTTP1_OK;
    }

  size_t max_copy = (size_t)parser->body_remaining;
  const char *input_pos = input;
  size_t copied = copy_data (&input_pos, input + input_len, &output,
                             &output_len, max_copy);
  *consumed = copied;
  *written = copied;
  parser->body_remaining -= (int64_t)copied;

  if (parser->body_remaining <= 0)
    {
      mark_body_complete (parser);
      return HTTP1_OK;
    }

  return HTTP1_INCOMPLETE;
}

static SocketHTTP1_Result
read_body_until_close (SocketHTTP1_Parser_T parser, const char *const input,
                       size_t input_len, size_t *consumed, char *output,
                       size_t output_len, size_t *written)
{
  /* Parser unused - body mode determined, just copy data */
  (void)parser;

  const char *input_pos = input;
  size_t copied = copy_data (&input_pos, input + input_len, &output,
                             &output_len, input_len);
  *consumed = copied;
  *written = copied;

  /* Never complete until connection closes */
  return HTTP1_INCOMPLETE;
}

static int64_t
parse_chunk_size (const char *const input, size_t len, size_t *line_len,
                  size_t max_ext_len)
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
      uint64_t new_size;

      /* Check overflow using compiler built-ins */
      if (__builtin_mul_overflow (size, HTTP1_HEX_RADIX, &new_size)
          || __builtin_add_overflow (new_size, digit, &size))
        return -1;

      has_digit = 1;
      p++;
    }

  if (!has_digit)
    return -1; /* No digits found */

  /* Skip chunk extension (semicolon followed by anything until CRLF) */
  size_t ext_len = 0;
  if (p < end && *p == ';')
    {
      p++;
      ext_len = 1;
      while (p < end && *p != '\r' && *p != '\n')
        {
          ext_len++;
          if (ext_len > max_ext_len)
            return -1; /* Extension too long */
          p++;
        }
    }

  HTTP1_CRLFResult res = http1_skip_crlf (&p, end);
  if (res == HTTP1_CRLF_INCOMPLETE)
    return -2;
  if (res != HTTP1_CRLF_OK)
    return -1;

  *line_len = (size_t)(p - input);

  /* SECURITY: Validate size fits in int64_t before cast to prevent overflow */
  if (size > (uint64_t)INT64_MAX)
    return -1;

  return (int64_t)size;
}

static SocketHTTP1_Result
handle_chunk_size_state (SocketHTTP1_Parser_T parser, const char **p,
                         const char *end)
{
  int64_t chunk_size;
  size_t line_len;

  chunk_size = parse_chunk_size (*p, (size_t)(end - *p), &line_len,
                                 parser->config.max_chunk_ext);

  if (chunk_size == -2)
    return HTTP1_INCOMPLETE; /* Need more data */

  if (chunk_size == -1)
    return HTTP1_ERROR_INVALID_CHUNK_SIZE;

  (*p) += line_len;

  if (chunk_size == 0)
    {
      /* Last chunk - expect trailers or final CRLF */
      parser->chunk_size = 0;
      parser->chunk_remaining = 0;

      if (parser->trailers == NULL)
        {
          SocketHTTP_Headers_T trailers
              = SocketHTTP_Headers_new (parser->arena);
          if (trailers == NULL)
            {
              return HTTP1_ERROR;
            }
          parser->trailers = trailers;
          parser->trailer_count = 0;
          parser->total_trailer_size = 0;
        }
      parser->internal_state = HTTP1_PS_TRAILER_START;
      parser->state = HTTP1_STATE_TRAILERS;
    }
  else
    {
      /* Validate chunk_size fits in size_t (32-bit safety) */
      if ((uint64_t)chunk_size > SIZE_MAX)
        return HTTP1_ERROR_CHUNK_TOO_LARGE;

      /* Check chunk size limit */
      if ((size_t)chunk_size > parser->config.max_chunk_size)
        return HTTP1_ERROR_CHUNK_TOO_LARGE;

      /* Safe to cast after validation */
      parser->chunk_size = (size_t)chunk_size;
      parser->chunk_remaining = (size_t)chunk_size;

      parser->internal_state = HTTP1_PS_CHUNK_DATA;
      parser->state = HTTP1_STATE_CHUNK_DATA;
    }

  return HTTP1_OK;
}

static SocketHTTP1_Result
handle_chunk_data_state (SocketHTTP1_Parser_T parser, const char **p,
                         const char *end, char **out, size_t *out_remaining)
{
  size_t copied
      = copy_data (p, end, out, out_remaining, parser->chunk_remaining);
  parser->chunk_remaining -= copied;

  if (parser->chunk_remaining == 0)
    {
      parser->internal_state = HTTP1_PS_CHUNK_DATA_CR;
      return HTTP1_OK;
    }

  return HTTP1_INCOMPLETE;
}

static SocketHTTP1_Result
handle_chunk_crlf_states (SocketHTTP1_Parser_T parser, const char **p,
                          const char *end)
{
  HTTP1_CRLFResult res = http1_skip_crlf (p, end);
  if (res == HTTP1_CRLF_INCOMPLETE)
    return HTTP1_INCOMPLETE;
  if (res != HTTP1_CRLF_OK)
    return HTTP1_ERROR_INVALID_CHUNK_SIZE;

  parser->internal_state = HTTP1_PS_CHUNK_SIZE;
  parser->state = HTTP1_STATE_CHUNK_SIZE;
  return HTTP1_OK;
}

/**
 * Handle trailer start state - detect empty line (trailers end) or start new
 * header.
 *
 * @param parser Parser instance with current state
 * @param p Pointer to current input position (modified as data consumed)
 * @param end End of input buffer
 * @return HTTP1_OK when state transition successful, HTTP1_INCOMPLETE for more
 * data, or error code
 */
static SocketHTTP1_Result
handle_trailer_start_state (SocketHTTP1_Parser_T parser, const char **p,
                            const char *end)
{
  HTTP1_CRLFResult res = http1_skip_crlf (p, end);
  if (res == HTTP1_CRLF_OK)
    {
      mark_body_complete (parser);
      parser->internal_state = HTTP1_PS_COMPLETE;
      return HTTP1_OK;
    }
  if (res == HTTP1_CRLF_INCOMPLETE)
    return HTTP1_INCOMPLETE;
  if (!http1_is_tchar (**p))
    return HTTP1_ERROR_INVALID_TRAILER;
  http1_tokenbuf_reset (&parser->name_buf);
  parser->line_length = 0;
  parser->internal_state = HTTP1_PS_TRAILER_NAME;
  return HTTP1_OK;
}

/**
 * Handle trailer name parsing state.
 *
 * @param parser Parser instance with current state
 * @param p Pointer to current input position (modified as data consumed)
 * @param end End of input buffer
 * @return HTTP1_OK on success, or error code
 */
static SocketHTTP1_Result
handle_trailer_name_state (SocketHTTP1_Parser_T parser, const char **p,
                           const char *end)
{
  (void)end;
  char c = **p;
  if (c == ':')
    {
      char *name_str = http1_tokenbuf_terminate (
          &parser->name_buf, parser->arena, parser->config.max_header_name);
      if (name_str == NULL)
        return HTTP1_ERROR_HEADER_TOO_LARGE;
      if (parser->name_buf.len == 0)
        return HTTP1_ERROR_INVALID_HEADER_NAME;
      parser->internal_state = HTTP1_PS_TRAILER_COLON;
      (*p)++;
      return HTTP1_OK;
    }
  if (!http1_is_tchar (c))
    return HTTP1_ERROR_INVALID_HEADER_NAME;
  if (http1_tokenbuf_append (&parser->name_buf, parser->arena, c,
                             parser->config.max_header_name)
      < 0)
    return HTTP1_ERROR_HEADER_TOO_LARGE;
  parser->line_length++;
  if (parser->line_length > parser->config.max_header_name)
    return HTTP1_ERROR_HEADER_TOO_LARGE;
  (*p)++;
  return HTTP1_OK;
}

/**
 * Handle trailer colon state - skip optional whitespace after colon and
 * prepare for value parsing.
 *
 * @param parser Parser instance with current state
 * @param p Pointer to current input position (modified as data consumed)
 * @param end End of input buffer
 * @return HTTP1_OK on success, or error code
 */
static SocketHTTP1_Result
handle_trailer_colon_state (SocketHTTP1_Parser_T parser, const char **p,
                            const char *end)
{
  (void)end;
  char c = **p;
  if (http1_is_ows (c))
    {
      (*p)++;
      return HTTP1_OK;
    }
  http1_tokenbuf_reset (&parser->value_buf);
  parser->line_length = 0;
  parser->internal_state = HTTP1_PS_TRAILER_VALUE;
  if (c == '\r' || c == '\n')
    {
      parser->internal_state
          = (c == '\r') ? HTTP1_PS_TRAILER_CR : HTTP1_PS_TRAILER_LF;
      (*p)++;
      return HTTP1_OK;
    }
  if (!(http1_is_field_vchar (c) || http1_is_ows (c)))
    return HTTP1_ERROR_INVALID_HEADER_VALUE;
  if (http1_tokenbuf_append (&parser->value_buf, parser->arena, c,
                             parser->config.max_header_value)
      < 0)
    return HTTP1_ERROR_HEADER_TOO_LARGE;
  parser->line_length++;
  if (parser->line_length > parser->config.max_header_value)
    return HTTP1_ERROR_HEADER_TOO_LARGE;
  (*p)++;
  return HTTP1_OK;
}

/**
 * Handle trailer value parsing state (after colon and optional whitespace).
 *
 * @param parser Parser instance with current state
 * @param p Pointer to current input position (modified as data consumed)
 * @param end End of input buffer
 * @return HTTP1_OK on success, or error code
 */
static SocketHTTP1_Result
handle_trailer_value_state (SocketHTTP1_Parser_T parser, const char **p,
                            const char *end)
{
  (void)end;
  char c = **p;
  if (c == '\r')
    {
      parser->internal_state = HTTP1_PS_TRAILER_CR;
      (*p)++;
      return HTTP1_OK;
    }
  if (c == '\n')
    {
      parser->internal_state = HTTP1_PS_TRAILER_LF;
      (*p)++;
      return HTTP1_OK;
    }
  if (!(http1_is_field_vchar (c) || http1_is_ows (c)))
    return HTTP1_ERROR_INVALID_HEADER_VALUE;
  if (http1_tokenbuf_append (&parser->value_buf, parser->arena, c,
                             parser->config.max_header_value)
      < 0)
    return HTTP1_ERROR_HEADER_TOO_LARGE;
  parser->line_length++;
  if (parser->line_length > parser->config.max_header_value)
    return HTTP1_ERROR_HEADER_TOO_LARGE;
  (*p)++;
  return HTTP1_OK;
}

/**
 * Handle trailer parsing states in chunked transfer encoding.
 *
 * Processes trailer headers after the final zero-size chunk (RFC 9112 Section
 * 7.1.3). States handled: HTTP1_PS_TRAILER_START through HTTP1_PS_COMPLETE.
 *
 * @param parser Parser instance with current state
 * @param p Pointer to current input position (modified as data consumed)
 * @param end End of input buffer
 * @return HTTP1_OK when trailers complete, HTTP1_INCOMPLETE for more data,
 *         or error code
 */
static SocketHTTP1_Result
handle_trailer_states (SocketHTTP1_Parser_T parser, const char **p,
                       const char *end)
{
  while (*p < end)
    {
      switch (parser->internal_state)
        {
        case HTTP1_PS_TRAILER_START:
          {
            SocketHTTP1_Result res = handle_trailer_start_state (parser, p, end);
            if (res != HTTP1_OK || parser->internal_state == HTTP1_PS_COMPLETE)
              return res;
            break;
          }

        case HTTP1_PS_TRAILER_NAME:
          {
            SocketHTTP1_Result res = handle_trailer_name_state (parser, p, end);
            if (res != HTTP1_OK)
              return res;
            break;
          }

        case HTTP1_PS_TRAILER_COLON:
          {
            SocketHTTP1_Result res = handle_trailer_colon_state (parser, p, end);
            if (res != HTTP1_OK)
              return res;
            break;
          }

        case HTTP1_PS_TRAILER_VALUE:
          {
            SocketHTTP1_Result res = handle_trailer_value_state (parser, p, end);
            if (res != HTTP1_OK)
              return res;
            break;
          }

        case HTTP1_PS_TRAILER_CR:
        case HTTP1_PS_TRAILER_LF:
          {
            /* Inline handle_trailer_line_completion logic */
            if (parser->internal_state == HTTP1_PS_TRAILER_CR)
              {
                if (**p != '\n')
                  return HTTP1_ERROR_INVALID_TRAILER;
                (*p)++;
              }
            SocketHTTP1_Result res = complete_trailer_header (parser);
            if (res != HTTP1_OK)
              return res;
            break;
          }

        case HTTP1_PS_TRAILERS_END_LF:
          mark_body_complete (parser);
          parser->internal_state = HTTP1_PS_COMPLETE;
          return HTTP1_OK;

        case HTTP1_PS_COMPLETE:
          return HTTP1_OK;

        default:
          return HTTP1_ERROR;
        }
    }

  return HTTP1_INCOMPLETE;
}

static SocketHTTP1_Result
read_body_chunked (SocketHTTP1_Parser_T parser, const char *const input,
                   size_t input_len, size_t *consumed, char *output,
                   size_t output_len, size_t *written)
{
  const char *p = input;
  const char *end = input + input_len;
  char *out = output;
  size_t out_remaining = output_len;
  SocketHTTP1_Result result;

#define UPDATE_PROGRESS_AND_RETURN(r)                                         \
  do                                                                          \
    {                                                                         \
      update_progress (input, p, output, out, consumed, written);             \
      return (r);                                                             \
    }                                                                         \
  while (0)

  *consumed = 0;
  *written = 0;

  while (p < end && out_remaining > 0)
    {
      switch (parser->internal_state)
        {
        case HTTP1_PS_CHUNK_SIZE:
          result = handle_chunk_size_state (parser, &p, end);
          if (result != HTTP1_OK)
            UPDATE_PROGRESS_AND_RETURN (result);
          break;

        case HTTP1_PS_CHUNK_DATA:
          result = handle_chunk_data_state (parser, &p, end, &out,
                                            &out_remaining);
          if (result == HTTP1_INCOMPLETE)
            UPDATE_PROGRESS_AND_RETURN (HTTP1_INCOMPLETE);
          break;

        case HTTP1_PS_CHUNK_DATA_CR:
          result = handle_chunk_crlf_states (parser, &p, end);
          if (result != HTTP1_OK)
            UPDATE_PROGRESS_AND_RETURN (result);
          break;

        case HTTP1_PS_TRAILER_START:
        case HTTP1_PS_TRAILER_NAME:
        case HTTP1_PS_TRAILER_COLON:
        case HTTP1_PS_TRAILER_VALUE:
        case HTTP1_PS_TRAILER_CR:
        case HTTP1_PS_TRAILER_LF:
        case HTTP1_PS_TRAILERS_END_LF:
        case HTTP1_PS_COMPLETE:
          result = handle_trailer_states (parser, &p, end);
          UPDATE_PROGRESS_AND_RETURN (result);

        default:
          return HTTP1_ERROR;
        }
    }

  update_progress (input, p, output, out, consumed, written);

  if (parser->body_complete)
    return HTTP1_OK;

  return HTTP1_INCOMPLETE;

#undef UPDATE_PROGRESS_AND_RETURN
}

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
    return HTTP1_OK;

  /* Check if we're in error state */
  if (parser->state == HTTP1_STATE_ERROR)
    return parser->error;

  switch (parser->body_mode)
    {
    case HTTP1_BODY_NONE:
      mark_body_complete (parser);
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
