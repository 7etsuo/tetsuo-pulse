/**
 * SocketHTTP1-chunked.c - HTTP/1.1 Chunked Transfer Encoding
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements RFC 9112 Section 7.1 chunked transfer coding:
 * - Chunk encoding for requests/responses
 * - Chunk decoding for body reading
 * - Trailer header support
 */

#include "http/SocketHTTP-private.h"
#include "http/SocketHTTP1-private.h"
#include "http/SocketHTTP1.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Constants
 * ============================================================================
 */

/** CRLF sequence as byte array (not null-terminated - wire format) */
static const unsigned char HTTP1_CRLF_BYTES[2] = { '\r', '\n' };
#define HTTP1_CRLF_LEN 2

/** Zero chunk size line "0\r\n" as byte array (not null-terminated - wire
 * format) */
static const unsigned char HTTP1_ZERO_CHUNK_BYTES[3] = { '0', '\r', '\n' };
#define HTTP1_ZERO_CHUNK_SIZE_LINE_LEN 3

/** Minimum buffer size for final zero chunk + final CRLF (no trailers) */
#define HTTP1_FINAL_CHUNK_MIN_SIZE                                            \
  (HTTP1_ZERO_CHUNK_SIZE_LINE_LEN + HTTP1_CRLF_LEN)

/** Hex radix for chunk size parsing */
#define HTTP1_HEX_RADIX 16

/**
 * is_forbidden_trailer - Check if header name is forbidden in trailers
 * @name: Header name (null-terminated)
 *
 * Returns: 1 if forbidden (TE, CL, Trailer), 0 otherwise
 */
static int
is_forbidden_trailer (const char *name)
{
  static const char *forbidden[]
      = { "transfer-encoding", "content-length", "trailer", NULL };

  if (!name)
    return 0;

  size_t len = strlen (name);

  for (const char **f = forbidden; *f; f++)
    {
      size_t flen = strlen (*f);
      if (len == flen && strncasecmp (name, *f, flen) == 0)
        return 1;
    }

  return 0;
}

/* ============================================================================
 * CRLF Handling
 * ============================================================================
 */

typedef enum
{
  CRLF_OK,
  CRLF_INCOMPLETE,
  CRLF_INVALID
} crlf_result_t;

/**
 * skip_crlf - Skip CRLF or bare LF leniently
 * @p: Input position (updated on success)
 * @end: End of input
 *
 * Advances past \r?\n , handling both CRLF and bare LF.
 * Returns CRLF_OK on success, INCOMPLETE if needs more data,
 * INVALID if malformed.
 */
static crlf_result_t
skip_crlf (const char **p, const char *end)
{
  if (*p >= end)
    return CRLF_INCOMPLETE;

  if (**p == '\r')
    {
      (*p)++;
      if (*p >= end)
        return CRLF_INCOMPLETE;
      if (**p == '\n')
        {
          (*p)++;
          return CRLF_OK;
        }
      else
        return CRLF_INVALID;
    }
  else if (**p == '\n')
    {
      (*p)++;
      return CRLF_OK;
    }
  else
    return CRLF_INVALID;
}

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * mark_body_complete - Mark parser body as complete
 * @parser: Parser instance
 *
 * Sets all state flags indicating body reception is finished.
 * Centralizes the repeated pattern of marking completion.
 */
static inline void
mark_body_complete (SocketHTTP1_Parser_T parser)
{
  parser->body_complete = 1;
  parser->state = HTTP1_STATE_COMPLETE;
  parser->internal_state = HTTP1_PS_COMPLETE;
}

/**
 * copy_data - Copy data up to limits, advancing positions
 * @input_pos: Input position (updated)
 * @input_end: End of input
 * @output_pos: Output position (updated)
 * @output_remaining: Remaining output space (updated)
 * @max_bytes: Maximum bytes to copy from source
 *
 * Copies min(available input, output space, max_bytes).
 * Returns bytes copied.
 */
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

/**
 * update_progress - Update consumed/written progress tracking
 * @input_start: Start of input buffer
 * @input_pos: Current input position
 * @output_start: Start of output buffer
 * @output_pos: Current output position
 * @consumed: Output - bytes consumed from input
 * @written: Output - bytes written to output
 *
 * Calculates and stores progress offsets for both input and output.
 */
static inline void
update_progress (const char *input_start, const char *input_pos,
                 const char *output_start, const char *output_pos,
                 size_t *consumed, size_t *written)
{
  *consumed = (size_t)(input_pos - input_start);
  *written = (size_t)(output_pos - output_start);
}

/* ============================================================================
 * Chunk Encoding
 * ============================================================================
 */

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

/* ============================================================================
 * Body Reading - Content-Length Mode
 * ============================================================================
 */

/**
 * read_body_content_length - Read body with known Content-Length
 * @parser: Parser instance
 * @input: Input buffer
 * @input_len: Input length
 * @consumed: Output - bytes consumed
 * @output: Output buffer
 * @output_len: Output buffer size
 * @written: Output - bytes written
 *
 * Copies data directly from input to output, tracking remaining bytes.
 *
 * Returns: HTTP1_OK when complete, HTTP1_INCOMPLETE if more data needed
 */
static SocketHTTP1_Result
read_body_content_length (SocketHTTP1_Parser_T parser, const char *input,
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

/**
 * read_body_until_close - Read body until connection closes
 * @parser: Parser instance (unused - body mode already determined)
 * @input: Input buffer
 * @input_len: Input length
 * @consumed: Output - bytes consumed
 * @output: Output buffer
 * @output_len: Output buffer size
 * @written: Output - bytes written
 *
 * HTTP/1.0 style - reads all available data.
 * Never returns HTTP1_OK; caller must detect connection close.
 *
 * Returns: HTTP1_INCOMPLETE always (complete only on connection close)
 */
static SocketHTTP1_Result
read_body_until_close (SocketHTTP1_Parser_T parser, const char *input,
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

/* ============================================================================
 * Chunk Size Parsing
 * ============================================================================
 */

/**
 * parse_chunk_size - Parse chunk size line from input
 * @input: Input buffer (points to start of chunk size line)
 * @len: Available input length
 * @line_len: Output - total line length including CRLF
 *
 * Parses hex chunk size, skips optional chunk extensions, expects CRLF.
 * Tolerates bare LF for lenient parsing.
 *
 * Returns: Chunk size on success, -1 on error, -2 if incomplete
 */
static int64_t
parse_chunk_size (const char *input, size_t len, size_t *line_len,
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

      /* Check overflow before multiplication */
      if (size > (UINT64_MAX - digit) / HTTP1_HEX_RADIX)
        return -1;

      size = size * HTTP1_HEX_RADIX + digit;
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
      while (p < end && *p != '\r' && *p != '\n' && ext_len < max_ext_len)
        {
          p++;
          ext_len++;
        }
      if (ext_len > max_ext_len)
        return -1; /* Extension too long */
    }

  crlf_result_t res = skip_crlf (&p, end);
  if (res == CRLF_INCOMPLETE)
    return -2;
  if (res != CRLF_OK)
    return -1;

  *line_len = (size_t)(p - input);

  /* Validate size fits in size_t */
  if (size > SIZE_MAX)
    return -1;

  return (int64_t)size;
}

/* ============================================================================
 * Chunked Body Reading - State Handlers
 * ============================================================================
 */

/**
 * handle_chunk_size_state - Process HTTP1_PS_CHUNK_SIZE state
 * @parser: Parser instance
 * @p: Current input position pointer (updated on return)
 * @end: End of input buffer
 *
 * Parses chunk size line and transitions to appropriate next state.
 *
 * Returns: HTTP1_OK to continue, HTTP1_INCOMPLETE if need more data,
 *          or error code
 */
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
  parser->chunk_size = (size_t)chunk_size;
  parser->chunk_remaining = (size_t)chunk_size;

  if (chunk_size == 0)
    {
      /* Last chunk - expect trailers or final CRLF */
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
      /* Check chunk size limit */
      if ((size_t)chunk_size > parser->config.max_chunk_size)
        return HTTP1_ERROR_CHUNK_TOO_LARGE;

      parser->internal_state = HTTP1_PS_CHUNK_DATA;
      parser->state = HTTP1_STATE_CHUNK_DATA;
    }

  return HTTP1_OK;
}

/**
 * handle_chunk_data_state - Process HTTP1_PS_CHUNK_DATA state
 * @parser: Parser instance
 * @p: Current input position pointer (updated on return)
 * @end: End of input buffer
 * @out: Current output position pointer (updated on return)
 * @out_remaining: Remaining output space pointer (updated on return)
 *
 * Copies chunk data from input to output.
 *
 * Returns: HTTP1_OK to continue, HTTP1_INCOMPLETE if need more data/space
 */
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

/**
 * handle_chunk_crlf_states - Process chunk CRLF states
 * @parser: Parser instance
 * @p: Current input position pointer (updated on return)
 * @end: End of input buffer
 *
 * Handles HTTP1_PS_CHUNK_DATA_CR and HTTP1_PS_CHUNK_DATA_LF states.
 *
 * Returns: HTTP1_OK to continue, or error code
 */
static SocketHTTP1_Result
handle_chunk_crlf_states (SocketHTTP1_Parser_T parser, const char **p,
                          const char *end)
{
  crlf_result_t res = skip_crlf (p, end);
  if (res == CRLF_INCOMPLETE)
    return HTTP1_INCOMPLETE;
  if (res != CRLF_OK)
    return HTTP1_ERROR_INVALID_CHUNK_SIZE;

  parser->internal_state = HTTP1_PS_CHUNK_SIZE;
  parser->state = HTTP1_STATE_CHUNK_SIZE;
  return HTTP1_OK;
}

/* Removed unused handle_trailer_states - trailers now parsed fully inline in
 * state machine */

/* ============================================================================
 * Chunked Body Reading - Main Function
 * ============================================================================
 */

/**
 * read_body_chunked - Read chunked transfer encoded body
 * @parser: Parser instance
 * @input: Input buffer
 * @input_len: Input length
 * @consumed: Output - bytes consumed from input
 * @output: Output buffer for decoded data
 * @output_len: Output buffer size
 * @written: Output - bytes written to output
 *
 * Processes chunked encoding state machine, outputting decoded body data.
 *
 * Returns: HTTP1_OK when complete, HTTP1_INCOMPLETE if more needed,
 *          or error code
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
  SocketHTTP1_Result result;

  *consumed = 0;
  *written = 0;

  while (p < end && out_remaining > 0)
    {
      switch (parser->internal_state)
        {
        case HTTP1_PS_CHUNK_SIZE:
          result = handle_chunk_size_state (parser, &p, end);
          if (result != HTTP1_OK)
            {
              update_progress (input, p, output, out, consumed, written);
              return result;
            }
          break;

        case HTTP1_PS_CHUNK_DATA:
          result = handle_chunk_data_state (parser, &p, end, &out,
                                            &out_remaining);
          if (result == HTTP1_INCOMPLETE)
            {
              update_progress (input, p, output, out, consumed, written);
              return HTTP1_INCOMPLETE;
            }
          break;

        case HTTP1_PS_CHUNK_DATA_CR:
          result = handle_chunk_crlf_states (parser, &p, end);
          if (result != HTTP1_OK)
            {
              update_progress (input, p, output, out, consumed, written);
              return result;
            }
          break;

        case HTTP1_PS_TRAILER_START:
          {
            crlf_result_t res = skip_crlf (&p, end);
            if (res == CRLF_OK)
              {
                mark_body_complete (parser);
                parser->internal_state = HTTP1_PS_COMPLETE;
                update_progress (input, p, output, out, consumed, written);
                return HTTP1_OK;
              }
            if (res == CRLF_INCOMPLETE)
              {
                update_progress (input, p, output, out, consumed, written);
                return HTTP1_INCOMPLETE;
              }
            // res == CRLF_INVALID - possible start of header name
            if (!http1_is_tchar (*p))
              {
                update_progress (input, p, output, out, consumed, written);
                return HTTP1_ERROR_INVALID_TRAILER;
              }
            http1_tokenbuf_reset (&parser->name_buf);
            parser->line_length = 0;
            parser->internal_state = HTTP1_PS_TRAILER_NAME;
            break; // next iteration will process first *p as name char
          }

        case HTTP1_PS_TRAILER_NAME:
          {
            if (*p == ':')
              {
                /* Terminate name buffer - stores result in
                 * parser->name_buf.data */
                if (http1_tokenbuf_terminate (&parser->name_buf, parser->arena,
                                              parser->config.max_header_name)
                    == NULL)
                  {
                    update_progress (input, p, output, out, consumed, written);
                    return HTTP1_ERROR_HEADER_TOO_LARGE;
                  }
                /* Validate name not empty */
                if (parser->name_buf.len == 0)
                  {
                    update_progress (input, p, output, out, consumed, written);
                    return HTTP1_ERROR_INVALID_HEADER_NAME;
                  }
                parser->internal_state = HTTP1_PS_TRAILER_COLON;
                p++;
                break; /* Continue processing */
              }
            if (!http1_is_tchar (*p))
              {
                update_progress (input, p, output, out, consumed, written);
                return HTTP1_ERROR_INVALID_HEADER_NAME;
              }
            if (http1_tokenbuf_append (&parser->name_buf, parser->arena, *p,
                                       parser->config.max_header_name)
                < 0)
              {
                update_progress (input, p, output, out, consumed, written);
                return HTTP1_ERROR_HEADER_TOO_LARGE;
              }
            parser->line_length++;
            if (parser->line_length > parser->config.max_header_name)
              {
                update_progress (input, p, output, out, consumed, written);
                return HTTP1_ERROR_HEADER_TOO_LARGE;
              }
            p++;
            break; /* Continue processing */
          }

        case HTTP1_PS_TRAILER_COLON:
          {
            if (http1_is_ows (*p))
              {
                p++;
                break; /* Continue processing */
              }
            /* Start value or empty value */
            http1_tokenbuf_reset (&parser->value_buf);
            parser->internal_state = HTTP1_PS_TRAILER_VALUE;
            /* Process current char as value */
            if (*p == '\r' || *p == '\n')
              {
                parser->internal_state
                    = (*p == '\r') ? HTTP1_PS_TRAILER_CR : HTTP1_PS_TRAILER_LF;
                p++;
                break; /* Continue processing */
              }
            if (!http1_is_field_vchar (*p) && !http1_is_ows (*p))
              {
                update_progress (input, p, output, out, consumed, written);
                return HTTP1_ERROR_INVALID_HEADER_VALUE;
              }
            if (http1_tokenbuf_append (&parser->value_buf, parser->arena, *p,
                                       parser->config.max_header_value)
                < 0)
              {
                update_progress (input, p, output, out, consumed, written);
                return HTTP1_ERROR_HEADER_TOO_LARGE;
              }
            parser->line_length++;
            p++;
            break; /* Continue processing */
          }

        case HTTP1_PS_TRAILER_VALUE:
          {
            if (*p == '\r')
              {
                parser->internal_state = HTTP1_PS_TRAILER_CR;
                p++;
                break; /* Continue processing */
              }
            if (*p == '\n')
              {
                parser->internal_state = HTTP1_PS_TRAILER_LF;
                p++;
                break; /* Continue processing */
              }
            if (http1_is_field_vchar (*p) || http1_is_ows (*p))
              {
                if (http1_tokenbuf_append (&parser->value_buf, parser->arena,
                                           *p, parser->config.max_header_value)
                    < 0)
                  {
                    update_progress (input, p, output, out, consumed, written);
                    return HTTP1_ERROR_HEADER_TOO_LARGE;
                  }
                parser->line_length++;
                if (parser->line_length > parser->config.max_header_value)
                  {
                    update_progress (input, p, output, out, consumed, written);
                    return HTTP1_ERROR_HEADER_TOO_LARGE;
                  }
                p++;
                break; /* Continue processing */
              }
            /* Invalid char in value */
            update_progress (input, p, output, out, consumed, written);
            return HTTP1_ERROR_INVALID_HEADER_VALUE;
          }

        case HTTP1_PS_TRAILER_CR:
          {
            if (*p == '\n')
              {
                // End of header line
                char *value = http1_tokenbuf_terminate (
                    &parser->value_buf, parser->arena,
                    parser->config.max_header_value);
                if (value == NULL)
                  {
                    update_progress (input, p, output, out, consumed, written);
                    return HTTP1_ERROR_HEADER_TOO_LARGE;
                  }
                /* Get name from parser buffer - name variable may be NULL on
                 * incremental calls */
                const char *trailer_name = parser->name_buf.data;
                if (trailer_name == NULL || value == NULL)
                  {
                    update_progress (input, p, output, out, consumed, written);
                    return HTTP1_ERROR_HEADER_TOO_LARGE;
                  }
                if (is_forbidden_trailer (trailer_name))
                  {
                    update_progress (input, p, output, out, consumed, written);
                    return HTTP1_ERROR_INVALID_TRAILER;
                  }

                // Check trailer limits
                size_t trailer_name_len = parser->name_buf.len;
                size_t value_len = strlen (value);
                size_t entry_size = trailer_name_len + value_len
                                    + 32; /* Approx overhead for entry struct +
                                             nulls + delimiters */
                if (parser->trailer_count >= parser->config.max_headers
                    || parser->total_trailer_size + entry_size
                           > parser->config.max_trailer_size)
                  {
                    update_progress (input, p, output, out, consumed, written);
                    return HTTP1_ERROR_HEADER_TOO_LARGE;
                  }

                /* Add to trailers (trailer_name already set from
                 * parser->name_buf.data) */
                if (SocketHTTP_Headers_add (parser->trailers, trailer_name,
                                            value)
                    < 0)
                  {
                    update_progress (input, p, output, out, consumed, written);
                    return HTTP1_ERROR_HEADER_TOO_LARGE;
                  }
                parser->trailer_count++;
                parser->total_trailer_size += entry_size;
                /* Reset for next header */
                http1_tokenbuf_reset (&parser->name_buf);
                http1_tokenbuf_reset (&parser->value_buf);
                parser->internal_state = HTTP1_PS_TRAILER_START;
                parser->line_length = 0;
                p++;
                break; /* Continue processing next header or final CRLF */
              }
            /* Invalid after CR */
            update_progress (input, p, output, out, consumed, written);
            return HTTP1_ERROR_INVALID_TRAILER;
          }

        case HTTP1_PS_TRAILER_LF:
          {
            // Bare LF, end header
            char *value
                = http1_tokenbuf_terminate (&parser->value_buf, parser->arena,
                                            parser->config.max_header_value);
            if (value == NULL)
              {
                update_progress (input, p, output, out, consumed, written);
                return HTTP1_ERROR_HEADER_TOO_LARGE;
              }
            /* Get name from parser buffer - name variable may be NULL on
             * incremental calls */
            const char *trailer_name = parser->name_buf.data;
            if (trailer_name == NULL || value == NULL)
              {
                update_progress (input, p, output, out, consumed, written);
                return HTTP1_ERROR_HEADER_TOO_LARGE;
              }

            // Check forbidden trailers using existing function
            if (is_forbidden_trailer (trailer_name))
              {
                update_progress (input, p, output, out, consumed, written);
                return HTTP1_ERROR_INVALID_TRAILER;
              }

            // Check trailer limits
            size_t trailer_name_len = parser->name_buf.len;
            size_t value_len = strlen (value);
            size_t entry_size
                = trailer_name_len + value_len + 32; /* Approx overhead */
            if (parser->trailer_count >= parser->config.max_headers
                || parser->total_trailer_size + entry_size
                       > parser->config.max_trailer_size)
              {
                update_progress (input, p, output, out, consumed, written);
                return HTTP1_ERROR_HEADER_TOO_LARGE;
              }

            /* Add to trailers (trailer_name already set from
             * parser->name_buf.data) */
            if (SocketHTTP_Headers_add (parser->trailers, trailer_name, value)
                < 0)
              {
                update_progress (input, p, output, out, consumed, written);
                return HTTP1_ERROR_HEADER_TOO_LARGE;
              }
            parser->trailer_count++;
            parser->total_trailer_size += entry_size;
            http1_tokenbuf_reset (&parser->name_buf);
            http1_tokenbuf_reset (&parser->value_buf);
            parser->internal_state = HTTP1_PS_TRAILER_START;
            parser->line_length = 0;
            p++;
            break; /* Continue processing next header or final CRLF */
          }

        case HTTP1_PS_TRAILERS_END_LF:
          {
            mark_body_complete (parser);
            parser->internal_state = HTTP1_PS_COMPLETE;
            update_progress (input, p, output, out, consumed, written);
            return HTTP1_OK;
          }

        case HTTP1_PS_COMPLETE:
          update_progress (input, p, output, out, consumed, written);
          return HTTP1_OK;

        default:
          return HTTP1_ERROR;
        }
    }

  update_progress (input, p, output, out, consumed, written);

  if (parser->body_complete)
    return HTTP1_OK;

  return HTTP1_INCOMPLETE;
}

/* ============================================================================
 * Public Body Reading API
 * ============================================================================
 */

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
