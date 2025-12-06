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

#include "http/SocketHTTP1.h"
#include "http/SocketHTTP1-private.h"
#include "http/SocketHTTP-private.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Constants
 * ============================================================================ */

/** Minimum buffer size for final chunk "0\r\n\r\n" */
#define HTTP1_FINAL_CHUNK_MIN_SIZE 5

/** Hex radix for chunk size parsing */
#define HTTP1_HEX_RADIX 16

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

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

  if (output_size < HTTP1_FINAL_CHUNK_MIN_SIZE)
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
 * Body Reading - Content-Length Mode
 * ============================================================================ */

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
  size_t to_read;

  *consumed = 0;
  *written = 0;

  if (parser->body_remaining <= 0)
    {
      mark_body_complete (parser);
      return HTTP1_OK;
    }

  /* Calculate how much to read (min of remaining, input, output) */
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
  size_t to_read;

  /* Parser unused - body mode determined, just copy data */
  (void)parser;

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

/* ============================================================================
 * Chunk Size Parsing
 * ============================================================================ */

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
  if (p < end && *p == ';')
    {
      while (p < end && *p != '\r' && *p != '\n')
        p++;
    }

  /* Expect CRLF or bare LF */
  if (p >= end)
    return -2; /* Incomplete - need more data */

  if (*p == '\r')
    {
      p++;
      if (p >= end)
        return -2; /* Incomplete */
      if (*p != '\n')
        return -1; /* Invalid - CR not followed by LF */
      p++;
    }
  else if (*p == '\n')
    {
      /* Bare LF - lenient parsing */
      p++;
    }
  else
    {
      return -1; /* Invalid character after size */
    }

  *line_len = (size_t)(p - input);

  /* Validate size fits in size_t */
  if (size > SIZE_MAX)
    return -1;

  return (int64_t)size;
}

/* ============================================================================
 * Chunked Body Reading - State Handlers
 * ============================================================================ */

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

  chunk_size = parse_chunk_size (*p, (size_t)(end - *p), &line_len);

  if (chunk_size == -2)
    return HTTP1_INCOMPLETE; /* Need more data */

  if (chunk_size == -1)
    return HTTP1_ERROR_INVALID_CHUNK_SIZE;

  *p += line_len;
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
  size_t to_read = parser->chunk_remaining;

  if (to_read > (size_t)(end - *p))
    to_read = (size_t)(end - *p);
  if (to_read > *out_remaining)
    to_read = *out_remaining;

  if (to_read > 0)
    {
      memcpy (*out, *p, to_read);
      *p += to_read;
      *out += to_read;
      *out_remaining -= to_read;
      parser->chunk_remaining -= to_read;
    }

  if (parser->chunk_remaining == 0)
    {
      parser->internal_state = HTTP1_PS_CHUNK_DATA_CR;
      return HTTP1_OK;
    }

  /* Need more data or output space */
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
  if (*p >= end)
    return HTTP1_INCOMPLETE;

  if (parser->internal_state == HTTP1_PS_CHUNK_DATA_CR)
    {
      if (**p == '\r')
        {
          (*p)++;
          parser->internal_state = HTTP1_PS_CHUNK_DATA_LF;
          if (*p >= end)
            return HTTP1_INCOMPLETE;
        }
      else if (**p == '\n')
        {
          /* Bare LF - lenient */
          (*p)++;
          parser->internal_state = HTTP1_PS_CHUNK_SIZE;
          parser->state = HTTP1_STATE_CHUNK_SIZE;
          return HTTP1_OK;
        }
      else
        {
          return HTTP1_ERROR_INVALID_CHUNK_SIZE;
        }
    }

  if (parser->internal_state == HTTP1_PS_CHUNK_DATA_LF)
    {
      if (**p != '\n')
        return HTTP1_ERROR_INVALID_CHUNK_SIZE;

      (*p)++;
      parser->internal_state = HTTP1_PS_CHUNK_SIZE;
      parser->state = HTTP1_STATE_CHUNK_SIZE;
    }

  return HTTP1_OK;
}

/**
 * handle_trailer_states - Process trailer parsing states
 * @parser: Parser instance
 * @p: Current input position pointer (updated on return)
 * @end: End of input buffer
 *
 * Handles HTTP1_PS_TRAILER_START and HTTP1_PS_TRAILERS_END_LF states.
 * Simplified implementation that skips trailer content.
 *
 * Returns: HTTP1_OK when complete, HTTP1_INCOMPLETE, or error code
 */
static SocketHTTP1_Result
handle_trailer_states (SocketHTTP1_Parser_T parser, const char **p,
                       const char *end)
{
  if (*p >= end)
    return HTTP1_INCOMPLETE;

  if (parser->internal_state == HTTP1_PS_TRAILER_START)
    {
      if (**p == '\r')
        {
          (*p)++;
          parser->internal_state = HTTP1_PS_TRAILERS_END_LF;
          if (*p >= end)
            return HTTP1_INCOMPLETE;
        }
      else if (**p == '\n')
        {
          /* Bare LF - end of message */
          (*p)++;
          mark_body_complete (parser);
          return HTTP1_OK;
        }
      else if (http1_is_tchar (**p))
        {
          /* Trailer header - skip for now (simplified) */
          while (*p < end && **p != '\n')
            (*p)++;
          if (*p < end)
            (*p)++; /* Skip LF */
          return HTTP1_OK;
        }
      else
        {
          return HTTP1_ERROR_INVALID_TRAILER;
        }
    }

  if (parser->internal_state == HTTP1_PS_TRAILERS_END_LF)
    {
      if (**p != '\n')
        return HTTP1_ERROR_INVALID_TRAILER;

      (*p)++;
      mark_body_complete (parser);
      return HTTP1_OK;
    }

  return HTTP1_INCOMPLETE;
}

/* ============================================================================
 * Chunked Body Reading - Main Function
 * ============================================================================ */

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
        case HTTP1_PS_CHUNK_DATA_LF:
          result = handle_chunk_crlf_states (parser, &p, end);
          if (result != HTTP1_OK)
            {
              update_progress (input, p, output, out, consumed, written);
              return result;
            }
          break;

        case HTTP1_PS_TRAILER_START:
        case HTTP1_PS_TRAILERS_END_LF:
          result = handle_trailer_states (parser, &p, end);
          update_progress (input, p, output, out, consumed, written);
          if (parser->body_complete)
            return HTTP1_OK;
          if (result != HTTP1_OK)
            return result;
          break;

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
