/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK-encoder-stream.c - QPACK Encoder Stream (RFC 9204 Section 4.2)
 *
 * Implements encoder stream infrastructure for QPACK header compression.
 * The encoder stream carries unframed encoder instructions to update the
 * decoder about dynamic table changes.
 */

#include <assert.h>
#include <string.h>

#include "core/Arena.h"
#include "http/SocketHPACK.h"
#include "http/SocketQPACKEncoderStream.h"

/* ============================================================================
 * QPACK Instruction Format Constants (RFC 9204 Section 4.3)
 * ============================================================================
 */

/* Set Dynamic Table Capacity (4.3.1): 0b001xxxxx, 5-bit prefix */
#define QPACK_INST_SET_CAPACITY_MASK 0xE0
#define QPACK_INST_SET_CAPACITY_VAL 0x20
#define QPACK_INST_SET_CAPACITY_PREFIX 5

/* Insert With Name Reference (4.3.2): 0b1Txxxxxx, 6-bit prefix */
#define QPACK_INST_INSERT_NAMEREF_MASK 0x80
#define QPACK_INST_INSERT_NAMEREF_VAL 0x80
#define QPACK_INST_INSERT_NAMEREF_PREFIX 6
#define QPACK_INST_INSERT_NAMEREF_STATIC 0x40

/* Insert With Literal Name (4.3.3): 0b01xxxxxx, 5-bit prefix */
#define QPACK_INST_INSERT_LITERAL_MASK 0xC0
#define QPACK_INST_INSERT_LITERAL_VAL 0x40
#define QPACK_INST_INSERT_LITERAL_PREFIX 5

/* Duplicate (4.3.4): 0b000xxxxx, 5-bit prefix */
#define QPACK_INST_DUPLICATE_MASK 0xE0
#define QPACK_INST_DUPLICATE_VAL 0x00
#define QPACK_INST_DUPLICATE_PREFIX 5

/* String encoding: 0b0xxxxxxx (literal) or 0b1xxxxxxx (Huffman) */
#define QPACK_STRING_HUFFMAN_FLAG 0x80
#define QPACK_STRING_PREFIX 7

/* Buffer growth factor */
#define BUFFER_GROWTH_FACTOR 2

/* ============================================================================
 * Exception Definitions
 * ============================================================================
 */

const Except_T SocketQPACK_EncoderStream_Error
    = { &SocketQPACK_EncoderStream_Error, "QPACK encoder stream error" };

const Except_T SocketQPACK_H3_ClosedCriticalStream
    = { &SocketQPACK_H3_ClosedCriticalStream,
        "H3_CLOSED_CRITICAL_STREAM: encoder stream closed prematurely" };

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *result_strings[] = {
  [QPACK_ENCODER_STREAM_OK] = "OK",
  [QPACK_ENCODER_STREAM_ERROR] = "Generic error",
  [QPACK_ENCODER_STREAM_BUFFER_FULL] = "Buffer capacity exceeded",
  [QPACK_ENCODER_STREAM_INVALID_PARAM] = "Invalid parameter",
  [QPACK_ENCODER_STREAM_ALREADY_INIT] = "Stream already initialized",
  [QPACK_ENCODER_STREAM_NOT_INIT] = "Stream not initialized",
  [QPACK_ENCODER_STREAM_CLOSED]
  = "Critical stream closed (H3_CLOSED_CRITICAL_STREAM)",
};

const char *
SocketQPACK_EncoderStream_result_string (
    SocketQPACK_EncoderStream_Result result)
{
  if (result < 0 || result > QPACK_ENCODER_STREAM_CLOSED)
    return "Unknown error";
  return result_strings[result];
}

/* ============================================================================
 * Encoder Stream Structure
 * ============================================================================
 */

struct SocketQPACK_EncoderStream
{
  Arena_T arena;         /* Arena for memory allocation */
  uint64_t stream_id;    /* QUIC unidirectional stream ID */
  unsigned char *buffer; /* Instruction buffer */
  size_t buffer_len;     /* Current buffer length (bytes used) */
  size_t buffer_cap;     /* Buffer capacity */
  int is_initialized;    /* Stream has been established */
  int is_closed;         /* Stream has been closed (error state) */
};

/* ============================================================================
 * Buffer Management
 * ============================================================================
 */

/**
 * Ensure buffer has at least required_space bytes available.
 * Grows buffer if necessary.
 */
static SocketQPACK_EncoderStream_Result
ensure_buffer_space (SocketQPACK_EncoderStream_T stream, size_t required_space)
{
  size_t available;
  size_t new_cap;
  unsigned char *new_buffer;

  if (stream == NULL)
    return QPACK_ENCODER_STREAM_INVALID_PARAM;

  available = stream->buffer_cap - stream->buffer_len;
  if (available >= required_space)
    return QPACK_ENCODER_STREAM_OK;

  /* Calculate new capacity */
  new_cap = stream->buffer_cap;
  while (new_cap - stream->buffer_len < required_space)
    {
      if (new_cap > QPACK_ENCODER_STREAM_MAX_CAPACITY / BUFFER_GROWTH_FACTOR)
        return QPACK_ENCODER_STREAM_BUFFER_FULL;
      new_cap *= BUFFER_GROWTH_FACTOR;
    }

  if (new_cap > QPACK_ENCODER_STREAM_MAX_CAPACITY)
    new_cap = QPACK_ENCODER_STREAM_MAX_CAPACITY;

  if (new_cap - stream->buffer_len < required_space)
    return QPACK_ENCODER_STREAM_BUFFER_FULL;

  /* Allocate new buffer and copy existing data */
  new_buffer = ALLOC (stream->arena, new_cap);
  if (new_buffer == NULL)
    return QPACK_ENCODER_STREAM_ERROR;

  if (stream->buffer_len > 0 && stream->buffer != NULL)
    memcpy (new_buffer, stream->buffer, stream->buffer_len);

  stream->buffer = new_buffer;
  stream->buffer_cap = new_cap;

  return QPACK_ENCODER_STREAM_OK;
}

/**
 * Append bytes to buffer.
 */
static SocketQPACK_EncoderStream_Result
buffer_append (SocketQPACK_EncoderStream_T stream,
               const unsigned char *data,
               size_t len)
{
  SocketQPACK_EncoderStream_Result result;

  result = ensure_buffer_space (stream, len);
  if (result != QPACK_ENCODER_STREAM_OK)
    return result;

  memcpy (stream->buffer + stream->buffer_len, data, len);
  stream->buffer_len += len;

  return QPACK_ENCODER_STREAM_OK;
}

/* ============================================================================
 * Integer Encoding (RFC 9204 Section 4.1.1 - uses RFC 7541 integer encoding)
 * ============================================================================
 */

/**
 * Encode integer with prefix and flags, append to buffer.
 * Uses HPACK integer encoding from SocketHPACK.
 */
static SocketQPACK_EncoderStream_Result
encode_int_to_buffer (SocketQPACK_EncoderStream_T stream,
                      uint64_t value,
                      int prefix_bits,
                      unsigned char flags)
{
  unsigned char int_buf[16];
  size_t int_len;
  SocketQPACK_EncoderStream_Result result;

  int_len
      = SocketHPACK_int_encode (value, prefix_bits, int_buf, sizeof (int_buf));
  if (int_len == 0)
    return QPACK_ENCODER_STREAM_ERROR;

  /* Combine first byte with flags */
  int_buf[0] |= flags;

  result = buffer_append (stream, int_buf, int_len);
  return result;
}

/* ============================================================================
 * String Encoding (RFC 9204 Section 4.1.2)
 * ============================================================================
 */

/**
 * Encode string literal and append to buffer.
 */
static SocketQPACK_EncoderStream_Result
encode_string_to_buffer (SocketQPACK_EncoderStream_T stream,
                         const unsigned char *str,
                         size_t len,
                         int use_huffman)
{
  unsigned char len_buf[16];
  size_t len_bytes;
  unsigned char flag;
  SocketQPACK_EncoderStream_Result result;

  if (use_huffman)
    {
      /* Calculate Huffman-encoded size */
      size_t huffman_len = SocketHPACK_huffman_encoded_size (str, len);

      /* Only use Huffman if it provides compression */
      if (huffman_len < len)
        {
          /* Encode with Huffman */
          unsigned char *huffman_buf;
          ssize_t encoded_len;

          flag = QPACK_STRING_HUFFMAN_FLAG;
          len_bytes = SocketHPACK_int_encode (
              huffman_len, QPACK_STRING_PREFIX, len_buf, sizeof (len_buf));
          if (len_bytes == 0)
            return QPACK_ENCODER_STREAM_ERROR;

          len_buf[0] |= flag;

          result = buffer_append (stream, len_buf, len_bytes);
          if (result != QPACK_ENCODER_STREAM_OK)
            return result;

          /* Allocate temporary buffer for Huffman encoding */
          huffman_buf = ALLOC (stream->arena, huffman_len + 8);
          if (huffman_buf == NULL)
            return QPACK_ENCODER_STREAM_ERROR;

          encoded_len = SocketHPACK_huffman_encode (
              str, len, huffman_buf, huffman_len + 8);
          if (encoded_len < 0)
            return QPACK_ENCODER_STREAM_ERROR;

          return buffer_append (stream, huffman_buf, (size_t)encoded_len);
        }
    }

  /* Literal encoding */
  flag = 0;
  len_bytes = SocketHPACK_int_encode (
      len, QPACK_STRING_PREFIX, len_buf, sizeof (len_buf));
  if (len_bytes == 0)
    return QPACK_ENCODER_STREAM_ERROR;

  len_buf[0] |= flag;

  result = buffer_append (stream, len_buf, len_bytes);
  if (result != QPACK_ENCODER_STREAM_OK)
    return result;

  return buffer_append (stream, str, len);
}

/* ============================================================================
 * Public API - Stream Lifecycle
 * ============================================================================
 */

SocketQPACK_EncoderStream_T
SocketQPACK_EncoderStream_new (Arena_T arena, uint64_t stream_id)
{
  SocketQPACK_EncoderStream_T stream;

  if (arena == NULL)
    return NULL;

  stream = ALLOC (arena, sizeof (*stream));
  if (stream == NULL)
    return NULL;

  stream->arena = arena;
  stream->stream_id = stream_id;
  stream->buffer_cap = QPACK_ENCODER_STREAM_INITIAL_CAPACITY;
  stream->buffer = ALLOC (arena, stream->buffer_cap);
  if (stream->buffer == NULL)
    return NULL;

  stream->buffer_len = 0;
  stream->is_initialized = 1;
  stream->is_closed = 0;

  return stream;
}

int
SocketQPACK_EncoderStream_is_initialized (SocketQPACK_EncoderStream_T stream)
{
  if (stream == NULL)
    return 0;
  return stream->is_initialized && !stream->is_closed;
}

int
SocketQPACK_EncoderStream_validate_type (uint64_t stream_type)
{
  return stream_type == QPACK_ENCODER_STREAM_TYPE;
}

uint64_t
SocketQPACK_EncoderStream_get_stream_id (SocketQPACK_EncoderStream_T stream)
{
  if (stream == NULL)
    return 0;
  return stream->stream_id;
}

/* ============================================================================
 * Public API - Encoder Instructions
 * ============================================================================
 */

SocketQPACK_EncoderStream_Result
SocketQPACK_EncoderStream_write_capacity (SocketQPACK_EncoderStream_T stream,
                                          uint64_t capacity)
{
  if (stream == NULL)
    return QPACK_ENCODER_STREAM_INVALID_PARAM;

  if (!stream->is_initialized)
    return QPACK_ENCODER_STREAM_NOT_INIT;

  if (stream->is_closed)
    return QPACK_ENCODER_STREAM_CLOSED;

  /* Set Dynamic Table Capacity instruction: 0b001xxxxx */
  return encode_int_to_buffer (stream,
                               capacity,
                               QPACK_INST_SET_CAPACITY_PREFIX,
                               QPACK_INST_SET_CAPACITY_VAL);
}

SocketQPACK_EncoderStream_Result
SocketQPACK_EncoderStream_write_insert_nameref (
    SocketQPACK_EncoderStream_T stream,
    int is_static,
    uint64_t name_index,
    const unsigned char *value,
    size_t value_len,
    int use_huffman)
{
  unsigned char flags;
  SocketQPACK_EncoderStream_Result result;

  if (stream == NULL || value == NULL)
    return QPACK_ENCODER_STREAM_INVALID_PARAM;

  if (!stream->is_initialized)
    return QPACK_ENCODER_STREAM_NOT_INIT;

  if (stream->is_closed)
    return QPACK_ENCODER_STREAM_CLOSED;

  /* Insert With Name Reference: 0b1Txxxxxx where T is static bit */
  flags = QPACK_INST_INSERT_NAMEREF_VAL;
  if (is_static)
    flags |= QPACK_INST_INSERT_NAMEREF_STATIC;

  result = encode_int_to_buffer (
      stream, name_index, QPACK_INST_INSERT_NAMEREF_PREFIX, flags);
  if (result != QPACK_ENCODER_STREAM_OK)
    return result;

  return encode_string_to_buffer (stream, value, value_len, use_huffman);
}

SocketQPACK_EncoderStream_Result
SocketQPACK_EncoderStream_write_insert_literal (
    SocketQPACK_EncoderStream_T stream,
    const unsigned char *name,
    size_t name_len,
    const unsigned char *value,
    size_t value_len,
    int use_huffman_name,
    int use_huffman_value)
{
  SocketQPACK_EncoderStream_Result result;
  unsigned char first_byte;
  unsigned char int_buf[16];
  size_t int_len;

  if (stream == NULL || name == NULL || value == NULL)
    return QPACK_ENCODER_STREAM_INVALID_PARAM;

  if (!stream->is_initialized)
    return QPACK_ENCODER_STREAM_NOT_INIT;

  if (stream->is_closed)
    return QPACK_ENCODER_STREAM_CLOSED;

  /* Insert With Literal Name: 0b01Hxxxxx where H is Huffman flag for name */
  first_byte = QPACK_INST_INSERT_LITERAL_VAL;
  if (use_huffman_name)
    first_byte |= 0x20; /* Huffman flag for name (bit 5) */

  /* Encode name length with 5-bit prefix */
  if (use_huffman_name)
    {
      size_t huffman_len = SocketHPACK_huffman_encoded_size (name, name_len);
      if (huffman_len < name_len)
        {
          /* Use Huffman for name */
          unsigned char *huffman_buf;
          ssize_t encoded_len;

          int_len = SocketHPACK_int_encode (huffman_len,
                                            QPACK_INST_INSERT_LITERAL_PREFIX,
                                            int_buf,
                                            sizeof (int_buf));
          if (int_len == 0)
            return QPACK_ENCODER_STREAM_ERROR;

          int_buf[0] |= first_byte;

          result = buffer_append (stream, int_buf, int_len);
          if (result != QPACK_ENCODER_STREAM_OK)
            return result;

          huffman_buf = ALLOC (stream->arena, huffman_len + 8);
          if (huffman_buf == NULL)
            return QPACK_ENCODER_STREAM_ERROR;

          encoded_len = SocketHPACK_huffman_encode (
              name, name_len, huffman_buf, huffman_len + 8);
          if (encoded_len < 0)
            return QPACK_ENCODER_STREAM_ERROR;

          result = buffer_append (stream, huffman_buf, (size_t)encoded_len);
          if (result != QPACK_ENCODER_STREAM_OK)
            return result;

          return encode_string_to_buffer (
              stream, value, value_len, use_huffman_value);
        }
    }

  /* Literal name (no Huffman or Huffman didn't compress) */
  first_byte = QPACK_INST_INSERT_LITERAL_VAL; /* Reset, no Huffman bit */
  int_len = SocketHPACK_int_encode (
      name_len, QPACK_INST_INSERT_LITERAL_PREFIX, int_buf, sizeof (int_buf));
  if (int_len == 0)
    return QPACK_ENCODER_STREAM_ERROR;

  int_buf[0] |= first_byte;

  result = buffer_append (stream, int_buf, int_len);
  if (result != QPACK_ENCODER_STREAM_OK)
    return result;

  result = buffer_append (stream, name, name_len);
  if (result != QPACK_ENCODER_STREAM_OK)
    return result;

  return encode_string_to_buffer (stream, value, value_len, use_huffman_value);
}

SocketQPACK_EncoderStream_Result
SocketQPACK_EncoderStream_write_duplicate (SocketQPACK_EncoderStream_T stream,
                                           uint64_t relative_index)
{
  if (stream == NULL)
    return QPACK_ENCODER_STREAM_INVALID_PARAM;

  if (!stream->is_initialized)
    return QPACK_ENCODER_STREAM_NOT_INIT;

  if (stream->is_closed)
    return QPACK_ENCODER_STREAM_CLOSED;

  /* Duplicate instruction: 0b000xxxxx */
  return encode_int_to_buffer (stream,
                               relative_index,
                               QPACK_INST_DUPLICATE_PREFIX,
                               QPACK_INST_DUPLICATE_VAL);
}

/* ============================================================================
 * Public API - Buffer Access
 * ============================================================================
 */

const unsigned char *
SocketQPACK_EncoderStream_get_buffer (SocketQPACK_EncoderStream_T stream,
                                      size_t *buffer_len)
{
  if (stream == NULL || buffer_len == NULL)
    {
      if (buffer_len != NULL)
        *buffer_len = 0;
      return NULL;
    }

  *buffer_len = stream->buffer_len;
  return stream->buffer;
}

void
SocketQPACK_EncoderStream_reset_buffer (SocketQPACK_EncoderStream_T stream)
{
  if (stream == NULL)
    return;

  stream->buffer_len = 0;
}

SocketQPACK_EncoderStream_Result
SocketQPACK_EncoderStream_close (SocketQPACK_EncoderStream_T stream)
{
  if (stream == NULL)
    return QPACK_ENCODER_STREAM_INVALID_PARAM;

  /* RFC 9204 Section 4.2: Closing encoder stream is an error */
  stream->is_closed = 1;
  return QPACK_ENCODER_STREAM_CLOSED;
}
