/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-decoder-stream.c
 * @brief QPACK Decoder Stream Infrastructure (RFC 9204 Section 4.2)
 *
 * Implements the decoder stream for QPACK, which carries decoder instructions
 * from decoder to encoder. The decoder stream is a unidirectional stream of
 * type 0x03.
 *
 * Decoder Instructions (RFC 9204 Section 4.4):
 * - Section Acknowledgment (Section 4.4.1)
 * - Stream Cancellation (Section 4.4.2)
 * - Insert Count Increment (Section 4.4.3)
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-4.2
 */

#include <string.h>

#include "http/qpack/SocketQPACKDecoderStream.h"

#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketHPACK.h"

/* ============================================================================
 * INTERNAL CONSTANTS
 * ============================================================================
 */

/** Maximum integer encoding buffer size (1 prefix + 10 continuation bytes) */
#define QPACK_INT_ENCODE_BUF_SIZE 16

/** Growth factor for buffer expansion */
#define QPACK_BUFFER_GROWTH_FACTOR 2

/* ============================================================================
 * INTERNAL STRUCTURE
 * ============================================================================
 */

/**
 * @brief QPACK decoder stream internal structure.
 */
struct SocketQPACK_DecoderStream
{
  Arena_T arena;         /**< Memory arena for allocations */
  uint64_t stream_id;    /**< QUIC unidirectional stream ID */
  unsigned char *buffer; /**< Instruction buffer */
  size_t buffer_len;     /**< Current data length in buffer */
  size_t buffer_cap;     /**< Buffer capacity */
  int initialized;       /**< Has stream been initialized? */
};

/* ============================================================================
 * BUFFER MANAGEMENT (INTERNAL)
 * ============================================================================
 */

/**
 * @brief Ensure buffer has at least required_space additional bytes.
 *
 * @param stream  Decoder stream
 * @param required_space Additional bytes needed
 * @return QPACK_STREAM_OK on success, error code on failure
 */
static SocketQPACKStream_Result
ensure_buffer_space (SocketQPACK_DecoderStream_T stream, size_t required_space)
{
  size_t needed;
  size_t new_cap;
  unsigned char *new_buf;

  /* Check for overflow in needed calculation */
  if (!SocketSecurity_check_add (stream->buffer_len, required_space, &needed))
    return QPACK_STREAM_ERR_BUFFER_FULL;

  /* Already have enough space */
  if (needed <= stream->buffer_cap)
    return QPACK_STREAM_OK;

  /* Calculate new capacity (double until sufficient or hit max) */
  new_cap = stream->buffer_cap;
  while (new_cap < needed)
    {
      size_t doubled;
      if (!SocketSecurity_check_multiply (
              new_cap, QPACK_BUFFER_GROWTH_FACTOR, &doubled))
        {
          /* Overflow - try exact fit instead */
          new_cap = needed;
          break;
        }
      new_cap = doubled;
    }

  /* Enforce maximum buffer size */
  if (new_cap > QPACK_DECODER_STREAM_MAX_BUFSIZE)
    {
      /* Try exact fit if growth exceeds max */
      if (needed > QPACK_DECODER_STREAM_MAX_BUFSIZE)
        return QPACK_STREAM_ERR_BUFFER_FULL;
      new_cap = needed;
    }

  /* Allocate new buffer and copy existing data */
  new_buf = ALLOC (stream->arena, new_cap);
  if (new_buf == NULL)
    return QPACK_STREAM_ERR_INTERNAL;

  if (stream->buffer_len > 0)
    memcpy (new_buf, stream->buffer, stream->buffer_len);

  stream->buffer = new_buf;
  stream->buffer_cap = new_cap;

  return QPACK_STREAM_OK;
}

/**
 * @brief Append bytes to the instruction buffer.
 *
 * @param stream Decoder stream
 * @param data   Data to append
 * @param len    Length of data
 * @return QPACK_STREAM_OK on success, error code on failure
 */
static SocketQPACKStream_Result
append_to_buffer (SocketQPACK_DecoderStream_T stream,
                  const unsigned char *data,
                  size_t len)
{
  SocketQPACKStream_Result result;

  if (len == 0)
    return QPACK_STREAM_OK;

  result = ensure_buffer_space (stream, len);
  if (result != QPACK_STREAM_OK)
    return result;

  memcpy (stream->buffer + stream->buffer_len, data, len);
  stream->buffer_len += len;

  return QPACK_STREAM_OK;
}

/* ============================================================================
 * INTEGER ENCODING (INTERNAL)
 *
 * Uses HPACK integer encoding (RFC 7541 Section 5.1) which is the same
 * encoding used by QPACK primitives (RFC 9204 Section 4.1.1).
 * ============================================================================
 */

/**
 * @brief Encode an integer with prefix and append to buffer.
 *
 * @param stream      Decoder stream
 * @param value       Integer value to encode
 * @param prefix_bits Number of prefix bits (1-8)
 * @param first_byte  First byte with flags already set (integer fills lower
 * bits)
 * @return QPACK_STREAM_OK on success, error code on failure
 */
static SocketQPACKStream_Result
encode_and_append_int (SocketQPACK_DecoderStream_T stream,
                       uint64_t value,
                       int prefix_bits,
                       unsigned char first_byte)
{
  unsigned char int_buf[QPACK_INT_ENCODE_BUF_SIZE];
  size_t int_len;

  /* Encode the integer */
  int_len
      = SocketHPACK_int_encode (value, prefix_bits, int_buf, sizeof (int_buf));
  if (int_len == 0)
    return QPACK_STREAM_ERR_INTERNAL;

  /* Merge first byte flags with integer encoding */
  int_buf[0] |= first_byte;

  return append_to_buffer (stream, int_buf, int_len);
}

/* ============================================================================
 * LIFECYCLE FUNCTIONS
 * ============================================================================
 */

SocketQPACK_DecoderStream_T
SocketQPACK_DecoderStream_new (Arena_T arena, uint64_t stream_id)
{
  SocketQPACK_DecoderStream_T stream;

  if (arena == NULL)
    return NULL;

  stream = CALLOC (arena, 1, sizeof (*stream));
  if (stream == NULL)
    return NULL;

  stream->arena = arena;
  stream->stream_id = stream_id;
  stream->initialized = 0;
  stream->buffer_len = 0;

  /* Pre-allocate initial buffer */
  stream->buffer_cap = QPACK_DECODER_STREAM_DEFAULT_BUFSIZE;
  stream->buffer = ALLOC (arena, stream->buffer_cap);
  if (stream->buffer == NULL)
    return NULL;

  return stream;
}

SocketQPACKStream_Result
SocketQPACK_DecoderStream_init (SocketQPACK_DecoderStream_T stream)
{
  if (stream == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  if (stream->initialized)
    return QPACK_STREAM_ERR_ALREADY_INIT;

  stream->initialized = 1;
  return QPACK_STREAM_OK;
}

SocketQPACKStream_Result
SocketQPACK_DecoderStream_validate_type (uint8_t type_byte)
{
  if (type_byte == QPACK_DECODER_STREAM_TYPE)
    return QPACK_STREAM_OK;

  return QPACK_STREAM_ERR_INVALID_TYPE;
}

SocketQPACKStream_Result
SocketQPACK_DecoderStream_validate_id (SocketQPACK_DecoderStream_T stream,
                                       uint64_t stream_id)
{
  if (stream == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  if (stream->stream_id == stream_id)
    return QPACK_STREAM_OK;

  return QPACK_STREAM_ERR_INVALID_TYPE;
}

bool
SocketQPACK_DecoderStream_is_open (SocketQPACK_DecoderStream_T stream)
{
  if (stream == NULL)
    return false;

  return stream->initialized != 0;
}

uint64_t
SocketQPACK_DecoderStream_get_id (SocketQPACK_DecoderStream_T stream)
{
  if (stream == NULL)
    return 0;

  return stream->stream_id;
}

/* ============================================================================
 * DECODER INSTRUCTIONS (RFC 9204 Section 4.4)
 * ============================================================================
 */

SocketQPACKStream_Result
SocketQPACK_DecoderStream_write_section_ack (SocketQPACK_DecoderStream_T stream,
                                             uint64_t stream_id)
{
  /*
   * RFC 9204 Section 4.4.1: Section Acknowledgment
   *
   *   0   1   2   3   4   5   6   7
   * +---+---+---+---+---+---+---+---+
   * | 1 |      Stream ID (7+)       |
   * +---+---------------------------+
   *
   * Bit pattern: 1xxxxxxx (0x80 mask)
   * The 7-bit prefix encodes the stream ID of the acknowledged field section.
   */
  if (stream == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  if (!stream->initialized)
    return QPACK_STREAM_ERR_NOT_INIT;

  return encode_and_append_int (stream,
                                stream_id,
                                QPACK_DINSTR_SECTION_ACK_PREFIX,
                                QPACK_DINSTR_SECTION_ACK_MASK);
}

SocketQPACKStream_Result
SocketQPACK_DecoderStream_write_stream_cancel (
    SocketQPACK_DecoderStream_T stream, uint64_t stream_id)
{
  /*
   * RFC 9204 Section 4.4.2: Stream Cancellation
   *
   *   0   1   2   3   4   5   6   7
   * +---+---+---+---+---+---+---+---+
   * | 0 | 1 |     Stream ID (6+)    |
   * +---+---+-----------------------+
   *
   * Bit pattern: 01xxxxxx (0x40 mask)
   * The 6-bit prefix encodes the stream ID being cancelled.
   */
  if (stream == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  if (!stream->initialized)
    return QPACK_STREAM_ERR_NOT_INIT;

  return encode_and_append_int (stream,
                                stream_id,
                                QPACK_DINSTR_STREAM_CANCEL_PREFIX,
                                QPACK_DINSTR_STREAM_CANCEL_MASK);
}

SocketQPACKStream_Result
SocketQPACK_DecoderStream_write_insert_count_inc (
    SocketQPACK_DecoderStream_T stream, uint64_t increment)
{
  /*
   * RFC 9204 Section 4.4.3: Insert Count Increment
   *
   *   0   1   2   3   4   5   6   7
   * +---+---+---+---+---+---+---+---+
   * | 0 | 0 |     Increment (6+)    |
   * +---+---+-----------------------+
   *
   * Bit pattern: 00xxxxxx (0x00 mask)
   * The 6-bit prefix encodes the increment value.
   *
   * Note: An increment of 0 is an error (QPACK_DECOMPRESSION_FAILED).
   */
  if (stream == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  if (!stream->initialized)
    return QPACK_STREAM_ERR_NOT_INIT;

  /* RFC 9204 Section 4.4.3: increment of 0 is an error */
  if (increment == 0)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  return encode_and_append_int (stream,
                                increment,
                                QPACK_DINSTR_INSERT_COUNT_INC_PREFIX,
                                QPACK_DINSTR_INSERT_COUNT_INC_MASK);
}

/* ============================================================================
 * BUFFER MANAGEMENT
 * ============================================================================
 */

const unsigned char *
SocketQPACK_DecoderStream_get_buffer (SocketQPACK_DecoderStream_T stream,
                                      size_t *len)
{
  if (len != NULL)
    *len = 0;

  if (stream == NULL)
    return NULL;

  if (len != NULL)
    *len = stream->buffer_len;

  if (stream->buffer_len == 0)
    return NULL;

  return stream->buffer;
}

SocketQPACKStream_Result
SocketQPACK_DecoderStream_reset_buffer (SocketQPACK_DecoderStream_T stream)
{
  if (stream == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  stream->buffer_len = 0;
  return QPACK_STREAM_OK;
}

size_t
SocketQPACK_DecoderStream_buffer_size (SocketQPACK_DecoderStream_T stream)
{
  if (stream == NULL)
    return 0;

  return stream->buffer_len;
}
