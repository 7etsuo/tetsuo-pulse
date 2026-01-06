/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACKDecoderStream.c
 * @brief QPACK Decoder Stream Implementation (RFC 9204 Section 4.2).
 *
 * Implements the decoder stream for QPACK header compression in HTTP/3.
 */

#include <string.h>

#include "http/qpack/SocketQPACKDecoderStream.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/* Maximum bytes needed for a QPACK integer encoding (RFC 9204 Section 4.1.1)
 * Uses the same encoding as HPACK: 1 prefix byte + up to 10 continuation bytes
 */
#define QPACK_INT_MAX_BYTES 11

/* HTTP/3 unidirectional stream type bits (RFC 9114 Section 6.2)
 * Stream type is encoded in the first varint on the stream.
 * For HTTP/3, the stream ID itself doesn't encode the type directly.
 * However, for QPACK validation, we check against the expected type.
 */

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * @brief Encode a QPACK integer with prefix.
 *
 * RFC 9204 Section 4.1.1: Integer encoding is identical to HPACK (RFC
 * 7541 5.1).
 *
 * @param value       Value to encode.
 * @param prefix_bits Number of bits in first byte (1-8).
 * @param output      Output buffer.
 * @param output_size Output buffer size.
 *
 * @return Number of bytes written, or 0 on error.
 */
static size_t
qpack_int_encode (uint64_t value,
                  int prefix_bits,
                  unsigned char *output,
                  size_t output_size)
{
  if (output == NULL || output_size == 0 || prefix_bits < 1 || prefix_bits > 8)
    return 0;

  /* Calculate the maximum value that fits in the prefix */
  uint64_t prefix_max = (1ULL << prefix_bits) - 1;

  if (value < prefix_max)
    {
      /* Value fits in prefix */
      output[0] = (unsigned char)value;
      return 1;
    }

  /* Value requires continuation bytes */
  output[0] = (unsigned char)prefix_max;
  value -= prefix_max;

  size_t pos = 1;
  while (value >= 128)
    {
      if (pos >= output_size)
        return 0; /* Buffer overflow */

      output[pos++] = (unsigned char)((value & 0x7F) | 0x80);
      value >>= 7;
    }

  if (pos >= output_size)
    return 0; /* Buffer overflow */

  output[pos++] = (unsigned char)value;
  return pos;
}

/**
 * @brief Write instruction to send buffer.
 *
 * @param stream         Decoder stream handle.
 * @param pattern        Instruction bit pattern for first byte.
 * @param prefix_bits    Number of prefix bits.
 * @param value          Value to encode.
 *
 * @return Result code.
 */
static SocketQPACKDecoderStream_Result
write_instruction (SocketQPACKDecoderStream_T stream,
                   unsigned char pattern,
                   int prefix_bits,
                   uint64_t value)
{
  unsigned char buf[QPACK_INT_MAX_BYTES];

  /* Encode the integer */
  size_t len = qpack_int_encode (value, prefix_bits, buf, sizeof (buf));
  if (len == 0)
    return QPACK_DECODER_STREAM_ERROR_ENCODE;

  /* Apply the pattern to the first byte */
  buf[0] |= pattern;

  /* Check buffer space */
  if (stream->send_buffer_used + len > stream->send_buffer_size)
    return QPACK_DECODER_STREAM_ERROR_BUFFER_FULL;

  /* Copy to send buffer */
  memcpy (stream->send_buffer + stream->send_buffer_used, buf, len);
  stream->send_buffer_used += len;

  return QPACK_DECODER_STREAM_OK;
}

/* ============================================================================
 * Lifecycle Functions
 * ============================================================================
 */

SocketQPACKDecoderStream_T
SocketQPACKDecoderStream_new (Arena_T arena, size_t buffer_size)
{
  if (arena == NULL)
    return NULL;

  SocketQPACKDecoderStream_T stream
      = ALLOC (arena, sizeof (struct SocketQPACKDecoderStream));
  if (stream == NULL)
    return NULL;

  /* Initialize fields */
  stream->arena = arena;
  stream->stream_id = 0;
  stream->state = QPACK_DECODER_STREAM_STATE_IDLE;

  /* Allocate send buffer */
  size_t buf_size = buffer_size > 0 ? buffer_size
                                    : QPACK_DECODER_STREAM_DEFAULT_BUFFER_SIZE;
  stream->send_buffer = ALLOC (arena, buf_size);
  if (stream->send_buffer == NULL)
    return NULL;

  stream->send_buffer_size = buf_size;
  stream->send_buffer_used = 0;

  /* Initialize counters */
  stream->max_acknowledged_section_id = 0;
  stream->known_received_count = 0;

  return stream;
}

SocketQPACKDecoderStream_Result
SocketQPACKDecoderStream_open (SocketQPACKDecoderStream_T stream,
                               uint64_t stream_id)
{
  if (stream == NULL)
    return QPACK_DECODER_STREAM_ERROR_NULL;

  if (stream->state == QPACK_DECODER_STREAM_STATE_OPEN)
    return QPACK_DECODER_STREAM_ERROR_DUPLICATE;

  if (stream->state == QPACK_DECODER_STREAM_STATE_CLOSED)
    return QPACK_DECODER_STREAM_ERROR_CLOSED;

  stream->stream_id = stream_id;
  stream->state = QPACK_DECODER_STREAM_STATE_OPEN;

  return QPACK_DECODER_STREAM_OK;
}

SocketQPACKDecoderStream_Result
SocketQPACKDecoderStream_close (SocketQPACKDecoderStream_T stream)
{
  if (stream == NULL)
    return QPACK_DECODER_STREAM_ERROR_NULL;

  stream->state = QPACK_DECODER_STREAM_STATE_CLOSED;

  return QPACK_DECODER_STREAM_OK;
}

SocketQPACKDecoderStream_Result
SocketQPACKDecoderStream_reset (SocketQPACKDecoderStream_T stream)
{
  if (stream == NULL)
    return QPACK_DECODER_STREAM_ERROR_NULL;

  stream->stream_id = 0;
  stream->state = QPACK_DECODER_STREAM_STATE_IDLE;
  stream->send_buffer_used = 0;
  stream->max_acknowledged_section_id = 0;
  stream->known_received_count = 0;

  return QPACK_DECODER_STREAM_OK;
}

/* ============================================================================
 * Instruction Functions (RFC 9204 Section 4.4)
 * ============================================================================
 */

SocketQPACKDecoderStream_Result
SocketQPACKDecoderStream_write_section_ack (SocketQPACKDecoderStream_T stream,
                                            uint64_t request_stream_id)
{
  if (stream == NULL)
    return QPACK_DECODER_STREAM_ERROR_NULL;

  if (stream->state != QPACK_DECODER_STREAM_STATE_OPEN)
    return QPACK_DECODER_STREAM_ERROR_INVALID_STATE;

  /* Section Acknowledgment: 1xxxxxxx with 7-bit prefix */
  SocketQPACKDecoderStream_Result result
      = write_instruction (stream,
                           QPACK_INSTR_SECTION_ACK_PATTERN,
                           QPACK_INSTR_SECTION_ACK_PREFIX,
                           request_stream_id);

  if (result == QPACK_DECODER_STREAM_OK)
    {
      /* Track acknowledged section ID */
      if (request_stream_id > stream->max_acknowledged_section_id)
        stream->max_acknowledged_section_id = request_stream_id;
    }

  return result;
}

SocketQPACKDecoderStream_Result
SocketQPACKDecoderStream_write_stream_cancel (SocketQPACKDecoderStream_T stream,
                                              uint64_t request_stream_id)
{
  if (stream == NULL)
    return QPACK_DECODER_STREAM_ERROR_NULL;

  if (stream->state != QPACK_DECODER_STREAM_STATE_OPEN)
    return QPACK_DECODER_STREAM_ERROR_INVALID_STATE;

  /* Stream Cancellation: 01xxxxxx with 6-bit prefix */
  return write_instruction (stream,
                            QPACK_INSTR_STREAM_CANCEL_PATTERN,
                            QPACK_INSTR_STREAM_CANCEL_PREFIX,
                            request_stream_id);
}

SocketQPACKDecoderStream_Result
SocketQPACKDecoderStream_write_insert_count_inc (
    SocketQPACKDecoderStream_T stream, uint64_t increment)
{
  if (stream == NULL)
    return QPACK_DECODER_STREAM_ERROR_NULL;

  if (stream->state != QPACK_DECODER_STREAM_STATE_OPEN)
    return QPACK_DECODER_STREAM_ERROR_INVALID_STATE;

  if (increment == 0)
    return QPACK_DECODER_STREAM_OK; /* No-op for zero increment */

  /* Insert Count Increment: 00xxxxxx with 6-bit prefix */
  SocketQPACKDecoderStream_Result result
      = write_instruction (stream,
                           QPACK_INSTR_INSERT_COUNT_INC_PATTERN,
                           QPACK_INSTR_INSERT_COUNT_INC_PREFIX,
                           increment);

  if (result == QPACK_DECODER_STREAM_OK)
    stream->known_received_count += increment;

  return result;
}

/* ============================================================================
 * Buffer Management Functions
 * ============================================================================
 */

const unsigned char *
SocketQPACKDecoderStream_get_pending (SocketQPACKDecoderStream_T stream,
                                      size_t *len)
{
  if (stream == NULL || len == NULL)
    {
      if (len != NULL)
        *len = 0;
      return NULL;
    }

  *len = stream->send_buffer_used;
  return stream->send_buffer_used > 0 ? stream->send_buffer : NULL;
}

SocketQPACKDecoderStream_Result
SocketQPACKDecoderStream_mark_sent (SocketQPACKDecoderStream_T stream,
                                    size_t len)
{
  if (stream == NULL)
    return QPACK_DECODER_STREAM_ERROR_NULL;

  if (len > stream->send_buffer_used)
    len = stream->send_buffer_used;

  if (len > 0 && len < stream->send_buffer_used)
    {
      /* Move remaining data to front of buffer */
      memmove (stream->send_buffer,
               stream->send_buffer + len,
               stream->send_buffer_used - len);
    }

  stream->send_buffer_used -= len;

  return QPACK_DECODER_STREAM_OK;
}

SocketQPACKDecoderStream_Result
SocketQPACKDecoderStream_clear_buffer (SocketQPACKDecoderStream_T stream)
{
  if (stream == NULL)
    return QPACK_DECODER_STREAM_ERROR_NULL;

  stream->send_buffer_used = 0;

  return QPACK_DECODER_STREAM_OK;
}

size_t
SocketQPACKDecoderStream_buffer_available (SocketQPACKDecoderStream_T stream)
{
  if (stream == NULL)
    return 0;

  return stream->send_buffer_size - stream->send_buffer_used;
}

/* ============================================================================
 * State Query Functions
 * ============================================================================
 */

SocketQPACKDecoderStreamState
SocketQPACKDecoderStream_get_state (SocketQPACKDecoderStream_T stream)
{
  if (stream == NULL)
    return QPACK_DECODER_STREAM_STATE_IDLE;

  return stream->state;
}

uint64_t
SocketQPACKDecoderStream_get_stream_id (SocketQPACKDecoderStream_T stream)
{
  if (stream == NULL || stream->state != QPACK_DECODER_STREAM_STATE_OPEN)
    return 0;

  return stream->stream_id;
}

int
SocketQPACKDecoderStream_is_open (SocketQPACKDecoderStream_T stream)
{
  if (stream == NULL)
    return 0;

  return stream->state == QPACK_DECODER_STREAM_STATE_OPEN ? 1 : 0;
}

uint64_t
SocketQPACKDecoderStream_get_known_received_count (
    SocketQPACKDecoderStream_T stream)
{
  if (stream == NULL)
    return 0;

  return stream->known_received_count;
}

/* ============================================================================
 * Validation Functions
 * ============================================================================
 */

int
SocketQPACKDecoderStream_validate_stream_type (uint64_t stream_id)
{
  /* HTTP/3 unidirectional stream types are encoded in the first varint
   * on the stream, not in the stream ID itself. For validation purposes,
   * we check that this is a client-initiated unidirectional stream.
   *
   * Stream ID bits (RFC 9000):
   *   Bit 0: Initiator (0=client, 1=server)
   *   Bit 1: Direction (0=bidi, 1=uni)
   *
   * Client-initiated unidirectional: 0x2, 0x6, 0xA, ...
   * Server-initiated unidirectional: 0x3, 0x7, 0xB, ...
   *
   * For a decoder stream, the type (0x03) is sent at stream start,
   * so we just verify this is a unidirectional stream.
   */
  return (stream_id & 0x02) == 0x02 ? 1 : 0;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

const char *
SocketQPACKDecoderStream_state_string (SocketQPACKDecoderStreamState state)
{
  switch (state)
    {
    case QPACK_DECODER_STREAM_STATE_IDLE:
      return "IDLE";
    case QPACK_DECODER_STREAM_STATE_OPEN:
      return "OPEN";
    case QPACK_DECODER_STREAM_STATE_CLOSED:
      return "CLOSED";
    default:
      return "UNKNOWN";
    }
}

const char *
SocketQPACKDecoderStream_result_string (SocketQPACKDecoderStream_Result result)
{
  switch (result)
    {
    case QPACK_DECODER_STREAM_OK:
      return "OK";
    case QPACK_DECODER_STREAM_ERROR_NULL:
      return "ERROR_NULL";
    case QPACK_DECODER_STREAM_ERROR_INVALID_STATE:
      return "ERROR_INVALID_STATE";
    case QPACK_DECODER_STREAM_ERROR_BUFFER_FULL:
      return "ERROR_BUFFER_FULL";
    case QPACK_DECODER_STREAM_ERROR_DUPLICATE:
      return "ERROR_DUPLICATE";
    case QPACK_DECODER_STREAM_ERROR_CLOSED:
      return "ERROR_CLOSED";
    case QPACK_DECODER_STREAM_ERROR_INVALID_TYPE:
      return "ERROR_INVALID_TYPE";
    case QPACK_DECODER_STREAM_ERROR_ENCODE:
      return "ERROR_ENCODE";
    default:
      return "UNKNOWN";
    }
}
