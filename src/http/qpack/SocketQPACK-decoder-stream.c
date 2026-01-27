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

#include "http/qpack/SocketQPACK-private.h"
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

/* ============================================================================
 * DECODER INSTRUCTION DECODING (RFC 9204 Section 4.4)
 *
 * These functions decode decoder instructions received from the peer's
 * decoder stream. Used by the encoder to process acknowledgments.
 * ============================================================================
 */

SocketQPACK_DecoderInstrType
SocketQPACK_identify_decoder_instruction (uint8_t first_byte)
{
  /*
   * RFC 9204 Section 4.4: Decoder instruction identification
   *
   * Bit patterns:
   * - 1xxxxxxx: Section Acknowledgment (bit 7 set)
   * - 01xxxxxx: Stream Cancellation (bits 7-6 = 01)
   * - 00xxxxxx: Insert Count Increment (bits 7-6 = 00)
   */
  if ((first_byte & 0x80) != 0)
    return QPACK_DINSTR_TYPE_SECTION_ACK;

  if ((first_byte & 0xC0) == 0x40)
    return QPACK_DINSTR_TYPE_STREAM_CANCEL;

  if ((first_byte & 0xC0) == 0x00)
    return QPACK_DINSTR_TYPE_INSERT_COUNT_INC;

  return QPACK_DINSTR_TYPE_UNKNOWN;
}

SocketQPACKStream_Result
SocketQPACK_decode_section_ack (const unsigned char *input,
                                size_t input_len,
                                uint64_t *stream_id,
                                size_t *consumed)
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
   * Uses 7-bit prefix integer encoding for stream ID.
   */
  SocketHPACK_Result hpack_result;

  if (input == NULL || stream_id == NULL || consumed == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  *consumed = 0;

  /* Need at least one byte */
  if (input_len < 1)
    return QPACK_STREAM_ERR_BUFFER_FULL;

  /* Verify bit pattern (bit 7 must be set) */
  if ((input[0] & QPACK_DINSTR_SECTION_ACK_MASK)
      != QPACK_DINSTR_SECTION_ACK_MASK)
    return QPACK_STREAM_ERR_INTERNAL;

  /* Decode stream ID using 7-bit prefix integer */
  hpack_result = SocketHPACK_int_decode (
      input, input_len, QPACK_DINSTR_SECTION_ACK_PREFIX, stream_id, consumed);

  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_STREAM_ERR_BUFFER_FULL;

  if (hpack_result != HPACK_OK)
    return QPACK_STREAM_ERR_INTERNAL;

  return QPACK_STREAM_OK;
}

SocketQPACKStream_Result
SocketQPACK_decode_stream_cancel (const unsigned char *input,
                                  size_t input_len,
                                  uint64_t *stream_id,
                                  size_t *consumed)
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
   * Uses 6-bit prefix integer encoding for stream ID.
   */
  SocketHPACK_Result hpack_result;

  if (input == NULL || stream_id == NULL || consumed == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  *consumed = 0;

  /* Need at least one byte */
  if (input_len < 1)
    return QPACK_STREAM_ERR_BUFFER_FULL;

  /* Verify bit pattern (bits 7-6 must be 01) */
  if ((input[0] & 0xC0) != QPACK_DINSTR_STREAM_CANCEL_MASK)
    return QPACK_STREAM_ERR_INTERNAL;

  /* Decode stream ID using 6-bit prefix integer */
  hpack_result = SocketHPACK_int_decode (
      input, input_len, QPACK_DINSTR_STREAM_CANCEL_PREFIX, stream_id, consumed);

  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_STREAM_ERR_BUFFER_FULL;

  if (hpack_result != HPACK_OK)
    return QPACK_STREAM_ERR_INTERNAL;

  return QPACK_STREAM_OK;
}

SocketQPACKStream_Result
SocketQPACK_stream_cancel_validate_id (uint64_t stream_id)
{
  /*
   * RFC 9204 Section 4.4.2: Stream Cancellation validation
   *
   * Stream ID 0 is typically reserved for the connection control stream
   * in HTTP/3 and should not be cancelled via QPACK.
   */
  if (stream_id == 0)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  return QPACK_STREAM_OK;
}

SocketQPACKStream_Result
SocketQPACK_stream_cancel_release_refs (SocketQPACK_Table_T table,
                                        uint64_t stream_id)
{
  /*
   * RFC 9204 Section 4.4.2: Release dynamic table references
   *
   * When a Stream Cancellation is received, we need to release all
   * dynamic table references held by that stream.
   *
   * Conservative implementation (fixes #3477): Since per-stream reference
   * tracking is not yet implemented, we decrement ref_count on all entries
   * that have references. This may under-count but prevents stuck entries
   * that can never be evicted.
   *
   * TODO: Implement proper per-stream reference tracking for accurate
   * reference management.
   */
  (void)stream_id;

  if (table == NULL)
    return QPACK_STREAM_OK;

  /* Walk all entries and decrement ref_count for referenced entries */
  for (size_t i = 0; i < table->count; i++)
    {
      size_t idx = RINGBUF_WRAP (table->head + i, table->capacity);
      if (table->entries[idx].meta.ref_count > 0)
        {
          table->entries[idx].meta.ref_count--;
        }
    }

  return QPACK_STREAM_OK;
}

SocketQPACKStream_Result
SocketQPACK_decode_insert_count_inc (const unsigned char *input,
                                     size_t input_len,
                                     uint64_t *increment,
                                     size_t *consumed)
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
   * Uses 6-bit prefix integer encoding for increment.
   * An increment of 0 is an error (QPACK_DECOMPRESSION_FAILED).
   */
  SocketHPACK_Result hpack_result;

  if (input == NULL || increment == NULL || consumed == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  *consumed = 0;

  /* Need at least one byte */
  if (input_len < 1)
    return QPACK_STREAM_ERR_BUFFER_FULL;

  /* Verify bit pattern (bits 7-6 must be 00) */
  if ((input[0] & 0xC0) != 0x00)
    return QPACK_STREAM_ERR_INTERNAL;

  /* Decode increment using 6-bit prefix integer */
  hpack_result = SocketHPACK_int_decode (input,
                                         input_len,
                                         QPACK_DINSTR_INSERT_COUNT_INC_PREFIX,
                                         increment,
                                         consumed);

  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_STREAM_ERR_BUFFER_FULL;

  if (hpack_result != HPACK_OK)
    return QPACK_STREAM_ERR_INTERNAL;

  /* RFC 9204 Section 4.4.3: increment of 0 is an error */
  if (*increment == 0)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  return QPACK_STREAM_OK;
}

SocketQPACKStream_Result
SocketQPACK_encode_insert_count_inc (unsigned char *output,
                                     size_t output_size,
                                     uint64_t increment,
                                     size_t *bytes_written)
{
  /*
   * RFC 9204 Section 4.4.3: Insert Count Increment
   *
   * Bit pattern: 00xxxxxx (0x00 mask)
   * The 6-bit prefix encodes the increment value.
   */
  size_t int_len;

  if (output == NULL || bytes_written == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  *bytes_written = 0;

  if (increment == 0)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  int_len = SocketHPACK_int_encode (
      increment, QPACK_DINSTR_INSERT_COUNT_INC_PREFIX, output, output_size);
  if (int_len == 0)
    return QPACK_STREAM_ERR_BUFFER_FULL;

  *bytes_written = int_len;
  return QPACK_STREAM_OK;
}

SocketQPACKStream_Result
SocketQPACK_apply_insert_count_inc (uint64_t *known_received_count,
                                    uint64_t insert_count,
                                    uint64_t increment)
{
  /*
   * RFC 9204 Section 4.4.3: Insert Count Increment
   *
   * Updates the Known Received Count based on the received increment.
   */
  uint64_t new_count;

  if (known_received_count == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  if (increment == 0)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  if (increment > UINT64_MAX - *known_received_count)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  new_count = *known_received_count + increment;

  if (new_count > insert_count)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  *known_received_count = new_count;
  return QPACK_STREAM_OK;
}

SocketQPACKStream_Result
SocketQPACK_validate_insert_count_inc (uint64_t known_received_count,
                                       uint64_t insert_count,
                                       uint64_t increment)
{
  /*
   * RFC 9204 Section 4.4.3: Validate increment value
   */
  uint64_t new_count;

  if (increment == 0)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  if (increment > UINT64_MAX - known_received_count)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  new_count = known_received_count + increment;

  if (new_count > insert_count)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  return QPACK_STREAM_OK;
}

SocketQPACKStream_Result
SocketQPACK_decode_decoder_instruction (const unsigned char *input,
                                        size_t input_len,
                                        SocketQPACK_DecoderInstruction *instr,
                                        size_t *consumed)
{
  SocketQPACK_DecoderInstrType type;
  SocketQPACKStream_Result result;

  if (instr == NULL || consumed == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  *consumed = 0;
  instr->type = QPACK_DINSTR_TYPE_UNKNOWN;
  instr->value = 0;

  if (input_len < 1)
    return QPACK_STREAM_ERR_BUFFER_FULL;

  type = SocketQPACK_identify_decoder_instruction (input[0]);

  switch (type)
    {
    case QPACK_DINSTR_TYPE_SECTION_ACK:
      result = SocketQPACK_decode_section_ack (
          input, input_len, &instr->value, consumed);
      break;

    case QPACK_DINSTR_TYPE_STREAM_CANCEL:
      result = SocketQPACK_decode_stream_cancel (
          input, input_len, &instr->value, consumed);
      break;

    case QPACK_DINSTR_TYPE_INSERT_COUNT_INC:
      result = SocketQPACK_decode_insert_count_inc (
          input, input_len, &instr->value, consumed);
      break;

    default:
      return QPACK_STREAM_ERR_INTERNAL;
    }

  if (result == QPACK_STREAM_OK)
    instr->type = type;

  return result;
}

/* ============================================================================
 * ACKNOWLEDGMENT STATE MANAGEMENT (RFC 9204 Section 3.3)
 *
 * Simple hash table to track pending stream RICs and Known Received Count.
 * ============================================================================
 */

/** Default capacity for pending stream tracking (power of 2) */
#define QPACK_ACK_STATE_DEFAULT_CAPACITY 64

/** Maximum pending streams (to prevent unbounded growth) */
#define QPACK_ACK_STATE_MAX_PENDING 4096

/** Hash table entry for tracking stream RIC */
typedef struct
{
  uint64_t stream_id;             /**< Stream ID (0 = empty slot) */
  uint64_t required_insert_count; /**< RIC for this stream */
  int occupied;                   /**< Is this slot occupied? */
} QPACKPendingEntry;

/**
 * @brief QPACK acknowledgment state internal structure.
 */
struct SocketQPACK_AckState
{
  Arena_T arena;                 /**< Memory arena for allocations */
  uint64_t known_received_count; /**< Known Received Count (KRC) */
  QPACKPendingEntry *pending;    /**< Hash table of pending stream RICs */
  size_t pending_capacity;       /**< Hash table capacity */
  size_t pending_count;          /**< Number of occupied entries */
};

/**
 * @brief Hash function for stream ID.
 */
static inline size_t
hash_stream_id (uint64_t stream_id, size_t capacity)
{
  uint64_t hash = stream_id * 0x9E3779B97F4A7C15ULL;
  return (size_t)(hash & (capacity - 1));
}

/** Maximum probes to prevent hash collision DoS (fixes #3464) */
#define QPACK_ACK_STATE_MAX_PROBES 16

/**
 * @brief Find slot for stream ID in hash table.
 *
 * Limits probe count to prevent algorithmic complexity attacks via
 * hash collisions (fixes #3464).
 *
 * @return true if found, false if not found or probe limit exceeded
 */
static bool
find_pending_slot (SocketQPACK_AckState_T state,
                   uint64_t stream_id,
                   size_t *idx)
{
  size_t start = hash_stream_id (stream_id, state->pending_capacity);
  size_t i = start;
  size_t probes = 0;

  do
    {
      /* Limit probes to prevent hash collision DoS */
      if (++probes > QPACK_ACK_STATE_MAX_PROBES)
        {
          *idx = start;
          return false;
        }

      QPACKPendingEntry *entry = &state->pending[i];

      if (!entry->occupied)
        {
          *idx = i;
          return false;
        }

      if (entry->stream_id == stream_id)
        {
          *idx = i;
          return true;
        }

      i = (i + 1) & (state->pending_capacity - 1);
    }
  while (i != start);

  *idx = start;
  return false;
}

SocketQPACK_AckState_T
SocketQPACK_AckState_new (Arena_T arena)
{
  SocketQPACK_AckState_T state;

  if (arena == NULL)
    return NULL;

  state = CALLOC (arena, 1, sizeof (*state));
  if (state == NULL)
    return NULL;

  state->arena = arena;
  state->known_received_count = 0;
  state->pending_count = 0;

  state->pending_capacity = QPACK_ACK_STATE_DEFAULT_CAPACITY;
  state->pending
      = CALLOC (arena, state->pending_capacity, sizeof (QPACKPendingEntry));
  if (state->pending == NULL)
    return NULL;

  return state;
}

SocketQPACKStream_Result
SocketQPACK_AckState_register_section (SocketQPACK_AckState_T state,
                                       uint64_t stream_id,
                                       uint64_t required_insert_count)
{
  size_t idx;
  bool found;

  if (state == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  if (required_insert_count == 0)
    return QPACK_STREAM_OK;

  if (state->pending_count >= (state->pending_capacity * 3 / 4))
    {
      if (state->pending_capacity >= QPACK_ACK_STATE_MAX_PENDING)
        return QPACK_STREAM_ERR_BUFFER_FULL;
    }

  found = find_pending_slot (state, stream_id, &idx);

  if (found)
    {
      if (required_insert_count > state->pending[idx].required_insert_count)
        state->pending[idx].required_insert_count = required_insert_count;
    }
  else
    {
      state->pending[idx].stream_id = stream_id;
      state->pending[idx].required_insert_count = required_insert_count;
      state->pending[idx].occupied = 1;
      state->pending_count++;
    }

  return QPACK_STREAM_OK;
}

SocketQPACKStream_Result
SocketQPACK_AckState_process_section_ack (SocketQPACK_AckState_T state,
                                          uint64_t stream_id,
                                          uint64_t insert_count)
{
  size_t idx;
  bool found;
  uint64_t ric;

  if (state == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  found = find_pending_slot (state, stream_id, &idx);

  if (!found)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  ric = state->pending[idx].required_insert_count;

  /*
   * Validate RIC against current Insert Count (fixes #3483).
   *
   * If stored RIC exceeds insert_count, this indicates state corruption
   * or extreme edge cases (e.g., counter wrap). Cap to insert_count to
   * prevent KRC from exceeding valid range while still allowing the
   * acknowledgment to proceed.
   */
  if (ric > insert_count)
    ric = insert_count;

  if (ric > state->known_received_count)
    state->known_received_count = ric;

  state->pending[idx].occupied = 0;
  state->pending[idx].stream_id = 0;
  state->pending[idx].required_insert_count = 0;
  state->pending_count--;

  return QPACK_STREAM_OK;
}

SocketQPACKStream_Result
SocketQPACK_AckState_process_stream_cancel (SocketQPACK_AckState_T state,
                                            uint64_t stream_id)
{
  size_t idx;
  bool found;

  if (state == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  found = find_pending_slot (state, stream_id, &idx);

  if (found)
    {
      state->pending[idx].occupied = 0;
      state->pending[idx].stream_id = 0;
      state->pending[idx].required_insert_count = 0;
      state->pending_count--;
    }

  return QPACK_STREAM_OK;
}

SocketQPACKStream_Result
SocketQPACK_AckState_process_insert_count_inc (SocketQPACK_AckState_T state,
                                               uint64_t increment)
{
  uint64_t new_krc;

  if (state == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  if (increment == 0)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  /*
   * RFC 9204 Section 4.4.3: Overflow in Known Received Count calculation
   * is a decoder stream error. Do NOT saturate - return error (fixes #3460).
   */
  if (!SocketSecurity_check_add (
          state->known_received_count, increment, &new_krc))
    {
      return QPACK_STREAM_ERR_INVALID_INDEX;
    }

  state->known_received_count = new_krc;

  return QPACK_STREAM_OK;
}

uint64_t
SocketQPACK_AckState_get_known_received_count (SocketQPACK_AckState_T state)
{
  if (state == NULL)
    return 0;

  return state->known_received_count;
}

bool
SocketQPACK_AckState_can_evict (SocketQPACK_AckState_T state,
                                uint64_t abs_index)
{
  if (state == NULL)
    return false;

  return abs_index < state->known_received_count;
}

/* ============================================================================
 * DECODER SYNCHRONIZATION STATE (RFC 9204 Section 2.2.2)
 *
 * Manages automatic generation of decoder instructions:
 * - Section Acknowledgment (2.2.2.1) - after decoding field sections
 * - Stream Cancellation (2.2.2.2) - on stream reset
 * - Insert Count Increment (2.2.2.3) - on encoder stream updates
 * ============================================================================
 */

/** Default coalescing threshold (emit after each entry for timely feedback) */
#define QPACK_DECODER_SYNC_DEFAULT_THRESHOLD 1

/**
 * @brief Decoder synchronization state internal structure.
 */
struct SocketQPACK_DecoderSync
{
  Arena_T arena;
  SocketQPACK_DecoderStream_T decoder_stream;

  /* Insert count tracking for coalescing (RFC 9204 Section 2.2.2.3) */
  uint64_t local_insert_count;      /**< Decoder's view of insert count */
  uint64_t last_communicated_count; /**< Last sent via Insert Count Increment */
  uint64_t coalesce_threshold;      /**< Threshold before auto-emit */
};

SocketQPACK_DecoderSync_T
SocketQPACK_DecoderSync_new (Arena_T arena,
                             SocketQPACK_DecoderStream_T decoder_stream)
{
  SocketQPACK_DecoderSync_T sync;

  if (arena == NULL || decoder_stream == NULL)
    return NULL;

  sync = CALLOC (arena, 1, sizeof (*sync));
  if (sync == NULL)
    return NULL;

  sync->arena = arena;
  sync->decoder_stream = decoder_stream;
  sync->local_insert_count = 0;
  sync->last_communicated_count = 0;
  sync->coalesce_threshold = QPACK_DECODER_SYNC_DEFAULT_THRESHOLD;

  return sync;
}

SocketQPACKStream_Result
SocketQPACK_DecoderSync_on_section_decoded (SocketQPACK_DecoderSync_T sync,
                                            uint64_t stream_id,
                                            uint64_t required_insert_count)
{
  /*
   * RFC 9204 Section 2.2.2.1: Section Acknowledgment
   *
   * "After processing an encoded field section whose declared Required
   * Insert Count is not zero, the decoder MUST emit a Section
   * Acknowledgment instruction."
   */
  if (sync == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  /* No acknowledgment needed for sections that don't reference dynamic table */
  if (required_insert_count == 0)
    return QPACK_STREAM_OK;

  return SocketQPACK_DecoderStream_write_section_ack (sync->decoder_stream,
                                                      stream_id);
}

SocketQPACKStream_Result
SocketQPACK_DecoderSync_on_stream_reset (SocketQPACK_DecoderSync_T sync,
                                         uint64_t stream_id)
{
  /*
   * RFC 9204 Section 2.2.2.2: Stream Cancellation
   *
   * "When an endpoint receives a stream reset before the end of a stream
   * or before all encoded field sections are processed...the decoder emits
   * a Stream Cancellation instruction."
   */
  if (sync == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  return SocketQPACK_DecoderStream_write_stream_cancel (sync->decoder_stream,
                                                        stream_id);
}

SocketQPACKStream_Result
SocketQPACK_DecoderSync_on_insert_received (SocketQPACK_DecoderSync_T sync,
                                            uint64_t count)
{
  /*
   * RFC 9204 Section 2.2.2.3: Insert Count Increment
   *
   * "After receiving new table entries on the encoder stream, the decoder
   * chooses when to emit Insert Count Increment instructions."
   *
   * We support coalescing: emit when (local - communicated) >= threshold.
   */
  uint64_t pending;
  SocketQPACKStream_Result result;

  if (sync == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  /* Track the new entries */
  if (!SocketSecurity_check_add (
          sync->local_insert_count, count, &sync->local_insert_count))
    {
      /* Overflow - saturate at UINT64_MAX */
      sync->local_insert_count = UINT64_MAX;
    }

  /* Check if we should emit based on coalescing threshold */
  pending = sync->local_insert_count - sync->last_communicated_count;
  if (pending >= sync->coalesce_threshold)
    {
      result = SocketQPACK_DecoderStream_write_insert_count_inc (
          sync->decoder_stream, pending);
      if (result != QPACK_STREAM_OK)
        return result;

      sync->last_communicated_count = sync->local_insert_count;
    }

  return QPACK_STREAM_OK;
}

SocketQPACKStream_Result
SocketQPACK_DecoderSync_flush (SocketQPACK_DecoderSync_T sync)
{
  /*
   * Force emit any pending Insert Count Increment.
   * This is useful before sending a response or when the application
   * needs to ensure the encoder knows about received entries.
   */
  uint64_t pending;
  SocketQPACKStream_Result result;

  if (sync == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  pending = sync->local_insert_count - sync->last_communicated_count;
  if (pending == 0)
    return QPACK_STREAM_OK; /* Nothing to flush */

  result = SocketQPACK_DecoderStream_write_insert_count_inc (
      sync->decoder_stream, pending);
  if (result != QPACK_STREAM_OK)
    return result;

  sync->last_communicated_count = sync->local_insert_count;

  return QPACK_STREAM_OK;
}

uint64_t
SocketQPACK_DecoderSync_get_insert_count (SocketQPACK_DecoderSync_T sync)
{
  if (sync == NULL)
    return 0;

  return sync->local_insert_count;
}

uint64_t
SocketQPACK_DecoderSync_get_acknowledged_count (SocketQPACK_DecoderSync_T sync)
{
  if (sync == NULL)
    return 0;

  return sync->last_communicated_count;
}

SocketQPACKStream_Result
SocketQPACK_DecoderSync_set_coalesce_threshold (SocketQPACK_DecoderSync_T sync,
                                                uint64_t threshold)
{
  if (sync == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  /* Threshold of 0 doesn't make sense - would never emit */
  if (threshold == 0)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  sync->coalesce_threshold = threshold;

  return QPACK_STREAM_OK;
}

uint64_t
SocketQPACK_DecoderSync_get_coalesce_threshold (SocketQPACK_DecoderSync_T sync)
{
  if (sync == NULL)
    return 0;

  return sync->coalesce_threshold;
}
