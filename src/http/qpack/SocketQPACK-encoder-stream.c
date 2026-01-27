/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-encoder-stream.c
 * @brief QPACK Encoder Stream Infrastructure (RFC 9204 Section 4.2)
 *
 * Implements the encoder stream for QPACK, which carries encoder instructions
 * from encoder to decoder. The encoder stream is a unidirectional stream of
 * type 0x02.
 *
 * Encoder Instructions (RFC 9204 Section 4.3):
 * - Set Dynamic Table Capacity (Section 4.3.1)
 * - Insert with Name Reference (Section 4.3.2)
 * - Insert with Literal Name (Section 4.3.3)
 * - Duplicate (Section 4.3.4)
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-4.2
 */

#include <string.h>

#include "http/qpack/SocketQPACKEncoderStream.h"

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
 * @brief QPACK encoder stream internal structure.
 */
struct SocketQPACK_EncoderStream
{
  Arena_T arena;         /**< Memory arena for allocations */
  uint64_t stream_id;    /**< QUIC unidirectional stream ID */
  uint64_t max_capacity; /**< Maximum dynamic table capacity (decoder limit) */
  unsigned char *buffer; /**< Instruction buffer */
  size_t buffer_len;     /**< Current data length in buffer */
  size_t buffer_cap;     /**< Buffer capacity */
  int initialized;       /**< Has stream been initialized? */
};

/* ============================================================================
 * RESULT STRINGS
 * ============================================================================
 */

static const char *const stream_result_strings[] = {
  [QPACK_STREAM_OK] = "OK",
  [QPACK_STREAM_ERR_BUFFER_FULL] = "Instruction buffer full",
  [QPACK_STREAM_ERR_ALREADY_INIT] = "Stream already initialized",
  [QPACK_STREAM_ERR_NOT_INIT] = "Stream not initialized",
  [QPACK_STREAM_ERR_INVALID_TYPE] = "Invalid stream type",
  [QPACK_STREAM_ERR_CLOSED_CRITICAL] = "Critical stream closed (H3 0x0104)",
  [QPACK_STREAM_ERR_NULL_PARAM] = "NULL parameter",
  [QPACK_STREAM_ERR_INVALID_INDEX] = "Invalid table index",
  [QPACK_STREAM_ERR_CAPACITY_EXCEED] = "Capacity exceeds maximum",
  [QPACK_STREAM_ERR_INTERNAL] = "Internal error",
};

const char *
SocketQPACKStream_result_string (SocketQPACKStream_Result result)
{
  if (result >= 0 && (size_t)result < ARRAY_LENGTH (stream_result_strings)
      && stream_result_strings[result] != NULL)
    {
      return stream_result_strings[result];
    }
  return "Unknown error";
}

/* ============================================================================
 * HTTP/3 ERROR CODE MAPPING (RFC 9204 Section 4.2 & 6)
 * ============================================================================
 */

uint64_t
SocketQPACKStream_result_to_h3_error (SocketQPACKStream_Result result)
{
  /*
   * RFC 9204 Section 4.2: Stream error to HTTP/3 error mapping:
   * - Closure of encoder/decoder stream -> H3_CLOSED_CRITICAL_STREAM (0x0104)
   * - Receipt of second instance of stream type -> H3_STREAM_CREATION_ERROR
   * (0x0103)
   *
   * RFC 9204 Section 6: Other errors map to QPACK_ENCODER_STREAM_ERROR (0x0201)
   * for encoder stream issues.
   */
  switch (result)
    {
    case QPACK_STREAM_OK:
      /* Not an error - return 0 to indicate no H3 error needed */
      return 0;

    case QPACK_STREAM_ERR_CLOSED_CRITICAL:
      /*
       * RFC 9204 Section 4.2: "Closure of either the send or receive side
       * of the encoder stream by either endpoint MUST be treated as a
       * connection error of type H3_CLOSED_CRITICAL_STREAM."
       */
      return H3_CLOSED_CRITICAL_STREAM;

    case QPACK_STREAM_ERR_ALREADY_INIT:
      /*
       * RFC 9204 Section 4.2: "Each endpoint MUST initiate, at most, one
       * encoder stream and one decoder stream. Receipt of a second instance
       * of either stream type MUST be treated as a connection error of type
       * H3_STREAM_CREATION_ERROR."
       */
      return H3_STREAM_CREATION_ERROR;

    case QPACK_STREAM_ERR_BUFFER_FULL:
    case QPACK_STREAM_ERR_NOT_INIT:
    case QPACK_STREAM_ERR_INVALID_TYPE:
    case QPACK_STREAM_ERR_NULL_PARAM:
    case QPACK_STREAM_ERR_INVALID_INDEX:
    case QPACK_STREAM_ERR_CAPACITY_EXCEED:
    case QPACK_STREAM_ERR_INTERNAL:
    default:
      /*
       * RFC 9204 Section 6: Other encoder stream errors are treated as
       * QPACK_ENCODER_STREAM_ERROR.
       */
      return QPACK_ENCODER_STREAM_ERROR;
    }
}

/* ============================================================================
 * BUFFER MANAGEMENT (INTERNAL)
 * ============================================================================
 */

/**
 * @brief Ensure buffer has at least required_space additional bytes.
 *
 * @param stream  Encoder stream
 * @param required_space Additional bytes needed
 * @return QPACK_STREAM_OK on success, error code on failure
 */
static SocketQPACKStream_Result
ensure_buffer_space (SocketQPACK_EncoderStream_T stream, size_t required_space)
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
  if (new_cap > QPACK_ENCODER_STREAM_MAX_BUFSIZE)
    {
      /* Try exact fit if growth exceeds max */
      if (needed > QPACK_ENCODER_STREAM_MAX_BUFSIZE)
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
 * @param stream Encoder stream
 * @param data   Data to append
 * @param len    Length of data
 * @return QPACK_STREAM_OK on success, error code on failure
 */
static SocketQPACKStream_Result
append_to_buffer (SocketQPACK_EncoderStream_T stream,
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
 * @param stream      Encoder stream
 * @param value       Integer value to encode
 * @param prefix_bits Number of prefix bits (1-8)
 * @param first_byte  First byte with flags already set (integer fills lower
 * bits)
 * @return QPACK_STREAM_OK on success, error code on failure
 */
static SocketQPACKStream_Result
encode_and_append_int (SocketQPACK_EncoderStream_T stream,
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
 * STRING ENCODING (INTERNAL)
 *
 * Uses HPACK string literal encoding (RFC 7541 Section 5.2).
 * ============================================================================
 */

/**
 * @brief Encode a Huffman-compressed string to buffer.
 */
static SocketQPACKStream_Result
encode_huffman_string (unsigned char *buf,
                       size_t buf_size,
                       const unsigned char *str,
                       size_t len,
                       size_t huffman_len,
                       size_t *out_len)
{
  size_t prefix_len;
  ssize_t huff_result;

  /* Encode length with H=1 flag */
  prefix_len = SocketHPACK_int_encode (
      huffman_len, QPACK_VALUE_LENGTH_PREFIX, buf, QPACK_INT_ENCODE_BUF_SIZE);
  if (prefix_len == 0)
    return QPACK_STREAM_ERR_INTERNAL;

  buf[0] |= QPACK_VALUE_HUFFMAN_MASK;

  /* Huffman-encode the string */
  huff_result = SocketHPACK_huffman_encode (
      str, len, buf + prefix_len, buf_size - prefix_len);
  if (huff_result < 0)
    return QPACK_STREAM_ERR_INTERNAL;

  *out_len = prefix_len + (size_t)huff_result;
  return QPACK_STREAM_OK;
}

/**
 * @brief Encode a literal (non-Huffman) string to buffer.
 */
static SocketQPACKStream_Result
encode_literal_string (unsigned char *buf,
                       const unsigned char *str,
                       size_t len,
                       size_t *out_len)
{
  size_t prefix_len;

  /* Encode length with H=0 flag */
  prefix_len = SocketHPACK_int_encode (
      len, QPACK_VALUE_LENGTH_PREFIX, buf, QPACK_INT_ENCODE_BUF_SIZE);
  if (prefix_len == 0)
    return QPACK_STREAM_ERR_INTERNAL;

  /* Clear H flag (should already be 0, but be explicit) */
  buf[0] &= ~QPACK_VALUE_HUFFMAN_MASK;

  /* Copy literal string (skip memcpy if empty to avoid UB with NULL) */
  if (len > 0)
    memcpy (buf + prefix_len, str, len);

  *out_len = prefix_len + len;
  return QPACK_STREAM_OK;
}

/**
 * @brief Encode a string literal and append to buffer.
 *
 * @param stream      Encoder stream
 * @param str         String data
 * @param len         String length
 * @param use_huffman true to Huffman-encode (if beneficial)
 * @return QPACK_STREAM_OK on success, error code on failure
 */
static SocketQPACKStream_Result
encode_and_append_string (SocketQPACK_EncoderStream_T stream,
                          const unsigned char *str,
                          size_t len,
                          bool use_huffman)
{
  unsigned char *temp_buf;
  size_t temp_buf_size;
  size_t encoded_len;
  size_t huffman_len = 0;
  bool actually_use_huffman = false;
  SocketQPACKStream_Result result;

  /* Determine if Huffman encoding is beneficial */
  if (use_huffman && len > 0)
    {
      huffman_len = SocketHPACK_huffman_encoded_size (str, len);
      if (huffman_len < len)
        actually_use_huffman = true;
    }

  /* Calculate required buffer size: length prefix + string data */
  size_t data_len = actually_use_huffman ? huffman_len : len;
  if (!SocketSecurity_check_add (
          QPACK_INT_ENCODE_BUF_SIZE, data_len, &temp_buf_size))
    return QPACK_STREAM_ERR_BUFFER_FULL;

  /* Ensure we have space */
  result = ensure_buffer_space (stream, temp_buf_size);
  if (result != QPACK_STREAM_OK)
    return result;

  /* Use arena for temp buffer to avoid stack overflow with large strings */
  temp_buf = ALLOC (stream->arena, temp_buf_size);
  if (temp_buf == NULL)
    return QPACK_STREAM_ERR_INTERNAL;

  /* Encode string (Huffman or literal) */
  if (actually_use_huffman)
    result = encode_huffman_string (
        temp_buf, temp_buf_size, str, len, huffman_len, &encoded_len);
  else
    result = encode_literal_string (temp_buf, str, len, &encoded_len);

  if (result != QPACK_STREAM_OK)
    return result;

  return append_to_buffer (stream, temp_buf, encoded_len);
}

/* ============================================================================
 * LIFECYCLE FUNCTIONS
 * ============================================================================
 */

SocketQPACK_EncoderStream_T
SocketQPACK_EncoderStream_new (Arena_T arena,
                               uint64_t stream_id,
                               uint64_t max_capacity)
{
  SocketQPACK_EncoderStream_T stream;

  if (arena == NULL)
    return NULL;

  stream = CALLOC (arena, 1, sizeof (*stream));
  if (stream == NULL)
    return NULL;

  stream->arena = arena;
  stream->stream_id = stream_id;
  stream->max_capacity = max_capacity;
  stream->initialized = 0;
  stream->buffer_len = 0;

  /* Pre-allocate initial buffer */
  stream->buffer_cap = QPACK_ENCODER_STREAM_DEFAULT_BUFSIZE;
  stream->buffer = ALLOC (arena, stream->buffer_cap);
  if (stream->buffer == NULL)
    return NULL;

  return stream;
}

SocketQPACKStream_Result
SocketQPACK_EncoderStream_init (SocketQPACK_EncoderStream_T stream)
{
  if (stream == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  if (stream->initialized)
    return QPACK_STREAM_ERR_ALREADY_INIT;

  stream->initialized = 1;
  return QPACK_STREAM_OK;
}

SocketQPACKStream_Result
SocketQPACK_EncoderStream_validate_type (uint8_t type_byte)
{
  if (type_byte == QPACK_ENCODER_STREAM_TYPE)
    return QPACK_STREAM_OK;

  return QPACK_STREAM_ERR_INVALID_TYPE;
}

bool
SocketQPACK_EncoderStream_is_open (SocketQPACK_EncoderStream_T stream)
{
  if (stream == NULL)
    return false;

  return stream->initialized != 0;
}

uint64_t
SocketQPACK_EncoderStream_get_id (SocketQPACK_EncoderStream_T stream)
{
  if (stream == NULL)
    return 0;

  return stream->stream_id;
}

/* ============================================================================
 * ENCODER INSTRUCTIONS (RFC 9204 Section 4.3)
 * ============================================================================
 */

SocketQPACKStream_Result
SocketQPACK_EncoderStream_write_capacity (SocketQPACK_EncoderStream_T stream,
                                          uint64_t capacity)
{
  /*
   * RFC 9204 Section 4.3.1: Set Dynamic Table Capacity
   *
   *   0   1   2   3   4   5   6   7
   * +---+---+---+---+---+---+---+---+
   * | 0 | 0 | 1 |   Capacity (5+)   |
   * +---+---+---+-------------------+
   *
   * Bit pattern: 001xxxxx (0x20 mask)
   */
  if (stream == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  if (!stream->initialized)
    return QPACK_STREAM_ERR_NOT_INIT;

  /* Capacity must not exceed decoder-advertised maximum */
  if (capacity > stream->max_capacity)
    return QPACK_STREAM_ERR_CAPACITY_EXCEED;

  return encode_and_append_int (stream,
                                capacity,
                                QPACK_INSTR_SET_CAPACITY_PREFIX,
                                QPACK_INSTR_SET_CAPACITY_MASK);
}

SocketQPACKStream_Result
SocketQPACK_EncoderStream_write_insert_nameref (
    SocketQPACK_EncoderStream_T stream,
    bool is_static,
    uint64_t name_index,
    const unsigned char *value,
    size_t value_len,
    bool use_huffman)
{
  /*
   * RFC 9204 Section 4.3.2: Insert with Name Reference
   *
   *   0   1   2   3   4   5   6   7
   * +---+---+---+---+---+---+---+---+
   * | 1 | T |    Name Index (6+)    |
   * +---+---+-----------------------+
   * | H |     Value Length (7+)     |
   * +---+---------------------------+
   * |  Value String (Length bytes)  |
   * +-------------------------------+
   *
   * T=1: Name from static table (index is static table index)
   * T=0: Name from dynamic table (index is encoder-relative)
   */
  unsigned char first_byte;
  SocketQPACKStream_Result result;

  if (stream == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  if (!stream->initialized)
    return QPACK_STREAM_ERR_NOT_INIT;

  if (value == NULL && value_len > 0)
    return QPACK_STREAM_ERR_NULL_PARAM;

  /* Validate static table index (0-98 per RFC 9204 Appendix A) */
  if (is_static && name_index >= SOCKETQPACK_STATIC_TABLE_SIZE)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  /* Build first byte: 1 | T | index... */
  first_byte = QPACK_INSTR_INSERT_NAMEREF_MASK; /* bit 7 = 1 */
  if (is_static)
    first_byte |= QPACK_INSTR_INSERT_NAMEREF_STATIC; /* bit 6 = T */

  /* Encode name index */
  result = encode_and_append_int (
      stream, name_index, QPACK_INSTR_INSERT_NAMEREF_PREFIX, first_byte);
  if (result != QPACK_STREAM_OK)
    return result;

  /* Encode value string */
  return encode_and_append_string (stream, value, value_len, use_huffman);
}

SocketQPACKStream_Result
SocketQPACK_EncoderStream_write_insert_literal (
    SocketQPACK_EncoderStream_T stream,
    const unsigned char *name,
    size_t name_len,
    bool name_huffman,
    const unsigned char *value,
    size_t value_len,
    bool value_huffman)
{
  /*
   * RFC 9204 Section 4.3.3: Insert with Literal Name
   *
   *   0   1   2   3   4   5   6   7
   * +---+---+---+---+---+---+---+---+
   * | 0 | 1 | H | Name Length (5+)  |
   * +---+---+---+-------------------+
   * |  Name String (Length bytes)   |
   * +---+---------------------------+
   * | H |     Value Length (7+)     |
   * +---+---------------------------+
   * |  Value String (Length bytes)  |
   * +-------------------------------+
   *
   * Bit pattern: 01Hxxxxx
   * H bit indicates if name is Huffman-encoded
   */
  unsigned char first_byte;
  size_t name_encoded_len;
  SocketQPACKStream_Result result;
  bool actually_huffman_name = false;

  if (stream == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  if (!stream->initialized)
    return QPACK_STREAM_ERR_NOT_INIT;

  if ((name == NULL && name_len > 0) || (value == NULL && value_len > 0))
    return QPACK_STREAM_ERR_NULL_PARAM;

  /* Determine if Huffman encoding is beneficial for name */
  if (name_huffman && name_len > 0)
    {
      size_t huff_len = SocketHPACK_huffman_encoded_size (name, name_len);
      if (huff_len < name_len)
        {
          actually_huffman_name = true;
          name_encoded_len = huff_len;
        }
      else
        {
          name_encoded_len = name_len;
        }
    }
  else
    {
      name_encoded_len = name_len;
    }

  /* Build first byte: 01 | H | length... */
  first_byte = QPACK_INSTR_INSERT_LITERAL_MASK; /* bits 7-6 = 01 */
  if (actually_huffman_name)
    first_byte |= QPACK_INSTR_INSERT_LITERAL_HUFFMAN; /* bit 5 = H */

  /* Encode name length with prefix */
  result = encode_and_append_int (
      stream, name_encoded_len, QPACK_INSTR_INSERT_LITERAL_PREFIX, first_byte);
  if (result != QPACK_STREAM_OK)
    return result;

  /* Encode name string */
  if (actually_huffman_name)
    {
      /* Huffman-encode name directly to buffer */
      size_t needed;
      if (!SocketSecurity_check_add (
              stream->buffer_len, name_encoded_len, &needed))
        return QPACK_STREAM_ERR_BUFFER_FULL;

      result = ensure_buffer_space (stream, name_encoded_len);
      if (result != QPACK_STREAM_OK)
        return result;

      ssize_t huff_result = SocketHPACK_huffman_encode (
          name,
          name_len,
          stream->buffer + stream->buffer_len,
          stream->buffer_cap - stream->buffer_len);
      if (huff_result < 0)
        return QPACK_STREAM_ERR_INTERNAL;

      stream->buffer_len += (size_t)huff_result;
    }
  else
    {
      /* Copy literal name */
      result = append_to_buffer (stream, name, name_len);
      if (result != QPACK_STREAM_OK)
        return result;
    }

  /* Encode value string (with its own H flag) */
  return encode_and_append_string (stream, value, value_len, value_huffman);
}

SocketQPACKStream_Result
SocketQPACK_EncoderStream_write_duplicate (SocketQPACK_EncoderStream_T stream,
                                           uint64_t rel_index)
{
  /*
   * RFC 9204 Section 4.3.4: Duplicate
   *
   *   0   1   2   3   4   5   6   7
   * +---+---+---+---+---+---+---+---+
   * | 0 | 0 | 0 |    Index (5+)     |
   * +---+---+---+-------------------+
   *
   * Bit pattern: 000xxxxx (0x00 mask)
   * Index is encoder-relative (0 = most recently inserted)
   */
  if (stream == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  if (!stream->initialized)
    return QPACK_STREAM_ERR_NOT_INIT;

  /* Note: We don't validate rel_index here because we don't track
   * the dynamic table state. The caller (encoder) is responsible
   * for ensuring rel_index is valid. */

  return encode_and_append_int (stream,
                                rel_index,
                                QPACK_INSTR_DUPLICATE_PREFIX,
                                QPACK_INSTR_DUPLICATE_MASK);
}

/* ============================================================================
 * BUFFER MANAGEMENT
 * ============================================================================
 */

const unsigned char *
SocketQPACK_EncoderStream_get_buffer (SocketQPACK_EncoderStream_T stream,
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
SocketQPACK_EncoderStream_reset_buffer (SocketQPACK_EncoderStream_T stream)
{
  if (stream == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  stream->buffer_len = 0;
  return QPACK_STREAM_OK;
}

size_t
SocketQPACK_EncoderStream_buffer_size (SocketQPACK_EncoderStream_T stream)
{
  if (stream == NULL)
    return 0;

  return stream->buffer_len;
}

/* ============================================================================
 * INSERT WITH NAME REFERENCE PRIMITIVES (RFC 9204 Section 4.3.2)
 * ============================================================================
 */

SocketQPACKStream_Result
SocketQPACK_encode_insert_nameref (unsigned char *output,
                                   size_t output_size,
                                   bool is_static,
                                   uint64_t name_index,
                                   const unsigned char *value,
                                   size_t value_len,
                                   bool use_huffman,
                                   size_t *bytes_written)
{
  /*
   * RFC 9204 Section 4.3.2: Insert with Name Reference
   *
   *   0   1   2   3   4   5   6   7
   * +---+---+---+---+---+---+---+---+
   * | 1 | T |    Name Index (6+)    |
   * +---+---+-----------------------+
   * | H |     Value Length (7+)     |
   * +---+---------------------------+
   * |  Value String (Length bytes)  |
   * +-------------------------------+
   */
  unsigned char int_buf[QPACK_INT_ENCODE_BUF_SIZE];
  size_t pos = 0;
  size_t int_len;
  unsigned char first_byte;
  size_t huffman_len = 0;
  bool actually_use_huffman = false;

  /* Parameter validation */
  if (output == NULL || bytes_written == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  if (value == NULL && value_len > 0)
    return QPACK_STREAM_ERR_NULL_PARAM;

  /* Validate static table index (0-98 per RFC 9204 Appendix A) */
  if (is_static && name_index >= SOCKETQPACK_STATIC_TABLE_SIZE)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  *bytes_written = 0;

  /* Build first byte: 1 | T | index... */
  first_byte = QPACK_INSTR_INSERT_NAMEREF_MASK; /* bit 7 = 1 */
  if (is_static)
    first_byte |= QPACK_INSTR_INSERT_NAMEREF_STATIC; /* bit 6 = T */

  /* Encode name index with 6-bit prefix */
  int_len = SocketHPACK_int_encode (
      name_index, QPACK_INSTR_INSERT_NAMEREF_PREFIX, int_buf, sizeof (int_buf));
  if (int_len == 0)
    return QPACK_STREAM_ERR_INTERNAL;

  /* Merge first byte flags with integer encoding */
  int_buf[0] |= first_byte;

  /* Check if we have room for the index */
  if (pos + int_len > output_size)
    return QPACK_STREAM_ERR_BUFFER_FULL;

  memcpy (output + pos, int_buf, int_len);
  pos += int_len;

  /* Determine if Huffman encoding is beneficial */
  if (use_huffman && value_len > 0)
    {
      huffman_len = SocketHPACK_huffman_encoded_size (value, value_len);
      if (huffman_len < value_len)
        actually_use_huffman = true;
    }

  /* Encode value length with 7-bit prefix */
  size_t encoded_value_len = actually_use_huffman ? huffman_len : value_len;
  int_len = SocketHPACK_int_encode (
      encoded_value_len, QPACK_VALUE_LENGTH_PREFIX, int_buf, sizeof (int_buf));
  if (int_len == 0)
    return QPACK_STREAM_ERR_INTERNAL;

  /* Set Huffman flag if using Huffman encoding */
  if (actually_use_huffman)
    int_buf[0] |= QPACK_VALUE_HUFFMAN_MASK;

  /* Check if we have room for value length + value data */
  if (pos + int_len + encoded_value_len > output_size)
    return QPACK_STREAM_ERR_BUFFER_FULL;

  memcpy (output + pos, int_buf, int_len);
  pos += int_len;

  /* Encode value string */
  if (value_len > 0)
    {
      if (actually_use_huffman)
        {
          ssize_t huff_result = SocketHPACK_huffman_encode (
              value, value_len, output + pos, output_size - pos);
          if (huff_result < 0)
            return QPACK_STREAM_ERR_INTERNAL;
          pos += (size_t)huff_result;
        }
      else
        {
          memcpy (output + pos, value, value_len);
          pos += value_len;
        }
    }

  *bytes_written = pos;
  return QPACK_STREAM_OK;
}

SocketQPACKStream_Result
SocketQPACK_decode_insert_nameref (const unsigned char *input,
                                   size_t input_len,
                                   Arena_T arena,
                                   SocketQPACK_InsertNameRef *result,
                                   size_t *consumed)
{
  /*
   * RFC 9204 Section 4.3.2: Insert with Name Reference
   *
   * First byte: 1T xxxxxx
   * - Bit 7: Always 1 for this instruction type
   * - Bit 6 (T): 1=static table, 0=dynamic table
   * - Bits 5-0: Start of 6+ prefix integer for name index
   */
  size_t pos = 0;
  uint64_t name_index;
  uint64_t value_len;
  size_t int_consumed;
  SocketHPACK_Result hpack_result;
  bool is_static;
  bool value_huffman;

  /* Parameter validation */
  if (input == NULL || arena == NULL || result == NULL || consumed == NULL)
    return QPACK_STREAM_ERR_NULL_PARAM;

  *consumed = 0;

  /* Need at least one byte */
  if (input_len < 1)
    return QPACK_STREAM_ERR_BUFFER_FULL;

  /* Verify this is an insert with name reference instruction */
  if ((input[0] & QPACK_INSTR_INSERT_NAMEREF_MASK)
      != QPACK_INSTR_INSERT_NAMEREF_MASK)
    return QPACK_STREAM_ERR_INTERNAL;

  /* Extract T bit (static/dynamic flag) */
  is_static = (input[0] & QPACK_INSTR_INSERT_NAMEREF_STATIC) != 0;

  /* Decode name index (6-bit prefix integer) */
  hpack_result = SocketHPACK_int_decode (input,
                                         input_len,
                                         QPACK_INSTR_INSERT_NAMEREF_PREFIX,
                                         &name_index,
                                         &int_consumed);
  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_STREAM_ERR_BUFFER_FULL;
  if (hpack_result != HPACK_OK)
    return QPACK_STREAM_ERR_INTERNAL;

  pos += int_consumed;

  /* Decode value length (7-bit prefix integer) */
  if (pos >= input_len)
    return QPACK_STREAM_ERR_BUFFER_FULL;

  value_huffman = (input[pos] & QPACK_VALUE_HUFFMAN_MASK) != 0;

  hpack_result = SocketHPACK_int_decode (input + pos,
                                         input_len - pos,
                                         QPACK_VALUE_LENGTH_PREFIX,
                                         &value_len,
                                         &int_consumed);
  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_STREAM_ERR_BUFFER_FULL;
  if (hpack_result != HPACK_OK)
    return QPACK_STREAM_ERR_INTERNAL;

  pos += int_consumed;

  /* Check if we have enough bytes for the value string */
  if (pos + value_len > input_len)
    return QPACK_STREAM_ERR_BUFFER_FULL;

  /* Populate result */
  result->is_static = is_static;
  result->name_index = name_index;
  result->value_huffman = value_huffman;

  if (value_len == 0)
    {
      result->value = NULL;
      result->value_len = 0;
    }
  else if (value_huffman)
    {
      /* Huffman-decode the value */
      /* Allocate decode buffer (worst case 2x expansion) */
      /* Check for multiplication overflow before allocation (fixes #3457) */
      size_t decode_buf_size;
      if (!SocketSecurity_check_multiply (value_len, 2, &decode_buf_size))
        return QPACK_STREAM_ERR_INTERNAL;
      if (decode_buf_size < 64)
        decode_buf_size = 64;

      unsigned char *decode_buf = ALLOC (arena, decode_buf_size);
      if (decode_buf == NULL)
        return QPACK_STREAM_ERR_INTERNAL;

      ssize_t decoded_len = SocketHPACK_huffman_decode (
          input + pos, value_len, decode_buf, decode_buf_size);
      if (decoded_len < 0)
        return QPACK_STREAM_ERR_INTERNAL;

      result->value = decode_buf;
      result->value_len = (size_t)decoded_len;
    }
  else
    {
      /* Literal value - point directly into input buffer */
      result->value = input + pos;
      result->value_len = value_len;
    }

  pos += value_len;
  *consumed = pos;

  return QPACK_STREAM_OK;
}

SocketQPACKStream_Result
SocketQPACK_validate_nameref_index (bool is_static,
                                    uint64_t name_index,
                                    uint64_t insert_count,
                                    uint64_t dropped_count)
{
  /*
   * RFC 9204 Section 4.3.2: Validate name reference index
   *
   * For static table: index must be 0-98 (99 entries)
   * For dynamic table: index is encoder-relative, must reference
   *                    a valid (non-evicted, non-future) entry
   */
  if (is_static)
    {
      /* Static table has 99 entries (indices 0-98) */
      if (name_index >= SOCKETQPACK_STATIC_TABLE_SIZE)
        return QPACK_STREAM_ERR_INVALID_INDEX;
      return QPACK_STREAM_OK;
    }

  /* Dynamic table: encoder-relative index validation */
  /* rel_index must be < insert_count to reference a valid entry */
  if (name_index >= insert_count)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  /* Convert to absolute index and check eviction */
  /* absolute = insert_count - relative - 1 */
  uint64_t abs_index = insert_count - name_index - 1;

  /* Check if entry has been evicted */
  if (abs_index < dropped_count)
    return QPACK_STREAM_ERR_INVALID_INDEX;

  return QPACK_STREAM_OK;
}
