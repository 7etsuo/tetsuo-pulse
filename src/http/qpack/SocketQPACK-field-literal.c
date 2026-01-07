/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-field-literal.c
 * @brief QPACK Literal Field Line with Literal Name (RFC 9204 Section 4.5.6)
 *
 * Implements encoding and decoding for the Literal Field Line with Literal Name
 * instruction used in QPACK field sections. This instruction encodes a header
 * field where both the name and value are represented as string literals.
 *
 * Wire format (RFC 9204 Section 4.5.6):
 *
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 | 1 | N | H |NameLen(3+)|
 * +---+---+---+---+---+-----------+
 * |  Name String (Length bytes)   |
 * +---+---------------------------+
 * | H |     Value Length (7+)     |
 * +---+---------------------------+
 * |  Value String (Length bytes)  |
 * +-------------------------------+
 *
 * Bit pattern: 001NHxxx
 * - N bit (bit 4): Never-indexed flag (1 = sensitive, never add to dynamic
 * table)
 * - H bit (bit 3): Huffman encoding for name (1 = Huffman, 0 = literal)
 * - xxx (bits 2-0): Start of 3-bit prefix integer for name length
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-4.5.6
 */

#include <string.h>

#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"

#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketHPACK.h"

/* ============================================================================
 * PATTERN VALIDATION (RFC 9204 Section 4.5.6)
 * ============================================================================
 */

bool
SocketQPACK_is_literal_field_literal_name (uint8_t first_byte)
{
  /*
   * RFC 9204 Section 4.5.6: Pattern bits must be 001
   * Mask with 0xE0 to check bits 7-5, compare with 0x20 (001xxxxx).
   */
  return (first_byte & QPACK_FIELD_LITERAL_LITERAL_MASK)
         == QPACK_FIELD_LITERAL_LITERAL_PATTERN;
}

/* ============================================================================
 * ENCODE LITERAL FIELD LINE WITH LITERAL NAME (RFC 9204 Section 4.5.6)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_encode_literal_field_literal_name (unsigned char *output,
                                               size_t output_size,
                                               const unsigned char *name,
                                               size_t name_len,
                                               bool name_huffman,
                                               const unsigned char *value,
                                               size_t value_len,
                                               bool value_huffman,
                                               bool never_indexed,
                                               size_t *bytes_written)
{
  size_t offset = 0;
  size_t name_encoded_len;
  size_t value_encoded_len;
  bool actually_huffman_name = false;
  bool actually_huffman_value = false;
  size_t prefix_len;
  unsigned char first_byte;

  /* Validate parameters */
  if (output == NULL || bytes_written == NULL)
    return QPACK_ERR_NULL_PARAM;

  if ((name == NULL && name_len > 0) || (value == NULL && value_len > 0))
    return QPACK_ERR_NULL_PARAM;

  *bytes_written = 0;

  if (output_size == 0)
    return QPACK_ERR_TABLE_SIZE;

  /* Determine if Huffman encoding is beneficial for name */
  if (name_huffman && name_len > 0)
    {
      name_encoded_len = SocketHPACK_huffman_encoded_size (name, name_len);
      if (name_encoded_len < name_len)
        actually_huffman_name = true;
      else
        name_encoded_len = name_len;
    }
  else
    {
      name_encoded_len = name_len;
    }

  /* Determine if Huffman encoding is beneficial for value */
  if (value_huffman && value_len > 0)
    {
      value_encoded_len = SocketHPACK_huffman_encoded_size (value, value_len);
      if (value_encoded_len < value_len)
        actually_huffman_value = true;
      else
        value_encoded_len = value_len;
    }
  else
    {
      value_encoded_len = value_len;
    }

  /*
   * Encode name length with 3-bit prefix
   * First byte: 0 0 1 | N | H | NameLen(3+)
   */

  /* Encode the name length integer */
  prefix_len = SocketHPACK_int_encode (name_encoded_len,
                                       QPACK_FIELD_LITERAL_NAME_PREFIX,
                                       output + offset,
                                       output_size - offset);
  if (prefix_len == 0)
    return QPACK_ERR_INTEGER;

  /* Build first byte with pattern 001, N bit, and H bit */
  first_byte = QPACK_FIELD_LITERAL_LITERAL_PATTERN; /* 001xxxxx */

  if (never_indexed)
    first_byte |= QPACK_FIELD_LITERAL_NEVER_INDEX; /* N bit */

  if (actually_huffman_name)
    first_byte |= QPACK_FIELD_LITERAL_NAME_HUFFMAN; /* H bit */

  /* Merge flags with the encoded integer (integer encoding uses lower bits) */
  output[offset] = (output[offset] & 0x07) | first_byte;

  offset += prefix_len;

  /* Encode name string */
  if (actually_huffman_name)
    {
      if (offset + name_encoded_len > output_size)
        return QPACK_ERR_TABLE_SIZE;
      ssize_t huff_result = SocketHPACK_huffman_encode (
          name, name_len, output + offset, output_size - offset);
      if (huff_result < 0)
        return QPACK_ERR_HUFFMAN;
      offset += (size_t)huff_result;
    }
  else
    {
      if (offset + name_len > output_size)
        return QPACK_ERR_TABLE_SIZE;
      if (name_len > 0)
        memcpy (output + offset, name, name_len);
      offset += name_len;
    }

  /*
   * Encode value length with 7-bit prefix
   * Byte: H | ValueLen(7+)
   */
  if (offset >= output_size)
    return QPACK_ERR_TABLE_SIZE;

  prefix_len = SocketHPACK_int_encode (value_encoded_len,
                                       QPACK_FIELD_LITERAL_VALUE_PREFIX,
                                       output + offset,
                                       output_size - offset);
  if (prefix_len == 0)
    return QPACK_ERR_INTEGER;

  /* Set H bit for value if using Huffman */
  if (actually_huffman_value)
    output[offset] |= QPACK_FIELD_LITERAL_VALUE_HUFFMAN;
  else
    output[offset] &= ~QPACK_FIELD_LITERAL_VALUE_HUFFMAN;

  offset += prefix_len;

  /* Encode value string */
  if (actually_huffman_value)
    {
      if (offset + value_encoded_len > output_size)
        return QPACK_ERR_TABLE_SIZE;
      ssize_t huff_result = SocketHPACK_huffman_encode (
          value, value_len, output + offset, output_size - offset);
      if (huff_result < 0)
        return QPACK_ERR_HUFFMAN;
      offset += (size_t)huff_result;
    }
  else
    {
      if (offset + value_len > output_size)
        return QPACK_ERR_TABLE_SIZE;
      if (value_len > 0)
        memcpy (output + offset, value, value_len);
      offset += value_len;
    }

  *bytes_written = offset;
  return QPACK_OK;
}

/* ============================================================================
 * DECODE LITERAL FIELD LINE WITH LITERAL NAME (RFC 9204 Section 4.5.6)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_decode_literal_field_literal_name (const unsigned char *input,
                                               size_t input_len,
                                               unsigned char *name_out,
                                               size_t name_out_size,
                                               size_t *name_len,
                                               unsigned char *value_out,
                                               size_t value_out_size,
                                               size_t *value_len,
                                               bool *never_indexed,
                                               size_t *bytes_consumed)
{
  size_t offset = 0;
  uint64_t name_wire_len;
  uint64_t value_wire_len;
  size_t consumed;
  bool name_huffman;
  bool value_huffman;
  SocketHPACK_Result hpack_result;

  /* Validate parameters */
  if (bytes_consumed == NULL)
    return QPACK_ERR_NULL_PARAM;

  *bytes_consumed = 0;

  if (name_out == NULL || value_out == NULL)
    return QPACK_ERR_NULL_PARAM;

  if (name_len == NULL || value_len == NULL || never_indexed == NULL)
    return QPACK_ERR_NULL_PARAM;

  *name_len = 0;
  *value_len = 0;
  *never_indexed = false;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  if (input == NULL)
    return QPACK_ERR_NULL_PARAM;

  /* Verify pattern bits: 001xxxxx */
  if (!SocketQPACK_is_literal_field_literal_name (input[0]))
    return QPACK_ERR_DECOMPRESSION;

  /* Extract N bit (never-indexed flag) */
  *never_indexed = (input[0] & QPACK_FIELD_LITERAL_NEVER_INDEX) != 0;

  /* Extract H bit for name (Huffman flag) */
  name_huffman = (input[0] & QPACK_FIELD_LITERAL_NAME_HUFFMAN) != 0;

  /* Decode name length with 3-bit prefix */
  hpack_result = SocketHPACK_int_decode (input + offset,
                                         input_len - offset,
                                         QPACK_FIELD_LITERAL_NAME_PREFIX,
                                         &name_wire_len,
                                         &consumed);
  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_INCOMPLETE;
  if (hpack_result != HPACK_OK)
    return QPACK_ERR_INTEGER;

  offset += consumed;

  /* Validate name length against remaining input */
  if (offset + name_wire_len > input_len)
    return QPACK_INCOMPLETE;

  /* Decode name string */
  if (name_huffman)
    {
      ssize_t decoded_len = SocketHPACK_huffman_decode (
          input + offset, (size_t)name_wire_len, name_out, name_out_size);
      if (decoded_len < 0)
        return QPACK_ERR_HUFFMAN;
      *name_len = (size_t)decoded_len;
    }
  else
    {
      if (name_wire_len > name_out_size)
        return QPACK_ERR_HEADER_SIZE;
      if (name_wire_len > 0)
        memcpy (name_out, input + offset, (size_t)name_wire_len);
      *name_len = (size_t)name_wire_len;
    }

  offset += (size_t)name_wire_len;

  /* Need at least one more byte for value length */
  if (offset >= input_len)
    return QPACK_INCOMPLETE;

  /* Extract H bit for value (Huffman flag) */
  value_huffman = (input[offset] & QPACK_FIELD_LITERAL_VALUE_HUFFMAN) != 0;

  /* Decode value length with 7-bit prefix */
  hpack_result = SocketHPACK_int_decode (input + offset,
                                         input_len - offset,
                                         QPACK_FIELD_LITERAL_VALUE_PREFIX,
                                         &value_wire_len,
                                         &consumed);
  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_INCOMPLETE;
  if (hpack_result != HPACK_OK)
    return QPACK_ERR_INTEGER;

  offset += consumed;

  /* Validate value length against remaining input */
  if (offset + value_wire_len > input_len)
    return QPACK_INCOMPLETE;

  /* Decode value string */
  if (value_huffman)
    {
      ssize_t decoded_len = SocketHPACK_huffman_decode (
          input + offset, (size_t)value_wire_len, value_out, value_out_size);
      if (decoded_len < 0)
        return QPACK_ERR_HUFFMAN;
      *value_len = (size_t)decoded_len;
    }
  else
    {
      if (value_wire_len > value_out_size)
        return QPACK_ERR_HEADER_SIZE;
      if (value_wire_len > 0)
        memcpy (value_out, input + offset, (size_t)value_wire_len);
      *value_len = (size_t)value_wire_len;
    }

  offset += (size_t)value_wire_len;

  *bytes_consumed = offset;
  return QPACK_OK;
}
