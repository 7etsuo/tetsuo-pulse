/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-literal-postbase.c
 * @brief QPACK Literal Field Line with Post-Base Name Reference (RFC 9204
 * Section 4.5.5)
 *
 * Implements encoding and decoding for literal field lines where the name
 * is referenced from a post-base dynamic table entry. Post-base entries are
 * those inserted during the encoding of the current field section, after
 * the Base index.
 *
 * Wire format (RFC 9204 Section 4.5.5):
 *
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 | 0 | 0 | N |NameIdx(3+)|
 * +---+---+---+---+---+-----------+
 * | H |     Value Length (7+)     |
 * +---+---------------------------+
 * |  Value String (Length bytes)  |
 * +-------------------------------+
 *
 * Bit pattern: 0000 N xxx (first 4 bits are 0, N is never-index flag)
 * Name index uses 3-bit prefix integer encoding.
 * Value uses standard string literal encoding with 7-bit prefix.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-4.5.5
 */

#include <string.h>

#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"

#include "core/SocketSecurity.h"
#include "http/SocketHPACK.h"

/* ============================================================================
 * INTERNAL CONSTANTS
 * ============================================================================
 */

/** Bit pattern for Literal Field Line with Post-Base Name Reference */
#define QPACK_LITERAL_POSTBASE_PATTERN 0x00

/** Pattern mask: bits 7-4 must be 0000 */
#define QPACK_LITERAL_POSTBASE_MASK 0xF0

/** Never-index flag (bit 3) */
#define QPACK_LITERAL_POSTBASE_N_FLAG 0x08

/** Name index prefix bits (3-bit integer) */
#define QPACK_LITERAL_POSTBASE_NAME_PREFIX 3

/** Value Huffman flag (bit 7) */
#define QPACK_VALUE_HUFFMAN_FLAG 0x80

/** Value length prefix bits (7-bit integer) */
#define QPACK_VALUE_LENGTH_PREFIX 7

/* ============================================================================
 * ENCODE LITERAL FIELD LINE WITH POST-BASE NAME REFERENCE
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_encode_literal_postbase_name (unsigned char *output,
                                          size_t output_size,
                                          uint64_t name_index,
                                          int never_index,
                                          const unsigned char *value,
                                          size_t value_len,
                                          int use_huffman,
                                          size_t *bytes_written)
{
  size_t offset = 0;
  size_t encoded_len;
  size_t value_encoded_len;
  int actually_huffman = 0;
  unsigned char first_byte;

  /* Validate required parameters */
  if (output == NULL || bytes_written == NULL)
    return QPACK_ERR_NULL_PARAM;

  if (value == NULL && value_len > 0)
    return QPACK_ERR_NULL_PARAM;

  *bytes_written = 0;

  if (output_size == 0)
    return QPACK_ERR_TABLE_SIZE;

  /*
   * Determine if Huffman encoding is beneficial for value.
   * Only use Huffman if it produces a smaller result.
   */
  if (use_huffman && value_len > 0)
    {
      value_encoded_len = SocketHPACK_huffman_encoded_size (value, value_len);
      if (value_encoded_len < value_len)
        actually_huffman = 1;
      else
        value_encoded_len = value_len;
    }
  else
    {
      value_encoded_len = value_len;
    }

  /*
   * Encode name index with 3-bit prefix.
   *
   * First byte format: 0000 N xxx
   * - Bits 7-4: 0000 (pattern identifier)
   * - Bit 3: N (never-index flag)
   * - Bits 2-0: name index (3-bit prefix)
   */
  first_byte = QPACK_LITERAL_POSTBASE_PATTERN;
  if (never_index)
    first_byte |= QPACK_LITERAL_POSTBASE_N_FLAG;

  encoded_len = SocketHPACK_int_encode (name_index,
                                        QPACK_LITERAL_POSTBASE_NAME_PREFIX,
                                        output + offset,
                                        output_size - offset);
  if (encoded_len == 0)
    return QPACK_ERR_INTEGER;

  /* Merge pattern and N flag with encoded integer */
  output[offset] |= first_byte;
  offset += encoded_len;

  /*
   * Encode value with 7-bit prefix.
   *
   * Value byte format: H xxxxxxx
   * - Bit 7: H (Huffman flag)
   * - Bits 6-0: value length (7-bit prefix)
   */
  if (offset >= output_size)
    return QPACK_ERR_TABLE_SIZE;

  encoded_len = SocketHPACK_int_encode (value_encoded_len,
                                        QPACK_VALUE_LENGTH_PREFIX,
                                        output + offset,
                                        output_size - offset);
  if (encoded_len == 0)
    return QPACK_ERR_INTEGER;

  /* Set Huffman flag if using Huffman encoding */
  if (actually_huffman)
    output[offset] |= QPACK_VALUE_HUFFMAN_FLAG;

  offset += encoded_len;

  /* Encode value string */
  if (actually_huffman)
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
 * DECODE LITERAL FIELD LINE WITH POST-BASE NAME REFERENCE
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_decode_literal_postbase_name (
    const unsigned char *input,
    size_t input_len,
    Arena_T arena,
    SocketQPACK_LiteralPostBaseName *result,
    size_t *consumed)
{
  size_t offset = 0;
  size_t int_consumed;
  uint64_t name_index;
  uint64_t value_len;
  int never_index;
  int value_huffman;
  SocketHPACK_Result hpack_result;

  /* Validate required parameters */
  if (result == NULL || consumed == NULL)
    return QPACK_ERR_NULL_PARAM;

  *consumed = 0;
  result->name_index = 0;
  result->never_index = 0;
  result->value_huffman = 0;
  result->value = NULL;
  result->value_len = 0;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  if (input == NULL)
    return QPACK_ERR_NULL_PARAM;

  if (arena == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * Verify bit pattern: bits 7-4 must be 0000
   */
  if ((input[0] & QPACK_LITERAL_POSTBASE_MASK)
      != QPACK_LITERAL_POSTBASE_PATTERN)
    return QPACK_ERR_INTERNAL; /* Not a literal with post-base name reference */

  /* Extract N flag (bit 3) */
  never_index = (input[0] & QPACK_LITERAL_POSTBASE_N_FLAG) ? 1 : 0;

  /*
   * Decode name index with 3-bit prefix.
   */
  hpack_result = SocketHPACK_int_decode (input + offset,
                                         input_len - offset,
                                         QPACK_LITERAL_POSTBASE_NAME_PREFIX,
                                         &name_index,
                                         &int_consumed);

  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_INCOMPLETE;
  if (hpack_result != HPACK_OK)
    return QPACK_ERR_INTEGER;

  offset += int_consumed;

  /* Need at least one byte for value length */
  if (offset >= input_len)
    return QPACK_INCOMPLETE;

  /* Extract H flag (bit 7 of value length byte) */
  value_huffman = (input[offset] & QPACK_VALUE_HUFFMAN_FLAG) ? 1 : 0;

  /*
   * Decode value length with 7-bit prefix.
   */
  hpack_result = SocketHPACK_int_decode (input + offset,
                                         input_len - offset,
                                         QPACK_VALUE_LENGTH_PREFIX,
                                         &value_len,
                                         &int_consumed);

  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_INCOMPLETE;
  if (hpack_result != HPACK_OK)
    return QPACK_ERR_INTEGER;

  offset += int_consumed;

  /* Validate value data is present */
  if (offset + value_len > input_len)
    return QPACK_INCOMPLETE;

  /* Decode value string */
  if (value_huffman)
    {
      /*
       * Huffman-decode the value into arena-allocated buffer.
       * Estimate decoded size as 2x encoded size (typical expansion).
       */
      size_t max_decoded = value_len * 2 + 16;
      unsigned char *decoded_value = ALLOC (arena, max_decoded);
      if (decoded_value == NULL)
        return QPACK_ERR_INTERNAL;

      ssize_t decoded_len = SocketHPACK_huffman_decode (
          input + offset, (size_t)value_len, decoded_value, max_decoded);
      if (decoded_len < 0)
        return QPACK_ERR_HUFFMAN;

      result->value = decoded_value;
      result->value_len = (size_t)decoded_len;
    }
  else
    {
      /* Plain text: point directly into input buffer */
      result->value = input + offset;
      result->value_len = (size_t)value_len;
    }

  offset += (size_t)value_len;

  /* Store decoded values */
  result->name_index = name_index;
  result->never_index = never_index;
  result->value_huffman = value_huffman;

  *consumed = offset;
  return QPACK_OK;
}

/* ============================================================================
 * VALIDATE POST-BASE NAME INDEX
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_validate_literal_postbase_index (uint64_t base,
                                             uint64_t insert_count,
                                             uint64_t post_base_idx)
{
  uint64_t absolute_index;

  /*
   * RFC 9204 Section 4.5.5: Post-base index is relative to Base.
   * Absolute index = base + post_base_idx
   *
   * For the reference to be valid:
   * 1. No integer overflow in base + post_base_idx
   * 2. Absolute index < insert_count (entry must exist)
   */

  /* Check for integer overflow */
  if (post_base_idx > UINT64_MAX - base)
    return QPACK_ERR_INVALID_INDEX;

  absolute_index = base + post_base_idx;

  /* Check that referenced entry exists */
  if (absolute_index >= insert_count)
    return QPACK_ERR_FUTURE_INDEX;

  return QPACK_OK;
}

/* ============================================================================
 * RESOLVE POST-BASE NAME REFERENCE
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_resolve_postbase_name (SocketQPACK_Table_T table,
                                   uint64_t base,
                                   uint64_t post_base_idx,
                                   const char **name,
                                   size_t *name_len)
{
  uint64_t absolute_index;
  uint64_t insert_count;
  SocketQPACK_Result result;
  const char *value;
  size_t value_len;

  /* Validate required parameters */
  if (table == NULL || name == NULL || name_len == NULL)
    return QPACK_ERR_NULL_PARAM;

  *name = NULL;
  *name_len = 0;

  /* Get current insert count from table */
  insert_count = SocketQPACK_Table_insert_count (table);

  /* Validate post-base index */
  result = SocketQPACK_validate_literal_postbase_index (
      base, insert_count, post_base_idx);
  if (result != QPACK_OK)
    return result;

  /* Convert post-base index to absolute index */
  result = SocketQPACK_postbase_to_abs (base, post_base_idx, &absolute_index);
  if (result != QPACK_OK)
    return result;

  /* Look up entry in dynamic table */
  result = SocketQPACK_Table_get (
      table, absolute_index, name, name_len, &value, &value_len);

  return result;
}
