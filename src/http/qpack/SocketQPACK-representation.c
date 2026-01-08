/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-representation.c
 * @brief QPACK Indexed Field Line (RFC 9204 Section 4.5.2)
 *
 * Implements encoding and decoding for the Indexed Field Line representation
 * used in QPACK field sections. This representation references a field line
 * from either the static or dynamic table.
 *
 * Wire format (RFC 9204 Section 4.5.2):
 *
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 1 | T |      Index (6+)       |
 * +---+---+-----------------------+
 *
 * Pattern: 1T followed by 6-bit prefix integer encoding
 * - T=1: Static table index (0-98)
 * - T=0: Dynamic table relative index (relative to Base)
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-4.5.2
 */

#include <string.h>

#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"

#include "core/SocketUtil.h"
#include "http/SocketHPACK.h"

/* ============================================================================
 * CONSTANTS
 * ============================================================================
 */

/** Indexed Field Line pattern mask (bit 7 must be 1) */
#define QPACK_INDEXED_FIELD_MASK 0x80

/** Type bit for static table (bit 6) */
#define QPACK_INDEXED_FIELD_STATIC_BIT 0x40

/** Index prefix bits (6-bit integer) */
#define QPACK_INDEXED_FIELD_PREFIX 6

/** Maximum valid static table index (0-98, 99 entries total) */
#define QPACK_STATIC_TABLE_MAX_INDEX 98

/* ============================================================================
 * ENCODE INDEXED FIELD LINE (RFC 9204 Section 4.5.2)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_encode_indexed_field (unsigned char *output,
                                  size_t output_size,
                                  uint64_t index,
                                  int is_static,
                                  size_t *bytes_written)
{
  size_t encoded_len;

  /* Validate parameters */
  if (output == NULL || bytes_written == NULL)
    return QPACK_ERR_NULL_PARAM;

  *bytes_written = 0;

  if (output_size == 0)
    return QPACK_ERR_TABLE_SIZE;

  /*
   * RFC 9204 Section 4.5.2:
   * For static table, index must be in range [0, 98].
   * For dynamic table, index is a relative index that will be validated
   * by the decoder against the Base.
   */
  if (is_static && index > QPACK_STATIC_TABLE_MAX_INDEX)
    return QPACK_ERR_INVALID_INDEX;

  /*
   * Encode index as 6-bit prefix integer.
   * First byte format: 1 | T | index[5:0]
   */
  encoded_len = SocketHPACK_int_encode (
      index, QPACK_INDEXED_FIELD_PREFIX, output, output_size);
  if (encoded_len == 0)
    return QPACK_ERR_INTEGER;

  /*
   * Set the pattern bits:
   * - Bit 7 = 1 (indexed field line pattern)
   * - Bit 6 = T (1 for static, 0 for dynamic)
   */
  output[0] |= QPACK_INDEXED_FIELD_MASK;
  if (is_static)
    output[0] |= QPACK_INDEXED_FIELD_STATIC_BIT;
  else
    output[0] &= ~QPACK_INDEXED_FIELD_STATIC_BIT;

  *bytes_written = encoded_len;
  return QPACK_OK;
}

/* ============================================================================
 * DECODE INDEXED FIELD LINE (RFC 9204 Section 4.5.2)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_decode_indexed_field (const unsigned char *input,
                                  size_t input_len,
                                  uint64_t *index,
                                  int *is_static,
                                  size_t *bytes_consumed)
{
  size_t consumed;
  SocketHPACK_Result hpack_result;

  /* Validate parameters */
  if (index == NULL || is_static == NULL || bytes_consumed == NULL)
    return QPACK_ERR_NULL_PARAM;

  *bytes_consumed = 0;
  *index = 0;
  *is_static = 0;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  if (input == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * RFC 9204 Section 4.5.2:
   * Verify the indexed field line pattern (bit 7 = 1).
   */
  if ((input[0] & QPACK_INDEXED_FIELD_MASK) != QPACK_INDEXED_FIELD_MASK)
    return QPACK_ERR_INTERNAL; /* Not an indexed field line */

  /* Extract type bit (T) */
  *is_static = (input[0] & QPACK_INDEXED_FIELD_STATIC_BIT) ? 1 : 0;

  /* Decode index as 6-bit prefix integer */
  hpack_result = SocketHPACK_int_decode (
      input, input_len, QPACK_INDEXED_FIELD_PREFIX, index, &consumed);

  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_INCOMPLETE;
  if (hpack_result != HPACK_OK)
    return QPACK_ERR_INTEGER;

  /*
   * RFC 9204 Section 4.5.2:
   * Validate static table index is in range [0, 98].
   * Dynamic table indices are validated later against Base.
   */
  if (*is_static && *index > QPACK_STATIC_TABLE_MAX_INDEX)
    return QPACK_ERR_INVALID_INDEX;

  *bytes_consumed = consumed;
  return QPACK_OK;
}

/* ============================================================================
 * INDEXED FIELD LINE WITH BASE RESOLUTION (RFC 9204 Section 4.5.2)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_resolve_indexed_field (uint64_t index,
                                   int is_static,
                                   uint64_t base,
                                   uint64_t dropped_count,
                                   uint64_t *abs_index)
{
  SocketQPACK_Result result;

  /* Validate output parameter */
  if (abs_index == NULL)
    return QPACK_ERR_NULL_PARAM;

  if (is_static)
    {
      /*
       * RFC 9204 Section 4.5.2:
       * For static table references, the index directly identifies the entry.
       * Static indices are 0-based and range from 0 to 98.
       */
      if (index > QPACK_STATIC_TABLE_MAX_INDEX)
        return QPACK_ERR_INVALID_INDEX;

      /* Static indices are returned as-is (no conversion needed) */
      *abs_index = index;
      return QPACK_OK;
    }

  /*
   * RFC 9204 Section 4.5.2 and Section 3.2.5:
   * For dynamic table references, the index is relative to Base.
   * Conversion: absolute = Base - relative - 1
   */
  result = SocketQPACK_relative_to_abs_field (base, index, abs_index);
  if (result != QPACK_OK)
    return result;

  /* Validate that the entry has not been evicted */
  if (*abs_index < dropped_count)
    return QPACK_ERR_EVICTED_INDEX;

  return QPACK_OK;
}

/* ============================================================================
 * CHECK IF BYTE IS INDEXED FIELD LINE
 * ============================================================================
 */

int
SocketQPACK_is_indexed_field_line (unsigned char byte)
{
  /*
   * RFC 9204 Section 4.5.2:
   * An Indexed Field Line starts with pattern 1xxxxxxx (bit 7 = 1).
   */
  return (byte & QPACK_INDEXED_FIELD_MASK) == QPACK_INDEXED_FIELD_MASK;
}
