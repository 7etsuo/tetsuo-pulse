/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-indexed.c
 * @brief QPACK Indexed Field Line with Post-Base Index (RFC 9204 Section 4.5.3)
 *
 * Implements encoding and decoding for the Indexed Field Line with Post-Base
 * Index representation. This representation allows referencing dynamic table
 * entries inserted after the Base value was established for the field section.
 *
 * Wire format (RFC 9204 Section 4.5.3):
 *
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 | 0 | 1 |  Index (4+)   |
 * +---+---+---+---+---------------+
 *
 * Pattern: 0001 (4 most significant bits)
 * Prefix: 4 bits (least significant nibble)
 * Index: Variable-length integer with 4-bit prefix (RFC 9204 Section 4.1.1)
 *
 * Post-base indexing allows field sections to reference entries inserted
 * during encoding (abs_index >= Base). This is necessary when the encoder
 * adds entries to the dynamic table while encoding a field section that
 * references those same entries.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-4.5.3
 */

#include <string.h>

#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"

#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketHPACK.h"

/* ============================================================================
 * CONSTANTS
 * ============================================================================
 */

/** Indexed Field Line with Post-Base Index pattern: 0001xxxx */
#define QPACK_INDEXED_POSTBASE_PATTERN 0x10

/** Pattern mask for post-base indexed (top 4 bits) */
#define QPACK_INDEXED_POSTBASE_MASK 0xF0

/** Prefix bits for post-base index (4 bits) */
#define QPACK_INDEXED_POSTBASE_PREFIX 4

/* ============================================================================
 * ENCODE INDEXED FIELD LINE WITH POST-BASE INDEX (RFC 9204 Section 4.5.3)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_encode_indexed_postbase (uint64_t post_base_index,
                                     unsigned char *output,
                                     size_t output_size,
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
   * RFC 9204 Section 4.5.3: Indexed Field Line with Post-Base Index
   *
   * The pattern 0001 occupies the top 4 bits of the first byte.
   * The remaining 4 bits (plus continuation bytes if needed) encode
   * the post-base index value using variable-length integer encoding.
   *
   *   0   1   2   3   4   5   6   7
   * +---+---+---+---+---+---+---+---+
   * | 0 | 0 | 0 | 1 |  Index (4+)   |
   * +---+---+---+---+---------------+
   */

  /* Encode post-base index as 4-bit prefix integer */
  encoded_len = SocketHPACK_int_encode (
      post_base_index, QPACK_INDEXED_POSTBASE_PREFIX, output, output_size);
  if (encoded_len == 0)
    return QPACK_ERR_INTEGER;

  /* Set pattern bits (0001) in the first byte */
  output[0] = (output[0] & ~QPACK_INDEXED_POSTBASE_MASK)
              | QPACK_INDEXED_POSTBASE_PATTERN;

  *bytes_written = encoded_len;
  return QPACK_OK;
}

/* ============================================================================
 * DECODE INDEXED FIELD LINE WITH POST-BASE INDEX (RFC 9204 Section 4.5.3)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_decode_indexed_postbase (const unsigned char *input,
                                     size_t input_len,
                                     uint64_t *post_base_index,
                                     size_t *bytes_consumed)
{
  SocketHPACK_Result hpack_result;

  /* Validate parameters */
  if (post_base_index == NULL || bytes_consumed == NULL)
    return QPACK_ERR_NULL_PARAM;

  *post_base_index = 0;
  *bytes_consumed = 0;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  if (input == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * RFC 9204 Section 4.5.3: Verify pattern bits
   *
   * The top 4 bits MUST be 0001 (0x10 when masked with 0xF0).
   * Other patterns indicate different field line representations:
   * - 1xxxxxxx: Indexed Field Line (static or dynamic)
   * - 0001xxxx: Indexed Field Line with Post-Base Index (this function)
   * - 001xxxxx: Literal Field Line with Name Reference
   * - 0000xxxx: Literal Field Line with Post-Base Name Reference
   * - 01xxxxxx: Literal Field Line with Literal Name
   */
  if ((input[0] & QPACK_INDEXED_POSTBASE_MASK)
      != QPACK_INDEXED_POSTBASE_PATTERN)
    return QPACK_ERR_INVALID_INDEX;

  /*
   * Decode post-base index using 4-bit prefix integer encoding.
   *
   * Per RFC 9204 Section 4.1.1 (which references RFC 7541 Section 5.1):
   * - If the value fits in the prefix (0-14 for 4-bit), it's encoded directly
   * - If the value is >= 15, the prefix is set to 15 (all 1s) and the
   *   remainder is encoded in continuation bytes
   */
  hpack_result = SocketHPACK_int_decode (input,
                                         input_len,
                                         QPACK_INDEXED_POSTBASE_PREFIX,
                                         post_base_index,
                                         bytes_consumed);

  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_INCOMPLETE;

  if (hpack_result != HPACK_OK)
    return QPACK_ERR_INTEGER;

  return QPACK_OK;
}

/* ============================================================================
 * VALIDATE POST-BASE INDEX (RFC 9204 Section 4.5.3)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_validate_indexed_postbase (uint64_t base,
                                       uint64_t insert_count,
                                       uint64_t post_base_index)
{
  /*
   * RFC 9204 Section 4.5.3: Post-Base Index Validation
   *
   * A post-base index is valid if:
   * 1. base + post_base_index does not overflow
   * 2. The resulting absolute index < insert_count (not a future entry)
   *
   * Post-base index 0 references the entry at absolute index = Base.
   * The valid range of post-base indices is [0, insert_count - base - 1].
   *
   * Note: If Base == Insert Count, no post-base entries are available,
   * and any post-base index is invalid.
   */
  return SocketQPACK_is_valid_postbase (base, insert_count, post_base_index);
}

/* ============================================================================
 * CONVERT POST-BASE INDEX TO ABSOLUTE INDEX (RFC 9204 Section 4.5.3)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_indexed_postbase_to_absolute (uint64_t base,
                                          uint64_t post_base_index,
                                          uint64_t *absolute_index)
{
  /*
   * RFC 9204 Section 3.2.6: Post-Base Indexing
   *
   * Formula: absolute = base + post_base_index
   *
   * Post-base index 0 references the entry at Base.
   * Higher post-base indices reference more recently inserted entries.
   */
  return SocketQPACK_postbase_to_abs (base, post_base_index, absolute_index);
}

/* ============================================================================
 * LOOKUP INDEXED FIELD LINE WITH POST-BASE INDEX (RFC 9204 Section 4.5.3)
 *
 * High-level function that validates, converts, and looks up the entry.
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_lookup_indexed_postbase (SocketQPACK_Table_T table,
                                     uint64_t base,
                                     uint64_t post_base_index,
                                     const char **name,
                                     size_t *name_len,
                                     const char **value,
                                     size_t *value_len)
{
  SocketQPACK_Result result;
  uint64_t insert_count;
  uint64_t absolute_index;

  /* Validate parameters */
  if (table == NULL)
    return QPACK_ERR_NULL_PARAM;

  if (name == NULL || name_len == NULL || value == NULL || value_len == NULL)
    return QPACK_ERR_NULL_PARAM;

  /* Get current insert count from table */
  insert_count = SocketQPACK_Table_insert_count (table);

  /* Validate post-base index is in range */
  result = SocketQPACK_validate_indexed_postbase (
      base, insert_count, post_base_index);
  if (result != QPACK_OK)
    return result;

  /* Convert to absolute index */
  result = SocketQPACK_indexed_postbase_to_absolute (
      base, post_base_index, &absolute_index);
  if (result != QPACK_OK)
    return result;

  /* Look up in dynamic table */
  return SocketQPACK_Table_get (
      table, absolute_index, name, name_len, value, value_len);
}

/* ============================================================================
 * IDENTIFY INDEXED FIELD LINE WITH POST-BASE PATTERN
 * ============================================================================
 */

bool
SocketQPACK_is_indexed_postbase (uint8_t first_byte)
{
  /*
   * RFC 9204 Section 4.5.3: Pattern identification
   *
   * The pattern 0001xxxx (first byte & 0xF0 == 0x10) identifies this
   * representation as an Indexed Field Line with Post-Base Index.
   */
  return (first_byte & QPACK_INDEXED_POSTBASE_MASK)
         == QPACK_INDEXED_POSTBASE_PATTERN;
}
