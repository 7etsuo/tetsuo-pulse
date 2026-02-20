/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-index.c
 * @brief QPACK indexing scheme implementation (RFC 9204 Sections 3.2.4-3.2.6)
 *
 * Implements the three index conversion schemes for QPACK:
 * - Absolute Indexing (Section 3.2.4)
 * - Relative Indexing for encoder stream and field sections (Section 3.2.5)
 * - Post-Base Indexing for field sections (Section 3.2.6)
 *
 * Key concepts:
 * - Absolute Index: First entry inserted has index 0, increments by 1
 * - Insert Count: Total entries ever inserted (equals next absolute index)
 * - Dropped Count: Number of evicted entries (oldest valid absolute index)
 * - Base: Insert Count when field section encoding started
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-3.2
 */

#include <stdint.h>

#include "core/SocketUtil.h"
#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  static const char *const strings[QPACK_RESULT_COUNT] = {
    [QPACK_OK] = "OK",
    [QPACK_INCOMPLETE] = "Incomplete data",
    [QPACK_ERR_INVALID_INDEX] = "Invalid index",
    [QPACK_ERR_EVICTED_INDEX] = "Entry has been evicted",
    [QPACK_ERR_FUTURE_INDEX] = "Reference to not-yet-inserted entry",
    [QPACK_ERR_BASE_OVERFLOW] = "Base exceeds Insert Count",
    [QPACK_ERR_TABLE_SIZE] = "Table size limit exceeded",
    [QPACK_ERR_HEADER_SIZE] = "Header size limit exceeded",
    [QPACK_ERR_HUFFMAN] = "Huffman decoding error",
    [QPACK_ERR_INTEGER] = "Integer decoding error",
    [QPACK_ERR_DECOMPRESSION] = "Decompression failed",
    [QPACK_ERR_NULL_PARAM] = "NULL parameter passed to function",
    [QPACK_ERR_INTERNAL] = "Internal error",
    [QPACK_ERR_INVALID_BASE] = "Invalid Base calculation",
    [QPACK_ERR_0RTT_MISMATCH] = "0-RTT settings mismatch",
  };

  if (result >= 0 && (size_t)result < QPACK_RESULT_COUNT)
    return strings[result];

  return "Unknown error";
}

uint64_t
SocketQPACK_result_to_h3_error (SocketQPACK_Result result)
{
  /*
   * RFC 9204 Section 6 defines three QPACK-specific HTTP/3 error codes:
   * - QPACK_DECOMPRESSION_FAILED (0x0200): Decoder failed to interpret
   *   an encoded field section
   * - QPACK_ENCODER_STREAM_ERROR (0x0201): Decoder failed to interpret
   *   an encoder instruction
   * - QPACK_DECODER_STREAM_ERROR (0x0202): Encoder failed to interpret
   *   a decoder instruction
   */
  switch (result)
    {
    case QPACK_OK:
    case QPACK_INCOMPLETE:
      /* Not errors - return 0 to indicate no H3 error needed */
      return 0;

    case QPACK_ERR_HUFFMAN:
    case QPACK_ERR_INTEGER:
    case QPACK_ERR_DECOMPRESSION:
    case QPACK_ERR_INVALID_INDEX:
    case QPACK_ERR_EVICTED_INDEX:
    case QPACK_ERR_FUTURE_INDEX:
    case QPACK_ERR_INVALID_BASE:
    case QPACK_ERR_HEADER_SIZE:
    case QPACK_ERR_BASE_OVERFLOW:
      /*
       * RFC 9204 Section 6: "If the decoder encounters an error while
       * processing an encoded field section, it MUST treat this as a
       * connection error of type QPACK_DECOMPRESSION_FAILED."
       *
       * HEADER_SIZE and BASE_OVERFLOW are field section errors, not
       * encoder stream errors.
       */
      return QPACK_DECOMPRESSION_FAILED;

    case QPACK_ERR_TABLE_SIZE:
      /*
       * RFC 9204 Section 6: "If the decoder fails to process an
       * instruction on the encoder stream, it MUST treat this as a
       * connection error of type QPACK_ENCODER_STREAM_ERROR."
       *
       * TABLE_SIZE errors occur when processing Set Dynamic Table
       * Capacity encoder instruction (Section 4.3.1).
       */
      return QPACK_ENCODER_STREAM_ERROR;

    case QPACK_ERR_0RTT_MISMATCH:
      /*
       * RFC 9204 Section 3.2.3: 0-RTT settings mismatch is a decoder
       * instruction validation failure, treated as QPACK_DECODER_STREAM_ERROR.
       */
      return QPACK_DECODER_STREAM_ERROR;

    case QPACK_ERR_NULL_PARAM:
    case QPACK_ERR_INTERNAL:
    default:
      /* Internal/programming errors default to decompression failed */
      return QPACK_DECOMPRESSION_FAILED;
    }
}

size_t
SocketQPACK_estimate_capacity (size_t max_size)
{
  size_t est_entries;

  if (max_size == 0)
    return QPACK_MIN_TABLE_CAPACITY;

  /* Estimate entries based on average entry size */
  est_entries = max_size / QPACK_AVERAGE_ENTRY_SIZE;
  if (est_entries < QPACK_MIN_TABLE_CAPACITY)
    est_entries = QPACK_MIN_TABLE_CAPACITY;

  /* Round up to power of 2 for efficient ring buffer operations */
  return NEXT_POW2_64 (est_entries);
}

SocketQPACK_Result
SocketQPACK_abs_to_relative_encoder (uint64_t insert_count,
                                     uint64_t abs_index,
                                     uint64_t *rel_out)
{
  /* Hardened NULL check - return error instead of crashing */
  if (rel_out == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * RFC 9204 Section 3.2.5:
   * "A relative index of 0 refers to the entry with absolute index equal
   * to Insert Count - 1."
   *
   * Cannot reference:
   * - Future entries (abs_index >= insert_count)
   * - Entries not yet inserted
   */
  if (abs_index >= insert_count)
    return QPACK_ERR_INVALID_INDEX;

  /* relative = insert_count - abs - 1 */
  *rel_out = insert_count - abs_index - 1;
  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_relative_to_abs_encoder (uint64_t insert_count,
                                     uint64_t rel_index,
                                     uint64_t *abs_out)
{
  /* Hardened NULL check */
  if (abs_out == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * rel_index must be < insert_count to reference a valid entry.
   * rel_index = 0 => abs = insert_count - 1 (most recent)
   * rel_index = insert_count - 1 => abs = 0 (first ever inserted)
   */
  if (rel_index >= insert_count)
    return QPACK_ERR_INVALID_INDEX;

  /* absolute = insert_count - relative - 1 */
  *abs_out = insert_count - rel_index - 1;
  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_abs_to_relative_field (uint64_t base,
                                   uint64_t abs_index,
                                   uint64_t *rel_out)
{
  /* Hardened NULL check */
  if (rel_out == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * RFC 9204 Section 3.2.5:
   * "For entries inserted before the defined Base, a relative index
   * starting from 0 is used, where 0 refers to the entry with
   * absolute index Base - 1."
   *
   * Only entries with abs_index < base can use relative indexing.
   * Entries with abs_index >= base must use post-base indexing.
   */
  if (base == 0 || abs_index >= base)
    return QPACK_ERR_INVALID_INDEX;

  /* relative = base - abs - 1 */
  *rel_out = base - abs_index - 1;
  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_relative_to_abs_field (uint64_t base,
                                   uint64_t rel_index,
                                   uint64_t *abs_out)
{
  /* Hardened NULL check */
  if (abs_out == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * rel_index must be < base to reference a valid entry.
   * rel_index = 0 => abs = base - 1 (most recent before Base)
   * rel_index = base - 1 => abs = 0 (first ever inserted)
   */
  if (base == 0 || rel_index >= base)
    return QPACK_ERR_INVALID_INDEX;

  /* absolute = base - relative - 1 */
  *abs_out = base - rel_index - 1;
  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_abs_to_postbase (uint64_t base,
                             uint64_t abs_index,
                             uint64_t *pb_out)
{
  /* Hardened NULL check */
  if (pb_out == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * RFC 9204 Section 3.2.6:
   * "For entries with an absolute index greater than or equal to Base,
   * a post-base index is used."
   *
   * Only entries with abs_index >= base can use post-base indexing.
   * Entries with abs_index < base must use relative indexing.
   */
  if (abs_index < base)
    return QPACK_ERR_INVALID_INDEX;

  /* post_base = abs - base */
  *pb_out = abs_index - base;
  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_postbase_to_abs (uint64_t base,
                             uint64_t pb_index,
                             uint64_t *abs_out)
{
  /* Hardened NULL check */
  if (abs_out == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * Check for overflow: base + pb_index must not overflow uint64_t.
   * This is important for security as RFC 9204 notes absolute indices
   * can reach 2^62 in long-lived connections.
   */
  if (pb_index > UINT64_MAX - base)
    return QPACK_ERR_INVALID_INDEX;

  /* absolute = base + post_base */
  *abs_out = base + pb_index;
  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_is_valid_relative_encoder (uint64_t insert_count,
                                       uint64_t dropped_count,
                                       uint64_t rel_index)
{
  uint64_t abs_index;

  /* Defensive check: dropped_count should never exceed insert_count */
  if (dropped_count > insert_count)
    return QPACK_ERR_INTERNAL;

  /*
   * Step 1: Check if relative index is in range (not a future entry).
   * rel_index < insert_count is required for a valid conversion.
   */
  if (rel_index >= insert_count)
    return QPACK_ERR_INVALID_INDEX;

  /*
   * Step 2: Convert to absolute and check eviction bounds.
   * absolute = insert_count - relative - 1
   */
  abs_index = insert_count - rel_index - 1;

  /*
   * Step 3: Check if entry has been evicted.
   * Entries with abs_index < dropped_count have been evicted.
   */
  if (abs_index < dropped_count)
    return QPACK_ERR_EVICTED_INDEX;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_is_valid_relative_field (uint64_t base,
                                     uint64_t dropped_count,
                                     uint64_t rel_index)
{
  uint64_t abs_index;

  /*
   * Step 1: Check if relative index is in range.
   * rel_index < base is required (cannot reference entries at or after Base).
   */
  if (base == 0 || rel_index >= base)
    return QPACK_ERR_INVALID_INDEX;

  /*
   * Step 2: Convert to absolute and check eviction bounds.
   * absolute = base - relative - 1
   */
  abs_index = base - rel_index - 1;

  /*
   * Step 3: Check if entry has been evicted.
   */
  if (abs_index < dropped_count)
    return QPACK_ERR_EVICTED_INDEX;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_is_valid_postbase (uint64_t base,
                               uint64_t insert_count,
                               uint64_t pb_index)
{
  uint64_t abs_index;

  /*
   * Check for overflow when computing absolute index.
   */
  if (pb_index > UINT64_MAX - base)
    return QPACK_ERR_INVALID_INDEX;

  abs_index = base + pb_index;

  /*
   * RFC 9204 Section 3.2.6:
   * "A post-base index of 0 refers to the entry with absolute index
   * equal to Base."
   *
   * The absolute index must be < insert_count (cannot reference future).
   */
  if (abs_index >= insert_count)
    return QPACK_ERR_FUTURE_INDEX;

  /*
   * Note: Post-base entries are guaranteed not to be evicted because
   * they were inserted at or after Base, which is when encoding started.
   * The encoder cannot evict entries it's currently referencing.
   * No eviction check needed here.
   */

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_is_valid_absolute (uint64_t insert_count,
                               uint64_t dropped_count,
                               uint64_t abs_index)
{
  /* Defensive check: dropped_count should never exceed insert_count */
  if (dropped_count > insert_count)
    return QPACK_ERR_INTERNAL;

  /*
   * Check bounds: valid range is [dropped_count, insert_count)
   */

  /* Cannot reference entries not yet inserted */
  if (abs_index >= insert_count)
    return QPACK_ERR_FUTURE_INDEX;

  /* Cannot reference evicted entries */
  if (abs_index < dropped_count)
    return QPACK_ERR_EVICTED_INDEX;

  return QPACK_OK;
}
