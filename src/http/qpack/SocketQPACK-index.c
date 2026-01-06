/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-index.c
 * @brief QPACK index conversion and validation (RFC 9204 Sections 3.2.4-3.2.6).
 *
 * Implements the three index address spaces used in QPACK:
 * - Absolute Indexing: Canonical, monotonically increasing (Section 3.2.4)
 * - Relative Indexing: Used in encoder stream and field sections (Section 3.2.5)
 * - Post-Base Indexing: References entries inserted during encoding (Section 3.2.6)
 */

#include "http/qpack/SocketQPACK.h"

#include <stdint.h>

/* ============================================================================
 * ABSOLUTE <-> ENCODER RELATIVE CONVERSIONS (RFC 9204 Section 3.2.5)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_abs_to_relative_encoder (uint64_t insert_count,
                                     uint64_t abs_index,
                                     uint64_t *rel_out)
{
  /* Hardened NULL check - return error instead of crashing */
  if (rel_out == NULL)
    return QPACK_ERR_NULL_PARAM;

  /* RFC 9204 §3.2.5: Cannot reference entry not yet inserted */
  if (abs_index >= insert_count)
    return QPACK_ERR_INVALID_INDEX;

  /* Formula: relative = insert_count - abs_index - 1 */
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

  /* RFC 9204 §3.2.5: Relative index must be < insert_count */
  if (rel_index >= insert_count)
    return QPACK_ERR_INVALID_INDEX;

  /* Formula: absolute = insert_count - relative - 1 */
  *abs_out = insert_count - rel_index - 1;
  return QPACK_OK;
}

/* ============================================================================
 * ABSOLUTE <-> FIELD RELATIVE CONVERSIONS (RFC 9204 Section 3.2.5)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_abs_to_relative_field (uint64_t base,
                                   uint64_t abs_index,
                                   uint64_t *rel_out)
{
  /* Hardened NULL check */
  if (rel_out == NULL)
    return QPACK_ERR_NULL_PARAM;

  /* Base of 0 means no entries available for relative indexing */
  if (base == 0)
    return QPACK_ERR_INVALID_INDEX;

  /* RFC 9204 §3.2.5: abs_index must be < base for relative indexing */
  if (abs_index >= base)
    return QPACK_ERR_INVALID_INDEX;

  /* Formula: relative = base - abs_index - 1 */
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

  /* Base of 0 means no valid relative indices exist */
  if (base == 0)
    return QPACK_ERR_INVALID_INDEX;

  /* RFC 9204 §3.2.5: rel_index must be < base */
  if (rel_index >= base)
    return QPACK_ERR_INVALID_INDEX;

  /* Formula: absolute = base - relative - 1 */
  *abs_out = base - rel_index - 1;
  return QPACK_OK;
}

/* ============================================================================
 * ABSOLUTE <-> POST-BASE CONVERSIONS (RFC 9204 Section 3.2.6)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_abs_to_postbase (uint64_t base, uint64_t abs_index, uint64_t *pb_out)
{
  /* Hardened NULL check */
  if (pb_out == NULL)
    return QPACK_ERR_NULL_PARAM;

  /* RFC 9204 §3.2.6: Post-base indices reference entries >= base */
  if (abs_index < base)
    return QPACK_ERR_INVALID_INDEX;

  /* Formula: post_base = abs_index - base */
  *pb_out = abs_index - base;
  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_postbase_to_abs (uint64_t base, uint64_t pb_index, uint64_t *abs_out)
{
  /* Hardened NULL check */
  if (abs_out == NULL)
    return QPACK_ERR_NULL_PARAM;

  /* Check for overflow before addition */
  if (pb_index > UINT64_MAX - base)
    return QPACK_ERR_INVALID_INDEX;

  /* Formula: absolute = base + post_base */
  *abs_out = base + pb_index;
  return QPACK_OK;
}

/* ============================================================================
 * INDEX VALIDATION FUNCTIONS
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_is_valid_relative_encoder (uint64_t insert_count,
                                       uint64_t dropped_count,
                                       uint64_t rel_index)
{
  /* Defensive check: dropped_count should never exceed insert_count */
  if (dropped_count > insert_count)
    return QPACK_ERR_INTERNAL;

  /* Check if relative index is in valid range */
  if (rel_index >= insert_count)
    return QPACK_ERR_INVALID_INDEX;

  /* Convert to absolute and check if evicted */
  uint64_t abs_index = insert_count - rel_index - 1;

  if (abs_index < dropped_count)
    return QPACK_ERR_EVICTED_INDEX;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_is_valid_relative_field (uint64_t base,
                                     uint64_t dropped_count,
                                     uint64_t rel_index)
{
  /* Base of 0 means no valid relative indices */
  if (base == 0)
    return QPACK_ERR_INVALID_INDEX;

  /* Check if relative index is in valid range */
  if (rel_index >= base)
    return QPACK_ERR_INVALID_INDEX;

  /* Convert to absolute and check if evicted */
  uint64_t abs_index = base - rel_index - 1;

  if (abs_index < dropped_count)
    return QPACK_ERR_EVICTED_INDEX;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_is_valid_postbase (uint64_t base,
                               uint64_t insert_count,
                               uint64_t pb_index)
{
  /* Check for overflow */
  if (pb_index > UINT64_MAX - base)
    return QPACK_ERR_FUTURE_INDEX;

  /* Post-base index must reference an inserted entry */
  uint64_t abs_index = base + pb_index;

  if (abs_index >= insert_count)
    return QPACK_ERR_FUTURE_INDEX;

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

  /* Check if index references a future entry */
  if (abs_index >= insert_count)
    return QPACK_ERR_FUTURE_INDEX;

  /* Check if index references an evicted entry */
  if (abs_index < dropped_count)
    return QPACK_ERR_EVICTED_INDEX;

  return QPACK_OK;
}

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================
 */

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  static const char *strings[] = {
    [QPACK_OK] = "OK",
    [QPACK_INCOMPLETE] = "Incomplete - need more data",
    [QPACK_ERR_INVALID_INDEX] = "Invalid table index",
    [QPACK_ERR_EVICTED_INDEX] = "Referenced entry has been evicted",
    [QPACK_ERR_FUTURE_INDEX] = "Index references not-yet-inserted entry",
    [QPACK_ERR_BASE_OVERFLOW] = "Base would exceed Insert Count",
    [QPACK_ERR_TABLE_SIZE] = "Dynamic table size limit exceeded",
    [QPACK_ERR_HEADER_SIZE] = "Header too large",
    [QPACK_ERR_HUFFMAN] = "Huffman decoding error",
    [QPACK_ERR_INTEGER] = "Integer decoding error",
    [QPACK_ERR_DECOMPRESSION] = "Decompression failed",
    [QPACK_ERR_NULL_PARAM] = "NULL parameter passed to function",
    [QPACK_ERR_INTERNAL] = "Internal error",
  };

  if (result < 0 || result > QPACK_ERR_INTERNAL)
    return "Unknown error";

  return strings[result] ? strings[result] : "Unknown error";
}

size_t
SocketQPACK_estimate_capacity (size_t max_size)
{
  /* Estimate entries based on average header size (64 bytes + 32 overhead) */
  size_t avg_entry_size = 64 + SOCKETQPACK_ENTRY_OVERHEAD;
  size_t estimated = max_size / avg_entry_size;

  /* Minimum capacity of 16 */
  if (estimated < 16)
    return 16;

  /* Round up to next power of 2 for efficient ring buffer operations */
  size_t capacity = 16;
  while (capacity < estimated && capacity < (SIZE_MAX / 2))
    capacity *= 2;

  return capacity;
}
