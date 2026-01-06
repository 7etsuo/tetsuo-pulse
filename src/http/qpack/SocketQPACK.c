/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK.c - QPACK Header Compression (RFC 9204)
 *
 * Required Insert Count encoding/decoding for field section prefix.
 */

#include "http/SocketQPACK.h"

#include <assert.h>
#include <string.h>

/* ============================================================================
 * Exception Definition
 * ============================================================================
 */

const Except_T SocketQPACK_Error
    = { &SocketQPACK_Error, "QPACK compression error" };

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *result_strings[] = {
  [QPACK_OK] = "OK",
  [QPACK_INCOMPLETE] = "Incomplete - need more data",
  [QPACK_ERROR] = "Generic error",
  [QPACK_ERROR_INVALID_INDEX] = "Invalid table index",
  [QPACK_ERROR_INSERT_COUNT] = "Invalid Required Insert Count",
  [QPACK_ERROR_INTEGER] = "Integer overflow",
  [QPACK_ERROR_TABLE_SIZE] = "Invalid dynamic table size update",
  [QPACK_ERROR_HEADER_SIZE] = "Header too large",
  [QPACK_ERROR_LIST_SIZE] = "Header list too large",
};

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  if (result < 0 || result > QPACK_ERROR_LIST_SIZE)
    return "Unknown error";
  return result_strings[result];
}

/* ============================================================================
 * Required Insert Count Encoding/Decoding (RFC 9204 Section 4.5.1.1)
 * ============================================================================
 */

uint32_t
SocketQPACK_max_entries (uint32_t max_table_capacity)
{
  return max_table_capacity / SOCKETQPACK_ENTRY_OVERHEAD;
}

uint64_t
SocketQPACK_encode_required_insert_count (uint64_t required_insert_count,
                                          uint32_t max_table_capacity)
{
  uint32_t max_entries;
  uint64_t full_range;

  if (required_insert_count == 0)
    return 0;

  max_entries = SocketQPACK_max_entries (max_table_capacity);

  /* Edge case: MaxEntries = 0 when table capacity < 32 */
  if (max_entries == 0)
    return required_insert_count;

  full_range = (uint64_t)max_entries * 2;

  /* RFC 9204 Section 4.5.1.1:
   * EncodedInsertCount = (ReqInsertCount mod (2 * MaxEntries)) + 1 */
  return (required_insert_count % full_range) + 1;
}

SocketQPACK_Result
SocketQPACK_decode_required_insert_count (uint64_t encoded_insert_count,
                                          uint32_t max_table_capacity,
                                          uint64_t total_inserts,
                                          uint64_t *decoded_out)
{
  uint32_t max_entries;
  uint64_t full_range;
  uint64_t max_value;
  uint64_t max_wrapped;
  uint64_t req_insert_count;

  if (decoded_out == NULL)
    return QPACK_ERROR;

  /* RFC 9204 Section 4.5.1.1: EncodedInsertCount = 0 means RIC = 0 */
  if (encoded_insert_count == 0)
    {
      *decoded_out = 0;
      return QPACK_OK;
    }

  max_entries = SocketQPACK_max_entries (max_table_capacity);

  /* Edge case: MaxEntries = 0 when table capacity < 32 */
  if (max_entries == 0)
    {
      /* Cannot have non-zero RIC with zero MaxEntries */
      return QPACK_ERROR_INSERT_COUNT;
    }

  full_range = (uint64_t)max_entries * 2;

  /* RFC 9204 Section 4.5.1.1: Reject if EncodedInsertCount > FullRange */
  if (encoded_insert_count > full_range)
    return QPACK_ERROR_INSERT_COUNT;

  /* MaxValue = TotalNumberOfInserts + MaxEntries */
  max_value = total_inserts + max_entries;

  /* MaxWrapped = floor(MaxValue / FullRange) * FullRange */
  max_wrapped = (max_value / full_range) * full_range;

  /* ReqInsertCount = MaxWrapped + EncodedInsertCount - 1 */
  req_insert_count = max_wrapped + encoded_insert_count - 1;

  /* Handle wrap-around: if ReqInsertCount > MaxValue */
  if (req_insert_count > max_value)
    {
      /* RFC 9204: if ReqInsertCount <= FullRange, this is an error */
      if (req_insert_count <= full_range)
        return QPACK_ERROR_INSERT_COUNT;

      req_insert_count -= full_range;
    }

  /* RFC 9204: Final ReqInsertCount must not be 0 */
  if (req_insert_count == 0)
    return QPACK_ERROR_INSERT_COUNT;

  *decoded_out = req_insert_count;
  return QPACK_OK;
}
