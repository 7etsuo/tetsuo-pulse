/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-prefix.c
 * @brief QPACK Encoded Field Section Prefix (RFC 9204 Section 4.5.1)
 *
 * Implements encoding and decoding for the Field Section Prefix, which
 * precedes all encoded field sections in QPACK. The prefix communicates
 * the Required Insert Count and Base to the decoder.
 *
 * Wire format (RFC 9204 Section 4.5.1):
 *
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * |   Required Insert Count (8+)  |
 * +---+---+---+---+---+---+---+---+
 * | S |      Delta Base (7+)      |
 * +---+---------------------------+
 *
 * Required Insert Count is encoded using 8-bit prefix integer.
 * Delta Base is encoded with 7-bit prefix, and S bit indicates sign:
 * - S=0: Base = Required Insert Count + Delta Base
 * - S=1: Base = Required Insert Count - Delta Base - 1
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-4.5.1
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

/** Required Insert Count prefix bits (8-bit integer) */
#define RIC_PREFIX_BITS 8

/** Delta Base prefix bits (7-bit integer) */
#define DELTA_BASE_PREFIX_BITS 7

/** Sign bit mask for Delta Base (bit 7 of second field) */
#define DELTA_BASE_SIGN_BIT 0x80

/* ============================================================================
 * ENCODE FIELD SECTION PREFIX (RFC 9204 Section 4.5.1)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_encode_prefix (uint64_t required_insert_count,
                           uint64_t base,
                           uint64_t max_entries,
                           unsigned char *output,
                           size_t output_size,
                           size_t *bytes_written)
{
  size_t offset = 0;
  size_t encoded_len;
  uint64_t encoded_ric;
  uint64_t delta_base;
  int sign_bit;

  /* Validate parameters */
  if (output == NULL || bytes_written == NULL)
    return QPACK_ERR_NULL_PARAM;

  *bytes_written = 0;

  if (output_size == 0)
    return QPACK_ERR_TABLE_SIZE;

  /*
   * RFC 9204 Section 4.5.1.1: Encoding the Required Insert Count
   *
   * If Required Insert Count is 0, encode as 0.
   * Otherwise, encode using modular arithmetic:
   *   EncodedRIC = (RIC mod (2 * MaxEntries)) + 1
   *
   * MaxEntries is derived from SETTINGS_QPACK_MAX_TABLE_CAPACITY / 32.
   */
  if (required_insert_count == 0)
    {
      encoded_ric = 0;
    }
  else
    {
      if (max_entries == 0)
        return QPACK_ERR_TABLE_SIZE; /* Invalid max_entries */

      encoded_ric = (required_insert_count % (2 * max_entries)) + 1;
    }

  /* Encode Required Insert Count as 8-bit prefix integer */
  encoded_len = SocketHPACK_int_encode (
      encoded_ric, RIC_PREFIX_BITS, output, output_size);
  if (encoded_len == 0)
    return QPACK_ERR_INTEGER;

  offset += encoded_len;

  /*
   * RFC 9204 Section 4.5.1.2: Encoding the Base
   *
   * Base is encoded as Delta Base relative to Required Insert Count.
   * Sign bit determines the direction:
   *   - S=0 (positive): Base = RIC + Delta Base
   *   - S=1 (negative): Base = RIC - Delta Base - 1
   */
  if (base >= required_insert_count)
    {
      /* Positive delta: S=0 */
      sign_bit = 0;
      delta_base = base - required_insert_count;
    }
  else
    {
      /* Negative delta: S=1 */
      sign_bit = 1;
      delta_base = required_insert_count - base - 1;
    }

  /* Check buffer space */
  if (offset >= output_size)
    return QPACK_ERR_TABLE_SIZE;

  /* Encode Delta Base as 7-bit prefix integer */
  encoded_len = SocketHPACK_int_encode (delta_base,
                                        DELTA_BASE_PREFIX_BITS,
                                        output + offset,
                                        output_size - offset);
  if (encoded_len == 0)
    return QPACK_ERR_INTEGER;

  /* Set sign bit (bit 7 of the Delta Base byte) */
  if (sign_bit)
    output[offset] |= DELTA_BASE_SIGN_BIT;
  else
    output[offset] &= ~DELTA_BASE_SIGN_BIT;

  offset += encoded_len;

  *bytes_written = offset;
  return QPACK_OK;
}

/* ============================================================================
 * DECODE FIELD SECTION PREFIX (RFC 9204 Section 4.5.1)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_decode_prefix (const unsigned char *input,
                           size_t input_len,
                           uint64_t max_entries,
                           uint64_t total_insert_count,
                           SocketQPACK_FieldSectionPrefix *prefix,
                           size_t *bytes_consumed)
{
  size_t offset = 0;
  size_t consumed;
  uint64_t encoded_ric;
  uint64_t delta_base;
  uint64_t required_insert_count;
  uint64_t base;
  int sign_bit;
  SocketHPACK_Result hpack_result;

  /* Validate parameters */
  if (prefix == NULL || bytes_consumed == NULL)
    return QPACK_ERR_NULL_PARAM;

  *bytes_consumed = 0;
  prefix->required_insert_count = 0;
  prefix->delta_base = 0;
  prefix->base = 0;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  if (input == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * RFC 9204 Section 4.5.1.1: Decode Required Insert Count
   *
   * Decode the 8-bit prefix integer.
   */
  hpack_result = SocketHPACK_int_decode (input + offset,
                                         input_len - offset,
                                         RIC_PREFIX_BITS,
                                         &encoded_ric,
                                         &consumed);

  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_INCOMPLETE;
  if (hpack_result != HPACK_OK)
    return QPACK_ERR_INTEGER;

  offset += consumed;

  /*
   * RFC 9204 Section 4.5.1.1: Decode Required Insert Count from encoded value
   *
   * If EncodedRIC == 0, then RIC = 0.
   * Otherwise, recover RIC using:
   *   FullRange = 2 * MaxEntries
   *   MaxValue = TotalInsertCount + MaxEntries
   *   MaxWrapped = floor(MaxValue / FullRange) * FullRange
   *   RIC = MaxWrapped + EncodedRIC - 1
   *
   *   If RIC > MaxValue, subtract FullRange.
   */
  if (encoded_ric == 0)
    {
      required_insert_count = 0;
    }
  else
    {
      if (max_entries == 0)
        return QPACK_ERR_TABLE_SIZE;

      uint64_t full_range = 2 * max_entries;
      uint64_t max_value = total_insert_count + max_entries;
      uint64_t max_wrapped = (max_value / full_range) * full_range;

      required_insert_count = max_wrapped + encoded_ric - 1;

      /* Handle wraparound */
      if (required_insert_count > max_value)
        {
          if (required_insert_count < full_range)
            return QPACK_ERR_DECOMPRESSION; /* Cannot decode RIC */
          required_insert_count -= full_range;
        }
    }

  /*
   * RFC 9204 Section 4.5.1: Validate Required Insert Count
   *
   * The decoder MUST treat it as a connection error of type
   * QPACK_DECOMPRESSION_FAILED if Required Insert Count is greater than
   * the number of entries the decoder has actually inserted.
   */
  if (required_insert_count > total_insert_count)
    return QPACK_ERR_DECOMPRESSION;

  /* Check for Delta Base byte */
  if (offset >= input_len)
    return QPACK_INCOMPLETE;

  /*
   * RFC 9204 Section 4.5.1.2: Decode Delta Base
   *
   * Extract sign bit (bit 7) and decode 7-bit prefix integer.
   */
  sign_bit = (input[offset] & DELTA_BASE_SIGN_BIT) ? 1 : 0;

  hpack_result = SocketHPACK_int_decode (input + offset,
                                         input_len - offset,
                                         DELTA_BASE_PREFIX_BITS,
                                         &delta_base,
                                         &consumed);

  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_INCOMPLETE;
  if (hpack_result != HPACK_OK)
    return QPACK_ERR_INTEGER;

  offset += consumed;

  /*
   * RFC 9204 Section 4.5.1.2: Compute Base from Delta Base
   *
   * S=0: Base = RIC + Delta Base
   * S=1: Base = RIC - Delta Base - 1
   */
  if (sign_bit == 0)
    {
      /* Check for overflow */
      if (delta_base > UINT64_MAX - required_insert_count)
        return QPACK_ERR_DECOMPRESSION;
      base = required_insert_count + delta_base;
    }
  else
    {
      /* Check for underflow */
      if (delta_base + 1 > required_insert_count)
        return QPACK_ERR_DECOMPRESSION;
      base = required_insert_count - delta_base - 1;
    }

  /* Store decoded values */
  prefix->required_insert_count = required_insert_count;
  prefix->delta_base
      = sign_bit ? -(int64_t)(delta_base + 1) : (int64_t)delta_base;
  prefix->base = base;

  *bytes_consumed = offset;
  return QPACK_OK;
}

/* ============================================================================
 * VALIDATE PREFIX (RFC 9204 Section 4.5.1)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_validate_prefix (const SocketQPACK_FieldSectionPrefix *prefix,
                             uint64_t total_insert_count)
{
  if (prefix == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * RFC 9204 Section 4.5.1:
   * Required Insert Count MUST NOT exceed total entries inserted.
   */
  if (prefix->required_insert_count > total_insert_count)
    return QPACK_ERR_DECOMPRESSION;

  /*
   * RFC 9204 Section 4.5.1.2:
   * Base must be within valid range. For negative delta, base < RIC.
   * For positive delta, base >= RIC.
   */
  if (prefix->delta_base >= 0)
    {
      /* Positive delta: base should equal RIC + delta_base */
      if (prefix->base
          != prefix->required_insert_count + (uint64_t)prefix->delta_base)
        return QPACK_ERR_BASE_OVERFLOW;
    }
  else
    {
      /* Negative delta: base should equal RIC - |delta_base| */
      uint64_t abs_delta = (uint64_t)(-(prefix->delta_base + 1)) + 1;
      if (abs_delta > prefix->required_insert_count)
        return QPACK_ERR_BASE_OVERFLOW;
      if (prefix->base != prefix->required_insert_count - abs_delta)
        return QPACK_ERR_BASE_OVERFLOW;
    }

  return QPACK_OK;
}

/* ============================================================================
 * COMPUTE MAX ENTRIES (RFC 9204 Section 4.5.1)
 * ============================================================================
 */

uint64_t
SocketQPACK_compute_max_entries (uint64_t max_table_capacity)
{
  /*
   * RFC 9204 Section 4.5.1.1:
   * MaxEntries = floor(MaxTableCapacity / 32)
   *
   * 32 is the QPACK entry overhead (SOCKETQPACK_ENTRY_OVERHEAD).
   */
  return max_table_capacity / SOCKETQPACK_ENTRY_OVERHEAD;
}

uint64_t
SocketQPACK_max_entries (uint64_t max_table_capacity)
{
  return SocketQPACK_compute_max_entries (max_table_capacity);
}

/* ============================================================================
 * REQUIRED INSERT COUNT ENCODING (RFC 9204 Section 4.5.1.1)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_encode_required_insert_count (uint64_t required_insert_count,
                                          uint64_t max_entries,
                                          uint64_t *encoded_ric)
{
  if (encoded_ric == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * RFC 9204 Section 4.5.1.1: Encoding the Required Insert Count
   *
   * If Required Insert Count is 0, encode as 0.
   * Otherwise, encode using modular arithmetic:
   *   EncodedRIC = (RIC mod (2 * MaxEntries)) + 1
   *
   * MaxEntries is derived from SETTINGS_QPACK_MAX_TABLE_CAPACITY / 32.
   */
  if (required_insert_count == 0)
    {
      *encoded_ric = 0;
      return QPACK_OK;
    }

  /* Non-zero RIC requires non-zero MaxEntries */
  if (max_entries == 0)
    return QPACK_ERR_TABLE_SIZE;

  /* Prevent overflow: 2 * max_entries must fit in uint64_t */
  if (max_entries > UINT64_MAX / 2)
    return QPACK_ERR_TABLE_SIZE;

  uint64_t full_range = 2 * max_entries;
  *encoded_ric = (required_insert_count % full_range) + 1;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_decode_required_insert_count (uint64_t encoded_ric,
                                          uint64_t max_entries,
                                          uint64_t total_insert_count,
                                          uint64_t *required_insert_count)
{
  if (required_insert_count == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * RFC 9204 Section 4.5.1.1: Decoding the Required Insert Count
   *
   * If EncodedRIC == 0, then RIC = 0.
   * Otherwise, recover RIC using wrap-around detection:
   *   FullRange = 2 * MaxEntries
   *   MaxValue = TotalInsertCount + MaxEntries
   *   MaxWrapped = floor(MaxValue / FullRange) * FullRange
   *   RIC = MaxWrapped + EncodedRIC - 1
   *
   *   If RIC > MaxValue:
   *     If RIC <= FullRange: ERROR (cannot wrap)
   *     RIC -= FullRange
   *
   *   If RIC == 0: ERROR (invalid decoded result)
   */
  if (encoded_ric == 0)
    {
      *required_insert_count = 0;
      return QPACK_OK;
    }

  /* Non-zero EncodedRIC requires non-zero MaxEntries */
  if (max_entries == 0)
    return QPACK_ERR_TABLE_SIZE;

  uint64_t full_range = 2 * max_entries;

  /* RFC 9204: EncodedRIC MUST NOT exceed FullRange */
  if (encoded_ric > full_range)
    return QPACK_ERR_DECOMPRESSION;

  uint64_t max_value = total_insert_count + max_entries;
  uint64_t max_wrapped = (max_value / full_range) * full_range;

  uint64_t ric = max_wrapped + encoded_ric - 1;

  /* Handle wrap-around */
  if (ric > max_value)
    {
      /* If RIC > MaxValue but <= FullRange, wrap is impossible */
      if (ric <= full_range)
        return QPACK_ERR_DECOMPRESSION;

      ric -= full_range;
    }

  /* RFC 9204: Decoded RIC of 0 is an error (should have been encoded as 0) */
  if (ric == 0)
    return QPACK_ERR_DECOMPRESSION;

  /* Validate RIC does not reference future entries */
  if (ric > total_insert_count)
    return QPACK_ERR_DECOMPRESSION;

  *required_insert_count = ric;
  return QPACK_OK;
}
