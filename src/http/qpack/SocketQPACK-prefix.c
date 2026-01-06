/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-prefix.c
 * @brief QPACK Field Section Prefix encoding/decoding (RFC 9204 Section 4.5.1)
 *
 * Implements the Encoded Field Section Prefix which appears at the start of
 * each encoded field section. The prefix contains:
 * - Required Insert Count: encoded with 8-bit prefix
 * - Sign bit (S) and Delta Base: encoded with 1+7 bit layout
 *
 * The Base is computed from Required Insert Count and Delta Base based on
 * the sign bit.
 */

#include "http/qpack/SocketQPACK-private.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

/* ============================================================================
 * Constants
 * ============================================================================
 */

/* Integer encoding constants (same as HPACK, RFC 7541 Section 5.1) */
#define QPACK_INT_CONTINUATION_MASK 0x80
#define QPACK_INT_PAYLOAD_MASK 0x7F
#define QPACK_INT_CONTINUATION_VALUE 128
#define QPACK_MAX_INT_CONTINUATION_BYTES 10
#define QPACK_MAX_SAFE_SHIFT 56

/* Field section prefix bit layout */
#define QPACK_PREFIX_RIC_BITS 8    /* Required Insert Count: 8-bit prefix */
#define QPACK_PREFIX_BASE_BITS 7   /* Delta Base: 7-bit prefix */
#define QPACK_PREFIX_SIGN_BIT 0x80 /* Sign bit in Delta Base octet */

/* Buffer sizes */
#define QPACK_INT_BUF_SIZE 16

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *result_strings[] = {
  [QPACK_OK] = "OK",
  [QPACK_INCOMPLETE] = "Incomplete - need more data",
  [QPACK_ERROR] = "Generic error",
  [QPACK_ERROR_INTEGER_OVERFLOW] = "Integer overflow",
  [QPACK_ERROR_INVALID_REQUIRED_INSERT_COUNT] = "Invalid Required Insert Count",
  [QPACK_ERROR_INVALID_BASE] = "Invalid Base",
  [QPACK_ERROR_BUFFER_TOO_SMALL] = "Buffer too small",
};

const char *
socketqpack_result_string (SocketQPACK_Result result)
{
  if (result < 0 || result > QPACK_ERROR_BUFFER_TOO_SMALL)
    return "Unknown error";
  return result_strings[result];
}

/* ============================================================================
 * Validation Helpers
 * ============================================================================
 */

static inline bool
valid_prefix_bits (int prefix_bits)
{
  return prefix_bits >= 1 && prefix_bits <= 8;
}

/* ============================================================================
 * Integer Encoding (RFC 9204 Section 4.1.1, RFC 7541 Section 5.1)
 * ============================================================================
 */

static size_t
encode_int_continuation (uint64_t value,
                         unsigned char *output,
                         size_t pos,
                         size_t output_size)
{
  while (value >= QPACK_INT_CONTINUATION_VALUE && pos < output_size)
    {
      output[pos++] = (unsigned char)(QPACK_INT_CONTINUATION_MASK
                                      | (value & QPACK_INT_PAYLOAD_MASK));
      value >>= 7;
    }

  if (pos >= output_size)
    return 0;

  output[pos++] = (unsigned char)value;
  return pos;
}

size_t
socketqpack_encode_integer (uint64_t value,
                            int prefix_bits,
                            unsigned char *output,
                            size_t output_size)
{
  uint64_t max_prefix;

  if (output == NULL || output_size == 0 || !valid_prefix_bits (prefix_bits))
    return 0;

  max_prefix = ((uint64_t)1 << prefix_bits) - 1;

  if (value < max_prefix)
    {
      output[0] = (unsigned char)value;
      return 1;
    }

  output[0] = (unsigned char)max_prefix;
  return encode_int_continuation (value - max_prefix, output, 1, output_size);
}

/* ============================================================================
 * Integer Decoding (RFC 9204 Section 4.1.1, RFC 7541 Section 5.1)
 * ============================================================================
 */

static SocketQPACK_Result
decode_int_continuation (const unsigned char *input,
                         size_t input_len,
                         size_t *pos,
                         uint64_t *result,
                         unsigned int *shift)
{
  uint64_t byte_val;
  unsigned int continuation_count = 0;

  do
    {
      if (*pos >= input_len)
        return QPACK_INCOMPLETE;

      continuation_count++;
      if (continuation_count > QPACK_MAX_INT_CONTINUATION_BYTES)
        return QPACK_ERROR_INTEGER_OVERFLOW;

      byte_val = input[(*pos)++];

      if (*shift > QPACK_MAX_SAFE_SHIFT)
        return QPACK_ERROR_INTEGER_OVERFLOW;

      uint64_t add_val = (byte_val & QPACK_INT_PAYLOAD_MASK) << *shift;
      if (*result > UINT64_MAX - add_val)
        return QPACK_ERROR_INTEGER_OVERFLOW;

      *result += add_val;
      *shift += 7;
    }
  while (byte_val & QPACK_INT_CONTINUATION_MASK);

  return QPACK_OK;
}

SocketQPACK_Result
socketqpack_decode_integer (const unsigned char *input,
                            size_t input_len,
                            int prefix_bits,
                            uint64_t *value,
                            size_t *consumed)
{
  size_t pos = 0;
  uint64_t max_prefix;
  uint64_t result;
  unsigned int shift = 0;

  if (input == NULL || value == NULL || consumed == NULL)
    return QPACK_ERROR;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  if (!valid_prefix_bits (prefix_bits))
    return QPACK_ERROR;

  max_prefix = ((uint64_t)1 << prefix_bits) - 1;
  result = input[pos++] & max_prefix;

  if (result < max_prefix)
    {
      *value = result;
      *consumed = pos;
      return QPACK_OK;
    }

  SocketQPACK_Result cont_result
      = decode_int_continuation (input, input_len, &pos, &result, &shift);
  if (cont_result != QPACK_OK)
    return cont_result;

  *value = result;
  *consumed = pos;
  return QPACK_OK;
}

/* ============================================================================
 * Required Insert Count Encoding/Decoding (RFC 9204 Section 4.5.1.1)
 * ============================================================================
 *
 * Required Insert Count is encoded modulo 2 * MaxEntries to reduce size.
 * For decode, we use the formula:
 *   if EncodedInsertCount > 0:
 *     MaxValue = TotalNumberOfInserts + MaxEntries
 *     FullRange = 2 * MaxEntries
 *     if EncodedInsertCount > MaxValue % FullRange:
 *       MaxValue -= FullRange
 *     ReqInsertCount = MaxValue - (MaxValue % FullRange) + EncodedInsertCount
 */

static size_t
encode_required_insert_count (size_t required_insert_count,
                              size_t max_entries,
                              unsigned char *output,
                              size_t output_size)
{
  if (required_insert_count == 0)
    {
      /* Zero encodes directly as zero */
      return socketqpack_encode_integer (
          0, QPACK_PREFIX_RIC_BITS, output, output_size);
    }

  /* Encode as (RIC mod (2 * MaxEntries)) + 1 */
  size_t full_range = 2 * max_entries;
  size_t encoded = (required_insert_count % full_range) + 1;

  return socketqpack_encode_integer (
      encoded, QPACK_PREFIX_RIC_BITS, output, output_size);
}

static SocketQPACK_Result
decode_required_insert_count (const unsigned char *input,
                              size_t input_len,
                              size_t max_entries,
                              size_t total_inserts,
                              size_t *required_insert_count,
                              size_t *consumed)
{
  uint64_t encoded_insert_count;
  SocketQPACK_Result result;

  result = socketqpack_decode_integer (
      input, input_len, QPACK_PREFIX_RIC_BITS, &encoded_insert_count, consumed);
  if (result != QPACK_OK)
    return result;

  if (encoded_insert_count == 0)
    {
      *required_insert_count = 0;
      return QPACK_OK;
    }

  /* RFC 9204 Section 4.5.1.1 decoding algorithm:
   *
   * FullRange = 2 * MaxEntries
   * if EncodedInsertCount > 0:
   *   MaxValue = TotalNumberOfInserts + MaxEntries
   *   MaxWrapped = MaxValue % FullRange
   *   if EncodedInsertCount > MaxWrapped:
   *     MaxValue -= FullRange
   *   ReqInsertCount = MaxValue - MaxWrapped + EncodedInsertCount - 1
   *
   * The -1 at the end is because encoding adds +1 to avoid zero.
   */
  if (max_entries == 0)
    return QPACK_ERROR_INVALID_REQUIRED_INSERT_COUNT;

  size_t full_range = 2 * max_entries;
  size_t max_value = total_inserts + max_entries;
  size_t max_wrapped = max_value % full_range;
  size_t encoded = (size_t)encoded_insert_count;

  if (encoded > max_wrapped)
    {
      if (max_value < full_range)
        return QPACK_ERROR_INVALID_REQUIRED_INSERT_COUNT;
      max_value -= full_range;
    }

  /* Subtract 1 because encoding adds 1 to avoid zero */
  *required_insert_count = max_value - max_wrapped + encoded - 1;

  /* Validate: Required Insert Count cannot be 0 when encoded was non-zero
   * (This can happen if max_value - max_wrapped + encoded - 1 == 0) */
  if (*required_insert_count == 0 && encoded_insert_count != 0)
    return QPACK_ERROR_INVALID_REQUIRED_INSERT_COUNT;

  /* Validate: Required Insert Count cannot exceed total inserts */
  if (*required_insert_count > total_inserts)
    return QPACK_ERROR_INVALID_REQUIRED_INSERT_COUNT;

  return QPACK_OK;
}

/* ============================================================================
 * Delta Base Encoding/Decoding (RFC 9204 Section 4.5.1.2)
 * ============================================================================
 *
 * Delta Base format:
 *   +---+---+---+---+---+---+---+---+
 *   | S |  Delta Base (7+)         |
 *   +---+---------------------------+
 *
 * S=0: Base = ReqInsertCount + DeltaBase (Base >= ReqInsertCount)
 * S=1: Base = ReqInsertCount - DeltaBase - 1 (Base < ReqInsertCount)
 */

static size_t
encode_delta_base (size_t required_insert_count,
                   size_t base,
                   unsigned char *output,
                   size_t output_size)
{
  unsigned char int_buf[QPACK_INT_BUF_SIZE];
  size_t int_len;

  if (base >= required_insert_count)
    {
      /* S=0: Delta Base = Base - Required Insert Count */
      size_t delta = base - required_insert_count;
      int_len = socketqpack_encode_integer (
          delta, QPACK_PREFIX_BASE_BITS, int_buf, sizeof (int_buf));
      if (int_len == 0 || int_len > output_size)
        return 0;

      /* First byte has S=0 (clear sign bit) */
      output[0] = int_buf[0] & ~QPACK_PREFIX_SIGN_BIT;
      memcpy (output + 1, int_buf + 1, int_len - 1);
      return int_len;
    }
  else
    {
      /* S=1: Delta Base = Required Insert Count - Base - 1 */
      size_t delta = required_insert_count - base - 1;
      int_len = socketqpack_encode_integer (
          delta, QPACK_PREFIX_BASE_BITS, int_buf, sizeof (int_buf));
      if (int_len == 0 || int_len > output_size)
        return 0;

      /* First byte has S=1 (set sign bit) */
      output[0] = int_buf[0] | QPACK_PREFIX_SIGN_BIT;
      memcpy (output + 1, int_buf + 1, int_len - 1);
      return int_len;
    }
}

static SocketQPACK_Result
decode_delta_base (const unsigned char *input,
                   size_t input_len,
                   size_t required_insert_count,
                   SocketQPACK_FieldSectionPrefix *prefix,
                   size_t *consumed)
{
  uint64_t delta_value;
  SocketQPACK_Result result;
  unsigned char sign_bit;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  /* Extract sign bit from first byte */
  sign_bit = input[0] & QPACK_PREFIX_SIGN_BIT;

  /* Decode the integer value (7-bit prefix) */
  result = socketqpack_decode_integer (
      input, input_len, QPACK_PREFIX_BASE_BITS, &delta_value, consumed);
  if (result != QPACK_OK)
    return result;

  /* Compute Base based on sign bit */
  if (sign_bit == 0)
    {
      /* S=0: Base = Required Insert Count + Delta Base */
      prefix->delta_base = (int64_t)delta_value;
      prefix->base = required_insert_count + (size_t)delta_value;
    }
  else
    {
      /* S=1: Base = Required Insert Count - Delta Base - 1 */
      prefix->delta_base = -(int64_t)delta_value - 1;

      /* Check for underflow */
      if (delta_value >= required_insert_count)
        return QPACK_ERROR_INVALID_BASE;

      prefix->base = required_insert_count - (size_t)delta_value - 1;
    }

  return QPACK_OK;
}

/* ============================================================================
 * Field Section Prefix Public API (RFC 9204 Section 4.5.1)
 * ============================================================================
 */

ssize_t
socketqpack_encode_prefix (size_t required_insert_count,
                           size_t base,
                           size_t max_entries,
                           unsigned char *output,
                           size_t output_size)
{
  size_t pos = 0;
  size_t bytes_written;

  if (output == NULL || output_size == 0)
    return -QPACK_ERROR;

  /* Encode Required Insert Count (8-bit prefix) */
  bytes_written = encode_required_insert_count (
      required_insert_count, max_entries, output + pos, output_size - pos);
  if (bytes_written == 0)
    return -QPACK_ERROR_BUFFER_TOO_SMALL;
  pos += bytes_written;

  /* Encode Delta Base with sign bit (7-bit prefix) */
  bytes_written = encode_delta_base (
      required_insert_count, base, output + pos, output_size - pos);
  if (bytes_written == 0)
    return -QPACK_ERROR_BUFFER_TOO_SMALL;
  pos += bytes_written;

  return (ssize_t)pos;
}

SocketQPACK_DecodePrefixResult
socketqpack_decode_prefix (const unsigned char *input,
                           size_t input_len,
                           size_t max_entries,
                           size_t total_inserts)
{
  SocketQPACK_DecodePrefixResult result = { 0 };
  size_t pos = 0;
  size_t consumed;
  SocketQPACK_Result status;

  if (input == NULL || input_len == 0)
    {
      result.status = QPACK_INCOMPLETE;
      return result;
    }

  /* Decode Required Insert Count */
  status = decode_required_insert_count (input,
                                         input_len,
                                         max_entries,
                                         total_inserts,
                                         &result.prefix.required_insert_count,
                                         &consumed);
  if (status != QPACK_OK)
    {
      result.status = status;
      return result;
    }
  pos += consumed;

  /* Decode Delta Base and compute absolute Base */
  status = decode_delta_base (input + pos,
                              input_len - pos,
                              result.prefix.required_insert_count,
                              &result.prefix,
                              &consumed);
  if (status != QPACK_OK)
    {
      result.status = status;
      return result;
    }
  pos += consumed;

  result.status = QPACK_OK;
  result.consumed = pos;
  return result;
}

SocketQPACK_Result
socketqpack_validate_prefix (const SocketQPACK_FieldSectionPrefix *prefix,
                             size_t total_inserts)
{
  if (prefix == NULL)
    return QPACK_ERROR;

  /* Required Insert Count must not exceed total insertions */
  if (prefix->required_insert_count > total_inserts)
    return QPACK_ERROR_INVALID_REQUIRED_INSERT_COUNT;

  /* Base validation is handled during decode */
  /* Additional validation can be added here if needed */

  return QPACK_OK;
}
