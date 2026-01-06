/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-base.c
 * @brief QPACK Base Encoding Implementation (RFC 9204 Section 4.5.1.2)
 *
 * Implements Base calculation for QPACK field section decoding.
 * The Base value is used to resolve relative indices in the dynamic table.
 */

#include "http/SocketQPACK-private.h"
#include "http/SocketQPACK.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

/* ============================================================================
 * Exception Definition
 * ============================================================================
 */

const Except_T SocketQPACK_DecodeError
    = { &SocketQPACK_DecodeError, "QPACK decoding error" };

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *result_strings[] = {
  [QPACK_OK] = "OK",
  [QPACK_INCOMPLETE] = "Incomplete - need more data",
  [QPACK_ERROR] = "Generic error",
  [QPACK_ERROR_INVALID_BASE] = "Invalid Base calculation",
  [QPACK_ERROR_INVALID_INDEX] = "Invalid table index",
  [QPACK_ERROR_INTEGER] = "Integer overflow",
  [QPACK_ERROR_HEADER_SIZE] = "Header too large",
  [QPACK_ERROR_DECOMPRESSION_FAILED] = "Decompression failed",
};

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  if (result < 0 || result > QPACK_ERROR_DECOMPRESSION_FAILED)
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

static inline bool
valid_sign_bit (int sign)
{
  return sign == 0 || sign == 1;
}

/* ============================================================================
 * Variable-Length Integer Encoding/Decoding
 * ============================================================================
 */

/**
 * Encode continuation bytes for multi-byte integer.
 */
static size_t
encode_int_continuation (uint64_t value,
                         unsigned char *output,
                         size_t pos,
                         size_t output_size)
{
  while (value >= 128 && pos < output_size)
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
qpack_int_encode (uint64_t value,
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

/**
 * Decode continuation bytes for multi-byte integer.
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
        return QPACK_ERROR_INTEGER;

      byte_val = input[(*pos)++];

      if (*shift > QPACK_MAX_SAFE_SHIFT)
        return QPACK_ERROR_INTEGER;

      uint64_t add_val = (byte_val & QPACK_INT_PAYLOAD_MASK) << *shift;
      if (*result > UINT64_MAX - add_val)
        return QPACK_ERROR_INTEGER;

      *result += add_val;
      *shift += 7;
    }
  while (byte_val & QPACK_INT_CONTINUATION_MASK);

  return QPACK_OK;
}

SocketQPACK_Result
qpack_int_decode (const unsigned char *input,
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
 * Base Validation (RFC 9204 Section 4.5.1.2)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_validate_base (uint32_t req_insert_count,
                           int32_t delta_base,
                           int sign)
{
  /* Validate sign bit is 0 or 1 */
  if (!valid_sign_bit (sign))
    return QPACK_ERROR_INVALID_BASE;

  /* Validate delta_base is non-negative */
  if (delta_base < 0)
    return QPACK_ERROR_INVALID_BASE;

  /* RFC 9204 Section 4.5.1.2:
   * When Sign=1, ReqInsertCount MUST be greater than DeltaBase
   * to ensure Base >= 0 after: Base = ReqInsertCount - DeltaBase - 1 */
  if (sign == 1)
    {
      /* Cast delta_base to uint32_t for comparison (we already checked >= 0) */
      if (req_insert_count <= (uint32_t)delta_base)
        return QPACK_ERROR_INVALID_BASE;
    }

  return QPACK_OK;
}

/* ============================================================================
 * Base Calculation (RFC 9204 Section 4.5.1.2)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_calculate_base (uint32_t req_insert_count,
                            int32_t delta_base,
                            int sign,
                            int32_t *base_out)
{
  int32_t base;
  SocketQPACK_Result validation;

  if (base_out == NULL)
    return QPACK_ERROR;

  /* First validate the inputs */
  validation = SocketQPACK_validate_base (req_insert_count, delta_base, sign);
  if (validation != QPACK_OK)
    return validation;

  /* RFC 9204 Section 4.5.1.2:
   * If Sign == 0: Base = ReqInsertCount + DeltaBase
   * If Sign == 1: Base = ReqInsertCount - DeltaBase - 1 */
  if (sign == 0)
    {
      /* Forward: Base = ReqInsertCount + DeltaBase */
      /* Check for overflow */
      uint64_t sum = (uint64_t)req_insert_count + (uint64_t)delta_base;
      if (sum > INT32_MAX)
        return QPACK_ERROR_INVALID_BASE;

      base = (int32_t)sum;
    }
  else
    {
      /* Backward: Base = ReqInsertCount - DeltaBase - 1 */
      /* We already validated req_insert_count > delta_base, so this is safe */
      base = (int32_t)req_insert_count - delta_base - 1;
    }

  /* Final sanity check: Base must be non-negative */
  if (base < 0)
    return QPACK_ERROR_INVALID_BASE;

  *base_out = base;
  return QPACK_OK;
}

/* ============================================================================
 * Base Prefix Parsing (RFC 9204 Section 4.5.1.2)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_parse_base_prefix (const unsigned char *input,
                               size_t input_len,
                               uint32_t req_insert_count,
                               SocketQPACK_Base_T *base_out,
                               size_t *consumed)
{
  uint64_t delta_base_raw;
  size_t bytes_consumed;
  int sign;
  SocketQPACK_Result result;

  if (input == NULL || base_out == NULL || consumed == NULL)
    return QPACK_ERROR;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  /* Extract sign bit from first byte (bit 7) */
  sign = (input[0] & QPACK_SIGN_BIT_MASK) ? 1 : 0;

  /* Decode DeltaBase using 7-bit prefix */
  result = qpack_int_decode (input,
                             input_len,
                             QPACK_DELTABASE_PREFIX_BITS,
                             &delta_base_raw,
                             &bytes_consumed);
  if (result != QPACK_OK)
    return result;

  /* Validate delta_base fits in int32_t */
  if (delta_base_raw > INT32_MAX)
    return QPACK_ERROR_INTEGER;

  int32_t delta_base = (int32_t)delta_base_raw;

  /* Populate output structure */
  base_out->req_insert_count = req_insert_count;
  base_out->delta_base = delta_base;
  base_out->sign = sign;

  /* Calculate Base value */
  result = SocketQPACK_calculate_base (
      req_insert_count, delta_base, sign, &base_out->base);
  if (result != QPACK_OK)
    return result;

  *consumed = bytes_consumed;
  return QPACK_OK;
}

/* ============================================================================
 * Base Prefix Encoding (RFC 9204 Section 4.5.1.2)
 * ============================================================================
 */

int
SocketQPACK_encode_base_prefix (int32_t base,
                                uint32_t req_insert_count,
                                unsigned char *output,
                                size_t output_size)
{
  int sign;
  int32_t delta_base;
  unsigned char int_buf[QPACK_INT_BUF_SIZE];
  size_t int_len;

  if (output == NULL || output_size == 0)
    return -1;

  /* Determine sign and delta_base from base and req_insert_count
   *
   * RFC 9204 Section 4.5.1.2:
   * - If Base >= ReqInsertCount: Sign=0, DeltaBase = Base - ReqInsertCount
   * - If Base < ReqInsertCount:  Sign=1, DeltaBase = ReqInsertCount - Base - 1
   */
  if (base >= (int32_t)req_insert_count)
    {
      sign = 0;
      delta_base = base - (int32_t)req_insert_count;
    }
  else
    {
      sign = 1;
      delta_base = (int32_t)req_insert_count - base - 1;
    }

  /* Sanity check: delta_base should be non-negative */
  if (delta_base < 0)
    return -1;

  /* Encode DeltaBase with 7-bit prefix */
  int_len = qpack_int_encode ((uint64_t)delta_base,
                              QPACK_DELTABASE_PREFIX_BITS,
                              int_buf,
                              sizeof (int_buf));
  if (int_len == 0 || int_len > output_size)
    return -1;

  /* Copy encoded integer to output, adding sign bit to first byte */
  output[0] = int_buf[0];
  if (sign == 1)
    output[0] |= QPACK_SIGN_BIT_MASK;

  for (size_t i = 1; i < int_len; i++)
    output[i] = int_buf[i];

  return (int)int_len;
}
