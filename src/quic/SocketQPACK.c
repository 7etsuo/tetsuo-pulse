/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK.c - QPACK Primitives (RFC 9204 Section 4.1)
 *
 * Integer and string encoding/decoding for QPACK header compression.
 * Reuses HPACK Huffman encoding (RFC 7541 Appendix B) but adds support
 * for QPACK-specific prefix sizes.
 */

#include <string.h>

#include "quic/SocketQPACK.h"
#include "http/SocketHPACK.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/* Maximum continuation bytes for integer encoding.
 * Each continuation byte carries 7 bits.
 * For 62-bit values: ceil(62/7) = 9 continuation bytes max.
 * We use 10 for safety margin. */
#define QPACK_MAX_INT_CONTINUATION_BYTES 10

/* Bit masks for integer encoding */
#define QPACK_INT_CONTINUATION_MASK 0x80
#define QPACK_INT_PAYLOAD_MASK 0x7F
#define QPACK_INT_CONTINUATION_VAL 128

/* Maximum safe shift to avoid overflow during decoding.
 * 64 bits - 8 bits for last byte = 56 bits. */
#define QPACK_MAX_SAFE_SHIFT 56

/* Huffman flag position (highest bit in prefix) */
#define QPACK_STRING_HUFFMAN_FLAG 0x80

/* Conservative Huffman decode buffer ratio (worst-case is ~1.6x) */
#define QPACK_HUFFMAN_DECODE_RATIO 2

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *result_strings[] = {
  [QPACK_OK] = "OK",
  [QPACK_ERROR] = "Generic error",
  [QPACK_INCOMPLETE] = "Incomplete - need more data",
  [QPACK_ERROR_INTEGER] = "Integer overflow or invalid encoding",
  [QPACK_ERROR_HUFFMAN] = "Huffman encoding/decoding error",
  [QPACK_ERROR_BUFFER] = "Output buffer too small",
  [QPACK_ERROR_PREFIX] = "Invalid prefix bits (must be 3-8)",
  [QPACK_ERROR_NULL] = "NULL pointer argument",
};

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  if (result < 0 || result > QPACK_ERROR_NULL)
    return "Unknown error";
  return result_strings[result];
}

/* ============================================================================
 * Validation Helpers
 * ============================================================================
 */

static inline int
valid_prefix_bits (int prefix_bits)
{
  return prefix_bits >= SOCKETQPACK_PREFIX_MIN
         && prefix_bits <= SOCKETQPACK_PREFIX_MAX;
}

/* ============================================================================
 * Integer Encoding (RFC 9204 Section 4.1.1)
 * ============================================================================
 */

/**
 * Encode continuation bytes for values that exceed prefix capacity.
 */
static size_t
encode_int_continuation (uint64_t value,
                         unsigned char *output,
                         size_t pos,
                         size_t output_size)
{
  while (value >= QPACK_INT_CONTINUATION_VAL && pos < output_size)
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

ssize_t
SocketQPACK_int_encode (uint64_t value,
                        int prefix_bits,
                        unsigned char *output,
                        size_t output_size)
{
  uint64_t max_prefix;

  if (output == NULL)
    return -1;

  if (output_size == 0)
    return -1;

  if (!valid_prefix_bits (prefix_bits))
    return -1;

  /* Check maximum representable value */
  if (value > SOCKETQPACK_INT_MAX)
    return -1;

  /* Calculate maximum value that fits in prefix */
  max_prefix = ((uint64_t)1 << prefix_bits) - 1;

  /* Value fits in prefix - single byte encoding */
  if (value < max_prefix)
    {
      output[0] = (unsigned char)value;
      return 1;
    }

  /* Value exceeds prefix - use continuation bytes */
  output[0] = (unsigned char)max_prefix;
  size_t result
      = encode_int_continuation (value - max_prefix, output, 1, output_size);
  if (result == 0)
    return -1;

  return (ssize_t)result;
}

/* ============================================================================
 * Integer Decoding (RFC 9204 Section 4.1.1)
 * ============================================================================
 */

/**
 * Decode continuation bytes for multi-byte integers.
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

      /* Check for overflow before shifting */
      if (*shift > QPACK_MAX_SAFE_SHIFT)
        return QPACK_ERROR_INTEGER;

      uint64_t add_val = (byte_val & QPACK_INT_PAYLOAD_MASK) << *shift;
      if (*result > UINT64_MAX - add_val)
        return QPACK_ERROR_INTEGER;

      *result += add_val;
      *shift += 7;
    }
  while (byte_val & QPACK_INT_CONTINUATION_MASK);

  /* Final overflow check against QPACK maximum */
  if (*result > SOCKETQPACK_INT_MAX)
    return QPACK_ERROR_INTEGER;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_int_decode (const unsigned char *input,
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
    return QPACK_ERROR_NULL;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  if (!valid_prefix_bits (prefix_bits))
    return QPACK_ERROR_PREFIX;

  /* Extract prefix mask and initial value */
  max_prefix = ((uint64_t)1 << prefix_bits) - 1;
  result = input[pos++] & max_prefix;

  /* Single-byte encoding: value fits in prefix */
  if (result < max_prefix)
    {
      *value = result;
      *consumed = pos;
      return QPACK_OK;
    }

  /* Multi-byte encoding: decode continuation bytes */
  SocketQPACK_Result cont_result
      = decode_int_continuation (input, input_len, &pos, &result, &shift);
  if (cont_result != QPACK_OK)
    return cont_result;

  *value = result;
  *consumed = pos;
  return QPACK_OK;
}

/* ============================================================================
 * Integer Size Calculation
 * ============================================================================
 */

size_t
SocketQPACK_int_size (uint64_t value, int prefix_bits)
{
  uint64_t max_prefix;
  size_t size;

  if (!valid_prefix_bits (prefix_bits))
    return 0;

  if (value > SOCKETQPACK_INT_MAX)
    return 0;

  max_prefix = ((uint64_t)1 << prefix_bits) - 1;

  /* Value fits in prefix */
  if (value < max_prefix)
    return 1;

  /* Count continuation bytes needed */
  size = 1; /* prefix byte */
  value -= max_prefix;
  while (value >= QPACK_INT_CONTINUATION_VAL)
    {
      size++;
      value >>= 7;
    }
  size++; /* final byte */

  return size;
}

/* ============================================================================
 * String Encoding (RFC 9204 Section 4.1.2)
 * ============================================================================
 */

/**
 * Encode integer with flag bit in the appropriate position.
 * The flag is placed at position (8 - prefix_bits) in the first byte.
 */
static ssize_t
encode_int_with_flag (uint64_t value,
                      int prefix_bits,
                      unsigned char flag,
                      unsigned char *output,
                      size_t output_size)
{
  ssize_t int_len
      = SocketQPACK_int_encode (value, prefix_bits, output, output_size);
  if (int_len <= 0)
    return -1;

  /* Set flag bit in the position determined by prefix_bits.
   * For prefix_bits=7, the Huffman flag is at bit 7 (0x80).
   * For prefix_bits=6, it's at bit 6 (0x40), etc. */
  unsigned char flag_mask = (unsigned char)(1 << (prefix_bits));
  if (flag)
    output[0] |= flag_mask;

  return int_len;
}

ssize_t
SocketQPACK_string_encode (const unsigned char *input,
                           size_t input_len,
                           int use_huffman,
                           int prefix_bits,
                           unsigned char *output,
                           size_t output_size)
{
  size_t pos = 0;
  ssize_t encoded;
  size_t data_len = input_len;
  int use_huffman_actual = 0;

  if (output == NULL)
    return -1;

  if (output_size == 0)
    return -1;

  if (!valid_prefix_bits (prefix_bits))
    return -1;

  /* For non-empty strings, check if Huffman compression helps */
  if (use_huffman && input != NULL && input_len > 0)
    {
      size_t huffman_size = SocketHPACK_huffman_encoded_size (input, input_len);
      if (huffman_size < input_len)
        {
          data_len = huffman_size;
          use_huffman_actual = 1;
        }
    }

  /* Encode length with Huffman flag */
  encoded = encode_int_with_flag (data_len,
                                  prefix_bits,
                                  (unsigned char)use_huffman_actual,
                                  output,
                                  output_size);
  if (encoded < 0)
    return -1;
  pos = (size_t)encoded;

  /* Encode string data */
  if (input_len > 0)
    {
      if (input == NULL)
        return -1;

      if (use_huffman_actual)
        {
          encoded = SocketHPACK_huffman_encode (
              input, input_len, output + pos, output_size - pos);
          if (encoded < 0)
            return -1;
        }
      else
        {
          if (pos + input_len > output_size)
            return -1;
          memcpy (output + pos, input, input_len);
          encoded = (ssize_t)input_len;
        }
      pos += (size_t)encoded;
    }

  return (ssize_t)pos;
}

/* ============================================================================
 * String Decoding (RFC 9204 Section 4.1.2)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_string_decode (const unsigned char *input,
                           size_t input_len,
                           int prefix_bits,
                           unsigned char *output,
                           size_t output_size,
                           size_t *decoded_len,
                           size_t *consumed)
{
  size_t pos = 0;
  int huffman;
  uint64_t str_len;
  SocketQPACK_Result result;

  if (input == NULL || decoded_len == NULL || consumed == NULL)
    return QPACK_ERROR_NULL;

  if (!valid_prefix_bits (prefix_bits))
    return QPACK_ERROR_PREFIX;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  /* Extract Huffman flag from first byte */
  unsigned char flag_mask = (unsigned char)(1 << prefix_bits);
  huffman = (input[0] & flag_mask) != 0;

  /* Decode string length */
  result
      = SocketQPACK_int_decode (input, input_len, prefix_bits, &str_len, &pos);
  if (result != QPACK_OK)
    return result;

  /* Validate string length */
  if (str_len > SIZE_MAX)
    return QPACK_ERROR_INTEGER;

  size_t len = (size_t)str_len;

  /* Check if we have enough input data */
  if (pos + len > input_len)
    return QPACK_INCOMPLETE;

  /* Handle empty string */
  if (len == 0)
    {
      *decoded_len = 0;
      *consumed = pos;
      return QPACK_OK;
    }

  /* Output buffer is required for non-empty strings */
  if (output == NULL)
    return QPACK_ERROR_NULL;

  /* Decode string data */
  if (huffman)
    {
      /* Huffman-decode the string */
      ssize_t decoded
          = SocketHPACK_huffman_decode (input + pos, len, output, output_size);
      if (decoded < 0)
        return QPACK_ERROR_HUFFMAN;

      *decoded_len = (size_t)decoded;
    }
  else
    {
      /* Plain text - just copy */
      if (len > output_size)
        return QPACK_ERROR_BUFFER;

      memcpy (output, input + pos, len);
      *decoded_len = len;
    }

  *consumed = pos + len;
  return QPACK_OK;
}

/* ============================================================================
 * String Size Calculation
 * ============================================================================
 */

size_t
SocketQPACK_string_size (const unsigned char *input,
                         size_t input_len,
                         int use_huffman,
                         int prefix_bits)
{
  size_t data_len = input_len;
  size_t header_len;

  if (!valid_prefix_bits (prefix_bits))
    return 0;

  /* Check if Huffman compression reduces size */
  if (use_huffman && input != NULL && input_len > 0)
    {
      size_t huffman_size = SocketHPACK_huffman_encoded_size (input, input_len);
      if (huffman_size < input_len)
        data_len = huffman_size;
    }

  /* Calculate header (length prefix) size */
  header_len = SocketQPACK_int_size (data_len, prefix_bits);
  if (header_len == 0)
    return 0;

  return header_len + data_len;
}

/* ============================================================================
 * Indexed Field Line with Post-Base Index (RFC 9204 Section 4.5.3)
 * ============================================================================
 */

ssize_t
SocketQPACK_encode_indexed_postbase (uint64_t post_base_index,
                                     unsigned char *output,
                                     size_t output_size)
{
  ssize_t int_len;

  if (output == NULL)
    return -1;

  if (output_size == 0)
    return -1;

  /* Check maximum representable value */
  if (post_base_index > SOCKETQPACK_INT_MAX)
    return -1;

  /* Encode the post-base index with 4-bit prefix */
  int_len = SocketQPACK_int_encode (
      post_base_index, SOCKETQPACK_POSTBASE_PREFIX, output, output_size);
  if (int_len < 0)
    return -1;

  /* Apply the pattern bits 0001 to the first byte.
   * The 4-bit prefix means bits 0-3 hold the index (or 0x0F if multi-byte),
   * and we need to set bits 4-7 to 0001 (0x10). */
  output[0]
      = (unsigned char)((output[0] & 0x0F) | SOCKETQPACK_POSTBASE_PATTERN);

  return int_len;
}

SocketQPACK_Result
SocketQPACK_decode_indexed_postbase (const unsigned char *input,
                                     size_t input_len,
                                     uint64_t *post_base_index,
                                     size_t *consumed)
{
  SocketQPACK_Result result;

  if (input == NULL || post_base_index == NULL || consumed == NULL)
    return QPACK_ERROR_NULL;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  /* Verify this is a post-base indexed field line (pattern 0001) */
  if ((input[0] & SOCKETQPACK_POSTBASE_MASK) != SOCKETQPACK_POSTBASE_PATTERN)
    return QPACK_ERROR;

  /* Decode the 4-bit prefix integer */
  result = SocketQPACK_int_decode (
      input, input_len, SOCKETQPACK_POSTBASE_PREFIX, post_base_index, consumed);

  return result;
}

SocketQPACK_Result
SocketQPACK_validate_postbase_index (uint64_t base,
                                     uint64_t insert_count,
                                     uint64_t post_base_index)
{
  uint64_t absolute_index;

  /* Check for overflow in Base + post_base_index */
  if (base > UINT64_MAX - post_base_index)
    return QPACK_ERROR_INTEGER;

  absolute_index = base + post_base_index;

  /* RFC 9204 Section 3.2.6: Absolute index must be less than Insert Count.
   * This ensures we're not referencing an entry that hasn't been inserted yet.
   */
  if (absolute_index >= insert_count)
    return QPACK_ERROR;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_postbase_to_absolute (uint64_t base,
                                  uint64_t post_base_index,
                                  uint64_t *absolute_index)
{
  if (absolute_index == NULL)
    return QPACK_ERROR_NULL;

  /* Check for overflow in Base + post_base_index */
  if (base > UINT64_MAX - post_base_index)
    return QPACK_ERROR_INTEGER;

  *absolute_index = base + post_base_index;
  return QPACK_OK;
}
