/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK.c - QPACK Primitives and Field Line Encoding (RFC 9204)
 *
 * Implements:
 * - Section 4.1: Integer and string encoding/decoding primitives
 * - Section 4.5.6: Literal Field Line with Literal Name
 *
 * Reuses HPACK Huffman encoding (RFC 7541 Appendix B).
 */

#include <string.h>

#include "http/qpack/SocketQPACK.h"
#include "http/SocketHPACK.h"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/* Maximum continuation bytes for integer encoding.
 * Each continuation byte carries 7 bits.
 * For 62-bit values: ceil(62/7) = 9 continuation bytes max. */
#define QPACK_MAX_INT_CONTINUATION_BYTES 10

/* Bit masks for integer encoding */
#define QPACK_INT_CONTINUATION_MASK 0x80
#define QPACK_INT_PAYLOAD_MASK 0x7F
#define QPACK_INT_CONTINUATION_VAL 128

/* Maximum safe shift to avoid overflow during decoding.
 * 64 bits - 8 bits for last byte = 56 bits. */
#define QPACK_MAX_SAFE_SHIFT 56

/* Huffman flag for value string (highest bit in 7-bit prefix) */
#define QPACK_VALUE_HUFFMAN_FLAG 0x80

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
  [QPACK_ERROR_PATTERN] = "Invalid pattern bits for field line type",
};

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  if ((unsigned)result > QPACK_ERROR_PATTERN)
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
 * The flag is placed at position (prefix_bits) in the first byte.
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

  /* Set flag bit in the position determined by prefix_bits. */
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
 * Literal Field Line with Literal Name - Encoding (RFC 9204 Section 4.5.6)
 *
 * Wire format:
 *   0 0 1 N H NameLen(3+) | NameString | H ValueLen(7+) | ValueString
 *
 * Bit layout of first byte:
 *   [7:5] = 001 (pattern for literal literal)
 *   [4]   = N (never-indexed flag)
 *   [3]   = H (Huffman flag for name)
 *   [2:0] = Name length prefix (3 bits)
 * ============================================================================
 */

ssize_t
SocketQPACK_literal_literal_encode (const unsigned char *name,
                                    size_t name_len,
                                    const unsigned char *value,
                                    size_t value_len,
                                    int never_indexed,
                                    int use_huffman,
                                    unsigned char *output,
                                    size_t output_size)
{
  size_t pos = 0;
  ssize_t encoded;
  size_t name_data_len = name_len;
  size_t value_data_len = value_len;
  int name_huffman = 0;
  int value_huffman = 0;

  if (output == NULL)
    return -1;

  if (output_size == 0)
    return -1;

  /* Determine if Huffman helps for name */
  if (use_huffman && name != NULL && name_len > 0)
    {
      size_t huffman_size = SocketHPACK_huffman_encoded_size (name, name_len);
      if (huffman_size < name_len)
        {
          name_data_len = huffman_size;
          name_huffman = 1;
        }
    }

  /* Determine if Huffman helps for value */
  if (use_huffman && value != NULL && value_len > 0)
    {
      size_t huffman_size = SocketHPACK_huffman_encoded_size (value, value_len);
      if (huffman_size < value_len)
        {
          value_data_len = huffman_size;
          value_huffman = 1;
        }
    }

  /*
   * Encode first byte with:
   * - Pattern '001' (bits 7-5)
   * - N bit (bit 4)
   * - H bit for name (bit 3)
   * - Name length (bits 2-0, with 3-bit prefix)
   */

  /* Start with pattern and flags */
  unsigned char first_byte = SOCKETQPACK_LITERAL_LITERAL_PATTERN;
  if (never_indexed)
    first_byte |= SOCKETQPACK_NEVER_INDEXED_BIT;
  if (name_huffman)
    first_byte |= SOCKETQPACK_NAME_HUFFMAN_BIT;

  /* Encode name length with 3-bit prefix */
  encoded = SocketQPACK_int_encode (
      name_data_len, SOCKETQPACK_LITERAL_NAME_PREFIX, output, output_size);
  if (encoded < 0)
    return -1;

  /* Set pattern and flags in first byte (preserving length prefix bits) */
  output[0] = (output[0] & 0x07) | first_byte;
  pos = (size_t)encoded;

  /* Encode name string */
  if (name_len > 0)
    {
      if (name == NULL)
        return -1;

      if (name_huffman)
        {
          encoded = SocketHPACK_huffman_encode (
              name, name_len, output + pos, output_size - pos);
          if (encoded < 0)
            return -1;
        }
      else
        {
          if (pos + name_len > output_size)
            return -1;
          memcpy (output + pos, name, name_len);
          encoded = (ssize_t)name_len;
        }
      pos += (size_t)encoded;
    }

  /*
   * Encode value with:
   * - H bit for value (bit 7)
   * - Value length (bits 6-0, with 7-bit prefix)
   */
  if (pos >= output_size)
    return -1;

  encoded = SocketQPACK_int_encode (value_data_len,
                                    SOCKETQPACK_LITERAL_VALUE_PREFIX,
                                    output + pos,
                                    output_size - pos);
  if (encoded < 0)
    return -1;

  /* Set Huffman flag for value */
  if (value_huffman)
    output[pos] |= QPACK_VALUE_HUFFMAN_FLAG;

  pos += (size_t)encoded;

  /* Encode value string */
  if (value_len > 0)
    {
      if (value == NULL)
        return -1;

      if (value_huffman)
        {
          encoded = SocketHPACK_huffman_encode (
              value, value_len, output + pos, output_size - pos);
          if (encoded < 0)
            return -1;
        }
      else
        {
          if (pos + value_len > output_size)
            return -1;
          memcpy (output + pos, value, value_len);
          encoded = (ssize_t)value_len;
        }
      pos += (size_t)encoded;
    }

  return (ssize_t)pos;
}

/* ============================================================================
 * Literal Field Line with Literal Name - Decoding (RFC 9204 Section 4.5.6)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_literal_literal_decode (const unsigned char *input,
                                    size_t input_len,
                                    unsigned char *name_out,
                                    size_t name_out_size,
                                    unsigned char *value_out,
                                    size_t value_out_size,
                                    SocketQPACK_LiteralLiteral_T *result,
                                    size_t *consumed)
{
  size_t pos = 0;
  uint64_t name_len;
  uint64_t value_len;
  size_t bytes_consumed;
  SocketQPACK_Result res;

  if (input == NULL || result == NULL || consumed == NULL)
    return QPACK_ERROR_NULL;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  /* Validate pattern bits (must be '001') */
  if (!SocketQPACK_is_literal_literal (input[0]))
    return QPACK_ERROR_PATTERN;

  /* Extract flags from first byte */
  result->never_indexed = (input[0] & SOCKETQPACK_NEVER_INDEXED_BIT) != 0;
  int name_huffman = (input[0] & SOCKETQPACK_NAME_HUFFMAN_BIT) != 0;

  /* Decode name length with 3-bit prefix */
  res = SocketQPACK_int_decode (input,
                                input_len,
                                SOCKETQPACK_LITERAL_NAME_PREFIX,
                                &name_len,
                                &bytes_consumed);
  if (res != QPACK_OK)
    return res;
  pos = bytes_consumed;

  /* Validate name length */
  if (name_len > SIZE_MAX)
    return QPACK_ERROR_INTEGER;

  size_t name_wire_len = (size_t)name_len;

  /* Check if we have enough input for name */
  if (pos + name_wire_len > input_len)
    return QPACK_INCOMPLETE;

  /* Decode name string */
  if (name_wire_len > 0)
    {
      if (name_out == NULL)
        return QPACK_ERROR_NULL;

      if (name_huffman)
        {
          ssize_t decoded = SocketHPACK_huffman_decode (
              input + pos, name_wire_len, name_out, name_out_size);
          if (decoded < 0)
            return QPACK_ERROR_HUFFMAN;
          result->name_len = (size_t)decoded;
        }
      else
        {
          if (name_wire_len > name_out_size)
            return QPACK_ERROR_BUFFER;
          memcpy (name_out, input + pos, name_wire_len);
          result->name_len = name_wire_len;
        }
      result->name = name_out;
      pos += name_wire_len;
    }
  else
    {
      result->name = name_out;
      result->name_len = 0;
    }

  /* Check if we have at least one byte for value header */
  if (pos >= input_len)
    return QPACK_INCOMPLETE;

  /* Extract Huffman flag for value from value length byte */
  int value_huffman = (input[pos] & QPACK_VALUE_HUFFMAN_FLAG) != 0;

  /* Decode value length with 7-bit prefix */
  res = SocketQPACK_int_decode (input + pos,
                                input_len - pos,
                                SOCKETQPACK_LITERAL_VALUE_PREFIX,
                                &value_len,
                                &bytes_consumed);
  if (res != QPACK_OK)
    return res;
  pos += bytes_consumed;

  /* Validate value length */
  if (value_len > SIZE_MAX)
    return QPACK_ERROR_INTEGER;

  size_t value_wire_len = (size_t)value_len;

  /* Check if we have enough input for value */
  if (pos + value_wire_len > input_len)
    return QPACK_INCOMPLETE;

  /* Decode value string */
  if (value_wire_len > 0)
    {
      if (value_out == NULL)
        return QPACK_ERROR_NULL;

      if (value_huffman)
        {
          ssize_t decoded = SocketHPACK_huffman_decode (
              input + pos, value_wire_len, value_out, value_out_size);
          if (decoded < 0)
            return QPACK_ERROR_HUFFMAN;
          result->value_len = (size_t)decoded;
        }
      else
        {
          if (value_wire_len > value_out_size)
            return QPACK_ERROR_BUFFER;
          memcpy (value_out, input + pos, value_wire_len);
          result->value_len = value_wire_len;
        }
      result->value = value_out;
      pos += value_wire_len;
    }
  else
    {
      result->value = value_out;
      result->value_len = 0;
    }

  *consumed = pos;
  return QPACK_OK;
}

/* ============================================================================
 * Literal Field Line with Literal Name - Size Calculation
 * ============================================================================
 */

size_t
SocketQPACK_literal_literal_size (const unsigned char *name,
                                  size_t name_len,
                                  const unsigned char *value,
                                  size_t value_len,
                                  int use_huffman)
{
  size_t name_data_len = name_len;
  size_t value_data_len = value_len;
  size_t total_size;

  /* Check if Huffman helps for name */
  if (use_huffman && name != NULL && name_len > 0)
    {
      size_t huffman_size = SocketHPACK_huffman_encoded_size (name, name_len);
      if (huffman_size < name_len)
        name_data_len = huffman_size;
    }

  /* Check if Huffman helps for value */
  if (use_huffman && value != NULL && value_len > 0)
    {
      size_t huffman_size = SocketHPACK_huffman_encoded_size (value, value_len);
      if (huffman_size < value_len)
        value_data_len = huffman_size;
    }

  /* Calculate name header size (3-bit prefix) */
  size_t name_header
      = SocketQPACK_int_size (name_data_len, SOCKETQPACK_LITERAL_NAME_PREFIX);
  if (name_header == 0)
    return 0;

  /* Calculate value header size (7-bit prefix) */
  size_t value_header
      = SocketQPACK_int_size (value_data_len, SOCKETQPACK_LITERAL_VALUE_PREFIX);
  if (value_header == 0)
    return 0;

  /* Total = name header + name data + value header + value data */
  total_size = name_header + name_data_len + value_header + value_data_len;

  return total_size;
}
