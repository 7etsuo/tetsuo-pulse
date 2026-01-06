/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK-encoder.c - QPACK Encoder Stream Instructions (RFC 9204 Section
 * 4.3)
 *
 * Implements encoding of encoder stream instructions, including:
 * - Insert with Literal Name (Section 4.3.3)
 * - Integer and string encoding primitives
 */

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"

#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"

/* ============================================================================
 * Exception Definition
 * ============================================================================
 */

const Except_T SocketQPACK_Error
    = { &SocketQPACK_Error, "QPACK compression error" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketQPACK);

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "QPACK"

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *result_strings[] = {
  [QPACK_OK] = "OK",
  [QPACK_INCOMPLETE] = "Incomplete - need more data",
  [QPACK_ERROR] = "Generic error",
  [QPACK_ERROR_INVALID_INDEX] = "Invalid table index",
  [QPACK_ERROR_HUFFMAN] = "Huffman decoding error",
  [QPACK_ERROR_INTEGER] = "Integer overflow",
  [QPACK_ERROR_TABLE_SIZE] = "Invalid dynamic table size update",
  [QPACK_ERROR_HEADER_SIZE] = "Header too large",
  [QPACK_ERROR_LIST_SIZE] = "Header list too large",
  [QPACK_ERROR_BOMB] = "QPACK bomb detected",
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

/* ============================================================================
 * Integer Encoding (RFC 9204 Section 4.1.1)
 *
 * Same algorithm as HPACK (RFC 7541 Section 5.1)
 * ============================================================================
 */

static size_t
encode_int_continuation (uint64_t value,
                         unsigned char *output,
                         size_t pos,
                         size_t output_size)
{
  while (value >= 128 && pos < output_size)
    {
      output[pos++] = (unsigned char)(0x80 | (value & 0x7F));
      value >>= 7;
    }

  if (pos >= output_size)
    return 0;

  output[pos++] = (unsigned char)value;
  return pos;
}

size_t
SocketQPACK_int_encode (uint64_t value,
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
 * Integer Decoding (RFC 9204 Section 4.1.1)
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
        return QPACK_ERROR_INTEGER;

      byte_val = input[(*pos)++];

      if (*shift > QPACK_MAX_SAFE_SHIFT)
        return QPACK_ERROR_INTEGER;

      uint64_t add_val = (byte_val & 0x7F) << *shift;
      if (*result > UINT64_MAX - add_val)
        return QPACK_ERROR_INTEGER;

      *result += add_val;
      *shift += 7;
    }
  while (byte_val & 0x80);

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
 * String Encoding (RFC 9204 Section 4.1.2)
 * ============================================================================
 */

static ssize_t
qpack_encode_int_with_flag (uint64_t value,
                            int prefix_bits,
                            unsigned char flag,
                            unsigned char *output,
                            size_t output_size)
{
  unsigned char int_buf[QPACK_INT_BUF_SIZE];
  size_t int_len;

  int_len
      = SocketQPACK_int_encode (value, prefix_bits, int_buf, sizeof (int_buf));
  if (int_len == 0 || int_len > output_size)
    return -1;

  output[0] = flag | int_buf[0];
  for (size_t i = 1; i < int_len; i++)
    output[i] = int_buf[i];

  return (ssize_t)int_len;
}

ssize_t
SocketQPACK_string_encode (const char *str,
                           size_t len,
                           int prefix_bits,
                           int use_huffman,
                           unsigned char *output,
                           size_t output_size)
{
  size_t pos = 0;
  ssize_t encoded;
  size_t data_len = len;
  unsigned char flag = QPACK_STRING_LITERAL_FLAG;
  int use_huffman_actual = 0;

  if (str == NULL && len > 0)
    return -1;
  if (output == NULL && output_size > 0)
    return -1;
  if (!valid_prefix_bits (prefix_bits))
    return -1;

  /* Check if Huffman encoding would be smaller */
  if (use_huffman && len > 0)
    {
      size_t huffman_size
          = SocketQPACK_huffman_encoded_size ((const unsigned char *)str, len);
      if (huffman_size < len)
        {
          data_len = huffman_size;
          flag = QPACK_STRING_HUFFMAN_FLAG;
          use_huffman_actual = 1;
        }
    }

  /* Encode length with H flag */
  encoded = qpack_encode_int_with_flag (
      data_len, prefix_bits, flag, output, output_size);
  if (encoded < 0)
    return -1;
  pos = (size_t)encoded;

  /* Encode string data */
  if (use_huffman_actual)
    {
      encoded = SocketQPACK_huffman_encode (
          (const unsigned char *)str, len, output + pos, output_size - pos);
      if (encoded < 0)
        return -1;
    }
  else
    {
      if (pos + len > output_size)
        return -1;
      if (len > 0)
        memcpy (output + pos, str, len);
      encoded = (ssize_t)len;
    }
  pos += (size_t)encoded;

  return (ssize_t)pos;
}

/* ============================================================================
 * String Decoding (RFC 9204 Section 4.1.2)
 * ============================================================================
 */

static SocketQPACK_Result
allocate_string_buffer (Arena_T arena, size_t buf_size, char **buf_out)
{
  size_t alloc_size = buf_size + 1;
  if (!SocketSecurity_check_size (alloc_size))
    return QPACK_ERROR_BOMB;

  *buf_out = ALLOC (arena, alloc_size);
  if (*buf_out == NULL)
    return QPACK_ERROR;

  return QPACK_OK;
}

static SocketQPACK_Result
decode_string_data_literal (const unsigned char *input,
                            size_t str_len,
                            size_t pos,
                            char **str_out,
                            size_t *str_len_out,
                            Arena_T arena)
{
  SocketQPACK_Result result = allocate_string_buffer (arena, str_len, str_out);
  if (result != QPACK_OK)
    return result;

  assert (input != NULL);
  memcpy (*str_out, input + pos, str_len);
  (*str_out)[str_len] = '\0';
  *str_len_out = str_len;
  return QPACK_OK;
}

static SocketQPACK_Result
decode_string_data_huffman (const unsigned char *input,
                            size_t encoded_len,
                            size_t pos,
                            char **str_out,
                            size_t *str_len_out,
                            Arena_T arena)
{
  size_t max_decoded;
  if (!SocketSecurity_check_multiply (
          encoded_len, QPACK_HUFFMAN_RATIO, &max_decoded))
    return QPACK_ERROR_BOMB;

  SocketQPACK_Result result
      = allocate_string_buffer (arena, max_decoded, str_out);
  if (result != QPACK_OK)
    return result;

  ssize_t decoded = SocketQPACK_huffman_decode (
      input + pos, encoded_len, (unsigned char *)*str_out, max_decoded);
  if (decoded < 0)
    return QPACK_ERROR_HUFFMAN;

  (*str_out)[decoded] = '\0';
  *str_len_out = (size_t)decoded;
  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_string_decode (const unsigned char *input,
                           size_t input_len,
                           int prefix_bits,
                           char **str_out,
                           size_t *str_len_out,
                           size_t *consumed,
                           Arena_T arena)
{
  size_t pos = 0;
  int huffman;
  uint64_t str_len;
  SocketQPACK_Result result;

  if (input == NULL || str_out == NULL || str_len_out == NULL
      || consumed == NULL || arena == NULL)
    return QPACK_ERROR;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  if (!valid_prefix_bits (prefix_bits))
    return QPACK_ERROR;

  /* Check H bit - located at bit position (prefix_bits) in the first byte
   * For 7-bit prefix: H is bit 7 (0x80)
   * For 5-bit prefix: H is bit 5 (0x20)
   * RFC 9204 Section 4.1.2: "The most significant bit of the first byte
   * indicates whether the string is Huffman-encoded." */
  unsigned char h_bit_mask = (unsigned char)(1 << prefix_bits);
  huffman = (input[0] & h_bit_mask) != 0;

  /* Decode length */
  result
      = SocketQPACK_int_decode (input, input_len, prefix_bits, &str_len, &pos);
  if (result != QPACK_OK)
    return result;

  /* Validate length */
  if (str_len > SIZE_MAX || pos + str_len > input_len)
    return (str_len > SIZE_MAX) ? QPACK_ERROR_INTEGER : QPACK_INCOMPLETE;

  size_t len = (size_t)str_len;

  /* Decode string data */
  if (huffman)
    result = decode_string_data_huffman (
        input, len, pos, str_out, str_len_out, arena);
  else
    result = decode_string_data_literal (
        input, len, pos, str_out, str_len_out, arena);

  if (result != QPACK_OK)
    return result;

  *consumed = pos + len;
  return QPACK_OK;
}

/* ============================================================================
 * Insert with Literal Name (RFC 9204 Section 4.3.3)
 *
 * Wire format:
 *      0   1   2   3   4   5   6   7
 *    +---+---+---+---+---+---+---+---+
 *    | 0 | 1 | H | Name Length (5+)  |
 *    +---+---+---+---+---+---+---+---+
 *    |  Name String (Length bytes)   |
 *    +---+---------------------------+
 *    | H |     Value Length (7+)     |
 *    +---+---------------------------+
 *    |  Value String (Length bytes)  |
 *    +-------------------------------+
 * ============================================================================
 */

ssize_t
SocketQPACK_encode_insert_literal_name (
    const SocketQPACK_InsertLiteralInstruction *instr,
    unsigned char *output,
    size_t output_size)
{
  size_t pos = 0;
  ssize_t encoded;

  if (instr == NULL || output == NULL)
    return -1;

  if (instr->name == NULL && instr->name_len > 0)
    return -1;
  if (instr->value == NULL && instr->value_len > 0)
    return -1;

  /* Check maximum string lengths */
  if (instr->name_len > SOCKETQPACK_MAX_HEADER_SIZE
      || instr->value_len > SOCKETQPACK_MAX_HEADER_SIZE)
    return -1;

  /* Encode name string with 5-bit prefix
   * First byte: 01 | H | length[4:0]
   * H bit is 0x20 (bit 5) when using Huffman */
  unsigned char name_flag
      = QPACK_INSERT_LITERAL_NAME_PATTERN; /* 0x40 = pattern 01 */
  if (instr->name_huffman)
    {
      /* Check if Huffman would actually be smaller */
      size_t huffman_size
          = SocketQPACK_huffman_encoded_size (instr->name, instr->name_len);
      if (huffman_size < instr->name_len)
        name_flag |= 0x20; /* Set H bit */
    }

  /* Encode name */
  if (output_size == 0)
    return -1;

  /* First, compute the actual data we'll encode */
  int name_use_huffman
      = instr->name_huffman
        && (SocketQPACK_huffman_encoded_size (instr->name, instr->name_len)
            < instr->name_len);
  size_t name_data_len
      = name_use_huffman
            ? SocketQPACK_huffman_encoded_size (instr->name, instr->name_len)
            : instr->name_len;

  /* Encode length with pattern and H flag */
  unsigned char int_buf[QPACK_INT_BUF_SIZE];
  size_t int_len = SocketQPACK_int_encode (name_data_len,
                                           QPACK_INSERT_LITERAL_NAME_PREFIX,
                                           int_buf,
                                           sizeof (int_buf));
  if (int_len == 0 || int_len > output_size)
    return -1;

  /* Set pattern bits (01) and H flag */
  output[0] = QPACK_INSERT_LITERAL_NAME_PATTERN | int_buf[0];
  if (name_use_huffman)
    output[0] |= 0x20; /* H bit */

  for (size_t i = 1; i < int_len; i++)
    output[i] = int_buf[i];
  pos = int_len;

  /* Encode name string data */
  if (name_use_huffman)
    {
      encoded = SocketQPACK_huffman_encode (
          instr->name, instr->name_len, output + pos, output_size - pos);
      if (encoded < 0)
        return -1;
    }
  else
    {
      if (pos + instr->name_len > output_size)
        return -1;
      if (instr->name_len > 0)
        memcpy (output + pos, instr->name, instr->name_len);
      encoded = (ssize_t)instr->name_len;
    }
  pos += (size_t)encoded;

  /* Encode value string with 7-bit prefix */
  encoded = SocketQPACK_string_encode ((const char *)instr->value,
                                       instr->value_len,
                                       QPACK_INSERT_LITERAL_VALUE_PREFIX,
                                       instr->value_huffman,
                                       output + pos,
                                       output_size - pos);
  if (encoded < 0)
    return -1;
  pos += (size_t)encoded;

  return (ssize_t)pos;
}

/* ============================================================================
 * Decode Insert with Literal Name (RFC 9204 Section 4.3.3)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_decode_insert_literal_name (const unsigned char *input,
                                        size_t input_len,
                                        char **name_out,
                                        size_t *name_len,
                                        char **value_out,
                                        size_t *value_len,
                                        size_t *consumed,
                                        Arena_T arena)
{
  size_t pos = 0;
  size_t name_consumed, value_consumed;
  SocketQPACK_Result result;

  if (input == NULL || name_out == NULL || name_len == NULL || value_out == NULL
      || value_len == NULL || consumed == NULL || arena == NULL)
    return QPACK_ERROR;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  /* Verify instruction pattern (bits 7-6 = 01) */
  if ((input[0] & QPACK_INSERT_LITERAL_NAME_MASK)
      != QPACK_INSERT_LITERAL_NAME_PATTERN)
    return QPACK_ERROR;

  /* Decode name string (5-bit prefix) */
  result = SocketQPACK_string_decode (input + pos,
                                      input_len - pos,
                                      QPACK_INSERT_LITERAL_NAME_PREFIX,
                                      name_out,
                                      name_len,
                                      &name_consumed,
                                      arena);
  if (result != QPACK_OK)
    return result;
  pos += name_consumed;

  /* Decode value string (7-bit prefix) */
  result = SocketQPACK_string_decode (input + pos,
                                      input_len - pos,
                                      QPACK_INSERT_LITERAL_VALUE_PREFIX,
                                      value_out,
                                      value_len,
                                      &value_consumed,
                                      arena);
  if (result != QPACK_OK)
    return result;
  pos += value_consumed;

  *consumed = pos;
  return QPACK_OK;
}

/* ============================================================================
 * Process Insert with Literal Name and Add to Dynamic Table
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_process_insert_literal_name (SocketQPACK_DynamicTable_T table,
                                         const unsigned char *input,
                                         size_t input_len,
                                         size_t *consumed,
                                         Arena_T arena)
{
  char *name = NULL;
  size_t name_len = 0;
  char *value = NULL;
  size_t value_len = 0;
  SocketQPACK_Result result;

  if (table == NULL)
    return QPACK_ERROR;

  /* Decode the instruction */
  result = SocketQPACK_decode_insert_literal_name (
      input, input_len, &name, &name_len, &value, &value_len, consumed, arena);
  if (result != QPACK_OK)
    return result;

  /* Insert into dynamic table */
  result = SocketQPACK_DynamicTable_insert (
      table, name, name_len, value, value_len);

  return result;
}
