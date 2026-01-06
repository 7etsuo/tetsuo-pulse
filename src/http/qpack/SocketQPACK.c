/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK.c - QPACK Header Compression (RFC 9204)
 *
 * Integer/string encoding, static/dynamic table operations,
 * encoder instructions.
 */

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"

#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"

/* Reuse HPACK Huffman codec */
#include "http/SocketHPACK.h"

#define T SocketQPACK_DynamicTable_T

SOCKET_DECLARE_MODULE_EXCEPTION (SocketQPACK);

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "QPACK"

/* ============================================================================
 * Constants
 * ============================================================================
 */

/* Integer encoding constants (same as HPACK RFC 7541 Section 5.1) */
#define QPACK_INT_CONTINUATION_MASK 0x80
#define QPACK_INT_PAYLOAD_MASK 0x7F
#define QPACK_INT_CONTINUATION_VALUE 128
#define QPACK_INT_BUF_SIZE 16
#define QPACK_MAX_INT_CONTINUATION_BYTES 10
#define QPACK_MAX_SAFE_SHIFT 56

/* Huffman decode buffer ratio */
#define QPACK_HUFFMAN_RATIO 2

/* ============================================================================
 * Exception Definition
 * ============================================================================
 */

const Except_T SocketQPACK_Error
    = { &SocketQPACK_Error, "QPACK compression error" };

#define RAISE_QPACK_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketQPACK, e)

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

static const char *result_strings[] = {
  [QPACK_OK] = "OK",
  [QPACK_INCOMPLETE] = "Incomplete - need more data",
  [QPACK_ERROR] = "Generic error",
  [QPACK_ERROR_INVALID_INDEX] = "Invalid table index",
  [QPACK_ERROR_HUFFMAN] = "Huffman encoding/decoding error",
  [QPACK_ERROR_INTEGER] = "Integer overflow",
  [QPACK_ERROR_TABLE_SIZE] = "Dynamic table size exceeded",
  [QPACK_ERROR_HEADER_SIZE] = "Header too large",
  [QPACK_ERROR_ENCODER_STREAM] = "Encoder stream error",
  [QPACK_ERROR_DECODER_STREAM] = "Decoder stream error",
  [QPACK_ERROR_DECOMPRESSION] = "Decompression failure",
};

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  if (result < 0 || result > QPACK_ERROR_DECOMPRESSION)
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
 * Integer Encoding (RFC 7541 Section 5.1, used by QPACK)
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
                           int use_huffman,
                           unsigned char *output,
                           size_t output_size)
{
  size_t pos = 0;
  ssize_t encoded;
  size_t data_len = len;
  unsigned char flag = 0; /* No Huffman */
  int use_huffman_actual = 0;

  if (str == NULL && len > 0)
    return -1;
  if (output == NULL && output_size > 0)
    return -1;

  if (use_huffman && len > 0)
    {
      size_t huffman_size
          = SocketHPACK_huffman_encoded_size ((const unsigned char *)str, len);
      if (huffman_size < len)
        {
          data_len = huffman_size;
          flag = QPACK_STRING_HUFFMAN_FLAG;
          use_huffman_actual = 1;
        }
    }

  encoded = qpack_encode_int_with_flag (
      data_len, QPACK_STRING_PREFIX, flag, output, output_size);
  if (encoded < 0)
    return -1;
  pos = (size_t)encoded;

  if (len == 0)
    return (ssize_t)pos;

  if (use_huffman_actual)
    {
      encoded = SocketHPACK_huffman_encode (
          (const unsigned char *)str, len, output + pos, output_size - pos);
      if (encoded < 0)
        return -1;
    }
  else
    {
      if (pos + len > output_size)
        return -1;
      memcpy (output + pos, str, len);
      encoded = (ssize_t)len;
    }
  pos += (size_t)encoded;

  return (ssize_t)pos;
}

static SocketQPACK_Result
allocate_string_buffer (Arena_T arena, size_t buf_size, char **buf_out)
{
  size_t alloc_size = buf_size + 1;
  if (!SocketSecurity_check_size (alloc_size))
    return QPACK_ERROR;

  *buf_out = ALLOC (arena, alloc_size);
  if (*buf_out == NULL)
    return QPACK_ERROR;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_string_decode (const unsigned char *input,
                           size_t input_len,
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

  huffman = (input[0] & QPACK_STRING_HUFFMAN_FLAG) != 0;
  result = SocketQPACK_int_decode (
      input, input_len, QPACK_STRING_PREFIX, &str_len, &pos);
  if (result != QPACK_OK)
    return result;

  /* 32-bit platform overflow check */
  if (str_len > SIZE_MAX || pos + str_len > input_len)
    return (str_len > SIZE_MAX) ? QPACK_ERROR_INTEGER : QPACK_INCOMPLETE;

  size_t len = (size_t)str_len;

  if (huffman)
    {
      /* Decode Huffman */
      size_t max_decoded;
      if (!SocketSecurity_check_multiply (
              len, QPACK_HUFFMAN_RATIO, &max_decoded))
        return QPACK_ERROR;

      result = allocate_string_buffer (arena, max_decoded, str_out);
      if (result != QPACK_OK)
        return result;

      ssize_t decoded = SocketHPACK_huffman_decode (
          input + pos, len, (unsigned char *)*str_out, max_decoded);
      if (decoded < 0)
        return QPACK_ERROR_HUFFMAN;

      (*str_out)[decoded] = '\0';
      *str_len_out = (size_t)decoded;
    }
  else
    {
      /* Literal string */
      result = allocate_string_buffer (arena, len, str_out);
      if (result != QPACK_OK)
        return result;

      memcpy (*str_out, input + pos, len);
      (*str_out)[len] = '\0';
      *str_len_out = len;
    }

  *consumed = pos + len;
  return QPACK_OK;
}

/* ============================================================================
 * Insert with Name Reference (RFC 9204 Section 4.3.2)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_validate_nameref_index (int is_static,
                                    size_t name_index,
                                    SocketQPACK_DynamicTable_T table)
{
  if (is_static)
    {
      if (name_index >= SOCKETQPACK_STATIC_TABLE_SIZE)
        {
          SOCKET_LOG_WARN_MSG ("QPACK: static name index %zu out of bounds "
                               "(max %zu)",
                               name_index,
                               (size_t)(SOCKETQPACK_STATIC_TABLE_SIZE - 1));
          return QPACK_ERROR_INVALID_INDEX;
        }
    }
  else
    {
      if (table == NULL)
        {
          SOCKET_LOG_ERROR_MSG ("QPACK: NULL table for dynamic name reference");
          return QPACK_ERROR;
        }

      uint64_t insertion_count = table->insertion_count;
      uint64_t drop_count = table->drop_count;

      /* For dynamic table reference in encoder instruction:
       * The name_index is relative to the base of the dynamic table.
       * Valid range: drop_count <= absolute_index < insertion_count */
      if (name_index >= table->count)
        {
          SOCKET_LOG_WARN_MSG ("QPACK: dynamic name index %zu out of bounds "
                               "(table count %zu)",
                               name_index,
                               table->count);
          return QPACK_ERROR_INVALID_INDEX;
        }
    }

  return QPACK_OK;
}

ssize_t
SocketQPACK_encode_insert_nameref (const SocketQPACK_InsertNameRef *instr,
                                   SocketQPACK_DynamicTable_T table,
                                   unsigned char *output,
                                   size_t output_size)
{
  size_t pos = 0;
  ssize_t encoded;
  unsigned char first_byte_flags;
  SocketQPACK_Result result;

  if (instr == NULL || output == NULL)
    return -1;

  /* Validate name index */
  result = SocketQPACK_validate_nameref_index (
      instr->is_static, instr->name_index, table);
  if (result != QPACK_OK)
    return -1;

  /* Build first byte flags:
   * Bit 7: Always 1 for Insert with Name Reference
   * Bit 6: T bit (1 for static, 0 for dynamic) */
  first_byte_flags = instr->is_static ? QPACK_INSTR_INSERT_NAMEREF_STATIC
                                      : QPACK_INSTR_INSERT_NAMEREF_DYNAMIC;

  /* Encode name index with 6-bit prefix */
  encoded = qpack_encode_int_with_flag (instr->name_index,
                                        QPACK_INSTR_INSERT_NAMEREF_PREFIX,
                                        first_byte_flags,
                                        output,
                                        output_size);
  if (encoded < 0)
    return -1;
  pos = (size_t)encoded;

  /* Encode value as string literal with 7-bit prefix */
  encoded = SocketQPACK_string_encode ((const char *)instr->value,
                                       instr->value_len,
                                       instr->use_huffman,
                                       output + pos,
                                       output_size - pos);
  if (encoded < 0)
    return -1;
  pos += (size_t)encoded;

  return (ssize_t)pos;
}

SocketQPACK_Result
SocketQPACK_decode_insert_nameref (const unsigned char *input,
                                   size_t input_len,
                                   SocketQPACK_DynamicTable_T table,
                                   size_t *consumed,
                                   Arena_T arena)
{
  size_t pos = 0;
  uint64_t name_index;
  size_t int_consumed;
  int is_static;
  SocketQPACK_Result result;
  SocketQPACK_Header name_hdr;
  char *value;
  size_t value_len;
  size_t str_consumed;

  if (input == NULL || table == NULL || consumed == NULL || arena == NULL)
    return QPACK_ERROR;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  /* Verify this is an Insert with Name Reference instruction */
  if ((input[0] & QPACK_INSTR_INSERT_NAMEREF_MASK)
      != QPACK_INSTR_INSERT_NAMEREF_MASK)
    {
      SOCKET_LOG_WARN_MSG (
          "QPACK: not an Insert with Name Reference instruction (byte=0x%02x)",
          input[0]);
      return QPACK_ERROR_ENCODER_STREAM;
    }

  /* Extract T bit */
  is_static = (input[0] & 0x40) != 0;

  /* Decode name index (6-bit prefix) */
  result = SocketQPACK_int_decode (input,
                                   input_len,
                                   QPACK_INSTR_INSERT_NAMEREF_PREFIX,
                                   &name_index,
                                   &int_consumed);
  if (result != QPACK_OK)
    return result;
  pos = int_consumed;

  /* Validate name index */
  result = SocketQPACK_validate_nameref_index (
      is_static, (size_t)name_index, table);
  if (result != QPACK_OK)
    return QPACK_ERROR_ENCODER_STREAM;

  /* Look up name from appropriate table */
  if (is_static)
    {
      result = SocketQPACK_static_get ((size_t)name_index, &name_hdr);
    }
  else
    {
      /* Convert relative index to absolute index for dynamic table lookup */
      /* In encoder instructions, dynamic index is relative to insertion_count:
       * absolute_index = insertion_count - 1 - relative_index */
      uint64_t absolute_index = table->insertion_count - 1 - (size_t)name_index;
      result = SocketQPACK_DynamicTable_get (table, absolute_index, &name_hdr);
    }
  if (result != QPACK_OK)
    return result;

  /* Decode value string */
  result = SocketQPACK_string_decode (
      input + pos, input_len - pos, &value, &value_len, &str_consumed, arena);
  if (result != QPACK_OK)
    return result;
  pos += str_consumed;

  /* Insert into dynamic table */
  result = SocketQPACK_DynamicTable_insert (
      table, name_hdr.name, name_hdr.name_len, value, value_len);
  if (result != QPACK_OK)
    return result;

  *consumed = pos;
  return QPACK_OK;
}

#undef T
