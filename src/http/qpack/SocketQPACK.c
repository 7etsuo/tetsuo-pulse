/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK.c - QPACK Header Compression (RFC 9204)
 *
 * Integer/string encoding, dynamic table management, and literal field line
 * encoding/decoding including post-base name references (Section 4.5.5).
 */

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "http/SocketQPACK-private.h"
#include "http/SocketQPACK.h"

#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"

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
  [QPACK_ERROR_HUFFMAN] = "Huffman decoding error",
  [QPACK_ERROR_INTEGER] = "Integer overflow",
  [QPACK_ERROR_TABLE_SIZE] = "Invalid dynamic table size update",
  [QPACK_ERROR_HEADER_SIZE] = "Header too large",
  [QPACK_ERROR_LIST_SIZE] = "Header list too large",
  [QPACK_ERROR_BOMB] = "QPACK bomb detected",
  [QPACK_ERROR_POSTBASE_INDEX] = "Post-base index >= insert_count",
};

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  if (result < 0 || result > QPACK_ERROR_POSTBASE_INDEX)
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
 * Integer Coding (RFC 9204 Section 4.1.1 - same as RFC 7541 Section 5.1)
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
 * String Literal Encoding/Decoding (RFC 9204 Section 4.1.2)
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

static ssize_t
qpack_encode_string (const char *str,
                     size_t len,
                     int use_huffman,
                     unsigned char *output,
                     size_t output_size)
{
  size_t pos = 0;
  ssize_t encoded;
  size_t data_len = len;
  unsigned char flag = QPACK_STRING_LITERAL_FLAG;
  int use_huffman_actual = 0;

  if (use_huffman)
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

  encoded = qpack_encode_int_with_flag (
      data_len, QPACK_PREFIX_STRING, flag, output, output_size);
  if (encoded < 0)
    return -1;
  pos = (size_t)encoded;

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

static SocketQPACK_Result
qpack_decode_string (const unsigned char *input,
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

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  huffman = (input[0] & QPACK_STRING_HUFFMAN_FLAG) != 0;
  result = SocketQPACK_int_decode (
      input, input_len, QPACK_PREFIX_STRING, &str_len, &pos);
  if (result != QPACK_OK)
    return result;

  if (str_len > SIZE_MAX || pos + str_len > input_len)
    return (str_len > SIZE_MAX) ? QPACK_ERROR_INTEGER : QPACK_INCOMPLETE;

  size_t len = (size_t)str_len;
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
 * Post-Base Index Conversion (RFC 9204 Section 4.5.5)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_postbase_to_absolute (uint32_t base,
                                  uint32_t post_base_index,
                                  uint32_t *abs_index)
{
  uint64_t result;

  if (abs_index == NULL)
    return QPACK_ERROR;

  /* Absolute index = base + post_base_index */
  result = (uint64_t)base + (uint64_t)post_base_index;

  /* Check for overflow */
  if (result > UINT32_MAX)
    return QPACK_ERROR_INTEGER;

  *abs_index = (uint32_t)result;
  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_validate_postbase_index (uint32_t abs_index, uint32_t insert_count)
{
  /*
   * RFC 9204 Section 4.5.5:
   * Post-base indices reference entries that have been added to the dynamic
   * table AFTER the base. The absolute index must be < insert_count.
   * (indices are 0-based, so valid range is [0, insert_count-1])
   */
  if (abs_index >= insert_count)
    return QPACK_ERROR_POSTBASE_INDEX;

  return QPACK_OK;
}

/* ============================================================================
 * Literal Field Line with Post-Base Name Reference (RFC 9204 Section 4.5.5)
 * ============================================================================
 */

ssize_t
SocketQPACK_encode_literal_postbase_name (uint32_t post_base_index,
                                          int never_index,
                                          const char *value,
                                          size_t value_len,
                                          int use_huffman,
                                          unsigned char *output,
                                          size_t output_size)
{
  size_t pos = 0;
  ssize_t encoded;
  unsigned char pattern_byte;

  if (output == NULL || output_size == 0)
    return -1;

  if (value == NULL && value_len > 0)
    return -1;

  /*
   * Wire format: 0000 N xxx
   * - 0000: Pattern identifier (bits 7-4)
   * - N: Never index flag (bit 3)
   * - xxx: 3-bit prefix for post-base index (bits 2-0)
   */
  pattern_byte = QPACK_LITERAL_POSTBASE_PATTERN;
  if (never_index)
    pattern_byte |= QPACK_LITERAL_POSTBASE_N_BIT;

  /* Encode post-base index with 3-bit prefix */
  encoded = qpack_encode_int_with_flag (post_base_index,
                                        QPACK_LITERAL_POSTBASE_PREFIX_BITS,
                                        pattern_byte,
                                        output,
                                        output_size);
  if (encoded < 0)
    return -1;
  pos = (size_t)encoded;

  /* Encode value as string literal */
  encoded = qpack_encode_string (
      value, value_len, use_huffman, output + pos, output_size - pos);
  if (encoded < 0)
    return -1;
  pos += (size_t)encoded;

  return (ssize_t)pos;
}

SocketQPACK_Result
SocketQPACK_decode_literal_postbase_name (const unsigned char *input,
                                          size_t input_len,
                                          const SocketQPACK_FieldPrefix *prefix,
                                          SocketQPACK_Table_T table,
                                          SocketQPACK_Header *header,
                                          size_t *consumed,
                                          Arena_T arena)
{
  size_t pos = 0;
  uint64_t post_base_index;
  uint32_t abs_index;
  int never_index;
  SocketQPACK_Result result;
  SocketQPACK_Header name_header;
  char *value;
  size_t value_len;
  size_t bytes_consumed;

  if (input == NULL || prefix == NULL || table == NULL || header == NULL
      || consumed == NULL || arena == NULL)
    return QPACK_ERROR;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  /* Verify this is a post-base name reference pattern (0000 N xxx) */
  if ((input[0] & QPACK_LITERAL_POSTBASE_MASK)
      != QPACK_LITERAL_POSTBASE_PATTERN)
    return QPACK_ERROR;

  /* Extract N bit (never index flag) */
  never_index = (input[0] & QPACK_LITERAL_POSTBASE_N_BIT) != 0;

  /* Decode post-base index with 3-bit prefix */
  result = SocketQPACK_int_decode (input,
                                   input_len,
                                   QPACK_LITERAL_POSTBASE_PREFIX_BITS,
                                   &post_base_index,
                                   &bytes_consumed);
  if (result != QPACK_OK)
    return result;
  pos = bytes_consumed;

  /* Convert to absolute index: absolute = base + post_base_index */
  if (post_base_index > UINT32_MAX)
    return QPACK_ERROR_INTEGER;

  result = SocketQPACK_postbase_to_absolute (
      prefix->base, (uint32_t)post_base_index, &abs_index);
  if (result != QPACK_OK)
    return result;

  /* Validate: absolute index must be < insert_count */
  result = SocketQPACK_validate_postbase_index (
      abs_index, SocketQPACK_Table_insert_count (table));
  if (result != QPACK_OK)
    return result;

  /* Look up name from dynamic table */
  result = SocketQPACK_Table_get_absolute (table, abs_index, &name_header);
  if (result != QPACK_OK)
    return result;

  /* Copy name to arena (table contents may change) */
  char *name_copy;
  result = allocate_string_buffer (arena, name_header.name_len, &name_copy);
  if (result != QPACK_OK)
    return result;

  memcpy (name_copy, name_header.name, name_header.name_len);
  name_copy[name_header.name_len] = '\0';

  /* Decode value string */
  result = qpack_decode_string (
      input + pos, input_len - pos, &value, &value_len, &bytes_consumed, arena);
  if (result != QPACK_OK)
    return result;
  pos += bytes_consumed;

  /* Populate header output */
  header->name = name_copy;
  header->name_len = name_header.name_len;
  header->value = value;
  header->value_len = value_len;
  header->never_index = never_index;

  *consumed = pos;
  return QPACK_OK;
}

/* ============================================================================
 * Encoder Configuration
 * ============================================================================
 */

void
SocketQPACK_encoder_config_defaults (SocketQPACK_EncoderConfig *config)
{
  if (config == NULL)
    return;

  config->max_table_size = SOCKETQPACK_DEFAULT_TABLE_SIZE;
  config->huffman_encode = 1;
  config->use_indexing = 1;
}

/* ============================================================================
 * Encoder Implementation
 * ============================================================================
 */

SocketQPACK_Encoder_T
SocketQPACK_Encoder_new (const SocketQPACK_EncoderConfig *config, Arena_T arena)
{
  SocketQPACK_Encoder_T encoder;
  SocketQPACK_EncoderConfig default_config;

  assert (arena != NULL);

  if (config == NULL)
    {
      SocketQPACK_encoder_config_defaults (&default_config);
      config = &default_config;
    }

  encoder = ALLOC (arena, sizeof (*encoder));

  encoder->table = SocketQPACK_Table_new (config->max_table_size, arena);
  encoder->pending_table_sizes[0] = 0;
  encoder->pending_table_sizes[1] = 0;
  encoder->pending_table_size_count = 0;
  encoder->huffman_encode = config->huffman_encode;
  encoder->use_indexing = config->use_indexing;
  encoder->arena = arena;

  return encoder;
}

void
SocketQPACK_Encoder_free (SocketQPACK_Encoder_T *encoder)
{
  if (encoder == NULL || *encoder == NULL)
    return;

  SocketQPACK_Table_free (&(*encoder)->table);
  *encoder = NULL;
}

SocketQPACK_Table_T
SocketQPACK_Encoder_get_table (SocketQPACK_Encoder_T encoder)
{
  assert (encoder != NULL);
  return encoder->table;
}

/* ============================================================================
 * Decoder Configuration
 * ============================================================================
 */

void
SocketQPACK_decoder_config_defaults (SocketQPACK_DecoderConfig *config)
{
  if (config == NULL)
    return;

  config->max_table_size = SOCKETQPACK_DEFAULT_TABLE_SIZE;
  config->max_header_size = SOCKETQPACK_MAX_HEADER_SIZE;
  config->max_header_list_size = SOCKETQPACK_MAX_HEADER_LIST_SIZE;
  config->max_expansion_ratio = QPACK_DEFAULT_EXPANSION_RATIO;
  config->max_output_bytes
      = (SOCKETQPACK_MAX_HEADER_LIST_SIZE * QPACK_DEFAULT_EXPANSION_MULTIPLIER
         < QPACK_DEFAULT_MAX_OUTPUT_BYTES)
            ? SOCKETQPACK_MAX_HEADER_LIST_SIZE
                  * QPACK_DEFAULT_EXPANSION_MULTIPLIER
            : QPACK_DEFAULT_MAX_OUTPUT_BYTES;
}

/* ============================================================================
 * Decoder Implementation
 * ============================================================================
 */

SocketQPACK_Decoder_T
SocketQPACK_Decoder_new (const SocketQPACK_DecoderConfig *config, Arena_T arena)
{
  SocketQPACK_Decoder_T decoder;
  SocketQPACK_DecoderConfig default_config;

  assert (arena != NULL);

  if (config == NULL)
    {
      SocketQPACK_decoder_config_defaults (&default_config);
      config = &default_config;
    }

  decoder = ALLOC (arena, sizeof (*decoder));

  decoder->table = SocketQPACK_Table_new (config->max_table_size, arena);
  decoder->max_header_size = config->max_header_size;
  decoder->max_header_list_size = config->max_header_list_size;
  decoder->settings_max_table_size = config->max_table_size;
  decoder->max_expansion_ratio = config->max_expansion_ratio;
  decoder->max_output_bytes = config->max_output_bytes;
  decoder->decode_input_bytes = 0;
  decoder->decode_output_bytes = 0;
  decoder->arena = arena;

  return decoder;
}

void
SocketQPACK_Decoder_free (SocketQPACK_Decoder_T *decoder)
{
  if (decoder == NULL || *decoder == NULL)
    return;

  SocketQPACK_Table_free (&(*decoder)->table);
  *decoder = NULL;
}

SocketQPACK_Table_T
SocketQPACK_Decoder_get_table (SocketQPACK_Decoder_T decoder)
{
  assert (decoder != NULL);
  return decoder->table;
}
