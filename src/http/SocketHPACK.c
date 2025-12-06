/**
 * SocketHPACK.c - HPACK Header Compression Implementation
 *
 * Part of the Socket Library
 *
 * Implements RFC 7541 HPACK:
 * - Integer encoding/decoding (Section 5.1)
 * - String literal encoding/decoding (Section 5.2)
 * - Indexed header field (Section 6.1)
 * - Literal header field (Section 6.2)
 * - Dynamic table size update (Section 6.3)
 * - Encoder and decoder state machines
 */

#include "http/SocketHPACK-private.h"
#include "http/SocketHPACK.h"
#include "core/SocketUtil.h"

#include <assert.h>
#include <string.h>

/* ============================================================================
 * Constants - RFC 7541 Field Type Bit Patterns
 * ============================================================================ */

/* Field type identification masks (RFC 7541 Section 6) */
#define HPACK_INDEXED_MASK         0x80  /* 1xxxxxxx - Indexed Header Field */
#define HPACK_LITERAL_INDEXED_MASK 0xC0  /* 01xxxxxx - Literal with Indexing */
#define HPACK_LITERAL_INDEXED_VAL  0x40
#define HPACK_LITERAL_NO_INDEX_MASK 0xF0 /* 0000xxxx - Literal without Indexing */
#define HPACK_LITERAL_NEVER_MASK   0xF0  /* 0001xxxx - Literal Never Indexed */
#define HPACK_LITERAL_NEVER_VAL    0x10
#define HPACK_TABLE_UPDATE_MASK    0xE0  /* 001xxxxx - Table Size Update */
#define HPACK_TABLE_UPDATE_VAL     0x20

/* Prefix bits for integer encoding (RFC 7541 Section 5.1) */
#define HPACK_PREFIX_INDEXED       7     /* For indexed header field */
#define HPACK_PREFIX_LITERAL_INDEX 6     /* For literal with indexing */
#define HPACK_PREFIX_LITERAL_OTHER 4     /* For literal without/never indexed */
#define HPACK_PREFIX_TABLE_UPDATE  5     /* For table size update */
#define HPACK_PREFIX_STRING        7     /* For string literal length */

/* Buffer sizes */
#define HPACK_INT_BUF_SIZE         16    /* Buffer for integer encoding */
#define HPACK_HUFFMAN_RATIO        2     /* Estimated decode expansion ratio */

/* Literal encoding mode flags */
#define HPACK_LITERAL_WITH_INDEXING 0x40
#define HPACK_LITERAL_WITHOUT_INDEX 0x00
#define HPACK_LITERAL_NEVER_INDEX   0x10

/* ============================================================================
 * Exception Definition
 * ============================================================================ */

const Except_T SocketHPACK_Error
    = { &SocketHPACK_Error, "HPACK compression error" };

/* Thread-local exception for detailed error messages */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketHPACK);

#define RAISE_HPACK_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketHPACK, e)

/* ============================================================================
 * Result Strings
 * ============================================================================ */

static const char *result_strings[] = {
  [HPACK_OK] = "OK",
  [HPACK_INCOMPLETE] = "Incomplete - need more data",
  [HPACK_ERROR] = "Generic error",
  [HPACK_ERROR_INVALID_INDEX] = "Invalid table index",
  [HPACK_ERROR_HUFFMAN] = "Huffman decoding error",
  [HPACK_ERROR_INTEGER] = "Integer overflow",
  [HPACK_ERROR_TABLE_SIZE] = "Invalid dynamic table size update",
  [HPACK_ERROR_HEADER_SIZE] = "Header too large",
  [HPACK_ERROR_LIST_SIZE] = "Header list too large",
  [HPACK_ERROR_BOMB] = "HPACK bomb detected",
};

const char *
SocketHPACK_result_string (SocketHPACK_Result result)
{
  if (result < 0 || result > HPACK_ERROR_BOMB)
    return "Unknown error";
  return result_strings[result];
}

/* ============================================================================
 * Integer Coding (RFC 7541 Section 5.1)
 * ============================================================================ */

size_t
SocketHPACK_int_encode (uint64_t value, int prefix_bits, unsigned char *output,
                        size_t output_size)
{
  size_t pos = 0;
  uint64_t max_prefix;

  if (output == NULL || output_size == 0)
    return 0;

  if (prefix_bits < 1 || prefix_bits > 8)
    return 0;

  max_prefix = ((uint64_t)1 << prefix_bits) - 1;

  if (value < max_prefix)
    {
      output[pos++] = (unsigned char)value;
      return pos;
    }

  /* Value requires continuation bytes */
  output[pos++] = (unsigned char)max_prefix;
  value -= max_prefix;

  while (value >= 128 && pos < output_size)
    {
      output[pos++] = (unsigned char)(0x80 | (value & 0x7F));
      value >>= 7;
    }

  if (pos < output_size)
    output[pos++] = (unsigned char)value;

  return pos;
}

SocketHPACK_Result
SocketHPACK_int_decode (const unsigned char *input, size_t input_len,
                        int prefix_bits, uint64_t *value, size_t *consumed)
{
  size_t pos = 0;
  uint64_t max_prefix;
  uint64_t result;
  uint64_t byte_val;
  unsigned int shift;

  if (input == NULL || value == NULL || consumed == NULL)
    return HPACK_ERROR;

  if (input_len == 0)
    return HPACK_INCOMPLETE;

  if (prefix_bits < 1 || prefix_bits > 8)
    return HPACK_ERROR;

  max_prefix = ((uint64_t)1 << prefix_bits) - 1;
  result = input[pos++] & max_prefix;

  if (result < max_prefix)
    {
      *value = result;
      *consumed = pos;
      return HPACK_OK;
    }

  /* Value requires continuation bytes */
  shift = 0;
  do
    {
      if (pos >= input_len)
        return HPACK_INCOMPLETE;

      byte_val = input[pos++];

      if (shift >= 63)
        return HPACK_ERROR_INTEGER;

      uint64_t add_val = (byte_val & 0x7F) << shift;
      if (result > UINT64_MAX - add_val)
        return HPACK_ERROR_INTEGER;

      result += add_val;
      shift += 7;
    }
  while (byte_val & 0x80);

  *value = result;
  *consumed = pos;
  return HPACK_OK;
}

/* ============================================================================
 * String Literal Encoding/Decoding (RFC 7541 Section 5.2)
 * ============================================================================ */

/**
 * hpack_encode_int_with_flag - Encode integer with flag byte prefix
 * @value: Integer value to encode
 * @prefix_bits: Number of bits in prefix
 * @flag: Flag byte to OR with first byte
 * @output: Output buffer
 * @output_size: Output buffer size
 *
 * Returns: Bytes written, or -1 on error
 */
static ssize_t
hpack_encode_int_with_flag (uint64_t value, int prefix_bits, unsigned char flag,
                            unsigned char *output, size_t output_size)
{
  unsigned char int_buf[HPACK_INT_BUF_SIZE];
  size_t int_len;
  size_t pos = 0;

  int_len = SocketHPACK_int_encode (value, prefix_bits, int_buf,
                                    sizeof (int_buf));
  if (int_len == 0 || pos + int_len > output_size)
    return -1;

  output[pos++] = flag | int_buf[0];
  for (size_t i = 1; i < int_len; i++)
    output[pos++] = int_buf[i];

  return (ssize_t)pos;
}

/**
 * hpack_encode_string - Encode a string literal (with optional Huffman)
 */
static ssize_t
hpack_encode_string (const char *str, size_t len, int use_huffman,
                     unsigned char *output, size_t output_size)
{
  size_t pos = 0;
  ssize_t encoded;

  if (use_huffman)
    {
      size_t huffman_size
          = SocketHPACK_huffman_encoded_size ((const unsigned char *)str, len);

      if (huffman_size < len)
        {
          /* Use Huffman encoding */
          encoded = hpack_encode_int_with_flag (huffman_size,
                                                HPACK_PREFIX_STRING,
                                                0x80, output, output_size);
          if (encoded < 0)
            return -1;
          pos = (size_t)encoded;

          encoded = SocketHPACK_huffman_encode (
              (const unsigned char *)str, len, output + pos, output_size - pos);
          if (encoded < 0)
            return -1;
          pos += (size_t)encoded;

          return (ssize_t)pos;
        }
    }

  /* Use literal encoding */
  encoded = hpack_encode_int_with_flag (len, HPACK_PREFIX_STRING,
                                        0x00, output, output_size);
  if (encoded < 0 || pos + (size_t)encoded + len > output_size)
    return -1;
  pos = (size_t)encoded;

  memcpy (output + pos, str, len);
  pos += len;

  return (ssize_t)pos;
}

/**
 * hpack_decode_string - Decode a string literal
 */
static SocketHPACK_Result
hpack_decode_string (const unsigned char *input, size_t input_len,
                     char **str_out, size_t *str_len_out, size_t *consumed,
                     Arena_T arena)
{
  size_t pos = 0;
  int huffman;
  uint64_t str_len;
  size_t int_consumed;
  SocketHPACK_Result result;
  char *str;

  if (input_len == 0)
    return HPACK_INCOMPLETE;

  huffman = (input[0] & 0x80) != 0;

  result = SocketHPACK_int_decode (input, input_len, HPACK_PREFIX_STRING,
                                   &str_len, &int_consumed);
  if (result != HPACK_OK)
    return result;

  pos = int_consumed;

  if (pos + str_len > input_len)
    return HPACK_INCOMPLETE;

  if (huffman)
    {
      size_t max_decoded = str_len * HPACK_HUFFMAN_RATIO;
      str = ALLOC (arena, max_decoded + 1);
      if (str == NULL)
        return HPACK_ERROR;

      ssize_t decoded = SocketHPACK_huffman_decode (
          input + pos, str_len, (unsigned char *)str, max_decoded);
      if (decoded < 0)
        return HPACK_ERROR_HUFFMAN;

      str[decoded] = '\0';
      *str_len_out = (size_t)decoded;
    }
  else
    {
      str = ALLOC (arena, str_len + 1);
      if (str == NULL)
        return HPACK_ERROR;

      memcpy (str, input + pos, str_len);
      str[str_len] = '\0';
      *str_len_out = str_len;
    }

  *str_out = str;
  *consumed = pos + str_len;
  return HPACK_OK;
}

/* ============================================================================
 * Encoder Configuration
 * ============================================================================ */

void
SocketHPACK_encoder_config_defaults (SocketHPACK_EncoderConfig *config)
{
  if (config == NULL)
    return;

  config->max_table_size = SOCKETHPACK_DEFAULT_TABLE_SIZE;
  config->huffman_encode = 1;
  config->use_indexing = 1;
}

/* ============================================================================
 * Encoder Implementation
 * ============================================================================ */

SocketHPACK_Encoder_T
SocketHPACK_Encoder_new (const SocketHPACK_EncoderConfig *config, Arena_T arena)
{
  SocketHPACK_Encoder_T encoder;
  SocketHPACK_EncoderConfig default_config;

  assert (arena != NULL);

  if (config == NULL)
    {
      SocketHPACK_encoder_config_defaults (&default_config);
      config = &default_config;
    }

  encoder = ALLOC (arena, sizeof (*encoder));
  if (encoder == NULL)
    SOCKET_RAISE_MSG (SocketHPACK, SocketHPACK_Error,
                      "Failed to allocate HPACK encoder");

  encoder->table = SocketHPACK_Table_new (config->max_table_size, arena);
  if (encoder->table == NULL)
    SOCKET_RAISE_MSG (SocketHPACK, SocketHPACK_Error,
                      "Failed to allocate HPACK encoder dynamic table");

  encoder->pending_table_size = 0;
  encoder->pending_table_size_update = 0;
  encoder->huffman_encode = config->huffman_encode;
  encoder->use_indexing = config->use_indexing;
  encoder->arena = arena;

  return encoder;
}

void
SocketHPACK_Encoder_free (SocketHPACK_Encoder_T *encoder)
{
  if (encoder == NULL || *encoder == NULL)
    return;

  SocketHPACK_Table_free (&(*encoder)->table);
  *encoder = NULL;
}

void
SocketHPACK_Encoder_set_table_size (SocketHPACK_Encoder_T encoder,
                                    size_t max_size)
{
  assert (encoder != NULL);
  encoder->pending_table_size = max_size;
  encoder->pending_table_size_update = 1;
}

SocketHPACK_Table_T
SocketHPACK_Encoder_get_table (SocketHPACK_Encoder_T encoder)
{
  assert (encoder != NULL);
  return encoder->table;
}

/**
 * hpack_encode_indexed - Encode indexed header field (RFC 7541 Section 6.1)
 */
static ssize_t
hpack_encode_indexed (size_t index, unsigned char *output, size_t output_size)
{
  return hpack_encode_int_with_flag (index, HPACK_PREFIX_INDEXED,
                                     HPACK_INDEXED_MASK, output, output_size);
}

/**
 * hpack_encode_literal - Encode literal header field (RFC 7541 Section 6.2)
 * @mode: HPACK_LITERAL_WITH_INDEXING, HPACK_LITERAL_WITHOUT_INDEX, or
 *        HPACK_LITERAL_NEVER_INDEX
 *
 * Consolidated function for all three literal encoding modes.
 */
static ssize_t
hpack_encode_literal (unsigned char mode, size_t name_index, const char *name,
                      size_t name_len, const char *value, size_t value_len,
                      int use_huffman, unsigned char *output,
                      size_t output_size)
{
  size_t pos = 0;
  int prefix_bits;
  ssize_t encoded;

  /* Determine prefix bits based on mode */
  prefix_bits = (mode == HPACK_LITERAL_WITH_INDEXING)
                    ? HPACK_PREFIX_LITERAL_INDEX
                    : HPACK_PREFIX_LITERAL_OTHER;

  if (name_index > 0)
    {
      /* Name is in table */
      encoded = hpack_encode_int_with_flag (name_index, prefix_bits, mode,
                                            output, output_size);
      if (encoded < 0)
        return -1;
      pos = (size_t)encoded;
    }
  else
    {
      /* New name */
      if (pos >= output_size)
        return -1;
      output[pos++] = mode;

      encoded = hpack_encode_string (name, name_len, use_huffman,
                                     output + pos, output_size - pos);
      if (encoded < 0)
        return -1;
      pos += (size_t)encoded;
    }

  /* Encode value */
  encoded = hpack_encode_string (value, value_len, use_huffman,
                                 output + pos, output_size - pos);
  if (encoded < 0)
    return -1;
  pos += (size_t)encoded;

  return (ssize_t)pos;
}

/**
 * hpack_encode_table_size_update - Encode dynamic table size update
 */
static ssize_t
hpack_encode_table_size_update (size_t max_size, unsigned char *output,
                                size_t output_size)
{
  return hpack_encode_int_with_flag (max_size, HPACK_PREFIX_TABLE_UPDATE,
                                     HPACK_TABLE_UPDATE_VAL, output,
                                     output_size);
}

/* External declaration for table find function */
extern int SocketHPACK_Table_find (SocketHPACK_Table_T table, const char *name,
                                   size_t name_len, const char *value,
                                   size_t value_len);

/**
 * hpack_encode_header - Encode a single header
 *
 * Returns: Bytes written, or -1 on error
 */
static ssize_t
hpack_encode_header (SocketHPACK_Encoder_T encoder,
                     const SocketHPACK_Header *hdr, unsigned char *output,
                     size_t output_size)
{
  int static_idx, dynamic_idx;
  size_t name_index = 0;

  /* Check static table for exact match */
  static_idx = SocketHPACK_static_find (hdr->name, hdr->name_len, hdr->value,
                                        hdr->value_len);
  if (static_idx > 0)
    return hpack_encode_indexed ((size_t)static_idx, output, output_size);

  /* Check dynamic table for exact match */
  dynamic_idx = SocketHPACK_Table_find (encoder->table, hdr->name,
                                        hdr->name_len, hdr->value,
                                        hdr->value_len);
  if (dynamic_idx > 0)
    {
      size_t index = SOCKETHPACK_STATIC_TABLE_SIZE + (size_t)dynamic_idx;
      return hpack_encode_indexed (index, output, output_size);
    }

  /* No exact match - determine name index for literal encoding */
  if (static_idx < 0)
    name_index = (size_t)(-static_idx);
  else if (dynamic_idx < 0)
    name_index = SOCKETHPACK_STATIC_TABLE_SIZE + (size_t)(-dynamic_idx);

  /* Encode based on indexing mode */
  if (hdr->never_index)
    {
      return hpack_encode_literal (HPACK_LITERAL_NEVER_INDEX, name_index,
                                   hdr->name, hdr->name_len, hdr->value,
                                   hdr->value_len, encoder->huffman_encode,
                                   output, output_size);
    }

  if (encoder->use_indexing)
    {
      ssize_t encoded = hpack_encode_literal (
          HPACK_LITERAL_WITH_INDEXING, name_index, hdr->name, hdr->name_len,
          hdr->value, hdr->value_len, encoder->huffman_encode, output,
          output_size);

      if (encoded >= 0)
        {
          SocketHPACK_Table_add (encoder->table, hdr->name, hdr->name_len,
                                 hdr->value, hdr->value_len);
        }
      return encoded;
    }

  return hpack_encode_literal (HPACK_LITERAL_WITHOUT_INDEX, name_index,
                               hdr->name, hdr->name_len, hdr->value,
                               hdr->value_len, encoder->huffman_encode, output,
                               output_size);
}

ssize_t
SocketHPACK_Encoder_encode (SocketHPACK_Encoder_T encoder,
                            const SocketHPACK_Header *headers, size_t count,
                            unsigned char *output, size_t output_size)
{
  size_t pos = 0;
  ssize_t encoded;

  assert (encoder != NULL);

  if (headers == NULL && count > 0)
    return -1;
  if (output == NULL && output_size > 0)
    return -1;

  /* Emit pending table size update */
  if (encoder->pending_table_size_update)
    {
      encoded = hpack_encode_table_size_update (encoder->pending_table_size,
                                                output + pos,
                                                output_size - pos);
      if (encoded < 0)
        return -1;
      pos += (size_t)encoded;

      SocketHPACK_Table_set_max_size (encoder->table,
                                      encoder->pending_table_size);
      encoder->pending_table_size_update = 0;
    }

  /* Encode each header */
  for (size_t i = 0; i < count; i++)
    {
      encoded = hpack_encode_header (encoder, &headers[i], output + pos,
                                     output_size - pos);
      if (encoded < 0)
        return -1;
      pos += (size_t)encoded;
    }

  return (ssize_t)pos;
}

/* ============================================================================
 * Decoder Configuration
 * ============================================================================ */

void
SocketHPACK_decoder_config_defaults (SocketHPACK_DecoderConfig *config)
{
  if (config == NULL)
    return;

  config->max_table_size = SOCKETHPACK_DEFAULT_TABLE_SIZE;
  config->max_header_size = SOCKETHPACK_MAX_HEADER_SIZE;
  config->max_header_list_size = SOCKETHPACK_MAX_HEADER_LIST_SIZE;
}

/* ============================================================================
 * Decoder Implementation
 * ============================================================================ */

SocketHPACK_Decoder_T
SocketHPACK_Decoder_new (const SocketHPACK_DecoderConfig *config, Arena_T arena)
{
  SocketHPACK_Decoder_T decoder;
  SocketHPACK_DecoderConfig default_config;

  assert (arena != NULL);

  if (config == NULL)
    {
      SocketHPACK_decoder_config_defaults (&default_config);
      config = &default_config;
    }

  decoder = ALLOC (arena, sizeof (*decoder));
  if (decoder == NULL)
    SOCKET_RAISE_MSG (SocketHPACK, SocketHPACK_Error,
                      "Failed to allocate HPACK decoder");

  decoder->table = SocketHPACK_Table_new (config->max_table_size, arena);
  if (decoder->table == NULL)
    SOCKET_RAISE_MSG (SocketHPACK, SocketHPACK_Error,
                      "Failed to allocate HPACK decoder dynamic table");

  decoder->max_header_size = config->max_header_size;
  decoder->max_header_list_size = config->max_header_list_size;
  decoder->settings_max_table_size = config->max_table_size;
  decoder->arena = arena;

  return decoder;
}

void
SocketHPACK_Decoder_free (SocketHPACK_Decoder_T *decoder)
{
  if (decoder == NULL || *decoder == NULL)
    return;

  SocketHPACK_Table_free (&(*decoder)->table);
  *decoder = NULL;
}

void
SocketHPACK_Decoder_set_table_size (SocketHPACK_Decoder_T decoder,
                                    size_t max_size)
{
  assert (decoder != NULL);
  decoder->settings_max_table_size = max_size;
}

SocketHPACK_Table_T
SocketHPACK_Decoder_get_table (SocketHPACK_Decoder_T decoder)
{
  assert (decoder != NULL);
  return decoder->table;
}

/**
 * hpack_get_indexed - Get header from combined static + dynamic table index
 */
static SocketHPACK_Result
hpack_get_indexed (SocketHPACK_Decoder_T decoder, size_t index,
                   SocketHPACK_Header *header)
{
  if (index == 0)
    return HPACK_ERROR_INVALID_INDEX;

  if (index <= SOCKETHPACK_STATIC_TABLE_SIZE)
    return SocketHPACK_static_get (index, header);

  size_t dyn_index = index - SOCKETHPACK_STATIC_TABLE_SIZE;
  return SocketHPACK_Table_get (decoder->table, dyn_index, header);
}

/**
 * hpack_copy_indexed_name - Copy name from indexed header
 *
 * Returns: HPACK_OK on success, error code on failure
 */
static SocketHPACK_Result
hpack_copy_indexed_name (SocketHPACK_Decoder_T decoder, size_t index,
                         SocketHPACK_Header *header, Arena_T arena)
{
  SocketHPACK_Header name_hdr;
  SocketHPACK_Result result;
  char *name_copy;

  result = hpack_get_indexed (decoder, index, &name_hdr);
  if (result != HPACK_OK)
    return result;

  name_copy = ALLOC (arena, name_hdr.name_len + 1);
  if (name_copy == NULL)
    return HPACK_ERROR;

  memcpy (name_copy, name_hdr.name, name_hdr.name_len);
  name_copy[name_hdr.name_len] = '\0';

  header->name = name_copy;
  header->name_len = name_hdr.name_len;
  return HPACK_OK;
}

/**
 * hpack_decode_literal - Decode literal header field (all modes)
 * @add_to_table: Whether to add decoded header to dynamic table
 * @never_indexed: Whether to mark header as never indexed
 *
 * Returns: HPACK_OK on success, error code on failure
 */
static SocketHPACK_Result
hpack_decode_literal (SocketHPACK_Decoder_T decoder, const unsigned char *input,
                      size_t input_len, int prefix_bits, size_t *pos,
                      SocketHPACK_Header *header, int add_to_table,
                      int never_indexed, Arena_T arena)
{
  uint64_t index;
  size_t consumed;
  SocketHPACK_Result result;
  char *name;
  size_t name_len;
  char *value;
  size_t value_len;

  /* Decode name index */
  result = SocketHPACK_int_decode (input + *pos, input_len - *pos, prefix_bits,
                                   &index, &consumed);
  if (result != HPACK_OK)
    return result;
  *pos += consumed;

  if (index > 0)
    {
      /* Name is indexed */
      result = hpack_copy_indexed_name (decoder, (size_t)index, header, arena);
      if (result != HPACK_OK)
        return result;
    }
  else
    {
      /* New name */
      result = hpack_decode_string (input + *pos, input_len - *pos, &name,
                                    &name_len, &consumed, arena);
      if (result != HPACK_OK)
        return result;
      *pos += consumed;

      header->name = name;
      header->name_len = name_len;
    }

  /* Decode value */
  result = hpack_decode_string (input + *pos, input_len - *pos, &value,
                                &value_len, &consumed, arena);
  if (result != HPACK_OK)
    return result;
  *pos += consumed;

  header->value = value;
  header->value_len = value_len;
  header->never_index = never_indexed;

  /* Add to dynamic table if requested */
  if (add_to_table)
    {
      SocketHPACK_Table_add (decoder->table, header->name, header->name_len,
                             header->value, header->value_len);
    }

  return HPACK_OK;
}

/**
 * hpack_decode_indexed_field - Decode indexed header field (Section 6.1)
 */
static SocketHPACK_Result
hpack_decode_indexed_field (SocketHPACK_Decoder_T decoder,
                            const unsigned char *input, size_t input_len,
                            size_t *pos, SocketHPACK_Header *header)
{
  uint64_t index;
  size_t consumed;
  SocketHPACK_Result result;

  result = SocketHPACK_int_decode (input + *pos, input_len - *pos,
                                   HPACK_PREFIX_INDEXED, &index, &consumed);
  if (result != HPACK_OK)
    return result;
  *pos += consumed;

  return hpack_get_indexed (decoder, (size_t)index, header);
}

/**
 * hpack_decode_table_update - Decode dynamic table size update (Section 6.3)
 */
static SocketHPACK_Result
hpack_decode_table_update (SocketHPACK_Decoder_T decoder,
                           const unsigned char *input, size_t input_len,
                           size_t *pos)
{
  uint64_t new_size;
  size_t consumed;
  SocketHPACK_Result result;

  result = SocketHPACK_int_decode (input + *pos, input_len - *pos,
                                   HPACK_PREFIX_TABLE_UPDATE, &new_size,
                                   &consumed);
  if (result != HPACK_OK)
    return result;
  *pos += consumed;

  if (new_size > decoder->settings_max_table_size)
    return HPACK_ERROR_TABLE_SIZE;

  SocketHPACK_Table_set_max_size (decoder->table, (size_t)new_size);
  return HPACK_OK;
}

SocketHPACK_Result
SocketHPACK_Decoder_decode (SocketHPACK_Decoder_T decoder,
                            const unsigned char *input, size_t input_len,
                            SocketHPACK_Header *headers, size_t max_headers,
                            size_t *header_count, Arena_T arena)
{
  size_t pos = 0;
  size_t hdr_count = 0;
  size_t total_size = 0;
  int table_update_allowed = 1;
  SocketHPACK_Result result;

  assert (decoder != NULL);
  assert (arena != NULL);

  if (input == NULL && input_len > 0)
    return HPACK_ERROR;
  if (headers == NULL && max_headers > 0)
    return HPACK_ERROR;
  if (header_count == NULL)
    return HPACK_ERROR;

  *header_count = 0;

  while (pos < input_len)
    {
      unsigned char byte = input[pos];
      SocketHPACK_Header header = { 0 };

      if (byte & HPACK_INDEXED_MASK)
        {
          /* Indexed Header Field (Section 6.1): 1xxxxxxx */
          table_update_allowed = 0;
          result = hpack_decode_indexed_field (decoder, input, input_len, &pos,
                                               &header);
          if (result != HPACK_OK)
            return result;
        }
      else if ((byte & HPACK_LITERAL_INDEXED_MASK) == HPACK_LITERAL_INDEXED_VAL)
        {
          /* Literal with Incremental Indexing (Section 6.2.1): 01xxxxxx */
          table_update_allowed = 0;
          result = hpack_decode_literal (decoder, input, input_len,
                                         HPACK_PREFIX_LITERAL_INDEX, &pos,
                                         &header, 1, 0, arena);
          if (result != HPACK_OK)
            return result;
        }
      else if ((byte & HPACK_LITERAL_NO_INDEX_MASK) == 0x00)
        {
          /* Literal without Indexing (Section 6.2.2): 0000xxxx */
          table_update_allowed = 0;
          result = hpack_decode_literal (decoder, input, input_len,
                                         HPACK_PREFIX_LITERAL_OTHER, &pos,
                                         &header, 0, 0, arena);
          if (result != HPACK_OK)
            return result;
        }
      else if ((byte & HPACK_LITERAL_NEVER_MASK) == HPACK_LITERAL_NEVER_VAL)
        {
          /* Literal Never Indexed (Section 6.2.3): 0001xxxx */
          table_update_allowed = 0;
          result = hpack_decode_literal (decoder, input, input_len,
                                         HPACK_PREFIX_LITERAL_OTHER, &pos,
                                         &header, 0, 1, arena);
          if (result != HPACK_OK)
            return result;
        }
      else if ((byte & HPACK_TABLE_UPDATE_MASK) == HPACK_TABLE_UPDATE_VAL)
        {
          /* Dynamic Table Size Update (Section 6.3): 001xxxxx */
          if (!table_update_allowed)
            return HPACK_ERROR_TABLE_SIZE;

          result = hpack_decode_table_update (decoder, input, input_len, &pos);
          if (result != HPACK_OK)
            return result;
          continue; /* Not a header, continue to next */
        }
      else
        {
          return HPACK_ERROR; /* Invalid encoding */
        }

      /* Validate header size */
      size_t header_size
          = hpack_entry_size (header.name_len, header.value_len);
      if (header_size > decoder->max_header_size)
        return HPACK_ERROR_HEADER_SIZE;

      total_size += header_size;
      if (total_size > decoder->max_header_list_size)
        return HPACK_ERROR_LIST_SIZE;

      /* Store header */
      if (hdr_count < max_headers)
        headers[hdr_count] = header;
      hdr_count++;
    }

  *header_count = hdr_count;
  return HPACK_OK;
}
