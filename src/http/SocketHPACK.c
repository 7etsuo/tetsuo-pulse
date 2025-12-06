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

  /* Calculate maximum value that fits in prefix */
  max_prefix = ((uint64_t)1 << prefix_bits) - 1;

  if (value < max_prefix)
    {
      /* Value fits in prefix */
      output[pos++] = (unsigned char)value;
    }
  else
    {
      /* Value requires continuation bytes */
      output[pos++] = (unsigned char)max_prefix;
      value -= max_prefix;

      /* Encode remaining value in 7-bit chunks */
      while (value >= 128 && pos < output_size)
        {
          output[pos++] = (unsigned char)(0x80 | (value & 0x7F));
          value >>= 7;
        }

      if (pos < output_size)
        {
          output[pos++] = (unsigned char)value;
        }
    }

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

  /* Extract value from prefix bits */
  max_prefix = ((uint64_t)1 << prefix_bits) - 1;
  result = input[pos++] & max_prefix;

  if (result < max_prefix)
    {
      /* Value fit in prefix */
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

      /* Check for overflow before adding */
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
 * Encode a string literal (with optional Huffman encoding)
 */
static ssize_t
hpack_encode_string (const char *str, size_t len, int use_huffman,
                     unsigned char *output, size_t output_size)
{
  size_t pos = 0;
  size_t int_len;

  if (use_huffman)
    {
      /* Check if Huffman encoding is beneficial */
      size_t huffman_size
          = SocketHPACK_huffman_encoded_size ((const unsigned char *)str, len);

      if (huffman_size < len)
        {
          /* Use Huffman encoding */
          unsigned char len_buf[16];
          int_len = SocketHPACK_int_encode (huffman_size, 7, len_buf,
                                            sizeof (len_buf));

          if (pos + int_len > output_size)
            return -1;

          /* Set Huffman flag (H bit) */
          output[pos++] = 0x80 | len_buf[0];
          for (size_t i = 1; i < int_len; i++)
            {
              if (pos >= output_size)
                return -1;
              output[pos++] = len_buf[i];
            }

          /* Encode the string */
          ssize_t encoded = SocketHPACK_huffman_encode (
              (const unsigned char *)str, len, output + pos, output_size - pos);
          if (encoded < 0)
            return -1;
          pos += (size_t)encoded;

          return (ssize_t)pos;
        }
    }

  /* Use literal encoding */
  unsigned char len_buf[16];
  int_len = SocketHPACK_int_encode (len, 7, len_buf, sizeof (len_buf));

  if (pos + int_len + len > output_size)
    return -1;

  /* No Huffman flag */
  output[pos++] = len_buf[0] & 0x7F;
  for (size_t i = 1; i < int_len; i++)
    output[pos++] = len_buf[i];

  /* Copy string */
  memcpy (output + pos, str, len);
  pos += len;

  return (ssize_t)pos;
}

/**
 * Decode a string literal
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

  /* Check Huffman flag */
  huffman = (input[0] & 0x80) != 0;

  /* Decode length */
  result = SocketHPACK_int_decode (input, input_len, 7, &str_len, &int_consumed);
  if (result != HPACK_OK)
    return result;

  pos = int_consumed;

  if (pos + str_len > input_len)
    return HPACK_INCOMPLETE;

  /* Allocate output string */
  if (huffman)
    {
      /* Huffman-encoded: decoded size may be larger */
      size_t max_decoded = str_len * 2; /* Estimate */
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
      /* Literal encoding */
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
    {
      SOCKET_ERROR_MSG ("Failed to allocate HPACK encoder");
      RAISE_HPACK_ERROR (SocketHPACK_Error);
    }

  encoder->table = SocketHPACK_Table_new (config->max_table_size, arena);
  if (encoder->table == NULL)
    {
      SOCKET_ERROR_MSG ("Failed to allocate HPACK encoder dynamic table");
      RAISE_HPACK_ERROR (SocketHPACK_Error);
    }

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
 * Encode indexed header field (RFC 7541 Section 6.1)
 */
static ssize_t
hpack_encode_indexed (size_t index, unsigned char *output, size_t output_size)
{
  size_t pos = 0;
  unsigned char int_buf[16];
  size_t int_len;

  /* Indexed header field: 1xxxxxxx */
  int_len = SocketHPACK_int_encode (index, 7, int_buf, sizeof (int_buf));

  if (int_len == 0 || pos + int_len > output_size)
    return -1;

  output[pos++] = 0x80 | int_buf[0];
  for (size_t i = 1; i < int_len; i++)
    output[pos++] = int_buf[i];

  return (ssize_t)pos;
}

/**
 * Encode literal header field with indexing (RFC 7541 Section 6.2.1)
 */
static ssize_t
hpack_encode_literal_indexed (size_t name_index, const char *name,
                              size_t name_len, const char *value,
                              size_t value_len, int use_huffman,
                              unsigned char *output, size_t output_size)
{
  size_t pos = 0;

  if (name_index > 0)
    {
      /* Name is in table: 01xxxxxx (index) + value */
      unsigned char int_buf[16];
      size_t int_len
          = SocketHPACK_int_encode (name_index, 6, int_buf, sizeof (int_buf));

      if (pos + int_len > output_size)
        return -1;

      output[pos++] = 0x40 | int_buf[0];
      for (size_t i = 1; i < int_len; i++)
        output[pos++] = int_buf[i];
    }
  else
    {
      /* New name: 01000000 + name + value */
      output[pos++] = 0x40;

      ssize_t name_encoded
          = hpack_encode_string (name, name_len, use_huffman, output + pos,
                                 output_size - pos);
      if (name_encoded < 0)
        return -1;
      pos += (size_t)name_encoded;
    }

  /* Encode value */
  ssize_t value_encoded = hpack_encode_string (value, value_len, use_huffman,
                                               output + pos, output_size - pos);
  if (value_encoded < 0)
    return -1;
  pos += (size_t)value_encoded;

  return (ssize_t)pos;
}

/**
 * Encode literal header field without indexing (RFC 7541 Section 6.2.2)
 */
static ssize_t
hpack_encode_literal_no_index (size_t name_index, const char *name,
                               size_t name_len, const char *value,
                               size_t value_len, int use_huffman,
                               unsigned char *output, size_t output_size)
{
  size_t pos = 0;

  if (name_index > 0)
    {
      /* Name is in table: 0000xxxx (index) + value */
      unsigned char int_buf[16];
      size_t int_len
          = SocketHPACK_int_encode (name_index, 4, int_buf, sizeof (int_buf));

      if (pos + int_len > output_size)
        return -1;

      output[pos++] = int_buf[0] & 0x0F;
      for (size_t i = 1; i < int_len; i++)
        output[pos++] = int_buf[i];
    }
  else
    {
      /* New name: 00000000 + name + value */
      output[pos++] = 0x00;

      ssize_t name_encoded
          = hpack_encode_string (name, name_len, use_huffman, output + pos,
                                 output_size - pos);
      if (name_encoded < 0)
        return -1;
      pos += (size_t)name_encoded;
    }

  /* Encode value */
  ssize_t value_encoded = hpack_encode_string (value, value_len, use_huffman,
                                               output + pos, output_size - pos);
  if (value_encoded < 0)
    return -1;
  pos += (size_t)value_encoded;

  return (ssize_t)pos;
}

/**
 * Encode literal header field never indexed (RFC 7541 Section 6.2.3)
 */
static ssize_t
hpack_encode_literal_never (size_t name_index, const char *name,
                            size_t name_len, const char *value,
                            size_t value_len, int use_huffman,
                            unsigned char *output, size_t output_size)
{
  size_t pos = 0;

  if (name_index > 0)
    {
      /* Name is in table: 0001xxxx (index) + value */
      unsigned char int_buf[16];
      size_t int_len
          = SocketHPACK_int_encode (name_index, 4, int_buf, sizeof (int_buf));

      if (pos + int_len > output_size)
        return -1;

      output[pos++] = 0x10 | (int_buf[0] & 0x0F);
      for (size_t i = 1; i < int_len; i++)
        output[pos++] = int_buf[i];
    }
  else
    {
      /* New name: 00010000 + name + value */
      output[pos++] = 0x10;

      ssize_t name_encoded
          = hpack_encode_string (name, name_len, use_huffman, output + pos,
                                 output_size - pos);
      if (name_encoded < 0)
        return -1;
      pos += (size_t)name_encoded;
    }

  /* Encode value */
  ssize_t value_encoded = hpack_encode_string (value, value_len, use_huffman,
                                               output + pos, output_size - pos);
  if (value_encoded < 0)
    return -1;
  pos += (size_t)value_encoded;

  return (ssize_t)pos;
}

/**
 * Encode dynamic table size update (RFC 7541 Section 6.3)
 */
static ssize_t
hpack_encode_table_size_update (size_t max_size, unsigned char *output,
                                size_t output_size)
{
  size_t pos = 0;
  unsigned char int_buf[16];
  size_t int_len;

  /* Table size update: 001xxxxx */
  int_len = SocketHPACK_int_encode (max_size, 5, int_buf, sizeof (int_buf));

  if (int_len == 0 || pos + int_len > output_size)
    return -1;

  output[pos++] = 0x20 | int_buf[0];
  for (size_t i = 1; i < int_len; i++)
    output[pos++] = int_buf[i];

  return (ssize_t)pos;
}

/* External declaration for table find function */
extern int SocketHPACK_Table_find (SocketHPACK_Table_T table, const char *name,
                                   size_t name_len, const char *value,
                                   size_t value_len);

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
      encoded
          = hpack_encode_table_size_update (encoder->pending_table_size,
                                            output + pos, output_size - pos);
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
      const SocketHPACK_Header *hdr = &headers[i];
      int static_idx;
      int dynamic_idx;
      size_t name_index = 0;

      /* Check for indexed representation */
      /* First check static table */
      static_idx = SocketHPACK_static_find (hdr->name, hdr->name_len,
                                            hdr->value, hdr->value_len);

      if (static_idx > 0)
        {
          /* Exact match in static table */
          encoded
              = hpack_encode_indexed ((size_t)static_idx, output + pos,
                                      output_size - pos);
          if (encoded < 0)
            return -1;
          pos += (size_t)encoded;
          continue;
        }

      /* Check dynamic table */
      dynamic_idx = SocketHPACK_Table_find (encoder->table, hdr->name,
                                            hdr->name_len, hdr->value,
                                            hdr->value_len);

      if (dynamic_idx > 0)
        {
          /* Exact match in dynamic table */
          size_t index = SOCKETHPACK_STATIC_TABLE_SIZE + (size_t)dynamic_idx;
          encoded = hpack_encode_indexed (index, output + pos, output_size - pos);
          if (encoded < 0)
            return -1;
          pos += (size_t)encoded;
          continue;
        }

      /* No exact match - use literal representation */
      /* Check for name match */
      if (static_idx < 0)
        name_index = (size_t)(-static_idx);
      else if (dynamic_idx < 0)
        name_index = SOCKETHPACK_STATIC_TABLE_SIZE + (size_t)(-dynamic_idx);

      if (hdr->never_index)
        {
          /* Never indexed */
          encoded = hpack_encode_literal_never (
              name_index, hdr->name, hdr->name_len, hdr->value, hdr->value_len,
              encoder->huffman_encode, output + pos, output_size - pos);
        }
      else if (encoder->use_indexing)
        {
          /* With indexing */
          encoded = hpack_encode_literal_indexed (
              name_index, hdr->name, hdr->name_len, hdr->value, hdr->value_len,
              encoder->huffman_encode, output + pos, output_size - pos);

          /* Add to dynamic table */
          if (encoded >= 0)
            {
              SocketHPACK_Table_add (encoder->table, hdr->name, hdr->name_len,
                                     hdr->value, hdr->value_len);
            }
        }
      else
        {
          /* Without indexing */
          encoded = hpack_encode_literal_no_index (
              name_index, hdr->name, hdr->name_len, hdr->value, hdr->value_len,
              encoder->huffman_encode, output + pos, output_size - pos);
        }

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
    {
      SOCKET_ERROR_MSG ("Failed to allocate HPACK decoder");
      RAISE_HPACK_ERROR (SocketHPACK_Error);
    }

  decoder->table = SocketHPACK_Table_new (config->max_table_size, arena);
  if (decoder->table == NULL)
    {
      SOCKET_ERROR_MSG ("Failed to allocate HPACK decoder dynamic table");
      RAISE_HPACK_ERROR (SocketHPACK_Error);
    }

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
 * Get header from combined static + dynamic table index
 */
static SocketHPACK_Result
hpack_get_indexed (SocketHPACK_Decoder_T decoder, size_t index,
                   SocketHPACK_Header *header)
{
  if (index == 0)
    return HPACK_ERROR_INVALID_INDEX;

  if (index <= SOCKETHPACK_STATIC_TABLE_SIZE)
    {
      return SocketHPACK_static_get (index, header);
    }
  else
    {
      size_t dyn_index = index - SOCKETHPACK_STATIC_TABLE_SIZE;
      return SocketHPACK_Table_get (decoder->table, dyn_index, header);
    }
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
      uint64_t index;
      size_t consumed;

      if (byte & 0x80)
        {
          /* Indexed Header Field (Section 6.1): 1xxxxxxx */
          table_update_allowed = 0;

          result = SocketHPACK_int_decode (input + pos, input_len - pos, 7,
                                           &index, &consumed);
          if (result != HPACK_OK)
            return result;
          pos += consumed;

          result = hpack_get_indexed (decoder, (size_t)index, &header);
          if (result != HPACK_OK)
            return result;
        }
      else if ((byte & 0xC0) == 0x40)
        {
          /* Literal Header Field with Incremental Indexing (Section 6.2.1):
           * 01xxxxxx */
          table_update_allowed = 0;

          result = SocketHPACK_int_decode (input + pos, input_len - pos, 6,
                                           &index, &consumed);
          if (result != HPACK_OK)
            return result;
          pos += consumed;

          if (index > 0)
            {
              /* Name is indexed */
              SocketHPACK_Header name_hdr;
              result = hpack_get_indexed (decoder, (size_t)index, &name_hdr);
              if (result != HPACK_OK)
                return result;

              /* Copy name */
              char *name_copy = ALLOC (arena, name_hdr.name_len + 1);
              if (name_copy == NULL)
                return HPACK_ERROR;
              memcpy (name_copy, name_hdr.name, name_hdr.name_len);
              name_copy[name_hdr.name_len] = '\0';

              header.name = name_copy;
              header.name_len = name_hdr.name_len;
            }
          else
            {
              /* New name */
              char *name;
              size_t name_len;
              result = hpack_decode_string (input + pos, input_len - pos, &name,
                                            &name_len, &consumed, arena);
              if (result != HPACK_OK)
                return result;
              pos += consumed;

              header.name = name;
              header.name_len = name_len;
            }

          /* Decode value */
          char *value;
          size_t value_len;
          result = hpack_decode_string (input + pos, input_len - pos, &value,
                                        &value_len, &consumed, arena);
          if (result != HPACK_OK)
            return result;
          pos += consumed;

          header.value = value;
          header.value_len = value_len;

          /* Add to dynamic table */
          SocketHPACK_Table_add (decoder->table, header.name, header.name_len,
                                 header.value, header.value_len);
        }
      else if ((byte & 0xF0) == 0x00)
        {
          /* Literal Header Field without Indexing (Section 6.2.2): 0000xxxx */
          table_update_allowed = 0;

          result = SocketHPACK_int_decode (input + pos, input_len - pos, 4,
                                           &index, &consumed);
          if (result != HPACK_OK)
            return result;
          pos += consumed;

          if (index > 0)
            {
              /* Name is indexed */
              SocketHPACK_Header name_hdr;
              result = hpack_get_indexed (decoder, (size_t)index, &name_hdr);
              if (result != HPACK_OK)
                return result;

              char *name_copy = ALLOC (arena, name_hdr.name_len + 1);
              if (name_copy == NULL)
                return HPACK_ERROR;
              memcpy (name_copy, name_hdr.name, name_hdr.name_len);
              name_copy[name_hdr.name_len] = '\0';

              header.name = name_copy;
              header.name_len = name_hdr.name_len;
            }
          else
            {
              char *name;
              size_t name_len;
              result = hpack_decode_string (input + pos, input_len - pos, &name,
                                            &name_len, &consumed, arena);
              if (result != HPACK_OK)
                return result;
              pos += consumed;

              header.name = name;
              header.name_len = name_len;
            }

          char *value;
          size_t value_len;
          result = hpack_decode_string (input + pos, input_len - pos, &value,
                                        &value_len, &consumed, arena);
          if (result != HPACK_OK)
            return result;
          pos += consumed;

          header.value = value;
          header.value_len = value_len;
          /* NOT added to dynamic table */
        }
      else if ((byte & 0xF0) == 0x10)
        {
          /* Literal Header Field Never Indexed (Section 6.2.3): 0001xxxx */
          table_update_allowed = 0;

          result = SocketHPACK_int_decode (input + pos, input_len - pos, 4,
                                           &index, &consumed);
          if (result != HPACK_OK)
            return result;
          pos += consumed;

          if (index > 0)
            {
              SocketHPACK_Header name_hdr;
              result = hpack_get_indexed (decoder, (size_t)index, &name_hdr);
              if (result != HPACK_OK)
                return result;

              char *name_copy = ALLOC (arena, name_hdr.name_len + 1);
              if (name_copy == NULL)
                return HPACK_ERROR;
              memcpy (name_copy, name_hdr.name, name_hdr.name_len);
              name_copy[name_hdr.name_len] = '\0';

              header.name = name_copy;
              header.name_len = name_hdr.name_len;
            }
          else
            {
              char *name;
              size_t name_len;
              result = hpack_decode_string (input + pos, input_len - pos, &name,
                                            &name_len, &consumed, arena);
              if (result != HPACK_OK)
                return result;
              pos += consumed;

              header.name = name;
              header.name_len = name_len;
            }

          char *value;
          size_t value_len;
          result = hpack_decode_string (input + pos, input_len - pos, &value,
                                        &value_len, &consumed, arena);
          if (result != HPACK_OK)
            return result;
          pos += consumed;

          header.value = value;
          header.value_len = value_len;
          header.never_index = 1;
          /* NOT added to dynamic table */
        }
      else if ((byte & 0xE0) == 0x20)
        {
          /* Dynamic Table Size Update (Section 6.3): 001xxxxx */
          if (!table_update_allowed)
            return HPACK_ERROR_TABLE_SIZE;

          uint64_t new_size;
          result = SocketHPACK_int_decode (input + pos, input_len - pos, 5,
                                           &new_size, &consumed);
          if (result != HPACK_OK)
            return result;
          pos += consumed;

          if (new_size > decoder->settings_max_table_size)
            return HPACK_ERROR_TABLE_SIZE;

          SocketHPACK_Table_set_max_size (decoder->table, (size_t)new_size);
          continue; /* Not a header, continue to next */
        }
      else
        {
          /* Invalid encoding */
          return HPACK_ERROR;
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

