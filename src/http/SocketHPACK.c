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

#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketHPACK-private.h"
#include "http/SocketHPACK.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

/* ============================================================================
 * Constants - RFC 7541 Field Type Bit Patterns
 * ============================================================================
 */

/* Field type identification masks (RFC 7541 Section 6) */
#define HPACK_INDEXED_MASK 0x80         /* 1xxxxxxx - Indexed Header Field */
#define HPACK_LITERAL_INDEXED_MASK 0xC0 /* 01xxxxxx - Literal with Indexing   \
                                         */
#define HPACK_LITERAL_INDEXED_VAL 0x40
#define HPACK_LITERAL_NO_INDEX_MASK                                           \
  0xF0                                /* 0000xxxx - Literal without Indexing */
#define HPACK_LITERAL_NEVER_MASK 0xF0 /* 0001xxxx - Literal Never Indexed */
#define HPACK_LITERAL_NEVER_VAL 0x10
#define HPACK_TABLE_UPDATE_MASK 0xE0 /* 001xxxxx - Table Size Update */
#define HPACK_TABLE_UPDATE_VAL 0x20

/* Prefix bits for integer encoding (RFC 7541 Section 5.1) */
#define HPACK_PREFIX_INDEXED 7       /* For indexed header field */
#define HPACK_PREFIX_LITERAL_INDEX 6 /* For literal with indexing */
#define HPACK_PREFIX_LITERAL_OTHER 4 /* For literal without/never indexed */
#define HPACK_PREFIX_TABLE_UPDATE 5  /* For table size update */
#define HPACK_PREFIX_STRING 7        /* For string literal length */

#define HPACK_STRING_HUFFMAN_FLAG 0x80 /* Huffman flag for string literals */
#define HPACK_STRING_LITERAL_FLAG 0x00 /* Literal string (no Huffman) flag */

#define HPACK_INT_CONTINUATION_MASK                                           \
  0x80                              /* Continuation bit in integer encoding */
#define HPACK_INT_PAYLOAD_MASK 0x7F /* 7-bit payload mask */
#define HPACK_INT_CONTINUATION_VALUE                                          \
  128 /* Value requiring continuation bytes */

/* Buffer sizes */
#define HPACK_INT_BUF_SIZE 16 /* Buffer for integer encoding */
#define HPACK_HUFFMAN_RATIO                                                   \
  2 /* Estimated decode expansion ratio (Huffman can expand slightly with     \
       padding) */

#define HPACK_UINT64_SHIFT_LIMIT                                              \
  63 /* Maximum shift before uint64_t overflow */

static inline bool
valid_prefix_bits (int prefix_bits)
{
  return prefix_bits >= 1 && prefix_bits <= 8;
}

/* Literal encoding mode flags */
#define HPACK_LITERAL_WITH_INDEXING 0x40
#define HPACK_LITERAL_WITHOUT_INDEX 0x00
#define HPACK_LITERAL_NEVER_INDEX 0x10

/* Literal type values for dispatch */
#define HPACK_LITERAL_WITHOUT_INDEX_VAL 0x00

/* ============================================================================
 * Exception Definition
 * ============================================================================
 */

const Except_T SocketHPACK_Error
    = { &SocketHPACK_Error, "HPACK compression error" };

/* Thread-local exception for detailed error messages */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketHPACK);

#define RAISE_HPACK_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketHPACK, e)

/* ============================================================================
 * Result Strings
 * ============================================================================
 */

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
 * ============================================================================
 */

static size_t
encode_int_continuation (uint64_t value, unsigned char *output, size_t pos,
                         size_t output_size)
{
  /**
   * encode_int_continuation - Encode integer continuation and final byte
   * @value: Value to encode (after prefix subtraction)
   * @output: Output buffer
   * @pos: Current position (updated)
   * @output_size: Buffer size
   *
   * Encodes the continuation bytes and final byte for large integers.
   * Returns new pos on success, 0 on buffer full error.
   * Thread-safe: Yes
   */
  while (value >= HPACK_INT_CONTINUATION_VALUE && pos < output_size)
    {
      output[pos++] = (unsigned char)(HPACK_INT_CONTINUATION_MASK
                                      | (value & HPACK_INT_PAYLOAD_MASK));
      value >>= 7;
    }

  if (pos < output_size)
    output[pos++] = (unsigned char)value;
  else
    return 0; /* Buffer full for final byte */

  return pos;
}

size_t
SocketHPACK_int_encode (uint64_t value, int prefix_bits, unsigned char *output,
                        size_t output_size)
{
  size_t pos = 0;
  uint64_t max_prefix;

  if (output == NULL || output_size == 0)
    return 0;

  if (!valid_prefix_bits (prefix_bits))
    return 0;

  max_prefix = ((uint64_t)1 << prefix_bits) - 1;

  if (value < max_prefix)
    {
      output[pos++] = (unsigned char)value;
      return pos;
    }

  /* Value requires continuation bytes - first byte is max_prefix */
  if (pos >= output_size)
    return 0;
  output[pos++] = (unsigned char)max_prefix;

  /* Encode remainder using multi-byte encoding */
  value -= max_prefix;
  return encode_int_continuation (value, output, pos, output_size);
}

/**
 * decode_int_continuation - Decode continuation bytes for HPACK integer
 * @input: Input buffer
 * @input_len: Remaining input length
 * @pos: Current position (updated)
 * @result: Accumulated value (updated)
 * @shift: Current shift amount (updated)
 *
 * Decodes the continuation bytes of a multi-byte integer encoding.
 * Handles overflow checks and updates result and position.
 *
 * Returns: HPACK_OK on success, HPACK_INCOMPLETE or HPACK_ERROR_INTEGER on
 * failure Thread-safe: Yes
 */
static SocketHPACK_Result
decode_int_continuation (const unsigned char *input, size_t input_len,
                         size_t *pos, uint64_t *result, unsigned int *shift)
{
  uint64_t byte_val;

  do
    {
      if (*pos >= input_len)
        return HPACK_INCOMPLETE;

      byte_val = input[(*pos)++];

      if (*shift >= HPACK_UINT64_SHIFT_LIMIT)
        return HPACK_ERROR_INTEGER;

      uint64_t add_val = (byte_val & HPACK_INT_PAYLOAD_MASK) << *shift;
      if (*result > UINT64_MAX - add_val)
        return HPACK_ERROR_INTEGER;

      *result += add_val;
      *shift += 7;
    }
  while (byte_val & HPACK_INT_CONTINUATION_MASK);

  return HPACK_OK;
}

SocketHPACK_Result
SocketHPACK_int_decode (const unsigned char *input, size_t input_len,
                        int prefix_bits, uint64_t *value, size_t *consumed)
{
  size_t pos = 0;
  uint64_t max_prefix;
  uint64_t result;
  unsigned int shift = 0; /* Initialized but used only in continuation */

  if (input == NULL || value == NULL || consumed == NULL)
    return HPACK_ERROR;

  if (input_len == 0)
    return HPACK_INCOMPLETE;

  if (!valid_prefix_bits (prefix_bits))
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
  SocketHPACK_Result cont_result
      = decode_int_continuation (input, input_len, &pos, &result, &shift);
  if (cont_result != HPACK_OK)
    return cont_result;

  *value = result;
  *consumed = pos;
  return HPACK_OK;
}

/* ============================================================================
 * String Literal Encoding/Decoding (RFC 7541 Section 5.2)
 * ============================================================================
 */

static ssize_t hpack_encode_int_with_flag (uint64_t value, int prefix_bits,
                                           unsigned char flag,
                                           unsigned char *output,
                                           size_t output_size);

static ssize_t
encode_string_length_flag (size_t len, unsigned char flag,
                           unsigned char *output, size_t output_size)
{
  /**
   * encode_string_length_flag - Encode string length with flag bit
   * @len: Length to encode
   * @flag: Flag byte (Huffman or literal)
   * @output: Output buffer
   * @output_size: Buffer size
   *
   * Encodes the string length with the specified flag (0x80 for Huffman).
   *
   * Returns: Bytes written for length, or -1 on error
   * Thread-safe: Yes
   */
  return hpack_encode_int_with_flag (len, HPACK_PREFIX_STRING, flag, output,
                                     output_size);
}

static ssize_t
encode_string_data_literal (const char *str, size_t len, unsigned char *output,
                            size_t pos, size_t output_size)
{
  /**
   * encode_string_data_literal - Encode literal string data
   * @str: String data
   * @len: Length
   * @output: Output buffer
   * @pos: Current position
   * @output_size: Buffer size
   *
   * Copies literal string data to output after length prefix.
   *
   * Returns: Bytes written (len), or -1 if buffer too small
   * Thread-safe: Yes
   */
  if (pos + len > output_size)
    return -1;

  memcpy (output + pos, str, len);
  return (ssize_t)len;
}

static ssize_t
encode_string_data_huffman (const char *str, size_t len, unsigned char *output,
                            size_t pos, size_t output_size)
{
  /**
   * encode_string_data_huffman - Encode Huffman-compressed string data
   * @str: Input string
   * @len: Length
   * @output: Output buffer
   * @pos: Current position
   * @output_size: Buffer size
   *
   * Encodes string using Huffman and writes to output.
   *
   * Returns: Bytes written, or -1 on error
   * Thread-safe: Yes
   */
  ssize_t encoded = SocketHPACK_huffman_encode (
      (const unsigned char *)str, len, output + pos, output_size - pos);
  if (encoded < 0)
    return -1;
  return encoded;
}

/**
 * hpack_encode_int_with_flag - Encode integer with flag bit in prefix byte
 * @value: Integer value to encode
 * @prefix_bits: Number of prefix bits (1-8)
 * @flag: Flag to OR with first prefix byte (e.g., 0x80 for Huffman)
 * @output: Output buffer
 * @output_size: Output buffer size
 *
 * Encodes an integer using HPACK format, setting the high bit(s) of the first
 * byte to the specified flag value.
 *
 * Returns: Bytes written, or -1 if buffer too small or invalid params
 * Thread-safe: Yes
 */
static ssize_t
hpack_encode_int_with_flag (uint64_t value, int prefix_bits,
                            unsigned char flag, unsigned char *output,
                            size_t output_size)
{
  unsigned char int_buf[HPACK_INT_BUF_SIZE];
  size_t int_len;
  size_t pos = 0;

  int_len
      = SocketHPACK_int_encode (value, prefix_bits, int_buf, sizeof (int_buf));
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
          encoded = encode_string_length_flag (
              huffman_size, HPACK_STRING_HUFFMAN_FLAG, output, output_size);
          if (encoded < 0)
            return -1;
          pos = (size_t)encoded;

          encoded = encode_string_data_huffman (str, len, output, pos,
                                                output_size);
          if (encoded < 0)
            return -1;
          pos += (size_t)encoded;

          return (ssize_t)pos;
        }
    }

  /* Use literal encoding */
  encoded = encode_string_length_flag (len, HPACK_STRING_LITERAL_FLAG, output,
                                       output_size);
  if (encoded < 0)
    return -1;
  pos = (size_t)encoded;

  encoded = encode_string_data_literal (str, len, output, pos, output_size);
  if (encoded < 0)
    return -1;
  pos += (size_t)encoded;

  return (ssize_t)pos;
}

/**
 * hpack_decode_string - Decode a string literal
 */
static SocketHPACK_Result
decode_string_header (const unsigned char *input, size_t input_len,
                      size_t *pos, int *huffman, uint64_t *str_len)
{
  /**
   * decode_string_header - Decode string length prefix and Huffman flag
   * @input: Input buffer
   * @input_len: Input length
   * @pos: Position (updated to after length)
   * @huffman: Output Huffman flag (1 if Huffman encoded)
   * @str_len: Output string length
   *
   * Decodes the HPACK string length prefix, including Huffman flag bit.
   *
   * Returns: HPACK_OK on success, HPACK_INCOMPLETE or error from int_decode
   * Thread-safe: Yes
   */
  if (input_len == 0)
    return HPACK_INCOMPLETE;

  *huffman = (input[0] & HPACK_STRING_HUFFMAN_FLAG) != 0;

  return SocketHPACK_int_decode (input, input_len, HPACK_PREFIX_STRING,
                                 str_len, pos);
}

static SocketHPACK_Result
decode_string_data_literal (const unsigned char *input, uint64_t str_len,
                            size_t pos, char **str_out, size_t *str_len_out,
                            Arena_T arena)
{
  /**
   * decode_string_data_literal - Decode literal string data
   * @input: Input buffer
   * @str_len: Decoded length
   * @pos: Position of data in input
   * @str_out: Output string (allocated)
   * @str_len_out: Actual length (same as str_len)
   * @arena: Arena for allocation
   *
   * Allocates and copies literal string data.
   *
   * Returns: HPACK_OK on success, HPACK_ERROR on allocation failure
   * Thread-safe: Yes (arena must be)
   */
  if (str_len > SIZE_MAX)
    return HPACK_ERROR_INTEGER;

  size_t alloc_size = (size_t)str_len + 1;
  if (!SocketSecurity_check_size (alloc_size))
    return HPACK_ERROR_BOMB;

  *str_len_out = (size_t)str_len;
  *str_out = ALLOC (arena, alloc_size);
  if (*str_out == NULL)
    return HPACK_ERROR;

  memcpy (*str_out, input + pos, str_len);
  (*str_out)[str_len] = '\0';
  return HPACK_OK;
}

static SocketHPACK_Result
decode_string_data_huffman (const unsigned char *input, uint64_t str_len,
                            size_t pos, char **str_out, size_t *str_len_out,
                            Arena_T arena)
{
  /**
   * decode_string_data_huffman - Decode Huffman-encoded string data
   * @input: Input buffer
   * @str_len: Encoded length
   * @pos: Position of encoded data
   * @str_out: Output string (allocated)
   * @str_len_out: Actual decoded length
   * @arena: Arena for allocation
   *
   * Allocates buffer and decodes Huffman data.
   *
   * Returns: HPACK_OK on success, HPACK_ERROR_HUFFMAN or HPACK_ERROR
   * Thread-safe: Yes (arena must be)
   */
  if (str_len > SIZE_MAX)
    return HPACK_ERROR_INTEGER;

  size_t encoded_len = (size_t)str_len;
  size_t max_decoded;
  if (!SocketSecurity_check_multiply (encoded_len, HPACK_HUFFMAN_RATIO,
                                      &max_decoded))
    return HPACK_ERROR_BOMB;

  if (!SocketSecurity_check_size (max_decoded + 1))
    return HPACK_ERROR_BOMB;

  *str_out = ALLOC (arena, max_decoded + 1);
  if (*str_out == NULL)
    return HPACK_ERROR;

  ssize_t decoded = SocketHPACK_huffman_decode (
      input + pos, encoded_len, (unsigned char *)*str_out, max_decoded);
  if (decoded < 0)
    return HPACK_ERROR_HUFFMAN;

  (*str_out)[decoded] = '\0';
  *str_len_out = (size_t)decoded;
  return HPACK_OK;
}

static SocketHPACK_Result
hpack_decode_string (const unsigned char *input, size_t input_len,
                     char **str_out, size_t *str_len_out, size_t *consumed,
                     Arena_T arena)
{
  size_t pos = 0;
  int huffman;
  uint64_t str_len;
  SocketHPACK_Result result;
  char *str;
  size_t actual_len;

  result = decode_string_header (input, input_len, &pos, &huffman, &str_len);
  if (result != HPACK_OK)
    return result;

  if (str_len > SIZE_MAX)
    return HPACK_ERROR_INTEGER;

  if (pos + (size_t)str_len > input_len)
    return HPACK_INCOMPLETE;

  if (huffman)
    {
      result = decode_string_data_huffman (input, str_len, pos, &str,
                                           &actual_len, arena);
    }
  else
    {
      result = decode_string_data_literal (input, str_len, pos, &str,
                                           &actual_len, arena);
    }
  if (result != HPACK_OK)
    return result;

  *str_out = str;
  *str_len_out = actual_len;
  *consumed = pos + str_len;
  return HPACK_OK;
}

/* ============================================================================
 * Encoder Configuration
 * ============================================================================
 */

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
 * ============================================================================
 */

SocketHPACK_Encoder_T
SocketHPACK_Encoder_new (const SocketHPACK_EncoderConfig *config,
                         Arena_T arena)
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

  encoder->table = SocketHPACK_Table_new (config->max_table_size, arena);

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

static ssize_t
encode_header_name (unsigned char mode, size_t name_index, const char *name,
                    size_t name_len, int use_huffman, unsigned char *output,
                    size_t output_size)
{
  /**
   * encode_header_name - Encode header name for literal field
   * @mode: Literal mode flag
   * @name_index: Table index for name (0 for new name)
   * @name: Name string (if new)
   * @name_len: Name length
   * @use_huffman: Use Huffman for string encoding
   * @output: Output buffer
   * @output_size: Buffer size
   *
   * Encodes the name part of a literal header field, either indexed or new
   * string.
   *
   * Returns: Bytes written, or -1 on error
   * Thread-safe: Yes
   */
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

      encoded = hpack_encode_string (name, name_len, use_huffman, output + pos,
                                     output_size - pos);
      if (encoded < 0)
        return -1;
      pos += (size_t)encoded;
    }

  return (ssize_t)pos;
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
  ssize_t encoded = encode_header_name (mode, name_index, name, name_len,
                                        use_huffman, output, output_size);
  if (encoded < 0)
    return -1;
  size_t pos = (size_t)encoded;

  /* Encode value */
  encoded = hpack_encode_string (value, value_len, use_huffman, output + pos,
                                 output_size - pos);
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

static ssize_t
emit_pending_table_update (SocketHPACK_Encoder_T encoder,
                           unsigned char *output, size_t output_size)
{
  /**
   * emit_pending_table_update - Emit pending dynamic table size update
   * @encoder: Encoder instance
   * @output: Output buffer
   * @output_size: Buffer size
   *
   * Encodes and emits a pending table size update at the start of header
   * block. Updates table max size and clears pending flag.
   *
   * Returns: Bytes written, or -1 on error
   * Thread-safe: No
   */
  if (!encoder->pending_table_size_update)
    return 0;

  ssize_t encoded = hpack_encode_table_size_update (
      encoder->pending_table_size, output, output_size);
  if (encoded < 0)
    return -1;

  SocketHPACK_Table_set_max_size (encoder->table, encoder->pending_table_size);
  encoder->pending_table_size_update = 0;

  return encoded;
}

static int
find_header_index (SocketHPACK_Encoder_T encoder,
                   const SocketHPACK_Header *hdr, size_t *name_index)
{
  /**
   * find_header_index - Find exact match or name-only index in tables
   * @encoder: Encoder (for dynamic table)
   * @hdr: Header to find
   * @name_index: Output name index for literal encoding (0 if new name)
   *
   * Searches static and dynamic tables for exact match or name-only match.
   *
   * Returns: Positive index for exact match, 0 for no exact match
   * Thread-safe: No
   */
  int static_idx = SocketHPACK_static_find (hdr->name, hdr->name_len,
                                            hdr->value, hdr->value_len);
  if (static_idx > 0)
    return static_idx;

  int dynamic_idx = SocketHPACK_Table_find (
      encoder->table, hdr->name, hdr->name_len, hdr->value, hdr->value_len);
  if (dynamic_idx > 0)
    return SOCKETHPACK_STATIC_TABLE_SIZE + dynamic_idx;

  /* No exact match - set name_index for literal */
  *name_index = 0;
  if (static_idx < 0)
    *name_index = (size_t)(-static_idx);
  else if (dynamic_idx < 0)
    *name_index = SOCKETHPACK_STATIC_TABLE_SIZE + (size_t)(-dynamic_idx);

  return 0;
}

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
  size_t name_index = 0;
  int exact_index = find_header_index (encoder, hdr, &name_index);

  if (exact_index > 0)
    return hpack_encode_indexed ((size_t)exact_index, output, output_size);

  /* No exact match - literal encoding */
  unsigned char mode;
  int add_to_table = 0;

  if (hdr->never_index)
    {
      mode = HPACK_LITERAL_NEVER_INDEX;
    }
  else if (encoder->use_indexing)
    {
      mode = HPACK_LITERAL_WITH_INDEXING;
      add_to_table = 1;
    }
  else
    {
      mode = HPACK_LITERAL_WITHOUT_INDEX;
    }

  ssize_t encoded = hpack_encode_literal (
      mode, name_index, hdr->name, hdr->name_len, hdr->value, hdr->value_len,
      encoder->huffman_encode, output, output_size);

  if (encoded >= 0 && add_to_table)
    {
      SocketHPACK_Table_add (encoder->table, hdr->name, hdr->name_len,
                             hdr->value, hdr->value_len);
    }

  return encoded;
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
  ssize_t update_encoded
      = emit_pending_table_update (encoder, output + pos, output_size - pos);
  if (update_encoded < 0)
    return -1;
  pos += (size_t)update_encoded;

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
 * ============================================================================
 */

void
SocketHPACK_decoder_config_defaults (SocketHPACK_DecoderConfig *config)
{
  if (config == NULL)
    return;

  config->max_table_size = SOCKETHPACK_DEFAULT_TABLE_SIZE;
  config->max_header_size = SOCKETHPACK_MAX_HEADER_SIZE;
  config->max_header_list_size = SOCKETHPACK_MAX_HEADER_LIST_SIZE;
  config->max_expansion_ratio
      = 10.0; /* Prevent decompression bombs: decoded <= encoded * ratio */
}

/* ============================================================================
 * Decoder Implementation
 * ============================================================================
 */

SocketHPACK_Decoder_T
SocketHPACK_Decoder_new (const SocketHPACK_DecoderConfig *config,
                         Arena_T arena)
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

  decoder->table = SocketHPACK_Table_new (config->max_table_size, arena);

  decoder->max_header_size = config->max_header_size;
  decoder->max_header_list_size = config->max_header_list_size;
  decoder->settings_max_table_size = config->max_table_size;
  decoder->max_expansion_ratio = config->max_expansion_ratio;
  decoder->decode_input_bytes = 0;
  decoder->decode_output_bytes = 0;
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

static SocketHPACK_Result
validate_header (SocketHPACK_Decoder_T decoder,
                 const SocketHPACK_Header *header, size_t *total_size)
{
  /**
   * validate_header - Validate header size limits
   * @decoder: Decoder with limits
   * @header: Decoded header
   * @total_size: Current total size (updated)
   *
   * Checks individual header size and updates total list size.
   *
   * Returns: HPACK_OK if valid, HPACK_ERROR_HEADER_SIZE or
   * HPACK_ERROR_LIST_SIZE if exceeded Thread-safe: No
   */
  size_t header_size = hpack_entry_size (header->name_len, header->value_len);
  if (header_size == SIZE_MAX || header_size > decoder->max_header_size)
    return HPACK_ERROR_HEADER_SIZE;

  size_t new_total;
  if (!SocketSecurity_check_add (*total_size, header_size, &new_total))
    return HPACK_ERROR_LIST_SIZE; /* Overflow protection */

  *total_size = new_total;
  if (*total_size > decoder->max_header_list_size)
    return HPACK_ERROR_LIST_SIZE;

  return HPACK_OK;
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
hpack_decode_literal (SocketHPACK_Decoder_T decoder,
                      const unsigned char *input, size_t input_len,
                      int prefix_bits, size_t *pos, SocketHPACK_Header *header,
                      int add_to_table, int never_indexed, Arena_T arena)
{
  uint64_t index;
  size_t consumed;
  SocketHPACK_Result result;
  char *name;
  size_t name_len;
  char *value;
  size_t value_len;

  /* Decode name index */
  if (!valid_prefix_bits (prefix_bits))
    return HPACK_ERROR;

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

  if (!valid_prefix_bits (HPACK_PREFIX_INDEXED))
    return HPACK_ERROR;

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

  if (!valid_prefix_bits (HPACK_PREFIX_TABLE_UPDATE))
    return HPACK_ERROR;

  result = SocketHPACK_int_decode (input + *pos, input_len - *pos,
                                   HPACK_PREFIX_TABLE_UPDATE, &new_size,
                                   &consumed);
  if (result != HPACK_OK)
    return result;
  *pos += consumed;

  if (new_size > SIZE_MAX)
    return HPACK_ERROR_INTEGER;
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
      else if ((byte & HPACK_LITERAL_INDEXED_MASK)
               == HPACK_LITERAL_INDEXED_VAL)
        {
          /* Literal with Incremental Indexing (Section 6.2.1): 01xxxxxx */
          table_update_allowed = 0;
          result = hpack_decode_literal (decoder, input, input_len,
                                         HPACK_PREFIX_LITERAL_INDEX, &pos,
                                         &header, 1, 0, arena);
          if (result != HPACK_OK)
            return result;
        }
      else if ((byte & HPACK_LITERAL_NO_INDEX_MASK)
               == HPACK_LITERAL_WITHOUT_INDEX_VAL)
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

      /* Validate and update size */
      SocketHPACK_Result val_result
          = validate_header (decoder, &header, &total_size);
      if (val_result != HPACK_OK)
        return val_result;

      /* Store header */
      if (hdr_count < max_headers)
        headers[hdr_count] = header;
      hdr_count++;
    }

  *header_count = hdr_count;
  return HPACK_OK;
}
