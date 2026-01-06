/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK.c - QPACK Header Compression (RFC 9204)
 *
 * Implementation of Section 4.5.4 - Literal Field Line with Name Reference.
 * Integer encoding/decoding follows RFC 9204 Section 5.1 (same as HPACK).
 */

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "http/SocketQPACK-private.h"
#include "http/SocketQPACK.h"

#include "core/SocketSecurity.h"

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
  [QPACK_ERROR_INTEGER] = "Integer encoding/decoding error",
  [QPACK_ERROR_TABLE_SIZE] = "Invalid dynamic table size",
  [QPACK_ERROR_HEADER_SIZE] = "Header too large",
  [QPACK_ERROR_LIST_SIZE] = "Header list too large",
  [QPACK_ERROR_INVALID_PATTERN] = "Invalid field line pattern",
};

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  if (result < 0 || result > QPACK_ERROR_INVALID_PATTERN)
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
 * Integer Encoding (RFC 9204 Section 5.1)
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

/* ============================================================================
 * Integer Decoding (RFC 9204 Section 5.1)
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
 * Pattern Detection (RFC 9204 Section 4.5.4)
 * ============================================================================
 */

int
SocketQPACK_is_literal_name_ref (unsigned char byte)
{
  return (byte & QPACK_LITERAL_NAME_REF_MASK) == QPACK_LITERAL_NAME_REF_PATTERN;
}

/* ============================================================================
 * Name Index Validation
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_validate_name_index (uint32_t name_index,
                                 int is_static,
                                 size_t dynamic_count)
{
  if (is_static)
    {
      /* Static table indices are 0-98 */
      if (name_index >= SOCKETQPACK_STATIC_TABLE_SIZE)
        return QPACK_ERROR_INVALID_INDEX;
    }
  else
    {
      /* Dynamic table - index must be < insert_count */
      if (name_index >= dynamic_count)
        return QPACK_ERROR_INVALID_INDEX;
    }
  return QPACK_OK;
}

/* ============================================================================
 * Name Resolution
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_resolve_name (uint32_t name_index,
                          int is_static,
                          SocketQPACK_Table_T dynamic_table,
                          SocketQPACK_Header *header)
{
  if (header == NULL)
    return QPACK_ERROR;

  if (is_static)
    return SocketQPACK_static_get ((size_t)name_index, header);

  if (dynamic_table == NULL)
    return QPACK_ERROR;

  return SocketQPACK_Table_get (dynamic_table, (size_t)name_index, header);
}

/* ============================================================================
 * Encoding: Literal Field Line with Name Reference
 * ============================================================================
 */

static ssize_t
encode_int_with_flag (uint64_t value,
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
encode_string (const char *str,
               size_t len,
               int use_huffman,
               unsigned char *output,
               size_t output_size)
{
  size_t pos = 0;
  ssize_t encoded;
  size_t data_len = len;
  unsigned char flag = 0;
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

  encoded = encode_int_with_flag (
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

ssize_t
SocketQPACK_encode_literal_name_ref (uint32_t name_index,
                                     int is_static,
                                     int never_indexed,
                                     const char *value,
                                     size_t value_len,
                                     int use_huffman,
                                     unsigned char *output,
                                     size_t output_size)
{
  size_t pos = 0;
  ssize_t encoded;
  unsigned char first_byte_flags;

  if (output == NULL || output_size == 0)
    return -1;

  /* Build first byte flags: 01NT */
  first_byte_flags = QPACK_LITERAL_NAME_REF_PATTERN;
  if (never_indexed)
    first_byte_flags |= QPACK_LITERAL_NAME_REF_N_BIT;
  if (is_static)
    first_byte_flags |= QPACK_LITERAL_NAME_REF_T_BIT;

  /* Encode name index with 4-bit prefix */
  encoded = encode_int_with_flag (name_index,
                                  QPACK_PREFIX_NAME_INDEX,
                                  first_byte_flags,
                                  output,
                                  output_size);
  if (encoded < 0)
    return -1;
  pos = (size_t)encoded;

  /* Encode value string */
  if (value == NULL)
    value_len = 0;

  encoded = encode_string (value ? value : "",
                           value_len,
                           use_huffman,
                           output + pos,
                           output_size - pos);
  if (encoded < 0)
    return -1;
  pos += (size_t)encoded;

  return (ssize_t)pos;
}

/* ============================================================================
 * Decoding: Literal Field Line with Name Reference
 * ============================================================================
 */

static SocketQPACK_Result
allocate_string_buffer (Arena_T arena, size_t buf_size, char **buf_out)
{
  size_t alloc_size = buf_size + 1;
  if (!SocketSecurity_check_size (alloc_size))
    return QPACK_ERROR_HEADER_SIZE;

  *buf_out = ALLOC (arena, alloc_size);
  if (*buf_out == NULL)
    return QPACK_ERROR;

  return QPACK_OK;
}

static SocketQPACK_Result
decode_string_literal (const unsigned char *input,
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
decode_string_huffman (const unsigned char *input,
                       size_t encoded_len,
                       size_t pos,
                       char **str_out,
                       size_t *str_len_out,
                       Arena_T arena)
{
  size_t max_decoded;
  if (!SocketSecurity_check_multiply (
          encoded_len, QPACK_HUFFMAN_RATIO, &max_decoded))
    return QPACK_ERROR_HEADER_SIZE;

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
decode_string (const unsigned char *input,
               size_t input_len,
               char **str_out,
               size_t *str_len_out,
               size_t *consumed,
               int *was_huffman,
               Arena_T arena)
{
  size_t pos = 0;
  int huffman;
  uint64_t str_len;
  SocketQPACK_Result result;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  huffman = (input[0] & QPACK_STRING_HUFFMAN_FLAG) != 0;
  if (was_huffman)
    *was_huffman = huffman;

  result = SocketQPACK_int_decode (
      input, input_len, QPACK_PREFIX_STRING, &str_len, &pos);
  if (result != QPACK_OK)
    return result;

  /* Check for overflow and incomplete data */
  if (str_len > SIZE_MAX || pos + str_len > input_len)
    return (str_len > SIZE_MAX) ? QPACK_ERROR_INTEGER : QPACK_INCOMPLETE;

  size_t len = (size_t)str_len;
  if (huffman)
    result
        = decode_string_huffman (input, len, pos, str_out, str_len_out, arena);
  else
    result
        = decode_string_literal (input, len, pos, str_out, str_len_out, arena);

  if (result != QPACK_OK)
    return result;

  *consumed = pos + len;
  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_decode_literal_name_ref (const unsigned char *input,
                                     size_t input_len,
                                     SocketQPACK_LiteralFieldLine *field,
                                     size_t *consumed,
                                     Arena_T arena)
{
  size_t pos = 0;
  uint64_t name_index;
  size_t index_consumed;
  SocketQPACK_Result result;

  if (input == NULL || field == NULL || consumed == NULL || arena == NULL)
    return QPACK_ERROR;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  /* Verify pattern is 01xxxxxx */
  if (!SocketQPACK_is_literal_name_ref (input[0]))
    return QPACK_ERROR_INVALID_PATTERN;

  /* Extract N and T bits */
  field->never_indexed = (input[0] & QPACK_LITERAL_NAME_REF_N_BIT) ? 1 : 0;
  field->is_static = (input[0] & QPACK_LITERAL_NAME_REF_T_BIT) ? 1 : 0;

  /* Decode name index with 4-bit prefix */
  result = SocketQPACK_int_decode (
      input, input_len, QPACK_PREFIX_NAME_INDEX, &name_index, &index_consumed);
  if (result != QPACK_OK)
    return result;

  if (name_index > UINT32_MAX)
    return QPACK_ERROR_INTEGER;

  field->name_index = (uint32_t)name_index;
  pos = index_consumed;

  /* Decode value string */
  char *value;
  size_t value_len;
  size_t value_consumed;
  int was_huffman;

  result = decode_string (input + pos,
                          input_len - pos,
                          &value,
                          &value_len,
                          &value_consumed,
                          &was_huffman,
                          arena);
  if (result != QPACK_OK)
    return result;

  field->value = value;
  field->value_len = value_len;
  field->huffman_encoded = was_huffman;

  *consumed = pos + value_consumed;
  return QPACK_OK;
}

/* ============================================================================
 * Dynamic Table Implementation
 * ============================================================================
 */

SocketQPACK_Table_T
SocketQPACK_Table_new (size_t max_size, Arena_T arena)
{
  SocketQPACK_Table_T table;
  size_t capacity;

  assert (arena != NULL);

  table = ALLOC (arena, sizeof (*table));
  if (table == NULL)
    return NULL;

  /* Calculate initial capacity */
  capacity = QPACK_MIN_DYNAMIC_TABLE_CAPACITY;
  if (max_size > 0)
    {
      size_t estimated = max_size / QPACK_AVERAGE_DYNAMIC_ENTRY_SIZE;
      if (estimated > capacity)
        capacity = estimated;
    }

  table->entries = CALLOC (arena, capacity, sizeof (QPACK_DynamicEntry));
  if (table->entries == NULL)
    return NULL;

  table->capacity = capacity;
  table->head = 0;
  table->tail = 0;
  table->count = 0;
  table->size = 0;
  table->max_size = max_size;
  table->insert_count = 0;
  table->arena = arena;

  return table;
}

void
SocketQPACK_Table_free (SocketQPACK_Table_T *table)
{
  if (table == NULL || *table == NULL)
    return;
  /* Memory freed when arena is disposed */
  *table = NULL;
}

void
SocketQPACK_Table_set_max_size (SocketQPACK_Table_T table, size_t max_size)
{
  assert (table != NULL);
  table->max_size = max_size;

  /* Evict entries if necessary */
  while (table->size > table->max_size && table->count > 0)
    qpack_table_evict (table, 0);
}

size_t
SocketQPACK_Table_size (SocketQPACK_Table_T table)
{
  assert (table != NULL);
  return table->size;
}

size_t
SocketQPACK_Table_count (SocketQPACK_Table_T table)
{
  assert (table != NULL);
  return table->count;
}

size_t
SocketQPACK_Table_max_size (SocketQPACK_Table_T table)
{
  assert (table != NULL);
  return table->max_size;
}

SocketQPACK_Result
SocketQPACK_Table_get (SocketQPACK_Table_T table,
                       size_t index,
                       SocketQPACK_Header *header)
{
  size_t ring_index;
  QPACK_DynamicEntry *entry;

  assert (table != NULL);
  assert (header != NULL);

  if (index >= table->count)
    return QPACK_ERROR_INVALID_INDEX;

  /* Convert absolute index to ring buffer position
   * Index 0 is the oldest entry (tail) */
  ring_index = (table->tail + index) % table->capacity;
  entry = &table->entries[ring_index];

  header->name = entry->name;
  header->name_len = entry->name_len;
  header->value = entry->value;
  header->value_len = entry->value_len;
  header->never_index = 0;

  return QPACK_OK;
}

size_t
qpack_table_evict (SocketQPACK_Table_T table, size_t required_space)
{
  size_t freed = 0;
  (void)required_space; /* Used for calculating when to stop */

  if (table->count == 0)
    return 0;

  QPACK_DynamicEntry *entry = &table->entries[table->tail];
  size_t entry_size = qpack_entry_size (entry->name_len, entry->value_len);

  /* Clear entry (memory managed by arena) */
  entry->name = NULL;
  entry->name_len = 0;
  entry->value = NULL;
  entry->value_len = 0;

  table->tail = (table->tail + 1) % table->capacity;
  table->count--;
  if (entry_size != SIZE_MAX)
    {
      table->size -= entry_size;
      freed = entry_size;
    }

  return freed;
}

SocketQPACK_Result
SocketQPACK_Table_add (SocketQPACK_Table_T table,
                       const char *name,
                       size_t name_len,
                       const char *value,
                       size_t value_len)
{
  size_t entry_size;
  QPACK_DynamicEntry *entry;
  char *name_copy;
  char *value_copy;

  assert (table != NULL);

  entry_size = qpack_entry_size (name_len, value_len);
  if (entry_size == SIZE_MAX)
    return QPACK_ERROR_HEADER_SIZE;

  /* Entry too large for table - evict all and don't add */
  if (entry_size > table->max_size)
    {
      while (table->count > 0)
        qpack_table_evict (table, 0);
      return QPACK_OK;
    }

  /* Evict until there's room */
  while (table->size + entry_size > table->max_size && table->count > 0)
    qpack_table_evict (table, entry_size);

  /* Copy strings */
  name_copy = ALLOC (table->arena, name_len + 1);
  if (name_copy == NULL)
    return QPACK_ERROR;
  memcpy (name_copy, name, name_len);
  name_copy[name_len] = '\0';

  value_copy = ALLOC (table->arena, value_len + 1);
  if (value_copy == NULL)
    return QPACK_ERROR;
  memcpy (value_copy, value, value_len);
  value_copy[value_len] = '\0';

  /* Add at head */
  entry = &table->entries[table->head];
  entry->name = name_copy;
  entry->name_len = name_len;
  entry->value = value_copy;
  entry->value_len = value_len;

  table->head = (table->head + 1) % table->capacity;
  table->count++;
  table->size += entry_size;
  table->insert_count++;

  return QPACK_OK;
}

int
SocketQPACK_Table_find (SocketQPACK_Table_T table,
                        const char *name,
                        size_t name_len,
                        const char *value,
                        size_t value_len)
{
  size_t i;
  int name_match_index = 0;

  if (table == NULL || name == NULL)
    return 0;

  for (i = 0; i < table->count; i++)
    {
      size_t ring_idx = (table->tail + i) % table->capacity;
      QPACK_DynamicEntry *entry = &table->entries[ring_idx];

      if (entry->name_len != name_len)
        continue;

      if (memcmp (entry->name, name, name_len) != 0)
        continue;

      /* Name matches - check value */
      if (value != NULL && entry->value_len == value_len
          && memcmp (entry->value, value, value_len) == 0)
        {
          /* Exact match - return positive index (1-based) */
          return (int)(i + 1);
        }

      /* Name-only match - remember index */
      if (name_match_index == 0)
        name_match_index = -((int)(i + 1));
    }

  return name_match_index;
}
