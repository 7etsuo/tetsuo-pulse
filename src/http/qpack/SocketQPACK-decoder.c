/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK-decoder.c - QPACK Decoder (RFC 9204)
 *
 * Implements QPACK decoder functionality including:
 * - Stream Cancellation instruction (Section 4.4.2)
 * - Dynamic table management
 * - Per-stream reference tracking
 * - Integer encoding/decoding (reuses HPACK RFC 7541 Section 5.1)
 */

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "http/SocketQPACK.h"
#include "http/SocketQPACK-private.h"

#include "core/SocketSecurity.h"

/* ============================================================================
 * Exception Definitions
 * ============================================================================
 */

const Except_T SocketQPACK_Error
    = { &SocketQPACK_Error, "QPACK compression error" };

const Except_T SocketQPACK_DecompressionFailed
    = { &SocketQPACK_DecompressionFailed, "QPACK decompression failed" };

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
  [QPACK_ERROR_TABLE_SIZE] = "Invalid dynamic table size",
  [QPACK_ERROR_HEADER_SIZE] = "Header too large",
  [QPACK_ERROR_LIST_SIZE] = "Header list too large",
  [QPACK_ERROR_STREAM_ID] = "Invalid stream ID",
  [QPACK_ERROR_DECODER_STREAM] = "Decoder stream error",
  [QPACK_ERROR_ENCODER_STREAM] = "Encoder stream error",
};

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  if (result < 0 || result > QPACK_ERROR_ENCODER_STREAM)
    return "Unknown error";
  return result_strings[result];
}

/* ============================================================================
 * Integer Encoding/Decoding (RFC 7541 Section 5.1)
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

  if (output == NULL || output_size == 0
      || !qpack_valid_prefix_bits (prefix_bits))
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

  if (!qpack_valid_prefix_bits (prefix_bits))
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
 * Dynamic Table
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

  /* Calculate initial capacity based on average entry size */
  if (max_size > 0)
    {
      capacity = max_size / QPACK_AVERAGE_DYNAMIC_ENTRY_SIZE;
      if (capacity < QPACK_MIN_DYNAMIC_TABLE_CAPACITY)
        capacity = QPACK_MIN_DYNAMIC_TABLE_CAPACITY;
      if (capacity > SOCKETQPACK_MAX_DYNAMIC_ENTRIES)
        capacity = SOCKETQPACK_MAX_DYNAMIC_ENTRIES;
    }
  else
    {
      capacity = 0;
    }

  table->entries = NULL;
  if (capacity > 0)
    {
      table->entries
          = CALLOC (arena, capacity, sizeof (SocketQPACK_DynamicEntry));
    }

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
  /* Arena handles all memory deallocation */
  *table = NULL;
}

void
SocketQPACK_Table_set_max_size (SocketQPACK_Table_T table, size_t max_size)
{
  assert (table != NULL);

  if (max_size > SOCKETQPACK_MAX_TABLE_SIZE)
    max_size = SOCKETQPACK_MAX_TABLE_SIZE;

  /* Evict entries if needed */
  while (table->size > max_size && table->count > 0)
    {
      /* Evict oldest entry (FIFO) */
      SocketQPACK_DynamicEntry *entry = &table->entries[table->tail];
      size_t entry_size = qpack_entry_size (entry->name_len, entry->value_len);

      if (entry_size != SIZE_MAX && entry_size <= table->size)
        table->size -= entry_size;
      else
        table->size = 0;

      /* Clear entry references */
      entry->name = NULL;
      entry->name_len = 0;
      entry->value = NULL;
      entry->value_len = 0;
      entry->ref_count = 0;
      entry->refs = NULL;

      table->tail = (table->tail + 1) % table->capacity;
      table->count--;
    }

  table->max_size = max_size;
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

uint64_t
SocketQPACK_Table_insert_count (SocketQPACK_Table_T table)
{
  assert (table != NULL);
  return table->insert_count;
}

SocketQPACK_Result
SocketQPACK_Table_get (SocketQPACK_Table_T table,
                       size_t index,
                       SocketQPACK_Header *header)
{
  size_t actual_index;
  SocketQPACK_DynamicEntry *entry;

  assert (table != NULL);
  assert (header != NULL);

  if (index == 0 || index > table->count)
    return QPACK_ERROR_INVALID_INDEX;

  /* Convert 1-based index to actual ring buffer position */
  /* Index 1 = most recent (head - 1), index count = oldest (tail) */
  actual_index = (table->head + table->capacity - index) % table->capacity;
  entry = &table->entries[actual_index];

  header->name = entry->name;
  header->name_len = entry->name_len;
  header->value = entry->value;
  header->value_len = entry->value_len;
  header->never_index = 0;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_Table_add (SocketQPACK_Table_T table,
                       const char *name,
                       size_t name_len,
                       const char *value,
                       size_t value_len)
{
  size_t entry_size;
  SocketQPACK_DynamicEntry *entry;

  assert (table != NULL);

  entry_size = qpack_entry_size (name_len, value_len);
  if (entry_size == SIZE_MAX)
    return QPACK_ERROR;

  /* Check if entry fits in table at all */
  if (entry_size > table->max_size)
    {
      /* Entry too large - clear table and return OK per RFC */
      while (table->count > 0)
        {
          SocketQPACK_DynamicEntry *old = &table->entries[table->tail];
          size_t old_size = qpack_entry_size (old->name_len, old->value_len);
          if (old_size != SIZE_MAX && old_size <= table->size)
            table->size -= old_size;
          table->tail = (table->tail + 1) % table->capacity;
          table->count--;
        }
      table->size = 0;
      table->insert_count++;
      return QPACK_OK;
    }

  /* Evict entries to make room */
  while (table->size + entry_size > table->max_size && table->count > 0)
    {
      SocketQPACK_DynamicEntry *old = &table->entries[table->tail];
      size_t old_size = qpack_entry_size (old->name_len, old->value_len);
      if (old_size != SIZE_MAX && old_size <= table->size)
        table->size -= old_size;
      table->tail = (table->tail + 1) % table->capacity;
      table->count--;
    }

  /* Check capacity */
  if (table->capacity == 0)
    return QPACK_ERROR;

  if (table->count >= table->capacity)
    {
      /* Table full - evict oldest */
      SocketQPACK_DynamicEntry *old = &table->entries[table->tail];
      size_t old_size = qpack_entry_size (old->name_len, old->value_len);
      if (old_size != SIZE_MAX && old_size <= table->size)
        table->size -= old_size;
      table->tail = (table->tail + 1) % table->capacity;
      table->count--;
    }

  /* Insert new entry at head */
  entry = &table->entries[table->head];

  /* Copy name */
  entry->name = ALLOC (table->arena, name_len + 1);
  if (entry->name == NULL)
    return QPACK_ERROR;
  memcpy (entry->name, name, name_len);
  entry->name[name_len] = '\0';
  entry->name_len = name_len;

  /* Copy value */
  entry->value = ALLOC (table->arena, value_len + 1);
  if (entry->value == NULL)
    return QPACK_ERROR;
  memcpy (entry->value, value, value_len);
  entry->value[value_len] = '\0';
  entry->value_len = value_len;

  entry->ref_count = 0;
  entry->refs = NULL;

  table->head = (table->head + 1) % table->capacity;
  table->count++;
  table->size += entry_size;
  table->insert_count++;

  return QPACK_OK;
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
  config->max_blocked_streams = SOCKETQPACK_MAX_BLOCKED_STREAMS;
  config->max_header_size = 8 * 1024;       /* 8KB per header */
  config->max_header_list_size = 64 * 1024; /* 64KB total */
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
  if (decoder == NULL)
    return NULL;

  decoder->table = SocketQPACK_Table_new (config->max_table_size, arena);
  if (decoder->table == NULL)
    return NULL;

  decoder->max_table_size = config->max_table_size;
  decoder->max_blocked_streams = config->max_blocked_streams;
  decoder->max_header_size = config->max_header_size;
  decoder->max_header_list_size = config->max_header_list_size;
  decoder->arena = arena;

  /* Initialize stream reference hash table */
  for (size_t i = 0; i < QPACK_STREAM_REF_HASH_SIZE; i++)
    decoder->stream_refs[i] = NULL;

  return decoder;
}

void
SocketQPACK_Decoder_free (SocketQPACK_Decoder_T *decoder)
{
  if (decoder == NULL || *decoder == NULL)
    return;

  SocketQPACK_Table_free (&(*decoder)->table);
  /* Arena handles all other memory */
  *decoder = NULL;
}

SocketQPACK_Table_T
SocketQPACK_Decoder_get_table (SocketQPACK_Decoder_T decoder)
{
  assert (decoder != NULL);
  return decoder->table;
}

/* ============================================================================
 * Stream Reference Tracking
 * ============================================================================
 */

/**
 * Find or create stream reference entry.
 */
static SocketQPACK_StreamRef *
find_or_create_stream_ref (SocketQPACK_Decoder_T decoder, uint64_t stream_id)
{
  size_t hash = qpack_stream_hash (stream_id);
  SocketQPACK_StreamRef *ref = decoder->stream_refs[hash];

  /* Search existing entries */
  while (ref != NULL)
    {
      if (ref->stream_id == stream_id)
        return ref;
      ref = ref->next;
    }

  /* Create new entry */
  ref = ALLOC (decoder->arena, sizeof (*ref));
  if (ref == NULL)
    return NULL;

  ref->stream_id = stream_id;
  ref->entry_capacity = QPACK_INITIAL_ENTRY_CAPACITY;
  ref->entry_indices
      = ALLOC (decoder->arena, ref->entry_capacity * sizeof (int));
  if (ref->entry_indices == NULL)
    return NULL;

  ref->entry_count = 0;
  ref->next = decoder->stream_refs[hash];
  decoder->stream_refs[hash] = ref;

  return ref;
}

/**
 * Find stream reference entry (no create).
 */
static SocketQPACK_StreamRef *
find_stream_ref (SocketQPACK_Decoder_T decoder, uint64_t stream_id)
{
  size_t hash = qpack_stream_hash (stream_id);
  SocketQPACK_StreamRef *ref = decoder->stream_refs[hash];

  while (ref != NULL)
    {
      if (ref->stream_id == stream_id)
        return ref;
      ref = ref->next;
    }

  return NULL;
}

/**
 * Remove stream reference from hash table.
 */
static void
remove_stream_ref (SocketQPACK_Decoder_T decoder, uint64_t stream_id)
{
  size_t hash = qpack_stream_hash (stream_id);
  SocketQPACK_StreamRef **prev = &decoder->stream_refs[hash];
  SocketQPACK_StreamRef *ref = *prev;

  while (ref != NULL)
    {
      if (ref->stream_id == stream_id)
        {
          *prev = ref->next;
          /* Memory freed by arena */
          return;
        }
      prev = &ref->next;
      ref = ref->next;
    }
}

SocketQPACK_Result
SocketQPACK_add_stream_reference (SocketQPACK_Decoder_T decoder,
                                  uint64_t stream_id,
                                  size_t entry_index)
{
  SocketQPACK_StreamRef *ref;
  SocketQPACK_DynamicEntry *entry;
  SocketQPACK_EntryRef *entry_ref;
  size_t actual_index;

  assert (decoder != NULL);

  if (entry_index == 0 || entry_index > decoder->table->count)
    return QPACK_ERROR_INVALID_INDEX;

  /* Find or create stream reference tracking */
  ref = find_or_create_stream_ref (decoder, stream_id);
  if (ref == NULL)
    return QPACK_ERROR;

  /* Grow entry_indices array if needed */
  if (ref->entry_count >= ref->entry_capacity)
    {
      size_t new_capacity = ref->entry_capacity * 2;
      int *new_indices = ALLOC (decoder->arena, new_capacity * sizeof (int));
      if (new_indices == NULL)
        return QPACK_ERROR;
      memcpy (new_indices, ref->entry_indices, ref->entry_count * sizeof (int));
      ref->entry_indices = new_indices;
      ref->entry_capacity = new_capacity;
    }

  /* Add entry index to stream's list */
  ref->entry_indices[ref->entry_count++] = (int)entry_index;

  /* Update entry's reference count and list */
  actual_index = (decoder->table->head + decoder->table->capacity - entry_index)
                 % decoder->table->capacity;
  entry = &decoder->table->entries[actual_index];
  entry->ref_count++;

  /* Add stream to entry's reference list */
  entry_ref = ALLOC (decoder->arena, sizeof (*entry_ref));
  if (entry_ref == NULL)
    return QPACK_ERROR;

  entry_ref->stream_id = stream_id;
  entry_ref->next = entry->refs;
  entry->refs = entry_ref;

  return QPACK_OK;
}

/* ============================================================================
 * Stream Cancellation (RFC 9204 Section 4.4.2)
 * ============================================================================
 */

int
SocketQPACK_is_stream_cancel_instruction (unsigned char byte)
{
  return (byte & QPACK_DECODER_STREAM_CANCEL_MASK)
         == QPACK_DECODER_STREAM_CANCEL_VAL;
}

SocketQPACK_Result
SocketQPACK_stream_cancel_validate_id (uint64_t stream_id)
{
  /* Stream ID 0 is reserved for the connection itself (not a request stream) */
  /* In HTTP/3, request streams are client-initiated bidirectional streams
   * which have IDs like 0, 4, 8, 12, etc. (multiples of 4).
   * However, stream ID 0 itself is a valid HTTP/3 request stream.
   * For QPACK stream cancellation, we allow any stream ID > 0 for safety,
   * but the actual validation may be context-dependent. */

  /* Per the issue specification: stream ID 0 is reserved for connection */
  /* We'll validate that stream_id is not 0 */
  if (stream_id == 0)
    return QPACK_ERROR_STREAM_ID;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_stream_cancel_release_refs (SocketQPACK_Decoder_T decoder,
                                        uint64_t stream_id)
{
  SocketQPACK_StreamRef *ref;

  assert (decoder != NULL);

  /* Find stream's references */
  ref = find_stream_ref (decoder, stream_id);
  if (ref == NULL)
    {
      /* Stream not found in tracking - this is OK per RFC, just warn */
      /* The stream may have never referenced any dynamic table entries,
       * or it was already cleaned up. This is not an error. */
      return QPACK_OK;
    }

  /* Release each entry reference */
  for (int i = 0; i < ref->entry_count; i++)
    {
      size_t entry_index = (size_t)ref->entry_indices[i];
      size_t actual_index;
      SocketQPACK_DynamicEntry *entry;
      SocketQPACK_EntryRef **prev_ref;
      SocketQPACK_EntryRef *entry_ref;

      /* Validate entry index is still valid */
      if (entry_index == 0 || entry_index > decoder->table->count)
        continue;

      actual_index
          = (decoder->table->head + decoder->table->capacity - entry_index)
            % decoder->table->capacity;
      entry = &decoder->table->entries[actual_index];

      /* Decrement reference count */
      if (entry->ref_count > 0)
        entry->ref_count--;

      /* Remove this stream from entry's reference list */
      prev_ref = &entry->refs;
      entry_ref = entry->refs;
      while (entry_ref != NULL)
        {
          if (entry_ref->stream_id == stream_id)
            {
              *prev_ref = entry_ref->next;
              /* Memory freed by arena */
              break;
            }
          prev_ref = &entry_ref->next;
          entry_ref = entry_ref->next;
        }
    }

  /* Remove stream from hash table */
  remove_stream_ref (decoder, stream_id);

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_decode_stream_cancel (SocketQPACK_Decoder_T decoder,
                                  const unsigned char *input,
                                  size_t input_len,
                                  size_t *consumed,
                                  uint64_t *stream_id)
{
  uint64_t id;
  size_t bytes_consumed;
  SocketQPACK_Result result;

  assert (decoder != NULL);
  assert (consumed != NULL);
  assert (stream_id != NULL);

  if (input == NULL || input_len == 0)
    return QPACK_INCOMPLETE;

  /* Verify this is a Stream Cancellation instruction */
  if (!SocketQPACK_is_stream_cancel_instruction (input[0]))
    return QPACK_ERROR_DECODER_STREAM;

  /* Decode stream ID with 6-bit prefix */
  result = SocketQPACK_int_decode (input,
                                   input_len,
                                   QPACK_DECODER_STREAM_CANCEL_PREFIX,
                                   &id,
                                   &bytes_consumed);
  if (result != QPACK_OK)
    return result;

  /* Validate stream ID */
  result = SocketQPACK_stream_cancel_validate_id (id);
  if (result != QPACK_OK)
    return result;

  /* Release all references for this stream */
  result = SocketQPACK_stream_cancel_release_refs (decoder, id);
  if (result != QPACK_OK)
    return result;

  *consumed = bytes_consumed;
  *stream_id = id;

  return QPACK_OK;
}
