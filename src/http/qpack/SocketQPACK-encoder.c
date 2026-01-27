/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-encoder.c
 * @brief QPACK Insert with Literal Name (RFC 9204 Section 4.3.3)
 *
 * Implements encoding and decoding for the Insert with Literal Name instruction
 * used in QPACK encoder stream. This instruction inserts a new entry with both
 * name and value provided as string literals.
 *
 * Wire format (RFC 9204 Section 4.3.3):
 *
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 1 | H | Name Length (5+)  |
 * +---+---+---+-------------------+
 * |  Name String (Length bytes)   |
 * +---+---------------------------+
 * | H |     Value Length (7+)     |
 * +---+---------------------------+
 * |  Value String (Length bytes)  |
 * +-------------------------------+
 *
 * Bit pattern: 01Hxxxxx
 * H bit indicates if name/value is Huffman-encoded
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-4.3.3
 */

#include <string.h>

#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"
#include "http/qpack/SocketQPACKDecoderStream.h"
#include "http/qpack/SocketQPACKEncoderStream.h"

#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketHPACK.h"

/* ============================================================================
 * INTERNAL CONSTANTS
 * ============================================================================
 */

/** Insert with Literal Name instruction mask: 01xxxxxx */
#define QPACK_INSERT_LITERAL_MASK 0x40

/** Huffman flag bit in name length byte (bit 5) */
#define QPACK_NAME_HUFFMAN_FLAG 0x20

/** Name length prefix size in bits */
#define QPACK_NAME_LENGTH_PREFIX 5

/** Huffman flag bit in value length byte (bit 7) */
#define QPACK_VALUE_HUFFMAN_FLAG 0x80

/** Value length prefix size in bits */
#define QPACK_VALUE_LENGTH_PREFIX 7

/** Maximum integer encoding buffer size */
#define QPACK_INT_ENCODE_BUF_SIZE 16

/* ============================================================================
 * DYNAMIC TABLE INSERTION (INTERNAL)
 * ============================================================================
 */

/**
 * @brief Insert entry with literal name into dynamic table.
 *
 * RFC 9204 Section 3.2.1: Adds a new entry to the dynamic table. The entry
 * is assigned the next absolute index (equal to Insert Count before insertion).
 * Eviction of older entries may occur if table capacity is exceeded.
 *
 * @param table      Dynamic table
 * @param name       Field name (must not be NULL if name_len > 0)
 * @param name_len   Length of name string
 * @param value      Field value (must not be NULL if value_len > 0)
 * @param value_len  Length of value string
 * @return QPACK_OK on success, error code on failure
 *
 * @internal
 */
static SocketQPACK_Result
qpack_insert_literal_to_table (SocketQPACK_Table_T table,
                               const char *name,
                               size_t name_len,
                               const char *value,
                               size_t value_len)
{
  size_t entry_size;
  size_t slot;
  QPACK_DynamicEntry *entry;

  if (table == NULL)
    return QPACK_ERR_NULL_PARAM;

  if ((name == NULL && name_len > 0) || (value == NULL && value_len > 0))
    return QPACK_ERR_NULL_PARAM;

  /* Calculate entry size: name + value + 32 bytes overhead */
  entry_size = qpack_entry_size (name_len, value_len);
  if (entry_size == SIZE_MAX)
    return QPACK_ERR_TABLE_SIZE; /* Overflow */

  /* If entry is larger than max table size, clear table and return */
  if (entry_size > table->max_size)
    {
      table->head = 0;
      table->tail = 0;
      table->count = 0;
      table->size = 0;
      /* Don't increment insert_count - entry wasn't actually inserted */
      return QPACK_OK;
    }

  /* Evict oldest entries to make room */
  while (table->count > 0 && table->size + entry_size > table->max_size)
    {
      QPACK_DynamicEntry *oldest = &table->entries[table->head];
      size_t oldest_size
          = qpack_entry_size (oldest->name_len, oldest->value_len);

      if (oldest_size > table->size)
        {
          /* Corruption detected - reset table */
          table->head = 0;
          table->tail = 0;
          table->count = 0;
          table->size = 0;
          break;
        }

      table->size -= oldest_size;
      table->head = RINGBUF_WRAP (table->head + 1, table->capacity);
      table->count--;
      table->dropped_count++;
    }

  /* Insert new entry at tail */
  slot = table->tail;
  entry = &table->entries[slot];

  /* Copy name */
  if (name_len > 0)
    {
      entry->name = ALLOC (table->arena, name_len + 1);
      if (entry->name == NULL)
        return QPACK_ERR_INTERNAL;
      memcpy (entry->name, name, name_len);
      entry->name[name_len] = '\0';
    }
  else
    {
      entry->name = ALLOC (table->arena, 1);
      if (entry->name == NULL)
        return QPACK_ERR_INTERNAL;
      entry->name[0] = '\0';
    }
  entry->name_len = name_len;

  /* Copy value */
  if (value_len > 0)
    {
      entry->value = ALLOC (table->arena, value_len + 1);
      if (entry->value == NULL)
        return QPACK_ERR_INTERNAL;
      memcpy (entry->value, value, value_len);
      entry->value[value_len] = '\0';
    }
  else
    {
      entry->value = ALLOC (table->arena, 1);
      if (entry->value == NULL)
        return QPACK_ERR_INTERNAL;
      entry->value[0] = '\0';
    }
  entry->value_len = value_len;

  /* Set metadata */
  entry->meta.abs_index = table->insert_count;
  entry->meta.insert_count = table->insert_count + 1;
  entry->meta.ref_count = 0;

  /* Update table state */
  table->tail = RINGBUF_WRAP (table->tail + 1, table->capacity);
  table->count++;
  table->size += entry_size;
  table->insert_count++;

  return QPACK_OK;
}

/* ============================================================================
 * ENCODE INSERT WITH LITERAL NAME (RFC 9204 Section 4.3.3)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_encode_insert_literal_name (unsigned char *buf,
                                        size_t buf_size,
                                        const unsigned char *name,
                                        size_t name_len,
                                        bool name_huffman,
                                        const unsigned char *value,
                                        size_t value_len,
                                        bool value_huffman,
                                        size_t *bytes_written)
{
  size_t offset = 0;
  size_t name_encoded_len;
  size_t value_encoded_len;
  bool actually_huffman_name = false;
  bool actually_huffman_value = false;
  size_t prefix_len;

  if (buf == NULL || bytes_written == NULL)
    return QPACK_ERR_NULL_PARAM;

  if ((name == NULL && name_len > 0) || (value == NULL && value_len > 0))
    return QPACK_ERR_NULL_PARAM;

  *bytes_written = 0;

  /* Determine if Huffman encoding is beneficial for name */
  if (name_huffman && name_len > 0)
    {
      name_encoded_len = SocketHPACK_huffman_encoded_size (name, name_len);
      if (name_encoded_len < name_len)
        actually_huffman_name = true;
      else
        name_encoded_len = name_len;
    }
  else
    {
      name_encoded_len = name_len;
    }

  /* Determine if Huffman encoding is beneficial for value */
  if (value_huffman && value_len > 0)
    {
      value_encoded_len = SocketHPACK_huffman_encoded_size (value, value_len);
      if (value_encoded_len < value_len)
        actually_huffman_value = true;
      else
        value_encoded_len = value_len;
    }
  else
    {
      value_encoded_len = value_len;
    }

  /*
   * Encode name length with 5-bit prefix
   * First byte: 01 | H | name_length[4:0]
   */
  if (offset >= buf_size)
    return QPACK_ERR_DECOMPRESSION; /* Buffer too small */

  prefix_len = SocketHPACK_int_encode (name_encoded_len,
                                       QPACK_NAME_LENGTH_PREFIX,
                                       buf + offset,
                                       buf_size - offset);
  if (prefix_len == 0)
    return QPACK_ERR_INTEGER;

  /* Set instruction prefix and Huffman flag */
  buf[offset] |= QPACK_INSERT_LITERAL_MASK; /* 01xxxxxx */
  if (actually_huffman_name)
    buf[offset] |= QPACK_NAME_HUFFMAN_FLAG; /* H bit */

  offset += prefix_len;

  /* Encode name string */
  if (actually_huffman_name)
    {
      if (offset + name_encoded_len > buf_size)
        return QPACK_ERR_DECOMPRESSION;
      ssize_t huff_result = SocketHPACK_huffman_encode (
          name, name_len, buf + offset, buf_size - offset);
      if (huff_result < 0)
        return QPACK_ERR_HUFFMAN;
      offset += (size_t)huff_result;
    }
  else
    {
      if (offset + name_len > buf_size)
        return QPACK_ERR_DECOMPRESSION;
      if (name_len > 0)
        memcpy (buf + offset, name, name_len);
      offset += name_len;
    }

  /*
   * Encode value length with 7-bit prefix
   * Byte: H | value_length[6:0]
   */
  prefix_len = SocketHPACK_int_encode (value_encoded_len,
                                       QPACK_VALUE_LENGTH_PREFIX,
                                       buf + offset,
                                       buf_size - offset);
  if (prefix_len == 0)
    return QPACK_ERR_INTEGER;

  if (actually_huffman_value)
    buf[offset] |= QPACK_VALUE_HUFFMAN_FLAG;

  offset += prefix_len;

  /* Encode value string */
  if (actually_huffman_value)
    {
      if (offset + value_encoded_len > buf_size)
        return QPACK_ERR_DECOMPRESSION;
      ssize_t huff_result = SocketHPACK_huffman_encode (
          value, value_len, buf + offset, buf_size - offset);
      if (huff_result < 0)
        return QPACK_ERR_HUFFMAN;
      offset += (size_t)huff_result;
    }
  else
    {
      if (offset + value_len > buf_size)
        return QPACK_ERR_DECOMPRESSION;
      if (value_len > 0)
        memcpy (buf + offset, value, value_len);
      offset += value_len;
    }

  *bytes_written = offset;
  return QPACK_OK;
}

/* ============================================================================
 * DECODE INSERT WITH LITERAL NAME (RFC 9204 Section 4.3.3)
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_decode_insert_literal_name (const unsigned char *buf,
                                        size_t buf_len,
                                        SocketQPACK_Table_T table,
                                        unsigned char *name_out,
                                        size_t name_out_size,
                                        size_t *name_len_out,
                                        unsigned char *value_out,
                                        size_t value_out_size,
                                        size_t *value_len_out,
                                        size_t *bytes_consumed)
{
  size_t offset = 0;
  uint64_t name_len;
  uint64_t value_len;
  size_t consumed;
  bool name_huffman;
  bool value_huffman;
  SocketHPACK_Result hpack_result;
  SocketQPACK_Result qpack_result;

  if (buf == NULL || bytes_consumed == NULL)
    return QPACK_ERR_NULL_PARAM;

  if (name_out == NULL || value_out == NULL)
    return QPACK_ERR_NULL_PARAM;

  if (name_len_out == NULL || value_len_out == NULL)
    return QPACK_ERR_NULL_PARAM;

  *bytes_consumed = 0;
  *name_len_out = 0;
  *value_len_out = 0;

  if (buf_len == 0)
    return QPACK_INCOMPLETE;

  /* Verify instruction type: 01xxxxxx */
  if ((buf[0] & 0xC0) != QPACK_INSERT_LITERAL_MASK)
    return QPACK_ERR_INTERNAL; /* Not an Insert with Literal Name instruction */

  /* Extract Huffman flag for name (bit 5) */
  name_huffman = (buf[0] & QPACK_NAME_HUFFMAN_FLAG) != 0;

  /* Decode name length with 5-bit prefix */
  hpack_result = SocketHPACK_int_decode (buf + offset,
                                         buf_len - offset,
                                         QPACK_NAME_LENGTH_PREFIX,
                                         &name_len,
                                         &consumed);
  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_INCOMPLETE;
  if (hpack_result != HPACK_OK)
    return QPACK_ERR_INTEGER;

  offset += consumed;

  /* Validate name length */
  if (offset + name_len > buf_len)
    return QPACK_INCOMPLETE;

  /* Decode name string */
  if (name_huffman)
    {
      ssize_t decoded_len = SocketHPACK_huffman_decode (
          buf + offset, (size_t)name_len, name_out, name_out_size);
      if (decoded_len < 0)
        return QPACK_ERR_HUFFMAN;
      *name_len_out = (size_t)decoded_len;
    }
  else
    {
      if (name_len > name_out_size)
        return QPACK_ERR_HEADER_SIZE;
      if (name_len > 0)
        memcpy (name_out, buf + offset, (size_t)name_len);
      *name_len_out = (size_t)name_len;
    }

  offset += (size_t)name_len;

  /* Need at least one more byte for value length */
  if (offset >= buf_len)
    return QPACK_INCOMPLETE;

  /* Extract Huffman flag for value (bit 7) */
  value_huffman = (buf[offset] & QPACK_VALUE_HUFFMAN_FLAG) != 0;

  /* Decode value length with 7-bit prefix */
  hpack_result = SocketHPACK_int_decode (buf + offset,
                                         buf_len - offset,
                                         QPACK_VALUE_LENGTH_PREFIX,
                                         &value_len,
                                         &consumed);
  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_INCOMPLETE;
  if (hpack_result != HPACK_OK)
    return QPACK_ERR_INTEGER;

  offset += consumed;

  /* Validate header value length against maximum (fixes #3474) */
  if (value_len > SOCKETQPACK_MAX_HEADER_VALUE_SIZE)
    return QPACK_ERR_HEADER_SIZE;

  /* Validate value length */
  if (offset + value_len > buf_len)
    return QPACK_INCOMPLETE;

  /* Decode value string */
  if (value_huffman)
    {
      ssize_t decoded_len = SocketHPACK_huffman_decode (
          buf + offset, (size_t)value_len, value_out, value_out_size);
      if (decoded_len < 0)
        return QPACK_ERR_HUFFMAN;
      *value_len_out = (size_t)decoded_len;
    }
  else
    {
      if (value_len > value_out_size)
        return QPACK_ERR_HEADER_SIZE;
      if (value_len > 0)
        memcpy (value_out, buf + offset, (size_t)value_len);
      *value_len_out = (size_t)value_len;
    }

  offset += (size_t)value_len;

  /* Insert into dynamic table if provided */
  if (table != NULL)
    {
      qpack_result = qpack_insert_literal_to_table (table,
                                                    (const char *)name_out,
                                                    *name_len_out,
                                                    (const char *)value_out,
                                                    *value_len_out);
      if (qpack_result != QPACK_OK)
        return qpack_result;
    }

  *bytes_consumed = offset;
  return QPACK_OK;
}

/* ============================================================================
 * DYNAMIC TABLE CREATION
 * ============================================================================
 */

SocketQPACK_Table_T
SocketQPACK_Table_new (Arena_T arena, size_t max_size)
{
  SocketQPACK_Table_T table;
  size_t capacity;

  if (arena == NULL)
    return NULL;

  table = CALLOC (arena, 1, sizeof (*table));
  if (table == NULL)
    return NULL;

  capacity = SocketQPACK_estimate_capacity (max_size);

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
  table->dropped_count = 0;
  table->known_received = 0;
  table->arena = arena;

  return table;
}

SocketQPACK_Result
SocketQPACK_Table_insert_literal (SocketQPACK_Table_T table,
                                  const char *name,
                                  size_t name_len,
                                  const char *value,
                                  size_t value_len)
{
  return qpack_insert_literal_to_table (
      table, name, name_len, value, value_len);
}

size_t
SocketQPACK_Table_size (SocketQPACK_Table_T table)
{
  if (table == NULL)
    return 0;
  return table->size;
}

size_t
SocketQPACK_Table_count (SocketQPACK_Table_T table)
{
  if (table == NULL)
    return 0;
  return table->count;
}

size_t
SocketQPACK_Table_max_size (SocketQPACK_Table_T table)
{
  if (table == NULL)
    return 0;
  return table->max_size;
}

uint64_t
SocketQPACK_Table_insert_count (SocketQPACK_Table_T table)
{
  if (table == NULL)
    return 0;
  return table->insert_count;
}

uint64_t
SocketQPACK_Table_dropped_count (SocketQPACK_Table_T table)
{
  if (table == NULL)
    return 0;
  return table->dropped_count;
}

void
SocketQPACK_Table_set_max_size (SocketQPACK_Table_T table, size_t max_size)
{
  if (table == NULL)
    return;

  if (max_size > SOCKETQPACK_MAX_TABLE_SIZE)
    max_size = SOCKETQPACK_MAX_TABLE_SIZE;

  table->max_size = max_size;

  /* Clear table if max_size is 0 */
  if (max_size == 0)
    {
      table->dropped_count += table->count;
      table->head = 0;
      table->tail = 0;
      table->count = 0;
      table->size = 0;
      return;
    }

  /* Evict entries if current size exceeds new max */
  while (table->count > 0 && table->size > max_size)
    {
      QPACK_DynamicEntry *oldest = &table->entries[table->head];
      size_t entry_size
          = qpack_entry_size (oldest->name_len, oldest->value_len);

      if (entry_size > table->size)
        {
          table->head = 0;
          table->tail = 0;
          table->count = 0;
          table->size = 0;
          break;
        }

      table->size -= entry_size;
      table->head = RINGBUF_WRAP (table->head + 1, table->capacity);
      table->count--;
      table->dropped_count++;
    }
}

SocketQPACK_Result
SocketQPACK_Table_get (SocketQPACK_Table_T table,
                       uint64_t abs_index,
                       const char **name,
                       size_t *name_len,
                       const char **value,
                       size_t *value_len)
{
  SocketQPACK_Result result;
  size_t ring_offset;
  size_t slot;
  QPACK_DynamicEntry *entry;

  if (table == NULL)
    return QPACK_ERR_NULL_PARAM;

  if (name == NULL || name_len == NULL || value == NULL || value_len == NULL)
    return QPACK_ERR_NULL_PARAM;

  /* Validate absolute index */
  result = SocketQPACK_is_valid_absolute (
      table->insert_count, table->dropped_count, abs_index);
  if (result != QPACK_OK)
    return result;

  /*
   * Convert absolute index to ring buffer slot.
   * abs_index ranges from [dropped_count, insert_count)
   * ring_offset = abs_index - dropped_count (position relative to head)
   * slot = (head + ring_offset) % capacity
   */
  ring_offset = (size_t)(abs_index - table->dropped_count);
  slot = RINGBUF_WRAP (table->head + ring_offset, table->capacity);

  entry = &table->entries[slot];
  *name = entry->name;
  *name_len = entry->name_len;
  *value = entry->value;
  *value_len = entry->value_len;

  return QPACK_OK;
}

/* ============================================================================
 * QPACK ENCODER (RFC 9204 Section 2.1.4)
 *
 * Encoder state management with Known Received Count tracking.
 * ============================================================================
 */

/**
 * @brief QPACK encoder internal structure.
 *
 * Bundles dynamic table with acknowledgment state for KRC tracking.
 */
struct SocketQPACK_Encoder
{
  Arena_T arena;                    /**< Memory arena for allocations */
  SocketQPACK_Table_T table;        /**< Dynamic table */
  SocketQPACK_AckState_T ack_state; /**< Acknowledgment state (KRC tracking) */
};

SocketQPACK_Encoder_T
SocketQPACK_Encoder_new (Arena_T arena, size_t max_table_size)
{
  SocketQPACK_Encoder_T encoder;

  if (arena == NULL)
    return NULL;

  encoder = CALLOC (arena, 1, sizeof (*encoder));
  if (encoder == NULL)
    return NULL;

  encoder->arena = arena;

  /* Create dynamic table */
  encoder->table = SocketQPACK_Table_new (arena, max_table_size);
  if (encoder->table == NULL)
    return NULL;

  /* Create acknowledgment state for KRC tracking */
  encoder->ack_state = SocketQPACK_AckState_new (arena);
  if (encoder->ack_state == NULL)
    return NULL;

  return encoder;
}

uint64_t
SocketQPACK_Encoder_known_received_count (SocketQPACK_Encoder_T encoder)
{
  if (encoder == NULL)
    return 0;

  return SocketQPACK_AckState_get_known_received_count (encoder->ack_state);
}

bool
SocketQPACK_Encoder_is_acknowledged (SocketQPACK_Encoder_T encoder,
                                      uint64_t absolute_index)
{
  uint64_t krc;

  if (encoder == NULL)
    return false;

  krc = SocketQPACK_AckState_get_known_received_count (encoder->ack_state);

  /*
   * RFC 9204 Section 2.1.4: Entry with absolute_index < KRC is safe
   * to reference in non-blocking representation.
   */
  return absolute_index < krc;
}

SocketQPACK_Result
SocketQPACK_Encoder_on_section_ack (SocketQPACK_Encoder_T encoder,
                                    uint64_t stream_id)
{
  SocketQPACKStream_Result result;
  uint64_t krc;

  if (encoder == NULL)
    return QPACK_ERR_NULL_PARAM;

  result = SocketQPACK_AckState_process_section_ack (
      encoder->ack_state, stream_id, encoder->table->insert_count);

  if (result == QPACK_STREAM_ERR_INVALID_INDEX)
    return QPACK_ERR_INVALID_INDEX;
  if (result != QPACK_STREAM_OK)
    return QPACK_ERR_INTERNAL;

  /* Sync table's known_received with ack_state's KRC */
  krc = SocketQPACK_AckState_get_known_received_count (encoder->ack_state);
  encoder->table->known_received = krc;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_Encoder_on_insert_count_inc (SocketQPACK_Encoder_T encoder,
                                         uint64_t increment)
{
  SocketQPACKStream_Result result;
  uint64_t krc;
  uint64_t insert_count;
  uint64_t new_krc;

  if (encoder == NULL)
    return QPACK_ERR_NULL_PARAM;

  if (increment == 0)
    return QPACK_ERR_INVALID_INDEX;

  /* Validate: new KRC cannot exceed insert_count */
  krc = SocketQPACK_AckState_get_known_received_count (encoder->ack_state);
  insert_count = encoder->table->insert_count;

  /* Check for overflow and bounds */
  if (!SocketSecurity_check_add (krc, increment, &new_krc))
    return QPACK_ERR_INVALID_INDEX; /* Overflow */

  if (new_krc > insert_count)
    return QPACK_ERR_INVALID_INDEX; /* Exceeds insert count */

  result
      = SocketQPACK_AckState_process_insert_count_inc (encoder->ack_state,
                                                        increment);
  if (result != QPACK_STREAM_OK)
    return QPACK_ERR_INTERNAL;

  /* Sync table's known_received with ack_state's KRC */
  krc = SocketQPACK_AckState_get_known_received_count (encoder->ack_state);
  encoder->table->known_received = krc;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_Encoder_on_stream_cancel (SocketQPACK_Encoder_T encoder,
                                      uint64_t stream_id)
{
  SocketQPACKStream_Result result;

  if (encoder == NULL)
    return QPACK_ERR_NULL_PARAM;

  result = SocketQPACK_AckState_process_stream_cancel (encoder->ack_state,
                                                        stream_id);
  if (result != QPACK_STREAM_OK)
    return QPACK_ERR_INTERNAL;

  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_Encoder_register_section (SocketQPACK_Encoder_T encoder,
                                      uint64_t stream_id,
                                      uint64_t required_insert_count)
{
  SocketQPACKStream_Result result;

  if (encoder == NULL)
    return QPACK_ERR_NULL_PARAM;

  result = SocketQPACK_AckState_register_section (encoder->ack_state,
                                                   stream_id,
                                                   required_insert_count);
  if (result == QPACK_STREAM_ERR_BUFFER_FULL)
    return QPACK_ERR_TABLE_SIZE;
  if (result != QPACK_STREAM_OK)
    return QPACK_ERR_INTERNAL;

  return QPACK_OK;
}

SocketQPACK_Table_T
SocketQPACK_Encoder_get_table (SocketQPACK_Encoder_T encoder)
{
  if (encoder == NULL)
    return NULL;

  return encoder->table;
}

uint64_t
SocketQPACK_Encoder_insert_count (SocketQPACK_Encoder_T encoder)
{
  if (encoder == NULL)
    return 0;

  return encoder->table->insert_count;
}
