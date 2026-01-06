/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK.c
 * @brief QPACK Header Compression (RFC 9204)
 *
 * Implements QPACK dynamic table and encoder instructions.
 * This file provides the Duplicate instruction (Section 4.3.4).
 */

#include <assert.h>
#include <string.h>

#include "quic/SocketQPACK.h"

#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"

#define T SocketQPACK_Table_T

/* ============================================================================
 * Constants
 * ============================================================================
 */

/** Minimum dynamic table entry capacity (power of 2 for ring buffer). */
#define QPACK_MIN_TABLE_CAPACITY 16

/** Average entry size estimate for capacity calculation. */
#define QPACK_AVERAGE_ENTRY_SIZE 50

/** Integer encoding max continuation bytes (same as HPACK). */
#define QPACK_INT_MAX_CONTINUATION 10

/** Maximum safe shift for integer decoding. */
#define QPACK_INT_MAX_SHIFT 56

/* Integer continuation masks */
#define QPACK_INT_CONTINUATION_MASK 0x80
#define QPACK_INT_PAYLOAD_MASK 0x7F
#define QPACK_INT_CONTINUATION_VALUE 128

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
  [QPACK_ERROR_INVALID_INDEX] = "Invalid relative index",
  [QPACK_ERROR_TABLE_FULL] = "Dynamic table capacity exhausted",
  [QPACK_ERROR_PARSE] = "Malformed wire format",
  [QPACK_ERROR_ENCODER_STREAM] = "Encoder stream error",
  [QPACK_ERROR_DECODER_STREAM] = "Decoder stream error",
};

const char *
SocketQPACK_result_string (SocketQPACK_Result result)
{
  if (result < 0 || result > QPACK_ERROR_DECODER_STREAM)
    return "Unknown error";
  return result_strings[result];
}

/* ============================================================================
 * Dynamic Table Structure
 * ============================================================================
 */

struct SocketQPACK_Table
{
  QPACK_DynamicEntry *entries; /**< Circular buffer of entries. */
  size_t capacity;             /**< Number of entry slots (power of 2). */
  size_t head;                 /**< Index of oldest entry. */
  size_t tail;                 /**< Index for next insertion. */
  size_t count;                /**< Current number of entries. */
  size_t size;                 /**< Current size in bytes. */
  size_t max_capacity;         /**< Maximum allowed size in bytes. */
  size_t insertion_count;      /**< Total entries ever inserted (abs index). */
  Arena_T arena;               /**< Memory arena for allocations. */
};

/* ============================================================================
 * Internal Helpers
 * ============================================================================
 */

size_t
SocketQPACK_entry_size (size_t name_len, size_t value_len)
{
  size_t temp;
  if (SocketSecurity_check_add (name_len, value_len, &temp)
      && SocketSecurity_check_add (temp, SOCKETQPACK_ENTRY_OVERHEAD, &temp))
    {
      return temp;
    }
  return SIZE_MAX;
}

static int
qpack_validate_table (const SocketQPACK_Table_T table, const char *func)
{
  if (table == NULL)
    return 0;
  (void)func;
  return 1;
}

static inline int
qpack_valid_prefix_bits (int prefix_bits)
{
  return prefix_bits >= 1 && prefix_bits <= 8;
}

/**
 * Calculate initial capacity (power-of-2) based on max size.
 */
static size_t
qpack_initial_capacity (size_t max_size)
{
  size_t est_entries;

  if (max_size == 0)
    return QPACK_MIN_TABLE_CAPACITY;

  est_entries = max_size / QPACK_AVERAGE_ENTRY_SIZE;
  if (est_entries < QPACK_MIN_TABLE_CAPACITY)
    est_entries = QPACK_MIN_TABLE_CAPACITY;

  /* Round up to power of 2 using compiler intrinsic */
  return NEXT_POW2_32 ((uint32_t)est_entries);
}

/**
 * Convert relative index to slot index in circular buffer.
 * Relative index 0 = newest (tail - 1), higher = older toward head.
 */
static inline size_t
qpack_rel_to_slot (const SocketQPACK_Table_T table, size_t rel_index)
{
  /* tail points to next insertion slot, so newest is at tail-1 */
  size_t offset = rel_index;
  return RINGBUF_WRAP (table->tail + table->capacity - 1 - offset,
                       table->capacity);
}

/**
 * Evict oldest entries until required_space can fit.
 */
static size_t
qpack_table_evict (SocketQPACK_Table_T table, size_t required_space)
{
  size_t evicted = 0;

  while (table->count > 0 && table->size + required_space > table->max_capacity)
    {
      QPACK_DynamicEntry *entry = &table->entries[table->head];
      size_t entry_size
          = SocketQPACK_entry_size (entry->name_len, entry->value_len);

      if (entry_size > table->size)
        {
          /* Corruption detected - reset table */
          table->size = 0;
          table->count = 0;
          return evicted;
        }

      table->size -= entry_size;
      table->head = RINGBUF_WRAP (table->head + 1, table->capacity);
      table->count--;
      evicted++;
    }

  return evicted;
}

/**
 * Clear the table without resetting insertion count.
 */
static void
qpack_table_clear (SocketQPACK_Table_T table)
{
  assert (table != NULL);
  table->head = 0;
  table->tail = 0;
  table->count = 0;
  table->size = 0;
  /* Note: insertion_count is NOT reset - absolute indices are monotonic */
}

/**
 * Duplicate string into arena.
 */
static char *
qpack_strdup (Arena_T arena, const char *str, size_t len)
{
  char *copy;

  if (str == NULL || len == 0)
    {
      copy = ALLOC (arena, 1);
      if (copy)
        copy[0] = '\0';
      return copy;
    }

  copy = ALLOC (arena, len + 1);
  if (copy == NULL)
    return NULL;

  memcpy (copy, str, len);
  copy[len] = '\0';
  return copy;
}

/* ============================================================================
 * Dynamic Table Implementation
 * ============================================================================
 */

SocketQPACK_Table_T
SocketQPACK_Table_new (size_t max_capacity, Arena_T arena)
{
  SocketQPACK_Table_T table;
  size_t initial_cap;

  assert (arena != NULL);

  table = ALLOC (arena, sizeof (*table));
  if (table == NULL)
    RAISE (SocketQPACK_Error);

  initial_cap = qpack_initial_capacity (max_capacity);

  table->entries = CALLOC (arena, initial_cap, sizeof (QPACK_DynamicEntry));
  if (table->entries == NULL)
    RAISE (SocketQPACK_Error);

  table->capacity = initial_cap;
  table->head = 0;
  table->tail = 0;
  table->count = 0;
  table->size = 0;
  table->max_capacity = max_capacity;
  table->insertion_count = 0;
  table->arena = arena;

  return table;
}

void
SocketQPACK_Table_free (SocketQPACK_Table_T *table)
{
  if (table == NULL || *table == NULL)
    return;
  /* Arena handles all memory - just NULL the pointer */
  *table = NULL;
}

size_t
SocketQPACK_Table_size (SocketQPACK_Table_T table)
{
  if (!qpack_validate_table (table, "Table_size"))
    return 0;
  return table->size;
}

size_t
SocketQPACK_Table_count (SocketQPACK_Table_T table)
{
  if (!qpack_validate_table (table, "Table_count"))
    return 0;
  return table->count;
}

size_t
SocketQPACK_Table_max_capacity (SocketQPACK_Table_T table)
{
  if (!qpack_validate_table (table, "Table_max_capacity"))
    return 0;
  return table->max_capacity;
}

size_t
SocketQPACK_Table_insertion_count (SocketQPACK_Table_T table)
{
  if (!qpack_validate_table (table, "Table_insertion_count"))
    return 0;
  return table->insertion_count;
}

void
SocketQPACK_Table_set_capacity (SocketQPACK_Table_T table, size_t max_capacity)
{
  if (!qpack_validate_table (table, "Table_set_capacity"))
    return;

  if (max_capacity > SOCKETQPACK_MAX_TABLE_CAPACITY)
    max_capacity = SOCKETQPACK_MAX_TABLE_CAPACITY;

  table->max_capacity = max_capacity;

  if (max_capacity == 0)
    qpack_table_clear (table);
  else
    qpack_table_evict (table, 0);
}

SocketQPACK_Result
SocketQPACK_Table_get (SocketQPACK_Table_T table,
                       size_t rel_index,
                       SocketQPACK_FieldLine *field_line)
{
  QPACK_DynamicEntry *entry;
  size_t slot;

  if (table == NULL || field_line == NULL)
    return QPACK_ERROR;

  if (rel_index >= table->count)
    return QPACK_ERROR_INVALID_INDEX;

  slot = qpack_rel_to_slot (table, rel_index);
  entry = &table->entries[slot];

  field_line->name = entry->name;
  field_line->name_len = entry->name_len;
  field_line->value = entry->value;
  field_line->value_len = entry->value_len;
  field_line->never_index = 0;

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
  QPACK_DynamicEntry *entry;

  if (table == NULL)
    return QPACK_ERROR;

  if ((name == NULL && name_len != 0) || (value == NULL && value_len != 0))
    return QPACK_ERROR;

  entry_size = SocketQPACK_entry_size (name_len, value_len);
  if (entry_size == SIZE_MAX)
    return QPACK_ERROR;

  /* If entry is larger than max capacity, clear table per RFC 9204 */
  if (entry_size > table->max_capacity)
    {
      qpack_table_clear (table);
      table->insertion_count++;
      return QPACK_OK;
    }

  /* Evict entries to make room */
  qpack_table_evict (table, entry_size);

  /* Insert at tail */
  entry = &table->entries[table->tail];
  entry->name = qpack_strdup (table->arena, name, name_len);
  entry->value = qpack_strdup (table->arena, value, value_len);

  if ((name_len > 0 && entry->name == NULL)
      || (value_len > 0 && entry->value == NULL))
    return QPACK_ERROR;

  entry->name_len = name_len;
  entry->value_len = value_len;
  entry->abs_index = table->insertion_count;

  table->tail = RINGBUF_WRAP (table->tail + 1, table->capacity);
  table->count++;
  table->size += entry_size;
  table->insertion_count++;

  return QPACK_OK;
}

/* ============================================================================
 * Integer Encoding (RFC 7541 Section 5.1, used by QPACK)
 * ============================================================================
 */

size_t
SocketQPACK_int_encode (uint64_t value,
                        int prefix_bits,
                        uint8_t *output,
                        size_t output_size)
{
  uint64_t max_prefix;
  size_t pos;

  if (output == NULL || output_size == 0
      || !qpack_valid_prefix_bits (prefix_bits))
    return 0;

  max_prefix = ((uint64_t)1 << prefix_bits) - 1;

  if (value < max_prefix)
    {
      output[0] = (uint8_t)value;
      return 1;
    }

  output[0] = (uint8_t)max_prefix;
  value -= max_prefix;
  pos = 1;

  while (value >= QPACK_INT_CONTINUATION_VALUE && pos < output_size)
    {
      output[pos++] = (uint8_t)(QPACK_INT_CONTINUATION_MASK
                                | (value & QPACK_INT_PAYLOAD_MASK));
      value >>= 7;
    }

  if (pos >= output_size)
    return 0;

  output[pos++] = (uint8_t)value;
  return pos;
}

SocketQPACK_Result
SocketQPACK_int_decode (const uint8_t *input,
                        size_t input_len,
                        int prefix_bits,
                        uint64_t *value,
                        size_t *consumed)
{
  size_t pos = 0;
  uint64_t max_prefix;
  uint64_t result;
  unsigned int shift = 0;
  unsigned int continuation_count = 0;

  if (input == NULL || value == NULL || consumed == NULL)
    return QPACK_ERROR;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  if (!qpack_valid_prefix_bits (prefix_bits))
    return QPACK_ERROR_PARSE;

  max_prefix = ((uint64_t)1 << prefix_bits) - 1;
  result = input[pos++] & max_prefix;

  if (result < max_prefix)
    {
      *value = result;
      *consumed = pos;
      return QPACK_OK;
    }

  /* Multi-byte encoding */
  do
    {
      if (pos >= input_len)
        return QPACK_INCOMPLETE;

      continuation_count++;
      if (continuation_count > QPACK_INT_MAX_CONTINUATION)
        return QPACK_ERROR_PARSE;

      uint8_t byte_val = input[pos++];

      if (shift > QPACK_INT_MAX_SHIFT)
        return QPACK_ERROR_PARSE;

      uint64_t add_val = (uint64_t)(byte_val & QPACK_INT_PAYLOAD_MASK) << shift;
      if (result > UINT64_MAX - add_val)
        return QPACK_ERROR_PARSE;

      result += add_val;
      shift += 7;

      if (!(byte_val & QPACK_INT_CONTINUATION_MASK))
        break;
    }
  while (1);

  *value = result;
  *consumed = pos;
  return QPACK_OK;
}

/* ============================================================================
 * Duplicate Instruction (RFC 9204 Section 4.3.4)
 * ============================================================================
 */

size_t
SocketQPACK_encode_duplicate (size_t rel_index,
                              uint8_t *output,
                              size_t output_size)
{
  uint8_t int_buf[16];
  size_t int_len;

  if (output == NULL || output_size == 0)
    return 0;

  /* Encode relative index with 5-bit prefix */
  int_len = SocketQPACK_int_encode (
      (uint64_t)rel_index, QPACK_DUPLICATE_PREFIX, int_buf, sizeof (int_buf));
  if (int_len == 0 || int_len > output_size)
    return 0;

  /* Apply the 3-bit pattern (000) to first byte */
  output[0] = (uint8_t)(QPACK_DUPLICATE_PATTERN | int_buf[0]);

  /* Copy continuation bytes if any */
  for (size_t i = 1; i < int_len; i++)
    output[i] = int_buf[i];

  return int_len;
}

SocketQPACK_Result
SocketQPACK_decode_duplicate (const uint8_t *input,
                              size_t input_len,
                              size_t *rel_index,
                              size_t *consumed)
{
  uint64_t value;
  SocketQPACK_Result result;

  if (input == NULL || rel_index == NULL || consumed == NULL)
    return QPACK_ERROR;

  if (input_len == 0)
    return QPACK_INCOMPLETE;

  /* Verify this is a duplicate instruction (top 3 bits = 000) */
  if ((input[0] & QPACK_DUPLICATE_MASK) != QPACK_DUPLICATE_PATTERN)
    return QPACK_ERROR_PARSE;

  /* Decode 5-bit prefix integer */
  result = SocketQPACK_int_decode (
      input, input_len, QPACK_DUPLICATE_PREFIX, &value, consumed);
  if (result != QPACK_OK)
    return result;

  /* Check for size_t overflow on 32-bit systems */
  if (value > SIZE_MAX)
    return QPACK_ERROR_PARSE;

  *rel_index = (size_t)value;
  return QPACK_OK;
}

SocketQPACK_Result
SocketQPACK_process_duplicate (SocketQPACK_Table_T table, size_t rel_index)
{
  SocketQPACK_FieldLine field_line;
  SocketQPACK_Result result;

  if (table == NULL)
    return QPACK_ERROR;

  /* Get the entry to duplicate */
  result = SocketQPACK_Table_get (table, rel_index, &field_line);
  if (result != QPACK_OK)
    return result;

  /* Insert a copy at the end of the table */
  result = SocketQPACK_Table_add (table,
                                  field_line.name,
                                  field_line.name_len,
                                  field_line.value,
                                  field_line.value_len);

  return result;
}

#undef T
