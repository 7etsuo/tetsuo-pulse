/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-capacity.c
 * @brief QPACK Set Dynamic Table Capacity instruction (RFC 9204 Section 4.3.1)
 *
 * Implements encoding, decoding, and application of the Set Dynamic Table
 * Capacity instruction for QPACK encoder stream.
 *
 * Wire format (RFC 9204 Section 4.3.1):
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 | 1 |   Capacity (5+)   |
 * +---+---+---+-------------------+
 *
 * The instruction uses a 3-bit pattern 001 (0x20 mask) with a 5-bit prefix
 * integer encoding as per RFC 7541 Section 5.1.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-4.3.1
 */

#include <string.h>

#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"

#include "core/SocketUtil.h"
#include "http/SocketHPACK.h"

/* ============================================================================
 * CONSTANTS
 * ============================================================================
 */

/** Set Dynamic Table Capacity instruction mask (bits 7-5 = 001) */
#define SET_CAPACITY_MASK 0x20

/** Set Dynamic Table Capacity instruction pattern (for verification) */
#define SET_CAPACITY_PATTERN 0x20

/** Set Dynamic Table Capacity prefix bits (5-bit integer) */
#define SET_CAPACITY_PREFIX 5

/* ============================================================================
 * ENCODE SET CAPACITY
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_encode_set_capacity (uint64_t capacity,
                                 unsigned char *output,
                                 size_t output_size,
                                 size_t *written)
{
  size_t encoded_len;

  /* Validate parameters */
  if (output == NULL || written == NULL)
    return QPACK_ERR_NULL_PARAM;

  if (output_size == 0)
    return QPACK_ERR_TABLE_SIZE;

  /*
   * RFC 9204 Section 4.3.1:
   * The Set Dynamic Table Capacity instruction begins with the '001' three-bit
   * pattern. The instruction uses a 5-bit prefix integer to represent the
   * capacity.
   */
  encoded_len = SocketHPACK_int_encode (
      capacity, SET_CAPACITY_PREFIX, output, output_size);

  if (encoded_len == 0)
    return QPACK_ERR_TABLE_SIZE;

  /* Set the 3-bit pattern 001 in bits 7-5 of the first byte */
  output[0] = (output[0] & 0x1F) | SET_CAPACITY_MASK;

  *written = encoded_len;
  return QPACK_OK;
}

/* ============================================================================
 * DECODE SET CAPACITY
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_decode_set_capacity (const unsigned char *input,
                                 size_t input_len,
                                 uint64_t *capacity,
                                 size_t *consumed)
{
  SocketHPACK_Result hpack_result;

  /* Validate parameters */
  if (capacity == NULL || consumed == NULL)
    return QPACK_ERR_NULL_PARAM;

  /* Initialize outputs */
  *capacity = 0;
  *consumed = 0;

  /* Need at least one byte to check instruction type */
  if (input_len == 0)
    return QPACK_INCOMPLETE;

  if (input == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * RFC 9204 Section 4.3.1:
   * Verify the instruction pattern. The first byte must have bits 7-5 = 001.
   * The mask 0xE0 extracts bits 7-5, which should equal 0x20.
   */
  if ((input[0] & 0xE0) != SET_CAPACITY_PATTERN)
    return QPACK_ERR_INTEGER;

  /*
   * Decode the 5-bit prefix integer starting from the lower 5 bits of
   * the first byte. Uses HPACK integer decoding (RFC 7541 Section 5.1).
   */
  hpack_result = SocketHPACK_int_decode (
      input, input_len, SET_CAPACITY_PREFIX, capacity, consumed);

  if (hpack_result == HPACK_INCOMPLETE)
    return QPACK_INCOMPLETE;

  if (hpack_result != HPACK_OK)
    return QPACK_ERR_INTEGER;

  return QPACK_OK;
}

/* ============================================================================
 * APPLY SET CAPACITY
 * ============================================================================
 */

/**
 * @brief Evict oldest entry from the dynamic table.
 * @internal
 *
 * Removes the entry at the head of the ring buffer (oldest entry)
 * and updates table metadata accordingly.
 *
 * @param table Dynamic table to evict from
 */
static void
evict_oldest_entry (SocketQPACK_Table_T table)
{
  QPACK_DynamicEntry *entry;
  size_t entry_size;

  if (table->count == 0)
    return;

  /* Get the oldest entry (at head) */
  entry = &table->entries[table->head];

  /* Calculate entry size per RFC 9204 Section 3.2.1 */
  entry_size = qpack_entry_size (entry->name_len, entry->value_len);
  if (entry_size == SIZE_MAX)
    entry_size = 0;

  /* Update table size */
  if (table->size >= entry_size)
    table->size -= entry_size;
  else
    table->size = 0;

  /* Clear entry (arena will handle memory cleanup) */
  entry->name = NULL;
  entry->name_len = 0;
  entry->value = NULL;
  entry->value_len = 0;
  entry->meta.abs_index = 0;
  entry->meta.insert_count = 0;
  entry->meta.ref_count = 0;

  /* Advance head using ring buffer wrap */
  table->head = RINGBUF_WRAP (table->head + 1, table->capacity);
  table->count--;
  table->dropped_count++;
}

bool
SocketQPACK_can_reduce_capacity (SocketQPACK_Table_T table,
                                 uint64_t new_capacity)
{
  size_t bytes_to_evict = 0;
  size_t idx;
  size_t checked = 0;

  /*
   * RFC 9204 Section 2.1.1 & 4.3.1 (fixes #3481):
   * Check if capacity reduction is safe before sending the instruction.
   *
   * The encoder MUST NOT cause a dynamic table entry to be evicted unless
   * that entry is evictable. This function pre-checks whether all entries
   * that would need to be evicted have ref_count == 0.
   */
  if (table == NULL)
    return true; /* No table means no eviction needed */

  /* If new capacity >= current size, no eviction needed */
  if (new_capacity >= table->size)
    return true;

  /* Walk entries from oldest (head) to check if eviction is possible */
  idx = table->head;
  while (checked < table->count && table->size - bytes_to_evict > new_capacity)
    {
      QPACK_DynamicEntry *entry = &table->entries[idx];
      size_t entry_size;

      /* Cannot evict entries with outstanding references */
      if (entry->meta.ref_count > 0)
        return false;

      entry_size = qpack_entry_size (entry->name_len, entry->value_len);
      if (entry_size == SIZE_MAX)
        entry_size = 0;

      bytes_to_evict += entry_size;
      idx = RINGBUF_WRAP (idx + 1, table->capacity);
      checked++;
    }

  return true;
}

SocketQPACK_Result
SocketQPACK_apply_set_capacity (SocketQPACK_Table_T table,
                                uint64_t capacity,
                                uint64_t max_capacity)
{
  /* Validate parameters */
  if (table == NULL)
    return QPACK_ERR_NULL_PARAM;

  /*
   * RFC 9204 Section 4.3.1:
   * "The new capacity MUST NOT exceed the limit provided in
   * SETTINGS_QPACK_MAX_TABLE_CAPACITY."
   *
   * Exceeding this limit is a connection error of type
   * QPACK_ENCODER_STREAM_ERROR.
   */
  if (capacity > max_capacity)
    return QPACK_ERR_TABLE_SIZE;

  /*
   * RFC 9204 Section 4.3.1:
   * "Reducing the capacity of the dynamic table can cause entries to be
   * evicted."
   *
   * RFC 9204 Section 2.1.1:
   * "This MUST NOT cause the eviction of entries that are not evictable."
   * Entries are not evictable while they are referenced by unacknowledged
   * field sections.
   *
   * Evict entries in FIFO order (oldest first) until size <= new capacity.
   */
  while (table->count > 0 && table->size > capacity)
    {
      QPACK_DynamicEntry *oldest = &table->entries[table->head];

      /* Cannot evict entries still referenced by unacknowledged field sections */
      if (oldest->meta.ref_count > 0)
        return QPACK_ERR_TABLE_SIZE;

      evict_oldest_entry (table);
    }

  /* Update the maximum size limit */
  table->max_size = (size_t)capacity;

  return QPACK_OK;
}
