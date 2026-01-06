/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketQPACK-table.c - QPACK Dynamic Table (RFC 9204 Section 3)
 *
 * Dynamic table implementation with FIFO eviction, absolute indexing,
 * and insert count tracking for QPACK.
 */

#include <assert.h>
#include <string.h>

#include "http/SocketQPACK-private.h"
#include "http/SocketQPACK.h"

#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"

/* ============================================================================
 * Table Creation/Destruction
 * ============================================================================
 */

SocketQPACK_Table_T
SocketQPACK_Table_new (size_t max_size, Arena_T arena)
{
  SocketQPACK_Table_T table;
  size_t initial_capacity;

  assert (arena != NULL);

  table = ALLOC (arena, sizeof (*table));

  /* Calculate initial capacity based on expected average entry size */
  initial_capacity = max_size / QPACK_AVERAGE_DYNAMIC_ENTRY_SIZE;
  if (initial_capacity < QPACK_MIN_DYNAMIC_TABLE_CAPACITY)
    initial_capacity = QPACK_MIN_DYNAMIC_TABLE_CAPACITY;

  table->entries
      = CALLOC (arena, initial_capacity, sizeof (QPACK_DynamicEntry));
  table->capacity = initial_capacity;
  table->head = 0;
  table->tail = 0;
  table->count = 0;
  table->size = 0;
  table->max_size = max_size;
  table->insert_count = 0;
  table->base_absolute = 0;
  table->arena = arena;

  return table;
}

void
SocketQPACK_Table_free (SocketQPACK_Table_T *table)
{
  if (table == NULL || *table == NULL)
    return;

  /* Arena-allocated, so just NULL out the pointer */
  *table = NULL;
}

/* ============================================================================
 * Table Accessors
 * ============================================================================
 */

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

uint32_t
SocketQPACK_Table_insert_count (SocketQPACK_Table_T table)
{
  assert (table != NULL);
  return table->insert_count;
}

/* ============================================================================
 * Table Size Management
 * ============================================================================
 */

size_t
qpack_table_evict (SocketQPACK_Table_T table, size_t required_space)
{
  size_t evicted = 0;

  while (table->count > 0 && table->size + required_space > table->max_size)
    {
      /* Evict oldest entry (at tail) */
      QPACK_DynamicEntry *entry = &table->entries[table->tail];

      /* Calculate entry size */
      size_t entry_size = qpack_entry_size (entry->name_len, entry->value_len);
      if (entry_size != SIZE_MAX && entry_size <= table->size)
        table->size -= entry_size;
      else
        table->size = 0;

      /* Clear entry */
      entry->name = NULL;
      entry->name_len = 0;
      entry->value = NULL;
      entry->value_len = 0;

      /* Advance tail (ring buffer) */
      table->tail = (table->tail + 1) % table->capacity;
      table->count--;
      table->base_absolute++;
      evicted++;
    }

  return evicted;
}

void
SocketQPACK_Table_set_max_size (SocketQPACK_Table_T table, size_t max_size)
{
  assert (table != NULL);

  table->max_size = max_size;

  /* Evict entries if necessary to fit new max size */
  qpack_table_evict (table, 0);
}

/* ============================================================================
 * Table Entry Access
 * ============================================================================
 */

SocketQPACK_Result
SocketQPACK_Table_get_absolute (SocketQPACK_Table_T table,
                                uint32_t abs_index,
                                SocketQPACK_Header *header)
{
  size_t ring_index;
  QPACK_DynamicEntry *entry;

  assert (table != NULL);

  if (header == NULL)
    return QPACK_ERROR;

  /*
   * RFC 9204 Section 3.2.4:
   * Absolute index 0 is the first entry ever inserted.
   * Current valid range is [base_absolute, insert_count - 1].
   */
  if (abs_index < table->base_absolute)
    return QPACK_ERROR_INVALID_INDEX; /* Entry was evicted */

  if (abs_index >= table->insert_count)
    return QPACK_ERROR_INVALID_INDEX; /* Entry not yet inserted */

  /* Convert absolute index to ring buffer index */
  /* Relative to tail: abs_index - base_absolute gives position from tail */
  uint32_t relative = abs_index - table->base_absolute;
  ring_index = (table->tail + relative) % table->capacity;

  entry = &table->entries[ring_index];

  header->name = entry->name;
  header->name_len = entry->name_len;
  header->value = entry->value;
  header->value_len = entry->value_len;
  header->never_index = 0;

  return QPACK_OK;
}

/* ============================================================================
 * Table Entry Addition
 * ============================================================================
 */

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

  if (name == NULL && name_len > 0)
    return QPACK_ERROR;

  /* Calculate entry size */
  entry_size = qpack_entry_size (name_len, value_len);
  if (entry_size == SIZE_MAX)
    return QPACK_ERROR;

  /* Entry too large for table - don't add but still increment insert_count */
  if (entry_size > table->max_size)
    {
      /* RFC 9204 Section 3.2.2: Entry too large, evict all entries */
      qpack_table_evict (table, table->max_size + 1);
      table->insert_count++;
      return QPACK_OK;
    }

  /* Evict entries to make room */
  qpack_table_evict (table, entry_size);

  /* Check if we need to grow the ring buffer */
  if (table->count >= table->capacity)
    {
      /* For simplicity, we don't grow - this shouldn't happen with proper
       * sizing */
      return QPACK_ERROR_TABLE_SIZE;
    }

  /* Copy name and value to arena */
  name_copy = ALLOC (table->arena, name_len + 1);
  if (name_len > 0)
    memcpy (name_copy, name, name_len);
  name_copy[name_len] = '\0';

  value_copy = ALLOC (table->arena, value_len + 1);
  if (value_len > 0)
    memcpy (value_copy, value, value_len);
  value_copy[value_len] = '\0';

  /* Add entry at head */
  entry = &table->entries[table->head];
  entry->name = name_copy;
  entry->name_len = name_len;
  entry->value = value_copy;
  entry->value_len = value_len;

  /* Advance head (ring buffer) */
  table->head = (table->head + 1) % table->capacity;
  table->count++;
  table->size += entry_size;
  table->insert_count++;

  return QPACK_OK;
}
