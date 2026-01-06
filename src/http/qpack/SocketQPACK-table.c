/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-table.c
 * @brief QPACK Dynamic Table implementation (RFC 9204 Section 3.2).
 *
 * Implements the dynamic table for QPACK header compression. Key features:
 * - FIFO ordering with doubly linked list
 * - Absolute indexing (persists for entry lifetime)
 * - Relative indexing (0 = newest)
 * - Post-base indexing for encoder stream references
 * - Automatic eviction when capacity exceeded
 *
 * @see https://www.rfc-editor.org/rfc/rfc9204#section-3.2
 */

#include <assert.h>
#include <string.h>

#include "core/Arena.h"
#include "core/SocketSecurity.h"
#include "core/SocketUtil.h"
#include "http/SocketQPACK-private.h"

#define T SocketQPACK_Table_T

/* Module exception */
const Except_T SocketQPACK_Exception = { NULL, "QPACK error" };

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "QPACK"

/* ============================================================================
 * Internal Helpers
 * ============================================================================
 */

/**
 * @brief Validate table pointer.
 */
static int
qpack_validate_table (const SocketQPACK_Table_T table, const char *func)
{
  if (table == NULL)
    {
      SOCKET_LOG_DEBUG_MSG ("SocketQPACK %s: NULL table pointer", func);
      return 0;
    }
  return 1;
}

/**
 * @brief Compute entry size with overflow protection.
 */
static size_t
qpack_compute_entry_size (size_t name_len, size_t value_len)
{
  size_t sum;

  if (!SocketSecurity_check_add (name_len, value_len, &sum))
    return SIZE_MAX;

  if (!SocketSecurity_check_add (sum, QPACK_ENTRY_OVERHEAD, &sum))
    return SIZE_MAX;

  return sum;
}

/**
 * @brief Duplicate string into arena with null terminator.
 */
static char *
qpack_strdup (Arena_T arena, const char *src, size_t len)
{
  char *dst;

  if (src == NULL && len > 0)
    return NULL;

  dst = ALLOC (arena, len + 1);
  if (dst == NULL)
    return NULL;

  if (len > 0 && src != NULL)
    memcpy (dst, src, len);

  dst[len] = '\0';
  return dst;
}

/**
 * @brief Evict oldest entry from table.
 */
static void
qpack_evict_oldest (SocketQPACK_Table_T table)
{
  SocketQPACK_Entry *victim;
  size_t victim_size;

  assert (table != NULL);
  assert (table->entry_count > 0);
  assert (table->tail != NULL);

  victim = table->tail;
  victim_size = qpack_compute_entry_size (victim->name_len, victim->value_len);

  /* Update linked list */
  if (victim->next != NULL)
    victim->next->prev = NULL;

  table->tail = victim->next;

  if (table->head == victim)
    table->head = NULL;

  /* Update size tracking */
  if (victim_size <= table->current_size)
    table->current_size -= victim_size;
  else
    table->current_size = 0;

  table->entry_count--;

  /* Note: Entry memory stays in arena, freed when arena disposed */
}

/**
 * @brief Evict entries until size fits within capacity.
 */
static void
qpack_evict_to_fit (SocketQPACK_Table_T table, size_t required_space)
{
  size_t target_size;

  assert (table != NULL);

  /* Handle capacity=0 case */
  if (table->capacity == 0)
    {
      while (table->entry_count > 0)
        qpack_evict_oldest (table);
      return;
    }

  /* Check for overflow when computing target */
  if (required_space > table->capacity)
    {
      /* Entry larger than capacity - will fail insertion */
      return;
    }

  target_size = table->capacity - required_space;

  while (table->entry_count > 0 && table->current_size > target_size)
    qpack_evict_oldest (table);
}

/**
 * @brief Find entry by absolute index (walk from head).
 */
static SocketQPACK_Entry *
qpack_find_absolute (SocketQPACK_Table_T table, size_t abs_index)
{
  SocketQPACK_Entry *entry;

  assert (table != NULL);

  for (entry = table->head; entry != NULL; entry = entry->prev)
    {
      if (entry->absolute_index == abs_index)
        return entry;
    }

  return NULL;
}

/**
 * @brief Compute oldest valid absolute index.
 */
static size_t
qpack_oldest_absolute_index (SocketQPACK_Table_T table)
{
  assert (table != NULL);

  if (table->entry_count == 0)
    return table->insert_count;

  return table->insert_count - table->entry_count;
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================
 */

void
SocketQPACK_table_config_defaults (SocketQPACK_TableConfig *config)
{
  if (config == NULL)
    return;

  config->max_capacity = SOCKETQPACK_DEFAULT_MAX_CAPACITY;
  config->initial_capacity = SOCKETQPACK_DEFAULT_MAX_CAPACITY;
}

size_t
SocketQPACK_Table_entry_size (size_t name_len, size_t value_len)
{
  return qpack_compute_entry_size (name_len, value_len);
}

const char *
SocketQPACK_error_string (SocketQPACK_Error error)
{
  switch (error)
    {
    case QPACK_OK:
      return "OK";
    case QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF:
      return "Invalid dynamic table reference";
    case QPACK_ERROR_DECODER_STREAM_ERROR:
      return "Decoder stream error";
    case QPACK_ERROR_ENTRY_TOO_LARGE:
      return "Entry exceeds table capacity";
    case QPACK_ERROR_ALLOCATION_FAILED:
      return "Memory allocation failed";
    default:
      return "Unknown error";
    }
}

SocketQPACK_Table_T
SocketQPACK_Table_new (const SocketQPACK_TableConfig *config, Arena_T arena)
{
  SocketQPACK_Table_T table;
  SocketQPACK_TableConfig defaults;

  assert (arena != NULL);

  if (config == NULL)
    {
      SocketQPACK_table_config_defaults (&defaults);
      config = &defaults;
    }

  table = ALLOC (arena, sizeof (*table));
  if (table == NULL)
    {
      SOCKET_LOG_ERROR_MSG ("SocketQPACK: failed to allocate table structure");
      RAISE (SocketQPACK_Exception);
    }

  table->arena = arena;
  table->head = NULL;
  table->tail = NULL;
  table->capacity = config->initial_capacity;
  table->max_capacity = config->max_capacity;
  table->current_size = 0;
  table->insert_count = 0;
  table->entry_count = 0;

  SOCKET_LOG_DEBUG_MSG ("SocketQPACK: created table with capacity=%zu, "
                        "max_capacity=%zu",
                        table->capacity,
                        table->max_capacity);

  return table;
}

void
SocketQPACK_Table_free (SocketQPACK_Table_T *table)
{
  if (table == NULL || *table == NULL)
    return;

  /* Memory is arena-managed, just clear pointer */
  *table = NULL;
}

SocketQPACK_Error
SocketQPACK_Table_set_capacity (SocketQPACK_Table_T table, size_t capacity)
{
  if (!qpack_validate_table (table, "set_capacity"))
    return QPACK_ERROR_DECODER_STREAM_ERROR;

  /* Clamp to max capacity */
  if (capacity > table->max_capacity)
    {
      SOCKET_LOG_WARN_MSG ("SocketQPACK: clamping capacity from %zu to max %zu",
                           capacity,
                           table->max_capacity);
      capacity = table->max_capacity;
    }

  table->capacity = capacity;

  /* Evict entries if needed */
  if (capacity == 0)
    {
      while (table->entry_count > 0)
        qpack_evict_oldest (table);
    }
  else
    {
      while (table->entry_count > 0 && table->current_size > capacity)
        qpack_evict_oldest (table);
    }

  SOCKET_LOG_DEBUG_MSG (
      "SocketQPACK: set capacity=%zu, current_size=%zu, count=%zu",
      capacity,
      table->current_size,
      table->entry_count);

  return QPACK_OK;
}

size_t
SocketQPACK_Table_capacity (SocketQPACK_Table_T table)
{
  if (!qpack_validate_table (table, "capacity"))
    return 0;
  return table->capacity;
}

size_t
SocketQPACK_Table_size (SocketQPACK_Table_T table)
{
  if (!qpack_validate_table (table, "size"))
    return 0;
  return table->current_size;
}

size_t
SocketQPACK_Table_count (SocketQPACK_Table_T table)
{
  if (!qpack_validate_table (table, "count"))
    return 0;
  return table->entry_count;
}

size_t
SocketQPACK_Table_insert_count (SocketQPACK_Table_T table)
{
  if (!qpack_validate_table (table, "insert_count"))
    return 0;
  return table->insert_count;
}

SocketQPACK_Error
SocketQPACK_Table_insert (SocketQPACK_Table_T table,
                          const char *name,
                          size_t name_len,
                          const char *value,
                          size_t value_len)
{
  SocketQPACK_Entry *entry;
  size_t entry_size;

  if (!qpack_validate_table (table, "insert"))
    return QPACK_ERROR_DECODER_STREAM_ERROR;

  /* Validate input */
  if ((name == NULL && name_len > 0) || (value == NULL && value_len > 0))
    {
      SOCKET_LOG_ERROR_MSG (
          "SocketQPACK: invalid NULL string with non-zero length");
      return QPACK_ERROR_DECODER_STREAM_ERROR;
    }

  /* Compute entry size */
  entry_size = qpack_compute_entry_size (name_len, value_len);
  if (entry_size == SIZE_MAX)
    {
      SOCKET_LOG_ERROR_MSG ("SocketQPACK: entry size overflow");
      return QPACK_ERROR_ENTRY_TOO_LARGE;
    }

  /* Check if entry can ever fit */
  if (entry_size > table->capacity)
    {
      SOCKET_LOG_WARN_MSG ("SocketQPACK: entry size %zu exceeds capacity %zu",
                           entry_size,
                           table->capacity);
      return QPACK_ERROR_ENTRY_TOO_LARGE;
    }

  /* Evict to make room */
  qpack_evict_to_fit (table, entry_size);

  /* Allocate entry */
  entry = ALLOC (table->arena, sizeof (*entry));
  if (entry == NULL)
    {
      SOCKET_LOG_ERROR_MSG ("SocketQPACK: failed to allocate entry");
      return QPACK_ERROR_ALLOCATION_FAILED;
    }

  /* Copy name and value */
  entry->name = qpack_strdup (table->arena, name, name_len);
  if (entry->name == NULL && name_len > 0)
    {
      SOCKET_LOG_ERROR_MSG ("SocketQPACK: failed to copy name");
      return QPACK_ERROR_ALLOCATION_FAILED;
    }

  entry->value = qpack_strdup (table->arena, value, value_len);
  if (entry->value == NULL && value_len > 0)
    {
      SOCKET_LOG_ERROR_MSG ("SocketQPACK: failed to copy value");
      return QPACK_ERROR_ALLOCATION_FAILED;
    }

  entry->name_len = name_len;
  entry->value_len = value_len;
  entry->absolute_index = table->insert_count;

  /* Insert at head */
  entry->prev = table->head;
  entry->next = NULL;

  if (table->head != NULL)
    table->head->next = entry;

  table->head = entry;

  if (table->tail == NULL)
    table->tail = entry;

  /* Update tracking */
  table->current_size += entry_size;
  table->entry_count++;
  table->insert_count++;

  SOCKET_LOG_DEBUG_MSG (
      "SocketQPACK: inserted entry abs_idx=%zu, name_len=%zu, "
      "value_len=%zu, size=%zu, table_size=%zu",
      entry->absolute_index,
      name_len,
      value_len,
      entry_size,
      table->current_size);

  return QPACK_OK;
}

SocketQPACK_Error
SocketQPACK_Table_get_absolute (SocketQPACK_Table_T table,
                                size_t abs_index,
                                const char **name,
                                size_t *name_len,
                                const char **value,
                                size_t *value_len)
{
  SocketQPACK_Entry *entry;
  size_t oldest_index;

  if (!qpack_validate_table (table, "get_absolute"))
    return QPACK_ERROR_DECODER_STREAM_ERROR;

  if (name == NULL || name_len == NULL || value == NULL || value_len == NULL)
    {
      SOCKET_LOG_ERROR_MSG ("SocketQPACK: NULL output pointer");
      return QPACK_ERROR_DECODER_STREAM_ERROR;
    }

  /* Check bounds */
  if (table->entry_count == 0)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketQPACK: table empty, cannot lookup abs_index=%zu", abs_index);
      return QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF;
    }

  oldest_index = qpack_oldest_absolute_index (table);

  /* Check if index was evicted */
  if (abs_index < oldest_index)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketQPACK: abs_index=%zu was evicted (oldest=%zu)",
          abs_index,
          oldest_index);
      return QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF;
    }

  /* Check if index is in future */
  if (abs_index >= table->insert_count)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketQPACK: abs_index=%zu is future (insert_count=%zu)",
          abs_index,
          table->insert_count);
      return QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF;
    }

  /* Find entry */
  entry = qpack_find_absolute (table, abs_index);
  if (entry == NULL)
    {
      SOCKET_LOG_ERROR_MSG ("SocketQPACK: entry not found for abs_index=%zu",
                            abs_index);
      return QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF;
    }

  *name = entry->name;
  *name_len = entry->name_len;
  *value = entry->value;
  *value_len = entry->value_len;

  return QPACK_OK;
}

SocketQPACK_Error
SocketQPACK_Table_get_relative (SocketQPACK_Table_T table,
                                size_t rel_index,
                                const char **name,
                                size_t *name_len,
                                const char **value,
                                size_t *value_len)
{
  SocketQPACK_Entry *entry;
  size_t i;

  if (!qpack_validate_table (table, "get_relative"))
    return QPACK_ERROR_DECODER_STREAM_ERROR;

  if (name == NULL || name_len == NULL || value == NULL || value_len == NULL)
    {
      SOCKET_LOG_ERROR_MSG ("SocketQPACK: NULL output pointer");
      return QPACK_ERROR_DECODER_STREAM_ERROR;
    }

  /* Check bounds */
  if (rel_index >= table->entry_count)
    {
      SOCKET_LOG_WARN_MSG (
          "SocketQPACK: rel_index=%zu out of range (count=%zu)",
          rel_index,
          table->entry_count);
      return QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF;
    }

  /* Walk from head (most recent) */
  entry = table->head;
  for (i = 0; i < rel_index && entry != NULL; i++)
    entry = entry->prev;

  if (entry == NULL)
    {
      SOCKET_LOG_ERROR_MSG ("SocketQPACK: entry not found for rel_index=%zu",
                            rel_index);
      return QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF;
    }

  *name = entry->name;
  *name_len = entry->name_len;
  *value = entry->value;
  *value_len = entry->value_len;

  return QPACK_OK;
}

SocketQPACK_Error
SocketQPACK_Table_post_base_to_absolute (SocketQPACK_Table_T table,
                                         size_t base,
                                         size_t post_base_index,
                                         size_t *abs_index)
{
  size_t computed;

  if (!qpack_validate_table (table, "post_base_to_absolute"))
    return QPACK_ERROR_DECODER_STREAM_ERROR;

  if (abs_index == NULL)
    {
      SOCKET_LOG_ERROR_MSG ("SocketQPACK: NULL abs_index output pointer");
      return QPACK_ERROR_DECODER_STREAM_ERROR;
    }

  /* Per RFC 9204 Section 4.5.4:
   * absolute = base + post_base_index
   * Note: The spec says "Required Insert Count" which is base + 1,
   * so absolute = (base + 1) + post_base_index - 1 = base + post_base_index
   */
  if (!SocketSecurity_check_add (base, post_base_index, &computed))
    {
      SOCKET_LOG_ERROR_MSG (
          "SocketQPACK: post_base_to_absolute overflow (base=%zu, pbi=%zu)",
          base,
          post_base_index);
      return QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF;
    }

  *abs_index = computed;

  SOCKET_LOG_DEBUG_MSG (
      "SocketQPACK: post_base_to_absolute base=%zu, pbi=%zu -> abs=%zu",
      base,
      post_base_index,
      computed);

  return QPACK_OK;
}

#undef T
