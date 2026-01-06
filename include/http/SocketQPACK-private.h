/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-private.h
 * @brief Internal QPACK header compression structures and constants.
 * @internal
 *
 * Private implementation for QPACK (RFC 9204). This module provides the
 * dynamic table implementation as specified in RFC 9204 Section 3.2.
 *
 * Key differences from HPACK (RFC 7541):
 * - Absolute indexing (entries have persistent indices)
 * - Relative indexing from current insert count
 * - Post-base indexing for encoder stream references
 * - No circular buffer - uses doubly linked list for FIFO order
 */

#ifndef SOCKETQPACK_PRIVATE_INCLUDED
#define SOCKETQPACK_PRIVATE_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include "core/Arena.h"
#include "core/Except.h"

/**
 * @brief Entry overhead per RFC 9204 Section 3.2.1.
 *
 * Each entry has an overhead of 32 bytes which accounts for the entry
 * structure pointers and metadata. This matches HPACK for compatibility.
 */
#define QPACK_ENTRY_OVERHEAD 32

/**
 * @brief Default maximum table capacity in bytes.
 */
#ifndef SOCKETQPACK_DEFAULT_MAX_CAPACITY
#define SOCKETQPACK_DEFAULT_MAX_CAPACITY 4096
#endif

/**
 * @brief Upper limit for QPACK table capacity.
 */
#ifndef SOCKETQPACK_MAX_CAPACITY_LIMIT
#define SOCKETQPACK_MAX_CAPACITY_LIMIT (64 * 1024)
#endif

/**
 * @brief QPACK error codes.
 */
typedef enum
{
  QPACK_OK = 0,
  QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF,
  QPACK_ERROR_DECODER_STREAM_ERROR,
  QPACK_ERROR_ENTRY_TOO_LARGE,
  QPACK_ERROR_ALLOCATION_FAILED
} SocketQPACK_Error;

/**
 * @brief Exception for QPACK errors.
 */
extern const Except_T SocketQPACK_Exception;

/**
 * @brief Dynamic table entry.
 *
 * Entries are stored in a doubly linked list to maintain FIFO ordering.
 * Each entry has a unique absolute index that persists for its lifetime.
 */
typedef struct SocketQPACK_Entry
{
  size_t absolute_index;          /**< Fixed index for entry lifetime */
  char *name;                     /**< Field name (arena-allocated) */
  size_t name_len;                /**< Name length in bytes */
  char *value;                    /**< Field value (arena-allocated) */
  size_t value_len;               /**< Value length in bytes */
  struct SocketQPACK_Entry *prev; /**< Previous entry (towards tail) */
  struct SocketQPACK_Entry *next; /**< Next entry (towards head) */
} SocketQPACK_Entry;

/**
 * @brief Dynamic table configuration.
 */
typedef struct
{
  size_t max_capacity;     /**< Max allowed capacity from SETTINGS */
  size_t initial_capacity; /**< Starting capacity (often same as max) */
} SocketQPACK_TableConfig;

/**
 * @brief Opaque dynamic table type.
 */
typedef struct SocketQPACK_Table *SocketQPACK_Table_T;

/**
 * @brief Dynamic table structure.
 *
 * Maintains field lines in FIFO order with O(1) insertion at head
 * and O(1) eviction at tail. Supports absolute, relative, and
 * post-base indexing per RFC 9204.
 */
struct SocketQPACK_Table
{
  Arena_T arena;           /**< Memory arena for allocations */
  SocketQPACK_Entry *head; /**< Most recently inserted entry */
  SocketQPACK_Entry *tail; /**< Oldest entry (evicted first) */

  size_t capacity;     /**< Current max size in bytes */
  size_t max_capacity; /**< Upper limit from settings */
  size_t current_size; /**< Sum of all entry sizes */
  size_t insert_count; /**< Total insertions ever made */
  size_t entry_count;  /**< Current number of entries */
};

/* ============================================================================
 * Dynamic Table API
 * ============================================================================
 */

/**
 * @brief Create new dynamic table with given configuration.
 *
 * @param config  Table configuration (NULL uses defaults)
 * @param arena   Memory arena for allocations
 *
 * @return New table instance
 * @throws SocketQPACK_Exception on allocation failure
 */
extern SocketQPACK_Table_T
SocketQPACK_Table_new (const SocketQPACK_TableConfig *config, Arena_T arena);

/**
 * @brief Destroy table and release resources.
 *
 * @param table  Pointer to table (set to NULL after)
 */
extern void SocketQPACK_Table_free (SocketQPACK_Table_T *table);

/**
 * @brief Update capacity limit, evicting entries if needed.
 *
 * Per RFC 9204 Section 3.2.3, capacity can be reduced at any time.
 * Entries are evicted from tail (oldest) until size fits within
 * new capacity. Setting capacity to 0 clears the entire table.
 *
 * @param table     Table to update
 * @param capacity  New capacity in bytes
 *
 * @return QPACK_OK on success
 */
extern SocketQPACK_Error
SocketQPACK_Table_set_capacity (SocketQPACK_Table_T table, size_t capacity);

/**
 * @brief Get current capacity limit.
 *
 * @param table  Table to query
 * @return Current capacity in bytes
 */
extern size_t SocketQPACK_Table_capacity (SocketQPACK_Table_T table);

/**
 * @brief Get current used size.
 *
 * @param table  Table to query
 * @return Current size in bytes
 */
extern size_t SocketQPACK_Table_size (SocketQPACK_Table_T table);

/**
 * @brief Get number of entries in table.
 *
 * @param table  Table to query
 * @return Entry count
 */
extern size_t SocketQPACK_Table_count (SocketQPACK_Table_T table);

/**
 * @brief Get total insertions ever made.
 *
 * This value only increases and never resets. Used for computing
 * relative and post-base indices.
 *
 * @param table  Table to query
 * @return Insert count
 */
extern size_t SocketQPACK_Table_insert_count (SocketQPACK_Table_T table);

/**
 * @brief Insert new field line into table.
 *
 * Per RFC 9204 Section 3.2.2, entries are evicted from tail (oldest)
 * as needed to make room. The entry is assigned the next absolute
 * index (equal to current insert_count before increment).
 *
 * @param table      Table to modify
 * @param name       Field name (copied into arena)
 * @param name_len   Name length
 * @param value      Field value (copied into arena)
 * @param value_len  Value length
 *
 * @return QPACK_OK on success,
 *         QPACK_ERROR_ENTRY_TOO_LARGE if entry exceeds max capacity,
 *         QPACK_ERROR_ALLOCATION_FAILED on memory failure
 */
extern SocketQPACK_Error SocketQPACK_Table_insert (SocketQPACK_Table_T table,
                                                   const char *name,
                                                   size_t name_len,
                                                   const char *value,
                                                   size_t value_len);

/**
 * @brief Look up entry by absolute index.
 *
 * Per RFC 9204 Section 3.2, absolute indices are assigned at insertion
 * and persist for the entry's lifetime.
 *
 * @param table      Table to search
 * @param abs_index  Absolute index to find
 * @param name       Output: name pointer (not copied)
 * @param name_len   Output: name length
 * @param value      Output: value pointer (not copied)
 * @param value_len  Output: value length
 *
 * @return QPACK_OK on success,
 *         QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF if index is invalid
 */
extern SocketQPACK_Error
SocketQPACK_Table_get_absolute (SocketQPACK_Table_T table,
                                size_t abs_index,
                                const char **name,
                                size_t *name_len,
                                const char **value,
                                size_t *value_len);

/**
 * @brief Look up entry by relative index.
 *
 * Relative index 0 refers to the most recently inserted entry.
 * Index increases with age (1 = second most recent, etc.).
 *
 * @param table      Table to search
 * @param rel_index  Relative index (0 = newest)
 * @param name       Output: name pointer (not copied)
 * @param name_len   Output: name length
 * @param value      Output: value pointer (not copied)
 * @param value_len  Output: value length
 *
 * @return QPACK_OK on success,
 *         QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF if index is invalid
 */
extern SocketQPACK_Error
SocketQPACK_Table_get_relative (SocketQPACK_Table_T table,
                                size_t rel_index,
                                const char **name,
                                size_t *name_len,
                                const char **value,
                                size_t *value_len);

/**
 * @brief Convert post-base index to absolute index.
 *
 * Per RFC 9204 Section 4.5.4, post-base indices reference entries
 * that will be inserted after the current base. The absolute index
 * is computed as: base + post_base_index
 *
 * @param table            Table for validation
 * @param base             Base value (Required Insert Count at encoding)
 * @param post_base_index  Post-base index from encoded field line
 * @param abs_index        Output: computed absolute index
 *
 * @return QPACK_OK on success,
 *         QPACK_ERROR_INVALID_DYNAMIC_TABLE_REF if resulting index invalid
 */
extern SocketQPACK_Error
SocketQPACK_Table_post_base_to_absolute (SocketQPACK_Table_T table,
                                         size_t base,
                                         size_t post_base_index,
                                         size_t *abs_index);

/**
 * @brief Compute entry size per RFC 9204 Section 3.2.1.
 *
 * Entry size = name_len + value_len + 32 bytes overhead.
 *
 * @param name_len   Name length in bytes
 * @param value_len  Value length in bytes
 *
 * @return Entry size, or SIZE_MAX on overflow
 */
extern size_t SocketQPACK_Table_entry_size (size_t name_len, size_t value_len);

/**
 * @brief Initialize default table configuration.
 *
 * @param config  Configuration to initialize
 */
extern void SocketQPACK_table_config_defaults (SocketQPACK_TableConfig *config);

/**
 * @brief Get string description of error code.
 *
 * @param error  Error code
 * @return Static string description
 */
extern const char *SocketQPACK_error_string (SocketQPACK_Error error);

#endif /* SOCKETQPACK_PRIVATE_INCLUDED */
