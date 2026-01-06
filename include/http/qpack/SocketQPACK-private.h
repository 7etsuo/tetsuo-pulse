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
 * Private implementation for QPACK (RFC 9204). Use SocketQPACK.h for public
 * API.
 */

#ifndef SOCKETQPACK_PRIVATE_INCLUDED
#define SOCKETQPACK_PRIVATE_INCLUDED

#include "http/qpack/SocketQPACK.h"
#include <stdint.h>

#include "core/SocketSecurity.h"

/* ============================================================================
 * Dynamic Table Internal Structure
 * ============================================================================
 */

#define QPACK_AVERAGE_DYNAMIC_ENTRY_SIZE 50
#define QPACK_MIN_DYNAMIC_TABLE_CAPACITY 16

/**
 * @brief Dynamic table entry storage
 */
typedef struct
{
  char *name;
  size_t name_len;
  char *value;
  size_t value_len;
} QPACK_DynamicEntry;

/**
 * @brief QPACK Dynamic Table
 *
 * Unlike HPACK, QPACK uses absolute indexing where each entry has a permanent
 * index that doesn't change when other entries are inserted or evicted.
 *
 * The insertion_count tracks the total number of entries ever inserted,
 * serving as the absolute index for the next entry.
 */
struct SocketQPACK_DynamicTable
{
  QPACK_DynamicEntry *entries; /**< Circular buffer of entries */
  size_t capacity;             /**< Buffer capacity (power of 2) */
  size_t head;                 /**< Index of oldest entry in buffer */
  size_t tail;                 /**< Index after newest entry in buffer */
  size_t count;                /**< Number of entries in table */
  size_t size;                 /**< Current table size in bytes */
  size_t max_size;             /**< Maximum table size in bytes */
  uint64_t insertion_count;    /**< Total entries ever inserted (absolute index
                                    of next entry) */
  uint64_t drop_count;         /**< Number of entries evicted (for index
                                    calculation) */
  Arena_T arena;               /**< Memory arena for allocations */
};

/* ============================================================================
 * Static Table Entry
 * ============================================================================
 */

typedef struct
{
  const char *name;
  const char *value;
  uint8_t name_len;
  uint8_t value_len;
} QPACK_StaticEntry;

/**
 * @brief QPACK static table (RFC 9204 Appendix A)
 * 99 entries (indices 0-98)
 */
extern const QPACK_StaticEntry
    qpack_static_table[SOCKETQPACK_STATIC_TABLE_SIZE];

/* ============================================================================
 * Internal Helpers
 * ============================================================================
 */

/**
 * @brief Calculate entry size including overhead
 */
static inline size_t
qpack_entry_size (size_t name_len, size_t value_len)
{
  size_t temp;
  if (SocketSecurity_check_add (name_len, value_len, &temp)
      && SocketSecurity_check_add (temp, SOCKETQPACK_ENTRY_OVERHEAD, &temp))
    {
      return temp;
    }
  return SIZE_MAX;
}

/**
 * @brief Evict entries to make room for new entry
 */
extern size_t
qpack_table_evict (SocketQPACK_DynamicTable_T table, size_t required_space);

#endif /* SOCKETQPACK_PRIVATE_INCLUDED */
