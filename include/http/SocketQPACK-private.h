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

#include "http/SocketQPACK.h"
#include <stdint.h>

#include "core/SocketSecurity.h"

/* ============================================================================
 * Internal Constants
 * ============================================================================
 */

/** Average entry size for capacity estimation */
#define QPACK_AVERAGE_DYNAMIC_ENTRY_SIZE 50

/** Minimum dynamic table capacity (power of 2) */
#define QPACK_MIN_DYNAMIC_TABLE_CAPACITY 16

/** Max continuation bytes for integer encoding */
#define QPACK_MAX_INT_CONTINUATION_BYTES 10

/** Max safe shift to prevent overflow */
#define QPACK_MAX_SAFE_SHIFT 56

/** Integer continuation mask */
#define QPACK_INT_CONTINUATION_MASK 0x80
#define QPACK_INT_CONTINUATION_VALUE 128
#define QPACK_INT_PAYLOAD_MASK 0x7F

/* ============================================================================
 * Wire Format Constants (RFC 9204 Section 4.3)
 * ============================================================================
 */

/** Set Dynamic Table Capacity instruction pattern (Section 4.3.1) */
#define QPACK_SET_CAPACITY_PATTERN 0x20
#define QPACK_SET_CAPACITY_MASK 0xE0
#define QPACK_SET_CAPACITY_PREFIX_BITS 5

/* ============================================================================
 * Internal Structures
 * ============================================================================
 */

/**
 * @brief Dynamic table entry.
 */
typedef struct
{
  char *name;
  size_t name_len;
  char *value;
  size_t value_len;
} QPACK_DynamicEntry;

/**
 * @brief QPACK dynamic table structure.
 *
 * Circular buffer implementation with FIFO eviction.
 */
struct SocketQPACK_Table
{
  QPACK_DynamicEntry *entries; /**< Entry array (circular buffer) */
  size_t capacity;             /**< Array capacity (power of 2) */
  size_t head;                 /**< Oldest entry index */
  size_t tail;                 /**< Next insertion index */
  size_t count;                /**< Number of entries */
  size_t size;                 /**< Current size in bytes */
  size_t max_size;             /**< Maximum capacity in bytes */
  Arena_T arena;               /**< Memory arena */
};

/* ============================================================================
 * Internal Functions
 * ============================================================================
 */

/**
 * @brief Evict entries to make room for required space.
 *
 * @param table The dynamic table.
 * @param required_space Space needed in bytes.
 * @return Number of entries evicted.
 */
extern size_t
qpack_table_evict (SocketQPACK_Table_T table, size_t required_space);

/**
 * @brief Calculate entry size including overhead.
 *
 * Per RFC 9204 Section 3.2.1: size = name_len + value_len + 32
 *
 * @param name_len Name length.
 * @param value_len Value length.
 * @return Entry size, or SIZE_MAX on overflow.
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

#endif /* SOCKETQPACK_PRIVATE_INCLUDED */
