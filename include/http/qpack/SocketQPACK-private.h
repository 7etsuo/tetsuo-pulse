/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketQPACK-private.h
 * @brief Internal QPACK structures and constants.
 * @internal
 *
 * Private implementation for QPACK (RFC 9204). Use SocketQPACK.h for public
 * API.
 *
 * @since 1.0.0
 */

#ifndef SOCKETQPACK_PRIVATE_INCLUDED
#define SOCKETQPACK_PRIVATE_INCLUDED

#include "http/qpack/SocketQPACK.h"
#include <stdint.h>

#include "core/Arena.h"
#include "core/SocketSecurity.h"

/* ============================================================================
 * INTERNAL CONSTANTS
 * ============================================================================
 */

/** Average entry size estimate for capacity calculation */
#define QPACK_AVERAGE_ENTRY_SIZE 50

/** Minimum dynamic table capacity (entries, power of 2) */
#define QPACK_MIN_TABLE_CAPACITY 16

/* ============================================================================
 * DYNAMIC TABLE ENTRY
 * ============================================================================
 */

/**
 * @brief Dynamic table entry structure.
 * @internal
 *
 * Each entry stores a header field (name/value pair) with its absolute index.
 * Entries form a doubly-linked list for FIFO eviction order.
 *
 * @since 1.0.0
 */
typedef struct QPACK_Entry
{
  char *name;               /**< Field name (arena-allocated) */
  size_t name_len;          /**< Name length in bytes */
  char *value;              /**< Field value (arena-allocated) */
  size_t value_len;         /**< Value length in bytes */
  size_t abs_index;         /**< Absolute index (0 = first ever inserted) */
  struct QPACK_Entry *prev; /**< Previous entry (towards tail/oldest) */
  struct QPACK_Entry *next; /**< Next entry (towards head/newest) */
} QPACK_Entry;

/* ============================================================================
 * ENCODER STRUCTURE - RFC 9204 Section 2.1.4
 * ============================================================================
 */

/**
 * @brief QPACK encoder state.
 * @internal
 *
 * Implements the encoder side of RFC 9204. Key fields:
 * - known_received_count: KRC per Section 2.1.4, tracks decoder acknowledgment
 * - insert_count: Total insertions, next absolute index to assign
 *
 * The relationship between KRC and insert_count:
 * - KRC <= insert_count always (cannot acknowledge what wasn't sent)
 * - Entries with abs_index < KRC are safe to reference without blocking
 * - Entries with abs_index >= KRC may cause decoder to block
 *
 * @since 1.0.0
 */
struct SocketQPACK_Encoder
{
  Arena_T arena; /**< Memory arena for allocations */

  /* Dynamic table state */
  QPACK_Entry *head;     /**< Most recently inserted entry */
  QPACK_Entry *tail;     /**< Oldest entry (evicted first) */
  size_t entry_count;    /**< Current number of entries in table */
  size_t table_size;     /**< Current table size in bytes */
  size_t max_table_size; /**< Maximum allowed table size */
  size_t insert_count;   /**< Total entries ever inserted (monotonic) */

  /* RFC 9204 Section 2.1.4: Known Received Count */
  size_t known_received_count; /**< Highest acknowledged absolute index + 1 */

  /* Note: The KRC represents the number of insertions the decoder has
   * acknowledged receiving. Entries with absolute index < KRC are guaranteed
   * to be in the decoder's table and can be safely referenced.
   *
   * KRC is updated by:
   * 1. Section Acknowledgment (Section 4.4.1): KRC = max(KRC, RIC)
   * 2. Insert Count Increment (Section 4.4.3): KRC += increment
   */
};

/* ============================================================================
 * INTERNAL HELPERS
 * ============================================================================
 */

/**
 * @brief Calculate entry size per RFC 9204 Section 3.2.1.
 * @internal
 *
 * Entry size = name length + value length + 32 bytes overhead.
 *
 * @param name_len  Name length in bytes
 * @param value_len Value length in bytes
 * @return Entry size in bytes, or SIZE_MAX on overflow
 *
 * @since 1.0.0
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
