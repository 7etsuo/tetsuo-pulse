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
 */

#ifndef SOCKETQPACK_PRIVATE_INCLUDED
#define SOCKETQPACK_PRIVATE_INCLUDED

#include "http/qpack/SocketQPACK.h"
#include <stdint.h>

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
 * INDEX METADATA (Internal)
 *
 * Tracks metadata for dynamic table entries as per RFC 9204 Section 3.2.4.
 * ============================================================================
 */

/**
 * @brief Metadata for a dynamic table entry.
 * @internal
 *
 * Tracks the absolute index assigned at insertion time. This index is
 * immutable for the lifetime of the entry and monotonically increases
 * across all insertions (RFC 9204 Section 3.2.4).
 */
struct QPACKIndexMetadata
{
  uint64_t abs_index;    /**< Absolute index (0 = first ever inserted) */
  uint64_t insert_count; /**< Insert Count at time of insertion */
  uint32_t ref_count;    /**< Reference count for tracking (future use) */
};

/* ============================================================================
 * DYNAMIC TABLE ENTRY
 * ============================================================================
 */

/**
 * @brief Dynamic table entry structure.
 * @internal
 */
typedef struct
{
  char *name;
  size_t name_len;
  char *value;
  size_t value_len;
  struct QPACKIndexMetadata meta; /**< Index metadata per RFC 9204 3.2.4 */
} QPACK_DynamicEntry;

/* ============================================================================
 * DYNAMIC TABLE STRUCTURE
 * ============================================================================
 */

/**
 * @brief QPACK dynamic table implementation.
 * @internal
 *
 * Implements RFC 9204 Section 3.2.1-3.2.3 with absolute indexing.
 * Uses a circular buffer (ring buffer) for O(1) insertion and eviction.
 */
struct SocketQPACK_Table
{
  QPACK_DynamicEntry *entries; /**< Circular buffer of entries */
  size_t capacity;             /**< Buffer capacity (power of 2) */
  size_t head;                 /**< Index of oldest entry */
  size_t tail;                 /**< Index for next insertion */
  size_t count;                /**< Current number of entries */
  size_t size;                 /**< Current size in bytes */
  size_t max_size;             /**< Maximum size in bytes */

  /* RFC 9204 absolute indexing state */
  uint64_t insert_count;   /**< Total entries ever inserted (monotonic) */
  uint64_t dropped_count;  /**< Total entries evicted (oldest valid abs idx) */
  uint64_t known_received; /**< Known Received Count from decoder */

  Arena_T arena; /**< Memory arena for allocations */
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
