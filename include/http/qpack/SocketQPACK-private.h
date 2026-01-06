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
 * Constants
 * ============================================================================
 */

#define QPACK_AVERAGE_DYNAMIC_ENTRY_SIZE 50
#define QPACK_MIN_DYNAMIC_TABLE_CAPACITY 16

/* Huffman encoding constants (same as HPACK - RFC 7541 Appendix B) */
#define QPACK_HUFFMAN_SYMBOLS 257
#define QPACK_HUFFMAN_EOS 256
#define QPACK_HUFFMAN_MAX_BITS 30
#define QPACK_HUFFMAN_NUM_STATES 256
#define QPACK_HUFFMAN_STATE_ERROR 0xFF
#define QPACK_HUFFMAN_STATE_ACCEPT 0xFE

/* Integer encoding limits */
#define QPACK_INT_BUF_SIZE 16
#define QPACK_MAX_INT_CONTINUATION_BYTES 10
#define QPACK_MAX_SAFE_SHIFT 56

/* String encoding */
#define QPACK_STRING_HUFFMAN_FLAG 0x80
#define QPACK_STRING_LITERAL_FLAG 0x00
#define QPACK_HUFFMAN_RATIO 2

/* Encoder stream instruction patterns (RFC 9204 Section 4.3) */
#define QPACK_INSERT_WITH_NAME_REF_STATIC 0x80 /* 1xxxxxxx - S=1 */
#define QPACK_INSERT_WITH_NAME_REF_DYNAMIC                                    \
  0x00                                         /* 0xxxxxxx - S=0 (after mask) \
                                                */
#define QPACK_INSERT_WITH_LITERAL_NAME 0x40    /* 01xxxxxx */
#define QPACK_INSERT_LITERAL_NAME_MASK 0xC0    /* Top 2 bits */
#define QPACK_INSERT_LITERAL_NAME_PATTERN 0x40 /* Pattern 01 */
#define QPACK_SET_DYNAMIC_TABLE_CAPACITY 0x20  /* 001xxxxx */
#define QPACK_DUPLICATE 0x00                   /* 000xxxxx */

/* Prefix bits for Insert with Literal Name */
#define QPACK_INSERT_LITERAL_NAME_PREFIX 5  /* 5-bit prefix for name length */
#define QPACK_INSERT_LITERAL_VALUE_PREFIX 7 /* 7-bit prefix for value length \
                                             */

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
 * Uses a ring buffer for FIFO eviction. Unlike HPACK, QPACK uses
 * absolute indices for referencing entries.
 */
struct SocketQPACK_DynamicTable
{
  QPACK_DynamicEntry *entries;
  size_t capacity;      /**< Ring buffer capacity */
  size_t head;          /**< Oldest entry index */
  size_t tail;          /**< Next insertion index */
  size_t count;         /**< Current entry count */
  size_t size;          /**< Current size in bytes */
  size_t max_size;      /**< Maximum size in bytes */
  size_t insert_count;  /**< Total entries ever inserted (for absolute index)
                         */
  size_t dropped_count; /**< Entries evicted (for absolute index calculation) */
  Arena_T arena;
};

/**
 * @brief Static table entry (compact form).
 */
typedef struct
{
  const char *name;
  const char *value;
  uint8_t name_len;
  uint8_t value_len;
} QPACK_StaticEntry;

/* ============================================================================
 * Huffman Tables (shared with HPACK)
 * ============================================================================
 */

typedef struct
{
  uint32_t code;
  uint8_t bits;
} QPACK_HuffmanSymbol;

typedef struct
{
  uint8_t next_state;
  uint8_t flags;
  uint8_t sym;
} QPACK_HuffmanTransition;

#define QPACK_DFA_ACCEPT 0x01
#define QPACK_DFA_EOS 0x02
#define QPACK_DFA_ERROR 0x04
#define QPACK_DFA_SYM2 0x08

/* External Huffman tables (defined in SocketQPACK-huffman.c) */
extern const QPACK_HuffmanSymbol qpack_huffman_encode[QPACK_HUFFMAN_SYMBOLS];
extern const QPACK_HuffmanTransition
    qpack_huffman_decode[QPACK_HUFFMAN_NUM_STATES][16];

/* External static table (defined in SocketQPACK-table.c) */
extern const QPACK_StaticEntry
    qpack_static_table[SOCKETQPACK_STATIC_TABLE_SIZE];

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * @brief Calculate entry size (name_len + value_len + overhead).
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
 * @brief Evict entries from table until required_space fits.
 *
 * @return Number of entries evicted
 */
extern size_t
qpack_table_evict (SocketQPACK_DynamicTable_T table, size_t required_space);

#endif /* SOCKETQPACK_PRIVATE_INCLUDED */
