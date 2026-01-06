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
 * Dynamic Table Internal Structures
 * ============================================================================
 */

#define QPACK_AVERAGE_DYNAMIC_ENTRY_SIZE 50
#define QPACK_MIN_DYNAMIC_TABLE_CAPACITY 16

/**
 * @brief Internal dynamic table entry.
 */
typedef struct
{
  char *name;
  size_t name_len;
  char *value;
  size_t value_len;
} QPACK_DynamicEntry;

/**
 * @brief Dynamic table structure.
 */
struct SocketQPACK_Table
{
  QPACK_DynamicEntry *entries; /**< Ring buffer of entries */
  size_t capacity;             /**< Buffer capacity */
  size_t head;                 /**< Newest entry index */
  size_t tail;                 /**< Oldest entry index */
  size_t count;                /**< Number of entries */
  size_t size;                 /**< Current size in bytes */
  size_t max_size;             /**< Maximum size in bytes */
  size_t insert_count;         /**< Total entries ever inserted (for abs idx) */
  Arena_T arena;               /**< Memory arena */
};

/* ============================================================================
 * Static Table Entry Structure
 * ============================================================================
 */

/**
 * @brief Static table entry.
 */
typedef struct
{
  const char *name;
  const char *value;
  uint8_t name_len;
  uint8_t value_len;
} QPACK_StaticEntry;

/* ============================================================================
 * Field Line Pattern Constants (RFC 9204 Section 4.5)
 * ============================================================================
 */

/**
 * RFC 9204 Section 4.5.4 - Literal Field Line with Name Reference
 *
 * Wire format:
 *     0   1   2   3   4   5   6   7
 *   +---+---+---+---+---+---+---+---+
 *   | 0 | 1 | N | T |Name Index (4+)|
 *   +---+---+---+---+---------------+
 *
 * Pattern: 01NTXXXX
 * - Bits 7-6: 01 (pattern identifier)
 * - Bit 5 (N): Never-indexed flag
 * - Bit 4 (T): Table selection (1=static, 0=dynamic)
 * - Bits 3-0: First 4 bits of name index
 */

/** Pattern mask for first two bits (01xxxxxx) */
#define QPACK_LITERAL_NAME_REF_MASK 0xC0

/** Pattern value for Literal with Name Reference */
#define QPACK_LITERAL_NAME_REF_PATTERN 0x40

/** Never-indexed bit position */
#define QPACK_LITERAL_NAME_REF_N_BIT 0x20

/** Static table bit position */
#define QPACK_LITERAL_NAME_REF_T_BIT 0x10

/** Prefix bits for name index (4 bits) */
#define QPACK_PREFIX_NAME_INDEX 4

/** Prefix bits for string length (7 bits) */
#define QPACK_PREFIX_STRING 7

/** Huffman flag in string length byte */
#define QPACK_STRING_HUFFMAN_FLAG 0x80

/* ============================================================================
 * Integer Encoding Constants (RFC 9204 Section 5.1)
 * ============================================================================
 */

/** Continuation bit in multi-byte integers */
#define QPACK_INT_CONTINUATION_MASK 0x80

/** Value bits in continuation bytes */
#define QPACK_INT_PAYLOAD_MASK 0x7F

/** Value that triggers continuation */
#define QPACK_INT_CONTINUATION_VALUE 128

/** Buffer size for integer encoding */
#define QPACK_INT_BUF_SIZE 16

/** Max continuation bytes for uint64_t */
#define QPACK_MAX_INT_CONTINUATION_BYTES 10

/** Max safe shift to prevent overflow */
#define QPACK_MAX_SAFE_SHIFT 56

/* ============================================================================
 * Huffman Constants
 * ============================================================================
 */

#define QPACK_HUFFMAN_SYMBOLS 257
#define QPACK_HUFFMAN_EOS 256
#define QPACK_HUFFMAN_MAX_BITS 30
#define QPACK_HUFFMAN_NUM_STATES 256
#define QPACK_HUFFMAN_STATE_ERROR 0xFF
#define QPACK_HUFFMAN_STATE_ACCEPT 0xFE

/** Conservative 2x ratio for Huffman decode buffer */
#define QPACK_HUFFMAN_RATIO 2

/* ============================================================================
 * Huffman Tables (RFC 7541 Appendix B - same as HPACK)
 * ============================================================================
 */

/**
 * @brief Huffman symbol encoding table entry.
 */
typedef struct
{
  uint32_t code; /**< Huffman code */
  uint8_t bits;  /**< Number of bits in code */
} QPACK_HuffmanSymbol;

/**
 * @brief Huffman DFA transition table entry.
 */
typedef struct
{
  uint8_t next_state; /**< Next state */
  uint8_t flags;      /**< Flags (accept, eos, error, sym2) */
  uint8_t sym;        /**< Decoded symbol */
} QPACK_HuffmanTransition;

#define QPACK_DFA_ACCEPT 0x01
#define QPACK_DFA_EOS 0x02
#define QPACK_DFA_ERROR 0x04
#define QPACK_DFA_SYM2 0x08

/* Huffman tables are defined in SocketQPACK-huffman.c */
extern const QPACK_HuffmanSymbol qpack_huffman_encode[QPACK_HUFFMAN_SYMBOLS];
extern const QPACK_HuffmanTransition
    qpack_huffman_decode[QPACK_HUFFMAN_NUM_STATES][16];

/* ============================================================================
 * Static Table (RFC 9204 Appendix A)
 * ============================================================================
 */

extern const QPACK_StaticEntry
    qpack_static_table[SOCKETQPACK_STATIC_TABLE_SIZE];

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

/**
 * @brief Evict oldest entries to make room.
 *
 * @param table          Table instance
 * @param required_space Space needed
 * @return Bytes freed
 */
extern size_t
qpack_table_evict (SocketQPACK_Table_T table, size_t required_space);

/**
 * @brief Find entry in dynamic table.
 *
 * @param table     Table instance
 * @param name      Header name
 * @param name_len  Name length
 * @param value     Header value (NULL for name-only match)
 * @param value_len Value length
 * @return Positive for exact match, negative for name-only, 0 if not found
 */
extern int SocketQPACK_Table_find (SocketQPACK_Table_T table,
                                   const char *name,
                                   size_t name_len,
                                   const char *value,
                                   size_t value_len);

/**
 * @brief Calculate entry size including overhead.
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
