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

#define QPACK_AVERAGE_DYNAMIC_ENTRY_SIZE 50
#define QPACK_MIN_DYNAMIC_TABLE_CAPACITY 16

/* Huffman constants - same as HPACK (RFC 7541 Appendix B) */
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

/* String encoding constants */
#define QPACK_STRING_HUFFMAN_FLAG 0x80
#define QPACK_STRING_LITERAL_FLAG 0x00
#define QPACK_PREFIX_STRING 7

/* Conservative 2x ratio for Huffman decode buffer */
#define QPACK_HUFFMAN_RATIO 2

/* Decompression bomb protection */
#define QPACK_DEFAULT_EXPANSION_RATIO 10.0
#define QPACK_DEFAULT_EXPANSION_MULTIPLIER 10
#define QPACK_DEFAULT_MAX_OUTPUT_BYTES (1024 * 1024)

/* ============================================================================
 * Wire Format Constants (RFC 9204 Section 4.5)
 * ============================================================================
 */

/**
 * Literal Field Line with Post-Base Name Reference (Section 4.5.5)
 * Wire format: 0000 N xxx
 *   - First 4 bits: 0000 (pattern identifier)
 *   - N bit (bit 3): Never index flag
 *   - xxx (bits 0-2): 3-bit prefix for name index
 */
#define QPACK_LITERAL_POSTBASE_PATTERN 0x00  /* 0000 xxxx */
#define QPACK_LITERAL_POSTBASE_MASK 0xF0     /* Check first 4 bits */
#define QPACK_LITERAL_POSTBASE_N_BIT 0x08    /* N bit position */
#define QPACK_LITERAL_POSTBASE_PREFIX_BITS 3 /* 3-bit prefix for index */

/* Integer continuation byte format */
#define QPACK_INT_CONTINUATION_MASK 0x80
#define QPACK_INT_PAYLOAD_MASK 0x7F

/* ============================================================================
 * Internal Structures
 * ============================================================================
 */

typedef struct
{
  char *name;
  size_t name_len;
  char *value;
  size_t value_len;
} QPACK_DynamicEntry;

struct SocketQPACK_Table
{
  QPACK_DynamicEntry *entries;
  size_t capacity;        /**< Number of entry slots allocated */
  size_t head;            /**< Ring buffer head (newest) */
  size_t tail;            /**< Ring buffer tail (oldest) */
  size_t count;           /**< Current number of entries */
  size_t size;            /**< Current size in bytes */
  size_t max_size;        /**< Maximum size in bytes */
  uint32_t insert_count;  /**< Total insertions (monotonically increasing) */
  uint32_t base_absolute; /**< Absolute index of oldest entry */
  Arena_T arena;
};

struct SocketQPACK_Encoder
{
  SocketQPACK_Table_T table;
  size_t pending_table_sizes[2];
  int pending_table_size_count;
  int huffman_encode;
  int use_indexing;
  Arena_T arena;
};

struct SocketQPACK_Decoder
{
  SocketQPACK_Table_T table;
  size_t max_header_size;
  size_t max_header_list_size;
  size_t settings_max_table_size;
  Arena_T arena;
  uint64_t decode_input_bytes;
  uint64_t decode_output_bytes;
  double max_expansion_ratio;
  size_t max_output_bytes;
};

/* Static table entry structure */
typedef struct
{
  const char *name;
  const char *value;
  uint8_t name_len;
  uint8_t value_len;
} QPACK_StaticEntry;

/* Huffman structures - same as HPACK */
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

/* ============================================================================
 * Internal Functions
 * ============================================================================
 */

/**
 * Calculate entry size with overhead.
 * @return Size including 32-byte overhead, or SIZE_MAX on overflow
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
 * Evict oldest entries to make room for new_size bytes.
 * @return Number of entries evicted
 */
extern size_t
qpack_table_evict (SocketQPACK_Table_T table, size_t required_space);

#endif /* SOCKETQPACK_PRIVATE_INCLUDED */
