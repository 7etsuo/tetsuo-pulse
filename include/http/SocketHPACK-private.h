/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHPACK-private.h
 * @brief Internal HPACK header compression structures and constants.
 * @internal
 *
 * Private implementation for HPACK (RFC 7541). Use SocketHPACK.h for public API.
 */

#ifndef SOCKETHPACK_PRIVATE_INCLUDED
#define SOCKETHPACK_PRIVATE_INCLUDED

#include "http/SocketHPACK.h"
#include <stdint.h>

#include "core/SocketSecurity.h"

#define HPACK_AVERAGE_DYNAMIC_ENTRY_SIZE 50
#define HPACK_MIN_DYNAMIC_TABLE_CAPACITY 16
#define HPACK_HUFFMAN_SYMBOLS 257
#define HPACK_HUFFMAN_EOS 256
#define HPACK_HUFFMAN_MAX_BITS 30
#define HPACK_HUFFMAN_NUM_STATES 256
#define HPACK_HUFFMAN_STATE_ERROR 0xFF
#define HPACK_HUFFMAN_STATE_ACCEPT 0xFE
typedef struct
{
  char *name;       /**< Header name (arena-allocated) */
  size_t name_len;  /**< Name length */
  char *value;      /**< Header value (arena-allocated) */
  size_t value_len;
} HPACK_DynamicEntry;
struct SocketHPACK_Table
{
  HPACK_DynamicEntry *entries; /**< Ring buffer of dynamic entries */
  size_t capacity;             /**< Maximum number of entries (power-of-2) */
  size_t head;                 /**< Index of oldest entry */
  size_t tail;     /**< Index for next insertion (one past newest) */
  size_t count;    /**< Current number of entries */
  size_t size;     /**< Current total size in bytes (sum of entry sizes) */
  size_t max_size; /**< Maximum allowed size in bytes (from settings) */
  Arena_T arena;
};

/* Find exact or name-only match in dynamic table */
extern int SocketHPACK_Table_find (SocketHPACK_Table_T table, const char *name,
                                   size_t name_len, const char *value, size_t value_len);
struct SocketHPACK_Encoder
{
  SocketHPACK_Table_T
      table; /**< Dynamic table shared with decoder if symmetric */
  size_t
      pending_table_sizes[2]; /**< Pending dynamic table size updates (RFC 7541 §4.2) */
  int pending_table_size_count; /**< Number of pending table size updates (0-2) */
  int huffman_encode; /**< Flag to enable Huffman coding for strings */
  int use_indexing;   /**< Flag to enable dynamic table indexing */
  Arena_T arena;
};
struct SocketHPACK_Decoder
{
  SocketHPACK_Table_T table; /**< Dynamic table for header field references */
  size_t
      max_header_size; /**< Maximum size for a single decoded header field */
  size_t max_header_list_size; /**< Maximum size for the entire header list */
  size_t settings_max_table_size; /**< Maximum dynamic table size from peer
                                     SETTINGS */
  Arena_T arena;                  /**< Arena for decoded header allocations */

  /* Decompression bomb protection */
  uint64_t decode_input_bytes; /**< Cumulative input bytes processed in current
                                  session */
  uint64_t decode_output_bytes; /**< Cumulative output bytes produced in
                                   current session */
  double max_expansion_ratio;
};
typedef struct
{
  const char *name;  /**< Header field name (compile-time constant string) */
  const char *value; /**< Header field value (compile-time constant string) */
  uint8_t name_len;  /**< Length of name in bytes */
  uint8_t value_len;
} HPACK_StaticEntry;
typedef struct
{
  uint32_t code; /**< Huffman code bits (left-aligned in 32-bit integer) */
  uint8_t bits;
} HPACK_HuffmanSymbol;
typedef struct
{
  uint8_t next_state; /**< Next state in DFA (or special values like
                         error/accept) */
  uint8_t flags;      /**< Bit flags controlling output and error handling
                         (HPACK_DFA_*) */
  uint8_t sym;
} HPACK_HuffmanTransition;

#define HPACK_DFA_ACCEPT 0x01
#define HPACK_DFA_EOS 0x02
#define HPACK_DFA_ERROR 0x04
#define HPACK_DFA_SYM2 0x08

extern const HPACK_HuffmanSymbol hpack_huffman_encode[HPACK_HUFFMAN_SYMBOLS];
extern const HPACK_HuffmanTransition
    hpack_huffman_decode[HPACK_HUFFMAN_NUM_STATES][16];
extern const HPACK_StaticEntry
    hpack_static_table[SOCKETHPACK_STATIC_TABLE_SIZE];

/* Evict oldest entries from dynamic table */
extern size_t hpack_table_evict (SocketHPACK_Table_T table,
                                 size_t required_space);

/* Calculate dynamic table entry size */
static inline size_t
hpack_entry_size (size_t name_len, size_t value_len)
{
  size_t temp;
  if (SocketSecurity_check_add (name_len, value_len, &temp)
      && SocketSecurity_check_add (temp, SOCKETHPACK_ENTRY_OVERHEAD, &temp))
    {
      return temp;
    }
  return SIZE_MAX;
}

#endif /* SOCKETHPACK_PRIVATE_INCLUDED */
