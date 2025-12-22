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
  char *name;
  size_t name_len;
  char *value;
  size_t value_len;
} HPACK_DynamicEntry;
struct SocketHPACK_Table
{
  HPACK_DynamicEntry *entries;
  size_t capacity;
  size_t head;
  size_t tail;
  size_t count;
  size_t size;
  size_t max_size;
  Arena_T arena;
};

extern int SocketHPACK_Table_find (SocketHPACK_Table_T table, const char *name,
                                   size_t name_len, const char *value, size_t value_len);
struct SocketHPACK_Encoder
{
  SocketHPACK_Table_T table;
  size_t pending_table_sizes[2];
  int pending_table_size_count;
  int huffman_encode;
  int use_indexing;
  Arena_T arena;
};
struct SocketHPACK_Decoder
{
  SocketHPACK_Table_T table;
  size_t max_header_size;
  size_t max_header_list_size;
  size_t settings_max_table_size;
  Arena_T arena;
  uint64_t decode_input_bytes;
  uint64_t decode_output_bytes;
  double max_expansion_ratio;
};
typedef struct
{
  const char *name;
  const char *value;
  uint8_t name_len;
  uint8_t value_len;
} HPACK_StaticEntry;
typedef struct
{
  uint32_t code;
  uint8_t bits;
} HPACK_HuffmanSymbol;
typedef struct
{
  uint8_t next_state;
  uint8_t flags;
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

extern size_t hpack_table_evict (SocketHPACK_Table_T table,
                                 size_t required_space);

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
