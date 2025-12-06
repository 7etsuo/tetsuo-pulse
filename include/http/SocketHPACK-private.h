/**
 * SocketHPACK-private.h - HPACK Internal Structures and Constants
 *
 * Part of the Socket Library
 *
 * Internal header for HPACK implementation. Do not include directly.
 */

#ifndef SOCKETHPACK_PRIVATE_INCLUDED
#define SOCKETHPACK_PRIVATE_INCLUDED

#include "http/SocketHPACK.h"
#include <stdint.h>

/* ============================================================================
 * Internal Constants
 * ============================================================================ */

/** Estimated average dynamic entry size for initial capacity calculation (bytes) */
#define HPACK_AVERAGE_DYNAMIC_ENTRY_SIZE 50

/** Minimum dynamic table capacity (power-of-2 for efficient modulo) */
#define HPACK_MIN_DYNAMIC_TABLE_CAPACITY 16

/** Number of symbols in Huffman table (0-255 + EOS) */
#define HPACK_HUFFMAN_SYMBOLS 257

/** EOS symbol code */
#define HPACK_HUFFMAN_EOS 256

/** Maximum Huffman code length in bits */
#define HPACK_HUFFMAN_MAX_BITS 30

/** Number of states in Huffman DFA decode table */
#define HPACK_HUFFMAN_NUM_STATES 256

/** Invalid DFA state (error) */
#define HPACK_HUFFMAN_STATE_ERROR 0xFF

/** Accept state marker */
#define HPACK_HUFFMAN_STATE_ACCEPT 0xFE

/* ============================================================================
 * Dynamic Table Entry
 * ============================================================================ */

/**
 * Dynamic table entry
 *
 * Stored in circular buffer. Strings are allocated from arena.
 */
typedef struct
{
  char *name;       /**< Header name (arena-allocated) */
  size_t name_len;  /**< Name length */
  char *value;      /**< Header value (arena-allocated) */
  size_t value_len; /**< Value length */
} HPACK_DynamicEntry;

/* ============================================================================
 * Dynamic Table Structure
 * ============================================================================ */

/**
 * Dynamic table implementation
 *
 * Uses circular buffer for O(1) FIFO operations.
 * Index 1 = most recently added (tail-1)
 * Higher indices = older entries toward head
 */
struct SocketHPACK_Table
{
  HPACK_DynamicEntry *entries; /**< Ring buffer of entries */
  size_t capacity;             /**< Max entries (power of 2) */
  size_t head;                 /**< Oldest entry index */
  size_t tail;                 /**< Next insertion index */
  size_t count;                /**< Current entry count */
  size_t size;                 /**< Current size in bytes */
  size_t max_size;             /**< Maximum size from settings */
  Arena_T arena;               /**< Memory arena */
};

/* ============================================================================
 * Encoder Structure
 * ============================================================================ */

/**
 * HPACK encoder implementation
 */
struct SocketHPACK_Encoder
{
  SocketHPACK_Table_T table;       /**< Dynamic table */
  size_t pending_table_size;       /**< Pending size update (0 = none) */
  int pending_table_size_update;   /**< Flag for pending update */
  int huffman_encode;              /**< Use Huffman encoding */
  int use_indexing;                /**< Add to dynamic table */
  Arena_T arena;                   /**< Memory arena */
};

/* ============================================================================
 * Decoder Structure
 * ============================================================================ */

/**
 * HPACK decoder implementation
 */
struct SocketHPACK_Decoder
{
  SocketHPACK_Table_T table;       /**< Dynamic table */
  size_t max_header_size;          /**< Max individual header size */
  size_t max_header_list_size;     /**< Max total decoded size */
  size_t settings_max_table_size;  /**< Max size from SETTINGS */
  Arena_T arena;                   /**< Memory arena */
};

/* ============================================================================
 * Static Table Entry
 * ============================================================================ */

/**
 * Static table entry structure
 * Field order optimized to minimize padding (pointers first, then integers)
 */
typedef struct
{
  const char *name;  /**< Header name (compile-time string) */
  const char *value; /**< Header value (compile-time string) */
  uint8_t name_len;  /**< Name length */
  uint8_t value_len; /**< Value length */
} HPACK_StaticEntry;

/* ============================================================================
 * Huffman Tables (defined in SocketHPACK-huffman.c)
 * ============================================================================ */

/**
 * Huffman encode table entry
 */
typedef struct
{
  uint32_t code; /**< Huffman code (left-aligned in 32 bits) */
  uint8_t bits;  /**< Number of bits in code */
} HPACK_HuffmanSymbol;

/**
 * Huffman DFA transition entry
 *
 * For each input byte, provides next state and output.
 */
typedef struct
{
  uint8_t next_state; /**< Next DFA state */
  uint8_t flags;      /**< HPACK_DFA_* flags */
  uint8_t sym;        /**< Output symbol (if accepting) */
} HPACK_HuffmanTransition;

/** DFA flags */
#define HPACK_DFA_ACCEPT 0x01   /**< State produces output */
#define HPACK_DFA_EOS    0x02   /**< EOS symbol encountered */
#define HPACK_DFA_ERROR  0x04   /**< Invalid sequence */
#define HPACK_DFA_SYM2   0x08   /**< Second symbol available */

/* External declarations for Huffman tables */
extern const HPACK_HuffmanSymbol hpack_huffman_encode[HPACK_HUFFMAN_SYMBOLS];
extern const HPACK_HuffmanTransition
    hpack_huffman_decode[HPACK_HUFFMAN_NUM_STATES][16];

/* External declaration for static table */
extern const HPACK_StaticEntry hpack_static_table[SOCKETHPACK_STATIC_TABLE_SIZE];

/* ============================================================================
 * Internal Functions
 * ============================================================================ */

/**
 * hpack_table_evict - Evict oldest entries until size fits
 * @table: Dynamic table
 * @required_space: Space needed for new entry
 *
 * Returns: Number of entries evicted
 */
extern size_t hpack_table_evict (SocketHPACK_Table_T table,
                                 size_t required_space);

/**
 * hpack_entry_size - Calculate entry size per RFC 7541
 * @name_len: Header name length
 * @value_len: Header value length
 *
 * Returns: Entry size including 32-byte overhead
 */
static inline size_t
hpack_entry_size (size_t name_len, size_t value_len)
{
  return name_len + value_len + SOCKETHPACK_ENTRY_OVERHEAD;
}

#endif /* SOCKETHPACK_PRIVATE_INCLUDED */

