/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDeflate-huffman.c
 * @brief RFC 1951 canonical Huffman decoder.
 *
 * Builds decode tables from code lengths per RFC 1951 Section 3.2.2.
 * Uses a two-level lookup table for fast decoding:
 * - Primary table (9 bits): Direct lookup for common short codes
 * - Secondary tables: For codes > 9 bits
 *
 * DEFLATE Huffman codes are canonical:
 * - All codes of a given length have consecutive values
 * - Shorter codes precede longer codes lexicographically
 * - Codes are stored MSB-first in the RFC but appear LSB-first in the stream
 */

#include "deflate/SocketDeflate.h"

#include "core/Arena.h"
#include "core/SocketUtil.h"

#include <string.h>

/* Primary lookup table size (9 bits = 512 entries) */
#define HUFFMAN_FAST_BITS 9
#define HUFFMAN_FAST_SIZE (1 << HUFFMAN_FAST_BITS)
#define HUFFMAN_FAST_MASK (HUFFMAN_FAST_SIZE - 1)

/* Secondary table marker (must be > DEFLATE_MAX_BITS to distinguish from codes) */
#define HUFFMAN_SECONDARY_MARKER 16

/* Maximum secondary table entries (for codes 10-15 bits) */
#define HUFFMAN_MAX_SECONDARY_BITS (DEFLATE_MAX_BITS - HUFFMAN_FAST_BITS)
#define HUFFMAN_MAX_SECONDARY_SIZE (1 << HUFFMAN_MAX_SECONDARY_BITS)

/**
 * Huffman table entry.
 *
 * For primary table:
 * - 1 <= bits <= 15: Direct decode, symbol is the decoded value
 * - bits == 16 (HUFFMAN_SECONDARY_MARKER): Secondary table, symbol is index
 * - bits == 0: Unused/invalid entry
 *
 * For secondary table:
 * - bits > 0: Direct decode
 * - bits == 0: Invalid code
 */
typedef struct
{
  uint16_t symbol; /* Decoded symbol or secondary table index */
  uint8_t bits;    /* Code length (0 = secondary/invalid) */
} HuffmanEntry;

/**
 * Huffman table structure.
 */
struct SocketDeflate_HuffmanTable
{
  HuffmanEntry *primary;          /* Primary lookup table (512 entries) */
  HuffmanEntry *secondary;        /* Secondary tables for long codes */
  unsigned int secondary_count;   /* Number of secondary sub-tables */
  unsigned int secondary_size;    /* Total secondary entries allocated */
  unsigned int max_bits;          /* Maximum code length in this table */
  unsigned int num_codes;         /* Number of valid codes */
  Arena_T arena;                  /* Memory arena */
};

/* Global fixed tables (initialized once) */
static SocketDeflate_HuffmanTable_T fixed_litlen_table = NULL;
static SocketDeflate_HuffmanTable_T fixed_dist_table = NULL;
static int fixed_tables_initialized = 0;

/*
 * Internal: Count codes per length.
 *
 * @param lengths  Array of code lengths
 * @param count    Number of symbols
 * @param bl_count Output: count of codes per length (0-15)
 */
static void
count_code_lengths (const uint8_t *lengths, unsigned int count,
                    unsigned int bl_count[DEFLATE_MAX_BITS + 1])
{
  unsigned int i;

  memset (bl_count, 0, (DEFLATE_MAX_BITS + 1) * sizeof (unsigned int));

  for (i = 0; i < count; i++)
    {
      if (lengths[i] <= DEFLATE_MAX_BITS)
        bl_count[lengths[i]]++;
    }
}

/*
 * Internal: Validate Huffman tree.
 *
 * Checks that the code lengths define a valid prefix-free code:
 * - Not over-subscribed (sum of 2^(-len) > 1 is invalid)
 *
 * Under-subscribed trees (incomplete) are allowed for decoders.
 * Unused bit patterns will simply return DEFLATE_ERROR_INVALID_CODE.
 *
 * @param bl_count  Count of codes per length
 * @param max_bits  Maximum code length to consider
 * @return DEFLATE_OK if valid, DEFLATE_ERROR_HUFFMAN_TREE if over-subscribed
 */
static SocketDeflate_Result
validate_huffman_tree (const unsigned int bl_count[DEFLATE_MAX_BITS + 1],
                       unsigned int max_bits)
{
  unsigned int left;
  unsigned int bits;

  /* Start with all slots available at max_bits depth */
  left = 1;

  for (bits = 1; bits <= max_bits; bits++)
    {
      /* Each level doubles the available codes */
      left <<= 1;

      /* Subtract codes used at this level */
      if (bl_count[bits] > left)
        {
          /* Over-subscribed tree - invalid */
          return DEFLATE_ERROR_HUFFMAN_TREE;
        }
      left -= bl_count[bits];
    }

  /* Under-subscribed (left > 0) is OK for decode tables.
   * The decoder will return DEFLATE_ERROR_INVALID_CODE for
   * bit patterns not assigned to any symbol. */

  return DEFLATE_OK;
}

/*
 * Internal: Compute first code for each length (RFC 1951 §3.2.2 step 2).
 *
 * @param bl_count   Count of codes per length
 * @param max_bits   Maximum code length
 * @param next_code  Output: first code for each length
 */
static void
compute_first_codes (const unsigned int bl_count[DEFLATE_MAX_BITS + 1],
                     unsigned int max_bits,
                     unsigned int next_code[DEFLATE_MAX_BITS + 1])
{
  unsigned int code = 0;
  unsigned int bits;

  next_code[0] = 0;

  for (bits = 1; bits <= max_bits; bits++)
    {
      code = (code + bl_count[bits - 1]) << 1;
      next_code[bits] = code;
    }
}

/*
 * Internal: Fill primary table entry.
 *
 * For codes <= HUFFMAN_FAST_BITS, fill multiple entries:
 * The code is left-padded with all possible suffixes.
 *
 * @param table     The Huffman table
 * @param code      The canonical code (MSB-first)
 * @param bits      Code length
 * @param symbol    Symbol to decode
 */
static void
fill_primary_entry (SocketDeflate_HuffmanTable_T table, unsigned int code,
                    unsigned int bits, unsigned int symbol)
{
  unsigned int reversed;
  unsigned int fill;
  unsigned int step;
  unsigned int i;

  /* Reverse code for LSB-first lookup */
  reversed = SocketDeflate_reverse_bits (code, bits);

  /* Fill all entries with this prefix */
  fill = 1U << bits;
  step = fill;

  for (i = reversed; i < HUFFMAN_FAST_SIZE; i += step)
    {
      table->primary[i].symbol = (uint16_t)symbol;
      table->primary[i].bits = (uint8_t)bits;
    }
}

/*
 * Internal: Build secondary table for long codes.
 *
 * Called for codes > HUFFMAN_FAST_BITS bits. Creates a sub-table
 * indexed by the remaining bits after the first HUFFMAN_FAST_BITS.
 *
 * @param table         The Huffman table
 * @param prefix        First HUFFMAN_FAST_BITS bits of reversed code
 * @param reversed_code Full code bit-reversed for LSB-first lookup
 * @param bits          Total code length
 * @param symbol        Symbol to decode
 * @return DEFLATE_OK on success
 */
static SocketDeflate_Result
add_secondary_entry (SocketDeflate_HuffmanTable_T table, unsigned int prefix,
                     unsigned int reversed_code, unsigned int bits,
                     unsigned int symbol)
{
  unsigned int secondary_idx;
  unsigned int secondary_bits;
  unsigned int secondary_index;
  unsigned int fill;
  unsigned int step;
  unsigned int i;
  HuffmanEntry *secondary_table;

  /* Check if we already have a secondary table for this prefix */
  if (table->primary[prefix].bits == HUFFMAN_SECONDARY_MARKER)
    {
      /* Use existing secondary table */
      secondary_idx = table->primary[prefix].symbol;
    }
  else
    {
      /* Create new secondary table */
      secondary_idx = table->secondary_count++;

      /* Initialize primary entry to point to secondary */
      table->primary[prefix].symbol = (uint16_t)secondary_idx;
      table->primary[prefix].bits = HUFFMAN_SECONDARY_MARKER;

      /* Initialize secondary table entries to invalid */
      secondary_table
          = &table->secondary[secondary_idx * HUFFMAN_MAX_SECONDARY_SIZE];
      for (i = 0; i < HUFFMAN_MAX_SECONDARY_SIZE; i++)
        {
          secondary_table[i].symbol = 0;
          secondary_table[i].bits = 0;
        }
    }

  /* Compute secondary lookup index from remaining bits */
  secondary_bits = bits - HUFFMAN_FAST_BITS;
  secondary_index = reversed_code >> HUFFMAN_FAST_BITS;

  /* Get secondary table pointer */
  secondary_table
      = &table->secondary[secondary_idx * HUFFMAN_MAX_SECONDARY_SIZE];

  /* Fill entries */
  fill = 1U << secondary_bits;
  step = fill;

  for (i = secondary_index; i < HUFFMAN_MAX_SECONDARY_SIZE; i += step)
    {
      secondary_table[i].symbol = (uint16_t)symbol;
      secondary_table[i].bits = (uint8_t)bits;
    }

  return DEFLATE_OK;
}

/*
 * Public API Implementation
 */

SocketDeflate_HuffmanTable_T
SocketDeflate_HuffmanTable_new (Arena_T arena)
{
  SocketDeflate_HuffmanTable_T table;

  table = ALLOC (arena, sizeof (*table));

  /* Allocate primary table */
  table->primary = ALLOC (arena, HUFFMAN_FAST_SIZE * sizeof (HuffmanEntry));

  /* Allocate space for secondary tables
   * Maximum: one secondary table per primary entry (worst case) */
  table->secondary
      = ALLOC (arena, HUFFMAN_FAST_SIZE * HUFFMAN_MAX_SECONDARY_SIZE
                          * sizeof (HuffmanEntry));

  table->secondary_count = 0;
  table->secondary_size = HUFFMAN_FAST_SIZE * HUFFMAN_MAX_SECONDARY_SIZE;
  table->max_bits = 0;
  table->num_codes = 0;
  table->arena = arena;

  return table;
}

SocketDeflate_Result
SocketDeflate_HuffmanTable_build (SocketDeflate_HuffmanTable_T table,
                                  const uint8_t *lengths, unsigned int count,
                                  unsigned int max_bits)
{
  unsigned int bl_count[DEFLATE_MAX_BITS + 1];
  unsigned int next_code[DEFLATE_MAX_BITS + 1];
  SocketDeflate_Result result;
  unsigned int i;
  unsigned int symbol;
  unsigned int code;
  unsigned int len;
  unsigned int prefix;

  /* Validate max_bits */
  if (max_bits > DEFLATE_MAX_BITS)
    max_bits = DEFLATE_MAX_BITS;

  /* Count codes per length */
  count_code_lengths (lengths, count, bl_count);

  /* Validate tree structure */
  result = validate_huffman_tree (bl_count, max_bits);
  if (result != DEFLATE_OK)
    return result;

  /* Initialize primary table to invalid */
  for (i = 0; i < HUFFMAN_FAST_SIZE; i++)
    {
      table->primary[i].symbol = 0;
      table->primary[i].bits = 0;
    }

  /* Reset secondary tables */
  table->secondary_count = 0;

  /* Compute first codes */
  compute_first_codes (bl_count, max_bits, next_code);

  /* Assign codes and fill tables (RFC 1951 §3.2.2 step 3) */
  table->max_bits = 0;
  table->num_codes = 0;

  for (symbol = 0; symbol < count; symbol++)
    {
      len = lengths[symbol];

      if (len == 0)
        continue; /* Symbol not used */

      if (len > max_bits)
        return DEFLATE_ERROR_HUFFMAN_TREE;

      /* Get canonical code */
      code = next_code[len]++;

      /* Track maximum bits */
      if (len > table->max_bits)
        table->max_bits = len;

      table->num_codes++;

      if (len <= HUFFMAN_FAST_BITS)
        {
          /* Short code: fill primary table */
          fill_primary_entry (table, code, len, symbol);
        }
      else
        {
          /* Long code: need secondary table */
          /* Reverse full code, then extract lower 9 bits for primary index */
          unsigned int reversed_code = SocketDeflate_reverse_bits (code, len);
          prefix = reversed_code & HUFFMAN_FAST_MASK;

          result
              = add_secondary_entry (table, prefix, reversed_code, len, symbol);
          if (result != DEFLATE_OK)
            return result;
        }
    }

  /* If no codes, set max_bits to 1 to avoid peek(0) */
  if (table->max_bits == 0)
    table->max_bits = 1;

  return DEFLATE_OK;
}

SocketDeflate_Result
SocketDeflate_HuffmanTable_decode (SocketDeflate_HuffmanTable_T table,
                                   SocketDeflate_BitReader_T reader,
                                   uint16_t *symbol)
{
  uint32_t bits;
  HuffmanEntry entry;
  SocketDeflate_Result result;
  unsigned int primary_idx;
  unsigned int secondary_idx;
  HuffmanEntry *secondary_table;
  unsigned int remaining_bits;

  /* Peek enough bits for longest code */
  result = SocketDeflate_BitReader_peek (reader, table->max_bits, &bits);
  if (result == DEFLATE_INCOMPLETE)
    {
      /* Try with available bits - might still be enough for shorter codes */
      size_t avail = SocketDeflate_BitReader_bits_available (reader);
      if (avail == 0)
        return DEFLATE_INCOMPLETE;

      result = SocketDeflate_BitReader_peek (reader, (unsigned int)avail,
                                             &bits);
      if (result != DEFLATE_OK)
        return result;
    }

  /* Primary table lookup */
  primary_idx = bits & HUFFMAN_FAST_MASK;
  entry = table->primary[primary_idx];

  if (entry.bits > 0 && entry.bits <= DEFLATE_MAX_BITS)
    {
      /* Fast path: code found in primary table */
      *symbol = entry.symbol;
      SocketDeflate_BitReader_consume (reader, entry.bits);
      return DEFLATE_OK;
    }

  if (entry.bits == HUFFMAN_SECONDARY_MARKER)
    {
      /* Slow path: use secondary table */
      secondary_idx = entry.symbol;
      secondary_table
          = &table->secondary[secondary_idx * HUFFMAN_MAX_SECONDARY_SIZE];

      /* Index with remaining bits */
      remaining_bits = (bits >> HUFFMAN_FAST_BITS) & (HUFFMAN_MAX_SECONDARY_SIZE - 1);
      entry = secondary_table[remaining_bits];

      if (entry.bits > 0)
        {
          *symbol = entry.symbol;
          SocketDeflate_BitReader_consume (reader, entry.bits);
          return DEFLATE_OK;
        }
    }

  /* Invalid code */
  return DEFLATE_ERROR_INVALID_CODE;
}

void
SocketDeflate_HuffmanTable_reset (SocketDeflate_HuffmanTable_T table)
{
  unsigned int i;

  /* Reset primary table */
  for (i = 0; i < HUFFMAN_FAST_SIZE; i++)
    {
      table->primary[i].symbol = 0;
      table->primary[i].bits = 0;
    }

  table->secondary_count = 0;
  table->max_bits = 0;
  table->num_codes = 0;
}

/*
 * Fixed Huffman Tables
 */

SocketDeflate_Result
SocketDeflate_fixed_tables_init (Arena_T arena)
{
  SocketDeflate_Result result;

  if (fixed_tables_initialized)
    return DEFLATE_OK;

  /* Create fixed literal/length table */
  fixed_litlen_table = SocketDeflate_HuffmanTable_new (arena);
  result = SocketDeflate_HuffmanTable_build (
      fixed_litlen_table, deflate_fixed_litlen_lengths, DEFLATE_LITLEN_CODES,
      DEFLATE_MAX_BITS);

  if (result != DEFLATE_OK)
    return result;

  /* Create fixed distance table */
  fixed_dist_table = SocketDeflate_HuffmanTable_new (arena);
  result = SocketDeflate_HuffmanTable_build (
      fixed_dist_table, deflate_fixed_dist_lengths, DEFLATE_DIST_CODES,
      DEFLATE_MAX_BITS);

  if (result != DEFLATE_OK)
    return result;

  fixed_tables_initialized = 1;

  return DEFLATE_OK;
}

SocketDeflate_HuffmanTable_T
SocketDeflate_get_fixed_litlen_table (void)
{
  return fixed_litlen_table;
}

SocketDeflate_HuffmanTable_T
SocketDeflate_get_fixed_dist_table (void)
{
  return fixed_dist_table;
}
