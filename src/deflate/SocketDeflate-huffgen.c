/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDeflate-huffgen.c
 * @brief RFC 1951 Huffman code generator for DEFLATE compression.
 *
 * Implements:
 * - Package-merge algorithm for length-limited Huffman codes
 * - Canonical code generation (RFC 1951 Section 3.2.2)
 * - RLE encoding for code length sequences (symbols 16-18)
 * - Length/distance code encoding (RFC 1951 Section 3.2.5)
 */

#include "deflate/SocketDeflate.h"

#include "core/Arena.h"

#include <stdlib.h>
#include <string.h>

/*
 * Package-Merge Algorithm Data Structures (Larmore & Hirschberg, 1990)
 *
 * The package-merge algorithm produces optimal length-limited Huffman codes.
 * It works by treating code length assignment as a coin collector's problem.
 */

/* Number of 32-bit words needed to store bit vector for up to 288 symbols */
#define PM_MASK_WORDS 9 /* ceil(288/32) = 9 */

/**
 * Package item: represents a symbol or merged pair with associated cost.
 * The symbol_mask tracks which symbols are included in this item.
 */
typedef struct
{
  uint64_t cost;                       /* Combined frequency (sort key) */
  uint32_t symbol_mask[PM_MASK_WORDS]; /* Bit vector for symbols */
} PackageItem;

/**
 * Merge list: holds items at one level of the algorithm.
 */
typedef struct
{
  PackageItem *items;
  unsigned int count;
} MergeList;

/*
 * Bit mask helpers for tracking which symbols are in a package.
 */

static inline void
mask_clear (uint32_t *mask)
{
  for (int i = 0; i < PM_MASK_WORDS; i++)
    mask[i] = 0;
}

static inline void
mask_set (uint32_t *mask, unsigned int sym)
{
  mask[sym / 32] |= (1U << (sym % 32));
}

static inline int
mask_test (const uint32_t *mask, unsigned int sym)
{
  return (mask[sym / 32] >> (sym % 32)) & 1;
}

/*
 * Compare items by cost for qsort (ascending order).
 */
static int
pm_compare (const void *va, const void *vb)
{
  const PackageItem *a = va;
  const PackageItem *b = vb;

  if (a->cost < b->cost)
    return -1;
  if (a->cost > b->cost)
    return 1;
  return 0;
}

/*
 * Build merge lists from bottom level (max_bits) up to level 1.
 *
 * At each level L:
 * 1. Create fresh coins for all symbols (cost = frequency)
 * 2. If L < max_bits: merge consecutive pairs from level L+1
 * 3. Sort all items by cost
 *
 * The items from lower levels propagate upward via merging.
 */
static void
pm_build_levels (MergeList *levels,
                 unsigned int max_bits,
                 const uint32_t *sorted_freq,
                 unsigned int num_symbols,
                 Arena_T arena)
{
  /* Maximum items per level: n coins + (n-1) merged = 2n-1 */
  unsigned int max_items = 2 * num_symbols;

  /* Allocate all levels */
  for (unsigned int L = 1; L <= max_bits; L++)
    {
      levels[L].items = ALLOC (arena, max_items * sizeof (PackageItem));
      levels[L].count = 0;
    }

  /* Build from bottom (max_bits) to top (1) */
  for (unsigned int L = max_bits; L >= 1; L--)
    {
      MergeList *cur = &levels[L];

      /* Add fresh coins for all symbols */
      for (unsigned int i = 0; i < num_symbols; i++)
        {
          PackageItem *item = &cur->items[cur->count++];
          item->cost = sorted_freq[i];
          mask_clear (item->symbol_mask);
          mask_set (item->symbol_mask, i);
        }

      /* Merge pairs from level below (if exists) */
      if (L < max_bits)
        {
          MergeList *below = &levels[L + 1];

          /* Merge consecutive pairs */
          for (unsigned int i = 0; i + 1 < below->count; i += 2)
            {
              const PackageItem *a = &below->items[i];
              const PackageItem *b = &below->items[i + 1];
              PackageItem *dst = &cur->items[cur->count++];

              dst->cost = a->cost + b->cost;
              for (int k = 0; k < PM_MASK_WORDS; k++)
                dst->symbol_mask[k] = a->symbol_mask[k] | b->symbol_mask[k];
            }
        }

      /* Sort by cost */
      qsort (cur->items, cur->count, sizeof (PackageItem), pm_compare);
    }
}

/*
 * Select 2*(n-1) smallest items from level 1 and count symbol occurrences.
 * Each symbol's code length = number of times it appears in selected items.
 */
static void
pm_extract_lengths (const MergeList *level1,
                    uint8_t *lengths,
                    const unsigned int *sorted_idx,
                    unsigned int num_symbols)
{
  /* Need 2*(n-1) items for n symbols */
  unsigned int need = 2 * (num_symbols - 1);

  /* Count how many times each symbol appears in selected items */
  unsigned int symbol_count[DEFLATE_LITLEN_CODES] = { 0 };

  for (unsigned int i = 0; i < need && i < level1->count; i++)
    {
      const PackageItem *item = &level1->items[i];

      /* Count all symbols in this item */
      for (unsigned int s = 0; s < num_symbols; s++)
        {
          if (mask_test (item->symbol_mask, s))
            symbol_count[s]++;
        }
    }

  /* Assign lengths based on counts */
  for (unsigned int i = 0; i < num_symbols; i++)
    {
      unsigned int orig_sym = sorted_idx[i];
      lengths[orig_sym] = (uint8_t)symbol_count[i];
    }
}

/*
 * Collect symbols with non-zero frequency into sorted arrays.
 * Returns the number of non-zero symbols found.
 */
static unsigned int
collect_nonzero_symbols (const uint32_t *freqs,
                         uint8_t *lengths,
                         unsigned int count,
                         uint32_t *sorted_freq,
                         unsigned int *sorted_idx)
{
  unsigned int num_symbols = 0;

  for (unsigned int i = 0; i < count; i++)
    {
      lengths[i] = 0;
      if (freqs[i] > 0)
        {
          sorted_freq[num_symbols] = freqs[i];
          sorted_idx[num_symbols] = i;
          num_symbols++;
        }
    }

  return num_symbols;
}

/*
 * Sort symbols by frequency (ascending) using bubble sort.
 */
static void
sort_by_frequency (uint32_t *sorted_freq,
                   unsigned int *sorted_idx,
                   unsigned int num_symbols)
{
  for (unsigned int i = 0; i < num_symbols - 1; i++)
    {
      for (unsigned int j = i + 1; j < num_symbols; j++)
        {
          if (sorted_freq[j] < sorted_freq[i])
            {
              uint32_t tmp_freq = sorted_freq[i];
              sorted_freq[i] = sorted_freq[j];
              sorted_freq[j] = tmp_freq;

              unsigned int tmp_idx = sorted_idx[i];
              sorted_idx[i] = sorted_idx[j];
              sorted_idx[j] = tmp_idx;
            }
        }
    }
}

/*
 * Build optimal code lengths using the package-merge algorithm.
 *
 * For DEFLATE's constraints (max 288 symbols, max 15 bits), this
 * produces optimal length-limited Huffman codes where more frequent
 * symbols get shorter codes.
 */
static void
build_lengths_limited (const uint32_t *freqs,
                       uint8_t *lengths,
                       unsigned int count,
                       unsigned int max_bits,
                       Arena_T arena)
{
  unsigned int num_symbols;
  uint32_t sorted_freq[DEFLATE_LITLEN_CODES];
  unsigned int sorted_idx[DEFLATE_LITLEN_CODES];
  MergeList levels[DEFLATE_MAX_BITS + 1];

  num_symbols = collect_nonzero_symbols (
      freqs, lengths, count, sorted_freq, sorted_idx);

  /* Handle special cases */
  if (num_symbols == 0)
    return;

  if (num_symbols == 1)
    {
      lengths[sorted_idx[0]] = 1;
      return;
    }

  if (num_symbols == 2)
    {
      lengths[sorted_idx[0]] = 1;
      lengths[sorted_idx[1]] = 1;
      return;
    }

  /* Sort by frequency (ascending) for package-merge */
  sort_by_frequency (sorted_freq, sorted_idx, num_symbols);

  /* Initialize levels array */
  memset (levels, 0, sizeof (levels));

  /* Build merge lists from level max_bits down to 1 */
  pm_build_levels (levels, max_bits, sorted_freq, num_symbols, arena);

  /* Select 2*(n-1) items from level 1, count symbol occurrences */
  pm_extract_lengths (&levels[1], lengths, sorted_idx, num_symbols);
}

/*
 * Public API Implementation
 */

SocketDeflate_Result
SocketDeflate_build_code_lengths (const uint32_t *freqs,
                                  uint8_t *lengths,
                                  unsigned int count,
                                  unsigned int max_bits,
                                  Arena_T arena)
{
  if (max_bits > DEFLATE_MAX_BITS)
    max_bits = DEFLATE_MAX_BITS;

  build_lengths_limited (freqs, lengths, count, max_bits, arena);

  return DEFLATE_OK;
}

void
SocketDeflate_generate_codes (const uint8_t *lengths,
                              SocketDeflate_HuffmanCode *codes,
                              unsigned int count)
{
  unsigned int bl_count[DEFLATE_MAX_BITS + 1] = { 0 };
  unsigned int next_code[DEFLATE_MAX_BITS + 1];
  unsigned int i;
  unsigned int bits;
  unsigned int code;

  /* Step 1: Count codes per length (RFC 1951 §3.2.2 step 1) */
  for (i = 0; i < count; i++)
    {
      if (lengths[i] > 0 && lengths[i] <= DEFLATE_MAX_BITS)
        bl_count[lengths[i]]++;
    }

  /* Step 2: Compute first code per length (RFC 1951 §3.2.2 step 2) */
  code = 0;
  bl_count[0] = 0;
  for (bits = 1; bits <= DEFLATE_MAX_BITS; bits++)
    {
      code = (code + bl_count[bits - 1]) << 1;
      next_code[bits] = code;
    }

  /* Step 3: Assign codes (RFC 1951 §3.2.2 step 3) */
  for (i = 0; i < count; i++)
    {
      codes[i].code = 0;
      codes[i].len = 0;

      if (lengths[i] > 0)
        {
          codes[i].code = next_code[lengths[i]]++;
          codes[i].len = lengths[i];
        }
    }
}

/*
 * Count consecutive zeros starting at position i.
 */
static unsigned int
count_zero_run (const uint8_t *lengths, unsigned int count, unsigned int i)
{
  unsigned int run = 1;

  while (i + run < count && lengths[i + run] == 0 && run < 138)
    run++;

  return run;
}

/*
 * Count consecutive copies of prev_len starting at position i.
 */
static unsigned int
count_repeat_run (const uint8_t *lengths,
                  unsigned int count,
                  unsigned int i,
                  uint8_t prev_len,
                  unsigned int max_run)
{
  unsigned int run = 0;

  while (i + run < count && lengths[i + run] == prev_len && run < max_run)
    run++;

  return run;
}

/*
 * Encode a run of zeros using symbols 17 or 18.
 */
static void
encode_zero_run (uint8_t *output,
                 size_t *out_pos,
                 size_t output_capacity,
                 unsigned int *i,
                 unsigned int run)
{
  if (run >= 11)
    {
      /* Symbol 18: repeat 0 for 11-138 times */
      output[(*out_pos)++] = DEFLATE_CODELEN_REPEAT_11;
      if (*out_pos < output_capacity)
        output[(*out_pos)++] = run - 11;
      *i += run;
    }
  else if (run >= 3)
    {
      /* Symbol 17: repeat 0 for 3-10 times */
      output[(*out_pos)++] = DEFLATE_CODELEN_REPEAT_3;
      if (*out_pos < output_capacity)
        output[(*out_pos)++] = run - 3;
      *i += run;
    }
  else
    {
      /* Emit zeros individually */
      while (run > 0 && *out_pos < output_capacity)
        {
          output[(*out_pos)++] = 0;
          run--;
          (*i)++;
        }
    }
}

/*
 * Encode a run of repeated lengths using symbol 16.
 */
static void
encode_repeat_run (uint8_t *output,
                   size_t *out_pos,
                   size_t output_capacity,
                   unsigned int *i,
                   uint8_t len,
                   unsigned int run)
{
  if (run >= 3)
    {
      /* Symbol 16: copy previous 3-6 times */
      output[(*out_pos)++] = DEFLATE_CODELEN_COPY_PREV;
      if (*out_pos < output_capacity)
        output[(*out_pos)++] = run - 3;
      *i += run;
    }
  else
    {
      /* Emit lengths individually */
      while (run > 0 && *out_pos < output_capacity)
        {
          output[(*out_pos)++] = len;
          run--;
          (*i)++;
        }
    }
}

size_t
SocketDeflate_encode_code_lengths (const uint8_t *lengths,
                                   unsigned int count,
                                   uint8_t *output,
                                   size_t output_capacity)
{
  size_t out_pos = 0;
  unsigned int i = 0;
  uint8_t prev_len = 0;

  while (i < count && out_pos < output_capacity)
    {
      uint8_t len = lengths[i];

      if (len == 0)
        {
          unsigned int run = count_zero_run (lengths, count, i);
          encode_zero_run (output, &out_pos, output_capacity, &i, run);
          prev_len = 0;
        }
      else if (len == prev_len && prev_len > 0)
        {
          unsigned int run = count_repeat_run (lengths, count, i, prev_len, 6);
          if (run == 0)
            run = 1; /* At least emit the current length */
          encode_repeat_run (output, &out_pos, output_capacity, &i, len, run);
        }
      else
        {
          /* Emit length literally */
          output[out_pos++] = len;
          prev_len = len;
          i++;

          /* Check for following copies we can encode with symbol 16 */
          if (out_pos < output_capacity && i < count && lengths[i] == len)
            {
              unsigned int run = count_repeat_run (lengths, count, i, len, 6);
              if (run >= 3)
                {
                  output[out_pos++] = DEFLATE_CODELEN_COPY_PREV;
                  if (out_pos < output_capacity)
                    output[out_pos++] = run - 3;
                  i += run;
                }
            }
        }
    }

  return out_pos;
}

/*
 * Length encoding table (RFC 1951 Section 3.2.5)
 *
 * Maps length (3-258) to code (257-285) and extra bits.
 * This is the inverse of deflate_length_table.
 */
static const struct
{
  uint16_t min_len;   /* Minimum length for this code */
  uint16_t code;      /* Length code (257-285) */
  uint8_t extra_bits; /* Number of extra bits */
} length_encode_table[] = {
  { 3, 257, 0 },   { 4, 258, 0 },   { 5, 259, 0 },   { 6, 260, 0 },
  { 7, 261, 0 },   { 8, 262, 0 },   { 9, 263, 0 },   { 10, 264, 0 },
  { 11, 265, 1 },  { 13, 266, 1 },  { 15, 267, 1 },  { 17, 268, 1 },
  { 19, 269, 2 },  { 23, 270, 2 },  { 27, 271, 2 },  { 31, 272, 2 },
  { 35, 273, 3 },  { 43, 274, 3 },  { 51, 275, 3 },  { 59, 276, 3 },
  { 67, 277, 4 },  { 83, 278, 4 },  { 99, 279, 4 },  { 115, 280, 4 },
  { 131, 281, 5 }, { 163, 282, 5 }, { 195, 283, 5 }, { 227, 284, 5 },
  { 258, 285, 0 },
};

#define LENGTH_ENCODE_TABLE_SIZE \
  (sizeof (length_encode_table) / sizeof (length_encode_table[0]))

void
SocketDeflate_encode_length (unsigned int length,
                             unsigned int *code_out,
                             unsigned int *extra_out,
                             unsigned int *extra_bits_out)
{
  unsigned int i;

  /* Clamp to valid range */
  if (length < DEFLATE_MIN_MATCH)
    length = DEFLATE_MIN_MATCH;
  if (length > DEFLATE_MAX_MATCH)
    length = DEFLATE_MAX_MATCH;

  /* Find the appropriate code */
  for (i = LENGTH_ENCODE_TABLE_SIZE - 1; i > 0; i--)
    {
      if (length >= length_encode_table[i].min_len)
        break;
    }

  *code_out = length_encode_table[i].code;
  *extra_bits_out = length_encode_table[i].extra_bits;
  *extra_out = length - length_encode_table[i].min_len;
}

/*
 * Distance encoding table (RFC 1951 Section 3.2.5)
 *
 * Maps distance (1-32768) to code (0-29) and extra bits.
 * This is the inverse of deflate_distance_table.
 */
static const struct
{
  uint16_t min_dist;  /* Minimum distance for this code */
  uint8_t code;       /* Distance code (0-29) */
  uint8_t extra_bits; /* Number of extra bits */
} distance_encode_table[] = {
  { 1, 0, 0 },       { 2, 1, 0 },       { 3, 2, 0 },      { 4, 3, 0 },
  { 5, 4, 1 },       { 7, 5, 1 },       { 9, 6, 2 },      { 13, 7, 2 },
  { 17, 8, 3 },      { 25, 9, 3 },      { 33, 10, 4 },    { 49, 11, 4 },
  { 65, 12, 5 },     { 97, 13, 5 },     { 129, 14, 6 },   { 193, 15, 6 },
  { 257, 16, 7 },    { 385, 17, 7 },    { 513, 18, 8 },   { 769, 19, 8 },
  { 1025, 20, 9 },   { 1537, 21, 9 },   { 2049, 22, 10 }, { 3073, 23, 10 },
  { 4097, 24, 11 },  { 6145, 25, 11 },  { 8193, 26, 12 }, { 12289, 27, 12 },
  { 16385, 28, 13 }, { 24577, 29, 13 },
};

#define DISTANCE_ENCODE_TABLE_SIZE \
  (sizeof (distance_encode_table) / sizeof (distance_encode_table[0]))

void
SocketDeflate_encode_distance (unsigned int distance,
                               unsigned int *code_out,
                               unsigned int *extra_out,
                               unsigned int *extra_bits_out)
{
  unsigned int i;

  /* Clamp to valid range */
  if (distance < 1)
    distance = 1;
  if (distance > DEFLATE_WINDOW_SIZE)
    distance = DEFLATE_WINDOW_SIZE;

  /* Find the appropriate code */
  for (i = DISTANCE_ENCODE_TABLE_SIZE - 1; i > 0; i--)
    {
      if (distance >= distance_encode_table[i].min_dist)
        break;
    }

  *code_out = distance_encode_table[i].code;
  *extra_bits_out = distance_encode_table[i].extra_bits;
  *extra_out = distance - distance_encode_table[i].min_dist;
}
