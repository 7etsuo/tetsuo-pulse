/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDeflate-deflate.c
 * @brief RFC 1951 DEFLATE compression API.
 *
 * Implements streaming DEFLATE compression with:
 * - Compression levels 0-9
 * - Automatic block type selection (stored, fixed, dynamic)
 * - LZ77 string matching with lazy matching
 * - Huffman code generation
 *
 * Key design decisions:
 * - Block-based processing with 32KB window
 * - Level 0 uses stored blocks only
 * - Level 1-3 use fixed Huffman codes (faster)
 * - Level 4-9 use dynamic Huffman codes (better compression)
 * - Lazy matching enabled for levels 4+
 */

#include "deflate/SocketDeflate.h"

#include "core/Arena.h"

#include <string.h>

/*
 * Compression Level Parameters
 *
 * Each level configures:
 * - chain_limit: Maximum hash chain traversal (more = better compression)
 * - lazy_match: Enable lazy matching (look ahead for longer matches)
 * - good_length: Reduce lazy search if match >= this length
 * - nice_length: Stop search if match >= this length
 * - use_dynamic: Prefer dynamic Huffman codes over fixed
 */
typedef struct
{
  int chain_limit;
  int lazy_match;
  int good_length;
  int nice_length;
  int use_dynamic;
} DeflateConfig;

static const DeflateConfig level_config[10] = {
  /* Level 0: Store only (no compression) */
  { 0, 0, 0, 0, 0 },
  /* Level 1: Fastest - minimal chaining, fixed Huffman */
  { 4, 0, 4, 8, 0 },
  /* Level 2: Fast */
  { 8, 0, 8, 16, 0 },
  /* Level 3: Fast */
  { 16, 0, 16, 32, 0 },
  /* Level 4: Moderate - enable lazy matching, dynamic Huffman */
  { 32, 1, 16, 64, 1 },
  /* Level 5: Moderate */
  { 64, 1, 32, 128, 1 },
  /* Level 6: Default (balanced) */
  { 128, 1, 32, 128, 1 },
  /* Level 7: High compression */
  { 256, 1, 64, 256, 1 },
  /* Level 8: Higher compression */
  { 512, 1, 128, 258, 1 },
  /* Level 9: Best compression - maximum effort */
  { 4096, 1, 258, 258, 1 },
};

/*
 * Block size limit: 32KB (matches window size)
 * Stored blocks limited to 65535 bytes per RFC 1951
 */
#define DEFLATE_BLOCK_SIZE 32768
#define DEFLATE_STORED_MAX 65535

/* Maximum overhead per block: header + worst case expansion */
#define DEFLATE_BLOCK_OVERHEAD 11

/*
 * Deflater State
 */
typedef enum
{
  DEFLATE_STATE_INIT,     /* Ready for input */
  DEFLATE_STATE_BLOCK,    /* Processing a block */
  DEFLATE_STATE_FLUSH,    /* Flushing output */
  DEFLATE_STATE_FINISHED, /* Stream complete */
} DeflateState;

/**
 * Deflater structure.
 *
 * Manages compression state including:
 * - Input buffering
 * - LZ77 matching
 * - Symbol frequency collection
 * - Huffman code generation
 * - Bit stream output
 */
struct SocketDeflate_Deflater
{
  Arena_T arena;
  int level;
  DeflateState state;

  /* Input buffer (up to 2 * window for back-references) */
  uint8_t *window;
  size_t window_size;
  size_t window_pos;  /* Current position in window */
  size_t block_start; /* Start of current block in window */

  /* LZ77 matcher */
  SocketDeflate_Matcher_T matcher;

  /* Symbol frequencies for Huffman code generation */
  uint32_t litlen_freq[DEFLATE_LITLEN_CODES];
  uint32_t dist_freq[DEFLATE_DISTANCE_CODES];

  /* Generated Huffman codes */
  SocketDeflate_HuffmanCode litlen_codes[DEFLATE_LITLEN_CODES];
  SocketDeflate_HuffmanCode dist_codes[DEFLATE_DISTANCE_CODES];
  uint8_t litlen_lengths[DEFLATE_LITLEN_CODES];
  uint8_t dist_lengths[DEFLATE_DISTANCE_CODES];

  /* LZ77 output buffer (symbols to encode) */
  uint16_t *lz77_literals;  /* Literal bytes (0-255) or match lengths (3-258) */
  uint16_t *lz77_distances; /* Distance (0 for literal, 1-32768 for match) */
  size_t lz77_count;
  size_t lz77_capacity;

  /* Bit writer */
  SocketDeflate_BitWriter_T writer;

  /* Statistics */
  size_t total_in;
  size_t total_out;

  /* Configuration from level */
  DeflateConfig config;
};

/*
 * Forward declarations for internal functions
 */
static void deflater_reset_block (SocketDeflate_Deflater_T def);
static SocketDeflate_Result
deflater_encode_block (SocketDeflate_Deflater_T def, int final);
static SocketDeflate_BlockType choose_block_type (SocketDeflate_Deflater_T def);
static SocketDeflate_Result
encode_stored_block (SocketDeflate_Deflater_T def, int final);
static SocketDeflate_Result
encode_fixed_block (SocketDeflate_Deflater_T def, int final);
static SocketDeflate_Result
encode_dynamic_block (SocketDeflate_Deflater_T def, int final);
static void lz77_compress_block (SocketDeflate_Deflater_T def);

/*
 * Public API Implementation
 */

SocketDeflate_Deflater_T
SocketDeflate_Deflater_new (Arena_T arena, int level)
{
  SocketDeflate_Deflater_T def;

  /* Clamp level to valid range */
  if (level < 0)
    level = 0;
  if (level > 9)
    level = 9;

  def = ALLOC (arena, sizeof (*def));
  if (!def)
    return NULL;

  def->arena = arena;
  def->level = level;
  def->state = DEFLATE_STATE_INIT;
  def->config = level_config[level];

  /* Allocate window (2 * WINDOW_SIZE for overlap) */
  def->window_size = 2 * DEFLATE_WINDOW_SIZE;
  def->window = ALLOC (arena, def->window_size);
  def->window_pos = 0;
  def->block_start = 0;

  /* Create LZ77 matcher */
  def->matcher = SocketDeflate_Matcher_new (arena);
  SocketDeflate_Matcher_set_limits (def->matcher,
                                    def->config.chain_limit,
                                    def->config.good_length,
                                    def->config.nice_length);

  /* Allocate LZ77 output buffer */
  def->lz77_capacity = DEFLATE_BLOCK_SIZE + 1;
  def->lz77_literals = ALLOC (arena, def->lz77_capacity * sizeof (uint16_t));
  def->lz77_distances = ALLOC (arena, def->lz77_capacity * sizeof (uint16_t));
  def->lz77_count = 0;

  /* Create bit writer (will be initialized with output buffer) */
  def->writer = SocketDeflate_BitWriter_new (arena);

  /* Initialize statistics */
  def->total_in = 0;
  def->total_out = 0;

  /* Reset block state */
  deflater_reset_block (def);

  return def;
}

SocketDeflate_Result
SocketDeflate_Deflater_deflate (SocketDeflate_Deflater_T def,
                                const uint8_t *input,
                                size_t input_len,
                                size_t *consumed,
                                uint8_t *output,
                                size_t output_len,
                                size_t *written)
{
  size_t input_consumed = 0;
  size_t output_written = 0;

  *consumed = 0;
  *written = 0;

  if (def->state == DEFLATE_STATE_FINISHED)
    return DEFLATE_OK;

  /* Initialize bit writer with output buffer */
  SocketDeflate_BitWriter_init (def->writer, output, output_len);

  while (input_consumed < input_len)
    {
      size_t copy_size;
      size_t available;

      /* Copy input to window */
      available = def->window_size - def->window_pos;
      copy_size = input_len - input_consumed;
      if (copy_size > available)
        copy_size = available;

      /* Limit to block size */
      if (def->window_pos - def->block_start + copy_size > DEFLATE_BLOCK_SIZE)
        copy_size = DEFLATE_BLOCK_SIZE - (def->window_pos - def->block_start);

      if (copy_size > 0)
        {
          memcpy (
              def->window + def->window_pos, input + input_consumed, copy_size);
          def->window_pos += copy_size;
          input_consumed += copy_size;
          def->total_in += copy_size;
        }

      /*
       * Note: We don't write intermediate blocks during deflate because
       * the bit stream might not end on a byte boundary, and the next
       * call (to finish) uses a different output buffer. This limits
       * streaming to window_size bytes, but ensures correctness.
       *
       * For truly streaming compression with very large inputs, a more
       * sophisticated approach would be needed.
       */
      if (def->window_pos >= def->window_size)
        {
          /* Window is full - can't accept more data */
          break;
        }
    }

  output_written = SocketDeflate_BitWriter_size (def->writer);
  *consumed = input_consumed;
  *written = output_written;
  def->total_out += output_written;

  return DEFLATE_OK;
}

SocketDeflate_Result
SocketDeflate_Deflater_finish (SocketDeflate_Deflater_T def,
                               uint8_t *output,
                               size_t output_len,
                               size_t *written)
{
  SocketDeflate_Result res;
  size_t output_written;

  *written = 0;

  if (def->state == DEFLATE_STATE_FINISHED)
    return DEFLATE_OK;

  /* Initialize bit writer with output buffer */
  SocketDeflate_BitWriter_init (def->writer, output, output_len);

  /* Encode remaining data as final block */
  res = deflater_encode_block (def, 1);
  if (res != DEFLATE_OK)
    {
      *written = SocketDeflate_BitWriter_size (def->writer);
      def->total_out += *written;
      return res;
    }

  /* Flush any remaining bits */
  output_written = SocketDeflate_BitWriter_flush (def->writer);
  *written = output_written;
  def->total_out += output_written;
  def->state = DEFLATE_STATE_FINISHED;

  return DEFLATE_OK;
}

SocketDeflate_Result
SocketDeflate_Deflater_sync_flush (SocketDeflate_Deflater_T def,
                                   uint8_t *output,
                                   size_t output_len,
                                   size_t *written)
{
  SocketDeflate_Result res;
  size_t output_written;

  *written = 0;

  if (def->state == DEFLATE_STATE_FINISHED)
    return DEFLATE_OK;

  /* Initialize bit writer with output buffer */
  SocketDeflate_BitWriter_init (def->writer, output, output_len);

  /* Encode buffered data as non-final block (BFINAL=0) */
  res = deflater_encode_block (def, 0);
  if (res != DEFLATE_OK)
    {
      *written = SocketDeflate_BitWriter_size (def->writer);
      def->total_out += *written;
      return res;
    }

  /* Write sync flush marker: empty stored block producing 0x00 0x00 0xFF 0xFF
   */
  output_written = SocketDeflate_BitWriter_sync_flush (def->writer);
  *written = output_written;
  def->total_out += output_written;

  /* Keep state for context takeover - don't mark as finished */
  /* Reset block state but preserve window for future messages */
  def->block_start = def->window_pos;

  return DEFLATE_OK;
}

int
SocketDeflate_Deflater_finished (SocketDeflate_Deflater_T def)
{
  return def->state == DEFLATE_STATE_FINISHED;
}

void
SocketDeflate_Deflater_reset (SocketDeflate_Deflater_T def)
{
  def->state = DEFLATE_STATE_INIT;
  def->window_pos = 0;
  def->block_start = 0;
  def->total_in = 0;
  def->total_out = 0;
  def->lz77_count = 0;

  SocketDeflate_Matcher_init (def->matcher, def->window, 0);
  deflater_reset_block (def);
}

size_t
SocketDeflate_Deflater_total_out (SocketDeflate_Deflater_T def)
{
  return def->total_out;
}

size_t
SocketDeflate_Deflater_total_in (SocketDeflate_Deflater_T def)
{
  return def->total_in;
}

size_t
SocketDeflate_compress_bound (size_t input_len)
{
  /*
   * Worst case: stored blocks only
   * Each stored block: 5 bytes header + 65535 bytes data
   * Final overhead: 5 bytes for empty final block
   */
  size_t num_blocks = (input_len + DEFLATE_STORED_MAX - 1) / DEFLATE_STORED_MAX;
  if (num_blocks == 0)
    num_blocks = 1; /* At least one block */

  return input_len + (num_blocks * 5) + 5;
}

/*
 * Internal Functions
 */

static void
deflater_reset_block (SocketDeflate_Deflater_T def)
{
  /* Clear frequency tables */
  memset (def->litlen_freq, 0, sizeof (def->litlen_freq));
  memset (def->dist_freq, 0, sizeof (def->dist_freq));

  /* End-of-block symbol is always present */
  def->litlen_freq[DEFLATE_END_OF_BLOCK] = 1;

  /* Clear LZ77 buffer */
  def->lz77_count = 0;
}

/*
 * Emit a literal byte to the LZ77 buffer.
 */
static void
emit_literal (SocketDeflate_Deflater_T def, uint8_t byte)
{
  def->lz77_literals[def->lz77_count] = byte;
  def->lz77_distances[def->lz77_count] = 0;
  def->litlen_freq[byte]++;
  def->lz77_count++;
}

/*
 * Emit a length/distance match to the LZ77 buffer.
 * Updates frequency tables for Huffman code generation.
 */
static void
emit_match (SocketDeflate_Deflater_T def,
            unsigned int length,
            unsigned int distance)
{
  unsigned int len_code, dist_code, extra, extra_bits;

  def->lz77_literals[def->lz77_count] = length;
  def->lz77_distances[def->lz77_count] = distance;

  SocketDeflate_encode_length (length, &len_code, &extra, &extra_bits);
  def->litlen_freq[len_code]++;

  SocketDeflate_encode_distance (distance, &dist_code, &extra, &extra_bits);
  def->dist_freq[dist_code]++;

  def->lz77_count++;
}

/*
 * Insert positions covered by a match into the hash table.
 */
static void
insert_match_positions (SocketDeflate_Deflater_T def,
                        size_t pos,
                        size_t length,
                        size_t end)
{
  for (size_t i = pos; i < pos + length && i + DEFLATE_MIN_MATCH <= end; i++)
    SocketDeflate_Matcher_insert (def->matcher, i);
}

/*
 * Check if lazy matching should defer the current match.
 */
static int
should_defer_match (SocketDeflate_Deflater_T def,
                    size_t pos,
                    unsigned int match_length)
{
  if (!def->config.lazy_match)
    return 0;
  if (match_length >= (unsigned int)def->config.good_length)
    return 0;
  return SocketDeflate_Matcher_should_defer (def->matcher, pos, match_length);
}

/*
 * LZ77 Compression Pass
 *
 * Scans the input block and produces a sequence of:
 * - Literal bytes (0-255)
 * - Length/distance pairs (length 3-258, distance 1-32768)
 *
 * Also collects symbol frequencies for Huffman code generation.
 */
static void
lz77_compress_block (SocketDeflate_Deflater_T def)
{
  size_t pos = def->block_start;
  size_t end = def->window_pos;
  size_t max_lz77 = def->lz77_capacity - 1;

  SocketDeflate_Matcher_init (def->matcher, def->window, end);

  while (pos < end && def->lz77_count < max_lz77)
    {
      /* Level 0: no compression, literals only */
      if (def->level == 0)
        {
          emit_literal (def, def->window[pos]);
          pos++;
          continue;
        }

      /* Try to find a match */
      SocketDeflate_Match match;
      int found = (pos + DEFLATE_MIN_MATCH <= end)
                      ? SocketDeflate_Matcher_find (def->matcher, pos, &match)
                      : 0;

      if (found && match.length >= DEFLATE_MIN_MATCH)
        {
          /* Check for lazy matching - defer if better match at next position */
          if (should_defer_match (def, pos, match.length))
            {
              emit_literal (def, def->window[pos]);
              SocketDeflate_Matcher_insert (def->matcher, pos);
              pos++;
              continue;
            }

          emit_match (def, match.length, match.distance);
          insert_match_positions (def, pos, match.length, end);
          pos += match.length;
        }
      else
        {
          emit_literal (def, def->window[pos]);
          if (pos + DEFLATE_MIN_MATCH <= end)
            SocketDeflate_Matcher_insert (def->matcher, pos);
          pos++;
        }
    }
}

/*
 * Choose the best block type based on data characteristics.
 *
 * Returns:
 * - STORED: For level 0 or if data is incompressible
 * - FIXED: For small blocks or levels 1-3
 * - DYNAMIC: For larger blocks with good compression potential
 */
static SocketDeflate_BlockType
choose_block_type (SocketDeflate_Deflater_T def)
{
  size_t block_size = def->window_pos - def->block_start;

  /* Level 0 always uses stored blocks */
  if (def->level == 0)
    return DEFLATE_BLOCK_STORED;

  /* Very small blocks: stored is often better */
  if (block_size < 128)
    return DEFLATE_BLOCK_STORED;

  /* Levels 1-3 prefer fixed Huffman for speed */
  if (!def->config.use_dynamic)
    return DEFLATE_BLOCK_FIXED;

  /* Levels 4-9 use dynamic Huffman for better compression */
  return DEFLATE_BLOCK_DYNAMIC;
}

/*
 * Encode the current block to the output stream.
 */
static SocketDeflate_Result
deflater_encode_block (SocketDeflate_Deflater_T def, int final)
{
  SocketDeflate_BlockType btype;
  SocketDeflate_Result res;
  size_t block_size = def->window_pos - def->block_start;

  /* Nothing to encode */
  if (block_size == 0 && !final)
    return DEFLATE_OK;

  /* Run LZ77 compression pass */
  lz77_compress_block (def);

  /* Choose block type */
  btype = choose_block_type (def);

  /* Encode based on block type */
  switch (btype)
    {
    case DEFLATE_BLOCK_STORED:
      res = encode_stored_block (def, final);
      break;
    case DEFLATE_BLOCK_FIXED:
      res = encode_fixed_block (def, final);
      break;
    case DEFLATE_BLOCK_DYNAMIC:
      res = encode_dynamic_block (def, final);
      break;
    default:
      res = DEFLATE_ERROR;
      break;
    }

  if (res == DEFLATE_OK)
    {
      def->block_start = def->window_pos;
      deflater_reset_block (def);
    }

  return res;
}

/*
 * Encode a stored block (BTYPE=00).
 *
 * Format: BFINAL(1) + BTYPE(2) + align + LEN(16) + NLEN(16) + data
 */
static SocketDeflate_Result
encode_stored_block (SocketDeflate_Deflater_T def, int final)
{
  size_t block_size = def->window_pos - def->block_start;
  size_t offset = 0;

  while (offset < block_size)
    {
      size_t chunk = block_size - offset;
      if (chunk > DEFLATE_STORED_MAX)
        chunk = DEFLATE_STORED_MAX;

      int is_final = final && (offset + chunk >= block_size);

      /* Write block header: BFINAL + BTYPE=00 */
      SocketDeflate_BitWriter_write (def->writer, is_final ? 1 : 0, 1);
      SocketDeflate_BitWriter_write (def->writer, DEFLATE_BLOCK_STORED, 2);

      /* Align to byte boundary */
      SocketDeflate_BitWriter_align (def->writer);

      /* Write LEN and NLEN */
      uint16_t len = (uint16_t)chunk;
      uint16_t nlen = ~len;
      SocketDeflate_BitWriter_write (def->writer, len, 16);
      SocketDeflate_BitWriter_write (def->writer, nlen, 16);

      /* Write data bytes */
      for (size_t i = 0; i < chunk; i++)
        {
          SocketDeflate_BitWriter_write (
              def->writer, def->window[def->block_start + offset + i], 8);
        }

      offset += chunk;
    }

  /* Handle empty final block */
  if (block_size == 0 && final)
    {
      SocketDeflate_BitWriter_write (def->writer, 1, 1);
      SocketDeflate_BitWriter_write (def->writer, DEFLATE_BLOCK_STORED, 2);
      SocketDeflate_BitWriter_align (def->writer);
      SocketDeflate_BitWriter_write (def->writer, 0, 16);
      SocketDeflate_BitWriter_write (def->writer, 0xFFFF, 16);
    }

  return DEFLATE_OK;
}

/*
 * Write a symbol using fixed Huffman codes.
 */
static void
write_fixed_litlen (SocketDeflate_BitWriter_T writer, unsigned int symbol)
{
  /* Fixed Huffman code lengths per RFC 1951 §3.2.6 */
  if (symbol <= 143)
    {
      /* 0-143: 8 bits (00110000 - 10111111) */
      SocketDeflate_BitWriter_write_huffman (writer, 0x30 + symbol, 8);
    }
  else if (symbol <= 255)
    {
      /* 144-255: 9 bits (110010000 - 111111111) */
      SocketDeflate_BitWriter_write_huffman (writer, 0x190 + (symbol - 144), 9);
    }
  else if (symbol <= 279)
    {
      /* 256-279: 7 bits (0000000 - 0010111) */
      SocketDeflate_BitWriter_write_huffman (writer, symbol - 256, 7);
    }
  else
    {
      /* 280-287: 8 bits (11000000 - 11000111) */
      SocketDeflate_BitWriter_write_huffman (writer, 0xC0 + (symbol - 280), 8);
    }
}

static void
write_fixed_dist (SocketDeflate_BitWriter_T writer, unsigned int code)
{
  /* All distance codes are 5 bits in fixed Huffman */
  SocketDeflate_BitWriter_write_huffman (writer, code, 5);
}

/*
 * Encode a fixed Huffman block (BTYPE=01).
 */
static SocketDeflate_Result
encode_fixed_block (SocketDeflate_Deflater_T def, int final)
{
  /* Write block header: BFINAL + BTYPE=01 */
  SocketDeflate_BitWriter_write (def->writer, final ? 1 : 0, 1);
  SocketDeflate_BitWriter_write (def->writer, DEFLATE_BLOCK_FIXED, 2);

  /* Encode LZ77 symbols */
  for (size_t i = 0; i < def->lz77_count; i++)
    {
      uint16_t value = def->lz77_literals[i];
      uint16_t distance = def->lz77_distances[i];

      if (distance == 0)
        {
          /* Literal byte */
          write_fixed_litlen (def->writer, value);
        }
      else
        {
          /* Length/distance pair */
          /* value contains match length (3-258), distance contains back
           * distance */
          unsigned int len_code, len_extra, len_extra_bits;
          unsigned int dist_code, dist_extra, dist_extra_bits;

          /* Encode length */
          SocketDeflate_encode_length (
              value, &len_code, &len_extra, &len_extra_bits);

          /* Write length code */
          write_fixed_litlen (def->writer, len_code);

          /* Write length extra bits */
          if (len_extra_bits > 0)
            SocketDeflate_BitWriter_write (
                def->writer, len_extra, len_extra_bits);

          /* Encode distance */
          SocketDeflate_encode_distance (
              distance, &dist_code, &dist_extra, &dist_extra_bits);

          /* Write distance code (5 bits for fixed Huffman) */
          write_fixed_dist (def->writer, dist_code);

          /* Write distance extra bits */
          if (dist_extra_bits > 0)
            SocketDeflate_BitWriter_write (
                def->writer, dist_extra, dist_extra_bits);
        }
    }

  /* Write end-of-block */
  write_fixed_litlen (def->writer, DEFLATE_END_OF_BLOCK);

  return DEFLATE_OK;
}

/*
 * Count the number of codes actually used (highest non-zero length + 1).
 */
static unsigned int
count_used_codes (const uint8_t *lengths,
                  unsigned int max_count,
                  unsigned int min_count)
{
  unsigned int count = min_count;

  for (unsigned int i = min_count; i < max_count; i++)
    {
      if (lengths[i] > 0)
        count = i + 1;
    }

  return count;
}

/*
 * Write the dynamic Huffman table header.
 */
static void
write_dynamic_header (SocketDeflate_Deflater_T def,
                      unsigned int hlit,
                      unsigned int hdist,
                      unsigned int hclen,
                      const uint8_t *cl_lengths)
{
  /* Write HLIT, HDIST, HCLEN */
  SocketDeflate_BitWriter_write (def->writer, hlit - 257, 5);
  SocketDeflate_BitWriter_write (def->writer, hdist - 1, 5);
  SocketDeflate_BitWriter_write (def->writer, hclen - 4, 4);

  /* Write code length code lengths in permuted order */
  for (unsigned int i = 0; i < hclen; i++)
    {
      unsigned int idx = deflate_codelen_order[i];
      SocketDeflate_BitWriter_write (def->writer, cl_lengths[idx], 3);
    }
}

/*
 * Write RLE-encoded code lengths using the code length Huffman table.
 */
static void
write_encoded_lengths (SocketDeflate_BitWriter_T writer,
                       const SocketDeflate_HuffmanCode *cl_codes,
                       const uint8_t *encoded,
                       size_t encoded_len)
{
  for (size_t i = 0; i < encoded_len; i++)
    {
      uint8_t sym = encoded[i];

      /* Write the code length symbol */
      SocketDeflate_BitWriter_write_huffman (
          writer, cl_codes[sym].code, cl_codes[sym].len);

      /* Write extra bits for special symbols */
      if (sym == 16)
        {
          /* Copy previous: 2 extra bits (3-6 copies) */
          i++;
          if (i < encoded_len)
            SocketDeflate_BitWriter_write (writer, encoded[i], 2);
        }
      else if (sym == 17)
        {
          /* Repeat 0: 3 extra bits (3-10 zeros) */
          i++;
          if (i < encoded_len)
            SocketDeflate_BitWriter_write (writer, encoded[i], 3);
        }
      else if (sym == 18)
        {
          /* Repeat 0: 7 extra bits (11-138 zeros) */
          i++;
          if (i < encoded_len)
            SocketDeflate_BitWriter_write (writer, encoded[i], 7);
        }
    }
}

/*
 * Build dynamic Huffman tables from collected frequencies.
 */
static void
build_dynamic_huffman_tables (SocketDeflate_Deflater_T def)
{
  SocketDeflate_build_code_lengths (def->litlen_freq,
                                    def->litlen_lengths,
                                    DEFLATE_LITLEN_CODES,
                                    DEFLATE_MAX_BITS,
                                    def->arena);
  SocketDeflate_generate_codes (
      def->litlen_lengths, def->litlen_codes, DEFLATE_LITLEN_CODES);

  SocketDeflate_build_code_lengths (def->dist_freq,
                                    def->dist_lengths,
                                    DEFLATE_DISTANCE_CODES,
                                    DEFLATE_MAX_BITS,
                                    def->arena);
  SocketDeflate_generate_codes (
      def->dist_lengths, def->dist_codes, DEFLATE_DISTANCE_CODES);
}

/*
 * Count code length symbol frequencies from RLE-encoded data.
 */
static void
count_codelen_frequencies (const uint8_t *encoded,
                           size_t encoded_len,
                           uint32_t *cl_freq)
{
  for (size_t i = 0; i < encoded_len; i++)
    {
      uint8_t sym = encoded[i];
      if (sym <= 18)
        cl_freq[sym]++;

      /* Skip extra bits for special symbols */
      if (sym == 16 || sym == 17 || sym == 18)
        i++;
    }
}

/*
 * Write a single LZ77 literal using dynamic Huffman codes.
 */
static void
write_dynamic_literal (SocketDeflate_Deflater_T def, uint16_t value)
{
  SocketDeflate_BitWriter_write_huffman (
      def->writer, def->litlen_codes[value].code, def->litlen_codes[value].len);
}

/*
 * Write a single LZ77 length/distance match using dynamic Huffman codes.
 */
static void
write_dynamic_match (SocketDeflate_Deflater_T def,
                     uint16_t length,
                     uint16_t distance)
{
  unsigned int len_code, len_extra, len_extra_bits;
  unsigned int dist_code, dist_extra, dist_extra_bits;

  /* Encode and write length */
  SocketDeflate_encode_length (length, &len_code, &len_extra, &len_extra_bits);
  SocketDeflate_BitWriter_write_huffman (def->writer,
                                         def->litlen_codes[len_code].code,
                                         def->litlen_codes[len_code].len);
  if (len_extra_bits > 0)
    SocketDeflate_BitWriter_write (def->writer, len_extra, len_extra_bits);

  /* Encode and write distance */
  SocketDeflate_encode_distance (
      distance, &dist_code, &dist_extra, &dist_extra_bits);
  SocketDeflate_BitWriter_write_huffman (def->writer,
                                         def->dist_codes[dist_code].code,
                                         def->dist_codes[dist_code].len);
  if (dist_extra_bits > 0)
    SocketDeflate_BitWriter_write (def->writer, dist_extra, dist_extra_bits);
}

/*
 * Write all LZ77 symbols using dynamic Huffman codes.
 */
static void
write_lz77_symbols_dynamic (SocketDeflate_Deflater_T def)
{
  for (size_t i = 0; i < def->lz77_count; i++)
    {
      uint16_t value = def->lz77_literals[i];
      uint16_t distance = def->lz77_distances[i];

      if (distance == 0)
        write_dynamic_literal (def, value);
      else
        write_dynamic_match (def, value, distance);
    }

  /* Write end-of-block */
  write_dynamic_literal (def, DEFLATE_END_OF_BLOCK);
}

/*
 * Encode a dynamic Huffman block (BTYPE=10).
 */
static SocketDeflate_Result
encode_dynamic_block (SocketDeflate_Deflater_T def, int final)
{
  uint8_t combined_lengths[DEFLATE_LITLEN_CODES + DEFLATE_DIST_CODES];
  uint8_t encoded_lengths[DEFLATE_LITLEN_CODES + DEFLATE_DIST_CODES + 100];
  size_t encoded_len;
  uint32_t cl_freq[DEFLATE_CODELEN_CODES] = { 0 };
  uint8_t cl_lengths[DEFLATE_CODELEN_CODES] = { 0 };
  SocketDeflate_HuffmanCode cl_codes[DEFLATE_CODELEN_CODES];
  unsigned int hlit, hdist, hclen;

  /* Build Huffman codes from frequencies */
  build_dynamic_huffman_tables (def);

  /* Determine HLIT and HDIST */
  hlit = count_used_codes (def->litlen_lengths, DEFLATE_LITLEN_CODES, 257);
  hdist = count_used_codes (def->dist_lengths, DEFLATE_DISTANCE_CODES, 1);

  /* Combine litlen and distance lengths */
  memcpy (combined_lengths, def->litlen_lengths, hlit);
  memcpy (combined_lengths + hlit, def->dist_lengths, hdist);

  /* RLE-encode the combined lengths */
  encoded_len = SocketDeflate_encode_code_lengths (combined_lengths,
                                                   hlit + hdist,
                                                   encoded_lengths,
                                                   sizeof (encoded_lengths));

  /* Count code length symbol frequencies and build CL table */
  count_codelen_frequencies (encoded_lengths, encoded_len, cl_freq);
  SocketDeflate_build_code_lengths (
      cl_freq, cl_lengths, DEFLATE_CODELEN_CODES, 7, def->arena);
  SocketDeflate_generate_codes (cl_lengths, cl_codes, DEFLATE_CODELEN_CODES);

  /* Determine HCLEN */
  hclen = DEFLATE_CODELEN_CODES;
  while (hclen > 4 && cl_lengths[deflate_codelen_order[hclen - 1]] == 0)
    hclen--;

  /* Write block header: BFINAL + BTYPE=10 */
  SocketDeflate_BitWriter_write (def->writer, final ? 1 : 0, 1);
  SocketDeflate_BitWriter_write (def->writer, DEFLATE_BLOCK_DYNAMIC, 2);

  /* Write dynamic Huffman table header and code lengths */
  write_dynamic_header (def, hlit, hdist, hclen, cl_lengths);
  write_encoded_lengths (def->writer, cl_codes, encoded_lengths, encoded_len);

  /* Write LZ77 symbols */
  write_lz77_symbols_dynamic (def);

  return DEFLATE_OK;
}
