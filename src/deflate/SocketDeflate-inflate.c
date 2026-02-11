/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDeflate-inflate.c
 * @brief RFC 1951 streaming inflate (decompression) API.
 *
 * Implements the high-level inflate API for DEFLATE streams. This module
 * provides multi-block stream handling, sliding window management for
 * back-references across blocks, and security limits against decompression
 * bombs.
 *
 * The inflate state machine:
 * 1. HEADER - Reading BFINAL and BTYPE bits
 * 2. BLOCK - Decompressing block data (dispatches to stored/fixed/dynamic)
 * 3. DONE - Final block complete
 *
 * @see RFC 1951 Section 3.2.3 - Block format
 */

#include "deflate/SocketDeflate.h"

#include <string.h>

/* Bomb protection: maximum expansion ratio (output/input) */
#define DEFLATE_MAX_RATIO 1000

/* Inflater state machine states */
typedef enum
{
  INFLATE_STATE_HEADER, /* Reading block header (BFINAL, BTYPE) */
  INFLATE_STATE_BLOCK,  /* Decompressing block data */
  INFLATE_STATE_DONE    /* Final block complete */
} InflateState;

/**
 * Inflater structure.
 *
 * Maintains all state needed for streaming decompression.
 */
struct SocketDeflate_Inflater
{
  Arena_T arena;
  SocketDeflate_BitReader_T reader;

  /* State machine */
  InflateState state;

  /* Block state */
  int final_block; /* BFINAL flag from current block */
  int block_type;  /* BTYPE (0-3) */

  /* Stored block state (for streaming) */
  size_t stored_len;      /* Remaining bytes in stored block */
  int stored_header_read; /* Have we read the LEN/NLEN header? */

  /* Output tracking */
  uint8_t *window;     /* 32KB sliding window for cross-block back-refs */
  size_t window_pos;   /* Current position in window (circular) */
  size_t total_output; /* Total bytes output across all calls */

  /* Security limits */
  size_t max_output;  /* Max output size (0 = unlimited) */
  size_t total_input; /* Total bytes consumed */
};

/**
 * Create a new inflater.
 */
SocketDeflate_Inflater_T
SocketDeflate_Inflater_new (Arena_T arena, size_t max_output)
{
  SocketDeflate_Inflater_T inf;

  if (arena == NULL)
    return NULL;

  inf = Arena_alloc (arena, sizeof (*inf), __FILE__, __LINE__);
  if (inf == NULL)
    return NULL;

  inf->arena = arena;
  inf->reader = SocketDeflate_BitReader_new (arena);
  if (inf->reader == NULL)
    return NULL;

  /* Allocate 32KB sliding window */
  inf->window = Arena_alloc (arena, DEFLATE_WINDOW_SIZE, __FILE__, __LINE__);
  if (inf->window == NULL)
    return NULL;

  inf->state = INFLATE_STATE_HEADER;
  inf->final_block = 0;
  inf->block_type = 0;
  inf->stored_len = 0;
  inf->stored_header_read = 0;
  inf->window_pos = 0;
  inf->total_output = 0;
  inf->max_output = max_output;
  inf->total_input = 0;

  return inf;
}

/**
 * Reset inflater for reuse.
 */
void
SocketDeflate_Inflater_reset (SocketDeflate_Inflater_T inf)
{
  if (inf == NULL)
    return;

  inf->state = INFLATE_STATE_HEADER;
  inf->final_block = 0;
  inf->block_type = 0;
  inf->stored_len = 0;
  inf->stored_header_read = 0;
  inf->window_pos = 0;
  inf->total_output = 0;
  inf->total_input = 0;

  /* Clear window */
  memset (inf->window, 0, DEFLATE_WINDOW_SIZE);
}

/**
 * Check if decompression is complete.
 */
int
SocketDeflate_Inflater_finished (SocketDeflate_Inflater_T inf)
{
  if (inf == NULL)
    return 0;

  return inf->state == INFLATE_STATE_DONE;
}

/**
 * Get total bytes output.
 */
size_t
SocketDeflate_Inflater_total_out (SocketDeflate_Inflater_T inf)
{
  if (inf == NULL)
    return 0;

  return inf->total_output;
}

/**
 * Get total bytes consumed.
 */
size_t
SocketDeflate_Inflater_total_in (SocketDeflate_Inflater_T inf)
{
  if (inf == NULL)
    return 0;

  return inf->total_input;
}

/**
 * Get accurate bytes consumed from last inflate call.
 *
 * This accounts for pre-fetched bytes in the bit buffer that weren't
 * actually used by the decompressor. Useful when input contains data
 * after the DEFLATE stream (e.g., gzip trailer).
 */
size_t
SocketDeflate_Inflater_actual_consumed (SocketDeflate_Inflater_T inf)
{
  if (inf == NULL || inf->reader == NULL)
    return 0;

  return SocketDeflate_BitReader_bytes_consumed (inf->reader);
}

/**
 * Copy byte to output and sliding window.
 */
static void
output_byte (SocketDeflate_Inflater_T inf,
             uint8_t *output,
             size_t *out_pos,
             uint8_t byte)
{
  output[*out_pos] = byte;
  (*out_pos)++;

  /* Also copy to sliding window (circular buffer) */
  inf->window[inf->window_pos] = byte;
  inf->window_pos = (inf->window_pos + 1) & (DEFLATE_WINDOW_SIZE - 1);
  inf->total_output++;
}

/**
 * Copy bytes from sliding window history.
 *
 * Handles overlap case where distance < length (RFC 1951 §3.2.3).
 */
static SocketDeflate_Result
copy_from_window (SocketDeflate_Inflater_T inf,
                  uint8_t *output,
                  size_t *out_pos,
                  size_t out_len,
                  unsigned int length,
                  unsigned int distance)
{
  size_t src_pos;
  unsigned int i;

  /* Validate distance doesn't go before start of available history */
  if (distance > inf->total_output)
    return DEFLATE_ERROR_DISTANCE_TOO_FAR;

  /* Calculate source position in circular window */
  src_pos = (inf->window_pos + DEFLATE_WINDOW_SIZE - distance)
            & (DEFLATE_WINDOW_SIZE - 1);

  /* Copy byte-by-byte for correct overlap handling */
  for (i = 0; i < length && *out_pos < out_len; i++)
    {
      uint8_t byte = inf->window[src_pos];
      output_byte (inf, output, out_pos, byte);
      src_pos = (src_pos + 1) & (DEFLATE_WINDOW_SIZE - 1);
    }

  return DEFLATE_OK;
}

/**
 * Decode length value from length symbol.
 *
 * Reads extra bits if needed and computes the final length value.
 */
static SocketDeflate_Result
decode_length_value (SocketDeflate_BitReader_T reader,
                     uint16_t symbol,
                     unsigned int *length_out)
{
  unsigned int extra_bits;
  uint32_t extra_val = 0;
  SocketDeflate_Result result;

  result = SocketDeflate_get_length_extra_bits (symbol, &extra_bits);
  if (result != DEFLATE_OK)
    return result;

  if (extra_bits > 0)
    {
      result = SocketDeflate_BitReader_read (reader, extra_bits, &extra_val);
      if (result != DEFLATE_OK)
        return result;
    }

  return SocketDeflate_decode_length (symbol, extra_val, length_out);
}

/**
 * Decode distance value from distance code.
 *
 * Reads extra bits if needed and computes the final distance value.
 */
static SocketDeflate_Result
decode_distance_value (SocketDeflate_BitReader_T reader,
                       uint16_t dist_code,
                       unsigned int *distance_out)
{
  unsigned int extra_bits;
  uint32_t extra_val = 0;
  SocketDeflate_Result result;

  if (!SocketDeflate_is_valid_distance_code (dist_code))
    return DEFLATE_ERROR_INVALID_DISTANCE;

  result = SocketDeflate_get_distance_extra_bits (dist_code, &extra_bits);
  if (result != DEFLATE_OK)
    return result;

  if (extra_bits > 0)
    {
      result = SocketDeflate_BitReader_read (reader, extra_bits, &extra_val);
      if (result != DEFLATE_OK)
        return result;
    }

  return SocketDeflate_decode_distance (dist_code, extra_val, distance_out);
}

/**
 * Decode a back-reference (length/distance pair) and copy to output.
 *
 * Decodes the distance code, then copies from the sliding window.
 */
static SocketDeflate_Result
decode_backref (SocketDeflate_Inflater_T inf,
                SocketDeflate_HuffmanTable_T dist_table,
                uint16_t length_symbol,
                uint8_t *output,
                size_t *out_pos,
                size_t out_len)
{
  unsigned int length, distance;
  uint16_t dist_code;
  SocketDeflate_Result result;

  /* Decode length */
  result = decode_length_value (inf->reader, length_symbol, &length);
  if (result != DEFLATE_OK)
    return result;

  /* Decode distance code from bitstream */
  result
      = SocketDeflate_HuffmanTable_decode (dist_table, inf->reader, &dist_code);
  if (result != DEFLATE_OK)
    return result;

  /* Decode distance value */
  result = decode_distance_value (inf->reader, dist_code, &distance);
  if (result != DEFLATE_OK)
    return result;

  /* Copy from window history */
  return copy_from_window (inf, output, out_pos, out_len, length, distance);
}

/**
 * Shared LZ77 decode loop for Huffman blocks.
 *
 * Decodes literals, length/distance pairs, and handles end-of-block.
 */
static SocketDeflate_Result
lz77_decode_loop (SocketDeflate_Inflater_T inf,
                  SocketDeflate_HuffmanTable_T litlen_table,
                  SocketDeflate_HuffmanTable_T dist_table,
                  uint8_t *output,
                  size_t out_len,
                  size_t *written)
{
  size_t out_pos = 0;
  SocketDeflate_Result result;

  while (out_pos < out_len)
    {
      uint16_t symbol;
      result = SocketDeflate_HuffmanTable_decode (
          litlen_table, inf->reader, &symbol);
      if (result != DEFLATE_OK)
        {
          *written = out_pos;
          return result;
        }

      if (symbol < DEFLATE_END_OF_BLOCK)
        {
          /* Literal byte */
          output_byte (inf, output, &out_pos, (uint8_t)symbol);
        }
      else if (symbol == DEFLATE_END_OF_BLOCK)
        {
          /* End of block */
          *written = out_pos;
          return DEFLATE_OK;
        }
      else
        {
          /* Back-reference (length/distance pair) */
          result = decode_backref (
              inf, dist_table, symbol, output, &out_pos, out_len);
          if (result != DEFLATE_OK)
            {
              *written = out_pos;
              return result;
            }
        }
    }

  /* Output buffer full */
  *written = out_pos;
  return DEFLATE_OUTPUT_FULL;
}

/**
 * Decode run-length encoded code lengths for dynamic Huffman tables.
 *
 * Symbols 0-15 are literal code lengths.
 * Symbol 16: Copy previous length 3-6 times (2 extra bits)
 * Symbol 17: Repeat 0 for 3-10 times (3 extra bits)
 * Symbol 18: Repeat 0 for 11-138 times (7 extra bits)
 *
 * @param reader      Bit reader
 * @param codelen_table  Code length Huffman table
 * @param code_lengths   Output array for decoded code lengths
 * @param total_codes    Number of code lengths to decode
 * @return DEFLATE_OK on success, error code on failure
 */
static SocketDeflate_Result
decode_code_lengths (SocketDeflate_BitReader_T reader,
                     SocketDeflate_HuffmanTable_T codelen_table,
                     uint8_t *code_lengths,
                     size_t total_codes)
{
  size_t code_idx = 0;
  SocketDeflate_Result result;

  while (code_idx < total_codes)
    {
      uint16_t symbol;
      result
          = SocketDeflate_HuffmanTable_decode (codelen_table, reader, &symbol);
      if (result != DEFLATE_OK)
        return result;

      if (symbol < 16)
        {
          /* Direct code length */
          code_lengths[code_idx++] = (uint8_t)symbol;
        }
      else if (symbol == 16)
        {
          /* Copy previous length 3-6 times */
          uint32_t count;
          result = SocketDeflate_BitReader_read (reader, 2, &count);
          if (result != DEFLATE_OK)
            return result;
          count += 3;

          if (code_idx == 0)
            return DEFLATE_ERROR; /* No previous length */

          uint8_t prev = code_lengths[code_idx - 1];
          for (unsigned int i = 0; i < count && code_idx < total_codes; i++)
            code_lengths[code_idx++] = prev;
        }
      else if (symbol == 17)
        {
          /* Repeat 0 for 3-10 times */
          uint32_t count;
          result = SocketDeflate_BitReader_read (reader, 3, &count);
          if (result != DEFLATE_OK)
            return result;
          count += 3;

          for (unsigned int i = 0; i < count && code_idx < total_codes; i++)
            code_lengths[code_idx++] = 0;
        }
      else if (symbol == 18)
        {
          /* Repeat 0 for 11-138 times */
          uint32_t count;
          result = SocketDeflate_BitReader_read (reader, 7, &count);
          if (result != DEFLATE_OK)
            return result;
          count += 11;

          for (unsigned int i = 0; i < count && code_idx < total_codes; i++)
            code_lengths[code_idx++] = 0;
        }
      else
        {
          return DEFLATE_ERROR_INVALID_CODE;
        }
    }

  return DEFLATE_OK;
}

/**
 * Check decompression bomb limits.
 *
 * Two protection mechanisms:
 * 1. Absolute output limit (max_output)
 * 2. Expansion ratio limit (1000:1)
 *
 * @param inf             The inflater state
 * @param bytes_consumed  Bytes consumed in current call
 * @return DEFLATE_ERROR_BOMB if limits exceeded, DEFLATE_OK otherwise
 */
static SocketDeflate_Result
check_bomb_limits (SocketDeflate_Inflater_T inf, size_t bytes_consumed)
{
  /* Check absolute output limit */
  if (inf->max_output > 0 && inf->total_output > inf->max_output)
    return DEFLATE_ERROR_BOMB;

  /* Check expansion ratio limit.
   * Use multiplication on the smaller side to avoid the integer division
   * truncation that lets ratios of 999.x:1 slip past a 1000:1 check.
   * Guard the multiplication against overflow. */
  size_t total_input = inf->total_input + bytes_consumed;
  if (total_input > 0)
    {
      size_t safe_limit;
      if (__builtin_mul_overflow (total_input, DEFLATE_MAX_RATIO, &safe_limit))
        safe_limit = SIZE_MAX; /* overflow means any output is within ratio */
      if (inf->total_output > safe_limit)
        return DEFLATE_ERROR_BOMB;
    }

  return DEFLATE_OK;
}

/**
 * Decode stored block (BTYPE=00) with window tracking.
 *
 * Supports streaming: if output buffer fills before block is complete,
 * returns DEFLATE_OUTPUT_FULL and tracks remaining bytes for next call.
 */
static SocketDeflate_Result
inflate_stored (SocketDeflate_Inflater_T inf,
                uint8_t *output,
                size_t out_len,
                size_t *written)
{
  size_t out_pos = 0;
  SocketDeflate_Result result;

  /* Read LEN/NLEN header if not already read */
  if (!inf->stored_header_read)
    {
      uint32_t len, nlen;

      /* Align to byte boundary */
      SocketDeflate_BitReader_align (inf->reader);

      /* Read LEN (16 bits) */
      result = SocketDeflate_BitReader_read (inf->reader, 16, &len);
      if (result != DEFLATE_OK)
        return result;

      /* Read NLEN (16 bits) */
      result = SocketDeflate_BitReader_read (inf->reader, 16, &nlen);
      if (result != DEFLATE_OK)
        return result;

      /* Validate NLEN == ~LEN */
      if ((len ^ nlen) != 0xFFFF)
        return DEFLATE_ERROR;

      inf->stored_len = len;
      inf->stored_header_read = 1;
    }

  /* Copy literal bytes through window */
  while (inf->stored_len > 0 && out_pos < out_len)
    {
      uint8_t byte;
      result = SocketDeflate_BitReader_read_bytes (inf->reader, &byte, 1);
      if (result != DEFLATE_OK)
        {
          *written = out_pos;
          return result;
        }
      output_byte (inf, output, &out_pos, byte);
      inf->stored_len--;
    }

  *written = out_pos;

  /* Check if block is complete */
  if (inf->stored_len > 0)
    return DEFLATE_OUTPUT_FULL;

  /* Block complete, reset header state for next stored block */
  inf->stored_header_read = 0;
  return DEFLATE_OK;
}

/**
 * Decode fixed Huffman block (BTYPE=01) with window tracking.
 */
static SocketDeflate_Result
inflate_fixed (SocketDeflate_Inflater_T inf,
               uint8_t *output,
               size_t out_len,
               size_t *written)
{
  SocketDeflate_HuffmanTable_T litlen_table;
  SocketDeflate_HuffmanTable_T dist_table;

  /* Get pre-built fixed Huffman tables */
  litlen_table = SocketDeflate_get_fixed_litlen_table ();
  dist_table = SocketDeflate_get_fixed_dist_table ();

  if (litlen_table == NULL || dist_table == NULL)
    return DEFLATE_ERROR;

  return lz77_decode_loop (
      inf, litlen_table, dist_table, output, out_len, written);
}

/**
 * Read dynamic block header counts: HLIT, HDIST, HCLEN.
 *
 * RFC 1951 §3.2.7: These determine the number of codes in each alphabet.
 */
static SocketDeflate_Result
read_dynamic_counts (SocketDeflate_BitReader_T reader,
                     uint32_t *hlit,
                     uint32_t *hdist,
                     uint32_t *hclen)
{
  SocketDeflate_Result result;

  result = SocketDeflate_BitReader_read (reader, 5, hlit);
  if (result != DEFLATE_OK)
    return result;
  *hlit += 257;

  result = SocketDeflate_BitReader_read (reader, 5, hdist);
  if (result != DEFLATE_OK)
    return result;
  *hdist += 1;

  result = SocketDeflate_BitReader_read (reader, 4, hclen);
  if (result != DEFLATE_OK)
    return result;
  *hclen += 4;

  return DEFLATE_OK;
}

/**
 * Read code length code lengths in permuted order.
 *
 * RFC 1951 §3.2.7: The code length codes are transmitted in a specific
 * order to maximize the chance of short encodings.
 */
static SocketDeflate_Result
read_codelen_lengths (SocketDeflate_BitReader_T reader,
                      uint8_t *codelen_lengths,
                      uint32_t hclen)
{
  SocketDeflate_Result result;

  memset (codelen_lengths, 0, DEFLATE_CODELEN_CODES);

  for (unsigned int i = 0; i < hclen; i++)
    {
      uint32_t len;
      result = SocketDeflate_BitReader_read (reader, 3, &len);
      if (result != DEFLATE_OK)
        return result;
      codelen_lengths[deflate_codelen_order[i]] = (uint8_t)len;
    }

  return DEFLATE_OK;
}

/**
 * Build a Huffman table with error handling.
 *
 * Wrapper that handles allocation and build in one call.
 */
static SocketDeflate_Result
build_huffman_table (Arena_T arena,
                     SocketDeflate_HuffmanTable_T *table_out,
                     const uint8_t *code_lengths,
                     size_t num_codes,
                     unsigned int max_bits)
{
  SocketDeflate_HuffmanTable_T table;

  table = SocketDeflate_HuffmanTable_new (arena);
  if (table == NULL)
    return DEFLATE_ERROR;

  SocketDeflate_Result result = SocketDeflate_HuffmanTable_build (
      table, code_lengths, num_codes, max_bits);
  if (result != DEFLATE_OK)
    return result;

  *table_out = table;
  return DEFLATE_OK;
}

/**
 * Decode dynamic Huffman block (BTYPE=10) with window tracking.
 *
 * Parses the dynamic block header to build custom Huffman tables,
 * then decodes the compressed data using those tables.
 */
static SocketDeflate_Result
inflate_dynamic (SocketDeflate_Inflater_T inf,
                 uint8_t *output,
                 size_t out_len,
                 size_t *written)
{
  uint32_t hlit, hdist, hclen;
  uint8_t codelen_lengths[DEFLATE_CODELEN_CODES];
  uint8_t code_lengths[DEFLATE_LITLEN_CODES + DEFLATE_DIST_CODES];
  SocketDeflate_HuffmanTable_T codelen_table;
  SocketDeflate_HuffmanTable_T litlen_table;
  SocketDeflate_HuffmanTable_T dist_table;
  SocketDeflate_Result result;

  /* Step 1: Read header counts */
  result = read_dynamic_counts (inf->reader, &hlit, &hdist, &hclen);
  if (result != DEFLATE_OK)
    return result;

  /* Step 2: Read code length code lengths */
  result = read_codelen_lengths (inf->reader, codelen_lengths, hclen);
  if (result != DEFLATE_OK)
    return result;

  /* Step 3: Build code length Huffman table */
  result = build_huffman_table (
      inf->arena, &codelen_table, codelen_lengths, DEFLATE_CODELEN_CODES, 7);
  if (result != DEFLATE_OK)
    return result;

  /* Step 4: Decode literal/length and distance code lengths */
  memset (code_lengths, 0, sizeof (code_lengths));
  result = decode_code_lengths (
      inf->reader, codelen_table, code_lengths, hlit + hdist);
  if (result != DEFLATE_OK)
    return result;

  /* Step 5: Build literal/length Huffman table */
  result = build_huffman_table (
      inf->arena, &litlen_table, code_lengths, hlit, DEFLATE_MAX_BITS);
  if (result != DEFLATE_OK)
    return result;

  /* Step 6: Build distance Huffman table */
  result = build_huffman_table (
      inf->arena, &dist_table, code_lengths + hlit, hdist, DEFLATE_MAX_BITS);
  if (result != DEFLATE_OK)
    return result;

  /* Step 7: Decode compressed data */
  return lz77_decode_loop (
      inf, litlen_table, dist_table, output, out_len, written);
}

/**
 * Calculate bytes consumed from bit reader.
 *
 * Returns all bytes that have been loaded into the bit buffer, even if
 * some bits haven't been consumed yet. This is the appropriate behavior
 * for the streaming API since the BitReader is reinitialized each call.
 */
static size_t
get_bytes_consumed (SocketDeflate_BitReader_T reader, size_t input_len)
{
  return input_len - SocketDeflate_BitReader_bytes_remaining (reader);
}

/**
 * Finalize output parameters and update total input.
 */
static void
finalize_output (SocketDeflate_Inflater_T inf,
                 size_t input_len,
                 size_t *consumed,
                 size_t *written,
                 size_t total_written)
{
  *consumed = get_bytes_consumed (inf->reader, input_len);
  inf->total_input += *consumed;
  *written = total_written;
}

/**
 * Read and parse block header (BFINAL + BTYPE).
 *
 * Returns DEFLATE_OK on success, error code on failure.
 * On error, also sets output parameters.
 */
static SocketDeflate_Result
read_block_header (SocketDeflate_Inflater_T inf,
                   size_t input_len,
                   size_t *consumed,
                   size_t *written,
                   size_t total_written)
{
  uint32_t header;
  SocketDeflate_Result result;

  result = SocketDeflate_BitReader_read (inf->reader, 3, &header);
  if (result != DEFLATE_OK)
    {
      finalize_output (inf, input_len, consumed, written, total_written);
      return result;
    }

  inf->final_block = header & 1;
  inf->block_type = (header >> 1) & 3;

  if (inf->block_type == DEFLATE_BLOCK_RESERVED)
    {
      finalize_output (inf, input_len, consumed, written, total_written);
      return DEFLATE_ERROR_INVALID_BTYPE;
    }

  inf->state = INFLATE_STATE_BLOCK;
  return DEFLATE_OK;
}

/**
 * Dispatch to appropriate block decoder based on BTYPE.
 */
static SocketDeflate_Result
dispatch_block_decoder (SocketDeflate_Inflater_T inf,
                        uint8_t *output,
                        size_t output_len,
                        size_t *block_written)
{
  switch (inf->block_type)
    {
    case DEFLATE_BLOCK_STORED:
      return inflate_stored (inf, output, output_len, block_written);

    case DEFLATE_BLOCK_FIXED:
      return inflate_fixed (inf, output, output_len, block_written);

    case DEFLATE_BLOCK_DYNAMIC:
      return inflate_dynamic (inf, output, output_len, block_written);

    default:
      return DEFLATE_ERROR;
    }
}

/**
 * Update state after block decode completes successfully.
 */
static void
update_state_after_block (SocketDeflate_Inflater_T inf)
{
  if (inf->final_block)
    inf->state = INFLATE_STATE_DONE;
  else
    inf->state = INFLATE_STATE_HEADER;
}

/**
 * Main inflate function (streaming).
 */
SocketDeflate_Result
SocketDeflate_Inflater_inflate (SocketDeflate_Inflater_T inf,
                                const uint8_t *input,
                                size_t input_len,
                                size_t *consumed,
                                uint8_t *output,
                                size_t output_len,
                                size_t *written)
{
  SocketDeflate_Result result;
  size_t total_written = 0;

  /* Validate parameters */
  if (inf == NULL || consumed == NULL || written == NULL)
    return DEFLATE_ERROR;
  if (input == NULL && input_len > 0)
    return DEFLATE_ERROR;
  if (output == NULL && output_len > 0)
    return DEFLATE_ERROR;

  *consumed = 0;
  *written = 0;

  /* Already done? */
  if (inf->state == INFLATE_STATE_DONE)
    return DEFLATE_OK;

  /* Initialize bit reader with new input */
  SocketDeflate_BitReader_init (inf->reader, input, input_len);

  /* Main processing loop */
  while (inf->state != INFLATE_STATE_DONE && total_written < output_len)
    {
      /* Read block header if needed */
      if (inf->state == INFLATE_STATE_HEADER)
        {
          result = read_block_header (
              inf, input_len, consumed, written, total_written);
          if (result != DEFLATE_OK)
            return result;
        }

      /* Decode block data */
      if (inf->state == INFLATE_STATE_BLOCK)
        {
          size_t block_written = 0;

          result = dispatch_block_decoder (inf,
                                           output + total_written,
                                           output_len - total_written,
                                           &block_written);
          total_written += block_written;

          /* Check bomb protection */
          size_t bytes_consumed = get_bytes_consumed (inf->reader, input_len);
          if (check_bomb_limits (inf, bytes_consumed) == DEFLATE_ERROR_BOMB)
            {
              finalize_output (
                  inf, input_len, consumed, written, total_written);
              return DEFLATE_ERROR_BOMB;
            }

          /* Handle decode result */
          if (result == DEFLATE_OK)
            {
              update_state_after_block (inf);
            }
          else
            {
              finalize_output (
                  inf, input_len, consumed, written, total_written);
              return result;
            }
        }
    }

  finalize_output (inf, input_len, consumed, written, total_written);
  return (inf->state == INFLATE_STATE_DONE) ? DEFLATE_OK : DEFLATE_INCOMPLETE;
}

/**
 * Get string representation of result code.
 */
const char *
SocketDeflate_result_string (SocketDeflate_Result result)
{
  switch (result)
    {
    case DEFLATE_OK:
      return "OK";
    case DEFLATE_INCOMPLETE:
      return "Incomplete (need more input)";
    case DEFLATE_OUTPUT_FULL:
      return "Output buffer full";
    case DEFLATE_ERROR:
      return "General error";
    case DEFLATE_ERROR_INVALID_BTYPE:
      return "Invalid block type (BTYPE=11 reserved)";
    case DEFLATE_ERROR_INVALID_CODE:
      return "Invalid Huffman code";
    case DEFLATE_ERROR_INVALID_DISTANCE:
      return "Invalid distance code";
    case DEFLATE_ERROR_DISTANCE_TOO_FAR:
      return "Distance exceeds available history";
    case DEFLATE_ERROR_HUFFMAN_TREE:
      return "Invalid Huffman tree";
    case DEFLATE_ERROR_BOMB:
      return "Decompression bomb detected";
    case DEFLATE_ERROR_GZIP_MAGIC:
      return "Invalid gzip magic bytes";
    case DEFLATE_ERROR_GZIP_METHOD:
      return "Unsupported gzip compression method";
    case DEFLATE_ERROR_GZIP_CRC:
      return "gzip CRC-32 mismatch";
    case DEFLATE_ERROR_GZIP_SIZE:
      return "gzip ISIZE mismatch";
    case DEFLATE_ERROR_GZIP_HCRC:
      return "gzip header CRC16 mismatch";
    case DEFLATE_ERROR_GZIP_OS:
      return "Invalid/unknown gzip OS code";
    default:
      return "Unknown error";
    }
}
