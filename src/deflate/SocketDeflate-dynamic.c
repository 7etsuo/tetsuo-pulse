/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDeflate-dynamic.c
 * @brief RFC 1951 dynamic Huffman block (BTYPE=10) decoder.
 *
 * Implements compressed block decoding with dynamic Huffman codes per RFC 1951
 * Section 3.2.7. Dynamic blocks transmit the Huffman tables in the block
 * header itself, allowing optimal compression per block.
 *
 * Block format:
 * 1. HLIT (5 bits) - number of literal/length codes - 257
 * 2. HDIST (5 bits) - number of distance codes - 1
 * 3. HCLEN (4 bits) - number of code length codes - 4
 * 4. (HCLEN+4) x 3 bits - code lengths for code length alphabet
 * 5. HLIT+257 code lengths for literal/length alphabet
 * 6. HDIST+1 code lengths for distance alphabet
 * 7. Compressed data using the dynamic tables
 *
 * @see RFC 1951 Section 3.2.7 - Dynamic Huffman codes
 */

#include "deflate/SocketDeflate.h"

/**
 * Decode block header containing HLIT, HDIST, HCLEN.
 *
 * @param reader    Bit reader positioned at block header
 * @param hlit_out  Output: number of literal/length codes (257-286)
 * @param hdist_out Output: number of distance codes (1-32)
 * @param hclen_out Output: number of code length codes (4-19)
 * @return DEFLATE_OK on success, error code on failure
 */
static SocketDeflate_Result
decode_block_header (SocketDeflate_BitReader_T reader,
                     unsigned int *hlit_out,
                     unsigned int *hdist_out,
                     unsigned int *hclen_out)
{
  uint32_t val;
  SocketDeflate_Result result;

  /* Read HLIT (5 bits) + 257 */
  result = SocketDeflate_BitReader_read (reader, 5, &val);
  if (result != DEFLATE_OK)
    return result;
  *hlit_out = val + 257;

  /* Read HDIST (5 bits) + 1 */
  result = SocketDeflate_BitReader_read (reader, 5, &val);
  if (result != DEFLATE_OK)
    return result;
  *hdist_out = val + 1;

  /* Read HCLEN (4 bits) + 4 */
  result = SocketDeflate_BitReader_read (reader, 4, &val);
  if (result != DEFLATE_OK)
    return result;
  *hclen_out = val + 4;

  /* Validate ranges per RFC 1951 */
  if (*hlit_out > 286 || *hdist_out > 32)
    return DEFLATE_ERROR;

  return DEFLATE_OK;
}

/**
 * Build the code length Huffman table.
 *
 * Reads code length code lengths in the RFC 1951 permuted order and
 * builds the Huffman table for decoding literal/length and distance
 * code lengths.
 *
 * @param reader        Bit reader
 * @param hclen         Number of code length codes (4-19)
 * @param codelen_table Output: Huffman table for code lengths
 * @return DEFLATE_OK on success, error code on failure
 */
static SocketDeflate_Result
build_codelen_table (SocketDeflate_BitReader_T reader,
                     unsigned int hclen,
                     SocketDeflate_HuffmanTable_T codelen_table)
{
  uint8_t codelen_lengths[DEFLATE_CODELEN_CODES] = { 0 };
  uint32_t val;
  unsigned int i;
  SocketDeflate_Result result;

  /* Read code lengths in RFC 1951 permuted order */
  for (i = 0; i < hclen; i++)
    {
      result = SocketDeflate_BitReader_read (reader, 3, &val);
      if (result != DEFLATE_OK)
        return result;
      codelen_lengths[deflate_codelen_order[i]] = (uint8_t)val;
    }
  /* Remaining slots (if hclen < 19) stay at 0 (unused) */

  /* Build Huffman table (max 7 bits for code length alphabet) */
  return SocketDeflate_HuffmanTable_build (
      codelen_table, codelen_lengths, DEFLATE_CODELEN_CODES, 7);
}

/**
 * Decode code lengths for literal/length and distance alphabets.
 *
 * Uses the code length Huffman table to decode the code lengths.
 * Handles run-length encoding codes:
 * - 16: Copy previous code length 3-6 times (2 extra bits)
 * - 17: Repeat 0 for 3-10 times (3 extra bits)
 * - 18: Repeat 0 for 11-138 times (7 extra bits)
 *
 * Per RFC 1951, run-length codes can cross from literal/length to
 * distance alphabet as they form a single sequence.
 *
 * @param reader        Bit reader
 * @param codelen_table Huffman table for code lengths
 * @param lengths       Output: decoded code lengths
 * @param count         Total number of lengths to decode
 * @return DEFLATE_OK on success, error code on failure
 */
static SocketDeflate_Result
decode_code_lengths (SocketDeflate_BitReader_T reader,
                     SocketDeflate_HuffmanTable_T codelen_table,
                     uint8_t *lengths,
                     unsigned int count)
{
  unsigned int i = 0;
  uint16_t symbol;
  uint32_t extra;
  unsigned int repeat;
  uint8_t prev;
  SocketDeflate_Result result;

  while (i < count)
    {
      result
          = SocketDeflate_HuffmanTable_decode (codelen_table, reader, &symbol);
      if (result != DEFLATE_OK)
        return result;

      if (symbol < 16)
        {
          /* Literal code length 0-15 */
          lengths[i++] = (uint8_t)symbol;
        }
      else if (symbol == 16)
        {
          /* Copy previous code length 3-6 times */
          if (i == 0)
            return DEFLATE_ERROR; /* No previous to copy */

          result = SocketDeflate_BitReader_read (reader, 2, &extra);
          if (result != DEFLATE_OK)
            return result;

          repeat = 3 + extra;
          prev = lengths[i - 1];

          while (repeat-- > 0 && i < count)
            lengths[i++] = prev;
        }
      else if (symbol == 17)
        {
          /* Repeat 0 for 3-10 times */
          result = SocketDeflate_BitReader_read (reader, 3, &extra);
          if (result != DEFLATE_OK)
            return result;

          repeat = 3 + extra;

          while (repeat-- > 0 && i < count)
            lengths[i++] = 0;
        }
      else if (symbol == 18)
        {
          /* Repeat 0 for 11-138 times */
          result = SocketDeflate_BitReader_read (reader, 7, &extra);
          if (result != DEFLATE_OK)
            return result;

          repeat = 11 + extra;

          while (repeat-- > 0 && i < count)
            lengths[i++] = 0;
        }
      else
        {
          return DEFLATE_ERROR_INVALID_CODE;
        }
    }

  return DEFLATE_OK;
}

/*
 * Public API
 */

SocketDeflate_Result
SocketDeflate_decode_dynamic_block (SocketDeflate_BitReader_T reader,
                                    Arena_T arena,
                                    uint8_t *output,
                                    size_t output_len,
                                    size_t *written)
{
  unsigned int hlit, hdist, hclen;
  /* Combined array for litlen + dist lengths (max 286 + 32 = 318) */
  uint8_t lengths[DEFLATE_LITLEN_CODES + DEFLATE_DIST_CODES];
  SocketDeflate_HuffmanTable_T codelen_table;
  SocketDeflate_HuffmanTable_T litlen_table;
  SocketDeflate_HuffmanTable_T dist_table;
  unsigned int total_lengths;
  SocketDeflate_Result result;

  *written = 0;

  /* Step 1: Decode block header */
  result = decode_block_header (reader, &hlit, &hdist, &hclen);
  if (result != DEFLATE_OK)
    return result;

  /* Step 2: Build code length Huffman table */
  codelen_table = SocketDeflate_HuffmanTable_new (arena);
  result = build_codelen_table (reader, hclen, codelen_table);
  if (result != DEFLATE_OK)
    return result;

  /* Step 3: Decode all code lengths (combined sequence per RFC 1951) */
  total_lengths = hlit + hdist;
  result = decode_code_lengths (reader, codelen_table, lengths, total_lengths);
  if (result != DEFLATE_OK)
    return result;

  /* Step 4: Build literal/length Huffman table */
  litlen_table = SocketDeflate_HuffmanTable_new (arena);
  result = SocketDeflate_HuffmanTable_build (
      litlen_table, lengths, hlit, DEFLATE_MAX_BITS);
  if (result != DEFLATE_OK)
    return result;

  /* Step 5: Build distance Huffman table */
  dist_table = SocketDeflate_HuffmanTable_new (arena);
  result = SocketDeflate_HuffmanTable_build (
      dist_table, lengths + hlit, hdist, DEFLATE_MAX_BITS);
  if (result != DEFLATE_OK)
    return result;

  /* Step 6: Decode compressed data using shared LZ77 loop */
  return inflate_lz77 (
      reader, litlen_table, dist_table, output, output_len, written);
}
