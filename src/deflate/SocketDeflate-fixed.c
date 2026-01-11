/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDeflate-fixed.c
 * @brief RFC 1951 fixed Huffman block (BTYPE=01) decoder.
 *
 * Implements compressed block decoding with fixed Huffman codes per RFC 1951
 * Section 3.2.6. Fixed blocks use predefined Huffman tables for:
 * - Literal/length alphabet (0-287): 7-9 bit codes
 * - Distance alphabet (0-31): 5-bit codes
 *
 * The decoder implements the LZ77 decompression loop:
 * 1. Decode symbol from literal/length table
 * 2. If literal (0-255): output byte directly
 * 3. If end-of-block (256): terminate
 * 4. If length code (257-285): decode length, then distance, then copy
 *
 * @see RFC 1951 Section 3.2.3 - Block format
 * @see RFC 1951 Section 3.2.5 - Length and distance codes
 * @see RFC 1951 Section 3.2.6 - Fixed Huffman codes
 */

#include "deflate/SocketDeflate.h"

#include <string.h>

/**
 * Decode length value from code and bit reader.
 *
 * Reads any required extra bits from the stream and combines
 * with the base value from the length table.
 *
 * @param reader     Bit reader
 * @param code       Length code (257-285)
 * @param length_out Output: decoded length (3-258)
 * @return DEFLATE_OK on success, error code on failure
 */
static SocketDeflate_Result
decode_length_value (SocketDeflate_BitReader_T reader,
                     uint16_t code,
                     unsigned int *length_out)
{
  unsigned int extra_bits;
  uint32_t extra_val;
  SocketDeflate_Result result;

  /* Get number of extra bits needed */
  result = SocketDeflate_get_length_extra_bits (code, &extra_bits);
  if (result != DEFLATE_OK)
    return result;

  /* Read extra bits if any */
  extra_val = 0;
  if (extra_bits > 0)
    {
      result = SocketDeflate_BitReader_read (reader, extra_bits, &extra_val);
      if (result != DEFLATE_OK)
        return result;
    }

  /* Decode length from code and extra bits */
  return SocketDeflate_decode_length (code, extra_val, length_out);
}

/**
 * Decode distance value from bit reader.
 *
 * Decodes distance code from the distance Huffman table, then reads
 * any required extra bits and combines with the base value.
 *
 * @param reader       Bit reader
 * @param dist_table   Distance Huffman table
 * @param distance_out Output: decoded distance (1-32768)
 * @return DEFLATE_OK on success, error code on failure
 */
static SocketDeflate_Result
decode_distance_value (SocketDeflate_BitReader_T reader,
                       SocketDeflate_HuffmanTable_T dist_table,
                       unsigned int *distance_out)
{
  uint16_t dist_code;
  unsigned int extra_bits;
  uint32_t extra_val;
  SocketDeflate_Result result;

  /* Decode distance code from Huffman table */
  result = SocketDeflate_HuffmanTable_decode (dist_table, reader, &dist_code);
  if (result != DEFLATE_OK)
    return result;

  /* Validate distance code (0-29 valid, 30-31 reserved) */
  if (!SocketDeflate_is_valid_distance_code (dist_code))
    return DEFLATE_ERROR_INVALID_DISTANCE;

  /* Get number of extra bits needed */
  result = SocketDeflate_get_distance_extra_bits (dist_code, &extra_bits);
  if (result != DEFLATE_OK)
    return result;

  /* Read extra bits if any */
  extra_val = 0;
  if (extra_bits > 0)
    {
      result = SocketDeflate_BitReader_read (reader, extra_bits, &extra_val);
      if (result != DEFLATE_OK)
        return result;
    }

  /* Decode distance from code and extra bits */
  return SocketDeflate_decode_distance (dist_code, extra_val, distance_out);
}

/**
 * Copy bytes from history with overlap handling.
 *
 * Handles the critical case where distance < length, meaning the copy
 * source and destination overlap. Per RFC 1951 Section 3.2.3:
 *
 * "Note also that the referenced string may overlap the current position;
 *  for example, if the last 2 bytes decoded have values X and Y, a string
 *  reference with <length = 5, distance = 2> adds X,Y,X,Y,X to the output
 *  stream."
 *
 * This cannot use memcpy because of the overlap. Each byte must be copied
 * individually so that previously-written bytes become available for
 * subsequent copies.
 *
 * @param output   Output buffer
 * @param out_pos  Current output position (in/out)
 * @param out_len  Output buffer size
 * @param length   Number of bytes to copy (3-258)
 * @param distance Distance back into history (1-32768)
 * @return DEFLATE_OK on success, DEFLATE_ERROR_DISTANCE_TOO_FAR if invalid
 */
static SocketDeflate_Result
copy_from_history (uint8_t *output,
                   size_t *out_pos,
                   size_t out_len,
                   unsigned int length,
                   unsigned int distance)
{
  size_t src;
  size_t dst;
  unsigned int i;

  /* Validate distance doesn't go before start of output */
  if (distance > *out_pos)
    return DEFLATE_ERROR_DISTANCE_TOO_FAR;

  dst = *out_pos;
  src = dst - distance;

  /* Copy byte-by-byte to handle overlap correctly */
  for (i = 0; i < length && dst < out_len; i++)
    {
      output[dst++] = output[src++];
    }

  *out_pos = dst;

  return DEFLATE_OK;
}

/**
 * Core LZ77 decode loop for Huffman blocks.
 *
 * Decodes symbols until end-of-block (256) or output buffer full:
 * - Literal (0-255): Write byte to output
 * - End-of-block (256): Return success
 * - Length code (257-285): Decode length, distance, copy from history
 *
 * This function is shared by both fixed and dynamic block decoders.
 *
 * @param reader       Bit reader with input data
 * @param litlen_table Literal/length Huffman table
 * @param dist_table   Distance Huffman table
 * @param output       Output buffer
 * @param output_len   Output buffer size
 * @param written      Output: bytes written
 * @return DEFLATE_OK on success (end-of-block reached)
 */
SocketDeflate_Result
inflate_lz77 (SocketDeflate_BitReader_T reader,
              SocketDeflate_HuffmanTable_T litlen_table,
              SocketDeflate_HuffmanTable_T dist_table,
              uint8_t *output,
              size_t output_len,
              size_t *written)
{
  size_t out_pos = 0;
  uint16_t symbol;
  unsigned int length;
  unsigned int distance;
  SocketDeflate_Result result;

  while (out_pos < output_len)
    {
      /* Decode literal/length symbol */
      result
          = SocketDeflate_HuffmanTable_decode (litlen_table, reader, &symbol);
      if (result != DEFLATE_OK)
        {
          *written = out_pos;
          return result;
        }

      if (symbol < DEFLATE_END_OF_BLOCK)
        {
          /* Literal byte (0-255) */
          output[out_pos++] = (uint8_t)symbol;
        }
      else if (symbol == DEFLATE_END_OF_BLOCK)
        {
          /* End of block - success */
          *written = out_pos;
          return DEFLATE_OK;
        }
      else
        {
          /* Length code (257-285) */
          if (!SocketDeflate_is_valid_litlen_code (symbol))
            {
              *written = out_pos;
              return DEFLATE_ERROR_INVALID_CODE;
            }

          /* Decode length value with extra bits */
          result = decode_length_value (reader, symbol, &length);
          if (result != DEFLATE_OK)
            {
              *written = out_pos;
              return result;
            }

          /* Decode distance value with extra bits */
          result = decode_distance_value (reader, dist_table, &distance);
          if (result != DEFLATE_OK)
            {
              *written = out_pos;
              return result;
            }

          /* Copy from history (handles overlap case) */
          result = copy_from_history (
              output, &out_pos, output_len, length, distance);
          if (result != DEFLATE_OK)
            {
              *written = out_pos;
              return result;
            }
        }
    }

  /* Output buffer full before end-of-block */
  *written = out_pos;
  return DEFLATE_ERROR;
}

/*
 * Public API
 */

SocketDeflate_Result
SocketDeflate_decode_fixed_block (SocketDeflate_BitReader_T reader,
                                  uint8_t *output,
                                  size_t output_len,
                                  size_t *written)
{
  SocketDeflate_HuffmanTable_T litlen_table;
  SocketDeflate_HuffmanTable_T dist_table;

  *written = 0;

  /* Get pre-built fixed Huffman tables */
  litlen_table = SocketDeflate_get_fixed_litlen_table ();
  dist_table = SocketDeflate_get_fixed_dist_table ();

  /* Tables must be initialized before use */
  if (litlen_table == NULL || dist_table == NULL)
    return DEFLATE_ERROR;

  /* Run LZ77 decode loop */
  return inflate_lz77 (
      reader, litlen_table, dist_table, output, output_len, written);
}
