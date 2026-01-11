/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDeflate-static.c
 * @brief RFC 1951 DEFLATE static tables and validation functions.
 *
 * Contains the static lookup tables for DEFLATE compression as specified
 * in RFC 1951 Sections 3.2.5, 3.2.6, and 3.2.7.
 *
 * Tables:
 * - deflate_length_table: Length codes 257-285 to lengths 3-258
 * - deflate_distance_table: Distance codes 0-29 to distances 1-32768
 * - deflate_fixed_litlen_lengths: Fixed Huffman bit lengths for literals
 * - deflate_fixed_dist_lengths: Fixed Huffman bit lengths for distances
 * - deflate_codelen_order: Code length alphabet order for dynamic blocks
 */

#include "deflate/SocketDeflate.h"

/* Exception for DEFLATE errors */
const Except_T SocketDeflate_Failed = { &SocketDeflate_Failed,
                                        "DEFLATE operation failed" };

/*
 * Length Code Table (RFC 1951 Section 3.2.5)
 *
 * Maps length codes 257-285 to base length values and extra bits.
 * Table index = code - 257 (so index 0 = code 257, index 28 = code 285).
 *
 *        Extra               Extra               Extra
 *   Code Bits Length(s) Code Bits Lengths   Code Bits Length(s)
 *   ---- ---- ------    ---- ---- -------   ---- ---- -------
 *    257   0     3       267   1   15,16     277   4   67-82
 *    258   0     4       268   1   17,18     278   4   83-98
 *    259   0     5       269   2   19-22     279   4   99-114
 *    260   0     6       270   2   23-26     280   4  115-130
 *    261   0     7       271   2   27-30     281   5  131-162
 *    262   0     8       272   2   31-34     282   5  163-194
 *    263   0     9       273   3   35-42     283   5  195-226
 *    264   0    10       274   3   43-50     284   5  227-257
 *    265   1  11,12      275   3   51-58     285   0    258
 *    266   1  13,14      276   3   59-66
 */
const SocketDeflate_CodeEntry deflate_length_table[DEFLATE_LENGTH_CODES] = {
  /* Code 257-264: 0 extra bits, lengths 3-10 */
  { 3, 0 },
  { 4, 0 },
  { 5, 0 },
  { 6, 0 },
  { 7, 0 },
  { 8, 0 },
  { 9, 0 },
  { 10, 0 },
  /* Code 265-268: 1 extra bit */
  { 11, 1 },
  { 13, 1 },
  { 15, 1 },
  { 17, 1 },
  /* Code 269-272: 2 extra bits */
  { 19, 2 },
  { 23, 2 },
  { 27, 2 },
  { 31, 2 },
  /* Code 273-276: 3 extra bits */
  { 35, 3 },
  { 43, 3 },
  { 51, 3 },
  { 59, 3 },
  /* Code 277-280: 4 extra bits */
  { 67, 4 },
  { 83, 4 },
  { 99, 4 },
  { 115, 4 },
  /* Code 281-284: 5 extra bits */
  { 131, 5 },
  { 163, 5 },
  { 195, 5 },
  { 227, 5 },
  /* Code 285: 0 extra bits, length 258 (maximum match length) */
  { 258, 0 }
};

/*
 * Distance Code Table (RFC 1951 Section 3.2.5)
 *
 * Maps distance codes 0-29 to base distance values and extra bits.
 * Table index = code directly.
 *
 *         Extra           Extra               Extra
 *    Code Bits Dist  Code Bits   Dist     Code Bits Distance
 *    ---- ---- ----  ---- ----  ------    ---- ---- --------
 *      0   0    1     10   4     33-48    20    9   1025-1536
 *      1   0    2     11   4     49-64    21    9   1537-2048
 *      2   0    3     12   5     65-96    22   10   2049-3072
 *      3   0    4     13   5     97-128   23   10   3073-4096
 *      4   1   5,6    14   6    129-192   24   11   4097-6144
 *      5   1   7,8    15   6    193-256   25   11   6145-8192
 *      6   2   9-12   16   7    257-384   26   12  8193-12288
 *      7   2  13-16   17   7    385-512   27   12 12289-16384
 *      8   3  17-24   18   8    513-768   28   13 16385-24576
 *      9   3  25-32   19   8   769-1024   29   13 24577-32768
 */
const SocketDeflate_CodeEntry deflate_distance_table[DEFLATE_DISTANCE_CODES]
    = {
        /* Code 0-3: 0 extra bits, distances 1-4 */
        { 1, 0 },
        { 2, 0 },
        { 3, 0 },
        { 4, 0 },
        /* Code 4-5: 1 extra bit */
        { 5, 1 },
        { 7, 1 },
        /* Code 6-7: 2 extra bits */
        { 9, 2 },
        { 13, 2 },
        /* Code 8-9: 3 extra bits */
        { 17, 3 },
        { 25, 3 },
        /* Code 10-11: 4 extra bits */
        { 33, 4 },
        { 49, 4 },
        /* Code 12-13: 5 extra bits */
        { 65, 5 },
        { 97, 5 },
        /* Code 14-15: 6 extra bits */
        { 129, 6 },
        { 193, 6 },
        /* Code 16-17: 7 extra bits */
        { 257, 7 },
        { 385, 7 },
        /* Code 18-19: 8 extra bits */
        { 513, 8 },
        { 769, 8 },
        /* Code 20-21: 9 extra bits */
        { 1025, 9 },
        { 1537, 9 },
        /* Code 22-23: 10 extra bits */
        { 2049, 10 },
        { 3073, 10 },
        /* Code 24-25: 11 extra bits */
        { 4097, 11 },
        { 6145, 11 },
        /* Code 26-27: 12 extra bits */
        { 8193, 12 },
        { 12289, 12 },
        /* Code 28-29: 13 extra bits */
        { 16385, 13 },
        { 24577, 13 }
      };

/*
 * Fixed Huffman Code Lengths for Literal/Length Alphabet (RFC 1951 Section
 * 3.2.6)
 *
 * Used when BTYPE=01 (fixed Huffman codes).
 *
 *          Lit Value    Bits        Codes
 *          ---------    ----        -----
 *            0 - 143     8          00110000 through 10111111
 *          144 - 255     9          110010000 through 111111111
 *          256 - 279     7          0000000 through 0010111
 *          280 - 287     8          11000000 through 11000111
 *
 * Note: Codes 286-287 participate in code construction but never occur
 * in the compressed data stream.
 */
const uint8_t deflate_fixed_litlen_lengths[DEFLATE_LITLEN_CODES] = {
  /* 0-143: 8 bits (144 entries) */
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, /* 0-15 */
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, /* 16-31 */
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, /* 32-47 */
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, /* 48-63 */
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, /* 64-79 */
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, /* 80-95 */
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, /* 96-111 */
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, /* 112-127 */
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, /* 128-143 */
  /* 144-255: 9 bits (112 entries) */
  9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, /* 144-159 */
  9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, /* 160-175 */
  9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, /* 176-191 */
  9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, /* 192-207 */
  9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, /* 208-223 */
  9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, /* 224-239 */
  9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, /* 240-255 */
  /* 256-279: 7 bits (24 entries) */
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, /* 256-271 */
  7, 7, 7, 7, 7, 7, 7, 7,                         /* 272-279 */
  /* 280-287: 8 bits (8 entries) */
  8, 8, 8, 8, 8, 8, 8, 8 /* 280-287 */
};

/*
 * Fixed Huffman Code Lengths for Distance Alphabet (RFC 1951 Section 3.2.6)
 *
 * All distance codes 0-31 are represented by 5-bit codes.
 * Note: Distance codes 30-31 will never actually occur in the data.
 */
const uint8_t deflate_fixed_dist_lengths[DEFLATE_DIST_CODES] = {
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5
};

/*
 * Code Length Alphabet Order (RFC 1951 Section 3.2.7)
 *
 * When reading code lengths for dynamic Huffman trees, the code lengths
 * for the code length alphabet are transmitted in this specific order:
 *
 * 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
 *
 * This ordering puts the most likely code lengths (shorter ones) first,
 * allowing the transmission to be truncated if the trailing values are 0.
 */
const uint8_t deflate_codelen_order[DEFLATE_CODELEN_CODES] = {
  16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

/*
 * Validation Functions
 */

int
SocketDeflate_is_valid_litlen_code (unsigned int code)
{
  /*
   * RFC 1951 Section 3.2.6:
   * "Literal/length values 286-287 will never actually occur in
   * the compressed data, but participate in the code construction."
   *
   * Valid codes: 0-285
   * Invalid codes: 286-287 (and anything > 287)
   */
  return code <= DEFLATE_LITLEN_MAX_DECODE;
}

int
SocketDeflate_is_valid_distance_code (unsigned int code)
{
  /*
   * RFC 1951 Section 3.2.6:
   * "Note that distance codes 30-31 will never actually occur
   * in the compressed data."
   *
   * Valid codes: 0-29
   * Invalid codes: 30-31 (and anything > 31)
   */
  return code <= DEFLATE_DIST_MAX_DECODE;
}

/*
 * Extra Bits Query Functions
 */

SocketDeflate_Result
SocketDeflate_get_length_extra_bits (unsigned int code, unsigned int *extra_out)
{
  unsigned int index;

  /* Length codes range from 257 to 285 */
  if (code < DEFLATE_LENGTH_CODE_MIN || code > DEFLATE_LENGTH_CODE_MAX)
    return DEFLATE_ERROR_INVALID_CODE;

  index = code - DEFLATE_LENGTH_CODE_MIN;
  *extra_out = deflate_length_table[index].extra_bits;

  return DEFLATE_OK;
}

SocketDeflate_Result
SocketDeflate_get_distance_extra_bits (unsigned int code,
                                       unsigned int *extra_out)
{
  /* Distance codes range from 0 to 29 */
  if (code > DEFLATE_DISTANCE_CODE_MAX)
    return DEFLATE_ERROR_INVALID_DISTANCE;

  *extra_out = deflate_distance_table[code].extra_bits;

  return DEFLATE_OK;
}

/*
 * Decode Functions
 */

SocketDeflate_Result
SocketDeflate_decode_length (unsigned int code, unsigned int extra,
                             unsigned int *length_out)
{
  unsigned int index;
  const SocketDeflate_CodeEntry *entry;
  unsigned int extra_mask;

  /* Length codes range from 257 to 285 */
  if (code < DEFLATE_LENGTH_CODE_MIN || code > DEFLATE_LENGTH_CODE_MAX)
    return DEFLATE_ERROR_INVALID_CODE;

  /* Table index = code - 257 */
  index = code - DEFLATE_LENGTH_CODE_MIN;
  entry = &deflate_length_table[index];

  /* Mask extra bits to valid range to prevent overflow from malformed input */
  extra_mask = (1U << entry->extra_bits) - 1;
  extra &= extra_mask;

  /* Length = base + extra bits value */
  *length_out = entry->base + extra;

  return DEFLATE_OK;
}

SocketDeflate_Result
SocketDeflate_decode_distance (unsigned int code, unsigned int extra,
                               unsigned int *distance_out)
{
  const SocketDeflate_CodeEntry *entry;
  unsigned int extra_mask;

  /* Distance codes range from 0 to 29 */
  if (code > DEFLATE_DISTANCE_CODE_MAX)
    return DEFLATE_ERROR_INVALID_DISTANCE;

  entry = &deflate_distance_table[code];

  /* Mask extra bits to valid range to prevent overflow from malformed input */
  extra_mask = (1U << entry->extra_bits) - 1;
  extra &= extra_mask;

  /* Distance = base + extra bits value */
  *distance_out = entry->base + extra;

  return DEFLATE_OK;
}
