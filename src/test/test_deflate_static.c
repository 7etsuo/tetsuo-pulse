/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_deflate_static.c - RFC 1951 DEFLATE static tables unit tests
 *
 * Tests for the DEFLATE static tables module, verifying that all tables
 * match the RFC 1951 specification exactly.
 *
 * Test coverage:
 * - Length code table boundaries and values
 * - Distance code table boundaries and values
 * - Fixed Huffman code lengths for literal/length alphabet
 * - Fixed Huffman code lengths for distance alphabet
 * - Code length alphabet order (for dynamic blocks)
 * - Invalid code detection (286-287 for litlen, 30-31 for distance)
 * - Length and distance decode functions
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "deflate/SocketDeflate.h"
#include "test/Test.h"

/*
 * Length Table Tests
 */

/* Test length table boundaries (first and last entries) */
TEST (deflate_length_table_boundaries)
{
  /* Code 257 (index 0) = length 3, 0 extra bits */
  ASSERT_EQ (deflate_length_table[0].base, 3);
  ASSERT_EQ (deflate_length_table[0].extra_bits, 0);

  /* Code 285 (index 28) = length 258, 0 extra bits (special case) */
  ASSERT_EQ (deflate_length_table[28].base, 258);
  ASSERT_EQ (deflate_length_table[28].extra_bits, 0);
}

/* Test that length table has exactly 29 entries (codes 257-285) */
TEST (deflate_length_table_size)
{
  ASSERT_EQ (sizeof (deflate_length_table) / sizeof (deflate_length_table[0]),
             DEFLATE_LENGTH_CODES);
  ASSERT_EQ (DEFLATE_LENGTH_CODES, 29);
}

/* Verify all length codes produce values in range 3-258 */
TEST (deflate_length_table_all_values)
{
  unsigned int length;
  SocketDeflate_Result result;

  /* Test each code 257-285 */
  for (unsigned int code = DEFLATE_LENGTH_CODE_MIN;
       code <= DEFLATE_LENGTH_CODE_MAX; code++)
    {
      unsigned int index = code - DEFLATE_LENGTH_CODE_MIN;
      const SocketDeflate_CodeEntry *entry = &deflate_length_table[index];
      unsigned int max_extra = (1U << entry->extra_bits) - 1;

      /* Test with minimum extra bits (0) */
      result = SocketDeflate_decode_length (code, 0, &length);
      ASSERT_EQ (result, DEFLATE_OK);
      ASSERT_EQ (length, entry->base);

      /* Test with maximum extra bits */
      result = SocketDeflate_decode_length (code, max_extra, &length);
      ASSERT_EQ (result, DEFLATE_OK);
      ASSERT_EQ (length, entry->base + max_extra);

      /* Verify length is in valid range */
      ASSERT (length >= DEFLATE_MIN_MATCH);
      ASSERT (length <= DEFLATE_MAX_MATCH);
    }
}

/* RFC 1951 specific: code 265 with extra bits 0/1 = lengths 11/12 */
TEST (deflate_length_code_265_extra_bits)
{
  unsigned int length;

  /* Code 265: base=11, 1 extra bit */
  ASSERT_EQ (deflate_length_table[265 - 257].base, 11);
  ASSERT_EQ (deflate_length_table[265 - 257].extra_bits, 1);

  /* extra=0 -> length 11 */
  ASSERT_EQ (SocketDeflate_decode_length (265, 0, &length), DEFLATE_OK);
  ASSERT_EQ (length, 11);

  /* extra=1 -> length 12 */
  ASSERT_EQ (SocketDeflate_decode_length (265, 1, &length), DEFLATE_OK);
  ASSERT_EQ (length, 12);
}

/* RFC 1951 specific: code 285 = length 258 (maximum, 0 extra bits) */
TEST (deflate_length_code_285_max_length)
{
  unsigned int length;

  /* Code 285 is special: 0 extra bits, length 258 */
  ASSERT_EQ (deflate_length_table[28].base, 258);
  ASSERT_EQ (deflate_length_table[28].extra_bits, 0);

  ASSERT_EQ (SocketDeflate_decode_length (285, 0, &length), DEFLATE_OK);
  ASSERT_EQ (length, 258);
  ASSERT_EQ (length, DEFLATE_MAX_MATCH);
}

/*
 * Distance Table Tests
 */

/* Test distance table boundaries */
TEST (deflate_distance_table_boundaries)
{
  /* Code 0 = distance 1, 0 extra bits */
  ASSERT_EQ (deflate_distance_table[0].base, 1);
  ASSERT_EQ (deflate_distance_table[0].extra_bits, 0);

  /* Code 29 = distance 24577 base, 13 extra bits */
  ASSERT_EQ (deflate_distance_table[29].base, 24577);
  ASSERT_EQ (deflate_distance_table[29].extra_bits, 13);
}

/* Test that distance table has exactly 30 entries (codes 0-29) */
TEST (deflate_distance_table_size)
{
  ASSERT_EQ (
      sizeof (deflate_distance_table) / sizeof (deflate_distance_table[0]),
      DEFLATE_DISTANCE_CODES);
  ASSERT_EQ (DEFLATE_DISTANCE_CODES, 30);
}

/* Code 29 with max extra bits (0x1FFF = 8191) = distance 32768 */
TEST (deflate_distance_max_32768)
{
  unsigned int distance;

  /* Code 29: base=24577, 13 extra bits, max extra = 8191 */
  ASSERT_EQ (SocketDeflate_decode_distance (29, 0x1FFF, &distance), DEFLATE_OK);
  ASSERT_EQ (distance, 24577 + 8191);
  ASSERT_EQ (distance, 32768);
  ASSERT_EQ (distance, DEFLATE_WINDOW_SIZE);
}

/* Verify all distance codes produce values in range 1-32768 */
TEST (deflate_distance_table_all_values)
{
  unsigned int distance;
  SocketDeflate_Result result;

  /* Test each code 0-29 */
  for (unsigned int code = DEFLATE_DISTANCE_CODE_MIN;
       code <= DEFLATE_DISTANCE_CODE_MAX; code++)
    {
      const SocketDeflate_CodeEntry *entry = &deflate_distance_table[code];
      unsigned int max_extra = (1U << entry->extra_bits) - 1;

      /* Test with minimum extra bits (0) */
      result = SocketDeflate_decode_distance (code, 0, &distance);
      ASSERT_EQ (result, DEFLATE_OK);
      ASSERT_EQ (distance, entry->base);

      /* Test with maximum extra bits */
      result = SocketDeflate_decode_distance (code, max_extra, &distance);
      ASSERT_EQ (result, DEFLATE_OK);
      ASSERT_EQ (distance, entry->base + max_extra);

      /* Verify distance is in valid range */
      ASSERT (distance >= 1);
      ASSERT (distance <= DEFLATE_WINDOW_SIZE);
    }
}

/*
 * Invalid Code Detection Tests
 */

/* RFC 1951: codes 286-287 are invalid for literal/length */
TEST (deflate_invalid_litlen_codes_286_287)
{
  /* Code 285 is the last valid length code */
  ASSERT_EQ (SocketDeflate_is_valid_litlen_code (285), 1);

  /* Codes 286-287 are invalid (participate in construction only) */
  ASSERT_EQ (SocketDeflate_is_valid_litlen_code (286), 0);
  ASSERT_EQ (SocketDeflate_is_valid_litlen_code (287), 0);

  /* Any code > 287 is also invalid */
  ASSERT_EQ (SocketDeflate_is_valid_litlen_code (288), 0);
  ASSERT_EQ (SocketDeflate_is_valid_litlen_code (1000), 0);
}

/* RFC 1951: codes 30-31 are invalid for distance */
TEST (deflate_invalid_distance_codes_30_31)
{
  /* Code 29 is the last valid distance code */
  ASSERT_EQ (SocketDeflate_is_valid_distance_code (29), 1);

  /* Codes 30-31 are invalid (participate in construction only) */
  ASSERT_EQ (SocketDeflate_is_valid_distance_code (30), 0);
  ASSERT_EQ (SocketDeflate_is_valid_distance_code (31), 0);

  /* Any code > 31 is also invalid */
  ASSERT_EQ (SocketDeflate_is_valid_distance_code (32), 0);
  ASSERT_EQ (SocketDeflate_is_valid_distance_code (1000), 0);
}

/* Test valid litlen code range 0-285 */
TEST (deflate_valid_litlen_codes_0_to_285)
{
  /* All codes 0-285 should be valid */
  for (unsigned int code = 0; code <= 285; code++)
    {
      ASSERT_EQ (SocketDeflate_is_valid_litlen_code (code), 1);
    }
}

/* Test valid distance code range 0-29 */
TEST (deflate_valid_distance_codes_0_to_29)
{
  /* All codes 0-29 should be valid */
  for (unsigned int code = 0; code <= 29; code++)
    {
      ASSERT_EQ (SocketDeflate_is_valid_distance_code (code), 1);
    }
}

/*
 * Fixed Huffman Code Length Tests
 */

/* RFC 1951 Section 3.2.6: literal/length code lengths */
TEST (deflate_fixed_litlen_lengths_rfc_compliance)
{
  int i;

  /* 0-143: 8 bits */
  for (i = 0; i < 144; i++)
    {
      ASSERT_EQ (deflate_fixed_litlen_lengths[i], 8);
    }

  /* 144-255: 9 bits */
  for (i = 144; i < 256; i++)
    {
      ASSERT_EQ (deflate_fixed_litlen_lengths[i], 9);
    }

  /* 256-279: 7 bits */
  for (i = 256; i < 280; i++)
    {
      ASSERT_EQ (deflate_fixed_litlen_lengths[i], 7);
    }

  /* 280-287: 8 bits */
  for (i = 280; i < 288; i++)
    {
      ASSERT_EQ (deflate_fixed_litlen_lengths[i], 8);
    }
}

/* Test fixed litlen lengths table size */
TEST (deflate_fixed_litlen_lengths_size)
{
  ASSERT_EQ (sizeof (deflate_fixed_litlen_lengths)
                 / sizeof (deflate_fixed_litlen_lengths[0]),
             DEFLATE_LITLEN_CODES);
  ASSERT_EQ (DEFLATE_LITLEN_CODES, 288);
}

/* RFC 1951 Section 3.2.6: all distance codes are 5 bits */
TEST (deflate_fixed_dist_lengths_all_five_bits)
{
  for (int i = 0; i < 32; i++)
    {
      ASSERT_EQ (deflate_fixed_dist_lengths[i], 5);
    }
}

/* Test fixed dist lengths table size */
TEST (deflate_fixed_dist_lengths_size)
{
  ASSERT_EQ (
      sizeof (deflate_fixed_dist_lengths) / sizeof (deflate_fixed_dist_lengths[0]),
      DEFLATE_DIST_CODES);
  ASSERT_EQ (DEFLATE_DIST_CODES, 32);
}

/*
 * Code Length Alphabet Order Tests
 */

/* RFC 1951 Section 3.2.7: exact permutation for dynamic blocks */
TEST (deflate_codelen_order_exact_match)
{
  /* Exact order from RFC 1951 Section 3.2.7 */
  const uint8_t expected[19]
      = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

  for (int i = 0; i < 19; i++)
    {
      ASSERT_EQ (deflate_codelen_order[i], expected[i]);
    }
}

/* Test code length order table size */
TEST (deflate_codelen_order_size)
{
  ASSERT_EQ (sizeof (deflate_codelen_order) / sizeof (deflate_codelen_order[0]),
             DEFLATE_CODELEN_CODES);
  ASSERT_EQ (DEFLATE_CODELEN_CODES, 19);
}

/* All values in code length order should be 0-18 */
TEST (deflate_codelen_order_values_in_range)
{
  for (int i = 0; i < 19; i++)
    {
      ASSERT (deflate_codelen_order[i] < 19);
    }
}

/*
 * Decode Function Error Handling Tests
 */

/* Length decode should reject invalid codes */
TEST (deflate_decode_length_invalid_codes)
{
  unsigned int length = 0;

  /* Codes below 257 are not length codes */
  ASSERT_EQ (SocketDeflate_decode_length (0, 0, &length),
             DEFLATE_ERROR_INVALID_CODE);
  ASSERT_EQ (SocketDeflate_decode_length (256, 0, &length),
             DEFLATE_ERROR_INVALID_CODE);

  /* Codes 286-287 are invalid */
  ASSERT_EQ (SocketDeflate_decode_length (286, 0, &length),
             DEFLATE_ERROR_INVALID_CODE);
  ASSERT_EQ (SocketDeflate_decode_length (287, 0, &length),
             DEFLATE_ERROR_INVALID_CODE);

  /* Codes above 287 are invalid */
  ASSERT_EQ (SocketDeflate_decode_length (288, 0, &length),
             DEFLATE_ERROR_INVALID_CODE);
}

/* Distance decode should reject invalid codes */
TEST (deflate_decode_distance_invalid_codes)
{
  unsigned int distance = 0;

  /* Codes 30-31 are invalid */
  ASSERT_EQ (SocketDeflate_decode_distance (30, 0, &distance),
             DEFLATE_ERROR_INVALID_DISTANCE);
  ASSERT_EQ (SocketDeflate_decode_distance (31, 0, &distance),
             DEFLATE_ERROR_INVALID_DISTANCE);

  /* Codes above 31 are invalid */
  ASSERT_EQ (SocketDeflate_decode_distance (32, 0, &distance),
             DEFLATE_ERROR_INVALID_DISTANCE);
}

/*
 * Constant Value Tests
 */

/* Verify key constants match RFC 1951 */
TEST (deflate_constants_rfc_compliance)
{
  /* Maximum Huffman code length is 15 bits */
  ASSERT_EQ (DEFLATE_MAX_BITS, 15);

  /* Sliding window is 32KB */
  ASSERT_EQ (DEFLATE_WINDOW_SIZE, 32768);

  /* Match lengths are 3-258 */
  ASSERT_EQ (DEFLATE_MIN_MATCH, 3);
  ASSERT_EQ (DEFLATE_MAX_MATCH, 258);

  /* End-of-block is symbol 256 */
  ASSERT_EQ (DEFLATE_END_OF_BLOCK, 256);
}

/* Verify block type constants */
TEST (deflate_block_type_constants)
{
  ASSERT_EQ (DEFLATE_BLOCK_STORED, 0);
  ASSERT_EQ (DEFLATE_BLOCK_FIXED, 1);
  ASSERT_EQ (DEFLATE_BLOCK_DYNAMIC, 2);
  ASSERT_EQ (DEFLATE_BLOCK_RESERVED, 3);
}

/*
 * Extra Bits Helper Function Tests
 */

/* Test get_length_extra_bits for all valid codes */
TEST (deflate_get_length_extra_bits_all_codes)
{
  unsigned int extra_bits;

  /* Code 257-264: 0 extra bits */
  for (unsigned int code = 257; code <= 264; code++)
    {
      ASSERT_EQ (SocketDeflate_get_length_extra_bits (code, &extra_bits),
                 DEFLATE_OK);
      ASSERT_EQ (extra_bits, 0);
    }

  /* Code 265-268: 1 extra bit */
  for (unsigned int code = 265; code <= 268; code++)
    {
      ASSERT_EQ (SocketDeflate_get_length_extra_bits (code, &extra_bits),
                 DEFLATE_OK);
      ASSERT_EQ (extra_bits, 1);
    }

  /* Code 269-272: 2 extra bits */
  for (unsigned int code = 269; code <= 272; code++)
    {
      ASSERT_EQ (SocketDeflate_get_length_extra_bits (code, &extra_bits),
                 DEFLATE_OK);
      ASSERT_EQ (extra_bits, 2);
    }

  /* Code 273-276: 3 extra bits */
  for (unsigned int code = 273; code <= 276; code++)
    {
      ASSERT_EQ (SocketDeflate_get_length_extra_bits (code, &extra_bits),
                 DEFLATE_OK);
      ASSERT_EQ (extra_bits, 3);
    }

  /* Code 277-280: 4 extra bits */
  for (unsigned int code = 277; code <= 280; code++)
    {
      ASSERT_EQ (SocketDeflate_get_length_extra_bits (code, &extra_bits),
                 DEFLATE_OK);
      ASSERT_EQ (extra_bits, 4);
    }

  /* Code 281-284: 5 extra bits */
  for (unsigned int code = 281; code <= 284; code++)
    {
      ASSERT_EQ (SocketDeflate_get_length_extra_bits (code, &extra_bits),
                 DEFLATE_OK);
      ASSERT_EQ (extra_bits, 5);
    }

  /* Code 285: 0 extra bits (special case) */
  ASSERT_EQ (SocketDeflate_get_length_extra_bits (285, &extra_bits), DEFLATE_OK);
  ASSERT_EQ (extra_bits, 0);
}

/* Test get_length_extra_bits error handling */
TEST (deflate_get_length_extra_bits_invalid)
{
  unsigned int extra_bits = 99;

  /* Codes below 257 are invalid */
  ASSERT_EQ (SocketDeflate_get_length_extra_bits (0, &extra_bits),
             DEFLATE_ERROR_INVALID_CODE);
  ASSERT_EQ (SocketDeflate_get_length_extra_bits (256, &extra_bits),
             DEFLATE_ERROR_INVALID_CODE);

  /* Codes above 285 are invalid */
  ASSERT_EQ (SocketDeflate_get_length_extra_bits (286, &extra_bits),
             DEFLATE_ERROR_INVALID_CODE);
  ASSERT_EQ (SocketDeflate_get_length_extra_bits (1000, &extra_bits),
             DEFLATE_ERROR_INVALID_CODE);
}

/* Test get_distance_extra_bits for all valid codes */
TEST (deflate_get_distance_extra_bits_all_codes)
{
  unsigned int extra_bits;

  /* Code 0-3: 0 extra bits */
  for (unsigned int code = 0; code <= 3; code++)
    {
      ASSERT_EQ (SocketDeflate_get_distance_extra_bits (code, &extra_bits),
                 DEFLATE_OK);
      ASSERT_EQ (extra_bits, 0);
    }

  /* Code 4-5: 1 extra bit */
  for (unsigned int code = 4; code <= 5; code++)
    {
      ASSERT_EQ (SocketDeflate_get_distance_extra_bits (code, &extra_bits),
                 DEFLATE_OK);
      ASSERT_EQ (extra_bits, 1);
    }

  /* Spot check higher codes */
  ASSERT_EQ (SocketDeflate_get_distance_extra_bits (10, &extra_bits), DEFLATE_OK);
  ASSERT_EQ (extra_bits, 4);

  ASSERT_EQ (SocketDeflate_get_distance_extra_bits (20, &extra_bits), DEFLATE_OK);
  ASSERT_EQ (extra_bits, 9);

  ASSERT_EQ (SocketDeflate_get_distance_extra_bits (29, &extra_bits), DEFLATE_OK);
  ASSERT_EQ (extra_bits, 13);
}

/* Test get_distance_extra_bits error handling */
TEST (deflate_get_distance_extra_bits_invalid)
{
  unsigned int extra_bits = 99;

  /* Codes 30-31 are invalid */
  ASSERT_EQ (SocketDeflate_get_distance_extra_bits (30, &extra_bits),
             DEFLATE_ERROR_INVALID_DISTANCE);
  ASSERT_EQ (SocketDeflate_get_distance_extra_bits (31, &extra_bits),
             DEFLATE_ERROR_INVALID_DISTANCE);

  /* Codes above 31 are invalid */
  ASSERT_EQ (SocketDeflate_get_distance_extra_bits (32, &extra_bits),
             DEFLATE_ERROR_INVALID_DISTANCE);
  ASSERT_EQ (SocketDeflate_get_distance_extra_bits (1000, &extra_bits),
             DEFLATE_ERROR_INVALID_DISTANCE);
}

/*
 * Extra Bits Overflow/Masking Tests
 */

/* Length decode masks extra bits to prevent overflow */
TEST (deflate_decode_length_extra_overflow_masked)
{
  unsigned int length;

  /* Code 257 has 0 extra bits - any extra value should be masked to 0 */
  ASSERT_EQ (SocketDeflate_decode_length (257, 0xFFFF, &length), DEFLATE_OK);
  ASSERT_EQ (length, 3); /* base=3, extra masked to 0 */

  /* Code 265 has 1 extra bit - extra=0xFF should be masked to 1 */
  ASSERT_EQ (SocketDeflate_decode_length (265, 0xFF, &length), DEFLATE_OK);
  ASSERT_EQ (length, 12); /* base=11, extra masked to 1 */

  /* Code 269 has 2 extra bits - extra=0xFF should be masked to 3 */
  ASSERT_EQ (SocketDeflate_decode_length (269, 0xFF, &length), DEFLATE_OK);
  ASSERT_EQ (length, 22); /* base=19, extra masked to 3 */

  /* Code 281 has 5 extra bits - extra=0xFF should be masked to 31 */
  ASSERT_EQ (SocketDeflate_decode_length (281, 0xFF, &length), DEFLATE_OK);
  ASSERT_EQ (length, 162); /* base=131, extra masked to 31 */

  /* Code 285 has 0 extra bits - any extra value should be masked to 0 */
  ASSERT_EQ (SocketDeflate_decode_length (285, 0xFFFFFFFF, &length), DEFLATE_OK);
  ASSERT_EQ (length, 258); /* base=258, extra masked to 0 */
}

/* Distance decode masks extra bits to prevent overflow */
TEST (deflate_decode_distance_extra_overflow_masked)
{
  unsigned int distance;

  /* Code 0 has 0 extra bits - any extra value should be masked to 0 */
  ASSERT_EQ (SocketDeflate_decode_distance (0, 0xFFFF, &distance), DEFLATE_OK);
  ASSERT_EQ (distance, 1); /* base=1, extra masked to 0 */

  /* Code 4 has 1 extra bit - extra=0xFF should be masked to 1 */
  ASSERT_EQ (SocketDeflate_decode_distance (4, 0xFF, &distance), DEFLATE_OK);
  ASSERT_EQ (distance, 6); /* base=5, extra masked to 1 */

  /* Code 10 has 4 extra bits - extra=0xFF should be masked to 15 */
  ASSERT_EQ (SocketDeflate_decode_distance (10, 0xFF, &distance), DEFLATE_OK);
  ASSERT_EQ (distance, 48); /* base=33, extra masked to 15 */

  /* Code 29 has 13 extra bits - extra=0xFFFF should be masked to 8191 */
  ASSERT_EQ (SocketDeflate_decode_distance (29, 0xFFFF, &distance), DEFLATE_OK);
  ASSERT_EQ (distance, 32768); /* base=24577, extra masked to 8191 */
}

/* Verify masking produces values within valid ranges */
TEST (deflate_decode_masked_values_in_range)
{
  unsigned int length, distance;

  /* Test all length codes with overflow extra - all should be <= MAX_MATCH */
  for (unsigned int code = DEFLATE_LENGTH_CODE_MIN;
       code <= DEFLATE_LENGTH_CODE_MAX; code++)
    {
      ASSERT_EQ (SocketDeflate_decode_length (code, 0xFFFFFFFF, &length),
                 DEFLATE_OK);
      ASSERT (length >= DEFLATE_MIN_MATCH);
      ASSERT (length <= DEFLATE_MAX_MATCH);
    }

  /* Test all distance codes with overflow extra - all should be <= WINDOW_SIZE */
  for (unsigned int code = DEFLATE_DISTANCE_CODE_MIN;
       code <= DEFLATE_DISTANCE_CODE_MAX; code++)
    {
      ASSERT_EQ (SocketDeflate_decode_distance (code, 0xFFFFFFFF, &distance),
                 DEFLATE_OK);
      ASSERT (distance >= 1);
      ASSERT (distance <= DEFLATE_WINDOW_SIZE);
    }
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
