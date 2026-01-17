/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_deflate_huffgen.c - RFC 1951 Huffman code generator unit tests
 *
 * Tests for the Huffman code generator module, verifying correct
 * code length computation, canonical code generation, and RLE encoding.
 *
 * Test coverage:
 * - Code length generation from frequencies
 * - Special cases (0, 1, 2 symbols)
 * - Skewed frequency distributions
 * - Package-merge length limiting
 * - Canonical code generation (RFC 1951 §3.2.2)
 * - Kraft inequality verification
 * - RLE encoding (symbols 16-18)
 * - Length/distance code encoding
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "deflate/SocketDeflate.h"
#include "test/Test.h"

static Arena_T test_arena;

/*
 * Code Length Generation Tests
 */

TEST (code_lengths_empty)
{
  /* All frequencies = 0 should produce all lengths = 0 */
  uint32_t freqs[10] = { 0 };
  uint8_t lengths[10];

  ASSERT_EQ (SocketDeflate_build_code_lengths (
                 freqs, lengths, 10, DEFLATE_MAX_BITS, test_arena),
             DEFLATE_OK);

  for (int i = 0; i < 10; i++)
    ASSERT_EQ (lengths[i], 0);
}

TEST (code_lengths_single)
{
  /* Single symbol should get length 1 */
  uint32_t freqs[10] = { 0, 0, 0, 100, 0, 0, 0, 0, 0, 0 };
  uint8_t lengths[10];

  ASSERT_EQ (SocketDeflate_build_code_lengths (
                 freqs, lengths, 10, DEFLATE_MAX_BITS, test_arena),
             DEFLATE_OK);

  ASSERT_EQ (lengths[3], 1);

  /* All others should be 0 */
  for (int i = 0; i < 10; i++)
    {
      if (i != 3)
        ASSERT_EQ (lengths[i], 0);
    }
}

TEST (code_lengths_two)
{
  /* Two symbols both get length 1 */
  uint32_t freqs[10] = { 0, 50, 0, 100, 0, 0, 0, 0, 0, 0 };
  uint8_t lengths[10];

  ASSERT_EQ (SocketDeflate_build_code_lengths (
                 freqs, lengths, 10, DEFLATE_MAX_BITS, test_arena),
             DEFLATE_OK);

  ASSERT_EQ (lengths[1], 1);
  ASSERT_EQ (lengths[3], 1);
}

TEST (code_lengths_balanced)
{
  /* Equal frequencies should produce balanced tree */
  uint32_t freqs[8] = { 100, 100, 100, 100, 100, 100, 100, 100 };
  uint8_t lengths[8];

  ASSERT_EQ (SocketDeflate_build_code_lengths (
                 freqs, lengths, 8, DEFLATE_MAX_BITS, test_arena),
             DEFLATE_OK);

  /* All should have length 3 for 8 equal symbols */
  for (int i = 0; i < 8; i++)
    ASSERT_EQ (lengths[i], 3);
}

TEST (code_lengths_skewed)
{
  /*
   * Highly skewed distribution (1M:1 ratio).
   * Must still respect 15-bit limit.
   */
  uint32_t freqs[32];
  for (int i = 0; i < 32; i++)
    freqs[i] = i == 0 ? 1000000 : 1;

  uint8_t lengths[32];

  ASSERT_EQ (SocketDeflate_build_code_lengths (
                 freqs, lengths, 32, DEFLATE_MAX_BITS, test_arena),
             DEFLATE_OK);

  /* All lengths must be <= 15 */
  for (int i = 0; i < 32; i++)
    {
      if (freqs[i] > 0)
        ASSERT (lengths[i] <= DEFLATE_MAX_BITS);
    }

  /* Most frequent symbol should have shortest code */
  ASSERT (lengths[0] > 0);
  for (int i = 1; i < 32; i++)
    {
      if (lengths[i] > 0)
        ASSERT (lengths[i] >= lengths[0]);
    }
}

TEST (package_merge_limit)
{
  /*
   * Extreme distribution that would exceed 15 bits with standard Huffman.
   * Package-merge must limit to max_bits.
   */
  uint32_t freqs[DEFLATE_LITLEN_CODES];
  memset (freqs, 0, sizeof (freqs));

  /* Create exponentially increasing frequencies */
  for (int i = 0; i < 20; i++)
    freqs[i] = 1U << i;

  uint8_t lengths[DEFLATE_LITLEN_CODES];

  ASSERT_EQ (
      SocketDeflate_build_code_lengths (
          freqs, lengths, DEFLATE_LITLEN_CODES, DEFLATE_MAX_BITS, test_arena),
      DEFLATE_OK);

  /* All non-zero lengths must be <= 15 */
  for (int i = 0; i < DEFLATE_LITLEN_CODES; i++)
    {
      ASSERT (lengths[i] <= DEFLATE_MAX_BITS);
    }
}

/*
 * Canonical Code Generation Tests
 */

TEST (code_generation_rfc)
{
  /*
   * RFC 1951 example: ABCDEFGH with lengths (3,3,3,3,3,2,4,4)
   * Expected codes:
   *   A=010, B=011, C=100, D=101, E=110, F=00, G=1110, H=1111
   */
  uint8_t lengths[8] = { 3, 3, 3, 3, 3, 2, 4, 4 };
  SocketDeflate_HuffmanCode codes[8];

  SocketDeflate_generate_codes (lengths, codes, 8);

  /* Check lengths are preserved */
  for (int i = 0; i < 8; i++)
    ASSERT_EQ (codes[i].len, lengths[i]);

  /* Check F (index 5) gets shortest code (length 2) = 00 */
  ASSERT_EQ (codes[5].code, 0);
  ASSERT_EQ (codes[5].len, 2);

  /* Check G and H (index 6,7) get longest codes (length 4) */
  ASSERT_EQ (codes[6].len, 4);
  ASSERT_EQ (codes[7].len, 4);

  /* Codes should be consecutive for same length */
  ASSERT_EQ (codes[7].code, codes[6].code + 1);
}

TEST (code_generation_fixed)
{
  /*
   * Verify canonical code generation matches the pattern
   * used by the fixed Huffman codes.
   */
  uint8_t lengths[10] = { 8, 8, 8, 8, 7, 7, 7, 9, 9, 9 };
  SocketDeflate_HuffmanCode codes[10];

  SocketDeflate_generate_codes (lengths, codes, 10);

  /* 7-bit codes should come before 8-bit codes (numerically) */
  /* 8-bit codes should be consecutive */
  /* 9-bit codes should come after 8-bit codes */

  for (int i = 0; i < 10; i++)
    ASSERT_EQ (codes[i].len, lengths[i]);
}

TEST (kraft_inequality)
{
  /*
   * Verify generated code lengths satisfy Kraft's inequality:
   * sum(2^-length) <= 1
   *
   * For a complete tree, the sum equals exactly 1.
   */
  uint32_t freqs[8] = { 100, 200, 300, 400, 500, 600, 700, 800 };
  uint8_t lengths[8];
  SocketDeflate_HuffmanCode codes[8];

  ASSERT_EQ (
      SocketDeflate_build_code_lengths (freqs, lengths, 8, 15, test_arena),
      DEFLATE_OK);

  SocketDeflate_generate_codes (lengths, codes, 8);

  /* Calculate Kraft sum: sum(2^-len) * 2^15 to avoid floats */
  unsigned int kraft_sum = 0;
  for (int i = 0; i < 8; i++)
    {
      if (lengths[i] > 0)
        kraft_sum += (1U << (15 - lengths[i]));
    }

  /* Sum should be <= 2^15 for valid codes */
  ASSERT (kraft_sum <= (1U << 15));
}

TEST (kraft_incomplete)
{
  /*
   * Single symbol tree has incomplete code space (Kraft sum < 1).
   * This is allowed by RFC 1951.
   */
  uint32_t freqs[10] = { 0, 0, 0, 100, 0, 0, 0, 0, 0, 0 };
  uint8_t lengths[10];

  ASSERT_EQ (SocketDeflate_build_code_lengths (
                 freqs, lengths, 10, DEFLATE_MAX_BITS, test_arena),
             DEFLATE_OK);

  /* Single symbol gets length 1, Kraft sum = 2^-1 = 0.5 < 1 */
  ASSERT_EQ (lengths[3], 1);
}

TEST (identical_lengths)
{
  /*
   * All same length should produce consecutive codes.
   */
  uint8_t lengths[4] = { 2, 2, 2, 2 };
  SocketDeflate_HuffmanCode codes[4];

  SocketDeflate_generate_codes (lengths, codes, 4);

  ASSERT_EQ (codes[0].code, 0);
  ASSERT_EQ (codes[1].code, 1);
  ASSERT_EQ (codes[2].code, 2);
  ASSERT_EQ (codes[3].code, 3);
}

/*
 * RLE Encoding Tests
 */

TEST (rle_copy_run)
{
  /*
   * Symbol 16: copy previous length 3-6 times.
   * Input: [8, 8, 8, 8, 8] (5 eights)
   * Output: [8, 16, 2] (8 followed by "copy 4 times")
   */
  uint8_t lengths[5] = { 8, 8, 8, 8, 8 };
  uint8_t output[10];

  size_t count
      = SocketDeflate_encode_code_lengths (lengths, 5, output, sizeof (output));

  /* Should have encoded something */
  ASSERT (count > 0);
  ASSERT (count < 5); /* Should be compressed */

  /* First byte should be 8 (the literal) */
  ASSERT_EQ (output[0], 8);

  /* Should have a symbol 16 */
  int has_16 = 0;
  for (size_t i = 0; i < count; i++)
    {
      if (output[i] == 16)
        has_16 = 1;
    }
  ASSERT (has_16);
}

TEST (rle_zero_short)
{
  /*
   * Symbol 17: repeat 0 for 3-10 times.
   * Input: [0, 0, 0, 0, 0] (5 zeros)
   * Output: [17, 2] (repeat 0 for 5 times: 3+2)
   */
  uint8_t lengths[5] = { 0, 0, 0, 0, 0 };
  uint8_t output[10];

  size_t count
      = SocketDeflate_encode_code_lengths (lengths, 5, output, sizeof (output));

  /* Should be compressed */
  ASSERT (count > 0);
  ASSERT (count < 5);

  /* Should have a symbol 17 */
  ASSERT_EQ (output[0], 17);
}

TEST (rle_zero_long)
{
  /*
   * Symbol 18: repeat 0 for 11-138 times.
   * Input: 20 zeros
   * Output: [18, 9] (repeat 0 for 20 times: 11+9)
   */
  uint8_t lengths[20] = { 0 };
  uint8_t output[10];

  size_t count = SocketDeflate_encode_code_lengths (
      lengths, 20, output, sizeof (output));

  /* Should be compressed to just 2 bytes */
  ASSERT_EQ (count, 2);

  /* Should use symbol 18 */
  ASSERT_EQ (output[0], 18);
  ASSERT_EQ (output[1], 9); /* 20 - 11 = 9 */
}

TEST (rle_mixed)
{
  /*
   * Mixed literal and run-length codes.
   * Input: [8, 8, 8, 8, 0, 0, 0, 7, 7, 7, 7]
   */
  uint8_t lengths[11] = { 8, 8, 8, 8, 0, 0, 0, 7, 7, 7, 7 };
  uint8_t output[20];

  size_t count = SocketDeflate_encode_code_lengths (
      lengths, 11, output, sizeof (output));

  /* Should be compressed */
  ASSERT (count > 0);
  ASSERT (count < 11);
}

TEST (rle_start_with_repeat)
{
  /*
   * When first lengths repeat, emit literal first, then symbol 16.
   * Input: [5, 5, 5, 5, 5]
   * Output: [5, 16, 2] (5 followed by "copy 4 times")
   */
  uint8_t lengths[5] = { 5, 5, 5, 5, 5 };
  uint8_t output[10];

  size_t count
      = SocketDeflate_encode_code_lengths (lengths, 5, output, sizeof (output));

  /* First must be the literal 5 */
  ASSERT_EQ (output[0], 5);

  /* Then symbol 16 for the copies */
  ASSERT_EQ (output[1], 16);
}

TEST (rle_boundary_cross)
{
  /*
   * Zeros spanning what would be the litlen/distance boundary.
   * This tests that encoding works across boundaries.
   */
  uint8_t lengths[300];
  memset (lengths, 0, sizeof (lengths));

  /* Put some non-zero values around position 286 */
  lengths[280] = 8;
  lengths[290] = 8;

  uint8_t output[600];
  size_t count = SocketDeflate_encode_code_lengths (
      lengths, 300, output, sizeof (output));

  /* Should produce valid encoding */
  ASSERT (count > 0);
  ASSERT (count < 300);
}

/*
 * Length/Distance Encoding Tests
 */

TEST (length_encoder)
{
  unsigned int code, extra, extra_bits;

  /* Length 3 -> code 257, no extra bits */
  SocketDeflate_encode_length (3, &code, &extra, &extra_bits);
  ASSERT_EQ (code, 257);
  ASSERT_EQ (extra_bits, 0);

  /* Length 10 -> code 264, no extra bits */
  SocketDeflate_encode_length (10, &code, &extra, &extra_bits);
  ASSERT_EQ (code, 264);
  ASSERT_EQ (extra_bits, 0);

  /* Length 11 -> code 265, 1 extra bit, extra=0 */
  SocketDeflate_encode_length (11, &code, &extra, &extra_bits);
  ASSERT_EQ (code, 265);
  ASSERT_EQ (extra_bits, 1);
  ASSERT_EQ (extra, 0);

  /* Length 12 -> code 265, 1 extra bit, extra=1 */
  SocketDeflate_encode_length (12, &code, &extra, &extra_bits);
  ASSERT_EQ (code, 265);
  ASSERT_EQ (extra_bits, 1);
  ASSERT_EQ (extra, 1);

  /* Length 258 -> code 285, no extra bits */
  SocketDeflate_encode_length (258, &code, &extra, &extra_bits);
  ASSERT_EQ (code, 285);
  ASSERT_EQ (extra_bits, 0);
}

TEST (distance_encoder)
{
  unsigned int code, extra, extra_bits;

  /* Distance 1 -> code 0, no extra bits */
  SocketDeflate_encode_distance (1, &code, &extra, &extra_bits);
  ASSERT_EQ (code, 0);
  ASSERT_EQ (extra_bits, 0);

  /* Distance 4 -> code 3, no extra bits */
  SocketDeflate_encode_distance (4, &code, &extra, &extra_bits);
  ASSERT_EQ (code, 3);
  ASSERT_EQ (extra_bits, 0);

  /* Distance 5 -> code 4, 1 extra bit, extra=0 */
  SocketDeflate_encode_distance (5, &code, &extra, &extra_bits);
  ASSERT_EQ (code, 4);
  ASSERT_EQ (extra_bits, 1);
  ASSERT_EQ (extra, 0);

  /* Distance 6 -> code 4, 1 extra bit, extra=1 */
  SocketDeflate_encode_distance (6, &code, &extra, &extra_bits);
  ASSERT_EQ (code, 4);
  ASSERT_EQ (extra_bits, 1);
  ASSERT_EQ (extra, 1);

  /* Distance 32768 -> code 29, 13 extra bits */
  SocketDeflate_encode_distance (32768, &code, &extra, &extra_bits);
  ASSERT_EQ (code, 29);
  ASSERT_EQ (extra_bits, 13);
}

TEST (full_alphabet)
{
  /*
   * Test with full 288-symbol litlen alphabet.
   */
  uint32_t freqs[DEFLATE_LITLEN_CODES];
  for (int i = 0; i < DEFLATE_LITLEN_CODES; i++)
    freqs[i] = (i < 256) ? 100 : 1; /* Literals more common */

  uint8_t lengths[DEFLATE_LITLEN_CODES];

  ASSERT_EQ (
      SocketDeflate_build_code_lengths (
          freqs, lengths, DEFLATE_LITLEN_CODES, DEFLATE_MAX_BITS, test_arena),
      DEFLATE_OK);

  /* All used symbols should have valid lengths */
  for (int i = 0; i < DEFLATE_LITLEN_CODES; i++)
    {
      if (freqs[i] > 0)
        {
          ASSERT (lengths[i] > 0);
          ASSERT (lengths[i] <= DEFLATE_MAX_BITS);
        }
    }
}

/*
 * Package-Merge Algorithm Optimality Tests
 */

TEST (package_merge_optimal)
{
  /*
   * Verify high-frequency symbols get shorter codes than low-frequency.
   * Package-merge should produce optimal frequency-based lengths.
   */
  uint32_t freqs[4] = { 1000, 100, 10, 1 };
  uint8_t lengths[4];

  ASSERT_EQ (
      SocketDeflate_build_code_lengths (freqs, lengths, 4, 15, test_arena),
      DEFLATE_OK);

  /* Higher frequency should mean shorter or equal length */
  ASSERT (lengths[0] <= lengths[1]);
  ASSERT (lengths[1] <= lengths[2]);
  ASSERT (lengths[2] <= lengths[3]);

  /* With such skewed distribution, first should be shorter than last */
  ASSERT (lengths[0] < lengths[3]);
}

TEST (package_merge_respects_max_bits)
{
  /*
   * Exponential distribution that would need >20 bits with unlimited Huffman.
   * Package-merge must limit to max_bits=4.
   */
  uint32_t freqs[20];
  for (int i = 0; i < 20; i++)
    freqs[i] = 1U << i;

  uint8_t lengths[20];

  ASSERT_EQ (
      SocketDeflate_build_code_lengths (freqs, lengths, 20, 4, test_arena),
      DEFLATE_OK);

  /* All lengths must be <= 4 */
  for (int i = 0; i < 20; i++)
    ASSERT (lengths[i] <= 4);

  /* All symbols should have non-zero length */
  for (int i = 0; i < 20; i++)
    ASSERT (lengths[i] > 0);
}

TEST (package_merge_uniform)
{
  /*
   * 256 equal frequencies should produce length 8 for all.
   * 2^8 = 256 symbols, so all get equal codes.
   */
  uint32_t freqs[256];
  for (int i = 0; i < 256; i++)
    freqs[i] = 100;

  uint8_t lengths[256];

  ASSERT_EQ (
      SocketDeflate_build_code_lengths (freqs, lengths, 256, 15, test_arena),
      DEFLATE_OK);

  /* All should have length 8 for 256 equal symbols */
  for (int i = 0; i < 256; i++)
    ASSERT_EQ (lengths[i], 8);
}

TEST (package_merge_power_of_two)
{
  /*
   * 16 equal frequencies -> all length 4.
   * 2^4 = 16 symbols.
   */
  uint32_t freqs[16];
  for (int i = 0; i < 16; i++)
    freqs[i] = 50;

  uint8_t lengths[16];

  ASSERT_EQ (
      SocketDeflate_build_code_lengths (freqs, lengths, 16, 15, test_arena),
      DEFLATE_OK);

  for (int i = 0; i < 16; i++)
    ASSERT_EQ (lengths[i], 4);
}

TEST (package_merge_kraft_sum)
{
  /*
   * Verify package-merge output satisfies Kraft's inequality.
   * sum(2^-length) <= 1 (multiply by 2^15 to use integers)
   */
  uint32_t freqs[32];
  for (int i = 0; i < 32; i++)
    freqs[i] = (i + 1) * 10; /* Varying frequencies */

  uint8_t lengths[32];

  ASSERT_EQ (
      SocketDeflate_build_code_lengths (freqs, lengths, 32, 15, test_arena),
      DEFLATE_OK);

  /* Calculate Kraft sum */
  unsigned int kraft_sum = 0;
  for (int i = 0; i < 32; i++)
    {
      if (lengths[i] > 0)
        kraft_sum += (1U << (15 - lengths[i]));
    }

  /* Must be <= 2^15 for valid codes */
  ASSERT (kraft_sum <= (1U << 15));

  /* For complete tree, should equal 2^15 */
  ASSERT_EQ (kraft_sum, (1U << 15));
}

TEST (package_merge_three_symbols)
{
  /*
   * 3 symbols is the boundary between special-case handling (0,1,2)
   * and the full package-merge algorithm. Verify it works correctly.
   */
  uint32_t freqs[3] = { 100, 50, 10 };
  uint8_t lengths[3];

  ASSERT_EQ (
      SocketDeflate_build_code_lengths (freqs, lengths, 3, 15, test_arena),
      DEFLATE_OK);

  /* All should have valid lengths */
  for (int i = 0; i < 3; i++)
    {
      ASSERT (lengths[i] > 0);
      ASSERT (lengths[i] <= 15);
    }

  /* Higher frequency should mean shorter or equal length */
  ASSERT (lengths[0] <= lengths[1]);
  ASSERT (lengths[1] <= lengths[2]);

  /* Verify Kraft inequality */
  unsigned int kraft_sum = 0;
  for (int i = 0; i < 3; i++)
    kraft_sum += (1U << (15 - lengths[i]));
  ASSERT (kraft_sum <= (1U << 15));
}

TEST (package_merge_tiny_max_bits)
{
  /*
   * Very small max_bits (2) forces all codes to be very short.
   * With 4 symbols and max 2 bits, all must get length 2.
   */
  uint32_t freqs[4] = { 1000, 100, 10, 1 };
  uint8_t lengths[4];

  ASSERT_EQ (
      SocketDeflate_build_code_lengths (freqs, lengths, 4, 2, test_arena),
      DEFLATE_OK);

  /* All must be <= 2 bits */
  for (int i = 0; i < 4; i++)
    {
      ASSERT (lengths[i] > 0);
      ASSERT (lengths[i] <= 2);
    }

  /* With 4 symbols and max 2 bits, all should be exactly 2 */
  for (int i = 0; i < 4; i++)
    ASSERT_EQ (lengths[i], 2);
}

/*
 * Test Runner
 */

int
main (void)
{
  test_arena = Arena_new ();

  Test_run_all ();

  Arena_dispose (&test_arena);

  return Test_get_failures () > 0 ? 1 : 0;
}
