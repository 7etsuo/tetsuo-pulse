/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_deflate_roundtrip.c - RFC 1951 encode/decode roundtrip tests
 *
 * Verifies that encoding and decoding are inverse operations:
 * - Length encode/decode roundtrip for all valid lengths (3-258)
 * - Distance encode/decode roundtrip for all valid distances (1-32768)
 * - Huffman code generation produces codes that decode correctly
 *
 * These tests ensure consistency between the compression and decompression
 * paths per RFC 1951 Section 3.2.5.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "deflate/SocketDeflate.h"
#include "test/Test.h"

static Arena_T test_arena;

/*
 * Length Roundtrip Tests
 */

TEST (roundtrip_length_min)
{
  /* Test minimum match length (3) */
  unsigned int code, extra, extra_bits;
  unsigned int decoded;
  SocketDeflate_Result result;

  SocketDeflate_encode_length (3, &code, &extra, &extra_bits);
  ASSERT_EQ (code, 257);
  ASSERT_EQ (extra_bits, 0);

  result = SocketDeflate_decode_length (code, extra, &decoded);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (decoded, 3);
}

TEST (roundtrip_length_max)
{
  /* Test maximum match length (258) */
  unsigned int code, extra, extra_bits;
  unsigned int decoded;
  SocketDeflate_Result result;

  SocketDeflate_encode_length (258, &code, &extra, &extra_bits);
  ASSERT_EQ (code, 285);
  ASSERT_EQ (extra_bits, 0);

  result = SocketDeflate_decode_length (code, extra, &decoded);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (decoded, 258);
}

TEST (roundtrip_length_all)
{
  /*
   * Verify all valid lengths (3-258) roundtrip correctly.
   * This is the comprehensive test per RFC 1951 Section 3.2.5.
   */
  unsigned int code, extra, extra_bits;
  unsigned int decoded;
  SocketDeflate_Result result;

  for (unsigned int length = 3; length <= 258; length++)
    {
      SocketDeflate_encode_length (length, &code, &extra, &extra_bits);

      /* Verify code is in valid range */
      ASSERT (code >= 257 && code <= 285);

      /* Verify extra bits count is valid */
      ASSERT (extra_bits <= 5);

      /* Verify extra value fits in extra_bits */
      if (extra_bits > 0)
        {
          ASSERT (extra < (1U << extra_bits));
        }

      /* Decode and verify we get the original length */
      result = SocketDeflate_decode_length (code, extra, &decoded);
      ASSERT_EQ (result, DEFLATE_OK);
      ASSERT_EQ (decoded, length);
    }
}

TEST (roundtrip_length_boundaries)
{
  /*
   * Test boundaries where extra bits count changes.
   * Per RFC 1951 Section 3.2.5, these are key transition points.
   */
  struct
  {
    unsigned int length;
    unsigned int expected_code;
    unsigned int expected_extra_bits;
  } boundaries[] = {
    { 10, 264, 0 },  /* Last 0-extra-bit code */
    { 11, 265, 1 },  /* First 1-extra-bit code */
    { 12, 265, 1 },  /* Second value in 1-extra range */
    { 18, 268, 1 },  /* Last 1-extra-bit code */
    { 19, 269, 2 },  /* First 2-extra-bit code */
    { 34, 272, 2 },  /* Last 2-extra-bit code */
    { 35, 273, 3 },  /* First 3-extra-bit code */
    { 66, 276, 3 },  /* Last 3-extra-bit code */
    { 67, 277, 4 },  /* First 4-extra-bit code */
    { 130, 280, 4 }, /* Last 4-extra-bit code */
    { 131, 281, 5 }, /* First 5-extra-bit code */
    { 257, 284, 5 }, /* Last 5-extra-bit code (257) */
    { 258, 285, 0 }, /* Special code 285 = exactly 258 */
  };

  for (size_t i = 0; i < sizeof (boundaries) / sizeof (boundaries[0]); i++)
    {
      unsigned int code, extra, extra_bits;
      unsigned int decoded;

      SocketDeflate_encode_length (boundaries[i].length, &code, &extra,
                                   &extra_bits);

      ASSERT_EQ (code, boundaries[i].expected_code);
      ASSERT_EQ (extra_bits, boundaries[i].expected_extra_bits);

      SocketDeflate_Result result
          = SocketDeflate_decode_length (code, extra, &decoded);
      ASSERT_EQ (result, DEFLATE_OK);
      ASSERT_EQ (decoded, boundaries[i].length);
    }
}

/*
 * Distance Roundtrip Tests
 */

TEST (roundtrip_distance_min)
{
  /* Test minimum distance (1) */
  unsigned int code, extra, extra_bits;
  unsigned int decoded;
  SocketDeflate_Result result;

  SocketDeflate_encode_distance (1, &code, &extra, &extra_bits);
  ASSERT_EQ (code, 0);
  ASSERT_EQ (extra_bits, 0);

  result = SocketDeflate_decode_distance (code, extra, &decoded);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (decoded, 1);
}

TEST (roundtrip_distance_max)
{
  /* Test maximum distance (32768) */
  unsigned int code, extra, extra_bits;
  unsigned int decoded;
  SocketDeflate_Result result;

  SocketDeflate_encode_distance (32768, &code, &extra, &extra_bits);
  ASSERT_EQ (code, 29);
  ASSERT_EQ (extra_bits, 13);

  result = SocketDeflate_decode_distance (code, extra, &decoded);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (decoded, 32768);
}

TEST (roundtrip_distance_all)
{
  /*
   * Verify all valid distances (1-32768) roundtrip correctly.
   * This is the comprehensive test per RFC 1951 Section 3.2.5.
   */
  unsigned int code, extra, extra_bits;
  unsigned int decoded;
  SocketDeflate_Result result;

  for (unsigned int distance = 1; distance <= 32768; distance++)
    {
      SocketDeflate_encode_distance (distance, &code, &extra, &extra_bits);

      /* Verify code is in valid range */
      ASSERT (code <= 29);

      /* Verify extra bits count is valid */
      ASSERT (extra_bits <= 13);

      /* Verify extra value fits in extra_bits */
      if (extra_bits > 0)
        {
          ASSERT (extra < (1U << extra_bits));
        }

      /* Decode and verify we get the original distance */
      result = SocketDeflate_decode_distance (code, extra, &decoded);
      ASSERT_EQ (result, DEFLATE_OK);
      ASSERT_EQ (decoded, distance);
    }
}

TEST (roundtrip_distance_boundaries)
{
  /*
   * Test boundaries where extra bits count changes.
   * Per RFC 1951 Section 3.2.5, these are key transition points.
   */
  struct
  {
    unsigned int distance;
    unsigned int expected_code;
    unsigned int expected_extra_bits;
  } boundaries[] = {
    { 4, 3, 0 },       /* Last 0-extra-bit code */
    { 5, 4, 1 },       /* First 1-extra-bit code */
    { 8, 5, 1 },       /* Last 1-extra-bit code */
    { 9, 6, 2 },       /* First 2-extra-bit code */
    { 16, 7, 2 },      /* Last 2-extra-bit code */
    { 17, 8, 3 },      /* First 3-extra-bit code */
    { 32, 9, 3 },      /* Last 3-extra-bit code */
    { 33, 10, 4 },     /* First 4-extra-bit code */
    { 64, 11, 4 },     /* Last 4-extra-bit code */
    { 65, 12, 5 },     /* First 5-extra-bit code */
    { 128, 13, 5 },    /* Last 5-extra-bit code */
    { 129, 14, 6 },    /* First 6-extra-bit code */
    { 256, 15, 6 },    /* Last 6-extra-bit code */
    { 257, 16, 7 },    /* First 7-extra-bit code */
    { 512, 17, 7 },    /* Last 7-extra-bit code */
    { 513, 18, 8 },    /* First 8-extra-bit code */
    { 1024, 19, 8 },   /* Last 8-extra-bit code */
    { 1025, 20, 9 },   /* First 9-extra-bit code */
    { 2048, 21, 9 },   /* Last 9-extra-bit code */
    { 2049, 22, 10 },  /* First 10-extra-bit code */
    { 4096, 23, 10 },  /* Last 10-extra-bit code */
    { 4097, 24, 11 },  /* First 11-extra-bit code */
    { 8192, 25, 11 },  /* Last 11-extra-bit code */
    { 8193, 26, 12 },  /* First 12-extra-bit code */
    { 16384, 27, 12 }, /* Last 12-extra-bit code */
    { 16385, 28, 13 }, /* First 13-extra-bit code */
    { 32768, 29, 13 }, /* Last 13-extra-bit code */
  };

  for (size_t i = 0; i < sizeof (boundaries) / sizeof (boundaries[0]); i++)
    {
      unsigned int code, extra, extra_bits;
      unsigned int decoded;

      SocketDeflate_encode_distance (boundaries[i].distance, &code, &extra,
                                     &extra_bits);

      ASSERT_EQ (code, boundaries[i].expected_code);
      ASSERT_EQ (extra_bits, boundaries[i].expected_extra_bits);

      SocketDeflate_Result result
          = SocketDeflate_decode_distance (code, extra, &decoded);
      ASSERT_EQ (result, DEFLATE_OK);
      ASSERT_EQ (decoded, boundaries[i].distance);
    }
}

/*
 * Huffman Code Roundtrip Tests
 */

TEST (roundtrip_huffman_codes_simple)
{
  /*
   * Generate codes for a simple 4-symbol alphabet, build decode table,
   * and verify all symbols decode correctly.
   */
  uint32_t freqs[4] = { 100, 50, 25, 10 };
  uint8_t lengths[4];
  SocketDeflate_HuffmanCode codes[4];

  /* Build code lengths */
  SocketDeflate_Result result = SocketDeflate_build_code_lengths (
      freqs, lengths, 4, DEFLATE_MAX_BITS, test_arena);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Generate canonical codes */
  SocketDeflate_generate_codes (lengths, codes, 4);

  /* Build decode table */
  SocketDeflate_HuffmanTable_T table
      = SocketDeflate_HuffmanTable_new (test_arena);
  result = SocketDeflate_HuffmanTable_build (table, lengths, 4, DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Verify each symbol decodes correctly by encoding with BitWriter
     and decoding with the table */
  for (unsigned int sym = 0; sym < 4; sym++)
    {
      if (codes[sym].len == 0)
        continue;

      /* Write the code to a bit stream */
      uint8_t buffer[16] = { 0 };
      SocketDeflate_BitWriter_T writer
          = SocketDeflate_BitWriter_new (test_arena);
      SocketDeflate_BitWriter_init (writer, buffer, sizeof (buffer));

      result = SocketDeflate_BitWriter_write_huffman (writer, codes[sym].code,
                                                      codes[sym].len);
      ASSERT_EQ (result, DEFLATE_OK);

      /* Pad to byte boundary */
      size_t written = SocketDeflate_BitWriter_flush (writer);
      ASSERT (written > 0);

      /* Read it back with bit reader and decode */
      SocketDeflate_BitReader_T reader
          = SocketDeflate_BitReader_new (test_arena);
      SocketDeflate_BitReader_init (reader, buffer, written);

      uint16_t decoded_sym;
      result = SocketDeflate_HuffmanTable_decode (table, reader, &decoded_sym);
      ASSERT_EQ (result, DEFLATE_OK);
      ASSERT_EQ (decoded_sym, sym);
    }
}

TEST (roundtrip_huffman_fixed_litlen)
{
  /*
   * Verify that the fixed literal/length table can decode all
   * its symbols correctly.
   */
  SocketDeflate_HuffmanCode codes[DEFLATE_LITLEN_CODES];

  /* Generate canonical codes from fixed lengths */
  SocketDeflate_generate_codes (deflate_fixed_litlen_lengths, codes,
                                DEFLATE_LITLEN_CODES);

  /* Build decode table */
  SocketDeflate_HuffmanTable_T table
      = SocketDeflate_HuffmanTable_new (test_arena);
  SocketDeflate_Result result = SocketDeflate_HuffmanTable_build (
      table, deflate_fixed_litlen_lengths, DEFLATE_LITLEN_CODES,
      DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Test a sampling of symbols across different code lengths */
  unsigned int test_symbols[] = {
    0,           /* Literal 0 (8 bits) */
    143,         /* Last 8-bit literal */
    144,         /* First 9-bit literal */
    255,         /* Last 9-bit literal */
    256,         /* End-of-block (7 bits) */
    257,         /* First length code (7 bits) */
    279,         /* Last 7-bit length code */
    280,         /* First 8-bit length code */
    285,         /* Last length code (8 bits) */
  };

  for (size_t i = 0; i < sizeof (test_symbols) / sizeof (test_symbols[0]); i++)
    {
      unsigned int sym = test_symbols[i];
      uint8_t buffer[16] = { 0 };

      /* Write the code */
      SocketDeflate_BitWriter_T writer
          = SocketDeflate_BitWriter_new (test_arena);
      SocketDeflate_BitWriter_init (writer, buffer, sizeof (buffer));

      result = SocketDeflate_BitWriter_write_huffman (writer, codes[sym].code,
                                                      codes[sym].len);
      ASSERT_EQ (result, DEFLATE_OK);

      size_t written = SocketDeflate_BitWriter_flush (writer);

      /* Read and decode */
      SocketDeflate_BitReader_T reader
          = SocketDeflate_BitReader_new (test_arena);
      SocketDeflate_BitReader_init (reader, buffer, written);

      uint16_t decoded_sym;
      result = SocketDeflate_HuffmanTable_decode (table, reader, &decoded_sym);
      ASSERT_EQ (result, DEFLATE_OK);
      ASSERT_EQ (decoded_sym, sym);
    }
}

TEST (roundtrip_huffman_fixed_distance)
{
  /*
   * Verify that the fixed distance table can decode all
   * its 30 valid codes correctly.
   */
  SocketDeflate_HuffmanCode codes[DEFLATE_DIST_CODES];

  /* Generate canonical codes from fixed lengths */
  SocketDeflate_generate_codes (deflate_fixed_dist_lengths, codes,
                                DEFLATE_DIST_CODES);

  /* Build decode table */
  SocketDeflate_HuffmanTable_T table
      = SocketDeflate_HuffmanTable_new (test_arena);
  SocketDeflate_Result result = SocketDeflate_HuffmanTable_build (
      table, deflate_fixed_dist_lengths, DEFLATE_DIST_CODES, DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Test all 30 valid distance codes */
  for (unsigned int sym = 0; sym < 30; sym++)
    {
      uint8_t buffer[16] = { 0 };

      /* Write the code */
      SocketDeflate_BitWriter_T writer
          = SocketDeflate_BitWriter_new (test_arena);
      SocketDeflate_BitWriter_init (writer, buffer, sizeof (buffer));

      result = SocketDeflate_BitWriter_write_huffman (writer, codes[sym].code,
                                                      codes[sym].len);
      ASSERT_EQ (result, DEFLATE_OK);

      size_t written = SocketDeflate_BitWriter_flush (writer);

      /* Read and decode */
      SocketDeflate_BitReader_T reader
          = SocketDeflate_BitReader_new (test_arena);
      SocketDeflate_BitReader_init (reader, buffer, written);

      uint16_t decoded_sym;
      result = SocketDeflate_HuffmanTable_decode (table, reader, &decoded_sym);
      ASSERT_EQ (result, DEFLATE_OK);
      ASSERT_EQ (decoded_sym, sym);
    }
}

TEST (roundtrip_huffman_dynamic)
{
  /*
   * Build a dynamic Huffman table from custom frequencies,
   * encode all symbols, and verify they decode correctly.
   */
  /* Create a frequency distribution with varying frequencies */
  uint32_t freqs[16];
  for (unsigned int i = 0; i < 16; i++)
    {
      freqs[i] = (i % 4 == 0) ? 100 : (i % 4 == 1) ? 50 : (i % 4 == 2) ? 25 : 10;
    }

  uint8_t lengths[16];
  SocketDeflate_HuffmanCode codes[16];

  /* Build code lengths */
  SocketDeflate_Result result = SocketDeflate_build_code_lengths (
      freqs, lengths, 16, DEFLATE_MAX_BITS, test_arena);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Generate canonical codes */
  SocketDeflate_generate_codes (lengths, codes, 16);

  /* Build decode table */
  SocketDeflate_HuffmanTable_T table
      = SocketDeflate_HuffmanTable_new (test_arena);
  result = SocketDeflate_HuffmanTable_build (table, lengths, 16, DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Test all 16 symbols */
  for (unsigned int sym = 0; sym < 16; sym++)
    {
      uint8_t buffer[16] = { 0 };

      /* Write the code */
      SocketDeflate_BitWriter_T writer
          = SocketDeflate_BitWriter_new (test_arena);
      SocketDeflate_BitWriter_init (writer, buffer, sizeof (buffer));

      result = SocketDeflate_BitWriter_write_huffman (writer, codes[sym].code,
                                                      codes[sym].len);
      ASSERT_EQ (result, DEFLATE_OK);

      size_t written = SocketDeflate_BitWriter_flush (writer);

      /* Read and decode */
      SocketDeflate_BitReader_T reader
          = SocketDeflate_BitReader_new (test_arena);
      SocketDeflate_BitReader_init (reader, buffer, written);

      uint16_t decoded_sym;
      result = SocketDeflate_HuffmanTable_decode (table, reader, &decoded_sym);
      ASSERT_EQ (result, DEFLATE_OK);
      ASSERT_EQ (decoded_sym, sym);
    }
}

TEST (roundtrip_codes_sequence)
{
  /*
   * Write a sequence of codes, then decode them all.
   * This tests that multiple codes in sequence roundtrip correctly.
   */
  uint32_t freqs[8] = { 100, 80, 60, 40, 30, 20, 15, 10 };
  uint8_t lengths[8];
  SocketDeflate_HuffmanCode codes[8];

  SocketDeflate_Result result = SocketDeflate_build_code_lengths (
      freqs, lengths, 8, DEFLATE_MAX_BITS, test_arena);
  ASSERT_EQ (result, DEFLATE_OK);

  SocketDeflate_generate_codes (lengths, codes, 8);

  SocketDeflate_HuffmanTable_T table
      = SocketDeflate_HuffmanTable_new (test_arena);
  result = SocketDeflate_HuffmanTable_build (table, lengths, 8, DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Encode a sequence of symbols */
  unsigned int sequence[] = { 0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 1, 7, 3, 5 };
  size_t seq_len = sizeof (sequence) / sizeof (sequence[0]);

  uint8_t buffer[64] = { 0 };
  SocketDeflate_BitWriter_T writer = SocketDeflate_BitWriter_new (test_arena);
  SocketDeflate_BitWriter_init (writer, buffer, sizeof (buffer));

  for (size_t i = 0; i < seq_len; i++)
    {
      unsigned int sym = sequence[i];
      result = SocketDeflate_BitWriter_write_huffman (writer, codes[sym].code,
                                                      codes[sym].len);
      ASSERT_EQ (result, DEFLATE_OK);
    }

  size_t written = SocketDeflate_BitWriter_flush (writer);

  /* Decode the sequence */
  SocketDeflate_BitReader_T reader = SocketDeflate_BitReader_new (test_arena);
  SocketDeflate_BitReader_init (reader, buffer, written);

  for (size_t i = 0; i < seq_len; i++)
    {
      uint16_t decoded_sym;
      result = SocketDeflate_HuffmanTable_decode (table, reader, &decoded_sym);
      ASSERT_EQ (result, DEFLATE_OK);
      ASSERT_EQ (decoded_sym, sequence[i]);
    }
}

/*
 * Kraft Inequality Validation
 */

TEST (roundtrip_kraft_sum)
{
  /*
   * Verify that generated codes satisfy Kraft's inequality:
   * sum(2^-len) <= 1
   *
   * For a complete prefix-free code, the sum equals exactly 1.
   * For incomplete codes (e.g., single symbol), sum < 1.
   */
  uint32_t freqs[8] = { 100, 50, 25, 12, 6, 3, 2, 1 };
  uint8_t lengths[8];

  SocketDeflate_Result result = SocketDeflate_build_code_lengths (
      freqs, lengths, 8, DEFLATE_MAX_BITS, test_arena);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Calculate Kraft sum: sum(2^(max_bits - len)) / 2^max_bits */
  unsigned int kraft_numerator = 0;
  for (unsigned int i = 0; i < 8; i++)
    {
      if (lengths[i] > 0)
        {
          kraft_numerator += 1U << (DEFLATE_MAX_BITS - lengths[i]);
        }
    }

  /* The sum should be <= 2^max_bits (which is 32768 for 15 bits) */
  unsigned int kraft_denominator = 1U << DEFLATE_MAX_BITS;
  ASSERT (kraft_numerator <= kraft_denominator);
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
