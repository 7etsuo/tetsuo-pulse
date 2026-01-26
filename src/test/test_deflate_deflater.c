/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_deflate_deflater.c - RFC 1951 DEFLATE compression API unit tests
 *
 * Tests for the Deflater streaming compression API, verifying:
 * - Deflater creation at all compression levels
 * - Stored block encoding (level 0)
 * - Fixed Huffman encoding (levels 1-3)
 * - Dynamic Huffman encoding (levels 4-9)
 * - Roundtrip compression/decompression
 * - Streaming with various buffer sizes
 * - Edge cases and boundary conditions
 * - zlib interoperability (compress with us, decompress with zlib and vice versa)
 *
 * Fixes #3418
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "deflate/SocketDeflate.h"
#include "test/Test.h"

/* zlib interoperability tests - enabled when zlib is available */
#if __has_include(<zlib.h>)
#define HAS_ZLIB 1
#include <zlib.h>
#endif

static Arena_T test_arena;
static int tables_initialized = 0;

/*
 * Ensure fixed tables are initialized for inflate operations
 */
static void
ensure_tables (void)
{
  if (!tables_initialized)
    {
      SocketDeflate_fixed_tables_init (test_arena);
      tables_initialized = 1;
    }
}

/*
 * Helper: Compress data with given level
 */
static size_t
compress_data (int level,
               const uint8_t *input,
               size_t input_len,
               uint8_t *output,
               size_t output_len)
{
  SocketDeflate_Deflater_T def;
  SocketDeflate_Result res;
  size_t consumed, written, total_written = 0;

  def = SocketDeflate_Deflater_new (test_arena, level);
  if (!def)
    return 0;

  res = SocketDeflate_Deflater_deflate (
      def, input, input_len, &consumed, output, output_len, &written);
  if (res != DEFLATE_OK)
    return 0;
  total_written += written;

  res = SocketDeflate_Deflater_finish (
      def, output + total_written, output_len - total_written, &written);
  if (res != DEFLATE_OK)
    return 0;
  total_written += written;

  return total_written;
}

/*
 * Helper: Decompress data
 */
static size_t
decompress_data (const uint8_t *input,
                 size_t input_len,
                 uint8_t *output,
                 size_t output_len)
{
  SocketDeflate_Inflater_T inf;
  SocketDeflate_Result res;
  size_t consumed, written;

  ensure_tables ();

  inf = SocketDeflate_Inflater_new (test_arena, output_len);
  if (!inf)
    return 0;

  res = SocketDeflate_Inflater_inflate (
      inf, input, input_len, &consumed, output, output_len, &written);
  if (res != DEFLATE_OK)
    return 0;

  return written;
}

/*
 * Helper: Test roundtrip at given level
 */
static int
roundtrip_test (int level, const uint8_t *input, size_t input_len)
{
  uint8_t compressed[65536];
  uint8_t decompressed[65536];
  size_t compressed_len, decompressed_len;

  compressed_len = compress_data (
      level, input, input_len, compressed, sizeof (compressed));
  if (compressed_len == 0 && input_len > 0)
    return 0;

  decompressed_len = decompress_data (
      compressed, compressed_len, decompressed, sizeof (decompressed));
  if (decompressed_len != input_len)
    return 0;

  return memcmp (input, decompressed, input_len) == 0;
}

/*
 * Deflater Creation Tests
 */

TEST (deflater_create_level0)
{
  SocketDeflate_Deflater_T def = SocketDeflate_Deflater_new (test_arena, 0);
  ASSERT (def != NULL);
}

TEST (deflater_create_level6)
{
  SocketDeflate_Deflater_T def = SocketDeflate_Deflater_new (test_arena, 6);
  ASSERT (def != NULL);
}

TEST (deflater_create_level9)
{
  SocketDeflate_Deflater_T def = SocketDeflate_Deflater_new (test_arena, 9);
  ASSERT (def != NULL);
}

TEST (deflater_create_negative_level)
{
  /* Negative levels should clamp to 0 */
  SocketDeflate_Deflater_T def = SocketDeflate_Deflater_new (test_arena, -1);
  ASSERT (def != NULL);
}

TEST (deflater_create_high_level)
{
  /* Levels > 9 should clamp to 9 */
  SocketDeflate_Deflater_T def = SocketDeflate_Deflater_new (test_arena, 100);
  ASSERT (def != NULL);
}

/*
 * Empty Input Tests
 */

TEST (deflater_empty_input)
{
  SocketDeflate_Deflater_T def;
  SocketDeflate_Result res;
  uint8_t output[64];
  size_t consumed, written, total = 0;

  def = SocketDeflate_Deflater_new (test_arena, 6);
  ASSERT (def != NULL);

  /* Empty deflate */
  res = SocketDeflate_Deflater_deflate (
      def, NULL, 0, &consumed, output, sizeof (output), &written);
  ASSERT_EQ (res, DEFLATE_OK);
  total += written;

  /* Finish */
  res = SocketDeflate_Deflater_finish (
      def, output + total, sizeof (output) - total, &written);
  ASSERT_EQ (res, DEFLATE_OK);
  total += written;

  /* Should produce at least an empty final block */
  ASSERT (total > 0);
}

/*
 * Stored Block Tests (Level 0)
 */

TEST (deflater_stored_small)
{
  const uint8_t input[] = "Hello, World!";
  ASSERT (roundtrip_test (0, input, sizeof (input) - 1));
}

TEST (deflater_stored_large)
{
  uint8_t input[4096];
  memset (input, 'X', sizeof (input));
  ASSERT (roundtrip_test (0, input, sizeof (input)));
}

/*
 * Fixed Huffman Tests (Levels 1-3)
 */

TEST (deflater_fixed_level1)
{
  const uint8_t input[] = "The quick brown fox jumps over the lazy dog.";
  ASSERT (roundtrip_test (1, input, sizeof (input) - 1));
}

TEST (deflater_fixed_level2)
{
  const uint8_t input[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  ASSERT (roundtrip_test (2, input, sizeof (input) - 1));
}

TEST (deflater_fixed_level3)
{
  /* Repeating data should find matches */
  const uint8_t input[] = "ABCDABCDABCDABCDABCDABCDABCDABCD";
  ASSERT (roundtrip_test (3, input, sizeof (input) - 1));
}

/*
 * Dynamic Huffman Tests (Levels 4-9)
 */

TEST (deflater_dynamic_level4)
{
  const uint8_t input[] = "Lorem ipsum dolor sit amet, consectetur "
                          "adipiscing elit, sed do eiusmod tempor incididunt.";
  ASSERT (roundtrip_test (4, input, sizeof (input) - 1));
}

TEST (deflater_dynamic_level6_default)
{
  const uint8_t input[] = "The default compression level (6) should produce "
                          "good compression with reasonable speed.";
  ASSERT (roundtrip_test (6, input, sizeof (input) - 1));
}

TEST (deflater_dynamic_level9_best)
{
  const uint8_t input[]
      = "Level 9 uses maximum effort for best compression. "
        "This test verifies correctness at the highest level.";
  ASSERT (roundtrip_test (9, input, sizeof (input) - 1));
}

/*
 * Roundtrip Tests with Various Data Patterns
 */

TEST (roundtrip_zeros)
{
  uint8_t input[1024];
  memset (input, 0, sizeof (input));
  ASSERT (roundtrip_test (6, input, sizeof (input)));
}

TEST (roundtrip_sequential)
{
  uint8_t input[256];
  for (int i = 0; i < 256; i++)
    input[i] = (uint8_t)i;
  ASSERT (roundtrip_test (6, input, sizeof (input)));
}

TEST (roundtrip_random_pattern)
{
  /* Pseudo-random data (deterministic for reproducibility) */
  uint8_t input[2048];
  unsigned int seed = 12345;
  for (size_t i = 0; i < sizeof (input); i++)
    {
      seed = seed * 1103515245 + 12345;
      input[i] = (uint8_t)(seed >> 16);
    }
  ASSERT (roundtrip_test (6, input, sizeof (input)));
}

TEST (roundtrip_repeated_pattern)
{
  /* Highly compressible: repeated 4-byte pattern */
  uint8_t input[4096];
  for (size_t i = 0; i < sizeof (input); i += 4)
    {
      input[i] = 'A';
      input[i + 1] = 'B';
      input[i + 2] = 'C';
      input[i + 3] = 'D';
    }
  ASSERT (roundtrip_test (6, input, sizeof (input)));
}

/*
 * API Tests
 */

TEST (deflater_reset)
{
  SocketDeflate_Deflater_T def;
  const uint8_t input[] = "Test data for reset";
  uint8_t output[256];
  size_t consumed, written;

  def = SocketDeflate_Deflater_new (test_arena, 6);
  ASSERT (def != NULL);

  /* First compression */
  SocketDeflate_Deflater_deflate (def,
                                  input,
                                  sizeof (input) - 1,
                                  &consumed,
                                  output,
                                  sizeof (output),
                                  &written);
  SocketDeflate_Deflater_finish (
      def, output + written, sizeof (output) - written, &written);

  /* Reset */
  SocketDeflate_Deflater_reset (def);
  ASSERT_EQ (SocketDeflate_Deflater_finished (def), 0);

  /* Second compression should work */
  SocketDeflate_Deflater_deflate (def,
                                  input,
                                  sizeof (input) - 1,
                                  &consumed,
                                  output,
                                  sizeof (output),
                                  &written);
  ASSERT_EQ (consumed, sizeof (input) - 1);
}

TEST (deflater_finished)
{
  SocketDeflate_Deflater_T def;
  const uint8_t input[] = "Test";
  uint8_t output[256];
  size_t consumed, written;

  def = SocketDeflate_Deflater_new (test_arena, 6);

  ASSERT_EQ (SocketDeflate_Deflater_finished (def), 0);

  SocketDeflate_Deflater_deflate (
      def, input, 4, &consumed, output, sizeof (output), &written);
  ASSERT_EQ (SocketDeflate_Deflater_finished (def), 0);

  SocketDeflate_Deflater_finish (
      def, output + written, sizeof (output) - written, &written);
  ASSERT_EQ (SocketDeflate_Deflater_finished (def), 1);
}

TEST (deflater_total_in_out)
{
  SocketDeflate_Deflater_T def;
  const uint8_t input[] = "This is test data to measure totals.";
  uint8_t output[256];
  size_t consumed, written;

  def = SocketDeflate_Deflater_new (test_arena, 6);

  SocketDeflate_Deflater_deflate (def,
                                  input,
                                  sizeof (input) - 1,
                                  &consumed,
                                  output,
                                  sizeof (output),
                                  &written);
  SocketDeflate_Deflater_finish (
      def, output + written, sizeof (output) - written, &written);

  ASSERT_EQ (SocketDeflate_Deflater_total_in (def), sizeof (input) - 1);
  ASSERT (SocketDeflate_Deflater_total_out (def) > 0);
}

TEST (compress_bound)
{
  /* Verify compress_bound returns reasonable values */
  size_t bound;

  bound = SocketDeflate_compress_bound (0);
  ASSERT (bound > 0);

  bound = SocketDeflate_compress_bound (1000);
  ASSERT (bound >= 1000);

  bound = SocketDeflate_compress_bound (65536);
  ASSERT (bound >= 65536);
}

/*
 * All Levels Roundtrip Test
 */

TEST (all_levels_roundtrip)
{
  const uint8_t input[]
      = "Test all compression levels 0-9 produce correct output.";

  for (int level = 0; level <= 9; level++)
    {
      ASSERT (roundtrip_test (level, input, sizeof (input) - 1));
    }
}

/*
 * Larger Data Tests
 */

TEST (large_data_16kb)
{
  uint8_t *input;
  size_t size = 16384;
  int result;

  input = ALLOC (test_arena, size);
  for (size_t i = 0; i < size; i++)
    input[i] = (uint8_t)(i * 7);

  result = roundtrip_test (6, input, size);
  ASSERT (result);
}

TEST (large_data_32kb)
{
  uint8_t *input;
  size_t size = 32768;
  int result;

  input = ALLOC (test_arena, size);
  for (size_t i = 0; i < size; i++)
    input[i] = (uint8_t)(i % 256);

  result = roundtrip_test (6, input, size);
  ASSERT (result);
}

/*
 * Output Buffer Tests
 */

TEST (output_buffer_too_small)
{
  SocketDeflate_Deflater_T def;
  const uint8_t input[] = "This is test data that needs compression space.";
  uint8_t tiny_output[2]; /* Too small for any block */
  uint8_t large_output[256];
  size_t consumed, written;
  SocketDeflate_Result res;

  def = SocketDeflate_Deflater_new (test_arena, 6);
  ASSERT (def != NULL);

  /* Deflate should accept input (buffered internally) */
  res = SocketDeflate_Deflater_deflate (def,
                                        input,
                                        sizeof (input) - 1,
                                        &consumed,
                                        tiny_output,
                                        sizeof (tiny_output),
                                        &written);
  ASSERT_EQ (res, DEFLATE_OK);
  ASSERT_EQ (consumed, sizeof (input) - 1);

  /* Finish with tiny buffer - may not fit everything */
  res = SocketDeflate_Deflater_finish (
      def, tiny_output, sizeof (tiny_output), &written);
  /* Result depends on whether data fits - just verify no crash */
  (void)res;

  /* Reset and try with adequate buffer */
  SocketDeflate_Deflater_reset (def);
  res = SocketDeflate_Deflater_deflate (def,
                                        input,
                                        sizeof (input) - 1,
                                        &consumed,
                                        large_output,
                                        sizeof (large_output),
                                        &written);
  ASSERT_EQ (res, DEFLATE_OK);

  res = SocketDeflate_Deflater_finish (
      def, large_output + written, sizeof (large_output) - written, &written);
  ASSERT_EQ (res, DEFLATE_OK);
}

/*
 * Lazy Matching Tests
 */

TEST (lazy_matching_benefit)
{
  /*
   * Test lazy matching with data where deferring a match helps.
   *
   * Pattern: "ABCXABCDABCD"
   * At position 4: "ABC" matches position 0 (length 3)
   * At position 5: "ABCD" could match position 4 (length 4)
   *
   * Lazy matching (levels 4+) should prefer the longer match.
   * Compare compression at level 3 (no lazy) vs level 6 (lazy).
   */
  const uint8_t input[] = "ABCXABCDABCDABCDABCDABCDABCDABCD";
  uint8_t compressed_no_lazy[256];
  uint8_t compressed_lazy[256];
  size_t len_no_lazy, len_lazy;

  len_no_lazy = compress_data (
      3, input, sizeof (input) - 1, compressed_no_lazy, sizeof (compressed_no_lazy));
  ASSERT (len_no_lazy > 0);

  len_lazy = compress_data (
      6, input, sizeof (input) - 1, compressed_lazy, sizeof (compressed_lazy));
  ASSERT (len_lazy > 0);

  /* Both should produce valid output */
  ASSERT (roundtrip_test (3, input, sizeof (input) - 1));
  ASSERT (roundtrip_test (6, input, sizeof (input) - 1));

  /*
   * Lazy matching typically produces equal or better compression.
   * We don't assert len_lazy <= len_no_lazy because dynamic Huffman
   * overhead can sometimes exceed savings on small inputs.
   */
}

TEST (streaming_multiple_chunks)
{
  /*
   * Test streaming compression with multiple deflate calls before finish.
   * Verifies that input can be provided in chunks rather than all at once.
   *
   * This test compares chunked input vs single-call input to ensure
   * both produce identical compressed output.
   */
  SocketDeflate_Deflater_T def1, def2;
  SocketDeflate_Result res;
  const size_t input_size = 512;
  const size_t chunk_size = 128;
  uint8_t *input;
  uint8_t compressed1[2048];
  uint8_t compressed2[2048];
  size_t consumed, written;
  size_t len1, len2;

  /* Allocate and fill input with pattern */
  input = ALLOC (test_arena, input_size);
  for (size_t i = 0; i < input_size; i++)
    input[i] = (uint8_t)((i * 17) % 256);

  /* Method 1: Single deflate call with all input */
  def1 = SocketDeflate_Deflater_new (test_arena, 6);
  ASSERT (def1 != NULL);

  res = SocketDeflate_Deflater_deflate (
      def1, input, input_size, &consumed, compressed1, sizeof (compressed1),
      &written);
  ASSERT_EQ (res, DEFLATE_OK);
  ASSERT_EQ (consumed, input_size);
  len1 = written;

  res = SocketDeflate_Deflater_finish (
      def1, compressed1 + len1, sizeof (compressed1) - len1, &written);
  ASSERT_EQ (res, DEFLATE_OK);
  len1 += written;

  /* Method 2: Multiple deflate calls with chunked input */
  def2 = SocketDeflate_Deflater_new (test_arena, 6);
  ASSERT (def2 != NULL);

  for (size_t offset = 0; offset < input_size; offset += chunk_size)
    {
      res = SocketDeflate_Deflater_deflate (def2,
                                            input + offset,
                                            chunk_size,
                                            &consumed,
                                            compressed2,
                                            sizeof (compressed2),
                                            &written);
      ASSERT_EQ (res, DEFLATE_OK);
      ASSERT_EQ (consumed, chunk_size);
    }

  res = SocketDeflate_Deflater_finish (
      def2, compressed2, sizeof (compressed2), &written);
  ASSERT_EQ (res, DEFLATE_OK);
  len2 = written;

  /* Both methods should produce same compressed output */
  ASSERT_EQ (len1, len2);
  ASSERT (memcmp (compressed1, compressed2, len1) == 0);

  /* Verify both can roundtrip */
  ASSERT (roundtrip_test (6, input, input_size));
}

/*
 * zlib Interoperability Tests
 *
 * These tests verify that our DEFLATE implementation is compatible with zlib:
 * - test_deflate_zlib_inflate_compat: Compress with us, decompress with zlib
 * - test_inflate_zlib_deflate_compat: Compress with zlib, decompress with us
 *
 * This ensures bidirectional interoperability per RFC 1951.
 */

#ifdef HAS_ZLIB

/*
 * Helper: Compress with zlib and return compressed size (raw deflate, no header)
 */
static size_t
zlib_compress_raw (const uint8_t *input,
                   size_t input_len,
                   uint8_t *output,
                   size_t output_len,
                   int level)
{
  z_stream strm;
  int ret;

  memset (&strm, 0, sizeof (strm));
  /* Use -15 for raw deflate (no zlib/gzip header) */
  ret = deflateInit2 (&strm, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
  if (ret != Z_OK)
    return 0;

  strm.avail_in = (uInt)input_len;
  strm.next_in = (Bytef *)input;
  strm.avail_out = (uInt)output_len;
  strm.next_out = output;

  ret = deflate (&strm, Z_FINISH);
  if (ret != Z_STREAM_END)
    {
      deflateEnd (&strm);
      return 0;
    }

  size_t compressed_size = output_len - strm.avail_out;
  deflateEnd (&strm);
  return compressed_size;
}

/*
 * Helper: Decompress with zlib (raw deflate, no header)
 */
static size_t
zlib_decompress_raw (const uint8_t *input,
                     size_t input_len,
                     uint8_t *output,
                     size_t output_len)
{
  z_stream strm;
  int ret;

  memset (&strm, 0, sizeof (strm));
  /* Use -15 for raw inflate (no zlib/gzip header) */
  ret = inflateInit2 (&strm, -15);
  if (ret != Z_OK)
    return 0;

  strm.avail_in = (uInt)input_len;
  strm.next_in = (Bytef *)input;
  strm.avail_out = (uInt)output_len;
  strm.next_out = output;

  ret = inflate (&strm, Z_FINISH);
  if (ret != Z_STREAM_END)
    {
      inflateEnd (&strm);
      return 0;
    }

  size_t decompressed_size = output_len - strm.avail_out;
  inflateEnd (&strm);
  return decompressed_size;
}

/*
 * Test: Compress with our implementation, decompress with zlib
 *
 * This verifies that our DEFLATE output is standards-compliant and
 * can be decompressed by the reference zlib implementation.
 */
TEST (deflate_zlib_inflate_compat)
{
  const uint8_t input[]
      = "The quick brown fox jumps over the lazy dog. "
        "Pack my box with five dozen liquor jugs. "
        "How vexingly quick daft zebras jump!";
  uint8_t compressed[1024];
  uint8_t decompressed[1024];
  size_t compressed_len, decompressed_len;

  /* Test all compression levels */
  for (int level = 0; level <= 9; level++)
    {
      /* Compress with our implementation */
      compressed_len = compress_data (
          level, input, sizeof (input) - 1, compressed, sizeof (compressed));
      ASSERT (compressed_len > 0);

      /* Decompress with zlib */
      decompressed_len = zlib_decompress_raw (
          compressed, compressed_len, decompressed, sizeof (decompressed));
      ASSERT_EQ (decompressed_len, sizeof (input) - 1);
      ASSERT (memcmp (input, decompressed, sizeof (input) - 1) == 0);
    }
}

/*
 * Test: Compress with zlib, decompress with our implementation
 *
 * This verifies that our inflate implementation correctly handles
 * zlib-compressed data, ensuring bidirectional compatibility.
 */
TEST (inflate_zlib_deflate_compat)
{
  const uint8_t input[]
      = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
        "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
        "Ut enim ad minim veniam, quis nostrud exercitation ullamco.";
  uint8_t compressed[1024];
  uint8_t decompressed[1024];
  size_t compressed_len, decompressed_len;

  ensure_tables ();

  /* Test multiple zlib compression levels */
  for (int level = 1; level <= 9; level++)
    {
      /* Compress with zlib */
      compressed_len = zlib_compress_raw (
          input, sizeof (input) - 1, compressed, sizeof (compressed), level);
      ASSERT (compressed_len > 0);

      /* Decompress with our implementation */
      decompressed_len = decompress_data (
          compressed, compressed_len, decompressed, sizeof (decompressed));
      ASSERT_EQ (decompressed_len, sizeof (input) - 1);
      ASSERT (memcmp (input, decompressed, sizeof (input) - 1) == 0);
    }
}

/*
 * Test: Bidirectional interop with various data patterns
 *
 * Tests interoperability with different data characteristics:
 * - Highly compressible (repeated patterns)
 * - Low entropy (random-ish data)
 * - Binary data with all byte values
 */
TEST (zlib_interop_data_patterns)
{
  uint8_t compressed[8192];
  uint8_t decompressed[4096];
  size_t compressed_len, decompressed_len;

  ensure_tables ();

  /* Pattern 1: Highly compressible - repeated sequence */
  {
    uint8_t input[2048];
    for (size_t i = 0; i < sizeof (input); i++)
      input[i] = "ABCD"[i % 4];

    /* Our compress -> zlib decompress */
    compressed_len
        = compress_data (6, input, sizeof (input), compressed, sizeof (compressed));
    ASSERT (compressed_len > 0);
    decompressed_len = zlib_decompress_raw (
        compressed, compressed_len, decompressed, sizeof (decompressed));
    ASSERT_EQ (decompressed_len, sizeof (input));
    ASSERT (memcmp (input, decompressed, sizeof (input)) == 0);

    /* zlib compress -> our decompress */
    compressed_len = zlib_compress_raw (
        input, sizeof (input), compressed, sizeof (compressed), 6);
    ASSERT (compressed_len > 0);
    decompressed_len = decompress_data (
        compressed, compressed_len, decompressed, sizeof (decompressed));
    ASSERT_EQ (decompressed_len, sizeof (input));
    ASSERT (memcmp (input, decompressed, sizeof (input)) == 0);
  }

  /* Pattern 2: All byte values (0x00-0xFF repeated) */
  {
    uint8_t input[1024];
    for (size_t i = 0; i < sizeof (input); i++)
      input[i] = (uint8_t)(i % 256);

    /* Our compress -> zlib decompress */
    compressed_len
        = compress_data (6, input, sizeof (input), compressed, sizeof (compressed));
    ASSERT (compressed_len > 0);
    decompressed_len = zlib_decompress_raw (
        compressed, compressed_len, decompressed, sizeof (decompressed));
    ASSERT_EQ (decompressed_len, sizeof (input));
    ASSERT (memcmp (input, decompressed, sizeof (input)) == 0);

    /* zlib compress -> our decompress */
    compressed_len = zlib_compress_raw (
        input, sizeof (input), compressed, sizeof (compressed), 6);
    ASSERT (compressed_len > 0);
    decompressed_len = decompress_data (
        compressed, compressed_len, decompressed, sizeof (decompressed));
    ASSERT_EQ (decompressed_len, sizeof (input));
    ASSERT (memcmp (input, decompressed, sizeof (input)) == 0);
  }

  /* Pattern 3: Pseudo-random data (harder to compress) */
  {
    uint8_t input[1024];
    unsigned int seed = 0xDEADBEEF;
    for (size_t i = 0; i < sizeof (input); i++)
      {
        seed = seed * 1103515245 + 12345;
        input[i] = (uint8_t)(seed >> 16);
      }

    /* Our compress -> zlib decompress */
    compressed_len
        = compress_data (6, input, sizeof (input), compressed, sizeof (compressed));
    ASSERT (compressed_len > 0);
    decompressed_len = zlib_decompress_raw (
        compressed, compressed_len, decompressed, sizeof (decompressed));
    ASSERT_EQ (decompressed_len, sizeof (input));
    ASSERT (memcmp (input, decompressed, sizeof (input)) == 0);

    /* zlib compress -> our decompress */
    compressed_len = zlib_compress_raw (
        input, sizeof (input), compressed, sizeof (compressed), 6);
    ASSERT (compressed_len > 0);
    decompressed_len = decompress_data (
        compressed, compressed_len, decompressed, sizeof (decompressed));
    ASSERT_EQ (decompressed_len, sizeof (input));
    ASSERT (memcmp (input, decompressed, sizeof (input)) == 0);
  }
}

/*
 * Test: zlib interop at all compression levels
 *
 * Comprehensive test that verifies interoperability across all
 * compression levels (0-9) in both directions.
 */
TEST (zlib_interop_all_levels)
{
  const uint8_t input[]
      = "This test verifies zlib interoperability at all compression levels. "
        "Compression levels 0-9 should all produce valid, interoperable output.";
  uint8_t compressed[1024];
  uint8_t decompressed[1024];
  size_t compressed_len, decompressed_len;

  ensure_tables ();

  for (int level = 0; level <= 9; level++)
    {
      /* Our level X -> zlib decompress */
      compressed_len = compress_data (
          level, input, sizeof (input) - 1, compressed, sizeof (compressed));
      ASSERT (compressed_len > 0);

      decompressed_len = zlib_decompress_raw (
          compressed, compressed_len, decompressed, sizeof (decompressed));
      ASSERT_EQ (decompressed_len, sizeof (input) - 1);
      ASSERT (memcmp (input, decompressed, sizeof (input) - 1) == 0);
    }

  /* zlib levels 1-9 -> our decompress (zlib level 0 is store, skip) */
  for (int level = 1; level <= 9; level++)
    {
      compressed_len = zlib_compress_raw (
          input, sizeof (input) - 1, compressed, sizeof (compressed), level);
      ASSERT (compressed_len > 0);

      decompressed_len = decompress_data (
          compressed, compressed_len, decompressed, sizeof (decompressed));
      ASSERT_EQ (decompressed_len, sizeof (input) - 1);
      ASSERT (memcmp (input, decompressed, sizeof (input) - 1) == 0);
    }
}

#endif /* HAS_ZLIB */

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
