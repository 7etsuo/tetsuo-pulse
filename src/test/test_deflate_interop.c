/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 *
 * Issue #3422: zlib/gzip interoperability verification suite
 */

/**
 * test_deflate_interop.c - Extended zlib/gzip interoperability tests
 *
 * Extends the basic zlib interoperability tests in test_deflate_deflater.c
 * with additional coverage for:
 * - gzip format parsing and verification
 * - CRC-32 calculation verification
 * - Known test vectors from RFC 1951/1952
 * - Large data tests (up to 64KB)
 * - Edge cases around block boundaries
 *
 * Basic bidirectional deflate/inflate tests are in test_deflate_deflater.c.
 *
 * @see RFC 1951 - DEFLATE Compressed Data Format Specification
 * @see RFC 1952 - GZIP file format specification
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#include "core/Arena.h"
#include "deflate/SocketDeflate.h"
#include "test/Test.h"

/*
 * Test infrastructure
 */
static Arena_T test_arena;
static int tables_initialized = 0;

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
 * Helper: Generate repeated pattern data
 */
static void
generate_repeated_data (uint8_t *buf, size_t len, const char *pattern)
{
  size_t pat_len = strlen (pattern);
  for (size_t i = 0; i < len; i++)
    {
      buf[i] = (uint8_t)pattern[i % pat_len];
    }
}

/*
 * Helper: Generate sequential data (0, 1, 2, ..., 255, 0, 1, ...)
 */
static void
generate_sequential_data (uint8_t *buf, size_t len)
{
  for (size_t i = 0; i < len; i++)
    {
      buf[i] = (uint8_t)(i & 0xFF);
    }
}

/*
 * Helper: Generate pseudo-random data (deterministic for reproducibility)
 */
static void
generate_random_data (uint8_t *buf, size_t len, uint32_t seed)
{
  uint32_t state = seed;
  for (size_t i = 0; i < len; i++)
    {
      /* Simple LCG: state = state * 1103515245 + 12345 */
      state = state * 1103515245U + 12345U;
      buf[i] = (uint8_t)((state >> 16) & 0xFF);
    }
}

/*
 * Helper: Decompress data with our native inflater
 *
 * Note: The output buffer should be slightly larger than expected output
 * to allow the inflater to process the end-of-block marker without
 * returning OUTPUT_FULL.
 */
static int
native_decompress (const uint8_t *input,
                   size_t input_len,
                   uint8_t *output,
                   size_t *output_len)
{
  SocketDeflate_Inflater_T inf;
  SocketDeflate_Result result;
  size_t consumed, written;
  size_t total_written = 0;
  size_t total_consumed = 0;
  int iterations = 0;
  const int max_iterations = 1000; /* Prevent infinite loops */

  ensure_tables ();

  inf = SocketDeflate_Inflater_new (test_arena, 0);
  if (!inf)
    return -1;

  /* Decompress in a loop in case of partial results */
  while (!SocketDeflate_Inflater_finished (inf) && iterations < max_iterations)
    {
      size_t out_space
          = (*output_len > total_written) ? (*output_len - total_written) : 0;

      result = SocketDeflate_Inflater_inflate (inf,
                                               input + total_consumed,
                                               input_len - total_consumed,
                                               &consumed,
                                               output + total_written,
                                               out_space,
                                               &written);

      total_consumed += consumed;
      total_written += written;
      iterations++;

      if (result == DEFLATE_OK)
        break;
      if (result == DEFLATE_OUTPUT_FULL)
        {
          /* Output full but not finished - need more output space */
          /* If we've written what was expected, try one more pass with 0 space
           */
          /* to let the inflater process remaining bits */
          if (total_written >= *output_len && consumed > 0)
            continue;
          /* Can't make progress - output buffer too small */
          break;
        }
      if (result != DEFLATE_INCOMPLETE)
        return -1;
      /* INCOMPLETE: need more input data */
      if (total_consumed >= input_len)
        return -1; /* No more input available */
    }

  if (!SocketDeflate_Inflater_finished (inf))
    return -1;

  *output_len = total_written;
  return 0;
}

/*
 * Helper: Compress data with system zlib (raw deflate, no wrapper)
 */
static int
zlib_compress_raw (const uint8_t *input,
                   size_t input_len,
                   uint8_t *output,
                   size_t *output_len,
                   int level)
{
  z_stream strm;
  int ret;

  memset (&strm, 0, sizeof (strm));

  /* windowBits = -15 for raw deflate (no zlib/gzip header) */
  ret = deflateInit2 (&strm, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
  if (ret != Z_OK)
    return -1;

  strm.next_in = (Bytef *)input;
  strm.avail_in = (uInt)input_len;
  strm.next_out = output;
  strm.avail_out = (uInt)*output_len;

  ret = deflate (&strm, Z_FINISH);
  if (ret != Z_STREAM_END)
    {
      deflateEnd (&strm);
      return -1;
    }

  *output_len = strm.total_out;
  deflateEnd (&strm);
  return 0;
}

/*
 * Helper: Decompress data with system zlib (raw deflate, no wrapper)
 */
static int
zlib_decompress_raw (const uint8_t *input,
                     size_t input_len,
                     uint8_t *output,
                     size_t *output_len)
{
  z_stream strm;
  int ret;

  memset (&strm, 0, sizeof (strm));

  /* windowBits = -15 for raw deflate (no zlib/gzip header) */
  ret = inflateInit2 (&strm, -15);
  if (ret != Z_OK)
    return -1;

  strm.next_in = (Bytef *)input;
  strm.avail_in = (uInt)input_len;
  strm.next_out = output;
  strm.avail_out = (uInt)*output_len;

  ret = inflate (&strm, Z_FINISH);
  if (ret != Z_STREAM_END)
    {
      inflateEnd (&strm);
      return -1;
    }

  *output_len = strm.total_out;
  inflateEnd (&strm);
  return 0;
}

/*
 * Helper: Compress data with system zlib (gzip format)
 */
static int
zlib_compress_gzip (const uint8_t *input,
                    size_t input_len,
                    uint8_t *output,
                    size_t *output_len,
                    int level)
{
  z_stream strm;
  int ret;

  memset (&strm, 0, sizeof (strm));

  /* windowBits = 15 + 16 for gzip format */
  ret = deflateInit2 (&strm, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
  if (ret != Z_OK)
    return -1;

  strm.next_in = (Bytef *)input;
  strm.avail_in = (uInt)input_len;
  strm.next_out = output;
  strm.avail_out = (uInt)*output_len;

  ret = deflate (&strm, Z_FINISH);
  if (ret != Z_STREAM_END)
    {
      deflateEnd (&strm);
      return -1;
    }

  *output_len = strm.total_out;
  deflateEnd (&strm);
  return 0;
}

/*
 * Helper: Decompress gzip data with system zlib
 */
static int
zlib_decompress_gzip (const uint8_t *input,
                      size_t input_len,
                      uint8_t *output,
                      size_t *output_len)
{
  z_stream strm;
  int ret;

  memset (&strm, 0, sizeof (strm));

  /* windowBits = 15 + 16 for gzip format */
  ret = inflateInit2 (&strm, 15 + 16);
  if (ret != Z_OK)
    return -1;

  strm.next_in = (Bytef *)input;
  strm.avail_in = (uInt)input_len;
  strm.next_out = output;
  strm.avail_out = (uInt)*output_len;

  ret = inflate (&strm, Z_FINISH);
  if (ret != Z_STREAM_END)
    {
      inflateEnd (&strm);
      return -1;
    }

  *output_len = strm.total_out;
  inflateEnd (&strm);
  return 0;
}

TEST (interop_crc32_matches_zlib)
{
  /* Verify our CRC32 matches zlib's implementation */
  const char *test_strings[]
      = { "",
          "a",
          "abc",
          "message digest",
          "abcdefghijklmnopqrstuvwxyz",
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
          "The quick brown fox jumps over the lazy dog",
          NULL };

  for (int i = 0; test_strings[i] != NULL; i++)
    {
      const char *str = test_strings[i];
      size_t len = strlen (str);

      uint32_t native_crc = SocketDeflate_crc32 (0, (const uint8_t *)str, len);
      uLong zlib_crc = crc32 (0L, (const Bytef *)str, (uInt)len);

      ASSERT_EQ (native_crc, (uint32_t)zlib_crc);
    }
}

TEST (interop_crc32_ieee_test_vector)
{
  /* IEEE 802.3 standard test vector: CRC32("123456789") = 0xCBF43926 */
  const char *data = "123456789";
  uint32_t expected = 0xCBF43926;

  uint32_t native_crc = SocketDeflate_crc32 (0, (const uint8_t *)data, 9);
  uLong zlib_crc = crc32 (0L, (const Bytef *)data, 9);

  ASSERT_EQ (native_crc, expected);
  ASSERT_EQ ((uint32_t)zlib_crc, expected);
}

TEST (interop_crc32_incremental)
{
  uint8_t data[1024];
  generate_random_data (data, sizeof (data), 0xCAFEBABE);

  /* Compute CRC32 in one go */
  uint32_t native_full = SocketDeflate_crc32 (0, data, sizeof (data));
  uLong zlib_full = crc32 (0L, data, (uInt)sizeof (data));

  /* Compute CRC32 incrementally with various chunk sizes */
  uint32_t native_inc = 0;
  uLong zlib_inc = crc32 (0L, Z_NULL, 0);

  size_t offset = 0;
  size_t chunks[] = { 1, 17, 64, 127, 256, 559 }; /* Varying chunk sizes */
  int chunk_idx = 0;

  while (offset < sizeof (data))
    {
      size_t chunk = chunks[chunk_idx % 6];
      if (offset + chunk > sizeof (data))
        chunk = sizeof (data) - offset;

      native_inc = SocketDeflate_crc32 (native_inc, data + offset, chunk);
      zlib_inc = crc32 (zlib_inc, data + offset, (uInt)chunk);
      offset += chunk;
      chunk_idx++;
    }

  ASSERT_EQ (native_full, native_inc);
  ASSERT_EQ ((uint32_t)zlib_full, (uint32_t)zlib_inc);
  ASSERT_EQ (native_full, (uint32_t)zlib_full);
}

TEST (interop_crc32_binary_data)
{
  /* Test with all byte values */
  uint8_t data[256];
  for (int i = 0; i < 256; i++)
    data[i] = (uint8_t)i;

  uint32_t native_crc = SocketDeflate_crc32 (0, data, sizeof (data));
  uLong zlib_crc = crc32 (0L, data, (uInt)sizeof (data));

  ASSERT_EQ (native_crc, (uint32_t)zlib_crc);
}

TEST (interop_gzip_header_parse)
{
  const char *data = "Test data for gzip header parsing";
  size_t data_len = strlen (data);
  uint8_t gzip_data[512];
  size_t gzip_len = sizeof (gzip_data);
  int ret;

  /* Compress with zlib in gzip format */
  ret = zlib_compress_gzip (
      (const uint8_t *)data, data_len, gzip_data, &gzip_len, 6);
  ASSERT_EQ (ret, 0);

  /* Parse the gzip header with our native parser */
  SocketDeflate_GzipHeader header;
  SocketDeflate_Result result
      = SocketDeflate_gzip_parse_header (gzip_data, gzip_len, &header);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Verify header fields */
  ASSERT_EQ (header.method, GZIP_METHOD_DEFLATE);
  ASSERT (header.header_size >= GZIP_HEADER_MIN_SIZE);
  ASSERT (header.header_size < gzip_len);
}

TEST (interop_gzip_native_inflate_zlib_data)
{
  const char *data
      = "Hello, gzip world! This tests our inflate with zlib gzip.";
  size_t data_len = strlen (data);
  uint8_t gzip_data[512];
  size_t gzip_len = sizeof (gzip_data);
  int ret;

  /* Compress with zlib in gzip format */
  ret = zlib_compress_gzip (
      (const uint8_t *)data, data_len, gzip_data, &gzip_len, 6);
  ASSERT_EQ (ret, 0);

  /* Parse the gzip header */
  SocketDeflate_GzipHeader header;
  SocketDeflate_Result result
      = SocketDeflate_gzip_parse_header (gzip_data, gzip_len, &header);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Decompress the DEFLATE data after the header */
  uint8_t decompressed[256];
  size_t decomp_len = sizeof (decompressed);
  const uint8_t *deflate_data = gzip_data + header.header_size;
  size_t deflate_len = gzip_len - header.header_size - GZIP_TRAILER_SIZE;

  ret = native_decompress (
      deflate_data, deflate_len, decompressed, &decomp_len);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (decomp_len, data_len);
  ASSERT (memcmp (decompressed, data, data_len) == 0);

  /* Verify CRC32 and size in trailer */
  uint32_t computed_crc = SocketDeflate_crc32 (0, decompressed, decomp_len);
  const uint8_t *trailer = gzip_data + gzip_len - GZIP_TRAILER_SIZE;
  result = SocketDeflate_gzip_verify_trailer (
      trailer, computed_crc, (uint32_t)decomp_len);
  ASSERT_EQ (result, DEFLATE_OK);
}

TEST (interop_gzip_trailer_verification)
{
  uint8_t data[1024];
  uint8_t gzip_data[2048];
  /* Extra space for inflater to process end-of-block marker */
  uint8_t decompressed[1024 + 256];
  size_t gzip_len = sizeof (gzip_data);
  int ret;

  generate_repeated_data (data, sizeof (data), "GZIP_TRAILER_TEST");

  /* Compress with zlib gzip */
  ret = zlib_compress_gzip (data, sizeof (data), gzip_data, &gzip_len, 6);
  ASSERT_EQ (ret, 0);

  /* Parse header */
  SocketDeflate_GzipHeader header;
  SocketDeflate_Result result
      = SocketDeflate_gzip_parse_header (gzip_data, gzip_len, &header);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Decompress */
  const uint8_t *deflate_data = gzip_data + header.header_size;
  size_t deflate_len = gzip_len - header.header_size - GZIP_TRAILER_SIZE;
  size_t decomp_len = sizeof (decompressed);

  ret = native_decompress (
      deflate_data, deflate_len, decompressed, &decomp_len);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (decomp_len, sizeof (data));

  /* Verify trailer */
  uint32_t computed_crc = SocketDeflate_crc32 (0, decompressed, decomp_len);
  const uint8_t *trailer = gzip_data + gzip_len - GZIP_TRAILER_SIZE;
  result = SocketDeflate_gzip_verify_trailer (
      trailer, computed_crc, (uint32_t)decomp_len);
  ASSERT_EQ (result, DEFLATE_OK);
}

TEST (interop_gzip_os_codes)
{
  /* Verify OS code validation */
  ASSERT_EQ (SocketDeflate_gzip_is_valid_os (GZIP_OS_UNIX), 1);
  ASSERT_EQ (SocketDeflate_gzip_is_valid_os (GZIP_OS_UNKNOWN), 1);
  ASSERT_EQ (SocketDeflate_gzip_is_valid_os (GZIP_OS_FAT), 1);
  ASSERT_EQ (SocketDeflate_gzip_is_valid_os (14), 0);  /* Reserved */
  ASSERT_EQ (SocketDeflate_gzip_is_valid_os (254), 0); /* Reserved */

  /* Verify OS strings exist */
  ASSERT (SocketDeflate_gzip_os_string (GZIP_OS_UNIX) != NULL);
  ASSERT (SocketDeflate_gzip_os_string (GZIP_OS_UNKNOWN) != NULL);
}

TEST (interop_vector_empty_stored_block)
{
  /* Empty stored block: BFINAL=1, BTYPE=00, LEN=0, NLEN=0xFFFF */
  uint8_t empty_stored[] = { 0x01, 0x00, 0x00, 0xFF, 0xFF };
  uint8_t output[64];
  size_t output_len;
  int ret;

  /* Decompress with zlib */
  output_len = sizeof (output);
  ret = zlib_decompress_raw (
      empty_stored, sizeof (empty_stored), output, &output_len);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (output_len, 0);

  /* Decompress with native */
  output_len = sizeof (output);
  ret = native_decompress (
      empty_stored, sizeof (empty_stored), output, &output_len);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (output_len, 0);
}

TEST (interop_vector_single_byte)
{
  /* Test single byte roundtrip */
  const uint8_t data[] = { 0x42 }; /* Single 'B' */
  uint8_t compressed[64];
  uint8_t decompressed[64];
  size_t comp_len, decomp_len;
  int ret;

  /* zlib → native */
  comp_len = sizeof (compressed);
  ret = zlib_compress_raw (data, 1, compressed, &comp_len, 6);
  ASSERT_EQ (ret, 0);

  decomp_len = sizeof (decompressed);
  ret = native_decompress (compressed, comp_len, decompressed, &decomp_len);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (decomp_len, 1);
  ASSERT_EQ (decompressed[0], 0x42);
}

TEST (interop_vector_all_byte_values)
{
  /* Test with all 256 byte values */
  uint8_t data[256];
  for (int i = 0; i < 256; i++)
    data[i] = (uint8_t)i;

  uint8_t compressed[512];
  uint8_t decompressed[256];
  size_t comp_len, decomp_len;
  int ret;

  /* zlib → native */
  comp_len = sizeof (compressed);
  ret = zlib_compress_raw (data, sizeof (data), compressed, &comp_len, 6);
  ASSERT_EQ (ret, 0);

  decomp_len = sizeof (decompressed);
  ret = native_decompress (compressed, comp_len, decompressed, &decomp_len);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (decomp_len, sizeof (data));
  ASSERT (memcmp (decompressed, data, sizeof (data)) == 0);
}

TEST (interop_vector_repeated_alphabet)
{
  /* Repeated alphabet - highly compressible */
  char data[260];
  for (int i = 0; i < 10; i++)
    memcpy (data + i * 26, "abcdefghijklmnopqrstuvwxyz", 26);
  size_t data_len = 260;

  uint8_t compressed[512];
  uint8_t decompressed[512];
  size_t comp_len, decomp_len;
  int ret;

  /* zlib → native */
  comp_len = sizeof (compressed);
  ret = zlib_compress_raw (
      (const uint8_t *)data, data_len, compressed, &comp_len, 6);
  ASSERT_EQ (ret, 0);

  decomp_len = sizeof (decompressed);
  ret = native_decompress (compressed, comp_len, decompressed, &decomp_len);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (decomp_len, data_len);
  ASSERT (memcmp (decompressed, data, data_len) == 0);
}

TEST (interop_large_16kb_repeated)
{
  size_t data_size = 16 * 1024;
  uint8_t *data = malloc (data_size);
  uint8_t *compressed = malloc (data_size);
  /* Extra space for inflater to process end-of-block marker */
  uint8_t *decompressed = malloc (data_size + 256);
  ASSERT (data && compressed && decompressed);

  generate_repeated_data (data, data_size, "LargeTest_");

  size_t comp_len = data_size;
  int ret = zlib_compress_raw (data, data_size, compressed, &comp_len, 6);
  ASSERT_EQ (ret, 0);

  size_t decomp_len = data_size + 256;
  ret = native_decompress (compressed, comp_len, decompressed, &decomp_len);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (decomp_len, data_size);
  ASSERT (memcmp (decompressed, data, data_size) == 0);

  free (data);
  free (compressed);
  free (decompressed);
}

TEST (interop_large_32kb_sequential)
{
  size_t data_size = 32 * 1024;
  uint8_t *data = malloc (data_size);
  uint8_t *compressed = malloc (data_size + 1024);
  /* Extra space for inflater to process end-of-block marker */
  uint8_t *decompressed = malloc (data_size + 256);
  ASSERT (data && compressed && decompressed);

  generate_sequential_data (data, data_size);

  size_t comp_len = data_size + 1024;
  int ret = zlib_compress_raw (data, data_size, compressed, &comp_len, 6);
  ASSERT_EQ (ret, 0);

  size_t decomp_len = data_size + 256;
  ret = native_decompress (compressed, comp_len, decompressed, &decomp_len);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (decomp_len, data_size);
  ASSERT (memcmp (decompressed, data, data_size) == 0);

  free (data);
  free (compressed);
  free (decompressed);
}

TEST (interop_large_64kb_random)
{
  size_t data_size = 64 * 1024;
  uint8_t *data = malloc (data_size);
  /* Random data doesn't compress well */
  uint8_t *compressed = malloc (data_size + data_size / 10 + 1024);
  uint8_t *decompressed = malloc (data_size);
  ASSERT (data && compressed && decompressed);

  generate_random_data (data, data_size, 0x12345678);

  size_t comp_len = data_size + data_size / 10 + 1024;
  int ret = zlib_compress_raw (data, data_size, compressed, &comp_len, 6);
  ASSERT_EQ (ret, 0);

  size_t decomp_len = data_size;
  ret = native_decompress (compressed, comp_len, decompressed, &decomp_len);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (decomp_len, data_size);
  ASSERT (memcmp (decompressed, data, data_size) == 0);

  free (data);
  free (compressed);
  free (decompressed);
}

TEST (interop_zlib_levels_to_native_inflate)
{
  const char *data = "Test string for all compression levels verification.";
  size_t data_len = strlen (data);
  uint8_t compressed[256];
  uint8_t decompressed[256];

  /* Test all zlib compression levels 0-9 */
  for (int level = 0; level <= 9; level++)
    {
      size_t comp_len = sizeof (compressed);
      int ret = zlib_compress_raw (
          (const uint8_t *)data, data_len, compressed, &comp_len, level);
      ASSERT_EQ (ret, 0);

      size_t decomp_len = sizeof (decompressed);
      ret = native_decompress (compressed, comp_len, decompressed, &decomp_len);
      ASSERT_EQ (ret, 0);
      ASSERT_EQ (decomp_len, data_len);
      ASSERT (memcmp (decompressed, data, data_len) == 0);
    }
}

TEST (interop_zlib_levels_various_patterns)
{
  uint8_t data[1024];
  uint8_t compressed[2048];
  /* Extra space for inflater to process end-of-block marker */
  uint8_t decompressed[1024 + 256];

  /* Test pattern 1: Highly compressible */
  generate_repeated_data (data, sizeof (data), "ABCD");
  for (int level = 1; level <= 9; level += 2)
    {
      size_t comp_len = sizeof (compressed);
      int ret = zlib_compress_raw (
          data, sizeof (data), compressed, &comp_len, level);
      ASSERT_EQ (ret, 0);

      size_t decomp_len = sizeof (decompressed);
      ret = native_decompress (compressed, comp_len, decompressed, &decomp_len);
      ASSERT_EQ (ret, 0);
      ASSERT_EQ (decomp_len, sizeof (data));
      ASSERT (memcmp (decompressed, data, sizeof (data)) == 0);
    }

  /* Test pattern 2: Random (low compression) */
  generate_random_data (data, sizeof (data), 0xDEADBEEF);
  for (int level = 1; level <= 9; level += 2)
    {
      size_t comp_len = sizeof (compressed);
      int ret = zlib_compress_raw (
          data, sizeof (data), compressed, &comp_len, level);
      ASSERT_EQ (ret, 0);

      size_t decomp_len = sizeof (decompressed);
      ret = native_decompress (compressed, comp_len, decompressed, &decomp_len);
      ASSERT_EQ (ret, 0);
      ASSERT_EQ (decomp_len, sizeof (data));
      ASSERT (memcmp (decompressed, data, sizeof (data)) == 0);
    }
}

TEST (interop_edge_tiny_sizes)
{
  uint8_t compressed[128];
  uint8_t decompressed[64];

  /* Test sizes 1-16 bytes */
  for (size_t size = 1; size <= 16; size++)
    {
      uint8_t data[16];
      generate_random_data (data, size, (uint32_t)size);

      size_t comp_len = sizeof (compressed);
      int ret = zlib_compress_raw (data, size, compressed, &comp_len, 6);
      ASSERT_EQ (ret, 0);

      size_t decomp_len = sizeof (decompressed);
      ret = native_decompress (compressed, comp_len, decompressed, &decomp_len);
      ASSERT_EQ (ret, 0);
      ASSERT_EQ (decomp_len, size);
      ASSERT (memcmp (decompressed, data, size) == 0);
    }
}

TEST (interop_edge_boundary_256)
{
  /* Test around 256 byte boundary */
  size_t sizes[] = { 254, 255, 256, 257, 258 };

  for (size_t i = 0; i < sizeof (sizes) / sizeof (sizes[0]); i++)
    {
      size_t size = sizes[i];
      uint8_t *data = malloc (size);
      uint8_t *compressed = malloc (size + 256);
      uint8_t *decompressed = malloc (size);
      ASSERT (data && compressed && decompressed);

      generate_sequential_data (data, size);

      size_t comp_len = size + 256;
      int ret = zlib_compress_raw (data, size, compressed, &comp_len, 6);
      ASSERT_EQ (ret, 0);

      size_t decomp_len = size;
      ret = native_decompress (compressed, comp_len, decompressed, &decomp_len);
      ASSERT_EQ (ret, 0);
      ASSERT_EQ (decomp_len, size);
      ASSERT (memcmp (decompressed, data, size) == 0);

      free (data);
      free (compressed);
      free (decompressed);
    }
}

TEST (interop_edge_all_zeros)
{
  /* 4KB of zeros - excellent compression */
  size_t data_size = 4096;
  uint8_t *data = calloc (1, data_size);
  uint8_t *compressed = malloc (256); /* Should compress very small */
  /* Extra space for inflater to process end-of-block marker */
  uint8_t *decompressed = malloc (data_size + 256);
  ASSERT (data && compressed && decompressed);

  size_t comp_len = 256;
  int ret = zlib_compress_raw (data, data_size, compressed, &comp_len, 6);
  ASSERT_EQ (ret, 0);
  ASSERT (comp_len < 100); /* Should be very small */

  size_t decomp_len = data_size + 256;
  ret = native_decompress (compressed, comp_len, decompressed, &decomp_len);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (decomp_len, data_size);
  ASSERT (memcmp (decompressed, data, data_size) == 0);

  free (data);
  free (compressed);
  free (decompressed);
}

TEST (interop_edge_all_ff)
{
  /* 4KB of 0xFF bytes */
  size_t data_size = 4096;
  uint8_t *data = malloc (data_size);
  uint8_t *compressed = malloc (256);
  /* Extra space for inflater to process end-of-block marker */
  uint8_t *decompressed = malloc (data_size + 256);
  ASSERT (data && compressed && decompressed);

  memset (data, 0xFF, data_size);

  size_t comp_len = 256;
  int ret = zlib_compress_raw (data, data_size, compressed, &comp_len, 6);
  ASSERT_EQ (ret, 0);

  size_t decomp_len = data_size + 256;
  ret = native_decompress (compressed, comp_len, decompressed, &decomp_len);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (decomp_len, data_size);
  ASSERT (memcmp (decompressed, data, data_size) == 0);

  free (data);
  free (compressed);
  free (decompressed);
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
