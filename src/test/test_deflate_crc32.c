/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_deflate_crc32.c - CRC-32 implementation unit tests
 *
 * Tests for the CRC-32 implementation including:
 * - IEEE 802.3 canonical test vector
 * - Empty data handling
 * - Single byte CRC
 * - Incremental computation
 * - Large data
 *
 * @see ISO 3309, IEEE 802.3 for CRC-32 specification
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "deflate/SocketDeflate.h"
#include "test/Test.h"

/*
 * IEEE 802.3 Canonical Test Vector
 *
 * The string "123456789" (without null terminator) should produce
 * CRC-32 = 0xCBF43926. This is THE canonical test for CRC-32.
 */
TEST (crc32_ieee_vector)
{
  const char *data = "123456789";
  uint32_t crc = SocketDeflate_crc32 (0, (const uint8_t *)data, 9);

  ASSERT_EQ (crc, 0xCBF43926U);
}

/*
 * Empty Data
 *
 * CRC of empty data should be 0.
 */
TEST (crc32_empty)
{
  uint32_t crc = SocketDeflate_crc32 (0, NULL, 0);
  ASSERT_EQ (crc, 0U);

  /* Also test with valid pointer but zero length */
  uint8_t dummy[1] = { 0xFF };
  crc = SocketDeflate_crc32 (0, dummy, 0);
  ASSERT_EQ (crc, 0U);
}

/*
 * Single Byte
 *
 * Test CRC of various single bytes.
 */
TEST (crc32_single_byte)
{
  uint8_t byte;
  uint32_t crc;

  /* CRC of 0x00 */
  byte = 0x00;
  crc = SocketDeflate_crc32 (0, &byte, 1);
  ASSERT_EQ (crc, 0xD202EF8DU);

  /* CRC of 0xFF */
  byte = 0xFF;
  crc = SocketDeflate_crc32 (0, &byte, 1);
  ASSERT_EQ (crc, 0xFF000000U);

  /* CRC of 'A' (0x41) */
  byte = 'A';
  crc = SocketDeflate_crc32 (0, &byte, 1);
  ASSERT_EQ (crc, 0xD3D99E8BU);
}

/*
 * Incremental Computation
 *
 * Computing CRC incrementally should produce same result as one-shot.
 */
TEST (crc32_incremental)
{
  const char *data = "123456789";
  uint32_t crc_oneshot;
  uint32_t crc_incremental;

  /* One-shot computation */
  crc_oneshot = SocketDeflate_crc32 (0, (const uint8_t *)data, 9);

  /* Incremental: compute in chunks */
  crc_incremental = 0;
  crc_incremental
      = SocketDeflate_crc32 (crc_incremental, (const uint8_t *)data, 3);
  crc_incremental
      = SocketDeflate_crc32 (crc_incremental, (const uint8_t *)data + 3, 3);
  crc_incremental
      = SocketDeflate_crc32 (crc_incremental, (const uint8_t *)data + 6, 3);

  ASSERT_EQ (crc_incremental, crc_oneshot);
}

/*
 * Incremental with Single Bytes
 *
 * Byte-by-byte computation should match one-shot.
 */
TEST (crc32_incremental_bytes)
{
  const char *data = "123456789";
  uint32_t crc_oneshot;
  uint32_t crc_bytewise;

  crc_oneshot = SocketDeflate_crc32 (0, (const uint8_t *)data, 9);

  crc_bytewise = 0;
  for (int i = 0; i < 9; i++)
    {
      crc_bytewise
          = SocketDeflate_crc32 (crc_bytewise, (const uint8_t *)data + i, 1);
    }

  ASSERT_EQ (crc_bytewise, crc_oneshot);
}

/*
 * All Byte Values
 *
 * Test CRC of all 256 byte values (0x00-0xFF).
 */
TEST (crc32_all_bytes)
{
  uint8_t data[256];
  uint32_t crc;

  /* Create array with all byte values */
  for (int i = 0; i < 256; i++)
    data[i] = (uint8_t)i;

  crc = SocketDeflate_crc32 (0, data, 256);

  /* Known CRC for bytes 0x00-0xFF */
  ASSERT_EQ (crc, 0x29058C73U);
}

/*
 * Large Data
 *
 * Test with 1MB of data to verify no overflow issues.
 */
TEST (crc32_large_data)
{
  uint8_t *data;
  size_t len = 1024 * 1024; /* 1MB */
  uint32_t crc;

  data = malloc (len);
  ASSERT (data != NULL);

  /* Fill with pattern */
  for (size_t i = 0; i < len; i++)
    data[i] = (uint8_t)(i & 0xFF);

  crc = SocketDeflate_crc32 (0, data, len);

  /* Verify CRC is non-zero (sanity check) */
  ASSERT (crc != 0);

  /* Verify incremental gives same result */
  uint32_t crc_inc = 0;
  size_t chunk_size = 64 * 1024; /* 64KB chunks */
  for (size_t offset = 0; offset < len; offset += chunk_size)
    {
      size_t chunk = (offset + chunk_size <= len) ? chunk_size : len - offset;
      crc_inc = SocketDeflate_crc32 (crc_inc, data + offset, chunk);
    }
  ASSERT_EQ (crc_inc, crc);

  free (data);
}

/*
 * Known Vectors from zlib/gzip
 *
 * Additional test vectors verified against system zlib.
 */
TEST (crc32_known_vectors)
{
  uint32_t crc;

  /* "Hello World" */
  crc = SocketDeflate_crc32 (0, (const uint8_t *)"Hello World", 11);
  ASSERT_EQ (crc, 0x4A17B156U);

  /* "The quick brown fox jumps over the lazy dog" */
  const char *fox = "The quick brown fox jumps over the lazy dog";
  crc = SocketDeflate_crc32 (0, (const uint8_t *)fox, strlen (fox));
  ASSERT_EQ (crc, 0x414FA339U);

  /* All zeros (8 bytes) */
  uint8_t zeros[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
  crc = SocketDeflate_crc32 (0, zeros, 8);
  ASSERT_EQ (crc, 0x6522DF69U);

  /* All ones (8 bytes) */
  uint8_t ones[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  crc = SocketDeflate_crc32 (0, ones, 8);
  ASSERT_EQ (crc, 0x2144DF1CU);
}

/*
 * Polynomial Verification
 *
 * Verify we're using the correct polynomial (0xEDB88320 reflected).
 * The polynomial determines the entire CRC behavior.
 */
TEST (crc32_polynomial_verify)
{
  /*
   * The IEEE 802.3 test vector is computed using polynomial 0xEDB88320:
   *   crc32("123456789") = 0xCBF43926
   *
   * Using the wrong polynomial (e.g., 0x82F63B78 for CRC-32C) would give:
   *   crc32c("123456789") = 0xE3069283
   *
   * This test ensures we're using the correct gzip/PNG polynomial.
   */
  uint32_t crc = SocketDeflate_crc32 (0, (const uint8_t *)"123456789", 9);

  /* Must match ISO 3309 / IEEE 802.3 */
  ASSERT_EQ (crc, 0xCBF43926U);

  /* Must NOT match CRC-32C (iSCSI polynomial) */
  ASSERT (crc != 0xE3069283U);
}

/*
 * NULL Pointer Safety
 */
TEST (crc32_null_safety)
{
  /* NULL data with zero length should return input CRC */
  uint32_t crc = SocketDeflate_crc32 (0, NULL, 0);
  ASSERT_EQ (crc, 0U);

  /* NULL data with non-zero length should also handle gracefully */
  crc = SocketDeflate_crc32 (0, NULL, 100);
  ASSERT_EQ (crc, 0U);

  /* Non-zero initial CRC with NULL data returns input */
  crc = SocketDeflate_crc32 (0x12345678U, NULL, 0);
  ASSERT_EQ (crc, 0x12345678U);
}

/*
 * CRC32 Combine - Basic Test
 *
 * Verify that combining CRCs gives same result as computing over concatenated data.
 */
TEST (crc32_combine_basic)
{
  const char *part1 = "Hello";
  const char *part2 = " World";
  const char *combined = "Hello World";

  /* Compute CRCs separately */
  uint32_t crc1 = SocketDeflate_crc32 (0, (const uint8_t *)part1, 5);
  uint32_t crc2 = SocketDeflate_crc32 (0, (const uint8_t *)part2, 6);

  /* Compute CRC of combined */
  uint32_t crc_full = SocketDeflate_crc32 (0, (const uint8_t *)combined, 11);

  /* Combine CRCs */
  uint32_t crc_combined = SocketDeflate_crc32_combine (crc1, crc2, 6);

  ASSERT_EQ (crc_combined, crc_full);
}

/*
 * CRC32 Combine - Empty Second Part
 */
TEST (crc32_combine_empty)
{
  const char *data = "TestData";
  uint32_t crc1 = SocketDeflate_crc32 (0, (const uint8_t *)data, 8);

  /* Combining with empty second part should return first CRC */
  uint32_t crc_combined = SocketDeflate_crc32_combine (crc1, 0, 0);
  ASSERT_EQ (crc_combined, crc1);
}

/*
 * CRC32 Combine - IEEE Vector Split
 *
 * Split the canonical "123456789" at various points and verify combine works.
 */
TEST (crc32_combine_ieee_split)
{
  const char *data = "123456789";
  uint32_t crc_full = 0xCBF43926U; /* Known IEEE result */

  /* Split at position 3: "123" + "456789" */
  uint32_t crc1 = SocketDeflate_crc32 (0, (const uint8_t *)data, 3);
  uint32_t crc2 = SocketDeflate_crc32 (0, (const uint8_t *)data + 3, 6);
  uint32_t combined = SocketDeflate_crc32_combine (crc1, crc2, 6);
  ASSERT_EQ (combined, crc_full);

  /* Split at position 5: "12345" + "6789" */
  crc1 = SocketDeflate_crc32 (0, (const uint8_t *)data, 5);
  crc2 = SocketDeflate_crc32 (0, (const uint8_t *)data + 5, 4);
  combined = SocketDeflate_crc32_combine (crc1, crc2, 4);
  ASSERT_EQ (combined, crc_full);

  /* Split at position 1: "1" + "23456789" */
  crc1 = SocketDeflate_crc32 (0, (const uint8_t *)data, 1);
  crc2 = SocketDeflate_crc32 (0, (const uint8_t *)data + 1, 8);
  combined = SocketDeflate_crc32_combine (crc1, crc2, 8);
  ASSERT_EQ (combined, crc_full);
}

/*
 * CRC32 Combine - Three Parts
 *
 * Verify associativity: combine(combine(A,B), C) == CRC(A||B||C)
 */
TEST (crc32_combine_three_parts)
{
  const char *p1 = "The quick ";
  const char *p2 = "brown fox ";
  const char *p3 = "jumps";
  const char *full = "The quick brown fox jumps";

  uint32_t crc1 = SocketDeflate_crc32 (0, (const uint8_t *)p1, 10);
  uint32_t crc2 = SocketDeflate_crc32 (0, (const uint8_t *)p2, 10);
  uint32_t crc3 = SocketDeflate_crc32 (0, (const uint8_t *)p3, 5);

  uint32_t crc_full = SocketDeflate_crc32 (0, (const uint8_t *)full, 25);

  /* Combine step by step */
  uint32_t crc12 = SocketDeflate_crc32_combine (crc1, crc2, 10);
  uint32_t crc123 = SocketDeflate_crc32_combine (crc12, crc3, 5);

  ASSERT_EQ (crc123, crc_full);
}

/*
 * Test Runner
 */
int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
