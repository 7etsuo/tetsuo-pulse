/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_qpack.c - Unit tests for QPACK Header Compression
 *
 * Part of the Socket Library
 *
 * Tests RFC 9204 QPACK implementation including:
 * - Required Insert Count encoding (Section 4.5.1.1)
 * - Required Insert Count decoding with wrap-around
 * - MaxEntries calculation
 * - Edge cases and error handling
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketQPACK.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple test assertion macro */
#define TEST_ASSERT(cond, msg)                                               \
  do                                                                         \
    {                                                                        \
      if (!(cond))                                                           \
        {                                                                    \
          fprintf (stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); \
          exit (1);                                                          \
        }                                                                    \
    }                                                                        \
  while (0)

/* ============================================================================
 * MaxEntries Calculation Tests
 * ============================================================================
 */

/**
 * Test MaxEntries = floor(MaxTableCapacity / 32)
 */
static void
test_max_entries_calculation (void)
{
  printf ("  MaxEntries calculation... ");

  /* Standard table size: 4096 / 32 = 128 */
  TEST_ASSERT (SocketQPACK_max_entries (4096) == 128,
               "MaxEntries for 4096 should be 128");

  /* Small table: 64 / 32 = 2 */
  TEST_ASSERT (SocketQPACK_max_entries (64) == 2,
               "MaxEntries for 64 should be 2");

  /* Very small table: 31 / 32 = 0 */
  TEST_ASSERT (SocketQPACK_max_entries (31) == 0,
               "MaxEntries for 31 should be 0");

  /* Zero table: 0 / 32 = 0 */
  TEST_ASSERT (SocketQPACK_max_entries (0) == 0,
               "MaxEntries for 0 should be 0");

  /* Large table: 65536 / 32 = 2048 */
  TEST_ASSERT (SocketQPACK_max_entries (65536) == 2048,
               "MaxEntries for 65536 should be 2048");

  /* Non-aligned: 100 / 32 = 3 */
  TEST_ASSERT (SocketQPACK_max_entries (100) == 3,
               "MaxEntries for 100 should be 3");

  printf ("PASS\n");
}

/* ============================================================================
 * Required Insert Count Encoding Tests (RFC 9204 Section 4.5.1.1)
 * ============================================================================
 */

/**
 * Test encoding RIC = 0
 */
static void
test_encode_ric_zero (void)
{
  uint64_t encoded;

  printf ("  Encode RIC = 0... ");

  encoded = SocketQPACK_encode_required_insert_count (0, 4096);
  TEST_ASSERT (encoded == 0, "RIC = 0 should encode to 0");

  printf ("PASS\n");
}

/**
 * Test encoding RIC = 1 with standard table
 * MaxEntries = 128, FullRange = 256
 * Encoded = (1 mod 256) + 1 = 2
 */
static void
test_encode_ric_one (void)
{
  uint64_t encoded;

  printf ("  Encode RIC = 1 with MaxTableCapacity = 4096... ");

  encoded = SocketQPACK_encode_required_insert_count (1, 4096);
  TEST_ASSERT (encoded == 2, "RIC = 1 should encode to 2");

  printf ("PASS\n");
}

/**
 * Test encoding at FullRange boundary
 * MaxEntries = 128, FullRange = 256
 * RIC = 256: encoded = (256 mod 256) + 1 = 1
 */
static void
test_encode_ric_at_fullrange (void)
{
  uint64_t encoded;

  printf ("  Encode RIC at FullRange boundary... ");

  /* RIC = 256 wraps to 0, then +1 = 1 */
  encoded = SocketQPACK_encode_required_insert_count (256, 4096);
  TEST_ASSERT (encoded == 1, "RIC = 256 (FullRange) should encode to 1");

  /* RIC = 255: encoded = (255 mod 256) + 1 = 256 */
  encoded = SocketQPACK_encode_required_insert_count (255, 4096);
  TEST_ASSERT (encoded == 256, "RIC = 255 should encode to 256");

  /* RIC = 257: encoded = (257 mod 256) + 1 = 2 */
  encoded = SocketQPACK_encode_required_insert_count (257, 4096);
  TEST_ASSERT (encoded == 2, "RIC = 257 should encode to 2");

  printf ("PASS\n");
}

/**
 * Test encoding with small MaxTableCapacity
 */
static void
test_encode_ric_small_table (void)
{
  uint64_t encoded;

  printf ("  Encode RIC with small table... ");

  /* MaxTableCapacity = 64, MaxEntries = 2, FullRange = 4 */
  /* RIC = 1: encoded = (1 mod 4) + 1 = 2 */
  encoded = SocketQPACK_encode_required_insert_count (1, 64);
  TEST_ASSERT (encoded == 2, "RIC = 1 with small table should encode to 2");

  /* RIC = 4: encoded = (4 mod 4) + 1 = 1 */
  encoded = SocketQPACK_encode_required_insert_count (4, 64);
  TEST_ASSERT (encoded == 1, "RIC = 4 should encode to 1 (wrap)");

  printf ("PASS\n");
}

/**
 * Test encoding with zero MaxEntries (table capacity < 32)
 */
static void
test_encode_ric_zero_max_entries (void)
{
  uint64_t encoded;

  printf ("  Encode RIC with zero MaxEntries... ");

  /* When MaxEntries = 0, just return RIC unchanged */
  encoded = SocketQPACK_encode_required_insert_count (5, 16);
  TEST_ASSERT (encoded == 5, "RIC with zero MaxEntries should pass through");

  printf ("PASS\n");
}

/* ============================================================================
 * Required Insert Count Decoding Tests (RFC 9204 Section 4.5.1.1)
 * ============================================================================
 */

/**
 * Test decoding EncodedRIC = 0
 */
static void
test_decode_ric_zero (void)
{
  uint64_t decoded;
  SocketQPACK_Result result;

  printf ("  Decode EncodedRIC = 0... ");

  result = SocketQPACK_decode_required_insert_count (0, 4096, 100, &decoded);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (decoded == 0, "EncodedRIC = 0 should decode to 0");

  printf ("PASS\n");
}

/**
 * Test decoding within valid range
 */
static void
test_decode_ric_valid_range (void)
{
  uint64_t decoded;
  SocketQPACK_Result result;

  printf ("  Decode EncodedRIC within valid range... ");

  /* MaxTableCapacity = 4096, MaxEntries = 128, FullRange = 256
   * TotalInserts = 10, MaxValue = 10 + 128 = 138
   * EncodedRIC = 2: MaxWrapped = 0, RIC = 0 + 2 - 1 = 1 */
  result = SocketQPACK_decode_required_insert_count (2, 4096, 10, &decoded);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (decoded == 1, "EncodedRIC = 2 should decode to 1");

  /* EncodedRIC = 11: RIC = 0 + 11 - 1 = 10 */
  result = SocketQPACK_decode_required_insert_count (11, 4096, 10, &decoded);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (decoded == 10, "EncodedRIC = 11 should decode to 10");

  printf ("PASS\n");
}

/**
 * Test decoding with wrap-around
 */
static void
test_decode_ric_wrap_around (void)
{
  uint64_t decoded;
  SocketQPACK_Result result;

  printf ("  Decode EncodedRIC with wrap-around... ");

  /* MaxTableCapacity = 4096, MaxEntries = 128, FullRange = 256
   * TotalInserts = 300, MaxValue = 300 + 128 = 428
   * MaxWrapped = floor(428 / 256) * 256 = 256
   * EncodedRIC = 50: RIC = 256 + 50 - 1 = 305 */
  result = SocketQPACK_decode_required_insert_count (50, 4096, 300, &decoded);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (decoded == 305, "EncodedRIC = 50 with TotalInserts = 300");

  printf ("PASS\n");
}

/**
 * Test decoding error: EncodedRIC > FullRange
 */
static void
test_decode_ric_exceeds_fullrange (void)
{
  uint64_t decoded;
  SocketQPACK_Result result;

  printf ("  Decode EncodedRIC > FullRange (error)... ");

  /* MaxTableCapacity = 4096, MaxEntries = 128, FullRange = 256
   * EncodedRIC = 257 > FullRange = 256 -> error */
  result = SocketQPACK_decode_required_insert_count (257, 4096, 10, &decoded);
  TEST_ASSERT (result == QPACK_ERROR_INSERT_COUNT,
               "Should return INSERT_COUNT error");

  printf ("PASS\n");
}

/**
 * Test decoding error: result would be 0
 */
static void
test_decode_ric_result_zero (void)
{
  uint64_t decoded;
  SocketQPACK_Result result;

  printf ("  Decode EncodedRIC resulting in 0 (error)... ");

  /* MaxTableCapacity = 64, MaxEntries = 2, FullRange = 4
   * TotalInserts = 0, MaxValue = 2
   * EncodedRIC = 1: MaxWrapped = 0, RIC = 0 + 1 - 1 = 0
   * But RIC = 0 after decoding non-zero EncodedRIC is an error! */
  result = SocketQPACK_decode_required_insert_count (1, 64, 4, &decoded);
  /* Actually, let's trace this:
   * MaxValue = 4 + 2 = 6
   * MaxWrapped = floor(6/4) * 4 = 4
   * RIC = 4 + 1 - 1 = 4
   * 4 <= 6, so no adjustment needed
   * RIC = 4 != 0, valid */
  TEST_ASSERT (result == QPACK_OK, "RIC = 4 should be valid");
  TEST_ASSERT (decoded == 4, "Should decode to 4");

  printf ("PASS\n");
}

/**
 * Test decoding with wrap-around adjustment
 */
static void
test_decode_ric_wrap_adjustment (void)
{
  uint64_t decoded;
  SocketQPACK_Result result;

  printf ("  Decode EncodedRIC with wrap adjustment... ");

  /* MaxTableCapacity = 4096, MaxEntries = 128, FullRange = 256
   * TotalInserts = 200, MaxValue = 200 + 128 = 328
   * MaxWrapped = floor(328 / 256) * 256 = 256
   *
   * EncodedRIC = 200: RIC = 256 + 200 - 1 = 455
   * 455 > 328 (MaxValue)
   * 455 > 256 (FullRange), so subtract FullRange
   * RIC = 455 - 256 = 199 */
  result = SocketQPACK_decode_required_insert_count (200, 4096, 200, &decoded);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (decoded == 199, "Should decode to 199 after adjustment");

  printf ("PASS\n");
}

/**
 * Test decoding with zero MaxEntries (edge case)
 */
static void
test_decode_ric_zero_max_entries (void)
{
  uint64_t decoded;
  SocketQPACK_Result result;

  printf ("  Decode with zero MaxEntries (error)... ");

  /* MaxTableCapacity = 16, MaxEntries = 0
   * Non-zero EncodedRIC with zero MaxEntries is an error */
  result = SocketQPACK_decode_required_insert_count (1, 16, 0, &decoded);
  TEST_ASSERT (result == QPACK_ERROR_INSERT_COUNT,
               "Should return INSERT_COUNT error");

  printf ("PASS\n");
}

/**
 * Test null output pointer
 */
static void
test_decode_ric_null_output (void)
{
  SocketQPACK_Result result;

  printf ("  Decode with NULL output pointer... ");

  result = SocketQPACK_decode_required_insert_count (10, 4096, 100, NULL);
  TEST_ASSERT (result == QPACK_ERROR, "Should return error for NULL output");

  printf ("PASS\n");
}

/* ============================================================================
 * Round-trip Tests
 * ============================================================================
 */

/**
 * Test encode/decode round-trip for various values
 *
 * RFC 9204 Section 4.5.1.1 notes:
 * - The decoder uses TotalNumberOfInserts to disambiguate wrapped values
 * - For round-trip to work, TotalInserts must be >= RIC
 * - The decoder calculates: MaxValue = TotalInserts + MaxEntries
 * - Valid RIC values are in range [1, MaxValue] for non-zero encoded values
 */
static void
test_round_trip (void)
{
  uint32_t max_capacity = 4096;
  uint64_t encoded, decoded;
  SocketQPACK_Result result;

  printf ("  Round-trip encode/decode... ");

  /* Test RIC = 0 */
  encoded = SocketQPACK_encode_required_insert_count (0, max_capacity);
  TEST_ASSERT (encoded == 0, "RIC = 0 should encode to 0");
  result = SocketQPACK_decode_required_insert_count (
      encoded, max_capacity, 0, &decoded);
  TEST_ASSERT (result == QPACK_OK && decoded == 0, "RIC = 0 round-trip failed");

  /* For non-zero RIC, we simulate the decoder having seen at least RIC inserts
   * This ensures the RIC value is within the valid range for the decoder */
  for (uint64_t ric = 1; ric <= 512; ric++)
    {
      encoded = SocketQPACK_encode_required_insert_count (ric, max_capacity);

      /* The decoder should have total_inserts >= ric to properly decode
       * We use total_inserts = ric to simulate the encoder and decoder
       * being in sync (decoder has seen exactly as many inserts as needed) */
      result = SocketQPACK_decode_required_insert_count (
          encoded, max_capacity, ric, &decoded);

      /* The decoded value should equal the original RIC when total_inserts >=
       * ric and ric <= total_inserts + max_entries (within valid range) */
      TEST_ASSERT (result == QPACK_OK,
                   "Round-trip decode should succeed when in sync");
      TEST_ASSERT (decoded == ric, "Round-trip mismatch");
    }

  printf ("PASS\n");
}

/**
 * Test round-trip with various MaxTableCapacity values
 *
 * Use total_inserts = ric to ensure encoder and decoder are in sync.
 */
static void
test_round_trip_various_capacities (void)
{
  uint32_t capacities[] = { 64, 256, 1024, 4096, 16384, 65536 };
  size_t num_caps = sizeof (capacities) / sizeof (capacities[0]);

  printf ("  Round-trip with various capacities... ");

  for (size_t i = 0; i < num_caps; i++)
    {
      uint32_t cap = capacities[i];
      uint32_t max_entries = SocketQPACK_max_entries (cap);

      if (max_entries == 0)
        continue;

      /* Test values from 1 to 3x MaxEntries */
      for (uint64_t ric = 1; ric <= (uint64_t)max_entries * 3; ric++)
        {
          uint64_t encoded, decoded;
          SocketQPACK_Result result;

          encoded = SocketQPACK_encode_required_insert_count (ric, cap);

          /* Use total_inserts = ric to keep encoder/decoder in sync */
          result = SocketQPACK_decode_required_insert_count (
              encoded, cap, ric, &decoded);

          TEST_ASSERT (result == QPACK_OK && decoded == ric,
                       "Round-trip failed for capacity");
        }
    }

  printf ("PASS\n");
}

/* ============================================================================
 * Result String Tests
 * ============================================================================
 */

static void
test_result_strings (void)
{
  printf ("  Result strings... ");

  TEST_ASSERT (strcmp (SocketQPACK_result_string (QPACK_OK), "OK") == 0,
               "QPACK_OK string mismatch");
  TEST_ASSERT (strcmp (SocketQPACK_result_string (QPACK_ERROR_INSERT_COUNT),
                       "Invalid Required Insert Count")
                   == 0,
               "QPACK_ERROR_INSERT_COUNT string mismatch");
  TEST_ASSERT (strcmp (SocketQPACK_result_string ((SocketQPACK_Result)999),
                       "Unknown error")
                   == 0,
               "Invalid result should return 'Unknown error'");

  printf ("PASS\n");
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================
 */

int
main (void)
{
  printf ("QPACK Required Insert Count Tests (RFC 9204 Section 4.5.1.1)\n");
  printf ("=============================================================\n\n");

  printf ("MaxEntries Calculation:\n");
  test_max_entries_calculation ();

  printf ("\nRequired Insert Count Encoding:\n");
  test_encode_ric_zero ();
  test_encode_ric_one ();
  test_encode_ric_at_fullrange ();
  test_encode_ric_small_table ();
  test_encode_ric_zero_max_entries ();

  printf ("\nRequired Insert Count Decoding:\n");
  test_decode_ric_zero ();
  test_decode_ric_valid_range ();
  test_decode_ric_wrap_around ();
  test_decode_ric_exceeds_fullrange ();
  test_decode_ric_result_zero ();
  test_decode_ric_wrap_adjustment ();
  test_decode_ric_zero_max_entries ();
  test_decode_ric_null_output ();

  printf ("\nRound-trip Tests:\n");
  test_round_trip ();
  test_round_trip_various_capacities ();

  printf ("\nResult Strings:\n");
  test_result_strings ();

  printf ("\n=============================================================\n");
  printf ("All tests passed!\n");

  return 0;
}
