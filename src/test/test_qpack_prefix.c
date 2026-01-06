/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_prefix.c
 * @brief Unit tests for QPACK Field Section Prefix (RFC 9204 Section 4.5.1)
 *
 * Tests encoding and decoding of:
 * - Required Insert Count (8-bit prefix integer)
 * - Delta Base with sign bit (7-bit prefix)
 * - Base computation from Delta Base and Required Insert Count
 */

#include "http/qpack/SocketQPACK-private.h"

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
          test_failures++;                                                   \
        }                                                                    \
    }                                                                        \
  while (0)

static int test_failures = 0;

/* ============================================================================
 * Integer Encoding Tests (RFC 9204 Section 4.1.1)
 * ============================================================================
 */

/**
 * Test integer encoding with 8-bit prefix (single byte case)
 */
static void
test_int_encode_8bit_small (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 42 with 8-bit prefix... ");

  len = socketqpack_encode_integer (42, 8, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Expected 1 byte");
  TEST_ASSERT (buf[0] == 42, "Expected 42");

  printf ("PASS\n");
}

/**
 * Test integer encoding at prefix boundary (255)
 */
static void
test_int_encode_8bit_boundary (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 254 with 8-bit prefix... ");

  len = socketqpack_encode_integer (254, 8, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Expected 1 byte");
  TEST_ASSERT (buf[0] == 254, "Expected 254");

  printf ("PASS\n");
}

/**
 * Test integer encoding requiring multi-byte (>= 255 for 8-bit prefix)
 */
static void
test_int_encode_8bit_large (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 300 with 8-bit prefix... ");

  len = socketqpack_encode_integer (300, 8, buf, sizeof (buf));
  TEST_ASSERT (len == 2, "Expected 2 bytes");
  TEST_ASSERT (buf[0] == 0xFF, "First byte should be 255");
  /* 300 - 255 = 45 = 0x2D */
  TEST_ASSERT (buf[1] == 0x2D, "Second byte should be 0x2D (45)");

  printf ("PASS\n");
}

/**
 * Test integer encoding with 7-bit prefix
 */
static void
test_int_encode_7bit (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 100 with 7-bit prefix... ");

  len = socketqpack_encode_integer (100, 7, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Expected 1 byte");
  TEST_ASSERT (buf[0] == 100, "Expected 100");

  printf ("PASS\n");
}

/**
 * Test integer encoding with 7-bit prefix at boundary
 */
static void
test_int_encode_7bit_boundary (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 127 with 7-bit prefix... ");

  /* 127 = 2^7 - 1 = max prefix value, needs continuation */
  len = socketqpack_encode_integer (127, 7, buf, sizeof (buf));
  TEST_ASSERT (len == 2, "Expected 2 bytes for value at boundary");
  TEST_ASSERT (buf[0] == 0x7F, "First byte should be 127");
  TEST_ASSERT (buf[1] == 0x00, "Second byte should be 0");

  printf ("PASS\n");
}

/* ============================================================================
 * Integer Decoding Tests
 * ============================================================================
 */

/**
 * Test integer decoding (single byte)
 */
static void
test_int_decode_small (void)
{
  unsigned char data[] = { 42 };
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Integer decode 42... ");

  result
      = socketqpack_decode_integer (data, sizeof (data), 8, &value, &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (value == 42, "Value should be 42");
  TEST_ASSERT (consumed == 1, "Should consume 1 byte");

  printf ("PASS\n");
}

/**
 * Test integer decoding (multi-byte)
 */
static void
test_int_decode_large (void)
{
  /* 300 encoded with 8-bit prefix: 0xFF, 0x2D */
  unsigned char data[] = { 0xFF, 0x2D };
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Integer decode 300... ");

  result
      = socketqpack_decode_integer (data, sizeof (data), 8, &value, &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (value == 300, "Value should be 300");
  TEST_ASSERT (consumed == 2, "Should consume 2 bytes");

  printf ("PASS\n");
}

/**
 * Test integer decoding with incomplete data
 */
static void
test_int_decode_incomplete (void)
{
  /* Start of a multi-byte integer but missing continuation */
  unsigned char data[] = { 0xFF };
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Integer decode incomplete... ");

  result
      = socketqpack_decode_integer (data, sizeof (data), 8, &value, &consumed);
  TEST_ASSERT (result == QPACK_INCOMPLETE, "Should return INCOMPLETE");

  printf ("PASS\n");
}

/* ============================================================================
 * Required Insert Count Tests (RFC 9204 Section 4.5.1.1)
 * ============================================================================
 */

/**
 * Test prefix with Required Insert Count = 0
 */
static void
test_prefix_ric_zero (void)
{
  unsigned char buf[16];
  ssize_t encoded_len;
  SocketQPACK_DecodePrefixResult decoded;

  printf ("  Prefix with Required Insert Count = 0... ");

  /* Encode: RIC=0, Base=0, max_entries=100 */
  encoded_len = socketqpack_encode_prefix (0, 0, 100, buf, sizeof (buf));
  TEST_ASSERT (encoded_len > 0, "Encoding should succeed");

  /* Decode */
  decoded = socketqpack_decode_prefix (buf, (size_t)encoded_len, 100, 0);
  TEST_ASSERT (decoded.status == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (decoded.prefix.required_insert_count == 0, "RIC should be 0");
  TEST_ASSERT (decoded.prefix.base == 0, "Base should be 0");

  printf ("PASS\n");
}

/**
 * Test prefix with small Required Insert Count
 */
static void
test_prefix_ric_small (void)
{
  unsigned char buf[16];
  ssize_t encoded_len;
  SocketQPACK_DecodePrefixResult decoded;

  printf ("  Prefix with Required Insert Count = 10... ");

  /* Encode: RIC=10, Base=10 (same as RIC, so DeltaBase=0, S=0) */
  encoded_len = socketqpack_encode_prefix (10, 10, 100, buf, sizeof (buf));
  TEST_ASSERT (encoded_len > 0, "Encoding should succeed");

  /* Decode with total_inserts >= RIC */
  decoded = socketqpack_decode_prefix (buf, (size_t)encoded_len, 100, 50);
  TEST_ASSERT (decoded.status == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (decoded.prefix.required_insert_count == 10, "RIC should be 10");
  TEST_ASSERT (decoded.prefix.base == 10, "Base should be 10");

  printf ("PASS\n");
}

/* ============================================================================
 * Delta Base Tests (RFC 9204 Section 4.5.1.2)
 * ============================================================================
 */

/**
 * Test positive Delta Base (S=0, Base >= Required Insert Count)
 */
static void
test_prefix_positive_delta_base (void)
{
  unsigned char buf[16];
  ssize_t encoded_len;
  SocketQPACK_DecodePrefixResult decoded;

  printf ("  Prefix with positive Delta Base (Base > RIC)... ");

  /* Encode: RIC=42, Base=50 -> DeltaBase = 50-42 = 8, S=0 */
  encoded_len = socketqpack_encode_prefix (42, 50, 100, buf, sizeof (buf));
  TEST_ASSERT (encoded_len > 0, "Encoding should succeed");

  /* Decode with total_inserts >= RIC */
  decoded = socketqpack_decode_prefix (buf, (size_t)encoded_len, 100, 50);
  TEST_ASSERT (decoded.status == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (decoded.prefix.required_insert_count == 42, "RIC should be 42");
  TEST_ASSERT (decoded.prefix.base == 50, "Base should be 50");
  TEST_ASSERT (decoded.prefix.delta_base == 8, "DeltaBase should be 8");

  printf ("PASS\n");
}

/**
 * Test negative Delta Base (S=1, Base < Required Insert Count)
 */
static void
test_prefix_negative_delta_base (void)
{
  unsigned char buf[16];
  ssize_t encoded_len;
  SocketQPACK_DecodePrefixResult decoded;

  printf ("  Prefix with negative Delta Base (Base < RIC)... ");

  /* Encode: RIC=42, Base=30 -> DeltaBase = 42-30-1 = 11, S=1 */
  encoded_len = socketqpack_encode_prefix (42, 30, 100, buf, sizeof (buf));
  TEST_ASSERT (encoded_len > 0, "Encoding should succeed");

  /* Decode with total_inserts >= RIC */
  decoded = socketqpack_decode_prefix (buf, (size_t)encoded_len, 100, 50);
  TEST_ASSERT (decoded.status == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (decoded.prefix.required_insert_count == 42, "RIC should be 42");
  TEST_ASSERT (decoded.prefix.base == 30, "Base should be 30");
  TEST_ASSERT (decoded.prefix.delta_base == -12, "DeltaBase should be -12");

  printf ("PASS\n");
}

/**
 * Test Delta Base = 0 with S=0 (Base == RIC)
 */
static void
test_prefix_delta_base_zero (void)
{
  unsigned char buf[16];
  ssize_t encoded_len;
  SocketQPACK_DecodePrefixResult decoded;

  printf ("  Prefix with Delta Base = 0 (Base == RIC)... ");

  /* Encode: RIC=25, Base=25 -> DeltaBase = 0, S=0 */
  encoded_len = socketqpack_encode_prefix (25, 25, 100, buf, sizeof (buf));
  TEST_ASSERT (encoded_len > 0, "Encoding should succeed");

  /* Decode */
  decoded = socketqpack_decode_prefix (buf, (size_t)encoded_len, 100, 50);
  TEST_ASSERT (decoded.status == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (decoded.prefix.required_insert_count == 25, "RIC should be 25");
  TEST_ASSERT (decoded.prefix.base == 25, "Base should be 25");
  TEST_ASSERT (decoded.prefix.delta_base == 0, "DeltaBase should be 0");

  printf ("PASS\n");
}

/* ============================================================================
 * Round-Trip Tests
 * ============================================================================
 */

/**
 * Test round-trip encoding/decoding for various values
 */
static void
test_prefix_roundtrip (void)
{
  unsigned char buf[32];
  ssize_t encoded_len;
  SocketQPACK_DecodePrefixResult decoded;

  printf ("  Round-trip encoding/decoding... ");

  /* Test cases: (ric, base, max_entries, total_inserts) */
  struct
  {
    size_t ric;
    size_t base;
    size_t max_entries;
    size_t total_inserts;
  } cases[] = {
    { 0, 0, 100, 0 },       { 1, 1, 100, 10 },    { 10, 5, 100, 20 },
    { 10, 15, 100, 20 },    { 50, 50, 100, 100 }, { 100, 150, 200, 150 },
    { 200, 100, 256, 250 },
  };

  for (size_t i = 0; i < sizeof (cases) / sizeof (cases[0]); i++)
    {
      encoded_len = socketqpack_encode_prefix (
          cases[i].ric, cases[i].base, cases[i].max_entries, buf, sizeof (buf));
      TEST_ASSERT (encoded_len > 0, "Encoding should succeed");

      decoded = socketqpack_decode_prefix (buf,
                                           (size_t)encoded_len,
                                           cases[i].max_entries,
                                           cases[i].total_inserts);
      TEST_ASSERT (decoded.status == QPACK_OK, "Decoding should succeed");
      TEST_ASSERT (decoded.prefix.required_insert_count == cases[i].ric,
                   "RIC mismatch");
      TEST_ASSERT (decoded.prefix.base == cases[i].base, "Base mismatch");
    }

  printf ("PASS\n");
}

/* ============================================================================
 * Validation Tests
 * ============================================================================
 */

/**
 * Test validation: Required Insert Count exceeds total_inserts
 */
static void
test_prefix_invalid_ric (void)
{
  unsigned char buf[16];
  ssize_t encoded_len;
  SocketQPACK_DecodePrefixResult decoded;

  printf ("  Validation: RIC > total_inserts... ");

  /* Encode with RIC=50 */
  encoded_len = socketqpack_encode_prefix (50, 50, 100, buf, sizeof (buf));
  TEST_ASSERT (encoded_len > 0, "Encoding should succeed");

  /* Decode with total_inserts < RIC (should fail) */
  decoded = socketqpack_decode_prefix (buf, (size_t)encoded_len, 100, 30);
  TEST_ASSERT (decoded.status == QPACK_ERROR_INVALID_REQUIRED_INSERT_COUNT,
               "Should reject RIC > total_inserts");

  printf ("PASS\n");
}

/**
 * Test validation: validate_prefix function
 */
static void
test_validate_prefix (void)
{
  SocketQPACK_FieldSectionPrefix prefix;
  SocketQPACK_Result result;

  printf ("  validate_prefix function... ");

  /* Valid prefix */
  prefix.required_insert_count = 10;
  prefix.base = 15;
  prefix.delta_base = 5;
  result = socketqpack_validate_prefix (&prefix, 20);
  TEST_ASSERT (result == QPACK_OK, "Valid prefix should pass");

  /* Invalid: RIC > total_inserts */
  prefix.required_insert_count = 30;
  result = socketqpack_validate_prefix (&prefix, 20);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_REQUIRED_INSERT_COUNT,
               "Should reject RIC > total_inserts");

  /* NULL prefix */
  result = socketqpack_validate_prefix (NULL, 20);
  TEST_ASSERT (result == QPACK_ERROR, "Should reject NULL prefix");

  printf ("PASS\n");
}

/* ============================================================================
 * Edge Cases
 * ============================================================================
 */

/**
 * Test edge case: max_entries = 0
 */
static void
test_prefix_max_entries_zero (void)
{
  unsigned char buf[] = { 0x01, 0x00 }; /* Non-zero encoded RIC */
  SocketQPACK_DecodePrefixResult decoded;

  printf ("  Edge case: max_entries = 0... ");

  decoded = socketqpack_decode_prefix (buf, sizeof (buf), 0, 10);
  TEST_ASSERT (decoded.status == QPACK_ERROR_INVALID_REQUIRED_INSERT_COUNT,
               "Should reject when max_entries is 0");

  printf ("PASS\n");
}

/**
 * Test edge case: empty input buffer
 */
static void
test_prefix_empty_input (void)
{
  SocketQPACK_DecodePrefixResult decoded;

  printf ("  Edge case: empty input... ");

  decoded = socketqpack_decode_prefix (NULL, 0, 100, 50);
  TEST_ASSERT (decoded.status == QPACK_INCOMPLETE,
               "Should return INCOMPLETE for empty input");

  printf ("PASS\n");
}

/**
 * Test edge case: buffer too small for encoding
 */
static void
test_prefix_buffer_too_small (void)
{
  unsigned char buf[1]; /* Too small for any prefix */
  ssize_t encoded_len;

  printf ("  Edge case: buffer too small... ");

  /* This should fail because we need at least 2 bytes */
  encoded_len = socketqpack_encode_prefix (100, 150, 256, buf, 0);
  TEST_ASSERT (encoded_len < 0, "Should fail with 0-size buffer");

  printf ("PASS\n");
}

/**
 * Test edge case: large Required Insert Count (multi-octet encoding)
 */
static void
test_prefix_large_ric (void)
{
  unsigned char buf[32];
  ssize_t encoded_len;
  SocketQPACK_DecodePrefixResult decoded;

  printf ("  Edge case: large Required Insert Count... ");

  /* Large RIC that requires multi-byte encoding */
  size_t ric = 500;
  size_t max_entries = 256;

  encoded_len
      = socketqpack_encode_prefix (ric, ric, max_entries, buf, sizeof (buf));
  TEST_ASSERT (encoded_len > 0, "Encoding should succeed");

  decoded
      = socketqpack_decode_prefix (buf, (size_t)encoded_len, max_entries, 600);
  TEST_ASSERT (decoded.status == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (decoded.prefix.required_insert_count == ric, "RIC should match");

  printf ("PASS\n");
}

/* ============================================================================
 * Result String Test
 * ============================================================================
 */

static void
test_result_strings (void)
{
  printf ("  Result string conversion... ");

  TEST_ASSERT (strcmp (socketqpack_result_string (QPACK_OK), "OK") == 0,
               "QPACK_OK string");
  TEST_ASSERT (socketqpack_result_string (QPACK_INCOMPLETE) != NULL,
               "QPACK_INCOMPLETE string");
  TEST_ASSERT (socketqpack_result_string (QPACK_ERROR_INTEGER_OVERFLOW) != NULL,
               "QPACK_ERROR_INTEGER_OVERFLOW string");
  TEST_ASSERT (socketqpack_result_string ((SocketQPACK_Result)999) != NULL,
               "Unknown error string");

  printf ("PASS\n");
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  printf ("QPACK Field Section Prefix Tests (RFC 9204 Section 4.5.1)\n");
  printf ("=========================================================\n\n");

  printf ("Integer Encoding Tests:\n");
  test_int_encode_8bit_small ();
  test_int_encode_8bit_boundary ();
  test_int_encode_8bit_large ();
  test_int_encode_7bit ();
  test_int_encode_7bit_boundary ();

  printf ("\nInteger Decoding Tests:\n");
  test_int_decode_small ();
  test_int_decode_large ();
  test_int_decode_incomplete ();

  printf ("\nRequired Insert Count Tests:\n");
  test_prefix_ric_zero ();
  test_prefix_ric_small ();

  printf ("\nDelta Base Tests:\n");
  test_prefix_positive_delta_base ();
  test_prefix_negative_delta_base ();
  test_prefix_delta_base_zero ();

  printf ("\nRound-Trip Tests:\n");
  test_prefix_roundtrip ();

  printf ("\nValidation Tests:\n");
  test_prefix_invalid_ric ();
  test_validate_prefix ();

  printf ("\nEdge Case Tests:\n");
  test_prefix_max_entries_zero ();
  test_prefix_empty_input ();
  test_prefix_buffer_too_small ();
  test_prefix_large_ric ();

  printf ("\nMiscellaneous Tests:\n");
  test_result_strings ();

  printf ("\n=========================================================\n");
  if (test_failures == 0)
    {
      printf ("All tests PASSED!\n");
      return 0;
    }
  else
    {
      printf ("FAILED: %d test(s)\n", test_failures);
      return 1;
    }
}
