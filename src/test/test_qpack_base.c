/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_base.c
 * @brief Unit tests for QPACK Base Encoding (RFC 9204 Section 4.5.1.2)
 *
 * Tests Base calculation, validation, and prefix encoding/decoding
 * as specified in RFC 9204 Section 4.5.1.2.
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketQPACK.h"

#include <limits.h>
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
 * Base Calculation Tests (RFC 9204 Section 4.5.1.2)
 * ============================================================================
 */

/**
 * Test Base = ReqInsertCount + DeltaBase when Sign = 0
 * This is the "forward" case where Base is ahead of ReqInsertCount.
 */
static void
test_base_sign_zero (void)
{
  int32_t base;
  SocketQPACK_Result result;

  printf ("  Base calculation with Sign=0... ");

  /* Base = 10 + 5 = 15 */
  result = SocketQPACK_calculate_base (10, 5, 0, &base);
  TEST_ASSERT (result == QPACK_OK, "Should succeed");
  TEST_ASSERT (base == 15, "Base should be 15");

  /* Base = 0 + 0 = 0 */
  result = SocketQPACK_calculate_base (0, 0, 0, &base);
  TEST_ASSERT (result == QPACK_OK, "Should succeed with zero values");
  TEST_ASSERT (base == 0, "Base should be 0");

  /* Base = 100 + 0 = 100 */
  result = SocketQPACK_calculate_base (100, 0, 0, &base);
  TEST_ASSERT (result == QPACK_OK, "Should succeed");
  TEST_ASSERT (base == 100, "Base should be 100");

  /* Base = 50 + 50 = 100 */
  result = SocketQPACK_calculate_base (50, 50, 0, &base);
  TEST_ASSERT (result == QPACK_OK, "Should succeed");
  TEST_ASSERT (base == 100, "Base should be 100");

  printf ("PASS\n");
}

/**
 * Test Base = ReqInsertCount - DeltaBase - 1 when Sign = 1
 * This is the "backward" case where Base is behind ReqInsertCount.
 */
static void
test_base_sign_one (void)
{
  int32_t base;
  SocketQPACK_Result result;

  printf ("  Base calculation with Sign=1... ");

  /* Base = 10 - 5 - 1 = 4 */
  result = SocketQPACK_calculate_base (10, 5, 1, &base);
  TEST_ASSERT (result == QPACK_OK, "Should succeed");
  TEST_ASSERT (base == 4, "Base should be 4");

  /* Base = 10 - 0 - 1 = 9 */
  result = SocketQPACK_calculate_base (10, 0, 1, &base);
  TEST_ASSERT (result == QPACK_OK, "Should succeed");
  TEST_ASSERT (base == 9, "Base should be 9");

  /* Base = 1 - 0 - 1 = 0 (minimum valid case) */
  result = SocketQPACK_calculate_base (1, 0, 1, &base);
  TEST_ASSERT (result == QPACK_OK, "Should succeed with minimum values");
  TEST_ASSERT (base == 0, "Base should be 0");

  /* Base = 100 - 50 - 1 = 49 */
  result = SocketQPACK_calculate_base (100, 50, 1, &base);
  TEST_ASSERT (result == QPACK_OK, "Should succeed");
  TEST_ASSERT (base == 49, "Base should be 49");

  printf ("PASS\n");
}

/**
 * Test rejection of negative Base values.
 */
static void
test_base_reject_negative (void)
{
  int32_t base;
  SocketQPACK_Result result;

  printf ("  Reject Base < 0... ");

  /* Sign=1, ReqInsertCount=5, DeltaBase=5 would give Base = 5 - 5 - 1 = -1 */
  /* But ReqInsertCount <= DeltaBase violates constraint */
  result = SocketQPACK_calculate_base (5, 5, 1, &base);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_BASE,
               "Should reject when ReqInsertCount == DeltaBase with Sign=1");

  /* Sign=1, ReqInsertCount=3, DeltaBase=5 violates ReqInsertCount > DeltaBase
   */
  result = SocketQPACK_calculate_base (3, 5, 1, &base);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_BASE,
               "Should reject when ReqInsertCount < DeltaBase with Sign=1");

  /* Sign=1, ReqInsertCount=0, DeltaBase=0 would give Base = 0 - 0 - 1 = -1 */
  result = SocketQPACK_calculate_base (0, 0, 1, &base);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_BASE,
               "Should reject zero values with Sign=1");

  printf ("PASS\n");
}

/**
 * Test Sign=1 constraint: ReqInsertCount MUST be > DeltaBase.
 */
static void
test_base_sign_one_constraint (void)
{
  int32_t base;
  SocketQPACK_Result result;

  printf ("  Sign=1 constraint validation... ");

  /* Valid: ReqInsertCount (10) > DeltaBase (5) */
  result = SocketQPACK_calculate_base (10, 5, 1, &base);
  TEST_ASSERT (result == QPACK_OK,
               "Should succeed when ReqInsertCount > DeltaBase");

  /* Invalid: ReqInsertCount (5) == DeltaBase (5) */
  result = SocketQPACK_calculate_base (5, 5, 1, &base);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_BASE,
               "Should reject when ReqInsertCount == DeltaBase");

  /* Invalid: ReqInsertCount (4) < DeltaBase (5) */
  result = SocketQPACK_calculate_base (4, 5, 1, &base);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_BASE,
               "Should reject when ReqInsertCount < DeltaBase");

  printf ("PASS\n");
}

/**
 * Test edge case: ReqInsertCount = 0, DeltaBase = 0, Sign = 0.
 * Base = 0 + 0 = 0, which is valid.
 */
static void
test_base_zero_values (void)
{
  int32_t base;
  SocketQPACK_Result result;

  printf ("  Edge case: ReqInsertCount=0, DeltaBase=0... ");

  /* Sign=0: Base = 0 + 0 = 0 */
  result = SocketQPACK_calculate_base (0, 0, 0, &base);
  TEST_ASSERT (result == QPACK_OK, "Should succeed");
  TEST_ASSERT (base == 0, "Base should be 0");

  printf ("PASS\n");
}

/**
 * Test large DeltaBase values (variable-length integer encoding limits).
 */
static void
test_base_large_delta (void)
{
  int32_t base;
  SocketQPACK_Result result;

  printf ("  Large DeltaBase values... ");

  /* Large forward delta: Base = 1000 + 500000 = 500001000 (invalid due to
   * overflow) */
  /* Actually, let's use values that fit */
  uint32_t large_req = 1000000;
  int32_t large_delta = 500000;

  /* Sign=0: Base = 1000000 + 500000 = 1500000 */
  result = SocketQPACK_calculate_base (large_req, large_delta, 0, &base);
  TEST_ASSERT (result == QPACK_OK, "Should succeed with large values");
  TEST_ASSERT (base == 1500000, "Base should be 1500000");

  /* Sign=1: Base = 1000000 - 500000 - 1 = 499999 */
  result = SocketQPACK_calculate_base (large_req, large_delta, 1, &base);
  TEST_ASSERT (result == QPACK_OK, "Should succeed");
  TEST_ASSERT (base == 499999, "Base should be 499999");

  printf ("PASS\n");
}

/**
 * Test maximum valid Base at INT32_MAX boundary.
 */
static void
test_base_max_boundary (void)
{
  int32_t base;
  SocketQPACK_Result result;

  printf ("  Maximum Base boundary... ");

  /* Just under INT32_MAX */
  uint32_t large_req = 2000000000;
  int32_t delta = 147483647; /* So sum = 2147483647 = INT32_MAX */

  result = SocketQPACK_calculate_base (large_req, delta, 0, &base);
  TEST_ASSERT (result == QPACK_OK, "Should succeed at INT32_MAX");
  TEST_ASSERT (base == INT32_MAX, "Base should be INT32_MAX");

  printf ("PASS\n");
}

/**
 * Test overflow detection in Base calculation.
 */
static void
test_base_overflow (void)
{
  int32_t base;
  SocketQPACK_Result result;

  printf ("  Overflow detection... ");

  /* Overflow case: very large values that would exceed INT32_MAX */
  uint32_t req = 2147483647; /* INT32_MAX */
  int32_t delta = 1;         /* Would overflow */

  result = SocketQPACK_calculate_base (req, delta, 0, &base);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_BASE, "Should detect overflow");

  printf ("PASS\n");
}

/* ============================================================================
 * Base Validation Tests
 * ============================================================================
 */

/**
 * Test SocketQPACK_validate_base function.
 */
static void
test_validate_base (void)
{
  SocketQPACK_Result result;

  printf ("  Base validation function... ");

  /* Valid cases */
  result = SocketQPACK_validate_base (10, 5, 0);
  TEST_ASSERT (result == QPACK_OK, "Should validate Sign=0 case");

  result = SocketQPACK_validate_base (10, 5, 1);
  TEST_ASSERT (result == QPACK_OK,
               "Should validate Sign=1 when ReqInsertCount > DeltaBase");

  /* Invalid sign */
  result = SocketQPACK_validate_base (10, 5, 2);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_BASE,
               "Should reject invalid sign");

  result = SocketQPACK_validate_base (10, 5, -1);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_BASE,
               "Should reject negative sign");

  /* Invalid Sign=1 constraint */
  result = SocketQPACK_validate_base (5, 5, 1);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_BASE,
               "Should reject equal values with Sign=1");

  /* Negative delta_base */
  result = SocketQPACK_validate_base (10, -1, 0);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_BASE,
               "Should reject negative delta_base");

  printf ("PASS\n");
}

/* ============================================================================
 * Base Prefix Parsing Tests
 * ============================================================================
 */

/**
 * Test parsing Base prefix with Sign=0 and small DeltaBase.
 */
static void
test_parse_base_prefix_sign_zero (void)
{
  SocketQPACK_Base_T base_calc;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Parse Base prefix with Sign=0... ");

  /* Sign=0, DeltaBase=5 -> byte = 0x05 */
  unsigned char data[] = { 0x05 };

  result = SocketQPACK_parse_base_prefix (
      data, sizeof (data), 10, &base_calc, &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should parse successfully");
  TEST_ASSERT (consumed == 1, "Should consume 1 byte");
  TEST_ASSERT (base_calc.sign == 0, "Sign should be 0");
  TEST_ASSERT (base_calc.delta_base == 5, "DeltaBase should be 5");
  TEST_ASSERT (base_calc.req_insert_count == 10, "ReqInsertCount should be 10");
  TEST_ASSERT (base_calc.base == 15, "Base should be 15");

  printf ("PASS\n");
}

/**
 * Test parsing Base prefix with Sign=1 and small DeltaBase.
 */
static void
test_parse_base_prefix_sign_one (void)
{
  SocketQPACK_Base_T base_calc;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Parse Base prefix with Sign=1... ");

  /* Sign=1, DeltaBase=3 -> byte = 0x80 | 0x03 = 0x83 */
  unsigned char data[] = { 0x83 };

  result = SocketQPACK_parse_base_prefix (
      data, sizeof (data), 10, &base_calc, &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should parse successfully");
  TEST_ASSERT (consumed == 1, "Should consume 1 byte");
  TEST_ASSERT (base_calc.sign == 1, "Sign should be 1");
  TEST_ASSERT (base_calc.delta_base == 3, "DeltaBase should be 3");
  TEST_ASSERT (base_calc.req_insert_count == 10, "ReqInsertCount should be 10");
  TEST_ASSERT (base_calc.base == 6, "Base should be 6 (10 - 3 - 1)");

  printf ("PASS\n");
}

/**
 * Test parsing Base prefix with multi-byte DeltaBase.
 */
static void
test_parse_base_prefix_multibyte (void)
{
  SocketQPACK_Base_T base_calc;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Parse Base prefix with multi-byte DeltaBase... ");

  /* Sign=0, DeltaBase=200
   * 200 > 127 (7-bit max), so needs continuation
   * First byte: 0x7F (127 = 2^7 - 1)
   * Second byte: 200 - 127 = 73 = 0x49 (no continuation bit) */
  unsigned char data[] = { 0x7F, 0x49 };

  result = SocketQPACK_parse_base_prefix (
      data, sizeof (data), 100, &base_calc, &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should parse multi-byte successfully");
  TEST_ASSERT (consumed == 2, "Should consume 2 bytes");
  TEST_ASSERT (base_calc.sign == 0, "Sign should be 0");
  TEST_ASSERT (base_calc.delta_base == 200, "DeltaBase should be 200");
  TEST_ASSERT (base_calc.base == 300, "Base should be 300");

  printf ("PASS\n");
}

/**
 * Test parsing with incomplete data.
 */
static void
test_parse_base_prefix_incomplete (void)
{
  SocketQPACK_Base_T base_calc;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Parse Base prefix with incomplete data... ");

  /* Empty buffer */
  result = SocketQPACK_parse_base_prefix (NULL, 0, 10, &base_calc, &consumed);
  TEST_ASSERT (result == QPACK_ERROR, "Should fail with NULL input");

  unsigned char data[] = { 0x7F }; /* Needs continuation but none provided */
  result = SocketQPACK_parse_base_prefix (
      data, sizeof (data), 10, &base_calc, &consumed);
  TEST_ASSERT (result == QPACK_INCOMPLETE, "Should return INCOMPLETE");

  printf ("PASS\n");
}

/**
 * Test parsing that results in invalid Base.
 */
static void
test_parse_base_prefix_invalid (void)
{
  SocketQPACK_Base_T base_calc;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Parse Base prefix with invalid result... ");

  /* Sign=1, DeltaBase=10, ReqInsertCount=5
   * Would give Base = 5 - 10 - 1 = -6, which is invalid
   * But validation catches ReqInsertCount <= DeltaBase first */
  unsigned char data[] = { 0x8A }; /* Sign=1, DeltaBase=10 */

  result = SocketQPACK_parse_base_prefix (
      data, sizeof (data), 5, &base_calc, &consumed);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_BASE,
               "Should reject invalid base calculation");

  printf ("PASS\n");
}

/* ============================================================================
 * Base Prefix Encoding Tests
 * ============================================================================
 */

/**
 * Test encoding Base prefix with Sign=0.
 */
static void
test_encode_base_prefix_sign_zero (void)
{
  unsigned char output[16];
  int len;

  printf ("  Encode Base prefix with Sign=0... ");

  /* Base=15, ReqInsertCount=10 -> Sign=0, DeltaBase=5 */
  len = SocketQPACK_encode_base_prefix (15, 10, output, sizeof (output));
  TEST_ASSERT (len == 1, "Should encode to 1 byte");
  TEST_ASSERT ((output[0] & 0x80) == 0, "Sign bit should be 0");
  TEST_ASSERT ((output[0] & 0x7F) == 5, "DeltaBase should be 5");

  /* Base=100, ReqInsertCount=100 -> Sign=0, DeltaBase=0 */
  len = SocketQPACK_encode_base_prefix (100, 100, output, sizeof (output));
  TEST_ASSERT (len == 1, "Should encode to 1 byte");
  TEST_ASSERT (output[0] == 0x00, "Should be 0x00 (Sign=0, DeltaBase=0)");

  printf ("PASS\n");
}

/**
 * Test encoding Base prefix with Sign=1.
 */
static void
test_encode_base_prefix_sign_one (void)
{
  unsigned char output[16];
  int len;

  printf ("  Encode Base prefix with Sign=1... ");

  /* Base=5, ReqInsertCount=10 -> Sign=1, DeltaBase = 10 - 5 - 1 = 4 */
  len = SocketQPACK_encode_base_prefix (5, 10, output, sizeof (output));
  TEST_ASSERT (len == 1, "Should encode to 1 byte");
  TEST_ASSERT ((output[0] & 0x80) == 0x80, "Sign bit should be 1");
  TEST_ASSERT ((output[0] & 0x7F) == 4, "DeltaBase should be 4");

  printf ("PASS\n");
}

/**
 * Test encoding with multi-byte DeltaBase.
 */
static void
test_encode_base_prefix_multibyte (void)
{
  unsigned char output[16];
  int len;

  printf ("  Encode Base prefix with multi-byte DeltaBase... ");

  /* Base=300, ReqInsertCount=100 -> Sign=0, DeltaBase=200 */
  len = SocketQPACK_encode_base_prefix (300, 100, output, sizeof (output));
  TEST_ASSERT (len == 2, "Should encode to 2 bytes");
  TEST_ASSERT ((output[0] & 0x80) == 0, "Sign bit should be 0");

  /* Verify round-trip */
  SocketQPACK_Base_T base_calc;
  size_t consumed;
  SocketQPACK_Result result = SocketQPACK_parse_base_prefix (
      output, (size_t)len, 100, &base_calc, &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should parse encoded data");
  TEST_ASSERT (base_calc.base == 300, "Round-trip should preserve Base");

  printf ("PASS\n");
}

/**
 * Test encoding/decoding round-trip for various values.
 */
static void
test_encode_decode_roundtrip (void)
{
  unsigned char output[16];
  int len;
  SocketQPACK_Base_T base_calc;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Encode/decode round-trip... ");

  /* Test several cases */
  struct
  {
    int32_t base;
    uint32_t req_insert_count;
  } test_cases[] = {
    { 0, 0 },      /* Zero values */
    { 10, 5 },     /* Base > ReqInsertCount (Sign=0) */
    { 5, 10 },     /* Base < ReqInsertCount (Sign=1) */
    { 100, 100 },  /* Equal (Sign=0, DeltaBase=0) */
    { 1000, 500 }, /* Large Sign=0 */
    { 500, 1000 }, /* Large Sign=1 */
    { 0, 100 },    /* Base=0 with non-zero req */
  };

  size_t num_cases = sizeof (test_cases) / sizeof (test_cases[0]);

  for (size_t i = 0; i < num_cases; i++)
    {
      int32_t orig_base = test_cases[i].base;
      uint32_t req = test_cases[i].req_insert_count;

      len = SocketQPACK_encode_base_prefix (
          orig_base, req, output, sizeof (output));
      TEST_ASSERT (len > 0, "Encoding should succeed");

      result = SocketQPACK_parse_base_prefix (
          output, (size_t)len, req, &base_calc, &consumed);
      TEST_ASSERT (result == QPACK_OK, "Decoding should succeed");
      TEST_ASSERT (base_calc.base == orig_base,
                   "Round-trip should preserve Base");
      TEST_ASSERT ((size_t)len == consumed, "Should consume all encoded bytes");
    }

  printf ("PASS\n");
}

/* ============================================================================
 * Result String Tests
 * ============================================================================
 */

/**
 * Test result string function.
 */
static void
test_result_strings (void)
{
  printf ("  Result string function... ");

  TEST_ASSERT (strcmp (SocketQPACK_result_string (QPACK_OK), "OK") == 0,
               "QPACK_OK string should be 'OK'");
  TEST_ASSERT (
      strstr (SocketQPACK_result_string (QPACK_ERROR_INVALID_BASE), "Base")
          != NULL,
      "INVALID_BASE string should mention 'Base'");
  TEST_ASSERT (strcmp (SocketQPACK_result_string ((SocketQPACK_Result)999),
                       "Unknown error")
                   == 0,
               "Unknown result should return 'Unknown error'");

  printf ("PASS\n");
}

/* ============================================================================
 * Indexed Field Line Use Cases
 * ============================================================================
 */

/**
 * Test Base calculation for indexed field line scenarios.
 * RFC 9204 Section 4.5.2 and 4.5.3 use Base for index resolution.
 */
static void
test_base_indexed_use_cases (void)
{
  int32_t base;
  SocketQPACK_Result result;

  printf ("  Base use cases for indexed fields... ");

  /* Case 1: Indexed with Incremental Indexing
   * Encoder uses entries up to Base for indexed references */
  result = SocketQPACK_calculate_base (50, 10, 0, &base);
  TEST_ASSERT (result == QPACK_OK, "Case 1 should succeed");
  TEST_ASSERT (base == 60, "Base for indexed should be 60");

  /* Case 2: Literal with Incremental Indexing
   * Can reference entries up to Base for name index */
  result = SocketQPACK_calculate_base (100, 0, 0, &base);
  TEST_ASSERT (result == QPACK_OK, "Case 2 should succeed");
  TEST_ASSERT (base == 100, "Base equals ReqInsertCount when DeltaBase=0");

  /* Case 3: Literal without Indexing
   * Same Base calculation applies */
  result = SocketQPACK_calculate_base (25, 5, 1, &base);
  TEST_ASSERT (result == QPACK_OK, "Case 3 should succeed");
  TEST_ASSERT (base == 19, "Base should be 19 (25 - 5 - 1)");

  printf ("PASS\n");
}

/**
 * Test Base at MaxEntries capacity boundary.
 */
static void
test_base_capacity_boundary (void)
{
  int32_t base;
  SocketQPACK_Result result;

  printf ("  Base at capacity boundary... ");

  /* Typical QPACK dynamic table max entries might be around 1000-4096
   * Test with values at these boundaries */
  uint32_t max_entries = 4096;

  /* ReqInsertCount at max_entries */
  result = SocketQPACK_calculate_base (max_entries, 0, 0, &base);
  TEST_ASSERT (result == QPACK_OK, "Should work at capacity");
  TEST_ASSERT (base == (int32_t)max_entries, "Base should equal max_entries");

  /* ReqInsertCount past max_entries (wrapping scenario) */
  result = SocketQPACK_calculate_base (max_entries + 100, 50, 1, &base);
  TEST_ASSERT (result == QPACK_OK, "Should work past capacity");
  TEST_ASSERT (base == (int32_t)(max_entries + 100 - 50 - 1),
               "Base calculation correct");

  printf ("PASS\n");
}

/* ============================================================================
 * NULL Pointer Tests
 * ============================================================================
 */

/**
 * Test NULL pointer handling.
 */
static void
test_null_pointers (void)
{
  int32_t base;
  SocketQPACK_Result result;
  SocketQPACK_Base_T base_calc;
  size_t consumed;
  unsigned char buf[16];

  printf ("  NULL pointer handling... ");

  /* calculate_base with NULL output */
  result = SocketQPACK_calculate_base (10, 5, 0, NULL);
  TEST_ASSERT (result == QPACK_ERROR, "Should reject NULL base_out");

  /* parse_base_prefix with NULL parameters */
  result = SocketQPACK_parse_base_prefix (NULL, 1, 10, &base_calc, &consumed);
  TEST_ASSERT (result == QPACK_ERROR, "Should reject NULL input");

  unsigned char data[] = { 0x05 };
  result = SocketQPACK_parse_base_prefix (
      data, sizeof (data), 10, NULL, &consumed);
  TEST_ASSERT (result == QPACK_ERROR, "Should reject NULL base_out");

  result = SocketQPACK_parse_base_prefix (
      data, sizeof (data), 10, &base_calc, NULL);
  TEST_ASSERT (result == QPACK_ERROR, "Should reject NULL consumed");

  /* encode_base_prefix with NULL output */
  int len = SocketQPACK_encode_base_prefix (10, 5, NULL, 16);
  TEST_ASSERT (len == -1, "Should reject NULL output");

  /* Zero output size */
  len = SocketQPACK_encode_base_prefix (10, 5, buf, 0);
  TEST_ASSERT (len == -1, "Should reject zero output size");

  printf ("PASS\n");
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================
 */

int
main (void)
{
  printf ("QPACK Base Encoding Tests (RFC 9204 Section 4.5.1.2)\n");
  printf ("=====================================================\n\n");

  printf ("Base Calculation Tests:\n");
  test_base_sign_zero ();
  test_base_sign_one ();
  test_base_reject_negative ();
  test_base_sign_one_constraint ();
  test_base_zero_values ();
  test_base_large_delta ();
  test_base_max_boundary ();
  test_base_overflow ();

  printf ("\nBase Validation Tests:\n");
  test_validate_base ();

  printf ("\nBase Prefix Parsing Tests:\n");
  test_parse_base_prefix_sign_zero ();
  test_parse_base_prefix_sign_one ();
  test_parse_base_prefix_multibyte ();
  test_parse_base_prefix_incomplete ();
  test_parse_base_prefix_invalid ();

  printf ("\nBase Prefix Encoding Tests:\n");
  test_encode_base_prefix_sign_zero ();
  test_encode_base_prefix_sign_one ();
  test_encode_base_prefix_multibyte ();
  test_encode_decode_roundtrip ();

  printf ("\nUse Case Tests:\n");
  test_base_indexed_use_cases ();
  test_base_capacity_boundary ();

  printf ("\nMiscellaneous Tests:\n");
  test_result_strings ();
  test_null_pointers ();

  printf ("\n=====================================================\n");
  printf ("All QPACK Base encoding tests passed!\n");

  return 0;
}
