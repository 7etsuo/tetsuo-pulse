/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_base.c
 * @brief Unit tests for QPACK Base Encoding (RFC 9204 Section 4.5.1.2)
 *
 * Tests the Base calculation, validation, and encoding functions per RFC 9204.
 */

#include <stdint.h>
#include <string.h>

#include "http/qpack/SocketQPACK.h"
#include "test/Test.h"

/* ============================================================================
 * CALCULATE BASE - NULL PARAMETER TESTS
 * ============================================================================
 */

TEST (qpack_calculate_base_null_output)
{
  SocketQPACK_Result result = SocketQPACK_calculate_base (0, 10, 5, NULL);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

/* ============================================================================
 * CALCULATE BASE - POSITIVE DELTA (Sign = 0)
 * ============================================================================
 */

TEST (qpack_calculate_base_positive_delta_zero)
{
  uint64_t base = 999;
  SocketQPACK_Result result = SocketQPACK_calculate_base (0, 10, 0, &base);
  ASSERT_EQ (result, QPACK_OK);
  /* Sign=0, RIC=10, Delta=0 -> Base = 10 + 0 = 10 */
  ASSERT_EQ (base, 10);
}

TEST (qpack_calculate_base_positive_delta_simple)
{
  uint64_t base = 0;
  SocketQPACK_Result result = SocketQPACK_calculate_base (0, 10, 5, &base);
  ASSERT_EQ (result, QPACK_OK);
  /* Sign=0, RIC=10, Delta=5 -> Base = 10 + 5 = 15 */
  ASSERT_EQ (base, 15);
}

TEST (qpack_calculate_base_positive_delta_ric_zero)
{
  uint64_t base = 999;
  SocketQPACK_Result result = SocketQPACK_calculate_base (0, 0, 0, &base);
  ASSERT_EQ (result, QPACK_OK);
  /* Sign=0, RIC=0, Delta=0 -> Base = 0 + 0 = 0 */
  ASSERT_EQ (base, 0);
}

TEST (qpack_calculate_base_positive_delta_large_values)
{
  uint64_t base = 0;
  SocketQPACK_Result result
      = SocketQPACK_calculate_base (0, 1000000, 500000, &base);
  ASSERT_EQ (result, QPACK_OK);
  /* Sign=0, RIC=1000000, Delta=500000 -> Base = 1500000 */
  ASSERT_EQ (base, 1500000);
}

TEST (qpack_calculate_base_positive_delta_overflow)
{
  uint64_t base = 999;
  /* Try to overflow: RIC + Delta > UINT64_MAX */
  SocketQPACK_Result result
      = SocketQPACK_calculate_base (0, UINT64_MAX, 1, &base);
  ASSERT_EQ (result, QPACK_ERR_BASE_OVERFLOW);
}

TEST (qpack_calculate_base_positive_delta_max_no_overflow)
{
  uint64_t base = 0;
  /* RIC + Delta = UINT64_MAX (no overflow) */
  SocketQPACK_Result result
      = SocketQPACK_calculate_base (0, UINT64_MAX - 1, 1, &base);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (base, UINT64_MAX);
}

/* ============================================================================
 * CALCULATE BASE - NEGATIVE DELTA (Sign = 1)
 * ============================================================================
 */

TEST (qpack_calculate_base_negative_delta_simple)
{
  uint64_t base = 999;
  SocketQPACK_Result result = SocketQPACK_calculate_base (1, 10, 4, &base);
  ASSERT_EQ (result, QPACK_OK);
  /* Sign=1, RIC=10, Delta=4 -> Base = 10 - 4 - 1 = 5 */
  ASSERT_EQ (base, 5);
}

TEST (qpack_calculate_base_negative_delta_zero)
{
  uint64_t base = 999;
  SocketQPACK_Result result = SocketQPACK_calculate_base (1, 10, 0, &base);
  ASSERT_EQ (result, QPACK_OK);
  /* Sign=1, RIC=10, Delta=0 -> Base = 10 - 0 - 1 = 9 */
  ASSERT_EQ (base, 9);
}

TEST (qpack_calculate_base_negative_delta_base_zero)
{
  uint64_t base = 999;
  SocketQPACK_Result result = SocketQPACK_calculate_base (1, 5, 4, &base);
  ASSERT_EQ (result, QPACK_OK);
  /* Sign=1, RIC=5, Delta=4 -> Base = 5 - 4 - 1 = 0 */
  ASSERT_EQ (base, 0);
}

TEST (qpack_calculate_base_negative_delta_invalid_underflow)
{
  uint64_t base = 999;
  /* Sign=1, RIC=5, Delta=5 -> Base = 5 - 5 - 1 = -1 (underflow) */
  SocketQPACK_Result result = SocketQPACK_calculate_base (1, 5, 5, &base);
  ASSERT_EQ (result, QPACK_ERR_INVALID_BASE);
}

TEST (qpack_calculate_base_negative_delta_ric_equals_delta)
{
  uint64_t base = 999;
  /* Sign=1, RIC=10, Delta=10 -> Invalid (RIC <= Delta) */
  SocketQPACK_Result result = SocketQPACK_calculate_base (1, 10, 10, &base);
  ASSERT_EQ (result, QPACK_ERR_INVALID_BASE);
}

TEST (qpack_calculate_base_negative_delta_ric_less_than_delta)
{
  uint64_t base = 999;
  /* Sign=1, RIC=5, Delta=10 -> Invalid (RIC < Delta) */
  SocketQPACK_Result result = SocketQPACK_calculate_base (1, 5, 10, &base);
  ASSERT_EQ (result, QPACK_ERR_INVALID_BASE);
}

TEST (qpack_calculate_base_negative_delta_ric_zero)
{
  uint64_t base = 999;
  /* Sign=1, RIC=0, Delta=0 -> Invalid (RIC <= Delta) */
  SocketQPACK_Result result = SocketQPACK_calculate_base (1, 0, 0, &base);
  ASSERT_EQ (result, QPACK_ERR_INVALID_BASE);
}

TEST (qpack_calculate_base_negative_delta_large_values)
{
  uint64_t base = 0;
  /* Sign=1, RIC=1000000, Delta=500000 -> Base = 1000000 - 500000 - 1 = 499999
   */
  SocketQPACK_Result result
      = SocketQPACK_calculate_base (1, 1000000, 500000, &base);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (base, 499999);
}

/* ============================================================================
 * VALIDATE BASE TESTS
 * ============================================================================
 */

TEST (qpack_validate_base_positive_valid)
{
  /* Sign=0, RIC=10, Delta=5: valid */
  SocketQPACK_Result result = SocketQPACK_validate_base (0, 10, 5);
  ASSERT_EQ (result, QPACK_OK);
}

TEST (qpack_validate_base_positive_overflow)
{
  /* Sign=0, RIC=UINT64_MAX, Delta=1: overflow */
  SocketQPACK_Result result = SocketQPACK_validate_base (0, UINT64_MAX, 1);
  ASSERT_EQ (result, QPACK_ERR_INVALID_BASE);
}

TEST (qpack_validate_base_negative_valid)
{
  /* Sign=1, RIC=10, Delta=4: valid (10 > 4) */
  SocketQPACK_Result result = SocketQPACK_validate_base (1, 10, 4);
  ASSERT_EQ (result, QPACK_OK);
}

TEST (qpack_validate_base_negative_equal)
{
  /* Sign=1, RIC=10, Delta=10: invalid (10 <= 10) */
  SocketQPACK_Result result = SocketQPACK_validate_base (1, 10, 10);
  ASSERT_EQ (result, QPACK_ERR_INVALID_BASE);
}

TEST (qpack_validate_base_negative_underflow)
{
  /* Sign=1, RIC=5, Delta=10: invalid (5 < 10) */
  SocketQPACK_Result result = SocketQPACK_validate_base (1, 5, 10);
  ASSERT_EQ (result, QPACK_ERR_INVALID_BASE);
}

TEST (qpack_validate_base_negative_boundary)
{
  /* Sign=1, RIC=5, Delta=4: valid, Base = 0 */
  SocketQPACK_Result result = SocketQPACK_validate_base (1, 5, 4);
  ASSERT_EQ (result, QPACK_OK);
}

/* ============================================================================
 * ENCODE BASE TESTS
 * ============================================================================
 */

TEST (qpack_encode_base_null_sign)
{
  uint64_t delta = 0;
  SocketQPACK_Result result = SocketQPACK_encode_base (10, 15, NULL, &delta);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_encode_base_null_delta)
{
  int sign = 0;
  SocketQPACK_Result result = SocketQPACK_encode_base (10, 15, &sign, NULL);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_encode_base_positive_delta)
{
  int sign = 999;
  uint64_t delta = 999;
  /* RIC=10, Base=15 -> Sign=0 (Base >= RIC), Delta = 15 - 10 = 5 */
  SocketQPACK_Result result = SocketQPACK_encode_base (10, 15, &sign, &delta);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (sign, 0);
  ASSERT_EQ (delta, 5);
}

TEST (qpack_encode_base_negative_delta)
{
  int sign = 999;
  uint64_t delta = 999;
  /* RIC=10, Base=5 -> Sign=1 (Base < RIC), Delta = 10 - 5 - 1 = 4 */
  SocketQPACK_Result result = SocketQPACK_encode_base (10, 5, &sign, &delta);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (sign, 1);
  ASSERT_EQ (delta, 4);
}

TEST (qpack_encode_base_equal)
{
  int sign = 999;
  uint64_t delta = 999;
  /* RIC=10, Base=10 -> Sign=0 (Base >= RIC), Delta = 10 - 10 = 0 */
  SocketQPACK_Result result = SocketQPACK_encode_base (10, 10, &sign, &delta);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (sign, 0);
  ASSERT_EQ (delta, 0);
}

TEST (qpack_encode_base_zero_zero)
{
  int sign = 999;
  uint64_t delta = 999;
  /* RIC=0, Base=0 -> Sign=0, Delta=0 */
  SocketQPACK_Result result = SocketQPACK_encode_base (0, 0, &sign, &delta);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (sign, 0);
  ASSERT_EQ (delta, 0);
}

TEST (qpack_encode_base_base_zero)
{
  int sign = 999;
  uint64_t delta = 999;
  /* RIC=5, Base=0 -> Sign=1 (Base < RIC), Delta = 5 - 0 - 1 = 4 */
  SocketQPACK_Result result = SocketQPACK_encode_base (5, 0, &sign, &delta);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (sign, 1);
  ASSERT_EQ (delta, 4);
}

TEST (qpack_encode_base_ric_zero)
{
  int sign = 999;
  uint64_t delta = 999;
  /* RIC=0, Base=5 -> Sign=0 (Base >= RIC), Delta = 5 - 0 = 5 */
  SocketQPACK_Result result = SocketQPACK_encode_base (0, 5, &sign, &delta);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (sign, 0);
  ASSERT_EQ (delta, 5);
}

TEST (qpack_encode_base_large_values)
{
  int sign = 0;
  uint64_t delta = 0;
  /* RIC=1000000, Base=1500000 -> Sign=0, Delta=500000 */
  SocketQPACK_Result result
      = SocketQPACK_encode_base (1000000, 1500000, &sign, &delta);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (sign, 0);
  ASSERT_EQ (delta, 500000);
}

/* ============================================================================
 * ROUND-TRIP TESTS
 * ============================================================================
 */

TEST (qpack_base_roundtrip_positive)
{
  int sign = 0;
  uint64_t delta = 0;
  uint64_t base_out = 0;

  /* Encode: RIC=42, Base=50 */
  SocketQPACK_Result result = SocketQPACK_encode_base (42, 50, &sign, &delta);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (sign, 0);
  ASSERT_EQ (delta, 8);

  /* Decode */
  result = SocketQPACK_calculate_base (sign, 42, delta, &base_out);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (base_out, 50);
}

TEST (qpack_base_roundtrip_negative)
{
  int sign = 0;
  uint64_t delta = 0;
  uint64_t base_out = 0;

  /* Encode: RIC=42, Base=30 */
  SocketQPACK_Result result = SocketQPACK_encode_base (42, 30, &sign, &delta);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (sign, 1);
  ASSERT_EQ (delta, 11); /* 42 - 30 - 1 = 11 */

  /* Decode */
  result = SocketQPACK_calculate_base (sign, 42, delta, &base_out);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (base_out, 30);
}

TEST (qpack_base_roundtrip_equal)
{
  int sign = 0;
  uint64_t delta = 0;
  uint64_t base_out = 0;

  /* Encode: RIC=100, Base=100 */
  SocketQPACK_Result result = SocketQPACK_encode_base (100, 100, &sign, &delta);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (sign, 0);
  ASSERT_EQ (delta, 0);

  /* Decode */
  result = SocketQPACK_calculate_base (sign, 100, delta, &base_out);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (base_out, 100);
}

TEST (qpack_base_roundtrip_zero_base)
{
  int sign = 0;
  uint64_t delta = 0;
  uint64_t base_out = 999;

  /* Encode: RIC=10, Base=0 */
  SocketQPACK_Result result = SocketQPACK_encode_base (10, 0, &sign, &delta);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (sign, 1);
  ASSERT_EQ (delta, 9); /* 10 - 0 - 1 = 9 */

  /* Decode */
  result = SocketQPACK_calculate_base (sign, 10, delta, &base_out);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (base_out, 0);
}

/* ============================================================================
 * RESULT STRING TESTS
 * ============================================================================
 */

TEST (qpack_result_string_invalid_base)
{
  const char *str = SocketQPACK_result_string (QPACK_ERR_INVALID_BASE);
  ASSERT_NOT_NULL (str);
  ASSERT (str[0] != '\0');
}

/* ============================================================================
 * MAIN
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
