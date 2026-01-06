/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_index.c
 * @brief Unit tests for QPACK index conversion (RFC 9204 Sections 3.2.4-3.2.6).
 *
 * Tests cover:
 * - NULL parameter handling (hardened security)
 * - RFC 9204 Appendix B test vectors
 * - RFC 9204 Figure 2, 3, 4 examples
 * - Edge cases (empty table, invalid state)
 * - Large index handling
 */

#include "http/qpack/SocketQPACK.h"
#include "test/Test.h"

#include <stdint.h>
#include <stdio.h>

/* ============================================================================
 * NULL PARAMETER HANDLING TESTS (Security Hardening)
 * ============================================================================
 */

TEST (qpack_null_param_abs_to_relative_encoder)
{
  SocketQPACK_Result result;

  /* NULL output pointer should return QPACK_ERR_NULL_PARAM, not crash */
  result = SocketQPACK_abs_to_relative_encoder (10, 5, NULL);
  ASSERT_EQ (QPACK_ERR_NULL_PARAM, result);
}

TEST (qpack_null_param_relative_to_abs_encoder)
{
  SocketQPACK_Result result;

  result = SocketQPACK_relative_to_abs_encoder (10, 5, NULL);
  ASSERT_EQ (QPACK_ERR_NULL_PARAM, result);
}

TEST (qpack_null_param_abs_to_relative_field)
{
  SocketQPACK_Result result;

  result = SocketQPACK_abs_to_relative_field (10, 5, NULL);
  ASSERT_EQ (QPACK_ERR_NULL_PARAM, result);
}

TEST (qpack_null_param_relative_to_abs_field)
{
  SocketQPACK_Result result;

  result = SocketQPACK_relative_to_abs_field (10, 5, NULL);
  ASSERT_EQ (QPACK_ERR_NULL_PARAM, result);
}

TEST (qpack_null_param_abs_to_postbase)
{
  SocketQPACK_Result result;

  result = SocketQPACK_abs_to_postbase (5, 10, NULL);
  ASSERT_EQ (QPACK_ERR_NULL_PARAM, result);
}

TEST (qpack_null_param_postbase_to_abs)
{
  SocketQPACK_Result result;

  result = SocketQPACK_postbase_to_abs (5, 5, NULL);
  ASSERT_EQ (QPACK_ERR_NULL_PARAM, result);
}

/* ============================================================================
 * RFC 9204 FIGURE 2 - ENCODER RELATIVE INDEXING EXAMPLES
 * ============================================================================
 *
 * RFC 9204 Figure 2 shows encoder stream relative indexing with insert_count=4:
 *
 *      +-----+---------------+-------+
 *      | n=4 |      foo      |   0   |  <-- Most recent (relative 0)
 *      +-----+---------------+-------+
 *      | n=3 |      bar      |   1   |
 *      +-----+---------------+-------+
 *      | n=2 |      baz      |   2   |
 *      +-----+---------------+-------+
 *      | n=1 |      qux      |   3   |  <-- Oldest (relative 3)
 *      +-----+---------------+-------+
 *            Absolute Index    Relative Index
 *
 * Note: The RFC uses 1-based absolute indices in examples, but implementation
 * uses 0-based (entry 0 has absolute index 0).
 */
TEST (qpack_rfc_figure2_encoder_indexing)
{
  SocketQPACK_Result result;
  uint64_t output;

  /* With insert_count=4:
   * - Absolute 3 -> Relative 0 (most recent)
   * - Absolute 2 -> Relative 1
   * - Absolute 1 -> Relative 2
   * - Absolute 0 -> Relative 3 (oldest)
   */
  result = SocketQPACK_abs_to_relative_encoder (4, 3, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (0, output);

  result = SocketQPACK_abs_to_relative_encoder (4, 2, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (1, output);

  result = SocketQPACK_abs_to_relative_encoder (4, 1, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (2, output);

  result = SocketQPACK_abs_to_relative_encoder (4, 0, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (3, output);

  /* Reverse conversions */
  result = SocketQPACK_relative_to_abs_encoder (4, 0, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (3, output);

  result = SocketQPACK_relative_to_abs_encoder (4, 3, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (0, output);
}

/* ============================================================================
 * RFC 9204 FIGURE 3 - FIELD SECTION RELATIVE INDEXING EXAMPLES
 * ============================================================================
 *
 * RFC 9204 Figure 3 shows field section relative indexing with Base=2:
 *
 *      +-----+---------------+-------+
 *      | n=4 |      foo      |  N/A  |  <-- Post-base (use post-base indexing)
 *      +-----+---------------+-------+
 *      | n=3 |      bar      |  N/A  |  <-- Post-base
 *      +-----+---------------+-------+
 *      | n=2 |      baz      |   0   |  <-- Base-1 (relative 0)
 *      +-----+---------------+-------+
 *      | n=1 |      qux      |   1   |  <-- Oldest visible (relative 1)
 *      +-----+---------------+-------+
 *            Absolute Index    Relative Index (Base=2)
 */
TEST (qpack_rfc_figure3_field_indexing)
{
  SocketQPACK_Result result;
  uint64_t output;

  /* With base=2 (0-indexed, so entries 0 and 1 are visible):
   * - Absolute 1 -> Relative 0
   * - Absolute 0 -> Relative 1
   */
  result = SocketQPACK_abs_to_relative_field (2, 1, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (0, output);

  result = SocketQPACK_abs_to_relative_field (2, 0, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (1, output);

  /* Entries at or above base should fail */
  result = SocketQPACK_abs_to_relative_field (2, 2, &output);
  ASSERT_EQ (QPACK_ERR_INVALID_INDEX, result);

  result = SocketQPACK_abs_to_relative_field (2, 3, &output);
  ASSERT_EQ (QPACK_ERR_INVALID_INDEX, result);
}

/* ============================================================================
 * RFC 9204 FIGURE 4 - POST-BASE INDEXING EXAMPLES
 * ============================================================================
 *
 * RFC 9204 Figure 4 shows post-base indexing with Base=2:
 *
 *      +-----+---------------+-------+
 *      | n=4 |      foo      |   1   |  <-- Post-base 1
 *      +-----+---------------+-------+
 *      | n=3 |      bar      |   0   |  <-- Post-base 0 (at Base)
 *      +-----+---------------+-------+
 *      | n=2 |      baz      |  N/A  |  <-- Use relative indexing
 *      +-----+---------------+-------+
 *      | n=1 |      qux      |  N/A  |
 *      +-----+---------------+-------+
 *            Absolute Index    Post-Base Index (Base=2)
 */
TEST (qpack_rfc_figure4_postbase_indexing)
{
  SocketQPACK_Result result;
  uint64_t output;

  /* With base=2:
   * - Absolute 2 -> Post-base 0
   * - Absolute 3 -> Post-base 1
   * - Absolute 4 -> Post-base 2
   */
  result = SocketQPACK_abs_to_postbase (2, 2, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (0, output);

  result = SocketQPACK_abs_to_postbase (2, 3, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (1, output);

  result = SocketQPACK_abs_to_postbase (2, 4, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (2, output);

  /* Entries below base should fail */
  result = SocketQPACK_abs_to_postbase (2, 1, &output);
  ASSERT_EQ (QPACK_ERR_INVALID_INDEX, result);

  result = SocketQPACK_abs_to_postbase (2, 0, &output);
  ASSERT_EQ (QPACK_ERR_INVALID_INDEX, result);

  /* Reverse conversions */
  result = SocketQPACK_postbase_to_abs (2, 0, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (2, output);

  result = SocketQPACK_postbase_to_abs (2, 1, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (3, output);
}

/* ============================================================================
 * RFC 9204 APPENDIX B - ENCODED STREAM TEST VECTORS
 * ============================================================================
 *
 * These tests verify index conversions match the examples in RFC 9204 Appendix B.
 */

/**
 * RFC 9204 Appendix B.2 - Post-base indexing in encoded field section.
 */
TEST (qpack_rfc_appendix_b2_postbase)
{
  SocketQPACK_Result result;
  uint64_t output;

  /* Scenario: Base=0, encoder inserts entries during encoding.
   * Entry at absolute 0 is referenced as post-base 0.
   * Entry at absolute 1 is referenced as post-base 1.
   */
  result = SocketQPACK_abs_to_postbase (0, 0, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (0, output);

  result = SocketQPACK_abs_to_postbase (0, 1, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (1, output);

  /* Validation: with insert_count=2, post-base 0 and 1 are valid */
  result = SocketQPACK_is_valid_postbase (0, 2, 0);
  ASSERT_EQ (QPACK_OK, result);

  result = SocketQPACK_is_valid_postbase (0, 2, 1);
  ASSERT_EQ (QPACK_OK, result);

  /* Post-base 2 would reference insert_count=2, which is future */
  result = SocketQPACK_is_valid_postbase (0, 2, 2);
  ASSERT_EQ (QPACK_ERR_FUTURE_INDEX, result);
}

/**
 * RFC 9204 Appendix B.4 - Relative indexing after dynamic table updates.
 */
TEST (qpack_rfc_appendix_b4_relative)
{
  SocketQPACK_Result result;
  uint64_t output;

  /* Scenario: After several insertions, insert_count=4.
   * Encoder references recently inserted entries.
   */
  result = SocketQPACK_relative_to_abs_encoder (4, 0, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (3, output); /* Most recent entry */

  result = SocketQPACK_relative_to_abs_encoder (4, 1, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (2, output);

  /* Field section with Base=4 uses relative indexing */
  result = SocketQPACK_relative_to_abs_field (4, 0, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (3, output);

  result = SocketQPACK_relative_to_abs_field (4, 3, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (0, output);
}

/* ============================================================================
 * EDGE CASE TESTS
 * ============================================================================
 */

/**
 * Test empty table edge case (insert_count=0).
 */
TEST (qpack_empty_table)
{
  SocketQPACK_Result result;
  uint64_t output;

  /* Empty table: insert_count=0, dropped_count=0 */

  /* Encoder relative: any index is invalid */
  result = SocketQPACK_abs_to_relative_encoder (0, 0, &output);
  ASSERT_EQ (QPACK_ERR_INVALID_INDEX, result);

  result = SocketQPACK_relative_to_abs_encoder (0, 0, &output);
  ASSERT_EQ (QPACK_ERR_INVALID_INDEX, result);

  /* Field relative with base=0: invalid */
  result = SocketQPACK_abs_to_relative_field (0, 0, &output);
  ASSERT_EQ (QPACK_ERR_INVALID_INDEX, result);

  result = SocketQPACK_relative_to_abs_field (0, 0, &output);
  ASSERT_EQ (QPACK_ERR_INVALID_INDEX, result);

  /* Post-base with base=0, insert_count=0: any index is future */
  result = SocketQPACK_is_valid_postbase (0, 0, 0);
  ASSERT_EQ (QPACK_ERR_FUTURE_INDEX, result);

  /* Absolute validation: empty table has no valid indices */
  result = SocketQPACK_is_valid_absolute (0, 0, 0);
  ASSERT_EQ (QPACK_ERR_FUTURE_INDEX, result);
}

/**
 * Test invalid state detection (dropped_count > insert_count).
 */
TEST (qpack_validate_invalid_state)
{
  SocketQPACK_Result result;

  /* Invalid state: dropped_count=5, insert_count=3 */
  result = SocketQPACK_is_valid_relative_encoder (3, 5, 0);
  ASSERT_EQ (QPACK_ERR_INTERNAL, result);

  result = SocketQPACK_is_valid_absolute (3, 5, 0);
  ASSERT_EQ (QPACK_ERR_INTERNAL, result);
}

/**
 * Test eviction detection in validation functions.
 */
TEST (qpack_eviction_detection)
{
  SocketQPACK_Result result;

  /* Scenario: insert_count=10, dropped_count=5
   * Valid absolute indices: 5, 6, 7, 8, 9
   * Evicted: 0, 1, 2, 3, 4
   * Future: 10+
   */

  /* Valid index */
  result = SocketQPACK_is_valid_absolute (10, 5, 7);
  ASSERT_EQ (QPACK_OK, result);

  /* Boundary: oldest valid */
  result = SocketQPACK_is_valid_absolute (10, 5, 5);
  ASSERT_EQ (QPACK_OK, result);

  /* Boundary: newest valid */
  result = SocketQPACK_is_valid_absolute (10, 5, 9);
  ASSERT_EQ (QPACK_OK, result);

  /* Just evicted */
  result = SocketQPACK_is_valid_absolute (10, 5, 4);
  ASSERT_EQ (QPACK_ERR_EVICTED_INDEX, result);

  /* Long evicted */
  result = SocketQPACK_is_valid_absolute (10, 5, 0);
  ASSERT_EQ (QPACK_ERR_EVICTED_INDEX, result);

  /* Future entry */
  result = SocketQPACK_is_valid_absolute (10, 5, 10);
  ASSERT_EQ (QPACK_ERR_FUTURE_INDEX, result);

  /* Far future */
  result = SocketQPACK_is_valid_absolute (10, 5, 100);
  ASSERT_EQ (QPACK_ERR_FUTURE_INDEX, result);

  /* Encoder relative with eviction */
  result = SocketQPACK_is_valid_relative_encoder (10, 5, 0); /* abs=9, valid */
  ASSERT_EQ (QPACK_OK, result);

  result = SocketQPACK_is_valid_relative_encoder (10, 5, 4); /* abs=5, valid */
  ASSERT_EQ (QPACK_OK, result);

  result = SocketQPACK_is_valid_relative_encoder (10, 5, 5); /* abs=4, evicted */
  ASSERT_EQ (QPACK_ERR_EVICTED_INDEX, result);

  /* Field relative with eviction */
  result = SocketQPACK_is_valid_relative_field (10, 5, 0); /* abs=9, valid */
  ASSERT_EQ (QPACK_OK, result);

  result = SocketQPACK_is_valid_relative_field (10, 5, 5); /* abs=4, evicted */
  ASSERT_EQ (QPACK_ERR_EVICTED_INDEX, result);
}

/**
 * Test large index values (near UINT64_MAX).
 */
TEST (qpack_large_indices)
{
  SocketQPACK_Result result;
  uint64_t output;

  /* Large insert_count */
  result
      = SocketQPACK_abs_to_relative_encoder (UINT64_MAX, UINT64_MAX - 1, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (0, output); /* Most recent */

  result = SocketQPACK_abs_to_relative_encoder (UINT64_MAX, 0, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (UINT64_MAX - 1, output); /* Oldest */

  /* Post-base overflow protection */
  result = SocketQPACK_postbase_to_abs (UINT64_MAX, 1, &output);
  ASSERT_EQ (QPACK_ERR_INVALID_INDEX, result); /* Would overflow */

  result = SocketQPACK_postbase_to_abs (UINT64_MAX - 10, 10, &output);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (UINT64_MAX, output);
}

/**
 * Test round-trip conversions maintain consistency.
 */
TEST (qpack_roundtrip_conversions)
{
  SocketQPACK_Result result;
  uint64_t relative, absolute;

  /* Encoder relative round-trip */
  for (uint64_t ic = 1; ic <= 100; ic++)
    {
      for (uint64_t abs = 0; abs < ic; abs++)
        {
          result = SocketQPACK_abs_to_relative_encoder (ic, abs, &relative);
          ASSERT_EQ (QPACK_OK, result);

          result = SocketQPACK_relative_to_abs_encoder (ic, relative, &absolute);
          ASSERT_EQ (QPACK_OK, result);
          ASSERT_EQ (abs, absolute);
        }
    }

  /* Field relative round-trip */
  for (uint64_t base = 1; base <= 100; base++)
    {
      for (uint64_t abs = 0; abs < base; abs++)
        {
          result = SocketQPACK_abs_to_relative_field (base, abs, &relative);
          ASSERT_EQ (QPACK_OK, result);

          result = SocketQPACK_relative_to_abs_field (base, relative, &absolute);
          ASSERT_EQ (QPACK_OK, result);
          ASSERT_EQ (abs, absolute);
        }
    }

  /* Post-base round-trip */
  for (uint64_t base = 0; base <= 50; base++)
    {
      for (uint64_t abs = base; abs < base + 50; abs++)
        {
          uint64_t postbase;
          result = SocketQPACK_abs_to_postbase (base, abs, &postbase);
          ASSERT_EQ (QPACK_OK, result);

          result = SocketQPACK_postbase_to_abs (base, postbase, &absolute);
          ASSERT_EQ (QPACK_OK, result);
          ASSERT_EQ (abs, absolute);
        }
    }
}

/**
 * Test result_string function.
 */
TEST (qpack_result_string)
{
  /* All result codes should have non-NULL strings */
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_OK));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_INCOMPLETE));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERR_INVALID_INDEX));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERR_EVICTED_INDEX));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERR_FUTURE_INDEX));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERR_BASE_OVERFLOW));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERR_TABLE_SIZE));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERR_HEADER_SIZE));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERR_HUFFMAN));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERR_INTEGER));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERR_DECOMPRESSION));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERR_NULL_PARAM));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERR_INTERNAL));

  /* Invalid result codes should return "Unknown error" */
  ASSERT_NOT_NULL (SocketQPACK_result_string ((SocketQPACK_Result) -1));
  ASSERT_NOT_NULL (SocketQPACK_result_string ((SocketQPACK_Result) 999));
}

/**
 * Test estimate_capacity function.
 */
TEST (qpack_estimate_capacity)
{
  size_t cap;

  /* Minimum capacity is 16 */
  cap = SocketQPACK_estimate_capacity (0);
  ASSERT_EQ (16, cap);

  cap = SocketQPACK_estimate_capacity (100);
  ASSERT_EQ (16, cap);

  /* Default 4096 bytes should give reasonable capacity */
  cap = SocketQPACK_estimate_capacity (4096);
  ASSERT (cap >= 16);
  ASSERT ((cap & (cap - 1)) == 0); /* Power of 2 */

  /* 64KB max should give larger capacity */
  cap = SocketQPACK_estimate_capacity (65536);
  ASSERT (cap > 16);
  ASSERT ((cap & (cap - 1)) == 0); /* Power of 2 */
}

/* ============================================================================
 * TEST RUNNER
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
