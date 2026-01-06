/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_index.c
 * @brief Unit tests for QPACK indexing schemes (RFC 9204 Sections 3.2.4-3.2.6)
 *
 * Tests the three indexing schemes:
 * - Absolute Indexing (Section 3.2.4)
 * - Encoder Relative Indexing (Section 3.2.5)
 * - Field Section Relative and Post-Base Indexing (Section 3.2.5-3.2.6)
 *
 * Test coverage includes:
 * - Basic index conversions
 * - Round-trip conversions (abs -> rel -> abs)
 * - Boundary conditions
 * - Error handling for invalid indices
 * - Eviction validation
 */

#include "core/Arena.h"
#include "http/qpack/SocketQPACK.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test assertion macro */
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
 * ENCODER RELATIVE INDEXING TESTS (RFC 9204 Section 3.2.5)
 * ============================================================================
 */

/**
 * Test basic encoder relative index conversion.
 *
 * With Insert Count = 5, entries have absolute indices 0-4.
 * Relative index 0 should reference absolute index 4 (most recent).
 */
static void
test_encoder_relative_basic (void)
{
  uint64_t rel, abs;
  SocketQPACK_Result result;

  printf ("  Encoder relative indexing basic... ");

  /* Insert Count = 5: entries at abs 0, 1, 2, 3, 4 */
  uint64_t insert_count = 5;

  /* rel 0 -> abs 4 (most recent) */
  result = SocketQPACK_relative_to_abs_encoder (insert_count, 0, &abs);
  TEST_ASSERT (result == QPACK_OK, "rel=0 should succeed");
  TEST_ASSERT (abs == 4, "rel=0 should give abs=4");

  /* rel 4 -> abs 0 (oldest) */
  result = SocketQPACK_relative_to_abs_encoder (insert_count, 4, &abs);
  TEST_ASSERT (result == QPACK_OK, "rel=4 should succeed");
  TEST_ASSERT (abs == 0, "rel=4 should give abs=0");

  /* abs 4 -> rel 0 */
  result = SocketQPACK_abs_to_relative_encoder (insert_count, 4, &rel);
  TEST_ASSERT (result == QPACK_OK, "abs=4 should succeed");
  TEST_ASSERT (rel == 0, "abs=4 should give rel=0");

  /* abs 0 -> rel 4 */
  result = SocketQPACK_abs_to_relative_encoder (insert_count, 0, &rel);
  TEST_ASSERT (result == QPACK_OK, "abs=0 should succeed");
  TEST_ASSERT (rel == 4, "abs=0 should give rel=4");

  printf ("PASS\n");
}

/**
 * Test encoder relative indexing round-trip.
 *
 * abs -> rel -> abs should return the original value.
 */
static void
test_encoder_relative_roundtrip (void)
{
  uint64_t rel, abs_out;
  SocketQPACK_Result result;

  printf ("  Encoder relative indexing round-trip... ");

  uint64_t insert_count = 10;

  for (uint64_t abs = 0; abs < insert_count; abs++)
    {
      /* abs -> rel */
      result = SocketQPACK_abs_to_relative_encoder (insert_count, abs, &rel);
      TEST_ASSERT (result == QPACK_OK, "abs_to_rel should succeed");

      /* rel -> abs */
      result
          = SocketQPACK_relative_to_abs_encoder (insert_count, rel, &abs_out);
      TEST_ASSERT (result == QPACK_OK, "rel_to_abs should succeed");
      TEST_ASSERT (abs_out == abs, "round-trip should return original");
    }

  printf ("PASS\n");
}

/**
 * Test encoder relative indexing boundary conditions.
 *
 * - rel >= insert_count should fail
 * - abs >= insert_count should fail
 */
static void
test_encoder_relative_boundaries (void)
{
  uint64_t out;
  SocketQPACK_Result result;

  printf ("  Encoder relative indexing boundaries... ");

  uint64_t insert_count = 5;

  /* rel = insert_count should fail (out of range) */
  result = SocketQPACK_relative_to_abs_encoder (insert_count, 5, &out);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "rel=5 should fail");

  /* abs = insert_count should fail (future entry) */
  result = SocketQPACK_abs_to_relative_encoder (insert_count, 5, &out);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "abs=5 should fail");

  /* insert_count = 0: any index should fail */
  result = SocketQPACK_relative_to_abs_encoder (0, 0, &out);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "empty table, rel=0 fail");

  printf ("PASS\n");
}

/* ============================================================================
 * FIELD SECTION RELATIVE INDEXING TESTS (RFC 9204 Section 3.2.5)
 * ============================================================================
 */

/**
 * Test basic field section relative index conversion.
 *
 * With Base = 5, relative index 0 references absolute index 4 (Base - 1).
 */
static void
test_field_relative_basic (void)
{
  uint64_t rel, abs;
  SocketQPACK_Result result;

  printf ("  Field section relative indexing basic... ");

  uint64_t base = 5;

  /* rel 0 -> abs 4 (Base - 1) */
  result = SocketQPACK_relative_to_abs_field (base, 0, &abs);
  TEST_ASSERT (result == QPACK_OK, "rel=0 should succeed");
  TEST_ASSERT (abs == 4, "rel=0 should give abs=4");

  /* rel 4 -> abs 0 */
  result = SocketQPACK_relative_to_abs_field (base, 4, &abs);
  TEST_ASSERT (result == QPACK_OK, "rel=4 should succeed");
  TEST_ASSERT (abs == 0, "rel=4 should give abs=0");

  /* abs 4 -> rel 0 */
  result = SocketQPACK_abs_to_relative_field (base, 4, &rel);
  TEST_ASSERT (result == QPACK_OK, "abs=4 should succeed");
  TEST_ASSERT (rel == 0, "abs=4 should give rel=0");

  /* abs 0 -> rel 4 */
  result = SocketQPACK_abs_to_relative_field (base, 0, &rel);
  TEST_ASSERT (result == QPACK_OK, "abs=0 should succeed");
  TEST_ASSERT (rel == 4, "abs=0 should give rel=4");

  printf ("PASS\n");
}

/**
 * Test field section relative indexing round-trip.
 */
static void
test_field_relative_roundtrip (void)
{
  uint64_t rel, abs_out;
  SocketQPACK_Result result;

  printf ("  Field section relative indexing round-trip... ");

  uint64_t base = 10;

  for (uint64_t abs = 0; abs < base; abs++)
    {
      /* abs -> rel */
      result = SocketQPACK_abs_to_relative_field (base, abs, &rel);
      TEST_ASSERT (result == QPACK_OK, "abs_to_rel should succeed");

      /* rel -> abs */
      result = SocketQPACK_relative_to_abs_field (base, rel, &abs_out);
      TEST_ASSERT (result == QPACK_OK, "rel_to_abs should succeed");
      TEST_ASSERT (abs_out == abs, "round-trip should return original");
    }

  printf ("PASS\n");
}

/**
 * Test field section relative indexing boundary conditions.
 */
static void
test_field_relative_boundaries (void)
{
  uint64_t out;
  SocketQPACK_Result result;

  printf ("  Field section relative indexing boundaries... ");

  uint64_t base = 5;

  /* rel = base should fail (out of range) */
  result = SocketQPACK_relative_to_abs_field (base, 5, &out);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "rel=5 should fail");

  /* abs = base should fail (must use post-base) */
  result = SocketQPACK_abs_to_relative_field (base, 5, &out);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "abs=5 should fail");

  /* base = 0: any index should fail */
  result = SocketQPACK_relative_to_abs_field (0, 0, &out);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "base=0, rel=0 fail");

  printf ("PASS\n");
}

/* ============================================================================
 * POST-BASE INDEXING TESTS (RFC 9204 Section 3.2.6)
 * ============================================================================
 */

/**
 * Test basic post-base index conversion.
 *
 * With Base = 5, post-base index 0 references absolute index 5 (Base).
 */
static void
test_postbase_basic (void)
{
  uint64_t pb, abs;
  SocketQPACK_Result result;

  printf ("  Post-base indexing basic... ");

  uint64_t base = 5;

  /* pb 0 -> abs 5 (Base) */
  result = SocketQPACK_postbase_to_abs (base, 0, &abs);
  TEST_ASSERT (result == QPACK_OK, "pb=0 should succeed");
  TEST_ASSERT (abs == 5, "pb=0 should give abs=5");

  /* pb 3 -> abs 8 */
  result = SocketQPACK_postbase_to_abs (base, 3, &abs);
  TEST_ASSERT (result == QPACK_OK, "pb=3 should succeed");
  TEST_ASSERT (abs == 8, "pb=3 should give abs=8");

  /* abs 5 -> pb 0 */
  result = SocketQPACK_abs_to_postbase (base, 5, &pb);
  TEST_ASSERT (result == QPACK_OK, "abs=5 should succeed");
  TEST_ASSERT (pb == 0, "abs=5 should give pb=0");

  /* abs 8 -> pb 3 */
  result = SocketQPACK_abs_to_postbase (base, 8, &pb);
  TEST_ASSERT (result == QPACK_OK, "abs=8 should succeed");
  TEST_ASSERT (pb == 3, "abs=8 should give pb=3");

  printf ("PASS\n");
}

/**
 * Test post-base indexing round-trip.
 */
static void
test_postbase_roundtrip (void)
{
  uint64_t pb, abs_out;
  SocketQPACK_Result result;

  printf ("  Post-base indexing round-trip... ");

  uint64_t base = 5;
  uint64_t insert_count = 10;

  /* Test entries at and after Base */
  for (uint64_t abs = base; abs < insert_count; abs++)
    {
      /* abs -> pb */
      result = SocketQPACK_abs_to_postbase (base, abs, &pb);
      TEST_ASSERT (result == QPACK_OK, "abs_to_pb should succeed");

      /* pb -> abs */
      result = SocketQPACK_postbase_to_abs (base, pb, &abs_out);
      TEST_ASSERT (result == QPACK_OK, "pb_to_abs should succeed");
      TEST_ASSERT (abs_out == abs, "round-trip should return original");
    }

  printf ("PASS\n");
}

/**
 * Test post-base indexing boundary conditions.
 */
static void
test_postbase_boundaries (void)
{
  uint64_t out;
  SocketQPACK_Result result;

  printf ("  Post-base indexing boundaries... ");

  uint64_t base = 5;

  /* abs < base should fail (must use relative) */
  result = SocketQPACK_abs_to_postbase (base, 4, &out);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "abs=4 should fail");

  result = SocketQPACK_abs_to_postbase (base, 0, &out);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "abs=0 should fail");

  /* base = 0: pb 0 -> abs 0 (edge case, should work) */
  result = SocketQPACK_postbase_to_abs (0, 0, &out);
  TEST_ASSERT (result == QPACK_OK, "base=0, pb=0 should succeed");
  TEST_ASSERT (out == 0, "base=0, pb=0 should give abs=0");

  printf ("PASS\n");
}

/* ============================================================================
 * VALIDATION TESTS
 * ============================================================================
 */

/**
 * Test encoder relative validation with eviction.
 */
static void
test_validate_encoder_relative (void)
{
  SocketQPACK_Result result;

  printf ("  Validate encoder relative with eviction... ");

  /*
   * Scenario: Insert Count = 10, Dropped = 3
   * Valid absolute indices: 3, 4, 5, 6, 7, 8, 9
   * Valid relative indices: 0, 1, 2, 3, 4, 5, 6
   */
  uint64_t insert_count = 10;
  uint64_t dropped = 3;

  /* rel 0 -> abs 9 (valid) */
  result = SocketQPACK_is_valid_relative_encoder (insert_count, dropped, 0);
  TEST_ASSERT (result == QPACK_OK, "rel=0 should be valid");

  /* rel 6 -> abs 3 (valid, oldest non-evicted) */
  result = SocketQPACK_is_valid_relative_encoder (insert_count, dropped, 6);
  TEST_ASSERT (result == QPACK_OK, "rel=6 should be valid");

  /* rel 7 -> abs 2 (evicted) */
  result = SocketQPACK_is_valid_relative_encoder (insert_count, dropped, 7);
  TEST_ASSERT (result == QPACK_ERR_EVICTED_INDEX, "rel=7 should be evicted");

  /* rel 10 -> out of range */
  result = SocketQPACK_is_valid_relative_encoder (insert_count, dropped, 10);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "rel=10 should be invalid");

  printf ("PASS\n");
}

/**
 * Test field relative validation with eviction.
 */
static void
test_validate_field_relative (void)
{
  SocketQPACK_Result result;

  printf ("  Validate field relative with eviction... ");

  /*
   * Scenario: Base = 8, Dropped = 3
   * Valid absolute indices via relative: 3, 4, 5, 6, 7
   * rel 0 -> abs 7, rel 4 -> abs 3
   */
  uint64_t base = 8;
  uint64_t dropped = 3;

  /* rel 0 -> abs 7 (valid) */
  result = SocketQPACK_is_valid_relative_field (base, dropped, 0);
  TEST_ASSERT (result == QPACK_OK, "rel=0 should be valid");

  /* rel 4 -> abs 3 (valid, oldest non-evicted) */
  result = SocketQPACK_is_valid_relative_field (base, dropped, 4);
  TEST_ASSERT (result == QPACK_OK, "rel=4 should be valid");

  /* rel 5 -> abs 2 (evicted) */
  result = SocketQPACK_is_valid_relative_field (base, dropped, 5);
  TEST_ASSERT (result == QPACK_ERR_EVICTED_INDEX, "rel=5 should be evicted");

  /* rel 8 -> out of range */
  result = SocketQPACK_is_valid_relative_field (base, dropped, 8);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "rel=8 should be invalid");

  printf ("PASS\n");
}

/**
 * Test post-base validation.
 */
static void
test_validate_postbase (void)
{
  SocketQPACK_Result result;

  printf ("  Validate post-base indexing... ");

  /*
   * Scenario: Base = 5, Insert Count = 10
   * Valid post-base indices: 0 (abs 5), 1 (abs 6), ..., 4 (abs 9)
   */
  uint64_t base = 5;
  uint64_t insert_count = 10;

  /* pb 0 -> abs 5 (valid) */
  result = SocketQPACK_is_valid_postbase (base, insert_count, 0);
  TEST_ASSERT (result == QPACK_OK, "pb=0 should be valid");

  /* pb 4 -> abs 9 (valid, most recent) */
  result = SocketQPACK_is_valid_postbase (base, insert_count, 4);
  TEST_ASSERT (result == QPACK_OK, "pb=4 should be valid");

  /* pb 5 -> abs 10 (future entry) */
  result = SocketQPACK_is_valid_postbase (base, insert_count, 5);
  TEST_ASSERT (result == QPACK_ERR_FUTURE_INDEX, "pb=5 should be future");

  printf ("PASS\n");
}

/**
 * Test absolute index validation.
 */
static void
test_validate_absolute (void)
{
  SocketQPACK_Result result;

  printf ("  Validate absolute indexing... ");

  uint64_t insert_count = 10;
  uint64_t dropped = 3;

  /* abs 3 (valid, oldest) */
  result = SocketQPACK_is_valid_absolute (insert_count, dropped, 3);
  TEST_ASSERT (result == QPACK_OK, "abs=3 should be valid");

  /* abs 9 (valid, most recent) */
  result = SocketQPACK_is_valid_absolute (insert_count, dropped, 9);
  TEST_ASSERT (result == QPACK_OK, "abs=9 should be valid");

  /* abs 2 (evicted) */
  result = SocketQPACK_is_valid_absolute (insert_count, dropped, 2);
  TEST_ASSERT (result == QPACK_ERR_EVICTED_INDEX, "abs=2 should be evicted");

  /* abs 10 (future) */
  result = SocketQPACK_is_valid_absolute (insert_count, dropped, 10);
  TEST_ASSERT (result == QPACK_ERR_FUTURE_INDEX, "abs=10 should be future");

  printf ("PASS\n");
}

/* ============================================================================
 * EDGE CASE TESTS
 * ============================================================================
 */

/**
 * Test with max_entries = 1 (eviction edge case).
 *
 * RFC 9204 note: With only one entry capacity, eviction happens on every
 * insert.
 */
static void
test_single_entry_table (void)
{
  uint64_t rel, abs;
  SocketQPACK_Result result;

  printf ("  Single entry table edge case... ");

  /* After 5 insertions with capacity=1, we have:
   * insert_count = 5, dropped = 4
   * Only abs=4 is valid
   */
  uint64_t insert_count = 5;
  uint64_t dropped = 4;

  /* rel 0 -> abs 4 (only valid entry) */
  result = SocketQPACK_relative_to_abs_encoder (insert_count, 0, &abs);
  TEST_ASSERT (result == QPACK_OK, "rel=0 should succeed");
  TEST_ASSERT (abs == 4, "rel=0 should give abs=4");

  /* rel 0 is valid */
  result = SocketQPACK_is_valid_relative_encoder (insert_count, dropped, 0);
  TEST_ASSERT (result == QPACK_OK, "rel=0 should be valid");

  /* rel 1 -> abs 3 (evicted) */
  result = SocketQPACK_is_valid_relative_encoder (insert_count, dropped, 1);
  TEST_ASSERT (result == QPACK_ERR_EVICTED_INDEX, "rel=1 should be evicted");

  /* abs 4 -> rel 0 */
  result = SocketQPACK_abs_to_relative_encoder (insert_count, 4, &rel);
  TEST_ASSERT (result == QPACK_OK, "abs=4 should succeed");
  TEST_ASSERT (rel == 0, "abs=4 should give rel=0");

  printf ("PASS\n");
}

/**
 * Test boundary values at Base transition.
 *
 * When abs = Base - 1, it's the last entry for relative indexing.
 * When abs = Base, it's the first entry for post-base indexing.
 */
static void
test_base_boundary (void)
{
  uint64_t out;
  SocketQPACK_Result result;

  printf ("  Base boundary transition... ");

  uint64_t base = 5;
  uint64_t insert_count = 8;

  /* abs = Base - 1 = 4: last for relative, rel = 0 */
  result = SocketQPACK_abs_to_relative_field (base, 4, &out);
  TEST_ASSERT (result == QPACK_OK, "abs=4 relative should succeed");
  TEST_ASSERT (out == 0, "abs=4 should give rel=0");

  /* abs = Base = 5: first for post-base, pb = 0 */
  result = SocketQPACK_abs_to_postbase (base, 5, &out);
  TEST_ASSERT (result == QPACK_OK, "abs=5 post-base should succeed");
  TEST_ASSERT (out == 0, "abs=5 should give pb=0");

  /* abs = Base - 1: cannot use post-base */
  result = SocketQPACK_abs_to_postbase (base, 4, &out);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "abs=4 pb should fail");

  /* abs = Base: cannot use relative */
  result = SocketQPACK_abs_to_relative_field (base, 5, &out);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "abs=5 rel should fail");

  /* Maximum valid post-base */
  result = SocketQPACK_is_valid_postbase (base, insert_count, 2);
  TEST_ASSERT (result == QPACK_OK, "pb=2 (abs=7) should be valid");

  /* One past maximum */
  result = SocketQPACK_is_valid_postbase (base, insert_count, 3);
  TEST_ASSERT (result == QPACK_ERR_FUTURE_INDEX, "pb=3 (abs=8) should fail");

  printf ("PASS\n");
}

/**
 * Test large index values (RFC 9204 notes 2^62 possible).
 */
static void
test_large_indices (void)
{
  uint64_t out;
  SocketQPACK_Result result;

  printf ("  Large index values... ");

  /* Large but valid indices */
  uint64_t large_ic = (1ULL << 40);
  uint64_t large_abs = large_ic - 1;

  /* rel 0 -> abs (large_ic - 1) */
  result = SocketQPACK_relative_to_abs_encoder (large_ic, 0, &out);
  TEST_ASSERT (result == QPACK_OK, "large rel=0 should succeed");
  TEST_ASSERT (out == large_abs, "large rel=0 should give correct abs");

  /* abs (large_ic - 1) -> rel 0 */
  result = SocketQPACK_abs_to_relative_encoder (large_ic, large_abs, &out);
  TEST_ASSERT (result == QPACK_OK, "large abs should succeed");
  TEST_ASSERT (out == 0, "large abs should give rel=0");

  /* Overflow protection: base + pb should not overflow */
  result = SocketQPACK_postbase_to_abs (UINT64_MAX, 1, &out);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "overflow should fail");

  result
      = SocketQPACK_postbase_to_abs (UINT64_MAX / 2, UINT64_MAX / 2 + 2, &out);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "overflow should fail");

  printf ("PASS\n");
}

/**
 * Test result strings.
 */
static void
test_result_strings (void)
{
  printf ("  Result string coverage... ");

  TEST_ASSERT (strcmp (SocketQPACK_result_string (QPACK_OK), "OK") == 0,
               "QPACK_OK string");
  TEST_ASSERT (strcmp (SocketQPACK_result_string (QPACK_ERR_INVALID_INDEX),
                       "Invalid index")
                   == 0,
               "QPACK_ERR_INVALID_INDEX string");
  TEST_ASSERT (strcmp (SocketQPACK_result_string (QPACK_ERR_EVICTED_INDEX),
                       "Entry has been evicted")
                   == 0,
               "QPACK_ERR_EVICTED_INDEX string");
  TEST_ASSERT (strcmp (SocketQPACK_result_string (QPACK_ERR_FUTURE_INDEX),
                       "Reference to not-yet-inserted entry")
                   == 0,
               "QPACK_ERR_FUTURE_INDEX string");

  /* Unknown error code */
  TEST_ASSERT (strcmp (SocketQPACK_result_string ((SocketQPACK_Result)999),
                       "Unknown error")
                   == 0,
               "Unknown error string");

  printf ("PASS\n");
}

/**
 * Test capacity estimation.
 */
static void
test_capacity_estimation (void)
{
  size_t cap;

  printf ("  Capacity estimation... ");

  /* Zero max_size returns minimum */
  cap = SocketQPACK_estimate_capacity (0);
  TEST_ASSERT (cap == 16, "cap(0) should be 16");

  /* Small size */
  cap = SocketQPACK_estimate_capacity (100);
  TEST_ASSERT (cap >= 16, "cap(100) should be >= 16");
  TEST_ASSERT ((cap & (cap - 1)) == 0, "cap should be power of 2");

  /* Default table size */
  cap = SocketQPACK_estimate_capacity (4096);
  TEST_ASSERT (cap >= 16, "cap(4096) should be >= 16");
  TEST_ASSERT ((cap & (cap - 1)) == 0, "cap should be power of 2");

  printf ("PASS\n");
}

/* ============================================================================
 * NULL PARAMETER TESTS (Hardening)
 * ============================================================================
 */

/**
 * Test NULL parameter handling for conversion functions.
 *
 * All conversion functions should return QPACK_ERR_NULL_PARAM when
 * the output parameter is NULL, instead of crashing.
 */
static void
test_null_parameters (void)
{
  SocketQPACK_Result result;

  printf ("  NULL parameter handling... ");

  /* Test abs_to_relative_encoder with NULL */
  result = SocketQPACK_abs_to_relative_encoder (10, 5, NULL);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "abs_to_rel_enc NULL should fail");

  /* Test relative_to_abs_encoder with NULL */
  result = SocketQPACK_relative_to_abs_encoder (10, 5, NULL);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "rel_to_abs_enc NULL should fail");

  /* Test abs_to_relative_field with NULL */
  result = SocketQPACK_abs_to_relative_field (10, 5, NULL);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "abs_to_rel_field NULL should fail");

  /* Test relative_to_abs_field with NULL */
  result = SocketQPACK_relative_to_abs_field (10, 5, NULL);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "rel_to_abs_field NULL should fail");

  /* Test abs_to_postbase with NULL */
  result = SocketQPACK_abs_to_postbase (5, 10, NULL);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "abs_to_pb NULL should fail");

  /* Test postbase_to_abs with NULL */
  result = SocketQPACK_postbase_to_abs (5, 3, NULL);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "pb_to_abs NULL should fail");

  printf ("PASS\n");
}

/**
 * Test defensive state validation.
 *
 * Validation functions should detect impossible states where
 * dropped_count > insert_count and return QPACK_ERR_INTERNAL.
 */
static void
test_invalid_state_detection (void)
{
  SocketQPACK_Result result;

  printf ("  Invalid state detection... ");

  /* Test is_valid_relative_encoder with invalid state */
  result = SocketQPACK_is_valid_relative_encoder (3, 5, 0);
  TEST_ASSERT (result == QPACK_ERR_INTERNAL, "invalid state (dropped>insert) encoder");

  /* Test is_valid_absolute with invalid state */
  result = SocketQPACK_is_valid_absolute (3, 5, 0);
  TEST_ASSERT (result == QPACK_ERR_INTERNAL, "invalid state (dropped>insert) absolute");

  printf ("PASS\n");
}

/**
 * Test NULL_PARAM result string.
 */
static void
test_null_param_result_string (void)
{
  printf ("  NULL_PARAM result string... ");

  TEST_ASSERT (strcmp (SocketQPACK_result_string (QPACK_ERR_NULL_PARAM),
                       "NULL parameter passed to function")
                   == 0,
               "QPACK_ERR_NULL_PARAM string");

  printf ("PASS\n");
}

/* ============================================================================
 * TEST SUITE
 * ============================================================================
 */

static void
run_encoder_relative_tests (void)
{
  printf ("Encoder Relative Indexing Tests (RFC 9204 Section 3.2.5):\n");
  test_encoder_relative_basic ();
  test_encoder_relative_roundtrip ();
  test_encoder_relative_boundaries ();
}

static void
run_field_relative_tests (void)
{
  printf ("Field Section Relative Indexing Tests (RFC 9204 Section 3.2.5):\n");
  test_field_relative_basic ();
  test_field_relative_roundtrip ();
  test_field_relative_boundaries ();
}

static void
run_postbase_tests (void)
{
  printf ("Post-Base Indexing Tests (RFC 9204 Section 3.2.6):\n");
  test_postbase_basic ();
  test_postbase_roundtrip ();
  test_postbase_boundaries ();
}

static void
run_validation_tests (void)
{
  printf ("Index Validation Tests:\n");
  test_validate_encoder_relative ();
  test_validate_field_relative ();
  test_validate_postbase ();
  test_validate_absolute ();
}

static void
run_edge_case_tests (void)
{
  printf ("Edge Case Tests:\n");
  test_single_entry_table ();
  test_base_boundary ();
  test_large_indices ();
  test_result_strings ();
  test_capacity_estimation ();
}

static void
run_hardening_tests (void)
{
  printf ("Hardening Tests:\n");
  test_null_parameters ();
  test_invalid_state_detection ();
  test_null_param_result_string ();
}

int
main (void)
{
  printf ("=== QPACK Indexing Scheme Tests (RFC 9204 Sections 3.2.4-3.2.6) "
          "===\n\n");

  run_encoder_relative_tests ();
  printf ("\n");

  run_field_relative_tests ();
  printf ("\n");

  run_postbase_tests ();
  printf ("\n");

  run_validation_tests ();
  printf ("\n");

  run_edge_case_tests ();
  printf ("\n");

  run_hardening_tests ();
  printf ("\n");

  printf ("=== All tests passed! ===\n");
  return 0;
}
