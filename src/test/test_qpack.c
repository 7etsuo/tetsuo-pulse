/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack.c
 * @brief Unit tests for QPACK Indexed Field Line (RFC 9204 Section 4.5.2).
 *
 * Tests encoding and decoding of QPACK Indexed Field Line representations:
 * - Static table encoding/decoding (indices 0-98)
 * - Dynamic table encoding/decoding with Base conversion
 * - Variable-length integer encoding for indices > 63
 * - Error handling for out-of-range indices
 */

#include <stdint.h>
#include <string.h>

#include "http/SocketQPACK-private.h"
#include "test/Test.h"

/* ============================================================================
 * Static Table Encoding Tests
 * ============================================================================
 */

/* Test encoding static table index 0 (:authority with empty value) */
TEST (qpack_encode_static_index_0)
{
  unsigned char output[16];
  ssize_t len = qpack_encode_indexed_static (0, output, sizeof (output));

  /* Index 0 with T=1 (static) should encode as 0xC0 (11000000) */
  ASSERT_EQ (1, len);
  ASSERT_EQ (0xC0, output[0]);
}

/* Test encoding static table index 1 (:path /) */
TEST (qpack_encode_static_index_1)
{
  unsigned char output[16];
  ssize_t len = qpack_encode_indexed_static (1, output, sizeof (output));

  /* Index 1 with T=1 (static) should encode as 0xC1 (11000001) */
  ASSERT_EQ (1, len);
  ASSERT_EQ (0xC1, output[0]);
}

/* Test encoding static table index 17 (:method GET) */
TEST (qpack_encode_static_index_17)
{
  unsigned char output[16];
  ssize_t len = qpack_encode_indexed_static (17, output, sizeof (output));

  /* Index 17 with T=1 (static) should encode as 0xD1 (11010001)
   * Pattern: 11 (indexed+static) + 010001 (17 in 6 bits) */
  ASSERT_EQ (1, len);
  ASSERT_EQ (0xD1, output[0]);
}

/* Test encoding maximum static table index 98 */
TEST (qpack_encode_static_index_98)
{
  unsigned char output[16];
  ssize_t len = qpack_encode_indexed_static (98, output, sizeof (output));

  /* Index 98 requires variable-length encoding:
   * First byte: 11111111 (0xFF) - pattern + max prefix value (63)
   * Second byte: 98 - 63 = 35 (0x23) */
  ASSERT_EQ (2, len);
  ASSERT_EQ (0xFF, output[0]);
  ASSERT_EQ (0x23, output[1]);
}

/* Test encoding static table index 63 (at boundary) */
TEST (qpack_encode_static_index_63)
{
  unsigned char output[16];
  ssize_t len = qpack_encode_indexed_static (63, output, sizeof (output));

  /* Index 63 is exactly the max 6-bit prefix value
   * Requires continuation: 11111111 + 00000000 */
  ASSERT_EQ (2, len);
  ASSERT_EQ (0xFF, output[0]);
  ASSERT_EQ (0x00, output[1]);
}

/* Test reject static table index 99 (out of range) */
TEST (qpack_encode_static_index_99_rejected)
{
  unsigned char output[16];
  ssize_t len = qpack_encode_indexed_static (99, output, sizeof (output));

  /* Index 99 is out of range, should return -1 */
  ASSERT_EQ (-1, len);
}

/* ============================================================================
 * Dynamic Table Encoding Tests
 * ============================================================================
 */

/* Test encoding dynamic table relative index 0 */
TEST (qpack_encode_dynamic_index_0)
{
  unsigned char output[16];
  ssize_t len = qpack_encode_indexed_dynamic (0, output, sizeof (output));

  /* Relative index 0 with T=0 (dynamic) should encode as 0x80 (10000000) */
  ASSERT_EQ (1, len);
  ASSERT_EQ (0x80, output[0]);
}

/* Test encoding dynamic table relative index 5 */
TEST (qpack_encode_dynamic_index_5)
{
  unsigned char output[16];
  ssize_t len = qpack_encode_indexed_dynamic (5, output, sizeof (output));

  /* Relative index 5 with T=0 (dynamic) should encode as 0x85 (10000101) */
  ASSERT_EQ (1, len);
  ASSERT_EQ (0x85, output[0]);
}

/* ============================================================================
 * Static Table Decoding Tests
 * ============================================================================
 */

/* Test decoding static table index 0 */
TEST (qpack_decode_static_index_0)
{
  unsigned char input[] = { 0xC0 }; /* Static index 0 */
  struct QPACK_Representation_T rep;
  size_t consumed;

  QPACK_Result result = qpack_decode_indexed_field (
      input, sizeof (input), NULL, &rep, &consumed);

  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (1, consumed);
  ASSERT_EQ (QPACK_REP_INDEXED, rep.type);
  ASSERT_EQ (0, rep.index);
  ASSERT_EQ (1, rep.is_static);
  ASSERT_EQ (0, rep.absolute_idx);
}

/* Test decoding static table index 1 */
TEST (qpack_decode_static_index_1)
{
  unsigned char input[] = { 0xC1 }; /* Static index 1 */
  struct QPACK_Representation_T rep;
  size_t consumed;

  QPACK_Result result = qpack_decode_indexed_field (
      input, sizeof (input), NULL, &rep, &consumed);

  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (1, consumed);
  ASSERT_EQ (1, rep.index);
  ASSERT_EQ (1, rep.is_static);
}

/* Test decoding static table index 98 (requires variable-length) */
TEST (qpack_decode_static_index_98)
{
  unsigned char input[] = { 0xFF, 0x23 }; /* Static index 98: 63 + 35 */
  struct QPACK_Representation_T rep;
  size_t consumed;

  QPACK_Result result = qpack_decode_indexed_field (
      input, sizeof (input), NULL, &rep, &consumed);

  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (2, consumed);
  ASSERT_EQ (98, rep.index);
  ASSERT_EQ (1, rep.is_static);
}

/* Test reject static table index 99 during decode */
TEST (qpack_decode_static_index_99_rejected)
{
  unsigned char input[] = { 0xFF, 0x24 }; /* Static index 99: 63 + 36 */
  struct QPACK_Representation_T rep;
  size_t consumed;

  QPACK_Result result = qpack_decode_indexed_field (
      input, sizeof (input), NULL, &rep, &consumed);

  ASSERT_EQ (QPACK_ERROR_INDEX_OUT_OF_RANGE_STATIC, result);
}

/* ============================================================================
 * Dynamic Table Decoding with Base Conversion
 * ============================================================================
 */

/* Test decoding dynamic relative index 0 with Base=100 -> absolute 99 */
TEST (qpack_decode_dynamic_base_100_relative_0)
{
  unsigned char input[] = { 0x80 }; /* Dynamic relative index 0 */
  struct QPACK_Representation_T rep;
  size_t consumed;
  QPACK_DecoderContext ctx = {
    .required_insert_count = 0, .base = 100, .max_dynamic = 0, .base_is_set = 1
  };

  QPACK_Result result = qpack_decode_indexed_field (
      input, sizeof (input), &ctx, &rep, &consumed);

  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (1, consumed);
  ASSERT_EQ (0, rep.index); /* Relative index */
  ASSERT_EQ (0, rep.is_static);
  ASSERT_EQ (99, rep.absolute_idx); /* Base - 1 - relative = 100 - 1 - 0 */
}

/* Test decoding dynamic relative index 5 with Base=100 -> absolute 94 */
TEST (qpack_decode_dynamic_base_100_relative_5)
{
  unsigned char input[] = { 0x85 }; /* Dynamic relative index 5 */
  struct QPACK_Representation_T rep;
  size_t consumed;
  QPACK_DecoderContext ctx = {
    .required_insert_count = 0, .base = 100, .max_dynamic = 0, .base_is_set = 1
  };

  QPACK_Result result = qpack_decode_indexed_field (
      input, sizeof (input), &ctx, &rep, &consumed);

  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (5, rep.index);
  ASSERT_EQ (0, rep.is_static);
  ASSERT_EQ (94, rep.absolute_idx); /* Base - 1 - relative = 100 - 1 - 5 */
}

/* Test dynamic table access without Base set fails */
TEST (qpack_decode_dynamic_base_not_set)
{
  unsigned char input[] = { 0x80 }; /* Dynamic relative index 0 */
  struct QPACK_Representation_T rep;
  size_t consumed;
  QPACK_DecoderContext ctx = {
    .required_insert_count = 0, .base = 0, .max_dynamic = 0, .base_is_set = 0
  };

  QPACK_Result result = qpack_decode_indexed_field (
      input, sizeof (input), &ctx, &rep, &consumed);

  ASSERT_EQ (QPACK_ERROR_BASE_NOT_SET, result);
}

/* Test dynamic table access with NULL context fails */
TEST (qpack_decode_dynamic_null_context)
{
  unsigned char input[] = { 0x80 }; /* Dynamic relative index 0 */
  struct QPACK_Representation_T rep;
  size_t consumed;

  QPACK_Result result = qpack_decode_indexed_field (
      input, sizeof (input), NULL, &rep, &consumed);

  ASSERT_EQ (QPACK_ERROR_BASE_NOT_SET, result);
}

/* Test dynamic index out of range when relative >= Base */
TEST (qpack_decode_dynamic_out_of_range)
{
  unsigned char input[] = { 0x85 }; /* Dynamic relative index 5 */
  struct QPACK_Representation_T rep;
  size_t consumed;
  QPACK_DecoderContext ctx
      = { .required_insert_count = 0,
          .base = 5, /* Base = 5, relative = 5 -> underflow */
          .max_dynamic = 0,
          .base_is_set = 1 };

  QPACK_Result result = qpack_decode_indexed_field (
      input, sizeof (input), &ctx, &rep, &consumed);

  ASSERT_EQ (QPACK_ERROR_INDEX_OUT_OF_RANGE_DYNAMIC, result);
}

/* ============================================================================
 * Variable-Length Integer Tests
 * ============================================================================
 */

/* Test 6-bit integer overflow (index > 63) encoding/decoding roundtrip */
TEST (qpack_roundtrip_index_64)
{
  unsigned char output[16];
  ssize_t enc_len = qpack_encode_indexed_static (64, output, sizeof (output));
  ASSERT (enc_len > 1); /* Should require continuation bytes */

  struct QPACK_Representation_T rep;
  size_t consumed;
  QPACK_Result result = qpack_decode_indexed_field (
      output, (size_t)enc_len, NULL, &rep, &consumed);

  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ ((size_t)enc_len, consumed);
  ASSERT_EQ (64, rep.index);
  ASSERT_EQ (1, rep.is_static);
}

/* Test roundtrip for all static table entries */
TEST (qpack_roundtrip_all_static)
{
  for (uint32_t i = 0; i <= QPACK_STATIC_INDEX_MAX; i++)
    {
      unsigned char output[16];
      ssize_t enc_len
          = qpack_encode_indexed_static (i, output, sizeof (output));
      ASSERT (enc_len > 0);

      struct QPACK_Representation_T rep;
      size_t consumed;
      QPACK_Result result = qpack_decode_indexed_field (
          output, (size_t)enc_len, NULL, &rep, &consumed);

      ASSERT_EQ (QPACK_OK, result);
      ASSERT_EQ ((size_t)enc_len, consumed);
      ASSERT_EQ (i, rep.index);
      ASSERT_EQ (1, rep.is_static);
    }
}

/* ============================================================================
 * Static Table Content Tests
 * ============================================================================
 */

/* Test static table entry 0: :authority */
TEST (qpack_static_table_entry_0)
{
  const QPACK_StaticEntry *entry;
  QPACK_Result result = qpack_static_get (0, &entry);

  ASSERT_EQ (QPACK_OK, result);
  ASSERT_NOT_NULL (entry);
  ASSERT (strcmp (entry->name, ":authority") == 0);
  ASSERT_EQ (10, entry->name_len);
  ASSERT_EQ (0, entry->value_len);
}

/* Test static table entry 17: :method GET */
TEST (qpack_static_table_entry_17)
{
  const QPACK_StaticEntry *entry;
  QPACK_Result result = qpack_static_get (17, &entry);

  ASSERT_EQ (QPACK_OK, result);
  ASSERT_NOT_NULL (entry);
  ASSERT (strcmp (entry->name, ":method") == 0);
  ASSERT (strcmp (entry->value, "GET") == 0);
}

/* Test static table entry 25: :status 200 */
TEST (qpack_static_table_entry_25)
{
  const QPACK_StaticEntry *entry;
  QPACK_Result result = qpack_static_get (25, &entry);

  ASSERT_EQ (QPACK_OK, result);
  ASSERT_NOT_NULL (entry);
  ASSERT (strcmp (entry->name, ":status") == 0);
  ASSERT (strcmp (entry->value, "200") == 0);
}

/* Test static table entry 98: x-frame-options sameorigin */
TEST (qpack_static_table_entry_98)
{
  const QPACK_StaticEntry *entry;
  QPACK_Result result = qpack_static_get (98, &entry);

  ASSERT_EQ (QPACK_OK, result);
  ASSERT_NOT_NULL (entry);
  ASSERT (strcmp (entry->name, "x-frame-options") == 0);
  ASSERT (strcmp (entry->value, "sameorigin") == 0);
}

/* Test static table entry 99 (out of range) */
TEST (qpack_static_table_entry_99_rejected)
{
  const QPACK_StaticEntry *entry;
  QPACK_Result result = qpack_static_get (99, &entry);

  ASSERT_EQ (QPACK_ERROR_INDEX_OUT_OF_RANGE_STATIC, result);
}

/* ============================================================================
 * Error Handling Tests
 * ============================================================================
 */

/* Test incomplete input during decode */
TEST (qpack_decode_incomplete_input)
{
  /* Variable-length integer that needs 2 bytes but only 1 provided */
  unsigned char input[] = { 0xFF }; /* Needs continuation */
  struct QPACK_Representation_T rep;
  size_t consumed;

  QPACK_Result result = qpack_decode_indexed_field (
      input, sizeof (input), NULL, &rep, &consumed);

  ASSERT_EQ (QPACK_INCOMPLETE, result);
}

/* Test empty input during decode */
TEST (qpack_decode_empty_input)
{
  struct QPACK_Representation_T rep;
  size_t consumed;

  QPACK_Result result
      = qpack_decode_indexed_field (NULL, 0, NULL, &rep, &consumed);

  ASSERT_EQ (QPACK_ERROR, result);
}

/* Test NULL output pointer for encode */
TEST (qpack_encode_null_output)
{
  ssize_t len = qpack_encode_indexed_static (0, NULL, 0);
  ASSERT_EQ (-1, len);
}

/* Test qpack_result_string returns valid strings */
TEST (qpack_result_string_valid)
{
  ASSERT_NOT_NULL (qpack_result_string (QPACK_OK));
  ASSERT_NOT_NULL (qpack_result_string (QPACK_ERROR));
  ASSERT_NOT_NULL (qpack_result_string (QPACK_ERROR_INDEX_OUT_OF_RANGE_STATIC));
  ASSERT_NOT_NULL (qpack_result_string (QPACK_ERROR_BASE_NOT_SET));
}

/* ============================================================================
 * Base Offset Calculation Tests
 * ============================================================================
 */

/* Test base offset conversion directly */
TEST (qpack_apply_base_offset_basic)
{
  QPACK_DecoderContext ctx
      = { .base = 100, .max_dynamic = 0, .base_is_set = 1 };
  uint32_t absolute;

  QPACK_Result result = qpack_apply_base_offset (0, &ctx, &absolute);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (99, absolute);

  result = qpack_apply_base_offset (5, &ctx, &absolute);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (94, absolute);

  result = qpack_apply_base_offset (99, &ctx, &absolute);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (0, absolute);
}

/* Test base offset with max_dynamic validation */
TEST (qpack_apply_base_offset_max_dynamic)
{
  QPACK_DecoderContext ctx
      = { .base = 100, .max_dynamic = 50, .base_is_set = 1 };
  uint32_t absolute;

  /* Absolute 99 exceeds max_dynamic 50 */
  QPACK_Result result = qpack_apply_base_offset (0, &ctx, &absolute);
  ASSERT_EQ (QPACK_ERROR_INDEX_OUT_OF_RANGE_DYNAMIC, result);

  /* Absolute 49 is within max_dynamic 50 */
  result = qpack_apply_base_offset (50, &ctx, &absolute);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (49, absolute);
}

/* Test validate_static_index function */
TEST (qpack_validate_static_index)
{
  ASSERT_EQ (QPACK_OK, qpack_validate_static_index (0));
  ASSERT_EQ (QPACK_OK, qpack_validate_static_index (98));
  ASSERT_EQ (QPACK_ERROR_INDEX_OUT_OF_RANGE_STATIC,
             qpack_validate_static_index (99));
  ASSERT_EQ (QPACK_ERROR_INDEX_OUT_OF_RANGE_STATIC,
             qpack_validate_static_index (100));
}

/* ============================================================================
 * Main - Run All Tests
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
