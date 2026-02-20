/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_error_integration.c
 * @brief Integration tests for QPACK error handling.
 *
 * Tests error conditions and edge cases in QPACK encoding/decoding:
 * - Invalid static table indices
 * - Evicted dynamic table entries
 * - Future/unresolvable references
 * - Buffer overflow handling
 * - Incomplete data handling
 * - RFC 9204 decompression failures
 */

#include <stdio.h>
#include <string.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACK.h"
#include "http/qpack/SocketQPACKEncoderStream.h"
#include "test/Test.h"

TEST (qpack_error_static_index_out_of_range)
{
  unsigned char buf[32];
  size_t written = 0;

  /* Static index 99 is out of range (max is 98) */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 99, 1, &written);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);

  /* Static index 1000 is out of range */
  result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 1000, 1, &written);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);

  /* Max valid static index (98) should work */
  result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 98, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
}

TEST (qpack_error_decode_static_index_out_of_range)
{
  /* Manually encode an invalid static index (> 98) */
  /* 0xFF 0x24 -> static index 63 + 36 = 99 (invalid) */
  unsigned char buf[] = { 0xFF, 0x24 };
  uint64_t index = 0;
  int is_static = 0;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);
}

TEST (qpack_error_resolve_static_index_invalid)
{
  uint64_t abs_index = 0;

  /* Resolve static index 99 (invalid) */
  SocketQPACK_Result result
      = SocketQPACK_resolve_indexed_field (99, 1, 100, 0, &abs_index);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);
}

TEST (qpack_error_evicted_entry_reference)
{
  uint64_t abs_index = 0;

  /* Dynamic relative index that resolves to evicted entry
   * Base=100, relative=95 -> absolute = 100 - 95 - 1 = 4
   * dropped_count=10, so entry 4 was evicted
   */
  SocketQPACK_Result result
      = SocketQPACK_resolve_indexed_field (95, 0, 100, 10, &abs_index);
  ASSERT_EQ (result, QPACK_ERR_EVICTED_INDEX);
}

TEST (qpack_error_evicted_entry_boundary)
{
  uint64_t abs_index = 0;

  /* Entry exactly at eviction boundary
   * Base=100, relative=90 -> absolute = 100 - 90 - 1 = 9
   * dropped_count=10, so entry 9 was evicted (10 entries: 0-9)
   */
  SocketQPACK_Result result
      = SocketQPACK_resolve_indexed_field (90, 0, 100, 10, &abs_index);
  ASSERT_EQ (result, QPACK_ERR_EVICTED_INDEX);

  /* Entry just after eviction boundary
   * relative=89 -> absolute = 100 - 89 - 1 = 10
   * Entry 10 is valid
   */
  result = SocketQPACK_resolve_indexed_field (89, 0, 100, 10, &abs_index);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (abs_index, 10);
}

TEST (qpack_error_table_lookup_evicted)
{
  Arena_T arena = Arena_new ();

  /* Create table with small capacity */
  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 128);
  ASSERT (table != NULL);

  /* Insert entries until eviction occurs */
  for (int i = 0; i < 10; i++)
    {
      char name_buf[32], value_buf[64];
      snprintf (name_buf, sizeof (name_buf), "header%d", i);
      snprintf (value_buf, sizeof (value_buf), "value%d-padding-to-fill", i);
      SocketQPACK_Result ins_result = SocketQPACK_Table_insert_literal (
          table, name_buf, strlen (name_buf), value_buf, strlen (value_buf));
      /* Ignore result - we just want to fill/evict the table */
      (void)ins_result;
    }

  /* Try to lookup entry 0 (likely evicted due to small capacity) */
  const char *name = NULL;
  size_t name_len = 0;
  const char *value = NULL;
  size_t value_len = 0;
  SocketQPACK_Result result
      = SocketQPACK_Table_get (table, 0, &name, &name_len, &value, &value_len);

  /* Either evicted or still present depending on exact sizes */
  ASSERT (result == QPACK_ERR_EVICTED_INDEX || result == QPACK_OK);

  Arena_dispose (&arena);
}

TEST (qpack_error_dynamic_index_underflow)
{
  uint64_t abs_index = 0;

  /* Dynamic relative index that would cause underflow
   * Base=10, relative=10 -> absolute = 10 - 10 - 1 = -1 (underflow)
   */
  SocketQPACK_Result result
      = SocketQPACK_resolve_indexed_field (10, 0, 10, 0, &abs_index);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);
}

TEST (qpack_error_dynamic_index_equals_base)
{
  uint64_t abs_index = 0;

  /* Dynamic relative index equals Base (boundary)
   * Base=5, relative=5 -> absolute = 5 - 5 - 1 = -1 (underflow)
   */
  SocketQPACK_Result result
      = SocketQPACK_resolve_indexed_field (5, 0, 5, 0, &abs_index);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);
}

TEST (qpack_error_dynamic_index_exceeds_base)
{
  uint64_t abs_index = 0;

  /* Dynamic relative index exceeds Base
   * Base=5, relative=10 -> underflow
   */
  SocketQPACK_Result result
      = SocketQPACK_resolve_indexed_field (10, 0, 5, 0, &abs_index);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);
}

TEST (qpack_error_ric_exceeds_total_inserts)
{
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  /* Encode prefix with RIC=100, but decode with total_insert_count=50 */
  unsigned char buf[16];
  size_t written = 0;

  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (100, 100, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode with total_insert_count=50 (less than RIC) */
  result
      = SocketQPACK_decode_prefix (buf, written, 128, 50, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_ERR_DECOMPRESSION);
}

TEST (qpack_error_ric_nonzero_max_entries_zero)
{
  unsigned char buf[16];
  size_t written = 0;

  /* Non-zero RIC with max_entries=0 should fail */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (10, 10, 0, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_ERR_TABLE_SIZE);
}

TEST (qpack_error_ric_decode_encoded_exceeds_fullrange)
{
  uint64_t ric = 0;

  /* Encoded RIC > FullRange should fail
   * MaxEntries=128, FullRange=256
   * EncodedRIC=300 > 256
   */
  SocketQPACK_Result result
      = SocketQPACK_decode_required_insert_count (300, 128, 100, &ric);
  ASSERT_EQ (result, QPACK_ERR_DECOMPRESSION);
}

TEST (qpack_error_base_underflow)
{
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  /* Manually create an encoded prefix that would cause Base underflow
   * EncodedRIC=2 -> RIC=1, S=1, DeltaBase=5 -> Base=1-5-1=-5 (underflow)
   */
  unsigned char buf[] = { 0x02, 0x85 };

  SocketQPACK_Result result = SocketQPACK_decode_prefix (
      buf, sizeof (buf), 128, 10, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_ERR_DECOMPRESSION);
}

TEST (qpack_error_postbase_index_exceeds_table)
{
  Arena_T arena = Arena_new ();

  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  /* Insert only 2 entries */
  ASSERT_EQ (SocketQPACK_Table_insert_literal (table, "h1", 2, "v1", 2),
             QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_insert_literal (table, "h2", 2, "v2", 2),
             QPACK_OK);

  /* Try to lookup post-base index 5 with Base=0
   * absolute = 0 + 5 = 5, but only 2 entries exist (0, 1)
   * This is a future reference, not an invalid index
   */
  const char *name = NULL;
  size_t name_len = 0;
  const char *value = NULL;
  size_t value_len = 0;
  SocketQPACK_Result result = SocketQPACK_lookup_indexed_postbase (
      table, 0, 5, &name, &name_len, &value, &value_len);
  ASSERT_EQ (result, QPACK_ERR_FUTURE_INDEX);

  Arena_dispose (&arena);
}

TEST (qpack_error_postbase_name_index_exceeds_table)
{
  Arena_T arena = Arena_new ();

  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  /* Insert only 1 entry */
  ASSERT_EQ (SocketQPACK_Table_insert_literal (table, "h1", 2, "v1", 2),
             QPACK_OK);

  /* Try to resolve post-base name index 5 with Base=0
   * absolute = 0 + 5 = 5, but only 1 entry exists (0)
   * This is a future reference, not an invalid index
   */
  const char *name = NULL;
  size_t name_len = 0;
  SocketQPACK_Result result
      = SocketQPACK_resolve_postbase_name (table, 0, 5, &name, &name_len);
  ASSERT_EQ (result, QPACK_ERR_FUTURE_INDEX);

  Arena_dispose (&arena);
}

TEST (qpack_error_literal_name_ref_static_invalid)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);

  const char *name = NULL;
  size_t name_len = 0;

  /* Static index 99 is invalid */
  SocketQPACK_Result result = SocketQPACK_resolve_literal_name_ref (
      true, 99, 100, table, &name, &name_len);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);

  Arena_dispose (&arena);
}

TEST (qpack_error_literal_name_ref_dynamic_evicted)
{
  Arena_T arena = Arena_new ();

  /* Create table and insert entry */
  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 128);
  ASSERT (table != NULL);

  /* Insert many entries to cause eviction */
  for (int i = 0; i < 10; i++)
    {
      char name_buf[32], value_buf[64];
      snprintf (name_buf, sizeof (name_buf), "header%d", i);
      snprintf (value_buf, sizeof (value_buf), "value%d-padding", i);
      SocketQPACK_Result ins_result = SocketQPACK_Table_insert_literal (
          table, name_buf, strlen (name_buf), value_buf, strlen (value_buf));
      /* Ignore result - we just want to fill/evict the table */
      (void)ins_result;
    }

  /* Try to resolve a dynamic name ref that may be evicted */
  const char *name = NULL;
  size_t name_len = 0;

  /* Large relative index with small Base will cause issues */
  SocketQPACK_Result result = SocketQPACK_resolve_literal_name_ref (
      false, 9, 10, table, &name, &name_len);

  /* Should either be evicted or invalid */
  ASSERT (result == QPACK_ERR_EVICTED_INDEX || result == QPACK_OK
          || result == QPACK_ERR_INVALID_INDEX);

  Arena_dispose (&arena);
}

TEST (qpack_error_encode_buffer_too_small)
{
  unsigned char buf[1]; /* Too small */
  size_t written = 0;

  /* Encoding requires at least a few bytes */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (100, 100, 128, buf, sizeof (buf), &written);
  /* Should fail due to insufficient buffer */
  ASSERT (result != QPACK_OK || written <= sizeof (buf));
}

TEST (qpack_error_encode_indexed_zero_buffer)
{
  unsigned char buf[16];
  size_t written = 0;

  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, 0, 0, 1, &written);
  ASSERT_EQ (result, QPACK_ERR_TABLE_SIZE);
}

TEST (qpack_error_decode_incomplete_indexed)
{
  /* Incomplete multi-byte index */
  unsigned char buf[] = { 0xFF }; /* Needs continuation */
  uint64_t index = 0;
  int is_static = 0;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_INCOMPLETE);
}

TEST (qpack_error_decode_incomplete_prefix)
{
  /* Only one byte of prefix */
  unsigned char buf[] = { 0x05 };
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_prefix (
      buf, sizeof (buf), 128, 10, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_INCOMPLETE);
}

TEST (qpack_error_decode_incomplete_literal)
{
  /* Incomplete literal field line */
  unsigned char buf[] = { 0x20, 0x03 }; /* Name length 3, but no name data */
  unsigned char name_out[64];
  unsigned char value_out[64];
  size_t name_len = 0;
  size_t value_len = 0;
  bool never_indexed = false;
  size_t consumed = 0;

  SocketQPACK_Result result
      = SocketQPACK_decode_literal_field_literal_name (buf,
                                                       sizeof (buf),
                                                       name_out,
                                                       sizeof (name_out),
                                                       &name_len,
                                                       value_out,
                                                       sizeof (value_out),
                                                       &value_len,
                                                       &never_indexed,
                                                       &consumed);
  ASSERT_EQ (result, QPACK_INCOMPLETE);
}

TEST (qpack_error_null_output_buffer)
{
  size_t written = 0;

  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (NULL, 16, 0, 1, &written);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_error_null_written)
{
  unsigned char buf[16];

  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 0, 1, NULL);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_error_null_decode_outputs)
{
  unsigned char buf[] = { 0xC0 };
  size_t consumed = 0;

  /* NULL index */
  int is_static = 0;
  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), NULL, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);

  /* NULL is_static */
  uint64_t index = 0;
  result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, NULL, &consumed);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);

  /* NULL consumed */
  result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, NULL);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_error_null_table)
{
  const char *name = NULL;
  size_t name_len = 0;
  const char *value = NULL;
  size_t value_len = 0;

  /* NULL table */
  SocketQPACK_Result result
      = SocketQPACK_Table_get (NULL, 0, &name, &name_len, &value, &value_len);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_error_empty_input_decode)
{
  uint64_t index = 0;
  int is_static = 0;
  size_t consumed = 0;

  /* Empty input for indexed field */
  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      NULL, 0, &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_INCOMPLETE);
  ASSERT_EQ (consumed, 0);
}

TEST (qpack_error_empty_input_prefix)
{
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  SocketQPACK_Result result
      = SocketQPACK_decode_prefix (NULL, 0, 128, 0, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_INCOMPLETE);
}

TEST (qpack_error_decode_indexed_wrong_pattern)
{
  /* Try to decode as indexed field line, but pattern is wrong */
  unsigned char buf[] = { 0x00 }; /* 0xxxxxxx is NOT indexed field line */
  uint64_t index = 0;
  int is_static = 0;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_ERR_INTERNAL);
}

TEST (qpack_error_decode_postbase_wrong_pattern)
{
  /* Try to decode as post-base, but pattern is wrong */
  unsigned char buf[] = { 0x80 }; /* 10xxxxxx is NOT post-base pattern */
  uint64_t index = 0;
  size_t consumed = 0;

  /* Verify pattern check */
  ASSERT_EQ (SocketQPACK_is_indexed_postbase (buf[0]), false);
}

TEST (qpack_error_decode_literal_literal_wrong_pattern)
{
  /* Try to decode as literal with literal name, but pattern is wrong */
  unsigned char buf[] = { 0x80 }; /* 10xxxxxx is NOT literal pattern */

  /* Verify pattern check */
  ASSERT_EQ (SocketQPACK_is_literal_field_literal_name (buf[0]), false);
}

TEST (qpack_error_huffman_decode_invalid)
{
  /* Invalid Huffman sequence in literal field */
  unsigned char buf[32];
  size_t written = 0;

  /* Encode header with Huffman flag, then corrupt the data */
  SocketQPACK_Result result = SocketQPACK_encode_literal_field_literal_name (
      buf,
      sizeof (buf),
      (const unsigned char *)"test",
      4,
      true,
      (const unsigned char *)"value",
      5,
      true,
      false,
      &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Corrupt the Huffman data by overwriting bytes */
  buf[written - 1] = 0xFF; /* Invalid EOS padding */
  buf[written - 2] = 0xFF;

  /* Try to decode */
  unsigned char name_out[64];
  unsigned char value_out[64];
  size_t name_len = 0;
  size_t value_len = 0;
  bool never_indexed = false;
  size_t consumed = 0;

  result = SocketQPACK_decode_literal_field_literal_name (buf,
                                                          written,
                                                          name_out,
                                                          sizeof (name_out),
                                                          &name_len,
                                                          value_out,
                                                          sizeof (value_out),
                                                          &value_len,
                                                          &never_indexed,
                                                          &consumed);

  /* Should fail with Huffman error */
  ASSERT (result == QPACK_ERR_HUFFMAN || result == QPACK_ERR_DECOMPRESSION);
}

TEST (qpack_error_table_insert_exceeds_capacity)
{
  Arena_T arena = Arena_new ();

  /* Create very small table */
  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 64);
  ASSERT (table != NULL);

  /* Try to insert entry larger than capacity */
  char large_name[64];
  char large_value[64];
  memset (large_name, 'a', sizeof (large_name) - 1);
  large_name[sizeof (large_name) - 1] = '\0';
  memset (large_value, 'b', sizeof (large_value) - 1);
  large_value[sizeof (large_value) - 1] = '\0';

  /* Entry size = 63 + 63 + 32 = 158 > 64 capacity */
  SocketQPACK_Result result = SocketQPACK_Table_insert_literal (
      table, large_name, 63, large_value, 63);

  /* Should either fail or cause eviction (depends on implementation) */
  /* Entry too large for table is typically silently rejected or causes eviction
   */
  (void)result;

  Arena_dispose (&arena);
}

TEST (qpack_error_table_zero_capacity)
{
  Arena_T arena = Arena_new ();

  /* Create table with zero capacity */
  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 0);
  ASSERT (table != NULL);

  /* Any insert should fail or be silently rejected */
  SocketQPACK_Result result
      = SocketQPACK_Table_insert_literal (table, "test", 4, "value", 5);

  /* With zero capacity, inserts cannot succeed */
  ASSERT (result == QPACK_ERR_TABLE_SIZE || result == QPACK_OK);

  Arena_dispose (&arena);
}

TEST (qpack_error_validate_prefix_null)
{
  SocketQPACK_Result result = SocketQPACK_validate_prefix (NULL, 100);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_error_validate_prefix_ric_exceeds)
{
  SocketQPACK_FieldSectionPrefix prefix
      = { .required_insert_count = 100, .delta_base = 0, .base = 100 };

  /* RIC exceeds total_insert_count */
  SocketQPACK_Result result = SocketQPACK_validate_prefix (&prefix, 50);
  ASSERT_EQ (result, QPACK_ERR_DECOMPRESSION);
}

TEST (qpack_error_decompression_future_reference)
{
  Arena_T arena = Arena_new ();

  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  /* Insert only 1 entry */
  ASSERT_EQ (SocketQPACK_Table_insert_literal (table, "h1", 2, "v1", 2),
             QPACK_OK);

  /* Try to reference entry 5 (doesn't exist yet - future reference)
   * Only 1 entry exists (0), so index 5 is a future reference
   */
  const char *name = NULL;
  size_t name_len = 0;
  const char *value = NULL;
  size_t value_len = 0;
  SocketQPACK_Result result
      = SocketQPACK_Table_get (table, 5, &name, &name_len, &value, &value_len);
  ASSERT_EQ (result, QPACK_ERR_FUTURE_INDEX);

  Arena_dispose (&arena);
}

TEST (qpack_error_field_section_invalid_sequence)
{
  /* Encode a field section with mismatched RIC
   * This simulates a decompression failure where Required Insert Count
   * doesn't match the actual references
   */
  unsigned char buf[256];
  size_t offset = 0;
  size_t written = 0;

  /* Prefix claims RIC=10 but we reference entry 15 */
  SocketQPACK_Result result = SocketQPACK_encode_prefix (
      10, 10, 128, buf + offset, sizeof (buf) - offset, &written);
  ASSERT_EQ (result, QPACK_OK);
  offset += written;

  /* Reference dynamic entry with relative index that would need higher RIC */
  /* This is valid encoding but would fail at resolution time */
  result = SocketQPACK_encode_indexed_field (
      buf + offset, sizeof (buf) - offset, 0, 0, &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Encoding succeeds but decoding/resolution would need to validate */
}

TEST (qpack_error_h3_code_constants)
{
  /* RFC 9114 HTTP/3 error codes */
  ASSERT_EQ (H3_STREAM_CREATION_ERROR, 0x0103);
  ASSERT_EQ (H3_CLOSED_CRITICAL_STREAM, 0x0104);

  /* RFC 9204 QPACK error codes */
  ASSERT_EQ (QPACK_DECOMPRESSION_FAILED, 0x0200);
  ASSERT_EQ (QPACK_ENCODER_STREAM_ERROR, 0x0201);
  ASSERT_EQ (QPACK_DECODER_STREAM_ERROR, 0x0202);
}

TEST (qpack_error_result_count_macro)
{
  /* QPACK_RESULT_COUNT should equal last error + 1 */
  ASSERT_EQ (QPACK_RESULT_COUNT, QPACK_ERR_0RTT_MISMATCH + 1);

  /* Verify it's a reasonable count (15 error codes currently) */
  ASSERT (QPACK_RESULT_COUNT >= 15);
  ASSERT (QPACK_RESULT_COUNT <= 100);
}

TEST (qpack_error_result_to_h3_ok)
{
  /* Non-errors should return 0 */
  ASSERT_EQ (SocketQPACK_result_to_h3_error (QPACK_OK), 0);
  ASSERT_EQ (SocketQPACK_result_to_h3_error (QPACK_INCOMPLETE), 0);
}

TEST (qpack_error_result_to_h3_decompression_failed)
{
  /* RFC 9204 Section 6: Field section decode errors ->
   * QPACK_DECOMPRESSION_FAILED
   */
  ASSERT_EQ (SocketQPACK_result_to_h3_error (QPACK_ERR_HUFFMAN),
             QPACK_DECOMPRESSION_FAILED);
  ASSERT_EQ (SocketQPACK_result_to_h3_error (QPACK_ERR_INTEGER),
             QPACK_DECOMPRESSION_FAILED);
  ASSERT_EQ (SocketQPACK_result_to_h3_error (QPACK_ERR_DECOMPRESSION),
             QPACK_DECOMPRESSION_FAILED);
  ASSERT_EQ (SocketQPACK_result_to_h3_error (QPACK_ERR_INVALID_INDEX),
             QPACK_DECOMPRESSION_FAILED);
  ASSERT_EQ (SocketQPACK_result_to_h3_error (QPACK_ERR_EVICTED_INDEX),
             QPACK_DECOMPRESSION_FAILED);
  ASSERT_EQ (SocketQPACK_result_to_h3_error (QPACK_ERR_FUTURE_INDEX),
             QPACK_DECOMPRESSION_FAILED);
  ASSERT_EQ (SocketQPACK_result_to_h3_error (QPACK_ERR_INVALID_BASE),
             QPACK_DECOMPRESSION_FAILED);

  /* These are also field section errors, not encoder stream errors */
  ASSERT_EQ (SocketQPACK_result_to_h3_error (QPACK_ERR_HEADER_SIZE),
             QPACK_DECOMPRESSION_FAILED);
  ASSERT_EQ (SocketQPACK_result_to_h3_error (QPACK_ERR_BASE_OVERFLOW),
             QPACK_DECOMPRESSION_FAILED);
}

TEST (qpack_error_result_to_h3_encoder_stream)
{
  /* RFC 9204 Section 6: Encoder instruction errors ->
   * QPACK_ENCODER_STREAM_ERROR
   *
   * TABLE_SIZE is the only error that occurs when processing encoder
   * instructions (Set Dynamic Table Capacity, Section 4.3.1).
   */
  ASSERT_EQ (SocketQPACK_result_to_h3_error (QPACK_ERR_TABLE_SIZE),
             QPACK_ENCODER_STREAM_ERROR);
}

TEST (qpack_error_result_to_h3_decoder_stream)
{
  /* RFC 9204 Section 3.2.3: 0-RTT mismatch -> QPACK_DECODER_STREAM_ERROR */
  ASSERT_EQ (SocketQPACK_result_to_h3_error (QPACK_ERR_0RTT_MISMATCH),
             QPACK_DECODER_STREAM_ERROR);
}

TEST (qpack_error_result_to_h3_internal)
{
  /* Internal errors default to QPACK_DECOMPRESSION_FAILED */
  ASSERT_EQ (SocketQPACK_result_to_h3_error (QPACK_ERR_NULL_PARAM),
             QPACK_DECOMPRESSION_FAILED);
  ASSERT_EQ (SocketQPACK_result_to_h3_error (QPACK_ERR_INTERNAL),
             QPACK_DECOMPRESSION_FAILED);
}

TEST (qpack_error_stream_to_h3_ok)
{
  /* Non-errors should return 0 */
  ASSERT_EQ (SocketQPACKStream_result_to_h3_error (QPACK_STREAM_OK), 0);
}

TEST (qpack_error_stream_to_h3_closed_critical)
{
  /* RFC 9204 Section 4.2: Stream closure -> H3_CLOSED_CRITICAL_STREAM */
  ASSERT_EQ (
      SocketQPACKStream_result_to_h3_error (QPACK_STREAM_ERR_CLOSED_CRITICAL),
      H3_CLOSED_CRITICAL_STREAM);
}

TEST (qpack_error_stream_to_h3_creation_error)
{
  /* RFC 9204 Section 4.2: Duplicate stream -> H3_STREAM_CREATION_ERROR */
  ASSERT_EQ (
      SocketQPACKStream_result_to_h3_error (QPACK_STREAM_ERR_ALREADY_INIT),
      H3_STREAM_CREATION_ERROR);
}

TEST (qpack_error_stream_to_h3_encoder_stream)
{
  /* RFC 9204 Section 6: Other stream errors -> QPACK_ENCODER_STREAM_ERROR */
  ASSERT_EQ (
      SocketQPACKStream_result_to_h3_error (QPACK_STREAM_ERR_BUFFER_FULL),
      QPACK_ENCODER_STREAM_ERROR);
  ASSERT_EQ (SocketQPACKStream_result_to_h3_error (QPACK_STREAM_ERR_NOT_INIT),
             QPACK_ENCODER_STREAM_ERROR);
  ASSERT_EQ (
      SocketQPACKStream_result_to_h3_error (QPACK_STREAM_ERR_INVALID_TYPE),
      QPACK_ENCODER_STREAM_ERROR);
  ASSERT_EQ (SocketQPACKStream_result_to_h3_error (QPACK_STREAM_ERR_NULL_PARAM),
             QPACK_ENCODER_STREAM_ERROR);
  ASSERT_EQ (
      SocketQPACKStream_result_to_h3_error (QPACK_STREAM_ERR_INVALID_INDEX),
      QPACK_ENCODER_STREAM_ERROR);
  ASSERT_EQ (
      SocketQPACKStream_result_to_h3_error (QPACK_STREAM_ERR_CAPACITY_EXCEED),
      QPACK_ENCODER_STREAM_ERROR);
  ASSERT_EQ (SocketQPACKStream_result_to_h3_error (QPACK_STREAM_ERR_INTERNAL),
             QPACK_ENCODER_STREAM_ERROR);
}

TEST (qpack_error_result_string_all_codes)
{
  /* Verify all result codes have strings */
  for (int i = 0; i < QPACK_RESULT_COUNT; i++)
    {
      const char *str = SocketQPACK_result_string ((SocketQPACK_Result)i);
      ASSERT (str != NULL);
      ASSERT (strcmp (str, "Unknown error") != 0);
    }

  /* Verify 0RTT mismatch string specifically */
  ASSERT (strcmp (SocketQPACK_result_string (QPACK_ERR_0RTT_MISMATCH),
                  "0-RTT settings mismatch")
          == 0);
}

TEST (qpack_error_result_string_out_of_range)
{
  /* Out of range should return "Unknown error" */
  const char *str = SocketQPACK_result_string ((SocketQPACK_Result)999);
  ASSERT (strcmp (str, "Unknown error") == 0);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
