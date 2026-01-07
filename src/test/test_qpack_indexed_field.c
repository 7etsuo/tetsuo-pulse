/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_indexed_field.c
 * @brief Unit tests for QPACK Indexed Field Line (RFC 9204 Section 4.5.2)
 *
 * Tests encoding, decoding, and resolution of Indexed Field Line
 * representation.
 */

#include <string.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACK.h"
#include "test/Test.h"

/* ============================================================================
 * ENCODE NULL PARAMETER TESTS
 * ============================================================================
 */

TEST (qpack_indexed_field_encode_null_output)
{
  size_t written = 999;
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (NULL, 16, 0, 1, &written);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_indexed_field_encode_null_written)
{
  unsigned char buf[16];
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 0, 1, NULL);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_indexed_field_encode_zero_buffer)
{
  unsigned char buf[1];
  size_t written = 999;
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, 0, 0, 1, &written);
  ASSERT_EQ (result, QPACK_ERR_TABLE_SIZE);
}

/* ============================================================================
 * ENCODE STATIC TABLE TESTS
 * ============================================================================
 */

TEST (qpack_indexed_field_encode_static_index_0)
{
  unsigned char buf[16];
  size_t written = 0;

  /* Static index 0 (:authority): T=1, Index=0
   * Wire format: 11000000 = 0xC0
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 0, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 1);
  ASSERT_EQ (buf[0], 0xC0);
}

TEST (qpack_indexed_field_encode_static_index_1)
{
  unsigned char buf[16];
  size_t written = 0;

  /* Static index 1 (:path /): T=1, Index=1
   * Wire format: 11000001 = 0xC1
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 1, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 1);
  ASSERT_EQ (buf[0], 0xC1);
}

TEST (qpack_indexed_field_encode_static_index_62)
{
  unsigned char buf[16];
  size_t written = 0;

  /* Static index 62: T=1, Index=62 (fits in 6-bit prefix without continuation)
   * Wire format: 0xC0 | 62 = 0xC0 | 0x3E = 0xFE
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 62, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 1);
  ASSERT_EQ (buf[0], 0xFE);
}

TEST (qpack_indexed_field_encode_static_index_63)
{
  unsigned char buf[16];
  size_t written = 0;

  /* Static index 63: T=1, Index=63 (2^6-1 signals multi-byte)
   * RFC 7541 Section 5.1: When value == (2^N-1), it signals continuation.
   * First byte: 0xC0 | 0x3F = 0xFF (signal continuation)
   * Continuation: 63 - 63 = 0, encoded as 0x00
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 63, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 2);
  ASSERT_EQ (buf[0], 0xFF);
  ASSERT_EQ (buf[1], 0x00);
}

TEST (qpack_indexed_field_encode_static_index_64)
{
  unsigned char buf[16];
  size_t written = 0;

  /* Static index 64: needs multi-byte encoding
   * First byte: 0xC0 | 0x3F = 0xFF (signal continuation)
   * Continuation: 64 - 63 = 1, encoded as 0x01 (with MSB=0)
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 64, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 2);
  ASSERT_EQ (buf[0], 0xFF);
  ASSERT_EQ (buf[1], 0x01);
}

TEST (qpack_indexed_field_encode_static_index_98)
{
  unsigned char buf[16];
  size_t written = 0;

  /* Static index 98 (maximum valid): needs multi-byte encoding
   * First byte: 0xFF (signal continuation)
   * Continuation: 98 - 63 = 35, encoded as 0x23 (with MSB=0)
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 98, 1, &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 2);
  ASSERT_EQ (buf[0], 0xFF);
  ASSERT_EQ (buf[1], 0x23); /* 35 = 0x23 */
}

TEST (qpack_indexed_field_encode_static_index_99_invalid)
{
  unsigned char buf[16];
  size_t written = 999;

  /* Static index 99 is out of range (max is 98) */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 99, 1, &written);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);
}

TEST (qpack_indexed_field_encode_static_index_large_invalid)
{
  unsigned char buf[16];
  size_t written = 999;

  /* Any static index > 98 is invalid */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 1000, 1, &written);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);
}

/* ============================================================================
 * ENCODE DYNAMIC TABLE TESTS
 * ============================================================================
 */

TEST (qpack_indexed_field_encode_dynamic_index_0)
{
  unsigned char buf[16];
  size_t written = 0;

  /* Dynamic relative index 0: T=0, Index=0
   * Wire format: 10000000 = 0x80
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 0, 0, &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 1);
  ASSERT_EQ (buf[0], 0x80);
}

TEST (qpack_indexed_field_encode_dynamic_index_5)
{
  unsigned char buf[16];
  size_t written = 0;

  /* Dynamic relative index 5: T=0, Index=5
   * Wire format: 10000101 = 0x85
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 5, 0, &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 1);
  ASSERT_EQ (buf[0], 0x85);
}

TEST (qpack_indexed_field_encode_dynamic_large_index)
{
  unsigned char buf[16];
  size_t written = 0;

  /* Dynamic relative index 100: needs multi-byte encoding
   * First byte: 0x80 | 0x3F = 0xBF (signal continuation)
   * Continuation: 100 - 63 = 37, encoded as 0x25
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 100, 0, &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 2);
  ASSERT_EQ (buf[0], 0xBF);
  ASSERT_EQ (buf[1], 0x25); /* 37 = 0x25 */
}

/* ============================================================================
 * DECODE NULL PARAMETER TESTS
 * ============================================================================
 */

TEST (qpack_indexed_field_decode_null_index)
{
  unsigned char buf[] = { 0xC0 };
  int is_static;
  size_t consumed = 999;
  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), NULL, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_indexed_field_decode_null_is_static)
{
  unsigned char buf[] = { 0xC0 };
  uint64_t index;
  size_t consumed = 999;
  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, NULL, &consumed);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_indexed_field_decode_null_consumed)
{
  unsigned char buf[] = { 0xC0 };
  uint64_t index;
  int is_static;
  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, NULL);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_indexed_field_decode_empty_input)
{
  uint64_t index = 999;
  int is_static = 999;
  size_t consumed = 999;
  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      NULL, 0, &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_INCOMPLETE);
  ASSERT_EQ (consumed, 0);
}

/* ============================================================================
 * DECODE STATIC TABLE TESTS
 * ============================================================================
 */

TEST (qpack_indexed_field_decode_static_index_0)
{
  /* 0xC0 = 11000000 -> T=1 (static), index=0 */
  unsigned char buf[] = { 0xC0 };
  uint64_t index = 999;
  int is_static = 0;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 1);
  ASSERT_EQ (is_static, 1);
  ASSERT_EQ (index, 0);
}

TEST (qpack_indexed_field_decode_static_index_1)
{
  /* 0xC1 = 11000001 -> T=1 (static), index=1 */
  unsigned char buf[] = { 0xC1 };
  uint64_t index = 999;
  int is_static = 0;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 1);
  ASSERT_EQ (is_static, 1);
  ASSERT_EQ (index, 1);
}

TEST (qpack_indexed_field_decode_static_index_62)
{
  /* 0xFE = 11111110 -> T=1 (static), index=62 (max single byte) */
  unsigned char buf[] = { 0xFE };
  uint64_t index = 999;
  int is_static = 0;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 1);
  ASSERT_EQ (is_static, 1);
  ASSERT_EQ (index, 62);
}

TEST (qpack_indexed_field_decode_static_index_63)
{
  /* 0xFF 0x00 = T=1, index=63 (needs continuation) */
  unsigned char buf[] = { 0xFF, 0x00 };
  uint64_t index = 999;
  int is_static = 0;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 2);
  ASSERT_EQ (is_static, 1);
  ASSERT_EQ (index, 63);
}

TEST (qpack_indexed_field_decode_static_index_64)
{
  /* 0xFF 0x01 -> T=1, index=63+1=64 */
  unsigned char buf[] = { 0xFF, 0x01 };
  uint64_t index = 999;
  int is_static = 0;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 2);
  ASSERT_EQ (is_static, 1);
  ASSERT_EQ (index, 64);
}

TEST (qpack_indexed_field_decode_static_index_98)
{
  /* 0xFF 0x23 -> T=1, index=63+35=98 (maximum valid) */
  unsigned char buf[] = { 0xFF, 0x23 };
  uint64_t index = 999;
  int is_static = 0;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 2);
  ASSERT_EQ (is_static, 1);
  ASSERT_EQ (index, 98);
}

TEST (qpack_indexed_field_decode_static_index_99_invalid)
{
  /* 0xFF 0x24 -> T=1, index=63+36=99 (invalid, > 98) */
  unsigned char buf[] = { 0xFF, 0x24 };
  uint64_t index = 999;
  int is_static = 0;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);
}

/* ============================================================================
 * DECODE DYNAMIC TABLE TESTS
 * ============================================================================
 */

TEST (qpack_indexed_field_decode_dynamic_index_0)
{
  /* 0x80 = 10000000 -> T=0 (dynamic), index=0 */
  unsigned char buf[] = { 0x80 };
  uint64_t index = 999;
  int is_static = 1;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 1);
  ASSERT_EQ (is_static, 0);
  ASSERT_EQ (index, 0);
}

TEST (qpack_indexed_field_decode_dynamic_index_5)
{
  /* 0x85 = 10000101 -> T=0 (dynamic), index=5 */
  unsigned char buf[] = { 0x85 };
  uint64_t index = 999;
  int is_static = 1;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 1);
  ASSERT_EQ (is_static, 0);
  ASSERT_EQ (index, 5);
}

TEST (qpack_indexed_field_decode_dynamic_large_index)
{
  /* 0xBF 0x25 -> T=0 (dynamic), index=63+37=100 */
  unsigned char buf[] = { 0xBF, 0x25 };
  uint64_t index = 999;
  int is_static = 1;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 2);
  ASSERT_EQ (is_static, 0);
  ASSERT_EQ (index, 100);
}

/* ============================================================================
 * DECODE NOT INDEXED FIELD LINE TESTS
 * ============================================================================
 */

TEST (qpack_indexed_field_decode_not_indexed_pattern)
{
  /* 0x00 = 00000000 -> bit 7 is 0, not an indexed field line */
  unsigned char buf[] = { 0x00 };
  uint64_t index = 999;
  int is_static = 999;
  size_t consumed = 999;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_ERR_INTERNAL);
}

TEST (qpack_indexed_field_decode_literal_pattern)
{
  /* 0x40 = 01000000 -> bit 7 is 0, literal field line pattern */
  unsigned char buf[] = { 0x40 };
  uint64_t index = 999;
  int is_static = 999;
  size_t consumed = 999;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_ERR_INTERNAL);
}

/* ============================================================================
 * ROUND-TRIP TESTS
 * ============================================================================
 */

TEST (qpack_indexed_field_roundtrip_static_0)
{
  unsigned char buf[16];
  size_t written = 0;
  uint64_t index = 999;
  int is_static = 0;
  size_t consumed = 0;

  /* Encode static index 0 */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 0, 1, &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode */
  result = SocketQPACK_decode_indexed_field (
      buf, written, &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, written);
  ASSERT_EQ (is_static, 1);
  ASSERT_EQ (index, 0);
}

TEST (qpack_indexed_field_roundtrip_static_98)
{
  unsigned char buf[16];
  size_t written = 0;
  uint64_t index = 999;
  int is_static = 0;
  size_t consumed = 0;

  /* Encode static index 98 (max valid) */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 98, 1, &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode */
  result = SocketQPACK_decode_indexed_field (
      buf, written, &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, written);
  ASSERT_EQ (is_static, 1);
  ASSERT_EQ (index, 98);
}

TEST (qpack_indexed_field_roundtrip_dynamic_0)
{
  unsigned char buf[16];
  size_t written = 0;
  uint64_t index = 999;
  int is_static = 1;
  size_t consumed = 0;

  /* Encode dynamic index 0 */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 0, 0, &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode */
  result = SocketQPACK_decode_indexed_field (
      buf, written, &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, written);
  ASSERT_EQ (is_static, 0);
  ASSERT_EQ (index, 0);
}

TEST (qpack_indexed_field_roundtrip_dynamic_large)
{
  unsigned char buf[16];
  size_t written = 0;
  uint64_t index = 999;
  int is_static = 1;
  size_t consumed = 0;

  /* Encode dynamic index 500 */
  SocketQPACK_Result result
      = SocketQPACK_encode_indexed_field (buf, sizeof (buf), 500, 0, &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode */
  result = SocketQPACK_decode_indexed_field (
      buf, written, &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, written);
  ASSERT_EQ (is_static, 0);
  ASSERT_EQ (index, 500);
}

/* ============================================================================
 * RESOLVE TESTS
 * ============================================================================
 */

TEST (qpack_indexed_field_resolve_null_abs_index)
{
  SocketQPACK_Result result
      = SocketQPACK_resolve_indexed_field (0, 1, 100, 0, NULL);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_indexed_field_resolve_static_valid)
{
  uint64_t abs_index = 999;

  /* Static index 50 -> returns 50 (no conversion) */
  SocketQPACK_Result result
      = SocketQPACK_resolve_indexed_field (50, 1, 100, 0, &abs_index);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (abs_index, 50);
}

TEST (qpack_indexed_field_resolve_static_invalid)
{
  uint64_t abs_index = 999;

  /* Static index 99 is invalid */
  SocketQPACK_Result result
      = SocketQPACK_resolve_indexed_field (99, 1, 100, 0, &abs_index);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);
}

TEST (qpack_indexed_field_resolve_dynamic_valid)
{
  uint64_t abs_index = 999;

  /* Dynamic relative index 0 with Base=100 -> absolute = 100 - 0 - 1 = 99 */
  SocketQPACK_Result result
      = SocketQPACK_resolve_indexed_field (0, 0, 100, 0, &abs_index);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (abs_index, 99);
}

TEST (qpack_indexed_field_resolve_dynamic_index_5)
{
  uint64_t abs_index = 999;

  /* Dynamic relative index 5 with Base=100 -> absolute = 100 - 5 - 1 = 94 */
  SocketQPACK_Result result
      = SocketQPACK_resolve_indexed_field (5, 0, 100, 0, &abs_index);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (abs_index, 94);
}

TEST (qpack_indexed_field_resolve_dynamic_evicted)
{
  uint64_t abs_index = 999;

  /* Dynamic relative index 95 with Base=100 -> absolute = 100 - 95 - 1 = 4
   * But dropped_count=10, so index 4 was evicted
   */
  SocketQPACK_Result result
      = SocketQPACK_resolve_indexed_field (95, 0, 100, 10, &abs_index);
  ASSERT_EQ (result, QPACK_ERR_EVICTED_INDEX);
}

TEST (qpack_indexed_field_resolve_dynamic_out_of_range)
{
  uint64_t abs_index = 999;

  /* Dynamic relative index 100 with Base=100 -> would cause underflow */
  SocketQPACK_Result result
      = SocketQPACK_resolve_indexed_field (100, 0, 100, 0, &abs_index);
  ASSERT_EQ (result, QPACK_ERR_INVALID_INDEX);
}

/* ============================================================================
 * IS INDEXED FIELD LINE TESTS
 * ============================================================================
 */

TEST (qpack_is_indexed_field_line_static)
{
  /* 0xC0 = 11000000 -> indexed field line (static) */
  ASSERT (SocketQPACK_is_indexed_field_line (0xC0) != 0);
}

TEST (qpack_is_indexed_field_line_dynamic)
{
  /* 0x80 = 10000000 -> indexed field line (dynamic) */
  ASSERT (SocketQPACK_is_indexed_field_line (0x80) != 0);
}

TEST (qpack_is_indexed_field_line_false_literal)
{
  /* 0x40 = 01000000 -> NOT indexed field line */
  ASSERT (SocketQPACK_is_indexed_field_line (0x40) == 0);
}

TEST (qpack_is_indexed_field_line_false_zero)
{
  /* 0x00 = 00000000 -> NOT indexed field line */
  ASSERT (SocketQPACK_is_indexed_field_line (0x00) == 0);
}

TEST (qpack_is_indexed_field_line_false_0x7F)
{
  /* 0x7F = 01111111 -> NOT indexed field line */
  ASSERT (SocketQPACK_is_indexed_field_line (0x7F) == 0);
}

/* ============================================================================
 * INCOMPLETE INPUT TESTS
 * ============================================================================
 */

TEST (qpack_indexed_field_decode_incomplete_multi_byte)
{
  /* 0xFF needs continuation byte */
  unsigned char buf[] = { 0xFF };
  uint64_t index = 999;
  int is_static = 999;
  size_t consumed = 999;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_INCOMPLETE);
}

TEST (qpack_indexed_field_decode_incomplete_dynamic_multi_byte)
{
  /* 0xBF needs continuation byte */
  unsigned char buf[] = { 0xBF };
  uint64_t index = 999;
  int is_static = 999;
  size_t consumed = 999;

  SocketQPACK_Result result = SocketQPACK_decode_indexed_field (
      buf, sizeof (buf), &index, &is_static, &consumed);
  ASSERT_EQ (result, QPACK_INCOMPLETE);
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
