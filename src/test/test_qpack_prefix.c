/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_prefix.c
 * @brief Unit tests for QPACK Field Section Prefix (RFC 9204 Section 4.5.1)
 *
 * Tests encoding, decoding, and validation of the Field Section Prefix.
 */

#include <string.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACK.h"
#include "test/Test.h"

/* ============================================================================
 * COMPUTE MAX ENTRIES TESTS
 * ============================================================================
 */

TEST (qpack_compute_max_entries_zero)
{
  uint64_t max_entries = SocketQPACK_compute_max_entries (0);
  ASSERT_EQ (max_entries, 0);
}

TEST (qpack_compute_max_entries_small)
{
  /* 31 bytes / 32 = 0 entries */
  uint64_t max_entries = SocketQPACK_compute_max_entries (31);
  ASSERT_EQ (max_entries, 0);
}

TEST (qpack_compute_max_entries_exact)
{
  /* 32 bytes / 32 = 1 entry */
  uint64_t max_entries = SocketQPACK_compute_max_entries (32);
  ASSERT_EQ (max_entries, 1);
}

TEST (qpack_compute_max_entries_default)
{
  /* 4096 bytes / 32 = 128 entries */
  uint64_t max_entries = SocketQPACK_compute_max_entries (4096);
  ASSERT_EQ (max_entries, 128);
}

TEST (qpack_compute_max_entries_large)
{
  /* 64KB / 32 = 2048 entries */
  uint64_t max_entries = SocketQPACK_compute_max_entries (65536);
  ASSERT_EQ (max_entries, 2048);
}

/* ============================================================================
 * ENCODE PREFIX NULL PARAMETER TESTS
 * ============================================================================
 */

TEST (qpack_encode_prefix_null_output)
{
  size_t written = 999;
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (0, 0, 128, NULL, 16, &written);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_encode_prefix_null_written)
{
  unsigned char buf[16];
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (0, 0, 128, buf, sizeof (buf), NULL);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_encode_prefix_zero_buffer)
{
  unsigned char buf[1];
  size_t written = 999;
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (0, 0, 128, buf, 0, &written);
  ASSERT_EQ (result, QPACK_ERR_TABLE_SIZE);
}

/* ============================================================================
 * ENCODE PREFIX BASIC TESTS
 * ============================================================================
 */

TEST (qpack_encode_prefix_ric_zero_base_zero)
{
  unsigned char buf[16];
  size_t written = 0;

  /* RIC=0, Base=0 -> EncodedRIC=0, DeltaBase=0, S=0 */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (0, 0, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 2);
  /* First byte: EncodedRIC=0 */
  ASSERT_EQ (buf[0], 0x00);
  /* Second byte: S=0, DeltaBase=0 */
  ASSERT_EQ (buf[1], 0x00);
}

TEST (qpack_encode_prefix_ric_one_base_one)
{
  unsigned char buf[16];
  size_t written = 0;

  /* RIC=1, Base=1 with MaxEntries=128
   * EncodedRIC = (1 % 256) + 1 = 2
   * DeltaBase = 1 - 1 = 0, S=0
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (1, 1, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 2);
  ASSERT_EQ (buf[0], 0x02);
  ASSERT_EQ (buf[1], 0x00);
}

TEST (qpack_encode_prefix_positive_delta)
{
  unsigned char buf[16];
  size_t written = 0;

  /* RIC=10, Base=15 with MaxEntries=128
   * EncodedRIC = (10 % 256) + 1 = 11
   * DeltaBase = 15 - 10 = 5, S=0
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (10, 15, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 2);
  ASSERT_EQ (buf[0], 11);
  /* S=0, DeltaBase=5 -> 0x05 */
  ASSERT_EQ (buf[1], 0x05);
}

TEST (qpack_encode_prefix_negative_delta)
{
  unsigned char buf[16];
  size_t written = 0;

  /* RIC=10, Base=5 with MaxEntries=128
   * EncodedRIC = (10 % 256) + 1 = 11
   * DeltaBase = 10 - 5 - 1 = 4, S=1
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (10, 5, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 2);
  ASSERT_EQ (buf[0], 11);
  /* S=1, DeltaBase=4 -> 0x80 | 0x04 = 0x84 */
  ASSERT_EQ (buf[1], 0x84);
}

TEST (qpack_encode_prefix_base_zero_ric_nonzero)
{
  unsigned char buf[16];
  size_t written = 0;

  /* RIC=5, Base=0 with MaxEntries=128
   * EncodedRIC = (5 % 256) + 1 = 6
   * DeltaBase = 5 - 0 - 1 = 4, S=1
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (5, 0, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 2);
  ASSERT_EQ (buf[0], 6);
  /* S=1, DeltaBase=4 -> 0x84 */
  ASSERT_EQ (buf[1], 0x84);
}

TEST (qpack_encode_prefix_large_ric)
{
  unsigned char buf[16];
  size_t written = 0;

  /* RIC=300, Base=300 with MaxEntries=128
   * EncodedRIC = (300 % 256) + 1 = 45
   * DeltaBase = 0, S=0
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (300, 300, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 2);
  ASSERT_EQ (buf[0], 45);
  ASSERT_EQ (buf[1], 0x00);
}

TEST (qpack_encode_prefix_max_entries_zero)
{
  unsigned char buf[16];
  size_t written = 999;

  /* max_entries=0 with non-zero RIC should fail */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (10, 10, 0, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_ERR_TABLE_SIZE);
}

/* ============================================================================
 * DECODE PREFIX NULL PARAMETER TESTS
 * ============================================================================
 */

TEST (qpack_decode_prefix_null_prefix)
{
  unsigned char buf[] = { 0x00, 0x00 };
  size_t consumed = 999;
  SocketQPACK_Result result
      = SocketQPACK_decode_prefix (buf, sizeof (buf), 128, 0, NULL, &consumed);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_decode_prefix_null_consumed)
{
  unsigned char buf[] = { 0x00, 0x00 };
  SocketQPACK_FieldSectionPrefix prefix;
  SocketQPACK_Result result
      = SocketQPACK_decode_prefix (buf, sizeof (buf), 128, 0, &prefix, NULL);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_decode_prefix_empty_input)
{
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 999;
  SocketQPACK_Result result
      = SocketQPACK_decode_prefix (NULL, 0, 128, 0, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_INCOMPLETE);
  ASSERT_EQ (consumed, 0);
}

/* ============================================================================
 * DECODE PREFIX BASIC TESTS
 * ============================================================================
 */

TEST (qpack_decode_prefix_ric_zero_base_zero)
{
  unsigned char buf[] = { 0x00, 0x00 };
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_prefix (
      buf, sizeof (buf), 128, 0, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 2);
  ASSERT_EQ (prefix.required_insert_count, 0);
  ASSERT_EQ (prefix.base, 0);
  ASSERT_EQ (prefix.delta_base, 0);
}

TEST (qpack_decode_prefix_ric_one_base_one)
{
  /* EncodedRIC=2 -> RIC=1, S=0, DeltaBase=0 -> Base=1 */
  unsigned char buf[] = { 0x02, 0x00 };
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_prefix (
      buf, sizeof (buf), 128, 10, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 2);
  ASSERT_EQ (prefix.required_insert_count, 1);
  ASSERT_EQ (prefix.base, 1);
  ASSERT_EQ (prefix.delta_base, 0);
}

TEST (qpack_decode_prefix_positive_delta)
{
  /* EncodedRIC=11 -> RIC=10, S=0, DeltaBase=5 -> Base=15 */
  unsigned char buf[] = { 11, 0x05 };
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_prefix (
      buf, sizeof (buf), 128, 20, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 2);
  ASSERT_EQ (prefix.required_insert_count, 10);
  ASSERT_EQ (prefix.base, 15);
  ASSERT_EQ (prefix.delta_base, 5);
}

TEST (qpack_decode_prefix_negative_delta)
{
  /* EncodedRIC=11 -> RIC=10, S=1, DeltaBase=4 -> Base=10-4-1=5 */
  unsigned char buf[] = { 11, 0x84 };
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_prefix (
      buf, sizeof (buf), 128, 20, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, 2);
  ASSERT_EQ (prefix.required_insert_count, 10);
  ASSERT_EQ (prefix.base, 5);
  /* delta_base should be negative: -(4+1) = -5 */
  ASSERT_EQ (prefix.delta_base, -5);
}

TEST (qpack_decode_prefix_ric_exceeds_total)
{
  /* EncodedRIC=11 -> RIC=10, but total_insert_count=5 */
  unsigned char buf[] = { 11, 0x00 };
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_prefix (
      buf, sizeof (buf), 128, 5, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_ERR_DECOMPRESSION);
}

TEST (qpack_decode_prefix_incomplete_ric)
{
  /* Only one byte, but RIC encoding may need more */
  unsigned char buf[] = { 0xFF }; /* 8-bit prefix max, needs continuation */
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_prefix (
      buf, sizeof (buf), 128, 1000, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_INCOMPLETE);
}

TEST (qpack_decode_prefix_incomplete_delta)
{
  /* Only RIC byte, no delta base byte */
  unsigned char buf[] = { 0x02 };
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_prefix (
      buf, sizeof (buf), 128, 10, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_INCOMPLETE);
}

TEST (qpack_decode_prefix_max_entries_zero)
{
  unsigned char buf[] = { 0x02, 0x00 };
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  /* max_entries=0 with non-zero encoded RIC should fail */
  SocketQPACK_Result result = SocketQPACK_decode_prefix (
      buf, sizeof (buf), 0, 10, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_ERR_TABLE_SIZE);
}

/* ============================================================================
 * ROUND-TRIP TESTS
 * ============================================================================
 */

TEST (qpack_prefix_roundtrip_zero)
{
  unsigned char buf[16];
  size_t written = 0;
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  /* Encode RIC=0, Base=0 */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (0, 0, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode */
  result = SocketQPACK_decode_prefix (buf, written, 128, 0, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, written);
  ASSERT_EQ (prefix.required_insert_count, 0);
  ASSERT_EQ (prefix.base, 0);
}

TEST (qpack_prefix_roundtrip_positive_delta)
{
  unsigned char buf[16];
  size_t written = 0;
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  /* Encode RIC=42, Base=50 */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (42, 50, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode */
  result
      = SocketQPACK_decode_prefix (buf, written, 128, 100, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, written);
  ASSERT_EQ (prefix.required_insert_count, 42);
  ASSERT_EQ (prefix.base, 50);
}

TEST (qpack_prefix_roundtrip_negative_delta)
{
  unsigned char buf[16];
  size_t written = 0;
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  /* Encode RIC=42, Base=30 */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (42, 30, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode */
  result
      = SocketQPACK_decode_prefix (buf, written, 128, 100, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, written);
  ASSERT_EQ (prefix.required_insert_count, 42);
  ASSERT_EQ (prefix.base, 30);
}

TEST (qpack_prefix_roundtrip_large_values)
{
  unsigned char buf[32];
  size_t written = 0;
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  /* Encode RIC=1000, Base=1200 with MaxEntries=2048 */
  SocketQPACK_Result result = SocketQPACK_encode_prefix (
      1000, 1200, 2048, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode */
  result = SocketQPACK_decode_prefix (
      buf, written, 2048, 2000, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (consumed, written);
  ASSERT_EQ (prefix.required_insert_count, 1000);
  ASSERT_EQ (prefix.base, 1200);
}

/* ============================================================================
 * VALIDATE PREFIX TESTS
 * ============================================================================
 */

TEST (qpack_validate_prefix_null)
{
  SocketQPACK_Result result = SocketQPACK_validate_prefix (NULL, 100);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_validate_prefix_ric_exceeds)
{
  SocketQPACK_FieldSectionPrefix prefix
      = { .required_insert_count = 100, .delta_base = 0, .base = 100 };

  SocketQPACK_Result result = SocketQPACK_validate_prefix (&prefix, 50);
  ASSERT_EQ (result, QPACK_ERR_DECOMPRESSION);
}

TEST (qpack_validate_prefix_valid_positive)
{
  SocketQPACK_FieldSectionPrefix prefix
      = { .required_insert_count = 42, .delta_base = 8, .base = 50 };

  SocketQPACK_Result result = SocketQPACK_validate_prefix (&prefix, 100);
  ASSERT_EQ (result, QPACK_OK);
}

TEST (qpack_validate_prefix_valid_negative)
{
  SocketQPACK_FieldSectionPrefix prefix
      = { .required_insert_count = 42, .delta_base = -12, .base = 30 };

  SocketQPACK_Result result = SocketQPACK_validate_prefix (&prefix, 100);
  ASSERT_EQ (result, QPACK_OK);
}

TEST (qpack_validate_prefix_valid_zero)
{
  SocketQPACK_FieldSectionPrefix prefix
      = { .required_insert_count = 0, .delta_base = 0, .base = 0 };

  SocketQPACK_Result result = SocketQPACK_validate_prefix (&prefix, 0);
  ASSERT_EQ (result, QPACK_OK);
}

/* ============================================================================
 * EDGE CASE TESTS
 * ============================================================================
 */

TEST (qpack_encode_prefix_delta_base_zero)
{
  unsigned char buf[16];
  size_t written = 0;

  /* RIC=50, Base=50 -> DeltaBase=0, S=0 */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (50, 50, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);
  /* Second byte should be 0x00 (S=0, DeltaBase=0) */
  ASSERT_EQ (buf[1], 0x00);
}

TEST (qpack_decode_prefix_wraparound)
{
  unsigned char buf[16];
  size_t written = 0;
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  /* MaxEntries=128, so FullRange=256
   * Encode RIC=300, which wraps: EncodedRIC = (300 % 256) + 1 = 45
   * With total_insert_count=350, we should recover RIC=300
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (300, 300, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);

  result
      = SocketQPACK_decode_prefix (buf, written, 128, 350, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (prefix.required_insert_count, 300);
  ASSERT_EQ (prefix.base, 300);
}

TEST (qpack_decode_prefix_base_underflow_check)
{
  /* Try to decode with negative delta that would underflow base */
  /* EncodedRIC=2 -> RIC=1, S=1, DeltaBase=5 -> Base=1-5-1=-5 (underflow) */
  unsigned char buf[] = { 0x02, 0x85 };
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_prefix (
      buf, sizeof (buf), 128, 10, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_ERR_DECOMPRESSION);
}

/* ============================================================================
 * MULTI-BYTE INTEGER TESTS
 * ============================================================================
 */

TEST (qpack_encode_prefix_multi_byte_ric)
{
  unsigned char buf[16];
  size_t written = 0;
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  /* With MaxEntries=128, encode RIC=500
   * EncodedRIC = (500 % 256) + 1 = 245
   * 245 fits in 8 bits (< 255), so single byte
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (500, 500, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);

  result
      = SocketQPACK_decode_prefix (buf, written, 128, 600, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (prefix.required_insert_count, 500);
}

TEST (qpack_encode_prefix_multi_byte_delta)
{
  unsigned char buf[16];
  size_t written = 0;
  SocketQPACK_FieldSectionPrefix prefix;
  size_t consumed = 0;

  /* RIC=100, Base=300 -> DeltaBase=200, needs continuation (> 127)
   * For correct decoding, total_insert_count must be >= RIC and allow
   * the modular arithmetic to recover the original RIC.
   * With MaxEntries=128, FullRange=256:
   * - EncodedRIC = (100 % 256) + 1 = 101
   * - For TotalInserts=200: MaxValue=328, MaxWrapped=256, RIC=256+100=356 > 328
   *   So RIC=356-256=100. And 100 <= 200, so validation passes.
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_prefix (100, 300, 128, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT (written > 2); /* Should need continuation bytes */

  result
      = SocketQPACK_decode_prefix (buf, written, 128, 200, &prefix, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (prefix.required_insert_count, 100);
  ASSERT_EQ (prefix.base, 300);
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
