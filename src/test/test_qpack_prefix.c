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
 * MAX ENTRIES ALIAS TESTS
 * ============================================================================
 */

TEST (qpack_max_entries_alias)
{
  /* Verify alias function produces same results */
  ASSERT_EQ (SocketQPACK_max_entries (0), SocketQPACK_compute_max_entries (0));
  ASSERT_EQ (SocketQPACK_max_entries (4096),
             SocketQPACK_compute_max_entries (4096));
  ASSERT_EQ (SocketQPACK_max_entries (65536),
             SocketQPACK_compute_max_entries (65536));
}

/* ============================================================================
 * ENCODE REQUIRED INSERT COUNT TESTS (RFC 9204 Section 4.5.1.1)
 * ============================================================================
 */

TEST (qpack_encode_ric_null_output)
{
  SocketQPACK_Result result
      = SocketQPACK_encode_required_insert_count (10, 128, NULL);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_encode_ric_zero)
{
  uint64_t encoded = 999;
  SocketQPACK_Result result
      = SocketQPACK_encode_required_insert_count (0, 128, &encoded);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (encoded, 0);
}

TEST (qpack_encode_ric_zero_with_zero_max_entries)
{
  /* RIC=0 should succeed even with max_entries=0 */
  uint64_t encoded = 999;
  SocketQPACK_Result result
      = SocketQPACK_encode_required_insert_count (0, 0, &encoded);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (encoded, 0);
}

TEST (qpack_encode_ric_nonzero_with_zero_max_entries)
{
  /* Non-zero RIC with max_entries=0 should fail */
  uint64_t encoded = 999;
  SocketQPACK_Result result
      = SocketQPACK_encode_required_insert_count (10, 0, &encoded);
  ASSERT_EQ (result, QPACK_ERR_TABLE_SIZE);
}

TEST (qpack_encode_ric_one)
{
  /* MaxEntries=128, FullRange=256
   * RIC=1: EncodedRIC = (1 % 256) + 1 = 2
   */
  uint64_t encoded = 0;
  SocketQPACK_Result result
      = SocketQPACK_encode_required_insert_count (1, 128, &encoded);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (encoded, 2);
}

TEST (qpack_encode_ric_wraps_at_full_range)
{
  /* MaxEntries=128, FullRange=256
   * RIC=300: EncodedRIC = (300 % 256) + 1 = 45
   */
  uint64_t encoded = 0;
  SocketQPACK_Result result
      = SocketQPACK_encode_required_insert_count (300, 128, &encoded);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (encoded, 45);
}

TEST (qpack_encode_ric_at_boundary)
{
  /* MaxEntries=128, FullRange=256
   * RIC=256: EncodedRIC = (256 % 256) + 1 = 1
   */
  uint64_t encoded = 0;
  SocketQPACK_Result result
      = SocketQPACK_encode_required_insert_count (256, 128, &encoded);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (encoded, 1);
}

TEST (qpack_encode_ric_max_in_range)
{
  /* MaxEntries=128, FullRange=256
   * RIC=255: EncodedRIC = (255 % 256) + 1 = 256
   */
  uint64_t encoded = 0;
  SocketQPACK_Result result
      = SocketQPACK_encode_required_insert_count (255, 128, &encoded);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (encoded, 256);
}

/* ============================================================================
 * DECODE REQUIRED INSERT COUNT TESTS (RFC 9204 Section 4.5.1.1)
 * ============================================================================
 */

TEST (qpack_decode_ric_null_output)
{
  SocketQPACK_Result result
      = SocketQPACK_decode_required_insert_count (10, 128, 100, NULL);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_decode_ric_zero)
{
  uint64_t ric = 999;
  SocketQPACK_Result result
      = SocketQPACK_decode_required_insert_count (0, 128, 100, &ric);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (ric, 0);
}

TEST (qpack_decode_ric_zero_with_zero_max_entries)
{
  /* EncodedRIC=0 should succeed even with max_entries=0 */
  uint64_t ric = 999;
  SocketQPACK_Result result
      = SocketQPACK_decode_required_insert_count (0, 0, 0, &ric);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (ric, 0);
}

TEST (qpack_decode_ric_nonzero_with_zero_max_entries)
{
  /* Non-zero EncodedRIC with max_entries=0 should fail */
  uint64_t ric = 999;
  SocketQPACK_Result result
      = SocketQPACK_decode_required_insert_count (10, 0, 100, &ric);
  ASSERT_EQ (result, QPACK_ERR_TABLE_SIZE);
}

TEST (qpack_decode_ric_simple)
{
  /* MaxEntries=128, FullRange=256
   * EncodedRIC=2, TotalInserts=100
   * MaxValue = 100 + 128 = 228
   * MaxWrapped = floor(228/256)*256 = 0
   * RIC = 0 + 2 - 1 = 1
   */
  uint64_t ric = 0;
  SocketQPACK_Result result
      = SocketQPACK_decode_required_insert_count (2, 128, 100, &ric);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (ric, 1);
}

TEST (qpack_decode_ric_with_wraparound)
{
  /* MaxEntries=128, FullRange=256
   * EncodedRIC=45, TotalInserts=350
   * MaxValue = 350 + 128 = 478
   * MaxWrapped = floor(478/256)*256 = 256
   * RIC = 256 + 45 - 1 = 300
   * 300 <= 478, no adjustment needed
   */
  uint64_t ric = 0;
  SocketQPACK_Result result
      = SocketQPACK_decode_required_insert_count (45, 128, 350, &ric);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (ric, 300);
}

TEST (qpack_decode_ric_exceeds_full_range)
{
  /* EncodedRIC > FullRange should fail
   * MaxEntries=128, FullRange=256
   * EncodedRIC=300 > 256
   */
  uint64_t ric = 0;
  SocketQPACK_Result result
      = SocketQPACK_decode_required_insert_count (300, 128, 100, &ric);
  ASSERT_EQ (result, QPACK_ERR_DECOMPRESSION);
}

TEST (qpack_decode_ric_exceeds_total_inserts)
{
  /* Decoded RIC > TotalInserts should fail
   * MaxEntries=128, FullRange=256
   * EncodedRIC=100, TotalInserts=50
   * MaxValue = 50 + 128 = 178
   * MaxWrapped = 0
   * RIC = 0 + 100 - 1 = 99
   * 99 > 50, so error
   */
  uint64_t ric = 0;
  SocketQPACK_Result result
      = SocketQPACK_decode_required_insert_count (100, 128, 50, &ric);
  ASSERT_EQ (result, QPACK_ERR_DECOMPRESSION);
}

TEST (qpack_decode_ric_at_full_range_boundary)
{
  /* MaxEntries=128, FullRange=256
   * EncodedRIC=256 (max valid), TotalInserts=300
   * MaxValue = 300 + 128 = 428
   * MaxWrapped = 256
   * RIC = 256 + 256 - 1 = 511
   * 511 > 428, so RIC = 511 - 256 = 255
   * 255 <= 300, valid
   */
  uint64_t ric = 0;
  SocketQPACK_Result result
      = SocketQPACK_decode_required_insert_count (256, 128, 300, &ric);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (ric, 255);
}

/* ============================================================================
 * ENCODE/DECODE ROUND-TRIP TESTS (RFC 9204 Section 4.5.1.1)
 * ============================================================================
 */

TEST (qpack_ric_roundtrip_zero)
{
  uint64_t encoded = 999;
  uint64_t decoded = 999;

  SocketQPACK_Result result
      = SocketQPACK_encode_required_insert_count (0, 128, &encoded);
  ASSERT_EQ (result, QPACK_OK);

  result
      = SocketQPACK_decode_required_insert_count (encoded, 128, 100, &decoded);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded, 0);
}

TEST (qpack_ric_roundtrip_small)
{
  uint64_t encoded = 0;
  uint64_t decoded = 0;

  /* Encode RIC=42 */
  SocketQPACK_Result result
      = SocketQPACK_encode_required_insert_count (42, 128, &encoded);
  ASSERT_EQ (result, QPACK_OK);

  /* Decode with TotalInserts=100 (> 42) */
  result
      = SocketQPACK_decode_required_insert_count (encoded, 128, 100, &decoded);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded, 42);
}

TEST (qpack_ric_roundtrip_with_wrap)
{
  uint64_t encoded = 0;
  uint64_t decoded = 0;

  /* Encode RIC=300 with MaxEntries=128 (FullRange=256)
   * EncodedRIC = (300 % 256) + 1 = 45
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_required_insert_count (300, 128, &encoded);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (encoded, 45);

  /* Decode with TotalInserts=350 (> 300)
   * MaxValue = 350 + 128 = 478
   * MaxWrapped = 256
   * RIC = 256 + 45 - 1 = 300
   */
  result
      = SocketQPACK_decode_required_insert_count (encoded, 128, 350, &decoded);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded, 300);
}

TEST (qpack_ric_roundtrip_various_capacities)
{
  /* Test with different MaxEntries values
   *
   * RFC 9204 Section 4.5.1.1: The decoder must have TotalInserts within
   * MaxEntries of the actual RIC for wrap-around detection to work.
   * So we use total_inserts = ric (encoder and decoder are synchronized).
   */
  uint64_t test_rics[] = { 1, 10, 50, 100, 200, 500, 1000 };
  uint64_t max_entries_vals[] = { 16, 64, 128, 256, 512, 2048 };

  for (size_t i = 0; i < sizeof (test_rics) / sizeof (test_rics[0]); i++)
    {
      uint64_t ric = test_rics[i];

      for (size_t j = 0;
           j < sizeof (max_entries_vals) / sizeof (max_entries_vals[0]);
           j++)
        {
          uint64_t max_entries = max_entries_vals[j];
          uint64_t encoded = 0;
          uint64_t decoded = 0;

          SocketQPACK_Result result = SocketQPACK_encode_required_insert_count (
              ric, max_entries, &encoded);
          ASSERT_EQ (result, QPACK_OK);

          /*
           * For correct wrap-around detection, TotalInserts must be within
           * MaxEntries of RIC. Use TotalInserts = RIC for synchronized
           * encoder/decoder.
           */
          uint64_t total_inserts = ric;
          result = SocketQPACK_decode_required_insert_count (
              encoded, max_entries, total_inserts, &decoded);
          ASSERT_EQ (result, QPACK_OK);
          ASSERT_EQ (decoded, ric);
        }
    }
}

TEST (qpack_ric_roundtrip_values_0_to_512)
{
  /* Per test plan: round-trip for values 0 to 512
   *
   * RFC 9204 Section 4.5.1.1: The wrap-around detection requires
   * TotalInserts to be within MaxEntries of the actual RIC.
   * Use TotalInserts = RIC for synchronized encoder/decoder.
   */
  uint64_t max_entries = 128; /* FullRange = 256 */

  for (uint64_t ric = 0; ric <= 512; ric++)
    {
      uint64_t encoded = 0;
      uint64_t decoded = 0;

      SocketQPACK_Result result = SocketQPACK_encode_required_insert_count (
          ric, max_entries, &encoded);
      ASSERT_EQ (result, QPACK_OK);

      /* Use TotalInserts = RIC for synchronized state */
      uint64_t total_inserts = ric;
      result = SocketQPACK_decode_required_insert_count (
          encoded, max_entries, total_inserts, &decoded);
      ASSERT_EQ (result, QPACK_OK);
      ASSERT_EQ (decoded, ric);
    }
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
