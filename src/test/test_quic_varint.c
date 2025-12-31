/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_varint.c - QUIC Variable-Length Integer unit tests
 *
 * Tests encoding/decoding of QUIC variable-length integers (RFC 9000 §16).
 * Covers boundary values, round-trip encoding, error conditions, and
 * RFC test vectors.
 */

#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICVarInt.h"
#include "test/Test.h"

/* ============================================================================
 * RFC 9000 Section 16 Test Vectors
 * ============================================================================
 */

TEST (quic_varint_decode_1byte_zero)
{
  const uint8_t data[] = { 0x00 };
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);

  ASSERT_EQ (res, QUIC_VARINT_OK);
  ASSERT_EQ (value, 0);
  ASSERT_EQ (consumed, 1);
}

TEST (quic_varint_decode_1byte_max)
{
  const uint8_t data[] = { 0x3F }; /* 63 */
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);

  ASSERT_EQ (res, QUIC_VARINT_OK);
  ASSERT_EQ (value, 63);
  ASSERT_EQ (consumed, 1);
}

TEST (quic_varint_decode_2byte_min)
{
  const uint8_t data[] = { 0x40, 0x40 }; /* 64 */
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);

  ASSERT_EQ (res, QUIC_VARINT_OK);
  ASSERT_EQ (value, 64);
  ASSERT_EQ (consumed, 2);
}

TEST (quic_varint_decode_2byte_max)
{
  const uint8_t data[] = { 0x7F, 0xFF }; /* 16383 */
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);

  ASSERT_EQ (res, QUIC_VARINT_OK);
  ASSERT_EQ (value, 16383);
  ASSERT_EQ (consumed, 2);
}

TEST (quic_varint_decode_4byte_min)
{
  const uint8_t data[] = { 0x80, 0x00, 0x40, 0x00 }; /* 16384 */
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);

  ASSERT_EQ (res, QUIC_VARINT_OK);
  ASSERT_EQ (value, 16384);
  ASSERT_EQ (consumed, 4);
}

TEST (quic_varint_decode_4byte_max)
{
  const uint8_t data[] = { 0xBF, 0xFF, 0xFF, 0xFF }; /* 1073741823 */
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);

  ASSERT_EQ (res, QUIC_VARINT_OK);
  ASSERT_EQ (value, 1073741823);
  ASSERT_EQ (consumed, 4);
}

TEST (quic_varint_decode_8byte_min)
{
  const uint8_t data[]
      = { 0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 }; /* 1073741824 */
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);

  ASSERT_EQ (res, QUIC_VARINT_OK);
  ASSERT_EQ (value, 1073741824);
  ASSERT_EQ (consumed, 8);
}

TEST (quic_varint_decode_8byte_max)
{
  /* 2^62-1 = 4611686018427387903 */
  const uint8_t data[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);

  ASSERT_EQ (res, QUIC_VARINT_OK);
  ASSERT_EQ (value, SOCKETQUICVARINT_MAX);
  ASSERT_EQ (consumed, 8);
}

/* RFC 9000 Appendix A.1 sample values */
TEST (quic_varint_decode_rfc_sample_37)
{
  const uint8_t data[] = { 0x25 }; /* 37 in 1-byte form */
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);

  ASSERT_EQ (res, QUIC_VARINT_OK);
  ASSERT_EQ (value, 37);
  ASSERT_EQ (consumed, 1);
}

TEST (quic_varint_decode_rfc_sample_15293)
{
  const uint8_t data[] = { 0x7B, 0xBD }; /* 15293 in 2-byte form */
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);

  ASSERT_EQ (res, QUIC_VARINT_OK);
  ASSERT_EQ (value, 15293);
  ASSERT_EQ (consumed, 2);
}

TEST (quic_varint_decode_rfc_sample_494878333)
{
  const uint8_t data[] = { 0x9D, 0x7F, 0x3E, 0x7D }; /* 494878333 */
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);

  ASSERT_EQ (res, QUIC_VARINT_OK);
  ASSERT_EQ (value, 494878333);
  ASSERT_EQ (consumed, 4);
}

TEST (quic_varint_decode_rfc_sample_151288809941952652)
{
  const uint8_t data[] = {
    0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C
  }; /* 151288809941952652 */
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);

  ASSERT_EQ (res, QUIC_VARINT_OK);
  ASSERT_EQ (value, 151288809941952652ULL);
  ASSERT_EQ (consumed, 8);
}

/* ============================================================================
 * Encoding Tests
 * ============================================================================
 */

TEST (quic_varint_encode_zero)
{
  uint8_t buf[8];
  size_t len = SocketQUICVarInt_encode (0, buf, sizeof (buf));

  ASSERT_EQ (len, 1);
  ASSERT_EQ (buf[0], 0x00);
}

TEST (quic_varint_encode_1byte_max)
{
  uint8_t buf[8];
  size_t len = SocketQUICVarInt_encode (63, buf, sizeof (buf));

  ASSERT_EQ (len, 1);
  ASSERT_EQ (buf[0], 0x3F);
}

TEST (quic_varint_encode_2byte_min)
{
  uint8_t buf[8];
  size_t len = SocketQUICVarInt_encode (64, buf, sizeof (buf));

  ASSERT_EQ (len, 2);
  ASSERT_EQ (buf[0], 0x40);
  ASSERT_EQ (buf[1], 0x40);
}

TEST (quic_varint_encode_2byte_max)
{
  uint8_t buf[8];
  size_t len = SocketQUICVarInt_encode (16383, buf, sizeof (buf));

  ASSERT_EQ (len, 2);
  ASSERT_EQ (buf[0], 0x7F);
  ASSERT_EQ (buf[1], 0xFF);
}

TEST (quic_varint_encode_4byte_min)
{
  uint8_t buf[8];
  size_t len = SocketQUICVarInt_encode (16384, buf, sizeof (buf));

  ASSERT_EQ (len, 4);
  ASSERT_EQ (buf[0], 0x80);
  ASSERT_EQ (buf[1], 0x00);
  ASSERT_EQ (buf[2], 0x40);
  ASSERT_EQ (buf[3], 0x00);
}

TEST (quic_varint_encode_4byte_max)
{
  uint8_t buf[8];
  size_t len = SocketQUICVarInt_encode (1073741823, buf, sizeof (buf));

  ASSERT_EQ (len, 4);
  ASSERT_EQ (buf[0], 0xBF);
  ASSERT_EQ (buf[1], 0xFF);
  ASSERT_EQ (buf[2], 0xFF);
  ASSERT_EQ (buf[3], 0xFF);
}

TEST (quic_varint_encode_8byte_min)
{
  uint8_t buf[8];
  size_t len = SocketQUICVarInt_encode (1073741824, buf, sizeof (buf));

  ASSERT_EQ (len, 8);
  ASSERT_EQ (buf[0], 0xC0);
  ASSERT_EQ (buf[1], 0x00);
  ASSERT_EQ (buf[2], 0x00);
  ASSERT_EQ (buf[3], 0x00);
  ASSERT_EQ (buf[4], 0x40);
  ASSERT_EQ (buf[5], 0x00);
  ASSERT_EQ (buf[6], 0x00);
  ASSERT_EQ (buf[7], 0x00);
}

TEST (quic_varint_encode_8byte_max)
{
  uint8_t buf[8];
  size_t len
      = SocketQUICVarInt_encode (SOCKETQUICVARINT_MAX, buf, sizeof (buf));

  ASSERT_EQ (len, 8);
  ASSERT_EQ (buf[0], 0xFF);
  ASSERT_EQ (buf[1], 0xFF);
  ASSERT_EQ (buf[2], 0xFF);
  ASSERT_EQ (buf[3], 0xFF);
  ASSERT_EQ (buf[4], 0xFF);
  ASSERT_EQ (buf[5], 0xFF);
  ASSERT_EQ (buf[6], 0xFF);
  ASSERT_EQ (buf[7], 0xFF);
}

/* ============================================================================
 * Round-Trip Tests
 * ============================================================================
 */

TEST (quic_varint_roundtrip_boundary_values)
{
  uint64_t test_values[] = { 0,
                             1,
                             62,
                             63,
                             64,
                             65,
                             16382,
                             16383,
                             16384,
                             16385,
                             1073741822,
                             1073741823,
                             1073741824,
                             1073741825,
                             SOCKETQUICVARINT_MAX - 1,
                             SOCKETQUICVARINT_MAX };

  for (size_t i = 0; i < sizeof (test_values) / sizeof (test_values[0]); i++)
    {
      uint8_t buf[8];
      uint64_t decoded;
      size_t consumed;

      size_t encoded_len
          = SocketQUICVarInt_encode (test_values[i], buf, sizeof (buf));
      ASSERT (encoded_len > 0);

      SocketQUICVarInt_Result res
          = SocketQUICVarInt_decode (buf, encoded_len, &decoded, &consumed);
      ASSERT_EQ (res, QUIC_VARINT_OK);
      ASSERT_EQ (decoded, test_values[i]);
      ASSERT_EQ (consumed, encoded_len);
    }
}

/* ============================================================================
 * Size Calculation Tests
 * ============================================================================
 */

TEST (quic_varint_size_1byte)
{
  ASSERT_EQ (SocketQUICVarInt_size (0), 1);
  ASSERT_EQ (SocketQUICVarInt_size (63), 1);
}

TEST (quic_varint_size_2byte)
{
  ASSERT_EQ (SocketQUICVarInt_size (64), 2);
  ASSERT_EQ (SocketQUICVarInt_size (16383), 2);
}

TEST (quic_varint_size_4byte)
{
  ASSERT_EQ (SocketQUICVarInt_size (16384), 4);
  ASSERT_EQ (SocketQUICVarInt_size (1073741823), 4);
}

TEST (quic_varint_size_8byte)
{
  ASSERT_EQ (SocketQUICVarInt_size (1073741824), 8);
  ASSERT_EQ (SocketQUICVarInt_size (SOCKETQUICVARINT_MAX), 8);
}

TEST (quic_varint_size_overflow)
{
  /* Value larger than maximum should return 0 */
  ASSERT_EQ (SocketQUICVarInt_size (SOCKETQUICVARINT_MAX + 1), 0);
  ASSERT_EQ (SocketQUICVarInt_size (UINT64_MAX), 0);
}

/* ============================================================================
 * Error Condition Tests
 * ============================================================================
 */

TEST (quic_varint_decode_null_data)
{
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (NULL, 10, &value, &consumed);
  ASSERT_EQ (res, QUIC_VARINT_ERROR_NULL);
}

TEST (quic_varint_decode_null_value)
{
  const uint8_t data[] = { 0x00 };
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), NULL, &consumed);
  ASSERT_EQ (res, QUIC_VARINT_ERROR_NULL);
}

TEST (quic_varint_decode_null_consumed)
{
  const uint8_t data[] = { 0x00 };
  uint64_t value;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, NULL);
  ASSERT_EQ (res, QUIC_VARINT_ERROR_NULL);
}

TEST (quic_varint_decode_empty_input)
{
  const uint8_t data[] = { 0x00 };
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, 0, &value, &consumed);
  ASSERT_EQ (res, QUIC_VARINT_INCOMPLETE);
}

TEST (quic_varint_decode_truncated_2byte)
{
  const uint8_t data[] = { 0x40 }; /* 2-byte prefix but only 1 byte */
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);
  ASSERT_EQ (res, QUIC_VARINT_INCOMPLETE);
}

TEST (quic_varint_decode_truncated_4byte)
{
  const uint8_t data[] = { 0x80, 0x00, 0x00 }; /* 4-byte prefix but only 3 */
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);
  ASSERT_EQ (res, QUIC_VARINT_INCOMPLETE);
}

TEST (quic_varint_decode_truncated_8byte)
{
  const uint8_t data[]
      = { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; /* 8-byte prefix but 7 */
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);
  ASSERT_EQ (res, QUIC_VARINT_INCOMPLETE);
}

TEST (quic_varint_encode_null_output)
{
  size_t len = SocketQUICVarInt_encode (100, NULL, 8);
  ASSERT_EQ (len, 0);
}

TEST (quic_varint_encode_buffer_too_small)
{
  uint8_t buf[1];
  size_t len = SocketQUICVarInt_encode (64, buf, sizeof (buf)); /* needs 2 */
  ASSERT_EQ (len, 0);
}

TEST (quic_varint_encode_overflow)
{
  uint8_t buf[8];
  size_t len
      = SocketQUICVarInt_encode (SOCKETQUICVARINT_MAX + 1, buf, sizeof (buf));
  ASSERT_EQ (len, 0);
}

/* ============================================================================
 * Result String Tests
 * ============================================================================
 */

TEST (quic_varint_result_string)
{
  ASSERT_NOT_NULL (SocketQUICVarInt_result_string (QUIC_VARINT_OK));
  ASSERT_NOT_NULL (SocketQUICVarInt_result_string (QUIC_VARINT_INCOMPLETE));
  ASSERT_NOT_NULL (SocketQUICVarInt_result_string (QUIC_VARINT_ERROR_OVERFLOW));
  ASSERT_NOT_NULL (SocketQUICVarInt_result_string (QUIC_VARINT_ERROR_BUFFER));
  ASSERT_NOT_NULL (SocketQUICVarInt_result_string (QUIC_VARINT_ERROR_NULL));
  ASSERT_NOT_NULL (
      SocketQUICVarInt_result_string ((SocketQUICVarInt_Result)99));
}

/* ============================================================================
 * Extra bytes in buffer test (ensure we only consume what we need)
 * ============================================================================
 */

TEST (quic_varint_decode_extra_bytes)
{
  /* 1-byte varint followed by extra data */
  const uint8_t data[] = { 0x25, 0xAA, 0xBB, 0xCC };
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);

  ASSERT_EQ (res, QUIC_VARINT_OK);
  ASSERT_EQ (value, 37);
  ASSERT_EQ (consumed, 1);
}

TEST (quic_varint_decode_2byte_extra_bytes)
{
  /* 2-byte varint followed by extra data */
  const uint8_t data[] = { 0x7B, 0xBD, 0xAA, 0xBB, 0xCC };
  uint64_t value;
  size_t consumed;

  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (data, sizeof (data), &value, &consumed);

  ASSERT_EQ (res, QUIC_VARINT_OK);
  ASSERT_EQ (value, 15293);
  ASSERT_EQ (consumed, 2);
}

/* ============================================================================
 * VALIDATE_VARINT_SIZES Macro Tests (Issue #2023)
 * ============================================================================
 */

TEST (quic_varint_validate_sizes_all_valid)
{
  /* Test that the macro returns 1 (true) when all sizes are valid */
  size_t s1 = SocketQUICVarInt_size (100);
  size_t s2 = SocketQUICVarInt_size (1000);
  size_t s3 = SocketQUICVarInt_size (10000);

  ASSERT (VALIDATE_VARINT_SIZES (s1, s2, s3));
}

TEST (quic_varint_validate_sizes_one_invalid)
{
  /* Test that the macro returns 0 (false) when one size is invalid */
  size_t s1 = SocketQUICVarInt_size (100);
  size_t s2 = SocketQUICVarInt_size (SOCKETQUICVARINT_MAX + 1); /* Invalid */
  size_t s3 = SocketQUICVarInt_size (10000);

  ASSERT (!VALIDATE_VARINT_SIZES (s1, s2, s3));
}

TEST (quic_varint_validate_sizes_all_invalid)
{
  /* Test that the macro returns 0 (false) when all sizes are invalid */
  size_t s1 = SocketQUICVarInt_size (SOCKETQUICVARINT_MAX + 1);
  size_t s2 = SocketQUICVarInt_size (SOCKETQUICVARINT_MAX + 2);
  size_t s3 = SocketQUICVarInt_size (UINT64_MAX);

  ASSERT (!VALIDATE_VARINT_SIZES (s1, s2, s3));
}

TEST (quic_varint_validate_sizes_single_value)
{
  /* Test that the macro works with a single value */
  size_t s1 = SocketQUICVarInt_size (100);
  ASSERT (VALIDATE_VARINT_SIZES (s1));

  size_t s2 = SocketQUICVarInt_size (SOCKETQUICVARINT_MAX + 1);
  ASSERT (!VALIDATE_VARINT_SIZES (s2));
}

TEST (quic_varint_validate_sizes_many_values)
{
  /* Test that the macro works with many values */
  size_t s1 = SocketQUICVarInt_size (1);
  size_t s2 = SocketQUICVarInt_size (64);
  size_t s3 = SocketQUICVarInt_size (16384);
  size_t s4 = SocketQUICVarInt_size (1073741824);
  size_t s5 = SocketQUICVarInt_size (SOCKETQUICVARINT_MAX);

  ASSERT (VALIDATE_VARINT_SIZES (s1, s2, s3, s4, s5));

  /* Now with one invalid in the middle */
  size_t s6 = SocketQUICVarInt_size (SOCKETQUICVARINT_MAX + 1);
  ASSERT (!VALIDATE_VARINT_SIZES (s1, s2, s6, s4, s5));
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
