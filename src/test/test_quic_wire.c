/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_quic_wire.c - QUIC Packet Number Encoding unit tests
 *
 * Tests packet number encoding/decoding algorithms (RFC 9000 Appendix A).
 * Covers RFC test vectors, boundary conditions, wrap-around handling,
 * and round-trip verification.
 */

#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICWire.h"
#include "test/Test.h"

/* ============================================================================
 * RFC 9000 Appendix A.2 Test Vectors (Encoding)
 * ============================================================================
 */

TEST (quic_wire_pn_length_rfc_example1)
{
  /* RFC Example: 0xabe8b3 acked, sending 0xac5c02 -> 29,519 unacked -> 2 bytes
   */
  unsigned len = SocketQUICWire_pn_length (0xac5c02, 0xabe8b3);
  ASSERT_EQ (len, 2);
}

TEST (quic_wire_pn_length_rfc_example2)
{
  /* RFC Example: 0xabe8b3 acked, sending 0xace8fe -> 131,147 unacked -> 3 bytes
   */
  unsigned len = SocketQUICWire_pn_length (0xace8fe, 0xabe8b3);
  ASSERT_EQ (len, 3);
}

TEST (quic_wire_pn_length_no_acks)
{
  /* No acks yet - first packet (pn=0) needs 1 byte */
  unsigned len = SocketQUICWire_pn_length (0, QUIC_PN_NONE);
  ASSERT_EQ (len, 1);
}

TEST (quic_wire_pn_length_no_acks_pn1)
{
  /* No acks yet - pn=1 needs 1 byte (2 unacked) */
  unsigned len = SocketQUICWire_pn_length (1, QUIC_PN_NONE);
  ASSERT_EQ (len, 1);
}

TEST (quic_wire_pn_length_no_acks_pn255)
{
  /* No acks yet - pn=255 needs 2 bytes (256 unacked) */
  unsigned len = SocketQUICWire_pn_length (255, QUIC_PN_NONE);
  ASSERT_EQ (len, 2);
}

TEST (quic_wire_pn_length_no_acks_pn65535)
{
  /* No acks yet - pn=65535 needs 3 bytes (65536 unacked) */
  unsigned len = SocketQUICWire_pn_length (65535, QUIC_PN_NONE);
  ASSERT_EQ (len, 3);
}

TEST (quic_wire_pn_length_consecutive)
{
  /* Consecutive acks - only 1 unacked -> 1 byte */
  unsigned len = SocketQUICWire_pn_length (100, 99);
  ASSERT_EQ (len, 1);
}

TEST (quic_wire_pn_length_1byte_boundary)
{
  /* 127 unacked packets -> 8 bits needed -> 1 byte */
  unsigned len = SocketQUICWire_pn_length (200, 73);
  ASSERT_EQ (len, 1);
}

TEST (quic_wire_pn_length_2byte_min)
{
  /* 129 unacked packets -> 9 bits needed -> 2 bytes */
  unsigned len = SocketQUICWire_pn_length (200, 71);
  ASSERT_EQ (len, 2);
}

TEST (quic_wire_pn_length_2byte_boundary)
{
  /* 32767 unacked packets -> 16 bits -> 2 bytes */
  unsigned len = SocketQUICWire_pn_length (40000, 7233);
  ASSERT_EQ (len, 2);
}

TEST (quic_wire_pn_length_3byte_min)
{
  /* 32769 unacked packets -> 17 bits -> 3 bytes */
  unsigned len = SocketQUICWire_pn_length (40000, 7231);
  ASSERT_EQ (len, 3);
}

TEST (quic_wire_pn_length_4byte)
{
  /* 8388608+ unacked -> 24+ bits -> 4 bytes */
  unsigned len = SocketQUICWire_pn_length (10000000, 1000000);
  ASSERT_EQ (len, 4);
}

/* ============================================================================
 * RFC 9000 Appendix A.3 Test Vectors (Decoding)
 * ============================================================================
 */

TEST (quic_wire_pn_decode_rfc_example)
{
  /* RFC Example: largest_pn=0xa82f30ea, truncated=0x9b32 (16-bit)
   * Should decode to 0xa82f9b32 */
  uint64_t full_pn;
  SocketQUICWire_Result res
      = SocketQUICWire_pn_decode (0xa82f30ea, 0x9b32, 16, &full_pn);

  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (full_pn, 0xa82f9b32);
}

TEST (quic_wire_pn_decode_8bit_simple)
{
  /* largest_pn=100, truncated=101 (8-bit) -> 101 */
  uint64_t full_pn;
  SocketQUICWire_Result res = SocketQUICWire_pn_decode (100, 101, 8, &full_pn);

  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (full_pn, 101);
}

TEST (quic_wire_pn_decode_8bit_wrap_forward)
{
  /* largest_pn=200, truncated=5 (8-bit) -> 261 (wrap forward) */
  uint64_t full_pn;
  SocketQUICWire_Result res = SocketQUICWire_pn_decode (200, 5, 8, &full_pn);

  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (full_pn, 261);
}

TEST (quic_wire_pn_decode_8bit_wrap_backward)
{
  /* largest_pn=10, truncated=250 (8-bit) -> should stay low (no wrap back to
   * -6) */
  uint64_t full_pn;
  SocketQUICWire_Result res = SocketQUICWire_pn_decode (10, 250, 8, &full_pn);

  ASSERT_EQ (res, QUIC_PN_OK);
  /* Expected is 11, candidate is 250 which is > 11 + 128 = 139
   * So we subtract 256: 250 - 256 would be negative, but candidate >= pn_win
   * is false Since 250 >= 256 is false, we don't subtract. Result is 250 */
  /* Actually: expected=11, candidate = (11 & ~0xFF) | 250 = 0 | 250 = 250
   * 250 > 11 + 128 = 139? Yes
   * 250 >= 256? No
   * So no wrap, result is 250 */
  ASSERT_EQ (full_pn, 250);
}

TEST (quic_wire_pn_decode_16bit_simple)
{
  /* largest_pn=0x1000, truncated=0x1001 (16-bit) -> 0x1001 */
  uint64_t full_pn;
  SocketQUICWire_Result res
      = SocketQUICWire_pn_decode (0x1000, 0x1001, 16, &full_pn);

  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (full_pn, 0x1001);
}

TEST (quic_wire_pn_decode_16bit_high_bits)
{
  /* largest_pn=0x12345, truncated=0x2346 (16-bit) -> 0x12346 */
  uint64_t full_pn;
  SocketQUICWire_Result res
      = SocketQUICWire_pn_decode (0x12345, 0x2346, 16, &full_pn);

  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (full_pn, 0x12346);
}

TEST (quic_wire_pn_decode_24bit)
{
  /* largest_pn=0xABCDE0, truncated=0xABCDE1 (24-bit) -> 0xABCDE1 */
  uint64_t full_pn;
  SocketQUICWire_Result res
      = SocketQUICWire_pn_decode (0xABCDE0, 0xABCDE1, 24, &full_pn);

  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (full_pn, 0xABCDE1);
}

TEST (quic_wire_pn_decode_32bit)
{
  /* 32-bit encoding, simple increment */
  uint64_t full_pn;
  SocketQUICWire_Result res
      = SocketQUICWire_pn_decode (0x12345678, 0x12345679, 32, &full_pn);

  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (full_pn, 0x12345679);
}

TEST (quic_wire_pn_decode_first_packet)
{
  /* First packet (no prior packets) */
  uint64_t full_pn;
  SocketQUICWire_Result res
      = SocketQUICWire_pn_decode (QUIC_PN_NONE, 0, 8, &full_pn);

  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (full_pn, 0);
}

TEST (quic_wire_pn_decode_invalid_bits)
{
  uint64_t full_pn;
  SocketQUICWire_Result res = SocketQUICWire_pn_decode (100, 101, 12, &full_pn);

  ASSERT_EQ (res, QUIC_PN_ERROR_BITS);
}

TEST (quic_wire_pn_decode_null)
{
  SocketQUICWire_Result res = SocketQUICWire_pn_decode (100, 101, 8, NULL);

  ASSERT_EQ (res, QUIC_PN_ERROR_NULL);
}

/* ============================================================================
 * Encoding Tests
 * ============================================================================
 */

TEST (quic_wire_pn_encode_1byte)
{
  uint8_t buf[4];
  size_t len = SocketQUICWire_pn_encode (5, 4, buf, sizeof (buf));

  ASSERT_EQ (len, 1);
  ASSERT_EQ (buf[0], 5);
}

TEST (quic_wire_pn_encode_2byte)
{
  uint8_t buf[4];
  size_t len = SocketQUICWire_pn_encode (0x1234, 0, buf, sizeof (buf));

  ASSERT_EQ (len, 2);
  ASSERT_EQ (buf[0], 0x12);
  ASSERT_EQ (buf[1], 0x34);
}

TEST (quic_wire_pn_encode_3byte)
{
  uint8_t buf[4];
  size_t len = SocketQUICWire_pn_encode (0x123456, 0, buf, sizeof (buf));

  ASSERT_EQ (len, 3);
  ASSERT_EQ (buf[0], 0x12);
  ASSERT_EQ (buf[1], 0x34);
  ASSERT_EQ (buf[2], 0x56);
}

TEST (quic_wire_pn_encode_4byte)
{
  uint8_t buf[4];
  size_t len = SocketQUICWire_pn_encode (0x12345678, 0, buf, sizeof (buf));

  ASSERT_EQ (len, 4);
  ASSERT_EQ (buf[0], 0x12);
  ASSERT_EQ (buf[1], 0x34);
  ASSERT_EQ (buf[2], 0x56);
  ASSERT_EQ (buf[3], 0x78);
}

TEST (quic_wire_pn_encode_rfc_example)
{
  /* RFC Example: 0xac5c02 with ack at 0xabe8b3 */
  uint8_t buf[4];
  size_t len = SocketQUICWire_pn_encode (0xac5c02, 0xabe8b3, buf, sizeof (buf));

  ASSERT_EQ (len, 2);
  ASSERT_EQ (buf[0], 0x5c);
  ASSERT_EQ (buf[1], 0x02);
}

TEST (quic_wire_pn_encode_buffer_too_small)
{
  uint8_t buf[1];
  size_t len = SocketQUICWire_pn_encode (0x1234, 0, buf, sizeof (buf));

  ASSERT_EQ (len, 0);
}

TEST (quic_wire_pn_encode_null)
{
  size_t len = SocketQUICWire_pn_encode (100, 0, NULL, 4);

  ASSERT_EQ (len, 0);
}

TEST (quic_wire_pn_encode_overflow)
{
  uint8_t buf[4];
  size_t len = SocketQUICWire_pn_encode (QUIC_PN_MAX + 1, 0, buf, sizeof (buf));

  ASSERT_EQ (len, 0);
}

/* ============================================================================
 * Read/Write Tests
 * ============================================================================
 */

TEST (quic_wire_pn_read_1byte)
{
  const uint8_t data[] = { 0x42 };
  uint64_t value;
  SocketQUICWire_Result res
      = SocketQUICWire_pn_read (data, sizeof (data), 1, &value);

  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (value, 0x42);
}

TEST (quic_wire_pn_read_2byte)
{
  const uint8_t data[] = { 0x12, 0x34 };
  uint64_t value;
  SocketQUICWire_Result res
      = SocketQUICWire_pn_read (data, sizeof (data), 2, &value);

  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (value, 0x1234);
}

TEST (quic_wire_pn_read_3byte)
{
  const uint8_t data[] = { 0x12, 0x34, 0x56 };
  uint64_t value;
  SocketQUICWire_Result res
      = SocketQUICWire_pn_read (data, sizeof (data), 3, &value);

  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (value, 0x123456);
}

TEST (quic_wire_pn_read_4byte)
{
  const uint8_t data[] = { 0x12, 0x34, 0x56, 0x78 };
  uint64_t value;
  SocketQUICWire_Result res
      = SocketQUICWire_pn_read (data, sizeof (data), 4, &value);

  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (value, 0x12345678);
}

TEST (quic_wire_pn_read_buffer_too_small)
{
  const uint8_t data[] = { 0x12 };
  uint64_t value;
  SocketQUICWire_Result res
      = SocketQUICWire_pn_read (data, sizeof (data), 2, &value);

  ASSERT_EQ (res, QUIC_PN_ERROR_BUFFER);
}

TEST (quic_wire_pn_read_invalid_len)
{
  const uint8_t data[] = { 0x12, 0x34, 0x56, 0x78, 0x9A };
  uint64_t value;
  SocketQUICWire_Result res
      = SocketQUICWire_pn_read (data, sizeof (data), 5, &value);

  ASSERT_EQ (res, QUIC_PN_ERROR_BITS);
}

TEST (quic_wire_pn_read_null_data)
{
  uint64_t value;
  SocketQUICWire_Result res = SocketQUICWire_pn_read (NULL, 4, 1, &value);

  ASSERT_EQ (res, QUIC_PN_ERROR_NULL);
}

TEST (quic_wire_pn_read_null_value)
{
  const uint8_t data[] = { 0x42 };
  SocketQUICWire_Result res
      = SocketQUICWire_pn_read (data, sizeof (data), 1, NULL);

  ASSERT_EQ (res, QUIC_PN_ERROR_NULL);
}

TEST (quic_wire_pn_write_1byte)
{
  uint8_t buf[4] = { 0 };
  size_t len = SocketQUICWire_pn_write (0x42, 1, buf, sizeof (buf));

  ASSERT_EQ (len, 1);
  ASSERT_EQ (buf[0], 0x42);
}

TEST (quic_wire_pn_write_2byte)
{
  uint8_t buf[4] = { 0 };
  size_t len = SocketQUICWire_pn_write (0x1234, 2, buf, sizeof (buf));

  ASSERT_EQ (len, 2);
  ASSERT_EQ (buf[0], 0x12);
  ASSERT_EQ (buf[1], 0x34);
}

TEST (quic_wire_pn_write_3byte)
{
  uint8_t buf[4] = { 0 };
  size_t len = SocketQUICWire_pn_write (0x123456, 3, buf, sizeof (buf));

  ASSERT_EQ (len, 3);
  ASSERT_EQ (buf[0], 0x12);
  ASSERT_EQ (buf[1], 0x34);
  ASSERT_EQ (buf[2], 0x56);
}

TEST (quic_wire_pn_write_4byte)
{
  uint8_t buf[4] = { 0 };
  size_t len = SocketQUICWire_pn_write (0x12345678, 4, buf, sizeof (buf));

  ASSERT_EQ (len, 4);
  ASSERT_EQ (buf[0], 0x12);
  ASSERT_EQ (buf[1], 0x34);
  ASSERT_EQ (buf[2], 0x56);
  ASSERT_EQ (buf[3], 0x78);
}

TEST (quic_wire_pn_write_buffer_too_small)
{
  uint8_t buf[1];
  size_t len = SocketQUICWire_pn_write (0x1234, 2, buf, sizeof (buf));

  ASSERT_EQ (len, 0);
}

TEST (quic_wire_pn_write_invalid_len)
{
  uint8_t buf[8];
  size_t len = SocketQUICWire_pn_write (0x12345678, 5, buf, sizeof (buf));

  ASSERT_EQ (len, 0);
}

TEST (quic_wire_pn_write_null)
{
  size_t len = SocketQUICWire_pn_write (0x42, 1, NULL, 4);

  ASSERT_EQ (len, 0);
}

/* ============================================================================
 * Round-Trip Tests
 * ============================================================================
 */

TEST (quic_wire_pn_roundtrip_simple)
{
  uint64_t original = 12345;
  uint64_t largest_acked = 12300;
  uint8_t buf[4];

  /* Encode */
  size_t len
      = SocketQUICWire_pn_encode (original, largest_acked, buf, sizeof (buf));
  ASSERT (len > 0);

  /* Read truncated value */
  uint64_t truncated;
  SocketQUICWire_Result res
      = SocketQUICWire_pn_read (buf, len, (unsigned)len, &truncated);
  ASSERT_EQ (res, QUIC_PN_OK);

  /* Decode back to full PN */
  uint64_t decoded;
  res = SocketQUICWire_pn_decode (
      largest_acked, truncated, (unsigned)len * 8, &decoded);
  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (decoded, original);
}

TEST (quic_wire_pn_roundtrip_rfc_example)
{
  uint64_t original = 0xac5c02;
  uint64_t largest_acked = 0xabe8b3;
  uint8_t buf[4];

  /* Encode */
  size_t len
      = SocketQUICWire_pn_encode (original, largest_acked, buf, sizeof (buf));
  ASSERT_EQ (len, 2);

  /* Read truncated value */
  uint64_t truncated;
  SocketQUICWire_Result res
      = SocketQUICWire_pn_read (buf, len, (unsigned)len, &truncated);
  ASSERT_EQ (res, QUIC_PN_OK);

  /* Decode back to full PN */
  uint64_t decoded;
  res = SocketQUICWire_pn_decode (
      largest_acked, truncated, (unsigned)len * 8, &decoded);
  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (decoded, original);
}

TEST (quic_wire_pn_roundtrip_large)
{
  uint64_t original = 0x123456789ABC;
  uint64_t largest_acked = 0x123456789AB0;
  uint8_t buf[4];

  /* Encode */
  size_t len
      = SocketQUICWire_pn_encode (original, largest_acked, buf, sizeof (buf));
  ASSERT (len > 0);

  /* Read truncated value */
  uint64_t truncated;
  SocketQUICWire_Result res
      = SocketQUICWire_pn_read (buf, len, (unsigned)len, &truncated);
  ASSERT_EQ (res, QUIC_PN_OK);

  /* Decode back to full PN */
  uint64_t decoded;
  res = SocketQUICWire_pn_decode (
      largest_acked, truncated, (unsigned)len * 8, &decoded);
  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (decoded, original);
}

TEST (quic_wire_pn_roundtrip_first_packet)
{
  uint64_t original = 0;
  uint8_t buf[4];

  /* Encode first packet */
  size_t len
      = SocketQUICWire_pn_encode (original, QUIC_PN_NONE, buf, sizeof (buf));
  ASSERT_EQ (len, 1);

  /* Read truncated value */
  uint64_t truncated;
  SocketQUICWire_Result res
      = SocketQUICWire_pn_read (buf, len, (unsigned)len, &truncated);
  ASSERT_EQ (res, QUIC_PN_OK);

  /* Decode back to full PN */
  uint64_t decoded;
  res = SocketQUICWire_pn_decode (
      QUIC_PN_NONE, truncated, (unsigned)len * 8, &decoded);
  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (decoded, original);
}

/* ============================================================================
 * Utility Tests
 * ============================================================================
 */

TEST (quic_wire_pn_is_valid_zero)
{
  ASSERT (SocketQUICWire_pn_is_valid (0));
}

TEST (quic_wire_pn_is_valid_max)
{
  ASSERT (SocketQUICWire_pn_is_valid (QUIC_PN_MAX));
}

TEST (quic_wire_pn_is_valid_overflow)
{
  ASSERT (!SocketQUICWire_pn_is_valid (QUIC_PN_MAX + 1));
}

TEST (quic_wire_result_string_ok)
{
  const char *str = SocketQUICWire_result_string (QUIC_PN_OK);
  ASSERT (str != NULL);
  ASSERT (strlen (str) > 0);
}

TEST (quic_wire_result_string_all)
{
  /* All result codes should have non-NULL strings */
  ASSERT (SocketQUICWire_result_string (QUIC_PN_OK) != NULL);
  ASSERT (SocketQUICWire_result_string (QUIC_PN_ERROR_NULL) != NULL);
  ASSERT (SocketQUICWire_result_string (QUIC_PN_ERROR_BUFFER) != NULL);
  ASSERT (SocketQUICWire_result_string (QUIC_PN_ERROR_OVERFLOW) != NULL);
  ASSERT (SocketQUICWire_result_string (QUIC_PN_ERROR_BITS) != NULL);
}

/* ============================================================================
 * Edge Case Tests
 * ============================================================================
 */

TEST (quic_wire_pn_decode_wrap_at_boundary)
{
  /* Test wrap-around detection at 8-bit boundary */
  uint64_t full_pn;

  /* Case: largest=0xFE, truncated=0x01 -> should be 0x101 (wrap forward) */
  SocketQUICWire_Result res
      = SocketQUICWire_pn_decode (0xFE, 0x01, 8, &full_pn);
  ASSERT_EQ (res, QUIC_PN_OK);
  ASSERT_EQ (full_pn, 0x101);
}

TEST (quic_wire_pn_length_max_unacked)
{
  /* Large gap should require 4 bytes */
  unsigned len = SocketQUICWire_pn_length (0xFFFFFFFF, 0);
  ASSERT_EQ (len, 4);
}

TEST (quic_wire_pn_encode_max_valid)
{
  /* Encode QUIC_PN_MAX should work */
  uint8_t buf[4];
  size_t len = SocketQUICWire_pn_encode (QUIC_PN_MAX, 0, buf, sizeof (buf));
  ASSERT_EQ (len, 4);
}

/* ============================================================================
 * Overflow Check Tests (Issue #1178)
 * ============================================================================
 */

TEST (quic_wire_pn_length_overflow_check_max_plus_one)
{
  /* Test case from issue #1178: QUIC_PN_MAX + 1 should return 4 */
  unsigned len = SocketQUICWire_pn_length (QUIC_PN_MAX + 1, QUIC_PN_NONE);
  ASSERT_EQ (len, 4);
}

TEST (quic_wire_pn_length_overflow_check_uint64_max)
{
  /* Test case from issue #1178: UINT64_MAX should return 4, not wrap to 1 */
  unsigned len = SocketQUICWire_pn_length (UINT64_MAX, QUIC_PN_NONE);
  ASSERT_EQ (len, 4);
}

TEST (quic_wire_pn_length_overflow_check_max_plus_1000)
{
  /* Test case from issue #1178: QUIC_PN_MAX + 1000 should return 4 */
  unsigned len = SocketQUICWire_pn_length (QUIC_PN_MAX + 1000, QUIC_PN_NONE);
  ASSERT_EQ (len, 4);
}

TEST (quic_wire_pn_length_overflow_with_acked)
{
  /* Overflow check should work regardless of largest_acked value */
  unsigned len = SocketQUICWire_pn_length (QUIC_PN_MAX + 1, 100);
  ASSERT_EQ (len, 4);
}

TEST (quic_wire_pn_length_at_max_boundary)
{
  /* QUIC_PN_MAX itself is valid, should not trigger overflow */
  unsigned len = SocketQUICWire_pn_length (QUIC_PN_MAX, QUIC_PN_NONE);
  ASSERT_EQ (len, 4);
}

TEST (quic_wire_pn_length_just_below_max)
{
  /* Just below QUIC_PN_MAX should work normally */
  unsigned len = SocketQUICWire_pn_length (QUIC_PN_MAX - 1, QUIC_PN_NONE);
  ASSERT_EQ (len, 4);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
