/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_proto_varint.c
 * @brief Unit tests for protobuf varint/zigzag/fixed primitives.
 */

#include "grpc/SocketProto.h"
#include "test/Test.h"

#include <limits.h>

TEST (proto_varint_u64_roundtrip_boundaries)
{
  const uint64_t values[]
      = { 0ULL,     1ULL,       127ULL,     128ULL,    255ULL,
          16384ULL, 1048576ULL, UINT32_MAX, UINT64_MAX };

  for (size_t i = 0; i < sizeof (values) / sizeof (values[0]); i++)
    {
      uint8_t buf[SOCKET_PROTO_MAX_VARINT_LEN];
      size_t written = 0;
      uint64_t decoded = 0;
      size_t consumed = 0;

      ASSERT_EQ (SOCKET_PROTO_OK,
                 SocketProto_varint_encode_u64 (
                     values[i], buf, sizeof (buf), &written));
      ASSERT_EQ (
          SOCKET_PROTO_OK,
          SocketProto_varint_decode_u64 (buf, written, &decoded, &consumed));
      ASSERT_EQ (values[i], decoded);
      ASSERT_EQ (written, consumed);
    }
}

TEST (proto_varint_u32_rejects_overflow)
{
  uint8_t buf[SOCKET_PROTO_MAX_VARINT_LEN];
  size_t written = 0;
  uint32_t decoded = 0;
  size_t consumed = 0;

  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_varint_encode_u64 (
                 (uint64_t)UINT32_MAX + 1ULL, buf, sizeof (buf), &written));
  ASSERT_EQ (SOCKET_PROTO_OVERFLOW,
             SocketProto_varint_decode_u32 (buf, written, &decoded, &consumed));
}

TEST (proto_varint_decode_detects_truncated_and_overflow_encodings)
{
  const uint8_t truncated[] = { 0x80 };
  const uint8_t overflow[]
      = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02 };
  uint64_t value = 0;
  size_t consumed = 0;

  ASSERT_EQ (SOCKET_PROTO_INCOMPLETE,
             SocketProto_varint_decode_u64 (
                 truncated, sizeof (truncated), &value, &consumed));
  ASSERT_EQ (SOCKET_PROTO_OVERFLOW,
             SocketProto_varint_decode_u64 (
                 overflow, sizeof (overflow), &value, &consumed));
}

TEST (proto_varint_encode_detects_small_buffer)
{
  uint8_t buf[1];
  size_t written = 0;

  ASSERT_EQ (SOCKET_PROTO_BUFFER_TOO_SMALL,
             SocketProto_varint_encode_u64 (300, buf, sizeof (buf), &written));
}

TEST (proto_zigzag_roundtrip)
{
  const int64_t values[] = { 0, 1, -1, 2, -2, INT32_MAX, INT32_MIN };

  for (size_t i = 0; i < sizeof (values) / sizeof (values[0]); i++)
    {
      uint64_t encoded = SocketProto_zigzag_encode_s64 (values[i]);
      int64_t decoded = SocketProto_zigzag_decode_s64 (encoded);
      ASSERT_EQ (values[i], decoded);
    }
}

TEST (proto_fixed32_roundtrip_and_truncation)
{
  uint8_t buf[4];
  uint32_t decoded = 0;

  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_fixed32_encode (0xA1B2C3D4U, buf, sizeof (buf)));
  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_fixed32_decode (buf, sizeof (buf), &decoded));
  ASSERT_EQ (0xA1B2C3D4U, decoded);
  ASSERT_EQ (SOCKET_PROTO_INCOMPLETE,
             SocketProto_fixed32_decode (buf, 3, &decoded));
}

TEST (proto_fixed64_roundtrip_and_truncation)
{
  uint8_t buf[8];
  uint64_t decoded = 0;

  ASSERT_EQ (
      SOCKET_PROTO_OK,
      SocketProto_fixed64_encode (0x1122334455667788ULL, buf, sizeof (buf)));
  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_fixed64_decode (buf, sizeof (buf), &decoded));
  ASSERT_EQ (0x1122334455667788ULL, decoded);
  ASSERT_EQ (SOCKET_PROTO_INCOMPLETE,
             SocketProto_fixed64_decode (buf, 7, &decoded));
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
