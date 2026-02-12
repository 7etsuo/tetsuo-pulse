/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_proto_wire.c
 * @brief Unit tests for protobuf wire-level helpers.
 */

#include "grpc/SocketProto.h"
#include "test/Test.h"

#include <string.h>

TEST (proto_wire_make_tag_validation)
{
  uint64_t tag = 0;

  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_wire_make_tag (15, SOCKET_PROTO_WIRE_VARINT, &tag));
  ASSERT_EQ (((uint64_t)15 << 3U) | SOCKET_PROTO_WIRE_VARINT, tag);

  ASSERT_EQ (SOCKET_PROTO_INVALID_TAG,
             SocketProto_wire_make_tag (0, SOCKET_PROTO_WIRE_VARINT, &tag));
  ASSERT_EQ (SOCKET_PROTO_INVALID_WIRE_TYPE,
             SocketProto_wire_make_tag (1, SOCKET_PROTO_WIRE_START_GROUP, &tag));
}

TEST (proto_wire_write_and_read_varint_field)
{
  uint8_t tag_buf[SOCKET_PROTO_MAX_VARINT_LEN];
  uint8_t val_buf[SOCKET_PROTO_MAX_VARINT_LEN];
  uint8_t encoded[SOCKET_PROTO_MAX_VARINT_LEN * 2U];
  size_t tag_len = 0;
  size_t val_len = 0;
  SocketProto_Field field;
  size_t consumed = 0;
  uint64_t decoded = 0;

  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_wire_write_tag (
                 5, SOCKET_PROTO_WIRE_VARINT, tag_buf, sizeof (tag_buf), &tag_len));
  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_varint_encode_u64 (
                 1500, val_buf, sizeof (val_buf), &val_len));

  memcpy (encoded, tag_buf, tag_len);
  memcpy (encoded + tag_len, val_buf, val_len);

  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_wire_read_field (
                 encoded, tag_len + val_len, &field, &consumed));
  ASSERT_EQ (5U, field.field_number);
  ASSERT_EQ ((uint8_t)SOCKET_PROTO_WIRE_VARINT, field.wire_type);
  ASSERT_EQ (tag_len + val_len, consumed);
  ASSERT_EQ (SOCKET_PROTO_OK, SocketProto_Field_decode_u64 (&field, &decoded));
  ASSERT_EQ (1500ULL, decoded);
}

TEST (proto_wire_write_and_read_length_delimited_field)
{
  const uint8_t payload[] = { 0x41, 0x42, 0x43, 0x44 };
  uint8_t encoded[64];
  size_t written = 0;
  SocketProto_Field field;
  size_t consumed = 0;

  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_wire_write_length_delimited (7,
                                                     payload,
                                                     sizeof (payload),
                                                     encoded,
                                                     sizeof (encoded),
                                                     &written));
  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_wire_read_field (encoded, written, &field, &consumed));
  ASSERT_EQ (7U, field.field_number);
  ASSERT_EQ ((uint8_t)SOCKET_PROTO_WIRE_LENGTH_DELIMITED, field.wire_type);
  ASSERT_EQ (sizeof (payload), field.value_len);
  ASSERT_EQ (0, memcmp (payload, field.value, sizeof (payload)));
  ASSERT_EQ (written, consumed);
}

TEST (proto_wire_read_fixed_fields)
{
  uint8_t fixed32_field[] = { 0x0D, 0x44, 0x33, 0x22, 0x11 };
  uint8_t fixed64_field[] = { 0x11, 0x88, 0x77, 0x66, 0x55,
                              0x44, 0x33, 0x22, 0x11 };
  SocketProto_Field field;
  size_t consumed = 0;
  uint32_t v32 = 0;
  uint64_t v64 = 0;

  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_wire_read_field (
                 fixed32_field, sizeof (fixed32_field), &field, &consumed));
  ASSERT_EQ (SOCKET_PROTO_OK, SocketProto_Field_decode_fixed32 (&field, &v32));
  ASSERT_EQ (0x11223344U, v32);

  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_wire_read_field (
                 fixed64_field, sizeof (fixed64_field), &field, &consumed));
  ASSERT_EQ (SOCKET_PROTO_OK, SocketProto_Field_decode_fixed64 (&field, &v64));
  ASSERT_EQ (0x1122334455667788ULL, v64);
}

TEST (proto_wire_rejects_group_wire_types)
{
  uint8_t invalid_group_field[] = { 0x13, 0x01 };
  SocketProto_Field field;
  size_t consumed = 0;

  ASSERT_EQ (SOCKET_PROTO_INVALID_WIRE_TYPE,
             SocketProto_wire_read_field (invalid_group_field,
                                          sizeof (invalid_group_field),
                                          &field,
                                          &consumed));
}

TEST (proto_wire_detects_truncated_payloads)
{
  uint8_t truncated_len_delim[] = { 0x0A, 0x05, 0x01, 0x02 };
  uint8_t truncated_fixed64[] = { 0x11, 0xAA, 0xBB, 0xCC };
  SocketProto_Field field;
  size_t consumed = 0;

  ASSERT_EQ (SOCKET_PROTO_INCOMPLETE,
             SocketProto_wire_read_field (truncated_len_delim,
                                          sizeof (truncated_len_delim),
                                          &field,
                                          &consumed));
  ASSERT_EQ (SOCKET_PROTO_INCOMPLETE,
             SocketProto_wire_read_field (
                 truncated_fixed64, sizeof (truncated_fixed64), &field, &consumed));
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
