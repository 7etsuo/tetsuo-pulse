/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_proto_message.c
 * @brief Unit tests for protobuf message parse/encode/runtime limits.
 */

#include "grpc/SocketProto.h"
#include "test/Test.h"

#include <string.h>

static const SocketProto_SchemaField test_schema_fields[] = {
  { 1, SOCKET_PROTO_KIND_VARINT, NULL },
  { 2, SOCKET_PROTO_KIND_LENGTH_DELIMITED, NULL },
};

static const SocketProto_Schema test_schema = {
  .fields = test_schema_fields,
  .field_count = sizeof (test_schema_fields) / sizeof (test_schema_fields[0]),
};

TEST (proto_message_roundtrip_and_unknown_preservation)
{
  SocketProto_Message_T builder = SocketProto_Message_new (NULL, NULL, &test_schema);
  SocketProto_Message_T parsed = SocketProto_Message_new (NULL, NULL, &test_schema);
  uint8_t encoded[128];
  uint8_t reencoded[128];
  size_t encoded_len = 0;
  size_t reencoded_len = 0;

  ASSERT_NOT_NULL (builder);
  ASSERT_NOT_NULL (parsed);

  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_Message_append_varint (builder, 1, 42));
  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_Message_append_bytes (
                 builder, 2, (const uint8_t *)"pong", 4));
  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_Message_append_varint (builder, 9, 777));

  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_Message_encode (
                 builder, encoded, sizeof (encoded), &encoded_len));

  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_Message_parse (parsed, encoded, encoded_len));
  ASSERT_EQ (3U, SocketProto_Message_field_count (parsed));
  ASSERT_EQ (1U, SocketProto_Message_unknown_count (parsed));

  const SocketProto_Field *f0 = SocketProto_Message_field_at (parsed, 0);
  const SocketProto_Field *f1 = SocketProto_Message_field_at (parsed, 1);
  const SocketProto_Field *unknown = SocketProto_Message_unknown_at (parsed, 0);
  uint64_t decoded_id = 0;

  ASSERT_NOT_NULL (f0);
  ASSERT_NOT_NULL (f1);
  ASSERT_NOT_NULL (unknown);
  ASSERT_EQ (1U, f0->field_number);
  ASSERT_EQ (2U, f1->field_number);
  ASSERT_EQ (9U, unknown->field_number);
  ASSERT_EQ (SOCKET_PROTO_OK, SocketProto_Field_decode_u64 (f0, &decoded_id));
  ASSERT_EQ (42ULL, decoded_id);

  ASSERT_EQ (SOCKET_PROTO_OK,
             SocketProto_Message_encode (
                 parsed, reencoded, sizeof (reencoded), &reencoded_len));
  ASSERT_EQ (encoded_len, reencoded_len);
  ASSERT_EQ (0, memcmp (encoded, reencoded, encoded_len));

  SocketProto_Message_free (&parsed);
  SocketProto_Message_free (&builder);
}

TEST (proto_message_rejects_malformed_wire)
{
  SocketProto_Message_T msg = SocketProto_Message_new (NULL, NULL, &test_schema);
  uint8_t invalid_wire[] = { 0x13, 0x00 };
  uint8_t truncated[] = { 0x08, 0x80 };

  ASSERT_NOT_NULL (msg);
  ASSERT_EQ (SOCKET_PROTO_INVALID_WIRE_TYPE,
             SocketProto_Message_parse (msg, invalid_wire, sizeof (invalid_wire)));
  ASSERT_EQ (SOCKET_PROTO_INCOMPLETE,
             SocketProto_Message_parse (msg, truncated, sizeof (truncated)));
  SocketProto_Message_free (&msg);
}

TEST (proto_message_enforces_field_and_size_limits)
{
  SocketProto_Limits field_limits;
  SocketProto_Limits size_limits;
  SocketProto_Message_T limited_by_fields;
  uint8_t three_fields[] = { 0x08, 0x01, 0x10, 0x02, 0x18, 0x03 };

  SocketProto_limits_defaults (&field_limits);
  field_limits.max_fields = 2;
  field_limits.max_message_size = 64;

  SocketProto_limits_defaults (&size_limits);
  size_limits.max_message_size = 5;

  limited_by_fields = SocketProto_Message_new (NULL, &field_limits, NULL);
  ASSERT_NOT_NULL (limited_by_fields);
  ASSERT_EQ (SOCKET_PROTO_LIMIT_FIELD_COUNT,
             SocketProto_Message_parse (
                 limited_by_fields, three_fields, sizeof (three_fields)));
  ASSERT_EQ (SOCKET_PROTO_LIMIT_MESSAGE_SIZE,
             SocketProto_Message_validate (
                 three_fields, sizeof (three_fields), &test_schema, &size_limits));

  SocketProto_Message_free (&limited_by_fields);
}

TEST (proto_message_enforces_nesting_depth)
{
  static const SocketProto_SchemaField level2_fields[]
      = { { 1, SOCKET_PROTO_KIND_VARINT, NULL } };
  static const SocketProto_Schema level2 = {
    .fields = level2_fields,
    .field_count = sizeof (level2_fields) / sizeof (level2_fields[0]),
  };
  static const SocketProto_SchemaField level1_fields[]
      = { { 1, SOCKET_PROTO_KIND_MESSAGE, &level2 } };
  static const SocketProto_Schema level1 = {
    .fields = level1_fields,
    .field_count = sizeof (level1_fields) / sizeof (level1_fields[0]),
  };
  static const SocketProto_SchemaField root_fields[]
      = { { 1, SOCKET_PROTO_KIND_MESSAGE, &level1 } };
  static const SocketProto_Schema root = {
    .fields = root_fields,
    .field_count = sizeof (root_fields) / sizeof (root_fields[0]),
  };

  SocketProto_Limits shallow_limits;
  SocketProto_Limits deep_limits;
  SocketProto_Message_T shallow_msg;
  SocketProto_Message_T deep_msg;
  const uint8_t nested_payload[] = {
    0x0A, 0x04, /* field 1, len 4 */
    0x0A, 0x02, /* field 1, len 2 */
    0x08, 0x07  /* field 1, varint 7 */
  };

  SocketProto_limits_defaults (&shallow_limits);
  shallow_limits.max_nesting_depth = 1;
  SocketProto_limits_defaults (&deep_limits);
  deep_limits.max_nesting_depth = 3;

  shallow_msg = SocketProto_Message_new (NULL, &shallow_limits, &root);
  deep_msg = SocketProto_Message_new (NULL, &deep_limits, &root);
  ASSERT_NOT_NULL (shallow_msg);
  ASSERT_NOT_NULL (deep_msg);

  ASSERT_EQ (SOCKET_PROTO_LIMIT_NESTING_DEPTH,
             SocketProto_Message_parse (
                 shallow_msg, nested_payload, sizeof (nested_payload)));
  ASSERT_EQ (
      SOCKET_PROTO_OK,
      SocketProto_Message_parse (deep_msg, nested_payload, sizeof (nested_payload)));

  SocketProto_Message_free (&deep_msg);
  SocketProto_Message_free (&shallow_msg);
}

TEST (proto_message_append_type_mismatch_fails_closed)
{
  SocketProto_Message_T msg = SocketProto_Message_new (NULL, NULL, &test_schema);
  ASSERT_NOT_NULL (msg);

  ASSERT_EQ (SOCKET_PROTO_TYPE_MISMATCH,
             SocketProto_Message_append_fixed64 (msg, 1, 0xABULL));
  ASSERT_EQ (SOCKET_PROTO_TYPE_MISMATCH,
             SocketProto_Message_append_varint (msg, 2, 8));

  SocketProto_Message_free (&msg);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
