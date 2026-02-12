/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_proto_message.c - libFuzzer harness for protobuf message runtime
 */

#include "grpc/SocketProto.h"

#include <stddef.h>
#include <stdint.h>

static const SocketProto_SchemaField fuzz_schema_fields[] = {
  { 1, SOCKET_PROTO_KIND_VARINT, NULL },
  { 2, SOCKET_PROTO_KIND_LENGTH_DELIMITED, NULL },
  { 3, SOCKET_PROTO_KIND_FIXED32, NULL },
};

static const SocketProto_Schema fuzz_schema = {
  .fields = fuzz_schema_fields,
  .field_count = sizeof (fuzz_schema_fields) / sizeof (fuzz_schema_fields[0]),
};

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketProto_Limits limits;
  SocketProto_Message_T msg;

  SocketProto_limits_defaults (&limits);
  if (size > 0)
    {
      limits.max_fields = (size_t)((data[0] % 64U) + 1U);
      limits.max_nesting_depth = (size_t)((data[0] % 8U) + 1U);
      limits.max_message_size = size + 8U;
    }

  msg = SocketProto_Message_new (NULL, &limits, &fuzz_schema);
  if (msg == NULL)
    return 0;

  (void)SocketProto_Message_parse (msg, data, size);
  (void)SocketProto_Message_validate (data, size, &fuzz_schema, &limits);

  uint8_t out[512];
  size_t written = 0;
  (void)SocketProto_Message_encode (msg, out, sizeof (out), &written);

  if (size >= 8)
    {
      uint64_t v = ((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48)
                   | ((uint64_t)data[2] << 40) | ((uint64_t)data[3] << 32)
                   | ((uint64_t)data[4] << 24) | ((uint64_t)data[5] << 16)
                   | ((uint64_t)data[6] << 8) | (uint64_t)data[7];
      (void)SocketProto_Message_append_varint (msg, 1, v);
    }
  if (size >= 4)
    {
      uint32_t v
          = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
            | ((uint32_t)data[2] << 8) | (uint32_t)data[3];
      (void)SocketProto_Message_append_fixed32 (msg, 3, v);
    }
  (void)SocketProto_Message_append_bytes (msg, 2, data, size);

  SocketProto_Message_free (&msg);
  return 0;
}
