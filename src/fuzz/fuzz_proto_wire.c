/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_proto_wire.c - libFuzzer harness for protobuf wire field parsing
 */

#include "grpc/SocketProto.h"

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (data == NULL)
    return 0;

  size_t offset = 0;
  int fields = 0;

  while (offset < size && fields < 128)
    {
      SocketProto_Field field;
      size_t consumed = 0;
      SocketProto_Result rc = SocketProto_wire_read_field (
          data + offset, size - offset, &field, &consumed);
      if (rc != SOCKET_PROTO_OK || consumed == 0)
        break;

      uint64_t u64 = 0;
      uint32_t u32 = 0;
      uint64_t u64f = 0;
      (void)SocketProto_Field_decode_u64 (&field, &u64);
      (void)SocketProto_Field_decode_fixed32 (&field, &u32);
      (void)SocketProto_Field_decode_fixed64 (&field, &u64f);

      offset += consumed;
      fields++;
    }

  if (size > 0)
    {
      uint8_t out[32];
      size_t written = 0;
      uint32_t field_number = (uint32_t)((data[0] % 30U) + 1U);
      uint8_t wire_type = (uint8_t)(data[0] % 6U);

      (void)SocketProto_wire_write_tag (
          field_number, wire_type, out, sizeof (out), &written);
      (void)SocketProto_wire_write_length_delimited (
          field_number, data, size, out, sizeof (out), &written);
    }

  return 0;
}
