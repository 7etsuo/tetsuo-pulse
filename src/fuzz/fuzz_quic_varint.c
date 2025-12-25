/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_quic_varint.c - libFuzzer harness for QUIC Variable-Length Integer
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Decode with malformed input (truncated, invalid prefix patterns)
 * - Round-trip encode/decode consistency
 * - Integer overflow in decoded values
 * - Buffer boundary conditions
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_quic_varint
 * Run:   ./fuzz_quic_varint corpus/quic_varint/ -fork=16 -max_len=64
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "quic/SocketQUICVarInt.h"

/* Fuzz operation opcodes */
enum FuzzOp
{
  OP_DECODE = 0,
  OP_ENCODE,
  OP_ROUNDTRIP,
  OP_MULTIPLE_DECODE,
  OP_MAX
};

/**
 * parse_u64 - Parse uint64_t from fuzz input
 * @data: Input bytes
 * @len: Number of bytes available
 *
 * Returns: Parsed value
 */
static uint64_t
parse_u64 (const uint8_t *data, size_t len)
{
  uint64_t value = 0;
  size_t i;

  for (i = 0; i < len && i < 8; i++)
    value |= ((uint64_t)data[i]) << (i * 8);

  return value;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 * @data: Fuzz input data
 * @size: Size of fuzz input
 *
 * Returns: 0 (required by libFuzzer)
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 1)
    return 0;

  uint8_t op = data[0] % OP_MAX;
  const uint8_t *payload = data + 1;
  size_t payload_size = size - 1;

  switch (op)
    {
    case OP_DECODE:
      {
        /* Attempt to decode arbitrary input */
        uint64_t value;
        size_t consumed;

        SocketQUICVarInt_Result res
            = SocketQUICVarInt_decode (payload, payload_size, &value,
                                       &consumed);

        if (res == QUIC_VARINT_OK)
          {
            /* Verify consumed is valid */
            assert (consumed > 0 && consumed <= payload_size);
            assert (consumed <= 8);

            /* Verify value is within range */
            assert (value <= SOCKETQUICVARINT_MAX);
          }
      }
      break;

    case OP_ENCODE:
      {
        /* Encode a fuzz-derived value */
        if (payload_size >= 8)
          {
            uint64_t value = parse_u64 (payload, 8);

            /* Cap to valid range to test normal encoding */
            if (value > SOCKETQUICVARINT_MAX)
              value = value % (SOCKETQUICVARINT_MAX + 1);

            uint8_t buf[8];
            size_t len = SocketQUICVarInt_encode (value, buf, sizeof (buf));

            /* Should always succeed for valid values */
            assert (len > 0);
            assert (len == SocketQUICVarInt_size (value));
          }
      }
      break;

    case OP_ROUNDTRIP:
      {
        /* Encode then decode - must produce same value */
        if (payload_size >= 8)
          {
            uint64_t original = parse_u64 (payload, 8);

            /* Cap to valid range */
            if (original > SOCKETQUICVARINT_MAX)
              original = original % (SOCKETQUICVARINT_MAX + 1);

            uint8_t buf[8];
            size_t encoded_len
                = SocketQUICVarInt_encode (original, buf, sizeof (buf));

            if (encoded_len > 0)
              {
                uint64_t decoded;
                size_t consumed;

                SocketQUICVarInt_Result res
                    = SocketQUICVarInt_decode (buf, encoded_len, &decoded,
                                               &consumed);

                /* Must succeed and produce same value */
                assert (res == QUIC_VARINT_OK);
                assert (decoded == original);
                assert (consumed == encoded_len);
              }
          }
      }
      break;

    case OP_MULTIPLE_DECODE:
      {
        /* Parse multiple consecutive varints from input */
        size_t offset = 0;
        int count = 0;

        while (offset < payload_size && count < 100)
          {
            uint64_t value;
            size_t consumed;

            SocketQUICVarInt_Result res
                = SocketQUICVarInt_decode (payload + offset,
                                           payload_size - offset, &value,
                                           &consumed);

            if (res != QUIC_VARINT_OK)
              break;

            /* Verify consumed is valid */
            assert (consumed > 0);
            assert (offset + consumed <= payload_size);

            offset += consumed;
            count++;
          }
      }
      break;
    }

  /* Test with all NULL parameters to verify null safety */
  SocketQUICVarInt_decode (NULL, 0, NULL, NULL);
  SocketQUICVarInt_encode (0, NULL, 0);
  SocketQUICVarInt_size (0);

  return 0;
}
