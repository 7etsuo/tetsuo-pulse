/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_qpack_literal.c - libFuzzer for QPACK Literal Field Lines (RFC 9204)
 *
 * Fuzzes QPACK literal field line encoding/decoding (RFC 9204 Sections 4.5.4,
 * 4.5.6). Tests literal values with name references and fully literal fields.
 *
 * Targets:
 * - Literal with name reference encode/decode (Section 4.5.4)
 * - Literal with literal name encode/decode (Section 4.5.6)
 * - Huffman encoding/decoding
 * - Never-indexed flag handling
 * - Name index validation
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_qpack_literal
 * ./fuzz_qpack_literal -fork=16 -max_len=4096
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/qpack/SocketQPACK.h"

/**
 * @brief Operations to fuzz
 */
enum FuzzOp
{
  OP_ENCODE_NAME_REF = 0,
  OP_DECODE_NAME_REF,
  OP_DECODE_NAME_REF_ARENA,
  OP_VALIDATE_NAME_REF_INDEX,
  OP_ENCODE_LITERAL_NAME,
  OP_DECODE_LITERAL_NAME,
  OP_ROUNDTRIP_NAME_REF,
  OP_ROUNDTRIP_LITERAL_NAME,
  OP_MAX
};

/**
 * @brief Read 64-bit value from byte array (little-endian)
 */
static uint64_t
read_u64 (const uint8_t *p)
{
  return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[7] << 56);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 17)
    return 0;

  uint8_t op = data[0] % OP_MAX;
  uint64_t val1 = read_u64 (data + 1);
  uint64_t val2 = read_u64 (data + 9);

  /* Extract control bits */
  bool is_static = (data[0] >> 4) & 1;
  bool never_indexed = (data[0] >> 5) & 1;
  bool use_huffman = (data[0] >> 6) & 1;

  /* Constrain values */
  uint64_t name_index = is_static ? (val1 % 99) : (val1 % 500);
  uint64_t base = (val1 % 10000) + 1;
  uint64_t dropped_count = val2 % base;

  /* Use fuzz data as value string */
  const unsigned char *value_data = data + 17;
  size_t value_len = (size > 17) ? (size - 17) % 256 : 0;

  SocketQPACK_Result res;
  unsigned char output[512];
  size_t bytes_written = 0;
  size_t bytes_consumed = 0;

  Arena_T arena_instance = Arena_new ();
  if (!arena_instance)
    return 0;
  volatile Arena_T arena = arena_instance;
  (void)arena;

  TRY
  {
    switch (op)
      {
      case OP_ENCODE_NAME_REF:
        {
          res = SocketQPACK_encode_literal_name_ref (
              output, sizeof (output), is_static, name_index, never_indexed,
              value_data, value_len, use_huffman, &bytes_written);
          (void)res;
          (void)bytes_written;
        }
        break;

      case OP_DECODE_NAME_REF:
        {
          if (size > 17)
            {
              SocketQPACK_LiteralNameRef result = { 0 };
              res = SocketQPACK_decode_literal_name_ref (value_data, size - 17,
                                                         &result,
                                                         &bytes_consumed);
              (void)res;
              (void)result.name_index;
              (void)result.is_static;
              (void)result.never_indexed;
            }
        }
        break;

      case OP_DECODE_NAME_REF_ARENA:
        {
          if (size > 17)
            {
              SocketQPACK_LiteralNameRef result = { 0 };
              res = SocketQPACK_decode_literal_name_ref_arena (
                  value_data, size - 17, arena_instance, &result,
                  &bytes_consumed);
              (void)res;
              if (res == QPACK_OK && result.value)
                {
                  (void)result.value[0]; /* Touch decoded value */
                }
            }
        }
        break;

      case OP_VALIDATE_NAME_REF_INDEX:
        {
          res = SocketQPACK_validate_literal_name_ref_index (
              is_static, name_index, base, dropped_count);
          (void)res;

          /* Test with various index values */
          res = SocketQPACK_validate_literal_name_ref_index (true, 0, base,
                                                             dropped_count);
          (void)res;
          res = SocketQPACK_validate_literal_name_ref_index (true, 98, base,
                                                             dropped_count);
          (void)res;
          res = SocketQPACK_validate_literal_name_ref_index (true, 99, base,
                                                             dropped_count);
          (void)res;
        }
        break;

      case OP_ENCODE_LITERAL_NAME:
        {
          /* Use part of fuzz data as name */
          size_t name_len = value_len / 2;
          const unsigned char *name_data = value_data;
          const unsigned char *val = value_data + name_len;
          size_t val_len = value_len - name_len;

          res = SocketQPACK_encode_literal_field_literal_name (
              output, sizeof (output), name_data, name_len, use_huffman, val,
              val_len, use_huffman, never_indexed, &bytes_written);
          (void)res;
        }
        break;

      case OP_DECODE_LITERAL_NAME:
        {
          if (size > 17)
            {
              unsigned char name_out[256];
              unsigned char value_out[256];
              size_t name_len_out = 0;
              size_t value_len_out = 0;
              bool never_idx_out = false;

              res = SocketQPACK_decode_literal_field_literal_name (
                  value_data, size - 17, name_out, sizeof (name_out),
                  &name_len_out, value_out, sizeof (value_out), &value_len_out,
                  &never_idx_out, &bytes_consumed);
              (void)res;
              (void)name_len_out;
              (void)value_len_out;
              (void)never_idx_out;
            }
        }
        break;

      case OP_ROUNDTRIP_NAME_REF:
        {
          /* Encode then decode */
          res = SocketQPACK_encode_literal_name_ref (
              output, sizeof (output), is_static, name_index, never_indexed,
              value_data, value_len % 64, false, /* No Huffman for roundtrip */
              &bytes_written);

          if (res == QPACK_OK && bytes_written > 0)
            {
              SocketQPACK_LiteralNameRef decoded = { 0 };
              res = SocketQPACK_decode_literal_name_ref (
                  output, bytes_written, &decoded, &bytes_consumed);
              (void)decoded.name_index;
            }
          (void)res;
        }
        break;

      case OP_ROUNDTRIP_LITERAL_NAME:
        {
          /* Encode then decode literal name */
          size_t name_len = (value_len / 2) % 32;
          size_t val_len = (value_len / 2) % 32;

          res = SocketQPACK_encode_literal_field_literal_name (
              output, sizeof (output), value_data, name_len, false,
              value_data + name_len, val_len, false, never_indexed,
              &bytes_written);

          if (res == QPACK_OK && bytes_written > 0)
            {
              unsigned char name_out[64];
              unsigned char value_out[64];
              size_t name_len_out = 0;
              size_t value_len_out = 0;
              bool never_idx_out = false;

              res = SocketQPACK_decode_literal_field_literal_name (
                  output, bytes_written, name_out, sizeof (name_out),
                  &name_len_out, value_out, sizeof (value_out), &value_len_out,
                  &never_idx_out, &bytes_consumed);
              (void)name_len_out;
              (void)value_len_out;
            }
          (void)res;
        }
        break;

      default:
        break;
      }
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on allocation failure */
  }
  END_TRY;

  Arena_dispose (&arena_instance);

  return 0;
}
