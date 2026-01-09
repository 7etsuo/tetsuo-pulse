/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_qpack_indexed.c - libFuzzer for QPACK Indexed Field Lines (RFC 9204)
 *
 * Fuzzes QPACK indexed field line encoding/decoding (RFC 9204 Sections 4.5.2,
 * 4.5.3). Tests static table references, dynamic table relative indexing, and
 * post-base indexing.
 *
 * Targets:
 * - Indexed field line encode/decode (Section 4.5.2)
 * - Post-base indexed field line (Section 4.5.3)
 * - Static table bounds (0-98)
 * - Dynamic table relative indexing
 * - Index validation against eviction bounds
 * - Roundtrip verification
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_qpack_indexed
 * ./fuzz_qpack_indexed -fork=16 -max_len=512
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "http/qpack/SocketQPACK.h"

/**
 * @brief Operations to fuzz
 */
enum FuzzOp
{
  OP_ENCODE_INDEXED = 0,
  OP_DECODE_INDEXED,
  OP_RESOLVE_INDEXED,
  OP_ENCODE_POSTBASE,
  OP_DECODE_POSTBASE,
  OP_VALIDATE_POSTBASE,
  OP_POSTBASE_TO_ABSOLUTE,
  OP_IS_INDEXED_FIELD_LINE,
  OP_IS_INDEXED_POSTBASE,
  OP_ROUNDTRIP_INDEXED,
  OP_ROUNDTRIP_POSTBASE,
  OP_DECODE_RAW,
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

  /* Constrain values to reasonable ranges */
  uint64_t index = val1 % 200;             /* Allow some overflow past static table */
  int is_static = (data[0] >> 4) & 1;
  uint64_t base = (val1 % 10000) + 1;      /* 1 to 10000 */
  uint64_t insert_count = base + (val2 % 1000); /* >= base */
  uint64_t dropped_count = val2 % base;    /* 0 to base-1 */
  uint64_t post_base_index = val2 % 500;

  SocketQPACK_Result res;
  unsigned char output[64];
  size_t bytes_written = 0;
  size_t bytes_consumed = 0;

  switch (op)
    {
    case OP_ENCODE_INDEXED:
      {
        /* Encode indexed field line */
        res = SocketQPACK_encode_indexed_field (output, sizeof (output), index,
                                                is_static, &bytes_written);
        (void)res;
        (void)bytes_written;

        /* Also test with static table bounds */
        res = SocketQPACK_encode_indexed_field (output, sizeof (output),
                                                val1 % 99, 1, &bytes_written);
        (void)res;

        /* Test with dynamic table */
        res = SocketQPACK_encode_indexed_field (output, sizeof (output),
                                                val2 % 1000, 0, &bytes_written);
        (void)res;
      }
      break;

    case OP_DECODE_INDEXED:
      {
        /* Decode from raw fuzz data */
        if (size > 17)
          {
            uint64_t decoded_index = 0;
            int decoded_static = 0;
            res = SocketQPACK_decode_indexed_field (data + 17, size - 17,
                                                    &decoded_index,
                                                    &decoded_static,
                                                    &bytes_consumed);
            (void)res;
            (void)decoded_index;
            (void)decoded_static;
          }
      }
      break;

    case OP_RESOLVE_INDEXED:
      {
        uint64_t abs_index = 0;

        /* Resolve static table reference */
        res = SocketQPACK_resolve_indexed_field (index % 99, 1, base,
                                                 dropped_count, &abs_index);
        (void)res;
        (void)abs_index;

        /* Resolve dynamic table reference */
        res = SocketQPACK_resolve_indexed_field (index % base, 0, base,
                                                 dropped_count, &abs_index);
        (void)res;
      }
      break;

    case OP_ENCODE_POSTBASE:
      {
        res = SocketQPACK_encode_indexed_postbase (post_base_index, output,
                                                   sizeof (output),
                                                   &bytes_written);
        (void)res;
        (void)bytes_written;
      }
      break;

    case OP_DECODE_POSTBASE:
      {
        /* Decode from raw fuzz data */
        if (size > 17)
          {
            uint64_t decoded_pb = 0;
            res = SocketQPACK_decode_indexed_postbase (data + 17, size - 17,
                                                       &decoded_pb,
                                                       &bytes_consumed);
            (void)res;
            (void)decoded_pb;
          }
      }
      break;

    case OP_VALIDATE_POSTBASE:
      {
        res = SocketQPACK_validate_indexed_postbase (base, insert_count,
                                                     post_base_index);
        (void)res;

        /* Test with constrained valid value */
        uint64_t valid_pb = (insert_count > base) ? val2 % (insert_count - base) : 0;
        res = SocketQPACK_validate_indexed_postbase (base, insert_count,
                                                     valid_pb);
        (void)res;
      }
      break;

    case OP_POSTBASE_TO_ABSOLUTE:
      {
        uint64_t abs_index = 0;
        res = SocketQPACK_indexed_postbase_to_absolute (base, post_base_index,
                                                        &abs_index);
        (void)res;
        (void)abs_index;

        /* Test with unconstrained values */
        res = SocketQPACK_indexed_postbase_to_absolute (val1, val2, &abs_index);
        (void)res;
      }
      break;

    case OP_IS_INDEXED_FIELD_LINE:
      {
        /* Test all possible first bytes */
        for (size_t i = 0; i < size && i < 256; i++)
          {
            int is_indexed = SocketQPACK_is_indexed_field_line (data[i]);
            (void)is_indexed;
          }
      }
      break;

    case OP_IS_INDEXED_POSTBASE:
      {
        /* Test all possible first bytes */
        for (size_t i = 0; i < size && i < 256; i++)
          {
            bool is_pb = SocketQPACK_is_indexed_postbase (data[i]);
            (void)is_pb;
          }
      }
      break;

    case OP_ROUNDTRIP_INDEXED:
      {
        /* Encode then decode indexed field line */
        uint64_t test_index = (is_static) ? (index % 99) : (index % 1000);

        res = SocketQPACK_encode_indexed_field (output, sizeof (output),
                                                test_index, is_static,
                                                &bytes_written);
        if (res == QPACK_OK && bytes_written > 0)
          {
            uint64_t decoded_index = 0;
            int decoded_static = 0;
            res = SocketQPACK_decode_indexed_field (output, bytes_written,
                                                    &decoded_index,
                                                    &decoded_static,
                                                    &bytes_consumed);
            (void)decoded_index;
            (void)decoded_static;
          }
        (void)res;
      }
      break;

    case OP_ROUNDTRIP_POSTBASE:
      {
        /* Encode then decode post-base indexed field line */
        res = SocketQPACK_encode_indexed_postbase (post_base_index, output,
                                                   sizeof (output),
                                                   &bytes_written);
        if (res == QPACK_OK && bytes_written > 0)
          {
            uint64_t decoded_pb = 0;
            res = SocketQPACK_decode_indexed_postbase (output, bytes_written,
                                                       &decoded_pb,
                                                       &bytes_consumed);
            (void)decoded_pb;
          }
        (void)res;
      }
      break;

    case OP_DECODE_RAW:
      {
        /* Try decoding raw fuzz bytes as various field line types */
        if (size > 17)
          {
            uint64_t idx = 0;
            int is_s = 0;
            uint64_t pb = 0;

            /* Check pattern and decode accordingly */
            if (SocketQPACK_is_indexed_field_line (data[17]))
              {
                res = SocketQPACK_decode_indexed_field (data + 17, size - 17,
                                                        &idx, &is_s,
                                                        &bytes_consumed);
                (void)res;
              }
            else if (SocketQPACK_is_indexed_postbase (data[17]))
              {
                res = SocketQPACK_decode_indexed_postbase (data + 17, size - 17,
                                                           &pb, &bytes_consumed);
                (void)res;
              }
          }
      }
      break;

    default:
      break;
    }

  /* Test edge cases */
  {
    /* Static table boundary (max is 98) */
    res = SocketQPACK_encode_indexed_field (output, sizeof (output), 98, 1,
                                            &bytes_written);
    (void)res;

    res = SocketQPACK_encode_indexed_field (output, sizeof (output), 99, 1,
                                            &bytes_written);
    (void)res;

    /* Zero index */
    res = SocketQPACK_encode_indexed_field (output, sizeof (output), 0, 1,
                                            &bytes_written);
    (void)res;

    res = SocketQPACK_encode_indexed_field (output, sizeof (output), 0, 0,
                                            &bytes_written);
    (void)res;

    /* NULL pointer tests */
    res = SocketQPACK_encode_indexed_field (NULL, 0, 0, 0, &bytes_written);
    (void)res;

    res = SocketQPACK_encode_indexed_field (output, sizeof (output), 0, 0,
                                            NULL);
    (void)res;

    uint64_t dummy_idx = 0;
    int dummy_static = 0;
    res = SocketQPACK_decode_indexed_field (data + 1, size - 1, NULL,
                                            &dummy_static, &bytes_consumed);
    (void)res;

    res = SocketQPACK_decode_indexed_field (data + 1, size - 1, &dummy_idx,
                                            NULL, &bytes_consumed);
    (void)res;

    res = SocketQPACK_resolve_indexed_field (0, 0, 0, 0, NULL);
    (void)res;
  }

  return 0;
}
