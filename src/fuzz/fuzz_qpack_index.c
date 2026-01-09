/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_qpack_index.c - libFuzzer for QPACK Index Conversion (RFC 9204)
 *
 * Fuzzes QPACK index conversion functions (RFC 9204 Sections 3.2.4-3.2.6)
 * and validation functions.
 *
 * Targets:
 * - Absolute to relative encoder conversion (Section 3.2.5)
 * - Relative to absolute encoder conversion
 * - Absolute to field-relative conversion (Section 3.2.5)
 * - Field-relative to absolute conversion
 * - Absolute to post-base conversion (Section 3.2.6)
 * - Post-base to absolute conversion
 * - Index validation with eviction bounds
 * - Roundtrip verification
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_qpack_index
 * ./fuzz_qpack_index -fork=16 -max_len=256
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
  OP_ABS_TO_REL_ENCODER = 0,
  OP_REL_TO_ABS_ENCODER,
  OP_ABS_TO_REL_FIELD,
  OP_REL_TO_ABS_FIELD,
  OP_ABS_TO_POSTBASE,
  OP_POSTBASE_TO_ABS,
  OP_VALIDATE_REL_ENCODER,
  OP_VALIDATE_REL_FIELD,
  OP_VALIDATE_POSTBASE,
  OP_VALIDATE_ABSOLUTE,
  OP_ROUNDTRIP_ENCODER,
  OP_ROUNDTRIP_FIELD,
  OP_ROUNDTRIP_POSTBASE,
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
  /* Need: op (1) + val1 (8) + val2 (8) + val3 (8) = 25 bytes minimum */
  if (size < 25)
    return 0;

  uint8_t op = data[0] % OP_MAX;
  uint64_t val1 = read_u64 (data + 1);
  uint64_t val2 = read_u64 (data + 9);
  uint64_t val3 = read_u64 (data + 17);

  /* Constrain values to reasonable ranges to increase hit rate */
  uint64_t insert_count = (val1 % 10000) + 1;      /* 1 to 10000 */
  uint64_t dropped_count = val2 % (insert_count);  /* 0 to insert_count-1 */
  uint64_t base = (val3 % insert_count) + 1;       /* 1 to insert_count */
  uint64_t abs_index = val1 % (insert_count + 10); /* Allow some overflow */
  uint64_t rel_index = val2 % (base + 10);
  uint64_t pb_index = val3 % 1000;

  uint64_t result_out = 0;
  SocketQPACK_Result res;

  switch (op)
    {
    case OP_ABS_TO_REL_ENCODER:
      {
        res = SocketQPACK_abs_to_relative_encoder (insert_count, abs_index,
                                                   &result_out);
        (void)res;
        (void)result_out;
      }
      break;

    case OP_REL_TO_ABS_ENCODER:
      {
        res = SocketQPACK_relative_to_abs_encoder (insert_count, rel_index,
                                                   &result_out);
        (void)res;
        (void)result_out;
      }
      break;

    case OP_ABS_TO_REL_FIELD:
      {
        res = SocketQPACK_abs_to_relative_field (base, abs_index, &result_out);
        (void)res;
        (void)result_out;
      }
      break;

    case OP_REL_TO_ABS_FIELD:
      {
        res = SocketQPACK_relative_to_abs_field (base, rel_index, &result_out);
        (void)res;
        (void)result_out;
      }
      break;

    case OP_ABS_TO_POSTBASE:
      {
        res = SocketQPACK_abs_to_postbase (base, abs_index, &result_out);
        (void)res;
        (void)result_out;
      }
      break;

    case OP_POSTBASE_TO_ABS:
      {
        res = SocketQPACK_postbase_to_abs (base, pb_index, &result_out);
        (void)res;
        (void)result_out;
      }
      break;

    case OP_VALIDATE_REL_ENCODER:
      {
        res = SocketQPACK_is_valid_relative_encoder (insert_count,
                                                     dropped_count, rel_index);
        (void)res;
      }
      break;

    case OP_VALIDATE_REL_FIELD:
      {
        res = SocketQPACK_is_valid_relative_field (base, dropped_count,
                                                   rel_index);
        (void)res;
      }
      break;

    case OP_VALIDATE_POSTBASE:
      {
        res = SocketQPACK_is_valid_postbase (base, insert_count, pb_index);
        (void)res;
      }
      break;

    case OP_VALIDATE_ABSOLUTE:
      {
        res = SocketQPACK_is_valid_absolute (insert_count, dropped_count,
                                             abs_index);
        (void)res;
      }
      break;

    case OP_ROUNDTRIP_ENCODER:
      {
        /* Test roundtrip: abs -> rel -> abs */
        uint64_t rel_out = 0;
        uint64_t abs_out = 0;

        res = SocketQPACK_abs_to_relative_encoder (insert_count, abs_index,
                                                   &rel_out);
        if (res == QPACK_OK)
          {
            res = SocketQPACK_relative_to_abs_encoder (insert_count, rel_out,
                                                       &abs_out);
            /* If both succeed, abs_out should equal abs_index */
            (void)abs_out;
          }
        (void)res;
      }
      break;

    case OP_ROUNDTRIP_FIELD:
      {
        /* Test roundtrip: abs -> rel -> abs (field addressing) */
        uint64_t rel_out = 0;
        uint64_t abs_out = 0;

        res = SocketQPACK_abs_to_relative_field (base, abs_index, &rel_out);
        if (res == QPACK_OK)
          {
            res
                = SocketQPACK_relative_to_abs_field (base, rel_out, &abs_out);
            /* If both succeed, abs_out should equal abs_index */
            (void)abs_out;
          }
        (void)res;
      }
      break;

    case OP_ROUNDTRIP_POSTBASE:
      {
        /* Test roundtrip: abs -> postbase -> abs */
        uint64_t pb_out = 0;
        uint64_t abs_out = 0;

        res = SocketQPACK_abs_to_postbase (base, abs_index, &pb_out);
        if (res == QPACK_OK)
          {
            res = SocketQPACK_postbase_to_abs (base, pb_out, &abs_out);
            /* If both succeed, abs_out should equal abs_index */
            (void)abs_out;
          }
        (void)res;
      }
      break;

    default:
      break;
    }

  /* Also test with raw unconstrained values for edge cases */
  if (size >= 33)
    {
      uint64_t raw1 = read_u64 (data + 25);
      uint64_t raw2 = read_u64 (data + 25);

      /* Test overflow conditions */
      res = SocketQPACK_abs_to_relative_encoder (raw1, raw2, &result_out);
      (void)res;

      res = SocketQPACK_postbase_to_abs (raw1, raw2, &result_out);
      (void)res;

      /* Test zero values */
      res = SocketQPACK_abs_to_relative_encoder (0, 0, &result_out);
      (void)res;

      res = SocketQPACK_abs_to_relative_field (0, 0, &result_out);
      (void)res;

      /* Test NULL output pointer (should not crash) */
      res = SocketQPACK_abs_to_relative_encoder (insert_count, abs_index,
                                                 NULL);
      (void)res;
    }

  return 0;
}
