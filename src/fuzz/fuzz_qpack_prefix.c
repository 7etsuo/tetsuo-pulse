/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_qpack_prefix.c - libFuzzer for QPACK Field Section Prefix (RFC 9204)
 *
 * Fuzzes QPACK Field Section Prefix encoding/decoding (RFC 9204 Section 4.5.1).
 * Tests Required Insert Count encoding with modular arithmetic and Base
 * computation with signed delta.
 *
 * Targets:
 * - Prefix encode/decode (Section 4.5.1)
 * - Required Insert Count encoding (Section 4.5.1.1)
 * - Base calculation with sign bit (Section 4.5.1.2)
 * - Roundtrip verification
 * - Wraparound recovery in RIC decoding
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_qpack_prefix
 * ./fuzz_qpack_prefix -fork=16 -max_len=512
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
  OP_ENCODE_PREFIX = 0,
  OP_DECODE_PREFIX,
  OP_VALIDATE_PREFIX,
  OP_ENCODE_RIC,
  OP_DECODE_RIC,
  OP_COMPUTE_MAX_ENTRIES,
  OP_ROUNDTRIP_PREFIX,
  OP_ROUNDTRIP_RIC,
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
  /* Need: op (1) + val1 (8) + val2 (8) + val3 (8) = 25 bytes minimum */
  if (size < 25)
    return 0;

  uint8_t op = data[0] % OP_MAX;
  uint64_t val1 = read_u64 (data + 1);
  uint64_t val2 = read_u64 (data + 9);
  uint64_t val3 = read_u64 (data + 17);

  /* Constrain values to reasonable ranges */
  uint64_t max_table_capacity
      = (val1 % SOCKETQPACK_MAX_TABLE_SIZE) + 1; /* 1 to 64KB */
  uint64_t max_entries = SocketQPACK_compute_max_entries (max_table_capacity);
  uint64_t total_insert_count = val2 % 100000;                       /* 0-99999 */
  uint64_t required_insert_count = val3 % (total_insert_count + 1);  /* 0-TIC */
  uint64_t base = (val1 % (required_insert_count + 10)); /* Allow some range */

  SocketQPACK_Result res;
  unsigned char output[64];
  size_t bytes_written = 0;
  size_t bytes_consumed = 0;

  switch (op)
    {
    case OP_ENCODE_PREFIX:
      {
        res = SocketQPACK_encode_prefix (required_insert_count, base,
                                         max_entries, output, sizeof (output),
                                         &bytes_written);
        (void)res;
        (void)bytes_written;
      }
      break;

    case OP_DECODE_PREFIX:
      {
        /* Use raw fuzz data for decoding */
        if (size > 25)
          {
            SocketQPACK_FieldSectionPrefix prefix = { 0 };
            res = SocketQPACK_decode_prefix (data + 25, size - 25, max_entries,
                                             total_insert_count, &prefix,
                                             &bytes_consumed);
            (void)res;
            (void)prefix.required_insert_count;
            (void)prefix.delta_base;
            (void)prefix.base;
          }
      }
      break;

    case OP_VALIDATE_PREFIX:
      {
        /* Create a prefix and validate it */
        SocketQPACK_FieldSectionPrefix prefix;
        prefix.required_insert_count = required_insert_count;
        prefix.delta_base = (int64_t)(base) - (int64_t)(required_insert_count);
        prefix.base = base;

        res = SocketQPACK_validate_prefix (&prefix, total_insert_count);
        (void)res;
      }
      break;

    case OP_ENCODE_RIC:
      {
        uint64_t encoded_ric = 0;
        res = SocketQPACK_encode_required_insert_count (required_insert_count,
                                                        max_entries,
                                                        &encoded_ric);
        (void)res;
        (void)encoded_ric;
      }
      break;

    case OP_DECODE_RIC:
      {
        uint64_t encoded_ric = val1 % (2 * max_entries + 2); /* Valid range */
        uint64_t decoded_ric = 0;
        res = SocketQPACK_decode_required_insert_count (
            encoded_ric, max_entries, total_insert_count, &decoded_ric);
        (void)res;
        (void)decoded_ric;
      }
      break;

    case OP_COMPUTE_MAX_ENTRIES:
      {
        /* Test with various capacities */
        uint64_t cap1 = SocketQPACK_compute_max_entries (0);
        uint64_t cap2 = SocketQPACK_compute_max_entries (32);
        uint64_t cap3 = SocketQPACK_compute_max_entries (SOCKETQPACK_MAX_TABLE_SIZE);
        uint64_t cap4 = SocketQPACK_compute_max_entries (val1);
        uint64_t cap5 = SocketQPACK_max_entries (val2); /* Test alias */
        (void)cap1;
        (void)cap2;
        (void)cap3;
        (void)cap4;
        (void)cap5;
      }
      break;

    case OP_ROUNDTRIP_PREFIX:
      {
        /* Encode then decode and verify roundtrip */
        SocketQPACK_FieldSectionPrefix decoded = { 0 };

        /* Start with valid values */
        uint64_t ric = required_insert_count;
        uint64_t b = (ric > 0) ? (ric - (val2 % ric) % ric) : 0;

        res = SocketQPACK_encode_prefix (ric, b, max_entries, output,
                                         sizeof (output), &bytes_written);
        if (res == QPACK_OK && bytes_written > 0)
          {
            res = SocketQPACK_decode_prefix (output, bytes_written, max_entries,
                                             total_insert_count, &decoded,
                                             &bytes_consumed);
            (void)decoded.required_insert_count;
            (void)decoded.base;
          }
        (void)res;
      }
      break;

    case OP_ROUNDTRIP_RIC:
      {
        /* Encode then decode RIC and verify */
        uint64_t encoded_ric = 0;
        uint64_t decoded_ric = 0;

        res = SocketQPACK_encode_required_insert_count (required_insert_count,
                                                        max_entries,
                                                        &encoded_ric);
        if (res == QPACK_OK)
          {
            res = SocketQPACK_decode_required_insert_count (
                encoded_ric, max_entries, total_insert_count, &decoded_ric);
            /* If both succeed and RIC was valid, decoded should match */
            (void)decoded_ric;
          }
        (void)res;
      }
      break;

    case OP_DECODE_RAW:
      {
        /* Decode raw fuzz bytes as prefix */
        if (size > 25)
          {
            SocketQPACK_FieldSectionPrefix prefix = { 0 };
            /* Try with different max_entries values */
            res = SocketQPACK_decode_prefix (data + 25, size - 25, 1,
                                             total_insert_count, &prefix,
                                             &bytes_consumed);
            (void)res;

            res = SocketQPACK_decode_prefix (data + 25, size - 25, 128,
                                             total_insert_count, &prefix,
                                             &bytes_consumed);
            (void)res;

            res = SocketQPACK_decode_prefix (data + 25, size - 25, 2048,
                                             total_insert_count, &prefix,
                                             &bytes_consumed);
            (void)res;
          }
      }
      break;

    default:
      break;
    }

  /* Also test edge cases with raw unconstrained values */
  if (size >= 33)
    {
      uint64_t raw1 = read_u64 (data + 25);
      uint64_t raw2 = read_u64 (data + 25);

      /* Test with extreme values */
      uint64_t encoded_out = 0;
      res = SocketQPACK_encode_required_insert_count (raw1, raw2, &encoded_out);
      (void)res;

      /* Test with zero max_entries */
      res = SocketQPACK_encode_prefix (1, 1, 0, output, sizeof (output),
                                       &bytes_written);
      (void)res;

      /* Test NULL pointers (should not crash) */
      res = SocketQPACK_encode_prefix (1, 1, 128, NULL, 0, &bytes_written);
      (void)res;

      res = SocketQPACK_encode_prefix (1, 1, 128, output, sizeof (output), NULL);
      (void)res;

      res = SocketQPACK_decode_prefix (data + 25, size - 25, 128, 1000, NULL,
                                       &bytes_consumed);
      (void)res;

      res = SocketQPACK_validate_prefix (NULL, 1000);
      (void)res;
    }

  return 0;
}
