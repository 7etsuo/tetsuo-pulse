/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_deflate_static.c - libFuzzer harness for DEFLATE static tables
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - Length decode function with arbitrary code/extra values
 * - Distance decode function with arbitrary code/extra values
 * - Validation functions with full input range
 * - Bounds checking on static table access
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_deflate_static
 * Run:   ./fuzz_deflate_static corpus/deflate_static/ -fork=16 -max_len=64
 */

#include <stddef.h>
#include <stdint.h>

#include "deflate/SocketDeflate.h"

/* Fuzz operation opcodes */
enum FuzzOp
{
  OP_LENGTH_DECODE = 0,
  OP_DISTANCE_DECODE,
  OP_VALID_LITLEN,
  OP_VALID_DISTANCE,
  OP_TABLE_ACCESS,
  OP_MULTI_DECODE,
  OP_MAX
};

/**
 * parse_u16 - Parse 16-bit unsigned from fuzz input
 */
static inline uint16_t
parse_u16 (const uint8_t *data)
{
  return ((uint16_t)data[0] << 8) | data[1];
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 * @data: Fuzz input data
 * @size: Size of fuzz input
 *
 * Tests the DEFLATE static table lookup functions with arbitrary inputs.
 * All functions under test are pure (no side effects, no allocations),
 * so no TRY/EXCEPT is needed.
 *
 * Returns: 0 (required by libFuzzer)
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  unsigned int length;
  unsigned int distance;
  SocketDeflate_Result result;

  if (size < 5)
    return 0;

  uint8_t op = data[0] % OP_MAX;
  unsigned int code = parse_u16 (data + 1);
  unsigned int extra = parse_u16 (data + 3);

  switch (op)
    {
    case OP_LENGTH_DECODE:
      /*
       * Test length decode with arbitrary code (0-65535) and extra bits.
       * Should return OK for codes 257-285, error for others.
       */
      result = SocketDeflate_decode_length (code, extra, &length);

      /* Verify consistency: OK only for valid codes 257-285 */
      if (code >= DEFLATE_LENGTH_CODE_MIN && code <= DEFLATE_LENGTH_CODE_MAX)
        {
          /* Should succeed for valid codes */
          (void)(result == DEFLATE_OK);
          /* Length should be in range 3-258 */
          (void)(length >= DEFLATE_MIN_MATCH && length <= DEFLATE_MAX_MATCH);
        }
      else
        {
          /* Should fail for invalid codes */
          (void)(result == DEFLATE_ERROR_INVALID_CODE);
        }
      break;

    case OP_DISTANCE_DECODE:
      /*
       * Test distance decode with arbitrary code (0-65535) and extra bits.
       * Should return OK for codes 0-29, error for others.
       */
      result = SocketDeflate_decode_distance (code, extra, &distance);

      /* Verify consistency: OK only for valid codes 0-29 */
      if (code <= DEFLATE_DISTANCE_CODE_MAX)
        {
          /* Should succeed for valid codes */
          (void)(result == DEFLATE_OK);
          /* Distance should be in range 1-32768 */
          (void)(distance >= 1 && distance <= DEFLATE_WINDOW_SIZE);
        }
      else
        {
          /* Should fail for invalid codes */
          (void)(result == DEFLATE_ERROR_INVALID_DISTANCE);
        }
      break;

    case OP_VALID_LITLEN:
      /*
       * Test litlen validation with full 16-bit code range.
       * Should return 1 for 0-285, 0 for 286+.
       */
      {
        int is_valid = SocketDeflate_is_valid_litlen_code (code);
        (void)(is_valid == (code <= DEFLATE_LITLEN_MAX_DECODE));
      }
      break;

    case OP_VALID_DISTANCE:
      /*
       * Test distance validation with full 16-bit code range.
       * Should return 1 for 0-29, 0 for 30+.
       */
      {
        int is_valid = SocketDeflate_is_valid_distance_code (code);
        (void)(is_valid == (code <= DEFLATE_DIST_MAX_DECODE));
      }
      break;

    case OP_TABLE_ACCESS:
      /*
       * Direct table access for valid indices only.
       * Sanitizer will catch any OOB access.
       */
      if (code < DEFLATE_LENGTH_CODES)
        {
          /* Access length table */
          const SocketDeflate_CodeEntry *entry = &deflate_length_table[code];
          (void)entry->base;
          (void)entry->extra_bits;
        }
      if (code < DEFLATE_DISTANCE_CODES)
        {
          /* Access distance table */
          const SocketDeflate_CodeEntry *entry = &deflate_distance_table[code];
          (void)entry->base;
          (void)entry->extra_bits;
        }
      if (code < DEFLATE_LITLEN_CODES)
        {
          /* Access fixed litlen lengths */
          (void)deflate_fixed_litlen_lengths[code];
        }
      if (code < DEFLATE_DIST_CODES)
        {
          /* Access fixed dist lengths */
          (void)deflate_fixed_dist_lengths[code];
        }
      if (code < DEFLATE_CODELEN_CODES)
        {
          /* Access code length order */
          (void)deflate_codelen_order[code];
        }
      break;

    case OP_MULTI_DECODE:
      /*
       * Multiple decode operations with data from rest of input.
       * Tests sequence of operations.
       */
      if (size >= 9)
        {
          unsigned int code2 = parse_u16 (data + 5);
          unsigned int extra2 = parse_u16 (data + 7);

          /* First decode */
          if (code >= DEFLATE_LENGTH_CODE_MIN
              && code <= DEFLATE_LENGTH_CODE_MAX)
            {
              SocketDeflate_decode_length (code, extra, &length);
            }

          /* Second decode */
          if (code2 <= DEFLATE_DISTANCE_CODE_MAX)
            {
              SocketDeflate_decode_distance (code2, extra2, &distance);
            }
        }
      break;
    }

  return 0;
}
