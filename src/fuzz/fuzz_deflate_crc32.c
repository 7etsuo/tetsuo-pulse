/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_deflate_crc32.c - libFuzzer harness for CRC-32 implementation
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketDeflate_crc32() with arbitrary input
 * - Incremental vs one-shot consistency
 * - Large and small inputs
 * - Various chunk sizes for incremental computation
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_deflate_crc32
 * Run:   ./fuzz_deflate_crc32 -max_len=65536 -runs=1000000
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "deflate/SocketDeflate.h"

/* Maximum input size to prevent timeouts */
#define MAX_INPUT_SIZE 65536

/**
 * Fuzz operation modes
 */
enum FuzzOp
{
  OP_ONE_SHOT = 0,        /* Single call CRC */
  OP_INCREMENTAL_FIXED,   /* Fixed chunk size */
  OP_INCREMENTAL_VARYING, /* Varying chunk sizes from fuzz input */
  OP_COMPARE,             /* Compare one-shot vs incremental */
  OP_MAX
};

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 *
 * The fuzzer exercises CRC-32 computation with various input patterns
 * and verifies internal consistency (incremental == one-shot).
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  uint8_t op;
  uint32_t crc_oneshot;
  uint32_t crc_incremental;
  const uint8_t *payload;
  size_t payload_size;

  /* Need at least 1 byte for operation code */
  if (size < 1)
    return 0;

  /* Limit input size */
  if (size > MAX_INPUT_SIZE)
    return 0;

  /* Parse operation */
  op = data[0] % OP_MAX;
  payload = data + 1;
  payload_size = size - 1;

  switch (op)
    {
    case OP_ONE_SHOT:
      {
        /* Simple one-shot CRC computation */
        crc_oneshot = SocketDeflate_crc32 (0, payload, payload_size);
        (void)crc_oneshot;
      }
      break;

    case OP_INCREMENTAL_FIXED:
      {
        /* Incremental CRC with fixed chunk size */
        size_t chunk_size = 64;
        crc_incremental = 0;

        for (size_t offset = 0; offset < payload_size; offset += chunk_size)
          {
            size_t chunk = (offset + chunk_size <= payload_size)
                               ? chunk_size
                               : payload_size - offset;
            crc_incremental = SocketDeflate_crc32 (
                crc_incremental, payload + offset, chunk);
          }
        (void)crc_incremental;
      }
      break;

    case OP_INCREMENTAL_VARYING:
      {
        /* Incremental CRC with chunk sizes derived from input */
        if (payload_size < 2)
          return 0;

        crc_incremental = 0;
        size_t offset = 0;

        while (offset < payload_size)
          {
            /* Use next byte to determine chunk size (1-256) */
            size_t chunk_hint = payload[offset] + 1;
            size_t remaining = payload_size - offset;
            size_t chunk = (chunk_hint < remaining) ? chunk_hint : remaining;

            crc_incremental = SocketDeflate_crc32 (
                crc_incremental, payload + offset, chunk);
            offset += chunk;
          }
        (void)crc_incremental;
      }
      break;

    case OP_COMPARE:
      {
        /* Verify one-shot equals incremental (byte-by-byte) */
        crc_oneshot = SocketDeflate_crc32 (0, payload, payload_size);

        crc_incremental = 0;
        for (size_t i = 0; i < payload_size; i++)
          {
            crc_incremental
                = SocketDeflate_crc32 (crc_incremental, payload + i, 1);
          }

        /* This should always hold - crash if not */
        if (crc_oneshot != crc_incremental)
          {
            __builtin_trap ();
          }
      }
      break;
    }

  return 0;
}
