/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_deflate_stored.c - libFuzzer harness for DEFLATE stored block decoder
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketDeflate_decode_stored_block with various inputs
 * - NLEN validation (one's complement check)
 * - Incomplete header handling
 * - Truncated data handling
 * - Edge cases: empty blocks, max-size blocks
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_deflate_stored
 * Run:   ./fuzz_deflate_stored corpus/deflate_stored/ -fork=16 -max_len=70000
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "deflate/SocketDeflate.h"

/* Fuzz operation opcodes */
enum FuzzOp
{
  OP_VALID_BLOCK = 0,     /* Generate valid stored block */
  OP_INVALID_NLEN,        /* Intentionally wrong NLEN */
  OP_TRUNCATED_HEADER,    /* Truncate before NLEN complete */
  OP_TRUNCATED_DATA,      /* Truncate during data section */
  OP_RANDOM_BYTES,        /* Raw fuzz input as stored block */
  OP_ALIGNMENT_TEST,      /* Test with pre-consumed bits */
  OP_MAX
};

/* Maximum output buffer size for fuzzing */
#define MAX_OUTPUT_SIZE 65536

/**
 * make_valid_stored_block - Construct a valid stored block header
 * @len: Block length (0-65535)
 * @header: Output buffer (must be at least 4 bytes)
 *
 * Writes LEN and NLEN (one's complement) in LSB-first order.
 */
static void
make_valid_stored_block (uint16_t len, uint8_t *header)
{
  uint16_t nlen = ~len;
  header[0] = len & 0xFF;
  header[1] = (len >> 8) & 0xFF;
  header[2] = nlen & 0xFF;
  header[3] = (nlen >> 8) & 0xFF;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 * @data: Fuzz input data
 * @size: Size of fuzz input
 *
 * Exercises the stored block decoder with various inputs.
 * The first byte selects the operation mode.
 *
 * Returns: 0 (required by libFuzzer)
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena;
  SocketDeflate_BitReader_T reader;
  SocketDeflate_Result result;
  uint8_t *output;
  size_t written;
  uint8_t header[4];
  uint8_t *input_buf;
  size_t input_size;

  if (size < 2)
    return 0;

  /* Parse fuzz input:
   * byte[0]: operation code
   * byte[1..]: data for the operation
   */
  uint8_t op = data[0] % OP_MAX;
  const uint8_t *fuzz_data = data + 1;
  size_t fuzz_size = size - 1;

  /* Create arena and output buffer */
  arena = Arena_new ();
  output = Arena_alloc (arena, MAX_OUTPUT_SIZE, __FILE__, __LINE__);
  reader = SocketDeflate_BitReader_new (arena);

  switch (op)
    {
    case OP_VALID_BLOCK:
      {
        /* Generate valid stored block with fuzz data as payload */
        if (fuzz_size < 2)
          break;

        /* Use first two bytes of fuzz data to determine block length */
        uint16_t len = (uint16_t)(fuzz_data[0] | (fuzz_data[1] << 8));
        size_t available_data = fuzz_size - 2;

        /* Limit length to available data */
        if (len > available_data)
          len = (uint16_t)available_data;

        /* Build valid header */
        make_valid_stored_block (len, header);

        /* Construct input: header + data */
        input_size = 4 + len;
        input_buf = Arena_alloc (arena, input_size, __FILE__, __LINE__);
        memcpy (input_buf, header, 4);
        if (len > 0)
          memcpy (input_buf + 4, fuzz_data + 2, len);

        SocketDeflate_BitReader_init (reader, input_buf, input_size);
        result = SocketDeflate_decode_stored_block (reader, output,
                                                    MAX_OUTPUT_SIZE, &written);
        /* Should succeed for valid blocks */
        (void)(result == DEFLATE_OK);
      }
      break;

    case OP_INVALID_NLEN:
      {
        /* Generate block with intentionally wrong NLEN */
        if (fuzz_size < 4)
          break;

        /* Use fuzz data directly as header (likely invalid NLEN) */
        input_size = fuzz_size;
        SocketDeflate_BitReader_init (reader, fuzz_data, input_size);
        result = SocketDeflate_decode_stored_block (reader, output,
                                                    MAX_OUTPUT_SIZE, &written);
        /* Should fail with DEFLATE_ERROR if NLEN invalid */
        (void)(result == DEFLATE_ERROR);
      }
      break;

    case OP_TRUNCATED_HEADER:
      {
        /* Test with truncated header (0-3 bytes) */
        size_t truncate_at = fuzz_size % 4;
        if (truncate_at == 0 && fuzz_size > 0)
          truncate_at = 1; /* At least 1 byte */

        if (truncate_at > fuzz_size)
          truncate_at = fuzz_size;

        SocketDeflate_BitReader_init (reader, fuzz_data, truncate_at);
        result = SocketDeflate_decode_stored_block (reader, output,
                                                    MAX_OUTPUT_SIZE, &written);
        /* Should fail with DEFLATE_INCOMPLETE */
        (void)(result == DEFLATE_INCOMPLETE);
      }
      break;

    case OP_TRUNCATED_DATA:
      {
        /* Generate valid header but truncate during data */
        if (fuzz_size < 3)
          break;

        /* Use moderate length to ensure truncation */
        uint16_t len = 100 + (fuzz_data[0] % 1000);
        make_valid_stored_block (len, header);

        /* Only provide header + partial data */
        size_t partial_data = fuzz_size - 1;
        if (partial_data > (size_t)(len - 1))
          partial_data = len - 1;

        input_size = 4 + partial_data;
        input_buf = Arena_alloc (arena, input_size, __FILE__, __LINE__);
        memcpy (input_buf, header, 4);
        if (partial_data > 0)
          memcpy (input_buf + 4, fuzz_data + 1, partial_data);

        SocketDeflate_BitReader_init (reader, input_buf, input_size);
        result = SocketDeflate_decode_stored_block (reader, output,
                                                    MAX_OUTPUT_SIZE, &written);
        /* Should fail with DEFLATE_INCOMPLETE */
        (void)(result == DEFLATE_INCOMPLETE);
      }
      break;

    case OP_RANDOM_BYTES:
      {
        /* Use raw fuzz data directly as stored block input */
        SocketDeflate_BitReader_init (reader, fuzz_data, fuzz_size);
        result = SocketDeflate_decode_stored_block (reader, output,
                                                    MAX_OUTPUT_SIZE, &written);
        /* May succeed or fail depending on data */
        (void)result;
      }
      break;

    case OP_ALIGNMENT_TEST:
      {
        /* Test alignment by consuming some bits first */
        if (fuzz_size < 5)
          break;

        /* First byte determines how many bits to consume (1-7) */
        unsigned int bits_to_consume = (fuzz_data[0] % 7) + 1;

        /* Build valid stored block from remaining data */
        uint16_t len = (uint16_t)(fuzz_data[1] | (fuzz_data[2] << 8));
        size_t available_data = fuzz_size - 3;
        if (len > available_data)
          len = (uint16_t)available_data;

        make_valid_stored_block (len, header);

        /* Input: padding byte + header + data */
        input_size = 1 + 4 + len;
        input_buf = Arena_alloc (arena, input_size, __FILE__, __LINE__);
        input_buf[0] = fuzz_data[0]; /* Padding byte */
        memcpy (input_buf + 1, header, 4);
        if (len > 0)
          memcpy (input_buf + 5, fuzz_data + 3, len);

        SocketDeflate_BitReader_init (reader, input_buf, input_size);

        /* Consume some bits to misalign */
        uint32_t dummy;
        SocketDeflate_BitReader_read (reader, bits_to_consume, &dummy);

        /* Now decode stored block (should align first) */
        result = SocketDeflate_decode_stored_block (reader, output,
                                                    MAX_OUTPUT_SIZE, &written);
        (void)result;
      }
      break;
    }

  Arena_dispose (&arena);

  return 0;
}
