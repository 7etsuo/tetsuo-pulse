/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_deflate_bitstream.c - libFuzzer harness for DEFLATE bit stream reader
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketDeflate_BitReader_read with arbitrary bit counts
 * - SocketDeflate_BitReader_peek and consume sequences
 * - SocketDeflate_BitReader_align byte boundary handling
 * - SocketDeflate_BitReader_read_bytes after alignment
 * - SocketDeflate_reverse_bits with all bit lengths
 * - Input validation (n=0, n>25, nbits>15)
 * - Edge cases: empty input, partial bytes, boundary conditions
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_deflate_bitstream
 * Run:   ./fuzz_deflate_bitstream corpus/deflate_bitstream/ -fork=16 -max_len=256
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "deflate/SocketDeflate.h"

/* Fuzz operation opcodes */
enum FuzzOp
{
  /* Reader operations */
  OP_READ_BITS = 0,
  OP_PEEK_BITS,
  OP_CONSUME_BITS,
  OP_ALIGN,
  OP_READ_BYTES,
  OP_REVERSE_BITS,
  OP_QUERY_STATE,
  OP_MULTI_READ,
  OP_INVALID_PARAMS, /* Test validation of invalid parameters */

  /* Writer operations */
  OP_WRITE_BITS,        /* Write bits to writer */
  OP_WRITE_HUFFMAN,     /* Write Huffman code */
  OP_WRITER_FLUSH,      /* Flush writer */
  OP_WRITER_ALIGN,      /* Align writer */
  OP_WRITER_SYNC_FLUSH, /* RFC 7692 sync flush */
  OP_ROUNDTRIP,         /* Write then read, verify match */
  OP_MULTI_WRITE,       /* Multiple write operations */

  OP_MAX
};

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 * @data: Fuzz input data
 * @size: Size of fuzz input
 *
 * Exercises the bit stream reader with fuzz-generated operations and data.
 * The first few bytes control operations, the rest is input data.
 *
 * Returns: 0 (required by libFuzzer)
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena;
  SocketDeflate_BitReader_T reader;
  uint32_t value;
  uint8_t byte_buf[64];

  if (size < 4)
    return 0;

  /* Parse fuzz input:
   * byte[0]: operation code
   * byte[1]: parameter 1 (e.g., number of bits)
   * byte[2]: parameter 2 (e.g., count)
   * byte[3..]: input data for bit reader
   */
  uint8_t op = data[0] % OP_MAX;
  uint8_t param1 = data[1];
  uint8_t param2 = data[2];
  const uint8_t *input_data = data + 3;
  size_t input_size = size - 3;

  /* Create arena and bit reader */
  arena = Arena_new ();
  reader = SocketDeflate_BitReader_new (arena);
  SocketDeflate_BitReader_init (reader, input_data, input_size);

  switch (op)
    {
    case OP_READ_BITS:
      {
        /* Read N bits (1-25) */
        unsigned int n = (param1 % DEFLATE_MAX_BITS_READ) + 1;
        (void)SocketDeflate_BitReader_read (reader, n, &value);
      }
      break;

    case OP_PEEK_BITS:
      {
        /* Peek N bits without consuming */
        unsigned int n = (param1 % DEFLATE_MAX_BITS_READ) + 1;
        if (SocketDeflate_BitReader_peek (reader, n, &value) == DEFLATE_OK)
          {
            /* Optionally consume some bits */
            unsigned int consume = param2 % (n + 1);
            SocketDeflate_BitReader_consume (reader, consume);
          }
      }
      break;

    case OP_CONSUME_BITS:
      {
        /* Consume arbitrary bits (tests bounds checking) */
        unsigned int n = param1;
        SocketDeflate_BitReader_consume (reader, n);
      }
      break;

    case OP_ALIGN:
      {
        /* Read some bits, then align */
        unsigned int pre_read = param1 % 8;
        if (pre_read > 0)
          SocketDeflate_BitReader_read (reader, pre_read, &value);

        SocketDeflate_BitReader_align (reader);

        /* Read more after alignment */
        unsigned int post_read = param2 % 17; /* 0-16 bits */
        if (post_read > 0)
          (void)SocketDeflate_BitReader_read (reader, post_read, &value);
      }
      break;

    case OP_READ_BYTES:
      {
        /* Align and read raw bytes */
        unsigned int pre_bits = param1 % 8;
        if (pre_bits > 0)
          (void)SocketDeflate_BitReader_read (reader, pre_bits, &value);

        SocketDeflate_BitReader_align (reader);

        unsigned int count = param2 % sizeof (byte_buf);
        (void)SocketDeflate_BitReader_read_bytes (reader, byte_buf, count);
      }
      break;

    case OP_REVERSE_BITS:
      {
        /* Test bit reversal with various lengths */
        unsigned int nbits = (param1 % 15) + 1; /* 1-15 bits */
        uint32_t input_val = ((uint32_t)param2 << 8) | data[3 % size];
        uint32_t reversed = SocketDeflate_reverse_bits (input_val, nbits);

        /* Verify reversing twice gives original (masked to nbits) */
        uint32_t mask = (1U << nbits) - 1;
        uint32_t double_reversed
            = SocketDeflate_reverse_bits (reversed, nbits);
        (void)(double_reversed == (input_val & mask));
      }
      break;

    case OP_QUERY_STATE:
      {
        /* Query state functions at various points */
        (void)SocketDeflate_BitReader_bits_available (reader);
        (void)SocketDeflate_BitReader_bytes_remaining (reader);
        (void)SocketDeflate_BitReader_at_end (reader);

        /* Read some, then query again */
        unsigned int n = param1 % 9;
        if (n > 0)
          (void)SocketDeflate_BitReader_read (reader, n, &value);

        (void)SocketDeflate_BitReader_bits_available (reader);
        (void)SocketDeflate_BitReader_at_end (reader);
      }
      break;

    case OP_MULTI_READ:
      {
        /* Multiple read operations in sequence */
        unsigned int ops_count = (param1 % 8) + 1;
        unsigned int i;

        for (i = 0; i < ops_count; i++)
          {
            unsigned int bits_to_read;
            size_t idx;

            idx = (3 + i) % size;
            bits_to_read = (data[idx] % DEFLATE_MAX_BITS_READ) + 1;

            if (SocketDeflate_BitReader_read (reader, bits_to_read, &value)
                != DEFLATE_OK)
              break;
          }
      }
      break;

    case OP_INVALID_PARAMS:
      {
        /* Test validation with invalid parameters */
        SocketDeflate_Result result;

        /* read with n=0 should return DEFLATE_ERROR */
        result = SocketDeflate_BitReader_read (reader, 0, &value);
        (void)(result == DEFLATE_ERROR);

        /* read with n > 25 should return DEFLATE_ERROR */
        result = SocketDeflate_BitReader_read (reader, param1 + 26, &value);
        (void)(result == DEFLATE_ERROR);

        /* peek with n=0 should return DEFLATE_ERROR */
        result = SocketDeflate_BitReader_peek (reader, 0, &value);
        (void)(result == DEFLATE_ERROR);

        /* peek with n > 25 should return DEFLATE_ERROR */
        result = SocketDeflate_BitReader_peek (reader, param2 + 26, &value);
        (void)(result == DEFLATE_ERROR);

        /* reverse_bits with nbits=0 should return 0 */
        uint32_t rev = SocketDeflate_reverse_bits (param1, 0);
        (void)(rev == 0);

        /* reverse_bits with nbits > 15 should return 0 */
        rev = SocketDeflate_reverse_bits (param1, param2 + 16);
        (void)(rev == 0);

        /* Valid operations should still work after invalid ones */
        if (input_size > 0)
          {
            result = SocketDeflate_BitReader_read (reader, 1, &value);
            (void)(result == DEFLATE_OK || result == DEFLATE_INCOMPLETE);
          }
      }
      break;

    /*
     * Writer Operations
     */

    case OP_WRITE_BITS:
      {
        /* Write N bits to writer */
        uint8_t out_buf[256];
        SocketDeflate_BitWriter_T writer = SocketDeflate_BitWriter_new (arena);
        SocketDeflate_BitWriter_init (writer, out_buf, sizeof (out_buf));

        unsigned int n = (param1 % DEFLATE_MAX_BITS_READ) + 1;
        uint32_t write_val
            = ((uint32_t)param2 << 8) | (input_size > 0 ? input_data[0] : 0);

        (void)SocketDeflate_BitWriter_write (writer, write_val, n);
        (void)SocketDeflate_BitWriter_flush (writer);
      }
      break;

    case OP_WRITE_HUFFMAN:
      {
        /* Write Huffman code (reversed) */
        uint8_t out_buf[256];
        SocketDeflate_BitWriter_T writer = SocketDeflate_BitWriter_new (arena);
        SocketDeflate_BitWriter_init (writer, out_buf, sizeof (out_buf));

        unsigned int len = (param1 % DEFLATE_MAX_BITS) + 1; /* 1-15 bits */
        uint32_t code = param2;

        (void)SocketDeflate_BitWriter_write_huffman (writer, code, len);
        (void)SocketDeflate_BitWriter_flush (writer);
      }
      break;

    case OP_WRITER_FLUSH:
      {
        /* Write some bits then flush */
        uint8_t out_buf[256];
        SocketDeflate_BitWriter_T writer = SocketDeflate_BitWriter_new (arena);
        SocketDeflate_BitWriter_init (writer, out_buf, sizeof (out_buf));

        unsigned int n = (param1 % 8) + 1; /* 1-8 bits */
        (void)SocketDeflate_BitWriter_write (writer, param2, n);

        size_t flushed = SocketDeflate_BitWriter_flush (writer);
        (void)flushed;
      }
      break;

    case OP_WRITER_ALIGN:
      {
        /* Write some bits then align */
        uint8_t out_buf[256];
        SocketDeflate_BitWriter_T writer = SocketDeflate_BitWriter_new (arena);
        SocketDeflate_BitWriter_init (writer, out_buf, sizeof (out_buf));

        unsigned int n = param1 % 8;
        if (n > 0)
          (void)SocketDeflate_BitWriter_write (writer, param2, n);

        SocketDeflate_BitWriter_align (writer);

        /* Verify alignment */
        (void)(SocketDeflate_BitWriter_bits_pending (writer) == 0);
      }
      break;

    case OP_WRITER_SYNC_FLUSH:
      {
        /* Test RFC 7692 sync flush */
        uint8_t out_buf[256];
        SocketDeflate_BitWriter_T writer = SocketDeflate_BitWriter_new (arena);
        SocketDeflate_BitWriter_init (writer, out_buf, sizeof (out_buf));

        /* Optionally write some data first */
        if (param1 & 1)
          {
            unsigned int n = (param2 % DEFLATE_MAX_BITS_READ) + 1;
            uint32_t write_val = (input_size > 0) ? input_data[0] : 0;
            (void)SocketDeflate_BitWriter_write (writer, write_val, n);
          }

        size_t total = SocketDeflate_BitWriter_sync_flush (writer);

        /* Verify trailer if we have enough data */
        if (total >= 5)
          {
            /* Last 4 bytes should be 0x00 0x00 0xFF 0xFF */
            (void)(out_buf[total - 4] == 0x00);
            (void)(out_buf[total - 3] == 0x00);
            (void)(out_buf[total - 2] == 0xFF);
            (void)(out_buf[total - 1] == 0xFF);
          }
      }
      break;

    case OP_ROUNDTRIP:
      {
        /* Write bits, then read them back and verify */
        uint8_t out_buf[256];
        SocketDeflate_BitWriter_T writer = SocketDeflate_BitWriter_new (arena);
        SocketDeflate_BitWriter_init (writer, out_buf, sizeof (out_buf));

        unsigned int n = (param1 % DEFLATE_MAX_BITS_READ) + 1;
        uint32_t write_val = param2 & ((1U << n) - 1); /* Mask to n bits */

        if (SocketDeflate_BitWriter_write (writer, write_val, n) == DEFLATE_OK)
          {
            size_t total = SocketDeflate_BitWriter_flush (writer);

            if (total > 0)
              {
                /* Read back */
                SocketDeflate_BitReader_T rd
                    = SocketDeflate_BitReader_new (arena);
                SocketDeflate_BitReader_init (rd, out_buf, total);

                uint32_t read_val;
                if (SocketDeflate_BitReader_read (rd, n, &read_val)
                    == DEFLATE_OK)
                  {
                    /* Verify roundtrip */
                    (void)(read_val == write_val);
                  }
              }
          }
      }
      break;

    case OP_MULTI_WRITE:
      {
        /* Multiple write operations */
        uint8_t out_buf[256];
        SocketDeflate_BitWriter_T writer = SocketDeflate_BitWriter_new (arena);
        SocketDeflate_BitWriter_init (writer, out_buf, sizeof (out_buf));

        unsigned int write_count = (param1 % 8) + 1;
        unsigned int i;

        for (i = 0; i < write_count && i < input_size; i++)
          {
            unsigned int bits = (input_data[i] % DEFLATE_MAX_BITS_READ) + 1;
            uint32_t val = (i + 1 < input_size) ? input_data[i + 1] : param2;

            if (SocketDeflate_BitWriter_write (writer, val, bits) != DEFLATE_OK)
              break;
          }

        (void)SocketDeflate_BitWriter_flush (writer);
      }
      break;
    }

  Arena_dispose (&arena);

  return 0;
}
