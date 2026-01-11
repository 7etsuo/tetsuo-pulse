/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_deflate_huffman.c - libFuzzer harness for DEFLATE Huffman decoder
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketDeflate_HuffmanTable_build with arbitrary code lengths
 * - SocketDeflate_HuffmanTable_decode with random bit streams
 * - Tree validation (over-subscribed, incomplete)
 * - Fixed table initialization and decoding
 * - Edge cases: empty alphabets, max size, invalid codes
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_deflate_huffman
 * Run:   ./fuzz_deflate_huffman corpus/deflate_huffman/ -fork=16 -max_len=512
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "deflate/SocketDeflate.h"

/* Fuzz operation opcodes */
enum FuzzOp
{
  OP_BUILD_DECODE = 0,     /* Build table from lengths, decode symbols */
  OP_FIXED_LITLEN_DECODE,  /* Decode with fixed litlen table */
  OP_FIXED_DIST_DECODE,    /* Decode with fixed dist table */
  OP_BUILD_INVALID,        /* Try to build invalid trees */
  OP_DECODE_SEQUENCE,      /* Build and decode multiple symbols */
  OP_RESET_REBUILD,        /* Reset and rebuild table */
  OP_MAX
};

/* Maximum alphabet sizes */
#define MAX_LITLEN_SYMBOLS DEFLATE_LITLEN_CODES
#define MAX_DIST_SYMBOLS DEFLATE_DIST_CODES
#define MAX_DECODE_OPS 64

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 * @data: Fuzz input data
 * @size: Size of fuzz input
 *
 * Exercises the Huffman decoder with fuzz-generated code lengths and bit data.
 * The first few bytes control operations, the rest is input data.
 *
 * Returns: 0 (required by libFuzzer)
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena;
  SocketDeflate_HuffmanTable_T table;
  SocketDeflate_BitReader_T reader;
  SocketDeflate_Result result;
  uint16_t symbol;
  uint8_t lengths[MAX_LITLEN_SYMBOLS];
  unsigned int i;

  if (size < 3)
    return 0;

  /* Parse fuzz input:
   * byte[0]: operation code
   * byte[1]: alphabet size (mod MAX_LITLEN_SYMBOLS + 1)
   * byte[2..]: code lengths and decode data
   */
  uint8_t op = data[0] % OP_MAX;
  unsigned int alpha_size = (data[1] % MAX_LITLEN_SYMBOLS) + 1;
  const uint8_t *lengths_data = data + 2;
  size_t lengths_size = size - 2;

  /* Create arena and structures */
  arena = Arena_new ();
  table = SocketDeflate_HuffmanTable_new (arena);
  reader = SocketDeflate_BitReader_new (arena);

  switch (op)
    {
    case OP_BUILD_DECODE:
      {
        /* Use fuzz data as code lengths (mod 16 to keep valid range) */
        unsigned int len_count
            = (lengths_size < alpha_size) ? lengths_size : alpha_size;
        memset (lengths, 0, sizeof (lengths));

        for (i = 0; i < len_count; i++)
          lengths[i] = lengths_data[i] % 16;

        /* Try to build table (may fail for invalid trees) */
        result = SocketDeflate_HuffmanTable_build (table, lengths, alpha_size,
                                                   DEFLATE_MAX_BITS);

        if (result == DEFLATE_OK && lengths_size > len_count)
          {
            /* Decode symbols from remaining data */
            const uint8_t *decode_data = lengths_data + len_count;
            size_t decode_size = lengths_size - len_count;

            if (decode_size > 0)
              {
                SocketDeflate_BitReader_init (reader, decode_data, decode_size);

                /* Try to decode symbols until we run out of data */
                for (i = 0; i < MAX_DECODE_OPS; i++)
                  {
                    result = SocketDeflate_HuffmanTable_decode (table, reader,
                                                                &symbol);
                    if (result != DEFLATE_OK)
                      break;
                  }
              }
          }
      }
      break;

    case OP_FIXED_LITLEN_DECODE:
      {
        /* Initialize fixed tables and decode */
        result = SocketDeflate_fixed_tables_init (arena);
        if (result == DEFLATE_OK)
          {
            SocketDeflate_HuffmanTable_T litlen
                = SocketDeflate_get_fixed_litlen_table ();

            if (litlen != NULL && lengths_size > 0)
              {
                SocketDeflate_BitReader_init (reader, lengths_data,
                                              lengths_size);

                for (i = 0; i < MAX_DECODE_OPS; i++)
                  {
                    result = SocketDeflate_HuffmanTable_decode (litlen, reader,
                                                                &symbol);
                    if (result != DEFLATE_OK)
                      break;
                  }
              }
          }
      }
      break;

    case OP_FIXED_DIST_DECODE:
      {
        /* Initialize fixed tables and decode distances */
        result = SocketDeflate_fixed_tables_init (arena);
        if (result == DEFLATE_OK)
          {
            SocketDeflate_HuffmanTable_T dist
                = SocketDeflate_get_fixed_dist_table ();

            if (dist != NULL && lengths_size > 0)
              {
                SocketDeflate_BitReader_init (reader, lengths_data,
                                              lengths_size);

                for (i = 0; i < MAX_DECODE_OPS; i++)
                  {
                    result = SocketDeflate_HuffmanTable_decode (dist, reader,
                                                                &symbol);
                    if (result != DEFLATE_OK)
                      break;
                  }
              }
          }
      }
      break;

    case OP_BUILD_INVALID:
      {
        /* Try various invalid tree configurations */
        memset (lengths, 0, sizeof (lengths));

        /* Test 1: Over-subscribed (all 1-bit codes) */
        if (alpha_size >= 3)
          {
            lengths[0] = 1;
            lengths[1] = 1;
            lengths[2] = 1;
            result = SocketDeflate_HuffmanTable_build (table, lengths, 3,
                                                       DEFLATE_MAX_BITS);
            (void)(result == DEFLATE_ERROR_HUFFMAN_TREE);
          }

        /* Reset for next test */
        SocketDeflate_HuffmanTable_reset (table);
        memset (lengths, 0, sizeof (lengths));

        /* Test 2: Code length > 15 */
        if (alpha_size >= 1)
          {
            lengths[0] = 16 + (data[2] % 240); /* 16-255 */
            result = SocketDeflate_HuffmanTable_build (table, lengths, 1,
                                                       DEFLATE_MAX_BITS);
            /* May or may not fail depending on validation */
          }

        /* Reset for next test */
        SocketDeflate_HuffmanTable_reset (table);
        memset (lengths, 0, sizeof (lengths));

        /* Test 3: Under-subscribed (incomplete tree) */
        if (alpha_size >= 2)
          {
            lengths[0] = 3;
            lengths[1] = 3;
            result = SocketDeflate_HuffmanTable_build (table, lengths, 2,
                                                       DEFLATE_MAX_BITS);
            (void)(result == DEFLATE_ERROR_HUFFMAN_TREE);
          }
      }
      break;

    case OP_DECODE_SEQUENCE:
      {
        /* Build a valid small tree and decode a sequence */
        memset (lengths, 0, sizeof (lengths));

        /* Create valid tree: 2 symbols at 1 bit each */
        lengths[0] = 1;
        lengths[1] = 1;

        result = SocketDeflate_HuffmanTable_build (table, lengths, 2,
                                                   DEFLATE_MAX_BITS);
        if (result == DEFLATE_OK && lengths_size > 0)
          {
            SocketDeflate_BitReader_init (reader, lengths_data, lengths_size);

            /* Decode as many symbols as possible */
            for (i = 0; i < lengths_size * 8; i++)
              {
                result = SocketDeflate_HuffmanTable_decode (table, reader,
                                                            &symbol);
                if (result != DEFLATE_OK)
                  break;
              }
          }
      }
      break;

    case OP_RESET_REBUILD:
      {
        /* Build, reset, rebuild with different lengths */
        memset (lengths, 0, sizeof (lengths));

        /* First build */
        for (i = 0; i < alpha_size && i < lengths_size; i++)
          lengths[i] = lengths_data[i] % 16;

        result = SocketDeflate_HuffmanTable_build (table, lengths, alpha_size,
                                                   DEFLATE_MAX_BITS);

        /* Reset */
        SocketDeflate_HuffmanTable_reset (table);

        /* Rebuild with modified lengths */
        for (i = 0; i < alpha_size && i < lengths_size; i++)
          lengths[i] = (lengths_data[i] + 1) % 16;

        result = SocketDeflate_HuffmanTable_build (table, lengths, alpha_size,
                                                   DEFLATE_MAX_BITS);

        /* Try decoding if build succeeded */
        if (result == DEFLATE_OK && lengths_size > alpha_size)
          {
            const uint8_t *decode_data = lengths_data + alpha_size;
            size_t decode_size = lengths_size - alpha_size;

            SocketDeflate_BitReader_init (reader, decode_data, decode_size);

            for (i = 0; i < MAX_DECODE_OPS; i++)
              {
                result = SocketDeflate_HuffmanTable_decode (table, reader,
                                                            &symbol);
                if (result != DEFLATE_OK)
                  break;
              }
          }
      }
      break;
    }

  Arena_dispose (&arena);

  return 0;
}
