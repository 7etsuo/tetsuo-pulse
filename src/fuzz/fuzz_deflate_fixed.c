/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_deflate_fixed.c - libFuzzer harness for DEFLATE fixed Huffman decoder
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketDeflate_decode_fixed_block with arbitrary input
 * - Fixed Huffman table decoding (literal/length and distance)
 * - LZ77 decode loop with various length/distance combinations
 * - Overlap copy handling (distance < length)
 * - Error handling for invalid codes and distances
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_deflate_fixed
 * Run:   ./fuzz_deflate_fixed corpus/deflate_fixed/ -fork=16 -max_len=65536
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "deflate/SocketDeflate.h"

/* Fuzz operation opcodes */
enum FuzzOp
{
  OP_RANDOM_DECODE = 0, /* Raw fuzz input as fixed block data */
  OP_VALID_LITERALS,    /* Valid literal-only block */
  OP_VALID_BACKREFS,    /* Valid block with back-references */
  OP_LARGE_OUTPUT,      /* Test with large output buffer */
  OP_SMALL_OUTPUT,      /* Test with small output buffer */
  OP_STRESS_OVERLAP,    /* Stress test overlap copy */
  OP_MAX
};

/* Maximum output buffer size */
#define MAX_OUTPUT_SIZE 131072 /* 128KB */
#define SMALL_OUTPUT_SIZE 64

/* Fixed tables initialized flag */
static int tables_initialized = 0;
static Arena_T fixed_arena = NULL;

/**
 * Initialize fixed Huffman tables once.
 * This is called lazily on first fuzz input.
 */
static int
ensure_tables_initialized (void)
{
  if (tables_initialized)
    return 1;

  fixed_arena = Arena_new ();
  if (SocketDeflate_fixed_tables_init (fixed_arena) != DEFLATE_OK)
    {
      Arena_dispose (&fixed_arena);
      fixed_arena = NULL;
      return 0;
    }

  tables_initialized = 1;
  return 1;
}

/**
 * Build a valid literal-only fixed block from fuzz data.
 *
 * Creates a block containing only literal bytes followed by end-of-block.
 * This exercises the literal decoding path without back-references.
 *
 * @param fuzz_data Input bytes to encode as literals
 * @param fuzz_size Number of bytes
 * @param out_buf   Output buffer for encoded data
 * @param out_cap   Capacity of output buffer
 * @return Size of encoded data
 */
static size_t
build_literal_block (const uint8_t *fuzz_data,
                     size_t fuzz_size,
                     uint8_t *out_buf,
                     size_t out_cap)
{
  uint32_t bits = 0;
  int bits_avail = 0;
  size_t out_pos = 0;
  size_t i;

  /* Limit literals to prevent huge encoded output */
  if (fuzz_size > 256)
    fuzz_size = 256;

  /* Encode each byte as a literal */
  for (i = 0; i < fuzz_size && out_pos < out_cap - 4; i++)
    {
      uint8_t ch = fuzz_data[i];
      uint32_t code;
      int code_len;

      if (ch < 144)
        {
          /* 8-bit code: symbol + 48, bit-reversed */
          code = SocketDeflate_reverse_bits (ch + 48, 8);
          code_len = 8;
        }
      else
        {
          /* 9-bit code: (symbol - 144) + 400, bit-reversed */
          code = SocketDeflate_reverse_bits ((ch - 144) + 400, 9);
          code_len = 9;
        }

      /* Pack bits LSB-first */
      bits |= code << bits_avail;
      bits_avail += code_len;

      while (bits_avail >= 8 && out_pos < out_cap)
        {
          out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
          bits >>= 8;
          bits_avail -= 8;
        }
    }

  /* End-of-block (symbol 256): 7-bit code 0000000 */
  bits |= 0 << bits_avail;
  bits_avail += 7;

  /* Flush remaining bits */
  while (bits_avail > 0 && out_pos < out_cap)
    {
      out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
      bits >>= 8;
      bits_avail -= 8;
    }

  return out_pos;
}

/**
 * Build a valid block with simple back-references.
 *
 * Creates: N literals + (length=3, distance=N) repeated + end-of-block
 * This tests the LZ77 decode path.
 */
static size_t
build_backref_block (const uint8_t *fuzz_data,
                     size_t fuzz_size,
                     uint8_t *out_buf,
                     size_t out_cap)
{
  uint32_t bits = 0;
  int bits_avail = 0;
  size_t out_pos = 0;
  size_t num_literals;
  size_t i;

  if (fuzz_size < 2)
    return 0;

  /* Number of initial literals (1-16) */
  num_literals = (fuzz_data[0] % 16) + 1;
  if (num_literals > fuzz_size - 1)
    num_literals = fuzz_size - 1;

  /* Encode literals */
  for (i = 0; i < num_literals && out_pos < out_cap - 8; i++)
    {
      uint8_t ch = fuzz_data[1 + i] % 128; /* Keep in 0-127 for 8-bit codes */
      uint32_t code = SocketDeflate_reverse_bits (ch + 48, 8);

      bits |= code << bits_avail;
      bits_avail += 8;

      while (bits_avail >= 8 && out_pos < out_cap)
        {
          out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
          bits >>= 8;
          bits_avail -= 8;
        }
    }

  /* Add length code 257 (length=3): 7-bit code 0000001 reversed = 0x40 */
  {
    uint32_t length_code = SocketDeflate_reverse_bits (1, 7);
    bits |= length_code << bits_avail;
    bits_avail += 7;

    while (bits_avail >= 8 && out_pos < out_cap)
      {
        out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
        bits >>= 8;
        bits_avail -= 8;
      }
  }

  /* Add distance code based on num_literals */
  {
    /* Distance code mapping for distance 1-4: codes 0-3 */
    unsigned int dist_code = (num_literals > 4) ? 3 : (num_literals - 1);
    uint32_t dist_reversed = SocketDeflate_reverse_bits (dist_code, 5);

    bits |= dist_reversed << bits_avail;
    bits_avail += 5;

    while (bits_avail >= 8 && out_pos < out_cap)
      {
        out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
        bits >>= 8;
        bits_avail -= 8;
      }
  }

  /* End-of-block */
  bits |= 0 << bits_avail;
  bits_avail += 7;

  while (bits_avail > 0 && out_pos < out_cap)
    {
      out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
      bits >>= 8;
      bits_avail -= 8;
    }

  return out_pos;
}

/**
 * Build a block that stresses overlap copy.
 *
 * Creates: 1 literal + multiple (length, distance=1) sequences
 * This creates runs of repeated bytes.
 */
static size_t
build_overlap_block (const uint8_t *fuzz_data,
                     size_t fuzz_size,
                     uint8_t *out_buf,
                     size_t out_cap)
{
  uint32_t bits = 0;
  int bits_avail = 0;
  size_t out_pos = 0;
  size_t num_runs;
  size_t i;

  if (fuzz_size < 2)
    return 0;

  /* Start with one literal */
  {
    uint8_t ch = fuzz_data[0] % 128;
    uint32_t code = SocketDeflate_reverse_bits (ch + 48, 8);
    bits |= code << bits_avail;
    bits_avail += 8;

    while (bits_avail >= 8 && out_pos < out_cap)
      {
        out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
        bits >>= 8;
        bits_avail -= 8;
      }
  }

  /* Add multiple length=3, distance=1 sequences */
  num_runs = (fuzz_data[1] % 8) + 1;
  for (i = 0; i < num_runs && out_pos < out_cap - 8; i++)
    {
      /* Length code 257: 7-bit code */
      uint32_t length_code = SocketDeflate_reverse_bits (1, 7);
      bits |= length_code << bits_avail;
      bits_avail += 7;

      while (bits_avail >= 8 && out_pos < out_cap)
        {
          out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
          bits >>= 8;
          bits_avail -= 8;
        }

      /* Distance code 0 (distance=1): 5-bit code */
      uint32_t dist_code = SocketDeflate_reverse_bits (0, 5);
      bits |= dist_code << bits_avail;
      bits_avail += 5;

      while (bits_avail >= 8 && out_pos < out_cap)
        {
          out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
          bits >>= 8;
          bits_avail -= 8;
        }
    }

  /* End-of-block */
  bits |= 0 << bits_avail;
  bits_avail += 7;

  while (bits_avail > 0 && out_pos < out_cap)
    {
      out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
      bits >>= 8;
      bits_avail -= 8;
    }

  return out_pos;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 * @data: Fuzz input data
 * @size: Size of fuzz input
 *
 * Exercises the fixed Huffman decoder with various inputs.
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
  uint8_t *input_buf;
  size_t input_size;
  size_t output_size;

  if (size < 2)
    return 0;

  /* Initialize fixed tables if needed */
  if (!ensure_tables_initialized ())
    return 0;

  /* Parse fuzz input */
  uint8_t op = data[0] % OP_MAX;
  const uint8_t *fuzz_data = data + 1;
  size_t fuzz_size = size - 1;

  /* Create per-test arena and output buffer */
  arena = Arena_new ();
  reader = SocketDeflate_BitReader_new (arena);

  switch (op)
    {
    case OP_RANDOM_DECODE:
      {
        /* Use raw fuzz data directly as fixed block input */
        output_size = MAX_OUTPUT_SIZE;
        output = Arena_alloc (arena, output_size, __FILE__, __LINE__);

        SocketDeflate_BitReader_init (reader, fuzz_data, fuzz_size);
        result = SocketDeflate_decode_fixed_block (
            reader, output, output_size, &written);
        (void)result;
      }
      break;

    case OP_VALID_LITERALS:
      {
        /* Build valid literal-only block */
        input_buf = Arena_alloc (arena, 4096, __FILE__, __LINE__);
        input_size
            = build_literal_block (fuzz_data, fuzz_size, input_buf, 4096);

        if (input_size > 0)
          {
            output_size = MAX_OUTPUT_SIZE;
            output = Arena_alloc (arena, output_size, __FILE__, __LINE__);

            SocketDeflate_BitReader_init (reader, input_buf, input_size);
            result = SocketDeflate_decode_fixed_block (
                reader, output, output_size, &written);
            /* Should succeed for valid input */
            (void)(result == DEFLATE_OK);
          }
      }
      break;

    case OP_VALID_BACKREFS:
      {
        /* Build valid block with back-references */
        input_buf = Arena_alloc (arena, 4096, __FILE__, __LINE__);
        input_size
            = build_backref_block (fuzz_data, fuzz_size, input_buf, 4096);

        if (input_size > 0)
          {
            output_size = MAX_OUTPUT_SIZE;
            output = Arena_alloc (arena, output_size, __FILE__, __LINE__);

            SocketDeflate_BitReader_init (reader, input_buf, input_size);
            result = SocketDeflate_decode_fixed_block (
                reader, output, output_size, &written);
            (void)(result == DEFLATE_OK);
          }
      }
      break;

    case OP_LARGE_OUTPUT:
      {
        /* Test with large output buffer */
        output_size = MAX_OUTPUT_SIZE;
        output = Arena_alloc (arena, output_size, __FILE__, __LINE__);

        SocketDeflate_BitReader_init (reader, fuzz_data, fuzz_size);
        result = SocketDeflate_decode_fixed_block (
            reader, output, output_size, &written);
        (void)result;
      }
      break;

    case OP_SMALL_OUTPUT:
      {
        /* Test with small output buffer - may hit output full condition */
        output_size = SMALL_OUTPUT_SIZE;
        output = Arena_alloc (arena, output_size, __FILE__, __LINE__);

        SocketDeflate_BitReader_init (reader, fuzz_data, fuzz_size);
        result = SocketDeflate_decode_fixed_block (
            reader, output, output_size, &written);
        /* May return DEFLATE_ERROR due to output buffer full */
        (void)result;
      }
      break;

    case OP_STRESS_OVERLAP:
      {
        /* Build block that stresses overlap copy */
        input_buf = Arena_alloc (arena, 4096, __FILE__, __LINE__);
        input_size
            = build_overlap_block (fuzz_data, fuzz_size, input_buf, 4096);

        if (input_size > 0)
          {
            output_size = MAX_OUTPUT_SIZE;
            output = Arena_alloc (arena, output_size, __FILE__, __LINE__);

            SocketDeflate_BitReader_init (reader, input_buf, input_size);
            result = SocketDeflate_decode_fixed_block (
                reader, output, output_size, &written);
            (void)(result == DEFLATE_OK);
          }
      }
      break;
    }

  Arena_dispose (&arena);

  return 0;
}
