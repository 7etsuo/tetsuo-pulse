/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_deflate_dynamic.c - libFuzzer harness for DEFLATE dynamic Huffman
 * decoder
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - SocketDeflate_decode_dynamic_block with arbitrary input
 * - Dynamic block header parsing (HLIT, HDIST, HCLEN)
 * - Code length alphabet decoding in permuted order
 * - Run-length codes (16, 17, 18) handling
 * - Building dynamic Huffman tables from code lengths
 * - LZ77 decode loop with dynamic tables
 * - Error handling for invalid codes and malformed tables
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_deflate_dynamic
 * Run:   ./fuzz_deflate_dynamic corpus/deflate_dynamic/ -fork=16 -max_len=65536
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
  OP_RANDOM_DECODE = 0,   /* Raw fuzz input as dynamic block data */
  OP_VALID_HEADER,        /* Valid header, fuzzed code lengths */
  OP_VALID_CODELEN_TABLE, /* Valid codelen table, fuzzed literal lengths */
  OP_STRESS_RUNLENGTH,    /* Heavy use of codes 16, 17, 18 */
  OP_LARGE_OUTPUT,        /* Test with large output buffer */
  OP_SMALL_OUTPUT,        /* Test with small output buffer */
  OP_MAX
};

/* Maximum output buffer size */
#define MAX_OUTPUT_SIZE 131072 /* 128KB */
#define SMALL_OUTPUT_SIZE 64

/**
 * Build a valid dynamic block header from fuzz data.
 *
 * Uses fuzz bytes to parameterize header values within valid ranges.
 *
 * @param fuzz_data Source of randomness
 * @param fuzz_size Size of fuzz data
 * @param out_buf   Output buffer for header bits
 * @param out_cap   Output buffer capacity
 * @return Size of encoded header
 */
static size_t
build_valid_header (const uint8_t *fuzz_data,
                    size_t fuzz_size,
                    uint8_t *out_buf,
                    size_t out_cap)
{
  uint32_t bits = 0;
  int bits_avail = 0;
  size_t out_pos = 0;

  if (fuzz_size < 3 || out_cap < 8)
    return 0;

  /* HLIT: 257-286 (use fuzz_data[0] % 30) */
  unsigned int hlit = 257 + (fuzz_data[0] % 30);
  bits |= (hlit - 257) << bits_avail;
  bits_avail += 5;

  /* HDIST: 1-32 (use fuzz_data[1] % 32) */
  unsigned int hdist = 1 + (fuzz_data[1] % 32);
  bits |= (hdist - 1) << bits_avail;
  bits_avail += 5;

  /* HCLEN: 4-19 (use fuzz_data[2] % 16) */
  unsigned int hclen = 4 + (fuzz_data[2] % 16);
  bits |= (hclen - 4) << bits_avail;
  bits_avail += 4;

  /* Flush header bits */
  while (bits_avail >= 8 && out_pos < out_cap)
    {
      out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
      bits >>= 8;
      bits_avail -= 8;
    }
  if (bits_avail > 0 && out_pos < out_cap)
    {
      out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
    }

  return out_pos;
}

/**
 * Build a valid code length Huffman table from fuzz data.
 *
 * Creates code length code lengths that form a valid Huffman tree.
 *
 * @param fuzz_data Source of randomness
 * @param fuzz_size Size of fuzz data
 * @param out_buf   Output buffer
 * @param out_cap   Output buffer capacity
 * @param hclen     Number of code length codes
 * @return Size of encoded data
 */
static size_t
build_valid_codelen_table (const uint8_t *fuzz_data,
                           size_t fuzz_size,
                           uint8_t *out_buf,
                           size_t out_cap,
                           unsigned int hclen)
{
  uint32_t bits = 0;
  int bits_avail = 0;
  size_t out_pos = 0;
  size_t fuzz_idx = 0;

  /* Code length order per RFC 1951 */
  static const unsigned int codelen_order[19]
      = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

  /* Build code lengths that form a valid tree */
  uint8_t codelen_lens[19] = { 0 };

  /* Ensure at least 2 symbols have non-zero lengths for a valid tree */
  /* Use fuzz data to select which symbols and what lengths */
  if (fuzz_size >= 4)
    {
      unsigned int sym1 = fuzz_data[fuzz_idx++] % 19;
      unsigned int sym2 = (fuzz_data[fuzz_idx++] % 18);
      if (sym2 >= sym1)
        sym2++; /* Ensure different symbols */
      unsigned int len1 = 1 + (fuzz_data[fuzz_idx++] % 7); /* 1-7 */
      unsigned int len2 = 1 + (fuzz_data[fuzz_idx++] % 7);

      /* For a valid tree with 2 symbols, they must have the same length
       * (complete binary tree with 2 leaves) */
      codelen_lens[sym1] = len1;
      codelen_lens[sym2] = len1; /* Same length */
    }
  else
    {
      /* Fallback: symbols 0 and 8 with length 1 */
      codelen_lens[0] = 1;
      codelen_lens[8] = 1;
    }

  /* Encode code lengths in permuted order */
  for (unsigned int i = 0; i < hclen && out_pos < out_cap; i++)
    {
      bits |= codelen_lens[codelen_order[i]] << bits_avail;
      bits_avail += 3;

      while (bits_avail >= 8 && out_pos < out_cap)
        {
          out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
          bits >>= 8;
          bits_avail -= 8;
        }
    }

  /* Flush remaining bits */
  if (bits_avail > 0 && out_pos < out_cap)
    {
      out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
    }

  return out_pos;
}

/**
 * Build a dynamic block that stresses run-length encoding.
 *
 * Creates blocks with heavy use of codes 16, 17, and 18.
 */
static size_t
build_runlength_stress_block (const uint8_t *fuzz_data,
                              size_t fuzz_size,
                              uint8_t *out_buf,
                              size_t out_cap)
{
  uint32_t bits = 0;
  int bits_avail = 0;
  size_t out_pos = 0;

  if (fuzz_size < 8 || out_cap < 64)
    return 0;

  /* Header: HLIT=257, HDIST=1, HCLEN=18 */
  /* HLIT - 257 = 0 */
  bits |= 0 << bits_avail;
  bits_avail += 5;
  /* HDIST - 1 = 0 */
  bits |= 0 << bits_avail;
  bits_avail += 5;
  /* HCLEN - 4 = 14 (HCLEN=18) */
  bits |= 14 << bits_avail;
  bits_avail += 4;

  /* Flush header */
  while (bits_avail >= 8 && out_pos < out_cap)
    {
      out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
      bits >>= 8;
      bits_avail -= 8;
    }

  /* Code length code lengths: enable symbols 0, 8, 16, 17, 18 */
  static const unsigned int codelen_order[19]
      = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

  uint8_t codelen_lens[19] = { 0 };
  codelen_lens[0] = 3;  /* length 0 */
  codelen_lens[8] = 3;  /* length 8 */
  codelen_lens[16] = 3; /* copy previous */
  codelen_lens[17] = 3; /* zeros 3-10 */
  codelen_lens[18] = 3; /* zeros 11-138 */
  /* Need 3 more symbols for valid tree (8 symbols at length 3) */
  codelen_lens[1] = 3;
  codelen_lens[7] = 3;
  codelen_lens[2] = 3;

  for (unsigned int i = 0; i < 18 && out_pos < out_cap; i++)
    {
      bits |= codelen_lens[codelen_order[i]] << bits_avail;
      bits_avail += 3;

      while (bits_avail >= 8 && out_pos < out_cap)
        {
          out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
          bits >>= 8;
          bits_avail -= 8;
        }
    }

  /* Flush remaining bits */
  if (bits_avail > 0 && out_pos < out_cap)
    {
      out_buf[out_pos++] = (uint8_t)(bits & 0xFF);
    }

  /* Append remaining fuzz data for code lengths and compressed data */
  size_t remaining = fuzz_size > 8 ? fuzz_size - 8 : 0;
  if (remaining > out_cap - out_pos)
    remaining = out_cap - out_pos;
  memcpy (out_buf + out_pos, fuzz_data + 8, remaining);
  out_pos += remaining;

  return out_pos;
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 * @data: Fuzz input data
 * @size: Size of fuzz input
 *
 * Exercises the dynamic Huffman decoder with various inputs.
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

  /* Parse fuzz input */
  uint8_t op = data[0] % OP_MAX;
  const uint8_t *fuzz_data = data + 1;
  size_t fuzz_size = size - 1;

  /* Create per-test arena */
  arena = Arena_new ();
  reader = SocketDeflate_BitReader_new (arena);

  switch (op)
    {
    case OP_RANDOM_DECODE:
      {
        /* Use raw fuzz data directly as dynamic block input */
        output_size = MAX_OUTPUT_SIZE;
        output = Arena_alloc (arena, output_size, __FILE__, __LINE__);

        SocketDeflate_BitReader_init (reader, fuzz_data, fuzz_size);
        result = SocketDeflate_decode_dynamic_block (
            reader, arena, output, output_size, &written);
        (void)result;
      }
      break;

    case OP_VALID_HEADER:
      {
        /* Build valid header, then append fuzz data */
        input_buf = Arena_alloc (arena, 4096, __FILE__, __LINE__);
        input_size = build_valid_header (fuzz_data, fuzz_size, input_buf, 64);

        /* Append remaining fuzz data */
        if (fuzz_size > 3 && input_size < 4096)
          {
            size_t append_size = fuzz_size - 3;
            if (append_size > 4096 - input_size)
              append_size = 4096 - input_size;
            memcpy (input_buf + input_size, fuzz_data + 3, append_size);
            input_size += append_size;
          }

        if (input_size > 0)
          {
            output_size = MAX_OUTPUT_SIZE;
            output = Arena_alloc (arena, output_size, __FILE__, __LINE__);

            SocketDeflate_BitReader_init (reader, input_buf, input_size);
            result = SocketDeflate_decode_dynamic_block (
                reader, arena, output, output_size, &written);
            (void)result;
          }
      }
      break;

    case OP_VALID_CODELEN_TABLE:
      {
        /* Build valid header and codelen table, then fuzz literal lengths */
        input_buf = Arena_alloc (arena, 8192, __FILE__, __LINE__);

        /* Header: HLIT=257, HDIST=1, HCLEN based on fuzz */
        unsigned int hclen = 4 + (fuzz_size > 0 ? fuzz_data[0] % 16 : 0);

        uint32_t bits = 0;
        int bits_avail = 0;
        size_t pos = 0;

        bits |= 0 << bits_avail;
        bits_avail += 5;
        bits |= 0 << bits_avail;
        bits_avail += 5;
        bits |= (hclen - 4) << bits_avail;
        bits_avail += 4;

        while (bits_avail >= 8)
          {
            input_buf[pos++] = (uint8_t)(bits & 0xFF);
            bits >>= 8;
            bits_avail -= 8;
          }

        /* Add valid codelen table */
        size_t codelen_size
            = build_valid_codelen_table (fuzz_data + 1,
                                         fuzz_size > 1 ? fuzz_size - 1 : 0,
                                         input_buf + pos,
                                         4096 - pos,
                                         hclen);
        pos += codelen_size;

        /* Append remaining fuzz data for literal lengths and compressed data */
        if (fuzz_size > 5 && pos < 8192)
          {
            size_t append_size = fuzz_size - 5;
            if (append_size > 8192 - pos)
              append_size = 8192 - pos;
            memcpy (input_buf + pos, fuzz_data + 5, append_size);
            pos += append_size;
          }

        input_size = pos;

        if (input_size > 0)
          {
            output_size = MAX_OUTPUT_SIZE;
            output = Arena_alloc (arena, output_size, __FILE__, __LINE__);

            SocketDeflate_BitReader_init (reader, input_buf, input_size);
            result = SocketDeflate_decode_dynamic_block (
                reader, arena, output, output_size, &written);
            (void)result;
          }
      }
      break;

    case OP_STRESS_RUNLENGTH:
      {
        /* Build block that stresses run-length codes */
        input_buf = Arena_alloc (arena, 8192, __FILE__, __LINE__);
        input_size = build_runlength_stress_block (
            fuzz_data, fuzz_size, input_buf, 8192);

        if (input_size > 0)
          {
            output_size = MAX_OUTPUT_SIZE;
            output = Arena_alloc (arena, output_size, __FILE__, __LINE__);

            SocketDeflate_BitReader_init (reader, input_buf, input_size);
            result = SocketDeflate_decode_dynamic_block (
                reader, arena, output, output_size, &written);
            (void)result;
          }
      }
      break;

    case OP_LARGE_OUTPUT:
      {
        /* Test with large output buffer */
        output_size = MAX_OUTPUT_SIZE;
        output = Arena_alloc (arena, output_size, __FILE__, __LINE__);

        SocketDeflate_BitReader_init (reader, fuzz_data, fuzz_size);
        result = SocketDeflate_decode_dynamic_block (
            reader, arena, output, output_size, &written);
        (void)result;
      }
      break;

    case OP_SMALL_OUTPUT:
      {
        /* Test with small output buffer - may hit output full condition */
        output_size = SMALL_OUTPUT_SIZE;
        output = Arena_alloc (arena, output_size, __FILE__, __LINE__);

        SocketDeflate_BitReader_init (reader, fuzz_data, fuzz_size);
        result = SocketDeflate_decode_dynamic_block (
            reader, arena, output, output_size, &written);
        /* May return DEFLATE_ERROR due to output buffer full */
        (void)result;
      }
      break;
    }

  Arena_dispose (&arena);

  return 0;
}
