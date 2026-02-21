/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_deflate_lz77.c - libFuzzer harness for DEFLATE LZ77 and Huffman
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets:
 * - LZ77 hash table operations with arbitrary input
 * - Match finding with edge case distances and lengths
 * - Lazy matching decisions
 * - Huffman code length generation from varied frequency distributions
 * - Canonical code generation
 * - RLE encoding of code lengths
 * - Length/distance encode/decode roundtrip
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_deflate_lz77
 * Run:   ./fuzz_deflate_lz77 corpus/deflate_lz77/ -fork=16 -max_len=4096
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "deflate/SocketDeflate.h"

/* Maximum input size for LZ77 matching */
#define FUZZ_MAX_INPUT (32 * 1024) /* 32KB, one window */

/* Fuzz operation opcodes */
enum FuzzOp
{
  OP_LZ77_MATCH = 0,
  OP_LZ77_LAZY,
  OP_HUFFMAN_BUILD,
  OP_HUFFMAN_GENERATE,
  OP_RLE_ENCODE,
  OP_LENGTH_ROUNDTRIP,
  OP_DISTANCE_ROUNDTRIP,
  OP_COMBINED,
  OP_MAX
};

/**
 * parse_u16 - Parse 16-bit value from fuzz input
 */
static uint16_t
parse_u16 (const uint8_t *data, size_t len)
{
  if (len >= 2)
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
  if (len >= 1)
    return data[0];
  return 0;
}

/**
 * parse_u32 - Parse 32-bit value from fuzz input
 */
static uint32_t
parse_u32 (const uint8_t *data, size_t len)
{
  if (len >= 4)
    {
      return (uint32_t)data[0] | ((uint32_t)data[1] << 8)
             | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
    }
  return parse_u16 (data, len);
}

/**
 * fuzz_lz77_match - Test LZ77 matching with fuzz input as data
 */
static void
fuzz_lz77_match (Arena_T arena, const uint8_t *data, size_t size)
{
  if (size < 6) /* Need at least 2 3-byte sequences */
    return;

  /* Cap input size */
  if (size > FUZZ_MAX_INPUT)
    size = FUZZ_MAX_INPUT;

  SocketDeflate_Matcher_T matcher = SocketDeflate_Matcher_new (arena);
  SocketDeflate_Matcher_init (matcher, data, size);

  /* Insert all positions that have at least 3 bytes */
  for (size_t i = 0; i + DEFLATE_MIN_MATCH <= size; i++)
    {
      SocketDeflate_Matcher_insert (matcher, i);
    }

  /* Find matches at various positions */
  SocketDeflate_Match match;
  for (size_t i = DEFLATE_MIN_MATCH; i + DEFLATE_MIN_MATCH <= size; i++)
    {
      if (SocketDeflate_Matcher_find (matcher, i, &match))
        {
          /* Verify match constraints per RFC 1951 */
          assert (match.length >= DEFLATE_MIN_MATCH);
          assert (match.length <= DEFLATE_MAX_MATCH);
          assert (match.distance >= 1);
          assert (match.distance <= DEFLATE_WINDOW_SIZE);
          assert (match.distance <= i); /* Can't reference before start */

          /* Verify the match is actually valid */
          size_t match_start = i - match.distance;
          for (size_t j = 0; j < match.length && i + j < size; j++)
            {
              assert (data[match_start + j] == data[i + j]);
            }
        }
    }
}

/**
 * fuzz_lz77_lazy - Test lazy matching decisions
 */
static void
fuzz_lz77_lazy (Arena_T arena, const uint8_t *data, size_t size)
{
  if (size < 10)
    return;

  if (size > FUZZ_MAX_INPUT)
    size = FUZZ_MAX_INPUT;

  SocketDeflate_Matcher_T matcher = SocketDeflate_Matcher_new (arena);
  SocketDeflate_Matcher_init (matcher, data, size);

  /* Configure with fuzz-derived limits */
  int chain_limit = (data[0] % 256) + 1;
  int good_length = (data[1] % 32) + 1;
  int nice_length = (data[2] % 258) + 3;
  SocketDeflate_Matcher_set_limits (
      matcher, chain_limit, good_length, nice_length);

  /* Insert positions */
  for (size_t i = 0; i + DEFLATE_MIN_MATCH <= size; i++)
    {
      SocketDeflate_Matcher_insert (matcher, i);
    }

  /* Test lazy matching at various positions */
  SocketDeflate_Match match;
  for (size_t i = 3; i + DEFLATE_MIN_MATCH <= size; i++)
    {
      if (SocketDeflate_Matcher_find (matcher, i, &match))
        {
          /* Should we defer this match? */
          int defer
              = SocketDeflate_Matcher_should_defer (matcher, i, match.length);
          (void)defer; /* Result is valid either way */
        }
    }
}

/**
 * fuzz_huffman_build - Test Huffman code length building
 */
static void
fuzz_huffman_build (Arena_T arena, const uint8_t *data, size_t size)
{
  if (size < 4)
    return;

  /* Use fuzz data to create frequency distribution */
  unsigned int count = (data[0] % 64) + 1;    /* 1-64 symbols */
  unsigned int max_bits = (data[1] % 15) + 1; /* 1-15 bits */

  if (size < 4 + count * 4)
    return;

  /* Parse frequencies from fuzz input */
  uint32_t freqs[288] = { 0 };
  for (unsigned int i = 0; i < count && i < 288; i++)
    {
      freqs[i] = parse_u32 (data + 4 + i * 4, 4);
    }

  /* Build code lengths */
  uint8_t lengths[288] = { 0 };
  SocketDeflate_Result result = SocketDeflate_build_code_lengths (
      freqs, lengths, count, max_bits, arena);

  if (result == DEFLATE_OK)
    {
      /* Verify constraints */
      for (unsigned int i = 0; i < count; i++)
        {
          assert (lengths[i] <= max_bits);
          /* If freq is 0, length should be 0 */
          /* Note: single-symbol case may have length > 0 with freq 0 */
        }

      /* Verify Kraft inequality: sum(2^-len) <= 1 */
      unsigned int kraft_sum = 0;
      for (unsigned int i = 0; i < count; i++)
        {
          if (lengths[i] > 0)
            {
              kraft_sum += 1U << (max_bits - lengths[i]);
            }
        }
      assert (kraft_sum <= (1U << max_bits));
    }
}

/**
 * fuzz_huffman_generate - Test canonical code generation
 */
static void
fuzz_huffman_generate (Arena_T arena, const uint8_t *data, size_t size)
{
  (void)arena; /* Not needed for generate_codes */

  if (size < 2)
    return;

  unsigned int count = (data[0] % 64) + 1;

  if (size < 2 + count)
    return;

  /* Use fuzz bytes as code lengths (0-15) */
  uint8_t lengths[288] = { 0 };
  for (unsigned int i = 0; i < count && i < 288; i++)
    {
      lengths[i] = data[2 + i] % 16; /* 0-15 bits */
    }

  /* Generate canonical codes */
  SocketDeflate_HuffmanCode codes[288];
  SocketDeflate_generate_codes (lengths, codes, count);

  /* Verify generated codes */
  for (unsigned int i = 0; i < count; i++)
    {
      if (lengths[i] > 0)
        {
          assert (codes[i].len == lengths[i]);
          /* Code should fit in len bits */
          assert (codes[i].code < (1U << codes[i].len));
        }
      else
        {
          assert (codes[i].len == 0);
        }
    }
}

/**
 * fuzz_rle_encode - Test RLE encoding of code lengths
 */
static void
fuzz_rle_encode (Arena_T arena, const uint8_t *data, size_t size)
{
  (void)arena;

  if (size < 2)
    return;

  unsigned int count = (data[0] % 200) + 1; /* Up to 200 lengths */

  if (size < 2 + count)
    return;

  /* Use fuzz bytes as code lengths */
  uint8_t lengths[288] = { 0 };
  for (unsigned int i = 0; i < count && i < 288; i++)
    {
      lengths[i] = data[2 + i] % 16;
    }

  /* Encode */
  uint8_t output[600]; /* Max: count * 2 for worst case */
  size_t encoded = SocketDeflate_encode_code_lengths (
      lengths, count, output, sizeof (output));

  /* Output should not exceed reasonable bounds */
  assert (encoded <= count * 2);

  /* Verify encoded symbols are valid (0-18) */
  for (size_t i = 0; i < encoded; i++)
    {
      assert (output[i] <= 18);
    }
}

/**
 * fuzz_length_roundtrip - Test length encode/decode roundtrip
 */
static void
fuzz_length_roundtrip (Arena_T arena, const uint8_t *data, size_t size)
{
  (void)arena;

  if (size < 2)
    return;

  /* Parse length from fuzz input (clamped to valid range) */
  unsigned int length = parse_u16 (data, size);
  length = (length % 256) + 3; /* 3-258 */

  unsigned int code, extra, extra_bits;
  SocketDeflate_encode_length (length, &code, &extra, &extra_bits);

  /* Verify encoding constraints */
  assert (code >= 257 && code <= 285);
  assert (extra_bits <= 5);
  if (extra_bits > 0)
    {
      assert (extra < (1U << extra_bits));
    }

  /* Decode and verify roundtrip */
  unsigned int decoded;
  SocketDeflate_Result result
      = SocketDeflate_decode_length (code, extra, &decoded);
  assert (result == DEFLATE_OK);
  assert (decoded == length);
}

/**
 * fuzz_distance_roundtrip - Test distance encode/decode roundtrip
 */
static void
fuzz_distance_roundtrip (Arena_T arena, const uint8_t *data, size_t size)
{
  (void)arena;

  if (size < 2)
    return;

  /* Parse distance from fuzz input (clamped to valid range) */
  unsigned int distance = parse_u16 (data, size);
  distance = (distance % 32768) + 1; /* 1-32768 */

  unsigned int code, extra, extra_bits;
  SocketDeflate_encode_distance (distance, &code, &extra, &extra_bits);

  /* Verify encoding constraints */
  assert (code <= 29);
  assert (extra_bits <= 13);
  if (extra_bits > 0)
    {
      assert (extra < (1U << extra_bits));
    }

  /* Decode and verify roundtrip */
  unsigned int decoded;
  SocketDeflate_Result result
      = SocketDeflate_decode_distance (code, extra, &decoded);
  assert (result == DEFLATE_OK);
  assert (decoded == distance);
}

/**
 * fuzz_combined - Combined LZ77 + Huffman test
 */
static void
fuzz_combined (Arena_T arena, const uint8_t *data, size_t size)
{
  if (size < 10)
    return;

  /* Use first part as LZ77 input */
  size_t lz77_size = size / 2;
  if (lz77_size > FUZZ_MAX_INPUT)
    lz77_size = FUZZ_MAX_INPUT;

  SocketDeflate_Matcher_T matcher = SocketDeflate_Matcher_new (arena);
  SocketDeflate_Matcher_init (matcher, data, lz77_size);

  /* Collect symbol frequencies from matches */
  uint32_t litlen_freqs[DEFLATE_LITLEN_CODES] = { 0 };
  uint32_t dist_freqs[DEFLATE_DISTANCE_CODES] = { 0 };

  for (size_t i = 0; i + DEFLATE_MIN_MATCH <= lz77_size; i++)
    {
      SocketDeflate_Matcher_insert (matcher, i);
    }

  for (size_t i = 0; i + DEFLATE_MIN_MATCH <= lz77_size; i++)
    {
      SocketDeflate_Match match;
      if (SocketDeflate_Matcher_find (matcher, i, &match))
        {
          /* Count length code frequency */
          unsigned int code, extra, extra_bits;
          SocketDeflate_encode_length (
              match.length, &code, &extra, &extra_bits);
          if (code < DEFLATE_LITLEN_CODES)
            litlen_freqs[code]++;

          /* Count distance code frequency */
          SocketDeflate_encode_distance (
              match.distance, &code, &extra, &extra_bits);
          if (code < DEFLATE_DISTANCE_CODES)
            dist_freqs[code]++;

          i += match.length - 1; /* Skip matched bytes */
        }
      else
        {
          /* Literal */
          litlen_freqs[data[i]]++;
        }
    }

  /* Add end-of-block */
  litlen_freqs[DEFLATE_END_OF_BLOCK]++;

  /* Build Huffman tables from collected frequencies */
  uint8_t litlen_lengths[DEFLATE_LITLEN_CODES];
  uint8_t dist_lengths[DEFLATE_DISTANCE_CODES];

  SocketDeflate_build_code_lengths (litlen_freqs,
                                    litlen_lengths,
                                    DEFLATE_LITLEN_CODES,
                                    DEFLATE_MAX_BITS,
                                    arena);
  SocketDeflate_build_code_lengths (dist_freqs,
                                    dist_lengths,
                                    DEFLATE_DISTANCE_CODES,
                                    DEFLATE_MAX_BITS,
                                    arena);

  /* Generate canonical codes */
  SocketDeflate_HuffmanCode litlen_codes[DEFLATE_LITLEN_CODES];
  SocketDeflate_HuffmanCode dist_codes[DEFLATE_DISTANCE_CODES];

  SocketDeflate_generate_codes (
      litlen_lengths, litlen_codes, DEFLATE_LITLEN_CODES);
  SocketDeflate_generate_codes (
      dist_lengths, dist_codes, DEFLATE_DISTANCE_CODES);

  /* Verify all generated codes */
  for (unsigned int i = 0; i < DEFLATE_LITLEN_CODES; i++)
    {
      if (litlen_lengths[i] > 0)
        {
          assert (litlen_codes[i].len == litlen_lengths[i]);
          assert (litlen_codes[i].code < (1U << litlen_codes[i].len));
        }
    }
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;

  if (size < 2)
    return 0;

  uint8_t op = data[0] % OP_MAX;
  const uint8_t *payload = data + 1;
  size_t payload_size = size - 1;

  TRY
  {
    arena = Arena_new ();
    if (!arena)
      return 0;

    switch (op)
      {
      case OP_LZ77_MATCH:
        fuzz_lz77_match (arena, payload, payload_size);
        break;

      case OP_LZ77_LAZY:
        fuzz_lz77_lazy (arena, payload, payload_size);
        break;

      case OP_HUFFMAN_BUILD:
        fuzz_huffman_build (arena, payload, payload_size);
        break;

      case OP_HUFFMAN_GENERATE:
        fuzz_huffman_generate (arena, payload, payload_size);
        break;

      case OP_RLE_ENCODE:
        fuzz_rle_encode (arena, payload, payload_size);
        break;

      case OP_LENGTH_ROUNDTRIP:
        fuzz_length_roundtrip (arena, payload, payload_size);
        break;

      case OP_DISTANCE_ROUNDTRIP:
        fuzz_distance_roundtrip (arena, payload, payload_size);
        break;

      case OP_COMBINED:
        fuzz_combined (arena, payload, payload_size);
        break;
      }
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected for large allocations */
  }
  EXCEPT (SocketDeflate_Failed)
  {
    /* Expected for invalid operations */
  }
  FINALLY
  {
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;

  return 0;
}
