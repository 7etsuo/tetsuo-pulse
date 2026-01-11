/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDeflate-bitstream.c
 * @brief RFC 1951 DEFLATE bit stream reader.
 *
 * Implements LSB-first bit reading as specified in RFC 1951 Section 3.1.1.
 * DEFLATE packs bits starting with the least-significant bit of each byte,
 * which is the opposite of HPACK's MSB-first ordering.
 *
 * Bit Accumulator Model:
 * - 64-bit accumulator holds bits LSB-aligned
 * - New bytes are added at the top (shifted left by bits_avail)
 * - Bits are consumed from the bottom (masked and right-shifted)
 *
 * Example: Reading from bytes [0xAB, 0xCD]
 *   After loading byte 0: bits = 0xAB, bits_avail = 8
 *   After loading byte 1: bits = 0xCDAB, bits_avail = 16
 *   Read 12 bits: value = bits & 0xFFF = 0xDAB
 *                 bits >>= 12, bits_avail = 4
 */

#include "deflate/SocketDeflate.h"

#include "core/Arena.h"
#include "core/SocketUtil.h"

#include <string.h>

/* Refill bit buffer when fewer than this many bits remain */
#define DEFLATE_REFILL_THRESHOLD 32

/**
 * Bit reader state structure.
 *
 * The bit accumulator uses LSB-first ordering:
 * - Valid bits are in the lowest bits_avail bits
 * - New bytes are shifted in at position bits_avail
 * - Consumption shifts right and decrements bits_avail
 */
struct SocketDeflate_BitReader
{
  /* Bit accumulator */
  uint64_t bits;  /* LSB-aligned bit buffer */
  int bits_avail; /* Number of valid bits (0-64) */

  /* Input stream */
  const uint8_t *input; /* Input buffer pointer */
  size_t input_len;     /* Total input length */
  size_t in_pos;        /* Current read position */
};

/*
 * Internal: Refill the bit accumulator from input.
 *
 * Loads bytes into the accumulator until we have at least
 * DEFLATE_REFILL_THRESHOLD bits or run out of input.
 *
 * Bytes are added at the top of the accumulator (shifted by bits_avail)
 * to maintain LSB-first bit ordering.
 */
static inline void
refill_bits (SocketDeflate_BitReader_T reader)
{
  while (reader->bits_avail <= DEFLATE_REFILL_THRESHOLD
         && reader->in_pos < reader->input_len)
    {
      /* Add new byte at position bits_avail (top of valid bits) */
      reader->bits
          |= (uint64_t)reader->input[reader->in_pos++] << reader->bits_avail;
      reader->bits_avail += 8;
    }
}

/*
 * Public API Implementation
 */

SocketDeflate_BitReader_T
SocketDeflate_BitReader_new (Arena_T arena)
{
  SocketDeflate_BitReader_T reader;

  reader = ALLOC (arena, sizeof (*reader));
  reader->bits = 0;
  reader->bits_avail = 0;
  reader->input = NULL;
  reader->input_len = 0;
  reader->in_pos = 0;

  return reader;
}

void
SocketDeflate_BitReader_init (SocketDeflate_BitReader_T reader,
                              const uint8_t *data, size_t size)
{
  reader->bits = 0;
  reader->bits_avail = 0;
  reader->input = data;
  reader->input_len = size;
  reader->in_pos = 0;
}

SocketDeflate_Result
SocketDeflate_BitReader_read (SocketDeflate_BitReader_T reader, unsigned int n,
                              uint32_t *value)
{
  /* Validate n is in range 1-25 */
  if (n == 0 || n > DEFLATE_MAX_BITS_READ)
    return DEFLATE_ERROR;

  /* Ensure we have enough bits */
  refill_bits (reader);

  if (reader->bits_avail < (int)n)
    return DEFLATE_INCOMPLETE;

  /* Extract N bits from LSB */
  *value = (uint32_t)(reader->bits & BITMASK64 (n));

  /* Consume those bits */
  reader->bits >>= n;
  reader->bits_avail -= n;

  return DEFLATE_OK;
}

SocketDeflate_Result
SocketDeflate_BitReader_peek (SocketDeflate_BitReader_T reader, unsigned int n,
                              uint32_t *value)
{
  /* Validate n is in range 1-25 */
  if (n == 0 || n > DEFLATE_MAX_BITS_READ)
    return DEFLATE_ERROR;

  /* Ensure we have enough bits */
  refill_bits (reader);

  if (reader->bits_avail < (int)n)
    return DEFLATE_INCOMPLETE;

  /* Extract without consuming */
  *value = (uint32_t)(reader->bits & BITMASK64 (n));

  return DEFLATE_OK;
}

void
SocketDeflate_BitReader_consume (SocketDeflate_BitReader_T reader,
                                 unsigned int n)
{
  if ((int)n > reader->bits_avail)
    n = reader->bits_avail;

  reader->bits >>= n;
  reader->bits_avail -= n;
}

void
SocketDeflate_BitReader_align (SocketDeflate_BitReader_T reader)
{
  /* Discard bits to reach byte boundary */
  int discard = reader->bits_avail & 7; /* bits_avail % 8 */

  if (discard > 0)
    {
      reader->bits >>= discard;
      reader->bits_avail -= discard;
    }
}

SocketDeflate_Result
SocketDeflate_BitReader_read_bytes (SocketDeflate_BitReader_T reader,
                                    uint8_t *dest, size_t count)
{
  size_t i;

  /*
   * First, consume any whole bytes from the bit accumulator.
   * After align(), bits_avail should be a multiple of 8.
   */
  while (count > 0 && reader->bits_avail >= 8)
    {
      *dest++ = (uint8_t)(reader->bits & 0xFF);
      reader->bits >>= 8;
      reader->bits_avail -= 8;
      count--;
    }

  /* Then read remaining bytes directly from input */
  if (count > 0)
    {
      size_t remaining = reader->input_len - reader->in_pos;
      if (remaining < count)
        return DEFLATE_INCOMPLETE;

      for (i = 0; i < count; i++)
        {
          dest[i] = reader->input[reader->in_pos++];
        }
    }

  return DEFLATE_OK;
}

size_t
SocketDeflate_BitReader_bits_available (SocketDeflate_BitReader_T reader)
{
  size_t remaining_bytes = reader->input_len - reader->in_pos;
  return (size_t)reader->bits_avail + (remaining_bytes * 8);
}

size_t
SocketDeflate_BitReader_bytes_remaining (SocketDeflate_BitReader_T reader)
{
  return reader->input_len - reader->in_pos;
}

int
SocketDeflate_BitReader_at_end (SocketDeflate_BitReader_T reader)
{
  return (reader->bits_avail == 0) && (reader->in_pos >= reader->input_len);
}

/*
 * Bit reversal for Huffman codes.
 *
 * DEFLATE Huffman codes are defined MSB-first in RFC 1951, but appear
 * LSB-first in the bit stream. When building decode tables, we need to
 * reverse the bit order of codes.
 *
 * Example: Code 0b110 (3 bits, MSB-first) becomes 0b011 when reversed.
 *
 * Uses a simple loop for clarity and correctness. For hot paths,
 * a lookup table or parallel bit manipulation could be used instead.
 */
uint32_t
SocketDeflate_reverse_bits (uint32_t value, unsigned int nbits)
{
  uint32_t result = 0;
  unsigned int i;

  /* nbits must be 1-15 (max Huffman code length) */
  if (nbits == 0 || nbits > DEFLATE_MAX_BITS)
    return 0;

  for (i = 0; i < nbits; i++)
    {
      result = (result << 1) | (value & 1);
      value >>= 1;
    }

  return result;
}
