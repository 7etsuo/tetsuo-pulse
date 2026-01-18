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

size_t
SocketDeflate_BitReader_bytes_consumed (SocketDeflate_BitReader_T reader)
{
  /*
   * The bit buffer may contain bytes that have been loaded from input
   * but not yet logically consumed. We subtract whole bytes still in
   * the buffer from in_pos to get the actual consumption.
   *
   * Example: 13 bytes input, after reading a 5-byte stored block header:
   *   - refill_bits loaded 8 bytes (bits_avail = 64, in_pos = 8)
   *   - After consuming 40 bits: bits_avail = 24 (3 whole bytes)
   *   - Actual consumed = 8 - 3 = 5 bytes
   */
  size_t bytes_in_buffer = (size_t)(reader->bits_avail / 8);
  return reader->in_pos - bytes_in_buffer;
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

/*
 * ============================================================================
 * Bit Stream Writer Implementation (RFC 1951 Section 3.1.1)
 * ============================================================================
 *
 * LSB-first bit output for DEFLATE compression.
 * Mirrors the reader's bit ordering for consistency.
 *
 * Bit Accumulator Model (Writer):
 * - 32-bit accumulator holds pending bits LSB-aligned
 * - New bits are added at position bits_pending
 * - Complete bytes are flushed from the bottom
 *
 * Example: Writing 0xA (4 bits) then 0x3 (2 bits)
 *   After write 0xA: bits = 0xA, bits_pending = 4
 *   After write 0x3: bits = (0x3 << 4) | 0xA = 0x3A, bits_pending = 6
 *   Output byte (when flushed): 0x3A (LSB-first packed)
 */

/**
 * Bit writer state structure.
 *
 * The bit accumulator uses LSB-first ordering:
 * - Valid bits are in the lowest bits_pending bits
 * - New bits are shifted in at position bits_pending
 * - Complete bytes are extracted from LSB when bits_pending >= 8
 */
struct SocketDeflate_BitWriter
{
  /* Output buffer */
  uint8_t *data;   /* Output buffer pointer */
  size_t capacity; /* Buffer capacity */
  size_t pos;      /* Current write position */

  /* Bit accumulator (64-bit to avoid overflow on shift) */
  uint64_t bits;    /* LSB-aligned bit buffer (pending bits) */
  int bits_pending; /* Number of valid bits (0-7 after flush) */
};

/*
 * Internal: Flush complete bytes from accumulator to output buffer.
 *
 * Extracts complete bytes from the accumulator and writes them
 * to the output buffer. Leaves partial bytes (< 8 bits) in accumulator.
 *
 * Returns: DEFLATE_OK on success, DEFLATE_ERROR if buffer full
 */
static inline SocketDeflate_Result
flush_bytes (SocketDeflate_BitWriter_T writer)
{
  while (writer->bits_pending >= 8)
    {
      if (writer->pos >= writer->capacity)
        return DEFLATE_ERROR; /* Buffer full */

      /* Write low byte to output */
      writer->data[writer->pos++] = (uint8_t)(writer->bits & 0xFF);

      /* Shift out the written byte */
      writer->bits >>= 8;
      writer->bits_pending -= 8;
    }

  return DEFLATE_OK;
}

/*
 * Public API Implementation
 */

SocketDeflate_BitWriter_T
SocketDeflate_BitWriter_new (Arena_T arena)
{
  SocketDeflate_BitWriter_T writer;

  writer = ALLOC (arena, sizeof (*writer));
  writer->data = NULL;
  writer->capacity = 0;
  writer->pos = 0;
  writer->bits = 0;
  writer->bits_pending = 0;

  return writer;
}

void
SocketDeflate_BitWriter_init (SocketDeflate_BitWriter_T writer, uint8_t *data,
                              size_t capacity)
{
  writer->data = data;
  writer->capacity = capacity;
  writer->pos = 0;
  writer->bits = 0;
  writer->bits_pending = 0;
}

SocketDeflate_Result
SocketDeflate_BitWriter_write (SocketDeflate_BitWriter_T writer, uint32_t value,
                               unsigned int n)
{
  /* Validate n is in range 1-25 */
  if (n == 0 || n > DEFLATE_MAX_BITS_READ)
    return DEFLATE_ERROR;

  /* Guard against accumulator overflow (can happen if output buffer is full) */
  if (writer->bits_pending + (int)n > 64)
    return DEFLATE_OUTPUT_FULL;

  /* Mask value to n bits */
  value &= BITMASK32 (n);

  /* Add bits to accumulator at position bits_pending (cast to 64-bit first) */
  writer->bits |= (uint64_t)value << writer->bits_pending;
  writer->bits_pending += n;

  /* Flush any complete bytes */
  return flush_bytes (writer);
}

SocketDeflate_Result
SocketDeflate_BitWriter_write_huffman (SocketDeflate_BitWriter_T writer,
                                       uint32_t code, unsigned int len)
{
  /*
   * Huffman codes are defined MSB-first in RFC 1951 but stored LSB-first
   * in the bit stream. We must reverse the bits before writing.
   *
   * Example: Code 0b110 (3 bits, MSB-first) stored as 0b011 (LSB-first)
   */
  if (len == 0 || len > DEFLATE_MAX_BITS)
    return DEFLATE_ERROR;

  uint32_t reversed = SocketDeflate_reverse_bits (code, len);
  return SocketDeflate_BitWriter_write (writer, reversed, len);
}

size_t
SocketDeflate_BitWriter_flush (SocketDeflate_BitWriter_T writer)
{
  /* Flush any pending bits with zero padding */
  if (writer->bits_pending > 0)
    {
      if (writer->pos < writer->capacity)
        {
          /* Write partial byte (already padded with zeros in high bits) */
          writer->data[writer->pos++] = (uint8_t)(writer->bits & 0xFF);
        }
      writer->bits = 0;
      writer->bits_pending = 0;
    }

  return writer->pos;
}

void
SocketDeflate_BitWriter_align (SocketDeflate_BitWriter_T writer)
{
  /* Align to byte boundary by flushing partial byte with zero padding */
  if (writer->bits_pending > 0)
    {
      if (writer->pos < writer->capacity)
        {
          writer->data[writer->pos++] = (uint8_t)(writer->bits & 0xFF);
        }
      writer->bits = 0;
      writer->bits_pending = 0;
    }
}

size_t
SocketDeflate_BitWriter_sync_flush (SocketDeflate_BitWriter_T writer)
{
  /*
   * RFC 7692 Section 7.2.1: Per-Message Deflate sync flush
   *
   * Writes an empty stored block that produces trailing bytes:
   *   0x00 0x00 0xFF 0xFF
   *
   * Format: BFINAL=0 (1 bit), BTYPE=00 (2 bits), align to byte,
   *         LEN=0x0000 (16 bits LE), NLEN=0xFFFF (16 bits LE)
   *
   * The 4-byte trailer is typically stripped before WebSocket transmission.
   */

  /* Write BFINAL=0, BTYPE=00 (3 bits total) */
  SocketDeflate_BitWriter_write (writer, 0, 3);

  /* Align to byte boundary */
  SocketDeflate_BitWriter_align (writer);

  /* Write LEN=0x0000 (16 bits little-endian) */
  SocketDeflate_BitWriter_write (writer, 0x0000, 16);

  /* Write NLEN=0xFFFF (16 bits little-endian) */
  SocketDeflate_BitWriter_write (writer, 0xFFFF, 16);

  /* Flush any remaining bits */
  return SocketDeflate_BitWriter_flush (writer);
}

size_t
SocketDeflate_BitWriter_size (SocketDeflate_BitWriter_T writer)
{
  return writer->pos;
}

size_t
SocketDeflate_BitWriter_capacity_remaining (SocketDeflate_BitWriter_T writer)
{
  return writer->capacity - writer->pos;
}

int
SocketDeflate_BitWriter_bits_pending (SocketDeflate_BitWriter_T writer)
{
  return writer->bits_pending;
}
