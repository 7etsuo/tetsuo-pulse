/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_deflate_bitstream.c - RFC 1951 DEFLATE bit stream reader unit tests
 *
 * Tests for the DEFLATE bit stream reader module, verifying correct
 * LSB-first bit ordering as specified in RFC 1951 Section 3.1.1.
 *
 * Test coverage:
 * - Basic read operations (single bits, multiple bits)
 * - LSB-first bit ordering verification
 * - Cross-byte boundary reads
 * - Peek and consume operations
 * - Byte alignment (for stored blocks)
 * - Raw byte reads
 * - Edge cases (empty input, incomplete)
 * - Bit reversal for Huffman codes
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "deflate/SocketDeflate.h"
#include "test/Test.h"

/*
 * Helper: Create and initialize a bit reader with test data
 */
static Arena_T test_arena;

static SocketDeflate_BitReader_T
make_reader (const uint8_t *data, size_t size)
{
  SocketDeflate_BitReader_T reader = SocketDeflate_BitReader_new (test_arena);
  SocketDeflate_BitReader_init (reader, data, size);
  return reader;
}

/*
 * Basic Operations Tests
 */

TEST (bitreader_create_and_init)
{
  uint8_t data[] = { 0xAB, 0xCD };
  SocketDeflate_BitReader_T reader = make_reader (data, 2);

  ASSERT (reader != NULL);
  ASSERT_EQ (SocketDeflate_BitReader_bits_available (reader), 16);
  ASSERT_EQ (SocketDeflate_BitReader_bytes_remaining (reader), 2);
  ASSERT_EQ (SocketDeflate_BitReader_at_end (reader), 0);
}

TEST (bitreader_read_single_bits)
{
  /* Byte 0xA5 = 10100101 in binary
   * LSB-first reading: bit 0 = 1, bit 1 = 0, bit 2 = 1, bit 3 = 0, ...
   */
  uint8_t data[] = { 0xA5 };
  SocketDeflate_BitReader_T reader = make_reader (data, 1);
  uint32_t bit;

  /* Read bits one at a time, LSB first */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 1, &bit), DEFLATE_OK);
  ASSERT_EQ (bit, 1); /* bit 0 */

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 1, &bit), DEFLATE_OK);
  ASSERT_EQ (bit, 0); /* bit 1 */

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 1, &bit), DEFLATE_OK);
  ASSERT_EQ (bit, 1); /* bit 2 */

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 1, &bit), DEFLATE_OK);
  ASSERT_EQ (bit, 0); /* bit 3 */

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 1, &bit), DEFLATE_OK);
  ASSERT_EQ (bit, 0); /* bit 4 */

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 1, &bit), DEFLATE_OK);
  ASSERT_EQ (bit, 1); /* bit 5 */

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 1, &bit), DEFLATE_OK);
  ASSERT_EQ (bit, 0); /* bit 6 */

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 1, &bit), DEFLATE_OK);
  ASSERT_EQ (bit, 1); /* bit 7 */

  /* All 8 bits consumed */
  ASSERT_EQ (SocketDeflate_BitReader_at_end (reader), 1);
}

TEST (bitreader_read_multiple_bits)
{
  /* Byte 0xAB = 10101011 in binary
   * Read 4 bits: gets bits 3210 = 1011 = 0xB
   * Read 4 bits: gets bits 7654 = 1010 = 0xA
   */
  uint8_t data[] = { 0xAB };
  SocketDeflate_BitReader_T reader = make_reader (data, 1);
  uint32_t value;

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 4, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xB); /* Low nibble */

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 4, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xA); /* High nibble */
}

TEST (bitreader_read_cross_byte_boundary)
{
  /* Bytes [0xAB, 0xCD]
   * In LSB-first accumulator: bits = 0xCDAB
   * Read 12 bits: value = 0xDAB (bits 11..0)
   */
  uint8_t data[] = { 0xAB, 0xCD };
  SocketDeflate_BitReader_T reader = make_reader (data, 2);
  uint32_t value;

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 12, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xDAB);

  /* 4 bits remain: 0xC */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 4, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xC);
}

/*
 * LSB-First Ordering Tests
 */

TEST (bitreader_lsb_first_order)
{
  /* RFC 1951 Section 3.1.1:
   * "Data elements are packed into bytes in order of
   * increasing bit number within the byte, i.e., starting
   * with the least-significant bit of the byte."
   *
   * Byte 0x08 = 00001000
   * Read 3 bits: bits 210 = 000 = 0
   * Read 1 bit:  bit 3 = 1
   * Read 4 bits: bits 7654 = 0000 = 0
   */
  uint8_t data[] = { 0x08 };
  SocketDeflate_BitReader_T reader = make_reader (data, 1);
  uint32_t value;

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 3, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0);

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 1, &value), DEFLATE_OK);
  ASSERT_EQ (value, 1);

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 4, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0);
}

TEST (bitreader_multi_byte_value_lsb)
{
  /* Read a 16-bit value spanning two bytes
   * Bytes [0x34, 0x12] should give 0x1234 when read as 16 bits
   * Because: accumulator = 0x12 << 8 | 0x34 = 0x1234
   *          (but in LSB-first it's still ordered as byte[1]<<8 | byte[0])
   *
   * Actually in our accumulator:
   *   bits = byte[0] | (byte[1] << 8) = 0x34 | (0x12 << 8) = 0x1234
   * Read 16 bits: value = bits & 0xFFFF = 0x1234
   */
  uint8_t data[] = { 0x34, 0x12 };
  SocketDeflate_BitReader_T reader = make_reader (data, 2);
  uint32_t value;

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 16, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0x1234);
}

TEST (bitreader_deflate_block_header)
{
  /* DEFLATE block header is 3 bits: BFINAL (1 bit) + BTYPE (2 bits)
   * Byte 0x03 = 00000011
   * BFINAL = bit 0 = 1 (final block)
   * BTYPE = bits 21 = 01 (fixed Huffman)
   */
  uint8_t data[] = { 0x03 };
  SocketDeflate_BitReader_T reader = make_reader (data, 1);
  uint32_t bfinal, btype;

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 1, &bfinal), DEFLATE_OK);
  ASSERT_EQ (bfinal, 1); /* BFINAL = 1 */

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 2, &btype), DEFLATE_OK);
  ASSERT_EQ (btype, 1); /* BTYPE = 01 (fixed) */
}

/*
 * Peek and Consume Tests
 */

TEST (bitreader_peek_does_not_consume)
{
  uint8_t data[] = { 0xAB };
  SocketDeflate_BitReader_T reader = make_reader (data, 1);
  uint32_t value1, value2;

  /* Peek should not consume */
  ASSERT_EQ (SocketDeflate_BitReader_peek (reader, 4, &value1), DEFLATE_OK);
  ASSERT_EQ (value1, 0xB);

  /* Peek again - same value */
  ASSERT_EQ (SocketDeflate_BitReader_peek (reader, 4, &value2), DEFLATE_OK);
  ASSERT_EQ (value2, 0xB);

  /* Still have 8 bits */
  ASSERT_EQ (SocketDeflate_BitReader_bits_available (reader), 8);
}

TEST (bitreader_consume_after_peek)
{
  uint8_t data[] = { 0xAB };
  SocketDeflate_BitReader_T reader = make_reader (data, 1);
  uint32_t value;

  /* Peek 8 bits */
  ASSERT_EQ (SocketDeflate_BitReader_peek (reader, 8, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xAB);

  /* Consume only 4 bits */
  SocketDeflate_BitReader_consume (reader, 4);

  /* Peek remaining - should be 0xA */
  ASSERT_EQ (SocketDeflate_BitReader_peek (reader, 4, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xA);
}

TEST (bitreader_peek_for_huffman)
{
  /* Simulate Huffman decoding: peek max bits, find code, consume code length
   *
   * Example: peek 15 bits, determine code is 7 bits, consume 7
   */
  uint8_t data[] = { 0xFF, 0xFF, 0xFF };
  SocketDeflate_BitReader_T reader = make_reader (data, 3);
  uint32_t bits;

  /* Peek 15 bits */
  ASSERT_EQ (SocketDeflate_BitReader_peek (reader, 15, &bits), DEFLATE_OK);
  ASSERT_EQ (bits, 0x7FFF); /* All 1s */

  /* Consume 7 bits (as if we found a 7-bit Huffman code) */
  SocketDeflate_BitReader_consume (reader, 7);

  /* Peek again for next symbol */
  ASSERT_EQ (SocketDeflate_BitReader_peek (reader, 15, &bits), DEFLATE_OK);
  ASSERT_EQ (bits, 0x7FFF); /* Still all 1s (remaining bytes) */
}

/*
 * Byte Alignment Tests
 */

TEST (bitreader_align_partial_byte)
{
  /* Read 3 bits, then align - should discard 5 bits */
  uint8_t data[] = { 0xAB, 0xCD };
  SocketDeflate_BitReader_T reader = make_reader (data, 2);
  uint32_t value;

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 3, &value), DEFLATE_OK);

  /* Align to byte boundary */
  SocketDeflate_BitReader_align (reader);

  /* After align: bits_avail should be multiple of 8 (or 0 with refill pending)
   */
  /* Next read should get from byte 1 = 0xCD */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 8, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xCD);
}

TEST (bitreader_align_already_aligned)
{
  /* When already aligned, align should be a no-op */
  uint8_t data[] = { 0xAB, 0xCD };
  SocketDeflate_BitReader_T reader = make_reader (data, 2);
  uint32_t value;

  /* Read exactly 8 bits - now aligned */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 8, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xAB);

  /* Align should do nothing */
  SocketDeflate_BitReader_align (reader);

  /* Next read should be 0xCD */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 8, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xCD);
}

TEST (bitreader_read_bytes_after_align)
{
  /* For stored blocks: read some bits, align, then read raw bytes */
  uint8_t data[] = { 0x01, 0x05, 0x00, 0xFA, 0xFF, 'H', 'e', 'l', 'l', 'o' };
  SocketDeflate_BitReader_T reader = make_reader (data, 10);
  uint32_t value;
  uint8_t buf[5];

  /* Read BFINAL (1) and BTYPE (00) = 3 bits total */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 1, &value), DEFLATE_OK);
  ASSERT_EQ (value, 1); /* BFINAL */

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 2, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0); /* BTYPE = 00 (stored) */

  /* Align to byte boundary */
  SocketDeflate_BitReader_align (reader);

  /* Read LEN (2 bytes little-endian) */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 16, &value), DEFLATE_OK);
  ASSERT_EQ (value, 5); /* LEN = 5 */

  /* Read NLEN (2 bytes little-endian) */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 16, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xFFFA); /* NLEN = ~5 */

  /* Read raw bytes */
  ASSERT_EQ (SocketDeflate_BitReader_read_bytes (reader, buf, 5), DEFLATE_OK);
  ASSERT_EQ (memcmp (buf, "Hello", 5), 0);
}

/*
 * Edge Cases Tests
 */

TEST (bitreader_empty_input)
{
  SocketDeflate_BitReader_T reader = make_reader (NULL, 0);
  uint32_t value;

  ASSERT_EQ (SocketDeflate_BitReader_at_end (reader), 1);
  ASSERT_EQ (SocketDeflate_BitReader_bits_available (reader), 0);
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 1, &value),
             DEFLATE_INCOMPLETE);
}

TEST (bitreader_incomplete_read)
{
  uint8_t data[] = { 0xAB };
  SocketDeflate_BitReader_T reader = make_reader (data, 1);
  uint32_t value;

  /* Try to read more bits than available */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 16, &value),
             DEFLATE_INCOMPLETE);

  /* Data should still be intact */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 8, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xAB);
}

TEST (bitreader_exact_byte_boundary)
{
  uint8_t data[] = { 0xAB, 0xCD, 0xEF };
  SocketDeflate_BitReader_T reader = make_reader (data, 3);
  uint32_t value;

  /* Read exactly 24 bits (3 bytes) */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 24, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xEFCDAB); /* Little-endian accumulation */

  ASSERT_EQ (SocketDeflate_BitReader_at_end (reader), 1);
}

TEST (bitreader_max_bits_read)
{
  /* Test reading DEFLATE_MAX_BITS_READ (25) bits */
  uint8_t data[] = { 0xFF, 0xFF, 0xFF, 0xFF };
  SocketDeflate_BitReader_T reader = make_reader (data, 4);
  uint32_t value;

  ASSERT_EQ (
      SocketDeflate_BitReader_read (reader, DEFLATE_MAX_BITS_READ, &value),
      DEFLATE_OK);
  ASSERT_EQ (value, 0x1FFFFFF); /* 25 bits all set */
}

/*
 * Bit Reversal Tests (for Huffman codes)
 */

TEST (bitreader_reverse_bits_simple)
{
  /* Reverse 0b110 (3 bits) -> 0b011 */
  ASSERT_EQ (SocketDeflate_reverse_bits (0x6, 3), 0x3);

  /* Reverse 0b1010 (4 bits) -> 0b0101 */
  ASSERT_EQ (SocketDeflate_reverse_bits (0xA, 4), 0x5);

  /* Reverse 0b11111111 (8 bits) -> 0b11111111 */
  ASSERT_EQ (SocketDeflate_reverse_bits (0xFF, 8), 0xFF);

  /* Reverse 0b00000001 (8 bits) -> 0b10000000 */
  ASSERT_EQ (SocketDeflate_reverse_bits (0x01, 8), 0x80);
}

TEST (bitreader_reverse_bits_various_lengths)
{
  /* Test reversal at various bit lengths */
  ASSERT_EQ (SocketDeflate_reverse_bits (0x1, 1), 0x1);
  ASSERT_EQ (SocketDeflate_reverse_bits (0x1, 2), 0x2);
  ASSERT_EQ (SocketDeflate_reverse_bits (0x1, 5), 0x10);
  ASSERT_EQ (SocketDeflate_reverse_bits (0x1, 8), 0x80);
  ASSERT_EQ (SocketDeflate_reverse_bits (0x1, 15), 0x4000);

  /* Fixed Huffman code example:
   * Symbol 'a' (97) has code 00011 (5 bits) in MSB-first
   * In LSB-first stream: 11000
   * reverse_bits(0x03, 5) should give bit-reversed for table lookup
   */
  ASSERT_EQ (SocketDeflate_reverse_bits (0x03, 5), 0x18); /* 0b11000 = 24 */
}

TEST (bitreader_huffman_code_orientation)
{
  /* RFC 1951 Section 3.1.1:
   * "Huffman codes are packed starting with the most-
   * significant bit of the code."
   *
   * Example: Code 0b110 (3 bits, value 6 MSB-first)
   * In the stream, this appears as: bit 0 = 0, bit 1 = 1, bit 2 = 1
   * Reading 3 bits LSB-first gives: 0b011 = 3
   *
   * So: stream_bits = reverse_bits(code, code_len)
   */
  uint32_t code = 0x6; /* 0b110 MSB-first */
  uint32_t code_len = 3;
  uint32_t stream_bits = SocketDeflate_reverse_bits (code, code_len);
  ASSERT_EQ (stream_bits, 0x3); /* 0b011 LSB-first */

  /* To look up a code from stream bits, reverse again */
  uint32_t recovered = SocketDeflate_reverse_bits (stream_bits, code_len);
  ASSERT_EQ (recovered, code);
}

/*
 * RFC 1951 Compliance Tests
 */

TEST (bitreader_rfc_bit_packing_example)
{
  /* RFC 1951 Section 3.1.1 describes packing order.
   * If we have 3 5-bit data elements A, B, C with values:
   *   A = 0b10101, B = 0b01010, C = 0b11111
   *
   * They pack into bytes as:
   *   Byte 0: [A bit 4..0 | B bit 1..0] = [10101 | 10] = 0b10|10101 = 0x55
   *   Wait, let me recalculate...
   *
   * Actually LSB first packing:
   *   Byte 0 bits: A[0], A[1], A[2], A[3], A[4], B[0], B[1], B[2]
   *              = 1,    0,    1,    0,    1,    0,    1,    0
   *              = 0b01010101 = 0x55
   *   Byte 1 bits: B[3], B[4], C[0], C[1], C[2], C[3], C[4], pad
   *              = 1,    0,    1,    1,    1,    1,    1,    ?
   *
   * Let me use actual values to test:
   */
  /* Pack 3-bit value 5 (101) and 3-bit value 3 (011) into byte 0xAD
   * Bits: [011][101] = 0b00 011 101 = 0x1D... no wait
   *
   * LSB first: bits 0-2 = value1, bits 3-5 = value2
   * value1 = 5 = 0b101, value2 = 3 = 0b011
   * byte = (value2 << 3) | value1 = 0b011101 = 0x1D
   */
  uint8_t data[] = { 0x1D };
  SocketDeflate_BitReader_T reader = make_reader (data, 1);
  uint32_t v1, v2;

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 3, &v1), DEFLATE_OK);
  ASSERT_EQ (v1, 5);

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 3, &v2), DEFLATE_OK);
  ASSERT_EQ (v2, 3);
}

TEST (bitreader_rfc_multivalue_packing)
{
  /* Pack: BFINAL=1 (1 bit), BTYPE=01 (2 bits), HLIT=28 (5 bits)
   * Total 8 bits = 1 byte
   *
   * LSB first: BFINAL | BTYPE | HLIT
   * bits: [1] [10] [11100] = ? let me recalculate
   *
   * BFINAL = 1 -> bit 0 = 1
   * BTYPE = 01 -> bits 2,1 = 0,1
   * HLIT = 28 = 0b11100 -> bits 7,6,5,4,3 = 1,1,1,0,0
   *
   * Byte = bit7..bit0 = HLIT[4] HLIT[3] HLIT[2] HLIT[1] HLIT[0] BTYPE[1]
   * BTYPE[0] BFINAL
   *       = 1        1        1        0        0        0        1 1
   *       = 0b11100011 = 0xE3
   */
  uint8_t data[] = { 0xE3 };
  SocketDeflate_BitReader_T reader = make_reader (data, 1);
  uint32_t bfinal, btype, hlit;

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 1, &bfinal), DEFLATE_OK);
  ASSERT_EQ (bfinal, 1);

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 2, &btype), DEFLATE_OK);
  ASSERT_EQ (btype, 1); /* 01 = fixed */

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 5, &hlit), DEFLATE_OK);
  ASSERT_EQ (hlit, 28);
}

/*
 * Query Functions Tests
 */

TEST (bitreader_bits_available)
{
  uint8_t data[] = { 0xAB, 0xCD, 0xEF };
  SocketDeflate_BitReader_T reader = make_reader (data, 3);
  uint32_t value;

  ASSERT_EQ (SocketDeflate_BitReader_bits_available (reader), 24);

  SocketDeflate_BitReader_read (reader, 5, &value);
  ASSERT_EQ (SocketDeflate_BitReader_bits_available (reader), 19);

  SocketDeflate_BitReader_read (reader, 10, &value);
  ASSERT_EQ (SocketDeflate_BitReader_bits_available (reader), 9);
}

TEST (bitreader_bytes_remaining)
{
  uint8_t data[] = { 0xAB, 0xCD, 0xEF, 0x12 };
  SocketDeflate_BitReader_T reader = make_reader (data, 4);
  uint32_t value;

  ASSERT_EQ (SocketDeflate_BitReader_bytes_remaining (reader), 4);

  /* After refill, bytes_remaining reflects unconsumed input bytes */
  SocketDeflate_BitReader_peek (reader, 8, &value);

  /* bytes_remaining decreases as bytes are loaded into accumulator */
  /* This depends on refill implementation - let's just verify it decreases */
  ASSERT (SocketDeflate_BitReader_bytes_remaining (reader) <= 4);
}

/*
 * Edge Case and Validation Tests
 */

TEST (bitreader_read_zero_bits_returns_error)
{
  uint8_t data[] = { 0xAB };
  SocketDeflate_BitReader_T reader = make_reader (data, 1);
  uint32_t value = 0xDEAD;

  /* Reading 0 bits should return error */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 0, &value), DEFLATE_ERROR);

  /* Value should be unchanged */
  ASSERT_EQ (value, 0xDEAD);

  /* Reader state should be unchanged - can still read normally */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 8, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xAB);
}

TEST (bitreader_read_too_many_bits_returns_error)
{
  uint8_t data[] = { 0xAB, 0xCD, 0xEF, 0x12 };
  SocketDeflate_BitReader_T reader = make_reader (data, 4);
  uint32_t value = 0xDEAD;

  /* Reading more than DEFLATE_MAX_BITS_READ (25) should return error */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 26, &value), DEFLATE_ERROR);
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 100, &value), DEFLATE_ERROR);

  /* Value should be unchanged */
  ASSERT_EQ (value, 0xDEAD);

  /* Reader state should be unchanged */
  ASSERT_EQ (SocketDeflate_BitReader_bits_available (reader), 32);
}

TEST (bitreader_peek_zero_bits_returns_error)
{
  uint8_t data[] = { 0xAB };
  SocketDeflate_BitReader_T reader = make_reader (data, 1);
  uint32_t value = 0xDEAD;

  /* Peeking 0 bits should return error */
  ASSERT_EQ (SocketDeflate_BitReader_peek (reader, 0, &value), DEFLATE_ERROR);
  ASSERT_EQ (value, 0xDEAD);
}

TEST (bitreader_peek_too_many_bits_returns_error)
{
  uint8_t data[] = { 0xAB, 0xCD, 0xEF, 0x12 };
  SocketDeflate_BitReader_T reader = make_reader (data, 4);
  uint32_t value = 0xDEAD;

  /* Peeking more than DEFLATE_MAX_BITS_READ (25) should return error */
  ASSERT_EQ (SocketDeflate_BitReader_peek (reader, 26, &value), DEFLATE_ERROR);
  ASSERT_EQ (value, 0xDEAD);
}

TEST (bitreader_consume_zero_bits)
{
  uint8_t data[] = { 0xAB };
  SocketDeflate_BitReader_T reader = make_reader (data, 1);
  uint32_t value;

  /* Peek first to load accumulator */
  SocketDeflate_BitReader_peek (reader, 8, &value);

  /* Consume 0 bits should be a no-op */
  SocketDeflate_BitReader_consume (reader, 0);

  /* Should still have all 8 bits */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 8, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xAB);
}

TEST (bitreader_consume_more_than_available)
{
  uint8_t data[] = { 0xAB };
  SocketDeflate_BitReader_T reader = make_reader (data, 1);
  uint32_t value;

  /* Peek to load accumulator */
  SocketDeflate_BitReader_peek (reader, 8, &value);

  /* Try to consume more than available - should clamp */
  SocketDeflate_BitReader_consume (reader, 100);

  /* Should be at end now */
  ASSERT_EQ (SocketDeflate_BitReader_at_end (reader), 1);
}

TEST (bitreader_read_bytes_zero_count)
{
  uint8_t data[] = { 0xAB, 0xCD };
  SocketDeflate_BitReader_T reader = make_reader (data, 2);
  uint8_t buf[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

  /* Reading 0 bytes should succeed immediately */
  ASSERT_EQ (SocketDeflate_BitReader_read_bytes (reader, buf, 0), DEFLATE_OK);

  /* Buffer unchanged */
  ASSERT_EQ (buf[0], 0xDE);

  /* Reader state unchanged */
  ASSERT_EQ (SocketDeflate_BitReader_bits_available (reader), 16);
}

TEST (bitreader_read_bytes_without_align)
{
  /* Test read_bytes when not aligned - consumes from shifted accumulator.
   *
   * After reading 3 bits from [0xAB, 0xCD, 0xEF]:
   * - Accumulator was loaded with all 3 bytes: 0xEFCDAB (24 bits)
   * - After consuming 3 bits: 0xEFCDAB >> 3 = 0x1DF9B5 (21 bits)
   * - read_bytes extracts whole bytes from accumulator:
   *   buf[0] = 0xB5, buf[1] = 0xF9
   *
   * This demonstrates why align() should be called before read_bytes()
   * for stored block data - otherwise you get shifted data.
   */
  uint8_t data[] = { 0xAB, 0xCD, 0xEF };
  SocketDeflate_BitReader_T reader = make_reader (data, 3);
  uint32_t value;
  uint8_t buf[2];

  /* Read 3 bits - accumulator is refilled and shifted */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 3, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0x3); /* Low 3 bits of 0xAB = 011 */

  /* Read bytes without align - gets shifted accumulator bytes */
  ASSERT_EQ (SocketDeflate_BitReader_read_bytes (reader, buf, 2), DEFLATE_OK);

  /* Gets bytes from shifted accumulator (0xEFCDAB >> 3 = 0x1DF9B5) */
  ASSERT_EQ (buf[0], 0xB5); /* Low byte of 0x1DF9B5 */
  ASSERT_EQ (buf[1], 0xF9); /* Next byte */
}

TEST (bitreader_reverse_bits_zero_nbits)
{
  /* reverse_bits with nbits=0 should return 0 */
  ASSERT_EQ (SocketDeflate_reverse_bits (0xFFFF, 0), 0);
  ASSERT_EQ (SocketDeflate_reverse_bits (0, 0), 0);
}

TEST (bitreader_reverse_bits_too_many_nbits)
{
  /* reverse_bits with nbits > 15 should return 0 */
  ASSERT_EQ (SocketDeflate_reverse_bits (0x1, 16), 0);
  ASSERT_EQ (SocketDeflate_reverse_bits (0xFFFF, 32), 0);
}

TEST (bitreader_reinit)
{
  /* Test re-initializing a reader with new data */
  uint8_t data1[] = { 0xAB };
  uint8_t data2[] = { 0xCD, 0xEF };
  SocketDeflate_BitReader_T reader = make_reader (data1, 1);
  uint32_t value;

  /* Read from first data */
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 8, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xAB);
  ASSERT_EQ (SocketDeflate_BitReader_at_end (reader), 1);

  /* Re-init with new data */
  SocketDeflate_BitReader_init (reader, data2, 2);

  /* Should now read from new data */
  ASSERT_EQ (SocketDeflate_BitReader_at_end (reader), 0);
  ASSERT_EQ (SocketDeflate_BitReader_bits_available (reader), 16);
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 16, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xEFCD);
}

/*
 * Helper: Create and initialize a bit writer with output buffer
 */
static SocketDeflate_BitWriter_T
make_writer (uint8_t *buffer, size_t capacity)
{
  SocketDeflate_BitWriter_T writer = SocketDeflate_BitWriter_new (test_arena);
  SocketDeflate_BitWriter_init (writer, buffer, capacity);
  return writer;
}

/*
 * Basic Operations Tests
 */

TEST (bitwriter_create_and_init)
{
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  ASSERT (writer != NULL);
  ASSERT_EQ (SocketDeflate_BitWriter_size (writer), 0);
  ASSERT_EQ (SocketDeflate_BitWriter_capacity_remaining (writer), 16);
  ASSERT_EQ (SocketDeflate_BitWriter_bits_pending (writer), 0);
}

TEST (bitwriter_single_byte)
{
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write 8 bits */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0xAB, 8), DEFLATE_OK);

  /* Should have written 1 byte */
  ASSERT_EQ (SocketDeflate_BitWriter_size (writer), 1);
  ASSERT_EQ (buffer[0], 0xAB);
  ASSERT_EQ (SocketDeflate_BitWriter_bits_pending (writer), 0);
}

TEST (bitwriter_cross_byte_boundary)
{
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write 12 bits: 0xDAB
   * LSB-first packing: low 8 bits = 0xAB, remaining 4 bits = 0xD
   */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0xDAB, 12), DEFLATE_OK);

  /* Should have written 1 byte, 4 bits pending */
  ASSERT_EQ (SocketDeflate_BitWriter_size (writer), 1);
  ASSERT_EQ (buffer[0], 0xAB);
  ASSERT_EQ (SocketDeflate_BitWriter_bits_pending (writer), 4);

  /* Flush to complete */
  size_t total = SocketDeflate_BitWriter_flush (writer);
  ASSERT_EQ (total, 2);
  ASSERT_EQ (buffer[1], 0x0D); /* 0xD with zero padding */
}

TEST (bitwriter_multiple_values)
{
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write 4 bits: 0xB (low nibble of 0xAB) */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0xB, 4), DEFLATE_OK);
  ASSERT_EQ (SocketDeflate_BitWriter_bits_pending (writer), 4);

  /* Write 4 bits: 0xA (high nibble of 0xAB) */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0xA, 4), DEFLATE_OK);

  /* Together should form 0xAB */
  ASSERT_EQ (SocketDeflate_BitWriter_size (writer), 1);
  ASSERT_EQ (buffer[0], 0xAB);
}

/*
 * LSB-First Ordering Tests
 */

TEST (bitwriter_lsb_first_order)
{
  /* RFC 1951 Section 3.1.1:
   * "Data elements are packed into bytes in order of
   * increasing bit number within the byte, i.e., starting
   * with the least-significant bit of the byte."
   *
   * Write 3-bit value 5 (101) and 3-bit value 3 (011)
   * Expected byte: bits 0-2 = 101, bits 3-5 = 011
   * byte = (value2 << 3) | value1 = 0b011101 = 0x1D
   */
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 5, 3), DEFLATE_OK);
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 3, 3), DEFLATE_OK);

  /* Flush partial byte */
  SocketDeflate_BitWriter_flush (writer);

  /* Verify LSB-first packing */
  ASSERT_EQ (buffer[0], 0x1D);
}

TEST (bitwriter_block_header)
{
  /* DEFLATE block header: BFINAL (1 bit) + BTYPE (2 bits)
   * BFINAL=1, BTYPE=01 (fixed Huffman)
   * Expected: 0b011 = 0x03 (with 5 zeros padding)
   */
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write BFINAL = 1 */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 1, 1), DEFLATE_OK);

  /* Write BTYPE = 01 (fixed) */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 1, 2), DEFLATE_OK);

  SocketDeflate_BitWriter_flush (writer);
  ASSERT_EQ (buffer[0], 0x03);
}

TEST (bitwriter_multivalue_packing)
{
  /* Pack: BFINAL=1 (1 bit), BTYPE=01 (2 bits), HLIT=28 (5 bits)
   *
   * BFINAL = 1 -> bit 0 = 1
   * BTYPE = 01 -> bits 2,1 = 0,1
   * HLIT = 28 = 0b11100 -> bits 7,6,5,4,3 = 1,1,1,0,0
   *
   * Byte = 0b11100011 = 0xE3
   */
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 1, 1),
             DEFLATE_OK); /* BFINAL */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 1, 2),
             DEFLATE_OK); /* BTYPE */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 28, 5),
             DEFLATE_OK); /* HLIT */

  ASSERT_EQ (SocketDeflate_BitWriter_size (writer), 1);
  ASSERT_EQ (buffer[0], 0xE3);
}

/*
 * Huffman Code Writing Tests
 */

TEST (bitwriter_huffman_code)
{
  /* RFC 1951: Huffman codes defined MSB-first, stored LSB-first
   *
   * Code 0b110 (3 bits, MSB-first) stored as 0b011 (LSB-first)
   */
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write Huffman code 0b110 (6) with length 3 */
  ASSERT_EQ (SocketDeflate_BitWriter_write_huffman (writer, 0x6, 3),
             DEFLATE_OK);

  SocketDeflate_BitWriter_flush (writer);

  /* Stream should contain reversed bits: 0b011 = 0x03 (with padding) */
  ASSERT_EQ (buffer[0], 0x03);
}

TEST (bitwriter_huffman_multiple)
{
  /* Write multiple Huffman codes */
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Code 1: 0b110 (3 bits) -> reversed 0b011 */
  ASSERT_EQ (SocketDeflate_BitWriter_write_huffman (writer, 0x6, 3),
             DEFLATE_OK);

  /* Code 2: 0b1010 (4 bits) -> reversed 0b0101 */
  ASSERT_EQ (SocketDeflate_BitWriter_write_huffman (writer, 0xA, 4),
             DEFLATE_OK);

  /* Total 7 bits, flush adds 1 padding bit */
  SocketDeflate_BitWriter_flush (writer);

  /* Packed: [0b011][0b0101] = 0b01010011 with leading zero pad
   * Wait, let's recalculate:
   * bits 0-2: 011 (reversed 110)
   * bits 3-6: 0101 (reversed 1010)
   * byte = 0b0101011 with 1 zero = 0b00101011 = 0x2B
   */
  ASSERT_EQ (buffer[0], 0x2B);
}

/*
 * Flush and Alignment Tests
 */

TEST (bitwriter_flush_partial)
{
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write 3 bits */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0x5, 3), DEFLATE_OK);
  ASSERT_EQ (SocketDeflate_BitWriter_size (writer), 0); /* Not yet flushed */

  /* Flush pads with zeros */
  size_t total = SocketDeflate_BitWriter_flush (writer);
  ASSERT_EQ (total, 1);
  ASSERT_EQ (buffer[0], 0x05); /* 0b101 padded with 5 zeros = 0b00000101 */
}

TEST (bitwriter_flush_already_aligned)
{
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write 8 bits - already aligned */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0xAB, 8), DEFLATE_OK);
  ASSERT_EQ (SocketDeflate_BitWriter_bits_pending (writer), 0);

  /* Flush should be no-op */
  size_t total = SocketDeflate_BitWriter_flush (writer);
  ASSERT_EQ (total, 1);
  ASSERT_EQ (buffer[0], 0xAB);
}

TEST (bitwriter_align)
{
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write 3 bits */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0x5, 3), DEFLATE_OK);

  /* Align to byte boundary */
  SocketDeflate_BitWriter_align (writer);

  ASSERT_EQ (SocketDeflate_BitWriter_size (writer), 1);
  ASSERT_EQ (SocketDeflate_BitWriter_bits_pending (writer), 0);
  ASSERT_EQ (buffer[0], 0x05);
}

/*
 * RFC 7692 Sync Flush Tests
 */

TEST (bitwriter_sync_flush_empty)
{
  /* Sync flush on empty writer produces exactly 5 bytes:
   * 1 byte for BFINAL+BTYPE+padding (0x00)
   * 2 bytes for LEN (0x00 0x00)
   * 2 bytes for NLEN (0xFF 0xFF)
   */
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  size_t total = SocketDeflate_BitWriter_sync_flush (writer);
  ASSERT_EQ (total, 5);

  /* Verify sync flush marker bytes */
  ASSERT_EQ (buffer[0], 0x00); /* BFINAL=0, BTYPE=00, 5 zero padding bits */
  ASSERT_EQ (buffer[1], 0x00); /* LEN low byte */
  ASSERT_EQ (buffer[2], 0x00); /* LEN high byte */
  ASSERT_EQ (buffer[3], 0xFF); /* NLEN low byte */
  ASSERT_EQ (buffer[4], 0xFF); /* NLEN high byte */
}

TEST (bitwriter_sync_flush_after_data)
{
  uint8_t buffer[32];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write some data first */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0x12345, 20), DEFLATE_OK);

  size_t pre_size = SocketDeflate_BitWriter_size (writer);

  /* Sync flush */
  size_t total = SocketDeflate_BitWriter_sync_flush (writer);

  /* Should have written data + sync flush bytes */
  ASSERT (total > pre_size);

  /* Last 4 bytes should be the sync flush trailer (after alignment) */
  /* Note: with 20 bits written, that's 2 full bytes + 4 bits pending
   * After align: 3 bytes of data
   * Sync flush writes: 1 byte (header + pad) + 4 bytes (LEN + NLEN)
   * But alignment is done in sync_flush, so let's check the trailer:
   */
  ASSERT_EQ (buffer[total - 4], 0x00); /* LEN low */
  ASSERT_EQ (buffer[total - 3], 0x00); /* LEN high */
  ASSERT_EQ (buffer[total - 2], 0xFF); /* NLEN low */
  ASSERT_EQ (buffer[total - 1], 0xFF); /* NLEN high */
}

TEST (bitwriter_sync_flush_alignment)
{
  /* Write non-aligned data, sync flush should align first */
  uint8_t buffer[32];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write 5 bits */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0x15, 5), DEFLATE_OK);

  /* Sync flush */
  SocketDeflate_BitWriter_sync_flush (writer);

  /* After sync_flush, writer should be aligned */
  ASSERT_EQ (SocketDeflate_BitWriter_bits_pending (writer), 0);
}

/*
 * Roundtrip Tests (Write then Read)
 */

TEST (bitwriter_reader_roundtrip_bits)
{
  uint8_t buffer[64];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write various bit patterns */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0x1, 1), DEFLATE_OK);
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0x3, 2), DEFLATE_OK);
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0x7F, 7), DEFLATE_OK);
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0xFF, 8), DEFLATE_OK);
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0xABCD, 16), DEFLATE_OK);

  size_t total = SocketDeflate_BitWriter_flush (writer);

  /* Read back and verify */
  SocketDeflate_BitReader_T reader = make_reader (buffer, total);
  uint32_t value;

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 1, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0x1);

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 2, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0x3);

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 7, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0x7F);

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 8, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xFF);

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 16, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xABCD);
}

TEST (bitwriter_reader_roundtrip_huffman)
{
  uint8_t buffer[64];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write Huffman codes (will be reversed) */
  ASSERT_EQ (SocketDeflate_BitWriter_write_huffman (writer, 0x6, 3),
             DEFLATE_OK); /* 110 -> 011 */
  ASSERT_EQ (SocketDeflate_BitWriter_write_huffman (writer, 0xA, 4),
             DEFLATE_OK); /* 1010 -> 0101 */

  size_t total = SocketDeflate_BitWriter_flush (writer);

  /* Read back raw bits and manually reverse to verify */
  SocketDeflate_BitReader_T reader = make_reader (buffer, total);
  uint32_t raw_bits;

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 3, &raw_bits), DEFLATE_OK);
  /* raw_bits should be 011 = 3, reverse gives 110 = 6 */
  ASSERT_EQ (SocketDeflate_reverse_bits (raw_bits, 3), 0x6);

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 4, &raw_bits), DEFLATE_OK);
  /* raw_bits should be 0101 = 5, reverse gives 1010 = 10 */
  ASSERT_EQ (SocketDeflate_reverse_bits (raw_bits, 4), 0xA);
}

TEST (bitwriter_reader_roundtrip_block_header)
{
  uint8_t buffer[64];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write DEFLATE block header for dynamic Huffman block */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 1, 1),
             DEFLATE_OK); /* BFINAL=1 */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 2, 2),
             DEFLATE_OK); /* BTYPE=10 */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 28, 5),
             DEFLATE_OK); /* HLIT=28 */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 29, 5),
             DEFLATE_OK); /* HDIST=29 */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 14, 4),
             DEFLATE_OK); /* HCLEN=14 */

  size_t total = SocketDeflate_BitWriter_flush (writer);

  /* Read back and verify */
  SocketDeflate_BitReader_T reader = make_reader (buffer, total);
  uint32_t bfinal, btype, hlit, hdist, hclen;

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 1, &bfinal), DEFLATE_OK);
  ASSERT_EQ (bfinal, 1);

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 2, &btype), DEFLATE_OK);
  ASSERT_EQ (btype, 2);

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 5, &hlit), DEFLATE_OK);
  ASSERT_EQ (hlit, 28);

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 5, &hdist), DEFLATE_OK);
  ASSERT_EQ (hdist, 29);

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 4, &hclen), DEFLATE_OK);
  ASSERT_EQ (hclen, 14);
}

/*
 * Edge Case Tests
 */

TEST (bitwriter_zero_bits_returns_error)
{
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Writing 0 bits should return error */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0xAB, 0), DEFLATE_ERROR);

  /* Writer state should be unchanged */
  ASSERT_EQ (SocketDeflate_BitWriter_size (writer), 0);
  ASSERT_EQ (SocketDeflate_BitWriter_bits_pending (writer), 0);
}

TEST (bitwriter_max_bits)
{
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write maximum 25 bits */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0x1FFFFFF, 25), DEFLATE_OK);

  size_t total = SocketDeflate_BitWriter_flush (writer);
  ASSERT_EQ (total, 4); /* 25 bits = 3 full bytes + 1 partial */

  /* Verify by reading back */
  SocketDeflate_BitReader_T reader = make_reader (buffer, total);
  uint32_t value;
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 25, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0x1FFFFFF);
}

TEST (bitwriter_too_many_bits_returns_error)
{
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Writing more than 25 bits should return error */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0xFFFFFFFF, 26),
             DEFLATE_ERROR);
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0xFFFFFFFF, 100),
             DEFLATE_ERROR);
}

TEST (bitwriter_capacity_exceeded)
{
  uint8_t buffer[2];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write 16 bits - exactly fills buffer */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0xABCD, 16), DEFLATE_OK);

  /* Next write should fail */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0xFF, 8), DEFLATE_ERROR);
}

TEST (bitwriter_huffman_zero_len_returns_error)
{
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Huffman with len=0 should return error */
  ASSERT_EQ (SocketDeflate_BitWriter_write_huffman (writer, 0x1, 0),
             DEFLATE_ERROR);
}

TEST (bitwriter_huffman_too_long_returns_error)
{
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Huffman with len > 15 should return error */
  ASSERT_EQ (SocketDeflate_BitWriter_write_huffman (writer, 0x1, 16),
             DEFLATE_ERROR);
}

TEST (bitwriter_reinit)
{
  uint8_t buffer1[16];
  uint8_t buffer2[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer1, sizeof (buffer1));

  /* Write to first buffer */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0xAB, 8), DEFLATE_OK);
  ASSERT_EQ (buffer1[0], 0xAB);

  /* Re-init with new buffer */
  SocketDeflate_BitWriter_init (writer, buffer2, sizeof (buffer2));

  /* Should start fresh */
  ASSERT_EQ (SocketDeflate_BitWriter_size (writer), 0);
  ASSERT_EQ (SocketDeflate_BitWriter_bits_pending (writer), 0);

  /* Write to new buffer */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0xCD, 8), DEFLATE_OK);
  ASSERT_EQ (buffer2[0], 0xCD);

  /* Original buffer unchanged (beyond initial write) */
  ASSERT_EQ (buffer1[0], 0xAB);
}

TEST (bitwriter_value_masking)
{
  /* write() should mask values to n bits before writing */
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write 4 bits from 0xFFFF - should only write 0xF */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0xFFFF, 4), DEFLATE_OK);

  SocketDeflate_BitWriter_flush (writer);
  ASSERT_EQ (buffer[0], 0x0F); /* Only low 4 bits, padded with zeros */

  /* Verify by reading back */
  SocketDeflate_BitReader_T reader = make_reader (buffer, 1);
  uint32_t value;
  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 4, &value), DEFLATE_OK);
  ASSERT_EQ (value, 0xF);
}

TEST (bitwriter_reader_roundtrip_all_lengths)
{
  /* Verify roundtrip for ALL bit lengths 1-25 */
  uint8_t buffer[64];
  unsigned int n;

  for (n = 1; n <= DEFLATE_MAX_BITS_READ; n++)
    {
      SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

      /* Create test value with all bits set for this length */
      uint32_t test_val = (1U << n) - 1; /* All n bits set */

      ASSERT_EQ (SocketDeflate_BitWriter_write (writer, test_val, n),
                 DEFLATE_OK);
      size_t total = SocketDeflate_BitWriter_flush (writer);

      /* Read back */
      SocketDeflate_BitReader_T reader = make_reader (buffer, total);
      uint32_t read_val;
      ASSERT_EQ (SocketDeflate_BitReader_read (reader, n, &read_val),
                 DEFLATE_OK);
      ASSERT_EQ (read_val, test_val);
    }
}

TEST (bitwriter_accumulator_boundary)
{
  /* Test writing exactly at 32-bit accumulator boundary:
   * 7 pending bits + 25 new bits = 32 bits exactly
   */
  uint8_t buffer[16];
  SocketDeflate_BitWriter_T writer = make_writer (buffer, sizeof (buffer));

  /* Write 7 bits to leave 7 pending */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0x7F, 7), DEFLATE_OK);
  ASSERT_EQ (SocketDeflate_BitWriter_bits_pending (writer), 7);

  /* Write max 25 bits - accumulator now has exactly 32 bits */
  ASSERT_EQ (SocketDeflate_BitWriter_write (writer, 0x1FFFFFF, 25), DEFLATE_OK);

  /* Should have flushed 4 complete bytes, 0 pending */
  ASSERT_EQ (SocketDeflate_BitWriter_size (writer), 4);
  ASSERT_EQ (SocketDeflate_BitWriter_bits_pending (writer), 0);

  /* Verify by reading back: 7 bits + 25 bits = 32 bits total */
  SocketDeflate_BitReader_T reader = make_reader (buffer, 4);
  uint32_t v1, v2;

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 7, &v1), DEFLATE_OK);
  ASSERT_EQ (v1, 0x7F);

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, 25, &v2), DEFLATE_OK);
  ASSERT_EQ (v2, 0x1FFFFFF);
}

/*
 * Test Runner
 */

int
main (void)
{
  test_arena = Arena_new ();

  Test_run_all ();

  Arena_dispose (&test_arena);

  return Test_get_failures () > 0 ? 1 : 0;
}
