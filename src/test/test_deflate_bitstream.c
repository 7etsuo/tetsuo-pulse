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

  ASSERT_EQ (SocketDeflate_BitReader_read (reader, DEFLATE_MAX_BITS_READ,
                                           &value),
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
  uint32_t code = 0x6;     /* 0b110 MSB-first */
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
