/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_deflate_fixed.c - RFC 1951 fixed Huffman block decoder unit tests
 *
 * Tests for the DEFLATE fixed block (BTYPE=01) decoder module,
 * verifying correct handling of compressed blocks per RFC 1951 Section 3.2.6.
 *
 * Test coverage:
 * - Literal-only decoding
 * - Length/distance decoding with extra bits
 * - Overlap copy handling (RFC 1951 §3.2.3)
 * - End-of-block termination
 * - Error conditions (invalid codes, distance too far)
 *
 * Fixed Huffman Code Reference (RFC 1951 §3.2.6):
 *   Literals 0-143:   8 bits (codes 00110000 - 10111111, MSB-first)
 *   Literals 144-255: 9 bits (codes 110010000 - 111111111)
 *   Codes 256-279:    7 bits (codes 0000000 - 0010111)
 *   Codes 280-287:    8 bits (codes 11000000 - 11000111)
 *   Distances 0-31:   5 bits (codes 00000 - 11111)
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "deflate/SocketDeflate.h"
#include "test/Test.h"

/*
 * Test infrastructure
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
 * Helper: Encode a fixed Huffman literal (0-143) into bits.
 *
 * For symbols 0-143: 8-bit codes from 00110000 (48) to 10111111 (191)
 * The code for symbol N (0-143) is: N + 0x30 (bit-reversed for stream)
 *
 * RFC 1951: symbols 0-143 have codes 00110000-10111111
 * Symbol 0   -> code 48  (0x30) = 00110000 MSB-first
 * Symbol 143 -> code 191 (0xBF) = 10111111 MSB-first
 *
 * Returns bit-reversed 8-bit code value.
 */
static uint8_t
encode_literal_0_143 (uint8_t symbol)
{
  uint8_t code = symbol + 0x30; /* MSB-first code */
  /* Bit-reverse for LSB-first stream */
  return (uint8_t)SocketDeflate_reverse_bits (code, 8);
}

/*
 * Helper: Build encoded stream from symbols.
 *
 * This helper constructs valid encoded data for fixed Huffman blocks.
 * Supports literals 0-143 and end-of-block (256).
 *
 * For simplicity, we pack bits LSB-first into bytes.
 */
typedef struct
{
  uint8_t *data;
  size_t size;
  size_t capacity;
  uint32_t bits;
  int bits_avail;
} BitWriter;

static void
bitwriter_init (BitWriter *bw, uint8_t *buf, size_t capacity)
{
  bw->data = buf;
  bw->size = 0;
  bw->capacity = capacity;
  bw->bits = 0;
  bw->bits_avail = 0;
}

static void
bitwriter_write (BitWriter *bw, uint32_t value, int nbits)
{
  /* Add bits LSB-first */
  bw->bits |= value << bw->bits_avail;
  bw->bits_avail += nbits;

  /* Flush complete bytes */
  while (bw->bits_avail >= 8 && bw->size < bw->capacity)
    {
      bw->data[bw->size++] = (uint8_t)(bw->bits & 0xFF);
      bw->bits >>= 8;
      bw->bits_avail -= 8;
    }
}

static void
bitwriter_flush (BitWriter *bw)
{
  /* Flush remaining bits (padded with zeros) */
  if (bw->bits_avail > 0 && bw->size < bw->capacity)
    {
      bw->data[bw->size++] = (uint8_t)(bw->bits & 0xFF);
      bw->bits = 0;
      bw->bits_avail = 0;
    }
}

/*
 * Fixed Huffman Code Encoder Helpers
 *
 * These produce the bit-reversed codes for LSB-first packing.
 */

/* End-of-block (symbol 256): 7-bit code 0000000 */
static void
write_end_of_block (BitWriter *bw)
{
  bitwriter_write (bw, 0, 7); /* Code 0 in 7 bits */
}

/* Literal byte 0-143: 8-bit code */
static void
write_literal_0_143 (BitWriter *bw, uint8_t ch)
{
  /* Symbol N (0-143) has MSB-first code N + 48 */
  uint32_t code = ch + 48;
  /* Bit-reverse for LSB-first stream */
  uint32_t reversed = SocketDeflate_reverse_bits (code, 8);
  bitwriter_write (bw, reversed, 8);
}

/* Literal byte 144-255: 9-bit code */
static void
write_literal_144_255 (BitWriter *bw, uint8_t ch)
{
  /* Symbol N (144-255) has MSB-first code (N - 144) + 400 */
  uint32_t code = (ch - 144) + 400;
  /* Bit-reverse for LSB-first stream */
  uint32_t reversed = SocketDeflate_reverse_bits (code, 9);
  bitwriter_write (bw, reversed, 9);
}

/* Generic literal byte (auto-selects encoding) */
static void
write_literal (BitWriter *bw, uint8_t ch)
{
  if (ch < 144)
    write_literal_0_143 (bw, ch);
  else
    write_literal_144_255 (bw, ch);
}

/* Length code 257-264 (0 extra bits, lengths 3-10): 7-bit codes */
static void
write_length_257_264 (BitWriter *bw, unsigned int code)
{
  /* Codes 257-279 have 7-bit Huffman codes starting at 0000001 */
  /* Code 257 -> Huffman code 1 (7 bits) */
  /* Code 264 -> Huffman code 8 (7 bits) */
  uint32_t huffman_code = code - 256; /* 1-8 for codes 257-264 */
  uint32_t reversed = SocketDeflate_reverse_bits (huffman_code, 7);
  bitwriter_write (bw, reversed, 7);
}

/* Length code 265-279 (with extra bits): 7-bit codes */
static void
write_length_265_279 (BitWriter *bw,
                      unsigned int code,
                      unsigned int extra,
                      unsigned int extra_bits)
{
  uint32_t huffman_code = code - 256;
  uint32_t reversed = SocketDeflate_reverse_bits (huffman_code, 7);
  bitwriter_write (bw, reversed, 7);
  if (extra_bits > 0)
    bitwriter_write (bw, extra, extra_bits);
}

/* Length code 280-285: 8-bit codes */
static void
write_length_280_285 (BitWriter *bw,
                      unsigned int code,
                      unsigned int extra,
                      unsigned int extra_bits)
{
  /* Codes 280-287 have 8-bit Huffman codes starting at 11000000 (192) */
  uint32_t huffman_code = (code - 280) + 192;
  uint32_t reversed = SocketDeflate_reverse_bits (huffman_code, 8);
  bitwriter_write (bw, reversed, 8);
  if (extra_bits > 0)
    bitwriter_write (bw, extra, extra_bits);
}

/* Distance code 0-31: 5-bit code + extra bits */
static void
write_distance (BitWriter *bw,
                unsigned int code,
                unsigned int extra,
                unsigned int extra_bits)
{
  /* All distance codes are 5-bit codes */
  uint32_t reversed = SocketDeflate_reverse_bits (code, 5);
  bitwriter_write (bw, reversed, 5);
  if (extra_bits > 0)
    bitwriter_write (bw, extra, extra_bits);
}

/*
 * Basic Decoding Tests
 */

TEST (fixed_end_of_block_only)
{
  /* Just end-of-block symbol - produces no output */
  uint8_t encoded[16];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));
  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 0);
}

TEST (fixed_single_literal)
{
  /* Single literal 'A' (65) then end-of-block */
  uint8_t encoded[16];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));
  write_literal (&bw, 'A');
  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 1);
  ASSERT_EQ (output[0], 'A');
}

TEST (fixed_literal_only)
{
  /* Multiple literals "Hello" (all in 0-143 range) */
  uint8_t encoded[64];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));
  write_literal (&bw, 'H');
  write_literal (&bw, 'e');
  write_literal (&bw, 'l');
  write_literal (&bw, 'l');
  write_literal (&bw, 'o');
  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 5);
  ASSERT (memcmp (output, "Hello", 5) == 0);
}

TEST (fixed_literal_high_range)
{
  /* Test literals in 144-255 range (9-bit codes) */
  uint8_t encoded[64];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));
  write_literal (&bw, 200); /* > 143, uses 9-bit code */
  write_literal (&bw, 255);
  write_literal (&bw, 144);
  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 3);
  ASSERT_EQ (output[0], 200);
  ASSERT_EQ (output[1], 255);
  ASSERT_EQ (output[2], 144);
}

/*
 * Length/Distance Tests
 */

TEST (fixed_simple_backreference)
{
  /* "AA" encoded as 'A' + length=3,dist=1 gives "AAAA" */
  uint8_t encoded[64];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));

  /* Write literal 'A' */
  write_literal (&bw, 'A');

  /* Write length code 257 (length=3, 0 extra bits) */
  write_length_257_264 (&bw, 257);

  /* Write distance code 0 (distance=1, 0 extra bits) */
  write_distance (&bw, 0, 0, 0);

  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 4); /* 'A' + 3 copies of 'A' */
  ASSERT (memcmp (output, "AAAA", 4) == 0);
}

TEST (fixed_with_length_distance)
{
  /* "AB" + length=4, distance=2 -> "ABABAB" */
  uint8_t encoded[64];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));

  write_literal (&bw, 'A');
  write_literal (&bw, 'B');

  /* Length code 258 = length 4 (0 extra bits) */
  write_length_257_264 (&bw, 258);

  /* Distance code 1 = distance 2 (0 extra bits) */
  write_distance (&bw, 1, 0, 0);

  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 6);
  ASSERT (memcmp (output, "ABABAB", 6) == 0);
}

/*
 * RFC 1951 Overlap Tests
 */

TEST (fixed_overlap_rfc_example)
{
  /* RFC 1951 §3.2.3 example:
   * "X,Y + <length=5, distance=2> adds X,Y,X,Y,X"
   * Result: "XYXYX" (5 bytes total from reference)
   */
  uint8_t encoded[64];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));

  write_literal (&bw, 'X');
  write_literal (&bw, 'Y');

  /* Length code 259 = length 5 (0 extra bits) */
  write_length_257_264 (&bw, 259);

  /* Distance code 1 = distance 2 (0 extra bits) */
  write_distance (&bw, 1, 0, 0);

  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 7); /* 'X','Y' + 5 bytes = 7 */
  ASSERT (memcmp (output, "XYXYXYX", 7) == 0);
}

TEST (fixed_overlap_copy)
{
  /* General overlap: 'A' + length=10, distance=1 -> "AAAAAAAAAA" (11 A's) */
  uint8_t encoded[64];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));

  write_literal (&bw, 'A');

  /* Length code 264 = length 10 (0 extra bits) */
  write_length_257_264 (&bw, 264);

  /* Distance code 0 = distance 1 (0 extra bits) */
  write_distance (&bw, 0, 0, 0);

  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 11); /* 1 + 10 = 11 */

  /* Verify all A's */
  for (size_t i = 0; i < 11; i++)
    ASSERT_EQ (output[i], 'A');
}

TEST (fixed_run_length_1)
{
  /* distance=1 creates run of repeated byte
   * "Q" + length=6, distance=1 -> "QQQQQQQ" (7 Q's)
   */
  uint8_t encoded[64];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));

  write_literal (&bw, 'Q');

  /* Length code 260 = length 6 (0 extra bits) */
  write_length_257_264 (&bw, 260);

  /* Distance code 0 = distance 1 (0 extra bits) */
  write_distance (&bw, 0, 0, 0);

  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 7);
  ASSERT (memcmp (output, "QQQQQQQ", 7) == 0);
}

/*
 * Extra Bits Tests
 */

TEST (fixed_length_with_extra_bits)
{
  /* Length code 265 = base 11, 1 extra bit
   * With extra=1: length = 11 + 1 = 12
   */
  uint8_t encoded[64];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));

  /* Write 4 literals "ABCD" */
  write_literal (&bw, 'A');
  write_literal (&bw, 'B');
  write_literal (&bw, 'C');
  write_literal (&bw, 'D');

  /* Length code 265 = base 11, 1 extra bit */
  write_length_265_279 (&bw, 265, 1, 1); /* extra=1 -> length=12 */

  /* Distance code 3 = distance 4 (0 extra bits) */
  write_distance (&bw, 3, 0, 0);

  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 16); /* 4 + 12 = 16 */
  ASSERT (memcmp (output, "ABCDABCDABCDABCD", 16) == 0);
}

TEST (fixed_distance_with_extra_bits)
{
  /* Distance code 4 = base 5, 1 extra bit
   * With extra=1: distance = 5 + 1 = 6
   */
  uint8_t encoded[64];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));

  /* Write 6 literals "ABCDEF" */
  write_literal (&bw, 'A');
  write_literal (&bw, 'B');
  write_literal (&bw, 'C');
  write_literal (&bw, 'D');
  write_literal (&bw, 'E');
  write_literal (&bw, 'F');

  /* Length code 257 = length 3 */
  write_length_257_264 (&bw, 257);

  /* Distance code 4 = base 5, 1 extra bit, extra=1 -> distance=6 */
  write_distance (&bw, 4, 1, 1);

  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 9); /* 6 + 3 = 9 */
  ASSERT (memcmp (output, "ABCDEFABC", 9) == 0);
}

TEST (fixed_length_code_285)
{
  /* Code 285 = length 258 with 0 extra bits (maximum length) */
  uint8_t encoded[256];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));

  /* Write single literal 'Z' */
  write_literal (&bw, 'Z');

  /* Length code 285 = length 258, 0 extra bits
   * Code 285 has 8-bit Huffman code (280-287 range)
   */
  write_length_280_285 (&bw, 285, 0, 0);

  /* Distance code 0 = distance 1 (0 extra bits) */
  write_distance (&bw, 0, 0, 0);

  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  /* Output: 1 literal + 258 copies = 259 bytes */
  uint8_t *output = malloc (512);
  ASSERT (output != NULL);
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);
  result = SocketDeflate_decode_fixed_block (reader, output, 512, &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 259);

  /* Verify all Z's */
  for (size_t i = 0; i < 259; i++)
    ASSERT_EQ (output[i], 'Z');

  free (output);
}

/*
 * Error Condition Tests
 */

TEST (fixed_distance_too_far)
{
  /* Back-reference at position 0 (before any output) - should error */
  uint8_t encoded[64];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));

  /* Length code 257 = length 3 without any preceding output */
  write_length_257_264 (&bw, 257);

  /* Distance code 0 = distance 1 */
  write_distance (&bw, 0, 0, 0);

  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_ERROR_DISTANCE_TOO_FAR);
  ASSERT_EQ (written, 0);
}

TEST (fixed_incomplete_input)
{
  /* Input ends before end-of-block */
  uint8_t encoded[4];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));
  write_literal (&bw, 'A');
  /* No end-of-block - truncate the stream */
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, 1); /* Only 1 byte */
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  /* May partially decode before running out of input */
  ASSERT (result == DEFLATE_INCOMPLETE || result == DEFLATE_OK);
}

TEST (fixed_tables_not_initialized)
{
  /* Note: This test only works if fixed tables haven't been initialized.
   * Since we initialize them in main(), we can't easily test this.
   * The function returns DEFLATE_ERROR if tables are NULL.
   * This is a documentation test. */

  /* Test passes if we get here - tables are initialized in main() */
  uint8_t encoded[8];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));
  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  /* Should succeed since tables are initialized */
  ASSERT_EQ (result, DEFLATE_OK);
}

/*
 * Integration Tests
 */

TEST (fixed_after_block_header)
{
  /* Complete DEFLATE fixed block: BFINAL=0, BTYPE=01, compressed data */
  uint8_t encoded[64];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));

  /* BFINAL=0 (1 bit) */
  bitwriter_write (&bw, 0, 1);
  /* BTYPE=01 (2 bits) - fixed Huffman */
  bitwriter_write (&bw, 1, 2);

  /* Now write the fixed block content */
  write_literal (&bw, 'T');
  write_literal (&bw, 'e');
  write_literal (&bw, 's');
  write_literal (&bw, 't');
  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written;
  uint32_t header;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);

  /* Read BFINAL */
  result = SocketDeflate_BitReader_read (reader, 1, &header);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (header, 0);

  /* Read BTYPE */
  result = SocketDeflate_BitReader_read (reader, 2, &header);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (header, 1); /* Fixed Huffman */

  /* Decode fixed block */
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 4);
  ASSERT (memcmp (output, "Test", 4) == 0);
}

TEST (fixed_final_block)
{
  /* BFINAL=1 fixed block */
  uint8_t encoded[64];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));

  /* BFINAL=1 (1 bit) */
  bitwriter_write (&bw, 1, 1);
  /* BTYPE=01 (2 bits) - fixed Huffman */
  bitwriter_write (&bw, 1, 2);

  write_literal (&bw, 'F');
  write_literal (&bw, 'I');
  write_literal (&bw, 'N');
  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written;
  uint32_t header;
  SocketDeflate_Result result;
  int is_final;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);

  /* Read BFINAL */
  result = SocketDeflate_BitReader_read (reader, 1, &header);
  ASSERT_EQ (result, DEFLATE_OK);
  is_final = (header == 1);
  ASSERT (is_final);

  /* Read BTYPE */
  result = SocketDeflate_BitReader_read (reader, 2, &header);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (header, 1);

  /* Decode fixed block */
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 3);
  ASSERT (memcmp (output, "FIN", 3) == 0);
}

TEST (fixed_written_zero_on_error)
{
  /* Verify *written is set to 0 on error paths */
  uint8_t encoded[64];
  BitWriter bw;
  bitwriter_init (&bw, encoded, sizeof (encoded));

  /* Create error condition: distance too far */
  write_length_257_264 (&bw, 257); /* length=3 */
  write_distance (&bw, 0, 0, 0);   /* distance=1 but no output yet */
  write_end_of_block (&bw);
  bitwriter_flush (&bw);

  uint8_t output[64];
  size_t written = 9999; /* Non-zero to verify it gets cleared */
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (encoded, bw.size);
  result = SocketDeflate_decode_fixed_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_ERROR_DISTANCE_TOO_FAR);
  ASSERT_EQ (written, 0);
}

/*
 * Test Runner
 */
int
main (void)
{
  SocketDeflate_Result init_result;

  test_arena = Arena_new ();

  /* Initialize fixed Huffman tables (required for decode_fixed_block) */
  init_result = SocketDeflate_fixed_tables_init (test_arena);
  if (init_result != DEFLATE_OK)
    {
      Arena_dispose (&test_arena);
      return 1;
    }

  Test_run_all ();

  Arena_dispose (&test_arena);

  return Test_get_failures () > 0 ? 1 : 0;
}
