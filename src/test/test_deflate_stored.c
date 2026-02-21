/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_deflate_stored.c - RFC 1951 stored block decoder unit tests
 *
 * Tests for the DEFLATE stored block (BTYPE=00) decoder module,
 * verifying correct handling of non-compressed blocks per RFC 1951
 * Section 3.2.4.
 *
 * Test coverage:
 * - Basic decoding (empty, small, medium, max blocks)
 * - NLEN validation (one's complement check)
 * - Byte alignment after partial reads
 * - Incomplete input handling
 * - Output buffer size validation
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
 * Basic Decoding Tests
 */

TEST (stored_decode_empty_block)
{
  /* Valid empty stored block:
   * LEN  = 0x0000 (stored as bytes 0x00, 0x00)
   * NLEN = 0xFFFF (stored as bytes 0xFF, 0xFF)
   * DATA = (none)
   */
  uint8_t input[] = { 0x00, 0x00, 0xFF, 0xFF };
  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (input, sizeof (input));
  result = SocketDeflate_decode_stored_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 0);
}

TEST (stored_decode_small_block)
{
  /* Valid small stored block:
   * LEN  = 5 (0x05, 0x00 in LSB-first)
   * NLEN = ~5 = 0xFFFA (0xFA, 0xFF)
   * DATA = "Hello"
   */
  uint8_t input[] = { 0x05, 0x00, 0xFA, 0xFF, 'H', 'e', 'l', 'l', 'o' };
  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (input, sizeof (input));
  result = SocketDeflate_decode_stored_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 5);
  ASSERT (memcmp (output, "Hello", 5) == 0);
}

TEST (stored_decode_medium_block)
{
  /* 1000-byte block */
  size_t len = 1000;
  uint16_t nlen = ~len;
  size_t total_size = 4 + len;
  uint8_t *input;
  uint8_t *output;
  size_t written;
  SocketDeflate_Result result;
  size_t i;

  input = malloc (total_size);
  ASSERT (input != NULL);
  input[0] = len & 0xFF;
  input[1] = (len >> 8) & 0xFF;
  input[2] = nlen & 0xFF;
  input[3] = (nlen >> 8) & 0xFF;

  /* Fill data with pattern */
  for (i = 0; i < len; i++)
    input[4 + i] = (uint8_t)(i & 0xFF);

  output = malloc (len + 64);
  ASSERT (output != NULL);

  SocketDeflate_BitReader_T reader = make_reader (input, total_size);
  result
      = SocketDeflate_decode_stored_block (reader, output, len + 64, &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 1000);

  /* Verify data */
  for (i = 0; i < len; i++)
    ASSERT_EQ (output[i], (uint8_t)(i & 0xFF));

  free (output);
  free (input);
}

TEST (stored_decode_max_block)
{
  /* Maximum block size: LEN = 65535 (0xFFFF), NLEN = 0x0000 */
  size_t len = 65535;
  size_t total_size = 4 + len;
  uint8_t *input;
  uint8_t *output;
  size_t written;
  SocketDeflate_Result result;
  size_t i;

  input = malloc (total_size);
  ASSERT (input != NULL);
  input[0] = 0xFF; /* LEN low */
  input[1] = 0xFF; /* LEN high */
  input[2] = 0x00; /* NLEN low */
  input[3] = 0x00; /* NLEN high */

  /* Fill data with pattern */
  for (i = 0; i < len; i++)
    input[4 + i] = (uint8_t)(i & 0xFF);

  output = malloc (len);
  ASSERT (output != NULL);

  SocketDeflate_BitReader_T reader = make_reader (input, total_size);
  result = SocketDeflate_decode_stored_block (reader, output, len, &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 65535);

  /* Verify content at boundaries to catch data corruption */
  for (i = 0; i < 256; i++)
    ASSERT_EQ (output[i], (uint8_t)(i & 0xFF));
  for (i = len - 256; i < len; i++)
    ASSERT_EQ (output[i], (uint8_t)(i & 0xFF));

  free (output);
  free (input);
}

/*
 * NLEN Validation Tests
 */

TEST (stored_invalid_nlen_zero)
{
  /* Invalid: LEN=5, NLEN=0 (should be 0xFFFA) */
  uint8_t input[] = { 0x05, 0x00, 0x00, 0x00, 'H', 'e', 'l', 'l', 'o' };
  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (input, sizeof (input));
  result = SocketDeflate_decode_stored_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_ERROR);
}

TEST (stored_invalid_nlen_random)
{
  /* Invalid: LEN=100, NLEN=0x1234 (random wrong value) */
  uint8_t input[] = { 0x64, 0x00, 0x34, 0x12 };
  uint8_t output[256];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (input, sizeof (input));
  result = SocketDeflate_decode_stored_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_ERROR);
}

TEST (stored_nlen_boundary_max_len)
{
  /* Valid boundary: LEN=0xFFFF, NLEN=0x0000 */
  uint8_t input[] = { 0xFF, 0xFF, 0x00, 0x00 };
  uint8_t *output;
  size_t written;
  SocketDeflate_Result result;

  /* We don't have 65535 bytes of data, so this will fail with INCOMPLETE */
  output = malloc (65535);
  ASSERT (output != NULL);

  SocketDeflate_BitReader_T reader = make_reader (input, sizeof (input));
  result = SocketDeflate_decode_stored_block (reader, output, 65535, &written);

  /* Validation passes but data read fails */
  ASSERT_EQ (result, DEFLATE_INCOMPLETE);

  free (output);
}

TEST (stored_nlen_boundary_zero_len)
{
  /* Valid boundary: LEN=0x0000, NLEN=0xFFFF */
  uint8_t input[] = { 0x00, 0x00, 0xFF, 0xFF };
  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (input, sizeof (input));
  result = SocketDeflate_decode_stored_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 0);
}

/*
 * Alignment Tests
 */

TEST (stored_alignment_after_bits)
{
  /* Simulate reading BFINAL + BTYPE = 3 bits first.
   * Byte 0x07 = 0b00000111
   * - Read 3 bits: get 0b111 = 7
   * - Remaining 5 bits (0b00000) should be discarded by align
   * Then stored block header follows in byte 1 onward.
   */
  uint8_t input[] = {
    0x07,           /* First byte: read 3 bits, discard 5 */
    0x03, 0x00,     /* LEN = 3 */
    0xFC, 0xFF,     /* NLEN = ~3 = 0xFFFC */
    'A',  'B',  'C' /* DATA */
  };
  uint8_t output[64];
  size_t written;
  uint32_t bits;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (input, sizeof (input));

  /* Simulate reading BFINAL + BTYPE = 3 bits */
  result = SocketDeflate_BitReader_read (reader, 3, &bits);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (bits, 0x07);

  /* Now decode stored block (should align first) */
  result = SocketDeflate_decode_stored_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 3);
  ASSERT (memcmp (output, "ABC", 3) == 0);
}

TEST (stored_alignment_after_byte)
{
  /* If exactly 8 bits consumed, align is a no-op */
  uint8_t input[] = {
    0xAB,       /* First byte: will be fully consumed */
    0x02, 0x00, /* LEN = 2 */
    0xFD, 0xFF, /* NLEN = ~2 = 0xFFFD */
    'X',  'Y'   /* DATA */
  };
  uint8_t output[64];
  size_t written;
  uint32_t bits;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (input, sizeof (input));

  /* Consume exactly 8 bits */
  result = SocketDeflate_BitReader_read (reader, 8, &bits);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (bits, 0xAB);

  /* Decode stored block */
  result = SocketDeflate_decode_stored_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 2);
  ASSERT (memcmp (output, "XY", 2) == 0);
}

TEST (stored_alignment_after_partial)
{
  /* 11 bits consumed: align discards 5 bits to reach byte 2 */
  uint8_t input[] = { 0xFF, 0x07, /* First 2 bytes: read 11 bits */
                      0x04, 0x00, /* LEN = 4 */
                      0xFB, 0xFF, /* NLEN = ~4 = 0xFFFB */
                      'T',  'E',  'S', 'T' };
  uint8_t output[64];
  size_t written;
  uint32_t bits;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (input, sizeof (input));

  /* Consume 11 bits */
  result = SocketDeflate_BitReader_read (reader, 11, &bits);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (bits, 0x7FF); /* All 1s */

  /* Decode stored block */
  result = SocketDeflate_decode_stored_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 4);
  ASSERT (memcmp (output, "TEST", 4) == 0);
}

/*
 * Edge Cases
 */

TEST (stored_incomplete_len)
{
  /* Input ends before LEN can be read (only 1 byte) */
  uint8_t input[] = { 0x05 };
  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (input, sizeof (input));
  result = SocketDeflate_decode_stored_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_INCOMPLETE);
}

TEST (stored_incomplete_nlen)
{
  /* Input ends after LEN but before NLEN complete */
  uint8_t input[] = { 0x05, 0x00, 0xFA };
  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (input, sizeof (input));
  result = SocketDeflate_decode_stored_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_INCOMPLETE);
}

TEST (stored_incomplete_data)
{
  /* LEN=5 but only 3 bytes of data provided */
  uint8_t input[] = { 0x05, 0x00, 0xFA, 0xFF, 'H', 'e', 'l' };
  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (input, sizeof (input));
  result = SocketDeflate_decode_stored_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_INCOMPLETE);
}

TEST (stored_output_too_small)
{
  /* Valid block but output buffer too small */
  uint8_t input[] = { 0x05, 0x00, 0xFA, 0xFF, 'H', 'e', 'l', 'l', 'o' };
  uint8_t output[3]; /* Only 3 bytes, need 5 */
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (input, sizeof (input));
  result = SocketDeflate_decode_stored_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_ERROR);
}

TEST (stored_empty_input)
{
  /* No input at all */
  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (NULL, 0);
  result = SocketDeflate_decode_stored_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_INCOMPLETE);
}

TEST (stored_written_zero_on_error)
{
  /* Verify *written is set to 0 on all error paths */
  uint8_t output[64];
  size_t written;
  SocketDeflate_Result result;

  /* Test 1: NLEN validation error */
  uint8_t invalid_nlen[] = { 0x05, 0x00, 0x00, 0x00, 'H', 'e', 'l', 'l', 'o' };
  written = 9999; /* Set to non-zero to verify it gets cleared */
  SocketDeflate_BitReader_T reader1
      = make_reader (invalid_nlen, sizeof (invalid_nlen));
  result = SocketDeflate_decode_stored_block (
      reader1, output, sizeof (output), &written);
  ASSERT_EQ (result, DEFLATE_ERROR);
  ASSERT_EQ (written, 0);

  /* Test 2: Incomplete input error */
  uint8_t incomplete[] = { 0x05 };
  written = 9999;
  SocketDeflate_BitReader_T reader2
      = make_reader (incomplete, sizeof (incomplete));
  result = SocketDeflate_decode_stored_block (
      reader2, output, sizeof (output), &written);
  ASSERT_EQ (result, DEFLATE_INCOMPLETE);
  ASSERT_EQ (written, 0);

  /* Test 3: Output buffer too small error */
  uint8_t valid[] = { 0x05, 0x00, 0xFA, 0xFF, 'H', 'e', 'l', 'l', 'o' };
  written = 9999;
  SocketDeflate_BitReader_T reader3 = make_reader (valid, sizeof (valid));
  result = SocketDeflate_decode_stored_block (reader3, output, 3, &written);
  ASSERT_EQ (result, DEFLATE_ERROR);
  ASSERT_EQ (written, 0);
}

/*
 * Integration Tests
 */

TEST (stored_after_block_header)
{
  /* Simulate complete DEFLATE block: BFINAL=0, BTYPE=00, then stored data
   * Byte 0: 0b00000_00_0 = BFINAL=0, BTYPE=00 (stored), padding=00000
   * Actually for BTYPE=00:
   *   BFINAL = bit 0
   *   BTYPE  = bits 1-2
   * So byte 0x00 = BFINAL=0, BTYPE=00, then 5 padding bits
   */
  uint8_t input[] = { 0x00,       /* BFINAL=0, BTYPE=00, 5 padding bits */
                      0x04, 0x00, /* LEN = 4 */
                      0xFB, 0xFF, /* NLEN = ~4 */
                      'D',  'A',  'T', 'A' };
  uint8_t output[64];
  size_t written;
  uint32_t header;
  SocketDeflate_Result result;

  SocketDeflate_BitReader_T reader = make_reader (input, sizeof (input));

  /* Read BFINAL (1 bit) */
  result = SocketDeflate_BitReader_read (reader, 1, &header);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (header, 0); /* BFINAL = 0 */

  /* Read BTYPE (2 bits) */
  result = SocketDeflate_BitReader_read (reader, 2, &header);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (header, 0); /* BTYPE = 00 (stored) */

  /* Decode stored block */
  result = SocketDeflate_decode_stored_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 4);
  ASSERT (memcmp (output, "DATA", 4) == 0);
}

TEST (stored_final_block)
{
  /* BFINAL=1 stored block */
  uint8_t input[] = { 0x01,       /* BFINAL=1, BTYPE=00, 5 padding bits */
                      0x03, 0x00, /* LEN = 3 */
                      0xFC, 0xFF, /* NLEN = ~3 */
                      'E',  'N',  'D' };
  uint8_t output[64];
  size_t written;
  uint32_t header;
  SocketDeflate_Result result;
  int is_final;

  SocketDeflate_BitReader_T reader = make_reader (input, sizeof (input));

  /* Read BFINAL (1 bit) */
  result = SocketDeflate_BitReader_read (reader, 1, &header);
  ASSERT_EQ (result, DEFLATE_OK);
  is_final = (header == 1);
  ASSERT (is_final);

  /* Read BTYPE (2 bits) */
  result = SocketDeflate_BitReader_read (reader, 2, &header);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (header, 0); /* BTYPE = 00 (stored) */

  /* Decode stored block */
  result = SocketDeflate_decode_stored_block (
      reader, output, sizeof (output), &written);

  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (written, 3);
  ASSERT (memcmp (output, "END", 3) == 0);
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
