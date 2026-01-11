/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_deflate_huffman.c
 * @brief Unit tests for RFC 1951 Huffman decoder.
 *
 * Tests:
 * - RFC 1951 §3.2.2 canonical code generation
 * - Two-level lookup table (primary + secondary)
 * - Tree validation (over-subscribed, incomplete)
 * - Fixed litlen/dist tables per RFC 1951 §3.2.6
 * - Edge cases and error handling
 */

#include "test/Test.h"

#include "core/Arena.h"
#include "deflate/SocketDeflate.h"

#include <string.h>

static Arena_T test_arena;
static SocketDeflate_HuffmanTable_T test_table;
static SocketDeflate_BitReader_T test_reader;

static void
setup (void)
{
  test_arena = Arena_new ();
  test_table = SocketDeflate_HuffmanTable_new (test_arena);
  test_reader = SocketDeflate_BitReader_new (test_arena);
}

static void
teardown (void)
{
  Arena_dispose (&test_arena);
  test_table = NULL;
  test_reader = NULL;
}

/*
 * Helper: Build table and decode from byte array.
 */
static SocketDeflate_Result
decode_from_bytes (const uint8_t *data, size_t size, uint16_t *symbol)
{
  SocketDeflate_BitReader_init (test_reader, data, size);
  return SocketDeflate_HuffmanTable_decode (test_table, test_reader, symbol);
}

/* ========================================================================
 * Basic Build Tests
 * ======================================================================== */

/*
 * Test: Build RFC 1951 example tree (A=2, B=1, C=3, D=3).
 *
 * From RFC 1951 §3.2.1:
 *   Symbol Code
 *   A      00
 *   B      1
 *   C      011
 *   D      010
 *
 * Canonical reordering per §3.2.2 (B has shortest, then A, C, D):
 *   B: len=1, code=0
 *   A: len=2, code=10
 *   C: len=3, code=110
 *   D: len=3, code=111
 */
TEST (huffman_build_simple_tree)
{
  /* Lengths for symbols A(0), B(1), C(2), D(3) */
  uint8_t lengths[] = { 2, 1, 3, 3 };
  SocketDeflate_Result result;

  setup ();

  result = SocketDeflate_HuffmanTable_build (test_table, lengths, 4,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  teardown ();
}

/*
 * Test: Build RFC 1951 §3.2.2 example (ABCDEFGH with lengths 3,3,3,3,3,2,4,4).
 *
 * Expected codes (MSB-first):
 *   F (len=2): 00
 *   A (len=3): 010
 *   B (len=3): 011
 *   C (len=3): 100
 *   D (len=3): 101
 *   E (len=3): 110
 *   G (len=4): 1110
 *   H (len=4): 1111
 */
TEST (huffman_build_abcdefgh)
{
  /* Lengths for A-H */
  uint8_t lengths[] = { 3, 3, 3, 3, 3, 2, 4, 4 };
  SocketDeflate_Result result;

  setup ();

  result = SocketDeflate_HuffmanTable_build (test_table, lengths, 8,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  teardown ();
}

/*
 * Test: Build fixed literal/length table (288 symbols).
 */
TEST (huffman_build_fixed_litlen)
{
  SocketDeflate_Result result;

  setup ();

  result = SocketDeflate_HuffmanTable_build (test_table,
                                             deflate_fixed_litlen_lengths,
                                             DEFLATE_LITLEN_CODES,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  teardown ();
}

/*
 * Test: Build fixed distance table (32 symbols, all 5-bit).
 */
TEST (huffman_build_fixed_dist)
{
  SocketDeflate_Result result;

  setup ();

  result = SocketDeflate_HuffmanTable_build (test_table,
                                             deflate_fixed_dist_lengths,
                                             DEFLATE_DIST_CODES,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  teardown ();
}

/* ========================================================================
 * Decode Tests
 * ======================================================================== */

/*
 * Test: Decode single symbol from simple tree.
 *
 * Tree: A=2, B=1, C=3, D=3
 * Canonical codes (MSB-first):
 *   B (sym=1): 0      → reversed: 0
 *   A (sym=0): 10     → reversed: 01
 *   C (sym=2): 110    → reversed: 011
 *   D (sym=3): 111    → reversed: 111
 */
TEST (huffman_decode_single_symbol)
{
  uint8_t lengths[] = { 2, 1, 3, 3 };
  uint16_t symbol;
  SocketDeflate_Result result;

  setup ();

  result = SocketDeflate_HuffmanTable_build (test_table, lengths, 4,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Decode B: code=0 (1 bit), input byte 0x00 has LSB=0 */
  uint8_t data_b[] = { 0x00 };
  result = decode_from_bytes (data_b, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 1); /* B */

  /* Decode A: code=10 → reversed=01, input 0x01 has bits 01 at LSB */
  uint8_t data_a[] = { 0x01 };
  result = decode_from_bytes (data_a, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 0); /* A */

  /* Decode C: code=110 → reversed=011, input 0x03 has bits 011 at LSB */
  uint8_t data_c[] = { 0x03 };
  result = decode_from_bytes (data_c, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 2); /* C */

  /* Decode D: code=111 → reversed=111, input 0x07 has bits 111 at LSB */
  uint8_t data_d[] = { 0x07 };
  result = decode_from_bytes (data_d, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 3); /* D */

  teardown ();
}

/*
 * Test: Decode sequence of symbols.
 *
 * Tree: A=2, B=1, C=3, D=3
 * Sequence: B, A, C, D
 * Codes (reversed): 0, 01, 011, 111
 * Packed LSB-first: 0 01 011 111 = 0b11101100 0b1 = 0xEC, 0x01
 *
 * Wait, let me recalculate:
 * B: 0 (1 bit)
 * A: 01 (2 bits)
 * C: 011 (3 bits)
 * D: 111 (3 bits)
 *
 * Total: 1+2+3+3 = 9 bits
 * Packed LSB-first into bytes:
 *   Bit 0: B[0] = 0
 *   Bit 1-2: A[0-1] = 01
 *   Bit 3-5: C[0-2] = 011
 *   Bit 6-7: D[0-1] = 11
 *   Bit 8: D[2] = 1
 *
 * Byte 0: bits 0-7 = 0 01 011 11 = 0b11011010 = 0xDA
 * Byte 1: bits 8   = 1 = 0x01
 */
TEST (huffman_decode_sequence)
{
  uint8_t lengths[] = { 2, 1, 3, 3 };
  uint8_t data[] = { 0xDA, 0x01 };
  uint16_t symbol;
  SocketDeflate_Result result;

  setup ();

  result = SocketDeflate_HuffmanTable_build (test_table, lengths, 4,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  SocketDeflate_BitReader_init (test_reader, data, sizeof (data));

  /* Decode B */
  result
      = SocketDeflate_HuffmanTable_decode (test_table, test_reader, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 1);

  /* Decode A */
  result
      = SocketDeflate_HuffmanTable_decode (test_table, test_reader, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 0);

  /* Decode C */
  result
      = SocketDeflate_HuffmanTable_decode (test_table, test_reader, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 2);

  /* Decode D */
  result
      = SocketDeflate_HuffmanTable_decode (test_table, test_reader, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 3);

  teardown ();
}

/*
 * Test: Decode ABCDEFGH example.
 *
 * Codes (MSB-first):
 *   F: 00 (2 bits)
 *   A: 010 (3 bits)
 *   B: 011 (3 bits)
 *   C: 100 (3 bits)
 *   D: 101 (3 bits)
 *   E: 110 (3 bits)
 *   G: 1110 (4 bits)
 *   H: 1111 (4 bits)
 *
 * Reversed for LSB-first:
 *   F (5): 00   → 00
 *   A (0): 010  → 010
 *   B (1): 011  → 110
 *   C (2): 100  → 001
 *   D (3): 101  → 101
 *   E (4): 110  → 011
 *   G (6): 1110 → 0111
 *   H (7): 1111 → 1111
 */
TEST (huffman_decode_abcdefgh)
{
  uint8_t lengths[] = { 3, 3, 3, 3, 3, 2, 4, 4 };
  uint16_t symbol;
  SocketDeflate_Result result;

  setup ();

  result = SocketDeflate_HuffmanTable_build (test_table, lengths, 8,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Decode F: reversed code 00, LSB of 0x00 */
  uint8_t data_f[] = { 0x00 };
  result = decode_from_bytes (data_f, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 5); /* F */

  /* Decode A: reversed code 010 = 0x02, LSB of 0x02 */
  uint8_t data_a[] = { 0x02 };
  result = decode_from_bytes (data_a, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 0); /* A */

  /* Decode B: reversed code 110 = 0x06, LSB of 0x06 */
  uint8_t data_b[] = { 0x06 };
  result = decode_from_bytes (data_b, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 1); /* B */

  /* Decode G: reversed code 0111 = 0x07, LSB of 0x07 */
  uint8_t data_g[] = { 0x07 };
  result = decode_from_bytes (data_g, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 6); /* G */

  /* Decode H: reversed code 1111 = 0x0F, LSB of 0x0F */
  uint8_t data_h[] = { 0x0F };
  result = decode_from_bytes (data_h, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 7); /* H */

  teardown ();
}

/*
 * Test: Decode end-of-block symbol (256) from fixed table.
 *
 * Fixed litlen: symbol 256 has length 7, code 0000000 (MSB-first).
 * Reversed: 0000000 = 0x00
 */
TEST (huffman_decode_end_of_block)
{
  uint16_t symbol;
  SocketDeflate_Result result;
  uint8_t data[] = { 0x00 };

  setup ();

  result = SocketDeflate_HuffmanTable_build (test_table,
                                             deflate_fixed_litlen_lengths,
                                             DEFLATE_LITLEN_CODES,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  result = decode_from_bytes (data, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, DEFLATE_END_OF_BLOCK);

  teardown ();
}

/* ========================================================================
 * Validation Tests
 * ======================================================================== */

/*
 * Test: Over-subscribed tree must fail.
 *
 * Three 1-bit codes: needs 3 leaves but only 2^1=2 available.
 */
TEST (huffman_oversubscribed_tree)
{
  uint8_t lengths[] = { 1, 1, 1 };
  SocketDeflate_Result result;

  setup ();

  result = SocketDeflate_HuffmanTable_build (test_table, lengths, 3,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_ERROR_HUFFMAN_TREE);

  teardown ();
}

/*
 * Test: Under-subscribed tree (incomplete) is allowed for decoders.
 *
 * Two 3-bit codes: uses 2 out of 8 leaves. Build should succeed,
 * but decoding unused bit patterns returns DEFLATE_ERROR_INVALID_CODE.
 */
TEST (huffman_incomplete_tree)
{
  uint8_t lengths[] = { 3, 3, 0, 0 };
  SocketDeflate_Result result;
  uint16_t symbol;

  setup ();

  /* Build should succeed - incomplete trees are valid for decoders */
  result = SocketDeflate_HuffmanTable_build (test_table, lengths, 4,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Valid codes should decode:
   * Symbol 0: 3-bit code 000 (reversed for LSB-first)
   * Symbol 1: 3-bit code 001 (reversed for LSB-first) */
  uint8_t data_sym0[] = { 0x00 }; /* bits: 00000000, symbol 0 code */
  result = decode_from_bytes (data_sym0, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 0);

  teardown ();
}

/*
 * Test: Single-code tree is valid (RFC 1951 §3.2.7).
 *
 * "If only one distance code is used, it is encoded using one bit,
 * not zero bits; in this case there is a single code length of one,
 * with one unused code."
 */
TEST (huffman_single_code_tree)
{
  uint8_t lengths[] = { 1, 0, 0, 0 };
  SocketDeflate_Result result;
  uint16_t symbol;

  setup ();

  result = SocketDeflate_HuffmanTable_build (test_table, lengths, 4,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Decode the single code (symbol 0) */
  uint8_t data[] = { 0x00 };
  result = decode_from_bytes (data, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 0);

  teardown ();
}

/*
 * Test: Code length > 15 must fail.
 */
TEST (huffman_max_bits_exceeded)
{
  uint8_t lengths[] = { 16, 0, 0, 0 };
  SocketDeflate_Result result;

  setup ();

  result = SocketDeflate_HuffmanTable_build (test_table, lengths, 4,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_ERROR_HUFFMAN_TREE);

  teardown ();
}

/*
 * Test: All same length codes.
 *
 * Four 2-bit codes: exactly fills 2^2=4 leaves.
 */
TEST (huffman_all_same_length)
{
  uint8_t lengths[] = { 2, 2, 2, 2 };
  SocketDeflate_Result result;
  uint16_t symbol;

  setup ();

  result = SocketDeflate_HuffmanTable_build (test_table, lengths, 4,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Decode all four symbols */
  /* Codes (MSB-first): 00, 01, 10, 11 */
  /* Reversed: 00, 10, 01, 11 */

  uint8_t data0[] = { 0x00 }; /* 00 → symbol 0 */
  result = decode_from_bytes (data0, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 0);

  uint8_t data1[] = { 0x02 }; /* 10 → symbol 1 (code 01 reversed) */
  result = decode_from_bytes (data1, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 1);

  uint8_t data2[] = { 0x01 }; /* 01 → symbol 2 (code 10 reversed) */
  result = decode_from_bytes (data2, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 2);

  uint8_t data3[] = { 0x03 }; /* 11 → symbol 3 */
  result = decode_from_bytes (data3, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 3);

  teardown ();
}

/* ========================================================================
 * Edge Case Tests
 * ======================================================================== */

/*
 * Test: Empty alphabet (all lengths = 0).
 */
TEST (huffman_empty_alphabet)
{
  uint8_t lengths[] = { 0, 0, 0, 0 };
  SocketDeflate_Result result;

  setup ();

  result = SocketDeflate_HuffmanTable_build (test_table, lengths, 4,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  teardown ();
}

/*
 * Test: Maximum alphabet size (288 for litlen).
 */
TEST (huffman_max_alphabet_size)
{
  SocketDeflate_Result result;

  setup ();

  result = SocketDeflate_HuffmanTable_build (test_table,
                                             deflate_fixed_litlen_lengths,
                                             DEFLATE_LITLEN_CODES,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  teardown ();
}

/*
 * Test: Not enough bits to decode.
 */
TEST (huffman_incomplete_input)
{
  uint8_t lengths[] = { 8, 8, 8, 8 }; /* 8-bit codes */
  uint8_t data[] = { 0x00 };          /* Only has bits for partial code */
  SocketDeflate_Result result;
  uint16_t symbol;

  setup ();

  result = SocketDeflate_HuffmanTable_build (test_table, lengths, 4,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Should decode successfully since we have 8 bits */
  result = decode_from_bytes (data, 1, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Now try with empty input */
  uint8_t empty[] = { 0 };
  SocketDeflate_BitReader_init (test_reader, empty, 0);
  result
      = SocketDeflate_HuffmanTable_decode (test_table, test_reader, &symbol);
  ASSERT_EQ (result, DEFLATE_INCOMPLETE);

  teardown ();
}

/*
 * Test: Codes requiring secondary table (> 9 bits).
 *
 * Create a tree with 10-bit codes to exercise secondary lookup.
 */
TEST (huffman_secondary_table_codes)
{
  /* Create alphabet with varying lengths including > 9 bits */
  uint8_t lengths[16];
  SocketDeflate_Result result;
  uint16_t symbol;
  unsigned int i;

  setup ();

  /* 1 symbol at 1 bit, 1 at 10 bits */
  memset (lengths, 0, sizeof (lengths));
  lengths[0] = 1;  /* Symbol 0: 1 bit */
  lengths[1] = 10; /* Symbol 1: 10 bits */

  result = SocketDeflate_HuffmanTable_build (test_table, lengths, 16,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Decode symbol 0: code 0 (1 bit) */
  uint8_t data0[] = { 0x00, 0x00 };
  result = decode_from_bytes (data0, 2, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 0);

  /* Decode symbol 1: canonical code 512 (10 bits MSB-first)
   * MSB-first: 1000000000
   * Reversed for LSB-first: 0000000001
   * In bytes: byte[0]=0x01 (bits 0-7=0x01), byte[1]=0x00 (bits 8-9=0) */
  uint8_t data1[] = { 0x01, 0x00 };
  result = decode_from_bytes (data1, 2, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 1);

  teardown ();
}

/*
 * Test: Table reset and rebuild.
 */
TEST (huffman_table_reset)
{
  uint8_t lengths1[] = { 2, 2, 2, 2 };
  uint8_t lengths2[] = { 1, 2, 3, 3 };
  SocketDeflate_Result result;

  setup ();

  /* Build first table */
  result = SocketDeflate_HuffmanTable_build (test_table, lengths1, 4,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  /* Reset and rebuild with different lengths */
  SocketDeflate_HuffmanTable_reset (test_table);

  result = SocketDeflate_HuffmanTable_build (test_table, lengths2, 4,
                                             DEFLATE_MAX_BITS);
  ASSERT_EQ (result, DEFLATE_OK);

  teardown ();
}

/* ========================================================================
 * Fixed Table Tests
 * ======================================================================== */

/*
 * Test: Initialize fixed tables.
 */
TEST (huffman_fixed_tables_init)
{
  SocketDeflate_Result result;
  SocketDeflate_HuffmanTable_T litlen;
  SocketDeflate_HuffmanTable_T dist;

  setup ();

  result = SocketDeflate_fixed_tables_init (test_arena);
  ASSERT_EQ (result, DEFLATE_OK);

  litlen = SocketDeflate_get_fixed_litlen_table ();
  ASSERT_NE (litlen, NULL);

  dist = SocketDeflate_get_fixed_dist_table ();
  ASSERT_NE (dist, NULL);

  teardown ();
}

/*
 * Test: Decode literals with fixed litlen table.
 *
 * Fixed codes for literals 0-143: 8 bits, codes 00110000-10111111
 * Symbol 0: code 00110000 (48) = 0x30, reversed = 0x0C
 */
TEST (huffman_fixed_litlen_decode)
{
  SocketDeflate_Result result;
  SocketDeflate_HuffmanTable_T litlen;
  uint16_t symbol;

  setup ();

  result = SocketDeflate_fixed_tables_init (test_arena);
  ASSERT_EQ (result, DEFLATE_OK);

  litlen = SocketDeflate_get_fixed_litlen_table ();
  ASSERT_NE (litlen, NULL);

  /* Decode symbol 0: code 00110000 reversed = 00001100 = 0x0C */
  uint8_t data0[] = { 0x0C };
  SocketDeflate_BitReader_init (test_reader, data0, 1);
  result = SocketDeflate_HuffmanTable_decode (litlen, test_reader, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 0);

  /* Decode end-of-block (256): 7-bit code 0000000 reversed = 0x00 */
  uint8_t data_eob[] = { 0x00 };
  SocketDeflate_BitReader_init (test_reader, data_eob, 1);
  result = SocketDeflate_HuffmanTable_decode (litlen, test_reader, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 256);

  teardown ();
}

/*
 * Test: Decode distances with fixed dist table.
 *
 * Fixed distance codes: all 5 bits, codes 00000-11111 (0-31)
 * Symbol 0: code 00000, reversed = 00000 = 0x00
 * Symbol 5: code 00101, reversed = 10100 = 0x14
 */
TEST (huffman_fixed_dist_decode)
{
  SocketDeflate_Result result;
  SocketDeflate_HuffmanTable_T dist;
  uint16_t symbol;

  setup ();

  result = SocketDeflate_fixed_tables_init (test_arena);
  ASSERT_EQ (result, DEFLATE_OK);

  dist = SocketDeflate_get_fixed_dist_table ();
  ASSERT_NE (dist, NULL);

  /* Decode symbol 0: code 00000 reversed = 0x00 */
  uint8_t data0[] = { 0x00 };
  SocketDeflate_BitReader_init (test_reader, data0, 1);
  result = SocketDeflate_HuffmanTable_decode (dist, test_reader, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 0);

  /* Decode symbol 5: code 00101 reversed = 10100 = 0x14 */
  uint8_t data5[] = { 0x14 };
  SocketDeflate_BitReader_init (test_reader, data5, 1);
  result = SocketDeflate_HuffmanTable_decode (dist, test_reader, &symbol);
  ASSERT_EQ (result, DEFLATE_OK);
  ASSERT_EQ (symbol, 5);

  teardown ();
}

/*
 * Test: Fixed tables singleton behavior.
 */
TEST (huffman_fixed_tables_singleton)
{
  SocketDeflate_Result result;
  SocketDeflate_HuffmanTable_T litlen1;
  SocketDeflate_HuffmanTable_T litlen2;

  setup ();

  /* First init */
  result = SocketDeflate_fixed_tables_init (test_arena);
  ASSERT_EQ (result, DEFLATE_OK);
  litlen1 = SocketDeflate_get_fixed_litlen_table ();

  /* Second init should return same tables */
  result = SocketDeflate_fixed_tables_init (test_arena);
  ASSERT_EQ (result, DEFLATE_OK);
  litlen2 = SocketDeflate_get_fixed_litlen_table ();

  ASSERT_EQ (litlen1, litlen2);

  teardown ();
}

/* ========================================================================
 * Test Runner
 * ======================================================================== */

int
main (void)
{
  Test_run_all ();

  return Test_get_failures () > 0 ? 1 : 0;
}
