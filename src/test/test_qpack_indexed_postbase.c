/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_indexed_postbase.c
 * @brief Unit tests for QPACK Indexed Field Line with Post-Base Index
 *        (RFC 9204 Section 4.5.3)
 *
 * Tests the encoding and decoding of Indexed Field Line with Post-Base Index,
 * which allows referencing dynamic table entries inserted after the Base
 * value was established for the field section.
 *
 * Test coverage includes:
 * - Pattern identification (0001xxxx)
 * - Encoding with 4-bit prefix (values 0-14)
 * - Encoding with continuation bytes (values >= 15)
 * - Decoding and round-trip verification
 * - Validation against insert count bounds
 * - Table lookup with post-base indexing
 * - Error handling for invalid patterns and indices
 */

#include "core/Arena.h"
#include "http/qpack/SocketQPACK.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test assertion macro */
#define TEST_ASSERT(cond, msg)                                               \
  do                                                                         \
    {                                                                        \
      if (!(cond))                                                           \
        {                                                                    \
          fprintf (stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); \
          exit (1);                                                          \
        }                                                                    \
    }                                                                        \
  while (0)

/* ============================================================================
 * PATTERN IDENTIFICATION TESTS
 * ============================================================================
 */

/**
 * Test pattern identification for post-base indexed field line.
 *
 * The pattern 0001xxxx should be identified as post-base indexed.
 * Other patterns should not match.
 */
static void
test_pattern_identification (void)
{
  printf ("  Pattern identification... ");

  /* Pattern 0001xxxx should match */
  TEST_ASSERT (SocketQPACK_is_indexed_postbase (0x10) == true,
               "0x10 should match");
  TEST_ASSERT (SocketQPACK_is_indexed_postbase (0x11) == true,
               "0x11 should match");
  TEST_ASSERT (SocketQPACK_is_indexed_postbase (0x1F) == true,
               "0x1F should match");

  /* Pattern 0000xxxx should NOT match */
  TEST_ASSERT (SocketQPACK_is_indexed_postbase (0x00) == false,
               "0x00 should not match");
  TEST_ASSERT (SocketQPACK_is_indexed_postbase (0x0F) == false,
               "0x0F should not match");

  /* Pattern 0010xxxx should NOT match */
  TEST_ASSERT (SocketQPACK_is_indexed_postbase (0x20) == false,
               "0x20 should not match");
  TEST_ASSERT (SocketQPACK_is_indexed_postbase (0x2F) == false,
               "0x2F should not match");

  /* Pattern 01xxxxxx should NOT match */
  TEST_ASSERT (SocketQPACK_is_indexed_postbase (0x40) == false,
               "0x40 should not match");
  TEST_ASSERT (SocketQPACK_is_indexed_postbase (0x7F) == false,
               "0x7F should not match");

  /* Pattern 1xxxxxxx should NOT match */
  TEST_ASSERT (SocketQPACK_is_indexed_postbase (0x80) == false,
               "0x80 should not match");
  TEST_ASSERT (SocketQPACK_is_indexed_postbase (0xFF) == false,
               "0xFF should not match");

  printf ("PASS\n");
}

/* ============================================================================
 * ENCODE TESTS
 * ============================================================================
 */

/**
 * Test encoding post-base indices that fit in 4-bit prefix (0-14).
 */
static void
test_encode_small_indices (void)
{
  unsigned char buf[16];
  size_t written;
  SocketQPACK_Result result;

  printf ("  Encode small indices (0-14)... ");

  /* Post-base index 0 -> 0x10 (pattern 0001 | 0000) */
  result = SocketQPACK_encode_indexed_postbase (0, buf, sizeof (buf), &written);
  TEST_ASSERT (result == QPACK_OK, "encode pb=0 should succeed");
  TEST_ASSERT (written == 1, "pb=0 should be 1 byte");
  TEST_ASSERT (buf[0] == 0x10, "pb=0 should encode as 0x10");

  /* Post-base index 5 -> 0x15 (pattern 0001 | 0101) */
  result = SocketQPACK_encode_indexed_postbase (5, buf, sizeof (buf), &written);
  TEST_ASSERT (result == QPACK_OK, "encode pb=5 should succeed");
  TEST_ASSERT (written == 1, "pb=5 should be 1 byte");
  TEST_ASSERT (buf[0] == 0x15, "pb=5 should encode as 0x15");

  /* Post-base index 14 -> 0x1E (pattern 0001 | 1110) */
  result
      = SocketQPACK_encode_indexed_postbase (14, buf, sizeof (buf), &written);
  TEST_ASSERT (result == QPACK_OK, "encode pb=14 should succeed");
  TEST_ASSERT (written == 1, "pb=14 should be 1 byte");
  TEST_ASSERT (buf[0] == 0x1E, "pb=14 should encode as 0x1E");

  printf ("PASS\n");
}

/**
 * Test encoding post-base indices requiring continuation bytes (>= 15).
 */
static void
test_encode_large_indices (void)
{
  unsigned char buf[16];
  size_t written;
  SocketQPACK_Result result;

  printf ("  Encode large indices (>= 15)... ");

  /*
   * Post-base index 15 -> 0x1F 0x00 (pattern + max prefix, then 0)
   * Value = 15 -> prefix full (15), continuation = 15 - 15 = 0
   */
  result
      = SocketQPACK_encode_indexed_postbase (15, buf, sizeof (buf), &written);
  TEST_ASSERT (result == QPACK_OK, "encode pb=15 should succeed");
  TEST_ASSERT (written == 2, "pb=15 should be 2 bytes");
  TEST_ASSERT (buf[0] == 0x1F, "pb=15 first byte should be 0x1F");
  TEST_ASSERT (buf[1] == 0x00, "pb=15 second byte should be 0x00");

  /*
   * Post-base index 16 -> 0x1F 0x01
   * Value = 16 -> prefix full (15), continuation = 16 - 15 = 1
   */
  result
      = SocketQPACK_encode_indexed_postbase (16, buf, sizeof (buf), &written);
  TEST_ASSERT (result == QPACK_OK, "encode pb=16 should succeed");
  TEST_ASSERT (written == 2, "pb=16 should be 2 bytes");
  TEST_ASSERT (buf[0] == 0x1F, "pb=16 first byte should be 0x1F");
  TEST_ASSERT (buf[1] == 0x01, "pb=16 second byte should be 0x01");

  /*
   * Post-base index 142 -> 0x1F 0x7F (15 + 127)
   * Value = 142 -> prefix full (15), continuation = 142 - 15 = 127
   */
  result
      = SocketQPACK_encode_indexed_postbase (142, buf, sizeof (buf), &written);
  TEST_ASSERT (result == QPACK_OK, "encode pb=142 should succeed");
  TEST_ASSERT (written == 2, "pb=142 should be 2 bytes");
  TEST_ASSERT (buf[0] == 0x1F, "pb=142 first byte should be 0x1F");
  TEST_ASSERT (buf[1] == 0x7F, "pb=142 second byte should be 0x7F");

  /*
   * Post-base index 143 -> 0x1F 0x80 0x01 (15 + 128, needs multi-byte)
   * Value = 143 -> prefix full (15), continuation = 128
   * 128 = 0x80 | continuation bit, then 0x01
   */
  result
      = SocketQPACK_encode_indexed_postbase (143, buf, sizeof (buf), &written);
  TEST_ASSERT (result == QPACK_OK, "encode pb=143 should succeed");
  TEST_ASSERT (written == 3, "pb=143 should be 3 bytes");
  TEST_ASSERT (buf[0] == 0x1F, "pb=143 first byte should be 0x1F");
  TEST_ASSERT (buf[1] == 0x80, "pb=143 second byte should be 0x80");
  TEST_ASSERT (buf[2] == 0x01, "pb=143 third byte should be 0x01");

  printf ("PASS\n");
}

/**
 * Test encoding error conditions.
 */
static void
test_encode_errors (void)
{
  unsigned char buf[16];
  size_t written;
  SocketQPACK_Result result;

  printf ("  Encode error handling... ");

  /* NULL output buffer */
  result = SocketQPACK_encode_indexed_postbase (0, NULL, 16, &written);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL output should fail");

  /* NULL bytes_written */
  result = SocketQPACK_encode_indexed_postbase (0, buf, 16, NULL);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL written should fail");

  /* Zero-length buffer */
  result = SocketQPACK_encode_indexed_postbase (0, buf, 0, &written);
  TEST_ASSERT (result == QPACK_ERR_TABLE_SIZE, "zero buffer should fail");

  /* Buffer too small for value needing continuation */
  result = SocketQPACK_encode_indexed_postbase (15, buf, 1, &written);
  TEST_ASSERT (result == QPACK_ERR_INTEGER,
               "small buffer for pb=15 should fail");

  printf ("PASS\n");
}

/* ============================================================================
 * DECODE TESTS
 * ============================================================================
 */

/**
 * Test decoding post-base indices from 4-bit prefix.
 */
static void
test_decode_small_indices (void)
{
  unsigned char buf[16];
  uint64_t post_base_index;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Decode small indices (0-14)... ");

  /* Decode pb=0: 0x10 */
  buf[0] = 0x10;
  result = SocketQPACK_decode_indexed_postbase (
      buf, 1, &post_base_index, &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode 0x10 should succeed");
  TEST_ASSERT (post_base_index == 0, "0x10 should decode to pb=0");
  TEST_ASSERT (consumed == 1, "0x10 should consume 1 byte");

  /* Decode pb=5: 0x15 */
  buf[0] = 0x15;
  result = SocketQPACK_decode_indexed_postbase (
      buf, 1, &post_base_index, &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode 0x15 should succeed");
  TEST_ASSERT (post_base_index == 5, "0x15 should decode to pb=5");
  TEST_ASSERT (consumed == 1, "0x15 should consume 1 byte");

  /* Decode pb=14: 0x1E */
  buf[0] = 0x1E;
  result = SocketQPACK_decode_indexed_postbase (
      buf, 1, &post_base_index, &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode 0x1E should succeed");
  TEST_ASSERT (post_base_index == 14, "0x1E should decode to pb=14");
  TEST_ASSERT (consumed == 1, "0x1E should consume 1 byte");

  printf ("PASS\n");
}

/**
 * Test decoding post-base indices with continuation bytes.
 */
static void
test_decode_large_indices (void)
{
  unsigned char buf[16];
  uint64_t post_base_index;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Decode large indices (>= 15)... ");

  /* Decode pb=15: 0x1F 0x00 */
  buf[0] = 0x1F;
  buf[1] = 0x00;
  result = SocketQPACK_decode_indexed_postbase (
      buf, 2, &post_base_index, &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode pb=15 should succeed");
  TEST_ASSERT (post_base_index == 15, "should decode to pb=15");
  TEST_ASSERT (consumed == 2, "pb=15 should consume 2 bytes");

  /* Decode pb=16: 0x1F 0x01 */
  buf[0] = 0x1F;
  buf[1] = 0x01;
  result = SocketQPACK_decode_indexed_postbase (
      buf, 2, &post_base_index, &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode pb=16 should succeed");
  TEST_ASSERT (post_base_index == 16, "should decode to pb=16");
  TEST_ASSERT (consumed == 2, "pb=16 should consume 2 bytes");

  /* Decode pb=142: 0x1F 0x7F (15 + 127) */
  buf[0] = 0x1F;
  buf[1] = 0x7F;
  result = SocketQPACK_decode_indexed_postbase (
      buf, 2, &post_base_index, &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode pb=142 should succeed");
  TEST_ASSERT (post_base_index == 142, "should decode to pb=142");
  TEST_ASSERT (consumed == 2, "pb=142 should consume 2 bytes");

  /* Decode pb=143: 0x1F 0x80 0x01 (15 + 128) */
  buf[0] = 0x1F;
  buf[1] = 0x80;
  buf[2] = 0x01;
  result = SocketQPACK_decode_indexed_postbase (
      buf, 3, &post_base_index, &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode pb=143 should succeed");
  TEST_ASSERT (post_base_index == 143, "should decode to pb=143");
  TEST_ASSERT (consumed == 3, "pb=143 should consume 3 bytes");

  printf ("PASS\n");
}

/**
 * Test decoding error conditions.
 */
static void
test_decode_errors (void)
{
  unsigned char buf[16];
  uint64_t post_base_index;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Decode error handling... ");

  /* NULL output parameters */
  buf[0] = 0x10;
  result = SocketQPACK_decode_indexed_postbase (buf, 1, NULL, &consumed);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL index output should fail");

  result = SocketQPACK_decode_indexed_postbase (buf, 1, &post_base_index, NULL);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL consumed should fail");

  /* Empty input */
  result = SocketQPACK_decode_indexed_postbase (
      buf, 0, &post_base_index, &consumed);
  TEST_ASSERT (result == QPACK_INCOMPLETE, "empty input should be incomplete");

  /* NULL input with non-zero length */
  result = SocketQPACK_decode_indexed_postbase (
      NULL, 1, &post_base_index, &consumed);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL input should fail");

  /* Wrong pattern (0000xxxx) */
  buf[0] = 0x00;
  result = SocketQPACK_decode_indexed_postbase (
      buf, 1, &post_base_index, &consumed);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "pattern 0000 should fail");

  /* Wrong pattern (0010xxxx) */
  buf[0] = 0x20;
  result = SocketQPACK_decode_indexed_postbase (
      buf, 1, &post_base_index, &consumed);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "pattern 0010 should fail");

  /* Wrong pattern (01xxxxxx) */
  buf[0] = 0x40;
  result = SocketQPACK_decode_indexed_postbase (
      buf, 1, &post_base_index, &consumed);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "pattern 01xx should fail");

  /* Wrong pattern (1xxxxxxx) */
  buf[0] = 0x80;
  result = SocketQPACK_decode_indexed_postbase (
      buf, 1, &post_base_index, &consumed);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "pattern 1xxx should fail");

  /* Incomplete continuation byte */
  buf[0] = 0x1F; /* Indicates continuation needed */
  result = SocketQPACK_decode_indexed_postbase (
      buf, 1, &post_base_index, &consumed);
  TEST_ASSERT (result == QPACK_INCOMPLETE,
               "incomplete continuation should fail");

  printf ("PASS\n");
}

/* ============================================================================
 * ROUND-TRIP TESTS
 * ============================================================================
 */

/**
 * Test encode -> decode round-trip for various indices.
 */
static void
test_roundtrip (void)
{
  unsigned char buf[16];
  uint64_t decoded;
  size_t written, consumed;
  SocketQPACK_Result result;

  printf ("  Round-trip encode/decode... ");

  /* Test indices from 0 to 20 */
  for (uint64_t i = 0; i <= 20; i++)
    {
      result = SocketQPACK_encode_indexed_postbase (
          i, buf, sizeof (buf), &written);
      TEST_ASSERT (result == QPACK_OK, "encode should succeed");

      result = SocketQPACK_decode_indexed_postbase (
          buf, written, &decoded, &consumed);
      TEST_ASSERT (result == QPACK_OK, "decode should succeed");
      TEST_ASSERT (decoded == i, "round-trip should preserve value");
      TEST_ASSERT (consumed == written, "consumed should match written");
    }

  /* Test larger values */
  uint64_t large_values[] = { 100, 127, 128, 255, 256, 1000, 10000, 65535 };
  for (size_t i = 0; i < sizeof (large_values) / sizeof (large_values[0]); i++)
    {
      result = SocketQPACK_encode_indexed_postbase (
          large_values[i], buf, sizeof (buf), &written);
      TEST_ASSERT (result == QPACK_OK, "encode large should succeed");

      result = SocketQPACK_decode_indexed_postbase (
          buf, written, &decoded, &consumed);
      TEST_ASSERT (result == QPACK_OK, "decode large should succeed");
      TEST_ASSERT (decoded == large_values[i],
                   "round-trip large should preserve value");
    }

  printf ("PASS\n");
}

/* ============================================================================
 * VALIDATION TESTS
 * ============================================================================
 */

/**
 * Test post-base index validation against insert count bounds.
 */
static void
test_validate_bounds (void)
{
  SocketQPACK_Result result;

  printf ("  Validate post-base index bounds... ");

  /*
   * Scenario: Base = 5, Insert Count = 10
   * Valid post-base indices: 0 (abs 5), 1 (abs 6), ..., 4 (abs 9)
   * Invalid: 5 (abs 10 >= insert_count)
   */
  uint64_t base = 5;
  uint64_t insert_count = 10;

  /* Post-base 0 -> abs 5 (valid) */
  result = SocketQPACK_validate_indexed_postbase (base, insert_count, 0);
  TEST_ASSERT (result == QPACK_OK, "pb=0 should be valid");

  /* Post-base 4 -> abs 9 (valid, maximum) */
  result = SocketQPACK_validate_indexed_postbase (base, insert_count, 4);
  TEST_ASSERT (result == QPACK_OK, "pb=4 should be valid");

  /* Post-base 5 -> abs 10 (invalid, >= insert_count) */
  result = SocketQPACK_validate_indexed_postbase (base, insert_count, 5);
  TEST_ASSERT (result == QPACK_ERR_FUTURE_INDEX, "pb=5 should be future");

  /* Post-base 100 -> abs 105 (invalid, >> insert_count) */
  result = SocketQPACK_validate_indexed_postbase (base, insert_count, 100);
  TEST_ASSERT (result == QPACK_ERR_FUTURE_INDEX, "pb=100 should be future");

  /* Base = Insert Count (no post-base entries available) */
  result = SocketQPACK_validate_indexed_postbase (10, 10, 0);
  TEST_ASSERT (result == QPACK_ERR_FUTURE_INDEX,
               "pb=0 with base=ic should fail");

  printf ("PASS\n");
}

/**
 * Test conversion from post-base index to absolute index.
 */
static void
test_convert_to_absolute (void)
{
  uint64_t absolute;
  SocketQPACK_Result result;

  printf ("  Convert post-base to absolute... ");

  /* Base = 5, pb = 0 -> abs = 5 */
  result = SocketQPACK_indexed_postbase_to_absolute (5, 0, &absolute);
  TEST_ASSERT (result == QPACK_OK, "convert pb=0 should succeed");
  TEST_ASSERT (absolute == 5, "pb=0 from base=5 should be abs=5");

  /* Base = 5, pb = 3 -> abs = 8 */
  result = SocketQPACK_indexed_postbase_to_absolute (5, 3, &absolute);
  TEST_ASSERT (result == QPACK_OK, "convert pb=3 should succeed");
  TEST_ASSERT (absolute == 8, "pb=3 from base=5 should be abs=8");

  /* Base = 0, pb = 0 -> abs = 0 */
  result = SocketQPACK_indexed_postbase_to_absolute (0, 0, &absolute);
  TEST_ASSERT (result == QPACK_OK, "convert base=0 pb=0 should succeed");
  TEST_ASSERT (absolute == 0, "pb=0 from base=0 should be abs=0");

  /* NULL output */
  result = SocketQPACK_indexed_postbase_to_absolute (5, 0, NULL);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL output should fail");

  /* Overflow protection */
  result = SocketQPACK_indexed_postbase_to_absolute (UINT64_MAX, 1, &absolute);
  TEST_ASSERT (result == QPACK_ERR_INVALID_INDEX, "overflow should fail");

  printf ("PASS\n");
}

/* ============================================================================
 * TABLE LOOKUP TESTS
 * ============================================================================
 */

/**
 * Test looking up entries using post-base index.
 */
static void
test_table_lookup (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Result result;
  const char *name, *value;
  size_t name_len, value_len;

  printf ("  Table lookup with post-base index... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (arena, 4096);
  TEST_ASSERT (table != NULL, "table creation should succeed");

  /* Insert some entries */
  result = SocketQPACK_Table_insert_literal (table, "header1", 7, "value1", 6);
  TEST_ASSERT (result == QPACK_OK, "insert 1 should succeed");
  /* abs 0 */

  result = SocketQPACK_Table_insert_literal (table, "header2", 7, "value2", 6);
  TEST_ASSERT (result == QPACK_OK, "insert 2 should succeed");
  /* abs 1 */

  result = SocketQPACK_Table_insert_literal (table, "header3", 7, "value3", 6);
  TEST_ASSERT (result == QPACK_OK, "insert 3 should succeed");
  /* abs 2 */

  /*
   * Set up scenario: Base = 1 (set when encoding started)
   * Current Insert Count = 3
   * Available via post-base: abs 1 (pb=0), abs 2 (pb=1)
   */
  uint64_t base = 1;

  /* Look up post-base 0 -> abs 1 -> "header2: value2" */
  result = SocketQPACK_lookup_indexed_postbase (
      table, base, 0, &name, &name_len, &value, &value_len);
  TEST_ASSERT (result == QPACK_OK, "lookup pb=0 should succeed");
  TEST_ASSERT (name_len == 7, "name_len should be 7");
  TEST_ASSERT (strncmp (name, "header2", 7) == 0, "name should be header2");
  TEST_ASSERT (value_len == 6, "value_len should be 6");
  TEST_ASSERT (strncmp (value, "value2", 6) == 0, "value should be value2");

  /* Look up post-base 1 -> abs 2 -> "header3: value3" */
  result = SocketQPACK_lookup_indexed_postbase (
      table, base, 1, &name, &name_len, &value, &value_len);
  TEST_ASSERT (result == QPACK_OK, "lookup pb=1 should succeed");
  TEST_ASSERT (name_len == 7, "name_len should be 7");
  TEST_ASSERT (strncmp (name, "header3", 7) == 0, "name should be header3");
  TEST_ASSERT (value_len == 6, "value_len should be 6");
  TEST_ASSERT (strncmp (value, "value3", 6) == 0, "value should be value3");

  /* Look up post-base 2 -> abs 3 (future, should fail) */
  result = SocketQPACK_lookup_indexed_postbase (
      table, base, 2, &name, &name_len, &value, &value_len);
  TEST_ASSERT (result == QPACK_ERR_FUTURE_INDEX, "lookup pb=2 should fail");

  /* NULL table */
  result = SocketQPACK_lookup_indexed_postbase (
      NULL, base, 0, &name, &name_len, &value, &value_len);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL table should fail");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test lookup with base = insert_count (no post-base entries).
 */
static void
test_table_lookup_no_postbase (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Result result;
  const char *name, *value;
  size_t name_len, value_len;

  printf ("  Table lookup with no post-base entries... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (arena, 4096);
  TEST_ASSERT (table != NULL, "table creation should succeed");

  /* Insert one entry */
  result = SocketQPACK_Table_insert_literal (table, "header1", 7, "value1", 6);
  TEST_ASSERT (result == QPACK_OK, "insert should succeed");

  /*
   * Base = Insert Count = 1 (no post-base entries)
   * Any post-base lookup should fail
   */
  uint64_t base = 1;

  result = SocketQPACK_lookup_indexed_postbase (
      table, base, 0, &name, &name_len, &value, &value_len);
  TEST_ASSERT (result == QPACK_ERR_FUTURE_INDEX,
               "lookup with no post-base should fail");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * BOUNDARY TESTS
 * ============================================================================
 */

/**
 * Test boundary value at max 4-bit prefix (14/15 transition).
 */
static void
test_prefix_boundary (void)
{
  unsigned char buf[16];
  uint64_t decoded;
  size_t written, consumed;
  SocketQPACK_Result result;

  printf ("  4-bit prefix boundary (14/15)... ");

  /* Index 14 should fit in single byte */
  result
      = SocketQPACK_encode_indexed_postbase (14, buf, sizeof (buf), &written);
  TEST_ASSERT (result == QPACK_OK, "encode pb=14 should succeed");
  TEST_ASSERT (written == 1, "pb=14 should be 1 byte");
  TEST_ASSERT ((buf[0] & 0x0F) == 14, "pb=14 lower nibble should be 14");

  /* Index 15 needs continuation */
  result
      = SocketQPACK_encode_indexed_postbase (15, buf, sizeof (buf), &written);
  TEST_ASSERT (result == QPACK_OK, "encode pb=15 should succeed");
  TEST_ASSERT (written == 2, "pb=15 should be 2 bytes");
  TEST_ASSERT ((buf[0] & 0x0F) == 15, "pb=15 lower nibble should be 15");
  TEST_ASSERT (buf[1] == 0x00, "pb=15 continuation should be 0");

  /* Verify decode works correctly at boundary */
  buf[0] = 0x1E; /* pb=14 */
  result = SocketQPACK_decode_indexed_postbase (buf, 1, &decoded, &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode pb=14 should succeed");
  TEST_ASSERT (decoded == 14, "decoded should be 14");

  buf[0] = 0x1F;
  buf[1] = 0x00; /* pb=15 */
  result = SocketQPACK_decode_indexed_postbase (buf, 2, &decoded, &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode pb=15 should succeed");
  TEST_ASSERT (decoded == 15, "decoded should be 15");

  printf ("PASS\n");
}

/**
 * Test maximum post-base index (large values).
 */
static void
test_max_index (void)
{
  unsigned char buf[16];
  uint64_t decoded;
  size_t written, consumed;
  SocketQPACK_Result result;

  printf ("  Maximum index values... ");

  /* Test large but representable values */
  uint64_t test_values[] = { 1000, 10000, 100000, 1000000 };

  for (size_t i = 0; i < sizeof (test_values) / sizeof (test_values[0]); i++)
    {
      result = SocketQPACK_encode_indexed_postbase (
          test_values[i], buf, sizeof (buf), &written);
      TEST_ASSERT (result == QPACK_OK, "encode large value should succeed");

      result = SocketQPACK_decode_indexed_postbase (
          buf, written, &decoded, &consumed);
      TEST_ASSERT (result == QPACK_OK, "decode large value should succeed");
      TEST_ASSERT (decoded == test_values[i],
                   "round-trip large value should match");
    }

  printf ("PASS\n");
}

/* ============================================================================
 * TEST SUITE
 * ============================================================================
 */

static void
run_pattern_tests (void)
{
  printf ("Pattern Identification Tests:\n");
  test_pattern_identification ();
}

static void
run_encode_tests (void)
{
  printf ("Encoding Tests (RFC 9204 Section 4.5.3):\n");
  test_encode_small_indices ();
  test_encode_large_indices ();
  test_encode_errors ();
}

static void
run_decode_tests (void)
{
  printf ("Decoding Tests (RFC 9204 Section 4.5.3):\n");
  test_decode_small_indices ();
  test_decode_large_indices ();
  test_decode_errors ();
}

static void
run_roundtrip_tests (void)
{
  printf ("Round-Trip Tests:\n");
  test_roundtrip ();
}

static void
run_validation_tests (void)
{
  printf ("Validation Tests (RFC 9204 Section 4.5.3):\n");
  test_validate_bounds ();
  test_convert_to_absolute ();
}

static void
run_table_tests (void)
{
  printf ("Table Lookup Tests:\n");
  test_table_lookup ();
  test_table_lookup_no_postbase ();
}

static void
run_boundary_tests (void)
{
  printf ("Boundary Tests:\n");
  test_prefix_boundary ();
  test_max_index ();
}

int
main (void)
{
  printf ("=== QPACK Indexed Field Line with Post-Base Index Tests "
          "(RFC 9204 Section 4.5.3) ===\n\n");

  run_pattern_tests ();
  printf ("\n");

  run_encode_tests ();
  printf ("\n");

  run_decode_tests ();
  printf ("\n");

  run_roundtrip_tests ();
  printf ("\n");

  run_validation_tests ();
  printf ("\n");

  run_table_tests ();
  printf ("\n");

  run_boundary_tests ();
  printf ("\n");

  printf ("=== All tests passed! ===\n");
  return 0;
}
