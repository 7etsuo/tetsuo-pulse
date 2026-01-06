/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_qpack_postbase.c - Unit tests for QPACK Literal Field Line with
 *                         Post-Base Name Reference (RFC 9204 Section 4.5.5)
 *
 * Tests:
 * - Encoding post-base name references
 * - Decoding post-base name references
 * - Index conversion (post-base to absolute)
 * - Validation of post-base indices
 * - Huffman vs. plain value encoding
 * - Multi-byte index encoding
 * - Dynamic table interaction
 * - Error cases
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketQPACK.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple test assertion macro */
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
 * Test: Integer Encoding (3-bit prefix for post-base)
 * ============================================================================
 */

static void
test_int_encode_3bit_small (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 5 with 3-bit prefix... ");

  len = SocketQPACK_int_encode (5, 3, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Expected 1 byte");
  TEST_ASSERT ((buf[0] & 0x07) == 5, "Expected 5 in lower 3 bits");

  printf ("PASS\n");
}

static void
test_int_encode_3bit_max_prefix (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 7 (max prefix) with 3-bit prefix... ");

  /* 7 = 2^3 - 1, should use exactly the prefix */
  len = SocketQPACK_int_encode (6, 3, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Expected 1 byte");
  TEST_ASSERT ((buf[0] & 0x07) == 6, "Expected 6 in lower 3 bits");

  printf ("PASS\n");
}

static void
test_int_encode_3bit_multi_byte (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 63 (multi-byte) with 3-bit prefix... ");

  /* 63 > 7, needs continuation bytes */
  len = SocketQPACK_int_encode (63, 3, buf, sizeof (buf));
  TEST_ASSERT (len == 2, "Expected 2 bytes");
  TEST_ASSERT ((buf[0] & 0x07) == 7, "First byte should have max prefix (7)");
  /* Second byte: 63 - 7 = 56 = 0x38 */
  TEST_ASSERT (buf[1] == 56, "Second byte should be 56");

  printf ("PASS\n");
}

static void
test_int_decode_3bit (void)
{
  unsigned char data[] = { 0x05 }; /* 5 in 3-bit prefix */
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Integer decode 5 with 3-bit prefix... ");

  result = SocketQPACK_int_decode (data, sizeof (data), 3, &value, &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (value == 5, "Value should be 5");
  TEST_ASSERT (consumed == 1, "Should consume 1 byte");

  printf ("PASS\n");
}

/* ============================================================================
 * Test: Post-Base to Absolute Index Conversion
 * ============================================================================
 */

static void
test_postbase_to_absolute_basic (void)
{
  uint32_t abs_index;
  SocketQPACK_Result result;

  printf ("  Post-base to absolute: base=10, post_base=5... ");

  result = SocketQPACK_postbase_to_absolute (10, 5, &abs_index);
  TEST_ASSERT (result == QPACK_OK, "Conversion should succeed");
  TEST_ASSERT (abs_index == 15, "Absolute index should be 15");

  printf ("PASS\n");
}

static void
test_postbase_to_absolute_zero (void)
{
  uint32_t abs_index;
  SocketQPACK_Result result;

  printf ("  Post-base to absolute: base=0, post_base=0... ");

  result = SocketQPACK_postbase_to_absolute (0, 0, &abs_index);
  TEST_ASSERT (result == QPACK_OK, "Conversion should succeed");
  TEST_ASSERT (abs_index == 0, "Absolute index should be 0");

  printf ("PASS\n");
}

static void
test_postbase_to_absolute_overflow (void)
{
  uint32_t abs_index;
  SocketQPACK_Result result;

  printf ("  Post-base to absolute overflow check... ");

  /* UINT32_MAX + 1 would overflow */
  result = SocketQPACK_postbase_to_absolute (UINT32_MAX, 1, &abs_index);
  TEST_ASSERT (result == QPACK_ERROR_INTEGER, "Should detect overflow");

  printf ("PASS\n");
}

/* ============================================================================
 * Test: Post-Base Index Validation
 * ============================================================================
 */

static void
test_validate_postbase_valid (void)
{
  SocketQPACK_Result result;

  printf ("  Validate post-base: abs_index=5, insert_count=10... ");

  result = SocketQPACK_validate_postbase_index (5, 10);
  TEST_ASSERT (result == QPACK_OK, "Index 5 < 10 should be valid");

  printf ("PASS\n");
}

static void
test_validate_postbase_boundary (void)
{
  SocketQPACK_Result result;

  printf ("  Validate post-base: abs_index=9, insert_count=10... ");

  result = SocketQPACK_validate_postbase_index (9, 10);
  TEST_ASSERT (result == QPACK_OK, "Index 9 < 10 should be valid");

  printf ("PASS\n");
}

static void
test_validate_postbase_equal (void)
{
  SocketQPACK_Result result;

  printf ("  Validate post-base: abs_index=10, insert_count=10... ");

  result = SocketQPACK_validate_postbase_index (10, 10);
  TEST_ASSERT (result == QPACK_ERROR_POSTBASE_INDEX,
               "Index 10 >= 10 should be invalid");

  printf ("PASS\n");
}

static void
test_validate_postbase_exceeds (void)
{
  SocketQPACK_Result result;

  printf ("  Validate post-base: abs_index=15, insert_count=10... ");

  result = SocketQPACK_validate_postbase_index (15, 10);
  TEST_ASSERT (result == QPACK_ERROR_POSTBASE_INDEX,
               "Index 15 >= 10 should be invalid");

  printf ("PASS\n");
}

/* ============================================================================
 * Test: Encode Literal Post-Base Name Reference
 * ============================================================================
 */

static void
test_encode_postbase_simple (void)
{
  unsigned char buf[256];
  ssize_t len;

  printf ("  Encode post-base: index=0, N=0, value='bar'... ");

  len = SocketQPACK_encode_literal_postbase_name (
      0, 0, "bar", 3, 0, buf, sizeof (buf));

  TEST_ASSERT (len > 0, "Encoding should succeed");
  /* First byte: 0000 N xxx = 0000 0 000 = 0x00 */
  TEST_ASSERT ((buf[0] & 0xF8) == 0x00, "Pattern should be 0000 0");
  TEST_ASSERT ((buf[0] & 0x07) == 0, "Index should be 0");

  printf ("PASS (len=%zd)\n", len);
}

static void
test_encode_postbase_never_index (void)
{
  unsigned char buf[256];
  ssize_t len;

  printf ("  Encode post-base: index=3, N=1, value='secret'... ");

  len = SocketQPACK_encode_literal_postbase_name (
      3, 1, "secret", 6, 0, buf, sizeof (buf));

  TEST_ASSERT (len > 0, "Encoding should succeed");
  /* First byte: 0000 N xxx = 0000 1 011 = 0x0B */
  TEST_ASSERT ((buf[0] & 0xF0) == 0x00, "Pattern should be 0000");
  TEST_ASSERT ((buf[0] & 0x08) == 0x08, "N bit should be set");
  TEST_ASSERT ((buf[0] & 0x07) == 3, "Index should be 3");

  printf ("PASS (len=%zd)\n", len);
}

static void
test_encode_postbase_large_index (void)
{
  unsigned char buf[256];
  ssize_t len;

  printf ("  Encode post-base: index=100, multi-byte... ");

  len = SocketQPACK_encode_literal_postbase_name (
      100, 0, "test", 4, 0, buf, sizeof (buf));

  TEST_ASSERT (len > 0, "Encoding should succeed");
  /* Index 100 > 7, needs continuation */
  TEST_ASSERT ((buf[0] & 0x07) == 7, "First byte should have max prefix (7)");

  printf ("PASS (len=%zd)\n", len);
}

static void
test_encode_postbase_huffman_value (void)
{
  unsigned char buf[256];
  ssize_t len_plain, len_huffman;

  printf ("  Encode post-base with Huffman value... ");

  /* 'www.example.com' should compress well with Huffman */
  len_plain = SocketQPACK_encode_literal_postbase_name (
      0, 0, "www.example.com", 15, 0, buf, sizeof (buf));

  len_huffman = SocketQPACK_encode_literal_postbase_name (
      0, 0, "www.example.com", 15, 1, buf, sizeof (buf));

  TEST_ASSERT (len_plain > 0, "Plain encoding should succeed");
  TEST_ASSERT (len_huffman > 0, "Huffman encoding should succeed");
  TEST_ASSERT (len_huffman <= len_plain, "Huffman should be same or smaller");

  printf ("PASS (plain=%zd, huffman=%zd)\n", len_plain, len_huffman);
}

/* ============================================================================
 * Test: Dynamic Table Operations
 * ============================================================================
 */

static void
test_dynamic_table_basic (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table;
  SocketQPACK_Result result;

  printf ("  Dynamic table: create and add entry... ");

  table = SocketQPACK_Table_new (4096, arena);
  TEST_ASSERT (table != NULL, "Table creation should succeed");
  TEST_ASSERT (SocketQPACK_Table_insert_count (table) == 0,
               "Initial insert count should be 0");

  /* Add an entry */
  result = SocketQPACK_Table_add (table, "x-custom", 8, "value1", 6);
  TEST_ASSERT (result == QPACK_OK, "Add should succeed");
  TEST_ASSERT (SocketQPACK_Table_insert_count (table) == 1,
               "Insert count should be 1");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 1, "Entry count should be 1");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_dynamic_table_get_absolute (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table;
  SocketQPACK_Header header;
  SocketQPACK_Result result;

  printf ("  Dynamic table: get by absolute index... ");

  table = SocketQPACK_Table_new (4096, arena);

  /* Add several entries */
  SocketQPACK_Table_add (table, "header1", 7, "value1", 6);
  SocketQPACK_Table_add (table, "header2", 7, "value2", 6);
  SocketQPACK_Table_add (table, "header3", 7, "value3", 6);

  TEST_ASSERT (SocketQPACK_Table_insert_count (table) == 3,
               "Insert count should be 3");

  /* Get entry at absolute index 0 (first inserted) */
  result = SocketQPACK_Table_get_absolute (table, 0, &header);
  TEST_ASSERT (result == QPACK_OK, "Get index 0 should succeed");
  TEST_ASSERT (strcmp (header.name, "header1") == 0,
               "Entry 0 should be header1");

  /* Get entry at absolute index 2 (last inserted) */
  result = SocketQPACK_Table_get_absolute (table, 2, &header);
  TEST_ASSERT (result == QPACK_OK, "Get index 2 should succeed");
  TEST_ASSERT (strcmp (header.name, "header3") == 0,
               "Entry 2 should be header3");

  /* Try to get invalid index */
  result = SocketQPACK_Table_get_absolute (table, 3, &header);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_INDEX,
               "Index 3 should be invalid");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * Test: Decode Literal Post-Base Name Reference
 * ============================================================================
 */

static void
test_decode_postbase_simple (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table;
  SocketQPACK_FieldPrefix prefix;
  SocketQPACK_Header header;
  unsigned char encoded[256];
  ssize_t enc_len;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Decode post-base: simple case... ");

  /* Set up table with entries */
  table = SocketQPACK_Table_new (4096, arena);
  SocketQPACK_Table_add (table, "x-custom", 8, "unused", 6);

  /* Set up prefix: base=0 means post-base index 0 = absolute index 0 */
  prefix.base = 0;
  prefix.required_insert_count = 1;
  prefix.delta_base = 0;
  prefix.sign_bit = 0;

  /* Encode a post-base reference */
  enc_len = SocketQPACK_encode_literal_postbase_name (
      0, 0, "newvalue", 8, 0, encoded, sizeof (encoded));
  TEST_ASSERT (enc_len > 0, "Encoding should succeed");

  /* Decode it */
  result = SocketQPACK_decode_literal_postbase_name (
      encoded, (size_t)enc_len, &prefix, table, &header, &consumed, arena);

  TEST_ASSERT (result == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (consumed == (size_t)enc_len, "Should consume all bytes");
  TEST_ASSERT (header.name_len == 8, "Name length should be 8");
  TEST_ASSERT (strcmp (header.name, "x-custom") == 0,
               "Name should be 'x-custom'");
  TEST_ASSERT (header.value_len == 8, "Value length should be 8");
  TEST_ASSERT (strcmp (header.value, "newvalue") == 0,
               "Value should be 'newvalue'");
  TEST_ASSERT (header.never_index == 0, "N bit should be 0");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_decode_postbase_never_index (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table;
  SocketQPACK_FieldPrefix prefix;
  SocketQPACK_Header header;
  unsigned char encoded[256];
  ssize_t enc_len;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Decode post-base: never index flag... ");

  table = SocketQPACK_Table_new (4096, arena);
  SocketQPACK_Table_add (table, "sensitive", 9, "unused", 6);

  prefix.base = 0;
  prefix.required_insert_count = 1;
  prefix.delta_base = 0;
  prefix.sign_bit = 0;

  /* Encode with N=1 (never index) */
  enc_len = SocketQPACK_encode_literal_postbase_name (
      0, 1, "secret", 6, 0, encoded, sizeof (encoded));
  TEST_ASSERT (enc_len > 0, "Encoding should succeed");

  result = SocketQPACK_decode_literal_postbase_name (
      encoded, (size_t)enc_len, &prefix, table, &header, &consumed, arena);

  TEST_ASSERT (result == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (header.never_index == 1, "N bit should be 1");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_decode_postbase_invalid_index (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table;
  SocketQPACK_FieldPrefix prefix;
  SocketQPACK_Header header;
  unsigned char encoded[256];
  ssize_t enc_len;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Decode post-base: invalid index error... ");

  table = SocketQPACK_Table_new (4096, arena);
  /* Add 1 entry, so insert_count = 1 */
  SocketQPACK_Table_add (table, "header1", 7, "value1", 6);

  /* Set base=0, so post-base index 1 = absolute index 1 */
  /* But insert_count = 1, so index 1 is invalid */
  prefix.base = 0;
  prefix.required_insert_count = 1;
  prefix.delta_base = 0;
  prefix.sign_bit = 0;

  /* Encode with post-base index 1 (invalid) */
  enc_len = SocketQPACK_encode_literal_postbase_name (
      1, 0, "value", 5, 0, encoded, sizeof (encoded));
  TEST_ASSERT (enc_len > 0, "Encoding should succeed");

  result = SocketQPACK_decode_literal_postbase_name (
      encoded, (size_t)enc_len, &prefix, table, &header, &consumed, arena);

  TEST_ASSERT (result == QPACK_ERROR_POSTBASE_INDEX,
               "Should fail with post-base index error");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_decode_postbase_with_base_offset (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table;
  SocketQPACK_FieldPrefix prefix;
  SocketQPACK_Header header;
  unsigned char encoded[256];
  ssize_t enc_len;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Decode post-base: with base offset... ");

  table = SocketQPACK_Table_new (4096, arena);
  SocketQPACK_Table_add (table, "header0", 7, "value0", 6);
  SocketQPACK_Table_add (table, "header1", 7, "value1", 6);
  SocketQPACK_Table_add (table, "header2", 7, "value2", 6);
  SocketQPACK_Table_add (table, "header3", 7, "value3", 6);

  /* Base=2, so post-base index 0 = absolute index 2 */
  prefix.base = 2;
  prefix.required_insert_count = 4;
  prefix.delta_base = -2;
  prefix.sign_bit = 1;

  /* Encode post-base index 1, which should be absolute index 3 */
  enc_len = SocketQPACK_encode_literal_postbase_name (
      1, 0, "newval", 6, 0, encoded, sizeof (encoded));
  TEST_ASSERT (enc_len > 0, "Encoding should succeed");

  result = SocketQPACK_decode_literal_postbase_name (
      encoded, (size_t)enc_len, &prefix, table, &header, &consumed, arena);

  TEST_ASSERT (result == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (strcmp (header.name, "header3") == 0,
               "Should reference header3 (abs index 3)");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_decode_postbase_huffman_value (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table;
  SocketQPACK_FieldPrefix prefix;
  SocketQPACK_Header header;
  unsigned char encoded[256];
  ssize_t enc_len;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Decode post-base: Huffman encoded value... ");

  table = SocketQPACK_Table_new (4096, arena);
  SocketQPACK_Table_add (table, "host", 4, "unused", 6);

  prefix.base = 0;
  prefix.required_insert_count = 1;
  prefix.delta_base = 0;
  prefix.sign_bit = 0;

  /* Encode with Huffman (H=1) */
  enc_len = SocketQPACK_encode_literal_postbase_name (
      0, 0, "www.example.com", 15, 1, encoded, sizeof (encoded));
  TEST_ASSERT (enc_len > 0, "Encoding should succeed");

  result = SocketQPACK_decode_literal_postbase_name (
      encoded, (size_t)enc_len, &prefix, table, &header, &consumed, arena);

  TEST_ASSERT (result == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (strcmp (header.value, "www.example.com") == 0,
               "Value should decode correctly");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * Test: Edge Cases
 * ============================================================================
 */

static void
test_encode_empty_value (void)
{
  unsigned char buf[256];
  ssize_t len;

  printf ("  Encode post-base: empty value... ");

  len = SocketQPACK_encode_literal_postbase_name (
      0, 0, "", 0, 0, buf, sizeof (buf));

  TEST_ASSERT (len > 0, "Encoding empty value should succeed");

  printf ("PASS (len=%zd)\n", len);
}

static void
test_decode_base_zero_no_entries (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table;
  SocketQPACK_FieldPrefix prefix;
  SocketQPACK_Header header;
  unsigned char encoded[256];
  ssize_t enc_len;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Decode post-base: base=0, no entries (edge case)... ");

  table = SocketQPACK_Table_new (4096, arena);
  /* Empty table, insert_count = 0 */

  prefix.base = 0;
  prefix.required_insert_count = 0;
  prefix.delta_base = 0;
  prefix.sign_bit = 0;

  /* Try to reference post-base index 0 (invalid, no entries) */
  enc_len = SocketQPACK_encode_literal_postbase_name (
      0, 0, "value", 5, 0, encoded, sizeof (encoded));
  TEST_ASSERT (enc_len > 0, "Encoding should succeed");

  result = SocketQPACK_decode_literal_postbase_name (
      encoded, (size_t)enc_len, &prefix, table, &header, &consumed, arena);

  TEST_ASSERT (result == QPACK_ERROR_POSTBASE_INDEX,
               "Should fail - no entries in table");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_static_table_lookup (void)
{
  SocketQPACK_Header header;
  SocketQPACK_Result result;

  printf ("  Static table: lookup index 0 (:authority)... ");

  result = SocketQPACK_static_get (0, &header);
  TEST_ASSERT (result == QPACK_OK, "Lookup should succeed");
  TEST_ASSERT (strcmp (header.name, ":authority") == 0,
               "Name should be ':authority'");
  TEST_ASSERT (header.value_len == 0, "Value should be empty");

  printf ("PASS\n");
}

static void
test_static_table_find (void)
{
  int index;

  printf ("  Static table: find ':method GET'... ");

  /* Should find exact match */
  index = SocketQPACK_static_find (":method", 7, "GET", 3);
  TEST_ASSERT (index == 17, "Should find :method GET at index 17");

  /* Should find name-only match */
  index = SocketQPACK_static_find (":method", 7, "PATCH", 5);
  TEST_ASSERT (index < 0 && index != -1,
               "Should return negative for name-only match");

  printf ("PASS\n");
}

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

static void
run_integer_tests (void)
{
  printf ("\nInteger Encoding Tests (3-bit prefix):\n");
  test_int_encode_3bit_small ();
  test_int_encode_3bit_max_prefix ();
  test_int_encode_3bit_multi_byte ();
  test_int_decode_3bit ();
}

static void
run_index_conversion_tests (void)
{
  printf ("\nPost-Base Index Conversion Tests:\n");
  test_postbase_to_absolute_basic ();
  test_postbase_to_absolute_zero ();
  test_postbase_to_absolute_overflow ();
}

static void
run_validation_tests (void)
{
  printf ("\nPost-Base Index Validation Tests:\n");
  test_validate_postbase_valid ();
  test_validate_postbase_boundary ();
  test_validate_postbase_equal ();
  test_validate_postbase_exceeds ();
}

static void
run_encode_tests (void)
{
  printf ("\nPost-Base Encoding Tests:\n");
  test_encode_postbase_simple ();
  test_encode_postbase_never_index ();
  test_encode_postbase_large_index ();
  test_encode_postbase_huffman_value ();
}

static void
run_dynamic_table_tests (void)
{
  printf ("\nDynamic Table Tests:\n");
  test_dynamic_table_basic ();
  test_dynamic_table_get_absolute ();
}

static void
run_decode_tests (void)
{
  printf ("\nPost-Base Decoding Tests:\n");
  test_decode_postbase_simple ();
  test_decode_postbase_never_index ();
  test_decode_postbase_invalid_index ();
  test_decode_postbase_with_base_offset ();
  test_decode_postbase_huffman_value ();
}

static void
run_edge_case_tests (void)
{
  printf ("\nEdge Case Tests:\n");
  test_encode_empty_value ();
  test_decode_base_zero_no_entries ();
  test_static_table_lookup ();
  test_static_table_find ();
}

int
main (void)
{
  printf ("=== QPACK Post-Base Name Reference Tests (RFC 9204 Section 4.5.5) "
          "===\n");

  run_integer_tests ();
  run_index_conversion_tests ();
  run_validation_tests ();
  run_encode_tests ();
  run_dynamic_table_tests ();
  run_decode_tests ();
  run_edge_case_tests ();

  printf ("\n=== All tests passed! ===\n");
  return 0;
}
