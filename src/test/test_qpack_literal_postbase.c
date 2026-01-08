/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_literal_postbase.c
 * @brief Unit tests for QPACK Literal Field Line with Post-Base Name Reference
 *        (RFC 9204 Section 4.5.5)
 *
 * Tests encoding, decoding, validation, and resolution of literal field lines
 * where the name is referenced from a post-base dynamic table entry.
 *
 * Test coverage includes:
 * - Basic encoding and decoding
 * - Never-index (N) flag handling
 * - Huffman encoding for values
 * - Post-base index validation
 * - Dynamic table name resolution
 * - Round-trip encode/decode
 * - Boundary conditions and error handling
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
 * BASIC ENCODING TESTS
 * ============================================================================
 */

/**
 * Test basic encoding of literal field line with post-base name reference.
 *
 * Encodes with N=0, name_index=0, plain text value.
 * Expected wire format: 0x00 | value_len | value_bytes
 */
static void
test_encode_basic (void)
{
  unsigned char output[256];
  size_t written;
  SocketQPACK_Result result;
  const unsigned char value[] = "test-value";
  size_t value_len = sizeof (value) - 1;

  printf ("  Encode basic literal with post-base name... ");

  result
      = SocketQPACK_encode_literal_postbase_name (output,
                                                  sizeof (output),
                                                  0, /* name_index */
                                                  0, /* never_index = false */
                                                  value,
                                                  value_len,
                                                  0, /* use_huffman = false */
                                                  &written);

  TEST_ASSERT (result == QPACK_OK, "Encoding should succeed");
  TEST_ASSERT (written > 0, "Should write some bytes");

  /* Verify first byte pattern: 0000 0 000 = 0x00 */
  TEST_ASSERT ((output[0] & 0xF8) == 0x00,
               "First byte pattern should be 0000 0");
  TEST_ASSERT ((output[0] & 0x07) == 0x00, "Name index should be 0");

  /* Verify value length byte (H=0, length=10) */
  TEST_ASSERT ((output[1] & 0x80) == 0x00, "Huffman flag should be 0");
  TEST_ASSERT ((output[1] & 0x7F) == value_len, "Value length should match");

  /* Verify value bytes */
  TEST_ASSERT (memcmp (output + 2, value, value_len) == 0,
               "Value should match");

  printf ("PASS\n");
}

/**
 * Test encoding with never-index flag set.
 *
 * N=1 should set bit 3 in the first byte.
 */
static void
test_encode_never_index (void)
{
  unsigned char output[256];
  size_t written;
  SocketQPACK_Result result;
  const unsigned char value[] = "secret";

  printf ("  Encode with never-index flag... ");

  result
      = SocketQPACK_encode_literal_postbase_name (output,
                                                  sizeof (output),
                                                  0, /* name_index */
                                                  1, /* never_index = true */
                                                  value,
                                                  sizeof (value) - 1,
                                                  0, /* use_huffman = false */
                                                  &written);

  TEST_ASSERT (result == QPACK_OK, "Encoding should succeed");

  /* Verify first byte pattern: 0000 1 000 = 0x08 */
  TEST_ASSERT ((output[0] & 0x08) == 0x08, "N flag should be set");
  TEST_ASSERT ((output[0] & 0xF0) == 0x00, "Top 4 bits should be 0000");

  printf ("PASS\n");
}

/**
 * Test encoding with larger name index.
 *
 * Name index = 7 should fit in 3 bits.
 * Name index = 10 should require multi-byte encoding.
 */
static void
test_encode_name_index (void)
{
  unsigned char output[256];
  size_t written;
  SocketQPACK_Result result;
  const unsigned char value[] = "v";

  printf ("  Encode with various name indices... ");

  /* Name index = 5 (fits in 3 bits) */
  result = SocketQPACK_encode_literal_postbase_name (
      output, sizeof (output), 5, 0, value, 1, 0, &written);

  TEST_ASSERT (result == QPACK_OK, "Index 5 should succeed");
  TEST_ASSERT ((output[0] & 0x07) == 5, "Index 5 in 3 bits");

  /* Name index = 7 (max value for 3 bits without continuation) */
  result = SocketQPACK_encode_literal_postbase_name (
      output, sizeof (output), 6, 0, value, 1, 0, &written);

  TEST_ASSERT (result == QPACK_OK, "Index 6 should succeed");
  TEST_ASSERT ((output[0] & 0x07) == 6, "Index 6 in 3 bits");

  /* Name index = 10 (requires multi-byte: 7 in prefix + continuation) */
  result = SocketQPACK_encode_literal_postbase_name (
      output, sizeof (output), 10, 0, value, 1, 0, &written);

  TEST_ASSERT (result == QPACK_OK, "Index 10 should succeed");
  TEST_ASSERT ((output[0] & 0x07) == 0x07, "Should use all 3 prefix bits");
  TEST_ASSERT (written >= 3, "Should have continuation byte");

  printf ("PASS\n");
}

/**
 * Test encoding with Huffman-encoded value.
 */
static void
test_encode_huffman_value (void)
{
  unsigned char output[256];
  size_t written;
  SocketQPACK_Result result;
  /* www.example.com compresses well with Huffman */
  const unsigned char value[] = "www.example.com";

  printf ("  Encode with Huffman value... ");

  result = SocketQPACK_encode_literal_postbase_name (output,
                                                     sizeof (output),
                                                     0,
                                                     0,
                                                     value,
                                                     sizeof (value) - 1,
                                                     1, /* use_huffman = true */
                                                     &written);

  TEST_ASSERT (result == QPACK_OK, "Encoding should succeed");

  /* Huffman flag should be set if compression was beneficial */
  int huffman_used = (output[1] & 0x80) != 0;
  if (huffman_used)
    {
      /* If Huffman was used, encoded length should be less */
      size_t encoded_value_len = output[1] & 0x7F;
      TEST_ASSERT (encoded_value_len < sizeof (value) - 1,
                   "Huffman should reduce size");
    }

  printf ("PASS\n");
}

/**
 * Test encoding with empty value.
 */
static void
test_encode_empty_value (void)
{
  unsigned char output[256];
  size_t written;
  SocketQPACK_Result result;

  printf ("  Encode with empty value... ");

  result = SocketQPACK_encode_literal_postbase_name (
      output, sizeof (output), 0, 0, NULL, 0, 0, &written);

  TEST_ASSERT (result == QPACK_OK, "Encoding should succeed");
  TEST_ASSERT (written == 2, "Should be 2 bytes (name_idx + value_len)");
  TEST_ASSERT ((output[1] & 0x7F) == 0, "Value length should be 0");

  printf ("PASS\n");
}

/* ============================================================================
 * BASIC DECODING TESTS
 * ============================================================================
 */

/**
 * Test basic decoding of literal field line with post-base name reference.
 */
static void
test_decode_basic (void)
{
  Arena_T arena;
  SocketQPACK_LiteralPostBaseName result;
  size_t consumed;
  SocketQPACK_Result qpack_result;

  /* Wire format: 0x00 (name_idx=0, N=0), 0x05 (value_len=5), "hello" */
  const unsigned char input[] = { 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' };

  printf ("  Decode basic literal with post-base name... ");

  arena = Arena_new ();

  qpack_result = SocketQPACK_decode_literal_postbase_name (
      input, sizeof (input), arena, &result, &consumed);

  TEST_ASSERT (qpack_result == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (consumed == sizeof (input), "Should consume all bytes");
  TEST_ASSERT (result.name_index == 0, "Name index should be 0");
  TEST_ASSERT (result.never_index == 0, "Never-index should be 0");
  TEST_ASSERT (result.value_huffman == 0, "Huffman flag should be 0");
  TEST_ASSERT (result.value_len == 5, "Value length should be 5");
  TEST_ASSERT (memcmp (result.value, "hello", 5) == 0, "Value should match");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test decoding with never-index flag.
 */
static void
test_decode_never_index (void)
{
  Arena_T arena;
  SocketQPACK_LiteralPostBaseName result;
  size_t consumed;
  SocketQPACK_Result qpack_result;

  /* Wire format: 0x08 (name_idx=0, N=1), 0x03 (value_len=3), "foo" */
  const unsigned char input[] = { 0x08, 0x03, 'f', 'o', 'o' };

  printf ("  Decode with never-index flag... ");

  arena = Arena_new ();

  qpack_result = SocketQPACK_decode_literal_postbase_name (
      input, sizeof (input), arena, &result, &consumed);

  TEST_ASSERT (qpack_result == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (result.never_index == 1, "Never-index should be 1");
  TEST_ASSERT (result.name_index == 0, "Name index should be 0");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test decoding with multi-byte name index.
 */
static void
test_decode_multibyte_index (void)
{
  Arena_T arena;
  SocketQPACK_LiteralPostBaseName result;
  size_t consumed;
  SocketQPACK_Result qpack_result;

  /* Wire format: name_idx=10 (0x07 + 0x03), value_len=1, "x" */
  /* 3-bit prefix: 7 in first byte, continuation: 10 - 7 = 3 */
  const unsigned char input[] = { 0x07, 0x03, 0x01, 'x' };

  printf ("  Decode with multi-byte name index... ");

  arena = Arena_new ();

  qpack_result = SocketQPACK_decode_literal_postbase_name (
      input, sizeof (input), arena, &result, &consumed);

  TEST_ASSERT (qpack_result == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (result.name_index == 10, "Name index should be 10");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test decoding with incomplete input.
 */
static void
test_decode_incomplete (void)
{
  Arena_T arena;
  SocketQPACK_LiteralPostBaseName result;
  size_t consumed;
  SocketQPACK_Result qpack_result;

  printf ("  Decode incomplete input... ");

  arena = Arena_new ();

  /* Empty input */
  qpack_result = SocketQPACK_decode_literal_postbase_name (
      (const unsigned char *)"", 0, arena, &result, &consumed);
  TEST_ASSERT (qpack_result == QPACK_INCOMPLETE, "Empty should be incomplete");

  /* Only first byte */
  const unsigned char partial1[] = { 0x00 };
  qpack_result = SocketQPACK_decode_literal_postbase_name (
      partial1, sizeof (partial1), arena, &result, &consumed);
  TEST_ASSERT (qpack_result == QPACK_INCOMPLETE,
               "Partial should be incomplete");

  /* Missing value bytes */
  const unsigned char partial2[] = { 0x00, 0x05, 'h', 'e' };
  qpack_result = SocketQPACK_decode_literal_postbase_name (
      partial2, sizeof (partial2), arena, &result, &consumed);
  TEST_ASSERT (qpack_result == QPACK_INCOMPLETE,
               "Missing value bytes should be incomplete");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test decoding rejects invalid bit pattern.
 */
static void
test_decode_invalid_pattern (void)
{
  Arena_T arena;
  SocketQPACK_LiteralPostBaseName result;
  size_t consumed;
  SocketQPACK_Result qpack_result;

  printf ("  Decode rejects invalid pattern... ");

  arena = Arena_new ();

  /* Pattern 0x10 (bits 7-4 = 0001, not 0000) */
  const unsigned char invalid1[] = { 0x10, 0x01, 'x' };
  qpack_result = SocketQPACK_decode_literal_postbase_name (
      invalid1, sizeof (invalid1), arena, &result, &consumed);
  TEST_ASSERT (qpack_result == QPACK_ERR_INTERNAL,
               "Should reject 0001 pattern");

  /* Pattern 0x80 (indexed field line pattern) */
  const unsigned char invalid2[] = { 0x80, 0x01, 'x' };
  qpack_result = SocketQPACK_decode_literal_postbase_name (
      invalid2, sizeof (invalid2), arena, &result, &consumed);
  TEST_ASSERT (qpack_result == QPACK_ERR_INTERNAL,
               "Should reject 1xxx pattern");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * ROUND-TRIP TESTS
 * ============================================================================
 */

/**
 * Test round-trip encode/decode.
 */
static void
test_roundtrip (void)
{
  Arena_T arena;
  unsigned char buffer[256];
  size_t written;
  SocketQPACK_LiteralPostBaseName decoded;
  size_t consumed;
  SocketQPACK_Result result;
  const unsigned char value[] = "application/json";
  size_t value_len = sizeof (value) - 1;

  printf ("  Round-trip encode/decode... ");

  arena = Arena_new ();

  /* Test various combinations */
  struct
  {
    uint64_t name_idx;
    int never_idx;
    int huffman;
  } test_cases[] = {
    { 0, 0, 0 }, { 0, 1, 0 }, { 5, 0, 0 }, { 10, 0, 0 },
    { 0, 0, 1 }, { 0, 1, 1 }, { 5, 1, 1 },
  };

  for (size_t i = 0; i < sizeof (test_cases) / sizeof (test_cases[0]); i++)
    {
      /* Encode */
      result
          = SocketQPACK_encode_literal_postbase_name (buffer,
                                                      sizeof (buffer),
                                                      test_cases[i].name_idx,
                                                      test_cases[i].never_idx,
                                                      value,
                                                      value_len,
                                                      test_cases[i].huffman,
                                                      &written);
      TEST_ASSERT (result == QPACK_OK, "Encode should succeed");

      /* Decode */
      result = SocketQPACK_decode_literal_postbase_name (
          buffer, written, arena, &decoded, &consumed);
      TEST_ASSERT (result == QPACK_OK, "Decode should succeed");

      /* Verify */
      TEST_ASSERT (consumed == written, "Should consume all encoded bytes");
      TEST_ASSERT (decoded.name_index == test_cases[i].name_idx,
                   "Name index should match");
      TEST_ASSERT (decoded.never_index == test_cases[i].never_idx,
                   "Never-index should match");
      TEST_ASSERT (decoded.value_len == value_len, "Value length should match");
      TEST_ASSERT (memcmp (decoded.value, value, value_len) == 0,
                   "Value should match");
    }

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * VALIDATION TESTS
 * ============================================================================
 */

/**
 * Test post-base index validation.
 */
static void
test_validate_postbase_index (void)
{
  SocketQPACK_Result result;

  printf ("  Validate post-base index... ");

  /*
   * Valid cases:
   * - base=5, insert_count=10: post_base can be 0-4 (abs 5-9)
   */
  result = SocketQPACK_validate_literal_postbase_index (5, 10, 0);
  TEST_ASSERT (result == QPACK_OK, "post_base=0 should be valid");

  result = SocketQPACK_validate_literal_postbase_index (5, 10, 4);
  TEST_ASSERT (result == QPACK_OK, "post_base=4 should be valid");

  /*
   * Invalid cases:
   * - post_base >= insert_count - base: references future entry
   */
  result = SocketQPACK_validate_literal_postbase_index (5, 10, 5);
  TEST_ASSERT (result == QPACK_ERR_FUTURE_INDEX,
               "post_base=5 should be future");

  result = SocketQPACK_validate_literal_postbase_index (5, 10, 100);
  TEST_ASSERT (result == QPACK_ERR_FUTURE_INDEX,
               "post_base=100 should be future");

  /* Edge case: base = 0 */
  result = SocketQPACK_validate_literal_postbase_index (0, 5, 0);
  TEST_ASSERT (result == QPACK_OK, "base=0, post_base=0 should be valid");

  result = SocketQPACK_validate_literal_postbase_index (0, 5, 4);
  TEST_ASSERT (result == QPACK_OK, "base=0, post_base=4 should be valid");

  result = SocketQPACK_validate_literal_postbase_index (0, 5, 5);
  TEST_ASSERT (result == QPACK_ERR_FUTURE_INDEX,
               "base=0, post_base=5 should be future");

  /* Edge case: base = insert_count - 1 (only one post-base entry) */
  result = SocketQPACK_validate_literal_postbase_index (4, 5, 0);
  TEST_ASSERT (result == QPACK_OK,
               "base=insert_count-1, post_base=0 should be valid");

  result = SocketQPACK_validate_literal_postbase_index (4, 5, 1);
  TEST_ASSERT (result == QPACK_ERR_FUTURE_INDEX,
               "base=insert_count-1, post_base=1 should be future");

  /* Edge case: base = insert_count (no post-base entries) */
  result = SocketQPACK_validate_literal_postbase_index (5, 5, 0);
  TEST_ASSERT (result == QPACK_ERR_FUTURE_INDEX,
               "base=insert_count should have no valid post-base");

  printf ("PASS\n");
}

/* ============================================================================
 * DYNAMIC TABLE RESOLUTION TESTS
 * ============================================================================
 */

/**
 * Test resolving post-base name from dynamic table.
 */
static void
test_resolve_postbase_name (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  const char *name;
  size_t name_len;
  SocketQPACK_Result result;

  printf ("  Resolve post-base name from table... ");

  arena = Arena_new ();

  /* Create dynamic table and add entries */
  table = SocketQPACK_Table_new (arena, 4096);
  TEST_ASSERT (table != NULL, "Table creation should succeed");

  /* Insert some entries: abs_idx 0, 1, 2, 3, 4 */
  result = SocketQPACK_Table_insert_literal (
      table, "content-type", 12, "text/html", 9);
  TEST_ASSERT (result == QPACK_OK, "Insert 0 should succeed");

  result = SocketQPACK_Table_insert_literal (
      table, "content-length", 14, "1234", 4);
  TEST_ASSERT (result == QPACK_OK, "Insert 1 should succeed");

  result
      = SocketQPACK_Table_insert_literal (table, "host", 4, "example.com", 11);
  TEST_ASSERT (result == QPACK_OK, "Insert 2 should succeed");

  result = SocketQPACK_Table_insert_literal (
      table, "cache-control", 13, "no-cache", 8);
  TEST_ASSERT (result == QPACK_OK, "Insert 3 should succeed");

  result = SocketQPACK_Table_insert_literal (table, "accept", 6, "*/*", 3);
  TEST_ASSERT (result == QPACK_OK, "Insert 4 should succeed");

  /* insert_count should now be 5 */
  TEST_ASSERT (SocketQPACK_Table_insert_count (table) == 5,
               "Insert count should be 5");

  /*
   * With base=2, post-base entries are at abs_idx 2, 3, 4
   * - post_base=0 -> abs=2 -> "host"
   * - post_base=1 -> abs=3 -> "cache-control"
   * - post_base=2 -> abs=4 -> "accept"
   */
  result = SocketQPACK_resolve_postbase_name (table, 2, 0, &name, &name_len);
  TEST_ASSERT (result == QPACK_OK, "Resolve post_base=0 should succeed");
  TEST_ASSERT (name_len == 4, "Name length should be 4");
  TEST_ASSERT (memcmp (name, "host", 4) == 0, "Name should be 'host'");

  result = SocketQPACK_resolve_postbase_name (table, 2, 1, &name, &name_len);
  TEST_ASSERT (result == QPACK_OK, "Resolve post_base=1 should succeed");
  TEST_ASSERT (name_len == 13, "Name length should be 13");
  TEST_ASSERT (memcmp (name, "cache-control", 13) == 0,
               "Name should be 'cache-control'");

  result = SocketQPACK_resolve_postbase_name (table, 2, 2, &name, &name_len);
  TEST_ASSERT (result == QPACK_OK, "Resolve post_base=2 should succeed");
  TEST_ASSERT (name_len == 6, "Name length should be 6");
  TEST_ASSERT (memcmp (name, "accept", 6) == 0, "Name should be 'accept'");

  /* post_base=3 should fail (abs=5 >= insert_count=5) */
  result = SocketQPACK_resolve_postbase_name (table, 2, 3, &name, &name_len);
  TEST_ASSERT (result == QPACK_ERR_FUTURE_INDEX,
               "Resolve post_base=3 should fail");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * ERROR HANDLING TESTS
 * ============================================================================
 */

/**
 * Test NULL parameter handling.
 */
static void
test_null_params (void)
{
  Arena_T arena;
  unsigned char buffer[256];
  size_t written;
  SocketQPACK_LiteralPostBaseName decoded;
  size_t consumed;
  SocketQPACK_Result result;
  const unsigned char value[] = "test";

  printf ("  NULL parameter handling... ");

  arena = Arena_new ();

  /* Encode: NULL output */
  result = SocketQPACK_encode_literal_postbase_name (
      NULL, 256, 0, 0, value, 4, 0, &written);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL output should fail");

  /* Encode: NULL bytes_written */
  result = SocketQPACK_encode_literal_postbase_name (
      buffer, sizeof (buffer), 0, 0, value, 4, 0, NULL);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM,
               "NULL bytes_written should fail");

  /* Decode: NULL result */
  result = SocketQPACK_decode_literal_postbase_name (
      buffer, sizeof (buffer), arena, NULL, &consumed);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL result should fail");

  /* Decode: NULL consumed */
  result = SocketQPACK_decode_literal_postbase_name (
      buffer, sizeof (buffer), arena, &decoded, NULL);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL consumed should fail");

  /* Decode: NULL arena */
  result = SocketQPACK_decode_literal_postbase_name (
      buffer, sizeof (buffer), NULL, &decoded, &consumed);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL arena should fail");

  /* Resolve: NULL table */
  const char *name;
  size_t name_len;
  result = SocketQPACK_resolve_postbase_name (NULL, 0, 0, &name, &name_len);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL table should fail");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test buffer size handling.
 */
static void
test_buffer_size (void)
{
  unsigned char buffer[4];
  size_t written;
  SocketQPACK_Result result;
  const unsigned char value[] = "a long value that exceeds buffer";

  printf ("  Buffer size handling... ");

  /* Buffer too small for value */
  result = SocketQPACK_encode_literal_postbase_name (
      buffer, sizeof (buffer), 0, 0, value, sizeof (value) - 1, 0, &written);
  TEST_ASSERT (result == QPACK_ERR_TABLE_SIZE, "Small buffer should fail");

  /* Zero size buffer */
  result = SocketQPACK_encode_literal_postbase_name (
      buffer, 0, 0, 0, value, sizeof (value) - 1, 0, &written);
  TEST_ASSERT (result == QPACK_ERR_TABLE_SIZE, "Zero size buffer should fail");

  printf ("PASS\n");
}

/* ============================================================================
 * MAIN TEST RUNNER
 * ============================================================================
 */

int
main (void)
{
  printf ("QPACK Literal Field Line with Post-Base Name Reference Tests\n");
  printf ("(RFC 9204 Section 4.5.5)\n\n");

  printf ("Encoding tests:\n");
  test_encode_basic ();
  test_encode_never_index ();
  test_encode_name_index ();
  test_encode_huffman_value ();
  test_encode_empty_value ();

  printf ("\nDecoding tests:\n");
  test_decode_basic ();
  test_decode_never_index ();
  test_decode_multibyte_index ();
  test_decode_incomplete ();
  test_decode_invalid_pattern ();

  printf ("\nRound-trip tests:\n");
  test_roundtrip ();

  printf ("\nValidation tests:\n");
  test_validate_postbase_index ();

  printf ("\nDynamic table resolution tests:\n");
  test_resolve_postbase_name ();

  printf ("\nError handling tests:\n");
  test_null_params ();
  test_buffer_size ();

  printf ("\nAll tests PASSED!\n");
  return 0;
}
