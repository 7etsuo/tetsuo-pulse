/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_insert_literal.c
 * @brief Unit tests for QPACK Insert with Literal Name (RFC 9204 Section 4.3.3)
 *
 * Tests the Insert with Literal Name instruction encoding, decoding, and
 * dynamic table insertion functionality.
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

/**
 * Test dynamic table creation.
 */
static void
test_table_creation (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;

  printf ("  Table creation... ");

  arena = Arena_new ();
  TEST_ASSERT (arena != NULL, "arena creation");

  table = SocketQPACK_Table_new (arena, 4096);
  TEST_ASSERT (table != NULL, "table creation");

  TEST_ASSERT (SocketQPACK_Table_size (table) == 0, "initial size is 0");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 0, "initial count is 0");
  TEST_ASSERT (SocketQPACK_Table_max_size (table) == 4096, "max_size is 4096");
  TEST_ASSERT (SocketQPACK_Table_insert_count (table) == 0,
               "insert_count is 0");
  TEST_ASSERT (SocketQPACK_Table_dropped_count (table) == 0,
               "dropped_count is 0");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test NULL arena handling.
 */
static void
test_table_null_arena (void)
{
  SocketQPACK_Table_T table;

  printf ("  Table NULL arena... ");

  table = SocketQPACK_Table_new (NULL, 4096);
  TEST_ASSERT (table == NULL, "NULL arena should fail");

  printf ("PASS\n");
}

/**
 * Test inserting entries into dynamic table.
 */
static void
test_table_insert_literal (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Result result;

  printf ("  Table insert literal... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (arena, 4096);

  /* Insert first entry */
  result = SocketQPACK_Table_insert_literal (table, "x-custom", 8, "value1", 6);
  TEST_ASSERT (result == QPACK_OK, "first insert success");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 1, "count is 1");
  TEST_ASSERT (SocketQPACK_Table_insert_count (table) == 1,
               "insert_count is 1");
  /* Entry size = 8 + 6 + 32 = 46 */
  TEST_ASSERT (SocketQPACK_Table_size (table) == 46, "size is 46");

  /* Insert second entry */
  result = SocketQPACK_Table_insert_literal (
      table, "content-type", 12, "text/html", 9);
  TEST_ASSERT (result == QPACK_OK, "second insert success");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 2, "count is 2");
  TEST_ASSERT (SocketQPACK_Table_insert_count (table) == 2,
               "insert_count is 2");
  /* Entry size = 12 + 9 + 32 = 53, total = 46 + 53 = 99 */
  TEST_ASSERT (SocketQPACK_Table_size (table) == 99, "size is 99");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test retrieving entries by absolute index.
 */
static void
test_table_get (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Result result;
  const char *name, *value;
  size_t name_len, value_len;

  printf ("  Table get by absolute index... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (arena, 4096);

  /* Insert entries */
  result = SocketQPACK_Table_insert_literal (table, "header1", 7, "value1", 6);
  TEST_ASSERT (result == QPACK_OK, "insert header1");
  result = SocketQPACK_Table_insert_literal (table, "header2", 7, "value2", 6);
  TEST_ASSERT (result == QPACK_OK, "insert header2");
  result = SocketQPACK_Table_insert_literal (table, "header3", 7, "value3", 6);
  TEST_ASSERT (result == QPACK_OK, "insert header3");

  /* Get first entry (abs_index = 0) */
  result
      = SocketQPACK_Table_get (table, 0, &name, &name_len, &value, &value_len);
  TEST_ASSERT (result == QPACK_OK, "get index 0 success");
  TEST_ASSERT (name_len == 7, "name_len is 7");
  TEST_ASSERT (memcmp (name, "header1", 7) == 0, "name is header1");
  TEST_ASSERT (value_len == 6, "value_len is 6");
  TEST_ASSERT (memcmp (value, "value1", 6) == 0, "value is value1");

  /* Get second entry (abs_index = 1) */
  result
      = SocketQPACK_Table_get (table, 1, &name, &name_len, &value, &value_len);
  TEST_ASSERT (result == QPACK_OK, "get index 1 success");
  TEST_ASSERT (memcmp (name, "header2", 7) == 0, "name is header2");

  /* Get third entry (abs_index = 2) */
  result
      = SocketQPACK_Table_get (table, 2, &name, &name_len, &value, &value_len);
  TEST_ASSERT (result == QPACK_OK, "get index 2 success");
  TEST_ASSERT (memcmp (name, "header3", 7) == 0, "name is header3");

  /* Try invalid index */
  result
      = SocketQPACK_Table_get (table, 3, &name, &name_len, &value, &value_len);
  TEST_ASSERT (result == QPACK_ERR_FUTURE_INDEX, "index 3 is future");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test table eviction.
 */
static void
test_table_eviction (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Result result;
  const char *name, *value;
  size_t name_len, value_len;

  printf ("  Table eviction... ");

  arena = Arena_new ();
  /* Small table to force eviction: 100 bytes max */
  table = SocketQPACK_Table_new (arena, 100);

  /* Insert entry (size = 10 + 10 + 32 = 52 bytes) */
  result = SocketQPACK_Table_insert_literal (
      table, "header0000", 10, "value00000", 10);
  TEST_ASSERT (result == QPACK_OK, "insert entry 0");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 1, "count is 1");
  TEST_ASSERT (SocketQPACK_Table_dropped_count (table) == 0,
               "dropped_count is 0");

  /* Insert another entry - should trigger eviction of first */
  result = SocketQPACK_Table_insert_literal (
      table, "header1111", 10, "value11111", 10);
  TEST_ASSERT (result == QPACK_OK, "insert entry 1");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 1, "count is still 1");
  TEST_ASSERT (SocketQPACK_Table_insert_count (table) == 2,
               "insert_count is 2");
  TEST_ASSERT (SocketQPACK_Table_dropped_count (table) == 1,
               "dropped_count is 1");

  /* First entry should be evicted */
  result
      = SocketQPACK_Table_get (table, 0, &name, &name_len, &value, &value_len);
  TEST_ASSERT (result == QPACK_ERR_EVICTED_INDEX, "index 0 is evicted");

  /* Second entry should be accessible */
  result
      = SocketQPACK_Table_get (table, 1, &name, &name_len, &value, &value_len);
  TEST_ASSERT (result == QPACK_OK, "index 1 accessible");
  TEST_ASSERT (memcmp (name, "header1111", 10) == 0, "name is header1111");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test setting max size.
 */
static void
test_table_set_max_size (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Result result;

  printf ("  Table set max size... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (arena, 4096);

  /* Insert some entries */
  result = SocketQPACK_Table_insert_literal (table, "header1", 7, "value1", 6);
  TEST_ASSERT (result == QPACK_OK, "insert header1");
  result = SocketQPACK_Table_insert_literal (table, "header2", 7, "value2", 6);
  TEST_ASSERT (result == QPACK_OK, "insert header2");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 2, "count is 2");

  /* Reduce max size to force eviction */
  SocketQPACK_Table_set_max_size (table, 50);
  TEST_ASSERT (SocketQPACK_Table_max_size (table) == 50, "max_size is 50");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 1, "count is 1 after resize");

  /* Set to 0 should clear table */
  SocketQPACK_Table_set_max_size (table, 0);
  TEST_ASSERT (SocketQPACK_Table_count (table) == 0, "count is 0");
  TEST_ASSERT (SocketQPACK_Table_size (table) == 0, "size is 0");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test basic encoding.
 */
static void
test_encode_basic (void)
{
  unsigned char buf[256];
  size_t bytes_written;
  SocketQPACK_Result result;

  printf ("  Encode basic... ");

  result = SocketQPACK_encode_insert_literal_name (
      buf,
      sizeof (buf),
      (const unsigned char *)"x-custom",
      8,
      false,
      (const unsigned char *)"test-value",
      10,
      false,
      &bytes_written);
  TEST_ASSERT (result == QPACK_OK, "encode success");
  TEST_ASSERT (bytes_written > 0, "bytes written > 0");

  /* First byte should be 01xxxxxx (Insert with Literal Name) */
  TEST_ASSERT ((buf[0] & 0xC0) == 0x40, "correct instruction prefix");

  /* H bit should be 0 (no Huffman for name) */
  TEST_ASSERT ((buf[0] & 0x20) == 0, "H bit is 0");

  /* Name length should be 8 (fits in 5 bits) */
  TEST_ASSERT ((buf[0] & 0x1F) == 8, "name length is 8");

  printf ("PASS\n");
}

/**
 * Test encoding with Huffman.
 */
static void
test_encode_huffman (void)
{
  unsigned char buf_no_huff[256];
  unsigned char buf_huff[256];
  size_t len_no_huff, len_huff;
  SocketQPACK_Result result;

  printf ("  Encode with Huffman... ");

  /* Without Huffman */
  result = SocketQPACK_encode_insert_literal_name (
      buf_no_huff,
      sizeof (buf_no_huff),
      (const unsigned char *)"content-type",
      12,
      false,
      (const unsigned char *)"application/json",
      16,
      false,
      &len_no_huff);
  TEST_ASSERT (result == QPACK_OK, "no huffman encode success");

  /* With Huffman */
  result = SocketQPACK_encode_insert_literal_name (
      buf_huff,
      sizeof (buf_huff),
      (const unsigned char *)"content-type",
      12,
      true,
      (const unsigned char *)"application/json",
      16,
      true,
      &len_huff);
  TEST_ASSERT (result == QPACK_OK, "huffman encode success");

  /* Huffman encoding should produce smaller output */
  TEST_ASSERT (len_huff < len_no_huff, "Huffman is smaller");

  /* H bit should be set for Huffman-encoded name */
  TEST_ASSERT ((buf_huff[0] & 0x20) == 0x20, "H bit is set");

  printf ("PASS\n");
}

/**
 * Test encoding with empty strings.
 */
static void
test_encode_empty (void)
{
  unsigned char buf[256];
  size_t bytes_written;
  SocketQPACK_Result result;

  printf ("  Encode empty strings... ");

  /* Empty name */
  result
      = SocketQPACK_encode_insert_literal_name (buf,
                                                sizeof (buf),
                                                NULL,
                                                0,
                                                false,
                                                (const unsigned char *)"value",
                                                5,
                                                false,
                                                &bytes_written);
  TEST_ASSERT (result == QPACK_OK, "empty name success");
  TEST_ASSERT ((buf[0] & 0x1F) == 0, "name length is 0");

  /* Empty value */
  result
      = SocketQPACK_encode_insert_literal_name (buf,
                                                sizeof (buf),
                                                (const unsigned char *)"name",
                                                4,
                                                false,
                                                NULL,
                                                0,
                                                false,
                                                &bytes_written);
  TEST_ASSERT (result == QPACK_OK, "empty value success");

  printf ("PASS\n");
}

/**
 * Test basic decoding.
 */
static void
test_decode_basic (void)
{
  unsigned char encoded[256];
  unsigned char name_out[256];
  unsigned char value_out[256];
  size_t encoded_len, name_len, value_len, consumed;
  SocketQPACK_Result result;

  printf ("  Decode basic... ");

  /* Encode first */
  result = SocketQPACK_encode_insert_literal_name (
      encoded,
      sizeof (encoded),
      (const unsigned char *)"x-custom",
      8,
      false,
      (const unsigned char *)"test-value",
      10,
      false,
      &encoded_len);
  TEST_ASSERT (result == QPACK_OK, "encode success");

  /* Decode */
  result
      = SocketQPACK_decode_insert_literal_name (encoded,
                                                encoded_len,
                                                NULL, /* no table insertion */
                                                name_out,
                                                sizeof (name_out),
                                                &name_len,
                                                value_out,
                                                sizeof (value_out),
                                                &value_len,
                                                &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode success");
  TEST_ASSERT (consumed == encoded_len, "all bytes consumed");
  TEST_ASSERT (name_len == 8, "name_len is 8");
  TEST_ASSERT (memcmp (name_out, "x-custom", 8) == 0, "name matches");
  TEST_ASSERT (value_len == 10, "value_len is 10");
  TEST_ASSERT (memcmp (value_out, "test-value", 10) == 0, "value matches");

  printf ("PASS\n");
}

/**
 * Test decoding with Huffman.
 */
static void
test_decode_huffman (void)
{
  unsigned char encoded[256];
  unsigned char name_out[256];
  unsigned char value_out[256];
  size_t encoded_len, name_len, value_len, consumed;
  SocketQPACK_Result result;

  printf ("  Decode with Huffman... ");

  /* Encode with Huffman */
  result = SocketQPACK_encode_insert_literal_name (
      encoded,
      sizeof (encoded),
      (const unsigned char *)"content-type",
      12,
      true,
      (const unsigned char *)"application/json",
      16,
      true,
      &encoded_len);
  TEST_ASSERT (result == QPACK_OK, "encode success");

  /* Decode */
  result = SocketQPACK_decode_insert_literal_name (encoded,
                                                   encoded_len,
                                                   NULL,
                                                   name_out,
                                                   sizeof (name_out),
                                                   &name_len,
                                                   value_out,
                                                   sizeof (value_out),
                                                   &value_len,
                                                   &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode success");
  TEST_ASSERT (name_len == 12, "name_len is 12");
  TEST_ASSERT (memcmp (name_out, "content-type", 12) == 0, "name matches");
  TEST_ASSERT (value_len == 16, "value_len is 16");
  TEST_ASSERT (memcmp (value_out, "application/json", 16) == 0,
               "value matches");

  printf ("PASS\n");
}

/**
 * Test decode with table insertion.
 */
static void
test_decode_with_table (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  unsigned char encoded[256];
  unsigned char name_out[256];
  unsigned char value_out[256];
  size_t encoded_len, name_len, value_len, consumed;
  SocketQPACK_Result result;
  const char *tbl_name, *tbl_value;
  size_t tbl_name_len, tbl_value_len;

  printf ("  Decode with table insertion... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (arena, 4096);

  /* Encode */
  result = SocketQPACK_encode_insert_literal_name (
      encoded,
      sizeof (encoded),
      (const unsigned char *)"x-custom",
      8,
      false,
      (const unsigned char *)"test-value",
      10,
      false,
      &encoded_len);
  TEST_ASSERT (result == QPACK_OK, "encode success");

  /* Decode with table */
  result = SocketQPACK_decode_insert_literal_name (encoded,
                                                   encoded_len,
                                                   table,
                                                   name_out,
                                                   sizeof (name_out),
                                                   &name_len,
                                                   value_out,
                                                   sizeof (value_out),
                                                   &value_len,
                                                   &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode success");

  /* Verify table was updated */
  TEST_ASSERT (SocketQPACK_Table_count (table) == 1, "count is 1");
  TEST_ASSERT (SocketQPACK_Table_insert_count (table) == 1,
               "insert_count is 1");

  /* Verify entry contents */
  result = SocketQPACK_Table_get (
      table, 0, &tbl_name, &tbl_name_len, &tbl_value, &tbl_value_len);
  TEST_ASSERT (result == QPACK_OK, "get success");
  TEST_ASSERT (tbl_name_len == 8, "tbl_name_len is 8");
  TEST_ASSERT (memcmp (tbl_name, "x-custom", 8) == 0, "tbl_name matches");
  TEST_ASSERT (tbl_value_len == 10, "tbl_value_len is 10");
  TEST_ASSERT (memcmp (tbl_value, "test-value", 10) == 0, "tbl_value matches");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test incomplete data handling.
 */
static void
test_decode_incomplete (void)
{
  unsigned char encoded[256];
  unsigned char name_out[256];
  unsigned char value_out[256];
  size_t encoded_len, name_len, value_len, consumed;
  SocketQPACK_Result result;

  printf ("  Decode incomplete data... ");

  /* Encode a complete instruction */
  result
      = SocketQPACK_encode_insert_literal_name (encoded,
                                                sizeof (encoded),
                                                (const unsigned char *)"header",
                                                6,
                                                false,
                                                (const unsigned char *)"value",
                                                5,
                                                false,
                                                &encoded_len);
  TEST_ASSERT (result == QPACK_OK, "encode success");

  /* Try to decode with truncated data */
  result = SocketQPACK_decode_insert_literal_name (encoded,
                                                   2, /* only 2 bytes */
                                                   NULL,
                                                   name_out,
                                                   sizeof (name_out),
                                                   &name_len,
                                                   value_out,
                                                   sizeof (value_out),
                                                   &value_len,
                                                   &consumed);
  TEST_ASSERT (result == QPACK_INCOMPLETE, "incomplete data detected");

  /* Empty buffer */
  result = SocketQPACK_decode_insert_literal_name (encoded,
                                                   0,
                                                   NULL,
                                                   name_out,
                                                   sizeof (name_out),
                                                   &name_len,
                                                   value_out,
                                                   sizeof (value_out),
                                                   &value_len,
                                                   &consumed);
  TEST_ASSERT (result == QPACK_INCOMPLETE, "empty buffer is incomplete");

  printf ("PASS\n");
}

/**
 * Test NULL parameter handling.
 */
static void
test_null_params (void)
{
  unsigned char buf[256];
  unsigned char name_out[256];
  unsigned char value_out[256];
  size_t bytes_written, name_len, value_len, consumed;
  SocketQPACK_Result result;

  printf ("  NULL parameter handling... ");

  /* Encode with NULL buffer */
  result
      = SocketQPACK_encode_insert_literal_name (NULL,
                                                256,
                                                (const unsigned char *)"name",
                                                4,
                                                false,
                                                (const unsigned char *)"value",
                                                5,
                                                false,
                                                &bytes_written);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL buffer fails");

  /* Encode with NULL bytes_written */
  result
      = SocketQPACK_encode_insert_literal_name (buf,
                                                256,
                                                (const unsigned char *)"name",
                                                4,
                                                false,
                                                (const unsigned char *)"value",
                                                5,
                                                false,
                                                NULL);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL bytes_written fails");

  /* Encode with NULL name but non-zero length */
  result
      = SocketQPACK_encode_insert_literal_name (buf,
                                                256,
                                                NULL,
                                                5, /* len > 0 with NULL */
                                                false,
                                                (const unsigned char *)"value",
                                                5,
                                                false,
                                                &bytes_written);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL name with len fails");

  /* Decode with NULL buffer */
  result = SocketQPACK_decode_insert_literal_name (NULL,
                                                   10,
                                                   NULL,
                                                   name_out,
                                                   sizeof (name_out),
                                                   &name_len,
                                                   value_out,
                                                   sizeof (value_out),
                                                   &value_len,
                                                   &consumed);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "decode NULL buffer fails");

  printf ("PASS\n");
}

static void
run_table_tests (void)
{
  printf ("Dynamic Table Tests:\n");
  test_table_creation ();
  test_table_null_arena ();
  test_table_insert_literal ();
  test_table_get ();
  test_table_eviction ();
  test_table_set_max_size ();
}

static void
run_encode_tests (void)
{
  printf ("Encode Tests:\n");
  test_encode_basic ();
  test_encode_huffman ();
  test_encode_empty ();
}

static void
run_decode_tests (void)
{
  printf ("Decode Tests:\n");
  test_decode_basic ();
  test_decode_huffman ();
  test_decode_with_table ();
  test_decode_incomplete ();
}

static void
run_error_tests (void)
{
  printf ("Error Handling Tests:\n");
  test_null_params ();
}

int
main (void)
{
  printf ("=== QPACK Insert with Literal Name Tests (RFC 9204 Section 4.3.3) "
          "===\n\n");

  run_table_tests ();
  printf ("\n");

  run_encode_tests ();
  printf ("\n");

  run_decode_tests ();
  printf ("\n");

  run_error_tests ();
  printf ("\n");

  printf ("=== All tests passed! ===\n");
  return 0;
}
