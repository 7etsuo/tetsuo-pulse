/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_qpack.c - Unit tests for QPACK Header Compression (RFC 9204)
 *
 * Tests QPACK implementation including:
 * - Integer encoding/decoding (Section 4.1.1)
 * - String encoding/decoding with Huffman (Section 4.1.2)
 * - Static table lookup (Appendix A)
 * - Dynamic table operations (Section 3.2)
 * - Insert with Literal Name instruction (Section 4.3.3)
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/qpack/SocketQPACK.h"

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
 * Test Helpers
 * ============================================================================
 */

/**
 * Convert hex string to bytes
 */
static int
hex_to_bytes (const char *hex, unsigned char *out, size_t max_len)
{
  size_t len = strlen (hex);
  size_t out_len = 0;

  if (len % 2 != 0)
    return -1;

  for (size_t i = 0; i < len; i += 2)
    {
      if (out_len >= max_len)
        return -1;

      int hi, lo;
      char c;

      c = hex[i];
      if (c >= '0' && c <= '9')
        hi = c - '0';
      else if (c >= 'a' && c <= 'f')
        hi = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F')
        hi = c - 'A' + 10;
      else
        return -1;

      c = hex[i + 1];
      if (c >= '0' && c <= '9')
        lo = c - '0';
      else if (c >= 'a' && c <= 'f')
        lo = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F')
        lo = c - 'A' + 10;
      else
        return -1;

      out[out_len++] = (unsigned char)((hi << 4) | lo);
    }

  return (int)out_len;
}

/* ============================================================================
 * Integer Encoding Tests (RFC 9204 Section 4.1.1)
 * ============================================================================
 */

/**
 * Test integer encoding with 5-bit prefix
 */
static void
test_int_encode_5bit_small (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 10 with 5-bit prefix... ");

  len = SocketQPACK_int_encode (10, 5, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Expected 1 byte");
  TEST_ASSERT (buf[0] == 0x0A, "Expected 0x0A (10)");

  printf ("PASS\n");
}

/**
 * Test integer encoding requiring multi-byte
 */
static void
test_int_encode_5bit_large (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 1337 with 5-bit prefix... ");

  len = SocketQPACK_int_encode (1337, 5, buf, sizeof (buf));
  TEST_ASSERT (len == 3, "Expected 3 bytes");
  TEST_ASSERT (buf[0] == 0x1F, "First byte should be 31 (2^5 - 1)");
  TEST_ASSERT (buf[1] == 0x9A, "Second byte should be 0x9A");
  TEST_ASSERT (buf[2] == 0x0A, "Third byte should be 0x0A");

  printf ("PASS\n");
}

/**
 * Test integer decoding
 */
static void
test_int_decode_small (void)
{
  unsigned char data[] = { 0x0A };
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Integer decode 10... ");

  result = SocketQPACK_int_decode (data, sizeof (data), 5, &value, &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (value == 10, "Value should be 10");
  TEST_ASSERT (consumed == 1, "Should consume 1 byte");

  printf ("PASS\n");
}

/**
 * Test multi-byte integer decoding
 */
static void
test_int_decode_large (void)
{
  unsigned char data[] = { 0x1F, 0x9A, 0x0A };
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Integer decode 1337... ");

  result = SocketQPACK_int_decode (data, sizeof (data), 5, &value, &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (value == 1337, "Value should be 1337");
  TEST_ASSERT (consumed == 3, "Should consume 3 bytes");

  printf ("PASS\n");
}

/* ============================================================================
 * String Encoding Tests (RFC 9204 Section 4.1.2)
 * ============================================================================
 */

static void
test_string_encode_literal (void)
{
  Arena_T arena = Arena_new ();
  unsigned char buf[256];
  ssize_t len;

  printf ("  String encode literal 'hello'... ");

  /* Encode without Huffman */
  len = SocketQPACK_string_encode ("hello", 5, 7, 0, buf, sizeof (buf));
  TEST_ASSERT (len > 0, "Should encode successfully");
  TEST_ASSERT ((buf[0] & 0x80) == 0, "H bit should be 0 for literal");
  TEST_ASSERT ((buf[0] & 0x7F) == 5, "Length should be 5");
  TEST_ASSERT (memcmp (buf + 1, "hello", 5) == 0, "Data should be 'hello'");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_string_encode_huffman (void)
{
  unsigned char buf[256];
  ssize_t len;

  printf ("  String encode Huffman 'www.example.com'... ");

  /* Encode with Huffman (should be smaller for this string) */
  len = SocketQPACK_string_encode (
      "www.example.com", 15, 7, 1, buf, sizeof (buf));
  TEST_ASSERT (len > 0, "Should encode successfully");
  /* Huffman encoding of www.example.com should be shorter than 15 bytes */
  TEST_ASSERT ((buf[0] & 0x80) != 0, "H bit should be 1 for Huffman (shorter)");

  printf ("PASS\n");
}

static void
test_string_decode_literal (void)
{
  Arena_T arena = Arena_new ();
  unsigned char data[] = { 0x05, 'h', 'e', 'l', 'l', 'o' };
  char *str;
  size_t str_len, consumed;
  SocketQPACK_Result result;

  printf ("  String decode literal... ");

  result = SocketQPACK_string_decode (
      data, sizeof (data), 7, &str, &str_len, &consumed, arena);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (str_len == 5, "Length should be 5");
  TEST_ASSERT (memcmp (str, "hello", 5) == 0, "Should be 'hello'");
  TEST_ASSERT (consumed == 6, "Should consume 6 bytes");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * Static Table Tests (RFC 9204 Appendix A)
 * ============================================================================
 */

static void
test_static_table_get (void)
{
  SocketQPACK_Header header;
  SocketQPACK_Result result;

  printf ("  Static table get index 0 (:authority)... ");

  result = SocketQPACK_static_get (0, &header);
  TEST_ASSERT (result == QPACK_OK, "Should get OK");
  TEST_ASSERT (header.name_len == 10, "Name length should be 10");
  TEST_ASSERT (memcmp (header.name, ":authority", 10) == 0,
               "Name should be ':authority'");
  TEST_ASSERT (header.value_len == 0, "Value should be empty");

  printf ("PASS\n");
}

static void
test_static_table_get_method_get (void)
{
  SocketQPACK_Header header;
  SocketQPACK_Result result;

  printf ("  Static table get index 17 (:method GET)... ");

  result = SocketQPACK_static_get (17, &header);
  TEST_ASSERT (result == QPACK_OK, "Should get OK");
  TEST_ASSERT (header.name_len == 7, "Name length should be 7");
  TEST_ASSERT (memcmp (header.name, ":method", 7) == 0,
               "Name should be ':method'");
  TEST_ASSERT (header.value_len == 3, "Value length should be 3");
  TEST_ASSERT (memcmp (header.value, "GET", 3) == 0, "Value should be 'GET'");

  printf ("PASS\n");
}

static void
test_static_table_invalid_index (void)
{
  SocketQPACK_Header header;
  SocketQPACK_Result result;

  printf ("  Static table invalid index... ");

  result = SocketQPACK_static_get (99, &header);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_INDEX, "Should return error");

  printf ("PASS\n");
}

static void
test_static_table_find (void)
{
  int idx;

  printf ("  Static table find ':method' 'GET'... ");

  idx = SocketQPACK_static_find (":method", 7, "GET", 3);
  TEST_ASSERT (idx > 0, "Should find exact match");
  TEST_ASSERT (idx == 18, "Index should be 18 (1-based for exact)");

  printf ("PASS\n");
}

static void
test_static_table_find_name_only (void)
{
  int idx;

  printf ("  Static table find ':method' (name only)... ");

  idx = SocketQPACK_static_find (":method", 7, NULL, 0);
  TEST_ASSERT (idx < 0, "Should find name-only match (negative)");

  printf ("PASS\n");
}

/* ============================================================================
 * Dynamic Table Tests (RFC 9204 Section 3.2)
 * ============================================================================
 */

static void
test_dynamic_table_create (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DynamicTable_T table;

  printf ("  Dynamic table create... ");

  table = SocketQPACK_DynamicTable_new (4096, arena);
  TEST_ASSERT (table != NULL, "Should create table");
  TEST_ASSERT (SocketQPACK_DynamicTable_size (table) == 0, "Size should be 0");
  TEST_ASSERT (SocketQPACK_DynamicTable_count (table) == 0,
               "Count should be 0");
  TEST_ASSERT (SocketQPACK_DynamicTable_max_size (table) == 4096,
               "Max size should be 4096");

  SocketQPACK_DynamicTable_free (&table);
  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_dynamic_table_insert (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DynamicTable_T table;
  SocketQPACK_Result result;

  printf ("  Dynamic table insert... ");

  table = SocketQPACK_DynamicTable_new (4096, arena);
  result = SocketQPACK_DynamicTable_insert (
      table, "custom-header", 13, "custom-value", 12);
  TEST_ASSERT (result == QPACK_OK, "Should insert OK");
  TEST_ASSERT (SocketQPACK_DynamicTable_count (table) == 1,
               "Count should be 1");
  /* Entry size = 13 + 12 + 32 = 57 */
  TEST_ASSERT (SocketQPACK_DynamicTable_size (table) == 57,
               "Size should be 57");
  TEST_ASSERT (SocketQPACK_DynamicTable_insert_count (table) == 1,
               "Insert count should be 1");

  SocketQPACK_DynamicTable_free (&table);
  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_dynamic_table_get (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DynamicTable_T table;
  SocketQPACK_Header header;
  SocketQPACK_Result result;

  printf ("  Dynamic table get... ");

  table = SocketQPACK_DynamicTable_new (4096, arena);
  SocketQPACK_DynamicTable_insert (
      table, "custom-header", 13, "custom-value", 12);

  /* QPACK uses absolute indexing - first entry is index 0 */
  result = SocketQPACK_DynamicTable_get (table, 0, &header);
  TEST_ASSERT (result == QPACK_OK, "Should get OK");
  TEST_ASSERT (header.name_len == 13, "Name length should be 13");
  TEST_ASSERT (memcmp (header.name, "custom-header", 13) == 0,
               "Name should match");
  TEST_ASSERT (header.value_len == 12, "Value length should be 12");
  TEST_ASSERT (memcmp (header.value, "custom-value", 12) == 0,
               "Value should match");

  SocketQPACK_DynamicTable_free (&table);
  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_dynamic_table_eviction (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DynamicTable_T table;
  SocketQPACK_Result result;

  printf ("  Dynamic table eviction... ");

  /* Small table to force eviction */
  table = SocketQPACK_DynamicTable_new (100, arena);

  /* First entry: 10 + 10 + 32 = 52 bytes */
  result = SocketQPACK_DynamicTable_insert (
      table, "header-one", 10, "value-one", 9); /* 10+9+32=51 */
  TEST_ASSERT (result == QPACK_OK, "Should insert first");
  TEST_ASSERT (SocketQPACK_DynamicTable_count (table) == 1,
               "Count should be 1");

  /* Second entry: 10 + 10 + 32 = 52 bytes - should evict first */
  result = SocketQPACK_DynamicTable_insert (
      table, "header-two", 10, "value-two", 9); /* 10+9+32=51 */
  TEST_ASSERT (result == QPACK_OK, "Should insert second");
  /* Both entries = 102 bytes, max is 100, so first should be evicted */
  TEST_ASSERT (SocketQPACK_DynamicTable_count (table) == 1,
               "Count should still be 1 after eviction");

  /* Verify we can access the second entry (absolute index 1) */
  SocketQPACK_Header header;
  result = SocketQPACK_DynamicTable_get (table, 1, &header);
  TEST_ASSERT (result == QPACK_OK, "Should get second entry");
  TEST_ASSERT (memcmp (header.name, "header-two", 10) == 0,
               "Should be second entry");

  /* First entry should be inaccessible (evicted) */
  result = SocketQPACK_DynamicTable_get (table, 0, &header);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_INDEX,
               "First entry should be evicted");

  SocketQPACK_DynamicTable_free (&table);
  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * Insert with Literal Name Tests (RFC 9204 Section 4.3.3)
 * ============================================================================
 */

static void
test_insert_literal_name_encode (void)
{
  unsigned char buf[256];
  ssize_t len;
  SocketQPACK_InsertLiteralInstruction instr;

  printf ("  Insert literal name encode... ");

  instr.name = (const unsigned char *)"custom-key";
  instr.name_len = 10;
  instr.value = (const unsigned char *)"custom-value";
  instr.value_len = 12;
  instr.name_huffman = 0;
  instr.value_huffman = 0;

  len = SocketQPACK_encode_insert_literal_name (&instr, buf, sizeof (buf));
  TEST_ASSERT (len > 0, "Should encode successfully");

  /* Verify pattern: first byte should have pattern 01 (bits 7-6) */
  TEST_ASSERT ((buf[0] & 0xC0) == 0x40, "Should have pattern 01");
  /* H bit should be 0 (bit 5) */
  TEST_ASSERT ((buf[0] & 0x20) == 0, "H bit should be 0 for literal name");

  printf ("PASS\n");
}

static void
test_insert_literal_name_encode_huffman (void)
{
  unsigned char buf[256];
  ssize_t len;
  SocketQPACK_InsertLiteralInstruction instr;

  printf ("  Insert literal name encode with Huffman... ");

  instr.name = (const unsigned char *)"www.example.com";
  instr.name_len = 15;
  instr.value = (const unsigned char *)"no-cache";
  instr.value_len = 8;
  instr.name_huffman = 1;
  instr.value_huffman = 1;

  len = SocketQPACK_encode_insert_literal_name (&instr, buf, sizeof (buf));
  TEST_ASSERT (len > 0, "Should encode successfully");

  /* Verify pattern 01 */
  TEST_ASSERT ((buf[0] & 0xC0) == 0x40, "Should have pattern 01");
  /* H bit should be 1 (bit 5) for Huffman name */
  TEST_ASSERT ((buf[0] & 0x20) != 0, "H bit should be 1 for Huffman name");

  printf ("PASS\n");
}

static void
test_insert_literal_name_decode (void)
{
  Arena_T arena = Arena_new ();
  unsigned char buf[256];
  ssize_t encoded_len;
  SocketQPACK_InsertLiteralInstruction instr;
  char *name, *value;
  size_t name_len, value_len, consumed;
  SocketQPACK_Result result;

  printf ("  Insert literal name decode... ");

  /* First encode */
  instr.name = (const unsigned char *)"test-header";
  instr.name_len = 11;
  instr.value = (const unsigned char *)"test-value";
  instr.value_len = 10;
  instr.name_huffman = 0;
  instr.value_huffman = 0;

  encoded_len
      = SocketQPACK_encode_insert_literal_name (&instr, buf, sizeof (buf));
  TEST_ASSERT (encoded_len > 0, "Should encode");

  /* Then decode */
  result = SocketQPACK_decode_insert_literal_name (buf,
                                                   (size_t)encoded_len,
                                                   &name,
                                                   &name_len,
                                                   &value,
                                                   &value_len,
                                                   &consumed,
                                                   arena);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (name_len == 11, "Name length should be 11");
  TEST_ASSERT (memcmp (name, "test-header", 11) == 0, "Name should match");
  TEST_ASSERT (value_len == 10, "Value length should be 10");
  TEST_ASSERT (memcmp (value, "test-value", 10) == 0, "Value should match");
  TEST_ASSERT (consumed == (size_t)encoded_len, "Should consume all bytes");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_insert_literal_name_roundtrip_huffman (void)
{
  Arena_T arena = Arena_new ();
  unsigned char buf[256];
  ssize_t encoded_len;
  SocketQPACK_InsertLiteralInstruction instr;
  char *name, *value;
  size_t name_len, value_len, consumed;
  SocketQPACK_Result result;

  printf ("  Insert literal name roundtrip with Huffman... ");

  /* Encode with Huffman */
  instr.name = (const unsigned char *)"content-type";
  instr.name_len = 12;
  instr.value = (const unsigned char *)"text/html";
  instr.value_len = 9;
  instr.name_huffman = 1;
  instr.value_huffman = 1;

  encoded_len
      = SocketQPACK_encode_insert_literal_name (&instr, buf, sizeof (buf));
  TEST_ASSERT (encoded_len > 0, "Should encode");

  /* Decode */
  result = SocketQPACK_decode_insert_literal_name (buf,
                                                   (size_t)encoded_len,
                                                   &name,
                                                   &name_len,
                                                   &value,
                                                   &value_len,
                                                   &consumed,
                                                   arena);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (name_len == 12, "Name length should be 12");
  TEST_ASSERT (memcmp (name, "content-type", 12) == 0, "Name should match");
  TEST_ASSERT (value_len == 9, "Value length should be 9");
  TEST_ASSERT (memcmp (value, "text/html", 9) == 0, "Value should match");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_process_insert_literal_name (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DynamicTable_T table;
  unsigned char buf[256];
  ssize_t encoded_len;
  SocketQPACK_InsertLiteralInstruction instr;
  size_t consumed;
  SocketQPACK_Result result;
  SocketQPACK_Header header;

  printf ("  Process insert literal name into table... ");

  table = SocketQPACK_DynamicTable_new (4096, arena);

  /* Encode instruction */
  instr.name = (const unsigned char *)"x-custom";
  instr.name_len = 8;
  instr.value = (const unsigned char *)"custom123";
  instr.value_len = 9;
  instr.name_huffman = 0;
  instr.value_huffman = 0;

  encoded_len
      = SocketQPACK_encode_insert_literal_name (&instr, buf, sizeof (buf));
  TEST_ASSERT (encoded_len > 0, "Should encode");

  /* Process (decode and insert into table) */
  result = SocketQPACK_process_insert_literal_name (
      table, buf, (size_t)encoded_len, &consumed, arena);
  TEST_ASSERT (result == QPACK_OK, "Should process OK");
  TEST_ASSERT (consumed == (size_t)encoded_len, "Should consume all bytes");

  /* Verify entry was added to table */
  TEST_ASSERT (SocketQPACK_DynamicTable_count (table) == 1,
               "Count should be 1");

  /* Retrieve and verify */
  result = SocketQPACK_DynamicTable_get (table, 0, &header);
  TEST_ASSERT (result == QPACK_OK, "Should get entry");
  TEST_ASSERT (header.name_len == 8, "Name length should be 8");
  TEST_ASSERT (memcmp (header.name, "x-custom", 8) == 0, "Name should match");
  TEST_ASSERT (header.value_len == 9, "Value length should be 9");
  TEST_ASSERT (memcmp (header.value, "custom123", 9) == 0,
               "Value should match");

  SocketQPACK_DynamicTable_free (&table);
  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * Edge Case Tests
 * ============================================================================
 */

static void
test_empty_string_encode (void)
{
  unsigned char buf[16];
  ssize_t len;

  printf ("  Empty string encode... ");

  len = SocketQPACK_string_encode ("", 0, 7, 0, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Should be 1 byte");
  TEST_ASSERT (buf[0] == 0, "Length byte should be 0");

  printf ("PASS\n");
}

static void
test_empty_name_value (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DynamicTable_T table;
  SocketQPACK_Result result;
  SocketQPACK_Header header;

  printf ("  Empty name/value insert... ");

  table = SocketQPACK_DynamicTable_new (4096, arena);

  /* Insert with empty value */
  result = SocketQPACK_DynamicTable_insert (table, "empty-value", 11, "", 0);
  TEST_ASSERT (result == QPACK_OK, "Should insert with empty value");

  result = SocketQPACK_DynamicTable_get (table, 0, &header);
  TEST_ASSERT (result == QPACK_OK, "Should get entry");
  TEST_ASSERT (header.value_len == 0, "Value should be empty");

  SocketQPACK_DynamicTable_free (&table);
  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_large_integer (void)
{
  unsigned char buf[16];
  size_t len;
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Large integer encode/decode... ");

  /* Encode large value */
  uint64_t large_val = 1000000;
  len = SocketQPACK_int_encode (large_val, 5, buf, sizeof (buf));
  TEST_ASSERT (len > 0, "Should encode");

  /* Decode */
  result = SocketQPACK_int_decode (buf, len, 5, &value, &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (value == large_val, "Value should match");

  printf ("PASS\n");
}

/* ============================================================================
 * Test Groups
 * ============================================================================
 */

static void
run_integer_tests (void)
{
  printf ("\nInteger Encoding/Decoding Tests:\n");
  test_int_encode_5bit_small ();
  test_int_encode_5bit_large ();
  test_int_decode_small ();
  test_int_decode_large ();
  test_large_integer ();
}

static void
run_string_tests (void)
{
  printf ("\nString Encoding/Decoding Tests:\n");
  test_string_encode_literal ();
  test_string_encode_huffman ();
  test_string_decode_literal ();
  test_empty_string_encode ();
}

static void
run_static_table_tests (void)
{
  printf ("\nStatic Table Tests:\n");
  test_static_table_get ();
  test_static_table_get_method_get ();
  test_static_table_invalid_index ();
  test_static_table_find ();
  test_static_table_find_name_only ();
}

static void
run_dynamic_table_tests (void)
{
  printf ("\nDynamic Table Tests:\n");
  test_dynamic_table_create ();
  test_dynamic_table_insert ();
  test_dynamic_table_get ();
  test_dynamic_table_eviction ();
  test_empty_name_value ();
}

static void
run_insert_literal_name_tests (void)
{
  printf ("\nInsert with Literal Name Tests (RFC 9204 Section 4.3.3):\n");
  test_insert_literal_name_encode ();
  test_insert_literal_name_encode_huffman ();
  test_insert_literal_name_decode ();
  test_insert_literal_name_roundtrip_huffman ();
  test_process_insert_literal_name ();
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  printf ("=== QPACK Header Compression Tests (RFC 9204) ===\n");

  run_integer_tests ();
  run_string_tests ();
  run_static_table_tests ();
  run_dynamic_table_tests ();
  run_insert_literal_name_tests ();

  printf ("\n=== All QPACK tests passed! ===\n");
  return 0;
}
