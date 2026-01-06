/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_qpack.c - Unit tests for QPACK Header Compression (RFC 9204)
 *
 * Tests RFC 9204 QPACK implementation including:
 * - Integer encoding/decoding
 * - String encoding/decoding
 * - Static table lookup
 * - Dynamic table operations
 * - Insert with Name Reference (Section 4.3.2)
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
 * Integer Encoding Tests
 * ============================================================================
 */

static void
test_int_encode_6bit_small (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 10 with 6-bit prefix... ");

  len = SocketQPACK_int_encode (10, 6, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Expected 1 byte");
  TEST_ASSERT (buf[0] == 0x0A, "Expected 0x0A (10)");

  printf ("PASS\n");
}

static void
test_int_encode_6bit_boundary (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 62 with 6-bit prefix... ");

  /* 62 fits in single byte (< 63 = 2^6 - 1) */
  len = SocketQPACK_int_encode (62, 6, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Expected 1 byte");
  TEST_ASSERT (buf[0] == 0x3E, "Expected 0x3E (62)");

  printf ("PASS\n");
}

static void
test_int_encode_6bit_multi (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 63 with 6-bit prefix... ");

  /* 63 = 2^6 - 1, requires continuation per RFC 7541 Section 5.1 */
  len = SocketQPACK_int_encode (63, 6, buf, sizeof (buf));
  TEST_ASSERT (len == 2, "Expected 2 bytes");
  TEST_ASSERT (buf[0] == 0x3F, "First byte should be 63 (prefix marker)");
  TEST_ASSERT (buf[1] == 0x00, "Second byte should be 0 (63-63=0)");

  printf ("PASS\n");
}

static void
test_int_decode_6bit (void)
{
  unsigned char data[] = { 0x0A };
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Integer decode 10 with 6-bit prefix... ");

  result = SocketQPACK_int_decode (data, sizeof (data), 6, &value, &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (value == 10, "Value should be 10");
  TEST_ASSERT (consumed == 1, "Should consume 1 byte");

  printf ("PASS\n");
}

static void
test_int_decode_6bit_multi (void)
{
  unsigned char data[] = { 0x3F, 0x00 };
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Integer decode 63 with 6-bit prefix... ");

  result = SocketQPACK_int_decode (data, sizeof (data), 6, &value, &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (value == 63, "Value should be 63");
  TEST_ASSERT (consumed == 2, "Should consume 2 bytes");

  printf ("PASS\n");
}

/* ============================================================================
 * Static Table Tests (RFC 9204 Appendix A)
 * ============================================================================
 */

static void
test_static_table_get_authority (void)
{
  SocketQPACK_Header header;
  SocketQPACK_Result result;

  printf ("  Static table index 0 (:authority)... ");

  result = SocketQPACK_static_get (0, &header);
  TEST_ASSERT (result == QPACK_OK, "Should get OK");
  TEST_ASSERT (header.name_len == 10, "Name length should be 10");
  TEST_ASSERT (memcmp (header.name, ":authority", 10) == 0,
               "Name should be :authority");
  TEST_ASSERT (header.value_len == 0, "Value should be empty");

  printf ("PASS\n");
}

static void
test_static_table_get_method_get (void)
{
  SocketQPACK_Header header;
  SocketQPACK_Result result;

  printf ("  Static table index 17 (:method GET)... ");

  result = SocketQPACK_static_get (17, &header);
  TEST_ASSERT (result == QPACK_OK, "Should get OK");
  TEST_ASSERT (memcmp (header.name, ":method", 7) == 0,
               "Name should be :method");
  TEST_ASSERT (memcmp (header.value, "GET", 3) == 0, "Value should be GET");

  printf ("PASS\n");
}

static void
test_static_table_get_out_of_bounds (void)
{
  SocketQPACK_Header header;
  SocketQPACK_Result result;

  printf ("  Static table index out of bounds (99)... ");

  result = SocketQPACK_static_get (99, &header);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_INDEX, "Should return error");

  printf ("PASS\n");
}

static void
test_static_table_find_exact (void)
{
  int result;

  printf ("  Static table find exact match... ");

  /* :method GET is at index 17 */
  result = SocketQPACK_static_find (":method", 7, "GET", 3);
  TEST_ASSERT (result == 18, "Should return index+1 (18)");

  printf ("PASS\n");
}

static void
test_static_table_find_name_only (void)
{
  int result;

  printf ("  Static table find name only... ");

  /* :status with non-matching value */
  result = SocketQPACK_static_find (":status", 7, "999", 3);
  /* Should return negative index of first name match */
  TEST_ASSERT (result < 0, "Should return negative for name-only match");

  printf ("PASS\n");
}

/* ============================================================================
 * Dynamic Table Tests
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
  TEST_ASSERT (SocketQPACK_DynamicTable_count (table) == 0, "Should be empty");
  TEST_ASSERT (SocketQPACK_DynamicTable_max_size (table) == 4096,
               "Max size should be 4096");
  TEST_ASSERT (SocketQPACK_DynamicTable_insertion_count (table) == 0,
               "Insertion count should be 0");

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
  SocketQPACK_Header header;

  printf ("  Dynamic table insert... ");

  table = SocketQPACK_DynamicTable_new (4096, arena);

  /* Insert entry */
  result = SocketQPACK_DynamicTable_insert (
      table, "custom-header", 13, "custom-value", 12);
  TEST_ASSERT (result == QPACK_OK, "Insert should succeed");
  TEST_ASSERT (SocketQPACK_DynamicTable_count (table) == 1,
               "Should have 1 entry");
  TEST_ASSERT (SocketQPACK_DynamicTable_insertion_count (table) == 1,
               "Insertion count should be 1");

  /* Retrieve by absolute index 0 */
  result = SocketQPACK_DynamicTable_get (table, 0, &header);
  TEST_ASSERT (result == QPACK_OK, "Get should succeed");
  TEST_ASSERT (header.name_len == 13, "Name length");
  TEST_ASSERT (memcmp (header.name, "custom-header", 13) == 0, "Name");
  TEST_ASSERT (header.value_len == 12, "Value length");
  TEST_ASSERT (memcmp (header.value, "custom-value", 12) == 0, "Value");

  SocketQPACK_DynamicTable_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_dynamic_table_multiple_inserts (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DynamicTable_T table;
  SocketQPACK_Result result;
  SocketQPACK_Header header;

  printf ("  Dynamic table multiple inserts... ");

  table = SocketQPACK_DynamicTable_new (4096, arena);

  /* Insert multiple entries */
  SocketQPACK_DynamicTable_insert (table, "header-1", 8, "value-1", 7);
  SocketQPACK_DynamicTable_insert (table, "header-2", 8, "value-2", 7);
  SocketQPACK_DynamicTable_insert (table, "header-3", 8, "value-3", 7);

  TEST_ASSERT (SocketQPACK_DynamicTable_count (table) == 3, "Should have 3");
  TEST_ASSERT (SocketQPACK_DynamicTable_insertion_count (table) == 3,
               "Insertion count");

  /* Verify ordering - absolute index 0 is oldest (header-1) */
  result = SocketQPACK_DynamicTable_get (table, 0, &header);
  TEST_ASSERT (result == QPACK_OK, "Get index 0");
  TEST_ASSERT (memcmp (header.value, "value-1", 7) == 0, "Index 0 = value-1");

  result = SocketQPACK_DynamicTable_get (table, 2, &header);
  TEST_ASSERT (result == QPACK_OK, "Get index 2");
  TEST_ASSERT (memcmp (header.value, "value-3", 7) == 0, "Index 2 = value-3");

  SocketQPACK_DynamicTable_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_dynamic_table_eviction (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DynamicTable_T table;
  SocketQPACK_Header header;

  printf ("  Dynamic table eviction... ");

  /* Small table to force eviction */
  table = SocketQPACK_DynamicTable_new (100, arena);

  /* Insert entries until eviction occurs */
  SocketQPACK_DynamicTable_insert (table, "h1", 2, "v1", 2);
  SocketQPACK_DynamicTable_insert (table, "h2", 2, "v2", 2);
  SocketQPACK_DynamicTable_insert (table, "h3", 2, "v3", 2);

  /* Absolute index 0 should now be invalid (evicted) */
  SocketQPACK_Result result = SocketQPACK_DynamicTable_get (table, 0, &header);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_INDEX,
               "Evicted entry should be invalid");

  /* But recent entries should still be accessible */
  TEST_ASSERT (SocketQPACK_DynamicTable_count (table) > 0,
               "Table should have entries");

  SocketQPACK_DynamicTable_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Insert with Name Reference Tests (RFC 9204 Section 4.3.2)
 * ============================================================================
 */

static void
test_encode_insert_nameref_static (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DynamicTable_T table;
  SocketQPACK_InsertNameRef instr;
  unsigned char output[256];
  ssize_t len;

  printf ("  Encode Insert with Name Reference (static)... ");

  table = SocketQPACK_DynamicTable_new (4096, arena);

  /* Reference static table index 17 (:method), value "PATCH" */
  instr.is_static = 1;
  instr.name_index = 17;
  instr.value = (const unsigned char *)"PATCH";
  instr.value_len = 5;
  instr.use_huffman = 0;

  len = SocketQPACK_encode_insert_nameref (
      &instr, table, output, sizeof (output));
  TEST_ASSERT (len > 0, "Encoding should succeed");

  /* Verify wire format:
   * Byte 0: 11010001 = 0xD1 (1=insert, 1=static, 010001=17)
   * Byte 1: 00000101 = 0x05 (no Huffman, length 5)
   * Bytes 2-6: "PATCH" */
  TEST_ASSERT (output[0] == 0xD1, "First byte should be 0xD1");
  TEST_ASSERT (output[1] == 0x05, "Length byte should be 0x05");
  TEST_ASSERT (memcmp (output + 2, "PATCH", 5) == 0, "Value should be PATCH");
  TEST_ASSERT (len == 7, "Total length should be 7");

  SocketQPACK_DynamicTable_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_encode_insert_nameref_dynamic (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DynamicTable_T table;
  SocketQPACK_InsertNameRef instr;
  unsigned char output[256];
  ssize_t len;

  printf ("  Encode Insert with Name Reference (dynamic)... ");

  table = SocketQPACK_DynamicTable_new (4096, arena);

  /* First insert an entry to reference */
  SocketQPACK_DynamicTable_insert (table, "x-custom", 8, "first", 5);

  /* Reference dynamic table (most recent = relative index 0) */
  instr.is_static = 0;
  instr.name_index = 0; /* Relative index to most recent */
  instr.value = (const unsigned char *)"second";
  instr.value_len = 6;
  instr.use_huffman = 0;

  len = SocketQPACK_encode_insert_nameref (
      &instr, table, output, sizeof (output));
  TEST_ASSERT (len > 0, "Encoding should succeed");

  /* Verify wire format:
   * Byte 0: 10000000 = 0x80 (1=insert, 0=dynamic, 000000=0)
   * Byte 1: length
   * Rest: value */
  TEST_ASSERT ((output[0] & 0xC0) == 0x80, "Should indicate dynamic ref");

  SocketQPACK_DynamicTable_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_encode_insert_nameref_invalid_static (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DynamicTable_T table;
  SocketQPACK_InsertNameRef instr;
  unsigned char output[256];
  ssize_t len;

  printf ("  Encode Insert with Name Reference (invalid static index)... ");

  table = SocketQPACK_DynamicTable_new (4096, arena);

  /* Reference invalid static index (99 is out of bounds) */
  instr.is_static = 1;
  instr.name_index = 99;
  instr.value = (const unsigned char *)"value";
  instr.value_len = 5;
  instr.use_huffman = 0;

  len = SocketQPACK_encode_insert_nameref (
      &instr, table, output, sizeof (output));
  TEST_ASSERT (len == -1, "Should fail for invalid index");

  SocketQPACK_DynamicTable_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_decode_insert_nameref_static (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DynamicTable_T table;
  SocketQPACK_Result result;
  size_t consumed;
  SocketQPACK_Header header;

  printf ("  Decode Insert with Name Reference (static)... ");

  table = SocketQPACK_DynamicTable_new (4096, arena);

  /* Wire format for static index 17 (:method), value "PATCH":
   * 0xD1 = 11010001 (static ref, index 17)
   * 0x05 = length 5
   * "PATCH" */
  unsigned char input[] = { 0xD1, 0x05, 'P', 'A', 'T', 'C', 'H' };

  result = SocketQPACK_decode_insert_nameref (
      input, sizeof (input), table, &consumed, arena);
  TEST_ASSERT (result == QPACK_OK, "Decode should succeed");
  TEST_ASSERT (consumed == 7, "Should consume 7 bytes");
  TEST_ASSERT (SocketQPACK_DynamicTable_count (table) == 1,
               "Table should have 1 entry");

  /* Verify inserted entry */
  result = SocketQPACK_DynamicTable_get (table, 0, &header);
  TEST_ASSERT (result == QPACK_OK, "Get should succeed");
  TEST_ASSERT (memcmp (header.name, ":method", 7) == 0,
               "Name should be :method");
  TEST_ASSERT (memcmp (header.value, "PATCH", 5) == 0, "Value should be PATCH");

  SocketQPACK_DynamicTable_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_decode_insert_nameref_dynamic (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DynamicTable_T table;
  SocketQPACK_Result result;
  size_t consumed;
  SocketQPACK_Header header;

  printf ("  Decode Insert with Name Reference (dynamic)... ");

  table = SocketQPACK_DynamicTable_new (4096, arena);

  /* First insert a base entry */
  SocketQPACK_DynamicTable_insert (table, "x-custom", 8, "original", 8);

  /* Wire format for dynamic index 0 (most recent), value "updated":
   * 0x80 = 10000000 (dynamic ref, relative index 0)
   * 0x07 = length 7
   * "updated" */
  unsigned char input[] = { 0x80, 0x07, 'u', 'p', 'd', 'a', 't', 'e', 'd' };

  result = SocketQPACK_decode_insert_nameref (
      input, sizeof (input), table, &consumed, arena);
  TEST_ASSERT (result == QPACK_OK, "Decode should succeed");
  TEST_ASSERT (consumed == 9, "Should consume 9 bytes");
  TEST_ASSERT (SocketQPACK_DynamicTable_count (table) == 2,
               "Table should have 2 entries");

  /* Verify new entry (absolute index 1) */
  result = SocketQPACK_DynamicTable_get (table, 1, &header);
  TEST_ASSERT (result == QPACK_OK, "Get should succeed");
  TEST_ASSERT (memcmp (header.name, "x-custom", 8) == 0,
               "Name should be x-custom");
  TEST_ASSERT (memcmp (header.value, "updated", 7) == 0,
               "Value should be updated");

  SocketQPACK_DynamicTable_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_decode_insert_nameref_invalid (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DynamicTable_T table;
  SocketQPACK_Result result;
  size_t consumed;

  printf ("  Decode Insert with Name Reference (invalid index)... ");

  table = SocketQPACK_DynamicTable_new (4096, arena);

  /* Wire format with invalid static index 99 */
  unsigned char input[] = { 0xFF, 0x24, /* 99 with 6-bit prefix */
                            0x05, 'v',  'a', 'l', 'u', 'e' };

  result = SocketQPACK_decode_insert_nameref (
      input, sizeof (input), table, &consumed, arena);
  TEST_ASSERT (result == QPACK_ERROR_ENCODER_STREAM,
               "Should return encoder stream error");

  SocketQPACK_DynamicTable_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_insert_nameref_roundtrip (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DynamicTable_T encoder_table;
  SocketQPACK_DynamicTable_T decoder_table;
  SocketQPACK_InsertNameRef instr;
  unsigned char wire[256];
  ssize_t wire_len;
  SocketQPACK_Result result;
  size_t consumed;
  SocketQPACK_Header header;

  printf ("  Insert with Name Reference roundtrip... ");

  encoder_table = SocketQPACK_DynamicTable_new (4096, arena);
  decoder_table = SocketQPACK_DynamicTable_new (4096, arena);

  /* Encode instruction */
  instr.is_static = 1;
  instr.name_index = 0; /* :authority */
  instr.value = (const unsigned char *)"example.com";
  instr.value_len = 11;
  instr.use_huffman = 0;

  wire_len = SocketQPACK_encode_insert_nameref (
      &instr, encoder_table, wire, sizeof (wire));
  TEST_ASSERT (wire_len > 0, "Encoding should succeed");

  /* Decode instruction */
  result = SocketQPACK_decode_insert_nameref (
      wire, (size_t)wire_len, decoder_table, &consumed, arena);
  TEST_ASSERT (result == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (consumed == (size_t)wire_len, "Should consume all bytes");

  /* Verify decoder table state */
  TEST_ASSERT (SocketQPACK_DynamicTable_count (decoder_table) == 1,
               "Decoder table should have entry");

  result = SocketQPACK_DynamicTable_get (decoder_table, 0, &header);
  TEST_ASSERT (result == QPACK_OK, "Get should succeed");
  TEST_ASSERT (memcmp (header.name, ":authority", 10) == 0, "Name");
  TEST_ASSERT (memcmp (header.value, "example.com", 11) == 0, "Value");

  SocketQPACK_DynamicTable_free (&encoder_table);
  SocketQPACK_DynamicTable_free (&decoder_table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

static void
test_insert_nameref_with_huffman (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DynamicTable_T table;
  SocketQPACK_InsertNameRef instr;
  unsigned char output[256];
  ssize_t len;

  printf ("  Encode Insert with Name Reference (Huffman)... ");

  table = SocketQPACK_DynamicTable_new (4096, arena);

  /* www.example.com compresses well with Huffman */
  instr.is_static = 1;
  instr.name_index = 0; /* :authority */
  instr.value = (const unsigned char *)"www.example.com";
  instr.value_len = 15;
  instr.use_huffman = 1;

  len = SocketQPACK_encode_insert_nameref (
      &instr, table, output, sizeof (output));
  TEST_ASSERT (len > 0, "Encoding should succeed");
  TEST_ASSERT ((output[0] & 0xC0) == 0xC0, "Should indicate static ref");
  /* Huffman flag should be set in length byte */
  TEST_ASSERT ((output[1] & 0x80) != 0, "Huffman flag should be set");

  SocketQPACK_DynamicTable_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

static void
run_integer_tests (void)
{
  printf ("Integer Encoding/Decoding Tests:\n");
  test_int_encode_6bit_small ();
  test_int_encode_6bit_boundary ();
  test_int_encode_6bit_multi ();
  test_int_decode_6bit ();
  test_int_decode_6bit_multi ();
}

static void
run_static_table_tests (void)
{
  printf ("Static Table Tests:\n");
  test_static_table_get_authority ();
  test_static_table_get_method_get ();
  test_static_table_get_out_of_bounds ();
  test_static_table_find_exact ();
  test_static_table_find_name_only ();
}

static void
run_dynamic_table_tests (void)
{
  printf ("Dynamic Table Tests:\n");
  test_dynamic_table_create ();
  test_dynamic_table_insert ();
  test_dynamic_table_multiple_inserts ();
  test_dynamic_table_eviction ();
}

static void
run_insert_nameref_tests (void)
{
  printf ("Insert with Name Reference Tests (RFC 9204 Section 4.3.2):\n");
  test_encode_insert_nameref_static ();
  test_encode_insert_nameref_dynamic ();
  test_encode_insert_nameref_invalid_static ();
  test_decode_insert_nameref_static ();
  test_decode_insert_nameref_dynamic ();
  test_decode_insert_nameref_invalid ();
  test_insert_nameref_roundtrip ();
  test_insert_nameref_with_huffman ();
}

int
main (void)
{
  printf ("\n=== QPACK Test Suite (RFC 9204) ===\n\n");

  run_integer_tests ();
  printf ("\n");

  run_static_table_tests ();
  printf ("\n");

  run_dynamic_table_tests ();
  printf ("\n");

  run_insert_nameref_tests ();
  printf ("\n");

  printf ("=== All QPACK tests passed ===\n\n");
  return 0;
}
