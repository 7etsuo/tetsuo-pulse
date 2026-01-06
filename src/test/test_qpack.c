/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_qpack.c - Unit tests for QPACK Header Compression (RFC 9204)
 *
 * Part of the Socket Library
 *
 * Tests RFC 9204 QPACK implementation including:
 * - Set Dynamic Table Capacity instruction (Section 4.3.1)
 * - Integer encoding/decoding (RFC 7541 Section 5.1)
 * - Dynamic table management (Section 3.2)
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketQPACK.h"
#include "test/Test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Integer Encoding Tests (RFC 7541 Section 5.1)
 * ============================================================================
 */

/**
 * Test integer encoding with 5-bit prefix (small value)
 */
TEST (qpack_int_encode_5bit_small)
{
  unsigned char buf[16];
  size_t len;

  len = SocketQPACK_int_encode (10, 5, buf, sizeof (buf));
  ASSERT_EQ (1, len);
  ASSERT_EQ (0x0A, buf[0]);
}

/**
 * Test integer encoding with 5-bit prefix (max single byte)
 */
TEST (qpack_int_encode_5bit_max_single)
{
  unsigned char buf[16];
  size_t len;

  /* 30 fits in 5 bits (max is 31) */
  len = SocketQPACK_int_encode (30, 5, buf, sizeof (buf));
  ASSERT_EQ (1, len);
  ASSERT_EQ (30, buf[0]);
}

/**
 * Test integer encoding with 5-bit prefix (multi-byte)
 */
TEST (qpack_int_encode_5bit_multibyte)
{
  unsigned char buf[16];
  size_t len;

  /* 1337 requires multi-byte encoding:
   * 1337 = 31 + 1306
   * 1306 = 154 + 10*128 = 0x9A + 0x0A*128
   * Wire: 0x1F (31), 0x9A (154 | 0x80), 0x0A (10)
   */
  len = SocketQPACK_int_encode (1337, 5, buf, sizeof (buf));
  ASSERT_EQ (3, len);
  ASSERT_EQ (0x1F, buf[0]);
  ASSERT_EQ (0x9A, buf[1]);
  ASSERT_EQ (0x0A, buf[2]);
}

/**
 * Test integer encoding with 8-bit prefix
 */
TEST (qpack_int_encode_8bit)
{
  unsigned char buf[16];
  size_t len;

  len = SocketQPACK_int_encode (42, 8, buf, sizeof (buf));
  ASSERT_EQ (1, len);
  ASSERT_EQ (42, buf[0]);
}

/**
 * Test integer encoding with null output
 */
TEST (qpack_int_encode_null_output)
{
  size_t len;

  len = SocketQPACK_int_encode (10, 5, NULL, 16);
  ASSERT_EQ (0, len);
}

/**
 * Test integer encoding with zero output size
 */
TEST (qpack_int_encode_zero_size)
{
  unsigned char buf[16];
  size_t len;

  len = SocketQPACK_int_encode (10, 5, buf, 0);
  ASSERT_EQ (0, len);
}

/* ============================================================================
 * Integer Decoding Tests (RFC 7541 Section 5.1)
 * ============================================================================
 */

/**
 * Test integer decoding with 5-bit prefix (small value)
 */
TEST (qpack_int_decode_5bit_small)
{
  unsigned char input[] = { 0x0A };
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  result = SocketQPACK_int_decode (input, sizeof (input), 5, &value, &consumed);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (10, value);
  ASSERT_EQ (1, consumed);
}

/**
 * Test integer decoding with 5-bit prefix (multi-byte)
 */
TEST (qpack_int_decode_5bit_multibyte)
{
  unsigned char input[] = { 0x1F, 0x9A, 0x0A };
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  result = SocketQPACK_int_decode (input, sizeof (input), 5, &value, &consumed);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (1337, value);
  ASSERT_EQ (3, consumed);
}

/**
 * Test integer decoding with incomplete data
 */
TEST (qpack_int_decode_incomplete)
{
  unsigned char input[] = { 0x1F, 0x9A }; /* Missing final byte */
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  result = SocketQPACK_int_decode (input, sizeof (input), 5, &value, &consumed);
  ASSERT_EQ (QPACK_INCOMPLETE, result);
}

/**
 * Test integer decoding with empty input
 */
TEST (qpack_int_decode_empty)
{
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  result = SocketQPACK_int_decode (NULL, 0, 5, &value, &consumed);
  ASSERT_EQ (QPACK_ERROR, result);
}

/* ============================================================================
 * Set Dynamic Table Capacity Encoding Tests (RFC 9204 Section 4.3.1)
 * ============================================================================
 */

/**
 * Test encoding single-byte capacity (0-31)
 */
TEST (qpack_encode_set_capacity_single_byte)
{
  unsigned char buf[16];
  size_t len;

  /* Capacity 10: pattern 001 | 0x0A = 0x2A */
  len = SocketQPACK_encode_set_capacity (10, buf, sizeof (buf));
  ASSERT_EQ (1, len);
  ASSERT_EQ (0x2A, buf[0]);
}

/**
 * Test encoding zero capacity (clears table)
 */
TEST (qpack_encode_set_capacity_zero)
{
  unsigned char buf[16];
  size_t len;

  /* Capacity 0: pattern 001 | 0x00 = 0x20 */
  len = SocketQPACK_encode_set_capacity (0, buf, sizeof (buf));
  ASSERT_EQ (1, len);
  ASSERT_EQ (0x20, buf[0]);
}

/**
 * Test encoding max single-byte capacity (31)
 */
TEST (qpack_encode_set_capacity_max_single)
{
  unsigned char buf[16];
  size_t len;

  /* Capacity 30: pattern 001 | 0x1E = 0x3E */
  len = SocketQPACK_encode_set_capacity (30, buf, sizeof (buf));
  ASSERT_EQ (1, len);
  ASSERT_EQ (0x3E, buf[0]);
}

/**
 * Test encoding multi-byte capacity (> 31)
 */
TEST (qpack_encode_set_capacity_multibyte)
{
  unsigned char buf[16];
  size_t len;

  /* Capacity 220:
   * 220 > 31, so: prefix = 31, remainder = 189
   * 189 >= 128, so needs continuation:
   *   189 = 61 + 1*128
   *   First continuation byte: (61 | 0x80) = 0xBD
   *   Second continuation byte: 0x01
   * Wire: 0x3F (0x20 | 0x1F), 0xBD (61 | 0x80), 0x01
   */
  len = SocketQPACK_encode_set_capacity (220, buf, sizeof (buf));
  ASSERT_EQ (3, len);
  ASSERT_EQ (0x3F, buf[0]); /* 0x20 | 0x1F = pattern + max prefix */
  ASSERT_EQ (0xBD, buf[1]); /* (189 & 0x7F) | 0x80 = 61 | 0x80 */
  ASSERT_EQ (0x01, buf[2]); /* 189 >> 7 = 1 */
}

/**
 * Test encoding capacity 4096 (typical default)
 */
TEST (qpack_encode_set_capacity_4096)
{
  unsigned char buf[16];
  size_t len;

  /* Capacity 4096:
   * 4096 > 31, so: prefix = 31, remainder = 4065
   * 4065 = 4065 mod 128 + (4065 / 128) * 128
   * 4065 / 128 = 31 remainder 97
   * Wire: 0x3F, 0xE1 (97 | 0x80), 0x1F (31)
   */
  len = SocketQPACK_encode_set_capacity (4096, buf, sizeof (buf));
  ASSERT_EQ (3, len);
  ASSERT_EQ (0x3F, buf[0]); /* 0x20 | 0x1F */
}

/**
 * Test encoding with NULL output
 */
TEST (qpack_encode_set_capacity_null)
{
  size_t len;

  len = SocketQPACK_encode_set_capacity (10, NULL, 16);
  ASSERT_EQ (0, len);
}

/**
 * Test encoding with insufficient buffer
 */
TEST (qpack_encode_set_capacity_small_buffer)
{
  unsigned char buf[1];
  size_t len;

  /* 4096 requires 3 bytes, but buffer is only 1 */
  len = SocketQPACK_encode_set_capacity (4096, buf, sizeof (buf));
  ASSERT_EQ (0, len);
}

/* ============================================================================
 * Set Dynamic Table Capacity Decoding Tests (RFC 9204 Section 4.3.1)
 * ============================================================================
 */

/**
 * Test decoding single-byte capacity
 */
TEST (qpack_decode_set_capacity_single_byte)
{
  unsigned char input[] = { 0x2A }; /* pattern 001 | 10 */
  size_t capacity;
  size_t consumed;
  SocketQPACK_Result result;

  result = SocketQPACK_decode_set_capacity (
      input, sizeof (input), &capacity, &consumed);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (10, capacity);
  ASSERT_EQ (1, consumed);
}

/**
 * Test decoding zero capacity
 */
TEST (qpack_decode_set_capacity_zero)
{
  unsigned char input[] = { 0x20 }; /* pattern 001 | 0 */
  size_t capacity;
  size_t consumed;
  SocketQPACK_Result result;

  result = SocketQPACK_decode_set_capacity (
      input, sizeof (input), &capacity, &consumed);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (0, capacity);
  ASSERT_EQ (1, consumed);
}

/**
 * Test decoding multi-byte capacity
 */
TEST (qpack_decode_set_capacity_multibyte)
{
  /* 220 = 31 + 189, 189 = 61 + 1*128 */
  unsigned char input[] = { 0x3F, 0xBD, 0x01 };
  size_t capacity;
  size_t consumed;
  SocketQPACK_Result result;

  result = SocketQPACK_decode_set_capacity (
      input, sizeof (input), &capacity, &consumed);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (220, capacity);
  ASSERT_EQ (3, consumed);
}

/**
 * Test decoding with wrong pattern
 */
TEST (qpack_decode_set_capacity_wrong_pattern)
{
  unsigned char input[] = { 0x80 }; /* Pattern 100 instead of 001 */
  size_t capacity;
  size_t consumed;
  SocketQPACK_Result result;

  result = SocketQPACK_decode_set_capacity (
      input, sizeof (input), &capacity, &consumed);
  ASSERT_EQ (QPACK_ERROR, result);
}

/**
 * Test decoding with incomplete data
 */
TEST (qpack_decode_set_capacity_incomplete)
{
  unsigned char input[] = { 0x3F }; /* Needs more bytes */
  size_t capacity;
  size_t consumed;
  SocketQPACK_Result result;

  result = SocketQPACK_decode_set_capacity (
      input, sizeof (input), &capacity, &consumed);
  ASSERT_EQ (QPACK_INCOMPLETE, result);
}

/**
 * Test decoding with empty input
 */
TEST (qpack_decode_set_capacity_empty)
{
  size_t capacity;
  size_t consumed;
  SocketQPACK_Result result;

  result = SocketQPACK_decode_set_capacity (NULL, 0, &capacity, &consumed);
  ASSERT_EQ (QPACK_ERROR, result);
}

/* ============================================================================
 * Dynamic Table Tests (RFC 9204 Section 3.2)
 * ============================================================================
 */

/**
 * Test creating a dynamic table
 */
TEST (qpack_table_new)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table;

  table = SocketQPACK_Table_new (4096, arena);
  ASSERT_NOT_NULL (table);
  ASSERT_EQ (0, SocketQPACK_Table_size (table));
  ASSERT_EQ (0, SocketQPACK_Table_count (table));
  ASSERT_EQ (4096, SocketQPACK_Table_max_size (table));

  SocketQPACK_Table_free (&table);
  ASSERT_NULL (table);

  Arena_dispose (&arena);
}

/**
 * Test creating a table with zero capacity
 */
TEST (qpack_table_new_zero)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table;

  table = SocketQPACK_Table_new (0, arena);
  ASSERT_NOT_NULL (table);
  ASSERT_EQ (0, SocketQPACK_Table_max_size (table));

  Arena_dispose (&arena);
}

/**
 * Test setting table max size
 */
TEST (qpack_table_set_max_size)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table;

  table = SocketQPACK_Table_new (4096, arena);
  ASSERT_NOT_NULL (table);

  SocketQPACK_Table_set_max_size (table, 2048);
  ASSERT_EQ (2048, SocketQPACK_Table_max_size (table));

  SocketQPACK_Table_set_max_size (table, 0);
  ASSERT_EQ (0, SocketQPACK_Table_max_size (table));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Apply Set Capacity Tests (RFC 9204 Section 4.3.1)
 * ============================================================================
 */

/**
 * Test applying set capacity to table
 */
TEST (qpack_apply_set_capacity)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table;
  SocketQPACK_Result result;

  table = SocketQPACK_Table_new (4096, arena);
  ASSERT_NOT_NULL (table);

  result = SocketQPACK_apply_set_capacity (table, 2048, 4096);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (2048, SocketQPACK_Table_max_size (table));

  Arena_dispose (&arena);
}

/**
 * Test applying zero capacity (clears table)
 */
TEST (qpack_apply_set_capacity_zero)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table;
  SocketQPACK_Result result;

  table = SocketQPACK_Table_new (4096, arena);
  ASSERT_NOT_NULL (table);

  result = SocketQPACK_apply_set_capacity (table, 0, 4096);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (0, SocketQPACK_Table_max_size (table));
  ASSERT_EQ (0, SocketQPACK_Table_size (table));
  ASSERT_EQ (0, SocketQPACK_Table_count (table));

  Arena_dispose (&arena);
}

/**
 * Test applying capacity exceeding maximum (error)
 */
TEST (qpack_apply_set_capacity_exceeds_max)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table;
  SocketQPACK_Result result;

  table = SocketQPACK_Table_new (4096, arena);
  ASSERT_NOT_NULL (table);

  result = SocketQPACK_apply_set_capacity (table, 8192, 4096);
  ASSERT_EQ (QPACK_ENCODER_STREAM_ERROR, result);

  Arena_dispose (&arena);
}

/**
 * Test applying capacity with NULL table
 */
TEST (qpack_apply_set_capacity_null_table)
{
  SocketQPACK_Result result;

  result = SocketQPACK_apply_set_capacity (NULL, 1024, 4096);
  ASSERT_EQ (QPACK_ERROR, result);
}

/* ============================================================================
 * Round-trip Tests (Encode -> Decode)
 * ============================================================================
 */

/**
 * Test round-trip for various capacity values
 */
TEST (qpack_set_capacity_roundtrip)
{
  unsigned char buf[16];
  size_t test_values[] = { 0, 1, 30, 31, 32, 100, 220, 1337, 4096, 65535 };
  size_t num_tests = sizeof (test_values) / sizeof (test_values[0]);

  for (size_t i = 0; i < num_tests; i++)
    {
      size_t original = test_values[i];
      size_t decoded;
      size_t consumed;
      size_t encoded_len;
      SocketQPACK_Result result;

      encoded_len
          = SocketQPACK_encode_set_capacity (original, buf, sizeof (buf));
      ASSERT (encoded_len > 0);

      result = SocketQPACK_decode_set_capacity (
          buf, encoded_len, &decoded, &consumed);
      ASSERT_EQ (QPACK_OK, result);
      ASSERT_EQ (original, decoded);
      ASSERT_EQ (encoded_len, consumed);
    }
}

/**
 * Test wire format compliance (pattern 001)
 */
TEST (qpack_set_capacity_wire_format)
{
  unsigned char buf[16];
  size_t len;

  /* All encoded Set Capacity instructions must have pattern 001 in top 3 bits
   */
  len = SocketQPACK_encode_set_capacity (0, buf, sizeof (buf));
  ASSERT (len > 0);
  ASSERT_EQ (0x20, buf[0] & 0xE0); /* Check pattern mask */

  len = SocketQPACK_encode_set_capacity (10, buf, sizeof (buf));
  ASSERT (len > 0);
  ASSERT_EQ (0x20, buf[0] & 0xE0);

  len = SocketQPACK_encode_set_capacity (1000, buf, sizeof (buf));
  ASSERT (len > 0);
  ASSERT_EQ (0x20, buf[0] & 0xE0);
}

/* ============================================================================
 * Integration Tests
 * ============================================================================
 */

/**
 * Test full workflow: encode, decode, apply
 */
TEST (qpack_set_capacity_integration)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table;
  unsigned char buf[16];
  size_t encoded_len;
  size_t decoded_capacity;
  size_t consumed;
  SocketQPACK_Result result;

  /* Create table */
  table = SocketQPACK_Table_new (4096, arena);
  ASSERT_NOT_NULL (table);
  ASSERT_EQ (4096, SocketQPACK_Table_max_size (table));

  /* Encode capacity change */
  encoded_len = SocketQPACK_encode_set_capacity (2048, buf, sizeof (buf));
  ASSERT (encoded_len > 0);

  /* Decode instruction */
  result = SocketQPACK_decode_set_capacity (
      buf, encoded_len, &decoded_capacity, &consumed);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (2048, decoded_capacity);

  /* Apply to table */
  result = SocketQPACK_apply_set_capacity (table, decoded_capacity, 4096);
  ASSERT_EQ (QPACK_OK, result);
  ASSERT_EQ (2048, SocketQPACK_Table_max_size (table));

  Arena_dispose (&arena);
}

/**
 * Test result string function
 */
TEST (qpack_result_string)
{
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_OK));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_INCOMPLETE));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERROR));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ENCODER_STREAM_ERROR));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERROR_NOT_FOUND));
}

/* ============================================================================
 * Static Table Tests (RFC 9204 Appendix A)
 * ============================================================================
 */

/**
 * Test static table entry 0: :authority (empty value)
 */
TEST (qpack_static_entry_0)
{
  const char *name, *value;
  size_t name_len, value_len;

  SocketQPACK_Result r
      = SocketQPACK_static_get (0, &name, &name_len, &value, &value_len);

  ASSERT_EQ (QPACK_OK, r);
  ASSERT_EQ (10, name_len);
  ASSERT (memcmp (name, ":authority", 10) == 0);
  ASSERT_EQ (0, value_len);
}

/**
 * Test static table entry 17: :method GET
 */
TEST (qpack_static_entry_17)
{
  const char *name, *value;
  size_t name_len, value_len;

  SocketQPACK_Result r
      = SocketQPACK_static_get (17, &name, &name_len, &value, &value_len);

  ASSERT_EQ (QPACK_OK, r);
  ASSERT_EQ (7, name_len);
  ASSERT (memcmp (name, ":method", 7) == 0);
  ASSERT_EQ (3, value_len);
  ASSERT (memcmp (value, "GET", 3) == 0);
}

/**
 * Test static table invalid index
 */
TEST (qpack_static_invalid_index)
{
  const char *name, *value;
  size_t name_len, value_len;

  SocketQPACK_Result r
      = SocketQPACK_static_get (99, &name, &name_len, &value, &value_len);

  ASSERT_EQ (QPACK_ERROR_INVALID_INDEX, r);
}

/**
 * Test static table find exact match
 */
TEST (qpack_static_find_exact)
{
  size_t idx;

  SocketQPACK_Result r
      = SocketQPACK_static_find (":method", 7, "GET", 3, &idx);

  ASSERT_EQ (QPACK_OK, r);
  ASSERT_EQ (17, idx);
}

/**
 * Test static table find empty value exact match
 */
TEST (qpack_static_find_empty_value)
{
  size_t idx;

  /* :authority has empty value at index 0 */
  SocketQPACK_Result r
      = SocketQPACK_static_find (":authority", 10, "", 0, &idx);

  ASSERT_EQ (QPACK_OK, r);
  ASSERT_EQ (0, idx);

  /* Also test with NULL value pointer and 0 length */
  r = SocketQPACK_static_find (":authority", 10, NULL, 0, &idx);
  ASSERT_EQ (QPACK_OK, r);
  ASSERT_EQ (0, idx);
}

/**
 * Test static table find case-insensitive
 */
TEST (qpack_static_find_case_insensitive)
{
  size_t idx;

  /* :METHOD should match :method */
  SocketQPACK_Result r
      = SocketQPACK_static_find (":METHOD", 7, "GET", 3, &idx);

  ASSERT_EQ (QPACK_OK, r);
  ASSERT_EQ (17, idx);
}

/**
 * Test static table find not found
 */
TEST (qpack_static_find_not_found)
{
  size_t idx;

  SocketQPACK_Result r
      = SocketQPACK_static_find ("x-custom-header", 15, "value", 5, &idx);

  ASSERT_EQ (QPACK_ERROR_NOT_FOUND, r);
}

/**
 * Test static table find name only
 */
TEST (qpack_static_find_name)
{
  size_t idx;

  /* :method first occurrence is at index 15 (CONNECT) */
  SocketQPACK_Result r = SocketQPACK_static_find_name (":method", 7, &idx);

  ASSERT_EQ (QPACK_OK, r);
  ASSERT_EQ (15, idx);
}

/**
 * Test static table length helpers
 */
TEST (qpack_static_length_helpers)
{
  ASSERT_EQ (10, SocketQPACK_static_name_len (0));
  ASSERT_EQ (0, SocketQPACK_static_value_len (0));
  ASSERT_EQ (7, SocketQPACK_static_name_len (17));
  ASSERT_EQ (3, SocketQPACK_static_value_len (17));
  ASSERT_EQ (0, SocketQPACK_static_name_len (99));
  ASSERT_EQ (0, SocketQPACK_static_value_len (99));
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  printf ("Running QPACK tests (RFC 9204)...\n\n");

  Test_run_all ();

  return Test_get_failures ();
}
