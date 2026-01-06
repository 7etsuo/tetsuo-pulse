/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack.c
 * @brief Unit tests for QPACK implementation (RFC 9204).
 *
 * Tests the Duplicate instruction (Section 4.3.4) and dynamic table.
 */

#include <string.h>

#include "core/Arena.h"
#include "quic/SocketQPACK.h"
#include "test/Test.h"

/* ============================================================================
 * Dynamic Table Tests
 * ============================================================================
 */

TEST (qpack_table_create)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table = SocketQPACK_Table_new (4096, arena);

  ASSERT_NOT_NULL (table);
  ASSERT_EQ (SocketQPACK_Table_size (table), 0);
  ASSERT_EQ (SocketQPACK_Table_count (table), 0);
  ASSERT_EQ (SocketQPACK_Table_max_capacity (table), 4096);
  ASSERT_EQ (SocketQPACK_Table_insertion_count (table), 0);

  Arena_dispose (&arena);
}

TEST (qpack_table_add_entry)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table = SocketQPACK_Table_new (4096, arena);
  SocketQPACK_Result result;
  SocketQPACK_FieldLine field;

  /* Add an entry */
  result = SocketQPACK_Table_add (table, "content-type", 12, "text/html", 9);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_count (table), 1);
  ASSERT_EQ (SocketQPACK_Table_insertion_count (table), 1);

  /* Size = 12 + 9 + 32 = 53 */
  ASSERT_EQ (SocketQPACK_Table_size (table), 53);

  /* Retrieve by relative index 0 (newest) */
  result = SocketQPACK_Table_get (table, 0, &field);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (field.name_len, 12);
  ASSERT_EQ (field.value_len, 9);
  ASSERT (memcmp (field.name, "content-type", 12) == 0);
  ASSERT (memcmp (field.value, "text/html", 9) == 0);

  Arena_dispose (&arena);
}

TEST (qpack_table_add_multiple_entries)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table = SocketQPACK_Table_new (4096, arena);
  SocketQPACK_Result result;
  SocketQPACK_FieldLine field;

  /* Add three entries */
  result = SocketQPACK_Table_add (table, "header-a", 8, "value-a", 7);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_Table_add (table, "header-b", 8, "value-b", 7);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_Table_add (table, "header-c", 8, "value-c", 7);
  ASSERT_EQ (result, QPACK_OK);

  ASSERT_EQ (SocketQPACK_Table_count (table), 3);
  ASSERT_EQ (SocketQPACK_Table_insertion_count (table), 3);

  /* Relative index 0 = newest (header-c) */
  result = SocketQPACK_Table_get (table, 0, &field);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT (memcmp (field.name, "header-c", 8) == 0);

  /* Relative index 1 = header-b */
  result = SocketQPACK_Table_get (table, 1, &field);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT (memcmp (field.name, "header-b", 8) == 0);

  /* Relative index 2 = oldest (header-a) */
  result = SocketQPACK_Table_get (table, 2, &field);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT (memcmp (field.name, "header-a", 8) == 0);

  /* Relative index 3 = out of bounds */
  result = SocketQPACK_Table_get (table, 3, &field);
  ASSERT_EQ (result, QPACK_ERROR_INVALID_INDEX);

  Arena_dispose (&arena);
}

TEST (qpack_table_eviction)
{
  Arena_T arena = Arena_new ();
  /* Small capacity to force eviction: each entry is ~47 bytes */
  SocketQPACK_Table_T table = SocketQPACK_Table_new (100, arena);
  SocketQPACK_Result result;
  SocketQPACK_FieldLine field;

  /* Add first entry (8+7+32 = 47 bytes) */
  result = SocketQPACK_Table_add (table, "header-a", 8, "value-a", 7);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_count (table), 1);

  /* Add second entry - should still fit (47+47 = 94 < 100) */
  result = SocketQPACK_Table_add (table, "header-b", 8, "value-b", 7);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_count (table), 2);

  /* Add third entry - should evict oldest (94+47 = 141 > 100) */
  result = SocketQPACK_Table_add (table, "header-c", 8, "value-c", 7);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_count (table), 2);

  /* Verify oldest was evicted - header-a should be gone */
  result = SocketQPACK_Table_get (table, 0, &field);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT (memcmp (field.name, "header-c", 8) == 0);

  result = SocketQPACK_Table_get (table, 1, &field);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT (memcmp (field.name, "header-b", 8) == 0);

  /* Insertion count still tracks all inserts */
  ASSERT_EQ (SocketQPACK_Table_insertion_count (table), 3);

  Arena_dispose (&arena);
}

TEST (qpack_table_capacity_update)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table = SocketQPACK_Table_new (4096, arena);
  SocketQPACK_Result result;

  /* Add entries */
  result = SocketQPACK_Table_add (table, "header-a", 8, "value-a", 7);
  ASSERT_EQ (result, QPACK_OK);
  result = SocketQPACK_Table_add (table, "header-b", 8, "value-b", 7);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_count (table), 2);

  /* Reduce capacity to force eviction */
  SocketQPACK_Table_set_capacity (table, 50);
  ASSERT_EQ (SocketQPACK_Table_max_capacity (table), 50);
  ASSERT_EQ (SocketQPACK_Table_count (table), 1);

  /* Set capacity to 0 clears table */
  SocketQPACK_Table_set_capacity (table, 0);
  ASSERT_EQ (SocketQPACK_Table_count (table), 0);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Integer Encoding Tests
 * ============================================================================
 */

TEST (qpack_int_encode_single_byte)
{
  uint8_t buf[16];
  size_t len;

  /* 5-bit prefix: values 0-30 fit in single byte */
  len = SocketQPACK_int_encode (0, 5, buf, sizeof (buf));
  ASSERT_EQ (len, 1);
  ASSERT_EQ (buf[0], 0x00);

  len = SocketQPACK_int_encode (15, 5, buf, sizeof (buf));
  ASSERT_EQ (len, 1);
  ASSERT_EQ (buf[0], 0x0F);

  len = SocketQPACK_int_encode (30, 5, buf, sizeof (buf));
  ASSERT_EQ (len, 1);
  ASSERT_EQ (buf[0], 0x1E);
}

TEST (qpack_int_encode_multi_byte)
{
  uint8_t buf[16];
  size_t len;

  /* 5-bit prefix: value 31 requires multi-byte (31 = 2^5-1 is the threshold) */
  len = SocketQPACK_int_encode (31, 5, buf, sizeof (buf));
  ASSERT_EQ (len, 2);
  ASSERT_EQ (buf[0], 0x1F); /* Prefix filled */
  ASSERT_EQ (buf[1], 0x00); /* 31 - 31 = 0 */

  /* Value 32 */
  len = SocketQPACK_int_encode (32, 5, buf, sizeof (buf));
  ASSERT_EQ (len, 2);
  ASSERT_EQ (buf[0], 0x1F);
  ASSERT_EQ (buf[1], 0x01); /* 32 - 31 = 1 */

  /* Larger value: 1000 with 5-bit prefix */
  len = SocketQPACK_int_encode (1000, 5, buf, sizeof (buf));
  ASSERT_EQ (len, 3);
  ASSERT_EQ (buf[0], 0x1F);
  /* 1000 - 31 = 969 = 0x3C9 */
  /* Encoded as: 0x49 (0b01001001 with continuation), 0x07 (0b00000111) */
  ASSERT_EQ (buf[1], 0xC9); /* 0x49 | 0x80 = continuation */
  ASSERT_EQ (buf[2], 0x07);
}

TEST (qpack_int_decode_single_byte)
{
  uint8_t input[] = { 0x0F };
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  result = SocketQPACK_int_decode (input, sizeof (input), 5, &value, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (value, 15);
  ASSERT_EQ (consumed, 1);
}

TEST (qpack_int_decode_multi_byte)
{
  /* Encode 1000 with 5-bit prefix and then decode */
  uint8_t buf[16];
  size_t len;
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  len = SocketQPACK_int_encode (1000, 5, buf, sizeof (buf));
  ASSERT (len > 0);

  result = SocketQPACK_int_decode (buf, len, 5, &value, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (value, 1000);
  ASSERT_EQ (consumed, len);
}

TEST (qpack_int_roundtrip)
{
  uint8_t buf[16];
  size_t len;
  uint64_t value;
  size_t consumed;

  /* Test various values with different prefix sizes */
  uint64_t test_values[]
      = { 0, 1, 30, 31, 32, 127, 128, 255, 256, 1000, 16383 };
  int prefixes[] = { 5, 6, 7, 8 };

  for (size_t i = 0; i < sizeof (test_values) / sizeof (test_values[0]); i++)
    {
      for (size_t j = 0; j < sizeof (prefixes) / sizeof (prefixes[0]); j++)
        {
          len = SocketQPACK_int_encode (
              test_values[i], prefixes[j], buf, sizeof (buf));
          ASSERT (len > 0);

          SocketQPACK_Result result = SocketQPACK_int_decode (
              buf, len, prefixes[j], &value, &consumed);
          ASSERT_EQ (result, QPACK_OK);
          ASSERT_EQ (value, test_values[i]);
        }
    }
}

/* ============================================================================
 * Duplicate Instruction Tests (RFC 9204 Section 4.3.4)
 * ============================================================================
 */

TEST (qpack_encode_duplicate_single_byte)
{
  uint8_t buf[16];
  size_t len;

  /* Relative index 0 - single byte */
  len = SocketQPACK_encode_duplicate (0, buf, sizeof (buf));
  ASSERT_EQ (len, 1);
  /* Pattern 000 + index 0 = 0x00 */
  ASSERT_EQ (buf[0], 0x00);

  /* Relative index 15 - single byte */
  len = SocketQPACK_encode_duplicate (15, buf, sizeof (buf));
  ASSERT_EQ (len, 1);
  ASSERT_EQ (buf[0], 0x0F);

  /* Relative index 30 - single byte */
  len = SocketQPACK_encode_duplicate (30, buf, sizeof (buf));
  ASSERT_EQ (len, 1);
  ASSERT_EQ (buf[0], 0x1E);
}

TEST (qpack_encode_duplicate_multi_byte)
{
  uint8_t buf[16];
  size_t len;

  /* Relative index 31 - multi-byte (>= 2^5-1) */
  len = SocketQPACK_encode_duplicate (31, buf, sizeof (buf));
  ASSERT_EQ (len, 2);
  ASSERT_EQ (buf[0], 0x1F); /* 000 + 11111 */
  ASSERT_EQ (buf[1], 0x00); /* 31 - 31 = 0 */

  /* Relative index 100 */
  len = SocketQPACK_encode_duplicate (100, buf, sizeof (buf));
  ASSERT_EQ (len, 2);
  ASSERT_EQ (buf[0], 0x1F);
  ASSERT_EQ (buf[1], 0x45); /* 100 - 31 = 69 = 0x45 */
}

TEST (qpack_decode_duplicate_single_byte)
{
  uint8_t input[] = { 0x0F };
  size_t rel_index;
  size_t consumed;
  SocketQPACK_Result result;

  result = SocketQPACK_decode_duplicate (
      input, sizeof (input), &rel_index, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (rel_index, 15);
  ASSERT_EQ (consumed, 1);
}

TEST (qpack_decode_duplicate_multi_byte)
{
  /* Encode and decode index 100 */
  uint8_t buf[16];
  size_t len;
  size_t rel_index;
  size_t consumed;
  SocketQPACK_Result result;

  len = SocketQPACK_encode_duplicate (100, buf, sizeof (buf));
  ASSERT (len > 0);

  result = SocketQPACK_decode_duplicate (buf, len, &rel_index, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (rel_index, 100);
  ASSERT_EQ (consumed, len);
}

TEST (qpack_decode_duplicate_wrong_pattern)
{
  /* 0x20 has pattern 001 (not 000), should fail */
  uint8_t input[] = { 0x20 };
  size_t rel_index;
  size_t consumed;
  SocketQPACK_Result result;

  result = SocketQPACK_decode_duplicate (
      input, sizeof (input), &rel_index, &consumed);
  ASSERT_EQ (result, QPACK_ERROR_PARSE);
}

TEST (qpack_duplicate_roundtrip)
{
  uint8_t buf[16];
  size_t len;
  size_t rel_index;
  size_t consumed;

  /* Test various indices */
  size_t test_indices[] = { 0, 1, 15, 30, 31, 32, 100, 255, 1000 };

  for (size_t i = 0; i < sizeof (test_indices) / sizeof (test_indices[0]); i++)
    {
      len = SocketQPACK_encode_duplicate (test_indices[i], buf, sizeof (buf));
      ASSERT (len > 0);

      SocketQPACK_Result result
          = SocketQPACK_decode_duplicate (buf, len, &rel_index, &consumed);
      ASSERT_EQ (result, QPACK_OK);
      ASSERT_EQ (rel_index, test_indices[i]);
    }
}

/* ============================================================================
 * Process Duplicate Tests
 * ============================================================================
 */

TEST (qpack_process_duplicate_creates_copy)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table = SocketQPACK_Table_new (4096, arena);
  SocketQPACK_Result result;
  SocketQPACK_FieldLine field1, field2;

  /* Add an entry */
  result = SocketQPACK_Table_add (table, "my-header", 9, "my-value", 8);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_count (table), 1);

  /* Duplicate it (relative index 0 = newest) */
  result = SocketQPACK_process_duplicate (table, 0);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_count (table), 2);

  /* Both entries should have same name/value */
  result = SocketQPACK_Table_get (table, 0, &field1); /* newest (duplicate) */
  ASSERT_EQ (result, QPACK_OK);
  result = SocketQPACK_Table_get (table, 1, &field2); /* original */
  ASSERT_EQ (result, QPACK_OK);

  ASSERT_EQ (field1.name_len, field2.name_len);
  ASSERT_EQ (field1.value_len, field2.value_len);
  ASSERT (memcmp (field1.name, field2.name, field1.name_len) == 0);
  ASSERT (memcmp (field1.value, field2.value, field1.value_len) == 0);

  /* They should be separate copies (different memory) */
  ASSERT (field1.name != field2.name);
  ASSERT (field1.value != field2.value);

  Arena_dispose (&arena);
}

TEST (qpack_process_duplicate_new_absolute_index)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table = SocketQPACK_Table_new (4096, arena);
  SocketQPACK_Result result;

  /* Add an entry */
  result = SocketQPACK_Table_add (table, "my-header", 9, "my-value", 8);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_insertion_count (table), 1);

  /* Duplicate it */
  result = SocketQPACK_process_duplicate (table, 0);
  ASSERT_EQ (result, QPACK_OK);

  /* Insertion count should increase (new absolute index) */
  ASSERT_EQ (SocketQPACK_Table_insertion_count (table), 2);

  Arena_dispose (&arena);
}

TEST (qpack_process_duplicate_invalid_index)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table = SocketQPACK_Table_new (4096, arena);
  SocketQPACK_Result result;

  /* Empty table - any index is invalid */
  result = SocketQPACK_process_duplicate (table, 0);
  ASSERT_EQ (result, QPACK_ERROR_INVALID_INDEX);

  /* Add one entry */
  result = SocketQPACK_Table_add (table, "header", 6, "value", 5);
  ASSERT_EQ (result, QPACK_OK);

  /* Index 1 is out of bounds (only index 0 valid) */
  result = SocketQPACK_process_duplicate (table, 1);
  ASSERT_EQ (result, QPACK_ERROR_INVALID_INDEX);

  /* Index 0 should work */
  result = SocketQPACK_process_duplicate (table, 0);
  ASSERT_EQ (result, QPACK_OK);

  Arena_dispose (&arena);
}

TEST (qpack_process_duplicate_near_eviction)
{
  Arena_T arena = Arena_new ();
  /* Small capacity: each entry ~47 bytes, capacity allows ~2 entries */
  SocketQPACK_Table_T table = SocketQPACK_Table_new (100, arena);
  SocketQPACK_Result result;
  SocketQPACK_FieldLine field;

  /* Add two entries (fills table) */
  result = SocketQPACK_Table_add (table, "header-a", 8, "value-a", 7);
  ASSERT_EQ (result, QPACK_OK);
  result = SocketQPACK_Table_add (table, "header-b", 8, "value-b", 7);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (SocketQPACK_Table_count (table), 2);

  /* Duplicate entry at index 1 (older, near eviction boundary) */
  result = SocketQPACK_process_duplicate (table, 1);
  ASSERT_EQ (result, QPACK_OK);

  /* Table should still have 2 entries (one evicted to make room) */
  ASSERT_EQ (SocketQPACK_Table_count (table), 2);

  /* Newest should be the duplicate of header-a */
  result = SocketQPACK_Table_get (table, 0, &field);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT (memcmp (field.name, "header-a", 8) == 0);

  Arena_dispose (&arena);
}

TEST (qpack_process_duplicate_can_reference_in_same_request)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table = SocketQPACK_Table_new (4096, arena);
  SocketQPACK_Result result;
  SocketQPACK_FieldLine field;

  /* Add original entry */
  result = SocketQPACK_Table_add (table, "x-custom", 8, "foobar", 6);
  ASSERT_EQ (result, QPACK_OK);

  /* Duplicate it */
  result = SocketQPACK_process_duplicate (table, 0);
  ASSERT_EQ (result, QPACK_OK);

  /* Add another entry */
  result = SocketQPACK_Table_add (table, "x-other", 7, "baz", 3);
  ASSERT_EQ (result, QPACK_OK);

  ASSERT_EQ (SocketQPACK_Table_count (table), 3);

  /* Can reference the duplicated entry (now at index 1) */
  result = SocketQPACK_Table_get (table, 1, &field);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT (memcmp (field.name, "x-custom", 8) == 0);
  ASSERT (memcmp (field.value, "foobar", 6) == 0);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Error Handling Tests
 * ============================================================================
 */

TEST (qpack_decode_incomplete_input)
{
  /* Multi-byte encoding cut short */
  uint8_t input[] = { 0x1F }; /* Indicates more bytes needed */
  size_t rel_index;
  size_t consumed;
  SocketQPACK_Result result;

  result = SocketQPACK_decode_duplicate (
      input, sizeof (input), &rel_index, &consumed);
  ASSERT_EQ (result, QPACK_INCOMPLETE);
}

TEST (qpack_encode_buffer_too_small)
{
  uint8_t buf[1];
  size_t len;

  /* Large index needs multi-byte encoding, buffer too small */
  len = SocketQPACK_encode_duplicate (1000, buf, sizeof (buf));
  ASSERT_EQ (len, 0);
}

TEST (qpack_entry_size_calculation)
{
  size_t size;

  /* Normal calculation */
  size = SocketQPACK_entry_size (10, 20);
  ASSERT_EQ (size, 10 + 20 + 32);

  /* Zero-length fields */
  size = SocketQPACK_entry_size (0, 0);
  ASSERT_EQ (size, 32);
}

/* ============================================================================
 * Integration Test: Insert, Duplicate, Reference Sequence
 * ============================================================================
 */

TEST (qpack_integration_insert_duplicate_reference)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table = SocketQPACK_Table_new (4096, arena);
  SocketQPACK_Result result;
  SocketQPACK_FieldLine field;
  uint8_t wire_buf[16];
  size_t wire_len;
  size_t decoded_index;
  size_t consumed;

  /* 1. Insert entry at absolute index 0 */
  result = SocketQPACK_Table_add (table, "content-length", 14, "1234", 4);
  ASSERT_EQ (result, QPACK_OK);

  /* 2. Encode duplicate instruction for relative index 0 */
  wire_len = SocketQPACK_encode_duplicate (0, wire_buf, sizeof (wire_buf));
  ASSERT (wire_len > 0);
  ASSERT_EQ (wire_buf[0], 0x00); /* Pattern 000 + index 0 */

  /* 3. Decode the instruction */
  result = SocketQPACK_decode_duplicate (
      wire_buf, wire_len, &decoded_index, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded_index, 0);

  /* 4. Process the duplicate instruction */
  result = SocketQPACK_process_duplicate (table, decoded_index);
  ASSERT_EQ (result, QPACK_OK);

  /* 5. Verify we can reference both entries */
  ASSERT_EQ (SocketQPACK_Table_count (table), 2);

  /* Original at index 1 */
  result = SocketQPACK_Table_get (table, 1, &field);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT (memcmp (field.name, "content-length", 14) == 0);

  /* Duplicate at index 0 (newest) */
  result = SocketQPACK_Table_get (table, 0, &field);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT (memcmp (field.name, "content-length", 14) == 0);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
