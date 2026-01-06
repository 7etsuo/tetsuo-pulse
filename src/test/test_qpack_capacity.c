/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_capacity.c
 * @brief Unit tests for QPACK Set Dynamic Table Capacity (RFC 9204 Section
 * 4.3.1)
 *
 * Tests the encode, decode, and apply functions for the Set Dynamic Table
 * Capacity instruction.
 */

#include <string.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACK-private.h"
#include "http/qpack/SocketQPACK.h"
#include "test/Test.h"

/* ============================================================================
 * ENCODE SET CAPACITY TESTS
 * ============================================================================
 */

TEST (qpack_encode_capacity_null_output)
{
  size_t written = 999;
  SocketQPACK_Result result
      = SocketQPACK_encode_set_capacity (100, NULL, 16, &written);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_encode_capacity_null_written)
{
  unsigned char buf[16];
  SocketQPACK_Result result
      = SocketQPACK_encode_set_capacity (100, buf, sizeof (buf), NULL);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_encode_capacity_zero_buffer)
{
  unsigned char buf[1];
  size_t written = 999;
  SocketQPACK_Result result
      = SocketQPACK_encode_set_capacity (100, buf, 0, &written);
  ASSERT_EQ (result, QPACK_ERR_TABLE_SIZE);
}

TEST (qpack_encode_capacity_zero_value)
{
  unsigned char buf[16];
  size_t written = 0;

  /* Capacity of 0 disables the dynamic table */
  SocketQPACK_Result result
      = SocketQPACK_encode_set_capacity (0, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 1);
  /* Pattern is 001xxxxx = 0x20, value 0 fits in 5 bits */
  ASSERT_EQ (buf[0], 0x20);
}

TEST (qpack_encode_capacity_small_value)
{
  unsigned char buf[16];
  size_t written = 0;

  /* Value 4096 fits in 5-bit prefix (< 31) */
  SocketQPACK_Result result
      = SocketQPACK_encode_set_capacity (20, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 1);
  /* Pattern 001 | 20 = 0x20 | 0x14 = 0x34 */
  ASSERT_EQ (buf[0], 0x34);
}

TEST (qpack_encode_capacity_max_prefix_value)
{
  unsigned char buf[16];
  size_t written = 0;

  /* Value 30 (max that fits in 5 bits without continuation) */
  SocketQPACK_Result result
      = SocketQPACK_encode_set_capacity (30, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (written, 1);
  /* Pattern 001 | 30 = 0x20 | 0x1E = 0x3E */
  ASSERT_EQ (buf[0], 0x3E);
}

TEST (qpack_encode_capacity_requires_continuation)
{
  unsigned char buf[16];
  size_t written = 0;

  /* Value 31 requires continuation (5-bit max is 31, which triggers multi-byte
   */
  SocketQPACK_Result result
      = SocketQPACK_encode_set_capacity (31, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT (written > 1);
  /* First byte should have all 5 prefix bits set (001 11111 = 0x3F) */
  ASSERT_EQ (buf[0], 0x3F);
}

TEST (qpack_encode_capacity_large_value)
{
  unsigned char buf[16];
  size_t written = 0;

  /* Value 4096 - typical table size */
  SocketQPACK_Result result
      = SocketQPACK_encode_set_capacity (4096, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT (written > 1);
  /* First byte should have pattern 001 with prefix bits maxed */
  ASSERT_EQ (buf[0], 0x3F);
}

TEST (qpack_encode_capacity_buffer_too_small)
{
  unsigned char buf[1];
  size_t written = 999;

  /* Large value needs multiple bytes, but buffer is only 1 byte */
  SocketQPACK_Result result
      = SocketQPACK_encode_set_capacity (1000000, buf, 1, &written);
  ASSERT_EQ (result, QPACK_ERR_TABLE_SIZE);
}

/* ============================================================================
 * DECODE SET CAPACITY TESTS
 * ============================================================================
 */

TEST (qpack_decode_capacity_null_capacity)
{
  unsigned char buf[] = { 0x20 };
  size_t consumed = 999;
  SocketQPACK_Result result
      = SocketQPACK_decode_set_capacity (buf, sizeof (buf), NULL, &consumed);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_decode_capacity_null_consumed)
{
  unsigned char buf[] = { 0x20 };
  uint64_t capacity = 999;
  SocketQPACK_Result result
      = SocketQPACK_decode_set_capacity (buf, sizeof (buf), &capacity, NULL);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_decode_capacity_empty_input)
{
  uint64_t capacity = 999;
  size_t consumed = 999;
  SocketQPACK_Result result
      = SocketQPACK_decode_set_capacity (NULL, 0, &capacity, &consumed);
  ASSERT_EQ (result, QPACK_INCOMPLETE);
  ASSERT_EQ (capacity, 0);
  ASSERT_EQ (consumed, 0);
}

TEST (qpack_decode_capacity_wrong_pattern)
{
  /* Pattern 0x80 is Insert with Name Reference, not Set Capacity */
  unsigned char buf[] = { 0x80 };
  uint64_t capacity = 999;
  size_t consumed = 999;
  SocketQPACK_Result result = SocketQPACK_decode_set_capacity (
      buf, sizeof (buf), &capacity, &consumed);
  ASSERT_EQ (result, QPACK_ERR_INTEGER);
}

TEST (qpack_decode_capacity_zero_value)
{
  unsigned char buf[] = { 0x20 }; /* Pattern 001 | 0 */
  uint64_t capacity = 999;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_set_capacity (
      buf, sizeof (buf), &capacity, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (capacity, 0);
  ASSERT_EQ (consumed, 1);
}

TEST (qpack_decode_capacity_small_value)
{
  unsigned char buf[] = { 0x34 }; /* Pattern 001 | 20 */
  uint64_t capacity = 0;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_set_capacity (
      buf, sizeof (buf), &capacity, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (capacity, 20);
  ASSERT_EQ (consumed, 1);
}

TEST (qpack_decode_capacity_incomplete_multibyte)
{
  /* Multi-byte integer but only first byte provided */
  unsigned char buf[] = { 0x3F }; /* Pattern 001 | 11111 (needs continuation) */
  uint64_t capacity = 999;
  size_t consumed = 999;

  SocketQPACK_Result result = SocketQPACK_decode_set_capacity (
      buf, sizeof (buf), &capacity, &consumed);
  ASSERT_EQ (result, QPACK_INCOMPLETE);
}

TEST (qpack_decode_capacity_multibyte)
{
  /* Encode value 31: prefix 11111 (31) + continuation 0x00 (value = 31 + 0) */
  unsigned char buf[] = { 0x3F, 0x00 };
  uint64_t capacity = 0;
  size_t consumed = 0;

  SocketQPACK_Result result = SocketQPACK_decode_set_capacity (
      buf, sizeof (buf), &capacity, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (capacity, 31);
  ASSERT_EQ (consumed, 2);
}

/* ============================================================================
 * ENCODE/DECODE ROUNDTRIP TESTS
 * ============================================================================
 */

TEST (qpack_capacity_roundtrip_zero)
{
  unsigned char buf[16];
  size_t written = 0;
  uint64_t decoded_capacity = 999;
  size_t consumed = 0;

  SocketQPACK_Result result
      = SocketQPACK_encode_set_capacity (0, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_decode_set_capacity (
      buf, written, &decoded_capacity, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded_capacity, 0);
  ASSERT_EQ (consumed, written);
}

TEST (qpack_capacity_roundtrip_small)
{
  unsigned char buf[16];
  size_t written = 0;
  uint64_t decoded_capacity = 0;
  size_t consumed = 0;
  uint64_t original = 25;

  SocketQPACK_Result result
      = SocketQPACK_encode_set_capacity (original, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_decode_set_capacity (
      buf, written, &decoded_capacity, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded_capacity, original);
  ASSERT_EQ (consumed, written);
}

TEST (qpack_capacity_roundtrip_typical)
{
  unsigned char buf[16];
  size_t written = 0;
  uint64_t decoded_capacity = 0;
  size_t consumed = 0;
  uint64_t original = 4096; /* Default table size */

  SocketQPACK_Result result
      = SocketQPACK_encode_set_capacity (original, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_decode_set_capacity (
      buf, written, &decoded_capacity, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded_capacity, original);
  ASSERT_EQ (consumed, written);
}

TEST (qpack_capacity_roundtrip_max)
{
  unsigned char buf[16];
  size_t written = 0;
  uint64_t decoded_capacity = 0;
  size_t consumed = 0;
  uint64_t original = 65536; /* 64KB */

  SocketQPACK_Result result
      = SocketQPACK_encode_set_capacity (original, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_decode_set_capacity (
      buf, written, &decoded_capacity, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded_capacity, original);
  ASSERT_EQ (consumed, written);
}

TEST (qpack_capacity_roundtrip_large)
{
  unsigned char buf[16];
  size_t written = 0;
  uint64_t decoded_capacity = 0;
  size_t consumed = 0;
  uint64_t original = 1000000; /* 1MB */

  SocketQPACK_Result result
      = SocketQPACK_encode_set_capacity (original, buf, sizeof (buf), &written);
  ASSERT_EQ (result, QPACK_OK);

  result = SocketQPACK_decode_set_capacity (
      buf, written, &decoded_capacity, &consumed);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (decoded_capacity, original);
  ASSERT_EQ (consumed, written);
}

/* ============================================================================
 * APPLY SET CAPACITY TESTS
 * ============================================================================
 */

TEST (qpack_apply_capacity_null_table)
{
  SocketQPACK_Result result
      = SocketQPACK_apply_set_capacity (NULL, 4096, 65536);
  ASSERT_EQ (result, QPACK_ERR_NULL_PARAM);
}

TEST (qpack_apply_capacity_exceeds_max)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Create a minimal table structure for testing */
  struct SocketQPACK_Table table;
  memset (&table, 0, sizeof (table));
  table.arena = arena;
  table.max_size = 4096;

  /* Try to set capacity higher than max_capacity */
  SocketQPACK_Result result
      = SocketQPACK_apply_set_capacity (&table, 8000, 4096);
  ASSERT_EQ (result, QPACK_ERR_TABLE_SIZE);

  Arena_dispose (&arena);
}

TEST (qpack_apply_capacity_set_to_zero)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Create a table with some capacity */
  struct SocketQPACK_Table table;
  memset (&table, 0, sizeof (table));
  table.arena = arena;
  table.max_size = 4096;
  table.size = 0;
  table.count = 0;

  /* Set capacity to 0 (disable table) */
  SocketQPACK_Result result = SocketQPACK_apply_set_capacity (&table, 0, 65536);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (table.max_size, 0);

  Arena_dispose (&arena);
}

TEST (qpack_apply_capacity_increase)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Create a table with small capacity */
  struct SocketQPACK_Table table;
  memset (&table, 0, sizeof (table));
  table.arena = arena;
  table.max_size = 1024;
  table.size = 500;
  table.count = 5;

  /* Increase capacity */
  SocketQPACK_Result result
      = SocketQPACK_apply_set_capacity (&table, 8192, 65536);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (table.max_size, 8192);
  /* Size and count unchanged when increasing capacity */
  ASSERT_EQ (table.size, 500);
  ASSERT_EQ (table.count, 5);

  Arena_dispose (&arena);
}

TEST (qpack_apply_capacity_decrease_no_eviction)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Create a table with room to spare */
  struct SocketQPACK_Table table;
  memset (&table, 0, sizeof (table));
  table.arena = arena;
  table.max_size = 4096;
  table.size = 500;
  table.count = 5;

  /* Decrease capacity but still above current size */
  SocketQPACK_Result result
      = SocketQPACK_apply_set_capacity (&table, 2048, 65536);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (table.max_size, 2048);
  /* No eviction needed */
  ASSERT_EQ (table.size, 500);
  ASSERT_EQ (table.count, 5);

  Arena_dispose (&arena);
}

TEST (qpack_apply_capacity_decrease_with_eviction)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Create table with entries */
  size_t capacity = 16; /* Power of 2 for ring buffer */
  QPACK_DynamicEntry *entries = CALLOC (arena, capacity, sizeof (*entries));
  ASSERT_NOT_NULL (entries);

  /* Setup entry 0 (head) - will be evicted */
  entries[0].name = "header1";
  entries[0].name_len = 7;
  entries[0].value = "value1";
  entries[0].value_len = 6;
  entries[0].meta.abs_index = 0;

  /* Setup entry 1 - will survive */
  entries[1].name = "h2";
  entries[1].name_len = 2;
  entries[1].value = "v2";
  entries[1].value_len = 2;
  entries[1].meta.abs_index = 1;

  struct SocketQPACK_Table table;
  memset (&table, 0, sizeof (table));
  table.arena = arena;
  table.entries = entries;
  table.capacity = capacity;
  table.head = 0;
  table.tail = 2;
  table.count = 2;
  /* Entry 0: 7+6+32=45, Entry 1: 2+2+32=36, Total=81 */
  table.size = 45 + 36;
  table.max_size = 4096;
  table.insert_count = 2;
  table.dropped_count = 0;

  /* Decrease capacity below entry 0's size - should evict entry 0 */
  SocketQPACK_Result result
      = SocketQPACK_apply_set_capacity (&table, 50, 65536);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (table.max_size, 50);
  ASSERT_EQ (table.count, 1);
  ASSERT_EQ (table.size, 36); /* Only entry 1 remains */
  ASSERT_EQ (table.head, 1);  /* Head advanced */
  ASSERT_EQ (table.dropped_count, 1);

  Arena_dispose (&arena);
}

TEST (qpack_apply_capacity_evict_all)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  /* Create table with entries */
  size_t capacity = 16;
  QPACK_DynamicEntry *entries = CALLOC (arena, capacity, sizeof (*entries));
  ASSERT_NOT_NULL (entries);

  /* Setup two entries */
  entries[0].name = "header1";
  entries[0].name_len = 7;
  entries[0].value = "value1";
  entries[0].value_len = 6;

  entries[1].name = "h2";
  entries[1].name_len = 2;
  entries[1].value = "v2";
  entries[1].value_len = 2;

  struct SocketQPACK_Table table;
  memset (&table, 0, sizeof (table));
  table.arena = arena;
  table.entries = entries;
  table.capacity = capacity;
  table.head = 0;
  table.tail = 2;
  table.count = 2;
  table.size = 45 + 36;
  table.max_size = 4096;
  table.insert_count = 2;
  table.dropped_count = 0;

  /* Set capacity to 0 - evict all entries */
  SocketQPACK_Result result = SocketQPACK_apply_set_capacity (&table, 0, 65536);
  ASSERT_EQ (result, QPACK_OK);
  ASSERT_EQ (table.max_size, 0);
  ASSERT_EQ (table.count, 0);
  ASSERT_EQ (table.size, 0);
  ASSERT_EQ (table.dropped_count, 2);

  Arena_dispose (&arena);
}

/* ============================================================================
 * MAIN
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
