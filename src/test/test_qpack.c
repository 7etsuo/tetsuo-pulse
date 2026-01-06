/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_qpack.c - Unit tests for QPACK Header Compression
 *
 * Part of the Socket Library
 *
 * Tests RFC 9204 QPACK implementation including:
 * - Integer encoding/decoding (Section 5.1)
 * - Static table lookup (Appendix A)
 * - Literal Field Line with Name Reference (Section 4.5.4)
 * - Huffman encoding/decoding (same as HPACK RFC 7541)
 * - Dynamic table operations
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
 * Integer Encoding Tests (RFC 9204 Section 5.1)
 * ============================================================================
 */

/**
 * Test integer encoding with 4-bit prefix (used in Literal Name Reference)
 */
static void
test_int_encode_4bit_small (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 5 with 4-bit prefix... ");

  len = SocketQPACK_int_encode (5, 4, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Expected 1 byte");
  TEST_ASSERT ((buf[0] & 0x0F) == 0x05, "Expected 0x05 in lower 4 bits");

  printf ("PASS\n");
}

/**
 * Test integer encoding requiring multi-byte with 4-bit prefix
 */
static void
test_int_encode_4bit_large (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 20 with 4-bit prefix... ");

  /* 20 > 15 (max 4-bit), so needs continuation */
  len = SocketQPACK_int_encode (20, 4, buf, sizeof (buf));
  TEST_ASSERT (len == 2, "Expected 2 bytes");
  TEST_ASSERT ((buf[0] & 0x0F) == 0x0F, "First byte should be 15 (2^4 - 1)");
  TEST_ASSERT (buf[1] == 0x05, "Second byte should be 5 (20-15)");

  printf ("PASS\n");
}

/**
 * Test integer decoding with 4-bit prefix
 */
static void
test_int_decode_4bit_small (void)
{
  unsigned char data[]
      = { 0x35 }; /* 0011 0101 - upper bits ignored, lower = 5 */
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Integer decode 5 with 4-bit prefix... ");

  result = SocketQPACK_int_decode (data, sizeof (data), 4, &value, &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (value == 5, "Value should be 5");
  TEST_ASSERT (consumed == 1, "Should consume 1 byte");

  printf ("PASS\n");
}

/**
 * Test multi-byte integer decoding with 4-bit prefix
 */
static void
test_int_decode_4bit_large (void)
{
  unsigned char data[] = { 0x0F, 0x05 }; /* 15 + 5 = 20 */
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Integer decode 20 with 4-bit prefix... ");

  result = SocketQPACK_int_decode (data, sizeof (data), 4, &value, &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (value == 20, "Value should be 20");
  TEST_ASSERT (consumed == 2, "Should consume 2 bytes");

  printf ("PASS\n");
}

/**
 * Test integer decode with incomplete data
 */
static void
test_int_decode_incomplete (void)
{
  unsigned char data[] = { 0x0F }; /* Needs continuation but none provided */
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Integer decode incomplete data... ");

  result = SocketQPACK_int_decode (data, sizeof (data), 4, &value, &consumed);
  TEST_ASSERT (result == QPACK_INCOMPLETE, "Should return INCOMPLETE");

  printf ("PASS\n");
}

/* ============================================================================
 * Static Table Tests (RFC 9204 Appendix A)
 * ============================================================================
 */

/**
 * Test static table entry 0 (:authority)
 */
static void
test_static_table_entry_0 (void)
{
  SocketQPACK_Header header;
  SocketQPACK_Result result;

  printf ("  Static table entry 0 (:authority)... ");

  result = SocketQPACK_static_get (0, &header);
  TEST_ASSERT (result == QPACK_OK, "Should get OK");
  TEST_ASSERT (strcmp (header.name, ":authority") == 0,
               "Name should be :authority");
  TEST_ASSERT (header.name_len == 10, "Name length should be 10");
  TEST_ASSERT (header.value_len == 0, "Value should be empty");

  printf ("PASS\n");
}

/**
 * Test static table entry 17 (:method GET)
 */
static void
test_static_table_entry_17 (void)
{
  SocketQPACK_Header header;
  SocketQPACK_Result result;

  printf ("  Static table entry 17 (:method GET)... ");

  result = SocketQPACK_static_get (17, &header);
  TEST_ASSERT (result == QPACK_OK, "Should get OK");
  TEST_ASSERT (strcmp (header.name, ":method") == 0, "Name should be :method");
  TEST_ASSERT (strcmp (header.value, "GET") == 0, "Value should be GET");

  printf ("PASS\n");
}

/**
 * Test static table entry 25 (:status 200)
 */
static void
test_static_table_entry_25 (void)
{
  SocketQPACK_Header header;
  SocketQPACK_Result result;

  printf ("  Static table entry 25 (:status 200)... ");

  result = SocketQPACK_static_get (25, &header);
  TEST_ASSERT (result == QPACK_OK, "Should get OK");
  TEST_ASSERT (strcmp (header.name, ":status") == 0, "Name should be :status");
  TEST_ASSERT (strcmp (header.value, "200") == 0, "Value should be 200");

  printf ("PASS\n");
}

/**
 * Test static table invalid index
 */
static void
test_static_table_invalid (void)
{
  SocketQPACK_Header header;
  SocketQPACK_Result result;

  printf ("  Static table invalid index... ");

  result = SocketQPACK_static_get (99, &header);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_INDEX,
               "Should return INVALID_INDEX");

  result = SocketQPACK_static_get (1000, &header);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_INDEX,
               "Should return INVALID_INDEX");

  printf ("PASS\n");
}

/**
 * Test static table find
 */
static void
test_static_table_find (void)
{
  int idx;

  printf ("  Static table find... ");

  /* Exact match */
  idx = SocketQPACK_static_find (":method", 7, "GET", 3);
  TEST_ASSERT (idx == 18, "Should find :method GET at index 17 (1-based: 18)");

  /* Name-only match */
  idx = SocketQPACK_static_find (":method", 7, "PATCH", 5);
  TEST_ASSERT (idx < 0, "Should return negative for name-only match");
  TEST_ASSERT (-idx >= 16 && -idx <= 22, "Should find :method in range 15-21");

  /* Not found */
  idx = SocketQPACK_static_find ("x-custom", 8, NULL, 0);
  TEST_ASSERT (idx == 0, "Should return 0 for not found");

  printf ("PASS\n");
}

/* ============================================================================
 * Pattern Detection Tests (RFC 9204 Section 4.5.4)
 * ============================================================================
 */

/**
 * Test pattern detection for Literal Field Line with Name Reference
 */
static void
test_pattern_detection (void)
{
  printf ("  Pattern detection (01NTXXXX)... ");

  /* Valid patterns (01xx xxxx) */
  TEST_ASSERT (SocketQPACK_is_literal_name_ref (0x40) == 1,
               "0x40 should match pattern");
  TEST_ASSERT (SocketQPACK_is_literal_name_ref (0x50) == 1,
               "0x50 should match pattern");
  TEST_ASSERT (SocketQPACK_is_literal_name_ref (0x60) == 1,
               "0x60 should match pattern");
  TEST_ASSERT (SocketQPACK_is_literal_name_ref (0x7F) == 1,
               "0x7F should match pattern");

  /* Invalid patterns */
  TEST_ASSERT (SocketQPACK_is_literal_name_ref (0x00) == 0,
               "0x00 should not match pattern");
  TEST_ASSERT (SocketQPACK_is_literal_name_ref (0x80) == 0,
               "0x80 should not match pattern (indexed)");
  TEST_ASSERT (SocketQPACK_is_literal_name_ref (0xC0) == 0,
               "0xC0 should not match pattern");
  TEST_ASSERT (SocketQPACK_is_literal_name_ref (0x20) == 0,
               "0x20 should not match pattern");

  printf ("PASS\n");
}

/* ============================================================================
 * Literal Field Line with Name Reference Encoding Tests
 * ============================================================================
 */

/**
 * Test encoding with static table reference
 * Example: Static table entry 5 (cookie), never-indexed, value "session=abc"
 */
static void
test_encode_static_ref (void)
{
  unsigned char buf[64];
  ssize_t len;

  printf ("  Encode static table reference (cookie)... ");

  /* Static table index 5 (cookie), N=0, T=1 */
  len = SocketQPACK_encode_literal_name_ref (5,             /* name_index */
                                             1,             /* is_static */
                                             0,             /* never_indexed */
                                             "session=abc", /* value */
                                             11,            /* value_len */
                                             0,             /* use_huffman */
                                             buf,
                                             sizeof (buf));

  TEST_ASSERT (len > 0, "Encoding should succeed");

  /* First byte: 01 N T IIII = 01 0 1 0101 = 0x55 */
  TEST_ASSERT (buf[0] == 0x55, "First byte should be 0x55");

  /* Second byte: length 11 with H=0 */
  TEST_ASSERT (buf[1] == 11, "Second byte should be 11 (length)");

  /* Value bytes */
  TEST_ASSERT (memcmp (buf + 2, "session=abc", 11) == 0, "Value should match");
  TEST_ASSERT (len == 13, "Total length should be 13");

  printf ("PASS\n");
}

/**
 * Test encoding with never-indexed flag
 */
static void
test_encode_never_indexed (void)
{
  unsigned char buf[64];
  ssize_t len;

  printf ("  Encode with never-indexed flag... ");

  /* Static table index 5 (cookie), N=1, T=1 */
  len = SocketQPACK_encode_literal_name_ref (5,        /* name_index */
                                             1,        /* is_static */
                                             1,        /* never_indexed */
                                             "secret", /* value */
                                             6,        /* value_len */
                                             0,        /* use_huffman */
                                             buf,
                                             sizeof (buf));

  TEST_ASSERT (len > 0, "Encoding should succeed");

  /* First byte: 01 N T IIII = 01 1 1 0101 = 0x75 */
  TEST_ASSERT (buf[0] == 0x75, "First byte should be 0x75 (N=1)");

  printf ("PASS\n");
}

/**
 * Test encoding with dynamic table reference
 */
static void
test_encode_dynamic_ref (void)
{
  unsigned char buf[64];
  ssize_t len;

  printf ("  Encode dynamic table reference... ");

  /* Dynamic table index 3, N=0, T=0 */
  len = SocketQPACK_encode_literal_name_ref (3,       /* name_index */
                                             0,       /* is_static (dynamic) */
                                             0,       /* never_indexed */
                                             "value", /* value */
                                             5,       /* value_len */
                                             0,       /* use_huffman */
                                             buf,
                                             sizeof (buf));

  TEST_ASSERT (len > 0, "Encoding should succeed");

  /* First byte: 01 N T IIII = 01 0 0 0011 = 0x43 */
  TEST_ASSERT (buf[0] == 0x43, "First byte should be 0x43 (T=0)");

  printf ("PASS\n");
}

/**
 * Test encoding with large index requiring continuation
 */
static void
test_encode_large_index (void)
{
  unsigned char buf[64];
  ssize_t len;

  printf ("  Encode large index (continuation)... ");

  /* Static table index 20 > 15 (max 4-bit), N=0, T=1 */
  len = SocketQPACK_encode_literal_name_ref (
      20,  /* name_index - requires continuation */
      1,   /* is_static */
      0,   /* never_indexed */
      "v", /* value */
      1,   /* value_len */
      0,   /* use_huffman */
      buf,
      sizeof (buf));

  TEST_ASSERT (len > 0, "Encoding should succeed");

  /* First byte: 01 0 1 1111 = 0x5F (prefix maxed out) */
  TEST_ASSERT (buf[0] == 0x5F, "First byte should be 0x5F");
  /* Second byte: 20 - 15 = 5 */
  TEST_ASSERT (buf[1] == 5, "Second byte should be 5");

  printf ("PASS\n");
}

/* ============================================================================
 * Literal Field Line with Name Reference Decoding Tests
 * ============================================================================
 */

/**
 * Test decoding static table reference
 */
static void
test_decode_static_ref (void)
{
  Arena_T arena;
  SocketQPACK_LiteralFieldLine field;
  size_t consumed;
  SocketQPACK_Result result;

  /* 0x55 = 01 0 1 0101 = static index 5, N=0, T=1
   * 0x05 = length 5, H=0
   * "value" */
  unsigned char input[] = { 0x55, 0x05, 'v', 'a', 'l', 'u', 'e' };

  printf ("  Decode static table reference... ");

  arena = Arena_new ();

  result = SocketQPACK_decode_literal_name_ref (
      input, sizeof (input), &field, &consumed, arena);

  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (field.name_index == 5, "Name index should be 5");
  TEST_ASSERT (field.is_static == 1, "Should be static table");
  TEST_ASSERT (field.never_indexed == 0, "Should not be never-indexed");
  TEST_ASSERT (field.value_len == 5, "Value length should be 5");
  TEST_ASSERT (memcmp (field.value, "value", 5) == 0, "Value should match");
  TEST_ASSERT (consumed == 7, "Should consume 7 bytes");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test decoding with never-indexed flag
 */
static void
test_decode_never_indexed (void)
{
  Arena_T arena;
  SocketQPACK_LiteralFieldLine field;
  size_t consumed;
  SocketQPACK_Result result;

  /* 0x75 = 01 1 1 0101 = static index 5, N=1, T=1 */
  unsigned char input[] = { 0x75, 0x03, 's', 'e', 'c' };

  printf ("  Decode with never-indexed flag... ");

  arena = Arena_new ();

  result = SocketQPACK_decode_literal_name_ref (
      input, sizeof (input), &field, &consumed, arena);

  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (field.never_indexed == 1, "Should be never-indexed");
  TEST_ASSERT (field.is_static == 1, "Should be static table");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test decoding dynamic table reference
 */
static void
test_decode_dynamic_ref (void)
{
  Arena_T arena;
  SocketQPACK_LiteralFieldLine field;
  size_t consumed;
  SocketQPACK_Result result;

  /* 0x43 = 01 0 0 0011 = dynamic index 3, N=0, T=0 */
  unsigned char input[] = { 0x43, 0x02, 'o', 'k' };

  printf ("  Decode dynamic table reference... ");

  arena = Arena_new ();

  result = SocketQPACK_decode_literal_name_ref (
      input, sizeof (input), &field, &consumed, arena);

  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (field.name_index == 3, "Name index should be 3");
  TEST_ASSERT (field.is_static == 0, "Should be dynamic table");
  TEST_ASSERT (field.value_len == 2, "Value length should be 2");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test decoding with large index (continuation bytes)
 */
static void
test_decode_large_index (void)
{
  Arena_T arena;
  SocketQPACK_LiteralFieldLine field;
  size_t consumed;
  SocketQPACK_Result result;

  /* 0x5F 0x05 = static index 20 (15 + 5), N=0, T=1 */
  unsigned char input[] = { 0x5F, 0x05, 0x01, 'x' };

  printf ("  Decode large index (continuation)... ");

  arena = Arena_new ();

  result = SocketQPACK_decode_literal_name_ref (
      input, sizeof (input), &field, &consumed, arena);

  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (field.name_index == 20, "Name index should be 20");
  TEST_ASSERT (field.is_static == 1, "Should be static table");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test decoding with invalid pattern
 */
static void
test_decode_invalid_pattern (void)
{
  Arena_T arena;
  SocketQPACK_LiteralFieldLine field;
  size_t consumed;
  SocketQPACK_Result result;

  /* 0x80 = indexed header (not literal with name ref) */
  unsigned char input[] = { 0x80, 0x02 };

  printf ("  Decode invalid pattern... ");

  arena = Arena_new ();

  result = SocketQPACK_decode_literal_name_ref (
      input, sizeof (input), &field, &consumed, arena);

  TEST_ASSERT (result == QPACK_ERROR_INVALID_PATTERN,
               "Should return INVALID_PATTERN");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test decoding with incomplete data
 */
static void
test_decode_incomplete (void)
{
  Arena_T arena;
  SocketQPACK_LiteralFieldLine field;
  size_t consumed;
  SocketQPACK_Result result;

  /* Only first byte - value data missing */
  unsigned char input[] = { 0x55, 0x05 };

  printf ("  Decode incomplete data... ");

  arena = Arena_new ();

  result = SocketQPACK_decode_literal_name_ref (
      input, sizeof (input), &field, &consumed, arena);

  TEST_ASSERT (result == QPACK_INCOMPLETE, "Should return INCOMPLETE");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * Round-trip Tests
 * ============================================================================
 */

/**
 * Test encode then decode yields original values
 */
static void
test_roundtrip_basic (void)
{
  Arena_T arena;
  unsigned char buf[128];
  SocketQPACK_LiteralFieldLine field;
  size_t consumed;
  ssize_t encoded_len;
  SocketQPACK_Result result;

  printf ("  Round-trip encode/decode... ");

  arena = Arena_new ();

  /* Encode */
  encoded_len = SocketQPACK_encode_literal_name_ref (
      17,       /* :method index in static table */
      1,        /* is_static */
      0,        /* never_indexed */
      "DELETE", /* value */
      6,        /* value_len */
      0,        /* use_huffman */
      buf,
      sizeof (buf));

  TEST_ASSERT (encoded_len > 0, "Encoding should succeed");

  /* Decode */
  result = SocketQPACK_decode_literal_name_ref (
      buf, (size_t)encoded_len, &field, &consumed, arena);

  TEST_ASSERT (result == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (field.name_index == 17, "Name index should be preserved");
  TEST_ASSERT (field.is_static == 1, "Static flag should be preserved");
  TEST_ASSERT (field.never_indexed == 0, "Never-indexed should be preserved");
  TEST_ASSERT (field.value_len == 6, "Value length should be preserved");
  TEST_ASSERT (memcmp (field.value, "DELETE", 6) == 0,
               "Value should be preserved");
  TEST_ASSERT ((size_t)encoded_len == consumed, "Should consume all bytes");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test round-trip with never-indexed flag
 */
static void
test_roundtrip_never_indexed (void)
{
  Arena_T arena;
  unsigned char buf[128];
  SocketQPACK_LiteralFieldLine field;
  size_t consumed;
  ssize_t encoded_len;
  SocketQPACK_Result result;

  printf ("  Round-trip with never-indexed... ");

  arena = Arena_new ();

  /* Encode with N=1 */
  encoded_len
      = SocketQPACK_encode_literal_name_ref (84, /* authorization index */
                                             1,  /* is_static */
                                             1,  /* never_indexed = YES */
                                             "Bearer token123", /* value */
                                             15,                /* value_len */
                                             0, /* use_huffman */
                                             buf,
                                             sizeof (buf));

  TEST_ASSERT (encoded_len > 0, "Encoding should succeed");

  /* Decode */
  result = SocketQPACK_decode_literal_name_ref (
      buf, (size_t)encoded_len, &field, &consumed, arena);

  TEST_ASSERT (result == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (field.never_indexed == 1, "Never-indexed should be preserved");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * Dynamic Table Tests
 * ============================================================================
 */

/**
 * Test dynamic table basic operations
 */
static void
test_dynamic_table_basic (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Header header;
  SocketQPACK_Result result;

  printf ("  Dynamic table basic operations... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (4096, arena);

  TEST_ASSERT (table != NULL, "Table creation should succeed");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 0,
               "Initial count should be 0");
  TEST_ASSERT (SocketQPACK_Table_size (table) == 0, "Initial size should be 0");

  /* Add entry */
  result
      = SocketQPACK_Table_add (table, "custom-header", 13, "custom-value", 12);
  TEST_ASSERT (result == QPACK_OK, "Add should succeed");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 1, "Count should be 1");

  /* Get entry (index 0 is oldest = first added) */
  result = SocketQPACK_Table_get (table, 0, &header);
  TEST_ASSERT (result == QPACK_OK, "Get should succeed");
  TEST_ASSERT (strcmp (header.name, "custom-header") == 0, "Name should match");
  TEST_ASSERT (strcmp (header.value, "custom-value") == 0,
               "Value should match");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test dynamic table eviction
 */
static void
test_dynamic_table_eviction (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Result result;

  printf ("  Dynamic table eviction... ");

  arena = Arena_new ();
  /* Small table - will trigger eviction quickly */
  table = SocketQPACK_Table_new (100, arena);

  /* Add entries until eviction occurs
   * Entry size = name_len + value_len + 32 (overhead)
   * "header" (6) + "value" (5) + 32 = 43 bytes per entry */
  result = SocketQPACK_Table_add (table, "header", 6, "value", 5);
  TEST_ASSERT (result == QPACK_OK, "First add should succeed");

  result = SocketQPACK_Table_add (table, "header", 6, "value", 5);
  TEST_ASSERT (result == QPACK_OK, "Second add should succeed");

  /* Third should trigger eviction of first */
  result = SocketQPACK_Table_add (table, "header", 6, "value", 5);
  TEST_ASSERT (result == QPACK_OK, "Third add should succeed");

  /* Count should be 2 (one evicted) */
  TEST_ASSERT (SocketQPACK_Table_count (table) <= 2,
               "Should have evicted entries");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test dynamic table find
 */
static void
test_dynamic_table_find (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  int idx;

  printf ("  Dynamic table find... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (4096, arena);

  /* Add some entries */
  SocketQPACK_Table_add (table, "x-custom-a", 10, "value-a", 7);
  SocketQPACK_Table_add (table, "x-custom-b", 10, "value-b", 7);
  SocketQPACK_Table_add (table, "x-custom-a", 10, "value-a2", 8);

  /* Find exact match */
  idx = SocketQPACK_Table_find (table, "x-custom-b", 10, "value-b", 7);
  TEST_ASSERT (idx > 0, "Should find exact match");

  /* Find name-only match */
  idx = SocketQPACK_Table_find (table, "x-custom-a", 10, "other", 5);
  TEST_ASSERT (idx < 0, "Should find name-only match (negative)");

  /* Not found */
  idx = SocketQPACK_Table_find (table, "x-unknown", 9, NULL, 0);
  TEST_ASSERT (idx == 0, "Should not find unknown header");

  SocketQPACK_Table_free (&table);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Name Validation Tests
 * ============================================================================
 */

/**
 * Test name index validation
 */
static void
test_name_index_validation (void)
{
  SocketQPACK_Result result;

  printf ("  Name index validation... ");

  /* Valid static indices (0-98) */
  result = SocketQPACK_validate_name_index (0, 1, 0);
  TEST_ASSERT (result == QPACK_OK, "Index 0 should be valid for static");

  result = SocketQPACK_validate_name_index (98, 1, 0);
  TEST_ASSERT (result == QPACK_OK, "Index 98 should be valid for static");

  /* Invalid static index */
  result = SocketQPACK_validate_name_index (99, 1, 0);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_INDEX,
               "Index 99 should be invalid for static");

  /* Valid dynamic index (depends on count) */
  result = SocketQPACK_validate_name_index (0, 0, 5);
  TEST_ASSERT (result == QPACK_OK, "Index 0 should be valid with 5 entries");

  /* Invalid dynamic index */
  result = SocketQPACK_validate_name_index (5, 0, 5);
  TEST_ASSERT (result == QPACK_ERROR_INVALID_INDEX,
               "Index 5 should be invalid with only 5 entries");

  printf ("PASS\n");
}

/* ============================================================================
 * Huffman Tests
 * ============================================================================
 */

/**
 * Test Huffman encode/decode round-trip
 */
static void
test_huffman_roundtrip (void)
{
  unsigned char encoded[128];
  unsigned char decoded[128];
  const char *test_str = "www.example.com";
  ssize_t enc_len, dec_len;

  printf ("  Huffman encode/decode round-trip... ");

  enc_len = SocketQPACK_huffman_encode ((const unsigned char *)test_str,
                                        strlen (test_str),
                                        encoded,
                                        sizeof (encoded));
  TEST_ASSERT (enc_len > 0, "Encoding should succeed");
  TEST_ASSERT ((size_t)enc_len < strlen (test_str), "Huffman should compress");

  dec_len = SocketQPACK_huffman_decode (
      encoded, (size_t)enc_len, decoded, sizeof (decoded));
  TEST_ASSERT (dec_len > 0, "Decoding should succeed");
  TEST_ASSERT ((size_t)dec_len == strlen (test_str),
               "Decoded length should match");
  TEST_ASSERT (memcmp (decoded, test_str, strlen (test_str)) == 0,
               "Decoded content should match");

  printf ("PASS\n");
}

/**
 * Test Huffman with literal in encoding
 */
static void
test_encode_with_huffman (void)
{
  Arena_T arena;
  unsigned char buf[128];
  SocketQPACK_LiteralFieldLine field;
  size_t consumed;
  ssize_t encoded_len;
  SocketQPACK_Result result;

  printf ("  Encode with Huffman value... ");

  arena = Arena_new ();

  /* Encode with Huffman */
  encoded_len = SocketQPACK_encode_literal_name_ref (1, /* :path index */
                                                     1, /* is_static */
                                                     0, /* never_indexed */
                                                     "/sample/path", /* value */
                                                     12, /* value_len */
                                                     1,  /* use_huffman = YES */
                                                     buf,
                                                     sizeof (buf));

  TEST_ASSERT (encoded_len > 0, "Encoding should succeed");

  /* Decode */
  result = SocketQPACK_decode_literal_name_ref (
      buf, (size_t)encoded_len, &field, &consumed, arena);

  TEST_ASSERT (result == QPACK_OK, "Decoding should succeed");
  TEST_ASSERT (field.value_len == 12, "Value length should be preserved");
  TEST_ASSERT (memcmp (field.value, "/sample/path", 12) == 0,
               "Value should be preserved");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * Result String Tests
 * ============================================================================
 */

/**
 * Test result string conversion
 */
static void
test_result_strings (void)
{
  printf ("  Result strings... ");

  TEST_ASSERT (strcmp (SocketQPACK_result_string (QPACK_OK), "OK") == 0,
               "OK string should match");
  TEST_ASSERT (strcmp (SocketQPACK_result_string (QPACK_INCOMPLETE),
                       "Incomplete - need more data")
                   == 0,
               "INCOMPLETE string should match");
  TEST_ASSERT (strcmp (SocketQPACK_result_string (QPACK_ERROR_INVALID_INDEX),
                       "Invalid table index")
                   == 0,
               "INVALID_INDEX string should match");

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
  test_int_encode_4bit_small ();
  test_int_encode_4bit_large ();
  test_int_decode_4bit_small ();
  test_int_decode_4bit_large ();
  test_int_decode_incomplete ();
}

static void
run_static_table_tests (void)
{
  printf ("Static Table Tests:\n");
  test_static_table_entry_0 ();
  test_static_table_entry_17 ();
  test_static_table_entry_25 ();
  test_static_table_invalid ();
  test_static_table_find ();
}

static void
run_pattern_tests (void)
{
  printf ("Pattern Detection Tests:\n");
  test_pattern_detection ();
}

static void
run_encoding_tests (void)
{
  printf ("Literal Field Line Encoding Tests:\n");
  test_encode_static_ref ();
  test_encode_never_indexed ();
  test_encode_dynamic_ref ();
  test_encode_large_index ();
}

static void
run_decoding_tests (void)
{
  printf ("Literal Field Line Decoding Tests:\n");
  test_decode_static_ref ();
  test_decode_never_indexed ();
  test_decode_dynamic_ref ();
  test_decode_large_index ();
  test_decode_invalid_pattern ();
  test_decode_incomplete ();
}

static void
run_roundtrip_tests (void)
{
  printf ("Round-trip Tests:\n");
  test_roundtrip_basic ();
  test_roundtrip_never_indexed ();
}

static void
run_dynamic_table_tests (void)
{
  printf ("Dynamic Table Tests:\n");
  test_dynamic_table_basic ();
  test_dynamic_table_eviction ();
  test_dynamic_table_find ();
}

static void
run_validation_tests (void)
{
  printf ("Validation Tests:\n");
  test_name_index_validation ();
}

static void
run_huffman_tests (void)
{
  printf ("Huffman Tests:\n");
  test_huffman_roundtrip ();
  test_encode_with_huffman ();
}

static void
run_utility_tests (void)
{
  printf ("Utility Tests:\n");
  test_result_strings ();
}

int
main (void)
{
  printf ("=== QPACK Tests (RFC 9204) ===\n\n");

  run_integer_tests ();
  printf ("\n");

  run_static_table_tests ();
  printf ("\n");

  run_pattern_tests ();
  printf ("\n");

  run_encoding_tests ();
  printf ("\n");

  run_decoding_tests ();
  printf ("\n");

  run_roundtrip_tests ();
  printf ("\n");

  run_dynamic_table_tests ();
  printf ("\n");

  run_validation_tests ();
  printf ("\n");

  run_huffman_tests ();
  printf ("\n");

  run_utility_tests ();
  printf ("\n");

  printf ("=== All QPACK tests passed! ===\n");
  return 0;
}
