/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_qpack.c - Unit tests for QPACK Header Compression (RFC 9204)
 *
 * Tests QPACK implementation including:
 * - Integer encoding/decoding (RFC 7541 Section 5.1)
 * - Dynamic table operations
 * - Stream Cancellation instruction (Section 4.4.2)
 * - Per-stream reference tracking
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
 * Integer Encoding Tests (RFC 7541 Section 5.1)
 * ============================================================================
 */

/**
 * Test integer encoding with 6-bit prefix (used by Stream Cancellation)
 */
static void
test_int_encode_6bit_small (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 4 with 6-bit prefix... ");

  len = SocketQPACK_int_encode (4, 6, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Expected 1 byte");
  TEST_ASSERT (buf[0] == 0x04, "Expected 0x04 (4)");

  printf ("PASS\n");
}

/**
 * Test integer encoding at prefix boundary
 */
static void
test_int_encode_6bit_boundary (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 63 with 6-bit prefix (boundary)... ");

  /* 63 = 2^6 - 1, fits exactly in prefix */
  len = SocketQPACK_int_encode (62, 6, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Expected 1 byte for value < max prefix");
  TEST_ASSERT (buf[0] == 62, "Expected 62");

  /* 63 requires continuation */
  len = SocketQPACK_int_encode (63, 6, buf, sizeof (buf));
  TEST_ASSERT (len == 2, "Expected 2 bytes for max prefix value");
  TEST_ASSERT (buf[0] == 0x3F, "First byte should be 63 (2^6 - 1)");
  TEST_ASSERT (buf[1] == 0x00, "Second byte should be 0");

  printf ("PASS\n");
}

/**
 * Test integer encoding requiring multi-byte
 */
static void
test_int_encode_6bit_large (void)
{
  unsigned char buf[16];
  size_t len;

  printf ("  Integer encode 1000 with 6-bit prefix... ");

  /* 1000 = 63 + 937 = 63 + (937 & 0x7F) | 0x80, (937 >> 7) */
  /* 937 = 0x3A9 = 0b1110101001 */
  /* 937 & 0x7F = 0x29 = 41, 937 >> 7 = 7 */
  /* So: 63, 41|0x80, 7 = 0x3F, 0xA9, 0x07 */
  len = SocketQPACK_int_encode (1000, 6, buf, sizeof (buf));
  TEST_ASSERT (len == 3, "Expected 3 bytes");
  TEST_ASSERT (buf[0] == 0x3F, "First byte should be 63");

  printf ("PASS\n");
}

/**
 * Test integer decoding - small value
 */
static void
test_int_decode_6bit_small (void)
{
  /* Stream ID 4 encoded: 01000100 = 0x44 */
  unsigned char data[] = { 0x44 };
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Integer decode 4 from 0x44... ");

  result = SocketQPACK_int_decode (data, sizeof (data), 6, &value, &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (value == 4, "Value should be 4");
  TEST_ASSERT (consumed == 1, "Should consume 1 byte");

  printf ("PASS\n");
}

/**
 * Test integer decoding - multi-byte
 */
static void
test_int_decode_6bit_large (void)
{
  /* Stream ID > 63 requires continuation bytes */
  /* Encode 127 with 6-bit prefix: 63 + 64 = 63, then 64 */
  /* 64 = 0x40, no continuation needed */
  unsigned char data[] = { 0x3F, 0x40 };
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Integer decode 127 (multi-byte)... ");

  result = SocketQPACK_int_decode (data, sizeof (data), 6, &value, &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (value == 127, "Value should be 127 (63 + 64)");
  TEST_ASSERT (consumed == 2, "Should consume 2 bytes");

  printf ("PASS\n");
}

/**
 * Test integer decode with incomplete data
 */
static void
test_int_decode_incomplete (void)
{
  /* Continuation byte expected but not present */
  unsigned char data[] = { 0x3F };
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Integer decode incomplete data... ");

  result = SocketQPACK_int_decode (data, sizeof (data), 6, &value, &consumed);
  TEST_ASSERT (result == QPACK_INCOMPLETE, "Should return incomplete");

  printf ("PASS\n");
}

/* ============================================================================
 * Dynamic Table Tests
 * ============================================================================
 */

/**
 * Test dynamic table creation
 */
static void
test_table_create (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;

  printf ("  Dynamic table creation... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (4096, arena);

  TEST_ASSERT (table != NULL, "Table should be created");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 0, "Table should be empty");
  TEST_ASSERT (SocketQPACK_Table_size (table) == 0, "Table size should be 0");
  TEST_ASSERT (SocketQPACK_Table_max_size (table) == 4096,
               "Max size should be 4096");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test dynamic table add and get
 */
static void
test_table_add_get (void)
{
  Arena_T arena;
  SocketQPACK_Table_T table;
  SocketQPACK_Header header;
  SocketQPACK_Result result;

  printf ("  Dynamic table add and get... ");

  arena = Arena_new ();
  table = SocketQPACK_Table_new (4096, arena);

  /* Add an entry */
  result = SocketQPACK_Table_add (table, "content-type", 12, "text/html", 9);
  TEST_ASSERT (result == QPACK_OK, "Add should succeed");
  TEST_ASSERT (SocketQPACK_Table_count (table) == 1, "Count should be 1");

  /* Get the entry (index 1 = most recent) */
  result = SocketQPACK_Table_get (table, 1, &header);
  TEST_ASSERT (result == QPACK_OK, "Get should succeed");
  TEST_ASSERT (header.name_len == 12, "Name length should be 12");
  TEST_ASSERT (strncmp (header.name, "content-type", 12) == 0,
               "Name should match");
  TEST_ASSERT (header.value_len == 9, "Value length should be 9");
  TEST_ASSERT (strncmp (header.value, "text/html", 9) == 0,
               "Value should match");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Stream Cancellation Tests (RFC 9204 Section 4.4.2)
 * ============================================================================
 */

/**
 * Test Stream Cancellation instruction detection
 */
static void
test_stream_cancel_detect (void)
{
  printf ("  Stream Cancellation instruction detection... ");

  /* Stream Cancellation: 01xxxxxx */
  TEST_ASSERT (SocketQPACK_is_stream_cancel_instruction (0x40) == 1,
               "0x40 should be stream cancel");
  TEST_ASSERT (SocketQPACK_is_stream_cancel_instruction (0x44) == 1,
               "0x44 should be stream cancel");
  TEST_ASSERT (SocketQPACK_is_stream_cancel_instruction (0x7F) == 1,
               "0x7F should be stream cancel");

  /* Section Acknowledgement: 1xxxxxxx */
  TEST_ASSERT (SocketQPACK_is_stream_cancel_instruction (0x80) == 0,
               "0x80 should NOT be stream cancel");
  TEST_ASSERT (SocketQPACK_is_stream_cancel_instruction (0xFF) == 0,
               "0xFF should NOT be stream cancel");

  /* Insert Count Increment: 00xxxxxx */
  TEST_ASSERT (SocketQPACK_is_stream_cancel_instruction (0x00) == 0,
               "0x00 should NOT be stream cancel");
  TEST_ASSERT (SocketQPACK_is_stream_cancel_instruction (0x3F) == 0,
               "0x3F should NOT be stream cancel");

  printf ("PASS\n");
}

/**
 * Test decoding single-octet stream cancellation (ID < 64)
 */
static void
test_stream_cancel_single_octet (void)
{
  Arena_T arena;
  SocketQPACK_Decoder_T decoder;
  unsigned char data[] = { 0x44 }; /* 01000100 = stream ID 4 */
  size_t consumed;
  uint64_t stream_id;
  SocketQPACK_Result result;

  printf ("  Decode single-octet stream cancellation (ID=4)... ");

  arena = Arena_new ();
  decoder = SocketQPACK_Decoder_new (NULL, arena);
  TEST_ASSERT (decoder != NULL, "Decoder should be created");

  result = SocketQPACK_decode_stream_cancel (
      decoder, data, sizeof (data), &consumed, &stream_id);
  TEST_ASSERT (result == QPACK_OK, "Decode should succeed");
  TEST_ASSERT (consumed == 1, "Should consume 1 byte");
  TEST_ASSERT (stream_id == 4, "Stream ID should be 4");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test decoding multi-octet stream cancellation (ID >= 64)
 */
static void
test_stream_cancel_multi_octet (void)
{
  Arena_T arena;
  SocketQPACK_Decoder_T decoder;
  /* 01111111 00000000 = stream ID 63 (boundary case) */
  unsigned char data1[] = { 0x7F, 0x00 };
  /* 01111111 01000000 = stream ID 127 (63 + 64) */
  unsigned char data2[] = { 0x7F, 0x40 };
  size_t consumed;
  uint64_t stream_id;
  SocketQPACK_Result result;

  printf ("  Decode multi-octet stream cancellation... ");

  arena = Arena_new ();
  decoder = SocketQPACK_Decoder_new (NULL, arena);
  TEST_ASSERT (decoder != NULL, "Decoder should be created");

  /* Test stream ID 63 */
  result = SocketQPACK_decode_stream_cancel (
      decoder, data1, sizeof (data1), &consumed, &stream_id);
  TEST_ASSERT (result == QPACK_OK, "Decode should succeed for ID 63");
  TEST_ASSERT (consumed == 2, "Should consume 2 bytes");
  TEST_ASSERT (stream_id == 63, "Stream ID should be 63");

  /* Test stream ID 127 */
  result = SocketQPACK_decode_stream_cancel (
      decoder, data2, sizeof (data2), &consumed, &stream_id);
  TEST_ASSERT (result == QPACK_OK, "Decode should succeed for ID 127");
  TEST_ASSERT (consumed == 2, "Should consume 2 bytes");
  TEST_ASSERT (stream_id == 127, "Stream ID should be 127");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test stream ID validation (reject ID 0)
 */
static void
test_stream_cancel_invalid_id (void)
{
  Arena_T arena;
  SocketQPACK_Decoder_T decoder;
  unsigned char data[] = { 0x40 }; /* 01000000 = stream ID 0 */
  size_t consumed;
  uint64_t stream_id;
  SocketQPACK_Result result;

  printf ("  Reject stream cancellation with ID 0... ");

  arena = Arena_new ();
  decoder = SocketQPACK_Decoder_new (NULL, arena);
  TEST_ASSERT (decoder != NULL, "Decoder should be created");

  result = SocketQPACK_decode_stream_cancel (
      decoder, data, sizeof (data), &consumed, &stream_id);
  TEST_ASSERT (result == QPACK_ERROR_STREAM_ID, "Should reject stream ID 0");

  /* Also test the validation function directly */
  TEST_ASSERT (SocketQPACK_stream_cancel_validate_id (0)
                   == QPACK_ERROR_STREAM_ID,
               "validate_id should reject 0");
  TEST_ASSERT (SocketQPACK_stream_cancel_validate_id (1) == QPACK_OK,
               "validate_id should accept 1");
  TEST_ASSERT (SocketQPACK_stream_cancel_validate_id (100) == QPACK_OK,
               "validate_id should accept 100");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test pattern discrimination (not a stream cancellation)
 */
static void
test_stream_cancel_wrong_pattern (void)
{
  Arena_T arena;
  SocketQPACK_Decoder_T decoder;
  /* 00111111 = Insert Count Increment pattern, not Stream Cancel */
  unsigned char data[] = { 0x3F };
  size_t consumed;
  uint64_t stream_id;
  SocketQPACK_Result result;

  printf ("  Reject wrong instruction pattern... ");

  arena = Arena_new ();
  decoder = SocketQPACK_Decoder_new (NULL, arena);
  TEST_ASSERT (decoder != NULL, "Decoder should be created");

  result = SocketQPACK_decode_stream_cancel (
      decoder, data, sizeof (data), &consumed, &stream_id);
  TEST_ASSERT (result == QPACK_ERROR_DECODER_STREAM,
               "Should reject wrong pattern");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test releasing references for stream with no references
 */
static void
test_stream_cancel_no_refs (void)
{
  Arena_T arena;
  SocketQPACK_Decoder_T decoder;
  SocketQPACK_Result result;

  printf ("  Handle cancellation for stream with no refs... ");

  arena = Arena_new ();
  decoder = SocketQPACK_Decoder_new (NULL, arena);
  TEST_ASSERT (decoder != NULL, "Decoder should be created");

  /* Release refs for stream that never had any - should succeed gracefully */
  result = SocketQPACK_stream_cancel_release_refs (decoder, 999);
  TEST_ASSERT (result == QPACK_OK, "Should succeed even if stream has no refs");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test adding and releasing stream references
 */
static void
test_stream_refs_add_release (void)
{
  Arena_T arena;
  SocketQPACK_Decoder_T decoder;
  SocketQPACK_Table_T table;
  SocketQPACK_Header header;
  SocketQPACK_Result result;

  printf ("  Add and release stream references... ");

  arena = Arena_new ();
  decoder = SocketQPACK_Decoder_new (NULL, arena);
  TEST_ASSERT (decoder != NULL, "Decoder should be created");

  table = SocketQPACK_Decoder_get_table (decoder);
  TEST_ASSERT (table != NULL, "Table should exist");

  /* Add some entries to the dynamic table */
  result = SocketQPACK_Table_add (table, "content-type", 12, "text/html", 9);
  TEST_ASSERT (result == QPACK_OK, "Add entry 1 should succeed");

  result = SocketQPACK_Table_add (table, "content-length", 14, "1234", 4);
  TEST_ASSERT (result == QPACK_OK, "Add entry 2 should succeed");

  result = SocketQPACK_Table_add (table, "cache-control", 13, "no-cache", 8);
  TEST_ASSERT (result == QPACK_OK, "Add entry 3 should succeed");

  /* Add references from stream 1 to entries 1 and 3 */
  result = SocketQPACK_add_stream_reference (decoder, 1, 1);
  TEST_ASSERT (result == QPACK_OK, "Add ref to entry 1 should succeed");

  result = SocketQPACK_add_stream_reference (decoder, 1, 3);
  TEST_ASSERT (result == QPACK_OK, "Add ref to entry 3 should succeed");

  /* Add reference from stream 2 to entry 2 */
  result = SocketQPACK_add_stream_reference (decoder, 2, 2);
  TEST_ASSERT (result == QPACK_OK, "Add ref from stream 2 should succeed");

  /* Release stream 1's references */
  result = SocketQPACK_stream_cancel_release_refs (decoder, 1);
  TEST_ASSERT (result == QPACK_OK, "Release refs should succeed");

  /* Entries should still be accessible */
  result = SocketQPACK_Table_get (table, 1, &header);
  TEST_ASSERT (result == QPACK_OK, "Entry 1 should still exist");

  /* Release stream 1 again - should succeed (no-op) */
  result = SocketQPACK_stream_cancel_release_refs (decoder, 1);
  TEST_ASSERT (result == QPACK_OK, "Re-release should succeed");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test incomplete Stream Cancellation instruction
 */
static void
test_stream_cancel_incomplete (void)
{
  Arena_T arena;
  SocketQPACK_Decoder_T decoder;
  /* 0x7F starts multi-byte encoding but no continuation */
  unsigned char data[] = { 0x7F };
  size_t consumed;
  uint64_t stream_id;
  SocketQPACK_Result result;

  printf ("  Handle incomplete stream cancellation... ");

  arena = Arena_new ();
  decoder = SocketQPACK_Decoder_new (NULL, arena);
  TEST_ASSERT (decoder != NULL, "Decoder should be created");

  result = SocketQPACK_decode_stream_cancel (
      decoder, data, sizeof (data), &consumed, &stream_id);
  TEST_ASSERT (result == QPACK_INCOMPLETE,
               "Should return incomplete for missing continuation");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Integration Tests
 * ============================================================================
 */

/**
 * Test full Stream Cancellation flow with dynamic table
 */
static void
test_stream_cancel_integration (void)
{
  Arena_T arena;
  SocketQPACK_Decoder_T decoder;
  SocketQPACK_Table_T table;
  SocketQPACK_Result result;
  /* Stream ID 5 encoded: 01000101 = 0x45 */
  unsigned char data[] = { 0x45 };
  size_t consumed;
  uint64_t stream_id;

  printf ("  Integration: full stream cancellation flow... ");

  arena = Arena_new ();
  decoder = SocketQPACK_Decoder_new (NULL, arena);
  table = SocketQPACK_Decoder_get_table (decoder);

  /* Setup: Add entries and references */
  SocketQPACK_Table_add (table, "x-custom-header", 15, "value1", 6);
  SocketQPACK_Table_add (table, "x-another", 9, "value2", 6);

  /* Stream 5 references entry 1 */
  SocketQPACK_add_stream_reference (decoder, 5, 1);

  /* Process stream cancellation instruction */
  result = SocketQPACK_decode_stream_cancel (
      decoder, data, sizeof (data), &consumed, &stream_id);
  TEST_ASSERT (result == QPACK_OK, "Decode should succeed");
  TEST_ASSERT (stream_id == 5, "Stream ID should be 5");

  /* Verify table is still intact */
  TEST_ASSERT (SocketQPACK_Table_count (table) == 2,
               "Table should still have 2 entries");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================
 */

int
main (void)
{
  printf ("QPACK Header Compression Tests (RFC 9204)\n");
  printf ("==========================================\n\n");

  printf ("Integer Encoding Tests:\n");
  test_int_encode_6bit_small ();
  test_int_encode_6bit_boundary ();
  test_int_encode_6bit_large ();
  test_int_decode_6bit_small ();
  test_int_decode_6bit_large ();
  test_int_decode_incomplete ();

  printf ("\nDynamic Table Tests:\n");
  test_table_create ();
  test_table_add_get ();

  printf ("\nStream Cancellation Tests (RFC 9204 Section 4.4.2):\n");
  test_stream_cancel_detect ();
  test_stream_cancel_single_octet ();
  test_stream_cancel_multi_octet ();
  test_stream_cancel_invalid_id ();
  test_stream_cancel_wrong_pattern ();
  test_stream_cancel_no_refs ();
  test_stream_refs_add_release ();
  test_stream_cancel_incomplete ();

  printf ("\nIntegration Tests:\n");
  test_stream_cancel_integration ();

  printf ("\n==========================================\n");
  printf ("All QPACK tests passed!\n");

  return 0;
}
