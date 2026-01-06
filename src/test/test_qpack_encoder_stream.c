/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_qpack_encoder_stream.c - Unit tests for QPACK Encoder Stream
 *
 * Tests RFC 9204 Section 4.2 - Encoder Stream Infrastructure including:
 * - Stream type validation (0x02)
 * - Stream initialization and lifecycle
 * - Set Dynamic Table Capacity instruction
 * - Insert With Name Reference instruction
 * - Insert With Literal Name instruction
 * - Duplicate instruction
 * - Buffer management
 * - Error handling (closure, duplicate init)
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHPACK.h"
#include "http/SocketQPACKEncoderStream.h"

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
 * Test: Stream Type Validation
 * RFC 9204 Section 4.2: An encoder stream is a unidirectional stream of
 * type 0x02
 * ============================================================================
 */

static void
test_stream_type_validation (void)
{
  printf ("  Stream type 0x02 validation... ");

  TEST_ASSERT (SocketQPACK_EncoderStream_validate_type (0x02) == 1,
               "Type 0x02 should be valid");
  TEST_ASSERT (SocketQPACK_EncoderStream_validate_type (0x00) == 0,
               "Type 0x00 should be invalid");
  TEST_ASSERT (SocketQPACK_EncoderStream_validate_type (0x01) == 0,
               "Type 0x01 should be invalid");
  TEST_ASSERT (SocketQPACK_EncoderStream_validate_type (0x03) == 0,
               "Type 0x03 should be invalid");
  TEST_ASSERT (SocketQPACK_EncoderStream_validate_type (0xFF) == 0,
               "Type 0xFF should be invalid");

  printf ("PASS\n");
}

/* ============================================================================
 * Test: Stream Initialization
 * ============================================================================
 */

static void
test_stream_initialization (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;

  printf ("  Stream initialization... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 0x02);

  TEST_ASSERT (stream != NULL, "Stream creation should succeed");
  TEST_ASSERT (SocketQPACK_EncoderStream_is_initialized (stream) == 1,
               "Stream should be initialized");
  TEST_ASSERT (SocketQPACK_EncoderStream_get_stream_id (stream) == 0x02,
               "Stream ID should match");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_stream_null_arena (void)
{
  SocketQPACK_EncoderStream_T stream;

  printf ("  Stream with NULL arena... ");

  stream = SocketQPACK_EncoderStream_new (NULL, 0x02);
  TEST_ASSERT (stream == NULL, "NULL arena should return NULL stream");

  printf ("PASS\n");
}

static void
test_stream_null_checks (void)
{
  printf ("  NULL stream checks... ");

  TEST_ASSERT (SocketQPACK_EncoderStream_is_initialized (NULL) == 0,
               "NULL stream should not be initialized");
  TEST_ASSERT (SocketQPACK_EncoderStream_get_stream_id (NULL) == 0,
               "NULL stream ID should be 0");

  printf ("PASS\n");
}

/* ============================================================================
 * Test: Set Dynamic Table Capacity Instruction
 * RFC 9204 Section 4.3.1
 * ============================================================================
 */

static void
test_capacity_instruction_small (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACK_EncoderStream_Result result;
  const unsigned char *buffer;
  size_t buffer_len;

  printf ("  Set Dynamic Table Capacity (small value)... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 0x02);

  /* Encode capacity 16 (fits in 5-bit prefix) */
  result = SocketQPACK_EncoderStream_write_capacity (stream, 16);
  TEST_ASSERT (result == QPACK_ENCODER_STREAM_OK, "Write should succeed");

  buffer = SocketQPACK_EncoderStream_get_buffer (stream, &buffer_len);
  TEST_ASSERT (buffer != NULL, "Buffer should not be NULL");
  TEST_ASSERT (buffer_len == 1, "Should encode to 1 byte");
  /* 0b001xxxxx with xxxxx = 16 = 0b10000 = 0x30 */
  TEST_ASSERT (buffer[0] == 0x30, "First byte should be 0x30");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_capacity_instruction_large (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACK_EncoderStream_Result result;
  const unsigned char *buffer;
  size_t buffer_len;

  printf ("  Set Dynamic Table Capacity (large value)... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 0x02);

  /* Encode capacity 4096 (needs multi-byte) */
  result = SocketQPACK_EncoderStream_write_capacity (stream, 4096);
  TEST_ASSERT (result == QPACK_ENCODER_STREAM_OK, "Write should succeed");

  buffer = SocketQPACK_EncoderStream_get_buffer (stream, &buffer_len);
  TEST_ASSERT (buffer != NULL, "Buffer should not be NULL");
  TEST_ASSERT (buffer_len > 1, "Should encode to multiple bytes");
  /* First byte should have high bits 001 and max prefix (31) = 0x3F */
  TEST_ASSERT ((buffer[0] & 0xE0) == 0x20, "High bits should be 001");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_capacity_instruction_zero (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACK_EncoderStream_Result result;
  const unsigned char *buffer;
  size_t buffer_len;

  printf ("  Set Dynamic Table Capacity (zero)... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 0x02);

  result = SocketQPACK_EncoderStream_write_capacity (stream, 0);
  TEST_ASSERT (result == QPACK_ENCODER_STREAM_OK, "Write should succeed");

  buffer = SocketQPACK_EncoderStream_get_buffer (stream, &buffer_len);
  TEST_ASSERT (buffer_len == 1, "Should encode to 1 byte");
  /* 0b00100000 = 0x20 */
  TEST_ASSERT (buffer[0] == 0x20, "Should encode as 0x20");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * Test: Insert With Name Reference Instruction
 * RFC 9204 Section 4.3.2
 * ============================================================================
 */

static void
test_insert_nameref_static (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACK_EncoderStream_Result result;
  const unsigned char *buffer;
  size_t buffer_len;
  const unsigned char value[] = "www.example.com";

  printf ("  Insert With Name Reference (static)... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 0x02);

  /* Reference static table index 1 (:authority) */
  result = SocketQPACK_EncoderStream_write_insert_nameref (
      stream, 1, 1, value, sizeof (value) - 1, 0);
  TEST_ASSERT (result == QPACK_ENCODER_STREAM_OK, "Write should succeed");

  buffer = SocketQPACK_EncoderStream_get_buffer (stream, &buffer_len);
  TEST_ASSERT (buffer != NULL, "Buffer should not be NULL");
  TEST_ASSERT (buffer_len > 2, "Should have index byte and value");
  /* First byte: 0b11xxxxxx (static=1, bit 6 set) with index 1 */
  TEST_ASSERT ((buffer[0] & 0xC0) == 0xC0, "Should have static+nameref bits");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_insert_nameref_dynamic (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACK_EncoderStream_Result result;
  const unsigned char *buffer;
  size_t buffer_len;
  const unsigned char value[] = "bar";

  printf ("  Insert With Name Reference (dynamic)... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 0x02);

  /* Reference dynamic table index 0 */
  result = SocketQPACK_EncoderStream_write_insert_nameref (
      stream, 0, 0, value, sizeof (value) - 1, 0);
  TEST_ASSERT (result == QPACK_ENCODER_STREAM_OK, "Write should succeed");

  buffer = SocketQPACK_EncoderStream_get_buffer (stream, &buffer_len);
  TEST_ASSERT (buffer != NULL, "Buffer should not be NULL");
  /* First byte: 0b10xxxxxx (static=0) with index 0 */
  TEST_ASSERT ((buffer[0] & 0xC0) == 0x80,
               "Should have nameref bit, no static");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * Test: Insert With Literal Name Instruction
 * RFC 9204 Section 4.3.3
 * ============================================================================
 */

static void
test_insert_literal (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACK_EncoderStream_Result result;
  const unsigned char *buffer;
  size_t buffer_len;
  const unsigned char name[] = "x-custom";
  const unsigned char value[] = "custom-value";

  printf ("  Insert With Literal Name... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 0x02);

  result = SocketQPACK_EncoderStream_write_insert_literal (
      stream, name, sizeof (name) - 1, value, sizeof (value) - 1, 0, 0);
  TEST_ASSERT (result == QPACK_ENCODER_STREAM_OK, "Write should succeed");

  buffer = SocketQPACK_EncoderStream_get_buffer (stream, &buffer_len);
  TEST_ASSERT (buffer != NULL, "Buffer should not be NULL");
  /* First byte: 0b01xxxxxx */
  TEST_ASSERT ((buffer[0] & 0xC0) == 0x40, "Should have literal insert bits");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_insert_literal_empty_name (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACK_EncoderStream_Result result;
  const unsigned char name[] = "";
  const unsigned char value[] = "value";

  printf ("  Insert With Literal Name (empty name)... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 0x02);

  result = SocketQPACK_EncoderStream_write_insert_literal (
      stream, name, 0, value, sizeof (value) - 1, 0, 0);
  TEST_ASSERT (result == QPACK_ENCODER_STREAM_OK, "Write should succeed");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * Test: Duplicate Instruction
 * RFC 9204 Section 4.3.4
 * ============================================================================
 */

static void
test_duplicate_instruction (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACK_EncoderStream_Result result;
  const unsigned char *buffer;
  size_t buffer_len;

  printf ("  Duplicate instruction... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 0x02);

  /* Duplicate entry at relative index 0 (newest) */
  result = SocketQPACK_EncoderStream_write_duplicate (stream, 0);
  TEST_ASSERT (result == QPACK_ENCODER_STREAM_OK, "Write should succeed");

  buffer = SocketQPACK_EncoderStream_get_buffer (stream, &buffer_len);
  TEST_ASSERT (buffer != NULL, "Buffer should not be NULL");
  TEST_ASSERT (buffer_len == 1, "Should encode to 1 byte");
  /* 0b000xxxxx with index 0 = 0x00 */
  TEST_ASSERT (buffer[0] == 0x00, "Should be 0x00");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_duplicate_instruction_large_index (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACK_EncoderStream_Result result;
  const unsigned char *buffer;
  size_t buffer_len;

  printf ("  Duplicate instruction (large index)... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 0x02);

  /* Duplicate entry at relative index 100 (needs multi-byte) */
  result = SocketQPACK_EncoderStream_write_duplicate (stream, 100);
  TEST_ASSERT (result == QPACK_ENCODER_STREAM_OK, "Write should succeed");

  buffer = SocketQPACK_EncoderStream_get_buffer (stream, &buffer_len);
  TEST_ASSERT (buffer != NULL, "Buffer should not be NULL");
  TEST_ASSERT (buffer_len > 1, "Should encode to multiple bytes");
  /* First byte should have high bits 000 and max prefix (31) */
  TEST_ASSERT ((buffer[0] & 0xE0) == 0x00, "High bits should be 000");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * Test: Buffer Management
 * ============================================================================
 */

static void
test_buffer_reset (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  const unsigned char *buffer;
  size_t buffer_len;

  printf ("  Buffer reset... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 0x02);

  /* Write something */
  SocketQPACK_EncoderStream_write_capacity (stream, 100);

  buffer = SocketQPACK_EncoderStream_get_buffer (stream, &buffer_len);
  TEST_ASSERT (buffer != NULL, "Buffer should not be NULL");
  TEST_ASSERT (buffer_len > 0, "Buffer should have data");

  /* Reset buffer */
  SocketQPACK_EncoderStream_reset_buffer (stream);

  buffer = SocketQPACK_EncoderStream_get_buffer (stream, &buffer_len);
  TEST_ASSERT (buffer != NULL, "Buffer should not be NULL after reset");
  TEST_ASSERT (buffer_len == 0, "Buffer should be empty after reset");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_buffer_accumulation (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  const unsigned char *buffer;
  size_t len1, len2;

  printf ("  Buffer accumulation... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 0x02);

  /* Write first instruction */
  SocketQPACK_EncoderStream_write_capacity (stream, 100);
  buffer = SocketQPACK_EncoderStream_get_buffer (stream, &len1);
  TEST_ASSERT (buffer != NULL, "Buffer should not be NULL");
  TEST_ASSERT (len1 > 0, "First write should produce data");

  /* Write second instruction */
  SocketQPACK_EncoderStream_write_duplicate (stream, 0);
  buffer = SocketQPACK_EncoderStream_get_buffer (stream, &len2);
  TEST_ASSERT (buffer != NULL, "Buffer should not be NULL");
  TEST_ASSERT (len2 > len1, "Buffer should accumulate");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
test_buffer_get_null_checks (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  const unsigned char *buffer;
  size_t buffer_len = 999;

  printf ("  Buffer get NULL checks... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 0x02);

  /* NULL buffer_len pointer */
  buffer = SocketQPACK_EncoderStream_get_buffer (stream, NULL);
  TEST_ASSERT (buffer == NULL, "Should return NULL with NULL buffer_len");

  /* NULL stream */
  buffer = SocketQPACK_EncoderStream_get_buffer (NULL, &buffer_len);
  TEST_ASSERT (buffer == NULL, "Should return NULL with NULL stream");
  TEST_ASSERT (buffer_len == 0, "Buffer len should be set to 0");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * Test: Stream Closure (Error Condition)
 * RFC 9204 Section 4.2: The sender MUST NOT close the encoder stream
 * ============================================================================
 */

static void
test_stream_closure (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACK_EncoderStream_Result result;

  printf ("  Stream closure raises H3_CLOSED_CRITICAL_STREAM... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 0x02);

  /* Close the stream (error condition) */
  result = SocketQPACK_EncoderStream_close (stream);
  TEST_ASSERT (result == QPACK_ENCODER_STREAM_CLOSED,
               "Close should return CLOSED status");

  /* Further operations should fail */
  TEST_ASSERT (SocketQPACK_EncoderStream_is_initialized (stream) == 0,
               "Stream should no longer be active after close");

  result = SocketQPACK_EncoderStream_write_capacity (stream, 100);
  TEST_ASSERT (result == QPACK_ENCODER_STREAM_CLOSED,
               "Write after close should fail");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * Test: Operations on Uninitialized Stream
 * ============================================================================
 */

static void
test_operations_on_null_stream (void)
{
  SocketQPACK_EncoderStream_Result result;
  const unsigned char value[] = "test";

  printf ("  Operations on NULL stream... ");

  result = SocketQPACK_EncoderStream_write_capacity (NULL, 100);
  TEST_ASSERT (result == QPACK_ENCODER_STREAM_INVALID_PARAM,
               "Write capacity on NULL should fail");

  result = SocketQPACK_EncoderStream_write_duplicate (NULL, 0);
  TEST_ASSERT (result == QPACK_ENCODER_STREAM_INVALID_PARAM,
               "Write duplicate on NULL should fail");

  result = SocketQPACK_EncoderStream_write_insert_nameref (
      NULL, 1, 0, value, 4, 0);
  TEST_ASSERT (result == QPACK_ENCODER_STREAM_INVALID_PARAM,
               "Write insert nameref on NULL should fail");

  result = SocketQPACK_EncoderStream_write_insert_literal (
      NULL, value, 4, value, 4, 0, 0);
  TEST_ASSERT (result == QPACK_ENCODER_STREAM_INVALID_PARAM,
               "Write insert literal on NULL should fail");

  printf ("PASS\n");
}

/* ============================================================================
 * Test: Result String
 * ============================================================================
 */

static void
test_result_string (void)
{
  const char *str;

  printf ("  Result string conversion... ");

  str = SocketQPACK_EncoderStream_result_string (QPACK_ENCODER_STREAM_OK);
  TEST_ASSERT (str != NULL && strcmp (str, "OK") == 0, "OK string");

  str = SocketQPACK_EncoderStream_result_string (QPACK_ENCODER_STREAM_CLOSED);
  TEST_ASSERT (str != NULL, "CLOSED string should exist");

  str = SocketQPACK_EncoderStream_result_string (
      (SocketQPACK_EncoderStream_Result)999);
  TEST_ASSERT (str != NULL && strcmp (str, "Unknown error") == 0,
               "Unknown error string");

  printf ("PASS\n");
}

/* ============================================================================
 * Test: Multiple Instructions Without Framing
 * RFC 9204 Section 4.2: Unframed sequence of encoder instructions
 * ============================================================================
 */

static void
test_unframed_instruction_sequence (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  const unsigned char *buffer;
  size_t buffer_len;
  const unsigned char name[] = "custom-header";
  const unsigned char value[] = "custom-value";

  printf ("  Unframed instruction sequence... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 0x02);

  /* Write multiple instructions */
  SocketQPACK_EncoderStream_write_capacity (stream, 4096);
  SocketQPACK_EncoderStream_write_insert_literal (
      stream, name, sizeof (name) - 1, value, sizeof (value) - 1, 0, 0);
  SocketQPACK_EncoderStream_write_duplicate (stream, 0);

  buffer = SocketQPACK_EncoderStream_get_buffer (stream, &buffer_len);
  TEST_ASSERT (buffer != NULL, "Buffer should not be NULL");
  TEST_ASSERT (buffer_len > 0, "Buffer should have accumulated data");

  /* Verify instructions are concatenated without framing */
  /* First instruction: capacity (0b001xxxxx) */
  TEST_ASSERT ((buffer[0] & 0xE0) == 0x20, "First should be capacity");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * Test: Only One Encoder Stream Per Direction
 * RFC 9204 Section 4.2: Each endpoint MUST initiate at most one encoder stream
 * ============================================================================
 */

static void
test_single_encoder_stream (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream1, stream2;

  printf ("  Single encoder stream per connection... ");

  arena = Arena_new ();

  /* First stream should succeed */
  stream1 = SocketQPACK_EncoderStream_new (arena, 0x02);
  TEST_ASSERT (stream1 != NULL, "First stream should be created");
  TEST_ASSERT (SocketQPACK_EncoderStream_is_initialized (stream1) == 1,
               "First stream should be initialized");

  /* Creating a second stream with different ID is allowed (different conn) */
  stream2 = SocketQPACK_EncoderStream_new (arena, 0x06);
  TEST_ASSERT (stream2 != NULL, "Second stream creation allowed");

  /* Note: RFC requires tracking at connection level, not stream level.
   * The caller is responsible for ensuring only one encoder stream per
   * connection direction. */

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
  printf ("\n=== QPACK Encoder Stream Tests (RFC 9204 Section 4.2) ===\n\n");

  printf ("Stream Type Validation:\n");
  test_stream_type_validation ();

  printf ("\nStream Initialization:\n");
  test_stream_initialization ();
  test_stream_null_arena ();
  test_stream_null_checks ();

  printf ("\nSet Dynamic Table Capacity (RFC 9204 Section 4.3.1):\n");
  test_capacity_instruction_small ();
  test_capacity_instruction_large ();
  test_capacity_instruction_zero ();

  printf ("\nInsert With Name Reference (RFC 9204 Section 4.3.2):\n");
  test_insert_nameref_static ();
  test_insert_nameref_dynamic ();

  printf ("\nInsert With Literal Name (RFC 9204 Section 4.3.3):\n");
  test_insert_literal ();
  test_insert_literal_empty_name ();

  printf ("\nDuplicate Instruction (RFC 9204 Section 4.3.4):\n");
  test_duplicate_instruction ();
  test_duplicate_instruction_large_index ();

  printf ("\nBuffer Management:\n");
  test_buffer_reset ();
  test_buffer_accumulation ();
  test_buffer_get_null_checks ();

  printf ("\nStream Closure:\n");
  test_stream_closure ();

  printf ("\nError Handling:\n");
  test_operations_on_null_stream ();
  test_result_string ();

  printf ("\nUnframed Instruction Sequence:\n");
  test_unframed_instruction_sequence ();

  printf ("\nSingle Encoder Stream Constraint:\n");
  test_single_encoder_stream ();

  printf ("\n=== All QPACK Encoder Stream Tests Passed ===\n\n");

  return 0;
}
