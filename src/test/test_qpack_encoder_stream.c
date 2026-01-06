/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_encoder_stream.c
 * @brief Unit tests for QPACK Encoder Stream Infrastructure (RFC 9204
 * Section 4.2)
 *
 * Tests the encoder stream implementation including:
 * - Stream lifecycle (creation, initialization, state)
 * - Stream type validation (Section 4.2)
 * - Encoder instructions (Section 4.3):
 *   - Set Dynamic Table Capacity (4.3.1)
 *   - Insert with Name Reference (4.3.2)
 *   - Insert with Literal Name (4.3.3)
 *   - Duplicate (4.3.4)
 * - Buffer management
 * - Error handling and security
 */

#include "core/Arena.h"
#include "http/qpack/SocketQPACK.h"
#include "http/qpack/SocketQPACKEncoderStream.h"

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
 * STREAM TYPE VALIDATION TESTS (RFC 9204 Section 4.2)
 * ============================================================================
 */

/**
 * Test encoder stream type validation.
 *
 * RFC 9204 Section 4.2: Encoder stream has type 0x02.
 */
static void
test_stream_type_validation (void)
{
  SocketQPACKStream_Result result;

  printf ("  Stream type validation... ");

  /* Valid encoder stream type (0x02) */
  result = SocketQPACK_EncoderStream_validate_type (QPACK_ENCODER_STREAM_TYPE);
  TEST_ASSERT (result == QPACK_STREAM_OK, "type 0x02 should be valid");

  /* Invalid types */
  result = SocketQPACK_EncoderStream_validate_type (0x00);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_TYPE, "type 0x00 invalid");

  result = SocketQPACK_EncoderStream_validate_type (0x01);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_TYPE, "type 0x01 invalid");

  result = SocketQPACK_EncoderStream_validate_type (QPACK_DECODER_STREAM_TYPE);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_TYPE, "type 0x03 invalid");

  result = SocketQPACK_EncoderStream_validate_type (0xFF);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_TYPE, "type 0xFF invalid");

  printf ("PASS\n");
}

/* ============================================================================
 * STREAM LIFECYCLE TESTS
 * ============================================================================
 */

/**
 * Test encoder stream creation.
 */
static void
test_stream_creation (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;

  printf ("  Stream creation... ");

  arena = Arena_new ();
  TEST_ASSERT (arena != NULL, "arena creation");

  /* Create stream with typical parameters */
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  TEST_ASSERT (stream != NULL, "stream creation");

  /* Verify initial state */
  TEST_ASSERT (!SocketQPACK_EncoderStream_is_open (stream),
               "stream not initialized");
  TEST_ASSERT (SocketQPACK_EncoderStream_get_id (stream) == 2, "stream_id=2");
  TEST_ASSERT (SocketQPACK_EncoderStream_buffer_size (stream) == 0,
               "buffer empty");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test encoder stream creation with NULL arena.
 */
static void
test_stream_creation_null_arena (void)
{
  SocketQPACK_EncoderStream_T stream;

  printf ("  Stream creation NULL arena... ");

  stream = SocketQPACK_EncoderStream_new (NULL, 2, 4096);
  TEST_ASSERT (stream == NULL, "NULL arena should fail");

  printf ("PASS\n");
}

/**
 * Test encoder stream initialization.
 */
static void
test_stream_initialization (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACKStream_Result result;

  printf ("  Stream initialization... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  TEST_ASSERT (stream != NULL, "stream creation");

  /* Not initialized yet */
  TEST_ASSERT (!SocketQPACK_EncoderStream_is_open (stream), "not open yet");

  /* Initialize */
  result = SocketQPACK_EncoderStream_init (stream);
  TEST_ASSERT (result == QPACK_STREAM_OK, "init should succeed");
  TEST_ASSERT (SocketQPACK_EncoderStream_is_open (stream), "now open");

  /* Double init should fail */
  result = SocketQPACK_EncoderStream_init (stream);
  TEST_ASSERT (result == QPACK_STREAM_ERR_ALREADY_INIT, "double init fails");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test encoder stream NULL parameter handling for lifecycle functions.
 */
static void
test_stream_lifecycle_null_params (void)
{
  SocketQPACKStream_Result result;
  size_t len;

  printf ("  Lifecycle NULL parameters... ");

  /* init with NULL */
  result = SocketQPACK_EncoderStream_init (NULL);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "init NULL fails");

  /* is_open with NULL */
  TEST_ASSERT (!SocketQPACK_EncoderStream_is_open (NULL), "is_open NULL=false");

  /* get_id with NULL */
  TEST_ASSERT (SocketQPACK_EncoderStream_get_id (NULL) == 0, "get_id NULL=0");

  /* buffer_size with NULL */
  TEST_ASSERT (SocketQPACK_EncoderStream_buffer_size (NULL) == 0,
               "buffer_size NULL=0");

  /* get_buffer with NULL */
  TEST_ASSERT (SocketQPACK_EncoderStream_get_buffer (NULL, &len) == NULL,
               "get_buffer NULL=NULL");
  TEST_ASSERT (len == 0, "get_buffer NULL len=0");

  /* reset_buffer with NULL */
  result = SocketQPACK_EncoderStream_reset_buffer (NULL);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "reset NULL fails");

  printf ("PASS\n");
}

/* ============================================================================
 * SET DYNAMIC TABLE CAPACITY TESTS (RFC 9204 Section 4.3.1)
 * ============================================================================
 */

/**
 * Test Set Dynamic Table Capacity instruction encoding.
 *
 * RFC 9204 Section 4.3.1: Bit pattern 001xxxxx with 5-bit prefix.
 */
static void
test_write_capacity_basic (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACKStream_Result result;
  const unsigned char *buf;
  size_t len;

  printf ("  Set capacity instruction basic... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  SocketQPACK_EncoderStream_init (stream);

  /* Write capacity = 0 (disable dynamic table) */
  result = SocketQPACK_EncoderStream_write_capacity (stream, 0);
  TEST_ASSERT (result == QPACK_STREAM_OK, "capacity=0 should succeed");

  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf != NULL, "buffer not NULL");
  TEST_ASSERT (len == 1, "single byte for capacity=0");
  TEST_ASSERT (buf[0] == 0x20, "001 00000 = 0x20 for capacity=0");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test Set Capacity with various values.
 */
static void
test_write_capacity_values (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACKStream_Result result;
  const unsigned char *buf;
  size_t len;

  printf ("  Set capacity various values... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 10000);
  SocketQPACK_EncoderStream_init (stream);

  /* Capacity = 30 (fits in 5 bits: 30 < 31) */
  result = SocketQPACK_EncoderStream_write_capacity (stream, 30);
  TEST_ASSERT (result == QPACK_STREAM_OK, "capacity=30 should succeed");
  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len);
  TEST_ASSERT (len == 1, "single byte for capacity=30");
  TEST_ASSERT (buf[0] == (0x20 | 30), "001 11110 for capacity=30");

  SocketQPACK_EncoderStream_reset_buffer (stream);

  /* Capacity = 31 (needs continuation: 2^5 - 1 = 31) */
  result = SocketQPACK_EncoderStream_write_capacity (stream, 31);
  TEST_ASSERT (result == QPACK_STREAM_OK, "capacity=31 should succeed");
  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len);
  TEST_ASSERT (len == 2, "two bytes for capacity=31");
  TEST_ASSERT (buf[0] == 0x3F, "001 11111 prefix full");
  TEST_ASSERT (buf[1] == 0x00, "continuation 0");

  SocketQPACK_EncoderStream_reset_buffer (stream);

  /* Capacity = 4096 */
  result = SocketQPACK_EncoderStream_write_capacity (stream, 4096);
  TEST_ASSERT (result == QPACK_STREAM_OK, "capacity=4096 should succeed");
  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf != NULL && len >= 2, "multi-byte encoding");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test Set Capacity exceeds maximum.
 */
static void
test_write_capacity_exceed_max (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACKStream_Result result;

  printf ("  Set capacity exceeds max... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096); /* max = 4096 */
  SocketQPACK_EncoderStream_init (stream);

  /* Exactly at max should succeed */
  result = SocketQPACK_EncoderStream_write_capacity (stream, 4096);
  TEST_ASSERT (result == QPACK_STREAM_OK, "capacity=max should succeed");

  SocketQPACK_EncoderStream_reset_buffer (stream);

  /* Above max should fail */
  result = SocketQPACK_EncoderStream_write_capacity (stream, 4097);
  TEST_ASSERT (result == QPACK_STREAM_ERR_CAPACITY_EXCEED,
               "capacity>max should fail");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test Set Capacity on uninitialized stream.
 */
static void
test_write_capacity_not_init (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACKStream_Result result;

  printf ("  Set capacity uninitialized... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  /* Don't init */

  result = SocketQPACK_EncoderStream_write_capacity (stream, 1000);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NOT_INIT, "uninitialized fails");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * INSERT WITH NAME REFERENCE TESTS (RFC 9204 Section 4.3.2)
 * ============================================================================
 */

/**
 * Test Insert with Name Reference - static table.
 *
 * RFC 9204 Section 4.3.2: Bit pattern 1Txxxxxx
 * T=1 for static table reference.
 */
static void
test_write_insert_nameref_static (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACKStream_Result result;
  const unsigned char *buf;
  size_t len;

  printf ("  Insert nameref static table... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  SocketQPACK_EncoderStream_init (stream);

  /* Static table index 0 (:authority), empty value */
  result = SocketQPACK_EncoderStream_write_insert_nameref (
      stream, true, 0, NULL, 0, false);
  TEST_ASSERT (result == QPACK_STREAM_OK, "nameref static idx=0 success");

  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf != NULL && len >= 2, "at least 2 bytes");
  /* First byte: 11 000000 = 0xC0 (1=nameref, 1=static, 0=index) */
  TEST_ASSERT ((buf[0] & 0xC0) == 0xC0, "11 prefix for static nameref");
  TEST_ASSERT ((buf[0] & 0x3F) == 0, "index 0");

  SocketQPACK_EncoderStream_reset_buffer (stream);

  /* Static table index 15 (:method GET), value "test" */
  const unsigned char *value = (const unsigned char *)"test";
  result = SocketQPACK_EncoderStream_write_insert_nameref (
      stream, true, 15, value, 4, false);
  TEST_ASSERT (result == QPACK_STREAM_OK, "nameref static idx=15 success");

  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf != NULL, "buffer not NULL");
  TEST_ASSERT ((buf[0] & 0xC0) == 0xC0, "11 prefix");
  TEST_ASSERT ((buf[0] & 0x3F) == 15, "index 15");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test Insert with Name Reference - dynamic table.
 *
 * T=0 for dynamic table reference.
 */
static void
test_write_insert_nameref_dynamic (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACKStream_Result result;
  const unsigned char *buf;
  size_t len;

  printf ("  Insert nameref dynamic table... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  SocketQPACK_EncoderStream_init (stream);

  /* Dynamic table index 0 (most recent), value "value" */
  const unsigned char *value = (const unsigned char *)"value";
  result = SocketQPACK_EncoderStream_write_insert_nameref (
      stream, false, 0, value, 5, false);
  TEST_ASSERT (result == QPACK_STREAM_OK, "nameref dynamic idx=0 success");

  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf != NULL, "buffer not NULL");
  /* First byte: 10 000000 = 0x80 (1=nameref, 0=dynamic, 0=index) */
  TEST_ASSERT ((buf[0] & 0xC0) == 0x80, "10 prefix for dynamic nameref");
  TEST_ASSERT ((buf[0] & 0x3F) == 0, "index 0");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test Insert with Name Reference - invalid static index.
 */
static void
test_write_insert_nameref_invalid_index (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACKStream_Result result;

  printf ("  Insert nameref invalid static index... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  SocketQPACK_EncoderStream_init (stream);

  /* Static table has indices 0-98 (99 entries) */
  result = SocketQPACK_EncoderStream_write_insert_nameref (
      stream, true, 99, NULL, 0, false);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_INDEX, "index 99 invalid");

  result = SocketQPACK_EncoderStream_write_insert_nameref (
      stream, true, 100, NULL, 0, false);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_INDEX, "index 100 invalid");

  /* Index 98 should be valid (last static entry) */
  result = SocketQPACK_EncoderStream_write_insert_nameref (
      stream, true, 98, NULL, 0, false);
  TEST_ASSERT (result == QPACK_STREAM_OK, "index 98 valid");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test Insert with Name Reference - with Huffman encoding.
 */
static void
test_write_insert_nameref_huffman (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACKStream_Result result;
  const unsigned char *buf;
  size_t len_no_huff, len_huff;

  printf ("  Insert nameref with Huffman... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  SocketQPACK_EncoderStream_init (stream);

  /* Value that compresses well with Huffman */
  const unsigned char *value = (const unsigned char *)"www.example.com";

  /* Without Huffman */
  result = SocketQPACK_EncoderStream_write_insert_nameref (
      stream, true, 0, value, 15, false);
  TEST_ASSERT (result == QPACK_STREAM_OK, "no huffman success");
  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len_no_huff);
  TEST_ASSERT (buf != NULL, "buffer not NULL");

  SocketQPACK_EncoderStream_reset_buffer (stream);

  /* With Huffman */
  result = SocketQPACK_EncoderStream_write_insert_nameref (
      stream, true, 0, value, 15, true);
  TEST_ASSERT (result == QPACK_STREAM_OK, "huffman success");
  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len_huff);
  TEST_ASSERT (buf != NULL, "buffer not NULL");

  /* Huffman should produce smaller encoding */
  TEST_ASSERT (len_huff < len_no_huff, "Huffman smaller");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * INSERT WITH LITERAL NAME TESTS (RFC 9204 Section 4.3.3)
 * ============================================================================
 */

/**
 * Test Insert with Literal Name - basic.
 *
 * RFC 9204 Section 4.3.3: Bit pattern 01Hxxxxx
 */
static void
test_write_insert_literal_basic (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACKStream_Result result;
  const unsigned char *buf;
  size_t len;

  printf ("  Insert literal basic... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  SocketQPACK_EncoderStream_init (stream);

  const unsigned char *name = (const unsigned char *)"x-custom";
  const unsigned char *value = (const unsigned char *)"test-value";

  result = SocketQPACK_EncoderStream_write_insert_literal (
      stream, name, 8, false, value, 10, false);
  TEST_ASSERT (result == QPACK_STREAM_OK, "literal insert success");

  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf != NULL, "buffer not NULL");
  /* First byte: 01 0 xxxxx (01=literal, 0=no huffman for name) */
  TEST_ASSERT ((buf[0] & 0xE0) == 0x40, "01x prefix for literal");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test Insert with Literal Name - empty strings.
 */
static void
test_write_insert_literal_empty (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACKStream_Result result;
  const unsigned char *buf;
  size_t len;

  printf ("  Insert literal empty strings... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  SocketQPACK_EncoderStream_init (stream);

  /* Empty name - allowed by spec */
  result = SocketQPACK_EncoderStream_write_insert_literal (
      stream, NULL, 0, false, (const unsigned char *)"value", 5, false);
  TEST_ASSERT (result == QPACK_STREAM_OK, "empty name success");

  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf != NULL && len >= 2, "at least 2 bytes");

  SocketQPACK_EncoderStream_reset_buffer (stream);

  /* Empty value - also allowed */
  result = SocketQPACK_EncoderStream_write_insert_literal (
      stream, (const unsigned char *)"name", 4, false, NULL, 0, false);
  TEST_ASSERT (result == QPACK_STREAM_OK, "empty value success");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test Insert with Literal Name - with Huffman.
 */
static void
test_write_insert_literal_huffman (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACKStream_Result result;
  size_t len_no_huff, len_huff;

  printf ("  Insert literal with Huffman... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  SocketQPACK_EncoderStream_init (stream);

  const unsigned char *name = (const unsigned char *)"content-type";
  const unsigned char *value = (const unsigned char *)"application/json";

  /* Without Huffman */
  result = SocketQPACK_EncoderStream_write_insert_literal (
      stream, name, 12, false, value, 16, false);
  TEST_ASSERT (result == QPACK_STREAM_OK, "no huffman success");
  SocketQPACK_EncoderStream_get_buffer (stream, &len_no_huff);

  SocketQPACK_EncoderStream_reset_buffer (stream);

  /* With Huffman on both */
  result = SocketQPACK_EncoderStream_write_insert_literal (
      stream, name, 12, true, value, 16, true);
  TEST_ASSERT (result == QPACK_STREAM_OK, "huffman success");
  SocketQPACK_EncoderStream_get_buffer (stream, &len_huff);

  /* Huffman should produce smaller encoding */
  TEST_ASSERT (len_huff < len_no_huff, "Huffman smaller");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test Insert with Literal Name - NULL value with non-zero length.
 */
static void
test_write_insert_literal_null_value (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACKStream_Result result;

  printf ("  Insert literal NULL value check... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  SocketQPACK_EncoderStream_init (stream);

  /* NULL value with len > 0 should fail */
  result = SocketQPACK_EncoderStream_write_insert_literal (
      stream, (const unsigned char *)"name", 4, false, NULL, 5, false);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "NULL value+len fails");

  /* NULL name with len > 0 should fail */
  result = SocketQPACK_EncoderStream_write_insert_literal (
      stream, NULL, 5, false, (const unsigned char *)"value", 5, false);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "NULL name+len fails");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * DUPLICATE INSTRUCTION TESTS (RFC 9204 Section 4.3.4)
 * ============================================================================
 */

/**
 * Test Duplicate instruction encoding.
 *
 * RFC 9204 Section 4.3.4: Bit pattern 000xxxxx with 5-bit prefix.
 */
static void
test_write_duplicate_basic (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACKStream_Result result;
  const unsigned char *buf;
  size_t len;

  printf ("  Duplicate instruction basic... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  SocketQPACK_EncoderStream_init (stream);

  /* Duplicate index 0 (most recent entry) */
  result = SocketQPACK_EncoderStream_write_duplicate (stream, 0);
  TEST_ASSERT (result == QPACK_STREAM_OK, "duplicate idx=0 success");

  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf != NULL, "buffer not NULL");
  TEST_ASSERT (len == 1, "single byte for idx=0");
  TEST_ASSERT (buf[0] == 0x00, "000 00000 for idx=0");

  SocketQPACK_EncoderStream_reset_buffer (stream);

  /* Duplicate index 30 (fits in 5 bits) */
  result = SocketQPACK_EncoderStream_write_duplicate (stream, 30);
  TEST_ASSERT (result == QPACK_STREAM_OK, "duplicate idx=30 success");
  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len);
  TEST_ASSERT (len == 1, "single byte for idx=30");
  TEST_ASSERT (buf[0] == 30, "000 11110 for idx=30");

  SocketQPACK_EncoderStream_reset_buffer (stream);

  /* Duplicate index 31 (needs continuation) */
  result = SocketQPACK_EncoderStream_write_duplicate (stream, 31);
  TEST_ASSERT (result == QPACK_STREAM_OK, "duplicate idx=31 success");
  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len);
  TEST_ASSERT (len == 2, "two bytes for idx=31");
  TEST_ASSERT (buf[0] == 0x1F, "000 11111 prefix full");
  TEST_ASSERT (buf[1] == 0x00, "continuation 0");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test Duplicate on uninitialized stream.
 */
static void
test_write_duplicate_not_init (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACKStream_Result result;

  printf ("  Duplicate uninitialized... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  /* Don't init */

  result = SocketQPACK_EncoderStream_write_duplicate (stream, 0);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NOT_INIT, "uninitialized fails");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * BUFFER MANAGEMENT TESTS
 * ============================================================================
 */

/**
 * Test buffer management - get, reset, size.
 */
static void
test_buffer_management (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  const unsigned char *buf;
  size_t len;

  printf ("  Buffer management... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  SocketQPACK_EncoderStream_init (stream);

  /* Empty buffer */
  TEST_ASSERT (SocketQPACK_EncoderStream_buffer_size (stream) == 0,
               "initially empty");
  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf == NULL && len == 0, "empty returns NULL");

  /* Write something */
  SocketQPACK_EncoderStream_write_capacity (stream, 100);
  TEST_ASSERT (SocketQPACK_EncoderStream_buffer_size (stream) > 0, "has data");

  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf != NULL && len > 0, "get_buffer returns data");
  TEST_ASSERT (len == SocketQPACK_EncoderStream_buffer_size (stream),
               "len matches size");

  /* Reset */
  SocketQPACK_EncoderStream_reset_buffer (stream);
  TEST_ASSERT (SocketQPACK_EncoderStream_buffer_size (stream) == 0,
               "reset clears");
  buf = SocketQPACK_EncoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf == NULL && len == 0, "empty after reset");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test buffer accumulation across multiple instructions.
 */
static void
test_buffer_accumulation (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  size_t len1, len2, len3;

  printf ("  Buffer accumulation... ");

  arena = Arena_new ();
  stream = SocketQPACK_EncoderStream_new (arena, 2, 4096);
  SocketQPACK_EncoderStream_init (stream);

  /* Write multiple instructions */
  SocketQPACK_EncoderStream_write_capacity (stream, 4096);
  len1 = SocketQPACK_EncoderStream_buffer_size (stream);
  TEST_ASSERT (len1 > 0, "first instruction written");

  SocketQPACK_EncoderStream_write_duplicate (stream, 0);
  len2 = SocketQPACK_EncoderStream_buffer_size (stream);
  TEST_ASSERT (len2 > len1, "second instruction accumulated");

  SocketQPACK_EncoderStream_write_insert_nameref (
      stream, true, 0, (const unsigned char *)"test", 4, false);
  len3 = SocketQPACK_EncoderStream_buffer_size (stream);
  TEST_ASSERT (len3 > len2, "third instruction accumulated");

  /* All instructions in one buffer */
  const unsigned char *buf;
  size_t total_len;
  buf = SocketQPACK_EncoderStream_get_buffer (stream, &total_len);
  TEST_ASSERT (buf != NULL, "buffer not NULL");
  TEST_ASSERT (total_len == len3, "total matches");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * RESULT STRING TESTS
 * ============================================================================
 */

/**
 * Test result string function.
 */
static void
test_result_strings (void)
{
  printf ("  Result strings... ");

  /* All known result codes */
  TEST_ASSERT (strcmp (SocketQPACKStream_result_string (QPACK_STREAM_OK), "OK")
                   == 0,
               "OK string");

  TEST_ASSERT (
      strstr (SocketQPACKStream_result_string (QPACK_STREAM_ERR_BUFFER_FULL),
              "buffer")
          != NULL,
      "BUFFER_FULL string");

  TEST_ASSERT (
      strstr (SocketQPACKStream_result_string (QPACK_STREAM_ERR_ALREADY_INIT),
              "already")
          != NULL,
      "ALREADY_INIT string");

  TEST_ASSERT (
      strstr (SocketQPACKStream_result_string (QPACK_STREAM_ERR_NOT_INIT),
              "not")
          != NULL,
      "NOT_INIT string");

  TEST_ASSERT (
      strstr (SocketQPACKStream_result_string (QPACK_STREAM_ERR_INVALID_TYPE),
              "type")
          != NULL,
      "INVALID_TYPE string");

  TEST_ASSERT (strstr (SocketQPACKStream_result_string (
                           QPACK_STREAM_ERR_CLOSED_CRITICAL),
                       "0x0104")
                   != NULL,
               "CLOSED_CRITICAL string with H3 code");

  TEST_ASSERT (
      strstr (SocketQPACKStream_result_string (QPACK_STREAM_ERR_NULL_PARAM),
              "NULL")
          != NULL,
      "NULL_PARAM string");

  TEST_ASSERT (
      strstr (SocketQPACKStream_result_string (QPACK_STREAM_ERR_INVALID_INDEX),
              "index")
          != NULL,
      "INVALID_INDEX string");

  TEST_ASSERT (strstr (SocketQPACKStream_result_string (
                           QPACK_STREAM_ERR_CAPACITY_EXCEED),
                       "exceeds")
                   != NULL,
               "CAPACITY_EXCEED string");

  /* Unknown code */
  TEST_ASSERT (
      strstr (SocketQPACKStream_result_string ((SocketQPACKStream_Result)999),
              "Unknown")
          != NULL,
      "Unknown result string");

  printf ("PASS\n");
}

/* ============================================================================
 * SECURITY TESTS
 * ============================================================================
 */

/**
 * Test NULL parameter handling for instruction functions.
 */
static void
test_instruction_null_params (void)
{
  SocketQPACKStream_Result result;

  printf ("  Instruction NULL parameters... ");

  /* All instruction functions with NULL stream */
  result = SocketQPACK_EncoderStream_write_capacity (NULL, 100);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "capacity NULL fails");

  result = SocketQPACK_EncoderStream_write_insert_nameref (
      NULL, true, 0, NULL, 0, false);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "nameref NULL fails");

  result = SocketQPACK_EncoderStream_write_insert_literal (
      NULL,
      (const unsigned char *)"n",
      1,
      false,
      (const unsigned char *)"v",
      1,
      false);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "literal NULL fails");

  result = SocketQPACK_EncoderStream_write_duplicate (NULL, 0);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "duplicate NULL fails");

  printf ("PASS\n");
}

/**
 * Test large values that could cause overflow.
 */
static void
test_large_values (void)
{
  Arena_T arena;
  SocketQPACK_EncoderStream_T stream;
  SocketQPACKStream_Result result;

  printf ("  Large values... ");

  arena = Arena_new ();
  /* Create with very large max capacity */
  stream = SocketQPACK_EncoderStream_new (arena, 2, UINT64_MAX);
  SocketQPACK_EncoderStream_init (stream);

  /* Large capacity value (should encode correctly with HPACK integer) */
  result = SocketQPACK_EncoderStream_write_capacity (stream, (1ULL << 40));
  TEST_ASSERT (result == QPACK_STREAM_OK, "large capacity succeeds");

  SocketQPACK_EncoderStream_reset_buffer (stream);

  /* Large duplicate index */
  result = SocketQPACK_EncoderStream_write_duplicate (stream, (1ULL << 40));
  TEST_ASSERT (result == QPACK_STREAM_OK, "large duplicate idx succeeds");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * TEST SUITE
 * ============================================================================
 */

static void
run_stream_type_tests (void)
{
  printf ("Stream Type Validation Tests (RFC 9204 Section 4.2):\n");
  test_stream_type_validation ();
}

static void
run_lifecycle_tests (void)
{
  printf ("Stream Lifecycle Tests:\n");
  test_stream_creation ();
  test_stream_creation_null_arena ();
  test_stream_initialization ();
  test_stream_lifecycle_null_params ();
}

static void
run_capacity_tests (void)
{
  printf ("Set Dynamic Table Capacity Tests (RFC 9204 Section 4.3.1):\n");
  test_write_capacity_basic ();
  test_write_capacity_values ();
  test_write_capacity_exceed_max ();
  test_write_capacity_not_init ();
}

static void
run_nameref_tests (void)
{
  printf ("Insert with Name Reference Tests (RFC 9204 Section 4.3.2):\n");
  test_write_insert_nameref_static ();
  test_write_insert_nameref_dynamic ();
  test_write_insert_nameref_invalid_index ();
  test_write_insert_nameref_huffman ();
}

static void
run_literal_tests (void)
{
  printf ("Insert with Literal Name Tests (RFC 9204 Section 4.3.3):\n");
  test_write_insert_literal_basic ();
  test_write_insert_literal_empty ();
  test_write_insert_literal_huffman ();
  test_write_insert_literal_null_value ();
}

static void
run_duplicate_tests (void)
{
  printf ("Duplicate Instruction Tests (RFC 9204 Section 4.3.4):\n");
  test_write_duplicate_basic ();
  test_write_duplicate_not_init ();
}

static void
run_buffer_tests (void)
{
  printf ("Buffer Management Tests:\n");
  test_buffer_management ();
  test_buffer_accumulation ();
}

static void
run_result_string_tests (void)
{
  printf ("Result String Tests:\n");
  test_result_strings ();
}

static void
run_security_tests (void)
{
  printf ("Security Tests:\n");
  test_instruction_null_params ();
  test_large_values ();
}

/* ============================================================================
 * INSERT WITH NAME REFERENCE PRIMITIVE TESTS (RFC 9204 Section 4.3.2)
 * ============================================================================
 */

/**
 * Test encode_insert_nameref basic functionality.
 */
static void
test_encode_insert_nameref_basic (void)
{
  unsigned char output[256];
  size_t bytes_written;
  SocketQPACKStream_Result result;

  printf ("  encode_insert_nameref basic... ");

  /* Static table index 0, empty value */
  result = SocketQPACK_encode_insert_nameref (
      output, sizeof (output), true, 0, NULL, 0, false, &bytes_written);
  TEST_ASSERT (result == QPACK_STREAM_OK, "static idx=0 empty value");
  TEST_ASSERT (bytes_written >= 2, "at least 2 bytes");
  /* First byte: 11 000000 = 0xC0 (1=nameref, 1=static, 0=index) */
  TEST_ASSERT ((output[0] & 0xC0) == 0xC0, "11 prefix for static nameref");
  TEST_ASSERT ((output[0] & 0x3F) == 0, "index 0");
  /* Second byte: value length = 0 */
  TEST_ASSERT ((output[1] & 0x7F) == 0, "value length 0");

  /* Static table index 15, value "test" */
  const unsigned char *value = (const unsigned char *)"test";
  result = SocketQPACK_encode_insert_nameref (
      output, sizeof (output), true, 15, value, 4, false, &bytes_written);
  TEST_ASSERT (result == QPACK_STREAM_OK, "static idx=15 with value");
  TEST_ASSERT ((output[0] & 0xC0) == 0xC0, "11 prefix");
  TEST_ASSERT ((output[0] & 0x3F) == 15, "index 15");

  printf ("PASS\n");
}

/**
 * Test encode_insert_nameref with dynamic table reference.
 */
static void
test_encode_insert_nameref_dynamic (void)
{
  unsigned char output[256];
  size_t bytes_written;
  SocketQPACKStream_Result result;

  printf ("  encode_insert_nameref dynamic... ");

  /* Dynamic table index 0, value "value" */
  const unsigned char *value = (const unsigned char *)"value";
  result = SocketQPACK_encode_insert_nameref (
      output, sizeof (output), false, 0, value, 5, false, &bytes_written);
  TEST_ASSERT (result == QPACK_STREAM_OK, "dynamic idx=0 success");
  /* First byte: 10 000000 = 0x80 (1=nameref, 0=dynamic, 0=index) */
  TEST_ASSERT ((output[0] & 0xC0) == 0x80, "10 prefix for dynamic nameref");
  TEST_ASSERT ((output[0] & 0x3F) == 0, "index 0");

  printf ("PASS\n");
}

/**
 * Test encode_insert_nameref with Huffman encoding.
 */
static void
test_encode_insert_nameref_with_huffman (void)
{
  unsigned char output_no_huff[256];
  unsigned char output_huff[256];
  size_t bytes_no_huff, bytes_huff;
  SocketQPACKStream_Result result;

  printf ("  encode_insert_nameref Huffman... ");

  /* Value that compresses well with Huffman */
  const unsigned char *value = (const unsigned char *)"www.example.com";

  /* Without Huffman */
  result = SocketQPACK_encode_insert_nameref (output_no_huff,
                                              sizeof (output_no_huff),
                                              true,
                                              0,
                                              value,
                                              15,
                                              false,
                                              &bytes_no_huff);
  TEST_ASSERT (result == QPACK_STREAM_OK, "no huffman success");

  /* With Huffman */
  result = SocketQPACK_encode_insert_nameref (
      output_huff, sizeof (output_huff), true, 0, value, 15, true, &bytes_huff);
  TEST_ASSERT (result == QPACK_STREAM_OK, "huffman success");

  /* Huffman should produce smaller encoding */
  TEST_ASSERT (bytes_huff < bytes_no_huff, "Huffman smaller");

  /* Verify Huffman flag is set */
  TEST_ASSERT ((output_huff[1] & 0x80) == 0x80, "H flag set");
  TEST_ASSERT ((output_no_huff[1] & 0x80) == 0x00, "H flag not set");

  printf ("PASS\n");
}

/**
 * Test encode_insert_nameref error cases.
 */
static void
test_encode_insert_nameref_errors (void)
{
  unsigned char output[256];
  size_t bytes_written;
  SocketQPACKStream_Result result;

  printf ("  encode_insert_nameref errors... ");

  /* NULL output */
  result = SocketQPACK_encode_insert_nameref (
      NULL, 256, true, 0, NULL, 0, false, &bytes_written);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "NULL output fails");

  /* NULL bytes_written */
  result = SocketQPACK_encode_insert_nameref (
      output, sizeof (output), true, 0, NULL, 0, false, NULL);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM,
               "NULL bytes_written fails");

  /* NULL value with non-zero length */
  result = SocketQPACK_encode_insert_nameref (
      output, sizeof (output), true, 0, NULL, 5, false, &bytes_written);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM,
               "NULL value with len fails");

  /* Invalid static index */
  result = SocketQPACK_encode_insert_nameref (
      output, sizeof (output), true, 99, NULL, 0, false, &bytes_written);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_INDEX, "static idx 99 fails");

  result = SocketQPACK_encode_insert_nameref (
      output, sizeof (output), true, 100, NULL, 0, false, &bytes_written);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_INDEX,
               "static idx 100 fails");

  /* Buffer too small */
  result = SocketQPACK_encode_insert_nameref (output,
                                              1,
                                              true,
                                              0,
                                              (const unsigned char *)"test",
                                              4,
                                              false,
                                              &bytes_written);
  TEST_ASSERT (result == QPACK_STREAM_ERR_BUFFER_FULL, "small buffer fails");

  printf ("PASS\n");
}

/**
 * Test decode_insert_nameref basic functionality.
 */
static void
test_decode_insert_nameref_basic (void)
{
  Arena_T arena;
  unsigned char encoded[256];
  size_t encoded_len;
  SocketQPACK_InsertNameRef decoded;
  size_t consumed;
  SocketQPACKStream_Result result;

  printf ("  decode_insert_nameref basic... ");

  arena = Arena_new ();
  TEST_ASSERT (arena != NULL, "arena creation");

  /* Encode static index 0, empty value */
  result = SocketQPACK_encode_insert_nameref (
      encoded, sizeof (encoded), true, 0, NULL, 0, false, &encoded_len);
  TEST_ASSERT (result == QPACK_STREAM_OK, "encode success");

  /* Decode */
  result = SocketQPACK_decode_insert_nameref (
      encoded, encoded_len, arena, &decoded, &consumed);
  TEST_ASSERT (result == QPACK_STREAM_OK, "decode success");
  TEST_ASSERT (consumed == encoded_len, "consumed all bytes");
  TEST_ASSERT (decoded.is_static == true, "is_static correct");
  TEST_ASSERT (decoded.name_index == 0, "name_index correct");
  TEST_ASSERT (decoded.value_len == 0, "value_len correct");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test decode_insert_nameref with value.
 */
static void
test_decode_insert_nameref_with_value (void)
{
  Arena_T arena;
  unsigned char encoded[256];
  size_t encoded_len;
  SocketQPACK_InsertNameRef decoded;
  size_t consumed;
  SocketQPACKStream_Result result;

  printf ("  decode_insert_nameref with value... ");

  arena = Arena_new ();

  /* Encode static index 15, value "test" */
  const unsigned char *value = (const unsigned char *)"test";
  result = SocketQPACK_encode_insert_nameref (
      encoded, sizeof (encoded), true, 15, value, 4, false, &encoded_len);
  TEST_ASSERT (result == QPACK_STREAM_OK, "encode success");

  /* Decode */
  result = SocketQPACK_decode_insert_nameref (
      encoded, encoded_len, arena, &decoded, &consumed);
  TEST_ASSERT (result == QPACK_STREAM_OK, "decode success");
  TEST_ASSERT (decoded.is_static == true, "is_static correct");
  TEST_ASSERT (decoded.name_index == 15, "name_index correct");
  TEST_ASSERT (decoded.value_len == 4, "value_len correct");
  TEST_ASSERT (memcmp (decoded.value, "test", 4) == 0, "value correct");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test decode_insert_nameref with Huffman-encoded value.
 */
static void
test_decode_insert_nameref_huffman_value (void)
{
  Arena_T arena;
  unsigned char encoded[256];
  size_t encoded_len;
  SocketQPACK_InsertNameRef decoded;
  size_t consumed;
  SocketQPACKStream_Result result;

  printf ("  decode_insert_nameref Huffman value... ");

  arena = Arena_new ();

  /* Encode with Huffman-encoded value */
  const unsigned char *value = (const unsigned char *)"www.example.com";
  result = SocketQPACK_encode_insert_nameref (
      encoded, sizeof (encoded), true, 0, value, 15, true, &encoded_len);
  TEST_ASSERT (result == QPACK_STREAM_OK, "encode success");

  /* Decode */
  result = SocketQPACK_decode_insert_nameref (
      encoded, encoded_len, arena, &decoded, &consumed);
  TEST_ASSERT (result == QPACK_STREAM_OK, "decode success");
  TEST_ASSERT (decoded.is_static == true, "is_static correct");
  TEST_ASSERT (decoded.name_index == 0, "name_index correct");
  TEST_ASSERT (decoded.value_len == 15, "value_len correct");
  TEST_ASSERT (memcmp (decoded.value, "www.example.com", 15) == 0,
               "value correctly decoded");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test decode_insert_nameref with dynamic table reference.
 */
static void
test_decode_insert_nameref_dynamic_ref (void)
{
  Arena_T arena;
  unsigned char encoded[256];
  size_t encoded_len;
  SocketQPACK_InsertNameRef decoded;
  size_t consumed;
  SocketQPACKStream_Result result;

  printf ("  decode_insert_nameref dynamic ref... ");

  arena = Arena_new ();

  /* Encode dynamic index 5, value "dynamic-value" */
  const unsigned char *value = (const unsigned char *)"dynamic-value";
  result = SocketQPACK_encode_insert_nameref (
      encoded, sizeof (encoded), false, 5, value, 13, false, &encoded_len);
  TEST_ASSERT (result == QPACK_STREAM_OK, "encode success");

  /* Decode */
  result = SocketQPACK_decode_insert_nameref (
      encoded, encoded_len, arena, &decoded, &consumed);
  TEST_ASSERT (result == QPACK_STREAM_OK, "decode success");
  TEST_ASSERT (decoded.is_static == false, "is_static false");
  TEST_ASSERT (decoded.name_index == 5, "name_index correct");
  TEST_ASSERT (decoded.value_len == 13, "value_len correct");
  TEST_ASSERT (memcmp (decoded.value, "dynamic-value", 13) == 0,
               "value correct");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test decode_insert_nameref error cases.
 */
static void
test_decode_insert_nameref_errors (void)
{
  Arena_T arena;
  unsigned char encoded[256];
  SocketQPACK_InsertNameRef decoded;
  size_t consumed;
  SocketQPACKStream_Result result;

  printf ("  decode_insert_nameref errors... ");

  arena = Arena_new ();

  /* NULL input */
  result = SocketQPACK_decode_insert_nameref (
      NULL, 10, arena, &decoded, &consumed);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "NULL input fails");

  /* NULL arena */
  result = SocketQPACK_decode_insert_nameref (
      encoded, 10, NULL, &decoded, &consumed);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "NULL arena fails");

  /* NULL result */
  result
      = SocketQPACK_decode_insert_nameref (encoded, 10, arena, NULL, &consumed);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "NULL result fails");

  /* NULL consumed */
  result
      = SocketQPACK_decode_insert_nameref (encoded, 10, arena, &decoded, NULL);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "NULL consumed fails");

  /* Empty input */
  result = SocketQPACK_decode_insert_nameref (
      encoded, 0, arena, &decoded, &consumed);
  TEST_ASSERT (result == QPACK_STREAM_ERR_BUFFER_FULL, "empty input fails");

  /* Truncated input (only first byte) */
  encoded[0] = 0xC0; /* Static nameref */
  result = SocketQPACK_decode_insert_nameref (
      encoded, 1, arena, &decoded, &consumed);
  TEST_ASSERT (result == QPACK_STREAM_ERR_BUFFER_FULL, "truncated input fails");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test validate_nameref_index for static table.
 */
static void
test_validate_nameref_index_static (void)
{
  SocketQPACKStream_Result result;

  printf ("  validate_nameref_index static... ");

  /* Valid static indices (0-98) */
  result = SocketQPACK_validate_nameref_index (true, 0, 0, 0);
  TEST_ASSERT (result == QPACK_STREAM_OK, "static index 0 valid");

  result = SocketQPACK_validate_nameref_index (true, 98, 0, 0);
  TEST_ASSERT (result == QPACK_STREAM_OK, "static index 98 valid");

  result = SocketQPACK_validate_nameref_index (true, 50, 0, 0);
  TEST_ASSERT (result == QPACK_STREAM_OK, "static index 50 valid");

  /* Invalid static indices (>= 99) */
  result = SocketQPACK_validate_nameref_index (true, 99, 0, 0);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_INDEX,
               "static index 99 invalid");

  result = SocketQPACK_validate_nameref_index (true, 100, 0, 0);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_INDEX,
               "static index 100 invalid");

  result = SocketQPACK_validate_nameref_index (true, 1000, 0, 0);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_INDEX,
               "static index 1000 invalid");

  printf ("PASS\n");
}

/**
 * Test validate_nameref_index for dynamic table.
 */
static void
test_validate_nameref_index_dynamic (void)
{
  SocketQPACKStream_Result result;

  printf ("  validate_nameref_index dynamic... ");

  /* insert_count=10, dropped_count=0: valid indices are 0-9 */
  result = SocketQPACK_validate_nameref_index (false, 0, 10, 0);
  TEST_ASSERT (result == QPACK_STREAM_OK, "dynamic index 0 valid (ic=10)");

  result = SocketQPACK_validate_nameref_index (false, 9, 10, 0);
  TEST_ASSERT (result == QPACK_STREAM_OK, "dynamic index 9 valid (ic=10)");

  /* Index >= insert_count is invalid (future reference) */
  result = SocketQPACK_validate_nameref_index (false, 10, 10, 0);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_INDEX,
               "dynamic index 10 invalid (ic=10)");

  result = SocketQPACK_validate_nameref_index (false, 100, 10, 0);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_INDEX,
               "dynamic index 100 invalid (ic=10)");

  /* With eviction: insert_count=10, dropped_count=5
   * Valid absolute indices: 5-9
   * Relative 0 -> abs 9 (valid)
   * Relative 4 -> abs 5 (valid)
   * Relative 5 -> abs 4 (evicted) */
  result = SocketQPACK_validate_nameref_index (false, 0, 10, 5);
  TEST_ASSERT (result == QPACK_STREAM_OK, "rel 0 -> abs 9 valid");

  result = SocketQPACK_validate_nameref_index (false, 4, 10, 5);
  TEST_ASSERT (result == QPACK_STREAM_OK, "rel 4 -> abs 5 valid");

  result = SocketQPACK_validate_nameref_index (false, 5, 10, 5);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_INDEX,
               "rel 5 -> abs 4 evicted");

  result = SocketQPACK_validate_nameref_index (false, 9, 10, 5);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_INDEX,
               "rel 9 -> abs 0 evicted");

  printf ("PASS\n");
}

/**
 * Test validate_nameref_index edge cases.
 */
static void
test_validate_nameref_index_edge_cases (void)
{
  SocketQPACKStream_Result result;

  printf ("  validate_nameref_index edge cases... ");

  /* Empty table (insert_count=0) */
  result = SocketQPACK_validate_nameref_index (false, 0, 0, 0);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_INDEX, "empty table invalid");

  /* Single entry (insert_count=1, dropped_count=0) */
  result = SocketQPACK_validate_nameref_index (false, 0, 1, 0);
  TEST_ASSERT (result == QPACK_STREAM_OK, "single entry index 0 valid");

  result = SocketQPACK_validate_nameref_index (false, 1, 1, 0);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_INDEX,
               "single entry index 1 invalid");

  /* All entries evicted */
  result = SocketQPACK_validate_nameref_index (false, 0, 10, 10);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_INDEX, "all evicted invalid");

  printf ("PASS\n");
}

/**
 * Test encode/decode roundtrip with various inputs.
 */
static void
test_encode_decode_roundtrip (void)
{
  Arena_T arena;
  unsigned char encoded[256];
  size_t encoded_len;
  SocketQPACK_InsertNameRef decoded;
  size_t consumed;
  SocketQPACKStream_Result result;

  printf ("  encode/decode roundtrip... ");

  arena = Arena_new ();

  /* Test various combinations */
  struct
  {
    bool is_static;
    uint64_t name_index;
    const char *value;
    bool use_huffman;
  } test_cases[] = {
    { true, 0, "", false },
    { true, 15, "GET", false },
    { true, 98, "value", false },
    { false, 0, "dynamic-value", false },
    { true, 0, "www.example.com", true },
    { true, 50, "application/json", true },
    { false, 10, "compress-this-value", true },
  };

  for (size_t i = 0; i < sizeof (test_cases) / sizeof (test_cases[0]); i++)
    {
      const unsigned char *value = (const unsigned char *)test_cases[i].value;
      size_t value_len = strlen (test_cases[i].value);

      /* Encode */
      result = SocketQPACK_encode_insert_nameref (encoded,
                                                  sizeof (encoded),
                                                  test_cases[i].is_static,
                                                  test_cases[i].name_index,
                                                  value,
                                                  value_len,
                                                  test_cases[i].use_huffman,
                                                  &encoded_len);
      TEST_ASSERT (result == QPACK_STREAM_OK, "encode roundtrip");

      /* Decode */
      result = SocketQPACK_decode_insert_nameref (
          encoded, encoded_len, arena, &decoded, &consumed);
      TEST_ASSERT (result == QPACK_STREAM_OK, "decode roundtrip");
      TEST_ASSERT (consumed == encoded_len, "consumed all");
      TEST_ASSERT (decoded.is_static == test_cases[i].is_static,
                   "is_static match");
      TEST_ASSERT (decoded.name_index == test_cases[i].name_index,
                   "name_index match");
      TEST_ASSERT (decoded.value_len == value_len, "value_len match");
      if (value_len > 0)
        TEST_ASSERT (memcmp (decoded.value, value, value_len) == 0,
                     "value match");
    }

  Arena_dispose (&arena);
  printf ("PASS\n");
}

static void
run_nameref_primitive_tests (void)
{
  printf (
      "Insert with Name Reference Primitive Tests (RFC 9204 Section 4.3.2):\n");
  test_encode_insert_nameref_basic ();
  test_encode_insert_nameref_dynamic ();
  test_encode_insert_nameref_with_huffman ();
  test_encode_insert_nameref_errors ();
  test_decode_insert_nameref_basic ();
  test_decode_insert_nameref_with_value ();
  test_decode_insert_nameref_huffman_value ();
  test_decode_insert_nameref_dynamic_ref ();
  test_decode_insert_nameref_errors ();
  test_validate_nameref_index_static ();
  test_validate_nameref_index_dynamic ();
  test_validate_nameref_index_edge_cases ();
  test_encode_decode_roundtrip ();
}

int
main (void)
{
  printf ("=== QPACK Encoder Stream Tests (RFC 9204 Section 4.2) ===\n\n");

  run_stream_type_tests ();
  printf ("\n");

  run_lifecycle_tests ();
  printf ("\n");

  run_capacity_tests ();
  printf ("\n");

  run_nameref_tests ();
  printf ("\n");

  run_literal_tests ();
  printf ("\n");

  run_duplicate_tests ();
  printf ("\n");

  run_buffer_tests ();
  printf ("\n");

  run_result_string_tests ();
  printf ("\n");

  run_security_tests ();
  printf ("\n");

  run_nameref_primitive_tests ();
  printf ("\n");

  printf ("=== All tests passed! ===\n");
  return 0;
}
