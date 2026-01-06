/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_decoder_stream.c
 * @brief Unit tests for QPACK Decoder Stream Infrastructure (RFC 9204
 * Section 4.2)
 *
 * Tests the decoder stream implementation including:
 * - Stream lifecycle (creation, initialization, state)
 * - Stream type and ID validation (Section 4.2)
 * - Decoder instructions (Section 4.4):
 *   - Section Acknowledgment (4.4.1)
 *   - Stream Cancellation (4.4.2)
 *   - Insert Count Increment (4.4.3)
 * - Buffer management
 * - Error handling and security
 */

#include "core/Arena.h"
#include "http/qpack/SocketQPACK.h"
#include "http/qpack/SocketQPACKDecoderStream.h"
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
 * Test decoder stream type validation.
 *
 * RFC 9204 Section 4.2: Decoder stream has type 0x03.
 */
static void
test_stream_type_validation (void)
{
  SocketQPACKStream_Result result;

  printf ("  Stream type validation... ");

  /* Valid decoder stream type (0x03) */
  result = SocketQPACK_DecoderStream_validate_type (QPACK_DECODER_STREAM_TYPE);
  TEST_ASSERT (result == QPACK_STREAM_OK, "type 0x03 should be valid");

  /* Invalid types */
  result = SocketQPACK_DecoderStream_validate_type (0x00);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_TYPE, "type 0x00 invalid");

  result = SocketQPACK_DecoderStream_validate_type (0x01);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_TYPE, "type 0x01 invalid");

  result = SocketQPACK_DecoderStream_validate_type (QPACK_ENCODER_STREAM_TYPE);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_TYPE,
               "type 0x02 (encoder) invalid for decoder");

  result = SocketQPACK_DecoderStream_validate_type (0xFF);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_TYPE, "type 0xFF invalid");

  printf ("PASS\n");
}

/* ============================================================================
 * STREAM LIFECYCLE TESTS
 * ============================================================================
 */

/**
 * Test decoder stream creation.
 */
static void
test_stream_creation (void)
{
  Arena_T arena;
  SocketQPACK_DecoderStream_T stream;

  printf ("  Stream creation... ");

  arena = Arena_new ();
  TEST_ASSERT (arena != NULL, "arena creation");

  /* Create stream with typical parameters */
  stream = SocketQPACK_DecoderStream_new (arena, 3);
  TEST_ASSERT (stream != NULL, "stream creation");

  /* Verify initial state */
  TEST_ASSERT (!SocketQPACK_DecoderStream_is_open (stream),
               "stream not initialized");
  TEST_ASSERT (SocketQPACK_DecoderStream_get_id (stream) == 3, "stream_id=3");
  TEST_ASSERT (SocketQPACK_DecoderStream_buffer_size (stream) == 0,
               "buffer empty");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test decoder stream creation with NULL arena.
 */
static void
test_stream_creation_null_arena (void)
{
  SocketQPACK_DecoderStream_T stream;

  printf ("  Stream creation NULL arena... ");

  stream = SocketQPACK_DecoderStream_new (NULL, 3);
  TEST_ASSERT (stream == NULL, "NULL arena should fail");

  printf ("PASS\n");
}

/**
 * Test decoder stream initialization.
 */
static void
test_stream_initialization (void)
{
  Arena_T arena;
  SocketQPACK_DecoderStream_T stream;
  SocketQPACKStream_Result result;

  printf ("  Stream initialization... ");

  arena = Arena_new ();
  stream = SocketQPACK_DecoderStream_new (arena, 3);
  TEST_ASSERT (stream != NULL, "stream creation");

  /* Not initialized yet */
  TEST_ASSERT (!SocketQPACK_DecoderStream_is_open (stream), "not open yet");

  /* Initialize */
  result = SocketQPACK_DecoderStream_init (stream);
  TEST_ASSERT (result == QPACK_STREAM_OK, "init should succeed");
  TEST_ASSERT (SocketQPACK_DecoderStream_is_open (stream), "now open");

  /* Double init should fail */
  result = SocketQPACK_DecoderStream_init (stream);
  TEST_ASSERT (result == QPACK_STREAM_ERR_ALREADY_INIT, "double init fails");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test decoder stream ID validation.
 */
static void
test_stream_id_validation (void)
{
  Arena_T arena;
  SocketQPACK_DecoderStream_T stream;
  SocketQPACKStream_Result result;

  printf ("  Stream ID validation... ");

  arena = Arena_new ();
  stream = SocketQPACK_DecoderStream_new (arena, 7);
  TEST_ASSERT (stream != NULL, "stream creation");

  /* Correct stream ID */
  result = SocketQPACK_DecoderStream_validate_id (stream, 7);
  TEST_ASSERT (result == QPACK_STREAM_OK, "matching ID should be valid");

  /* Wrong stream ID */
  result = SocketQPACK_DecoderStream_validate_id (stream, 3);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_TYPE,
               "non-matching ID invalid");

  result = SocketQPACK_DecoderStream_validate_id (stream, 0);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_TYPE, "ID 0 invalid");

  /* NULL stream */
  result = SocketQPACK_DecoderStream_validate_id (NULL, 7);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "NULL stream fails");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test decoder stream NULL parameter handling for lifecycle functions.
 */
static void
test_stream_lifecycle_null_params (void)
{
  SocketQPACKStream_Result result;
  size_t len;

  printf ("  Lifecycle NULL parameters... ");

  /* init with NULL */
  result = SocketQPACK_DecoderStream_init (NULL);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "init NULL fails");

  /* is_open with NULL */
  TEST_ASSERT (!SocketQPACK_DecoderStream_is_open (NULL), "is_open NULL=false");

  /* get_id with NULL */
  TEST_ASSERT (SocketQPACK_DecoderStream_get_id (NULL) == 0, "get_id NULL=0");

  /* buffer_size with NULL */
  TEST_ASSERT (SocketQPACK_DecoderStream_buffer_size (NULL) == 0,
               "buffer_size NULL=0");

  /* get_buffer with NULL */
  TEST_ASSERT (SocketQPACK_DecoderStream_get_buffer (NULL, &len) == NULL,
               "get_buffer NULL=NULL");
  TEST_ASSERT (len == 0, "get_buffer NULL len=0");

  /* reset_buffer with NULL */
  result = SocketQPACK_DecoderStream_reset_buffer (NULL);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "reset NULL fails");

  printf ("PASS\n");
}

/* ============================================================================
 * SECTION ACKNOWLEDGMENT TESTS (RFC 9204 Section 4.4.1)
 * ============================================================================
 */

/**
 * Test Section Acknowledgment instruction encoding.
 *
 * RFC 9204 Section 4.4.1: Bit pattern 1xxxxxxx with 7-bit prefix.
 */
static void
test_write_section_ack_basic (void)
{
  Arena_T arena;
  SocketQPACK_DecoderStream_T stream;
  SocketQPACKStream_Result result;
  const unsigned char *buf;
  size_t len;

  printf ("  Section acknowledgment basic... ");

  arena = Arena_new ();
  stream = SocketQPACK_DecoderStream_new (arena, 3);
  SocketQPACK_DecoderStream_init (stream);

  /* Acknowledge stream 0 */
  result = SocketQPACK_DecoderStream_write_section_ack (stream, 0);
  TEST_ASSERT (result == QPACK_STREAM_OK,
               "section_ack stream=0 should succeed");

  buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf != NULL, "buffer not NULL");
  TEST_ASSERT (len == 1, "single byte for stream_id=0");
  TEST_ASSERT (buf[0] == 0x80, "1 0000000 = 0x80 for stream_id=0");

  SocketQPACK_DecoderStream_reset_buffer (stream);

  /* Acknowledge stream 126 (fits in 7 bits: 126 < 127) */
  result = SocketQPACK_DecoderStream_write_section_ack (stream, 126);
  TEST_ASSERT (result == QPACK_STREAM_OK,
               "section_ack stream=126 should succeed");
  buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  TEST_ASSERT (len == 1, "single byte for stream_id=126");
  TEST_ASSERT (buf[0] == (0x80 | 126), "1 1111110 for stream_id=126");

  SocketQPACK_DecoderStream_reset_buffer (stream);

  /* Acknowledge stream 127 (needs continuation: 2^7 - 1 = 127) */
  result = SocketQPACK_DecoderStream_write_section_ack (stream, 127);
  TEST_ASSERT (result == QPACK_STREAM_OK,
               "section_ack stream=127 should succeed");
  buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  TEST_ASSERT (len == 2, "two bytes for stream_id=127");
  TEST_ASSERT (buf[0] == 0xFF, "1 1111111 prefix full");
  TEST_ASSERT (buf[1] == 0x00, "continuation 0");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test Section Acknowledgment with large stream IDs.
 */
static void
test_write_section_ack_large_id (void)
{
  Arena_T arena;
  SocketQPACK_DecoderStream_T stream;
  SocketQPACKStream_Result result;
  const unsigned char *buf;
  size_t len;

  printf ("  Section acknowledgment large IDs... ");

  arena = Arena_new ();
  stream = SocketQPACK_DecoderStream_new (arena, 3);
  SocketQPACK_DecoderStream_init (stream);

  /* Large stream ID that requires multiple continuation bytes */
  result = SocketQPACK_DecoderStream_write_section_ack (stream, 1000);
  TEST_ASSERT (result == QPACK_STREAM_OK,
               "section_ack stream=1000 should succeed");
  buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf != NULL && len >= 2, "multi-byte encoding");
  TEST_ASSERT ((buf[0] & 0x80) == 0x80, "high bit set for section ack");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test Section Acknowledgment on uninitialized stream.
 */
static void
test_write_section_ack_not_init (void)
{
  Arena_T arena;
  SocketQPACK_DecoderStream_T stream;
  SocketQPACKStream_Result result;

  printf ("  Section acknowledgment uninitialized... ");

  arena = Arena_new ();
  stream = SocketQPACK_DecoderStream_new (arena, 3);
  /* Don't init */

  result = SocketQPACK_DecoderStream_write_section_ack (stream, 0);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NOT_INIT, "uninitialized fails");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * STREAM CANCELLATION TESTS (RFC 9204 Section 4.4.2)
 * ============================================================================
 */

/**
 * Test Stream Cancellation instruction encoding.
 *
 * RFC 9204 Section 4.4.2: Bit pattern 01xxxxxx with 6-bit prefix.
 */
static void
test_write_stream_cancel_basic (void)
{
  Arena_T arena;
  SocketQPACK_DecoderStream_T stream;
  SocketQPACKStream_Result result;
  const unsigned char *buf;
  size_t len;

  printf ("  Stream cancellation basic... ");

  arena = Arena_new ();
  stream = SocketQPACK_DecoderStream_new (arena, 3);
  SocketQPACK_DecoderStream_init (stream);

  /* Cancel stream 0 */
  result = SocketQPACK_DecoderStream_write_stream_cancel (stream, 0);
  TEST_ASSERT (result == QPACK_STREAM_OK,
               "stream_cancel stream=0 should succeed");

  buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf != NULL, "buffer not NULL");
  TEST_ASSERT (len == 1, "single byte for stream_id=0");
  TEST_ASSERT (buf[0] == 0x40, "01 000000 = 0x40 for stream_id=0");

  SocketQPACK_DecoderStream_reset_buffer (stream);

  /* Cancel stream 62 (fits in 6 bits: 62 < 63) */
  result = SocketQPACK_DecoderStream_write_stream_cancel (stream, 62);
  TEST_ASSERT (result == QPACK_STREAM_OK,
               "stream_cancel stream=62 should succeed");
  buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  TEST_ASSERT (len == 1, "single byte for stream_id=62");
  TEST_ASSERT (buf[0] == (0x40 | 62), "01 111110 for stream_id=62");

  SocketQPACK_DecoderStream_reset_buffer (stream);

  /* Cancel stream 63 (needs continuation: 2^6 - 1 = 63) */
  result = SocketQPACK_DecoderStream_write_stream_cancel (stream, 63);
  TEST_ASSERT (result == QPACK_STREAM_OK,
               "stream_cancel stream=63 should succeed");
  buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  TEST_ASSERT (len == 2, "two bytes for stream_id=63");
  TEST_ASSERT (buf[0] == 0x7F, "01 111111 prefix full");
  TEST_ASSERT (buf[1] == 0x00, "continuation 0");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test Stream Cancellation on uninitialized stream.
 */
static void
test_write_stream_cancel_not_init (void)
{
  Arena_T arena;
  SocketQPACK_DecoderStream_T stream;
  SocketQPACKStream_Result result;

  printf ("  Stream cancellation uninitialized... ");

  arena = Arena_new ();
  stream = SocketQPACK_DecoderStream_new (arena, 3);
  /* Don't init */

  result = SocketQPACK_DecoderStream_write_stream_cancel (stream, 0);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NOT_INIT, "uninitialized fails");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/* ============================================================================
 * INSERT COUNT INCREMENT TESTS (RFC 9204 Section 4.4.3)
 * ============================================================================
 */

/**
 * Test Insert Count Increment instruction encoding.
 *
 * RFC 9204 Section 4.4.3: Bit pattern 00xxxxxx with 6-bit prefix.
 */
static void
test_write_insert_count_inc_basic (void)
{
  Arena_T arena;
  SocketQPACK_DecoderStream_T stream;
  SocketQPACKStream_Result result;
  const unsigned char *buf;
  size_t len;

  printf ("  Insert count increment basic... ");

  arena = Arena_new ();
  stream = SocketQPACK_DecoderStream_new (arena, 3);
  SocketQPACK_DecoderStream_init (stream);

  /* Increment by 1 */
  result = SocketQPACK_DecoderStream_write_insert_count_inc (stream, 1);
  TEST_ASSERT (result == QPACK_STREAM_OK, "insert_count_inc=1 should succeed");

  buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf != NULL, "buffer not NULL");
  TEST_ASSERT (len == 1, "single byte for increment=1");
  TEST_ASSERT (buf[0] == 0x01, "00 000001 = 0x01 for increment=1");

  SocketQPACK_DecoderStream_reset_buffer (stream);

  /* Increment by 62 (fits in 6 bits: 62 < 63) */
  result = SocketQPACK_DecoderStream_write_insert_count_inc (stream, 62);
  TEST_ASSERT (result == QPACK_STREAM_OK, "insert_count_inc=62 should succeed");
  buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  TEST_ASSERT (len == 1, "single byte for increment=62");
  TEST_ASSERT (buf[0] == 62, "00 111110 for increment=62");

  SocketQPACK_DecoderStream_reset_buffer (stream);

  /* Increment by 63 (needs continuation: 2^6 - 1 = 63) */
  result = SocketQPACK_DecoderStream_write_insert_count_inc (stream, 63);
  TEST_ASSERT (result == QPACK_STREAM_OK, "insert_count_inc=63 should succeed");
  buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  TEST_ASSERT (len == 2, "two bytes for increment=63");
  TEST_ASSERT (buf[0] == 0x3F, "00 111111 prefix full");
  TEST_ASSERT (buf[1] == 0x00, "continuation 0");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test Insert Count Increment with 0 (error case).
 *
 * RFC 9204 Section 4.4.3: increment of 0 is an error.
 */
static void
test_write_insert_count_inc_zero (void)
{
  Arena_T arena;
  SocketQPACK_DecoderStream_T stream;
  SocketQPACKStream_Result result;

  printf ("  Insert count increment zero (error)... ");

  arena = Arena_new ();
  stream = SocketQPACK_DecoderStream_new (arena, 3);
  SocketQPACK_DecoderStream_init (stream);

  /* Increment of 0 is an error per RFC 9204 Section 4.4.3 */
  result = SocketQPACK_DecoderStream_write_insert_count_inc (stream, 0);
  TEST_ASSERT (result == QPACK_STREAM_ERR_INVALID_INDEX,
               "increment=0 should fail");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test Insert Count Increment on uninitialized stream.
 */
static void
test_write_insert_count_inc_not_init (void)
{
  Arena_T arena;
  SocketQPACK_DecoderStream_T stream;
  SocketQPACKStream_Result result;

  printf ("  Insert count increment uninitialized... ");

  arena = Arena_new ();
  stream = SocketQPACK_DecoderStream_new (arena, 3);
  /* Don't init */

  result = SocketQPACK_DecoderStream_write_insert_count_inc (stream, 5);
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
  SocketQPACK_DecoderStream_T stream;
  const unsigned char *buf;
  size_t len;

  printf ("  Buffer management... ");

  arena = Arena_new ();
  stream = SocketQPACK_DecoderStream_new (arena, 3);
  SocketQPACK_DecoderStream_init (stream);

  /* Empty buffer */
  TEST_ASSERT (SocketQPACK_DecoderStream_buffer_size (stream) == 0,
               "initially empty");
  buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf == NULL && len == 0, "empty returns NULL");

  /* Write something */
  SocketQPACK_DecoderStream_write_section_ack (stream, 5);
  TEST_ASSERT (SocketQPACK_DecoderStream_buffer_size (stream) > 0, "has data");

  buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  TEST_ASSERT (buf != NULL && len > 0, "get_buffer returns data");
  TEST_ASSERT (len == SocketQPACK_DecoderStream_buffer_size (stream),
               "len matches size");

  /* Reset */
  SocketQPACK_DecoderStream_reset_buffer (stream);
  TEST_ASSERT (SocketQPACK_DecoderStream_buffer_size (stream) == 0,
               "reset clears");
  buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
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
  SocketQPACK_DecoderStream_T stream;
  size_t len1, len2, len3;

  printf ("  Buffer accumulation... ");

  arena = Arena_new ();
  stream = SocketQPACK_DecoderStream_new (arena, 3);
  SocketQPACK_DecoderStream_init (stream);

  /* Write multiple instructions */
  SocketQPACK_DecoderStream_write_section_ack (stream, 4);
  len1 = SocketQPACK_DecoderStream_buffer_size (stream);
  TEST_ASSERT (len1 > 0, "first instruction written");

  SocketQPACK_DecoderStream_write_stream_cancel (stream, 8);
  len2 = SocketQPACK_DecoderStream_buffer_size (stream);
  TEST_ASSERT (len2 > len1, "second instruction accumulated");

  SocketQPACK_DecoderStream_write_insert_count_inc (stream, 10);
  len3 = SocketQPACK_DecoderStream_buffer_size (stream);
  TEST_ASSERT (len3 > len2, "third instruction accumulated");

  /* All instructions in one buffer */
  const unsigned char *buf;
  size_t total_len;
  buf = SocketQPACK_DecoderStream_get_buffer (stream, &total_len);
  TEST_ASSERT (buf != NULL, "buffer not NULL");
  TEST_ASSERT (total_len == len3, "total matches");

  Arena_dispose (&arena);
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
  result = SocketQPACK_DecoderStream_write_section_ack (NULL, 0);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM, "section_ack NULL fails");

  result = SocketQPACK_DecoderStream_write_stream_cancel (NULL, 0);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM,
               "stream_cancel NULL fails");

  result = SocketQPACK_DecoderStream_write_insert_count_inc (NULL, 1);
  TEST_ASSERT (result == QPACK_STREAM_ERR_NULL_PARAM,
               "insert_count_inc NULL fails");

  printf ("PASS\n");
}

/**
 * Test large values that could cause overflow.
 */
static void
test_large_values (void)
{
  Arena_T arena;
  SocketQPACK_DecoderStream_T stream;
  SocketQPACKStream_Result result;

  printf ("  Large values... ");

  arena = Arena_new ();
  stream = SocketQPACK_DecoderStream_new (arena, 3);
  SocketQPACK_DecoderStream_init (stream);

  /* Large stream ID (should encode correctly with HPACK integer) */
  result = SocketQPACK_DecoderStream_write_section_ack (stream, (1ULL << 40));
  TEST_ASSERT (result == QPACK_STREAM_OK, "large section_ack succeeds");

  SocketQPACK_DecoderStream_reset_buffer (stream);

  /* Large stream ID for cancellation */
  result = SocketQPACK_DecoderStream_write_stream_cancel (stream, (1ULL << 40));
  TEST_ASSERT (result == QPACK_STREAM_OK, "large stream_cancel succeeds");

  SocketQPACK_DecoderStream_reset_buffer (stream);

  /* Large increment */
  result
      = SocketQPACK_DecoderStream_write_insert_count_inc (stream, (1ULL << 40));
  TEST_ASSERT (result == QPACK_STREAM_OK, "large insert_count_inc succeeds");

  Arena_dispose (&arena);
  printf ("PASS\n");
}

/**
 * Test instruction bit patterns are distinct.
 */
static void
test_instruction_bit_patterns (void)
{
  Arena_T arena;
  SocketQPACK_DecoderStream_T stream;
  const unsigned char *buf;
  size_t len;

  printf ("  Instruction bit patterns... ");

  arena = Arena_new ();
  stream = SocketQPACK_DecoderStream_new (arena, 3);
  SocketQPACK_DecoderStream_init (stream);

  /* Section Ack: 1xxxxxxx */
  SocketQPACK_DecoderStream_write_section_ack (stream, 0);
  buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  TEST_ASSERT ((buf[0] & 0x80) == 0x80, "section_ack has bit 7 set");
  SocketQPACK_DecoderStream_reset_buffer (stream);

  /* Stream Cancel: 01xxxxxx */
  SocketQPACK_DecoderStream_write_stream_cancel (stream, 0);
  buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  TEST_ASSERT ((buf[0] & 0xC0) == 0x40, "stream_cancel has bits 7-6 = 01");
  SocketQPACK_DecoderStream_reset_buffer (stream);

  /* Insert Count Inc: 00xxxxxx */
  SocketQPACK_DecoderStream_write_insert_count_inc (stream, 1);
  buf = SocketQPACK_DecoderStream_get_buffer (stream, &len);
  TEST_ASSERT ((buf[0] & 0xC0) == 0x00, "insert_count_inc has bits 7-6 = 00");

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
  test_stream_id_validation ();
  test_stream_lifecycle_null_params ();
}

static void
run_section_ack_tests (void)
{
  printf ("Section Acknowledgment Tests (RFC 9204 Section 4.4.1):\n");
  test_write_section_ack_basic ();
  test_write_section_ack_large_id ();
  test_write_section_ack_not_init ();
}

static void
run_stream_cancel_tests (void)
{
  printf ("Stream Cancellation Tests (RFC 9204 Section 4.4.2):\n");
  test_write_stream_cancel_basic ();
  test_write_stream_cancel_not_init ();
}

static void
run_insert_count_inc_tests (void)
{
  printf ("Insert Count Increment Tests (RFC 9204 Section 4.4.3):\n");
  test_write_insert_count_inc_basic ();
  test_write_insert_count_inc_zero ();
  test_write_insert_count_inc_not_init ();
}

static void
run_buffer_tests (void)
{
  printf ("Buffer Management Tests:\n");
  test_buffer_management ();
  test_buffer_accumulation ();
}

static void
run_security_tests (void)
{
  printf ("Security Tests:\n");
  test_instruction_null_params ();
  test_large_values ();
  test_instruction_bit_patterns ();
}

int
main (void)
{
  printf ("=== QPACK Decoder Stream Tests (RFC 9204 Section 4.2) ===\n\n");

  run_stream_type_tests ();
  printf ("\n");

  run_lifecycle_tests ();
  printf ("\n");

  run_section_ack_tests ();
  printf ("\n");

  run_stream_cancel_tests ();
  printf ("\n");

  run_insert_count_inc_tests ();
  printf ("\n");

  run_buffer_tests ();
  printf ("\n");

  run_security_tests ();
  printf ("\n");

  printf ("=== All tests passed! ===\n");
  return 0;
}
