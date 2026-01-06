/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_decoder_stream.c
 * @brief Unit tests for QPACK Decoder Stream (RFC 9204 Section 4.2).
 *
 * Tests the decoder stream infrastructure including:
 *   - Stream lifecycle (create, open, close, reset)
 *   - Section Acknowledgment encoding
 *   - Stream Cancellation encoding
 *   - Insert Count Increment encoding
 *   - Buffer management
 *   - Error handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACKDecoderStream.h"

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
 * Lifecycle Tests
 * ============================================================================
 */

/**
 * Test stream creation.
 */
static void
test_new (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;

  printf ("  Decoder stream new... ");

  arena = Arena_new ();
  TEST_ASSERT (arena != NULL, "Arena should be created");

  stream = SocketQPACKDecoderStream_new (arena, 0);
  TEST_ASSERT (stream != NULL, "Stream should be created");
  TEST_ASSERT (SocketQPACKDecoderStream_get_state (stream)
                   == QPACK_DECODER_STREAM_STATE_IDLE,
               "Initial state should be IDLE");
  TEST_ASSERT (SocketQPACKDecoderStream_get_stream_id (stream) == 0,
               "Stream ID should be 0 when not open");
  TEST_ASSERT (SocketQPACKDecoderStream_is_open (stream) == 0,
               "Stream should not be open");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test stream creation with NULL arena.
 */
static void
test_new_null_arena (void)
{
  SocketQPACKDecoderStream_T stream;

  printf ("  Decoder stream new with NULL arena... ");

  stream = SocketQPACKDecoderStream_new (NULL, 0);
  TEST_ASSERT (stream == NULL, "Stream should be NULL with NULL arena");

  printf ("PASS\n");
}

/**
 * Test stream open.
 */
static void
test_open (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;

  printf ("  Decoder stream open... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);
  TEST_ASSERT (stream != NULL, "Stream should be created");

  /* Open with a unidirectional stream ID */
  result = SocketQPACKDecoderStream_open (stream, 0x02);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK, "Open should succeed");
  TEST_ASSERT (SocketQPACKDecoderStream_get_state (stream)
                   == QPACK_DECODER_STREAM_STATE_OPEN,
               "State should be OPEN");
  TEST_ASSERT (SocketQPACKDecoderStream_get_stream_id (stream) == 0x02,
               "Stream ID should be set");
  TEST_ASSERT (SocketQPACKDecoderStream_is_open (stream) == 1,
               "Stream should be open");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test duplicate stream open fails.
 */
static void
test_open_duplicate (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;

  printf ("  Decoder stream duplicate open fails... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);

  result = SocketQPACKDecoderStream_open (stream, 0x02);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK, "First open should succeed");

  result = SocketQPACKDecoderStream_open (stream, 0x06);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_ERROR_DUPLICATE,
               "Second open should fail with DUPLICATE");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test stream close.
 */
static void
test_close (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;

  printf ("  Decoder stream close... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);

  result = SocketQPACKDecoderStream_open (stream, 0x02);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK, "Open should succeed");

  result = SocketQPACKDecoderStream_close (stream);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK, "Close should succeed");
  TEST_ASSERT (SocketQPACKDecoderStream_get_state (stream)
                   == QPACK_DECODER_STREAM_STATE_CLOSED,
               "State should be CLOSED");
  TEST_ASSERT (SocketQPACKDecoderStream_is_open (stream) == 0,
               "Stream should not be open");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test open after close fails.
 */
static void
test_open_after_close (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;

  printf ("  Decoder stream open after close fails... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);

  SocketQPACKDecoderStream_open (stream, 0x02);
  SocketQPACKDecoderStream_close (stream);

  result = SocketQPACKDecoderStream_open (stream, 0x06);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_ERROR_CLOSED,
               "Open after close should fail with CLOSED");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test stream reset.
 */
static void
test_reset (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;

  printf ("  Decoder stream reset... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);

  SocketQPACKDecoderStream_open (stream, 0x02);

  result = SocketQPACKDecoderStream_reset (stream);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK, "Reset should succeed");
  TEST_ASSERT (SocketQPACKDecoderStream_get_state (stream)
                   == QPACK_DECODER_STREAM_STATE_IDLE,
               "State should be IDLE after reset");
  TEST_ASSERT (SocketQPACKDecoderStream_get_stream_id (stream) == 0,
               "Stream ID should be 0 after reset");

  /* Can open again after reset */
  result = SocketQPACKDecoderStream_open (stream, 0x06);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK,
               "Open after reset should succeed");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Instruction Encoding Tests
 * ============================================================================
 */

/**
 * Test Section Acknowledgment encoding with small stream ID.
 */
static void
test_section_ack_small_id (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;
  const unsigned char *data;
  size_t len;

  printf ("  Section Acknowledgment small ID... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);
  SocketQPACKDecoderStream_open (stream, 0x02);

  /* Acknowledge stream ID 4 (fits in 7-bit prefix) */
  result = SocketQPACKDecoderStream_write_section_ack (stream, 4);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK, "Write should succeed");

  data = SocketQPACKDecoderStream_get_pending (stream, &len);
  TEST_ASSERT (data != NULL, "Should have pending data");
  TEST_ASSERT (len == 1, "Should be 1 byte");
  TEST_ASSERT (data[0] == 0x84, "Should be 0x84 (0x80 | 4)");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test Section Acknowledgment encoding with medium stream ID.
 */
static void
test_section_ack_medium_id (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;
  const unsigned char *data;
  size_t len;

  printf ("  Section Acknowledgment medium ID... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);
  SocketQPACKDecoderStream_open (stream, 0x02);

  /* Acknowledge stream ID 200 (requires continuation) */
  /* 200 = 127 + 73, encoded as: 0xFF, 0x49 */
  result = SocketQPACKDecoderStream_write_section_ack (stream, 200);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK, "Write should succeed");

  data = SocketQPACKDecoderStream_get_pending (stream, &len);
  TEST_ASSERT (data != NULL, "Should have pending data");
  TEST_ASSERT (len == 2, "Should be 2 bytes");
  TEST_ASSERT (data[0] == 0xFF, "First byte should be 0xFF");
  TEST_ASSERT (data[1] == 0x49, "Second byte should be 0x49");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test Section Acknowledgment encoding with large stream ID.
 */
static void
test_section_ack_large_id (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;
  const unsigned char *data;
  size_t len;

  printf ("  Section Acknowledgment large ID... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);
  SocketQPACKDecoderStream_open (stream, 0x02);

  /* Acknowledge stream ID 20000 */
  result = SocketQPACKDecoderStream_write_section_ack (stream, 20000);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK, "Write should succeed");

  data = SocketQPACKDecoderStream_get_pending (stream, &len);
  TEST_ASSERT (data != NULL, "Should have pending data");
  TEST_ASSERT (len >= 3, "Should be at least 3 bytes");
  TEST_ASSERT ((data[0] & 0x80) == 0x80, "First byte should have 0x80 pattern");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test Stream Cancellation encoding with small stream ID.
 */
static void
test_stream_cancel_small_id (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;
  const unsigned char *data;
  size_t len;

  printf ("  Stream Cancellation small ID... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);
  SocketQPACKDecoderStream_open (stream, 0x02);

  /* Cancel stream ID 8 (fits in 6-bit prefix) */
  result = SocketQPACKDecoderStream_write_stream_cancel (stream, 8);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK, "Write should succeed");

  data = SocketQPACKDecoderStream_get_pending (stream, &len);
  TEST_ASSERT (data != NULL, "Should have pending data");
  TEST_ASSERT (len == 1, "Should be 1 byte");
  TEST_ASSERT (data[0] == 0x48, "Should be 0x48 (0x40 | 8)");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test Stream Cancellation encoding with medium stream ID.
 */
static void
test_stream_cancel_medium_id (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;
  const unsigned char *data;
  size_t len;

  printf ("  Stream Cancellation medium ID... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);
  SocketQPACKDecoderStream_open (stream, 0x02);

  /* Cancel stream ID 100 (requires continuation) */
  /* 100 = 63 + 37, encoded as: 0x7F, 0x25 */
  result = SocketQPACKDecoderStream_write_stream_cancel (stream, 100);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK, "Write should succeed");

  data = SocketQPACKDecoderStream_get_pending (stream, &len);
  TEST_ASSERT (data != NULL, "Should have pending data");
  TEST_ASSERT (len == 2, "Should be 2 bytes");
  TEST_ASSERT (data[0] == 0x7F, "First byte should be 0x7F");
  TEST_ASSERT (data[1] == 0x25, "Second byte should be 0x25");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test Insert Count Increment encoding with small value.
 */
static void
test_insert_count_inc_small (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;
  const unsigned char *data;
  size_t len;

  printf ("  Insert Count Increment small... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);
  SocketQPACKDecoderStream_open (stream, 0x02);

  /* Increment by 5 (fits in 6-bit prefix) */
  result = SocketQPACKDecoderStream_write_insert_count_inc (stream, 5);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK, "Write should succeed");

  data = SocketQPACKDecoderStream_get_pending (stream, &len);
  TEST_ASSERT (data != NULL, "Should have pending data");
  TEST_ASSERT (len == 1, "Should be 1 byte");
  TEST_ASSERT (data[0] == 0x05, "Should be 0x05 (0x00 | 5)");

  /* Verify known received count updated */
  TEST_ASSERT (SocketQPACKDecoderStream_get_known_received_count (stream) == 5,
               "Known received count should be 5");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test Insert Count Increment encoding with medium value.
 */
static void
test_insert_count_inc_medium (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;
  const unsigned char *data;
  size_t len;

  printf ("  Insert Count Increment medium... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);
  SocketQPACKDecoderStream_open (stream, 0x02);

  /* Increment by 100 (requires continuation) */
  /* 100 = 63 + 37, encoded as: 0x3F, 0x25 */
  result = SocketQPACKDecoderStream_write_insert_count_inc (stream, 100);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK, "Write should succeed");

  data = SocketQPACKDecoderStream_get_pending (stream, &len);
  TEST_ASSERT (data != NULL, "Should have pending data");
  TEST_ASSERT (len == 2, "Should be 2 bytes");
  TEST_ASSERT (data[0] == 0x3F, "First byte should be 0x3F");
  TEST_ASSERT (data[1] == 0x25, "Second byte should be 0x25");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test Insert Count Increment with zero is no-op.
 */
static void
test_insert_count_inc_zero (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;
  size_t len;

  printf ("  Insert Count Increment zero is no-op... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);
  SocketQPACKDecoderStream_open (stream, 0x02);

  result = SocketQPACKDecoderStream_write_insert_count_inc (stream, 0);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK, "Write should succeed");

  (void)SocketQPACKDecoderStream_get_pending (stream, &len);
  TEST_ASSERT (len == 0, "Should have no pending data");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Buffer Management Tests
 * ============================================================================
 */

/**
 * Test multiple instructions batched in buffer.
 */
static void
test_multiple_instructions (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  const unsigned char *data;
  size_t len;

  printf ("  Multiple instructions batched... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);
  SocketQPACKDecoderStream_open (stream, 0x02);

  /* Write multiple instructions */
  SocketQPACKDecoderStream_write_section_ack (stream, 4);      /* 1 byte */
  SocketQPACKDecoderStream_write_stream_cancel (stream, 8);    /* 1 byte */
  SocketQPACKDecoderStream_write_insert_count_inc (stream, 3); /* 1 byte */

  data = SocketQPACKDecoderStream_get_pending (stream, &len);
  TEST_ASSERT (data != NULL, "Should have pending data");
  TEST_ASSERT (len == 3, "Should be 3 bytes total");
  TEST_ASSERT (data[0] == 0x84, "First instruction: 0x84");
  TEST_ASSERT (data[1] == 0x48, "Second instruction: 0x48");
  TEST_ASSERT (data[2] == 0x03, "Third instruction: 0x03");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test mark_sent removes data from buffer.
 */
static void
test_mark_sent (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;
  const unsigned char *data;
  size_t len;

  printf ("  Mark sent removes data... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);
  SocketQPACKDecoderStream_open (stream, 0x02);

  /* Write two instructions */
  SocketQPACKDecoderStream_write_section_ack (stream, 4);   /* 1 byte */
  SocketQPACKDecoderStream_write_stream_cancel (stream, 8); /* 1 byte */

  /* Mark first instruction as sent */
  result = SocketQPACKDecoderStream_mark_sent (stream, 1);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK, "Mark sent should succeed");

  data = SocketQPACKDecoderStream_get_pending (stream, &len);
  TEST_ASSERT (data != NULL, "Should have pending data");
  TEST_ASSERT (len == 1, "Should be 1 byte remaining");
  TEST_ASSERT (data[0] == 0x48, "Remaining instruction: 0x48");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test clear_buffer discards all pending.
 */
static void
test_clear_buffer (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;
  size_t len;

  printf ("  Clear buffer discards pending... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);
  SocketQPACKDecoderStream_open (stream, 0x02);

  /* Write instructions */
  SocketQPACKDecoderStream_write_section_ack (stream, 4);
  SocketQPACKDecoderStream_write_stream_cancel (stream, 8);

  result = SocketQPACKDecoderStream_clear_buffer (stream);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK, "Clear should succeed");

  (void)SocketQPACKDecoderStream_get_pending (stream, &len);
  TEST_ASSERT (len == 0, "Should have no pending data");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test buffer overflow protection.
 */
static void
test_buffer_overflow (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;

  printf ("  Buffer overflow protection... ");

  arena = Arena_new ();
  /* Create stream with tiny buffer (1 byte) */
  stream = SocketQPACKDecoderStream_new (arena, 1);
  SocketQPACKDecoderStream_open (stream, 0x02);

  /* First small instruction should succeed (1 byte: 0x81) */
  result = SocketQPACKDecoderStream_write_section_ack (stream, 1);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_OK, "First write should succeed");

  /* Second instruction should fail due to buffer full */
  result = SocketQPACKDecoderStream_write_section_ack (stream, 2);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_ERROR_BUFFER_FULL,
               "Second write should fail with BUFFER_FULL");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test buffer_available returns correct space.
 */
static void
test_buffer_available (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  size_t avail;

  printf ("  Buffer available returns correct space... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 100);
  SocketQPACKDecoderStream_open (stream, 0x02);

  avail = SocketQPACKDecoderStream_buffer_available (stream);
  TEST_ASSERT (avail == 100, "Initial available should be 100");

  /* Write 1-byte instruction */
  SocketQPACKDecoderStream_write_section_ack (stream, 1);

  avail = SocketQPACKDecoderStream_buffer_available (stream);
  TEST_ASSERT (avail == 99, "Available should be 99 after write");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Error Handling Tests
 * ============================================================================
 */

/**
 * Test operations on closed stream fail.
 */
static void
test_write_on_closed_stream (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;

  printf ("  Write on closed stream fails... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);
  SocketQPACKDecoderStream_open (stream, 0x02);
  SocketQPACKDecoderStream_close (stream);

  result = SocketQPACKDecoderStream_write_section_ack (stream, 4);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_ERROR_INVALID_STATE,
               "Write should fail with INVALID_STATE");

  result = SocketQPACKDecoderStream_write_stream_cancel (stream, 8);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_ERROR_INVALID_STATE,
               "Write should fail with INVALID_STATE");

  result = SocketQPACKDecoderStream_write_insert_count_inc (stream, 5);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_ERROR_INVALID_STATE,
               "Write should fail with INVALID_STATE");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test operations on idle stream fail.
 */
static void
test_write_on_idle_stream (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;
  SocketQPACKDecoderStream_Result result;

  printf ("  Write on idle stream fails... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);
  /* Not opened */

  result = SocketQPACKDecoderStream_write_section_ack (stream, 4);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_ERROR_INVALID_STATE,
               "Write should fail with INVALID_STATE");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test NULL pointer handling.
 */
static void
test_null_handling (void)
{
  SocketQPACKDecoderStream_Result result;
  size_t len;

  printf ("  NULL pointer handling... ");

  result = SocketQPACKDecoderStream_open (NULL, 0x02);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_ERROR_NULL,
               "Open with NULL should fail");

  result = SocketQPACKDecoderStream_close (NULL);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_ERROR_NULL,
               "Close with NULL should fail");

  result = SocketQPACKDecoderStream_reset (NULL);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_ERROR_NULL,
               "Reset with NULL should fail");

  result = SocketQPACKDecoderStream_write_section_ack (NULL, 4);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_ERROR_NULL,
               "Write with NULL should fail");

  TEST_ASSERT (SocketQPACKDecoderStream_get_pending (NULL, &len) == NULL,
               "Get pending with NULL stream should return NULL");
  TEST_ASSERT (len == 0, "Length should be 0 on NULL");

  TEST_ASSERT (SocketQPACKDecoderStream_get_state (NULL)
                   == QPACK_DECODER_STREAM_STATE_IDLE,
               "Get state with NULL should return IDLE");

  TEST_ASSERT (SocketQPACKDecoderStream_is_open (NULL) == 0,
               "Is open with NULL should return 0");

  TEST_ASSERT (SocketQPACKDecoderStream_buffer_available (NULL) == 0,
               "Buffer available with NULL should return 0");

  printf ("PASS\n");
}

/* ============================================================================
 * Validation Tests
 * ============================================================================
 */

/**
 * Test stream type validation.
 */
static void
test_validate_stream_type (void)
{
  printf ("  Validate stream type... ");

  /* Client-initiated unidirectional: 0x2, 0x6, 0xA, ... */
  TEST_ASSERT (SocketQPACKDecoderStream_validate_stream_type (0x02) == 1,
               "0x02 should be valid");
  TEST_ASSERT (SocketQPACKDecoderStream_validate_stream_type (0x06) == 1,
               "0x06 should be valid");
  TEST_ASSERT (SocketQPACKDecoderStream_validate_stream_type (0x0A) == 1,
               "0x0A should be valid");

  /* Server-initiated unidirectional: 0x3, 0x7, 0xB, ... */
  TEST_ASSERT (SocketQPACKDecoderStream_validate_stream_type (0x03) == 1,
               "0x03 should be valid");
  TEST_ASSERT (SocketQPACKDecoderStream_validate_stream_type (0x07) == 1,
               "0x07 should be valid");

  /* Bidirectional streams are invalid for decoder stream */
  TEST_ASSERT (SocketQPACKDecoderStream_validate_stream_type (0x00) == 0,
               "0x00 should be invalid");
  TEST_ASSERT (SocketQPACKDecoderStream_validate_stream_type (0x01) == 0,
               "0x01 should be invalid");
  TEST_ASSERT (SocketQPACKDecoderStream_validate_stream_type (0x04) == 0,
               "0x04 should be invalid");
  TEST_ASSERT (SocketQPACKDecoderStream_validate_stream_type (0x05) == 0,
               "0x05 should be invalid");

  printf ("PASS\n");
}

/* ============================================================================
 * Utility Function Tests
 * ============================================================================
 */

/**
 * Test state string conversion.
 */
static void
test_state_string (void)
{
  printf ("  State string conversion... ");

  TEST_ASSERT (strcmp (SocketQPACKDecoderStream_state_string (
                           QPACK_DECODER_STREAM_STATE_IDLE),
                       "IDLE")
                   == 0,
               "IDLE string");
  TEST_ASSERT (strcmp (SocketQPACKDecoderStream_state_string (
                           QPACK_DECODER_STREAM_STATE_OPEN),
                       "OPEN")
                   == 0,
               "OPEN string");
  TEST_ASSERT (strcmp (SocketQPACKDecoderStream_state_string (
                           QPACK_DECODER_STREAM_STATE_CLOSED),
                       "CLOSED")
                   == 0,
               "CLOSED string");
  TEST_ASSERT (strcmp (SocketQPACKDecoderStream_state_string (
                           (SocketQPACKDecoderStreamState)99),
                       "UNKNOWN")
                   == 0,
               "Unknown state string");

  printf ("PASS\n");
}

/**
 * Test result string conversion.
 */
static void
test_result_string (void)
{
  printf ("  Result string conversion... ");

  TEST_ASSERT (
      strcmp (SocketQPACKDecoderStream_result_string (QPACK_DECODER_STREAM_OK),
              "OK")
          == 0,
      "OK string");
  TEST_ASSERT (strcmp (SocketQPACKDecoderStream_result_string (
                           QPACK_DECODER_STREAM_ERROR_NULL),
                       "ERROR_NULL")
                   == 0,
               "ERROR_NULL string");
  TEST_ASSERT (strcmp (SocketQPACKDecoderStream_result_string (
                           QPACK_DECODER_STREAM_ERROR_BUFFER_FULL),
                       "ERROR_BUFFER_FULL")
                   == 0,
               "ERROR_BUFFER_FULL string");
  TEST_ASSERT (strcmp (SocketQPACKDecoderStream_result_string (
                           (SocketQPACKDecoderStream_Result)99),
                       "UNKNOWN")
                   == 0,
               "Unknown result string");

  printf ("PASS\n");
}

/* ============================================================================
 * State Transition Tests
 * ============================================================================
 */

/**
 * Test proper state transitions through lifecycle.
 */
static void
test_state_transitions (void)
{
  Arena_T arena;
  SocketQPACKDecoderStream_T stream;

  printf ("  State transitions... ");

  arena = Arena_new ();
  stream = SocketQPACKDecoderStream_new (arena, 0);

  /* IDLE -> OPEN */
  TEST_ASSERT (SocketQPACKDecoderStream_get_state (stream)
                   == QPACK_DECODER_STREAM_STATE_IDLE,
               "Should start IDLE");

  SocketQPACKDecoderStream_open (stream, 0x02);
  TEST_ASSERT (SocketQPACKDecoderStream_get_state (stream)
                   == QPACK_DECODER_STREAM_STATE_OPEN,
               "Should be OPEN after open");

  /* OPEN -> CLOSED */
  SocketQPACKDecoderStream_close (stream);
  TEST_ASSERT (SocketQPACKDecoderStream_get_state (stream)
                   == QPACK_DECODER_STREAM_STATE_CLOSED,
               "Should be CLOSED after close");

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
  printf ("QPACK Decoder Stream Unit Tests\n");
  printf ("================================\n\n");

  printf ("Lifecycle Tests:\n");
  test_new ();
  test_new_null_arena ();
  test_open ();
  test_open_duplicate ();
  test_close ();
  test_open_after_close ();
  test_reset ();

  printf ("\nInstruction Encoding Tests:\n");
  test_section_ack_small_id ();
  test_section_ack_medium_id ();
  test_section_ack_large_id ();
  test_stream_cancel_small_id ();
  test_stream_cancel_medium_id ();
  test_insert_count_inc_small ();
  test_insert_count_inc_medium ();
  test_insert_count_inc_zero ();

  printf ("\nBuffer Management Tests:\n");
  test_multiple_instructions ();
  test_mark_sent ();
  test_clear_buffer ();
  test_buffer_overflow ();
  test_buffer_available ();

  printf ("\nError Handling Tests:\n");
  test_write_on_closed_stream ();
  test_write_on_idle_stream ();
  test_null_handling ();

  printf ("\nValidation Tests:\n");
  test_validate_stream_type ();

  printf ("\nUtility Function Tests:\n");
  test_state_string ();
  test_result_string ();

  printf ("\nState Transition Tests:\n");
  test_state_transitions ();

  printf ("\n================================\n");
  printf ("All QPACK Decoder Stream tests passed!\n");

  return 0;
}
