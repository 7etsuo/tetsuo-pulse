/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_decoder_sync.c
 * @brief Unit tests for QPACK Decoder State Synchronization (RFC 9204 Section
 * 2.2.2)
 *
 * Tests the automatic generation of decoder instructions:
 * - Section Acknowledgment (2.2.2.1)
 * - Stream Cancellation (2.2.2.2)
 * - Insert Count Increment (2.2.2.3)
 */

#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACKDecoderStream.h"
#include "test/Test.h"

static SocketQPACK_DecoderSync_T
create_sync_state (Arena_T arena, SocketQPACK_DecoderStream_T *out_stream)
{
  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 100);
  if (stream == NULL)
    return NULL;

  if (SocketQPACK_DecoderStream_init (stream) != QPACK_STREAM_OK)
    return NULL;

  *out_stream = stream;
  return SocketQPACK_DecoderSync_new (arena, stream);
}

TEST (qpack_decoder_sync_new_basic)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;

  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  ASSERT_EQ (SocketQPACK_DecoderSync_get_insert_count (sync), 0);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_acknowledged_count (sync), 0);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_coalesce_threshold (sync), 1);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_new_null_arena)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 100);
  ASSERT_NOT_NULL (stream);
  ASSERT_EQ (SocketQPACK_DecoderStream_init (stream), QPACK_STREAM_OK);

  SocketQPACK_DecoderSync_T sync = SocketQPACK_DecoderSync_new (NULL, stream);
  ASSERT_NULL (sync);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_new_null_stream)
{
  Arena_T arena = Arena_new ();

  SocketQPACK_DecoderSync_T sync = SocketQPACK_DecoderSync_new (arena, NULL);
  ASSERT_NULL (sync);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_section_decoded_ric_nonzero)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Decode a section with RIC > 0 should emit Section Ack */
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderSync_on_section_decoded (sync, 42, 5);
  ASSERT_EQ (result, QPACK_STREAM_OK);

  /* Verify buffer contains Section Ack instruction */
  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  ASSERT_NOT_NULL (buf);
  ASSERT (buf_len > 0);

  /* Decode and verify it's a Section Ack for stream 42 */
  uint64_t decoded_stream_id = 0;
  size_t consumed = 0;
  result = SocketQPACK_decode_section_ack (
      buf, buf_len, &decoded_stream_id, &consumed);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (decoded_stream_id, 42);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_section_decoded_ric_zero)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Decode a section with RIC = 0 should NOT emit Section Ack */
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderSync_on_section_decoded (sync, 42, 0);
  ASSERT_EQ (result, QPACK_STREAM_OK);

  /* Buffer should be empty */
  ASSERT_EQ (SocketQPACK_DecoderStream_buffer_size (stream), 0);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_section_decoded_multiple)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Decode multiple sections */
  ASSERT_EQ (SocketQPACK_DecoderSync_on_section_decoded (sync, 10, 3),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderSync_on_section_decoded (sync, 20, 5),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderSync_on_section_decoded (sync, 30, 0),
             QPACK_STREAM_OK); /* No ack for RIC=0 */

  /* Get buffer and decode all instructions */
  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  ASSERT_NOT_NULL (buf);

  /* Should have exactly 2 Section Acks */
  size_t offset = 0;
  uint64_t stream_id;
  size_t consumed;

  /* First: stream 10 */
  ASSERT_EQ (SocketQPACK_decode_section_ack (
                 buf + offset, buf_len - offset, &stream_id, &consumed),
             QPACK_STREAM_OK);
  ASSERT_EQ (stream_id, 10);
  offset += consumed;

  /* Second: stream 20 */
  ASSERT_EQ (SocketQPACK_decode_section_ack (
                 buf + offset, buf_len - offset, &stream_id, &consumed),
             QPACK_STREAM_OK);
  ASSERT_EQ (stream_id, 20);
  offset += consumed;

  /* Should have consumed all bytes */
  ASSERT_EQ (offset, buf_len);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_section_decoded_null)
{
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderSync_on_section_decoded (NULL, 42, 5);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NULL_PARAM);
}

TEST (qpack_decoder_sync_stream_reset_basic)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Reset a stream should emit Stream Cancel */
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderSync_on_stream_reset (sync, 55);
  ASSERT_EQ (result, QPACK_STREAM_OK);

  /* Verify buffer contains Stream Cancel instruction */
  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  ASSERT_NOT_NULL (buf);
  ASSERT (buf_len > 0);

  /* Decode and verify */
  uint64_t decoded_stream_id = 0;
  size_t consumed = 0;
  result = SocketQPACK_decode_stream_cancel (
      buf, buf_len, &decoded_stream_id, &consumed);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (decoded_stream_id, 55);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_stream_reset_multiple)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Reset multiple streams */
  ASSERT_EQ (SocketQPACK_DecoderSync_on_stream_reset (sync, 100),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderSync_on_stream_reset (sync, 200),
             QPACK_STREAM_OK);

  /* Get buffer and decode all instructions */
  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  ASSERT_NOT_NULL (buf);

  size_t offset = 0;
  uint64_t stream_id;
  size_t consumed;

  /* First: stream 100 */
  ASSERT_EQ (SocketQPACK_decode_stream_cancel (
                 buf + offset, buf_len - offset, &stream_id, &consumed),
             QPACK_STREAM_OK);
  ASSERT_EQ (stream_id, 100);
  offset += consumed;

  /* Second: stream 200 */
  ASSERT_EQ (SocketQPACK_decode_stream_cancel (
                 buf + offset, buf_len - offset, &stream_id, &consumed),
             QPACK_STREAM_OK);
  ASSERT_EQ (stream_id, 200);
  offset += consumed;

  ASSERT_EQ (offset, buf_len);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_stream_reset_null)
{
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderSync_on_stream_reset (NULL, 55);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NULL_PARAM);
}

TEST (qpack_decoder_sync_insert_received_immediate)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Default threshold is 1, so each insert should immediately emit */
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderSync_on_insert_received (sync, 1);
  ASSERT_EQ (result, QPACK_STREAM_OK);

  /* Should have emitted Insert Count Increment of 1 */
  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  ASSERT_NOT_NULL (buf);
  ASSERT (buf_len > 0);

  uint64_t decoded_increment = 0;
  size_t consumed = 0;
  result = SocketQPACK_decode_insert_count_inc (
      buf, buf_len, &decoded_increment, &consumed);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (decoded_increment, 1);

  /* State should be updated */
  ASSERT_EQ (SocketQPACK_DecoderSync_get_insert_count (sync), 1);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_acknowledged_count (sync), 1);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_insert_received_coalescing)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Set threshold to 5 */
  ASSERT_EQ (SocketQPACK_DecoderSync_set_coalesce_threshold (sync, 5),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_coalesce_threshold (sync), 5);

  /* Insert 3 entries - should NOT emit yet (below threshold) */
  ASSERT_EQ (SocketQPACK_DecoderSync_on_insert_received (sync, 3),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderStream_buffer_size (stream), 0);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_insert_count (sync), 3);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_acknowledged_count (sync), 0);

  /* Insert 2 more - now at 5, should emit */
  ASSERT_EQ (SocketQPACK_DecoderSync_on_insert_received (sync, 2),
             QPACK_STREAM_OK);
  ASSERT (SocketQPACK_DecoderStream_buffer_size (stream) > 0);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_insert_count (sync), 5);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_acknowledged_count (sync), 5);

  /* Verify emitted increment is 5 */
  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  uint64_t decoded_increment = 0;
  size_t consumed = 0;
  ASSERT_EQ (SocketQPACK_decode_insert_count_inc (
                 buf, buf_len, &decoded_increment, &consumed),
             QPACK_STREAM_OK);
  ASSERT_EQ (decoded_increment, 5);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_insert_received_multiple_batches)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Set threshold to 3 */
  ASSERT_EQ (SocketQPACK_DecoderSync_set_coalesce_threshold (sync, 3),
             QPACK_STREAM_OK);

  /* Insert 10 entries one at a time */
  for (int i = 0; i < 10; i++)
    {
      ASSERT_EQ (SocketQPACK_DecoderSync_on_insert_received (sync, 1),
                 QPACK_STREAM_OK);
    }

  /* Should have emitted 3 instructions (at 3, 6, 9) */
  /* Insert count is 10, acknowledged is 9 */
  ASSERT_EQ (SocketQPACK_DecoderSync_get_insert_count (sync), 10);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_acknowledged_count (sync), 9);

  /* Get buffer and decode */
  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  ASSERT_NOT_NULL (buf);

  size_t offset = 0;
  uint64_t increment;
  size_t consumed;
  int count = 0;

  while (offset < buf_len)
    {
      SocketQPACKStream_Result result = SocketQPACK_decode_insert_count_inc (
          buf + offset, buf_len - offset, &increment, &consumed);
      ASSERT_EQ (result, QPACK_STREAM_OK);
      ASSERT_EQ (increment, 3); /* Each batch is 3 */
      offset += consumed;
      count++;
    }
  ASSERT_EQ (count, 3);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_insert_received_null)
{
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderSync_on_insert_received (NULL, 1);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NULL_PARAM);
}

TEST (qpack_decoder_sync_flush_pending)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Set high threshold so nothing auto-emits */
  ASSERT_EQ (SocketQPACK_DecoderSync_set_coalesce_threshold (sync, 100),
             QPACK_STREAM_OK);

  /* Insert 7 entries */
  ASSERT_EQ (SocketQPACK_DecoderSync_on_insert_received (sync, 7),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderStream_buffer_size (stream), 0);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_insert_count (sync), 7);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_acknowledged_count (sync), 0);

  /* Flush should emit the pending 7 */
  ASSERT_EQ (SocketQPACK_DecoderSync_flush (sync), QPACK_STREAM_OK);
  ASSERT (SocketQPACK_DecoderStream_buffer_size (stream) > 0);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_acknowledged_count (sync), 7);

  /* Verify emitted increment */
  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  uint64_t decoded_increment = 0;
  size_t consumed = 0;
  ASSERT_EQ (SocketQPACK_decode_insert_count_inc (
                 buf, buf_len, &decoded_increment, &consumed),
             QPACK_STREAM_OK);
  ASSERT_EQ (decoded_increment, 7);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_flush_nothing)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* No inserts, flush should succeed but emit nothing */
  ASSERT_EQ (SocketQPACK_DecoderSync_flush (sync), QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderStream_buffer_size (stream), 0);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_flush_already_acked)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Insert with threshold=1 (immediate ack) */
  ASSERT_EQ (SocketQPACK_DecoderSync_on_insert_received (sync, 5),
             QPACK_STREAM_OK);

  /* Clear buffer */
  ASSERT_EQ (SocketQPACK_DecoderStream_reset_buffer (stream), QPACK_STREAM_OK);

  /* Flush should do nothing since already acknowledged */
  ASSERT_EQ (SocketQPACK_DecoderSync_flush (sync), QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderStream_buffer_size (stream), 0);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_flush_null)
{
  SocketQPACKStream_Result result = SocketQPACK_DecoderSync_flush (NULL);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NULL_PARAM);
}

TEST (qpack_decoder_sync_set_threshold_valid)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Default is 1 */
  ASSERT_EQ (SocketQPACK_DecoderSync_get_coalesce_threshold (sync), 1);

  /* Set to various values */
  ASSERT_EQ (SocketQPACK_DecoderSync_set_coalesce_threshold (sync, 10),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_coalesce_threshold (sync), 10);

  ASSERT_EQ (SocketQPACK_DecoderSync_set_coalesce_threshold (sync, 1),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_coalesce_threshold (sync), 1);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_set_threshold_zero)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Threshold of 0 is invalid */
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderSync_set_coalesce_threshold (sync, 0);
  ASSERT_EQ (result, QPACK_STREAM_ERR_INVALID_INDEX);

  /* Should remain at default */
  ASSERT_EQ (SocketQPACK_DecoderSync_get_coalesce_threshold (sync), 1);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_set_threshold_null)
{
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderSync_set_coalesce_threshold (NULL, 5);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NULL_PARAM);
}

TEST (qpack_decoder_sync_get_threshold_null)
{
  uint64_t threshold = SocketQPACK_DecoderSync_get_coalesce_threshold (NULL);
  ASSERT_EQ (threshold, 0);
}

TEST (qpack_decoder_sync_get_insert_count_null)
{
  uint64_t count = SocketQPACK_DecoderSync_get_insert_count (NULL);
  ASSERT_EQ (count, 0);
}

TEST (qpack_decoder_sync_get_acknowledged_count_null)
{
  uint64_t count = SocketQPACK_DecoderSync_get_acknowledged_count (NULL);
  ASSERT_EQ (count, 0);
}

TEST (qpack_decoder_sync_mixed_instructions)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Mix of all instruction types */
  ASSERT_EQ (SocketQPACK_DecoderSync_on_section_decoded (sync, 10, 5),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderSync_on_insert_received (sync, 3),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderSync_on_stream_reset (sync, 20),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderSync_on_section_decoded (sync, 30, 7),
             QPACK_STREAM_OK);

  /* Get buffer and verify instruction order */
  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  ASSERT_NOT_NULL (buf);

  size_t offset = 0;
  SocketQPACK_DecoderInstruction instr;
  size_t consumed;

  /* First: Section Ack for stream 10 */
  ASSERT_EQ (SocketQPACK_decode_decoder_instruction (
                 buf + offset, buf_len - offset, &instr, &consumed),
             QPACK_STREAM_OK);
  ASSERT_EQ (instr.type, QPACK_DINSTR_TYPE_SECTION_ACK);
  ASSERT_EQ (instr.value, 10);
  offset += consumed;

  /* Second: Insert Count Increment of 3 */
  ASSERT_EQ (SocketQPACK_decode_decoder_instruction (
                 buf + offset, buf_len - offset, &instr, &consumed),
             QPACK_STREAM_OK);
  ASSERT_EQ (instr.type, QPACK_DINSTR_TYPE_INSERT_COUNT_INC);
  ASSERT_EQ (instr.value, 3);
  offset += consumed;

  /* Third: Stream Cancel for stream 20 */
  ASSERT_EQ (SocketQPACK_decode_decoder_instruction (
                 buf + offset, buf_len - offset, &instr, &consumed),
             QPACK_STREAM_OK);
  ASSERT_EQ (instr.type, QPACK_DINSTR_TYPE_STREAM_CANCEL);
  ASSERT_EQ (instr.value, 20);
  offset += consumed;

  /* Fourth: Section Ack for stream 30 */
  ASSERT_EQ (SocketQPACK_decode_decoder_instruction (
                 buf + offset, buf_len - offset, &instr, &consumed),
             QPACK_STREAM_OK);
  ASSERT_EQ (instr.type, QPACK_DINSTR_TYPE_SECTION_ACK);
  ASSERT_EQ (instr.value, 30);
  offset += consumed;

  ASSERT_EQ (offset, buf_len);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_large_stream_id)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Large stream ID (multi-byte encoding) */
  uint64_t large_id = 123456789;
  ASSERT_EQ (SocketQPACK_DecoderSync_on_section_decoded (sync, large_id, 1),
             QPACK_STREAM_OK);

  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  ASSERT_NOT_NULL (buf);

  uint64_t decoded_id = 0;
  size_t consumed = 0;
  ASSERT_EQ (
      SocketQPACK_decode_section_ack (buf, buf_len, &decoded_id, &consumed),
      QPACK_STREAM_OK);
  ASSERT_EQ (decoded_id, large_id);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_large_increment)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Large increment (multi-byte encoding) */
  uint64_t large_count = 10000;
  ASSERT_EQ (SocketQPACK_DecoderSync_on_insert_received (sync, large_count),
             QPACK_STREAM_OK);

  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  ASSERT_NOT_NULL (buf);

  uint64_t decoded_inc = 0;
  size_t consumed = 0;
  ASSERT_EQ (SocketQPACK_decode_insert_count_inc (
                 buf, buf_len, &decoded_inc, &consumed),
             QPACK_STREAM_OK);
  ASSERT_EQ (decoded_inc, large_count);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_insert_received_zero_count)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Insert with count=0 should be a no-op */
  ASSERT_EQ (SocketQPACK_DecoderSync_on_insert_received (sync, 0),
             QPACK_STREAM_OK);

  /* State should be unchanged */
  ASSERT_EQ (SocketQPACK_DecoderSync_get_insert_count (sync), 0);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_acknowledged_count (sync), 0);

  /* Buffer should be empty */
  ASSERT_EQ (SocketQPACK_DecoderStream_buffer_size (stream), 0);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_insert_overflow_saturates)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Set a very high threshold to avoid auto-emit for easier testing */
  ASSERT_EQ (SocketQPACK_DecoderSync_set_coalesce_threshold (sync, UINT64_MAX),
             QPACK_STREAM_OK);

  /* Receive a large value near UINT64_MAX */
  ASSERT_EQ (SocketQPACK_DecoderSync_on_insert_received (sync, UINT64_MAX - 10),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_insert_count (sync), UINT64_MAX - 10);

  /* Receiving more should saturate at UINT64_MAX, not wrap */
  ASSERT_EQ (SocketQPACK_DecoderSync_on_insert_received (sync, 20),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_insert_count (sync), UINT64_MAX);

  /* Further inserts should stay at UINT64_MAX */
  ASSERT_EQ (SocketQPACK_DecoderSync_on_insert_received (sync, 100),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_insert_count (sync), UINT64_MAX);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_uninitialized_stream_section_ack)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 100);
  ASSERT_NOT_NULL (stream);

  /* Do NOT initialize the stream */
  SocketQPACK_DecoderSync_T sync = SocketQPACK_DecoderSync_new (arena, stream);
  ASSERT_NOT_NULL (sync);

  /* Attempting to write Section Ack should fail */
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderSync_on_section_decoded (sync, 42, 5);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NOT_INIT);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_uninitialized_stream_cancel)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 100);
  ASSERT_NOT_NULL (stream);

  /* Do NOT initialize the stream */
  SocketQPACK_DecoderSync_T sync = SocketQPACK_DecoderSync_new (arena, stream);
  ASSERT_NOT_NULL (sync);

  /* Attempting to write Stream Cancel should fail */
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderSync_on_stream_reset (sync, 55);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NOT_INIT);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_uninitialized_stream_insert_inc)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 100);
  ASSERT_NOT_NULL (stream);

  /* Do NOT initialize the stream */
  SocketQPACK_DecoderSync_T sync = SocketQPACK_DecoderSync_new (arena, stream);
  ASSERT_NOT_NULL (sync);

  /* Attempting Insert Count Increment should fail (threshold=1 triggers write)
   */
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderSync_on_insert_received (sync, 1);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NOT_INIT);

  /* But with high threshold, the track should succeed (no write yet) */
  Arena_T arena2 = Arena_new ();
  SocketQPACK_DecoderStream_T stream2
      = SocketQPACK_DecoderStream_new (arena2, 200);
  ASSERT_NOT_NULL (stream2);
  SocketQPACK_DecoderSync_T sync2
      = SocketQPACK_DecoderSync_new (arena2, stream2);
  ASSERT_NOT_NULL (sync2);

  /* Set high threshold so no immediate write */
  ASSERT_EQ (SocketQPACK_DecoderSync_set_coalesce_threshold (sync2, 100),
             QPACK_STREAM_OK);
  result = SocketQPACK_DecoderSync_on_insert_received (sync2, 1);
  ASSERT_EQ (result, QPACK_STREAM_OK); /* Tracking succeeds, no write yet */

  /* But flush should fail because stream not initialized */
  result = SocketQPACK_DecoderSync_flush (sync2);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NOT_INIT);

  Arena_dispose (&arena);
  Arena_dispose (&arena2);
}

TEST (qpack_decoder_sync_large_threshold)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Set threshold to UINT64_MAX */
  ASSERT_EQ (SocketQPACK_DecoderSync_set_coalesce_threshold (sync, UINT64_MAX),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_coalesce_threshold (sync), UINT64_MAX);

  /* Insert should succeed but not trigger emit */
  ASSERT_EQ (SocketQPACK_DecoderSync_on_insert_received (sync, 1000),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderStream_buffer_size (stream), 0);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_insert_count (sync), 1000);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_acknowledged_count (sync), 0);

  /* Flush should emit the pending count */
  ASSERT_EQ (SocketQPACK_DecoderSync_flush (sync), QPACK_STREAM_OK);
  ASSERT (SocketQPACK_DecoderStream_buffer_size (stream) > 0);
  ASSERT_EQ (SocketQPACK_DecoderSync_get_acknowledged_count (sync), 1000);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_sync_stream_id_zero)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderStream_T stream;
  SocketQPACK_DecoderSync_T sync = create_sync_state (arena, &stream);
  ASSERT_NOT_NULL (sync);

  /* Stream ID 0 should be valid for Section Ack */
  ASSERT_EQ (SocketQPACK_DecoderSync_on_section_decoded (sync, 0, 5),
             QPACK_STREAM_OK);

  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  ASSERT_NOT_NULL (buf);

  uint64_t decoded_id = 99;
  size_t consumed = 0;
  ASSERT_EQ (
      SocketQPACK_decode_section_ack (buf, buf_len, &decoded_id, &consumed),
      QPACK_STREAM_OK);
  ASSERT_EQ (decoded_id, 0);

  Arena_dispose (&arena);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
