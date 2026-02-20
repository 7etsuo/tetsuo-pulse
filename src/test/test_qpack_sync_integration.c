/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_sync_integration.c
 * @brief Integration tests for QPACK encoder-decoder synchronization.
 *
 * Tests the synchronization mechanisms between QPACK encoder and decoder
 * as defined in RFC 9204 Section 4.4, including:
 * - Section Acknowledgment (4.4.1)
 * - Stream Cancellation (4.4.2)
 * - Insert Count Increment (4.4.3)
 */

#include <string.h>

#include "core/Arena.h"
#include "http/qpack/SocketQPACK.h"
#include "http/qpack/SocketQPACKDecoderStream.h"
#include "http/qpack/SocketQPACKEncoderStream.h"
#include "test/Test.h"

TEST (qpack_sync_insert_count_increment_roundtrip)
{
  unsigned char buf[32];
  size_t written = 0;
  uint64_t decoded_increment = 0;
  size_t consumed = 0;

  /* Encode increment of 5 */
  SocketQPACKStream_Result result
      = SocketQPACK_encode_insert_count_inc (buf, sizeof (buf), 5, &written);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT (written > 0);

  /* Decode */
  result = SocketQPACK_decode_insert_count_inc (
      buf, written, &decoded_increment, &consumed);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (decoded_increment, 5);
  ASSERT_EQ (consumed, written);
}

TEST (qpack_sync_insert_count_increment_large)
{
  unsigned char buf[32];
  size_t written = 0;
  uint64_t decoded_increment = 0;
  size_t consumed = 0;

  /* Encode large increment (needs multi-byte) */
  SocketQPACKStream_Result result
      = SocketQPACK_encode_insert_count_inc (buf, sizeof (buf), 1000, &written);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT (written > 1); /* Should need continuation */

  result = SocketQPACK_decode_insert_count_inc (
      buf, written, &decoded_increment, &consumed);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (decoded_increment, 1000);
}

TEST (qpack_sync_insert_count_increment_zero_invalid)
{
  unsigned char buf[32];
  size_t written = 0;

  /* Increment of 0 should fail */
  SocketQPACKStream_Result result
      = SocketQPACK_encode_insert_count_inc (buf, sizeof (buf), 0, &written);
  ASSERT_EQ (result, QPACK_STREAM_ERR_INVALID_INDEX);
}

TEST (qpack_sync_insert_count_increment_null_params)
{
  unsigned char buf[32];
  size_t written = 0;
  uint64_t increment = 0;
  size_t consumed = 0;

  /* NULL output */
  SocketQPACKStream_Result result
      = SocketQPACK_encode_insert_count_inc (NULL, 32, 5, &written);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NULL_PARAM);

  /* NULL written */
  result = SocketQPACK_encode_insert_count_inc (buf, sizeof (buf), 5, NULL);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NULL_PARAM);

  /* NULL decode increment */
  result = SocketQPACK_decode_insert_count_inc (buf, 2, NULL, &consumed);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NULL_PARAM);

  /* NULL decode consumed */
  result = SocketQPACK_decode_insert_count_inc (buf, 2, &increment, NULL);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NULL_PARAM);
}

TEST (qpack_sync_apply_insert_count_inc_basic)
{
  uint64_t known_received_count = 0;

  /* Apply increment of 10 with insert_count=20 */
  SocketQPACKStream_Result result
      = SocketQPACK_apply_insert_count_inc (&known_received_count, 20, 10);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (known_received_count, 10);

  /* Apply another increment of 5 */
  result = SocketQPACK_apply_insert_count_inc (&known_received_count, 20, 5);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (known_received_count, 15);
}

TEST (qpack_sync_apply_insert_count_inc_exceed)
{
  uint64_t known_received_count = 10;

  /* Try to apply increment that would exceed insert_count */
  SocketQPACKStream_Result result
      = SocketQPACK_apply_insert_count_inc (&known_received_count, 15, 10);
  ASSERT_EQ (result, QPACK_STREAM_ERR_INVALID_INDEX);
  /* known_received_count should be unchanged */
  ASSERT_EQ (known_received_count, 10);
}

TEST (qpack_sync_apply_insert_count_inc_zero)
{
  uint64_t known_received_count = 5;

  /* Increment of 0 is invalid */
  SocketQPACKStream_Result result
      = SocketQPACK_apply_insert_count_inc (&known_received_count, 10, 0);
  ASSERT_EQ (result, QPACK_STREAM_ERR_INVALID_INDEX);
}

TEST (qpack_sync_apply_insert_count_inc_null)
{
  SocketQPACKStream_Result result
      = SocketQPACK_apply_insert_count_inc (NULL, 10, 5);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NULL_PARAM);
}

TEST (qpack_sync_validate_insert_count_inc)
{
  /* Valid: increment that doesn't exceed insert_count */
  SocketQPACKStream_Result result
      = SocketQPACK_validate_insert_count_inc (5, 20, 10);
  ASSERT_EQ (result, QPACK_STREAM_OK);

  /* Valid: exactly to insert_count */
  result = SocketQPACK_validate_insert_count_inc (5, 15, 10);
  ASSERT_EQ (result, QPACK_STREAM_OK);

  /* Invalid: would exceed */
  result = SocketQPACK_validate_insert_count_inc (5, 10, 10);
  ASSERT_EQ (result, QPACK_STREAM_ERR_INVALID_INDEX);

  /* Invalid: zero increment */
  result = SocketQPACK_validate_insert_count_inc (5, 20, 0);
  ASSERT_EQ (result, QPACK_STREAM_ERR_INVALID_INDEX);
}

TEST (qpack_sync_section_ack_roundtrip)
{
  unsigned char buf[32];
  size_t consumed = 0;
  uint64_t decoded_stream_id = 0;

  /* Manually encode Section Ack for stream ID 42
   * Pattern: 1xxxxxxx (7-bit prefix)
   * 42 fits in 7 bits: 0x80 | 42 = 0xAA
   */
  buf[0] = 0x80 | 42;

  SocketQPACKStream_Result result
      = SocketQPACK_decode_section_ack (buf, 1, &decoded_stream_id, &consumed);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (decoded_stream_id, 42);
  ASSERT_EQ (consumed, 1);
}

TEST (qpack_sync_section_ack_large_stream_id)
{
  unsigned char buf[32];
  size_t consumed = 0;
  uint64_t decoded_stream_id = 0;

  /* Encode Section Ack for stream ID 500 (needs multi-byte)
   * 7-bit prefix max is 127
   * First byte: 0xFF (continuation), then 500 - 127 = 373
   * 373 = 256 + 117 = ...actually we need proper encoding
   */
  /* 7-bit prefix: 127 = 0x7F, so first byte = 0xFF
   * Continuation: 500 - 127 = 373
   * 373 = 0x175 = 1 01110101
   * Continuation bytes: 0x75 | 0x80, 0x02 | 0x00
   * = 0xF5, 0x02
   */
  buf[0] = 0xFF; /* 0x80 | 0x7F = signal continuation */
  buf[1] = 0xF5; /* 373 & 0x7F | 0x80 = 117 | 0x80 */
  buf[2] = 0x02; /* 373 >> 7 = 2 */

  SocketQPACKStream_Result result
      = SocketQPACK_decode_section_ack (buf, 3, &decoded_stream_id, &consumed);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (decoded_stream_id, 500);
  ASSERT_EQ (consumed, 3);
}

TEST (qpack_sync_section_ack_null_params)
{
  unsigned char buf[] = { 0x80 };
  size_t consumed = 0;
  uint64_t stream_id = 0;

  /* NULL stream_id */
  SocketQPACKStream_Result result
      = SocketQPACK_decode_section_ack (buf, 1, NULL, &consumed);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NULL_PARAM);

  /* NULL consumed */
  result = SocketQPACK_decode_section_ack (buf, 1, &stream_id, NULL);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NULL_PARAM);
}

TEST (qpack_sync_section_ack_incomplete)
{
  unsigned char buf[] = { 0xFF }; /* Signals continuation but no more bytes */
  size_t consumed = 0;
  uint64_t stream_id = 0;

  SocketQPACKStream_Result result
      = SocketQPACK_decode_section_ack (buf, 1, &stream_id, &consumed);
  ASSERT_EQ (result, QPACK_STREAM_ERR_BUFFER_FULL);
}

TEST (qpack_sync_stream_cancel_roundtrip)
{
  unsigned char buf[32];
  size_t consumed = 0;
  uint64_t decoded_stream_id = 0;

  /* Manually encode Stream Cancel for stream ID 10
   * Pattern: 01xxxxxx (6-bit prefix)
   * 10 fits in 6 bits: 0x40 | 10 = 0x4A
   */
  buf[0] = 0x40 | 10;

  SocketQPACKStream_Result result = SocketQPACK_decode_stream_cancel (
      buf, 1, &decoded_stream_id, &consumed);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (decoded_stream_id, 10);
  ASSERT_EQ (consumed, 1);
}

TEST (qpack_sync_stream_cancel_large_stream_id)
{
  unsigned char buf[32];
  size_t consumed = 0;
  uint64_t decoded_stream_id = 0;

  /* Encode Stream Cancel for stream ID 200 (needs multi-byte)
   * 6-bit prefix max is 63
   * First byte: 0x7F (0x40 | 0x3F = continuation)
   * Continuation: 200 - 63 = 137
   * RFC 7541 integer encoding:
   * - 137 >= 128: (137 & 127) | 128 = 9 | 128 = 0x89
   * - 137 >> 7 = 1: final byte = 0x01
   */
  buf[0] = 0x7F; /* 0x40 | 0x3F = signal continuation */
  buf[1] = 0x89; /* (137 & 127) | 128 = continuation */
  buf[2] = 0x01; /* 137 >> 7 = 1 (final) */

  SocketQPACKStream_Result result = SocketQPACK_decode_stream_cancel (
      buf, 3, &decoded_stream_id, &consumed);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (decoded_stream_id, 200);
  ASSERT_EQ (consumed, 3);
}

TEST (qpack_sync_stream_cancel_validate_id)
{
  /* Stream ID 0 is reserved */
  SocketQPACKStream_Result result = SocketQPACK_stream_cancel_validate_id (0);
  ASSERT_EQ (result, QPACK_STREAM_ERR_INVALID_INDEX);

  /* Other stream IDs are valid */
  result = SocketQPACK_stream_cancel_validate_id (1);
  ASSERT_EQ (result, QPACK_STREAM_OK);

  result = SocketQPACK_stream_cancel_validate_id (12345);
  ASSERT_EQ (result, QPACK_STREAM_OK);
}

TEST (qpack_sync_stream_cancel_release_refs)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  /* Release refs for stream 42 (should succeed even with empty table) */
  SocketQPACKStream_Result result
      = SocketQPACK_stream_cancel_release_refs (table, 42);
  ASSERT_EQ (result, QPACK_STREAM_OK);

  /* NULL table should also succeed */
  result = SocketQPACK_stream_cancel_release_refs (NULL, 42);
  ASSERT_EQ (result, QPACK_STREAM_OK);

  Arena_dispose (&arena);
}

TEST (qpack_sync_per_stream_ref_tracking)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Table_T table = SocketQPACK_Table_new (arena, 4096);
  ASSERT (table != NULL);

  /* Insert two entries into dynamic table */
  SocketQPACK_Result qr
      = SocketQPACK_Table_insert_literal (table, "x-a", 3, "val-a", 5);
  ASSERT_EQ (qr, QPACK_OK);

  qr = SocketQPACK_Table_insert_literal (table, "x-b", 3, "val-b", 5);
  ASSERT_EQ (qr, QPACK_OK);

  /* Stream 10 references entry 0, stream 20 references entries 0 and 1 */
  qr = SocketQPACK_Table_record_stream_ref (table, 10, 0);
  ASSERT_EQ (qr, QPACK_OK);

  qr = SocketQPACK_Table_record_stream_ref (table, 20, 0);
  ASSERT_EQ (qr, QPACK_OK);

  qr = SocketQPACK_Table_record_stream_ref (table, 20, 1);
  ASSERT_EQ (qr, QPACK_OK);

  /* Cancel stream 10 — only entry 0's ref_count should decrease by 1 */
  SocketQPACK_Table_release_stream_refs (table, 10);

  /* Record more refs for stream 30 to entry 1 */
  qr = SocketQPACK_Table_record_stream_ref (table, 30, 1);
  ASSERT_EQ (qr, QPACK_OK);

  /* Cancel stream 20 — entry 0 ref_count drops to 0, entry 1 drops by 1 */
  SocketQPACK_Table_release_stream_refs (table, 20);

  /* Cancel stream 30 */
  SocketQPACK_Table_release_stream_refs (table, 30);

  /* Verify: cancel on non-existent stream is harmless */
  SocketQPACK_Table_release_stream_refs (table, 999);

  Arena_dispose (&arena);
}

TEST (qpack_sync_identify_decoder_instruction)
{
  /* Section Ack: 1xxxxxxx */
  ASSERT_EQ (SocketQPACK_identify_decoder_instruction (0x80),
             QPACK_DINSTR_TYPE_SECTION_ACK);
  ASSERT_EQ (SocketQPACK_identify_decoder_instruction (0xFF),
             QPACK_DINSTR_TYPE_SECTION_ACK);
  ASSERT_EQ (SocketQPACK_identify_decoder_instruction (0xAB),
             QPACK_DINSTR_TYPE_SECTION_ACK);

  /* Stream Cancel: 01xxxxxx */
  ASSERT_EQ (SocketQPACK_identify_decoder_instruction (0x40),
             QPACK_DINSTR_TYPE_STREAM_CANCEL);
  ASSERT_EQ (SocketQPACK_identify_decoder_instruction (0x7F),
             QPACK_DINSTR_TYPE_STREAM_CANCEL);
  ASSERT_EQ (SocketQPACK_identify_decoder_instruction (0x55),
             QPACK_DINSTR_TYPE_STREAM_CANCEL);

  /* Insert Count Increment: 00xxxxxx */
  ASSERT_EQ (SocketQPACK_identify_decoder_instruction (0x00),
             QPACK_DINSTR_TYPE_INSERT_COUNT_INC);
  ASSERT_EQ (SocketQPACK_identify_decoder_instruction (0x3F),
             QPACK_DINSTR_TYPE_INSERT_COUNT_INC);
  ASSERT_EQ (SocketQPACK_identify_decoder_instruction (0x15),
             QPACK_DINSTR_TYPE_INSERT_COUNT_INC);
}

TEST (qpack_sync_decode_decoder_instruction_section_ack)
{
  unsigned char buf[] = { 0x80 | 42 }; /* Section Ack for stream 42 */
  SocketQPACK_DecoderInstruction instr;
  size_t consumed = 0;

  SocketQPACKStream_Result result = SocketQPACK_decode_decoder_instruction (
      buf, sizeof (buf), &instr, &consumed);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (instr.type, QPACK_DINSTR_TYPE_SECTION_ACK);
  ASSERT_EQ (instr.value, 42);
  ASSERT_EQ (consumed, 1);
}

TEST (qpack_sync_decode_decoder_instruction_stream_cancel)
{
  unsigned char buf[] = { 0x40 | 15 }; /* Stream Cancel for stream 15 */
  SocketQPACK_DecoderInstruction instr;
  size_t consumed = 0;

  SocketQPACKStream_Result result = SocketQPACK_decode_decoder_instruction (
      buf, sizeof (buf), &instr, &consumed);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (instr.type, QPACK_DINSTR_TYPE_STREAM_CANCEL);
  ASSERT_EQ (instr.value, 15);
  ASSERT_EQ (consumed, 1);
}

TEST (qpack_sync_decode_decoder_instruction_insert_count_inc)
{
  unsigned char buf[] = { 0x00 | 25 }; /* Insert Count Increment of 25 */
  SocketQPACK_DecoderInstruction instr;
  size_t consumed = 0;

  SocketQPACKStream_Result result = SocketQPACK_decode_decoder_instruction (
      buf, sizeof (buf), &instr, &consumed);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (instr.type, QPACK_DINSTR_TYPE_INSERT_COUNT_INC);
  ASSERT_EQ (instr.value, 25);
  ASSERT_EQ (consumed, 1);
}

TEST (qpack_sync_decode_decoder_instruction_null)
{
  unsigned char buf[] = { 0x80 };
  size_t consumed = 0;

  SocketQPACKStream_Result result
      = SocketQPACK_decode_decoder_instruction (buf, 1, NULL, &consumed);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NULL_PARAM);
}

TEST (qpack_sync_decoder_stream_new)
{
  Arena_T arena = Arena_new ();

  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 123);
  ASSERT (stream != NULL);
  ASSERT_EQ (SocketQPACK_DecoderStream_get_id (stream), 123);
  ASSERT_EQ (SocketQPACK_DecoderStream_is_open (stream), false);

  Arena_dispose (&arena);
}

TEST (qpack_sync_decoder_stream_init)
{
  Arena_T arena = Arena_new ();

  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 456);
  ASSERT (stream != NULL);

  SocketQPACKStream_Result result = SocketQPACK_DecoderStream_init (stream);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderStream_is_open (stream), true);

  /* Double init should fail */
  result = SocketQPACK_DecoderStream_init (stream);
  ASSERT_EQ (result, QPACK_STREAM_ERR_ALREADY_INIT);

  Arena_dispose (&arena);
}

TEST (qpack_sync_decoder_stream_validate_type)
{
  /* Decoder stream type is 0x03 */
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderStream_validate_type (QPACK_DECODER_STREAM_TYPE);
  ASSERT_EQ (result, QPACK_STREAM_OK);

  /* Other types should fail */
  result = SocketQPACK_DecoderStream_validate_type (QPACK_ENCODER_STREAM_TYPE);
  ASSERT_EQ (result, QPACK_STREAM_ERR_INVALID_TYPE);

  result = SocketQPACK_DecoderStream_validate_type (0x00);
  ASSERT_EQ (result, QPACK_STREAM_ERR_INVALID_TYPE);
}

TEST (qpack_sync_decoder_stream_validate_id)
{
  Arena_T arena = Arena_new ();

  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 789);
  ASSERT (stream != NULL);

  /* Matching ID should pass */
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderStream_validate_id (stream, 789);
  ASSERT_EQ (result, QPACK_STREAM_OK);

  /* Non-matching ID should fail */
  result = SocketQPACK_DecoderStream_validate_id (stream, 123);
  ASSERT_EQ (result, QPACK_STREAM_ERR_INVALID_TYPE);

  Arena_dispose (&arena);
}

TEST (qpack_sync_decoder_stream_write_section_ack)
{
  Arena_T arena = Arena_new ();

  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 100);
  ASSERT (stream != NULL);
  ASSERT_EQ (SocketQPACK_DecoderStream_init (stream), QPACK_STREAM_OK);

  /* Write Section Ack for stream 42 */
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderStream_write_section_ack (stream, 42);
  ASSERT_EQ (result, QPACK_STREAM_OK);

  /* Verify buffer contains the instruction */
  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  ASSERT (buf != NULL);
  ASSERT (buf_len > 0);

  /* Decode and verify */
  uint64_t decoded_stream_id = 0;
  size_t consumed = 0;
  SocketQPACKStream_Result decode_result = SocketQPACK_decode_section_ack (
      buf, buf_len, &decoded_stream_id, &consumed);
  ASSERT_EQ (decode_result, QPACK_STREAM_OK);
  ASSERT_EQ (decoded_stream_id, 42);

  Arena_dispose (&arena);
}

TEST (qpack_sync_decoder_stream_write_stream_cancel)
{
  Arena_T arena = Arena_new ();

  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 100);
  ASSERT (stream != NULL);
  ASSERT_EQ (SocketQPACK_DecoderStream_init (stream), QPACK_STREAM_OK);

  /* Write Stream Cancel for stream 55 */
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderStream_write_stream_cancel (stream, 55);
  ASSERT_EQ (result, QPACK_STREAM_OK);

  /* Verify buffer contains the instruction */
  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  ASSERT (buf != NULL);
  ASSERT (buf_len > 0);

  /* Decode and verify */
  uint64_t decoded_stream_id = 0;
  size_t consumed = 0;
  SocketQPACKStream_Result decode_result = SocketQPACK_decode_stream_cancel (
      buf, buf_len, &decoded_stream_id, &consumed);
  ASSERT_EQ (decode_result, QPACK_STREAM_OK);
  ASSERT_EQ (decoded_stream_id, 55);

  Arena_dispose (&arena);
}

TEST (qpack_sync_decoder_stream_write_insert_count_inc)
{
  Arena_T arena = Arena_new ();

  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 100);
  ASSERT (stream != NULL);
  ASSERT_EQ (SocketQPACK_DecoderStream_init (stream), QPACK_STREAM_OK);

  /* Write Insert Count Increment of 10 */
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderStream_write_insert_count_inc (stream, 10);
  ASSERT_EQ (result, QPACK_STREAM_OK);

  /* Verify buffer contains the instruction */
  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  ASSERT (buf != NULL);
  ASSERT (buf_len > 0);

  /* Decode and verify */
  uint64_t decoded_increment = 0;
  size_t consumed = 0;
  SocketQPACKStream_Result decode_result = SocketQPACK_decode_insert_count_inc (
      buf, buf_len, &decoded_increment, &consumed);
  ASSERT_EQ (decode_result, QPACK_STREAM_OK);
  ASSERT_EQ (decoded_increment, 10);

  Arena_dispose (&arena);
}

TEST (qpack_sync_decoder_stream_write_not_init)
{
  Arena_T arena = Arena_new ();

  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 100);
  ASSERT (stream != NULL);
  /* Don't initialize! */

  /* All writes should fail */
  SocketQPACKStream_Result result
      = SocketQPACK_DecoderStream_write_section_ack (stream, 42);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NOT_INIT);

  result = SocketQPACK_DecoderStream_write_stream_cancel (stream, 55);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NOT_INIT);

  result = SocketQPACK_DecoderStream_write_insert_count_inc (stream, 10);
  ASSERT_EQ (result, QPACK_STREAM_ERR_NOT_INIT);

  Arena_dispose (&arena);
}

TEST (qpack_sync_decoder_stream_buffer_management)
{
  Arena_T arena = Arena_new ();

  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 100);
  ASSERT (stream != NULL);
  ASSERT_EQ (SocketQPACK_DecoderStream_init (stream), QPACK_STREAM_OK);

  /* Buffer should initially be empty */
  ASSERT_EQ (SocketQPACK_DecoderStream_buffer_size (stream), 0);

  /* Write some instructions */
  ASSERT_EQ (SocketQPACK_DecoderStream_write_section_ack (stream, 1),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderStream_write_section_ack (stream, 2),
             QPACK_STREAM_OK);

  /* Buffer should have data */
  ASSERT (SocketQPACK_DecoderStream_buffer_size (stream) > 0);

  /* Get buffer for transmission */
  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  ASSERT (buf != NULL);
  ASSERT (buf_len > 0);
  ASSERT_EQ (buf_len, SocketQPACK_DecoderStream_buffer_size (stream));

  /* Reset buffer after "transmission" */
  ASSERT_EQ (SocketQPACK_DecoderStream_reset_buffer (stream), QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderStream_buffer_size (stream), 0);

  Arena_dispose (&arena);
}

TEST (qpack_sync_decoder_stream_multiple_instructions)
{
  Arena_T arena = Arena_new ();

  SocketQPACK_DecoderStream_T stream
      = SocketQPACK_DecoderStream_new (arena, 100);
  ASSERT (stream != NULL);
  ASSERT_EQ (SocketQPACK_DecoderStream_init (stream), QPACK_STREAM_OK);

  /* Write multiple instructions */
  ASSERT_EQ (SocketQPACK_DecoderStream_write_section_ack (stream, 10),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderStream_write_insert_count_inc (stream, 5),
             QPACK_STREAM_OK);
  ASSERT_EQ (SocketQPACK_DecoderStream_write_stream_cancel (stream, 20),
             QPACK_STREAM_OK);

  /* Get buffer and decode all instructions */
  size_t buf_len = 0;
  const unsigned char *buf
      = SocketQPACK_DecoderStream_get_buffer (stream, &buf_len);
  ASSERT (buf != NULL);

  size_t offset = 0;
  SocketQPACK_DecoderInstruction instr;
  size_t consumed = 0;

  /* First: Section Ack for stream 10 */
  ASSERT_EQ (SocketQPACK_decode_decoder_instruction (
                 buf + offset, buf_len - offset, &instr, &consumed),
             QPACK_STREAM_OK);
  ASSERT_EQ (instr.type, QPACK_DINSTR_TYPE_SECTION_ACK);
  ASSERT_EQ (instr.value, 10);
  offset += consumed;

  /* Second: Insert Count Increment of 5 */
  ASSERT_EQ (SocketQPACK_decode_decoder_instruction (
                 buf + offset, buf_len - offset, &instr, &consumed),
             QPACK_STREAM_OK);
  ASSERT_EQ (instr.type, QPACK_DINSTR_TYPE_INSERT_COUNT_INC);
  ASSERT_EQ (instr.value, 5);
  offset += consumed;

  /* Third: Stream Cancel for stream 20 */
  ASSERT_EQ (SocketQPACK_decode_decoder_instruction (
                 buf + offset, buf_len - offset, &instr, &consumed),
             QPACK_STREAM_OK);
  ASSERT_EQ (instr.type, QPACK_DINSTR_TYPE_STREAM_CANCEL);
  ASSERT_EQ (instr.value, 20);
  offset += consumed;

  /* Should have consumed all bytes */
  ASSERT_EQ (offset, buf_len);

  Arena_dispose (&arena);
}

TEST (qpack_sync_encoder_stream_new)
{
  Arena_T arena = Arena_new ();

  SocketQPACK_EncoderStream_T stream
      = SocketQPACK_EncoderStream_new (arena, 200, 4096);
  ASSERT (stream != NULL);

  Arena_dispose (&arena);
}

TEST (qpack_sync_known_received_count_scenario)
{
  /* Simulate encoder-decoder synchronization:
   * 1. Encoder inserts entries
   * 2. Decoder receives and acknowledges
   * 3. Encoder updates Known Received Count
   */
  uint64_t insert_count = 0;         /* Encoder's Insert Count */
  uint64_t known_received_count = 0; /* Encoder's Known Received Count */

  /* Encoder inserts 10 entries */
  insert_count = 10;

  /* Decoder acknowledges 5 entries */
  SocketQPACKStream_Result result = SocketQPACK_apply_insert_count_inc (
      &known_received_count, insert_count, 5);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (known_received_count, 5);

  /* Encoder inserts 5 more entries */
  insert_count = 15;

  /* Decoder acknowledges 8 more entries (total 13) */
  result = SocketQPACK_apply_insert_count_inc (
      &known_received_count, insert_count, 8);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (known_received_count, 13);

  /* Decoder acknowledges 2 more (total 15, matches insert count) */
  result = SocketQPACK_apply_insert_count_inc (
      &known_received_count, insert_count, 2);
  ASSERT_EQ (result, QPACK_STREAM_OK);
  ASSERT_EQ (known_received_count, 15);

  /* Try to acknowledge more than inserted - should fail */
  result = SocketQPACK_apply_insert_count_inc (
      &known_received_count, insert_count, 1);
  ASSERT_EQ (result, QPACK_STREAM_ERR_INVALID_INDEX);
  ASSERT_EQ (known_received_count, 15); /* Unchanged */
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
