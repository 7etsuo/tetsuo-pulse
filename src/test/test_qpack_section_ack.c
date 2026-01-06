/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_section_ack.c
 * @brief Unit tests for QPACK Section Acknowledgment (RFC 9204 Section 4.4.1).
 */

#include "quic/SocketQPACK.h"
#include "core/Arena.h"
#include "test/Test.h"

#include <string.h>

/* ============================================================================
 * Integer Encoding Tests (RFC 9204 Section 4.1.1)
 * ============================================================================
 */

TEST (qpack_int_encode_small_value)
{
  /* Value fits in 7-bit prefix */
  unsigned char buf[16];
  size_t len = SocketQPACK_int_encode (42, 7, buf, sizeof (buf));

  ASSERT_EQ (1, len);
  ASSERT_EQ (42, buf[0]);
}

TEST (qpack_int_encode_max_prefix)
{
  /* Value equals max prefix (2^7 - 1 = 127) needs continuation */
  unsigned char buf[16];
  size_t len = SocketQPACK_int_encode (127, 7, buf, sizeof (buf));

  ASSERT_EQ (2, len);
  ASSERT_EQ (0x7F, buf[0]); /* Max prefix */
  ASSERT_EQ (0x00, buf[1]); /* 127 - 127 = 0 */
}

TEST (qpack_int_encode_large_value)
{
  /* Value 1337 with 7-bit prefix */
  unsigned char buf[16];
  size_t len = SocketQPACK_int_encode (1337, 7, buf, sizeof (buf));

  /* 1337 with 7-bit prefix:
   * max_prefix = 127
   * 1337 >= 127, so first byte = 0x7F
   * remaining = 1337 - 127 = 1210
   * 1210 = 0x4BA
   * First continuation: 1210 & 0x7F = 0x3A, set high bit -> 0xBA
   * Remaining: 1210 >> 7 = 9
   * Second byte (no continuation): 0x09
   */
  ASSERT_EQ (3, len);
  ASSERT_EQ (0x7F, buf[0]); /* Max prefix */
  ASSERT_EQ (0xBA, buf[1]); /* 0x80 | (1210 & 0x7F) */
  ASSERT_EQ (0x09, buf[2]); /* 1210 >> 7 = 9 */
}

TEST (qpack_int_decode_small_value)
{
  unsigned char data[] = { 0x2A }; /* 42 */
  uint64_t value;
  size_t consumed;

  SocketQPACK_Result res
      = SocketQPACK_int_decode (data, sizeof (data), 7, &value, &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (42, value);
  ASSERT_EQ (1, consumed);
}

TEST (qpack_int_decode_large_value)
{
  /* 1337 with 7-bit prefix (from encode test) */
  unsigned char data[] = { 0x7F, 0xBA, 0x09 };
  uint64_t value;
  size_t consumed;

  SocketQPACK_Result res
      = SocketQPACK_int_decode (data, sizeof (data), 7, &value, &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (1337, value);
  ASSERT_EQ (3, consumed);
}

TEST (qpack_int_decode_incomplete)
{
  /* Incomplete multi-byte integer */
  unsigned char data[] = { 0x7F }; /* Needs continuation */
  uint64_t value;
  size_t consumed;

  SocketQPACK_Result res
      = SocketQPACK_int_decode (data, sizeof (data), 7, &value, &consumed);

  ASSERT_EQ (QPACK_INCOMPLETE, res);
}

TEST (qpack_int_roundtrip_zero)
{
  unsigned char buf[16];
  size_t len = SocketQPACK_int_encode (0, 7, buf, sizeof (buf));

  ASSERT_EQ (1, len);
  ASSERT_EQ (0, buf[0]);

  uint64_t value;
  size_t consumed;
  SocketQPACK_Result res
      = SocketQPACK_int_decode (buf, len, 7, &value, &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (0, value);
  ASSERT_EQ (1, consumed);
}

TEST (qpack_int_roundtrip_large_value)
{
  /*
   * Test large value encoding/decoding.
   * Note: UINT64_MAX cannot be roundtripped due to 10-byte continuation limit.
   * RFC 7541/9204 integer encoding with 10 continuation bytes can represent
   * up to about 2^70, but our overflow checks limit this to prevent DoS.
   * Use a large but representable value instead.
   */
  unsigned char buf[16];
  uint64_t large_val = (1ULL << 62) - 1; /* Max QUIC varint value */
  size_t len = SocketQPACK_int_encode (large_val, 7, buf, sizeof (buf));

  /* Should succeed */
  ASSERT (len > 0);

  uint64_t value;
  size_t consumed;
  SocketQPACK_Result res
      = SocketQPACK_int_decode (buf, len, 7, &value, &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (large_val, value);
}

/* ============================================================================
 * Section Acknowledgment Decode Tests (RFC 9204 Section 4.4.1)
 * ============================================================================
 */

TEST (qpack_section_ack_decode_small_stream_id)
{
  /* Section Ack with stream ID 42 (fits in 7 bits)
   * Wire format: 1xxxxxxx where xxxxxxx is stream ID
   * 0x80 | 42 = 0xAA
   */
  unsigned char data[] = { 0xAA };
  SocketQPACK_DecoderInstruction_T instruction;
  size_t consumed;

  SocketQPACK_Result res = SocketQPACK_decode_section_ack (
      data, sizeof (data), &instruction, &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (QPACK_INSTRUCTION_SECTION_ACK, instruction.type);
  ASSERT_EQ (42, instruction.stream_id);
  ASSERT_EQ (1, consumed);
}

TEST (qpack_section_ack_decode_large_stream_id)
{
  /* Section Ack with stream ID 1337 (requires multi-byte encoding)
   * First byte: 0x80 | 0x7F = 0xFF (pattern + max prefix)
   * Continuation: same as integer encoding for 1337 - 127 = 1210
   */
  unsigned char data[] = { 0xFF, 0xBA, 0x09 };
  SocketQPACK_DecoderInstruction_T instruction;
  size_t consumed;

  SocketQPACK_Result res = SocketQPACK_decode_section_ack (
      data, sizeof (data), &instruction, &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (QPACK_INSTRUCTION_SECTION_ACK, instruction.type);
  ASSERT_EQ (1337, instruction.stream_id);
  ASSERT_EQ (3, consumed);
}

TEST (qpack_section_ack_decode_max_prefix_stream_id)
{
  /* Section Ack with stream ID 127 (max prefix value)
   * Wire format: 0xFF, 0x00 */
  unsigned char data[] = { 0xFF, 0x00 };
  SocketQPACK_DecoderInstruction_T instruction;
  size_t consumed;

  SocketQPACK_Result res = SocketQPACK_decode_section_ack (
      data, sizeof (data), &instruction, &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (127, instruction.stream_id);
  ASSERT_EQ (2, consumed);
}

TEST (qpack_section_ack_decode_stream_id_zero)
{
  /* Section Ack with stream ID 0
   * Wire format: 0x80 */
  unsigned char data[] = { 0x80 };
  SocketQPACK_DecoderInstruction_T instruction;
  size_t consumed;

  SocketQPACK_Result res = SocketQPACK_decode_section_ack (
      data, sizeof (data), &instruction, &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (0, instruction.stream_id);
  ASSERT_EQ (1, consumed);
}

TEST (qpack_section_ack_decode_invalid_pattern)
{
  /* Invalid pattern (not 1xxxxxxx) */
  unsigned char data[] = { 0x40 }; /* Stream Cancellation pattern */
  SocketQPACK_DecoderInstruction_T instruction;
  size_t consumed;

  SocketQPACK_Result res = SocketQPACK_decode_section_ack (
      data, sizeof (data), &instruction, &consumed);

  ASSERT_EQ (QPACK_ERROR_INVALID_INSTRUCTION, res);
}

TEST (qpack_section_ack_decode_incomplete)
{
  /* Incomplete multi-byte stream ID */
  unsigned char data[] = { 0xFF }; /* Needs continuation */
  SocketQPACK_DecoderInstruction_T instruction;
  size_t consumed;

  SocketQPACK_Result res = SocketQPACK_decode_section_ack (
      data, sizeof (data), &instruction, &consumed);

  ASSERT_EQ (QPACK_INCOMPLETE, res);
}

/* ============================================================================
 * Section Acknowledgment Encode Tests
 * ============================================================================
 */

TEST (qpack_section_ack_encode_small_stream_id)
{
  unsigned char buf[16];
  size_t len = SocketQPACK_encode_section_ack (42, buf, sizeof (buf));

  ASSERT_EQ (1, len);
  ASSERT_EQ (0xAA, buf[0]); /* 0x80 | 42 */
}

TEST (qpack_section_ack_encode_large_stream_id)
{
  unsigned char buf[16];
  size_t len = SocketQPACK_encode_section_ack (1337, buf, sizeof (buf));

  ASSERT_EQ (3, len);
  ASSERT_EQ (0xFF, buf[0]); /* 0x80 | 0x7F */
  ASSERT_EQ (0xBA, buf[1]);
  ASSERT_EQ (0x09, buf[2]);
}

TEST (qpack_section_ack_roundtrip)
{
  /* Encode then decode */
  unsigned char buf[16];
  size_t len = SocketQPACK_encode_section_ack (12345, buf, sizeof (buf));

  ASSERT (len > 0);

  SocketQPACK_DecoderInstruction_T instruction;
  size_t consumed;
  SocketQPACK_Result res
      = SocketQPACK_decode_section_ack (buf, len, &instruction, &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (QPACK_INSTRUCTION_SECTION_ACK, instruction.type);
  ASSERT_EQ (12345, instruction.stream_id);
  ASSERT_EQ (len, consumed);
}

/* ============================================================================
 * Decoder State Tests
 * ============================================================================
 */

TEST (qpack_decoder_state_new)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderState_T state = SocketQPACK_DecoderState_new (arena);

  ASSERT_NOT_NULL (state);
  ASSERT_EQ (0, SocketQPACK_DecoderState_get_known_received_count (state));

  Arena_dispose (&arena);
}

TEST (qpack_decoder_state_register_stream)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderState_T state = SocketQPACK_DecoderState_new (arena);

  /* Register a stream with RIC = 5 */
  SocketQPACK_Result res
      = SocketQPACK_DecoderState_register_stream (state, 100, 5);

  ASSERT_EQ (QPACK_OK, res);

  Arena_dispose (&arena);
}

TEST (qpack_decoder_state_register_zero_ric)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderState_T state = SocketQPACK_DecoderState_new (arena);

  /* Register stream with RIC = 0 (should be no-op per RFC) */
  SocketQPACK_Result res
      = SocketQPACK_DecoderState_register_stream (state, 100, 0);

  ASSERT_EQ (QPACK_OK, res);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Section Acknowledgment Validation Tests
 * ============================================================================
 */

TEST (qpack_validate_section_ack_updates_krc)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderState_T state = SocketQPACK_DecoderState_new (arena);

  /* Register stream 100 with RIC = 5 */
  SocketQPACK_DecoderState_register_stream (state, 100, 5);

  /* Initial KRC is 0 */
  ASSERT_EQ (0, SocketQPACK_DecoderState_get_known_received_count (state));

  /* Decode and validate Section Acknowledgment */
  SocketQPACK_DecoderInstruction_T instruction = {
    .type = QPACK_INSTRUCTION_SECTION_ACK, .stream_id = 100, .increment = 0
  };

  SocketQPACK_Result res
      = SocketQPACK_validate_section_ack (state, &instruction);
  ASSERT_EQ (QPACK_OK, res);

  /* KRC should now be 5 */
  ASSERT_EQ (5, SocketQPACK_DecoderState_get_known_received_count (state));

  Arena_dispose (&arena);
}

TEST (qpack_validate_section_ack_krc_only_increases)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderState_T state = SocketQPACK_DecoderState_new (arena);

  /* Register streams with different RICs */
  SocketQPACK_DecoderState_register_stream (state, 100, 10);
  SocketQPACK_DecoderState_register_stream (state, 200, 5);

  /* Acknowledge stream 100 (RIC = 10) first */
  SocketQPACK_DecoderInstruction_T instr1 = {
    .type = QPACK_INSTRUCTION_SECTION_ACK, .stream_id = 100, .increment = 0
  };
  SocketQPACK_validate_section_ack (state, &instr1);
  ASSERT_EQ (10, SocketQPACK_DecoderState_get_known_received_count (state));

  /* Register and acknowledge stream with lower RIC */
  SocketQPACK_DecoderState_register_stream (state, 300, 3);
  SocketQPACK_DecoderInstruction_T instr2 = {
    .type = QPACK_INSTRUCTION_SECTION_ACK, .stream_id = 300, .increment = 0
  };
  SocketQPACK_validate_section_ack (state, &instr2);

  /* KRC should still be 10 (only increases) */
  ASSERT_EQ (10, SocketQPACK_DecoderState_get_known_received_count (state));

  Arena_dispose (&arena);
}

TEST (qpack_validate_section_ack_idempotent)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderState_T state = SocketQPACK_DecoderState_new (arena);

  /* Register stream 100 with RIC = 5 */
  SocketQPACK_DecoderState_register_stream (state, 100, 5);

  SocketQPACK_DecoderInstruction_T instruction = {
    .type = QPACK_INSTRUCTION_SECTION_ACK, .stream_id = 100, .increment = 0
  };

  /* First acknowledgment */
  SocketQPACK_Result res1
      = SocketQPACK_validate_section_ack (state, &instruction);
  ASSERT_EQ (QPACK_OK, res1);
  ASSERT_EQ (5, SocketQPACK_DecoderState_get_known_received_count (state));

  /* Second acknowledgment of same stream (should be idempotent) */
  SocketQPACK_Result res2
      = SocketQPACK_validate_section_ack (state, &instruction);
  ASSERT_EQ (QPACK_OK, res2);
  ASSERT_EQ (5, SocketQPACK_DecoderState_get_known_received_count (state));

  Arena_dispose (&arena);
}

TEST (qpack_validate_section_ack_unknown_stream)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderState_T state = SocketQPACK_DecoderState_new (arena);

  /* Don't register any streams */

  SocketQPACK_DecoderInstruction_T instruction = {
    .type = QPACK_INSTRUCTION_SECTION_ACK, .stream_id = 999, .increment = 0
  };

  /* Acknowledging unknown stream should be OK (idempotent behavior) */
  SocketQPACK_Result res
      = SocketQPACK_validate_section_ack (state, &instruction);
  ASSERT_EQ (QPACK_OK, res);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Decoder Instruction Dispatch Tests
 * ============================================================================
 */

TEST (qpack_decode_instruction_section_ack)
{
  unsigned char data[] = { 0xAA }; /* Section Ack for stream 42 */
  SocketQPACK_DecoderInstruction_T instruction;
  size_t consumed;

  SocketQPACK_Result res = SocketQPACK_decode_decoder_instruction (
      data, sizeof (data), &instruction, &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (QPACK_INSTRUCTION_SECTION_ACK, instruction.type);
  ASSERT_EQ (42, instruction.stream_id);
}

TEST (qpack_decode_instruction_stream_cancel)
{
  /* Stream Cancellation: 01xxxxxx with 6-bit prefix
   * 0x40 | 10 = 0x4A */
  unsigned char data[] = { 0x4A };
  SocketQPACK_DecoderInstruction_T instruction;
  size_t consumed;

  SocketQPACK_Result res = SocketQPACK_decode_decoder_instruction (
      data, sizeof (data), &instruction, &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (QPACK_INSTRUCTION_STREAM_CANCEL, instruction.type);
  ASSERT_EQ (10, instruction.stream_id);
}

TEST (qpack_decode_instruction_insert_count_inc)
{
  /* Insert Count Increment: 00xxxxxx with 6-bit prefix
   * 0x00 | 15 = 0x0F */
  unsigned char data[] = { 0x0F };
  SocketQPACK_DecoderInstruction_T instruction;
  size_t consumed;

  SocketQPACK_Result res = SocketQPACK_decode_decoder_instruction (
      data, sizeof (data), &instruction, &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (QPACK_INSTRUCTION_INSERT_COUNT_INC, instruction.type);
  ASSERT_EQ (15, instruction.increment);
}

/* ============================================================================
 * Boundary Condition Tests
 * ============================================================================
 */

TEST (qpack_section_ack_large_stream_id)
{
  /*
   * Test with large stream ID.
   * QUIC stream IDs are 62-bit values (RFC 9000), so test with max QUIC value.
   * UINT64_MAX would exceed the 10-byte continuation limit for integer
   * encoding.
   */
  unsigned char buf[16];
  uint64_t max_quic_stream_id
      = (1ULL << 62) - 1; /* Max 62-bit QUIC stream ID */
  size_t len
      = SocketQPACK_encode_section_ack (max_quic_stream_id, buf, sizeof (buf));

  ASSERT (len > 0);

  SocketQPACK_DecoderInstruction_T instruction;
  size_t consumed;
  SocketQPACK_Result res
      = SocketQPACK_decode_section_ack (buf, len, &instruction, &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (max_quic_stream_id, instruction.stream_id);
}

TEST (qpack_int_encode_buffer_too_small)
{
  /* Buffer too small for large value */
  unsigned char buf[1];
  size_t len = SocketQPACK_int_encode (1337, 7, buf, sizeof (buf));

  ASSERT_EQ (0, len); /* Should fail */
}

TEST (qpack_section_ack_null_params)
{
  SocketQPACK_DecoderInstruction_T instruction;
  size_t consumed;

  /* NULL input */
  SocketQPACK_Result res1
      = SocketQPACK_decode_section_ack (NULL, 1, &instruction, &consumed);
  ASSERT_EQ (QPACK_ERROR, res1);

  /* NULL instruction */
  unsigned char data[] = { 0x80 };
  SocketQPACK_Result res2
      = SocketQPACK_decode_section_ack (data, sizeof (data), NULL, &consumed);
  ASSERT_EQ (QPACK_ERROR, res2);

  /* NULL consumed */
  SocketQPACK_Result res3 = SocketQPACK_decode_section_ack (
      data, sizeof (data), &instruction, NULL);
  ASSERT_EQ (QPACK_ERROR, res3);
}

TEST (qpack_result_strings)
{
  /* Verify result strings are defined */
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_OK));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_INCOMPLETE));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERROR));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERROR_STREAM_NOT_FOUND));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERROR_INVALID_INSTRUCTION));

  /* Invalid result should return "Unknown error" */
  ASSERT_NOT_NULL (SocketQPACK_result_string ((SocketQPACK_Result)999));
}

/* ============================================================================
 * Integration Tests
 * ============================================================================
 */

TEST (qpack_section_ack_full_flow)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderState_T state = SocketQPACK_DecoderState_new (arena);

  /* Simulate encoder sending multiple header sections */
  SocketQPACK_DecoderState_register_stream (state, 4, 3);  /* RIC = 3 */
  SocketQPACK_DecoderState_register_stream (state, 8, 7);  /* RIC = 7 */
  SocketQPACK_DecoderState_register_stream (state, 12, 5); /* RIC = 5 */

  ASSERT_EQ (0, SocketQPACK_DecoderState_get_known_received_count (state));

  /* Decoder acknowledges stream 4 */
  unsigned char ack1[16];
  size_t len1 = SocketQPACK_encode_section_ack (4, ack1, sizeof (ack1));
  SocketQPACK_DecoderInstruction_T instr1;
  size_t consumed1;
  SocketQPACK_decode_section_ack (ack1, len1, &instr1, &consumed1);
  SocketQPACK_validate_section_ack (state, &instr1);

  ASSERT_EQ (3, SocketQPACK_DecoderState_get_known_received_count (state));

  /* Decoder acknowledges stream 8 */
  unsigned char ack2[16];
  size_t len2 = SocketQPACK_encode_section_ack (8, ack2, sizeof (ack2));
  SocketQPACK_DecoderInstruction_T instr2;
  size_t consumed2;
  SocketQPACK_decode_section_ack (ack2, len2, &instr2, &consumed2);
  SocketQPACK_validate_section_ack (state, &instr2);

  ASSERT_EQ (7, SocketQPACK_DecoderState_get_known_received_count (state));

  /* Decoder acknowledges stream 12 (lower RIC, KRC shouldn't decrease) */
  unsigned char ack3[16];
  size_t len3 = SocketQPACK_encode_section_ack (12, ack3, sizeof (ack3));
  SocketQPACK_DecoderInstruction_T instr3;
  size_t consumed3;
  SocketQPACK_decode_section_ack (ack3, len3, &instr3, &consumed3);
  SocketQPACK_validate_section_ack (state, &instr3);

  /* KRC stays at 7 (doesn't decrease) */
  ASSERT_EQ (7, SocketQPACK_DecoderState_get_known_received_count (state));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Main Entry Point
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
