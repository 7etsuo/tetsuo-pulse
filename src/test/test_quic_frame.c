/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_frame.c
 * @brief Unit tests for QUIC Frame parsing (RFC 9000 Section 12).
 */

#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICVarInt.h"
#include "core/Arena.h"
#include "test/Test.h"

#include <string.h>

TEST (frame_padding_parse)
{
  uint8_t data[] = { 0x00 };
  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, sizeof (data), &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_PADDING, frame.type);
  ASSERT_EQ (1, consumed);
}

TEST (frame_ping_parse)
{
  uint8_t data[] = { 0x01 };
  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, sizeof (data), &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_PING, frame.type);
  ASSERT_EQ (1, consumed);
}

TEST (frame_ack_simple)
{
  uint8_t data[] = { 0x02, 0x0a, 0x00, 0x00, 0x05 };
  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, sizeof (data), &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_ACK, frame.type);
  ASSERT_EQ (10, frame.data.ack.largest_ack);
  ASSERT_EQ (0, frame.data.ack.ack_delay);
  ASSERT_EQ (0, frame.data.ack.range_count);
  ASSERT_EQ (5, frame.data.ack.first_range);

  SocketQUICFrame_free (&frame);
}

TEST (frame_crypto)
{
  uint8_t data[] = { 0x06, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' };
  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, sizeof (data), &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_CRYPTO, frame.type);
  ASSERT_EQ (0, frame.data.crypto.offset);
  ASSERT_EQ (5, frame.data.crypto.length);
  ASSERT_NOT_NULL (frame.data.crypto.data);
  ASSERT (memcmp (frame.data.crypto.data, "hello", 5) == 0);
}

TEST (frame_stream_basic)
{
  uint8_t data[] = { 0x08, 0x00, 'h', 'e', 'l', 'l', 'o' };
  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, sizeof (data), &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT (SocketQUICFrame_is_stream (frame.type));
  ASSERT_EQ (0, frame.data.stream.stream_id);
  ASSERT_EQ (0, frame.data.stream.has_fin);
  ASSERT_EQ (0, frame.data.stream.has_length);
  ASSERT_EQ (0, frame.data.stream.has_offset);
  ASSERT_EQ (5, frame.data.stream.length);
}

TEST (frame_stream_all_flags)
{
  uint8_t data[] = { 0x0f, 0x04, 0x32, 0x02, 'h', 'i' };
  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, sizeof (data), &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (1, frame.data.stream.has_fin);
  ASSERT_EQ (1, frame.data.stream.has_length);
  ASSERT_EQ (1, frame.data.stream.has_offset);
  ASSERT_EQ (4, frame.data.stream.stream_id);
  ASSERT_EQ (50, frame.data.stream.offset);
  ASSERT_EQ (2, frame.data.stream.length);
}

TEST (frame_new_token)
{
  uint8_t data[] = { 0x07, 0x04, 't', 'e', 's', 't' };
  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, sizeof (data), &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_NEW_TOKEN, frame.type);
  ASSERT_EQ (4, frame.data.new_token.token_length);
  ASSERT (memcmp (frame.data.new_token.token, "test", 4) == 0);
}

TEST (frame_max_data)
{
  uint8_t data[] = { 0x10, 0x43, 0xe8 };
  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, sizeof (data), &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_MAX_DATA, frame.type);
  ASSERT_EQ (1000, frame.data.max_data.max_data);
}

TEST (frame_path_challenge)
{
  uint8_t data[] = { 0x1a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, sizeof (data), &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_PATH_CHALLENGE, frame.type);
  ASSERT (memcmp (frame.data.path_challenge.data,
                  "\x01\x02\x03\x04\x05\x06\x07\x08", 8) == 0);
}

TEST (frame_connection_close)
{
  uint8_t data[] = { 0x1c, 0x0a, 0x06, 0x04, 't', 'e', 's', 't' };
  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, sizeof (data), &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_CONNECTION_CLOSE, frame.type);
  ASSERT_EQ (10, frame.data.connection_close.error_code);
  ASSERT_EQ (6, frame.data.connection_close.frame_type);
  ASSERT_EQ (4, frame.data.connection_close.reason_length);
  ASSERT_EQ (0, frame.data.connection_close.is_app_error);
}

TEST (frame_handshake_done)
{
  uint8_t data[] = { 0x1e };
  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, sizeof (data), &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_HANDSHAKE_DONE, frame.type);
  ASSERT_EQ (1, consumed);
}

TEST (frame_validation_padding)
{
  SocketQUICFrame_T frame = { .type = QUIC_FRAME_PADDING };

  ASSERT_EQ (QUIC_FRAME_OK,
             SocketQUICFrame_validate (&frame, QUIC_PKT_INITIAL));
  ASSERT_EQ (QUIC_FRAME_OK,
             SocketQUICFrame_validate (&frame, QUIC_PKT_0RTT));
  ASSERT_EQ (QUIC_FRAME_OK,
             SocketQUICFrame_validate (&frame, QUIC_PKT_HANDSHAKE));
  ASSERT_EQ (QUIC_FRAME_OK,
             SocketQUICFrame_validate (&frame, QUIC_PKT_1RTT));
}

TEST (frame_validation_ack)
{
  SocketQUICFrame_T frame = { .type = QUIC_FRAME_ACK };

  ASSERT_EQ (QUIC_FRAME_OK,
             SocketQUICFrame_validate (&frame, QUIC_PKT_INITIAL));
  ASSERT_EQ (QUIC_FRAME_ERROR_PACKET_TYPE,
             SocketQUICFrame_validate (&frame, QUIC_PKT_0RTT));
  ASSERT_EQ (QUIC_FRAME_OK,
             SocketQUICFrame_validate (&frame, QUIC_PKT_HANDSHAKE));
  ASSERT_EQ (QUIC_FRAME_OK,
             SocketQUICFrame_validate (&frame, QUIC_PKT_1RTT));
}

TEST (frame_validation_stream)
{
  SocketQUICFrame_T frame = { .type = QUIC_FRAME_STREAM };

  ASSERT_EQ (QUIC_FRAME_ERROR_PACKET_TYPE,
             SocketQUICFrame_validate (&frame, QUIC_PKT_INITIAL));
  ASSERT_EQ (QUIC_FRAME_OK,
             SocketQUICFrame_validate (&frame, QUIC_PKT_0RTT));
  ASSERT_EQ (QUIC_FRAME_ERROR_PACKET_TYPE,
             SocketQUICFrame_validate (&frame, QUIC_PKT_HANDSHAKE));
  ASSERT_EQ (QUIC_FRAME_OK,
             SocketQUICFrame_validate (&frame, QUIC_PKT_1RTT));
}

TEST (frame_validation_new_token)
{
  SocketQUICFrame_T frame = { .type = QUIC_FRAME_NEW_TOKEN };

  ASSERT_EQ (QUIC_FRAME_ERROR_PACKET_TYPE,
             SocketQUICFrame_validate (&frame, QUIC_PKT_INITIAL));
  ASSERT_EQ (QUIC_FRAME_ERROR_PACKET_TYPE,
             SocketQUICFrame_validate (&frame, QUIC_PKT_0RTT));
  ASSERT_EQ (QUIC_FRAME_ERROR_PACKET_TYPE,
             SocketQUICFrame_validate (&frame, QUIC_PKT_HANDSHAKE));
  ASSERT_EQ (QUIC_FRAME_OK,
             SocketQUICFrame_validate (&frame, QUIC_PKT_1RTT));
}

TEST (frame_ack_eliciting)
{
  ASSERT_EQ (0, SocketQUICFrame_is_ack_eliciting (QUIC_FRAME_PADDING));
  ASSERT_EQ (1, SocketQUICFrame_is_ack_eliciting (QUIC_FRAME_PING));
  ASSERT_EQ (0, SocketQUICFrame_is_ack_eliciting (QUIC_FRAME_ACK));
  ASSERT_EQ (0, SocketQUICFrame_is_ack_eliciting (QUIC_FRAME_ACK_ECN));
  ASSERT_EQ (1, SocketQUICFrame_is_ack_eliciting (QUIC_FRAME_STREAM));
  ASSERT_EQ (1, SocketQUICFrame_is_ack_eliciting (QUIC_FRAME_CRYPTO));
  ASSERT_EQ (0,
             SocketQUICFrame_is_ack_eliciting (QUIC_FRAME_CONNECTION_CLOSE));
}

TEST (frame_type_string)
{
  ASSERT (strcmp ("PADDING", SocketQUICFrame_type_string (QUIC_FRAME_PADDING)) == 0);
  ASSERT (strcmp ("PING", SocketQUICFrame_type_string (QUIC_FRAME_PING)) == 0);
  ASSERT (strcmp ("ACK", SocketQUICFrame_type_string (QUIC_FRAME_ACK)) == 0);
  ASSERT (strcmp ("STREAM", SocketQUICFrame_type_string (QUIC_FRAME_STREAM)) == 0);
  ASSERT (strcmp ("CRYPTO", SocketQUICFrame_type_string (QUIC_FRAME_CRYPTO)) == 0);
}

TEST (frame_error_truncated)
{
  uint8_t data[] = { 0x06, 0x00, 0x05, 'a', 'b' };
  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, sizeof (data), &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_ERROR_TRUNCATED, res);
}

TEST (frame_error_unknown_type)
{
  uint8_t data[] = { 0x40, 0xff };
  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, sizeof (data), &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_ERROR_TYPE, res);
}

TEST (frame_null_pointers)
{
  uint8_t data[] = { 0x00 };
  SocketQUICFrame_T frame;
  size_t consumed;

  ASSERT_EQ (QUIC_FRAME_ERROR_NULL,
             SocketQUICFrame_parse (NULL, 1, &frame, &consumed));
  ASSERT_EQ (QUIC_FRAME_ERROR_NULL,
             SocketQUICFrame_parse (data, 1, NULL, &consumed));
  ASSERT_EQ (QUIC_FRAME_ERROR_NULL,
             SocketQUICFrame_parse (data, 1, &frame, NULL));
}

/* ============================================================================
 * Connection ID Frame Tests (RFC 9000 §19.15-19.16)
 * ============================================================================
 */

TEST (frame_new_connection_id_encode_basic)
{
  uint8_t cid[] = { 0x01, 0x02, 0x03, 0x04 };
  uint8_t token[16] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
  uint8_t buf[128];
  size_t len;

  /* Encode NEW_CONNECTION_ID frame */
  len = SocketQUICFrame_encode_new_connection_id (
      5,    /* sequence */
      2,    /* retire_prior_to */
      4,    /* cid_length */
      cid, token, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x18, buf[0]); /* Frame type */

  /* Parse it back */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_NEW_CONNECTION_ID, frame.type);
  ASSERT_EQ (5, frame.data.new_connection_id.sequence);
  ASSERT_EQ (2, frame.data.new_connection_id.retire_prior_to);
  ASSERT_EQ (4, frame.data.new_connection_id.cid_length);
  ASSERT (memcmp (frame.data.new_connection_id.cid, cid, 4) == 0);
  ASSERT (memcmp (frame.data.new_connection_id.stateless_reset_token, token,
                  16) == 0);
  ASSERT_EQ (len, consumed);
}

TEST (frame_new_connection_id_encode_max_length)
{
  uint8_t cid[20];
  uint8_t token[16];
  uint8_t buf[128];

  /* Fill with test data */
  for (int i = 0; i < 20; i++)
    cid[i] = (uint8_t)i;
  for (int i = 0; i < 16; i++)
    token[i] = (uint8_t)(0xf0 + i);

  /* Encode with maximum CID length (20 bytes) */
  size_t len = SocketQUICFrame_encode_new_connection_id (
      100, 50, 20, cid, token, buf, sizeof (buf));

  ASSERT (len > 0);

  /* Verify round-trip */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (100, frame.data.new_connection_id.sequence);
  ASSERT_EQ (50, frame.data.new_connection_id.retire_prior_to);
  ASSERT_EQ (20, frame.data.new_connection_id.cid_length);
  ASSERT (memcmp (frame.data.new_connection_id.cid, cid, 20) == 0);
}

TEST (frame_new_connection_id_encode_min_length)
{
  uint8_t cid[] = { 0xab };
  uint8_t token[16] = { 0 };
  uint8_t buf[128];

  /* Encode with minimum CID length (1 byte) */
  size_t len = SocketQUICFrame_encode_new_connection_id (
      0, 0, 1, cid, token, buf, sizeof (buf));

  ASSERT (len > 0);

  /* Verify round-trip */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (0, frame.data.new_connection_id.sequence);
  ASSERT_EQ (0, frame.data.new_connection_id.retire_prior_to);
  ASSERT_EQ (1, frame.data.new_connection_id.cid_length);
  ASSERT_EQ (0xab, frame.data.new_connection_id.cid[0]);
}

TEST (frame_new_connection_id_encode_invalid_length)
{
  uint8_t cid[20] = { 0 };
  uint8_t token[16] = { 0 };
  uint8_t buf[128];

  /* CID length 0 is invalid for NEW_CONNECTION_ID */
  ASSERT_EQ (0, SocketQUICFrame_encode_new_connection_id (
                    0, 0, 0, cid, token, buf, sizeof (buf)));

  /* CID length > 20 is invalid */
  ASSERT_EQ (0, SocketQUICFrame_encode_new_connection_id (
                    0, 0, 21, cid, token, buf, sizeof (buf)));
}

TEST (frame_new_connection_id_encode_retire_validation)
{
  uint8_t cid[] = { 0x01 };
  uint8_t token[16] = { 0 };
  uint8_t buf[128];

  /* retire_prior_to must be <= sequence */
  ASSERT_EQ (0, SocketQUICFrame_encode_new_connection_id (
                    5, 10, /* retire > sequence */
                    1, cid, token, buf, sizeof (buf)));

  /* Equal is valid */
  ASSERT (SocketQUICFrame_encode_new_connection_id (
              5, 5, 1, cid, token, buf, sizeof (buf)) > 0);
}

TEST (frame_new_connection_id_encode_buffer_size)
{
  uint8_t cid[] = { 0x01 };
  uint8_t token[16] = { 0 };
  uint8_t buf[10];

  /* Buffer too small should return 0 */
  ASSERT_EQ (0, SocketQUICFrame_encode_new_connection_id (
                    0, 0, 1, cid, token, buf, 5));
}

TEST (frame_retire_connection_id_encode_basic)
{
  uint8_t buf[128];

  /* Encode RETIRE_CONNECTION_ID frame */
  size_t len
      = SocketQUICFrame_encode_retire_connection_id (42, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x19, buf[0]); /* Frame type */

  /* Parse it back */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_RETIRE_CONNECTION_ID, frame.type);
  ASSERT_EQ (42, frame.data.retire_connection_id.sequence);
  ASSERT_EQ (len, consumed);
}

TEST (frame_retire_connection_id_encode_large_sequence)
{
  uint8_t buf[128];

  /* Large sequence number */
  size_t len = SocketQUICFrame_encode_retire_connection_id (
      0x123456789abcdef, buf, sizeof (buf));

  ASSERT (len > 0);

  /* Verify round-trip */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (0x123456789abcdef, frame.data.retire_connection_id.sequence);
}

TEST (frame_retire_connection_id_encode_buffer_size)
{
  uint8_t buf[2];

  /* Buffer too small should return 0 */
  ASSERT_EQ (0, SocketQUICFrame_encode_retire_connection_id (
                    1000000, buf, sizeof (buf)));
}

TEST (frame_connection_id_validation)
{
  SocketQUICFrame_T frame;

  /* NEW_CONNECTION_ID allowed in 0-RTT and 1-RTT */
  frame.type = QUIC_FRAME_NEW_CONNECTION_ID;
  ASSERT_EQ (QUIC_FRAME_ERROR_PACKET_TYPE,
             SocketQUICFrame_validate (&frame, QUIC_PKT_INITIAL));
  ASSERT_EQ (QUIC_FRAME_OK,
             SocketQUICFrame_validate (&frame, QUIC_PKT_0RTT));
  ASSERT_EQ (QUIC_FRAME_ERROR_PACKET_TYPE,
             SocketQUICFrame_validate (&frame, QUIC_PKT_HANDSHAKE));
  ASSERT_EQ (QUIC_FRAME_OK,
             SocketQUICFrame_validate (&frame, QUIC_PKT_1RTT));

  /* RETIRE_CONNECTION_ID allowed in 0-RTT and 1-RTT */
  frame.type = QUIC_FRAME_RETIRE_CONNECTION_ID;
  ASSERT_EQ (QUIC_FRAME_ERROR_PACKET_TYPE,
             SocketQUICFrame_validate (&frame, QUIC_PKT_INITIAL));
  ASSERT_EQ (QUIC_FRAME_OK,
             SocketQUICFrame_validate (&frame, QUIC_PKT_0RTT));
  ASSERT_EQ (QUIC_FRAME_ERROR_PACKET_TYPE,
             SocketQUICFrame_validate (&frame, QUIC_PKT_HANDSHAKE));
  ASSERT_EQ (QUIC_FRAME_OK,
             SocketQUICFrame_validate (&frame, QUIC_PKT_1RTT));
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
