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
 * Flow Control Frame Encoding Tests (RFC 9000 §19.12-19.14)
 * ============================================================================
 */

TEST (frame_encode_data_blocked_basic)
{
  uint8_t buf[16];
  size_t len;

  /* Encode DATA_BLOCKED with max_data = 1000 */
  len = SocketQUICFrame_encode_data_blocked (1000, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x14, buf[0]); /* Frame type */

  /* Verify by parsing back */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_DATA_BLOCKED, frame.type);
  ASSERT_EQ (1000, frame.data.data_blocked.limit);
  ASSERT_EQ (len, consumed);
}

TEST (frame_encode_data_blocked_large)
{
  uint8_t buf[16];
  size_t len;

  /* Encode with large value requiring 4-byte varint */
  uint64_t max_data = 100000;
  len = SocketQUICFrame_encode_data_blocked (max_data, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x14, buf[0]);

  /* Verify by parsing */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (max_data, frame.data.data_blocked.limit);
}

TEST (frame_encode_data_blocked_buffer_too_small)
{
  uint8_t buf[2];
  size_t len;

  /* Try encoding with insufficient buffer */
  len = SocketQUICFrame_encode_data_blocked (1000, buf, sizeof (buf));

  ASSERT_EQ (0, len); /* Should fail */
}

TEST (frame_encode_data_blocked_null)
{
  size_t len = SocketQUICFrame_encode_data_blocked (100, NULL, 16);
  ASSERT_EQ (0, len);
}

TEST (frame_encode_stream_data_blocked_basic)
{
  uint8_t buf[16];
  size_t len;

  /* Encode STREAM_DATA_BLOCKED with stream_id = 4, max_data = 2000 */
  len = SocketQUICFrame_encode_stream_data_blocked (4, 2000, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x15, buf[0]); /* Frame type */

  /* Verify by parsing */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_STREAM_DATA_BLOCKED, frame.type);
  ASSERT_EQ (4, frame.data.stream_data_blocked.stream_id);
  ASSERT_EQ (2000, frame.data.stream_data_blocked.limit);
  ASSERT_EQ (len, consumed);
}

TEST (frame_encode_stream_data_blocked_large_stream_id)
{
  uint8_t buf[32];
  size_t len;

  /* Encode with large stream ID and max_data */
  uint64_t stream_id = 1000000;
  uint64_t max_data = 5000000;
  len = SocketQUICFrame_encode_stream_data_blocked (stream_id, max_data, buf,
                                                     sizeof (buf));

  ASSERT (len > 0);

  /* Verify by parsing */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (stream_id, frame.data.stream_data_blocked.stream_id);
  ASSERT_EQ (max_data, frame.data.stream_data_blocked.limit);
}

TEST (frame_encode_stream_data_blocked_buffer_too_small)
{
  uint8_t buf[2];
  size_t len;

  len = SocketQUICFrame_encode_stream_data_blocked (4, 2000, buf, sizeof (buf));

  ASSERT_EQ (0, len); /* Should fail */
}

TEST (frame_encode_stream_data_blocked_null)
{
  size_t len = SocketQUICFrame_encode_stream_data_blocked (4, 2000, NULL, 16);
  ASSERT_EQ (0, len);
}

TEST (frame_encode_streams_blocked_bidi)
{
  uint8_t buf[16];
  size_t len;

  /* Encode STREAMS_BLOCKED (bidirectional) with max_streams = 100 */
  len = SocketQUICFrame_encode_streams_blocked (1, 100, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x16, buf[0]); /* Bidirectional type */

  /* Verify by parsing */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_STREAMS_BLOCKED_BIDI, frame.type);
  ASSERT_EQ (100, frame.data.streams_blocked.limit);
  ASSERT_EQ (1, frame.data.streams_blocked.is_bidi);
  ASSERT_EQ (len, consumed);
}

TEST (frame_encode_streams_blocked_uni)
{
  uint8_t buf[16];
  size_t len;

  /* Encode STREAMS_BLOCKED (unidirectional) with max_streams = 50 */
  len = SocketQUICFrame_encode_streams_blocked (0, 50, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x17, buf[0]); /* Unidirectional type */

  /* Verify by parsing */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_STREAMS_BLOCKED_UNI, frame.type);
  ASSERT_EQ (50, frame.data.streams_blocked.limit);
  ASSERT_EQ (0, frame.data.streams_blocked.is_bidi);
  ASSERT_EQ (len, consumed);
}

TEST (frame_encode_streams_blocked_large)
{
  uint8_t buf[16];
  size_t len;

  /* Encode with large max_streams value */
  uint64_t max_streams = 1000000;
  len = SocketQUICFrame_encode_streams_blocked (1, max_streams, buf, sizeof (buf));

  ASSERT (len > 0);

  /* Verify by parsing */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (max_streams, frame.data.streams_blocked.limit);
  ASSERT_EQ (1, frame.data.streams_blocked.is_bidi);
}

TEST (frame_encode_streams_blocked_buffer_too_small)
{
  uint8_t buf[2];
  size_t len;

  len = SocketQUICFrame_encode_streams_blocked (1, 100, buf, sizeof (buf));

  ASSERT_EQ (0, len); /* Should fail */
}

TEST (frame_encode_streams_blocked_null)
{
  size_t len = SocketQUICFrame_encode_streams_blocked (1, 100, NULL, 16);
  ASSERT_EQ (0, len);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
