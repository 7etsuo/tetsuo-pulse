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
 * MAX_DATA Frame Tests (RFC 9000 Section 19.9)
 * ============================================================================
 */

TEST (frame_encode_max_data_basic)
{
  uint8_t buf[16];
  size_t len;

  /* Encode MAX_DATA with value 1000 */
  len = SocketQUICFrame_encode_max_data (1000, buf, sizeof (buf));
  ASSERT (len > 0);
  ASSERT_EQ (0x10, buf[0]); /* Type: MAX_DATA */

  /* Parse it back and verify */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_MAX_DATA, frame.type);
  ASSERT_EQ (1000, frame.data.max_data.max_data);
  ASSERT_EQ (len, consumed);
}

TEST (frame_encode_max_data_large)
{
  uint8_t buf[16];
  size_t len;

  /* Encode MAX_DATA with large value requiring 8-byte varint */
  uint64_t max_val = 0x3FFFFFFFFFFFFFFF; /* 2^62 - 1 */
  len = SocketQUICFrame_encode_max_data (max_val, buf, sizeof (buf));
  ASSERT (len > 0);
  ASSERT_EQ (0x10, buf[0]);

  /* Verify round-trip */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (max_val, frame.data.max_data.max_data);
}

TEST (frame_encode_max_data_zero)
{
  uint8_t buf[16];
  size_t len;

  /* Zero is a valid max_data value */
  len = SocketQUICFrame_encode_max_data (0, buf, sizeof (buf));
  ASSERT (len > 0);
  ASSERT_EQ (2, len); /* Type byte + 1-byte varint */
  ASSERT_EQ (0x10, buf[0]);
  ASSERT_EQ (0x00, buf[1]);
}

TEST (frame_encode_max_data_buffer_too_small)
{
  uint8_t buf[1];
  size_t len;

  /* Buffer too small */
  len = SocketQUICFrame_encode_max_data (1000, buf, sizeof (buf));
  ASSERT_EQ (0, len);
}

TEST (frame_encode_max_data_null)
{
  size_t len;

  len = SocketQUICFrame_encode_max_data (1000, NULL, 16);
  ASSERT_EQ (0, len);
}

/* ============================================================================
 * MAX_STREAM_DATA Frame Tests (RFC 9000 Section 19.10)
 * ============================================================================
 */

TEST (frame_encode_max_stream_data_basic)
{
  uint8_t buf[32];
  size_t len;

  /* Encode MAX_STREAM_DATA for stream 4 with limit 2048 */
  len = SocketQUICFrame_encode_max_stream_data (4, 2048, buf, sizeof (buf));
  ASSERT (len > 0);
  ASSERT_EQ (0x11, buf[0]); /* Type: MAX_STREAM_DATA */

  /* Parse it back */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_MAX_STREAM_DATA, frame.type);
  ASSERT_EQ (4, frame.data.max_stream_data.stream_id);
  ASSERT_EQ (2048, frame.data.max_stream_data.max_data);
  ASSERT_EQ (len, consumed);
}

TEST (frame_encode_max_stream_data_large_stream_id)
{
  uint8_t buf[32];
  size_t len;

  /* Large stream ID */
  uint64_t stream_id = 0x123456;
  uint64_t max_data = 0xABCDEF;

  len = SocketQUICFrame_encode_max_stream_data (stream_id, max_data, buf,
                                                 sizeof (buf));
  ASSERT (len > 0);

  /* Verify round-trip */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (stream_id, frame.data.max_stream_data.stream_id);
  ASSERT_EQ (max_data, frame.data.max_stream_data.max_data);
}

TEST (frame_encode_max_stream_data_buffer_too_small)
{
  uint8_t buf[2];
  size_t len;

  len = SocketQUICFrame_encode_max_stream_data (4, 2048, buf, sizeof (buf));
  ASSERT_EQ (0, len);
}

TEST (frame_encode_max_stream_data_null)
{
  size_t len;

  len = SocketQUICFrame_encode_max_stream_data (4, 2048, NULL, 32);
  ASSERT_EQ (0, len);
}

/* ============================================================================
 * MAX_STREAMS Frame Tests (RFC 9000 Section 19.11)
 * ============================================================================
 */

TEST (frame_encode_max_streams_bidi)
{
  uint8_t buf[16];
  size_t len;

  /* Encode MAX_STREAMS bidirectional with limit 100 */
  len = SocketQUICFrame_encode_max_streams (1, 100, buf, sizeof (buf));
  ASSERT (len > 0);
  ASSERT_EQ (0x12, buf[0]); /* Type: MAX_STREAMS_BIDI */

  /* Parse it back */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_MAX_STREAMS_BIDI, frame.type);
  ASSERT_EQ (100, frame.data.max_streams.max_streams);
  ASSERT_EQ (1, frame.data.max_streams.is_bidi);
  ASSERT_EQ (len, consumed);
}

TEST (frame_encode_max_streams_uni)
{
  uint8_t buf[16];
  size_t len;

  /* Encode MAX_STREAMS unidirectional with limit 50 */
  len = SocketQUICFrame_encode_max_streams (0, 50, buf, sizeof (buf));
  ASSERT (len > 0);
  ASSERT_EQ (0x13, buf[0]); /* Type: MAX_STREAMS_UNI */

  /* Parse it back */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_MAX_STREAMS_UNI, frame.type);
  ASSERT_EQ (50, frame.data.max_streams.max_streams);
  ASSERT_EQ (0, frame.data.max_streams.is_bidi);
  ASSERT_EQ (len, consumed);
}

TEST (frame_encode_max_streams_large_value)
{
  uint8_t buf[16];
  size_t len;

  /* Large stream count */
  uint64_t max_streams = 0x1FFFFF;
  len = SocketQUICFrame_encode_max_streams (1, max_streams, buf, sizeof (buf));
  ASSERT (len > 0);

  /* Verify round-trip */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (max_streams, frame.data.max_streams.max_streams);
  ASSERT_EQ (1, frame.data.max_streams.is_bidi);
}

TEST (frame_encode_max_streams_buffer_too_small)
{
  uint8_t buf[1];
  size_t len;

  len = SocketQUICFrame_encode_max_streams (1, 100, buf, sizeof (buf));
  ASSERT_EQ (0, len);
}

TEST (frame_encode_max_streams_null)
{
  size_t len;

  len = SocketQUICFrame_encode_max_streams (1, 100, NULL, 16);
  ASSERT_EQ (0, len);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
