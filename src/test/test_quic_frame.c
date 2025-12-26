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

TEST (frame_path_response)
{
  uint8_t data[] = { 0x1b, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, sizeof (data), &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_PATH_RESPONSE, frame.type);
  ASSERT (memcmp (frame.data.path_response.data,
                  "\x11\x22\x33\x44\x55\x66\x77\x88", 8) == 0);
  ASSERT_EQ (9, consumed);
}

TEST (frame_path_challenge_encode)
{
  uint8_t challenge_data[8] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11 };
  uint8_t encoded[9];

  size_t len = SocketQUICFrame_encode_path_challenge (challenge_data, encoded);

  ASSERT_EQ (9, len);
  ASSERT_EQ (0x1a, encoded[0]);
  ASSERT (memcmp (encoded + 1, challenge_data, 8) == 0);
}

TEST (frame_path_response_encode)
{
  uint8_t response_data[8] = { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
  uint8_t encoded[9];

  size_t len = SocketQUICFrame_encode_path_response (response_data, encoded);

  ASSERT_EQ (9, len);
  ASSERT_EQ (0x1b, encoded[0]);
  ASSERT (memcmp (encoded + 1, response_data, 8) == 0);
}

TEST (frame_path_challenge_decode)
{
  uint8_t wire_data[] = { 0x1a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  uint8_t decoded[8];

  int consumed = SocketQUICFrame_decode_path_challenge (wire_data, sizeof (wire_data), decoded);

  ASSERT_EQ (9, consumed);
  ASSERT (memcmp (decoded, "\x01\x02\x03\x04\x05\x06\x07\x08", 8) == 0);
}

TEST (frame_path_response_decode)
{
  uint8_t wire_data[] = { 0x1b, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11 };
  uint8_t decoded[8];

  int consumed = SocketQUICFrame_decode_path_response (wire_data, sizeof (wire_data), decoded);

  ASSERT_EQ (9, consumed);
  ASSERT (memcmp (decoded, "\xaa\xbb\xcc\xdd\xee\xff\x00\x11", 8) == 0);
}

TEST (frame_path_encode_decode_roundtrip)
{
  uint8_t original[8] = { 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49 };
  uint8_t encoded[9];
  uint8_t decoded[8];

  /* Encode */
  size_t enc_len = SocketQUICFrame_encode_path_challenge (original, encoded);
  ASSERT_EQ (9, enc_len);

  /* Decode */
  int dec_len = SocketQUICFrame_decode_path_challenge (encoded, enc_len, decoded);
  ASSERT_EQ (9, dec_len);

  /* Verify roundtrip */
  ASSERT (memcmp (original, decoded, 8) == 0);
}

TEST (frame_path_encode_null_checks)
{
  uint8_t data[8] = { 0 };
  uint8_t out[9];

  /* Null data pointer */
  ASSERT_EQ (0, SocketQUICFrame_encode_path_challenge (NULL, out));
  ASSERT_EQ (0, SocketQUICFrame_encode_path_response (NULL, out));

  /* Null output pointer */
  ASSERT_EQ (0, SocketQUICFrame_encode_path_challenge (data, NULL));
  ASSERT_EQ (0, SocketQUICFrame_encode_path_response (data, NULL));
}

TEST (frame_path_decode_null_checks)
{
  uint8_t wire[9] = { 0x1a, 0, 0, 0, 0, 0, 0, 0, 0 };
  uint8_t data[8];

  /* Null input pointer */
  ASSERT_EQ (-1, SocketQUICFrame_decode_path_challenge (NULL, 9, data));
  ASSERT_EQ (-1, SocketQUICFrame_decode_path_response (NULL, 9, data));

  /* Null data pointer */
  ASSERT_EQ (-1, SocketQUICFrame_decode_path_challenge (wire, 9, NULL));
  ASSERT_EQ (-1, SocketQUICFrame_decode_path_response (wire, 9, NULL));

  /* Truncated input */
  ASSERT_EQ (-1, SocketQUICFrame_decode_path_challenge (wire, 8, data));
  ASSERT_EQ (-1, SocketQUICFrame_decode_path_response (wire, 8, data));
}

TEST (frame_path_decode_wrong_type)
{
  uint8_t wrong_type[9] = { 0x1b, 0, 0, 0, 0, 0, 0, 0, 0 };  /* PATH_RESPONSE type */
  uint8_t data[8];

  /* Try to decode PATH_RESPONSE as PATH_CHALLENGE */
  ASSERT_EQ (-1, SocketQUICFrame_decode_path_challenge (wrong_type, 9, data));

  /* Try to decode PATH_CHALLENGE as PATH_RESPONSE */
  wrong_type[0] = 0x1a;
  ASSERT_EQ (-1, SocketQUICFrame_decode_path_response (wrong_type, 9, data));
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

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
