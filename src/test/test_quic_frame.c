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

TEST (frame_stream_overflow_32bit)
{
  /* Craft a STREAM frame with length > SIZE_MAX on 32-bit systems.
   * Frame format: type (1 byte) | stream_id (varint) | length (varint)
   * Type 0x0a = STREAM with LEN flag set
   * Stream ID = 0 (1 byte: 0x00)
   * Length = 0x100000000 (5 bytes as 8-byte varint: 0xc0 0x00 0x00 0x01 0x00 0x00 0x00 0x00)
   *
   * This value is 2^32, which exceeds SIZE_MAX (0xFFFFFFFF) on 32-bit systems
   * but fits in uint64_t. This tests the overflow check added for issue #741.
   */
  uint8_t data[] = {
    0x0a,                                           /* STREAM with LEN flag */
    0x00,                                           /* stream_id = 0 */
    0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00  /* length = 2^32 */
  };
  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (data, sizeof (data), &frame, &consumed);

  /* On 32-bit systems where SIZE_MAX < 2^32, should return overflow error.
   * On 64-bit systems, will return TRUNCATED (not enough data in buffer).
   * Both are acceptable - the key is no silent truncation occurs. */
#if SIZE_MAX < UINT64_MAX
  ASSERT_EQ (QUIC_FRAME_ERROR_OVERFLOW, res);
#else
  /* On 64-bit, length is valid but buffer is too small */
  ASSERT_EQ (QUIC_FRAME_ERROR_TRUNCATED, res);
#endif
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

TEST (frame_handshake_done_encode)
{
  uint8_t encoded[1];

  size_t len = SocketQUICFrame_encode_handshake_done (encoded);

  ASSERT_EQ (1, len);
  ASSERT_EQ (0x1e, encoded[0]);
}

TEST (frame_handshake_done_encode_null_check)
{
  /* Null output pointer */
  ASSERT_EQ (0, SocketQUICFrame_encode_handshake_done (NULL));
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

/* ============================================================================
 * CONNECTION_CLOSE frame encoding tests (RFC 9000 Section 19.19)
 * ============================================================================
 */

TEST (frame_encode_connection_close_transport_basic)
{
  uint8_t buf[256];
  size_t len = SocketQUICFrame_encode_connection_close_transport (
      0x0a,   /* error_code: PROTOCOL_VIOLATION */
      0x06,   /* frame_type: CRYPTO */
      "test", /* reason */
      buf, sizeof (buf));

  ASSERT (len > 0);

  /* Parse it back to verify encoding */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_CONNECTION_CLOSE, frame.type);
  ASSERT_EQ (0x0a, frame.data.connection_close.error_code);
  ASSERT_EQ (0x06, frame.data.connection_close.frame_type);
  ASSERT_EQ (4, frame.data.connection_close.reason_length);
  ASSERT_EQ (0, frame.data.connection_close.is_app_error);
  ASSERT (memcmp (frame.data.connection_close.reason, "test", 4) == 0);
  ASSERT_EQ (len, consumed);
}

TEST (frame_encode_connection_close_transport_no_reason)
{
  uint8_t buf[256];
  size_t len = SocketQUICFrame_encode_connection_close_transport (
      0x01,  /* error_code: INTERNAL_ERROR */
      0x00,  /* frame_type: none */
      NULL,  /* no reason */
      buf, sizeof (buf));

  ASSERT (len > 0);

  /* Parse it back */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_CONNECTION_CLOSE, frame.type);
  ASSERT_EQ (0x01, frame.data.connection_close.error_code);
  ASSERT_EQ (0x00, frame.data.connection_close.frame_type);
  ASSERT_EQ (0, frame.data.connection_close.reason_length);
  ASSERT_EQ (0, frame.data.connection_close.is_app_error);
}

TEST (frame_encode_connection_close_transport_long_reason)
{
  uint8_t buf[512];
  const char *reason = "This is a longer error message to test handling of "
                       "variable-length reason phrases in CONNECTION_CLOSE";

  size_t len = SocketQUICFrame_encode_connection_close_transport (
      0x0c,   /* error_code: FLOW_CONTROL_ERROR */
      0x10,   /* frame_type: MAX_DATA */
      reason, buf, sizeof (buf));

  ASSERT (len > 0);

  /* Parse it back */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (strlen (reason), (size_t)frame.data.connection_close.reason_length);
  ASSERT (
      memcmp (frame.data.connection_close.reason, reason, strlen (reason))
      == 0);
}

TEST (frame_encode_connection_close_app_basic)
{
  uint8_t buf[256];
  size_t len = SocketQUICFrame_encode_connection_close_app (
      1000,          /* error_code: application-defined */
      "user abort",  /* reason */
      buf, sizeof (buf));

  ASSERT (len > 0);

  /* Parse it back */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_CONNECTION_CLOSE_APP, frame.type);
  ASSERT_EQ (1000, frame.data.connection_close.error_code);
  ASSERT_EQ (10, frame.data.connection_close.reason_length);
  ASSERT_EQ (1, frame.data.connection_close.is_app_error);
  ASSERT (memcmp (frame.data.connection_close.reason, "user abort", 10) == 0);
}

TEST (frame_encode_connection_close_app_no_reason)
{
  uint8_t buf[256];
  size_t len = SocketQUICFrame_encode_connection_close_app (
      42,   /* error_code */
      NULL, /* no reason */
      buf, sizeof (buf));

  ASSERT (len > 0);

  /* Parse it back */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_CONNECTION_CLOSE_APP, frame.type);
  ASSERT_EQ (42, frame.data.connection_close.error_code);
  ASSERT_EQ (0, frame.data.connection_close.reason_length);
  ASSERT_EQ (1, frame.data.connection_close.is_app_error);
}

TEST (frame_encode_connection_close_buffer_too_small)
{
  uint8_t buf[8]; /* Too small */
  size_t len = SocketQUICFrame_encode_connection_close_transport (
      0x01, 0x00, "this reason is too long for the buffer", buf,
      sizeof (buf));

  /* Should fail gracefully */
  ASSERT_EQ (0, len);
}

TEST (frame_encode_connection_close_null_buffer)
{
  size_t len = SocketQUICFrame_encode_connection_close_transport (
      0x01, 0x00, "test", NULL, 256);

  ASSERT_EQ (0, len);
}

TEST (frame_encode_connection_close_large_error_code)
{
  uint8_t buf[256];
  /* Use a large error code that requires multi-byte varint encoding */
  uint64_t large_code = 0x123456;

  size_t len = SocketQUICFrame_encode_connection_close_transport (
      large_code, 0x1a, /* PATH_CHALLENGE */
      "large code", buf, sizeof (buf));

  ASSERT (len > 0);

  /* Parse it back */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (large_code, frame.data.connection_close.error_code);
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

/* ============================================================================
 * Overflow Protection Tests (32-bit safety)
 * ============================================================================
 */

TEST (frame_crypto_overflow_32bit)
{
  /* On 32-bit systems, a uint64_t length > SIZE_MAX should be rejected.
   * We simulate this by creating a frame with length that would overflow
   * when cast to size_t on 32-bit (SIZE_MAX = 0xFFFFFFFF).
   * On 64-bit systems this test will pass trivially since SIZE_MAX == UINT64_MAX.
   */
  uint8_t buf[512];
  size_t pos = 0;

  /* Encode CRYPTO frame type */
  buf[pos++] = 0x06;

  /* Encode offset = 0 (varint) */
  buf[pos++] = 0x00;

  /* Encode length as 8-byte varint with value > 32-bit SIZE_MAX
   * Format: 11xxxxxx ... (8 bytes total)
   * Value: 0x0000000100000000 (4GB + 1)
   */
  buf[pos++] = 0xc0;  /* 11000000 - 8-byte varint marker */
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x01;  /* High 32 bits = 1 */
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;  /* Low 32 bits = 0 */

  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, pos, &frame, &consumed);

  /* On 32-bit systems, this should return OVERFLOW error.
   * On 64-bit systems with SIZE_MAX == UINT64_MAX, it will return TRUNCATED
   * because we don't have 4GB of actual data in the buffer.
   */
#if SIZE_MAX < UINT64_MAX
  ASSERT_EQ (QUIC_FRAME_ERROR_OVERFLOW, res);
#else
  /* On 64-bit, truncation check happens first */
  ASSERT_EQ (QUIC_FRAME_ERROR_TRUNCATED, res);
#endif
}

TEST (frame_new_token_overflow_32bit)
{
  /* Similar test for NEW_TOKEN frame */
  uint8_t buf[512];
  size_t pos = 0;

  /* Encode NEW_TOKEN frame type */
  buf[pos++] = 0x07;

  /* Encode token_length as 8-byte varint > SIZE_MAX on 32-bit */
  buf[pos++] = 0xc0;  /* 8-byte varint */
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x01;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;

  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, pos, &frame, &consumed);

#if SIZE_MAX < UINT64_MAX
  ASSERT_EQ (QUIC_FRAME_ERROR_OVERFLOW, res);
#else
  ASSERT_EQ (QUIC_FRAME_ERROR_TRUNCATED, res);
#endif
}

TEST (frame_stream_overflow_32bit)
{
  /* Test STREAM frame with length > SIZE_MAX on 32-bit */
  uint8_t buf[512];
  size_t pos = 0;

  /* STREAM frame with FIN, LEN, and OFF flags (0x0f) */
  buf[pos++] = 0x0f;

  /* Stream ID = 0 */
  buf[pos++] = 0x00;

  /* Offset = 0 */
  buf[pos++] = 0x00;

  /* Length as 8-byte varint > SIZE_MAX on 32-bit */
  buf[pos++] = 0xc0;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x01;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;

  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, pos, &frame, &consumed);

#if SIZE_MAX < UINT64_MAX
  ASSERT_EQ (QUIC_FRAME_ERROR_OVERFLOW, res);
#else
  ASSERT_EQ (QUIC_FRAME_ERROR_TRUNCATED, res);
#endif
}

TEST (frame_connection_close_overflow_32bit)
{
  /* Test CONNECTION_CLOSE with reason_length > SIZE_MAX on 32-bit */
  uint8_t buf[512];
  size_t pos = 0;

  /* CONNECTION_CLOSE frame type */
  buf[pos++] = 0x1c;

  /* Error code = 0 */
  buf[pos++] = 0x00;

  /* Frame type = 0 */
  buf[pos++] = 0x00;

  /* Reason length as 8-byte varint > SIZE_MAX on 32-bit */
  buf[pos++] = 0xc0;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x01;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;

  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, pos, &frame, &consumed);

#if SIZE_MAX < UINT64_MAX
  ASSERT_EQ (QUIC_FRAME_ERROR_OVERFLOW, res);
#else
  ASSERT_EQ (QUIC_FRAME_ERROR_TRUNCATED, res);
#endif
}

TEST (frame_datagram_overflow_32bit)
{
  /* Test DATAGRAM frame with length > SIZE_MAX on 32-bit */
  uint8_t buf[512];
  size_t pos = 0;

  /* DATAGRAM_LEN frame type (with explicit length) */
  buf[pos++] = 0x31;

  /* Length as 8-byte varint > SIZE_MAX on 32-bit */
  buf[pos++] = 0xc0;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x01;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;
  buf[pos++] = 0x00;

  SocketQUICFrame_T frame;
  size_t consumed;

  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, pos, &frame, &consumed);

#if SIZE_MAX < UINT64_MAX
  ASSERT_EQ (QUIC_FRAME_ERROR_OVERFLOW, res);
#else
  ASSERT_EQ (QUIC_FRAME_ERROR_TRUNCATED, res);
#endif
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
