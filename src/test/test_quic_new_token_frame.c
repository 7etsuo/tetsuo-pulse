/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_new_token_frame.c
 * @brief Unit tests for QUIC NEW_TOKEN frame encoding/decoding (RFC 9000 §19.7).
 */

#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICVarInt.h"
#include "test/Test.h"

#include <string.h>

/* ============================================================================
 * NEW_TOKEN Frame Encoding Tests
 * ============================================================================
 */

TEST (frame_new_token_encode_basic)
{
  uint8_t buf[128];
  const uint8_t token[] = "test-token-1234";
  size_t token_len = strlen ((const char *)token);
  size_t len;

  /* Encode basic NEW_TOKEN frame */
  len = SocketQUICFrame_encode_new_token (token, token_len, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (QUIC_FRAME_NEW_TOKEN, buf[0]); /* Frame type: 0x07 */

  /* Verify by decoding back */
  uint8_t decoded_token[128];
  size_t decoded_len = sizeof (decoded_token);

  int res
      = SocketQUICFrame_decode_new_token (buf, len, decoded_token, &decoded_len);

  ASSERT_EQ (0, res);
  ASSERT_EQ (token_len, decoded_len);
  ASSERT (memcmp (decoded_token, token, token_len) == 0);
}

TEST (frame_new_token_encode_single_byte)
{
  uint8_t buf[128];
  const uint8_t token[] = "x";
  size_t len;

  /* Single-byte token */
  len = SocketQUICFrame_encode_new_token (token, 1, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (QUIC_FRAME_NEW_TOKEN, buf[0]);

  /* Decode and verify */
  uint8_t decoded_token[128];
  size_t decoded_len = sizeof (decoded_token);

  ASSERT_EQ (0, SocketQUICFrame_decode_new_token (buf, len, decoded_token,
                                                   &decoded_len));
  ASSERT_EQ (1, decoded_len);
  ASSERT_EQ ('x', decoded_token[0]);
}

TEST (frame_new_token_encode_long_token)
{
  uint8_t buf[256];
  uint8_t token[128];
  size_t len;

  /* Fill token with pattern */
  for (size_t i = 0; i < sizeof (token); i++)
    token[i] = (uint8_t)(i & 0xff);

  len = SocketQUICFrame_encode_new_token (token, sizeof (token), buf,
                                           sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (QUIC_FRAME_NEW_TOKEN, buf[0]);

  /* Decode and verify */
  uint8_t decoded_token[256];
  size_t decoded_len = sizeof (decoded_token);

  ASSERT_EQ (0, SocketQUICFrame_decode_new_token (buf, len, decoded_token,
                                                   &decoded_len));
  ASSERT_EQ (sizeof (token), decoded_len);
  ASSERT (memcmp (decoded_token, token, sizeof (token)) == 0);
}

TEST (frame_new_token_encode_empty_invalid)
{
  uint8_t buf[128];
  const uint8_t token[] = "test";

  /* Empty token is invalid per RFC 9000 Section 19.7 */
  size_t len = SocketQUICFrame_encode_new_token (token, 0, buf, sizeof (buf));

  ASSERT_EQ (0, len); /* Should fail */
}

TEST (frame_new_token_encode_buffer_too_small)
{
  uint8_t buf[8];
  const uint8_t token[100] = { 0 };

  /* Try to encode token larger than buffer */
  size_t len
      = SocketQUICFrame_encode_new_token (token, sizeof (token), buf,
                                           sizeof (buf));

  ASSERT_EQ (0, len); /* Should fail gracefully */
}

TEST (frame_new_token_encode_null_buffer)
{
  const uint8_t token[] = "test";

  /* NULL output buffer should return 0 */
  size_t len = SocketQUICFrame_encode_new_token (token, 4, NULL, 128);
  ASSERT_EQ (0, len);
}

TEST (frame_new_token_encode_null_token)
{
  uint8_t buf[128];

  /* NULL token with non-zero length should fail */
  size_t len = SocketQUICFrame_encode_new_token (NULL, 10, buf, sizeof (buf));
  ASSERT_EQ (0, len);
}

TEST (frame_new_token_roundtrip)
{
  uint8_t buf[128];
  const uint8_t original_token[] = "roundtrip-test-token-12345";
  size_t original_len = strlen ((const char *)original_token);

  /* Encode */
  size_t encoded_len
      = SocketQUICFrame_encode_new_token (original_token, original_len, buf,
                                           sizeof (buf));
  ASSERT (encoded_len > 0);

  /* Decode */
  uint8_t decoded_token[128];
  size_t decoded_len = sizeof (decoded_token);

  ASSERT_EQ (0, SocketQUICFrame_decode_new_token (buf, encoded_len,
                                                   decoded_token, &decoded_len));

  /* Verify roundtrip */
  ASSERT_EQ (original_len, decoded_len);
  ASSERT (memcmp (decoded_token, original_token, original_len) == 0);
}

/* ============================================================================
 * NEW_TOKEN Frame Decoding Tests
 * ============================================================================
 */

TEST (frame_new_token_decode_wrong_type)
{
  uint8_t buf[128];
  uint8_t token[128];
  size_t token_len = sizeof (token);

  /* Not a NEW_TOKEN frame */
  buf[0] = QUIC_FRAME_PADDING;
  buf[1] = 0x04;
  memcpy (buf + 2, "test", 4);

  int res = SocketQUICFrame_decode_new_token (buf, 6, token, &token_len);
  ASSERT_EQ (-1, res); /* Should fail */
}

TEST (frame_new_token_decode_truncated)
{
  uint8_t buf[128];
  uint8_t token[128];
  size_t token_len = sizeof (token);

  /* Valid header but truncated data */
  buf[0] = QUIC_FRAME_NEW_TOKEN;
  buf[1] = 0x10; /* Claims 16 bytes */
  memcpy (buf + 2, "short", 5);

  int res = SocketQUICFrame_decode_new_token (buf, 7, token, &token_len);
  ASSERT_EQ (-1, res); /* Should fail */
}

TEST (frame_new_token_decode_null_params)
{
  uint8_t buf[] = { QUIC_FRAME_NEW_TOKEN, 0x04, 't', 'e', 's', 't' };
  uint8_t token[128];
  size_t token_len = sizeof (token);

  /* NULL data */
  ASSERT_EQ (-1, SocketQUICFrame_decode_new_token (NULL, sizeof (buf), token,
                                                    &token_len));

  /* NULL token output */
  ASSERT_EQ (-1,
             SocketQUICFrame_decode_new_token (buf, sizeof (buf), NULL,
                                                &token_len));

  /* NULL token_len */
  ASSERT_EQ (-1,
             SocketQUICFrame_decode_new_token (buf, sizeof (buf), token, NULL));

  /* Zero length */
  ASSERT_EQ (-1,
             SocketQUICFrame_decode_new_token (buf, 0, token, &token_len));
}

TEST (frame_new_token_decode_output_buffer_too_small)
{
  uint8_t buf[128];
  uint8_t token[4]; /* Small buffer */
  size_t token_len = sizeof (token);
  const uint8_t large_token[100] = { 0 };

  /* Encode large token */
  size_t encoded_len = SocketQUICFrame_encode_new_token (large_token,
                                                          sizeof (large_token),
                                                          buf, sizeof (buf));
  ASSERT (encoded_len > 0);

  /* Try to decode into small buffer */
  int res
      = SocketQUICFrame_decode_new_token (buf, encoded_len, token, &token_len);
  ASSERT_EQ (-1, res); /* Should fail */
}

TEST (frame_new_token_varint_token_length)
{
  uint8_t buf[256];
  uint8_t token[100];
  size_t token_len;

  /* Fill token with pattern */
  for (size_t i = 0; i < sizeof (token); i++)
    token[i] = (uint8_t)(i + 1);

  /* Encode token requiring 2-byte varint length (64-16383) */
  size_t encoded_len
      = SocketQUICFrame_encode_new_token (token, sizeof (token), buf,
                                           sizeof (buf));
  ASSERT (encoded_len > 0);

  /* Verify the length field uses correct varint encoding */
  ASSERT_EQ (QUIC_FRAME_NEW_TOKEN, buf[0]);

  /* Decode token length varint */
  uint64_t decoded_token_len;
  size_t consumed;
  SocketQUICVarInt_Result res
      = SocketQUICVarInt_decode (buf + 1, encoded_len - 1, &decoded_token_len,
                                  &consumed);

  ASSERT_EQ (QUIC_VARINT_OK, res);
  ASSERT_EQ (sizeof (token), decoded_token_len);

  /* Full decode roundtrip */
  uint8_t decoded_token[256];
  token_len = sizeof (decoded_token);

  ASSERT_EQ (0, SocketQUICFrame_decode_new_token (buf, encoded_len,
                                                   decoded_token, &token_len));
  ASSERT_EQ (sizeof (token), token_len);
  ASSERT (memcmp (decoded_token, token, sizeof (token)) == 0);
}

TEST (frame_new_token_integration_with_parser)
{
  uint8_t buf[128];
  const uint8_t token[] = "integration-test-token";
  size_t token_len = strlen ((const char *)token);

  /* Encode using encode function */
  size_t encoded_len
      = SocketQUICFrame_encode_new_token (token, token_len, buf, sizeof (buf));
  ASSERT (encoded_len > 0);

  /* Parse using general frame parser */
  SocketQUICFrame_T frame;
  size_t consumed;
  SocketQUICFrame_Result res
      = SocketQUICFrame_parse (buf, encoded_len, &frame, &consumed);

  ASSERT_EQ (QUIC_FRAME_OK, res);
  ASSERT_EQ (QUIC_FRAME_NEW_TOKEN, frame.type);
  ASSERT_EQ (token_len, frame.data.new_token.token_length);
  ASSERT (memcmp (frame.data.new_token.token, token, token_len) == 0);
  ASSERT_EQ (encoded_len, consumed);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
