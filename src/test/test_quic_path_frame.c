/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_path_frame.c
 * @brief Unit tests for QUIC PATH_CHALLENGE and PATH_RESPONSE frame
 * encoding/decoding (RFC 9000 §19.17-19.18).
 */

#include "quic/SocketQUICFrame.h"
#include "test/Test.h"

#include <string.h>

TEST (frame_path_challenge_encode_basic)
{
  uint8_t buf[128];
  const uint8_t data[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  size_t len;

  /* Encode basic PATH_CHALLENGE frame */
  len = SocketQUICFrame_encode_path_challenge (data, buf, sizeof (buf));

  ASSERT_EQ (9, len); /* 1 byte type + 8 bytes data */
  ASSERT_EQ (QUIC_FRAME_PATH_CHALLENGE, buf[0]); /* Frame type: 0x1a */

  /* Verify data was copied correctly */
  ASSERT (memcmp (buf + 1, data, 8) == 0);
}

TEST (frame_path_challenge_encode_roundtrip)
{
  uint8_t buf[128];
  const uint8_t original_data[8]
      = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 };
  uint8_t decoded_data[8];

  /* Encode */
  size_t len = SocketQUICFrame_encode_path_challenge (
      original_data, buf, sizeof (buf));
  ASSERT_EQ (9, len);

  /* Decode */
  int res = SocketQUICFrame_decode_path_challenge (buf, len, decoded_data);
  ASSERT_EQ (9, res);

  /* Verify roundtrip */
  ASSERT (memcmp (decoded_data, original_data, 8) == 0);
}

TEST (frame_path_challenge_encode_buffer_too_small)
{
  uint8_t buf[8]; /* Only 8 bytes, need 9 */
  const uint8_t data[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

  /* Try to encode into insufficient buffer */
  size_t len = SocketQUICFrame_encode_path_challenge (data, buf, sizeof (buf));

  ASSERT_EQ (0, len); /* Should fail gracefully */
}

TEST (frame_path_challenge_encode_exact_buffer_size)
{
  uint8_t buf[9]; /* Exactly 9 bytes */
  const uint8_t data[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

  /* Encode with exact buffer size */
  size_t len = SocketQUICFrame_encode_path_challenge (data, buf, sizeof (buf));

  ASSERT_EQ (9, len); /* Should succeed */
  ASSERT_EQ (QUIC_FRAME_PATH_CHALLENGE, buf[0]);
  ASSERT (memcmp (buf + 1, data, 8) == 0);
}

TEST (frame_path_challenge_encode_null_data)
{
  uint8_t buf[128];

  /* NULL data pointer should fail */
  size_t len = SocketQUICFrame_encode_path_challenge (NULL, buf, sizeof (buf));
  ASSERT_EQ (0, len);
}

TEST (frame_path_challenge_encode_null_buffer)
{
  const uint8_t data[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

  /* NULL output buffer should fail */
  size_t len = SocketQUICFrame_encode_path_challenge (data, NULL, 128);
  ASSERT_EQ (0, len);
}

TEST (frame_path_challenge_encode_zero_buffer_size)
{
  uint8_t buf[128];
  const uint8_t data[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

  /* Zero buffer size should fail */
  size_t len = SocketQUICFrame_encode_path_challenge (data, buf, 0);
  ASSERT_EQ (0, len);
}

TEST (frame_path_response_encode_basic)
{
  uint8_t buf[128];
  const uint8_t data[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  size_t len;

  /* Encode basic PATH_RESPONSE frame */
  len = SocketQUICFrame_encode_path_response (data, buf, sizeof (buf));

  ASSERT_EQ (9, len);                           /* 1 byte type + 8 bytes data */
  ASSERT_EQ (QUIC_FRAME_PATH_RESPONSE, buf[0]); /* Frame type: 0x1b */

  /* Verify data was copied correctly */
  ASSERT (memcmp (buf + 1, data, 8) == 0);
}

TEST (frame_path_response_encode_roundtrip)
{
  uint8_t buf[128];
  const uint8_t original_data[8]
      = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 };
  uint8_t decoded_data[8];

  /* Encode */
  size_t len
      = SocketQUICFrame_encode_path_response (original_data, buf, sizeof (buf));
  ASSERT_EQ (9, len);

  /* Decode */
  int res = SocketQUICFrame_decode_path_response (buf, len, decoded_data);
  ASSERT_EQ (9, res);

  /* Verify roundtrip */
  ASSERT (memcmp (decoded_data, original_data, 8) == 0);
}

TEST (frame_path_response_encode_buffer_too_small)
{
  uint8_t buf[8]; /* Only 8 bytes, need 9 */
  const uint8_t data[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

  /* Try to encode into insufficient buffer */
  size_t len = SocketQUICFrame_encode_path_response (data, buf, sizeof (buf));

  ASSERT_EQ (0, len); /* Should fail gracefully */
}

TEST (frame_path_response_encode_exact_buffer_size)
{
  uint8_t buf[9]; /* Exactly 9 bytes */
  const uint8_t data[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

  /* Encode with exact buffer size */
  size_t len = SocketQUICFrame_encode_path_response (data, buf, sizeof (buf));

  ASSERT_EQ (9, len); /* Should succeed */
  ASSERT_EQ (QUIC_FRAME_PATH_RESPONSE, buf[0]);
  ASSERT (memcmp (buf + 1, data, 8) == 0);
}

TEST (frame_path_response_encode_null_data)
{
  uint8_t buf[128];

  /* NULL data pointer should fail */
  size_t len = SocketQUICFrame_encode_path_response (NULL, buf, sizeof (buf));
  ASSERT_EQ (0, len);
}

TEST (frame_path_response_encode_null_buffer)
{
  const uint8_t data[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

  /* NULL output buffer should fail */
  size_t len = SocketQUICFrame_encode_path_response (data, NULL, 128);
  ASSERT_EQ (0, len);
}

TEST (frame_path_response_encode_zero_buffer_size)
{
  uint8_t buf[128];
  const uint8_t data[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

  /* Zero buffer size should fail */
  size_t len = SocketQUICFrame_encode_path_response (data, buf, 0);
  ASSERT_EQ (0, len);
}

TEST (frame_path_challenge_response_echo)
{
  uint8_t challenge_buf[128];
  uint8_t response_buf[128];
  const uint8_t challenge_data[8]
      = { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
  uint8_t decoded_data[8];

  /* Encode PATH_CHALLENGE */
  size_t challenge_len = SocketQUICFrame_encode_path_challenge (
      challenge_data, challenge_buf, sizeof (challenge_buf));
  ASSERT_EQ (9, challenge_len);

  /* Decode the challenge */
  int res = SocketQUICFrame_decode_path_challenge (
      challenge_buf, challenge_len, decoded_data);
  ASSERT_EQ (9, res);

  /* Encode PATH_RESPONSE with the same data (echo) */
  size_t response_len = SocketQUICFrame_encode_path_response (
      decoded_data, response_buf, sizeof (response_buf));
  ASSERT_EQ (9, response_len);

  /* Verify frame types are different */
  ASSERT_EQ (QUIC_FRAME_PATH_CHALLENGE, challenge_buf[0]);
  ASSERT_EQ (QUIC_FRAME_PATH_RESPONSE, response_buf[0]);

  /* Verify data is the same */
  ASSERT (memcmp (challenge_buf + 1, response_buf + 1, 8) == 0);

  /* Decode response and verify */
  uint8_t response_data[8];
  res = SocketQUICFrame_decode_path_response (
      response_buf, response_len, response_data);
  ASSERT_EQ (9, res);
  ASSERT (memcmp (response_data, challenge_data, 8) == 0);
}

TEST (frame_path_challenge_buffer_validation_issue_950)
{
  const uint8_t data[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  uint8_t buf[128];

  /* Test all buffer sizes from 0 to 10 */
  for (size_t buf_size = 0; buf_size < 10; buf_size++)
    {
      size_t len = SocketQUICFrame_encode_path_challenge (data, buf, buf_size);

      if (buf_size < 9)
        {
          /* Should fail for buffers smaller than 9 bytes */
          ASSERT_EQ (0, len);
        }
      else
        {
          /* Should succeed for buffers of 9 or more bytes */
          ASSERT_EQ (9, len);
          ASSERT_EQ (QUIC_FRAME_PATH_CHALLENGE, buf[0]);
        }
    }
}

TEST (frame_path_response_buffer_validation_issue_950)
{
  const uint8_t data[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
  uint8_t buf[128];

  /* Test all buffer sizes from 0 to 10 */
  for (size_t buf_size = 0; buf_size < 10; buf_size++)
    {
      size_t len = SocketQUICFrame_encode_path_response (data, buf, buf_size);

      if (buf_size < 9)
        {
          /* Should fail for buffers smaller than 9 bytes */
          ASSERT_EQ (0, len);
        }
      else
        {
          /* Should succeed for buffers of 9 or more bytes */
          ASSERT_EQ (9, len);
          ASSERT_EQ (QUIC_FRAME_PATH_RESPONSE, buf[0]);
        }
    }
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
