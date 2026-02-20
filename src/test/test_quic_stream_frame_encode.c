/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_stream_frame_encode.c
 * @brief Unit tests for QUIC STREAM frame encoding/decoding (RFC 9000 §19.8).
 */

#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICVarInt.h"
#include "test/Test.h"

#include <stdint.h>
#include <string.h>

TEST (frame_stream_encode_basic)
{
  uint8_t buf[128];
  const uint8_t data[] = "hello";
  size_t len;

  /* Encode basic STREAM frame (stream_id=0, offset=0, no FIN) */
  len = SocketQUICFrame_encode_stream (0, 0, data, 5, 0, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x0a, buf[0]); /* Frame type: STREAM | LEN (no OFF, no FIN) */

  /* Verify by parsing back */
  len = SocketQUICFrame_encode_stream (0, 0, data, 5, 0, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x0a, buf[0]);

  SocketQUICFrameStream_T frame;
  ssize_t consumed = SocketQUICFrame_decode_stream (buf, len, &frame);

  ASSERT (consumed > 0);
  ASSERT_EQ (0, frame.stream_id);
  ASSERT_EQ (0, frame.offset);
  ASSERT_EQ (5, frame.length);
  ASSERT_EQ (0, frame.has_fin);
  ASSERT (memcmp (frame.data, "hello", 5) == 0);
}

TEST (frame_stream_encode_with_offset)
{
  uint8_t buf[128];
  const uint8_t data[] = "world";
  size_t len;

  /* Encode STREAM frame with offset (stream_id=4, offset=100) */
  len = SocketQUICFrame_encode_stream (4, 100, data, 5, 0, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x0e, buf[0]); /* Frame type: STREAM | OFF | LEN (no FIN) */

  /* Verify by parsing */
  SocketQUICFrameStream_T frame;
  ssize_t consumed = SocketQUICFrame_decode_stream (buf, len, &frame);

  ASSERT (consumed > 0);
  ASSERT_EQ (4, frame.stream_id);
  ASSERT_EQ (100, frame.offset);
  ASSERT_EQ (5, frame.length);
  ASSERT_EQ (0, frame.has_fin);
  ASSERT (memcmp (frame.data, "world", 5) == 0);
}

TEST (frame_stream_encode_with_fin)
{
  uint8_t buf[128];
  const uint8_t data[] = "bye";
  size_t len;

  /* Encode STREAM frame with FIN flag */
  len = SocketQUICFrame_encode_stream (8, 0, data, 3, 1, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x0b, buf[0]); /* Frame type: STREAM | FIN | LEN */

  /* Verify by parsing */
  SocketQUICFrameStream_T frame;
  ssize_t consumed = SocketQUICFrame_decode_stream (buf, len, &frame);

  ASSERT (consumed > 0);
  ASSERT_EQ (8, frame.stream_id);
  ASSERT_EQ (0, frame.offset);
  ASSERT_EQ (3, frame.length);
  ASSERT_EQ (1, frame.has_fin);
  ASSERT (memcmp (frame.data, "bye", 3) == 0);
}

TEST (frame_stream_encode_all_flags)
{
  uint8_t buf[128];
  const uint8_t data[] = "test";
  size_t len;

  /* Encode with all flags: FIN | LEN | OFF */
  len = SocketQUICFrame_encode_stream (12, 500, data, 4, 1, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x0f, buf[0]); /* Frame type: STREAM | FIN | LEN | OFF */

  /* Verify by parsing */
  SocketQUICFrameStream_T frame;
  ssize_t consumed = SocketQUICFrame_decode_stream (buf, len, &frame);

  ASSERT (consumed > 0);
  ASSERT_EQ (12, frame.stream_id);
  ASSERT_EQ (500, frame.offset);
  ASSERT_EQ (4, frame.length);
  ASSERT_EQ (1, frame.has_fin);
  ASSERT (memcmp (frame.data, "test", 4) == 0);
}

TEST (frame_stream_encode_zero_length_with_fin)
{
  uint8_t buf[128];
  size_t len;

  /* Zero-length data with FIN is valid (signals stream close) */
  len = SocketQUICFrame_encode_stream (16, 1000, NULL, 0, 1, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x0f, buf[0]); /* STREAM | FIN | LEN | OFF */

  /* Verify by parsing */
  SocketQUICFrameStream_T frame;
  ssize_t consumed = SocketQUICFrame_decode_stream (buf, len, &frame);

  ASSERT (consumed > 0);
  ASSERT_EQ (16, frame.stream_id);
  ASSERT_EQ (1000, frame.offset);
  ASSERT_EQ (0, frame.length);
  ASSERT_EQ (1, frame.has_fin);
}

TEST (frame_stream_encode_buffer_too_small)
{
  uint8_t buf[8];
  const uint8_t data[100] = { 0 };
  size_t len;

  /* Try to encode frame larger than buffer */
  len = SocketQUICFrame_encode_stream (0, 0, data, 100, 0, buf, sizeof (buf));

  ASSERT_EQ (0, len); /* Should fail gracefully */

  len = SocketQUICFrame_encode_stream (8, 0, data, 3, 1, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x0b, buf[0]);

  SocketQUICFrameStream_T frame;
  ASSERT (SocketQUICFrame_decode_stream (buf, len, &frame) > 0);
  ASSERT_EQ (1, frame.has_fin);
}

TEST (frame_stream_encode_null_buffer)
{
  const uint8_t data[] = "test";

  /* NULL output buffer should return 0 */
  size_t len = SocketQUICFrame_encode_stream (0, 0, data, 4, 0, NULL, 128);
  ASSERT_EQ (0, len);
}

TEST (frame_stream_decode_null_params)
{
  uint8_t buf[] = { 0x08, 0x00 };
  SocketQUICFrameStream_T frame;

  /* NULL data - should return -QUIC_FRAME_ERROR_NULL */
  ssize_t result = SocketQUICFrame_decode_stream (NULL, sizeof (buf), &frame);
  ASSERT (result < 0);
  ASSERT_EQ (-(ssize_t)QUIC_FRAME_ERROR_NULL, result);

  /* NULL frame - should return -QUIC_FRAME_ERROR_NULL */
  result = SocketQUICFrame_decode_stream (buf, sizeof (buf), NULL);
  ASSERT (result < 0);
  ASSERT_EQ (-(ssize_t)QUIC_FRAME_ERROR_NULL, result);

  /* Zero length - should return -QUIC_FRAME_ERROR_NULL */
  result = SocketQUICFrame_decode_stream (buf, 0, &frame);
  ASSERT (result < 0);
  ASSERT_EQ (-(ssize_t)QUIC_FRAME_ERROR_NULL, result);
}

TEST (frame_stream_encode_overflow_protection)
{
  uint8_t buf[128];
  const uint8_t data[] = "test";

  /* Test integer overflow protection - SIZE_MAX should cause overflow check to
   * fail */
  size_t len = SocketQUICFrame_encode_stream (
      0, 0, data, SIZE_MAX, 0, buf, sizeof (buf));
  ASSERT_EQ (0, len); /* Should fail due to overflow */

  /* Test near-overflow case: SIZE_MAX - small value */
  len = SocketQUICFrame_encode_stream (
      0, 0, data, SIZE_MAX - 10, 0, buf, sizeof (buf));
  ASSERT_EQ (0, len); /* Should fail due to overflow */

  /* Test with offset to ensure header_size calculation works */
  len = SocketQUICFrame_encode_stream (
      100, 500, data, SIZE_MAX - 20, 0, buf, sizeof (buf));
  ASSERT_EQ (0, len); /* Should fail due to overflow */
}

TEST (frame_stream_decode_error_type_mismatch)
{
  /* Non-STREAM frame type (0x06 = CRYPTO) */
  uint8_t buf[] = { 0x06, 0x00 };
  SocketQUICFrameStream_T frame;

  ssize_t result = SocketQUICFrame_decode_stream (buf, sizeof (buf), &frame);
  ASSERT (result < 0);
  ASSERT_EQ (-(ssize_t)QUIC_FRAME_ERROR_TYPE, result);
}

TEST (frame_stream_decode_error_truncated)
{
  /* Valid STREAM frame type but truncated data */
  uint8_t buf[] = { 0x08 }; /* Missing stream ID */
  SocketQUICFrameStream_T frame;

  ssize_t result = SocketQUICFrame_decode_stream (buf, sizeof (buf), &frame);
  ASSERT (result < 0);
  /* Should be truncated error from parser */
  ASSERT_EQ (-(ssize_t)QUIC_FRAME_ERROR_TRUNCATED, result);
}

TEST (frame_stream_decode_error_distinction)
{
  SocketQUICFrameStream_T frame;
  ssize_t result;

  /* Test 1: NULL pointer error */
  result = SocketQUICFrame_decode_stream (NULL, 10, &frame);
  ASSERT_EQ (-(ssize_t)QUIC_FRAME_ERROR_NULL, result);

  /* Test 2: Wrong frame type error */
  uint8_t wrong_type[] = { 0x01, 0x00 }; /* PING frame */
  result
      = SocketQUICFrame_decode_stream (wrong_type, sizeof (wrong_type), &frame);
  ASSERT_EQ (-(ssize_t)QUIC_FRAME_ERROR_TYPE, result);

  /* Test 3: Truncated frame error */
  uint8_t truncated[] = { 0x08 }; /* STREAM frame, but no stream ID */
  result
      = SocketQUICFrame_decode_stream (truncated, sizeof (truncated), &frame);
  ASSERT_EQ (-(ssize_t)QUIC_FRAME_ERROR_TRUNCATED, result);

  /* Verify errors are distinct */
  ASSERT (QUIC_FRAME_ERROR_NULL != QUIC_FRAME_ERROR_TYPE);
  ASSERT (QUIC_FRAME_ERROR_NULL != QUIC_FRAME_ERROR_TRUNCATED);
  ASSERT (QUIC_FRAME_ERROR_TYPE != QUIC_FRAME_ERROR_TRUNCATED);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
