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
#include "test/Test.h"

#include <string.h>

TEST (frame_stream_encode_basic)
{
  uint8_t buf[128];
  const uint8_t data[] = "hello";
  size_t len;

  len = SocketQUICFrame_encode_stream (0, 0, data, 5, 0, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x0a, buf[0]);

  SocketQUICFrameStream_T frame;
  int consumed = SocketQUICFrame_decode_stream (buf, len, &frame);

  ASSERT (consumed > 0);
  ASSERT_EQ (0, frame.stream_id);
  ASSERT_EQ (0, frame.offset);
  ASSERT_EQ (5, frame.length);
  ASSERT_EQ (0, frame.has_fin);
  ASSERT (memcmp (frame.data, "hello", 5) == 0);
}

TEST (frame_stream_encode_with_fin)
{
  uint8_t buf[128];
  const uint8_t data[] = "bye";

  size_t len = SocketQUICFrame_encode_stream (8, 0, data, 3, 1, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x0b, buf[0]);

  SocketQUICFrameStream_T frame;
  ASSERT (SocketQUICFrame_decode_stream (buf, len, &frame) > 0);
  ASSERT_EQ (1, frame.has_fin);
}

TEST (frame_stream_encode_null_buffer)
{
  const uint8_t data[] = "test";

  size_t len = SocketQUICFrame_encode_stream (0, 0, data, 4, 0, NULL, 128);
  ASSERT_EQ (0, len);
}

TEST (frame_stream_decode_null_params)
{
  uint8_t buf[] = { 0x08, 0x00 };
  SocketQUICFrameStream_T frame;

  ASSERT_EQ (-1, SocketQUICFrame_decode_stream (NULL, sizeof (buf), &frame));
  ASSERT_EQ (-1, SocketQUICFrame_decode_stream (buf, sizeof (buf), NULL));
  ASSERT_EQ (-1, SocketQUICFrame_decode_stream (buf, 0, &frame));
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
