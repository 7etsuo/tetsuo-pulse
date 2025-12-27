/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_crypto_frame_encode.c
 * @brief Unit tests for QUIC CRYPTO frame encoding/decoding (RFC 9000 §19.6).
 */

#include "quic/SocketQUICFrame.h"
#include "quic/SocketQUICVarInt.h"
#include "test/Test.h"

#include <string.h>

/* ============================================================================
 * CRYPTO Frame Encoding Tests
 * ============================================================================
 */

TEST (frame_crypto_encode_basic)
{
  uint8_t buf[128];
  const uint8_t data[] = "ClientHello";
  size_t len;

  /* Encode basic CRYPTO frame (offset=0) */
  len = SocketQUICFrame_encode_crypto (0, data, 11, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x06, buf[0]); /* Frame type: CRYPTO */

  /* Verify by parsing back */
  SocketQUICFrameCrypto_T frame;
  int consumed = SocketQUICFrame_decode_crypto (buf, len, &frame);

  ASSERT (consumed > 0);
  ASSERT_EQ (0, frame.offset);
  ASSERT_EQ (11, frame.length);
  ASSERT (memcmp (frame.data, "ClientHello", 11) == 0);
}

TEST (frame_crypto_encode_with_offset)
{
  uint8_t buf[128];
  const uint8_t data[] = "ServerHello";
  size_t len;

  /* Encode CRYPTO frame with offset=256 */
  len = SocketQUICFrame_encode_crypto (256, data, 11, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x06, buf[0]); /* Frame type: CRYPTO */

  /* Verify by parsing */
  SocketQUICFrameCrypto_T frame;
  int consumed = SocketQUICFrame_decode_crypto (buf, len, &frame);

  ASSERT (consumed > 0);
  ASSERT_EQ (256, frame.offset);
  ASSERT_EQ (11, frame.length);
  ASSERT (memcmp (frame.data, "ServerHello", 11) == 0);
}

TEST (frame_crypto_encode_large_offset)
{
  uint8_t buf[256];
  const uint8_t data[] = "Certificate";
  size_t len;

  /* Encode CRYPTO frame with large offset */
  uint64_t large_offset = 1000000;
  len = SocketQUICFrame_encode_crypto (large_offset, data, 11, buf,
                                        sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x06, buf[0]);

  /* Verify by parsing */
  SocketQUICFrameCrypto_T frame;
  int consumed = SocketQUICFrame_decode_crypto (buf, len, &frame);

  ASSERT (consumed > 0);
  ASSERT_EQ (large_offset, frame.offset);
  ASSERT_EQ (11, frame.length);
  ASSERT (memcmp (frame.data, "Certificate", 11) == 0);
}

TEST (frame_crypto_encode_zero_length)
{
  uint8_t buf[128];
  size_t len;

  /* Zero-length CRYPTO frame is valid (edge case) */
  len = SocketQUICFrame_encode_crypto (0, NULL, 0, buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x06, buf[0]);

  /* Verify by parsing */
  SocketQUICFrameCrypto_T frame;
  int consumed = SocketQUICFrame_decode_crypto (buf, len, &frame);

  ASSERT (consumed > 0);
  ASSERT_EQ (0, frame.offset);
  ASSERT_EQ (0, frame.length);
}

TEST (frame_crypto_encode_large_data)
{
  uint8_t buf[2048];
  uint8_t data[1024];
  size_t len;

  /* Fill data with a pattern */
  for (size_t i = 0; i < sizeof (data); i++)
    data[i] = (uint8_t)(i % 256);

  /* Encode large CRYPTO frame */
  len = SocketQUICFrame_encode_crypto (100, data, sizeof (data), buf,
                                        sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x06, buf[0]);

  /* Verify by parsing */
  SocketQUICFrameCrypto_T frame;
  int consumed = SocketQUICFrame_decode_crypto (buf, len, &frame);

  ASSERT (consumed > 0);
  ASSERT_EQ (100, frame.offset);
  ASSERT_EQ (sizeof (data), frame.length);
  ASSERT (memcmp (frame.data, data, sizeof (data)) == 0);
}

TEST (frame_crypto_encode_buffer_too_small)
{
  uint8_t buf[8];
  const uint8_t data[100] = { 0 };

  /* Try to encode frame larger than buffer */
  size_t len
      = SocketQUICFrame_encode_crypto (0, data, 100, buf, sizeof (buf));

  ASSERT_EQ (0, len); /* Should fail gracefully */
}

TEST (frame_crypto_encode_null_buffer)
{
  const uint8_t data[] = "test";

  /* NULL output buffer should return 0 */
  size_t len = SocketQUICFrame_encode_crypto (0, data, 4, NULL, 128);
  ASSERT_EQ (0, len);
}

TEST (frame_crypto_encode_null_data_with_length)
{
  uint8_t buf[128];

  /* NULL data with non-zero length should fail */
  size_t len = SocketQUICFrame_encode_crypto (0, NULL, 10, buf, sizeof (buf));
  ASSERT_EQ (0, len);
}

TEST (frame_crypto_encode_roundtrip_multiple)
{
  uint8_t buf[256];
  const uint8_t data1[] = "First fragment";
  const uint8_t data2[] = "Second fragment";
  const uint8_t data3[] = "Third fragment";
  size_t len1, len2, len3;
  int consumed1, consumed2, consumed3;
  SocketQUICFrameCrypto_T frame;

  /* Encode and verify first fragment */
  len1 = SocketQUICFrame_encode_crypto (0, data1, 14, buf, sizeof (buf));
  ASSERT (len1 > 0);
  consumed1 = SocketQUICFrame_decode_crypto (buf, len1, &frame);
  ASSERT (consumed1 > 0);
  ASSERT_EQ (0, frame.offset);
  ASSERT_EQ (14, frame.length);

  /* Encode and verify second fragment */
  len2 = SocketQUICFrame_encode_crypto (14, data2, 15, buf, sizeof (buf));
  ASSERT (len2 > 0);
  consumed2 = SocketQUICFrame_decode_crypto (buf, len2, &frame);
  ASSERT (consumed2 > 0);
  ASSERT_EQ (14, frame.offset);
  ASSERT_EQ (15, frame.length);

  /* Encode and verify third fragment */
  len3 = SocketQUICFrame_encode_crypto (29, data3, 14, buf, sizeof (buf));
  ASSERT (len3 > 0);
  consumed3 = SocketQUICFrame_decode_crypto (buf, len3, &frame);
  ASSERT (consumed3 > 0);
  ASSERT_EQ (29, frame.offset);
  ASSERT_EQ (14, frame.length);
}

/* ============================================================================
 * CRYPTO Frame Decoding Tests
 * ============================================================================
 */

TEST (frame_crypto_decode_null_params)
{
  uint8_t buf[] = { 0x06, 0x00, 0x00 };
  SocketQUICFrameCrypto_T frame;

  /* NULL data */
  ASSERT_EQ (-1, SocketQUICFrame_decode_crypto (NULL, sizeof (buf), &frame));

  /* NULL frame */
  ASSERT_EQ (-1, SocketQUICFrame_decode_crypto (buf, sizeof (buf), NULL));

  /* Zero length */
  ASSERT_EQ (-1, SocketQUICFrame_decode_crypto (buf, 0, &frame));
}

TEST (frame_crypto_decode_invalid_type)
{
  uint8_t buf[] = { 0x08, 0x00, 0x00 }; /* STREAM frame, not CRYPTO */
  SocketQUICFrameCrypto_T frame;

  /* Should fail with wrong frame type */
  ASSERT_EQ (-1, SocketQUICFrame_decode_crypto (buf, sizeof (buf), &frame));
}

TEST (frame_crypto_decode_truncated)
{
  /* CRYPTO frame with incomplete header */
  uint8_t buf1[] = { 0x06 }; /* Just type, no offset */
  uint8_t buf2[] = { 0x06, 0x00 }; /* Type + offset, no length */
  SocketQUICFrameCrypto_T frame;

  ASSERT_EQ (-1, SocketQUICFrame_decode_crypto (buf1, sizeof (buf1), &frame));
  ASSERT_EQ (-1, SocketQUICFrame_decode_crypto (buf2, sizeof (buf2), &frame));
}

TEST (frame_crypto_decode_data_truncated)
{
  /* CRYPTO frame with length=10 but only 5 bytes of data */
  uint8_t buf[] = { 0x06, 0x00, 0x0a, 0x01, 0x02, 0x03, 0x04, 0x05 };
  SocketQUICFrameCrypto_T frame;

  /* Should fail due to truncated data */
  ASSERT_EQ (-1, SocketQUICFrame_decode_crypto (buf, sizeof (buf), &frame));
}

/* ============================================================================
 * CRYPTO Frame Integration Tests
 * ============================================================================
 */

TEST (frame_crypto_verify_frame_type)
{
  uint8_t buf[128];
  const uint8_t data[] = "Finished";

  size_t len = SocketQUICFrame_encode_crypto (0, data, 8, buf, sizeof (buf));
  ASSERT (len > 0);

  /* Verify frame type constant matches RFC 9000 */
  ASSERT_EQ (0x06, QUIC_FRAME_CRYPTO);
  ASSERT_EQ (0x06, buf[0]);
}

TEST (frame_crypto_offset_encoding)
{
  uint8_t buf[128];
  const uint8_t data[] = "test";

  /* Test various offset values to verify varint encoding */
  uint64_t offsets[] = { 0, 1, 63, 64, 255, 256, 16383, 16384, 1073741823 };

  for (size_t i = 0; i < sizeof (offsets) / sizeof (offsets[0]); i++)
    {
      size_t len = SocketQUICFrame_encode_crypto (offsets[i], data, 4, buf,
                                                   sizeof (buf));
      ASSERT (len > 0);

      SocketQUICFrameCrypto_T frame;
      int consumed = SocketQUICFrame_decode_crypto (buf, len, &frame);

      ASSERT (consumed > 0);
      ASSERT_EQ (offsets[i], frame.offset);
      ASSERT_EQ (4, frame.length);
    }
}

TEST (frame_crypto_no_data_pointer_copy)
{
  uint8_t buf[128];
  const uint8_t data[] = "original";

  size_t len = SocketQUICFrame_encode_crypto (0, data, 8, buf, sizeof (buf));
  ASSERT (len > 0);

  SocketQUICFrameCrypto_T frame;
  int consumed = SocketQUICFrame_decode_crypto (buf, len, &frame);
  ASSERT (consumed > 0);

  /* Verify that frame.data points into buf, not a separate allocation */
  ASSERT (frame.data >= buf && frame.data < buf + sizeof (buf));
  ASSERT (memcmp (frame.data, "original", 8) == 0);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
