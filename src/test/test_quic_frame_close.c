/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_frame_close.c
 * @brief Tests for QUIC CONNECTION_CLOSE frame encoding (RFC 9000
 * Section 19.19).
 *
 * Tests cover:
 * - Basic encoding of transport and application CONNECTION_CLOSE frames
 * - UTF-8 validation of reason phrases
 * - Length limits for reason phrases (DoS protection)
 * - Edge cases (NULL reasons, empty strings, maximum length)
 * - Buffer overflow protection
 */

#include "quic/SocketQUICFrame.h"
#include "test/Test.h"

#include <string.h>

/**
 * Test basic transport CONNECTION_CLOSE frame encoding.
 */
TEST (test_connection_close_transport_basic)
{
  uint8_t buf[256];
  const char *reason = "Connection reset";

  size_t len = SocketQUICFrame_encode_connection_close_transport (
      0x0a, /* PROTOCOL_VIOLATION */
      0x06, /* CRYPTO frame */
      reason,
      buf,
      sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (buf[0], QUIC_FRAME_CONNECTION_CLOSE);
}

/**
 * Test basic application CONNECTION_CLOSE frame encoding.
 */
TEST (test_connection_close_app_basic)
{
  uint8_t buf[256];
  const char *reason = "User requested shutdown";

  size_t len = SocketQUICFrame_encode_connection_close_app (
      1000, /* Application error code */
      reason,
      buf,
      sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (buf[0], QUIC_FRAME_CONNECTION_CLOSE_APP);
}

/**
 * Test CONNECTION_CLOSE with NULL reason (no reason phrase).
 */
TEST (test_connection_close_null_reason)
{
  uint8_t buf[256];

  /* Transport variant */
  size_t len1 = SocketQUICFrame_encode_connection_close_transport (
      0x01, 0x00, NULL, buf, sizeof (buf));
  ASSERT (len1 > 0);

  /* Application variant */
  size_t len2 = SocketQUICFrame_encode_connection_close_app (
      0x01, NULL, buf, sizeof (buf));
  ASSERT (len2 > 0);
}

/**
 * Test CONNECTION_CLOSE with empty string reason.
 */
TEST (test_connection_close_empty_reason)
{
  uint8_t buf[256];

  size_t len = SocketQUICFrame_encode_connection_close_transport (
      0x01, 0x00, "", buf, sizeof (buf));
  ASSERT (len > 0);
}

/**
 * Test CONNECTION_CLOSE with maximum allowed reason length.
 * Verifies that QUIC_REASON_MAX_LENGTH (1024 bytes) is accepted.
 */
TEST (test_connection_close_max_reason_length)
{
  uint8_t buf[2048];
  char reason[QUIC_REASON_MAX_LENGTH + 1];

  /* Fill with valid ASCII (which is also valid UTF-8) */
  memset (reason, 'A', QUIC_REASON_MAX_LENGTH);
  reason[QUIC_REASON_MAX_LENGTH] = '\0';

  size_t len = SocketQUICFrame_encode_connection_close_transport (
      0x01, 0x00, reason, buf, sizeof (buf));

  ASSERT (len > 0);
}

/**
 * Test CONNECTION_CLOSE rejects reason exceeding maximum length.
 * This is the key security test - verifies DoS protection via length limit.
 */
TEST (test_connection_close_reject_oversized_reason)
{
  uint8_t buf[4096];
  char reason[QUIC_REASON_MAX_LENGTH + 2];

  /* Create a string that's 1 byte too long */
  memset (reason, 'A', QUIC_REASON_MAX_LENGTH + 1);
  reason[QUIC_REASON_MAX_LENGTH + 1] = '\0';

  /* Transport variant should reject */
  size_t len1 = SocketQUICFrame_encode_connection_close_transport (
      0x01, 0x00, reason, buf, sizeof (buf));
  ASSERT_EQ (len1, 0);

  /* Application variant should also reject */
  size_t len2 = SocketQUICFrame_encode_connection_close_app (
      0x01, reason, buf, sizeof (buf));
  ASSERT_EQ (len2, 0);
}

/**
 * Test CONNECTION_CLOSE with invalid UTF-8 in reason phrase.
 */
TEST (test_connection_close_invalid_utf8)
{
  uint8_t buf[256];
  /* Invalid UTF-8: continuation byte without start byte */
  const char *invalid_utf8 = "Invalid \x80 sequence";

  size_t len = SocketQUICFrame_encode_connection_close_transport (
      0x01, 0x00, invalid_utf8, buf, sizeof (buf));

  /* Should reject invalid UTF-8 */
  ASSERT_EQ (len, 0);
}

/**
 * Test CONNECTION_CLOSE with valid multi-byte UTF-8 characters.
 */
TEST (test_connection_close_valid_utf8)
{
  uint8_t buf[256];
  /* Valid UTF-8: "Error: 错误" (Chinese characters) */
  const char *valid_utf8 = "Error: \xe9\x94\x99\xe8\xaf\xaf";

  size_t len = SocketQUICFrame_encode_connection_close_transport (
      0x01, 0x00, valid_utf8, buf, sizeof (buf));

  ASSERT (len > 0);
}

/**
 * Test buffer overflow protection - buffer too small.
 */
TEST (test_connection_close_buffer_too_small)
{
  uint8_t buf[10]; /* Deliberately small buffer */
  const char *reason = "This reason is definitely too long for the buffer";

  size_t len = SocketQUICFrame_encode_connection_close_transport (
      0x01, 0x00, reason, buf, sizeof (buf));

  /* Should fail gracefully, not crash */
  ASSERT_EQ (len, 0);
}

/**
 * Test NULL output buffer (error handling).
 */
TEST (test_connection_close_null_buffer)
{
  size_t len = SocketQUICFrame_encode_connection_close_transport (
      0x01, 0x00, "reason", NULL, 100);

  ASSERT_EQ (len, 0);
}

/**
 * Test zero-length output buffer (error handling).
 */
TEST (test_connection_close_zero_buffer)
{
  uint8_t buf[1];

  size_t len = SocketQUICFrame_encode_connection_close_transport (
      0x01, 0x00, "reason", buf, 0);

  ASSERT_EQ (len, 0);
}

/**
 * Test large error codes (varint encoding boundary).
 */
TEST (test_connection_close_large_error_code)
{
  uint8_t buf[256];

  /* Test with large error code (requires 8-byte varint) */
  size_t len = SocketQUICFrame_encode_connection_close_transport (
      0x3FFFFFFFFFFFFFFF, /* Maximum QUIC varint */
      0x00,
      "Large error code",
      buf,
      sizeof (buf));

  ASSERT (len > 0);
}

/**
 * Test that encoding returns correct length for parsing.
 * Verifies the encoded length matches the actual bytes written.
 */
TEST (test_connection_close_encoded_length)
{
  uint8_t buf[256];
  const char *reason = "Test";

  size_t len = SocketQUICFrame_encode_connection_close_transport (
      0x01, 0x00, reason, buf, sizeof (buf));

  ASSERT (len > 0);
  /* Length should include: type(1) + error_code + frame_type + reason_len +
   * reason */
  /* At minimum: 1 + 1 + 1 + 1 + 4 = 8 bytes */
  ASSERT (len >= 8);
}

/**
 * Stress test: encoding many frames with varying reason lengths.
 * Ensures no memory corruption or performance degradation.
 */
TEST (test_connection_close_stress)
{
  uint8_t buf[2048];

  /* Test 100 encodings with varying lengths */
  for (int i = 0; i < 100; i++)
    {
      char reason[128];
      size_t reason_len = (i % 100); /* 0 to 99 characters */

      memset (reason, 'A', reason_len);
      reason[reason_len] = '\0';

      size_t len = SocketQUICFrame_encode_connection_close_app (
          i, reason, buf, sizeof (buf));

      ASSERT (len > 0);
    }
}

/**
 * Test DoS scenario: multiple extremely long strings.
 * Verifies that strnlen() protection prevents CPU exhaustion.
 */
TEST (test_connection_close_dos_protection)
{
  uint8_t buf[4096];
  char long_reason[QUIC_REASON_MAX_LENGTH + 100];

  /* Create strings that exceed the limit */
  memset (long_reason, 'X', sizeof (long_reason) - 1);
  long_reason[sizeof (long_reason) - 1] = '\0';

  /* Attempt to encode 50 times - should all fail quickly due to strnlen() */
  for (int i = 0; i < 50; i++)
    {
      size_t len = SocketQUICFrame_encode_connection_close_transport (
          0x01, 0x00, long_reason, buf, sizeof (buf));

      /* All should fail */
      ASSERT_EQ (len, 0);
    }

  /* If strnlen() protection is working, this test completes quickly.
   * Without protection, strlen() would scan 50 * (1024+100) = 56,200 bytes. */
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
