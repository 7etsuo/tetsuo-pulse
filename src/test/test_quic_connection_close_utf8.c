/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_quic_connection_close_utf8.c
 * @brief Unit tests for CONNECTION_CLOSE frame UTF-8 validation (RFC 9000 §19.19).
 *
 * Tests UTF-8 validation of reason phrases in CONNECTION_CLOSE frames per
 * RFC 9000 Section 19.19, which specifies that reason phrases MUST be UTF-8.
 */

#include "quic/SocketQUICFrame.h"
#include "test/Test.h"

#include <string.h>

/* ============================================================================
 * CONNECTION_CLOSE Transport Frame UTF-8 Validation Tests
 * ============================================================================
 */

TEST (connection_close_transport_valid_utf8_ascii)
{
  uint8_t buf[256];
  size_t len;

  /* ASCII is valid UTF-8 */
  len = SocketQUICFrame_encode_connection_close_transport (
      0x0a, /* PROTOCOL_VIOLATION */
      0x06, /* CRYPTO frame */
      "Invalid handshake", buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x1c, buf[0]); /* Frame type: CONNECTION_CLOSE */
}

TEST (connection_close_transport_valid_utf8_multibyte)
{
  uint8_t buf[256];
  size_t len;

  /* Valid UTF-8 with multibyte characters */
  len = SocketQUICFrame_encode_connection_close_transport (
      0x01,              /* INTERNAL_ERROR */
      0x00,              /* No specific frame */
      "Error: café ☕", /* UTF-8 with 2-byte and 3-byte sequences */
      buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x1c, buf[0]);
}

TEST (connection_close_transport_valid_utf8_emoji)
{
  uint8_t buf[256];
  size_t len;

  /* Valid UTF-8 with 4-byte emoji */
  len = SocketQUICFrame_encode_connection_close_transport (
      0x02,       /* FLOW_CONTROL_ERROR */
      0x10,       /* MAX_DATA frame */
      "Error 😞", /* UTF-8 with 4-byte sequence */
      buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x1c, buf[0]);
}

TEST (connection_close_transport_null_reason)
{
  uint8_t buf[256];
  size_t len;

  /* NULL reason is valid (empty reason phrase) */
  len = SocketQUICFrame_encode_connection_close_transport (0x00, 0x00, NULL,
                                                            buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x1c, buf[0]);
}

TEST (connection_close_transport_empty_reason)
{
  uint8_t buf[256];
  size_t len;

  /* Empty string is valid UTF-8 */
  len = SocketQUICFrame_encode_connection_close_transport (0x00, 0x00, "", buf,
                                                            sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x1c, buf[0]);
}

TEST (connection_close_transport_invalid_utf8_truncated)
{
  uint8_t buf[256];
  size_t len;

  /* Truncated UTF-8 sequence (missing continuation byte) */
  char invalid_utf8[] = "Error: \xC3"; /* Incomplete 2-byte sequence */

  len = SocketQUICFrame_encode_connection_close_transport (0x01, 0x00,
                                                            invalid_utf8, buf,
                                                            sizeof (buf));

  /* Should fail due to invalid UTF-8 */
  ASSERT_EQ (0, len);
}

TEST (connection_close_transport_invalid_utf8_overlong)
{
  uint8_t buf[256];
  size_t len;

  /* Overlong encoding (security issue) */
  char invalid_utf8[]
      = "Error: \xC0\x80"; /* Overlong encoding of U+0000 */

  len = SocketQUICFrame_encode_connection_close_transport (0x01, 0x00,
                                                            invalid_utf8, buf,
                                                            sizeof (buf));

  /* Should fail due to overlong encoding */
  ASSERT_EQ (0, len);
}

TEST (connection_close_transport_invalid_utf8_surrogate)
{
  uint8_t buf[256];
  size_t len;

  /* UTF-16 surrogate (invalid in UTF-8) */
  char invalid_utf8[]
      = "Error: \xED\xA0\x80"; /* UTF-16 surrogate U+D800 */

  len = SocketQUICFrame_encode_connection_close_transport (0x01, 0x00,
                                                            invalid_utf8, buf,
                                                            sizeof (buf));

  /* Should fail due to surrogate */
  ASSERT_EQ (0, len);
}

TEST (connection_close_transport_invalid_utf8_continuation)
{
  uint8_t buf[256];
  size_t len;

  /* Invalid continuation byte */
  char invalid_utf8[]
      = "Error: \x80"; /* Continuation byte without lead byte */

  len = SocketQUICFrame_encode_connection_close_transport (0x01, 0x00,
                                                            invalid_utf8, buf,
                                                            sizeof (buf));

  /* Should fail due to invalid byte */
  ASSERT_EQ (0, len);
}

TEST (connection_close_transport_invalid_utf8_too_large)
{
  uint8_t buf[256];
  size_t len;

  /* Code point exceeds U+10FFFF */
  char invalid_utf8[]
      = "Error: \xF4\x90\x80\x80"; /* U+110000, exceeds maximum */

  len = SocketQUICFrame_encode_connection_close_transport (0x01, 0x00,
                                                            invalid_utf8, buf,
                                                            sizeof (buf));

  /* Should fail due to out-of-range code point */
  ASSERT_EQ (0, len);
}

/* ============================================================================
 * CONNECTION_CLOSE Application Frame UTF-8 Validation Tests
 * ============================================================================
 */

TEST (connection_close_app_valid_utf8_ascii)
{
  uint8_t buf[256];
  size_t len;

  /* ASCII is valid UTF-8 */
  len = SocketQUICFrame_encode_connection_close_app (
      1000, /* Application error code */
      "User requested shutdown", buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x1d, buf[0]); /* Frame type: CONNECTION_CLOSE_APP */
}

TEST (connection_close_app_valid_utf8_multibyte)
{
  uint8_t buf[256];
  size_t len;

  /* Valid UTF-8 with multibyte characters */
  len = SocketQUICFrame_encode_connection_close_app (
      2000,                           /* Application error code */
      "Erreur: connexion fermée", /* UTF-8 with accents */
      buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x1d, buf[0]);
}

TEST (connection_close_app_valid_utf8_chinese)
{
  uint8_t buf[256];
  size_t len;

  /* Valid UTF-8 with Chinese characters */
  len = SocketQUICFrame_encode_connection_close_app (
      3000,               /* Application error code */
      "错误：连接关闭", /* UTF-8 with 3-byte sequences */
      buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x1d, buf[0]);
}

TEST (connection_close_app_null_reason)
{
  uint8_t buf[256];
  size_t len;

  /* NULL reason is valid (empty reason phrase) */
  len = SocketQUICFrame_encode_connection_close_app (1000, NULL, buf,
                                                      sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x1d, buf[0]);
}

TEST (connection_close_app_empty_reason)
{
  uint8_t buf[256];
  size_t len;

  /* Empty string is valid UTF-8 */
  len
      = SocketQUICFrame_encode_connection_close_app (1000, "", buf, sizeof (buf));

  ASSERT (len > 0);
  ASSERT_EQ (0x1d, buf[0]);
}

TEST (connection_close_app_invalid_utf8_truncated)
{
  uint8_t buf[256];
  size_t len;

  /* Truncated 3-byte UTF-8 sequence */
  char invalid_utf8[] = "Shutdown: \xE2\x98"; /* Incomplete 3-byte sequence */

  len = SocketQUICFrame_encode_connection_close_app (1000, invalid_utf8, buf,
                                                      sizeof (buf));

  /* Should fail due to invalid UTF-8 */
  ASSERT_EQ (0, len);
}

TEST (connection_close_app_invalid_utf8_overlong)
{
  uint8_t buf[256];
  size_t len;

  /* Overlong 3-byte encoding */
  char invalid_utf8[]
      = "Error: \xE0\x80\x80"; /* Overlong encoding of U+0000 */

  len = SocketQUICFrame_encode_connection_close_app (1000, invalid_utf8, buf,
                                                      sizeof (buf));

  /* Should fail due to overlong encoding */
  ASSERT_EQ (0, len);
}

TEST (connection_close_app_invalid_utf8_bad_continuation)
{
  uint8_t buf[256];
  size_t len;

  /* Invalid continuation byte in 2-byte sequence */
  char invalid_utf8[] = "Error: \xC2\x00"; /* Invalid continuation */

  len = SocketQUICFrame_encode_connection_close_app (1000, invalid_utf8, buf,
                                                      sizeof (buf));

  /* Should fail due to invalid continuation */
  ASSERT_EQ (0, len);
}

TEST (connection_close_app_invalid_utf8_5byte)
{
  uint8_t buf[256];
  size_t len;

  /* 5-byte sequence (invalid in UTF-8) */
  char invalid_utf8[]
      = "Error: \xF8\x88\x80\x80\x80"; /* 5-byte sequence */

  len = SocketQUICFrame_encode_connection_close_app (1000, invalid_utf8, buf,
                                                      sizeof (buf));

  /* Should fail due to invalid 5-byte sequence */
  ASSERT_EQ (0, len);
}

/* ============================================================================
 * Edge Cases and Boundary Tests
 * ============================================================================
 */

TEST (connection_close_valid_utf8_all_ascii)
{
  uint8_t buf[256];
  size_t len;

  /* All printable ASCII characters */
  const char *reason = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

  len = SocketQUICFrame_encode_connection_close_transport (0x00, 0x00, reason,
                                                            buf, sizeof (buf));

  ASSERT (len > 0);
}

TEST (connection_close_valid_utf8_boundary_1byte)
{
  uint8_t buf[256];
  size_t len;

  /* Boundary: highest 1-byte UTF-8 (U+007F) */
  char reason[] = "Boundary: \x7F";

  len = SocketQUICFrame_encode_connection_close_app (1000, reason, buf,
                                                      sizeof (buf));

  ASSERT (len > 0);
}

TEST (connection_close_valid_utf8_boundary_2byte)
{
  uint8_t buf[256];
  size_t len;

  /* Boundary: highest 2-byte UTF-8 (U+07FF) */
  char reason[] = "Boundary: \xDF\xBF"; /* U+07FF */

  len = SocketQUICFrame_encode_connection_close_app (1000, reason, buf,
                                                      sizeof (buf));

  ASSERT (len > 0);
}

TEST (connection_close_valid_utf8_boundary_3byte)
{
  uint8_t buf[256];
  size_t len;

  /* Boundary: highest 3-byte UTF-8 (U+FFFF, excluding surrogates) */
  char reason[] = "Boundary: \xEF\xBF\xBF"; /* U+FFFF */

  len = SocketQUICFrame_encode_connection_close_app (1000, reason, buf,
                                                      sizeof (buf));

  ASSERT (len > 0);
}

TEST (connection_close_valid_utf8_boundary_4byte)
{
  uint8_t buf[256];
  size_t len;

  /* Boundary: highest valid 4-byte UTF-8 (U+10FFFF) */
  char reason[] = "Boundary: \xF4\x8F\xBF\xBF"; /* U+10FFFF */

  len = SocketQUICFrame_encode_connection_close_app (1000, reason, buf,
                                                      sizeof (buf));

  ASSERT (len > 0);
}

TEST (connection_close_null_output_buffer)
{
  size_t len;

  /* NULL output buffer should fail */
  len = SocketQUICFrame_encode_connection_close_transport (0x00, 0x00,
                                                            "Error", NULL, 256);

  ASSERT_EQ (0, len);
}

TEST (connection_close_zero_output_buffer)
{
  uint8_t buf[1];
  size_t len;

  /* Zero-length output buffer should fail */
  len = SocketQUICFrame_encode_connection_close_transport (0x00, 0x00, "Error",
                                                            buf, 0);

  ASSERT_EQ (0, len);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
