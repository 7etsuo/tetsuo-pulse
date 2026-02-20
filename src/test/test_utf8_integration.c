/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_utf8_integration.c - Integration tests for SocketUTF8 in protocol
 * modules
 *
 * Tests UTF-8 validation integration in higher-level protocols that require
 * UTF-8 validation per RFC requirements:
 *
 * - WebSocket text frames (RFC 6455 §5.6)
 * - WebSocket close frame reasons (RFC 6455 §5.5.1)
 * - HTTP/2 header field values (RFC 7540 §8.1.2)
 * - HPACK string literals (RFC 7541 §5.2)
 *
 * These tests verify that:
 * 1. Valid UTF-8 sequences are accepted in protocol contexts
 * 2. Invalid UTF-8 sequences are rejected with appropriate errors
 * 3. Incremental validation works across fragmented messages
 * 4. Security-critical malformed sequences (overlong, surrogates) are rejected
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketUTF8.h"
#include "test/Test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Test that simulates WebSocket text frame validation with valid UTF-8.
 * RFC 6455 §5.6: All text frames MUST be valid UTF-8.
 */
TEST (websocket_text_frame_valid_utf8)
{
  /* Simulate a WebSocket text frame payload with mixed UTF-8 content */
  const char *payload = "Hello, 世界! 🌍 Café";
  size_t len = strlen (payload);

  /* Validate the entire frame payload */
  SocketUTF8_Result result
      = SocketUTF8_validate ((const unsigned char *)payload, len);

  ASSERT_EQ (UTF8_VALID, result);

  /* Count code points */
  size_t count = 0;
  result = SocketUTF8_count_codepoints (
      (const unsigned char *)payload, len, &count);

  ASSERT_EQ (UTF8_VALID, result);
  ASSERT_EQ (17, count); /* H e l l o , SP 世 界 ! SP 🌍 SP C a f é */
}

/**
 * Test that WebSocket text frames reject invalid UTF-8 (surrogate pairs).
 * RFC 6455 §8.1: Invalid UTF-8 MUST result in connection closure.
 */
TEST (websocket_text_frame_invalid_surrogate)
{
  /* Invalid UTF-8: lone surrogate U+D800 */
  const unsigned char payload[] = { 'H', 'e', 'l', 'l', 'o', 0xED, 0xA0, 0x80 };

  SocketUTF8_Result result = SocketUTF8_validate (payload, sizeof (payload));

  /* Should detect surrogate and reject */
  ASSERT_EQ (UTF8_SURROGATE, result);
}

/**
 * Test that WebSocket text frames reject overlong encodings (security).
 * Overlong encodings can bypass security filters.
 */
TEST (websocket_text_frame_overlong_encoding)
{
  /* Overlong encoding of '/' (0x2F) as C0 AF */
  const unsigned char payload[]
      = { 'H', 'T', 'T', 'P', 0xC0, 0xAF, 'p', 'a', 't', 'h' };

  SocketUTF8_Result result = SocketUTF8_validate (payload, sizeof (payload));

  ASSERT_EQ (UTF8_OVERLONG, result);
}

/**
 * Test incremental UTF-8 validation for fragmented WebSocket messages.
 * RFC 6455 §5.4: Messages can be fragmented across multiple frames.
 */
TEST (websocket_fragmented_text_incremental)
{
  SocketUTF8_State state;
  SocketUTF8_init (&state);

  /* Fragment 1: "Hello, " */
  const char *frag1 = "Hello, ";
  SocketUTF8_Result result = SocketUTF8_update (
      &state, (const unsigned char *)frag1, strlen (frag1));
  ASSERT_EQ (UTF8_VALID, result);

  /* Fragment 2: First byte of '世' (E4 B8 AD) - partial multi-byte */
  const unsigned char frag2[] = { 0xE4 };
  result = SocketUTF8_update (&state, frag2, sizeof (frag2));
  ASSERT_EQ (UTF8_INCOMPLETE, result); /* Valid prefix, needs more */

  /* Fragment 3: Complete '世' and start '界' */
  const unsigned char frag3[] = { 0xB8, 0xAD, 0xE7, 0x95 };
  result = SocketUTF8_update (&state, frag3, sizeof (frag3));
  ASSERT_EQ (UTF8_INCOMPLETE, result); /* '世' complete, '界' incomplete */

  /* Fragment 4: Complete '界' and add "!" */
  const unsigned char frag4[] = { 0x8C, '!' };
  result = SocketUTF8_update (&state, frag4, sizeof (frag4));
  ASSERT_EQ (UTF8_VALID, result);

  /* Final check */
  result = SocketUTF8_finish (&state);
  ASSERT_EQ (UTF8_VALID, result);
}

/**
 * Test that incomplete multi-byte sequence at end of final frame is rejected.
 */
TEST (websocket_fragmented_incomplete_final)
{
  SocketUTF8_State state;
  SocketUTF8_init (&state);

  /* Fragment 1: "Hello" */
  const char *frag1 = "Hello";
  SocketUTF8_Result result = SocketUTF8_update (
      &state, (const unsigned char *)frag1, strlen (frag1));
  ASSERT_EQ (UTF8_VALID, result);

  /* Fragment 2: Incomplete 3-byte sequence (final frame) */
  const unsigned char frag2[] = { 0xE4, 0xB8 }; /* Missing final byte */
  result = SocketUTF8_update (&state, frag2, sizeof (frag2));
  ASSERT_EQ (UTF8_INCOMPLETE, result);

  /* Finish should detect incomplete sequence */
  result = SocketUTF8_finish (&state);
  ASSERT_EQ (UTF8_INCOMPLETE, result);
}

/**
 * Test valid UTF-8 in WebSocket close frame reason text.
 * RFC 6455 §5.5.1: Close reason MUST be valid UTF-8.
 */
TEST (websocket_close_reason_valid)
{
  const char *reason = "Going away - server restart";
  SocketUTF8_Result result = SocketUTF8_validate_str (reason);

  ASSERT_EQ (UTF8_VALID, result);
}

/**
 * Test that invalid UTF-8 in close reason is rejected.
 */
TEST (websocket_close_reason_invalid)
{
  /* Invalid UTF-8: unexpected continuation byte */
  const unsigned char reason[] = { 'E', 'r', 'r', 'o', 'r', ':', ' ', 0x80 };

  SocketUTF8_Result result = SocketUTF8_validate (reason, sizeof (reason));

  ASSERT_NE (UTF8_VALID, result);
}

/**
 * Test UTF-8 validation for close reason with emoji (4-byte UTF-8).
 */
TEST (websocket_close_reason_emoji)
{
  const char *reason = "Goodbye 👋 See you later!";
  SocketUTF8_Result result = SocketUTF8_validate_str (reason);

  ASSERT_EQ (UTF8_VALID, result);

  /* Verify code point count */
  size_t count = 0;
  SocketUTF8_count_codepoints (
      (const unsigned char *)reason, strlen (reason), &count);
  ASSERT_EQ (24, count); /* "Goodbye 👋 See you later!" */
}

/**
 * Test UTF-8 validation for HTTP/2 custom header values.
 * RFC 7540 §8.1.2: Header field values should be valid UTF-8.
 */
TEST (http2_header_value_valid_utf8)
{
  /* Custom header with UTF-8 value */
  const char *header_value = "Content from 東京";
  SocketUTF8_Result result = SocketUTF8_validate_str (header_value);

  ASSERT_EQ (UTF8_VALID, result);
}

/**
 * Test that malformed UTF-8 in header values is detected.
 */
TEST (http2_header_value_invalid_utf8)
{
  /* Invalid: overlong encoding of 'A' (U+0041) */
  const unsigned char header_value[]
      = { 'V', 'a', 'l', 'u', 'e', '=', 0xC1, 0x81 };

  SocketUTF8_Result result
      = SocketUTF8_validate (header_value, sizeof (header_value));

  ASSERT_EQ (UTF8_OVERLONG, result);
}

/**
 * Test UTF-8 validation for internationalized domain names in headers.
 */
TEST (http2_header_idn_host)
{
  /* Internationalized domain name */
  const char *host = "www.日本.jp";
  SocketUTF8_Result result = SocketUTF8_validate_str (host);

  ASSERT_EQ (UTF8_VALID, result);
}

/**
 * Test UTF-8 validation after HPACK Huffman decoding.
 * RFC 7541 §5.2: Decoded strings should be valid UTF-8.
 */
TEST (hpack_decoded_string_valid_utf8)
{
  /* Simulate a Huffman-decoded header value */
  const char *decoded = "application/json; charset=utf-8";
  SocketUTF8_Result result = SocketUTF8_validate_str (decoded);

  ASSERT_EQ (UTF8_VALID, result);
}

/**
 * Test that HPACK decoder would reject invalid UTF-8 after decoding.
 */
TEST (hpack_decoded_string_invalid_utf8)
{
  /* Simulated decoded value with invalid UTF-8 */
  const unsigned char decoded[] = {
    't', 'e', 'x', 't', '/', 0xF5, 0x80, 0x80, 0x80
  }; /* Invalid: 0xF5 is invalid start byte */

  SocketUTF8_Result result = SocketUTF8_validate (decoded, sizeof (decoded));

  /* 0xF5 is an invalid UTF-8 start byte (only F0-F4 valid) */
  ASSERT_NE (UTF8_VALID, result);
}

/**
 * Test HPACK literal with non-ASCII UTF-8 content.
 */
TEST (hpack_literal_utf8_content_type)
{
  const char *content_type = "text/plain; name=\"文書.txt\"";
  SocketUTF8_Result result = SocketUTF8_validate_str (content_type);

  ASSERT_EQ (UTF8_VALID, result);
}

/**
 * Test maximum valid Unicode code point in protocol context.
 */
TEST (protocol_max_valid_codepoint)
{
  /* U+10FFFF: Last valid Unicode code point */
  const unsigned char data[] = { 0xF4, 0x8F, 0xBF, 0xBF };

  SocketUTF8_Result result = SocketUTF8_validate (data, sizeof (data));

  ASSERT_EQ (UTF8_VALID, result);

  /* Verify it encodes correctly */
  uint32_t codepoint = 0;
  size_t consumed = 0;
  result = SocketUTF8_decode (data, sizeof (data), &codepoint, &consumed);

  ASSERT_EQ (UTF8_VALID, result);
  ASSERT_EQ (0x10FFFF, codepoint);
  ASSERT_EQ (4, consumed);
}

/**
 * Test rejection of code points beyond Unicode range.
 */
TEST (protocol_beyond_unicode_range)
{
  /* Invalid: F4 90 80 80 would be U+110000 (beyond U+10FFFF) */
  const unsigned char data[] = { 0xF4, 0x90, 0x80, 0x80 };

  SocketUTF8_Result result = SocketUTF8_validate (data, sizeof (data));

  ASSERT_NE (UTF8_VALID, result);
}

/**
 * Test empty payload validation (valid in all contexts).
 */
TEST (protocol_empty_payload)
{
  SocketUTF8_Result result = SocketUTF8_validate (NULL, 0);
  ASSERT_EQ (UTF8_VALID, result);

  result = SocketUTF8_validate_str ("");
  ASSERT_EQ (UTF8_VALID, result);
}

/**
 * Test rejection of NULL byte overlong encoding (security bypass attempt).
 */
TEST (security_overlong_null_bypass)
{
  /* Overlong NULL: C0 80 (could bypass NULL checks) */
  const unsigned char payload[]
      = { 'p', 'a', 't', 'h', 0xC0, 0x80, 'f', 'i', 'l', 'e' };

  SocketUTF8_Result result = SocketUTF8_validate (payload, sizeof (payload));

  ASSERT_EQ (UTF8_OVERLONG, result);
}

/**
 * Test rejection of overlong directory traversal sequences.
 */
TEST (security_overlong_path_traversal)
{
  /* Overlong '..' using C0 AE C0 AE */
  const unsigned char payload[] = { '/',  'p',  'a',  't', 'h', '/', 0xC0,
                                    0xAE, 0xC0, 0xAE, '/', 'e', 't', 'c' };

  SocketUTF8_Result result = SocketUTF8_validate (payload, sizeof (payload));

  ASSERT_EQ (UTF8_OVERLONG, result);
}

/**
 * Test rejection of UTF-16 surrogate pairs in UTF-8 context.
 */
TEST (security_surrogate_pair_injection)
{
  /* High surrogate: ED A0 80 (U+D800) */
  const unsigned char payload[] = { 't', 'e', 'x', 't', 0xED, 0xA0, 0x80 };

  SocketUTF8_Result result = SocketUTF8_validate (payload, sizeof (payload));

  ASSERT_EQ (UTF8_SURROGATE, result);
}

/**
 * Test realistic WebSocket message with mixed scripts.
 */
TEST (realworld_mixed_scripts)
{
  const char *message = "System status: OK ✓\n"
                        "データ転送完了\n"
                        "Статус: активен\n"
                        "حالة: نشط\n"
                        "🚀 Deployment successful!";

  SocketUTF8_Result result = SocketUTF8_validate_str (message);

  ASSERT_EQ (UTF8_VALID, result);

  /* Count code points */
  size_t count = 0;
  SocketUTF8_count_codepoints (
      (const unsigned char *)message, strlen (message), &count);
  /* Should be able to count all valid code points */
  ASSERT (count > 0);
}

/**
 * Test HTTP/2 header with complex Accept-Language value.
 */
TEST (realworld_accept_language_header)
{
  const char *accept_lang = "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7,中文;q=0.6";

  SocketUTF8_Result result = SocketUTF8_validate_str (accept_lang);

  ASSERT_EQ (UTF8_VALID, result);
}

/**
 * Test large WebSocket text frame with continuous UTF-8 stream.
 */
TEST (realworld_large_text_frame)
{
  /* Create a large buffer with repeated valid UTF-8 */
  Arena_T arena = Arena_new ();
  size_t size = 8192;
  unsigned char *buffer = ALLOC (arena, size);

  /* Fill with repeating pattern: "Hello世界! " (13 bytes) */
  const char *pattern = "Hello世界! ";
  size_t pattern_len = strlen (pattern);

  for (size_t i = 0; i < size; i++)
    {
      buffer[i] = pattern[i % pattern_len];
    }

  /* Validate the entire buffer */
  SocketUTF8_Result result = SocketUTF8_validate (buffer, size);

  /* Note: May be incomplete if size doesn't align with pattern boundary */
  ASSERT (result == UTF8_VALID || result == UTF8_INCOMPLETE);

  Arena_dispose (&arena);
}

/**
 * Test incremental validation with state reset and reuse.
 */
TEST (realworld_state_reuse)
{
  SocketUTF8_State state;
  SocketUTF8_init (&state);

  /* First message */
  const char *msg1 = "First message 📝";
  SocketUTF8_Result result
      = SocketUTF8_update (&state, (const unsigned char *)msg1, strlen (msg1));
  ASSERT_EQ (UTF8_VALID, result);
  ASSERT_EQ (UTF8_VALID, SocketUTF8_finish (&state));

  /* Reset and validate second message */
  SocketUTF8_reset (&state);

  const char *msg2 = "Second message ✅";
  result
      = SocketUTF8_update (&state, (const unsigned char *)msg2, strlen (msg2));
  ASSERT_EQ (UTF8_VALID, result);
  ASSERT_EQ (UTF8_VALID, SocketUTF8_finish (&state));
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
