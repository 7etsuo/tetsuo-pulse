/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_utf8.c - Unit tests for SocketUTF8 module
 *
 * Part of the Socket Library
 *
 * Tests UTF-8 validation against Unicode test vectors and security cases:
 * - Valid ASCII and multi-byte sequences
 * - Boundary cases (first/last valid code points per length)
 * - Overlong encoding rejection (security critical)
 * - Surrogate rejection (U+D800-U+DFFF)
 * - Invalid code point rejection (>U+10FFFF)
 * - Incremental validation across chunk boundaries
 */

#include "core/Except.h"
#include "core/SocketUTF8.h"
#include "test/Test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * ASCII Tests
 * ============================================================================
 */

TEST (utf8_ascii_empty)
{
  /* Empty input is valid */
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (NULL, 0));
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate ((const unsigned char *)"", 0));
}

TEST (utf8_ascii_single)
{
  /* Single ASCII byte */
  const unsigned char data[] = { 'A' };
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (data, 1));
}

TEST (utf8_ascii_string)
{
  /* ASCII string */
  const char *str = "Hello, World!";
  ASSERT_EQ (UTF8_VALID,
             SocketUTF8_validate ((const unsigned char *)str, strlen (str)));
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate_str (str));
}

TEST (utf8_ascii_all)
{
  /* All valid ASCII bytes (0x00-0x7F) */
  unsigned char data[128];
  for (int i = 0; i < 128; i++)
    data[i] = (unsigned char)i;

  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (data, 128));
}

TEST (utf8_ascii_null_str)
{
  /* NULL string is valid (empty) */
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate_str (NULL));
}

/* ============================================================================
 * 2-Byte Sequence Tests
 * ============================================================================
 */

TEST (utf8_2byte_first)
{
  /* First valid 2-byte code point: U+0080 */
  const unsigned char data[] = { 0xC2, 0x80 };
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (data, 2));
}

TEST (utf8_2byte_last)
{
  /* Last valid 2-byte code point: U+07FF */
  const unsigned char data[] = { 0xDF, 0xBF };
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (data, 2));
}

TEST (utf8_2byte_middle)
{
  /* Middle 2-byte code point: U+00A9 (copyright symbol) */
  const unsigned char data[] = { 0xC2, 0xA9 };
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (data, 2));
}

TEST (utf8_2byte_incomplete)
{
  /* Incomplete 2-byte sequence */
  const unsigned char data[] = { 0xC2 };
  ASSERT_EQ (UTF8_INCOMPLETE, SocketUTF8_validate (data, 1));
}

/* ============================================================================
 * 3-Byte Sequence Tests
 * ============================================================================
 */

TEST (utf8_3byte_first)
{
  /* First valid 3-byte code point: U+0800 */
  const unsigned char data[] = { 0xE0, 0xA0, 0x80 };
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (data, 3));
}

TEST (utf8_3byte_last)
{
  /* Last valid 3-byte code point: U+FFFF (excluding surrogates) */
  const unsigned char data[] = { 0xEF, 0xBF, 0xBF };
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (data, 3));
}

TEST (utf8_3byte_euro)
{
  /* Euro sign: U+20AC */
  const unsigned char data[] = { 0xE2, 0x82, 0xAC };
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (data, 3));
}

TEST (utf8_3byte_cjk)
{
  /* CJK character: U+4E2D (Chinese "middle") */
  const unsigned char data[] = { 0xE4, 0xB8, 0xAD };
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (data, 3));
}

TEST (utf8_3byte_incomplete_1)
{
  /* Incomplete 3-byte sequence (1 byte) */
  const unsigned char data[] = { 0xE0 };
  ASSERT_EQ (UTF8_INCOMPLETE, SocketUTF8_validate (data, 1));
}

TEST (utf8_3byte_incomplete_2)
{
  /* Incomplete 3-byte sequence (2 bytes) */
  const unsigned char data[] = { 0xE0, 0xA0 };
  ASSERT_EQ (UTF8_INCOMPLETE, SocketUTF8_validate (data, 2));
}

/* ============================================================================
 * 4-Byte Sequence Tests
 * ============================================================================
 */

TEST (utf8_4byte_first)
{
  /* First valid 4-byte code point: U+10000 */
  const unsigned char data[] = { 0xF0, 0x90, 0x80, 0x80 };
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (data, 4));
}

TEST (utf8_4byte_last)
{
  /* Last valid code point: U+10FFFF */
  const unsigned char data[] = { 0xF4, 0x8F, 0xBF, 0xBF };
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (data, 4));
}

TEST (utf8_4byte_emoji)
{
  /* Emoji: U+1F600 (grinning face) */
  const unsigned char data[] = { 0xF0, 0x9F, 0x98, 0x80 };
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (data, 4));
}

TEST (utf8_4byte_incomplete)
{
  /* Incomplete 4-byte sequence (3 bytes) */
  const unsigned char data[] = { 0xF0, 0x90, 0x80 };
  ASSERT_EQ (UTF8_INCOMPLETE, SocketUTF8_validate (data, 3));
}

/* ============================================================================
 * Overlong Encoding Rejection (Security Critical)
 * ============================================================================
 */

TEST (utf8_overlong_2byte_nul)
{
  /* Overlong NUL: C0 80 should encode as 00 */
  const unsigned char data[] = { 0xC0, 0x80 };
  ASSERT_EQ (UTF8_OVERLONG, SocketUTF8_validate (data, 2));
}

TEST (utf8_overlong_2byte_slash)
{
  /* Overlong '/': C0 AF should encode as 2F */
  const unsigned char data[] = { 0xC0, 0xAF };
  ASSERT_EQ (UTF8_OVERLONG, SocketUTF8_validate (data, 2));
}

TEST (utf8_overlong_2byte_c1)
{
  /* C1 xx is always overlong */
  const unsigned char data[] = { 0xC1, 0x80 };
  ASSERT_EQ (UTF8_OVERLONG, SocketUTF8_validate (data, 2));
}

TEST (utf8_overlong_3byte)
{
  /* Overlong 3-byte: E0 80 80 should encode shorter */
  const unsigned char data[] = { 0xE0, 0x80, 0x80 };
  ASSERT_EQ (UTF8_OVERLONG, SocketUTF8_validate (data, 3));
}

TEST (utf8_overlong_3byte_boundary)
{
  /* E0 9F BF = U+07FF should be 2-byte */
  const unsigned char data[] = { 0xE0, 0x9F, 0xBF };
  ASSERT_EQ (UTF8_OVERLONG, SocketUTF8_validate (data, 3));
}

TEST (utf8_overlong_4byte)
{
  /* Overlong 4-byte: F0 80 80 80 should encode shorter */
  const unsigned char data[] = { 0xF0, 0x80, 0x80, 0x80 };
  ASSERT_EQ (UTF8_OVERLONG, SocketUTF8_validate (data, 4));
}

TEST (utf8_overlong_4byte_boundary)
{
  /* F0 8F BF BF = U+FFFF should be 3-byte */
  const unsigned char data[] = { 0xF0, 0x8F, 0xBF, 0xBF };
  ASSERT_EQ (UTF8_OVERLONG, SocketUTF8_validate (data, 4));
}

/* ============================================================================
 * Surrogate Rejection (UTF-16 surrogates invalid in UTF-8)
 * ============================================================================
 */

TEST (utf8_surrogate_first)
{
  /* First surrogate: U+D800 (ED A0 80) */
  const unsigned char data[] = { 0xED, 0xA0, 0x80 };
  ASSERT_EQ (UTF8_SURROGATE, SocketUTF8_validate (data, 3));
}

TEST (utf8_surrogate_last)
{
  /* Last surrogate: U+DFFF (ED BF BF) */
  const unsigned char data[] = { 0xED, 0xBF, 0xBF };
  ASSERT_EQ (UTF8_SURROGATE, SocketUTF8_validate (data, 3));
}

TEST (utf8_surrogate_middle)
{
  /* Middle surrogate: U+DB00 */
  const unsigned char data[] = { 0xED, 0xAC, 0x80 };
  ASSERT_EQ (UTF8_SURROGATE, SocketUTF8_validate (data, 3));
}

TEST (utf8_valid_around_surrogates)
{
  /* Code points just before and after surrogates are valid */
  /* U+D7FF (ED 9F BF) */
  const unsigned char before[] = { 0xED, 0x9F, 0xBF };
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (before, 3));

  /* U+E000 (EE 80 80) */
  const unsigned char after[] = { 0xEE, 0x80, 0x80 };
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (after, 3));
}

/* ============================================================================
 * Code Point > U+10FFFF Rejection
 * ============================================================================
 */

TEST (utf8_too_large_f4_90)
{
  /* U+110000 (F4 90 80 80) - first invalid */
  const unsigned char data[] = { 0xF4, 0x90, 0x80, 0x80 };
  ASSERT_EQ (UTF8_TOO_LARGE, SocketUTF8_validate (data, 4));
}

TEST (utf8_too_large_f5)
{
  /* F5 xx xx xx - always invalid (would be U+140000+) */
  const unsigned char data[] = { 0xF5, 0x80, 0x80, 0x80 };
  ASSERT_EQ (UTF8_INVALID, SocketUTF8_validate (data, 4));
}

TEST (utf8_invalid_fe)
{
  /* FE - invalid byte */
  const unsigned char data[] = { 0xFE };
  ASSERT_EQ (UTF8_INVALID, SocketUTF8_validate (data, 1));
}

TEST (utf8_invalid_ff)
{
  /* FF - invalid byte */
  const unsigned char data[] = { 0xFF };
  ASSERT_EQ (UTF8_INVALID, SocketUTF8_validate (data, 1));
}

/* ============================================================================
 * Invalid Continuation Bytes
 * ============================================================================
 */

TEST (utf8_isolated_continuation)
{
  /* 80-BF without start byte */
  const unsigned char data[] = { 0x80 };
  ASSERT_EQ (UTF8_INVALID, SocketUTF8_validate (data, 1));
}

TEST (utf8_missing_continuation)
{
  /* Start byte followed by non-continuation */
  const unsigned char data[] = { 0xC2, 0x41 }; /* 'A' instead of 80-BF */
  ASSERT_EQ (UTF8_INVALID, SocketUTF8_validate (data, 2));
}

TEST (utf8_unexpected_start)
{
  /* Start byte where continuation expected */
  const unsigned char data[] = { 0xE0, 0xC0 }; /* Another start byte */
  ASSERT_EQ (UTF8_INVALID, SocketUTF8_validate (data, 2));
}

/* ============================================================================
 * Incremental Validation Tests
 * ============================================================================
 */

TEST (utf8_incremental_ascii)
{
  SocketUTF8_State state;
  const unsigned char data[] = "Hello";

  SocketUTF8_init (&state);
  ASSERT_EQ (UTF8_VALID, SocketUTF8_update (&state, data, 5));
  ASSERT_EQ (UTF8_VALID, SocketUTF8_finish (&state));
}

TEST (utf8_incremental_empty)
{
  SocketUTF8_State state;

  SocketUTF8_init (&state);
  ASSERT_EQ (UTF8_VALID, SocketUTF8_update (&state, NULL, 0));
  ASSERT_EQ (UTF8_VALID, SocketUTF8_finish (&state));
}

TEST (utf8_incremental_split_2byte)
{
  SocketUTF8_State state;
  /* U+00A9 (copyright) = C2 A9 */
  const unsigned char part1[] = { 0xC2 };
  const unsigned char part2[] = { 0xA9 };

  SocketUTF8_init (&state);
  ASSERT_EQ (UTF8_INCOMPLETE, SocketUTF8_update (&state, part1, 1));
  ASSERT_EQ (UTF8_VALID, SocketUTF8_update (&state, part2, 1));
  ASSERT_EQ (UTF8_VALID, SocketUTF8_finish (&state));
}

TEST (utf8_incremental_split_3byte)
{
  SocketUTF8_State state;
  /* Euro sign U+20AC = E2 82 AC */
  const unsigned char part1[] = { 0xE2 };
  const unsigned char part2[] = { 0x82 };
  const unsigned char part3[] = { 0xAC };

  SocketUTF8_init (&state);
  ASSERT_EQ (UTF8_INCOMPLETE, SocketUTF8_update (&state, part1, 1));
  ASSERT_EQ (UTF8_INCOMPLETE, SocketUTF8_update (&state, part2, 1));
  ASSERT_EQ (UTF8_VALID, SocketUTF8_update (&state, part3, 1));
  ASSERT_EQ (UTF8_VALID, SocketUTF8_finish (&state));
}

TEST (utf8_incremental_split_4byte)
{
  SocketUTF8_State state;
  /* Emoji U+1F600 = F0 9F 98 80 */
  const unsigned char part1[] = { 0xF0, 0x9F };
  const unsigned char part2[] = { 0x98, 0x80 };

  SocketUTF8_init (&state);
  ASSERT_EQ (UTF8_INCOMPLETE, SocketUTF8_update (&state, part1, 2));
  ASSERT_EQ (UTF8_VALID, SocketUTF8_update (&state, part2, 2));
  ASSERT_EQ (UTF8_VALID, SocketUTF8_finish (&state));
}

TEST (utf8_incremental_truncated)
{
  SocketUTF8_State state;
  /* Start 3-byte sequence but don't complete */
  const unsigned char data[] = { 0xE2, 0x82 };

  SocketUTF8_init (&state);
  ASSERT_EQ (UTF8_INCOMPLETE, SocketUTF8_update (&state, data, 2));
  ASSERT_EQ (UTF8_INCOMPLETE, SocketUTF8_finish (&state));
}

TEST (utf8_incremental_invalid)
{
  SocketUTF8_State state;
  /* Surrogate in middle of stream */
  const unsigned char part1[] = { 'A', 'B' };
  const unsigned char part2[] = { 0xED, 0xA0, 0x80 }; /* Surrogate */

  SocketUTF8_init (&state);
  ASSERT_EQ (UTF8_VALID, SocketUTF8_update (&state, part1, 2));
  ASSERT_EQ (UTF8_SURROGATE, SocketUTF8_update (&state, part2, 3));
}

TEST (utf8_incremental_reset)
{
  SocketUTF8_State state;

  SocketUTF8_init (&state);
  SocketUTF8_update (&state, (const unsigned char *)"\xE2", 1);
  ASSERT_EQ (UTF8_INCOMPLETE, SocketUTF8_finish (&state));

  /* Reset and validate fresh data */
  SocketUTF8_reset (&state);
  ASSERT_EQ (UTF8_VALID,
             SocketUTF8_update (&state, (const unsigned char *)"OK", 2));
  ASSERT_EQ (UTF8_VALID, SocketUTF8_finish (&state));
}

/* ============================================================================
 * Utility Function Tests
 * ============================================================================
 */

TEST (utf8_sequence_len)
{
  /* ASCII */
  ASSERT_EQ (1, SocketUTF8_sequence_len (0x00));
  ASSERT_EQ (1, SocketUTF8_sequence_len (0x7F));

  /* Continuation bytes (invalid as start) */
  ASSERT_EQ (0, SocketUTF8_sequence_len (0x80));
  ASSERT_EQ (0, SocketUTF8_sequence_len (0xBF));

  /* Invalid overlong starts */
  ASSERT_EQ (0, SocketUTF8_sequence_len (0xC0));
  ASSERT_EQ (0, SocketUTF8_sequence_len (0xC1));

  /* Valid 2-byte starts */
  ASSERT_EQ (2, SocketUTF8_sequence_len (0xC2));
  ASSERT_EQ (2, SocketUTF8_sequence_len (0xDF));

  /* 3-byte starts */
  ASSERT_EQ (3, SocketUTF8_sequence_len (0xE0));
  ASSERT_EQ (3, SocketUTF8_sequence_len (0xEF));

  /* Valid 4-byte starts */
  ASSERT_EQ (4, SocketUTF8_sequence_len (0xF0));
  ASSERT_EQ (4, SocketUTF8_sequence_len (0xF4));

  /* Invalid bytes */
  ASSERT_EQ (0, SocketUTF8_sequence_len (0xF5));
  ASSERT_EQ (0, SocketUTF8_sequence_len (0xFE));
  ASSERT_EQ (0, SocketUTF8_sequence_len (0xFF));
}

TEST (utf8_codepoint_len)
{
  /* 1-byte range */
  ASSERT_EQ (1, SocketUTF8_codepoint_len (0x00));
  ASSERT_EQ (1, SocketUTF8_codepoint_len (0x7F));

  /* 2-byte range */
  ASSERT_EQ (2, SocketUTF8_codepoint_len (0x80));
  ASSERT_EQ (2, SocketUTF8_codepoint_len (0x7FF));

  /* 3-byte range */
  ASSERT_EQ (3, SocketUTF8_codepoint_len (0x800));
  ASSERT_EQ (3, SocketUTF8_codepoint_len (0xFFFF));

  /* 4-byte range */
  ASSERT_EQ (4, SocketUTF8_codepoint_len (0x10000));
  ASSERT_EQ (4, SocketUTF8_codepoint_len (0x10FFFF));

  /* Surrogates (invalid) */
  ASSERT_EQ (0, SocketUTF8_codepoint_len (0xD800));
  ASSERT_EQ (0, SocketUTF8_codepoint_len (0xDFFF));

  /* Out of range */
  ASSERT_EQ (0, SocketUTF8_codepoint_len (0x110000));
}

TEST (utf8_encode_ascii)
{
  unsigned char output[4] = { 0 };
  ASSERT_EQ (1, SocketUTF8_encode (0x41, output)); /* 'A' */
  ASSERT_EQ (0x41, output[0]);
}

TEST (utf8_encode_2byte)
{
  unsigned char output[4] = { 0 };
  ASSERT_EQ (2, SocketUTF8_encode (0x00A9, output)); /* Copyright */
  ASSERT_EQ (0xC2, output[0]);
  ASSERT_EQ (0xA9, output[1]);
}

TEST (utf8_encode_3byte)
{
  unsigned char output[4] = { 0 };
  ASSERT_EQ (3, SocketUTF8_encode (0x20AC, output)); /* Euro */
  ASSERT_EQ (0xE2, output[0]);
  ASSERT_EQ (0x82, output[1]);
  ASSERT_EQ (0xAC, output[2]);
}

TEST (utf8_encode_4byte)
{
  unsigned char output[4] = { 0 };
  ASSERT_EQ (4, SocketUTF8_encode (0x1F600, output)); /* Emoji */
  ASSERT_EQ (0xF0, output[0]);
  ASSERT_EQ (0x9F, output[1]);
  ASSERT_EQ (0x98, output[2]);
  ASSERT_EQ (0x80, output[3]);
}

TEST (utf8_encode_invalid)
{
  unsigned char output[4];
  ASSERT_EQ (0, SocketUTF8_encode (0xD800, output));   /* Surrogate */
  ASSERT_EQ (0, SocketUTF8_encode (0x110000, output)); /* Too large */
  ASSERT_EQ (0, SocketUTF8_encode (0x41, NULL));       /* NULL output */
}

TEST (utf8_decode_ascii)
{
  const unsigned char data[] = { 'A' };
  uint32_t cp;
  size_t consumed;

  ASSERT_EQ (UTF8_VALID, SocketUTF8_decode (data, 1, &cp, &consumed));
  ASSERT_EQ (0x41u, cp);
  ASSERT_EQ (1u, consumed);
}

TEST (utf8_decode_2byte)
{
  const unsigned char data[] = { 0xC2, 0xA9 };
  uint32_t cp;
  size_t consumed;

  ASSERT_EQ (UTF8_VALID, SocketUTF8_decode (data, 2, &cp, &consumed));
  ASSERT_EQ (0x00A9u, cp);
  ASSERT_EQ (2u, consumed);
}

TEST (utf8_decode_3byte)
{
  const unsigned char data[] = { 0xE2, 0x82, 0xAC };
  uint32_t cp;
  size_t consumed;

  ASSERT_EQ (UTF8_VALID, SocketUTF8_decode (data, 3, &cp, &consumed));
  ASSERT_EQ (0x20ACu, cp);
  ASSERT_EQ (3u, consumed);
}

TEST (utf8_decode_4byte)
{
  const unsigned char data[] = { 0xF0, 0x9F, 0x98, 0x80 };
  uint32_t cp;
  size_t consumed;

  ASSERT_EQ (UTF8_VALID, SocketUTF8_decode (data, 4, &cp, &consumed));
  ASSERT_EQ (0x1F600u, cp);
  ASSERT_EQ (4u, consumed);
}

TEST (utf8_decode_incomplete)
{
  const unsigned char data[] = { 0xE2, 0x82 };
  size_t consumed;

  ASSERT_EQ (UTF8_INCOMPLETE, SocketUTF8_decode (data, 2, NULL, &consumed));
}

TEST (utf8_decode_overlong)
{
  const unsigned char data[] = { 0xC0, 0x80 };
  size_t consumed;

  ASSERT_EQ (UTF8_OVERLONG, SocketUTF8_decode (data, 2, NULL, &consumed));
}

TEST (utf8_decode_surrogate)
{
  const unsigned char data[] = { 0xED, 0xA0, 0x80 };
  size_t consumed;

  ASSERT_EQ (UTF8_SURROGATE, SocketUTF8_decode (data, 3, NULL, &consumed));
}

TEST (utf8_count_codepoints)
{
  const unsigned char data[] = "Hello\xE2\x82\xAC"; /* Hello + Euro */
  size_t count;

  ASSERT_EQ (UTF8_VALID, SocketUTF8_count_codepoints (data, 8, &count));
  ASSERT_EQ (6u, count); /* H e l l o Euro */
}

TEST (utf8_count_empty)
{
  size_t count = 999;
  ASSERT_EQ (UTF8_VALID, SocketUTF8_count_codepoints (NULL, 0, &count));
  ASSERT_EQ (0u, count);
}

TEST (utf8_count_invalid)
{
  const unsigned char data[] = { 0xED, 0xA0, 0x80 }; /* Surrogate */
  size_t count;

  ASSERT_EQ (UTF8_SURROGATE, SocketUTF8_count_codepoints (data, 3, &count));
}

TEST (utf8_result_string)
{
  /* Verify all result codes have strings */
  ASSERT_NOT_NULL (SocketUTF8_result_string (UTF8_VALID));
  ASSERT_NOT_NULL (SocketUTF8_result_string (UTF8_INVALID));
  ASSERT_NOT_NULL (SocketUTF8_result_string (UTF8_INCOMPLETE));
  ASSERT_NOT_NULL (SocketUTF8_result_string (UTF8_OVERLONG));
  ASSERT_NOT_NULL (SocketUTF8_result_string (UTF8_SURROGATE));
  ASSERT_NOT_NULL (SocketUTF8_result_string (UTF8_TOO_LARGE));

  /* Invalid code returns something */
  ASSERT_NOT_NULL (SocketUTF8_result_string ((SocketUTF8_Result)99));
}

/* ============================================================================
 * Encode/Decode Round-Trip Tests
 * ============================================================================
 */

TEST (utf8_roundtrip_ascii)
{
  for (uint32_t cp = 0; cp <= 0x7F; cp++)
    {
      unsigned char encoded[4];
      uint32_t decoded;
      size_t consumed;
      int len = SocketUTF8_encode (cp, encoded);
      ASSERT_EQ (1, len);
      ASSERT_EQ (UTF8_VALID,
                 SocketUTF8_decode (encoded, (size_t)len, &decoded, &consumed));
      ASSERT_EQ (cp, decoded);
    }
}

TEST (utf8_roundtrip_sample)
{
  /* Sample code points from each range */
  const uint32_t test_codepoints[] = {
    0x00,     /* NUL */
    0x41,     /* 'A' */
    0x7F,     /* DEL */
    0x80,     /* First 2-byte */
    0x7FF,    /* Last 2-byte */
    0x800,    /* First 3-byte */
    0x20AC,   /* Euro */
    0xD7FF,   /* Before surrogates */
    0xE000,   /* After surrogates */
    0xFFFF,   /* Last 3-byte */
    0x10000,  /* First 4-byte */
    0x1F600,  /* Emoji */
    0x10FFFF, /* Last valid */
  };

  for (size_t i = 0; i < sizeof (test_codepoints) / sizeof (test_codepoints[0]);
       i++)
    {
      uint32_t cp = test_codepoints[i];
      unsigned char encoded[4];
      uint32_t decoded;
      size_t consumed;

      int len = SocketUTF8_encode (cp, encoded);
      ASSERT (len > 0);
      ASSERT_EQ (UTF8_VALID,
                 SocketUTF8_decode (encoded, (size_t)len, &decoded, &consumed));
      ASSERT_EQ (cp, decoded);
      ASSERT_EQ ((size_t)len, consumed);
    }
}

/* ============================================================================
 * Mixed Content Tests
 * ============================================================================
 */

TEST (utf8_mixed_content)
{
  /* Mix of ASCII, 2-byte, 3-byte, 4-byte */
  const unsigned char data[] = {
    'H',  'i',  ' ',       /* ASCII */
    0xC2, 0xA9,            /* Copyright */
    ' ',                   /* ASCII */
    0xE2, 0x82, 0xAC,      /* Euro */
    ' ',                   /* ASCII */
    0xF0, 0x9F, 0x98, 0x80 /* Emoji */
  };

  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (data, sizeof (data)));
}

TEST (utf8_long_valid)
{
  /* Longer valid UTF-8 string */
  const char *str = "Hello, \xC2\xA9 2024 "
                    "\xE4\xB8\x96\xE7\x95\x8C" /* Chinese "world" */
                    " \xF0\x9F\x8C\x8D";       /* Earth emoji */

  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate_str (str));
}

/* ============================================================================
 * Boundary and Stress Tests
 * ============================================================================
 */

TEST (utf8_stress_large_ascii)
{
  /* Test 1MB of valid ASCII */
  size_t len = 1024 * 1024;
  unsigned char *data = malloc (len);
  if (!data)
    {
      fprintf (stderr, "Failed to allocate memory for test\n");
      return;
    }

  memset (data, 'A', len);
  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (data, len));
  free (data);
}

TEST (utf8_stress_large_multibyte)
{
  /* Test 1MB of 3-byte sequences (Euro signs) */
  size_t num_euros = 100000; /* 100K Euro signs = 300KB */
  size_t len = num_euros * 3;
  unsigned char *data = malloc (len);
  if (!data)
    {
      fprintf (stderr, "Failed to allocate memory for test\n");
      return;
    }

  /* Fill with Euro sign: E2 82 AC */
  for (size_t i = 0; i < num_euros; i++)
    {
      data[i * 3 + 0] = 0xE2;
      data[i * 3 + 1] = 0x82;
      data[i * 3 + 2] = 0xAC;
    }

  ASSERT_EQ (UTF8_VALID, SocketUTF8_validate (data, len));
  free (data);
}

TEST (utf8_state_tracking_bytes_2byte)
{
  SocketUTF8_State state;
  SocketUTF8_init (&state);

  /* Start 2-byte sequence */
  const unsigned char part1[] = { 0xC2 };
  SocketUTF8_update (&state, part1, 1);
  ASSERT_EQ (2u, state.bytes_needed); /* Expecting 2-byte sequence */
  ASSERT_EQ (1u, state.bytes_seen);   /* Seen 1 so far */

  /* Complete */
  const unsigned char part2[] = { 0xA9 };
  SocketUTF8_update (&state, part2, 1);
  ASSERT_EQ (0u, state.bytes_needed); /* Sequence complete */
  ASSERT_EQ (0u, state.bytes_seen);
}

TEST (utf8_state_tracking_bytes_3byte)
{
  SocketUTF8_State state;
  SocketUTF8_init (&state);

  /* Start 3-byte sequence */
  const unsigned char part1[] = { 0xE2 };
  SocketUTF8_update (&state, part1, 1);
  ASSERT_EQ (3u, state.bytes_needed); /* Expecting 3-byte sequence */
  ASSERT_EQ (1u, state.bytes_seen);   /* Seen 1 so far */

  /* Continue */
  const unsigned char part2[] = { 0x82 };
  SocketUTF8_update (&state, part2, 1);
  ASSERT_EQ (3u, state.bytes_needed);
  ASSERT_EQ (2u, state.bytes_seen);

  /* Complete */
  const unsigned char part3[] = { 0xAC };
  SocketUTF8_update (&state, part3, 1);
  ASSERT_EQ (0u, state.bytes_needed); /* Sequence complete */
  ASSERT_EQ (0u, state.bytes_seen);
}

TEST (utf8_state_tracking_bytes_4byte)
{
  SocketUTF8_State state;
  SocketUTF8_init (&state);

  /* Start 4-byte sequence */
  const unsigned char part1[] = { 0xF0 };
  SocketUTF8_update (&state, part1, 1);
  ASSERT_EQ (4u, state.bytes_needed); /* Expecting 4-byte sequence */
  ASSERT_EQ (1u, state.bytes_seen);   /* Seen 1 so far */

  /* Continue */
  const unsigned char part2[] = { 0x9F };
  SocketUTF8_update (&state, part2, 1);
  ASSERT_EQ (4u, state.bytes_needed);
  ASSERT_EQ (2u, state.bytes_seen);

  /* Continue */
  const unsigned char part3[] = { 0x98 };
  SocketUTF8_update (&state, part3, 1);
  ASSERT_EQ (4u, state.bytes_needed);
  ASSERT_EQ (3u, state.bytes_seen);

  /* Complete */
  const unsigned char part4[] = { 0x80 };
  SocketUTF8_update (&state, part4, 1);
  ASSERT_EQ (0u, state.bytes_needed); /* Sequence complete */
  ASSERT_EQ (0u, state.bytes_seen);
}

TEST (utf8_multiple_reset_cycles)
{
  SocketUTF8_State state;
  SocketUTF8_init (&state);

  for (int i = 0; i < 1000; i++)
    {
      const unsigned char data[] = { 0xE2, 0x82, 0xAC }; /* Euro */
      ASSERT_EQ (UTF8_VALID, SocketUTF8_update (&state, data, 3));
      SocketUTF8_reset (&state);
    }
}

TEST (utf8_decode_consumed_null)
{
  const unsigned char data[] = { 0xC2, 0xA9 };
  uint32_t cp;

  /* Test with NULL consumed parameter */
  ASSERT_EQ (UTF8_VALID, SocketUTF8_decode (data, 2, &cp, NULL));
  ASSERT_EQ (0xA9u, cp);
}

TEST (utf8_decode_2byte_invalid_continuation)
{
  /* Test each continuation byte failure point */
  const unsigned char data1[] = { 0xC2, 0x41 }; /* ASCII instead of
                                                   continuation */
  size_t consumed;
  uint32_t cp;
  ASSERT_EQ (UTF8_INVALID, SocketUTF8_decode (data1, 2, &cp, &consumed));
  ASSERT_EQ (1u, consumed); /* Failed at second byte */
}

TEST (utf8_decode_3byte_invalid_continuation_first)
{
  /* Invalid first continuation byte */
  const unsigned char data[] = { 0xE2, 0x41, 0xAC }; /* ASCII at position 1 */
  size_t consumed;
  uint32_t cp;
  ASSERT_EQ (UTF8_INVALID, SocketUTF8_decode (data, 3, &cp, &consumed));
  ASSERT_EQ (1u, consumed); /* Failed at second byte */
}

TEST (utf8_decode_3byte_invalid_continuation_second)
{
  /* Invalid second continuation byte */
  const unsigned char data[] = { 0xE2, 0x82, 0x41 }; /* ASCII at position 2 */
  size_t consumed;
  uint32_t cp;
  ASSERT_EQ (UTF8_INVALID, SocketUTF8_decode (data, 3, &cp, &consumed));
  ASSERT_EQ (2u, consumed); /* Failed at third byte */
}

TEST (utf8_decode_4byte_invalid_continuation_first)
{
  /* Invalid first continuation byte */
  const unsigned char data[] = { 0xF0, 0x41, 0x98, 0x80 };
  size_t consumed;
  uint32_t cp;
  ASSERT_EQ (UTF8_INVALID, SocketUTF8_decode (data, 4, &cp, &consumed));
  ASSERT_EQ (1u, consumed);
}

TEST (utf8_decode_4byte_invalid_continuation_second)
{
  /* Invalid second continuation byte */
  const unsigned char data[] = { 0xF0, 0x9F, 0x41, 0x80 };
  size_t consumed;
  uint32_t cp;
  ASSERT_EQ (UTF8_INVALID, SocketUTF8_decode (data, 4, &cp, &consumed));
  ASSERT_EQ (2u, consumed);
}

TEST (utf8_decode_4byte_invalid_continuation_third)
{
  /* Invalid third continuation byte */
  const unsigned char data[] = { 0xF0, 0x9F, 0x98, 0x41 };
  size_t consumed;
  uint32_t cp;
  ASSERT_EQ (UTF8_INVALID, SocketUTF8_decode (data, 4, &cp, &consumed));
  ASSERT_EQ (3u, consumed);
}

TEST (utf8_count_millions)
{
  /* Generate 1 million ASCII characters */
  size_t len = 1000000;
  unsigned char *data = malloc (len);
  if (!data)
    {
      fprintf (stderr, "Failed to allocate memory for test\n");
      return;
    }

  memset (data, 'A', len);
  size_t count;
  ASSERT_EQ (UTF8_VALID, SocketUTF8_count_codepoints (data, len, &count));
  ASSERT_EQ (len, count);
  free (data);
}

TEST (utf8_count_large_multibyte)
{
  /* Count 100K Euro signs (3 bytes each) */
  size_t num_euros = 100000;
  size_t len = num_euros * 3;
  unsigned char *data = malloc (len);
  if (!data)
    {
      fprintf (stderr, "Failed to allocate memory for test\n");
      return;
    }

  for (size_t i = 0; i < num_euros; i++)
    {
      data[i * 3 + 0] = 0xE2;
      data[i * 3 + 1] = 0x82;
      data[i * 3 + 2] = 0xAC;
    }

  size_t count;
  ASSERT_EQ (UTF8_VALID, SocketUTF8_count_codepoints (data, len, &count));
  ASSERT_EQ (num_euros, count);
  free (data);
}

TEST (utf8_incremental_large_chunks)
{
  /* Test incremental validation with large chunks */
  SocketUTF8_State state;
  SocketUTF8_init (&state);

  size_t chunk_size = 100000;
  unsigned char *chunk = malloc (chunk_size);
  if (!chunk)
    {
      fprintf (stderr, "Failed to allocate memory for test\n");
      return;
    }

  memset (chunk, 'X', chunk_size);

  /* Feed 10 chunks */
  for (int i = 0; i < 10; i++)
    {
      ASSERT_EQ (UTF8_VALID, SocketUTF8_update (&state, chunk, chunk_size));
    }

  ASSERT_EQ (UTF8_VALID, SocketUTF8_finish (&state));
  free (chunk);
}

TEST (utf8_incremental_split_across_many_chunks)
{
  /* Split a single 4-byte sequence across 4 chunks */
  SocketUTF8_State state;
  SocketUTF8_init (&state);

  const unsigned char part1[] = { 0xF0 };
  const unsigned char part2[] = { 0x9F };
  const unsigned char part3[] = { 0x98 };
  const unsigned char part4[] = { 0x80 };

  ASSERT_EQ (UTF8_INCOMPLETE, SocketUTF8_update (&state, part1, 1));
  ASSERT_EQ (UTF8_INCOMPLETE, SocketUTF8_update (&state, part2, 1));
  ASSERT_EQ (UTF8_INCOMPLETE, SocketUTF8_update (&state, part3, 1));
  ASSERT_EQ (UTF8_VALID, SocketUTF8_update (&state, part4, 1));
  ASSERT_EQ (UTF8_VALID, SocketUTF8_finish (&state));
}

TEST (utf8_decode_codepoint_null)
{
  /* Test decode with NULL codepoint parameter */
  const unsigned char data[] = { 0xE2, 0x82, 0xAC }; /* Euro */
  size_t consumed;

  ASSERT_EQ (UTF8_VALID, SocketUTF8_decode (data, 3, NULL, &consumed));
  ASSERT_EQ (3u, consumed);
}

TEST (utf8_boundary_all_ranges)
{
  /* Test boundary values for each byte length */
  struct
  {
    const unsigned char *data;
    size_t len;
    uint32_t expected_cp;
  } tests[] = {
    /* 1-byte boundaries */
    { (const unsigned char *)"\x00", 1, 0x00 },     /* Min 1-byte */
    { (const unsigned char *)"\x7F", 1, 0x7F },     /* Max 1-byte */

    /* 2-byte boundaries */
    { (const unsigned char *)"\xC2\x80", 2, 0x80 }, /* Min 2-byte */
    { (const unsigned char *)"\xDF\xBF", 2, 0x7FF }, /* Max 2-byte */

    /* 3-byte boundaries */
    { (const unsigned char *)"\xE0\xA0\x80", 3, 0x800 }, /* Min 3-byte */
    { (const unsigned char *)"\xEF\xBF\xBF", 3, 0xFFFF }, /* Max 3-byte */

    /* 4-byte boundaries */
    { (const unsigned char *)"\xF0\x90\x80\x80", 4, 0x10000 }, /* Min 4-byte
                                                                 */
    { (const unsigned char *)"\xF4\x8F\xBF\xBF", 4, 0x10FFFF }, /* Max
                                                                   codepoint */
  };

  for (size_t i = 0; i < sizeof (tests) / sizeof (tests[0]); i++)
    {
      uint32_t cp;
      size_t consumed;
      ASSERT_EQ (UTF8_VALID,
                 SocketUTF8_decode (tests[i].data, tests[i].len, &cp, &consumed));
      ASSERT_EQ (tests[i].expected_cp, cp);
      ASSERT_EQ (tests[i].len, consumed);
    }
}

/* ============================================================================
||||||| parent of a3f6affe (test(core): Add NULL pointer validation tests for SocketUTF8)
 * NULL Pointer Validation Tests
 * ============================================================================
 */

TEST (utf8_validate_null_data)
{
  /* NULL data with len > 0 should raise exception */
  volatile int caught = 0;

  TRY
  {
    SocketUTF8_validate (NULL, 1);
  }
  EXCEPT (SocketUTF8_Failed)
  {
    caught = 1;
  }
  END_TRY;

  ASSERT_EQ (1, caught);
}

TEST (utf8_init_null_state)
{
  /* NULL state pointer should raise exception */
  volatile int caught = 0;

  TRY
  {
    SocketUTF8_init (NULL);
  }
  EXCEPT (SocketUTF8_Failed)
  {
    caught = 1;
  }
  END_TRY;

  ASSERT_EQ (1, caught);
}

TEST (utf8_update_null_state)
{
  /* NULL state pointer should raise exception */
  volatile int caught = 0;
  const unsigned char data[] = "test";

  TRY
  {
    SocketUTF8_update (NULL, data, 4);
  }
  EXCEPT (SocketUTF8_Failed)
  {
    caught = 1;
  }
  END_TRY;

  ASSERT_EQ (1, caught);
}

TEST (utf8_update_null_data)
{
  /* NULL data with len > 0 should raise exception */
  volatile int caught = 0;
  SocketUTF8_State state;

  SocketUTF8_init (&state);

  TRY
  {
    SocketUTF8_update (&state, NULL, 1);
  }
  EXCEPT (SocketUTF8_Failed)
  {
    caught = 1;
  }
  END_TRY;

  ASSERT_EQ (1, caught);
}

TEST (utf8_finish_null_state)
{
  /* NULL state pointer should raise exception */
  volatile int caught = 0;

  TRY
  {
    SocketUTF8_finish (NULL);
  }
  EXCEPT (SocketUTF8_Failed)
  {
    caught = 1;
  }
  END_TRY;

  ASSERT_EQ (1, caught);
}

TEST (utf8_reset_null_state)
{
  /* NULL state pointer should raise exception */
  volatile int caught = 0;

  TRY
  {
    SocketUTF8_reset (NULL);
  }
  EXCEPT (SocketUTF8_Failed)
  {
    caught = 1;
  }
  END_TRY;

  ASSERT_EQ (1, caught);
}

TEST (utf8_count_codepoints_null_count)
{
  /* NULL count pointer should raise exception */
  volatile int caught = 0;
  const unsigned char data[] = "test";

  TRY
  {
    SocketUTF8_count_codepoints (data, 4, NULL);
  }
  EXCEPT (SocketUTF8_Failed)
  {
    caught = 1;
  }
  END_TRY;

  ASSERT_EQ (1, caught);
}

TEST (utf8_count_codepoints_null_data)
{
  /* NULL data with len > 0 should raise exception */
  volatile int caught = 0;
  size_t count;

  TRY
  {
    SocketUTF8_count_codepoints (NULL, 1, &count);
  }
  EXCEPT (SocketUTF8_Failed)
  {
    caught = 1;
  }
  END_TRY;

  ASSERT_EQ (1, caught);
}

TEST (utf8_decode_null_data)
{
  /* NULL data with len > 0 should raise exception */
  volatile int caught = 0;
  uint32_t cp;
  size_t consumed;

  TRY
  {
    SocketUTF8_decode (NULL, 1, &cp, &consumed);
  }
  EXCEPT (SocketUTF8_Failed)
  {
    caught = 1;
  }
  END_TRY;

  ASSERT_EQ (1, caught);
}

/* ============================================================================
 * Main Entry Point
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
