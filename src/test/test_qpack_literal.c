/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_qpack_literal.c - Tests for QPACK Literal Field Line with Literal Name
 *                        (RFC 9204 Section 4.5.6)
 *
 * Tests encoding/decoding of field lines where both name and value are
 * literal strings, with various configurations of Huffman encoding and
 * the never-indexed flag.
 */

#include <string.h>

#include "http/qpack/SocketQPACK.h"
#include "test/Test.h"

/* ============================================================================
 * Pattern Validation Tests
 * ============================================================================
 */

TEST (qpack_literal_literal_pattern_valid)
{
  /* Pattern '001' should match */
  ASSERT (SocketQPACK_is_literal_literal (0x20)); /* 00100000 */
  ASSERT (SocketQPACK_is_literal_literal (0x21)); /* 00100001 */
  ASSERT (SocketQPACK_is_literal_literal (0x2F)); /* 00101111 */
  ASSERT (SocketQPACK_is_literal_literal (0x30)); /* 00110000 */
  ASSERT (SocketQPACK_is_literal_literal (0x3F)); /* 00111111 */
}

TEST (qpack_literal_literal_pattern_invalid)
{
  /* Pattern '000', '010', '011', '1xx' should not match */
  ASSERT (!SocketQPACK_is_literal_literal (0x00)); /* 00000000 - indexed */
  ASSERT (
      !SocketQPACK_is_literal_literal (0x40)); /* 01000000 - literal indexed */
  ASSERT (!SocketQPACK_is_literal_literal (0x60)); /* 01100000 */
  ASSERT (!SocketQPACK_is_literal_literal (0x80)); /* 10000000 - indexed */
  ASSERT (!SocketQPACK_is_literal_literal (0xC0)); /* 11000000 */
}

/* ============================================================================
 * Encoding Tests - Basic
 * ============================================================================
 */

TEST (qpack_literal_literal_encode_basic)
{
  unsigned char buf[256];
  const char *name = "content-type";
  const char *value = "text/plain";
  ssize_t len;

  len = SocketQPACK_literal_literal_encode ((const unsigned char *)name,
                                            strlen (name),
                                            (const unsigned char *)value,
                                            strlen (value),
                                            0,
                                            0,
                                            buf,
                                            sizeof (buf));

  ASSERT (len > 0);

  /* Verify pattern bits are '001' */
  ASSERT (SocketQPACK_is_literal_literal (buf[0]));

  /* Verify N bit is 0 (not never-indexed) */
  ASSERT_EQ (0, buf[0] & SOCKETQPACK_NEVER_INDEXED_BIT);

  /* Verify H bit for name is 0 (plain text) */
  ASSERT_EQ (0, buf[0] & SOCKETQPACK_NAME_HUFFMAN_BIT);
}

TEST (qpack_literal_literal_encode_never_indexed)
{
  unsigned char buf[256];
  const char *name = "authorization";
  const char *value = "Bearer secret-token";
  ssize_t len;

  len = SocketQPACK_literal_literal_encode (
      (const unsigned char *)name,
      strlen (name),
      (const unsigned char *)value,
      strlen (value),
      1,
      0,
      buf,
      sizeof (buf)); /* never_indexed = 1 */

  ASSERT (len > 0);

  /* Verify N bit is set */
  ASSERT_NE (0, buf[0] & SOCKETQPACK_NEVER_INDEXED_BIT);
}

TEST (qpack_literal_literal_encode_huffman)
{
  unsigned char buf[256];
  const char *name = "www-authenticate";
  const char *value = "www.example.org";
  ssize_t len;

  len = SocketQPACK_literal_literal_encode ((const unsigned char *)name,
                                            strlen (name),
                                            (const unsigned char *)value,
                                            strlen (value),
                                            0,
                                            1,
                                            buf,
                                            sizeof (buf)); /* use_huffman = 1 */

  ASSERT (len > 0);

  /* Huffman may or may not be used depending on whether it saves space */
}

TEST (qpack_literal_literal_encode_empty_value)
{
  unsigned char buf[256];
  const char *name = "x-empty";
  ssize_t len;

  len = SocketQPACK_literal_literal_encode ((const unsigned char *)name,
                                            strlen (name),
                                            (const unsigned char *)"",
                                            0,
                                            0,
                                            0,
                                            buf,
                                            sizeof (buf));

  ASSERT (len > 0);
}

TEST (qpack_literal_literal_encode_buffer_too_small)
{
  unsigned char buf[2];
  const char *name = "content-type";
  const char *value = "application/json";
  ssize_t len;

  len = SocketQPACK_literal_literal_encode ((const unsigned char *)name,
                                            strlen (name),
                                            (const unsigned char *)value,
                                            strlen (value),
                                            0,
                                            0,
                                            buf,
                                            sizeof (buf));

  ASSERT_EQ (-1, len);
}

TEST (qpack_literal_literal_encode_null_buffer)
{
  ssize_t len
      = SocketQPACK_literal_literal_encode ((const unsigned char *)"name",
                                            4,
                                            (const unsigned char *)"value",
                                            5,
                                            0,
                                            0,
                                            NULL,
                                            256);

  ASSERT_EQ (-1, len);
}

/* ============================================================================
 * Decoding Tests - Basic
 * ============================================================================
 */

TEST (qpack_literal_literal_decode_basic)
{
  unsigned char encoded[256];
  unsigned char name_buf[256];
  unsigned char value_buf[256];
  const char *name = "content-type";
  const char *value = "text/plain";
  ssize_t enc_len;
  SocketQPACK_LiteralLiteral_T result;
  size_t consumed;

  /* Encode first */
  enc_len = SocketQPACK_literal_literal_encode ((const unsigned char *)name,
                                                strlen (name),
                                                (const unsigned char *)value,
                                                strlen (value),
                                                0,
                                                0,
                                                encoded,
                                                sizeof (encoded));
  ASSERT (enc_len > 0);

  /* Decode */
  SocketQPACK_Result res
      = SocketQPACK_literal_literal_decode (encoded,
                                            (size_t)enc_len,
                                            name_buf,
                                            sizeof (name_buf),
                                            value_buf,
                                            sizeof (value_buf),
                                            &result,
                                            &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ ((size_t)enc_len, consumed);
  ASSERT_EQ (strlen (name), result.name_len);
  ASSERT_EQ (strlen (value), result.value_len);
  ASSERT_EQ (0, result.never_indexed);
  ASSERT (memcmp (result.name, name, result.name_len) == 0);
  ASSERT (memcmp (result.value, value, result.value_len) == 0);
}

TEST (qpack_literal_literal_decode_never_indexed)
{
  unsigned char encoded[256];
  unsigned char name_buf[256];
  unsigned char value_buf[256];
  const char *name = "authorization";
  const char *value = "Bearer token123";
  ssize_t enc_len;
  SocketQPACK_LiteralLiteral_T result;
  size_t consumed;

  /* Encode with never_indexed = 1 */
  enc_len = SocketQPACK_literal_literal_encode ((const unsigned char *)name,
                                                strlen (name),
                                                (const unsigned char *)value,
                                                strlen (value),
                                                1,
                                                0,
                                                encoded,
                                                sizeof (encoded));
  ASSERT (enc_len > 0);

  /* Decode */
  SocketQPACK_Result res
      = SocketQPACK_literal_literal_decode (encoded,
                                            (size_t)enc_len,
                                            name_buf,
                                            sizeof (name_buf),
                                            value_buf,
                                            sizeof (value_buf),
                                            &result,
                                            &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (1, result.never_indexed);
}

TEST (qpack_literal_literal_decode_huffman)
{
  unsigned char encoded[256];
  unsigned char name_buf[256];
  unsigned char value_buf[256];
  const char *name = "content-type";
  const char *value = "application/json";
  ssize_t enc_len;
  SocketQPACK_LiteralLiteral_T result;
  size_t consumed;

  /* Encode with Huffman */
  enc_len = SocketQPACK_literal_literal_encode ((const unsigned char *)name,
                                                strlen (name),
                                                (const unsigned char *)value,
                                                strlen (value),
                                                0,
                                                1,
                                                encoded,
                                                sizeof (encoded));
  ASSERT (enc_len > 0);

  /* Decode */
  SocketQPACK_Result res
      = SocketQPACK_literal_literal_decode (encoded,
                                            (size_t)enc_len,
                                            name_buf,
                                            sizeof (name_buf),
                                            value_buf,
                                            sizeof (value_buf),
                                            &result,
                                            &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (strlen (name), result.name_len);
  ASSERT_EQ (strlen (value), result.value_len);
  ASSERT (memcmp (result.name, name, result.name_len) == 0);
  ASSERT (memcmp (result.value, value, result.value_len) == 0);
}

TEST (qpack_literal_literal_decode_empty_value)
{
  unsigned char encoded[256];
  unsigned char name_buf[256];
  unsigned char value_buf[256];
  const char *name = "x-empty";
  ssize_t enc_len;
  SocketQPACK_LiteralLiteral_T result;
  size_t consumed;

  enc_len = SocketQPACK_literal_literal_encode ((const unsigned char *)name,
                                                strlen (name),
                                                (const unsigned char *)"",
                                                0,
                                                0,
                                                0,
                                                encoded,
                                                sizeof (encoded));
  ASSERT (enc_len > 0);

  SocketQPACK_Result res
      = SocketQPACK_literal_literal_decode (encoded,
                                            (size_t)enc_len,
                                            name_buf,
                                            sizeof (name_buf),
                                            value_buf,
                                            sizeof (value_buf),
                                            &result,
                                            &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (strlen (name), result.name_len);
  ASSERT_EQ (0, result.value_len);
}

TEST (qpack_literal_literal_decode_invalid_pattern)
{
  unsigned char data[]
      = { 0x00, 0x05, 'h', 'e', 'l', 'l', 'o', 0x05, 'w', 'o', 'r', 'l', 'd' };
  unsigned char name_buf[256];
  unsigned char value_buf[256];
  SocketQPACK_LiteralLiteral_T result;
  size_t consumed;

  /* First byte has pattern '000', not '001' */
  SocketQPACK_Result res
      = SocketQPACK_literal_literal_decode (data,
                                            sizeof (data),
                                            name_buf,
                                            sizeof (name_buf),
                                            value_buf,
                                            sizeof (value_buf),
                                            &result,
                                            &consumed);

  ASSERT_EQ (QPACK_ERROR_PATTERN, res);
}

TEST (qpack_literal_literal_decode_incomplete_name)
{
  unsigned char data[]
      = { 0x25, 'h', 'e' }; /* Pattern 001, length 5, only 2 bytes */
  unsigned char name_buf[256];
  unsigned char value_buf[256];
  SocketQPACK_LiteralLiteral_T result;
  size_t consumed;

  SocketQPACK_Result res
      = SocketQPACK_literal_literal_decode (data,
                                            sizeof (data),
                                            name_buf,
                                            sizeof (name_buf),
                                            value_buf,
                                            sizeof (value_buf),
                                            &result,
                                            &consumed);

  ASSERT_EQ (QPACK_INCOMPLETE, res);
}

TEST (qpack_literal_literal_decode_incomplete_value)
{
  unsigned char data[]
      = { 0x24, 't', 'e', 's', 't', 0x05, 'v' }; /* name OK, value truncated */
  unsigned char name_buf[256];
  unsigned char value_buf[256];
  SocketQPACK_LiteralLiteral_T result;
  size_t consumed;

  SocketQPACK_Result res
      = SocketQPACK_literal_literal_decode (data,
                                            sizeof (data),
                                            name_buf,
                                            sizeof (name_buf),
                                            value_buf,
                                            sizeof (value_buf),
                                            &result,
                                            &consumed);

  ASSERT_EQ (QPACK_INCOMPLETE, res);
}

TEST (qpack_literal_literal_decode_buffer_too_small)
{
  unsigned char encoded[256];
  unsigned char name_buf[2]; /* Too small */
  unsigned char value_buf[256];
  const char *name = "content-type";
  const char *value = "text/plain";
  ssize_t enc_len;
  SocketQPACK_LiteralLiteral_T result;
  size_t consumed;

  enc_len = SocketQPACK_literal_literal_encode ((const unsigned char *)name,
                                                strlen (name),
                                                (const unsigned char *)value,
                                                strlen (value),
                                                0,
                                                0,
                                                encoded,
                                                sizeof (encoded));
  ASSERT (enc_len > 0);

  SocketQPACK_Result res
      = SocketQPACK_literal_literal_decode (encoded,
                                            (size_t)enc_len,
                                            name_buf,
                                            sizeof (name_buf),
                                            value_buf,
                                            sizeof (value_buf),
                                            &result,
                                            &consumed);

  ASSERT_EQ (QPACK_ERROR_BUFFER, res);
}

TEST (qpack_literal_literal_decode_null_pointers)
{
  unsigned char encoded[]
      = { 0x24, 't', 'e', 's', 't', 0x05, 'v', 'a', 'l', 'u', 'e' };
  unsigned char name_buf[256];
  unsigned char value_buf[256];
  SocketQPACK_LiteralLiteral_T result;
  size_t consumed;

  ASSERT_EQ (QPACK_ERROR_NULL,
             SocketQPACK_literal_literal_decode (NULL,
                                                 sizeof (encoded),
                                                 name_buf,
                                                 sizeof (name_buf),
                                                 value_buf,
                                                 sizeof (value_buf),
                                                 &result,
                                                 &consumed));

  ASSERT_EQ (QPACK_ERROR_NULL,
             SocketQPACK_literal_literal_decode (encoded,
                                                 sizeof (encoded),
                                                 name_buf,
                                                 sizeof (name_buf),
                                                 value_buf,
                                                 sizeof (value_buf),
                                                 NULL,
                                                 &consumed));

  ASSERT_EQ (QPACK_ERROR_NULL,
             SocketQPACK_literal_literal_decode (encoded,
                                                 sizeof (encoded),
                                                 name_buf,
                                                 sizeof (name_buf),
                                                 value_buf,
                                                 sizeof (value_buf),
                                                 &result,
                                                 NULL));
}

/* ============================================================================
 * Round-Trip Tests
 * ============================================================================
 */

TEST (qpack_literal_literal_roundtrip_various_sizes)
{
  unsigned char encoded[4096];
  unsigned char name_buf[256];
  unsigned char value_buf[2048];
  SocketQPACK_LiteralLiteral_T result;
  size_t consumed;

  /* Test various name/value size combinations */
  struct
  {
    const char *name;
    const char *value;
  } test_cases[] = {
    { "a", "b" },
    { "content-type", "application/json" },
    { "x-custom-header-with-longer-name", "short" },
    { "short",
      "a much longer value that should test multi-byte length encoding" },
    { "cache-control", "no-cache, no-store, must-revalidate, max-age=0" },
    { "set-cookie",
      "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict" },
  };

  for (size_t i = 0; i < sizeof (test_cases) / sizeof (test_cases[0]); i++)
    {
      const char *name = test_cases[i].name;
      const char *value = test_cases[i].value;

      /* Test with plain encoding */
      ssize_t enc_len
          = SocketQPACK_literal_literal_encode ((const unsigned char *)name,
                                                strlen (name),
                                                (const unsigned char *)value,
                                                strlen (value),
                                                0,
                                                0,
                                                encoded,
                                                sizeof (encoded));
      ASSERT (enc_len > 0);

      SocketQPACK_Result res
          = SocketQPACK_literal_literal_decode (encoded,
                                                (size_t)enc_len,
                                                name_buf,
                                                sizeof (name_buf),
                                                value_buf,
                                                sizeof (value_buf),
                                                &result,
                                                &consumed);

      ASSERT_EQ (QPACK_OK, res);
      ASSERT_EQ ((size_t)enc_len, consumed);
      ASSERT_EQ (strlen (name), result.name_len);
      ASSERT_EQ (strlen (value), result.value_len);
      ASSERT (memcmp (result.name, name, result.name_len) == 0);
      ASSERT (memcmp (result.value, value, result.value_len) == 0);

      /* Test with Huffman encoding */
      enc_len
          = SocketQPACK_literal_literal_encode ((const unsigned char *)name,
                                                strlen (name),
                                                (const unsigned char *)value,
                                                strlen (value),
                                                0,
                                                1,
                                                encoded,
                                                sizeof (encoded));
      ASSERT (enc_len > 0);

      res = SocketQPACK_literal_literal_decode (encoded,
                                                (size_t)enc_len,
                                                name_buf,
                                                sizeof (name_buf),
                                                value_buf,
                                                sizeof (value_buf),
                                                &result,
                                                &consumed);

      ASSERT_EQ (QPACK_OK, res);
      ASSERT_EQ (strlen (name), result.name_len);
      ASSERT_EQ (strlen (value), result.value_len);
      ASSERT (memcmp (result.name, name, result.name_len) == 0);
      ASSERT (memcmp (result.value, value, result.value_len) == 0);
    }
}

TEST (qpack_literal_literal_roundtrip_sensitive)
{
  unsigned char encoded[256];
  unsigned char name_buf[256];
  unsigned char value_buf[256];
  SocketQPACK_LiteralLiteral_T result;
  size_t consumed;

  const char *sensitive_headers[] = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
  };

  for (size_t i = 0;
       i < sizeof (sensitive_headers) / sizeof (sensitive_headers[0]);
       i++)
    {
      const char *name = sensitive_headers[i];
      const char *value = "sensitive-value-that-should-not-be-indexed";

      ssize_t enc_len = SocketQPACK_literal_literal_encode (
          (const unsigned char *)name,
          strlen (name),
          (const unsigned char *)value,
          strlen (value),
          1,
          0,
          encoded,
          sizeof (encoded)); /* never_indexed = 1 */
      ASSERT (enc_len > 0);

      SocketQPACK_Result res
          = SocketQPACK_literal_literal_decode (encoded,
                                                (size_t)enc_len,
                                                name_buf,
                                                sizeof (name_buf),
                                                value_buf,
                                                sizeof (value_buf),
                                                &result,
                                                &consumed);

      ASSERT_EQ (QPACK_OK, res);
      ASSERT_EQ (1, result.never_indexed);
      ASSERT (memcmp (result.name, name, result.name_len) == 0);
      ASSERT (memcmp (result.value, value, result.value_len) == 0);
    }
}

TEST (qpack_literal_literal_roundtrip_binary_data)
{
  unsigned char encoded[256];
  unsigned char name_buf[256];
  unsigned char value_buf[256];
  SocketQPACK_LiteralLiteral_T result;
  size_t consumed;

  unsigned char name[] = { 'x', '-', 'b', 'i', 'n' };
  unsigned char value[] = { 0x00, 0x01, 0x02, 0xff, 0xfe, 0x80, 0x7f };

  ssize_t enc_len = SocketQPACK_literal_literal_encode (name,
                                                        sizeof (name),
                                                        value,
                                                        sizeof (value),
                                                        0,
                                                        0,
                                                        encoded,
                                                        sizeof (encoded));
  ASSERT (enc_len > 0);

  SocketQPACK_Result res
      = SocketQPACK_literal_literal_decode (encoded,
                                            (size_t)enc_len,
                                            name_buf,
                                            sizeof (name_buf),
                                            value_buf,
                                            sizeof (value_buf),
                                            &result,
                                            &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (sizeof (name), result.name_len);
  ASSERT_EQ (sizeof (value), result.value_len);
  ASSERT (memcmp (result.name, name, result.name_len) == 0);
  ASSERT (memcmp (result.value, value, result.value_len) == 0);
}

/* ============================================================================
 * Size Calculation Tests
 * ============================================================================
 */

TEST (qpack_literal_literal_size_basic)
{
  const char *name = "content-type";
  const char *value = "text/plain";

  size_t calc_size
      = SocketQPACK_literal_literal_size ((const unsigned char *)name,
                                          strlen (name),
                                          (const unsigned char *)value,
                                          strlen (value),
                                          0);
  ASSERT (calc_size > 0);

  /* Verify against actual encoding */
  unsigned char buf[256];
  ssize_t enc_len
      = SocketQPACK_literal_literal_encode ((const unsigned char *)name,
                                            strlen (name),
                                            (const unsigned char *)value,
                                            strlen (value),
                                            0,
                                            0,
                                            buf,
                                            sizeof (buf));

  ASSERT_EQ (calc_size, (size_t)enc_len);
}

TEST (qpack_literal_literal_size_huffman)
{
  const char *name = "content-type";
  const char *value = "application/json";

  size_t calc_size
      = SocketQPACK_literal_literal_size ((const unsigned char *)name,
                                          strlen (name),
                                          (const unsigned char *)value,
                                          strlen (value),
                                          1);
  ASSERT (calc_size > 0);

  unsigned char buf[256];
  ssize_t enc_len
      = SocketQPACK_literal_literal_encode ((const unsigned char *)name,
                                            strlen (name),
                                            (const unsigned char *)value,
                                            strlen (value),
                                            0,
                                            1,
                                            buf,
                                            sizeof (buf));

  ASSERT_EQ (calc_size, (size_t)enc_len);
}

TEST (qpack_literal_literal_size_empty_value)
{
  const char *name = "x-empty";

  size_t calc_size
      = SocketQPACK_literal_literal_size ((const unsigned char *)name,
                                          strlen (name),
                                          (const unsigned char *)"",
                                          0,
                                          0);
  ASSERT (calc_size > 0);

  unsigned char buf[256];
  ssize_t enc_len
      = SocketQPACK_literal_literal_encode ((const unsigned char *)name,
                                            strlen (name),
                                            (const unsigned char *)"",
                                            0,
                                            0,
                                            0,
                                            buf,
                                            sizeof (buf));

  ASSERT_EQ (calc_size, (size_t)enc_len);
}

/* ============================================================================
 * Integer Primitive Tests (from Section 4.1)
 * ============================================================================
 */

TEST (qpack_int_encode_small_value)
{
  unsigned char buf[16];
  ssize_t len;

  /* Value 10 with 5-bit prefix should fit in single byte */
  len = SocketQPACK_int_encode (10, 5, buf, sizeof (buf));
  ASSERT_EQ (1, len);
  ASSERT_EQ (10, buf[0] & 0x1f);
}

TEST (qpack_int_encode_multi_byte)
{
  unsigned char buf[16];
  ssize_t len;

  /* Value 1337 with 5-bit prefix needs continuation bytes */
  len = SocketQPACK_int_encode (1337, 5, buf, sizeof (buf));
  ASSERT (len >= 2);
  ASSERT_EQ (0x1f, buf[0] & 0x1f);
}

TEST (qpack_int_decode_roundtrip)
{
  unsigned char buf[16];
  uint64_t value;
  size_t consumed;
  ssize_t len;

  for (int prefix = 3; prefix <= 8; prefix++)
    {
      len = SocketQPACK_int_encode (1337, prefix, buf, sizeof (buf));
      ASSERT (len > 0);

      SocketQPACK_Result res = SocketQPACK_int_decode (
          buf, (size_t)len, prefix, &value, &consumed);
      ASSERT_EQ (QPACK_OK, res);
      ASSERT_EQ (1337, value);
      ASSERT_EQ ((size_t)len, consumed);
    }
}

/* ============================================================================
 * String Primitive Tests (from Section 4.1)
 * ============================================================================
 */

TEST (qpack_string_encode_plain)
{
  unsigned char buf[256];
  const char *str = "hello";
  ssize_t len;

  len = SocketQPACK_string_encode (
      (const unsigned char *)str, strlen (str), 0, 7, buf, sizeof (buf));
  ASSERT (len > 0);
  ASSERT_EQ (0, buf[0] & 0x80); /* Huffman flag off */
}

TEST (qpack_string_decode_roundtrip)
{
  unsigned char encoded[256];
  unsigned char decoded[256];
  const char *str = "www.example.org";
  ssize_t enc_len;
  size_t decoded_len, consumed;

  enc_len = SocketQPACK_string_encode ((const unsigned char *)str,
                                       strlen (str),
                                       1,
                                       7,
                                       encoded,
                                       sizeof (encoded));
  ASSERT (enc_len > 0);

  SocketQPACK_Result res = SocketQPACK_string_decode (encoded,
                                                      (size_t)enc_len,
                                                      7,
                                                      decoded,
                                                      sizeof (decoded),
                                                      &decoded_len,
                                                      &consumed);

  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (strlen (str), decoded_len);
  ASSERT (memcmp (decoded, str, decoded_len) == 0);
}

/* ============================================================================
 * Result String Tests
 * ============================================================================
 */

TEST (qpack_result_string)
{
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_OK));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERROR));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_INCOMPLETE));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERROR_PATTERN));

  /* Invalid result code should return something */
  ASSERT_NOT_NULL (SocketQPACK_result_string ((SocketQPACK_Result)999));
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
