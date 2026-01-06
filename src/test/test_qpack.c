/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_qpack.c - Tests for QPACK Primitives (RFC 9204 Section 4.1)
 *
 * Tests integer encoding/decoding with various prefix sizes and
 * string literal encoding/decoding with optional Huffman compression.
 */

#include <string.h>

#include "quic/SocketQPACK.h"
#include "test/Test.h"

/* ============================================================================
 * Integer Encoding Tests
 * ============================================================================
 */

TEST (qpack_int_encode_small_value_prefix5)
{
  unsigned char buf[16];
  ssize_t len;

  /* Value 10 with 5-bit prefix should fit in single byte */
  len = SocketQPACK_int_encode (10, 5, buf, sizeof (buf));
  ASSERT_EQ (1, len);
  ASSERT_EQ (10, buf[0] & 0x1f); /* Only check prefix bits */
}

TEST (qpack_int_encode_small_value_prefix6)
{
  unsigned char buf[16];
  ssize_t len;

  /* Value 30 with 6-bit prefix should fit in single byte */
  len = SocketQPACK_int_encode (30, 6, buf, sizeof (buf));
  ASSERT_EQ (1, len);
  ASSERT_EQ (30, buf[0] & 0x3f);
}

TEST (qpack_int_encode_small_value_prefix7)
{
  unsigned char buf[16];
  ssize_t len;

  /* Value 100 with 7-bit prefix should fit in single byte */
  len = SocketQPACK_int_encode (100, 7, buf, sizeof (buf));
  ASSERT_EQ (1, len);
  ASSERT_EQ (100, buf[0] & 0x7f);
}

TEST (qpack_int_encode_small_value_prefix8)
{
  unsigned char buf[16];
  ssize_t len;

  /* Value 200 with 8-bit prefix should fit in single byte */
  len = SocketQPACK_int_encode (200, 8, buf, sizeof (buf));
  ASSERT_EQ (1, len);
  ASSERT_EQ (200, buf[0]);
}

TEST (qpack_int_encode_value_exceeds_prefix5)
{
  unsigned char buf[16];
  ssize_t len;

  /* Value 1337 with 5-bit prefix (max prefix = 31) needs continuation */
  len = SocketQPACK_int_encode (1337, 5, buf, sizeof (buf));
  ASSERT (len >= 2);
  ASSERT_EQ (0x1f, buf[0] & 0x1f); /* Prefix maxed out */
  ASSERT (buf[1] & 0x80);          /* Continuation bit set */
}

TEST (qpack_int_encode_value_exceeds_prefix3)
{
  unsigned char buf[16];
  ssize_t len;

  /* Value 10 with 3-bit prefix (max prefix = 7) needs continuation */
  len = SocketQPACK_int_encode (10, 3, buf, sizeof (buf));
  ASSERT_EQ (2, len);
  ASSERT_EQ (0x07, buf[0] & 0x07); /* Prefix maxed out (7) */
  ASSERT_EQ (0x03, buf[1]);        /* 10 - 7 = 3, no continuation */
}

TEST (qpack_int_encode_max_62bit)
{
  unsigned char buf[16];
  ssize_t len;

  /* Maximum 62-bit value */
  uint64_t max_val = SOCKETQPACK_INT_MAX;
  len = SocketQPACK_int_encode (max_val, 8, buf, sizeof (buf));
  ASSERT (len > 0);
  ASSERT (len <= 10); /* Should fit in at most 10 bytes */
}

TEST (qpack_int_encode_zero)
{
  unsigned char buf[16];
  ssize_t len;

  /* Zero should always encode in 1 byte */
  for (int prefix = 3; prefix <= 8; prefix++)
    {
      len = SocketQPACK_int_encode (0, prefix, buf, sizeof (buf));
      ASSERT_EQ (1, len);
      ASSERT_EQ (0, buf[0] & ((1 << prefix) - 1));
    }
}

TEST (qpack_int_encode_invalid_prefix)
{
  unsigned char buf[16];
  ssize_t len;

  /* Prefix too small */
  len = SocketQPACK_int_encode (10, 2, buf, sizeof (buf));
  ASSERT_EQ (-1, len);

  /* Prefix too large */
  len = SocketQPACK_int_encode (10, 9, buf, sizeof (buf));
  ASSERT_EQ (-1, len);
}

TEST (qpack_int_encode_buffer_too_small)
{
  unsigned char buf[1];
  ssize_t len;

  /* Large value needs more than 1 byte */
  len = SocketQPACK_int_encode (1000000, 5, buf, sizeof (buf));
  ASSERT_EQ (-1, len);
}

TEST (qpack_int_encode_null_buffer)
{
  ssize_t len = SocketQPACK_int_encode (10, 5, NULL, 16);
  ASSERT_EQ (-1, len);
}

/* ============================================================================
 * Integer Decoding Tests
 * ============================================================================
 */

TEST (qpack_int_decode_small_value)
{
  unsigned char data[] = { 10 };
  uint64_t value;
  size_t consumed;
  SocketQPACK_Result res;

  res = SocketQPACK_int_decode (data, sizeof (data), 5, &value, &consumed);
  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (10, value);
  ASSERT_EQ (1, consumed);
}

TEST (qpack_int_decode_multi_byte)
{
  /* Encode 1337 with 5-bit prefix, then decode */
  unsigned char buf[16];
  ssize_t len = SocketQPACK_int_encode (1337, 5, buf, sizeof (buf));
  ASSERT (len > 0);

  uint64_t value;
  size_t consumed;
  SocketQPACK_Result res;

  res = SocketQPACK_int_decode (buf, (size_t)len, 5, &value, &consumed);
  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (1337, value);
  ASSERT_EQ ((size_t)len, consumed);
}

TEST (qpack_int_decode_roundtrip_all_prefixes)
{
  unsigned char buf[16];
  uint64_t test_values[] = { 0,
                             1,
                             10,
                             31,
                             63,
                             100,
                             127,
                             255,
                             1337,
                             16383,
                             65535,
                             1000000,
                             4611686018427387903ULL };

  for (int prefix = 3; prefix <= 8; prefix++)
    {
      for (size_t i = 0; i < sizeof (test_values) / sizeof (test_values[0]);
           i++)
        {
          uint64_t orig = test_values[i];
          ssize_t len
              = SocketQPACK_int_encode (orig, prefix, buf, sizeof (buf));
          ASSERT (len > 0);

          uint64_t decoded;
          size_t consumed;
          SocketQPACK_Result res;

          res = SocketQPACK_int_decode (
              buf, (size_t)len, prefix, &decoded, &consumed);
          ASSERT_EQ (QPACK_OK, res);
          ASSERT_EQ (orig, decoded);
          ASSERT_EQ ((size_t)len, consumed);
        }
    }
}

TEST (qpack_int_decode_incomplete)
{
  /* Multi-byte encoding truncated */
  unsigned char data[] = { 0x1f, 0x9a }; /* Missing final byte */
  uint64_t value;
  size_t consumed;

  /* Set continuation bit on second byte to simulate incomplete */
  data[1] |= 0x80;

  SocketQPACK_Result res
      = SocketQPACK_int_decode (data, sizeof (data), 5, &value, &consumed);
  ASSERT_EQ (QPACK_INCOMPLETE, res);
}

TEST (qpack_int_decode_empty_input)
{
  uint64_t value;
  size_t consumed;

  SocketQPACK_Result res
      = SocketQPACK_int_decode (NULL, 0, 5, &value, &consumed);
  ASSERT_NE (QPACK_OK, res);
}

TEST (qpack_int_decode_invalid_prefix)
{
  unsigned char data[] = { 10 };
  uint64_t value;
  size_t consumed;

  SocketQPACK_Result res
      = SocketQPACK_int_decode (data, sizeof (data), 2, &value, &consumed);
  ASSERT_EQ (QPACK_ERROR_PREFIX, res);

  res = SocketQPACK_int_decode (data, sizeof (data), 9, &value, &consumed);
  ASSERT_EQ (QPACK_ERROR_PREFIX, res);
}

TEST (qpack_int_decode_null_pointers)
{
  unsigned char data[] = { 10 };
  uint64_t value;
  size_t consumed;

  ASSERT_EQ (QPACK_ERROR_NULL,
             SocketQPACK_int_decode (NULL, 1, 5, &value, &consumed));
  ASSERT_EQ (QPACK_ERROR_NULL,
             SocketQPACK_int_decode (data, 1, 5, NULL, &consumed));
  ASSERT_EQ (QPACK_ERROR_NULL,
             SocketQPACK_int_decode (data, 1, 5, &value, NULL));
}

/* ============================================================================
 * Integer Size Calculation Tests
 * ============================================================================
 */

TEST (qpack_int_size_small_values)
{
  /* Values that fit in prefix should return 1 */
  ASSERT_EQ (1, SocketQPACK_int_size (10, 5));  /* 10 < 31 */
  ASSERT_EQ (1, SocketQPACK_int_size (30, 5));  /* 30 < 31 */
  ASSERT_EQ (1, SocketQPACK_int_size (63, 7));  /* 63 < 127 */
  ASSERT_EQ (1, SocketQPACK_int_size (254, 8)); /* 254 < 255 */
}

TEST (qpack_int_size_large_values)
{
  /* Values exceeding prefix need continuation bytes */
  size_t size = SocketQPACK_int_size (1337, 5);
  ASSERT (size > 1);

  /* Verify size matches actual encoding */
  unsigned char buf[16];
  ssize_t len = SocketQPACK_int_encode (1337, 5, buf, sizeof (buf));
  ASSERT_EQ ((size_t)len, size);
}

TEST (qpack_int_size_max_value)
{
  size_t size = SocketQPACK_int_size (SOCKETQPACK_INT_MAX, 8);
  ASSERT (size > 0);
  ASSERT (size <= 10);
}

TEST (qpack_int_size_invalid_prefix)
{
  ASSERT_EQ (0, SocketQPACK_int_size (10, 2));
  ASSERT_EQ (0, SocketQPACK_int_size (10, 9));
}

/* ============================================================================
 * String Encoding Tests
 * ============================================================================
 */

TEST (qpack_string_encode_plain)
{
  unsigned char buf[256];
  const char *str = "hello";
  size_t str_len = strlen (str);

  ssize_t len = SocketQPACK_string_encode (
      (const unsigned char *)str, str_len, 0, 7, buf, sizeof (buf));
  ASSERT (len > 0);

  /* First byte should have Huffman bit clear and length in lower 7 bits */
  ASSERT_EQ (0, buf[0] & 0x80); /* Huffman flag off */
  ASSERT_EQ (5, buf[0] & 0x7f); /* Length = 5 */

  /* Remaining bytes should be the string itself */
  ASSERT (memcmp (buf + 1, str, str_len) == 0);
}

TEST (qpack_string_encode_huffman)
{
  unsigned char buf[256];
  const char *str = "www.example.org";
  size_t str_len = strlen (str);

  ssize_t len = SocketQPACK_string_encode (
      (const unsigned char *)str, str_len, 1, 7, buf, sizeof (buf));
  ASSERT (len > 0);

  /* If Huffman helps, the flag should be set */
  /* Note: may or may not use Huffman depending on compression ratio */
}

TEST (qpack_string_encode_empty)
{
  unsigned char buf[16];

  ssize_t len = SocketQPACK_string_encode (NULL, 0, 0, 7, buf, sizeof (buf));
  ASSERT_EQ (1, len);
  ASSERT_EQ (0, buf[0] & 0x7f); /* Length = 0 */
}

TEST (qpack_string_encode_prefix3)
{
  unsigned char buf[256];
  const char *str = "test";
  size_t str_len = strlen (str);

  ssize_t len = SocketQPACK_string_encode (
      (const unsigned char *)str, str_len, 0, 3, buf, sizeof (buf));
  ASSERT (len > 0);

  /* With 3-bit prefix, length 4 should fit but Huffman flag at bit 3 */
  ASSERT_EQ (4, buf[0] & 0x07); /* Length in lower 3 bits */
}

TEST (qpack_string_encode_large)
{
  unsigned char buf[8192];
  unsigned char input[4096];
  memset (input, 'a', sizeof (input));

  ssize_t len = SocketQPACK_string_encode (
      input, sizeof (input), 0, 7, buf, sizeof (buf));
  ASSERT (len > 0);
}

TEST (qpack_string_encode_invalid_prefix)
{
  unsigned char buf[16];
  const char *str = "test";

  ASSERT_EQ (-1,
             SocketQPACK_string_encode (
                 (const unsigned char *)str, 4, 0, 2, buf, sizeof (buf)));
  ASSERT_EQ (-1,
             SocketQPACK_string_encode (
                 (const unsigned char *)str, 4, 0, 9, buf, sizeof (buf)));
}

TEST (qpack_string_encode_buffer_too_small)
{
  unsigned char buf[2];
  const char *str = "hello world";

  ssize_t len = SocketQPACK_string_encode (
      (const unsigned char *)str, strlen (str), 0, 7, buf, sizeof (buf));
  ASSERT_EQ (-1, len);
}

/* ============================================================================
 * String Decoding Tests
 * ============================================================================
 */

TEST (qpack_string_decode_plain)
{
  /* Encode then decode */
  unsigned char encoded[256];
  unsigned char decoded[256];
  const char *str = "hello";
  size_t str_len = strlen (str);

  ssize_t enc_len = SocketQPACK_string_encode (
      (const unsigned char *)str, str_len, 0, 7, encoded, sizeof (encoded));
  ASSERT (enc_len > 0);

  size_t decoded_len, consumed;
  SocketQPACK_Result res = SocketQPACK_string_decode (encoded,
                                                      (size_t)enc_len,
                                                      7,
                                                      decoded,
                                                      sizeof (decoded),
                                                      &decoded_len,
                                                      &consumed);
  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (str_len, decoded_len);
  ASSERT_EQ ((size_t)enc_len, consumed);
  ASSERT (memcmp (decoded, str, str_len) == 0);
}

TEST (qpack_string_decode_huffman_roundtrip)
{
  unsigned char encoded[256];
  unsigned char decoded[256];
  const char *str = "www.example.org";
  size_t str_len = strlen (str);

  ssize_t enc_len = SocketQPACK_string_encode (
      (const unsigned char *)str, str_len, 1, 7, encoded, sizeof (encoded));
  ASSERT (enc_len > 0);

  size_t decoded_len, consumed;
  SocketQPACK_Result res = SocketQPACK_string_decode (encoded,
                                                      (size_t)enc_len,
                                                      7,
                                                      decoded,
                                                      sizeof (decoded),
                                                      &decoded_len,
                                                      &consumed);
  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (str_len, decoded_len);
  ASSERT (memcmp (decoded, str, str_len) == 0);
}

TEST (qpack_string_decode_empty)
{
  unsigned char encoded[16];
  unsigned char decoded[16];

  ssize_t enc_len
      = SocketQPACK_string_encode (NULL, 0, 0, 7, encoded, sizeof (encoded));
  ASSERT (enc_len > 0);

  size_t decoded_len, consumed;
  SocketQPACK_Result res = SocketQPACK_string_decode (encoded,
                                                      (size_t)enc_len,
                                                      7,
                                                      decoded,
                                                      sizeof (decoded),
                                                      &decoded_len,
                                                      &consumed);
  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (0, decoded_len);
}

TEST (qpack_string_decode_all_prefixes)
{
  for (int prefix = 3; prefix <= 8; prefix++)
    {
      unsigned char encoded[256];
      unsigned char decoded[256];
      const char *str = "test string";
      size_t str_len = strlen (str);

      ssize_t enc_len = SocketQPACK_string_encode ((const unsigned char *)str,
                                                   str_len,
                                                   0,
                                                   prefix,
                                                   encoded,
                                                   sizeof (encoded));
      ASSERT (enc_len > 0);

      size_t decoded_len, consumed;
      SocketQPACK_Result res = SocketQPACK_string_decode (encoded,
                                                          (size_t)enc_len,
                                                          prefix,
                                                          decoded,
                                                          sizeof (decoded),
                                                          &decoded_len,
                                                          &consumed);
      ASSERT_EQ (QPACK_OK, res);
      ASSERT_EQ (str_len, decoded_len);
      ASSERT (memcmp (decoded, str, str_len) == 0);
    }
}

TEST (qpack_string_decode_incomplete)
{
  unsigned char data[] = { 0x05 }; /* Length 5, but no data */
  unsigned char decoded[256];
  size_t decoded_len, consumed;

  SocketQPACK_Result res = SocketQPACK_string_decode (data,
                                                      sizeof (data),
                                                      7,
                                                      decoded,
                                                      sizeof (decoded),
                                                      &decoded_len,
                                                      &consumed);
  ASSERT_EQ (QPACK_INCOMPLETE, res);
}

TEST (qpack_string_decode_buffer_too_small)
{
  unsigned char encoded[256];
  unsigned char decoded[2];
  const char *str = "hello world this is a long string";

  ssize_t enc_len = SocketQPACK_string_encode ((const unsigned char *)str,
                                               strlen (str),
                                               0,
                                               7,
                                               encoded,
                                               sizeof (encoded));
  ASSERT (enc_len > 0);

  size_t decoded_len, consumed;
  SocketQPACK_Result res = SocketQPACK_string_decode (encoded,
                                                      (size_t)enc_len,
                                                      7,
                                                      decoded,
                                                      sizeof (decoded),
                                                      &decoded_len,
                                                      &consumed);
  ASSERT_EQ (QPACK_ERROR_BUFFER, res);
}

TEST (qpack_string_decode_invalid_prefix)
{
  unsigned char data[] = { 0x05, 'h', 'e', 'l', 'l', 'o' };
  unsigned char decoded[256];
  size_t decoded_len, consumed;

  ASSERT_EQ (QPACK_ERROR_PREFIX,
             SocketQPACK_string_decode (data,
                                        sizeof (data),
                                        2,
                                        decoded,
                                        sizeof (decoded),
                                        &decoded_len,
                                        &consumed));
}

TEST (qpack_string_decode_null_pointers)
{
  unsigned char data[] = { 0x05, 'h', 'e', 'l', 'l', 'o' };
  unsigned char decoded[256];
  size_t decoded_len, consumed;

  ASSERT_EQ (
      QPACK_ERROR_NULL,
      SocketQPACK_string_decode (
          NULL, 6, 7, decoded, sizeof (decoded), &decoded_len, &consumed));
  ASSERT_EQ (QPACK_ERROR_NULL,
             SocketQPACK_string_decode (
                 data, 6, 7, decoded, sizeof (decoded), NULL, &consumed));
  ASSERT_EQ (QPACK_ERROR_NULL,
             SocketQPACK_string_decode (
                 data, 6, 7, decoded, sizeof (decoded), &decoded_len, NULL));
}

/* ============================================================================
 * String Size Calculation Tests
 * ============================================================================
 */

TEST (qpack_string_size_plain)
{
  const char *str = "hello";
  size_t str_len = strlen (str);

  size_t size
      = SocketQPACK_string_size ((const unsigned char *)str, str_len, 0, 7);
  ASSERT (size > 0);

  /* Verify against actual encoding */
  unsigned char buf[256];
  ssize_t enc_len = SocketQPACK_string_encode (
      (const unsigned char *)str, str_len, 0, 7, buf, sizeof (buf));
  ASSERT_EQ (size, (size_t)enc_len);
}

TEST (qpack_string_size_huffman)
{
  const char *str = "www.example.org";
  size_t str_len = strlen (str);

  size_t size
      = SocketQPACK_string_size ((const unsigned char *)str, str_len, 1, 7);
  ASSERT (size > 0);

  unsigned char buf[256];
  ssize_t enc_len = SocketQPACK_string_encode (
      (const unsigned char *)str, str_len, 1, 7, buf, sizeof (buf));
  ASSERT_EQ (size, (size_t)enc_len);
}

TEST (qpack_string_size_empty)
{
  size_t size = SocketQPACK_string_size (NULL, 0, 0, 7);
  ASSERT_EQ (1, size); /* Just the length byte */
}

TEST (qpack_string_size_invalid_prefix)
{
  ASSERT_EQ (0,
             SocketQPACK_string_size ((const unsigned char *)"test", 4, 0, 2));
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
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERROR_INTEGER));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERROR_HUFFMAN));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERROR_BUFFER));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERROR_PREFIX));
  ASSERT_NOT_NULL (SocketQPACK_result_string (QPACK_ERROR_NULL));

  /* Invalid result code should return something */
  ASSERT_NOT_NULL (SocketQPACK_result_string ((SocketQPACK_Result)999));
}

/* ============================================================================
 * Edge Case Tests
 * ============================================================================
 */

TEST (qpack_int_boundary_values)
{
  unsigned char buf[16];
  uint64_t value;
  size_t consumed;
  ssize_t len;

  /* Test boundary values for each prefix size */
  for (int prefix = 3; prefix <= 8; prefix++)
    {
      uint64_t max_prefix = ((uint64_t)1 << prefix) - 1;

      /* Value exactly at prefix maximum - 1 (fits in prefix) */
      len = SocketQPACK_int_encode (max_prefix - 1, prefix, buf, sizeof (buf));
      ASSERT_EQ (1, len);
      ASSERT_EQ (
          QPACK_OK,
          SocketQPACK_int_decode (buf, (size_t)len, prefix, &value, &consumed));
      ASSERT_EQ (max_prefix - 1, value);

      /* Value exactly at prefix maximum (triggers continuation) */
      len = SocketQPACK_int_encode (max_prefix, prefix, buf, sizeof (buf));
      ASSERT (len >= 2);
      ASSERT_EQ (
          QPACK_OK,
          SocketQPACK_int_decode (buf, (size_t)len, prefix, &value, &consumed));
      ASSERT_EQ (max_prefix, value);

      /* Value at prefix maximum + 1 */
      len = SocketQPACK_int_encode (max_prefix + 1, prefix, buf, sizeof (buf));
      ASSERT (len >= 2);
      ASSERT_EQ (
          QPACK_OK,
          SocketQPACK_int_decode (buf, (size_t)len, prefix, &value, &consumed));
      ASSERT_EQ (max_prefix + 1, value);
    }
}

TEST (qpack_string_binary_data)
{
  unsigned char encoded[256];
  unsigned char decoded[256];
  unsigned char binary_data[] = { 0x00, 0x01, 0x02, 0xff, 0xfe, 0x80, 0x7f };

  ssize_t enc_len = SocketQPACK_string_encode (
      binary_data, sizeof (binary_data), 0, 7, encoded, sizeof (encoded));
  ASSERT (enc_len > 0);

  size_t decoded_len, consumed;
  SocketQPACK_Result res = SocketQPACK_string_decode (encoded,
                                                      (size_t)enc_len,
                                                      7,
                                                      decoded,
                                                      sizeof (decoded),
                                                      &decoded_len,
                                                      &consumed);
  ASSERT_EQ (QPACK_OK, res);
  ASSERT_EQ (sizeof (binary_data), decoded_len);
  ASSERT (memcmp (decoded, binary_data, sizeof (binary_data)) == 0);
}

TEST (qpack_int_encode_values_0_to_100)
{
  unsigned char buf[16];

  for (int prefix = 3; prefix <= 8; prefix++)
    {
      for (uint64_t i = 0; i <= 100; i++)
        {
          ssize_t len = SocketQPACK_int_encode (i, prefix, buf, sizeof (buf));
          ASSERT (len > 0);

          uint64_t decoded;
          size_t consumed;
          SocketQPACK_Result res = SocketQPACK_int_decode (
              buf, (size_t)len, prefix, &decoded, &consumed);
          ASSERT_EQ (QPACK_OK, res);
          ASSERT_EQ (i, decoded);
        }
    }
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
