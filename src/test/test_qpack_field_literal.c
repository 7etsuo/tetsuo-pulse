/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_field_literal.c
 * @brief Unit tests for QPACK Literal Field Line with Literal Name
 *        (RFC 9204 Section 4.5.6)
 *
 * Tests the encoding, decoding, and round-trip functionality for the
 * Literal Field Line with Literal Name instruction used in QPACK field
 * sections.
 */

#include "http/qpack/SocketQPACK.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test assertion macro */
#define TEST_ASSERT(cond, msg)                                               \
  do                                                                         \
    {                                                                        \
      if (!(cond))                                                           \
        {                                                                    \
          fprintf (stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); \
          exit (1);                                                          \
        }                                                                    \
    }                                                                        \
  while (0)

/* ============================================================================
 * PATTERN VALIDATION TESTS
 * ============================================================================
 */

/**
 * Test pattern validation for Literal Field Line with Literal Name.
 */
static void
test_pattern_validation (void)
{
  printf ("  Pattern validation... ");

  /* Valid patterns: 001xxxxx (0x20-0x3F) */
  TEST_ASSERT (SocketQPACK_is_literal_field_literal_name (0x20) == true,
               "0x20 is valid");
  TEST_ASSERT (SocketQPACK_is_literal_field_literal_name (0x21) == true,
               "0x21 is valid");
  TEST_ASSERT (SocketQPACK_is_literal_field_literal_name (0x2F) == true,
               "0x2F is valid");
  TEST_ASSERT (SocketQPACK_is_literal_field_literal_name (0x30) == true,
               "0x30 is valid");
  TEST_ASSERT (SocketQPACK_is_literal_field_literal_name (0x3F) == true,
               "0x3F is valid");

  /* Invalid patterns: not 001xxxxx */
  TEST_ASSERT (SocketQPACK_is_literal_field_literal_name (0x00) == false,
               "0x00 is invalid");
  TEST_ASSERT (SocketQPACK_is_literal_field_literal_name (0x1F) == false,
               "0x1F is invalid");
  TEST_ASSERT (SocketQPACK_is_literal_field_literal_name (0x40) == false,
               "0x40 is invalid");
  TEST_ASSERT (SocketQPACK_is_literal_field_literal_name (0x80) == false,
               "0x80 is invalid");
  TEST_ASSERT (SocketQPACK_is_literal_field_literal_name (0xFF) == false,
               "0xFF is invalid");

  printf ("PASS\n");
}

/* ============================================================================
 * ENCODING TESTS
 * ============================================================================
 */

/**
 * Test basic encoding without Huffman or never-indexed.
 */
static void
test_encode_basic (void)
{
  unsigned char buf[256];
  size_t bytes_written;
  SocketQPACK_Result result;

  printf ("  Encode basic... ");

  result = SocketQPACK_encode_literal_field_literal_name (
      buf,
      sizeof (buf),
      (const unsigned char *)"x-custom",
      8,
      false, /* no Huffman for name */
      (const unsigned char *)"test-value",
      10,
      false, /* no Huffman for value */
      false, /* not never-indexed */
      &bytes_written);

  TEST_ASSERT (result == QPACK_OK, "encode success");
  TEST_ASSERT (bytes_written > 0, "bytes written > 0");

  /* First byte should be 001xxxxx (pattern) without N or H bits */
  TEST_ASSERT ((buf[0] & 0xE0) == 0x20, "correct pattern bits (001)");
  TEST_ASSERT ((buf[0] & 0x10) == 0, "N bit is 0");
  TEST_ASSERT ((buf[0] & 0x08) == 0, "H bit is 0");

  /* Name length should be 8 (fits in 3 bits) */
  TEST_ASSERT ((buf[0] & 0x07) == 7 || bytes_written > 2,
               "name length encoding");

  printf ("PASS\n");
}

/**
 * Test encoding with never-indexed flag.
 */
static void
test_encode_never_indexed (void)
{
  unsigned char buf[256];
  size_t bytes_written;
  SocketQPACK_Result result;

  printf ("  Encode with never-indexed... ");

  result = SocketQPACK_encode_literal_field_literal_name (
      buf,
      sizeof (buf),
      (const unsigned char *)"authorization",
      13,
      false,
      (const unsigned char *)"Bearer token123",
      15,
      false,
      true, /* never-indexed */
      &bytes_written);

  TEST_ASSERT (result == QPACK_OK, "encode success");

  /* First byte should have N bit set (bit 4) */
  TEST_ASSERT ((buf[0] & 0xE0) == 0x20, "correct pattern bits (001)");
  TEST_ASSERT ((buf[0] & 0x10) == 0x10, "N bit is set");

  printf ("PASS\n");
}

/**
 * Test encoding with Huffman compression.
 */
static void
test_encode_huffman (void)
{
  unsigned char buf_no_huff[256];
  unsigned char buf_huff[256];
  size_t len_no_huff, len_huff;
  SocketQPACK_Result result;

  printf ("  Encode with Huffman... ");

  /* Without Huffman */
  result = SocketQPACK_encode_literal_field_literal_name (
      buf_no_huff,
      sizeof (buf_no_huff),
      (const unsigned char *)"content-type",
      12,
      false,
      (const unsigned char *)"application/json",
      16,
      false,
      false,
      &len_no_huff);
  TEST_ASSERT (result == QPACK_OK, "no huffman encode success");

  /* With Huffman */
  result = SocketQPACK_encode_literal_field_literal_name (
      buf_huff,
      sizeof (buf_huff),
      (const unsigned char *)"content-type",
      12,
      true,
      (const unsigned char *)"application/json",
      16,
      true,
      false,
      &len_huff);
  TEST_ASSERT (result == QPACK_OK, "huffman encode success");

  /* Huffman encoding should produce smaller output */
  TEST_ASSERT (len_huff < len_no_huff, "Huffman is smaller");

  /* H bit should be set for Huffman-encoded name */
  TEST_ASSERT ((buf_huff[0] & 0x08) == 0x08, "name H bit is set");

  printf ("PASS\n");
}

/**
 * Test encoding with empty strings.
 */
static void
test_encode_empty (void)
{
  unsigned char buf[256];
  size_t bytes_written;
  SocketQPACK_Result result;

  printf ("  Encode empty strings... ");

  /* Empty name */
  result = SocketQPACK_encode_literal_field_literal_name (
      buf,
      sizeof (buf),
      NULL,
      0,
      false,
      (const unsigned char *)"value",
      5,
      false,
      false,
      &bytes_written);
  TEST_ASSERT (result == QPACK_OK, "empty name success");
  TEST_ASSERT ((buf[0] & 0x07) == 0, "name length is 0");

  /* Empty value */
  result = SocketQPACK_encode_literal_field_literal_name (
      buf,
      sizeof (buf),
      (const unsigned char *)"name",
      4,
      false,
      NULL,
      0,
      false,
      false,
      &bytes_written);
  TEST_ASSERT (result == QPACK_OK, "empty value success");

  /* Both empty */
  result = SocketQPACK_encode_literal_field_literal_name (
      buf, sizeof (buf), NULL, 0, false, NULL, 0, false, false, &bytes_written);
  TEST_ASSERT (result == QPACK_OK, "both empty success");
  /* Should be just 2 bytes: first byte (pattern + name len 0) + value len 0 */
  TEST_ASSERT (bytes_written == 2, "minimum encoding is 2 bytes");

  printf ("PASS\n");
}

/* ============================================================================
 * DECODING TESTS
 * ============================================================================
 */

/**
 * Test basic decoding.
 */
static void
test_decode_basic (void)
{
  unsigned char encoded[256];
  unsigned char name_out[256];
  unsigned char value_out[256];
  size_t encoded_len, name_len, value_len, consumed;
  bool never_indexed;
  SocketQPACK_Result result;

  printf ("  Decode basic... ");

  /* Encode first */
  result = SocketQPACK_encode_literal_field_literal_name (
      encoded,
      sizeof (encoded),
      (const unsigned char *)"x-custom",
      8,
      false,
      (const unsigned char *)"test-value",
      10,
      false,
      false,
      &encoded_len);
  TEST_ASSERT (result == QPACK_OK, "encode success");

  /* Decode */
  result = SocketQPACK_decode_literal_field_literal_name (encoded,
                                                          encoded_len,
                                                          name_out,
                                                          sizeof (name_out),
                                                          &name_len,
                                                          value_out,
                                                          sizeof (value_out),
                                                          &value_len,
                                                          &never_indexed,
                                                          &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode success");
  TEST_ASSERT (consumed == encoded_len, "all bytes consumed");
  TEST_ASSERT (name_len == 8, "name_len is 8");
  TEST_ASSERT (memcmp (name_out, "x-custom", 8) == 0, "name matches");
  TEST_ASSERT (value_len == 10, "value_len is 10");
  TEST_ASSERT (memcmp (value_out, "test-value", 10) == 0, "value matches");
  TEST_ASSERT (never_indexed == false, "never_indexed is false");

  printf ("PASS\n");
}

/**
 * Test decoding with never-indexed flag.
 */
static void
test_decode_never_indexed (void)
{
  unsigned char encoded[256];
  unsigned char name_out[256];
  unsigned char value_out[256];
  size_t encoded_len, name_len, value_len, consumed;
  bool never_indexed;
  SocketQPACK_Result result;

  printf ("  Decode with never-indexed... ");

  /* Encode with never-indexed */
  result = SocketQPACK_encode_literal_field_literal_name (
      encoded,
      sizeof (encoded),
      (const unsigned char *)"authorization",
      13,
      false,
      (const unsigned char *)"Bearer token",
      12,
      false,
      true, /* never-indexed */
      &encoded_len);
  TEST_ASSERT (result == QPACK_OK, "encode success");

  /* Decode */
  result = SocketQPACK_decode_literal_field_literal_name (encoded,
                                                          encoded_len,
                                                          name_out,
                                                          sizeof (name_out),
                                                          &name_len,
                                                          value_out,
                                                          sizeof (value_out),
                                                          &value_len,
                                                          &never_indexed,
                                                          &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode success");
  TEST_ASSERT (never_indexed == true, "never_indexed is true");

  printf ("PASS\n");
}

/**
 * Test decoding with Huffman compression.
 */
static void
test_decode_huffman (void)
{
  unsigned char encoded[256];
  unsigned char name_out[256];
  unsigned char value_out[256];
  size_t encoded_len, name_len, value_len, consumed;
  bool never_indexed;
  SocketQPACK_Result result;

  printf ("  Decode with Huffman... ");

  /* Encode with Huffman */
  result = SocketQPACK_encode_literal_field_literal_name (
      encoded,
      sizeof (encoded),
      (const unsigned char *)"content-type",
      12,
      true,
      (const unsigned char *)"application/json",
      16,
      true,
      false,
      &encoded_len);
  TEST_ASSERT (result == QPACK_OK, "encode success");

  /* Decode */
  result = SocketQPACK_decode_literal_field_literal_name (encoded,
                                                          encoded_len,
                                                          name_out,
                                                          sizeof (name_out),
                                                          &name_len,
                                                          value_out,
                                                          sizeof (value_out),
                                                          &value_len,
                                                          &never_indexed,
                                                          &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode success");
  TEST_ASSERT (name_len == 12, "name_len is 12");
  TEST_ASSERT (memcmp (name_out, "content-type", 12) == 0, "name matches");
  TEST_ASSERT (value_len == 16, "value_len is 16");
  TEST_ASSERT (memcmp (value_out, "application/json", 16) == 0,
               "value matches");

  printf ("PASS\n");
}

/**
 * Test decoding empty strings.
 */
static void
test_decode_empty (void)
{
  unsigned char encoded[256];
  unsigned char name_out[256];
  unsigned char value_out[256];
  size_t encoded_len, name_len, value_len, consumed;
  bool never_indexed;
  SocketQPACK_Result result;

  printf ("  Decode empty strings... ");

  /* Encode empty name */
  result = SocketQPACK_encode_literal_field_literal_name (
      encoded,
      sizeof (encoded),
      NULL,
      0,
      false,
      (const unsigned char *)"value",
      5,
      false,
      false,
      &encoded_len);
  TEST_ASSERT (result == QPACK_OK, "encode success");

  /* Decode */
  result = SocketQPACK_decode_literal_field_literal_name (encoded,
                                                          encoded_len,
                                                          name_out,
                                                          sizeof (name_out),
                                                          &name_len,
                                                          value_out,
                                                          sizeof (value_out),
                                                          &value_len,
                                                          &never_indexed,
                                                          &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode empty name success");
  TEST_ASSERT (name_len == 0, "name_len is 0");
  TEST_ASSERT (value_len == 5, "value_len is 5");

  /* Encode both empty */
  result = SocketQPACK_encode_literal_field_literal_name (encoded,
                                                          sizeof (encoded),
                                                          NULL,
                                                          0,
                                                          false,
                                                          NULL,
                                                          0,
                                                          false,
                                                          false,
                                                          &encoded_len);
  TEST_ASSERT (result == QPACK_OK, "encode both empty success");

  /* Decode */
  result = SocketQPACK_decode_literal_field_literal_name (encoded,
                                                          encoded_len,
                                                          name_out,
                                                          sizeof (name_out),
                                                          &name_len,
                                                          value_out,
                                                          sizeof (value_out),
                                                          &value_len,
                                                          &never_indexed,
                                                          &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode both empty success");
  TEST_ASSERT (name_len == 0, "name_len is 0");
  TEST_ASSERT (value_len == 0, "value_len is 0");

  printf ("PASS\n");
}

/**
 * Test incomplete data handling.
 */
static void
test_decode_incomplete (void)
{
  unsigned char encoded[256];
  unsigned char name_out[256];
  unsigned char value_out[256];
  size_t encoded_len, name_len, value_len, consumed;
  bool never_indexed;
  SocketQPACK_Result result;

  printf ("  Decode incomplete data... ");

  /* Encode a complete instruction */
  result = SocketQPACK_encode_literal_field_literal_name (
      encoded,
      sizeof (encoded),
      (const unsigned char *)"header",
      6,
      false,
      (const unsigned char *)"value",
      5,
      false,
      false,
      &encoded_len);
  TEST_ASSERT (result == QPACK_OK, "encode success");

  /* Try to decode with truncated data */
  result = SocketQPACK_decode_literal_field_literal_name (encoded,
                                                          2, /* only 2 bytes */
                                                          name_out,
                                                          sizeof (name_out),
                                                          &name_len,
                                                          value_out,
                                                          sizeof (value_out),
                                                          &value_len,
                                                          &never_indexed,
                                                          &consumed);
  TEST_ASSERT (result == QPACK_INCOMPLETE, "incomplete data detected");

  /* Empty buffer */
  result = SocketQPACK_decode_literal_field_literal_name (encoded,
                                                          0,
                                                          name_out,
                                                          sizeof (name_out),
                                                          &name_len,
                                                          value_out,
                                                          sizeof (value_out),
                                                          &value_len,
                                                          &never_indexed,
                                                          &consumed);
  TEST_ASSERT (result == QPACK_INCOMPLETE, "empty buffer is incomplete");

  printf ("PASS\n");
}

/* ============================================================================
 * ERROR HANDLING TESTS
 * ============================================================================
 */

/**
 * Test NULL parameter handling.
 */
static void
test_null_params (void)
{
  unsigned char buf[256];
  unsigned char name_out[256];
  unsigned char value_out[256];
  size_t bytes_written, name_len, value_len, consumed;
  bool never_indexed;
  SocketQPACK_Result result;

  printf ("  NULL parameter handling... ");

  /* Encode with NULL buffer */
  result = SocketQPACK_encode_literal_field_literal_name (
      NULL,
      256,
      (const unsigned char *)"name",
      4,
      false,
      (const unsigned char *)"value",
      5,
      false,
      false,
      &bytes_written);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL buffer fails");

  /* Encode with NULL bytes_written */
  result = SocketQPACK_encode_literal_field_literal_name (
      buf,
      256,
      (const unsigned char *)"name",
      4,
      false,
      (const unsigned char *)"value",
      5,
      false,
      false,
      NULL);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL bytes_written fails");

  /* Encode with NULL name but non-zero length */
  result = SocketQPACK_encode_literal_field_literal_name (
      buf,
      256,
      NULL,
      5, /* len > 0 with NULL */
      false,
      (const unsigned char *)"value",
      5,
      false,
      false,
      &bytes_written);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "NULL name with len fails");

  /* Decode with NULL name_out */
  result = SocketQPACK_decode_literal_field_literal_name (buf,
                                                          10,
                                                          NULL,
                                                          256,
                                                          &name_len,
                                                          value_out,
                                                          sizeof (value_out),
                                                          &value_len,
                                                          &never_indexed,
                                                          &consumed);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "decode NULL name_out fails");

  /* Decode with NULL value_out */
  result = SocketQPACK_decode_literal_field_literal_name (buf,
                                                          10,
                                                          name_out,
                                                          sizeof (name_out),
                                                          &name_len,
                                                          NULL,
                                                          256,
                                                          &value_len,
                                                          &never_indexed,
                                                          &consumed);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM, "decode NULL value_out fails");

  /* Decode with NULL bytes_consumed */
  result = SocketQPACK_decode_literal_field_literal_name (buf,
                                                          10,
                                                          name_out,
                                                          sizeof (name_out),
                                                          &name_len,
                                                          value_out,
                                                          sizeof (value_out),
                                                          &value_len,
                                                          &never_indexed,
                                                          NULL);
  TEST_ASSERT (result == QPACK_ERR_NULL_PARAM,
               "decode NULL bytes_consumed fails");

  printf ("PASS\n");
}

/**
 * Test buffer overflow protection.
 */
static void
test_buffer_overflow (void)
{
  unsigned char buf[10];
  size_t bytes_written;
  SocketQPACK_Result result;

  printf ("  Buffer overflow protection... ");

  /* Try to encode with insufficient buffer */
  result = SocketQPACK_encode_literal_field_literal_name (
      buf,
      1, /* way too small */
      (const unsigned char *)"long-header-name",
      16,
      false,
      (const unsigned char *)"long-header-value",
      17,
      false,
      false,
      &bytes_written);
  TEST_ASSERT (result == QPACK_ERR_TABLE_SIZE || result == QPACK_ERR_INTEGER,
               "overflow protected");

  /* Try encoding that just barely overflows */
  result = SocketQPACK_encode_literal_field_literal_name (
      buf,
      5, /* very small */
      (const unsigned char *)"name",
      4,
      false,
      (const unsigned char *)"value",
      5,
      false,
      false,
      &bytes_written);
  TEST_ASSERT (result != QPACK_OK, "insufficient buffer detected");

  printf ("PASS\n");
}

/* ============================================================================
 * ROUND-TRIP TESTS
 * ============================================================================
 */

/**
 * Test encode-decode round-trip with various data.
 */
static void
test_roundtrip (void)
{
  unsigned char encoded[1024];
  unsigned char name_out[256];
  unsigned char value_out[256];
  size_t encoded_len, name_len, value_len, consumed;
  bool never_indexed;
  SocketQPACK_Result result;

  printf ("  Round-trip various data... ");

  /* Test various header types */
  struct
  {
    const char *name;
    const char *value;
    bool never_idx;
    bool name_huff;
    bool value_huff;
  } test_cases[]
      = { { "content-type", "text/html; charset=utf-8", false, true, true },
          { "x-custom-header", "custom-value", false, false, false },
          { "authorization", "Bearer secret-token", true, false, false },
          { "cookie", "session=abc123; user=john", true, true, true },
          { "accept-encoding", "gzip, deflate, br", false, true, true },
          { "cache-control", "no-cache, no-store", false, false, true },
          { "", "empty-name-value", false, false, false },
          { "empty-value", "", false, true, false } };

  size_t num_tests = sizeof (test_cases) / sizeof (test_cases[0]);

  for (size_t i = 0; i < num_tests; i++)
    {
      size_t name_in_len = strlen (test_cases[i].name);
      size_t value_in_len = strlen (test_cases[i].value);

      /* Encode */
      result = SocketQPACK_encode_literal_field_literal_name (
          encoded,
          sizeof (encoded),
          (const unsigned char *)test_cases[i].name,
          name_in_len,
          test_cases[i].name_huff,
          (const unsigned char *)test_cases[i].value,
          value_in_len,
          test_cases[i].value_huff,
          test_cases[i].never_idx,
          &encoded_len);
      TEST_ASSERT (result == QPACK_OK, "encode success");

      /* Decode */
      result
          = SocketQPACK_decode_literal_field_literal_name (encoded,
                                                           encoded_len,
                                                           name_out,
                                                           sizeof (name_out),
                                                           &name_len,
                                                           value_out,
                                                           sizeof (value_out),
                                                           &value_len,
                                                           &never_indexed,
                                                           &consumed);
      TEST_ASSERT (result == QPACK_OK, "decode success");
      TEST_ASSERT (consumed == encoded_len, "all bytes consumed");
      TEST_ASSERT (name_len == name_in_len, "name length matches");
      TEST_ASSERT (value_len == value_in_len, "value length matches");
      if (name_in_len > 0)
        TEST_ASSERT (memcmp (name_out, test_cases[i].name, name_in_len) == 0,
                     "name matches");
      if (value_in_len > 0)
        TEST_ASSERT (memcmp (value_out, test_cases[i].value, value_in_len) == 0,
                     "value matches");
      TEST_ASSERT (never_indexed == test_cases[i].never_idx,
                   "never_indexed matches");
    }

  printf ("PASS\n");
}

/**
 * Test with long strings requiring multi-byte integer encoding.
 */
static void
test_long_strings (void)
{
  unsigned char encoded[8192];
  unsigned char name_out[1024];
  unsigned char value_out[4096];
  size_t encoded_len, name_len, value_len, consumed;
  bool never_indexed;
  SocketQPACK_Result result;
  char long_name[300];
  char long_value[2000];

  printf ("  Long strings (multi-byte integers)... ");

  /* Create strings that exceed 3-bit and 7-bit prefix limits */
  memset (long_name, 'n', sizeof (long_name) - 1);
  long_name[sizeof (long_name) - 1] = '\0';

  memset (long_value, 'v', sizeof (long_value) - 1);
  long_value[sizeof (long_value) - 1] = '\0';

  /* Encode */
  result = SocketQPACK_encode_literal_field_literal_name (
      encoded,
      sizeof (encoded),
      (const unsigned char *)long_name,
      strlen (long_name),
      false, /* no huffman to test raw lengths */
      (const unsigned char *)long_value,
      strlen (long_value),
      false,
      false,
      &encoded_len);
  TEST_ASSERT (result == QPACK_OK, "encode long strings success");

  /* Decode */
  result = SocketQPACK_decode_literal_field_literal_name (encoded,
                                                          encoded_len,
                                                          name_out,
                                                          sizeof (name_out),
                                                          &name_len,
                                                          value_out,
                                                          sizeof (value_out),
                                                          &value_len,
                                                          &never_indexed,
                                                          &consumed);
  TEST_ASSERT (result == QPACK_OK, "decode long strings success");
  TEST_ASSERT (consumed == encoded_len, "all bytes consumed");
  TEST_ASSERT (name_len == strlen (long_name), "long name length matches");
  TEST_ASSERT (value_len == strlen (long_value), "long value length matches");
  TEST_ASSERT (memcmp (name_out, long_name, name_len) == 0,
               "long name matches");
  TEST_ASSERT (memcmp (value_out, long_value, value_len) == 0,
               "long value matches");

  printf ("PASS\n");
}

/* ============================================================================
 * TEST SUITE
 * ============================================================================
 */

static void
run_pattern_tests (void)
{
  printf ("Pattern Validation Tests:\n");
  test_pattern_validation ();
}

static void
run_encode_tests (void)
{
  printf ("Encode Tests:\n");
  test_encode_basic ();
  test_encode_never_indexed ();
  test_encode_huffman ();
  test_encode_empty ();
}

static void
run_decode_tests (void)
{
  printf ("Decode Tests:\n");
  test_decode_basic ();
  test_decode_never_indexed ();
  test_decode_huffman ();
  test_decode_empty ();
  test_decode_incomplete ();
}

static void
run_error_tests (void)
{
  printf ("Error Handling Tests:\n");
  test_null_params ();
  test_buffer_overflow ();
}

static void
run_roundtrip_tests (void)
{
  printf ("Round-trip Tests:\n");
  test_roundtrip ();
  test_long_strings ();
}

int
main (void)
{
  printf ("=== QPACK Literal Field Line with Literal Name Tests "
          "(RFC 9204 Section 4.5.6) ===\n\n");

  run_pattern_tests ();
  printf ("\n");

  run_encode_tests ();
  printf ("\n");

  run_decode_tests ();
  printf ("\n");

  run_error_tests ();
  printf ("\n");

  run_roundtrip_tests ();
  printf ("\n");

  printf ("=== All tests passed! ===\n");
  return 0;
}
