/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_qpack_insert_count_inc.c
 * @brief Unit tests for QPACK Insert Count Increment instruction (RFC 9204
 * Section 4.4.3).
 *
 * Tests:
 * - Wire format encoding/decoding
 * - Decoder state updates
 * - Error handling for invalid increments
 * - RFC 7541 integer encoding edge cases
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/qpack/SocketQPACK.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple test assertion macro */
#define TEST_ASSERT(cond, msg)                                                 \
  do                                                                           \
    {                                                                          \
      if (!(cond))                                                             \
        {                                                                      \
          fprintf (stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__);   \
          exit (1);                                                            \
        }                                                                      \
    }                                                                          \
  while (0)

/* ============================================================================
 * Encoding Tests
 * ============================================================================
 */

/**
 * Test encoding small increment (fits in 6 bits)
 * Value 10: 00 001010 = 0x0A
 */
static void
test_encode_small_increment (void)
{
  unsigned char buf[16];
  ssize_t len;

  printf ("  Encode small increment (10)... ");

  len = SocketQPACK_encode_insert_count_inc (10, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Expected 1 byte");
  TEST_ASSERT (buf[0] == 0x0A, "Expected 0x0A (00001010)");

  printf ("PASS\n");
}

/**
 * Test encoding increment at prefix boundary
 * Value 62: 00 111110 = 0x3E (max single byte before continuation)
 */
static void
test_encode_boundary_increment (void)
{
  unsigned char buf[16];
  ssize_t len;

  printf ("  Encode boundary increment (62)... ");

  len = SocketQPACK_encode_insert_count_inc (62, buf, sizeof (buf));
  TEST_ASSERT (len == 1, "Expected 1 byte");
  TEST_ASSERT (buf[0] == 0x3E, "Expected 0x3E (00111110)");

  printf ("PASS\n");
}

/**
 * Test encoding increment requiring multi-byte (value 63 and above)
 * Value 63: 00 111111 followed by 0x00 = prefix maxed + continuation
 */
static void
test_encode_multibyte_increment (void)
{
  unsigned char buf[16];
  ssize_t len;

  printf ("  Encode multi-byte increment (63)... ");

  len = SocketQPACK_encode_insert_count_inc (63, buf, sizeof (buf));
  TEST_ASSERT (len == 2, "Expected 2 bytes");
  TEST_ASSERT (buf[0] == 0x3F, "First byte should be 0x3F (prefix maxed)");
  TEST_ASSERT (buf[1] == 0x00, "Second byte should be 0x00");

  printf ("PASS\n");
}

/**
 * Test encoding large increment (value 1000)
 * Requires multi-byte encoding
 *
 * RFC 7541 Section 5.1 Integer encoding for 1000 with 6-bit prefix:
 * - 6-bit max prefix = 63 (2^6 - 1)
 * - Since 1000 >= 63, first byte = 63 (0x3F)
 * - Remainder = 1000 - 63 = 937
 * - 937 in continuation bytes:
 *   - 937 % 128 = 41 = 0x29, continuation bit = 0x80 | 0x29 = 0xA9
 *   - 937 / 128 = 7 = 0x07 (no continuation bit)
 */
static void
test_encode_large_increment (void)
{
  unsigned char buf[16];
  ssize_t len;

  printf ("  Encode large increment (1000)... ");

  len = SocketQPACK_encode_insert_count_inc (1000, buf, sizeof (buf));
  TEST_ASSERT (len == 3, "Expected 3 bytes");
  TEST_ASSERT (buf[0] == 0x3F, "First byte should be 0x3F (prefix maxed)");
  TEST_ASSERT (buf[1] == 0xA9, "Second byte should be 0xA9 (41 + cont bit)");
  TEST_ASSERT (buf[2] == 0x07, "Third byte should be 0x07");

  printf ("PASS\n");
}

/**
 * Test encoding zero increment returns error
 */
static void
test_encode_zero_increment_fails (void)
{
  unsigned char buf[16];
  ssize_t len;

  printf ("  Encode zero increment fails... ");

  len = SocketQPACK_encode_insert_count_inc (0, buf, sizeof (buf));
  TEST_ASSERT (len == -1, "Should return -1 for zero increment");

  printf ("PASS\n");
}

/**
 * Test encoding with NULL buffer fails
 */
static void
test_encode_null_buffer_fails (void)
{
  ssize_t len;

  printf ("  Encode with NULL buffer fails... ");

  len = SocketQPACK_encode_insert_count_inc (10, NULL, 16);
  TEST_ASSERT (len == -1, "Should return -1 for NULL buffer");

  printf ("PASS\n");
}

/**
 * Test encoding with zero size buffer fails
 */
static void
test_encode_zero_size_fails (void)
{
  unsigned char buf[16];
  ssize_t len;

  printf ("  Encode with zero size buffer fails... ");

  len = SocketQPACK_encode_insert_count_inc (10, buf, 0);
  TEST_ASSERT (len == -1, "Should return -1 for zero size buffer");

  printf ("PASS\n");
}

/* ============================================================================
 * Decoding Tests
 * ============================================================================
 */

/**
 * Test decoding small increment
 */
static void
test_decode_small_increment (void)
{
  unsigned char data[] = { 0x0A }; /* 00001010 = 10 */
  size_t increment;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Decode small increment (10)... ");

  result
      = SocketQPACK_decode_insert_count_inc (data, sizeof (data), &increment,
                                             &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (increment == 10, "Increment should be 10");
  TEST_ASSERT (consumed == 1, "Should consume 1 byte");

  printf ("PASS\n");
}

/**
 * Test decoding multi-byte increment (value 63)
 */
static void
test_decode_multibyte_increment (void)
{
  unsigned char data[] = { 0x3F, 0x00 }; /* 63 */
  size_t increment;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Decode multi-byte increment (63)... ");

  result
      = SocketQPACK_decode_insert_count_inc (data, sizeof (data), &increment,
                                             &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (increment == 63, "Increment should be 63");
  TEST_ASSERT (consumed == 2, "Should consume 2 bytes");

  printf ("PASS\n");
}

/**
 * Test decoding large increment (value 1000)
 */
static void
test_decode_large_increment (void)
{
  unsigned char data[] = { 0x3F, 0xA9, 0x07 }; /* 1000 */
  size_t increment;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Decode large increment (1000)... ");

  result
      = SocketQPACK_decode_insert_count_inc (data, sizeof (data), &increment,
                                             &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should decode OK");
  TEST_ASSERT (increment == 1000, "Increment should be 1000");
  TEST_ASSERT (consumed == 3, "Should consume 3 bytes");

  printf ("PASS\n");
}

/**
 * Test decoding with incomplete data
 */
static void
test_decode_incomplete_data (void)
{
  unsigned char data[] = { 0x3F }; /* Incomplete multi-byte */
  size_t increment;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Decode with incomplete data... ");

  result
      = SocketQPACK_decode_insert_count_inc (data, sizeof (data), &increment,
                                             &consumed);
  TEST_ASSERT (result == QPACK_INCOMPLETE, "Should return INCOMPLETE");

  printf ("PASS\n");
}

/**
 * Test decoding wrong instruction pattern
 */
static void
test_decode_wrong_pattern (void)
{
  unsigned char data[] = { 0x80 }; /* Pattern 10xxxxxx - not Insert Count Inc */
  size_t increment;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Decode wrong pattern fails... ");

  result
      = SocketQPACK_decode_insert_count_inc (data, sizeof (data), &increment,
                                             &consumed);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_ERROR,
               "Should return DECODER_STREAM_ERROR");

  printf ("PASS\n");
}

/**
 * Test decoding with NULL inputs
 */
static void
test_decode_null_inputs (void)
{
  unsigned char data[] = { 0x0A };
  size_t increment;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Decode with NULL inputs... ");

  result = SocketQPACK_decode_insert_count_inc (NULL, 1, &increment, &consumed);
  TEST_ASSERT (result == QPACK_ERROR, "Should return ERROR for NULL input");

  result = SocketQPACK_decode_insert_count_inc (data, sizeof (data), NULL,
                                                &consumed);
  TEST_ASSERT (result == QPACK_ERROR, "Should return ERROR for NULL increment");

  result
      = SocketQPACK_decode_insert_count_inc (data, sizeof (data), &increment,
                                             NULL);
  TEST_ASSERT (result == QPACK_ERROR, "Should return ERROR for NULL consumed");

  printf ("PASS\n");
}

/**
 * Test decoding with empty input
 */
static void
test_decode_empty_input (void)
{
  unsigned char data[] = { 0 };
  size_t increment;
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Decode with empty input... ");

  result = SocketQPACK_decode_insert_count_inc (data, 0, &increment, &consumed);
  TEST_ASSERT (result == QPACK_INCOMPLETE, "Should return INCOMPLETE");

  printf ("PASS\n");
}

/* ============================================================================
 * Decoder State Tests
 * ============================================================================
 */

/**
 * Test applying valid increment
 */
static void
test_apply_valid_increment (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Decoder_T decoder = SocketQPACK_Decoder_new (NULL, arena);
  SocketQPACK_Result result;

  printf ("  Apply valid increment... ");

  /* Set encoder's insert count */
  SocketQPACK_Decoder_set_insert_count (decoder, 100);

  /* Apply increment of 10 */
  result = SocketQPACK_Decoder_apply_increment (decoder, 10);
  TEST_ASSERT (result == QPACK_OK, "Should apply OK");
  TEST_ASSERT (SocketQPACK_Decoder_get_known_received_count (decoder) == 10,
               "Known received count should be 10");

  /* Apply another increment of 20 */
  result = SocketQPACK_Decoder_apply_increment (decoder, 20);
  TEST_ASSERT (result == QPACK_OK, "Should apply OK");
  TEST_ASSERT (SocketQPACK_Decoder_get_known_received_count (decoder) == 30,
               "Known received count should be 30");

  SocketQPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test applying zero increment fails
 */
static void
test_apply_zero_increment_fails (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Decoder_T decoder = SocketQPACK_Decoder_new (NULL, arena);
  SocketQPACK_Result result;

  printf ("  Apply zero increment fails... ");

  SocketQPACK_Decoder_set_insert_count (decoder, 100);

  result = SocketQPACK_Decoder_apply_increment (decoder, 0);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_ERROR,
               "Should return DECODER_STREAM_ERROR for zero increment");
  TEST_ASSERT (SocketQPACK_Decoder_get_known_received_count (decoder) == 0,
               "Known received count should remain 0");

  SocketQPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test applying increment exceeding insert count fails
 */
static void
test_apply_exceeding_increment_fails (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Decoder_T decoder = SocketQPACK_Decoder_new (NULL, arena);
  SocketQPACK_Result result;

  printf ("  Apply exceeding increment fails... ");

  /* Set encoder's insert count to 10 */
  SocketQPACK_Decoder_set_insert_count (decoder, 10);

  /* Try to apply increment of 20 (exceeds 10) */
  result = SocketQPACK_Decoder_apply_increment (decoder, 20);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_ERROR,
               "Should return DECODER_STREAM_ERROR for exceeding increment");
  TEST_ASSERT (SocketQPACK_Decoder_get_known_received_count (decoder) == 0,
               "Known received count should remain 0");

  SocketQPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test applying increment exactly equal to insert count
 */
static void
test_apply_exact_increment (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Decoder_T decoder = SocketQPACK_Decoder_new (NULL, arena);
  SocketQPACK_Result result;

  printf ("  Apply exact increment... ");

  /* Set encoder's insert count to 50 */
  SocketQPACK_Decoder_set_insert_count (decoder, 50);

  /* Apply increment of 50 (exactly equal to insert count) */
  result = SocketQPACK_Decoder_apply_increment (decoder, 50);
  TEST_ASSERT (result == QPACK_OK, "Should apply OK");
  TEST_ASSERT (SocketQPACK_Decoder_get_known_received_count (decoder) == 50,
               "Known received count should be 50");

  SocketQPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test multiple sequential increments
 */
static void
test_multiple_sequential_increments (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Decoder_T decoder = SocketQPACK_Decoder_new (NULL, arena);
  SocketQPACK_Result result;

  printf ("  Multiple sequential increments... ");

  /* Set encoder's insert count */
  SocketQPACK_Decoder_set_insert_count (decoder, 100);

  /* Apply several increments */
  result = SocketQPACK_Decoder_apply_increment (decoder, 5);
  TEST_ASSERT (result == QPACK_OK, "First increment should succeed");
  TEST_ASSERT (SocketQPACK_Decoder_get_known_received_count (decoder) == 5,
               "Should be 5");

  result = SocketQPACK_Decoder_apply_increment (decoder, 10);
  TEST_ASSERT (result == QPACK_OK, "Second increment should succeed");
  TEST_ASSERT (SocketQPACK_Decoder_get_known_received_count (decoder) == 15,
               "Should be 15");

  result = SocketQPACK_Decoder_apply_increment (decoder, 25);
  TEST_ASSERT (result == QPACK_OK, "Third increment should succeed");
  TEST_ASSERT (SocketQPACK_Decoder_get_known_received_count (decoder) == 40,
               "Should be 40");

  result = SocketQPACK_Decoder_apply_increment (decoder, 60);
  TEST_ASSERT (result == QPACK_OK, "Fourth increment should succeed");
  TEST_ASSERT (SocketQPACK_Decoder_get_known_received_count (decoder) == 100,
               "Should be 100");

  /* Next increment should fail (would exceed 100) */
  result = SocketQPACK_Decoder_apply_increment (decoder, 1);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_ERROR,
               "Fifth increment should fail");

  SocketQPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Process (Decode + Apply) Tests
 * ============================================================================
 */

/**
 * Test full process flow
 */
static void
test_process_insert_count_inc (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Decoder_T decoder = SocketQPACK_Decoder_new (NULL, arena);
  unsigned char data[] = { 0x0A }; /* increment = 10 */
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Process insert count increment... ");

  SocketQPACK_Decoder_set_insert_count (decoder, 100);

  result = SocketQPACK_Decoder_process_insert_count_inc (decoder, data,
                                                         sizeof (data),
                                                         &consumed);
  TEST_ASSERT (result == QPACK_OK, "Should process OK");
  TEST_ASSERT (consumed == 1, "Should consume 1 byte");
  TEST_ASSERT (SocketQPACK_Decoder_get_known_received_count (decoder) == 10,
               "Known received count should be 10");

  SocketQPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test process with invalid increment (zero)
 */
static void
test_process_zero_increment (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Decoder_T decoder = SocketQPACK_Decoder_new (NULL, arena);
  unsigned char data[] = { 0x00 }; /* increment = 0 */
  size_t consumed;
  SocketQPACK_Result result;

  printf ("  Process zero increment fails... ");

  SocketQPACK_Decoder_set_insert_count (decoder, 100);

  result = SocketQPACK_Decoder_process_insert_count_inc (decoder, data,
                                                         sizeof (data),
                                                         &consumed);
  TEST_ASSERT (result == QPACK_DECODER_STREAM_ERROR,
               "Should return DECODER_STREAM_ERROR");
  TEST_ASSERT (SocketQPACK_Decoder_get_known_received_count (decoder) == 0,
               "Known received count should remain 0");

  SocketQPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Encode/Decode Round-Trip Tests
 * ============================================================================
 */

/**
 * Test encode-decode round trip for various values
 */
static void
test_roundtrip (void)
{
  unsigned char buf[16];
  size_t test_values[] = { 1, 10, 62, 63, 100, 500, 1000, 10000, 100000 };
  size_t num_tests = sizeof (test_values) / sizeof (test_values[0]);

  printf ("  Encode-decode round trip... ");

  for (size_t i = 0; i < num_tests; i++)
    {
      size_t original = test_values[i];
      ssize_t encoded_len;
      size_t decoded;
      size_t consumed;
      SocketQPACK_Result result;

      /* Encode */
      encoded_len
          = SocketQPACK_encode_insert_count_inc (original, buf, sizeof (buf));
      TEST_ASSERT (encoded_len > 0, "Encoding should succeed");

      /* Decode */
      result = SocketQPACK_decode_insert_count_inc (buf, (size_t)encoded_len,
                                                    &decoded, &consumed);
      TEST_ASSERT (result == QPACK_OK, "Decoding should succeed");
      TEST_ASSERT (decoded == original, "Decoded value should match original");
      TEST_ASSERT (consumed == (size_t)encoded_len,
                   "Should consume all encoded bytes");
    }

  printf ("PASS\n");
}

/* ============================================================================
 * Utility Tests
 * ============================================================================
 */

/**
 * Test is_insert_count_inc helper
 */
static void
test_is_insert_count_inc (void)
{
  printf ("  is_insert_count_inc helper... ");

  /* Valid Insert Count Increment patterns (00xxxxxx) */
  TEST_ASSERT (SocketQPACK_is_insert_count_inc (0x00), "0x00 should match");
  TEST_ASSERT (SocketQPACK_is_insert_count_inc (0x0A), "0x0A should match");
  TEST_ASSERT (SocketQPACK_is_insert_count_inc (0x3F), "0x3F should match");

  /* Invalid patterns */
  TEST_ASSERT (!SocketQPACK_is_insert_count_inc (0x40), "0x40 should not match");
  TEST_ASSERT (!SocketQPACK_is_insert_count_inc (0x80), "0x80 should not match");
  TEST_ASSERT (!SocketQPACK_is_insert_count_inc (0xC0), "0xC0 should not match");

  printf ("PASS\n");
}

/**
 * Test result_string function
 */
static void
test_result_string (void)
{
  printf ("  Result strings... ");

  TEST_ASSERT (strcmp (SocketQPACK_result_string (QPACK_OK), "OK") == 0,
               "QPACK_OK string");
  TEST_ASSERT (strcmp (SocketQPACK_result_string (QPACK_DECODER_STREAM_ERROR),
                       "Decoder stream protocol error")
                   == 0,
               "QPACK_DECODER_STREAM_ERROR string");

  printf ("PASS\n");
}

/* ============================================================================
 * Decoder Creation Tests
 * ============================================================================
 */

/**
 * Test decoder creation with defaults
 */
static void
test_decoder_creation_defaults (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_Decoder_T decoder;

  printf ("  Decoder creation with defaults... ");

  decoder = SocketQPACK_Decoder_new (NULL, arena);
  TEST_ASSERT (decoder != NULL, "Decoder should be created");
  TEST_ASSERT (SocketQPACK_Decoder_get_known_received_count (decoder) == 0,
               "Initial known_received_count should be 0");

  SocketQPACK_Decoder_free (&decoder);
  TEST_ASSERT (decoder == NULL, "Decoder should be NULL after free");

  Arena_dispose (&arena);

  printf ("PASS\n");
}

/**
 * Test decoder creation with config
 */
static void
test_decoder_creation_with_config (void)
{
  Arena_T arena = Arena_new ();
  SocketQPACK_DecoderConfig config;
  SocketQPACK_Decoder_T decoder;

  printf ("  Decoder creation with config... ");

  SocketQPACK_decoder_config_defaults (&config);
  config.max_table_capacity = 8192;
  config.max_blocked_streams = 50;

  decoder = SocketQPACK_Decoder_new (&config, arena);
  TEST_ASSERT (decoder != NULL, "Decoder should be created");
  TEST_ASSERT (decoder->max_table_capacity == 8192,
               "max_table_capacity should be 8192");
  TEST_ASSERT (decoder->max_blocked_streams == 50,
               "max_blocked_streams should be 50");

  SocketQPACK_Decoder_free (&decoder);
  Arena_dispose (&arena);

  printf ("PASS\n");
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  printf ("QPACK Insert Count Increment Tests (RFC 9204 Section 4.4.3)\n");
  printf ("============================================================\n");

  printf ("\nEncoding Tests:\n");
  test_encode_small_increment ();
  test_encode_boundary_increment ();
  test_encode_multibyte_increment ();
  test_encode_large_increment ();
  test_encode_zero_increment_fails ();
  test_encode_null_buffer_fails ();
  test_encode_zero_size_fails ();

  printf ("\nDecoding Tests:\n");
  test_decode_small_increment ();
  test_decode_multibyte_increment ();
  test_decode_large_increment ();
  test_decode_incomplete_data ();
  test_decode_wrong_pattern ();
  test_decode_null_inputs ();
  test_decode_empty_input ();

  printf ("\nDecoder State Tests:\n");
  test_apply_valid_increment ();
  test_apply_zero_increment_fails ();
  test_apply_exceeding_increment_fails ();
  test_apply_exact_increment ();
  test_multiple_sequential_increments ();

  printf ("\nProcess Tests:\n");
  test_process_insert_count_inc ();
  test_process_zero_increment ();

  printf ("\nRound-Trip Tests:\n");
  test_roundtrip ();

  printf ("\nUtility Tests:\n");
  test_is_insert_count_inc ();
  test_result_string ();

  printf ("\nDecoder Creation Tests:\n");
  test_decoder_creation_defaults ();
  test_decoder_creation_with_config ();

  printf ("\n============================================================\n");
  printf ("All tests passed!\n");

  return 0;
}
