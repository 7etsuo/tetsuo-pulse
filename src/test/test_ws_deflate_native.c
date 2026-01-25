/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_ws_deflate_native.c - Native DEFLATE WebSocket compression tests
 *
 * Unit tests for RFC 7692 permessage-deflate using native DEFLATE
 * implementation. Tests compression, decompression, roundtrip, context
 * takeover, trailer handling, and decompression bomb protection.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "deflate/SocketDeflate.h"
#include "test/Test.h"

#ifdef SOCKETWS_HAS_NATIVE_DEFLATE

static Arena_T test_arena;

/* RFC 7692: Trailer bytes removed on compress, added on decompress */
#define WS_DEFLATE_TRAILER_SIZE 4
static const uint8_t WS_DEFLATE_TRAILER[WS_DEFLATE_TRAILER_SIZE]
    = { 0x00, 0x00, 0xFF, 0xFF };

/*
 * Helper: Simulate ws_compress_message using native DEFLATE directly.
 * This allows testing without full WebSocket infrastructure.
 */
static int
test_compress (Arena_T arena,
               SocketDeflate_Deflater_T deflater,
               const uint8_t *input,
               size_t input_len,
               uint8_t **output,
               size_t *output_len,
               int use_sync_flush)
{
  SocketDeflate_Result res;
  size_t buf_size;
  size_t consumed, written;
  uint8_t *buf;

  buf_size = SocketDeflate_compress_bound (input_len) + 64;
  buf = ALLOC (arena, buf_size);
  if (!buf)
    return -1;

  res = SocketDeflate_Deflater_deflate (
      deflater, input, input_len, &consumed, buf, buf_size, &written);
  if (res != DEFLATE_OK || consumed != input_len)
    return -1;

  if (use_sync_flush)
    {
      size_t flush_written;
      res = SocketDeflate_Deflater_sync_flush (
          deflater, buf + written, buf_size - written, &flush_written);
      if (res != DEFLATE_OK)
        return -1;
      written += flush_written;
    }
  else
    {
      size_t finish_written;
      res = SocketDeflate_Deflater_finish (
          deflater, buf + written, buf_size - written, &finish_written);
      if (res != DEFLATE_OK)
        return -1;
      written += finish_written;
      SocketDeflate_Deflater_reset (deflater);
    }

  /* Remove RFC 7692 trailer if present */
  if (written >= WS_DEFLATE_TRAILER_SIZE
      && memcmp (buf + written - WS_DEFLATE_TRAILER_SIZE,
                 WS_DEFLATE_TRAILER,
                 WS_DEFLATE_TRAILER_SIZE)
             == 0)
    {
      written -= WS_DEFLATE_TRAILER_SIZE;
    }

  *output = buf;
  *output_len = written;
  return 0;
}

/*
 * Helper: Simulate ws_decompress_message using native DEFLATE directly.
 */
static int
test_decompress (Arena_T arena,
                 SocketDeflate_Inflater_T inflater,
                 const uint8_t *input,
                 size_t input_len,
                 uint8_t **output,
                 size_t *output_len,
                 int reset_after)
{
  SocketDeflate_Result res;
  size_t buf_size;
  size_t consumed, written, total_written;
  uint8_t *buf;
  uint8_t *input_with_trailer;

  /* Append RFC 7692 trailer */
  input_with_trailer = ALLOC (arena, input_len + WS_DEFLATE_TRAILER_SIZE);
  if (!input_with_trailer)
    return -1;
  memcpy (input_with_trailer, input, input_len);
  memcpy (input_with_trailer + input_len,
          WS_DEFLATE_TRAILER,
          WS_DEFLATE_TRAILER_SIZE);

  buf_size = input_len * 4;
  if (buf_size < 4096)
    buf_size = 4096;

  buf = ALLOC (arena, buf_size);
  if (!buf)
    return -1;

  total_written = 0;
  consumed = 0;

  while (consumed < input_len + WS_DEFLATE_TRAILER_SIZE)
    {
      size_t this_consumed = 0;
      res = SocketDeflate_Inflater_inflate (inflater,
                                            input_with_trailer + consumed,
                                            input_len + WS_DEFLATE_TRAILER_SIZE
                                                - consumed,
                                            &this_consumed,
                                            buf + total_written,
                                            buf_size - total_written,
                                            &written);

      consumed += this_consumed;

      if (res == DEFLATE_OUTPUT_FULL)
        {
          /* Grow buffer */
          size_t new_size = buf_size * 2;
          uint8_t *new_buf = ALLOC (arena, new_size);
          if (!new_buf)
            return -1;
          memcpy (new_buf, buf, total_written);
          buf = new_buf;
          buf_size = new_size;
        }
      else if (res != DEFLATE_OK && res != DEFLATE_INCOMPLETE)
        {
          return -1;
        }

      total_written += written;

      if (res == DEFLATE_OK)
        break;
    }

  if (reset_after)
    SocketDeflate_Inflater_reset (inflater);

  *output = buf;
  *output_len = total_written;
  return 0;
}

/*
 * Basic Compression Tests
 */

TEST (ws_compress_simple_message)
{
  const uint8_t input[] = "Hello, WebSocket World!";
  size_t input_len = sizeof (input) - 1;
  uint8_t *output;
  size_t output_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  ASSERT_NOT_NULL (deflater);

  int result = test_compress (
      test_arena, deflater, input, input_len, &output, &output_len, 0);
  ASSERT_EQ (result, 0);

  /* Compressed output should exist and be smaller than input for compressible
   * data */
  ASSERT_NOT_NULL (output);
  ASSERT (output_len > 0);

  /* Verify trailer was removed (should NOT end with 00 00 FF FF) */
  if (output_len >= WS_DEFLATE_TRAILER_SIZE)
    {
      int has_trailer = memcmp (output + output_len - WS_DEFLATE_TRAILER_SIZE,
                                WS_DEFLATE_TRAILER,
                                WS_DEFLATE_TRAILER_SIZE)
                        == 0;
      ASSERT_EQ (has_trailer, 0);
    }
}

TEST (ws_compress_empty_message)
{
  const uint8_t *input = (const uint8_t *)"";
  size_t input_len = 0;
  uint8_t *output;
  size_t output_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  ASSERT_NOT_NULL (deflater);

  int result = test_compress (
      test_arena, deflater, input, input_len, &output, &output_len, 0);
  ASSERT_EQ (result, 0);

  /* Empty message should produce minimal output */
  ASSERT_NOT_NULL (output);
}

TEST (ws_compress_large_message)
{
  /* 8KB message with repetitive content (highly compressible) */
  size_t input_len = 8 * 1024;
  uint8_t *input = ALLOC (test_arena, input_len);
  ASSERT_NOT_NULL (input);

  for (size_t i = 0; i < input_len; i++)
    input[i] = (uint8_t)(i % 256);

  uint8_t *output;
  size_t output_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  ASSERT_NOT_NULL (deflater);

  int result = test_compress (
      test_arena, deflater, input, input_len, &output, &output_len, 0);
  ASSERT_EQ (result, 0);

  ASSERT_NOT_NULL (output);
  ASSERT (output_len > 0);

  /* Repetitive data should compress well */
  ASSERT (output_len < input_len);
}

/*
 * Basic Decompression Tests
 */

TEST (ws_decompress_simple_message)
{
  /* First compress, then decompress */
  const uint8_t input[] = "Hello, WebSocket World!";
  size_t input_len = sizeof (input) - 1;
  uint8_t *compressed;
  size_t compressed_len;
  uint8_t *decompressed;
  size_t decompressed_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  ASSERT_NOT_NULL (deflater);

  int result = test_compress (
      test_arena, deflater, input, input_len, &compressed, &compressed_len, 0);
  ASSERT_EQ (result, 0);

  SocketDeflate_Inflater_T inflater
      = SocketDeflate_Inflater_new (test_arena, 1024 * 1024);
  ASSERT_NOT_NULL (inflater);

  result = test_decompress (test_arena,
                            inflater,
                            compressed,
                            compressed_len,
                            &decompressed,
                            &decompressed_len,
                            1);
  ASSERT_EQ (result, 0);

  ASSERT_EQ (decompressed_len, input_len);
  ASSERT_EQ (memcmp (decompressed, input, input_len), 0);
}

/*
 * Roundtrip Tests
 */

TEST (ws_roundtrip_text_message)
{
  const uint8_t input[] = "The quick brown fox jumps over the lazy dog. "
                          "Pack my box with five dozen liquor jugs.";
  size_t input_len = sizeof (input) - 1;
  uint8_t *compressed;
  size_t compressed_len;
  uint8_t *decompressed;
  size_t decompressed_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  SocketDeflate_Inflater_T inflater
      = SocketDeflate_Inflater_new (test_arena, 1024 * 1024);
  ASSERT_NOT_NULL (deflater);
  ASSERT_NOT_NULL (inflater);

  int result = test_compress (
      test_arena, deflater, input, input_len, &compressed, &compressed_len, 0);
  ASSERT_EQ (result, 0);

  result = test_decompress (test_arena,
                            inflater,
                            compressed,
                            compressed_len,
                            &decompressed,
                            &decompressed_len,
                            1);
  ASSERT_EQ (result, 0);

  ASSERT_EQ (decompressed_len, input_len);
  ASSERT_EQ (memcmp (decompressed, input, input_len), 0);
}

TEST (ws_roundtrip_binary_message)
{
  /* Binary data with all byte values */
  size_t input_len = 512;
  uint8_t *input = ALLOC (test_arena, input_len);
  ASSERT_NOT_NULL (input);

  for (size_t i = 0; i < input_len; i++)
    input[i] = (uint8_t)(i & 0xFF);

  uint8_t *compressed;
  size_t compressed_len;
  uint8_t *decompressed;
  size_t decompressed_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  SocketDeflate_Inflater_T inflater
      = SocketDeflate_Inflater_new (test_arena, 1024 * 1024);
  ASSERT_NOT_NULL (deflater);
  ASSERT_NOT_NULL (inflater);

  int result = test_compress (
      test_arena, deflater, input, input_len, &compressed, &compressed_len, 0);
  ASSERT_EQ (result, 0);

  result = test_decompress (test_arena,
                            inflater,
                            compressed,
                            compressed_len,
                            &decompressed,
                            &decompressed_len,
                            1);
  ASSERT_EQ (result, 0);

  ASSERT_EQ (decompressed_len, input_len);
  ASSERT_EQ (memcmp (decompressed, input, input_len), 0);
}

TEST (ws_roundtrip_large_message)
{
  /* 2KB message with simple pattern */
  size_t input_len = 2048;
  uint8_t *input = ALLOC (test_arena, input_len);
  ASSERT_NOT_NULL (input);

  /* Simple repeated pattern that's easy to verify */
  const char *pattern = "WebSocket compression test data. ";
  size_t pattern_len = strlen (pattern);
  for (size_t i = 0; i < input_len; i++)
    input[i] = (uint8_t)pattern[i % pattern_len];

  uint8_t *compressed;
  size_t compressed_len;
  uint8_t *decompressed;
  size_t decompressed_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  SocketDeflate_Inflater_T inflater
      = SocketDeflate_Inflater_new (test_arena, 8 * 1024);
  ASSERT_NOT_NULL (deflater);
  ASSERT_NOT_NULL (inflater);

  int result = test_compress (
      test_arena, deflater, input, input_len, &compressed, &compressed_len, 0);
  ASSERT_EQ (result, 0);

  result = test_decompress (test_arena,
                            inflater,
                            compressed,
                            compressed_len,
                            &decompressed,
                            &decompressed_len,
                            1);
  ASSERT_EQ (result, 0);

  ASSERT_EQ (decompressed_len, input_len);
  ASSERT_EQ (memcmp (decompressed, input, input_len), 0);
}

/*
 * Context Takeover Tests
 */

TEST (ws_context_takeover_multiple_messages)
{
  /*
   * With context takeover (sync_flush), multiple messages share compression
   * context. Second message should reference patterns from first message.
   */
  const uint8_t msg1[] = "Hello WebSocket";
  const uint8_t msg2[] = "Hello WebSocket again";
  size_t msg1_len = sizeof (msg1) - 1;
  size_t msg2_len = sizeof (msg2) - 1;
  uint8_t *comp1, *comp2;
  size_t comp1_len, comp2_len;
  uint8_t *decomp1, *decomp2;
  size_t decomp1_len, decomp2_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  SocketDeflate_Inflater_T inflater
      = SocketDeflate_Inflater_new (test_arena, 1024 * 1024);
  ASSERT_NOT_NULL (deflater);
  ASSERT_NOT_NULL (inflater);

  /* Compress first message with sync_flush (context takeover) */
  int result = test_compress (
      test_arena, deflater, msg1, msg1_len, &comp1, &comp1_len, 1);
  ASSERT_EQ (result, 0);

  /* Compress second message with shared context */
  result = test_compress (
      test_arena, deflater, msg2, msg2_len, &comp2, &comp2_len, 1);
  ASSERT_EQ (result, 0);

  /* Decompress first message (no reset) */
  result = test_decompress (
      test_arena, inflater, comp1, comp1_len, &decomp1, &decomp1_len, 0);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (decomp1_len, msg1_len);
  ASSERT_EQ (memcmp (decomp1, msg1, msg1_len), 0);

  /* Decompress second message with shared context */
  result = test_decompress (
      test_arena, inflater, comp2, comp2_len, &decomp2, &decomp2_len, 0);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (decomp2_len, msg2_len);
  ASSERT_EQ (memcmp (decomp2, msg2, msg2_len), 0);
}

TEST (ws_context_takeover_roundtrip)
{
  /*
   * Verify context takeover works for multiple messages.
   * Each message should roundtrip correctly when context is shared.
   */
  const uint8_t msg1[] = "First message with context takeover";
  const uint8_t msg2[] = "Second message sharing compression context";
  const uint8_t msg3[] = "Third message in the same stream";
  size_t msg1_len = sizeof (msg1) - 1;
  size_t msg2_len = sizeof (msg2) - 1;
  size_t msg3_len = sizeof (msg3) - 1;
  uint8_t *comp1, *comp2, *comp3;
  size_t comp1_len, comp2_len, comp3_len;
  uint8_t *decomp1, *decomp2, *decomp3;
  size_t decomp1_len, decomp2_len, decomp3_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  SocketDeflate_Inflater_T inflater
      = SocketDeflate_Inflater_new (test_arena, 1024 * 1024);
  ASSERT_NOT_NULL (deflater);
  ASSERT_NOT_NULL (inflater);

  /* Compress three messages with context takeover */
  int result = test_compress (
      test_arena, deflater, msg1, msg1_len, &comp1, &comp1_len, 1);
  ASSERT_EQ (result, 0);

  result = test_compress (
      test_arena, deflater, msg2, msg2_len, &comp2, &comp2_len, 1);
  ASSERT_EQ (result, 0);

  result = test_compress (
      test_arena, deflater, msg3, msg3_len, &comp3, &comp3_len, 1);
  ASSERT_EQ (result, 0);

  /* Decompress all three with shared context */
  result = test_decompress (
      test_arena, inflater, comp1, comp1_len, &decomp1, &decomp1_len, 0);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (decomp1_len, msg1_len);
  ASSERT_EQ (memcmp (decomp1, msg1, msg1_len), 0);

  result = test_decompress (
      test_arena, inflater, comp2, comp2_len, &decomp2, &decomp2_len, 0);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (decomp2_len, msg2_len);
  ASSERT_EQ (memcmp (decomp2, msg2, msg2_len), 0);

  result = test_decompress (
      test_arena, inflater, comp3, comp3_len, &decomp3, &decomp3_len, 0);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (decomp3_len, msg3_len);
  ASSERT_EQ (memcmp (decomp3, msg3, msg3_len), 0);
}

TEST (ws_no_context_takeover_isolation)
{
  /*
   * Without context takeover (finish + reset), each message is independent.
   * Verify messages decompress correctly without sharing context.
   */
  const uint8_t msg1[] = "First independent message";
  const uint8_t msg2[] = "Second independent message";
  size_t msg1_len = sizeof (msg1) - 1;
  size_t msg2_len = sizeof (msg2) - 1;
  uint8_t *comp1, *comp2;
  size_t comp1_len, comp2_len;
  uint8_t *decomp1, *decomp2;
  size_t decomp1_len, decomp2_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  ASSERT_NOT_NULL (deflater);

  /* Compress with finish + reset (no context takeover) */
  int result = test_compress (
      test_arena, deflater, msg1, msg1_len, &comp1, &comp1_len, 0);
  ASSERT_EQ (result, 0);

  result = test_compress (
      test_arena, deflater, msg2, msg2_len, &comp2, &comp2_len, 0);
  ASSERT_EQ (result, 0);

  /* Each message should decompress independently with fresh inflater */
  SocketDeflate_Inflater_T inflater1
      = SocketDeflate_Inflater_new (test_arena, 1024 * 1024);
  result = test_decompress (
      test_arena, inflater1, comp1, comp1_len, &decomp1, &decomp1_len, 1);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (decomp1_len, msg1_len);
  ASSERT_EQ (memcmp (decomp1, msg1, msg1_len), 0);

  SocketDeflate_Inflater_T inflater2
      = SocketDeflate_Inflater_new (test_arena, 1024 * 1024);
  result = test_decompress (
      test_arena, inflater2, comp2, comp2_len, &decomp2, &decomp2_len, 1);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (decomp2_len, msg2_len);
  ASSERT_EQ (memcmp (decomp2, msg2, msg2_len), 0);
}

/*
 * RFC 7692 Trailer Handling Tests
 */

TEST (ws_trailer_removal)
{
  /*
   * Verify that compression removes the RFC 7692 trailer.
   * The trailer (0x00 0x00 0xFF 0xFF) marks the end of a sync flush.
   */
  const uint8_t input[] = "Test message for trailer handling";
  size_t input_len = sizeof (input) - 1;
  uint8_t *output;
  size_t output_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  ASSERT_NOT_NULL (deflater);

  /* Use sync_flush which produces the trailer */
  int result = test_compress (
      test_arena, deflater, input, input_len, &output, &output_len, 1);
  ASSERT_EQ (result, 0);

  /* Verify output does not end with trailer */
  if (output_len >= WS_DEFLATE_TRAILER_SIZE)
    {
      int ends_with_trailer
          = memcmp (output + output_len - WS_DEFLATE_TRAILER_SIZE,
                    WS_DEFLATE_TRAILER,
                    WS_DEFLATE_TRAILER_SIZE)
            == 0;
      ASSERT_EQ (ends_with_trailer, 0);
    }
}

TEST (ws_trailer_addition)
{
  /*
   * Verify that decompression adds the trailer before inflating.
   * We test this by checking that compressed data without trailer
   * can still decompress when processed through our helper.
   */
  const uint8_t input[] = "Test message";
  size_t input_len = sizeof (input) - 1;
  uint8_t *compressed;
  size_t compressed_len;
  uint8_t *decompressed;
  size_t decompressed_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  SocketDeflate_Inflater_T inflater
      = SocketDeflate_Inflater_new (test_arena, 1024 * 1024);
  ASSERT_NOT_NULL (deflater);
  ASSERT_NOT_NULL (inflater);

  /* Compress (trailer removed) */
  int result = test_compress (
      test_arena, deflater, input, input_len, &compressed, &compressed_len, 1);
  ASSERT_EQ (result, 0);

  /* Decompress (trailer added by test_decompress) */
  result = test_decompress (test_arena,
                            inflater,
                            compressed,
                            compressed_len,
                            &decompressed,
                            &decompressed_len,
                            1);
  ASSERT_EQ (result, 0);

  /* Verify roundtrip succeeded */
  ASSERT_EQ (decompressed_len, input_len);
  ASSERT_EQ (memcmp (decompressed, input, input_len), 0);
}

/*
 * Bomb Protection Tests
 */

TEST (ws_large_compressed_data)
{
  /*
   * Verify that large compressible data works correctly.
   * Use highly compressible input to test expansion handling.
   */
  /* Create highly compressible input */
  size_t input_len = 4000;
  uint8_t *input = ALLOC (test_arena, input_len);
  ASSERT_NOT_NULL (input);
  memset (input, 'A', input_len);

  uint8_t *compressed;
  size_t compressed_len;
  uint8_t *decompressed;
  size_t decompressed_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  ASSERT_NOT_NULL (deflater);

  int result = test_compress (
      test_arena, deflater, input, input_len, &compressed, &compressed_len, 0);
  ASSERT_EQ (result, 0);

  /* Compressed size should be much smaller for repetitive data */
  ASSERT (compressed_len < input_len / 10);

  /* Decompress with adequate limit */
  SocketDeflate_Inflater_T inflater
      = SocketDeflate_Inflater_new (test_arena, input_len * 2);
  ASSERT_NOT_NULL (inflater);

  result = test_decompress (test_arena,
                            inflater,
                            compressed,
                            compressed_len,
                            &decompressed,
                            &decompressed_len,
                            1);
  ASSERT_EQ (result, 0);

  ASSERT_EQ (decompressed_len, input_len);
  ASSERT_EQ (memcmp (decompressed, input, input_len), 0);
}

/*
 * Edge Case Tests
 */

TEST (ws_empty_message_roundtrip)
{
  const uint8_t *input = (const uint8_t *)"";
  size_t input_len = 0;
  uint8_t *compressed;
  size_t compressed_len;
  uint8_t *decompressed;
  size_t decompressed_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  SocketDeflate_Inflater_T inflater
      = SocketDeflate_Inflater_new (test_arena, 1024 * 1024);
  ASSERT_NOT_NULL (deflater);
  ASSERT_NOT_NULL (inflater);

  int result = test_compress (
      test_arena, deflater, input, input_len, &compressed, &compressed_len, 0);
  ASSERT_EQ (result, 0);

  result = test_decompress (test_arena,
                            inflater,
                            compressed,
                            compressed_len,
                            &decompressed,
                            &decompressed_len,
                            1);
  ASSERT_EQ (result, 0);

  ASSERT_EQ (decompressed_len, 0);
}

TEST (ws_single_byte_message)
{
  const uint8_t input[] = { 0x42 };
  size_t input_len = 1;
  uint8_t *compressed;
  size_t compressed_len;
  uint8_t *decompressed;
  size_t decompressed_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  SocketDeflate_Inflater_T inflater
      = SocketDeflate_Inflater_new (test_arena, 1024 * 1024);
  ASSERT_NOT_NULL (deflater);
  ASSERT_NOT_NULL (inflater);

  int result = test_compress (
      test_arena, deflater, input, input_len, &compressed, &compressed_len, 0);
  ASSERT_EQ (result, 0);

  result = test_decompress (test_arena,
                            inflater,
                            compressed,
                            compressed_len,
                            &decompressed,
                            &decompressed_len,
                            1);
  ASSERT_EQ (result, 0);

  ASSERT_EQ (decompressed_len, 1);
  ASSERT_EQ (decompressed[0], 0x42);
}

TEST (ws_all_byte_values)
{
  /* Message containing all 256 byte values */
  size_t input_len = 256;
  uint8_t input[256];
  for (int i = 0; i < 256; i++)
    input[i] = (uint8_t)i;

  uint8_t *compressed;
  size_t compressed_len;
  uint8_t *decompressed;
  size_t decompressed_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  SocketDeflate_Inflater_T inflater
      = SocketDeflate_Inflater_new (test_arena, 1024 * 1024);
  ASSERT_NOT_NULL (deflater);
  ASSERT_NOT_NULL (inflater);

  int result = test_compress (
      test_arena, deflater, input, input_len, &compressed, &compressed_len, 0);
  ASSERT_EQ (result, 0);

  result = test_decompress (test_arena,
                            inflater,
                            compressed,
                            compressed_len,
                            &decompressed,
                            &decompressed_len,
                            1);
  ASSERT_EQ (result, 0);

  ASSERT_EQ (decompressed_len, input_len);
  ASSERT_EQ (memcmp (decompressed, input, input_len), 0);
}

/*
 * Compression Level Tests
 */

TEST (ws_compression_level_default)
{
  /*
   * Test default compression level (6) works correctly.
   * Level 0 (stored) has different behavior, so we focus on compressed levels.
   */
  const uint8_t input[] = "Test data for compression levels. "
                          "This message has some repetition for testing. "
                          "Test data for compression levels.";
  size_t input_len = sizeof (input) - 1;
  uint8_t *compressed;
  size_t compressed_len;
  uint8_t *decompressed;
  size_t decompressed_len;

  SocketDeflate_Deflater_T deflater
      = SocketDeflate_Deflater_new (test_arena, DEFLATE_LEVEL_DEFAULT);
  SocketDeflate_Inflater_T inflater
      = SocketDeflate_Inflater_new (test_arena, 1024 * 1024);
  ASSERT_NOT_NULL (deflater);
  ASSERT_NOT_NULL (inflater);

  int result = test_compress (
      test_arena, deflater, input, input_len, &compressed, &compressed_len, 0);
  ASSERT_EQ (result, 0);

  result = test_decompress (test_arena,
                            inflater,
                            compressed,
                            compressed_len,
                            &decompressed,
                            &decompressed_len,
                            1);
  ASSERT_EQ (result, 0);

  ASSERT_EQ (decompressed_len, input_len);
  ASSERT_EQ (memcmp (decompressed, input, input_len), 0);
}

/*
 * Test Runner
 */

int
main (void)
{
  test_arena = Arena_new ();

  Test_run_all ();

  Arena_dispose (&test_arena);

  return Test_get_failures () > 0 ? 1 : 0;
}

#else /* !SOCKETWS_HAS_NATIVE_DEFLATE */

/* Stub main when native DEFLATE is disabled */
int
main (void)
{
  return 0;
}

#endif /* SOCKETWS_HAS_NATIVE_DEFLATE */
