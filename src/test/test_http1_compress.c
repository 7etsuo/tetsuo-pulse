/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_http1_compress.c - HTTP/1.1 Content-Encoding compression tests
 *
 * Tests for native DEFLATE integration with HTTP compression layer:
 * - gzip encode/decode with CRC verification
 * - deflate encode/decode (raw and zlib-wrapped)
 * - streaming decompression
 * - decompression bomb protection
 * - truncated stream handling
 * - trailer verification
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/Arena.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "test/Test.h"

#if SOCKETHTTP1_HAS_COMPRESSION

static Arena_T test_arena;

/* Test data */
static const char hello_plaintext[] = "Hello, World!";
static const size_t hello_plaintext_len = 13;

/* zlib-wrapped DEFLATE "Hello, World!" - for testing auto-detection */
static const uint8_t zlib_hello[]
    = { 0x78, 0x9c, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf,
        0x2f, 0xca, 0x49, 0x51, 0x04, 0x00, 0x1f, 0x9e, 0x04, 0x6a };
static const size_t zlib_hello_len = sizeof (zlib_hello);

/*
 * Helper: Encode data with specified coding
 */
static ssize_t
encode_data (SocketHTTP_Coding coding,
             SocketHTTP1_CompressLevel level,
             const void *input,
             size_t input_len,
             uint8_t *output,
             size_t output_len)
{
  SocketHTTP1_Encoder_T encoder;
  ssize_t enc_len, finish_len;

  encoder = SocketHTTP1_Encoder_new (coding, level, NULL, test_arena);
  if (!encoder)
    return -1;

  enc_len = SocketHTTP1_Encoder_encode (
      encoder, input, input_len, output, output_len, 1);
  if (enc_len < 0)
    {
      SocketHTTP1_Encoder_free (&encoder);
      return -1;
    }

  finish_len = SocketHTTP1_Encoder_finish (
      encoder, output + enc_len, output_len - enc_len);
  SocketHTTP1_Encoder_free (&encoder);

  if (finish_len < 0)
    return -1;

  return enc_len + finish_len;
}

/*
 * Helper: Decode data with specified coding
 */
static SocketHTTP1_Result
decode_data (SocketHTTP_Coding coding,
             const void *input,
             size_t input_len,
             uint8_t *output,
             size_t output_len,
             size_t *written_out)
{
  SocketHTTP1_Decoder_T decoder;
  SocketHTTP1_Result res;
  size_t consumed, written, total = 0;

  decoder = SocketHTTP1_Decoder_new (coding, NULL, test_arena);
  if (!decoder)
    return HTTP1_ERROR;

  res = SocketHTTP1_Decoder_decode (
      decoder, input, input_len, &consumed, output, output_len, &written);
  total = written;

  if (res == HTTP1_INCOMPLETE)
    {
      size_t finish_written = 0;
      res = SocketHTTP1_Decoder_finish (
          decoder, output + total, output_len - total, &finish_written);
      total += finish_written;
    }

  SocketHTTP1_Decoder_free (&decoder);
  *written_out = total;
  return res;
}

/*
 * Helper: Decode multi-member data with proper streaming loop.
 *
 * Calls decode() repeatedly until all input is consumed, accumulating
 * output from each member.
 */
static SocketHTTP1_Result
decode_data_streaming (SocketHTTP_Coding coding,
                       const void *input,
                       size_t input_len,
                       uint8_t *output,
                       size_t output_len,
                       size_t *written_out)
{
  SocketHTTP1_Decoder_T decoder;
  SocketHTTP1_Result res;
  const uint8_t *in_ptr = input;
  size_t in_remain = input_len;
  uint8_t *out_ptr = output;
  size_t out_remain = output_len;
  size_t total_written = 0;
  int iterations = 0;

  decoder = SocketHTTP1_Decoder_new (coding, NULL, test_arena);
  if (!decoder)
    return HTTP1_ERROR;

  /* Keep decoding until done or error */
  while (iterations < 100)
    {
      size_t consumed = 0, written = 0;
      res = SocketHTTP1_Decoder_decode (
          decoder, in_ptr, in_remain, &consumed, out_ptr, out_remain, &written);

      in_ptr += consumed;
      in_remain -= consumed;
      out_ptr += written;
      out_remain -= written;
      total_written += written;
      iterations++;

      if (res == HTTP1_OK)
        break;
      if (res != HTTP1_INCOMPLETE)
        break;

      /* No progress and all input consumed - try finish */
      if (consumed == 0 && written == 0 && in_remain == 0)
        {
          size_t finish_written = 0;
          res = SocketHTTP1_Decoder_finish (
              decoder, out_ptr, out_remain, &finish_written);
          total_written += finish_written;
          break;
        }

      /* No progress but input remains - might need more output space */
      if (consumed == 0 && written == 0)
        break;
    }

  SocketHTTP1_Decoder_free (&decoder);
  *written_out = total_written;
  return res;
}

/*
 * gzip Roundtrip Test
 */
TEST (http_gzip_roundtrip)
{
  uint8_t compressed[512];
  uint8_t decompressed[256];
  ssize_t enc_len;
  size_t dec_len;
  SocketHTTP1_Result res;

  const char test_data[] = "This is a test message for gzip roundtrip testing.";
  size_t test_len = strlen (test_data);

  enc_len = encode_data (HTTP_CODING_GZIP,
                         HTTP1_COMPRESS_DEFAULT,
                         test_data,
                         test_len,
                         compressed,
                         sizeof (compressed));
  ASSERT (enc_len > 0);

  res = decode_data (HTTP_CODING_GZIP,
                     compressed,
                     enc_len,
                     decompressed,
                     sizeof (decompressed),
                     &dec_len);

  ASSERT_EQ (res, HTTP1_OK);
  ASSERT_EQ (dec_len, test_len);
  ASSERT (memcmp (decompressed, test_data, test_len) == 0);
}

/*
 * deflate Roundtrip Test
 */
TEST (http_deflate_roundtrip)
{
  uint8_t compressed[512];
  uint8_t decompressed[256];
  ssize_t enc_len;
  size_t dec_len;
  SocketHTTP1_Result res;

  const char test_data[] = "Deflate roundtrip test with repeated data. "
                           "Repeated data should compress well. "
                           "Repeated data should compress well.";
  size_t test_len = strlen (test_data);

  enc_len = encode_data (HTTP_CODING_DEFLATE,
                         HTTP1_COMPRESS_DEFAULT,
                         test_data,
                         test_len,
                         compressed,
                         sizeof (compressed));
  ASSERT (enc_len > 0);

  res = decode_data (HTTP_CODING_DEFLATE,
                     compressed,
                     enc_len,
                     decompressed,
                     sizeof (decompressed),
                     &dec_len);

  ASSERT_EQ (res, HTTP1_OK);
  ASSERT_EQ (dec_len, test_len);
  ASSERT (memcmp (decompressed, test_data, test_len) == 0);
}

/*
 * zlib-Wrapped Auto-Detection Test
 *
 * Per RFC 2616, Content-Encoding: deflate should be raw DEFLATE,
 * but many servers incorrectly send zlib-wrapped data.
 * Our decoder should auto-detect and handle both.
 */
TEST (http_deflate_zlib_wrapped)
{
  uint8_t output[256];
  size_t written;
  SocketHTTP1_Result res;

  /* Decode pre-compressed zlib-wrapped data */
  res = decode_data (HTTP_CODING_DEFLATE,
                     zlib_hello,
                     zlib_hello_len,
                     output,
                     sizeof (output),
                     &written);

  ASSERT_EQ (res, HTTP1_OK);
  ASSERT_EQ (written, hello_plaintext_len);
  ASSERT (memcmp (output, hello_plaintext, hello_plaintext_len) == 0);
}

/*
 * gzip Streaming Decode Test
 */
TEST (http_gzip_streaming)
{
  SocketHTTP1_Encoder_T encoder;
  SocketHTTP1_Decoder_T decoder;
  uint8_t compressed[256];
  uint8_t output[256];
  size_t total_written = 0;
  ssize_t enc_len;
  SocketHTTP1_Result res;

  /* Encode test data */
  enc_len = encode_data (HTTP_CODING_GZIP,
                         HTTP1_COMPRESS_FAST,
                         hello_plaintext,
                         hello_plaintext_len,
                         compressed,
                         sizeof (compressed));
  ASSERT (enc_len > 0);

  /* Decode incrementally - simulating streaming data arrival */
  decoder = SocketHTTP1_Decoder_new (HTTP_CODING_GZIP, NULL, test_arena);
  ASSERT (decoder != NULL);

  size_t available = 0;
  size_t total_consumed = 0;
  int iterations = 0;

  while (iterations < 100)
    {
      /* "Receive" 16 more bytes */
      if (available < (size_t)enc_len)
        {
          size_t chunk = (size_t)enc_len - available;
          if (chunk > 16)
            chunk = 16;
          available += chunk;
        }

      size_t consumed = 0;
      size_t written = 0;

      res = SocketHTTP1_Decoder_decode (decoder,
                                        compressed + total_consumed,
                                        available - total_consumed,
                                        &consumed,
                                        output + total_written,
                                        sizeof (output) - total_written,
                                        &written);

      total_consumed += consumed;
      total_written += written;
      iterations++;

      if (res == HTTP1_OK)
        break;
      if (res != HTTP1_INCOMPLETE)
        break;

      /* Break if no progress with all data available */
      if (consumed == 0 && written == 0 && available >= (size_t)enc_len)
        break;
    }

  /* Finish */
  size_t finish_written = 0;
  res = SocketHTTP1_Decoder_finish (decoder,
                                    output + total_written,
                                    sizeof (output) - total_written,
                                    &finish_written);
  total_written += finish_written;

  SocketHTTP1_Decoder_free (&decoder);

  ASSERT_EQ (res, HTTP1_OK);
  ASSERT_EQ (total_written, hello_plaintext_len);
  ASSERT (memcmp (output, hello_plaintext, hello_plaintext_len) == 0);
}

/*
 * Small Output Buffer Test
 */
TEST (http_small_output_buffer)
{
  uint8_t compressed[256];
  uint8_t output[4]; /* Small buffer */
  uint8_t full_output[256];
  ssize_t enc_len;
  size_t total_written = 0;
  size_t total_consumed = 0;

  /* Encode */
  enc_len = encode_data (HTTP_CODING_GZIP,
                         HTTP1_COMPRESS_FAST,
                         hello_plaintext,
                         hello_plaintext_len,
                         compressed,
                         sizeof (compressed));
  ASSERT (enc_len > 0);

  /* Decode with tiny output buffer */
  SocketHTTP1_Decoder_T decoder
      = SocketHTTP1_Decoder_new (HTTP_CODING_GZIP, NULL, test_arena);
  ASSERT (decoder != NULL);

  SocketHTTP1_Result res;
  int iterations = 0;

  while (total_consumed < (size_t)enc_len && iterations < 100)
    {
      size_t consumed = 0, written = 0;

      res = SocketHTTP1_Decoder_decode (decoder,
                                        compressed + total_consumed,
                                        enc_len - total_consumed,
                                        &consumed,
                                        output,
                                        sizeof (output),
                                        &written);

      if (written > 0)
        {
          memcpy (full_output + total_written, output, written);
          total_written += written;
        }
      total_consumed += consumed;
      iterations++;

      if (res == HTTP1_OK)
        break;
      if (res != HTTP1_INCOMPLETE)
        break;
    }

  /* Finish */
  size_t finish_written = 0;
  res = SocketHTTP1_Decoder_finish (decoder,
                                    full_output + total_written,
                                    sizeof (full_output) - total_written,
                                    &finish_written);
  total_written += finish_written;

  SocketHTTP1_Decoder_free (&decoder);

  ASSERT_EQ (res, HTTP1_OK);
  ASSERT_EQ (total_written, hello_plaintext_len);
  ASSERT (memcmp (full_output, hello_plaintext, hello_plaintext_len) == 0);
}

/*
 * Compression Levels Test
 */
TEST (http_compression_levels)
{
  const char test_data[] = "Test data for compression level comparison. "
                           "This message should be compressed at different "
                           "levels to verify the encoder respects the setting.";
  size_t test_len = strlen (test_data);

  SocketHTTP1_CompressLevel levels[]
      = { HTTP1_COMPRESS_FAST, HTTP1_COMPRESS_DEFAULT, HTTP1_COMPRESS_BEST };

  for (size_t i = 0; i < sizeof (levels) / sizeof (levels[0]); i++)
    {
      uint8_t compressed[512];
      ssize_t enc_len;

      enc_len = encode_data (HTTP_CODING_GZIP,
                             levels[i],
                             test_data,
                             test_len,
                             compressed,
                             sizeof (compressed));
      ASSERT (enc_len > 0);
    }
}

/*
 * Decompression Bomb Protection Test
 *
 * The decoder should reject compressed data that would expand
 * beyond the configured max_decompressed_size.
 */
TEST (http_bomb_protection)
{
  SocketHTTP1_Config cfg;
  SocketHTTP1_Decoder_T decoder;
  uint8_t compressed[512];
  uint8_t output[256];
  ssize_t enc_len;
  size_t consumed, written;
  SocketHTTP1_Result res;

  /* Create a compressible test string (lots of repetition) */
  char bomb_input[4096];
  memset (bomb_input, 'A', sizeof (bomb_input));
  bomb_input[sizeof (bomb_input) - 1] = '\0';

  /* Compress it */
  enc_len = encode_data (HTTP_CODING_GZIP,
                         HTTP1_COMPRESS_BEST,
                         bomb_input,
                         sizeof (bomb_input) - 1,
                         compressed,
                         sizeof (compressed));
  ASSERT (enc_len > 0);

  /* Try to decode with a very small max size */
  SocketHTTP1_config_defaults (&cfg);
  cfg.max_decompressed_size = 100; /* Much smaller than actual size */

  decoder = SocketHTTP1_Decoder_new (HTTP_CODING_GZIP, &cfg, test_arena);
  ASSERT (decoder != NULL);

  res = SocketHTTP1_Decoder_decode (decoder,
                                    compressed,
                                    enc_len,
                                    &consumed,
                                    output,
                                    sizeof (output),
                                    &written);

  SocketHTTP1_Decoder_free (&decoder);

  /* Should return error when bomb detected */
  ASSERT (res == HTTP1_ERROR_BODY_TOO_LARGE || res == HTTP1_ERROR);
}

/*
 * Truncated gzip Stream Test
 *
 * Decoder should return INCOMPLETE when given truncated data.
 */
TEST (http_truncated_gzip)
{
  uint8_t compressed[256];
  uint8_t output[256];
  ssize_t enc_len;
  size_t consumed, written;
  SocketHTTP1_Result res;

  /* Compress some data */
  enc_len = encode_data (HTTP_CODING_GZIP,
                         HTTP1_COMPRESS_FAST,
                         hello_plaintext,
                         hello_plaintext_len,
                         compressed,
                         sizeof (compressed));
  ASSERT (enc_len > 10); /* Must have header + data + trailer */

  /* Try decoding with truncated input (cut off trailer) */
  SocketHTTP1_Decoder_T decoder
      = SocketHTTP1_Decoder_new (HTTP_CODING_GZIP, NULL, test_arena);
  ASSERT (decoder != NULL);

  /* Only provide header + partial data (missing trailer) */
  size_t truncated_len = enc_len - 8; /* Remove trailer */

  res = SocketHTTP1_Decoder_decode (decoder,
                                    compressed,
                                    truncated_len,
                                    &consumed,
                                    output,
                                    sizeof (output),
                                    &written);

  /* Should be incomplete since trailer is missing */
  if (res == HTTP1_INCOMPLETE)
    {
      size_t finish_written = 0;
      res = SocketHTTP1_Decoder_finish (decoder,
                                        output + written,
                                        sizeof (output) - written,
                                        &finish_written);
      /* finish should also return incomplete without trailer */
      ASSERT (res == HTTP1_INCOMPLETE);
    }

  SocketHTTP1_Decoder_free (&decoder);
}

/*
 * gzip CRC Verification Test
 *
 * Verify that corrupted data is detected via CRC check.
 */
TEST (http_gzip_crc_verification)
{
  uint8_t compressed[256];
  uint8_t output[256];
  ssize_t enc_len;
  size_t written;
  SocketHTTP1_Result res;

  /* Compress some data */
  enc_len = encode_data (HTTP_CODING_GZIP,
                         HTTP1_COMPRESS_FAST,
                         hello_plaintext,
                         hello_plaintext_len,
                         compressed,
                         sizeof (compressed));
  ASSERT (enc_len > 0);

  /* Corrupt a byte in the compressed data (not header or trailer) */
  if (enc_len > 15)
    compressed[12] ^= 0xFF; /* Flip bits in compressed payload */

  /* Try to decode - should fail due to corruption */
  res = decode_data (
      HTTP_CODING_GZIP, compressed, enc_len, output, sizeof (output), &written);

  /* Corruption should cause either CRC mismatch or inflate error */
  ASSERT (res != HTTP1_OK);
}

/*
 * Empty gzip Stream Test
 */
TEST (http_empty_gzip)
{
  uint8_t compressed[256];
  uint8_t output[256];
  ssize_t enc_len;
  size_t written;
  SocketHTTP1_Result res;

  /* Compress empty data */
  enc_len = encode_data (HTTP_CODING_GZIP,
                         HTTP1_COMPRESS_FAST,
                         "",
                         0,
                         compressed,
                         sizeof (compressed));
  ASSERT (enc_len > 0); /* Header + empty block + trailer */

  /* Decode it */
  res = decode_data (
      HTTP_CODING_GZIP, compressed, enc_len, output, sizeof (output), &written);

  ASSERT_EQ (res, HTTP1_OK);
  ASSERT_EQ (written, 0);
}

/*
 * Empty deflate Stream Test
 */
TEST (http_empty_deflate)
{
  uint8_t compressed[256];
  uint8_t output[256];
  ssize_t enc_len;
  size_t written;
  SocketHTTP1_Result res;

  /* Compress empty data */
  enc_len = encode_data (HTTP_CODING_DEFLATE,
                         HTTP1_COMPRESS_FAST,
                         "",
                         0,
                         compressed,
                         sizeof (compressed));
  ASSERT (enc_len
          > 0); /* Empty block only (no header/trailer for raw deflate) */

  /* Decode it */
  res = decode_data (HTTP_CODING_DEFLATE,
                     compressed,
                     enc_len,
                     output,
                     sizeof (output),
                     &written);

  ASSERT_EQ (res, HTTP1_OK);
  ASSERT_EQ (written, 0);
}

/*
 * Multi-Member gzip: Two Members (RFC 1952 Section 2.2)
 *
 * Per RFC 1952: "A gzip file is a sequence of 'members'".
 * Members are concatenated with no delimiter between them.
 */
TEST (http_gzip_multi_member_two)
{
  uint8_t member1[256], member2[256], combined[512];
  uint8_t output[512];
  ssize_t len1, len2;
  size_t written;
  SocketHTTP1_Result res;

  const char data1[] = "First gzip member data.";
  const char data2[] = "Second gzip member data.";

  /* Encode two separate gzip streams */
  len1 = encode_data (HTTP_CODING_GZIP,
                      HTTP1_COMPRESS_FAST,
                      data1,
                      strlen (data1),
                      member1,
                      sizeof (member1));
  len2 = encode_data (HTTP_CODING_GZIP,
                      HTTP1_COMPRESS_FAST,
                      data2,
                      strlen (data2),
                      member2,
                      sizeof (member2));
  ASSERT (len1 > 0 && len2 > 0);

  /* Concatenate into multi-member stream */
  memcpy (combined, member1, len1);
  memcpy (combined + len1, member2, len2);

  /* Decode - should produce both outputs */
  res = decode_data_streaming (HTTP_CODING_GZIP,
                               combined,
                               len1 + len2,
                               output,
                               sizeof (output),
                               &written);

  ASSERT_EQ (res, HTTP1_OK);
  ASSERT_EQ (written, strlen (data1) + strlen (data2));
  ASSERT (memcmp (output, data1, strlen (data1)) == 0);
  ASSERT (memcmp (output + strlen (data1), data2, strlen (data2)) == 0);
}

/*
 * Multi-Member gzip: Three Members
 */
TEST (http_gzip_multi_member_three)
{
  uint8_t members[3][128];
  uint8_t combined[512];
  uint8_t output[512];
  ssize_t lens[3];
  size_t written, total_len = 0, total_expected = 0;
  SocketHTTP1_Result res;

  const char *data[] = { "AAA", "BBBBB", "CCCCCCC" };

  for (int i = 0; i < 3; i++)
    {
      lens[i] = encode_data (HTTP_CODING_GZIP,
                             HTTP1_COMPRESS_FAST,
                             data[i],
                             strlen (data[i]),
                             members[i],
                             128);
      ASSERT (lens[i] > 0);
      memcpy (combined + total_len, members[i], lens[i]);
      total_len += lens[i];
      total_expected += strlen (data[i]);
    }

  res = decode_data_streaming (
      HTTP_CODING_GZIP, combined, total_len, output, sizeof (output), &written);

  ASSERT_EQ (res, HTTP1_OK);
  ASSERT_EQ (written, total_expected);
  /* Verify concatenated output */
  ASSERT (memcmp (output, "AAABBBBBCCCCCCC", total_expected) == 0);
}

/*
 * Multi-Member gzip: Empty Member in the Middle
 *
 * Tests: gzip("Hello") + gzip("") + gzip("World")
 * Should decode to "HelloWorld"
 */
TEST (http_gzip_multi_member_with_empty)
{
  uint8_t member1[128], member2[128], member3[128];
  uint8_t combined[512];
  uint8_t output[256];
  ssize_t len1, len2, len3;
  size_t written;
  SocketHTTP1_Result res;

  const char *part1 = "Hello";
  const char *part2 = "";
  const char *part3 = "World";

  len1 = encode_data (HTTP_CODING_GZIP,
                      HTTP1_COMPRESS_FAST,
                      part1,
                      strlen (part1),
                      member1,
                      sizeof (member1));
  len2 = encode_data (HTTP_CODING_GZIP,
                      HTTP1_COMPRESS_FAST,
                      part2,
                      strlen (part2),
                      member2,
                      sizeof (member2));
  len3 = encode_data (HTTP_CODING_GZIP,
                      HTTP1_COMPRESS_FAST,
                      part3,
                      strlen (part3),
                      member3,
                      sizeof (member3));
  ASSERT (len1 > 0 && len2 > 0 && len3 > 0);

  /* Concatenate */
  size_t total_len = 0;
  memcpy (combined + total_len, member1, len1);
  total_len += len1;
  memcpy (combined + total_len, member2, len2);
  total_len += len2;
  memcpy (combined + total_len, member3, len3);
  total_len += len3;

  res = decode_data_streaming (
      HTTP_CODING_GZIP, combined, total_len, output, sizeof (output), &written);

  ASSERT_EQ (res, HTTP1_OK);
  ASSERT_EQ (written, strlen ("HelloWorld"));
  ASSERT (memcmp (output, "HelloWorld", strlen ("HelloWorld")) == 0);
}

/*
 * Multi-Member gzip: Small Chunk Streaming
 *
 * Tests streaming decode with small chunks to verify member
 * boundary handling works correctly.
 */
TEST (http_gzip_multi_member_streaming)
{
  SocketHTTP1_Decoder_T decoder;
  uint8_t member1[128], member2[128];
  uint8_t combined[256];
  uint8_t output[256];
  ssize_t len1, len2;
  size_t total_written = 0;
  size_t total_consumed = 0;
  size_t total_len;
  SocketHTTP1_Result res;

  const char *data1 = "Stream1";
  const char *data2 = "Stream2";

  len1 = encode_data (HTTP_CODING_GZIP,
                      HTTP1_COMPRESS_FAST,
                      data1,
                      strlen (data1),
                      member1,
                      sizeof (member1));
  len2 = encode_data (HTTP_CODING_GZIP,
                      HTTP1_COMPRESS_FAST,
                      data2,
                      strlen (data2),
                      member2,
                      sizeof (member2));
  ASSERT (len1 > 0 && len2 > 0);

  memcpy (combined, member1, len1);
  memcpy (combined + len1, member2, len2);
  total_len = len1 + len2;

  /* Decode with 16-byte chunks */
  decoder = SocketHTTP1_Decoder_new (HTTP_CODING_GZIP, NULL, test_arena);
  ASSERT (decoder != NULL);

  int iterations = 0;
  while (iterations < 100)
    {
      size_t chunk_size = 16;
      size_t available = total_consumed + chunk_size;
      if (available > total_len)
        available = total_len;

      size_t consumed = 0, written = 0;
      res = SocketHTTP1_Decoder_decode (decoder,
                                        combined + total_consumed,
                                        available - total_consumed,
                                        &consumed,
                                        output + total_written,
                                        sizeof (output) - total_written,
                                        &written);

      total_consumed += consumed;
      total_written += written;
      iterations++;

      if (res == HTTP1_OK)
        break;
      if (res != HTTP1_INCOMPLETE)
        break;

      /* Break if no progress with all data available */
      if (consumed == 0 && written == 0 && available >= total_len)
        {
          size_t finish_written = 0;
          res = SocketHTTP1_Decoder_finish (decoder,
                                            output + total_written,
                                            sizeof (output) - total_written,
                                            &finish_written);
          total_written += finish_written;
          break;
        }
    }

  SocketHTTP1_Decoder_free (&decoder);

  ASSERT_EQ (res, HTTP1_OK);
  ASSERT_EQ (total_written, strlen ("Stream1Stream2"));
  ASSERT (memcmp (output, "Stream1Stream2", total_written) == 0);
}

/*
 * Multi-Member gzip: CRC Error in Second Member
 *
 * Verifies that CRC errors are detected per-member, not just for the first.
 */
TEST (http_gzip_multi_member_crc_error_second)
{
  uint8_t member1[128], member2[128];
  uint8_t combined[256];
  uint8_t output[256];
  ssize_t len1, len2;
  size_t written;
  SocketHTTP1_Result res;

  const char *data1 = "First";
  const char *data2 = "Second";

  len1 = encode_data (HTTP_CODING_GZIP,
                      HTTP1_COMPRESS_FAST,
                      data1,
                      strlen (data1),
                      member1,
                      sizeof (member1));
  len2 = encode_data (HTTP_CODING_GZIP,
                      HTTP1_COMPRESS_FAST,
                      data2,
                      strlen (data2),
                      member2,
                      sizeof (member2));
  ASSERT (len1 > 0 && len2 > 0);

  /* Concatenate members */
  memcpy (combined, member1, len1);
  memcpy (combined + len1, member2, len2);

  /* Corrupt the second member's compressed data (not header or trailer) */
  if (len2 > 15)
    combined[len1 + 12] ^= 0xFF; /* Flip bits in member2's payload */

  /* Decode - should fail due to CRC mismatch in second member */
  res = decode_data_streaming (HTTP_CODING_GZIP,
                               combined,
                               len1 + len2,
                               output,
                               sizeof (output),
                               &written);

  /* Should error - either CRC mismatch or inflate error from corruption */
  ASSERT (res != HTTP1_OK);
}

/*
 * Multi-Member gzip: Truncated Second Member
 *
 * Verifies that a truncated multi-member stream returns INCOMPLETE,
 * not OK (which would indicate we stopped after first member).
 */
TEST (http_gzip_multi_member_truncated)
{
  uint8_t member1[128], member2[128];
  uint8_t combined[256];
  uint8_t output[256];
  ssize_t len1, len2;
  size_t written;
  SocketHTTP1_Result res;

  const char *data1 = "Complete";
  const char *data2 = "Truncated";

  len1 = encode_data (HTTP_CODING_GZIP,
                      HTTP1_COMPRESS_FAST,
                      data1,
                      strlen (data1),
                      member1,
                      sizeof (member1));
  len2 = encode_data (HTTP_CODING_GZIP,
                      HTTP1_COMPRESS_FAST,
                      data2,
                      strlen (data2),
                      member2,
                      sizeof (member2));
  ASSERT (len1 > 0 && len2 > 0);

  /* Concatenate member1 + partial member2 (just header, no data/trailer) */
  memcpy (combined, member1, len1);
  memcpy (combined + len1, member2, 10); /* Only gzip header (10 bytes) */

  /* Decode - should return INCOMPLETE because second member is truncated */
  res = decode_data_streaming (HTTP_CODING_GZIP,
                               combined,
                               len1 + 10, /* Truncated */
                               output,
                               sizeof (output),
                               &written);

  /* First member should decode, but we should get INCOMPLETE for truncated
   * second */
  ASSERT_EQ (res, HTTP1_INCOMPLETE);
  /* Should have decoded the first member's content */
  ASSERT_EQ (written, strlen (data1));
  ASSERT (memcmp (output, data1, strlen (data1)) == 0);
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

#else /* !SOCKETHTTP1_HAS_COMPRESSION */

int
main (void)
{
  /* Compression not enabled - skip tests */
  return 0;
}

#endif /* SOCKETHTTP1_HAS_COMPRESSION */
