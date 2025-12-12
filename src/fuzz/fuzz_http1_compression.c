/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_http1_compression.c - Comprehensive fuzzing harness for HTTP/1.1 compression
 *
 * Tests gzip, deflate, and brotli compression/decompression with malformed inputs
 * to find decompression bomb vulnerabilities, buffer overflows, and parsing errors.
 *
 * Targets:
 * - Decompression bomb protection
 * - Malformed compressed data handling
 * - Encoder/decoder state corruption
 * - Buffer overflow in compressed streams
 * - Memory exhaustion from expansion
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON -DENABLE_COMPRESSION=ON .. && make fuzz_http1_compression
 * ./fuzz_http1_compression corpus/http1_compression/ -fork=16 -max_len=65536
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if SOCKETHTTP1_HAS_COMPRESSION

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
  {
    Arena_T arena = NULL;
  SocketHTTP1_Encoder_T encoder = NULL;
  SocketHTTP1_Decoder_T decoder = NULL;
  unsigned char compress_buf[65536];
  unsigned char decompress_buf[131072]; /* 2x input for expansion */
  ssize_t encoded_len;
  size_t consumed, written;

  /* Skip empty input */
  if (size == 0 || size > 32768) /* Limit to reasonable size */
    return 0;

  arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
      SocketHTTP1_Config cfg;
      SocketHTTP1_config_defaults (&cfg);
      cfg.max_decompressed_size = 65536; /* Prevent decompression bombs */

      /* Test all supported compression algorithms */
      SocketHTTP_Coding codings[] = {
          HTTP_CODING_GZIP,
          HTTP_CODING_DEFLATE,
          HTTP_CODING_BR
      };

      for (size_t coding_idx = 0; coding_idx < sizeof (codings) / sizeof (codings[0]); coding_idx++)
      {
          SocketHTTP_Coding coding = codings[coding_idx];

          /* Test 1: Encoder with fuzzed input */
          encoder = SocketHTTP1_Encoder_new (coding, HTTP1_COMPRESS_DEFAULT, &cfg, arena);
          if (encoder)
          {
              /* Encode the fuzzed data */
              encoded_len = SocketHTTP1_Encoder_encode (encoder, data, size,
                                                        compress_buf, sizeof (compress_buf), 1);
              if (encoded_len > 0)
              {
                  /* Test incremental encoding */
                  size_t offset = 0;
                  while (offset < size)
                  {
                      size_t chunk = (size - offset) > 1024 ? 1024 : (size - offset);
                      SocketHTTP1_Encoder_encode (encoder, data + offset, chunk,
                                                  compress_buf, sizeof (compress_buf), 0);
                      offset += chunk;
                  }

                  /* Finish encoding */
                  SocketHTTP1_Encoder_finish (encoder, compress_buf, sizeof (compress_buf));
              }
              SocketHTTP1_Encoder_free (&encoder);
          }

          /* Test 2: Decoder with fuzzed compressed data */
          decoder = SocketHTTP1_Decoder_new (coding, &cfg, arena);
          if (decoder)
          {
              /* Try to decompress the fuzzed data as compressed stream */
              SocketHTTP1_Result result = SocketHTTP1_Decoder_decode (decoder, data, size, &consumed,
                                                                       decompress_buf, sizeof (decompress_buf), &written);
            (void)result;

              /* Test incremental decompression */
              if (size > 0)
              {
                  for (size_t offset = 0; offset < size; offset += (size / 8 + 1))
                  {
                      size_t chunk = (size - offset) > 2048 ? 2048 : (size - offset);
                      if (chunk > 0)
                          SocketHTTP1_Decoder_decode (decoder, data + offset, chunk, &consumed,
                                                      decompress_buf, sizeof (decompress_buf), &written);
                  }
              }

              /* Try to finish decompression */
              SocketHTTP1_Decoder_finish (decoder, decompress_buf, sizeof (decompress_buf), &written);

              SocketHTTP1_Decoder_free (&decoder);
          }

          /* Test 3: Decoder with valid compressed data followed by fuzz */
          if (size >= 10) /* Need minimum size for valid compressed data */
          {
              /* Create some valid compressed data first */
              encoder = SocketHTTP1_Encoder_new (coding, HTTP1_COMPRESS_DEFAULT, &cfg, arena);
              if (encoder)
              {
                  const char *test_data = "Hello World! This is test data for compression.";
                  encoded_len = SocketHTTP1_Encoder_encode (encoder, (const unsigned char *)test_data,
                                                            strlen (test_data), compress_buf,
                                                            sizeof (compress_buf), 1);
                  if (encoded_len > 0)
                  {
                      ssize_t finish_len = SocketHTTP1_Encoder_finish (encoder, compress_buf + encoded_len,
                                                                       sizeof (compress_buf) - encoded_len);

                      /* Now append fuzzed data and try to decompress */
                      if (finish_len > 0 && (size_t)encoded_len + (size_t)finish_len < sizeof (compress_buf))
                      {
                          size_t valid_size = encoded_len + finish_len;
                          size_t append_size = (size > sizeof (compress_buf) - valid_size) ?
                                               sizeof (compress_buf) - valid_size : size;

                          memcpy (compress_buf + valid_size, data, append_size);

                          decoder = SocketHTTP1_Decoder_new (coding, &cfg, arena);
                          if (decoder)
                          {
                              SocketHTTP1_Decoder_decode (decoder, compress_buf, valid_size + append_size,
                                                          &consumed, decompress_buf, sizeof (decompress_buf), &written);
                              SocketHTTP1_Decoder_free (&decoder);
                          }
                      }
                  }
                  SocketHTTP1_Encoder_free (&encoder);
              }
          }
      }

      /* Test 4: Edge cases with various compression levels */
      SocketHTTP1_CompressLevel levels[] = {
          HTTP1_COMPRESS_FAST,
          HTTP1_COMPRESS_DEFAULT,
          HTTP1_COMPRESS_BEST
      };

      for (size_t level_idx = 0; level_idx < sizeof (levels) / sizeof (SocketHTTP1_CompressLevel); level_idx++)
      {
          encoder = SocketHTTP1_Encoder_new (HTTP_CODING_GZIP, levels[level_idx], &cfg, arena);
          if (encoder)
          {
              SocketHTTP1_Encoder_encode (encoder, data, size > 1024 ? 1024 : size,
                                          compress_buf, sizeof (compress_buf), 1);
              SocketHTTP1_Encoder_finish (encoder, compress_buf, sizeof (compress_buf));
              SocketHTTP1_Encoder_free (&encoder);
          }
      }
  }
  EXCEPT (SocketHTTP1_ParseError)
  {
      /* Expected on malformed compressed data */
  }
  EXCEPT (SocketHTTP1_SerializeError)
  {
      /* Expected on encoding/serialization errors */
  }
  EXCEPT (Arena_Failed)
  {
      /* Expected on memory exhaustion */
  }
  FINALLY
  {
    Arena_dispose (&arena);
  }
  END_TRY;

  return 0;
}

#else /* !SOCKETHTTP1_HAS_COMPRESSION */

/* Stub fuzzer when compression is not available */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  (void)data;
  (void)size;
  return 0; /* No-op when compression disabled */
}

#endif /* SOCKETHTTP1_HAS_COMPRESSION */
