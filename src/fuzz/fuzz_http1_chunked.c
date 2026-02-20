/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_http1_chunked.c - Enterprise-grade HTTP/1.1 chunked encoding fuzzer
 *
 * Comprehensive fuzzing harness for HTTP/1.1 chunked transfer encoding
 * targeting all edge cases and attack vectors per RFC 9112 Section 7.1.
 *
 * Targets:
 * - Chunk size parsing (hex values, leading zeros, edge cases)
 * - Chunk data reading (exact length, boundary conditions)
 * - Chunk extensions parsing (name=value pairs)
 * - Trailer headers parsing and validation
 * - Final chunk (0\r\n) handling
 * - Incremental chunked body reading
 * - Chunk encoding output
 * - Malformed chunk rejection
 *
 * Security Focus:
 * - Integer overflow in chunk sizes
 * - Extremely large chunk sizes (DoS)
 * - Negative or invalid chunk sizes
 * - Chunk smuggling attacks
 * - Malformed CRLF sequences
 * - Extension injection
 * - Trailer header injection
 * - Buffer overflow prevention
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http1_chunked
 * ./fuzz_http1_chunked corpus/http1_chunked/ -fork=16 -max_len=65536
 */

#include <stdio.h>
#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Request prefix for chunked encoding tests */
static const char *chunked_request_prefix = "POST / HTTP/1.1\r\n"
                                            "Host: test.com\r\n"
                                            "Transfer-Encoding: chunked\r\n"
                                            "\r\n";

/* Request with trailer headers declared */
static const char *chunked_with_trailer_prefix
    = "POST / HTTP/1.1\r\n"
      "Host: test.com\r\n"
      "Transfer-Encoding: chunked\r\n"
      "Trailer: X-Checksum, X-Final-Status\r\n"
      "\r\n";

/**
 * Test chunked body reading with variable buffer sizes
 */
static void
test_chunked_reading (SocketHTTP1_Parser_T parser,
                      const char *body,
                      size_t body_len,
                      size_t buf_size)
{
  char body_buf[8192];
  size_t body_consumed, body_written;
  size_t total_consumed = 0;

  size_t actual_buf_size
      = buf_size > sizeof (body_buf) ? sizeof (body_buf) : buf_size;

  while (total_consumed < body_len
         && !SocketHTTP1_Parser_body_complete (parser))
    {
      size_t remaining = body_len - total_consumed;
      size_t to_read
          = remaining > actual_buf_size ? actual_buf_size : remaining;

      SocketHTTP1_Result result
          = SocketHTTP1_Parser_read_body (parser,
                                          body + total_consumed,
                                          to_read,
                                          &body_consumed,
                                          body_buf,
                                          actual_buf_size,
                                          &body_written);

      if (body_consumed == 0)
        break;

      total_consumed += body_consumed;
      (void)body_written;

      if (result != HTTP1_OK && result != HTTP1_INCOMPLETE)
        break;
    }
}

/**
 * Parse chunked request and read body
 */
static void
test_chunked_request (Arena_T arena,
                      const char *body_data,
                      size_t body_len,
                      const char *prefix,
                      int strict)
{
  SocketHTTP1_Config cfg;
  SocketHTTP1_config_defaults (&cfg);
  cfg.strict_mode = strict;

  SocketHTTP1_Parser_T parser
      = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, arena);
  if (!parser)
    return;

  /* Parse headers */
  size_t consumed;
  SocketHTTP1_Result result
      = SocketHTTP1_Parser_execute (parser, prefix, strlen (prefix), &consumed);

  if (result == HTTP1_OK)
    {
      /* Verify chunked body mode */
      SocketHTTP1_BodyMode mode = SocketHTTP1_Parser_body_mode (parser);
      if (mode == HTTP1_BODY_CHUNKED)
        {
          /* Read chunked body with various buffer sizes */
          test_chunked_reading (parser, body_data, body_len, 1);

          /* Reset and try with larger buffer */
          SocketHTTP1_Parser_reset (parser);
          SocketHTTP1_Parser_execute (
              parser, prefix, strlen (prefix), &consumed);
          test_chunked_reading (parser, body_data, body_len, 64);

          /* Reset and try with even larger buffer */
          SocketHTTP1_Parser_reset (parser);
          SocketHTTP1_Parser_execute (
              parser, prefix, strlen (prefix), &consumed);
          test_chunked_reading (parser, body_data, body_len, 4096);
        }
    }

  SocketHTTP1_Parser_free (&parser);
}

/**
 * Test chunk encoding function
 */
static void
test_chunk_encoding (const uint8_t *data, size_t size)
{
  char encode_buf[32768];

  /* Test encoding with various sizes */
  size_t test_sizes[] = { 0, 1, 10, 100, 1000, 4096, 8192 };

  for (size_t i = 0; i < sizeof (test_sizes) / sizeof (test_sizes[0]); i++)
    {
      size_t encode_size = test_sizes[i];
      if (encode_size > size)
        encode_size = size;

      /* Calculate required buffer size */
      size_t required = SocketHTTP1_chunk_encode_size (encode_size);
      if (required <= sizeof (encode_buf))
        {
          ssize_t encoded = SocketHTTP1_chunk_encode (
              data, encode_size, encode_buf, sizeof (encode_buf));
          (void)encoded;
        }
    }

  /* Test final chunk */
  ssize_t final_len
      = SocketHTTP1_chunk_final (encode_buf, sizeof (encode_buf), NULL);
  (void)final_len;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;

  /* Skip empty input */
  if (size == 0)
    return 0;

  arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    test_chunked_request (
        arena, (const char *)data, size, chunked_request_prefix, 0);
    test_chunked_request (
        arena, (const char *)data, size, chunked_request_prefix, 1);

    {
      const char *valid_chunked[] = {
        /* Single chunk */
        "5\r\nhello\r\n0\r\n\r\n",

        /* Multiple chunks */
        "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",

        /* Empty chunks (just final) */
        "0\r\n\r\n",

        /* Large hex sizes */
        "a\r\n0123456789\r\n0\r\n\r\n",
        "A\r\n0123456789\r\n0\r\n\r\n",
        "f\r\n012345678901234\r\n0\r\n\r\n",
        "F\r\n012345678901234\r\n0\r\n\r\n",
        "10\r\n0123456789abcdef\r\n0\r\n\r\n",

        /* Chunk with extension */
        "5;ext=value\r\nhello\r\n0\r\n\r\n",
        "5;ext1=val1;ext2=val2\r\nhello\r\n0\r\n\r\n",
        "5;ext\r\nhello\r\n0\r\n\r\n",

        /* Final chunk with extension */
        "5\r\nhello\r\n0;final=true\r\n\r\n",

        /* Trailers */
        "5\r\nhello\r\n0\r\nX-Checksum: abc123\r\n\r\n",
        "5\r\nhello\r\n0\r\nX-Checksum: abc123\r\nX-Final: done\r\n\r\n",

        /* Leading zeros in size */
        "005\r\nhello\r\n0\r\n\r\n",
        "00005\r\nhello\r\n0\r\n\r\n",

        /* Mixed case hex */
        "aB\r\n"
        "01234567890"
        "\r\n0\r\n\r\n",

        /* Many small chunks */
        "1\r\na\r\n1\r\nb\r\n1\r\nc\r\n1\r\nd\r\n1\r\ne\r\n0\r\n\r\n",
      };

      for (size_t i = 0; i < sizeof (valid_chunked) / sizeof (valid_chunked[0]);
           i++)
        {
          test_chunked_request (arena,
                                valid_chunked[i],
                                strlen (valid_chunked[i]),
                                chunked_request_prefix,
                                0);
          test_chunked_request (arena,
                                valid_chunked[i],
                                strlen (valid_chunked[i]),
                                chunked_request_prefix,
                                1);
        }
    }

    {
      const char *malformed_chunked[] = {
        /* Missing final chunk */
        "5\r\nhello\r\n",

        /* Missing final CRLF */
        "5\r\nhello\r\n0\r\n",

        /* Invalid hex */
        "XYZ\r\nhello\r\n0\r\n\r\n",
        "5G\r\nhello\r\n0\r\n\r\n",

        /* Negative size (invalid) */
        "-5\r\nhello\r\n0\r\n\r\n",

        /* Missing CRLF after size */
        "5hello\r\n0\r\n\r\n",

        /* Missing CRLF after data */
        "5\r\nhello0\r\n\r\n",

        /* Wrong data length (too short) */
        "10\r\nhello\r\n0\r\n\r\n",

        /* LF only (invalid per strict parsing) */
        "5\nhello\n0\n\n",

        /* CR only */
        "5\rhello\r0\r\r",

        /* Double CRLF in data */
        "7\r\nhel\r\nlo\r\n0\r\n\r\n",

        /* Null byte in size */
        "5\x00\r\nhello\r\n0\r\n\r\n",

        /* Very large size (DoS) */
        "FFFFFFFF\r\n",
        "7FFFFFFF\r\n",

        /* Size overflow attempt */
        "FFFFFFFFFFFFFFFF\r\n",

        /* Empty size */
        "\r\nhello\r\n0\r\n\r\n",

        /* Just CRLF */
        "\r\n",

        /* Extension with CRLF (injection) */
        "5;ext=val\r\nue\r\nhello\r\n0\r\n\r\n",

        /* Extension with null byte */
        "5;ext=\x00val\r\nhello\r\n0\r\n\r\n",

        /* Trailer injection attempt */
        "5\r\nhello\r\n0\r\nX-Evil\r\n: injected\r\n\r\n",

        /* Space before size */
        " 5\r\nhello\r\n0\r\n\r\n",

        /* Space after size */
        "5 \r\nhello\r\n0\r\n\r\n",

        /* Tab in size */
        "5\t\r\nhello\r\n0\r\n\r\n",
      };

      for (size_t i = 0;
           i < sizeof (malformed_chunked) / sizeof (malformed_chunked[0]);
           i++)
        {
          test_chunked_request (arena,
                                malformed_chunked[i],
                                strlen (malformed_chunked[i]),
                                chunked_request_prefix,
                                0);
          test_chunked_request (arena,
                                malformed_chunked[i],
                                strlen (malformed_chunked[i]),
                                chunked_request_prefix,
                                1);
        }
    }

    {
      const char *chunked_trailers[] = {
        /* Valid trailers */
        "5\r\nhello\r\n0\r\nX-Checksum: abc123\r\n\r\n",
        "5\r\nhello\r\n0\r\nX-Checksum: abc\r\nX-Final-Status: ok\r\n\r\n",

        /* Many trailers */
        "5\r\nhello\r\n0\r\n"
        "Trailer1: value1\r\n"
        "Trailer2: value2\r\n"
        "Trailer3: value3\r\n"
        "\r\n",

        /* Trailer with extension on final chunk */
        "5\r\nhello\r\n0;ext=val\r\nX-Checksum: abc\r\n\r\n",

        /* Empty trailer section */
        "5\r\nhello\r\n0\r\n\r\n",

        /* Trailer with colon in value */
        "5\r\nhello\r\n0\r\nX-Time: 12:34:56\r\n\r\n",

        /* Trailer with long value */
        "5\r\nhello\r\n0\r\nX-Long: "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "\r\n\r\n",
      };

      for (size_t i = 0;
           i < sizeof (chunked_trailers) / sizeof (chunked_trailers[0]);
           i++)
        {
          test_chunked_request (arena,
                                chunked_trailers[i],
                                strlen (chunked_trailers[i]),
                                chunked_with_trailer_prefix,
                                0);
          test_chunked_request (arena,
                                chunked_trailers[i],
                                strlen (chunked_trailers[i]),
                                chunked_with_trailer_prefix,
                                1);
        }
    }

    {
      const char *extension_tests[] = {
        /* Simple extension */
        "5;name=value\r\nhello\r\n0\r\n\r\n",

        /* Multiple extensions */
        "5;a=1;b=2;c=3\r\nhello\r\n0\r\n\r\n",

        /* Extension without value */
        "5;flag\r\nhello\r\n0\r\n\r\n",

        /* Quoted extension value */
        "5;name=\"quoted value\"\r\nhello\r\n0\r\n\r\n",

        /* Extension with special chars */
        "5;name=a-b_c.d\r\nhello\r\n0\r\n\r\n",

        /* Very long extension */
        ("5;name=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
         "\r\nhello\r\n0\r\n\r\n"),

        /* Many extensions */
        "5;a;b;c;d;e;f;g;h;i;j\r\nhello\r\n0\r\n\r\n",

        /* Extension on all chunks */
        "5;ext1=a\r\nhello\r\n6;ext2=b\r\n world\r\n0;ext3=c\r\n\r\n",
      };

      for (size_t i = 0;
           i < sizeof (extension_tests) / sizeof (extension_tests[0]);
           i++)
        {
          test_chunked_request (arena,
                                extension_tests[i],
                                strlen (extension_tests[i]),
                                chunked_request_prefix,
                                0);
        }
    }

    {
      const char *size_tests[] = {
        /* Zero (final only) */
        "0\r\n\r\n",

        /* One byte */
        "1\r\nx\r\n0\r\n\r\n",

        /* Various hex values */
        "1\r\na\r\n0\r\n\r\n",
        "2\r\nab\r\n0\r\n\r\n",
        "3\r\nabc\r\n0\r\n\r\n",
        "9\r\n123456789\r\n0\r\n\r\n",
        "a\r\n1234567890\r\n0\r\n\r\n",
        "b\r\n12345678901\r\n0\r\n\r\n",
        "c\r\n123456789012\r\n0\r\n\r\n",
        "d\r\n1234567890123\r\n0\r\n\r\n",
        "e\r\n12345678901234\r\n0\r\n\r\n",
        "f\r\n123456789012345\r\n0\r\n\r\n",

        /* Two digit hex */
        "10\r\n1234567890123456\r\n0\r\n\r\n",
        "ff\r\n", /* 255 bytes - would need data */
        "FF\r\n",
      };

      for (size_t i = 0; i < sizeof (size_tests) / sizeof (size_tests[0]); i++)
        {
          test_chunked_request (arena,
                                size_tests[i],
                                strlen (size_tests[i]),
                                chunked_request_prefix,
                                0);
        }
    }

    test_chunk_encoding (data, size);

    if (size > 10)
      {
        char chunked_body[16384];
        size_t offset = 0;
        size_t fuzz_offset = 0;

        /* Build multiple chunks from fuzz data */
        int chunk_count = 0;
        while (fuzz_offset < size && offset < sizeof (chunked_body) - 100
               && chunk_count < 20)
          {
            /* Get chunk size from fuzz data */
            size_t chunk_size = data[fuzz_offset] % 64 + 1;
            fuzz_offset++;

            if (fuzz_offset + chunk_size > size)
              chunk_size = size - fuzz_offset;

            if (chunk_size == 0)
              break;

            /* Write chunk size */
            int written = snprintf (chunked_body + offset,
                                    sizeof (chunked_body) - offset,
                                    "%zx\r\n",
                                    chunk_size);
            if (written <= 0)
              break;
            offset += written;

            /* Write chunk data */
            if (offset + chunk_size + 2 >= sizeof (chunked_body))
              break;

            memcpy (chunked_body + offset, data + fuzz_offset, chunk_size);
            offset += chunk_size;
            fuzz_offset += chunk_size;

            /* Write CRLF */
            chunked_body[offset++] = '\r';
            chunked_body[offset++] = '\n';

            chunk_count++;
          }

        /* Write final chunk */
        if (offset + 5 < sizeof (chunked_body))
          {
            memcpy (chunked_body + offset, "0\r\n\r\n", 5);
            offset += 5;

            test_chunked_request (
                arena, chunked_body, offset, chunked_request_prefix, 0);
            test_chunked_request (
                arena, chunked_body, offset, chunked_request_prefix, 1);
          }
      }

    {
      const char *test_body = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
      size_t test_len = strlen (test_body);

      SocketHTTP1_Config cfg;
      SocketHTTP1_config_defaults (&cfg);

      SocketHTTP1_Parser_T parser
          = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, arena);
      if (parser)
        {
          /* Parse headers first */
          size_t consumed;
          SocketHTTP1_Result result
              = SocketHTTP1_Parser_execute (parser,
                                            chunked_request_prefix,
                                            strlen (chunked_request_prefix),
                                            &consumed);

          if (result == HTTP1_OK)
            {
              /* Read body byte-by-byte */
              char body_buf[1];
              size_t body_consumed, body_written;
              size_t total = 0;

              while (total < test_len
                     && !SocketHTTP1_Parser_body_complete (parser))
                {
                  SocketHTTP1_Result body_result
                      = SocketHTTP1_Parser_read_body (parser,
                                                      test_body + total,
                                                      1,
                                                      &body_consumed,
                                                      body_buf,
                                                      1,
                                                      &body_written);

                  if (body_consumed == 0)
                    break;
                  total += body_consumed;

                  if (body_result != HTTP1_OK
                      && body_result != HTTP1_INCOMPLETE)
                    break;
                }
            }

          SocketHTTP1_Parser_free (&parser);
        }
    }
  }
  EXCEPT (SocketHTTP1_ParseError)
  {
    /* Expected on malformed input */
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on memory exhaustion */
  }
  END_TRY;

  Arena_dispose (&arena);

  return 0;
}
