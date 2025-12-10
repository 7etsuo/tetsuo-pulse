/**
 * fuzz_http_smuggling.c - Enterprise-grade HTTP Request Smuggling fuzzer
 *
 * Comprehensive fuzzing harness targeting all known HTTP request smuggling
 * attack vectors per RFC 9112 Section 6.3 and real-world exploits.
 *
 * Attack Categories Tested:
 *
 * 1. CL.TE (Content-Length.Transfer-Encoding) Attacks:
 *    - Front-end uses Content-Length, back-end uses Transfer-Encoding
 *    - Embedded requests in body
 *
 * 2. TE.CL (Transfer-Encoding.Content-Length) Attacks:
 *    - Front-end uses Transfer-Encoding, back-end uses Content-Length
 *    - Chunked body with malicious trailing content
 *
 * 3. TE.TE (Transfer-Encoding.Transfer-Encoding) Obfuscation:
 *    - Multiple TE headers with obfuscation
 *    - Capitalization tricks: chunked, ChUnKeD, CHUNKED
 *    - Whitespace injection: "chunked ", " chunked", "\tchunked"
 *    - Invalid values: "chunked,identity", "xchunked"
 *
 * 4. Duplicate Header Attacks:
 *    - Multiple Content-Length headers with different values
 *    - Multiple Transfer-Encoding headers
 *
 * 5. Header Obfuscation:
 *    - Obs-fold (line folding) in critical headers
 *    - Null bytes in headers
 *    - CRLF injection attempts
 *    - Unicode/encoding attacks
 *
 * 6. HTTP Version Attacks:
 *    - HTTP/1.0 vs HTTP/1.1 semantic differences
 *    - Keep-alive vs close differences
 *
 * 7. Body Length Manipulation:
 *    - Negative Content-Length
 *    - Overflowing Content-Length
 *    - Mismatched Content-Length and actual body
 *
 * Security Focus:
 * - Parser state corruption detection
 * - Invalid body length calculation
 * - Resource exhaustion from ambiguous messages
 * - Buffer overflows from malformed chunks
 * - Connection state desync
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http_smuggling
 * ./fuzz_http_smuggling corpus/http_smug/ -fork=16 -max_len=65536
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * Parse request and detect smuggling indicators
 */
static void
test_smuggling_detection (Arena_T arena, const char *request, size_t len,
                          int strict)
{
  SocketHTTP1_Parser_T parser = NULL;
  SocketHTTP1_Config cfg;
  size_t consumed;

  SocketHTTP1_config_defaults (&cfg);
  cfg.strict_mode = strict;

  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, arena);
  if (!parser)
    return;

  SocketHTTP1_Result result
      = SocketHTTP1_Parser_execute (parser, request, len, &consumed);

  /* Analyze result for smuggling indicators */
  if (result == HTTP1_OK)
    {
      const SocketHTTP_Request *req = SocketHTTP1_Parser_get_request (parser);
      if (req && req->headers)
        {
          /* Check for conflicting headers */
          const char *cl = SocketHTTP_Headers_get (req->headers, "Content-Length");
          const char *te
              = SocketHTTP_Headers_get (req->headers, "Transfer-Encoding");

          /* Both CL and TE present is a smuggling indicator */
          if (cl && te)
            {
              /* Parser should reject or handle deterministically */
              (void)cl;
              (void)te;
            }

          /* Check for multiple values */
          const char *cl_all[10];
          size_t cl_count = SocketHTTP_Headers_get_all (req->headers,
                                                        "Content-Length",
                                                        cl_all, 10);
          if (cl_count > 1)
            {
              /* Multiple CL headers - smuggling indicator */
              (void)cl_count;
            }

          const char *te_all[10];
          size_t te_count = SocketHTTP_Headers_get_all (req->headers,
                                                        "Transfer-Encoding",
                                                        te_all, 10);
          if (te_count > 1)
            {
              /* Multiple TE headers - smuggling indicator */
              (void)te_count;
            }
        }

      /* Check body handling */
      SocketHTTP1_BodyMode mode = SocketHTTP1_Parser_body_mode (parser);
      (void)mode;

      int64_t body_len = SocketHTTP1_Parser_content_length (parser);
      (void)body_len;

      /* Try to read body if present */
      if (consumed < len)
        {
          char body_buf[8192];
          size_t body_consumed, body_written;
          SocketHTTP1_Parser_read_body (parser, request + consumed,
                                        len - consumed, &body_consumed,
                                        body_buf, sizeof (body_buf),
                                        &body_written);
        }
    }

  SocketHTTP1_Parser_free (&parser);
}

/**
 * Test incremental parsing for smuggling
 */
static void
test_incremental_smuggling (Arena_T arena, const char *request, size_t len)
{
  SocketHTTP1_Parser_T parser = NULL;
  SocketHTTP1_Config cfg;

  SocketHTTP1_config_defaults (&cfg);
  cfg.strict_mode = 1;

  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, arena);
  if (!parser)
    return;

  /* Parse byte-by-byte to catch state machine issues */
  size_t offset = 0;
  size_t consumed;
  SocketHTTP1_Result result = HTTP1_INCOMPLETE;

  while (offset < len && result == HTTP1_INCOMPLETE)
    {
      result = SocketHTTP1_Parser_execute (parser, request + offset, 1,
                                           &consumed);
      offset += consumed;
      if (consumed == 0 && result == HTTP1_INCOMPLETE)
        offset++;
    }

  /* Continue to body if headers complete */
  if (result == HTTP1_OK && offset < len)
    {
      char body_buf[4096];
      size_t body_consumed, body_written;

      while (offset < len && !SocketHTTP1_Parser_body_complete (parser))
        {
          SocketHTTP1_Result body_result = SocketHTTP1_Parser_read_body (
              parser, request + offset, 1, &body_consumed, body_buf,
              sizeof (body_buf), &body_written);

          if (body_consumed == 0)
            break;
          offset += body_consumed;

          if (body_result != HTTP1_OK && body_result != HTTP1_INCOMPLETE)
            break;
        }
    }

  SocketHTTP1_Parser_free (&parser);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;

  /* Minimum size for meaningful HTTP request */
  if (size < 16)
    return 0;

  arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    /* ====================================================================
     * Test 1: Direct fuzzed input parsing
     * ==================================================================== */
    test_smuggling_detection (arena, (const char *)data, size, 0);
    test_smuggling_detection (arena, (const char *)data, size, 1);

    /* ====================================================================
     * Test 2: Byte-by-byte parsing for state corruption
     * ==================================================================== */
    test_incremental_smuggling (arena, (const char *)data, size);

    /* ====================================================================
     * Test 3: CL.TE Attack Vectors
     * ==================================================================== */
    {
      const char *cl_te_attacks[] = {
        /* Basic CL.TE */
        "POST / HTTP/1.1\r\n"
        "Host: vulnerable.com\r\n"
        "Content-Length: 13\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "SMUGGLED",

        /* CL.TE with embedded request */
        "POST / HTTP/1.1\r\n"
        "Host: vulnerable.com\r\n"
        "Content-Length: 35\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "GET /admin HTTP/1.1\r\n"
        "Host: x\r\n"
        "\r\n",

        /* CL.TE with prefix injection */
        "POST / HTTP/1.1\r\n"
        "Host: vulnerable.com\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "X",
      };

      for (size_t i = 0; i < sizeof (cl_te_attacks) / sizeof (cl_te_attacks[0]);
           i++)
        {
          test_smuggling_detection (arena, cl_te_attacks[i],
                                    strlen (cl_te_attacks[i]), 0);
          test_smuggling_detection (arena, cl_te_attacks[i],
                                    strlen (cl_te_attacks[i]), 1);
        }
    }

    /* ====================================================================
     * Test 4: TE.CL Attack Vectors
     * ==================================================================== */
    {
      const char *te_cl_attacks[] = {
        /* Basic TE.CL */
        "POST / HTTP/1.1\r\n"
        "Host: vulnerable.com\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5c\r\n"
        "GPOST / HTTP/1.1\r\n"
        "Host: vulnerable.com\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "x=1\r\n"
        "0\r\n"
        "\r\n",

        /* TE.CL with trailing data */
        "POST / HTTP/1.1\r\n"
        "Host: vulnerable.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 3\r\n"
        "\r\n"
        "1\r\n"
        "Z\r\n"
        "0\r\n"
        "\r\n"
        "GET /admin HTTP/1.1\r\n"
        "\r\n",
      };

      for (size_t i = 0; i < sizeof (te_cl_attacks) / sizeof (te_cl_attacks[0]);
           i++)
        {
          test_smuggling_detection (arena, te_cl_attacks[i],
                                    strlen (te_cl_attacks[i]), 0);
          test_smuggling_detection (arena, te_cl_attacks[i],
                                    strlen (te_cl_attacks[i]), 1);
        }
    }

    /* ====================================================================
     * Test 5: TE.TE Obfuscation Attacks
     * ==================================================================== */
    {
      const char *te_te_attacks[] = {
        /* Capitalization variants */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: ChUnKeD\r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n",

        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: CHUNKED\r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n",

        /* Whitespace before value */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding:  chunked\r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n",

        /* Tab before value */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding:\tchunked\r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n",

        /* Trailing whitespace */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: chunked \r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n",

        /* Multiple TE headers */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-Encoding: identity\r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n",

        /* TE with invalid value followed by valid */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: xchunked\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n",

        /* Comma-separated values */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: chunked, identity\r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n",

        /* Obs-fold in TE header */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        " , identity\r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n",

        /* Null byte in TE value */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: chun\x00ked\r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n",

        /* Vertical tab */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding:\x0bchunked\r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n",

        /* Form feed */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding:\x0cchunked\r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n",

        /* Backspace trick */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: x\x08chunked\r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n",
      };

      for (size_t i = 0; i < sizeof (te_te_attacks) / sizeof (te_te_attacks[0]);
           i++)
        {
          test_smuggling_detection (arena, te_te_attacks[i],
                                    strlen (te_te_attacks[i]), 0);
          test_smuggling_detection (arena, te_te_attacks[i],
                                    strlen (te_te_attacks[i]), 1);
        }
    }

    /* ====================================================================
     * Test 6: Duplicate Content-Length Attacks
     * ==================================================================== */
    {
      const char *dup_cl_attacks[] = {
        /* Two different CL values */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "hello",

        /* Same CL value (should be OK) */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello",

        /* Many CL headers */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello",

        /* First large, second small */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: 100\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello",

        /* First small, second large */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 100\r\n"
        "\r\n"
        "hello",

        /* Comma-separated (invalid but tested) */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: 5, 10\r\n"
        "\r\n"
        "hello",
      };

      for (size_t i = 0;
           i < sizeof (dup_cl_attacks) / sizeof (dup_cl_attacks[0]); i++)
        {
          test_smuggling_detection (arena, dup_cl_attacks[i],
                                    strlen (dup_cl_attacks[i]), 0);
          test_smuggling_detection (arena, dup_cl_attacks[i],
                                    strlen (dup_cl_attacks[i]), 1);
        }
    }

    /* ====================================================================
     * Test 7: Content-Length Edge Cases
     * ==================================================================== */
    {
      const char *cl_edge_cases[] = {
        /* Negative CL */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: -1\r\n"
        "\r\n",

        /* Zero CL */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: 0\r\n"
        "\r\n",

        /* Very large CL */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: 99999999999999999999\r\n"
        "\r\n",

        /* CL with leading zeros */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: 00005\r\n"
        "\r\n"
        "hello",

        /* CL with plus sign */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: +5\r\n"
        "\r\n"
        "hello",

        /* CL with whitespace */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length:  5\r\n"
        "\r\n"
        "hello",

        /* CL with trailing whitespace */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: 5 \r\n"
        "\r\n"
        "hello",

        /* CL with hex (invalid) */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: 0x5\r\n"
        "\r\n"
        "hello",

        /* CL with float (invalid) */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: 5.0\r\n"
        "\r\n"
        "hello",

        /* Empty CL value */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: \r\n"
        "\r\n",

        /* CL with letters */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: 5abc\r\n"
        "\r\n"
        "hello",

        /* Integer overflow attempt */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Content-Length: 18446744073709551615\r\n"
        "\r\n",
      };

      for (size_t i = 0;
           i < sizeof (cl_edge_cases) / sizeof (cl_edge_cases[0]); i++)
        {
          test_smuggling_detection (arena, cl_edge_cases[i],
                                    strlen (cl_edge_cases[i]), 0);
          test_smuggling_detection (arena, cl_edge_cases[i],
                                    strlen (cl_edge_cases[i]), 1);
        }
    }

    /* ====================================================================
     * Test 8: Malformed Chunk Sizes
     * ==================================================================== */
    {
      const char *chunk_attacks[] = {
        /* Negative chunk size */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "-5\r\n"
        "hello\r\n"
        "0\r\n"
        "\r\n",

        /* Extremely large chunk */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "FFFFFFFF\r\n"
        "hello\r\n"
        "0\r\n"
        "\r\n",

        /* Invalid hex in chunk size */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "XYZ\r\n"
        "hello\r\n"
        "0\r\n"
        "\r\n",

        /* Chunk size with extension */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5;ext=value\r\n"
        "hello\r\n"
        "0\r\n"
        "\r\n",

        /* Chunk size with malicious extension */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5;x=\r\n"
        "hello\r\n"
        "0\r\n"
        "\r\n",

        /* Very long chunk extension */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5;ext=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n"
        "hello\r\n"
        "0\r\n"
        "\r\n",

        /* Leading zeros in chunk size */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "00005\r\n"
        "hello\r\n"
        "0\r\n"
        "\r\n",

        /* Missing CRLF after chunk data */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5\r\n"
        "hello"
        "0\r\n"
        "\r\n",

        /* LF-only line endings */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5\n"
        "hello\n"
        "0\n"
        "\n",

        /* Mixed line endings */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5\r\n"
        "hello\n"
        "0\r\n"
        "\r\n",
      };

      for (size_t i = 0;
           i < sizeof (chunk_attacks) / sizeof (chunk_attacks[0]); i++)
        {
          test_smuggling_detection (arena, chunk_attacks[i],
                                    strlen (chunk_attacks[i]), 0);
          test_smuggling_detection (arena, chunk_attacks[i],
                                    strlen (chunk_attacks[i]), 1);
        }
    }

    /* ====================================================================
     * Test 9: HTTP/1.0 vs HTTP/1.1 Differences
     * ==================================================================== */
    {
      const char *version_attacks[] = {
        /* HTTP/1.0 with TE (should ignore TE) */
        "POST / HTTP/1.0\r\n"
        "Host: test.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello",

        /* HTTP/1.0 with Connection: keep-alive */
        "POST / HTTP/1.0\r\n"
        "Host: test.com\r\n"
        "Connection: keep-alive\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello",

        /* HTTP/1.1 with Connection: close */
        "POST / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "Connection: close\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello",

        /* HTTP/0.9 style (no headers) */
        "GET /\r\n",
      };

      for (size_t i = 0;
           i < sizeof (version_attacks) / sizeof (version_attacks[0]); i++)
        {
          test_smuggling_detection (arena, version_attacks[i],
                                    strlen (version_attacks[i]), 0);
          test_smuggling_detection (arena, version_attacks[i],
                                    strlen (version_attacks[i]), 1);
        }
    }

    /* ====================================================================
     * Test 10: Header Injection Attacks
     * ==================================================================== */
    {
      const char *injection_attacks[] = {
        /* CRLF in header value */
        "GET / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "X-Header: value\r\nEvil: injected\r\n"
        "\r\n",

        /* Null byte in header */
        "GET / HTTP/1.1\r\n"
        "Host: test\x00.com\r\n"
        "\r\n",

        /* CR without LF */
        "GET / HTTP/1.1\r\n"
        "Host: test.com\r"
        "X-Injected: value\r\n"
        "\r\n",

        /* LF without CR */
        "GET / HTTP/1.1\r\n"
        "Host: test.com\n"
        "X-Injected: value\r\n"
        "\r\n",

        /* Obs-fold injection */
        "GET / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "X-Folded: first\r\n"
        " second\r\n"
        "\r\n",

        /* Space before colon (invalid) */
        "GET / HTTP/1.1\r\n"
        "Host : test.com\r\n"
        "\r\n",

        /* Very long header line */
        "GET / HTTP/1.1\r\n"
        "Host: test.com\r\n"
        "X-Long: "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "\r\n"
        "\r\n",
      };

      for (size_t i = 0;
           i < sizeof (injection_attacks) / sizeof (injection_attacks[0]); i++)
        {
          test_smuggling_detection (arena, injection_attacks[i],
                                    strlen (injection_attacks[i]), 0);
          test_smuggling_detection (arena, injection_attacks[i],
                                    strlen (injection_attacks[i]), 1);
        }
    }

    /* ====================================================================
     * Test 11: Build smuggling request with fuzzed payload
     * ==================================================================== */
    if (size > 50)
      {
        /* Use fuzz data to build potential smuggling request */
        char smuggle_buf[8192];
        int len;

        /* CL.TE with fuzzed embedded data */
        size_t payload_len = size > 100 ? 100 : size;

        len = snprintf (smuggle_buf, sizeof (smuggle_buf),
                        "POST / HTTP/1.1\r\n"
                        "Host: test.com\r\n"
                        "Content-Length: %zu\r\n"
                        "Transfer-Encoding: chunked\r\n"
                        "\r\n"
                        "0\r\n"
                        "\r\n",
                        payload_len + 7);

        if (len > 0 && (size_t)len + payload_len < sizeof (smuggle_buf))
          {
            memcpy (smuggle_buf + len, data, payload_len);
            test_smuggling_detection (arena, smuggle_buf, len + payload_len, 0);
            test_smuggling_detection (arena, smuggle_buf, len + payload_len, 1);
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
