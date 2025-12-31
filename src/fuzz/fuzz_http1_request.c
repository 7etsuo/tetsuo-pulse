/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_http1_request.c - Enterprise-grade HTTP/1.1 request parsing fuzzer
 *
 * Comprehensive fuzzing harness for HTTP/1.1 request parsing targeting all
 * attack vectors and edge cases:
 *
 * Targets:
 * - Request line parsing (method, URI, version)
 * - Header parsing (name validation, value injection, obs-fold)
 * - Body mode detection (Content-Length, chunked, close-delimited)
 * - Incremental parsing with arbitrary chunk boundaries
 * - Parser state machine transitions and reset
 * - Configuration variations (strict/lenient mode)
 * - Resource limits (max headers, max header size, max URI)
 * - Keep-alive and upgrade detection
 * - 100-continue expectation handling
 * - Malformed request rejection
 * - Memory safety under stress
 *
 * Security focus:
 * - Request smuggling vector detection
 * - Header injection prevention
 * - Buffer overflow prevention
 * - Integer overflow in lengths
 * - Resource exhaustion protection
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http1_request
 * ./fuzz_http1_request corpus/http1_request/ -fork=16 -max_len=65536
 */

#include <stdio.h>
#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketSecurity.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * Test incremental parsing with variable chunk sizes
 */
static void
test_incremental_parsing (SocketHTTP1_Parser_T parser,
                          const uint8_t *data,
                          size_t size,
                          size_t chunk_size)
{
  size_t offset = 0;
  size_t consumed;
  SocketHTTP1_Result result = HTTP1_INCOMPLETE;

  while (offset < size && result == HTTP1_INCOMPLETE)
    {
      size_t remaining = size - offset;
      size_t to_parse = (remaining < chunk_size) ? remaining : chunk_size;

      result = SocketHTTP1_Parser_execute (
          parser, (const char *)data + offset, to_parse, &consumed);
      offset += consumed;

      /* If no progress made and still incomplete, advance by 1 to prevent
       * infinite loop */
      if (consumed == 0 && result == HTTP1_INCOMPLETE)
        {
          offset++;
        }
    }

  /* If headers complete, try to read body */
  if (result == HTTP1_OK
      && SocketHTTP1_Parser_state (parser) >= HTTP1_STATE_BODY)
    {
      char body_buf[8192];
      size_t body_consumed, body_written;
      size_t body_remaining = size - offset;

      while (body_remaining > 0 && !SocketHTTP1_Parser_body_complete (parser))
        {
          size_t to_read
              = (body_remaining < chunk_size) ? body_remaining : chunk_size;
          SocketHTTP1_Result body_result
              = SocketHTTP1_Parser_read_body (parser,
                                              (const char *)data + offset,
                                              to_read,
                                              &body_consumed,
                                              body_buf,
                                              sizeof (body_buf),
                                              &body_written);

          if (body_consumed == 0)
            break;

          offset += body_consumed;
          body_remaining -= body_consumed;

          if (body_result != HTTP1_OK && body_result != HTTP1_INCOMPLETE)
            break;
        }
    }
}

/**
 * Exercise all parser accessor functions
 */
static void
exercise_parser_accessors (SocketHTTP1_Parser_T parser)
{
  /* State and mode */
  SocketHTTP1_State state = SocketHTTP1_Parser_state (parser);
  (void)state;

  SocketHTTP1_BodyMode body_mode = SocketHTTP1_Parser_body_mode (parser);
  (void)body_mode;

  /* Content info */
  int64_t content_length = SocketHTTP1_Parser_content_length (parser);
  (void)content_length;

  int64_t body_remaining = SocketHTTP1_Parser_body_remaining (parser);
  (void)body_remaining;

  int body_complete = SocketHTTP1_Parser_body_complete (parser);
  (void)body_complete;

  /* Connection info */
  int should_keepalive = SocketHTTP1_Parser_should_keepalive (parser);
  (void)should_keepalive;

  int is_upgrade = SocketHTTP1_Parser_is_upgrade (parser);
  (void)is_upgrade;

  int expects_continue = SocketHTTP1_Parser_expects_continue (parser);
  (void)expects_continue;

  /* Request data if available */
  if (state >= HTTP1_STATE_BODY)
    {
      const SocketHTTP_Request *req = SocketHTTP1_Parser_get_request (parser);
      if (req)
        {
          /* Access all request fields */
          (void)req->method;
          (void)req->version;
          (void)req->scheme;
          (void)req->authority;
          (void)req->path;
          (void)req->has_body;
          (void)req->content_length;

          if (req->headers)
            {
              /* Test header accessors */
              SocketHTTP_Headers_get (req->headers, "Host");
              SocketHTTP_Headers_get (req->headers, "Content-Length");
              SocketHTTP_Headers_get (req->headers, "Transfer-Encoding");
              SocketHTTP_Headers_get (req->headers, "Connection");
              SocketHTTP_Headers_get (req->headers, "Expect");
              SocketHTTP_Headers_get (req->headers, "Upgrade");
              SocketHTTP_Headers_has (req->headers, "Content-Type");
              SocketHTTP_Headers_count (req->headers);

              /* Iterate headers */
              size_t count = SocketHTTP_Headers_count (req->headers);
              for (size_t i = 0; i < count && i < 50; i++)
                {
                  const SocketHTTP_Header *h
                      = SocketHTTP_Headers_at (req->headers, i);
                  if (h)
                    {
                      (void)h->name;
                      (void)h->value;
                    }
                }
            }
        }
    }
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketHTTP1_Parser_T parser = NULL;
  size_t consumed;
  SocketHTTP1_Result result;

  /* Skip empty input */
  if (size == 0)
    return 0;

  /* Create arena */
  arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    /* ====================================================================
     * Test 1: Default configuration parsing
     * ==================================================================== */
    {
      parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
      if (parser)
        {
          result = SocketHTTP1_Parser_execute (
              parser, (const char *)data, size, &consumed);

          /* Exercise accessors regardless of result */
          exercise_parser_accessors (parser);

          /* If headers parsed, try body */
          if (result == HTTP1_OK
              && SocketHTTP1_Parser_state (parser) >= HTTP1_STATE_BODY)
            {
              char body_buf[8192];
              size_t body_consumed, body_written;
              size_t remaining = size - consumed;

              if (remaining > 0)
                {
                  SocketHTTP1_Parser_read_body (parser,
                                                (const char *)data + consumed,
                                                remaining,
                                                &body_consumed,
                                                body_buf,
                                                sizeof (body_buf),
                                                &body_written);
                }
            }

          /* Test parser reset and reuse */
          SocketHTTP1_Parser_reset (parser);
          result = SocketHTTP1_Parser_execute (
              parser, (const char *)data, size, &consumed);

          SocketHTTP1_Parser_free (&parser);
        }
    }

    /* ====================================================================
     * Test 2: Strict mode configuration
     * ==================================================================== */
    {
      SocketHTTP1_Config strict_cfg;
      SocketHTTP1_config_defaults (&strict_cfg);
      strict_cfg.strict_mode = 1;

      parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &strict_cfg, arena);
      if (parser)
        {
          result = SocketHTTP1_Parser_execute (
              parser, (const char *)data, size, &consumed);
          exercise_parser_accessors (parser);
          SocketHTTP1_Parser_free (&parser);
        }
    }

    /* ====================================================================
     * Test 3: Lenient mode with larger limits
     * ==================================================================== */
    {
      SocketHTTP1_Config lenient_cfg;
      SocketHTTP1_config_defaults (&lenient_cfg);
      lenient_cfg.strict_mode = 0;
      lenient_cfg.max_header_size = 32768;
      lenient_cfg.max_headers = 200;

      parser
          = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &lenient_cfg, arena);
      if (parser)
        {
          result = SocketHTTP1_Parser_execute (
              parser, (const char *)data, size, &consumed);
          exercise_parser_accessors (parser);
          SocketHTTP1_Parser_free (&parser);
        }
    }

    /* ====================================================================
     * Test 4: Restrictive limits for DoS protection testing
     * ==================================================================== */
    {
      SocketHTTP1_Config restrictive_cfg;
      SocketHTTP1_config_defaults (&restrictive_cfg);
      restrictive_cfg.max_header_size = 1024;
      restrictive_cfg.max_headers = 10;
      restrictive_cfg.max_request_line = 256;

      parser = SocketHTTP1_Parser_new (
          HTTP1_PARSE_REQUEST, &restrictive_cfg, arena);
      if (parser)
        {
          result = SocketHTTP1_Parser_execute (
              parser, (const char *)data, size, &consumed);
          SocketHTTP1_Parser_free (&parser);
        }
    }

    /* ====================================================================
     * Test 5: Incremental parsing with various chunk sizes
     * ==================================================================== */
    {
      size_t chunk_sizes[] = { 1, 2, 7, 13, 64, 256, 1024 };

      for (size_t i = 0;
           i < sizeof (chunk_sizes) / sizeof (chunk_sizes[0]) && size > 10;
           i++)
        {
          parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
          if (parser)
            {
              test_incremental_parsing (parser, data, size, chunk_sizes[i]);
              exercise_parser_accessors (parser);
              SocketHTTP1_Parser_free (&parser);
            }
        }
    }

    /* ====================================================================
     * Test 6: Known valid requests with fuzzed modifications
     * ==================================================================== */
    {
      const char *valid_requests[] = {
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "POST /data HTTP/1.1\r\nHost: test.com\r\nContent-Length: 5\r\n\r\n"
        "hello",
        "PUT /resource HTTP/1.1\r\nHost: api.com\r\nTransfer-Encoding: "
        "chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        "OPTIONS * HTTP/1.1\r\nHost: server.com\r\n\r\n",
        "DELETE /item/123 HTTP/1.1\r\nHost: api.com\r\nAuthorization: Bearer "
        "token\r\n\r\n",
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        "GET /path HTTP/1.0\r\nHost: old.com\r\n\r\n",
        "HEAD /check HTTP/1.1\r\nHost: health.com\r\n\r\n",
        "PATCH /update HTTP/1.1\r\nHost: api.com\r\nContent-Type: "
        "application/json\r\nContent-Length: 2\r\n\r\n{}",
      };

      for (size_t i = 0;
           i < sizeof (valid_requests) / sizeof (valid_requests[0]);
           i++)
        {
          parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
          if (parser)
            {
              SocketHTTP1_Parser_execute (parser,
                                          valid_requests[i],
                                          strlen (valid_requests[i]),
                                          &consumed);
              exercise_parser_accessors (parser);
              SocketHTTP1_Parser_free (&parser);
            }
        }
    }

    /* ====================================================================
     * Test 7: Malformed requests (security edge cases)
     * ==================================================================== */
    {
      const char *malformed_requests[] = {
        /* No CRLF */
        "GET / HTTP/1.1 Host: test.com",
        /* Missing version */
        "GET /\r\nHost: test.com\r\n\r\n",
        /* Invalid method characters */
        "G\x00T / HTTP/1.1\r\nHost: test.com\r\n\r\n",
        /* Header injection attempt */
        "GET / HTTP/1.1\r\nHost: test.com\r\nX-Inject: value\r\nEvil: "
        "header\r\n\r\n",
        /* Duplicate Content-Length (smuggling) */
        "POST / HTTP/1.1\r\nHost: test.com\r\nContent-Length: "
        "5\r\nContent-Length: 10\r\n\r\nhello",
        /* CL + TE (smuggling) */
        "POST / HTTP/1.1\r\nHost: test.com\r\nContent-Length: "
        "5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        /* TE + CL (smuggling) */
        "POST / HTTP/1.1\r\nHost: test.com\r\nTransfer-Encoding: "
        "chunked\r\nContent-Length: 5\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        /* Obs-fold in header (deprecated) */
        "GET / HTTP/1.1\r\nHost: test.com\r\nX-Folded: value\r\n "
        "continued\r\n\r\n",
        /* Null byte in header */
        "GET / HTTP/1.1\r\nHost: test\x00.com\r\n\r\n",
        /* CRLF in header value */
        "GET / HTTP/1.1\r\nHost: test\r\n.com\r\n\r\n",
        /* Very long header name */
        "GET / HTTP/1.1\r\nHost: test.com\r\n",
        /* Empty header name */
        "GET / HTTP/1.1\r\n: value\r\nHost: test.com\r\n\r\n",
        /* Space before colon */
        "GET / HTTP/1.1\r\nHost : test.com\r\n\r\n",
        /* Invalid HTTP version */
        "GET / HTTP/9.9\r\nHost: test.com\r\n\r\n",
        /* Negative content length */
        "POST / HTTP/1.1\r\nHost: test.com\r\nContent-Length: -1\r\n\r\n",
        /* Huge content length (DoS) */
        "POST / HTTP/1.1\r\nHost: test.com\r\nContent-Length: "
        "99999999999999999999\r\n\r\n",
        /* Invalid chunk size */
        "POST / HTTP/1.1\r\nHost: test.com\r\nTransfer-Encoding: "
        "chunked\r\n\r\nZZZ\r\nhello\r\n0\r\n\r\n",
        /* Chunked with negative size */
        "POST / HTTP/1.1\r\nHost: test.com\r\nTransfer-Encoding: "
        "chunked\r\n\r\n-5\r\nhello\r\n0\r\n\r\n",
        /* TE obfuscation variants */
        "POST / HTTP/1.1\r\nHost: test.com\r\nTransfer-Encoding: "
        "chunked\r\nTransfer-Encoding: identity\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: test.com\r\nTransfer-Encoding:  "
        "chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: test.com\r\nTransfer-Encoding:\tchunked\r\n\r"
        "\n5\r\nhello\r\n0\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: test.com\r\nTransfer-Encoding: "
        "chunked,identity\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
      };

      SocketHTTP1_Config strict_cfg;
      SocketHTTP1_config_defaults (&strict_cfg);
      strict_cfg.strict_mode = 1;

      for (size_t i = 0;
           i < sizeof (malformed_requests) / sizeof (malformed_requests[0]);
           i++)
        {
          parser = SocketHTTP1_Parser_new (
              HTTP1_PARSE_REQUEST, &strict_cfg, arena);
          if (parser)
            {
              SocketHTTP1_Parser_execute (parser,
                                          malformed_requests[i],
                                          strlen (malformed_requests[i]),
                                          &consumed);
              SocketHTTP1_Parser_free (&parser);
            }
        }
    }

    /* ====================================================================
     * Test 8: Build request with fuzzed components and parse
     * ==================================================================== */
    if (size > 20)
      {
        /* Use fuzz data to construct a request */
        char request_buf[8192];
        int req_len;

        /* Extract components from fuzz data */
        const char *methods[] = { "GET",     "POST",  "PUT",   "DELETE", "HEAD",
                                  "OPTIONS", "PATCH", "TRACE", "CONNECT" };
        int method_idx = data[0] % 9;

        size_t path_len = (data[1] % 128) + 1;
        if (path_len > size - 20)
          path_len = size - 20;

        char path[256];
        path[0] = '/';
        size_t copy_len
            = (path_len < sizeof (path) - 2) ? path_len : sizeof (path) - 2;
        memcpy (path + 1, data + 2, copy_len);
        path[copy_len + 1] = '\0';

        /* Sanitize path for valid HTTP */
        for (size_t i = 0; i < copy_len + 1; i++)
          {
            if (path[i] < 0x21 || path[i] > 0x7E)
              path[i] = 'x';
          }

        req_len = snprintf (request_buf,
                            sizeof (request_buf),
                            "%s %s HTTP/1.1\r\n"
                            "Host: example.com\r\n"
                            "\r\n",
                            methods[method_idx],
                            path);

        if (req_len > 0 && (size_t)req_len < sizeof (request_buf))
          {
            parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
            if (parser)
              {
                SocketHTTP1_Parser_execute (
                    parser, request_buf, req_len, &consumed);
                exercise_parser_accessors (parser);
                SocketHTTP1_Parser_free (&parser);
              }
          }
      }

    /* ====================================================================
     * Test 9: Result string function coverage
     * ==================================================================== */
    {
      SocketHTTP1_Result results[] = { HTTP1_OK,
                                       HTTP1_INCOMPLETE,
                                       HTTP1_ERROR,
                                       HTTP1_ERROR_LINE_TOO_LONG,
                                       HTTP1_ERROR_INVALID_METHOD,
                                       HTTP1_ERROR_INVALID_URI,
                                       HTTP1_ERROR_INVALID_VERSION,
                                       HTTP1_ERROR_INVALID_STATUS,
                                       HTTP1_ERROR_INVALID_HEADER_NAME,
                                       HTTP1_ERROR_INVALID_HEADER_VALUE,
                                       HTTP1_ERROR_HEADER_TOO_LARGE,
                                       HTTP1_ERROR_TOO_MANY_HEADERS,
                                       HTTP1_ERROR_INVALID_CONTENT_LENGTH,
                                       HTTP1_ERROR_INVALID_CHUNK_SIZE,
                                       HTTP1_ERROR_CHUNK_TOO_LARGE,
                                       HTTP1_ERROR_BODY_TOO_LARGE,
                                       HTTP1_ERROR_INVALID_TRAILER,
                                       HTTP1_ERROR_UNSUPPORTED_TRANSFER_CODING,
                                       HTTP1_ERROR_UNEXPECTED_EOF,
                                       HTTP1_ERROR_SMUGGLING_DETECTED };

      for (size_t i = 0; i < sizeof (results) / sizeof (results[0]); i++)
        {
          const char *str = SocketHTTP1_result_string (results[i]);
          (void)str;
        }

      /* Also test with fuzzed values */
      if (size >= 1)
        {
          SocketHTTP1_result_string ((SocketHTTP1_Result)data[0]);
        }
    }

    /* ====================================================================
     * Test 10: Expect: 100-continue handling
     * ==================================================================== */
    {
      const char *continue_requests[] = {
        "POST / HTTP/1.1\r\nHost: test.com\r\nContent-Length: "
        "1000\r\nExpect: 100-continue\r\n\r\n",
        "PUT /upload HTTP/1.1\r\nHost: test.com\r\nContent-Length: "
        "5000\r\nExpect: 100-Continue\r\n\r\n",
      };

      for (size_t i = 0;
           i < sizeof (continue_requests) / sizeof (continue_requests[0]);
           i++)
        {
          parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
          if (parser)
            {
              SocketHTTP1_Parser_execute (parser,
                                          continue_requests[i],
                                          strlen (continue_requests[i]),
                                          &consumed);

              int expects = SocketHTTP1_Parser_expects_continue (parser);
              (void)expects;

              SocketHTTP1_Parser_free (&parser);
            }
        }
    }

    /* ====================================================================
     * Test 11: Upgrade handling (WebSocket, HTTP/2)
     * ==================================================================== */
    {
      const char *upgrade_requests[] = {
        "GET /ws HTTP/1.1\r\nHost: test.com\r\nUpgrade: "
        "websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
        "dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: test.com\r\nUpgrade: h2c\r\nConnection: "
        "Upgrade, HTTP2-Settings\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n",
      };

      for (size_t i = 0;
           i < sizeof (upgrade_requests) / sizeof (upgrade_requests[0]);
           i++)
        {
          parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
          if (parser)
            {
              SocketHTTP1_Parser_execute (parser,
                                          upgrade_requests[i],
                                          strlen (upgrade_requests[i]),
                                          &consumed);

              int is_upgrade = SocketHTTP1_Parser_is_upgrade (parser);
              (void)is_upgrade;

              SocketHTTP1_Parser_free (&parser);
            }
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
