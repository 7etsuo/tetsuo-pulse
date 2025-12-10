/**
 * fuzz_http1_response.c - Enterprise-grade HTTP/1.1 response parsing fuzzer
 *
 * Comprehensive fuzzing harness for HTTP/1.1 response parsing targeting all
 * attack vectors and edge cases:
 *
 * Targets:
 * - Status line parsing (version, status code, reason phrase)
 * - Header parsing with validation
 * - Body mode detection (Content-Length, chunked, close-delimited)
 * - Incremental parsing with arbitrary chunk boundaries
 * - Parser state machine transitions and reset
 * - Configuration variations (strict/lenient mode)
 * - Resource limits (max headers, max header size)
 * - Keep-alive detection for connection reuse
 * - 1xx informational responses
 * - Redirect response handling (3xx)
 * - Error response handling (4xx, 5xx)
 * - HEAD response handling (no body)
 * - 204/304 responses (no body)
 *
 * Security focus:
 * - Response splitting prevention
 * - Header injection prevention
 * - Buffer overflow prevention
 * - Integer overflow in Content-Length
 * - Malformed chunked encoding
 * - Resource exhaustion protection
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http1_response
 * ./fuzz_http1_response corpus/http1_response/ -fork=16 -max_len=65536
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
 * Test incremental parsing with variable chunk sizes
 */
static void
test_incremental_parsing (SocketHTTP1_Parser_T parser, const uint8_t *data,
                          size_t size, size_t chunk_size)
{
  size_t offset = 0;
  size_t consumed;
  SocketHTTP1_Result result = HTTP1_INCOMPLETE;

  while (offset < size && result == HTTP1_INCOMPLETE)
    {
      size_t remaining = size - offset;
      size_t to_parse = (remaining < chunk_size) ? remaining : chunk_size;

      result = SocketHTTP1_Parser_execute (parser, (const char *)data + offset,
                                           to_parse, &consumed);
      offset += consumed;

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

      while (body_remaining > 0
             && !SocketHTTP1_Parser_body_complete (parser))
        {
          size_t to_read
              = (body_remaining < chunk_size) ? body_remaining : chunk_size;
          SocketHTTP1_Result body_result = SocketHTTP1_Parser_read_body (
              parser, (const char *)data + offset, to_read, &body_consumed,
              body_buf, sizeof (body_buf), &body_written);

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
 * Exercise all parser accessor functions for responses
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

  /* Response data if available */
  if (state >= HTTP1_STATE_BODY)
    {
      const SocketHTTP_Response *resp
          = SocketHTTP1_Parser_get_response (parser);
      if (resp)
        {
          /* Access all response fields */
          (void)resp->version;
          (void)resp->status_code;
          (void)resp->reason_phrase;
          (void)resp->has_body;
          (void)resp->content_length;

          /* Test status code utilities */
          int valid = SocketHTTP_status_valid (resp->status_code);
          (void)valid;

          SocketHTTP_StatusCategory cat
              = SocketHTTP_status_category (resp->status_code);
          (void)cat;

          const char *reason = SocketHTTP_status_reason (resp->status_code);
          (void)reason;

          if (resp->headers)
            {
              /* Test common response header accessors */
              SocketHTTP_Headers_get (resp->headers, "Content-Type");
              SocketHTTP_Headers_get (resp->headers, "Content-Length");
              SocketHTTP_Headers_get (resp->headers, "Transfer-Encoding");
              SocketHTTP_Headers_get (resp->headers, "Connection");
              SocketHTTP_Headers_get (resp->headers, "Set-Cookie");
              SocketHTTP_Headers_get (resp->headers, "Location");
              SocketHTTP_Headers_get (resp->headers, "WWW-Authenticate");
              SocketHTTP_Headers_get (resp->headers, "Cache-Control");
              SocketHTTP_Headers_get (resp->headers, "Date");
              SocketHTTP_Headers_get (resp->headers, "Server");
              SocketHTTP_Headers_has (resp->headers, "Content-Encoding");
              SocketHTTP_Headers_count (resp->headers);

              /* Get all Set-Cookie headers (common duplicate) */
              const char *cookies[16];
              SocketHTTP_Headers_get_all (resp->headers, "Set-Cookie", cookies,
                                          16);

              /* Iterate headers */
              size_t count = SocketHTTP_Headers_count (resp->headers);
              for (size_t i = 0; i < count && i < 50; i++)
                {
                  const SocketHTTP_Header *h
                      = SocketHTTP_Headers_at (resp->headers, i);
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
      parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
      if (parser)
        {
          result = SocketHTTP1_Parser_execute (parser, (const char *)data,
                                               size, &consumed);
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
                  SocketHTTP1_Parser_read_body (
                      parser, (const char *)data + consumed, remaining,
                      &body_consumed, body_buf, sizeof (body_buf),
                      &body_written);
                }
            }

          /* Test parser reset and reuse */
          SocketHTTP1_Parser_reset (parser);
          SocketHTTP1_Parser_execute (parser, (const char *)data, size,
                                      &consumed);

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

      parser
          = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, &strict_cfg, arena);
      if (parser)
        {
          result = SocketHTTP1_Parser_execute (parser, (const char *)data,
                                               size, &consumed);
          exercise_parser_accessors (parser);
          SocketHTTP1_Parser_free (&parser);
        }
    }

    /* ====================================================================
     * Test 3: Incremental parsing with various chunk sizes
     * ==================================================================== */
    {
      size_t chunk_sizes[] = { 1, 3, 7, 16, 64, 256, 1024 };

      for (size_t i = 0;
           i < sizeof (chunk_sizes) / sizeof (chunk_sizes[0]) && size > 10;
           i++)
        {
          parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
          if (parser)
            {
              test_incremental_parsing (parser, data, size, chunk_sizes[i]);
              exercise_parser_accessors (parser);
              SocketHTTP1_Parser_free (&parser);
            }
        }
    }

    /* ====================================================================
     * Test 4: All valid status code categories
     * ==================================================================== */
    {
      /* 1xx Informational */
      const char *informational[]
          = { "HTTP/1.1 100 Continue\r\n\r\n",
              "HTTP/1.1 101 Switching Protocols\r\nUpgrade: "
              "websocket\r\nConnection: Upgrade\r\n\r\n",
              "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; "
              "as=style\r\n\r\n" };

      for (size_t i = 0; i < sizeof (informational) / sizeof (informational[0]);
           i++)
        {
          parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
          if (parser)
            {
              SocketHTTP1_Parser_execute (parser, informational[i],
                                          strlen (informational[i]), &consumed);
              exercise_parser_accessors (parser);
              SocketHTTP1_Parser_free (&parser);
            }
        }

      /* 2xx Success */
      const char *success[] = {
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        "HTTP/1.1 201 Created\r\nLocation: /resource/1\r\nContent-Length: "
        "0\r\n\r\n",
        "HTTP/1.1 204 No Content\r\n\r\n",
        "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes "
        "0-100/1000\r\nContent-Length: 101\r\n\r\n",
      };

      for (size_t i = 0; i < sizeof (success) / sizeof (success[0]); i++)
        {
          parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
          if (parser)
            {
              SocketHTTP1_Parser_execute (parser, success[i],
                                          strlen (success[i]), &consumed);
              exercise_parser_accessors (parser);
              SocketHTTP1_Parser_free (&parser);
            }
        }

      /* 3xx Redirection */
      const char *redirects[] = {
        "HTTP/1.1 301 Moved Permanently\r\nLocation: "
        "https://new.example.com/\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 304 Not Modified\r\nETag: \"abc123\"\r\n\r\n",
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: "
        "/temp\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 308 Permanent Redirect\r\nLocation: "
        "/permanent\r\nContent-Length: 0\r\n\r\n",
      };

      for (size_t i = 0; i < sizeof (redirects) / sizeof (redirects[0]); i++)
        {
          parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
          if (parser)
            {
              SocketHTTP1_Parser_execute (parser, redirects[i],
                                          strlen (redirects[i]), &consumed);
              exercise_parser_accessors (parser);
              SocketHTTP1_Parser_free (&parser);
            }
        }

      /* 4xx Client Errors */
      const char *client_errors[]
          = { "HTTP/1.1 400 Bad Request\r\nContent-Type: "
              "text/plain\r\nContent-Length: 11\r\n\r\nBad Request",
              "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic "
              "realm=\"test\"\r\nContent-Length: 0\r\n\r\n",
              "HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden",
              "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found",
              "HTTP/1.1 429 Too Many Requests\r\nRetry-After: "
              "60\r\nContent-Length: 0\r\n\r\n" };

      for (size_t i = 0;
           i < sizeof (client_errors) / sizeof (client_errors[0]); i++)
        {
          parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
          if (parser)
            {
              SocketHTTP1_Parser_execute (parser, client_errors[i],
                                          strlen (client_errors[i]),
                                          &consumed);
              exercise_parser_accessors (parser);
              SocketHTTP1_Parser_free (&parser);
            }
        }

      /* 5xx Server Errors */
      const char *server_errors[]
          = { "HTTP/1.1 500 Internal Server Error\r\nContent-Length: "
              "21\r\n\r\nInternal Server Error",
              "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
              "HTTP/1.1 503 Service Unavailable\r\nRetry-After: "
              "300\r\nContent-Length: 0\r\n\r\n",
              "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n" };

      for (size_t i = 0;
           i < sizeof (server_errors) / sizeof (server_errors[0]); i++)
        {
          parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
          if (parser)
            {
              SocketHTTP1_Parser_execute (parser, server_errors[i],
                                          strlen (server_errors[i]),
                                          &consumed);
              exercise_parser_accessors (parser);
              SocketHTTP1_Parser_free (&parser);
            }
        }
    }

    /* ====================================================================
     * Test 5: Malformed responses (security edge cases)
     * ==================================================================== */
    {
      const char *malformed_responses[] = {
        /* Invalid status line */
        "HTTP/1.1\r\n\r\n",
        /* Missing status code */
        "HTTP/1.1  OK\r\n\r\n",
        /* Non-numeric status code */
        "HTTP/1.1 ABC OK\r\n\r\n",
        /* Status code out of range */
        "HTTP/1.1 999 Unknown\r\n\r\n",
        "HTTP/1.1 99 Too Low\r\n\r\n",
        "HTTP/1.1 0 Zero\r\n\r\n",
        "HTTP/1.1 -200 Negative\r\n\r\n",
        /* Null in status line */
        "HTTP/1.1 200 OK\x00Extra\r\n\r\n",
        /* CRLF injection in reason */
        "HTTP/1.1 200 OK\r\nInjected: header\r\n\r\n",
        /* Header injection */
        "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc\r\nX-Injected: "
        "value\r\n\r\n",
        /* Duplicate Content-Length */
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: "
        "10\r\n\r\nhello",
        /* CL + TE conflict */
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: "
        "chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        /* Invalid chunked encoding */
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: "
        "chunked\r\n\r\nXXX\r\nhello\r\n0\r\n\r\n",
        /* Negative chunk size */
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: "
        "chunked\r\n\r\n-5\r\nhello\r\n0\r\n\r\n",
        /* Huge Content-Length */
        "HTTP/1.1 200 OK\r\nContent-Length: "
        "99999999999999999999\r\n\r\n",
        /* Null byte in header name */
        "HTTP/1.1 200 OK\r\nX-Hea\x00der: value\r\n\r\n",
        /* Null byte in header value */
        "HTTP/1.1 200 OK\r\nX-Header: val\x00ue\r\n\r\n",
        /* Space in header name */
        "HTTP/1.1 200 OK\r\nX Header: value\r\n\r\n",
        /* Missing colon in header */
        "HTTP/1.1 200 OK\r\nX-Header value\r\n\r\n",
        /* Obs-fold (deprecated) */
        "HTTP/1.1 200 OK\r\nX-Folded: first\r\n second\r\n\r\n",
        /* Very long reason phrase */
        "HTTP/1.1 200 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "\r\n\r\n",
        /* Invalid HTTP version */
        "HTTP/9.9 200 OK\r\n\r\n",
        "HTTP/1 200 OK\r\n\r\n",
        "HTTTP/1.1 200 OK\r\n\r\n",
        /* TE obfuscation */
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, "
        "identity\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding:  "
        "chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding:\tchunked\r\n\r\n5\r\nhello\r\n0"
        "\r\n\r\n",
      };

      SocketHTTP1_Config strict_cfg;
      SocketHTTP1_config_defaults (&strict_cfg);
      strict_cfg.strict_mode = 1;

      for (size_t i = 0;
           i < sizeof (malformed_responses) / sizeof (malformed_responses[0]);
           i++)
        {
          parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, &strict_cfg,
                                           arena);
          if (parser)
            {
              SocketHTTP1_Parser_execute (parser, malformed_responses[i],
                                          strlen (malformed_responses[i]),
                                          &consumed);
              SocketHTTP1_Parser_free (&parser);
            }
        }
    }

    /* ====================================================================
     * Test 6: Chunked responses with trailers
     * ==================================================================== */
    {
      const char *chunked_responses[] = {
        /* Basic chunked */
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: "
        "chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        /* Multiple chunks */
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: "
        "chunked\r\n\r\n5\r\nhello\r\n6\r\n "
        "world\r\n0\r\n\r\n",
        /* Chunked with extensions */
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: "
        "chunked\r\n\r\n5;ext=value\r\nhello\r\n0\r\n\r\n",
        /* Chunked with trailers */
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: "
        "X-Checksum\r\n\r\n5\r\nhello\r\n0\r\nX-Checksum: abc123\r\n\r\n",
        /* Empty chunked */
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        /* Hex chunk sizes */
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: "
        "chunked\r\n\r\na\r\n0123456789\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: "
        "chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: "
        "chunked\r\n\r\nf\r\n012345678901234\r\n0\r\n\r\n",
      };

      for (size_t i = 0;
           i < sizeof (chunked_responses) / sizeof (chunked_responses[0]); i++)
        {
          parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
          if (parser)
            {
              result = SocketHTTP1_Parser_execute (
                  parser, chunked_responses[i], strlen (chunked_responses[i]),
                  &consumed);

              if (result == HTTP1_OK)
                {
                  /* Read the body */
                  char body_buf[1024];
                  size_t body_consumed, body_written;
                  size_t remaining = strlen (chunked_responses[i]) - consumed;

                  while (remaining > 0
                         && !SocketHTTP1_Parser_body_complete (parser))
                    {
                      SocketHTTP1_Parser_read_body (
                          parser, chunked_responses[i] + consumed, remaining,
                          &body_consumed, body_buf, sizeof (body_buf),
                          &body_written);

                      if (body_consumed == 0)
                        break;
                      consumed += body_consumed;
                      remaining -= body_consumed;
                    }
                }

              SocketHTTP1_Parser_free (&parser);
            }
        }
    }

    /* ====================================================================
     * Test 7: Keep-alive handling
     * ==================================================================== */
    {
      const char *keepalive_responses[] = {
        /* HTTP/1.1 default keep-alive */
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        /* Explicit keep-alive */
        "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: "
        "5\r\n\r\nhello",
        /* Explicit close */
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
        "5\r\n\r\nhello",
        /* HTTP/1.0 default close */
        "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        /* HTTP/1.0 with keep-alive */
        "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: "
        "5\r\n\r\nhello",
      };

      for (size_t i = 0;
           i < sizeof (keepalive_responses) / sizeof (keepalive_responses[0]);
           i++)
        {
          parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
          if (parser)
            {
              SocketHTTP1_Parser_execute (parser, keepalive_responses[i],
                                          strlen (keepalive_responses[i]),
                                          &consumed);

              int should_keepalive
                  = SocketHTTP1_Parser_should_keepalive (parser);
              (void)should_keepalive;

              SocketHTTP1_Parser_free (&parser);
            }
        }
    }

    /* ====================================================================
     * Test 8: Build response with fuzzed components
     * ==================================================================== */
    if (size > 10)
      {
        char response_buf[8192];
        int resp_len;

        /* Use fuzz data to construct a response */
        int status_code = 100 + (((int)data[0] << 8 | data[1]) % 500);

        size_t body_len = data[2];
        if (body_len > size - 10)
          body_len = size - 10;

        resp_len = snprintf (response_buf, sizeof (response_buf),
                             "HTTP/1.1 %d %s\r\n"
                             "Content-Length: %zu\r\n"
                             "\r\n",
                             status_code, SocketHTTP_status_reason (status_code),
                             body_len);

        if (resp_len > 0
            && (size_t)resp_len + body_len < sizeof (response_buf))
          {
            memcpy (response_buf + resp_len, data + 3, body_len);

            parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
            if (parser)
              {
                SocketHTTP1_Parser_execute (parser, response_buf,
                                            resp_len + body_len, &consumed);
                exercise_parser_accessors (parser);
                SocketHTTP1_Parser_free (&parser);
              }
          }
      }

    /* ====================================================================
     * Test 9: Responses with multiple Set-Cookie headers
     * ==================================================================== */
    {
      const char *cookie_response
          = "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: session=abc123; Path=/; HttpOnly\r\n"
            "Set-Cookie: user=john; Path=/; Secure\r\n"
            "Set-Cookie: tracking=xyz; Path=/; SameSite=Strict\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "OK";

      parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
      if (parser)
        {
          SocketHTTP1_Parser_execute (parser, cookie_response,
                                      strlen (cookie_response), &consumed);

          const SocketHTTP_Response *resp
              = SocketHTTP1_Parser_get_response (parser);
          if (resp && resp->headers)
            {
              /* Get all cookies */
              const char *cookies[10];
              size_t count = SocketHTTP_Headers_get_all (resp->headers,
                                                         "Set-Cookie", cookies,
                                                         10);
              (void)count;
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
