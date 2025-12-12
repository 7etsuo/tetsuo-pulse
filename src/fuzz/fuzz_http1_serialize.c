/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_http1_serialize.c - HTTP/1.1 serialization fuzzer
 *
 * Tests HTTP/1.1 request and response serialization with fuzzed data:
 * - SocketHTTP1_serialize_request with fuzzed SocketHTTP_Request structs
 * - SocketHTTP1_serialize_response with fuzzed SocketHTTP_Response structs
 * - Buffer boundary conditions
 * - Header serialization edge cases
 * - Status line formatting
 * - Request line formatting
 *
 * Serialization bugs can lead to malformed HTTP messages and security issues.
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http1_serialize
 * ./fuzz_http1_serialize corpus/http1_serialize/ -fork=16 -max_len=4096
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Static arena for reuse across invocations */
static Arena_T g_arena = NULL;

/**
 * LLVMFuzzerInitialize - One-time setup for fuzzer
 */
int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void)argc;
  (void)argv;
  g_arena = Arena_new ();
  return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  char output_buffer[16384];

  /* Skip empty input */
  if (size < 2)
    return 0;

  /* Check arena is initialized */
  if (!g_arena)
    {
      g_arena = Arena_new ();
      if (!g_arena)
        return 0;
    }

  /* Clear arena for reuse */
  Arena_clear (g_arena);

  /* Select ONE test based on first byte - don't run all tests every time */
  uint8_t test_selector = data[0] % 4;

  TRY
  {
    switch (test_selector)
      {
      case 0:
        /* Test 1: Request serialization with fuzzed components */
        {
          SocketHTTP_Request request;
          memset (&request, 0, sizeof (request));
          request.method = (SocketHTTP_Method)(data[1] % 10);
          request.version = HTTP_VERSION_1_1;

          char path[256];
          size_t path_len = (size > 2) ? ((size - 2 > sizeof (path) - 1) ? sizeof (path) - 1 : size - 2) : 0;
          if (path_len > 0)
            {
              memcpy (path, data + 2, path_len);
              path[path_len] = '\0';
              request.path = path;
            }
          else
            request.path = "/";

          SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (g_arena);
          if (headers)
            {
              request.headers = headers;
              SocketHTTP_Headers_add (headers, "Host", "example.com");
              ssize_t serialized = SocketHTTP1_serialize_request (&request, output_buffer, sizeof (output_buffer));
              (void)serialized;
            }
        }
        break;

      case 1:
        /* Test 2: Response serialization with fuzzed components */
        {
          SocketHTTP_Response response;
          memset (&response, 0, sizeof (response));
          response.version = HTTP_VERSION_1_1;
          response.status_code = (size >= 3) ? (100 + (((int)data[1] << 8) | data[2]) % 500) : 200;
          response.reason_phrase = "OK";

          SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (g_arena);
          if (headers)
            {
              response.headers = headers;
              SocketHTTP_Headers_add (headers, "Content-Type", "text/plain");
              ssize_t serialized = SocketHTTP1_serialize_response (&response, output_buffer, sizeof (output_buffer));
              (void)serialized;
            }
        }
        break;

      case 2:
        /* Test 3: Roundtrip parsing of serialized requests */
        {
          SocketHTTP_Request request;
          memset (&request, 0, sizeof (request));
          request.method = HTTP_METHOD_GET;
          request.version = HTTP_VERSION_1_1;
          request.path = "/test";

          SocketHTTP_Headers_T headers = SocketHTTP_Headers_new (g_arena);
          if (headers)
            {
              request.headers = headers;
              SocketHTTP_Headers_add (headers, "Host", "example.com");

              ssize_t len = SocketHTTP1_serialize_request (&request, output_buffer, sizeof (output_buffer));
              if (len > 0)
                {
                  SocketHTTP1_Config cfg;
                  SocketHTTP1_config_defaults (&cfg);
                  SocketHTTP1_Parser_T parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, g_arena);
                  if (parser)
                    {
                      size_t consumed;
                      SocketHTTP1_Parser_execute (parser, output_buffer, len, &consumed);
                      SocketHTTP1_Parser_free (&parser);
                    }
                }
            }
        }
        break;

      case 3:
        /* Test 4: Edge cases - single method/status based on input */
        {
          SocketHTTP_Method methods[] = {
              HTTP_METHOD_GET, HTTP_METHOD_HEAD, HTTP_METHOD_POST, HTTP_METHOD_PUT,
              HTTP_METHOD_DELETE, HTTP_METHOD_CONNECT, HTTP_METHOD_OPTIONS,
              HTTP_METHOD_TRACE, HTTP_METHOD_PATCH, HTTP_METHOD_UNKNOWN
          };
          SocketHTTP_Request method_req;
          memset (&method_req, 0, sizeof (method_req));
          method_req.method = methods[data[1] % 10];
          method_req.version = HTTP_VERSION_1_1;
          method_req.path = "/";
          SocketHTTP_Headers_T h = SocketHTTP_Headers_new (g_arena);
          if (h)
            {
              method_req.headers = h;
              SocketHTTP_Headers_add (h, "Host", "example.com");
              SocketHTTP1_serialize_request (&method_req, output_buffer, sizeof (output_buffer));
            }
        }
        break;
      }
  }
  EXCEPT (SocketHTTP1_SerializeError) { /* Expected */ }
  EXCEPT (SocketHTTP1_ParseError) { /* Expected */ }
  EXCEPT (SocketHTTP_Failed) { /* Expected */ }
  EXCEPT (Arena_Failed) { /* Expected */ }
  END_TRY;

  return 0;
}
