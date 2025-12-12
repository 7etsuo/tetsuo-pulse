/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_ws_handshake.c - WebSocket Handshake Fuzzing Harness
 *
 * Tests handshake validation with random HTTP responses.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/SocketCrypto.h"
#include "http/SocketHTTP1.h"

/**
 * LLVMFuzzerTestOneInput - LibFuzzer entry point
 *
 * Tests HTTP/1.1 response parsing for WebSocket upgrade.
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketHTTP1_Parser_T parser = NULL;
  size_t consumed;
  SocketHTTP1_Result result;

  if (size == 0 || size > 65536)
    return 0;

  arena = Arena_new ();
  if (!arena)
    return 0;

  /* Create HTTP response parser */
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
  if (!parser)
    {
      Arena_dispose (&arena);
      return 0;
    }

  /* Parse the fuzzed input as HTTP response */
  result = SocketHTTP1_Parser_execute (parser, (const char *)data, size,
                                       &consumed);

  /* If parsing succeeded, validate WebSocket-specific headers */
  if (result == HTTP1_OK)
    {
      const SocketHTTP_Response *response
          = SocketHTTP1_Parser_get_response (parser);

      if (response && response->headers)
        {
          /* Try to access headers that would be checked during handshake */
          (void)SocketHTTP_Headers_get (response->headers, "Upgrade");
          (void)SocketHTTP_Headers_get (response->headers, "Connection");
          (void)SocketHTTP_Headers_get (response->headers,
                                        "Sec-WebSocket-Accept");
          (void)SocketHTTP_Headers_get (response->headers,
                                        "Sec-WebSocket-Protocol");
          (void)SocketHTTP_Headers_get (response->headers,
                                        "Sec-WebSocket-Extensions");
        }
    }

  /* Cleanup */
  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);

  return 0;
}
