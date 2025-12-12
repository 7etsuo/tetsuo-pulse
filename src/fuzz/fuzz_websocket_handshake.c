/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_websocket_handshake.c - WebSocket HTTP handshake parsing fuzzer
 *
 * Tests WebSocket upgrade request parsing and validation with malformed inputs
 * to find vulnerabilities in handshake header processing.
 *
 * Targets:
 * - Sec-WebSocket-Key header validation
 * - Sec-WebSocket-Version header checking
 * - Sec-WebSocket-Protocol negotiation
 * - Sec-WebSocket-Extensions parsing
 * - Origin header validation
 * - Host header validation
 * - Upgrade/WebSocket header presence
 * - Connection: Upgrade header validation
 * - Malformed HTTP request handling
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_websocket_handshake
 * ./fuzz_websocket_handshake corpus/websocket_handshake/ -fork=16 -max_len=8192
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "socket/SocketWS.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Valid WebSocket upgrade request template */
static const char *ws_upgrade_template
    = "GET /websocket HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Key: %s\r\n"
      "Sec-WebSocket-Version: 13\r\n"
      "Origin: http://example.com\r\n"
      "\r\n";

/* Common WebSocket keys for testing */
static const char *valid_ws_keys[] = {
  "dGhlIHNhbXBsZSBub25jZQ==",
  "dGVzdA==",
  "MTIzNDU2Nzg5MDEyMzQ1Ng==",
  "QUJDREVGR0hJSktMTU5PUQ==",
  "eHh4eHh4eHh4eHh4eHh4eA==",
};

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketHTTP1_Parser_T parser = NULL;
  char request_buffer[8192];
  size_t consumed;

  /* Skip empty input */
  if (size == 0)
    return 0;

  arena = Arena_new ();
  if (!arena)
    return 0;

  TRY
  {
    SocketHTTP1_Config cfg;
    SocketHTTP1_config_defaults (&cfg);
    cfg.strict_mode = 1;

    /* Test 1: Direct fuzzing of HTTP request parsing */
    parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, arena);
    if (parser)
      {
        SocketHTTP1_Parser_execute (parser, (const char *)data, size,
                                    &consumed);

        if (SocketHTTP1_Parser_state (parser) >= HTTP1_STATE_BODY)
          {
            const SocketHTTP_Request *request
                = SocketHTTP1_Parser_get_request (parser);
            if (request)
              {
                /* Test WebSocket upgrade detection */
                int is_upgrade = SocketWS_is_upgrade (request);
                (void)is_upgrade;

                /* Test header access patterns */
                const char *upgrade
                    = SocketHTTP_Headers_get (request->headers, "Upgrade");
                const char *connection
                    = SocketHTTP_Headers_get (request->headers, "Connection");
                const char *ws_key = SocketHTTP_Headers_get (
                    request->headers, "Sec-WebSocket-Key");
                const char *ws_version = SocketHTTP_Headers_get (
                    request->headers, "Sec-WebSocket-Version");

                if (upgrade && connection && ws_key && ws_version)
                  {
                    int valid_upgrade = (strcasecmp (upgrade, "websocket") == 0);
                    int valid_version = (strcmp (ws_version, "13") == 0);
                    (void)valid_upgrade;
                    (void)valid_version;
                  }
              }
          }
        SocketHTTP1_Parser_free (&parser);
        parser = NULL;
      }

    /* Test 2: Template-based fuzzing with valid structure */
    if (size <= 256)
      {
        char fuzzed_key[257];
        size_t key_len = size > 255 ? 255 : size;
        memcpy (fuzzed_key, data, key_len);
        fuzzed_key[key_len] = '\0';

        /* Make printable */
        for (size_t i = 0; i < key_len; i++)
          {
            fuzzed_key[i] = (data[i] % 64) + 32;
          }

        int request_len = snprintf (request_buffer, sizeof (request_buffer),
                                    ws_upgrade_template, fuzzed_key);

        if (request_len > 0 && (size_t)request_len < sizeof (request_buffer))
          {
            parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, arena);
            if (parser)
              {
                SocketHTTP1_Parser_execute (parser, request_buffer, request_len,
                                            &consumed);
                SocketHTTP1_Parser_free (&parser);
                parser = NULL;
              }
          }
      }

    /* Test 3: Various malformed WebSocket headers */
    const char *malformed_requests[] = {
      "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: WEBSOCKET\r\nConnection: "
      "Upgrade\r\nSec-WebSocket-Key: dGVzdA==\r\nSec-WebSocket-Version: "
      "13\r\n\r\n",
      "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: "
      "keep-alive\r\nSec-WebSocket-Key: dGVzdA==\r\nSec-WebSocket-Version: "
      "13\r\n\r\n",
      "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: "
      "Upgrade\r\nSec-WebSocket-Key: \r\nSec-WebSocket-Version: 13\r\n\r\n",
      "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: "
      "Upgrade\r\nSec-WebSocket-Key: short\r\nSec-WebSocket-Version: "
      "13\r\n\r\n",
      "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: "
      "Upgrade\r\nSec-WebSocket-Key: dGVzdA==\r\nSec-WebSocket-Version: "
      "8\r\n\r\n",
    };

    for (size_t i = 0;
         i < sizeof (malformed_requests) / sizeof (malformed_requests[0]); i++)
      {
        parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, arena);
        if (parser)
          {
            SocketHTTP1_Parser_execute (parser, malformed_requests[i],
                                        strlen (malformed_requests[i]),
                                        &consumed);

            if (SocketHTTP1_Parser_state (parser) >= HTTP1_STATE_BODY)
              {
                const SocketHTTP_Request *request
                    = SocketHTTP1_Parser_get_request (parser);
                if (request)
                  {
                    int is_upgrade = SocketWS_is_upgrade (request);
                    (void)is_upgrade;
                  }
              }
            SocketHTTP1_Parser_free (&parser);
            parser = NULL;
          }
      }

    /* Test 4: Valid keys */
    for (size_t i = 0;
         i < sizeof (valid_ws_keys) / sizeof (valid_ws_keys[0]); i++)
      {
        char valid_request[1024];
        int len = snprintf (valid_request, sizeof (valid_request),
                            ws_upgrade_template, valid_ws_keys[i]);

        if (len > 0 && (size_t)len < sizeof (valid_request))
          {
            parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, arena);
            if (parser)
              {
                SocketHTTP1_Parser_execute (parser, valid_request, len,
                                            &consumed);

                if (SocketHTTP1_Parser_state (parser) >= HTTP1_STATE_BODY)
                  {
                    const SocketHTTP_Request *request
                        = SocketHTTP1_Parser_get_request (parser);
                    if (request)
                      {
                        int is_upgrade = SocketWS_is_upgrade (request);
                        (void)is_upgrade;
                      }
                  }
                SocketHTTP1_Parser_free (&parser);
                parser = NULL;
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

  if (parser)
    SocketHTTP1_Parser_free (&parser);

  Arena_dispose (&arena);

  return 0;
}
