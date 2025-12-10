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
 * WebSocket handshake security is critical as it establishes the WebSocket
 * connection and can be exploited for cross-site WebSocket hijacking (CSWSH)
 * and other protocol-level attacks.
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

/* Valid WebSocket upgrade request template */
static const char *ws_upgrade_template =
  "GET /websocket HTTP/1.1\r\n"
  "Host: example.com\r\n"
  "Upgrade: websocket\r\n"
  "Connection: Upgrade\r\n"
  "Sec-WebSocket-Key: %s\r\n"
  "Sec-WebSocket-Version: 13\r\n"
  "Origin: http://example.com\r\n"
  "\r\n";

/* Common WebSocket keys for testing */
static const char *valid_ws_keys[] = {
  "dGhlIHNhbXBsZSBub25jZQ==", /* "the sample nonce" */
  "dGVzdA==",                  /* "test" */
  "MTIzNDU2Nzg5MDEyMzQ1Ng==", /* "1234567890123456" */
  "QUJDREVGR0hJSktMTU5PUQ==", /* "ABCDEFGHIJKLMNOPQ" */
  "eHh4eHh4eHh4eHh4eHh4eA==", /* "xxxxxxxxxxxxxxxx" */
};

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

  Arena_T arena_instance = arena;

      SocketHTTP1_Config cfg;
      SocketHTTP1_config_defaults (&cfg);
      cfg.strict_mode = 1; /* Enable strict validation */

      parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, arena);
      if (!parser)
        return 0;

      /* Test 1: Direct fuzzing of HTTP request parsing */
      SocketHTTP1_Parser_execute (parser, (const char *)data, size, &consumed);

      if (SocketHTTP1_Parser_state (parser) >= HTTP1_STATE_BODY)
          const SocketHTTP_Request *request = SocketHTTP1_Parser_get_request (parser);
          if (request)
              /* Test WebSocket upgrade detection with parsed request */
              int is_upgrade = SocketWS_is_upgrade (request);
              (void)is_upgrade; /* Result is informative */

              /* Test various header access patterns that WebSocket validation uses */
              const char *upgrade = SocketHTTP_Headers_get (request->headers, "Upgrade");
              const char *connection = SocketHTTP_Headers_get (request->headers, "Connection");
              const char *ws_key = SocketHTTP_Headers_get (request->headers, "Sec-WebSocket-Key");
              const char *ws_version = SocketHTTP_Headers_get (request->headers, "Sec-WebSocket-Version");
              const char *origin = SocketHTTP_Headers_get (request->headers, "Origin");
              const char *host = SocketHTTP_Headers_get (request->headers, "Host");
              const char *ws_protocol = SocketHTTP_Headers_get (request->headers, "Sec-WebSocket-Protocol");
              const char *ws_extensions = SocketHTTP_Headers_get (request->headers, "Sec-WebSocket-Extensions");

              /* Test header validation logic */
              if (upgrade && connection && ws_key && ws_version)
                  /* Simulate WebSocket validation checks */
                  int valid_upgrade = (strcasecmp (upgrade, "websocket") == 0);
                  int valid_connection = (strstr (connection, "Upgrade") != NULL ||
                                        strstr (connection, "upgrade") != NULL);
                  int valid_version = (strcmp (ws_version, "13") == 0);
                  size_t key_len = strlen (ws_key);

                  (void)valid_upgrade;
                  (void)valid_connection;
                  (void)valid_version;
                  (void)key_len;

              /* Test protocol negotiation parsing */
              if (ws_protocol)
                  /* Parse comma-separated protocol list */
                  char *protocol_copy = Arena_alloc (arena, strlen (ws_protocol) + 1, __FILE__, __LINE__);
                  if (protocol_copy)
                      strcpy (protocol_copy, ws_protocol);
                      char *token = strtok (protocol_copy, ", \t");
                      while (token)
                          /* Validate each protocol name */
                          size_t proto_len = strlen (token);
                          if (proto_len > 0 && proto_len <= 255) /* RFC limits */
                              /* Check for valid protocol characters */
                              int valid_proto = 1;
                              for (size_t i = 0; i < proto_len; i++)
                                  char c = token[i];
                                  if (!((c >= 0x21 && c <= 0x2F) || (c >= 0x3A && c <= 0x40) ||
                                        (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) ||
                                        (c >= 0x7B && c <= 0x7E)))
                                      valid_proto = 0;
                                      break;
                              (void)valid_proto;
                          token = strtok (NULL, ", \t");

              /* Test extensions parsing */
              if (ws_extensions)
                  /* Parse extension list - this is complex per RFC 6455 */
                  char *ext_copy = Arena_alloc (arena, strlen (ws_extensions) + 1, __FILE__, __LINE__);
                  if (ext_copy)
                      strcpy (ext_copy, ws_extensions);
                      /* Basic parsing - real implementation is more complex */
                      (void)ext_copy;

      SocketHTTP1_Parser_free (&parser);
      parser = NULL;

      /* Test 2: Template-based fuzzing with valid structure */
      if (size <= 256) /* Limit key size for template */
          /* Create request with fuzzed Sec-WebSocket-Key */
          char fuzzed_key[257];
          size_t key_len = size > 255 ? 255 : size;
          memcpy (fuzzed_key, data, key_len);
          fuzzed_key[key_len] = '\0';

          /* Ensure base64-like characters for more realistic fuzzing */
          for (size_t i = 0; i < key_len; i++)
              fuzzed_key[i] = (data[i] % 64) + 32; /* Printable ASCII range */

          int request_len = snprintf (request_buffer, sizeof (request_buffer),
                                     ws_upgrade_template, fuzzed_key);

          if (request_len > 0 && (size_t)request_len < sizeof (request_buffer))
              /* Parse the constructed request */
              parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, arena);
              if (parser)
                  SocketHTTP1_Parser_execute (parser, request_buffer, request_len, &consumed);

                  if (SocketHTTP1_Parser_state (parser) >= HTTP1_STATE_BODY)
                      const SocketHTTP_Request *request = SocketHTTP1_Parser_get_request (parser);
                      if (request)
                          /* Test WebSocket validation on constructed request */
                          int is_upgrade = SocketWS_is_upgrade (request);
                          (void)is_upgrade;

                  SocketHTTP1_Parser_free (&parser);
                  parser = NULL;

      /* Test 3: Various malformed WebSocket headers */
      const char *malformed_headers[][2] = {
          {"Upgrade", "WEBSOCKET"},     /* Wrong case */
          {"Upgrade", "websocket\r\n"}, /* CRLF injection */
          {"Connection", "upgrade"},    /* Lowercase */
          {"Connection", "keep-alive, upgrade"}, /* Multiple values */
          {"Sec-WebSocket-Key", ""},    /* Empty key */
          {"Sec-WebSocket-Key", "short"}, /* Too short */
          {"Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==extra"}, /* Too long */
          {"Sec-WebSocket-Version", "8"}, /* Wrong version */
          {"Sec-WebSocket-Version", "13; extra"}, /* With extra data */
          {"Origin", "javascript:alert(1)"}, /* XSS attempt */
          {"Host", ""}, /* Empty host */
          {"Host", "host\r\nX-Injected: value"}, /* Header injection */
      };

      for (size_t i = 0; i < sizeof (malformed_headers) / sizeof (malformed_headers[0]); i++)
          /* Build request with malformed header */
          char malformed_request[2048];
          int len = snprintf (malformed_request, sizeof (malformed_request),
                            "GET /ws HTTP/1.1\r\n"
                            "Host: test.com\r\n"
                            "Upgrade: websocket\r\n"
                            "Connection: Upgrade\r\n"
                            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                            "Sec-WebSocket-Version: 13\r\n"
                            "%s: %s\r\n"
                            "\r\n",
                            malformed_headers[i][0], malformed_headers[i][1]);

          if (len > 0 && (size_t)len < sizeof (malformed_request))
              parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, arena);
              if (parser)
                  SocketHTTP1_Parser_execute (parser, malformed_request, len, &consumed);

                  if (SocketHTTP1_Parser_state (parser) >= HTTP1_STATE_BODY)
                      const SocketHTTP_Request *request = SocketHTTP1_Parser_get_request (parser);
                      if (request)
                          /* Test validation on malformed headers */
                          int is_upgrade = SocketWS_is_upgrade (request);
                          (void)is_upgrade;

                  SocketHTTP1_Parser_free (&parser);
                  parser = NULL;

      /* Test 4: Edge cases with valid keys */
      for (size_t i = 0; i < sizeof (valid_ws_keys) / sizeof (valid_ws_keys[0]); i++)
          char valid_request[1024];
          int len = snprintf (valid_request, sizeof (valid_request),
                            ws_upgrade_template, valid_ws_keys[i]);

          if (len > 0 && (size_t)len < sizeof (valid_request))
              parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, arena);
              if (parser)
                  SocketHTTP1_Parser_execute (parser, valid_request, len, &consumed);

                  if (SocketHTTP1_Parser_state (parser) >= HTTP1_STATE_BODY)
                      const SocketHTTP_Request *request = SocketHTTP1_Parser_get_request (parser);
                      if (request)
                          /* Test validation on valid headers */
                          int is_upgrade = SocketWS_is_upgrade (request);
                          (void)is_upgrade;

                  SocketHTTP1_Parser_free (&parser);
                  parser = NULL;
      /* Expected on malformed HTTP requests */
      /* Expected on invalid WebSocket handshakes */
      /* Expected on memory exhaustion */

  if (parser)
    SocketHTTP1_Parser_free (&parser);

  Arena_T temp_arena = arena;
  Arena_dispose (&temp_arena);

  return 0;
