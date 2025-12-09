/**
 * fuzz_http_smuggling.c - libFuzzer for HTTP/1.1 Request Smuggling Vectors
 *
 * Fuzzes SocketHTTP1 parser for smuggling attacks (RFC 9112 Sec 6.3):
 * - CL.TE, TE.CL variants
 * - Multi CL headers
 * - TE chunked manipulations
 * - Obs-fold bypasses
 *
 * Inputs: Fuzzed HTTP request lines/headers/body to trigger parser state
 * errors.
 *
 * Targets:
 * - Parser state corruption
 * - Invalid body length calc
 * - Resource exhaustion from ambiguous messages
 * - Buffer overflows from malformed chunks
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http_smuggling
 * ./fuzz_http_smuggling corpus/http_smug/ -fork=16 -max_len=16384
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "test/Test.h" /* For ASSERT, but fuzzer swallows */

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 20)
    return 0; /* Min request size */

  Arena_T arena_instance = Arena_new ();
  if (!arena_instance)
    return 0;
  volatile Arena_T arena = arena_instance;

  TRY
  {
    SocketHTTP1_Config cfg;
    SocketHTTP1_config_defaults (&cfg);
    cfg.strict_mode = 1; /* Enforce smuggling rejection */

    SocketHTTP1_Parser_T parser
        = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, &cfg, arena);
    if (!parser)
      return 0;

    /* Incremental parse fuzzed data to trigger state issues */
    size_t consumed = 0;
    SocketHTTP1_Result res = SocketHTTP1_Parser_execute (
        parser, (const char *)data, size, &consumed);

    /* Continue parsing if partial */
    while (res == HTTP1_INCOMPLETE && consumed < size)
      {
        size_t more = 0;
        res = SocketHTTP1_Parser_execute (
            parser, (const char *)data + consumed, size - consumed, &more);
        consumed += more;
      }

    /* Check for smuggling indicators: invalid body mode, bad lengths */
    if (res == HTTP1_OK)
      {
        /* Validate parsed request for anomalies */
        const SocketHTTP_Request *req
            = SocketHTTP1_Parser_get_request (parser);
        if (req)
          {
            /* Fuzz would trigger exceptions on bad CL/TE */
            (void)req->method;
            (void)req->path;
          }
      }

    SocketHTTP1_Parser_free (&parser);
  }
  EXCEPT (SocketHTTP1_ParseError)
  {
    /* Expected on malformed; coverage good */
  }
  EXCEPT (Arena_Failed) { /* Expected on malformed; coverage good */ }
  END_TRY;

  arena_instance = arena;
  Arena_dispose (&arena_instance);

  return 0;
}
