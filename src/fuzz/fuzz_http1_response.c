/**
 * fuzz_http1_response.c - Fuzzing harness for HTTP/1.1 response parsing
 *
 * Part of the Socket Library
 */

#include "core/Arena.h"
#include "http/SocketHTTP1.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

  /* Create arena and parser */
  arena = Arena_new ();
  if (!arena)
    return 0;

  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_RESPONSE, NULL, arena);
  if (!parser)
    {
      Arena_dispose (&arena);
      return 0;
    }

  /* Parse the fuzzed input */
  result = SocketHTTP1_Parser_execute (parser, (const char *)data, size,
                                       &consumed);

  /* If headers parsed, try to read body */
  if (result == HTTP1_OK
      && SocketHTTP1_Parser_state (parser) >= HTTP1_STATE_BODY)
    {
      char body_buf[4096];
      size_t body_consumed, body_written;
      size_t remaining = size - consumed;

      if (remaining > 0)
        {
          SocketHTTP1_Parser_read_body (
              parser, (const char *)data + consumed, remaining, &body_consumed,
              body_buf, sizeof (body_buf), &body_written);
        }
    }

  /* Cleanup */
  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);

  return 0;
}

