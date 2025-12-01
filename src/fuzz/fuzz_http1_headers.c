/**
 * fuzz_http1_headers.c - Fuzzing harness for HTTP/1.1 header parsing
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 */

#include "core/Arena.h"
#include "http/SocketHTTP.h"
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
  char *request = NULL;
  size_t request_len;
  const char *prefix = "GET / HTTP/1.1\r\n";
  const char *suffix = "\r\n";

  /* Skip empty or too large input */
  if (size == 0 || size > 65536)
    return 0;

  /* Create arena */
  arena = Arena_new ();
  if (!arena)
    return 0;

  /* Build request with fuzzed headers */
  request_len = strlen (prefix) + size + strlen (suffix);
  request = Arena_alloc (arena, request_len + 1, __FILE__, __LINE__);
  if (!request)
    {
      Arena_dispose (&arena);
      return 0;
    }

  memcpy (request, prefix, strlen (prefix));
  memcpy (request + strlen (prefix), data, size);
  memcpy (request + strlen (prefix) + size, suffix, strlen (suffix));
  request[request_len] = '\0';

  /* Create parser */
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
  if (!parser)
    {
      Arena_dispose (&arena);
      return 0;
    }

  /* Parse */
  SocketHTTP1_Parser_execute (parser, request, request_len, &consumed);

  /* If parsing succeeded, exercise header accessors */
  if (SocketHTTP1_Parser_state (parser) >= HTTP1_STATE_BODY)
    {
      const SocketHTTP_Request *req = SocketHTTP1_Parser_get_request (parser);
      if (req && req->headers)
        {
          /* Test various header operations */
          SocketHTTP_Headers_get (req->headers, "Host");
          SocketHTTP_Headers_get (req->headers, "Content-Length");
          SocketHTTP_Headers_get (req->headers, "Transfer-Encoding");
          SocketHTTP_Headers_has (req->headers, "Connection");
          SocketHTTP_Headers_count (req->headers);

          /* Iterate headers */
          size_t count = SocketHTTP_Headers_count (req->headers);
          for (size_t i = 0; i < count && i < 100; i++)
            {
              SocketHTTP_Headers_at (req->headers, i);
            }
        }
    }

  /* Try serialization if we have a valid request */
  if (SocketHTTP1_Parser_state (parser) >= HTTP1_STATE_BODY)
    {
      const SocketHTTP_Request *req = SocketHTTP1_Parser_get_request (parser);
      if (req)
        {
          char serialize_buf[8192];
          SocketHTTP1_serialize_request (req, serialize_buf,
                                         sizeof (serialize_buf));
        }
    }

  /* Cleanup */
  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);

  return 0;
}

