/**
 * fuzz_http1_chunked.c - Fuzzing harness for HTTP/1.1 chunked encoding
 *
 * Part of the Socket Library
 */

#include "core/Arena.h"
#include "http/SocketHTTP1.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Prefix to make parser think we're reading chunked body */
static const char *chunked_request = "POST / HTTP/1.1\r\n"
                                     "Host: test.com\r\n"
                                     "Transfer-Encoding: chunked\r\n"
                                     "\r\n";

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketHTTP1_Parser_T parser = NULL;
  size_t consumed;
  SocketHTTP1_Result result;
  char body_buf[8192];
  size_t body_consumed, body_written;

  /* Skip empty input */
  if (size == 0)
    return 0;

  /* Create arena and parser */
  arena = Arena_new ();
  if (!arena)
    return 0;

  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, arena);
  if (!parser)
    {
      Arena_dispose (&arena);
      return 0;
    }

  /* Parse the fixed chunked request headers */
  result = SocketHTTP1_Parser_execute (parser, chunked_request,
                                       strlen (chunked_request), &consumed);

  if (result != HTTP1_OK)
    {
      SocketHTTP1_Parser_free (&parser);
      Arena_dispose (&arena);
      return 0;
    }

  /* Now feed the fuzzed data as chunked body */
  result = SocketHTTP1_Parser_read_body (parser, (const char *)data, size,
                                         &body_consumed, body_buf,
                                         sizeof (body_buf), &body_written);

  /* Try chunk encoding the data */
  if (size < 4096)
    {
      char encode_buf[16384];
      SocketHTTP1_chunk_encode (data, size, encode_buf, sizeof (encode_buf));
    }

  /* Cleanup */
  SocketHTTP1_Parser_free (&parser);
  Arena_dispose (&arena);

  return 0;
}

