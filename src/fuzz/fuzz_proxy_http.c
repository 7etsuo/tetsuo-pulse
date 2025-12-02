/**
 * fuzz_proxy_http.c - Fuzzing harness for HTTP CONNECT response parsing
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Fuzzes HTTP CONNECT response parsing:
 * - Uses SocketHTTP1_Parser_T internally
 * - Tests status code mapping
 */

#include "core/Arena.h"
#include "socket/SocketProxy-private.h"
#include "socket/SocketProxy.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct SocketProxy_Conn_T conn;
  Arena_T arena = NULL;

  /* Skip empty input */
  if (size == 0)
    return 0;

  /* Create arena for HTTP parser */
  arena = Arena_new ();
  if (!arena)
    return 0;

  /* Initialize connection structure */
  memset (&conn, 0, sizeof (conn));
  conn.arena = arena;
  conn.http_parser = NULL;

  /* Copy fuzzed data into receive buffer */
  memcpy (conn.recv_buf, data, size < sizeof (conn.recv_buf)
                                   ? size
                                   : sizeof (conn.recv_buf) - 1);
  conn.recv_len = size < sizeof (conn.recv_buf) ? size : sizeof (conn.recv_buf) - 1;

  /* Test HTTP response parsing */
  proxy_http_recv_response (&conn);

  /* Test status code mapping with various codes from input */
  if (size >= 2)
    {
      int status = ((int)data[0] << 8) | (int)data[1];
      /* Limit to reasonable HTTP status code range */
      status = 100 + (status % 500);
      proxy_http_status_to_result (status);
    }

  /* Cleanup */
  if (conn.http_parser)
    {
      SocketHTTP1_Parser_free (&conn.http_parser);
    }
  Arena_dispose (&arena);

  return 0;
}

