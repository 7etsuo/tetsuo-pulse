/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_proxy_http.c - Fuzzing harness for HTTP CONNECT response parsing
 *
 * Part of the Socket Library
 *
 * Performance Optimization:
 * - Uses static arena with Arena_clear() for reuse
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

/* Static arena for reuse across invocations */
static Arena_T g_arena = NULL;

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
  struct SocketProxy_Conn_T conn;

  /* Skip empty input */
  if (size == 0)
    return 0;

  /* Ensure arena exists and clear for reuse */
  if (!g_arena)
    {
      g_arena = Arena_new ();
      if (!g_arena)
        return 0;
    }
  Arena_clear (g_arena);

  /* Initialize connection structure */
  memset (&conn, 0, sizeof (conn));
  conn.arena = g_arena;
  conn.http_parser = NULL;

  /* Copy fuzzed data into receive buffer */
  memcpy (conn.recv_buf, data,
          size < sizeof (conn.recv_buf) ? size : sizeof (conn.recv_buf) - 1);
  conn.recv_len
      = size < sizeof (conn.recv_buf) ? size : sizeof (conn.recv_buf) - 1;

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

  /* Cleanup parser but keep arena for reuse */
  if (conn.http_parser)
    {
      SocketHTTP1_Parser_free (&conn.http_parser);
    }

  return 0;
}
