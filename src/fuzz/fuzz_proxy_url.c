/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_proxy_url.c - Fuzzing harness for proxy URL parsing
 *
 * Part of the Socket Library
 *
 * Performance Optimization:
 * - Uses static arena with Arena_clear() for reuse
 * - Uses stack buffer instead of malloc
 *
 * Fuzzes proxy URL parsing:
 * - All supported schemes (http, https, socks4, socks4a, socks5, socks5h)
 * - Username/password parsing
 * - Host/port parsing
 * - IPv6 address handling
 */

#include "core/Arena.h"
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
  SocketProxy_Config config;
  char url_buf[2049]; /* Stack buffer to avoid malloc */

  /* Skip empty input */
  if (size == 0)
    return 0;

  /* Limit URL length */
  if (size > 2048)
    size = 2048;

  /* Create null-terminated URL string on stack */
  memcpy (url_buf, data, size);
  url_buf[size] = '\0';

  /* Clear arena for reuse */
  if (g_arena)
    Arena_clear (g_arena);

  /* Test URL parsing without arena (uses static buffer) */
  SocketProxy_parse_url (url_buf, &config, NULL);

  /* Test URL parsing with arena */
  if (g_arena)
    SocketProxy_parse_url (url_buf, &config, g_arena);

  return 0;
}
