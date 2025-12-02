/**
 * fuzz_proxy_url.c - Fuzzing harness for proxy URL parsing
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
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

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketProxy_Config config;
  Arena_T arena = NULL;
  char *url_buf = NULL;

  /* Skip empty input */
  if (size == 0)
    return 0;

  /* Limit URL length to prevent excessive memory use */
  if (size > 2048)
    size = 2048;

  /* Create null-terminated URL string */
  url_buf = malloc (size + 1);
  if (!url_buf)
    return 0;

  memcpy (url_buf, data, size);
  url_buf[size] = '\0';

  /* Test URL parsing without arena (uses static buffer) */
  SocketProxy_parse_url (url_buf, &config, NULL);

  /* Test URL parsing with arena */
  arena = Arena_new ();
  if (arena)
    {
      SocketProxy_parse_url (url_buf, &config, arena);
      Arena_dispose (&arena);
    }

  /* Cleanup */
  free (url_buf);

  return 0;
}

