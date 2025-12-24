/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_dnscookie.c
 * @brief Unit tests for DNS Cookies (RFC 7873).
 */

#include "core/Arena.h"
#include "dns/SocketDNSCookie.h"
#include "dns/SocketDNSWire.h"
#include "test/Test.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

/*
 * Test cookie cache creation
 */
TEST (cookie_cache_new)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketDNSCookie_T cache = SocketDNSCookie_new (arena);
  ASSERT_NOT_NULL (cache);

  SocketDNSCookie_free (&cache);
  ASSERT_NULL (cache);

  Arena_dispose (&arena);
}

/*
 * Test client cookie generation
 */
TEST (client_cookie_generation)
{
  Arena_T arena = Arena_new ();
  SocketDNSCookie_T cache = SocketDNSCookie_new (arena);

  struct sockaddr_in server;
  memset (&server, 0, sizeof (server));
  server.sin_family = AF_INET;
  server.sin_port = htons (53);
  inet_pton (AF_INET, "8.8.8.8", &server.sin_addr);

  SocketDNSCookie_Cookie cookie;
  int ret = SocketDNSCookie_generate (cache, (struct sockaddr *)&server,
                                      sizeof (server), NULL, 0, &cookie);

  ASSERT (ret == 0);

  /* Client cookie should be 8 bytes, non-zero */
  int all_zero = 1;
  for (int i = 0; i < DNS_CLIENT_COOKIE_SIZE; i++)
    {
      if (cookie.client_cookie[i] != 0)
        all_zero = 0;
    }
  ASSERT (!all_zero);

  /* No server cookie yet */
  ASSERT (cookie.server_cookie_len == 0);

  SocketDNSCookie_free (&cache);
  Arena_dispose (&arena);
}

/*
 * Test that same server gets same cookie
 */
TEST (client_cookie_deterministic)
{
  Arena_T arena = Arena_new ();
  SocketDNSCookie_T cache = SocketDNSCookie_new (arena);

  struct sockaddr_in server;
  memset (&server, 0, sizeof (server));
  server.sin_family = AF_INET;
  server.sin_port = htons (53);
  inet_pton (AF_INET, "8.8.8.8", &server.sin_addr);

  SocketDNSCookie_Cookie cookie1, cookie2;
  SocketDNSCookie_generate (cache, (struct sockaddr *)&server, sizeof (server),
                            NULL, 0, &cookie1);
  SocketDNSCookie_generate (cache, (struct sockaddr *)&server, sizeof (server),
                            NULL, 0, &cookie2);

  /* Same server should get same cookie */
  ASSERT (memcmp (cookie1.client_cookie, cookie2.client_cookie,
                  DNS_CLIENT_COOKIE_SIZE)
          == 0);

  SocketDNSCookie_free (&cache);
  Arena_dispose (&arena);
}

/*
 * Test different servers get different cookies
 */
TEST (client_cookie_per_server)
{
  Arena_T arena = Arena_new ();
  SocketDNSCookie_T cache = SocketDNSCookie_new (arena);

  struct sockaddr_in server1, server2;
  memset (&server1, 0, sizeof (server1));
  memset (&server2, 0, sizeof (server2));

  server1.sin_family = AF_INET;
  server1.sin_port = htons (53);
  inet_pton (AF_INET, "8.8.8.8", &server1.sin_addr);

  server2.sin_family = AF_INET;
  server2.sin_port = htons (53);
  inet_pton (AF_INET, "1.1.1.1", &server2.sin_addr);

  SocketDNSCookie_Cookie cookie1, cookie2;
  SocketDNSCookie_generate (cache, (struct sockaddr *)&server1, sizeof (server1),
                            NULL, 0, &cookie1);
  SocketDNSCookie_generate (cache, (struct sockaddr *)&server2, sizeof (server2),
                            NULL, 0, &cookie2);

  /* Different servers should get different cookies */
  ASSERT (memcmp (cookie1.client_cookie, cookie2.client_cookie,
                  DNS_CLIENT_COOKIE_SIZE)
          != 0);

  SocketDNSCookie_free (&cache);
  Arena_dispose (&arena);
}

/*
 * Test IPv6 cookie generation
 */
TEST (client_cookie_ipv6)
{
  Arena_T arena = Arena_new ();
  SocketDNSCookie_T cache = SocketDNSCookie_new (arena);

  struct sockaddr_in6 server;
  memset (&server, 0, sizeof (server));
  server.sin6_family = AF_INET6;
  server.sin6_port = htons (53);
  inet_pton (AF_INET6, "2001:4860:4860::8888", &server.sin6_addr);

  SocketDNSCookie_Cookie cookie;
  int ret = SocketDNSCookie_generate (cache, (struct sockaddr *)&server,
                                      sizeof (server), NULL, 0, &cookie);

  ASSERT (ret == 0);

  /* Client cookie should be non-zero */
  int all_zero = 1;
  for (int i = 0; i < DNS_CLIENT_COOKIE_SIZE; i++)
    {
      if (cookie.client_cookie[i] != 0)
        all_zero = 0;
    }
  ASSERT (!all_zero);

  SocketDNSCookie_free (&cache);
  Arena_dispose (&arena);
}

/*
 * Test cookie parsing - client only
 */
TEST (cookie_parse_client_only)
{
  unsigned char data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

  SocketDNSCookie_Cookie cookie;
  int ret = SocketDNSCookie_parse (data, sizeof (data), &cookie);

  ASSERT (ret == 0);
  ASSERT (memcmp (cookie.client_cookie, data, DNS_CLIENT_COOKIE_SIZE) == 0);
  ASSERT (cookie.server_cookie_len == 0);
}

/*
 * Test cookie parsing - client + server
 */
TEST (cookie_parse_with_server)
{
  unsigned char data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, /* client */
                          0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}; /* server */

  SocketDNSCookie_Cookie cookie;
  int ret = SocketDNSCookie_parse (data, sizeof (data), &cookie);

  ASSERT (ret == 0);
  ASSERT (memcmp (cookie.client_cookie, data, DNS_CLIENT_COOKIE_SIZE) == 0);
  ASSERT (cookie.server_cookie_len == 8);
  ASSERT (memcmp (cookie.server_cookie, data + 8, 8) == 0);
}

/*
 * Test cookie parsing - maximum server cookie
 */
TEST (cookie_parse_max_server)
{
  unsigned char data[40];
  for (int i = 0; i < 40; i++)
    data[i] = (unsigned char)i;

  SocketDNSCookie_Cookie cookie;
  int ret = SocketDNSCookie_parse (data, sizeof (data), &cookie);

  ASSERT (ret == 0);
  ASSERT (cookie.server_cookie_len == 32);
}

/*
 * Test cookie parsing - invalid length
 */
TEST (cookie_parse_invalid_length)
{
  unsigned char short_data[] = {0x01, 0x02, 0x03}; /* Too short */
  unsigned char gap_data[] = {0x01, 0x02, 0x03, 0x04, 0x05,
                              0x06, 0x07, 0x08, 0x09, 0x0a}; /* 10 bytes - gap */

  SocketDNSCookie_Cookie cookie;

  /* Too short */
  ASSERT (SocketDNSCookie_parse (short_data, sizeof (short_data), &cookie) == -1);

  /* Invalid gap (9-15 bytes not allowed) */
  ASSERT (SocketDNSCookie_parse (gap_data, sizeof (gap_data), &cookie) == -1);
}

/*
 * Test cookie encoding
 */
TEST (cookie_encode)
{
  SocketDNSCookie_Cookie cookie;
  memset (&cookie, 0, sizeof (cookie));

  for (int i = 0; i < DNS_CLIENT_COOKIE_SIZE; i++)
    cookie.client_cookie[i] = (uint8_t)(i + 1);

  cookie.server_cookie_len = 8;
  for (int i = 0; i < 8; i++)
    cookie.server_cookie[i] = (uint8_t)(0x10 + i);

  unsigned char buf[40];
  int len = SocketDNSCookie_encode (&cookie, buf, sizeof (buf));

  ASSERT (len == 16);
  ASSERT (buf[0] == 0x01 && buf[7] == 0x08);
  ASSERT (buf[8] == 0x10 && buf[15] == 0x17);
}

/*
 * Test cookie encode - client only
 */
TEST (cookie_encode_client_only)
{
  SocketDNSCookie_Cookie cookie;
  memset (&cookie, 0, sizeof (cookie));

  for (int i = 0; i < DNS_CLIENT_COOKIE_SIZE; i++)
    cookie.client_cookie[i] = (uint8_t)(i + 1);

  unsigned char buf[8];
  int len = SocketDNSCookie_encode (&cookie, buf, sizeof (buf));

  ASSERT (len == 8);
}

/*
 * Test server cookie caching
 */
TEST (cookie_cache_store_lookup)
{
  Arena_T arena = Arena_new ();
  SocketDNSCookie_T cache = SocketDNSCookie_new (arena);

  struct sockaddr_in server;
  memset (&server, 0, sizeof (server));
  server.sin_family = AF_INET;
  server.sin_port = htons (53);
  inet_pton (AF_INET, "8.8.8.8", &server.sin_addr);

  uint8_t client_cookie[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  uint8_t server_cookie[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                               0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};

  int ret = SocketDNSCookie_cache_store (cache, (struct sockaddr *)&server,
                                         sizeof (server), client_cookie,
                                         server_cookie, 16);
  ASSERT (ret == 0);

  /* Look up the cached cookie */
  SocketDNSCookie_Entry entry;
  ret = SocketDNSCookie_cache_lookup (cache, (struct sockaddr *)&server,
                                      sizeof (server), &entry);
  ASSERT (ret == 1);
  ASSERT (entry.server_cookie_len == 16);
  ASSERT (memcmp (entry.server_cookie, server_cookie, 16) == 0);

  SocketDNSCookie_free (&cache);
  Arena_dispose (&arena);
}

/*
 * Test cache miss
 */
TEST (cookie_cache_miss)
{
  Arena_T arena = Arena_new ();
  SocketDNSCookie_T cache = SocketDNSCookie_new (arena);

  struct sockaddr_in server;
  memset (&server, 0, sizeof (server));
  server.sin_family = AF_INET;
  server.sin_port = htons (53);
  inet_pton (AF_INET, "8.8.8.8", &server.sin_addr);

  /* Look up without storing first */
  SocketDNSCookie_Entry entry;
  int ret = SocketDNSCookie_cache_lookup (cache, (struct sockaddr *)&server,
                                          sizeof (server), &entry);
  ASSERT (ret == 0); /* Miss */

  SocketDNSCookie_free (&cache);
  Arena_dispose (&arena);
}

/*
 * Test cache invalidation
 */
TEST (cookie_cache_invalidate)
{
  Arena_T arena = Arena_new ();
  SocketDNSCookie_T cache = SocketDNSCookie_new (arena);

  struct sockaddr_in server;
  memset (&server, 0, sizeof (server));
  server.sin_family = AF_INET;
  server.sin_port = htons (53);
  inet_pton (AF_INET, "8.8.8.8", &server.sin_addr);

  uint8_t client_cookie[8] = {0};
  uint8_t server_cookie[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

  SocketDNSCookie_cache_store (cache, (struct sockaddr *)&server, sizeof (server),
                               client_cookie, server_cookie, 8);

  /* Invalidate */
  int ret = SocketDNSCookie_cache_invalidate (cache, (struct sockaddr *)&server,
                                              sizeof (server));
  ASSERT (ret == 1);

  /* Should be gone */
  ret = SocketDNSCookie_cache_lookup (cache, (struct sockaddr *)&server,
                                      sizeof (server), NULL);
  ASSERT (ret == 0);

  SocketDNSCookie_free (&cache);
  Arena_dispose (&arena);
}

/*
 * Test cookie validation
 */
TEST (cookie_validate)
{
  SocketDNSCookie_Cookie sent = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
                                 {0},
                                 0};

  SocketDNSCookie_Cookie response_good
      = {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
         {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
         8};

  SocketDNSCookie_Cookie response_bad
      = {{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8},
         {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
         8};

  ASSERT (SocketDNSCookie_validate (&sent, &response_good) == 1);
  ASSERT (SocketDNSCookie_validate (&sent, &response_bad) == 0);
}

/*
 * Test BADCOOKIE check
 */
TEST (badcookie_check)
{
  ASSERT (SocketDNSCookie_is_badcookie (DNS_RCODE_BADCOOKIE) == 1);
  ASSERT (SocketDNSCookie_is_badcookie (23) == 1);
  ASSERT (SocketDNSCookie_is_badcookie (0) == 0);
  ASSERT (SocketDNSCookie_is_badcookie (DNS_RCODE_NOERROR) == 0);
  ASSERT (SocketDNSCookie_is_badcookie (DNS_RCODE_NXDOMAIN) == 0);
}

/*
 * Test secret rotation
 */
TEST (secret_rotation)
{
  Arena_T arena = Arena_new ();
  SocketDNSCookie_T cache = SocketDNSCookie_new (arena);

  struct sockaddr_in server;
  memset (&server, 0, sizeof (server));
  server.sin_family = AF_INET;
  server.sin_port = htons (53);
  inet_pton (AF_INET, "8.8.8.8", &server.sin_addr);

  /* Get cookie before rotation */
  SocketDNSCookie_Cookie cookie1;
  SocketDNSCookie_generate (cache, (struct sockaddr *)&server, sizeof (server),
                            NULL, 0, &cookie1);

  /* Rotate secret */
  int ret = SocketDNSCookie_rotate_secret (cache);
  ASSERT (ret == 0);

  /* Get cookie after rotation */
  SocketDNSCookie_Cookie cookie2;
  SocketDNSCookie_generate (cache, (struct sockaddr *)&server, sizeof (server),
                            NULL, 0, &cookie2);

  /* Cookies should be different after rotation */
  ASSERT (memcmp (cookie1.client_cookie, cookie2.client_cookie,
                  DNS_CLIENT_COOKIE_SIZE)
          != 0);

  SocketDNSCookie_free (&cache);
  Arena_dispose (&arena);
}

/*
 * Test hex formatting
 */
TEST (cookie_to_hex)
{
  SocketDNSCookie_Cookie cookie;
  memset (&cookie, 0, sizeof (cookie));

  cookie.client_cookie[0] = 0x01;
  cookie.client_cookie[1] = 0x23;
  cookie.client_cookie[2] = 0x45;
  cookie.client_cookie[3] = 0x67;
  cookie.client_cookie[4] = 0x89;
  cookie.client_cookie[5] = 0xab;
  cookie.client_cookie[6] = 0xcd;
  cookie.client_cookie[7] = 0xef;

  char buf[80];
  int len = SocketDNSCookie_to_hex (&cookie, buf, sizeof (buf));

  ASSERT (len == 16);
  ASSERT (strcmp (buf, "0123456789abcdef") == 0);
}

/*
 * Test hex formatting with server cookie
 */
TEST (cookie_to_hex_with_server)
{
  SocketDNSCookie_Cookie cookie;
  memset (&cookie, 0, sizeof (cookie));

  for (int i = 0; i < 8; i++)
    cookie.client_cookie[i] = (uint8_t)i;

  cookie.server_cookie_len = 8;
  for (int i = 0; i < 8; i++)
    cookie.server_cookie[i] = (uint8_t)(0xA0 + i);

  char buf[80];
  int len = SocketDNSCookie_to_hex (&cookie, buf, sizeof (buf));

  ASSERT (len == 33); /* 16 + 1 + 16 */
  ASSERT (strstr (buf, ":") != NULL);
}

/*
 * Test cookie equality
 */
TEST (cookie_equality)
{
  SocketDNSCookie_Cookie a, b;
  memset (&a, 0, sizeof (a));
  memset (&b, 0, sizeof (b));

  for (int i = 0; i < 8; i++)
    {
      a.client_cookie[i] = (uint8_t)i;
      b.client_cookie[i] = (uint8_t)i;
    }

  ASSERT (SocketDNSCookie_equal (&a, &b) == 1);

  /* Differ in one byte */
  b.client_cookie[0] = 0xFF;
  ASSERT (SocketDNSCookie_equal (&a, &b) == 0);
}

/*
 * Test statistics
 */
TEST (cookie_stats)
{
  Arena_T arena = Arena_new ();
  SocketDNSCookie_T cache = SocketDNSCookie_new (arena);

  struct sockaddr_in server;
  memset (&server, 0, sizeof (server));
  server.sin_family = AF_INET;
  server.sin_port = htons (53);
  inet_pton (AF_INET, "8.8.8.8", &server.sin_addr);

  /* Generate some cookies */
  SocketDNSCookie_Cookie cookie;
  SocketDNSCookie_generate (cache, (struct sockaddr *)&server, sizeof (server),
                            NULL, 0, &cookie);

  SocketDNSCookie_Stats stats;
  SocketDNSCookie_stats (cache, &stats);

  ASSERT (stats.client_cookies_generated >= 1);
  ASSERT (stats.max_entries == DNS_COOKIE_CACHE_DEFAULT_SIZE);

  SocketDNSCookie_free (&cache);
  Arena_dispose (&arena);
}

/*
 * Test cache LRU eviction
 */
TEST (cookie_cache_lru_eviction)
{
  Arena_T arena = Arena_new ();
  SocketDNSCookie_T cache = SocketDNSCookie_new (arena);

  /* Set small cache size */
  SocketDNSCookie_set_cache_size (cache, 3);

  /* Add 4 entries (should evict first) */
  for (int i = 0; i < 4; i++)
    {
      struct sockaddr_in server;
      memset (&server, 0, sizeof (server));
      server.sin_family = AF_INET;
      server.sin_port = htons (53);
      server.sin_addr.s_addr = htonl (0x08080800 + i);

      uint8_t client_cookie[8] = {0};
      uint8_t server_cookie[8] = {0};

      SocketDNSCookie_cache_store (cache, (struct sockaddr *)&server,
                                   sizeof (server), client_cookie, server_cookie,
                                   8);
    }

  /* First entry should be evicted */
  struct sockaddr_in first;
  memset (&first, 0, sizeof (first));
  first.sin_family = AF_INET;
  first.sin_port = htons (53);
  first.sin_addr.s_addr = htonl (0x08080800);

  int ret = SocketDNSCookie_cache_lookup (cache, (struct sockaddr *)&first,
                                          sizeof (first), NULL);
  ASSERT (ret == 0); /* Should be evicted */

  /* Last entry should still be there */
  struct sockaddr_in last;
  memset (&last, 0, sizeof (last));
  last.sin_family = AF_INET;
  last.sin_port = htons (53);
  last.sin_addr.s_addr = htonl (0x08080803);

  ret = SocketDNSCookie_cache_lookup (cache, (struct sockaddr *)&last,
                                      sizeof (last), NULL);
  ASSERT (ret == 1); /* Should still be there */

  SocketDNSCookie_free (&cache);
  Arena_dispose (&arena);
}

/*
 * Main test entry point
 */
int
main (void)
{
  printf ("Running DNS Cookie tests...\n");
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
