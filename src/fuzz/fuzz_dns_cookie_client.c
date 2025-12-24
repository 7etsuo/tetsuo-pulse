/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dns_cookie_client.c - libFuzzer harness for DNS Cookie client logic
 *
 * Fuzzes DNS Cookie client-side operations (RFC 7873).
 *
 * Targets:
 * - SocketDNSCookie_new() - Cookie cache initialization
 * - SocketDNSCookie_generate() - Client cookie generation with HMAC-SHA256
 * - SocketDNSCookie_validate() - Response cookie validation
 * - SocketDNSCookie_cache_store() - Server cookie storage
 * - SocketDNSCookie_cache_lookup() - Cache hit/miss testing
 * - SocketDNSCookie_cache_invalidate() - BADCOOKIE handling
 * - SocketDNSCookie_cache_expire() - TTL expiration logic
 * - SocketDNSCookie_rotate_secret() - Secret rollover
 * - SocketDNSCookie_set_secret_lifetime() - Configuration
 * - SocketDNSCookie_set_cache_size() - LRU eviction
 * - SocketDNSCookie_set_server_ttl() - TTL configuration
 * - SocketDNSCookie_stats() - Statistics tracking
 *
 * Test cases:
 * - Client cookie generation for IPv4/IPv6
 * - Server cookie caching and lookup
 * - Cookie validation and constant-time comparison
 * - Secret rotation and rollover period
 * - Cache eviction (LRU policy)
 * - TTL expiration
 * - BADCOOKIE response handling
 * - Edge cases: NULL pointers, zero lengths, max values
 * - Concurrent operations simulation
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_dns_cookie_client
 * Run:   ./fuzz_dns_cookie_client corpus/dns_cookie_client/ -fork=16 -max_len=1024
 */

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNSCookie.h"

/* Helper to construct IPv4 address from fuzzer input */
static void
build_ipv4_addr (const uint8_t *data, size_t len, struct sockaddr_in *addr,
                 socklen_t *addr_len)
{
  memset (addr, 0, sizeof (*addr));
  addr->sin_family = AF_INET;

  /* Use first 4 bytes for IP address */
  if (len >= 4)
    memcpy (&addr->sin_addr, data, 4);

  /* Use next 2 bytes for port */
  if (len >= 6)
    addr->sin_port = ((uint16_t)data[4] << 8) | data[5];
  else
    addr->sin_port = htons (53);

  *addr_len = sizeof (*addr);
}

/* Helper to construct IPv6 address from fuzzer input */
static void
build_ipv6_addr (const uint8_t *data, size_t len, struct sockaddr_in6 *addr,
                 socklen_t *addr_len)
{
  memset (addr, 0, sizeof (*addr));
  addr->sin6_family = AF_INET6;

  /* Use first 16 bytes for IPv6 address */
  if (len >= 16)
    memcpy (&addr->sin6_addr, data, 16);

  /* Use next 2 bytes for port */
  if (len >= 18)
    addr->sin6_port = ((uint16_t)data[16] << 8) | data[17];
  else
    addr->sin6_port = htons (53);

  *addr_len = sizeof (*addr);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  Arena_T arena = NULL;
  SocketDNSCookie_T cache = NULL;
  volatile int exception_caught = 0;

  if (size < 8)
    return 0;

  /* Split input into different sections for various operations */
  const uint8_t *section1 = data;
  size_t section1_len = size / 4;

  const uint8_t *section2 = data + section1_len;
  size_t section2_len = size / 4;

  const uint8_t *section3 = data + section1_len + section2_len;
  size_t section3_len = size / 4;

  const uint8_t *section4
      = data + section1_len + section2_len + section3_len;
  size_t section4_len = size - section1_len - section2_len - section3_len;

  TRY
  {
    /* Create arena and cookie cache */
    arena = Arena_new ();
    cache = SocketDNSCookie_new (arena);

    /* Test 1: Configuration fuzzing */
    if (section1_len >= 4)
      {
        int secret_lifetime
            = ((int)section1[0] << 24) | ((int)section1[1] << 16)
              | ((int)section1[2] << 8) | section1[3];
        SocketDNSCookie_set_secret_lifetime (cache, secret_lifetime);

        if (section1_len >= 8)
          {
            size_t cache_size = ((size_t)section1[4] << 8) | section1[5];
            SocketDNSCookie_set_cache_size (cache, cache_size);

            int server_ttl
                = ((int)section1[6] << 8) | section1[7];
            SocketDNSCookie_set_server_ttl (cache, server_ttl);
          }
      }

    /* Test 2: Client cookie generation for different address types */
    if (section2_len >= 6)
      {
        SocketDNSCookie_Cookie cookie;
        struct sockaddr_in server_v4, client_v4;
        struct sockaddr_in6 server_v6, client_v6;
        socklen_t server_len, client_len;

        /* Test IPv4 generation */
        build_ipv4_addr (section2, section2_len, &server_v4, &server_len);
        build_ipv4_addr (section2 + 6,
                         section2_len > 6 ? section2_len - 6 : 0, &client_v4,
                         &client_len);

        int result = SocketDNSCookie_generate (
            cache, (struct sockaddr *)&server_v4, server_len,
            (struct sockaddr *)&client_v4, client_len, &cookie);
        (void)result;

        /* Test IPv6 generation if enough data */
        if (section2_len >= 34)
          {
            build_ipv6_addr (section2, section2_len, &server_v6, &server_len);
            build_ipv6_addr (section2 + 18, section2_len - 18, &client_v6,
                             &client_len);

            result = SocketDNSCookie_generate (
                cache, (struct sockaddr *)&server_v6, server_len,
                (struct sockaddr *)&client_v6, client_len, &cookie);
            (void)result;
          }

        /* Test with NULL client address (should use server address only) */
        result = SocketDNSCookie_generate (
            cache, (struct sockaddr *)&server_v4, server_len, NULL, 0,
            &cookie);
        (void)result;
      }

    /* Test 3: Server cookie caching and lookup */
    if (section3_len >= DNS_CLIENT_COOKIE_SIZE + DNS_SERVER_COOKIE_MIN_SIZE
                            + 6)
      {
        struct sockaddr_in server_addr;
        socklen_t addr_len;
        SocketDNSCookie_Cookie cookie;
        SocketDNSCookie_Entry entry;

        build_ipv4_addr (section3, section3_len, &server_addr, &addr_len);

        /* Extract client and server cookies from fuzz input */
        const uint8_t *client_cookie = section3 + 6;
        const uint8_t *server_cookie
            = section3 + 6 + DNS_CLIENT_COOKIE_SIZE;

        /* Determine server cookie length (8-32 bytes valid) */
        size_t server_len = section3[0] % (DNS_SERVER_COOKIE_MAX_SIZE
                                           - DNS_SERVER_COOKIE_MIN_SIZE + 1)
                            + DNS_SERVER_COOKIE_MIN_SIZE;

        /* Ensure we don't read beyond input */
        size_t available
            = section3_len - 6 - DNS_CLIENT_COOKIE_SIZE;
        if (server_len > available)
          server_len = available;

        /* Only proceed if server_len is valid */
        if (server_len >= DNS_SERVER_COOKIE_MIN_SIZE
            && server_len <= DNS_SERVER_COOKIE_MAX_SIZE)
          {
            /* Store server cookie */
            int result = SocketDNSCookie_cache_store (
                cache, (struct sockaddr *)&server_addr, addr_len,
                client_cookie, server_cookie, server_len);
            (void)result;

            /* Lookup the stored cookie */
            int found = SocketDNSCookie_cache_lookup (
                cache, (struct sockaddr *)&server_addr, addr_len, &entry);
            (void)found;

            /* Verify cookie if lookup succeeded */
            if (found)
              {
                /* Build cookies for validation */
                memcpy (cookie.client_cookie, client_cookie,
                        DNS_CLIENT_COOKIE_SIZE);
                memcpy (cookie.server_cookie, server_cookie, server_len);
                cookie.server_cookie_len = server_len;

                SocketDNSCookie_Cookie response;
                memcpy (response.client_cookie, entry.client_cookie,
                        DNS_CLIENT_COOKIE_SIZE);
                memcpy (response.server_cookie, entry.server_cookie,
                        entry.server_cookie_len);
                response.server_cookie_len = entry.server_cookie_len;

                /* Validate response cookie */
                int valid = SocketDNSCookie_validate (&cookie, &response);
                (void)valid;

                /* Test cookie equality */
                int equal = SocketDNSCookie_equal (&cookie, &response);
                (void)equal;

                /* Test hex formatting */
                char hex_buf[128];
                int hex_len
                    = SocketDNSCookie_to_hex (&cookie, hex_buf, sizeof (hex_buf));
                (void)hex_len;
              }

            /* Test BADCOOKIE invalidation */
            if (section3[1] & 0x01)
              {
                int invalidated = SocketDNSCookie_cache_invalidate (
                    cache, (struct sockaddr *)&server_addr, addr_len);
                (void)invalidated;

                /* Verify entry was removed */
                found = SocketDNSCookie_cache_lookup (
                    cache, (struct sockaddr *)&server_addr, addr_len, NULL);
                (void)found;
              }
          }
      }

    /* Test 4: Secret rotation and rollover */
    if (section4_len >= 1)
      {
        /* Test forced rotation */
        if (section4[0] & 0x01)
          {
            int result = SocketDNSCookie_rotate_secret (cache);
            (void)result;
          }

        /* Generate cookies after rotation to test rollover period */
        if (section4_len >= 6)
          {
            struct sockaddr_in server_addr;
            socklen_t addr_len;
            SocketDNSCookie_Cookie cookie;

            build_ipv4_addr (section4, section4_len, &server_addr, &addr_len);

            int result = SocketDNSCookie_generate (
                cache, (struct sockaddr *)&server_addr, addr_len, NULL, 0,
                &cookie);
            (void)result;
          }
      }

    /* Test 5: Cache expiration */
    if (section4_len >= 2 && (section4[1] & 0x02))
      {
        int expired = SocketDNSCookie_cache_expire (cache);
        (void)expired;
      }

    /* Test 6: Cache clear */
    if (section4_len >= 3 && (section4[2] & 0x04))
      {
        SocketDNSCookie_cache_clear (cache);
      }

    /* Test 7: LRU eviction by filling cache beyond capacity */
    if (section4_len >= 4 && (section4[3] & 0x08))
      {
        /* Set small cache size to trigger eviction */
        SocketDNSCookie_set_cache_size (cache, 2);

        /* Add multiple entries to trigger LRU eviction */
        for (size_t i = 0; i < 5 && i * 10 + 10 < section4_len; i++)
          {
            struct sockaddr_in server_addr;
            socklen_t addr_len;
            build_ipv4_addr (section4 + i * 10, 10, &server_addr, &addr_len);

            uint8_t client_cookie[DNS_CLIENT_COOKIE_SIZE] = { 0 };
            uint8_t server_cookie[DNS_SERVER_COOKIE_MIN_SIZE] = { 0 };

            memcpy (client_cookie, section4 + i * 10,
                    (i * 10 + DNS_CLIENT_COOKIE_SIZE <= section4_len)
                        ? DNS_CLIENT_COOKIE_SIZE
                        : 0);

            SocketDNSCookie_cache_store (
                cache, (struct sockaddr *)&server_addr, addr_len,
                client_cookie, server_cookie, DNS_SERVER_COOKIE_MIN_SIZE);
          }
      }

    /* Test 8: Statistics */
    SocketDNSCookie_Stats stats;
    SocketDNSCookie_stats (cache, &stats);
    (void)stats.client_cookies_generated;
    (void)stats.server_cookies_cached;
    (void)stats.cache_hits;
    (void)stats.cache_misses;
    (void)stats.cache_evictions;

    /* Test 9: BADCOOKIE RCODE check */
    if (size >= 2)
      {
        uint16_t rcode = ((uint16_t)data[0] << 8) | data[1];
        int is_bad = SocketDNSCookie_is_badcookie (rcode);
        (void)is_bad;

        /* Specifically test RCODE 23 (BADCOOKIE) */
        is_bad = SocketDNSCookie_is_badcookie (23);
        (void)is_bad;
      }

    /* Test 10: NULL pointer handling (should not crash) */
    (void)SocketDNSCookie_generate (NULL, NULL, 0, NULL, 0, NULL);
    (void)SocketDNSCookie_cache_store (NULL, NULL, 0, NULL, NULL, 0);
    (void)SocketDNSCookie_cache_lookup (NULL, NULL, 0, NULL);
    (void)SocketDNSCookie_cache_invalidate (NULL, NULL, 0);
    (void)SocketDNSCookie_cache_expire (NULL);
    SocketDNSCookie_cache_clear (NULL);
    (void)SocketDNSCookie_rotate_secret (NULL);
    SocketDNSCookie_set_secret_lifetime (NULL, 0);
    SocketDNSCookie_set_cache_size (NULL, 0);
    SocketDNSCookie_set_server_ttl (NULL, 0);
    SocketDNSCookie_stats (NULL, NULL);
    SocketDNSCookie_stats_reset (NULL);
    (void)SocketDNSCookie_validate (NULL, NULL);
    (void)SocketDNSCookie_equal (NULL, NULL);
    (void)SocketDNSCookie_to_hex (NULL, NULL, 0);

    /* Test 11: Edge cases with valid cache but invalid inputs */
    if (cache)
      {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof (addr);
        build_ipv4_addr (data, size, &addr, &addr_len);

        /* Generate with zero-length address */
        SocketDNSCookie_Cookie cookie;
        (void)SocketDNSCookie_generate (cache, (struct sockaddr *)&addr, 0,
                                        NULL, 0, &cookie);

        /* Store with invalid server cookie lengths */
        uint8_t client_cookie[DNS_CLIENT_COOKIE_SIZE] = { 0 };
        uint8_t server_cookie[DNS_SERVER_COOKIE_MAX_SIZE + 10] = { 0 };

        /* Too short */
        (void)SocketDNSCookie_cache_store (
            cache, (struct sockaddr *)&addr, addr_len, client_cookie,
            server_cookie, DNS_SERVER_COOKIE_MIN_SIZE - 1);

        /* Too long */
        (void)SocketDNSCookie_cache_store (
            cache, (struct sockaddr *)&addr, addr_len, client_cookie,
            server_cookie, DNS_SERVER_COOKIE_MAX_SIZE + 1);

        /* Test with mismatched address families */
        struct sockaddr_in6 addr6;
        build_ipv6_addr (data, size, &addr6, &addr_len);

        (void)SocketDNSCookie_generate (cache, (struct sockaddr *)&addr6,
                                        addr_len, (struct sockaddr *)&addr,
                                        sizeof (addr), &cookie);
      }

    /* Test 12: Statistics reset */
    if (section4_len >= 5 && (section4[4] & 0x10))
      {
        SocketDNSCookie_stats_reset (cache);

        /* Verify stats were reset */
        SocketDNSCookie_Stats stats_after;
        SocketDNSCookie_stats (cache, &stats_after);
        (void)stats_after.client_cookies_generated;
      }

    /* Clean up */
    SocketDNSCookie_free (&cache);
    Arena_dispose (&arena);
  }
  EXCEPT (SocketDNSCookie_Failed)
  {
    exception_caught = 1;
    /* Expected for invalid inputs - just cleanup */
    if (cache)
      SocketDNSCookie_free (&cache);
    if (arena)
      Arena_dispose (&arena);
  }
  EXCEPT (Arena_Failed)
  {
    exception_caught = 1;
    /* Arena allocation failure */
    if (cache)
      SocketDNSCookie_free (&cache);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;

  (void)exception_caught;

  return 0;
}
