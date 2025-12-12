/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_http_cookies.c - HTTP Cookie parsing and handling fuzzing harness
 *
 * Tests cookie parsing, validation, and jar management with malformed inputs
 * to find vulnerabilities in cookie handling and jar operations.
 *
 * Targets:
 * - Cookie structure creation with fuzzed values
 * - Cookie jar set/get operations
 * - Cookie jar clear and clear_expired operations
 * - Domain/path matching logic
 * - Cookie attribute validation
 *
 * Cookies are critical security components that handle sensitive session data.
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_http_cookies
 * ./fuzz_http_cookies corpus/http_cookies/ -fork=16 -max_len=4096
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTPClient.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketHTTPClient_CookieJar_T cookie_jar = NULL;

  /* Skip empty input */
  if (size == 0)
    return 0;

  cookie_jar = SocketHTTPClient_CookieJar_new ();
  if (!cookie_jar)
    return 0;

  TRY
  {
    /* ====================================================================
     * Test 1: Set cookies with fuzzed names and values
     * ==================================================================== */
    if (size > 10)
      {
        size_t offset = 0;

        /* Create and set multiple fuzzed cookies */
        for (int i = 0; i < 20 && offset + 4 < size; i++)
          {
            SocketHTTPClient_Cookie cookie;
            memset (&cookie, 0, sizeof (cookie));

            /* Determine name and value lengths from fuzz data */
            size_t name_len = (data[offset] % 32) + 1;
            size_t value_len = (data[offset + 1] % 64) + 1;
            offset += 2;

            if (offset + name_len + value_len > size)
              break;

            /* Create name and value strings */
            char name[64], value[128];
            size_t actual_name = (name_len < sizeof (name) - 1) ? name_len : sizeof (name) - 1;
            size_t actual_value = (value_len < sizeof (value) - 1) ? value_len : sizeof (value) - 1;

            if (offset + actual_name + actual_value > size)
              break;

            memcpy (name, data + offset, actual_name);
            name[actual_name] = '\0';
            offset += actual_name;

            memcpy (value, data + offset, actual_value);
            value[actual_value] = '\0';
            offset += actual_value;

            /* Set up cookie structure */
            cookie.name = name;
            cookie.value = value;
            cookie.domain = "example.com";
            cookie.path = "/";
            cookie.expires = time (NULL) + 3600; /* 1 hour from now */
            cookie.secure = (data[offset % size] & 1) ? 1 : 0;
            cookie.http_only = (data[offset % size] & 2) ? 1 : 0;

            /* Set cookie in jar */
            SocketHTTPClient_CookieJar_set (cookie_jar, &cookie);
          }
      }

    /* ====================================================================
     * Test 2: Get cookies with fuzzed domain/path/name
     * ==================================================================== */
    {
      /* Create fuzzed domain, path, and name for lookup */
      char domain[128], path[128], name[64];

      if (size > 10)
        {
          /* Split input into 3 parts, ensuring we don't read past buffer */
          size_t third = size / 3;
          size_t domain_len = (third > sizeof (domain) - 1) ? sizeof (domain) - 1 : third;
          size_t path_len = (third > sizeof (path) - 1) ? sizeof (path) - 1 : third;
          
          /* Ensure we have enough data for all three parts */
          size_t remaining = size - domain_len - path_len;
          size_t name_len = (remaining > sizeof (name) - 1) ? sizeof (name) - 1 : remaining;

          memcpy (domain, data, domain_len);
          domain[domain_len] = '\0';

          memcpy (path, data + domain_len, path_len);
          path[path_len] = '\0';

          memcpy (name, data + domain_len + path_len, name_len);
          name[name_len] = '\0';

          const SocketHTTPClient_Cookie *cookie = SocketHTTPClient_CookieJar_get (
              cookie_jar, domain, path, name);
          (void)cookie;
        }

      /* Test with known domains/paths */
      const char *domains[] = {"example.com", "sub.example.com", ".example.com", "other.com"};
      const char *paths[] = {"/", "/test", "/test/nested", "/api"};
      const char *names[] = {"session", "user", "auth", "test"};

      for (size_t d = 0; d < sizeof (domains) / sizeof (domains[0]); d++)
        {
          for (size_t p = 0; p < sizeof (paths) / sizeof (paths[0]); p++)
            {
              for (size_t n = 0; n < sizeof (names) / sizeof (names[0]); n++)
                {
                  const SocketHTTPClient_Cookie *cookie = SocketHTTPClient_CookieJar_get (
                      cookie_jar, domains[d], paths[p], names[n]);
                  (void)cookie;
                }
            }
        }
    }

    /* ====================================================================
     * Test 3: Cookie attributes validation
     * ==================================================================== */
    {
      /* Test with various cookie attribute combinations */
      const struct
      {
        const char *name;
        const char *value;
        const char *domain;
        const char *path;
        int secure;
        int http_only;
      } test_cookies[] = {
          {"session", "abc123", "example.com", "/", 1, 1},
          {"user", "john", ".example.com", "/", 0, 0},
          {"token", "xyz", "sub.example.com", "/api", 1, 0},
          {"tracking", "123", "example.com", "/tracking/", 0, 1},
          {"", "empty_name", "example.com", "/", 0, 0}, /* Empty name */
          {"empty_value", "", "example.com", "/", 0, 0}, /* Empty value */
      };

      for (size_t i = 0; i < sizeof (test_cookies) / sizeof (test_cookies[0]); i++)
        {
          SocketHTTPClient_Cookie cookie;
          memset (&cookie, 0, sizeof (cookie));
          cookie.name = test_cookies[i].name;
          cookie.value = test_cookies[i].value;
          cookie.domain = test_cookies[i].domain;
          cookie.path = test_cookies[i].path;
          cookie.secure = test_cookies[i].secure;
          cookie.http_only = test_cookies[i].http_only;
          cookie.expires = time (NULL) + 3600;

          SocketHTTPClient_CookieJar_set (cookie_jar, &cookie);
        }
    }

    /* ====================================================================
     * Test 4: Expiration handling
     * ==================================================================== */
    if (size >= 4)
      {
        /* Create cookies with fuzzed expiration times */
        time_t now = time (NULL);

        /* Use fuzz data for expiration offset - use unsigned to avoid UB */
        int32_t offset_seconds = (int32_t)(((uint32_t)data[0] << 24) |
                                           ((uint32_t)data[1] << 16) |
                                           ((uint32_t)data[2] << 8) |
                                           (uint32_t)data[3]);

        SocketHTTPClient_Cookie cookie;
        memset (&cookie, 0, sizeof (cookie));
        cookie.name = "expiry_test";
        cookie.value = "test_value";
        cookie.domain = "example.com";
        cookie.path = "/";
        cookie.expires = now + offset_seconds;

        SocketHTTPClient_CookieJar_set (cookie_jar, &cookie);

        /* Clear expired cookies */
        SocketHTTPClient_CookieJar_clear_expired (cookie_jar);
      }

    /* ====================================================================
     * Test 5: Clear operations
     * ==================================================================== */
    {
      /* Clear expired first */
      SocketHTTPClient_CookieJar_clear_expired (cookie_jar);

      /* Add some more cookies */
      SocketHTTPClient_Cookie cookie;
      memset (&cookie, 0, sizeof (cookie));
      cookie.name = "after_clear";
      cookie.value = "value";
      cookie.domain = "example.com";
      cookie.path = "/";
      cookie.expires = time (NULL) + 3600;

      SocketHTTPClient_CookieJar_set (cookie_jar, &cookie);

      /* Full clear */
      SocketHTTPClient_CookieJar_clear (cookie_jar);

      /* Add after clear */
      cookie.name = "after_full_clear";
      SocketHTTPClient_CookieJar_set (cookie_jar, &cookie);
    }

    /* ====================================================================
     * Test 6: SameSite attribute handling
     * ==================================================================== */
    {
      /* Test SameSite values */
      SocketHTTPClient_SameSite samesite_values[] = {
          COOKIE_SAMESITE_NONE, COOKIE_SAMESITE_LAX, COOKIE_SAMESITE_STRICT
      };

      for (size_t i = 0; i < sizeof (samesite_values) / sizeof (samesite_values[0]); i++)
        {
          SocketHTTPClient_Cookie cookie;
          memset (&cookie, 0, sizeof (cookie));
          cookie.name = "samesite_test";
          cookie.value = "value";
          cookie.domain = "example.com";
          cookie.path = "/";
          cookie.same_site = samesite_values[i];
          cookie.secure = (samesite_values[i] == COOKIE_SAMESITE_NONE) ? 1 : 0;
          cookie.expires = time (NULL) + 3600;

          SocketHTTPClient_CookieJar_set (cookie_jar, &cookie);
        }
    }

    /* ====================================================================
     * Test 7: Long cookie values
     * ==================================================================== */
    if (size > 100)
      {
        /* Create a cookie with long name and value from fuzz data */
        char long_name[256], long_value[2048];

        size_t name_len = (size > sizeof (long_name) - 1) ? sizeof (long_name) - 1 : size / 4;
        size_t value_len = (size > sizeof (long_value) - 1) ? sizeof (long_value) - 1 : size;

        memcpy (long_name, data, name_len);
        long_name[name_len] = '\0';

        memcpy (long_value, data, value_len);
        long_value[value_len] = '\0';

        /* Remove problematic characters */
        for (size_t i = 0; i < name_len; i++)
          {
            if (long_name[i] == '=' || long_name[i] == ';' || long_name[i] == '\0')
              long_name[i] = 'x';
          }
        for (size_t i = 0; i < value_len; i++)
          {
            if (long_value[i] == ';' || long_value[i] == '\0')
              long_value[i] = 'y';
          }

        SocketHTTPClient_Cookie cookie;
        memset (&cookie, 0, sizeof (cookie));
        cookie.name = long_name;
        cookie.value = long_value;
        cookie.domain = "example.com";
        cookie.path = "/";
        cookie.expires = time (NULL) + 3600;

        SocketHTTPClient_CookieJar_set (cookie_jar, &cookie);
      }

    /* ====================================================================
     * Test 8: Domain matching edge cases
     * ==================================================================== */
    {
      /* Create cookies with various domain formats */
      const struct
      {
        const char *domain;
        const char *path;
      } domain_tests[] = {
          {"example.com", "/"},
          {".example.com", "/"},
          {"sub.example.com", "/"},
          {"sub.sub.example.com", "/"},
          {"localhost", "/"},
          {"127.0.0.1", "/"},
          {"[::1]", "/"}, /* IPv6 */
      };

      for (size_t i = 0; i < sizeof (domain_tests) / sizeof (domain_tests[0]); i++)
        {
          SocketHTTPClient_Cookie cookie;
          memset (&cookie, 0, sizeof (cookie));
          cookie.name = "domain_test";
          cookie.value = "value";
          cookie.domain = domain_tests[i].domain;
          cookie.path = domain_tests[i].path;
          cookie.expires = time (NULL) + 3600;

          SocketHTTPClient_CookieJar_set (cookie_jar, &cookie);

          /* Try to get the cookie back */
          const SocketHTTPClient_Cookie *retrieved = SocketHTTPClient_CookieJar_get (
              cookie_jar, domain_tests[i].domain, domain_tests[i].path, "domain_test");
          (void)retrieved;
        }
    }
  }
  EXCEPT (SocketHTTPClient_Failed)
  {
    /* Expected on malformed cookie data */
  }
  EXCEPT (Arena_Failed)
  {
    /* Expected on memory exhaustion */
  }
  END_TRY;

  SocketHTTPClient_CookieJar_free (&cookie_jar);

  return 0;
}
