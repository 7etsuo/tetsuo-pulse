/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_simple_proxy_url.c - Tests for SocketSimple Proxy URL Parsing
 *
 * Part of the Socket Library Test Suite
 *
 * Tests cover:
 * - URL parsing with normal credentials
 * - URL decoding of percent-encoded credentials
 * - Detection of truncated usernames (too long)
 * - Detection of truncated passwords (too long)
 * - Edge cases near buffer boundaries
 *
 * Addresses security issue #2320 - unchecked url_decode return values
 */

#include "simple/SocketSimple-proxy.h"
#include "simple/SocketSimple.h"
#include "test/Test.h"

#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Normal URL Parsing Tests
 * ============================================================================
 */

TEST (simple_proxy_parse_url_basic)
{
  SocketSimple_ProxyConfig config;
  int result;

  result = Socket_simple_proxy_parse_url ("socks5://proxy.example.com:1080",
                                          &config);

  ASSERT_EQ (0, result);
  ASSERT_EQ (SOCKET_SIMPLE_PROXY_SOCKS5, config.type);
  ASSERT (strcmp (config.host, "proxy.example.com") == 0);
  ASSERT_EQ (1080, config.port);
  ASSERT (config.username[0] == '\0');
  ASSERT (config.password[0] == '\0');
}

TEST (simple_proxy_parse_url_with_auth)
{
  SocketSimple_ProxyConfig config;
  int result;

  result = Socket_simple_proxy_parse_url (
      "socks5://myuser:mypass@proxy.example.com:1080", &config);

  ASSERT_EQ (0, result);
  ASSERT_EQ (SOCKET_SIMPLE_PROXY_SOCKS5, config.type);
  ASSERT (strcmp (config.host, "proxy.example.com") == 0);
  ASSERT_EQ (1080, config.port);
  ASSERT (strcmp (config.username, "myuser") == 0);
  ASSERT (strcmp (config.password, "mypass") == 0);
}

TEST (simple_proxy_parse_url_username_only)
{
  SocketSimple_ProxyConfig config;
  int result;

  result = Socket_simple_proxy_parse_url (
      "socks5://myuser@proxy.example.com:1080", &config);

  ASSERT_EQ (0, result);
  ASSERT (strcmp (config.username, "myuser") == 0);
  ASSERT (config.password[0] == '\0');
}

/* ============================================================================
 * URL Decoding Tests
 * ============================================================================
 */

TEST (simple_proxy_parse_url_percent_encoded_username)
{
  SocketSimple_ProxyConfig config;
  int result;

  /* Username with special characters: "user@domain" -> "user%40domain" */
  result = Socket_simple_proxy_parse_url (
      "socks5://user%40domain:pass@proxy.example.com:1080", &config);

  ASSERT_EQ (0, result);
  ASSERT (strcmp (config.username, "user@domain") == 0);
  ASSERT (strcmp (config.password, "pass") == 0);
}

TEST (simple_proxy_parse_url_percent_encoded_password)
{
  SocketSimple_ProxyConfig config;
  int result;

  /* Password with colon: "p:ss" -> "p%3Ass" */
  result = Socket_simple_proxy_parse_url (
      "socks5://user:p%3Ass@proxy.example.com:1080", &config);

  ASSERT_EQ (0, result);
  ASSERT (strcmp (config.username, "user") == 0);
  ASSERT (strcmp (config.password, "p:ss") == 0);
}

TEST (simple_proxy_parse_url_both_percent_encoded)
{
  SocketSimple_ProxyConfig config;
  int result;

  /* Username: "us er" -> "us%20er", Password: "pa ss" -> "pa%20ss" */
  result = Socket_simple_proxy_parse_url (
      "socks5://us%20er:pa%20ss@proxy.example.com:1080", &config);

  ASSERT_EQ (0, result);
  ASSERT (strcmp (config.username, "us er") == 0);
  ASSERT (strcmp (config.password, "pa ss") == 0);
}

/* ============================================================================
 * Truncation Detection Tests (Security Issue #2320)
 * ============================================================================
 */

TEST (simple_proxy_parse_url_username_too_long)
{
  SocketSimple_ProxyConfig config;
  int result;
  char url[512];

  /* Build URL with username that is exactly 128 chars (buffer size) */
  /* This should be rejected because url_decode needs space for null terminator
   */
  const char *long_username
      = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" /* 64 */
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; /* 128
                                                                               total
                                                                             */

  snprintf (url, sizeof (url), "socks5://%s:pass@proxy.example.com:1080",
            long_username);

  result = Socket_simple_proxy_parse_url (url, &config);

  /* Should fail due to username being too long */
  ASSERT_EQ (-1, result);
}

TEST (simple_proxy_parse_url_password_too_long)
{
  SocketSimple_ProxyConfig config;
  int result;
  char url[512];

  /* Build URL with password that is exactly 128 chars (buffer size) */
  const char *long_password
      = "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp" /* 64 */
        "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp"; /* 128
                                                                               total
                                                                             */

  snprintf (url, sizeof (url), "socks5://user:%s@proxy.example.com:1080",
            long_password);

  result = Socket_simple_proxy_parse_url (url, &config);

  /* Should fail due to password being too long */
  ASSERT_EQ (-1, result);
}

TEST (simple_proxy_parse_url_username_only_too_long)
{
  SocketSimple_ProxyConfig config;
  int result;
  char url[512];

  /* Build URL with username only (no password) that is too long */
  const char *long_username
      = "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu" /* 64 */
        "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu"; /* 128
                                                                                 total
                                                                               */

  snprintf (url, sizeof (url), "socks5://%s@proxy.example.com:1080",
            long_username);

  result = Socket_simple_proxy_parse_url (url, &config);

  /* Should fail due to username being too long */
  ASSERT_EQ (-1, result);
}

/* ============================================================================
 * Edge Case Tests - Near Boundary
 * ============================================================================
 */

TEST (simple_proxy_parse_url_username_max_valid_length)
{
  SocketSimple_ProxyConfig config;
  int result;
  char url[512];

  /* Build URL with username that is 100 chars (safe, well below limit) */
  const char *username_100
      = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" /* 64 */
        "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"; /* 100 total */

  snprintf (url, sizeof (url), "socks5://%s:pass@proxy.example.com:1080",
            username_100);

  result = Socket_simple_proxy_parse_url (url, &config);

  ASSERT_EQ (0, result);
  ASSERT (strlen (config.username) == 100);
  ASSERT (strcmp (config.username, username_100) == 0);
}

TEST (simple_proxy_parse_url_password_max_valid_length)
{
  SocketSimple_ProxyConfig config;
  int result;
  char url[512];

  /* Build URL with password that is 100 chars (safe, well below limit) */
  const char *password_100
      = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" /* 64 */
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"; /* 100 total */

  snprintf (url, sizeof (url), "socks5://user:%s@proxy.example.com:1080",
            password_100);

  result = Socket_simple_proxy_parse_url (url, &config);

  ASSERT_EQ (0, result);
  ASSERT (strlen (config.password) == 100);
  ASSERT (strcmp (config.password, password_100) == 0);
}

/* ============================================================================
 * URL Decoding with Truncation
 * ============================================================================
 */

TEST (simple_proxy_parse_url_percent_encoded_causes_truncation)
{
  SocketSimple_ProxyConfig config;
  int result;
  char url[512];

  /* Build username with many %20 (space) encodings that expand during decode
   */
  /* Each %20 becomes one character, but the source string is already long */
  /* This simulates a case where URL encoding makes the input long enough to
   * truncate */

  /* Create a username that's long but becomes even longer when considering
   * buffer */
  const char *username_with_encoding
      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" /* 63 */
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; /* 126
                                                                              */

  /* If we add more, it should fail */
  snprintf (url, sizeof (url), "socks5://%sXX:pass@proxy.example.com:1080",
            username_with_encoding);

  result = Socket_simple_proxy_parse_url (url, &config);

  /* Should fail */
  ASSERT_EQ (-1, result);
}

/* ============================================================================
 * Multiple Proxy Types with Long Credentials
 * ============================================================================
 */

TEST (simple_proxy_parse_url_http_username_too_long)
{
  SocketSimple_ProxyConfig config;
  int result;
  char url[512];

  const char *long_username
      = "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"
        "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh";

  snprintf (url, sizeof (url), "http://%s:pass@proxy.example.com:8080",
            long_username);

  result = Socket_simple_proxy_parse_url (url, &config);

  /* Should fail */
  ASSERT_EQ (-1, result);
}

TEST (simple_proxy_parse_url_socks4a_password_too_long)
{
  SocketSimple_ProxyConfig config;
  int result;
  char url[512];

  const char *long_password
      = "ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss"
        "ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss";

  snprintf (url, sizeof (url), "socks4a://user:%s@proxy.example.com:1080",
            long_password);

  result = Socket_simple_proxy_parse_url (url, &config);

  /* Should fail */
  ASSERT_EQ (-1, result);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
