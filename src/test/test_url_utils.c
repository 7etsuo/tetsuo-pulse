/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_url_utils.c
 * @brief Unit tests for URL encoding utilities (socket_util_hex_digit,
 * socket_util_url_decode)
 *
 * Tests the shared URL utility functions in SocketUtil.h that are used
 * by multiple modules for percent-encoding/decoding.
 */

#include "core/SocketUtil.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Test socket_util_hex_digit */
static void
test_hex_digit (void)
{
  /* Valid hex digits 0-9 */
  assert (socket_util_hex_digit ('0') == 0);
  assert (socket_util_hex_digit ('5') == 5);
  assert (socket_util_hex_digit ('9') == 9);

  /* Valid hex digits a-f (lowercase) */
  assert (socket_util_hex_digit ('a') == 10);
  assert (socket_util_hex_digit ('c') == 12);
  assert (socket_util_hex_digit ('f') == 15);

  /* Valid hex digits A-F (uppercase) */
  assert (socket_util_hex_digit ('A') == 10);
  assert (socket_util_hex_digit ('C') == 12);
  assert (socket_util_hex_digit ('F') == 15);

  /* Invalid characters */
  assert (socket_util_hex_digit ('g') == -1);
  assert (socket_util_hex_digit ('G') == -1);
  assert (socket_util_hex_digit ('z') == -1);
  assert (socket_util_hex_digit ('@') == -1);
  assert (socket_util_hex_digit (' ') == -1);
  assert (socket_util_hex_digit ('\0') == -1);

  printf ("test_hex_digit: PASS\n");
}

/* Test socket_util_url_decode - basic cases */
static void
test_url_decode_basic (void)
{
  char buf[128];
  size_t len;
  int ret;

  /* No encoding */
  ret = socket_util_url_decode ("hello", 5, buf, sizeof (buf), &len);
  assert (ret == 0);
  assert (strcmp (buf, "hello") == 0);
  assert (len == 5);

  /* Space encoded as %20 */
  ret = socket_util_url_decode ("hello%20world", 13, buf, sizeof (buf), &len);
  assert (ret == 0);
  assert (strcmp (buf, "hello world") == 0);
  assert (len == 11);

  /* Multiple percent sequences */
  ret = socket_util_url_decode (
      "hello%20world%21", 16, buf, sizeof (buf), &len);
  assert (ret == 0);
  assert (strcmp (buf, "hello world!") == 0);
  assert (len == 12);

  /* Mixed case hex digits */
  ret = socket_util_url_decode ("test%2Fpath%3D", 14, buf, sizeof (buf), &len);
  assert (ret == 0);
  assert (strcmp (buf, "test/path=") == 0);
  assert (len == 10);

  /* Upper case hex */
  ret = socket_util_url_decode ("%41%42%43", 9, buf, sizeof (buf), &len);
  assert (ret == 0);
  assert (strcmp (buf, "ABC") == 0);
  assert (len == 3);

  printf ("test_url_decode_basic: PASS\n");
}

/* Test socket_util_url_decode - edge cases */
static void
test_url_decode_edge_cases (void)
{
  char buf[128];
  size_t len;
  int ret;

  /* Empty string */
  ret = socket_util_url_decode ("", 0, buf, sizeof (buf), &len);
  assert (ret == 0);
  assert (strcmp (buf, "") == 0);
  assert (len == 0);

  /* Invalid percent sequence (not enough chars) */
  ret = socket_util_url_decode ("test%2", 6, buf, sizeof (buf), &len);
  assert (ret == 0);
  assert (strcmp (buf, "test%2") == 0); /* Copied literally */
  assert (len == 6);

  /* Invalid percent sequence (at end) */
  ret = socket_util_url_decode ("test%", 5, buf, sizeof (buf), &len);
  assert (ret == 0);
  assert (strcmp (buf, "test%") == 0);
  assert (len == 5);

  /* Invalid hex digits */
  ret = socket_util_url_decode ("test%ZZ", 7, buf, sizeof (buf), &len);
  assert (ret == 0);
  assert (strcmp (buf, "test%ZZ") == 0); /* Copied literally */
  assert (len == 7);

  /* Null bytes (not recommended but should work) */
  ret = socket_util_url_decode ("%00test", 7, buf, sizeof (buf), &len);
  assert (ret == 0);
  assert (buf[0] == '\0');
  assert (len == 5); /* null + "test" */

  /* No output length pointer (optional) */
  ret = socket_util_url_decode ("hello", 5, buf, sizeof (buf), NULL);
  assert (ret == 0);
  assert (strcmp (buf, "hello") == 0);

  printf ("test_url_decode_edge_cases: PASS\n");
}

/* Test socket_util_url_decode - truncation detection */
static void
test_url_decode_truncation (void)
{
  char buf[8];
  size_t len;
  int ret;

  /* Exact fit (7 chars + null terminator) */
  ret = socket_util_url_decode ("1234567", 7, buf, sizeof (buf), &len);
  assert (ret == 0);
  assert (strcmp (buf, "1234567") == 0);
  assert (len == 7);

  /* Truncation: 8+ chars won't fit */
  ret = socket_util_url_decode ("12345678", 8, buf, sizeof (buf), &len);
  assert (ret == -1); /* Truncation detected */

  /* Truncation with encoded chars - fits exactly */
  ret = socket_util_url_decode ("123456%20", 9, buf, sizeof (buf), &len);
  assert (ret == 0); /* "123456 " = 7 chars + null fits in size 8 */
  assert (strcmp (buf, "123456 ") == 0);

  /* Actual truncation with encoded chars */
  ret = socket_util_url_decode ("1234567%20", 10, buf, sizeof (buf), &len);
  assert (ret == -1); /* "1234567 " = 8 chars doesn't fit (need 9 with null) */

  /* Zero-size buffer */
  ret = socket_util_url_decode ("test", 4, buf, 0, &len);
  assert (ret == -1); /* Can't fit anything */

  printf ("test_url_decode_truncation: PASS\n");
}

/* Test socket_util_url_decode - special characters */
static void
test_url_decode_special_chars (void)
{
  char buf[128];
  size_t len;
  int ret;

  /* Username:password encoding (colon, at-sign) */
  ret = socket_util_url_decode ("user%3Apass", 11, buf, sizeof (buf), &len);
  assert (ret == 0);
  assert (strcmp (buf, "user:pass") == 0);

  /* Path with slashes */
  ret = socket_util_url_decode (
      "%2Fpath%2Fto%2Ffile", 19, buf, sizeof (buf), &len);
  assert (ret == 0);
  assert (strcmp (buf, "/path/to/file") == 0);

  /* Query string characters */
  ret = socket_util_url_decode (
      "key%3Dvalue%26foo%3Dbar", 23, buf, sizeof (buf), &len);
  assert (ret == 0);
  assert (strcmp (buf, "key=value&foo=bar") == 0);

  /* Spaces as plus (should NOT decode + as space - that's a quirk of
   * application/x-www-form-urlencoded, not RFC 3986 percent-encoding) */
  ret = socket_util_url_decode ("hello+world", 11, buf, sizeof (buf), &len);
  assert (ret == 0);
  assert (strcmp (buf, "hello+world") == 0); /* Plus not decoded */

  printf ("test_url_decode_special_chars: PASS\n");
}

/* Test realistic proxy URL credentials */
static void
test_url_decode_proxy_credentials (void)
{
  char username[64];
  char password[64];
  int ret;

  /* Simple username */
  ret = socket_util_url_decode ("admin", 5, username, sizeof (username), NULL);
  assert (ret == 0);
  assert (strcmp (username, "admin") == 0);

  /* Username with special chars */
  ret = socket_util_url_decode (
      "user%40domain.com", 17, username, sizeof (username), NULL);
  assert (ret == 0);
  assert (strcmp (username, "user@domain.com") == 0);

  /* Password with special chars */
  ret = socket_util_url_decode (
      "p%40ssw0rd%21", 13, password, sizeof (password), NULL);
  assert (ret == 0);
  assert (strcmp (password, "p@ssw0rd!") == 0);

  /* URL-unsafe password */
  ret = socket_util_url_decode (
      "a%2Fb%3Ac%20d", 13, password, sizeof (password), NULL);
  assert (ret == 0);
  assert (strcmp (password, "a/b:c d") == 0);

  printf ("test_url_decode_proxy_credentials: PASS\n");
}

int
main (void)
{
  printf ("=== URL Utilities Test Suite ===\n");

  test_hex_digit ();
  test_url_decode_basic ();
  test_url_decode_edge_cases ();
  test_url_decode_truncation ();
  test_url_decode_special_chars ();
  test_url_decode_proxy_credentials ();

  printf ("=== All tests passed ===\n");
  return 0;
}
