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
#include "test/Test.h"

#include <stdio.h>
#include <string.h>

TEST (url_hex_digit)
{
  /* Valid hex digits 0-9 */
  ASSERT_EQ (0, socket_util_hex_digit ('0'));
  ASSERT_EQ (5, socket_util_hex_digit ('5'));
  ASSERT_EQ (9, socket_util_hex_digit ('9'));

  /* Valid hex digits a-f (lowercase) */
  ASSERT_EQ (10, socket_util_hex_digit ('a'));
  ASSERT_EQ (12, socket_util_hex_digit ('c'));
  ASSERT_EQ (15, socket_util_hex_digit ('f'));

  /* Valid hex digits A-F (uppercase) */
  ASSERT_EQ (10, socket_util_hex_digit ('A'));
  ASSERT_EQ (12, socket_util_hex_digit ('C'));
  ASSERT_EQ (15, socket_util_hex_digit ('F'));

  /* Invalid characters */
  ASSERT_EQ (-1, socket_util_hex_digit ('g'));
  ASSERT_EQ (-1, socket_util_hex_digit ('G'));
  ASSERT_EQ (-1, socket_util_hex_digit ('z'));
  ASSERT_EQ (-1, socket_util_hex_digit ('@'));
  ASSERT_EQ (-1, socket_util_hex_digit (' '));
  ASSERT_EQ (-1, socket_util_hex_digit ('\0'));
}

TEST (url_decode_basic)
{
  char buf[128];
  size_t len;

  /* No encoding */
  ASSERT_EQ (0, socket_util_url_decode ("hello", 5, buf, sizeof (buf), &len));
  ASSERT (strcmp (buf, "hello") == 0);
  ASSERT_EQ (5, len);

  /* Space encoded as %20 */
  ASSERT_EQ (
      0, socket_util_url_decode ("hello%20world", 13, buf, sizeof (buf), &len));
  ASSERT (strcmp (buf, "hello world") == 0);
  ASSERT_EQ (11, len);

  /* Multiple percent sequences */
  ASSERT_EQ (
      0,
      socket_util_url_decode ("hello%20world%21", 16, buf, sizeof (buf), &len));
  ASSERT (strcmp (buf, "hello world!") == 0);
  ASSERT_EQ (12, len);

  /* Mixed case hex digits */
  ASSERT_EQ (
      0,
      socket_util_url_decode ("test%2Fpath%3D", 14, buf, sizeof (buf), &len));
  ASSERT (strcmp (buf, "test/path=") == 0);
  ASSERT_EQ (10, len);

  /* Upper case hex */
  ASSERT_EQ (0,
             socket_util_url_decode ("%41%42%43", 9, buf, sizeof (buf), &len));
  ASSERT (strcmp (buf, "ABC") == 0);
  ASSERT_EQ (3, len);
}

TEST (url_decode_edge_cases)
{
  char buf[128];
  size_t len;

  /* Empty string */
  ASSERT_EQ (0, socket_util_url_decode ("", 0, buf, sizeof (buf), &len));
  ASSERT (strcmp (buf, "") == 0);
  ASSERT_EQ (0, len);

  /* Invalid percent sequence (not enough chars) */
  ASSERT_EQ (0, socket_util_url_decode ("test%2", 6, buf, sizeof (buf), &len));
  ASSERT (strcmp (buf, "test%2") == 0); /* Copied literally */
  ASSERT_EQ (6, len);

  /* Invalid percent sequence (at end) */
  ASSERT_EQ (0, socket_util_url_decode ("test%", 5, buf, sizeof (buf), &len));
  ASSERT (strcmp (buf, "test%") == 0);
  ASSERT_EQ (5, len);

  /* Invalid hex digits */
  ASSERT_EQ (0, socket_util_url_decode ("test%ZZ", 7, buf, sizeof (buf), &len));
  ASSERT (strcmp (buf, "test%ZZ") == 0); /* Copied literally */
  ASSERT_EQ (7, len);

  /* Null bytes (not recommended but should work) */
  ASSERT_EQ (0, socket_util_url_decode ("%00test", 7, buf, sizeof (buf), &len));
  ASSERT_EQ (0, (unsigned char)buf[0]);
  ASSERT_EQ (5, len); /* null + "test" */

  /* No output length pointer (optional) */
  ASSERT_EQ (0, socket_util_url_decode ("hello", 5, buf, sizeof (buf), NULL));
  ASSERT (strcmp (buf, "hello") == 0);
}

TEST (url_decode_truncation)
{
  char buf[8];
  size_t len;

  /* Exact fit (7 chars + null terminator) */
  ASSERT_EQ (0, socket_util_url_decode ("1234567", 7, buf, sizeof (buf), &len));
  ASSERT (strcmp (buf, "1234567") == 0);
  ASSERT_EQ (7, len);

  /* Truncation: 8+ chars won't fit */
  ASSERT_EQ (-1,
             socket_util_url_decode ("12345678", 8, buf, sizeof (buf), &len));

  /* Truncation with encoded chars - fits exactly */
  ASSERT_EQ (0,
             socket_util_url_decode ("123456%20", 9, buf, sizeof (buf), &len));
  ASSERT (strcmp (buf, "123456 ") == 0);

  /* Actual truncation with encoded chars */
  ASSERT_EQ (
      -1, socket_util_url_decode ("1234567%20", 10, buf, sizeof (buf), &len));

  /* Zero-size buffer */
  ASSERT_EQ (-1, socket_util_url_decode ("test", 4, buf, 0, &len));
}

TEST (url_decode_special_chars)
{
  char buf[128];
  size_t len;

  /* Username:password encoding (colon) */
  ASSERT_EQ (
      0, socket_util_url_decode ("user%3Apass", 11, buf, sizeof (buf), &len));
  ASSERT (strcmp (buf, "user:pass") == 0);

  /* Path with slashes */
  ASSERT_EQ (0,
             socket_util_url_decode (
                 "%2Fpath%2Fto%2Ffile", 19, buf, sizeof (buf), &len));
  ASSERT (strcmp (buf, "/path/to/file") == 0);

  /* Query string characters */
  ASSERT_EQ (0,
             socket_util_url_decode (
                 "key%3Dvalue%26foo%3Dbar", 23, buf, sizeof (buf), &len));
  ASSERT (strcmp (buf, "key=value&foo=bar") == 0);

  /* Plus is not decoded to space (not application/x-www-form-urlencoded). */
  ASSERT_EQ (
      0, socket_util_url_decode ("hello+world", 11, buf, sizeof (buf), &len));
  ASSERT (strcmp (buf, "hello+world") == 0);
}

TEST (url_decode_proxy_credentials)
{
  char username[64];
  char password[64];

  /* Simple username */
  ASSERT_EQ (
      0,
      socket_util_url_decode ("admin", 5, username, sizeof (username), NULL));
  ASSERT (strcmp (username, "admin") == 0);

  /* Username with special chars */
  ASSERT_EQ (0,
             socket_util_url_decode (
                 "user%40domain.com", 17, username, sizeof (username), NULL));
  ASSERT (strcmp (username, "user@domain.com") == 0);

  /* Password with special chars */
  ASSERT_EQ (0,
             socket_util_url_decode (
                 "p%40ssw0rd%21", 13, password, sizeof (password), NULL));
  ASSERT (strcmp (password, "p@ssw0rd!") == 0);

  /* URL-unsafe password */
  ASSERT_EQ (0,
             socket_util_url_decode (
                 "a%2Fb%3Ac%20d", 13, password, sizeof (password), NULL));
  ASSERT (strcmp (password, "a/b:c d") == 0);
}

int
main (void)
{
  printf ("URL Utilities Tests\n");
  printf ("===================\n\n");

  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
