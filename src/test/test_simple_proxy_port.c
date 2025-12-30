/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_simple_proxy_port.c - Port parsing security test
 * Tests that strtol overflow checks work correctly in proxy URL parsing
 * Addresses CWE-190: Integer Overflow or Wraparound
 * Addresses CERT C: ERR34-C (Detect errors when converting string to number)
 */

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "simple/SocketSimple-proxy.h"
#include "simple/SocketSimple.h"
#include "test/Test.h"

/* Test that valid ports are parsed correctly */
TEST (proxy_port_valid_parsing)
{
  SocketSimple_ProxyConfig config;
  int result;

  /* Standard HTTP proxy port */
  result = Socket_simple_proxy_parse_url ("http://proxy.example.com:8080",
                                          &config);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (config.port, 8080);

  /* SOCKS5 proxy with standard port */
  result = Socket_simple_proxy_parse_url ("socks5://proxy.example.com:1080",
                                          &config);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (config.port, 1080);

  /* Port 1 (minimum valid) */
  result = Socket_simple_proxy_parse_url ("http://proxy.example.com:1",
                                          &config);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (config.port, 1);

  /* Port 65535 (maximum valid) */
  result = Socket_simple_proxy_parse_url ("http://proxy.example.com:65535",
                                          &config);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (config.port, 65535);
}

/* Test that port 0 is rejected */
TEST (proxy_port_zero_rejected)
{
  SocketSimple_ProxyConfig config;
  int result;

  result = Socket_simple_proxy_parse_url ("http://proxy.example.com:0",
                                          &config);
  ASSERT_EQ (result, -1);
  ASSERT_EQ (Socket_simple_code (), SOCKET_SIMPLE_ERR_INVALID_ARG);
}

/* Test that negative ports are rejected */
TEST (proxy_port_negative_rejected)
{
  SocketSimple_ProxyConfig config;
  int result;

  result = Socket_simple_proxy_parse_url ("http://proxy.example.com:-1",
                                          &config);
  ASSERT_EQ (result, -1);
  ASSERT_EQ (Socket_simple_code (), SOCKET_SIMPLE_ERR_INVALID_ARG);

  result = Socket_simple_proxy_parse_url ("http://proxy.example.com:-8080",
                                          &config);
  ASSERT_EQ (result, -1);
  ASSERT_EQ (Socket_simple_code (), SOCKET_SIMPLE_ERR_INVALID_ARG);
}

/* Test that ports > 65535 are rejected */
TEST (proxy_port_too_large_rejected)
{
  SocketSimple_ProxyConfig config;
  int result;

  result = Socket_simple_proxy_parse_url ("http://proxy.example.com:65536",
                                          &config);
  ASSERT_EQ (result, -1);
  ASSERT_EQ (Socket_simple_code (), SOCKET_SIMPLE_ERR_INVALID_ARG);

  result = Socket_simple_proxy_parse_url ("http://proxy.example.com:99999",
                                          &config);
  ASSERT_EQ (result, -1);
  ASSERT_EQ (Socket_simple_code (), SOCKET_SIMPLE_ERR_INVALID_ARG);
}

/* Test that non-numeric ports are rejected */
TEST (proxy_port_non_numeric_rejected)
{
  SocketSimple_ProxyConfig config;
  int result;

  result = Socket_simple_proxy_parse_url ("http://proxy.example.com:abc",
                                          &config);
  ASSERT_EQ (result, -1);
  ASSERT_EQ (Socket_simple_code (), SOCKET_SIMPLE_ERR_INVALID_ARG);

  result = Socket_simple_proxy_parse_url ("http://proxy.example.com:80x",
                                          &config);
  ASSERT_EQ (result, -1);
  ASSERT_EQ (Socket_simple_code (), SOCKET_SIMPLE_ERR_INVALID_ARG);
}

/* Test that LONG_MAX overflow is detected */
TEST (proxy_port_overflow_detected)
{
  SocketSimple_ProxyConfig config;
  int result;
  char url[256];

  /* Test with LONG_MAX */
  snprintf (url, sizeof (url), "http://proxy.example.com:%ld", LONG_MAX);
  result = Socket_simple_proxy_parse_url (url, &config);
  ASSERT_EQ (result, -1);
  ASSERT_EQ (Socket_simple_code (), SOCKET_SIMPLE_ERR_INVALID_ARG);

  /* Test with LONG_MIN */
  snprintf (url, sizeof (url), "http://proxy.example.com:%ld", LONG_MIN);
  result = Socket_simple_proxy_parse_url (url, &config);
  ASSERT_EQ (result, -1);
  ASSERT_EQ (Socket_simple_code (), SOCKET_SIMPLE_ERR_INVALID_ARG);
}

/* Test that very long numeric strings that would overflow are rejected */
TEST (proxy_port_very_long_number_rejected)
{
  SocketSimple_ProxyConfig config;
  int result;

  /* A number way beyond LONG_MAX (many 9's) */
  result = Socket_simple_proxy_parse_url (
      "http://proxy.example.com:99999999999999999999999999999999", &config);
  ASSERT_EQ (result, -1);
  ASSERT_EQ (Socket_simple_code (), SOCKET_SIMPLE_ERR_INVALID_ARG);
}

/* Test default ports when port is omitted */
TEST (proxy_port_default_values)
{
  SocketSimple_ProxyConfig config;
  int result;

  /* HTTP defaults to 8080 */
  result = Socket_simple_proxy_parse_url ("http://proxy.example.com", &config);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (config.port, 8080);

  /* SOCKS5 defaults to 1080 */
  result
      = Socket_simple_proxy_parse_url ("socks5://proxy.example.com", &config);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (config.port, 1080);
}

/* Test IPv6 addresses with port */
TEST (proxy_port_ipv6_parsing)
{
  SocketSimple_ProxyConfig config;
  int result;

  result = Socket_simple_proxy_parse_url ("http://[::1]:8080", &config);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (config.port, 8080);
  ASSERT (strcmp (config.host, "::1") == 0);

  result = Socket_simple_proxy_parse_url (
      "http://[2001:db8::1]:1080", &config);
  ASSERT_EQ (result, 0);
  ASSERT_EQ (config.port, 1080);
  ASSERT (strcmp (config.host, "2001:db8::1") == 0);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
