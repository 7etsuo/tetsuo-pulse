/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_ipv4_parse.c - Unit tests for parse_ipv4_address
 *
 * Part of the Socket Library
 *
 * Tests for the parse_ipv4_address function in src/core/SocketSYNProtect-ip.c
 * Covers valid addresses, invalid inputs, and edge cases.
 */

#include "core/SocketConfig.h"
#include "test/Test.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

/* Forward declaration of the function under test */
int parse_ipv4_address (const char *ip, uint8_t *addr_bytes);

/* Test counters */
static int tests_run = 0;
static int tests_passed = 0;

#define RUN_TEST(test_func)                     \
  do                                            \
    {                                           \
      printf ("  Running: %s... ", #test_func); \
      fflush (stdout);                          \
      tests_run++;                              \
      if (test_func ())                         \
        {                                       \
          printf ("PASSED\n");                  \
          tests_passed++;                       \
        }                                       \
      else                                      \
        {                                       \
          printf ("FAILED\n");                  \
        }                                       \
    }                                           \
  while (0)

/* Helper to verify byte array is zeroed from index start to end-1 */
static int
bytes_are_zero (const uint8_t *bytes, size_t start, size_t end)
{
  for (size_t i = start; i < end; i++)
    {
      if (bytes[i] != 0)
        return 0;
    }
  return 1;
}

/* ============================================================================
 * Valid IPv4 Address Tests
 * ============================================================================
 */

/**
 * test_parse_standard_ipv4 - Test parsing standard format IPv4 addresses
 */
static int
test_parse_standard_ipv4 (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  memset (addr_bytes, 0xFF, sizeof (addr_bytes));

  int result = parse_ipv4_address ("192.168.1.1", addr_bytes);

  if (result != 1)
    return 0;

  /* Verify first 4 bytes match expected IPv4 address */
  if (addr_bytes[0] != 192 || addr_bytes[1] != 168 || addr_bytes[2] != 1
      || addr_bytes[3] != 1)
    return 0;

  /* Verify bytes 4-15 are zeroed */
  if (!bytes_are_zero (addr_bytes, 4, SOCKET_IPV6_ADDR_BYTES))
    return 0;

  return 1;
}

/**
 * test_parse_edge_zero_ipv4 - Test parsing 0.0.0.0
 */
static int
test_parse_edge_zero_ipv4 (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  memset (addr_bytes, 0xFF, sizeof (addr_bytes));

  int result = parse_ipv4_address ("0.0.0.0", addr_bytes);

  if (result != 1)
    return 0;

  /* All 16 bytes should be zero */
  if (!bytes_are_zero (addr_bytes, 0, SOCKET_IPV6_ADDR_BYTES))
    return 0;

  return 1;
}

/**
 * test_parse_edge_max_ipv4 - Test parsing 255.255.255.255
 */
static int
test_parse_edge_max_ipv4 (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  memset (addr_bytes, 0, sizeof (addr_bytes));

  int result = parse_ipv4_address ("255.255.255.255", addr_bytes);

  if (result != 1)
    return 0;

  /* Verify first 4 bytes are 255 */
  if (addr_bytes[0] != 255 || addr_bytes[1] != 255 || addr_bytes[2] != 255
      || addr_bytes[3] != 255)
    return 0;

  /* Verify bytes 4-15 are zeroed */
  if (!bytes_are_zero (addr_bytes, 4, SOCKET_IPV6_ADDR_BYTES))
    return 0;

  return 1;
}

/**
 * test_parse_leading_zeros_ipv4 - Test parsing with leading zeros
 */
static int
test_parse_leading_zeros_ipv4 (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  memset (addr_bytes, 0xFF, sizeof (addr_bytes));

  /* inet_pton behavior with leading zeros varies - it may accept or reject
   * Based on the implementation using inet_pton, we test what it actually does
   */
  int result = parse_ipv4_address ("192.168.001.001", addr_bytes);

  /* inet_pton typically accepts leading zeros, parsing as decimal */
  /* If successful, verify bytes match 192.168.1.1 */
  if (result == 1)
    {
      if (addr_bytes[0] != 192 || addr_bytes[1] != 168 || addr_bytes[2] != 1
          || addr_bytes[3] != 1)
        return 0;

      if (!bytes_are_zero (addr_bytes, 4, SOCKET_IPV6_ADDR_BYTES))
        return 0;
    }
  /* If rejected, that's also valid behavior for inet_pton */

  return 1;
}

/**
 * test_parse_localhost_ipv4 - Test parsing 127.0.0.1
 */
static int
test_parse_localhost_ipv4 (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  memset (addr_bytes, 0xFF, sizeof (addr_bytes));

  int result = parse_ipv4_address ("127.0.0.1", addr_bytes);

  if (result != 1)
    return 0;

  if (addr_bytes[0] != 127 || addr_bytes[1] != 0 || addr_bytes[2] != 0
      || addr_bytes[3] != 1)
    return 0;

  if (!bytes_are_zero (addr_bytes, 4, SOCKET_IPV6_ADDR_BYTES))
    return 0;

  return 1;
}

/* ============================================================================
 * Invalid Input Tests
 * ============================================================================
 */

/**
 * test_parse_null_ip - Test with NULL ip parameter
 */
static int
test_parse_null_ip (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  memset (addr_bytes, 0xFF, sizeof (addr_bytes));

  int result = parse_ipv4_address (NULL, addr_bytes);

  /* Should return 0 for failure */
  if (result != 0)
    return 0;

  /* addr_bytes should be unchanged */
  for (size_t i = 0; i < SOCKET_IPV6_ADDR_BYTES; i++)
    {
      if (addr_bytes[i] != 0xFF)
        return 0;
    }

  return 1;
}

/**
 * test_parse_null_addr_bytes - Test with NULL addr_bytes parameter
 */
static int
test_parse_null_addr_bytes (void)
{
  int result = parse_ipv4_address ("192.168.1.1", NULL);

  /* Should return 0 for failure */
  return (result == 0);
}

/**
 * test_parse_both_null - Test with both parameters NULL
 */
static int
test_parse_both_null (void)
{
  int result = parse_ipv4_address (NULL, NULL);

  /* Should return 0 for failure */
  return (result == 0);
}

/**
 * test_parse_empty_string - Test with empty string
 */
static int
test_parse_empty_string (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  memset (addr_bytes, 0xFF, sizeof (addr_bytes));

  int result = parse_ipv4_address ("", addr_bytes);

  /* Should return 0 for failure */
  if (result != 0)
    return 0;

  /* addr_bytes should be unchanged */
  for (size_t i = 0; i < SOCKET_IPV6_ADDR_BYTES; i++)
    {
      if (addr_bytes[i] != 0xFF)
        return 0;
    }

  return 1;
}

/**
 * test_parse_octet_too_large - Test with octet > 255
 */
static int
test_parse_octet_too_large (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  memset (addr_bytes, 0xFF, sizeof (addr_bytes));

  int result = parse_ipv4_address ("256.1.1.1", addr_bytes);

  /* Should return 0 for failure */
  if (result != 0)
    return 0;

  /* addr_bytes should be unchanged */
  for (size_t i = 0; i < SOCKET_IPV6_ADDR_BYTES; i++)
    {
      if (addr_bytes[i] != 0xFF)
        return 0;
    }

  return 1;
}

/**
 * test_parse_missing_octet - Test with missing octet
 */
static int
test_parse_missing_octet (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  memset (addr_bytes, 0xFF, sizeof (addr_bytes));

  int result = parse_ipv4_address ("192.168.1", addr_bytes);

  /* Should return 0 for failure */
  if (result != 0)
    return 0;

  /* addr_bytes should be unchanged */
  for (size_t i = 0; i < SOCKET_IPV6_ADDR_BYTES; i++)
    {
      if (addr_bytes[i] != 0xFF)
        return 0;
    }

  return 1;
}

/**
 * test_parse_too_many_octets - Test with too many octets
 */
static int
test_parse_too_many_octets (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  memset (addr_bytes, 0xFF, sizeof (addr_bytes));

  int result = parse_ipv4_address ("192.168.1.1.1", addr_bytes);

  /* Should return 0 for failure */
  if (result != 0)
    return 0;

  /* addr_bytes should be unchanged */
  for (size_t i = 0; i < SOCKET_IPV6_ADDR_BYTES; i++)
    {
      if (addr_bytes[i] != 0xFF)
        return 0;
    }

  return 1;
}

/**
 * test_parse_non_numeric - Test with non-numeric octets
 */
static int
test_parse_non_numeric (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  memset (addr_bytes, 0xFF, sizeof (addr_bytes));

  int result = parse_ipv4_address ("abc.def.ghi.jkl", addr_bytes);

  /* Should return 0 for failure */
  if (result != 0)
    return 0;

  /* addr_bytes should be unchanged */
  for (size_t i = 0; i < SOCKET_IPV6_ADDR_BYTES; i++)
    {
      if (addr_bytes[i] != 0xFF)
        return 0;
    }

  return 1;
}

/**
 * test_parse_ipv6_format - Test that IPv6 address fails
 */
static int
test_parse_ipv6_format (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  memset (addr_bytes, 0xFF, sizeof (addr_bytes));

  int result = parse_ipv4_address ("2001:db8::1", addr_bytes);

  /* Should return 0 for failure */
  if (result != 0)
    return 0;

  /* addr_bytes should be unchanged */
  for (size_t i = 0; i < SOCKET_IPV6_ADDR_BYTES; i++)
    {
      if (addr_bytes[i] != 0xFF)
        return 0;
    }

  return 1;
}

/**
 * test_parse_partial_address - Test partial address
 */
static int
test_parse_partial_address (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  memset (addr_bytes, 0xFF, sizeof (addr_bytes));

  int result = parse_ipv4_address ("10.", addr_bytes);

  /* Should return 0 for failure */
  if (result != 0)
    return 0;

  /* addr_bytes should be unchanged */
  for (size_t i = 0; i < SOCKET_IPV6_ADDR_BYTES; i++)
    {
      if (addr_bytes[i] != 0xFF)
        return 0;
    }

  return 1;
}

/**
 * test_parse_trailing_dot - Test with trailing dot
 */
static int
test_parse_trailing_dot (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  memset (addr_bytes, 0xFF, sizeof (addr_bytes));

  int result = parse_ipv4_address ("192.168.1.1.", addr_bytes);

  /* Should return 0 for failure */
  if (result != 0)
    return 0;

  /* addr_bytes should be unchanged */
  for (size_t i = 0; i < SOCKET_IPV6_ADDR_BYTES; i++)
    {
      if (addr_bytes[i] != 0xFF)
        return 0;
    }

  return 1;
}

/**
 * test_parse_negative_octet - Test with negative octet
 */
static int
test_parse_negative_octet (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  memset (addr_bytes, 0xFF, sizeof (addr_bytes));

  int result = parse_ipv4_address ("192.168.-1.1", addr_bytes);

  /* Should return 0 for failure */
  if (result != 0)
    return 0;

  /* addr_bytes should be unchanged */
  for (size_t i = 0; i < SOCKET_IPV6_ADDR_BYTES; i++)
    {
      if (addr_bytes[i] != 0xFF)
        return 0;
    }

  return 1;
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================
 */

int
main (void)
{
  printf ("\n=== parse_ipv4_address Unit Tests ===\n\n");

  printf ("Valid IPv4 Address Tests:\n");
  RUN_TEST (test_parse_standard_ipv4);
  RUN_TEST (test_parse_edge_zero_ipv4);
  RUN_TEST (test_parse_edge_max_ipv4);
  RUN_TEST (test_parse_leading_zeros_ipv4);
  RUN_TEST (test_parse_localhost_ipv4);

  printf ("\nInvalid Input Tests:\n");
  RUN_TEST (test_parse_null_ip);
  RUN_TEST (test_parse_null_addr_bytes);
  RUN_TEST (test_parse_both_null);
  RUN_TEST (test_parse_empty_string);
  RUN_TEST (test_parse_octet_too_large);
  RUN_TEST (test_parse_missing_octet);
  RUN_TEST (test_parse_too_many_octets);
  RUN_TEST (test_parse_non_numeric);
  RUN_TEST (test_parse_ipv6_format);
  RUN_TEST (test_parse_partial_address);
  RUN_TEST (test_parse_trailing_dot);
  RUN_TEST (test_parse_negative_octet);

  printf ("\n=== Results: %d/%d tests passed ===\n\n", tests_passed,
          tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}
