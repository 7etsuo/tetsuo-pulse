/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_synprotect_ip_parsing.c - Unit tests for IP parsing functions
 *
 * Part of the Socket Library
 *
 * Dedicated unit tests for the parse_ip_address function and its helpers
 * in src/core/SocketSYNProtect-ip.c. These tests verify dual-stack IP
 * parsing (IPv4/IPv6) with edge cases and error handling.
 */

#include "core/SocketConfig.h"
#include "test/Test.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Forward declarations of internal functions from SocketSYNProtect-ip.c */
extern int
parse_ip_address (const char *ip, uint8_t *addr_bytes, size_t addr_size);

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

/**
 * test_ipv4_standard - Test standard IPv4 address parsing
 */
static int
test_ipv4_standard (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  memset (addr_bytes, 0xFF, sizeof (addr_bytes));

  family = parse_ip_address ("192.168.1.1", addr_bytes, sizeof (addr_bytes));

  /* Should return AF_INET (2) */
  if (family != AF_INET)
    return 0;

  /* Verify bytes are correctly set (network byte order) */
  struct in_addr expected;
  inet_pton (AF_INET, "192.168.1.1", &expected);

  if (memcmp (addr_bytes, &expected.s_addr, SOCKET_IPV4_ADDR_BYTES) != 0)
    return 0;

  return 1;
}

/**
 * test_ipv4_loopback - Test IPv4 loopback address
 */
static int
test_ipv4_loopback (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  family = parse_ip_address ("127.0.0.1", addr_bytes, sizeof (addr_bytes));

  if (family != AF_INET)
    return 0;

  struct in_addr expected;
  inet_pton (AF_INET, "127.0.0.1", &expected);

  return memcmp (addr_bytes, &expected.s_addr, SOCKET_IPV4_ADDR_BYTES) == 0;
}

/**
 * test_ipv4_zeros - Test IPv4 address with all zeros
 */
static int
test_ipv4_zeros (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  family = parse_ip_address ("0.0.0.0", addr_bytes, sizeof (addr_bytes));

  if (family != AF_INET)
    return 0;

  struct in_addr expected;
  inet_pton (AF_INET, "0.0.0.0", &expected);

  return memcmp (addr_bytes, &expected.s_addr, SOCKET_IPV4_ADDR_BYTES) == 0;
}

/**
 * test_ipv4_broadcast - Test IPv4 broadcast address
 */
static int
test_ipv4_broadcast (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  family
      = parse_ip_address ("255.255.255.255", addr_bytes, sizeof (addr_bytes));

  if (family != AF_INET)
    return 0;

  struct in_addr expected;
  inet_pton (AF_INET, "255.255.255.255", &expected);

  return memcmp (addr_bytes, &expected.s_addr, SOCKET_IPV4_ADDR_BYTES) == 0;
}

/**
 * test_ipv6_standard - Test standard IPv6 address parsing
 */
static int
test_ipv6_standard (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  memset (addr_bytes, 0xFF, sizeof (addr_bytes));

  family = parse_ip_address ("2001:db8::1", addr_bytes, sizeof (addr_bytes));

  /* Should return AF_INET6 (10) */
  if (family != AF_INET6)
    return 0;

  /* Verify bytes are correctly set */
  struct in6_addr expected;
  inet_pton (AF_INET6, "2001:db8::1", &expected);

  if (memcmp (addr_bytes, expected.s6_addr, SOCKET_IPV6_ADDR_BYTES) != 0)
    return 0;

  return 1;
}

/**
 * test_ipv6_loopback - Test IPv6 loopback address
 */
static int
test_ipv6_loopback (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  family = parse_ip_address ("::1", addr_bytes, sizeof (addr_bytes));

  if (family != AF_INET6)
    return 0;

  struct in6_addr expected;
  inet_pton (AF_INET6, "::1", &expected);

  return memcmp (addr_bytes, expected.s6_addr, SOCKET_IPV6_ADDR_BYTES) == 0;
}

/**
 * test_ipv6_zeros - Test IPv6 all zeros address
 */
static int
test_ipv6_zeros (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  family = parse_ip_address ("::", addr_bytes, sizeof (addr_bytes));

  if (family != AF_INET6)
    return 0;

  struct in6_addr expected;
  inet_pton (AF_INET6, "::", &expected);

  return memcmp (addr_bytes, expected.s6_addr, SOCKET_IPV6_ADDR_BYTES) == 0;
}

/**
 * test_ipv6_full_form - Test IPv6 full form (no compression)
 */
static int
test_ipv6_full_form (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  family = parse_ip_address ("2001:0db8:0000:0000:0000:0000:0000:0001",
                             addr_bytes,
                             sizeof (addr_bytes));

  if (family != AF_INET6)
    return 0;

  struct in6_addr expected;
  inet_pton (AF_INET6, "2001:0db8:0000:0000:0000:0000:0000:0001", &expected);

  return memcmp (addr_bytes, expected.s6_addr, SOCKET_IPV6_ADDR_BYTES) == 0;
}

/**
 * test_ipv6_compressed - Test IPv6 with multiple compressions
 */
static int
test_ipv6_compressed (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  family = parse_ip_address ("fe80::1", addr_bytes, sizeof (addr_bytes));

  if (family != AF_INET6)
    return 0;

  struct in6_addr expected;
  inet_pton (AF_INET6, "fe80::1", &expected);

  return memcmp (addr_bytes, expected.s6_addr, SOCKET_IPV6_ADDR_BYTES) == 0;
}

/**
 * test_null_ip_pointer - Test NULL ip parameter
 */
static int
test_null_ip_pointer (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  family = parse_ip_address (NULL, addr_bytes, sizeof (addr_bytes));

  /* Should return 0 on error */
  return (family == 0);
}

/**
 * test_null_addr_bytes_pointer - Test NULL addr_bytes parameter
 */
static int
test_null_addr_bytes_pointer (void)
{
  int family;

  family = parse_ip_address ("192.168.1.1", NULL, 16);

  /* Should return 0 on error */
  return (family == 0);
}

/**
 * test_insufficient_buffer_size - Test addr_size < 16
 */
static int
test_insufficient_buffer_size (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  /* Buffer size less than SOCKET_IPV6_ADDR_BYTES (16) */
  family = parse_ip_address ("192.168.1.1", addr_bytes, 15);

  /* Should return 0 on error */
  return (family == 0);
}

/**
 * test_invalid_ipv4_string - Test invalid IPv4 string
 */
static int
test_invalid_ipv4_string (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  /* Invalid IPv4 - out of range octet */
  family = parse_ip_address ("256.1.1.1", addr_bytes, sizeof (addr_bytes));
  if (family != 0)
    return 0;

  /* Invalid IPv4 - too many octets */
  family = parse_ip_address ("1.2.3.4.5", addr_bytes, sizeof (addr_bytes));
  if (family != 0)
    return 0;

  /* Invalid IPv4 - non-numeric */
  family
      = parse_ip_address ("abc.def.ghi.jkl", addr_bytes, sizeof (addr_bytes));
  if (family != 0)
    return 0;

  return 1;
}

/**
 * test_invalid_ipv6_string - Test invalid IPv6 string
 */
static int
test_invalid_ipv6_string (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  /* Invalid IPv6 - too many groups */
  family = parse_ip_address (
      "2001:db8:0:0:0:0:0:0:1", addr_bytes, sizeof (addr_bytes));
  if (family != 0)
    return 0;

  /* Invalid IPv6 - invalid characters */
  family = parse_ip_address ("gggg::1", addr_bytes, sizeof (addr_bytes));
  if (family != 0)
    return 0;

  /* Invalid IPv6 - multiple :: */
  family = parse_ip_address ("2001::db8::1", addr_bytes, sizeof (addr_bytes));
  if (family != 0)
    return 0;

  return 1;
}

/**
 * test_empty_string - Test empty string
 */
static int
test_empty_string (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  family = parse_ip_address ("", addr_bytes, sizeof (addr_bytes));

  /* Should return 0 on error */
  return (family == 0);
}

/**
 * test_whitespace_string - Test string with whitespace
 */
static int
test_whitespace_string (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  /* Leading space */
  family = parse_ip_address (" 192.168.1.1", addr_bytes, sizeof (addr_bytes));
  if (family != 0)
    return 0;

  /* Trailing space */
  family = parse_ip_address ("192.168.1.1 ", addr_bytes, sizeof (addr_bytes));
  if (family != 0)
    return 0;

  return 1;
}

/**
 * test_buffer_zeroing - Test that IPv4 zeros upper bytes
 */
static int
test_buffer_zeroing (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  /* Fill buffer with non-zero values */
  memset (addr_bytes, 0xAA, sizeof (addr_bytes));

  family = parse_ip_address ("10.0.0.1", addr_bytes, sizeof (addr_bytes));

  if (family != AF_INET)
    return 0;

  /* For IPv4, the implementation zeros the full buffer first */
  /* Check that bytes 4-15 are zero */
  for (int i = SOCKET_IPV4_ADDR_BYTES; i < SOCKET_IPV6_ADDR_BYTES; i++)
    {
      if (addr_bytes[i] != 0)
        return 0;
    }

  return 1;
}

/**
 * test_exact_buffer_size - Test with exact minimum buffer size
 */
static int
test_exact_buffer_size (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  /* Exactly 16 bytes should work */
  family = parse_ip_address ("192.168.1.1", addr_bytes, 16);

  return (family == AF_INET);
}

/**
 * test_large_buffer_size - Test with larger than needed buffer
 */
static int
test_large_buffer_size (void)
{
  uint8_t addr_bytes[32]; /* Larger than needed */
  int family;

  family = parse_ip_address ("192.168.1.1", addr_bytes, 32);

  return (family == AF_INET);
}

/**
 * test_ipv4_mapped_ipv6 - Test IPv4-mapped IPv6 address
 */
static int
test_ipv4_mapped_ipv6 (void)
{
  uint8_t addr_bytes[SOCKET_IPV6_ADDR_BYTES];
  int family;

  /* IPv4-mapped IPv6 format: ::ffff:192.0.2.1 */
  family
      = parse_ip_address ("::ffff:192.0.2.1", addr_bytes, sizeof (addr_bytes));

  /* inet_pton should parse this as IPv6 */
  if (family != AF_INET6)
    return 0;

  struct in6_addr expected;
  inet_pton (AF_INET6, "::ffff:192.0.2.1", &expected);

  return memcmp (addr_bytes, expected.s6_addr, SOCKET_IPV6_ADDR_BYTES) == 0;
}

int
main (void)
{
  printf ("\n=== IP Parsing Unit Tests (parse_ip_address) ===\n\n");

  printf ("IPv4 Parsing Tests:\n");
  RUN_TEST (test_ipv4_standard);
  RUN_TEST (test_ipv4_loopback);
  RUN_TEST (test_ipv4_zeros);
  RUN_TEST (test_ipv4_broadcast);

  printf ("\nIPv6 Parsing Tests:\n");
  RUN_TEST (test_ipv6_standard);
  RUN_TEST (test_ipv6_loopback);
  RUN_TEST (test_ipv6_zeros);
  RUN_TEST (test_ipv6_full_form);
  RUN_TEST (test_ipv6_compressed);

  printf ("\nInvalid Input Tests:\n");
  RUN_TEST (test_null_ip_pointer);
  RUN_TEST (test_null_addr_bytes_pointer);
  RUN_TEST (test_insufficient_buffer_size);
  RUN_TEST (test_invalid_ipv4_string);
  RUN_TEST (test_invalid_ipv6_string);
  RUN_TEST (test_empty_string);
  RUN_TEST (test_whitespace_string);

  printf ("\nEdge Cases:\n");
  RUN_TEST (test_buffer_zeroing);
  RUN_TEST (test_exact_buffer_size);
  RUN_TEST (test_large_buffer_size);
  RUN_TEST (test_ipv4_mapped_ipv6);

  printf ("\n=== Results: %d/%d tests passed ===\n\n", tests_passed, tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}
