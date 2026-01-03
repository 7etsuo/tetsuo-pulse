/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_ipv6_parse.c - Unit tests for parse_ipv6_address()
 *
 * Part of the Socket Library
 *
 * Comprehensive unit tests for the parse_ipv6_address function in
 * src/core/SocketSYNProtect-ip.c. Tests valid IPv6 formats, invalid
 * inputs, edge cases, and error handling.
 */

#include "core/SocketSYNProtect-private.h"
#undef T  /* Undefine T from SocketSYNProtect-private.h before including Test.h */
#include "test/Test.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

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

/* ============================================================================
 * Valid IPv6 Address Tests
 * ============================================================================
 */

/**
 * test_ipv6_full_format - Test full IPv6 address format
 */
static int
test_ipv6_full_format (void)
{
  uint8_t addr_bytes[16];
  int result
      = parse_ipv6_address ("2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                            addr_bytes);

  if (result != 1)
    return 0;

  /* Verify expected bytes (network byte order) */
  uint8_t expected[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
                           0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34 };

  return memcmp (addr_bytes, expected, 16) == 0;
}

/**
 * test_ipv6_compressed - Test compressed IPv6 address
 */
static int
test_ipv6_compressed (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("2001:db8::1", addr_bytes);

  if (result != 1)
    return 0;

  /* Verify expected bytes */
  uint8_t expected[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

  return memcmp (addr_bytes, expected, 16) == 0;
}

/**
 * test_ipv6_loopback - Test IPv6 loopback address
 */
static int
test_ipv6_loopback (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("::1", addr_bytes);

  if (result != 1)
    return 0;

  /* Verify loopback: 15 zero bytes followed by 1 */
  uint8_t expected[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

  return memcmp (addr_bytes, expected, 16) == 0;
}

/**
 * test_ipv6_all_zeros - Test IPv6 all zeros address
 */
static int
test_ipv6_all_zeros (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("::", addr_bytes);

  if (result != 1)
    return 0;

  /* Verify all zeros */
  uint8_t expected[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  return memcmp (addr_bytes, expected, 16) == 0;
}

/**
 * test_ipv6_ipv4_mapped - Test IPv4-mapped IPv6 address
 */
static int
test_ipv6_ipv4_mapped (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("::ffff:192.168.1.1", addr_bytes);

  if (result != 1)
    return 0;

  /* Verify IPv4-mapped format: ::ffff:192.168.1.1 */
  uint8_t expected[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x01, 0x01 };

  return memcmp (addr_bytes, expected, 16) == 0;
}

/**
 * test_ipv6_link_local - Test link-local IPv6 address
 */
static int
test_ipv6_link_local (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("fe80::1", addr_bytes);

  if (result != 1)
    return 0;

  /* Verify link-local prefix fe80:: */
  if (addr_bytes[0] != 0xfe || addr_bytes[1] != 0x80)
    return 0;

  /* Verify suffix ::1 */
  return addr_bytes[15] == 0x01;
}

/**
 * test_ipv6_multicast - Test multicast IPv6 address
 */
static int
test_ipv6_multicast (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("ff02::1", addr_bytes);

  if (result != 1)
    return 0;

  /* Verify multicast prefix ff02:: */
  return addr_bytes[0] == 0xff && addr_bytes[1] == 0x02 && addr_bytes[15] == 0x01;
}

/* ============================================================================
 * Invalid Input Tests
 * ============================================================================
 */

/**
 * test_ipv6_null_ip - Test NULL pointer for ip parameter
 */
static int
test_ipv6_null_ip (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address (NULL, addr_bytes);

  /* Should return 0 for NULL input */
  return result == 0;
}

/**
 * test_ipv6_null_addr_bytes - Test NULL pointer for addr_bytes parameter
 */
static int
test_ipv6_null_addr_bytes (void)
{
  int result = parse_ipv6_address ("2001:db8::1", NULL);

  /* Should return 0 for NULL output buffer */
  return result == 0;
}

/**
 * test_ipv6_both_null - Test both parameters NULL
 */
static int
test_ipv6_both_null (void)
{
  int result = parse_ipv6_address (NULL, NULL);

  /* Should return 0 for NULL inputs */
  return result == 0;
}

/**
 * test_ipv6_invalid_ipv4 - Test IPv4 address (should fail)
 */
static int
test_ipv6_invalid_ipv4 (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("192.168.1.1", addr_bytes);

  /* IPv4 address should fail IPv6 parsing */
  return result == 0;
}

/**
 * test_ipv6_invalid_hex - Test invalid hexadecimal characters
 */
static int
test_ipv6_invalid_hex (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("2001:0dbg:85a3::1", addr_bytes);

  /* 'g' is not a valid hex character */
  return result == 0;
}

/**
 * test_ipv6_too_many_groups - Test too many groups
 */
static int
test_ipv6_too_many_groups (void)
{
  uint8_t addr_bytes[16];
  int result
      = parse_ipv6_address ("2001:db8:85a3:1:2:3:4:5:6", addr_bytes);

  /* IPv6 has max 8 groups */
  return result == 0;
}

/**
 * test_ipv6_group_too_long - Test group with more than 4 hex digits
 */
static int
test_ipv6_group_too_long (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("2001:0db8a:85a3::1", addr_bytes);

  /* Group should be max 4 hex digits */
  return result == 0;
}

/* ============================================================================
 * Edge Case Tests
 * ============================================================================
 */

/**
 * test_ipv6_empty_string - Test empty string
 */
static int
test_ipv6_empty_string (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("", addr_bytes);

  /* Empty string should fail */
  return result == 0;
}

/**
 * test_ipv6_multiple_compressions - Test multiple :: compressions (invalid)
 */
static int
test_ipv6_multiple_compressions (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("2001::db8::1", addr_bytes);

  /* Only one :: compression allowed */
  return result == 0;
}

/**
 * test_ipv6_leading_colon - Test invalid leading single colon
 */
static int
test_ipv6_leading_colon (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address (":2001:db8::1", addr_bytes);

  /* Single leading colon is invalid */
  return result == 0;
}

/**
 * test_ipv6_trailing_colon - Test invalid trailing single colon
 */
static int
test_ipv6_trailing_colon (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("2001:db8::1:", addr_bytes);

  /* Single trailing colon is invalid */
  return result == 0;
}

/**
 * test_ipv6_triple_colon - Test invalid triple colon
 */
static int
test_ipv6_triple_colon (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("2001:::db8", addr_bytes);

  /* Triple colon is invalid */
  return result == 0;
}

/**
 * test_ipv6_mixed_case - Test mixed case hex digits (should succeed)
 */
static int
test_ipv6_mixed_case (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("2001:0DB8:85A3::1", addr_bytes);

  if (result != 1)
    return 0;

  /* Verify parsing worked (compare to lowercase version) */
  uint8_t expected[16];
  parse_ipv6_address ("2001:0db8:85a3::1", expected);

  return memcmp (addr_bytes, expected, 16) == 0;
}

/**
 * test_ipv6_max_compression - Test maximum compression
 */
static int
test_ipv6_max_compression (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("::ffff:0:0", addr_bytes);

  if (result != 1)
    return 0;

  /* Verify structure: many zeros, then ffff:0:0 */
  return addr_bytes[10] == 0xff && addr_bytes[11] == 0xff;
}

/**
 * test_ipv6_no_compression - Test address without compression
 */
static int
test_ipv6_no_compression (void)
{
  uint8_t addr_bytes[16];
  int result
      = parse_ipv6_address ("2001:0db8:0000:0000:0000:0000:0000:0001",
                            addr_bytes);

  if (result != 1)
    return 0;

  /* Verify can parse full uncompressed form */
  uint8_t expected[16];
  parse_ipv6_address ("2001:db8::1", expected);

  return memcmp (addr_bytes, expected, 16) == 0;
}

/* ============================================================================
 * Boundary Tests
 * ============================================================================
 */

/**
 * test_ipv6_all_f - Test all F's address
 */
static int
test_ipv6_all_f (void)
{
  uint8_t addr_bytes[16];
  int result
      = parse_ipv6_address ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                            addr_bytes);

  if (result != 1)
    return 0;

  /* Verify all bytes are 0xff */
  for (int i = 0; i < 16; i++)
    {
      if (addr_bytes[i] != 0xff)
        return 0;
    }

  return 1;
}

/**
 * test_ipv6_partial_compression_start - Test compression at start
 */
static int
test_ipv6_partial_compression_start (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("::1234:5678", addr_bytes);

  if (result != 1)
    return 0;

  /* Verify trailing bytes */
  return addr_bytes[12] == 0x12 && addr_bytes[13] == 0x34
         && addr_bytes[14] == 0x56 && addr_bytes[15] == 0x78;
}

/**
 * test_ipv6_partial_compression_end - Test compression at end
 */
static int
test_ipv6_partial_compression_end (void)
{
  uint8_t addr_bytes[16];
  int result = parse_ipv6_address ("1234:5678::", addr_bytes);

  if (result != 1)
    return 0;

  /* Verify leading bytes */
  return addr_bytes[0] == 0x12 && addr_bytes[1] == 0x34
         && addr_bytes[2] == 0x56 && addr_bytes[3] == 0x78;
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================
 */

int
main (void)
{
  printf ("\n=== parse_ipv6_address() Unit Tests ===\n\n");

  printf ("Valid IPv6 Addresses:\n");
  RUN_TEST (test_ipv6_full_format);
  RUN_TEST (test_ipv6_compressed);
  RUN_TEST (test_ipv6_loopback);
  RUN_TEST (test_ipv6_all_zeros);
  RUN_TEST (test_ipv6_ipv4_mapped);
  RUN_TEST (test_ipv6_link_local);
  RUN_TEST (test_ipv6_multicast);

  printf ("\nInvalid Inputs:\n");
  RUN_TEST (test_ipv6_null_ip);
  RUN_TEST (test_ipv6_null_addr_bytes);
  RUN_TEST (test_ipv6_both_null);
  RUN_TEST (test_ipv6_invalid_ipv4);
  RUN_TEST (test_ipv6_invalid_hex);
  RUN_TEST (test_ipv6_too_many_groups);
  RUN_TEST (test_ipv6_group_too_long);

  printf ("\nEdge Cases:\n");
  RUN_TEST (test_ipv6_empty_string);
  RUN_TEST (test_ipv6_multiple_compressions);
  RUN_TEST (test_ipv6_leading_colon);
  RUN_TEST (test_ipv6_trailing_colon);
  RUN_TEST (test_ipv6_triple_colon);
  RUN_TEST (test_ipv6_mixed_case);
  RUN_TEST (test_ipv6_max_compression);
  RUN_TEST (test_ipv6_no_compression);

  printf ("\nBoundary Tests:\n");
  RUN_TEST (test_ipv6_all_f);
  RUN_TEST (test_ipv6_partial_compression_start);
  RUN_TEST (test_ipv6_partial_compression_end);

  printf ("\n=== Results: %d/%d tests passed ===\n\n", tests_passed,
          tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}
