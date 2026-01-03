/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_ip_equality.c - Unit tests for ip_addresses_equal
 * Tests for the IP address equality comparison function.
 * Covers string equality, binary comparison, different families, and invalid inputs.
 */

#include <assert.h>
#include <string.h>

#include "core/SocketSYNProtect-private.h"
#undef T  /* Undefine SocketSYNProtect_T before including Test.h */
#include "test/Test.h"

/* Test 1: Identical strings - String equality fast path */
TEST (ip_equality_identical_strings)
{
  int result = ip_addresses_equal ("192.168.1.1", "192.168.1.1");
  ASSERT_EQ (1, result);
}

/* Test 2: IPv6 identical strings (case sensitivity) */
TEST (ip_equality_ipv6_lowercase)
{
  int result = ip_addresses_equal ("2001:db8::1", "2001:db8::1");
  ASSERT_EQ (1, result);
}

/* Test 3: IPv6 case sensitivity - uppercase vs lowercase (should be equal) */
TEST (ip_equality_ipv6_case_insensitive)
{
  int result = ip_addresses_equal ("2001:db8::1", "2001:DB8::1");
  ASSERT_EQ (1, result);
}

/* Test 4: IPv4 different representations with leading zeros
 * Note: Modern inet_pton() REJECTS leading zeros for security (octal ambiguity)
 * So this returns 0 (invalid), not 1 (equal)
 */
TEST (ip_equality_ipv4_leading_zeros_invalid)
{
  int result = ip_addresses_equal ("192.168.1.1", "192.168.001.001");
  ASSERT_EQ (0, result);  /* Leading zeros make it invalid */
}

/* Test 5: IPv6 compressed vs full (bypass prevention) */
TEST (ip_equality_ipv6_compressed_vs_full)
{
  int result
      = ip_addresses_equal ("2001:db8::1",
                            "2001:0db8:0000:0000:0000:0000:0000:0001");
  ASSERT_EQ (1, result);
}

/* Test 6: IPv6 different compressions of same address */
TEST (ip_equality_ipv6_different_compressions)
{
  int result = ip_addresses_equal ("2001:db8:0:0:0:0:0:1", "2001:db8::1");
  ASSERT_EQ (1, result);
}

/* Test 7: Different IPv4 addresses */
TEST (ip_equality_different_ipv4)
{
  int result = ip_addresses_equal ("192.168.1.1", "192.168.1.2");
  ASSERT_EQ (0, result);
}

/* Test 8: Different IPv6 addresses */
TEST (ip_equality_different_ipv6)
{
  int result = ip_addresses_equal ("2001:db8::1", "2001:db8::2");
  ASSERT_EQ (0, result);
}

/* Test 9: Different address families - IPv4 vs IPv6 loopback */
TEST (ip_equality_different_families_loopback)
{
  int result = ip_addresses_equal ("127.0.0.1", "::1");
  ASSERT_EQ (0, result);
}

/* Test 10: Different address families - IPv4 vs IPv4-mapped IPv6 */
TEST (ip_equality_ipv4_vs_mapped)
{
  int result = ip_addresses_equal ("192.168.1.1", "::ffff:192.168.1.1");
  ASSERT_EQ (0, result);
}

/* Test 11: NULL ip1 */
TEST (ip_equality_null_ip1)
{
  int result = ip_addresses_equal (NULL, "192.168.1.1");
  ASSERT_EQ (0, result);
}

/* Test 12: NULL ip2 */
TEST (ip_equality_null_ip2)
{
  int result = ip_addresses_equal ("192.168.1.1", NULL);
  ASSERT_EQ (0, result);
}

/* Test 13: Both NULL */
TEST (ip_equality_both_null)
{
  int result = ip_addresses_equal (NULL, NULL);
  ASSERT_EQ (0, result);
}

/* Test 14: Invalid IP format (ip1) */
TEST (ip_equality_invalid_ip1)
{
  int result = ip_addresses_equal ("not.an.ip.address", "192.168.1.1");
  ASSERT_EQ (0, result);
}

/* Test 15: Invalid IP format (ip2) */
TEST (ip_equality_invalid_ip2)
{
  int result = ip_addresses_equal ("192.168.1.1", "invalid");
  ASSERT_EQ (0, result);
}

/* Test 16: Both invalid IP formats */
TEST (ip_equality_both_invalid)
{
  int result = ip_addresses_equal ("not.valid", "also.invalid");
  ASSERT_EQ (0, result);
}

/* Test 17: Empty strings - fast path strcmp returns 1 */
TEST (ip_equality_empty_strings)
{
  int result = ip_addresses_equal ("", "");
  ASSERT_EQ (1, result);  /* strcmp("", "") == 0, so fast path returns 1 */
}

/* Test 18: IPv4 loopback addresses */
TEST (ip_equality_ipv4_loopback)
{
  int result = ip_addresses_equal ("127.0.0.1", "127.0.0.1");
  ASSERT_EQ (1, result);
}

/* Test 19: IPv6 loopback addresses */
TEST (ip_equality_ipv6_loopback)
{
  int result = ip_addresses_equal ("::1", "::1");
  ASSERT_EQ (1, result);
}

/* Test 20: IPv6 full loopback vs compressed */
TEST (ip_equality_ipv6_loopback_full_vs_compressed)
{
  int result
      = ip_addresses_equal ("::1",
                            "0000:0000:0000:0000:0000:0000:0000:0001");
  ASSERT_EQ (1, result);
}

/* Test 21: IPv4 all zeros */
TEST (ip_equality_ipv4_zeros)
{
  int result = ip_addresses_equal ("0.0.0.0", "0.0.0.0");
  ASSERT_EQ (1, result);
}

/* Test 22: IPv6 all zeros */
TEST (ip_equality_ipv6_zeros)
{
  int result = ip_addresses_equal ("::", "::");
  ASSERT_EQ (1, result);
}

/* Test 23: IPv6 all zeros full vs compressed */
TEST (ip_equality_ipv6_zeros_full_vs_compressed)
{
  int result
      = ip_addresses_equal ("::",
                            "0000:0000:0000:0000:0000:0000:0000:0000");
  ASSERT_EQ (1, result);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
