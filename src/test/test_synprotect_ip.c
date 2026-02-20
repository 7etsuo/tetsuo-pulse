/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_synprotect_ip.c - Unit tests for SYN Protection IP parsing functions
 *
 * Tests IP address parsing, validation, and comparison functions in
 * SocketSYNProtect-ip.c to ensure correct IPv4/IPv6 handling and format
 * normalization that prevents bypass attacks.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <string.h>

#include "core/SocketConfig.h"
#include "core/SocketSYNProtect-private.h"
#undef T /* Undefine T from SocketSYNProtect-private.h before including Test.h \
          */
#include "test/Test.h"

TEST (parse_ipv4_valid_loopback)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv4_address ("127.0.0.1", bytes);

  ASSERT_EQ (result, 1);
  /* IPv4 stored in first 4 bytes, rest zeroed */
  ASSERT_EQ (bytes[0], 127);
  ASSERT_EQ (bytes[1], 0);
  ASSERT_EQ (bytes[2], 0);
  ASSERT_EQ (bytes[3], 1);
  /* Remaining bytes should be zero */
  for (int i = 4; i < SOCKET_IPV6_ADDR_BYTES; i++)
    {
      ASSERT_EQ (bytes[i], 0);
    }
}

TEST (parse_ipv4_valid_private_10)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv4_address ("10.0.0.0", bytes);

  ASSERT_EQ (result, 1);
  ASSERT_EQ (bytes[0], 10);
  ASSERT_EQ (bytes[1], 0);
  ASSERT_EQ (bytes[2], 0);
  ASSERT_EQ (bytes[3], 0);
}

TEST (parse_ipv4_valid_private_192)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv4_address ("192.168.1.1", bytes);

  ASSERT_EQ (result, 1);
  ASSERT_EQ (bytes[0], 192);
  ASSERT_EQ (bytes[1], 168);
  ASSERT_EQ (bytes[2], 1);
  ASSERT_EQ (bytes[3], 1);
}

TEST (parse_ipv4_valid_broadcast)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv4_address ("255.255.255.255", bytes);

  ASSERT_EQ (result, 1);
  ASSERT_EQ (bytes[0], 255);
  ASSERT_EQ (bytes[1], 255);
  ASSERT_EQ (bytes[2], 255);
  ASSERT_EQ (bytes[3], 255);
}

TEST (parse_ipv4_valid_zero)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv4_address ("0.0.0.0", bytes);

  ASSERT_EQ (result, 1);
  ASSERT_EQ (bytes[0], 0);
  ASSERT_EQ (bytes[1], 0);
  ASSERT_EQ (bytes[2], 0);
  ASSERT_EQ (bytes[3], 0);
}

TEST (parse_ipv4_invalid_out_of_range)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv4_address ("999.999.999.999", bytes);

  ASSERT_EQ (result, 0);
}

TEST (parse_ipv4_invalid_empty_string)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv4_address ("", bytes);

  ASSERT_EQ (result, 0);
}

TEST (parse_ipv4_invalid_null_ip)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv4_address (NULL, bytes);

  ASSERT_EQ (result, 0);
}

TEST (parse_ipv4_invalid_null_buffer)
{
  int result = parse_ipv4_address ("127.0.0.1", NULL);

  ASSERT_EQ (result, 0);
}

TEST (parse_ipv4_invalid_malformed)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv4_address ("192.168.1", bytes);

  ASSERT_EQ (result, 0);
}

TEST (parse_ipv4_invalid_extra_octets)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv4_address ("192.168.1.1.1", bytes);

  ASSERT_EQ (result, 0);
}

TEST (parse_ipv4_invalid_non_numeric)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv4_address ("abc.def.ghi.jkl", bytes);

  ASSERT_EQ (result, 0);
}

TEST (parse_ipv6_valid_loopback)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv6_address ("::1", bytes);

  ASSERT_EQ (result, 1);
  /* First 15 bytes should be zero */
  for (int i = 0; i < 15; i++)
    {
      ASSERT_EQ (bytes[i], 0);
    }
  /* Last byte should be 1 */
  ASSERT_EQ (bytes[15], 1);
}

TEST (parse_ipv6_valid_all_zeros)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv6_address ("::", bytes);

  ASSERT_EQ (result, 1);
  /* All bytes should be zero */
  for (int i = 0; i < SOCKET_IPV6_ADDR_BYTES; i++)
    {
      ASSERT_EQ (bytes[i], 0);
    }
}

TEST (parse_ipv6_valid_full_address)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result
      = parse_ipv6_address ("2001:0db8:0000:0000:0000:0000:0000:0001", bytes);

  ASSERT_EQ (result, 1);
  ASSERT_EQ (bytes[0], 0x20);
  ASSERT_EQ (bytes[1], 0x01);
  ASSERT_EQ (bytes[2], 0x0d);
  ASSERT_EQ (bytes[3], 0xb8);
  /* Middle bytes are zero */
  for (int i = 4; i < 14; i++)
    {
      ASSERT_EQ (bytes[i], 0);
    }
  ASSERT_EQ (bytes[14], 0);
  ASSERT_EQ (bytes[15], 1);
}

TEST (parse_ipv6_valid_compressed)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv6_address ("2001:db8::1", bytes);

  ASSERT_EQ (result, 1);
  ASSERT_EQ (bytes[0], 0x20);
  ASSERT_EQ (bytes[1], 0x01);
  ASSERT_EQ (bytes[2], 0x0d);
  ASSERT_EQ (bytes[3], 0xb8);
  /* Middle bytes are zero */
  for (int i = 4; i < 14; i++)
    {
      ASSERT_EQ (bytes[i], 0);
    }
  ASSERT_EQ (bytes[14], 0);
  ASSERT_EQ (bytes[15], 1);
}

TEST (parse_ipv6_valid_link_local)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv6_address ("fe80::1", bytes);

  ASSERT_EQ (result, 1);
  ASSERT_EQ (bytes[0], 0xfe);
  ASSERT_EQ (bytes[1], 0x80);
  for (int i = 2; i < 14; i++)
    {
      ASSERT_EQ (bytes[i], 0);
    }
  ASSERT_EQ (bytes[14], 0);
  ASSERT_EQ (bytes[15], 1);
}

TEST (parse_ipv6_invalid_malformed)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv6_address ("gggg::1", bytes);

  ASSERT_EQ (result, 0);
}

TEST (parse_ipv6_invalid_empty_string)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv6_address ("", bytes);

  ASSERT_EQ (result, 0);
}

TEST (parse_ipv6_invalid_null_ip)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv6_address (NULL, bytes);

  ASSERT_EQ (result, 0);
}

TEST (parse_ipv6_invalid_null_buffer)
{
  int result = parse_ipv6_address ("::1", NULL);

  ASSERT_EQ (result, 0);
}

TEST (parse_ipv6_invalid_too_many_groups)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv6_address (
      "2001:0db8:0000:0000:0000:0000:0000:0000:0001", bytes);

  ASSERT_EQ (result, 0);
}

TEST (parse_ip_address_ipv4_returns_AF_INET)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int family = parse_ip_address ("192.168.1.1", bytes, SOCKET_IPV6_ADDR_BYTES);

  ASSERT_EQ (family, AF_INET);
  ASSERT_EQ (bytes[0], 192);
  ASSERT_EQ (bytes[1], 168);
  ASSERT_EQ (bytes[2], 1);
  ASSERT_EQ (bytes[3], 1);
}

TEST (parse_ip_address_ipv6_returns_AF_INET6)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int family = parse_ip_address ("2001:db8::1", bytes, SOCKET_IPV6_ADDR_BYTES);

  ASSERT_EQ (family, AF_INET6);
  ASSERT_EQ (bytes[0], 0x20);
  ASSERT_EQ (bytes[1], 0x01);
  ASSERT_EQ (bytes[2], 0x0d);
  ASSERT_EQ (bytes[3], 0xb8);
}

TEST (parse_ip_address_invalid_returns_zero)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int family = parse_ip_address ("invalid", bytes, SOCKET_IPV6_ADDR_BYTES);

  ASSERT_EQ (family, 0);
}

TEST (parse_ip_address_null_ip_returns_zero)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int family = parse_ip_address (NULL, bytes, SOCKET_IPV6_ADDR_BYTES);

  ASSERT_EQ (family, 0);
}

TEST (parse_ip_address_null_buffer_returns_zero)
{
  int family = parse_ip_address ("192.168.1.1", NULL, SOCKET_IPV6_ADDR_BYTES);

  ASSERT_EQ (family, 0);
}

TEST (parse_ip_address_insufficient_buffer_returns_zero)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  /* Buffer size less than SOCKET_IPV6_ADDR_BYTES */
  int family = parse_ip_address ("192.168.1.1", bytes, 10);

  ASSERT_EQ (family, 0);
}

TEST (ip_addresses_equal_same_ipv4_literal)
{
  int result = ip_addresses_equal ("192.168.1.1", "192.168.1.1");

  ASSERT_EQ (result, 1);
}

TEST (ip_addresses_equal_ipv4_leading_zeros_rejected)
{
  /* "192.168.001.001" should NOT parse (inet_pton rejects leading zeros) */
  int result = ip_addresses_equal ("192.168.1.1", "192.168.001.001");

  /* Leading zeros are rejected by inet_pton for security, so this should fail
   */
  ASSERT_EQ (result, 0);
}

TEST (ip_addresses_equal_different_ipv4)
{
  int result = ip_addresses_equal ("192.168.1.1", "192.168.1.2");

  ASSERT_EQ (result, 0);
}

TEST (ip_addresses_equal_same_ipv6_compressed)
{
  int result = ip_addresses_equal ("2001:db8::1", "2001:db8::1");

  ASSERT_EQ (result, 1);
}

TEST (ip_addresses_equal_ipv6_different_representations)
{
  /* Full vs compressed representation of same address */
  int result = ip_addresses_equal ("2001:db8::1",
                                   "2001:0db8:0000:0000:0000:0000:0000:0001");

  ASSERT_EQ (result, 1);
}

TEST (ip_addresses_equal_ipv6_loopback_representations)
{
  /* Different representations of IPv6 loopback */
  int result
      = ip_addresses_equal ("::1", "0000:0000:0000:0000:0000:0000:0000:0001");

  ASSERT_EQ (result, 1);
}

TEST (ip_addresses_equal_different_ipv6)
{
  int result = ip_addresses_equal ("2001:db8::1", "2001:db8::2");

  ASSERT_EQ (result, 0);
}

TEST (ip_addresses_equal_different_families)
{
  /* IPv4 vs IPv6 should never be equal */
  int result = ip_addresses_equal ("127.0.0.1", "::1");

  ASSERT_EQ (result, 0);
}

TEST (ip_addresses_equal_null_ip1)
{
  int result = ip_addresses_equal (NULL, "192.168.1.1");

  ASSERT_EQ (result, 0);
}

TEST (ip_addresses_equal_null_ip2)
{
  int result = ip_addresses_equal ("192.168.1.1", NULL);

  ASSERT_EQ (result, 0);
}

TEST (ip_addresses_equal_both_null)
{
  int result = ip_addresses_equal (NULL, NULL);

  ASSERT_EQ (result, 0);
}

TEST (ip_addresses_equal_invalid_ip1)
{
  int result = ip_addresses_equal ("invalid", "192.168.1.1");

  ASSERT_EQ (result, 0);
}

TEST (ip_addresses_equal_invalid_ip2)
{
  int result = ip_addresses_equal ("192.168.1.1", "invalid");

  ASSERT_EQ (result, 0);
}

TEST (ip_addresses_equal_both_invalid)
{
  int result = ip_addresses_equal ("invalid1", "invalid2");

  ASSERT_EQ (result, 0);
}

TEST (parse_ipv4_edge_case_octet_255)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv4_address ("255.0.0.0", bytes);

  ASSERT_EQ (result, 1);
  ASSERT_EQ (bytes[0], 255);
}

TEST (parse_ipv4_edge_case_public_dns)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv4_address ("8.8.8.8", bytes);

  ASSERT_EQ (result, 1);
  ASSERT_EQ (bytes[0], 8);
  ASSERT_EQ (bytes[1], 8);
  ASSERT_EQ (bytes[2], 8);
  ASSERT_EQ (bytes[3], 8);
}

TEST (parse_ipv6_edge_case_multicast)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv6_address ("ff02::1", bytes);

  ASSERT_EQ (result, 1);
  ASSERT_EQ (bytes[0], 0xff);
  ASSERT_EQ (bytes[1], 0x02);
}

TEST (parse_ipv6_edge_case_documentation)
{
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv6_address ("2001:db8::", bytes);

  ASSERT_EQ (result, 1);
  ASSERT_EQ (bytes[0], 0x20);
  ASSERT_EQ (bytes[1], 0x01);
  ASSERT_EQ (bytes[2], 0x0d);
  ASSERT_EQ (bytes[3], 0xb8);
  /* Rest should be zero */
  for (int i = 4; i < SOCKET_IPV6_ADDR_BYTES; i++)
    {
      ASSERT_EQ (bytes[i], 0);
    }
}

TEST (format_bypass_ipv4_octal_notation_rejected)
{
  /* Octal notation like "0177.0.0.1" (127.0.0.1 in octal) should not parse */
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  /* inet_pton rejects octal/hex, but test anyway */
  int result = parse_ipv4_address ("0177.0.0.1", bytes);

  /* inet_pton rejects leading zeros in non-zero octets, so this should fail
   */
  ASSERT_EQ (result, 0);
}

TEST (format_bypass_ipv4_hex_notation_rejected)
{
  /* Hex notation should be rejected */
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv4_address ("0x7f.0x00.0x00.0x01", bytes);

  ASSERT_EQ (result, 0);
}

TEST (format_bypass_ipv4_single_number_rejected)
{
  /* Single 32-bit number format should be rejected */
  uint8_t bytes[SOCKET_IPV6_ADDR_BYTES];
  int result = parse_ipv4_address ("2130706433", bytes); /* 127.0.0.1 as int */

  ASSERT_EQ (result, 0);
}

TEST (format_bypass_ipv6_mixed_case_normalized)
{
  /* Mixed case hex should be normalized by inet_pton */
  int result = ip_addresses_equal ("2001:DB8::1", "2001:db8::1");

  ASSERT_EQ (result, 1);
}

TEST (format_bypass_ipv6_leading_zeros_normalized)
{
  /* Leading zeros in groups should be normalized */
  int result = ip_addresses_equal ("2001:0db8::0001", "2001:db8::1");

  ASSERT_EQ (result, 1);
}

TEST (integration_parse_and_compare_ipv4)
{
  uint8_t bytes1[SOCKET_IPV6_ADDR_BYTES];
  uint8_t bytes2[SOCKET_IPV6_ADDR_BYTES];

  int family1
      = parse_ip_address ("192.168.1.1", bytes1, SOCKET_IPV6_ADDR_BYTES);
  int family2
      = parse_ip_address ("192.168.1.1", bytes2, SOCKET_IPV6_ADDR_BYTES);

  ASSERT_EQ (family1, AF_INET);
  ASSERT_EQ (family2, AF_INET);

  /* Verify bytes match */
  int match = memcmp (bytes1, bytes2, SOCKET_IPV4_ADDR_BYTES);
  ASSERT_EQ (match, 0);
}

TEST (integration_parse_and_compare_ipv6)
{
  uint8_t bytes1[SOCKET_IPV6_ADDR_BYTES];
  uint8_t bytes2[SOCKET_IPV6_ADDR_BYTES];

  int family1
      = parse_ip_address ("2001:db8::1", bytes1, SOCKET_IPV6_ADDR_BYTES);
  int family2
      = parse_ip_address ("2001:db8::1", bytes2, SOCKET_IPV6_ADDR_BYTES);

  ASSERT_EQ (family1, AF_INET6);
  ASSERT_EQ (family2, AF_INET6);

  /* Verify bytes match */
  int match = memcmp (bytes1, bytes2, SOCKET_IPV6_ADDR_BYTES);
  ASSERT_EQ (match, 0);
}

TEST (integration_parse_different_addresses)
{
  uint8_t bytes1[SOCKET_IPV6_ADDR_BYTES];
  uint8_t bytes2[SOCKET_IPV6_ADDR_BYTES];

  int family1
      = parse_ip_address ("192.168.1.1", bytes1, SOCKET_IPV6_ADDR_BYTES);
  int family2
      = parse_ip_address ("192.168.1.2", bytes2, SOCKET_IPV6_ADDR_BYTES);

  ASSERT_EQ (family1, AF_INET);
  ASSERT_EQ (family2, AF_INET);

  /* Verify bytes differ */
  int match = memcmp (bytes1, bytes2, SOCKET_IPV4_ADDR_BYTES);
  ASSERT_NE (match, 0);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
