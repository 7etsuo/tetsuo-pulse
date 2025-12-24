/*
 * SPDX-LICENSE-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_synprotect_ip.c - IP Parsing and CIDR Matching Fuzzer
 *
 * Part of the Socket Library Fuzzing Suite
 *
 * Targets SocketSYNProtect-ip.c (currently 0% coverage):
 * - parse_ipv4_address() - IPv4 parsing with malformed inputs
 * - parse_ipv6_address() - IPv6 parsing with edge cases
 * - parse_ip_address() - Family detection logic
 * - ip_addresses_equal() - Canonical form comparison bypass testing
 * - cidr_full_bytes_match() - Prefix matching boundary conditions
 * - cidr_partial_byte_match() - Bit-level mask operations
 * - ip_matches_cidr_bytes() - CIDR range matching edge cases
 * - whitelist_check_bucket_bytes() - Whitelist traversal and matching
 * - blacklist_check() - Blacklist matching and expiration logic
 * - remove_ip_entry_from_hash() - Hash table removal edge cases
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_synprotect_ip
 * Run:   ./fuzz_synprotect_ip corpus/synprotect_ip/ -fork=16 -max_len=1024
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Except.h"
#include "core/SocketSYNProtect.h"

/* Fuzzer operation codes */
enum IPOperations
{
  OP_WHITELIST_ADD_IP = 0,
  OP_WHITELIST_ADD_CIDR,
  OP_WHITELIST_REMOVE,
  OP_WHITELIST_CONTAINS,
  OP_BLACKLIST_ADD,
  OP_BLACKLIST_ADD_PERMANENT,
  OP_BLACKLIST_REMOVE,
  OP_BLACKLIST_CONTAINS,
  OP_CHECK_IP,
  OP_IP_EQUALITY_TEST,
  OP_CIDR_BOUNDARY_TEST,
  OP_MALFORMED_IP_TEST,
  OP_HASH_COLLISION_TEST,
  OP_CLEANUP,
  OP_COUNT
};

/**
 * read_byte - Read single byte from fuzzer data
 */
static uint8_t
read_byte (const uint8_t **data, size_t *remaining)
{
  if (*remaining == 0)
    return 0;
  uint8_t val = **data;
  (*data)++;
  (*remaining)--;
  return val;
}

/**
 * read_uint16 - Read 16-bit value from fuzzer data
 */
static uint16_t
read_uint16 (const uint8_t **data, size_t *remaining)
{
  uint16_t val = 0;
  for (int i = 0; i < 2 && *remaining > 0; i++)
    {
      val = (val << 8) | read_byte (data, remaining);
    }
  return val;
}

/**
 * read_int - Read 32-bit integer from fuzzer data
 */
static int
read_int (const uint8_t **data, size_t *remaining)
{
  int val = 0;
  for (int i = 0; i < 4 && *remaining > 0; i++)
    {
      val = (val << 8) | read_byte (data, remaining);
    }
  return val;
}

/**
 * read_string - Read null-terminated string from fuzzer data
 */
static size_t
read_string (char *buf, size_t bufsize, const uint8_t **data,
             size_t *remaining)
{
  size_t len = 0;

  while (len < bufsize - 1 && *remaining > 0)
    {
      uint8_t c = read_byte (data, remaining);
      if (c == 0)
        break;
      buf[len++] = (char)c;
    }

  buf[len] = '\0';
  return len;
}

/**
 * generate_ipv4 - Generate IPv4 address with various edge cases
 */
static void
generate_ipv4 (char *buf, size_t bufsize, const uint8_t **data,
               size_t *remaining)
{
  uint8_t variant = read_byte (data, remaining) % 10;

  switch (variant)
    {
    case 0: /* Standard valid */
      snprintf (buf, bufsize, "%u.%u.%u.%u", read_byte (data, remaining),
                read_byte (data, remaining), read_byte (data, remaining),
                read_byte (data, remaining));
      break;

    case 1: /* Boundary values (0/255) */
      snprintf (buf, bufsize, "%u.%u.%u.%u",
                read_byte (data, remaining) % 2 ? 0 : 255,
                read_byte (data, remaining) % 2 ? 0 : 255,
                read_byte (data, remaining) % 2 ? 0 : 255,
                read_byte (data, remaining) % 2 ? 0 : 255);
      break;

    case 2: /* Missing octets */
      snprintf (buf, bufsize, "%u.%u", read_byte (data, remaining),
                read_byte (data, remaining));
      break;

    case 3: /* Extra octets */
      snprintf (buf, bufsize, "%u.%u.%u.%u.%u", read_byte (data, remaining),
                read_byte (data, remaining), read_byte (data, remaining),
                read_byte (data, remaining), read_byte (data, remaining));
      break;

    case 4: /* Octet overflow (>255) */
      snprintf (buf, bufsize, "%u.%u.%u.%u", 256 + read_byte (data, remaining),
                read_byte (data, remaining), read_byte (data, remaining),
                read_byte (data, remaining));
      break;

    case 5: /* Leading zeros (canonical form bypass attempt) */
      snprintf (buf, bufsize, "0%u.0%u.0%u.0%u", read_byte (data, remaining),
                read_byte (data, remaining), read_byte (data, remaining),
                read_byte (data, remaining));
      break;

    case 6: /* Hexadecimal format */
      snprintf (buf, bufsize, "0x%x.0x%x.0x%x.0x%x",
                read_byte (data, remaining), read_byte (data, remaining),
                read_byte (data, remaining), read_byte (data, remaining));
      break;

    case 7: /* Negative values */
      snprintf (buf, bufsize, "-%u.%u.%u.%u", read_byte (data, remaining),
                read_byte (data, remaining), read_byte (data, remaining),
                read_byte (data, remaining));
      break;

    case 8: /* Special addresses */
      {
        const char *special[]
            = { "0.0.0.0", "127.0.0.1", "255.255.255.255", "192.168.1.1",
                "10.0.0.1",  "172.16.0.1" };
        snprintf (buf, bufsize, "%s",
                  special[read_byte (data, remaining) % 6]);
      }
      break;

    case 9: /* Random malformed */
      read_string (buf, bufsize, data, remaining);
      break;
    }
}

/**
 * generate_ipv6 - Generate IPv6 address with various edge cases
 */
static void
generate_ipv6 (char *buf, size_t bufsize, const uint8_t **data,
               size_t *remaining)
{
  uint8_t variant = read_byte (data, remaining) % 10;

  switch (variant)
    {
    case 0: /* Full form */
      snprintf (buf, bufsize, "%x:%x:%x:%x:%x:%x:%x:%x",
                read_uint16 (data, remaining), read_uint16 (data, remaining),
                read_uint16 (data, remaining), read_uint16 (data, remaining),
                read_uint16 (data, remaining), read_uint16 (data, remaining),
                read_uint16 (data, remaining), read_uint16 (data, remaining));
      break;

    case 1: /* Compressed form (::) */
      snprintf (buf, bufsize, "%x::%x", read_uint16 (data, remaining),
                read_uint16 (data, remaining));
      break;

    case 2: /* Multiple compressions (invalid) */
      snprintf (buf, bufsize, "%x::%x::%x", read_uint16 (data, remaining),
                read_uint16 (data, remaining), read_uint16 (data, remaining));
      break;

    case 3: /* Trailing compression */
      snprintf (buf, bufsize, "%x:%x:%x::", read_uint16 (data, remaining),
                read_uint16 (data, remaining), read_uint16 (data, remaining));
      break;

    case 4: /* IPv4-mapped IPv6 */
      snprintf (buf, bufsize, "::ffff:%u.%u.%u.%u",
                read_byte (data, remaining), read_byte (data, remaining),
                read_byte (data, remaining), read_byte (data, remaining));
      break;

    case 5: /* Too many groups */
      snprintf (buf, bufsize, "%x:%x:%x:%x:%x:%x:%x:%x:%x",
                read_uint16 (data, remaining), read_uint16 (data, remaining),
                read_uint16 (data, remaining), read_uint16 (data, remaining),
                read_uint16 (data, remaining), read_uint16 (data, remaining),
                read_uint16 (data, remaining), read_uint16 (data, remaining),
                read_uint16 (data, remaining));
      break;

    case 6: /* Too few groups */
      snprintf (buf, bufsize, "%x:%x", read_uint16 (data, remaining),
                read_uint16 (data, remaining));
      break;

    case 7: /* Invalid characters */
      snprintf (buf, bufsize, "%x:%x:GGGG:%x", read_uint16 (data, remaining),
                read_uint16 (data, remaining), read_uint16 (data, remaining));
      break;

    case 8: /* Special addresses */
      {
        const char *special[]
            = { "::", "::1", "fe80::1", "ff02::1", "2001:db8::1" };
        snprintf (buf, bufsize, "%s",
                  special[read_byte (data, remaining) % 5]);
      }
      break;

    case 9: /* Random malformed */
      read_string (buf, bufsize, data, remaining);
      break;
    }
}

/**
 * generate_cidr - Generate CIDR notation with edge cases
 */
static void
generate_cidr (char *buf, size_t bufsize, const uint8_t **data,
               size_t *remaining)
{
  uint8_t variant = read_byte (data, remaining) % 8;
  char ip_buf[128];

  switch (variant)
    {
    case 0: /* Valid IPv4 CIDR */
      generate_ipv4 (ip_buf, sizeof (ip_buf), data, remaining);
      snprintf (buf, bufsize, "%s/%u", ip_buf,
                read_byte (data, remaining) % 33);
      break;

    case 1: /* Valid IPv6 CIDR */
      generate_ipv6 (ip_buf, sizeof (ip_buf), data, remaining);
      snprintf (buf, bufsize, "%s/%u", ip_buf,
                read_byte (data, remaining) % 129);
      break;

    case 2: /* Boundary prefix lengths */
      {
        uint8_t is_ipv6 = read_byte (data, remaining) % 2;
        if (is_ipv6)
          {
            generate_ipv6 (ip_buf, sizeof (ip_buf), data, remaining);
            uint8_t prefix_choice = read_byte (data, remaining) % 4;
            int prefix = (prefix_choice == 0)   ? 0
                         : (prefix_choice == 1) ? 1
                         : (prefix_choice == 2) ? 127
                                                : 128;
            snprintf (buf, bufsize, "%s/%d", ip_buf, prefix);
          }
        else
          {
            generate_ipv4 (ip_buf, sizeof (ip_buf), data, remaining);
            uint8_t prefix_choice = read_byte (data, remaining) % 4;
            int prefix = (prefix_choice == 0)   ? 0
                         : (prefix_choice == 1) ? 1
                         : (prefix_choice == 2) ? 31
                                                : 32;
            snprintf (buf, bufsize, "%s/%d", ip_buf, prefix);
          }
      }
      break;

    case 3: /* Invalid prefix (out of range) */
      generate_ipv4 (ip_buf, sizeof (ip_buf), data, remaining);
      snprintf (buf, bufsize, "%s/%u", ip_buf,
                33 + read_byte (data, remaining));
      break;

    case 4: /* Missing prefix */
      generate_ipv4 (ip_buf, sizeof (ip_buf), data, remaining);
      snprintf (buf, bufsize, "%s/", ip_buf);
      break;

    case 5: /* Negative prefix */
      generate_ipv4 (ip_buf, sizeof (ip_buf), data, remaining);
      snprintf (buf, bufsize, "%s/-%u", ip_buf, read_byte (data, remaining));
      break;

    case 6: /* Multiple slashes */
      generate_ipv4 (ip_buf, sizeof (ip_buf), data, remaining);
      snprintf (buf, bufsize, "%s/%u/%u", ip_buf,
                read_byte (data, remaining) % 33,
                read_byte (data, remaining) % 33);
      break;

    case 7: /* Random malformed */
      read_string (buf, bufsize, data, remaining);
      break;
    }
}

/**
 * generate_ip - Generate IP address (IPv4, IPv6, or malformed)
 */
static void
generate_ip (char *buf, size_t bufsize, const uint8_t **data,
             size_t *remaining)
{
  uint8_t type = read_byte (data, remaining) % 4;

  switch (type)
    {
    case 0:
      generate_ipv4 (buf, bufsize, data, remaining);
      break;
    case 1:
      generate_ipv6 (buf, bufsize, data, remaining);
      break;
    case 2:
      buf[0] = '\0'; /* Empty string */
      break;
    case 3:
      read_string (buf, bufsize, data, remaining);
      break;
    }
}

/**
 * test_ip_equality - Test IP address equality edge cases
 */
static void
test_ip_equality (SocketSYNProtect_T protect, const uint8_t **data,
                  size_t *remaining)
{
  char ip1[128], ip2[128];

  generate_ip (ip1, sizeof (ip1), data, remaining);
  generate_ip (ip2, sizeof (ip2), data, remaining);

  /* Add both to whitelist and check if treated as equal */
  SocketSYNProtect_whitelist_add (protect, ip1);
  SocketSYNProtect_whitelist_add (protect, ip2);

  /* Check if they're both contained */
  SocketSYNProtect_whitelist_contains (protect, ip1);
  SocketSYNProtect_whitelist_contains (protect, ip2);

  /* Remove and verify */
  SocketSYNProtect_whitelist_remove (protect, ip1);
  SocketSYNProtect_whitelist_contains (protect, ip2);
}

/**
 * test_cidr_boundaries - Test CIDR matching at bit boundaries
 */
static void
test_cidr_boundaries (SocketSYNProtect_T protect, const uint8_t **data,
                      size_t *remaining)
{
  char cidr[128];
  char test_ip[128];

  generate_cidr (cidr, sizeof (cidr), data, remaining);
  SocketSYNProtect_whitelist_add_cidr (protect, cidr);

  /* Generate IPs that should/shouldn't match */
  for (int i = 0; i < 3; i++)
    {
      generate_ip (test_ip, sizeof (test_ip), data, remaining);
      SocketSYNProtect_whitelist_contains (protect, test_ip);
    }
}

/**
 * test_hash_collisions - Test hash table collision handling
 */
static void
test_hash_collisions (SocketSYNProtect_T protect, const uint8_t **data,
                      size_t *remaining)
{
  /* Add many IPs to force collisions */
  char ip_buf[128];
  int count = read_byte (data, remaining) % 20 + 5;

  for (int i = 0; i < count; i++)
    {
      generate_ip (ip_buf, sizeof (ip_buf), data, remaining);
      SocketSYNProtect_whitelist_add (protect, ip_buf);
    }

  /* Test lookups */
  for (int i = 0; i < count; i++)
    {
      generate_ip (ip_buf, sizeof (ip_buf), data, remaining);
      SocketSYNProtect_whitelist_contains (protect, ip_buf);
    }

  /* Remove some */
  for (int i = 0; i < count / 2; i++)
    {
      generate_ip (ip_buf, sizeof (ip_buf), data, remaining);
      SocketSYNProtect_whitelist_remove (protect, ip_buf);
    }
}

/**
 * test_blacklist_expiration - Test blacklist expiration logic
 */
static void
test_blacklist_expiration (SocketSYNProtect_T protect, const uint8_t **data,
                            size_t *remaining)
{
  char ip_buf[128];

  generate_ip (ip_buf, sizeof (ip_buf), data, remaining);

  /* Add with various expiration times */
  int duration_ms = read_int (data, remaining);
  SocketSYNProtect_blacklist_add (protect, ip_buf, duration_ms);

  /* Check immediately */
  SocketSYNProtect_blacklist_contains (protect, ip_buf);

  /* Run cleanup */
  SocketSYNProtect_cleanup (protect);

  /* Check again */
  SocketSYNProtect_blacklist_contains (protect, ip_buf);
}

/**
 * LLVMFuzzerTestOneInput - libFuzzer entry point
 */
int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  const uint8_t *ptr = data;
  size_t remaining = size;

  if (size < 4)
    return 0;

  /* Create protection instance */
  TRY
  {
    SocketSYNProtect_config_defaults (&config);

    /* Use small limits for fuzzing efficiency */
    config.max_whitelist = 100;
    config.max_blacklist = 100;
    config.max_tracked_ips = 100;

    protect = SocketSYNProtect_new (NULL, &config);
    if (protect == NULL)
      return 0;
  }
  ELSE { return 0; }
  END_TRY;

  /* Execute random operations */
  while (remaining > 8)
    {
      uint8_t op = read_byte (&ptr, &remaining) % OP_COUNT;
      char ip_buf[128];
      char cidr_buf[128];

      TRY
      {
        switch (op)
          {
          case OP_WHITELIST_ADD_IP:
            generate_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_whitelist_add (protect, ip_buf);
            break;

          case OP_WHITELIST_ADD_CIDR:
            generate_cidr (cidr_buf, sizeof (cidr_buf), &ptr, &remaining);
            SocketSYNProtect_whitelist_add_cidr (protect, cidr_buf);
            break;

          case OP_WHITELIST_REMOVE:
            generate_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_whitelist_remove (protect, ip_buf);
            break;

          case OP_WHITELIST_CONTAINS:
            generate_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_whitelist_contains (protect, ip_buf);
            break;

          case OP_BLACKLIST_ADD:
            generate_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_blacklist_add (protect, ip_buf,
                                            read_int (&ptr, &remaining));
            break;

          case OP_BLACKLIST_ADD_PERMANENT:
            generate_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_blacklist_add (protect, ip_buf, 0);
            break;

          case OP_BLACKLIST_REMOVE:
            generate_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_blacklist_remove (protect, ip_buf);
            break;

          case OP_BLACKLIST_CONTAINS:
            generate_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_blacklist_contains (protect, ip_buf);
            break;

          case OP_CHECK_IP:
            generate_ip (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_check (protect, ip_buf, NULL);
            break;

          case OP_IP_EQUALITY_TEST:
            test_ip_equality (protect, &ptr, &remaining);
            break;

          case OP_CIDR_BOUNDARY_TEST:
            test_cidr_boundaries (protect, &ptr, &remaining);
            break;

          case OP_MALFORMED_IP_TEST:
            /* Feed completely random data as IP */
            read_string (ip_buf, sizeof (ip_buf), &ptr, &remaining);
            SocketSYNProtect_whitelist_add (protect, ip_buf);
            SocketSYNProtect_blacklist_add (protect, ip_buf, 1000);
            SocketSYNProtect_check (protect, ip_buf, NULL);
            break;

          case OP_HASH_COLLISION_TEST:
            test_hash_collisions (protect, &ptr, &remaining);
            break;

          case OP_CLEANUP:
            SocketSYNProtect_cleanup (protect);
            break;
          }
      }
      ELSE { /* Ignore exceptions during fuzzing */ }
      END_TRY;

      /* Early exit if running low on data */
      if (remaining < 16)
        break;
    }

  /* Cleanup */
  TRY { SocketSYNProtect_free (&protect); }
  ELSE { /* Ignore cleanup exceptions */ }
  END_TRY;

  return 0;
}
