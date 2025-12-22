/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/* IP parsing, CIDR matching, whitelist/blacklist lookups */

#include "core/SocketSYNProtect-private.h"
#include "core/SocketSYNProtect.h"

#include "core/SocketUtil.h"
#include <arpa/inet.h>
#include <string.h>

static int
parse_ipv4_address (const char *ip, uint8_t *addr_bytes)
{
  struct in_addr addr4;

  if (inet_pton (AF_INET, ip, &addr4) == 1)
    {
      memset (addr_bytes, 0, SOCKET_IPV6_ADDR_BYTES);
      memcpy (addr_bytes, &addr4.s_addr, SOCKET_IPV4_ADDR_BYTES);
      return 1;
    }
  return 0;
}

static int
parse_ipv6_address (const char *ip, uint8_t *addr_bytes)
{
  struct in6_addr addr6;

  if (inet_pton (AF_INET6, ip, &addr6) == 1)
    {
      memcpy (addr_bytes, addr6.s6_addr, SOCKET_IPV6_ADDR_BYTES);
      return 1;
    }
  return 0;
}

/* Returns AF_INET, AF_INET6, or 0 on error */
static int
parse_ip_address (const char *ip, uint8_t *addr_bytes, size_t addr_size)
{
  if (addr_size < SOCKET_IPV6_ADDR_BYTES)
    return 0;

  if (parse_ipv4_address (ip, addr_bytes))
    return AF_INET;

  if (parse_ipv6_address (ip, addr_bytes))
    return AF_INET6;

  return 0;
}

/* Compares parsed bytes to prevent bypass via alternate IP formats */
static int
ip_addresses_equal (const char *ip1, const char *ip2)
{
  uint8_t bytes1[SOCKET_IPV6_ADDR_BYTES];
  uint8_t bytes2[SOCKET_IPV6_ADDR_BYTES];
  int family1, family2;
  size_t cmp_len;

  if (strcmp (ip1, ip2) == 0)
    return 1;

  family1 = parse_ip_address (ip1, bytes1, sizeof (bytes1));
  family2 = parse_ip_address (ip2, bytes2, sizeof (bytes2));

  if (family1 == 0 || family2 == 0)
    return 0;

  if (family1 != family2)
    return 0;

  cmp_len = (family1 == AF_INET) ? SOCKET_IPV4_ADDR_BYTES
                                 : SOCKET_IPV6_ADDR_BYTES;
  return memcmp (bytes1, bytes2, cmp_len) == 0;
}

static int
cidr_full_bytes_match (const uint8_t *ip_bytes, const uint8_t *entry_bytes,
                       int bytes)
{
  return (memcmp (ip_bytes, entry_bytes, (size_t)bytes) == 0);
}

static int
cidr_partial_byte_match (const uint8_t *ip_bytes, const uint8_t *entry_bytes,
                         int byte_index, int remaining_bits)
{
  uint8_t mask = (uint8_t)(0xFF << (8 - remaining_bits));
  return ((ip_bytes[byte_index] & mask) == (entry_bytes[byte_index] & mask));
}

static int
ip_matches_cidr_bytes (int family, const uint8_t *ip_bytes,
                       const SocketSYN_WhitelistEntry *entry)
{
  int bits, bytes_to_match, remaining_bits;

  if (family != entry->addr_family)
    return 0;

  bits = entry->prefix_len;
  bytes_to_match = bits / 8;
  remaining_bits = bits % 8;

  if (!cidr_full_bytes_match (ip_bytes, entry->addr_bytes, bytes_to_match))
    return 0;

  if (remaining_bits != 0)
    return cidr_partial_byte_match (ip_bytes, entry->addr_bytes,
                                    bytes_to_match, remaining_bits);

  return 1;
}

/* Avoid in loops; use ip_matches_cidr_bytes for efficiency */
static int
ip_matches_cidr (const char *ip, const SocketSYN_WhitelistEntry *entry)
{
  uint8_t ip_bytes[16];
  int family = parse_ip_address (ip, ip_bytes, sizeof (ip_bytes));
  if (family == 0)
    return 0;
  return ip_matches_cidr_bytes (family, ip_bytes, entry);
}

/* Compares parsed bytes to prevent bypass via alternate IP formats */
static int
whitelist_check_bucket_bytes (const SocketSYN_WhitelistEntry *entry,
                              const char *ip_str, int family,
                              const uint8_t *ip_bytes)
{
  size_t cmp_len;

  cmp_len = (family == AF_INET) ? SOCKET_IPV4_ADDR_BYTES
                                : SOCKET_IPV6_ADDR_BYTES;

  while (entry != NULL)
    {
      if (entry->is_cidr)
        {
          if (entry->addr_family == family
              && ip_matches_cidr_bytes (family, ip_bytes, entry))
            return 1;
        }
      else
        {
          if (strcmp (entry->ip, ip_str) == 0)
            return 1;

          if (entry->addr_family == family
              && memcmp (entry->addr_bytes, ip_bytes, cmp_len) == 0)
            return 1;
        }
      entry = entry->next;
    }
  return 0;
}

static int
whitelist_check_bucket (const SocketSYN_WhitelistEntry *entry, const char *ip)
{
  uint8_t ip_bytes[16];
  int family = parse_ip_address (ip, ip_bytes, sizeof (ip_bytes));
  return whitelist_check_bucket_bytes (entry, ip, family, ip_bytes);
}

static int
whitelist_check_all_cidrs_bytes (SocketSYNProtect_T protect, int family,
                                 const uint8_t *ip_bytes, unsigned skip_bucket)
{
  for (size_t i = 0; i < SOCKET_SYN_LIST_HASH_SIZE; i++)
    {
      if (i == skip_bucket)
        continue;

      const SocketSYN_WhitelistEntry *entry = protect->whitelist_table[i];
      while (entry != NULL)
        {
          if (entry->is_cidr && entry->addr_family == family
              && ip_matches_cidr_bytes (family, ip_bytes, entry))
            return 1;
          entry = entry->next;
        }
    }
  return 0;
}

static int
whitelist_check_all_cidrs (SocketSYNProtect_T protect, const char *ip, unsigned skip_bucket)
{
  uint8_t ip_bytes[16];
  int family = parse_ip_address (ip, ip_bytes, sizeof (ip_bytes));
  if (family == 0)
    return 0;
  return whitelist_check_all_cidrs_bytes (protect, family, ip_bytes,
                                          skip_bucket);
}

static int
whitelist_check (SocketSYNProtect_T protect, const char *ip)
{
  unsigned bucket;
  uint8_t ip_bytes[16];
  int family;

  if (protect->whitelist_count == 0)
    return 0;

  family = parse_ip_address (ip, ip_bytes, sizeof (ip_bytes));
  if (family == 0)
    return 0;

  bucket = synprotect_hash_ip (protect, ip, SOCKET_SYN_LIST_HASH_SIZE);

  if (whitelist_check_bucket_bytes (protect->whitelist_table[bucket], ip,
                                    family, ip_bytes))
    return 1;

  return whitelist_check_all_cidrs_bytes (protect, family, ip_bytes, bucket);
}

void
remove_ip_entry_from_hash (SocketSYNProtect_T protect, SocketSYN_IPEntry *entry)
{
  unsigned bucket
      = synprotect_hash_ip (protect, entry->state.ip, protect->ip_table_size);
  SocketSYN_IPEntry **pp = &protect->ip_table[bucket];

  while (*pp != NULL)
    {
      if (*pp == entry)
        {
          *pp = entry->hash_next;
          break;
        }
      pp = &(*pp)->hash_next;
    }
}

/* Uses binary IP comparison to prevent bypass via alternate IP formats */
static int
blacklist_check (SocketSYNProtect_T protect, const char *ip, int64_t now_ms)
{
  unsigned bucket;
  const SocketSYN_BlacklistEntry *entry;

  if (protect->blacklist_count == 0)
    return 0;

  bucket = synprotect_hash_ip (protect, ip, SOCKET_SYN_LIST_HASH_SIZE);
  entry = protect->blacklist_table[bucket];

  while (entry != NULL)
    {
      if (ip_addresses_equal (entry->ip, ip))
        {
          if (entry->expires_ms == 0 || entry->expires_ms > now_ms)
            return 1;
        }
      entry = entry->next;
    }

  return 0;
}

#undef T