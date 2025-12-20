/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * SocketSYNProtect-ip.c - IP Address and CIDR Management for SYN Protection
 *
 * Implements IP parsing, CIDR matching, whitelist/blacklist lookups.
 */

#include "core/SocketSYNProtect-private.h"
#include "core/SocketSYNProtect.h"

#include "core/SocketUtil.h"
#include <arpa/inet.h>
#include <string.h>

/* ============================================================================
 * Internal Helper Functions - IP Address Parsing
 * ============================================================================
 */

/**
 * parse_ipv4_address - Parse IPv4 address to bytes
 * @ip: IP address string
 * @addr_bytes: Output buffer (at least SOCKET_IPV4_ADDR_BYTES)
 *
 * Returns: 1 on success, 0 on failure
 */
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

/**
 * parse_ipv6_address - Parse IPv6 address to bytes
 * @ip: IP address string
 * @addr_bytes: Output buffer (at least SOCKET_IPV6_ADDR_BYTES)
 *
 * Returns: 1 on success, 0 on failure
 */
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

/**
 * parse_ip_address - Parse IP address string to bytes
 * @ip: IP address string
 * @addr_bytes: Output buffer (at least SOCKET_IPV6_ADDR_BYTES)
 * @addr_size: Size of output buffer
 *
 * Returns: AF_INET, AF_INET6, or 0 on error
 */
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

/* ============================================================================
 * Internal Helper Functions - CIDR Matching
 * ============================================================================
 */

/**
 * cidr_full_bytes_match - Compare full bytes of addresses
 * @ip_bytes: IP address bytes
 * @entry_bytes: CIDR entry bytes
 * @bytes: Number of bytes to compare
 *
 * Returns: 1 if match, 0 otherwise
 */
static int
cidr_full_bytes_match (const uint8_t *ip_bytes, const uint8_t *entry_bytes,
                       int bytes)
{
  return (memcmp (ip_bytes, entry_bytes, (size_t)bytes) == 0);
}

/**
 * cidr_partial_byte_match - Compare partial byte with mask
 * @ip_bytes: IP address bytes
 * @entry_bytes: CIDR entry bytes
 * @byte_index: Index of byte to compare
 * @remaining_bits: Number of bits to compare
 *
 * Returns: 1 if match, 0 otherwise
 */
static int
cidr_partial_byte_match (const uint8_t *ip_bytes, const uint8_t *entry_bytes,
                         int byte_index, int remaining_bits)
{
  uint8_t mask = (uint8_t)(0xFF << (8 - remaining_bits));
  return ((ip_bytes[byte_index] & mask) == (entry_bytes[byte_index] & mask));
}

/**
 * ip_matches_cidr_bytes - Check if IP matches CIDR entry
 * @family: Address family (AF_INET/AF_INET6)
 * @ip_bytes: Parsed IP bytes
 * @entry: Whitelist entry with CIDR
 *
 * Returns: 1 if match, 0 otherwise
 */
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

/**
 * ip_matches_cidr - Check if IP matches CIDR entry
 * @ip: IP address string
 * @entry: Whitelist entry with CIDR
 *
 * Returns: 1 if match, 0 otherwise
 * Note: Avoid in loops; use ip_matches_cidr_bytes for efficiency
 */
static int
ip_matches_cidr (const char *ip, const SocketSYN_WhitelistEntry *entry)
{
  uint8_t ip_bytes[16];
  int family = parse_ip_address (ip, ip_bytes, sizeof (ip_bytes));
  if (family == 0)
    return 0;
  return ip_matches_cidr_bytes (family, ip_bytes, entry);
}

/* ============================================================================
 * Internal Helper Functions - Whitelist
 * ============================================================================
 */

/**
 * whitelist_check_bucket_bytes - Check single bucket for IP match
 * @entry: First entry in bucket chain
 * @ip_str: IP address string (for exact matches)
 * @family: Parsed family
 * @ip_bytes: Parsed IP bytes
 *
 * Returns: 1 if found, 0 otherwise
 */
static int
whitelist_check_bucket_bytes (const SocketSYN_WhitelistEntry *entry,
                              const char *ip_str, int family,
                              const uint8_t *ip_bytes)
{
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

/**
 * whitelist_check_all_cidrs_bytes - Check all buckets for CIDR match
 * @protect: Protection instance (must hold mutex)
 * @family: Address family
 * @ip_bytes: Parsed IP bytes
 * @skip_bucket: Bucket to skip (already checked)
 *
 * Returns: 1 if found, 0 otherwise
 */
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

/**
 * whitelist_check - Check if IP is whitelisted
 * @protect: Protection instance (must hold mutex)
 * @ip: IP address to check
 *
 * Returns: 1 if whitelisted, 0 otherwise
 */
static int
whitelist_check (SocketSYNProtect_T protect, const char *ip)
{
  unsigned bucket;
  uint8_t ip_bytes[16];
  int family;

  if (protect->whitelist_count == 0)
    return 0;

  family = parse_ip_address (ip, ip_bytes, sizeof (ip_bytes));
  /* If invalid IP, can't be whitelisted */
  if (family == 0)
    return 0;

  bucket = synprotect_hash_ip (protect, ip, SOCKET_SYN_LIST_HASH_SIZE);

  if (whitelist_check_bucket_bytes (protect->whitelist_table[bucket], ip,
                                    family, ip_bytes))
    return 1;

  return whitelist_check_all_cidrs_bytes (protect, family, ip_bytes, bucket);
}

/* ============================================================================
 * Internal Helper Functions - Blacklist
 * ============================================================================
 */

/**
 * remove_ip_entry_from_hash - Remove entry from hash table
 * @protect: Protection instance (must hold mutex)
 * @entry: Entry to remove
 */
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

/**
 * blacklist_check - Check if IP is blacklisted
 * @protect: Protection instance (must hold mutex)
 * @ip: IP address to check
 * @now_ms: Current timestamp
 *
 * Returns: 1 if blacklisted and not expired, 0 otherwise
 */
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
      if (strcmp (entry->ip, ip) == 0)
        {
          if (entry->expires_ms == 0 || entry->expires_ms > now_ms)
            return 1;
        }
      entry = entry->next;
    }

  return 0;
}

#undef T