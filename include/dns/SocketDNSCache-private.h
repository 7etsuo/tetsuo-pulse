/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETDNSCACHE_PRIVATE_H
#define SOCKETDNSCACHE_PRIVATE_H

/**
 * @file SocketDNSCache-private.h
 * @brief Shared hash function for DNS cache key tuples.
 *
 * Provides a common DJB2-based hash for the (name, qtype, qclass) tuple
 * used by both SocketDNSNegCache and SocketDNSServfailCache.
 *
 * Uses case-insensitive name hashing per RFC 1035 Section 2.3.3 and a
 * random seed for hash collision DoS protection.
 */

#include <stdint.h>

#include "core/SocketUtil/Core.h"
#include "core/SocketUtil/Hash.h"

/**
 * @brief Compute raw hash for DNS cache key tuple (before modulo).
 *
 * Computes a seeded DJB2 XOR hash over the case-insensitive name,
 * then extends with qtype and qclass. Returns the raw hash value
 * so callers can extend it further (e.g., with a nameserver field)
 * before applying modulo.
 *
 * @param name    DNS name to hash (case-insensitive).
 * @param qtype   Query type (0 for NXDOMAIN entries).
 * @param qclass  Query class.
 * @param seed    Per-instance random seed for DoS protection.
 * @return Raw hash value (before modulo reduction).
 */
static inline unsigned
dns_cache_hash_tuple_raw (const char *name,
                          uint16_t qtype,
                          uint16_t qclass,
                          uint32_t seed)
{
  unsigned hash = SOCKET_UTIL_DJB2_SEED;

  /* Mix in random seed for DoS protection */
  hash = DJB2_STEP_XOR (hash, seed);

  /* Hash the normalized name (case-insensitive per DNS spec) */
  for (const char *p = name; *p; p++)
    {
      unsigned char c = ASCII_TOLOWER ((unsigned char)*p);
      hash = DJB2_STEP_XOR (hash, c);
    }

  /* Extend hash with qtype and qclass for RFC 2308 cache key tuple */
  hash = DJB2_STEP_XOR (hash, qtype);
  hash = DJB2_STEP_XOR (hash, qclass);

  return hash;
}

/**
 * @brief Hash a DNS cache key tuple (name, qtype, qclass) with seed.
 *
 * Convenience wrapper that computes the raw tuple hash and applies
 * modulo reduction. Use dns_cache_hash_tuple_raw() when the hash
 * needs to be extended with additional fields before reduction.
 *
 * @param name    DNS name to hash (case-insensitive).
 * @param qtype   Query type (0 for NXDOMAIN entries).
 * @param qclass  Query class.
 * @param seed    Per-instance random seed for DoS protection.
 * @param table_size  Hash table size for modulo reduction.
 * @return Hash value in range [0, table_size).
 */
static inline unsigned
dns_cache_hash_tuple (const char *name,
                      uint16_t qtype,
                      uint16_t qclass,
                      uint32_t seed,
                      unsigned table_size)
{
  return dns_cache_hash_tuple_raw (name, qtype, qclass, seed) % table_size;
}

/**
 * @brief Remove an entry from a doubly-linked LRU list.
 *
 * Unlinks `entry` from the list anchored by `head_ptr` / `tail_ptr`.
 * All DNS cache entry types share lru_prev/lru_next intrusive fields.
 *
 * @param head_ptr  Pointer to head pointer (e.g., cache->lru_head).
 * @param tail_ptr  Pointer to tail pointer (e.g., cache->lru_tail).
 * @param entry     Entry to remove (must have lru_prev/lru_next fields).
 */
#define DNS_LRU_REMOVE(head_ptr, tail_ptr, entry)        \
  do                                                     \
    {                                                    \
      if ((entry)->lru_prev)                             \
        (entry)->lru_prev->lru_next = (entry)->lru_next; \
      else                                               \
        (head_ptr) = (entry)->lru_next;                  \
                                                         \
      if ((entry)->lru_next)                             \
        (entry)->lru_next->lru_prev = (entry)->lru_prev; \
      else                                               \
        (tail_ptr) = (entry)->lru_prev;                  \
                                                         \
      (entry)->lru_prev = NULL;                          \
      (entry)->lru_next = NULL;                          \
    }                                                    \
  while (0)

/**
 * @brief Insert an entry at the head of a doubly-linked LRU list.
 *
 * @param head_ptr  Pointer to head pointer.
 * @param tail_ptr  Pointer to tail pointer.
 * @param entry     Entry to insert at head.
 */
#define DNS_LRU_INSERT_HEAD(head_ptr, tail_ptr, entry) \
  do                                                   \
    {                                                  \
      (entry)->lru_prev = NULL;                        \
      (entry)->lru_next = (head_ptr);                  \
                                                       \
      if ((head_ptr))                                  \
        (head_ptr)->lru_prev = (entry);                \
      else                                             \
        (tail_ptr) = (entry);                          \
                                                       \
      (head_ptr) = (entry);                            \
    }                                                  \
  while (0)

/**
 * @brief Move an entry to the head of a doubly-linked LRU list (touch).
 *
 * @param head_ptr  Pointer to head pointer.
 * @param tail_ptr  Pointer to tail pointer.
 * @param entry     Entry to move to head.
 */
#define DNS_LRU_TOUCH(head_ptr, tail_ptr, entry)                 \
  do                                                             \
    {                                                            \
      if ((entry) != (head_ptr))                                 \
        {                                                        \
          DNS_LRU_REMOVE ((head_ptr), (tail_ptr), (entry));      \
          DNS_LRU_INSERT_HEAD ((head_ptr), (tail_ptr), (entry)); \
        }                                                        \
    }                                                            \
  while (0)

#endif /* SOCKETDNSCACHE_PRIVATE_H */
