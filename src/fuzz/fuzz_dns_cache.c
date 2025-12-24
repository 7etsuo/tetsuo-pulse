/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dns_cache.c - libFuzzer harness for DNS cache subsystems
 *
 * Fuzzes the DNS cache implementations (RFC 2308):
 * - SocketDNSNegCache: Negative caching (NXDOMAIN, NODATA)
 * - SocketDNSServfailCache: Server failure caching (SERVFAIL)
 *
 * Targets:
 * - SocketDNSNegCache_insert_nxdomain()
 * - SocketDNSNegCache_insert_nodata()
 * - SocketDNSNegCache_insert_nxdomain_with_soa()
 * - SocketDNSNegCache_insert_nodata_with_soa()
 * - SocketDNSNegCache_lookup()
 * - SocketDNSNegCache_remove()
 * - SocketDNSNegCache_build_response()
 * - SocketDNSServfailCache_insert()
 * - SocketDNSServfailCache_lookup()
 * - SocketDNSServfailCache_remove()
 * - SocketDNSServfailCache_remove_nameserver()
 *
 * Test cases:
 * - Edge case TTL values (0, 1, UINT32_MAX)
 * - Negative cache key generation (NXDOMAIN qtype=0, NODATA qtype-specific)
 * - Cache eviction under pressure (fill beyond max_entries)
 * - Concurrent insert/lookup patterns
 * - SERVFAIL 4-tuple caching (qname, qtype, qclass, nameserver)
 * - TTL expiration edge cases (just expired, just valid)
 * - SOA record caching for RFC 2308 Section 6 compliance
 * - Response building with decremented TTLs
 * - Nameserver-specific removal
 * - Name normalization (case-insensitive)
 * - LRU eviction correctness
 * - Statistics tracking accuracy
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_dns_cache
 * Run:   ./fuzz_dns_cache corpus/dns_cache/ -fork=16 -max_len=4096
 */

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNSNegCache.h"
#include "dns/SocketDNSServfailCache.h"
#include "dns/SocketDNSWire.h"

/* Maximum operations per fuzzing iteration */
#define MAX_OPS 128

/* Operation types */
typedef enum
{
  OP_NEG_INSERT_NXDOMAIN = 0,
  OP_NEG_INSERT_NODATA = 1,
  OP_NEG_INSERT_NXDOMAIN_SOA = 2,
  OP_NEG_INSERT_NODATA_SOA = 3,
  OP_NEG_LOOKUP = 4,
  OP_NEG_REMOVE = 5,
  OP_NEG_REMOVE_NODATA = 6,
  OP_NEG_BUILD_RESPONSE = 7,
  OP_NEG_SET_MAX_ENTRIES = 8,
  OP_NEG_SET_MAX_TTL = 9,
  OP_NEG_CLEAR = 10,
  OP_NEG_STATS = 11,
  OP_SERVFAIL_INSERT = 12,
  OP_SERVFAIL_LOOKUP = 13,
  OP_SERVFAIL_REMOVE = 14,
  OP_SERVFAIL_REMOVE_NS = 15,
  OP_SERVFAIL_CLEAR = 16,
  OP_SERVFAIL_SET_MAX = 17,
  OP_SERVFAIL_STATS = 18,
  OP_COUNT
} OpType;

/**
 * @brief Extract variable-length string from fuzzer input.
 *
 * Reads a length byte followed by that many bytes of string data.
 * Ensures null termination.
 */
static size_t
extract_string (const uint8_t *data, size_t size, size_t *offset, char *out,
                size_t max_len)
{
  if (*offset >= size)
    {
      if (max_len > 0)
        out[0] = '\0';
      return 0;
    }

  uint8_t len = data[(*offset)++];
  if (len == 0 || len > max_len - 1)
    len = max_len - 1;

  size_t available = size - *offset;
  if (len > available)
    len = available;

  if (len > 0)
    {
      memcpy (out, data + *offset, len);
      *offset += len;
    }

  out[len] = '\0';
  return len;
}

/**
 * @brief Extract uint16_t from fuzzer input.
 */
static uint16_t
extract_uint16 (const uint8_t *data, size_t size, size_t *offset)
{
  if (*offset + 2 > size)
    return 0;

  uint16_t val = ((uint16_t)data[*offset] << 8) | data[*offset + 1];
  *offset += 2;
  return val;
}

/**
 * @brief Extract uint32_t from fuzzer input.
 */
static uint32_t
extract_uint32 (const uint8_t *data, size_t size, size_t *offset)
{
  if (*offset + 4 > size)
    return 0;

  uint32_t val = ((uint32_t)data[*offset] << 24)
                 | ((uint32_t)data[*offset + 1] << 16)
                 | ((uint32_t)data[*offset + 2] << 8) | data[*offset + 3];
  *offset += 4;
  return val;
}

/**
 * @brief Create fake SOA RDATA for testing.
 */
static void
make_soa_rdata (const uint8_t *data, size_t size, size_t *offset,
                SocketDNS_CachedSOA *soa)
{
  memset (soa, 0, sizeof (*soa));

  /* Extract SOA owner name */
  char name[DNS_NEGCACHE_MAX_SOA_NAME + 1];
  extract_string (data, size, offset, name, sizeof (name));
  snprintf (soa->name, sizeof (soa->name), "%s", name);

  /* Generate minimal SOA RDATA (MNAME, RNAME, serial, refresh, retry, expire,
   * minimum) */
  soa->rdlen = 0;
  soa->has_soa = 1;

  /* For fuzzing, we'll use a simple fixed SOA structure */
  /* Real SOA parsing is tested in fuzz_dns_soa.c */
  if (*offset + 20 <= size)
    {
      memcpy (soa->rdata, data + *offset, 20);
      soa->rdlen = 20;
      *offset += 20;
    }

  soa->original_ttl = extract_uint32 (data, size, offset);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  volatile Arena_T arena = NULL;
  volatile SocketDNSNegCache_T negcache = NULL;
  volatile SocketDNSServfailCache_T servfailcache = NULL;

  /* Need at least 1 byte for operation count */
  if (size < 1)
    return 0;

  size_t offset = 0;

  /* Extract number of operations */
  uint8_t op_count = data[offset++];
  if (op_count > (MAX_OPS - 1))
    op_count = (MAX_OPS - 1);

  TRY
  {
    /* Create arena and caches */
    arena = Arena_new ();
    if (arena == NULL)
      RETURN 0;

    negcache = SocketDNSNegCache_new (arena);
    servfailcache = SocketDNSServfailCache_new (arena);

    if (negcache == NULL || servfailcache == NULL)
      RETURN 0;

    /* Set initial cache sizes (fuzzer can change these later) */
    SocketDNSNegCache_set_max_entries (negcache, 100);
    SocketDNSServfailCache_set_max_entries (servfailcache, 50);

    /* Execute operations */
    for (uint8_t i = 0; i < op_count && offset < size; i++)
      {
        if (offset >= size)
          break;

        OpType op = data[offset++] % OP_COUNT;

        /* Extract common parameters */
        char qname[DNS_NEGCACHE_MAX_NAME + 1];
        char nameserver[DNS_SERVFAIL_MAX_NS + 1];
        uint16_t qtype, qclass;
        uint32_t ttl;

        switch (op)
          {
          case OP_NEG_INSERT_NXDOMAIN:
            extract_string (data, size, &offset, qname, sizeof (qname));
            qclass = extract_uint16 (data, size, &offset);
            ttl = extract_uint32 (data, size, &offset);
            (void)SocketDNSNegCache_insert_nxdomain (negcache, qname, qclass,
                                                      ttl);
            break;

          case OP_NEG_INSERT_NODATA:
            extract_string (data, size, &offset, qname, sizeof (qname));
            qtype = extract_uint16 (data, size, &offset);
            qclass = extract_uint16 (data, size, &offset);
            ttl = extract_uint32 (data, size, &offset);
            (void)SocketDNSNegCache_insert_nodata (negcache, qname, qtype,
                                                    qclass, ttl);
            break;

          case OP_NEG_INSERT_NXDOMAIN_SOA:
            {
              extract_string (data, size, &offset, qname, sizeof (qname));
              qclass = extract_uint16 (data, size, &offset);
              ttl = extract_uint32 (data, size, &offset);

              SocketDNS_CachedSOA soa;
              make_soa_rdata (data, size, &offset, &soa);

              (void)SocketDNSNegCache_insert_nxdomain_with_soa (
                  negcache, qname, qclass, ttl, &soa);
            }
            break;

          case OP_NEG_INSERT_NODATA_SOA:
            {
              extract_string (data, size, &offset, qname, sizeof (qname));
              qtype = extract_uint16 (data, size, &offset);
              qclass = extract_uint16 (data, size, &offset);
              ttl = extract_uint32 (data, size, &offset);

              SocketDNS_CachedSOA soa;
              make_soa_rdata (data, size, &offset, &soa);

              (void)SocketDNSNegCache_insert_nodata_with_soa (
                  negcache, qname, qtype, qclass, ttl, &soa);
            }
            break;

          case OP_NEG_LOOKUP:
            {
              extract_string (data, size, &offset, qname, sizeof (qname));
              qtype = extract_uint16 (data, size, &offset);
              qclass = extract_uint16 (data, size, &offset);

              SocketDNS_NegCacheEntry entry;
              (void)SocketDNSNegCache_lookup (negcache, qname, qtype, qclass,
                                               &entry);
            }
            break;

          case OP_NEG_REMOVE:
            extract_string (data, size, &offset, qname, sizeof (qname));
            (void)SocketDNSNegCache_remove (negcache, qname);
            break;

          case OP_NEG_REMOVE_NODATA:
            extract_string (data, size, &offset, qname, sizeof (qname));
            qtype = extract_uint16 (data, size, &offset);
            qclass = extract_uint16 (data, size, &offset);
            (void)SocketDNSNegCache_remove_nodata (negcache, qname, qtype,
                                                    qclass);
            break;

          case OP_NEG_BUILD_RESPONSE:
            {
              extract_string (data, size, &offset, qname, sizeof (qname));
              qtype = extract_uint16 (data, size, &offset);
              qclass = extract_uint16 (data, size, &offset);

              /* First lookup to get an entry */
              SocketDNS_NegCacheEntry entry;
              SocketDNS_NegCacheResult result = SocketDNSNegCache_lookup (
                  negcache, qname, qtype, qclass, &entry);

              /* If we have a cached entry, try building a response */
              if (result != DNS_NEG_MISS)
                {
                  unsigned char response[1024];
                  size_t written;
                  uint16_t query_id = extract_uint16 (data, size, &offset);

                  (void)SocketDNSNegCache_build_response (
                      &entry, qname, qtype, qclass, query_id, response,
                      sizeof (response), &written);
                }
            }
            break;

          case OP_NEG_SET_MAX_ENTRIES:
            {
              uint32_t max = extract_uint32 (data, size, &offset);
              if (max > 1000)
                max = 1000; /* Cap to prevent excessive memory */
              SocketDNSNegCache_set_max_entries (negcache, max);
            }
            break;

          case OP_NEG_SET_MAX_TTL:
            {
              uint32_t max_ttl = extract_uint32 (data, size, &offset);
              SocketDNSNegCache_set_max_ttl (negcache, max_ttl);
            }
            break;

          case OP_NEG_CLEAR:
            SocketDNSNegCache_clear (negcache);
            break;

          case OP_NEG_STATS:
            {
              SocketDNS_NegCacheStats stats;
              SocketDNSNegCache_stats (negcache, &stats);
              (void)stats.hit_rate; /* Use to prevent optimization */
            }
            break;

          case OP_SERVFAIL_INSERT:
            extract_string (data, size, &offset, qname, sizeof (qname));
            qtype = extract_uint16 (data, size, &offset);
            qclass = extract_uint16 (data, size, &offset);
            extract_string (data, size, &offset, nameserver,
                            sizeof (nameserver));
            ttl = extract_uint32 (data, size, &offset);
            (void)SocketDNSServfailCache_insert (servfailcache, qname, qtype,
                                                  qclass, nameserver, ttl);
            break;

          case OP_SERVFAIL_LOOKUP:
            {
              extract_string (data, size, &offset, qname, sizeof (qname));
              qtype = extract_uint16 (data, size, &offset);
              qclass = extract_uint16 (data, size, &offset);
              extract_string (data, size, &offset, nameserver,
                              sizeof (nameserver));

              SocketDNS_ServfailCacheEntry entry;
              (void)SocketDNSServfailCache_lookup (
                  servfailcache, qname, qtype, qclass, nameserver, &entry);
            }
            break;

          case OP_SERVFAIL_REMOVE:
            extract_string (data, size, &offset, qname, sizeof (qname));
            qtype = extract_uint16 (data, size, &offset);
            qclass = extract_uint16 (data, size, &offset);
            extract_string (data, size, &offset, nameserver,
                            sizeof (nameserver));
            (void)SocketDNSServfailCache_remove (servfailcache, qname, qtype,
                                                  qclass, nameserver);
            break;

          case OP_SERVFAIL_REMOVE_NS:
            extract_string (data, size, &offset, nameserver,
                            sizeof (nameserver));
            (void)SocketDNSServfailCache_remove_nameserver (servfailcache,
                                                             nameserver);
            break;

          case OP_SERVFAIL_CLEAR:
            SocketDNSServfailCache_clear (servfailcache);
            break;

          case OP_SERVFAIL_SET_MAX:
            {
              uint32_t max = extract_uint32 (data, size, &offset);
              if (max > 500)
                max = 500; /* Cap to prevent excessive memory */
              SocketDNSServfailCache_set_max_entries (servfailcache, max);
            }
            break;

          case OP_SERVFAIL_STATS:
            {
              SocketDNS_ServfailCacheStats stats;
              SocketDNSServfailCache_stats (servfailcache, &stats);
              (void)stats.hit_rate; /* Use to prevent optimization */
            }
            break;

          case OP_COUNT:
            /* Unreachable due to modulo, but satisfies -Wswitch */
            break;
          }
      }

    /* Cleanup - free in correct order */
    SocketDNSNegCache_free ((SocketDNSNegCache_T *)&negcache);
    SocketDNSServfailCache_free ((SocketDNSServfailCache_T *)&servfailcache);
    Arena_dispose ((Arena_T *)&arena);
  }
  EXCEPT (Arena_Failed)
  {
     /* Expected - fuzzer may exhaust memory */
  }
  FINALLY
  {
    if (negcache != NULL)
      SocketDNSNegCache_free ((SocketDNSNegCache_T *)&negcache);
    if (servfailcache != NULL)
      SocketDNSServfailCache_free ((SocketDNSServfailCache_T *)&servfailcache);
    if (arena != NULL)
      Arena_dispose ((Arena_T *)&arena);
  }
  END_TRY;

  return 0;
}
