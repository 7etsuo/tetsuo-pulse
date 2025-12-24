/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/*
 * test_dns_negcache.c - Unit tests for DNS Negative Response Cache (RFC 2308)
 *
 * Tests RFC 2308 compliant negative caching with proper cache key tuples:
 * - NXDOMAIN: <QNAME, QCLASS> tuple (matches any QTYPE)
 * - NODATA: <QNAME, QTYPE, QCLASS> tuple (type-specific)
 */

#include "core/Arena.h"
#include "dns/SocketDNSNegCache.h"
#include "test/Test.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* DNS type constants for testing */
#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_CLASS_IN 1

/* Test basic cache creation and disposal */
TEST (negcache_new_free)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);
  ASSERT_NOT_NULL (cache);

  SocketDNS_NegCacheStats stats;
  SocketDNSNegCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 0);
  ASSERT_EQ (stats.max_entries, DNS_NEGCACHE_DEFAULT_MAX);
  ASSERT_EQ (stats.max_ttl, DNS_NEGCACHE_DEFAULT_MAX_TTL);

  SocketDNSNegCache_free (&cache);
  ASSERT_NULL (cache);
  Arena_dispose (&arena);
}

/* Test NXDOMAIN insertion and lookup */
TEST (negcache_nxdomain_insert_lookup)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);

  /* Insert NXDOMAIN for nonexistent.example.com */
  int ret
      = SocketDNSNegCache_insert_nxdomain (cache, "nonexistent.example.com",
                                           DNS_CLASS_IN, 300);
  ASSERT_EQ (ret, 0);

  SocketDNS_NegCacheStats stats;
  SocketDNSNegCache_stats (cache, &stats);
  ASSERT_EQ (stats.insertions, 1);
  ASSERT_EQ (stats.current_size, 1);

  /* Lookup should hit for ANY query type (RFC 2308 Section 5) */
  SocketDNS_NegCacheEntry entry;
  SocketDNS_NegCacheResult result;

  result = SocketDNSNegCache_lookup (cache, "nonexistent.example.com",
                                     DNS_TYPE_A, DNS_CLASS_IN, &entry);
  ASSERT_EQ (result, DNS_NEG_HIT_NXDOMAIN);
  ASSERT_EQ (entry.type, DNS_NEG_NXDOMAIN);
  ASSERT (entry.ttl_remaining > 0);
  ASSERT (entry.ttl_remaining <= 300);

  /* AAAA lookup should also hit the NXDOMAIN */
  result = SocketDNSNegCache_lookup (cache, "nonexistent.example.com",
                                     DNS_TYPE_AAAA, DNS_CLASS_IN, &entry);
  ASSERT_EQ (result, DNS_NEG_HIT_NXDOMAIN);

  /* MX lookup should also hit */
  result = SocketDNSNegCache_lookup (cache, "nonexistent.example.com",
                                     DNS_TYPE_MX, DNS_CLASS_IN, &entry);
  ASSERT_EQ (result, DNS_NEG_HIT_NXDOMAIN);

  SocketDNSNegCache_stats (cache, &stats);
  ASSERT_EQ (stats.hits, 3);
  ASSERT_EQ (stats.nxdomain_hits, 3);

  SocketDNSNegCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test NODATA insertion and lookup */
TEST (negcache_nodata_insert_lookup)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);

  /* Insert NODATA for example.com AAAA (name exists but no AAAA records) */
  int ret = SocketDNSNegCache_insert_nodata (cache, "example.com",
                                             DNS_TYPE_AAAA, DNS_CLASS_IN, 300);
  ASSERT_EQ (ret, 0);

  SocketDNS_NegCacheStats stats;
  SocketDNSNegCache_stats (cache, &stats);
  ASSERT_EQ (stats.insertions, 1);

  /* Lookup AAAA should hit */
  SocketDNS_NegCacheEntry entry;
  SocketDNS_NegCacheResult result;

  result = SocketDNSNegCache_lookup (cache, "example.com", DNS_TYPE_AAAA,
                                     DNS_CLASS_IN, &entry);
  ASSERT_EQ (result, DNS_NEG_HIT_NODATA);
  ASSERT_EQ (entry.type, DNS_NEG_NODATA);

  /* Lookup A should MISS (NODATA is type-specific per RFC 2308) */
  result = SocketDNSNegCache_lookup (cache, "example.com", DNS_TYPE_A,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_MISS);

  /* Lookup MX should also MISS */
  result = SocketDNSNegCache_lookup (cache, "example.com", DNS_TYPE_MX,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_MISS);

  SocketDNSNegCache_stats (cache, &stats);
  ASSERT_EQ (stats.hits, 1);
  ASSERT_EQ (stats.nodata_hits, 1);
  ASSERT_EQ (stats.misses, 2);

  SocketDNSNegCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test NXDOMAIN takes precedence over NODATA */
TEST (negcache_nxdomain_precedence)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);

  /* Insert NODATA for specific type first */
  SocketDNSNegCache_insert_nodata (cache, "test.example.com", DNS_TYPE_A,
                                   DNS_CLASS_IN, 300);

  /* Then insert NXDOMAIN for same name (should replace/override) */
  SocketDNSNegCache_insert_nxdomain (cache, "test.example.com", DNS_CLASS_IN,
                                     600);

  /* Lookup should return NXDOMAIN (takes precedence) */
  SocketDNS_NegCacheResult result;
  result = SocketDNSNegCache_lookup (cache, "test.example.com", DNS_TYPE_A,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_HIT_NXDOMAIN);

  /* Other types should also return NXDOMAIN */
  result = SocketDNSNegCache_lookup (cache, "test.example.com", DNS_TYPE_AAAA,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_HIT_NXDOMAIN);

  SocketDNSNegCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test case-insensitive lookup */
TEST (negcache_case_insensitive)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);

  /* Insert with lowercase */
  SocketDNSNegCache_insert_nxdomain (cache, "test.example.com", DNS_CLASS_IN,
                                     300);

  /* Lookup with different cases should all hit */
  SocketDNS_NegCacheResult result;

  result = SocketDNSNegCache_lookup (cache, "TEST.EXAMPLE.COM", DNS_TYPE_A,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_HIT_NXDOMAIN);

  result = SocketDNSNegCache_lookup (cache, "Test.Example.Com", DNS_TYPE_A,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_HIT_NXDOMAIN);

  result = SocketDNSNegCache_lookup (cache, "tEsT.eXaMpLe.CoM", DNS_TYPE_A,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_HIT_NXDOMAIN);

  SocketDNSNegCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test TTL expiration */
TEST (negcache_ttl_expiration)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);

  /* Insert with 1 second TTL */
  SocketDNSNegCache_insert_nxdomain (cache, "expiring.example.com",
                                     DNS_CLASS_IN, 1);

  /* Should hit immediately */
  SocketDNS_NegCacheResult result;
  result = SocketDNSNegCache_lookup (cache, "expiring.example.com", DNS_TYPE_A,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_HIT_NXDOMAIN);

  /* Wait for TTL to expire */
  sleep (2);

  /* Should now miss due to expiration */
  result = SocketDNSNegCache_lookup (cache, "expiring.example.com", DNS_TYPE_A,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_MISS);

  SocketDNS_NegCacheStats stats;
  SocketDNSNegCache_stats (cache, &stats);
  ASSERT (stats.expirations > 0);

  SocketDNSNegCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test max TTL clamping */
TEST (negcache_max_ttl_clamp)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);

  /* Set low max TTL */
  SocketDNSNegCache_set_max_ttl (cache, 60);

  /* Insert with high TTL - should be clamped */
  SocketDNSNegCache_insert_nxdomain (cache, "clamped.example.com", DNS_CLASS_IN,
                                     3600);

  /* Lookup and verify TTL was clamped */
  SocketDNS_NegCacheEntry entry;
  SocketDNSNegCache_lookup (cache, "clamped.example.com", DNS_TYPE_A,
                            DNS_CLASS_IN, &entry);
  ASSERT (entry.original_ttl <= 60);

  SocketDNSNegCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test LRU eviction when cache is full */
TEST (negcache_lru_eviction)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);

  /* Set very small cache size */
  SocketDNSNegCache_set_max_entries (cache, 3);

  /* Insert 3 entries */
  SocketDNSNegCache_insert_nxdomain (cache, "first.example.com", DNS_CLASS_IN,
                                     300);
  SocketDNSNegCache_insert_nxdomain (cache, "second.example.com", DNS_CLASS_IN,
                                     300);
  SocketDNSNegCache_insert_nxdomain (cache, "third.example.com", DNS_CLASS_IN,
                                     300);

  SocketDNS_NegCacheStats stats;
  SocketDNSNegCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 3);

  /* Access first entry to make it recently used */
  SocketDNSNegCache_lookup (cache, "first.example.com", DNS_TYPE_A,
                            DNS_CLASS_IN, NULL);

  /* Insert 4th entry - should evict LRU (second) */
  SocketDNSNegCache_insert_nxdomain (cache, "fourth.example.com", DNS_CLASS_IN,
                                     300);

  SocketDNSNegCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 3);
  ASSERT (stats.evictions > 0);

  /* First should still be present (was accessed) */
  SocketDNS_NegCacheResult result;
  result = SocketDNSNegCache_lookup (cache, "first.example.com", DNS_TYPE_A,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_HIT_NXDOMAIN);

  /* Second should have been evicted */
  result = SocketDNSNegCache_lookup (cache, "second.example.com", DNS_TYPE_A,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_MISS);

  SocketDNSNegCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test remove by name */
TEST (negcache_remove)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);

  /* Insert NXDOMAIN */
  SocketDNSNegCache_insert_nxdomain (cache, "remove.example.com", DNS_CLASS_IN,
                                     300);

  /* Insert multiple NODATA for same name */
  SocketDNSNegCache_insert_nodata (cache, "partial.example.com", DNS_TYPE_A,
                                   DNS_CLASS_IN, 300);
  SocketDNSNegCache_insert_nodata (cache, "partial.example.com", DNS_TYPE_AAAA,
                                   DNS_CLASS_IN, 300);

  SocketDNS_NegCacheStats stats;
  SocketDNSNegCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 3);

  /* Remove all entries for partial.example.com */
  int removed = SocketDNSNegCache_remove (cache, "partial.example.com");
  ASSERT_EQ (removed, 2);

  SocketDNSNegCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 1);

  /* Lookups should miss */
  SocketDNS_NegCacheResult result;
  result = SocketDNSNegCache_lookup (cache, "partial.example.com", DNS_TYPE_A,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_MISS);

  /* Original entry should still exist */
  result = SocketDNSNegCache_lookup (cache, "remove.example.com", DNS_TYPE_A,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_HIT_NXDOMAIN);

  SocketDNSNegCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test remove specific NODATA */
TEST (negcache_remove_nodata)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);

  /* Insert multiple NODATA for same name */
  SocketDNSNegCache_insert_nodata (cache, "multi.example.com", DNS_TYPE_A,
                                   DNS_CLASS_IN, 300);
  SocketDNSNegCache_insert_nodata (cache, "multi.example.com", DNS_TYPE_AAAA,
                                   DNS_CLASS_IN, 300);
  SocketDNSNegCache_insert_nodata (cache, "multi.example.com", DNS_TYPE_MX,
                                   DNS_CLASS_IN, 300);

  SocketDNS_NegCacheStats stats;
  SocketDNSNegCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 3);

  /* Remove only AAAA NODATA */
  int removed = SocketDNSNegCache_remove_nodata (cache, "multi.example.com",
                                                 DNS_TYPE_AAAA, DNS_CLASS_IN);
  ASSERT_EQ (removed, 1);

  SocketDNSNegCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 2);

  /* AAAA should miss */
  SocketDNS_NegCacheResult result;
  result = SocketDNSNegCache_lookup (cache, "multi.example.com", DNS_TYPE_AAAA,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_MISS);

  /* A and MX should still hit */
  result = SocketDNSNegCache_lookup (cache, "multi.example.com", DNS_TYPE_A,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_HIT_NODATA);

  result = SocketDNSNegCache_lookup (cache, "multi.example.com", DNS_TYPE_MX,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_HIT_NODATA);

  SocketDNSNegCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test cache clear */
TEST (negcache_clear)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);

  /* Insert several entries */
  SocketDNSNegCache_insert_nxdomain (cache, "a.example.com", DNS_CLASS_IN, 300);
  SocketDNSNegCache_insert_nxdomain (cache, "b.example.com", DNS_CLASS_IN, 300);
  SocketDNSNegCache_insert_nodata (cache, "c.example.com", DNS_TYPE_A,
                                   DNS_CLASS_IN, 300);

  SocketDNS_NegCacheStats stats;
  SocketDNSNegCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 3);

  /* Clear cache */
  SocketDNSNegCache_clear (cache);

  SocketDNSNegCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 0);

  /* All lookups should miss */
  SocketDNS_NegCacheResult result;
  result = SocketDNSNegCache_lookup (cache, "a.example.com", DNS_TYPE_A,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_MISS);

  SocketDNSNegCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test statistics accuracy */
TEST (negcache_stats_accuracy)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);

  SocketDNS_NegCacheStats stats;
  SocketDNSNegCache_stats (cache, &stats);

  /* Initial stats should be zero */
  ASSERT_EQ (stats.hits, 0);
  ASSERT_EQ (stats.misses, 0);
  ASSERT_EQ (stats.insertions, 0);

  /* Insert and lookup */
  SocketDNSNegCache_insert_nxdomain (cache, "stat.example.com", DNS_CLASS_IN,
                                     300);
  SocketDNSNegCache_insert_nodata (cache, "nodata.example.com", DNS_TYPE_A,
                                   DNS_CLASS_IN, 300);

  SocketDNSNegCache_lookup (cache, "stat.example.com", DNS_TYPE_A, DNS_CLASS_IN,
                            NULL);
  SocketDNSNegCache_lookup (cache, "stat.example.com", DNS_TYPE_AAAA,
                            DNS_CLASS_IN, NULL);
  SocketDNSNegCache_lookup (cache, "nodata.example.com", DNS_TYPE_A,
                            DNS_CLASS_IN, NULL);
  SocketDNSNegCache_lookup (cache, "miss.example.com", DNS_TYPE_A, DNS_CLASS_IN,
                            NULL);

  SocketDNSNegCache_stats (cache, &stats);

  ASSERT_EQ (stats.insertions, 2);
  ASSERT_EQ (stats.hits, 3);       /* 2 NXDOMAIN + 1 NODATA */
  ASSERT_EQ (stats.nxdomain_hits, 2);
  ASSERT_EQ (stats.nodata_hits, 1);
  ASSERT_EQ (stats.misses, 1);

  /* Verify hit rate calculation */
  double expected_hit_rate = 3.0 / 4.0; /* 3 hits out of 4 lookups */
  ASSERT (stats.hit_rate > 0.7);
  ASSERT (stats.hit_rate < 0.8);

  SocketDNSNegCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test type name and result name functions */
TEST (negcache_name_functions)
{
  const char *type_name;
  const char *result_name;

  type_name = SocketDNSNegCache_type_name (DNS_NEG_NXDOMAIN);
  ASSERT (strcmp (type_name, "NXDOMAIN") == 0);

  type_name = SocketDNSNegCache_type_name (DNS_NEG_NODATA);
  ASSERT (strcmp (type_name, "NODATA") == 0);

  result_name = SocketDNSNegCache_result_name (DNS_NEG_MISS);
  ASSERT (strcmp (result_name, "MISS") == 0);

  result_name = SocketDNSNegCache_result_name (DNS_NEG_HIT_NXDOMAIN);
  ASSERT (strcmp (result_name, "HIT_NXDOMAIN") == 0);

  result_name = SocketDNSNegCache_result_name (DNS_NEG_HIT_NODATA);
  ASSERT (strcmp (result_name, "HIT_NODATA") == 0);
}

/* Test different query classes (RFC 2308 compliance) */
TEST (negcache_different_classes)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);

  /* Insert NXDOMAIN for class IN */
  SocketDNSNegCache_insert_nxdomain (cache, "class.example.com", DNS_CLASS_IN,
                                     300);

  /* Lookup with same class should hit */
  SocketDNS_NegCacheResult result;
  result = SocketDNSNegCache_lookup (cache, "class.example.com", DNS_TYPE_A,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_HIT_NXDOMAIN);

  /* Lookup with different class should miss (per RFC 2308) */
  uint16_t DNS_CLASS_CH = 3; /* Chaos class */
  result = SocketDNSNegCache_lookup (cache, "class.example.com", DNS_TYPE_A,
                                     DNS_CLASS_CH, NULL);
  ASSERT_EQ (result, DNS_NEG_MISS);

  SocketDNSNegCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test name length limits */
TEST (negcache_name_limits)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);

  /* Create a name at the max length (255 characters) */
  char long_name[256];
  memset (long_name, 'a', 255);
  long_name[255] = '\0';

  /* Should succeed */
  int ret
      = SocketDNSNegCache_insert_nxdomain (cache, long_name, DNS_CLASS_IN, 300);
  ASSERT_EQ (ret, 0);

  /* Lookup should work */
  SocketDNS_NegCacheResult result;
  result = SocketDNSNegCache_lookup (cache, long_name, DNS_TYPE_A, DNS_CLASS_IN,
                                     NULL);
  ASSERT_EQ (result, DNS_NEG_HIT_NXDOMAIN);

  /* Create a name exceeding max length (256 characters) */
  char too_long_name[257];
  memset (too_long_name, 'b', 256);
  too_long_name[256] = '\0';

  /* Should fail */
  ret = SocketDNSNegCache_insert_nxdomain (cache, too_long_name, DNS_CLASS_IN,
                                           300);
  ASSERT_EQ (ret, -1);

  SocketDNSNegCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test cache disabled (max_entries = 0) */
TEST (negcache_disabled)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);

  /* Disable cache */
  SocketDNSNegCache_set_max_entries (cache, 0);

  /* Insertions should fail */
  int ret = SocketDNSNegCache_insert_nxdomain (cache, "disabled.example.com",
                                               DNS_CLASS_IN, 300);
  ASSERT_EQ (ret, -1);

  SocketDNS_NegCacheStats stats;
  SocketDNSNegCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 0);
  ASSERT_EQ (stats.insertions, 0);

  SocketDNSNegCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test zero TTL entries */
TEST (negcache_zero_ttl)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);

  /* Insert with zero TTL - should still be cached momentarily */
  int ret = SocketDNSNegCache_insert_nxdomain (cache, "zero.example.com",
                                               DNS_CLASS_IN, 0);
  ASSERT_EQ (ret, 0);

  /* Immediate lookup might hit or miss depending on timing */
  SocketDNS_NegCacheStats stats;
  SocketDNSNegCache_stats (cache, &stats);
  ASSERT_EQ (stats.insertions, 1);

  SocketDNSNegCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test NULL entry pointer in lookup */
TEST (negcache_null_entry)
{
  Arena_T arena = Arena_new ();
  SocketDNSNegCache_T cache = SocketDNSNegCache_new (arena);

  SocketDNSNegCache_insert_nxdomain (cache, "null.example.com", DNS_CLASS_IN,
                                     300);

  /* Lookup with NULL entry should still work */
  SocketDNS_NegCacheResult result;
  result = SocketDNSNegCache_lookup (cache, "null.example.com", DNS_TYPE_A,
                                     DNS_CLASS_IN, NULL);
  ASSERT_EQ (result, DNS_NEG_HIT_NXDOMAIN);

  SocketDNSNegCache_free (&cache);
  Arena_dispose (&arena);
}

/* Main function - run all tests */
int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
