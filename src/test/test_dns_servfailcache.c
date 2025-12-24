/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/*
 * test_dns_servfailcache.c - Unit tests for DNS SERVFAIL Cache (RFC 2308 Section 7.1)
 *
 * Tests RFC 2308 Section 7.1 compliant SERVFAIL caching with:
 * - 4-tuple cache key: <QNAME, QTYPE, QCLASS, nameserver>
 * - 5-minute maximum TTL
 * - Server-specific failure tracking
 */

#include "core/Arena.h"
#include "dns/SocketDNSServfailCache.h"
#include "test/Test.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* DNS type constants for testing */
#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_MX 15
#define DNS_CLASS_IN 1

/* Test basic cache creation and disposal */
TEST (servfailcache_new_free)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);
  ASSERT_NOT_NULL (cache);

  SocketDNS_ServfailCacheStats stats;
  SocketDNSServfailCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 0);
  ASSERT_EQ (stats.max_entries, DNS_SERVFAIL_DEFAULT_MAX);

  SocketDNSServfailCache_free (&cache);
  ASSERT_NULL (cache);
  Arena_dispose (&arena);
}

/* Test SERVFAIL insertion and lookup */
TEST (servfailcache_insert_lookup)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);

  /* Insert SERVFAIL for example.com A query to 8.8.8.8 */
  int ret = SocketDNSServfailCache_insert (cache, "example.com", DNS_TYPE_A,
                                            DNS_CLASS_IN, "8.8.8.8", 300);
  ASSERT_EQ (ret, 0);

  SocketDNS_ServfailCacheStats stats;
  SocketDNSServfailCache_stats (cache, &stats);
  ASSERT_EQ (stats.insertions, 1);
  ASSERT_EQ (stats.current_size, 1);

  /* Lookup should hit for same 4-tuple */
  SocketDNS_ServfailCacheEntry entry;
  SocketDNS_ServfailCacheResult result;

  result = SocketDNSServfailCache_lookup (cache, "example.com", DNS_TYPE_A,
                                           DNS_CLASS_IN, "8.8.8.8", &entry);
  ASSERT_EQ (result, DNS_SERVFAIL_HIT);
  ASSERT (entry.ttl_remaining > 0);
  ASSERT (entry.ttl_remaining <= 300);

  SocketDNSServfailCache_stats (cache, &stats);
  ASSERT_EQ (stats.hits, 1);

  SocketDNSServfailCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test server-specific caching: different nameserver should miss */
TEST (servfailcache_server_specific)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);

  /* Insert SERVFAIL for 8.8.8.8 */
  SocketDNSServfailCache_insert (cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN,
                                  "8.8.8.8", 300);

  /* Lookup with same nameserver should hit */
  SocketDNS_ServfailCacheResult result;
  result = SocketDNSServfailCache_lookup (cache, "example.com", DNS_TYPE_A,
                                           DNS_CLASS_IN, "8.8.8.8", NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_HIT);

  /* Lookup with different nameserver should MISS */
  result = SocketDNSServfailCache_lookup (cache, "example.com", DNS_TYPE_A,
                                           DNS_CLASS_IN, "8.8.4.4", NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_MISS);

  /* Lookup with IPv6 nameserver should MISS */
  result = SocketDNSServfailCache_lookup (cache, "example.com", DNS_TYPE_A,
                                           DNS_CLASS_IN, "2001:4860:4860::8888",
                                           NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_MISS);

  SocketDNS_ServfailCacheStats stats;
  SocketDNSServfailCache_stats (cache, &stats);
  ASSERT_EQ (stats.hits, 1);
  ASSERT_EQ (stats.misses, 2);

  SocketDNSServfailCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test type-specific caching: different QTYPE should miss */
TEST (servfailcache_type_specific)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);

  /* Insert SERVFAIL for A query */
  SocketDNSServfailCache_insert (cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN,
                                  "8.8.8.8", 300);

  /* Lookup A should hit */
  SocketDNS_ServfailCacheResult result;
  result = SocketDNSServfailCache_lookup (cache, "example.com", DNS_TYPE_A,
                                           DNS_CLASS_IN, "8.8.8.8", NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_HIT);

  /* Lookup AAAA should MISS (type-specific) */
  result = SocketDNSServfailCache_lookup (cache, "example.com", DNS_TYPE_AAAA,
                                           DNS_CLASS_IN, "8.8.8.8", NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_MISS);

  /* Lookup MX should also MISS */
  result = SocketDNSServfailCache_lookup (cache, "example.com", DNS_TYPE_MX,
                                           DNS_CLASS_IN, "8.8.8.8", NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_MISS);

  SocketDNSServfailCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test case-insensitive name lookup */
TEST (servfailcache_case_insensitive)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);

  /* Insert with lowercase */
  SocketDNSServfailCache_insert (cache, "test.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 300);

  /* Lookup with different cases should all hit */
  SocketDNS_ServfailCacheResult result;

  result = SocketDNSServfailCache_lookup (cache, "TEST.EXAMPLE.COM", DNS_TYPE_A,
                                           DNS_CLASS_IN, "8.8.8.8", NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_HIT);

  result = SocketDNSServfailCache_lookup (cache, "Test.Example.Com", DNS_TYPE_A,
                                           DNS_CLASS_IN, "8.8.8.8", NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_HIT);

  result = SocketDNSServfailCache_lookup (cache, "tEsT.eXaMpLe.CoM", DNS_TYPE_A,
                                           DNS_CLASS_IN, "8.8.8.8", NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_HIT);

  SocketDNSServfailCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test RFC 2308 Section 7.1: 5-minute max TTL */
TEST (servfailcache_max_ttl_5min)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);

  /* Insert with TTL higher than 5 minutes - should be capped */
  SocketDNSServfailCache_insert (cache, "clamped.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 3600);

  /* Lookup and verify TTL was capped at 300 seconds */
  SocketDNS_ServfailCacheEntry entry;
  SocketDNSServfailCache_lookup (cache, "clamped.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", &entry);
  ASSERT (entry.original_ttl <= DNS_SERVFAIL_MAX_TTL);
  ASSERT_EQ (entry.original_ttl, 300);

  /* Insert with TTL less than 5 minutes - should be kept as-is */
  SocketDNSServfailCache_insert (cache, "short.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 60);

  SocketDNSServfailCache_lookup (cache, "short.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", &entry);
  ASSERT_EQ (entry.original_ttl, 60);

  SocketDNSServfailCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test TTL expiration */
TEST (servfailcache_ttl_expiration)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);

  /* Insert with 1 second TTL */
  SocketDNSServfailCache_insert (cache, "expiring.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 1);

  /* Should hit immediately */
  SocketDNS_ServfailCacheResult result;
  result = SocketDNSServfailCache_lookup (cache, "expiring.example.com",
                                           DNS_TYPE_A, DNS_CLASS_IN, "8.8.8.8",
                                           NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_HIT);

  /* Wait for TTL to expire */
  sleep (2);

  /* Should now miss due to expiration */
  result = SocketDNSServfailCache_lookup (cache, "expiring.example.com",
                                           DNS_TYPE_A, DNS_CLASS_IN, "8.8.8.8",
                                           NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_MISS);

  SocketDNS_ServfailCacheStats stats;
  SocketDNSServfailCache_stats (cache, &stats);
  ASSERT (stats.expirations > 0);

  SocketDNSServfailCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test LRU eviction when cache is full */
TEST (servfailcache_lru_eviction)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);

  /* Set very small cache size */
  SocketDNSServfailCache_set_max_entries (cache, 3);

  /* Insert 3 entries */
  SocketDNSServfailCache_insert (cache, "first.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 300);
  SocketDNSServfailCache_insert (cache, "second.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 300);
  SocketDNSServfailCache_insert (cache, "third.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 300);

  SocketDNS_ServfailCacheStats stats;
  SocketDNSServfailCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 3);

  /* Access first entry to make it recently used */
  SocketDNSServfailCache_lookup (cache, "first.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", NULL);

  /* Insert 4th entry - should evict LRU (second) */
  SocketDNSServfailCache_insert (cache, "fourth.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 300);

  SocketDNSServfailCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 3);
  ASSERT (stats.evictions > 0);

  /* First should still be present (was accessed) */
  SocketDNS_ServfailCacheResult result;
  result = SocketDNSServfailCache_lookup (cache, "first.example.com",
                                           DNS_TYPE_A, DNS_CLASS_IN, "8.8.8.8",
                                           NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_HIT);

  /* Second should have been evicted */
  result = SocketDNSServfailCache_lookup (cache, "second.example.com",
                                           DNS_TYPE_A, DNS_CLASS_IN, "8.8.8.8",
                                           NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_MISS);

  SocketDNSServfailCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test remove specific entry */
TEST (servfailcache_remove)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);

  /* Insert two entries */
  SocketDNSServfailCache_insert (cache, "remove.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 300);
  SocketDNSServfailCache_insert (cache, "keep.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 300);

  SocketDNS_ServfailCacheStats stats;
  SocketDNSServfailCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 2);

  /* Remove one entry */
  int removed = SocketDNSServfailCache_remove (cache, "remove.example.com",
                                                DNS_TYPE_A, DNS_CLASS_IN,
                                                "8.8.8.8");
  ASSERT_EQ (removed, 1);

  SocketDNSServfailCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 1);

  /* Removed entry should miss */
  SocketDNS_ServfailCacheResult result;
  result = SocketDNSServfailCache_lookup (cache, "remove.example.com",
                                           DNS_TYPE_A, DNS_CLASS_IN, "8.8.8.8",
                                           NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_MISS);

  /* Other entry should still hit */
  result = SocketDNSServfailCache_lookup (cache, "keep.example.com", DNS_TYPE_A,
                                           DNS_CLASS_IN, "8.8.8.8", NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_HIT);

  SocketDNSServfailCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test remove all entries for a nameserver */
TEST (servfailcache_remove_nameserver)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);

  /* Insert entries for two different nameservers */
  SocketDNSServfailCache_insert (cache, "a.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 300);
  SocketDNSServfailCache_insert (cache, "b.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 300);
  SocketDNSServfailCache_insert (cache, "c.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.4.4", 300);

  SocketDNS_ServfailCacheStats stats;
  SocketDNSServfailCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 3);

  /* Remove all entries for 8.8.8.8 */
  int removed = SocketDNSServfailCache_remove_nameserver (cache, "8.8.8.8");
  ASSERT_EQ (removed, 2);

  SocketDNSServfailCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 1);

  /* 8.8.8.8 entries should miss */
  SocketDNS_ServfailCacheResult result;
  result = SocketDNSServfailCache_lookup (cache, "a.example.com", DNS_TYPE_A,
                                           DNS_CLASS_IN, "8.8.8.8", NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_MISS);

  /* 8.8.4.4 entry should still hit */
  result = SocketDNSServfailCache_lookup (cache, "c.example.com", DNS_TYPE_A,
                                           DNS_CLASS_IN, "8.8.4.4", NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_HIT);

  SocketDNSServfailCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test cache clear */
TEST (servfailcache_clear)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);

  /* Insert several entries */
  SocketDNSServfailCache_insert (cache, "a.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 300);
  SocketDNSServfailCache_insert (cache, "b.example.com", DNS_TYPE_AAAA,
                                  DNS_CLASS_IN, "8.8.8.8", 300);
  SocketDNSServfailCache_insert (cache, "c.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.4.4", 300);

  SocketDNS_ServfailCacheStats stats;
  SocketDNSServfailCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 3);

  /* Clear cache */
  SocketDNSServfailCache_clear (cache);

  SocketDNSServfailCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 0);

  /* All lookups should miss */
  SocketDNS_ServfailCacheResult result;
  result = SocketDNSServfailCache_lookup (cache, "a.example.com", DNS_TYPE_A,
                                           DNS_CLASS_IN, "8.8.8.8", NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_MISS);

  SocketDNSServfailCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test statistics accuracy */
TEST (servfailcache_stats_accuracy)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);

  SocketDNS_ServfailCacheStats stats;
  SocketDNSServfailCache_stats (cache, &stats);

  /* Initial stats should be zero */
  ASSERT_EQ (stats.hits, 0);
  ASSERT_EQ (stats.misses, 0);
  ASSERT_EQ (stats.insertions, 0);

  /* Insert and lookup */
  SocketDNSServfailCache_insert (cache, "stat.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 300);

  SocketDNSServfailCache_lookup (cache, "stat.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", NULL);
  SocketDNSServfailCache_lookup (cache, "stat.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", NULL);
  SocketDNSServfailCache_lookup (cache, "miss.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", NULL);

  SocketDNSServfailCache_stats (cache, &stats);

  ASSERT_EQ (stats.insertions, 1);
  ASSERT_EQ (stats.hits, 2);
  ASSERT_EQ (stats.misses, 1);

  /* Verify hit rate calculation */
  double expected_hit_rate = 2.0 / 3.0; /* 2 hits out of 3 lookups */
  ASSERT (stats.hit_rate > 0.6);
  ASSERT (stats.hit_rate < 0.7);

  SocketDNSServfailCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test result name function */
TEST (servfailcache_result_name)
{
  const char *result_name;

  result_name = SocketDNSServfailCache_result_name (DNS_SERVFAIL_MISS);
  ASSERT (strcmp (result_name, "MISS") == 0);

  result_name = SocketDNSServfailCache_result_name (DNS_SERVFAIL_HIT);
  ASSERT (strcmp (result_name, "HIT") == 0);
}

/* Test name and nameserver length limits */
TEST (servfailcache_length_limits)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);

  /* Create a name at the max length (255 characters) */
  char long_name[256];
  memset (long_name, 'a', 255);
  long_name[255] = '\0';

  /* Should succeed */
  int ret = SocketDNSServfailCache_insert (cache, long_name, DNS_TYPE_A,
                                            DNS_CLASS_IN, "8.8.8.8", 300);
  ASSERT_EQ (ret, 0);

  /* Lookup should work */
  SocketDNS_ServfailCacheResult result;
  result = SocketDNSServfailCache_lookup (cache, long_name, DNS_TYPE_A,
                                           DNS_CLASS_IN, "8.8.8.8", NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_HIT);

  /* Create a name exceeding max length (256 characters) */
  char too_long_name[257];
  memset (too_long_name, 'b', 256);
  too_long_name[256] = '\0';

  /* Should fail */
  ret = SocketDNSServfailCache_insert (cache, too_long_name, DNS_TYPE_A,
                                        DNS_CLASS_IN, "8.8.8.8", 300);
  ASSERT_EQ (ret, -1);

  /* Create a nameserver at max length (64 characters) */
  char long_ns[65];
  memset (long_ns, '1', 64);
  long_ns[64] = '\0';

  ret = SocketDNSServfailCache_insert (cache, "test.example.com", DNS_TYPE_A,
                                        DNS_CLASS_IN, long_ns, 300);
  ASSERT_EQ (ret, 0);

  /* Create a nameserver exceeding max length (65 characters) */
  char too_long_ns[66];
  memset (too_long_ns, '2', 65);
  too_long_ns[65] = '\0';

  ret = SocketDNSServfailCache_insert (cache, "test2.example.com", DNS_TYPE_A,
                                        DNS_CLASS_IN, too_long_ns, 300);
  ASSERT_EQ (ret, -1);

  SocketDNSServfailCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test cache disabled (max_entries = 0) */
TEST (servfailcache_disabled)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);

  /* Disable cache */
  SocketDNSServfailCache_set_max_entries (cache, 0);

  /* Insertions should fail */
  int ret = SocketDNSServfailCache_insert (cache, "disabled.example.com",
                                            DNS_TYPE_A, DNS_CLASS_IN, "8.8.8.8",
                                            300);
  ASSERT_EQ (ret, -1);

  SocketDNS_ServfailCacheStats stats;
  SocketDNSServfailCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 0);
  ASSERT_EQ (stats.insertions, 0);

  SocketDNSServfailCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test NULL entry pointer in lookup */
TEST (servfailcache_null_entry)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);

  SocketDNSServfailCache_insert (cache, "null.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 300);

  /* Lookup with NULL entry should still work */
  SocketDNS_ServfailCacheResult result;
  result = SocketDNSServfailCache_lookup (cache, "null.example.com", DNS_TYPE_A,
                                           DNS_CLASS_IN, "8.8.8.8", NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_HIT);

  SocketDNSServfailCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test update existing entry */
TEST (servfailcache_update_existing)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);

  /* Insert entry with short TTL */
  SocketDNSServfailCache_insert (cache, "update.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 60);

  SocketDNS_ServfailCacheEntry entry;
  SocketDNSServfailCache_lookup (cache, "update.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", &entry);
  ASSERT_EQ (entry.original_ttl, 60);

  /* Update with longer TTL (capped at 300) */
  SocketDNSServfailCache_insert (cache, "update.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", 300);

  SocketDNSServfailCache_lookup (cache, "update.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "8.8.8.8", &entry);
  ASSERT_EQ (entry.original_ttl, 300);

  /* Size should still be 1 */
  SocketDNS_ServfailCacheStats stats;
  SocketDNSServfailCache_stats (cache, &stats);
  ASSERT_EQ (stats.current_size, 1);

  SocketDNSServfailCache_free (&cache);
  Arena_dispose (&arena);
}

/* Test IPv6 nameserver addresses */
TEST (servfailcache_ipv6_nameserver)
{
  Arena_T arena = Arena_new ();
  SocketDNSServfailCache_T cache = SocketDNSServfailCache_new (arena);

  /* Insert with IPv6 nameserver */
  SocketDNSServfailCache_insert (cache, "ipv6.example.com", DNS_TYPE_A,
                                  DNS_CLASS_IN, "2001:4860:4860::8888", 300);

  /* Lookup should hit */
  SocketDNS_ServfailCacheResult result;
  result = SocketDNSServfailCache_lookup (cache, "ipv6.example.com", DNS_TYPE_A,
                                           DNS_CLASS_IN, "2001:4860:4860::8888",
                                           NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_HIT);

  /* Different IPv6 should miss */
  result = SocketDNSServfailCache_lookup (cache, "ipv6.example.com", DNS_TYPE_A,
                                           DNS_CLASS_IN, "2001:4860:4860::8844",
                                           NULL);
  ASSERT_EQ (result, DNS_SERVFAIL_MISS);

  SocketDNSServfailCache_free (&cache);
  Arena_dispose (&arena);
}

/* Main function - run all tests */
int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
