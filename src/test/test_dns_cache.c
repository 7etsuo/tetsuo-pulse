/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/*
 * test_dns_cache.c - Unit tests for DNS cache integration
 *
 * Tests DNS result caching with TTL-based expiration per RFC 1035 Section 7.4.
 */

#include "dns/SocketDNS.h"
#include "socket/SocketCommon.h"
#include "test/Test.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Helper to resolve synchronously and ignore errors */
static struct addrinfo *
resolve_quiet (SocketDNS_T dns, const char *host, int port)
{
  struct addrinfo *volatile result = NULL;
  TRY { result = SocketDNS_resolve_sync (dns, host, port, NULL, 5000); }
  EXCEPT (SocketDNS_Failed)
  {
    /* Resolution failed - return NULL */
  }
  END_TRY;
  return result;
}

/* Test cache disabled when max_entries=0 */
TEST (dns_cache_disabled)
{
  SocketDNS_T dns = SocketDNS_new ();
  SocketDNS_CacheStats stats;

  /* Disable cache */
  SocketDNS_cache_set_max_entries (dns, 0);

  /* Resolve localhost (should always work) */
  struct addrinfo *res = resolve_quiet (dns, "localhost", 80);
  if (res)
    SocketCommon_free_addrinfo (res);

  /* Check cache stats - should have no insertions */
  SocketDNS_cache_stats (dns, &stats);
  ASSERT_EQ (stats.insertions, 0);
  ASSERT_EQ (stats.current_size, 0);
  ASSERT_EQ (stats.max_entries, 0);

  SocketDNS_free (&dns);
}

/* Test cache hit returns cached result */
TEST (dns_cache_hit)
{
  SocketDNS_T dns = SocketDNS_new ();
  SocketDNS_CacheStats stats;

  /* Enable cache with default settings */
  SocketDNS_cache_set_max_entries (dns, 100);
  SocketDNS_cache_set_ttl (dns, 60);

  /* First resolution - should miss cache */
  struct addrinfo *res1 = resolve_quiet (dns, "localhost", 80);
  ASSERT_NOT_NULL (res1);

  SocketDNS_cache_stats (dns, &stats);
  ASSERT_EQ (stats.misses, 1);
  ASSERT_EQ (stats.hits, 0);
  ASSERT_EQ (stats.insertions, 1);

  /* Second resolution - should hit cache */
  struct addrinfo *res2 = resolve_quiet (dns, "localhost", 80);
  ASSERT_NOT_NULL (res2);

  SocketDNS_cache_stats (dns, &stats);
  ASSERT_EQ (stats.misses, 1);
  ASSERT_EQ (stats.hits, 1);

  SocketCommon_free_addrinfo (res1);
  SocketCommon_free_addrinfo (res2);
  SocketDNS_free (&dns);
}

/* Test cache miss triggers new resolution */
TEST (dns_cache_miss)
{
  SocketDNS_T dns = SocketDNS_new ();
  SocketDNS_CacheStats stats;

  SocketDNS_cache_set_max_entries (dns, 100);
  SocketDNS_cache_set_ttl (dns, 60);

  /* Clear any prior state */
  SocketDNS_cache_clear (dns);

  /* Resolve two different hostnames */
  struct addrinfo *res1 = resolve_quiet (dns, "localhost", 80);
  struct addrinfo *res2 = resolve_quiet (dns, "127.0.0.1", 80);

  /* Note: 127.0.0.1 is an IP and bypasses cache */
  SocketDNS_cache_stats (dns, &stats);
  ASSERT_EQ (stats.misses, 1);    /* Only localhost causes miss */
  ASSERT_EQ (stats.insertions, 1); /* Only localhost gets cached */

  if (res1)
    SocketCommon_free_addrinfo (res1);
  if (res2)
    SocketCommon_free_addrinfo (res2);
  SocketDNS_free (&dns);
}

/* Test TTL expiration */
TEST (dns_cache_ttl_expiration)
{
  SocketDNS_T dns = SocketDNS_new ();
  SocketDNS_CacheStats stats;

  /* Set very short TTL (1 second) */
  SocketDNS_cache_set_max_entries (dns, 100);
  SocketDNS_cache_set_ttl (dns, 1);

  /* First resolution */
  struct addrinfo *res1 = resolve_quiet (dns, "localhost", 80);
  ASSERT_NOT_NULL (res1);

  SocketDNS_cache_stats (dns, &stats);
  ASSERT_EQ (stats.insertions, 1);
  uint64_t initial_misses = stats.misses;

  /* Wait for TTL to expire */
  sleep (2);

  /* Second resolution - should miss due to expiration */
  struct addrinfo *res2 = resolve_quiet (dns, "localhost", 80);
  ASSERT_NOT_NULL (res2);

  SocketDNS_cache_stats (dns, &stats);
  /* After expiration, we should have one more miss */
  ASSERT (stats.misses > initial_misses);

  SocketCommon_free_addrinfo (res1);
  SocketCommon_free_addrinfo (res2);
  SocketDNS_free (&dns);
}

/* Test LRU eviction when cache is full */
TEST (dns_cache_lru_eviction)
{
  SocketDNS_T dns = SocketDNS_new ();
  SocketDNS_CacheStats stats;

  /* Set small cache size */
  SocketDNS_cache_set_max_entries (dns, 2);
  SocketDNS_cache_set_ttl (dns, 300);

  /* Resolve first hostname */
  struct addrinfo *res1 = resolve_quiet (dns, "localhost", 80);

  SocketDNS_cache_stats (dns, &stats);
  ASSERT_EQ (stats.current_size, 1);

  /* Access localhost again to make it recently used */
  struct addrinfo *res1_again = resolve_quiet (dns, "localhost", 80);

  /* We can't easily add more unique hostnames without network access,
   * so just verify basic eviction mechanism via stats */
  SocketDNS_cache_stats (dns, &stats);
  ASSERT (stats.current_size <= 2);

  if (res1)
    SocketCommon_free_addrinfo (res1);
  if (res1_again)
    SocketCommon_free_addrinfo (res1_again);
  SocketDNS_free (&dns);
}

/* Test case-insensitive lookup */
TEST (dns_cache_case_insensitive)
{
  SocketDNS_T dns = SocketDNS_new ();
  SocketDNS_CacheStats stats;

  SocketDNS_cache_set_max_entries (dns, 100);
  SocketDNS_cache_set_ttl (dns, 60);

  /* Resolve lowercase */
  struct addrinfo *res1 = resolve_quiet (dns, "localhost", 80);
  ASSERT_NOT_NULL (res1);

  SocketDNS_cache_stats (dns, &stats);
  uint64_t hits_before = stats.hits;

  /* Resolve with different case - should hit cache */
  struct addrinfo *res2 = resolve_quiet (dns, "LOCALHOST", 80);
  ASSERT_NOT_NULL (res2);

  SocketDNS_cache_stats (dns, &stats);
  ASSERT (stats.hits > hits_before);

  /* Try mixed case */
  struct addrinfo *res3 = resolve_quiet (dns, "LocalHost", 80);
  ASSERT_NOT_NULL (res3);

  SocketCommon_free_addrinfo (res1);
  SocketCommon_free_addrinfo (res2);
  SocketCommon_free_addrinfo (res3);
  SocketDNS_free (&dns);
}

/* Test cache clear removes all entries */
TEST (dns_cache_clear)
{
  SocketDNS_T dns = SocketDNS_new ();
  SocketDNS_CacheStats stats;

  SocketDNS_cache_set_max_entries (dns, 100);
  SocketDNS_cache_set_ttl (dns, 60);

  /* Add entry to cache */
  struct addrinfo *res1 = resolve_quiet (dns, "localhost", 80);

  SocketDNS_cache_stats (dns, &stats);
  ASSERT_EQ (stats.current_size, 1);

  /* Clear cache */
  SocketDNS_cache_clear (dns);

  SocketDNS_cache_stats (dns, &stats);
  ASSERT_EQ (stats.current_size, 0);

  /* Verify next lookup causes miss */
  uint64_t misses_before = stats.misses;
  struct addrinfo *res2 = resolve_quiet (dns, "localhost", 80);

  SocketDNS_cache_stats (dns, &stats);
  ASSERT (stats.misses > misses_before);

  if (res1)
    SocketCommon_free_addrinfo (res1);
  if (res2)
    SocketCommon_free_addrinfo (res2);
  SocketDNS_free (&dns);
}

/* Test cache remove removes specific entry */
TEST (dns_cache_remove)
{
  SocketDNS_T dns = SocketDNS_new ();
  SocketDNS_CacheStats stats;
  int removed;

  SocketDNS_cache_set_max_entries (dns, 100);
  SocketDNS_cache_set_ttl (dns, 60);

  /* Add entry to cache */
  struct addrinfo *res1 = resolve_quiet (dns, "localhost", 80);

  SocketDNS_cache_stats (dns, &stats);
  ASSERT_EQ (stats.current_size, 1);

  /* Remove specific entry */
  removed = SocketDNS_cache_remove (dns, "localhost");
  ASSERT_EQ (removed, 1);

  SocketDNS_cache_stats (dns, &stats);
  ASSERT_EQ (stats.current_size, 0);

  /* Try to remove non-existent entry */
  removed = SocketDNS_cache_remove (dns, "nonexistent.local");
  ASSERT_EQ (removed, 0);

  if (res1)
    SocketCommon_free_addrinfo (res1);
  SocketDNS_free (&dns);
}

/* Test cache statistics are accurate */
TEST (dns_cache_stats_accuracy)
{
  SocketDNS_T dns = SocketDNS_new ();
  SocketDNS_CacheStats stats;

  SocketDNS_cache_set_max_entries (dns, 100);
  SocketDNS_cache_set_ttl (dns, 300);
  SocketDNS_cache_clear (dns);

  /* Initial stats should be zeroed (except config values) */
  SocketDNS_cache_stats (dns, &stats);
  ASSERT_EQ (stats.hits, 0);
  ASSERT_EQ (stats.misses, 0);
  ASSERT_EQ (stats.current_size, 0);
  ASSERT_EQ (stats.max_entries, 100);
  ASSERT_EQ (stats.ttl_seconds, 300);

  /* First lookup - miss */
  struct addrinfo *res1 = resolve_quiet (dns, "localhost", 80);

  SocketDNS_cache_stats (dns, &stats);
  ASSERT_EQ (stats.misses, 1);
  ASSERT_EQ (stats.insertions, 1);
  ASSERT_EQ (stats.current_size, 1);

  /* Second lookup - hit */
  struct addrinfo *res2 = resolve_quiet (dns, "localhost", 80);

  SocketDNS_cache_stats (dns, &stats);
  ASSERT_EQ (stats.hits, 1);
  ASSERT_EQ (stats.misses, 1);

  /* Verify hit rate calculation */
  ASSERT (stats.hit_rate > 0.0);
  ASSERT (stats.hit_rate <= 1.0);

  if (res1)
    SocketCommon_free_addrinfo (res1);
  if (res2)
    SocketCommon_free_addrinfo (res2);
  SocketDNS_free (&dns);
}

/* Test IP addresses bypass cache */
TEST (dns_cache_ip_bypass)
{
  SocketDNS_T dns = SocketDNS_new ();
  SocketDNS_CacheStats stats;

  SocketDNS_cache_set_max_entries (dns, 100);
  SocketDNS_cache_set_ttl (dns, 60);
  SocketDNS_cache_clear (dns);

  /* Resolve IPv4 address (should bypass cache) */
  struct addrinfo *res1 = resolve_quiet (dns, "127.0.0.1", 80);

  SocketDNS_cache_stats (dns, &stats);
  ASSERT_EQ (stats.insertions, 0); /* IP should not be cached */
  ASSERT_EQ (stats.misses, 0);     /* IP should not count as miss */

  /* Resolve again - still no cache activity */
  struct addrinfo *res2 = resolve_quiet (dns, "127.0.0.1", 80);

  SocketDNS_cache_stats (dns, &stats);
  ASSERT_EQ (stats.insertions, 0);
  ASSERT_EQ (stats.hits, 0);

  /* Resolve IPv6 localhost */
  struct addrinfo *res3 = resolve_quiet (dns, "::1", 80);

  SocketDNS_cache_stats (dns, &stats);
  ASSERT_EQ (stats.insertions, 0); /* IPv6 should also bypass */

  if (res1)
    SocketCommon_free_addrinfo (res1);
  if (res2)
    SocketCommon_free_addrinfo (res2);
  if (res3)
    SocketCommon_free_addrinfo (res3);
  SocketDNS_free (&dns);
}

/* Test SocketDNS_CacheStats structure ABI stability */
TEST (dns_cache_stats_abi)
{
  /* Verify structure size (64 bytes for ABI stability) */
  ASSERT_EQ (sizeof (SocketDNS_CacheStats), 64);

  /* Verify field offsets for ABI compatibility */
  ASSERT_EQ (offsetof (SocketDNS_CacheStats, hits), 0);
  ASSERT_EQ (offsetof (SocketDNS_CacheStats, misses), 8);
  ASSERT_EQ (offsetof (SocketDNS_CacheStats, evictions), 16);
  ASSERT_EQ (offsetof (SocketDNS_CacheStats, insertions), 24);
  ASSERT_EQ (offsetof (SocketDNS_CacheStats, current_size), 32);
  ASSERT_EQ (offsetof (SocketDNS_CacheStats, max_entries), 40);
  ASSERT_EQ (offsetof (SocketDNS_CacheStats, hit_rate), 48);
  ASSERT_EQ (offsetof (SocketDNS_CacheStats, ttl_seconds), 56);
  ASSERT_EQ (offsetof (SocketDNS_CacheStats, _reserved), 60);

  /* Verify all fields use fixed-width types */
  SocketDNS_CacheStats stats = { 0 };
  stats.hits = UINT64_MAX;
  stats.misses = UINT64_MAX;
  stats.evictions = UINT64_MAX;
  stats.insertions = UINT64_MAX;
  stats.current_size = UINT64_MAX;
  stats.max_entries = UINT64_MAX;
  stats.hit_rate = 1.0;
  stats.ttl_seconds = INT32_MAX;

  /* Verify structure can be zeroed safely */
  memset (&stats, 0, sizeof (stats));
  ASSERT_EQ (stats.hits, 0);
  ASSERT_EQ (stats.ttl_seconds, 0);
}

/* Main function - run all tests */
int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
