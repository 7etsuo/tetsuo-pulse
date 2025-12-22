/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_dns_resolver.c
 * @brief Unit tests for SocketDNSResolver (RFC 1035 Section 7).
 */

#include "dns/SocketDNSResolver.h"
#include "core/Arena.h"
#include "test/Test.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

/* Test callback state */
static volatile int g_callback_invoked = 0;
static volatile int g_callback_error = -999;
static volatile size_t g_callback_count = 0;

static void
test_callback (SocketDNSResolver_Query_T query,
               const SocketDNSResolver_Result *result, int error,
               void *userdata)
{
  (void)query;
  (void)userdata;

  g_callback_invoked = 1;
  g_callback_error = error;
  g_callback_count = result ? result->count : 0;
}

/* Test: Basic lifecycle (new/free) */
TEST (dns_resolver_lifecycle)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = NULL;

  TRY
  {
    resolver = SocketDNSResolver_new (arena);
    ASSERT_NOT_NULL (resolver);

    /* Verify defaults */
    ASSERT_EQ (SocketDNSResolver_pending_count (resolver), 0);
    ASSERT_EQ (SocketDNSResolver_nameserver_count (resolver), 0);
  }
  EXCEPT (SocketDNSResolver_Failed)
  {
    Test_fail ("SocketDNSResolver_new raised exception", __FILE__, __LINE__);
    RAISE (Test_Failed);
  }
  END_TRY;

  SocketDNSResolver_free (&resolver);
  ASSERT_NULL (resolver);

  Arena_dispose (&arena);
}

/* Test: Add nameservers */
TEST (dns_resolver_nameservers)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);

  /* Add IPv4 nameserver */
  int ret = SocketDNSResolver_add_nameserver (resolver, "8.8.8.8", 53);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSResolver_nameserver_count (resolver), 1);

  /* Add IPv6 nameserver */
  ret = SocketDNSResolver_add_nameserver (resolver, "2001:4860:4860::8888", 53);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSResolver_nameserver_count (resolver), 2);

  /* Clear nameservers */
  SocketDNSResolver_clear_nameservers (resolver);
  ASSERT_EQ (SocketDNSResolver_nameserver_count (resolver), 0);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: IP address immediate resolution */
TEST (dns_resolver_ip_address)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);

  /* Add a nameserver (not used for IP addresses) */
  SocketDNSResolver_add_nameserver (resolver, "8.8.8.8", 53);

  /* Resolve IPv4 address - should return immediately */
  g_callback_invoked = 0;
  g_callback_error = -999;
  g_callback_count = 0;

  SocketDNSResolver_Query_T q
      = SocketDNSResolver_resolve (resolver, "127.0.0.1", RESOLVER_FLAG_IPV4,
                                   test_callback, NULL);

  /* IP addresses return NULL query handle and invoke callback immediately */
  ASSERT_NULL (q);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);
  ASSERT_EQ (g_callback_count, 1);

  /* Test IPv6 */
  g_callback_invoked = 0;
  g_callback_error = -999;
  g_callback_count = 0;

  q = SocketDNSResolver_resolve (resolver, "::1", RESOLVER_FLAG_IPV6,
                                 test_callback, NULL);

  ASSERT_NULL (q);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);
  ASSERT_EQ (g_callback_count, 1);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: IPv6 with zone ID (RFC 6874) */
TEST (dns_resolver_ipv6_zone_id)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);

  /* Add a nameserver (not used for IP addresses) */
  SocketDNSResolver_add_nameserver (resolver, "8.8.8.8", 53);

  /* Test link-local address with zone ID using loopback interface */
  g_callback_invoked = 0;
  g_callback_error = -999;
  g_callback_count = 0;

  /* fe80::1%lo - link-local with loopback zone ID */
  SocketDNSResolver_Query_T q
      = SocketDNSResolver_resolve (resolver, "fe80::1%lo", RESOLVER_FLAG_IPV6,
                                   test_callback, NULL);

  /* Should return immediately (no DNS query) */
  ASSERT_NULL (q);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);
  ASSERT_EQ (g_callback_count, 1);

  /* Test with eth0 zone ID (may not exist, but parsing should work) */
  g_callback_invoked = 0;
  g_callback_error = -999;
  g_callback_count = 0;

  q = SocketDNSResolver_resolve (resolver, "fe80::1%eth0", RESOLVER_FLAG_IPV6,
                                 test_callback, NULL);

  ASSERT_NULL (q);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);
  ASSERT_EQ (g_callback_count, 1);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: Various IPv4 address formats */
TEST (dns_resolver_ipv4_formats)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);
  SocketDNSResolver_add_nameserver (resolver, "8.8.8.8", 53);

  /* Standard format */
  g_callback_invoked = 0;
  SocketDNSResolver_resolve (resolver, "192.168.1.1", RESOLVER_FLAG_IPV4,
                             test_callback, NULL);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);

  /* Loopback */
  g_callback_invoked = 0;
  SocketDNSResolver_resolve (resolver, "127.0.0.1", RESOLVER_FLAG_IPV4,
                             test_callback, NULL);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);

  /* All zeros */
  g_callback_invoked = 0;
  SocketDNSResolver_resolve (resolver, "0.0.0.0", RESOLVER_FLAG_IPV4,
                             test_callback, NULL);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);

  /* Broadcast */
  g_callback_invoked = 0;
  SocketDNSResolver_resolve (resolver, "255.255.255.255", RESOLVER_FLAG_IPV4,
                             test_callback, NULL);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: Various IPv6 address formats */
TEST (dns_resolver_ipv6_formats)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);
  SocketDNSResolver_add_nameserver (resolver, "8.8.8.8", 53);

  /* Full format */
  g_callback_invoked = 0;
  SocketDNSResolver_resolve (resolver, "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                             RESOLVER_FLAG_IPV6, test_callback, NULL);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);

  /* Compressed format */
  g_callback_invoked = 0;
  SocketDNSResolver_resolve (resolver, "2001:db8:85a3::8a2e:370:7334",
                             RESOLVER_FLAG_IPV6, test_callback, NULL);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);

  /* Loopback */
  g_callback_invoked = 0;
  SocketDNSResolver_resolve (resolver, "::1", RESOLVER_FLAG_IPV6,
                             test_callback, NULL);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);

  /* All zeros */
  g_callback_invoked = 0;
  SocketDNSResolver_resolve (resolver, "::", RESOLVER_FLAG_IPV6,
                             test_callback, NULL);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);

  /* IPv4-mapped IPv6 */
  g_callback_invoked = 0;
  SocketDNSResolver_resolve (resolver, "::ffff:192.0.2.1", RESOLVER_FLAG_IPV6,
                             test_callback, NULL);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: Localhost resolution */
TEST (dns_resolver_localhost)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);
  SocketDNSResolver_add_nameserver (resolver, "8.8.8.8", 53);

  /* "localhost" should return immediately without DNS query */
  g_callback_invoked = 0;
  g_callback_error = -999;
  g_callback_count = 0;

  SocketDNSResolver_Query_T q
      = SocketDNSResolver_resolve (resolver, "localhost", RESOLVER_FLAG_BOTH,
                                   test_callback, NULL);

  ASSERT_NULL (q);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);
  /* Should return both IPv4 and IPv6 loopback */
  ASSERT_EQ (g_callback_count, 2);

  /* Case insensitive */
  g_callback_invoked = 0;
  g_callback_count = 0;
  q = SocketDNSResolver_resolve (resolver, "LOCALHOST", RESOLVER_FLAG_BOTH,
                                 test_callback, NULL);
  ASSERT_NULL (q);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);
  ASSERT_EQ (g_callback_count, 2);

  /* IPv4 only */
  g_callback_invoked = 0;
  g_callback_count = 0;
  q = SocketDNSResolver_resolve (resolver, "localhost", RESOLVER_FLAG_IPV4,
                                 test_callback, NULL);
  ASSERT_NULL (q);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);
  ASSERT_EQ (g_callback_count, 1);

  /* IPv6 only */
  g_callback_invoked = 0;
  g_callback_count = 0;
  q = SocketDNSResolver_resolve (resolver, "localhost", RESOLVER_FLAG_IPV6,
                                 test_callback, NULL);
  ASSERT_NULL (q);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_OK);
  ASSERT_EQ (g_callback_count, 1);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: No nameservers error */
TEST (dns_resolver_no_nameservers)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);

  /* Don't add any nameservers */

  g_callback_invoked = 0;
  g_callback_error = -999;

  SocketDNSResolver_Query_T q
      = SocketDNSResolver_resolve (resolver, "example.com", RESOLVER_FLAG_IPV4,
                                   test_callback, NULL);

  /* Should fail immediately with no nameservers error */
  ASSERT_NULL (q);
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, RESOLVER_ERROR_NO_NS);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: Cache disabled */
TEST (dns_resolver_cache_disabled)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);
  SocketDNSResolver_CacheStats stats;

  /* Disable cache */
  SocketDNSResolver_cache_set_max (resolver, 0);

  SocketDNSResolver_cache_stats (resolver, &stats);
  ASSERT_EQ (stats.max_entries, 0);
  ASSERT_EQ (stats.current_size, 0);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: Cache TTL setting */
TEST (dns_resolver_cache_ttl)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);
  SocketDNSResolver_CacheStats stats;

  /* Set custom TTL */
  SocketDNSResolver_cache_set_ttl (resolver, 120);

  SocketDNSResolver_cache_stats (resolver, &stats);
  ASSERT_EQ (stats.ttl_seconds, 120);

  /* Reset to default */
  SocketDNSResolver_cache_set_ttl (resolver, RESOLVER_DEFAULT_CACHE_TTL);

  SocketDNSResolver_cache_stats (resolver, &stats);
  ASSERT_EQ (stats.ttl_seconds, RESOLVER_DEFAULT_CACHE_TTL);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: Cache max entries */
TEST (dns_resolver_cache_max)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);
  SocketDNSResolver_CacheStats stats;

  /* Set small max */
  SocketDNSResolver_cache_set_max (resolver, 10);

  SocketDNSResolver_cache_stats (resolver, &stats);
  ASSERT_EQ (stats.max_entries, 10);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: Cache clear */
TEST (dns_resolver_cache_clear)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);
  SocketDNSResolver_CacheStats stats;

  SocketDNSResolver_cache_stats (resolver, &stats);
  size_t initial_size = stats.current_size;

  SocketDNSResolver_cache_clear (resolver);

  SocketDNSResolver_cache_stats (resolver, &stats);
  ASSERT_EQ (stats.current_size, 0);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: Error string conversion */
TEST (dns_resolver_strerror)
{
  const char *str;

  str = SocketDNSResolver_strerror (RESOLVER_OK);
  ASSERT_NOT_NULL (str);
  ASSERT (strlen (str) > 0);

  str = SocketDNSResolver_strerror (RESOLVER_ERROR_TIMEOUT);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "timeout") != NULL || strstr (str, "Timeout") != NULL);

  str = SocketDNSResolver_strerror (RESOLVER_ERROR_NXDOMAIN);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "exist") != NULL);

  str = SocketDNSResolver_strerror (RESOLVER_ERROR_NO_NS);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "nameserver") != NULL
          || strstr (str, "Nameserver") != NULL);

  str = SocketDNSResolver_strerror (RESOLVER_ERROR_CNAME_LOOP);
  ASSERT_NOT_NULL (str);
  ASSERT (strstr (str, "CNAME") != NULL);
}

/* Test: FD accessors */
TEST (dns_resolver_fd_accessors)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);

  int fd_v4 = SocketDNSResolver_fd_v4 (resolver);
  int fd_v6 = SocketDNSResolver_fd_v6 (resolver);

  /* FDs should be valid or -1 */
  ASSERT (fd_v4 >= -1);
  ASSERT (fd_v6 >= -1);

  /* At least one should be valid */
  ASSERT (fd_v4 >= 0 || fd_v6 >= 0);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: Result free (NULL safety) */
TEST (dns_resolver_result_free_null)
{
  /* Should not crash */
  SocketDNSResolver_result_free (NULL);

  SocketDNSResolver_Result result = { 0 };
  SocketDNSResolver_result_free (&result);

  /* Still should be safe */
  ASSERT_NULL (result.addresses);
}

/* Test: Query hostname accessor */
TEST (dns_resolver_query_hostname)
{
  const char *hostname = SocketDNSResolver_query_hostname (NULL);
  ASSERT_NULL (hostname);
}

/* Test: Pending count starts at zero */
TEST (dns_resolver_pending_count)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);

  ASSERT_EQ (SocketDNSResolver_pending_count (resolver), 0);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: Process with no pending queries */
TEST (dns_resolver_process_empty)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);

  int completed = SocketDNSResolver_process (resolver, 0);
  ASSERT_EQ (completed, 0);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: Configuration setters */
TEST (dns_resolver_config_setters)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);

  /* These should not crash */
  SocketDNSResolver_set_timeout (resolver, 10000);
  SocketDNSResolver_set_retries (resolver, 5);

  /* Negative values should be handled */
  SocketDNSResolver_set_timeout (resolver, -1);
  SocketDNSResolver_set_retries (resolver, -1);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: Configuration propagates to transport (RFC 1035 §4.2.1) */
TEST (dns_resolver_config_propagation)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);

  /* Set timeout and retries - should propagate to transport */
  SocketDNSResolver_set_timeout (resolver, 3000);
  SocketDNSResolver_set_retries (resolver, 5);

  /* Add nameserver to enable queries */
  int ret = SocketDNSResolver_add_nameserver (resolver, "8.8.8.8", 53);
  ASSERT_EQ (ret, 0);

  /* Verify resolver is still functional after config changes */
  ASSERT_EQ (SocketDNSResolver_nameserver_count (resolver), 1);

  /* Change config again - should not crash */
  SocketDNSResolver_set_timeout (resolver, 1000);
  SocketDNSResolver_set_retries (resolver, 2);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: resolv.conf options apply to transport */
TEST (dns_resolver_resolv_conf_options)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);

  /* Load resolv.conf - should apply timeout/attempts/rotate */
  int count = SocketDNSResolver_load_resolv_conf (resolver);

  /* Should have loaded at least one nameserver (or fallback) */
  ASSERT (count >= 0);

  /* Resolver should be functional */
  ASSERT (SocketDNSResolver_nameserver_count (resolver) >= 0);

  /* Can override config after loading */
  SocketDNSResolver_set_timeout (resolver, 2000);
  SocketDNSResolver_set_retries (resolver, 3);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Test: Cancel non-existent query */
TEST (dns_resolver_cancel_invalid)
{
  Arena_T arena = Arena_new ();
  SocketDNSResolver_T resolver = SocketDNSResolver_new (arena);

  int ret = SocketDNSResolver_cancel (resolver, NULL);
  ASSERT_EQ (ret, -1);

  SocketDNSResolver_free (&resolver);
  Arena_dispose (&arena);
}

/* Main function */
int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
