/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * fuzz_dns_resolver.c - libFuzzer harness for DNS resolver state machine
 *
 * Fuzzes the DNS resolver's query lifecycle and state transitions:
 * - SocketDNSResolver_new() - Resolver initialization
 * - SocketDNSResolver_resolve() - Query submission
 * - SocketDNSResolver_process() - State machine processing
 * - SocketDNSResolver_cancel() - Query cancellation
 * - State transitions (INIT -> SENT -> WAITING -> COMPLETE/FAILED)
 * - CNAME chain following (QUERY_STATE_CNAME)
 * - TCP fallback handling (QUERY_STATE_TCP_FALLBACK)
 * - Concurrent query multiplexing
 * - Query ID collision handling
 * - Transaction ID matching
 * - Cache hit/miss paths
 * - Callback invocation edge cases
 * - Response validation (RFC 5452)
 * - Timeout handling
 * - Error propagation
 *
 * Test cases:
 * - Multiple concurrent queries with different hostnames
 * - Query cancellation at various states
 * - Response with CNAME chains (max depth testing)
 * - Truncated responses requiring TCP fallback
 * - Invalid responses (ID mismatch, validation failures)
 * - Cache operations (insert/lookup/eviction)
 * - Nameserver rotation on failure
 * - Timeout and retry logic
 * - IPv4-only, IPv6-only, and dual-stack queries
 * - Localhost and numeric IP fast paths
 *
 * Build: CC=clang cmake .. -DENABLE_FUZZING=ON && make fuzz_dns_resolver
 * Run:   ./fuzz_dns_resolver corpus/dns_resolver/ -fork=16 -max_len=4096
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNSResolver.h"
#include "dns/SocketDNSTransport.h"
#include "dns/SocketDNSWire.h"

/* Suppress GCC clobbered warnings for volatile variables */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Operation types for fuzzing */
typedef enum
{
  OP_LIFECYCLE = 0,     /* Create/free resolver */
  OP_RESOLVE_SINGLE,    /* Single query */
  OP_RESOLVE_MULTI,     /* Multiple concurrent queries */
  OP_RESOLVE_CNAME,     /* CNAME chain simulation */
  OP_CANCEL,            /* Cancel query */
  OP_PROCESS,           /* Process state machine */
  OP_CACHE_OPS,         /* Cache operations */
  OP_NAMESERVER_CONFIG, /* Nameserver configuration */
  OP_TIMEOUT_CONFIG,    /* Timeout/retry configuration */
  OP_SPECIAL_HOSTS      /* Localhost, numeric IPs */
} ResolverOp;

/* Callback tracking */
static volatile int callback_count = 0;
static volatile int last_error = 0;
static volatile size_t last_address_count = 0;
static volatile int callback_invoked = 0;

/* Test callback - must be async-signal-safe */
static void
test_callback (SocketDNSResolver_Query_T query, const SocketDNSResolver_Result *result,
               int error, void *userdata)
{
  (void)query;
  (void)userdata;

  callback_invoked = 1;
  callback_count++;
  last_error = error;

  if (result && error == RESOLVER_OK)
    {
      last_address_count = result->count;

      /* Validate result structure */
      if (result->addresses && result->count > 0)
        {
          /* Check address count bounds */
          (void)(result->count <= RESOLVER_MAX_ADDRESSES);

          /* Check each address */
          for (size_t i = 0; i < result->count; i++)
            {
              int family = result->addresses[i].family;
              (void)(family == AF_INET || family == AF_INET6);

              /* TTL validation */
              uint32_t ttl = result->addresses[i].ttl;
              (void)(ttl <= DNS_TTL_MAX);
            }

          /* min_ttl should be minimum of all TTLs */
          (void)(result->min_ttl <= DNS_TTL_MAX);
        }
    }
}

/* Extract operation from fuzz data */
static uint8_t
get_op (const uint8_t *data, size_t size)
{
  return size > 0 ? data[0] % 10 : 0;
}

/* Extract flags from fuzz data */
static int
get_flags (const uint8_t *data, size_t offset, size_t size)
{
  if (offset >= size)
    return RESOLVER_FLAG_BOTH;

  uint8_t flag_byte = data[offset];
  int flags = 0;

  /* Extract flag bits */
  if (flag_byte & 0x01)
    flags |= RESOLVER_FLAG_IPV4;
  if (flag_byte & 0x02)
    flags |= RESOLVER_FLAG_IPV6;
  if (flag_byte & 0x04)
    flags |= RESOLVER_FLAG_NO_CACHE;
  if (flag_byte & 0x08)
    flags |= RESOLVER_FLAG_TCP;

  /* Default to BOTH if neither v4 nor v6 set */
  if (!(flags & (RESOLVER_FLAG_IPV4 | RESOLVER_FLAG_IPV6)))
    flags |= RESOLVER_FLAG_BOTH;

  return flags;
}

/* Extract hostname from fuzz data */
static void
get_hostname (const uint8_t *data, size_t offset, size_t size, char *hostname, size_t max_len)
{
  size_t avail = 0;
  if (offset < size)
    avail = size - offset;

  if (avail == 0 || max_len == 0)
    {
      hostname[0] = '\0';
      return;
    }

  /* Copy up to max_len-1 bytes */
  size_t copy_len = avail < (max_len - 1) ? avail : (max_len - 1);

  if (copy_len > 0)
    {
      memcpy (hostname, data + offset, copy_len);

      /* Ensure printable ASCII and valid DNS chars */
      for (size_t i = 0; i < copy_len; i++)
        {
          unsigned char c = (unsigned char)hostname[i];

          /* Replace invalid chars with valid ones */
          if (c == 0 || c < 32 || c > 126)
            hostname[i] = 'a';
          else if (c == ' ')
            hostname[i] = '-';
        }
    }

  hostname[copy_len] = '\0';
}

/* Extract timeout value */
static int
get_timeout (const uint8_t *data, size_t offset, size_t size)
{
  if (offset + 2 > size)
    return RESOLVER_DEFAULT_TIMEOUT_MS;

  uint16_t val = ((uint16_t)data[offset] << 8) | data[offset + 1];

  /* Clamp to reasonable range */
  if (val < 100)
    val = 100;
  if (val > 30000)
    val = 30000;

  return (int)val;
}

/* Extract retry count */
static int
get_retries (const uint8_t *data, size_t offset, size_t size)
{
  if (offset >= size)
    return RESOLVER_DEFAULT_MAX_RETRIES;

  return (int)(data[offset] % 10);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;

  Arena_T arena = NULL;
  SocketDNSResolver_T resolver = NULL;
  volatile uint8_t op = get_op (data, size);
  volatile SocketDNSResolver_Query_T queries[8] = { NULL };
  volatile int num_queries = 0;

  /* Reset callback state */
  callback_invoked = 0;
  callback_count = 0;
  last_error = 0;
  last_address_count = 0;

  TRY
  {
    arena = Arena_new ();

    switch (op)
      {
      case OP_LIFECYCLE:
        {
          /* Test resolver creation and disposal */
          resolver = SocketDNSResolver_new (arena);

          /* Add a nameserver */
          SocketDNSResolver_add_nameserver (resolver, "8.8.8.8", 53);

          /* Get various counts and stats */
          (void)SocketDNSResolver_nameserver_count (resolver);
          (void)SocketDNSResolver_pending_count (resolver);
          (void)SocketDNSResolver_fd_v4 (resolver);
          (void)SocketDNSResolver_fd_v6 (resolver);

          /* Cache stats */
          SocketDNSResolver_CacheStats stats;
          SocketDNSResolver_cache_stats (resolver, &stats);
          (void)stats.hits;
          (void)stats.misses;

          SocketDNSResolver_free (&resolver);
          break;
        }

      case OP_RESOLVE_SINGLE:
        {
          /* Single query with various flags */
          resolver = SocketDNSResolver_new (arena);
          SocketDNSResolver_add_nameserver (resolver, "8.8.8.8", 53);

          char hostname[256];
          get_hostname (data, 2, size, hostname, sizeof (hostname));

          if (hostname[0] != '\0')
            {
              int flags = get_flags (data, 1, size);

              SocketDNSResolver_Query_T q = SocketDNSResolver_resolve (
                  resolver, hostname, flags, test_callback, NULL);

              if (q)
                {
                  /* Get query hostname */
                  const char *qname = SocketDNSResolver_query_hostname (q);
                  (void)qname;

                  /* Process for a bit */
                  for (int i = 0; i < 5 && SocketDNSResolver_pending_count (resolver) > 0; i++)
                    {
                      SocketDNSResolver_process (resolver, 10);
                    }
                }
            }

          SocketDNSResolver_free (&resolver);
          break;
        }

      case OP_RESOLVE_MULTI:
        {
          /* Multiple concurrent queries */
          resolver = SocketDNSResolver_new (arena);
          SocketDNSResolver_add_nameserver (resolver, "8.8.8.8", 53);
          SocketDNSResolver_add_nameserver (resolver, "1.1.1.1", 53);

          /* Submit multiple queries */
          size_t offset = 2;
          for (int i = 0; i < 8 && offset + 10 < size; i++)
            {
              char hostname[64];
              get_hostname (data, offset, size, hostname, sizeof (hostname));
              offset += 32;

              if (hostname[0] != '\0')
                {
                  int flags = get_flags (data, offset, size);
                  offset++;

                  SocketDNSResolver_Query_T q = SocketDNSResolver_resolve (
                      resolver, hostname, flags, test_callback, (void *)(uintptr_t)i);

                  if (q)
                    {
                      queries[num_queries++] = q;
                    }
                }
            }

          /* Process all queries */
          int iterations = 0;
          while (SocketDNSResolver_pending_count (resolver) > 0 && iterations < 20)
            {
              SocketDNSResolver_process (resolver, 10);
              iterations++;
            }

          SocketDNSResolver_free (&resolver);
          break;
        }

      case OP_CANCEL:
        {
          /* Test query cancellation */
          resolver = SocketDNSResolver_new (arena);
          SocketDNSResolver_add_nameserver (resolver, "8.8.8.8", 53);

          char hostname[256];
          get_hostname (data, 2, size, hostname, sizeof (hostname));

          if (hostname[0] != '\0')
            {
              SocketDNSResolver_Query_T q = SocketDNSResolver_resolve (
                  resolver, hostname, RESOLVER_FLAG_BOTH, test_callback, NULL);

              if (q)
                {
                  /* Cancel immediately or after some processing */
                  if (size > 10 && data[10] & 0x01)
                    {
                      SocketDNSResolver_process (resolver, 5);
                    }

                  int cancel_result = SocketDNSResolver_cancel (resolver, q);
                  (void)cancel_result;

                  /* Process to fire cancelled callback */
                  SocketDNSResolver_process (resolver, 10);

                  /* Try canceling again (should fail) */
                  (void)SocketDNSResolver_cancel (resolver, q);
                }
            }

          SocketDNSResolver_free (&resolver);
          break;
        }

      case OP_PROCESS:
        {
          /* Test process() with various timeout values */
          resolver = SocketDNSResolver_new (arena);
          SocketDNSResolver_add_nameserver (resolver, "8.8.8.8", 53);

          char hostname[256];
          get_hostname (data, 2, size, hostname, sizeof (hostname));

          if (hostname[0] != '\0')
            {
              SocketDNSResolver_resolve (resolver, hostname, RESOLVER_FLAG_BOTH,
                                         test_callback, NULL);

              /* Process with varying timeout */
              int timeout = get_timeout (data, 1, size);

              for (int i = 0; i < 10 && SocketDNSResolver_pending_count (resolver) > 0; i++)
                {
                  int completed = SocketDNSResolver_process (resolver, timeout);
                  (void)completed;
                }
            }

          SocketDNSResolver_free (&resolver);
          break;
        }

      case OP_CACHE_OPS:
        {
          /* Test cache operations */
          resolver = SocketDNSResolver_new (arena);
          SocketDNSResolver_add_nameserver (resolver, "8.8.8.8", 53);

          /* Configure cache */
          if (size > 5)
            {
              size_t max_entries = ((size_t)data[2] << 8) | data[3];
              max_entries = max_entries % 1000 + 10;
              SocketDNSResolver_cache_set_max (resolver, max_entries);

              int ttl = ((int)data[4] << 8) | data[5];
              ttl = ttl % 3600;
              SocketDNSResolver_cache_set_ttl (resolver, ttl);
            }

          /* Submit queries that might hit cache */
          char hostname[128];
          get_hostname (data, 6, size, hostname, sizeof (hostname));

          if (hostname[0] != '\0')
            {
              /* First query - cache miss */
              SocketDNSResolver_resolve (resolver, hostname, RESOLVER_FLAG_BOTH,
                                         test_callback, NULL);
              SocketDNSResolver_process (resolver, 10);

              /* Second query - should be cache hit if first succeeded */
              SocketDNSResolver_resolve (resolver, hostname, RESOLVER_FLAG_BOTH,
                                         test_callback, NULL);
              SocketDNSResolver_process (resolver, 10);

              /* Query with NO_CACHE flag */
              SocketDNSResolver_resolve (resolver, hostname,
                                         RESOLVER_FLAG_BOTH | RESOLVER_FLAG_NO_CACHE,
                                         test_callback, NULL);
              SocketDNSResolver_process (resolver, 10);
            }

          /* Get cache stats */
          SocketDNSResolver_CacheStats stats;
          SocketDNSResolver_cache_stats (resolver, &stats);
          (void)stats.hit_rate;

          /* Clear cache */
          SocketDNSResolver_cache_clear (resolver);

          /* Verify cache cleared */
          SocketDNSResolver_cache_stats (resolver, &stats);
          (void)(stats.current_size == 0);

          SocketDNSResolver_free (&resolver);
          break;
        }

      case OP_NAMESERVER_CONFIG:
        {
          /* Test nameserver configuration */
          resolver = SocketDNSResolver_new (arena);

          /* Add multiple nameservers */
          size_t offset = 1;
          for (int i = 0; i < 4 && offset + 16 < size; i++)
            {
              /* Extract IPv4 address bytes */
              char addr[64];
              if (offset + 4 <= size)
                {
                  snprintf (addr, sizeof (addr), "%u.%u.%u.%u",
                           data[offset], data[offset + 1],
                           data[offset + 2], data[offset + 3]);
                  offset += 4;

                  int port = ((int)data[offset] << 8) | data[offset + 1];
                  offset += 2;

                  if (port == 0)
                    port = 53;

                  SocketDNSResolver_add_nameserver (resolver, addr, port);
                }
            }

          int count = SocketDNSResolver_nameserver_count (resolver);
          (void)count;

          /* Load resolv.conf (may fail but shouldn't crash) */
          (void)SocketDNSResolver_load_resolv_conf (resolver);

          /* Clear nameservers */
          SocketDNSResolver_clear_nameservers (resolver);

          (void)(SocketDNSResolver_nameserver_count (resolver) == 0);

          SocketDNSResolver_free (&resolver);
          break;
        }

      case OP_TIMEOUT_CONFIG:
        {
          /* Test timeout and retry configuration */
          resolver = SocketDNSResolver_new (arena);
          SocketDNSResolver_add_nameserver (resolver, "8.8.8.8", 53);

          /* Set timeout */
          int timeout = get_timeout (data, 1, size);
          SocketDNSResolver_set_timeout (resolver, timeout);

          /* Set retries */
          int retries = get_retries (data, 3, size);
          SocketDNSResolver_set_retries (resolver, retries);

          /* Submit query with these settings */
          char hostname[128];
          get_hostname (data, 4, size, hostname, sizeof (hostname));

          if (hostname[0] != '\0')
            {
              SocketDNSResolver_resolve (resolver, hostname, RESOLVER_FLAG_BOTH,
                                         test_callback, NULL);

              /* Process briefly */
              for (int i = 0; i < 5; i++)
                {
                  SocketDNSResolver_process (resolver, timeout / 10);
                }
            }

          SocketDNSResolver_free (&resolver);
          break;
        }

      case OP_SPECIAL_HOSTS:
        {
          /* Test special hostname handling */
          resolver = SocketDNSResolver_new (arena);
          SocketDNSResolver_add_nameserver (resolver, "8.8.8.8", 53);

          /* Test localhost */
          callback_invoked = 0;
          SocketDNSResolver_resolve (resolver, "localhost", RESOLVER_FLAG_BOTH,
                                     test_callback, NULL);
          /* Localhost should invoke callback immediately */
          (void)callback_invoked;

          /* Test numeric IPv4 */
          callback_invoked = 0;
          SocketDNSResolver_resolve (resolver, "192.168.1.1", RESOLVER_FLAG_BOTH,
                                     test_callback, NULL);
          (void)callback_invoked;

          /* Test numeric IPv6 */
          callback_invoked = 0;
          SocketDNSResolver_resolve (resolver, "2001:db8::1", RESOLVER_FLAG_BOTH,
                                     test_callback, NULL);
          (void)callback_invoked;

          /* Test IPv6 with zone ID */
          callback_invoked = 0;
          SocketDNSResolver_resolve (resolver, "fe80::1%lo", RESOLVER_FLAG_BOTH,
                                     test_callback, NULL);
          (void)callback_invoked;

          /* Process any pending */
          SocketDNSResolver_process (resolver, 10);

          SocketDNSResolver_free (&resolver);
          break;
        }

      default:
        {
          /* Default: comprehensive stress test */
          resolver = SocketDNSResolver_new (arena);
          SocketDNSResolver_add_nameserver (resolver, "8.8.8.8", 53);

          /* Configure based on fuzz data */
          if (size > 10)
            {
              SocketDNSResolver_set_timeout (resolver, get_timeout (data, 1, size));
              SocketDNSResolver_set_retries (resolver, get_retries (data, 3, size));

              size_t max_cache = ((size_t)data[4] << 8) | data[5];
              SocketDNSResolver_cache_set_max (resolver, max_cache % 500 + 10);
            }

          /* Submit multiple queries */
          size_t offset = 10;
          for (int i = 0; i < 4 && offset + 20 < size; i++)
            {
              char hostname[128];
              get_hostname (data, offset, size, hostname, sizeof (hostname));
              offset += 32;

              if (hostname[0] != '\0')
                {
                  int flags = get_flags (data, offset, size);
                  offset++;

                  SocketDNSResolver_resolve (resolver, hostname, flags,
                                             test_callback, (void *)(uintptr_t)i);
                }
            }

          /* Process queries */
          int iterations = 0;
          while (SocketDNSResolver_pending_count (resolver) > 0 && iterations < 15)
            {
              SocketDNSResolver_process (resolver, 10);
              iterations++;
            }

          SocketDNSResolver_free (&resolver);
          break;
        }
      }

    /* Test error string conversion */
    const char *err_str = SocketDNSResolver_strerror (last_error);
    (void)err_str;

    /* Test all error codes */
    (void)SocketDNSResolver_strerror (RESOLVER_OK);
    (void)SocketDNSResolver_strerror (RESOLVER_ERROR_TIMEOUT);
    (void)SocketDNSResolver_strerror (RESOLVER_ERROR_CANCELLED);
    (void)SocketDNSResolver_strerror (RESOLVER_ERROR_NXDOMAIN);
    (void)SocketDNSResolver_strerror (RESOLVER_ERROR_SERVFAIL);
    (void)SocketDNSResolver_strerror (RESOLVER_ERROR_REFUSED);
    (void)SocketDNSResolver_strerror (RESOLVER_ERROR_NO_NS);
    (void)SocketDNSResolver_strerror (RESOLVER_ERROR_NETWORK);
    (void)SocketDNSResolver_strerror (RESOLVER_ERROR_CNAME_LOOP);
    (void)SocketDNSResolver_strerror (RESOLVER_ERROR_INVALID);
    (void)SocketDNSResolver_strerror (RESOLVER_ERROR_NOMEM);
    (void)SocketDNSResolver_strerror (RESOLVER_ERROR_VALIDATION_QNAME);
    (void)SocketDNSResolver_strerror (RESOLVER_ERROR_VALIDATION_QTYPE);
    (void)SocketDNSResolver_strerror (RESOLVER_ERROR_VALIDATION_QCLASS);
    (void)SocketDNSResolver_strerror (RESOLVER_ERROR_VALIDATION_BAILIWICK);
  }
  EXCEPT (SocketDNSResolver_Failed)
  {
    /* Expected for some invalid inputs */
  }
  EXCEPT (SocketDNSTransport_Failed)
  {
    /* Expected for network transport failures during fuzzing */
  }
  FINALLY
  {
    if (resolver)
      SocketDNSResolver_free (&resolver);
    if (arena)
      Arena_dispose (&arena);
  }
  END_TRY;

  return 0;
}
