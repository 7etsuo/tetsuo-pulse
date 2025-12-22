/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/*
 * test_dns_transport.c - Unit tests for DNS UDP transport (RFC 1035 §4.2.1)
 *
 * Tests the DNS transport layer functionality including:
 * - Transport instance lifecycle
 * - Nameserver configuration
 * - Query submission and validation
 * - Error code handling
 */

#include "core/Arena.h"
#include "dns/SocketDNSTransport.h"
#include "dns/SocketDNSWire.h"
#include "test/Test.h"

#include <stdio.h>
#include <string.h>

/* Test basic transport instantiation */
TEST (dns_transport_new_creates_instance)
{
  Arena_T arena = Arena_new ();
  SocketDNSTransport_T transport = SocketDNSTransport_new (arena, NULL);

  ASSERT_NOT_NULL (transport);
  ASSERT_EQ (SocketDNSTransport_nameserver_count (transport), 0);
  ASSERT_EQ (SocketDNSTransport_pending_count (transport), 0);

  SocketDNSTransport_free (&transport);
  ASSERT_NULL (transport);
  Arena_dispose (&arena);
}

/* Test adding IPv4 nameserver */
TEST (dns_transport_add_nameserver_ipv4)
{
  Arena_T arena = Arena_new ();
  SocketDNSTransport_T transport = SocketDNSTransport_new (arena, NULL);
  int ret;

  ret = SocketDNSTransport_add_nameserver (transport, "8.8.8.8", DNS_PORT);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSTransport_nameserver_count (transport), 1);

  ret = SocketDNSTransport_add_nameserver (transport, "8.8.4.4", DNS_PORT);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSTransport_nameserver_count (transport), 2);

  SocketDNSTransport_free (&transport);
  Arena_dispose (&arena);
}

/* Test adding IPv6 nameserver */
TEST (dns_transport_add_nameserver_ipv6)
{
  Arena_T arena = Arena_new ();
  SocketDNSTransport_T transport = SocketDNSTransport_new (arena, NULL);
  int ret;

  ret = SocketDNSTransport_add_nameserver (transport, "2001:4860:4860::8888",
                                           DNS_PORT);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSTransport_nameserver_count (transport), 1);

  SocketDNSTransport_free (&transport);
  Arena_dispose (&arena);
}

/* Test maximum nameserver limit */
TEST (dns_transport_max_nameservers)
{
  Arena_T arena = Arena_new ();
  SocketDNSTransport_T transport = SocketDNSTransport_new (arena, NULL);
  int ret;
  int i;
  char addr[32];

  /* Add maximum allowed nameservers */
  for (i = 0; i < DNS_MAX_NAMESERVERS; i++)
    {
      snprintf (addr, sizeof (addr), "10.0.0.%d", i + 1);
      ret = SocketDNSTransport_add_nameserver (transport, addr, DNS_PORT);
      ASSERT_EQ (ret, 0);
    }

  ASSERT_EQ (SocketDNSTransport_nameserver_count (transport),
             DNS_MAX_NAMESERVERS);

  /* Try to add one more - should fail */
  ret = SocketDNSTransport_add_nameserver (transport, "10.0.0.100", DNS_PORT);
  ASSERT_EQ (ret, -1);
  ASSERT_EQ (SocketDNSTransport_nameserver_count (transport),
             DNS_MAX_NAMESERVERS);

  SocketDNSTransport_free (&transport);
  Arena_dispose (&arena);
}

/* Test clearing nameservers */
TEST (dns_transport_clear_nameservers)
{
  Arena_T arena = Arena_new ();
  SocketDNSTransport_T transport = SocketDNSTransport_new (arena, NULL);

  SocketDNSTransport_add_nameserver (transport, "8.8.8.8", DNS_PORT);
  SocketDNSTransport_add_nameserver (transport, "8.8.4.4", DNS_PORT);
  ASSERT_EQ (SocketDNSTransport_nameserver_count (transport), 2);

  SocketDNSTransport_clear_nameservers (transport);
  ASSERT_EQ (SocketDNSTransport_nameserver_count (transport), 0);

  SocketDNSTransport_free (&transport);
  Arena_dispose (&arena);
}

/* Test invalid address rejection */
TEST (dns_transport_add_nameserver_invalid)
{
  Arena_T arena = Arena_new ();
  SocketDNSTransport_T transport = SocketDNSTransport_new (arena, NULL);
  int ret;

  /* Invalid IPv4 */
  ret = SocketDNSTransport_add_nameserver (transport, "999.999.999.999",
                                           DNS_PORT);
  ASSERT_EQ (ret, -1);

  /* Not an address */
  ret = SocketDNSTransport_add_nameserver (transport, "not-an-address",
                                           DNS_PORT);
  ASSERT_EQ (ret, -1);

  /* Empty string */
  ret = SocketDNSTransport_add_nameserver (transport, "", DNS_PORT);
  ASSERT_EQ (ret, -1);

  ASSERT_EQ (SocketDNSTransport_nameserver_count (transport), 0);

  SocketDNSTransport_free (&transport);
  Arena_dispose (&arena);
}

/* Test configuration */
TEST (dns_transport_configure)
{
  Arena_T arena = Arena_new ();
  SocketDNSTransport_T transport = SocketDNSTransport_new (arena, NULL);
  SocketDNSTransport_Config config;

  config.initial_timeout_ms = 3000;
  config.max_timeout_ms = 10000;
  config.max_retries = 5;
  config.rotate_nameservers = 0;

  SocketDNSTransport_configure (transport, &config);

  /* Configuration is internal, but we can verify via query behavior later */
  ASSERT_NOT_NULL (transport);

  SocketDNSTransport_free (&transport);
  Arena_dispose (&arena);
}

/* Callback flag for tests */
static volatile int callback_invoked = 0;
static volatile int callback_error = 0;

static void
test_callback (SocketDNSQuery_T query, const unsigned char *response,
               size_t len, int error, void *userdata)
{
  (void)query;
  (void)response;
  (void)len;
  (void)userdata;
  callback_invoked = 1;
  callback_error = error;
}

/* Test query returns handle with nameserver configured */
TEST (dns_transport_query_returns_handle)
{
  Arena_T arena = Arena_new ();
  SocketDNSTransport_T transport = SocketDNSTransport_new (arena, NULL);
  SocketDNSQuery_T query;
  unsigned char query_buf[DNS_UDP_MAX_SIZE];
  SocketDNS_Header hdr;
  size_t len = DNS_HEADER_SIZE;

  /* Add a nameserver first */
  SocketDNSTransport_add_nameserver (transport, "127.0.0.1", DNS_PORT);

  /* Build a minimal query */
  memset (&hdr, 0, sizeof (hdr));
  hdr.id = 0x1234;
  hdr.rd = 1;
  hdr.qdcount = 1;
  SocketDNS_header_encode (&hdr, query_buf, sizeof (query_buf));

  query = SocketDNSTransport_query_udp (transport, query_buf, len,
                                        test_callback, NULL);
  ASSERT_NOT_NULL (query);
  ASSERT_EQ (SocketDNSQuery_get_id (query), 0x1234);
  ASSERT_EQ (SocketDNSQuery_get_retry_count (query), 0);
  ASSERT_EQ (SocketDNSTransport_pending_count (transport), 1);
  ASSERT (SocketDNSTransport_is_pending (transport, query));

  /* Cancel to clean up */
  SocketDNSTransport_cancel (transport, query);

  SocketDNSTransport_free (&transport);
  Arena_dispose (&arena);
}

/* Test query without nameserver returns NULL and calls callback with error */
TEST (dns_transport_query_no_nameserver)
{
  Arena_T arena = Arena_new ();
  SocketDNSTransport_T transport = SocketDNSTransport_new (arena, NULL);
  SocketDNSQuery_T query;
  unsigned char query_buf[DNS_HEADER_SIZE];
  SocketDNS_Header hdr;

  callback_invoked = 0;
  callback_error = 0;

  /* No nameserver configured */
  memset (&hdr, 0, sizeof (hdr));
  hdr.id = 0x5678;
  hdr.rd = 1;
  SocketDNS_header_encode (&hdr, query_buf, sizeof (query_buf));

  query = SocketDNSTransport_query_udp (transport, query_buf, DNS_HEADER_SIZE,
                                        test_callback, NULL);
  ASSERT_NULL (query);
  ASSERT_EQ (callback_invoked, 1);
  ASSERT_EQ (callback_error, DNS_ERROR_NONS);

  SocketDNSTransport_free (&transport);
  Arena_dispose (&arena);
}

/* Test cancel removes pending query */
TEST (dns_transport_cancel_removes_query)
{
  Arena_T arena = Arena_new ();
  SocketDNSTransport_T transport = SocketDNSTransport_new (arena, NULL);
  SocketDNSQuery_T query;
  unsigned char query_buf[DNS_UDP_MAX_SIZE];
  SocketDNS_Header hdr;
  int ret;

  SocketDNSTransport_add_nameserver (transport, "127.0.0.1", DNS_PORT);

  memset (&hdr, 0, sizeof (hdr));
  hdr.id = 0xABCD;
  hdr.rd = 1;
  SocketDNS_header_encode (&hdr, query_buf, sizeof (query_buf));

  query = SocketDNSTransport_query_udp (transport, query_buf, DNS_HEADER_SIZE,
                                        test_callback, NULL);
  ASSERT_NOT_NULL (query);
  ASSERT_EQ (SocketDNSTransport_pending_count (transport), 1);

  ret = SocketDNSTransport_cancel (transport, query);
  ASSERT_EQ (ret, 0);

  /* Cancelled query is no longer considered pending */
  ASSERT (!SocketDNSTransport_is_pending (transport, query));

  /* Process to invoke cancelled callback */
  callback_invoked = 0;
  SocketDNSTransport_process (transport, 0);
  ASSERT_EQ (callback_invoked, 1);
  ASSERT_EQ (callback_error, DNS_ERROR_CANCELLED);
  ASSERT_EQ (SocketDNSTransport_pending_count (transport), 0);

  SocketDNSTransport_free (&transport);
  Arena_dispose (&arena);
}

/* Test cancelling non-existent query */
TEST (dns_transport_cancel_nonexistent)
{
  Arena_T arena = Arena_new ();
  SocketDNSTransport_T transport = SocketDNSTransport_new (arena, NULL);
  int ret;

  ret = SocketDNSTransport_cancel (transport, NULL);
  ASSERT_EQ (ret, -1);

  SocketDNSTransport_free (&transport);
  Arena_dispose (&arena);
}

/* Test socket file descriptors */
TEST (dns_transport_file_descriptors)
{
  Arena_T arena = Arena_new ();
  SocketDNSTransport_T transport = SocketDNSTransport_new (arena, NULL);
  int fd_v4, fd_v6;

  fd_v4 = SocketDNSTransport_fd_v4 (transport);
  fd_v6 = SocketDNSTransport_fd_v6 (transport);

  /* At least one should be valid (depends on system IPv6 support) */
  ASSERT (fd_v4 >= 0 || fd_v6 >= 0);

  SocketDNSTransport_free (&transport);
  Arena_dispose (&arena);
}

/* Test error string conversion */
TEST (dns_transport_strerror)
{
  const char *str;

  str = SocketDNSTransport_strerror (DNS_ERROR_SUCCESS);
  ASSERT_NOT_NULL (str);
  ASSERT (strlen (str) > 0);

  str = SocketDNSTransport_strerror (DNS_ERROR_TIMEOUT);
  ASSERT_NOT_NULL (str);
  ASSERT (strlen (str) > 0);

  str = SocketDNSTransport_strerror (DNS_ERROR_TRUNCATED);
  ASSERT_NOT_NULL (str);
  ASSERT (strlen (str) > 0);

  str = SocketDNSTransport_strerror (DNS_ERROR_CANCELLED);
  ASSERT_NOT_NULL (str);
  ASSERT (strlen (str) > 0);

  str = SocketDNSTransport_strerror (DNS_ERROR_NETWORK);
  ASSERT_NOT_NULL (str);
  ASSERT (strlen (str) > 0);

  str = SocketDNSTransport_strerror (DNS_ERROR_INVALID);
  ASSERT_NOT_NULL (str);
  ASSERT (strlen (str) > 0);

  str = SocketDNSTransport_strerror (DNS_ERROR_NXDOMAIN);
  ASSERT_NOT_NULL (str);
  ASSERT (strlen (str) > 0);

  str = SocketDNSTransport_strerror (DNS_ERROR_NONS);
  ASSERT_NOT_NULL (str);
  ASSERT (strlen (str) > 0);

  /* Unknown error */
  str = SocketDNSTransport_strerror (-999);
  ASSERT_NOT_NULL (str);
}

/* Test query size validation (must be <= 512 bytes per RFC 1035) */
TEST (dns_transport_query_size_validation)
{
  Arena_T arena = Arena_new ();
  SocketDNSTransport_T transport = SocketDNSTransport_new (arena, NULL);
  SocketDNSQuery_T query;
  unsigned char query_buf[DNS_UDP_MAX_SIZE + 1];

  SocketDNSTransport_add_nameserver (transport, "127.0.0.1", DNS_PORT);

  /* Query too large */
  memset (query_buf, 0, sizeof (query_buf));
  query = SocketDNSTransport_query_udp (transport, query_buf, sizeof (query_buf),
                                        test_callback, NULL);
  ASSERT_NULL (query);

  /* Query at exact limit should be accepted */
  query = SocketDNSTransport_query_udp (transport, query_buf, DNS_UDP_MAX_SIZE,
                                        test_callback, NULL);
  ASSERT_NOT_NULL (query);

  SocketDNSTransport_cancel (transport, query);
  SocketDNSTransport_free (&transport);
  Arena_dispose (&arena);
}

/* Test process with no pending queries */
TEST (dns_transport_process_empty)
{
  Arena_T arena = Arena_new ();
  SocketDNSTransport_T transport = SocketDNSTransport_new (arena, NULL);
  int ret;

  SocketDNSTransport_add_nameserver (transport, "127.0.0.1", DNS_PORT);

  /* Should return 0 (no queries processed) */
  ret = SocketDNSTransport_process (transport, 0);
  ASSERT_EQ (ret, 0);

  SocketDNSTransport_free (&transport);
  Arena_dispose (&arena);
}

/* Test free cancels all pending queries */
TEST (dns_transport_free_cancels_queries)
{
  Arena_T arena = Arena_new ();
  SocketDNSTransport_T transport = SocketDNSTransport_new (arena, NULL);
  unsigned char query_buf[DNS_HEADER_SIZE];
  SocketDNS_Header hdr;

  SocketDNSTransport_add_nameserver (transport, "127.0.0.1", DNS_PORT);

  memset (&hdr, 0, sizeof (hdr));
  hdr.id = 0x1111;
  hdr.rd = 1;
  SocketDNS_header_encode (&hdr, query_buf, sizeof (query_buf));

  callback_invoked = 0;
  SocketDNSTransport_query_udp (transport, query_buf, DNS_HEADER_SIZE,
                                test_callback, NULL);

  hdr.id = 0x2222;
  SocketDNS_header_encode (&hdr, query_buf, sizeof (query_buf));
  SocketDNSTransport_query_udp (transport, query_buf, DNS_HEADER_SIZE,
                                test_callback, NULL);

  ASSERT_EQ (SocketDNSTransport_pending_count (transport), 2);

  /* Free should cancel all pending queries */
  SocketDNSTransport_free (&transport);
  ASSERT_NULL (transport);

  /* Callbacks should have been invoked with CANCELLED */
  ASSERT_EQ (callback_invoked, 1);
  ASSERT_EQ (callback_error, DNS_ERROR_CANCELLED);

  Arena_dispose (&arena);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
