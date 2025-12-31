/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_dns_over_tls.c
 * @brief Unit tests for DNS-over-TLS transport (RFC 7858, RFC 8310).
 */

#include "dns/SocketDNSoverTLS.h"
#include "dns/SocketDNSWire.h"
#include "core/Arena.h"
#include "test/Test.h"

#if SOCKET_HAS_TLS

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

/* Test callback state */
static volatile int g_callback_invoked = 0;
static volatile int g_callback_error = -999;
static volatile size_t g_response_len = 0;

static void
test_callback (SocketDNSoverTLS_Query_T query,
               const unsigned char *response,
               size_t len,
               int error,
               void *userdata)
{
  (void)query;
  (void)userdata;

  g_callback_invoked = 1;
  g_callback_error = error;
  g_response_len = (response && error == DOT_ERROR_SUCCESS) ? len : 0;
}

/* Reset test callback state */
static void
reset_callback_state (void)
{
  g_callback_invoked = 0;
  g_callback_error = -999;
  g_response_len = 0;
}

/* Test: Basic lifecycle (new/free) */
TEST (dot_lifecycle)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverTLS_T dot = NULL;

  dot = SocketDNSoverTLS_new (arena);
  ASSERT_NOT_NULL (dot);

  /* Verify defaults */
  ASSERT_EQ (SocketDNSoverTLS_pending_count (dot), 0);
  ASSERT_EQ (SocketDNSoverTLS_server_count (dot), 0);
  ASSERT_EQ (SocketDNSoverTLS_is_connected (dot), 0);

  SocketDNSoverTLS_free (&dot);
  ASSERT_NULL (dot);

  Arena_dispose (&arena);
}

/* Test: Server configuration */
TEST (dot_server_config)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverTLS_T dot = SocketDNSoverTLS_new (arena);

  /* Add server via config struct */
  SocketDNSoverTLS_Config config = { .server_address = "8.8.8.8",
                                     .port = 853,
                                     .server_name = "dns.google",
                                     .mode = DOT_MODE_STRICT,
                                     .spki_pin = NULL,
                                     .spki_pin_backup = NULL };

  int ret = SocketDNSoverTLS_configure (dot, &config);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSoverTLS_server_count (dot), 1);

  /* Add IPv6 server */
  config.server_address = "2001:4860:4860::8888";
  ret = SocketDNSoverTLS_configure (dot, &config);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSoverTLS_server_count (dot), 2);

  /* Clear servers */
  SocketDNSoverTLS_clear_servers (dot);
  ASSERT_EQ (SocketDNSoverTLS_server_count (dot), 0);

  SocketDNSoverTLS_free (&dot);
  Arena_dispose (&arena);
}

/* Test: Well-known server configuration */
TEST (dot_wellknown_servers)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverTLS_T dot = SocketDNSoverTLS_new (arena);

  /* Add well-known servers */
  int ret = SocketDNSoverTLS_add_server (dot, "google", DOT_MODE_STRICT);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSoverTLS_server_count (dot), 1);

  ret = SocketDNSoverTLS_add_server (dot, "cloudflare", DOT_MODE_STRICT);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSoverTLS_server_count (dot), 2);

  ret = SocketDNSoverTLS_add_server (dot, "quad9", DOT_MODE_OPPORTUNISTIC);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSoverTLS_server_count (dot), 3);

  /* Unknown server should fail */
  ret = SocketDNSoverTLS_add_server (dot, "unknown", DOT_MODE_STRICT);
  ASSERT_EQ (ret, -1);
  ASSERT_EQ (SocketDNSoverTLS_server_count (dot), 3);

  SocketDNSoverTLS_free (&dot);
  Arena_dispose (&arena);
}

/* Test: Query without server fails */
TEST (dot_query_no_server)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverTLS_T dot = SocketDNSoverTLS_new (arena);

  /* Build a simple A query */
  unsigned char query[512];
  size_t query_len;

  SocketDNS_Header hdr;
  SocketDNS_header_init_query (&hdr, 0x1234, 1);

  SocketDNS_header_encode (&hdr, query, sizeof (query));

  SocketDNS_Question question;
  SocketDNS_question_init (&question, "example.com", DNS_TYPE_A);

  size_t written;
  int ret = SocketDNS_question_encode (&question,
                                       query + DNS_HEADER_SIZE,
                                       sizeof (query) - DNS_HEADER_SIZE,
                                       &written);
  ASSERT_EQ (ret, 0);
  query_len = DNS_HEADER_SIZE + written;

  /* Query without server should return NULL */
  reset_callback_state ();
  SocketDNSoverTLS_Query_T q
      = SocketDNSoverTLS_query (dot, query, query_len, test_callback, NULL);
  ASSERT_NULL (q);

  SocketDNSoverTLS_free (&dot);
  Arena_dispose (&arena);
}

/* Test: Error string conversion */
TEST (dot_error_strings)
{
  /* All error codes should return non-empty strings */
  ASSERT_NOT_NULL (SocketDNSoverTLS_strerror (DOT_ERROR_SUCCESS));
  ASSERT_NOT_NULL (SocketDNSoverTLS_strerror (DOT_ERROR_TIMEOUT));
  ASSERT_NOT_NULL (SocketDNSoverTLS_strerror (DOT_ERROR_CANCELLED));
  ASSERT_NOT_NULL (SocketDNSoverTLS_strerror (DOT_ERROR_NETWORK));
  ASSERT_NOT_NULL (SocketDNSoverTLS_strerror (DOT_ERROR_TLS_HANDSHAKE));
  ASSERT_NOT_NULL (SocketDNSoverTLS_strerror (DOT_ERROR_TLS_VERIFY));
  ASSERT_NOT_NULL (SocketDNSoverTLS_strerror (DOT_ERROR_TLS_IO));
  ASSERT_NOT_NULL (SocketDNSoverTLS_strerror (DOT_ERROR_INVALID));
  ASSERT_NOT_NULL (SocketDNSoverTLS_strerror (DOT_ERROR_NO_SERVER));
  ASSERT_NOT_NULL (SocketDNSoverTLS_strerror (DOT_ERROR_FORMERR));
  ASSERT_NOT_NULL (SocketDNSoverTLS_strerror (DOT_ERROR_SERVFAIL));
  ASSERT_NOT_NULL (SocketDNSoverTLS_strerror (DOT_ERROR_NXDOMAIN));
  ASSERT_NOT_NULL (SocketDNSoverTLS_strerror (DOT_ERROR_REFUSED));
  ASSERT_NOT_NULL (SocketDNSoverTLS_strerror (DOT_ERROR_SPKI_MISMATCH));

  /* Unknown code should also return a valid string */
  ASSERT_NOT_NULL (SocketDNSoverTLS_strerror (-100));

  /* Specific string checks */
  ASSERT (strcmp (SocketDNSoverTLS_strerror (DOT_ERROR_SUCCESS), "Success")
          == 0);
  ASSERT (strcmp (SocketDNSoverTLS_strerror (DOT_ERROR_NXDOMAIN),
                  "Domain does not exist")
          == 0);
}

/* Test: DoT port constant */
TEST (dot_port_constant)
{
  /* RFC 7858 specifies port 853 */
  ASSERT_EQ (DOT_PORT, 853);
}

/* Test: Privacy modes */
TEST (dot_privacy_modes)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverTLS_T dot = SocketDNSoverTLS_new (arena);

  /* Test opportunistic mode */
  SocketDNSoverTLS_Config config = { .server_address = "8.8.8.8",
                                     .port = 853,
                                     .server_name = "dns.google",
                                     .mode = DOT_MODE_OPPORTUNISTIC,
                                     .spki_pin = NULL,
                                     .spki_pin_backup = NULL };

  int ret = SocketDNSoverTLS_configure (dot, &config);
  ASSERT_EQ (ret, 0);

  /* Test strict mode */
  config.mode = DOT_MODE_STRICT;
  config.server_address = "1.1.1.1";
  config.server_name = "cloudflare-dns.com";
  ret = SocketDNSoverTLS_configure (dot, &config);
  ASSERT_EQ (ret, 0);

  ASSERT_EQ (SocketDNSoverTLS_server_count (dot), 2);

  SocketDNSoverTLS_free (&dot);
  Arena_dispose (&arena);
}

/* Test: Statistics initialization */
TEST (dot_stats)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverTLS_T dot = SocketDNSoverTLS_new (arena);

  SocketDNSoverTLS_Stats stats;
  SocketDNSoverTLS_stats (dot, &stats);

  /* All stats should be zero initially */
  ASSERT_EQ (stats.queries_sent, 0);
  ASSERT_EQ (stats.queries_completed, 0);
  ASSERT_EQ (stats.queries_failed, 0);
  ASSERT_EQ (stats.connections_opened, 0);
  ASSERT_EQ (stats.connections_reused, 0);
  ASSERT_EQ (stats.handshake_failures, 0);
  ASSERT_EQ (stats.verify_failures, 0);
  ASSERT_EQ (stats.bytes_sent, 0);
  ASSERT_EQ (stats.bytes_received, 0);

  SocketDNSoverTLS_free (&dot);
  Arena_dispose (&arena);
}

/* Test: Query cancellation */
TEST (dot_cancel_query)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverTLS_T dot = SocketDNSoverTLS_new (arena);

  /* Add server */
  SocketDNSoverTLS_add_server (dot, "google", DOT_MODE_STRICT);

  /* Build a query */
  unsigned char query[512];
  size_t query_len;

  SocketDNS_Header hdr;
  SocketDNS_header_init_query (&hdr, 0x5678, 1);
  SocketDNS_header_encode (&hdr, query, sizeof (query));

  SocketDNS_Question question;
  SocketDNS_question_init (&question, "example.com", DNS_TYPE_A);

  size_t written;
  SocketDNS_question_encode (&question,
                             query + DNS_HEADER_SIZE,
                             sizeof (query) - DNS_HEADER_SIZE,
                             &written);
  query_len = DNS_HEADER_SIZE + written;

  reset_callback_state ();
  SocketDNSoverTLS_Query_T q
      = SocketDNSoverTLS_query (dot, query, query_len, test_callback, NULL);

  if (q)
    {
      /* Cancel the query */
      int ret = SocketDNSoverTLS_cancel (dot, q);
      ASSERT_EQ (ret, 0);

      /* Cancelling again should fail */
      ret = SocketDNSoverTLS_cancel (dot, q);
      ASSERT_EQ (ret, -1);

      /* Verify callback was invoked with cancelled error */
      ASSERT_EQ (g_callback_invoked, 1);
      ASSERT_EQ (g_callback_error, DOT_ERROR_CANCELLED);
    }

  SocketDNSoverTLS_free (&dot);
  Arena_dispose (&arena);
}

/* Test: Close all connections */
TEST (dot_close_all)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverTLS_T dot = SocketDNSoverTLS_new (arena);

  /* Add servers */
  SocketDNSoverTLS_add_server (dot, "google", DOT_MODE_STRICT);
  SocketDNSoverTLS_add_server (dot, "cloudflare", DOT_MODE_STRICT);

  /* Close all - should not crash even with no connections */
  SocketDNSoverTLS_close_all (dot);

  ASSERT_EQ (SocketDNSoverTLS_is_connected (dot), 0);
  ASSERT_EQ (SocketDNSoverTLS_pending_count (dot), 0);

  SocketDNSoverTLS_free (&dot);
  Arena_dispose (&arena);
}

/* Test: File descriptor access */
TEST (dot_fd_access)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverTLS_T dot = SocketDNSoverTLS_new (arena);

  /* No connection, fd should be -1 */
  ASSERT_EQ (SocketDNSoverTLS_fd (dot), -1);

  SocketDNSoverTLS_free (&dot);
  Arena_dispose (&arena);
}

/* Test: Invalid address rejection */
TEST (dot_invalid_address)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverTLS_T dot = SocketDNSoverTLS_new (arena);

  /* Invalid address should fail */
  SocketDNSoverTLS_Config config = { .server_address = "not-an-ip-address",
                                     .port = 853,
                                     .server_name = "test",
                                     .mode = DOT_MODE_STRICT,
                                     .spki_pin = NULL,
                                     .spki_pin_backup = NULL };

  int ret = SocketDNSoverTLS_configure (dot, &config);
  ASSERT_EQ (ret, -1);
  ASSERT_EQ (SocketDNSoverTLS_server_count (dot), 0);

  SocketDNSoverTLS_free (&dot);
  Arena_dispose (&arena);
}

/* Test: IPv6 server configuration */
TEST (dot_ipv6_config)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverTLS_T dot = SocketDNSoverTLS_new (arena);

  /* Add IPv6 well-known server */
  int ret = SocketDNSoverTLS_add_server (dot, "google-v6", DOT_MODE_STRICT);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSoverTLS_server_count (dot), 1);

  ret = SocketDNSoverTLS_add_server (dot, "cloudflare-v6", DOT_MODE_STRICT);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSoverTLS_server_count (dot), 2);

  ret = SocketDNSoverTLS_add_server (dot, "quad9-v6", DOT_MODE_STRICT);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSoverTLS_server_count (dot), 3);

  SocketDNSoverTLS_free (&dot);
  Arena_dispose (&arena);
}

/* Test: SPKI pin configuration */
TEST (dot_spki_config)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverTLS_T dot = SocketDNSoverTLS_new (arena);

  /* Configure with SPKI pins */
  SocketDNSoverTLS_Config config
      = { .server_address = "8.8.8.8",
          .port = 853,
          .server_name = "dns.google",
          .mode = DOT_MODE_STRICT,
          /* Example SPKI pin (not real) */
          .spki_pin = "sha256//example_pin_not_real_just_for_testing",
          .spki_pin_backup = "sha256//backup_pin_not_real_just_for_testing" };

  int ret = SocketDNSoverTLS_configure (dot, &config);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSoverTLS_server_count (dot), 1);

  SocketDNSoverTLS_free (&dot);
  Arena_dispose (&arena);
}

/* Test: Query ID extraction */
TEST (dot_query_id)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverTLS_T dot = SocketDNSoverTLS_new (arena);

  /* Add server */
  SocketDNSoverTLS_add_server (dot, "google", DOT_MODE_OPPORTUNISTIC);

  /* Build query with specific ID */
  unsigned char query[512];
  size_t query_len;
  uint16_t test_id = 0xABCD;

  SocketDNS_Header hdr;
  SocketDNS_header_init_query (&hdr, test_id, 1);
  SocketDNS_header_encode (&hdr, query, sizeof (query));

  SocketDNS_Question question;
  SocketDNS_question_init (&question, "test.com", DNS_TYPE_A);

  size_t written;
  SocketDNS_question_encode (&question,
                             query + DNS_HEADER_SIZE,
                             sizeof (query) - DNS_HEADER_SIZE,
                             &written);
  query_len = DNS_HEADER_SIZE + written;

  reset_callback_state ();
  SocketDNSoverTLS_Query_T q
      = SocketDNSoverTLS_query (dot, query, query_len, test_callback, NULL);

  if (q)
    {
      /* Verify query ID extraction */
      ASSERT_EQ (SocketDNSoverTLS_query_id (q), test_id);

      /* Cancel to clean up */
      SocketDNSoverTLS_cancel (dot, q);
    }

  SocketDNSoverTLS_free (&dot);
  Arena_dispose (&arena);
}

/* Test: Cumulative memory limit (CWE-770 mitigation) */
TEST (dot_memory_limit)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverTLS_T dot = SocketDNSoverTLS_new (arena);

  /* Add server */
  SocketDNSoverTLS_add_server (dot, "google", DOT_MODE_OPPORTUNISTIC);

  /* Build large queries to test memory limit
   * DOT_MAX_TOTAL_QUERY_BYTES = 10MB
   * We'll try to allocate 11MB worth of queries to exceed the limit
   */
  const size_t large_query_size = 60000; /* ~60KB per query */
  const int num_queries = 180;           /* 180 * 60KB = 10.8MB */

  int queries_accepted = 0;
  int queries_rejected = 0;

  for (int i = 0; i < num_queries; i++)
    {
      /* Build a query with padding to reach desired size */
      unsigned char *query = ALLOC (arena, large_query_size);
      memset (query, 0, large_query_size);

      /* Create valid DNS header */
      SocketDNS_Header hdr;
      SocketDNS_header_init_query (&hdr, (uint16_t)(0x1000 + i), 1);
      SocketDNS_header_encode (&hdr, query, large_query_size);

      /* Add a question section */
      SocketDNS_Question question;
      SocketDNS_question_init (&question, "example.com", DNS_TYPE_A);
      size_t written;
      SocketDNS_question_encode (&question,
                                 query + DNS_HEADER_SIZE,
                                 large_query_size - DNS_HEADER_SIZE,
                                 &written);

      reset_callback_state ();
      SocketDNSoverTLS_Query_T q = SocketDNSoverTLS_query (
          dot, query, large_query_size, test_callback, NULL);

      if (q)
        {
          queries_accepted++;
        }
      else
        {
          queries_rejected++;
          /* Should start rejecting after reaching the limit */
          break;
        }
    }

  /* Verify that some queries were accepted but not all */
  ASSERT (queries_accepted > 0);
  ASSERT (queries_rejected > 0 || queries_accepted < num_queries);

  /* Pending count should match accepted queries */
  ASSERT_EQ (SocketDNSoverTLS_pending_count (dot), queries_accepted);

  /* Cancel all queries to free memory */
  SocketDNSoverTLS_close_all (dot);
  ASSERT_EQ (SocketDNSoverTLS_pending_count (dot), 0);

  /* After cancelling, should be able to add queries again */
  unsigned char small_query[512];
  SocketDNS_Header hdr;
  SocketDNS_header_init_query (&hdr, 0x9999, 1);
  SocketDNS_header_encode (&hdr, small_query, sizeof (small_query));

  SocketDNS_Question question;
  SocketDNS_question_init (&question, "test.com", DNS_TYPE_A);
  size_t written;
  SocketDNS_question_encode (&question,
                             small_query + DNS_HEADER_SIZE,
                             sizeof (small_query) - DNS_HEADER_SIZE,
                             &written);
  size_t small_query_len = DNS_HEADER_SIZE + written;

  reset_callback_state ();
  SocketDNSoverTLS_Query_T q = SocketDNSoverTLS_query (
      dot, small_query, small_query_len, test_callback, NULL);
  ASSERT_NOT_NULL (q);

  SocketDNSoverTLS_free (&dot);
  Arena_dispose (&arena);
}

/* Test: String truncation detection in configure */
TEST (dot_configure_truncation)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverTLS_T dot = SocketDNSoverTLS_new (arena);

  /* Test 1: Server address truncation (buffer size is 64) */
  char long_address[128];
  memset (long_address, 'a', sizeof (long_address) - 1);
  long_address[sizeof (long_address) - 1] = '\0';

  SocketDNSoverTLS_Config config = { .server_address = long_address,
                                     .port = 853,
                                     .server_name = NULL,
                                     .mode = DOT_MODE_OPPORTUNISTIC,
                                     .spki_pin = NULL,
                                     .spki_pin_backup = NULL };

  int ret = SocketDNSoverTLS_configure (dot, &config);
  ASSERT_EQ (ret, -1); /* Should fail due to address truncation */

  /* Test 2: Server name truncation (buffer size is 256) */
  char long_server_name[300];
  memset (long_server_name, 'b', sizeof (long_server_name) - 1);
  long_server_name[sizeof (long_server_name) - 1] = '\0';

  config.server_address = "8.8.8.8";
  config.server_name = long_server_name;

  ret = SocketDNSoverTLS_configure (dot, &config);
  ASSERT_EQ (ret, -1); /* Should fail due to server name truncation */

  /* Test 3: SPKI pin truncation (buffer size is 64) */
  char long_pin[80];
  memset (long_pin, 'c', sizeof (long_pin) - 1);
  long_pin[sizeof (long_pin) - 1] = '\0';

  config.server_name = "dns.google";
  config.spki_pin = long_pin;

  ret = SocketDNSoverTLS_configure (dot, &config);
  ASSERT_EQ (ret, -1); /* Should fail due to SPKI pin truncation */

  /* Test 4: Valid configuration (no truncation) */
  config.spki_pin = "YZPgTZ+woNCCCIW3LH2CxQeLzB/1m42QcCTBSdgayjs=";
  config.spki_pin_backup = NULL;

  ret = SocketDNSoverTLS_configure (dot, &config);
  ASSERT_EQ (ret, 0); /* Should succeed - all fields fit */
  ASSERT_EQ (SocketDNSoverTLS_server_count (dot), 1);

  SocketDNSoverTLS_free (&dot);
  Arena_dispose (&arena);
}

#else /* !SOCKET_HAS_TLS */

/* Stub test when TLS is disabled */
TEST (dot_tls_disabled)
{
  /* DNS-over-TLS requires TLS support */
  ASSERT (1); /* Pass - TLS is disabled */
}

#endif /* SOCKET_HAS_TLS */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
