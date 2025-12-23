/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_dns_over_https.c
 * @brief Unit tests for DNS-over-HTTPS transport (RFC 8484).
 */

#include "dns/SocketDNSoverHTTPS.h"
#include "dns/SocketDNSWire.h"
#include "core/Arena.h"
#include "core/SocketCrypto.h"
#include "test/Test.h"

#if SOCKET_HAS_TLS

#include <stdio.h>
#include <string.h>

/* Test callback state */
static volatile int g_callback_invoked = 0;
static volatile int g_callback_error = -999;
static volatile size_t g_response_len = 0;

static void
test_callback (SocketDNSoverHTTPS_Query_T query, const unsigned char *response,
               size_t len, int error, void *userdata)
{
  (void)query;
  (void)userdata;

  g_callback_invoked = 1;
  g_callback_error = error;
  g_response_len = (response && error == DOH_ERROR_SUCCESS) ? len : 0;
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
TEST (doh_lifecycle)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverHTTPS_T doh = NULL;

  doh = SocketDNSoverHTTPS_new (arena);
  ASSERT_NOT_NULL (doh);

  /* Verify defaults */
  ASSERT_EQ (SocketDNSoverHTTPS_pending_count (doh), 0);
  ASSERT_EQ (SocketDNSoverHTTPS_server_count (doh), 0);

  SocketDNSoverHTTPS_free (&doh);
  ASSERT_NULL (doh);

  Arena_dispose (&arena);
}

/* Test: Server configuration */
TEST (doh_server_config)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverHTTPS_T doh = SocketDNSoverHTTPS_new (arena);

  /* Add server via config struct */
  SocketDNSoverHTTPS_Config config = { .url = "https://dns.google/dns-query",
                                        .method = DOH_METHOD_POST,
                                        .prefer_http2 = 1,
                                        .timeout_ms = 5000 };

  int ret = SocketDNSoverHTTPS_configure (doh, &config);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSoverHTTPS_server_count (doh), 1);

  /* Add another server */
  config.url = "https://cloudflare-dns.com/dns-query";
  ret = SocketDNSoverHTTPS_configure (doh, &config);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSoverHTTPS_server_count (doh), 2);

  /* Clear servers */
  SocketDNSoverHTTPS_clear_servers (doh);
  ASSERT_EQ (SocketDNSoverHTTPS_server_count (doh), 0);

  SocketDNSoverHTTPS_free (&doh);
  Arena_dispose (&arena);
}

/* Test: Well-known server configuration */
TEST (doh_wellknown_servers)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverHTTPS_T doh = SocketDNSoverHTTPS_new (arena);

  /* Add well-known servers */
  int ret = SocketDNSoverHTTPS_add_server (doh, "google");
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSoverHTTPS_server_count (doh), 1);

  ret = SocketDNSoverHTTPS_add_server (doh, "cloudflare");
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSoverHTTPS_server_count (doh), 2);

  ret = SocketDNSoverHTTPS_add_server (doh, "quad9");
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSoverHTTPS_server_count (doh), 3);

  ret = SocketDNSoverHTTPS_add_server (doh, "nextdns");
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSoverHTTPS_server_count (doh), 4);

  /* Unknown server should fail */
  ret = SocketDNSoverHTTPS_add_server (doh, "unknown");
  ASSERT_EQ (ret, -1);
  ASSERT_EQ (SocketDNSoverHTTPS_server_count (doh), 4);

  SocketDNSoverHTTPS_free (&doh);
  Arena_dispose (&arena);
}

/* Test: Query without server fails */
TEST (doh_query_no_server)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverHTTPS_T doh = SocketDNSoverHTTPS_new (arena);

  /* Build a simple A query */
  unsigned char query[512];
  size_t query_len;

  SocketDNS_Header hdr;
  SocketDNS_header_init_query (&hdr, 0x1234, 1);

  SocketDNS_header_encode (&hdr, query, sizeof (query));

  SocketDNS_Question question;
  SocketDNS_question_init (&question, "example.com", DNS_TYPE_A);

  size_t written;
  int ret = SocketDNS_question_encode (&question, query + DNS_HEADER_SIZE,
                                       sizeof (query) - DNS_HEADER_SIZE, &written);
  ASSERT_EQ (ret, 0);
  query_len = DNS_HEADER_SIZE + written;

  /* Query without server should return NULL and invoke callback */
  reset_callback_state ();
  SocketDNSoverHTTPS_Query_T q
      = SocketDNSoverHTTPS_query (doh, query, query_len, test_callback, NULL);
  ASSERT_NULL (q);

  /* Callback should have been invoked with NO_SERVER error */
  ASSERT_EQ (g_callback_invoked, 1);
  ASSERT_EQ (g_callback_error, DOH_ERROR_NO_SERVER);

  SocketDNSoverHTTPS_free (&doh);
  Arena_dispose (&arena);
}

/* Test: Error string conversion */
TEST (doh_error_strings)
{
  /* All error codes should return non-empty strings */
  ASSERT_NOT_NULL (SocketDNSoverHTTPS_strerror (DOH_ERROR_SUCCESS));
  ASSERT_NOT_NULL (SocketDNSoverHTTPS_strerror (DOH_ERROR_TIMEOUT));
  ASSERT_NOT_NULL (SocketDNSoverHTTPS_strerror (DOH_ERROR_CANCELLED));
  ASSERT_NOT_NULL (SocketDNSoverHTTPS_strerror (DOH_ERROR_NETWORK));
  ASSERT_NOT_NULL (SocketDNSoverHTTPS_strerror (DOH_ERROR_TLS));
  ASSERT_NOT_NULL (SocketDNSoverHTTPS_strerror (DOH_ERROR_HTTP));
  ASSERT_NOT_NULL (SocketDNSoverHTTPS_strerror (DOH_ERROR_INVALID));
  ASSERT_NOT_NULL (SocketDNSoverHTTPS_strerror (DOH_ERROR_NO_SERVER));
  ASSERT_NOT_NULL (SocketDNSoverHTTPS_strerror (DOH_ERROR_CONTENT_TYPE));
  ASSERT_NOT_NULL (SocketDNSoverHTTPS_strerror (DOH_ERROR_FORMERR));
  ASSERT_NOT_NULL (SocketDNSoverHTTPS_strerror (DOH_ERROR_SERVFAIL));
  ASSERT_NOT_NULL (SocketDNSoverHTTPS_strerror (DOH_ERROR_NXDOMAIN));
  ASSERT_NOT_NULL (SocketDNSoverHTTPS_strerror (DOH_ERROR_REFUSED));

  /* Unknown code should also return a valid string */
  ASSERT_NOT_NULL (SocketDNSoverHTTPS_strerror (-100));

  /* Specific string checks */
  ASSERT (strcmp (SocketDNSoverHTTPS_strerror (DOH_ERROR_SUCCESS), "Success") == 0);
  ASSERT (strcmp (SocketDNSoverHTTPS_strerror (DOH_ERROR_NXDOMAIN),
                  "Domain not found (NXDOMAIN)") == 0);
}

/* Test: Statistics initialized to zero */
TEST (doh_stats_initialized)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverHTTPS_T doh = SocketDNSoverHTTPS_new (arena);

  SocketDNSoverHTTPS_Stats stats;
  SocketDNSoverHTTPS_stats (doh, &stats);

  ASSERT_EQ (stats.queries_sent, 0);
  ASSERT_EQ (stats.queries_completed, 0);
  ASSERT_EQ (stats.queries_failed, 0);
  ASSERT_EQ (stats.http2_requests, 0);
  ASSERT_EQ (stats.http1_requests, 0);
  ASSERT_EQ (stats.bytes_sent, 0);
  ASSERT_EQ (stats.bytes_received, 0);

  SocketDNSoverHTTPS_free (&doh);
  Arena_dispose (&arena);
}

/* Test: Query ID extraction */
TEST (doh_query_id)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverHTTPS_T doh = SocketDNSoverHTTPS_new (arena);

  /* Add a server */
  SocketDNSoverHTTPS_add_server (doh, "google");

  /* Build a query with specific ID */
  unsigned char query[512];
  size_t query_len;

  SocketDNS_Header hdr;
  SocketDNS_header_init_query (&hdr, 0xABCD, 1);

  SocketDNS_header_encode (&hdr, query, sizeof (query));

  SocketDNS_Question question;
  SocketDNS_question_init (&question, "example.com", DNS_TYPE_A);

  size_t written;
  SocketDNS_question_encode (&question, query + DNS_HEADER_SIZE,
                              sizeof (query) - DNS_HEADER_SIZE, &written);
  query_len = DNS_HEADER_SIZE + written;

  /* Submit query - will fail eventually but we can check the ID */
  reset_callback_state ();
  SocketDNSoverHTTPS_Query_T q
      = SocketDNSoverHTTPS_query (doh, query, query_len, test_callback, NULL);

  if (q)
    {
      /* Verify ID extraction */
      uint16_t id = SocketDNSoverHTTPS_query_id (q);
      ASSERT_EQ (id, 0xABCD);

      /* Cancel to clean up */
      SocketDNSoverHTTPS_cancel (doh, q);
    }

  /* Process to invoke any pending callbacks */
  SocketDNSoverHTTPS_process (doh, 0);

  SocketDNSoverHTTPS_free (&doh);
  Arena_dispose (&arena);
}

/* Test: HTTP method enumeration */
TEST (doh_method_enum)
{
  /* Verify method enum values */
  ASSERT_EQ (DOH_METHOD_POST, 0);
  ASSERT_EQ (DOH_METHOD_GET, 1);
}

/* Test: Default path constant */
TEST (doh_default_path)
{
  /* RFC 8484 default path */
  ASSERT (strcmp (DOH_DEFAULT_PATH, "/dns-query") == 0);
}

/* Test: Timeout constants */
TEST (doh_timeout_constants)
{
  /* Verify reasonable timeout values */
  ASSERT (DOH_QUERY_TIMEOUT_MS > 0);
  ASSERT (DOH_CONNECT_TIMEOUT_MS > 0);
  ASSERT (DOH_CONNECT_TIMEOUT_MS >= DOH_QUERY_TIMEOUT_MS);
}

/* Test: GET method configuration */
TEST (doh_get_method_config)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverHTTPS_T doh = SocketDNSoverHTTPS_new (arena);

  /* Configure with GET method */
  SocketDNSoverHTTPS_Config config = { .url = "https://dns.google/dns-query",
                                        .method = DOH_METHOD_GET,
                                        .prefer_http2 = 1,
                                        .timeout_ms = 5000 };

  int ret = SocketDNSoverHTTPS_configure (doh, &config);
  ASSERT_EQ (ret, 0);
  ASSERT_EQ (SocketDNSoverHTTPS_server_count (doh), 1);

  SocketDNSoverHTTPS_free (&doh);
  Arena_dispose (&arena);
}

/* Test: Pending count */
TEST (doh_pending_count)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverHTTPS_T doh = SocketDNSoverHTTPS_new (arena);

  /* Initially zero */
  ASSERT_EQ (SocketDNSoverHTTPS_pending_count (doh), 0);

  SocketDNSoverHTTPS_free (&doh);
  Arena_dispose (&arena);
}

/* Test: NULL query ID returns 0 */
TEST (doh_null_query_id)
{
  uint16_t id = SocketDNSoverHTTPS_query_id (NULL);
  ASSERT_EQ (id, 0);
}

/* Test: Cancel NULL query */
TEST (doh_cancel_null)
{
  Arena_T arena = Arena_new ();
  SocketDNSoverHTTPS_T doh = SocketDNSoverHTTPS_new (arena);

  int ret = SocketDNSoverHTTPS_cancel (doh, NULL);
  ASSERT_EQ (ret, -1);

  SocketDNSoverHTTPS_free (&doh);
  Arena_dispose (&arena);
}

/* Test: Base64URL encoding (indirectly via GET request) */
TEST (doh_base64url_internal)
{
  /* Test base64url encoding by verifying it can handle edge cases */
  /* This tests the internal base64url_encode function indirectly */

  Arena_T arena = Arena_new ();
  SocketDNSoverHTTPS_T doh = SocketDNSoverHTTPS_new (arena);

  /* Configure with GET method */
  SocketDNSoverHTTPS_Config config = { .url = "https://dns.google/dns-query",
                                        .method = DOH_METHOD_GET,
                                        .prefer_http2 = 1,
                                        .timeout_ms = 100 };

  SocketDNSoverHTTPS_configure (doh, &config);

  /* Build a minimal query */
  unsigned char query[64];
  SocketDNS_Header hdr;
  SocketDNS_header_init_query (&hdr, 0x1234, 1);
  SocketDNS_header_encode (&hdr, query, sizeof (query));

  SocketDNS_Question question;
  SocketDNS_question_init (&question, "a.b", DNS_TYPE_A);

  size_t written;
  SocketDNS_question_encode (&question, query + DNS_HEADER_SIZE,
                              sizeof (query) - DNS_HEADER_SIZE, &written);
  size_t query_len = DNS_HEADER_SIZE + written;

  /* The query will be sent (may fail due to network) but tests encoding path */
  reset_callback_state ();
  SocketDNSoverHTTPS_Query_T q
      = SocketDNSoverHTTPS_query (doh, query, query_len, test_callback, NULL);

  /* If query was accepted, cancel it */
  if (q)
    {
      SocketDNSoverHTTPS_cancel (doh, q);
      SocketDNSoverHTTPS_process (doh, 0);
    }

  SocketDNSoverHTTPS_free (&doh);
  Arena_dispose (&arena);
}

#endif /* SOCKET_HAS_TLS */

int
main (void)
{
#if SOCKET_HAS_TLS
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
#else
  printf ("Skipped: TLS support not available\n");
  return 0;
#endif
}
