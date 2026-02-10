/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_http3_client.c
 * @brief Unit tests for HTTP/3 client API (RFC 9114).
 *
 * Tests the SocketHTTP3_Client_T wrapper including config defaults,
 * client lifecycle, state management, Alt-Svc parsing, and the
 * underlying H3 connection integration.
 */

#ifdef SOCKET_HAS_TLS

#include "core/Arena.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP3-client.h"
#include "http/SocketHTTP3-constants.h"
#include "http/SocketHTTP3.h"
#include "test/Test.h"

#include <string.h>

/* ============================================================================
 * Alt-Svc Parsing Tests (RFC 7838)
 * ============================================================================
 */

TEST (h3_client_alt_svc_basic_port)
{
  char host[256] = { 0 };
  uint16_t port
      = SocketHTTP3_parse_alt_svc ("h3=\":443\"", host, sizeof (host));
  ASSERT_EQ (443, port);
  ASSERT_EQ ('\0', host[0]);
}

TEST (h3_client_alt_svc_with_host)
{
  char host[256] = { 0 };
  uint16_t port = SocketHTTP3_parse_alt_svc (
      "h3=\"alt.example.com:8443\"", host, sizeof (host));
  ASSERT_EQ (8443, port);
  ASSERT_EQ (0, strcmp (host, "alt.example.com"));
}

TEST (h3_client_alt_svc_multiple_entries)
{
  char host[256] = { 0 };
  /* h2 entry first, then h3 */
  uint16_t port = SocketHTTP3_parse_alt_svc (
      "h2=\":443\", h3=\":8443\"", host, sizeof (host));
  ASSERT_EQ (8443, port);
}

TEST (h3_client_alt_svc_null_input)
{
  uint16_t port = SocketHTTP3_parse_alt_svc (NULL, NULL, 0);
  ASSERT_EQ (0, port);
}

TEST (h3_client_alt_svc_no_h3)
{
  char host[256] = { 0 };
  uint16_t port
      = SocketHTTP3_parse_alt_svc ("h2=\":443\"", host, sizeof (host));
  ASSERT_EQ (0, port);
}

TEST (h3_client_alt_svc_empty_string)
{
  char host[256] = { 0 };
  uint16_t port = SocketHTTP3_parse_alt_svc ("", host, sizeof (host));
  ASSERT_EQ (0, port);
}

TEST (h3_client_alt_svc_invalid_port)
{
  char host[256] = { 0 };
  uint16_t port
      = SocketHTTP3_parse_alt_svc ("h3=\":abc\"", host, sizeof (host));
  ASSERT_EQ (0, port);
}

TEST (h3_client_alt_svc_zero_port)
{
  char host[256] = { 0 };
  uint16_t port = SocketHTTP3_parse_alt_svc ("h3=\":0\"", host, sizeof (host));
  ASSERT_EQ (0, port);
}

TEST (h3_client_alt_svc_null_host_buf)
{
  /* host_out=NULL should not crash, just return the port */
  uint16_t port = SocketHTTP3_parse_alt_svc ("h3=\":443\"", NULL, 0);
  ASSERT_EQ (443, port);
}

TEST (h3_client_alt_svc_host_too_long)
{
  /* Host buffer too small to fit the extracted host */
  char host[4] = { 0 };
  uint16_t port = SocketHTTP3_parse_alt_svc (
      "h3=\"longhost.example.com:443\"", host, sizeof (host));
  ASSERT_EQ (443, port);
  /* Host should be empty since it didn't fit */
  ASSERT_EQ ('\0', host[0]);
}

/* ============================================================================
 * Config Defaults Tests
 * ============================================================================
 */

TEST (h3_client_config_defaults)
{
  SocketHTTP3_ClientConfig config;
  memset (&config, 0xFF, sizeof (config));

  SocketHTTP3_ClientConfig_defaults (&config);

  ASSERT_EQ (30000ULL, config.idle_timeout_ms);
  ASSERT_EQ (262144ULL, config.max_stream_data);
  ASSERT_EQ (100ULL, config.initial_max_streams_bidi);
  ASSERT_NULL (config.ca_file);
  ASSERT_EQ (1, config.verify_peer);
  ASSERT_EQ (5000U, config.connect_timeout_ms);
  ASSERT_EQ (30000U, config.request_timeout_ms);
}

TEST (h3_client_config_defaults_null)
{
  /* Should not crash */
  SocketHTTP3_ClientConfig_defaults (NULL);
}

/* ============================================================================
 * Client Creation Tests
 * ============================================================================
 */

TEST (h3_client_new_with_defaults)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Client_T client = SocketHTTP3_Client_new (arena, NULL);
  ASSERT_NOT_NULL (client);
  ASSERT_EQ (0, SocketHTTP3_Client_is_connected (client));

  Arena_dispose (&arena);
}

TEST (h3_client_new_with_config)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ClientConfig config;
  SocketHTTP3_ClientConfig_defaults (&config);
  config.idle_timeout_ms = 60000;
  config.request_timeout_ms = 10000;

  SocketHTTP3_Client_T client = SocketHTTP3_Client_new (arena, &config);
  ASSERT_NOT_NULL (client);
  ASSERT_EQ (0, SocketHTTP3_Client_is_connected (client));

  Arena_dispose (&arena);
}

TEST (h3_client_new_null_arena)
{
  SocketHTTP3_Client_T client = SocketHTTP3_Client_new (NULL, NULL);
  ASSERT_NULL (client);
}

/* ============================================================================
 * Client State Tests
 * ============================================================================
 */

TEST (h3_client_not_connected_state)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Client_T client = SocketHTTP3_Client_new (arena, NULL);
  ASSERT_NOT_NULL (client);

  /* Not connected yet */
  ASSERT_EQ (0, SocketHTTP3_Client_is_connected (client));

  Arena_dispose (&arena);
}

TEST (h3_client_is_connected_null)
{
  ASSERT_EQ (0, SocketHTTP3_Client_is_connected (NULL));
}

TEST (h3_client_conn_accessor)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Client_T client = SocketHTTP3_Client_new (arena, NULL);
  ASSERT_NOT_NULL (client);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Client_conn (client);
  ASSERT_NOT_NULL (conn);

  Arena_dispose (&arena);
}

TEST (h3_client_conn_null)
{
  ASSERT_NULL (SocketHTTP3_Client_conn (NULL));
}

/* ============================================================================
 * Request Before Connect Tests
 * ============================================================================
 */

TEST (h3_client_request_before_connect)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Client_T client = SocketHTTP3_Client_new (arena, NULL);
  ASSERT_NOT_NULL (client);

  /* Request before connect should fail */
  int status = 0;
  int rc = SocketHTTP3_Client_request (
      client, HTTP_METHOD_GET, "/", NULL, NULL, 0, NULL, &status, NULL, NULL);
  ASSERT_EQ (-1, rc);

  Arena_dispose (&arena);
}

TEST (h3_client_request_null_client)
{
  int rc = SocketHTTP3_Client_request (
      NULL, HTTP_METHOD_GET, "/", NULL, NULL, 0, NULL, NULL, NULL, NULL);
  ASSERT_EQ (-1, rc);
}

TEST (h3_client_request_null_path)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Client_T client = SocketHTTP3_Client_new (arena, NULL);
  ASSERT_NOT_NULL (client);

  int rc = SocketHTTP3_Client_request (
      client, HTTP_METHOD_GET, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL);
  ASSERT_EQ (-1, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Streaming API Before Connect Tests
 * ============================================================================
 */

TEST (h3_client_new_request_before_connect)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Client_T client = SocketHTTP3_Client_new (arena, NULL);
  ASSERT_NOT_NULL (client);

  /* Should fail: not connected */
  SocketHTTP3_Request_T req = SocketHTTP3_Client_new_request (client);
  ASSERT_NULL (req);

  Arena_dispose (&arena);
}

TEST (h3_client_flush_before_connect)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Client_T client = SocketHTTP3_Client_new (arena, NULL);
  ASSERT_NOT_NULL (client);

  int rc = SocketHTTP3_Client_flush (client);
  ASSERT_EQ (-1, rc);

  Arena_dispose (&arena);
}

TEST (h3_client_poll_before_connect)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Client_T client = SocketHTTP3_Client_new (arena, NULL);
  ASSERT_NOT_NULL (client);

  int rc = SocketHTTP3_Client_poll (client, 0);
  ASSERT_EQ (-1, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Close Tests
 * ============================================================================
 */

TEST (h3_client_close_without_connect)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Client_T client = SocketHTTP3_Client_new (arena, NULL);
  ASSERT_NOT_NULL (client);

  /* Close without connecting should succeed (no GOAWAY needed) */
  int rc = SocketHTTP3_Client_close (client);
  ASSERT_EQ (0, rc);
  ASSERT_EQ (0, SocketHTTP3_Client_is_connected (client));

  Arena_dispose (&arena);
}

TEST (h3_client_close_null)
{
  int rc = SocketHTTP3_Client_close (NULL);
  ASSERT_EQ (-1, rc);
}

/* ============================================================================
 * Connect Error Tests
 * ============================================================================
 */

TEST (h3_client_connect_null_client)
{
  int rc = SocketHTTP3_Client_connect (NULL, "example.com", 443);
  ASSERT_EQ (-1, rc);
}

TEST (h3_client_connect_null_host)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Client_T client = SocketHTTP3_Client_new (arena, NULL);
  ASSERT_NOT_NULL (client);

  int rc = SocketHTTP3_Client_connect (client, NULL, 443);
  ASSERT_EQ (-1, rc);

  Arena_dispose (&arena);
}

/* ============================================================================
 * Flush/Poll Null Tests
 * ============================================================================
 */

TEST (h3_client_flush_null)
{
  int rc = SocketHTTP3_Client_flush (NULL);
  ASSERT_EQ (-1, rc);
}

TEST (h3_client_poll_null)
{
  int rc = SocketHTTP3_Client_poll (NULL, 0);
  ASSERT_EQ (-1, rc);
}

/* ============================================================================
 * H3 Connection Integration Tests
 * ============================================================================
 */

TEST (h3_client_conn_state_idle)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Client_T client = SocketHTTP3_Client_new (arena, NULL);
  ASSERT_NOT_NULL (client);

  SocketHTTP3_Conn_T conn = SocketHTTP3_Client_conn (client);
  ASSERT_NOT_NULL (conn);

  /* Before connect, H3 connection should be in IDLE state */
  ASSERT_EQ (H3_CONN_STATE_IDLE, SocketHTTP3_Conn_state (conn));

  Arena_dispose (&arena);
}

/* ============================================================================
 * Entry point
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

#else /* !SOCKET_HAS_TLS */

#include <stdio.h>

int
main (void)
{
  printf ("HTTP/3 client tests require TLS support (SOCKET_HAS_TLS)\n");
  return 0;
}

#endif /* SOCKET_HAS_TLS */
