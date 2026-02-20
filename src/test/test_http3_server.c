/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_http3_server.c
 * @brief Unit tests for HTTP/3 server API (RFC 9114).
 *
 * Tests the SocketHTTP3_Server_T wrapper including config defaults,
 * server lifecycle, handler registration, and NULL parameter handling.
 */

#ifdef SOCKET_HAS_TLS

#include "core/Arena.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP3-server.h"
#include "http/SocketHTTP3.h"
#include "quic/SocketQUICServer.h"
#include "test/Test.h"

#include <string.h>

TEST (h3_server_config_defaults)
{
  SocketHTTP3_ServerConfig config;
  memset (&config, 0xFF, sizeof (config));

  SocketHTTP3_ServerConfig_defaults (&config);

  ASSERT_EQ (0, strcmp (config.bind_addr, "0.0.0.0"));
  ASSERT_EQ (443, config.port);
  ASSERT_EQ (30000ULL, config.idle_timeout_ms);
  ASSERT_EQ (100ULL, config.initial_max_streams_bidi);
  ASSERT_EQ (262144ULL, config.max_stream_data);
  ASSERT_NULL (config.cert_file);
  ASSERT_NULL (config.key_file);
  ASSERT_EQ (256U, config.max_connections);
  ASSERT_EQ (65536U, config.max_header_size);
}

TEST (h3_server_config_defaults_null)
{
  /* Should not crash */
  SocketHTTP3_ServerConfig_defaults (NULL);
}

TEST (h3_server_quic_config_defaults)
{
  SocketQUICServerConfig config;
  memset (&config, 0xFF, sizeof (config));

  SocketQUICServerConfig_defaults (&config);

  ASSERT_EQ (0, strcmp (config.bind_addr, "0.0.0.0"));
  ASSERT_EQ (443, config.port);
  ASSERT_EQ (30000ULL, config.idle_timeout_ms);
  ASSERT_EQ (262144ULL, config.max_stream_data);
  ASSERT_EQ (1048576ULL, config.initial_max_data);
  ASSERT_EQ (100ULL, config.initial_max_streams_bidi);
  ASSERT_NULL (config.cert_file);
  ASSERT_NULL (config.key_file);
  ASSERT_EQ (0, strcmp (config.alpn, "h3"));
  ASSERT_EQ (256U, config.max_connections);
}

TEST (h3_server_new_valid)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ServerConfig config;
  SocketHTTP3_ServerConfig_defaults (&config);
  config.cert_file = "/tmp/cert.pem";
  config.key_file = "/tmp/key.pem";

  SocketHTTP3_Server_T server = SocketHTTP3_Server_new (arena, &config);
  ASSERT_NOT_NULL (server);

  SocketHTTP3_Server_close (server);
  Arena_dispose (&arena);
}

TEST (h3_server_new_null_arena)
{
  SocketHTTP3_ServerConfig config;
  SocketHTTP3_ServerConfig_defaults (&config);
  config.cert_file = "/tmp/cert.pem";
  config.key_file = "/tmp/key.pem";

  SocketHTTP3_Server_T server = SocketHTTP3_Server_new (NULL, &config);
  ASSERT_NULL (server);
}

TEST (h3_server_new_null_config)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_Server_T server = SocketHTTP3_Server_new (arena, NULL);
  ASSERT_NULL (server);
  Arena_dispose (&arena);
}

TEST (h3_server_close_null)
{
  /* Should not crash */
  SocketHTTP3_Server_close (NULL);
}

TEST (h3_server_shutdown_null)
{
  int rc = SocketHTTP3_Server_shutdown (NULL);
  ASSERT_EQ (-1, rc);
}

TEST (h3_server_shutdown_without_start)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ServerConfig config;
  SocketHTTP3_ServerConfig_defaults (&config);
  config.cert_file = "/tmp/cert.pem";
  config.key_file = "/tmp/key.pem";

  SocketHTTP3_Server_T server = SocketHTTP3_Server_new (arena, &config);
  ASSERT_NOT_NULL (server);

  /* Shutdown before start should succeed (no connections to GOAWAY) */
  int rc = SocketHTTP3_Server_shutdown (server);
  ASSERT_EQ (0, rc);

  SocketHTTP3_Server_close (server);
  Arena_dispose (&arena);
}

TEST (h3_server_active_connections_initial)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ServerConfig config;
  SocketHTTP3_ServerConfig_defaults (&config);
  config.cert_file = "/tmp/cert.pem";
  config.key_file = "/tmp/key.pem";

  SocketHTTP3_Server_T server = SocketHTTP3_Server_new (arena, &config);
  ASSERT_NOT_NULL (server);

  ASSERT_EQ (0U, SocketHTTP3_Server_active_connections (server));

  SocketHTTP3_Server_close (server);
  Arena_dispose (&arena);
}

TEST (h3_server_active_connections_null)
{
  ASSERT_EQ (0U, SocketHTTP3_Server_active_connections (NULL));
}

static void
dummy_handler (SocketHTTP3_Request_T req,
               const SocketHTTP_Headers_T headers,
               void *userdata)
{
  (void)req;
  (void)headers;
  (void)userdata;
}

TEST (h3_server_handler_registration)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ServerConfig config;
  SocketHTTP3_ServerConfig_defaults (&config);
  config.cert_file = "/tmp/cert.pem";
  config.key_file = "/tmp/key.pem";

  SocketHTTP3_Server_T server = SocketHTTP3_Server_new (arena, &config);
  ASSERT_NOT_NULL (server);

  int userdata = 42;
  SocketHTTP3_Server_on_request (server, dummy_handler, &userdata);

  /* Just ensure it doesn't crash; internal state is opaque */

  SocketHTTP3_Server_close (server);
  Arena_dispose (&arena);
}

TEST (h3_server_handler_null_server)
{
  /* Should not crash */
  SocketHTTP3_Server_on_request (NULL, dummy_handler, NULL);
}

TEST (h3_server_poll_before_start)
{
  Arena_T arena = Arena_new ();
  SocketHTTP3_ServerConfig config;
  SocketHTTP3_ServerConfig_defaults (&config);
  config.cert_file = "/tmp/cert.pem";
  config.key_file = "/tmp/key.pem";

  SocketHTTP3_Server_T server = SocketHTTP3_Server_new (arena, &config);
  ASSERT_NOT_NULL (server);

  /* Poll before start should fail */
  int rc = SocketHTTP3_Server_poll (server, 0);
  ASSERT_EQ (-1, rc);

  SocketHTTP3_Server_close (server);
  Arena_dispose (&arena);
}

TEST (h3_server_poll_null)
{
  int rc = SocketHTTP3_Server_poll (NULL, 0);
  ASSERT_EQ (-1, rc);
}

TEST (h3_server_start_null)
{
  int rc = SocketHTTP3_Server_start (NULL);
  ASSERT_EQ (-1, rc);
}

TEST (h3_server_request_new_incoming_valid)
{
  Arena_T arena = Arena_new ();

  /* Create a server-role H3 connection */
  SocketHTTP3_ConnConfig h3_config;
  SocketHTTP3_ConnConfig_defaults (&h3_config, H3_ROLE_SERVER);
  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &h3_config);
  ASSERT_NOT_NULL (conn);

  /* Initialize to OPEN state */
  int rc = SocketHTTP3_Conn_init (conn);
  ASSERT_EQ (0, rc);

  /* Create incoming request for client-initiated bidi stream 0 */
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new_incoming (conn, 0);
  ASSERT_NOT_NULL (req);
  ASSERT_EQ (0ULL, SocketHTTP3_Request_stream_id (req));

  Arena_dispose (&arena);
}

TEST (h3_server_request_new_incoming_stream4)
{
  Arena_T arena = Arena_new ();

  SocketHTTP3_ConnConfig h3_config;
  SocketHTTP3_ConnConfig_defaults (&h3_config, H3_ROLE_SERVER);
  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &h3_config);
  ASSERT_NOT_NULL (conn);

  int rc = SocketHTTP3_Conn_init (conn);
  ASSERT_EQ (0, rc);

  /* Stream 4 is the second client-initiated bidi stream */
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new_incoming (conn, 4);
  ASSERT_NOT_NULL (req);
  ASSERT_EQ (4ULL, SocketHTTP3_Request_stream_id (req));

  Arena_dispose (&arena);
}

TEST (h3_server_request_new_incoming_reject_unidi)
{
  Arena_T arena = Arena_new ();

  SocketHTTP3_ConnConfig h3_config;
  SocketHTTP3_ConnConfig_defaults (&h3_config, H3_ROLE_SERVER);
  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &h3_config);
  ASSERT_NOT_NULL (conn);

  int rc = SocketHTTP3_Conn_init (conn);
  ASSERT_EQ (0, rc);

  /* Stream 2 is client-initiated unidirectional — should be rejected */
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new_incoming (conn, 2);
  ASSERT_NULL (req);

  Arena_dispose (&arena);
}

TEST (h3_server_request_new_incoming_reject_server_bidi)
{
  Arena_T arena = Arena_new ();

  SocketHTTP3_ConnConfig h3_config;
  SocketHTTP3_ConnConfig_defaults (&h3_config, H3_ROLE_SERVER);
  SocketHTTP3_Conn_T conn = SocketHTTP3_Conn_new (arena, NULL, &h3_config);
  ASSERT_NOT_NULL (conn);

  int rc = SocketHTTP3_Conn_init (conn);
  ASSERT_EQ (0, rc);

  /* Stream 1 is server-initiated bidi — should be rejected */
  SocketHTTP3_Request_T req = SocketHTTP3_Request_new_incoming (conn, 1);
  ASSERT_NULL (req);

  Arena_dispose (&arena);
}

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
  printf ("HTTP/3 server tests require TLS support (SOCKET_HAS_TLS)\n");
  return 0;
}

#endif /* SOCKET_HAS_TLS */
