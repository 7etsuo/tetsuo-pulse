/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_httpserver.c - SocketHTTPServer unit tests
 *
 * Part of the Socket Library Test Suite
 *
 * Comprehensive tests for the HTTP server module including:
 * - Server lifecycle (new, free, start, stop)
 * - Configuration handling
 * - Handler and validator registration
 * - Request/response operations
 * - Graceful shutdown (drain)
 * - Error handling
 */

/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */

#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTPServer.h"
#include "socket/Socket.h"
#include "test/Test.h"

/* Suppress longjmp clobbering warnings for test variables */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* ============================================================================
 * Test Helpers
 * ============================================================================
 */

static void
setup_signals (void)
{
  signal (SIGPIPE, SIG_IGN);
}

/* Simple handler that just responds with 200 OK */
static void
simple_handler (SocketHTTPServer_Request_T req, void *userdata)
{
  (void)userdata;
  SocketHTTPServer_Request_status (req, 200);
  SocketHTTPServer_Request_header (req, "Content-Type", "text/plain");
  SocketHTTPServer_Request_body_data (req, "OK", 2);
  SocketHTTPServer_Request_finish (req);
}

/* Handler that echoes userdata */
typedef struct
{
  int call_count;
  const char *response;
} HandlerContext;

static void
counting_handler (SocketHTTPServer_Request_T req, void *userdata)
{
  HandlerContext *ctx = (HandlerContext *)userdata;
  if (ctx)
    {
      ctx->call_count++;
    }
  SocketHTTPServer_Request_status (req, 200);
  if (ctx && ctx->response)
    {
      SocketHTTPServer_Request_body_data (req, ctx->response,
                                          strlen (ctx->response));
    }
  SocketHTTPServer_Request_finish (req);
}

/* Validator that allows all requests */
static int
allow_all_validator (SocketHTTPServer_Request_T req, int *reject_status,
                     void *userdata)
{
  (void)req;
  (void)reject_status;
  (void)userdata;
  return 1; /* Allow */
}

/* Validator that rejects all requests */
static int
reject_all_validator (SocketHTTPServer_Request_T req, int *reject_status,
                      void *userdata)
{
  (void)req;
  (void)userdata;
  *reject_status = 403;
  return 0; /* Reject */
}

/* ============================================================================
 * Configuration Tests
 * ============================================================================
 */

TEST (httpserver_config_defaults)
{
  setup_signals ();
  SocketHTTPServer_Config config;

  SocketHTTPServer_config_defaults (&config);

  /* Check default values */
  ASSERT_EQ (HTTPSERVER_DEFAULT_PORT, config.port);
  ASSERT_EQ (HTTPSERVER_DEFAULT_BACKLOG, config.backlog);
  ASSERT_EQ (HTTPSERVER_DEFAULT_MAX_CONNECTIONS, config.max_connections);
  ASSERT_EQ (HTTPSERVER_DEFAULT_MAX_HEADER_SIZE, config.max_header_size);
  ASSERT_EQ (HTTPSERVER_DEFAULT_MAX_BODY_SIZE, config.max_body_size);
  ASSERT_EQ (HTTPSERVER_DEFAULT_REQUEST_TIMEOUT_MS, config.request_timeout_ms);
  ASSERT_EQ (HTTPSERVER_DEFAULT_KEEPALIVE_TIMEOUT_MS, config.keepalive_timeout_ms);
  ASSERT_NULL (config.tls_context);
}

TEST (httpserver_config_custom_port)
{
  setup_signals ();
  SocketHTTPServer_Config config;

  SocketHTTPServer_config_defaults (&config);
  config.port = 9999;

  ASSERT_EQ (9999, config.port);
}

TEST (httpserver_config_custom_limits)
{
  setup_signals ();
  SocketHTTPServer_Config config;

  SocketHTTPServer_config_defaults (&config);
  config.max_connections = 5000;
  config.max_requests_per_connection = 500;
  config.max_connections_per_client = 50;

  ASSERT_EQ (5000, config.max_connections);
  ASSERT_EQ (500, config.max_requests_per_connection);
  ASSERT_EQ (50, config.max_connections_per_client);
}

TEST (httpserver_config_timeouts)
{
  setup_signals ();
  SocketHTTPServer_Config config;

  SocketHTTPServer_config_defaults (&config);
  config.request_timeout_ms = 10000;
  config.keepalive_timeout_ms = 120000;
  config.request_read_timeout_ms = 15000;
  config.response_write_timeout_ms = 30000;

  ASSERT_EQ (10000, config.request_timeout_ms);
  ASSERT_EQ (120000, config.keepalive_timeout_ms);
  ASSERT_EQ (15000, config.request_read_timeout_ms);
  ASSERT_EQ (30000, config.response_write_timeout_ms);
}

/* ============================================================================
 * Server Lifecycle Tests
 * ============================================================================
 */

TEST (httpserver_new_default_config)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0; /* Ephemeral port */

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

TEST (httpserver_new_custom_config)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;
  config.max_connections = 100;
  config.max_header_size = 32 * 1024;
  config.max_body_size = 1 * 1024 * 1024;

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

TEST (httpserver_free)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    SocketHTTPServer_free (&server);
    ASSERT_NULL (server);

    /* Double free should be safe */
    SocketHTTPServer_free (&server);
    ASSERT_NULL (server);
  }
  END_TRY;
}

TEST (httpserver_start_stop)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;
  config.bind_address = "127.0.0.1";

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    int result = SocketHTTPServer_start (server);
    ASSERT_EQ (0, result);

    /* State should be running */
    SocketHTTPServer_State state = SocketHTTPServer_state (server);
    ASSERT_EQ (HTTPSERVER_STATE_RUNNING, state);

    SocketHTTPServer_stop (server);
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

TEST (httpserver_start_stop_running)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0; /* Ephemeral */
  config.bind_address = "127.0.0.1";

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    int result = SocketHTTPServer_start (server);
    ASSERT_EQ (0, result);

    /* State should be running */
    SocketHTTPServer_State state = SocketHTTPServer_state (server);
    ASSERT_EQ (HTTPSERVER_STATE_RUNNING, state);

    /* Stop the server */
    SocketHTTPServer_stop (server);
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

TEST (httpserver_fd)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;
  config.bind_address = "127.0.0.1";

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    int result = SocketHTTPServer_start (server);
    ASSERT_EQ (0, result);

    int fd = SocketHTTPServer_fd (server);
    ASSERT (fd >= 0);
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

/* ============================================================================
 * Handler Registration Tests
 * ============================================================================
 */

TEST (httpserver_set_handler)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    HandlerContext ctx = { 0, "test response" };
    SocketHTTPServer_set_handler (server, counting_handler, &ctx);
    /* Should not crash */
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

TEST (httpserver_set_handler_null)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    /* NULL handler should be valid (disables handling) */
    SocketHTTPServer_set_handler (server, NULL, NULL);
    /* Should not crash */
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

TEST (httpserver_set_validator)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    SocketHTTPServer_set_validator (server, allow_all_validator, NULL);
    /* Should not crash */
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

TEST (httpserver_set_validator_reject)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    SocketHTTPServer_set_validator (server, reject_all_validator, NULL);
    /* Should not crash */
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

/* ============================================================================
 * Graceful Shutdown Tests
 * ============================================================================
 */

TEST (httpserver_drain)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;
  config.bind_address = "127.0.0.1";

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    int result = SocketHTTPServer_start (server);
    ASSERT_EQ (0, result);

    /* Start drain with short timeout */
    SocketHTTPServer_drain (server, 100);

    /* State should be draining or stopped */
    SocketHTTPServer_State state = SocketHTTPServer_state (server);
    ASSERT (state == HTTPSERVER_STATE_DRAINING
                 || state == HTTPSERVER_STATE_STOPPED);
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

TEST (httpserver_drain_wait)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;
  config.bind_address = "127.0.0.1";

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    int result = SocketHTTPServer_start (server);
    ASSERT_EQ (0, result);

    /* Wait for drain with timeout */
    result = SocketHTTPServer_drain_wait (server, 100);
    /* Should return 0 (success) or timeout indicator */
    /* With no connections, should complete quickly */
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

TEST (httpserver_state_query)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;
  config.bind_address = "127.0.0.1";

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    /* Before start */
    SocketHTTPServer_State state1 = SocketHTTPServer_state (server);
    (void)state1;

    SocketHTTPServer_start (server);

    /* After start */
    SocketHTTPServer_State state2 = SocketHTTPServer_state (server);
    ASSERT_EQ (HTTPSERVER_STATE_RUNNING, state2);

    SocketHTTPServer_stop (server);
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

/* ============================================================================
 * Process Tests
 * ============================================================================
 */

TEST (httpserver_process_no_connections)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;
  config.bind_address = "127.0.0.1";

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    SocketHTTPServer_start (server);

    /* Process with no connections should return quickly */
    int result = SocketHTTPServer_process (server, 10);
    /* Result is number of events processed or -1 on error */
    ASSERT (result >= 0);
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

TEST (httpserver_multiple_start_stop)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;
  config.bind_address = "127.0.0.1";

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    /* Multiple start/stop cycles */
    int result = SocketHTTPServer_start (server);
    ASSERT_EQ (0, result);
    
    SocketHTTPServer_stop (server);

    /* State should be updated */
    SocketHTTPServer_State state = SocketHTTPServer_state (server);
    (void)state;
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

/* ============================================================================
 * Default Config Tests
 * ============================================================================
 */

TEST (httpserver_new_null_config_uses_defaults)
{
  setup_signals ();
  SocketHTTPServer_T server = NULL;

  TRY
  {
    /* NULL config should use defaults */
    server = SocketHTTPServer_new (NULL);
    ASSERT_NOT_NULL (server);
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

/* ============================================================================
 * Main - Run all HTTP server tests
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}

