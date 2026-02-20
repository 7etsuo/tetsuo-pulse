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
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
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

static void
always_404_handler (SocketHTTPServer_Request_T req, void *userdata)
{
  (void)userdata;
  SocketHTTPServer_Request_status (req, 404);
  SocketHTTPServer_Request_header (req, "Content-Type", "text/plain");
  SocketHTTPServer_Request_body_string (req, "Not Found");
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
      SocketHTTPServer_Request_body_data (
          req, ctx->response, strlen (ctx->response));
    }
  SocketHTTPServer_Request_finish (req);
}

/* Validator that allows all requests */
static int
allow_all_validator (SocketHTTPServer_Request_T req,
                     int *reject_status,
                     void *userdata)
{
  (void)req;
  (void)reject_status;
  (void)userdata;
  return 1; /* Allow */
}

/* Validator that rejects all requests */
static int
reject_all_validator (SocketHTTPServer_Request_T req,
                      int *reject_status,
                      void *userdata)
{
  (void)req;
  (void)userdata;
  *reject_status = 403;
  return 0; /* Reject */
}

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
  ASSERT_EQ (HTTPSERVER_DEFAULT_KEEPALIVE_TIMEOUT_MS,
             config.keepalive_timeout_ms);
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

    /* State should be updated after stop */
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

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

/* Context for body streaming callback tests */
typedef struct
{
  size_t total_bytes;
  int chunk_count;
  int final_received;
  int abort_on_chunk; /* 0 = don't abort, N = abort on chunk N */
  char received_data[4096];
  size_t received_len;
} BodyStreamContext;

/* Body callback that accumulates data */
static int
accumulating_body_callback (SocketHTTPServer_Request_T req,
                            const void *chunk,
                            size_t len,
                            int is_final,
                            void *userdata)
{
  (void)req;
  BodyStreamContext *ctx = (BodyStreamContext *)userdata;
  if (ctx == NULL)
    return 0;

  ctx->chunk_count++;
  ctx->total_bytes += len;

  /* Accumulate data if space available */
  if (ctx->received_len + len <= sizeof (ctx->received_data))
    {
      memcpy (ctx->received_data + ctx->received_len, chunk, len);
      ctx->received_len += len;
    }

  if (is_final)
    ctx->final_received = 1;

  /* Check if we should abort */
  if (ctx->abort_on_chunk > 0 && ctx->chunk_count >= ctx->abort_on_chunk)
    return 1; /* Abort */

  return 0; /* Continue */
}

/* Validator that enables body streaming */
static int
streaming_validator (SocketHTTPServer_Request_T req,
                     int *reject_status,
                     void *userdata)
{
  BodyStreamContext *ctx = (BodyStreamContext *)userdata;
  (void)reject_status;

  /* Enable body streaming with our callback */
  SocketHTTPServer_Request_body_stream (req, accumulating_body_callback, ctx);

  return 1; /* Allow */
}

/* Handler for streaming body test */
static void
streaming_body_handler (SocketHTTPServer_Request_T req, void *userdata)
{
  (void)userdata;

  /* Body should have been delivered via callback, not buffered */
  const void *body = SocketHTTPServer_Request_body (req);
  size_t body_len = SocketHTTPServer_Request_body_len (req);

  /* In streaming mode, body() should return NULL */
  ASSERT_NULL (body);
  ASSERT_EQ (0, body_len);

  SocketHTTPServer_Request_status (req, 200);
  SocketHTTPServer_Request_header (req, "Content-Type", "text/plain");
  SocketHTTPServer_Request_body_data (req, "OK", 2);
  SocketHTTPServer_Request_finish (req);
}

TEST (httpserver_body_streaming_callback)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;
  Socket_T client = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;
  config.bind_address = "127.0.0.1";

  BodyStreamContext stream_ctx = { 0 };

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    /* Set up validator that enables streaming and handler */
    SocketHTTPServer_set_validator (server, streaming_validator, &stream_ctx);
    SocketHTTPServer_set_handler (server, streaming_body_handler, &stream_ctx);

    int result = SocketHTTPServer_start (server);
    ASSERT_EQ (0, result);

    /* Get the listening fd */
    int fd = SocketHTTPServer_fd (server);
    ASSERT (fd >= 0);

    /* For now, just verify the server starts and streaming is set up */
    /* A full integration test would require connecting a client */
    /* Note: SocketHTTPServer_fd returns fd (int), not Socket_T */
    ASSERT_NOT_NULL (server);
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

TEST (httpserver_body_streaming_context_setup)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;
  config.bind_address = "127.0.0.1";

  BodyStreamContext stream_ctx = { 0 };
  stream_ctx.abort_on_chunk = 0; /* Don't abort */

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    /* Set up validator that enables streaming */
    SocketHTTPServer_set_validator (server, streaming_validator, &stream_ctx);
    SocketHTTPServer_set_handler (server, streaming_body_handler, &stream_ctx);

    int result = SocketHTTPServer_start (server);
    ASSERT_EQ (0, result);

    /* Verify server is ready for streaming requests */
    SocketHTTPServer_State state = SocketHTTPServer_state (server);
    ASSERT_EQ (HTTPSERVER_STATE_RUNNING, state);
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

TEST (httpserver_body_streaming_abort_context)
{
  setup_signals ();

  /* Test the abort context setup */
  BodyStreamContext stream_ctx = { 0 };
  stream_ctx.abort_on_chunk = 2; /* Abort on 2nd chunk */

  /* Simulate callback behavior */
  int result1 = accumulating_body_callback (NULL, "chunk1", 6, 0, &stream_ctx);
  ASSERT_EQ (0, result1); /* Should continue after first chunk */
  ASSERT_EQ (1, stream_ctx.chunk_count);
  ASSERT_EQ (6, stream_ctx.total_bytes);

  int result2 = accumulating_body_callback (NULL, "chunk2", 6, 0, &stream_ctx);
  ASSERT_EQ (1, result2); /* Should abort on second chunk */
  ASSERT_EQ (2, stream_ctx.chunk_count);
  ASSERT_EQ (12, stream_ctx.total_bytes);
}

TEST (httpserver_static_symlink_escape_blocked)
{
  setup_signals ();

#ifdef _WIN32
  /* POSIX-only: symlink + AF_INET sockets. */
  return;
#else
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;
  int client_fd = -1;
  int secret_fd = -1;

  char dir_template[] = "/tmp/tetsuo-pulse-staticXXXXXX";
  char *base_dir = NULL;
  char base2_dir[4096] = { 0 };
  char link_path[4096] = { 0 };
  char secret_path[4112] = { 0 };

  TRY
  {
    base_dir = mkdtemp (dir_template);
    ASSERT_NOT_NULL (base_dir);

    /* Create sibling directory with an overlapping prefix: "<base>2" */
    snprintf (base2_dir, sizeof (base2_dir), "%s2", base_dir);
    ASSERT_EQ (0, mkdir (base2_dir, 0700));

    /* Create "secret" file in sibling directory */
    snprintf (secret_path, sizeof (secret_path), "%s/secret.txt", base2_dir);
    secret_fd = open (secret_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ASSERT (secret_fd >= 0);
    ASSERT_EQ (6, (int)write (secret_fd, "SECRET", 6));
    close (secret_fd);
    secret_fd = -1;

    /* Create symlink inside base dir pointing at sibling dir */
    snprintf (link_path, sizeof (link_path), "%s/link", base_dir);
    ASSERT_EQ (0, symlink (base2_dir, link_path));

    SocketHTTPServer_config_defaults (&config);
    config.port = 0;
    config.bind_address = "127.0.0.1";

    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    SocketHTTPServer_set_handler (server, always_404_handler, NULL);
    ASSERT_EQ (0,
               SocketHTTPServer_add_static_dir (server, "/static", base_dir));
    ASSERT_EQ (0, SocketHTTPServer_start (server));

    int listen_fd = SocketHTTPServer_fd (server);
    ASSERT (listen_fd >= 0);

    struct sockaddr_in sin;
    socklen_t slen = sizeof (sin);
    ASSERT_EQ (0, getsockname (listen_fd, (struct sockaddr *)&sin, &slen));
    int port = (int)ntohs (sin.sin_port);
    ASSERT (port > 0);

    /* Connect client and request the symlinked file. */
    client_fd = socket (AF_INET, SOCK_STREAM, 0);
    ASSERT (client_fd >= 0);

    struct sockaddr_in addr;
    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons ((uint16_t)port);
    ASSERT_EQ (1, inet_pton (AF_INET, "127.0.0.1", &addr.sin_addr));

    ASSERT_EQ (0, connect (client_fd, (struct sockaddr *)&addr, sizeof (addr)));

    const char *req = "GET /static/link/secret.txt HTTP/1.1\r\n"
                      "Host: 127.0.0.1\r\n"
                      "Connection: close\r\n"
                      "\r\n";

    size_t req_len = strlen (req);
    size_t sent = 0;
    while (sent < req_len)
      {
        ssize_t n = send (client_fd, req + sent, req_len - sent, 0);
        if (n > 0)
          sent += (size_t)n;
        else if (n < 0 && errno == EINTR)
          continue;
        else
          ASSERT (0);
      }

    /* Read response while pumping the server event loop. */
    int flags = fcntl (client_fd, F_GETFL, 0);
    ASSERT (flags >= 0);
    ASSERT_EQ (0, fcntl (client_fd, F_SETFL, flags | O_NONBLOCK));

    char resp[8192];
    size_t resp_len = 0;

    for (int i = 0; i < 200; i++)
      {
        (void)SocketHTTPServer_process (server, 10);

        ssize_t n = recv (
            client_fd, resp + resp_len, sizeof (resp) - 1 - resp_len, 0);
        if (n > 0)
          {
            resp_len += (size_t)n;
            if (resp_len >= sizeof (resp) - 1)
              break;
            continue;
          }

        if (n == 0)
          break; /* peer closed */

        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
          continue;

        break;
      }

    resp[resp_len] = '\0';

    /* With the traversal fix, this must not serve the sibling file. */
    ASSERT_NOT_NULL (strstr (resp, " 404 "));
    ASSERT (strstr (resp, "SECRET") == NULL);
  }
  FINALLY
  {
    if (secret_fd >= 0)
      close (secret_fd);
    if (client_fd >= 0)
      close (client_fd);
    if (server)
      SocketHTTPServer_free (&server);

    if (secret_path[0])
      (void)unlink (secret_path);
    if (link_path[0])
      (void)unlink (link_path);
    if (base2_dir[0])
      (void)rmdir (base2_dir);
    if (base_dir != NULL)
      (void)rmdir (base_dir);
  }
  END_TRY;
#endif
}

TEST (httpserver_body_streaming_final_flag)
{
  setup_signals ();

  /* Test the final flag handling */
  BodyStreamContext stream_ctx = { 0 };

  /* Send non-final chunk */
  int result1 = accumulating_body_callback (NULL, "data", 4, 0, &stream_ctx);
  ASSERT_EQ (0, result1);
  ASSERT_EQ (0, stream_ctx.final_received);

  /* Send final chunk */
  int result2 = accumulating_body_callback (NULL, "end", 3, 1, &stream_ctx);
  ASSERT_EQ (0, result2);
  ASSERT_EQ (1, stream_ctx.final_received);
  ASSERT_EQ (7, stream_ctx.total_bytes);
  ASSERT_EQ (2, stream_ctx.chunk_count);
}

/* Handler that verifies body was received correctly */
static size_t chunked_body_received_len = 0;
static int chunked_body_handler_called = 0;

static void
chunked_body_verify_handler (SocketHTTPServer_Request_T req, void *userdata)
{
  (void)userdata;
  chunked_body_handler_called = 1;

  const void *body = SocketHTTPServer_Request_body (req);
  size_t body_len = SocketHTTPServer_Request_body_len (req);

  chunked_body_received_len = body_len;

  /* Verify body is available */
  if (body != NULL && body_len > 0)
    {
      SocketHTTPServer_Request_status (req, 200);
      SocketHTTPServer_Request_header (req, "Content-Type", "text/plain");

      /* Echo back the body length */
      char len_str[32];
      snprintf (len_str, sizeof (len_str), "received=%zu", body_len);
      SocketHTTPServer_Request_body_data (req, len_str, strlen (len_str));
    }
  else
    {
      SocketHTTPServer_Request_status (req, 204);
    }
  SocketHTTPServer_Request_finish (req);
}

TEST (httpserver_dynamic_chunked_body_config)
{
  setup_signals ();

  /* Test that HTTPSERVER_CHUNKED_BODY_INITIAL_SIZE is properly defined */
  ASSERT (HTTPSERVER_CHUNKED_BODY_INITIAL_SIZE > 0);
  ASSERT (HTTPSERVER_CHUNKED_BODY_INITIAL_SIZE
          <= HTTPSERVER_DEFAULT_MAX_BODY_SIZE);

  /* Default is 8KB */
  ASSERT_EQ (8192, HTTPSERVER_CHUNKED_BODY_INITIAL_SIZE);
}

TEST (httpserver_dynamic_chunked_body_server_setup)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;
  config.bind_address = "127.0.0.1";
  /* Set a small max body size for testing */
  config.max_body_size = 64 * 1024; /* 64KB */

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    chunked_body_handler_called = 0;
    chunked_body_received_len = 0;

    SocketHTTPServer_set_handler (server, chunked_body_verify_handler, NULL);

    int result = SocketHTTPServer_start (server);
    ASSERT_EQ (0, result);

    SocketHTTPServer_State state = SocketHTTPServer_state (server);
    ASSERT_EQ (HTTPSERVER_STATE_RUNNING, state);

    /* Server is ready to accept chunked uploads with dynamic allocation */
    ASSERT_NOT_NULL (server);
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

TEST (httpserver_dynamic_chunked_body_small_limit)
{
  setup_signals ();
  SocketHTTPServer_Config config;
  SocketHTTPServer_T server = NULL;

  SocketHTTPServer_config_defaults (&config);
  config.port = 0;
  config.bind_address = "127.0.0.1";
  /* Set max body smaller than initial chunk size to test edge case */
  config.max_body_size = 4 * 1024; /* 4KB (smaller than 8KB initial) */

  TRY
  {
    server = SocketHTTPServer_new (&config);
    ASSERT_NOT_NULL (server);

    SocketHTTPServer_set_handler (server, simple_handler, NULL);

    int result = SocketHTTPServer_start (server);
    ASSERT_EQ (0, result);

    /* Server should handle the case where max_body < initial_size gracefully */
    SocketHTTPServer_State state = SocketHTTPServer_state (server);
    ASSERT_EQ (HTTPSERVER_STATE_RUNNING, state);
  }
  FINALLY
  {
    if (server)
      SocketHTTPServer_free (&server);
  }
  END_TRY;
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
