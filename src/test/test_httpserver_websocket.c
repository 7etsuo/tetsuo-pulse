/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_httpserver_websocket.c - HTTP Server WebSocket Integration Tests
 *
 * Tests for WebSocket upgrade and poll loop integration in the HTTP server.
 * Verifies that upgraded WebSocket connections remain in the server's event
 * loop and deliver messages via callback.
 *
 * Tests:
 * - State transitions (HTTP -> WebSocket)
 * - Callback invocation for messages
 * - Finality flag handling
 * - Poll integration
 * - Resource cleanup
 * - Error handling
 */

/* cppcheck-suppress-file variableScope ; volatile across TRY/EXCEPT */

#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "http/SocketHTTPServer.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketWS.h"
#include "test/Test.h"

/* Suppress longjmp clobbering warnings for test variables */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* ============================================================================
 * Test Configuration
 * ============================================================================
 */

#define TEST_PORT_BASE 47000
#define TEST_HOST "127.0.0.1"
#define TEST_TIMEOUT_MS 5000

static int httpserver_ws_port_counter = 0;

static int
get_httpserver_ws_port (void)
{
  return TEST_PORT_BASE + (httpserver_ws_port_counter++ % 1000);
}

static void
setup_signals (void)
{
  signal (SIGPIPE, SIG_IGN);
}

/* ============================================================================
 * Callback Context for Testing
 * ============================================================================
 */

typedef struct
{
  atomic_int message_count;
  atomic_int final_received;
  atomic_int close_received;
  char last_message[1024];
  size_t last_message_len;
  pthread_mutex_t mutex;
} WSCallbackContext;

static void
ws_callback_ctx_init (WSCallbackContext *ctx)
{
  memset (ctx, 0, sizeof (*ctx));
  pthread_mutex_init (&ctx->mutex, NULL);
}

static void
ws_callback_ctx_destroy (WSCallbackContext *ctx)
{
  pthread_mutex_destroy (&ctx->mutex);
}

/* Body callback that records received WebSocket messages */
static int
ws_test_callback (SocketHTTPServer_Request_T req,
                  const void *chunk,
                  size_t len,
                  int is_final,
                  void *userdata)
{
  WSCallbackContext *ctx = (WSCallbackContext *)userdata;

  (void)req;

  if (ctx == NULL)
    return 0;

  pthread_mutex_lock (&ctx->mutex);

  atomic_fetch_add (&ctx->message_count, 1);

  if (is_final)
    atomic_store (&ctx->final_received, 1);

  /* Store last message */
  if (len > 0 && len < sizeof (ctx->last_message))
    {
      memcpy (ctx->last_message, chunk, len);
      ctx->last_message_len = len;
    }

  pthread_mutex_unlock (&ctx->mutex);

  return 0; /* Continue */
}

/* ============================================================================
 * Server Fixture
 * ============================================================================
 */

typedef struct
{
  SocketHTTPServer_T server;
  int port;
  pthread_t thread;
  atomic_int running;
  atomic_int stop_flag;
  WSCallbackContext *callback_ctx;
  atomic_int upgrade_count;
  SocketWS_T last_ws;
} WSServerFixture;

/* Handler that upgrades WebSocket requests */
static void
ws_upgrade_handler (SocketHTTPServer_Request_T req, void *userdata)
{
  WSServerFixture *fixture = (WSServerFixture *)userdata;

  if (SocketHTTPServer_Request_is_websocket (req))
    {
      SocketWS_T ws = SocketHTTPServer_Request_upgrade_websocket (
          req, ws_test_callback, fixture->callback_ctx);
      if (ws != NULL)
        {
          atomic_fetch_add (&fixture->upgrade_count, 1);
          fixture->last_ws = ws;
        }
      return;
    }

  /* Non-WebSocket request - return 200 OK */
  SocketHTTPServer_Request_status (req, 200);
  SocketHTTPServer_Request_header (req, "Content-Type", "text/plain");
  SocketHTTPServer_Request_body_string (req, "Not a WebSocket request");
  SocketHTTPServer_Request_finish (req);
}

/* Handler that upgrades with NULL callback */
static void
ws_upgrade_null_callback_handler (SocketHTTPServer_Request_T req,
                                  void *userdata)
{
  WSServerFixture *fixture = (WSServerFixture *)userdata;

  if (SocketHTTPServer_Request_is_websocket (req))
    {
      SocketWS_T ws
          = SocketHTTPServer_Request_upgrade_websocket (req, NULL, NULL);
      if (ws != NULL)
        {
          atomic_fetch_add (&fixture->upgrade_count, 1);
          fixture->last_ws = ws;
        }
      return;
    }

  SocketHTTPServer_Request_status (req, 400);
  SocketHTTPServer_Request_finish (req);
}

static void *
ws_server_thread (void *arg)
{
  WSServerFixture *fixture = (WSServerFixture *)arg;

  atomic_store (&fixture->running, 1);

  while (!atomic_load (&fixture->stop_flag))
    {
      SocketHTTPServer_process (fixture->server, 10);
    }

  atomic_store (&fixture->running, 0);
  return NULL;
}

static int
ws_fixture_start (WSServerFixture *fixture,
                  WSCallbackContext *ctx,
                  SocketHTTPServer_Handler handler)
{
  SocketHTTPServer_Config config;

  memset (fixture, 0, sizeof (*fixture));
  fixture->callback_ctx = ctx;
  fixture->port = get_httpserver_ws_port ();

  SocketHTTPServer_config_defaults (&config);
  config.port = fixture->port;
  config.bind_address = TEST_HOST;

  fixture->server = SocketHTTPServer_new (&config);
  if (fixture->server == NULL)
    return -1;

  SocketHTTPServer_set_handler (fixture->server, handler, fixture);

  if (SocketHTTPServer_start (fixture->server) < 0)
    {
      SocketHTTPServer_free (&fixture->server);
      return -1;
    }

  atomic_store (&fixture->stop_flag, 0);

  if (pthread_create (&fixture->thread, NULL, ws_server_thread, fixture) != 0)
    {
      SocketHTTPServer_stop (fixture->server);
      SocketHTTPServer_free (&fixture->server);
      return -1;
    }

  /* Wait for server thread to start */
  int tries = 0;
  while (!atomic_load (&fixture->running) && tries < 100)
    {
      usleep (1000);
      tries++;
    }

  return 0;
}

static void
ws_fixture_stop (WSServerFixture *fixture)
{
  if (fixture->server == NULL)
    return;

  atomic_store (&fixture->stop_flag, 1);

  /* Wake up server thread */
  SocketHTTPServer_stop (fixture->server);

  pthread_join (fixture->thread, NULL);

  SocketHTTPServer_free (&fixture->server);
  fixture->server = NULL;
}

/* ============================================================================
 * Client Helpers
 * ============================================================================
 */

static unsigned
ws_translate_revents (short revents)
{
  unsigned ev = 0;

  if (revents & POLLIN)
    ev |= POLL_READ;
  if (revents & POLLOUT)
    ev |= POLL_WRITE;
  if (revents & POLLERR)
    ev |= POLL_ERROR;
  if (revents & POLLHUP)
    ev |= POLL_HANGUP;

  return ev;
}

static short
ws_poll_wanted_events (SocketWS_T ws)
{
  unsigned need;
  short events = 0;

  if (ws == NULL)
    return POLLIN;

  need = SocketWS_poll_events (ws);
  if (need & POLL_READ)
    events |= POLLIN;
  if (need & POLL_WRITE)
    events |= POLLOUT;

  if (events == 0)
    events = POLLIN;

  return events;
}

static void
ws_poll_and_process (SocketWS_T ws, int timeout_ms)
{
  struct pollfd pfd = { 0 };

  if (ws == NULL)
    return;

  pfd.fd = Socket_fd (SocketWS_socket (ws));
  pfd.events = ws_poll_wanted_events (ws);

  if (poll (&pfd, 1, timeout_ms) > 0)
    {
      TRY
      {
        SocketWS_process (ws, ws_translate_revents (pfd.revents));
      }
      EXCEPT (SocketWS_Failed)
      {
      }
      EXCEPT (SocketWS_ProtocolError)
      {
      }
      EXCEPT (SocketWS_Closed)
      {
      }
      END_TRY;
    }
}

/* Send data and flush by polling until write completes */
static void
ws_send_and_flush (SocketWS_T ws, const char *data, size_t len)
{
  int i;

  if (ws == NULL)
    return;

  SocketWS_send_text (ws, data, len);

  /* Poll multiple times to ensure data is sent */
  for (i = 0; i < 5; i++)
    {
      ws_poll_and_process (ws, 20);
      usleep (10000);
    }
}

/* Connect and upgrade to WebSocket */
static SocketWS_T
ws_connect_and_upgrade (WSServerFixture *fixture, Socket_T *out_socket)
{
  Socket_T sock = NULL;
  SocketWS_T ws = NULL;
  SocketWS_Config config;

  TRY
  {
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);
    if (sock == NULL)
      RETURN NULL;

    Socket_connect (sock, TEST_HOST, fixture->port);

    SocketWS_config_defaults (&config);
    config.role = WS_ROLE_CLIENT;

    ws = SocketWS_client_new (sock, TEST_HOST, "/ws", &config);
    if (ws == NULL)
      {
        Socket_free (&sock);
        RETURN NULL;
      }

    /* Complete handshake */
    int hs_result;
    int loops = 0;
    do
      {
        hs_result = SocketWS_handshake (ws);
        if (hs_result > 0)
          ws_poll_and_process (ws, 50);
        if (++loops > 100)
          break;
      }
    while (hs_result > 0);

    if (hs_result < 0 || SocketWS_state (ws) != WS_STATE_OPEN)
      {
        SocketWS_free (&ws);
        Socket_free (&sock);
        RETURN NULL;
      }

    *out_socket = sock;
    RETURN ws;
  }
  EXCEPT (Socket_Failed)
  {
    if (ws)
      SocketWS_free (&ws);
    if (sock)
      Socket_free (&sock);
    return NULL;
  }
  EXCEPT (SocketWS_Failed)
  {
    if (ws)
      SocketWS_free (&ws);
    if (sock)
      Socket_free (&sock);
    return NULL;
  }
  END_TRY;

  return NULL;
}

/* ============================================================================
 * State Transition Tests
 * ============================================================================
 */

TEST (httpserver_ws_upgrade_state_transition)
{
  setup_signals ();
  WSServerFixture fixture;
  WSCallbackContext ctx;
  Socket_T client = NULL;
  SocketWS_T ws = NULL;

  ws_callback_ctx_init (&ctx);

  if (ws_fixture_start (&fixture, &ctx, ws_upgrade_handler) < 0)
    {
      printf ("  [SKIP] Could not start server\n");
      ws_callback_ctx_destroy (&ctx);
      return;
    }

  TRY
  {
    ws = ws_connect_and_upgrade (&fixture, &client);
    ASSERT_NOT_NULL (ws);

    /* Wait for server to process upgrade */
    usleep (50000);

    /* Verify upgrade occurred */
    ASSERT_EQ (1, atomic_load (&fixture.upgrade_count));
  }
  FINALLY
  {
    if (ws)
      SocketWS_free (&ws);
    if (client)
      Socket_free (&client);
    ws_fixture_stop (&fixture);
    ws_callback_ctx_destroy (&ctx);
  }
  END_TRY;
}

TEST (httpserver_ws_upgrade_invalid_request)
{
  setup_signals ();
  WSServerFixture fixture;
  WSCallbackContext ctx;
  Socket_T client = NULL;
  char response[1024];
  ssize_t n;
  ssize_t total = 0;
  struct pollfd pfd;
  int fd;

  ws_callback_ctx_init (&ctx);

  if (ws_fixture_start (&fixture, &ctx, ws_upgrade_handler) < 0)
    {
      printf ("  [SKIP] Could not start server\n");
      ws_callback_ctx_destroy (&ctx);
      return;
    }

  TRY
  {
    client = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (client);

    Socket_connect (client, TEST_HOST, fixture.port);

    /* Send regular HTTP request (not WebSocket upgrade) */
    const char *request = "GET / HTTP/1.1\r\n"
                          "Host: localhost\r\n"
                          "Connection: close\r\n"
                          "\r\n";
    Socket_sendall (client, request, strlen (request));

    /* Wait for response with polling */
    fd = Socket_fd (client);
    memset (&pfd, 0, sizeof (pfd));
    pfd.fd = fd;
    pfd.events = POLLIN;

    /* Read response with timeout */
    memset (response, 0, sizeof (response));
    while (total < (ssize_t)sizeof (response) - 1)
      {
        if (poll (&pfd, 1, 500) <= 0)
          break;
        n = recv (fd, response + total, sizeof (response) - 1 - total, 0);
        if (n <= 0)
          break;
        total += n;
        /* Check if we have complete response */
        if (strstr (response, "\r\n\r\n") != NULL)
          break;
      }

    ASSERT (total > 0);

    /* Should get regular HTTP response */
    ASSERT (strstr (response, "HTTP/1.1") != NULL);

    /* No WebSocket upgrade should have occurred */
    ASSERT_EQ (0, atomic_load (&fixture.upgrade_count));
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    ws_fixture_stop (&fixture);
    ws_callback_ctx_destroy (&ctx);
  }
  END_TRY;
}

/* ============================================================================
 * Callback Invocation Tests
 * ============================================================================
 */

TEST (httpserver_ws_callback_text_message)
{
  setup_signals ();
  WSServerFixture fixture;
  WSCallbackContext ctx;
  Socket_T client = NULL;
  SocketWS_T ws = NULL;

  ws_callback_ctx_init (&ctx);

  if (ws_fixture_start (&fixture, &ctx, ws_upgrade_handler) < 0)
    {
      printf ("  [SKIP] Could not start server\n");
      ws_callback_ctx_destroy (&ctx);
      return;
    }

  TRY
  {
    ws = ws_connect_and_upgrade (&fixture, &client);
    ASSERT_NOT_NULL (ws);

    /* Wait for upgrade to complete on server */
    usleep (50000);
    ASSERT_EQ (1, atomic_load (&fixture.upgrade_count));

    /* Send text message */
    ws_send_and_flush (ws, "Hello Server", 12);

    /* Wait for server to receive and process */
    usleep (200000);

    /* Verify callback was invoked */
    ASSERT_EQ (1, atomic_load (&ctx.message_count));
    ASSERT_EQ (12, ctx.last_message_len);
    ASSERT_EQ (0, memcmp (ctx.last_message, "Hello Server", 12));
  }
  FINALLY
  {
    if (ws)
      SocketWS_free (&ws);
    if (client)
      Socket_free (&client);
    ws_fixture_stop (&fixture);
    ws_callback_ctx_destroy (&ctx);
  }
  END_TRY;
}

TEST (httpserver_ws_callback_binary_message)
{
  setup_signals ();
  WSServerFixture fixture;
  WSCallbackContext ctx;
  Socket_T client = NULL;
  SocketWS_T ws = NULL;
  unsigned char binary_data[] = { 0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD };

  ws_callback_ctx_init (&ctx);

  if (ws_fixture_start (&fixture, &ctx, ws_upgrade_handler) < 0)
    {
      printf ("  [SKIP] Could not start server\n");
      ws_callback_ctx_destroy (&ctx);
      return;
    }

  TRY
  {
    ws = ws_connect_and_upgrade (&fixture, &client);
    ASSERT_NOT_NULL (ws);

    usleep (50000);
    ASSERT_EQ (1, atomic_load (&fixture.upgrade_count));

    /* Send binary message */
    SocketWS_send_binary (ws, binary_data, sizeof (binary_data));
    ws_poll_and_process (ws, 50);

    usleep (100000);

    ASSERT_EQ (1, atomic_load (&ctx.message_count));
    ASSERT_EQ (sizeof (binary_data), ctx.last_message_len);
    ASSERT_EQ (0, memcmp (ctx.last_message, binary_data, sizeof (binary_data)));
  }
  FINALLY
  {
    if (ws)
      SocketWS_free (&ws);
    if (client)
      Socket_free (&client);
    ws_fixture_stop (&fixture);
    ws_callback_ctx_destroy (&ctx);
  }
  END_TRY;
}

TEST (httpserver_ws_callback_multiple_messages)
{
  setup_signals ();
  WSServerFixture fixture;
  WSCallbackContext ctx;
  Socket_T client = NULL;
  SocketWS_T ws = NULL;

  ws_callback_ctx_init (&ctx);

  if (ws_fixture_start (&fixture, &ctx, ws_upgrade_handler) < 0)
    {
      printf ("  [SKIP] Could not start server\n");
      ws_callback_ctx_destroy (&ctx);
      return;
    }

  TRY
  {
    ws = ws_connect_and_upgrade (&fixture, &client);
    ASSERT_NOT_NULL (ws);

    usleep (50000);

    /* Send 3 messages */
    SocketWS_send_text (ws, "Message 1", 9);
    ws_poll_and_process (ws, 50);
    usleep (50000);

    SocketWS_send_text (ws, "Message 2", 9);
    ws_poll_and_process (ws, 50);
    usleep (50000);

    SocketWS_send_text (ws, "Message 3", 9);
    ws_poll_and_process (ws, 50);
    usleep (100000);

    /* Verify all 3 messages received */
    ASSERT_EQ (3, atomic_load (&ctx.message_count));
  }
  FINALLY
  {
    if (ws)
      SocketWS_free (&ws);
    if (client)
      Socket_free (&client);
    ws_fixture_stop (&fixture);
    ws_callback_ctx_destroy (&ctx);
  }
  END_TRY;
}

TEST (httpserver_ws_callback_null_safe)
{
  setup_signals ();
  WSServerFixture fixture;
  Socket_T client = NULL;
  SocketWS_T ws = NULL;

  /* Use NULL callback handler */
  if (ws_fixture_start (&fixture, NULL, ws_upgrade_null_callback_handler) < 0)
    {
      printf ("  [SKIP] Could not start server\n");
      return;
    }

  TRY
  {
    ws = ws_connect_and_upgrade (&fixture, &client);
    ASSERT_NOT_NULL (ws);

    usleep (100000);

    /* Upgrade should have occurred */
    ASSERT_EQ (1, atomic_load (&fixture.upgrade_count));

    /* No crash = success (don't send messages, just test upgrade with NULL cb)
     */
  }
  FINALLY
  {
    if (ws)
      SocketWS_free (&ws);
    if (client)
      Socket_free (&client);
    ws_fixture_stop (&fixture);
  }
  END_TRY;
}

/* ============================================================================
 * Poll Integration Tests
 * ============================================================================
 */

TEST (httpserver_ws_stays_in_poll)
{
  setup_signals ();
  WSServerFixture fixture;
  WSCallbackContext ctx;
  Socket_T client = NULL;
  SocketWS_T ws = NULL;

  ws_callback_ctx_init (&ctx);

  if (ws_fixture_start (&fixture, &ctx, ws_upgrade_handler) < 0)
    {
      printf ("  [SKIP] Could not start server\n");
      ws_callback_ctx_destroy (&ctx);
      return;
    }

  TRY
  {
    ws = ws_connect_and_upgrade (&fixture, &client);
    ASSERT_NOT_NULL (ws);

    usleep (50000);
    ASSERT_EQ (1, atomic_load (&fixture.upgrade_count));

    /* Wait 200ms then send message - proves poll integration works */
    usleep (200000);

    SocketWS_send_text (ws, "Delayed message", 15);
    ws_poll_and_process (ws, 50);

    usleep (100000);

    /* Message should have been received via poll loop */
    ASSERT_EQ (1, atomic_load (&ctx.message_count));
    ASSERT_EQ (15, ctx.last_message_len);
  }
  FINALLY
  {
    if (ws)
      SocketWS_free (&ws);
    if (client)
      Socket_free (&client);
    ws_fixture_stop (&fixture);
    ws_callback_ctx_destroy (&ctx);
  }
  END_TRY;
}

/* ============================================================================
 * Cleanup Tests
 * ============================================================================
 */

TEST (httpserver_ws_cleanup_on_close)
{
  setup_signals ();
  WSServerFixture fixture;
  WSCallbackContext ctx;
  Socket_T client = NULL;
  SocketWS_T ws = NULL;

  ws_callback_ctx_init (&ctx);

  if (ws_fixture_start (&fixture, &ctx, ws_upgrade_handler) < 0)
    {
      printf ("  [SKIP] Could not start server\n");
      ws_callback_ctx_destroy (&ctx);
      return;
    }

  TRY
  {
    ws = ws_connect_and_upgrade (&fixture, &client);
    ASSERT_NOT_NULL (ws);

    usleep (50000);

    /* Initiate clean close */
    SocketWS_close (ws, WS_CLOSE_NORMAL, "Test complete");
    ws_poll_and_process (ws, 100);

    usleep (100000);

    /* No crash = cleanup successful */
    /* ASan will detect leaks if cleanup failed */
  }
  FINALLY
  {
    if (ws)
      SocketWS_free (&ws);
    if (client)
      Socket_free (&client);
    ws_fixture_stop (&fixture);
    ws_callback_ctx_destroy (&ctx);
  }
  END_TRY;
}

TEST (httpserver_ws_cleanup_on_disconnect)
{
  setup_signals ();
  WSServerFixture fixture;
  WSCallbackContext ctx;
  Socket_T client = NULL;
  SocketWS_T ws = NULL;

  ws_callback_ctx_init (&ctx);

  if (ws_fixture_start (&fixture, &ctx, ws_upgrade_handler) < 0)
    {
      printf ("  [SKIP] Could not start server\n");
      ws_callback_ctx_destroy (&ctx);
      return;
    }

  TRY
  {
    ws = ws_connect_and_upgrade (&fixture, &client);
    ASSERT_NOT_NULL (ws);

    usleep (50000);

    /* Abruptly close socket without WebSocket close handshake */
    SocketWS_free (&ws);
    ws = NULL;
    Socket_free (&client);
    client = NULL;

    /* Give server time to detect disconnect */
    usleep (100000);

    /* No crash = cleanup successful */
  }
  FINALLY
  {
    if (ws)
      SocketWS_free (&ws);
    if (client)
      Socket_free (&client);
    ws_fixture_stop (&fixture);
    ws_callback_ctx_destroy (&ctx);
  }
  END_TRY;
}

TEST (httpserver_ws_server_stop_cleanup)
{
  setup_signals ();
  WSServerFixture fixture;
  WSCallbackContext ctx;
  Socket_T client = NULL;
  SocketWS_T ws = NULL;

  ws_callback_ctx_init (&ctx);

  if (ws_fixture_start (&fixture, &ctx, ws_upgrade_handler) < 0)
    {
      printf ("  [SKIP] Could not start server\n");
      ws_callback_ctx_destroy (&ctx);
      return;
    }

  TRY
  {
    ws = ws_connect_and_upgrade (&fixture, &client);
    ASSERT_NOT_NULL (ws);

    usleep (50000);

    /* Stop server while WebSocket is active */
    ws_fixture_stop (&fixture);

    /* No crash = cleanup successful */
    /* ASan will detect leaks */
  }
  FINALLY
  {
    if (ws)
      SocketWS_free (&ws);
    if (client)
      Socket_free (&client);
    /* fixture already stopped */
    ws_callback_ctx_destroy (&ctx);
  }
  END_TRY;
}

/* ============================================================================
 * Error Handling Tests
 * ============================================================================
 */

TEST (httpserver_ws_handshake_failure)
{
  setup_signals ();
  WSServerFixture fixture;
  WSCallbackContext ctx;
  Socket_T client = NULL;
  char response[1024];
  ssize_t n;

  ws_callback_ctx_init (&ctx);

  if (ws_fixture_start (&fixture, &ctx, ws_upgrade_handler) < 0)
    {
      printf ("  [SKIP] Could not start server\n");
      ws_callback_ctx_destroy (&ctx);
      return;
    }

  TRY
  {
    client = Socket_new (AF_INET, SOCK_STREAM, 0);
    ASSERT_NOT_NULL (client);

    Socket_connect (client, TEST_HOST, fixture.port);

    /* Send malformed WebSocket upgrade (missing Sec-WebSocket-Key) */
    const char *request = "GET /ws HTTP/1.1\r\n"
                          "Host: localhost\r\n"
                          "Upgrade: websocket\r\n"
                          "Connection: Upgrade\r\n"
                          "\r\n";
    Socket_sendall (client, request, strlen (request));

    usleep (50000);

    n = Socket_recv (client, response, sizeof (response) - 1);
    if (n > 0)
      response[n] = '\0';

    /* Server should still be running */
    ASSERT_EQ (HTTPSERVER_STATE_RUNNING,
               SocketHTTPServer_state (fixture.server));
  }
  FINALLY
  {
    if (client)
      Socket_free (&client);
    ws_fixture_stop (&fixture);
    ws_callback_ctx_destroy (&ctx);
  }
  END_TRY;
}

/* ============================================================================
 * Concurrent Connection Tests
 * ============================================================================
 */

TEST (httpserver_ws_multiple_connections)
{
  setup_signals ();
  WSServerFixture fixture;
  WSCallbackContext ctx;
  Socket_T clients[3] = { NULL, NULL, NULL };
  SocketWS_T websockets[3] = { NULL, NULL, NULL };
  int i;

  ws_callback_ctx_init (&ctx);

  if (ws_fixture_start (&fixture, &ctx, ws_upgrade_handler) < 0)
    {
      printf ("  [SKIP] Could not start server\n");
      ws_callback_ctx_destroy (&ctx);
      return;
    }

  TRY
  {
    /* Connect 3 WebSocket clients */
    for (i = 0; i < 3; i++)
      {
        websockets[i] = ws_connect_and_upgrade (&fixture, &clients[i]);
        ASSERT_NOT_NULL (websockets[i]);
        usleep (30000);
      }

    /* All 3 should have upgraded */
    ASSERT_EQ (3, atomic_load (&fixture.upgrade_count));

    /* Each sends a message */
    for (i = 0; i < 3; i++)
      {
        char msg[32];
        snprintf (msg, sizeof (msg), "Client %d", i);
        SocketWS_send_text (websockets[i], msg, strlen (msg));
        ws_poll_and_process (websockets[i], 50);
        usleep (50000);
      }

    /* All messages should be received */
    ASSERT_EQ (3, atomic_load (&ctx.message_count));
  }
  FINALLY
  {
    for (i = 0; i < 3; i++)
      {
        if (websockets[i])
          SocketWS_free (&websockets[i]);
        if (clients[i])
          Socket_free (&clients[i]);
      }
    ws_fixture_stop (&fixture);
    ws_callback_ctx_destroy (&ctx);
  }
  END_TRY;
}

/* Test multiple concurrent upgrades (without message exchange) */
TEST (httpserver_ws_multiple_upgrades)
{
  setup_signals ();
  WSServerFixture fixture;
  WSCallbackContext ctx;
  Socket_T clients[3] = { NULL, NULL, NULL };
  SocketWS_T websockets[3] = { NULL, NULL, NULL };
  int i;

  ws_callback_ctx_init (&ctx);

  if (ws_fixture_start (&fixture, &ctx, ws_upgrade_handler) < 0)
    {
      printf ("  [SKIP] Could not start server\n");
      ws_callback_ctx_destroy (&ctx);
      return;
    }

  TRY
  {
    /* Connect 3 WebSocket clients */
    for (i = 0; i < 3; i++)
      {
        websockets[i] = ws_connect_and_upgrade (&fixture, &clients[i]);
        ASSERT_NOT_NULL (websockets[i]);
        usleep (50000);
      }

    /* All 3 should have upgraded */
    ASSERT_EQ (3, atomic_load (&fixture.upgrade_count));
  }
  FINALLY
  {
    for (i = 0; i < 3; i++)
      {
        if (websockets[i])
          SocketWS_free (&websockets[i]);
        if (clients[i])
          Socket_free (&clients[i]);
      }
    ws_fixture_stop (&fixture);
    ws_callback_ctx_destroy (&ctx);
  }
  END_TRY;
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
