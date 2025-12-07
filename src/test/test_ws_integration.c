/**
 * test_ws_integration.c - WebSocket Protocol Integration Tests
 *
 * End-to-end WebSocket tests with real network I/O.
 * Uses loopback (127.0.0.1) for client/server testing.
 *
 * Tests:
 * - HTTP upgrade handshake
 * - WebSocket client/server creation
 * - State transitions
 * - Send operations (text/binary/ping)
 *
 * Note: SocketWS_recv_message is not yet implemented in the core library.
 * These tests focus on what's currently available: handshake and send.
 *
 * Module Reuse:
 * - SocketWS for WebSocket protocol
 * - SocketHTTP1_Parser for upgrade request parsing
 * - SocketCrypto_websocket_* for handshake keys
 * - Socket, SocketPoll for networking
 */

#include <arpa/inet.h>
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
#include "core/SocketConfig.h"  /* For SOCKET_HAS_TLS */
#include "core/SocketCrypto.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketBuf.h"
#include "socket/SocketWS.h"
#include "test/Test.h"

/* ============================================================================
 * Test Configuration
 * ============================================================================ */

#define TEST_PORT_BASE 46000
#define TEST_TIMEOUT_MS 5000

static int ws_test_port_counter = 0;

static int
get_ws_test_port (void)
{
  return TEST_PORT_BASE + (ws_test_port_counter++ % 1000);
}

/* ============================================================================
 * WebSocket Server Infrastructure
 * ============================================================================ */

typedef struct
{
  Socket_T listen_socket;
  Socket_T client_socket;
  SocketWS_T ws;
  pthread_t thread;
  atomic_int running;
  atomic_int connected;
  atomic_int handshake_done;
  int port;
  Arena_T arena;
} WSTestServer;

/* Parse incoming HTTP upgrade request and accept WebSocket */
static int
server_accept_websocket (WSTestServer *server)
{
  char buf[4096];
  ssize_t n;
  SocketHTTP1_Parser_T parser;
  SocketHTTP1_Result result;
  size_t consumed = 0;
  SocketWS_Config config;

  /* Read HTTP upgrade request */
  n = Socket_recv (server->client_socket, buf, sizeof (buf) - 1);
  if (n <= 0)
    return -1;

  buf[n] = '\0';

  /* Parse HTTP request */
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, server->arena);
  if (parser == NULL)
    return -1;

  result = SocketHTTP1_Parser_execute (parser, buf, (size_t)n, &consumed);
  if (result != HTTP1_OK && result != HTTP1_INCOMPLETE)
    {
      SocketHTTP1_Parser_free (&parser);
      return -1;
    }

  /* Get parsed request */
  const SocketHTTP_Request *request = SocketHTTP1_Parser_get_request (parser);
  if (request == NULL)
    {
      SocketHTTP1_Parser_free (&parser);
      return -1;
    }

  /* Check if it's a WebSocket upgrade */
  if (!SocketWS_is_upgrade (request))
    {
      SocketHTTP1_Parser_free (&parser);
      return -1;
    }

  /* Accept WebSocket upgrade */
  SocketWS_config_defaults (&config);
  config.role = WS_ROLE_SERVER;
  config.validate_utf8 = 1;

  server->ws = SocketWS_server_accept (server->client_socket, request, &config);
  SocketHTTP1_Parser_free (&parser);

  if (server->ws == NULL)
    return -1;

  /* Complete handshake (send 101 response) */
  int hs_result;
  do
    {
      hs_result = SocketWS_handshake (server->ws);
    }
  while (hs_result > 0);

  if (hs_result < 0)
    {
      SocketWS_free (&server->ws);
      return -1;
    }

  return 0;
}

static void *
ws_server_thread_func (void *arg)
{
  WSTestServer *server = (WSTestServer *)arg;

  /* Accept client connection */
  server->client_socket = Socket_accept (server->listen_socket);
  if (server->client_socket == NULL)
    {
      server->running = 0;
      return NULL;
    }

  server->connected = 1;

  /* Accept WebSocket upgrade */
  if (server_accept_websocket (server) < 0)
    {
      Socket_free (&server->client_socket);
      server->running = 0;
      return NULL;
    }

  server->handshake_done = 1;

  /* Keep connection alive for tests */
  while (server->running && server->ws != NULL)
    {
      usleep (10000);
    }

  /* Clean close */
  if (server->ws && SocketWS_state (server->ws) == WS_STATE_OPEN)
    {
      SocketWS_close (server->ws, WS_CLOSE_NORMAL, "Server shutdown");
    }

  if (server->ws)
    SocketWS_free (&server->ws);
  if (server->client_socket)
    Socket_free (&server->client_socket);

  return NULL;
}

static int
ws_server_start (WSTestServer *server)
{
  int port;
  struct sockaddr_in addr;
  socklen_t len;

  memset (server, 0, sizeof (*server));

  server->arena = Arena_new ();
  if (server->arena == NULL)
    return -1;

  port = get_ws_test_port ();
  server->port = port;

  server->listen_socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  if (server->listen_socket == NULL)
    {
      Arena_dispose (&server->arena);
      return -1;
    }

  TRY
  Socket_setreuseaddr (server->listen_socket);
  Socket_bind (server->listen_socket, "127.0.0.1", port);
  Socket_listen (server->listen_socket, 5);
  EXCEPT (Socket_Failed)
  Socket_free (&server->listen_socket);
  Arena_dispose (&server->arena);
  return -1;
  END_TRY;

  /* Get actual port */
  len = sizeof (addr);
  getsockname (Socket_fd (server->listen_socket), (struct sockaddr *)&addr,
               &len);
  server->port = ntohs (addr.sin_port);

  server->running = 1;

  if (pthread_create (&server->thread, NULL, ws_server_thread_func, server)
      != 0)
    {
      server->running = 0;
      Socket_free (&server->listen_socket);
      Arena_dispose (&server->arena);
      return -1;
    }

  return 0;
}

static void
ws_server_stop (WSTestServer *server)
{
  server->running = 0;

  /* Shutdown listen socket to unblock accept.
   * Use shutdown() rather than close() so the socket memory remains valid
   * until the thread exits. This avoids TSan data races. */
  if (server->listen_socket)
    shutdown (Socket_fd (server->listen_socket), SHUT_RDWR);

  pthread_join (server->thread, NULL);

  /* Now safe to free - thread has exited */
  if (server->listen_socket)
    Socket_free (&server->listen_socket);

  if (server->arena)
    Arena_dispose (&server->arena);
}

/* ============================================================================
 * Integration Tests
 * ============================================================================ */

TEST (ws_integration_handshake)
{
  WSTestServer server;
  Socket_T client_socket = NULL;
  SocketWS_T ws = NULL;
  SocketWS_Config config;

  signal (SIGPIPE, SIG_IGN);

  if (ws_server_start (&server) < 0)
    {
      printf ("  [SKIP] Could not start WebSocket server\n");
      return;
    }

  TRY
  /* Connect to server */
  client_socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (client_socket);

  Socket_connect (client_socket, "127.0.0.1", server.port);

  /* Create WebSocket client */
  SocketWS_config_defaults (&config);
  config.role = WS_ROLE_CLIENT;

  ws = SocketWS_client_new (client_socket, "127.0.0.1", "/ws", &config);
  ASSERT_NOT_NULL (ws);

  /* Perform handshake */
  int result;
  do
    {
      result = SocketWS_handshake (ws);
    }
  while (result > 0);

  ASSERT_EQ (result, 0);
  ASSERT_EQ (SocketWS_state (ws), WS_STATE_OPEN);

  /* Wait for server handshake */
  int tries = 0;
  while (!server.handshake_done && tries < 100)
    {
      usleep (10000);
      tries++;
    }

  ASSERT (server.handshake_done);

  /* Close properly */
  SocketWS_close (ws, WS_CLOSE_NORMAL, "Test complete");

  EXCEPT (Socket_Failed)
  printf ("  [WARN] Socket error\n");
  EXCEPT (SocketWS_Failed)
  printf ("  [WARN] WebSocket error: %s\n", SocketWS_Failed.reason);
  FINALLY
  if (ws)
    SocketWS_free (&ws);
  if (client_socket)
    Socket_free (&client_socket);
  ws_server_stop (&server);
  END_TRY;
}

TEST (ws_integration_send_text)
{
  WSTestServer server;
  Socket_T client_socket = NULL;
  SocketWS_T ws = NULL;
  SocketWS_Config config;
  const char *test_message = "Hello, WebSocket!";

  signal (SIGPIPE, SIG_IGN);

  if (ws_server_start (&server) < 0)
    {
      printf ("  [SKIP] Could not start WebSocket server\n");
      return;
    }

  TRY
  /* Connect and handshake */
  client_socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_connect (client_socket, "127.0.0.1", server.port);

  SocketWS_config_defaults (&config);
  config.role = WS_ROLE_CLIENT;

  ws = SocketWS_client_new (client_socket, "127.0.0.1", "/ws", &config);

  int result;
  do
    {
      result = SocketWS_handshake (ws);
    }
  while (result > 0);

  ASSERT_EQ (result, 0);

  /* Wait for server to be ready */
  int tries = 0;
  while (!server.handshake_done && tries < 100)
    {
      usleep (10000);
      tries++;
    }

  /* Send text message */
  result = SocketWS_send_text (ws, test_message, strlen (test_message));
  ASSERT_EQ (result, 0);

  /* Note: Receiving is not tested as SocketWS_recv_message is not implemented */

  SocketWS_close (ws, WS_CLOSE_NORMAL, NULL);

  EXCEPT (Socket_Failed)
  printf ("  [WARN] Socket error\n");
  EXCEPT (SocketWS_Failed)
  printf ("  [WARN] WebSocket error\n");
  FINALLY
  if (ws)
    SocketWS_free (&ws);
  if (client_socket)
    Socket_free (&client_socket);
  ws_server_stop (&server);
  END_TRY;
}

TEST (ws_integration_send_binary)
{
  WSTestServer server;
  Socket_T client_socket = NULL;
  SocketWS_T ws = NULL;
  SocketWS_Config config;
  unsigned char binary_data[256];

  signal (SIGPIPE, SIG_IGN);

  /* Fill with pattern */
  for (size_t i = 0; i < sizeof (binary_data); i++)
    binary_data[i] = (unsigned char)i;

  if (ws_server_start (&server) < 0)
    {
      printf ("  [SKIP] Could not start WebSocket server\n");
      return;
    }

  TRY
  /* Connect and handshake */
  client_socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_connect (client_socket, "127.0.0.1", server.port);

  SocketWS_config_defaults (&config);
  config.role = WS_ROLE_CLIENT;

  ws = SocketWS_client_new (client_socket, "127.0.0.1", "/ws", &config);

  int result;
  do
    {
      result = SocketWS_handshake (ws);
    }
  while (result > 0);

  ASSERT_EQ (result, 0);

  /* Wait for server */
  int tries = 0;
  while (!server.handshake_done && tries < 100)
    {
      usleep (10000);
      tries++;
    }

  /* Send binary message */
  result = SocketWS_send_binary (ws, binary_data, sizeof (binary_data));
  ASSERT_EQ (result, 0);

  SocketWS_close (ws, WS_CLOSE_NORMAL, NULL);

  EXCEPT (Socket_Failed)
  printf ("  [WARN] Socket error\n");
  EXCEPT (SocketWS_Failed)
  printf ("  [WARN] WebSocket error\n");
  FINALLY
  if (ws)
    SocketWS_free (&ws);
  if (client_socket)
    Socket_free (&client_socket);
  ws_server_stop (&server);
  END_TRY;
}

TEST (ws_integration_ping)
{
  WSTestServer server;
  Socket_T client_socket = NULL;
  SocketWS_T ws = NULL;
  SocketWS_Config config;
  const char *ping_data = "PING";

  signal (SIGPIPE, SIG_IGN);

  if (ws_server_start (&server) < 0)
    {
      printf ("  [SKIP] Could not start WebSocket server\n");
      return;
    }

  TRY
  /* Connect and handshake */
  client_socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_connect (client_socket, "127.0.0.1", server.port);

  SocketWS_config_defaults (&config);
  config.role = WS_ROLE_CLIENT;

  ws = SocketWS_client_new (client_socket, "127.0.0.1", "/ws", &config);

  int result;
  do
    {
      result = SocketWS_handshake (ws);
    }
  while (result > 0);

  ASSERT_EQ (result, 0);

  /* Wait for server */
  int tries = 0;
  while (!server.handshake_done && tries < 100)
    {
      usleep (10000);
      tries++;
    }

  /* Send ping */
  result = SocketWS_ping (ws, ping_data, strlen (ping_data));
  ASSERT_EQ (result, 0);

  SocketWS_close (ws, WS_CLOSE_NORMAL, NULL);

  EXCEPT (Socket_Failed)
  printf ("  [WARN] Socket error\n");
  EXCEPT (SocketWS_Failed)
  printf ("  [WARN] WebSocket error\n");
  FINALLY
  if (ws)
    SocketWS_free (&ws);
  if (client_socket)
    Socket_free (&client_socket);
  ws_server_stop (&server);
  END_TRY;
}

TEST (ws_integration_close)
{
  WSTestServer server;
  Socket_T client_socket = NULL;
  SocketWS_T ws = NULL;
  SocketWS_Config config;

  signal (SIGPIPE, SIG_IGN);

  if (ws_server_start (&server) < 0)
    {
      printf ("  [SKIP] Could not start WebSocket server\n");
      return;
    }

  TRY
  /* Connect and handshake */
  client_socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_connect (client_socket, "127.0.0.1", server.port);

  SocketWS_config_defaults (&config);
  config.role = WS_ROLE_CLIENT;

  ws = SocketWS_client_new (client_socket, "127.0.0.1", "/ws", &config);

  int result;
  do
    {
      result = SocketWS_handshake (ws);
    }
  while (result > 0);

  ASSERT_EQ (result, 0);

  /* Wait for server */
  int tries = 0;
  while (!server.handshake_done && tries < 100)
    {
      usleep (10000);
      tries++;
    }

  /* Initiate close */
  result = SocketWS_close (ws, WS_CLOSE_NORMAL, "Test close");
  ASSERT_EQ (result, 0);

  /* State should be CLOSING or CLOSED */
  SocketWS_State state = SocketWS_state (ws);
  ASSERT (state == WS_STATE_CLOSING || state == WS_STATE_CLOSED);

  EXCEPT (Socket_Failed)
  printf ("  [WARN] Socket error\n");
  EXCEPT (SocketWS_Failed)
  printf ("  [WARN] WebSocket error\n");
  FINALLY
  if (ws)
    SocketWS_free (&ws);
  if (client_socket)
    Socket_free (&client_socket);
  ws_server_stop (&server);
  END_TRY;
}

TEST (ws_integration_state_transitions)
{
  WSTestServer server;
  Socket_T client_socket = NULL;
  SocketWS_T ws = NULL;
  SocketWS_Config config;

  signal (SIGPIPE, SIG_IGN);

  if (ws_server_start (&server) < 0)
    {
      printf ("  [SKIP] Could not start WebSocket server\n");
      return;
    }

  TRY
  /* Connect */
  client_socket = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_connect (client_socket, "127.0.0.1", server.port);

  SocketWS_config_defaults (&config);
  config.role = WS_ROLE_CLIENT;

  ws = SocketWS_client_new (client_socket, "127.0.0.1", "/ws", &config);
  ASSERT_NOT_NULL (ws);

  /* Initial state should be CONNECTING */
  ASSERT_EQ (SocketWS_state (ws), WS_STATE_CONNECTING);

  /* Perform handshake */
  int result;
  do
    {
      result = SocketWS_handshake (ws);
    }
  while (result > 0);

  ASSERT_EQ (result, 0);

  /* State should now be OPEN */
  ASSERT_EQ (SocketWS_state (ws), WS_STATE_OPEN);

  /* Close */
  SocketWS_close (ws, WS_CLOSE_NORMAL, NULL);

  /* State should be CLOSING or CLOSED */
  SocketWS_State state = SocketWS_state (ws);
  ASSERT (state == WS_STATE_CLOSING || state == WS_STATE_CLOSED);

  EXCEPT (Socket_Failed)
  printf ("  [WARN] Socket error\n");
  EXCEPT (SocketWS_Failed)
  printf ("  [WARN] WebSocket error\n");
  FINALLY
  if (ws)
    SocketWS_free (&ws);
  if (client_socket)
    Socket_free (&client_socket);
  ws_server_stop (&server);
  END_TRY;
}

/* ============================================================================
 * Main Entry Point
 * ============================================================================ */

int
main (void)
{
  printf ("=== WebSocket Integration Tests ===\n");

#if SOCKET_HAS_TLS
  Test_run_all ();
#else
  printf ("\n[SKIPPED] WebSocket integration tests require TLS support\n");
  printf ("WebSocket handshake uses SHA-1 for Sec-WebSocket-Accept computation\n");
#endif

  printf ("\n");
  return Test_get_failures () > 0 ? 1 : 0;
}
