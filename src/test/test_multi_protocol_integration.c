/**
 * test_multi_protocol_integration.c - Multi-Protocol Integration Tests
 *
 * Tests combining multiple protocols in single applications:
 * - HTTP → WebSocket upgrade handshake parsing
 * - IPv6 + IPv4 dual-stack networking
 * - Protocol negotiation and fallback
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
#include "core/SocketConfig.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTP1.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketWS.h"
#include "test/Test.h"

/* ============================================================================
 * Test Configuration
 * ============================================================================
 */

#define TEST_PORT_BASE 48000
#define TEST_TIMEOUT_MS 5000

static int mp_test_port_counter = 0;

static int
get_mp_test_port (void)
{
  return TEST_PORT_BASE + (mp_test_port_counter++ % 1000);
}

/* ============================================================================
 * HTTP to WebSocket Upgrade Server
 * ============================================================================
 */

typedef struct
{
  Socket_T listen_socket;
  Socket_T client_socket;
  pthread_t thread;
  atomic_int running;
  atomic_int upgrade_complete;
  int port;
  Arena_T arena;
} UpgradeTestServer;

static void
upgrade_server_handle_http (UpgradeTestServer *server)
{
  char buf[4096];
  ssize_t n;
  SocketHTTP1_Parser_T parser;
  SocketHTTP1_Result result;
  size_t consumed = 0;

  /* Read HTTP upgrade request */
  n = Socket_recv (server->client_socket, buf, sizeof (buf) - 1);
  if (n <= 0)
    return;

  buf[n] = '\0';

  /* Parse HTTP request */
  parser = SocketHTTP1_Parser_new (HTTP1_PARSE_REQUEST, NULL, server->arena);
  if (parser == NULL)
    return;

  result = SocketHTTP1_Parser_execute (parser, buf, n, &consumed);

  if (result == HTTP1_OK)
    {
      const SocketHTTP_Request *req = SocketHTTP1_Parser_get_request (parser);

      /* Check if this is a WebSocket upgrade request */
      if (req && SocketWS_is_upgrade (req))
        {
          /* Send simple upgrade response (just test HTTP parsing) */
          char response[256];
          snprintf (response, sizeof (response),
                   "HTTP/1.1 101 Switching Protocols\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Accept: test_key\r\n"
                   "\r\n");

          Socket_send (server->client_socket, response, strlen (response));

          /* Upgrade complete */
          server->upgrade_complete = 1;
        }
    }

  SocketHTTP1_Parser_free (&parser);
}

static void *
upgrade_server_thread (void *arg)
{
  UpgradeTestServer *server = (UpgradeTestServer *)arg;

  while (server->running)
    {
      /* Accept client connection */
      if (!server->client_socket)
        {
          server->client_socket = Socket_accept_timeout (server->listen_socket, 100);
          if (server->client_socket)
            {
              Socket_setnonblocking (server->client_socket);
            }
        }

      /* Handle HTTP upgrade request */
      if (server->client_socket && !server->upgrade_complete)
        {
          upgrade_server_handle_http (server);
        }

      usleep (10000); /* 10ms */
    }

  return NULL;
}

static void
upgrade_test_server_start (UpgradeTestServer *server)
{
  int port = get_mp_test_port ();

  server->arena = Arena_new ();
  server->port = port;
  server->running = 1;
  server->upgrade_complete = 0;
  server->client_socket = NULL;

  /* Create listening socket */
  server->listen_socket = Socket_listen_tcp ("127.0.0.1", port, 5);
  ASSERT_NOT_NULL (server->listen_socket);

  /* Start server thread */
  ASSERT_EQ (pthread_create (&server->thread, NULL, upgrade_server_thread, server), 0);
}

static void
upgrade_test_server_stop (UpgradeTestServer *server)
{
  server->running = 0;
  pthread_join (server->thread, NULL);

  if (server->client_socket)
    Socket_free (&server->client_socket);
  if (server->listen_socket)
    Socket_free (&server->listen_socket);

  Arena_dispose (&server->arena);
}

/* ============================================================================
 * IPv6 Dual-Stack Server
 * ============================================================================
 */

typedef struct
{
  Socket_T listen_socket_ipv4;
  Socket_T listen_socket_ipv6;
  Socket_T client_socket;
  pthread_t thread;
  atomic_int running;
  atomic_int ipv4_connections;
  atomic_int ipv6_connections;
  int port;
  Arena_T arena;
} DualStackServer;

static void *
dual_stack_server_thread (void *arg)
{
  DualStackServer *server = (DualStackServer *)arg;
  SocketPoll_T poll = SocketPoll_new (10);

  SocketPoll_add (poll, server->listen_socket_ipv4, POLL_READ, NULL);
  SocketPoll_add (poll, server->listen_socket_ipv6, POLL_READ, NULL);

  while (server->running)
    {
      SocketEvent_T *events = NULL;
      int nfds = SocketPoll_wait (poll, &events, 100);

      for (int i = 0; i < nfds; i++)
        {
          Socket_T accepted = Socket_accept (events[i].socket);
          if (accepted)
            {
              /* Determine which protocol was used */
              struct sockaddr_storage addr;
              socklen_t addr_len = sizeof (addr);

              if (getpeername (Socket_fd (accepted), (struct sockaddr *)&addr, &addr_len) == 0)
                {
                  if (addr.ss_family == AF_INET)
                    {
                      server->ipv4_connections++;
                    }
                  else if (addr.ss_family == AF_INET6)
                    {
                      server->ipv6_connections++;
                    }
                }

              /* Simple echo server */
              char buf[1024];
              ssize_t n = Socket_recv (accepted, buf, sizeof (buf));
              if (n > 0)
                {
                  Socket_send (accepted, buf, n);
                }

              Socket_free (&accepted);
            }
        }
    }

  SocketPoll_free (&poll);
  return NULL;
}

static void
dual_stack_server_start (DualStackServer *server)
{
  int port = get_mp_test_port ();

  server->arena = Arena_new ();
  server->port = port;
  server->running = 1;
  server->ipv4_connections = 0;
  server->ipv6_connections = 0;

  /* Create IPv4 listening socket */
  server->listen_socket_ipv4 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_bind (server->listen_socket_ipv4, "127.0.0.1", port);
  Socket_listen (server->listen_socket_ipv4, 10);

  /* Create IPv6 listening socket */
  server->listen_socket_ipv6 = Socket_new (AF_INET6, SOCK_STREAM, 0);
  Socket_bind (server->listen_socket_ipv6, "::1", port);
  Socket_listen (server->listen_socket_ipv6, 10);

  /* Start server thread */
  ASSERT_EQ (pthread_create (&server->thread, NULL, dual_stack_server_thread, server), 0);

  /* Give server time to start */
  usleep (50000);
}

static void
dual_stack_server_stop (DualStackServer *server)
{
  server->running = 0;
  pthread_join (server->thread, NULL);

  Socket_free (&server->listen_socket_ipv6);
  Socket_free (&server->listen_socket_ipv4);
  Arena_dispose (&server->arena);
}

/* ============================================================================
 * Integration Tests
 * ============================================================================
 */

TEST (integration_http_websocket_upgrade_handshake)
{
  UpgradeTestServer server;
  Socket_T client = NULL;

  signal (SIGPIPE, SIG_IGN);

  /* Start upgrade server */
  upgrade_test_server_start (&server);

  /* Connect to server */
  client = Socket_connect_tcp ("127.0.0.1", server.port, 1000);
  ASSERT_NOT_NULL (client);

  /* Send WebSocket upgrade request */
  const char *upgrade_request =
    "GET /ws HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n";

  ssize_t sent = Socket_send (client, upgrade_request, strlen (upgrade_request));
  ASSERT_EQ (sent, (ssize_t)strlen (upgrade_request));

  /* Give server time to process and respond */
  usleep (200000); /* 200ms */

  /* Verify upgrade was completed (server parsed the request) */
  ASSERT_EQ (server.upgrade_complete, 1);

  /* Read the upgrade response */
  char response_buf[1024] = {0};
  ssize_t received = Socket_recv (client, response_buf, sizeof (response_buf));
  ASSERT (received > 0);

  /* Verify it's a switching protocols response */
  ASSERT (strstr (response_buf, "101 Switching Protocols") != NULL);
  ASSERT (strstr (response_buf, "Upgrade: websocket") != NULL);

  /* Cleanup */
  Socket_free (&client);
  upgrade_test_server_stop (&server);
}

TEST (integration_ipv6_dual_stack)
{
  DualStackServer server;
  Socket_T ipv4_client = NULL;
  Socket_T ipv6_client = NULL;

  signal (SIGPIPE, SIG_IGN);

  /* Start dual-stack server */
  dual_stack_server_start (&server);

  /* Test IPv4 connection */
  ipv4_client = Socket_connect_tcp ("127.0.0.1", server.port, 1000);
  ASSERT_NOT_NULL (ipv4_client);

  /* Send test message over IPv4 */
  const char *ipv4_msg = "Hello from IPv4";
  ssize_t sent = Socket_send (ipv4_client, ipv4_msg, strlen (ipv4_msg));
  ASSERT_EQ (sent, (ssize_t)strlen (ipv4_msg));

  /* Receive echo */
  char ipv4_buf[1024] = {0};
  ssize_t received = Socket_recv (ipv4_client, ipv4_buf, sizeof (ipv4_buf));
  ASSERT_EQ (received, sent);
  ASSERT_EQ (strcmp (ipv4_buf, ipv4_msg), 0);

  /* Test IPv6 connection */
  ipv6_client = Socket_new (AF_INET6, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (ipv6_client);

  /* Connect to IPv6 localhost */
  Socket_connect (ipv6_client, "::1", server.port);

  /* Send test message over IPv6 */
  const char *ipv6_msg = "Hello from IPv6";
  sent = Socket_send (ipv6_client, ipv6_msg, strlen (ipv6_msg));
  ASSERT_EQ (sent, (ssize_t)strlen (ipv6_msg));

  /* Receive echo */
  char ipv6_buf[1024] = {0};
  received = Socket_recv (ipv6_client, ipv6_buf, sizeof (ipv6_buf));
  ASSERT_EQ (received, sent);
  ASSERT_EQ (strcmp (ipv6_buf, ipv6_msg), 0);

  /* Wait for server to process connections */
  usleep (100000); /* 100ms */

  /* Verify both connections were handled */
  ASSERT (server.ipv4_connections > 0);
  ASSERT (server.ipv6_connections > 0);

  /* Cleanup */
  Socket_free (&ipv6_client);
  Socket_free (&ipv4_client);
  dual_stack_server_stop (&server);
}

int
main (void)
{
  printf ("=== Multi-Protocol Integration Tests ===\n");

  Test_run_all ();

  printf ("\n");
  return Test_get_failures () > 0 ? 1 : 0;
}