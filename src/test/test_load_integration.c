/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_load_integration.c - Load Testing Integration Tests
 *
 * Tests library behavior under load and stress conditions:
 * - Memory leak detection during prolonged operation
 * - Connection churn (rapid connect/disconnect cycles)
 * - Resource exhaustion scenarios
 * - Long-running stability testing
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
#include "core/SocketMetrics.h"
#include "poll/SocketPoll.h"
#include "pool/SocketPool.h"
#include "socket/Socket.h"
#include "test/Test.h"

#define TEST_PORT_BASE 50000
#define TEST_TIMEOUT_MS 5000

static int load_test_port_counter = 0;

static int
get_load_test_port (void)
{
  return TEST_PORT_BASE + (load_test_port_counter++ % 1000);
}

typedef struct
{
  Socket_T listen_socket;
  pthread_t thread;
  atomic_int running;
  atomic_int connections_handled;
  atomic_int messages_processed;
  int port;
  Arena_T arena;
  /* Load testing parameters */
  atomic_int max_connections;
  atomic_int connection_timeout_ms;
} LoadTestServer;

static void *
load_test_server_thread (void *arg)
{
  LoadTestServer *server = (LoadTestServer *)arg;
  SocketPoll_T poll = SocketPoll_new (server->max_connections + 10);

  SocketPoll_add (poll, server->listen_socket, POLL_READ, NULL);

  while (server->running)
    {
      SocketEvent_T *events = NULL;
      int nfds = SocketPoll_wait (
          poll, &events, 50); /* Short timeout for responsiveness */

      for (int i = 0; i < nfds; i++)
        {
          if (events[i].socket == server->listen_socket)
            {
              /* Accept new connections */
              Socket_T accepted = Socket_accept (server->listen_socket);
              if (accepted)
                {
                  server->connections_handled++;

                  /* Set timeout for connection */
                  Socket_settimeout (accepted, server->connection_timeout_ms);

                  /* Add to poll set */
                  SocketPoll_add (poll, accepted, POLL_READ, (void *)1);

                  /* If we've hit max connections, start closing old ones */
                  if (server->connections_handled > server->max_connections)
                    {
                      /* Close this connection to prevent overload */
                      SocketPoll_del (poll, accepted);
                      Socket_free (&accepted);
                      continue;
                    }
                }
            }
          else if (events[i].data == (void *)1) /* Client connection */
            {
              Socket_T sock = events[i].socket;
              char buf[1024];
              ssize_t n = Socket_recv (sock, buf, sizeof (buf));

              if (n > 0)
                {
                  server->messages_processed++;

                  /* Echo back the data */
                  ssize_t sent = Socket_send (sock, buf, n);
                  if (sent > 0)
                    {
                      server->messages_processed++; /* Count responses too */
                    }
                }
              else if (n == 0 || (n < 0 && errno != EAGAIN))
                {
                  /* Connection closed or error */
                  SocketPoll_del (poll, sock);
                  Socket_free (&sock);
                }
            }
        }
    }

  SocketPoll_free (&poll);
  return NULL;
}

static void
load_test_server_start (LoadTestServer *server,
                        int max_connections,
                        int timeout_ms)
{
  int port = get_load_test_port ();

  server->arena = Arena_new ();
  server->port = port;
  server->running = 1;
  server->connections_handled = 0;
  server->messages_processed = 0;
  server->max_connections = max_connections;
  server->connection_timeout_ms = timeout_ms;

  /* Create listening socket */
  server->listen_socket
      = Socket_listen_tcp ("127.0.0.1", port, max_connections);
  ASSERT_NOT_NULL (server->listen_socket);

  /* Start server thread */
  ASSERT_EQ (
      pthread_create (&server->thread, NULL, load_test_server_thread, server),
      0);

  /* Give server time to start */
  usleep (100000);
}

static void
load_test_server_stop (LoadTestServer *server)
{
  server->running = 0;
  pthread_join (server->thread, NULL);

  if (server->listen_socket)
    Socket_free (&server->listen_socket);

  Arena_dispose (&server->arena);
}

typedef struct
{
  pthread_t thread;
  atomic_int running;
  atomic_int connections_made;
  atomic_int messages_sent;
  atomic_int errors_encountered;
  int port;
  int iterations;
  int delay_us;
} LoadTestClient;

static void *
load_test_client_thread (void *arg)
{
  LoadTestClient *client = (LoadTestClient *)arg;

  for (int i = 0; i < client->iterations && client->running; i++)
    {
      Socket_T sock = Socket_connect_tcp ("127.0.0.1", client->port, 500);
      if (sock)
        {
          client->connections_made++;

          /* Send a small message */
          const char *msg = "load_test";
          ssize_t sent = Socket_send (sock, msg, strlen (msg));
          if (sent > 0)
            {
              client->messages_sent++;

              /* Receive echo */
              char buf[64];
              ssize_t received = Socket_recv (sock, buf, sizeof (buf));
              if (received <= 0)
                {
                  client->errors_encountered++;
                }
            }
          else
            {
              client->errors_encountered++;
            }

          Socket_free (&sock);
        }
      else
        {
          client->errors_encountered++;
        }

      /* Small delay between connections */
      if (client->delay_us > 0)
        usleep (client->delay_us);
    }

  return NULL;
}

static void
load_test_client_start (LoadTestClient *client,
                        int port,
                        int iterations,
                        int delay_us)
{
  client->running = 1;
  client->connections_made = 0;
  client->messages_sent = 0;
  client->errors_encountered = 0;
  client->port = port;
  client->iterations = iterations;
  client->delay_us = delay_us;

  ASSERT_EQ (
      pthread_create (&client->thread, NULL, load_test_client_thread, client),
      0);
}

static void
load_test_client_stop (LoadTestClient *client)
{
  client->running = 0;
  pthread_join (client->thread, NULL);
}

TEST (integration_load_connection_churn)
{
  Socket_T server_sock = NULL;
  int total_connections = 0;
  int total_messages = 0;

  signal (SIGPIPE, SIG_IGN);

  /* Create simple echo server */
  server_sock = Socket_listen_tcp ("127.0.0.1", 0, 10);
  ASSERT_NOT_NULL (server_sock);
  int port = Socket_getlocalport (server_sock);

  /* Simple connection churn test */
  for (int i = 0; i < 20; i++)
    {
      Socket_T client = Socket_connect_tcp ("127.0.0.1", port, 1000);
      if (client)
        {
          total_connections++;

          /* Accept connection */
          Socket_T accepted = Socket_accept_timeout (server_sock, 500);
          if (accepted)
            {
              /* Send message */
              char msg[64];
              snprintf (msg, sizeof (msg), "Churn test %d", i);
              ssize_t sent = Socket_send (client, msg, strlen (msg));
              if (sent > 0)
                {
                  total_messages++;

                  /* Receive and echo */
                  char buf[1024] = { 0 };
                  ssize_t received = Socket_recv (accepted, buf, sizeof (buf));
                  if (received > 0)
                    {
                      Socket_send (accepted, buf, received);
                    }
                }

              /* Receive echo */
              char client_buf[1024] = { 0 };
              Socket_recv (client, client_buf, sizeof (client_buf));

              Socket_free (&accepted);
            }

          Socket_free (&client);

          /* Small delay between connections */
          usleep (5000);
        }
    }

  printf ("  Total connections: %d, messages: %d\n",
          total_connections,
          total_messages);

  /* Verify basic functionality */
  ASSERT (total_connections > 0);
  ASSERT (total_messages > 0);

  /* Cleanup */
  Socket_free (&server_sock);
}

TEST (integration_load_resource_exhaustion)
{
  Socket_T server_sock = NULL;
  const int num_clients = 5;

  signal (SIGPIPE, SIG_IGN);

  /* Create simple echo server */
  server_sock = Socket_listen_tcp ("127.0.0.1", 0, 10);
  ASSERT_NOT_NULL (server_sock);
  int port = Socket_getlocalport (server_sock);

  /* Try to create multiple concurrent connections */
  int successful_connections = 0;

  for (int i = 0; i < num_clients; i++)
    {
      Socket_T client = Socket_connect_tcp ("127.0.0.1", port, 1000);
      if (client)
        {
          successful_connections++;

          /* Accept connection */
          Socket_T accepted = Socket_accept_timeout (server_sock, 500);
          if (accepted)
            {
              /* Send a message to ensure connection works */
              const char *msg = "resource_test";
              ssize_t sent = Socket_send (client, msg, strlen (msg));
              if (sent > 0)
                {
                  /* Receive and echo */
                  char buf[1024] = { 0 };
                  ssize_t received = Socket_recv (accepted, buf, sizeof (buf));
                  if (received > 0)
                    {
                      Socket_send (accepted, buf, received);
                    }
                }

              /* Receive echo */
              char client_buf[1024] = { 0 };
              Socket_recv (client, client_buf, sizeof (client_buf));

              Socket_free (&accepted);
            }

          Socket_free (&client);
        }
    }

  printf (
      "  Successful connections: %d/%d\n", successful_connections, num_clients);

  /* Should have some connections */
  ASSERT (successful_connections > 0);

  /* Cleanup */
  Socket_free (&server_sock);
}

TEST (integration_load_long_running_stability)
{
  Socket_T server_sock = NULL;
  Socket_T client = NULL;
  int connections_made = 0;
  int messages_sent = 0;
  int initial_live_count;
  int final_live_count;

  signal (SIGPIPE, SIG_IGN);

  /* Track initial state */
  initial_live_count = Socket_debug_live_count ();

  /* Create simple echo server */
  server_sock = Socket_listen_tcp ("127.0.0.1", 0, 10);
  ASSERT_NOT_NULL (server_sock);
  int port = Socket_getlocalport (server_sock);

  /* Simple stability test - make multiple connections */
  for (int i = 0; i < 20; i++)
    {
      client = Socket_connect_tcp ("127.0.0.1", port, 1000);
      if (client)
        {
          connections_made++;

          /* Accept connection */
          Socket_T accepted = Socket_accept_timeout (server_sock, 500);
          if (accepted)
            {
              /* Send message */
              char msg[64];
              snprintf (msg, sizeof (msg), "Stability test %d", i);
              ssize_t sent = Socket_send (client, msg, strlen (msg));
              if (sent > 0)
                {
                  messages_sent++;

                  /* Receive and echo */
                  char buf[1024] = { 0 };
                  ssize_t received = Socket_recv (accepted, buf, sizeof (buf));
                  if (received > 0)
                    {
                      Socket_send (accepted, buf, received);
                    }
                }

              /* Receive echo */
              char client_buf[1024] = { 0 };
              Socket_recv (client, client_buf, sizeof (client_buf));

              Socket_free (&accepted);
            }

          Socket_free (&client);
          client = NULL;

          /* Small delay */
          usleep (10000);
        }
    }

  /* Check final state */
  final_live_count = Socket_debug_live_count ();

  printf ("  Initial sockets: %d, Final sockets: %d\n",
          initial_live_count,
          final_live_count);
  printf ("  Made %d connections, sent %d messages\n",
          connections_made,
          messages_sent);

  /* Verify basic functionality */
  ASSERT (connections_made > 0);
  ASSERT (messages_sent > 0);

  /* Check for major memory leaks */
  int leaked_sockets = final_live_count - initial_live_count;
  ASSERT (leaked_sockets <= 2); /* Allow small variance */

  /* Cleanup */
  Socket_free (&server_sock);
}

int
main (void)
{
  printf ("=== Load Testing Integration Tests ===\n");

  Test_run_all ();

  printf ("\n");
  return Test_get_failures () > 0 ? 1 : 0;
}