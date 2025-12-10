/**
 * test_connection_resilience.c - Connection Resilience Integration Tests
 *
 * Tests connection recovery and state preservation:
 * - Connection state preservation across operations
 * - Manual reconnection after connection loss
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
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "test/Test.h"

/* ============================================================================
 * Integration Tests
 * ============================================================================
 */

TEST (integration_connection_state_preservation)
{
  Socket_T client = NULL;
  Socket_T server_sock = NULL;
  int initial_live_count;

  signal (SIGPIPE, SIG_IGN);

  /* Track initial socket count for leak detection */
  initial_live_count = Socket_debug_live_count ();

  /* Create a simple echo server for this test */
  server_sock = Socket_listen_tcp ("127.0.0.1", 0, 1);
  ASSERT_NOT_NULL (server_sock);
  int port = Socket_getlocalport (server_sock);

  /* Connect client */
  client = Socket_connect_tcp ("127.0.0.1", port, 1000);
  ASSERT_NOT_NULL (client);

  /* Accept connection */
  Socket_T accepted = Socket_accept_timeout (server_sock, 1000);
  ASSERT_NOT_NULL (accepted);

  /* Verify initial connection state */
  ASSERT_EQ (Socket_isconnected (client), 1);

  /* Send and receive a simple message to test basic functionality */
  const char *test_msg = "State preservation test";
  ssize_t sent = Socket_send (client, test_msg, strlen (test_msg));
  ASSERT_EQ (sent, (ssize_t)strlen (test_msg));

  char buf[1024] = {0};
  ssize_t received = Socket_recv (accepted, buf, sizeof (buf));
  ASSERT_EQ (received, sent);
  ASSERT_EQ (strcmp (buf, test_msg), 0);

  /* Echo back */
  sent = Socket_send (accepted, buf, received);
  ASSERT_EQ (sent, received);

  /* Receive echo on client */
  memset (buf, 0, sizeof (buf));
  received = Socket_recv (client, buf, sizeof (buf));
  ASSERT_EQ (received, sent);
  ASSERT_EQ (strcmp (buf, test_msg), 0);

  /* Verify connection still works */
  ASSERT_EQ (Socket_isconnected (client), 1);

  /* Cleanup */
  Socket_free (&accepted);
  Socket_free (&client);
  Socket_free (&server_sock);

  /* Verify no socket leaks */
  ASSERT_EQ (Socket_debug_live_count (), initial_live_count);
}

TEST (integration_connection_recovery_manual_reconnect)
{
  Socket_T server_sock = NULL;
  Socket_T client = NULL;
  int reconnect_attempts = 0;

  signal (SIGPIPE, SIG_IGN);

  /* Create a simple echo server */
  server_sock = Socket_listen_tcp ("127.0.0.1", 0, 5);
  ASSERT_NOT_NULL (server_sock);
  int port = Socket_getlocalport (server_sock);

  /* Manual reconnection test */
  const int max_attempts = 3;

  for (int attempt = 0; attempt < max_attempts; attempt++)
    {
      /* Create new client connection */
      client = Socket_connect_tcp ("127.0.0.1", port, 1000);
      if (client)
        {
          reconnect_attempts++;

          /* Accept connection on server */
          Socket_T accepted = Socket_accept_timeout (server_sock, 500);
          if (accepted)
            {
              /* Send test message */
              char msg[64];
              snprintf (msg, sizeof (msg), "Client %d message", attempt);
              ssize_t sent = Socket_send (client, msg, strlen (msg));
              if (sent > 0)
                {
                  /* Receive on server */
                  char buf[1024] = {0};
                  ssize_t received = Socket_recv (accepted, buf, sizeof (buf));
                  if (received > 0)
                    {
                      /* Echo back */
                      Socket_send (accepted, buf, received);
                    }
                }

              /* Receive echo on client */
              char client_buf[1024] = {0};
              ssize_t client_received = Socket_recv (client, client_buf, sizeof (client_buf));
              ASSERT (client_received > 0);

              Socket_free (&accepted);
            }

          /* Close connection */
          Socket_free (&client);
          client = NULL;

          /* Wait before next attempt */
          usleep (50000);
        }
    }

  /* Verify we successfully reconnected multiple times */
  ASSERT_EQ (reconnect_attempts, max_attempts);

  /* Cleanup */
  Socket_free (&server_sock);
}

int
main (void)
{
  printf ("=== Connection Resilience Integration Tests ===\n");

  Test_run_all ();

  printf ("\n");
  return Test_get_failures () > 0 ? 1 : 0;
}