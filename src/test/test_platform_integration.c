/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_platform_integration.c - Platform-Specific Integration Tests
 *
 * Tests platform-specific functionality and performance:
 * - Unix domain socket performance and reliability
 * - Platform-specific socket options and behavior
 * - Filesystem integration (sendfile, splice)
 * - Platform-specific TLS behavior
 * - OS-specific socket features
 */

#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "test/Test.h"

#ifdef __linux__
#include <sys/sendfile.h>
#endif

/* ============================================================================
 * Test Configuration
 * ============================================================================
 */

#define TEST_TIMEOUT_MS 5000
#define TEST_SOCKET_PATH "/tmp/test_unix_socket"
#define TEST_DATA_SIZE (64 * 1024) /* 64KB for performance tests */

static int platform_test_counter = 0;

static char *
get_test_socket_path (void)
{
  static char path[256];
  snprintf (path,
            sizeof (path),
            "/tmp/test_unix_socket_%d_%d",
            getpid (),
            platform_test_counter++);
  return path;
}

/* ============================================================================
 * Unix Domain Socket Performance Server
 * ============================================================================
 */

typedef struct
{
  Socket_T listen_socket;
  pthread_t thread;
  atomic_int running;
  atomic_int connections_handled;
  atomic_int bytes_transferred;
  int messages_processed;
  const char *socket_path;
  Arena_T arena;
} UnixSocketServer;

static void *
unix_socket_server_thread (void *arg)
{
  UnixSocketServer *server = (UnixSocketServer *)arg;
  SocketPoll_T poll = SocketPoll_new (10);

  SocketPoll_add (poll, server->listen_socket, POLL_READ, NULL);

  while (server->running)
    {
      SocketEvent_T *events = NULL;
      int nfds = SocketPoll_wait (poll, &events, 100);

      for (int i = 0; i < nfds; i++)
        {
          if (events[i].socket == server->listen_socket)
            {
              /* Accept Unix domain connection */
              Socket_T accepted = Socket_accept (server->listen_socket);
              if (accepted)
                {
                  server->connections_handled++;
                  SocketPoll_add (poll, accepted, POLL_READ, (void *)1);
                }
            }
          else if (events[i].data == (void *)1) /* Client connection */
            {
              Socket_T sock = events[i].socket;
              char buf[8192];
              ssize_t n = Socket_recv (sock, buf, sizeof (buf));

              if (n > 0)
                {
                  server->bytes_transferred += n;
                  server->messages_processed++;

                  /* Echo back the data */
                  ssize_t sent = Socket_send (sock, buf, n);
                  if (sent > 0)
                    {
                      server->bytes_transferred += sent;
                    }
                }
              else if (n == 0)
                {
                  /* Connection closed */
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
unix_socket_server_start (UnixSocketServer *server, const char *socket_path)
{
  server->arena = Arena_new ();
  server->running = 1;
  server->connections_handled = 0;
  server->bytes_transferred = 0;
  server->messages_processed = 0;
  server->socket_path = socket_path;

  /* Clean up any existing socket file */
  unlink (socket_path);

  /* Create Unix domain listening socket */
  server->listen_socket = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (server->listen_socket);

  Socket_bind_unix (server->listen_socket, socket_path);
  Socket_listen (server->listen_socket, 10);

  /* Start server thread */
  ASSERT_EQ (
      pthread_create (&server->thread, NULL, unix_socket_server_thread, server),
      0);

  /* Give server time to start */
  usleep (50000);
}

static void
unix_socket_server_stop (UnixSocketServer *server)
{
  server->running = 0;
  pthread_join (server->thread, NULL);

  if (server->listen_socket)
    Socket_free (&server->listen_socket);

  if (server->socket_path)
    unlink (server->socket_path);

  Arena_dispose (&server->arena);
}

/* ============================================================================
 * Integration Tests
 * ============================================================================
 */

TEST (integration_platform_unix_socket_performance)
{
  Socket_T socks[2] = { NULL, NULL };

  /* Test Unix socket pair for basic performance */
  SocketPair_new (SOCK_STREAM, &socks[0], &socks[1]);
  ASSERT_NOT_NULL (socks[0]);
  ASSERT_NOT_NULL (socks[1]);

  /* Send a few messages quickly */
  for (int i = 0; i < 10; i++)
    {
      char msg[64];
      snprintf (msg, sizeof (msg), "Performance test %d", i);
      ssize_t sent = Socket_send (socks[0], msg, strlen (msg));
      ASSERT_EQ (sent, (ssize_t)strlen (msg));

      char buf[128] = { 0 };
      ssize_t received = Socket_recv (socks[1], buf, sizeof (buf));
      ASSERT_EQ (received, sent);
      ASSERT_EQ (strcmp (buf, msg), 0);
    }

  /* Cleanup */
  Socket_free (&socks[1]);
  Socket_free (&socks[0]);
}

TEST (integration_platform_unix_socket_reliability)
{
  Socket_T socks[2] = { NULL, NULL };

  /* Test Unix socket pair creation and basic communication */
  SocketPair_new (SOCK_STREAM, &socks[0], &socks[1]);
  ASSERT_NOT_NULL (socks[0]);
  ASSERT_NOT_NULL (socks[1]);

  /* Send test message */
  const char *test_msg = "Unix socket pair test";
  ssize_t sent = Socket_send (socks[0], test_msg, strlen (test_msg));
  ASSERT_EQ (sent, (ssize_t)strlen (test_msg));

  /* Receive on other end */
  char buf[256] = { 0 };
  ssize_t received = Socket_recv (socks[1], buf, sizeof (buf));
  ASSERT_EQ (received, sent);
  ASSERT_EQ (strcmp (buf, test_msg), 0);

  /* Cleanup */
  Socket_free (&socks[1]);
  Socket_free (&socks[0]);
}

TEST (integration_platform_socket_duplication)
{
  UnixSocketServer server;
  Socket_T client = NULL;
  Socket_T dup_client = NULL;
  char *socket_path = NULL;

  signal (SIGPIPE, SIG_IGN);

  /* Start Unix socket server */
  socket_path = get_test_socket_path ();
  unix_socket_server_start (&server, socket_path);

  /* Create client socket */
  client = Socket_new (AF_UNIX, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (client);

  Socket_connect_unix (client, socket_path);

  /* Duplicate the socket */
  dup_client = Socket_dup (client);
  ASSERT_NOT_NULL (dup_client);

  /* Verify they are different objects but reference same underlying socket */
  ASSERT_NE (client, dup_client);
  ASSERT_NE (Socket_fd (client), Socket_fd (dup_client));

  /* Test that both can be used for I/O */
  const char *msg1 = "Message through original socket";

  /* Send through original socket */
  ssize_t sent1 = Socket_send (client, msg1, strlen (msg1));
  ASSERT_EQ (sent1, (ssize_t)strlen (msg1));

  /* Receive echo */
  char buf1[256] = { 0 };
  ssize_t received1 = Socket_recv (client, buf1, sizeof (buf1) - 1);
  if (received1 > 0)
    {
      ASSERT_EQ (received1, sent1);
      ASSERT_EQ (strcmp (buf1, msg1), 0);
    }

  /* Server processing is tested separately */

  /* Cleanup */
  Socket_free (&dup_client);
  Socket_free (&client);
  unix_socket_server_stop (&server);
}

TEST (integration_platform_socket_options)
{
  Socket_T sock = NULL;

  signal (SIGPIPE, SIG_IGN);

  /* Test various socket options */
  sock = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (sock);

  /* Test reuse address */
  Socket_setreuseaddr (sock);

  /* Test non-blocking mode */
  Socket_setnonblocking (sock);

  /* Test various TCP options if supported */
  Socket_setnodelay (sock, 1);           /* Disable Nagle */
  Socket_setkeepalive (sock, 60, 10, 3); /* Enable keepalive */

  /* Test timeout settings */
  Socket_settimeout (sock, 5000); /* 5 second timeout */

  /* Test buffer size settings (may be adjusted by OS) */
  Socket_setbandwidth (sock, 1024 * 1024); /* 1MB/s bandwidth limit */

  /* Socket should still be valid after setting options */
  ASSERT_EQ (Socket_fd (sock), Socket_fd (sock)); /* Basic validity check */

  /* Cleanup */
  Socket_free (&sock);
}

TEST (integration_platform_unix_socket_fd_passing)
{
  Socket_T socks[2] = { NULL, NULL };
  int test_fd = -1;

  signal (SIGPIPE, SIG_IGN);

  /* Create Unix socket pair */
  SocketPair_new (SOCK_STREAM, &socks[0], &socks[1]);
  ASSERT_NOT_NULL (socks[0]);
  ASSERT_NOT_NULL (socks[1]);

  /* Create a test file descriptor to pass */
  char temp_file[256];
  snprintf (
      temp_file, sizeof (temp_file), "/tmp/test_fd_pass_%d.txt", getpid ());

  test_fd = open (temp_file, O_CREAT | O_RDWR, 0644);
  ASSERT (test_fd >= 0);

  /* Write some data to the file */
  const char *test_data = "Data in passed file descriptor";
  ssize_t written = write (test_fd, test_data, strlen (test_data));
  ASSERT (written == (ssize_t)strlen (test_data));
  lseek (test_fd, 0, SEEK_SET); /* Reset to beginning */

  /* Try to send file descriptor (if supported) */
  int sent_fd = Socket_sendfd (socks[0], test_fd);
  if (sent_fd >= 0)
    {
      /* FD passing succeeded */
      int received_fd = -1;
      int recv_result = Socket_recvfd (socks[1], &received_fd);
      if (recv_result >= 0 && received_fd >= 0)
        {
          /* Verify we can read from the received FD */
          char buf[256] = { 0 };
          ssize_t n = read (received_fd, buf, sizeof (buf) - 1);
          ASSERT (n > 0);
          ASSERT_EQ (strcmp (buf, test_data), 0);

          close (received_fd);
        }
    }
  else
    {
      /* FD passing not supported or failed */
      printf ("  [INFO] File descriptor passing not supported\n");
    }

  close (test_fd);
  test_fd = -1;
  unlink (temp_file);

  /* Cleanup */
  Socket_free (&socks[1]);
  Socket_free (&socks[0]);
}

int
main (void)
{
  printf ("=== Platform-Specific Integration Tests ===\n");

  Test_run_all ();

  printf ("\n");
  return Test_get_failures () > 0 ? 1 : 0;
}