/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_simple_recv_line.c - Tests for optimized Socket_simple_recv_line
 *
 * Validates buffered I/O implementation for line-oriented protocols.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "simple/SocketSimple.h"
#include "test/Test.h"

#define TEST_PORT 17980

/* Server thread that sends lines */
static void *
server_thread (void *arg)
{
  int port = *(int *)arg;
  SocketSimple_Socket_T server = Socket_simple_listen (NULL, port, 5);
  if (!server)
    {
      return NULL;
    }

  SocketSimple_Socket_T client = Socket_simple_accept (server);
  if (client)
    {
      /* Send multiple lines */
      const char *lines[] = { "First line\n",
                              "Second line\n",
                              "Third line with more data\n",
                              "Final line\n" };

      for (size_t i = 0; i < sizeof (lines) / sizeof (lines[0]); i++)
        {
          Socket_simple_send (client, lines[i], strlen (lines[i]));
        }

      usleep (100000); /* Wait 100ms before close */
      Socket_simple_close (&client);
    }

  Socket_simple_close (&server);
  return NULL;
}

TEST (simple_recv_line_basic)
{
  int port = TEST_PORT;
  pthread_t tid;

  /* Start server */
  pthread_create (&tid, NULL, server_thread, &port);
  usleep (100000); /* Wait for server to start */

  /* Connect client */
  SocketSimple_Socket_T client = Socket_simple_connect ("127.0.0.1", port);
  ASSERT_NOT_NULL (client);

  /* Receive lines */
  char buf[256];
  ssize_t n;

  n = Socket_simple_recv_line (client, buf, sizeof (buf));
  ASSERT (n > 0);
  ASSERT (strcmp (buf, "First line\n") == 0);

  n = Socket_simple_recv_line (client, buf, sizeof (buf));
  ASSERT (n > 0);
  ASSERT (strcmp (buf, "Second line\n") == 0);

  n = Socket_simple_recv_line (client, buf, sizeof (buf));
  ASSERT (n > 0);
  ASSERT (strcmp (buf, "Third line with more data\n") == 0);

  n = Socket_simple_recv_line (client, buf, sizeof (buf));
  ASSERT (n > 0);
  ASSERT (strcmp (buf, "Final line\n") == 0);

  Socket_simple_close (&client);
  pthread_join (tid, NULL);
}

/* Test reading lines without newlines (EOF case) */
static void *
server_thread_no_newline (void *arg)
{
  int port = *(int *)arg;
  SocketSimple_Socket_T server = Socket_simple_listen (NULL, port, 5);
  if (!server)
    {
      return NULL;
    }

  SocketSimple_Socket_T client = Socket_simple_accept (server);
  if (client)
    {
      const char *data = "Line without newline";
      Socket_simple_send (client, data, strlen (data));
      usleep (50000);
      Socket_simple_close (&client);
    }

  Socket_simple_close (&server);
  return NULL;
}

TEST (simple_recv_line_no_newline)
{
  int port = TEST_PORT + 1;
  pthread_t tid;

  pthread_create (&tid, NULL, server_thread_no_newline, &port);
  usleep (100000);

  SocketSimple_Socket_T client = Socket_simple_connect ("127.0.0.1", port);
  ASSERT_NOT_NULL (client);

  char buf[256];
  ssize_t n = Socket_simple_recv_line (client, buf, sizeof (buf));
  ASSERT (n > 0);
  ASSERT (strcmp (buf, "Line without newline") == 0);

  Socket_simple_close (&client);
  pthread_join (tid, NULL);
}

/* Test buffer boundary conditions */
static void *
server_thread_long_lines (void *arg)
{
  int port = *(int *)arg;
  SocketSimple_Socket_T server = Socket_simple_listen (NULL, port, 5);
  if (!server)
    {
      return NULL;
    }

  SocketSimple_Socket_T client = Socket_simple_accept (server);
  if (client)
    {
      /* Send a line longer than typical buffer */
      char long_line[5000];
      memset (long_line, 'A', sizeof (long_line) - 2);
      long_line[sizeof (long_line) - 2] = '\n';
      long_line[sizeof (long_line) - 1] = '\0';

      Socket_simple_send (client, long_line, strlen (long_line));
      usleep (50000);
      Socket_simple_close (&client);
    }

  Socket_simple_close (&server);
  return NULL;
}

TEST (simple_recv_line_long_line)
{
  int port = TEST_PORT + 2;
  pthread_t tid;

  pthread_create (&tid, NULL, server_thread_long_lines, &port);
  usleep (100000);

  SocketSimple_Socket_T client = Socket_simple_connect ("127.0.0.1", port);
  ASSERT_NOT_NULL (client);

  char buf[6000];
  ssize_t n = Socket_simple_recv_line (client, buf, sizeof (buf));
  ASSERT (n > 0);
  ASSERT (buf[n - 1] == '\n');

  /* Verify content */
  for (ssize_t i = 0; i < n - 1; i++)
    {
      ASSERT (buf[i] == 'A');
    }

  Socket_simple_close (&client);
  pthread_join (tid, NULL);
}

/* Test maxlen boundary */
TEST (simple_recv_line_maxlen)
{
  int port = TEST_PORT + 3;
  pthread_t tid;

  pthread_create (&tid, NULL, server_thread_long_lines, &port);
  usleep (100000);

  SocketSimple_Socket_T client = Socket_simple_connect ("127.0.0.1", port);
  ASSERT_NOT_NULL (client);

  /* Use small buffer to test maxlen */
  char buf[100];
  ssize_t n = Socket_simple_recv_line (client, buf, sizeof (buf));
  ASSERT (n > 0);
  ASSERT ((size_t)n <= sizeof (buf) - 1);
  ASSERT (buf[n] == '\0');

  Socket_simple_close (&client);
  pthread_join (tid, NULL);
}

/* Test invalid arguments */
TEST (simple_recv_line_invalid_args)
{
  char buf[100];

  /* NULL socket */
  ssize_t n = Socket_simple_recv_line (NULL, buf, sizeof (buf));
  ASSERT (n < 0);

  /* NULL buffer */
  SocketSimple_Socket_T sock = Socket_simple_connect ("127.0.0.1", 80);
  if (sock)
    {
      n = Socket_simple_recv_line (sock, NULL, sizeof (buf));
      ASSERT (n < 0);

      /* Zero maxlen */
      n = Socket_simple_recv_line (sock, buf, 0);
      ASSERT (n < 0);

      Socket_simple_close (&sock);
    }
}

/* Test multiple consecutive calls (buffering) */
static void *
server_thread_multiple_short_lines (void *arg)
{
  int port = *(int *)arg;
  SocketSimple_Socket_T server = Socket_simple_listen (NULL, port, 5);
  if (!server)
    {
      return NULL;
    }

  SocketSimple_Socket_T client = Socket_simple_accept (server);
  if (client)
    {
      /* Send many short lines in one send to test buffering */
      const char *data = "A\nB\nC\nD\nE\nF\nG\nH\nI\nJ\n";
      Socket_simple_send (client, data, strlen (data));
      usleep (50000);
      Socket_simple_close (&client);
    }

  Socket_simple_close (&server);
  return NULL;
}

TEST (simple_recv_line_buffering)
{
  int port = TEST_PORT + 4;
  pthread_t tid;

  pthread_create (&tid, NULL, server_thread_multiple_short_lines, &port);
  usleep (100000);

  SocketSimple_Socket_T client = Socket_simple_connect ("127.0.0.1", port);
  ASSERT_NOT_NULL (client);

  /* Receive multiple short lines - should use internal buffer */
  const char *expected[] = { "A\n", "B\n", "C\n", "D\n", "E\n",
                             "F\n", "G\n", "H\n", "I\n", "J\n" };

  for (size_t i = 0; i < sizeof (expected) / sizeof (expected[0]); i++)
    {
      char buf[10];
      ssize_t n = Socket_simple_recv_line (client, buf, sizeof (buf));
      ASSERT (n > 0);
      ASSERT (strcmp (buf, expected[i]) == 0);
    }

  Socket_simple_close (&client);
  pthread_join (tid, NULL);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
