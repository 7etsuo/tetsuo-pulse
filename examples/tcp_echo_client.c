/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * tcp_echo_client.c - Basic TCP Echo Client Example
 *
 * Demonstrates a simple TCP echo client using the core Socket API.
 * Shows basic socket operations: connect, send, recv.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_tcp_echo_client
 *
 * Usage:
 *   ./example_tcp_echo_client [host] [port] [message]
 *   ./example_tcp_echo_client localhost 8080 "Hello, World!"
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "socket/Socket.h"

int
main (int argc, char **argv)
{
  /* Variables that might be clobbered by longjmp must be volatile */
  const char *volatile host = "localhost";
  volatile int port = 8080;
  const char *volatile message = "Hello from TCP echo client!";
  Socket_T sock = NULL;
  volatile int result = 0;

  /* Parse command line arguments */
  if (argc > 1)
    host = argv[1];
  if (argc > 2)
    port = atoi (argv[2]);
  if (argc > 3)
    message = argv[3];

  if (port <= 0 || port > 65535)
    {
      fprintf (stderr, "Invalid port: %d\n", port);
      return 1;
    }

  /* Setup signal handling */
  signal (SIGPIPE, SIG_IGN);

  printf ("TCP Echo Client Example\n");
  printf ("=======================\n\n");
  printf ("Connecting to %s:%d\n", host, port);
  printf ("Message: %s\n\n", message);

  TRY
  {
    /* Create TCP socket */
    sock = Socket_new (AF_INET, SOCK_STREAM, 0);

    /* Connect to server */
    printf ("Connecting...\n");
    Socket_connect (sock, host, port);

    printf ("Connected! Sending message...\n");

    /* Send message */
    Socket_sendall (sock, message, strlen (message));

    /* Receive echo response */
    char buffer[1024];
    ssize_t n = Socket_recv (sock, buffer, sizeof (buffer) - 1);

    if (n > 0)
      {
        buffer[n] = '\0';
        printf ("Received echo (%zd bytes): %s\n", n, buffer);

        /* Verify it's the same message */
        if (n == (ssize_t)strlen (message) && memcmp (buffer, message, n) == 0)
          {
            printf ("✅ Echo successful!\n");
          }
        else
          {
            printf ("❌ Echo mismatch!\n");
            result = 1;
          }
      }
    else if (n == 0)
      {
        printf ("Server closed connection unexpectedly\n");
        result = 1;
      }
    else
      {
        printf ("Receive error\n");
        result = 1;
      }

    /* Clean close */
    Socket_shutdown (sock, SHUT_WR); /* Send EOF */

    /* Read any remaining data */
    while ((n = Socket_recv (sock, buffer, sizeof (buffer))) > 0)
      {
        /* Discard remaining data */
      }
  }
  EXCEPT (Socket_Failed)
  {
    fprintf (stderr, "Socket error\n");
    result = 1;
  }
  END_TRY;

  /* Cleanup */
  if (sock)
    Socket_free (&sock);

  return result;
}
