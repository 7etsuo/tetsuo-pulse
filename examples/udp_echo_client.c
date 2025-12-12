/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * udp_echo_client.c - Basic UDP Echo Client Example
 *
 * Demonstrates a simple UDP echo client using the SocketDgram API.
 * Shows UDP socket operations: connect, send, recv.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_udp_echo_client
 *
 * Usage:
 *   ./example_udp_echo_client [host] [port] [message]
 *   ./example_udp_echo_client localhost 8080 "Hello, World!"
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "socket/SocketDgram.h"

int
main (int argc, char **argv)
{
  /* Variables that might be clobbered by longjmp must be volatile */
  const char *volatile host = "localhost";
  volatile int port = 8080;
  const char *volatile message = "Hello from UDP echo client!";
  SocketDgram_T sock = NULL;
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

  printf ("UDP Echo Client Example\n");
  printf ("=======================\n\n");
  printf ("Connecting to %s:%d\n", host, port);
  printf ("Message: %s\n\n", message);

  TRY
  {
    /* Create UDP socket */
    sock = SocketDgram_new (AF_INET, 0);

    /* Connect to server (optional, but sets default destination) */
    printf ("Setting default destination...\n");
    SocketDgram_connect (sock, host, port);

    printf ("Sending message...\n");

    /* Send message */
    SocketDgram_send (sock, message, strlen (message));

    /* Receive echo response */
    char buffer[1024];
    ssize_t n = SocketDgram_recv (sock, buffer, sizeof (buffer) - 1);

    if (n > 0)
      {
        buffer[n] = '\0';
        printf ("Received echo (%zd bytes): %s\n", n, buffer);

        /* Verify it's the same message */
        if (n == (ssize_t)strlen (message) &&
            memcmp (buffer, message, n) == 0)
          {
            printf ("✅ Echo successful!\n");
          }
        else
          {
            printf ("❌ Echo mismatch!\n");
            result = 1;
          }
      }
      else
        {
          printf ("Receive error or timeout\n");
          result = 1;
        }
  }
  EXCEPT (SocketDgram_Failed)
  {
    fprintf (stderr, "UDP socket error\n");
    result = 1;
  }
  END_TRY;

  /* Cleanup */
  if (sock)
    SocketDgram_free (&sock);

  return result;
}