/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * tcp_echo_server.c - Basic TCP Echo Server Example
 *
 * Demonstrates a simple TCP echo server using the core Socket API.
 * Shows basic socket operations: bind, listen, accept, recv, send.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_tcp_echo_server
 *
 * Usage:
 *   ./example_tcp_echo_server [port]
 *   ./example_tcp_echo_server 8080
 *
 * Test with:
 *   echo "Hello, World!" | nc localhost 8080
 *   telnet localhost 8080
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "socket/Socket.h"

/* Global flag for graceful shutdown */
static volatile int running = 1;

static void
signal_handler (int signo)
{
  (void)signo;
  running = 0;
}

int
main (int argc, char **argv)
{
  volatile int port = 8080;
  Socket_T server = NULL;
  Socket_T client = NULL;
  volatile int result = 0;

  /* Parse port from command line */
  if (argc > 1)
    {
      port = atoi (argv[1]);
      if (port <= 0 || port > 65535)
        {
          fprintf (stderr, "Invalid port: %s\n", argv[1]);
          return 1;
        }
    }

  /* Setup signal handlers */
  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);
  signal (SIGPIPE, SIG_IGN);

  printf ("TCP Echo Server Example\n");
  printf ("=======================\n\n");
  printf ("Listening on port %d\n", port);
  printf ("Test with: echo 'Hello' | nc localhost %d\n\n", port);
  printf ("Press Ctrl+C to stop\n\n");

  TRY
  {
    /* Create TCP socket */
    server = Socket_new (AF_INET, SOCK_STREAM, 0);

    /* Configure socket options */
    Socket_setreuseaddr (server);
    Socket_setnonblocking (server);

    /* Bind to port */
    printf ("Binding to port %d...\n", port);
    Socket_bind (server, NULL, port);

    /* Listen for connections */
    printf ("Listening for connections...\n");
    Socket_listen (server, 128);

    printf ("Server ready! Waiting for connections...\n\n");

    /* Main server loop */
    while (running)
      {
        /* Accept new connection */
        client = Socket_accept (server);

        if (client)
          {
            /* Handle the client connection */
            char buffer[1024];
            ssize_t n;

            printf ("[%s:%d] Client connected\n",
                    Socket_getpeeraddr (client),
                    Socket_getpeerport (client));

            /* Echo loop */
            while ((n = Socket_recv (client, buffer, sizeof (buffer) - 1)) > 0)
              {
                buffer[n] = '\0'; /* Null terminate for printing */

                printf ("[%s:%d] Received %zd bytes: %.50s%s\n",
                        Socket_getpeeraddr (client),
                        Socket_getpeerport (client),
                        n, buffer,
                        n > 50 ? "..." : "");

                /* Echo back */
                Socket_sendall (client, buffer, n);
              }

            if (n == 0)
              {
                printf ("[%s:%d] Client disconnected\n",
                        Socket_getpeeraddr (client),
                        Socket_getpeerport (client));
              }
            else
              {
                printf ("[%s:%d] Error\n",
                        Socket_getpeeraddr (client),
                        Socket_getpeerport (client));
              }

            Socket_free (&client);
          }
        else if (running)
          {
            /* No connection available, sleep briefly */
            usleep (10000); /* 10ms */
          }
      }

    printf ("\nShutting down...\n");
  }
  EXCEPT (Socket_Failed)
  {
    fprintf (stderr, "Socket error\n");
    result = 1;
  }
  END_TRY;

  /* Cleanup */
  if (client)
    Socket_free (&client);
  if (server)
    Socket_free (&server);

  printf ("Server stopped.\n");
  return result;
}