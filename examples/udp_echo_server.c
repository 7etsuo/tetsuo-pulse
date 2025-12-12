/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * udp_echo_server.c - Basic UDP Echo Server Example
 *
 * Demonstrates a simple UDP echo server using the SocketDgram API.
 * Shows UDP socket operations: bind, recvfrom, sendto.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_udp_echo_server
 *
 * Usage:
 *   ./example_udp_echo_server [port]
 *   ./example_udp_echo_server 8080
 *
 * Test with:
 *   echo "Hello, World!" | nc -u localhost 8080
 *   python3 -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'Hello',('localhost',8080)); print(s.recv(1024))"
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "socket/SocketDgram.h"

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
  SocketDgram_T sock = NULL;
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

  printf ("UDP Echo Server Example\n");
  printf ("=======================\n\n");
  printf ("Listening on port %d\n", port);
  printf ("Test with: echo 'Hello' | nc -u localhost %d\n\n", port);
  printf ("Press Ctrl+C to stop\n\n");

  TRY
  {
    /* Create UDP socket */
    sock = SocketDgram_new (AF_INET, 0);

    /* Bind to port */
    printf ("Binding to port %d...\n", port);
    SocketDgram_bind (sock, NULL, port);

    printf ("Server ready! Waiting for UDP packets...\n\n");

    /* Main server loop */
    while (running)
      {
        char buffer[1024];
        char client_host[256];
        int client_port;

        /* Receive UDP packet */
        ssize_t n = SocketDgram_recvfrom (sock, buffer, sizeof (buffer) - 1,
                                          client_host, sizeof (client_host),
                                          &client_port);

        if (n > 0)
          {
            buffer[n] = '\0'; /* Null terminate for printing */

            printf ("[%s:%d] Received %zd bytes: %.50s%s\n",
                    client_host, client_port, n, buffer,
                    n > 50 ? "..." : "");

            /* Echo back to client */
            SocketDgram_sendto (sock, buffer, n, client_host, client_port);

            printf ("Echoed back to %s:%d\n", client_host, client_port);
          }
        else if (n < 0)
          {
            printf ("Receive error\n");
            usleep (100000); /* Sleep 100ms on error */
          }
      }

    printf ("\nShutting down...\n");
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

  printf ("Server stopped.\n");
  return result;
}