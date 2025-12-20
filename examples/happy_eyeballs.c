/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * happy_eyeballs.c - Happy Eyeballs (RFC 8305) Example
 *
 * Demonstrates fast dual-stack (IPv6/IPv4) connection establishment.
 * Happy Eyeballs races connections to both address families and uses
 * whichever connects first.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_happy_eyeballs
 *
 * Usage:
 *   ./example_happy_eyeballs [host] [port]
 *   ./example_happy_eyeballs google.com 80
 *   ./example_happy_eyeballs ipv6.google.com 443
 *
 * The algorithm:
 *   1. Query DNS for both A (IPv4) and AAAA (IPv6) records
 *   2. Start connection to first address (prefer IPv6)
 *   3. After 250ms delay, start IPv4 connection (if IPv6 not done)
 *   4. First successful connection wins; close others
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"
#include "socket/Socket.h"
#include "socket/SocketHappyEyeballs.h"

/* Helper to describe address family */
static const char *
af_name (int family)
{
  switch (family)
    {
    case AF_INET:
      return "IPv4";
    case AF_INET6:
      return "IPv6";
    default:
      return "Unknown";
    }
}

int
main (int argc, char **argv)
{
  /* Variables that might be clobbered by longjmp must be volatile */
  const char *volatile host = "google.com";
  volatile int port = 80;
  Socket_T sock = NULL;
  SocketDNS_T dns = NULL;
  SocketPoll_T poll = NULL;
  SocketHE_T he = NULL;
  volatile int result = 0;

  /* Parse command line arguments */
  if (argc > 1)
    host = argv[1];
  if (argc > 2)
    port = atoi (argv[2]);

  if (port <= 0 || port > 65535)
    {
      fprintf (stderr, "Invalid port: %d\n", port);
      return 1;
    }

  /* Setup signal handling */
  signal (SIGPIPE, SIG_IGN);

  printf ("Happy Eyeballs (RFC 8305) Example\n");
  printf ("==================================\n\n");
  printf ("Target: %s:%d\n\n", host, port);

  TRY
  {
    /* Create DNS resolver and poll instance */
    printf ("1. Initializing DNS resolver and event loop...\n");
    dns = SocketDNS_new ();
    poll = SocketPoll_new (64);
    printf ("   [OK] DNS resolver and poll initialized\n");

    /* Method 1: Synchronous Happy Eyeballs (simplest) */
    printf ("\n2. Attempting synchronous Happy Eyeballs connection...\n");
    printf ("   (Timeout: 10 seconds)\n");

    /* Create configuration with default settings */
    SocketHE_Config config;
    SocketHappyEyeballs_config_defaults (&config);
    config.total_timeout_ms = 10000; /* 10 second total timeout */
    config.attempt_delay_ms = 250;   /* RFC 8305 recommended delay */

    /* Perform synchronous connection - races IPv6 and IPv4 */
    sock = SocketHappyEyeballs_connect (dns, host, port, &config);

    if (sock)
      {
        printf ("   [OK] Connection established!\n\n");

        /* Report which address family won */
        printf ("3. Connection Details:\n");
        const char *local_addr = Socket_getlocaladdr (sock);
        int local_port = Socket_getlocalport (sock);
        const char *peer_addr = Socket_getpeeraddr (sock);
        int peer_port = Socket_getpeerport (sock);

        /* Determine address family from address format */
        int family = (strchr (peer_addr, ':') != NULL) ? AF_INET6 : AF_INET;
        printf ("   Winner: %s\n", af_name (family));
        printf ("   Local:  %s:%d\n", local_addr, local_port);
        printf ("   Remote: %s:%d\n", peer_addr, peer_port);

        /* Send a simple HTTP request as a test */
        printf ("\n4. Testing connection with HTTP request...\n");
        char request[256];
        snprintf (request, sizeof (request),
                  "GET / HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "Connection: close\r\n\r\n",
                  host);

        Socket_sendall (sock, request, strlen (request));
        printf ("   [OK] Sent %zu bytes\n", strlen (request));

        /* Read response header */
        char buffer[1024];
        ssize_t received = Socket_recv (sock, buffer, sizeof (buffer) - 1);

        if (received > 0)
          {
            buffer[received] = '\0';
            /* Show first line of response */
            char *newline = strchr (buffer, '\n');
            if (newline)
              *newline = '\0';
            printf ("   [OK] Response: %s\n", buffer);
          }

        Socket_free (&sock);
        printf ("\n   Synchronous connection test complete.\n");
      }
    else
      {
        printf ("   [FAIL] Synchronous connection failed\n");
      }

    /* Method 2: Asynchronous Happy Eyeballs (for event loops) */
    printf ("\n5. Demonstrating asynchronous Happy Eyeballs...\n");

    /* Start async connection */
    he = SocketHappyEyeballs_start (dns, poll, host, port, &config);

    printf ("   Connection attempt started, entering event loop...\n");

    /* Process until complete */
    int iterations = 0;
    while (!SocketHappyEyeballs_poll (he))
      {
        int timeout = SocketHappyEyeballs_next_timeout_ms (he);
        if (timeout < 0)
          timeout = 100;

        SocketEvent_T *events;
        int nevents = SocketPoll_wait (poll, &events, timeout);

        /* Process Happy Eyeballs state machine */
        SocketHappyEyeballs_process (he);

        iterations++;
        if (iterations > 200) /* Safety limit */
          {
            printf ("   [WARN] Too many iterations, breaking\n");
            break;
          }
      }

    /* Check result */
    SocketHE_State state = SocketHappyEyeballs_state (he);
    if (state == HE_STATE_CONNECTED)
      {
        Socket_T async_sock = SocketHappyEyeballs_result (he);
        const char *async_peer = Socket_getpeeraddr (async_sock);
        int async_port = Socket_getpeerport (async_sock);

        int async_family
            = (strchr (async_peer, ':') != NULL) ? AF_INET6 : AF_INET;

        printf ("   [OK] Async connection successful in %d iterations!\n",
                iterations);
        printf ("   Winner: %s (%s:%d)\n", af_name (async_family), async_peer,
                async_port);

        Socket_free (&async_sock);
      }
    else if (state == HE_STATE_FAILED)
      {
        const char *error = SocketHappyEyeballs_error (he);
        printf ("   [FAIL] Async connection failed: %s\n",
                error ? error : "unknown");
      }
    else
      {
        printf ("   [WARN] Async connection in unexpected state: %d\n", state);
      }

    SocketHappyEyeballs_free (&he);
  }
  EXCEPT (SocketHE_Failed)
  {
    fprintf (stderr, "\n[ERROR] Happy Eyeballs error: %s\n",
             Socket_GetLastError ());
    result = 1;
  }
  EXCEPT (SocketDNS_Failed)
  {
    fprintf (stderr, "\n[ERROR] DNS error: %s\n", Socket_GetLastError ());
    result = 1;
  }
  EXCEPT (Socket_Failed)
  {
    fprintf (stderr, "\n[ERROR] Socket error: %s\n", Socket_GetLastError ());
    result = 1;
  }
  ELSE
  {
    fprintf (stderr, "\n[ERROR] Unknown error\n");
    result = 1;
  }
  END_TRY;

  /* Cleanup */
  printf ("\nCleaning up...\n");
  if (he)
    SocketHappyEyeballs_free (&he);
  if (sock)
    Socket_free (&sock);
  if (poll)
    SocketPoll_free (&poll);
  if (dns)
    SocketDNS_free (&dns);

  printf ("\n%s\n", result == 0 ? "[OK] Example completed successfully!"
                                : "[FAIL] Example completed with errors");

  return result;
}
