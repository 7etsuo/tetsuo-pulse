/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * connection_pool.c - Connection Pool Example
 *
 * Demonstrates connection pooling using the SocketPool API.
 * Shows pool creation, connection management, and statistics.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_connection_pool
 *
 * Usage:
 *   ./example_connection_pool [max_connections] [buffer_size]
 *   ./example_connection_pool 10 4096
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "poll/SocketPoll.h"
#include "pool/SocketPool.h"
#include "socket/Socket.h"

/* Global flag for graceful shutdown */
static volatile int running = 1;

static void
signal_handler (int signo)
{
  (void)signo;
  running = 0;
}

/* Simulate some work on a connection */
static void
simulate_work_wrapper (Connection_T conn, void *arg)
{
  int duration_ms = (int)(intptr_t)arg;

  printf ("[%s:%d] Working for %dms...\n",
          Socket_getpeeraddr (Connection_socket (conn)),
          Socket_getpeerport (Connection_socket (conn)), duration_ms);

  usleep (duration_ms * 1000);

  printf ("[%s:%d] Work complete\n",
          Socket_getpeeraddr (Connection_socket (conn)),
          Socket_getpeerport (Connection_socket (conn)));
}

/* Predicate function for finding idle connections */
static int
is_idle_connection (Connection_T conn, void *userdata)
{
  (void)userdata;
  return !Connection_isactive (conn);
}

int
main (int argc, char **argv)
{
  /* Variables that might be clobbered by longjmp must be volatile */
  volatile int max_connections = 10;
  volatile size_t buffer_size = 4096;
  Arena_T arena = NULL;
  SocketPool_T pool = NULL;
  SocketPoll_T poll = NULL;
  volatile int result = 0;

  /* Parse command line arguments */
  if (argc > 1)
    max_connections = atoi (argv[1]);
  if (argc > 2)
    buffer_size = (size_t)atoi (argv[2]);

  if (max_connections <= 0 || buffer_size == 0)
    {
      fprintf (stderr, "Invalid parameters\n");
      return 1;
    }

  /* Setup signal handlers */
  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);
  signal (SIGPIPE, SIG_IGN);

  printf ("Connection Pool Example\n");
  printf ("=======================\n\n");
  printf ("Pool size: %d connections\n", max_connections);
  printf ("Buffer size: %zu bytes\n\n", buffer_size);

  TRY
  {
    /* Create resources */
    arena = Arena_new ();
    pool = SocketPool_new (arena, max_connections, buffer_size);
    poll = SocketPoll_new (max_connections + 10);

    printf ("Connection pool created\n");
    printf ("Initial state: %zu connections\n\n", SocketPool_count (pool));

    /* Simulate connection pool usage */
    volatile int cycle = 0;

    while (running && cycle < 5)
      {
        printf ("=== Cycle %d ===\n", cycle + 1);

        /* Add some connections to the pool */
        printf ("Adding connections to pool...\n");

        for (volatile int i = 0;
             i < 3 && SocketPool_count (pool) < (size_t)max_connections; i++)
          {
            /* Create a dummy connection (we'll simulate with localhost) */
            Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);

            TRY
            {
              /* Try to connect to localhost:22 (SSH) or fallback to dummy */
              Socket_connect (sock, "127.0.0.1", 22);
            }
            EXCEPT (Socket_Failed)
            {
              /* Connection failed, create a bound socket instead */
              Socket_bind (sock, "127.0.0.1", 0);
            }
            END_TRY;

            Connection_T conn = SocketPool_add (pool, sock);
            if (conn)
              {
                printf ("Added connection %zu\n", SocketPool_count (pool));
              }
          }

        /* Display pool statistics */
        printf ("\nPool Statistics:\n");
        printf ("  Total connections: %zu\n", SocketPool_count (pool));
        printf ("  Active connections: %zu\n",
                SocketPool_get_active_count (pool));
        printf ("  Idle connections: %zu\n", SocketPool_get_idle_count (pool));
        printf ("  Hit rate: %.1f%%\n",
                SocketPool_get_hit_rate (pool) * 100.0);

        /* Simulate work on some connections */
        if (SocketPool_count (pool) > 0)
          {
            printf ("\nSimulating work on connections...\n");

            SocketPool_foreach (pool, simulate_work_wrapper,
                                (void *)500); /* 500ms work */

            /* Find a specific connection (first idle one) */
            Connection_T found
                = SocketPool_find (pool, is_idle_connection, NULL);

            if (found)
              {
                printf ("\nFound idle connection, doing extra work...\n");
                simulate_work_wrapper (found, (void *)200);
              }
          }

        /* Clean up idle connections occasionally */
        if (cycle % 2 == 1)
          {
            printf ("\nCleaning up idle connections...\n");
            SocketPool_cleanup (pool, 1); /* 1 second idle timeout */
            printf ("After cleanup: %zu connections\n",
                    SocketPool_count (pool));
          }

        printf ("\nCycle %d complete\n\n", cycle + 1);
        cycle++;

        /* Wait a bit between cycles */
        sleep (1);
      }

    /* Graceful shutdown */
    printf ("=== Graceful Shutdown ===\n");
    printf ("Active connections: %zu\n", SocketPool_count (pool));

    if (SocketPool_count (pool) > 0)
      {
        printf ("Draining connections...\n");
        SocketPool_drain (pool, 2000); /* 2 second timeout */

        while (SocketPool_drain_poll (pool) > 0)
          {
            printf ("Waiting for connections to drain...\n");
            usleep (100000); /* 100ms */
          }

        printf ("All connections drained\n");
      }
  }
  EXCEPT (Socket_Failed)
  {
    fprintf (stderr, "Socket error\n");
    result = 1;
  }
  EXCEPT (SocketPool_Failed)
  {
    fprintf (stderr, "Pool error\n");
    result = 1;
  }
  END_TRY;

  /* Cleanup */
  if (poll)
    SocketPoll_free (&poll);
  if (pool)
    SocketPool_free (&pool);
  if (arena)
    Arena_dispose (&arena);

  printf ("\nConnection pool example complete.\n");
  return result;
}
