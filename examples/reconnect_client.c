/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * reconnect_client.c - Automatic Reconnection Example
 *
 * Demonstrates resilient TCP connections with automatic reconnection,
 * exponential backoff, jitter, and circuit breaker patterns.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_reconnect_client
 *
 * Usage:
 *   ./example_reconnect_client [host] [port]
 *   ./example_reconnect_client localhost 8080
 *
 * Test:
 *   1. Start a simple echo server: nc -l 8080
 *   2. Run this client
 *   3. Kill and restart the server to see reconnection in action
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Except.h"
#include "socket/Socket.h"
#include "socket/SocketReconnect.h"

/* Global flag for clean shutdown */
static volatile sig_atomic_t g_running = 1;

static void
signal_handler (int signo)
{
  (void)signo;
  g_running = 0;
}

/* State change callback - called when connection state changes */
static void
on_state_change (SocketReconnect_T conn, SocketReconnect_State old_state,
                 SocketReconnect_State new_state, void *user_data)
{
  (void)conn;
  (void)user_data;

  const char *state_names[] = { "DISCONNECTED", "CONNECTING", "CONNECTED",
                                "BACKOFF", "CIRCUIT_OPEN" };

  printf ("   [STATE] %s -> %s\n", state_names[old_state],
          state_names[new_state]);
}

/* Health check callback - called periodically when connected */
static int
health_check (SocketReconnect_T conn, void *user_data)
{
  (void)user_data;

  /* Simple health check: verify socket is still valid */
  if (!SocketReconnect_is_connected (conn))
    {
      printf ("   [HEALTH] Connection lost\n");
      return 0; /* Unhealthy */
    }

  printf ("   [HEALTH] Connection OK\n");
  return 1; /* Healthy */
}

int
main (int argc, char **argv)
{
  /* Variables that might be clobbered by longjmp must be volatile */
  const char *volatile host = "localhost";
  volatile int port = 8080;
  SocketReconnect_T conn = NULL;
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
  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);
  signal (SIGPIPE, SIG_IGN);

  printf ("Reconnecting Client Example\n");
  printf ("===========================\n\n");
  printf ("Target: %s:%d\n", host, port);
  printf ("Press Ctrl+C to exit\n\n");

  TRY
  {
    /* Create reconnection policy with custom settings */
    printf ("1. Configuring reconnection policy...\n");

    SocketReconnect_Policy_T policy;
    SocketReconnect_policy_defaults (&policy);

    /* Customize backoff settings */
    policy.initial_delay_ms = 500; /* Start with 500ms delay */
    policy.max_delay_ms = 30000;   /* Cap at 30 seconds */
    policy.multiplier = 2.0;       /* Double delay each attempt */
    policy.jitter = 0.25;          /* +/- 25% randomization */
    policy.max_attempts = 0;       /* 0 = unlimited attempts */

    /* Circuit breaker settings */
    policy.circuit_failure_threshold = 5;    /* Open after 5 failures */
    policy.circuit_reset_timeout_ms = 60000; /* Try again after 60s */

    printf ("   Initial delay:     %d ms\n", policy.initial_delay_ms);
    printf ("   Max delay:         %d ms\n", policy.max_delay_ms);
    printf ("   Backoff multiplier: %.1f\n", policy.multiplier);
    printf ("   Jitter:            %.0f%%\n", policy.jitter * 100);
    printf ("   Circuit threshold: %d failures\n",
            policy.circuit_failure_threshold);
    printf ("   Circuit reset:     %d ms\n", policy.circuit_reset_timeout_ms);

    /* Create reconnecting connection */
    printf ("\n2. Creating reconnecting connection...\n");
    conn = SocketReconnect_new (host, port, &policy, on_state_change, NULL);
    printf ("   [OK] Reconnect context created\n");

    /* Set up health check (every 10 seconds) */
    SocketReconnect_set_health_check (conn, health_check, NULL, 10000);
    printf ("   [OK] Health check configured (10s interval)\n");

    /* Initial connection attempt */
    printf ("\n3. Initiating connection...\n");
    SocketReconnect_connect (conn);

    /* Main loop - send/receive with automatic reconnection */
    printf ("\n4. Entering main loop (send message every 3s)...\n");
    int message_count = 0;

    while (g_running)
      {
        /* Check if connected */
        if (SocketReconnect_is_connected (conn))
          {
            /* Send a test message */
            char message[128];
            snprintf (message, sizeof (message), "Message #%d from client\n",
                      ++message_count);

            /* SocketReconnect_send handles reconnection on errors */
            ssize_t sent
                = SocketReconnect_send (conn, message, strlen (message));

            if (sent > 0)
              {
                printf ("   [SEND] %s", message);

                /* Try to receive echo (non-blocking with short timeout) */
                char buffer[256];
                ssize_t received
                    = SocketReconnect_recv (conn, buffer, sizeof (buffer) - 1);
                if (received > 0)
                  {
                    buffer[received] = '\0';
                    printf ("   [RECV] %s", buffer);
                  }
              }
            else
              {
                printf ("   [WARN] Send failed (will reconnect)\n");
              }
          }
        else
          {
            SocketReconnect_State state = SocketReconnect_state (conn);
            printf ("   [INFO] Not connected (state: %d), waiting...\n",
                    state);
          }

        /* Process reconnection timers and events */
        SocketReconnect_tick (conn);

        /* Get stats */
        if (message_count > 0 && message_count % 5 == 0)
          {
            SocketReconnect_Stats stats;
            SocketReconnect_stats (conn, &stats);
            printf (
                "   [STATS] Attempts: %zu, Failures: %zu, Reconnects: %zu\n",
                stats.attempts, stats.failures, stats.reconnects);
          }

        /* Sleep between messages */
        sleep (3);
      }

    printf ("\n5. Shutting down...\n");
  }
  EXCEPT (SocketReconnect_Failed)
  {
    fprintf (stderr, "\n[ERROR] Reconnect error: %s\n",
             Socket_GetLastError ());
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
  if (conn)
    SocketReconnect_free (&conn);

  printf ("\n%s\n", result == 0 ? "[OK] Example completed successfully!"
                                : "[FAIL] Example completed with errors");

  return result;
}
