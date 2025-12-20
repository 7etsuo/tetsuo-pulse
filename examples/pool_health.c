/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * pool_health.c - Connection Pool Health Check Example
 *
 * Demonstrates the SocketPoolHealth API for connection pool health checks
 * and circuit breaker patterns. Shows production-grade resilience patterns:
 * - Per-host circuit breaker with automatic failure tracking
 * - Background health probes for idle connections
 * - Custom health check callbacks
 * - Circuit breaker state transitions (CLOSED -> OPEN -> HALF_OPEN -> CLOSED)
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_pool_health
 *
 * Usage:
 *   ./example_pool_health
 *
 * The example demonstrates:
 * 1. Creating a pool with health check configuration
 * 2. Enabling health checks with custom settings
 * 3. Circuit breaker state machine behavior
 * 4. Success/failure reporting and state transitions
 * 5. Custom health probe callbacks
 * 6. Health statistics monitoring
 */

#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "pool/SocketPool.h"
#include "pool/SocketPoolHealth.h"
#include "socket/Socket.h"

/* Global flag for graceful shutdown */
static volatile int running = 1;

static void
signal_handler (int signo)
{
  (void)signo;
  running = 0;
}

/* Custom health probe callback for demonstration */
static int
custom_health_probe (SocketPool_T pool, Connection_T conn, int timeout_ms,
                     void *data)
{
  (void)pool;
  (void)data;

  Socket_T sock = Connection_socket (conn);
  int fd = Socket_fd (sock);

  /* Simple poll-based check: verify socket is readable/writable */
  struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLOUT, .revents = 0 };

  int ret = poll (&pfd, 1, timeout_ms);

  if (ret < 0)
    {
      printf ("[PROBE] Socket error during health check\n");
      return 0; /* Unhealthy */
    }

  if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
    {
      printf ("[PROBE] Socket closed or has error\n");
      return 0; /* Unhealthy */
    }

  /* Socket appears healthy */
  return 1;
}

/* Helper to print circuit state */
static const char *
circuit_state_string (SocketPoolCircuit_State state)
{
  switch (state)
    {
    case POOL_CIRCUIT_CLOSED:
      return "CLOSED";
    case POOL_CIRCUIT_OPEN:
      return "OPEN";
    case POOL_CIRCUIT_HALF_OPEN:
      return "HALF_OPEN";
    default:
      return "UNKNOWN";
    }
}

/* Demonstrate basic circuit breaker behavior */
static void
demo_circuit_breaker (SocketPool_T pool)
{
  const char *host = "example.com";
  int port = 443;

  printf ("\n=== Circuit Breaker Demo ===\n\n");

  /* Check initial state */
  SocketPoolCircuit_State state = SocketPool_circuit_state (pool, host, port);
  printf ("[INFO] Initial circuit state for %s:%d: %s\n", host, port,
          circuit_state_string (state));

  /* Report some failures to trigger circuit opening */
  printf ("\n[INFO] Simulating connection failures...\n");

  for (int i = 0; i < 5; i++)
    {
      if (SocketPool_circuit_allows (pool, host, port))
        {
          printf ("  Attempt %d: Connection allowed\n", i + 1);
          SocketPool_circuit_report_failure (pool, host, port);
          printf ("  [FAIL] Reported failure\n");
        }
      else
        {
          printf ("  [BLOCKED] Circuit is open, connection blocked\n");
        }

      state = SocketPool_circuit_state (pool, host, port);
      printf ("  Circuit state: %s\n\n", circuit_state_string (state));

      usleep (100000); /* 100ms delay */
    }

  /* Verify circuit is now OPEN */
  state = SocketPool_circuit_state (pool, host, port);
  if (state == POOL_CIRCUIT_OPEN)
    {
      printf ("[OK] Circuit successfully transitioned to OPEN state\n");
    }
  else
    {
      printf ("[FAIL] Expected OPEN state, got %s\n",
              circuit_state_string (state));
    }

  /* Wait for reset timeout (we set it to 2 seconds for demo) */
  printf ("\n[INFO] Waiting for reset timeout (2 seconds)...\n");
  sleep (2);

  /* Circuit should now be in HALF_OPEN state */
  state = SocketPool_circuit_state (pool, host, port);
  printf ("[INFO] Circuit state after timeout: %s\n",
          circuit_state_string (state));

  if (state == POOL_CIRCUIT_HALF_OPEN)
    {
      printf ("[OK] Circuit transitioned to HALF_OPEN for recovery testing\n");
    }

  /* Test probe behavior in HALF_OPEN state */
  printf ("\n[INFO] Testing HALF_OPEN probe behavior...\n");

  /* First probe should be allowed */
  if (SocketPool_circuit_allows (pool, host, port))
    {
      printf ("  Probe 1: [OK] Allowed\n");
      SocketPool_circuit_report_success (pool, host, port);
      printf ("  [OK] Reported success\n");
    }

  /* Check if circuit closed after successful probe */
  state = SocketPool_circuit_state (pool, host, port);
  printf ("  Circuit state: %s\n", circuit_state_string (state));

  if (state == POOL_CIRCUIT_CLOSED)
    {
      printf ("[OK] Circuit successfully recovered to CLOSED state\n");
    }
  else
    {
      printf ("[FAIL] Expected CLOSED state, got %s\n",
              circuit_state_string (state));
    }
}

/* Demonstrate manual circuit reset */
static void
demo_manual_reset (SocketPool_T pool)
{
  const char *host = "api.example.com";
  int port = 8080;

  printf ("\n\n=== Manual Circuit Reset Demo ===\n\n");

  /* Trigger circuit to open */
  printf ("[INFO] Opening circuit with failures...\n");
  for (int i = 0; i < 5; i++)
    {
      SocketPool_circuit_report_failure (pool, host, port);
    }

  SocketPoolCircuit_State state = SocketPool_circuit_state (pool, host, port);
  printf ("[INFO] Circuit state: %s\n", circuit_state_string (state));

  if (state == POOL_CIRCUIT_OPEN)
    {
      printf ("[OK] Circuit is OPEN\n");
    }

  /* Manually reset the circuit */
  printf ("\n[INFO] Manually resetting circuit...\n");
  int ret = SocketPool_circuit_reset (pool, host, port);

  if (ret == 0)
    {
      printf ("[OK] Circuit reset successful\n");
    }
  else
    {
      printf ("[FAIL] Circuit reset failed\n");
    }

  /* Verify circuit is CLOSED */
  state = SocketPool_circuit_state (pool, host, port);
  printf ("[INFO] Circuit state after reset: %s\n",
          circuit_state_string (state));

  if (state == POOL_CIRCUIT_CLOSED)
    {
      printf ("[OK] Circuit successfully reset to CLOSED\n");
    }
  else
    {
      printf ("[FAIL] Expected CLOSED state, got %s\n",
              circuit_state_string (state));
    }
}

/* Demonstrate health statistics */
static void
demo_health_stats (SocketPool_T pool)
{
  printf ("\n\n=== Health Statistics Demo ===\n\n");

  uint64_t probes_sent = 0;
  uint64_t probes_passed = 0;
  uint64_t probes_failed = 0;
  uint64_t circuits_opened = 0;

  SocketPool_health_stats (pool, &probes_sent, &probes_passed, &probes_failed,
                           &circuits_opened);

  printf ("Health Subsystem Statistics:\n");
  printf ("  Probes sent:       %lu\n", (unsigned long)probes_sent);
  printf ("  Probes passed:     %lu\n", (unsigned long)probes_passed);
  printf ("  Probes failed:     %lu\n", (unsigned long)probes_failed);
  printf ("  Circuits opened:   %lu\n", (unsigned long)circuits_opened);

  if (probes_sent > 0)
    {
      double success_rate = (double)probes_passed / probes_sent * 100.0;
      printf ("  Success rate:      %.1f%%\n", success_rate);
      printf ("[OK] Health statistics retrieved\n");
    }
  else
    {
      printf ("[INFO] No background probes executed yet\n");
    }
}

/* Demonstrate connection checking */
static void
demo_connection_checking (SocketPool_T pool)
{
  printf ("\n\n=== Connection Allows Check Demo ===\n\n");

  const char *hosts[] = { "service1.example.com", "service2.example.com",
                          "service3.example.com" };
  int ports[] = { 443, 8080, 9090 };

  printf (
      "[INFO] Checking if connections are allowed to various hosts...\n\n");

  for (size_t i = 0; i < sizeof (hosts) / sizeof (hosts[0]); i++)
    {
      int allowed = SocketPool_circuit_allows (pool, hosts[i], ports[i]);
      SocketPoolCircuit_State state
          = SocketPool_circuit_state (pool, hosts[i], ports[i]);

      printf ("Host: %s:%d\n", hosts[i], ports[i]);
      printf ("  Circuit state: %s\n", circuit_state_string (state));
      printf ("  Connection allowed: %s\n", allowed ? "YES" : "NO");

      if (allowed)
        {
          printf ("  [OK] Can proceed with connection\n");
        }
      else
        {
          printf ("  [BLOCKED] Connection blocked by circuit breaker\n");
        }

      printf ("\n");
    }
}

int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  Arena_T arena = NULL;
  SocketPool_T pool = NULL;
  volatile int result = 0;

  /* Setup signal handlers */
  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);
  signal (SIGPIPE, SIG_IGN);

  printf ("Connection Pool Health Check Example\n");
  printf ("====================================\n\n");

  TRY
  {
    /* Create arena and pool */
    arena = Arena_new ();
    pool = SocketPool_new (arena, 100, 4096);

    printf ("[OK] Connection pool created\n");
    printf ("  Max connections: 100\n");
    printf ("  Buffer size: 4096 bytes\n\n");

    /* Configure health checking */
    printf ("=== Health Check Configuration ===\n\n");

    SocketPoolHealth_Config config;
    SocketPoolHealth_config_defaults (&config);

    /* Customize for faster demo (normally use production defaults) */
    config.failure_threshold = 5;    /* Open after 5 failures */
    config.reset_timeout_ms = 2000;  /* 2 seconds (normally 30s) */
    config.half_open_max_probes = 3; /* Max 3 probe attempts */
    config.probe_interval_ms = 5000; /* Probe every 5 seconds */
    config.probe_timeout_ms = 1000;  /* 1 second probe timeout */
    config.probes_per_cycle = 10;    /* Probe up to 10 connections */
    config.max_circuits = 1000;      /* Track up to 1000 host:port pairs */

    printf ("Configuration:\n");
    printf ("  Failure threshold:     %d\n", config.failure_threshold);
    printf ("  Reset timeout:         %d ms\n", config.reset_timeout_ms);
    printf ("  Half-open max probes:  %d\n", config.half_open_max_probes);
    printf ("  Probe interval:        %d ms\n", config.probe_interval_ms);
    printf ("  Probe timeout:         %d ms\n", config.probe_timeout_ms);
    printf ("  Probes per cycle:      %d\n", config.probes_per_cycle);
    printf ("  Max circuits:          %d\n", config.max_circuits);

    /* Enable health checks */
    printf ("\n[INFO] Enabling health checks...\n");
    int ret = SocketPool_enable_health_checks (pool, &config);

    if (ret == 0)
      {
        printf ("[OK] Health checks enabled successfully\n");
      }
    else
      {
        printf ("[FAIL] Failed to enable health checks\n");
        result = 1;
        goto cleanup;
      }

    /* Set custom health probe callback */
    printf ("\n[INFO] Setting custom health probe callback...\n");
    SocketPool_set_health_callback (pool, custom_health_probe, NULL);
    printf ("[OK] Custom callback registered\n");

    /* Run demonstrations */
    demo_circuit_breaker (pool);
    demo_manual_reset (pool);
    demo_connection_checking (pool);

    /* Let background probes run for a bit */
    printf ("\n\n=== Background Health Probes ===\n\n");
    printf ("[INFO] Letting background health probes run for 3 "
            "seconds...\n");
    printf ("[INFO] Press Ctrl+C to stop early\n\n");

    int elapsed = 0;
    while (running && elapsed < 3)
      {
        sleep (1);
        elapsed++;
        printf ("  Elapsed: %d seconds\n", elapsed);
      }

    if (running)
      {
        printf ("\n[OK] Background probe period complete\n");
      }
    else
      {
        printf ("\n[INFO] Interrupted by signal\n");
      }

    /* Show final statistics */
    demo_health_stats (pool);

    /* Disable health checks */
    printf ("\n\n=== Cleanup ===\n\n");
    printf ("[INFO] Disabling health checks...\n");
    SocketPool_disable_health_checks (pool);
    printf ("[OK] Health checks disabled\n");
  }
  EXCEPT (SocketPool_Failed)
  {
    fprintf (stderr, "[FAIL] SocketPool error occurred\n");
    result = 1;
  }
  EXCEPT (Arena_Failed)
  {
    fprintf (stderr, "[FAIL] Arena allocation failed\n");
    result = 1;
  }
  END_TRY;

cleanup:
  /* Cleanup */
  if (pool)
    {
      SocketPool_free (&pool);
      printf ("[OK] Connection pool freed\n");
    }

  if (arena)
    {
      Arena_dispose (&arena);
      printf ("[OK] Arena disposed\n");
    }

  printf ("\n====================================\n");
  printf ("Pool health check example complete.\n");
  return result;
}
