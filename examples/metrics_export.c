/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * metrics_export.c - Metrics Collection and Export Example
 *
 * Demonstrates production-grade metrics collection with export to
 * Prometheus, StatsD, and JSON formats.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_metrics_export
 *
 * Usage:
 *   ./example_metrics_export [format]
 *   ./example_metrics_export prometheus
 *   ./example_metrics_export statsd
 *   ./example_metrics_export json
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Except.h"
#include "core/SocketMetrics.h"

/* Simulate some work and record metrics */
static void
simulate_http_requests (int count)
{
  printf ("   Simulating %d HTTP requests...\n", count);

  for (int i = 0; i < count; i++)
    {
      /* Increment request counter */
      SocketMetrics_counter_inc (SOCKET_CTR_HTTP_CLIENT_REQUESTS_TOTAL);

      /* Simulate request latency (10-500ms) */
      double latency_ms = 10.0 + (rand () % 490);
      SocketMetrics_histogram_observe (
          SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS, latency_ms);

      /* Simulate occasional errors (10% rate) */
      if (rand () % 10 == 0)
        {
          SocketMetrics_counter_inc (SOCKET_CTR_HTTP_CLIENT_ERRORS);
        }
      else
        {
          SocketMetrics_counter_inc (SOCKET_CTR_HTTP_CLIENT_RESPONSES_TOTAL);
        }

      /* Simulate varying response sizes */
      double response_size = 100.0 + (rand () % 50000);
      SocketMetrics_histogram_observe (
          SOCKET_HIST_HTTP_CLIENT_RESPONSE_SIZE_BYTES, response_size);
    }
}

static void
simulate_connection_pool (void)
{
  printf ("   Simulating connection pool activity...\n");

  /* Set gauge for active connections */
  SocketMetrics_gauge_set (SOCKET_GAU_POOL_ACTIVE_CONNECTIONS, 42);
  SocketMetrics_gauge_set (SOCKET_GAU_POOL_IDLE_CONNECTIONS, 8);

  /* Increment counters */
  for (int i = 0; i < 100; i++)
    {
      SocketMetrics_counter_inc (SOCKET_CTR_POOL_CONNECTIONS_CREATED);
      SocketMetrics_counter_inc (SOCKET_CTR_POOL_CONNECTIONS_REUSED);
      SocketMetrics_counter_inc (SOCKET_CTR_POOL_CONNECTIONS_REUSED);

      /* Simulate acquire time */
      double acquire_ms = 0.1 + (rand () % 50) / 10.0;
      SocketMetrics_histogram_observe (SOCKET_HIST_POOL_ACQUIRE_TIME_MS,
                                       acquire_ms);
    }
}

static void
simulate_dns_queries (void)
{
  printf ("   Simulating DNS queries...\n");

  for (int i = 0; i < 50; i++)
    {
      SocketMetrics_counter_inc (SOCKET_CTR_DNS_QUERIES_TOTAL);

      /* Simulate cache hits (60%) and misses */
      if (rand () % 10 < 6)
        {
          SocketMetrics_counter_inc (SOCKET_CTR_DNS_CACHE_HITS);
          SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 0.1);
        }
      else
        {
          SocketMetrics_counter_inc (SOCKET_CTR_DNS_CACHE_MISSES);
          double query_ms = 10.0 + (rand () % 200);
          SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                           query_ms);
        }
    }
}

static void
print_prometheus_format (void)
{
  printf ("\n=== Prometheus Export Format ===\n\n");

  char buffer[65536];
  size_t len = SocketMetrics_export_prometheus (buffer, sizeof (buffer));

  if (len > 0 && len < sizeof (buffer))
    {
      printf ("%s\n", buffer);
    }
  else
    {
      printf ("   [ERROR] Export buffer too small\n");
    }
}

static void
print_statsd_format (void)
{
  printf ("\n=== StatsD Export Format ===\n\n");

  char buffer[65536];
  size_t len
      = SocketMetrics_export_statsd (buffer, sizeof (buffer), "myapp.socket");

  if (len > 0 && len < sizeof (buffer))
    {
      printf ("%s\n", buffer);
    }
  else
    {
      printf ("   [ERROR] Export buffer too small\n");
    }
}

static void
print_json_format (void)
{
  printf ("\n=== JSON Export Format ===\n\n");

  char buffer[65536];
  size_t len = SocketMetrics_export_json (buffer, sizeof (buffer));

  if (len > 0 && len < sizeof (buffer))
    {
      printf ("%s\n", buffer);
    }
  else
    {
      printf ("   [ERROR] Export buffer too small\n");
    }
}

static void
print_percentiles (void)
{
  printf ("\n=== Histogram Percentiles ===\n\n");

  printf ("HTTP Client Request Latency:\n");
  printf ("   p50:  %.2f ms\n",
          SocketMetrics_histogram_percentile (
              SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS, 50.0));
  printf ("   p75:  %.2f ms\n",
          SocketMetrics_histogram_percentile (
              SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS, 75.0));
  printf ("   p90:  %.2f ms\n",
          SocketMetrics_histogram_percentile (
              SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS, 90.0));
  printf ("   p95:  %.2f ms\n",
          SocketMetrics_histogram_percentile (
              SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS, 95.0));
  printf ("   p99:  %.2f ms\n",
          SocketMetrics_histogram_percentile (
              SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS, 99.0));
  printf ("   Count: %lu\n", (unsigned long)SocketMetrics_histogram_count (
                                 SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS));
  printf ("   Sum:   %.2f ms\n",
          SocketMetrics_histogram_sum (
              SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS));

  printf ("\nDNS Query Time:\n");
  printf ("   p50:  %.2f ms\n", SocketMetrics_histogram_percentile (
                                    SOCKET_HIST_DNS_QUERY_TIME_MS, 50.0));
  printf ("   p99:  %.2f ms\n", SocketMetrics_histogram_percentile (
                                    SOCKET_HIST_DNS_QUERY_TIME_MS, 99.0));
}

int
main (int argc, char **argv)
{
  const char *format = "all";

  if (argc > 1)
    format = argv[1];

  printf ("Metrics Collection Example\n");
  printf ("==========================\n\n");

  /* Initialize metrics system */
  printf ("1. Initializing metrics system...\n");
  SocketMetrics_init ();
  printf ("   [OK] Metrics initialized\n");

  /* Reset any existing metrics */
  SocketMetrics_reset ();

  /* Generate sample metrics */
  printf ("\n2. Generating sample metrics...\n");
  srand (42); /* Reproducible random for demo */

  simulate_http_requests (100);
  simulate_connection_pool ();
  simulate_dns_queries ();

  printf ("   [OK] Metrics generated\n");

  /* Export in requested format(s) */
  printf ("\n3. Exporting metrics...\n");

  if (strcmp (format, "prometheus") == 0 || strcmp (format, "all") == 0)
    {
      print_prometheus_format ();
    }

  if (strcmp (format, "statsd") == 0 || strcmp (format, "all") == 0)
    {
      print_statsd_format ();
    }

  if (strcmp (format, "json") == 0 || strcmp (format, "all") == 0)
    {
      print_json_format ();
    }

  if (strcmp (format, "percentiles") == 0 || strcmp (format, "all") == 0)
    {
      print_percentiles ();
    }

  /* Demonstrate counter reading */
  printf ("\n=== Direct Counter Values ===\n\n");
  printf ("HTTP Requests Total:  %lu\n",
          (unsigned long)SocketMetrics_counter_get (
              SOCKET_CTR_HTTP_CLIENT_REQUESTS_TOTAL));
  printf ("HTTP Responses Total: %lu\n",
          (unsigned long)SocketMetrics_counter_get (
              SOCKET_CTR_HTTP_CLIENT_RESPONSES_TOTAL));
  printf ("HTTP Errors:          %lu\n",
          (unsigned long)SocketMetrics_counter_get (
              SOCKET_CTR_HTTP_CLIENT_ERRORS));
  printf ("Pool Created:         %lu\n",
          (unsigned long)SocketMetrics_counter_get (
              SOCKET_CTR_POOL_CONNECTIONS_CREATED));
  printf ("Pool Reused:          %lu\n",
          (unsigned long)SocketMetrics_counter_get (
              SOCKET_CTR_POOL_CONNECTIONS_REUSED));
  printf (
      "DNS Queries:          %lu\n",
      (unsigned long)SocketMetrics_counter_get (SOCKET_CTR_DNS_QUERIES_TOTAL));
  printf (
      "DNS Cache Hits:       %lu\n",
      (unsigned long)SocketMetrics_counter_get (SOCKET_CTR_DNS_CACHE_HITS));

  /* Demonstrate gauge reading */
  printf ("\n=== Current Gauge Values ===\n\n");
  printf ("Active Connections:   %ld\n",
          (long)SocketMetrics_gauge_get (SOCKET_GAU_POOL_ACTIVE_CONNECTIONS));
  printf ("Idle Connections:     %ld\n",
          (long)SocketMetrics_gauge_get (SOCKET_GAU_POOL_IDLE_CONNECTIONS));

  /* Cleanup */
  printf ("\n4. Cleaning up...\n");
  SocketMetrics_shutdown ();

  printf ("\n[OK] Example completed successfully!\n");
  return 0;
}
