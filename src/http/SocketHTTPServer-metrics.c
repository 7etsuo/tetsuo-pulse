/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketHTTPServer-metrics.c
 * @brief HTTP server metrics and statistics collection.
 * @internal
 *
 * Provides thread-safe statistics tracking and reporting for HTTP server
 * instances. Uses atomic operations for lock-free counter updates.
 */

#include "http/SocketHTTPServer-private.h"
#include "core/SocketMetrics.h"
#include "core/SocketUtil.h"
#include <assert.h>
#include <stdatomic.h>
#include <string.h>

void
SocketHTTPServer_stats (SocketHTTPServer_T server,
                        SocketHTTPServer_Stats *stats)
{
  assert (server != NULL);
  assert (stats != NULL);

  memset (stats, 0, sizeof (*stats));

  /* Use per-server metrics when enabled, otherwise global metrics */
  if (server->config.per_server_metrics)
    {
      /* Per-server instance metrics - atomic reads */
      stats->active_connections
          = (size_t)atomic_load (&server->instance_metrics.active_connections);
      stats->total_connections
          = atomic_load (&server->instance_metrics.connections_total);
      stats->connections_rejected
          = atomic_load (&server->instance_metrics.connections_rejected);
      stats->total_requests
          = atomic_load (&server->instance_metrics.requests_total);
      stats->total_bytes_sent
          = atomic_load (&server->instance_metrics.bytes_sent);
      stats->total_bytes_received
          = atomic_load (&server->instance_metrics.bytes_received);
      stats->errors_4xx = atomic_load (&server->instance_metrics.errors_4xx);
      stats->errors_5xx = atomic_load (&server->instance_metrics.errors_5xx);
      stats->timeouts
          = atomic_load (&server->instance_metrics.requests_timeout);
      stats->rate_limited
          = atomic_load (&server->instance_metrics.rate_limited);
    }
  else
    {
      /* Global metrics - thread-safe via SocketMetrics */
      stats->active_connections = (size_t)SocketMetrics_gauge_get (
          SOCKET_GAU_HTTP_SERVER_ACTIVE_CONNECTIONS);
      stats->total_connections = SocketMetrics_counter_get (
          SOCKET_CTR_HTTP_SERVER_CONNECTIONS_TOTAL);
      stats->total_requests
          = SocketMetrics_counter_get (SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL);
      stats->total_bytes_sent
          = SocketMetrics_counter_get (SOCKET_CTR_HTTP_SERVER_BYTES_SENT);
      stats->total_bytes_received
          = SocketMetrics_counter_get (SOCKET_CTR_HTTP_SERVER_BYTES_RECEIVED);
      stats->errors_4xx
          = SocketMetrics_counter_get (SOCKET_CTR_HTTP_RESPONSES_4XX);
      stats->errors_5xx
          = SocketMetrics_counter_get (SOCKET_CTR_HTTP_RESPONSES_5XX);
      stats->connections_rejected
          = SocketMetrics_counter_get (SOCKET_CTR_LIMIT_CONNECTIONS_EXCEEDED);
      stats->timeouts
          = SocketMetrics_counter_get (SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT);
      stats->rate_limited
          = SocketMetrics_counter_get (SOCKET_CTR_HTTP_SERVER_RATE_LIMITED);
    }

  /* RPS approximation: delta requests / delta time using per-server tracking
   */
  /* Thread-safe via mutex */
  uint64_t prev_requests = server->stats_prev_requests;
  int64_t prev_time = server->stats_prev_time_ms;
  int64_t now = Socket_get_monotonic_ms ();
  uint64_t curr_requests = stats->total_requests;

  pthread_mutex_lock (&server->stats_mutex);
  if (prev_time > 0 && now > prev_time)
    {
      double seconds = (double)(now - prev_time) / 1000.0;
      if (seconds > 0.0)
        {
          stats->requests_per_second
              = (size_t)((curr_requests - prev_requests) / seconds);
        }
    }
  server->stats_prev_requests = curr_requests;
  server->stats_prev_time_ms = now;
  pthread_mutex_unlock (&server->stats_mutex);

  /* Latency from histogram snapshot (unit: ms in metric, convert to us) */
  SocketMetrics_HistogramSnapshot snap;
  SocketMetrics_histogram_snapshot (SOCKET_HIST_HTTP_SERVER_REQUEST_LATENCY_MS,
                                    &snap);
  stats->avg_request_time_us = (int64_t)(snap.mean * 1000);
  stats->max_request_time_us = (int64_t)(snap.max * 1000);
  stats->p50_request_time_us = (int64_t)(snap.p50 * 1000);
  stats->p95_request_time_us = (int64_t)(snap.p95 * 1000);
  stats->p99_request_time_us = (int64_t)(snap.p99 * 1000);
}

void
SocketHTTPServer_stats_reset (SocketHTTPServer_T server)
{
  assert (server != NULL);

  /* Reset per-server RPS tracking */
  pthread_mutex_lock (&server->stats_mutex);
  server->stats_prev_requests = 0;
  server->stats_prev_time_ms = 0;
  pthread_mutex_unlock (&server->stats_mutex);

  /* Reset per-server instance metrics if enabled */
  if (server->config.per_server_metrics)
    {
      /* Preserve active_connections (current gauge), reset cumulative counters
       */
      atomic_store (&server->instance_metrics.connections_total, 0);
      atomic_store (&server->instance_metrics.connections_rejected, 0);
      atomic_store (&server->instance_metrics.requests_total, 0);
      atomic_store (&server->instance_metrics.requests_timeout, 0);
      atomic_store (&server->instance_metrics.rate_limited, 0);
      atomic_store (&server->instance_metrics.bytes_sent, 0);
      atomic_store (&server->instance_metrics.bytes_received, 0);
      atomic_store (&server->instance_metrics.errors_4xx, 0);
      atomic_store (&server->instance_metrics.errors_5xx, 0);
      /* Note: active_connections not reset - reflects live state */
    }

  /* Reset centralized metrics - affects all modules using global metrics */
  SocketMetrics_reset ();
}
