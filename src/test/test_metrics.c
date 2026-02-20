/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_metrics.c - SocketMetrics unit tests
 *
 * Part of the Socket Library Test Suite
 *
 * Comprehensive tests for the metrics subsystem including:
 * - Counter metrics (increment, add, get)
 * - Gauge metrics (set, inc, dec, add, get)
 * - Histogram metrics (observe, percentile, count, sum, snapshot)
 * - Snapshot and reset operations
 * - Export formats (Prometheus, StatsD, JSON)
 * - Socket count and peak tracking
 * - Metadata queries (names, help text)
 */

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Except.h"
#include "core/SocketMetrics.h"
#include "core/SocketUtil.h"
#include "socket/Socket.h"
#include "test/Test.h"

TEST (metrics_init_shutdown)
{
  /* Should be idempotent and not crash */
  int result = SocketMetrics_init ();
  ASSERT_EQ (0, result);

  SocketMetrics_shutdown ();

  /* Should be safe to call again */
  result = SocketMetrics_init ();
  ASSERT_EQ (0, result);
}

TEST (metrics_init_idempotent)
{
  /* Multiple init calls should be safe */
  int result1 = SocketMetrics_init ();
  int result2 = SocketMetrics_init ();
  int result3 = SocketMetrics_init ();

  ASSERT_EQ (0, result1);
  ASSERT_EQ (0, result2);
  ASSERT_EQ (0, result3);
}

TEST (metrics_counter_inc)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  uint64_t before = SocketMetrics_counter_get (SOCKET_CTR_SOCKET_CREATED);

  SocketMetrics_counter_inc (SOCKET_CTR_SOCKET_CREATED);

  uint64_t after = SocketMetrics_counter_get (SOCKET_CTR_SOCKET_CREATED);

  ASSERT_EQ (before + 1, after);
}

TEST (metrics_counter_add)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  SocketMetrics_counter_add (SOCKET_CTR_HTTP_CLIENT_BYTES_SENT, 1000);

  uint64_t value
      = SocketMetrics_counter_get (SOCKET_CTR_HTTP_CLIENT_BYTES_SENT);

  ASSERT_EQ (1000, value);
}

TEST (metrics_counter_get)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  /* Initial value should be 0 after reset */
  uint64_t value
      = SocketMetrics_counter_get (SOCKET_CTR_POOL_CONNECTIONS_CREATED);
  ASSERT_EQ (0, value);

  /* Add some value */
  SocketMetrics_counter_add (SOCKET_CTR_POOL_CONNECTIONS_CREATED, 42);
  value = SocketMetrics_counter_get (SOCKET_CTR_POOL_CONNECTIONS_CREATED);
  ASSERT_EQ (42, value);
}

TEST (metrics_counter_all_types)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  /* Test a few different counter types */
  SocketMetrics_counter_inc (SOCKET_CTR_SOCKET_CONNECT_SUCCESS);
  SocketMetrics_counter_inc (SOCKET_CTR_DNS_QUERIES_TOTAL);
  SocketMetrics_counter_inc (SOCKET_CTR_TLS_HANDSHAKES_TOTAL);

  ASSERT_EQ (1, SocketMetrics_counter_get (SOCKET_CTR_SOCKET_CONNECT_SUCCESS));
  ASSERT_EQ (1, SocketMetrics_counter_get (SOCKET_CTR_DNS_QUERIES_TOTAL));
  ASSERT_EQ (1, SocketMetrics_counter_get (SOCKET_CTR_TLS_HANDSHAKES_TOTAL));
}

TEST (metrics_counter_multiple_increments)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  for (int i = 0; i < 100; i++)
    {
      SocketMetrics_counter_inc (SOCKET_CTR_POLL_WAKEUPS);
    }

  uint64_t value = SocketMetrics_counter_get (SOCKET_CTR_POLL_WAKEUPS);
  ASSERT_EQ (100, value);
}

TEST (metrics_gauge_set)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  SocketMetrics_gauge_set (SOCKET_GAU_POOL_ACTIVE_CONNECTIONS, 42);

  int64_t value = SocketMetrics_gauge_get (SOCKET_GAU_POOL_ACTIVE_CONNECTIONS);

  ASSERT_EQ (42, value);
}

TEST (metrics_gauge_inc_dec)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  SocketMetrics_gauge_set (SOCKET_GAU_HTTP_CLIENT_ACTIVE_REQUESTS, 10);

  SocketMetrics_gauge_inc (SOCKET_GAU_HTTP_CLIENT_ACTIVE_REQUESTS);
  ASSERT_EQ (11,
             SocketMetrics_gauge_get (SOCKET_GAU_HTTP_CLIENT_ACTIVE_REQUESTS));

  SocketMetrics_gauge_dec (SOCKET_GAU_HTTP_CLIENT_ACTIVE_REQUESTS);
  ASSERT_EQ (10,
             SocketMetrics_gauge_get (SOCKET_GAU_HTTP_CLIENT_ACTIVE_REQUESTS));

  SocketMetrics_gauge_dec (SOCKET_GAU_HTTP_CLIENT_ACTIVE_REQUESTS);
  ASSERT_EQ (9,
             SocketMetrics_gauge_get (SOCKET_GAU_HTTP_CLIENT_ACTIVE_REQUESTS));
}

TEST (metrics_gauge_add)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  SocketMetrics_gauge_set (SOCKET_GAU_DNS_PENDING_QUERIES, 5);
  SocketMetrics_gauge_add (SOCKET_GAU_DNS_PENDING_QUERIES, 10);

  ASSERT_EQ (15, SocketMetrics_gauge_get (SOCKET_GAU_DNS_PENDING_QUERIES));

  /* Negative add */
  SocketMetrics_gauge_add (SOCKET_GAU_DNS_PENDING_QUERIES, -5);
  ASSERT_EQ (10, SocketMetrics_gauge_get (SOCKET_GAU_DNS_PENDING_QUERIES));
}

TEST (metrics_gauge_get)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  /* Initial value should be 0 after reset */
  int64_t value = SocketMetrics_gauge_get (SOCKET_GAU_POLL_REGISTERED_FDS);
  ASSERT_EQ (0, value);

  SocketMetrics_gauge_set (SOCKET_GAU_POLL_REGISTERED_FDS, 100);
  value = SocketMetrics_gauge_get (SOCKET_GAU_POLL_REGISTERED_FDS);
  ASSERT_EQ (100, value);
}

TEST (metrics_gauge_negative_values)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  /* Gauges can be negative */
  SocketMetrics_gauge_set (SOCKET_GAU_POOL_IDLE_CONNECTIONS, -10);
  ASSERT_EQ (-10, SocketMetrics_gauge_get (SOCKET_GAU_POOL_IDLE_CONNECTIONS));
}

TEST (metrics_histogram_observe)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  SocketMetrics_histogram_observe (SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS,
                                   100.0);
  SocketMetrics_histogram_observe (SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS,
                                   200.0);
  SocketMetrics_histogram_observe (SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS,
                                   150.0);

  uint64_t count = SocketMetrics_histogram_count (
      SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS);
  ASSERT_EQ (3, count);
}

TEST (metrics_histogram_count_sum)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  SocketMetrics_histogram_observe (SOCKET_HIST_SOCKET_CONNECT_TIME_MS, 10.0);
  SocketMetrics_histogram_observe (SOCKET_HIST_SOCKET_CONNECT_TIME_MS, 20.0);
  SocketMetrics_histogram_observe (SOCKET_HIST_SOCKET_CONNECT_TIME_MS, 30.0);

  uint64_t count
      = SocketMetrics_histogram_count (SOCKET_HIST_SOCKET_CONNECT_TIME_MS);
  double sum = SocketMetrics_histogram_sum (SOCKET_HIST_SOCKET_CONNECT_TIME_MS);

  ASSERT_EQ (3, count);
  /* Allow small floating point tolerance */
  ASSERT (fabs (sum - 60.0) < 0.001);
}

TEST (metrics_histogram_percentile)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Add values 1-100 */
  for (int i = 1; i <= 100; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                       (double)i);
    }

  double p50 = SocketMetrics_histogram_percentile (
      SOCKET_HIST_DNS_QUERY_TIME_MS, 50.0);
  double p90 = SocketMetrics_histogram_percentile (
      SOCKET_HIST_DNS_QUERY_TIME_MS, 90.0);
  double p99 = SocketMetrics_histogram_percentile (
      SOCKET_HIST_DNS_QUERY_TIME_MS, 99.0);

  /* p50 should be around 50 */
  ASSERT (p50 >= 45 && p50 <= 55);

  /* p90 should be around 90 */
  ASSERT (p90 >= 85 && p90 <= 95);

  /* p99 should be around 99 */
  ASSERT (p99 >= 95 && p99 <= 100);
}

TEST (metrics_histogram_snapshot)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  SocketMetrics_histogram_observe (SOCKET_HIST_POOL_ACQUIRE_TIME_MS, 10.0);
  SocketMetrics_histogram_observe (SOCKET_HIST_POOL_ACQUIRE_TIME_MS, 20.0);
  SocketMetrics_histogram_observe (SOCKET_HIST_POOL_ACQUIRE_TIME_MS, 30.0);
  SocketMetrics_histogram_observe (SOCKET_HIST_POOL_ACQUIRE_TIME_MS, 40.0);
  SocketMetrics_histogram_observe (SOCKET_HIST_POOL_ACQUIRE_TIME_MS, 50.0);

  SocketMetrics_HistogramSnapshot snapshot;
  SocketMetrics_histogram_snapshot (SOCKET_HIST_POOL_ACQUIRE_TIME_MS,
                                    &snapshot);

  ASSERT_EQ (5, snapshot.count);
  ASSERT (fabs (snapshot.sum - 150.0) < 0.001);
  ASSERT (fabs (snapshot.min - 10.0) < 0.001);
  ASSERT (fabs (snapshot.max - 50.0) < 0.001);
  ASSERT (fabs (snapshot.mean - 30.0) < 0.001);
}

TEST (metrics_histogram_empty)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Empty histogram should return 0 */
  uint64_t count
      = SocketMetrics_histogram_count (SOCKET_HIST_TLS_HANDSHAKE_TIME_MS);
  ASSERT_EQ (0, count);

  double p50 = SocketMetrics_histogram_percentile (
      SOCKET_HIST_TLS_HANDSHAKE_TIME_MS, 50.0);
  ASSERT (p50 == 0.0);
}

TEST (metrics_get_snapshot)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  /* Set some values */
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 10);
  SocketMetrics_gauge_set (SOCKET_GAU_POOL_ACTIVE_CONNECTIONS, 5);

  SocketMetrics_Snapshot snapshot;
  SocketMetrics_get (&snapshot);

  /* Verify timestamp is set */
  ASSERT (snapshot.timestamp_ms > 0);

  /* Verify counter value */
  ASSERT_EQ (10, snapshot.counters[SOCKET_CTR_SOCKET_CREATED]);

  /* Verify gauge value */
  ASSERT_EQ (5, snapshot.gauges[SOCKET_GAU_POOL_ACTIVE_CONNECTIONS]);
}

TEST (metrics_reset_all)
{
  SocketMetrics_init ();

  /* Set some values */
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 100);
  SocketMetrics_gauge_set (SOCKET_GAU_POOL_ACTIVE_CONNECTIONS, 50);
  SocketMetrics_histogram_observe (SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS,
                                   100.0);

  /* Reset all */
  SocketMetrics_reset ();

  /* All should be 0 */
  ASSERT_EQ (0, SocketMetrics_counter_get (SOCKET_CTR_SOCKET_CREATED));
  ASSERT_EQ (0, SocketMetrics_gauge_get (SOCKET_GAU_POOL_ACTIVE_CONNECTIONS));
  ASSERT_EQ (0,
             SocketMetrics_histogram_count (
                 SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS));
}

TEST (metrics_reset_counters_only)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  /* Set values */
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 100);
  SocketMetrics_gauge_set (SOCKET_GAU_POOL_ACTIVE_CONNECTIONS, 50);

  /* Reset only counters */
  SocketMetrics_reset_counters ();

  /* Counter should be 0, gauge should remain */
  ASSERT_EQ (0, SocketMetrics_counter_get (SOCKET_CTR_SOCKET_CREATED));
  ASSERT_EQ (50, SocketMetrics_gauge_get (SOCKET_GAU_POOL_ACTIVE_CONNECTIONS));
}

TEST (metrics_reset_histograms_only)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  /* Set values */
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 100);
  SocketMetrics_histogram_observe (SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS,
                                   100.0);

  /* Reset only histograms */
  SocketMetrics_reset_histograms ();

  /* Counter should remain, histogram should be 0 */
  ASSERT_EQ (100, SocketMetrics_counter_get (SOCKET_CTR_SOCKET_CREATED));
  ASSERT_EQ (0,
             SocketMetrics_histogram_count (
                 SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS));
}

TEST (metrics_export_prometheus_format)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 42);

  char buffer[65536]; /* Large buffer for Prometheus output */
  size_t len = SocketMetrics_export_prometheus (buffer, sizeof (buffer));

  ASSERT (len > 0);
  ASSERT (len < sizeof (buffer));

  /* Should contain Prometheus format markers */
  ASSERT_NOT_NULL (strstr (buffer, "# HELP"));
  ASSERT_NOT_NULL (strstr (buffer, "# TYPE"));
  ASSERT_NOT_NULL (strstr (buffer, "counter"));
}

TEST (metrics_export_statsd_format)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 42);

  char buffer[8192];
  size_t len = SocketMetrics_export_statsd (buffer, sizeof (buffer), "myapp");

  ASSERT (len > 0);
  ASSERT (len < sizeof (buffer));

  /* Should contain the prefix */
  ASSERT_NOT_NULL (strstr (buffer, "myapp"));

  /* Should contain StatsD format (|c for counter) */
  ASSERT_NOT_NULL (strstr (buffer, "|c"));
}

TEST (metrics_export_json_format)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 42);

  char buffer[131072]; /* Large buffer for JSON output */
  size_t len = SocketMetrics_export_json (buffer, sizeof (buffer));

  ASSERT (len > 0);
  ASSERT (len < sizeof (buffer));

  /* Should be valid JSON (has braces) */
  ASSERT_NOT_NULL (strstr (buffer, "{"));
  ASSERT_NOT_NULL (strstr (buffer, "}"));
  ASSERT_NOT_NULL (strstr (buffer, "\"counters\""));
  ASSERT_NOT_NULL (strstr (buffer, "\"gauges\""));
}

TEST (metrics_export_buffer_sizing)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 42);

  /* Test with small buffer */
  char small_buffer[10];
  size_t len
      = SocketMetrics_export_prometheus (small_buffer, sizeof (small_buffer));

  /* Should return required size when buffer too small */
  ASSERT (len >= sizeof (small_buffer));
}

TEST (metrics_socket_count)
{
  SocketMetrics_init ();

  int before = SocketMetrics_get_socket_count ();

  /* Create a socket */
  Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
  ASSERT_NOT_NULL (sock);

  int after_create = SocketMetrics_get_socket_count ();
  ASSERT_EQ (before + 1, after_create);

  /* Free the socket */
  Socket_free (&sock);

  int after_free = SocketMetrics_get_socket_count ();
  ASSERT_EQ (before, after_free);
}

TEST (metrics_peak_connections)
{
  SocketMetrics_init ();
  SocketMetrics_reset_peaks ();

  /* Get initial values */
  int initial_peak = SocketMetrics_get_peak_connections ();

  /* Create multiple sockets */
  Socket_T sock1 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock2 = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_T sock3 = Socket_new (AF_INET, SOCK_STREAM, 0);

  int peak_with_3 = SocketMetrics_get_peak_connections ();
  ASSERT (peak_with_3 >= initial_peak + 3);

  /* Free sockets */
  Socket_free (&sock3);
  Socket_free (&sock2);
  Socket_free (&sock1);

  /* Peak should still reflect the max */
  int peak_after_free = SocketMetrics_get_peak_connections ();
  ASSERT_EQ (peak_with_3, peak_after_free);
}

TEST (metrics_reset_peaks)
{
  SocketMetrics_init ();

  /* Create and free some sockets to establish a peak */
  Socket_T sock = Socket_new (AF_INET, SOCK_STREAM, 0);
  Socket_free (&sock);

  int peak_before = SocketMetrics_get_peak_connections ();

  /* Reset peaks */
  SocketMetrics_reset_peaks ();

  int peak_after = SocketMetrics_get_peak_connections ();

  /* Peak should be reset to current count */
  ASSERT (peak_after <= peak_before);
}

TEST (metrics_update_peak_basic)
{
  SocketMetrics_init ();
  SocketMetrics_reset_peaks ();

  int initial_peak = SocketMetrics_get_peak_connections ();

  /* Update with higher count should increase peak */
  SocketMetrics_update_peak_if_needed (initial_peak + 10);

  int new_peak = SocketMetrics_get_peak_connections ();
  ASSERT_EQ (initial_peak + 10, new_peak);
}

TEST (metrics_update_peak_no_change_when_lower)
{
  SocketMetrics_init ();
  SocketMetrics_reset_peaks ();

  /* Set an initial peak */
  SocketMetrics_update_peak_if_needed (100);
  ASSERT_EQ (100, SocketMetrics_get_peak_connections ());

  /* Try to update with lower value - should not change */
  SocketMetrics_update_peak_if_needed (50);
  ASSERT_EQ (100, SocketMetrics_get_peak_connections ());
}

TEST (metrics_update_peak_no_change_when_equal)
{
  SocketMetrics_init ();
  SocketMetrics_reset_peaks ();

  /* Set an initial peak */
  SocketMetrics_update_peak_if_needed (100);
  ASSERT_EQ (100, SocketMetrics_get_peak_connections ());

  /* Try to update with equal value - should not change */
  SocketMetrics_update_peak_if_needed (100);
  ASSERT_EQ (100, SocketMetrics_get_peak_connections ());
}

TEST (metrics_update_peak_zero)
{
  SocketMetrics_init ();
  SocketMetrics_reset_peaks ();

  /* Test with zero value */
  SocketMetrics_update_peak_if_needed (0);
  int peak = SocketMetrics_get_peak_connections ();

  /* Peak should be at least 0 */
  ASSERT (peak >= 0);
}

TEST (metrics_update_peak_large_value)
{
  SocketMetrics_init ();
  SocketMetrics_reset_peaks ();

  /* Test with large value */
  SocketMetrics_update_peak_if_needed (10000);
  ASSERT_EQ (10000, SocketMetrics_get_peak_connections ());
}

TEST (metrics_update_peak_incremental)
{
  SocketMetrics_init ();
  SocketMetrics_reset_peaks ();

  /* Incrementally increase peak */
  for (int i = 1; i <= 100; i++)
    {
      SocketMetrics_update_peak_if_needed (i);
      ASSERT_EQ (i, SocketMetrics_get_peak_connections ());
    }
}

#include <pthread.h>

#define THREAD_COUNT 8
#define ITERATIONS_PER_THREAD 1000

typedef struct
{
  int thread_id;
  int max_value;
} thread_data_t;

static void *
thread_update_peak (void *arg)
{
  thread_data_t *data = (thread_data_t *)arg;

  /* Each thread updates with increasing values */
  for (int i = 0; i < ITERATIONS_PER_THREAD; i++)
    {
      int value = data->thread_id * ITERATIONS_PER_THREAD + i;
      SocketMetrics_update_peak_if_needed (value);
      if (value > data->max_value)
        {
          data->max_value = value;
        }
    }

  return NULL;
}

TEST (metrics_update_peak_concurrent)
{
  SocketMetrics_init ();
  SocketMetrics_reset_peaks ();

  pthread_t threads[THREAD_COUNT];
  thread_data_t thread_data[THREAD_COUNT];

  int expected_max = 0;

  /* Start threads */
  for (int i = 0; i < THREAD_COUNT; i++)
    {
      thread_data[i].thread_id = i;
      thread_data[i].max_value = 0;
      pthread_create (&threads[i], NULL, thread_update_peak, &thread_data[i]);
    }

  /* Wait for all threads */
  for (int i = 0; i < THREAD_COUNT; i++)
    {
      pthread_join (threads[i], NULL);
      if (thread_data[i].max_value > expected_max)
        {
          expected_max = thread_data[i].max_value;
        }
    }

  /* Peak should be the highest value seen across all threads */
  int final_peak = SocketMetrics_get_peak_connections ();
  ASSERT_EQ (expected_max, final_peak);
}

static void *
thread_update_same_value (void *arg)
{
  int value = *(int *)arg;

  /* All threads try to update with the same value repeatedly */
  for (int i = 0; i < ITERATIONS_PER_THREAD; i++)
    {
      SocketMetrics_update_peak_if_needed (value);
    }

  return NULL;
}

TEST (metrics_update_peak_concurrent_same_value)
{
  SocketMetrics_init ();
  SocketMetrics_reset_peaks ();

  pthread_t threads[THREAD_COUNT];
  int shared_value = 5000;

  /* All threads update with the same value */
  for (int i = 0; i < THREAD_COUNT; i++)
    {
      pthread_create (
          &threads[i], NULL, thread_update_same_value, &shared_value);
    }

  /* Wait for all threads */
  for (int i = 0; i < THREAD_COUNT; i++)
    {
      pthread_join (threads[i], NULL);
    }

  /* Peak should be the shared value */
  ASSERT_EQ (shared_value, SocketMetrics_get_peak_connections ());
}

static void *
thread_update_descending (void *arg)
{
  thread_data_t *data = (thread_data_t *)arg;

  /* Each thread updates with descending values from high to low */
  int start = (data->thread_id + 1) * ITERATIONS_PER_THREAD;
  for (int i = 0; i < ITERATIONS_PER_THREAD; i++)
    {
      int value = start - i;
      SocketMetrics_update_peak_if_needed (value);
      if (value > data->max_value)
        {
          data->max_value = value;
        }
    }

  return NULL;
}

TEST (metrics_update_peak_concurrent_descending)
{
  SocketMetrics_init ();
  SocketMetrics_reset_peaks ();

  pthread_t threads[THREAD_COUNT];
  thread_data_t thread_data[THREAD_COUNT];

  int expected_max = 0;

  /* Start threads with descending values */
  for (int i = 0; i < THREAD_COUNT; i++)
    {
      thread_data[i].thread_id = i;
      thread_data[i].max_value = 0;
      pthread_create (
          &threads[i], NULL, thread_update_descending, &thread_data[i]);
    }

  /* Wait for all threads */
  for (int i = 0; i < THREAD_COUNT; i++)
    {
      pthread_join (threads[i], NULL);
      if (thread_data[i].max_value > expected_max)
        {
          expected_max = thread_data[i].max_value;
        }
    }

  /* Peak should be the highest starting value */
  int final_peak = SocketMetrics_get_peak_connections ();
  ASSERT_EQ (expected_max, final_peak);
}

TEST (metrics_counter_name)
{
  const char *name = SocketMetrics_counter_name (SOCKET_CTR_SOCKET_CREATED);
  ASSERT_NOT_NULL (name);
  ASSERT (strlen (name) > 0);
}

TEST (metrics_gauge_name)
{
  const char *name
      = SocketMetrics_gauge_name (SOCKET_GAU_POOL_ACTIVE_CONNECTIONS);
  ASSERT_NOT_NULL (name);
  ASSERT (strlen (name) > 0);
}

TEST (metrics_histogram_name)
{
  const char *name = SocketMetrics_histogram_name (
      SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS);
  ASSERT_NOT_NULL (name);
  ASSERT (strlen (name) > 0);
}

TEST (metrics_counter_help)
{
  const char *help = SocketMetrics_counter_help (SOCKET_CTR_SOCKET_CREATED);
  ASSERT_NOT_NULL (help);
  ASSERT (strlen (help) > 0);
}

TEST (metrics_gauge_help)
{
  const char *help
      = SocketMetrics_gauge_help (SOCKET_GAU_POOL_ACTIVE_CONNECTIONS);
  ASSERT_NOT_NULL (help);
  ASSERT (strlen (help) > 0);
}

TEST (metrics_histogram_help)
{
  const char *help = SocketMetrics_histogram_help (
      SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS);
  ASSERT_NOT_NULL (help);
  ASSERT (strlen (help) > 0);
}

TEST (metrics_category_name)
{
  const char *pool_name = SocketMetrics_category_name (SOCKET_METRIC_CAT_POOL);
  ASSERT_NOT_NULL (pool_name);
  ASSERT (strlen (pool_name) > 0);

  const char *tls_name = SocketMetrics_category_name (SOCKET_METRIC_CAT_TLS);
  ASSERT_NOT_NULL (tls_name);
  ASSERT (strlen (tls_name) > 0);
}

TEST (metrics_grpc_metadata_names_and_help_are_mapped)
{
  const char *grpc_category
      = SocketMetrics_category_name (SOCKET_METRIC_CAT_GRPC);
  const char *client_started
      = SocketMetrics_counter_name (SOCKET_CTR_GRPC_CLIENT_CALLS_STARTED);
  const char *client_started_help
      = SocketMetrics_counter_help (SOCKET_CTR_GRPC_CLIENT_CALLS_STARTED);
  const char *server_status_ok
      = SocketMetrics_counter_name (SOCKET_CTR_GRPC_SERVER_STATUS_OK);
  const char *server_status_ok_help
      = SocketMetrics_counter_help (SOCKET_CTR_GRPC_SERVER_STATUS_OK);
  const char *stream_gauge
      = SocketMetrics_gauge_name (SOCKET_GAU_GRPC_CLIENT_ACTIVE_STREAMS);
  const char *stream_gauge_help
      = SocketMetrics_gauge_help (SOCKET_GAU_GRPC_CLIENT_ACTIVE_STREAMS);
  const char *client_latency_hist
      = SocketMetrics_histogram_name (SOCKET_HIST_GRPC_CLIENT_CALL_LATENCY_MS);
  const char *client_latency_help
      = SocketMetrics_histogram_help (SOCKET_HIST_GRPC_CLIENT_CALL_LATENCY_MS);

  ASSERT_NOT_NULL (grpc_category);
  ASSERT_EQ (0, strcmp (grpc_category, "grpc"));
  ASSERT_NOT_NULL (client_started);
  ASSERT_NOT_NULL (client_started_help);
  ASSERT_NOT_NULL (server_status_ok);
  ASSERT_NOT_NULL (server_status_ok_help);
  ASSERT_NOT_NULL (stream_gauge);
  ASSERT_NOT_NULL (stream_gauge_help);
  ASSERT_NOT_NULL (client_latency_hist);
  ASSERT_NOT_NULL (client_latency_help);
  ASSERT (strstr (client_started, "grpc_client_") != NULL);
  ASSERT (strstr (server_status_ok, "grpc_server_") != NULL);
  ASSERT (strstr (stream_gauge, "grpc_") != NULL);
  ASSERT (strstr (client_latency_hist, "grpc_client_") != NULL);
  ASSERT (strlen (client_started_help) > 0);
  ASSERT (strlen (server_status_ok_help) > 0);
  ASSERT (strlen (stream_gauge_help) > 0);
  ASSERT (strlen (client_latency_help) > 0);
}

TEST (metrics_export_prometheus_exact_buffer_size)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 42);

  /* First get the required size with large buffer */
  char large_buf[65536];
  size_t needed
      = SocketMetrics_export_prometheus (large_buf, sizeof (large_buf));
  ASSERT (needed > 0);
  ASSERT (needed < sizeof (large_buf));

  /* Test with exact buffer size */
  char *exact_buf = malloc (needed);
  ASSERT_NOT_NULL (exact_buf);
  size_t actual = SocketMetrics_export_prometheus (exact_buf, needed);

  /* Should match the needed size */
  ASSERT_EQ (needed, actual);
  free (exact_buf);
}

TEST (metrics_export_prometheus_off_by_one)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 100);

  /* Get required size */
  char large_buf[65536];
  size_t needed
      = SocketMetrics_export_prometheus (large_buf, sizeof (large_buf));

  /* Test with buffer 1 byte too small */
  if (needed > 1)
    {
      char *small_buf = malloc (needed - 1);
      ASSERT_NOT_NULL (small_buf);
      size_t actual = SocketMetrics_export_prometheus (small_buf, needed - 1);

      /* Should truncate safely */
      ASSERT (actual <= needed - 1);
      free (small_buf);
    }
}

TEST (metrics_export_prometheus_tiny_buffer)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  /* Populate with multiple metrics */
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 100);
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CONNECT_SUCCESS, 50);
  SocketMetrics_gauge_set (SOCKET_GAU_POOL_ACTIVE_CONNECTIONS, 5);

  /* Test with tiny 10-byte buffer */
  char tiny_buf[10];
  size_t actual = SocketMetrics_export_prometheus (tiny_buf, sizeof (tiny_buf));

  /* Should handle gracefully without overflow */
  ASSERT (actual >= sizeof (tiny_buf));
}

TEST (metrics_export_prometheus_zero_buffer)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 42);

  /* Zero-size buffer should return 0 */
  char buffer[100];
  size_t result = SocketMetrics_export_prometheus (buffer, 0);
  ASSERT_EQ (0, result);
}

TEST (metrics_export_prometheus_null_buffer)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 42);

  /* NULL buffer should return 0 */
  size_t result = SocketMetrics_export_prometheus (NULL, 1000);
  ASSERT_EQ (0, result);
}

TEST (metrics_export_statsd_exact_buffer_size)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 42);

  /* Get required size */
  char large_buf[8192];
  size_t needed
      = SocketMetrics_export_statsd (large_buf, sizeof (large_buf), "test");
  ASSERT (needed > 0);

  /* Test with exact size */
  char *exact_buf = malloc (needed);
  ASSERT_NOT_NULL (exact_buf);
  size_t actual = SocketMetrics_export_statsd (exact_buf, needed, "test");
  ASSERT_EQ (needed, actual);
  free (exact_buf);
}

TEST (metrics_export_statsd_null_buffer)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 42);

  size_t result = SocketMetrics_export_statsd (NULL, 1000, "test");
  ASSERT_EQ (0, result);
}

TEST (metrics_export_statsd_zero_buffer)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  char buffer[100];
  size_t result = SocketMetrics_export_statsd (buffer, 0, "test");
  ASSERT_EQ (0, result);
}

TEST (metrics_export_json_exact_buffer_size)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 42);

  /* Get required size */
  char large_buf[131072];
  size_t needed = SocketMetrics_export_json (large_buf, sizeof (large_buf));
  ASSERT (needed > 0);

  /* Test with exact size */
  char *exact_buf = malloc (needed);
  ASSERT_NOT_NULL (exact_buf);
  size_t actual = SocketMetrics_export_json (exact_buf, needed);
  ASSERT_EQ (needed, actual);
  free (exact_buf);
}

TEST (metrics_export_json_null_buffer)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  size_t result = SocketMetrics_export_json (NULL, 1000);
  ASSERT_EQ (0, result);
}

TEST (metrics_export_json_zero_buffer)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  char buffer[100];
  size_t result = SocketMetrics_export_json (buffer, 0);
  ASSERT_EQ (0, result);
}

TEST (metrics_export_prometheus_large_values)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  /* Test with UINT64_MAX counter */
  SocketMetrics_counter_add (SOCKET_CTR_HTTP_CLIENT_BYTES_SENT, UINT64_MAX);

  char buffer[65536];
  size_t len = SocketMetrics_export_prometheus (buffer, sizeof (buffer));

  ASSERT (len > 0);
  /* Should contain the max value in string form */
  ASSERT_NOT_NULL (strstr (buffer, "18446744073709551615"));
}

TEST (metrics_export_prometheus_negative_gauge)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  /* Test with negative gauge value */
  SocketMetrics_gauge_set (SOCKET_GAU_POOL_IDLE_CONNECTIONS, INT64_MIN);

  char buffer[65536];
  size_t len = SocketMetrics_export_prometheus (buffer, sizeof (buffer));

  ASSERT (len > 0);
  /* Should contain negative value */
  ASSERT_NOT_NULL (strstr (buffer, "-"));
}

TEST (metrics_export_prometheus_empty_metrics)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  /* All metrics at zero */
  char buffer[65536];
  size_t len = SocketMetrics_export_prometheus (buffer, sizeof (buffer));

  ASSERT (len > 0);
  /* Should still produce valid output with zeros */
  ASSERT_NOT_NULL (strstr (buffer, "# HELP"));
  ASSERT_NOT_NULL (strstr (buffer, "# TYPE"));
}

TEST (metrics_export_prometheus_full_metrics)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  /* Populate all metric types */
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 100);
  SocketMetrics_counter_add (SOCKET_CTR_HTTP_CLIENT_BYTES_SENT, 5000);
  SocketMetrics_gauge_set (SOCKET_GAU_POOL_ACTIVE_CONNECTIONS, 10);
  SocketMetrics_gauge_set (SOCKET_GAU_HTTP_CLIENT_ACTIVE_REQUESTS, 3);

  /* Add histogram observations */
  SocketMetrics_histogram_observe (SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS,
                                   100.0);
  SocketMetrics_histogram_observe (SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS,
                                   200.0);
  SocketMetrics_histogram_observe (SOCKET_HIST_SOCKET_CONNECT_TIME_MS, 50.0);

  char buffer[131072];
  size_t len = SocketMetrics_export_prometheus (buffer, sizeof (buffer));

  ASSERT (len > 0);
  ASSERT (len < sizeof (buffer));
  /* Should contain all sections */
  ASSERT_NOT_NULL (strstr (buffer, "counter"));
  ASSERT_NOT_NULL (strstr (buffer, "gauge"));
  ASSERT_NOT_NULL (strstr (buffer, "summary"));
}

TEST (metrics_export_statsd_null_prefix)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 42);

  /* NULL prefix should use default "socket" */
  char buffer[8192];
  size_t len = SocketMetrics_export_statsd (buffer, sizeof (buffer), NULL);

  ASSERT (len > 0);
  ASSERT_NOT_NULL (strstr (buffer, "socket."));
}

TEST (metrics_export_statsd_empty_prefix)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 42);

  /* Empty prefix should use default "socket" */
  char buffer[8192];
  size_t len = SocketMetrics_export_statsd (buffer, sizeof (buffer), "");

  ASSERT (len > 0);
  /* Empty prefix becomes "socket" */
  ASSERT_NOT_NULL (strstr (buffer, "."));
}

TEST (metrics_export_statsd_long_prefix)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 42);

  /* Long prefix */
  const char *long_prefix = "myapp.production.cluster1.backend.metrics";
  char buffer[8192];
  size_t len
      = SocketMetrics_export_statsd (buffer, sizeof (buffer), long_prefix);

  ASSERT (len > 0);
  ASSERT_NOT_NULL (strstr (buffer, long_prefix));
}

TEST (metrics_export_statsd_metric_separators)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 42);

  char buffer[8192];
  size_t len = SocketMetrics_export_statsd (buffer, sizeof (buffer), "app");

  ASSERT (len > 0);
  /* Should contain dot separators */
  ASSERT_NOT_NULL (strstr (buffer, "app."));
  ASSERT_NOT_NULL (strstr (buffer, "."));
}

TEST (metrics_export_statsd_type_suffixes)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 100);
  SocketMetrics_gauge_set (SOCKET_GAU_POOL_ACTIVE_CONNECTIONS, 5);

  char buffer[8192];
  size_t len = SocketMetrics_export_statsd (buffer, sizeof (buffer), "test");

  ASSERT (len > 0);
  /* Counter suffix */
  ASSERT_NOT_NULL (strstr (buffer, "|c"));
  /* Gauge suffix */
  ASSERT_NOT_NULL (strstr (buffer, "|g"));
}

TEST (metrics_export_statsd_prefix_sanitized)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();
  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 1);

  char buffer[8192];
  size_t len = SocketMetrics_export_statsd (
      buffer, sizeof (buffer), "app\nattack.metric:1|c");

  ASSERT (len > 0);
  ASSERT_NOT_NULL (strstr (buffer, "appattack.metric1c."));
  ASSERT_NULL (strstr (buffer, "attack.metric:1|c"));
}

TEST (metrics_export_statsd_percentile_names)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Add histogram data */
  for (int i = 1; i <= 100; i++)
    {
      SocketMetrics_histogram_observe (
          SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS, (double)i);
    }

  char buffer[8192];
  size_t len = SocketMetrics_export_statsd (buffer, sizeof (buffer), "app");

  ASSERT (len > 0);
  /* Should contain percentile names */
  ASSERT_NOT_NULL (strstr (buffer, "p50"));
  ASSERT_NOT_NULL (strstr (buffer, "p95"));
  ASSERT_NOT_NULL (strstr (buffer, "p99"));
}

TEST (metrics_export_json_valid_structure)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  SocketMetrics_counter_add (SOCKET_CTR_SOCKET_CREATED, 100);
  SocketMetrics_gauge_set (SOCKET_GAU_POOL_ACTIVE_CONNECTIONS, 5);

  char buffer[131072];
  size_t len = SocketMetrics_export_json (buffer, sizeof (buffer));

  ASSERT (len > 0);

  /* Verify balanced braces */
  int brace_count = 0;
  for (char *p = buffer; *p; p++)
    {
      if (*p == '{')
        brace_count++;
      if (*p == '}')
        brace_count--;
    }
  ASSERT_EQ (0, brace_count);

  /* Verify no trailing commas before closing braces */
  ASSERT_NULL (strstr (buffer, ",\n  }"));
  ASSERT_NULL (strstr (buffer, ",\n}"));
}

TEST (metrics_export_json_floating_point_precision)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Add values to get varied percentiles */
  SocketMetrics_histogram_observe (SOCKET_HIST_SOCKET_CONNECT_TIME_MS,
                                   1.123456789);
  SocketMetrics_histogram_observe (SOCKET_HIST_SOCKET_CONNECT_TIME_MS,
                                   2.987654321);
  SocketMetrics_histogram_observe (SOCKET_HIST_SOCKET_CONNECT_TIME_MS, 3.5);

  char buffer[131072];
  size_t len = SocketMetrics_export_json (buffer, sizeof (buffer));

  ASSERT (len > 0);

  /* Should not contain NaN or Infinity */
  ASSERT_NULL (strstr (buffer, "NaN"));
  ASSERT_NULL (strstr (buffer, "Infinity"));
  ASSERT_NULL (strstr (buffer, "nan"));
  ASSERT_NULL (strstr (buffer, "inf"));
}

TEST (metrics_export_json_empty_histograms)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  /* No histogram observations */
  char buffer[131072];
  size_t len = SocketMetrics_export_json (buffer, sizeof (buffer));

  ASSERT (len > 0);

  /* Should still have histograms section with all zeros */
  ASSERT_NOT_NULL (strstr (buffer, "\"histograms\""));
  ASSERT_NOT_NULL (strstr (buffer, "\"count\": 0"));
}

TEST (metrics_export_json_large_counter_values)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  /* Test with very large counter value */
  SocketMetrics_counter_add (SOCKET_CTR_HTTP_CLIENT_BYTES_SENT,
                             9223372036854775807ULL);

  char buffer[131072];
  size_t len = SocketMetrics_export_json (buffer, sizeof (buffer));

  ASSERT (len > 0);
  /* Should contain large number as string */
  ASSERT_NOT_NULL (strstr (buffer, "9223372036854775807"));
}

TEST (metrics_export_json_negative_gauge_values)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  /* Test with negative gauge */
  SocketMetrics_gauge_set (SOCKET_GAU_POOL_IDLE_CONNECTIONS, -42);

  char buffer[131072];
  size_t len = SocketMetrics_export_json (buffer, sizeof (buffer));

  ASSERT (len > 0);
  /* Should contain negative value */
  ASSERT_NOT_NULL (strstr (buffer, "-42"));
}

TEST (metrics_export_json_timestamp_present)
{
  SocketMetrics_init ();
  SocketMetrics_reset ();

  char buffer[131072];
  size_t len = SocketMetrics_export_json (buffer, sizeof (buffer));

  ASSERT (len > 0);
  /* Should contain timestamp_ms field */
  ASSERT_NOT_NULL (strstr (buffer, "\"timestamp_ms\""));
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
