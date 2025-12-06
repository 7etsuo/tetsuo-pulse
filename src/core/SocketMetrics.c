/**
 * SocketMetrics.c - Production-Grade Metrics Implementation
 *
 * Part of the Socket Library
 *
 * This file implements the comprehensive metrics collection and export system
 * for production monitoring and observability.
 *
 * IMPLEMENTATION NOTES:
 * - Counters and gauges use atomic operations for lock-free performance
 * - Histograms use a circular buffer with mutex protection
 * - Percentiles calculated using sort + linear interpolation
 *
 * THREAD SAFETY:
 * - All counter/gauge operations are atomic
 * - Histogram operations protected by per-histogram mutex
 * - Snapshot operations acquire all locks atomically
 */

#include "core/SocketMetrics.h"
#include "core/SocketConfig.h"
#include "core/SocketUtil.h"

#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */

/** Standard percentiles for histogram snapshots */
#define PERCENTILE_P50 50.0
#define PERCENTILE_P75 75.0
#define PERCENTILE_P90 90.0
#define PERCENTILE_P95 95.0
#define PERCENTILE_P99 99.0
#define PERCENTILE_P999 99.9

/* ============================================================================
 * Internal Logging
 * ============================================================================ */

#ifdef SOCKET_METRICS_DEBUG
#define METRICS_LOG_DEBUG(msg)                                                 \
  fprintf (stderr, "[SocketMetrics] DEBUG: %s\n", (msg))
#else
#define METRICS_LOG_DEBUG(msg) ((void)0)
#endif

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

/**
 * Histogram - Internal histogram data structure
 *
 * Uses circular buffer reservoir sampling for O(1) insertion.
 * Percentile calculation is O(n log n) using qsort.
 */
typedef struct Histogram
{
  pthread_mutex_t mutex;
  double values[SOCKET_METRICS_HISTOGRAM_BUCKETS];
  size_t write_index;
  _Atomic uint64_t count;
  double sum;
  double min;
  double max;
  int initialized;
} Histogram;

/* ============================================================================
 * Static Data
 * ============================================================================ */

static _Atomic int metrics_initialized = 0;
static _Atomic uint64_t counter_values[SOCKET_COUNTER_METRIC_COUNT];
static _Atomic int64_t gauge_values[SOCKET_GAUGE_METRIC_COUNT];
static Histogram histogram_values[SOCKET_HISTOGRAM_METRIC_COUNT];
static pthread_mutex_t metrics_global_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ============================================================================
 * Metric Name Tables
 * ============================================================================ */

static const char *const counter_names[SOCKET_COUNTER_METRIC_COUNT] = {
  /* Pool */
  "pool_connections_created",
  "pool_connections_destroyed",
  "pool_connections_failed",
  "pool_connections_reused",
  "pool_connections_evicted",
  "pool_drain_started",
  "pool_drain_completed",
  /* HTTP Client */
  "http_client_requests_total",
  "http_client_requests_failed",
  "http_client_requests_timeout",
  "http_client_bytes_sent",
  "http_client_bytes_received",
  "http_client_retries",
  /* HTTP Server */
  "http_server_requests_total",
  "http_server_requests_failed",
  "http_server_bytes_sent",
  "http_server_bytes_received",
  "http_server_connections_total",
  /* HTTP Responses */
  "http_responses_1xx",
  "http_responses_2xx",
  "http_responses_3xx",
  "http_responses_4xx",
  "http_responses_5xx",
  /* TLS */
  "tls_handshakes_total",
  "tls_handshakes_failed",
  "tls_session_reuse_count",
  "tls_cert_verify_failures",
  "tls_renegotiations",
  /* DNS */
  "dns_queries_total",
  "dns_queries_failed",
  "dns_queries_timeout",
  "dns_queries_cancelled",
  "dns_cache_hits",
  "dns_cache_misses",
  /* Socket */
  "socket_created",
  "socket_closed",
  "socket_connect_success",
  "socket_connect_failed",
  "socket_accept_total",
  /* Poll */
  "poll_wakeups",
  "poll_events_dispatched",
  "poll_timeout_expirations",
  /* Resource Limits */
  "limit_header_size_exceeded",
  "limit_body_size_exceeded",
  "limit_response_size_exceeded",
  "limit_memory_exceeded",
  "limit_connections_exceeded",
  "limit_streams_exceeded",
  "limit_header_list_exceeded"
};

static const char *const counter_help[SOCKET_COUNTER_METRIC_COUNT] = {
  /* Pool */
  "Total connections created in pool",
  "Total connections destroyed in pool",
  "Failed connection attempts",
  "Connections reused from pool",
  "Connections evicted due to idle/age limits",
  "Pool drain operations started",
  "Pool drain operations completed",
  /* HTTP Client */
  "Total HTTP requests sent",
  "Failed HTTP requests",
  "HTTP requests that timed out",
  "Total bytes sent by HTTP client",
  "Total bytes received by HTTP client",
  "HTTP request retry count",
  /* HTTP Server */
  "Total HTTP requests received",
  "Failed request processing",
  "Total bytes sent by HTTP server",
  "Total bytes received by HTTP server",
  "Total connections accepted by server",
  /* HTTP Responses */
  "Informational HTTP responses (1xx)",
  "Successful HTTP responses (2xx)",
  "Redirection HTTP responses (3xx)",
  "Client error HTTP responses (4xx)",
  "Server error HTTP responses (5xx)",
  /* TLS */
  "Total TLS handshakes attempted",
  "Failed TLS handshakes",
  "TLS session resumption count",
  "TLS certificate verification failures",
  "TLS renegotiation attempts (blocked)",
  /* DNS */
  "Total DNS queries submitted",
  "Failed DNS queries",
  "DNS queries that timed out",
  "DNS queries cancelled",
  "DNS cache hits",
  "DNS cache misses",
  /* Socket */
  "Total sockets created",
  "Total sockets closed",
  "Successful socket connect operations",
  "Failed socket connect operations",
  "Total socket accept operations",
  /* Poll */
  "Poll/epoll wakeup count",
  "Events dispatched from poll",
  "Poll timeout expirations",
  /* Resource Limits */
  "HTTP header size limit exceeded",
  "HTTP body size limit exceeded",
  "HTTP response size limit exceeded",
  "Global memory limit exceeded",
  "Maximum connections limit exceeded",
  "HTTP/2 max streams limit exceeded",
  "HTTP/2 header list size limit exceeded"
};

static const char *const gauge_names[SOCKET_GAUGE_METRIC_COUNT] = {
  /* Pool */
  "pool_active_connections",
  "pool_idle_connections",
  "pool_pending_connections",
  "pool_size",
  /* HTTP Client */
  "http_client_active_requests",
  "http_client_open_connections",
  /* HTTP Server */
  "http_server_active_connections",
  "http_server_active_requests",
  "http_server_queued_requests",
  /* TLS */
  "tls_active_sessions",
  "tls_cached_sessions",
  /* DNS */
  "dns_pending_queries",
  "dns_worker_threads",
  "dns_cache_size",
  /* Socket */
  "socket_open_fds",
  /* Poll */
  "poll_registered_fds",
  "poll_active_timers"
};

static const char *const gauge_help[SOCKET_GAUGE_METRIC_COUNT] = {
  /* Pool */
  "Currently active connections in pool",
  "Currently idle connections in pool",
  "Pending connection attempts",
  "Current pool capacity",
  /* HTTP Client */
  "In-flight HTTP requests",
  "Open HTTP client connections",
  /* HTTP Server */
  "Active HTTP server connections",
  "In-flight server requests",
  "Requests waiting in queue",
  /* TLS */
  "Active TLS sessions",
  "Cached TLS session tickets",
  /* DNS */
  "Pending DNS queries",
  "Active DNS worker threads",
  "DNS cache entry count",
  /* Socket */
  "Open file descriptors",
  /* Poll */
  "File descriptors registered with poll",
  "Active timers"
};

static const char *const histogram_names[SOCKET_HISTOGRAM_METRIC_COUNT] = {
  /* Pool */
  "pool_acquire_time_ms",
  "pool_connection_age_ms",
  "pool_idle_time_ms",
  /* HTTP Client */
  "http_client_request_latency_ms",
  "http_client_connect_time_ms",
  "http_client_ttfb_ms",
  "http_client_response_size",
  /* HTTP Server */
  "http_server_request_latency_ms",
  "http_server_response_size",
  "http_server_request_size",
  /* TLS */
  "tls_handshake_time_ms",
  /* DNS */
  "dns_query_time_ms",
  /* Socket */
  "socket_connect_time_ms"
};

static const char *const histogram_help[SOCKET_HISTOGRAM_METRIC_COUNT] = {
  /* Pool */
  "Time to acquire connection from pool (ms)",
  "Connection age at close (ms)",
  "Time connection was idle (ms)",
  /* HTTP Client */
  "HTTP request total latency (ms)",
  "HTTP connection establishment time (ms)",
  "HTTP time to first byte (ms)",
  "HTTP response body size (bytes)",
  /* HTTP Server */
  "HTTP request processing time (ms)",
  "HTTP response body size (bytes)",
  "HTTP request body size (bytes)",
  /* TLS */
  "TLS handshake duration (ms)",
  /* DNS */
  "DNS query duration (ms)",
  /* Socket */
  "Socket connect duration (ms)"
};

static const char *const category_names[SOCKET_METRIC_CAT_COUNT] = {
  "pool",       "http_client", "http_server", "tls",
  "dns",        "socket",      "poll"
};

/* ============================================================================
 * Histogram Validation Helper
 * ============================================================================ */

/**
 * histogram_valid - Check if histogram metric is valid and initialized
 * @metric: Histogram metric to check
 *
 * Returns: 1 if valid, 0 otherwise
 * Thread-safe: Yes (reads atomic/static data only)
 */
static inline int
histogram_valid (SocketHistogramMetric metric)
{
  if (metric < 0 || metric >= SOCKET_HISTOGRAM_METRIC_COUNT)
    return 0;
  return histogram_values[metric].initialized;
}

/* ============================================================================
 * Percentile Calculation Helpers
 * ============================================================================ */

/**
 * compare_double - Comparison function for qsort
 * @a: First double pointer
 * @b: Second double pointer
 *
 * Returns: -1, 0, or 1 for ordering
 */
static int
compare_double (const void *a, const void *b)
{
  double da = *(const double *)a;
  double db = *(const double *)b;

  if (da < db)
    return -1;
  if (da > db)
    return 1;
  return 0;
}

/**
 * percentile_from_sorted - Calculate percentile from sorted array
 * @sorted: Sorted array of values
 * @n: Number of elements in array
 * @percentile: Percentile to calculate (0.0 to 100.0)
 *
 * Returns: Interpolated percentile value
 * Thread-safe: Yes (pure function)
 *
 * Uses linear interpolation for accurate percentile calculation.
 */
static double
percentile_from_sorted (const double *sorted, size_t n, double percentile)
{
  double index;
  size_t lower;
  size_t upper;
  double frac;

  assert (sorted != NULL);
  assert (n > 0);

  index = (percentile / 100.0) * (double)(n - 1);
  lower = (size_t)floor (index);
  upper = (size_t)ceil (index);
  frac = index - (double)lower;

  if (lower == upper || upper >= n)
    return sorted[lower];

  return sorted[lower] * (1.0 - frac) + sorted[upper] * frac;
}

/* ============================================================================
 * Histogram Implementation
 * ============================================================================ */

/**
 * histogram_init - Initialize a histogram structure
 * @h: Histogram to initialize
 *
 * Thread-safe: No (called during init only)
 */
static void
histogram_init (Histogram *h)
{
  pthread_mutex_init (&h->mutex, NULL);
  memset (h->values, 0, sizeof (h->values));
  h->write_index = 0;
  atomic_store (&h->count, 0);
  h->sum = 0.0;
  h->min = HUGE_VAL;
  h->max = -HUGE_VAL;
  h->initialized = 1;
}

/**
 * histogram_destroy - Destroy a histogram structure
 * @h: Histogram to destroy
 *
 * Thread-safe: No (called during shutdown only)
 */
static void
histogram_destroy (Histogram *h)
{
  if (h->initialized)
    {
      pthread_mutex_destroy (&h->mutex);
      h->initialized = 0;
    }
}

/**
 * histogram_observe - Record an observation
 * @h: Histogram to update
 * @value: Value to record
 *
 * Thread-safe: Yes (mutex protected)
 */
static void
histogram_observe (Histogram *h, double value)
{
  pthread_mutex_lock (&h->mutex);

  h->values[h->write_index] = value;
  h->write_index = (h->write_index + 1) % SOCKET_METRICS_HISTOGRAM_BUCKETS;
  h->sum += value;

  if (value < h->min)
    h->min = value;
  if (value > h->max)
    h->max = value;

  pthread_mutex_unlock (&h->mutex);

  atomic_fetch_add (&h->count, 1);
}

/**
 * histogram_copy_values - Copy histogram values to buffer
 * @h: Histogram to copy from
 * @dest: Destination buffer (must be SOCKET_METRICS_HISTOGRAM_BUCKETS size)
 * @count: Total observation count
 *
 * Returns: Number of values copied (min of count and bucket size)
 * Thread-safe: Yes (mutex protected)
 */
static size_t
histogram_copy_values (Histogram *h, double *dest, uint64_t count)
{
  size_t n;

  n = count < SOCKET_METRICS_HISTOGRAM_BUCKETS
          ? (size_t)count
          : SOCKET_METRICS_HISTOGRAM_BUCKETS;

  pthread_mutex_lock (&h->mutex);
  memcpy (dest, h->values, n * sizeof (double));
  pthread_mutex_unlock (&h->mutex);

  return n;
}

/**
 * histogram_percentile - Calculate percentile from histogram
 * @h: Histogram to query
 * @percentile: Percentile (0.0 to 100.0)
 *
 * Returns: Percentile value, or 0.0 if no data
 * Thread-safe: Yes (uses internal locking)
 */
static double
histogram_percentile (Histogram *h, double percentile)
{
  uint64_t count;
  size_t n;
  double *sorted;
  double result;

  count = atomic_load (&h->count);
  if (count == 0)
    return 0.0;

  sorted = malloc (SOCKET_METRICS_HISTOGRAM_BUCKETS * sizeof (double));
  if (!sorted)
    return 0.0;

  n = histogram_copy_values (h, sorted, count);
  qsort (sorted, n, sizeof (double), compare_double);
  result = percentile_from_sorted (sorted, n, percentile);

  free (sorted);
  return result;
}

/**
 * histogram_fill_snapshot - Fill snapshot with histogram statistics
 * @h: Histogram to snapshot
 * @snap: Output snapshot structure
 *
 * Thread-safe: Yes (uses internal locking)
 */
static void
histogram_fill_snapshot (Histogram *h, SocketMetrics_HistogramSnapshot *snap)
{
  uint64_t count;
  size_t n;
  double *sorted;

  memset (snap, 0, sizeof (*snap));

  count = atomic_load (&h->count);
  snap->count = count;

  if (count == 0)
    return;

  /* Copy basic stats under lock */
  pthread_mutex_lock (&h->mutex);
  snap->sum = h->sum;
  snap->min = h->min;
  snap->max = h->max;
  pthread_mutex_unlock (&h->mutex);

  snap->mean = snap->sum / (double)count;

  /* Allocate and sort values for percentile calculation */
  sorted = malloc (SOCKET_METRICS_HISTOGRAM_BUCKETS * sizeof (double));
  if (!sorted)
    return;

  n = histogram_copy_values (h, sorted, count);
  qsort (sorted, n, sizeof (double), compare_double);

  /* Calculate all standard percentiles */
  snap->p50 = percentile_from_sorted (sorted, n, PERCENTILE_P50);
  snap->p75 = percentile_from_sorted (sorted, n, PERCENTILE_P75);
  snap->p90 = percentile_from_sorted (sorted, n, PERCENTILE_P90);
  snap->p95 = percentile_from_sorted (sorted, n, PERCENTILE_P95);
  snap->p99 = percentile_from_sorted (sorted, n, PERCENTILE_P99);
  snap->p999 = percentile_from_sorted (sorted, n, PERCENTILE_P999);

  free (sorted);
}

/**
 * histogram_reset - Reset histogram to initial state
 * @h: Histogram to reset
 *
 * Thread-safe: Yes (mutex protected)
 */
static void
histogram_reset (Histogram *h)
{
  pthread_mutex_lock (&h->mutex);
  memset (h->values, 0, sizeof (h->values));
  h->write_index = 0;
  h->sum = 0.0;
  h->min = HUGE_VAL;
  h->max = -HUGE_VAL;
  pthread_mutex_unlock (&h->mutex);

  atomic_store (&h->count, 0);
}

/* ============================================================================
 * Initialization and Shutdown
 * ============================================================================ */

int
SocketMetrics_init (void)
{
  int expected;
  int i;

  expected = 0;
  if (!atomic_compare_exchange_strong (&metrics_initialized, &expected, 1))
    return 0; /* Already initialized */

  for (i = 0; i < SOCKET_COUNTER_METRIC_COUNT; i++)
    atomic_store (&counter_values[i], 0);

  for (i = 0; i < SOCKET_GAUGE_METRIC_COUNT; i++)
    atomic_store (&gauge_values[i], 0);

  for (i = 0; i < SOCKET_HISTOGRAM_METRIC_COUNT; i++)
    histogram_init (&histogram_values[i]);

  METRICS_LOG_DEBUG ("Metrics subsystem initialized");
  return 0;
}

void
SocketMetrics_shutdown (void)
{
  int expected;
  int i;

  expected = 1;
  if (!atomic_compare_exchange_strong (&metrics_initialized, &expected, 0))
    return;

  pthread_mutex_lock (&metrics_global_mutex);

  for (i = 0; i < SOCKET_HISTOGRAM_METRIC_COUNT; i++)
    histogram_destroy (&histogram_values[i]);

  pthread_mutex_unlock (&metrics_global_mutex);

  METRICS_LOG_DEBUG ("Metrics subsystem shutdown");
}

/* ============================================================================
 * Counter Operations
 * ============================================================================ */

void
SocketMetrics_counter_inc (SocketCounterMetric metric)
{
  if (metric < 0 || metric >= SOCKET_COUNTER_METRIC_COUNT)
    return;
  atomic_fetch_add (&counter_values[metric], 1);
}

void
SocketMetrics_counter_add (SocketCounterMetric metric, uint64_t value)
{
  if (metric < 0 || metric >= SOCKET_COUNTER_METRIC_COUNT)
    return;
  atomic_fetch_add (&counter_values[metric], value);
}

uint64_t
SocketMetrics_counter_get (SocketCounterMetric metric)
{
  if (metric < 0 || metric >= SOCKET_COUNTER_METRIC_COUNT)
    return 0;
  return atomic_load (&counter_values[metric]);
}

/* ============================================================================
 * Gauge Operations
 * ============================================================================ */

void
SocketMetrics_gauge_set (SocketGaugeMetric metric, int64_t value)
{
  if (metric < 0 || metric >= SOCKET_GAUGE_METRIC_COUNT)
    return;
  atomic_store (&gauge_values[metric], value);
}

void
SocketMetrics_gauge_inc (SocketGaugeMetric metric)
{
  if (metric < 0 || metric >= SOCKET_GAUGE_METRIC_COUNT)
    return;
  atomic_fetch_add (&gauge_values[metric], 1);
}

void
SocketMetrics_gauge_dec (SocketGaugeMetric metric)
{
  if (metric < 0 || metric >= SOCKET_GAUGE_METRIC_COUNT)
    return;
  atomic_fetch_sub (&gauge_values[metric], 1);
}

void
SocketMetrics_gauge_add (SocketGaugeMetric metric, int64_t value)
{
  if (metric < 0 || metric >= SOCKET_GAUGE_METRIC_COUNT)
    return;
  atomic_fetch_add (&gauge_values[metric], value);
}

int64_t
SocketMetrics_gauge_get (SocketGaugeMetric metric)
{
  if (metric < 0 || metric >= SOCKET_GAUGE_METRIC_COUNT)
    return 0;
  return atomic_load (&gauge_values[metric]);
}

/* ============================================================================
 * Histogram Operations
 * ============================================================================ */

void
SocketMetrics_histogram_observe (SocketHistogramMetric metric, double value)
{
  if (!histogram_valid (metric))
    return;
  histogram_observe (&histogram_values[metric], value);
}

double
SocketMetrics_histogram_percentile (SocketHistogramMetric metric,
                                    double percentile)
{
  if (!histogram_valid (metric))
    return 0.0;

  if (percentile < 0.0)
    percentile = 0.0;
  if (percentile > 100.0)
    percentile = 100.0;

  return histogram_percentile (&histogram_values[metric], percentile);
}

uint64_t
SocketMetrics_histogram_count (SocketHistogramMetric metric)
{
  if (metric < 0 || metric >= SOCKET_HISTOGRAM_METRIC_COUNT)
    return 0;
  return atomic_load (&histogram_values[metric].count);
}

double
SocketMetrics_histogram_sum (SocketHistogramMetric metric)
{
  double sum;

  if (!histogram_valid (metric))
    return 0.0;

  pthread_mutex_lock (&histogram_values[metric].mutex);
  sum = histogram_values[metric].sum;
  pthread_mutex_unlock (&histogram_values[metric].mutex);

  return sum;
}

void
SocketMetrics_histogram_snapshot (SocketHistogramMetric metric,
                                  SocketMetrics_HistogramSnapshot *snapshot)
{
  if (!snapshot)
    return;

  if (!histogram_valid (metric))
    {
      memset (snapshot, 0, sizeof (*snapshot));
      return;
    }

  histogram_fill_snapshot (&histogram_values[metric], snapshot);
}

/* ============================================================================
 * Snapshot and Reset
 * ============================================================================ */

void
SocketMetrics_get (SocketMetrics_Snapshot *snapshot)
{
  int i;

  if (!snapshot)
    return;

  memset (snapshot, 0, sizeof (*snapshot));
  snapshot->timestamp_ms = (uint64_t)Socket_get_monotonic_ms ();

  for (i = 0; i < SOCKET_COUNTER_METRIC_COUNT; i++)
    snapshot->counters[i] = atomic_load (&counter_values[i]);

  for (i = 0; i < SOCKET_GAUGE_METRIC_COUNT; i++)
    snapshot->gauges[i] = atomic_load (&gauge_values[i]);

  for (i = 0; i < SOCKET_HISTOGRAM_METRIC_COUNT; i++)
    {
      if (histogram_values[i].initialized)
        histogram_fill_snapshot (&histogram_values[i], &snapshot->histograms[i]);
    }
}

void
SocketMetrics_reset (void)
{
  int i;

  for (i = 0; i < SOCKET_COUNTER_METRIC_COUNT; i++)
    atomic_store (&counter_values[i], 0);

  for (i = 0; i < SOCKET_GAUGE_METRIC_COUNT; i++)
    atomic_store (&gauge_values[i], 0);

  for (i = 0; i < SOCKET_HISTOGRAM_METRIC_COUNT; i++)
    {
      if (histogram_values[i].initialized)
        histogram_reset (&histogram_values[i]);
    }

  METRICS_LOG_DEBUG ("All metrics reset");
}

void
SocketMetrics_reset_counters (void)
{
  int i;

  for (i = 0; i < SOCKET_COUNTER_METRIC_COUNT; i++)
    atomic_store (&counter_values[i], 0);
}

void
SocketMetrics_reset_histograms (void)
{
  int i;

  for (i = 0; i < SOCKET_HISTOGRAM_METRIC_COUNT; i++)
    {
      if (histogram_values[i].initialized)
        histogram_reset (&histogram_values[i]);
    }
}

/* ============================================================================
 * Export Helpers
 * ============================================================================ */

/**
 * export_append - Safely append formatted string to export buffer
 * @buffer: Buffer to write to
 * @buffer_size: Total buffer size
 * @pos: Current position (updated on success)
 * @fmt: Printf format string
 *
 * Returns: Number of characters written, or 0 if buffer full
 */
static size_t
export_append (char *buffer, size_t buffer_size, size_t *pos, const char *fmt,
               ...)
{
  va_list args;
  int written;
  size_t remaining;

  if (*pos >= buffer_size)
    return 0;

  remaining = buffer_size - *pos;
  va_start (args, fmt);
  written = vsnprintf (buffer + *pos, remaining, fmt, args);
  va_end (args);

  if (written < 0)
    return 0;

  if ((size_t)written >= remaining)
    {
      *pos = buffer_size;
      return 0;
    }

  *pos += (size_t)written;
  return (size_t)written;
}

/**
 * export_counter_prometheus - Export single counter in Prometheus format
 */
static void
export_counter_prometheus (char *buffer, size_t buffer_size, size_t *pos,
                           int idx, uint64_t value)
{
  export_append (buffer, buffer_size, pos, "# HELP socket_%s %s\n",
                 counter_names[idx], counter_help[idx]);
  export_append (buffer, buffer_size, pos, "# TYPE socket_%s counter\n",
                 counter_names[idx]);
  export_append (buffer, buffer_size, pos, "socket_%s %llu\n",
                 counter_names[idx], (unsigned long long)value);
}

/**
 * export_gauge_prometheus - Export single gauge in Prometheus format
 */
static void
export_gauge_prometheus (char *buffer, size_t buffer_size, size_t *pos,
                         int idx, int64_t value)
{
  export_append (buffer, buffer_size, pos, "# HELP socket_%s %s\n",
                 gauge_names[idx], gauge_help[idx]);
  export_append (buffer, buffer_size, pos, "# TYPE socket_%s gauge\n",
                 gauge_names[idx]);
  export_append (buffer, buffer_size, pos, "socket_%s %lld\n", gauge_names[idx],
                 (long long)value);
}

/**
 * export_histogram_prometheus - Export single histogram in Prometheus format
 */
static void
export_histogram_prometheus (char *buffer, size_t buffer_size, size_t *pos,
                             int idx,
                             const SocketMetrics_HistogramSnapshot *h)
{
  export_append (buffer, buffer_size, pos, "# HELP socket_%s %s\n",
                 histogram_names[idx], histogram_help[idx]);
  export_append (buffer, buffer_size, pos, "# TYPE socket_%s summary\n",
                 histogram_names[idx]);

  if (h->count > 0)
    {
      export_append (buffer, buffer_size, pos,
                     "socket_%s{quantile=\"0.5\"} %.3f\n", histogram_names[idx],
                     h->p50);
      export_append (buffer, buffer_size, pos,
                     "socket_%s{quantile=\"0.9\"} %.3f\n", histogram_names[idx],
                     h->p90);
      export_append (buffer, buffer_size, pos,
                     "socket_%s{quantile=\"0.95\"} %.3f\n", histogram_names[idx],
                     h->p95);
      export_append (buffer, buffer_size, pos,
                     "socket_%s{quantile=\"0.99\"} %.3f\n", histogram_names[idx],
                     h->p99);
      export_append (buffer, buffer_size, pos,
                     "socket_%s{quantile=\"0.999\"} %.3f\n",
                     histogram_names[idx], h->p999);
    }

  export_append (buffer, buffer_size, pos, "socket_%s_sum %.3f\n",
                 histogram_names[idx], h->sum);
  export_append (buffer, buffer_size, pos, "socket_%s_count %llu\n",
                 histogram_names[idx], (unsigned long long)h->count);
}

/* ============================================================================
 * Export Functions
 * ============================================================================ */

size_t
SocketMetrics_export_prometheus (char *buffer, size_t buffer_size)
{
  size_t pos = 0;
  int i;
  SocketMetrics_Snapshot snapshot;

  if (!buffer || buffer_size == 0)
    return 0;

  buffer[0] = '\0';
  SocketMetrics_get (&snapshot);

  for (i = 0; i < SOCKET_COUNTER_METRIC_COUNT; i++)
    export_counter_prometheus (buffer, buffer_size, &pos, i,
                               snapshot.counters[i]);

  for (i = 0; i < SOCKET_GAUGE_METRIC_COUNT; i++)
    export_gauge_prometheus (buffer, buffer_size, &pos, i, snapshot.gauges[i]);

  for (i = 0; i < SOCKET_HISTOGRAM_METRIC_COUNT; i++)
    export_histogram_prometheus (buffer, buffer_size, &pos, i,
                                 &snapshot.histograms[i]);

  return pos;
}

size_t
SocketMetrics_export_statsd (char *buffer, size_t buffer_size,
                             const char *prefix)
{
  size_t pos = 0;
  int i;
  const char *pfx;
  SocketMetrics_Snapshot snapshot;

  if (!buffer || buffer_size == 0)
    return 0;

  buffer[0] = '\0';
  pfx = prefix ? prefix : "socket";
  SocketMetrics_get (&snapshot);

  for (i = 0; i < SOCKET_COUNTER_METRIC_COUNT; i++)
    {
      export_append (buffer, buffer_size, &pos, "%s.%s:%llu|c\n", pfx,
                     counter_names[i], (unsigned long long)snapshot.counters[i]);
    }

  for (i = 0; i < SOCKET_GAUGE_METRIC_COUNT; i++)
    {
      export_append (buffer, buffer_size, &pos, "%s.%s:%lld|g\n", pfx,
                     gauge_names[i], (long long)snapshot.gauges[i]);
    }

  for (i = 0; i < SOCKET_HISTOGRAM_METRIC_COUNT; i++)
    {
      const SocketMetrics_HistogramSnapshot *h = &snapshot.histograms[i];

      if (h->count > 0)
        {
          export_append (buffer, buffer_size, &pos, "%s.%s.p50:%.3f|g\n", pfx,
                         histogram_names[i], h->p50);
          export_append (buffer, buffer_size, &pos, "%s.%s.p95:%.3f|g\n", pfx,
                         histogram_names[i], h->p95);
          export_append (buffer, buffer_size, &pos, "%s.%s.p99:%.3f|g\n", pfx,
                         histogram_names[i], h->p99);
          export_append (buffer, buffer_size, &pos, "%s.%s.count:%llu|c\n", pfx,
                         histogram_names[i], (unsigned long long)h->count);
        }
    }

  return pos;
}

size_t
SocketMetrics_export_json (char *buffer, size_t buffer_size)
{
  size_t pos = 0;
  int i;
  int first;
  SocketMetrics_Snapshot snapshot;

  if (!buffer || buffer_size == 0)
    return 0;

  buffer[0] = '\0';
  SocketMetrics_get (&snapshot);

  export_append (buffer, buffer_size, &pos, "{\n");
  export_append (buffer, buffer_size, &pos, "  \"timestamp_ms\": %llu,\n",
                 (unsigned long long)snapshot.timestamp_ms);

  /* Counters */
  export_append (buffer, buffer_size, &pos, "  \"counters\": {\n");
  first = 1;
  for (i = 0; i < SOCKET_COUNTER_METRIC_COUNT; i++)
    {
      if (!first)
        export_append (buffer, buffer_size, &pos, ",\n");
      first = 0;
      export_append (buffer, buffer_size, &pos, "    \"%s\": %llu",
                     counter_names[i], (unsigned long long)snapshot.counters[i]);
    }
  export_append (buffer, buffer_size, &pos, "\n  },\n");

  /* Gauges */
  export_append (buffer, buffer_size, &pos, "  \"gauges\": {\n");
  first = 1;
  for (i = 0; i < SOCKET_GAUGE_METRIC_COUNT; i++)
    {
      if (!first)
        export_append (buffer, buffer_size, &pos, ",\n");
      first = 0;
      export_append (buffer, buffer_size, &pos, "    \"%s\": %lld",
                     gauge_names[i], (long long)snapshot.gauges[i]);
    }
  export_append (buffer, buffer_size, &pos, "\n  },\n");

  /* Histograms */
  export_append (buffer, buffer_size, &pos, "  \"histograms\": {\n");
  first = 1;
  for (i = 0; i < SOCKET_HISTOGRAM_METRIC_COUNT; i++)
    {
      const SocketMetrics_HistogramSnapshot *h = &snapshot.histograms[i];

      if (!first)
        export_append (buffer, buffer_size, &pos, ",\n");
      first = 0;

      export_append (buffer, buffer_size, &pos, "    \"%s\": {\n",
                     histogram_names[i]);
      export_append (buffer, buffer_size, &pos, "      \"count\": %llu,\n",
                     (unsigned long long)h->count);
      export_append (buffer, buffer_size, &pos, "      \"sum\": %.3f,\n",
                     h->sum);
      export_append (buffer, buffer_size, &pos, "      \"min\": %.3f,\n",
                     h->count > 0 ? h->min : 0.0);
      export_append (buffer, buffer_size, &pos, "      \"max\": %.3f,\n",
                     h->count > 0 ? h->max : 0.0);
      export_append (buffer, buffer_size, &pos, "      \"mean\": %.3f,\n",
                     h->mean);
      export_append (buffer, buffer_size, &pos, "      \"p50\": %.3f,\n",
                     h->p50);
      export_append (buffer, buffer_size, &pos, "      \"p75\": %.3f,\n",
                     h->p75);
      export_append (buffer, buffer_size, &pos, "      \"p90\": %.3f,\n",
                     h->p90);
      export_append (buffer, buffer_size, &pos, "      \"p95\": %.3f,\n",
                     h->p95);
      export_append (buffer, buffer_size, &pos, "      \"p99\": %.3f,\n",
                     h->p99);
      export_append (buffer, buffer_size, &pos, "      \"p999\": %.3f\n",
                     h->p999);
      export_append (buffer, buffer_size, &pos, "    }");
    }
  export_append (buffer, buffer_size, &pos, "\n  }\n");

  export_append (buffer, buffer_size, &pos, "}\n");

  return pos;
}

/* ============================================================================
 * Metric Metadata
 * ============================================================================ */

const char *
SocketMetrics_counter_name (SocketCounterMetric metric)
{
  if (metric < 0 || metric >= SOCKET_COUNTER_METRIC_COUNT)
    return "unknown";
  return counter_names[metric];
}

const char *
SocketMetrics_gauge_name (SocketGaugeMetric metric)
{
  if (metric < 0 || metric >= SOCKET_GAUGE_METRIC_COUNT)
    return "unknown";
  return gauge_names[metric];
}

const char *
SocketMetrics_histogram_name (SocketHistogramMetric metric)
{
  if (metric < 0 || metric >= SOCKET_HISTOGRAM_METRIC_COUNT)
    return "unknown";
  return histogram_names[metric];
}

const char *
SocketMetrics_counter_help (SocketCounterMetric metric)
{
  if (metric < 0 || metric >= SOCKET_COUNTER_METRIC_COUNT)
    return "";
  return counter_help[metric];
}

const char *
SocketMetrics_gauge_help (SocketGaugeMetric metric)
{
  if (metric < 0 || metric >= SOCKET_GAUGE_METRIC_COUNT)
    return "";
  return gauge_help[metric];
}

const char *
SocketMetrics_histogram_help (SocketHistogramMetric metric)
{
  if (metric < 0 || metric >= SOCKET_HISTOGRAM_METRIC_COUNT)
    return "";
  return histogram_help[metric];
}

const char *
SocketMetrics_category_name (SocketMetricCategory category)
{
  if (category < 0 || category >= SOCKET_METRIC_CAT_COUNT)
    return "unknown";
  return category_names[category];
}
