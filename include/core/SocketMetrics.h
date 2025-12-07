#ifndef SOCKETMETRICS_INCLUDED
#define SOCKETMETRICS_INCLUDED

/**
 * SocketMetrics.h - Production-Grade Metrics and Observability
 *
 * Part of the Socket Library
 *
 * This header provides comprehensive metrics collection and export capabilities
 * for production monitoring and observability. It tracks performance metrics
 * across all major subsystems: connection pools, HTTP client/server, TLS, and DNS.
 *
 * FEATURES:
 * - Counter metrics (monotonically increasing values)
 * - Gauge metrics (current value that can go up or down)
 * - Histogram metrics with percentile calculation (p50, p95, p99)
 * - Category-based organization (pool, http_client, http_server, tls, dns)
 * - Thread-safe atomic operations
 * - Multiple export formats (Prometheus, StatsD, JSON)
 *
 * THREAD SAFETY:
 * - All operations are thread-safe using atomic operations or mutex protection
 * - Histogram operations use fine-grained locking for performance
 * - Snapshot operations provide consistent point-in-time views
 *
 * USAGE:
 *   // Record metrics
 *   SocketMetrics_counter_inc(SOCKET_METRIC_HTTP_REQUESTS_TOTAL);
 *   SocketMetrics_gauge_set(SOCKET_METRIC_POOL_ACTIVE_CONNECTIONS, 42);
 *   SocketMetrics_histogram_observe(SOCKET_METRIC_HTTP_REQUEST_LATENCY_MS, 125);
 *
 *   // Export to Prometheus format
 *   char buffer[65536];
 *   size_t len = SocketMetrics_export_prometheus(buffer, sizeof(buffer));
 *
 *   // Get percentiles
 *   double p50 = SocketMetrics_histogram_percentile(
 *                  SOCKET_METRIC_HTTP_REQUEST_LATENCY_MS, 50.0);
 *
 * MEMORY:
 * - Histograms use fixed-size circular buffers (configurable)
 * - No dynamic allocation after initialization
 * - Total memory usage: ~100KB for default configuration
 */

#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * Configuration
 * ============================================================================ */

/**
 * SOCKET_METRICS_HISTOGRAM_BUCKETS - Number of samples in histogram reservoir
 *
 * Higher values give more accurate percentiles but use more memory.
 * Default: 1024 samples per histogram (~8KB per histogram)
 */
#ifndef SOCKET_METRICS_HISTOGRAM_BUCKETS
#define SOCKET_METRICS_HISTOGRAM_BUCKETS 1024
#endif

/**
 * SOCKET_METRICS_EXPORT_BUFFER_SIZE - Default export buffer size
 */
#ifndef SOCKET_METRICS_EXPORT_BUFFER_SIZE
#define SOCKET_METRICS_EXPORT_BUFFER_SIZE 65536
#endif

/**
 * SOCKET_METRICS_MAX_LABEL_LEN - Maximum length for metric labels
 */
#ifndef SOCKET_METRICS_MAX_LABEL_LEN
#define SOCKET_METRICS_MAX_LABEL_LEN 64
#endif

/**
 * SOCKET_METRICS_MAX_HELP_LEN - Maximum length for metric help text
 */
#ifndef SOCKET_METRICS_MAX_HELP_LEN
#define SOCKET_METRICS_MAX_HELP_LEN 256
#endif

/* ============================================================================
 * Metric Type Definitions
 * ============================================================================ */

/**
 * SocketMetricType - Type of metric
 */
typedef enum SocketMetricType
{
  SOCKET_METRIC_TYPE_COUNTER = 0,  /**< Monotonically increasing counter */
  SOCKET_METRIC_TYPE_GAUGE,        /**< Value that can go up or down */
  SOCKET_METRIC_TYPE_HISTOGRAM     /**< Distribution with percentiles */
} SocketMetricType;

/**
 * SocketMetricCategory - Category grouping for metrics
 */
typedef enum SocketMetricCategory
{
  SOCKET_METRIC_CAT_POOL = 0,      /**< Connection pool metrics */
  SOCKET_METRIC_CAT_HTTP_CLIENT,   /**< HTTP client metrics */
  SOCKET_METRIC_CAT_HTTP_SERVER,   /**< HTTP server metrics */
  SOCKET_METRIC_CAT_TLS,           /**< TLS/SSL metrics */
  SOCKET_METRIC_CAT_DNS,           /**< DNS resolution metrics */
  SOCKET_METRIC_CAT_SOCKET,        /**< Core socket metrics */
  SOCKET_METRIC_CAT_POLL,          /**< Poll/event loop metrics */
  SOCKET_METRIC_CAT_COUNT          /**< Number of categories */
} SocketMetricCategory;

/* ============================================================================
 * Counter Metrics (Monotonically Increasing)
 * ============================================================================ */

/**
 * SocketCounterMetric - Counter metric identifiers
 *
 * Counters are monotonically increasing values that track totals.
 * Use SocketMetrics_counter_inc() to increment.
 */
typedef enum SocketCounterMetric
{
  /* Connection Pool Counters */
  SOCKET_CTR_POOL_CONNECTIONS_CREATED = 0,     /**< Total connections created */
  SOCKET_CTR_POOL_CONNECTIONS_DESTROYED,       /**< Total connections destroyed */
  SOCKET_CTR_POOL_CONNECTIONS_FAILED,          /**< Failed connection attempts */
  SOCKET_CTR_POOL_CONNECTIONS_REUSED,          /**< Connections reused from pool */
  SOCKET_CTR_POOL_CONNECTIONS_EVICTED,         /**< Connections evicted (idle/max age) */
  SOCKET_CTR_POOL_DRAIN_STARTED,               /**< Drain operations started */
  SOCKET_CTR_POOL_DRAIN_COMPLETED,             /**< Drain operations completed */

  /* HTTP Client Counters */
  SOCKET_CTR_HTTP_CLIENT_REQUESTS_TOTAL,       /**< Total HTTP requests sent */
  SOCKET_CTR_HTTP_CLIENT_REQUESTS_FAILED,      /**< Failed HTTP requests */
  SOCKET_CTR_HTTP_CLIENT_REQUESTS_TIMEOUT,     /**< Timed out HTTP requests */
  SOCKET_CTR_HTTP_CLIENT_BYTES_SENT,           /**< Total bytes sent */
  SOCKET_CTR_HTTP_CLIENT_BYTES_RECEIVED,       /**< Total bytes received */
  SOCKET_CTR_HTTP_CLIENT_RETRIES,              /**< Request retry count */

  /* HTTP Server Counters */
  SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL,       /**< Total requests received */
  SOCKET_CTR_HTTP_SERVER_REQUESTS_FAILED,      /**< Failed request processing */
  SOCKET_CTR_HTTP_SERVER_BYTES_SENT,           /**< Total bytes sent */
  SOCKET_CTR_HTTP_SERVER_BYTES_RECEIVED,       /**< Total bytes received */
  SOCKET_CTR_HTTP_SERVER_CONNECTIONS_TOTAL,    /**< Total connections accepted */

  /* HTTP Response Status Counters */
  SOCKET_CTR_HTTP_RESPONSES_1XX,               /**< Informational responses */
  SOCKET_CTR_HTTP_RESPONSES_2XX,               /**< Successful responses */
  SOCKET_CTR_HTTP_RESPONSES_3XX,               /**< Redirection responses */
  SOCKET_CTR_HTTP_RESPONSES_4XX,               /**< Client error responses */
  SOCKET_CTR_HTTP_RESPONSES_5XX,               /**< Server error responses */

  /* TLS Counters */
  SOCKET_CTR_TLS_HANDSHAKES_TOTAL,             /**< Total TLS handshakes */
  SOCKET_CTR_TLS_HANDSHAKES_FAILED,            /**< Failed TLS handshakes */
  SOCKET_CTR_TLS_SESSION_REUSE_COUNT,          /**< Session resumption count */
  SOCKET_CTR_TLS_CERT_VERIFY_FAILURES,         /**< Certificate verification failures */
  SOCKET_CTR_TLS_RENEGOTIATIONS,               /**< TLS renegotiations (blocked) */
  SOCKET_CTR_TLS_PINNING_FAILURES,             /**< Certificate pinning violations */
  SOCKET_CTR_TLS_CT_VERIFICATION_FAILURES,     /**< Certificate Transparency failures */
  SOCKET_CTR_TLS_CRL_CHECK_FAILURES,           /**< CRL/OCSP revocation check failures */

  /* DTLS Counters */
  SOCKET_CTR_DTLS_HANDSHAKES_TOTAL,            /**< Total DTLS handshakes */
  SOCKET_CTR_DTLS_HANDSHAKES_FAILED,           /**< Failed DTLS handshakes */
  SOCKET_CTR_DTLS_COOKIES_GENERATED,           /**< DTLS cookies generated */
  SOCKET_CTR_DTLS_COOKIE_VERIFICATION_FAILURES,/**< Invalid DTLS cookies */
  SOCKET_CTR_DTLS_REPLAY_PACKETS_DETECTED,     /**< DTLS replay protection triggers */
  SOCKET_CTR_DTLS_FRAGMENT_FAILURES,           /**< DTLS fragmentation errors */

  /* DNS Counters */
  SOCKET_CTR_DNS_QUERIES_TOTAL,                /**< Total DNS queries */
  SOCKET_CTR_DNS_QUERIES_FAILED,               /**< Failed DNS queries */
  SOCKET_CTR_DNS_QUERIES_TIMEOUT,              /**< Timed out DNS queries */
  SOCKET_CTR_DNS_QUERIES_CANCELLED,            /**< Cancelled DNS queries */
  SOCKET_CTR_DNS_CACHE_HITS,                   /**< DNS cache hits */
  SOCKET_CTR_DNS_CACHE_MISSES,                 /**< DNS cache misses */

  /* Core Socket Counters */
  SOCKET_CTR_SOCKET_CREATED,                   /**< Sockets created */
  SOCKET_CTR_SOCKET_CLOSED,                    /**< Sockets closed */
  SOCKET_CTR_SOCKET_CONNECT_SUCCESS,           /**< Successful connects */
  SOCKET_CTR_SOCKET_CONNECT_FAILED,            /**< Failed connects */
  SOCKET_CTR_SOCKET_ACCEPT_TOTAL,              /**< Total accepts */

  /* Poll Counters */
  SOCKET_CTR_POLL_WAKEUPS,                     /**< Poll wakeup count */
  SOCKET_CTR_POLL_EVENTS_DISPATCHED,           /**< Events dispatched */
  SOCKET_CTR_POLL_TIMEOUT_EXPIRATIONS,         /**< Poll timeout expirations */

  /* Resource Limit Counters */
  SOCKET_CTR_LIMIT_HEADER_SIZE_EXCEEDED,       /**< Header size limit exceeded */
  SOCKET_CTR_LIMIT_BODY_SIZE_EXCEEDED,         /**< Body size limit exceeded */
  SOCKET_CTR_LIMIT_RESPONSE_SIZE_EXCEEDED,     /**< Response size limit exceeded */
  SOCKET_CTR_LIMIT_MEMORY_EXCEEDED,            /**< Global memory limit exceeded */
  SOCKET_CTR_LIMIT_CONNECTIONS_EXCEEDED,       /**< Max connections exceeded */
  SOCKET_CTR_LIMIT_STREAMS_EXCEEDED,           /**< HTTP/2 max streams exceeded */
  SOCKET_CTR_LIMIT_HEADER_LIST_EXCEEDED,       /**< HTTP/2 header list size exceeded */

  /* SYN Flood Protection Counters */
  SOCKET_CTR_SYNPROTECT_ATTEMPTS_TOTAL,        /**< Total SYN/check attempts */
  SOCKET_CTR_SYNPROTECT_ALLOWED,               /**< Allowed connections */
  SOCKET_CTR_SYNPROTECT_THROTTLED,             /**< Throttled connections */
  SOCKET_CTR_SYNPROTECT_CHALLENGED,            /**< Challenged connections */
  SOCKET_CTR_SYNPROTECT_BLOCKED,               /**< Blocked connections */
  SOCKET_CTR_SYNPROTECT_WHITELISTED,           /**< Whitelisted IPs */
  SOCKET_CTR_SYNPROTECT_BLACKLISTED,           /**< Blacklisted IPs */
  SOCKET_CTR_SYNPROTECT_LRU_EVICTIONS,         /**< LRU evictions from IP table */

  SOCKET_COUNTER_METRIC_COUNT                  /**< Number of counter metrics */
} SocketCounterMetric;

/* ============================================================================
 * Gauge Metrics (Current Values)
 * ============================================================================ */

/**
 * SocketGaugeMetric - Gauge metric identifiers
 *
 * Gauges represent current values that can increase or decrease.
 * Use SocketMetrics_gauge_set(), _inc(), _dec() to modify.
 */
typedef enum SocketGaugeMetric
{
  /* Connection Pool Gauges */
  SOCKET_GAU_POOL_ACTIVE_CONNECTIONS = 0,      /**< Currently active connections */
  SOCKET_GAU_POOL_IDLE_CONNECTIONS,            /**< Currently idle connections */
  SOCKET_GAU_POOL_PENDING_CONNECTIONS,         /**< Pending connection attempts */
  SOCKET_GAU_POOL_SIZE,                        /**< Current pool capacity */

  /* HTTP Client Gauges */
  SOCKET_GAU_HTTP_CLIENT_ACTIVE_REQUESTS,      /**< In-flight HTTP requests */
  SOCKET_GAU_HTTP_CLIENT_OPEN_CONNECTIONS,     /**< Open HTTP connections */

  /* HTTP Server Gauges */
  SOCKET_GAU_HTTP_SERVER_ACTIVE_CONNECTIONS,   /**< Active server connections */
  SOCKET_GAU_HTTP_SERVER_ACTIVE_REQUESTS,      /**< In-flight server requests */
  SOCKET_GAU_HTTP_SERVER_QUEUED_REQUESTS,      /**< Requests waiting in queue */

  /* TLS Gauges */
  SOCKET_GAU_TLS_ACTIVE_SESSIONS,              /**< Active TLS sessions */
  SOCKET_GAU_TLS_CACHED_SESSIONS,              /**< Cached session tickets */
  SOCKET_GAU_DTLS_ACTIVE_SESSIONS,             /**< Active DTLS sessions */

  /* DNS Gauges */
  SOCKET_GAU_DNS_PENDING_QUERIES,              /**< Pending DNS queries */
  SOCKET_GAU_DNS_WORKER_THREADS,               /**< Active DNS worker threads */
  SOCKET_GAU_DNS_CACHE_SIZE,                   /**< DNS cache entry count */

  /* Core Socket Gauges */
  SOCKET_GAU_SOCKET_OPEN_FDS,                  /**< Open file descriptors */

  /* Poll Gauges */
  SOCKET_GAU_POLL_REGISTERED_FDS,              /**< FDs registered with poll */
  SOCKET_GAU_POLL_ACTIVE_TIMERS,               /**< Active timers */

  /* SYN Flood Protection Gauges */
  SOCKET_GAU_SYNPROTECT_TRACKED_IPS,           /**< Currently tracked IP entries */
  SOCKET_GAU_SYNPROTECT_BLOCKED_IPS,           /**< Currently blocked IPs */

  SOCKET_GAUGE_METRIC_COUNT                    /**< Number of gauge metrics */
} SocketGaugeMetric;

/* ============================================================================
 * Histogram Metrics (Distributions)
 * ============================================================================ */

/**
 * SocketHistogramMetric - Histogram metric identifiers
 *
 * Histograms track value distributions and support percentile queries.
 * Use SocketMetrics_histogram_observe() to record observations.
 */
typedef enum SocketHistogramMetric
{
  /* Connection Pool Histograms */
  SOCKET_HIST_POOL_ACQUIRE_TIME_MS = 0,        /**< Time to acquire connection */
  SOCKET_HIST_POOL_CONNECTION_AGE_MS,          /**< Connection age at close */
  SOCKET_HIST_POOL_IDLE_TIME_MS,               /**< Time connection was idle */

  /* HTTP Client Histograms */
  SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS,  /**< Request latency (total) */
  SOCKET_HIST_HTTP_CLIENT_CONNECT_TIME_MS,     /**< Connection time */
  SOCKET_HIST_HTTP_CLIENT_TTFB_MS,             /**< Time to first byte */
  SOCKET_HIST_HTTP_CLIENT_RESPONSE_SIZE,       /**< Response body size */

  /* HTTP Server Histograms */
  SOCKET_HIST_HTTP_SERVER_REQUEST_LATENCY_MS,  /**< Request processing time */
  SOCKET_HIST_HTTP_SERVER_RESPONSE_SIZE,       /**< Response body size */
  SOCKET_HIST_HTTP_SERVER_REQUEST_SIZE,        /**< Request body size */

  /* TLS Histograms */
  SOCKET_HIST_TLS_HANDSHAKE_TIME_MS,           /**< TLS handshake duration */
  SOCKET_HIST_DTLS_HANDSHAKE_TIME_MS,          /**< DTLS handshake duration */

  /* DNS Histograms */
  SOCKET_HIST_DNS_QUERY_TIME_MS,               /**< DNS query duration */

  /* Core Socket Histograms */
  SOCKET_HIST_SOCKET_CONNECT_TIME_MS,          /**< Connect duration */

  SOCKET_HISTOGRAM_METRIC_COUNT                /**< Number of histogram metrics */
} SocketHistogramMetric;

/* ============================================================================
 * Snapshot Structures
 * ============================================================================ */

/**
 * SocketMetrics_HistogramSnapshot - Point-in-time histogram snapshot
 *
 * Contains pre-calculated percentiles and statistics.
 */
typedef struct SocketMetrics_HistogramSnapshot
{
  uint64_t count;          /**< Total observations */
  double sum;              /**< Sum of all observations */
  double min;              /**< Minimum observed value */
  double max;              /**< Maximum observed value */
  double mean;             /**< Mean value */
  double p50;              /**< 50th percentile (median) */
  double p75;              /**< 75th percentile */
  double p90;              /**< 90th percentile */
  double p95;              /**< 95th percentile */
  double p99;              /**< 99th percentile */
  double p999;             /**< 99.9th percentile */
} SocketMetrics_HistogramSnapshot;

/**
 * SocketMetrics_Snapshot - Complete metrics snapshot
 *
 * Point-in-time snapshot of all metrics for consistent export.
 */
typedef struct SocketMetrics_Snapshot
{
  uint64_t timestamp_ms;                                        /**< Snapshot time */
  uint64_t counters[SOCKET_COUNTER_METRIC_COUNT];               /**< Counter values */
  int64_t gauges[SOCKET_GAUGE_METRIC_COUNT];                    /**< Gauge values */
  SocketMetrics_HistogramSnapshot histograms[SOCKET_HISTOGRAM_METRIC_COUNT];
} SocketMetrics_Snapshot;

/* ============================================================================
 * Initialization and Shutdown
 * ============================================================================ */

/**
 * SocketMetrics_init - Initialize metrics subsystem
 *
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Yes (idempotent, can be called multiple times)
 *
 * Must be called before using any metrics functions.
 * Called automatically by library initialization.
 */
extern int SocketMetrics_init (void);

/**
 * SocketMetrics_shutdown - Shutdown metrics subsystem
 *
 * Thread-safe: Yes (idempotent)
 *
 * Releases resources. Safe to call multiple times.
 */
extern void SocketMetrics_shutdown (void);

/* ============================================================================
 * Counter Operations
 * ============================================================================ */

/**
 * SocketMetrics_counter_inc - Increment counter by 1
 * @metric: Counter metric to increment
 *
 * Thread-safe: Yes (atomic operation)
 */
extern void SocketMetrics_counter_inc (SocketCounterMetric metric);

/**
 * SocketMetrics_counter_add - Add value to counter
 * @metric: Counter metric to modify
 * @value: Value to add (must be positive)
 *
 * Thread-safe: Yes (atomic operation)
 */
extern void SocketMetrics_counter_add (SocketCounterMetric metric, uint64_t value);

/**
 * SocketMetrics_counter_get - Get current counter value
 * @metric: Counter metric to read
 *
 * Returns: Current counter value
 * Thread-safe: Yes (atomic read)
 */
extern uint64_t SocketMetrics_counter_get (SocketCounterMetric metric);

/* ============================================================================
 * Gauge Operations
 * ============================================================================ */

/**
 * SocketMetrics_gauge_set - Set gauge to specific value
 * @metric: Gauge metric to set
 * @value: New value
 *
 * Thread-safe: Yes (atomic operation)
 */
extern void SocketMetrics_gauge_set (SocketGaugeMetric metric, int64_t value);

/**
 * SocketMetrics_gauge_inc - Increment gauge by 1
 * @metric: Gauge metric to increment
 *
 * Thread-safe: Yes (atomic operation)
 */
extern void SocketMetrics_gauge_inc (SocketGaugeMetric metric);

/**
 * SocketMetrics_gauge_dec - Decrement gauge by 1
 * @metric: Gauge metric to decrement
 *
 * Thread-safe: Yes (atomic operation)
 */
extern void SocketMetrics_gauge_dec (SocketGaugeMetric metric);

/**
 * SocketMetrics_gauge_add - Add value to gauge
 * @metric: Gauge metric to modify
 * @value: Value to add (can be negative)
 *
 * Thread-safe: Yes (atomic operation)
 */
extern void SocketMetrics_gauge_add (SocketGaugeMetric metric, int64_t value);

/**
 * SocketMetrics_gauge_get - Get current gauge value
 * @metric: Gauge metric to read
 *
 * Returns: Current gauge value
 * Thread-safe: Yes (atomic read)
 */
extern int64_t SocketMetrics_gauge_get (SocketGaugeMetric metric);

/* ============================================================================
 * Histogram Operations
 * ============================================================================ */

/**
 * SocketMetrics_histogram_observe - Record observation in histogram
 * @metric: Histogram metric to update
 * @value: Observed value
 *
 * Thread-safe: Yes (mutex protected)
 */
extern void SocketMetrics_histogram_observe (SocketHistogramMetric metric,
                                             double value);

/**
 * SocketMetrics_histogram_percentile - Get percentile from histogram
 * @metric: Histogram metric to query
 * @percentile: Percentile to calculate (0.0 to 100.0)
 *
 * Returns: Percentile value, or 0.0 if no data
 * Thread-safe: Yes (mutex protected)
 *
 * Common percentiles: 50 (median), 75, 90, 95, 99, 99.9
 */
extern double SocketMetrics_histogram_percentile (SocketHistogramMetric metric,
                                                  double percentile);

/**
 * SocketMetrics_histogram_count - Get observation count
 * @metric: Histogram metric to query
 *
 * Returns: Total number of observations
 * Thread-safe: Yes (atomic read)
 */
extern uint64_t SocketMetrics_histogram_count (SocketHistogramMetric metric);

/**
 * SocketMetrics_histogram_sum - Get sum of observations
 * @metric: Histogram metric to query
 *
 * Returns: Sum of all observed values
 * Thread-safe: Yes (mutex protected)
 */
extern double SocketMetrics_histogram_sum (SocketHistogramMetric metric);

/**
 * SocketMetrics_histogram_snapshot - Get histogram snapshot
 * @metric: Histogram metric to snapshot
 * @snapshot: Output structure for snapshot data
 *
 * Thread-safe: Yes (mutex protected)
 *
 * Calculates all statistics and percentiles at snapshot time.
 */
extern void SocketMetrics_histogram_snapshot (
    SocketHistogramMetric metric, SocketMetrics_HistogramSnapshot *snapshot);

/* ============================================================================
 * Snapshot and Reset
 * ============================================================================ */

/**
 * SocketMetrics_get - Get complete metrics snapshot
 * @snapshot: Output structure for all metrics
 *
 * Thread-safe: Yes
 *
 * Captures consistent point-in-time view of all metrics.
 * Equivalent to the required SocketMetrics_get() from TODO.
 */
extern void SocketMetrics_get (SocketMetrics_Snapshot *snapshot);

/**
 * SocketMetrics_reset - Reset all metrics to initial values
 *
 * Thread-safe: Yes
 *
 * Resets all counters to 0, gauges to 0, and clears histogram data.
 * Equivalent to the required SocketMetrics_reset() from TODO.
 */
extern void SocketMetrics_reset (void);

/**
 * SocketMetrics_reset_counters - Reset only counter metrics
 *
 * Thread-safe: Yes
 */
extern void SocketMetrics_reset_counters (void);

/**
 * SocketMetrics_reset_histograms - Reset only histogram metrics
 *
 * Thread-safe: Yes
 */
extern void SocketMetrics_reset_histograms (void);

/* ============================================================================
 * Export Functions
 * ============================================================================ */

/**
 * SocketMetrics_export_prometheus - Export metrics in Prometheus text format
 * @buffer: Output buffer for formatted text
 * @buffer_size: Size of output buffer
 *
 * Returns: Number of bytes written (excluding NUL), or required size if too small
 * Thread-safe: Yes
 *
 * Exports metrics in Prometheus exposition format (text/plain).
 * Format: https://prometheus.io/docs/instrumenting/exposition_formats/
 *
 * Example output:
 *   # HELP socket_pool_connections_created Total connections created
 *   # TYPE socket_pool_connections_created counter
 *   socket_pool_connections_created 1234
 */
extern size_t SocketMetrics_export_prometheus (char *buffer, size_t buffer_size);

/**
 * SocketMetrics_export_statsd - Export metrics in StatsD format
 * @buffer: Output buffer for formatted text
 * @buffer_size: Size of output buffer
 * @prefix: Metric name prefix (e.g., "myapp.socket") or NULL
 *
 * Returns: Number of bytes written (excluding NUL), or required size if too small
 * Thread-safe: Yes
 *
 * Exports metrics in StatsD line format.
 * Format: https://github.com/statsd/statsd/blob/master/docs/metric_types.md
 *
 * Example output:
 *   myapp.socket.pool.connections_created:1234|c
 *   myapp.socket.pool.active_connections:42|g
 */
extern size_t SocketMetrics_export_statsd (char *buffer, size_t buffer_size,
                                           const char *prefix);

/**
 * SocketMetrics_export_json - Export metrics in JSON format
 * @buffer: Output buffer for formatted text
 * @buffer_size: Size of output buffer
 *
 * Returns: Number of bytes written (excluding NUL), or required size if too small
 * Thread-safe: Yes
 *
 * Exports metrics as JSON object.
 *
 * Example output:
 *   {
 *     "timestamp_ms": 1699876543210,
 *     "counters": {
 *       "pool_connections_created": 1234,
 *       ...
 *     },
 *     "gauges": {
 *       "pool_active_connections": 42,
 *       ...
 *     },
 *     "histograms": {
 *       "http_client_request_latency_ms": {
 *         "count": 1000,
 *         "sum": 125000.0,
 *         "p50": 100.0,
 *         "p95": 250.0,
 *         "p99": 500.0
 *       },
 *       ...
 *     }
 *   }
 */
extern size_t SocketMetrics_export_json (char *buffer, size_t buffer_size);

/* ============================================================================
 * Metric Metadata
 * ============================================================================ */

/**
 * SocketMetrics_counter_name - Get counter metric name
 * @metric: Counter metric
 *
 * Returns: Static string with metric name (snake_case)
 * Thread-safe: Yes
 */
extern const char *SocketMetrics_counter_name (SocketCounterMetric metric);

/**
 * SocketMetrics_gauge_name - Get gauge metric name
 * @metric: Gauge metric
 *
 * Returns: Static string with metric name (snake_case)
 * Thread-safe: Yes
 */
extern const char *SocketMetrics_gauge_name (SocketGaugeMetric metric);

/**
 * SocketMetrics_histogram_name - Get histogram metric name
 * @metric: Histogram metric
 *
 * Returns: Static string with metric name (snake_case)
 * Thread-safe: Yes
 */
extern const char *SocketMetrics_histogram_name (SocketHistogramMetric metric);

/**
 * SocketMetrics_counter_help - Get counter metric help text
 * @metric: Counter metric
 *
 * Returns: Static string with help text
 * Thread-safe: Yes
 */
extern const char *SocketMetrics_counter_help (SocketCounterMetric metric);

/**
 * SocketMetrics_gauge_help - Get gauge metric help text
 * @metric: Gauge metric
 *
 * Returns: Static string with help text
 * Thread-safe: Yes
 */
extern const char *SocketMetrics_gauge_help (SocketGaugeMetric metric);

/**
 * SocketMetrics_histogram_help - Get histogram metric help text
 * @metric: Histogram metric
 *
 * Returns: Static string with help text
 * Thread-safe: Yes
 */
extern const char *SocketMetrics_histogram_help (SocketHistogramMetric metric);

/**
 * SocketMetrics_category_name - Get category name
 * @category: Metric category
 *
 * Returns: Static string with category name
 * Thread-safe: Yes
 */
extern const char *SocketMetrics_category_name (SocketMetricCategory category);

/* ============================================================================
 * Convenience Macros
 * ============================================================================ */

/**
 * SOCKET_METRICS_TIME_START - Start timing an operation
 */
#define SOCKET_METRICS_TIME_START()                                            \
  int64_t _socket_metrics_start_time = Socket_get_monotonic_ms ()

/**
 * SOCKET_METRICS_TIME_OBSERVE - Record elapsed time to histogram
 * @metric: Histogram metric to record to
 */
#define SOCKET_METRICS_TIME_OBSERVE(metric)                                    \
  do                                                                           \
    {                                                                          \
      int64_t _elapsed = Socket_get_monotonic_ms () - _socket_metrics_start_time; \
      SocketMetrics_histogram_observe ((metric), (double)_elapsed);            \
    }                                                                          \
  while (0)

/**
 * SOCKET_METRICS_HTTP_RESPONSE_CLASS - Record HTTP response by status class
 * @status: HTTP status code (100-599)
 */
#define SOCKET_METRICS_HTTP_RESPONSE_CLASS(status)                             \
  do                                                                           \
    {                                                                          \
      int _class = (status) / 100;                                             \
      switch (_class)                                                          \
        {                                                                      \
        case 1:                                                                \
          SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_1XX);           \
          break;                                                               \
        case 2:                                                                \
          SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_2XX);           \
          break;                                                               \
        case 3:                                                                \
          SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_3XX);           \
          break;                                                               \
        case 4:                                                                \
          SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_4XX);           \
          break;                                                               \
        case 5:                                                                \
          SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_5XX);           \
          break;                                                               \
        }                                                                      \
    }                                                                          \
  while (0)

#endif /* SOCKETMETRICS_INCLUDED */
