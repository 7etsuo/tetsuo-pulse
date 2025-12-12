/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#ifndef SOCKETMETRICS_INCLUDED
#define SOCKETMETRICS_INCLUDED

/**
 * @defgroup utilities Utilities
 * @brief Helper modules for rate limiting, retry logic, and metrics
 *
 * The utilities group provides cross-cutting concerns like metrics collection,
 * rate limiting, retry policies, and performance monitoring. These modules
 * integrate seamlessly with core I/O and higher-level protocols.
 *
 * ## Architecture Overview
 *
 * ```
 * ┌───────────────────────────────────────────────────────────┐
 * │                    Application Layer                      │
 * │  HTTP Servers, TCP Services, Connection Pools, etc.       │
 * └─────────────────────┬─────────────────────────────────────┘
 *                       │ Uses
 * ┌─────────────────────▼─────────────────────────────────────┐
 * │                 Utilities Layer                           │
 * │  SocketMetrics, SocketRateLimit, SocketRetry, etc.        │
 * └─────────────────────┬─────────────────────────────────────┘
 *                       │ Uses
 * ┌─────────────────────▼─────────────────────────────────────┐
 * │              Foundation Layer                             │
 * │  Arena, Except, SocketUtil (legacy compat)                │
 * └───────────────────────────────────────────────────────────┘
 * ```
 *
 * ## Module Relationships
 *
 * - **Depends on**: Foundation modules for atomic ops and logging
 * - **Used by**: Connection Mgmt, HTTP, Security, Event System
 * - **Backward Compatibility**: Legacy metrics in SocketUtil.h map to new
 * system
 * - **Integration**: Export metrics to Prometheus/StatsD for observability
 *
 * @{
 */

/**
 * @file SocketMetrics.h
 * @ingroup utilities
 * @brief Production-grade metrics collection and observability for monitoring.
 *
 * This header provides comprehensive metrics collection and export
 * capabilities for production monitoring and observability. It tracks
 * performance metrics across all major subsystems: connection pools, HTTP
 * client/server, TLS, and DNS.
 *
 * Features:
 * - Counter metrics (monotonically increasing values)
 * - Gauge metrics (current value that can go up or down)
 * - Histogram metrics with percentile calculation (p50, p95, p99)
 * - Category-based organization (pool, http_client, http_server, tls, dns)
 * - Thread-safe atomic operations
 * - Multiple export formats (Prometheus, StatsD, JSON)
 *
 * Thread Safety:
 * - All operations are thread-safe using atomic operations or mutex protection
 * - Histogram operations use fine-grained locking for performance
 * - Snapshot operations provide consistent point-in-time views
 *
 * Memory:
 * - Histograms use fixed-size circular buffers (configurable)
 * - No dynamic allocation after initialization
 * - Total memory usage: ~100KB for default configuration
 *
 * ## Usage Example
 *
 * @code{.c}
 * // Initialize (optional, auto-called by library)
 * SocketMetrics_init();
 *
 * // Record a counter event
 * SocketMetrics_counter_inc(SOCKET_CTR_HTTP_CLIENT_REQUESTS_TOTAL);
 *
 * // Update gauge for current state
 * SocketMetrics_gauge_set(SOCKET_GAU_HTTP_CLIENT_ACTIVE_REQUESTS, 5);
 *
 * // Time an operation with macro convenience
 * SOCKET_METRICS_TIME_START();
 * // ... perform HTTP request ...
 * SOCKET_METRICS_TIME_OBSERVE(SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS);
 *
 * // Export for monitoring system
 * char buffer[65536];
 * size_t len = SocketMetrics_export_prometheus(buffer, sizeof(buffer));
 * // Send buffer to Prometheus scraper or log file
 *
 * // Cleanup at shutdown
 * SocketMetrics_shutdown();
 * @endcode
 *
 * ## Export Formats
 *
 * ### Prometheus Text Format
 *
 * Standard exposition format with # HELP and # TYPE headers.
 *
 * Example:
 * @code
 * # HELP socket_pool_connections_created Total connections created
 * # TYPE socket_pool_connections_created counter
 * socket_pool_connections_created 1234
 * # HELP socket_http_client_request_latency_ms HTTP client request latency in
 * ms # TYPE socket_http_client_request_latency_ms histogram
 * socket_http_client_request_latency_ms_sum 125000
 * socket_http_client_request_latency_ms_count 1000
 * socket_http_client_request_latency_ms{quantile="0.5"} 100
 * socket_http_client_request_latency_ms{quantile="0.95"} 250
 * @endcode
 *
 * ### StatsD Line Format
 *
 * UDP-friendly lines for StatsD aggregation.
 *
 * Example:
 * @code
 * myapp.socket.pool.connections_created:1234|c
 * myapp.socket.http_client.active_requests:5|g
 * myapp.socket.http_client.request_latency_ms:125|ms|@0.95
 * @endcode
 *
 * ### JSON Structured Format
 *
 * For API endpoints or structured logging.
 *
 * Example snippet:
 * @code{.json}
 * {
 *   "timestamp_ms": 1699876543210,
 *   "counters": { "pool_connections_created": 1234 },
 *   "gauges": { "pool_active_connections": 42 },
 *   "histograms": {
 *     "http_client_request_latency_ms": {
 *       "count": 1000, "sum": 125000.0, "p50": 100.0, "p95": 250.0
 *     }
 *   }
 * }
 * @endcode
 *
 * @note Metrics are designed for high-performance; counters/gauges are
 * lock-free.
 * @warning Large histograms (high SOCKET_METRICS_HISTOGRAM_BUCKETS) increase
 * memory and percentile calc time.
 * @complexity
 * - Counter/Gauge ops: O(1) atomic
 * - Histogram observe: O(1) amortized reservoir sampling
 * - Percentile query: O(n log n) sort where n=1024 buckets
 * - Full snapshot/export: O(total metrics count) ≈ O(200)
 *
 * @see SocketMetrics_counter_inc() for counters
 * @see SocketMetrics_gauge_set() for gauges
 * @see SocketMetrics_histogram_observe() for distributions
 * @see SocketMetrics_export_prometheus() for Prometheus integration
 * @see docs/METRICS.md for detailed guide and migration from legacy system
 * @see SocketUtil.h for backward-compatible SocketMetrics_increment()
 */

#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * Configuration
 * ============================================================================
 */

/**
 * @brief SOCKET_METRICS_HISTOGRAM_BUCKETS - Number of samples in histogram
 * reservoir
 * @ingroup utilities
 *
 * Higher values give more accurate percentiles but use more memory.
 * Default: 1024 samples per histogram (~8KB per histogram)
 */
#ifndef SOCKET_METRICS_HISTOGRAM_BUCKETS
#define SOCKET_METRICS_HISTOGRAM_BUCKETS 1024
#endif

/**
 * @brief SOCKET_METRICS_EXPORT_BUFFER_SIZE - Default export buffer size
 * @ingroup utilities
 */
#ifndef SOCKET_METRICS_EXPORT_BUFFER_SIZE
#define SOCKET_METRICS_EXPORT_BUFFER_SIZE 65536
#endif

/**
 * @brief SOCKET_METRICS_MAX_LABEL_LEN - Maximum length for metric labels
 * @ingroup utilities
 */
#ifndef SOCKET_METRICS_MAX_LABEL_LEN
#define SOCKET_METRICS_MAX_LABEL_LEN 64
#endif

/**
 * @brief SOCKET_METRICS_MAX_HELP_LEN - Maximum length for metric help text
 * @ingroup utilities
 */
#ifndef SOCKET_METRICS_MAX_HELP_LEN
#define SOCKET_METRICS_MAX_HELP_LEN 256
#endif

/* ============================================================================
 * Metric Type Definitions
 * ============================================================================
 */

/**
 * @brief Metric type enumeration defining the three supported metric kinds.
 * @ingroup utilities
 *
 * This enum classifies metrics into counters (cumulative totals that only
 * increase), gauges (current snapshot values that can increase or decrease),
 * and histograms (value distributions for analyzing latencies, sizes, or other
 * variable metrics with percentile calculations like p50, p95, p99).
 *
 * ## Usage Patterns
 *
 * - **Counters**: Use for counting events like requests processed, errors
 * occurred, or bytes transferred. Never decrease.
 *
 * - **Gauges**: Track current state like active connections, queue depth, or
 * memory usage.
 *
 * - **Histograms**: Record observations of variable values (e.g., response
 * times) to compute percentiles for SLO monitoring.
 *
 * ## Metric Types Table
 *
 * | Type       | Purpose                          | Key Operations | StatsD
 * Suffix | Prometheus Type |
 * |------------|----------------------------------|---------------------------------|---------------|-----------------|
 * | COUNTER    | Cumulative event counts          | inc(), add(value) | \|c |
 * counter         | | GAUGE      | Current value snapshots          |
 * set(value), inc(), dec()        | \|g           | gauge           | |
 * HISTOGRAM  | Value distributions & percentiles| observe(value),
 * percentile(p)   | \|ms or \|h   | histogram       |
 *
 * @note Counters wrap around on overflow (uint64_t, ~584 years at 1/sec rate).
 * @warning Gauges should be updated frequently for accurate monitoring.
 * @complexity All type-specific ops are O(1) except histogram percentiles O(n
 * log n).
 *
 * @see SocketMetrics_counter_inc() for counter examples
 * @see SocketMetrics_gauge_set() for gauge examples
 * @see SocketMetrics_histogram_observe() for histogram examples
 * @see docs/METRICS.md#metric-types for best practices
 */
typedef enum SocketMetricType
{
  SOCKET_METRIC_TYPE_COUNTER
  = 0, /**< Monotonically increasing counter for event totals */
  SOCKET_METRIC_TYPE_GAUGE, /**< Gauge for current state values (up or down) */
  SOCKET_METRIC_TYPE_HISTOGRAM /**< Histogram for distributions with
                                  percentiles */
} SocketMetricType;

/**
 * @brief Category enumeration for logical grouping of metrics by subsystem.
 * @ingroup utilities
 *
 * Metrics are organized into categories corresponding to major library
 * modules. This enables filtered querying, namespacing in exports (e.g.,
 * "socket_pool_*" prefix in Prometheus), and targeted alerting/dashboards.
 *
 * Categories are used internally for metric naming and documentation but
 * exposed via SocketMetrics_category_name() for dynamic tools.
 *
 * ## Categories Overview Table
 *
 * | Category       | Subsystem              | Purpose | Example Metrics |
 * |----------------|------------------------|----------------------------------------------|------------------------------------------|
 * | POOL           | Connection Pooling     | Track pool health, efficiency,
 * and lifecycle | connections_active, acquire_time_ms      | | HTTP_CLIENT |
 * HTTP Client            | Monitor outbound requests and performance    |
 * requests_total, latency_ms, bytes_sent   | | HTTP_SERVER    | HTTP Server |
 * Server request handling and throughput       | requests_total,
 * response_size, errors    | | TLS            | TLS/SSL Security       |
 * Handshake success, verification, sessions    | handshakes_total,
 * cert_failures          | | DNS            | DNS Resolution         | Query
 * performance and cache effectiveness    | queries_total, cache_hits,
 * query_time_ms | | SOCKET         | Core Socket I/O        | Basic socket
 * creation, connect/accept stats  | connect_success, accept_total            |
 * | POLL           | Event Loop             | Polling efficiency and event
 * processing      | wakeups, events_dispatched               |
 *
 * ## Best Practices
 *
 * - **Alerting**: Set alerts per category (e.g., high TLS failures → security
 * issue)
 * - **Dashboards**: Group by category for subsystem-specific views
 * - **Export Prefix**: Categories form base names in exports (e.g., "pool_"
 * prefix)
 *
 * @note SOCKET_METRIC_CAT_COUNT is sentinel, not a real category.
 * @threadsafe Yes - enum values are constants
 *
 * @see SocketMetrics_category_name() to retrieve string representation
 * @see docs/METRICS.md#categories for dashboard examples
 */
typedef enum SocketMetricCategory
{
  SOCKET_METRIC_CAT_POOL
  = 0, /**< Connection pool metrics: lifecycle, health, efficiency */
  SOCKET_METRIC_CAT_HTTP_CLIENT, /**< HTTP client metrics: requests, latency,
                                    throughput */
  SOCKET_METRIC_CAT_HTTP_SERVER, /**< HTTP server metrics: requests handled,
                                    errors, bytes */
  SOCKET_METRIC_CAT_TLS, /**< TLS/SSL metrics: handshakes, verification,
                            sessions */
  SOCKET_METRIC_CAT_DNS, /**< DNS resolution metrics: queries, cache, timeouts
                          */
  SOCKET_METRIC_CAT_SOCKET, /**< Core socket metrics: creation, connect, accept
                             */
  SOCKET_METRIC_CAT_POLL,   /**< Poll/event loop metrics: wakeups, events,
                               timeouts */
  SOCKET_METRIC_CAT_COUNT   /**< Sentinel: total number of categories (not for
                               use) */
} SocketMetricCategory;

/* ============================================================================
 * Counter Metrics (Monotonically Increasing)
 * ============================================================================
 */

/**
 * @brief SocketCounterMetric - Counter metric identifiers
 * @ingroup utilities
 *
 * Counters are monotonically increasing values that track totals.
 * Use SocketMetrics_counter_inc() to increment.
 */
typedef enum SocketCounterMetric
{
  /* Connection Pool Counters */
  SOCKET_CTR_POOL_CONNECTIONS_CREATED = 0, /**< Total connections created */
  SOCKET_CTR_POOL_CONNECTIONS_DESTROYED,   /**< Total connections destroyed */
  SOCKET_CTR_POOL_CONNECTIONS_FAILED,      /**< Failed connection attempts */
  SOCKET_CTR_POOL_CONNECTIONS_REUSED,      /**< Connections reused from pool */
  SOCKET_CTR_POOL_CONNECTIONS_EVICTED, /**< Connections evicted (idle/max age)
                                        */
  SOCKET_CTR_POOL_DRAIN_STARTED,       /**< Drain operations started */
  SOCKET_CTR_POOL_DRAIN_COMPLETED,     /**< Drain operations completed */

  /* HTTP Client Counters */
  SOCKET_CTR_HTTP_CLIENT_REQUESTS_TOTAL,   /**< Total HTTP requests sent */
  SOCKET_CTR_HTTP_CLIENT_REQUESTS_FAILED,  /**< Failed HTTP requests */
  SOCKET_CTR_HTTP_CLIENT_REQUESTS_TIMEOUT, /**< Timed out HTTP requests */
  SOCKET_CTR_HTTP_CLIENT_BYTES_SENT,       /**< Total bytes sent */
  SOCKET_CTR_HTTP_CLIENT_BYTES_RECEIVED,   /**< Total bytes received */
  SOCKET_CTR_HTTP_CLIENT_RETRIES,          /**< Request retry count */

  /* HTTP Server Counters */
  SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL,    /**< Total requests received */
  SOCKET_CTR_HTTP_SERVER_REQUESTS_FAILED,   /**< Failed request processing */
  SOCKET_CTR_HTTP_SERVER_REQUESTS_TIMEOUT,  /**< Requests timed out */
  SOCKET_CTR_HTTP_SERVER_RATE_LIMITED,      /**< Requests rejected by rate limit */
  SOCKET_CTR_HTTP_SERVER_BYTES_SENT,        /**< Total bytes sent */
  SOCKET_CTR_HTTP_SERVER_BYTES_RECEIVED,    /**< Total bytes received */
  SOCKET_CTR_HTTP_SERVER_CONNECTIONS_TOTAL, /**< Total connections accepted */

  /* HTTP Response Status Counters */
  SOCKET_CTR_HTTP_RESPONSES_1XX, /**< Informational responses */
  SOCKET_CTR_HTTP_RESPONSES_2XX, /**< Successful responses */
  SOCKET_CTR_HTTP_RESPONSES_3XX, /**< Redirection responses */
  SOCKET_CTR_HTTP_RESPONSES_4XX, /**< Client error responses */
  SOCKET_CTR_HTTP_RESPONSES_5XX, /**< Server error responses */

  /* TLS Counters */
  SOCKET_CTR_TLS_HANDSHAKES_TOTAL,     /**< Total TLS handshakes */
  SOCKET_CTR_TLS_HANDSHAKES_FAILED,    /**< Failed TLS handshakes */
  SOCKET_CTR_TLS_SESSION_REUSE_COUNT,  /**< Session resumption count */
  SOCKET_CTR_TLS_CERT_VERIFY_FAILURES, /**< Certificate verification failures
                                        */
  SOCKET_CTR_TLS_RENEGOTIATIONS,       /**< TLS renegotiations (blocked) */
  SOCKET_CTR_TLS_PINNING_FAILURES,     /**< Certificate pinning violations */
  SOCKET_CTR_TLS_CT_VERIFICATION_FAILURES, /**< Certificate Transparency
                                              failures */
  SOCKET_CTR_TLS_CRL_CHECK_FAILURES, /**< CRL/OCSP revocation check failures */
  SOCKET_CTR_TLS_EARLY_DATA_SENT,    /**< TLS 1.3 0-RTT early data sent */
  SOCKET_CTR_TLS_EARLY_DATA_RECV,    /**< TLS 1.3 0-RTT early data received */
  SOCKET_CTR_TLS_KEY_UPDATES,        /**< TLS 1.3 KeyUpdate operations */

  /* DTLS Counters */
  SOCKET_CTR_DTLS_HANDSHAKES_TOTAL,    /**< Total DTLS handshakes initiated */
  SOCKET_CTR_DTLS_HANDSHAKES_COMPLETE, /**< Completed DTLS handshakes */
  SOCKET_CTR_DTLS_HANDSHAKES_FAILED,   /**< Failed DTLS handshakes */
  SOCKET_CTR_DTLS_COOKIES_GENERATED,   /**< DTLS cookies generated */
  SOCKET_CTR_DTLS_COOKIES_VERIFIED,    /**< DTLS cookies verified successfully */
  SOCKET_CTR_DTLS_COOKIE_VERIFICATION_FAILURES, /**< Invalid DTLS cookies */
  SOCKET_CTR_DTLS_REPLAY_PACKETS_DETECTED, /**< DTLS replay protection triggers
                                            */
  SOCKET_CTR_DTLS_FRAGMENT_FAILURES,       /**< DTLS fragmentation errors */

  /* DNS Counters */
  SOCKET_CTR_DNS_QUERIES_TOTAL,     /**< Total DNS queries */
  SOCKET_CTR_DNS_QUERIES_FAILED,    /**< Failed DNS queries */
  SOCKET_CTR_DNS_QUERIES_TIMEOUT,   /**< Timed out DNS queries */
  SOCKET_CTR_DNS_QUERIES_CANCELLED, /**< Cancelled DNS queries */
  SOCKET_CTR_DNS_CACHE_HITS,        /**< DNS cache hits */
  SOCKET_CTR_DNS_CACHE_MISSES,      /**< DNS cache misses */

  /* Core Socket Counters */
  SOCKET_CTR_SOCKET_CREATED,         /**< Sockets created */
  SOCKET_CTR_SOCKET_CLOSED,          /**< Sockets closed */
  SOCKET_CTR_SOCKET_CONNECT_SUCCESS, /**< Successful connects */
  SOCKET_CTR_SOCKET_CONNECT_FAILED,  /**< Failed connects */
  SOCKET_CTR_SOCKET_ACCEPT_TOTAL,    /**< Total accepts */

  /* Poll Counters */
  SOCKET_CTR_POLL_WAKEUPS,             /**< Poll wakeup count */
  SOCKET_CTR_POLL_EVENTS_DISPATCHED,   /**< Events dispatched */
  SOCKET_CTR_POLL_TIMEOUT_EXPIRATIONS, /**< Poll timeout expirations */

  /* Resource Limit Counters */
  SOCKET_CTR_LIMIT_HEADER_SIZE_EXCEEDED,   /**< Header size limit exceeded */
  SOCKET_CTR_LIMIT_BODY_SIZE_EXCEEDED,     /**< Body size limit exceeded */
  SOCKET_CTR_LIMIT_RESPONSE_SIZE_EXCEEDED, /**< Response size limit exceeded */
  SOCKET_CTR_LIMIT_MEMORY_EXCEEDED,        /**< Global memory limit exceeded */
  SOCKET_CTR_LIMIT_CONNECTIONS_EXCEEDED,   /**< Max connections exceeded */
  SOCKET_CTR_LIMIT_STREAMS_EXCEEDED,       /**< HTTP/2 max streams exceeded */
  SOCKET_CTR_LIMIT_HEADER_LIST_EXCEEDED, /**< HTTP/2 header list size exceeded
                                          */

  /* SYN Flood Protection Counters */
  SOCKET_CTR_SYNPROTECT_ATTEMPTS_TOTAL, /**< Total SYN/check attempts */
  SOCKET_CTR_SYNPROTECT_ALLOWED,        /**< Allowed connections */
  SOCKET_CTR_SYNPROTECT_THROTTLED,      /**< Throttled connections */
  SOCKET_CTR_SYNPROTECT_CHALLENGED,     /**< Challenged connections */
  SOCKET_CTR_SYNPROTECT_BLOCKED,        /**< Blocked connections */
  SOCKET_CTR_SYNPROTECT_WHITELISTED,    /**< Whitelisted IPs */
  SOCKET_CTR_SYNPROTECT_BLACKLISTED,    /**< Blacklisted IPs */
  SOCKET_CTR_SYNPROTECT_LRU_EVICTIONS,  /**< LRU evictions from IP table */

  SOCKET_COUNTER_METRIC_COUNT /**< Number of counter metrics */
} SocketCounterMetric;

/* ============================================================================
 * Gauge Metrics (Current Values)
 * ============================================================================
 */

/**
 * @brief SocketGaugeMetric - Gauge metric identifiers
 * @ingroup utilities
 *
 * Gauges represent current values that can increase or decrease.
 * Use SocketMetrics_gauge_set(), _inc(), _dec() to modify.
 */
typedef enum SocketGaugeMetric
{
  /* Connection Pool Gauges */
  SOCKET_GAU_POOL_ACTIVE_CONNECTIONS = 0, /**< Currently active connections */
  SOCKET_GAU_POOL_IDLE_CONNECTIONS,       /**< Currently idle connections */
  SOCKET_GAU_POOL_PENDING_CONNECTIONS,    /**< Pending connection attempts */
  SOCKET_GAU_POOL_SIZE,                   /**< Current pool capacity */

  /* HTTP Client Gauges */
  SOCKET_GAU_HTTP_CLIENT_ACTIVE_REQUESTS,  /**< In-flight HTTP requests */
  SOCKET_GAU_HTTP_CLIENT_OPEN_CONNECTIONS, /**< Open HTTP connections */

  /* HTTP Server Gauges */
  SOCKET_GAU_HTTP_SERVER_ACTIVE_CONNECTIONS, /**< Active server connections */
  SOCKET_GAU_HTTP_SERVER_ACTIVE_REQUESTS,    /**< In-flight server requests */
  SOCKET_GAU_HTTP_SERVER_QUEUED_REQUESTS,    /**< Requests waiting in queue */

  /* TLS Gauges */
  SOCKET_GAU_TLS_ACTIVE_SESSIONS,  /**< Active TLS sessions */
  SOCKET_GAU_TLS_CACHED_SESSIONS,  /**< Cached session tickets */
  SOCKET_GAU_DTLS_ACTIVE_SESSIONS, /**< Active DTLS sessions */

  /* DNS Gauges */
  SOCKET_GAU_DNS_PENDING_QUERIES, /**< Pending DNS queries */
  SOCKET_GAU_DNS_WORKER_THREADS,  /**< Active DNS worker threads */
  SOCKET_GAU_DNS_CACHE_SIZE,      /**< DNS cache entry count */

  /* Core Socket Gauges */
  SOCKET_GAU_SOCKET_OPEN_FDS, /**< Open file descriptors */

  /* Poll Gauges */
  SOCKET_GAU_POLL_REGISTERED_FDS, /**< FDs registered with poll */
  SOCKET_GAU_POLL_ACTIVE_TIMERS,  /**< Active timers */

  /* SYN Flood Protection Gauges */
  SOCKET_GAU_SYNPROTECT_TRACKED_IPS, /**< Currently tracked IP entries */
  SOCKET_GAU_SYNPROTECT_BLOCKED_IPS, /**< Currently blocked IPs */

  SOCKET_GAUGE_METRIC_COUNT /**< Number of gauge metrics */
} SocketGaugeMetric;

/* ============================================================================
 * Histogram Metrics (Distributions)
 * ============================================================================
 */

/**
 * @brief SocketHistogramMetric - Histogram metric identifiers
 * @ingroup utilities
 *
 * Histograms track value distributions and support percentile queries.
 * Use SocketMetrics_histogram_observe() to record observations.
 */
typedef enum SocketHistogramMetric
{
  /* Connection Pool Histograms */
  SOCKET_HIST_POOL_ACQUIRE_TIME_MS = 0, /**< Time to acquire connection */
  SOCKET_HIST_POOL_CONNECTION_AGE_MS,   /**< Connection age at close */
  SOCKET_HIST_POOL_IDLE_TIME_MS,        /**< Time connection was idle */

  /* HTTP Client Histograms */
  SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS, /**< Request latency (total) */
  SOCKET_HIST_HTTP_CLIENT_CONNECT_TIME_MS,    /**< Connection time */
  SOCKET_HIST_HTTP_CLIENT_TTFB_MS,            /**< Time to first byte */
  SOCKET_HIST_HTTP_CLIENT_RESPONSE_SIZE,      /**< Response body size */

  /* HTTP Server Histograms */
  SOCKET_HIST_HTTP_SERVER_REQUEST_LATENCY_MS, /**< Request processing time */
  SOCKET_HIST_HTTP_SERVER_RESPONSE_SIZE,      /**< Response body size */
  SOCKET_HIST_HTTP_SERVER_REQUEST_SIZE,       /**< Request body size */

  /* TLS Histograms */
  SOCKET_HIST_TLS_HANDSHAKE_TIME_MS,  /**< TLS handshake duration */
  SOCKET_HIST_DTLS_HANDSHAKE_TIME_MS, /**< DTLS handshake duration */

  /* DNS Histograms */
  SOCKET_HIST_DNS_QUERY_TIME_MS, /**< DNS query duration */

  /* Core Socket Histograms */
  SOCKET_HIST_SOCKET_CONNECT_TIME_MS, /**< Connect duration */

  SOCKET_HISTOGRAM_METRIC_COUNT /**< Number of histogram metrics */
} SocketHistogramMetric;

/* ============================================================================
 * Snapshot Structures
 * ============================================================================
 */

/**
 * @brief Point-in-time snapshot of histogram statistics with percentiles.
 * @ingroup utilities
 * Contains count, sum, min/max, mean, and common percentiles (p50, p95, etc.).
 * @see SocketMetrics_histogram_snapshot() to populate this structure.
 * @see SocketMetrics_Snapshot::histograms for integration in full snapshot.
 */
typedef struct SocketMetrics_HistogramSnapshot
{
  uint64_t count; /**< Total observations */
  double sum;     /**< Sum of all observations */
  double min;     /**< Minimum observed value */
  double max;     /**< Maximum observed value */
  double mean;    /**< Mean value */
  double p50;     /**< 50th percentile (median) */
  double p75;     /**< 75th percentile */
  double p90;     /**< 90th percentile */
  double p95;     /**< 95th percentile */
  double p99;     /**< 99th percentile */
  double p999;    /**< 99.9th percentile */
} SocketMetrics_HistogramSnapshot;

/**
 * @brief Complete point-in-time snapshot of all metrics for export and
 * analysis.
 * @ingroup utilities
 *
 * Aggregates counters, gauges, and histogram snapshots across all categories.
 * Thread-safe capture ensures consistency for observability tools.
 * @see SocketMetrics_get() to populate.
 * @see SocketMetrics_export_prometheus() for Prometheus format export.
 */
typedef struct SocketMetrics_Snapshot
{
  uint64_t timestamp_ms;                          /**< Snapshot time */
  uint64_t counters[SOCKET_COUNTER_METRIC_COUNT]; /**< Counter values */
  int64_t gauges[SOCKET_GAUGE_METRIC_COUNT];      /**< Gauge values */
  SocketMetrics_HistogramSnapshot histograms[SOCKET_HISTOGRAM_METRIC_COUNT];
} SocketMetrics_Snapshot;

/* ============================================================================
 * Initialization and Shutdown
 * ============================================================================
 */

/**
 * @brief Initialize the metrics subsystem.
 * @ingroup utilities
 * @return 0 on success, -1 on failure.
 * @threadsafe Yes - idempotent, can be called multiple times.
 * @note Automatically called by library initialization; explicit call optional
 * for custom setups.
 * @see SocketMetrics_shutdown() for resource cleanup.
 * @see SocketMetrics_get() to capture metrics snapshots.
 */
extern int SocketMetrics_init (void);

/**
 * @brief Shut down the metrics subsystem, releasing all resources.
 * @ingroup utilities
 * @threadsafe Yes - idempotent, safe to call multiple times even if not
 * initialized.
 * @see SocketMetrics_init() for subsystem initialization.
 * @see SocketMetrics_reset() if reset needed before shutdown.
 */
extern void SocketMetrics_shutdown (void);

/* ============================================================================
 * Counter Operations
 * ============================================================================
 */

/**
 * @brief Increment a counter metric by 1 atomically.
 * @ingroup utilities
 * @param metric The counter metric identifier to increment.
 * @threadsafe Yes - uses atomic operations for thread safety.
 * @see SocketMetrics_counter_add() to add arbitrary values.
 * @see SocketMetrics_counter_get() to read the current value.
 * @see SocketCounterMetric for list of counters.
 */
extern void SocketMetrics_counter_inc (SocketCounterMetric metric);

/**
 * @brief Add value to counter
 * @ingroup utilities
 * @param metric Counter metric to modify
 * @param value Value to add (must be positive)
 *
 * @threadsafe Yes (atomic operation)
 */
extern void SocketMetrics_counter_add (SocketCounterMetric metric,
                                       uint64_t value);

/**
 * @brief Get current counter value
 * @ingroup utilities
 * @param metric Counter metric to read
 *
 * @return Current counter value
 * @threadsafe Yes (atomic read)
 */
extern uint64_t SocketMetrics_counter_get (SocketCounterMetric metric);

/* ============================================================================
 * Gauge Operations
 * ============================================================================
 */

/**
 * @brief Set gauge to specific value
 * @ingroup utilities
 * @param metric Gauge metric to set
 * @param value New value
 *
 * @threadsafe Yes (atomic operation)
 */
extern void SocketMetrics_gauge_set (SocketGaugeMetric metric, int64_t value);

/**
 * @brief Increment gauge by 1
 * @ingroup utilities
 * @param metric Gauge metric to increment
 *
 * @threadsafe Yes (atomic operation)
 */
extern void SocketMetrics_gauge_inc (SocketGaugeMetric metric);

/**
 * @brief Decrement gauge by 1
 * @ingroup utilities
 * @param metric Gauge metric to decrement
 *
 * @threadsafe Yes (atomic operation)
 */
extern void SocketMetrics_gauge_dec (SocketGaugeMetric metric);

/**
 * @brief Add value to gauge
 * @ingroup utilities
 * @param metric Gauge metric to modify
 * @param value Value to add (can be negative)
 *
 * @threadsafe Yes (atomic operation)
 */
extern void SocketMetrics_gauge_add (SocketGaugeMetric metric, int64_t value);

/**
 * @brief Get current gauge value
 * @ingroup utilities
 * @param metric Gauge metric to read
 *
 * @return Current gauge value
 * @threadsafe Yes (atomic read)
 */
extern int64_t SocketMetrics_gauge_get (SocketGaugeMetric metric);

/* ============================================================================
 * Histogram Operations
 * ============================================================================
 */

/**
 * @brief Record observation in histogram
 * @ingroup utilities
 * @param metric Histogram metric to update
 * @param value Observed value
 *
 * @threadsafe Yes (mutex protected)
 */
extern void SocketMetrics_histogram_observe (SocketHistogramMetric metric,
                                             double value);

/**
 * @brief Get percentile from histogram
 * @ingroup utilities
 * @param metric Histogram metric to query
 * @param percentile Percentile to calculate (0.0 to 100.0)
 *
 * @return Percentile value, or 0.0 if no data
 * @threadsafe Yes (mutex protected)
 *
 * Common percentiles: 50 (median), 75, 90, 95, 99, 99.9
 */
extern double SocketMetrics_histogram_percentile (SocketHistogramMetric metric,
                                                  double percentile);

/**
 * @brief Get observation count
 * @ingroup utilities
 * @param metric Histogram metric to query
 *
 * @return Total number of observations
 * @threadsafe Yes (atomic read)
 */
extern uint64_t SocketMetrics_histogram_count (SocketHistogramMetric metric);

/**
 * @brief Get sum of observations
 * @ingroup utilities
 * @param metric Histogram metric to query
 *
 * @return Sum of all observed values
 * @threadsafe Yes (mutex protected)
 */
extern double SocketMetrics_histogram_sum (SocketHistogramMetric metric);

/**
 * @brief Get histogram snapshot
 * @ingroup utilities
 * @param metric Histogram metric to snapshot
 * @param snapshot Output structure for snapshot data
 *
 * @threadsafe Yes (mutex protected)
 *
 * Calculates all statistics and percentiles at snapshot time.
 */
extern void
SocketMetrics_histogram_snapshot (SocketHistogramMetric metric,
                                  SocketMetrics_HistogramSnapshot *snapshot);

/* ============================================================================
 * Snapshot and Reset
 * ============================================================================
 */

/**
 * @brief Capture a complete point-in-time snapshot of all metrics.
 * @ingroup utilities
 * @param snapshot Output structure populated with current metrics data.
 * @threadsafe Yes - provides consistent view without blocking other
 * operations.
 * @see SocketMetrics_export_prometheus() to export the snapshot.
 * @see SocketMetrics_Snapshot for structure details.
 * @see SocketMetrics_reset() to clear metrics before new snapshot.
 */
extern void SocketMetrics_get (SocketMetrics_Snapshot *snapshot);

/**
 * @brief Reset all metrics to initial values
 * @ingroup utilities
 *
 * @threadsafe Yes
 *
 * Resets all counters to 0, gauges to 0, and clears histogram data.
 * Equivalent to the required SocketMetrics_reset() from TODO.
 */
extern void SocketMetrics_reset (void);

/**
 * @brief Reset only counter metrics
 * @ingroup utilities
 *
 * @threadsafe Yes
 */
extern void SocketMetrics_reset_counters (void);

/**
 * @brief Reset only histogram metrics
 * @ingroup utilities
 *
 * @threadsafe Yes
 */
extern void SocketMetrics_reset_histograms (void);

/* ============================================================================
 * Export Functions
 * ============================================================================
 */

/**
 * @brief Export metrics in Prometheus text format
 * @ingroup utilities
 * @param buffer Output buffer for formatted text
 * @param buffer_size Size of output buffer
 *
 * @return Number of bytes written (excluding NUL), or required size if too
 * small.
 * @threadsafe Yes - atomic snapshot acquisition with mutex protection for
 * consistency.
 *
 * Exports metrics in Prometheus exposition format (text/plain).
 * Format: https://prometheus.io/docs/instrumenting/exposition_formats/
 *
 * Example output:
 *   # HELP socket_pool_connections_created Total connections created
 *   # TYPE socket_pool_connections_created counter
 *   socket_pool_connections_created 1234
 */
extern size_t SocketMetrics_export_prometheus (char *buffer,
                                               size_t buffer_size);

/**
 * @brief Export metrics in StatsD format
 * @ingroup utilities
 * @param buffer Output buffer for formatted text
 * @param buffer_size Size of output buffer
 * @param prefix Metric name prefix (e.g., "myapp.socket") or NULL
 *
 * @return Number of bytes written (excluding NUL), or required size if too
 * small.
 * @threadsafe Yes - atomic snapshot acquisition with mutex protection for
 * consistency.
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
 * @brief Export metrics in JSON format
 * @ingroup utilities
 * @param buffer Output buffer for formatted text
 * @param buffer_size Size of output buffer
 *
 * @return Number of bytes written (excluding NUL), or required size if too
 * small.
 * @threadsafe Yes - atomic snapshot acquisition with mutex protection for
 * consistency.
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
 * ============================================================================
 */

/**
 * @brief Get counter metric name
 * @ingroup utilities
 * @param metric Counter metric
 *
 * @return Static string with metric name (snake_case)
 * @threadsafe Yes
 */
extern const char *SocketMetrics_counter_name (SocketCounterMetric metric);

/**
 * @brief Get gauge metric name
 * @ingroup utilities
 * @param metric Gauge metric
 *
 * @return Static string with metric name (snake_case)
 * @threadsafe Yes
 */
extern const char *SocketMetrics_gauge_name (SocketGaugeMetric metric);

/**
 * @brief Get histogram metric name
 * @ingroup utilities
 * @param metric Histogram metric
 *
 * @return Static string with metric name (snake_case)
 * @threadsafe Yes
 */
extern const char *SocketMetrics_histogram_name (SocketHistogramMetric metric);

/**
 * @brief Get counter metric help text
 * @ingroup utilities
 * @param metric Counter metric
 *
 * @return Static string with help text
 * @threadsafe Yes
 */
extern const char *SocketMetrics_counter_help (SocketCounterMetric metric);

/**
 * @brief Get gauge metric help text
 * @ingroup utilities
 * @param metric Gauge metric
 *
 * @return Static string with help text
 * @threadsafe Yes
 */
extern const char *SocketMetrics_gauge_help (SocketGaugeMetric metric);

/**
 * @brief Get histogram metric help text
 * @ingroup utilities
 * @param metric Histogram metric
 *
 * @return Static string with help text
 * @threadsafe Yes
 */
extern const char *SocketMetrics_histogram_help (SocketHistogramMetric metric);

/**
 * @brief Get the name of a metric category as a static string.
 * @ingroup utilities
 * @param category The metric category enum value.
 * @return Static read-only string (do not free) with category name.
 * @threadsafe Yes - returns constant data.
 * @see SocketMetricCategory for enum values.
 */
extern const char *SocketMetrics_category_name (SocketMetricCategory category);

/* ============================================================================
 * Socket Count and Peak Tracking
 * ============================================================================
 */

/**
 * @brief Get current count of open sockets.
 * @ingroup utilities
 *
 * Returns the number of Socket_T instances currently allocated (not freed).
 * This is useful for monitoring resource usage and detecting leaks.
 *
 * @return Current count of open Socket_T instances (>= 0)
 *
 * @threadsafe Yes - atomic counter read
 *
 * ## Example
 *
 * @code{.c}
 * int before = SocketMetrics_get_socket_count();
 * Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
 * assert(SocketMetrics_get_socket_count() == before + 1);
 * Socket_free(&sock);
 * assert(SocketMetrics_get_socket_count() == before);
 * @endcode
 *
 * @note This wraps Socket_debug_live_count() for consistency with metrics API
 * @see SocketMetrics_get_peak_connections() for high watermark
 * @see Socket_debug_live_count() for underlying implementation
 */
extern int SocketMetrics_get_socket_count (void);

/**
 * @brief Get peak (high watermark) count of simultaneous connections.
 * @ingroup utilities
 *
 * Returns the highest number of Socket_T instances that were allocated
 * simultaneously since the library was initialized or since the last call
 * to SocketMetrics_reset_peaks().
 *
 * This is useful for capacity planning and understanding peak load.
 *
 * @return Peak socket count since init/reset (>= 0)
 *
 * @threadsafe Yes - atomic counter read
 *
 * ## Example
 *
 * @code{.c}
 * // After running load test
 * printf("Peak connections: %d\n", SocketMetrics_get_peak_connections());
 * printf("Current connections: %d\n", SocketMetrics_get_socket_count());
 *
 * // Reset for next interval
 * SocketMetrics_reset_peaks();
 * @endcode
 *
 * @see SocketMetrics_get_socket_count() for current count
 * @see SocketMetrics_reset_peaks() to reset high watermark
 */
extern int SocketMetrics_get_peak_connections (void);

/**
 * @brief Reset peak connection counters.
 * @ingroup utilities
 *
 * Resets the peak (high watermark) connection count to the current count.
 * This is useful for interval-based monitoring where you want to track
 * peak usage per time period.
 *
 * @threadsafe Yes - atomic update
 *
 * ## Example
 *
 * @code{.c}
 * // Log peaks every hour
 * while (running) {
 *     sleep(3600);
 *     printf("Peak this hour: %d\n", SocketMetrics_get_peak_connections());
 *     SocketMetrics_reset_peaks();
 * }
 * @endcode
 *
 * @see SocketMetrics_get_peak_connections() to query peak
 * @see SocketMetrics_reset() to reset all metrics including peaks
 */
extern void SocketMetrics_reset_peaks (void);

/**
 * @brief Internal: Update peak counter if current count is higher.
 * @ingroup utilities
 * @internal
 *
 * Called from socket creation paths to track peak connections.
 * Applications should not call this directly.
 *
 * @param[in] current_count Current socket count
 *
 * @threadsafe Yes - uses atomic compare-and-swap
 */
extern void SocketMetrics_update_peak_if_needed (int current_count);

/* ============================================================================
 * Convenience Macros
 * ============================================================================
 */

/**
 * @brief SOCKET_METRICS_TIME_START - Start timing an operation
 * @ingroup utilities
 */
#define SOCKET_METRICS_TIME_START()                                           \
  int64_t _socket_metrics_start_time = Socket_get_monotonic_ms ()

/**
 * @brief SOCKET_METRICS_TIME_OBSERVE - Record elapsed time to histogram
 * @ingroup utilities
 * @param metric Histogram metric to record to
 */
#define SOCKET_METRICS_TIME_OBSERVE(metric)                                   \
  do                                                                          \
    {                                                                         \
      int64_t _elapsed                                                        \
          = Socket_get_monotonic_ms () - _socket_metrics_start_time;          \
      SocketMetrics_histogram_observe ((metric), (double)_elapsed);           \
    }                                                                         \
  while (0)

/**
 * @brief SOCKET_METRICS_HTTP_RESPONSE_CLASS - Record HTTP response by status
 * class
 * @ingroup utilities
 * @param status HTTP status code (100-599)
 */
#define SOCKET_METRICS_HTTP_RESPONSE_CLASS(status)                            \
  do                                                                          \
    {                                                                         \
      int _class = (status) / 100;                                            \
      switch (_class)                                                         \
        {                                                                     \
        case 1:                                                               \
          SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_1XX);          \
          break;                                                              \
        case 2:                                                               \
          SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_2XX);          \
          break;                                                              \
        case 3:                                                               \
          SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_3XX);          \
          break;                                                              \
        case 4:                                                               \
          SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_4XX);          \
          break;                                                              \
        case 5:                                                               \
          SocketMetrics_counter_inc (SOCKET_CTR_HTTP_RESPONSES_5XX);          \
          break;                                                              \
        }                                                                     \
    }                                                                         \
  while (0)

/** @} */

#endif /* SOCKETMETRICS_INCLUDED */
