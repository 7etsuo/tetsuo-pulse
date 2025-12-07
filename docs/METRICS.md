# Metrics and Observability Guide

This document describes the comprehensive metrics collection and export system provided by the Socket Library for production monitoring and observability.

## Overview

The Socket Library provides a production-grade metrics system with:

- **Counter Metrics**: Monotonically increasing values (requests, connections, errors)
- **Gauge Metrics**: Current values that can increase or decrease (active connections, queue size)
- **Histogram Metrics**: Distributions with percentile calculations (latency, response sizes)
- **Multiple Export Formats**: Prometheus, StatsD, and JSON

## Quick Start

```c
#include "core/SocketMetrics.h"

int main(void)
{
    // Initialize metrics (usually done once at startup)
    SocketMetrics_init();
    
    // Record metrics
    SocketMetrics_counter_inc(SOCKET_CTR_HTTP_CLIENT_REQUESTS_TOTAL);
    SocketMetrics_gauge_set(SOCKET_GAU_POOL_ACTIVE_CONNECTIONS, 42);
    SocketMetrics_histogram_observe(SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS, 125.5);
    
    // Export to Prometheus format
    char buffer[65536];
    size_t len = SocketMetrics_export_prometheus(buffer, sizeof(buffer));
    printf("%s", buffer);
    
    // Shutdown
    SocketMetrics_shutdown();
    return 0;
}
```

## Metric Types

### Counter Metrics

Counters are monotonically increasing values that track cumulative totals. They never decrease (except on reset).

```c
// Increment by 1
SocketMetrics_counter_inc(SOCKET_CTR_HTTP_CLIENT_REQUESTS_TOTAL);

// Increment by specific amount
SocketMetrics_counter_add(SOCKET_CTR_HTTP_CLIENT_BYTES_SENT, bytes_sent);

// Read current value
uint64_t total = SocketMetrics_counter_get(SOCKET_CTR_HTTP_CLIENT_REQUESTS_TOTAL);
```

Available Counter Metrics:

| Metric | Description |
|--------|-------------|
| `SOCKET_CTR_POOL_CONNECTIONS_CREATED` | Total connections created in pool |
| `SOCKET_CTR_POOL_CONNECTIONS_DESTROYED` | Total connections destroyed |
| `SOCKET_CTR_POOL_CONNECTIONS_FAILED` | Failed connection attempts |
| `SOCKET_CTR_POOL_CONNECTIONS_REUSED` | Connections reused from pool |
| `SOCKET_CTR_POOL_CONNECTIONS_EVICTED` | Connections evicted due to idle/age limits |
| `SOCKET_CTR_HTTP_CLIENT_REQUESTS_TOTAL` | Total HTTP requests sent |
| `SOCKET_CTR_HTTP_CLIENT_REQUESTS_FAILED` | Failed HTTP requests |
| `SOCKET_CTR_HTTP_CLIENT_BYTES_SENT` | Total bytes sent by HTTP client |
| `SOCKET_CTR_HTTP_CLIENT_BYTES_RECEIVED` | Total bytes received |
| `SOCKET_CTR_HTTP_SERVER_REQUESTS_TOTAL` | Total HTTP requests received |
| `SOCKET_CTR_HTTP_RESPONSES_2XX` | Successful HTTP responses |
| `SOCKET_CTR_HTTP_RESPONSES_4XX` | Client error responses |
| `SOCKET_CTR_HTTP_RESPONSES_5XX` | Server error responses |
| `SOCKET_CTR_TLS_HANDSHAKES_TOTAL` | Total TLS handshakes |
| `SOCKET_CTR_TLS_HANDSHAKES_FAILED` | Failed TLS handshakes |
| `SOCKET_CTR_TLS_SESSION_REUSE_COUNT` | TLS session resumption count |
| `SOCKET_CTR_DNS_QUERIES_TOTAL` | Total DNS queries |
| `SOCKET_CTR_DNS_QUERIES_FAILED` | Failed DNS queries |
| `SOCKET_CTR_SOCKET_CONNECT_SUCCESS` | Successful socket connects |
| `SOCKET_CTR_SOCKET_CONNECT_FAILED` | Failed socket connects |

### Gauge Metrics

Gauges represent current values that can increase or decrease, like active connections or queue sizes.

```c
// Set to specific value
SocketMetrics_gauge_set(SOCKET_GAU_POOL_ACTIVE_CONNECTIONS, 42);

// Increment/decrement by 1
SocketMetrics_gauge_inc(SOCKET_GAU_POOL_ACTIVE_CONNECTIONS);
SocketMetrics_gauge_dec(SOCKET_GAU_POOL_ACTIVE_CONNECTIONS);

// Add arbitrary amount (can be negative)
SocketMetrics_gauge_add(SOCKET_GAU_POOL_ACTIVE_CONNECTIONS, delta);

// Read current value
int64_t active = SocketMetrics_gauge_get(SOCKET_GAU_POOL_ACTIVE_CONNECTIONS);
```

Available Gauge Metrics:

| Metric | Description |
|--------|-------------|
| `SOCKET_GAU_POOL_ACTIVE_CONNECTIONS` | Currently active connections |
| `SOCKET_GAU_POOL_IDLE_CONNECTIONS` | Currently idle connections |
| `SOCKET_GAU_POOL_PENDING_CONNECTIONS` | Pending connection attempts |
| `SOCKET_GAU_POOL_SIZE` | Current pool capacity |
| `SOCKET_GAU_HTTP_CLIENT_ACTIVE_REQUESTS` | In-flight HTTP requests |
| `SOCKET_GAU_HTTP_SERVER_ACTIVE_CONNECTIONS` | Active server connections |
| `SOCKET_GAU_TLS_ACTIVE_SESSIONS` | Active TLS sessions |
| `SOCKET_GAU_DNS_PENDING_QUERIES` | Pending DNS queries |
| `SOCKET_GAU_SOCKET_OPEN_FDS` | Open file descriptors |
| `SOCKET_GAU_POLL_REGISTERED_FDS` | FDs registered with poll |

### Histogram Metrics

Histograms track value distributions and support percentile queries (p50, p95, p99, etc.). They're ideal for latency measurements.

```c
// Record an observation
SocketMetrics_histogram_observe(SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS, 125.5);

// Using timing macros
SOCKET_METRICS_TIME_START();
// ... perform operation ...
SOCKET_METRICS_TIME_OBSERVE(SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS);

// Get percentiles
double p50 = SocketMetrics_histogram_percentile(
    SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS, 50.0);
double p95 = SocketMetrics_histogram_percentile(
    SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS, 95.0);
double p99 = SocketMetrics_histogram_percentile(
    SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS, 99.0);

// Get snapshot with all statistics
SocketMetrics_HistogramSnapshot snap;
SocketMetrics_histogram_snapshot(SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS, &snap);
printf("Count: %llu, Mean: %.2f, p50: %.2f, p95: %.2f, p99: %.2f\n",
       snap.count, snap.mean, snap.p50, snap.p95, snap.p99);
```

Available Histogram Metrics:

| Metric | Description |
|--------|-------------|
| `SOCKET_HIST_POOL_ACQUIRE_TIME_MS` | Time to acquire connection from pool |
| `SOCKET_HIST_POOL_CONNECTION_AGE_MS` | Connection age at close |
| `SOCKET_HIST_POOL_IDLE_TIME_MS` | Time connection was idle |
| `SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS` | HTTP request total latency |
| `SOCKET_HIST_HTTP_CLIENT_CONNECT_TIME_MS` | HTTP connection time |
| `SOCKET_HIST_HTTP_CLIENT_TTFB_MS` | Time to first byte |
| `SOCKET_HIST_HTTP_CLIENT_RESPONSE_SIZE` | Response body size |
| `SOCKET_HIST_HTTP_SERVER_REQUEST_LATENCY_MS` | Request processing time |
| `SOCKET_HIST_TLS_HANDSHAKE_TIME_MS` | TLS handshake duration |
| `SOCKET_HIST_DNS_QUERY_TIME_MS` | DNS query duration |
| `SOCKET_HIST_SOCKET_CONNECT_TIME_MS` | Socket connect duration |

## Security Metrics

The library now includes dedicated metrics for security event monitoring, enhancing observability for TLS/DTLS hardening (see SECURITY.md for details on usage in attack detection).

### TLS/DTLS Security Counters

| Metric | Description |
|--------|-------------|
| `SOCKET_CTR_TLS_PINNING_FAILURES` | Certificate pinning violations (e.g., key mismatch during verification) |
| `SOCKET_CTR_TLS_CT_VERIFICATION_FAILURES` | Certificate Transparency log verification failures |
| `SOCKET_CTR_TLS_CRL_CHECK_FAILURES` | CRL/OCSP revocation check failures |

### DTLS-Specific Counters (RFC 6347 DoS Protection)

| Metric | Description |
|--------|-------------|
| `SOCKET_CTR_DTLS_HANDSHAKES_TOTAL` | Total DTLS handshakes initiated |
| `SOCKET_CTR_DTLS_HANDSHAKES_FAILED` | Failed DTLS handshakes (e.g., protocol errors) |
| `SOCKET_CTR_DTLS_COOKIES_GENERATED` | HelloVerifyRequest cookies generated for SYN protection |
| `SOCKET_CTR_DTLS_COOKIE_VERIFICATION_FAILURES` | Invalid/expired cookies rejected |
| `SOCKET_CTR_DTLS_REPLAY_PACKETS_DETECTED` | Packets dropped due to replay detection |
| `SOCKET_CTR_DTLS_FRAGMENT_FAILURES` | Fragmented message reassembly failures |

### Additional Gauges & Histograms

- `SOCKET_GAU_DTLS_ACTIVE_SESSIONS`: Active DTLS sessions (gauge)
- `SOCKET_HIST_DTLS_HANDSHAKE_TIME_MS`: DTLS handshake latency distribution

Use these to alert on anomalies (e.g., high cookie failures indicate DoS attempts). Integrate via `SocketMetrics_counter_inc()` on failure paths in TLS code.

## Export Formats

### Prometheus Format

Export metrics in Prometheus exposition format for scraping by Prometheus server.

```c
char buffer[65536];
size_t len = SocketMetrics_export_prometheus(buffer, sizeof(buffer));

// Output example:
// # HELP socket_http_client_requests_total Total HTTP requests sent
// # TYPE socket_http_client_requests_total counter
// socket_http_client_requests_total 12345
// # HELP socket_http_client_request_latency_ms HTTP request total latency (ms)
// # TYPE socket_http_client_request_latency_ms summary
// socket_http_client_request_latency_ms{quantile="0.5"} 125.000
// socket_http_client_request_latency_ms{quantile="0.95"} 250.000
// socket_http_client_request_latency_ms{quantile="0.99"} 500.000
// socket_http_client_request_latency_ms_sum 1250000.000
// socket_http_client_request_latency_ms_count 10000
```

Example HTTP endpoint (using SocketHTTPServer):

```c
void metrics_handler(SocketHTTPServer_Request req)
{
    static char buffer[65536];
    size_t len = SocketMetrics_export_prometheus(buffer, sizeof(buffer));
    
    SocketHTTPServer_Response_status(req, 200);
    SocketHTTPServer_Response_header(req, "Content-Type", 
                                     "text/plain; version=0.0.4");
    SocketHTTPServer_Response_body(req, buffer, len);
    SocketHTTPServer_Response_send(req);
}
```

### StatsD Format

Export metrics in StatsD line protocol format for sending to StatsD/Graphite.

```c
char buffer[65536];
const char *prefix = "myapp.socket";  // Optional prefix
size_t len = SocketMetrics_export_statsd(buffer, sizeof(buffer), prefix);

// Output example:
// myapp.socket.pool_connections_created:1234|c
// myapp.socket.pool_active_connections:42|g
// myapp.socket.http_client_request_latency_ms.p50:125.000|g
// myapp.socket.http_client_request_latency_ms.p95:250.000|g
// myapp.socket.http_client_request_latency_ms.p99:500.000|g
```

Send to StatsD server:

```c
void send_to_statsd(const char *host, int port)
{
    char buffer[65536];
    size_t len = SocketMetrics_export_statsd(buffer, sizeof(buffer), "myapp");
    
    SocketDgram_T udp = SocketDgram_new(SOCKET_AF_INET, 0);
    SocketDgram_sendto(udp, buffer, len, host, port);
    SocketDgram_free(&udp);
}
```

### JSON Format

Export metrics as JSON for custom integrations, dashboards, or APIs.

```c
char buffer[65536];
size_t len = SocketMetrics_export_json(buffer, sizeof(buffer));

// Output example:
// {
//   "timestamp_ms": 1699876543210,
//   "counters": {
//     "pool_connections_created": 1234,
//     "http_client_requests_total": 5678,
//     ...
//   },
//   "gauges": {
//     "pool_active_connections": 42,
//     ...
//   },
//   "histograms": {
//     "http_client_request_latency_ms": {
//       "count": 10000,
//       "sum": 1250000.000,
//       "min": 5.000,
//       "max": 2500.000,
//       "mean": 125.000,
//       "p50": 100.000,
//       "p95": 250.000,
//       "p99": 500.000,
//       "p999": 1500.000
//     },
//     ...
//   }
// }
```

## Snapshots

Get a consistent point-in-time snapshot of all metrics:

```c
SocketMetrics_Snapshot snapshot;
SocketMetrics_get(&snapshot);

printf("Timestamp: %llu ms\n", (unsigned long long)snapshot.timestamp_ms);
printf("Requests: %llu\n", snapshot.counters[SOCKET_CTR_HTTP_CLIENT_REQUESTS_TOTAL]);
printf("Active: %lld\n", snapshot.gauges[SOCKET_GAU_POOL_ACTIVE_CONNECTIONS]);
printf("Latency p99: %.2f ms\n", snapshot.histograms[SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS].p99);
```

## Resetting Metrics

Reset all metrics to initial values (useful for testing or interval-based reporting):

```c
// Reset everything
SocketMetrics_reset();

// Reset only counters
SocketMetrics_reset_counters();

// Reset only histograms
SocketMetrics_reset_histograms();
```

## Convenience Macros

### Timing Operations

```c
// Time an operation and record to histogram
SOCKET_METRICS_TIME_START();
// ... perform operation ...
SOCKET_METRICS_TIME_OBSERVE(SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS);
```

### HTTP Response Classification

```c
// Automatically increment the correct HTTP status class counter
int status_code = 200;
SOCKET_METRICS_HTTP_RESPONSE_CLASS(status_code);  // Increments SOCKET_CTR_HTTP_RESPONSES_2XX
```

## Thread Safety

- **Counters and Gauges**: Lock-free atomic operations, safe for concurrent use
- **Histograms**: Mutex-protected, safe for concurrent use but with some overhead
- **Export Functions**: Thread-safe, uses snapshot for consistency
- **Initialization/Shutdown**: Idempotent, safe to call multiple times

## Performance Considerations

1. **Counter/Gauge Operations**: O(1) atomic operations, negligible overhead
2. **Histogram Observations**: O(1) amortized, mutex-protected
3. **Percentile Queries**: O(n log n) due to sorting, where n = histogram bucket count
4. **Export Functions**: O(m) where m = total metric count, plus O(n log n) for each histogram

For high-throughput applications:
- Prefer counters over histograms when possible
- Use snapshots for bulk reads rather than individual queries
- Consider periodic export (e.g., every 10 seconds) rather than on-demand

## Memory Usage

- Base overhead: ~1KB for counter and gauge arrays
- Per histogram: ~8KB (1024 double values + metadata)
- Total with all histograms: ~100KB

Histogram size is configurable at compile time:

```c
// In your build system
-DSOCKET_METRICS_HISTOGRAM_BUCKETS=2048  // Double the default
```

## Integration Examples

### Prometheus + Grafana Setup

1. Create a `/metrics` endpoint in your HTTP server
2. Configure Prometheus to scrape the endpoint:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'socket_app'
    scrape_interval: 10s
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
```

3. Create Grafana dashboards using queries like:
   - `rate(socket_http_client_requests_total[5m])` - Requests per second
   - `socket_pool_active_connections` - Active connections
   - `socket_http_client_request_latency_ms{quantile="0.99"}` - p99 latency

### DataDog Integration (via StatsD)

```c
// Send metrics to DataDog agent
void flush_metrics_to_datadog(void)
{
    static char buffer[65536];
    size_t len = SocketMetrics_export_statsd(buffer, sizeof(buffer), "myapp.socket");
    
    // DataDog agent typically listens on UDP 8125
    SocketDgram_T udp = SocketDgram_new(SOCKET_AF_INET, 0);
    SocketDgram_sendto(udp, buffer, len, "127.0.0.1", 8125);
    SocketDgram_free(&udp);
}

// Set up periodic flushing
SocketTimer_add_repeating(poll, 10000, flush_metrics_to_datadog, NULL);
```

### Custom JSON Dashboard

```c
// Serve metrics as JSON API
void metrics_api_handler(SocketHTTPServer_Request req)
{
    static char buffer[65536];
    size_t len = SocketMetrics_export_json(buffer, sizeof(buffer));
    
    SocketHTTPServer_Response_status(req, 200);
    SocketHTTPServer_Response_header(req, "Content-Type", "application/json");
    SocketHTTPServer_Response_header(req, "Cache-Control", "no-cache");
    SocketHTTPServer_Response_body(req, buffer, len);
    SocketHTTPServer_Response_send(req);
}
```

## Best Practices

1. **Initialize Early**: Call `SocketMetrics_init()` at application startup
2. **Use Descriptive Prefixes**: When using StatsD, use a meaningful prefix for your application
3. **Monitor Percentiles**: For latency metrics, focus on p95/p99, not just averages
4. **Set Alerts**: Use your monitoring system to alert on:
   - High error rates (`SOCKET_CTR_*_FAILED` metrics)
   - Connection pool exhaustion (`SOCKET_GAU_POOL_IDLE_CONNECTIONS` near 0)
   - High latency percentiles
5. **Periodic Reset**: For interval-based reporting, reset after export:
   ```c
   SocketMetrics_export_statsd(buffer, sizeof(buffer), prefix);
   send_to_backend(buffer);
   SocketMetrics_reset();
   ```

## Migration from Legacy Metrics

The Socket Library previously had a simpler metrics system in `SocketUtil.h`. That system is still available as `SocketMetrics_increment()` and `SocketMetrics_getsnapshot()` for backward compatibility, but new code should use the comprehensive `SocketMetrics.h` system.

| Legacy API | New API |
|------------|---------|
| `SocketMetrics_increment()` | `SocketMetrics_counter_inc()` / `_add()` |
| `SocketMetrics_getsnapshot()` | `SocketMetrics_get()` |
| `SocketMetrics_reset()` | `SocketMetrics_legacy_reset()` (legacy) |
| N/A | `SocketMetrics_reset()` (new) |
| N/A | `SocketMetrics_export_*()` |
| N/A | `SocketMetrics_histogram_*()` |

## API Reference

See the Doxygen documentation for `SocketMetrics.h` for complete API details.
