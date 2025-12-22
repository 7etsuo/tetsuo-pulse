/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file benchmark_http_common.h
 * @brief Shared infrastructure for HTTP client benchmarks (tetsuo-socket vs
 * libcurl).
 *
 * Provides common types, timing utilities, percentile calculation, and JSON
 * output for fair comparison between HTTP client implementations.
 */

#ifndef BENCHMARK_HTTP_COMMON_H
#define BENCHMARK_HTTP_COMMON_H

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Benchmark configuration defaults
 * Note: Keep total requests low until issue #119 (HTTP client memory corruption)
 * is fixed. With high request counts (>2000 total), the HTTP client crashes.
 */
#define BENCH_HTTP_DEFAULT_REQUESTS 100
#define BENCH_HTTP_DEFAULT_THREADS 4
#define BENCH_HTTP_DEFAULT_WARMUP 10
#define BENCH_HTTP_DEFAULT_PORT 8080
#define BENCH_HTTP_DEFAULT_TLS_PORT 8443

typedef enum
{
  BENCH_HTTP_VERSION_AUTO = 0, /* Let library negotiate */
  BENCH_HTTP_VERSION_1_1 = 1,  /* Force HTTP/1.1 */
  BENCH_HTTP_VERSION_2 = 2     /* Force HTTP/2 */
} BenchHTTPVersion;

/**
 * @brief Benchmark configuration.
 */
typedef struct
{
  const char *url;          /* Target URL */
  int threads;              /* Number of concurrent threads */
  int requests_per_thread;  /* Requests per thread */
  int warmup_requests;      /* Warmup requests (excluded from measurements) */
  BenchHTTPVersion version; /* HTTP version to use */
  int use_tls;              /* Use HTTPS */
  int keep_alive;           /* Enable connection reuse */
  int verbose;              /* Verbose output */
  const char *output_file;  /* JSON output file (NULL for none) */
} BenchHTTPConfig;

/**
 * @brief Per-thread results.
 */
typedef struct
{
  uint64_t *latencies_ns;  /* Latency samples in nanoseconds */
  size_t latency_count;    /* Number of samples */
  size_t latency_capacity; /* Allocated capacity */
  uint64_t successful;     /* Successful requests */
  uint64_t failed;         /* Failed requests */
  uint64_t bytes_received; /* Total bytes received */
} BenchHTTPThreadResult;

/**
 * @brief Aggregated benchmark results.
 */
typedef struct
{
  /* Request counts */
  uint64_t total_requests;
  uint64_t successful_requests;
  uint64_t failed_requests;
  uint64_t bytes_received;

  /* Connection metrics */
  uint64_t connections_created;
  uint64_t connections_reused;
  double connection_reuse_ratio;

  /* Timing */
  uint64_t start_ns;
  uint64_t end_ns;
  double elapsed_sec;
  double requests_per_sec;

  /* Latency percentiles (nanoseconds) */
  uint64_t latency_min;
  uint64_t latency_max;
  double latency_mean;
  uint64_t latency_p50;
  uint64_t latency_p90;
  uint64_t latency_p99;
  uint64_t latency_p999;
} BenchHTTPResult;

/**
 * @brief Thread argument for worker threads.
 */
typedef struct
{
  int thread_id;
  const BenchHTTPConfig *config;
  BenchHTTPThreadResult *result;
  void *client; /* Client handle (library-specific) */
} BenchHTTPThreadArg;

/*---------------------------------------------------------------------------
 * High-precision timing utilities
 *---------------------------------------------------------------------------*/

/**
 * @brief Get current time in nanoseconds (monotonic clock).
 */
static inline uint64_t
bench_now_ns (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/**
 * @brief Convert nanoseconds to microseconds.
 */
static inline double
bench_ns_to_us (uint64_t ns)
{
  return (double)ns / 1000.0;
}

/**
 * @brief Convert nanoseconds to milliseconds.
 */
static inline double
bench_ns_to_ms (uint64_t ns)
{
  return (double)ns / 1000000.0;
}

/*---------------------------------------------------------------------------
 * Thread result management
 *---------------------------------------------------------------------------*/

/**
 * @brief Initialize thread result with preallocated latency buffer.
 */
static inline int
bench_thread_result_init (BenchHTTPThreadResult *result, size_t capacity)
{
  result->latencies_ns = calloc (capacity, sizeof (uint64_t));
  if (!result->latencies_ns)
    return -1;
  result->latency_count = 0;
  result->latency_capacity = capacity;
  result->successful = 0;
  result->failed = 0;
  result->bytes_received = 0;
  return 0;
}

/**
 * @brief Free thread result resources.
 */
static inline void
bench_thread_result_free (BenchHTTPThreadResult *result)
{
  free (result->latencies_ns);
  result->latencies_ns = NULL;
}

/**
 * @brief Record a latency sample.
 */
static inline void
bench_record_latency (BenchHTTPThreadResult *result, uint64_t latency_ns)
{
  if (result->latency_count < result->latency_capacity)
    {
      result->latencies_ns[result->latency_count++] = latency_ns;
    }
}

/*---------------------------------------------------------------------------
 * Percentile calculation
 *---------------------------------------------------------------------------*/

/**
 * @brief Comparison function for qsort (uint64_t).
 */
static inline int
bench_cmp_uint64 (const void *a, const void *b)
{
  uint64_t va = *(const uint64_t *)a;
  uint64_t vb = *(const uint64_t *)b;
  if (va < vb)
    return -1;
  if (va > vb)
    return 1;
  return 0;
}

/**
 * @brief Calculate percentile from sorted array.
 */
static inline uint64_t
bench_percentile (const uint64_t *sorted, size_t count, double pct)
{
  if (count == 0)
    return 0;
  size_t idx = (size_t)((pct / 100.0) * (double)(count - 1));
  if (idx >= count)
    idx = count - 1;
  return sorted[idx];
}

/**
 * @brief Compute latency statistics from thread results.
 *
 * @param results Array of thread results.
 * @param num_threads Number of threads.
 * @param out Aggregated result output.
 */
static inline void
bench_compute_stats (BenchHTTPThreadResult *results, int num_threads,
                     BenchHTTPResult *out)
{
  /* Count total samples */
  size_t total_samples = 0;
  for (int i = 0; i < num_threads; i++)
    {
      total_samples += results[i].latency_count;
      out->successful_requests += results[i].successful;
      out->failed_requests += results[i].failed;
      out->bytes_received += results[i].bytes_received;
    }
  out->total_requests = out->successful_requests + out->failed_requests;

  if (total_samples == 0)
    return;

  /* Merge all latency samples */
  uint64_t *all_latencies = calloc (total_samples, sizeof (uint64_t));
  if (!all_latencies)
    return;

  size_t offset = 0;
  for (int i = 0; i < num_threads; i++)
    {
      memcpy (all_latencies + offset, results[i].latencies_ns,
              results[i].latency_count * sizeof (uint64_t));
      offset += results[i].latency_count;
    }

  /* Sort for percentile calculation */
  qsort (all_latencies, total_samples, sizeof (uint64_t), bench_cmp_uint64);

  /* Compute stats */
  out->latency_min = all_latencies[0];
  out->latency_max = all_latencies[total_samples - 1];

  uint64_t sum = 0;
  for (size_t i = 0; i < total_samples; i++)
    sum += all_latencies[i];
  out->latency_mean = (double)sum / (double)total_samples;

  out->latency_p50 = bench_percentile (all_latencies, total_samples, 50.0);
  out->latency_p90 = bench_percentile (all_latencies, total_samples, 90.0);
  out->latency_p99 = bench_percentile (all_latencies, total_samples, 99.0);
  out->latency_p999 = bench_percentile (all_latencies, total_samples, 99.9);

  /* Throughput */
  out->elapsed_sec
      = (double)(out->end_ns - out->start_ns) / 1000000000.0;
  if (out->elapsed_sec > 0)
    out->requests_per_sec
        = (double)out->successful_requests / out->elapsed_sec;

  /* Connection reuse ratio */
  if (out->connections_created + out->connections_reused > 0)
    out->connection_reuse_ratio
        = (double)out->connections_reused
          / (double)(out->connections_created + out->connections_reused);

  free (all_latencies);
}

/*---------------------------------------------------------------------------
 * Output formatting
 *---------------------------------------------------------------------------*/

/**
 * @brief Print results to console.
 */
static inline void
bench_print_results (const char *client_name, const BenchHTTPConfig *config,
                     const BenchHTTPResult *result)
{
  const char *version_str
      = config->version == BENCH_HTTP_VERSION_1_1   ? "HTTP/1.1"
        : config->version == BENCH_HTTP_VERSION_2   ? "HTTP/2"
                                                    : "auto";

  printf ("\n========================================\n");
  printf ("%s Benchmark Results\n", client_name);
  printf ("========================================\n");
  printf ("URL: %s\n", config->url);
  printf ("Protocol: %s\n", version_str);
  printf ("Threads: %d\n", config->threads);
  printf ("Requests: %lu (success: %lu, fail: %lu)\n",
          (unsigned long)result->total_requests,
          (unsigned long)result->successful_requests,
          (unsigned long)result->failed_requests);
  printf ("Elapsed: %.3f sec\n", result->elapsed_sec);
  printf ("Throughput: %.2f req/sec\n", result->requests_per_sec);
  printf ("\nLatency (microseconds):\n");
  printf ("  min:  %.2f\n", bench_ns_to_us (result->latency_min));
  printf ("  max:  %.2f\n", bench_ns_to_us (result->latency_max));
  printf ("  mean: %.2f\n", bench_ns_to_us ((uint64_t)result->latency_mean));
  printf ("  p50:  %.2f\n", bench_ns_to_us (result->latency_p50));
  printf ("  p90:  %.2f\n", bench_ns_to_us (result->latency_p90));
  printf ("  p99:  %.2f\n", bench_ns_to_us (result->latency_p99));
  printf ("  p999: %.2f\n", bench_ns_to_us (result->latency_p999));
  printf ("\nConnections:\n");
  printf ("  created: %lu\n", (unsigned long)result->connections_created);
  printf ("  reused:  %lu\n", (unsigned long)result->connections_reused);
  printf ("  reuse ratio: %.4f\n", result->connection_reuse_ratio);
  printf ("========================================\n\n");
}

/**
 * @brief Write results to JSON file.
 */
static inline int
bench_write_json (const char *filename, const char *client_name,
                  const BenchHTTPConfig *config, const BenchHTTPResult *result)
{
  FILE *f = fopen (filename, "w");
  if (!f)
    return -1;

  const char *version_str
      = config->version == BENCH_HTTP_VERSION_1_1   ? "h1"
        : config->version == BENCH_HTTP_VERSION_2   ? "h2"
                                                    : "auto";

  fprintf (f, "{\n");
  fprintf (f, "  \"client\": \"%s\",\n", client_name);
  fprintf (f, "  \"protocol\": \"%s\",\n", version_str);
  fprintf (f, "  \"url\": \"%s\",\n", config->url);
  fprintf (f, "  \"threads\": %d,\n", config->threads);
  fprintf (f, "  \"requests_per_thread\": %d,\n", config->requests_per_thread);
  fprintf (f, "  \"results\": {\n");
  fprintf (f, "    \"total_requests\": %lu,\n",
           (unsigned long)result->total_requests);
  fprintf (f, "    \"successful_requests\": %lu,\n",
           (unsigned long)result->successful_requests);
  fprintf (f, "    \"failed_requests\": %lu,\n",
           (unsigned long)result->failed_requests);
  fprintf (f, "    \"elapsed_sec\": %.6f,\n", result->elapsed_sec);
  fprintf (f, "    \"requests_per_sec\": %.2f,\n", result->requests_per_sec);
  fprintf (f, "    \"bytes_received\": %lu,\n",
           (unsigned long)result->bytes_received);
  fprintf (f, "    \"latency_us\": {\n");
  fprintf (f, "      \"min\": %.2f,\n", bench_ns_to_us (result->latency_min));
  fprintf (f, "      \"max\": %.2f,\n", bench_ns_to_us (result->latency_max));
  fprintf (f, "      \"mean\": %.2f,\n",
           bench_ns_to_us ((uint64_t)result->latency_mean));
  fprintf (f, "      \"p50\": %.2f,\n", bench_ns_to_us (result->latency_p50));
  fprintf (f, "      \"p90\": %.2f,\n", bench_ns_to_us (result->latency_p90));
  fprintf (f, "      \"p99\": %.2f,\n", bench_ns_to_us (result->latency_p99));
  fprintf (f, "      \"p999\": %.2f\n", bench_ns_to_us (result->latency_p999));
  fprintf (f, "    },\n");
  fprintf (f, "    \"connections\": {\n");
  fprintf (f, "      \"created\": %lu,\n",
           (unsigned long)result->connections_created);
  fprintf (f, "      \"reused\": %lu,\n",
           (unsigned long)result->connections_reused);
  fprintf (f, "      \"reuse_ratio\": %.4f\n", result->connection_reuse_ratio);
  fprintf (f, "    }\n");
  fprintf (f, "  }\n");
  fprintf (f, "}\n");

  fclose (f);
  return 0;
}

/**
 * @brief Initialize config with defaults.
 */
static inline void
bench_config_defaults (BenchHTTPConfig *config)
{
  memset (config, 0, sizeof (*config));
  config->url = "http://127.0.0.1:8080/small";
  config->threads = BENCH_HTTP_DEFAULT_THREADS;
  config->requests_per_thread = BENCH_HTTP_DEFAULT_REQUESTS;
  config->warmup_requests = BENCH_HTTP_DEFAULT_WARMUP;
  config->version = BENCH_HTTP_VERSION_AUTO;
  config->use_tls = 0;
  config->keep_alive = 1;
  config->verbose = 0;
  config->output_file = NULL;
}

/**
 * @brief Parse command-line arguments.
 */
static inline int
bench_parse_args (int argc, char **argv, BenchHTTPConfig *config)
{
  for (int i = 1; i < argc; i++)
    {
      if (strncmp (argv[i], "--url=", 6) == 0)
        {
          config->url = argv[i] + 6;
        }
      else if (strncmp (argv[i], "--threads=", 10) == 0)
        {
          config->threads = atoi (argv[i] + 10);
        }
      else if (strncmp (argv[i], "--requests=", 11) == 0)
        {
          config->requests_per_thread = atoi (argv[i] + 11);
        }
      else if (strncmp (argv[i], "--warmup=", 9) == 0)
        {
          config->warmup_requests = atoi (argv[i] + 9);
        }
      else if (strcmp (argv[i], "--http1") == 0)
        {
          config->version = BENCH_HTTP_VERSION_1_1;
        }
      else if (strcmp (argv[i], "--http2") == 0)
        {
          config->version = BENCH_HTTP_VERSION_2;
        }
      else if (strcmp (argv[i], "--no-keepalive") == 0)
        {
          config->keep_alive = 0;
        }
      else if (strcmp (argv[i], "--verbose") == 0 || strcmp (argv[i], "-v") == 0)
        {
          config->verbose = 1;
        }
      else if (strncmp (argv[i], "--output=", 9) == 0)
        {
          config->output_file = argv[i] + 9;
        }
      else if (strcmp (argv[i], "--help") == 0 || strcmp (argv[i], "-h") == 0)
        {
          printf ("Usage: %s [options]\n", argv[0]);
          printf ("Options:\n");
          printf ("  --url=URL          Target URL (default: "
                  "http://127.0.0.1:8080/small)\n");
          printf ("  --threads=N        Number of threads (default: %d)\n",
                  BENCH_HTTP_DEFAULT_THREADS);
          printf (
              "  --requests=N       Requests per thread (default: %d)\n",
              BENCH_HTTP_DEFAULT_REQUESTS);
          printf ("  --warmup=N         Warmup requests (default: %d)\n",
                  BENCH_HTTP_DEFAULT_WARMUP);
          printf ("  --http1            Force HTTP/1.1\n");
          printf ("  --http2            Force HTTP/2\n");
          printf ("  --no-keepalive     Disable connection reuse\n");
          printf ("  --output=FILE      Write JSON results to FILE\n");
          printf ("  --verbose, -v      Verbose output\n");
          printf ("  --help, -h         Show this help\n");
          return 1;
        }
    }
  return 0;
}

#endif /* BENCHMARK_HTTP_COMMON_H */
