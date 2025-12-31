/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file benchmark_http_tetsuo.c
 * @brief HTTP client benchmark using tetsuo-socket's SocketHTTPClient.
 *
 * Measures requests/sec, latency percentiles, and connection reuse
 * for fair comparison against libcurl.
 *
 * Usage:
 *   ./benchmark_http_tetsuo --url=http://127.0.0.1:8080/small --threads=4
 */

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "benchmark_http_common.h"
#include "core/Except.h"
#include "http/SocketHTTP.h"
#include "http/SocketHTTPClient.h"

static volatile sig_atomic_t g_running = 1;

static void
handle_signal (int sig)
{
  (void)sig;
  g_running = 0;
}

/**
 * @brief Worker thread for concurrent benchmarking.
 */
static void *
bench_worker (void *arg)
{
  BenchHTTPThreadArg *targ = (BenchHTTPThreadArg *)arg;
  const BenchHTTPConfig *config = targ->config;
  BenchHTTPThreadResult *result = targ->result;
  SocketHTTPClient_T client = (SocketHTTPClient_T)targ->client;

  int total_requests = config->requests_per_thread + config->warmup_requests;

  for (int i = 0; i < total_requests && g_running; i++)
    {
      int is_warmup = (i < config->warmup_requests);

      uint64_t start = bench_now_ns ();

      SocketHTTPClient_Response response;
      memset (&response, 0, sizeof (response));

      int rc = SocketHTTPClient_get (client, config->url, &response);

      uint64_t elapsed = bench_now_ns () - start;

      if (rc == HTTPCLIENT_OK && response.status_code == 200)
        {
          if (!is_warmup)
            {
              result->successful++;
              result->bytes_received += response.body_len;
              bench_record_latency (result, elapsed);
            }
        }
      else
        {
          if (!is_warmup)
            {
              result->failed++;
              if (config->verbose)
                {
                  fprintf (stderr,
                           "[Thread %d] Request %d failed: rc=%d, "
                           "status=%d\n",
                           targ->thread_id,
                           i,
                           rc,
                           response.status_code);
                }
            }
        }

      SocketHTTPClient_Response_free (&response);
    }

  return NULL;
}

/**
 * @brief Create HTTP client with config parity for fair comparison.
 */
static SocketHTTPClient_T
create_client (const BenchHTTPConfig *config)
{
  SocketHTTPClient_Config client_config;
  SocketHTTPClient_config_defaults (&client_config);

  /* Connection pooling - match libcurl defaults */
  client_config.enable_connection_pool = config->keep_alive ? 1 : 0;
  client_config.max_connections_per_host = 6;
  client_config.max_total_connections = 100;
  client_config.idle_timeout_ms = 60000;

  /* Timeouts */
  client_config.connect_timeout_ms = 30000;
  client_config.request_timeout_ms = 60000;

  /* HTTP version */
  if (config->version == BENCH_HTTP_VERSION_1_1)
    {
      client_config.max_version = HTTP_VERSION_1_1;
    }
  else if (config->version == BENCH_HTTP_VERSION_2)
    {
      client_config.max_version = HTTP_VERSION_2;
      client_config.allow_http2_cleartext = 1;
    }
  else
    {
      client_config.max_version = HTTP_VERSION_2;
    }

  /* Disable redirects for raw benchmark */
  client_config.follow_redirects = 0;

  /* Disable compression for raw benchmark */
  client_config.accept_encoding = 0;
  client_config.auto_decompress = 0;

  /* Disable retry for raw benchmark */
  client_config.enable_retry = 0;

  /* Benchmark mode: discard body data like curl does */
  client_config.discard_body = 1;

  return SocketHTTPClient_new (&client_config);
}

int
main (int argc, char **argv)
{
  BenchHTTPConfig config;
  bench_config_defaults (&config);

  if (bench_parse_args (argc, argv, &config) != 0)
    return 0; /* --help */

  signal (SIGINT, handle_signal);
  signal (SIGTERM, handle_signal);
  signal (SIGPIPE, SIG_IGN);

  printf ("tetsuo-socket HTTP benchmark\n");
  printf ("URL: %s\n", config.url);
  printf ("Threads: %d\n", config.threads);
  printf ("Requests per thread: %d (+ %d warmup)\n",
          config.requests_per_thread,
          config.warmup_requests);

  /* Create per-thread clients and results */
  SocketHTTPClient_T *clients = calloc (config.threads, sizeof (*clients));
  BenchHTTPThreadResult *results = calloc (config.threads, sizeof (*results));
  BenchHTTPThreadArg *args = calloc (config.threads, sizeof (*args));
  pthread_t *threads = calloc (config.threads, sizeof (*threads));

  if (!clients || !results || !args || !threads)
    {
      fprintf (stderr, "Failed to allocate memory\n");
      return 1;
    }

  /* Initialize clients and result buffers */
  for (int i = 0; i < config.threads; i++)
    {
      clients[i] = create_client (&config);
      if (!clients[i])
        {
          fprintf (stderr, "Failed to create HTTP client for thread %d\n", i);
          return 1;
        }

      if (bench_thread_result_init (&results[i],
                                    (size_t)config.requests_per_thread)
          != 0)
        {
          fprintf (
              stderr, "Failed to allocate result buffer for thread %d\n", i);
          return 1;
        }

      args[i].thread_id = i;
      args[i].config = &config;
      args[i].result = &results[i];
      args[i].client = clients[i];
    }

  /* Run benchmark */
  BenchHTTPResult result;
  memset (&result, 0, sizeof (result));
  result.start_ns = bench_now_ns ();

  for (int i = 0; i < config.threads; i++)
    {
      pthread_create (&threads[i], NULL, bench_worker, &args[i]);
    }

  for (int i = 0; i < config.threads; i++)
    {
      pthread_join (threads[i], NULL);
    }

  result.end_ns = bench_now_ns ();

  /* Collect connection stats from first client (pool is per-client) */
  SocketHTTPClient_PoolStats pool_stats;
  SocketHTTPClient_pool_stats (clients[0], &pool_stats);

  /* Aggregate from all clients */
  for (int i = 0; i < config.threads; i++)
    {
      SocketHTTPClient_PoolStats stats;
      SocketHTTPClient_pool_stats (clients[i], &stats);
      result.connections_created += stats.connections_created;
      result.connections_reused += stats.reused_connections;
    }

  /* Compute statistics */
  bench_compute_stats (results, config.threads, &result);

  /* Print results */
  bench_print_results ("tetsuo-socket", &config, &result);

  /* Write JSON output if requested */
  if (config.output_file)
    {
      if (bench_write_json (
              config.output_file, "tetsuo-socket", &config, &result)
          == 0)
        {
          printf ("Results written to: %s\n", config.output_file);
        }
      else
        {
          fprintf (stderr, "Failed to write JSON output\n");
        }
    }

  /* Cleanup */
  for (int i = 0; i < config.threads; i++)
    {
      SocketHTTPClient_free (&clients[i]);
      bench_thread_result_free (&results[i]);
    }

  free (clients);
  free (results);
  free (args);
  free (threads);

  return 0;
}
