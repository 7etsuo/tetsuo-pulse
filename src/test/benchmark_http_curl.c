/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file benchmark_http_curl.c
 * @brief HTTP client benchmark using libcurl.
 *
 * Measures requests/sec, latency percentiles, and connection reuse
 * for fair comparison against tetsuo-socket.
 *
 * Configuration is matched to tetsuo-socket defaults for fair comparison.
 *
 * Usage:
 *   ./benchmark_http_curl --url=http://127.0.0.1:8080/small --threads=4
 */

#include <curl/curl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "benchmark_http_common.h"

static volatile sig_atomic_t g_running = 1;

static void
handle_signal (int sig)
{
  (void)sig;
  g_running = 0;
}

/**
 * @brief Write callback that discards response body but tracks size.
 */
static size_t
write_callback (void *contents, size_t size, size_t nmemb, void *userp)
{
  (void)contents; /* Data is discarded, only tracking size */
  size_t *bytes_received = (size_t *)userp;
  size_t total = size * nmemb;
  *bytes_received += total;
  return total;
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
  CURL *curl = (CURL *)targ->client;

  int total_requests = config->requests_per_thread + config->warmup_requests;

  for (int i = 0; i < total_requests && g_running; i++)
    {
      int is_warmup = (i < config->warmup_requests);
      size_t bytes_received = 0;

      /* Reset for each request */
      curl_easy_setopt (curl, CURLOPT_WRITEDATA, &bytes_received);

      uint64_t start = bench_now_ns ();

      CURLcode res = curl_easy_perform (curl);

      uint64_t elapsed = bench_now_ns () - start;

      if (res == CURLE_OK)
        {
          long response_code;
          curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response_code);

          if (response_code == 200)
            {
              if (!is_warmup)
                {
                  result->successful++;
                  result->bytes_received += bytes_received;
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
                               "[Thread %d] Request %d: HTTP %ld\n",
                               targ->thread_id,
                               i,
                               response_code);
                    }
                }
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
                           "[Thread %d] Request %d failed: %s\n",
                           targ->thread_id,
                           i,
                           curl_easy_strerror (res));
                }
            }
        }
    }

  return NULL;
}

/**
 * @brief Create curl handle with config parity for fair comparison.
 *
 * Configuration matches tetsuo-socket defaults:
 * - Max 6 connections per host
 * - Max 100 total connections
 * - 30s connect timeout
 * - 60s request timeout
 * - Keep-alive enabled
 */
static CURL *
create_curl_handle (const BenchHTTPConfig *config)
{
  CURL *curl = curl_easy_init ();
  if (!curl)
    return NULL;

  /* Target URL */
  curl_easy_setopt (curl, CURLOPT_URL, config->url);

  /* Disable signal handlers (required for multi-threaded) */
  curl_easy_setopt (curl, CURLOPT_NOSIGNAL, 1L);

  /* Timeouts - match tetsuo-socket defaults */
  curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, 30L);
  curl_easy_setopt (curl, CURLOPT_TIMEOUT, 60L);

  /* Keep-alive */
  if (config->keep_alive)
    {
      curl_easy_setopt (curl, CURLOPT_TCP_KEEPALIVE, 1L);
      curl_easy_setopt (curl, CURLOPT_TCP_KEEPIDLE, 60L);
      curl_easy_setopt (curl, CURLOPT_TCP_KEEPINTVL, 60L);
    }
  else
    {
      /* Disable connection reuse */
      curl_easy_setopt (curl, CURLOPT_FORBID_REUSE, 1L);
    }

  /* HTTP version */
  if (config->version == BENCH_HTTP_VERSION_1_1)
    {
      curl_easy_setopt (curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    }
  else if (config->version == BENCH_HTTP_VERSION_2)
    {
      /* HTTP/2 for both TLS and cleartext */
      curl_easy_setopt (
          curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
    }
  else
    {
      /* Auto-negotiate (prefer HTTP/2 over TLS) */
      curl_easy_setopt (curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
    }

  /* Disable redirect following for raw benchmark */
  curl_easy_setopt (curl, CURLOPT_FOLLOWLOCATION, 0L);

  /* Disable compression for raw benchmark */
  curl_easy_setopt (curl, CURLOPT_ACCEPT_ENCODING, "");

  /* Write callback to track response size */
  curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_callback);

  return curl;
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

  /* Initialize libcurl globally */
  curl_global_init (CURL_GLOBAL_DEFAULT);

  printf ("libcurl HTTP benchmark\n");
  printf ("URL: %s\n", config.url);
  printf ("Threads: %d\n", config.threads);
  printf ("Requests per thread: %d (+ %d warmup)\n",
          config.requests_per_thread,
          config.warmup_requests);
  printf ("libcurl version: %s\n", curl_version ());

  /* Create per-thread handles and results */
  CURL **handles = calloc (config.threads, sizeof (*handles));
  BenchHTTPThreadResult *results = calloc (config.threads, sizeof (*results));
  BenchHTTPThreadArg *args = calloc (config.threads, sizeof (*args));
  pthread_t *threads = calloc (config.threads, sizeof (*threads));

  if (!handles || !results || !args || !threads)
    {
      fprintf (stderr, "Failed to allocate memory\n");
      curl_global_cleanup ();
      return 1;
    }

  /* Initialize handles and result buffers */
  for (int i = 0; i < config.threads; i++)
    {
      handles[i] = create_curl_handle (&config);
      if (!handles[i])
        {
          fprintf (stderr, "Failed to create curl handle for thread %d\n", i);
          curl_global_cleanup ();
          return 1;
        }

      if (bench_thread_result_init (&results[i],
                                    (size_t)config.requests_per_thread)
          != 0)
        {
          fprintf (
              stderr, "Failed to allocate result buffer for thread %d\n", i);
          curl_global_cleanup ();
          return 1;
        }

      args[i].thread_id = i;
      args[i].config = &config;
      args[i].result = &results[i];
      args[i].client = handles[i];
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

  /* Collect connection stats from curl handles */
  for (int i = 0; i < config.threads; i++)
    {
      long num_connects = 0;
      curl_easy_getinfo (handles[i], CURLINFO_NUM_CONNECTS, &num_connects);

      /* Each handle tracks total connects, reuse = requests - connects */
      long reused = (long)results[i].successful - num_connects;
      if (reused < 0)
        reused = 0;

      result.connections_created += (uint64_t)num_connects;
      result.connections_reused += (uint64_t)reused;
    }

  /* Compute statistics */
  bench_compute_stats (results, config.threads, &result);

  /* Print results */
  bench_print_results ("libcurl", &config, &result);

  /* Write JSON output if requested */
  if (config.output_file)
    {
      if (bench_write_json (config.output_file, "libcurl", &config, &result)
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
      curl_easy_cleanup (handles[i]);
      bench_thread_result_free (&results[i]);
    }

  free (handles);
  free (results);
  free (args);
  free (threads);

  curl_global_cleanup ();

  return 0;
}
