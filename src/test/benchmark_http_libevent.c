/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file benchmark_http_libevent.c
 * @brief HTTP client benchmark using libevent.
 *
 * Measures requests/sec, latency percentiles, and connection reuse
 * for comparison against tetsuo-socket and libcurl.
 *
 * Usage:
 *   ./benchmark_http_libevent --url=http://127.0.0.1:8080/small --threads=4
 */

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <event2/keyvalq_struct.h>
#include <event2/util.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "benchmark_http_common.h"

static volatile sig_atomic_t g_running = 1;

static void
handle_signal (int sig)
{
  (void)sig;
  g_running = 0;
}

/**
 * @brief Per-request context for async tracking.
 */
typedef struct
{
  BenchHTTPThreadResult *result;
  uint64_t start_ns;
  int is_warmup;
  int *pending;
  struct event_base *base;
} RequestContext;

/**
 * @brief HTTP request callback.
 */
static void
http_request_done (struct evhttp_request *req, void *arg)
{
  RequestContext *ctx = (RequestContext *)arg;
  uint64_t elapsed = bench_now_ns () - ctx->start_ns;

  if (req == NULL)
    {
      /* Connection failed */
      if (!ctx->is_warmup)
        ctx->result->failed++;
    }
  else
    {
      int code = evhttp_request_get_response_code (req);
      if (code == 200)
        {
          if (!ctx->is_warmup)
            {
              ctx->result->successful++;
              struct evbuffer *buf = evhttp_request_get_input_buffer (req);
              ctx->result->bytes_received += evbuffer_get_length (buf);
              bench_record_latency (ctx->result, elapsed);
            }
        }
      else
        {
          if (!ctx->is_warmup)
            ctx->result->failed++;
        }
    }

  (*ctx->pending)--;
  if (*ctx->pending == 0)
    event_base_loopbreak (ctx->base);

  free (ctx);
}

/**
 * @brief Parse URL into components.
 */
static int
parse_url (const char *url, char *host, size_t host_len, int *port,
           char *path, size_t path_len)
{
  /* Simple URL parser for http://host:port/path */
  const char *p = url;

  /* Skip scheme */
  if (strncmp (p, "http://", 7) == 0)
    p += 7;
  else if (strncmp (p, "https://", 8) == 0)
    {
      p += 8;
      *port = 443;
    }
  else
    return -1;

  /* Extract host */
  const char *host_end = strchr (p, ':');
  const char *path_start = strchr (p, '/');

  if (host_end && (!path_start || host_end < path_start))
    {
      size_t len = host_end - p;
      if (len >= host_len)
        return -1;
      memcpy (host, p, len);
      host[len] = '\0';
      *port = atoi (host_end + 1);
      p = path_start ? path_start : "";
    }
  else if (path_start)
    {
      size_t len = path_start - p;
      if (len >= host_len)
        return -1;
      memcpy (host, p, len);
      host[len] = '\0';
      if (*port == 0)
        *port = 80;
      p = path_start;
    }
  else
    {
      size_t len = strlen (p);
      if (len >= host_len)
        return -1;
      strcpy (host, p);
      if (*port == 0)
        *port = 80;
      p = "/";
    }

  /* Copy path */
  if (strlen (p) == 0)
    p = "/";
  if (strlen (p) >= path_len)
    return -1;
  strcpy (path, p);

  return 0;
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

  /* Parse URL */
  char host[256];
  char path[1024];
  int port = 0;

  if (parse_url (config->url, host, sizeof (host), &port, path, sizeof (path))
      != 0)
    {
      fprintf (stderr, "Failed to parse URL: %s\n", config->url);
      return NULL;
    }

  /* Create event base */
  struct event_base *base = event_base_new ();
  if (!base)
    {
      fprintf (stderr, "Failed to create event base\n");
      return NULL;
    }

  /* Create HTTP connection */
  struct evhttp_connection *conn
      = evhttp_connection_base_new (base, NULL, host, port);
  if (!conn)
    {
      fprintf (stderr, "Failed to create HTTP connection\n");
      event_base_free (base);
      return NULL;
    }

  /* Set connection options */
  evhttp_connection_set_timeout (conn, 60);
  if (config->keep_alive)
    evhttp_connection_set_retries (conn, 0);

  int total_requests = config->requests_per_thread + config->warmup_requests;
  int pending = 0;

  /* Send requests */
  for (int i = 0; i < total_requests && g_running; i++)
    {
      int is_warmup = (i < config->warmup_requests);

      /* Create context first */
      RequestContext *ctx = malloc (sizeof (*ctx));
      if (!ctx)
        {
          if (!is_warmup)
            result->failed++;
          continue;
        }

      ctx->result = result;
      ctx->start_ns = bench_now_ns ();
      ctx->is_warmup = is_warmup;
      ctx->pending = &pending;
      ctx->base = base;

      /* Create request with callback */
      struct evhttp_request *req
          = evhttp_request_new (http_request_done, ctx);
      if (!req)
        {
          free (ctx);
          if (!is_warmup)
            result->failed++;
          continue;
        }

      /* Add headers */
      struct evkeyvalq *headers = evhttp_request_get_output_headers (req);
      evhttp_add_header (headers, "Host", host);
      evhttp_add_header (headers, "Connection",
                         config->keep_alive ? "keep-alive" : "close");

      /* Send request */
      pending++;
      if (evhttp_make_request (conn, req, EVHTTP_REQ_GET, path) != 0)
        {
          pending--;
          if (!is_warmup)
            result->failed++;
          free (ctx);
          continue;
        }
    }

  /* Wait for all requests to complete */
  while (pending > 0 && g_running)
    {
      event_base_loop (base, EVLOOP_ONCE);
    }

  /* Cleanup */
  evhttp_connection_free (conn);
  event_base_free (base);

  return NULL;
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

  printf ("libevent HTTP benchmark\n");
  printf ("URL: %s\n", config.url);
  printf ("Threads: %d\n", config.threads);
  printf ("Requests per thread: %d (+ %d warmup)\n", config.requests_per_thread,
          config.warmup_requests);
  printf ("libevent version: %s\n", event_get_version ());

  /* Create per-thread results */
  BenchHTTPThreadResult *results = calloc (config.threads, sizeof (*results));
  BenchHTTPThreadArg *args = calloc (config.threads, sizeof (*args));
  pthread_t *threads = calloc (config.threads, sizeof (*threads));

  if (!results || !args || !threads)
    {
      fprintf (stderr, "Failed to allocate memory\n");
      return 1;
    }

  /* Initialize result buffers */
  for (int i = 0; i < config.threads; i++)
    {
      if (bench_thread_result_init (&results[i],
                                    (size_t)config.requests_per_thread)
          != 0)
        {
          fprintf (stderr, "Failed to allocate result buffer for thread %d\n",
                   i);
          return 1;
        }

      args[i].thread_id = i;
      args[i].config = &config;
      args[i].result = &results[i];
      args[i].client = NULL;
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

  /* libevent doesn't expose connection stats easily, estimate */
  result.connections_created = config.threads;
  result.connections_reused
      = config.keep_alive ? (config.threads * config.requests_per_thread
                             - config.threads)
                          : 0;

  /* Compute statistics */
  bench_compute_stats (results, config.threads, &result);

  /* Print results */
  bench_print_results ("libevent", &config, &result);

  /* Write JSON output if requested */
  if (config.output_file)
    {
      if (bench_write_json (config.output_file, "libevent", &config, &result)
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
      bench_thread_result_free (&results[i]);
    }

  free (results);
  free (args);
  free (threads);

  return 0;
}
