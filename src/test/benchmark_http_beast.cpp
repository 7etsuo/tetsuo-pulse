/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file benchmark_http_beast.cpp
 * @brief HTTP client benchmark using Boost.Beast.
 *
 * Measures requests/sec, latency percentiles, and connection reuse
 * for comparison against tetsuo-socket and libcurl.
 *
 * Usage:
 *   ./benchmark_http_beast --url=http://127.0.0.1:8080/small --threads=4
 */

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

/* Include C benchmark infrastructure */
extern "C"
{
#include "benchmark_http_common.h"
}

static std::atomic<bool> g_running{ true };

static void
handle_signal (int sig)
{
  (void)sig;
  g_running = false;
}

/**
 * @brief Parse URL into components.
 */
static bool
parse_url (const std::string &url, std::string &host, std::string &port,
           std::string &target)
{
  size_t pos = 0;

  /* Skip scheme */
  if (url.compare (0, 7, "http://") == 0)
    {
      pos = 7;
      port = "80";
    }
  else if (url.compare (0, 8, "https://") == 0)
    {
      pos = 8;
      port = "443";
    }
  else
    {
      return false;
    }

  /* Find host end */
  size_t host_end = url.find ('/', pos);
  if (host_end == std::string::npos)
    {
      host_end = url.length ();
      target = "/";
    }
  else
    {
      target = url.substr (host_end);
    }

  std::string host_port = url.substr (pos, host_end - pos);

  /* Check for port */
  size_t colon = host_port.find (':');
  if (colon != std::string::npos)
    {
      host = host_port.substr (0, colon);
      port = host_port.substr (colon + 1);
    }
  else
    {
      host = host_port;
    }

  return !host.empty ();
}

/**
 * @brief Worker thread for concurrent benchmarking.
 */
static void
bench_worker (BenchHTTPThreadArg *targ)
{
  const BenchHTTPConfig *config = targ->config;
  BenchHTTPThreadResult *result = targ->result;

  /* Parse URL */
  std::string host, port, target;
  if (!parse_url (config->url, host, port, target))
    {
      std::cerr << "Failed to parse URL: " << config->url << "\n";
      return;
    }

  try
    {
      /* Create I/O context */
      net::io_context ioc;

      /* Resolver and socket */
      tcp::resolver resolver (ioc);
      beast::tcp_stream stream (ioc);

      /* Resolve */
      auto const results = resolver.resolve (host, port);

      /* Connect */
      stream.connect (results);

      /* Set timeout */
      stream.expires_after (std::chrono::seconds (60));

      int total_requests
          = config->requests_per_thread + config->warmup_requests;

      for (int i = 0; i < total_requests && g_running; i++)
        {
          bool is_warmup = (i < config->warmup_requests);

          /* Build request */
          http::request<http::empty_body> req{ http::verb::get, target, 11 };
          req.set (http::field::host, host);
          req.set (http::field::user_agent, BOOST_BEAST_VERSION_STRING);
          req.set (http::field::connection,
                   config->keep_alive ? "keep-alive" : "close");

          /* Response container */
          beast::flat_buffer buffer;
          http::response<http::dynamic_body> res;

          auto start = bench_now_ns ();

          try
            {
              /* Send request */
              http::write (stream, req);

              /* Receive response */
              http::read (stream, buffer, res);

              auto elapsed = bench_now_ns () - start;

              if (res.result () == http::status::ok)
                {
                  if (!is_warmup)
                    {
                      result->successful++;
                      result->bytes_received += res.body ().size ();
                      bench_record_latency (result, elapsed);
                    }
                }
              else
                {
                  if (!is_warmup)
                    result->failed++;
                }
            }
          catch (const std::exception &e)
            {
              if (!is_warmup)
                result->failed++;

              /* Try to reconnect for next request */
              if (config->keep_alive && i < total_requests - 1)
                {
                  try
                    {
                      stream.close ();
                      stream.connect (results);
                    }
                  catch (...)
                    {
                    }
                }
            }

          /* If not keep-alive, reconnect for each request */
          if (!config->keep_alive && i < total_requests - 1)
            {
              stream.close ();
              stream.connect (results);
            }
        }

      /* Gracefully close */
      beast::error_code ec;
      stream.socket ().shutdown (tcp::socket::shutdown_both, ec);
    }
  catch (const std::exception &e)
    {
      std::cerr << "Thread " << targ->thread_id << " error: " << e.what ()
                << "\n";
    }
}

int
main (int argc, char **argv)
{
  BenchHTTPConfig config;
  bench_config_defaults (&config);

  if (bench_parse_args (argc, argv, &config) != 0)
    return 0; /* --help */

  std::signal (SIGINT, handle_signal);
  std::signal (SIGTERM, handle_signal);
  std::signal (SIGPIPE, SIG_IGN);

  std::cout << "Boost.Beast HTTP benchmark\n";
  std::cout << "URL: " << config.url << "\n";
  std::cout << "Threads: " << config.threads << "\n";
  std::cout << "Requests per thread: " << config.requests_per_thread << " (+ "
            << config.warmup_requests << " warmup)\n";
  std::cout << "Boost.Beast version: " << BOOST_BEAST_VERSION_STRING << "\n";

  /* Create per-thread results */
  std::vector<BenchHTTPThreadResult> results (config.threads);
  std::vector<BenchHTTPThreadArg> args (config.threads);
  std::vector<std::thread> threads;

  /* Initialize result buffers */
  for (int i = 0; i < config.threads; i++)
    {
      if (bench_thread_result_init (&results[i],
                                    (size_t)config.requests_per_thread)
          != 0)
        {
          std::cerr << "Failed to allocate result buffer for thread " << i
                    << "\n";
          return 1;
        }

      args[i].thread_id = i;
      args[i].config = &config;
      args[i].result = &results[i];
      args[i].client = nullptr;
    }

  /* Run benchmark */
  BenchHTTPResult result;
  std::memset (&result, 0, sizeof (result));
  result.start_ns = bench_now_ns ();

  for (int i = 0; i < config.threads; i++)
    {
      threads.emplace_back (bench_worker, &args[i]);
    }

  for (auto &t : threads)
    {
      t.join ();
    }

  result.end_ns = bench_now_ns ();

  /* Beast uses one connection per thread with keep-alive */
  result.connections_created = config.threads;
  result.connections_reused
      = config.keep_alive
            ? (config.threads * config.requests_per_thread - config.threads)
            : 0;

  /* Compute statistics */
  bench_compute_stats (results.data (), config.threads, &result);

  /* Print results */
  bench_print_results ("Boost.Beast", &config, &result);

  /* Write JSON output if requested */
  if (config.output_file)
    {
      if (bench_write_json (config.output_file, "boost-beast", &config,
                            &result)
          == 0)
        {
          std::cout << "Results written to: " << config.output_file << "\n";
        }
      else
        {
          std::cerr << "Failed to write JSON output\n";
        }
    }

  /* Cleanup */
  for (int i = 0; i < config.threads; i++)
    {
      bench_thread_result_free (&results[i]);
    }

  return 0;
}
