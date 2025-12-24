/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 *
 * resolver_harness.c - DNS resolver harness for protocol fuzzing
 *
 * This harness sends DNS queries to a local dns-fuzz-server
 * which responds with malformed DNS responses.
 *
 * Usage:
 *   ./dns_resolver_harness [-s server] [-p port] [-n iterations]
 *
 * Build:
 *   cmake -B build -DBUILD_PROTOCOL_FUZZ_HARNESSES=ON
 *   cmake --build build --target dns_resolver_harness
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNSResolver.h"
#include "dns/SocketDNSWire.h"

#define DEFAULT_PORT 10053
#define DEFAULT_ITERATIONS 1000

static volatile sig_atomic_t running = 1;
static volatile int completed = 0;
static volatile int failed = 0;

static void
signal_handler (int sig)
{
  (void)sig;
  running = 0;
}

static const char *DOMAINS[] = { "example.com",
                                 "www.example.com",
                                 "test.invalid",
                                 "localhost",
                                 "subdomain.example.com" };
#define NUM_DOMAINS (sizeof (DOMAINS) / sizeof (DOMAINS[0]))

static void
query_callback (SocketDNSResolver_Query_T query,
                const SocketDNSResolver_Result *result, int error,
                void *userdata)
{
  (void)query;
  (void)userdata;

  if (error == 0 && result)
    {
      completed++;
      fprintf (stderr, "[dns] OK: %zu results\n", result->count);
    }
  else
    {
      failed++;
      fprintf (stderr, "[dns] Fail: error=%d\n", error);
    }
}

int
main (int argc, char *argv[])
{
  const char *volatile server = "127.0.0.1";
  volatile int port = DEFAULT_PORT;
  volatile int iterations = DEFAULT_ITERATIONS;
  volatile Arena_T arena = NULL;
  volatile SocketDNSResolver_T resolver = NULL;

  /* Parse args */
  for (int i = 1; i < argc; i++)
    {
      if (strcmp (argv[i], "-s") == 0 && i + 1 < argc)
        server = argv[++i];
      else if (strcmp (argv[i], "-p") == 0 && i + 1 < argc)
        port = atoi (argv[++i]);
      else if (strcmp (argv[i], "-n") == 0 && i + 1 < argc)
        iterations = atoi (argv[++i]);
      else if (strcmp (argv[i], "-h") == 0)
        {
          fprintf (stderr, "Usage: %s [-s server] [-p port] [-n iterations]\n",
                   argv[0]);
          return 0;
        }
    }

  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);
  signal (SIGPIPE, SIG_IGN);

  arena = Arena_new ();

  TRY
  {
    resolver = SocketDNSResolver_new (arena);

    if (SocketDNSResolver_add_nameserver (resolver, server, port) != 0)
      {
        fprintf (stderr, "Failed to add nameserver %s:%d\n", server, port);
        RAISE (SocketDNSResolver_Failed);
      }

    SocketDNSResolver_set_timeout (resolver, 1000);
    SocketDNSResolver_set_retries (resolver, 1);

    fprintf (stderr, "DNS harness: %s:%d, %d iterations\n", server, port,
             iterations);

    for (int i = 0; i < iterations && running; i++)
      {
        const char *domain = DOMAINS[i % NUM_DOMAINS];

        SocketDNSResolver_Query_T query = SocketDNSResolver_resolve (
            resolver, domain, RESOLVER_FLAG_BOTH, query_callback, NULL);

        if (!query)
          {
            failed++;
            continue;
          }

        /* Process until this query completes */
        while (SocketDNSResolver_pending_count (resolver) > 0 && running)
          {
            SocketDNSResolver_process (resolver, 100);
          }

        if (i % 100 == 0)
          fprintf (stderr, "[dns] Progress: %d/%d\n", i, iterations);
      }
  }
  EXCEPT (SocketDNSResolver_Failed)
  {
    fprintf (stderr, "DNS resolver error\n");
  }
  END_TRY;

  fprintf (stderr, "\n=== Summary ===\nCompleted: %d\nFailed: %d\n", completed,
           failed);

  /* Cleanup - cast away volatile for free functions */
  {
    SocketDNSResolver_T res = (SocketDNSResolver_T)resolver;
    Arena_T a = (Arena_T)arena;
    if (res)
      SocketDNSResolver_free (&res);
    if (a)
      Arena_dispose (&a);
  }

  return 0;
}
