/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "dns/SocketDNS.h"
#include "socket/SocketCommon.h"

#define DNS_STRESS_NUM_REQUESTS 10000
#define DNS_STRESS_NUM_THREADS 20
#define DNS_STRESS_HOST_PREFIX "example"
#define DNS_STRESS_PORT 80

static volatile int dns_running = 1;
static pthread_mutex_t dns_stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static long total_requests = 0;
static long completed_requests = 0;
static long timed_out_requests = 0;
static long failed_requests = 0;

/* Thread function for DNS stress */
static void *
dns_stress_thread (void *arg)
{
  int thread_id = *(int *)arg;
  free (arg);

  Arena_T arena = Arena_new ();
  if (!arena)
    {
      fprintf (stderr, "Thread %d: Failed to allocate arena\n", thread_id);
      return NULL;
    }

  TRY
  {
    SocketDNS_T dns = SocketDNS_new ();
    if (!dns)
      {
        Arena_dispose (&arena);
        fprintf (
            stderr, "Thread %d: Failed to create DNS resolver\n", thread_id);
        return NULL;
      }

    for (int i = 0;
         i < DNS_STRESS_NUM_REQUESTS / DNS_STRESS_NUM_THREADS && dns_running;
         i++)
      {
        char hostname[256];
        Request_T req;

        /* Generate random hostname for stress */
        snprintf (hostname,
                  sizeof (hostname),
                  "%s%d.%d.com",
                  DNS_STRESS_HOST_PREFIX,
                  thread_id,
                  i);

        req = SocketDNS_resolve (dns, hostname, DNS_STRESS_PORT, NULL, NULL);
        if (!req)
          {
            pthread_mutex_lock (&dns_stats_mutex);
            failed_requests++;
            total_requests++;
            pthread_mutex_unlock (&dns_stats_mutex);
            continue;
          }

        pthread_mutex_lock (&dns_stats_mutex);
        total_requests++;
        pthread_mutex_unlock (&dns_stats_mutex);

        /* Poll for completion */
        int attempts = 0;
        while (dns_running && attempts < 100)
          { // Max 10 seconds polling
            struct addrinfo *result = SocketDNS_getresult (dns, req);
            if (result)
              {
                SocketCommon_free_addrinfo (result);
                pthread_mutex_lock (&dns_stats_mutex);
                completed_requests++;
                pthread_mutex_unlock (&dns_stats_mutex);
                break;
              }

            attempts++;
            usleep (100000); // 100ms poll interval
          }

        if (attempts >= 100)
          {
            pthread_mutex_lock (&dns_stats_mutex);
            timed_out_requests++;
            pthread_mutex_unlock (&dns_stats_mutex);
            SocketDNS_cancel (dns, req);
          }

        SocketDNS_free (
            &dns); // Free and recreate for next iteration? No, reuse
      }

    SocketDNS_free (&dns);
  }
  EXCEPT (SocketDNS_Failed)
  {
    fprintf (stderr, "Thread %d: DNS operation failed\n", thread_id);
  }
  EXCEPT (Arena_Failed)
  {
    fprintf (stderr, "Thread %d: Arena failed\n", thread_id);
  }
  FINALLY
  {
    Arena_dispose (&arena);
  }
  END_TRY;

  return NULL;
}

int
main ()
{
  signal (SIGPIPE, SIG_IGN);

  printf ("Starting DNS stress test: %d requests across %d threads\n",
          DNS_STRESS_NUM_REQUESTS,
          DNS_STRESS_NUM_THREADS);

  pthread_t *threads = calloc (DNS_STRESS_NUM_THREADS, sizeof (pthread_t));
  int *thread_ids = malloc (DNS_STRESS_NUM_THREADS * sizeof (int));

  for (int i = 0; i < DNS_STRESS_NUM_THREADS; i++)
    {
      thread_ids[i] = i;
      pthread_create (&threads[i], NULL, dns_stress_thread, &thread_ids[i]);
    }

  /* Wait for completion */
  sleep (10); // Allow time for stress
  dns_running = 0;

  for (int i = 0; i < DNS_STRESS_NUM_THREADS; i++)
    {
      pthread_join (threads[i], NULL);
    }

  /* Report results */
  pthread_mutex_lock (&dns_stats_mutex);
  printf ("\nDNS Stress Test Results:\n");
  printf ("Total requests: %ld\n", total_requests);
  printf ("Completed: %ld (%.1f%%)\n",
          completed_requests,
          total_requests > 0 ? (double)completed_requests / total_requests * 100
                             : 0);
  printf ("Timed out: %ld (%.1f%%)\n",
          timed_out_requests,
          total_requests > 0 ? (double)timed_out_requests / total_requests * 100
                             : 0);
  printf ("Failed: %ld (%.1f%%)\n",
          failed_requests,
          total_requests > 0 ? (double)failed_requests / total_requests * 100
                             : 0);
  pthread_mutex_unlock (&dns_stats_mutex);

  printf ("No socket leaks check - DNS uses internal sockets.\n");
  free (threads);
  free (thread_ids);

  return 0;
}
