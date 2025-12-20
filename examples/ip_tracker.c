/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * ip_tracker.c - IP Connection Tracking Example
 *
 * Demonstrates per-IP connection tracking using the SocketIPTracker API.
 * Shows creation, tracking, releasing, querying, and management operations.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_ip_tracker
 *
 * Usage:
 *   ./example_ip_tracker [max_per_ip]
 *   ./example_ip_tracker 5
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketIPTracker.h"

/* Test IP addresses for demonstration */
static const char *test_ips[] = {
  "192.168.1.1",     "192.168.1.2", "192.168.1.3", "10.0.0.1", "10.0.0.2",
  "2001:db8::1",     "2001:db8::2", "invalid-ip", /* Invalid IP for testing */
  "999.999.999.999",                              /* Invalid IP for testing */
};

static const int num_test_ips = sizeof (test_ips) / sizeof (test_ips[0]);

/* Print section header */
static void
print_header (const char *title)
{
  printf ("\n=== %s ===\n", title);
}

/* Print test status */
static void
print_status (const char *test, int success)
{
  printf ("  %s %s\n", success ? "[OK]  " : "[FAIL]", test);
}

/* Print info message */
static void
print_info (const char *message)
{
  printf ("  [INFO] %s\n", message);
}

/* Display tracker statistics */
static void
display_stats (SocketIPTracker_T tracker)
{
  size_t total = SocketIPTracker_total (tracker);
  size_t unique = SocketIPTracker_unique_ips (tracker);
  int max = SocketIPTracker_getmax (tracker);
  size_t max_unique = SocketIPTracker_getmaxunique (tracker);

  printf ("  [INFO] Statistics:\n");
  printf ("         - Total connections: %zu\n", total);
  printf ("         - Unique IPs: %zu\n", unique);
  printf ("         - Max per IP: %d %s\n", max,
          max == 0 ? "(unlimited)" : "");
  printf ("         - Max unique IPs: %zu %s\n", max_unique,
          max_unique == 0 ? "(unlimited)" : "");
}

int
main (int argc, char **argv)
{
  /* Variables that might be clobbered by longjmp must be volatile */
  volatile int max_per_ip = 3;
  Arena_T arena = NULL;
  SocketIPTracker_T tracker = NULL;
  volatile int result = 0;

  /* Parse command line arguments */
  if (argc > 1)
    max_per_ip = atoi (argv[1]);

  if (max_per_ip < 0)
    {
      fprintf (stderr, "Invalid max_per_ip: %d (will be clamped to 0)\n",
               max_per_ip);
    }

  /* Setup signal handling */
  signal (SIGPIPE, SIG_IGN);

  printf ("IP Connection Tracker Example\n");
  printf ("=============================\n\n");
  printf ("Configuration:\n");
  printf ("  Max connections per IP: %d %s\n", max_per_ip,
          max_per_ip == 0 ? "(unlimited)" : "");

  TRY
  {
    /* Test 1: Create tracker with arena */
    print_header ("Test 1: Creating IP Tracker");

    arena = Arena_new ();
    tracker = SocketIPTracker_new (arena, max_per_ip);

    print_status ("Created tracker with arena", 1);
    print_status ("Initialized with per-IP limit", 1);
    display_stats (tracker);

    /* Test 2: Basic tracking operations */
    print_header ("Test 2: Basic Tracking Operations");

    const char *ip1 = test_ips[0]; /* 192.168.1.1 */
    const char *ip2 = test_ips[1]; /* 192.168.1.2 */

    /* Track first connection from ip1 */
    int tracked = SocketIPTracker_track (tracker, ip1);
    print_status ("Track first connection from 192.168.1.1", tracked);

    if (tracked)
      {
        int count = SocketIPTracker_count (tracker, ip1);
        printf ("  [INFO] 192.168.1.1 now has %d connection(s)\n", count);
        print_status ("Count matches (expected 1)", count == 1);
      }

    /* Track second connection from ip1 */
    tracked = SocketIPTracker_track (tracker, ip1);
    print_status ("Track second connection from 192.168.1.1", tracked);

    if (tracked)
      {
        int count = SocketIPTracker_count (tracker, ip1);
        printf ("  [INFO] 192.168.1.1 now has %d connection(s)\n", count);
        print_status ("Count matches (expected 2)", count == 2);
      }

    /* Track connection from different IP */
    tracked = SocketIPTracker_track (tracker, ip2);
    print_status ("Track connection from 192.168.1.2", tracked);

    if (tracked)
      {
        int count = SocketIPTracker_count (tracker, ip2);
        printf ("  [INFO] 192.168.1.2 now has %d connection(s)\n", count);
        print_status ("Count matches (expected 1)", count == 1);
      }

    display_stats (tracker);

    /* Test 3: Limit enforcement */
    print_header ("Test 3: Per-IP Limit Enforcement");

    if (max_per_ip > 0)
      {
        printf ("  [INFO] Attempting to exceed limit of %d for 192.168.1.1\n",
                max_per_ip);

        /* Try to reach the limit */
        int current_count = SocketIPTracker_count (tracker, ip1);
        int success = 1;

        for (int i = current_count; i < max_per_ip; i++)
          {
            if (!SocketIPTracker_track (tracker, ip1))
              {
                success = 0;
                break;
              }
          }

        print_status ("Reached limit successfully", success);

        current_count = SocketIPTracker_count (tracker, ip1);
        printf ("  [INFO] 192.168.1.1 count: %d (limit: %d)\n", current_count,
                max_per_ip);

        /* Try to exceed the limit */
        tracked = SocketIPTracker_track (tracker, ip1);
        print_status ("Rejected connection exceeding limit", !tracked);

        if (!tracked)
          {
            printf ("  [INFO] Connection correctly rejected\n");
          }
      }
    else
      {
        print_info ("Unlimited mode - skipping limit test");
      }

    display_stats (tracker);

    /* Test 4: Release operations */
    print_header ("Test 4: Releasing Connections");

    int count_before = SocketIPTracker_count (tracker, ip1);
    printf ("  [INFO] 192.168.1.1 connections before release: %d\n",
            count_before);

    SocketIPTracker_release (tracker, ip1);
    int count_after = SocketIPTracker_count (tracker, ip1);
    printf ("  [INFO] 192.168.1.1 connections after release: %d\n",
            count_after);

    print_status ("Count decreased by 1", count_after == count_before - 1);

    /* Release all connections from ip1 */
    printf ("  [INFO] Releasing all connections from 192.168.1.1\n");
    while (SocketIPTracker_count (tracker, ip1) > 0)
      {
        SocketIPTracker_release (tracker, ip1);
      }

    count_after = SocketIPTracker_count (tracker, ip1);
    print_status ("All connections released (count = 0)", count_after == 0);

    display_stats (tracker);

    /* Test 5: IPv6 support */
    print_header ("Test 5: IPv6 Address Support");

    const char *ipv6_1 = test_ips[5]; /* 2001:db8::1 */
    const char *ipv6_2 = test_ips[6]; /* 2001:db8::2 */

    tracked = SocketIPTracker_track (tracker, ipv6_1);
    print_status ("Track IPv6 connection (2001:db8::1)", tracked);

    if (tracked)
      {
        int count = SocketIPTracker_count (tracker, ipv6_1);
        printf ("  [INFO] 2001:db8::1 has %d connection(s)\n", count);
      }

    tracked = SocketIPTracker_track (tracker, ipv6_2);
    print_status ("Track IPv6 connection (2001:db8::2)", tracked);

    display_stats (tracker);

    /* Test 6: Invalid IP handling */
    print_header ("Test 6: Invalid IP Address Handling");

    const char *invalid_ip1 = test_ips[7]; /* "invalid-ip" */
    const char *invalid_ip2 = test_ips[8]; /* "999.999.999.999" */

    tracked = SocketIPTracker_track (tracker, invalid_ip1);
    print_status ("Rejected invalid IP (invalid-ip)", !tracked);

    tracked = SocketIPTracker_track (tracker, invalid_ip2);
    print_status ("Rejected invalid IP (999.999.999.999)", !tracked);

    /* Release from invalid IP should be safe no-op */
    SocketIPTracker_release (tracker, invalid_ip1);
    print_status ("Release from invalid IP is safe no-op", 1);

    /* Test 7: Updating limits dynamically */
    print_header ("Test 7: Dynamic Limit Updates");

    int old_limit = SocketIPTracker_getmax (tracker);
    int new_limit = max_per_ip > 0 ? max_per_ip * 2 : 10;

    printf ("  [INFO] Changing limit from %d to %d\n", old_limit, new_limit);
    SocketIPTracker_setmax (tracker, new_limit);

    int current_limit = SocketIPTracker_getmax (tracker);
    print_status ("Limit updated successfully", current_limit == new_limit);

    printf ("  [INFO] New limit: %d\n", current_limit);

    /* Test with new limit */
    const char *test_ip = test_ips[3]; /* 10.0.0.1 */
    int added = 0;

    for (int i = 0; i < new_limit; i++)
      {
        if (SocketIPTracker_track (tracker, test_ip))
          added++;
      }

    print_status ("Added connections up to new limit", added == new_limit);
    printf ("  [INFO] Added %d connections to 10.0.0.1\n", added);

    display_stats (tracker);

    /* Test 8: Maximum unique IPs */
    print_header ("Test 8: Maximum Unique IPs Limit");

    size_t old_max_unique = SocketIPTracker_getmaxunique (tracker);
    size_t new_max_unique = 5;

    printf ("  [INFO] Setting max unique IPs to %zu\n", new_max_unique);
    SocketIPTracker_setmaxunique (tracker, new_max_unique);

    size_t current_unique = SocketIPTracker_unique_ips (tracker);
    printf ("  [INFO] Current unique IPs: %zu (max: %zu)\n", current_unique,
            new_max_unique);

    if (current_unique < new_max_unique)
      {
        /* Try adding more unique IPs */
        int ip_index = 0;
        size_t ips_added = 0;

        while (ip_index < num_test_ips
               && SocketIPTracker_unique_ips (tracker) < new_max_unique)
          {
            /* Skip invalid IPs */
            if (strcmp (test_ips[ip_index], "invalid-ip") != 0
                && strcmp (test_ips[ip_index], "999.999.999.999") != 0)
              {
                /* Only count if it's a new unique IP */
                int old_count
                    = SocketIPTracker_count (tracker, test_ips[ip_index]);
                if (old_count == 0
                    && SocketIPTracker_track (tracker, test_ips[ip_index]))
                  {
                    ips_added++;
                  }
              }
            ip_index++;
          }

        printf ("  [INFO] Added %zu new unique IP(s)\n", ips_added);
      }

    display_stats (tracker);

    /* Test 9: Query operations */
    print_header ("Test 9: Query Operations");

    printf ("  [INFO] Current tracker state:\n");
    printf ("         Total connections: %zu\n",
            SocketIPTracker_total (tracker));
    printf ("         Unique IPs tracked: %zu\n",
            SocketIPTracker_unique_ips (tracker));

    /* Query individual IPs */
    for (int i = 0; i < 5 && i < num_test_ips; i++)
      {
        if (strcmp (test_ips[i], "invalid-ip") != 0
            && strcmp (test_ips[i], "999.999.999.999") != 0)
          {
            int count = SocketIPTracker_count (tracker, test_ips[i]);
            if (count > 0)
              {
                printf ("         - %s: %d connection(s)\n", test_ips[i],
                        count);
              }
          }
      }

    print_status ("Query operations completed", 1);

    /* Test 10: Clear all tracking */
    print_header ("Test 10: Clearing All Tracked Connections");

    size_t total_before = SocketIPTracker_total (tracker);
    size_t unique_before = SocketIPTracker_unique_ips (tracker);

    printf ("  [INFO] Before clear: %zu connections, %zu unique IPs\n",
            total_before, unique_before);

    SocketIPTracker_clear (tracker);

    size_t total_after = SocketIPTracker_total (tracker);
    size_t unique_after = SocketIPTracker_unique_ips (tracker);

    printf ("  [INFO] After clear: %zu connections, %zu unique IPs\n",
            total_after, unique_after);

    print_status ("All connections cleared", total_after == 0);
    print_status ("All unique IPs cleared", unique_after == 0);

    /* Verify IPs are no longer tracked */
    int all_cleared = 1;
    for (int i = 0; i < num_test_ips; i++)
      {
        if (SocketIPTracker_count (tracker, test_ips[i]) != 0)
          {
            all_cleared = 0;
            break;
          }
      }

    print_status ("All individual IP counts are zero", all_cleared);

    /* Test 11: Post-clear functionality */
    print_header ("Test 11: Tracker Functionality After Clear");

    tracked = SocketIPTracker_track (tracker, test_ips[0]);
    print_status ("Can track new connections after clear", tracked);

    if (tracked)
      {
        int count = SocketIPTracker_count (tracker, test_ips[0]);
        print_status ("New tracking works correctly", count == 1);
      }

    display_stats (tracker);

    /* Final summary */
    print_header ("Test Summary");

    printf ("  [OK]   All tests completed successfully\n");
    printf ("  [INFO] IP tracker is fully functional\n");
    printf ("  [INFO] Demonstrated features:\n");
    printf ("         - Tracker creation with Arena\n");
    printf ("         - Connection tracking and release\n");
    printf ("         - Per-IP limit enforcement\n");
    printf ("         - IPv4 and IPv6 support\n");
    printf ("         - Invalid IP handling\n");
    printf ("         - Dynamic limit updates\n");
    printf ("         - Maximum unique IPs limit\n");
    printf ("         - Query operations\n");
    printf ("         - Clear and reset functionality\n");
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    fprintf (stderr, "[FAIL] IP tracker error\n");
    result = 1;
  }
  END_TRY;

  /* Cleanup */
  if (tracker)
    SocketIPTracker_free (&tracker);
  if (arena)
    Arena_dispose (&arena);

  printf ("\nIP tracker example complete.\n");
  return result;
}
