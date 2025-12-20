/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * syn_protect.c - SYN Flood Protection Example
 *
 * Demonstrates SYN flood protection using the SocketSYNProtect API.
 * Shows protection creation, configuration, whitelist/blacklist management,
 * connection evaluation, reputation tracking, and cleanup.
 *
 * Build:
 *   cmake -DBUILD_EXAMPLES=ON ..
 *   make example_syn_protect
 *
 * Usage:
 *   ./example_syn_protect
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketSYNProtect.h"

/* Sample IP addresses for testing */
static const char *test_ips[] = {
  "192.168.1.100", /* Trusted internal IP */
  "10.0.0.50",     /* Whitelisted network */
  "203.0.113.25",  /* Legitimate client */
  "198.51.100.10", /* Suspicious IP */
  "192.0.2.1",     /* Known attacker */
  "198.51.100.20", /* Rate limit violator */
};

static const int NUM_TEST_IPS = sizeof (test_ips) / sizeof (test_ips[0]);

/* Helper function to display action result */
static void
print_action (const char *ip, SocketSYN_Action action)
{
  const char *action_str = SocketSYNProtect_action_name (action);

  switch (action)
    {
    case SYN_ACTION_ALLOW:
      printf ("  [OK] %s -> %s\n", ip, action_str);
      break;
    case SYN_ACTION_THROTTLE:
      printf ("  [INFO] %s -> %s (rate limited)\n", ip, action_str);
      break;
    case SYN_ACTION_CHALLENGE:
      printf ("  [INFO] %s -> %s (require payload)\n", ip, action_str);
      break;
    case SYN_ACTION_BLOCK:
      printf ("  [FAIL] %s -> %s (rejected)\n", ip, action_str);
      break;
    }
}

/* Helper function to display IP state */
static void
print_ip_state (const char *ip, const SocketSYN_IPState *state)
{
  (void)ip; /* Parameter for API consistency */
  printf ("    IP: %s\n", state->ip);
  printf ("    Reputation: %s (score: %.2f)\n",
          SocketSYNProtect_reputation_name (state->rep), state->score);
  printf ("    Attempts (current): %u\n", state->attempts_current);
  printf ("    Successes: %u, Failures: %u\n", state->successes,
          state->failures);

  if (state->block_until_ms > 0)
    {
      printf ("    Blocked until: %lld ms\n",
              (long long)state->block_until_ms);
    }
}

/* Helper function to display statistics */
static void
print_stats (SocketSYNProtect_T protect)
{
  SocketSYNProtect_Stats stats;
  SocketSYNProtect_stats (protect, &stats);

  printf ("\nProtection Statistics:\n");
  printf ("  Uptime: %lld ms\n", (long long)stats.uptime_ms);
  printf ("  Total attempts: %lu\n", (unsigned long)stats.total_attempts);
  printf ("  Allowed: %lu\n", (unsigned long)stats.total_allowed);
  printf ("  Throttled: %lu\n", (unsigned long)stats.total_throttled);
  printf ("  Challenged: %lu\n", (unsigned long)stats.total_challenged);
  printf ("  Blocked: %lu\n", (unsigned long)stats.total_blocked);
  printf ("  Whitelisted hits: %lu\n", (unsigned long)stats.total_whitelisted);
  printf ("  Blacklisted hits: %lu\n", (unsigned long)stats.total_blacklisted);
  printf ("  Currently tracked IPs: %lu\n",
          (unsigned long)stats.current_tracked_ips);
  printf ("  Currently blocked IPs: %lu\n",
          (unsigned long)stats.current_blocked_ips);
  printf ("  LRU evictions: %lu\n", (unsigned long)stats.lru_evictions);

  /* Calculate block rate */
  if (stats.total_attempts > 0)
    {
      double block_rate
          = (double)stats.total_blocked / (double)stats.total_attempts;
      printf ("  Block rate: %.1f%%\n", block_rate * 100.0);
    }
}

/* Simulate connection attempts from various IPs */
static void
simulate_connection_attempts (SocketSYNProtect_T protect, const char *ip,
                              int num_attempts, int success_rate)
{
  printf ("\nSimulating %d connection attempts from %s...\n", num_attempts,
          ip);

  for (volatile int i = 0; i < num_attempts; i++)
    {
      SocketSYN_IPState state;
      SocketSYN_Action action = SocketSYNProtect_check (protect, ip, &state);

      if (i == 0 || i == num_attempts - 1)
        {
          print_action (ip, action);
        }

      /* Simulate connection outcome based on action and success rate */
      if (action != SYN_ACTION_BLOCK)
        {
          /* Determine if this connection succeeds */
          int succeeds = (rand () % 100) < success_rate;

          if (succeeds)
            {
              SocketSYNProtect_report_success (protect, ip);
            }
          else
            {
              SocketSYNProtect_report_failure (protect, ip, ECONNRESET);
            }
        }
      else
        {
          /* Blocked connections count as failures */
          SocketSYNProtect_report_failure (protect, ip, ECONNREFUSED);
        }

      /* Small delay to simulate real-world timing */
      if (i < num_attempts - 1)
        {
          usleep (10000); /* 10ms */
        }
    }

  /* Show final state for this IP */
  SocketSYN_IPState final_state;
  if (SocketSYNProtect_get_ip_state (protect, ip, &final_state))
    {
      printf ("  Final state for %s:\n", ip);
      print_ip_state (ip, &final_state);
    }
}

int
main (void)
{
  /* Variables that might be clobbered by longjmp must be volatile */
  Arena_T arena = NULL;
  SocketSYNProtect_T protect = NULL;
  volatile int result = 0;

  /* Seed random number generator for simulation */
  srand ((unsigned int)time (NULL));

  printf ("SYN Flood Protection Example\n");
  printf ("============================\n\n");

  TRY
  {
    /* =================================================================
     * Step 1: Create protection with default configuration
     * =================================================================
     */
    printf ("[INFO] Step 1: Creating SYN protection instance\n");

    arena = Arena_new ();
    protect = SocketSYNProtect_new (arena, NULL);

    printf ("[OK] Protection instance created\n");

    /* =================================================================
     * Step 2: Configure protection settings
     * =================================================================
     */
    printf ("\n[INFO] Step 2: Configuring protection settings\n");

    SocketSYNProtect_Config config;
    SocketSYNProtect_config_defaults (&config);

    /* Customize for this demo */
    config.window_duration_ms = 5000;    /* 5 second window */
    config.max_attempts_per_window = 20; /* Max 20 attempts per 5s */
    config.max_global_per_second = 100;  /* Global rate limit */
    config.min_success_ratio = 0.3f;     /* Require 30% success rate */
    config.throttle_delay_ms = 50;       /* 50ms throttle delay */
    config.block_duration_ms = 60000;    /* 1 minute blocks */
    config.score_throttle = 0.7f;        /* Throttle below 70% score */
    config.score_challenge = 0.5f;       /* Challenge below 50% score */
    config.score_block = 0.3f;           /* Block below 30% score */
    config.max_tracked_ips = 1000;       /* Track up to 1000 IPs */

    SocketSYNProtect_configure (protect, &config);

    printf ("[OK] Protection configured:\n");
    printf ("  Window: %d ms\n", config.window_duration_ms);
    printf ("  Max attempts per window: %d\n", config.max_attempts_per_window);
    printf ("  Score thresholds: throttle=%.1f, challenge=%.1f, block=%.1f\n",
            config.score_throttle, config.score_challenge, config.score_block);

    /* =================================================================
     * Step 3: Add whitelist entries
     * =================================================================
     */
    printf ("\n[INFO] Step 3: Adding whitelist entries\n");

    /* Whitelist individual IP */
    if (SocketSYNProtect_whitelist_add (protect, "192.168.1.100"))
      {
        printf ("[OK] Whitelisted IP: 192.168.1.100\n");
      }

    /* Whitelist CIDR range */
    if (SocketSYNProtect_whitelist_add_cidr (protect, "10.0.0.0/24"))
      {
        printf ("[OK] Whitelisted CIDR: 10.0.0.0/24\n");
      }

    /* Verify whitelist membership */
    if (SocketSYNProtect_whitelist_contains (protect, "10.0.0.50"))
      {
        printf ("[OK] Verified 10.0.0.50 is in whitelist (via CIDR)\n");
      }

    /* =================================================================
     * Step 4: Add blacklist entries
     * =================================================================
     */
    printf ("\n[INFO] Step 4: Adding blacklist entries\n");

    /* Permanent blacklist for known attacker */
    if (SocketSYNProtect_blacklist_add (protect, "192.0.2.1", 0))
      {
        printf ("[OK] Permanently blacklisted: 192.0.2.1\n");
      }

    /* Temporary 30-second blacklist */
    if (SocketSYNProtect_blacklist_add (protect, "198.51.100.99", 30000))
      {
        printf ("[OK] Temporarily blacklisted: 198.51.100.99 (30s)\n");
      }

    /* Verify blacklist membership */
    if (SocketSYNProtect_blacklist_contains (protect, "192.0.2.1"))
      {
        printf ("[OK] Verified 192.0.2.1 is blacklisted\n");
      }

    /* =================================================================
     * Step 5: Test connection evaluation
     * =================================================================
     */
    printf ("\n[INFO] Step 5: Testing connection evaluation\n");

    /* Test whitelisted IP - should always allow */
    printf ("\nTesting whitelisted IP (192.168.1.100):\n");
    SocketSYN_Action action
        = SocketSYNProtect_check (protect, "192.168.1.100", NULL);
    print_action ("192.168.1.100", action);

    /* Test blacklisted IP - should always block */
    printf ("\nTesting blacklisted IP (192.0.2.1):\n");
    action = SocketSYNProtect_check (protect, "192.0.2.1", NULL);
    print_action ("192.0.2.1", action);

    /* Test normal IP - should allow initially */
    printf ("\nTesting normal IP (203.0.113.25):\n");
    action = SocketSYNProtect_check (protect, "203.0.113.25", NULL);
    print_action ("203.0.113.25", action);

    /* =================================================================
     * Step 6: Simulate various traffic patterns
     * =================================================================
     */
    printf ("\n[INFO] Step 6: Simulating various traffic patterns\n");

    /* Good client with high success rate */
    simulate_connection_attempts (protect, "203.0.113.25", 10,
                                  90); /* 90% success */

    /* Suspicious client with moderate success rate */
    simulate_connection_attempts (protect, "198.51.100.10", 15,
                                  40); /* 40% success */

    /* Attacker with low success rate */
    simulate_connection_attempts (protect, "198.51.100.20", 25,
                                  5); /* 5% success */

    /* Rate limit violator - rapid attempts */
    printf ("\nSimulating rapid connection attempts (rate limit test)...\n");
    for (volatile int i = 0; i < 30; i++)
      {
        action = SocketSYNProtect_check (protect, "198.51.100.30", NULL);

        if (i == 0)
          {
            print_action ("198.51.100.30", action);
            printf ("  ... (continuing rapid attempts) ...\n");
          }

        if (action != SYN_ACTION_BLOCK)
          {
            SocketSYNProtect_report_failure (protect, "198.51.100.30",
                                             ECONNRESET);
          }

        usleep (5000); /* 5ms between attempts */
      }

    /* Show final action */
    action = SocketSYNProtect_check (protect, "198.51.100.30", NULL);
    print_action ("198.51.100.30", action);

    /* =================================================================
     * Step 7: Query IP reputation state
     * =================================================================
     */
    printf ("\n[INFO] Step 7: Querying IP reputation state\n");

    const char *query_ips[]
        = { "203.0.113.25", "198.51.100.10", "198.51.100.20" };

    for (volatile int i = 0; i < 3; i++)
      {
        SocketSYN_IPState state;
        if (SocketSYNProtect_get_ip_state (protect, query_ips[i], &state))
          {
            printf ("\nState for %s:\n", query_ips[i]);
            print_ip_state (query_ips[i], &state);
          }
        else
          {
            printf ("\n[INFO] No state tracked for %s\n", query_ips[i]);
          }
      }

    /* =================================================================
     * Step 8: Display statistics
     * =================================================================
     */
    printf ("\n[INFO] Step 8: Displaying protection statistics\n");
    print_stats (protect);

    /* =================================================================
     * Step 9: Cleanup stale entries
     * =================================================================
     */
    printf ("\n[INFO] Step 9: Performing cleanup of stale entries\n");

    /* Wait a bit to allow some time decay */
    printf ("Waiting 2 seconds for time-based decay...\n");
    sleep (2);

    size_t cleaned = SocketSYNProtect_cleanup (protect);
    printf ("[OK] Cleaned up %zu stale entries\n", cleaned);

    /* Show updated stats */
    print_stats (protect);

    /* =================================================================
     * Step 10: Test whitelist/blacklist removal
     * =================================================================
     */
    printf ("\n[INFO] Step 10: Testing whitelist/blacklist removal\n");

    /* Remove from blacklist */
    printf ("Removing 198.51.100.99 from blacklist...\n");
    SocketSYNProtect_blacklist_remove (protect, "198.51.100.99");

    if (!SocketSYNProtect_blacklist_contains (protect, "198.51.100.99"))
      {
        printf ("[OK] 198.51.100.99 removed from blacklist\n");
      }

    /* Test that it can now be evaluated normally */
    action = SocketSYNProtect_check (protect, "198.51.100.99", NULL);
    print_action ("198.51.100.99", action);

    /* =================================================================
     * Step 11: Test dynamic reconfiguration
     * =================================================================
     */
    printf ("\n[INFO] Step 11: Testing dynamic reconfiguration\n");

    printf ("Tightening protection limits (simulating attack response)...\n");
    config.max_attempts_per_window = 5; /* Much stricter */
    config.score_block = 0.5f;          /* Block at higher score */
    SocketSYNProtect_configure (protect, &config);

    printf ("[OK] Configuration updated\n");
    printf ("  New max attempts: %d\n", config.max_attempts_per_window);
    printf ("  New block threshold: %.1f\n", config.score_block);

    /* Test with new configuration */
    simulate_connection_attempts (protect, "198.51.100.40", 10,
                                  30); /* 30% success */

    /* =================================================================
     * Step 12: Test clearing operations
     * =================================================================
     */
    printf ("\n[INFO] Step 12: Testing clearing operations\n");

    /* Clear all tracked IPs but preserve lists */
    printf ("Clearing all tracked IP states...\n");
    SocketSYNProtect_clear_all (protect);
    printf ("[OK] Tracked IPs cleared\n");

    /* Verify whitelist/blacklist preserved */
    if (SocketSYNProtect_whitelist_contains (protect, "192.168.1.100"))
      {
        printf ("[OK] Whitelist preserved after clear_all\n");
      }

    if (SocketSYNProtect_blacklist_contains (protect, "192.0.2.1"))
      {
        printf ("[OK] Blacklist preserved after clear_all\n");
      }

    /* Show stats after clear */
    print_stats (protect);

    /* =================================================================
     * Step 13: Test full reset
     * =================================================================
     */
    printf ("\n[INFO] Step 13: Testing full reset\n");

    printf ("Performing full reset...\n");
    SocketSYNProtect_reset (protect);
    printf ("[OK] Protection instance reset\n");

    /* Verify everything cleared */
    if (!SocketSYNProtect_whitelist_contains (protect, "192.168.1.100"))
      {
        printf ("[OK] Whitelist cleared after reset\n");
      }

    if (!SocketSYNProtect_blacklist_contains (protect, "192.0.2.1"))
      {
        printf ("[OK] Blacklist cleared after reset\n");
      }

    /* Final stats should show minimal activity */
    print_stats (protect);

    printf ("\n[OK] All tests completed successfully\n");
  }
  EXCEPT (SocketSYNProtect_Failed)
  {
    fprintf (stderr, "[FAIL] SYN protection error\n");
    result = 1;
  }
  END_TRY;

  /* Cleanup */
  if (protect)
    SocketSYNProtect_free (&protect);
  if (arena)
    Arena_dispose (&arena);

  printf ("\nSYN protection example complete.\n");
  return result;
}
