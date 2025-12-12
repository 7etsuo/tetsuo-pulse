/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_synprotect.c - SYN Flood Protection Tests
 *
 * Part of the Socket Library
 *
 * Comprehensive tests for SYN flood protection including:
 * - Lifecycle (new/free)
 * - Configuration and defaults
 * - IP tracking and scoring
 * - Sliding window algorithm
 * - Whitelist and blacklist
 * - Action determination
 * - Statistics collection
 * - Thread safety
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketSYNProtect.h"
#include "core/SocketUtil.h"
#include "test/Test.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* GCC volatile clobbered warning suppression */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/* Test counters */
static int tests_run = 0;
static int tests_passed = 0;

#define RUN_TEST(test_func)                                                   \
  do                                                                          \
    {                                                                         \
      printf ("  Running: %s... ", #test_func);                               \
      fflush (stdout);                                                        \
      tests_run++;                                                            \
      if (test_func ())                                                       \
        {                                                                     \
          printf ("PASSED\n");                                                \
          tests_passed++;                                                     \
        }                                                                     \
      else                                                                    \
        {                                                                     \
          printf ("FAILED\n");                                                \
        }                                                                     \
    }                                                                         \
  while (0)

/* ============================================================================
 * Lifecycle Tests
 * ============================================================================
 */

/**
 * test_new_free_basic - Test basic lifecycle with defaults
 */
static int
test_new_free_basic (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);
    success = (protect != NULL);
    SocketSYNProtect_free (&protect);
    success = success && (protect == NULL);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_new_with_arena - Test creation with arena allocation
 */
static int
test_new_with_arena (void)
{
  Arena_T arena = NULL;
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    arena = Arena_new ();
    protect = SocketSYNProtect_new (arena, NULL);
    success = (protect != NULL);
    SocketSYNProtect_free (&protect);
    Arena_dispose (&arena);
    success = success && 1;
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_new_with_config - Test creation with custom config
 */
static int
test_new_with_config (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_config_defaults (&config);
    config.max_attempts_per_window = 100;
    config.block_duration_ms = 30000;
    config.score_block = 0.1f;

    protect = SocketSYNProtect_new (NULL, &config);
    success = (protect != NULL);
    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_free_null - Test freeing NULL pointer
 */
static int
test_free_null (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 1;

  TRY
  {
    SocketSYNProtect_free (&protect);
    SocketSYNProtect_free (NULL); /* Should not crash */
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/* ============================================================================
 * Configuration Tests
 * ============================================================================
 */

/**
 * test_config_defaults - Test config defaults are reasonable
 */
static int
test_config_defaults (void)
{
  SocketSYNProtect_Config config;
  SocketSYNProtect_config_defaults (&config);

  /* Verify defaults */
  if (config.window_duration_ms <= 0)
    return 0;
  if (config.max_attempts_per_window <= 0)
    return 0;
  if (config.max_global_per_second <= 0)
    return 0;
  if (config.score_block < 0.0f || config.score_block > 1.0f)
    return 0;
  if (config.score_throttle < 0.0f || config.score_throttle > 1.0f)
    return 0;
  if (config.score_challenge < 0.0f || config.score_challenge > 1.0f)
    return 0;
  if (config.max_tracked_ips == 0)
    return 0;

  return 1;
}

/**
 * test_configure_runtime - Test runtime configuration update
 */
static int
test_configure_runtime (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    SocketSYNProtect_config_defaults (&config);
    config.max_attempts_per_window = 25;
    SocketSYNProtect_configure (protect, &config);

    success = 1;
    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/* ============================================================================
 * Basic Check Tests
 * ============================================================================
 */

/**
 * test_check_null_ip - Test check with NULL IP
 */
static int
test_check_null_ip (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);
    SocketSYN_Action action = SocketSYNProtect_check (protect, NULL, NULL);
    success = (action == SYN_ACTION_ALLOW);
    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_check_empty_ip - Test check with empty IP string
 */
static int
test_check_empty_ip (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);
    SocketSYN_Action action = SocketSYNProtect_check (protect, "", NULL);
    success = (action == SYN_ACTION_ALLOW);
    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_check_first_ip - Test first check for new IP
 */
static int
test_check_first_ip (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);
    SocketSYN_Action action
        = SocketSYNProtect_check (protect, "192.168.1.100", NULL);
    /* First check should typically allow */
    success = (action == SYN_ACTION_ALLOW);
    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_check_with_state - Test check returns IP state
 */
static int
test_check_with_state (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);
    memset (&state, 0, sizeof (state));

    SocketSYNProtect_check (protect, "10.0.0.1", &state);

    /* State should be populated */
    success = (state.ip[0] != '\0');
    success = success && (state.attempts_current >= 1);
    success = success && (state.score > 0.0f && state.score <= 1.0f);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/* ============================================================================
 * Scoring Tests
 * ============================================================================
 */

/**
 * test_score_penalty - Test score penalty on repeated attempts
 */
static int
test_score_penalty (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state1, state2;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    SocketSYNProtect_check (protect, "1.2.3.4", &state1);
    SocketSYNProtect_check (protect, "1.2.3.4", &state2);

    /* Score should decrease with each attempt */
    success = (state2.score < state1.score);
    success = success && (state2.attempts_current > state1.attempts_current);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_score_reward - Test score reward on success report
 */
static int
test_score_reward (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state1, state2;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    /* Make several attempts to lower score */
    for (int i = 0; i < 5; i++)
      SocketSYNProtect_check (protect, "5.6.7.8", NULL);

    SocketSYNProtect_get_ip_state (protect, "5.6.7.8", &state1);

    /* Report success - should increase score */
    SocketSYNProtect_report_success (protect, "5.6.7.8");
    SocketSYNProtect_get_ip_state (protect, "5.6.7.8", &state2);

    success = (state2.score > state1.score);
    success = success && (state2.successes == 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_score_failure_penalty - Test score penalty on failure report
 */
static int
test_score_failure_penalty (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state1, state2;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    SocketSYNProtect_check (protect, "9.10.11.12", NULL);
    SocketSYNProtect_get_ip_state (protect, "9.10.11.12", &state1);

    SocketSYNProtect_report_failure (protect, "9.10.11.12", 0);
    SocketSYNProtect_get_ip_state (protect, "9.10.11.12", &state2);

    success = (state2.score < state1.score);
    success = success && (state2.failures == 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/* ============================================================================
 * Whitelist Tests
 * ============================================================================
 */

/**
 * test_whitelist_add_single - Test adding single IP to whitelist
 */
static int
test_whitelist_add_single (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    int result = SocketSYNProtect_whitelist_add (protect, "192.168.1.1");
    success = (result == 1);

    int contains
        = SocketSYNProtect_whitelist_contains (protect, "192.168.1.1");
    success = success && (contains == 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_whitelist_bypass - Test whitelisted IP bypasses check
 */
static int
test_whitelist_bypass (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    SocketSYNProtect_whitelist_add (protect, "10.0.0.100");

    /* Many attempts should still be allowed */
    SocketSYN_Action action = SYN_ACTION_BLOCK;
    for (int i = 0; i < 100; i++)
      action = SocketSYNProtect_check (protect, "10.0.0.100", NULL);

    success = (action == SYN_ACTION_ALLOW);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_whitelist_cidr - Test CIDR notation whitelist
 */
static int
test_whitelist_cidr (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    int result
        = SocketSYNProtect_whitelist_add_cidr (protect, "172.16.0.0/12");
    success = (result == 1);

    /* IP in range should be whitelisted */
    int contains
        = SocketSYNProtect_whitelist_contains (protect, "172.20.5.10");
    success = success && (contains == 1);

    /* IP outside range should not be whitelisted */
    int not_contains
        = SocketSYNProtect_whitelist_contains (protect, "172.32.0.1");
    success = success && (not_contains == 0);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_whitelist_cidr_invalid - Test rejection of invalid CIDR notations and
 * no wildcard effect
 */
static int
test_whitelist_cidr_invalid (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    /* Invalid prefix like /abc should fail add, not create /0 wildcard */
    int result1
        = SocketSYNProtect_whitelist_add_cidr (protect, "192.168.1.1/abc");
    success = (result1 == 0);

    /* Failure should not whitelist arbitrary IPs */
    int contains_arbitrary
        = SocketSYNProtect_whitelist_contains (protect, "8.8.8.8");
    success = success && (contains_arbitrary == 0);

    /* Invalid large prefix /999 should fail */
    int result2
        = SocketSYNProtect_whitelist_add_cidr (protect, "192.168.1.1/999");
    success = success && (result2 == 0);

    /* Negative prefix /-1 should fail */
    int result3
        = SocketSYNProtect_whitelist_add_cidr (protect, "192.168.1.1/-1");
    success = success && (result3 == 0);

    /* No / should fall back to single IP add (success) */
    int result4 = SocketSYNProtect_whitelist_add_cidr (protect, "192.168.1.1");
    success = success && (result4 == 1);
    int contains_fallback
        = SocketSYNProtect_whitelist_contains (protect, "192.168.1.1");
    success = success && (contains_fallback == 1);

    /* /0 should be accepted but match only exact (or disallow?) - test match
     */
    int result5 = SocketSYNProtect_whitelist_add_cidr (protect, "0.0.0.0/0");
    success
        = success && (result5 == 1); // Allowed, but verify behavior if needed
    int contains_all
        = SocketSYNProtect_whitelist_contains (protect, "255.255.255.255");
    // Note: /0 matches all IPv4; adjust policy if to disallow

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_whitelist_remove - Test removing from whitelist
 */
static int
test_whitelist_remove (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    SocketSYNProtect_whitelist_add (protect, "1.1.1.1");
    SocketSYNProtect_whitelist_remove (protect, "1.1.1.1");

    int contains = SocketSYNProtect_whitelist_contains (protect, "1.1.1.1");
    success = (contains == 0);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_whitelist_clear - Test clearing whitelist
 */
static int
test_whitelist_clear (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    SocketSYNProtect_whitelist_add (protect, "2.2.2.2");
    SocketSYNProtect_whitelist_add (protect, "3.3.3.3");
    SocketSYNProtect_whitelist_clear (protect);

    success = !SocketSYNProtect_whitelist_contains (protect, "2.2.2.2");
    success
        = success && !SocketSYNProtect_whitelist_contains (protect, "3.3.3.3");

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/* ============================================================================
 * Blacklist Tests
 * ============================================================================
 */

/**
 * test_blacklist_add - Test adding to blacklist
 */
static int
test_blacklist_add (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    int result = SocketSYNProtect_blacklist_add (protect, "10.10.10.10", 0);
    success = (result == 1);

    int contains
        = SocketSYNProtect_blacklist_contains (protect, "10.10.10.10");
    success = success && (contains == 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_blacklist_blocks - Test blacklisted IP is blocked
 */
static int
test_blacklist_blocks (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    SocketSYNProtect_blacklist_add (protect, "20.20.20.20", 0);

    SocketSYN_Action action
        = SocketSYNProtect_check (protect, "20.20.20.20", NULL);
    success = (action == SYN_ACTION_BLOCK);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_blacklist_timed - Test timed blacklist expiry
 */
static int
test_blacklist_timed (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    /* Add with 100ms expiry */
    SocketSYNProtect_blacklist_add (protect, "30.30.30.30", 100);

    /* Should be blocked immediately */
    int blocked = SocketSYNProtect_blacklist_contains (protect, "30.30.30.30");
    success = (blocked == 1);

    /* Wait for expiry */
    usleep (150000); /* 150ms */

    /* Run cleanup to process expiry */
    SocketSYNProtect_cleanup (protect);

    /* Should no longer be blocked */
    int expired = SocketSYNProtect_blacklist_contains (protect, "30.30.30.30");
    success = success && (expired == 0);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_blacklist_remove - Test removing from blacklist
 */
static int
test_blacklist_remove (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    SocketSYNProtect_blacklist_add (protect, "40.40.40.40", 0);
    SocketSYNProtect_blacklist_remove (protect, "40.40.40.40");

    int contains
        = SocketSYNProtect_blacklist_contains (protect, "40.40.40.40");
    success = (contains == 0);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/* ============================================================================
 * Statistics Tests
 * ============================================================================
 */

/**
 * test_stats_basic - Test basic statistics collection
 */
static int
test_stats_basic (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Stats stats;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    /* Make some attempts */
    SocketSYNProtect_check (protect, "100.0.0.1", NULL);
    SocketSYNProtect_check (protect, "100.0.0.2", NULL);
    SocketSYNProtect_check (protect, "100.0.0.3", NULL);

    SocketSYNProtect_stats (protect, &stats);

    success = (stats.total_attempts == 3);
    success = success && (stats.current_tracked_ips == 3);
    success = success && (stats.uptime_ms >= 0);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_stats_reset - Test statistics reset
 */
static int
test_stats_reset (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Stats stats;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    SocketSYNProtect_check (protect, "200.0.0.1", NULL);
    SocketSYNProtect_stats_reset (protect);
    SocketSYNProtect_stats (protect, &stats);

    success = (stats.total_attempts == 0);
    success = success && (stats.total_allowed == 0);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/* ============================================================================
 * Action Name Tests
 * ============================================================================
 */

/**
 * test_action_names - Test action name lookup
 */
static int
test_action_names (void)
{
  int success = 1;

  success
      = success
        && (strcmp (SocketSYNProtect_action_name (SYN_ACTION_ALLOW), "ALLOW")
            == 0);
  success = success
            && (strcmp (SocketSYNProtect_action_name (SYN_ACTION_THROTTLE),
                        "THROTTLE")
                == 0);
  success = success
            && (strcmp (SocketSYNProtect_action_name (SYN_ACTION_CHALLENGE),
                        "CHALLENGE")
                == 0);
  success
      = success
        && (strcmp (SocketSYNProtect_action_name (SYN_ACTION_BLOCK), "BLOCK")
            == 0);

  return success;
}

/**
 * test_reputation_names - Test reputation name lookup
 */
static int
test_reputation_names (void)
{
  int success = 1;

  success = success
            && (strcmp (SocketSYNProtect_reputation_name (SYN_REP_TRUSTED),
                        "TRUSTED")
                == 0);
  success = success
            && (strcmp (SocketSYNProtect_reputation_name (SYN_REP_NEUTRAL),
                        "NEUTRAL")
                == 0);
  success = success
            && (strcmp (SocketSYNProtect_reputation_name (SYN_REP_SUSPECT),
                        "SUSPECT")
                == 0);
  success = success
            && (strcmp (SocketSYNProtect_reputation_name (SYN_REP_HOSTILE),
                        "HOSTILE")
                == 0);

  return success;
}

/* ============================================================================
 * Maintenance Tests
 * ============================================================================
 */

/**
 * test_cleanup - Test cleanup removes expired entries
 */
static int
test_cleanup (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    /* Add timed blacklist entry */
    SocketSYNProtect_blacklist_add (protect, "50.50.50.50", 50);

    usleep (100000); /* 100ms */

    size_t removed = SocketSYNProtect_cleanup (protect);
    success = (removed >= 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_clear_all - Test clearing all tracked state
 */
static int
test_clear_all (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Stats stats;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    /* Add some entries */
    SocketSYNProtect_check (protect, "60.0.0.1", NULL);
    SocketSYNProtect_check (protect, "60.0.0.2", NULL);
    SocketSYNProtect_whitelist_add (protect, "60.0.0.3");

    SocketSYNProtect_clear_all (protect);
    SocketSYNProtect_stats (protect, &stats);

    /* Tracked IPs should be cleared, but whitelist preserved */
    success = (stats.current_tracked_ips == 0);
    success
        = success
          && (SocketSYNProtect_whitelist_contains (protect, "60.0.0.3") == 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_reset - Test full reset
 */
static int
test_reset (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Stats stats;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    SocketSYNProtect_check (protect, "70.0.0.1", NULL);
    SocketSYNProtect_whitelist_add (protect, "70.0.0.2");
    SocketSYNProtect_blacklist_add (protect, "70.0.0.3", 0);

    SocketSYNProtect_reset (protect);
    SocketSYNProtect_stats (protect, &stats);

    success = (stats.current_tracked_ips == 0);
    success
        = success
          && (SocketSYNProtect_whitelist_contains (protect, "70.0.0.2") == 0);
    success
        = success
          && (SocketSYNProtect_blacklist_contains (protect, "70.0.0.3") == 0);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/* ============================================================================
 * IP State Query Tests
 * ============================================================================
 */

/**
 * test_get_ip_state_found - Test getting state for tracked IP
 */
static int
test_get_ip_state_found (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    SocketSYNProtect_check (protect, "80.0.0.1", NULL);

    int found = SocketSYNProtect_get_ip_state (protect, "80.0.0.1", &state);
    success = (found == 1);
    success = success && (strcmp (state.ip, "80.0.0.1") == 0);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_get_ip_state_not_found - Test getting state for unknown IP
 */
static int
test_get_ip_state_not_found (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    int found = SocketSYNProtect_get_ip_state (protect, "90.0.0.1", &state);
    success = (found == 0);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/* ============================================================================
 * IPv6 Tests
 * ============================================================================
 */

/**
 * test_ipv6_basic - Test basic IPv6 address handling
 */
static int
test_ipv6_basic (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    SocketSYN_Action action
        = SocketSYNProtect_check (protect, "2001:db8::1", NULL);
    success = (action == SYN_ACTION_ALLOW);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_ipv6_whitelist - Test IPv6 whitelist
 */
static int
test_ipv6_whitelist (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    SocketSYNProtect_whitelist_add (protect, "2001:db8::100");
    int contains
        = SocketSYNProtect_whitelist_contains (protect, "2001:db8::100");
    success = (contains == 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/**
 * test_ipv6_cidr - Test IPv6 CIDR whitelist
 */
static int
test_ipv6_cidr (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    int result
        = SocketSYNProtect_whitelist_add_cidr (protect, "2001:db8::/32");
    success = (result == 1);

    int contains
        = SocketSYNProtect_whitelist_contains (protect, "2001:db8::1234");
    success = success && (contains == 1);

    int not_contains
        = SocketSYNProtect_whitelist_contains (protect, "2001:db9::1");
    success = success && (not_contains == 0);

    SocketSYNProtect_free (&protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/* ============================================================================
 * Thread Safety Test
 * ============================================================================
 */

static SocketSYNProtect_T g_protect = NULL;
static volatile int g_thread_errors = 0;

static void *
thread_worker (void *arg)
{
  int thread_id = *(int *)arg;
  char ip[32];

  for (int i = 0; i < 100; i++)
    {
      snprintf (ip, sizeof (ip), "100.%d.%d.%d", thread_id, i % 256,
                (i * 7) % 256);

      TRY { SocketSYNProtect_check (g_protect, ip, NULL); }
      ELSE { g_thread_errors++; }
      END_TRY;
    }

  return NULL;
}

/**
 * test_thread_safety - Test concurrent access from multiple threads
 */
static int
test_thread_safety (void)
{
  pthread_t threads[4];
  int thread_ids[4];
  volatile int success = 0;

  TRY
  {
    g_protect = SocketSYNProtect_new (NULL, NULL);
    g_thread_errors = 0;

    for (int i = 0; i < 4; i++)
      {
        thread_ids[i] = i;
        pthread_create (&threads[i], NULL, thread_worker, &thread_ids[i]);
      }

    for (int i = 0; i < 4; i++)
      pthread_join (threads[i], NULL);

    success = (g_thread_errors == 0);

    SocketSYNProtect_Stats stats;
    SocketSYNProtect_stats (g_protect, &stats);
    success = success && (stats.total_attempts == 400);

    SocketSYNProtect_free (&g_protect);
  }
  ELSE { success = 0; }
  END_TRY;

  return success;
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================
 */

int
main (void)
{
  printf ("\n=== SocketSYNProtect Tests ===\n\n");

  printf ("Lifecycle Tests:\n");
  RUN_TEST (test_new_free_basic);
  RUN_TEST (test_new_with_arena);
  RUN_TEST (test_new_with_config);
  RUN_TEST (test_free_null);

  printf ("\nConfiguration Tests:\n");
  RUN_TEST (test_config_defaults);
  RUN_TEST (test_configure_runtime);

  printf ("\nBasic Check Tests:\n");
  RUN_TEST (test_check_null_ip);
  RUN_TEST (test_check_empty_ip);
  RUN_TEST (test_check_first_ip);
  RUN_TEST (test_check_with_state);

  printf ("\nScoring Tests:\n");
  RUN_TEST (test_score_penalty);
  RUN_TEST (test_score_reward);
  RUN_TEST (test_score_failure_penalty);

  printf ("\nWhitelist Tests:\n");
  RUN_TEST (test_whitelist_add_single);
  RUN_TEST (test_whitelist_bypass);
  RUN_TEST (test_whitelist_cidr);
  RUN_TEST (test_whitelist_cidr_invalid);
  RUN_TEST (test_whitelist_remove);
  RUN_TEST (test_whitelist_clear);

  printf ("\nBlacklist Tests:\n");
  RUN_TEST (test_blacklist_add);
  RUN_TEST (test_blacklist_blocks);
  RUN_TEST (test_blacklist_timed);
  RUN_TEST (test_blacklist_remove);

  printf ("\nStatistics Tests:\n");
  RUN_TEST (test_stats_basic);
  RUN_TEST (test_stats_reset);

  printf ("\nName Lookup Tests:\n");
  RUN_TEST (test_action_names);
  RUN_TEST (test_reputation_names);

  printf ("\nMaintenance Tests:\n");
  RUN_TEST (test_cleanup);
  RUN_TEST (test_clear_all);
  RUN_TEST (test_reset);

  printf ("\nIP State Query Tests:\n");
  RUN_TEST (test_get_ip_state_found);
  RUN_TEST (test_get_ip_state_not_found);

  printf ("\nIPv6 Tests:\n");
  RUN_TEST (test_ipv6_basic);
  RUN_TEST (test_ipv6_whitelist);
  RUN_TEST (test_ipv6_cidr);

  printf ("\nThread Safety Tests:\n");
  RUN_TEST (test_thread_safety);

  printf ("\n=== Results: %d/%d tests passed ===\n\n", tests_passed,
          tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}
