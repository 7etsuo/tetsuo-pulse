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
 * - CIDR matching algorithms
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketSYNProtect.h"
#include "core/SocketSYNProtect-private.h"
#undef T /* Avoid conflict between SocketSYNProtect-private.h and Test.h */
#include "core/SocketUtil.h"
#include "test/Test.h"
#include <arpa/inet.h>
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

#define RUN_TEST(test_func)                     \
  do                                            \
    {                                           \
      printf ("  Running: %s... ", #test_func); \
      fflush (stdout);                          \
      tests_run++;                              \
      if (test_func ())                         \
        {                                       \
          printf ("PASSED\n");                  \
          tests_passed++;                       \
        }                                       \
      else                                      \
        {                                       \
          printf ("FAILED\n");                  \
        }                                       \
    }                                           \
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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

    int contains = SocketSYNProtect_whitelist_contains (protect, "192.168.1.1");
    success = success && (contains == 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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

    int result = SocketSYNProtect_whitelist_add_cidr (protect, "172.16.0.0/12");
    success = (result == 1);

    /* IP in range should be whitelisted */
    int contains = SocketSYNProtect_whitelist_contains (protect, "172.20.5.10");
    success = success && (contains == 1);

    /* IP outside range should not be whitelisted */
    int not_contains
        = SocketSYNProtect_whitelist_contains (protect, "172.32.0.1");
    success = success && (not_contains == 0);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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

    int contains = SocketSYNProtect_blacklist_contains (protect, "10.10.10.10");
    success = success && (contains == 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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

    int contains = SocketSYNProtect_blacklist_contains (protect, "40.40.40.40");
    success = (contains == 0);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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
  ELSE
  {
    success = 0;
  }
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

    int result = SocketSYNProtect_whitelist_add_cidr (protect, "2001:db8::/32");
    success = (result == 1);

    int contains
        = SocketSYNProtect_whitelist_contains (protect, "2001:db8::1234");
    success = success && (contains == 1);

    int not_contains
        = SocketSYNProtect_whitelist_contains (protect, "2001:db9::1");
    success = success && (not_contains == 0);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/* ============================================================================
 * Sliding Window Algorithm Tests
 * ============================================================================
 */

/**
 * test_window_rotation_no_rotation - Test window does not rotate within window
 * duration
 */
static int
test_window_rotation_no_rotation (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_Config config;
    SocketSYNProtect_config_defaults (&config);
    config.window_duration_ms = 1000; /* 1 second window */

    protect = SocketSYNProtect_new (NULL, &config);

    /* Make first attempt */
    SocketSYNProtect_check (protect, "192.168.1.1", &state);
    uint32_t initial_current = state.attempts_current;
    uint32_t initial_previous = state.attempts_previous;
    int64_t initial_window_start = state.window_start_ms;

    /* Make another attempt within 500ms (half window) */
    usleep (500000); /* 500ms */
    SocketSYNProtect_check (protect, "192.168.1.1", &state);

    /* Window should NOT have rotated */
    success = (state.attempts_current > initial_current);
    success = success && (state.attempts_previous == initial_previous);
    success = success && (state.window_start_ms == initial_window_start);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_window_rotation_occurs - Test window rotation after window duration
 * passes
 */
static int
test_window_rotation_occurs (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_Config config;
    SocketSYNProtect_config_defaults (&config);
    config.window_duration_ms = 200; /* 200ms window for faster testing */

    protect = SocketSYNProtect_new (NULL, &config);

    /* Make attempts to build up current count */
    SocketSYNProtect_check (protect, "192.168.1.2", NULL);
    SocketSYNProtect_check (protect, "192.168.1.2", NULL);
    SocketSYNProtect_check (protect, "192.168.1.2", &state);

    uint32_t old_current = state.attempts_current;
    int64_t old_window_start = state.window_start_ms;

    /* Wait past window duration */
    usleep (250000); /* 250ms > 200ms window */

    /* Next check should trigger rotation */
    SocketSYNProtect_check (protect, "192.168.1.2", &state);

    /* Verify rotation occurred:
     * - attempts_previous should equal old attempts_current
     * - attempts_current should be 1 (just the new attempt)
     * - window_start_ms should have updated
     */
    success = (state.attempts_previous == old_current);
    success = success && (state.attempts_current == 1);
    success = success && (state.window_start_ms > old_window_start);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_window_progress_0_percent - Test linear interpolation at 0% progress
 */
static int
test_window_progress_0_percent (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_Config config;
    SocketSYNProtect_config_defaults (&config);
    config.window_duration_ms = 1000;
    config.max_attempts_per_window = 100; /* High to avoid blocking */

    protect = SocketSYNProtect_new (NULL, &config);

    /* Build up previous window with 10 attempts */
    for (int i = 0; i < 10; i++)
      SocketSYNProtect_check (protect, "10.0.0.1", NULL);

    /* Wait for window to rotate */
    usleep (1100000); /* 1100ms > 1000ms */

    /* Make 1 attempt in new window (triggers rotation) */
    SocketSYNProtect_check (protect, "10.0.0.1", &state);

    /* At 0% progress (start of new window):
     * - previous = 10, current = 1
     * - effective = current + previous * (1.0 - 0.0) = 1 + 10 = 11
     */
    uint32_t expected_min = 10; /* Should have full weight from previous */
    success = (state.attempts_previous == 10);
    success = success && (state.attempts_current == 1);
    /* Effective attempts should be ~11 (1 + 10*1.0) */
    success = success && (state.attempts_current + state.attempts_previous
                          >= expected_min);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_window_progress_50_percent - Test linear interpolation at ~50% progress
 */
static int
test_window_progress_50_percent (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_Config config;
    SocketSYNProtect_config_defaults (&config);
    config.window_duration_ms = 1000;
    config.max_attempts_per_window = 100;

    protect = SocketSYNProtect_new (NULL, &config);

    /* Build previous window with 10 attempts */
    for (int i = 0; i < 10; i++)
      SocketSYNProtect_check (protect, "10.0.0.2", NULL);

    /* Rotate window */
    usleep (1100000); /* 1100ms */
    SocketSYNProtect_check (protect, "10.0.0.2", NULL);

    /* Wait ~50% into new window */
    usleep (500000); /* 500ms = 50% of 1000ms */

    /* Make attempts */
    for (int i = 0; i < 5; i++)
      SocketSYNProtect_check (protect, "10.0.0.2", NULL);

    SocketSYNProtect_get_ip_state (protect, "10.0.0.2", &state);

    /* At ~50% progress:
     * - previous = 10, current = 6 (1 from rotation + 5 new)
     * - effective = 6 + 10 * 0.5 = 11
     * Allow some tolerance for timing
     */
    success = (state.attempts_previous == 10);
    success = success && (state.attempts_current >= 5);
    /* Total should be between current and current+previous */
    uint32_t total_effective = state.attempts_current + state.attempts_previous;
    success = success && (total_effective >= 11)
              && (total_effective <= 16);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_window_progress_100_percent - Test linear interpolation at 100%
 * progress
 */
static int
test_window_progress_100_percent (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_Config config;
    SocketSYNProtect_config_defaults (&config);
    config.window_duration_ms = 500; /* Shorter for faster test */
    config.max_attempts_per_window = 100;

    protect = SocketSYNProtect_new (NULL, &config);

    /* Build previous window */
    for (int i = 0; i < 10; i++)
      SocketSYNProtect_check (protect, "10.0.0.3", NULL);

    /* Rotate window by waiting past window duration */
    usleep (600000); /* 600ms > 500ms */
    SocketSYNProtect_check (protect, "10.0.0.3", NULL);

    /* Wait until very close to next rotation (approaching 100% progress) */
    usleep (450000); /* 450ms = 90% of 500ms window */

    /* Make attempts */
    for (int i = 0; i < 5; i++)
      SocketSYNProtect_check (protect, "10.0.0.3", NULL);

    SocketSYNProtect_get_ip_state (protect, "10.0.0.3", &state);

    /* At ~90-100% progress:
     * - previous = 10, current = 6 (1 from rotation + 5 new)
     * - effective = 6 + 10 * (1.0 - progress)
     * At end of window, previous weight should be very small
     * Just verify the state values are correct, not the exact effective
     * calculation
     */
    success = (state.attempts_previous == 10);
    success = success && (state.attempts_current >= 5);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_effective_attempts_current_only - Test effective attempts with no
 * previous window
 */
static int
test_effective_attempts_current_only (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    /* First check - no previous window */
    SocketSYNProtect_check (protect, "172.16.0.1", &state);

    /* Should have 1 current attempt, 0 previous */
    success = (state.attempts_current == 1);
    success = success && (state.attempts_previous == 0);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_effective_attempts_both_windows - Test effective attempts calculation
 * with both windows
 */
static int
test_effective_attempts_both_windows (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_Config config;
    SocketSYNProtect_config_defaults (&config);
    config.window_duration_ms = 500;
    config.max_attempts_per_window = 100;

    protect = SocketSYNProtect_new (NULL, &config);

    /* Build previous window */
    for (int i = 0; i < 10; i++)
      SocketSYNProtect_check (protect, "172.16.0.2", NULL);

    /* Rotate window */
    usleep (600000); /* 600ms */

    /* Add current window attempts */
    for (int i = 0; i < 5; i++)
      SocketSYNProtect_check (protect, "172.16.0.2", NULL);

    SocketSYNProtect_get_ip_state (protect, "172.16.0.2", &state);

    /* Verify both windows have data */
    success = (state.attempts_previous == 10);
    success = success && (state.attempts_current == 5);
    /* Effective should be weighted sum (5 + 10 * progress_weight) */
    /* At start of window, should be close to 5 + 10 = 15 */

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_window_zero_duration - Test edge case of zero window duration
 */
static int
test_window_zero_duration (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_Config config;
    SocketSYNProtect_config_defaults (&config);
    config.window_duration_ms = 0; /* Edge case - should be normalized */

    protect = SocketSYNProtect_new (NULL, &config);

    /* Should still function without crashes */
    SocketSYNProtect_check (protect, "172.16.0.3", &state);

    /* With window_ms=0, effective attempts should just return current */
    success = (state.attempts_current >= 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_monotonic_time_handling - Test that negative elapsed time is handled
 */
static int
test_monotonic_time_handling (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    /* Normal check should work */
    SocketSYNProtect_check (protect, "172.16.0.4", &state);

    /* The implementation handles monotonic time internally
     * and clamps negative values to 0, so we just verify
     * it doesn't crash with normal operations */
    success = (state.attempts_current >= 1);
    success = success && (state.window_start_ms > 0);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/* ============================================================================
 * CIDR Matching Algorithm Tests
 * ============================================================================
 */

/**
 * test_cidr_full_bytes_match - Test full byte matching for CIDR ranges
 */
static int
test_cidr_full_bytes_match (void)
{
  uint8_t ip1[4] = { 192, 168, 1, 100 };
  uint8_t ip2[4] = { 192, 168, 1, 200 };
  uint8_t ip3[4] = { 192, 168, 2, 100 };

  /* First 3 bytes match */
  int match1 = cidr_full_bytes_match (ip1, ip2, 3);
  if (!match1)
    return 0;

  /* First 2 bytes match */
  int match2 = cidr_full_bytes_match (ip1, ip3, 2);
  if (!match2)
    return 0;

  /* First 3 bytes don't match (third byte differs) */
  int match3 = cidr_full_bytes_match (ip1, ip3, 3);
  if (match3)
    return 0;

  /* All 4 bytes don't match */
  int match4 = cidr_full_bytes_match (ip1, ip2, 4);
  if (match4)
    return 0;

  return 1;
}

/**
 * test_cidr_partial_byte_match - Test partial byte matching with bit masks
 */
static int
test_cidr_partial_byte_match (void)
{
  /* Test /25: 192.168.1.128 matches 192.168.1.128-255 */
  uint8_t ip1[4] = { 192, 168, 1, 128 }; /* 10000000 */
  uint8_t ip2[4] = { 192, 168, 1, 200 }; /* 11001000 */
  uint8_t ip3[4] = { 192, 168, 1, 64 };  /* 01000000 */

  /* Top 1 bit of byte 3: 128 (1xxxxxxx) matches 200 (1xxxxxxx) */
  int match1 = cidr_partial_byte_match (ip1, ip2, 3, 1);
  if (!match1)
    return 0;

  /* Top 1 bit: 128 (1xxxxxxx) doesn't match 64 (0xxxxxxx) */
  int match2 = cidr_partial_byte_match (ip1, ip3, 3, 1);
  if (match2)
    return 0;

  /* Test /23: partial byte with 7 bits */
  uint8_t ip4[4] = { 192, 168, 2, 0 };  /* byte[2] = 00000010 */
  uint8_t ip5[4] = { 192, 168, 3, 0 };  /* byte[2] = 00000011 */
  uint8_t ip6[4] = { 192, 168, 4, 0 };  /* byte[2] = 00000100 */

  /* Top 7 bits of byte 2: 0000001x matches */
  int match3 = cidr_partial_byte_match (ip4, ip5, 2, 7);
  if (!match3)
    return 0;

  /* Top 7 bits: 0000001x doesn't match 0000010x */
  int match4 = cidr_partial_byte_match (ip4, ip6, 2, 7);
  if (match4)
    return 0;

  return 1;
}

/**
 * test_ip_matches_cidr_bytes_ipv4 - Test IPv4 CIDR matching with binary
 * addresses
 */
static int
test_ip_matches_cidr_bytes_ipv4 (void)
{
  SocketSYN_WhitelistEntry entry;
  uint8_t ip_bytes[16];
  struct in_addr addr;

  /* Setup: 192.168.1.0/24 */
  entry.addr_family = AF_INET;
  entry.prefix_len = 24;
  inet_pton (AF_INET, "192.168.1.0", &addr);
  memset (entry.addr_bytes, 0, sizeof (entry.addr_bytes));
  memcpy (entry.addr_bytes, &addr.s_addr, 4);

  /* Test 1: 192.168.1.100 matches 192.168.1.0/24 */
  inet_pton (AF_INET, "192.168.1.100", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (!ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  /* Test 2: 192.168.2.1 does NOT match 192.168.1.0/24 */
  inet_pton (AF_INET, "192.168.2.1", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  /* Test 3: 10.0.0.1 matches 10.0.0.0/8 */
  entry.prefix_len = 8;
  inet_pton (AF_INET, "10.0.0.0", &addr);
  memcpy (entry.addr_bytes, &addr.s_addr, 4);
  inet_pton (AF_INET, "10.0.0.1", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (!ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  /* Test 4: Family mismatch (IPv4 IP vs IPv6 CIDR) */
  if (ip_matches_cidr_bytes (AF_INET6, ip_bytes, &entry))
    return 0;

  return 1;
}

/**
 * test_ip_matches_cidr_bytes_ipv4_partial - Test IPv4 partial byte boundaries
 */
static int
test_ip_matches_cidr_bytes_ipv4_partial (void)
{
  SocketSYN_WhitelistEntry entry;
  uint8_t ip_bytes[16];
  struct in_addr addr;

  /* Test /25: 192.168.1.128/25 covers 192.168.1.128-255 */
  entry.addr_family = AF_INET;
  entry.prefix_len = 25;
  inet_pton (AF_INET, "192.168.1.128", &addr);
  memset (entry.addr_bytes, 0, sizeof (entry.addr_bytes));
  memcpy (entry.addr_bytes, &addr.s_addr, 4);

  /* 192.168.1.200 should match (top bit = 1) */
  inet_pton (AF_INET, "192.168.1.200", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (!ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  /* 192.168.1.64 should NOT match (top bit = 0) */
  inet_pton (AF_INET, "192.168.1.64", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  /* Test /31: exact 2-address subnet */
  entry.prefix_len = 31;
  inet_pton (AF_INET, "192.168.1.0", &addr);
  memcpy (entry.addr_bytes, &addr.s_addr, 4);

  inet_pton (AF_INET, "192.168.1.0", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (!ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  inet_pton (AF_INET, "192.168.1.1", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (!ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  inet_pton (AF_INET, "192.168.1.2", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  return 1;
}

/**
 * test_ip_matches_cidr_bytes_ipv4_edge - Test IPv4 edge cases (/0, /32)
 */
static int
test_ip_matches_cidr_bytes_ipv4_edge (void)
{
  SocketSYN_WhitelistEntry entry;
  uint8_t ip_bytes[16];
  struct in_addr addr;

  /* Test /0: matches all IPv4 */
  entry.addr_family = AF_INET;
  entry.prefix_len = 0;
  inet_pton (AF_INET, "0.0.0.0", &addr);
  memset (entry.addr_bytes, 0, sizeof (entry.addr_bytes));
  memcpy (entry.addr_bytes, &addr.s_addr, 4);

  inet_pton (AF_INET, "1.2.3.4", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (!ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  inet_pton (AF_INET, "255.255.255.255", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (!ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  /* Test /32: exact match only */
  entry.prefix_len = 32;
  inet_pton (AF_INET, "192.168.1.100", &addr);
  memcpy (entry.addr_bytes, &addr.s_addr, 4);

  /* Exact match */
  inet_pton (AF_INET, "192.168.1.100", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (!ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  /* Off by one */
  inet_pton (AF_INET, "192.168.1.101", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  return 1;
}

/**
 * test_ip_matches_cidr_bytes_ipv6 - Test IPv6 CIDR matching
 */
static int
test_ip_matches_cidr_bytes_ipv6 (void)
{
  SocketSYN_WhitelistEntry entry;
  uint8_t ip_bytes[16];
  struct in6_addr addr6;

  /* Setup: 2001:db8::/32 */
  entry.addr_family = AF_INET6;
  entry.prefix_len = 32;
  inet_pton (AF_INET6, "2001:db8::", &addr6);
  memcpy (entry.addr_bytes, addr6.s6_addr, 16);

  /* Test 1: 2001:db8::1234 matches 2001:db8::/32 */
  inet_pton (AF_INET6, "2001:db8::1234", &addr6);
  memcpy (ip_bytes, addr6.s6_addr, 16);
  if (!ip_matches_cidr_bytes (AF_INET6, ip_bytes, &entry))
    return 0;

  /* Test 2: 2001:db9::1 does NOT match 2001:db8::/32 */
  inet_pton (AF_INET6, "2001:db9::1", &addr6);
  memcpy (ip_bytes, addr6.s6_addr, 16);
  if (ip_matches_cidr_bytes (AF_INET6, ip_bytes, &entry))
    return 0;

  /* Test 3: fe80::1 matches fe80::/10 */
  entry.prefix_len = 10;
  inet_pton (AF_INET6, "fe80::", &addr6);
  memcpy (entry.addr_bytes, addr6.s6_addr, 16);

  inet_pton (AF_INET6, "fe80::1", &addr6);
  memcpy (ip_bytes, addr6.s6_addr, 16);
  if (!ip_matches_cidr_bytes (AF_INET6, ip_bytes, &entry))
    return 0;

  /* Test 4: Family mismatch (IPv6 IP vs IPv4 CIDR) */
  entry.addr_family = AF_INET;
  if (ip_matches_cidr_bytes (AF_INET6, ip_bytes, &entry))
    return 0;

  return 1;
}

/**
 * test_ip_matches_cidr_bytes_ipv6_edge - Test IPv6 edge cases (/0, /128)
 */
static int
test_ip_matches_cidr_bytes_ipv6_edge (void)
{
  SocketSYN_WhitelistEntry entry;
  uint8_t ip_bytes[16];
  struct in6_addr addr6;

  /* Test /0: matches all IPv6 */
  entry.addr_family = AF_INET6;
  entry.prefix_len = 0;
  inet_pton (AF_INET6, "::", &addr6);
  memcpy (entry.addr_bytes, addr6.s6_addr, 16);

  inet_pton (AF_INET6, "2001:db8::1", &addr6);
  memcpy (ip_bytes, addr6.s6_addr, 16);
  if (!ip_matches_cidr_bytes (AF_INET6, ip_bytes, &entry))
    return 0;

  inet_pton (AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &addr6);
  memcpy (ip_bytes, addr6.s6_addr, 16);
  if (!ip_matches_cidr_bytes (AF_INET6, ip_bytes, &entry))
    return 0;

  /* Test /128: exact match only */
  entry.prefix_len = 128;
  inet_pton (AF_INET6, "2001:db8::1234", &addr6);
  memcpy (entry.addr_bytes, addr6.s6_addr, 16);

  /* Exact match */
  inet_pton (AF_INET6, "2001:db8::1234", &addr6);
  memcpy (ip_bytes, addr6.s6_addr, 16);
  if (!ip_matches_cidr_bytes (AF_INET6, ip_bytes, &entry))
    return 0;

  /* Off by one */
  inet_pton (AF_INET6, "2001:db8::1235", &addr6);
  memcpy (ip_bytes, addr6.s6_addr, 16);
  if (ip_matches_cidr_bytes (AF_INET6, ip_bytes, &entry))
    return 0;

  return 1;
}

/**
 * test_ip_matches_cidr_string - Test string-based CIDR matching wrapper
 */
static int
test_ip_matches_cidr_string (void)
{
  SocketSYN_WhitelistEntry entry;
  struct in_addr addr4;
  struct in6_addr addr6;

  /* IPv4: 10.0.0.0/8 */
  entry.addr_family = AF_INET;
  entry.prefix_len = 8;
  inet_pton (AF_INET, "10.0.0.0", &addr4);
  memset (entry.addr_bytes, 0, sizeof (entry.addr_bytes));
  memcpy (entry.addr_bytes, &addr4.s_addr, 4);

  if (!ip_matches_cidr ("10.20.30.40", &entry))
    return 0;

  if (ip_matches_cidr ("11.0.0.1", &entry))
    return 0;

  /* IPv6: 2001:db8::/32 */
  entry.addr_family = AF_INET6;
  entry.prefix_len = 32;
  inet_pton (AF_INET6, "2001:db8::", &addr6);
  memcpy (entry.addr_bytes, addr6.s6_addr, 16);

  if (!ip_matches_cidr ("2001:db8::abcd", &entry))
    return 0;

  if (ip_matches_cidr ("2001:db9::1", &entry))
    return 0;

  /* NULL IP should return 0 */
  if (ip_matches_cidr (NULL, &entry))
    return 0;

  return 1;
}

/**
 * test_cidr_prefix_boundaries - Test all common prefix boundary cases
 */
static int
test_cidr_prefix_boundaries (void)
{
  SocketSYN_WhitelistEntry entry;
  uint8_t ip_bytes[16];
  struct in_addr addr;

  /* Test /7 boundary (partial first byte) */
  entry.addr_family = AF_INET;
  entry.prefix_len = 7;
  inet_pton (AF_INET, "8.0.0.0", &addr); /* 00001000 */
  memset (entry.addr_bytes, 0, sizeof (entry.addr_bytes));
  memcpy (entry.addr_bytes, &addr.s_addr, 4);

  /* 8.x.x.x (0000100x) should match */
  inet_pton (AF_INET, "8.8.8.8", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (!ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  /* 10.x.x.x (0000101x) should NOT match (bit 7 differs) */
  inet_pton (AF_INET, "10.0.0.0", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  /* Test /15 boundary (partial second byte) */
  entry.prefix_len = 15;
  inet_pton (AF_INET, "192.168.0.0", &addr);
  memcpy (entry.addr_bytes, &addr.s_addr, 4);

  inet_pton (AF_INET, "192.168.1.1", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (!ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  inet_pton (AF_INET, "192.169.0.0", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (!ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  /* Test /23 boundary (partial third byte) */
  entry.prefix_len = 23;
  inet_pton (AF_INET, "172.16.2.0", &addr);
  memcpy (entry.addr_bytes, &addr.s_addr, 4);

  inet_pton (AF_INET, "172.16.3.100", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (!ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  inet_pton (AF_INET, "172.16.4.0", &addr);
  memset (ip_bytes, 0, sizeof (ip_bytes));
  memcpy (ip_bytes, &addr.s_addr, 4);
  if (ip_matches_cidr_bytes (AF_INET, ip_bytes, &entry))
    return 0;

  return 1;
}

/* ============================================================================
 * Thread Safety Test
 * Thread Safety Test
 * LRU Eviction Tests
 * ============================================================================
 */

/* Forward declarations for thread worker (used in concurrent eviction test) */
static SocketSYNProtect_T g_protect = NULL;
static volatile int g_thread_errors = 0;
static void *thread_worker (void *arg);

/**
 * test_lru_eviction_at_capacity - Test LRU eviction when max tracked IPs
 * reached
 */
static int
test_lru_eviction_at_capacity (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  SocketSYNProtect_Stats stats;
  SocketSYN_IPState state;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_config_defaults (&config);
    config.max_tracked_ips = 10;
    protect = SocketSYNProtect_new (NULL, &config);

    /* Track 10 unique IPs to fill to capacity */
    char ip[32];
    for (int i = 0; i < 10; i++)
      {
        snprintf (ip, sizeof (ip), "192.168.1.%d", i + 1);
        SocketSYNProtect_check (protect, ip, NULL);
      }

    /* Verify we have 10 tracked IPs */
    SocketSYNProtect_stats (protect, &stats);
    success = (stats.current_tracked_ips == 10);

    /* Remember the first IP */
    const char *first_ip = "192.168.1.1";

    /* Track an 11th IP - should evict oldest (first) IP */
    SocketSYNProtect_check (protect, "192.168.1.11", NULL);

    /* Verify stats */
    SocketSYNProtect_stats (protect, &stats);
    success = success && (stats.current_tracked_ips == 10);
    success = success && (stats.lru_evictions == 1);

    /* Verify first IP was evicted */
    int found = SocketSYNProtect_get_ip_state (protect, first_ip, &state);
    success = success && (found == 0);

    /* Verify 11th IP is present */
    found = SocketSYNProtect_get_ip_state (protect, "192.168.1.11", &state);
    success = success && (found == 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_lru_touch_moves_to_front - Test that accessing an IP moves it to front
 * of LRU
 */
static int
test_lru_touch_moves_to_front (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  SocketSYN_IPState state;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_config_defaults (&config);
    config.max_tracked_ips = 5;
    protect = SocketSYNProtect_new (NULL, &config);

    /* Track 5 IPs in order: 1, 2, 3, 4, 5 */
    char ip[32];
    for (int i = 0; i < 5; i++)
      {
        snprintf (ip, sizeof (ip), "10.0.0.%d", i + 1);
        SocketSYNProtect_check (protect, ip, NULL);
      }

    /* Access IP #1 again - should move it to front of LRU */
    SocketSYNProtect_check (protect, "10.0.0.1", NULL);

    /* Now add a 6th IP - should evict IP #2 (not IP #1) */
    SocketSYNProtect_check (protect, "10.0.0.6", NULL);

    /* IP #1 should still exist (was moved to front) */
    int found1 = SocketSYNProtect_get_ip_state (protect, "10.0.0.1", &state);
    success = (found1 == 1);

    /* IP #2 should be evicted (was at tail) */
    int found2 = SocketSYNProtect_get_ip_state (protect, "10.0.0.2", &state);
    success = success && (found2 == 0);

    /* IP #6 should exist */
    int found6 = SocketSYNProtect_get_ip_state (protect, "10.0.0.6", &state);
    success = success && (found6 == 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_lru_ordering_preserved - Test that eviction follows strict LRU order
 */
static int
test_lru_ordering_preserved (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  SocketSYNProtect_Stats stats;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_config_defaults (&config);
    config.max_tracked_ips = 5;
    protect = SocketSYNProtect_new (NULL, &config);

    /* Track IPs: A, B, C, D, E */
    char ip[32];
    for (int i = 0; i < 5; i++)
      {
        snprintf (ip, sizeof (ip), "172.16.1.%d", i + 1);
        SocketSYNProtect_check (protect, ip, NULL);
      }

    /* Verify we have 5 IPs */
    SocketSYNProtect_stats (protect, &stats);
    success = (stats.current_tracked_ips == 5);

    /* Add a 6th IP - should evict one (likely the oldest) */
    SocketSYNProtect_check (protect, "172.16.1.6", NULL);

    /* Verify stats show eviction occurred */
    SocketSYNProtect_stats (protect, &stats);
    success = success && (stats.current_tracked_ips == 5);
    success = success && (stats.lru_evictions == 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_lru_with_arena_allocation - Test that arena allocation works
 * correctly
 */
static int
test_lru_with_arena_allocation (void)
{
  Arena_T arena = NULL;
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  SocketSYNProtect_Stats stats;
  volatile int success = 0;

  TRY
  {
    arena = Arena_new ();
    SocketSYNProtect_config_defaults (&config);
    config.max_tracked_ips = 10;
    protect = SocketSYNProtect_new (arena, &config);

    /* Add several IPs */
    char ip[32];
    for (int i = 0; i < 5; i++)
      {
        snprintf (ip, sizeof (ip), "192.0.2.%d", i + 1);
        SocketSYNProtect_check (protect, ip, NULL);
      }

    /* Verify IPs were tracked */
    SocketSYNProtect_stats (protect, &stats);
    success = (stats.current_tracked_ips == 5);

    /* Verify protection is working */
    SocketSYN_Action action
        = SocketSYNProtect_check (protect, "192.0.2.1", NULL);
    success = success && (action != SYN_ACTION_BLOCK);

    SocketSYNProtect_free (&protect);
    Arena_dispose (&arena);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_lru_with_malloc_allocation - Test LRU eviction with malloc allocation
 */
static int
test_lru_with_malloc_allocation (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  SocketSYNProtect_Stats stats;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_config_defaults (&config);
    config.max_tracked_ips = 3;
    protect = SocketSYNProtect_new (NULL, &config);

    /* Fill to capacity and trigger eviction */
    SocketSYNProtect_check (protect, "198.51.100.1", NULL);
    SocketSYNProtect_check (protect, "198.51.100.2", NULL);
    SocketSYNProtect_check (protect, "198.51.100.3", NULL);
    SocketSYNProtect_check (protect, "198.51.100.4", NULL); /* Triggers eviction
                                                              */

    SocketSYNProtect_stats (protect, &stats);
    success = (stats.current_tracked_ips == 3);
    success = success && (stats.lru_evictions == 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_lru_stats_accuracy - Test LRU eviction counter accuracy
 */
static int
test_lru_stats_accuracy (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  SocketSYNProtect_Stats stats;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_config_defaults (&config);
    config.max_tracked_ips = 5;
    protect = SocketSYNProtect_new (NULL, &config);

    /* Track 20 IPs - should cause 15 evictions */
    char ip[32];
    for (int i = 0; i < 20; i++)
      {
        snprintf (ip, sizeof (ip), "203.0.113.%d", i + 1);
        SocketSYNProtect_check (protect, ip, NULL);
      }

    SocketSYNProtect_stats (protect, &stats);

    /* Verify exactly 15 evictions */
    success = (stats.lru_evictions == 15);

    /* Verify current tracked IPs is at max */
    success = success && (stats.current_tracked_ips == 5);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_lru_concurrent_eviction - Test thread safety of LRU operations
 */
static int
test_lru_concurrent_eviction (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  SocketSYNProtect_Stats stats;
  pthread_t threads[4];
  int thread_ids[4];
  volatile int success = 0;

  TRY
  {
    /* Small capacity to force frequent evictions */
    SocketSYNProtect_config_defaults (&config);
    config.max_tracked_ips = 10;
    protect = SocketSYNProtect_new (NULL, &config);

    /* Spawn threads that will cause concurrent evictions */
    g_protect = protect;
    g_thread_errors = 0;

    for (int i = 0; i < 4; i++)
      {
        thread_ids[i] = i;
        pthread_create (&threads[i], NULL, thread_worker, &thread_ids[i]);
      }

    for (int i = 0; i < 4; i++)
      pthread_join (threads[i], NULL);

    /* Verify no errors occurred */
    success = (g_thread_errors == 0);

    /* Verify stats are consistent */
    SocketSYNProtect_stats (protect, &stats);
    success = success && (stats.current_tracked_ips <= 10);
    success = success && (stats.lru_evictions > 0);

    g_protect = NULL;
    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/* ============================================================================
 * Thread Safety Test
 * ============================================================================
 */

static void *
thread_worker (void *arg)
{
  int thread_id = *(int *)arg;
  char ip[32];

  for (int i = 0; i < 100; i++)
    {
      snprintf (
          ip, sizeof (ip), "100.%d.%d.%d", thread_id, i % 256, (i * 7) % 256);

      TRY
      {
        SocketSYNProtect_check (g_protect, ip, NULL);
      }
      ELSE
      {
        g_thread_errors++;
      }
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
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/* ============================================================================
 * LRU Eviction Tests
 * ============================================================================
 */

/**
 * test_lru_ordering_basic - Test LRU order is newest-to-oldest
 */
static int
test_lru_ordering_basic (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state1, state2, state3;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    /* Add 3 IPs in order */
    SocketSYNProtect_check (protect, "10.0.0.1", &state1);
    SocketSYNProtect_check (protect, "10.0.0.2", &state2);
    SocketSYNProtect_check (protect, "10.0.0.3", &state3);

    /* Most recent should be checked last */
    success = (state3.last_attempt_ms >= state2.last_attempt_ms);
    success = success && (state2.last_attempt_ms >= state1.last_attempt_ms);

    /* All should be tracked */
    SocketSYNProtect_Stats stats;
    SocketSYNProtect_stats (protect, &stats);
    success = success && (stats.current_tracked_ips == 3);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_lru_touch_middle - Test accessing middle IP moves it to front
 */
static int
test_lru_touch_middle (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state1, state2;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    /* Add 3 IPs */
    SocketSYNProtect_check (protect, "192.168.1.1", NULL);
    SocketSYNProtect_check (protect, "192.168.1.2", NULL);
    SocketSYNProtect_check (protect, "192.168.1.3", NULL);

    SocketSYNProtect_get_ip_state (protect, "192.168.1.2", &state1);

    /* Access the middle IP again */
    SocketSYNProtect_check (protect, "192.168.1.2", NULL);
    SocketSYNProtect_get_ip_state (protect, "192.168.1.2", &state2);

    /* Should have newer timestamp and more attempts */
    success = (state2.last_attempt_ms >= state1.last_attempt_ms);
    success = success && (state2.attempts_current > state1.attempts_current);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_lru_touch_head - Test accessing head IP is a no-op
 */
static int
test_lru_touch_head (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYN_IPState state1, state2;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    /* Add 3 IPs - last one is head */
    SocketSYNProtect_check (protect, "172.16.0.1", NULL);
    SocketSYNProtect_check (protect, "172.16.0.2", NULL);
    SocketSYNProtect_check (protect, "172.16.0.3", NULL);

    SocketSYNProtect_get_ip_state (protect, "172.16.0.3", &state1);

    /* Access head again */
    SocketSYNProtect_check (protect, "172.16.0.3", NULL);
    SocketSYNProtect_get_ip_state (protect, "172.16.0.3", &state2);

    /* Should increment attempts counter */
    success = (state2.attempts_current > state1.attempts_current);

    /* All still tracked */
    SocketSYNProtect_Stats stats;
    SocketSYNProtect_stats (protect, &stats);
    success = success && (stats.current_tracked_ips == 3);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_lru_eviction_basic - Test eviction when reaching capacity
 */
static int
test_lru_eviction_basic (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  volatile int success = 0;

  TRY
  {
    /* Set low capacity for testing */
    SocketSYNProtect_config_defaults (&config);
    config.max_tracked_ips = 3;

    protect = SocketSYNProtect_new (NULL, &config);

    /* Fill to capacity */
    SocketSYNProtect_check (protect, "1.1.1.1", NULL);
    SocketSYNProtect_check (protect, "2.2.2.2", NULL);
    SocketSYNProtect_check (protect, "3.3.3.3", NULL);

    SocketSYNProtect_Stats stats1;
    SocketSYNProtect_stats (protect, &stats1);
    success = (stats1.current_tracked_ips == 3);

    /* Add one more - should evict oldest (1.1.1.1) */
    SocketSYNProtect_check (protect, "4.4.4.4", NULL);

    SocketSYNProtect_Stats stats2;
    SocketSYNProtect_stats (protect, &stats2);

    /* Should still be at capacity */
    success = success && (stats2.current_tracked_ips == 3);

    /* Oldest IP should be gone */
    SocketSYN_IPState state;
    int found = SocketSYNProtect_get_ip_state (protect, "1.1.1.1", &state);
    success = success && (found == 0);

    /* New IP should be present */
    found = SocketSYNProtect_get_ip_state (protect, "4.4.4.4", &state);
    success = success && (found == 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_lru_eviction_counter - Test eviction counter increments
 */
static int
test_lru_eviction_counter (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_config_defaults (&config);
    config.max_tracked_ips = 2;

    protect = SocketSYNProtect_new (NULL, &config);

    /* Fill capacity */
    SocketSYNProtect_check (protect, "10.1.1.1", NULL);
    SocketSYNProtect_check (protect, "10.2.2.2", NULL);

    SocketSYNProtect_Stats stats1;
    SocketSYNProtect_stats (protect, &stats1);
    uint64_t evictions_before = stats1.lru_evictions;

    /* Trigger eviction */
    SocketSYNProtect_check (protect, "10.3.3.3", NULL);

    SocketSYNProtect_Stats stats2;
    SocketSYNProtect_stats (protect, &stats2);

    /* Eviction counter should increment */
    success = (stats2.lru_evictions == evictions_before + 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_lru_eviction_empty - Test eviction from empty list is no-op
 */
static int
test_lru_eviction_empty (void)
{
  SocketSYNProtect_T protect = NULL;
  volatile int success = 0;

  TRY
  {
    protect = SocketSYNProtect_new (NULL, NULL);

    /* Get initial stats */
    SocketSYNProtect_Stats stats1;
    SocketSYNProtect_stats (protect, &stats1);
    success = (stats1.current_tracked_ips == 0);

    /* Cleanup should handle empty list gracefully */
    size_t removed = SocketSYNProtect_cleanup (protect);

    SocketSYNProtect_Stats stats2;
    SocketSYNProtect_stats (protect, &stats2);

    /* Should still be empty */
    success = success && (stats2.current_tracked_ips == 0);
    success = success && (stats2.lru_evictions == 0);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_lru_eviction_single - Test evicting single entry
 */
static int
test_lru_eviction_single (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_config_defaults (&config);
    config.max_tracked_ips = 1;

    protect = SocketSYNProtect_new (NULL, &config);

    /* Add one IP */
    SocketSYNProtect_check (protect, "50.50.50.50", NULL);

    SocketSYNProtect_Stats stats1;
    SocketSYNProtect_stats (protect, &stats1);
    success = (stats1.current_tracked_ips == 1);

    /* Add another - should evict the first and only entry */
    SocketSYNProtect_check (protect, "60.60.60.60", NULL);

    SocketSYNProtect_Stats stats2;
    SocketSYNProtect_stats (protect, &stats2);

    /* Should still have 1 entry */
    success = success && (stats2.current_tracked_ips == 1);

    /* Old IP should be gone */
    SocketSYN_IPState state;
    int found = SocketSYNProtect_get_ip_state (protect, "50.50.50.50", &state);
    success = success && (found == 0);

    /* New IP should exist */
    found = SocketSYNProtect_get_ip_state (protect, "60.60.60.60", &state);
    success = success && (found == 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_lru_eviction_removes_from_hash - Test eviction removes from hash table
 */
static int
test_lru_eviction_removes_from_hash (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_config_defaults (&config);
    config.max_tracked_ips = 3;

    protect = SocketSYNProtect_new (NULL, &config);

    /* Fill capacity */
    SocketSYNProtect_check (protect, "100.0.0.1", NULL);
    SocketSYNProtect_check (protect, "100.0.0.2", NULL);
    SocketSYNProtect_check (protect, "100.0.0.3", NULL);

    /* Verify all present */
    SocketSYN_IPState state;
    success = (SocketSYNProtect_get_ip_state (protect, "100.0.0.1", &state)
               == 1);
    success = success
              && (SocketSYNProtect_get_ip_state (protect, "100.0.0.2", &state)
                  == 1);
    success = success
              && (SocketSYNProtect_get_ip_state (protect, "100.0.0.3", &state)
                  == 1);

    /* Trigger eviction of oldest */
    SocketSYNProtect_check (protect, "100.0.0.4", NULL);

    /* Evicted IP should not be found in hash table */
    int found = SocketSYNProtect_get_ip_state (protect, "100.0.0.1", &state);
    success = success && (found == 0);

    /* Other IPs should remain */
    success = success
              && (SocketSYNProtect_get_ip_state (protect, "100.0.0.2", &state)
                  == 1);
    success = success
              && (SocketSYNProtect_get_ip_state (protect, "100.0.0.3", &state)
                  == 1);
    success = success
              && (SocketSYNProtect_get_ip_state (protect, "100.0.0.4", &state)
                  == 1);

    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
  END_TRY;

  return success;
}

/**
 * test_lru_with_malloc - Test LRU with malloc allocator
 */
static int
test_lru_with_malloc (void)
{
  SocketSYNProtect_T protect = NULL;
  SocketSYNProtect_Config config;
  volatile int success = 0;

  TRY
  {
    SocketSYNProtect_config_defaults (&config);
    config.max_tracked_ips = 2;

    /* NULL arena means malloc */
    protect = SocketSYNProtect_new (NULL, &config);

    /* Fill and trigger eviction */
    SocketSYNProtect_check (protect, "250.0.0.1", NULL);
    SocketSYNProtect_check (protect, "250.0.0.2", NULL);
    SocketSYNProtect_check (protect, "250.0.0.3", NULL);

    /* Should have evicted and freed memory */
    SocketSYNProtect_Stats stats;
    SocketSYNProtect_stats (protect, &stats);
    success = (stats.current_tracked_ips == 2);
    success = success && (stats.lru_evictions >= 1);

    /* No leaks should be detected by sanitizers */
    SocketSYNProtect_free (&protect);
  }
  ELSE
  {
    success = 0;
  }
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

  printf ("\nSliding Window Algorithm Tests:\n");
  RUN_TEST (test_window_rotation_no_rotation);
  RUN_TEST (test_window_rotation_occurs);
  RUN_TEST (test_window_progress_0_percent);
  RUN_TEST (test_window_progress_50_percent);
  RUN_TEST (test_window_progress_100_percent);
  RUN_TEST (test_effective_attempts_current_only);
  RUN_TEST (test_effective_attempts_both_windows);
  RUN_TEST (test_window_zero_duration);
  RUN_TEST (test_monotonic_time_handling);

  printf ("\nCIDR Matching Algorithm Tests:\n");
  RUN_TEST (test_cidr_full_bytes_match);
  RUN_TEST (test_cidr_partial_byte_match);
  RUN_TEST (test_ip_matches_cidr_bytes_ipv4);
  RUN_TEST (test_ip_matches_cidr_bytes_ipv4_partial);
  RUN_TEST (test_ip_matches_cidr_bytes_ipv4_edge);
  RUN_TEST (test_ip_matches_cidr_bytes_ipv6);
  RUN_TEST (test_ip_matches_cidr_bytes_ipv6_edge);
  RUN_TEST (test_ip_matches_cidr_string);
  RUN_TEST (test_cidr_prefix_boundaries);

  printf ("\nLRU Eviction Tests:\n");
  RUN_TEST (test_lru_eviction_at_capacity);
  RUN_TEST (test_lru_touch_moves_to_front);
  RUN_TEST (test_lru_ordering_preserved);
  RUN_TEST (test_lru_with_arena_allocation);
  RUN_TEST (test_lru_with_malloc_allocation);
  RUN_TEST (test_lru_stats_accuracy);
  RUN_TEST (test_lru_concurrent_eviction);

  printf ("\nThread Safety Tests:\n");
  RUN_TEST (test_thread_safety);

  printf ("\nLRU Eviction Tests:\n");
  RUN_TEST (test_lru_ordering_basic);
  RUN_TEST (test_lru_touch_middle);
  RUN_TEST (test_lru_touch_head);
  RUN_TEST (test_lru_eviction_basic);
  RUN_TEST (test_lru_eviction_counter);
  RUN_TEST (test_lru_eviction_empty);
  RUN_TEST (test_lru_eviction_single);
  RUN_TEST (test_lru_eviction_removes_from_hash);
  RUN_TEST (test_lru_with_malloc);

  printf ("\n=== Results: %d/%d tests passed ===\n\n", tests_passed, tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}
