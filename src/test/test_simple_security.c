/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file test_simple_security.c
 * @brief Tests for Simple API security wrapper pattern refactoring.
 *
 * Verifies that Socket_simple_syn_new and Socket_simple_ip_tracker_new
 * work correctly after extracting the common wrapper pattern into the
 * SIMPLE_SECURITY_WRAP_NEW macro.
 */

#include <string.h>

#include "simple/SocketSimple-security.h"
#include "test/Test.h"

/* ============================================================================
 * SYN Protection Tests
 * ============================================================================
 */

TEST (syn_new_default_config)
{
  SocketSimple_SYNProtect_T protect;

  /* Create with NULL config - should use defaults */
  protect = Socket_simple_syn_new (NULL);
  ASSERT_NOT_NULL (protect);

  /* Cleanup */
  Socket_simple_syn_free (&protect);
  ASSERT_NULL (protect);
}

TEST (syn_new_custom_config)
{
  SocketSimple_SYNConfig config;
  SocketSimple_SYNProtect_T protect;

  /* Initialize config with custom values */
  Socket_simple_syn_config_init (&config);
  config.max_tracked_ips = 500;
  config.window_duration_ms = 10000;
  config.max_attempts_per_window = 5;

  /* Create with custom config */
  protect = Socket_simple_syn_new (&config);
  ASSERT_NOT_NULL (protect);

  /* Cleanup */
  Socket_simple_syn_free (&protect);
  ASSERT_NULL (protect);
}

TEST (syn_basic_functionality)
{
  SocketSimple_SYNProtect_T protect;
  SocketSimple_SYNAction action;

  protect = Socket_simple_syn_new (NULL);
  ASSERT_NOT_NULL (protect);

  /* Check unknown IP - should allow by default */
  action = Socket_simple_syn_check (protect, "192.168.1.100");
  ASSERT_EQ (action, SOCKET_SIMPLE_SYN_ALLOW);

  /* Report success */
  Socket_simple_syn_report_success (protect, "192.168.1.100");

  /* Check stats */
  SocketSimple_SYNStats stats;
  int result = Socket_simple_syn_stats (protect, &stats);
  ASSERT_EQ (result, 0);
  ASSERT (stats.total_attempts > 0);

  Socket_simple_syn_free (&protect);
}

TEST (syn_whitelist)
{
  SocketSimple_SYNProtect_T protect;
  int result;

  protect = Socket_simple_syn_new (NULL);
  ASSERT_NOT_NULL (protect);

  /* Add to whitelist */
  result = Socket_simple_syn_whitelist_add (protect, "10.0.0.1");
  ASSERT_NE (result, 0);

  /* Check if in whitelist */
  result = Socket_simple_syn_whitelist_contains (protect, "10.0.0.1");
  ASSERT_NE (result, 0);

  /* Remove from whitelist */
  Socket_simple_syn_whitelist_remove (protect, "10.0.0.1");
  result = Socket_simple_syn_whitelist_contains (protect, "10.0.0.1");
  ASSERT_EQ (result, 0);

  Socket_simple_syn_free (&protect);
}

/* ============================================================================
 * IP Tracker Tests
 * ============================================================================
 */

TEST (ip_tracker_new)
{
  SocketSimple_IPTracker_T tracker;

  /* Create with max_per_ip = 10 */
  tracker = Socket_simple_ip_tracker_new (10);
  ASSERT_NOT_NULL (tracker);

  /* Check max value */
  int max = Socket_simple_ip_tracker_get_max (tracker);
  ASSERT_EQ (max, 10);

  /* Cleanup */
  Socket_simple_ip_tracker_free (&tracker);
  ASSERT_NULL (tracker);
}

TEST (ip_tracker_basic_functionality)
{
  SocketSimple_IPTracker_T tracker;
  int result;

  tracker = Socket_simple_ip_tracker_new (3);
  ASSERT_NOT_NULL (tracker);

  /* Track first connection from 192.168.1.1 */
  result = Socket_simple_ip_tracker_track (tracker, "192.168.1.1");
  ASSERT_NE (result, 0);

  /* Check count */
  int count = Socket_simple_ip_tracker_count (tracker, "192.168.1.1");
  ASSERT_EQ (count, 1);

  /* Track second connection */
  result = Socket_simple_ip_tracker_track (tracker, "192.168.1.1");
  ASSERT_NE (result, 0);

  count = Socket_simple_ip_tracker_count (tracker, "192.168.1.1");
  ASSERT_EQ (count, 2);

  /* Release one connection */
  Socket_simple_ip_tracker_release (tracker, "192.168.1.1");
  count = Socket_simple_ip_tracker_count (tracker, "192.168.1.1");
  ASSERT_EQ (count, 1);

  /* Check total connections */
  size_t total = Socket_simple_ip_tracker_total (tracker);
  ASSERT_EQ (total, 1);

  /* Check unique IPs */
  size_t unique = Socket_simple_ip_tracker_unique_ips (tracker);
  ASSERT_EQ (unique, 1);

  Socket_simple_ip_tracker_free (&tracker);
}

TEST (ip_tracker_max_limit)
{
  SocketSimple_IPTracker_T tracker;
  int result;

  tracker = Socket_simple_ip_tracker_new (2);
  ASSERT_NOT_NULL (tracker);

  /* Track up to max */
  result = Socket_simple_ip_tracker_track (tracker, "10.0.0.1");
  ASSERT_NE (result, 0);

  result = Socket_simple_ip_tracker_track (tracker, "10.0.0.1");
  ASSERT_NE (result, 0);

  /* Try to exceed limit */
  result = Socket_simple_ip_tracker_track (tracker, "10.0.0.1");
  ASSERT_EQ (result, 0);

  /* Release one and try again */
  Socket_simple_ip_tracker_release (tracker, "10.0.0.1");
  result = Socket_simple_ip_tracker_track (tracker, "10.0.0.1");
  ASSERT_NE (result, 0);

  Socket_simple_ip_tracker_free (&tracker);
}

TEST (ip_tracker_set_max)
{
  SocketSimple_IPTracker_T tracker;
  int max;

  tracker = Socket_simple_ip_tracker_new (10);
  ASSERT_NOT_NULL (tracker);

  /* Change max */
  Socket_simple_ip_tracker_set_max (tracker, 20);
  max = Socket_simple_ip_tracker_get_max (tracker);
  ASSERT_EQ (max, 20);

  Socket_simple_ip_tracker_free (&tracker);
}

TEST (ip_tracker_clear)
{
  SocketSimple_IPTracker_T tracker;

  tracker = Socket_simple_ip_tracker_new (10);
  ASSERT_NOT_NULL (tracker);

  /* Track some connections */
  Socket_simple_ip_tracker_track (tracker, "10.0.0.1");
  Socket_simple_ip_tracker_track (tracker, "10.0.0.2");
  Socket_simple_ip_tracker_track (tracker, "10.0.0.3");

  /* Verify total */
  size_t total = Socket_simple_ip_tracker_total (tracker);
  ASSERT_EQ (total, 3);

  /* Clear */
  Socket_simple_ip_tracker_clear (tracker);
  total = Socket_simple_ip_tracker_total (tracker);
  ASSERT_EQ (total, 0);

  size_t unique = Socket_simple_ip_tracker_unique_ips (tracker);
  ASSERT_EQ (unique, 0);

  Socket_simple_ip_tracker_free (&tracker);
}

/* ============================================================================
 * Test Runner
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
