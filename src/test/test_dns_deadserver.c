/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/*
 * test_dns_deadserver.c - Unit tests for DNS Dead Server Tracking (RFC 2308 Section 7.2)
 *
 * Tests RFC 2308 Section 7.2 compliant dead server tracking with:
 * - Per-nameserver tracking (not per-query)
 * - 5-minute maximum blacklist duration
 * - Consecutive failure threshold
 * - Automatic recovery when server responds
 */

#include "core/Arena.h"
#include "dns/SocketDNSDeadServer.h"
#include "test/Test.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Test basic tracker creation and disposal */
TEST (deadserver_new_free)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);
  ASSERT_NOT_NULL (tracker);

  SocketDNS_DeadServerStats stats;
  SocketDNSDeadServer_stats (tracker, &stats);
  ASSERT_EQ (stats.current_dead, 0);
  ASSERT_EQ (stats.max_tracked, DNS_DEAD_SERVER_MAX_TRACKED);

  SocketDNSDeadServer_free (&tracker);
  ASSERT_NULL (tracker);
  Arena_dispose (&arena);
}

/* Test that servers are not dead initially */
TEST (deadserver_initially_not_dead)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);

  /* Any server should be considered alive initially */
  bool is_dead = SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL);
  ASSERT_EQ (is_dead, false);

  is_dead = SocketDNSDeadServer_is_dead (tracker, "8.8.4.4", NULL);
  ASSERT_EQ (is_dead, false);

  is_dead
      = SocketDNSDeadServer_is_dead (tracker, "2001:4860:4860::8888", NULL);
  ASSERT_EQ (is_dead, false);

  SocketDNS_DeadServerStats stats;
  SocketDNSDeadServer_stats (tracker, &stats);
  ASSERT_EQ (stats.checks, 3);
  ASSERT_EQ (stats.dead_hits, 0);

  SocketDNSDeadServer_free (&tracker);
  Arena_dispose (&arena);
}

/* Test consecutive failure threshold (default 2) */
TEST (deadserver_failure_threshold)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);

  /* Verify default threshold is 2 */
  int threshold = SocketDNSDeadServer_get_threshold (tracker);
  ASSERT_EQ (threshold, DNS_DEAD_SERVER_DEFAULT_THRESHOLD);

  /* First failure - not dead yet */
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), false);

  /* Second failure - now dead (threshold=2) */
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), true);

  SocketDNS_DeadServerStats stats;
  SocketDNSDeadServer_stats (tracker, &stats);
  ASSERT_EQ (stats.dead_marks, 1);
  ASSERT_EQ (stats.current_dead, 1);

  SocketDNSDeadServer_free (&tracker);
  Arena_dispose (&arena);
}

/* Test custom failure threshold */
TEST (deadserver_custom_threshold)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);

  /* Set threshold to 3 */
  SocketDNSDeadServer_set_threshold (tracker, 3);
  ASSERT_EQ (SocketDNSDeadServer_get_threshold (tracker), 3);

  /* First two failures - not dead yet */
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), false);

  /* Third failure - now dead */
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), true);

  SocketDNSDeadServer_free (&tracker);
  Arena_dispose (&arena);
}

/* Test threshold of 1 (immediate dead on first failure) */
TEST (deadserver_threshold_one)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);

  /* Set threshold to 1 */
  SocketDNSDeadServer_set_threshold (tracker, 1);

  /* First failure - immediately dead */
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), true);

  SocketDNSDeadServer_free (&tracker);
  Arena_dispose (&arena);
}

/* Test mark_alive clears dead status */
TEST (deadserver_mark_alive)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);

  /* Mark server as dead */
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), true);

  /* Mark alive - should clear dead status */
  SocketDNSDeadServer_mark_alive (tracker, "8.8.8.8");
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), false);

  SocketDNS_DeadServerStats stats;
  SocketDNSDeadServer_stats (tracker, &stats);
  ASSERT_EQ (stats.alive_marks, 1);
  ASSERT_EQ (stats.current_dead, 0);

  SocketDNSDeadServer_free (&tracker);
  Arena_dispose (&arena);
}

/* Test mark_alive resets failure counter */
TEST (deadserver_alive_resets_counter)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);

  /* One failure */
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), false);

  /* Mark alive - resets counter */
  SocketDNSDeadServer_mark_alive (tracker, "8.8.8.8");

  /* One more failure - should still be alive (counter reset) */
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), false);

  /* Second failure after reset - now dead */
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), true);

  SocketDNSDeadServer_free (&tracker);
  Arena_dispose (&arena);
}

/* Test per-nameserver isolation */
TEST (deadserver_per_server_isolation)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);

  /* Mark 8.8.8.8 as dead */
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), true);

  /* Other servers should still be alive */
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.4.4", NULL), false);
  ASSERT_EQ (
      SocketDNSDeadServer_is_dead (tracker, "2001:4860:4860::8888", NULL),
      false);

  /* Mark 8.8.4.4 as dead too */
  SocketDNSDeadServer_mark_failure (tracker, "8.8.4.4");
  SocketDNSDeadServer_mark_failure (tracker, "8.8.4.4");
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.4.4", NULL), true);

  /* Alive on one server doesn't affect another */
  SocketDNSDeadServer_mark_alive (tracker, "8.8.8.8");
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), false);
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.4.4", NULL), true);

  SocketDNSDeadServer_free (&tracker);
  Arena_dispose (&arena);
}

/* Test RFC 2308 Section 7.2: 5-minute max TTL */
TEST (deadserver_max_ttl_5min)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);

  /* Mark server as dead */
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), true);

  /* Check TTL is <= 5 minutes */
  SocketDNS_DeadServerEntry entry;
  SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", &entry);
  ASSERT (entry.ttl_remaining <= DNS_DEAD_SERVER_MAX_TTL);
  ASSERT (entry.ttl_remaining > 0);
  ASSERT_EQ (entry.consecutive_failures, 2);

  SocketDNSDeadServer_free (&tracker);
  Arena_dispose (&arena);
}

/* Test TTL expiration */
TEST (deadserver_ttl_expiration)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);

  /* Mark server as dead */
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), true);

  /* Wait 1 second and check it's still dead */
  sleep (1);
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), true);

  /* Note: We can't easily test the 5-minute expiration in a unit test
     as it would take too long. The expiration logic is tested indirectly
     by verifying the TTL value is reasonable. */

  SocketDNSDeadServer_free (&tracker);
  Arena_dispose (&arena);
}

/* Test prune function */
TEST (deadserver_prune)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);

  /* Mark some servers as dead */
  SocketDNSDeadServer_set_threshold (tracker, 1);
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  SocketDNSDeadServer_mark_failure (tracker, "8.8.4.4");

  SocketDNS_DeadServerStats stats;
  SocketDNSDeadServer_stats (tracker, &stats);
  ASSERT_EQ (stats.current_dead, 2);

  /* Prune should not remove entries that haven't expired */
  int pruned = SocketDNSDeadServer_prune (tracker);
  ASSERT_EQ (pruned, 0);

  SocketDNSDeadServer_stats (tracker, &stats);
  ASSERT_EQ (stats.current_dead, 2);

  SocketDNSDeadServer_free (&tracker);
  Arena_dispose (&arena);
}

/* Test clear function */
TEST (deadserver_clear)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);

  /* Mark several servers as dead */
  SocketDNSDeadServer_set_threshold (tracker, 1);
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  SocketDNSDeadServer_mark_failure (tracker, "8.8.4.4");
  SocketDNSDeadServer_mark_failure (tracker, "1.1.1.1");

  SocketDNS_DeadServerStats stats;
  SocketDNSDeadServer_stats (tracker, &stats);
  ASSERT_EQ (stats.current_dead, 3);

  /* Clear all */
  SocketDNSDeadServer_clear (tracker);

  SocketDNSDeadServer_stats (tracker, &stats);
  ASSERT_EQ (stats.current_dead, 0);

  /* All servers should be alive now */
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), false);
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.4.4", NULL), false);
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "1.1.1.1", NULL), false);

  SocketDNSDeadServer_free (&tracker);
  Arena_dispose (&arena);
}

/* Test statistics accuracy */
TEST (deadserver_stats_accuracy)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);

  SocketDNS_DeadServerStats stats;
  SocketDNSDeadServer_stats (tracker, &stats);

  /* Initial stats should be zero */
  ASSERT_EQ (stats.checks, 0);
  ASSERT_EQ (stats.dead_hits, 0);
  ASSERT_EQ (stats.alive_marks, 0);
  ASSERT_EQ (stats.dead_marks, 0);

  /* Check some servers */
  SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL);
  SocketDNSDeadServer_is_dead (tracker, "8.8.4.4", NULL);

  SocketDNSDeadServer_stats (tracker, &stats);
  ASSERT_EQ (stats.checks, 2);
  ASSERT_EQ (stats.dead_hits, 0);

  /* Mark as dead and check again */
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");

  SocketDNSDeadServer_stats (tracker, &stats);
  ASSERT_EQ (stats.dead_marks, 1);

  SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL);

  SocketDNSDeadServer_stats (tracker, &stats);
  ASSERT_EQ (stats.dead_hits, 1);
  ASSERT_EQ (stats.checks, 3);

  /* Mark alive */
  SocketDNSDeadServer_mark_alive (tracker, "8.8.8.8");

  SocketDNSDeadServer_stats (tracker, &stats);
  ASSERT_EQ (stats.alive_marks, 1);

  SocketDNSDeadServer_free (&tracker);
  Arena_dispose (&arena);
}

/* Test IPv6 nameserver addresses */
TEST (deadserver_ipv6)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);

  /* Mark IPv6 server as dead */
  SocketDNSDeadServer_mark_failure (tracker, "2001:4860:4860::8888");
  SocketDNSDeadServer_mark_failure (tracker, "2001:4860:4860::8888");
  ASSERT_EQ (
      SocketDNSDeadServer_is_dead (tracker, "2001:4860:4860::8888", NULL),
      true);

  /* Different IPv6 should be alive */
  ASSERT_EQ (
      SocketDNSDeadServer_is_dead (tracker, "2001:4860:4860::8844", NULL),
      false);

  /* Mark alive */
  SocketDNSDeadServer_mark_alive (tracker, "2001:4860:4860::8888");
  ASSERT_EQ (
      SocketDNSDeadServer_is_dead (tracker, "2001:4860:4860::8888", NULL),
      false);

  SocketDNSDeadServer_free (&tracker);
  Arena_dispose (&arena);
}

/* Test NULL inputs are handled gracefully */
TEST (deadserver_null_inputs)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);

  /* is_dead with NULL address should return false */
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, NULL, NULL), false);

  /* mark_failure with NULL should not crash */
  SocketDNSDeadServer_mark_failure (tracker, NULL);

  /* mark_alive with NULL should not crash */
  SocketDNSDeadServer_mark_alive (tracker, NULL);

  /* Tracker should still work after NULL inputs */
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", NULL), true);

  SocketDNSDeadServer_free (&tracker);
  Arena_dispose (&arena);
}

/* Test entry info is populated correctly */
TEST (deadserver_entry_info)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);

  /* Mark server as dead */
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8");
  SocketDNSDeadServer_mark_failure (tracker, "8.8.8.8"); /* 3 failures */

  SocketDNS_DeadServerEntry entry;
  memset (&entry, 0, sizeof (entry));

  bool is_dead = SocketDNSDeadServer_is_dead (tracker, "8.8.8.8", &entry);
  ASSERT_EQ (is_dead, true);
  ASSERT_EQ (entry.consecutive_failures, 3);
  ASSERT (entry.ttl_remaining > 0);
  ASSERT (entry.ttl_remaining <= DNS_DEAD_SERVER_MAX_TTL);
  ASSERT (entry.marked_dead_ms > 0);

  SocketDNSDeadServer_free (&tracker);
  Arena_dispose (&arena);
}

/* Test maximum tracked servers limit */
TEST (deadserver_max_tracked)
{
  Arena_T arena = Arena_new ();
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (arena);

  SocketDNSDeadServer_set_threshold (tracker, 1);

  /* Fill up to max */
  char addr[32];
  for (int i = 0; i < DNS_DEAD_SERVER_MAX_TRACKED; i++)
    {
      snprintf (addr, sizeof (addr), "192.168.1.%d", i);
      SocketDNSDeadServer_mark_failure (tracker, addr);
    }

  SocketDNS_DeadServerStats stats;
  SocketDNSDeadServer_stats (tracker, &stats);
  ASSERT_EQ (stats.current_dead, DNS_DEAD_SERVER_MAX_TRACKED);

  /* All should be tracked and dead */
  for (int i = 0; i < DNS_DEAD_SERVER_MAX_TRACKED; i++)
    {
      snprintf (addr, sizeof (addr), "192.168.1.%d", i);
      ASSERT_EQ (SocketDNSDeadServer_is_dead (tracker, addr, NULL), true);
    }

  SocketDNSDeadServer_free (&tracker);
  Arena_dispose (&arena);
}

/* Test that tracker works with NULL arena */
TEST (deadserver_null_arena)
{
  SocketDNSDeadServer_T tracker = SocketDNSDeadServer_new (NULL);
  ASSERT_NULL (tracker);
}

/* Main function - run all tests */
int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
