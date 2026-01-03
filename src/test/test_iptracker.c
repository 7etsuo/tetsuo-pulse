/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_iptracker.c - SocketIPTracker edge case unit tests
 * Tests for edge cases and error conditions in SocketIPTracker module.
 * Implements missing test coverage from issue #3058.
 */

#include <assert.h>
#include <limits.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketIPTracker.h"
#include "test/Test.h"

/* Test empty IP string handling */
TEST (iptracker_empty_ip_string)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = SocketIPTracker_new (arena, 10);

  /* Empty string should be rejected as basic invalid (returns 1 - allowed but
   * not tracked) */
  int result = SocketIPTracker_track (tracker, "");
  ASSERT_EQ (result, 1); /* Basic invalid returns 1 (safe default) */

  /* Count should return 0 (not tracked) */
  ASSERT_EQ (SocketIPTracker_count (tracker, ""), 0);

  /* Total and unique should still be 0 */
  ASSERT_EQ (SocketIPTracker_total (tracker), 0);
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 0);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test very long IP string handling */
TEST (iptracker_very_long_ip)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = SocketIPTracker_new (arena, 10);

  /* Create IP string that's too long (256 bytes) */
  char long_ip[256];
  memset (long_ip, 'a', sizeof (long_ip) - 1);
  long_ip[sizeof (long_ip) - 1] = '\0';

  /* Should be rejected (returns 0 - advanced invalid) */
  int result = SocketIPTracker_track (tracker, long_ip);
  ASSERT_EQ (result, 0);

  /* Count should return 0 (not tracked) */
  ASSERT_EQ (SocketIPTracker_count (tracker, long_ip), 0);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test release on non-existent IP */
TEST (iptracker_release_nonexistent)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = SocketIPTracker_new (arena, 10);

  /* Release IP that was never tracked (should not crash) */
  SocketIPTracker_release (tracker, "192.168.1.1");

  /* Should not crash, counts should be 0 */
  ASSERT_EQ (SocketIPTracker_count (tracker, "192.168.1.1"), 0);
  ASSERT_EQ (SocketIPTracker_total (tracker), 0);
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 0);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test multiple release beyond zero */
TEST (iptracker_release_beyond_zero)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = SocketIPTracker_new (arena, 10);

  /* Track once */
  int result = SocketIPTracker_track (tracker, "192.168.1.1");
  ASSERT_EQ (result, 1); /* Should be allowed */
  ASSERT_EQ (SocketIPTracker_count (tracker, "192.168.1.1"), 1);
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 1);
  ASSERT_EQ (SocketIPTracker_total (tracker), 1);

  /* Release once (should go to 0 and remove entry) */
  SocketIPTracker_release (tracker, "192.168.1.1");
  ASSERT_EQ (SocketIPTracker_count (tracker, "192.168.1.1"), 0);
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 0);
  ASSERT_EQ (SocketIPTracker_total (tracker), 0);

  /* Release again (should be no-op, entry doesn't exist) */
  SocketIPTracker_release (tracker, "192.168.1.1");
  ASSERT_EQ (SocketIPTracker_count (tracker, "192.168.1.1"), 0);
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 0);
  ASSERT_EQ (SocketIPTracker_total (tracker), 0);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test mixed IPv4 and IPv6 tracking */
TEST (iptracker_mixed_ipv4_ipv6)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = SocketIPTracker_new (arena, 10);

  /* Track IPv4 and IPv6 */
  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);
  ASSERT_EQ (SocketIPTracker_track (tracker, "2001:db8::1"), 1);
  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);

  /* Verify counts */
  ASSERT_EQ (SocketIPTracker_count (tracker, "192.168.1.1"), 2);
  ASSERT_EQ (SocketIPTracker_count (tracker, "2001:db8::1"), 1);
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 2);
  ASSERT_EQ (SocketIPTracker_total (tracker), 3);

  /* Clear and verify */
  SocketIPTracker_clear (tracker);
  ASSERT_EQ (SocketIPTracker_count (tracker, "192.168.1.1"), 0);
  ASSERT_EQ (SocketIPTracker_count (tracker, "2001:db8::1"), 0);
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 0);
  ASSERT_EQ (SocketIPTracker_total (tracker), 0);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test NULL IP handling */
TEST (iptracker_null_ip)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = SocketIPTracker_new (arena, 10);

  /* NULL IP should be rejected as basic invalid (returns 1) */
  int result = SocketIPTracker_track (tracker, NULL);
  ASSERT_EQ (result, 1);

  /* Count should return 0 */
  ASSERT_EQ (SocketIPTracker_count (tracker, NULL), 0);

  /* Release NULL should not crash */
  SocketIPTracker_release (tracker, NULL);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test invalid IP format */
TEST (iptracker_invalid_ip_format)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = SocketIPTracker_new (arena, 10);

  /* Invalid IP formats should be rejected (returns 0) */
  ASSERT_EQ (SocketIPTracker_track (tracker, "not.an.ip"), 0);
  ASSERT_EQ (SocketIPTracker_track (tracker, "999.999.999.999"), 0);
  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1"), 0);
  ASSERT_EQ (SocketIPTracker_track (tracker, "gggg::1"), 0);

  /* None should be tracked */
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 0);
  ASSERT_EQ (SocketIPTracker_total (tracker), 0);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test per-IP limit enforcement */
TEST (iptracker_per_ip_limit)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = SocketIPTracker_new (arena, 3);

  const char *ip = "192.168.1.1";

  /* Track up to limit */
  ASSERT_EQ (SocketIPTracker_track (tracker, ip), 1);
  ASSERT_EQ (SocketIPTracker_track (tracker, ip), 1);
  ASSERT_EQ (SocketIPTracker_track (tracker, ip), 1);
  ASSERT_EQ (SocketIPTracker_count (tracker, ip), 3);

  /* Next track should be rejected */
  ASSERT_EQ (SocketIPTracker_track (tracker, ip), 0);
  ASSERT_EQ (SocketIPTracker_count (tracker, ip), 3);

  /* Release one and try again */
  SocketIPTracker_release (tracker, ip);
  ASSERT_EQ (SocketIPTracker_count (tracker, ip), 2);
  ASSERT_EQ (SocketIPTracker_track (tracker, ip), 1);
  ASSERT_EQ (SocketIPTracker_count (tracker, ip), 3);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test unlimited mode (max_per_ip = 0) */
TEST (iptracker_unlimited_mode)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = SocketIPTracker_new (arena, 0);

  const char *ip = "192.168.1.1";

  /* Track many times */
  for (int i = 0; i < 100; i++)
    {
      ASSERT_EQ (SocketIPTracker_track (tracker, ip), 1);
    }

  ASSERT_EQ (SocketIPTracker_count (tracker, ip), 100);
  ASSERT_EQ (SocketIPTracker_total (tracker), 100);
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 1);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test max unique IPs limit */
TEST (iptracker_max_unique_limit)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = SocketIPTracker_new (arena, 10);

  /* Set max unique IPs to 2 */
  SocketIPTracker_setmaxunique (tracker, 2);
  ASSERT_EQ (SocketIPTracker_getmaxunique (tracker), 2);

  /* Track first two IPs - should succeed */
  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);
  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.2"), 1);
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 2);

  /* Third IP should be rejected (unique limit reached) */
  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.3"), 0);
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 2);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test setmax/getmax */
TEST (iptracker_setmax_getmax)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = SocketIPTracker_new (arena, 5);

  ASSERT_EQ (SocketIPTracker_getmax (tracker), 5);

  SocketIPTracker_setmax (tracker, 10);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 10);

  /* Setting negative should clamp to 0 (unlimited) */
  SocketIPTracker_setmax (tracker, -1);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 0);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test clear functionality */
TEST (iptracker_clear)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = SocketIPTracker_new (arena, 10);

  /* Track multiple IPs */
  SocketIPTracker_track (tracker, "192.168.1.1");
  SocketIPTracker_track (tracker, "192.168.1.1");
  SocketIPTracker_track (tracker, "192.168.1.2");
  SocketIPTracker_track (tracker, "10.0.0.1");

  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 3);
  ASSERT_EQ (SocketIPTracker_total (tracker), 4);

  /* Clear should remove all */
  SocketIPTracker_clear (tracker);
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 0);
  ASSERT_EQ (SocketIPTracker_total (tracker), 0);
  ASSERT_EQ (SocketIPTracker_count (tracker, "192.168.1.1"), 0);

  /* Should be able to track again after clear */
  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 1);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test IPv6 compressed notation */
TEST (iptracker_ipv6_compressed)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = SocketIPTracker_new (arena, 10);

  /* Various IPv6 formats */
  ASSERT_EQ (SocketIPTracker_track (tracker, "::1"), 1);
  ASSERT_EQ (SocketIPTracker_track (tracker, "2001:db8::1"), 1);
  ASSERT_EQ (SocketIPTracker_track (tracker, "fe80::"), 1);
  ASSERT_EQ (SocketIPTracker_track (tracker,
                                    "2001:0db8:0000:0000:0000:0000:0000:0001"),
             1);

  /* Should track as different IPs */
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 4);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test with NULL arena (malloc mode) */
TEST (iptracker_null_arena)
{
  SocketIPTracker_T tracker = SocketIPTracker_new (NULL, 10);

  /* Basic operations should work */
  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);
  ASSERT_EQ (SocketIPTracker_count (tracker, "192.168.1.1"), 1);

  SocketIPTracker_release (tracker, "192.168.1.1");
  ASSERT_EQ (SocketIPTracker_count (tracker, "192.168.1.1"), 0);

  SocketIPTracker_free (&tracker);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
