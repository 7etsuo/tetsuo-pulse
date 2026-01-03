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
||||||| parent of 86742604 (test(core): Add comprehensive tests for SocketIPTracker_setmax/getmax)
#include <pthread.h>
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

||||||| parent of 86742604 (test(core): Add comprehensive tests for SocketIPTracker_setmax/getmax)
/* ==================== setmax/getmax Tests ==================== */

/* Test basic setmax/getmax functionality */
TEST (iptracker_setmax_getmax_basic)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 10);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;

  /* Test initial value */
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 10);

  /* Test setting new value */
  SocketIPTracker_setmax (tracker, 5);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 5);

  /* Test setting to zero (unlimited mode) */
  SocketIPTracker_setmax (tracker, 0);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 0);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test negative value clamping */
TEST (iptracker_setmax_negative_clamp)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 10);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;

  /* Negative values should be clamped to 0 */
  SocketIPTracker_setmax (tracker, -1);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 0);

  SocketIPTracker_setmax (tracker, -100);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 0);

  SocketIPTracker_setmax (tracker, -2147483647);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 0);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test multiple setmax calls */
TEST (iptracker_setmax_multiple_changes)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 5);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;

  ASSERT_EQ (SocketIPTracker_getmax (tracker), 5);

  SocketIPTracker_setmax (tracker, 10);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 10);

  SocketIPTracker_setmax (tracker, 20);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 20);

  SocketIPTracker_setmax (tracker, 1);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 1);

  SocketIPTracker_setmax (tracker, 100);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 100);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test changing limit after tracking connections */
TEST (iptracker_dynamic_max_change)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 10);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;

  /* Track up to the limit */
  for (int i = 0; i < 10; i++)
    {
      ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);
    }

  /* 11th connection should be rejected */
  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 0);

  /* Lower the limit */
  SocketIPTracker_setmax (tracker, 5);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 5);

  /* Existing connections above new limit are not affected */
  ASSERT_EQ (SocketIPTracker_count (tracker, "192.168.1.1"), 10);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test raising limit after hitting max */
TEST (iptracker_raise_limit_after_max)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 3);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;

  /* Track up to limit */
  for (int i = 0; i < 3; i++)
    {
      ASSERT_EQ (SocketIPTracker_track (tracker, "10.0.0.1"), 1);
    }

  /* Should be rejected at limit */
  ASSERT_EQ (SocketIPTracker_track (tracker, "10.0.0.1"), 0);

  /* Raise the limit */
  SocketIPTracker_setmax (tracker, 5);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 5);

  /* Now new connections should be accepted */
  ASSERT_EQ (SocketIPTracker_track (tracker, "10.0.0.1"), 1);
  ASSERT_EQ (SocketIPTracker_track (tracker, "10.0.0.1"), 1);

  /* Should be at new limit */
  ASSERT_EQ (SocketIPTracker_count (tracker, "10.0.0.1"), 5);
  ASSERT_EQ (SocketIPTracker_track (tracker, "10.0.0.1"), 0);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test unlimited mode (max_per_ip = 0) */
TEST (iptracker_unlimited_mode)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 0);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;

  ASSERT_EQ (SocketIPTracker_getmax (tracker), 0);

  /* Should be able to track many connections from same IP */
  for (int i = 0; i < 100; i++)
    {
      ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);
    }

  ASSERT_EQ (SocketIPTracker_count (tracker, "192.168.1.1"), 100);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test switching to unlimited mode after limit */
TEST (iptracker_switch_to_unlimited)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 5);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;

  /* Track to limit */
  for (int i = 0; i < 5; i++)
    {
      ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);
    }

  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 0);

  /* Switch to unlimited */
  SocketIPTracker_setmax (tracker, 0);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 0);

  /* Now should accept unlimited connections */
  for (int i = 0; i < 50; i++)
    {
      ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);
    }

  ASSERT_EQ (SocketIPTracker_count (tracker, "192.168.1.1"), 55);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test switching from unlimited to limited */
TEST (iptracker_switch_from_unlimited)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 0);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;

  /* Track many connections in unlimited mode */
  for (int i = 0; i < 20; i++)
    {
      ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);
    }

  ASSERT_EQ (SocketIPTracker_count (tracker, "192.168.1.1"), 20);

  /* Switch to limited mode */
  SocketIPTracker_setmax (tracker, 10);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 10);

  /* Existing connections above limit remain */
  ASSERT_EQ (SocketIPTracker_count (tracker, "192.168.1.1"), 20);

  /* Try to track from a different IP - should respect new limit */
  for (int i = 0; i < 10; i++)
    {
      ASSERT_EQ (SocketIPTracker_track (tracker, "10.0.0.2"), 1);
    }

  ASSERT_EQ (SocketIPTracker_track (tracker, "10.0.0.2"), 0);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test enforcement after lowering limit */
TEST (iptracker_enforce_after_lower_limit)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 10);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;

  /* Track 5 connections from IP1 */
  for (int i = 0; i < 5; i++)
    {
      ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);
    }

  /* Lower limit to 3 */
  SocketIPTracker_setmax (tracker, 3);

  /* Existing 5 connections remain */
  ASSERT_EQ (SocketIPTracker_count (tracker, "192.168.1.1"), 5);

  /* New IP should respect the new limit */
  for (int i = 0; i < 3; i++)
    {
      ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.2"), 1);
    }

  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.2"), 0);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test setmax with large positive values */
TEST (iptracker_setmax_large_values)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 1);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;

  SocketIPTracker_setmax (tracker, 1000);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 1000);

  SocketIPTracker_setmax (tracker, 1000000);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 1000000);

  SocketIPTracker_setmax (tracker, 2147483647); /* INT_MAX */
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 2147483647);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test getmax without prior setmax */
TEST (iptracker_getmax_initial_value)
{
  Arena_T arena = Arena_new ();

  SocketIPTracker_T tracker1 = NULL;
  TRY
  {
    tracker1 = SocketIPTracker_new (arena, 0);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;
  ASSERT_EQ (SocketIPTracker_getmax (tracker1), 0);

  SocketIPTracker_T tracker2 = NULL;
  TRY
  {
    tracker2 = SocketIPTracker_new (arena, 42);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    SocketIPTracker_free (&tracker1);
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;
  ASSERT_EQ (SocketIPTracker_getmax (tracker2), 42);

  SocketIPTracker_T tracker3 = NULL;
  TRY
  {
    tracker3 = SocketIPTracker_new (arena, -5);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    SocketIPTracker_free (&tracker1);
    SocketIPTracker_free (&tracker2);
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;
  ASSERT_EQ (SocketIPTracker_getmax (tracker3), 0); /* Clamped at creation */

  SocketIPTracker_free (&tracker1);
  SocketIPTracker_free (&tracker2);
  SocketIPTracker_free (&tracker3);
  Arena_dispose (&arena);
}

/* Test interactions with release */
TEST (iptracker_setmax_with_release)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 5);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;

  /* Track to limit */
  for (int i = 0; i < 5; i++)
    {
      ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);
    }

  /* At limit */
  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 0);

  /* Release 2 connections */
  SocketIPTracker_release (tracker, "192.168.1.1");
  SocketIPTracker_release (tracker, "192.168.1.1");

  /* Should be able to track 2 more */
  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);
  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);

  /* Lower limit to 3 */
  SocketIPTracker_setmax (tracker, 3);

  /* Currently at 5, should be rejected */
  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 0);

  /* Release to below new limit */
  SocketIPTracker_release (tracker, "192.168.1.1");
  SocketIPTracker_release (tracker, "192.168.1.1");
  SocketIPTracker_release (tracker, "192.168.1.1");

  /* Now at 2, should accept up to new limit of 3 */
  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);
  ASSERT_EQ (SocketIPTracker_count (tracker, "192.168.1.1"), 3);
  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 0);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test clear preserves max setting */
TEST (iptracker_clear_preserves_max)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 10);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;

  SocketIPTracker_setmax (tracker, 7);
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 7);

  /* Track some connections */
  for (int i = 0; i < 5; i++)
    {
      ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);
    }

  /* Clear all entries */
  SocketIPTracker_clear (tracker);

  /* Max setting should be preserved */
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 7);

  /* Should enforce the preserved limit */
  for (int i = 0; i < 7; i++)
    {
      ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 1);
    }

  ASSERT_EQ (SocketIPTracker_track (tracker, "192.168.1.1"), 0);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Thread data for concurrent tests */
typedef struct
{
  SocketIPTracker_T tracker;
  int iterations;
} thread_data_t;

/* Thread function for concurrent setmax */
static void *
setmax_thread (void *arg)
{
  thread_data_t *data = (thread_data_t *)arg;

  for (int i = 0; i < data->iterations; i++)
    {
      SocketIPTracker_setmax (data->tracker, i % 100);
    }

  return NULL;
}

/* Thread function for concurrent getmax */
static void *
getmax_thread (void *arg)
{
  thread_data_t *data = (thread_data_t *)arg;
  volatile int max;

  for (int i = 0; i < data->iterations; i++)
    {
      max = SocketIPTracker_getmax (data->tracker);
      (void)max; /* Use the value to prevent optimization */
    }

  return NULL;
}

/* Test thread safety of concurrent setmax calls */
TEST (iptracker_concurrent_setmax)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 10);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;

  pthread_t threads[4];
  thread_data_t data = { .tracker = tracker, .iterations = 1000 };

  /* Spawn threads that concurrently call setmax */
  for (int i = 0; i < 4; i++)
    {
      pthread_create (&threads[i], NULL, setmax_thread, &data);
    }

  /* Wait for all threads */
  for (int i = 0; i < 4; i++)
    {
      pthread_join (threads[i], NULL);
    }

  /* Should not crash and should have a valid value */
  int final_max = SocketIPTracker_getmax (tracker);
  ASSERT (final_max >= 0 && final_max < 100);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test thread safety of concurrent getmax calls */
TEST (iptracker_concurrent_getmax)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 42);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;

  pthread_t threads[4];
  thread_data_t data = { .tracker = tracker, .iterations = 1000 };

  /* Spawn threads that concurrently call getmax */
  for (int i = 0; i < 4; i++)
    {
      pthread_create (&threads[i], NULL, getmax_thread, &data);
    }

  /* Wait for all threads */
  for (int i = 0; i < 4; i++)
    {
      pthread_join (threads[i], NULL);
    }

  /* Should not crash and value should still be 42 */
  ASSERT_EQ (SocketIPTracker_getmax (tracker), 42);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Thread function for mixed setmax/getmax */
static void *
mixed_setmax_getmax_thread (void *arg)
{
  thread_data_t *data = (thread_data_t *)arg;
  volatile int max;

  for (int i = 0; i < data->iterations; i++)
    {
      if (i % 2 == 0)
        {
          SocketIPTracker_setmax (data->tracker, i % 50);
        }
      else
        {
          max = SocketIPTracker_getmax (data->tracker);
          (void)max;
        }
    }

  return NULL;
}

/* Test thread safety of mixed setmax/getmax calls */
TEST (iptracker_concurrent_setmax_getmax)
{
  Arena_T arena = Arena_new ();
  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 10);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0);
  }
  END_TRY;

  pthread_t threads[4];
  thread_data_t data = { .tracker = tracker, .iterations = 1000 };

  /* Spawn threads that mix setmax and getmax */
  for (int i = 0; i < 4; i++)
    {
      pthread_create (&threads[i], NULL, mixed_setmax_getmax_thread, &data);
    }

  /* Wait for all threads */
  for (int i = 0; i < 4; i++)
    {
      pthread_join (threads[i], NULL);
    }

  /* Should not crash and should have a valid value */
  int final_max = SocketIPTracker_getmax (tracker);
  ASSERT (final_max >= 0 && final_max < 50);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
