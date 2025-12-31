/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_iptracker.c - SocketIPTracker unit tests
 * Tests for the IP tracking module including secure random seed generation.
 */

#include <assert.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketIPTracker.h"
#include "test/Test.h"

/* Test basic tracker creation with secure random seed */
TEST (iptracker_new_creates_tracker)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketIPTracker_T tracker = NULL;
  volatile int exception_raised = 0;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 10);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    /* If we get here, it means all secure random sources failed */
    exception_raised = 1;
  }
  END_TRY;

  /* Test should pass if no exception was raised */
  ASSERT_EQ (exception_raised, 0);
  ASSERT_NOT_NULL (tracker);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test tracker creation without arena */
TEST (iptracker_new_without_arena)
{
  SocketIPTracker_T tracker = NULL;
  volatile int exception_raised = 0;
  TRY
  {
    tracker = SocketIPTracker_new (NULL, 5);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    exception_raised = 1;
  }
  END_TRY;

  ASSERT_EQ (exception_raised, 0);
  ASSERT_NOT_NULL (tracker);

  SocketIPTracker_free (&tracker);
}

/* Test basic IP tracking */
TEST (iptracker_track_basic)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketIPTracker_T tracker = NULL;
  volatile int exception_raised = 0;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 10);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    exception_raised = 1;
  }
  END_TRY;

  if (exception_raised)
    {
      Arena_dispose (&arena);
      ASSERT_EQ (exception_raised, 0);
      return;
    }

  /* Track an IPv4 address */
  int result = SocketIPTracker_track (tracker, "192.168.1.1");
  ASSERT_EQ (result, 1);

  /* Verify count */
  int count = SocketIPTracker_count (tracker, "192.168.1.1");
  ASSERT_EQ (count, 1);

  /* Track same IP again */
  result = SocketIPTracker_track (tracker, "192.168.1.1");
  ASSERT_EQ (result, 1);

  count = SocketIPTracker_count (tracker, "192.168.1.1");
  ASSERT_EQ (count, 2);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test IP release */
TEST (iptracker_release_basic)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 10);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0); /* Should not raise exception */
  }
  END_TRY;

  /* Track and release */
  SocketIPTracker_track (tracker, "10.0.0.1");
  SocketIPTracker_track (tracker, "10.0.0.1");
  ASSERT_EQ (SocketIPTracker_count (tracker, "10.0.0.1"), 2);

  SocketIPTracker_release (tracker, "10.0.0.1");
  ASSERT_EQ (SocketIPTracker_count (tracker, "10.0.0.1"), 1);

  SocketIPTracker_release (tracker, "10.0.0.1");
  ASSERT_EQ (SocketIPTracker_count (tracker, "10.0.0.1"), 0);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test max per IP limit */
TEST (iptracker_max_per_ip_limit)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 3);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0); /* Should not raise exception */
  }
  END_TRY;

  /* Track up to limit */
  ASSERT_EQ (SocketIPTracker_track (tracker, "172.16.0.1"), 1);
  ASSERT_EQ (SocketIPTracker_track (tracker, "172.16.0.1"), 1);
  ASSERT_EQ (SocketIPTracker_track (tracker, "172.16.0.1"), 1);
  ASSERT_EQ (SocketIPTracker_count (tracker, "172.16.0.1"), 3);

  /* Should reject beyond limit */
  ASSERT_EQ (SocketIPTracker_track (tracker, "172.16.0.1"), 0);
  ASSERT_EQ (SocketIPTracker_count (tracker, "172.16.0.1"), 3);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test IPv6 addresses */
TEST (iptracker_ipv6_addresses)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 10);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0); /* Should not raise exception */
  }
  END_TRY;

  /* Track IPv6 address */
  int result = SocketIPTracker_track (tracker, "2001:db8::1");
  ASSERT_EQ (result, 1);
  ASSERT_EQ (SocketIPTracker_count (tracker, "2001:db8::1"), 1);

  /* Track compressed IPv6 */
  result = SocketIPTracker_track (tracker, "::1");
  ASSERT_EQ (result, 1);
  ASSERT_EQ (SocketIPTracker_count (tracker, "::1"), 1);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test invalid IP addresses */
TEST (iptracker_invalid_ips)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 10);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0); /* Should not raise exception */
  }
  END_TRY;

  /* NULL IP should be handled gracefully (returns 1 for basic invalid) */
  int result = SocketIPTracker_track (tracker, NULL);
  ASSERT_EQ (result, 1);

  /* Invalid format should be rejected */
  result = SocketIPTracker_track (tracker, "not.an.ip");
  ASSERT_EQ (result, 0);

  result = SocketIPTracker_track (tracker, "999.999.999.999");
  ASSERT_EQ (result, 0);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test unique IP tracking */
TEST (iptracker_unique_ips)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 10);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0); /* Should not raise exception */
  }
  END_TRY;

  /* Track multiple unique IPs */
  SocketIPTracker_track (tracker, "10.0.0.1");
  SocketIPTracker_track (tracker, "10.0.0.2");
  SocketIPTracker_track (tracker, "10.0.0.3");

  /* Track some IPs multiple times */
  SocketIPTracker_track (tracker, "10.0.0.1");
  SocketIPTracker_track (tracker, "10.0.0.2");

  /* Should have 3 unique IPs, 5 total connections */
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 3);
  ASSERT_EQ (SocketIPTracker_total (tracker), 5);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

/* Test clear functionality */
TEST (iptracker_clear)
{
  Arena_T arena = Arena_new ();
  ASSERT_NOT_NULL (arena);

  SocketIPTracker_T tracker = NULL;
  TRY
  {
    tracker = SocketIPTracker_new (arena, 10);
  }
  EXCEPT (SocketIPTracker_Failed)
  {
    Arena_dispose (&arena);
    ASSERT (0); /* Should not raise exception */
  }
  END_TRY;

  /* Track several IPs */
  SocketIPTracker_track (tracker, "10.0.0.1");
  SocketIPTracker_track (tracker, "10.0.0.2");
  SocketIPTracker_track (tracker, "10.0.0.3");

  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 3);
  ASSERT_EQ (SocketIPTracker_total (tracker), 3);

  /* Clear should reset everything */
  SocketIPTracker_clear (tracker);
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 0);
  ASSERT_EQ (SocketIPTracker_total (tracker), 0);

  /* Should be able to track again after clear */
  SocketIPTracker_track (tracker, "10.0.0.1");
  ASSERT_EQ (SocketIPTracker_unique_ips (tracker), 1);
  ASSERT_EQ (SocketIPTracker_total (tracker), 1);

  SocketIPTracker_free (&tracker);
  Arena_dispose (&arena);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
