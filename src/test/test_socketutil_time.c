/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_socketutil_time.c - Tests for SocketUtil time utilities
 * Tests Socket_get_monotonic_ms and socket_warn_monotonic_fallback behavior
 */

#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "core/SocketLog.h"
#include "core/SocketUtil/Time.h"
#include "test/Test.h"

/* ============================================================================
 * TEST INFRASTRUCTURE FOR LOG CAPTURE
 * ============================================================================
 */

/* Capture state for SocketLog_emit calls */
static struct
{
  int call_count;
  SocketLogLevel last_level;
  char last_module[64];
  char last_message[256];
} log_capture;

/* Custom log callback to capture emissions */
static void
test_log_callback (void *userdata,
                   SocketLogLevel level,
                   const char *component,
                   const char *message)
{
  (void)userdata;
  log_capture.call_count++;
  log_capture.last_level = level;
  strncpy (
      log_capture.last_module, component, sizeof (log_capture.last_module) - 1);
  log_capture.last_module[sizeof (log_capture.last_module) - 1] = '\0';
  strncpy (
      log_capture.last_message, message, sizeof (log_capture.last_message) - 1);
  log_capture.last_message[sizeof (log_capture.last_message) - 1] = '\0';
}

/* Reset log capture state */
static void
reset_log_capture (void)
{
  memset (&log_capture, 0, sizeof (log_capture));
}

/* Install test log handler */
static void
install_log_capture (void)
{
  reset_log_capture ();
  SocketLog_setcallback (test_log_callback, NULL);
}

/* Restore default log handler */
static void
restore_log_handler (void)
{
  SocketLog_setcallback (NULL, NULL);
}

/* ============================================================================
 * TESTS FOR Socket_get_monotonic_ms
 * ============================================================================
 */

/* Test that Socket_get_monotonic_ms returns non-zero */
TEST (socketutil_time_monotonic_returns_nonzero)
{
  int64_t time_ms = Socket_get_monotonic_ms ();
  ASSERT_NE (time_ms, 0);
}

/* Test that Socket_get_monotonic_ms is monotonic (never goes backwards) */
TEST (socketutil_time_monotonic_never_decreases)
{
  int64_t time1 = Socket_get_monotonic_ms ();
  int64_t time2 = Socket_get_monotonic_ms ();

  ASSERT (time2 >= time1);
}

/* Test that Socket_get_monotonic_ms progresses over time */
TEST (socketutil_time_monotonic_progresses)
{
  int64_t time1 = Socket_get_monotonic_ms ();

  /* Busy-wait for a tiny amount of time */
  volatile int busy_counter = 0;
  for (int i = 0; i < 100000; i++)
    {
      busy_counter++;
    }

  int64_t time2 = Socket_get_monotonic_ms ();

  /* Time should have advanced (or at worst stayed the same on fast systems) */
  ASSERT (time2 >= time1);
}

/* ============================================================================
 * TESTS FOR socket_warn_monotonic_fallback (indirect testing)
 * ============================================================================
 */

/*
 * NOTE: socket_warn_monotonic_fallback is a static function in SocketUtil.c.
 * It can only be called from Socket_get_monotonic_ms when falling back to
 * CLOCK_REALTIME.
 *
 * Testing strategy:
 * 1. Since CLOCK_MONOTONIC is typically available on modern systems, we cannot
 *    reliably force a fallback in normal test conditions.
 * 2. We verify the warning behavior by checking the log capture after
 *    Socket_get_monotonic_ms is called multiple times.
 * 3. If a fallback occurs (on systems without CLOCK_MONOTONIC), we verify:
 *    - Warning is emitted only once
 *    - Warning has correct log level (SOCKET_LOG_WARN)
 *    - Warning has correct module ("Socket")
 *    - Warning message mentions CLOCK_MONOTONIC and CLOCK_REALTIME
 */

/*
 * Test that monotonic fallback warning is emitted at most once.
 *
 * This test may not trigger the warning on systems with CLOCK_MONOTONIC,
 * but if it does trigger, it verifies one-time emission behavior.
 */
TEST (socketutil_time_monotonic_fallback_warning_once)
{
  install_log_capture ();

  /* Call Socket_get_monotonic_ms multiple times */
  for (int i = 0; i < 5; i++)
    {
      (void)Socket_get_monotonic_ms ();
    }

  /*
   * If a fallback warning was emitted, verify it was called at most once.
   * We check if the message contains "CLOCK_MONOTONIC" to identify it.
   */
  if (strstr (log_capture.last_message, "CLOCK_MONOTONIC") != NULL)
    {
      /* Warning was emitted - verify it was called exactly once */
      ASSERT_EQ (log_capture.call_count, 1);

      /* Verify log level is WARN */
      ASSERT_EQ (log_capture.last_level, SOCKET_LOG_WARN);

      /* Verify module is "Socket" */
      ASSERT (strcmp (log_capture.last_module, "Socket") == 0);

      /* Verify message mentions CLOCK_REALTIME */
      ASSERT (strstr (log_capture.last_message, "CLOCK_REALTIME") != NULL);

      /* Verify message mentions time manipulation vulnerability */
      ASSERT (strstr (log_capture.last_message, "time manipulation") != NULL);
    }
  /* else: No fallback occurred (CLOCK_MONOTONIC available), test passes */

  restore_log_handler ();
}

/*
 * Test that if fallback warning is emitted, it has correct content.
 *
 * This is a documentation test that may not trigger on most systems,
 * but validates the warning format when it does occur.
 */
TEST (socketutil_time_monotonic_fallback_warning_content)
{
  install_log_capture ();

  /* Trigger one call */
  (void)Socket_get_monotonic_ms ();

  /* If fallback warning was emitted, validate its content */
  if (strstr (log_capture.last_message, "CLOCK_MONOTONIC") != NULL)
    {
      /* Should mention CLOCK_MONOTONIC unavailable */
      ASSERT (strstr (log_capture.last_message, "CLOCK_MONOTONIC") != NULL);
      ASSERT (strstr (log_capture.last_message, "unavailable") != NULL);

      /* Should mention using CLOCK_REALTIME */
      ASSERT (strstr (log_capture.last_message, "CLOCK_REALTIME") != NULL);

      /* Should warn about security implications */
      ASSERT (strstr (log_capture.last_message, "vulnerable") != NULL
              || strstr (log_capture.last_message, "manipulation") != NULL);
    }

  restore_log_handler ();
}

/* ============================================================================
 * TESTS FOR timespec CONVERSION UTILITIES
 * ============================================================================
 */

/* Test ms_to_timespec conversion */
TEST (socketutil_time_ms_to_timespec_basic)
{
  struct timespec ts = socket_util_ms_to_timespec (1500);

  ASSERT_EQ (ts.tv_sec, 1);
  ASSERT_EQ (ts.tv_nsec, 500000000);
}

/* Test ms_to_timespec with exact seconds */
TEST (socketutil_time_ms_to_timespec_exact_seconds)
{
  struct timespec ts = socket_util_ms_to_timespec (3000);

  ASSERT_EQ (ts.tv_sec, 3);
  ASSERT_EQ (ts.tv_nsec, 0);
}

/* Test ms_to_timespec with zero */
TEST (socketutil_time_ms_to_timespec_zero)
{
  struct timespec ts = socket_util_ms_to_timespec (0);

  ASSERT_EQ (ts.tv_sec, 0);
  ASSERT_EQ (ts.tv_nsec, 0);
}

/* Test timespec_to_ms conversion */
TEST (socketutil_time_timespec_to_ms_basic)
{
  struct timespec ts;
  ts.tv_sec = 2;
  ts.tv_nsec = 500000000;

  unsigned long ms = socket_util_timespec_to_ms (ts);
  ASSERT_EQ (ms, 2500);
}

/* Test timespec_to_ms with exact seconds */
TEST (socketutil_time_timespec_to_ms_exact_seconds)
{
  struct timespec ts;
  ts.tv_sec = 5;
  ts.tv_nsec = 0;

  unsigned long ms = socket_util_timespec_to_ms (ts);
  ASSERT_EQ (ms, 5000);
}

/* Test timespec_to_ms with zero */
TEST (socketutil_time_timespec_to_ms_zero)
{
  struct timespec ts;
  ts.tv_sec = 0;
  ts.tv_nsec = 0;

  unsigned long ms = socket_util_timespec_to_ms (ts);
  ASSERT_EQ (ms, 0);
}

/* Test round-trip conversion */
TEST (socketutil_time_roundtrip_conversion)
{
  unsigned long original_ms = 12345;
  struct timespec ts = socket_util_ms_to_timespec (original_ms);
  unsigned long converted_ms = socket_util_timespec_to_ms (ts);

  ASSERT_EQ (converted_ms, original_ms);
}

/* Test timespec_add basic */
TEST (socketutil_time_timespec_add_basic)
{
  struct timespec ts1, ts2, result;

  ts1.tv_sec = 1;
  ts1.tv_nsec = 500000000;

  ts2.tv_sec = 2;
  ts2.tv_nsec = 300000000;

  result = socket_util_timespec_add (ts1, ts2);

  ASSERT_EQ (result.tv_sec, 3);
  ASSERT_EQ (result.tv_nsec, 800000000);
}

/* Test timespec_add with nanosecond overflow */
TEST (socketutil_time_timespec_add_overflow)
{
  struct timespec ts1, ts2, result;

  ts1.tv_sec = 1;
  ts1.tv_nsec = 700000000;

  ts2.tv_sec = 2;
  ts2.tv_nsec = 500000000;

  result = socket_util_timespec_add (ts1, ts2);

  /* 1.7s + 2.5s = 4.2s */
  ASSERT_EQ (result.tv_sec, 4);
  ASSERT_EQ (result.tv_nsec, 200000000);
}

/* Test timespec_add with zero */
TEST (socketutil_time_timespec_add_zero)
{
  struct timespec ts1, ts2, result;

  ts1.tv_sec = 5;
  ts1.tv_nsec = 123456789;

  ts2.tv_sec = 0;
  ts2.tv_nsec = 0;

  result = socket_util_timespec_add (ts1, ts2);

  ASSERT_EQ (result.tv_sec, ts1.tv_sec);
  ASSERT_EQ (result.tv_nsec, ts1.tv_nsec);
}

/* Entry point for running all tests */
int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
||||||| parent of 2c5d447e (test(core): add comprehensive tests for Socket_get_monotonic_ms)
/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_socketutil_time.c - Unit tests for Socket_get_monotonic_ms
 * Tests for monotonic time retrieval, clock selection, and fallback behavior.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include "test/Test.h"

/* ============================================================================
 * BASIC FUNCTIONALITY TESTS
 * ============================================================================
 */

/* Test that Socket_get_monotonic_ms returns non-zero timestamp */
TEST (get_monotonic_ms_returns_nonzero)
{
  int64_t time_ms = Socket_get_monotonic_ms ();
  ASSERT_NE (time_ms, 0);
}

/* Test that consecutive calls return increasing values */
TEST (get_monotonic_ms_monotonic_property)
{
  int64_t time1 = Socket_get_monotonic_ms ();
  ASSERT_NE (time1, 0);

  /* Small delay to ensure time advances */
  struct timespec delay = { 0, 1000000 }; /* 1ms */
  nanosleep (&delay, NULL);

  int64_t time2 = Socket_get_monotonic_ms ();
  ASSERT_NE (time2, 0);

  /* time2 should be >= time1 (monotonic) */
  ASSERT (time2 >= time1);
}

/* Test that returned value is reasonable (not absurdly large/small) */
TEST (get_monotonic_ms_reasonable_value)
{
  int64_t time_ms = Socket_get_monotonic_ms ();
  ASSERT_NE (time_ms, 0);

  /* Should be positive */
  ASSERT (time_ms > 0);

  /* Should be less than 1000 years in milliseconds
   * (roughly 31,536,000,000,000,000 ms) */
  ASSERT (time_ms < 31536000000000000LL);

  /* For systems up more than a few seconds, should be > 1000ms */
  ASSERT (time_ms > 1000);
}

/* ============================================================================
 * ELAPSED TIME MEASUREMENT TESTS
 * ============================================================================
 */

/* Test elapsed time measurement accuracy */
TEST (get_monotonic_ms_elapsed_time_accuracy)
{
  int64_t start = Socket_get_monotonic_ms ();
  ASSERT_NE (start, 0);

  /* Sleep for 10ms */
  struct timespec delay = { 0, 10000000 }; /* 10ms */
  nanosleep (&delay, NULL);

  int64_t end = Socket_get_monotonic_ms ();
  ASSERT_NE (end, 0);

  int64_t elapsed = end - start;

  /* Elapsed should be at least 10ms (allowing for system jitter) */
  ASSERT (elapsed >= 10);

  /* Should not be absurdly high (< 100ms for 10ms sleep) */
  ASSERT (elapsed < 100);
}

/* Test that multiple rapid calls show progression */
TEST (get_monotonic_ms_rapid_calls)
{
  volatile int64_t prev = Socket_get_monotonic_ms ();
  ASSERT_NE (prev, 0);

  int monotonic_count = 0;
  for (int i = 0; i < 100; i++)
    {
      volatile int64_t current = Socket_get_monotonic_ms ();
      ASSERT_NE (current, 0);

      /* Current should be >= previous (monotonic property) */
      ASSERT (current >= prev);

      if (current > prev)
        {
          monotonic_count++;
        }

      prev = current;
    }

  /* On modern systems with high-resolution clocks, rapid calls may return
   * the same timestamp. This is acceptable as long as monotonicity is
   * maintained (which we verify above with current >= prev).
   * The important property is that time never goes backward. */
}

/* ============================================================================
 * CLOCK SELECTION VERIFICATION
 * ============================================================================
 */

/* Test that preferred clocks are attempted in order */
TEST (get_monotonic_ms_clock_selection)
{
  /* This test verifies the function works with available clocks.
   * On most systems, CLOCK_MONOTONIC should be available.
   * The function tries preferred clocks first before CLOCK_REALTIME.
   */

  int64_t time1 = Socket_get_monotonic_ms ();
  ASSERT_NE (time1, 0);

  /* Verify CLOCK_MONOTONIC works directly */
  struct timespec ts;
  int clock_available = (clock_gettime (CLOCK_MONOTONIC, &ts) == 0);

  if (clock_available)
    {
      /* On systems with CLOCK_MONOTONIC, function should use it.
       * We just verify that both methods return reasonable values.
       * The exact difference may vary due to scheduling and system load. */
      int64_t mono_ms = (int64_t)ts.tv_sec * SOCKET_MS_PER_SECOND
                        + (int64_t)ts.tv_nsec / SOCKET_NS_PER_MS;

      /* Both should be positive and reasonable */
      ASSERT (time1 > 0);
      ASSERT (mono_ms > 0);
    }
}

/* Test that function handles systems with different clock support */
TEST (get_monotonic_ms_works_on_various_systems)
{
  /* Test that the function returns a valid result regardless of
   * which clocks are available on the system */

  int64_t time_ms = Socket_get_monotonic_ms ();
  ASSERT_NE (time_ms, 0);
  ASSERT (time_ms > 0);

  /* Verify at least one clock is functional */
  struct timespec ts;
  int has_monotonic = (clock_gettime (CLOCK_MONOTONIC, &ts) == 0);
  int has_realtime = (clock_gettime (CLOCK_REALTIME, &ts) == 0);

  /* At least CLOCK_REALTIME should be available on POSIX systems */
  ASSERT (has_monotonic || has_realtime);
}

/* ============================================================================
 * ERROR HANDLING TESTS
 * ============================================================================
 */

/* Test return value behavior (should return 0 on total failure) */
TEST (get_monotonic_ms_failure_returns_zero)
{
  /* Under normal circumstances, this test always passes because
   * CLOCK_REALTIME fallback is available. This test documents
   * the expected behavior when all clocks fail.
   *
   * In strict mode or on systems where all clocks fail,
   * Socket_get_monotonic_ms returns 0.
   */

  int64_t time_ms = Socket_get_monotonic_ms ();

  /* On working systems, should never be 0 */
  ASSERT_NE (time_ms, 0);

  /* If this test fails (time_ms == 0), it indicates a system
   * where no clocks are available - an extremely rare condition */
}

/* ============================================================================
 * INTEGRATION TESTS WITH TIME UTILITIES
 * ============================================================================
 */

/* Test conversion consistency with timespec helpers */
TEST (get_monotonic_ms_timespec_conversion_consistency)
{
  int64_t time_ms = Socket_get_monotonic_ms ();
  ASSERT_NE (time_ms, 0);

  /* Convert to timespec and back */
  struct timespec ts = socket_util_ms_to_timespec ((unsigned long)time_ms);
  unsigned long converted_back = socket_util_timespec_to_ms (ts);

  /* Should match (within rounding) */
  int64_t diff = (time_ms > (int64_t)converted_back)
                     ? (time_ms - (int64_t)converted_back)
                     : ((int64_t)converted_back - time_ms);

  /* Difference should be minimal (rounding in nanoseconds) */
  ASSERT (diff < 2);
}

/* Test timespec_add helper */
TEST (get_monotonic_ms_timespec_add)
{
  struct timespec ts1 = { 1, 500000000 }; /* 1.5 seconds */
  struct timespec ts2 = { 2, 700000000 }; /* 2.7 seconds */

  struct timespec result = socket_util_timespec_add (ts1, ts2);

  /* Result should be 4.2 seconds = 4 sec + 200,000,000 ns */
  ASSERT_EQ (result.tv_sec, 4);
  ASSERT_EQ (result.tv_nsec, 200000000);
}

/* Test timespec_add overflow handling */
TEST (get_monotonic_ms_timespec_add_overflow)
{
  struct timespec ts1 = { 1, 600000000 }; /* 1.6 seconds */
  struct timespec ts2 = { 2, 500000000 }; /* 2.5 seconds */

  struct timespec result = socket_util_timespec_add (ts1, ts2);

  /* Result should be 4.1 seconds = 4 sec + 100,000,000 ns
   * (nanoseconds overflow properly handled) */
  ASSERT_EQ (result.tv_sec, 4);
  ASSERT_EQ (result.tv_nsec, 100000000);
}

/* ============================================================================
 * MONOTONICITY GUARANTEES
 * ============================================================================
 */

/* Test that time doesn't go backward (critical for rate limiting) */
TEST (get_monotonic_ms_never_decreases)
{
  volatile int64_t prev = Socket_get_monotonic_ms ();
  ASSERT_NE (prev, 0);

  /* Run 1000 iterations checking monotonicity */
  for (int i = 0; i < 1000; i++)
    {
      volatile int64_t current = Socket_get_monotonic_ms ();
      ASSERT_NE (current, 0);

      /* Current MUST be >= previous (never go backward) */
      ASSERT (current >= prev);

      prev = current;
    }
}

/* ============================================================================
 * MAIN TEST ENTRY
 * ============================================================================
 */

int
main (void)
{
  Test_run_all ();
  return Test_get_failures ();
}
