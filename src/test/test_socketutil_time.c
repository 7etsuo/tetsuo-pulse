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
