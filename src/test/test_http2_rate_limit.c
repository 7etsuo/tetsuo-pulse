/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_http2_rate_limit.c - HTTP/2 Stream Sliding Window Rate Limit Tests
 *
 * Tests for CVE-2023-44487 (Rapid Reset Attack) protection via
 * sliding window rate limiting of stream creations.
 *
 * References:
 * - CVE-2023-44487: HTTP/2 Rapid Reset Attack
 * - RFC 9113 Section 5.1.2: Stream Concurrency
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "core/TimeWindow.h"
#include "http/SocketHTTP2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Test Utilities
 * ============================================================================
 */

static int tests_run = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond, msg)                                               \
  do                                                                         \
    {                                                                        \
      if (!(cond))                                                           \
        {                                                                    \
          fprintf (stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); \
          return 0;                                                          \
        }                                                                    \
    }                                                                        \
  while (0)

#define TEST_BEGIN(name)                  \
  do                                      \
    {                                     \
      tests_run++;                        \
      printf ("  Testing %s... ", #name); \
      fflush (stdout);                    \
    }                                     \
  while (0)

#define TEST_PASS()        \
  do                       \
    {                      \
      tests_passed++;      \
      printf ("PASSED\n"); \
      return 1;            \
    }                      \
  while (0)

/* ============================================================================
 * Configuration Tests
 * ============================================================================
 */

static int
test_config_sliding_window_defaults (void)
{
  TEST_BEGIN (config_sliding_window_defaults);

  SocketHTTP2_Config config;
  SocketHTTP2_config_defaults (&config, HTTP2_ROLE_SERVER);

  /* Verify sliding window defaults are set correctly */
  TEST_ASSERT (config.stream_window_size_ms
                   == SOCKETHTTP2_STREAM_WINDOW_SIZE_MS,
               "stream_window_size_ms should match default");
  TEST_ASSERT (config.stream_max_per_window
                   == SOCKETHTTP2_STREAM_MAX_PER_WINDOW,
               "stream_max_per_window should match default");
  TEST_ASSERT (config.stream_burst_threshold
                   == SOCKETHTTP2_STREAM_BURST_THRESHOLD,
               "stream_burst_threshold should match default");
  TEST_ASSERT (config.stream_burst_interval_ms
                   == SOCKETHTTP2_STREAM_BURST_INTERVAL_MS,
               "stream_burst_interval_ms should match default");
  TEST_ASSERT (config.stream_churn_threshold
                   == SOCKETHTTP2_STREAM_CHURN_THRESHOLD,
               "stream_churn_threshold should match default");

  TEST_PASS ();
}

static int
test_config_sliding_window_client (void)
{
  TEST_BEGIN (config_sliding_window_client);

  SocketHTTP2_Config config;
  SocketHTTP2_config_defaults (&config, HTTP2_ROLE_CLIENT);

  /* Client should have same rate limit defaults as server */
  TEST_ASSERT (config.stream_window_size_ms
                   == SOCKETHTTP2_STREAM_WINDOW_SIZE_MS,
               "Client stream_window_size_ms");
  TEST_ASSERT (config.stream_max_per_window
                   == SOCKETHTTP2_STREAM_MAX_PER_WINDOW,
               "Client stream_max_per_window");

  TEST_PASS ();
}

static int
test_config_custom_values (void)
{
  TEST_BEGIN (config_custom_values);

  SocketHTTP2_Config config;
  SocketHTTP2_config_defaults (&config, HTTP2_ROLE_SERVER);

  /* Customize the values */
  config.stream_window_size_ms = 30000;
  config.stream_max_per_window = 500;
  config.stream_burst_threshold = 25;
  config.stream_burst_interval_ms = 500;
  config.stream_churn_threshold = 50;

  /* Verify values are retained */
  TEST_ASSERT (config.stream_window_size_ms == 30000,
               "Custom stream_window_size_ms");
  TEST_ASSERT (config.stream_max_per_window == 500,
               "Custom stream_max_per_window");
  TEST_ASSERT (config.stream_burst_threshold == 25,
               "Custom stream_burst_threshold");
  TEST_ASSERT (config.stream_burst_interval_ms == 500,
               "Custom stream_burst_interval_ms");
  TEST_ASSERT (config.stream_churn_threshold == 50,
               "Custom stream_churn_threshold");

  TEST_PASS ();
}

/* ============================================================================
 * TimeWindow Unit Tests (for sliding window behavior)
 * ============================================================================
 */

static int
test_timewindow_basic (void)
{
  TEST_BEGIN (timewindow_basic);

  TimeWindow_T window;
  int64_t now_ms = 1000000;

  TimeWindow_init (&window, 60000, now_ms);

  /* Initially empty */
  TEST_ASSERT (TimeWindow_effective_count (&window, now_ms) == 0,
               "Initial count should be 0");

  /* Record some events */
  TimeWindow_record (&window, now_ms);
  TimeWindow_record (&window, now_ms + 100);
  TimeWindow_record (&window, now_ms + 200);

  TEST_ASSERT (TimeWindow_effective_count (&window, now_ms + 200) == 3,
               "Count after 3 records should be 3");

  TEST_PASS ();
}

static int
test_timewindow_sliding (void)
{
  TEST_BEGIN (timewindow_sliding);

  TimeWindow_T window;
  int64_t now_ms = 1000000;

  /* 1 second window */
  TimeWindow_init (&window, 1000, now_ms);

  /* Record 10 events at the start */
  for (int i = 0; i < 10; i++)
    {
      TimeWindow_record (&window, now_ms + i * 10);
    }

  /* Should have all 10 events immediately after recording */
  uint32_t count_immediate = TimeWindow_effective_count (&window, now_ms + 100);
  TEST_ASSERT (count_immediate == 10,
               "All 10 events should be counted immediately");

  /* Record 5 more events in the next second - this triggers window rotation */
  for (int i = 0; i < 5; i++)
    {
      TimeWindow_record (&window, now_ms + 1000 + i * 10);
    }

  /* At 1050ms, we should have: current=5, previous=10, with some decay */
  uint32_t count_second_window
      = TimeWindow_effective_count (&window, now_ms + 1050);

  /* The effective count should include some contribution from the previous
   * window */
  TEST_ASSERT (count_second_window >= 5,
               "Count should include current window events");
  TEST_ASSERT (count_second_window <= 15,
               "Count should not exceed total events");

  TEST_PASS ();
}

static int
test_timewindow_burst_detection (void)
{
  TEST_BEGIN (timewindow_burst_detection);

  TimeWindow_T burst_window;
  int64_t now_ms = 1000000;
  uint32_t burst_threshold = 50;

  /* 1 second burst interval */
  TimeWindow_init (&burst_window, 1000, now_ms);

  /* Simulate burst: 60 stream creations in 1 second */
  for (uint32_t i = 0; i < 60; i++)
    {
      TimeWindow_record (&burst_window, now_ms + i * 10);
    }

  uint32_t count = TimeWindow_effective_count (&burst_window, now_ms + 600);
  TEST_ASSERT (count >= burst_threshold, "Burst should exceed threshold");

  TEST_PASS ();
}

static int
test_timewindow_churn_detection (void)
{
  TEST_BEGIN (timewindow_churn_detection);

  TimeWindow_T churn_window;
  int64_t now_ms = 1000000;
  uint32_t churn_threshold = 100;

  /* 60 second window for churn */
  TimeWindow_init (&churn_window, 60000, now_ms);

  /* Simulate rapid create+close cycles */
  for (uint32_t i = 0; i < 120; i++)
    {
      TimeWindow_record (&churn_window, now_ms + i * 100);
    }

  uint32_t count = TimeWindow_effective_count (&churn_window, now_ms + 12000);
  TEST_ASSERT (count >= churn_threshold, "Churn count should exceed threshold");

  TEST_PASS ();
}

/* ============================================================================
 * Rate Limit Constants Tests
 * ============================================================================
 */

static int
test_rate_limit_constants (void)
{
  TEST_BEGIN (rate_limit_constants);

  /* Verify constants are reasonable values */
  TEST_ASSERT (SOCKETHTTP2_STREAM_WINDOW_SIZE_MS >= 1000,
               "Window should be at least 1 second");
  TEST_ASSERT (SOCKETHTTP2_STREAM_WINDOW_SIZE_MS <= 300000,
               "Window should be at most 5 minutes");

  TEST_ASSERT (SOCKETHTTP2_STREAM_MAX_PER_WINDOW >= 100,
               "Max per window should allow reasonable usage");
  TEST_ASSERT (SOCKETHTTP2_STREAM_MAX_PER_WINDOW <= 10000,
               "Max per window should prevent abuse");

  TEST_ASSERT (SOCKETHTTP2_STREAM_BURST_THRESHOLD >= 10,
               "Burst threshold should allow short bursts");
  TEST_ASSERT (SOCKETHTTP2_STREAM_BURST_THRESHOLD <= 200,
               "Burst threshold should limit rapid creation");

  TEST_ASSERT (SOCKETHTTP2_STREAM_BURST_INTERVAL_MS >= 100,
               "Burst interval should be at least 100ms");
  TEST_ASSERT (SOCKETHTTP2_STREAM_BURST_INTERVAL_MS <= 10000,
               "Burst interval should be at most 10 seconds");

  TEST_ASSERT (SOCKETHTTP2_STREAM_CHURN_THRESHOLD >= 50,
               "Churn threshold should allow normal usage");
  TEST_ASSERT (SOCKETHTTP2_STREAM_CHURN_THRESHOLD <= 500,
               "Churn threshold should limit rapid reset attacks");

  TEST_PASS ();
}

static int
test_cve_2023_44487_constants (void)
{
  TEST_BEGIN (cve_2023_44487_constants);

  /* CVE-2023-44487 specific: verify protection is configured */

  /* RST rate limit should be set */
  TEST_ASSERT (SOCKETHTTP2_RST_RATE_LIMIT > 0,
               "RST rate limit should be positive");
  TEST_ASSERT (SOCKETHTTP2_RST_RATE_LIMIT <= 200,
               "RST rate limit should restrict resets");

  /* Stream churn threshold should catch rapid reset patterns */
  TEST_ASSERT (SOCKETHTTP2_STREAM_CHURN_THRESHOLD
                   < SOCKETHTTP2_STREAM_MAX_PER_WINDOW,
               "Churn threshold should be stricter than total window limit");

  TEST_PASS ();
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================
 */

int
main (void)
{
  printf ("HTTP/2 Sliding Window Rate Limit Tests\n");
  printf ("======================================\n\n");

  /* Configuration tests */
  printf ("Configuration Tests:\n");
  test_config_sliding_window_defaults ();
  test_config_sliding_window_client ();
  test_config_custom_values ();
  printf ("\n");

  /* TimeWindow behavior tests */
  printf ("TimeWindow Behavior Tests:\n");
  test_timewindow_basic ();
  test_timewindow_sliding ();
  test_timewindow_burst_detection ();
  test_timewindow_churn_detection ();
  printf ("\n");

  /* Rate limit constants tests */
  printf ("Rate Limit Constants Tests:\n");
  test_rate_limit_constants ();
  test_cve_2023_44487_constants ();
  printf ("\n");

  /* Summary */
  printf ("======================================\n");
  printf ("Tests: %d/%d passed\n", tests_passed, tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}
