/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * test_metrics_percentile.c - SocketMetrics histogram percentile edge case tests
 *
 * Tests for histogram percentile calculation covering:
 * - Boundary percentiles (p0, p100)
 * - Small sample sizes (n=1, n=2, n=3)
 * - Duplicate values
 * - Linear interpolation accuracy
 * - Extreme values
 * - Ring buffer wraparound
 * - Snapshot consistency
 */

#include <assert.h>
#include <float.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "core/SocketMetrics.h"
#include "test/Test.h"

/* Helper macro for approximate floating point equality */
#define ASSERT_NEAR(expected, actual, epsilon)                                 \
  do                                                                           \
    {                                                                          \
      double _exp = (expected);                                                \
      double _act = (actual);                                                  \
      double _eps = (epsilon);                                                 \
      if (fabs (_exp - _act) > _eps)                                           \
        {                                                                      \
          char _msg[1024];                                                     \
          snprintf (_msg,                                                      \
                    sizeof (_msg),                                             \
                    "Expected %f ± %f, got %f (diff: %f)",                     \
                    _exp,                                                      \
                    _eps,                                                      \
                    _act,                                                      \
                    fabs (_exp - _act));                                       \
          Test_fail (_msg, __FILE__, __LINE__);                                \
          RAISE (Test_Failed);                                                 \
        }                                                                      \
    }                                                                          \
  while (0)

/* Test boundary percentiles: p0 (min) and p100 (max) */
TEST (metrics_percentile_boundary_p0_p100)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Observe values 10, 20, 30, 40, 50 */
  for (int i = 1; i <= 5; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                        (double)(i * 10));
    }

  /* p0 should equal min (10.0) */
  double p0
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS, 0.0);
  ASSERT_NEAR (10.0, p0, 0.001);

  /* p100 should equal max (50.0) */
  double p100 = SocketMetrics_histogram_percentile (
      SOCKET_HIST_DNS_QUERY_TIME_MS, 100.0);
  ASSERT_NEAR (50.0, p100, 0.001);
}

/* Test p50 (median) calculation */
TEST (metrics_percentile_median_odd_count)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Observe values 1, 2, 3, 4, 5 - median should be 3 */
  for (int i = 1; i <= 5; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                        (double)i);
    }

  double p50
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                            50.0);
  ASSERT_NEAR (3.0, p50, 0.001);
}

/* Test percentile clamping for out-of-range values */
TEST (metrics_percentile_clamping)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Observe values 10, 20, 30 */
  for (int i = 1; i <= 3; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                        (double)(i * 10));
    }

  /* Negative percentile should be clamped to 0 (min) */
  double p_neg = SocketMetrics_histogram_percentile (
      SOCKET_HIST_DNS_QUERY_TIME_MS, -10.0);
  ASSERT_NEAR (10.0, p_neg, 0.001);

  /* Percentile > 100 should be clamped to 100 (max) */
  double p_over = SocketMetrics_histogram_percentile (
      SOCKET_HIST_DNS_QUERY_TIME_MS, 150.0);
  ASSERT_NEAR (30.0, p_over, 0.001);
}

/* Test single value (n=1) - all percentiles should return that value */
TEST (metrics_percentile_single_value)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Single observation */
  SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 42.0);

  /* All percentiles should return 42.0 */
  double p0
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS, 0.0);
  double p50
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                            50.0);
  double p100 = SocketMetrics_histogram_percentile (
      SOCKET_HIST_DNS_QUERY_TIME_MS, 100.0);

  ASSERT_NEAR (42.0, p0, 0.001);
  ASSERT_NEAR (42.0, p50, 0.001);
  ASSERT_NEAR (42.0, p100, 0.001);
}

/* Test two values (n=2) - p50 should be average */
TEST (metrics_percentile_two_values)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Observe 10.0 and 30.0 */
  SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 10.0);
  SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 30.0);

  /* p50 should interpolate between 10 and 30 */
  double p50
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                            50.0);
  ASSERT_NEAR (20.0, p50, 0.001);
}

/* Test three values (n=3) - verify exact middle value */
TEST (metrics_percentile_three_values)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Observe 1, 2, 3 */
  SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 1.0);
  SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 2.0);
  SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 3.0);

  /* p50 should be exactly 2.0 */
  double p50
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                            50.0);
  ASSERT_NEAR (2.0, p50, 0.001);
}

/* Test empty histogram - all percentiles should be 0 */
TEST (metrics_percentile_empty_histogram)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* No observations */
  double p50
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                            50.0);
  ASSERT_NEAR (0.0, p50, 0.001);
}

/* Test all duplicate values */
TEST (metrics_percentile_all_duplicates)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Observe 42.0 one thousand times */
  for (int i = 0; i < 1000; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 42.0);
    }

  /* All percentiles should be 42.0 */
  double p0
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS, 0.0);
  double p50
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                            50.0);
  double p95
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                            95.0);
  double p100 = SocketMetrics_histogram_percentile (
      SOCKET_HIST_DNS_QUERY_TIME_MS, 100.0);

  ASSERT_NEAR (42.0, p0, 0.001);
  ASSERT_NEAR (42.0, p50, 0.001);
  ASSERT_NEAR (42.0, p95, 0.001);
  ASSERT_NEAR (42.0, p100, 0.001);
}

/* Test bimodal distribution */
TEST (metrics_percentile_bimodal)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* 500 observations of 10.0, 500 observations of 90.0 */
  for (int i = 0; i < 500; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 10.0);
    }
  for (int i = 0; i < 500; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 90.0);
    }

  /* p0 should be 10.0 */
  double p0
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS, 0.0);
  ASSERT_NEAR (10.0, p0, 0.001);

  /* p50 should be between the two modes */
  double p50
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                            50.0);
  /* p50 should interpolate between 10 and 90 */
  ASSERT (p50 >= 10.0 && p50 <= 90.0);

  /* p100 should be 90.0 */
  double p100 = SocketMetrics_histogram_percentile (
      SOCKET_HIST_DNS_QUERY_TIME_MS, 100.0);
  ASSERT_NEAR (90.0, p100, 0.001);
}

/* Test skewed distribution (980 low values, 20 high values) */
TEST (metrics_percentile_skewed)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* 980 observations of 1.0 */
  for (int i = 0; i < 980; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 1.0);
    }

  /* 20 observations of 100.0 */
  for (int i = 0; i < 20; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 100.0);
    }

  /* p50 should be 1.0 (median is in the low cluster) */
  double p50
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                            50.0);
  ASSERT_NEAR (1.0, p50, 0.001);

  /* p99 should be close to 100.0 (99th percentile should hit the high values) */
  double p99
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                            99.0);
  /* Should be close to 100.0 */
  ASSERT (p99 > 90.0);
}

/* Test linear interpolation accuracy */
TEST (metrics_percentile_interpolation)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Create precise distribution: [10, 20, 30, 40, 50] */
  double values[] = { 10.0, 20.0, 30.0, 40.0, 50.0 };
  for (int i = 0; i < 5; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                        values[i]);
    }

  /* p25 should interpolate
   * index = 0.25 * (5-1) = 1.0 → exact match at index 1, returns 20.0 */
  double p25
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                            25.0);
  ASSERT_NEAR (20.0, p25, 0.001);

  /* p75 should interpolate
   * index = 0.75 * (5-1) = 3.0 → exact match at index 3, returns 40.0 */
  double p75
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                            75.0);
  ASSERT_NEAR (40.0, p75, 0.001);

  /* p60 should interpolate: index = 0.60 * 4 = 2.4
   * lower=2 (30.0), upper=3 (40.0), frac=0.4
   * result = 30.0 * 0.6 + 40.0 * 0.4 = 18.0 + 16.0 = 34.0 */
  double p60
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                            60.0);
  ASSERT_NEAR (34.0, p60, 0.001);
}

/* Test extreme values - very large */
TEST (metrics_percentile_extreme_large)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Observe very large values near DBL_MAX */
  double large_val = 1e100;
  for (int i = 0; i < 10; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                        large_val);
    }

  double p50
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                            50.0);
  ASSERT_NEAR (large_val, p50, large_val * 0.001);
}

/* Test extreme values - very small */
TEST (metrics_percentile_extreme_small)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Observe very small positive values */
  double small_val = 1e-100;
  for (int i = 0; i < 10; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                        small_val);
    }

  double p50
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                            50.0);
  ASSERT_NEAR (small_val, p50, small_val * 0.1);
}

/* Test negative values */
TEST (metrics_percentile_negative_values)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Observe negative values (e.g., time deltas) */
  for (int i = -5; i <= 5; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                        (double)i);
    }

  /* p50 should be around 0 */
  double p50
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                            50.0);
  ASSERT_NEAR (0.0, p50, 0.5);

  /* p0 should be -5 */
  double p0
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS, 0.0);
  ASSERT_NEAR (-5.0, p0, 0.001);

  /* p100 should be 5 */
  double p100 = SocketMetrics_histogram_percentile (
      SOCKET_HIST_DNS_QUERY_TIME_MS, 100.0);
  ASSERT_NEAR (5.0, p100, 0.001);
}

/* Test mixed range values spanning many orders of magnitude */
TEST (metrics_percentile_mixed_range)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Observe values from 1e-6 to 1e6 */
  SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 1e-6);
  SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 1e-3);
  SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 1.0);
  SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 1e3);
  SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 1e6);

  /* p0 should be smallest */
  double p0
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS, 0.0);
  ASSERT_NEAR (1e-6, p0, 1e-9);

  /* p100 should be largest */
  double p100 = SocketMetrics_histogram_percentile (
      SOCKET_HIST_DNS_QUERY_TIME_MS, 100.0);
  ASSERT_NEAR (1e6, p100, 1e3);
}

/* Test histogram ring buffer wraparound at exactly HISTOGRAM_BUCKETS */
TEST (metrics_percentile_wraparound_exact)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Observe exactly SOCKET_METRICS_HISTOGRAM_BUCKETS (1024) values */
  for (int i = 0; i < 1024; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                        (double)i);
    }

  /* Verify count */
  uint64_t count
      = SocketMetrics_histogram_count (SOCKET_HIST_DNS_QUERY_TIME_MS);
  ASSERT_EQ (count, 1024);

  /* p0 should be 0 */
  double p0
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS, 0.0);
  ASSERT_NEAR (0.0, p0, 0.001);

  /* p100 should be 1023 */
  double p100 = SocketMetrics_histogram_percentile (
      SOCKET_HIST_DNS_QUERY_TIME_MS, 100.0);
  ASSERT_NEAR (1023.0, p100, 0.001);
}

/* Test histogram ring buffer wraparound with overflow */
TEST (metrics_percentile_wraparound_overflow)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Observe HISTOGRAM_BUCKETS + 1 values
   * This should cause the first value to be overwritten */
  for (int i = 0; i < 1025; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                        (double)i);
    }

  /* Count should still be capped at bucket size in percentile calculation */
  uint64_t count
      = SocketMetrics_histogram_count (SOCKET_HIST_DNS_QUERY_TIME_MS);
  ASSERT_EQ (count, 1025);

  /* Min should be 1 (0 was overwritten), not 0 */
  double p0
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS, 0.0);
  ASSERT_NEAR (1.0, p0, 0.001);

  /* Max should be 1024 */
  double p100 = SocketMetrics_histogram_percentile (
      SOCKET_HIST_DNS_QUERY_TIME_MS, 100.0);
  ASSERT_NEAR (1024.0, p100, 0.001);
}

/* Test full ring buffer rotation (2x HISTOGRAM_BUCKETS) */
TEST (metrics_percentile_full_rotation)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Observe 2 * HISTOGRAM_BUCKETS values */
  for (int i = 0; i < 2048; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                        (double)i);
    }

  /* Should only have the last 1024 values (1024-2047) */
  double p0
      = SocketMetrics_histogram_percentile (SOCKET_HIST_DNS_QUERY_TIME_MS, 0.0);
  ASSERT_NEAR (1024.0, p0, 0.001);

  double p100 = SocketMetrics_histogram_percentile (
      SOCKET_HIST_DNS_QUERY_TIME_MS, 100.0);
  ASSERT_NEAR (2047.0, p100, 0.001);
}

/* Test snapshot consistency - all percentiles should be ordered */
TEST (metrics_percentile_snapshot_order)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Observe 1000 random-ish values */
  for (int i = 0; i < 1000; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS,
                                        (double)((i * 7) % 1000));
    }

  SocketMetrics_HistogramSnapshot snap;
  SocketMetrics_histogram_snapshot (SOCKET_HIST_DNS_QUERY_TIME_MS, &snap);

  /* Verify ordering: p50 <= p75 <= p90 <= p95 <= p99 <= p999 */
  ASSERT (snap.p50 <= snap.p75);
  ASSERT (snap.p75 <= snap.p90);
  ASSERT (snap.p90 <= snap.p95);
  ASSERT (snap.p95 <= snap.p99);
  ASSERT (snap.p99 <= snap.p999);

  /* Verify bounds */
  ASSERT (snap.min <= snap.p50);
  ASSERT (snap.p999 <= snap.max);
}

/* Test snapshot with very few values */
TEST (metrics_percentile_snapshot_few_values)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Only 3 observations */
  SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 10.0);
  SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 20.0);
  SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 30.0);

  SocketMetrics_HistogramSnapshot snap;
  SocketMetrics_histogram_snapshot (SOCKET_HIST_DNS_QUERY_TIME_MS, &snap);

  /* Verify basic stats */
  ASSERT_EQ (snap.count, 3);
  ASSERT_NEAR (snap.min, 10.0, 0.001);
  ASSERT_NEAR (snap.max, 30.0, 0.001);
  ASSERT_NEAR (snap.sum, 60.0, 0.001);
  ASSERT_NEAR (snap.mean, 20.0, 0.001);

  /* Verify ordering still holds */
  ASSERT (snap.p50 <= snap.p75);
  ASSERT (snap.p75 <= snap.p90);
  ASSERT (snap.p90 <= snap.p95);
  ASSERT (snap.p95 <= snap.p99);
  ASSERT (snap.p99 <= snap.p999);
}

/* Test precision with many small values */
TEST (metrics_percentile_precision_small_values)
{
  SocketMetrics_init ();
  SocketMetrics_reset_histograms ();

  /* Sum of many small values */
  for (int i = 0; i < 10000; i++)
    {
      SocketMetrics_histogram_observe (SOCKET_HIST_DNS_QUERY_TIME_MS, 0.001);
    }

  SocketMetrics_HistogramSnapshot snap;
  SocketMetrics_histogram_snapshot (SOCKET_HIST_DNS_QUERY_TIME_MS, &snap);

  /* All percentiles should be 0.001 */
  ASSERT_NEAR (snap.p50, 0.001, 0.0001);
  ASSERT_NEAR (snap.p95, 0.001, 0.0001);
  ASSERT_NEAR (snap.p99, 0.001, 0.0001);

  /* Mean should be 0.001 */
  ASSERT_NEAR (snap.mean, 0.001, 0.0001);
}

int
main (void)
{
  Test_run_all ();
  return Test_get_failures () > 0 ? 1 : 0;
}
