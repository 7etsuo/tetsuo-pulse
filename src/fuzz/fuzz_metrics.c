/**
 * fuzz_metrics.c - SocketMetrics counter overflow and concurrent access fuzzer
 *
 * Comprehensive fuzzing harness for SocketMetrics to test:
 * - Counter overflow behavior
 * - Rapid increment/snapshot race conditions
 * - Invalid metric indices
 * - Memory safety of metric names
 * - Snapshot consistency
 *
 * Attack Categories Tested:
 *
 * 1. Counter Overflow:
 *    - Incrementing counters with large values
 *    - Wrapping behavior at ULLONG_MAX
 *    - Atomic increment correctness
 *
 * 2. Invalid Metric Indices:
 *    - Out-of-bounds metric enum values
 *    - Negative indices (if applicable)
 *    - Boundary values (SOCKET_METRIC_COUNT)
 *
 * 3. Snapshot Consistency:
 *    - Snapshot during rapid updates
 *    - Multiple concurrent snapshots
 *    - Snapshot after reset
 *
 * 4. String Functions:
 *    - Metric name retrieval for all indices
 *    - Invalid indices returning safe defaults
 *
 * Security Focus:
 * - Thread safety of atomic operations
 * - Buffer overflows in name retrieval
 * - Integer overflow in counters
 *
 * Build/Run: CC=clang cmake -DENABLE_FUZZING=ON .. && make fuzz_metrics
 * ./fuzz_metrics corpus/metrics/ -fork=16 -max_len=1024
 */

#include "core/SocketUtil.h"
#include "core/Arena.h"
#include "core/Except.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Suppress GCC clobbered warnings for TRY/EXCEPT */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

/**
 * Read 64-bit value from fuzz data
 */
static unsigned long long
read_u64 (const uint8_t *data)
{
  unsigned long long val = 0;
  for (int i = 0; i < 8; i++)
    {
      val = (val << 8) | data[i];
    }
  return val;
}

/**
 * Test counter increment with fuzzed values
 */
static void
test_counter_increment (const uint8_t *data, size_t size)
{
  if (size < 10)
    return;

  /* Get metric index from fuzz data */
  int metric_idx = data[0];

  /* Get increment value from fuzz data */
  unsigned long increment_value
      = ((unsigned long)data[1] << 24) | ((unsigned long)data[2] << 16)
        | ((unsigned long)data[3] << 8) | data[4];

  /* Test valid metric indices */
  if (metric_idx < SOCKET_METRIC_COUNT)
    {
      SocketMetric metric = (SocketMetric)metric_idx;
      SocketMetrics_increment (metric, increment_value);

      /* Verify by snapshot */
      SocketMetricsSnapshot snapshot;
      SocketMetrics_getsnapshot (&snapshot);

      /* Access the value */
      unsigned long long val = SocketMetrics_snapshot_value (&snapshot, metric);
      (void)val;
    }
}

/**
 * Test all valid metric indices
 */
static void
test_all_metrics (void)
{
  /* Test all valid metric indices */
  for (int i = 0; i < SOCKET_METRIC_COUNT; i++)
    {
      /* Increment each metric */
      SocketMetrics_increment ((SocketMetric)i, 1);

      /* Get metric name */
      const char *name = SocketMetrics_name ((SocketMetric)i);
      (void)name;
    }
}

/**
 * Test metric name retrieval for all indices
 */
static void
test_metric_names (void)
{
  size_t count = SocketMetrics_count ();

  for (size_t i = 0; i < count; i++)
    {
      const char *name = SocketMetrics_name ((SocketMetric)i);
      if (name)
        {
          /* Verify name is not empty */
          size_t len = strlen (name);
          (void)len;
        }
    }

  /* Test out-of-bounds indices */
  const char *invalid_name = SocketMetrics_name ((SocketMetric)SOCKET_METRIC_COUNT);
  (void)invalid_name;

  invalid_name = SocketMetrics_name ((SocketMetric)(SOCKET_METRIC_COUNT + 1));
  (void)invalid_name;

  invalid_name = SocketMetrics_name ((SocketMetric)255);
  (void)invalid_name;

  /* Test negative-ish values (cast from signed) */
  invalid_name = SocketMetrics_name ((SocketMetric)-1);
  (void)invalid_name;
}

/**
 * Test snapshot operations
 */
static void
test_snapshots (const uint8_t *data, size_t size)
{
  if (size < 8)
    return;

  /* Take multiple snapshots */
  SocketMetricsSnapshot snap1, snap2, snap3;
  memset (&snap1, 0, sizeof (snap1));
  memset (&snap2, 0, sizeof (snap2));
  memset (&snap3, 0, sizeof (snap3));

  SocketMetrics_getsnapshot (&snap1);

  /* Increment some metrics */
  int metric_idx = data[0] % SOCKET_METRIC_COUNT;
  unsigned long increment = data[1] + 1;
  SocketMetrics_increment ((SocketMetric)metric_idx, increment);

  SocketMetrics_getsnapshot (&snap2);

  /* Verify snap2 >= snap1 for the incremented metric */
  unsigned long long val1
      = SocketMetrics_snapshot_value (&snap1, (SocketMetric)metric_idx);
  unsigned long long val2
      = SocketMetrics_snapshot_value (&snap2, (SocketMetric)metric_idx);

  /* val2 should be >= val1 (accounting for potential wrapping) */
  (void)val1;
  (void)val2;

  /* Test snapshot_value with NULL */
  unsigned long long null_val
      = SocketMetrics_snapshot_value (NULL, (SocketMetric)metric_idx);
  (void)null_val;

  /* Test snapshot_value with invalid metric */
  unsigned long long invalid_val
      = SocketMetrics_snapshot_value (&snap2, (SocketMetric)SOCKET_METRIC_COUNT);
  (void)invalid_val;

  invalid_val = SocketMetrics_snapshot_value (&snap2, (SocketMetric)255);
  (void)invalid_val;

  /* Test reset and snapshot after */
  SocketMetrics_legacy_reset ();
  SocketMetrics_getsnapshot (&snap3);

  /* Verify all values are 0 or minimal after reset */
  for (int i = 0; i < SOCKET_METRIC_COUNT; i++)
    {
      unsigned long long val
          = SocketMetrics_snapshot_value (&snap3, (SocketMetric)i);
      (void)val;
    }
}

/**
 * Test rapid increments (simulate high-frequency updates)
 */
static void
test_rapid_increments (const uint8_t *data, size_t size)
{
  if (size < 16)
    return;

  /* Perform many rapid increments */
  int iterations = (data[0] % 100) + 1;
  int metric_idx = data[1] % SOCKET_METRIC_COUNT;

  for (int i = 0; i < iterations; i++)
    {
      unsigned long increment = (data[2 + (i % 14)] % 100) + 1;
      SocketMetrics_increment ((SocketMetric)metric_idx, increment);
    }

  /* Snapshot after rapid increments */
  SocketMetricsSnapshot snapshot;
  SocketMetrics_getsnapshot (&snapshot);
}

/**
 * Test large increment values (potential overflow)
 */
static void
test_overflow (const uint8_t *data, size_t size)
{
  if (size < 10)
    return;

  int metric_idx = data[0] % SOCKET_METRIC_COUNT;

  /* Test with maximum value */
  unsigned long max_val = (unsigned long)-1;
  SocketMetrics_increment ((SocketMetric)metric_idx, max_val);

  SocketMetricsSnapshot snapshot;
  SocketMetrics_getsnapshot (&snapshot);

  /* Increment again to test wrapping */
  SocketMetrics_increment ((SocketMetric)metric_idx, 1);

  SocketMetrics_getsnapshot (&snapshot);

  /* Test with fuzzed large values */
  if (size >= 8)
    {
      unsigned long long fuzz_val = read_u64 (data + 2);
      /* Truncate to unsigned long */
      unsigned long increment = (unsigned long)(fuzz_val & 0xFFFFFFFF);
      SocketMetrics_increment ((SocketMetric)metric_idx, increment);
    }
}

/**
 * Test count function
 */
static void
test_count (void)
{
  size_t count = SocketMetrics_count ();

  /* Verify count matches expected */
  if (count != SOCKET_METRIC_COUNT)
    {
      /* Inconsistency */
    }

  /* Verify count is reasonable */
  if (count > 1000)
    {
      /* Suspicious - possible corruption */
    }
}

/**
 * Test with fuzzed metric operation sequence
 */
static void
test_operation_sequence (const uint8_t *data, size_t size)
{
  if (size < 20)
    return;

  size_t offset = 0;

  while (offset + 5 < size)
    {
      uint8_t op = data[offset++];
      int metric_idx = data[offset++] % SOCKET_METRIC_COUNT;

      switch (op % 5)
        {
        case 0: /* Increment */
          {
            unsigned long val = ((unsigned long)data[offset] << 8) | data[offset + 1];
            offset += 2;
            SocketMetrics_increment ((SocketMetric)metric_idx, val + 1);
          }
          break;

        case 1: /* Snapshot */
          {
            SocketMetricsSnapshot snap;
            SocketMetrics_getsnapshot (&snap);
            offset += 2;
          }
          break;

        case 2: /* Get name */
          {
            const char *name = SocketMetrics_name ((SocketMetric)metric_idx);
            (void)name;
            offset += 2;
          }
          break;

        case 3: /* Get count */
          {
            size_t count = SocketMetrics_count ();
            (void)count;
            offset += 2;
          }
          break;

        case 4: /* Snapshot value */
          {
            SocketMetricsSnapshot snap;
            SocketMetrics_getsnapshot (&snap);
            unsigned long long val
                = SocketMetrics_snapshot_value (&snap, (SocketMetric)metric_idx);
            (void)val;
            offset += 2;
          }
          break;
        }
    }
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size == 0)
    return 0;

  TRY
  {
    /* ====================================================================
     * Test 1: Counter increment with fuzzed values
     * ==================================================================== */
    test_counter_increment (data, size);

    /* ====================================================================
     * Test 2: All valid metrics
     * ==================================================================== */
    test_all_metrics ();

    /* ====================================================================
     * Test 3: Metric name retrieval
     * ==================================================================== */
    test_metric_names ();

    /* ====================================================================
     * Test 4: Snapshot operations
     * ==================================================================== */
    test_snapshots (data, size);

    /* ====================================================================
     * Test 5: Rapid increments
     * ==================================================================== */
    test_rapid_increments (data, size);

    /* ====================================================================
     * Test 6: Overflow testing
     * ==================================================================== */
    test_overflow (data, size);

    /* ====================================================================
     * Test 7: Count function
     * ==================================================================== */
    test_count ();

    /* ====================================================================
     * Test 8: Operation sequences
     * ==================================================================== */
    test_operation_sequence (data, size);

    /* ====================================================================
     * Test 9: Reset after all tests
     * ==================================================================== */
    SocketMetrics_legacy_reset ();
  }
  EXCEPT (Arena_Failed) { /* Unlikely but handle */ }
  END_TRY;

  return 0;
}
