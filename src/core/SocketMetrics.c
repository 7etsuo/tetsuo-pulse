/**
 * SocketMetrics.c - Metrics collection subsystem
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Provides thread-safe metrics collection for monitoring socket library
 * operations. Metrics are stored in a global array protected by mutex.
 *
 * FEATURES:
 * - Thread-safe increment operations
 * - Atomic snapshot retrieval
 * - Reset capability for testing
 * - Named metric lookup
 *
 * THREAD SAFETY:
 * - All operations are thread-safe via mutex protection
 * - Snapshots are atomic copies of all metric values
 */

#include <assert.h>
#include <pthread.h>
#include <string.h>

#include "core/SocketLog.h"
#include "core/SocketMetrics.h"

/* Mutex protecting metric values */
static pthread_mutex_t socketmetrics_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Metric values array */
static unsigned long long socketmetrics_values[SOCKET_METRIC_COUNT] = { 0ULL };

/* Metric names for display/debugging */
static const char *socketmetrics_names[SOCKET_METRIC_COUNT]
    = { "socket.connect_success", "socket.connect_failure",
        "socket.shutdown_calls",  "dns.request_submitted",
        "dns.request_completed",  "dns.request_failed",
        "dns.request_cancelled",  "dns.request_timeout",
        "poll.wakeups",           "poll.events_dispatched",
        "pool.connections_added", "pool.connections_removed",
        "pool.connections_reused" };

/**
 * SocketMetrics_increment - Increment a metric counter
 * @metric: Metric to increment (from SocketMetric enum)
 * @value: Amount to add to the metric
 *
 * Thread-safe: Yes (mutex protected)
 *
 * Increments the specified metric by the given value. Invalid metric
 * indices are logged and ignored.
 */
void
SocketMetrics_increment (SocketMetric metric, unsigned long value)
{
  if (metric < 0 || metric >= (SocketMetric)SOCKET_METRIC_COUNT)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, "SocketMetrics",
                       "Invalid metric %d in increment ignored", (int)metric);
      return;
    }

  assert (metric >= 0);
  assert (metric < SOCKET_METRIC_COUNT);

  pthread_mutex_lock (&socketmetrics_mutex);
  socketmetrics_values[metric] += value;
  pthread_mutex_unlock (&socketmetrics_mutex);
}

/**
 * SocketMetrics_getsnapshot - Get atomic snapshot of all metrics
 * @snapshot: Output structure to receive metric values
 *
 * Thread-safe: Yes (mutex protected)
 *
 * Copies all current metric values atomically to the provided snapshot
 * structure. NULL snapshots are logged and ignored.
 */
void
SocketMetrics_getsnapshot (SocketMetricsSnapshot *snapshot)
{
  if (snapshot == NULL)
    {
      SocketLog_emit (SOCKET_LOG_WARN, "SocketMetrics",
                      "NULL snapshot in getsnapshot ignored");
      return;
    }

  assert (snapshot);

  pthread_mutex_lock (&socketmetrics_mutex);
  memcpy (snapshot->values, socketmetrics_values,
          sizeof (socketmetrics_values));
  pthread_mutex_unlock (&socketmetrics_mutex);
}

/**
 * SocketMetrics_reset - Reset all metrics to zero
 *
 * Thread-safe: Yes (mutex protected)
 *
 * Clears all metric values. Useful for testing or periodic resets.
 */
void
SocketMetrics_reset (void)
{
  pthread_mutex_lock (&socketmetrics_mutex);
  memset (socketmetrics_values, 0, sizeof (socketmetrics_values));
  pthread_mutex_unlock (&socketmetrics_mutex);
}

/**
 * SocketMetrics_name - Get human-readable name for a metric
 * @metric: Metric to get name for
 *
 * Returns: Static string with metric name, or "unknown" for invalid metrics
 * Thread-safe: Yes (returns static data)
 */
const char *
SocketMetrics_name (SocketMetric metric)
{
  if (metric < 0 || metric >= SOCKET_METRIC_COUNT)
    return "unknown";
  return socketmetrics_names[metric];
}

/**
 * SocketMetrics_count - Get total number of defined metrics
 *
 * Returns: Number of metrics in the SocketMetric enum
 * Thread-safe: Yes (returns constant)
 */
size_t
SocketMetrics_count (void)
{
  return SOCKET_METRIC_COUNT;
}
