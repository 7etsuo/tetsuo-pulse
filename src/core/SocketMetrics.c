#include <assert.h>
#include <pthread.h>
#include <string.h>

#include "core/SocketLog.h"

#include "core/SocketMetrics.h"

static pthread_mutex_t socketmetrics_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned long long socketmetrics_values[SOCKET_METRIC_COUNT] = { 0ULL };

static const char *socketmetrics_names[SOCKET_METRIC_COUNT]
    = { "socket.connect_success", "socket.connect_failure",
        "socket.shutdown_calls",  "dns.request_submitted",
        "dns.request_completed",  "dns.request_failed",
        "dns.request_cancelled",  "dns.request_timeout",
        "poll.wakeups",           "poll.events_dispatched",
        "pool.connections_added", "pool.connections_removed",
        "pool.connections_reused" };

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

void
SocketMetrics_reset (void)
{
  pthread_mutex_lock (&socketmetrics_mutex);
  memset (socketmetrics_values, 0, sizeof (socketmetrics_values));
  pthread_mutex_unlock (&socketmetrics_mutex);
}

const char *
SocketMetrics_name (SocketMetric metric)
{
  if (metric < 0 || metric >= SOCKET_METRIC_COUNT)
    return "unknown";
  return socketmetrics_names[metric];
}

size_t
SocketMetrics_count (void)
{
  return SOCKET_METRIC_COUNT;
}
