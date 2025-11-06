#ifndef SOCKETMETRICS_INCLUDED
#define SOCKETMETRICS_INCLUDED

#include <stddef.h>

typedef enum SocketMetric
{
    SOCKET_METRIC_SOCKET_CONNECT_SUCCESS = 0,
    SOCKET_METRIC_SOCKET_CONNECT_FAILURE,
    SOCKET_METRIC_SOCKET_SHUTDOWN_CALL,
    SOCKET_METRIC_DNS_REQUEST_SUBMITTED,
    SOCKET_METRIC_DNS_REQUEST_COMPLETED,
    SOCKET_METRIC_DNS_REQUEST_FAILED,
    SOCKET_METRIC_DNS_REQUEST_CANCELLED,
    SOCKET_METRIC_DNS_REQUEST_TIMEOUT,
    SOCKET_METRIC_POLL_WAKEUPS,
    SOCKET_METRIC_POLL_EVENTS_DISPATCHED,
    SOCKET_METRIC_POOL_CONNECTIONS_ADDED,
    SOCKET_METRIC_POOL_CONNECTIONS_REMOVED,
    SOCKET_METRIC_POOL_CONNECTIONS_REUSED,
    SOCKET_METRIC_COUNT
} SocketMetric;

typedef struct SocketMetricsSnapshot
{
    unsigned long long values[SOCKET_METRIC_COUNT];
} SocketMetricsSnapshot;

void SocketMetrics_increment(SocketMetric metric, unsigned long value);
void SocketMetrics_getsnapshot(SocketMetricsSnapshot *snapshot);
void SocketMetrics_reset(void);
const char *SocketMetrics_name(SocketMetric metric);
size_t SocketMetrics_count(void);

static inline unsigned long long
SocketMetrics_snapshot_value(const SocketMetricsSnapshot *snapshot, SocketMetric metric)
{
    if (!snapshot)
        return 0ULL;
    if (metric < 0 || metric >= SOCKET_METRIC_COUNT)
        return 0ULL;
    return snapshot->values[metric];
}

#endif /* SOCKETMETRICS_INCLUDED */

