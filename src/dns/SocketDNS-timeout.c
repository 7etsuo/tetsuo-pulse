/**
 * SocketDNS-timeout.c - Timeout handling for async DNS resolution
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Contains timeout calculation and request timeout handling functions.
 */

/* All includes before T macro definition to avoid redefinition warnings */
#include "core/Arena.h"
#include "dns/SocketDNS.h"
#include "dns/SocketDNS-private.h"

/* Redefine T after all includes (Arena.h and SocketDNS.h both undef T at end) */
#undef T
#define T SocketDNS_T
#undef Request_T
#define Request_T SocketDNS_Request_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS-timeout"

/**
 * request_effective_timeout_ms - Get effective timeout for request
 * @dns: DNS resolver instance
 * @req: Request
 * Returns: Per-request timeout override or default resolver timeout (ms)
 */
int
request_effective_timeout_ms (struct SocketDNS_T *dns,
                              const struct SocketDNS_Request_T *req)
{
  if (req->timeout_override_ms >= 0)
    return req->timeout_override_ms;
  return dns->request_timeout_ms;
}

/**
 * request_timed_out - Check if request has timed out
 * @dns: DNS resolver instance
 * @req: Request to check
 * Returns: 1 if timed out, 0 otherwise
 * Uses CLOCK_MONOTONIC for monotonic time calculation.
 * Thread-safe: Yes - read-only for req state
 */
int
request_timed_out (struct SocketDNS_T *dns,
                   const struct SocketDNS_Request_T *req)
{
  int timeout_ms = request_effective_timeout_ms (dns, req);
  struct timespec now;
  long long elapsed_ms;

  if (timeout_ms <= 0)
    return 0;

  clock_gettime (CLOCK_MONOTONIC, &now);

  elapsed_ms = (now.tv_sec - req->submit_time.tv_sec) * SOCKET_MS_PER_SECOND;
  elapsed_ms += (now.tv_nsec - req->submit_time.tv_nsec) / SOCKET_NS_PER_MS;

  return elapsed_ms >= timeout_ms;
}

/**
 * mark_request_timeout - Mark request as timed out
 * @dns: DNS resolver instance
 * @req: Request to mark as timed out
 * Sets state to complete with timeout error, frees result if any, signals
 * completion. Thread-safe: Must be called with mutex locked? No, but callers
 * lock.
 */
void
mark_request_timeout (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  req->state = REQ_COMPLETE;
  req->error = EAI_AGAIN;
  if (req->result)
    {
      freeaddrinfo (req->result);
      req->result = NULL;
    }
  SIGNAL_DNS_COMPLETION (dns);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_TIMEOUT, 1);
  SocketEvent_emit_dns_timeout (req->host ? req->host : "(wildcard)",
                                req->port);
}

/**
 * handle_request_timeout - Handle request timeout case
 * @dns: DNS resolver instance
 * @req: Request that timed out
 * Thread-safe: Uses mutex internally
 * Marks request as timed out, signals completion, emits event.
 */
void
handle_request_timeout (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req)
{
  pthread_mutex_lock (&dns->mutex);
  mark_request_timeout (dns, req);
  pthread_mutex_unlock (&dns->mutex);
}

#undef T
#undef Request_T

