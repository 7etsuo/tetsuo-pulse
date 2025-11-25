/**
 * SocketDNS.c - Core public API for async DNS resolution
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Contains public API functions for DNS resolver lifecycle and request
 * management. Accessor functions are in SocketDNS-accessors.c.
 */

#include <assert.h>
#include <netdb.h>
#include <pthread.h>
#include <string.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketError.h"
#include "core/SocketEvents.h"
#include "core/SocketMetrics.h"
#include "dns/SocketDNS.h"
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS"
#define T SocketDNS_T
#define Request_T SocketDNS_Request_T
#include "dns/SocketDNS-private.h"

/* SocketDNS module exceptions and thread-local detailed exception */
const Except_T SocketDNS_Failed
    = { &SocketDNS_Failed, "SocketDNS operation failed" };

#ifdef _WIN32
__declspec (thread) Except_T SocketDNS_DetailedException;
#else
__thread Except_T SocketDNS_DetailedException;
#endif

/**
 * cancel_pending_state - Handle cancellation of pending request
 * @dns: DNS resolver instance
 * @req: Request to cancel
 * Thread-safe: Must be called with mutex locked
 */
static void
cancel_pending_state (struct SocketDNS_T *dns,
                      struct SocketDNS_Request_T *req)
{
  cancel_pending_request (dns, req);
  req->error = dns_cancellation_error ();
}

/**
 * cancel_processing_state - Handle cancellation of processing request
 * @dns: DNS resolver instance
 * @req: Request to cancel
 * Thread-safe: Must be called with mutex locked
 */
static void
cancel_processing_state (struct SocketDNS_T *dns,
                         struct SocketDNS_Request_T *req)
{
  (void)dns; /* Suppress unused parameter warning */
  req->state = REQ_CANCELLED;
  req->error = dns_cancellation_error ();
}

/**
 * cancel_complete_state - Handle cancellation of completed request
 * @req: Request to cancel
 * Thread-safe: Must be called with mutex locked
 */
static void
cancel_complete_state (struct SocketDNS_Request_T *req)
{
  if (req->result)
    {
      freeaddrinfo (req->result);
      req->result = NULL;
    }
  req->error = dns_cancellation_error ();
}

T
SocketDNS_new (void)
{
  struct SocketDNS_T *dns;

  dns = allocate_dns_resolver ();
  initialize_dns_fields (dns);
  initialize_dns_components (dns);
  start_dns_workers (dns);

  return dns;
}

void
SocketDNS_free (T *dns)
{
  T d;

  if (!dns || !*dns)
    return;
  assert (dns && *dns);

  d = *dns;

  shutdown_workers (d);
  drain_completion_pipe (d);
  reset_dns_state (d);
  destroy_dns_resources (d);
  *dns = NULL;
}

Request_T
SocketDNS_resolve (struct SocketDNS_T *dns, const char *host, int port,
                   SocketDNS_Callback callback, void *data)
{
  size_t host_len;
  int queue_full;

  if (!dns)
    {
      SOCKET_ERROR_MSG ("Invalid NULL dns resolver");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
  assert (dns);

  host_len = host ? strlen (host) : 0;
  validate_resolve_params (host, port);
  Request_T req = allocate_request (dns, host, host_len, port, callback, data);

  pthread_mutex_lock (&dns->mutex);
  queue_full = check_queue_limit (dns);
  if (queue_full)
    {
      size_t max_pending = dns->max_pending;
      pthread_mutex_unlock (&dns->mutex);
      SOCKET_ERROR_MSG ("DNS request queue full (max %zu pending)", max_pending);
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
  submit_dns_request (dns, req);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_SUBMITTED, 1);
  pthread_mutex_unlock (&dns->mutex);

  return req;
}

void
SocketDNS_cancel (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  Request_T r = req;
  int send_signal = 0;
  int cancelled = 0;

  if (!dns || !req)
    return;
  assert (dns);
  assert (req);

  pthread_mutex_lock (&dns->mutex);

  if (r->state == REQ_PENDING)
    {
      cancel_pending_state (dns, r);
      send_signal = 1;
      cancelled = 1;
    }
  else if (r->state == REQ_PROCESSING)
    {
      cancel_processing_state (dns, r);
      send_signal = 1;
      cancelled = 1;
    }
  else if (r->state == REQ_COMPLETE)
    {
      cancel_complete_state (r);
    }
  else if (r->state == REQ_CANCELLED)
    {
      if (r->error == 0)
        r->error = dns_cancellation_error ();
    }

  if (send_signal)
    {
      signal_completion (dns);
      pthread_cond_broadcast (&dns->result_cond);
    }

  hash_table_remove (dns, r);
  if (cancelled)
    SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_CANCELLED, 1);
  pthread_mutex_unlock (&dns->mutex);
}

#undef T
#undef Request_T
