/**
 * SocketDNS.c - Core public API for async DNS resolution
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Contains public API functions for DNS resolution, request management,
 * and resolver lifecycle. Internal implementation details are delegated
 * to SocketDNS-init.c, SocketDNS-request.c, and SocketDNS-worker.c.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

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
#include "socket/SocketCommon.h"

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

/**
 * init_completed_request_fields - Initialize fields for completed request
 * @req: Request structure to initialize
 * @dns: DNS resolver instance
 * @result: Address info result
 * @port: Port number
 * Raises: SocketDNS_Failed on allocation failure
 */
static void
init_completed_request_fields (struct SocketDNS_Request_T *req,
                               struct SocketDNS_T *dns,
                               struct addrinfo *result, int port)
{
  req->dns_resolver = dns;
  req->host = NULL;
  req->port = port;
  req->callback = NULL;
  req->callback_data = NULL;
  req->state = REQ_COMPLETE;
  req->result = SocketCommon_copy_addrinfo (result);
  if (!req->result)
    {
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
  freeaddrinfo (result);
  req->error = 0;
  req->queue_next = NULL;
  req->hash_next = NULL;
  clock_gettime (CLOCK_MONOTONIC, &req->submit_time);
  req->timeout_override_ms = -1;
}

/**
 * transfer_result_ownership - Handle result ownership transfer to caller
 * @r: Request to process
 * Returns: Result pointer (transfers ownership) or NULL if callback consumed it
 * Thread-safe: Must be called with mutex locked
 */
static struct addrinfo *
transfer_result_ownership (struct SocketDNS_Request_T *r)
{
  struct addrinfo *result = NULL;

  if (r->state == REQ_COMPLETE)
    {
      /* If callback was provided, result ownership was transferred to callback */
      if (r->callback)
        {
          /* Callback already received the result - it's been consumed */
          result = NULL;
        }
      else
        {
          /* No callback - transfer ownership to caller */
          result = r->result;
          r->result = NULL;
        }

      hash_table_remove ((struct SocketDNS_T *)r->dns_resolver, r);
    }

  return result;
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
  check_queue_limit (dns);
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

size_t
SocketDNS_getmaxpending (struct SocketDNS_T *dns)
{
  size_t current;

  if (!dns)
    return 0;
  assert (dns);

  pthread_mutex_lock (&dns->mutex);
  current = dns->max_pending;
  pthread_mutex_unlock (&dns->mutex);

  return current;
}

void
SocketDNS_setmaxpending (struct SocketDNS_T *dns, size_t max_pending)
{
  size_t queue_depth;

  if (!dns)
    {
      SOCKET_ERROR_MSG ("Invalid NULL dns resolver");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
  assert (dns);

  pthread_mutex_lock (&dns->mutex);
  queue_depth = dns->queue_size;
  if (max_pending < queue_depth)
    {
      pthread_mutex_unlock (&dns->mutex);
      SOCKET_ERROR_MSG (
          "Cannot set max pending (%zu) below current queue depth (%zu)",
          max_pending, queue_depth);
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  dns->max_pending = max_pending;
  pthread_mutex_unlock (&dns->mutex);
}

int
SocketDNS_gettimeout (struct SocketDNS_T *dns)
{
  int current;

  if (!dns)
    return 0;
  assert (dns);

  pthread_mutex_lock (&dns->mutex);
  current = dns->request_timeout_ms;
  pthread_mutex_unlock (&dns->mutex);

  return current;
}

void
SocketDNS_settimeout (struct SocketDNS_T *dns, int timeout_ms)
{
  int sanitized = timeout_ms < 0 ? 0 : timeout_ms;

  if (!dns)
    return;
  assert (dns);

  pthread_mutex_lock (&dns->mutex);
  dns->request_timeout_ms = sanitized;
  pthread_mutex_unlock (&dns->mutex);
}

int
SocketDNS_pollfd (struct SocketDNS_T *dns)
{
  if (!dns)
    return -1;
  assert (dns);
  return dns->pipefd[0];
}

int
SocketDNS_check (struct SocketDNS_T *dns)
{
  char buffer[SOCKET_DNS_PIPE_BUFFER_SIZE];
  ssize_t n;
  volatile int count = 0;

  if (!dns)
    return 0;
  assert (dns);

  /* Check if pipe is still valid (may be closed during shutdown) */
  if (dns->pipefd[0] < 0)
    return 0;

  /* Read all available data from pipe (non-blocking) */
  while ((n = read (dns->pipefd[0], buffer, sizeof (buffer))) > 0)
    {
      count += n;
    }

  /* EAGAIN/EWOULDBLOCK means no data available - not an error */
  if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    {
      /* Real error - but don't raise exception, just return count */
      return count;
    }

  return count;
}

struct addrinfo *
SocketDNS_getresult (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  Request_T r = req;
  struct addrinfo *result = NULL;

  if (!dns || !req)
    return NULL;
  assert (dns);
  assert (req);

  pthread_mutex_lock (&dns->mutex);
  result = transfer_result_ownership (r);
  pthread_mutex_unlock (&dns->mutex);

  return result;
}

int
SocketDNS_geterror (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  Request_T r = req;
  int error = 0;

  if (!dns || !req)
    return 0;
  assert (dns);
  assert (req);

  pthread_mutex_lock (&dns->mutex);
  if (r->state == REQ_COMPLETE || r->state == REQ_CANCELLED)
    error = r->error;
  pthread_mutex_unlock (&dns->mutex);

  return error;
}

Request_T
SocketDNS_create_completed_request (struct SocketDNS_T *dns,
                                    struct addrinfo *result, int port)
{
  if (!dns || !result)
    {
      SOCKET_ERROR_MSG (
          "Invalid NULL dns or result in create_completed_request");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
  assert (dns);
  assert (result);

  /* Note: addrinfo already validated during resolution, no need to re-validate */

  Request_T req = allocate_request_structure (dns);
  init_completed_request_fields (req, dns, result, port);

  pthread_mutex_lock (&dns->mutex);
  hash_table_insert (dns, req);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_COMPLETED, 1);
  signal_completion (dns);
  pthread_cond_broadcast (&dns->result_cond);
  pthread_mutex_unlock (&dns->mutex);

  return req;
}

void
SocketDNS_request_settimeout (struct SocketDNS_T *dns,
                              struct SocketDNS_Request_T *req, int timeout_ms)
{
  Request_T r = req;
  int sanitized = timeout_ms < 0 ? 0 : timeout_ms;

  if (!dns || !req)
    return;
  assert (dns);
  assert (req);

  pthread_mutex_lock (&dns->mutex);
  if (r->state == REQ_PENDING || r->state == REQ_PROCESSING)
    r->timeout_override_ms = sanitized;
  pthread_mutex_unlock (&dns->mutex);
}

#undef T
#undef Request_T
