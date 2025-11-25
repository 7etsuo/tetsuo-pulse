/**
 * SocketDNS-accessors.c - Accessor functions for async DNS resolution
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Contains getter/setter functions for DNS resolver configuration,
 * result retrieval, and status checking.
 */

/* All includes before T macro definition to avoid redefinition warnings */
#include <errno.h>

#include "core/Arena.h"
#include "dns/SocketDNS.h"
#include "dns/SocketDNS-private.h"

/* Redefine T after all includes (Arena.h and SocketDNS.h both undef T at end) */
#undef T
#define T SocketDNS_T
#undef Request_T
#define Request_T SocketDNS_Request_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS-accessors"

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
      /* If no callback, transfer ownership to caller; else callback consumed it */
      if (!r->callback)
        {
          result = r->result;
          r->result = NULL;
        }

      hash_table_remove (r->dns_resolver, r);
    }

  return result;
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

size_t
SocketDNS_getmaxpending (struct SocketDNS_T *dns)
{
  size_t current;

  if (!dns)
    return 0;

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

  pthread_mutex_lock (&dns->mutex);
  current = dns->request_timeout_ms;
  pthread_mutex_unlock (&dns->mutex);

  return current;
}

void
SocketDNS_settimeout (struct SocketDNS_T *dns, int timeout_ms)
{
  if (!dns)
    return;

  pthread_mutex_lock (&dns->mutex);
  dns->request_timeout_ms = SANITIZE_TIMEOUT_MS (timeout_ms);
  pthread_mutex_unlock (&dns->mutex);
}

int
SocketDNS_pollfd (struct SocketDNS_T *dns)
{
  if (!dns)
    return -1;
  return dns->pipefd[0];
}

int
SocketDNS_check (struct SocketDNS_T *dns)
{
  char buffer[SOCKET_DNS_PIPE_BUFFER_SIZE];
  ssize_t n;
  int count = 0;

  if (!dns)
    return 0;

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
  struct addrinfo *result = NULL;

  if (!dns || !req)
    return NULL;

  pthread_mutex_lock (&dns->mutex);
  result = transfer_result_ownership (req);
  pthread_mutex_unlock (&dns->mutex);

  return result;
}

int
SocketDNS_geterror (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  int error = 0;

  if (!dns || !req)
    return 0;

  pthread_mutex_lock (&dns->mutex);
  if (req->state == REQ_COMPLETE || req->state == REQ_CANCELLED)
    error = req->error;
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

  Request_T req = allocate_request_structure (dns);
  init_completed_request_fields (req, dns, result, port);

  pthread_mutex_lock (&dns->mutex);
  hash_table_insert (dns, req);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_COMPLETED, 1);
  SIGNAL_DNS_COMPLETION (dns);
  pthread_mutex_unlock (&dns->mutex);

  return req;
}

void
SocketDNS_request_settimeout (struct SocketDNS_T *dns,
                              struct SocketDNS_Request_T *req, int timeout_ms)
{
  if (!dns || !req)
    return;

  pthread_mutex_lock (&dns->mutex);
  if (req->state == REQ_PENDING || req->state == REQ_PROCESSING)
    req->timeout_override_ms = SANITIZE_TIMEOUT_MS (timeout_ms);
  pthread_mutex_unlock (&dns->mutex);
}

#undef T
#undef Request_T

