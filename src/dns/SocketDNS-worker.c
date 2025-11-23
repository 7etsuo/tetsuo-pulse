/**
 * SocketDNS-worker.c - Worker thread implementation for async DNS resolution
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Contains worker thread logic, request processing, and DNS resolution functions.
 */

#include <assert.h>
#include "core/SocketConfig.h"
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "core/SocketEvents.h"
#include "core/SocketMetrics.h"
#include "dns/SocketDNS.h"
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS-worker"
#define T SocketDNS_T
#define Request_T SocketDNS_Request_T
#include "dns/SocketDNS-private.h"
#include "socket/SocketCommon.h"

/**
 * initialize_addrinfo_hints - Initialize getaddrinfo hints structure
 * @hints: Hints structure to initialize
 * Sets up hints for DNS resolution with AF_UNSPEC (IPv4/IPv6).
 * Thread-safe: Yes - no shared state
 */
void
initialize_addrinfo_hints (struct addrinfo *hints)
{
  memset (hints, 0, sizeof (*hints));
  hints->ai_family = AF_UNSPEC;
  hints->ai_socktype = SOCK_STREAM;
  hints->ai_protocol = 0;
}

/**
 * worker_thread - Worker thread for DNS resolution
 * @arg: DNS resolver instance
 * Returns: NULL
 * Worker thread that processes DNS resolution requests from queue.
 * Blocks waiting for requests, performs resolution, stores results.
 * Thread-safe: Uses mutex/cond for synchronization
 */
void *
worker_thread (void *arg)
{
  struct SocketDNS_T *dns = (T)arg;
  struct SocketDNS_Request_T *req;
  struct addrinfo hints;

  initialize_addrinfo_hints (&hints);

  while (1)
    {
      pthread_mutex_lock (&dns->mutex);
      req = wait_for_request (dns);
      pthread_mutex_unlock (&dns->mutex);

      if (!req)
        break;

      process_single_request (dns, req, &hints);
    }

  return NULL;
}

/**
 * handle_request_timeout - Handle request timeout case
 * @dns: DNS resolver instance
 * @req: Request that timed out
 * Thread-safe: Uses mutex internally
 * Marks request as timed out, signals completion, emits event.
 */
void handle_request_timeout (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  pthread_mutex_lock (&dns->mutex);
  mark_request_timeout (dns, req);
  pthread_mutex_unlock (&dns->mutex);
}

/**
 * prepare_local_hints - Prepare local hints copy with request-specific flags
 * @local_hints: Output local hints structure
 * @base_hints: Base hints to copy from
 * @req: Request determining flags (e.g., AI_PASSIVE for NULL host)
 */
void prepare_local_hints (struct addrinfo *local_hints, const struct addrinfo *base_hints, const struct SocketDNS_Request_T *req)
{
  memcpy (local_hints, base_hints, sizeof (*local_hints));
  if (req->host == NULL)
    {
      local_hints->ai_flags |= AI_PASSIVE;
    }
}

/**
 * handle_resolution_result - Handle post-resolution logic under mutex
 * @dns: DNS resolver instance
 * @req: Request to update
 * @result: Resolution result (may be freed if timed out)
 * @res: Resolution error code (may be overridden if timed out)
 * Thread-safe: Must be called with mutex locked? No, locks internally.
 * Checks for timeout after resolution, frees result if timed out, stores result.
 */
void handle_resolution_result (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req, struct addrinfo *result, int res)
{
  pthread_mutex_lock (&dns->mutex);
  if (request_timed_out (dns, req))
    {
      if (result)
        {
          freeaddrinfo (result);
          result = NULL;
        }
      res = EAI_AGAIN;
    }
  store_resolution_result (dns, req, result, res);
  pthread_mutex_unlock (&dns->mutex);
}

/**
 * process_single_request - Process one DNS resolution request
 * @dns: DNS resolver instance
 * @req: Request to process
 * @base_hints: Base getaddrinfo hints structure
 * Performs DNS resolution for one request: timeout check, hints prep, resolution,
 * result handling, callback invocation.
 * Thread-safe: No - called from worker thread, uses mutex for shared state.
 * Raises: None directly, uses exceptions via helpers.
 */
void process_single_request (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req, struct addrinfo *base_hints)
{
  if (request_timed_out (dns, req))
    {
      handle_request_timeout (dns, req);
      return;
    }

  struct addrinfo local_hints;
  prepare_local_hints (&local_hints, base_hints, req);

  struct addrinfo *result = NULL;
  int res = perform_dns_resolution (req, &local_hints, &result);

  handle_resolution_result (dns, req, result, res);

  invoke_callback (dns, req);
}

/**
 * dequeue_request - Dequeue next request from queue
 * @dns: DNS resolver instance
 * Returns: Next request or NULL if queue empty
 * Thread-safe: Must be called with mutex locked
 */
Request_T dequeue_request (struct SocketDNS_T *dns)
{
  struct SocketDNS_Request_T *req;

  if (!dns->queue_head)
    return NULL;

  req = dns->queue_head;
  dns->queue_head = req->queue_next;
  if (!dns->queue_head)
    dns->queue_tail = NULL;
  dns->queue_size--;
  req->queue_next = NULL;
  req->state = REQ_PROCESSING;

  return req;
}

/**
 * wait_for_request - Wait for next request or shutdown
 * @dns: DNS resolver instance
 * Returns: Request to process, or NULL if shutdown
 * Thread-safe: Must be called with mutex locked, unlocks on return
 */
Request_T wait_for_request (struct SocketDNS_T *dns)
{
  while (dns->queue_head == NULL && !dns->shutdown)
    {
      pthread_cond_wait (&dns->queue_cond, &dns->mutex);
    }

  if (dns->shutdown && dns->queue_head == NULL)
    {
      pthread_mutex_unlock (&dns->mutex);
      return NULL;
    }

  return dequeue_request (dns);
}

/**
 * mark_request_timeout - Mark request as timed out
 * @dns: DNS resolver instance
 * @req: Request to mark as timed out
 * Sets state to complete with timeout error, frees result if any, signals completion.
 * Thread-safe: Must be called with mutex locked? No, but callers lock.
 */
void mark_request_timeout (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  req->state = REQ_COMPLETE;
  req->error = EAI_AGAIN;
  if (req->result)
    {
      freeaddrinfo (req->result);
      req->result = NULL;
    }
  signal_completion (dns);
  pthread_cond_broadcast (&dns->result_cond);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_TIMEOUT, 1);
  SocketEvent_emit_dns_timeout (req->host ? req->host : "(wildcard)",
                                req->port);
}

/**
 * signal_completion - Signal completion via pipe
 * @dns: DNS resolver instance
 * Writes completion signal to pipe. Non-blocking best-effort operation.
 * Pipe may be full, which is acceptable - signals are cumulative.
 * Thread-safe: Yes - write to pipe[1] is atomic for 1 byte
 */
void signal_completion (struct SocketDNS_T *dns)
{
  char byte = COMPLETION_SIGNAL_BYTE;
  ssize_t n;

  n = write (dns->pipefd[1], &byte, 1);
  (void)n; /* Ignore result - pipe may be full, that's OK */
}

/**
 * store_resolution_result - Store completed resolution result
 * @dns: DNS resolver instance
 * @req: Completed request
 * @result: Resolution result (caller transfers ownership if stored)
 * @error: Error code from getaddrinfo
 * Thread-safe: Must be called with mutex locked
 * Stores result if request still processing; otherwise frees if cancelled.
 * Updates metrics, signals completion.
 */
void store_resolution_result (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req, struct addrinfo *result, int error)
{
  if (req->state == REQ_PROCESSING)
    {
      req->state = REQ_COMPLETE;
      req->result = SocketCommon_copy_addrinfo (result);
      if (!req->result) {
        freeaddrinfo (result);
        req->error = EAI_MEMORY;
        req->state = REQ_COMPLETE; // still complete, but error
      } else {
        freeaddrinfo (result); // transfer by copy and free original
      }
      req->error = error;

      if (error == 0)
        SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_COMPLETED, 1);
      else
        SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_FAILED, 1);

      signal_completion (dns);
      pthread_cond_broadcast (&dns->result_cond);
    }
  else
    {
      /* Request was cancelled, free result */
      if (result)
        freeaddrinfo (result);

      if (req->state == REQ_CANCELLED)
        {
          if (req->error == 0)
            req->error = dns_cancellation_error ();
          signal_completion (dns);
          pthread_cond_broadcast (&dns->result_cond);
        }
    }
}

/**
 * dns_cancellation_error - Get appropriate error code for cancelled request
 * Returns: EAI_CANCELLED if defined, else EAI_AGAIN
 * Used for consistent error reporting on cancellation.
 */
int
dns_cancellation_error (void)
{
#ifdef EAI_CANCELLED
  return EAI_CANCELLED;
#else
  return EAI_AGAIN;
#endif
}

/**
 * request_effective_timeout_ms - Get effective timeout for request
 * @dns: DNS resolver instance
 * @req: Request
 * Returns: Per-request timeout override or default resolver timeout (ms)
 */
int request_effective_timeout_ms (struct SocketDNS_T *dns, const struct SocketDNS_Request_T *req)
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
int request_timed_out (struct SocketDNS_T *dns, const struct SocketDNS_Request_T *req)
{
  int timeout_ms = request_effective_timeout_ms (dns, req);
  struct timespec now;
  long long elapsed_ms;

  if (timeout_ms <= 0)
    return 0;

  clock_gettime (CLOCK_MONOTONIC, &now);

  elapsed_ms = (now.tv_sec - req->submit_time.tv_sec) * 1000LL; /* SOCKET_MS_PER_SECOND */
  elapsed_ms += (now.tv_nsec - req->submit_time.tv_nsec) / 1000000LL; /* SOCKET_NS_PER_MS */

  return elapsed_ms >= timeout_ms;
}

/**
 * perform_dns_resolution - Perform actual DNS lookup
 * @req: Request to resolve
 * @hints: getaddrinfo hints structure
 * Returns: getaddrinfo result code
 * @result: Set to resolved addresses (or NULL on error); caller owns on success
 * Performs DNS resolution with optional port parameter.
 * Handles NULL host (wildcard bind) by passing NULL to getaddrinfo.
 * Note: getaddrinfo() is called directly and is not interruptible.
 */
int
perform_dns_resolution (struct SocketDNS_Request_T *req, const struct addrinfo *hints,
                        struct addrinfo **result)
{
  char port_str[SOCKET_DNS_PORT_STR_SIZE];
  const char *service = NULL;
  int res;

  if (req->port > 0)
    {
      int sn_res = snprintf (port_str, sizeof (port_str), "%d", req->port);
      if (sn_res < 0 || (size_t)sn_res >= sizeof (port_str))
        {
          *result = NULL;
          return EAI_FAIL;
        }
      service = port_str;
    }

  res = getaddrinfo (req->host, service, hints, result);
  return res;
}

/**
 * invoke_callback - Invoke completion callback if provided
 * @dns: DNS resolver instance
 * @req: Completed request
 * Thread-safe: Called without mutex held (callback may take time); locks briefly to clear result
 * Note: Callback receives ownership of result. Clears req->result after to prevent use-after-free.
 * SocketDNS_getresult() returns NULL if callback provided.
 */
void invoke_callback (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  if (req->callback && req->state == REQ_COMPLETE)
    {
      /* Callback receives ownership of result */
      struct addrinfo *result = req->result;
      req->callback (req, result, req->error, req->callback_data);

      /* Clear result pointer after callback to prevent use-after-free.
       * Callback has taken ownership and freed it. */
      pthread_mutex_lock (&dns->mutex);
      req->result = NULL;
      pthread_mutex_unlock (&dns->mutex);
    }
}

#undef T
#undef T
#undef Request_T