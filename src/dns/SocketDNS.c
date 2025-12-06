/**
 * SocketDNS.c - Async DNS resolution public API
 *
 * Part of the Socket Library
 *
 * Contains:
 * - Public API functions (new, free, resolve, cancel)
 * - Accessor functions (getters/setters for configuration)
 * - Validation functions (hostname, IP address, port validation)
 */

/* System headers first */

#include <errno.h>
#include <string.h>

/* Project headers - Arena.h included to ensure T macro is defined/undefined
 * before we define our module's T. SocketDNS-private.h forward-declares Arena_T
 * but doesn't include Arena.h to avoid T macro conflicts in other contexts. */
#include "core/Arena.h"
#include "dns/SocketDNS.h"
#include "dns/SocketDNS-private.h"
#include "socket/SocketCommon-private.h"

/* Define our module's T macro (Arena.h undefs T at end of header) */
#undef T /* Defensive: ensure clean slate */
#define T SocketDNS_T
#define Request_T SocketDNS_Request_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS"

/* SocketDNS module exception - global constant shared by all threads */
const Except_T SocketDNS_Failed
    = { &SocketDNS_Failed, "SocketDNS operation failed" };

/**
 * Thread-local exception for detailed error messages.
 *
 * SOCKET_DECLARE_MODULE_EXCEPTION creates a static __thread variable
 * (SocketDNS_DetailedException) used by SOCKET_RAISE_MSG/FMT macros.
 * Each .c file using these macros needs its own declaration due to
 * static linkage. Thread-local storage ensures safe concurrent use.
 */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketDNS);

/*
 * =============================================================================
 * Validation Functions
 * =============================================================================
 */

/**
 * is_ip_address - Check if string is a valid IP address (IPv4 or IPv6)
 * @host: Host string to check
 * Returns: 1 if valid IP address, 0 otherwise
 * 
 * Wrapper for common implementation to maintain API compatibility.
 */
/* is_ip_address removed: use socketcommon_is_ip_address directly */

/**
 * is_valid_label_char - Check if character is valid in hostname label
 * @c: Character to check
 * @at_start: Whether this is the first character of a label
 *
 * Returns: true if valid character for position
 * Thread-safe: Yes - no shared state
 *
 * Per RFC 1123: label start must be alphanumeric; other positions allow hyphen.
 */
/* is_valid_label_char removed: duplicate in SocketCommon.c */

/**
 * is_valid_label_length - Check label length is within bounds
 * @label_len: Current label length
 *
 * Returns: true if within bounds (1 to SOCKET_DNS_MAX_LABEL_LENGTH)
 * Thread-safe: Yes - no shared state
 *
 * Validates that a DNS label has valid length per RFC 1035 Section 2.3.4.
 * Labels must be between 1 and 63 characters inclusive (63 = max label length).
 * A label_len of 0 indicates an empty label (e.g., consecutive dots ".."),
 * which is invalid per RFC 1035.
 */
/* is_valid_label_length removed: duplicate in SocketCommon.c */

/**
 * validate_hostname_label - Validate hostname labels per RFC 1123
 * @label: Hostname string containing one or more dot-separated labels
 * @len: Output parameter for total validated length (can be NULL)
 *
 * Returns: 1 if all labels valid, 0 otherwise
 * Thread-safe: Yes - no shared state modified
 *
 * Validates that each dot-separated label:
 * - Starts with alphanumeric character
 * - Contains only alphanumeric or hyphen characters
 * - Has length between 1 and SOCKET_DNS_MAX_LABEL_LENGTH (63)
 */
/* validate_hostname_label removed: duplicate implementation in SocketCommon.c
 * Use socketcommon_validate_hostname_labels(hostname) which returns 1/0 valid.
 * Note: no length output; compute strlen separately if needed.
 */

/* validate_hostname removed: use socketcommon_validate_hostname_internal or SocketCommon_validate_hostname directly */

/**
 * validate_resolve_params - Validate parameters for DNS resolution
 * @host: Hostname to validate (NULL allowed for wildcard bind)
 * @port: Port number to validate
 * Raises: SocketDNS_Failed on invalid parameters
 */
void
validate_resolve_params (const char *host, int port)
{
  /* Host validation - NULL is allowed for wildcard bind with AI_PASSIVE.
   * Uses SocketCommon validation to avoid duplication. */

  if (host != NULL)
    {
      if (!socketcommon_is_ip_address (host))
        {
          SocketCommon_validate_hostname (host, SocketDNS_Failed);
        }
    }

  SocketCommon_validate_port (port, SocketDNS_Failed);
}

/*
 * =============================================================================
 * Static Helper Functions
 * =============================================================================
 */

/**
 * validate_request_ownership_locked - Validate request belongs to resolver
 * @dns: DNS resolver instance
 * @req: Request to validate
 *
 * Returns: 1 if valid, 0 if invalid (caller should unlock and return)
 * Thread-safe: Must be called with mutex locked
 *
 * Security check to prevent cross-resolver request handle corruption.
 */
static int
validate_request_ownership_locked (const struct SocketDNS_T *dns,
                                   const struct SocketDNS_Request_T *req)
{
  return req->dns_resolver == dns;
}

/**
 * cancel_pending_state - Handle cancellation of pending (queued) request
 * @dns: DNS resolver instance
 * @req: Request to cancel
 *
 * Thread-safe: Must be called with mutex locked
 *
 * Removes request from queue and marks as cancelled with appropriate error.
 */
static void
cancel_pending_state (struct SocketDNS_T *dns,
                      struct SocketDNS_Request_T *req)
{
  cancel_pending_request (dns, req);
  req->error = dns_cancellation_error ();
}

/**
 * cancel_processing_state - Handle cancellation of in-progress request
 * @dns: DNS resolver instance (unused but kept for consistency)
 * @req: Request to cancel
 *
 * Thread-safe: Must be called with mutex locked
 *
 * Marks request as cancelled. The worker thread will detect this state
 * after resolution completes and discard the result.
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
 * @req: Request to cancel (modified in place)
 *
 * Thread-safe: Must be called with mutex locked
 *
 * Frees any stored result only if no callback was provided. When a callback
 * exists, the callback owns the result and is responsible for freeing it.
 * Sets cancellation error code.
 */
static void
cancel_complete_state (struct SocketDNS_Request_T *req)
{
  /* Only free result if no callback was provided.
   * If callback exists, it has received ownership of the result
   * and is responsible for freeing it (may have already done so). */
  if (req->result && !req->callback)
    {
      SocketCommon_free_addrinfo (req->result);
      req->result = NULL;
    }
  req->error = dns_cancellation_error ();
}

/**
 * handle_cancel_by_state - Handle cancellation based on request state
 * @dns: DNS resolver instance
 * @req: Request to cancel
 * @send_signal: Output flag indicating if completion signal needed
 * @cancelled: Output flag indicating if cancellation metrics needed
 *
 * Thread-safe: Must be called with mutex locked
 */
static void
handle_cancel_by_state (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req,
                        int *send_signal, int *cancelled)
{
  switch (req->state)
    {
    case REQ_PENDING:
      cancel_pending_state (dns, req);
      *send_signal = 1;
      *cancelled = 1;
      break;

    case REQ_PROCESSING:
      cancel_processing_state (dns, req);
      *send_signal = 1;
      *cancelled = 1;
      break;

    case REQ_COMPLETE:
      cancel_complete_state (req);
      break;

    case REQ_CANCELLED:
      if (req->error == 0)
        req->error = dns_cancellation_error ();
      break;
    }
}

/**
 * transfer_result_ownership - Handle result ownership transfer to caller
 * @req: Request to process (modified: result cleared if transferred)
 *
 * Returns: Result pointer (transfers ownership) or NULL if:
 *   - Request is not complete (still pending/processing/cancelled)
 *   - Callback was provided (callback has already consumed the result)
 *
 * Thread-safe: Must be called with mutex locked
 *
 * Ownership semantics:
 * - If callback was provided during SocketDNS_resolve(), the callback receives
 *   ownership of the result and must call SocketCommon_free_addrinfo().
 * - If no callback was provided (polling mode), this function transfers
 *   ownership to the caller who must call SocketCommon_free_addrinfo().
 * - After successful transfer, the request is removed from the hash table
 *   and the request handle becomes invalid.
 */
static struct addrinfo *
transfer_result_ownership (struct SocketDNS_Request_T *req)
{
  struct addrinfo *result = NULL;

  if (req->state == REQ_COMPLETE)
    {
      /* If no callback, transfer ownership to caller; else callback consumed it
       */
      if (!req->callback)
        {
          result = req->result;
          req->result = NULL;
        }

      hash_table_remove (req->dns_resolver, req);
    }

  return result;
}

/**
 * init_completed_request_fields - Initialize fields for completed request
 * @req: Request structure to initialize (output)
 * @dns: DNS resolver instance (back-pointer stored in req)
 * @result: Address info result (ownership transferred, copied then freed)
 * @port: Port number
 *
 * Raises: SocketDNS_Failed on allocation failure
 * Thread-safe: Must be called with mutex locked
 *
 * Copies the addrinfo result and frees the original using
 * SocketCommon_free_addrinfo() since callers pass memory allocated via
 * SocketCommon_copy_addrinfo(), not raw getaddrinfo(). The request is marked
 * as complete and ready for retrieval.
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
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "Failed to copy address info");
    }
  SocketCommon_free_addrinfo (result);
  req->error = 0;
  req->queue_next = NULL;
  req->hash_next = NULL;
  clock_gettime (CLOCK_MONOTONIC, &req->submit_time);
  req->timeout_override_ms = -1;
}

/*
 * =============================================================================
 * Public API - Lifecycle
 * =============================================================================
 */

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

  d = *dns;

  shutdown_workers (d);
  drain_completion_pipe (d);
  reset_dns_state (d);
  destroy_dns_resources (d);
  *dns = NULL;
}

/*
 * =============================================================================
 * Public API - Resolution
 * =============================================================================
 */

/**
 * validate_dns_instance - Validate DNS resolver instance is not NULL
 * @dns: DNS resolver instance to validate (read-only check)
 *
 * Raises: SocketDNS_Failed if dns is NULL
 * Thread-safe: Yes - no shared state modified
 */
static void
validate_dns_instance (const struct SocketDNS_T *dns)
{
  if (!dns)
    {
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "Invalid NULL dns resolver");
    }
}

/**
 * check_queue_capacity - Check if queue has capacity for new request
 * @dns: DNS resolver instance
 *
 * Raises: SocketDNS_Failed if queue is full
 * Thread-safe: Yes - acquires and releases mutex internally
 *
 * Security: Must be called BEFORE allocating request memory to prevent
 * arena memory leak if queue is full (arena memory cannot be individually
 * freed, only disposed as a whole).
 */
static void
check_queue_capacity (struct SocketDNS_T *dns)
{
  pthread_mutex_lock (&dns->mutex);

  if (check_queue_limit (dns))
    {
      size_t max_pending = dns->max_pending;
      pthread_mutex_unlock (&dns->mutex);
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "DNS request queue full (max %zu pending)", max_pending);
    }

  pthread_mutex_unlock (&dns->mutex);
}

/**
 * prepare_resolve_request - Prepare and allocate DNS resolution request
 * @dns: DNS resolver instance
 * @host: Hostname to resolve (may be NULL for wildcard)
 * @port: Port number
 * @callback: Completion callback
 * @data: User data for callback
 * Returns: Allocated and initialized request
 * Raises: SocketDNS_Failed on validation or allocation failure
 *
 * Note: Queue capacity should be checked BEFORE calling this function
 * to avoid memory leak from arena allocation on queue-full condition.
 */
static Request_T
prepare_resolve_request (struct SocketDNS_T *dns, const char *host, int port,
                         SocketDNS_Callback callback, void *data)
{
  size_t host_len = host ? strlen (host) : 0;
  validate_resolve_params (host, port);
  return allocate_request (dns, host, host_len, port, callback, data);
}

/**
 * submit_resolve_request - Submit request to queue under mutex protection
 * @dns: DNS resolver instance
 * @req: Request to submit
 *
 * Thread-safe: Yes - acquires and releases mutex internally
 *
 * Note: Queue capacity must have been checked before allocation.
 * There's a small race window where queue could fill between check
 * and submit, but this only happens under extreme load and results
 * in slightly exceeding max_pending (bounded by concurrent callers).
 */
static void
submit_resolve_request (struct SocketDNS_T *dns, Request_T req)
{
  pthread_mutex_lock (&dns->mutex);
  submit_dns_request (dns, req);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_SUBMITTED, 1);
  pthread_mutex_unlock (&dns->mutex);
}

Request_T
SocketDNS_resolve (struct SocketDNS_T *dns, const char *host, int port,
                   SocketDNS_Callback callback, void *data)
{
  validate_dns_instance (dns);

  /* Check queue capacity BEFORE allocation to prevent arena memory leak.
   * If queue is full, we raise exception without allocating. */
  check_queue_capacity (dns);

  Request_T req = prepare_resolve_request (dns, host, port, callback, data);
  submit_resolve_request (dns, req);
  return req;
}

void
SocketDNS_cancel (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  int send_signal = 0;
  int cancelled = 0;

  if (!dns || !req)
    return;

  pthread_mutex_lock (&dns->mutex);

  if (!validate_request_ownership_locked (dns, req))
    {
      pthread_mutex_unlock (&dns->mutex);
      return;
    }

  handle_cancel_by_state (dns, req, &send_signal, &cancelled);

  if (send_signal)
    SIGNAL_DNS_COMPLETION (dns);

  hash_table_remove (dns, req);

  if (cancelled)
    SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_CANCELLED, 1);

  pthread_mutex_unlock (&dns->mutex);
}

/*
 * =============================================================================
 * Public API - Accessors
 * =============================================================================
 */

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
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "Invalid NULL dns resolver");
    }

  pthread_mutex_lock (&dns->mutex);
  queue_depth = dns->queue_size;
  if (max_pending < queue_depth)
    {
      pthread_mutex_unlock (&dns->mutex);
      SOCKET_RAISE_MSG (
          SocketDNS, SocketDNS_Failed,
          "Cannot set max pending (%zu) below current queue depth (%zu)",
          max_pending, queue_depth);
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

/**
 * SocketDNS_check - Drain completion signals from pipe (non-blocking)
 * @dns: DNS resolver instance
 *
 * Returns: Number of completion signal bytes drained from pipe
 *
 * Thread-safe: Yes - safe to call from any thread
 *
 * This function drains the completion signal pipe without blocking. Each byte
 * in the pipe represents one completed, cancelled, or timed-out request.
 * The return value indicates how many such events occurred since the last
 * call to SocketDNS_check().
 *
 * Usage pattern for poll-mode (no callback):
 *   1. Add SocketDNS_pollfd(dns) to your SocketPoll with POLL_READ
 *   2. When poll returns readable, call SocketDNS_check(dns) to drain signals
 *   3. Call SocketDNS_getresult(dns, req) for each tracked request handle
 *      to retrieve completed results
 *
 * Note: This function does NOT automatically retrieve results. You must
 * track your Request_T handles and call SocketDNS_getresult() separately.
 *
 * Error handling: On pipe read errors (other than EAGAIN/EWOULDBLOCK),
 * returns the count drained so far without raising an exception.
 */
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

  if (!validate_request_ownership_locked (dns, req))
    {
      pthread_mutex_unlock (&dns->mutex);
      return NULL;
    }

  result = transfer_result_ownership (req);
  pthread_mutex_unlock (&dns->mutex);

  return result;
}

int
SocketDNS_geterror (struct SocketDNS_T *dns,
                    const struct SocketDNS_Request_T *req)
{
  int error = 0;

  if (!dns || !req)
    return 0;

  pthread_mutex_lock (&dns->mutex);

  if (!validate_request_ownership_locked (dns, req))
    {
      pthread_mutex_unlock (&dns->mutex);
      return 0;
    }

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
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "Invalid NULL dns or result in create_completed_request");
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

  if (!validate_request_ownership_locked (dns, req))
    {
      pthread_mutex_unlock (&dns->mutex);
      return;
    }

  if (req->state == REQ_PENDING || req->state == REQ_PROCESSING)
    req->timeout_override_ms = SANITIZE_TIMEOUT_MS (timeout_ms);
  pthread_mutex_unlock (&dns->mutex);
}

/*
 * =============================================================================
 * Public API - Synchronous Resolution with Timeout
 * =============================================================================
 */

/**
 * compute_deadline - Calculate absolute deadline for pthread_cond_timedwait
 * @timeout_ms: Timeout in milliseconds
 * @deadline: Output timespec structure
 *
 * Uses CLOCK_REALTIME as required by pthread_cond_timedwait.
 */
static void
compute_deadline (int timeout_ms, struct timespec *deadline)
{
  clock_gettime (CLOCK_REALTIME, deadline);
  deadline->tv_sec += timeout_ms / SOCKET_MS_PER_SECOND;
  deadline->tv_nsec += (timeout_ms % SOCKET_MS_PER_SECOND) * (SOCKET_NS_PER_SECOND / SOCKET_MS_PER_SECOND);

  /* Normalize nanoseconds (handle overflow from ms->ns conversion) */
  if (deadline->tv_nsec >= SOCKET_NS_PER_SECOND)
    {
      deadline->tv_sec++;
      deadline->tv_nsec -= SOCKET_NS_PER_SECOND;
    }
}

/**
 * wait_for_completion - Wait for request completion with timeout
 * @dns: DNS resolver instance (mutex must be held on entry, held on exit)
 * @req: Request to wait for
 * @timeout_ms: Timeout in milliseconds (0 = no timeout)
 *
 * Returns: 0 on completion, ETIMEDOUT on timeout
 */
static int
wait_for_completion (struct SocketDNS_T *dns,
                     const struct SocketDNS_Request_T *req, int timeout_ms)
{
  struct timespec deadline;

  if (timeout_ms > 0)
    compute_deadline (timeout_ms, &deadline);

  while (req->state != REQ_COMPLETE && req->state != REQ_CANCELLED)
    {
      if (timeout_ms > 0)
        {
          int rc = pthread_cond_timedwait (&dns->result_cond, &dns->mutex,
                                           &deadline);
          if (rc == ETIMEDOUT)
            return ETIMEDOUT;
        }
      else
        {
          pthread_cond_wait (&dns->result_cond, &dns->mutex);
        }
    }

  return 0;
}

/**
 * setup_hints_for_fast_path - Setup addrinfo hints for fast-path resolution
 * @local_hints: Output hints structure
 * @hints: User-provided hints (may be NULL)
 * @host: Host string (NULL for wildcard)
 *
 * Initializes hints for getaddrinfo fast-path (IP address or wildcard).
 * For NULL host, sets AI_PASSIVE for bind. For IP, sets AI_NUMERICHOST.
 */
/* setup_hints_for_fast_path removed: logic now in SocketCommon_resolve_address */

/**
 * resolve_fast_path - Resolve IP address or wildcard without async DNS
 * @host: IP address string or NULL for wildcard
 * @port: Port number
 * @hints: User-provided hints (may be NULL)
 *
 * Returns: Copied addrinfo result (caller must free with
 * SocketCommon_free_addrinfo) Raises: SocketDNS_Failed on resolution or copy
 * failure
 *
 * Fast path for IP addresses and wildcard that bypasses async DNS.
 * Uses AI_NUMERICHOST or AI_PASSIVE to skip DNS lookup.
 */
/* resolve_fast_path removed: replaced with SocketCommon_resolve_address call for code reuse */

/**
 * handle_sync_timeout - Handle timeout during synchronous resolution
 * @dns: DNS resolver instance (mutex must be held)
 * @req: Request that timed out
 * @timeout_ms: Timeout value for error message
 * @host: Hostname for error message
 *
 * Raises: SocketDNS_Failed (always)
 *
 * Cancels the request and raises timeout exception. Unlocks mutex before raise.
 */
static void
handle_sync_timeout (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req,
                     int timeout_ms, const char *host)
{
  req->state = REQ_CANCELLED;
  req->error = EAI_AGAIN;
  hash_table_remove (dns, req);
  pthread_mutex_unlock (&dns->mutex);

  SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                    "DNS resolution timed out after %d ms: %s", timeout_ms,
                    host ? host : "(wildcard)");
}

/**
 * handle_sync_error - Handle error during synchronous resolution
 * @dns: DNS resolver instance (mutex must be held)
 * @req: Request that failed
 * @error: Error code from getaddrinfo
 * @host: Hostname for error message
 *
 * Raises: SocketDNS_Failed (always)
 *
 * Removes request from hash table and raises error. Unlocks mutex before raise.
 */
static void
handle_sync_error (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req,
                   int error, const char *host)
{
  hash_table_remove (dns, req);
  pthread_mutex_unlock (&dns->mutex);

  SOCKET_RAISE_FMT (SocketDNS, SocketDNS_Failed, "DNS resolution failed: %s (%s)",
                    host ? host : "(wildcard)", gai_strerror (error));
}

/**
 * resolve_async_with_wait - Submit async request and wait for completion
 * @dns: DNS resolver instance
 * @host: Hostname to resolve
 * @port: Port number
 * @timeout_ms: Effective timeout in milliseconds
 *
 * Returns: Resolved addrinfo (caller must free with SocketCommon_free_addrinfo)
 * Raises: SocketDNS_Failed on timeout or resolution error
 *
 * Submits async request and blocks until completion or timeout.
 */
static struct addrinfo *
resolve_async_with_wait (struct SocketDNS_T *dns, const char *host, int port,
                         int timeout_ms)
{
  struct addrinfo *result;
  Request_T req;
  int error;

  req = SocketDNS_resolve (dns, host, port, NULL, NULL);

  if (timeout_ms > 0)
    SocketDNS_request_settimeout (dns, req, timeout_ms);

  pthread_mutex_lock (&dns->mutex);

  if (wait_for_completion (dns, req, timeout_ms) == ETIMEDOUT)
    handle_sync_timeout (dns, req, timeout_ms, host);

  error = req->error;
  if (error != 0)
    handle_sync_error (dns, req, error, host);

  result = req->result;
  req->result = NULL;
  hash_table_remove (dns, req);
  pthread_mutex_unlock (&dns->mutex);

  return result;
}

struct addrinfo *
SocketDNS_resolve_sync (struct SocketDNS_T *dns, const char *host, int port,
                        const struct addrinfo *hints, int timeout_ms)
{
  int effective_timeout;

  if (!dns)
    {
      SOCKET_RAISE_MSG (SocketDNS, SocketDNS_Failed,
                        "SocketDNS_resolve_sync requires non-NULL dns resolver");
    }

  effective_timeout = (timeout_ms > 0) ? timeout_ms : dns->request_timeout_ms;

  /* Fast path: IP addresses and wildcard use SocketCommon synchronous resolution */
  if (host == NULL || socketcommon_is_ip_address (host))
    {
      struct addrinfo *tmp_res = NULL;
      int family = hints ? hints->ai_family : AF_UNSPEC;
      SocketCommon_resolve_address (host, port, hints, &tmp_res, SocketDNS_Failed, family, 1);
      struct addrinfo *result = SocketCommon_copy_addrinfo (tmp_res);
      SocketCommon_free_addrinfo (tmp_res);
      return result;
    }

  /* Hostname requires async resolution with timeout */
  return resolve_async_with_wait (dns, host, port, effective_timeout);
}

#undef T
#undef Request_T
