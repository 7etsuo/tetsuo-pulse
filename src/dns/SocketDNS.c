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
 * before we define our module's T. SocketDNS-private.h forward-declares
 * Arena_T but doesn't include Arena.h to avoid T macro conflicts in other
 * contexts. */
#include "core/Arena.h"
#include "dns/SocketDNS-private.h"
#include "dns/SocketDNS.h"
#include "socket/SocketCommon-private.h"

/* Define our module's T macro (Arena.h undefs T at end of header) */
#undef T /* Defensive: ensure clean slate */
#define T SocketDNS_T

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
cancel_pending_state (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
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
handle_cancel_by_state (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req, int *send_signal,
                        int *cancelled)
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
      /* If no callback, transfer ownership to caller; else callback consumed
       * it
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

/* Forward declarations for synchronous resolution helpers */
static int wait_for_completion (struct SocketDNS_T *dns,
                                const struct SocketDNS_Request_T *req,
                                int timeout_ms);

static void handle_sync_timeout (struct SocketDNS_T *dns,
                                 struct SocketDNS_Request_T *req,
                                 int timeout_ms, const char *host);

static void handle_sync_error (struct SocketDNS_T *dns,
                               struct SocketDNS_Request_T *req, int error,
                               const char *host);

/**
 * @brief Fast-path synchronous resolution for IP addresses and wildcard binds.
 *
 * Performs direct getaddrinfo() call without involving the thread pool for
 * cases where resolution can be done synchronously and immediately (IP
 * addresses or NULL host for wildcard binding with AI_PASSIVE flag).
 *
 * @param host Hostname or IP address string (NULL for wildcard/AI_PASSIVE)
 * @port Port number to associate with addresses
 * @param hints getaddrinfo() hints structure (may be NULL for defaults)
 *
 * @return Newly allocated addrinfo linked list (caller must free with
 *         SocketCommon_free_addrinfo())
 * @throws SocketDNS_Failed on resolution failure, memory allocation error, or
 *         invalid parameters (via SocketCommon_resolve_address)
 *
 * @threadsafe Yes - no shared state modified
 *
 * @see SocketCommon_resolve_address() for underlying resolution logic
 * @see SocketCommon_copy_addrinfo() for result duplication to transfer
 * ownership
 * @see SocketDNS_resolve_sync() for full synchronous API usage
 */
static struct addrinfo *
dns_sync_fast_path (const char *host, int port, const struct addrinfo *hints)
{
  struct addrinfo *tmp_res = NULL;
  int family = hints ? hints->ai_family : AF_UNSPEC;

  SocketCommon_resolve_address (host, port, hints, &tmp_res, SocketDNS_Failed,
                                family, 1);

  struct addrinfo *result = SocketCommon_copy_addrinfo (tmp_res);
  SocketCommon_free_addrinfo (tmp_res);

  return result;
}

/**
 * @brief Wait for async request completion and retrieve result under mutex
 * protection.
 *
 * Internal helper for synchronous resolution wrapper. Locks mutex, waits for
 * completion or timeout, handles timeout/error cases by raising exceptions,
 * transfers result ownership, removes request from hash table, and unlocks.
 *
 * @param dns DNS resolver instance
 * @param req Request handle to wait for
 * @param timeout_ms Timeout in milliseconds (0 = infinite wait)
 * @param host Hostname for error messages (may be NULL)
 *
 * @return Resolved addrinfo (ownership transferred, caller must free)
 * @throws SocketDNS_Failed on timeout or resolution error (unlocks before
 * raise)
 *
 * @threadsafe Yes - acquires/releases mutex internally
 *
 * @note Called immediately after SocketDNS_resolve() in sync wrapper path.
 * @note Uses wait_for_completion(), handle_sync_timeout(),
 * handle_sync_error().
 */
static struct addrinfo *
wait_and_retrieve_result (struct SocketDNS_T *dns,
                          struct SocketDNS_Request_T *req, int timeout_ms,
                          const char *host)
{
  int error;
  struct addrinfo *result;

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

/*
 * =============================================================================
 * Public API - Lifecycle
 * =============================================================================
 */

/**
 * SocketDNS_new - Create new DNS resolver instance
 *
 * Allocates and initializes a new SocketDNS_T instance with default
 * configuration:
 * - num_workers = SOCKET_DNS_DEFAULT_NUM_WORKERS (typically CPU cores)
 * - max_pending = SOCKET_DNS_MAX_PENDING (typically 1000)
 * - request_timeout_ms = SOCKET_DNS_DEFAULT_TIMEOUT_MS (typically 5000ms)
 *
 * The resolver creates a thread pool for async getaddrinfo() calls and sets up
 * internal synchronization primitives (mutex, conditions, completion pipe).
 *
 * Returns: New DNS resolver instance, or raises SocketDNS_Failed on failure
 * Raises: SocketDNS_Failed on memory allocation, mutex init, pipe creation,
 *         or worker thread startup failure
 * Thread-safe: Yes - each resolver instance is independent
 *
 * Usage:
 *   SocketDNS_T *dns = SocketDNS_new();
 *   // Use dns for resolutions...
 *   SocketDNS_free(&dns);
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

/**
 * SocketDNS_free - Destroy DNS resolver instance
 * @dns: Pointer to DNS resolver pointer (set to NULL on success)
 *
 * Shuts down worker threads, cancels pending requests, drains completion pipe,
 * frees all allocated resources (arena, mutex, conditions, pipe, threads).
 *
 * All pending and in-progress requests are cancelled with EAI_CANCELED error.
 * Completed requests remain retrievable until SocketDNS_getresult() is called.
 *
 * Raises: None (safe to call on NULL or already-freed instance)
 * Thread-safe: Yes - but concurrent use with active resolutions may race
 *              (requests may complete after free if not waited for)
 *
 * Note: After free, all Request_T handles become invalid. Applications must
 *       cancel or retrieve results before freeing to avoid leaks.
 */
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
                        "DNS request queue full (max %zu pending)",
                        max_pending);
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

/**
 * SocketDNS_resolve - Submit asynchronous DNS resolution request
 * @dns: DNS resolver instance
 * @host: Hostname or IP address to resolve (NULL for wildcard/AI_PASSIVE)
 * @port: Port number for service name resolution (0-65535)
 * @callback: Completion callback (NULL for polling mode)
 * @data: User data passed to callback (ignored if no callback)
 *
 * Submits a DNS resolution request to the thread pool. If host is NULL or
 * valid IP, may use fast-path synchronous resolution internally but still
 * returns Request_T.
 *
 * Returns: Request handle for tracking completion (valid until result
 * retrieved) Raises: SocketDNS_Failed if queue full (max_pending exceeded) or
 * validation fails Thread-safe: Yes - protects internal queue and hash table
 * with mutex
 *
 * Validation:
 * - Hostname validated per RFC 1123 (alphanumeric, hyphen, dot-separated
 * labels)
 * - IP addresses supported (IPv4/IPv6)
 * - Port validated (1-65535, 0 allowed for unspecified)
 *
 * Callback Mode: If callback provided, invoked from worker thread on
 * completion. See SocketDNS_Callback doc for thread safety requirements.
 *
 * Polling Mode: If NULL callback, use SocketDNS_pollfd() + SocketDNS_check() +
 * SocketDNS_getresult(req) to retrieve results.
 *
 * Cancellation: Use SocketDNS_cancel() before completion to abort request.
 * Per-request timeout: SocketDNS_request_settimeout() after submit.
 *
 * Error Codes (from getaddrinfo()):
 * - 0: Success
 * - EAI_AGAIN: Temporary failure (retryable)
 * - EAI_NONAME: Host not found (permanent)
 * - EAI_FAIL: Non-recoverable failure
 * - EAI_SYSTEM: System error (errno details)
 */
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

/**
 * SocketDNS_cancel - Cancel pending or in-progress DNS request
 * @dns: DNS resolver instance
 * @req: Request handle to cancel
 *
 * Cancels the specified request if it is pending or processing. Completed
 * requests are marked as cancelled but results remain retrievable.
 * Already-cancelled requests are ignored.
 *
 * Cancellation semantics by state:
 * - REQ_PENDING: Removed from queue, never processed
 * - REQ_PROCESSING: Marked cancelled; worker discards result after
 * getaddrinfo()
 * - REQ_COMPLETE: Result preserved if polling mode; callback already consumed
 * if applicable
 * - REQ_CANCELLED: No-op
 *
 * Sends completion signal to wake waiters and increments cancellation metric.
 * Request handle becomes invalid after retrieval or free (use
 * SocketDNS_geterror).
 *
 * Raises: None (safe to call on NULL or invalid handles)
 * Thread-safe: Yes - acquires mutex for state update and signalling
 *
 * Note: Cancellation is best-effort for processing requests (worker may
 * complete shortly after cancel call). For guaranteed non-processing, call
 * before submit. Cancelled requests return EAI_CANCELED error code.
 */
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

/**
 * SocketDNS_getmaxpending - Get maximum pending requests limit
 * @dns: DNS resolver instance
 *
 * Returns current max_pending value (queue capacity limit).
 * Returns 0 if dns is NULL.
 *
 * Thread-safe: Yes - atomic read under mutex
 * Raises: None
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

/**
 * SocketDNS_setmaxpending - Set maximum pending requests limit
 * @dns: DNS resolver instance
 * @max_pending: New queue capacity limit (0 = capacity 0 / queuing disabled)
 *
 * Updates the maximum number of pending requests the queue can hold.
 * Cannot reduce below current queue_size (would reject new requests
 * prematurely). New limit takes effect immediately for future
 * SocketDNS_resolve() calls.
 *
 * Raises: SocketDNS_Failed if new limit < current queue_size
 * Thread-safe: Yes - updates under mutex protection
 *
 * Note: Setting to 0 disables limit (use caution to avoid memory exhaustion).
 * Default: SOCKET_DNS_MAX_PENDING (typically 1000)
 */
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

/**
 * SocketDNS_gettimeout - Get default request timeout
 * @dns: DNS resolver instance
 *
 * Returns the default timeout in milliseconds for new requests.
 * Returns 0 if dns is NULL or timeout disabled (infinite wait).
 *
 * Thread-safe: Yes - atomic read under mutex
 * Raises: None
 *
 * Note: 0 means no timeout (wait indefinitely). Negative values are sanitized
 * to 0. Per-request overrides via SocketDNS_request_settimeout() take
 * precedence.
 */
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

/**
 * SocketDNS_settimeout - Set default request timeout
 * @dns: DNS resolver instance
 * @timeout_ms: New default timeout in milliseconds (0 = infinite)
 *
 * Updates the default timeout for future SocketDNS_resolve() calls.
 * Existing requests and per-request overrides are unaffected.
 * Negative values are sanitized to 0 (no timeout).
 *
 * Raises: None (safe to call on NULL dns)
 * Thread-safe: Yes - updates under mutex
 *
 * Note: Affects new requests only. Use SocketDNS_request_settimeout() for
 * existing requests. Default: SOCKET_DNS_DEFAULT_TIMEOUT_MS (typically
 * 5000ms). For sync resolution, uses this value if timeout_ms <= 0 in
 * SocketDNS_resolve_sync().
 */
void
SocketDNS_settimeout (struct SocketDNS_T *dns, int timeout_ms)
{
  if (!dns)
    return;

  pthread_mutex_lock (&dns->mutex);
  dns->request_timeout_ms = SANITIZE_TIMEOUT_MS (timeout_ms);
  pthread_mutex_unlock (&dns->mutex);
}

/**
 * SocketDNS_pollfd - Get file descriptor for poll integration
 * @dns: DNS resolver instance
 *
 * Returns the read-end file descriptor of the completion pipe.
 * Add this FD to SocketPoll with POLL_READ interest to detect completed
 * requests.
 *
 * Returns: Pipe FD (>=0) or -1 if dns NULL or pipe invalid (shutdown state)
 * Raises: None
 * Thread-safe: Yes - atomic read (no mutex needed)
 *
 * Usage:
 *   int dns_fd = SocketDNS_pollfd(dns);
 *   SocketPoll_add(poll, dns_fd, POLL_READ, dns_userdata);
 *   // When POLL_READ on dns_fd, call SocketDNS_check(dns) to process
 * completions
 *
 * Note: FD is edge-triggered compatible. Always drain fully with
 * SocketDNS_check() to avoid missed signals under high load.
 */
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

/**
 * SocketDNS_getresult - Retrieve completed resolution result
 * @dns: DNS resolver instance
 * @req: Request handle
 *
 * Retrieves the addrinfo result if request is complete and no callback was
 * used. Transfers ownership of result to caller (must free with
 * SocketCommon_free_addrinfo). Invalidates the request handle (subsequent
 * calls return NULL).
 *
 * Returns: addrinfo result (ownership transferred) or NULL if:
 *          - Request not complete (still pending/processing)
 *          - Callback used (callback owns result)
 *          - Invalid request or wrong resolver
 * Raises: None
 * Thread-safe: Yes - under mutex
 *
 * Note: For callback mode, result is passed to callback (this returns NULL).
 * Always check SocketDNS_geterror() for error details before using result.
 * After successful retrieval, request is removed from hash table.
 */
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

/**
 * SocketDNS_geterror - Get error code for completed or cancelled request
 * @dns: DNS resolver instance
 * @req: Request handle
 *
 * Returns the getaddrinfo() error code for completed or cancelled requests.
 * Returns 0 for:
 * - Successful resolutions
 * - Invalid/NULL inputs
 * - Incomplete requests (use after SocketDNS_check() or callback)
 *
 * Error codes:
 * - 0: Success
 * - EAI_*: Standard getaddrinfo() errors (see <netdb.h>)
 * - EAI_CANCELED: Custom code for user cancellation
 *
 * Raises: None
 * Thread-safe: Yes - read under mutex
 *
 * Usage: Always call after SocketDNS_getresult() or in callback to check
 * success. For retry decisions, use SocketError_is_retryable_errno(error) or
 * check EAI_AGAIN.
 */
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

/**
 * SocketDNS_create_completed_request - Create pre-completed request
 * (internal/testing)
 * @dns: DNS resolver instance
 * @result: Pre-resolved addrinfo (copied, original freed)
 * @port: Port number for request
 *
 * INTERNAL API: Creates a request in REQ_COMPLETE state with provided result.
 * Used by SocketDNS_resolve_sync fast-path and potentially unit tests.
 * Copies result into request arena and signals completion.
 *
 * Returns: Request handle in completed state
 * Raises: SocketDNS_Failed on allocation or copy failure
 * Thread-safe: Yes - inserts under mutex and signals
 *
 * Note: Primarily for internal use. Applications should use
 * SocketDNS_resolve() or SocketDNS_resolve_sync(). Result is copied; caller
 * does not retain ownership. Increments completion metric and sends pipe
 * signal.
 */
Request_T
SocketDNS_create_completed_request (struct SocketDNS_T *dns,
                                    struct addrinfo *result, int port)
{
  if (!dns || !result)
    {
      SOCKET_RAISE_MSG (
          SocketDNS, SocketDNS_Failed,
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

/**
 * SocketDNS_request_settimeout - Set per-request timeout override
 * @dns: DNS resolver instance
 * @req: Request handle (must be pending or processing)
 * @timeout_ms: Timeout in ms (-1 to reset to default, 0=infinite)
 *
 * Overrides the default timeout for a specific request. Only affects pending
 * or processing requests (no-op for completed/cancelled).
 * Negative values reset to resolver default; sanitized internally.
 *
 * Raises: None (silent no-op on invalid inputs or wrong state)
 * Thread-safe: Yes - under mutex
 *
 * Note: Call after SocketDNS_resolve() but before completion for effect.
 * Higher precision than resolver default; useful for varying latencies.
 * Timeout checked by workers using CLOCK_MONOTONIC for accuracy.
 */
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
  deadline->tv_nsec += (timeout_ms % SOCKET_MS_PER_SECOND)
                       * (SOCKET_NS_PER_SECOND / SOCKET_MS_PER_SECOND);

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
 * handle_sync_timeout - Handle timeout during synchronous resolution
 * @dns: DNS resolver instance (mutex must be held)
 * @req: Request that timed out
 * @timeout_ms: Timeout value for error message
 * @host: Hostname for error message
 *
 * Raises: SocketDNS_Failed (always)
 *
 * Cancels the request and raises timeout exception. Unlocks mutex before
 * raise.
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
 * Removes request from hash table and raises error. Unlocks mutex before
 * raise.
 */
static void
handle_sync_error (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req,
                   int error, const char *host)
{
  hash_table_remove (dns, req);
  pthread_mutex_unlock (&dns->mutex);

  SOCKET_RAISE_FMT (SocketDNS, SocketDNS_Failed,
                    "DNS resolution failed: %s (%s)",
                    host ? host : "(wildcard)", gai_strerror (error));
}

/**
 * resolve_async_with_wait - Submit async request and wait for completion
 * @dns: DNS resolver instance
 * @host: Hostname to resolve
 * @port: Port number
 * @timeout_ms: Effective timeout in milliseconds
 *
 * Returns: Resolved addrinfo (caller must free with
 * SocketCommon_free_addrinfo) Raises: SocketDNS_Failed on timeout or
 * resolution error
 *
 * Submits async request and blocks until completion or timeout.
 */
static struct addrinfo *
resolve_async_with_wait (struct SocketDNS_T *dns, const char *host, int port,
                         int timeout_ms)
{
  Request_T req;

  req = SocketDNS_resolve (dns, host, port, NULL, NULL);

  if (timeout_ms > 0)
    SocketDNS_request_settimeout (dns, req, timeout_ms);

  return wait_and_retrieve_result (dns, req, timeout_ms, host);
}

/**
 * SocketDNS_resolve_sync - Synchronous DNS resolution with timeout support
 * @dns: DNS resolver instance (required for sync mode)
 * @host: Hostname or IP (NULL=wildcard)
 * @port: Port number
 * @hints: getaddrinfo hints (may be NULL for defaults)
 * @timeout_ms: Max wait time (0=use default, <0=resolver default)
 *
 * Performs blocking DNS resolution with configurable timeout.
 * Fast-path for IPs/wildcard uses direct getaddrinfo (no threads).
 * Hostnames use async resolution under the hood with wait.
 *
 * Returns: addrinfo result (caller frees with SocketCommon_free_addrinfo)
 * Raises: SocketDNS_Failed on resolution failure, timeout, or invalid params
 * Thread-safe: Yes, but blocks calling thread until complete or timeout
 *
 * Timeout: Effective timeout = timeout_ms >0 ? timeout_ms :
 * dns->request_timeout_ms If both 0, waits indefinitely (avoid in production).
 *
 * Hints: Supports standard getaddrinfo hints (family, socktype, protocol,
 * flags). Fast-path automatically sets AI_NUMERICHOST/AI_PASSIVE as needed.
 *
 * Validation: Same as SocketDNS_resolve (hostname/port checks).
 * Error details available via SocketError_categorize_errno if needed
 * post-raise.
 *
 * Usage: Convenience wrapper for apps needing sync API with timeout
 * protection. For non-blocking, prefer SocketDNS_resolve + poll/callback.
 */
struct addrinfo *
SocketDNS_resolve_sync (struct SocketDNS_T *dns, const char *host, int port,
                        const struct addrinfo *hints, int timeout_ms)
{
  int effective_timeout;

  if (!dns)
    {
      SOCKET_RAISE_MSG (
          SocketDNS, SocketDNS_Failed,
          "SocketDNS_resolve_sync requires non-NULL dns resolver");
    }

  effective_timeout = (timeout_ms > 0) ? timeout_ms : dns->request_timeout_ms;

  /* Fast path: IP addresses and wildcard use direct synchronous resolution via
   * helper */
  if (host == NULL || socketcommon_is_ip_address (host))
    return dns_sync_fast_path (host, port, hints);

  /* Hostname requires async resolution with timeout */
  return resolve_async_with_wait (dns, host, port, effective_timeout);
}

#undef T
#undef Request_T
