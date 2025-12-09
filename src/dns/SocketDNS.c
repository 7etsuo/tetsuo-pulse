/**
 * @file SocketDNS.c
 * @ingroup core_io
 * @brief Asynchronous DNS resolution implementation.
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

/**
 * @brief Global exception type for SocketDNS failures.
 * @ingroup core_io
 * @var SocketDNS_Failed
 *
 * Shared constant exception for all SocketDNS operations. Used in RAISE macros.
 * Thread-shared safe as immutable.
 *
 * @see Except_T base type.
 * @see SOCKET_RAISE_MODULE macros for usage.
 * @see docs/ERROR_HANDLING.md exception patterns.
 */
const Except_T SocketDNS_Failed
    = { &SocketDNS_Failed, "SocketDNS operation failed" };

/**
 * @brief Thread-local exception for detailed SocketDNS error messages.
 * @internal
 *
 * SOCKET_DECLARE_MODULE_EXCEPTION defines static __thread SocketDNS_DetailedException for SOCKET_RAISE_MSG/FMT.
 * Per-.c file due to static linkage; thread-local for concurrent safety.
 *
 * @see SOCKET_RAISE_MSG and SOCKET_RAISE_FMT for formatted raises.
 * @see docs/ERROR_HANDLING.md for module exception pattern.
 * @see core/Except.h base exception handling.
 */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketDNS);

/*
 * =============================================================================
 * Validation Functions
 * =============================================================================
 */

/**
 * @brief Validate hostname and port parameters for DNS resolution.
 * @param host Hostname or NULL (for wildcard/AI_PASSIVE).
 * @param port Port number.
 * @throws SocketDNS_Failed on invalid hostname or port.
 * @internal
 *
 * Uses SocketCommon validators for IP/hostname/port. NULL host ok for bind.
 *
 * @see SocketCommon_validate_hostname()
 * @see SocketCommon_validate_port()
 * @see socketcommon_is_ip_address() for fast-path decision.
 * @see SocketDNS_resolve() public validation entry.
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
 * @brief Validate request ownership (belongs to this resolver).
 * @param dns Resolver.
 * @param req Request.
 * @return 1 valid, 0 invalid.
 * @threadsafe Must call with mutex locked.
 * @internal
 *
 * Security: Prevents cross-resolver corruption via back-pointer check.
 *
 * @see hash_table_remove() for removal after validation.
 * @see SocketDNS_getresult() public ownership check.
 */
static int
validate_request_ownership_locked (const struct SocketDNS_T *dns,
                                   const struct SocketDNS_Request_T *req)
{
  return req->dns_resolver == dns;
}

/**
 * @brief Cancel pending queued request (remove from queue).
 * @param dns Resolver.
 * @param req Pending request.
 * @threadsafe Must with mutex locked.
 * @internal
 *
 * Removes from queue, sets REQ_CANCELLED, error=EAI_CANCELED.
 *
 * @see cancel_pending_request() helper.
 * @see handle_cancel_by_state() dispatcher.
 * @see SocketDNS_cancel() public entry.
 */
static void
cancel_pending_state (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  cancel_pending_request (dns, req);
  req->error = dns_cancellation_error ();
}

/**
 * @brief Mark in-progress request as cancelled (worker discards result).
 * @param dns Resolver (unused, consistency).
 * @param req Processing request.
 * @threadsafe Must with mutex locked.
 * @internal
 *
 * Sets REQ_CANCELLED, error=EAI_CANCELED. Worker checks post-resolve, discards.
 *
 * @see handle_cancel_by_state() state dispatcher.
 * @see SocketDNS_cancel() public.
 * @see worker_thread() for detect/discards.
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
 * @brief Handle cancellation of already-completed request.
 * @param req Completed request (modified).
 * @threadsafe Must with mutex locked.
 * @internal
 *
 * Frees result if no callback (polling owns). Callback mode: assumes callback freed. Sets error=EAI_CANCELED.
 *
 * @see transfer_result_ownership() for polling ownership.
 * @see SocketDNS_Callback for callback responsibility.
 * @see handle_cancel_by_state() dispatcher.
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
 * @brief Dispatch cancellation logic by request state.
 * @param dns Resolver.
 * @param req Request.
 * @param[out] send_signal 1 if need signal completion.
 * @param[out] cancelled 1 if metrics increment.
 * @threadsafe Must with mutex locked.
 * @internal
 *
 * Calls state-specific handlers (pending/processing/complete). Sets outputs for signal/metrics.
 *
 * @see cancel_pending_state() etc. for state handlers.
 * @see SocketDNS_cancel() public dispatcher.
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
 * @brief Transfer result ownership from request to caller (polling mode).
 * @param req Request (result cleared on transfer).
 * @return addrinfo (ownership transferred) or NULL (incomplete/callback/invalid).
 * @threadsafe Must with mutex locked.
 * @internal
 *
 * For polling: transfers if complete/no-callback, removes from hash. Callback mode: NULL (already consumed).
 *
 * Semantics:
 * - Callback mode: Callback owns (must free).
 * - Polling: Caller owns post-transfer (free SocketCommon_free_addrinfo).
 * - Post-success: Req invalid, removed from table.
 *
 * @see SocketDNS_getresult() public wrapper.
 * @see SocketCommon_free_addrinfo() required cleanup.
 * @see SocketDNS_Callback ownership in callback.
 * @see docs/MEMORY_MANAGEMENT.md ownership transfer patterns.
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
 * @brief Initialize completed request fields (copy result, set state).
 * @param req Request to init.
 * @param dns Owning resolver (back-pointer).
 * @param result addrinfo (transferred; copied to arena, original freed).
 * @param port Port.
 * @throws SocketDNS_Failed on copy/allocation fail.
 * @threadsafe Must with mutex locked.
 * @internal
 *
 * Copies result via SocketCommon_copy_addrinfo to arena, frees input, sets REQ_COMPLETE, error=0, timestamps.
 * Ready for hash insert/retrieval.
 *
 * @see SocketCommon_copy_addrinfo() copy impl.
 * @see SocketCommon_free_addrinfo() free input.
 * @see SocketDNS_create_completed_request() caller.
 * @see docs/MEMORY_MANAGEMENT.md arena copy patterns.
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
 * @brief Create new DNS resolver instance.
 * @ingroup core_io
 * @return New DNS resolver instance.
 * @throws SocketDNS_Failed on memory allocation, mutex init, pipe creation, or worker thread startup failure.
 * @threadsafe Yes - each resolver instance is independent.
 *
 * Allocates and initializes a new SocketDNS_T instance with default configuration:
 * - num_workers = SOCKET_DNS_DEFAULT_NUM_WORKERS (typically CPU cores)
 * - max_pending = SOCKET_DNS_MAX_PENDING (typically 1000)
 * - request_timeout_ms = SOCKET_DNS_DEFAULT_TIMEOUT_MS (typically 5000ms)
 *
 * The resolver creates a thread pool for async getaddrinfo() calls and sets up internal synchronization primitives (mutex, conditions, completion pipe).
 *
 * Usage:
 *   SocketDNS_T *dns = SocketDNS_new();
 *   // Use dns for resolutions...
 *   SocketDNS_free(&dns);
 *
 * @see SocketDNS_free() for cleanup.
 * @see SocketDNS_resolve() for submitting resolution requests.
 * @see SocketDNS_setmaxpending() and SocketDNS_settimeout() for configuration.
 * @see docs/ASYNC_IO.md for thread pool and async patterns.
 * @see SocketCommon.h for address resolution utilities used internally.
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
 * @brief Destroy DNS resolver instance and free all resources.
 * @ingroup core_io
 * @param dns Pointer to DNS resolver instance (set to NULL on success).
 * @throws None - safe to call on NULL or already-freed instance.
 * @threadsafe Conditional - concurrent use with active resolutions may race (requests may complete after free if not waited for).
 *
 * Shuts down worker threads, cancels pending requests, drains completion pipe, and frees all allocated resources (arena, mutex, conditions, pipe, threads).
 *
 * All pending and in-progress requests are cancelled with EAI_CANCELED error. Completed requests remain retrievable until SocketDNS_getresult() is called.
 *
 * Note: After free, all Request_T handles become invalid. Applications must cancel or retrieve results before freeing to avoid leaks and undefined behavior.
 *
 * @see SocketDNS_new() for creation.
 * @see SocketDNS_cancel() for cancelling individual requests.
 * @see SocketDNS_getresult() to retrieve pending results before free.
 * @see docs/MEMORY_MANAGEMENT.md for arena cleanup patterns.
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
 * @brief Validate DNS resolver instance (non-NULL check).
 * @param dns Resolver to validate.
 * @throws SocketDNS_Failed if NULL.
 * @threadsafe Yes - read-only, no shared state.
 * @internal
 *
 * Simple null check with raise for public API guards.
 *
 * @see validate_resolve_params() for param validation.
 * @see SocketDNS_new() entry point.
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
 * @brief Check queue capacity before request allocation.
 * @param dns Resolver instance.
 * @throws SocketDNS_Failed if queue full (max_pending reached).
 * @threadsafe Yes - internal mutex.
 * @internal
 *
 * Pre-allocation check to avoid arena leak on full queue (arena dispose-only).
 * Security: Prevents memory exhaustion DoS by limiting pending.
 *
 * @see SocketDNS_setmaxpending() for limit config.
 * @see prepare_resolve_request() next step on success.
 * @see docs/SECURITY.md queue limits.
 * @see docs/MEMORY_MANAGEMENT.md arena semantics.
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
/**
 * @brief Allocate and prepare new resolution request.
 * @param dns Resolver.
 * @param host Host string.
 * @param port Port.
 * @param callback Callback or NULL.
 * @param data User data.
 * @return Initialized Request_T.
 * @throws SocketDNS_Failed on validation or alloc fail.
 * @internal
 *
 * Validates params, allocs structure, copies host, inits fields.
 *
 * @see validate_resolve_params() validation.
 * @see allocate_request() allocator.
 * @see submit_resolve_request() next for queue/hash.
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
 * @brief Submit asynchronous DNS resolution request to thread pool.
 * @ingroup core_io
 * @param dns DNS resolver instance.
 * @param host Hostname or IP address to resolve (NULL for wildcard bind with AI_PASSIVE flag).
 * @param port Port number (0-65535; 0 means no service resolution).
 * @param callback Completion callback (NULL for polling mode).
 * @param data User data passed to callback (ignored if no callback).
 * @return Request handle for tracking completion (valid until result retrieved or cancelled).
 * @throws SocketDNS_Failed if queue full (max_pending exceeded) or invalid parameters.
 * @threadsafe Yes - internal mutex protects queue and hash table.
 *
 * Submits a DNS resolution request. For IP addresses or NULL host, may use fast-path synchronous resolution but returns Request_T handle.
 *
 * Validation:
 * - Hostname per RFC 1123 (labels alphanumeric + hyphen/dot).
 * - Supports IPv4/IPv6 addresses.
 * - Port 0-65535 (0 for address-only lookup).
 *
 * Callback Mode: Invoked from worker thread on completion. Must be thread-safe; see SocketDNS_Callback for details.
 * Polling Mode: Use SocketDNS_pollfd(), SocketDNS_check(), SocketDNS_getresult().
 *
 * Additional control:
 * - SocketDNS_cancel() to abort before completion.
 * - SocketDNS_request_settimeout() for per-request timeout after submit.
 *
 * Error codes (getaddrinfo()):
 * - 0: Success
 * - EAI_AGAIN: Temporary (retryable)
 * - EAI_NONAME: Not found (permanent)
 * - EAI_FAIL: Non-recoverable
 * - EAI_SYSTEM: System error
 * - EAI_CANCELED: User cancellation (custom)
 *
 * @see SocketDNS_Callback for callback safety requirements.
 * @see SocketDNS_getresult() for retrieving results in polling mode.
 * @see SocketDNS_cancel() for request cancellation.
 * @see SocketDNS_request_settimeout() for timeouts.
 * @see SocketCommon_resolve_address() for underlying resolution (internal).
 * @see docs/SECURITY.md for DoS protection via queue limits.
 * @see docs/ERROR_HANDLING.md for retryable error patterns.
 * @see docs/ASYNC_IO.md for worker thread considerations.
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
 * @brief Cancel pending or in-progress DNS resolution request.
 * @ingroup core_io
 * @param dns DNS resolver instance.
 * @param req Request handle to cancel.
 * @throws None - safe to call on NULL or invalid handles.
 * @threadsafe Yes - acquires mutex for state update and signalling.
 *
 * Cancels the specified request. Completed requests marked cancelled but results remain retrievable. Already-cancelled ignored.
 *
 * State-specific behavior:
 * - REQ_PENDING: Removed from queue, never processed.
 * - REQ_PROCESSING: Marked cancelled; worker discards result post-getaddrinfo().
 * - REQ_COMPLETE: Result preserved (polling) or consumed (callback).
 * - REQ_CANCELLED: No-op.
 *
 * Sends completion signal to wake waiters, increments cancellation metric. Handle invalid after retrieval/free; check SocketDNS_geterror().
 *
 * Note: Best-effort for processing (may complete post-cancel). Guarantee: cancel before submit. Cancelled return EAI_CANCELED.
 *
 * @see SocketDNS_resolve() for request submission.
 * @see SocketDNS_geterror() for cancellation error code.
 * @see SocketDNS_getresult() for results post-cancel.
 * @see docs/ASYNC_IO.md for cancellation in async systems.
 * @see SocketError_is_retryable_errno() for error categorization.
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
 * @brief Get maximum pending requests limit (queue capacity).
 * @ingroup core_io
 * @param dns DNS resolver instance.
 * @return Current max_pending value; 0 if dns NULL or disabled.
 * @throws None.
 * @threadsafe Yes - atomic read under mutex.
 *
 * @see SocketDNS_setmaxpending() to update limit.
 * @see SocketDNS_resolve() for queue submission (fails if full).
 * @see docs/SECURITY.md for DoS protection via limits.
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
 * @brief Set maximum pending requests limit (queue capacity).
 * @ingroup core_io
 * @param dns DNS resolver instance.
 * @param max_pending New queue capacity limit (0 disables limit).
 * @throws SocketDNS_Failed if new limit < current queue depth.
 * @threadsafe Yes - updates under mutex.
 *
 * Updates queue capacity. Cannot reduce below current queue_size to avoid premature rejection of new requests. New limit effective immediately for SocketDNS_resolve().
 *
 * Note: Setting to 0 removes limit (caution: risk memory exhaustion). Default: SOCKET_DNS_MAX_PENDING (typically 1000).
 *
 * @see SocketDNS_getmaxpending() for querying current limit.
 * @see SocketDNS_resolve() which fails if queue full.
 * @see docs/SECURITY.md for DoS protection tuning.
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
 * @brief Get default request timeout in milliseconds.
 * @ingroup core_io
 * @param dns DNS resolver instance.
 * @return Default timeout for new requests; 0 if NULL or disabled (infinite wait).
 * @throws None.
 * @threadsafe Yes - atomic read under mutex.
 *
 * Note: 0 = no timeout (infinite). Negative values sanitized to 0. Per-request overrides via SocketDNS_request_settimeout() take precedence.
 *
 * @see SocketDNS_settimeout() to set the default.
 * @see SocketDNS_request_settimeout() for per-request overrides.
 * @see SocketDNS_resolve_sync() uses this if timeout unspecified.
 * @see docs/TIMEOUTS.md for timeout best practices.
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
 * @brief Set default request timeout for future resolutions.
 * @ingroup core_io
 * @param dns DNS resolver instance.
 * @param timeout_ms New default timeout in ms (0=infinite; negative -> 0).
 * @throws None - safe on NULL dns.
 * @threadsafe Yes - updates under mutex.
 *
 * Updates default for new SocketDNS_resolve() calls. Existing requests and per-request overrides unaffected. Negative values sanitized to 0.
 *
 * Note: Affects new requests only. Use SocketDNS_request_settimeout() for existing. Default: SOCKET_DNS_DEFAULT_TIMEOUT_MS (~5000ms). SocketDNS_resolve_sync() uses this if timeout_ms <=0.
 *
 * @see SocketDNS_gettimeout() for current value.
 * @see SocketDNS_request_settimeout() for per-request overrides.
 * @see docs/TIMEOUTS.md for timeout configuration and best practices.
 * @see SocketDNS_resolve_sync() for synchronous usage.
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
 * @brief Get file descriptor for SocketPoll integration (completion signals).
 * @ingroup core_io
 * @param dns DNS resolver instance.
 * @return Read-end pipe FD (>=0); -1 if NULL dns or shutdown.
 * @throws None.
 * @threadsafe Yes - atomic read (no mutex).
 *
 * Returns completion pipe FD. Add to SocketPoll with POLL_READ to detect completed/cancelled requests.
 *
 * Usage:
 *   int dns_fd = SocketDNS_pollfd(dns);
 *   SocketPoll_add(poll, dns_fd, POLL_READ, userdata);
 *   // On event: SocketDNS_check(dns) to drain signals.
 *
 * Note: Compatible with edge-triggered polling. Always fully drain with SocketDNS_check() to prevent missed signals under high load. FD valid throughout resolver lifetime.
 *
 * @see SocketPoll_add() and SocketPoll_wait() for event loop usage.
 * @see SocketDNS_check() to process completions.
 * @see event_system group for I/O multiplexing.
 * @see docs/ASYNC_IO.md for non-blocking patterns.
 */
int
SocketDNS_pollfd (struct SocketDNS_T *dns)
{
  if (!dns)
    return -1;
  return dns->pipefd[0];
}

/**
 * @brief Drain completion signals from pipe non-blocking.
 * @ingroup core_io
 * @param dns DNS resolver instance.
 * @return Number of events drained (bytes; one per completed/cancelled/timeout request).
 * @throws None - partial count on pipe errors (except EAGAIN/EWOULDBLOCK).
 * @threadsafe Yes - safe from any thread.
 *
 * Drains signal pipe. Each byte = one event since last call. Call after SocketPoll on SocketDNS_pollfd().
 *
 * Poll-mode (no callback):
 * 1. SocketPoll_add(SocketDNS_pollfd(dns), POLL_READ).
 * 2. On readable: SocketDNS_check(dns).
 * 3. SocketDNS_getresult() for tracked requests.
 *
 * Note: No auto-result retrieval. Track Request_T and fetch separately. Errors return partial count, no exception.
 *
 * @see SocketDNS_pollfd() for poll FD.
 * @see SocketDNS_getresult() for result retrieval.
 * @see SocketPoll.h for event system.
 * @see docs/ASYNC_IO.md for poll-based completion handling.
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
 * @brief Retrieve completed resolution result, transferring ownership.
 * @ingroup core_io
 * @param dns DNS resolver instance.
 * @param req Request handle (must match this dns).
 * @return addrinfo (caller owns; free SocketCommon_free_addrinfo()) or NULL (incomplete, callback used, invalid, error).
 * @throws None.
 * @threadsafe Yes - under mutex.
 *
 * Retrieves if complete and polling mode (no callback). Transfers ownership; invalidates req.
 *
 * NULL cases:
 * - Pending/processing.
 * - Callback mode (callback owns).
 * - Invalid handle or wrong resolver.
 *
 * Always check SocketDNS_geterror() before use. Removes req from hash table on success.
 *
 * Note: Callback mode returns NULL (result to callback). 
 *
 * @see SocketCommon_free_addrinfo() for cleanup.
 * @see SocketDNS_geterror() to validate success.
 * @see SocketDNS_resolve() for mode selection (callback vs poll).
 * @see docs/ERROR_HANDLING.md for post-retrieval checks.
 * @see SocketDNS_Callback for callback ownership.
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
 * @brief Get error code for completed or cancelled request.
 * @ingroup core_io
 * @param dns DNS resolver instance.
 * @param req Request handle (must match dns).
 * @return getaddrinfo() error; 0 for success, invalid/NULL input, or incomplete.
 * @throws None.
 * @threadsafe Yes - read under mutex.
 *
 * For complete/cancelled requests only. 0 also for invalid input or pending (call after SocketDNS_check()/callback).
 *
 * Codes:
 * - 0: Success
 * - EAI_*: Standard (see <netdb.h>)
 * - EAI_CANCELED: User cancellation (custom)
 *
 * Usage: Always pair with SocketDNS_getresult() or in callback. Retries: SocketError_is_retryable_errno() or == EAI_AGAIN.
 *
 * @see SocketDNS_getresult() for result + error validation.
 * @see SocketError_is_retryable_errno() for retry decisions.
 * @see docs/ERROR_HANDLING.md for categorization and patterns.
 * @see <netdb.h> for full EAI_* definitions.
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
 * @brief Create pre-completed request from pre-resolved addrinfo (internal).
 * @ingroup core_io
 * @param dns DNS resolver instance.
 * @param result Pre-resolved addrinfo (ownership transferred; copied internally, original freed).
 * @param port Port number for request.
 * @return Request_T in REQ_COMPLETE state.
 * @throws SocketDNS_Failed on allocation or copy failure.
 * @threadsafe Yes - under mutex insert and signal.
 *
 * Internal API for fast-path (e.g., IP sync resolution) or tests. Copies result to arena, marks complete, signals completion via pipe/cond.
 *
 * Note: Applications use SocketDNS_resolve() or SocketDNS_resolve_sync(). Caller transfers ownership of result (func copies and frees input).
 * Increments SOCKET_METRIC_DNS_REQUEST_COMPLETED, sends signal.
 *
 * @internal
 * @see SocketDNS_resolve_sync() fast-path user.
 * @see SocketDNS_getresult() for retrieval.
 * @see SocketCommon_copy_addrinfo() for internal copy.
 * @see test_socketdns.c for test usage.
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
 * @brief Set per-request timeout override (pending/processing only).
 * @ingroup core_io
 * @param dns DNS resolver instance.
 * @param req Request handle.
 * @param timeout_ms Override ms (-1=default, 0=infinite, negative->0).
 * @throws None - no-op on invalid state/input.
 * @threadsafe Yes - under mutex.
 *
 * Overrides resolver default. Affects only pending/processing (no-op complete/cancelled). Negative reset to default, sanitized.
 *
 * Note: Call after SocketDNS_resolve(), before complete. Workers enforce with CLOCK_MONOTONIC. Useful for SLA-varying requests.
 *
 * @see SocketDNS_settimeout() for resolver-wide default.
 * @see SocketDNS_gettimeout() to query default.
 * @see request_timed_out() internal check logic.
 * @see docs/TIMEOUTS.md for timeout strategies and precision.
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
 * @brief Perform synchronous DNS resolution with timeout guarantee.
 * @ingroup core_io
 * @param dns DNS resolver (required).
 * @param host Hostname or IP (NULL for wildcard bind).
 * @param port Port number.
 * @param hints getaddrinfo hints (NULL for defaults).
 * @param timeout_ms Max wait ms (0=default, <=0=resolver default).
 * @return addrinfo result (free with SocketCommon_free_addrinfo).
 * @throws SocketDNS_Failed on failure, timeout, or invalid input.
 * @threadsafe Yes - blocks caller until done or timeout.
 *
 * Blocks for resolution. Fast-path IPs/wildcard: direct getaddrinfo (no threads). Hostnames: internal async + wait.
 *
 * Timeout: >0 ? param : dns default. Both 0 = infinite (avoid prod).
 *
 * Hints: Standard family/socktype/protocol/flags. Auto-sets AI_NUMERICHOST/AI_PASSIVE for fast-path.
 *
 * Validation: Same as SocketDNS_resolve (RFC 1123 host, port 0-65535).
 * Errors: Post-raise, use SocketError_categorize_errno details.
 *
 * Convenience for sync API with block protection. Non-block: SocketDNS_resolve + poll/callback.
 *
 * @see SocketCommon_free_addrinfo() for result cleanup.
 * @see SocketDNS_resolve() async alternative.
 * @see docs/TIMEOUTS.md sync/async tradeoffs.
 * @see docs/ERROR_HANDLING.md failure analysis.
 * @see <netdb.h> for hints and EAI errors.
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
