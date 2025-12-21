/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDNS.c
 * @ingroup dns
 * @brief Asynchronous DNS resolution implementation.
 *
 * Public API implementation for the DNS resolver module.
 * Contains validation functions, resolver lifecycle management,
 * and async resolution coordination.
 *
 * @see SocketDNS-internal.c for internal implementation details.
 * @see SocketDNS.h for public API declarations.
 * @see SocketDNS-private.h for internal structures.
 */

/* System headers first */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

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
 * @brief Validate ownership and return early if invalid.
 * @param dns Resolver (must have mutex locked).
 * @param req Request to validate.
 * @param retval Return value if validation fails.
 *
 * Consolidates the common pattern of validating ownership, unlocking,
 * and returning on failure. Must be called with mutex already locked.
 */
#define VALIDATE_OWNERSHIP_OR_RETURN(dns, req, retval)                        \
  do                                                                          \
    {                                                                         \
      if (!validate_request_ownership_locked ((dns), (req)))                  \
        {                                                                     \
          pthread_mutex_unlock (&(dns)->mutex);                               \
          return retval;                                                      \
        }                                                                     \
    }                                                                         \
  while (0)

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
  req->submit_time_ms = Socket_get_monotonic_ms ();
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
  struct addrinfo *tmp_res;
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
  VALIDATE_OWNERSHIP_OR_RETURN (dns, req, );

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
  if (!dns)
    return 0;

  return DNS_LOCKED_SIZE_GETTER (dns, max_pending);
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
  if (!dns)
    return 0;

  return DNS_LOCKED_INT_GETTER (dns, request_timeout_ms);
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

  DNS_LOCKED_INT_SETTER (dns, request_timeout_ms,
                         SANITIZE_TIMEOUT_MS (timeout_ms));
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
  VALIDATE_OWNERSHIP_OR_RETURN (dns, req, NULL);

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
  VALIDATE_OWNERSHIP_OR_RETURN (dns, req, 0);

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
  VALIDATE_OWNERSHIP_OR_RETURN (dns, req, );

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
 * Security: Uses CLOCK_MONOTONIC to prevent timing attacks via system clock
 * manipulation. The result_cond is initialized with CLOCK_MONOTONIC attribute.
 */
static void
compute_deadline (int timeout_ms, struct timespec *deadline)
{
  clock_gettime (CLOCK_MONOTONIC, deadline);
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

/* ============================================================================
 * DNS Cache Functions
 * ============================================================================
 */

/**
 * cache_hash_function - Compute hash for hostname
 * @hostname: Hostname string to hash
 *
 * Returns: Hash value for cache lookup
 * Thread-safe: Yes - pure function
 */
static unsigned
cache_hash_function (const char *hostname)
{
  return socket_util_hash_djb2_ci (hostname, SOCKET_DNS_CACHE_HASH_SIZE);
}

/**
 * cache_entry_expired - Check if cache entry has exceeded TTL
 * @dns: DNS resolver instance
 * @entry: Cache entry to check
 *
 * Returns: 1 if expired, 0 if still valid
 * Thread-safe: Yes - read-only
 */
static int
cache_entry_expired (const struct SocketDNS_T *dns,
                     const struct SocketDNS_CacheEntry *entry)
{
  int64_t now_ms;
  int64_t age_ms;

  if (dns->cache_ttl_seconds <= 0)
    return 0; /* TTL disabled, never expire */

  now_ms = Socket_get_monotonic_ms ();
  age_ms = now_ms - entry->insert_time_ms;

  return age_ms >= (int64_t)dns->cache_ttl_seconds * 1000;
}

/**
 * cache_lru_remove - Remove entry from LRU list
 * @dns: DNS resolver instance
 * @entry: Entry to remove
 *
 * Thread-safe: Must hold mutex
 */
static void
cache_lru_remove (struct SocketDNS_T *dns, struct SocketDNS_CacheEntry *entry)
{
  if (entry->lru_prev)
    entry->lru_prev->lru_next = entry->lru_next;
  else
    dns->cache_lru_head = entry->lru_next;

  if (entry->lru_next)
    entry->lru_next->lru_prev = entry->lru_prev;
  else
    dns->cache_lru_tail = entry->lru_prev;

  entry->lru_prev = NULL;
  entry->lru_next = NULL;
}

/**
 * cache_lru_insert_front - Insert entry at front of LRU list (most recent)
 * @dns: DNS resolver instance
 * @entry: Entry to insert
 *
 * Thread-safe: Must hold mutex
 */
static void
cache_lru_insert_front (struct SocketDNS_T *dns,
                        struct SocketDNS_CacheEntry *entry)
{
  entry->lru_prev = NULL;
  entry->lru_next = dns->cache_lru_head;

  if (dns->cache_lru_head)
    dns->cache_lru_head->lru_prev = entry;
  else
    dns->cache_lru_tail = entry;

  dns->cache_lru_head = entry;
}

/**
 * cache_entry_free - Free a single cache entry
 * @entry: Entry to free (including addrinfo)
 *
 * Thread-safe: Must hold mutex
 */
static void
cache_entry_free (struct SocketDNS_CacheEntry *entry)
{
  if (entry)
    {
      if (entry->result)
        SocketCommon_free_addrinfo (entry->result);
      /* hostname is arena-allocated, no free needed */
      /* entry itself is arena-allocated, no free needed */
    }
}

/**
 * cache_hash_remove - Remove entry from hash table
 * @dns: DNS resolver instance
 * @entry: Entry to remove
 *
 * Thread-safe: Must hold mutex
 */
static void
cache_hash_remove (struct SocketDNS_T *dns, struct SocketDNS_CacheEntry *entry)
{
  unsigned hash = cache_hash_function (entry->hostname);
  struct SocketDNS_CacheEntry **pp = &dns->cache_hash[hash];

  while (*pp)
    {
      if (*pp == entry)
        {
          *pp = entry->hash_next;
          return;
        }
      pp = &(*pp)->hash_next;
    }
}

/**
 * cache_evict_oldest - Evict the oldest (LRU tail) entry
 * @dns: DNS resolver instance
 *
 * Thread-safe: Must hold mutex
 */
static void
cache_evict_oldest (struct SocketDNS_T *dns)
{
  struct SocketDNS_CacheEntry *oldest = dns->cache_lru_tail;

  if (!oldest)
    return;

  cache_lru_remove (dns, oldest);
  cache_hash_remove (dns, oldest);
  cache_entry_free (oldest);
  dns->cache_size--;
  dns->cache_evictions++;
}

/**
 * cache_lookup - Look up hostname in cache
 * @dns: DNS resolver instance
 * @hostname: Hostname to find
 *
 * Returns: Cache entry or NULL if not found/expired
 * Thread-safe: Must hold mutex
 * Note: Updates LRU order on hit
 */
static struct SocketDNS_CacheEntry *
cache_lookup (struct SocketDNS_T *dns, const char *hostname)
{
  unsigned hash;
  struct SocketDNS_CacheEntry *entry;

  if (dns->cache_max_entries == 0)
    return NULL; /* Cache disabled */

  hash = cache_hash_function (hostname);
  entry = dns->cache_hash[hash];

  while (entry)
    {
      if (strcasecmp (entry->hostname, hostname) == 0)
        {
          /* Check TTL */
          if (cache_entry_expired (dns, entry))
            {
              /* Expired - remove and return miss */
              cache_lru_remove (dns, entry);
              cache_hash_remove (dns, entry);
              cache_entry_free (entry);
              dns->cache_size--;
              dns->cache_evictions++;
              return NULL;
            }

          /* Hit - update LRU and access time */
          entry->last_access_ms = Socket_get_monotonic_ms ();
          cache_lru_remove (dns, entry);
          cache_lru_insert_front (dns, entry);
          dns->cache_hits++;
          return entry;
        }
      entry = entry->hash_next;
    }

  dns->cache_misses++;
  return NULL;
}

/**
 * cache_allocate_entry - Allocate and initialize cache entry structure
 * @dns: DNS resolver instance
 * @hostname: Hostname key to copy
 * @result: addrinfo to copy (ownership retained by caller)
 *
 * Returns: Initialized entry or NULL on allocation failure
 * Thread-safe: Must hold mutex (for arena access)
 */
static struct SocketDNS_CacheEntry *
cache_allocate_entry (struct SocketDNS_T *dns, const char *hostname,
                      struct addrinfo *result)
{
  struct SocketDNS_CacheEntry *entry;
  int64_t now_ms;

  entry = ALLOC (dns->arena, sizeof (*entry));
  if (!entry)
    return NULL;

  entry->hostname = socket_util_arena_strdup (dns->arena, hostname);
  if (!entry->hostname)
    return NULL;

  entry->result = SocketCommon_copy_addrinfo (result);
  if (!entry->result)
    return NULL;

  now_ms = Socket_get_monotonic_ms ();
  entry->insert_time_ms = now_ms;
  entry->last_access_ms = now_ms;
  entry->hash_next = NULL;
  entry->lru_prev = NULL;
  entry->lru_next = NULL;

  return entry;
}

/**
 * cache_insert - Insert result into cache
 * @dns: DNS resolver instance
 * @hostname: Hostname key
 * @result: addrinfo to cache (copied)
 *
 * Thread-safe: Must hold mutex
 */
static void
cache_insert (struct SocketDNS_T *dns, const char *hostname,
              struct addrinfo *result)
{
  struct SocketDNS_CacheEntry *entry;
  unsigned hash;

  if (dns->cache_max_entries == 0 || !result)
    return;

  while (dns->cache_size >= dns->cache_max_entries)
    cache_evict_oldest (dns);

  entry = cache_allocate_entry (dns, hostname, result);
  if (!entry)
    return;

  hash = cache_hash_function (hostname);
  entry->hash_next = dns->cache_hash[hash];
  dns->cache_hash[hash] = entry;

  cache_lru_insert_front (dns, entry);

  dns->cache_size++;
  dns->cache_insertions++;
}

/**
 * SocketDNS_cache_clear - Clear the entire DNS cache
 * @dns: DNS resolver instance
 *
 * Thread-safe: Yes
 */
void
SocketDNS_cache_clear (T dns)
{
  size_t i;

  assert (dns);

  pthread_mutex_lock (&dns->mutex);

  /* Free all entries in hash table */
  for (i = 0; i < SOCKET_DNS_CACHE_HASH_SIZE; i++)
    {
      struct SocketDNS_CacheEntry *entry = dns->cache_hash[i];
      while (entry)
        {
          struct SocketDNS_CacheEntry *next = entry->hash_next;
          cache_entry_free (entry);
          entry = next;
        }
      dns->cache_hash[i] = NULL;
    }

  dns->cache_lru_head = NULL;
  dns->cache_lru_tail = NULL;
  dns->cache_size = 0;

  pthread_mutex_unlock (&dns->mutex);
}

/**
 * SocketDNS_cache_remove - Remove specific hostname from cache
 * @dns: DNS resolver instance
 * @hostname: Hostname to remove
 *
 * Returns: 1 if found and removed, 0 if not found
 * Thread-safe: Yes
 */
int
SocketDNS_cache_remove (T dns, const char *hostname)
{
  unsigned hash;
  struct SocketDNS_CacheEntry *entry;
  struct SocketDNS_CacheEntry **pp;
  int found = 0;

  assert (dns);
  assert (hostname);

  pthread_mutex_lock (&dns->mutex);

  hash = cache_hash_function (hostname);
  pp = &dns->cache_hash[hash];

  while (*pp)
    {
      entry = *pp;
      if (strcasecmp (entry->hostname, hostname) == 0)
        {
          *pp = entry->hash_next;
          cache_lru_remove (dns, entry);
          cache_entry_free (entry);
          dns->cache_size--;
          found = 1;
          break;
        }
      pp = &entry->hash_next;
    }

  pthread_mutex_unlock (&dns->mutex);
  return found;
}

/**
 * SocketDNS_cache_set_ttl - Set cache TTL
 * @dns: DNS resolver instance
 * @ttl_seconds: TTL in seconds (0 disables expiry)
 *
 * Thread-safe: Yes
 */
void
SocketDNS_cache_set_ttl (T dns, int ttl_seconds)
{
  assert (dns);

  pthread_mutex_lock (&dns->mutex);
  dns->cache_ttl_seconds = ttl_seconds >= 0 ? ttl_seconds : 0;
  pthread_mutex_unlock (&dns->mutex);
}

/**
 * SocketDNS_cache_set_max_entries - Set maximum cache entries
 * @dns: DNS resolver instance
 * @max_entries: Maximum entries (0 disables caching)
 *
 * Thread-safe: Yes
 */
void
SocketDNS_cache_set_max_entries (T dns, size_t max_entries)
{
  assert (dns);

  pthread_mutex_lock (&dns->mutex);

  dns->cache_max_entries = max_entries;

  /* Evict if now over limit */
  while (dns->cache_size > max_entries && max_entries > 0)
    cache_evict_oldest (dns);

  /* If disabled, clear everything */
  if (max_entries == 0 && dns->cache_size > 0)
    {
      pthread_mutex_unlock (&dns->mutex);
      SocketDNS_cache_clear (dns);
      return;
    }

  pthread_mutex_unlock (&dns->mutex);
}

/**
 * SocketDNS_cache_stats - Get cache statistics
 * @dns: DNS resolver instance
 * @stats: Output statistics structure
 *
 * Thread-safe: Yes
 */
void
SocketDNS_cache_stats (T dns, SocketDNS_CacheStats *stats)
{
  uint64_t total;

  assert (dns);
  assert (stats);

  pthread_mutex_lock (&dns->mutex);

  stats->hits = dns->cache_hits;
  stats->misses = dns->cache_misses;
  stats->evictions = dns->cache_evictions;
  stats->insertions = dns->cache_insertions;
  stats->current_size = dns->cache_size;
  stats->max_entries = dns->cache_max_entries;
  stats->ttl_seconds = dns->cache_ttl_seconds;

  total = stats->hits + stats->misses;
  stats->hit_rate = (total > 0) ? (double)stats->hits / (double)total : 0.0;

  pthread_mutex_unlock (&dns->mutex);
}

/* ============================================================================
 * DNS Configuration Functions
 * ============================================================================
 */

/**
 * SocketDNS_prefer_ipv6 - Set IPv6 preference
 * @dns: DNS resolver instance
 * @prefer_ipv6: 1 to prefer IPv6, 0 to prefer IPv4
 *
 * Thread-safe: Yes
 */
void
SocketDNS_prefer_ipv6 (T dns, int prefer_ipv6)
{
  assert (dns);

  DNS_LOCKED_INT_SETTER (dns, prefer_ipv6, prefer_ipv6 ? 1 : 0);
}

/**
 * SocketDNS_get_prefer_ipv6 - Get IPv6 preference
 * @dns: DNS resolver instance
 *
 * Returns: 1 if IPv6 preferred, 0 if IPv4 preferred
 * Thread-safe: Yes
 */
int
SocketDNS_get_prefer_ipv6 (T dns)
{
  assert (dns);

  return DNS_LOCKED_INT_GETTER (dns, prefer_ipv6);
}

/**
 * @brief Validate IP address format (IPv4 or IPv6).
 * @param ip IP address string to validate.
 * @return 1 if valid IPv4 or IPv6, 0 if invalid.
 *
 * Security: Uses inet_pton() which is safe and properly validates
 * IP address format without buffer overflow risks.
 */
static int
validate_ip_address (const char *ip)
{
  struct in_addr addr4;
  struct in6_addr addr6;

  if (!ip || !*ip)
    return 0;

  /* Try IPv4 first (more common) */
  if (inet_pton (AF_INET, ip, &addr4) == 1)
    return 1;

  /* Try IPv6 */
  if (inet_pton (AF_INET6, ip, &addr6) == 1)
    return 1;

  return 0;
}

/**
 * @brief Copy string array to arena-allocated storage (helper).
 * @param dns DNS resolver instance.
 * @param src Source string array.
 * @param count Number of strings.
 * @param dest_array Pointer to destination array pointer.
 * @param dest_count Pointer to destination count.
 * @return 0 on success, -1 on allocation failure.
 * @threadsafe Must be called with mutex locked.
 * @internal
 */
static int
copy_string_array_to_arena (struct SocketDNS_T *dns, const char **src,
                            size_t count, char ***dest_array,
                            size_t *dest_count)
{
  size_t i;

  *dest_array = ALLOC (dns->arena, count * sizeof (char *));
  if (!*dest_array)
    return -1;

  for (i = 0; i < count; i++)
    {
      size_t len = strlen (src[i]);
      (*dest_array)[i] = ALLOC (dns->arena, len + 1);
      if (!(*dest_array)[i])
        {
          *dest_array = NULL;
          *dest_count = 0;
          return -1;
        }
      memcpy ((*dest_array)[i], src[i], len + 1);
    }

  *dest_count = count;
  return 0;
}

/**
 * SocketDNS_set_nameservers - Set custom nameservers
 * @dns: DNS resolver instance
 * @servers: Array of nameserver IP addresses (IPv4 or IPv6)
 * @count: Number of servers
 *
 * Returns: 0 on success, -1 if not supported or invalid IP
 * Thread-safe: Yes
 *
 * Security: Validates all IP addresses before storing to prevent
 * injection attacks and ensure only valid IPs reach the resolver.
 *
 * Note: Custom nameservers require platform-specific support.
 * On Linux, this modifies the per-thread resolver state.
 */
int
SocketDNS_set_nameservers (T dns, const char **servers, size_t count)
{
  int result;
  size_t i;

  assert (dns);

  /* Validate all IP addresses before acquiring lock */
  if (servers != NULL && count > 0)
    {
      for (i = 0; i < count; i++)
        {
          if (!validate_ip_address (servers[i]))
            {
              SOCKET_LOG_WARN_MSG ("Invalid nameserver IP address: %s",
                                   servers[i] ? servers[i] : "(null)");
              return -1;
            }
        }
    }

  pthread_mutex_lock (&dns->mutex);

  /* Clear existing custom nameservers (arena-allocated, just NULL ptr) */
  dns->custom_nameservers = NULL;
  dns->nameserver_count = 0;

  if (servers == NULL || count == 0)
    {
      pthread_mutex_unlock (&dns->mutex);
      return 0;
    }

  result = copy_string_array_to_arena (dns, servers, count,
                                       &dns->custom_nameservers,
                                       &dns->nameserver_count);
  pthread_mutex_unlock (&dns->mutex);

  if (result < 0)
    return -1;

  /* Note: Actually using custom nameservers requires platform-specific
   * resolver configuration (e.g., res_init() on Linux). Since getaddrinfo()
   * doesn't support this directly, we store the config but don't apply it.
   * Future: Could implement with res_query() or a custom DNS client. */

#ifdef __linux__
  return 0; /* Successfully configured - will be applied in worker threads */
#else
  SOCKET_LOG_WARN_MSG (
      "Custom nameservers configured but not applied (platform limitation)");
  return -1;
#endif
}

/**
 * SocketDNS_set_search_domains - Set custom search domains
 * @dns: DNS resolver instance
 * @domains: Array of search domain strings
 * @count: Number of domains
 *
 * Returns: 0 on success, -1 if not supported
 * Thread-safe: Yes
 */
int
SocketDNS_set_search_domains (T dns, const char **domains, size_t count)
{
  int result;

  assert (dns);

  pthread_mutex_lock (&dns->mutex);

  /* Clear existing search domains (arena-allocated, just NULL ptr) */
  dns->search_domains = NULL;
  dns->search_domain_count = 0;

  if (domains == NULL || count == 0)
    {
      pthread_mutex_unlock (&dns->mutex);
      return 0;
    }

  result = copy_string_array_to_arena (dns, domains, count,
                                       &dns->search_domains,
                                       &dns->search_domain_count);
  pthread_mutex_unlock (&dns->mutex);

  if (result < 0)
    return -1;

  /* Search domains are stored but not applied. On Linux, the res_state->dnsrch
   * array contains pointers into the defdname buffer, making it non-trivial
   * to set custom search domains. Only nameservers are currently supported. */
  SOCKET_LOG_WARN_MSG (
      "Custom search domains configured but not applied (platform limitation)");
  return -1;
}

#undef T
#undef Request_T
