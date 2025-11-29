/**
 * SocketDNS.c - Async DNS resolution public API
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Contains:
 * - Public API functions (new, free, resolve, cancel)
 * - Accessor functions (getters/setters for configuration)
 * - Validation functions (hostname, IP address, port validation)
 */

/* All includes must come before T macro definition to avoid conflicts */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include "core/Arena.h"
#include "dns/SocketDNS.h"
#include "dns/SocketDNS-private.h"

/* Undefine T from Arena.h, then define our module's T */
#undef T
#define T SocketDNS_T
#define Request_T SocketDNS_Request_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS"

/* SocketDNS module exception and thread-local detailed exception */
const Except_T SocketDNS_Failed
    = { &SocketDNS_Failed, "SocketDNS operation failed" };

#ifdef _WIN32
__declspec (thread) Except_T SocketDNS_DetailedException;
#else
__thread Except_T SocketDNS_DetailedException;
#endif

/*
 * =============================================================================
 * Validation Functions
 * =============================================================================
 */

/**
 * is_ip_address - Check if string is a valid IP address (IPv4 or IPv6)
 * @host: Host string to check
 * Returns: 1 if valid IP address, 0 otherwise
 */
bool
is_ip_address (const char *host)
{
  if (!host)
    return false;

  struct in_addr ipv4;
  struct in6_addr ipv6;

  return inet_pton (AF_INET, host, &ipv4) == 1
         || inet_pton (AF_INET6, host, &ipv6) == 1;
}

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
static bool
is_valid_label_char (char c, bool at_start)
{
  if (at_start)
    return isalnum ((unsigned char)c);
  return isalnum ((unsigned char)c) || c == '-';
}

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
static bool
is_valid_label_length (int label_len)
{
  /* RFC 1035: max label length is 63; min is 1 (empty labels invalid) */
  return label_len > 0 && label_len <= SOCKET_DNS_MAX_LABEL_LENGTH;
}

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
int
validate_hostname_label (const char *label, size_t *len)
{
  const char *p = label;
  int label_len = 0;
  bool at_label_start = true;

  while (*p)
    {
      if (*p == '.')
        {
          /* Dot separator - validate completed label and reset
           * Rejects consecutive dots (label_len=0) as empty labels per RFC 1035 */
          if (!is_valid_label_length (label_len))
            return 0;
          at_label_start = true;
          label_len = 0;
        }
      else
        {
          /* Label character - validate and update state */
          if (!is_valid_label_char (*p, at_label_start))
            return 0;
          at_label_start = false;
          label_len++;
        }
      p++;
    }

  /* Validate final label */
  if (!is_valid_label_length (label_len))
    return 0;

  if (len)
    *len = (size_t)(p - label);
  return 1;
}

/**
 * validate_hostname - Validate hostname format and constraints
 * @hostname: Hostname string to validate
 * Returns: 1 if valid hostname, 0 otherwise
 * Validates hostname length and calls validate_hostname_label for each label.
 */
int
validate_hostname (const char *hostname)
{
  if (!hostname)
    return 0;

  size_t len = strlen (hostname);
  if (len == 0 || len > SOCKET_ERROR_MAX_HOSTNAME)
    return 0;

  return validate_hostname_label (hostname, NULL);
}

/**
 * validate_resolve_params - Validate parameters for DNS resolution
 * @host: Hostname to validate (NULL allowed for wildcard bind)
 * @port: Port number to validate
 * Raises: SocketDNS_Failed on invalid parameters
 */
void
validate_resolve_params (const char *host, int port)
{
  /* Host validation - NULL is allowed for wildcard bind with AI_PASSIVE */
  if (host != NULL)
    {
      /* validate_hostname handles all length and format checks */
      if (!is_ip_address (host) && !validate_hostname (host))
        {
          SOCKET_ERROR_MSG ("Invalid hostname format");
          RAISE_DNS_ERROR (SocketDNS_Failed);
        }
    }

  if (!SOCKET_VALID_PORT (port))
    {
      SOCKET_ERROR_MSG ("Invalid port number");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
}

/*
 * =============================================================================
 * Static Helper Functions
 * =============================================================================
 */

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
 * Copies the addrinfo result and frees the original. The request is marked
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
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
  freeaddrinfo (result);
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
      SOCKET_ERROR_MSG ("Invalid NULL dns resolver");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
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
 * Raises: SocketDNS_Failed if queue is full
 *
 * Thread-safe: Yes - acquires and releases mutex internally
 */
static void
submit_resolve_request (struct SocketDNS_T *dns, Request_T req)
{
  pthread_mutex_lock (&dns->mutex);

  if (check_queue_limit (dns))
    {
      size_t max_pending = dns->max_pending;
      pthread_mutex_unlock (&dns->mutex);
      SOCKET_ERROR_MSG ("DNS request queue full (max %zu pending)", max_pending);
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  submit_dns_request (dns, req);
  SocketMetrics_increment (SOCKET_METRIC_DNS_REQUEST_SUBMITTED, 1);
  pthread_mutex_unlock (&dns->mutex);
}

Request_T
SocketDNS_resolve (struct SocketDNS_T *dns, const char *host, int port,
                   SocketDNS_Callback callback, void *data)
{
  validate_dns_instance (dns);
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
  deadline->tv_sec += timeout_ms / 1000;
  deadline->tv_nsec += (timeout_ms % 1000) * 1000000L;

  /* Normalize nanoseconds */
  if (deadline->tv_nsec >= 1000000000L)
    {
      deadline->tv_sec++;
      deadline->tv_nsec -= 1000000000L;
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

struct addrinfo *
SocketDNS_resolve_sync (struct SocketDNS_T *dns, const char *host, int port,
                        const struct addrinfo *hints, int timeout_ms)
{
  Request_T req;
  struct addrinfo *result = NULL;
  int error;
  int effective_timeout;

  /* Validate DNS resolver */
  if (!dns)
    {
      SOCKET_ERROR_MSG ("SocketDNS_resolve_sync requires non-NULL dns resolver");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  /* Use resolver default timeout if not specified */
  effective_timeout = (timeout_ms > 0) ? timeout_ms : dns->request_timeout_ms;

  /* Fast path: NULL host (wildcard) or IP addresses don't need DNS resolution */
  if (host == NULL || is_ip_address (host))
    {
      struct addrinfo local_hints;
      int gai_result;

      memset (&local_hints, 0, sizeof (local_hints));
      local_hints.ai_family = hints ? hints->ai_family : AF_UNSPEC;
      local_hints.ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
      local_hints.ai_protocol = hints ? hints->ai_protocol : 0;

      if (host == NULL)
        {
          /* Wildcard address - use AI_PASSIVE for bind */
          local_hints.ai_flags = AI_PASSIVE;
          if (hints)
            local_hints.ai_flags |= hints->ai_flags;
        }
      else
        {
          /* IP address - use AI_NUMERICHOST to skip DNS */
          local_hints.ai_flags = AI_NUMERICHOST;
          if (hints)
            local_hints.ai_flags |= (hints->ai_flags & ~AI_PASSIVE);
        }

      char port_str[16];
      snprintf (port_str, sizeof (port_str), "%d", port);

      gai_result = getaddrinfo (host, port_str, &local_hints, &result);
      if (gai_result != 0)
        {
          SOCKET_ERROR_MSG ("Failed to resolve address: %s (%s)",
                            host ? host : "(wildcard)",
                            gai_strerror (gai_result));
          RAISE_DNS_ERROR (SocketDNS_Failed);
        }

      /* Copy the result so all paths return consistently-allocated memory
       * that should be freed with SocketCommon_free_addrinfo() */
      struct addrinfo *copy = SocketCommon_copy_addrinfo (result);
      freeaddrinfo (result);

      if (!copy)
        {
          SOCKET_ERROR_MSG ("Failed to copy address info");
          RAISE_DNS_ERROR (SocketDNS_Failed);
        }

      return copy;
    }

  /* Submit async request (no callback = polling mode) */
  req = SocketDNS_resolve (dns, host, port, NULL, NULL);

  /* Set per-request timeout if specified */
  if (effective_timeout > 0)
    SocketDNS_request_settimeout (dns, req, effective_timeout);

  /* Wait for completion under mutex */
  pthread_mutex_lock (&dns->mutex);

  if (wait_for_completion (dns, req, effective_timeout) == ETIMEDOUT)
    {
      /* Cancel the timed-out request */
      req->state = REQ_CANCELLED;
      req->error = EAI_AGAIN;
      hash_table_remove (dns, req);
      pthread_mutex_unlock (&dns->mutex);

      SOCKET_ERROR_MSG ("DNS resolution timed out after %d ms: %s",
                        effective_timeout, host ? host : "(wildcard)");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  /* Check for errors */
  error = req->error;
  if (error != 0)
    {
      hash_table_remove (dns, req);
      pthread_mutex_unlock (&dns->mutex);

      SOCKET_ERROR_MSG ("DNS resolution failed: %s (%s)", host ? host : "(wildcard)",
                        gai_strerror (error));
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  /* Transfer ownership of result to caller */
  result = req->result;
  req->result = NULL;
  hash_table_remove (dns, req);

  pthread_mutex_unlock (&dns->mutex);

  return result;
}

#undef T
#undef Request_T
