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
 * Returns: true if valid (alphanumeric or hyphen)
 */
static bool
is_valid_label_char (char c)
{
  return isalnum ((unsigned char)c) || c == '-';
}

/**
 * is_valid_label_start - Check if character can start a label
 * @c: Character to check
 * Returns: true if valid label start (alphanumeric only)
 */
static bool
is_valid_label_start (char c)
{
  return isalnum ((unsigned char)c);
}

/**
 * check_label_bounds - Check label length is within bounds
 * @label_len: Current label length
 * Returns: true if within bounds
 */
static bool
check_label_bounds (int label_len)
{
  return label_len > 0 && label_len <= SOCKET_DNS_MAX_LABEL_LENGTH;
}

/**
 * validate_hostname_label - Validate hostname labels per RFC 1123
 * @label: Hostname string containing one or more dot-separated labels
 * @len: Output parameter for total validated length (can be NULL)
 *
 * Returns: 1 if all labels valid, 0 otherwise
 *
 * Thread-safe: Yes - no shared state modified
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
          if (!check_label_bounds (label_len))
            return 0;
          at_label_start = true;
          label_len = 0;
        }
      else
        {
          if (at_label_start && !is_valid_label_start (*p))
            return 0;
          if (!is_valid_label_char (*p))
            return 0;

          at_label_start = false;
          label_len++;
        }
      p++;
    }

  if (!check_label_bounds (label_len))
    return 0;

  if (len)
    *len = p - label;
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
 * @req: Request to cancel
 *
 * Thread-safe: Must be called with mutex locked
 *
 * Frees any stored result (ownership not yet transferred to caller)
 * and sets cancellation error code.
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
