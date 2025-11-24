/**
 * SocketDNS-request.c - Request allocation and queue management for async DNS resolution
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Contains DNS request lifecycle management, validation, and queue operations.
 */

#include "core/SocketConfig.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdint.h>
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
#define SOCKET_LOG_COMPONENT "SocketDNS-request"
#define T SocketDNS_T
#define Request_T SocketDNS_Request_T
#include "dns/SocketDNS-private.h"
#include "socket/SocketCommon.h"

/**
 * request_hash_function - Calculate hash for request pointer
 * @req: Request pointer to hash
 * Returns: Hash value in range [0, SOCKET_DNS_REQUEST_HASH_SIZE)
 * Uses golden ratio multiplicative hashing for good distribution.
 */
unsigned
request_hash_function (struct SocketDNS_Request_T *req)
{
  uintptr_t ptr = (uintptr_t)req;
  return ((unsigned)ptr * HASH_GOLDEN_RATIO) % SOCKET_DNS_REQUEST_HASH_SIZE;
}

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
 * validate_hostname_label - Validate a single hostname label
 * @label: Label string to validate
 * @len: Length of label (output)
 * Returns: 1 if valid label, 0 otherwise
 * Validates label characters, length, and format according to DNS rules.
 */
int
validate_hostname_label (const char *label, size_t *len)
{
  const char *p = label;
  int label_len = 0;
  bool new_label = true; /* Start of label */

  while (*p)
    {
      if (*p == '.')
        {
          if (new_label || label_len == 0
              || label_len > SOCKET_DNS_MAX_LABEL_LENGTH)
            return 0; /* Empty label or too long */
          new_label = true;
          label_len = 0;
        }
      else
        {
          if (new_label)
            {
              if (!isalnum ((unsigned char)*p))
                return 0; /* Label must start with alnum */
              new_label = false;
            }
          if (!isalnum ((unsigned char)*p) && *p != '-')
            return 0; /* Invalid char in label */
          if (*p == '-' && label_len == 0)
            return 0; /* Can't start label with - */
          label_len++;
          if (label_len > SOCKET_DNS_MAX_LABEL_LENGTH)
            return 0;
        }
      p++;
    }

  /* Final label check */
  if (new_label || label_len == 0 || label_len > SOCKET_DNS_MAX_LABEL_LENGTH)
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
  size_t host_len;

  if (host != NULL)
    {
      host_len = strlen (host);
      if (host_len == 0 || host_len > SOCKET_ERROR_MAX_HOSTNAME)
        {
          SOCKET_ERROR_MSG ("Invalid hostname length");
          RAISE_DNS_ERROR (SocketDNS_Failed);
        }

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

/**
 * allocate_request_structure - Allocate request structure
 * @dns: DNS resolver instance
 * Returns: Allocated request structure
 * Raises: SocketDNS_Failed on allocation failure
 * Allocates memory for the request structure from arena.
 */
Request_T
allocate_request_structure (struct SocketDNS_T *dns)
{
  Request_T req;

  req = ALLOC (dns->arena, sizeof (*req));
  if (!req)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate DNS request");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  return req;
}

/**
 * allocate_request_hostname - Allocate and copy hostname
 * @dns: DNS resolver instance
 * @req: Request structure to initialize
 * @host: Hostname to copy (NULL allowed for wildcard bind)
 * @host_len: Length of hostname (0 if host is NULL)
 * Raises: SocketDNS_Failed on allocation failure
 * Allocates memory for hostname and copies it. Sets req->host to NULL if host
 * is NULL.
 */
void
allocate_request_hostname (struct SocketDNS_T *dns,
                           struct SocketDNS_Request_T *req, const char *host,
                           size_t host_len)
{
  if (host == NULL)
    {
      req->host = NULL;
      return;
    }

  req->host = ALLOC (dns->arena, host_len + 1);
  if (!req->host)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate hostname");
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }

  strncpy (req->host, host, host_len + 1);
  req->host[host_len] = '\0';
}

/**
 * initialize_request_fields - Initialize request fields
 * @req: Request structure to initialize
 * @port: Port number
 * @callback: Completion callback
 * @data: User data for callback
 * Sets all request fields to initial values.
 */
void
initialize_request_fields (struct SocketDNS_Request_T *req, int port,
                           SocketDNS_Callback callback, void *data)
{
  req->port = port;
  req->callback = callback;
  req->callback_data = data;
  req->state = REQ_PENDING;
  req->result = NULL;
  req->error = 0;
  req->queue_next = NULL;
  req->hash_next = NULL;
  clock_gettime (CLOCK_MONOTONIC, &req->submit_time);
  req->timeout_override_ms = -1;
}

/**
 * allocate_request - Allocate and initialize request structure
 * @dns: DNS resolver instance
 * @host: Hostname to resolve
 * @host_len: Length of hostname
 * @port: Port number
 * @callback: Completion callback
 * @data: User data for callback
 * Returns: Allocated request structure
 * Raises: SocketDNS_Failed on allocation failure
 * Allocates and fully initializes a DNS request structure.
 */
Request_T
allocate_request (struct SocketDNS_T *dns, const char *host, size_t host_len,
                  int port, SocketDNS_Callback callback, void *data)
{
  Request_T req = allocate_request_structure (dns);
  allocate_request_hostname (dns, req, host, host_len);
  initialize_request_fields (req, port, callback, data);
  req->dns_resolver = dns;

  return req;
}

/**
 * hash_table_insert - Insert request into hash table
 * @dns: DNS resolver instance
 * @req: Request to insert
 * Thread-safe: Must be called with mutex locked
 */
void
hash_table_insert (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  unsigned hash;

  hash = request_hash_function (req);
  req->hash_value = hash;
  req->hash_next = dns->request_hash[hash];
  dns->request_hash[hash] = req;
}

/**
 * hash_table_remove - Remove request from hash table
 * @dns: DNS resolver instance
 * @req: Request to remove
 * Thread-safe: Must be called with mutex locked
 */
void
hash_table_remove (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  unsigned hash;
  Request_T *pp;

  hash = req->hash_value;
  pp = &dns->request_hash[hash];
  while (*pp)
    {
      if (*pp == req)
        {
          *pp = req->hash_next;
          break;
        }
      pp = &(*pp)->hash_next;
    }
}

/**
 * queue_append - Append request to queue
 * @dns: DNS resolver instance
 * @req: Request to append
 * Thread-safe: Must be called with mutex locked
 */
void
queue_append (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  if (dns->queue_tail)
    {
      dns->queue_tail->queue_next = req;
      dns->queue_tail = req;
    }
  else
    {
      dns->queue_head = req;
      dns->queue_tail = req;
    }
  dns->queue_size++;
}

/**
 * remove_from_queue_head - Remove request from queue head
 * @dns: DNS resolver instance
 * @req: Request to remove
 */
void
remove_from_queue_head (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req)
{
  dns->queue_head = req->queue_next;
  if (!dns->queue_head)
    dns->queue_tail = NULL;
}

/**
 * remove_from_queue_middle - Remove request from queue middle/tail
 * @dns: DNS resolver instance
 * @req: Request to remove
 */
void
remove_from_queue_middle (struct SocketDNS_T *dns,
                          struct SocketDNS_Request_T *req)
{
  Request_T prev = dns->queue_head;
  while (prev && prev->queue_next != req)
    prev = prev->queue_next;
  if (prev)
    {
      prev->queue_next = req->queue_next;
      if (dns->queue_tail == req)
        dns->queue_tail = prev;
    }
}

/**
 * queue_remove - Remove request from queue
 * @dns: DNS resolver instance
 * @req: Request to remove
 * Thread-safe: Must be called with mutex locked
 */
void
queue_remove (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  if (dns->queue_head == req)
    remove_from_queue_head (dns, req);
  else
    remove_from_queue_middle (dns, req);
  dns->queue_size--;
}

/**
 * check_queue_limit - Check if queue has reached limit
 * @dns: DNS resolver instance
 * Raises: SocketDNS_Failed if queue is full
 * Thread-safe: Must be called with mutex locked
 */
void
check_queue_limit (struct SocketDNS_T *dns)
{
  if (dns->queue_size >= dns->max_pending)
    {
      pthread_mutex_unlock (&dns->mutex);
      SOCKET_ERROR_MSG ("DNS request queue full (max %zu pending)",
                        dns->max_pending);
      RAISE_DNS_ERROR (SocketDNS_Failed);
    }
}

/**
 * submit_dns_request - Submit request to queue and hash table
 * @dns: DNS resolver instance
 * @req: Request to submit
 * Thread-safe: Must be called with mutex locked
 * Inserts request into hash table, appends to queue, and signals workers.
 */
void
submit_dns_request (struct SocketDNS_T *dns, struct SocketDNS_Request_T *req)
{
  hash_table_insert (dns, req);
  queue_append (dns, req);
  pthread_cond_signal (&dns->queue_cond);
}

/**
 * cancel_pending_request - Cancel a pending request
 * @dns: DNS resolver instance
 * @req: Request to cancel
 * Thread-safe: Must be called with mutex locked
 */
void
cancel_pending_request (struct SocketDNS_T *dns,
                        struct SocketDNS_Request_T *req)
{
  queue_remove (dns, req);
  req->state = REQ_CANCELLED;
}

#undef T
#undef Request_T
