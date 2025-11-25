/**
 * SocketDNS-request.c - Request allocation and queue management for async DNS
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Contains DNS request lifecycle management and queue operations.
 * Validation functions are in SocketDNS-validate.c.
 */

/* All includes before T macro definition to avoid redefinition warnings */
#include <stdint.h>
#include <string.h>

#include "core/Arena.h"
#include "dns/SocketDNS.h"
#include "dns/SocketDNS-private.h"

/* Redefine T after all includes (Arena.h and SocketDNS.h both undef T at end) */
#undef T
#define T SocketDNS_T
#undef Request_T
#define Request_T SocketDNS_Request_T

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketDNS-request"

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

  memcpy (req->host, host, host_len);
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
 * Returns: 1 if queue is full, 0 otherwise
 * Thread-safe: Must be called with mutex locked
 * Note: Does NOT unlock mutex - caller is responsible for cleanup
 */
int
check_queue_limit (struct SocketDNS_T *dns)
{
  return dns->queue_size >= dns->max_pending;
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
