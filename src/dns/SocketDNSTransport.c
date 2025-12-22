/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDNSTransport.c
 * @brief DNS UDP transport implementation (RFC 1035 Section 4.2.1).
 * @ingroup dns_transport
 *
 * Implements async UDP transport for DNS queries with retry and timeout
 * handling. Uses non-blocking sockets with poll() for event processing.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/SocketTimer.h"
#include "dns/SocketDNSTransport.h"
#include "dns/SocketDNSWire.h"
#include "socket/SocketDgram.h"

#undef T
#define T SocketDNSTransport_T

/* Internal query state */
struct SocketDNSQuery
{
  uint16_t id;                           /* DNS message ID */
  unsigned char query[DNS_UDP_MAX_SIZE]; /* Query copy */
  size_t query_len;                      /* Query length */
  int current_ns;                        /* Current nameserver index */
  int retry_count;                       /* Number of retries */
  int timeout_ms;                        /* Current timeout (backoff) */
  int64_t sent_time_ms;                  /* Timestamp when sent */
  int cancelled;                         /* Cancelled flag */
  int completed;                         /* Completed flag */
  SocketDNSTransport_Callback callback;  /* User callback */
  void *userdata;                        /* User data */
  struct SocketDNSQuery *next;           /* Linked list next */
  struct SocketDNSQuery *prev;           /* Linked list prev */
};

/* Main transport structure */
struct T
{
  Arena_T arena;              /* Memory arena */
  SocketPoll_T poll;          /* Poll instance (for timers) */
  SocketDgram_T socket_v4;    /* IPv4 UDP socket */
  SocketDgram_T socket_v6;    /* IPv6 UDP socket */
  int fd_v4;                  /* IPv4 socket fd */
  int fd_v6;                  /* IPv6 socket fd */

  /* Nameserver configuration */
  SocketDNS_Nameserver nameservers[DNS_MAX_NAMESERVERS];
  int nameserver_count;
  int current_ns; /* Current nameserver for rotation */

  /* Configuration */
  int initial_timeout_ms;
  int max_timeout_ms;
  int max_retries;
  int rotate_nameservers;

  /* Query tracking */
  struct SocketDNSQuery *pending_head;
  struct SocketDNSQuery *pending_tail;
  int pending_count;

  /* Receive buffer */
  unsigned char recv_buf[DNS_UDP_MAX_SIZE];
};

const Except_T SocketDNSTransport_Failed
    = { &SocketDNSTransport_Failed, "DNS transport operation failed" };

/* Get monotonic time in milliseconds */
static int64_t
get_monotonic_ms (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Detect address family from string */
static int
detect_address_family (const char *address)
{
  struct in_addr addr4;
  struct in6_addr addr6;

  if (inet_pton (AF_INET, address, &addr4) == 1)
    return AF_INET;
  if (inet_pton (AF_INET6, address, &addr6) == 1)
    return AF_INET6;
  return -1;
}

/* Add query to pending list */
static void
add_to_pending (T transport, struct SocketDNSQuery *query)
{
  query->next = NULL;
  query->prev = transport->pending_tail;
  if (transport->pending_tail)
    transport->pending_tail->next = query;
  else
    transport->pending_head = query;
  transport->pending_tail = query;
  transport->pending_count++;
}

/* Remove query from pending list */
static void
remove_from_pending (T transport, struct SocketDNSQuery *query)
{
  if (query->prev)
    query->prev->next = query->next;
  else
    transport->pending_head = query->next;

  if (query->next)
    query->next->prev = query->prev;
  else
    transport->pending_tail = query->prev;

  query->next = NULL;
  query->prev = NULL;
  transport->pending_count--;
}

/* Find query by ID */
static struct SocketDNSQuery *
find_query_by_id (T transport, uint16_t id)
{
  struct SocketDNSQuery *q;
  for (q = transport->pending_head; q != NULL; q = q->next)
    {
      if (q->id == id && !q->cancelled && !q->completed)
        return q;
    }
  return NULL;
}

/* Map DNS RCODE to error code */
static int
rcode_to_error (int rcode)
{
  switch (rcode)
    {
    case DNS_RCODE_NOERROR:
      return DNS_ERROR_SUCCESS;
    case DNS_RCODE_FORMERR:
      return DNS_ERROR_FORMERR;
    case DNS_RCODE_SERVFAIL:
      return DNS_ERROR_SERVFAIL;
    case DNS_RCODE_NXDOMAIN:
      return DNS_ERROR_NXDOMAIN;
    case DNS_RCODE_REFUSED:
      return DNS_ERROR_REFUSED;
    default:
      return DNS_ERROR_INVALID;
    }
}

/* Send query to current nameserver */
static int
send_query (T transport, struct SocketDNSQuery *query)
{
  SocketDNS_Nameserver *ns;
  volatile SocketDgram_T sock;
  volatile ssize_t sent;

  if (transport->nameserver_count == 0)
    return -1;

  ns = &transport->nameservers[query->current_ns];

  /* Select appropriate socket */
  if (ns->family == AF_INET6)
    sock = transport->socket_v6;
  else
    sock = transport->socket_v4;

  if (!sock)
    return -1;

  /* Send the query */
  TRY
  {
    sent = SocketDgram_sendto (sock, query->query, query->query_len,
                               ns->address, ns->port);
  }
  EXCEPT (SocketDgram_Failed)
  {
    return -1;
  }
  END_TRY;

  if (sent <= 0)
    return -1;

  query->sent_time_ms = get_monotonic_ms ();
  return 0;
}

/* Complete a query with result */
static void
complete_query (T transport, struct SocketDNSQuery *query,
                const unsigned char *response, size_t len, int error)
{
  query->completed = 1;
  remove_from_pending (transport, query);

  if (query->callback)
    query->callback (query, response, len, error, query->userdata);
}

/* Process a single received response */
static int
process_response (T transport, const unsigned char *data, size_t len,
                  const char *sender_addr, int sender_port)
{
  SocketDNS_Header hdr;
  struct SocketDNSQuery *query;
  int error;

  (void)sender_addr;
  (void)sender_port;

  /* Validate minimum size */
  if (len < DNS_HEADER_SIZE)
    return 0;

  /* Decode header */
  if (SocketDNS_header_decode (data, len, &hdr) != 0)
    return 0;

  /* Must be a response */
  if (hdr.qr != 1)
    return 0;

  /* Find matching query */
  query = find_query_by_id (transport, hdr.id);
  if (!query)
    return 0;

  /* Check truncation */
  if (hdr.tc)
    {
      complete_query (transport, query, data, len, DNS_ERROR_TRUNCATED);
      return 1;
    }

  /* Map RCODE to error */
  error = rcode_to_error (hdr.rcode);

  /* Complete the query */
  complete_query (transport, query, data, len, error);
  return 1;
}

/* Receive and process responses from a socket */
static int
receive_responses (T transport, SocketDgram_T sock)
{
  volatile int processed = 0;
  volatile ssize_t len;
  char sender_addr[64];
  int sender_port;

  if (!sock)
    return 0;

  /* Try to receive responses (non-blocking) */
  while (1)
    {
      TRY
      {
        len = SocketDgram_recvfrom (sock, transport->recv_buf,
                                    sizeof (transport->recv_buf), sender_addr,
                                    sizeof (sender_addr), &sender_port);
      }
      EXCEPT (SocketDgram_Failed)
      {
        break;
      }
      END_TRY;

      if (len <= 0)
        break;

      processed
          += process_response (transport, transport->recv_buf, (size_t)len,
                               sender_addr, sender_port);
    }

  return processed;
}

/* Check for timed out queries */
static int
check_timeouts (T transport)
{
  struct SocketDNSQuery *query, *next;
  int64_t now_ms = get_monotonic_ms ();
  int processed = 0;

  for (query = transport->pending_head; query != NULL; query = next)
    {
      next = query->next;

      if (query->completed || query->cancelled)
        continue;

      /* Check if timed out */
      if (now_ms - query->sent_time_ms >= query->timeout_ms)
        {
          /* Check if we should retry */
          if (query->retry_count < transport->max_retries)
            {
              query->retry_count++;

              /* Exponential backoff */
              query->timeout_ms *= 2;
              if (query->timeout_ms > transport->max_timeout_ms)
                query->timeout_ms = transport->max_timeout_ms;

              /* Rotate nameserver if enabled */
              if (transport->rotate_nameservers
                  && transport->nameserver_count > 1)
                {
                  query->current_ns
                      = (query->current_ns + 1) % transport->nameserver_count;
                }

              /* Resend */
              if (send_query (transport, query) != 0)
                {
                  complete_query (transport, query, NULL, 0, DNS_ERROR_NETWORK);
                  processed++;
                }
            }
          else
            {
              /* Max retries exhausted */
              complete_query (transport, query, NULL, 0, DNS_ERROR_TIMEOUT);
              processed++;
            }
        }
    }

  return processed;
}

/* Process cancelled queries */
static int
process_cancelled (T transport)
{
  struct SocketDNSQuery *query, *next;
  int processed = 0;

  for (query = transport->pending_head; query != NULL; query = next)
    {
      next = query->next;

      if (query->cancelled && !query->completed)
        {
          complete_query (transport, query, NULL, 0, DNS_ERROR_CANCELLED);
          processed++;
        }
    }

  return processed;
}

/* Public API implementation */

T
SocketDNSTransport_new (Arena_T arena, SocketPoll_T poll)
{
  T transport;

  assert (arena);

  transport = Arena_alloc (arena, sizeof (*transport), __FILE__, __LINE__);
  memset (transport, 0, sizeof (*transport));

  transport->arena = arena;
  transport->poll = poll;

  /* Default configuration */
  transport->initial_timeout_ms = DNS_RETRY_INITIAL_MS;
  transport->max_timeout_ms = DNS_RETRY_MAX_MS;
  transport->max_retries = DNS_RETRY_MAX_ATTEMPTS;
  transport->rotate_nameservers = 1;

  /* Create IPv4 socket */
  TRY
  {
    transport->socket_v4 = SocketDgram_new (AF_INET, 0);
    if (transport->socket_v4)
      {
        SocketDgram_setnonblocking (transport->socket_v4);
        transport->fd_v4 = SocketDgram_fd (transport->socket_v4);
      }
  }
  EXCEPT (SocketDgram_Failed)
  {
    transport->socket_v4 = NULL;
    transport->fd_v4 = -1;
  }
  END_TRY;

  /* Create IPv6 socket */
  TRY
  {
    transport->socket_v6 = SocketDgram_new (AF_INET6, 0);
    if (transport->socket_v6)
      {
        SocketDgram_setnonblocking (transport->socket_v6);
        transport->fd_v6 = SocketDgram_fd (transport->socket_v6);
      }
  }
  EXCEPT (SocketDgram_Failed)
  {
    transport->socket_v6 = NULL;
    transport->fd_v6 = -1;
  }
  END_TRY;

  /* At least one socket must be available */
  if (!transport->socket_v4 && !transport->socket_v6)
    {
      RAISE (SocketDNSTransport_Failed);
    }

  return transport;
}

void
SocketDNSTransport_free (T *transport)
{
  struct SocketDNSQuery *query, *next;

  if (!transport || !*transport)
    return;

  /* Cancel all pending queries */
  for (query = (*transport)->pending_head; query != NULL; query = next)
    {
      next = query->next;
      if (!query->completed)
        {
          query->cancelled = 1;
          if (query->callback)
            query->callback (query, NULL, 0, DNS_ERROR_CANCELLED,
                             query->userdata);
        }
    }

  /* Free sockets */
  if ((*transport)->socket_v4)
    SocketDgram_free (&(*transport)->socket_v4);
  if ((*transport)->socket_v6)
    SocketDgram_free (&(*transport)->socket_v6);

  /* Arena will clean up the rest */
  *transport = NULL;
}

int
SocketDNSTransport_add_nameserver (T transport, const char *address, int port)
{
  SocketDNS_Nameserver *ns;
  int family;

  assert (transport);
  assert (address);

  if (transport->nameserver_count >= DNS_MAX_NAMESERVERS)
    return -1;

  family = detect_address_family (address);
  if (family < 0)
    return -1;

  /* Check we have the right socket */
  if (family == AF_INET6 && !transport->socket_v6)
    return -1;
  if (family == AF_INET && !transport->socket_v4)
    return -1;

  ns = &transport->nameservers[transport->nameserver_count];
  strncpy (ns->address, address, sizeof (ns->address) - 1);
  ns->address[sizeof (ns->address) - 1] = '\0';
  ns->port = port > 0 ? port : DNS_PORT;
  ns->family = family;

  transport->nameserver_count++;
  return 0;
}

void
SocketDNSTransport_clear_nameservers (T transport)
{
  assert (transport);
  transport->nameserver_count = 0;
  transport->current_ns = 0;
}

int
SocketDNSTransport_nameserver_count (T transport)
{
  assert (transport);
  return transport->nameserver_count;
}

void
SocketDNSTransport_configure (T transport,
                              const SocketDNSTransport_Config *config)
{
  assert (transport);
  assert (config);

  if (config->initial_timeout_ms > 0)
    transport->initial_timeout_ms = config->initial_timeout_ms;
  if (config->max_timeout_ms > 0)
    transport->max_timeout_ms = config->max_timeout_ms;
  if (config->max_retries >= 0)
    transport->max_retries = config->max_retries;
  transport->rotate_nameservers = config->rotate_nameservers;
}

SocketDNSQuery_T
SocketDNSTransport_query_udp (T transport, const unsigned char *query_data,
                              size_t len, SocketDNSTransport_Callback callback,
                              void *userdata)
{
  struct SocketDNSQuery *query;
  SocketDNS_Header hdr;

  assert (transport);
  assert (query_data);
  assert (callback);

  /* Validate size - return NULL for invalid parameters */
  if (len < DNS_HEADER_SIZE || len > DNS_UDP_MAX_SIZE)
    return NULL;

  /* Check nameservers - call callback with error */
  if (transport->nameserver_count == 0)
    {
      callback (NULL, NULL, 0, DNS_ERROR_NONS, userdata);
      return NULL;
    }

  /* Check pending limit */
  if (transport->pending_count >= DNS_MAX_PENDING_QUERIES)
    return NULL;

  /* Decode header to get ID */
  if (SocketDNS_header_decode (query_data, len, &hdr) != 0)
    return NULL;

  /* Allocate query struct */
  query = Arena_alloc (transport->arena, sizeof (*query), __FILE__, __LINE__);
  memset (query, 0, sizeof (*query));

  query->id = hdr.id;
  memcpy (query->query, query_data, len);
  query->query_len = len;
  query->current_ns = transport->current_ns;
  query->retry_count = 0;
  query->timeout_ms = transport->initial_timeout_ms;
  query->callback = callback;
  query->userdata = userdata;

  /* Add to pending list */
  add_to_pending (transport, query);

  /* Send query */
  if (send_query (transport, query) != 0)
    {
      remove_from_pending (transport, query);
      RAISE (SocketDNSTransport_Failed);
    }

  /* Rotate current nameserver for next query */
  if (transport->rotate_nameservers && transport->nameserver_count > 1)
    {
      transport->current_ns
          = (transport->current_ns + 1) % transport->nameserver_count;
    }

  return query;
}

int
SocketDNSTransport_cancel (T transport, SocketDNSQuery_T query)
{
  struct SocketDNSQuery *q;

  assert (transport);

  if (!query)
    return -1;

  /* Verify query is in our pending list */
  for (q = transport->pending_head; q != NULL; q = q->next)
    {
      if (q == query && !q->completed)
        {
          q->cancelled = 1;
          return 0;
        }
    }

  return -1;
}

int
SocketDNSTransport_process (T transport, int timeout_ms)
{
  struct pollfd fds[2];
  int nfds = 0;
  int ret;
  int processed = 0;

  assert (transport);

  /* Set up poll fds */
  if (transport->fd_v4 >= 0)
    {
      fds[nfds].fd = transport->fd_v4;
      fds[nfds].events = POLLIN;
      fds[nfds].revents = 0;
      nfds++;
    }
  if (transport->fd_v6 >= 0)
    {
      fds[nfds].fd = transport->fd_v6;
      fds[nfds].events = POLLIN;
      fds[nfds].revents = 0;
      nfds++;
    }

  /* Process cancelled queries first */
  processed += process_cancelled (transport);

  if (nfds == 0)
    {
      /* No sockets, just check timeouts */
      processed += check_timeouts (transport);
      return processed;
    }

  /* Poll for readable sockets */
  ret = poll (fds, (nfds_t)nfds, timeout_ms);

  if (ret > 0)
    {
      /* Check which sockets are readable */
      for (int i = 0; i < nfds; i++)
        {
          if (fds[i].revents & POLLIN)
            {
              if (fds[i].fd == transport->fd_v4)
                processed += receive_responses (transport, transport->socket_v4);
              else if (fds[i].fd == transport->fd_v6)
                processed += receive_responses (transport, transport->socket_v6);
            }
        }
    }

  /* Check for timeouts */
  processed += check_timeouts (transport);

  return processed;
}

uint16_t
SocketDNSQuery_get_id (SocketDNSQuery_T query)
{
  assert (query);
  return query->id;
}

int
SocketDNSQuery_get_retry_count (SocketDNSQuery_T query)
{
  assert (query);
  return query->retry_count;
}

int
SocketDNSTransport_is_pending (T transport, SocketDNSQuery_T query)
{
  struct SocketDNSQuery *q;

  assert (transport);
  assert (query);

  for (q = transport->pending_head; q != NULL; q = q->next)
    {
      if (q == query && !q->completed && !q->cancelled)
        return 1;
    }
  return 0;
}

int
SocketDNSTransport_fd_v4 (T transport)
{
  assert (transport);
  return transport->fd_v4;
}

int
SocketDNSTransport_fd_v6 (T transport)
{
  assert (transport);
  return transport->fd_v6;
}

int
SocketDNSTransport_pending_count (T transport)
{
  assert (transport);
  return transport->pending_count;
}

const char *
SocketDNSTransport_strerror (int error)
{
  switch (error)
    {
    case DNS_ERROR_SUCCESS:
      return "Success";
    case DNS_ERROR_TIMEOUT:
      return "Query timed out";
    case DNS_ERROR_TRUNCATED:
      return "Response truncated (TC bit set)";
    case DNS_ERROR_CANCELLED:
      return "Query cancelled";
    case DNS_ERROR_NETWORK:
      return "Network error";
    case DNS_ERROR_INVALID:
      return "Invalid response";
    case DNS_ERROR_FORMERR:
      return "Server format error";
    case DNS_ERROR_SERVFAIL:
      return "Server failure";
    case DNS_ERROR_NXDOMAIN:
      return "Domain does not exist";
    case DNS_ERROR_REFUSED:
      return "Query refused";
    case DNS_ERROR_NONS:
      return "No nameservers configured";
    default:
      return "Unknown error";
    }
}
