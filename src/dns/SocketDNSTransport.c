/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDNSTransport.c
 * @brief DNS UDP and TCP transport implementation (RFC 1035 Section 4.2).
 * @ingroup dns_transport
 *
 * Implements async UDP and TCP transport for DNS queries with retry and timeout
 * handling. Uses non-blocking sockets with poll() for event processing.
 *
 * TCP transport per RFC 1035 Section 4.2.2:
 * - 2-byte length prefix (network byte order) before message
 * - Used when UDP response truncated (TC bit)
 * - Non-blocking connect and I/O
 * - Connection reuse for multiple queries
 *
 * EDNS0 support (RFC 6891):
 * - UDP receive buffer supports up to 4096 bytes
 * - Queries with OPT record can request larger payload sizes
 * - FORMERR fallback for non-EDNS0 servers handled at higher layer
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/SocketTimer.h"
#include "core/SocketUtil.h"
#include "dns/SocketDNSDeadServer.h"
#include "dns/SocketDNSTransport.h"
#include "dns/SocketDNSWire.h"
#include "socket/SocketDgram.h"

#undef T
#define T SocketDNSTransport_T

/* TCP connection state per nameserver */
struct DNSTCPConnection
{
  int fd;                                  /* TCP socket fd (-1 if not connected) */
  int family;                              /* AF_INET or AF_INET6 */
  int connecting;                          /* Non-blocking connect in progress */
  int64_t connect_start_ms;                /* When connect started */
  int64_t last_activity_ms;                /* Last send/recv time */

  /* Receive state for 2-byte length prefix */
  unsigned char len_buf[2];                /* Length prefix buffer */
  size_t len_received;                     /* Bytes of length received (0-2) */
  size_t msg_len;                          /* Message length after decoding */
  unsigned char *recv_buf;                 /* Message receive buffer */
  size_t recv_len;                         /* Bytes of message received */

  /* Send state for pending data */
  unsigned char *send_buf;                 /* Pending send data */
  size_t send_len;                         /* Total bytes to send */
  size_t send_offset;                      /* Bytes already sent */
};

/* Internal query state */
struct SocketDNSQuery
{
  uint16_t id;                           /* DNS message ID */
  unsigned char *query;                  /* Query copy (arena-allocated) */
  size_t query_len;                      /* Query length */
  int current_ns;                        /* Current nameserver index */
  int retry_count;                       /* Number of retries */
  int timeout_ms;                        /* Current timeout (backoff) */
  int64_t sent_time_ms;                  /* Timestamp when sent */
  int cancelled;                         /* Cancelled flag */
  int completed;                         /* Completed flag */
  int is_tcp;                            /* Using TCP transport */
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

  /* TCP connections per nameserver */
  struct DNSTCPConnection tcp_conns[DNS_MAX_NAMESERVERS];

  /* Configuration */
  int initial_timeout_ms;
  int max_timeout_ms;
  int max_retries;
  int rotate_nameservers;
  int tcp_connect_timeout_ms;
  int tcp_idle_timeout_ms;

  /* Query tracking */
  struct SocketDNSQuery *pending_head;
  struct SocketDNSQuery *pending_tail;
  int pending_count;

  /* Dead server tracker (RFC 2308 Section 7.2) */
  SocketDNSDeadServer_T dead_server_tracker;

  /* Receive buffer (for UDP, sized for EDNS0 per RFC 6891) */
  unsigned char recv_buf[DNS_EDNS0_DEFAULT_UDPSIZE];
};

const Except_T SocketDNSTransport_Failed
    = { &SocketDNSTransport_Failed, "DNS transport operation failed" };

/* Use centralized monotonic time utility from SocketUtil.h */
#define get_monotonic_ms() Socket_get_monotonic_ms()

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

  /* Mark server as alive - it responded (RFC 2308 Section 7.2) */
  if (transport->dead_server_tracker != NULL)
    {
      SocketDNS_Nameserver *ns = &transport->nameservers[query->current_ns];
      SocketDNSDeadServer_mark_alive (transport->dead_server_tracker,
                                      ns->address);
    }

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

/* Find next non-dead nameserver, starting from given index */
static int
find_next_alive_ns (T transport, int start_ns)
{
  int i;
  int ns_count = transport->nameserver_count;

  if (transport->dead_server_tracker == NULL)
    return start_ns; /* No tracker, use as-is */

  /* Try each nameserver starting from start_ns */
  for (i = 0; i < ns_count; i++)
    {
      int ns_idx = (start_ns + i) % ns_count;
      SocketDNS_Nameserver *ns = &transport->nameservers[ns_idx];

      if (!SocketDNSDeadServer_is_dead (transport->dead_server_tracker,
                                         ns->address, NULL))
        return ns_idx;
    }

  /* All servers are dead - return start_ns anyway (they'll be retried
     as dead markings expire per RFC 2308 5-minute limit) */
  return start_ns;
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

      /* Skip completed, cancelled, and TCP queries */
      if (query->completed || query->cancelled || query->is_tcp)
        continue;

      /* Check if timed out */
      if (now_ms - query->sent_time_ms >= query->timeout_ms)
        {
          /* Mark this nameserver as having failed (RFC 2308 Section 7.2) */
          if (transport->dead_server_tracker != NULL)
            {
              SocketDNS_Nameserver *ns
                  = &transport->nameservers[query->current_ns];
              SocketDNSDeadServer_mark_failure (transport->dead_server_tracker,
                                                ns->address);
            }

          /* Check if we should retry */
          if (query->retry_count < transport->max_retries)
            {
              query->retry_count++;

              /* Exponential backoff */
              query->timeout_ms *= 2;
              if (query->timeout_ms > transport->max_timeout_ms)
                query->timeout_ms = transport->max_timeout_ms;

              /* Rotate nameserver if enabled, skipping dead servers */
              if (transport->rotate_nameservers
                  && transport->nameserver_count > 1)
                {
                  int next_ns
                      = (query->current_ns + 1) % transport->nameserver_count;
                  query->current_ns = find_next_alive_ns (transport, next_ns);
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
  transport->tcp_connect_timeout_ms = DNS_TCP_CONNECT_TIMEOUT_MS;
  transport->tcp_idle_timeout_ms = DNS_TCP_IDLE_TIMEOUT_MS;

  /* Initialize TCP connections to disconnected state */
  for (int i = 0; i < DNS_MAX_NAMESERVERS; i++)
    {
      transport->tcp_conns[i].fd = -1;
      transport->tcp_conns[i].connecting = 0;
    }

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

  /* Close TCP connections */
  for (int i = 0; i < DNS_MAX_NAMESERVERS; i++)
    {
      if ((*transport)->tcp_conns[i].fd >= 0)
        {
          close ((*transport)->tcp_conns[i].fd);
          (*transport)->tcp_conns[i].fd = -1;
        }
    }

  /* Free UDP sockets */
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
  int ret = snprintf (ns->address, sizeof (ns->address), "%s", address);
  if (SOCKET_SNPRINTF_CHECK (ret, sizeof (ns->address)) < 0)
    return -1; /* Address string truncated */
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

void
SocketDNSTransport_set_dead_server_tracker (T transport,
                                            SocketDNSDeadServer_T tracker)
{
  assert (transport);
  transport->dead_server_tracker = tracker;
}

SocketDNSDeadServer_T
SocketDNSTransport_get_dead_server_tracker (T transport)
{
  assert (transport);
  return transport->dead_server_tracker;
}

SocketDNSQuery_T
SocketDNSTransport_query_udp (T transport, const unsigned char *query_data,
                              size_t len, SocketDNSTransport_Callback callback,
                              void *userdata)
{
  struct SocketDNSQuery *query;
  SocketDNS_Header hdr;

  /* Validate parameters - return NULL for invalid inputs */
  if (!transport || !query_data || !callback)
    return NULL;

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

  /* Allocate query struct and buffer */
  query = Arena_alloc (transport->arena, sizeof (*query), __FILE__, __LINE__);
  memset (query, 0, sizeof (*query));

  query->query = Arena_alloc (transport->arena, len, __FILE__, __LINE__);
  query->id = hdr.id;
  memcpy (query->query, query_data, len);
  query->query_len = len;
  query->is_tcp = 0;
  /* Select first non-dead nameserver (RFC 2308 Section 7.2) */
  query->current_ns = find_next_alive_ns (transport, transport->current_ns);
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

/* Forward declaration for TCP processing */
static int process_tcp_queries (T transport);

/* Set up poll file descriptors for IPv4/IPv6 sockets */
static int
setup_poll_fds (T transport, struct pollfd *fds)
{
  int nfds = 0;

  assert (transport);
  assert (fds);

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

  return nfds;
}

int
SocketDNSTransport_process (T transport, int timeout_ms)
{
  struct pollfd fds[2];
  int nfds;
  int ret;
  int processed = 0;

  assert (transport);

  /* Set up poll fds */
  nfds = setup_poll_fds (transport, fds);

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

  /* Check for timeouts (UDP only) */
  processed += check_timeouts (transport);

  /* Process TCP queries */
  processed += process_tcp_queries (transport);

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

/* ============== TCP Transport Implementation ============== */

/* Close a TCP connection and reset state */
static void
tcp_conn_close (struct DNSTCPConnection *conn)
{
  if (conn->fd >= 0)
    {
      close (conn->fd);
      conn->fd = -1;
    }
  conn->connecting = 0;
  conn->len_received = 0;
  conn->msg_len = 0;
  conn->recv_len = 0;
  conn->send_len = 0;
  conn->send_offset = 0;
}

/* Create a non-blocking TCP socket */
static int
tcp_socket_create (int family)
{
  int fd;
  int flags;

  fd = socket (family, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  /* Set non-blocking */
  flags = fcntl (fd, F_GETFL);
  if (flags < 0 || fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      close (fd);
      return -1;
    }

  /* Disable Nagle for lower latency (non-fatal optimization) */
  int nodelay = 1;
  (void)setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof (nodelay));

  return fd;
}

/* Start non-blocking connect to nameserver */
static int
tcp_conn_start (T transport, int ns_idx)
{
  struct DNSTCPConnection *conn = &transport->tcp_conns[ns_idx];
  SocketDNS_Nameserver *ns = &transport->nameservers[ns_idx];
  struct sockaddr_storage ss;
  socklen_t sslen;
  int ret;

  /* Already connected or connecting? */
  if (conn->fd >= 0)
    return 0;

  /* Create socket */
  conn->fd = tcp_socket_create (ns->family);
  if (conn->fd < 0)
    return -1;

  conn->family = ns->family;

  /* Build sockaddr */
  memset (&ss, 0, sizeof (ss));
  if (ns->family == AF_INET)
    {
      struct sockaddr_in *sa4 = (struct sockaddr_in *)&ss;
      sa4->sin_family = AF_INET;
      sa4->sin_port = htons ((uint16_t)ns->port);
      if (inet_pton (AF_INET, ns->address, &sa4->sin_addr) != 1)
        {
          tcp_conn_close (conn);
          return -1;
        }
      sslen = sizeof (*sa4);
    }
  else
    {
      struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&ss;
      sa6->sin6_family = AF_INET6;
      sa6->sin6_port = htons ((uint16_t)ns->port);
      if (inet_pton (AF_INET6, ns->address, &sa6->sin6_addr) != 1)
        {
          tcp_conn_close (conn);
          return -1;
        }
      sslen = sizeof (*sa6);
    }

  /* Non-blocking connect */
  ret = connect (conn->fd, (struct sockaddr *)&ss, sslen);
  if (ret < 0)
    {
      if (errno == EINPROGRESS)
        {
          conn->connecting = 1;
          conn->connect_start_ms = get_monotonic_ms ();
          return 0;
        }
      tcp_conn_close (conn);
      return -1;
    }

  /* Connected immediately */
  conn->connecting = 0;
  conn->last_activity_ms = get_monotonic_ms ();
  return 0;
}

/* Check if connect completed (for EINPROGRESS) */
static int
tcp_conn_check_connect (T transport, int ns_idx)
{
  struct DNSTCPConnection *conn = &transport->tcp_conns[ns_idx];
  struct pollfd pfd;
  int ret, err;
  socklen_t errlen = sizeof (err);

  if (!conn->connecting)
    return conn->fd >= 0 ? 1 : -1;

  /* Check with poll */
  pfd.fd = conn->fd;
  pfd.events = POLLOUT;
  pfd.revents = 0;
  ret = poll (&pfd, 1, 0);

  if (ret < 0)
    {
      tcp_conn_close (conn);
      return -1;
    }

  if (ret == 0)
    {
      /* Still connecting - check timeout */
      int64_t now = get_monotonic_ms ();
      if (now - conn->connect_start_ms > transport->tcp_connect_timeout_ms)
        {
          tcp_conn_close (conn);
          return -1;
        }
      return 0; /* Still in progress */
    }

  /* Check for connect error */
  if (getsockopt (conn->fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0)
    {
      tcp_conn_close (conn);
      return -1;
    }

  /* Connected! */
  conn->connecting = 0;
  conn->last_activity_ms = get_monotonic_ms ();
  return 1;
}

/* Send buffered data on TCP socket, handling EAGAIN and partial sends
 * Returns: 1 = fully sent, 0 = would block (partial), -1 = error (conn closed)
 */
static int
tcp_send_buffered (struct DNSTCPConnection *conn)
{
  ssize_t sent;

  while (conn->send_offset < conn->send_len)
    {
      sent = send (conn->fd, conn->send_buf + conn->send_offset,
                   conn->send_len - conn->send_offset, MSG_NOSIGNAL);
      if (sent < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0; /* Would block, try again later */
          tcp_conn_close (conn);
          return -1;
        }
      conn->send_offset += (size_t)sent;
    }

  /* Done sending */
  conn->send_len = 0;
  conn->send_offset = 0;
  return 1;
}

/* Send data on TCP with length prefix (RFC 1035 §4.2.2) */
static int
tcp_send_query (T transport, struct SocketDNSQuery *query)
{
  struct DNSTCPConnection *conn = &transport->tcp_conns[query->current_ns];
  unsigned char len_prefix[2];
  size_t total_len;
  int ret;

  if (conn->fd < 0 || conn->connecting)
    return -1;

  /* If we have pending send data, continue that first */
  if (conn->send_len > 0)
    return tcp_send_buffered (conn);

  /* Build message with length prefix */
  total_len = 2 + query->query_len;
  conn->send_buf = Arena_alloc (transport->arena, total_len, __FILE__, __LINE__);
  len_prefix[0] = (unsigned char)((query->query_len >> 8) & 0xFF);
  len_prefix[1] = (unsigned char)(query->query_len & 0xFF);
  memcpy (conn->send_buf, len_prefix, 2);
  memcpy (conn->send_buf + 2, query->query, query->query_len);
  conn->send_len = total_len;
  conn->send_offset = 0;

  /* Try to send immediately */
  ret = tcp_send_buffered (conn);
  if (ret == 1)
    {
      conn->last_activity_ms = get_monotonic_ms ();
      query->sent_time_ms = conn->last_activity_ms;
    }
  return ret;
}

/* Read 2-byte length prefix (RFC 1035 Section 4.2.2) */
static int
tcp_recv_length_prefix (struct DNSTCPConnection *conn)
{
  ssize_t received;

  while (conn->len_received < 2)
    {
      received = recv (conn->fd, conn->len_buf + conn->len_received,
                       2 - conn->len_received, 0);
      if (received < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0; /* Would block */
          tcp_conn_close (conn);
          return -1;
        }
      if (received == 0)
        {
          /* Connection closed */
          tcp_conn_close (conn);
          return -1;
        }
      conn->len_received += (size_t)received;
    }

  /* Decode length from network byte order */
  conn->msg_len = ((size_t)conn->len_buf[0] << 8) | (size_t)conn->len_buf[1];
  if (conn->msg_len == 0 || conn->msg_len > DNS_TCP_MAX_SIZE)
    {
      tcp_conn_close (conn);
      return -1;
    }

  return 1;
}

/* Read message body after length prefix is known */
static int
tcp_recv_message_body (T transport, struct DNSTCPConnection *conn,
                       unsigned char **out_msg, size_t *out_len)
{
  ssize_t received;

  /* Allocate buffer if needed */
  if (conn->recv_buf == NULL)
    {
      conn->recv_buf
          = Arena_alloc (transport->arena, conn->msg_len, __FILE__, __LINE__);
      conn->recv_len = 0;
    }

  /* Read message incrementally */
  while (conn->recv_len < conn->msg_len)
    {
      received = recv (conn->fd, conn->recv_buf + conn->recv_len,
                       conn->msg_len - conn->recv_len, 0);
      if (received < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0; /* Would block */
          tcp_conn_close (conn);
          return -1;
        }
      if (received == 0)
        {
          tcp_conn_close (conn);
          return -1;
        }
      conn->recv_len += (size_t)received;
    }

  /* Complete message received */
  *out_msg = conn->recv_buf;
  *out_len = conn->msg_len;
  return 1;
}

/* Receive TCP response with length prefix */
static int
tcp_recv_response (T transport, int ns_idx, unsigned char **response,
                   size_t *response_len)
{
  struct DNSTCPConnection *conn = &transport->tcp_conns[ns_idx];
  int ret;

  if (conn->fd < 0)
    return -1;

  /* Read 2-byte length prefix if not already received */
  if (conn->len_received < 2)
    {
      ret = tcp_recv_length_prefix (conn);
      if (ret <= 0)
        return ret; /* Error or would block */
    }

  /* Read message body */
  ret = tcp_recv_message_body (transport, conn, response, response_len);
  if (ret <= 0)
    return ret; /* Error or would block */

  /* Reset for next message */
  conn->len_received = 0;
  conn->msg_len = 0;
  conn->recv_buf = NULL;
  conn->recv_len = 0;
  conn->last_activity_ms = get_monotonic_ms ();

  return 1;
}

/**
 * Check TCP connection state and send query when connected.
 *
 * @param transport Transport instance
 * @param query Query to check
 * @return 1 if processed (completed), 0 if still pending, -1 for continue loop
 */
static int
check_tcp_connection_state (T transport, struct SocketDNSQuery *query)
{
  struct DNSTCPConnection *conn = &transport->tcp_conns[query->current_ns];
  int status;

  if (!conn->connecting)
    return 0; /* Not in connecting state */

  status = tcp_conn_check_connect (transport, query->current_ns);
  if (status < 0)
    {
      /* Mark server as having failed (RFC 2308 Section 7.2) */
      if (transport->dead_server_tracker != NULL)
        {
          SocketDNS_Nameserver *ns = &transport->nameservers[query->current_ns];
          SocketDNSDeadServer_mark_failure (transport->dead_server_tracker,
                                            ns->address);
        }
      complete_query (transport, query, NULL, 0, DNS_ERROR_CONNFAIL);
      return 1; /* Processed */
    }

  if (status == 0)
    return -1; /* Still connecting, continue loop */

  /* Now connected, send query */
  if (tcp_send_query (transport, query) < 0)
    {
      complete_query (transport, query, NULL, 0, DNS_ERROR_NETWORK);
      return 1; /* Processed */
    }

  return 0; /* Sent successfully, continue checking */
}

/**
 * Handle TCP response polling and validation.
 *
 * @param transport Transport instance
 * @param query Query to check for response
 * @return 1 if processed (completed), 0 if no response, -1 for continue loop
 */
static int
handle_tcp_response (T transport, struct SocketDNSQuery *query)
{
  struct DNSTCPConnection *conn = &transport->tcp_conns[query->current_ns];
  struct pollfd pfd;
  unsigned char *response;
  size_t response_len;
  int ret;

  if (conn->fd < 0 || conn->connecting)
    return 0; /* Not ready to receive */

  pfd.fd = conn->fd;
  pfd.events = POLLIN;
  pfd.revents = 0;

  if (poll (&pfd, 1, 0) <= 0 || !(pfd.revents & POLLIN))
    return 0; /* No data available */

  ret = tcp_recv_response (transport, query->current_ns, &response,
                           &response_len);
  if (ret < 0)
    {
      complete_query (transport, query, NULL, 0, DNS_ERROR_NETWORK);
      return 1; /* Processed */
    }

  if (ret > 0)
    {
      SocketDNS_Header hdr;

      /* Mark server as alive - it responded (RFC 2308 Section 7.2) */
      if (transport->dead_server_tracker != NULL)
        {
          SocketDNS_Nameserver *ns = &transport->nameservers[query->current_ns];
          SocketDNSDeadServer_mark_alive (transport->dead_server_tracker,
                                          ns->address);
        }

      /* Validate response */
      if (response_len >= DNS_HEADER_SIZE
          && SocketDNS_header_decode (response, response_len, &hdr) == 0
          && hdr.qr == 1 && hdr.id == query->id)
        {
          int error = rcode_to_error (hdr.rcode);
          complete_query (transport, query, response, response_len, error);
        }
      else
        {
          /* Invalid response, but keep connection open for retries */
          complete_query (transport, query, NULL, 0, DNS_ERROR_INVALID);
        }
      return -1; /* Processed, continue loop */
    }

  return 0; /* No complete response yet */
}

/**
 * Handle TCP query timeout.
 *
 * @param transport Transport instance
 * @param query Query to check for timeout
 * @param now_ms Current timestamp in milliseconds
 * @return 1 if timed out (processed), 0 otherwise
 */
static int
handle_tcp_timeout (T transport, struct SocketDNSQuery *query, int64_t now_ms)
{
  if (now_ms - query->sent_time_ms < query->timeout_ms)
    return 0; /* Not timed out */

  /* Mark server as having failed (RFC 2308 Section 7.2) */
  if (transport->dead_server_tracker != NULL)
    {
      SocketDNS_Nameserver *ns = &transport->nameservers[query->current_ns];
      SocketDNSDeadServer_mark_failure (transport->dead_server_tracker,
                                        ns->address);
    }

  complete_query (transport, query, NULL, 0, DNS_ERROR_TIMEOUT);
  return 1; /* Processed */
}

/* Process TCP queries - check connections and receive responses */
static int
process_tcp_queries (T transport)
{
  struct SocketDNSQuery *query, *next;
  int processed = 0;
  int64_t now_ms = get_monotonic_ms ();

  for (query = transport->pending_head; query != NULL; query = next)
    {
      int result;
      next = query->next;

      if (!query->is_tcp || query->completed || query->cancelled)
        continue;

      /* Check connection state */
      result = check_tcp_connection_state (transport, query);
      if (result > 0)
        {
          processed++;
          continue;
        }
      if (result < 0)
        continue; /* Still connecting */

      /* Check for response */
      result = handle_tcp_response (transport, query);
      if (result != 0)
        {
          if (result > 0)
            processed++;
          continue;
        }

      /* Check for timeout */
      if (handle_tcp_timeout (transport, query, now_ms))
        processed++;
    }

  return processed;
}

SocketDNSQuery_T
SocketDNSTransport_query_tcp (T transport, const unsigned char *query_data,
                              size_t len, SocketDNSTransport_Callback callback,
                              void *userdata)
{
  struct SocketDNSQuery *query;
  SocketDNS_Header hdr;

  /* Validate parameters - return NULL for invalid inputs */
  if (!transport || !query_data || !callback)
    return NULL;

  /* Validate size */
  if (len < DNS_HEADER_SIZE || len > DNS_TCP_MAX_SIZE)
    return NULL;

  /* Check nameservers */
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

  /* Allocate query struct and buffer */
  query = Arena_alloc (transport->arena, sizeof (*query), __FILE__, __LINE__);
  memset (query, 0, sizeof (*query));

  query->query = Arena_alloc (transport->arena, len, __FILE__, __LINE__);
  query->id = hdr.id;
  memcpy (query->query, query_data, len);
  query->query_len = len;
  query->is_tcp = 1;
  /* Select first non-dead nameserver (RFC 2308 Section 7.2) */
  query->current_ns = find_next_alive_ns (transport, transport->current_ns);
  query->retry_count = 0;
  query->timeout_ms = transport->tcp_connect_timeout_ms;
  query->callback = callback;
  query->userdata = userdata;

  /* Add to pending list */
  add_to_pending (transport, query);

  /* Start TCP connection if needed */
  if (tcp_conn_start (transport, query->current_ns) < 0)
    {
      remove_from_pending (transport, query);
      callback (query, NULL, 0, DNS_ERROR_CONNFAIL, userdata);
      return NULL;
    }

  /* If already connected, send immediately */
  struct DNSTCPConnection *conn = &transport->tcp_conns[query->current_ns];
  if (!conn->connecting)
    {
      if (tcp_send_query (transport, query) < 0)
        {
          remove_from_pending (transport, query);
          callback (query, NULL, 0, DNS_ERROR_NETWORK, userdata);
          return NULL;
        }
    }
  else
    {
      /* Will be sent when connection completes */
      query->sent_time_ms = get_monotonic_ms ();
    }

  /* Rotate nameserver for next query */
  if (transport->rotate_nameservers && transport->nameserver_count > 1)
    {
      transport->current_ns
          = (transport->current_ns + 1) % transport->nameserver_count;
    }

  return query;
}

void
SocketDNSTransport_tcp_close_all (T transport)
{
  assert (transport);

  for (int i = 0; i < DNS_MAX_NAMESERVERS; i++)
    {
      tcp_conn_close (&transport->tcp_conns[i]);
    }
}

int
SocketDNSTransport_tcp_fd (T transport, int ns_index)
{
  assert (transport);

  if (ns_index < 0 || ns_index >= transport->nameserver_count)
    return -1;

  return transport->tcp_conns[ns_index].fd;
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
    case DNS_ERROR_CONNFAIL:
      return "TCP connection failed";
    default:
      return "Unknown error";
    }
}
