/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketDNSoverTLS.c
 * @brief DNS-over-TLS transport implementation (RFC 7858, RFC 8310).
 * @ingroup dns_dot
 *
 * Implements encrypted DNS transport using TLS on port 853.
 *
 * ## Key Implementation Details
 *
 * - Uses same 2-byte length prefix framing as DNS-over-TCP (RFC 1035 Section 4.2.2)
 * - TLS session resumption for fast reconnects
 * - Non-blocking TLS handshake with poll integration
 * - Supports opportunistic and strict privacy modes (RFC 8310)
 * - SPKI pinning for Out-of-Band Key-Pinned Privacy (RFC 7858 Section 4.2)
 */

#include "dns/SocketDNSoverTLS.h"

#if SOCKET_HAS_TLS

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/SocketUtil.h"
#include "dns/SocketDNSWire.h"
#include "socket/Socket.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"

#undef T
#define T SocketDNSoverTLS_T

/**
 * Maximum DNS message size (65535 bytes).
 * RFC 1035 §4.2.2: TCP messages have a 16-bit length field,
 * limiting message size to 2^16 - 1 bytes (excluding the length prefix itself).
 */
#define DOT_MAX_MESSAGE_SIZE 65535

/**
 * Receive buffer size for chunked reads from TLS socket.
 *
 * Set to 4096 bytes (typical page size) for optimal I/O performance:
 * - Matches common system page size on x86/x86_64/ARM
 * - Allows kernel to efficiently transfer data between user/kernel space
 * - Small enough to avoid stack allocation issues
 * - Large enough to minimize system call overhead for typical DNS responses
 *
 * Note: Full DNS messages up to DOT_MAX_MESSAGE_SIZE are assembled from
 * multiple chunks using dynamically allocated buffers (see receive_data()).
 */
#define DOT_RECV_BUFFER_SIZE 4096

/**
 * Maximum total memory for pending query allocations (CWE-770 mitigation).
 *
 * Set to 10MB to prevent arena exhaustion while allowing reasonable query load.
 * With DOT_MAX_PENDING_QUERIES=100 and DOT_MAX_MESSAGE_SIZE=65535, the worst
 * case without this limit would be 6.5MB (100 * 65KB). This limit provides
 * additional headroom while preventing unbounded allocation.
 */
#define DOT_MAX_TOTAL_QUERY_BYTES (10 * 1024 * 1024)

/**
 * Server address buffer size.
 *
 * Sized to hold IPv6 addresses with zone identifiers:
 * - IPv6 max: 39 chars (8 groups of 4 hex + 7 colons)
 * - Zone ID: "%" + zone name (up to 20 chars typical)
 * - Null terminator: 1 char
 * - Total: 39 + 1 + 20 + 1 = 61, rounded to 64 for alignment
 *
 * Example: "fe80::1234:5678:90ab:cdef%eth0"
 */
#define DOT_SERVER_ADDRESS_SIZE 64

/**
 * DNS server name buffer size.
 *
 * RFC 1035 §2.3.4 specifies maximum domain name length of 255 octets.
 * Add 1 byte for null terminator.
 */
#define DOT_SERVER_NAME_SIZE 256

/**
 * SPKI pin buffer size.
 *
 * Base64-encoded SHA256 hash:
 * - SHA256 hash: 32 bytes
 * - Base64 encoding: ceil(32 * 4/3) = 44 chars
 * - Null terminator: 1 char
 * - Padding/alignment: rounded to 64 bytes
 *
 * Used for RFC 7469 Public Key Pinning (HPKP) in DNS-over-TLS.
 */
#define DOT_SPKI_PIN_SIZE 64

/* Well-known DoT servers */
static const struct
{
  const char *name;
  const char *address;
  const char *server_name;
  int is_ipv6;
} well_known_servers[] = {
  { "google", "8.8.8.8", "dns.google", 0 },
  { "google-v6", "2001:4860:4860::8888", "dns.google", 1 },
  { "cloudflare", "1.1.1.1", "cloudflare-dns.com", 0 },
  { "cloudflare-v6", "2606:4700:4700::1111", "cloudflare-dns.com", 1 },
  { "quad9", "9.9.9.9", "dns.quad9.net", 0 },
  { "quad9-v6", "2620:fe::fe", "dns.quad9.net", 1 },
  { NULL, NULL, NULL, 0 }
};

/* Server configuration entry */
struct ServerConfig
{
  char address[DOT_SERVER_ADDRESS_SIZE];
  int port;
  char server_name[DOT_SERVER_NAME_SIZE];
  SocketDNSoverTLS_Mode mode;
  char spki_pin[DOT_SPKI_PIN_SIZE];        /* Base64-encoded SHA256 */
  char spki_pin_backup[DOT_SPKI_PIN_SIZE]; /* Backup pin */
  int family;                              /* AF_INET or AF_INET6 */
};

/* TLS connection state */
typedef enum
{
  CONN_STATE_DISCONNECTED = 0,
  CONN_STATE_CONNECTING,
  CONN_STATE_HANDSHAKING,
  CONN_STATE_CONNECTED,
  CONN_STATE_ERROR
} ConnectionState;

/* TLS connection */
struct Connection
{
  Socket_T socket;
  SocketTLSContext_T tls_ctx;
  ConnectionState state;
  int64_t connect_start_ms;
  int64_t last_activity_ms;
  int server_index;

  /* Receive state for 2-byte length prefix */
  unsigned char len_buf[2];
  size_t len_received;
  size_t msg_len;
  unsigned char *recv_buf;
  size_t recv_len;
  size_t recv_alloc;

  /* Send queue */
  unsigned char *send_buf;
  size_t send_len;
  size_t send_offset;
};

/* Pending query */
struct SocketDNSoverTLS_Query
{
  uint16_t id;
  unsigned char *query;
  size_t query_len;
  int64_t sent_time_ms;
  int cancelled;
  int completed;
  SocketDNSoverTLS_Callback callback;
  void *userdata;
  struct SocketDNSoverTLS_Query *next;
  struct SocketDNSoverTLS_Query *prev;
};

/* Main transport structure */
struct T
{
  Arena_T arena;

  /* Server configuration */
  struct ServerConfig servers[DOT_MAX_CONNECTIONS];
  int server_count;
  int current_server;

  /* Active connection */
  struct Connection conn;

  /* Pending queries */
  struct SocketDNSoverTLS_Query *pending_head;
  struct SocketDNSoverTLS_Query *pending_tail;
  int pending_count;

  /* Memory tracking (CWE-770: Allocation of Resources Without Limits) */
  size_t total_query_bytes;

  /* Statistics */
  SocketDNSoverTLS_Stats stats;

  /* Timeouts */
  int handshake_timeout_ms;
  int query_timeout_ms;
  int idle_timeout_ms;
};

const Except_T SocketDNSoverTLS_Failed
    = { &SocketDNSoverTLS_Failed, "DNS-over-TLS operation failed" };

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

/* Initialize connection structure */
static void
init_connection (struct Connection *conn)
{
  memset (conn, 0, sizeof (*conn));
  conn->socket = NULL;
  conn->tls_ctx = NULL;
  conn->state = CONN_STATE_DISCONNECTED;
  conn->server_index = -1;
}

/* Close TLS connection */
static void
close_connection (T transport, struct Connection *conn)
{
  if (conn->socket)
    {
      if (conn->state == CONN_STATE_CONNECTED)
        {
          SocketTLS_disable (conn->socket);
        }
      Socket_free (&conn->socket);
    }

  if (conn->tls_ctx)
    {
      SocketTLSContext_free (&conn->tls_ctx);
    }

  conn->state = CONN_STATE_DISCONNECTED;
  conn->len_received = 0;
  conn->msg_len = 0;
  conn->recv_len = 0;
  conn->send_len = 0;
  conn->send_offset = 0;
  (void)transport;
}

/* Create TLS context for server */
static SocketTLSContext_T
create_tls_context (T transport, struct ServerConfig *server)
{
  SocketTLSContext_T ctx = NULL;

  TRY
  {
    /* Create client context with system CAs */
    ctx = SocketTLSContext_new_client (NULL);

    /* Set verification mode based on privacy mode */
    if (server->mode == DOT_MODE_STRICT)
      {
        SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_PEER);
      }
    else
      {
        /* Opportunistic: accept any certificate */
        SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_NONE);
      }

    /* Enable session caching for resumption */
    SocketTLSContext_enable_session_cache (ctx, 10, 300);

    /* Add SPKI pins if configured */
    if (server->spki_pin[0] != '\0')
      {
        SocketTLSContext_add_pin_hex (ctx, server->spki_pin);
        SocketTLSContext_set_pin_enforcement (ctx, 1);
      }
    if (server->spki_pin_backup[0] != '\0')
      {
        SocketTLSContext_add_pin_hex (ctx, server->spki_pin_backup);
      }
  }
  EXCEPT (SocketTLS_Failed)
  {
    if (ctx)
      SocketTLSContext_free (&ctx);
    ctx = NULL;
  }
  END_TRY;

  (void)transport;
  return ctx;
}

/* Start TLS connection to server */
static int
start_connection (T transport, int server_index)
{
  struct ServerConfig *server;
  struct Connection *conn;
  int fd;

  if (server_index < 0 || server_index >= transport->server_count)
    return -1;

  server = &transport->servers[server_index];
  conn = &transport->conn;

  /* Close existing connection */
  if (conn->state != CONN_STATE_DISCONNECTED)
    {
      close_connection (transport, conn);
    }

  /* Create TLS context */
  conn->tls_ctx = create_tls_context (transport, server);
  if (!conn->tls_ctx)
    {
      transport->stats.handshake_failures++;
      return -1;
    }

  TRY
  {
    /* Create socket */
    conn->socket = Socket_new (server->family, SOCK_STREAM, 0);
    Socket_setnonblocking (conn->socket);

    /* Connect to server */
    fd = Socket_fd (conn->socket);

    struct sockaddr_storage addr;
    socklen_t addrlen;

    if (server->family == AF_INET)
      {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
        memset (addr4, 0, sizeof (*addr4));
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons (server->port);
        inet_pton (AF_INET, server->address, &addr4->sin_addr);
        addrlen = sizeof (*addr4);
      }
    else
      {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
        memset (addr6, 0, sizeof (*addr6));
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons (server->port);
        inet_pton (AF_INET6, server->address, &addr6->sin6_addr);
        addrlen = sizeof (*addr6);
      }

    int ret = connect (fd, (struct sockaddr *)&addr, addrlen);
    if (ret < 0 && errno != EINPROGRESS)
      {
        RAISE (Socket_Failed);
      }

    conn->state = CONN_STATE_CONNECTING;
    conn->connect_start_ms = get_monotonic_ms ();
    conn->server_index = server_index;
    transport->stats.connections_opened++;
  }
  EXCEPT (Socket_Failed)
  {
    close_connection (transport, conn);
    transport->stats.handshake_failures++;
    return -1;
  }
  END_TRY;

  return 0;
}

/* Check if TCP connection has completed */
static int
check_tcp_connect_complete (T transport, struct Connection *conn)
{
  struct ServerConfig *server = &transport->servers[conn->server_index];
  int fd = Socket_fd (conn->socket);
  struct pollfd pfd = { .fd = fd, .events = POLLOUT };
  int ret = poll (&pfd, 1, 0);

  if (ret <= 0)
    return 0; /* Still connecting */

  if (pfd.revents & (POLLERR | POLLHUP))
    {
      close_connection (transport, conn);
      transport->stats.handshake_failures++;
      return -1;
    }

  /* Check socket error */
  int error = 0;
  socklen_t errlen = sizeof (error);
  if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &errlen) != 0)
    {
      close_connection (transport, conn);
      transport->stats.handshake_failures++;
      return -1;
    }

  if (error != 0)
    {
      close_connection (transport, conn);
      transport->stats.handshake_failures++;
      return -1;
    }

  /* Connection established, start TLS handshake */
  TRY
  {
    SocketTLS_enable (conn->socket, conn->tls_ctx);
    SocketTLS_set_hostname (conn->socket, server->server_name);
    conn->state = CONN_STATE_HANDSHAKING;
  }
  EXCEPT (SocketTLS_Failed)
  {
    close_connection (transport, conn);
    transport->stats.handshake_failures++;
    return -1;
  }
  END_TRY;

  return 0;
}

/* Perform TLS handshake */
static int
perform_tls_handshake (T transport, struct Connection *conn, int64_t now)
{
  volatile TLSHandshakeState hs_state;

  TRY
  {
    hs_state = SocketTLS_handshake (conn->socket);
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    close_connection (transport, conn);
    transport->stats.handshake_failures++;
    return -1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    close_connection (transport, conn);
    transport->stats.verify_failures++;
    return -1;
  }
  END_TRY;

  switch (hs_state)
    {
    case TLS_HANDSHAKE_COMPLETE:
      conn->state = CONN_STATE_CONNECTED;
      conn->last_activity_ms = now;
      return 1; /* Connected */

    case TLS_HANDSHAKE_ERROR:
      close_connection (transport, conn);
      transport->stats.handshake_failures++;
      return -1;

    case TLS_HANDSHAKE_WANT_READ:
    case TLS_HANDSHAKE_WANT_WRITE:
    case TLS_HANDSHAKE_IN_PROGRESS:
    case TLS_HANDSHAKE_NOT_STARTED:
      return 0; /* Still handshaking */
    }

  return 0;
}

/* Continue TLS connection (non-blocking) */
static int
continue_connection (T transport)
{
  struct Connection *conn = &transport->conn;
  int64_t now;

  if (conn->state == CONN_STATE_DISCONNECTED
      || conn->state == CONN_STATE_CONNECTED)
    return 0;

  now = get_monotonic_ms ();

  /* Check for timeout */
  if (now - conn->connect_start_ms > transport->handshake_timeout_ms)
    {
      close_connection (transport, conn);
      transport->stats.handshake_failures++;
      return -1;
    }

  if (conn->state == CONN_STATE_CONNECTING)
    {
      return check_tcp_connect_complete (transport, conn);
    }

  if (conn->state == CONN_STATE_HANDSHAKING)
    {
      return perform_tls_handshake (transport, conn, now);
    }

  return 0;
}

/* Send pending data */
static int
send_pending (T transport)
{
  struct Connection *conn = &transport->conn;
  volatile ssize_t sent;

  if (conn->state != CONN_STATE_CONNECTED)
    return 0;

  while (conn->send_offset < conn->send_len)
    {
      TRY
      {
        sent = SocketTLS_send (conn->socket,
                               conn->send_buf + conn->send_offset,
                               conn->send_len - conn->send_offset);
      }
      EXCEPT (SocketTLS_Failed)
      {
        close_connection (transport, conn);
        return -1;
      }
      END_TRY;

      if (sent <= 0)
        {
          /* Would block (returns 0 with errno=EAGAIN) */
          return 0;
        }

      conn->send_offset += (size_t)sent;
      transport->stats.bytes_sent += (uint64_t)sent;
      conn->last_activity_ms = get_monotonic_ms ();
    }

  /* All data sent */
  conn->send_len = 0;
  conn->send_offset = 0;
  return 1;
}

/* Queue query for sending */
static int
queue_query (T transport, struct SocketDNSoverTLS_Query *query)
{
  struct Connection *conn = &transport->conn;
  size_t total_len;

  /* Validate query length fits in 16-bit length prefix (CWE-681) */
  if (query->query_len > 65535)
    {
      return -1; /* Query too large for wire format */
    }

  /* Need 2-byte length prefix + query */
  total_len = 2 + query->query_len;

  /* Allocate send buffer if needed */
  if (!conn->send_buf)
    {
      conn->send_buf = ALLOC (transport->arena, DOT_MAX_MESSAGE_SIZE + 2);
    }

  /* Check if there's room - avoid integer overflow (CWE-190) */
  if (total_len > DOT_MAX_MESSAGE_SIZE + 2 - conn->send_len)
    {
      return -1; /* Buffer full */
    }

  /* Add length prefix (network byte order) */
  conn->send_buf[conn->send_len] = (unsigned char)(query->query_len >> 8);
  conn->send_buf[conn->send_len + 1] = (unsigned char)(query->query_len & 0xFF);
  memcpy (conn->send_buf + conn->send_len + 2, query->query, query->query_len);
  conn->send_len += total_len;

  return 0;
}

/* Receive data from connection */
static int
receive_data (T transport)
{
  struct Connection *conn = &transport->conn;
  unsigned char buf[DOT_RECV_BUFFER_SIZE];
  volatile ssize_t n;
  size_t processed;

  if (conn->state != CONN_STATE_CONNECTED)
    return 0;

  /* Try to receive data */
  TRY
  {
    n = SocketTLS_recv (conn->socket, buf, sizeof (buf));
  }
  EXCEPT (SocketTLS_Failed)
  {
    close_connection (transport, conn);
    return -1;
  }
  END_TRY;

  if (n <= 0)
    {
      if (n == 0)
        {
          /* Connection closed */
          close_connection (transport, conn);
        }
      return (int)n;
    }

  transport->stats.bytes_received += (uint64_t)n;
  conn->last_activity_ms = get_monotonic_ms ();

  /* Process received data */
  processed = 0;
  while (processed < (size_t)n)
    {
      /* Read length prefix first */
      while (conn->len_received < 2 && processed < (size_t)n)
        {
          conn->len_buf[conn->len_received++] = buf[processed++];
        }

      if (conn->len_received < 2)
        break; /* Need more data */

      /* Decode message length */
      if (conn->msg_len == 0)
        {
          conn->msg_len
              = ((size_t)conn->len_buf[0] << 8) | (size_t)conn->len_buf[1];

          /* Validate length - reject zero-length messages (CWE-476, CWE-400) */
          if (conn->msg_len == 0 || conn->msg_len > DOT_MAX_MESSAGE_SIZE)
            {
              /* Invalid length */
              close_connection (transport, conn);
              return -1;
            }

          /* Allocate receive buffer */
          if (!conn->recv_buf || conn->recv_alloc < conn->msg_len)
            {
              conn->recv_buf = ALLOC (transport->arena, conn->msg_len);
              conn->recv_alloc = conn->msg_len;
            }
          conn->recv_len = 0;
        }

      /* Read message body */
      size_t need = conn->msg_len - conn->recv_len;
      size_t avail = (size_t)n - processed;
      size_t copy = (need < avail) ? need : avail;

      memcpy (conn->recv_buf + conn->recv_len, buf + processed, copy);
      conn->recv_len += copy;
      processed += copy;

      /* Check if complete message */
      if (conn->recv_len == conn->msg_len)
        {
          /* Got complete message, return it */
          return 1;
        }
    }

  return 0;
}

/* Find query by ID */
static struct SocketDNSoverTLS_Query *
find_query_by_id (T transport, uint16_t id)
{
  struct SocketDNSoverTLS_Query *q;
  for (q = transport->pending_head; q != NULL; q = q->next)
    {
      if (q->id == id && !q->cancelled && !q->completed)
        return q;
    }
  return NULL;
}

/* Complete a query */
static void
complete_query (T transport, struct SocketDNSoverTLS_Query *query,
                const unsigned char *response, size_t len, int error)
{
  query->completed = 1;

  /* Remove from list */
  if (query->prev)
    query->prev->next = query->next;
  else
    transport->pending_head = query->next;

  if (query->next)
    query->next->prev = query->prev;
  else
    transport->pending_tail = query->prev;

  transport->pending_count--;

  /* Decrement memory tracking (CWE-770 mitigation) */
  if (transport->total_query_bytes >= query->query_len)
    {
      transport->total_query_bytes -= query->query_len;
    }
  else
    {
      transport->total_query_bytes = 0; /* Safety: prevent underflow */
    }

  /* Update stats */
  if (error == DOT_ERROR_SUCCESS)
    transport->stats.queries_completed++;
  else
    transport->stats.queries_failed++;

  /* Invoke callback */
  if (query->callback)
    {
      query->callback (query, response, len, error, query->userdata);
    }
}

/* Map DNS RCODE to error code */
static int
rcode_to_error (int rcode)
{
  switch (rcode)
    {
    case DNS_RCODE_NOERROR:
      return DOT_ERROR_SUCCESS;
    case DNS_RCODE_FORMERR:
      return DOT_ERROR_FORMERR;
    case DNS_RCODE_SERVFAIL:
      return DOT_ERROR_SERVFAIL;
    case DNS_RCODE_NXDOMAIN:
      return DOT_ERROR_NXDOMAIN;
    case DNS_RCODE_REFUSED:
      return DOT_ERROR_REFUSED;
    default:
      return DOT_ERROR_INVALID;
    }
}

/* Process received message */
static void
process_response (T transport)
{
  struct Connection *conn = &transport->conn;
  SocketDNS_Header hdr;
  struct SocketDNSoverTLS_Query *query;
  int error;

  if (conn->recv_len < DNS_HEADER_SIZE)
    {
      return; /* Invalid response */
    }

  /* Decode header */
  if (SocketDNS_header_decode (conn->recv_buf, conn->recv_len, &hdr) != 0)
    {
      return; /* Invalid header */
    }

  /* Find matching query */
  query = find_query_by_id (transport, hdr.id);
  if (!query)
    {
      return; /* Unknown query ID */
    }

  /* Check for errors */
  if (!hdr.qr)
    {
      return; /* Not a response */
    }

  error = rcode_to_error (hdr.rcode);
  complete_query (transport, query, conn->recv_buf, conn->recv_len, error);

  /* Reset receive state for next message */
  conn->len_received = 0;
  conn->msg_len = 0;
  conn->recv_len = 0;
}

/* Cancel pending queries with error */
static void
cancel_all_queries (T transport, int error)
{
  struct SocketDNSoverTLS_Query *q, *next;

  for (q = transport->pending_head; q != NULL; q = next)
    {
      next = q->next;
      complete_query (transport, q, NULL, 0, error);
    }
}

/* Queue all pending queries for sending after connection established */
static void
queue_pending_queries (T transport)
{
  struct SocketDNSoverTLS_Query *q;

  for (q = transport->pending_head; q != NULL; q = q->next)
    {
      if (!q->cancelled && !q->completed)
        {
          queue_query (transport, q);
        }
    }
}

/* Process query timeouts and idle connection timeout */
static int
process_query_timeouts (T transport, int64_t now)
{
  struct SocketDNSoverTLS_Query *q, *next;
  struct Connection *conn;
  int completed;

  completed = 0;
  conn = &transport->conn;

  /* Check query timeouts */
  for (q = transport->pending_head; q != NULL; q = next)
    {
      next = q->next;
      if (!q->cancelled && !q->completed)
        {
          if (now - q->sent_time_ms > transport->query_timeout_ms)
            {
              complete_query (transport, q, NULL, 0, DOT_ERROR_TIMEOUT);
              completed++;
            }
        }
    }

  /* Check idle timeout */
  if (conn->state == CONN_STATE_CONNECTED
      && now - conn->last_activity_ms > transport->idle_timeout_ms)
    {
      close_connection (transport, conn);
    }

  return completed;
}

/* Process connection state machine continuation */
static int
process_connection_state (T transport)
{
  struct Connection *conn;
  int ret;

  conn = &transport->conn;

  /* Continue connection if in progress */
  if (conn->state == CONN_STATE_CONNECTING
      || conn->state == CONN_STATE_HANDSHAKING)
    {
      ret = continue_connection (transport);
      if (ret < 0)
        {
          /* Connection failed, cancel pending queries */
          cancel_all_queries (transport, DOT_ERROR_TLS_HANDSHAKE);
          return -1;
        }

      if (ret > 0)
        {
          /* Just connected, queue pending queries */
          queue_pending_queries (transport);
          transport->stats.connections_reused++;
        }
    }

  /* Start connection if disconnected but have pending queries */
  if (conn->state == CONN_STATE_DISCONNECTED)
    {
      if (transport->pending_count > 0)
        {
          start_connection (transport, transport->current_server);
        }
      return 0;
    }

  return 1; /* Connection ready or in progress */
}

/* Determine poll events based on connection state */
static int
get_poll_events (const struct Connection *conn)
{
  int events = POLLIN;

  if (conn->state == CONN_STATE_CONNECTING
      || conn->state == CONN_STATE_HANDSHAKING || conn->send_len > 0)
    {
      events |= POLLOUT;
    }

  return events;
}

/* Handle connection state machine progression */
static int
handle_connection_progress (T transport, struct Connection *conn)
{
  int ret;

  if (conn->state != CONN_STATE_CONNECTING
      && conn->state != CONN_STATE_HANDSHAKING)
    {
      return 0;
    }

  ret = continue_connection (transport);
  if (ret < 0)
    {
      cancel_all_queries (transport, DOT_ERROR_TLS_HANDSHAKE);
      return -1;
    }

  if (ret > 0)
    {
      /* Just connected, queue pending queries */
      queue_pending_queries (transport);
    }

  return ret;
}

/* Handle socket events for connected state */
static int
handle_connected_io (T transport, struct Connection *conn, short revents)
{
  int completed = 0;
  int ret;

  (void)conn;

  /* Send pending data */
  if (revents & POLLOUT)
    {
      send_pending (transport);
    }

  /* Receive data */
  if (revents & POLLIN)
    {
      ret = receive_data (transport);
      if (ret > 0)
        {
          process_response (transport);
          completed++;
        }
    }

  return completed;
}

/* Process socket I/O (poll, send, receive) */
static int
process_socket_io (T transport, int timeout_ms)
{
  struct Connection *conn;
  struct pollfd pfd;
  int fd;
  int ret;

  conn = &transport->conn;

  /* Get socket file descriptor */
  fd = Socket_fd (conn->socket);
  if (fd < 0)
    return 0;

  /* Setup poll */
  pfd.fd = fd;
  pfd.events = (short)get_poll_events (conn);
  pfd.revents = 0;

  /* Poll socket */
  ret = poll (&pfd, 1, timeout_ms);
  if (ret <= 0)
    return 0;

  /* Check for errors */
  if (pfd.revents & (POLLERR | POLLHUP))
    {
      close_connection (transport, conn);
      cancel_all_queries (transport, DOT_ERROR_NETWORK);
      return 0;
    }

  /* Handle connection progress */
  if (handle_connection_progress (transport, conn) < 0)
    return 0;

  /* Handle I/O for connected state */
  if (conn->state == CONN_STATE_CONNECTED)
    return handle_connected_io (transport, conn, pfd.revents);

  return 0;
}

/* ============================================================================
 * Public API
 * ============================================================================
 */

T
SocketDNSoverTLS_new (Arena_T arena)
{
  T transport;

  assert (arena);

  transport = ALLOC (arena, sizeof (*transport));
  memset (transport, 0, sizeof (*transport));

  transport->arena = arena;
  transport->handshake_timeout_ms = DOT_HANDSHAKE_TIMEOUT_MS;
  transport->query_timeout_ms = DOT_DEFAULT_QUERY_TIMEOUT_MS;
  transport->idle_timeout_ms = DOT_IDLE_TIMEOUT_MS;

  init_connection (&transport->conn);

  return transport;
}

void
SocketDNSoverTLS_free (T *transport_p)
{
  T transport;

  if (!transport_p || !*transport_p)
    return;

  transport = *transport_p;

  /* Cancel all pending queries */
  cancel_all_queries (transport, DOT_ERROR_CANCELLED);

  /* Close connection */
  close_connection (transport, &transport->conn);

  *transport_p = NULL;
}

int
SocketDNSoverTLS_configure (T transport, const SocketDNSoverTLS_Config *config)
{
  struct ServerConfig *server;
  int family;

  assert (transport);
  assert (config);
  assert (config->server_address);

  if (transport->server_count >= DOT_MAX_CONNECTIONS)
    return -1;

  family = detect_address_family (config->server_address);
  if (family < 0)
    return -1;

  server = &transport->servers[transport->server_count];
  memset (server, 0, sizeof (*server));

  socket_util_safe_strncpy (server->address, config->server_address, sizeof (server->address));
  server->port = (config->port > 0) ? config->port : DOT_PORT;
  server->family = family;
  server->mode = config->mode;

  if (config->server_name)
    {
      socket_util_safe_strncpy (server->server_name, config->server_name,
                                sizeof (server->server_name));
    }
  else
    {
      /* Use address as SNI if no server name provided */
      socket_util_safe_strncpy (server->server_name, config->server_address,
                                sizeof (server->server_name));
    }

  if (config->spki_pin)
    {
      socket_util_safe_strncpy (server->spki_pin, config->spki_pin, sizeof (server->spki_pin));
    }

  if (config->spki_pin_backup)
    {
      socket_util_safe_strncpy (server->spki_pin_backup, config->spki_pin_backup,
                                sizeof (server->spki_pin_backup));
    }

  transport->server_count++;
  return 0;
}

int
SocketDNSoverTLS_add_server (T transport, const char *server_name,
                             SocketDNSoverTLS_Mode mode)
{
  SocketDNSoverTLS_Config config;
  int i;

  assert (transport);
  assert (server_name);

  /* Look up well-known server */
  for (i = 0; well_known_servers[i].name != NULL; i++)
    {
      if (strcmp (server_name, well_known_servers[i].name) == 0)
        {
          memset (&config, 0, sizeof (config));
          config.server_address = well_known_servers[i].address;
          config.port = DOT_PORT;
          config.server_name = well_known_servers[i].server_name;
          config.mode = mode;
          return SocketDNSoverTLS_configure (transport, &config);
        }
    }

  return -1; /* Unknown server */
}

void
SocketDNSoverTLS_clear_servers (T transport)
{
  assert (transport);

  close_connection (transport, &transport->conn);
  transport->server_count = 0;
  transport->current_server = 0;
}

int
SocketDNSoverTLS_server_count (T transport)
{
  assert (transport);
  return transport->server_count;
}

/* Validate query can be submitted */
static int
validate_query_submission (T transport, size_t query_len)
{
  if (transport->server_count == 0)
    return -1;

  /* Validate query length to prevent memory exhaustion (CWE-770) */
  if (query_len > DOT_MAX_MESSAGE_SIZE)
    return -1;

  if (transport->pending_count >= DOT_MAX_PENDING_QUERIES)
    return -1;

  /* Check cumulative memory limit (CWE-770 mitigation) */
  if (transport->total_query_bytes + query_len > DOT_MAX_TOTAL_QUERY_BYTES)
    return -1;

  return 0;
}

/* Allocate and initialize query structure */
static struct SocketDNSoverTLS_Query *
create_query (T transport, const unsigned char *query, size_t len,
              uint16_t id, SocketDNSoverTLS_Callback callback, void *userdata)
{
  struct SocketDNSoverTLS_Query *q;

  q = ALLOC (transport->arena, sizeof (*q));
  memset (q, 0, sizeof (*q));

  q->id = id;
  q->query = ALLOC (transport->arena, len);
  memcpy (q->query, query, len);
  q->query_len = len;
  q->sent_time_ms = get_monotonic_ms ();
  q->callback = callback;
  q->userdata = userdata;

  return q;
}

/* Add query to pending list */
static void
enqueue_query (T transport, struct SocketDNSoverTLS_Query *q)
{
  q->next = NULL;
  q->prev = transport->pending_tail;
  if (transport->pending_tail)
    transport->pending_tail->next = q;
  else
    transport->pending_head = q;
  transport->pending_tail = q;
  transport->pending_count++;
  transport->stats.queries_sent++;
}

/* Ensure connection is established, with fallback */
static int
ensure_connected (T transport)
{
  if (transport->conn.state != CONN_STATE_DISCONNECTED)
    return 0; /* Already connecting or connected */

  /* Try current server */
  if (start_connection (transport, transport->current_server) == 0)
    return 0;

  /* Fallback to next server - protect against division by zero (CWE-369) */
  if (transport->server_count > 0)
    {
      transport->current_server
          = (transport->current_server + 1) % transport->server_count;
      if (start_connection (transport, transport->current_server) == 0)
        return 0;
    }

  return -1; /* All servers failed */
}

SocketDNSoverTLS_Query_T
SocketDNSoverTLS_query (T transport, const unsigned char *query, size_t len,
                        SocketDNSoverTLS_Callback callback, void *userdata)
{
  struct SocketDNSoverTLS_Query *q;
  SocketDNS_Header hdr;

  assert (transport);
  assert (query);
  assert (callback);
  assert (len >= DNS_HEADER_SIZE);

  /* Validate submission */
  if (validate_query_submission (transport, len) < 0)
    return NULL;

  /* Parse query ID */
  if (SocketDNS_header_decode (query, len, &hdr) != 0)
    return NULL;

  /* Create query */
  q = create_query (transport, query, len, hdr.id, callback, userdata);

  /* Track memory (CWE-770 mitigation) */
  transport->total_query_bytes += len;

  /* Add to pending list */
  enqueue_query (transport, q);

  /* Ensure connection */
  if (ensure_connected (transport) < 0)
    {
      complete_query (transport, q, NULL, 0, DOT_ERROR_NETWORK);
      return NULL;
    }

  /* Queue for sending if ready */
  if (transport->conn.state == CONN_STATE_CONNECTED)
    queue_query (transport, q);

  return q;
}

int
SocketDNSoverTLS_cancel (T transport, SocketDNSoverTLS_Query_T query)
{
  assert (transport);

  if (!query || query->cancelled || query->completed)
    return -1;

  query->cancelled = 1;
  complete_query (transport, query, NULL, 0, DOT_ERROR_CANCELLED);
  return 0;
}

uint16_t
SocketDNSoverTLS_query_id (SocketDNSoverTLS_Query_T query)
{
  assert (query);
  return query->id;
}

int
SocketDNSoverTLS_process (T transport, int timeout_ms)
{
  int completed;
  int64_t now;
  int state_result;

  assert (transport);

  completed = 0;
  now = get_monotonic_ms ();

  /* Handle timeouts */
  completed += process_query_timeouts (transport, now);

  /* No server configured */
  if (transport->server_count == 0)
    {
      return completed;
    }

  /* Process connection state machine */
  state_result = process_connection_state (transport);
  if (state_result < 0)
    {
      /* Connection failed */
      return completed;
    }

  if (state_result == 0)
    {
      /* Disconnected, no I/O to perform */
      return completed;
    }

  /* Handle I/O */
  completed += process_socket_io (transport, timeout_ms);

  return completed;
}

int
SocketDNSoverTLS_fd (T transport)
{
  assert (transport);

  if (transport->conn.socket
      && transport->conn.state != CONN_STATE_DISCONNECTED)
    {
      return Socket_fd (transport->conn.socket);
    }

  return -1;
}

int
SocketDNSoverTLS_pending_count (T transport)
{
  assert (transport);
  return transport->pending_count;
}

void
SocketDNSoverTLS_close_all (T transport)
{
  assert (transport);

  cancel_all_queries (transport, DOT_ERROR_CANCELLED);
  close_connection (transport, &transport->conn);
}

int
SocketDNSoverTLS_is_connected (T transport)
{
  assert (transport);
  return (transport->conn.state == CONN_STATE_CONNECTED) ? 1 : 0;
}

void
SocketDNSoverTLS_stats (T transport, SocketDNSoverTLS_Stats *stats)
{
  assert (transport);
  assert (stats);
  *stats = transport->stats;
}

/* Dispatch table for error messages */
static const char *error_messages[] = {
  [0]  = "Success",
  [1]  = "Query timeout",
  [2]  = "Query cancelled",
  [3]  = "Network error",
  [4]  = "TLS handshake failed",
  [5]  = "Certificate verification failed",
  [6]  = "TLS I/O error",
  [7]  = "Invalid response",
  [8]  = "No server configured",
  [9]  = "Server returned FORMERR",
  [10] = "Server returned SERVFAIL",
  [11] = "Domain does not exist",
  [12] = "Server refused query",
  [13] = "SPKI pin mismatch",
};

#define ERROR_MESSAGE_COUNT (sizeof (error_messages) / sizeof (error_messages[0]))

const char *
SocketDNSoverTLS_strerror (int error)
{
  /* Convert error code to array index (error codes are negative or zero) */
  int index = (error <= 0) ? -error : error;

  if (index >= (int) ERROR_MESSAGE_COUNT)
    return "Unknown error";

  return error_messages[index];
}

#endif /* SOCKET_HAS_TLS */
