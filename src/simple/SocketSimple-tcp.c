/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * @file SocketSimple-tcp.c
 * @brief TCP/UDP implementation for Simple API.
 *
 * Uses library convenience functions (Socket_connect_tcp, Socket_listen_tcp,
 * SocketDgram_bind_udp) which handle address family detection automatically.
 */

#include "SocketSimple-internal.h"

#include "socket/SocketCommon.h"

/* ============================================================================
 * Helper Functions
 * ============================================================================
 */

/**
 * @brief Check if an error code represents a timeout condition.
 *
 * Centralizes timeout detection logic to ensure consistent handling across
 * all timeout-capable functions. Checks for retryable errors that specifically
 * indicate timeout conditions (ETIMEDOUT, EAGAIN, EINPROGRESS).
 *
 * @param err The error number to check (typically from Socket_geterrno())
 * @return 1 if the error represents a timeout, 0 otherwise
 */
static inline int
is_timeout_error (int err)
{
  return Socket_error_is_retryable (err)
         && (err == ETIMEDOUT || err == EAGAIN || err == EINPROGRESS);
}

/* ============================================================================
 * TCP Client Functions
 * ============================================================================
 */

SocketSimple_Socket_T
Socket_simple_connect (const char *host, int port)
{
  /* Use timeout version with default timeout */
  return Socket_simple_connect_timeout (host, port, SOCKET_SIMPLE_DEFAULT_TIMEOUT_MS);
}

SocketSimple_Socket_T
Socket_simple_connect_timeout (const char *host, int port, int timeout_ms)
{
  volatile Socket_T sock = NULL;

  Socket_simple_clear_error ();

  if (!host || port <= 0 || port > 65535)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid host or port");
      return NULL;
    }

  TRY
  {
    /* Use library convenience function - handles address family automatically
     */
    sock = Socket_connect_tcp (host, port, timeout_ms);
  }
  EXCEPT (Socket_Failed)
  {
    int err = Socket_geterrno ();
    if (is_timeout_error (err))
      {
        simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "Connection timed out");
      }
    else
      {
        simple_set_error_errno (SOCKET_SIMPLE_ERR_CONNECT,
                                "Connection failed");
      }
    if (sock)
      Socket_free ((Socket_T *)&sock);
    return NULL;
  }
  END_TRY;

  SocketSimple_Socket_T handle = simple_create_handle (sock, 0, 0);
  if (!handle)
    {
      Socket_free ((Socket_T *)&sock);
    }
  return handle;
}

/* ============================================================================
 * TCP Server Functions
 * ============================================================================
 */

SocketSimple_Socket_T
Socket_simple_listen (const char *host, int port, int backlog)
{
  volatile Socket_T sock = NULL;

  Socket_simple_clear_error ();

  if (port <= 0 || port > 65535)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid port");
      return NULL;
    }

  TRY
  {
    /* Use library convenience function - handles address family automatically
     */
    sock = Socket_listen_tcp (host ? host : "0.0.0.0", port,
                              backlog > 0 ? backlog : SOCKET_SIMPLE_DEFAULT_BACKLOG);
  }
  EXCEPT (Socket_Failed)
  {
    int err = Socket_geterrno ();
    if (err == EADDRINUSE)
      {
        simple_set_error (SOCKET_SIMPLE_ERR_BIND, "Address already in use");
      }
    else
      {
        simple_set_error_errno (SOCKET_SIMPLE_ERR_LISTEN, "Listen failed");
      }
    if (sock)
      Socket_free ((Socket_T *)&sock);
    return NULL;
  }
  END_TRY;

  SocketSimple_Socket_T handle = simple_create_handle (sock, 1, 0);
  if (!handle)
    {
      Socket_free ((Socket_T *)&sock);
    }
  return handle;
}

SocketSimple_Socket_T
Socket_simple_accept (SocketSimple_Socket_T server)
{
  volatile Socket_T client = NULL;

  Socket_simple_clear_error ();

  if (!server || !server->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid server socket");
      return NULL;
    }

  TRY { client = Socket_accept (server->socket); }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_ACCEPT, "Accept failed");
    return NULL;
  }
  END_TRY;

  SocketSimple_Socket_T handle = simple_create_handle (client, 0, 0);
  if (!handle)
    {
      Socket_free ((Socket_T *)&client);
    }
  return handle;
}

SocketSimple_Socket_T
Socket_simple_accept_timeout (SocketSimple_Socket_T server, int timeout_ms)
{
  volatile Socket_T client = NULL;

  Socket_simple_clear_error ();

  if (!server || !server->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid server socket");
      return NULL;
    }

  TRY { client = Socket_accept_timeout (server->socket, timeout_ms); }
  EXCEPT (Socket_Failed)
  {
    int err = Socket_geterrno ();
    if (is_timeout_error (err))
      {
        simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "Accept timed out");
      }
    else
      {
        simple_set_error_errno (SOCKET_SIMPLE_ERR_ACCEPT, "Accept failed");
      }
    return NULL;
  }
  END_TRY;

  SocketSimple_Socket_T handle = simple_create_handle (client, 0, 0);
  if (!handle)
    {
      Socket_free ((Socket_T *)&client);
    }
  return handle;
}

/* ============================================================================
 * I/O Functions
 * ============================================================================
 */

int
Socket_simple_send (SocketSimple_Socket_T sock, const void *data, size_t len)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket || !data)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  TRY { Socket_sendall (sock->socket, data, len); }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_SEND, "Send failed");
    return -1;
  }
  EXCEPT (Socket_Closed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_CLOSED, "Connection closed");
    sock->is_connected = 0;
    return -1;
  }
  END_TRY;

  return 0;
}

ssize_t
Socket_simple_recv (SocketSimple_Socket_T sock, void *buf, size_t len)
{
  volatile ssize_t n = 0;

  Socket_simple_clear_error ();

  if (!sock || !sock->socket || !buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  TRY { n = Socket_recv (sock->socket, buf, len); }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_RECV, "Receive failed");
    return -1;
  }
  EXCEPT (Socket_Closed)
  {
    sock->is_connected = 0;
    return 0;
  }
  END_TRY;

  if (n == 0)
    {
      sock->is_connected = 0;
    }
  return n;
}

ssize_t
Socket_simple_recv_timeout (SocketSimple_Socket_T sock, void *buf, size_t len,
                            int timeout_ms)
{
  volatile ssize_t n = 0;
  volatile int timed_out = 0;

  Socket_simple_clear_error ();

  if (!sock || !sock->socket || !buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  TRY
  {
    int ready = Socket_probe (sock->socket, timeout_ms);
    if (!ready)
      {
        simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "Receive timed out");
        timed_out = 1;
      }
    else
      {
        n = Socket_recv (sock->socket, buf, len);
      }
  }
  EXCEPT (Socket_Failed)
  {
    int err = Socket_geterrno ();
    if (is_timeout_error (err))
      {
        simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "Receive timed out");
      }
    else
      {
        simple_set_error_errno (SOCKET_SIMPLE_ERR_RECV, "Receive failed");
      }
    return -1;
  }
  EXCEPT (Socket_Closed)
  {
    sock->is_connected = 0;
    return 0;
  }
  END_TRY;

  if (timed_out)
    {
      return -1;
    }

  if (n == 0)
    {
      sock->is_connected = 0;
    }
  return n;
}

int
Socket_simple_recv_all (SocketSimple_Socket_T sock, void *buf, size_t len)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket || !buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  TRY { Socket_recvall (sock->socket, buf, len); }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_RECV, "Receive failed");
    return -1;
  }
  EXCEPT (Socket_Closed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_CLOSED,
                      "Connection closed before all data received");
    sock->is_connected = 0;
    return -1;
  }
  END_TRY;

  return 0;
}

#define RECV_LINE_BUFFER_SIZE 4096

ssize_t
Socket_simple_recv_line (SocketSimple_Socket_T sock, char *buf, size_t maxlen)
{
  static __thread char internal_buffer[RECV_LINE_BUFFER_SIZE];
  static __thread size_t buffer_pos = 0;
  static __thread ssize_t buffer_len = 0;
  static __thread Socket_T last_socket = NULL;

  Socket_simple_clear_error ();

  if (!sock || !sock->socket || !buf || maxlen == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  /* Reset buffer if socket changed */
  if (last_socket != sock->socket)
    {
      buffer_pos = 0;
      buffer_len = 0;
      last_socket = sock->socket;
    }

  size_t pos = 0;
  while (pos < maxlen - 1)
    {
      /* Refill buffer if empty */
      if (buffer_pos >= (size_t)buffer_len)
        {
          buffer_len
              = Socket_simple_recv (sock, internal_buffer, sizeof (internal_buffer));
          if (buffer_len < 0)
            return -1;
          if (buffer_len == 0)
            break; /* EOF */
          buffer_pos = 0;
        }

      /* Copy from buffer to output, stopping at newline */
      char c = internal_buffer[buffer_pos++];
      buf[pos++] = c;
      if (c == '\n')
        break;
    }

  buf[pos] = '\0';
  return (ssize_t)pos;
}

/* ============================================================================
 * Socket Options
 * ============================================================================
 */

int
Socket_simple_set_timeout (SocketSimple_Socket_T sock, int send_ms,
                           int recv_ms)
{
  int timeout_sec;

  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  timeout_sec = (send_ms > recv_ms ? send_ms : recv_ms) / 1000;
  if (timeout_sec <= 0)
    {
      timeout_sec = 1;
    }

  TRY { Socket_settimeout (sock->socket, timeout_sec); }
  EXCEPT (Socket_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_SOCKET, "Failed to set timeout");
    return -1;
  }
  END_TRY;

  return 0;
}

int
Socket_simple_fd (SocketSimple_Socket_T sock)
{
  if (!sock)
    return -1;
  if (sock->dgram)
    return SocketDgram_fd (sock->dgram);
  if (sock->socket)
    return Socket_fd (sock->socket);
  return -1;
}

int
Socket_simple_is_connected (SocketSimple_Socket_T sock)
{
  if (!sock)
    return 0;
  return sock->is_connected;
}

/* ============================================================================
 * Cleanup
 * ============================================================================
 */

void
Socket_simple_close (SocketSimple_Socket_T *sock)
{
  if (!sock || !*sock)
    return;

  struct SocketSimple_Socket *s = *sock;

#ifdef SOCKET_HAS_TLS
  if (s->tls_ctx)
    {
      SocketTLSContext_free (&s->tls_ctx);
    }
#endif

  if (s->dgram)
    {
      SocketDgram_free (&s->dgram);
    }

  if (s->socket)
    {
      Socket_free (&s->socket);
    }

  free (s);
  *sock = NULL;
}

/* ============================================================================
 * UDP Functions
 * ============================================================================
 */

SocketSimple_Socket_T
Socket_simple_udp_bind (const char *host, int port)
{
  volatile SocketDgram_T dgram = NULL;

  Socket_simple_clear_error ();

  if (port <= 0 || port > 65535)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid port");
      return NULL;
    }

  TRY
  {
    /* Use library convenience function - handles address family automatically
     */
    dgram = SocketDgram_bind_udp (host ? host : "0.0.0.0", port);
  }
  EXCEPT (SocketDgram_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_BIND, "UDP bind failed");
    if (dgram)
      SocketDgram_free ((SocketDgram_T *)&dgram);
    return NULL;
  }
  END_TRY;

  SocketSimple_Socket_T handle = simple_create_udp_handle (dgram);
  if (!handle)
    {
      SocketDgram_free ((SocketDgram_T *)&dgram);
    }
  return handle;
}

SocketSimple_Socket_T
Socket_simple_udp_new (void)
{
  volatile SocketDgram_T dgram = NULL;

  Socket_simple_clear_error ();

  TRY { dgram = SocketDgram_new (AF_INET, 0); }
  EXCEPT (SocketDgram_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_SOCKET, "Failed to create UDP socket");
    return NULL;
  }
  END_TRY;

  SocketSimple_Socket_T handle = simple_create_udp_handle (dgram);
  if (!handle)
    {
      SocketDgram_free ((SocketDgram_T *)&dgram);
    }
  return handle;
}

int
Socket_simple_udp_sendto (SocketSimple_Socket_T sock, const void *data,
                          size_t len, const char *host, int port)
{
  volatile ssize_t sent = 0;

  Socket_simple_clear_error ();

  if (!sock || !sock->dgram || !data || !host)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  if (port <= 0 || port > 65535)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid port");
      return -1;
    }

  TRY { sent = SocketDgram_sendto (sock->dgram, data, len, host, port); }
  EXCEPT (SocketDgram_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_SEND, "UDP send failed");
    return -1;
  }
  END_TRY;

  return (sent > 0) ? 0 : -1;
}

ssize_t
Socket_simple_udp_recvfrom (SocketSimple_Socket_T sock, void *buf, size_t len,
                            char *from_host, size_t host_len, int *from_port)
{
  volatile ssize_t received = 0;

  Socket_simple_clear_error ();

  if (!sock || !sock->dgram || !buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  TRY
  {
    received = SocketDgram_recvfrom (sock->dgram, buf, len, from_host,
                                     host_len, from_port);
  }
  EXCEPT (SocketDgram_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_RECV, "UDP receive failed");
    return -1;
  }
  END_TRY;

  return received;
}

/* ============================================================================
 * UDP Advanced Features (Multicast, Broadcast)
 * ============================================================================
 */

#include <netinet/in.h>
#include <arpa/inet.h>

int
Socket_simple_udp_join_multicast (SocketSimple_Socket_T sock, const char *group,
                                   const char *iface)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->dgram || !group)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  TRY { SocketDgram_joinmulticast (sock->dgram, group, iface); }
  EXCEPT (SocketDgram_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                            "Failed to join multicast group");
    return -1;
  }
  END_TRY;

  return 0;
}

int
Socket_simple_udp_leave_multicast (SocketSimple_Socket_T sock,
                                    const char *group, const char *iface)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->dgram || !group)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  TRY { SocketDgram_leavemulticast (sock->dgram, group, iface); }
  EXCEPT (SocketDgram_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                            "Failed to leave multicast group");
    return -1;
  }
  END_TRY;

  return 0;
}

int
Socket_simple_udp_set_multicast_ttl (SocketSimple_Socket_T sock, int ttl)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->dgram)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  if (ttl < 0 || ttl > 255)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "TTL must be 0-255");
      return -1;
    }

  int fd = SocketDgram_fd (sock->dgram);
  unsigned char ttl_val = (unsigned char)ttl;

  if (setsockopt (fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl_val, sizeof (ttl_val))
      < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to set multicast TTL");
      return -1;
    }

  return 0;
}

int
Socket_simple_udp_set_multicast_loopback (SocketSimple_Socket_T sock,
                                           int enable)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->dgram)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  int fd = SocketDgram_fd (sock->dgram);
  unsigned char loop = enable ? 1 : 0;

  if (setsockopt (fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof (loop)) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to set multicast loopback");
      return -1;
    }

  return 0;
}

int
Socket_simple_udp_set_multicast_interface (SocketSimple_Socket_T sock,
                                            const char *iface)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->dgram)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  int fd = SocketDgram_fd (sock->dgram);
  struct in_addr addr;

  if (iface)
    {
      if (inet_pton (AF_INET, iface, &addr) != 1)
        {
          simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                            "Invalid interface address");
          return -1;
        }
    }
  else
    {
      addr.s_addr = INADDR_ANY;
    }

  if (setsockopt (fd, IPPROTO_IP, IP_MULTICAST_IF, &addr, sizeof (addr)) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to set multicast interface");
      return -1;
    }

  return 0;
}

int
Socket_simple_udp_set_broadcast (SocketSimple_Socket_T sock, int enable)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->dgram)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  int fd = SocketDgram_fd (sock->dgram);
  int val = enable ? 1 : 0;

  if (setsockopt (fd, SOL_SOCKET, SO_BROADCAST, &val, sizeof (val)) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to set broadcast");
      return -1;
    }

  return 0;
}

int
Socket_simple_udp_set_ttl (SocketSimple_Socket_T sock, int ttl)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->dgram)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  if (ttl < 0 || ttl > 255)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "TTL must be 0-255");
      return -1;
    }

  int fd = SocketDgram_fd (sock->dgram);

  if (setsockopt (fd, IPPROTO_IP, IP_TTL, &ttl, sizeof (ttl)) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET, "Failed to set TTL");
      return -1;
    }

  return 0;
}

int
Socket_simple_udp_connect (SocketSimple_Socket_T sock, const char *host,
                            int port)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->dgram || !host)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  if (port <= 0 || port > 65535)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid port");
      return -1;
    }

  TRY { SocketDgram_connect (sock->dgram, host, port); }
  EXCEPT (SocketDgram_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_CONNECT, "UDP connect failed");
    return -1;
  }
  END_TRY;

  return 0;
}

ssize_t
Socket_simple_udp_send (SocketSimple_Socket_T sock, const void *data,
                         size_t len)
{
  volatile ssize_t sent = 0;

  Socket_simple_clear_error ();

  if (!sock || !sock->dgram || !data)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  TRY { sent = SocketDgram_send (sock->dgram, data, len); }
  EXCEPT (SocketDgram_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_SEND, "UDP send failed");
    return -1;
  }
  END_TRY;

  return sent;
}

ssize_t
Socket_simple_udp_recv (SocketSimple_Socket_T sock, void *buf, size_t len)
{
  volatile ssize_t received = 0;

  Socket_simple_clear_error ();

  if (!sock || !sock->dgram || !buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  TRY { received = SocketDgram_recv (sock->dgram, buf, len); }
  EXCEPT (SocketDgram_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_RECV, "UDP receive failed");
    return -1;
  }
  END_TRY;

  return received;
}

/* ============================================================================
 * Unix Domain Socket Functions
 * ============================================================================
 */

#include <sys/un.h>
#include <unistd.h>

SocketSimple_Socket_T
Socket_simple_connect_unix (const char *path)
{
  volatile Socket_T sock = NULL;

  Socket_simple_clear_error ();

  if (!path || path[0] == '\0')
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket path");
      return NULL;
    }

  TRY
  {
    sock = Socket_new (AF_UNIX, SOCK_STREAM, 0);
    Socket_connect_unix (sock, path);
  }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_CONNECT,
                            "Unix socket connect failed");
    if (sock)
      Socket_free ((Socket_T *)&sock);
    return NULL;
  }
  END_TRY;

  SocketSimple_Socket_T handle = simple_create_handle (sock, 0, 0);
  if (!handle)
    {
      Socket_free ((Socket_T *)&sock);
    }
  return handle;
}

SocketSimple_Socket_T
Socket_simple_listen_unix (const char *path, int backlog)
{
  volatile Socket_T sock = NULL;

  Socket_simple_clear_error ();

  if (!path || path[0] == '\0')
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket path");
      return NULL;
    }

  /* Remove existing socket file if it exists */
  unlink (path);

  TRY
  {
    sock = Socket_new (AF_UNIX, SOCK_STREAM, 0);
    Socket_bind_unix (sock, path);
    Socket_listen (sock, backlog > 0 ? backlog : SOCKET_SIMPLE_DEFAULT_BACKLOG);
  }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_LISTEN,
                            "Unix socket listen failed");
    if (sock)
      Socket_free ((Socket_T *)&sock);
    return NULL;
  }
  END_TRY;

  SocketSimple_Socket_T handle = simple_create_handle (sock, 1, 0);
  if (!handle)
    {
      Socket_free ((Socket_T *)&sock);
    }
  return handle;
}

/* ============================================================================
 * TCP Socket Options
 * ============================================================================
 */

#include <netinet/tcp.h>
#include <fcntl.h>

int
Socket_simple_set_nodelay (SocketSimple_Socket_T sock, int enable)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  TRY { Socket_setnodelay (sock->socket, enable); }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                            "Failed to set TCP_NODELAY");
    return -1;
  }
  END_TRY;

  return 0;
}

int
Socket_simple_get_nodelay (SocketSimple_Socket_T sock)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  int fd = Socket_fd (sock->socket);
  int val = 0;
  socklen_t len = sizeof (val);

  if (getsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &val, &len) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to get TCP_NODELAY");
      return -1;
    }

  return val ? 1 : 0;
}

/* ============================================================================
 * Keepalive Helper Functions
 * ============================================================================
 */

static int
set_keepalive_idle (int fd, int idle_secs)
{
#ifdef TCP_KEEPIDLE
  if (idle_secs <= 0)
    return 0;

  if (setsockopt (fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle_secs,
                  sizeof (idle_secs))
      < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to set TCP_KEEPIDLE");
      return -1;
    }
#else
  (void)fd;
  (void)idle_secs;
#endif
  return 0;
}

static int
set_keepalive_interval (int fd, int interval_secs)
{
#ifdef TCP_KEEPINTVL
  if (interval_secs <= 0)
    return 0;

  if (setsockopt (fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval_secs,
                  sizeof (interval_secs))
      < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to set TCP_KEEPINTVL");
      return -1;
    }
#else
  (void)fd;
  (void)interval_secs;
#endif
  return 0;
}

static int
set_keepalive_count (int fd, int count)
{
#ifdef TCP_KEEPCNT
  if (count <= 0)
    return 0;

  if (setsockopt (fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof (count)) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to set TCP_KEEPCNT");
      return -1;
    }
#else
  (void)fd;
  (void)count;
#endif
  return 0;
}

/* ============================================================================
 * Keepalive Configuration
 * ============================================================================
 */

int
Socket_simple_set_keepalive (SocketSimple_Socket_T sock, int enable,
                              int idle_secs, int interval_secs, int count)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  int fd = Socket_fd (sock->socket);
  int val = enable ? 1 : 0;

  if (setsockopt (fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof (val)) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to set SO_KEEPALIVE");
      return -1;
    }

  if (!enable)
    return 0;

  if (set_keepalive_idle (fd, idle_secs) < 0)
    return -1;
  if (set_keepalive_interval (fd, interval_secs) < 0)
    return -1;
  if (set_keepalive_count (fd, count) < 0)
    return -1;

  return 0;
}

int
Socket_simple_get_keepalive (SocketSimple_Socket_T sock, int *enabled,
                              int *idle_secs, int *interval_secs, int *count)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket || !enabled)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  int fd = Socket_fd (sock->socket);
  int val = 0;
  socklen_t len = sizeof (val);

  if (getsockopt (fd, SOL_SOCKET, SO_KEEPALIVE, &val, &len) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to get SO_KEEPALIVE");
      return -1;
    }

  *enabled = val ? 1 : 0;

#ifdef TCP_KEEPIDLE
  if (idle_secs)
    {
      len = sizeof (*idle_secs);
      if (getsockopt (fd, IPPROTO_TCP, TCP_KEEPIDLE, idle_secs, &len) < 0)
        {
          simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                                  "Failed to get TCP_KEEPIDLE");
          return -1;
        }
    }
#endif
#ifdef TCP_KEEPINTVL
  if (interval_secs)
    {
      len = sizeof (*interval_secs);
      if (getsockopt (fd, IPPROTO_TCP, TCP_KEEPINTVL, interval_secs, &len) < 0)
        {
          simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                                  "Failed to get TCP_KEEPINTVL");
          return -1;
        }
    }
#endif
#ifdef TCP_KEEPCNT
  if (count)
    {
      len = sizeof (*count);
      if (getsockopt (fd, IPPROTO_TCP, TCP_KEEPCNT, count, &len) < 0)
        {
          simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                                  "Failed to get TCP_KEEPCNT");
          return -1;
        }
    }
#endif

  return 0;
}

int
Socket_simple_set_sndbuf (SocketSimple_Socket_T sock, int size)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  int fd = Socket_fd (sock->socket);

  if (setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof (size)) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to set SO_SNDBUF");
      return -1;
    }

  return 0;
}

int
Socket_simple_get_sndbuf (SocketSimple_Socket_T sock)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  int fd = Socket_fd (sock->socket);
  int val = 0;
  socklen_t len = sizeof (val);

  if (getsockopt (fd, SOL_SOCKET, SO_SNDBUF, &val, &len) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to get SO_SNDBUF");
      return -1;
    }

  return val;
}

int
Socket_simple_set_rcvbuf (SocketSimple_Socket_T sock, int size)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  int fd = Socket_fd (sock->socket);

  if (setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof (size)) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to set SO_RCVBUF");
      return -1;
    }

  return 0;
}

int
Socket_simple_get_rcvbuf (SocketSimple_Socket_T sock)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  int fd = Socket_fd (sock->socket);
  int val = 0;
  socklen_t len = sizeof (val);

  if (getsockopt (fd, SOL_SOCKET, SO_RCVBUF, &val, &len) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to get SO_RCVBUF");
      return -1;
    }

  return val;
}

int
Socket_simple_set_blocking (SocketSimple_Socket_T sock, int blocking)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  int fd = Socket_fd (sock->socket);
  int flags = fcntl (fd, F_GETFL, 0);

  if (flags < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to get socket flags");
      return -1;
    }

  if (blocking)
    flags &= ~O_NONBLOCK;
  else
    flags |= O_NONBLOCK;

  if (fcntl (fd, F_SETFL, flags) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to set socket flags");
      return -1;
    }

  return 0;
}

int
Socket_simple_is_blocking (SocketSimple_Socket_T sock)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  int fd = Socket_fd (sock->socket);
  int flags = fcntl (fd, F_GETFL, 0);

  if (flags < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to get socket flags");
      return -1;
    }

  return (flags & O_NONBLOCK) ? 0 : 1;
}

int
Socket_simple_set_reuseaddr (SocketSimple_Socket_T sock, int enable)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  int fd = Socket_fd (sock->socket);
  int val = enable ? 1 : 0;

  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof (val)) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to set SO_REUSEADDR");
      return -1;
    }

  return 0;
}

int
Socket_simple_set_reuseport (SocketSimple_Socket_T sock, int enable)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

#ifdef SO_REUSEPORT
  int fd = Socket_fd (sock->socket);
  int val = enable ? 1 : 0;

  if (setsockopt (fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof (val)) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to set SO_REUSEPORT");
      return -1;
    }

  return 0;
#else
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "SO_REUSEPORT not available on this platform");
  return -1;
#endif
}

/* ============================================================================
 * Socket Address Information
 * ============================================================================
 */

#include <arpa/inet.h>
#include <netinet/in.h>

int
Socket_simple_get_local_addr (SocketSimple_Socket_T sock, char *host,
                               size_t host_len, int *port)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  const char *addr = Socket_getlocaladdr (sock->socket);
  if (addr && host && host_len > 0)
    {
      strncpy (host, addr, host_len - 1);
      host[host_len - 1] = '\0';
    }

  if (port)
    *port = Socket_getlocalport (sock->socket);

  return 0;
}

int
Socket_simple_get_peer_addr (SocketSimple_Socket_T sock, char *host,
                              size_t host_len, int *port)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  const char *addr = Socket_getpeeraddr (sock->socket);
  if (addr && host && host_len > 0)
    {
      strncpy (host, addr, host_len - 1);
      host[host_len - 1] = '\0';
    }

  if (port)
    *port = Socket_getpeerport (sock->socket);

  return 0;
}

int
Socket_simple_get_peer_creds (SocketSimple_Socket_T sock, int *pid, int *uid,
                               int *gid)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

#if defined(SO_PEERCRED)
  int fd = Socket_fd (sock->socket);
  struct ucred cred;
  socklen_t len = sizeof (cred);

  if (getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to get peer credentials");
      return -1;
    }

  if (pid)
    *pid = cred.pid;
  if (uid)
    *uid = cred.uid;
  if (gid)
    *gid = cred.gid;

  return 0;
#elif defined(LOCAL_PEERCRED)
  int fd = Socket_fd (sock->socket);
  struct xucred cred;
  socklen_t len = sizeof (cred);

  if (getsockopt (fd, 0, LOCAL_PEERCRED, &cred, &len) < 0)
    {
      simple_set_error_errno (SOCKET_SIMPLE_ERR_SOCKET,
                              "Failed to get peer credentials");
      return -1;
    }

  if (pid)
    *pid = -1; /* Not available on BSD */
  if (uid)
    *uid = cred.cr_uid;
  if (gid)
    *gid = cred.cr_gid;

  return 0;
#else
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED,
                    "Peer credentials not available on this platform");
  return -1;
#endif
}

/* ============================================================================
 * Scatter-Gather I/O
 * ============================================================================
 */

#include <sys/uio.h>

ssize_t
Socket_simple_sendv (SocketSimple_Socket_T sock, const struct iovec *iov,
                      int iovcnt)
{
  volatile ssize_t n = 0;

  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  if (!iov || iovcnt <= 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid iovec");
      return -1;
    }

  TRY { n = Socket_sendv (sock->socket, iov, iovcnt); }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_SEND, "Send failed");
    return -1;
  }
  EXCEPT (Socket_Closed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_CLOSED, "Connection closed");
    sock->is_connected = 0;
    return -1;
  }
  END_TRY;

  return n;
}

ssize_t
Socket_simple_recvv (SocketSimple_Socket_T sock, struct iovec *iov, int iovcnt)
{
  volatile ssize_t n = 0;

  Socket_simple_clear_error ();

  if (!sock || !sock->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid socket");
      return -1;
    }

  if (!iov || iovcnt <= 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid iovec");
      return -1;
    }

  TRY { n = Socket_recvv (sock->socket, iov, iovcnt); }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_RECV, "Receive failed");
    return -1;
  }
  EXCEPT (Socket_Closed)
  {
    sock->is_connected = 0;
    return 0;
  }
  END_TRY;

  if (n == 0)
    {
      sock->is_connected = 0;
    }
  return n;
}
