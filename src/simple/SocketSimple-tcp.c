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
 * TCP Client Functions
 * ============================================================================
 */

SocketSimple_Socket_T
Socket_simple_connect (const char *host, int port)
{
  /* Use timeout version with default timeout */
  return Socket_simple_connect_timeout (host, port, 30000);
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
    /* Use library convenience function - handles address family automatically */
    sock = Socket_connect_tcp (host, port, timeout_ms);
  }
  EXCEPT (Socket_Failed)
  {
    int err = Socket_geterrno ();
    if (Socket_error_is_retryable (err)
        && (err == ETIMEDOUT || err == EINPROGRESS))
      {
        simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "Connection timed out");
      }
    else
      {
        simple_set_error_errno (SOCKET_SIMPLE_ERR_CONNECT, "Connection failed");
      }
    if (sock)
      Socket_free ((Socket_T *)&sock);
    return NULL;
  }
  END_TRY;

  return simple_create_handle (sock, 0, 0);
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
    /* Use library convenience function - handles address family automatically */
    sock = Socket_listen_tcp (host ? host : "0.0.0.0",
                              port,
                              backlog > 0 ? backlog : 128);
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

  return simple_create_handle (sock, 1, 0);
}

SocketSimple_Socket_T
Socket_simple_accept (SocketSimple_Socket_T server)
{
  volatile Socket_T client = NULL;

  Socket_simple_clear_error ();

  if (!server || !server->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid server socket");
      return NULL;
    }

  TRY { client = Socket_accept (server->socket); }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_ACCEPT, "Accept failed");
    return NULL;
  }
  END_TRY;

  return simple_create_handle (client, 0, 0);
}

SocketSimple_Socket_T
Socket_simple_accept_timeout (SocketSimple_Socket_T server, int timeout_ms)
{
  volatile Socket_T client = NULL;

  Socket_simple_clear_error ();

  if (!server || !server->socket)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid server socket");
      return NULL;
    }

  TRY { client = Socket_accept_timeout (server->socket, timeout_ms); }
  EXCEPT (Socket_Failed)
  {
    int err = Socket_geterrno ();
    if (Socket_error_is_retryable (err) && (err == ETIMEDOUT || err == EAGAIN))
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

  return simple_create_handle (client, 0, 0);
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
  int ready;

  Socket_simple_clear_error ();

  if (!sock || !sock->socket || !buf)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  TRY
  {
    ready = Socket_probe (sock->socket, timeout_ms);
    if (!ready)
      {
        simple_set_error (SOCKET_SIMPLE_ERR_TIMEOUT, "Receive timed out");
        return -1;
      }
    n = Socket_recv (sock->socket, buf, len);
  }
  EXCEPT (Socket_Failed)
  {
    int err = Socket_geterrno ();
    if (Socket_error_is_retryable (err) && (err == ETIMEDOUT || err == EAGAIN))
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

ssize_t
Socket_simple_recv_line (SocketSimple_Socket_T sock, char *buf, size_t maxlen)
{
  Socket_simple_clear_error ();

  if (!sock || !sock->socket || !buf || maxlen == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }

  size_t pos = 0;
  while (pos < maxlen - 1)
    {
      ssize_t n = Socket_simple_recv (sock, buf + pos, 1);
      if (n < 0)
        return -1;
      if (n == 0)
        break;
      if (buf[pos] == '\n')
        {
          pos++;
          break;
        }
      pos++;
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
    /* Use library convenience function - handles address family automatically */
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

  return simple_create_udp_handle (dgram);
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

  return simple_create_udp_handle (dgram);
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
    received = SocketDgram_recvfrom (sock->dgram, buf, len, from_host, host_len,
                                     from_port);
  }
  EXCEPT (SocketDgram_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_RECV, "UDP receive failed");
    return -1;
  }
  END_TRY;

  return received;
}
