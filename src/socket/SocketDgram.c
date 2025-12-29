/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#define SOCKET_LOG_COMPONENT "SocketDgram"
#include "core/SocketUtil.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"
#include "socket/SocketDgram-private.h"
#include "socket/SocketDgram.h"
#include "socket/SocketIO.h"

#if SOCKET_HAS_TLS
#include "core/SocketCrypto.h"
#include "tls/SocketDTLS.h"
#include "tls/SocketDTLSConfig.h"
#include "tls/SocketDTLSContext.h"
#include "tls/SocketTLS-private.h" /* For shared tls_cleanup_alpn_temp (if DTLS uses ALPN) */
#include <openssl/ssl.h>
#endif

#define T SocketDgram_T

const Except_T SocketDgram_Failed
    = { &SocketDgram_Failed, "Datagram socket operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketDgram);

#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketDgram, e)

static struct SocketLiveCount dgram_live_tracker = SOCKETLIVECOUNT_STATIC_INIT;

#define dgram_live_increment() SocketLiveCount_increment (&dgram_live_tracker)
#define dgram_live_decrement() SocketLiveCount_decrement (&dgram_live_tracker)

int
SocketDgram_debug_live_count (void)
{
  return SocketLiveCount_get (&dgram_live_tracker);
}

static T
dgram_alloc_structure (SocketBase_T base)
{
  T sock = Arena_calloc (SocketBase_arena (base), 1, sizeof (struct T),
                         __FILE__, __LINE__);
  if (!sock)
    {
      SocketCommon_free_base (&base);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate dgram structure");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return sock;
}

T
SocketDgram_new (int domain, int protocol)
{
  SocketBase_T volatile base = NULL;
  SocketBase_T base_handle;
  T sock;

  TRY base = SocketCommon_new_base (domain, SOCKET_DGRAM_TYPE, protocol);
  EXCEPT (Arena_Failed)
  RAISE_MODULE_ERROR (SocketDgram_Failed);
  EXCEPT (Socket_Failed)
  RAISE_MODULE_ERROR (SocketDgram_Failed);
  END_TRY;

  base_handle = (SocketBase_T)base;

  if (!base_handle || !SocketBase_arena (base_handle))
    {
      SOCKET_ERROR_MSG ("Invalid base from new_base (null arena)");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }

  sock = dgram_alloc_structure (base_handle);
  sock->base = base_handle;
  dgram_live_increment ();
  return sock;
}

void
SocketDgram_free (T *socket)
{
  T s = *socket;
  if (!s)
    return;

  *socket = NULL;

#if SOCKET_HAS_TLS
  if (s->dtls_ssl)
    {
      SSL_set_app_data ((SSL *)s->dtls_ssl, NULL);
      tls_cleanup_alpn_temp ((SSL *)s->dtls_ssl);
      SSL_free ((SSL *)s->dtls_ssl);
      s->dtls_ssl = NULL;
    }
  if (s->dtls_ctx)
    {
      SocketDTLSContext_free ((SocketDTLSContext_T *)&s->dtls_ctx);
      s->dtls_ctx = NULL;
    }
  if (s->dtls_read_buf)
    {
      SocketCrypto_secure_clear (s->dtls_read_buf,
                                 SOCKET_DTLS_MAX_RECORD_SIZE);
      s->dtls_read_buf = NULL;
      s->dtls_read_buf_len = 0;
    }
  if (s->dtls_write_buf)
    {
      SocketCrypto_secure_clear (s->dtls_write_buf,
                                 SOCKET_DTLS_MAX_RECORD_SIZE);
      s->dtls_write_buf = NULL;
      s->dtls_write_buf_len = 0;
    }
  /* Clear SNI hostname */
  if (s->dtls_sni_hostname)
    {
      size_t hostname_len = strlen (s->dtls_sni_hostname) + 1;
      SocketCrypto_secure_clear ((void *)s->dtls_sni_hostname, hostname_len);
      s->dtls_sni_hostname = NULL;
    }

  /* Invalidate DTLS peer cache - use SocketCommon_free_addrinfo for copied addrinfo */
  if (s->dtls_peer_res)
    {
      SocketCommon_free_addrinfo (s->dtls_peer_res);
      s->dtls_peer_res = NULL;
    }
  s->dtls_peer_host = NULL;
  s->dtls_peer_port = 0;
  s->dtls_peer_cache_ts = 0;

  /* Reset DTLS state flags */
  s->dtls_enabled = 0;
  s->dtls_handshake_done = 0;
  s->dtls_shutdown_done = 0;
  s->dtls_mtu = 0;
  s->dtls_last_handshake_state = DTLS_HANDSHAKE_NOT_STARTED;
#endif

  /* Common base cleanup: closes fd, disposes arena (frees s too) */
  SocketCommon_free_base (&s->base);
  dgram_live_decrement ();
}

static int
resolve_sendto_address (const char *host, int port, struct addrinfo **res)
{
  struct addrinfo hints;

  SocketCommon_setup_hints (&hints, SOCKET_DGRAM_TYPE, 0);
  SocketCommon_resolve_address (host, port, &hints, res, SocketDgram_Failed,
                                SOCKET_AF_UNSPEC, 1);
  return 0;
}

static ssize_t
perform_sendto (T socket, const void *buf, size_t len,
                const struct addrinfo *res)
{
  ssize_t sent;

  if (len > SAFE_UDP_SIZE)
    {
      SOCKET_ERROR_MSG (
          "Datagram len %zu > SAFE_UDP_SIZE %zu (risk of fragmentation)", len,
          SAFE_UDP_SIZE);
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }

  sent = sendto (SocketBase_fd (socket->base), buf, len, MSG_NOSIGNAL,
                 res->ai_addr, res->ai_addrlen);
  if (sent < 0)
    {
      if (socketio_is_wouldblock ())
        return 0;
      SOCKET_ERROR_FMT ("Failed to send datagram");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return sent;
}

static ssize_t
perform_recvfrom (T socket, void *buf, size_t len,
                  struct sockaddr_storage *addr, socklen_t *addrlen)
{
  ssize_t received = recvfrom (SocketBase_fd (socket->base), buf, len, 0,
                               (struct sockaddr *)addr, addrlen);
  if (received < 0)
    {
      if (socketio_is_wouldblock ())
        return 0;
      SOCKET_ERROR_FMT ("Failed to receive datagram");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return received;
}

static void
extract_sender_info (const struct sockaddr_storage *addr, socklen_t addrlen,
                     char *host, size_t host_len, int *port)
{
  char serv[SOCKET_NI_MAXSERV];
  int result = getnameinfo ((struct sockaddr *)addr, addrlen, host, host_len,
                            serv, SOCKET_NI_MAXSERV,
                            SOCKET_NI_NUMERICHOST | SOCKET_NI_NUMERICSERV);
  if (result == 0)
    {
      char *endptr;
      errno = 0;
      long port_long = strtol (serv, &endptr, 10);
      *port
          = (*endptr == '\0' && errno != ERANGE && port_long > 0
             && port_long <= SOCKET_MAX_PORT)
                ? (int)port_long
                : 0;
    }
  else
    {
      if (host_len > 0)
        host[0] = '\0';
      *port = 0;
    }
}

ssize_t
SocketDgram_sendto (T socket, const void *buf, size_t len, const char *host,
                    int port)
{
  struct addrinfo *res = NULL;
  volatile ssize_t sent = 0;

  assert (socket);
  assert (buf);
  assert (len > 0);
  assert (host);

  SocketCommon_validate_port (port, SocketDgram_Failed);
  SocketCommon_validate_hostname (host, SocketDgram_Failed);
  resolve_sendto_address (host, port, &res);

  TRY sent = perform_sendto (socket, buf, len, res);
  FINALLY SocketCommon_free_addrinfo (res);
  END_TRY;

  return (ssize_t)sent;
}

ssize_t
SocketDgram_recvfrom (T socket, void *buf, size_t len, char *host,
                      size_t host_len, int *port)
{
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof (addr);
  ssize_t received;

  assert (socket);
  assert (buf);
  assert (len > 0);

  memset (&addr, 0, sizeof (addr));
  received = perform_recvfrom (socket, buf, len, &addr, &addrlen);

  if (received > 0 && host && host_len > 0 && port)
    extract_sender_info (&addr, addrlen, host, host_len, port);

  return received;
}

ssize_t
SocketDgram_send (T socket, const void *buf, size_t len)
{
  ssize_t sent;

  assert (socket);
  assert (buf);
  assert (len > 0);

  sent = send (SocketBase_fd (socket->base), buf, len, MSG_NOSIGNAL);
  if (sent < 0)
    {
      if (socketio_is_wouldblock ())
        return 0;
      SOCKET_ERROR_FMT ("Failed to send datagram");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return sent;
}

ssize_t
SocketDgram_recv (T socket, void *buf, size_t len)
{
  ssize_t received;

  assert (socket);
  assert (buf);
  assert (len > 0);

  received = recv (SocketBase_fd (socket->base), buf, len, 0);
  if (received < 0)
    {
      if (socketio_is_wouldblock ())
        return 0;
      SOCKET_ERROR_FMT ("Failed to receive datagram");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return received;
}

void
SocketDgram_setnonblocking (T socket)
{
  assert (socket);
  SocketCommon_set_nonblock (socket->base, true, SocketDgram_Failed);
}

void
SocketDgram_setreuseaddr (T socket)
{
  assert (socket);
  SocketCommon_setreuseaddr (socket->base, SocketDgram_Failed);
}

void
SocketDgram_setreuseport (T socket)
{
  assert (socket);
  SocketCommon_setreuseport (socket->base, SocketDgram_Failed);
}

void
SocketDgram_setbroadcast (T socket, int enable)
{
  int optval = enable ? 1 : 0;
  assert (socket);

  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                  SOCKET_SO_BROADCAST, &optval, sizeof (optval))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set SO_BROADCAST");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
}

void
SocketDgram_joinmulticast (T socket, const char *group, const char *interface)
{
  assert (socket);
  assert (group);
  SocketCommon_join_multicast (socket->base, group, interface,
                               SocketDgram_Failed);
}

void
SocketDgram_leavemulticast (T socket, const char *group, const char *interface)
{
  assert (socket);
  assert (group);
  SocketCommon_leave_multicast (socket->base, group, interface,
                                SocketDgram_Failed);
}

void
SocketDgram_setttl (T socket, int ttl)
{
  int socket_family;
  assert (socket);

  if (ttl < 1 || ttl > SOCKET_MAX_TTL)
    {
      SOCKET_ERROR_MSG ("Invalid TTL value: %d (must be 1-%d)", ttl,
                        SOCKET_MAX_TTL);
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }

  socket_family
      = SocketCommon_get_family (socket->base, true, SocketDgram_Failed);
  SocketCommon_set_ttl (socket->base, socket_family, ttl, SocketDgram_Failed);
}

void
SocketDgram_settimeout (T socket, int timeout_sec)
{
  assert (socket);
  SocketCommon_settimeout (socket->base, timeout_sec, SocketDgram_Failed);
}

int
SocketDgram_gettimeout (T socket)
{
  struct timeval tv;
  assert (socket);

  if (SocketCommon_getoption_timeval (SocketBase_fd (socket->base),
                                      SOCKET_SOL_SOCKET, SOCKET_SO_RCVTIMEO,
                                      &tv, SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);

  return (int)tv.tv_sec;
}

int
SocketDgram_getbroadcast (T socket)
{
  int opt = 0;
  assert (socket);

  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_SOL_SOCKET, SOCKET_SO_BROADCAST, &opt,
                                  SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);

  return opt ? 1 : 0;
}

int
SocketDgram_getrcvbuf (T socket)
{
  int bufsize = 0;
  assert (socket);

  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_SOL_SOCKET, SOCKET_SO_RCVBUF,
                                  &bufsize, SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);

  return bufsize;
}

int
SocketDgram_getsndbuf (T socket)
{
  int bufsize = 0;
  assert (socket);

  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_SOL_SOCKET, SOCKET_SO_SNDBUF,
                                  &bufsize, SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);

  return bufsize;
}

void
SocketDgram_setcloexec (T socket, int enable)
{
  assert (socket);
  SocketCommon_setcloexec_with_error (socket->base, enable,
                                      SocketDgram_Failed);
}

static int
dgram_get_ttl_params (int socket_family, int *level, int *optname)
{
  if (socket_family == SOCKET_AF_INET)
    {
      *level = SOCKET_IPPROTO_IP;
      *optname = SOCKET_IP_TTL;
    }
  else if (socket_family == SOCKET_AF_INET6)
    {
      *level = SOCKET_IPPROTO_IPV6;
      *optname = SOCKET_IPV6_UNICAST_HOPS;
    }
  else
    {
      SOCKET_ERROR_MSG ("Unsupported address family for TTL");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return 0;
}

int
SocketDgram_getttl (T socket)
{
  int socket_family, level = 0, optname = 0, ttl = 0;
  assert (socket);

  socket_family
      = SocketCommon_get_family (socket->base, true, SocketDgram_Failed);
  dgram_get_ttl_params (socket_family, &level, &optname);

  if (SocketCommon_getoption_int (SocketBase_fd (socket->base), level, optname,
                                  &ttl, SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);

  return ttl;
}

int
SocketDgram_fd (const T socket)
{
  assert (socket);
  return SocketBase_fd (socket->base);
}

const char *
SocketDgram_getlocaladdr (const T socket)
{
  assert (socket);
  return socket->base->localaddr ? socket->base->localaddr : "(unknown)";
}

int
SocketDgram_getlocalport (const T socket)
{
  assert (socket);
  return socket->base->localport;
}

int
SocketDgram_isconnected (T socket)
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof (addr);
  assert (socket);

  memset (&addr, 0, sizeof (addr));
  return getpeername (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
                      &len)
                 == 0
             ? 1
             : 0;
}

int
SocketDgram_isbound (T socket)
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof (addr);
  assert (socket);

  if (socket->base->localaddr != NULL)
    return 1;

  memset (&addr, 0, sizeof (addr));
  if (getsockname (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
                   &len)
      == 0)
    return SocketCommon_check_bound_by_family (&addr);

  return 0;
}

/* Operation type for dgram_perform_address_operation */
typedef enum
{
  DGRAM_OP_BIND,
  DGRAM_OP_CONNECT
} DgramOpType;

static int
dgram_try_single_address (int fd, const struct addrinfo *rp, DgramOpType op)
{
  return (op == DGRAM_OP_BIND) ? bind (fd, rp->ai_addr, rp->ai_addrlen)
                               : connect (fd, rp->ai_addr, rp->ai_addrlen);
}

static void
dgram_setup_dual_stack (int fd, int family, int socket_family, DgramOpType op)
{
  if (op == DGRAM_OP_BIND && family == SOCKET_AF_INET6
      && socket_family == SOCKET_AF_INET6)
    {
      int no = 0;
      setsockopt (fd, SOCKET_IPPROTO_IPV6, SOCKET_IPV6_V6ONLY, &no,
                  sizeof (no));
    }
}

static int
dgram_try_addresses (T socket, struct addrinfo *res, int socket_family,
                     DgramOpType op)
{
  int fd = SocketBase_fd (socket->base);
  struct addrinfo *rp;

  for (rp = res; rp != NULL; rp = rp->ai_next)
    {
      if (socket_family != SOCKET_AF_UNSPEC && rp->ai_family != socket_family)
        continue;

      dgram_setup_dual_stack (fd, rp->ai_family, socket_family, op);

      if (dgram_try_single_address (fd, rp, op) == 0)
        {
          /* Validate address length before memcpy to prevent buffer overflow */
          if (rp->ai_addrlen > sizeof (struct sockaddr_storage))
            {
              SOCKET_ERROR_FMT ("Address length %u exceeds storage size %zu",
                                rp->ai_addrlen,
                                sizeof (struct sockaddr_storage));
              continue; /* Try next address */
            }

          /* Cache address in appropriate field based on operation type */
          if (op == DGRAM_OP_CONNECT)
            {
              memcpy (&socket->base->remote_addr, rp->ai_addr, rp->ai_addrlen);
              socket->base->remote_addrlen = rp->ai_addrlen;
            }
          else
            {
              memcpy (&socket->base->local_addr, rp->ai_addr, rp->ai_addrlen);
              socket->base->local_addrlen = rp->ai_addrlen;
            }
          return 0;
        }
    }
  return -1;
}

static void
dgram_perform_address_operation (T socket, const char *host, int port,
                                 DgramOpType op)
{
  struct addrinfo hints, *res = NULL;
  int socket_family;
  int flags = (op == DGRAM_OP_BIND) ? SOCKET_AI_PASSIVE : 0;

  SocketCommon_setup_hints (&hints, SOCKET_DGRAM_TYPE, flags);
  SocketCommon_resolve_address (host, port, &hints, &res, SocketDgram_Failed,
                                SOCKET_AF_UNSPEC, 1);

  socket_family
      = SocketCommon_get_family (socket->base, false, SocketDgram_Failed);

  if (dgram_try_addresses (socket, res, socket_family, op) == 0)
    {
      SocketCommon_update_local_endpoint (socket->base);
      SocketCommon_free_addrinfo (res);
      return;
    }

  /* Format appropriate error message */
  if (op == DGRAM_OP_BIND)
    SocketCommon_format_bind_error (host, port);
  else
    SOCKET_ERROR_FMT ("Failed to connect to %.*s:%d",
                      SOCKET_ERROR_MAX_HOSTNAME, host, port);

  SocketCommon_free_addrinfo (res);
  RAISE_MODULE_ERROR (SocketDgram_Failed);
}

void
SocketDgram_bind (T socket, const char *host, int port)
{
  assert (socket);
  SocketCommon_validate_port (port, SocketDgram_Failed);
  host = SocketCommon_normalize_wildcard_host (host);
  if (host)
    SocketCommon_validate_hostname (host, SocketDgram_Failed);

  dgram_perform_address_operation (socket, host, port, DGRAM_OP_BIND);
}

void
SocketDgram_connect (T socket, const char *host, int port)
{
  assert (socket);
  assert (host);
  SocketCommon_validate_port (port, SocketDgram_Failed);
  SocketCommon_validate_hostname (host, SocketDgram_Failed);

  dgram_perform_address_operation (socket, host, port, DGRAM_OP_CONNECT);
}

static inline void
dgram_validate_iov (const struct iovec *iov, int iovcnt)
{
  (void)iov;    /* Used only in assertions */
  (void)iovcnt; /* Used only in assertions */
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);
}

ssize_t
SocketDgram_sendv (T socket, const struct iovec *iov, int iovcnt)
{
  struct msghdr msg;
  ssize_t result;
  size_t total_len;

  assert (socket);
  dgram_validate_iov (iov, iovcnt);

  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);
  if (total_len > SAFE_UDP_SIZE)
    {
      SOCKET_ERROR_MSG ("Sendv total %zu > SAFE_UDP_SIZE %zu", total_len,
                        SAFE_UDP_SIZE);
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }

  memset (&msg, 0, sizeof (msg));
  msg.msg_iov = (struct iovec *)iov;
  msg.msg_iovlen = (size_t)iovcnt;

  result = sendmsg (SocketBase_fd (socket->base), &msg, MSG_NOSIGNAL);
  if (result < 0)
    {
      if (socketio_is_wouldblock ())
        return 0;
      SOCKET_ERROR_FMT ("Scatter/gather send failed (iovcnt=%d)", iovcnt);
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return result;
}

ssize_t
SocketDgram_recvv (T socket, struct iovec *iov, int iovcnt)
{
  ssize_t result;

  assert (socket);
  dgram_validate_iov (iov, iovcnt);

  result = readv (SocketBase_fd (socket->base), iov, iovcnt);
  if (result < 0)
    {
      if (socketio_is_wouldblock ())
        return 0;
      SOCKET_ERROR_FMT ("Scatter/gather receive failed (iovcnt=%d)", iovcnt);
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return result;
}

ssize_t
SocketDgram_sendall (T socket, const void *buf, size_t len)
{
  const char *ptr = (const char *)buf;
  size_t total_sent = 0;

  assert (socket);
  assert (buf);
  assert (len > 0);

  while (total_sent < len)
    {
      ssize_t sent
          = SocketDgram_send (socket, ptr + total_sent, len - total_sent);
      if (sent == 0)
        return (ssize_t)total_sent;
      total_sent += (size_t)sent;
    }
  return (ssize_t)total_sent;
}

ssize_t
SocketDgram_recvall (T socket, void *buf, size_t len)
{
  char *ptr = (char *)buf;
  size_t total_received = 0;

  assert (socket);
  assert (buf);
  assert (len > 0);

  while (total_received < len)
    {
      ssize_t received = SocketDgram_recv (socket, ptr + total_received,
                                           len - total_received);
      if (received == 0)
        return (ssize_t)total_received;
      total_received += (size_t)received;
    }
  return (ssize_t)total_received;
}

static size_t
dgram_iov_loop_send (T socket, struct iovec *iov_copy, int iovcnt,
                     size_t total_len)
{
  size_t total_sent = 0;

  while (total_sent < total_len)
    {
      int active_iovcnt = 0;
      const struct iovec *active_iov
          = SocketCommon_find_active_iov (iov_copy, iovcnt, &active_iovcnt);
      if (active_iov == NULL)
        break;

      ssize_t sent = SocketDgram_sendv (socket, active_iov, active_iovcnt);
      if (sent == 0)
        break;

      total_sent += (size_t)sent;
      SocketCommon_advance_iov (iov_copy, iovcnt, (size_t)sent);
    }
  return total_sent;
}

static size_t
dgram_iov_loop_recv (T socket, struct iovec *iov_copy, int iovcnt,
                     size_t total_len)
{
  size_t total_received = 0;

  while (total_received < total_len)
    {
      int active_iovcnt = 0;
      struct iovec *active_iov
          = SocketCommon_find_active_iov (iov_copy, iovcnt, &active_iovcnt);
      if (active_iov == NULL)
        break;

      ssize_t received = SocketDgram_recvv (socket, active_iov, active_iovcnt);
      if (received == 0)
        break;

      total_received += (size_t)received;
      SocketCommon_advance_iov (iov_copy, iovcnt, (size_t)received);
    }
  return total_received;
}

ssize_t
SocketDgram_sendvall (T socket, const struct iovec *iov, int iovcnt)
{
  struct iovec *iov_copy;
  size_t total_len;
  volatile size_t total_sent = 0;

  assert (socket);
  dgram_validate_iov (iov, iovcnt);

  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);
  iov_copy = SocketCommon_alloc_iov_copy (iov, iovcnt, SocketDgram_Failed);

  TRY total_sent = dgram_iov_loop_send (socket, iov_copy, iovcnt, total_len);
  FINALLY free (iov_copy);
  END_TRY;

  return (ssize_t)total_sent;
}

ssize_t
SocketDgram_recvvall (T socket, struct iovec *iov, int iovcnt)
{
  struct iovec *iov_copy;
  size_t total_len;
  volatile size_t total_received = 0;

  assert (socket);
  dgram_validate_iov (iov, iovcnt);

  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);
  iov_copy = SocketCommon_alloc_iov_copy (iov, iovcnt, SocketDgram_Failed);

  TRY total_received
      = dgram_iov_loop_recv (socket, iov_copy, iovcnt, total_len);
  SocketCommon_sync_iov_progress (iov, iov_copy, iovcnt);
  FINALLY free (iov_copy);
  END_TRY;

  return (ssize_t)total_received;
}

T
SocketDgram_bind_udp4 (const char *host, int port)
{
  T server = NULL;

  assert (port >= 0 && port <= SOCKET_MAX_PORT);

  TRY
  {
    /* Create IPv4 UDP socket */
    server = SocketDgram_new (AF_INET, 0);

    /* Bind to address/port */
    SocketDgram_bind (server, host, port);
  }
  EXCEPT (SocketDgram_Failed)
  {
    if (server)
      SocketDgram_free (&server);
    RERAISE;
  }
  END_TRY;

  return server;
}

T
SocketDgram_bind_udp6 (const char *host, int port)
{
  T server = NULL;

  assert (port >= 0 && port <= SOCKET_MAX_PORT);

  TRY
  {
    /* Create IPv6 UDP socket */
    server = SocketDgram_new (AF_INET6, 0);

    /* Bind to address/port */
    SocketDgram_bind (server, host, port);
  }
  EXCEPT (SocketDgram_Failed)
  {
    if (server)
      SocketDgram_free (&server);
    RERAISE;
  }
  END_TRY;

  return server;
}

static int
detect_address_family (const char *host)
{
  /* NULL or empty string defaults to IPv4 for backward compatibility */
  if (!host || host[0] == '\0')
    return AF_INET;

  /* Check for IPv6 indicators: contains ':' or starts with '[' */
  if (strchr (host, ':') != NULL || host[0] == '[')
    return AF_INET6;

  /* Default to IPv4 for numeric or hostname */
  return AF_INET;
}

T
SocketDgram_bind_udp (const char *host, int port)
{
  T server = NULL;
  int family;

  assert (port >= 0 && port <= SOCKET_MAX_PORT);

  /* Auto-detect address family from host string */
  family = detect_address_family (host);

  TRY
  {
    /* Create UDP socket with detected family */
    server = SocketDgram_new (family, 0);

    /* Bind to address/port */
    SocketDgram_bind (server, host, port);
  }
  EXCEPT (SocketDgram_Failed)
  {
    if (server)
      SocketDgram_free (&server);
    RERAISE;
  }
  END_TRY;

  return server;
}

#undef T
