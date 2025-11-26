/**
 * SocketDgram.c - UDP/datagram socket implementation
 *
 * Consolidated module for UDP socket operations including core lifecycle,
 * options, bind/connect, and scatter/gather I/O.
 *
 * Features:
 * - Socket lifecycle management (new/free)
 * - Basic send/recv operations
 * - Socket options (reuseaddr, broadcast, multicast, TTL)
 * - Bind and connect operations with address resolution
 * - Scatter/gather I/O (sendv/recvv)
 * - Thread-safe live count tracking
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig-limits.h"
#include "core/SocketConfig.h"
#define SOCKET_LOG_COMPONENT "SocketDgram"
#include "core/SocketError.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"
#include "socket/SocketDgram-private.h"
#include "socket/SocketDgram.h"
#include "socket/SocketIO.h"
#include "socket/SocketLiveCount.h"

#define T SocketDgram_T

const Except_T SocketDgram_Failed
    = { &SocketDgram_Failed, "Datagram socket operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketDgram);

#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketDgram, e)

/* Shared live count tracker - see SocketLiveCount.h */
static struct SocketLiveCount dgram_live_tracker = SOCKETLIVECOUNT_STATIC_INIT;

#define dgram_live_increment() SocketLiveCount_increment (&dgram_live_tracker)
#define dgram_live_decrement() SocketLiveCount_decrement (&dgram_live_tracker)

/* Note: struct T defined in SocketDgram-private.h */

int
SocketDgram_debug_live_count (void)
{
  return SocketLiveCount_get (&dgram_live_tracker);
}

/* ==================== Lifecycle Operations ==================== */

T
SocketDgram_new (int domain, int protocol)
{
  SocketBase_T base = NULL;
  T sock;

  TRY base = SocketCommon_new_base (domain, SOCKET_DGRAM_TYPE, protocol);
  EXCEPT (Arena_Failed)
  RAISE_MODULE_ERROR (SocketDgram_Failed);
  EXCEPT (Socket_Failed)
  RAISE_MODULE_ERROR (SocketDgram_Failed);
  END_TRY;

  if (!base || !SocketBase_arena (base))
    {
      SOCKET_ERROR_MSG ("Invalid base from new_base (null arena)");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }

  sock = Arena_calloc (SocketBase_arena (base), 1, sizeof (struct T), __FILE__,
                       __LINE__);
  if (!sock)
    {
      SocketCommon_free_base (&base);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate dgram structure");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }

  sock->base = base;
  dgram_live_increment ();
  return sock;
}

void
SocketDgram_free (T *socket)
{
  T s = *socket;
  if (!s)
    return;

  dgram_live_decrement ();
  SocketCommon_free_base (&s->base);
  *socket = NULL;
}

/* ==================== Address Resolution Helpers ==================== */

static int
resolve_sendto_address (const char *host, int port, struct addrinfo **res)
{
  struct addrinfo hints;
  char port_str[SOCKET_PORT_STR_BUFSIZE];
  int result;

  result = snprintf (port_str, sizeof (port_str), "%d", port);
  assert (result > 0 && result < (int)sizeof (port_str));

  /* Inline setup_sendto_hints - was just a wrapper */
  SocketCommon_setup_hints (&hints, SOCKET_DGRAM_TYPE, 0);
  result = getaddrinfo (host, port_str, &hints, res);
  if (result != 0)
    {
      SOCKET_ERROR_MSG ("Invalid host/IP address: %.*s (%s)",
                        SOCKET_ERROR_MAX_HOSTNAME, host,
                        gai_strerror (result));
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return 0;
}

static ssize_t
perform_sendto (T socket, const void *buf, size_t len, struct addrinfo *res)
{
  if (len > SAFE_UDP_SIZE)
    {
      SOCKET_ERROR_MSG (
          "Datagram len %zu > SAFE_UDP_SIZE %zu (risk of fragmentation)", len,
          SAFE_UDP_SIZE);
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }

  ssize_t sent = sendto (SocketBase_fd (socket->base), buf, len, 0,
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
  int result;

  result = getnameinfo ((struct sockaddr *)addr, addrlen, host, host_len, serv,
                        SOCKET_NI_MAXSERV,
                        SOCKET_NI_NUMERICHOST | SOCKET_NI_NUMERICSERV);
  if (result == 0)
    {
      char *endptr;
      long port_long = strtol (serv, &endptr, 10);
      if (*endptr == '\0' && port_long > 0 && port_long <= SOCKET_MAX_PORT)
        *port = (int)port_long;
      else
        *port = 0;
    }
  else
    {
      if (host_len > 0)
        host[0] = '\0';
      *port = 0;
    }
}

/* ==================== Basic I/O Operations ==================== */

ssize_t
SocketDgram_sendto (T socket, const void *buf, size_t len, const char *host,
                    int port)
{
  struct addrinfo *res = NULL;
  ssize_t sent;

  assert (socket);
  assert (buf);
  assert (len > 0);
  assert (host);

  SocketCommon_validate_port (port, SocketDgram_Failed);
  SocketCommon_validate_hostname (host, SocketDgram_Failed);
  resolve_sendto_address (host, port, &res);
  sent = perform_sendto (socket, buf, len, res);
  freeaddrinfo (res);
  return sent;
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

  received = perform_recvfrom (socket, buf, len, &addr, &addrlen);
  if (host && host_len > 0 && port)
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

  sent = send (SocketBase_fd (socket->base), buf, len, 0);
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

/* ==================== Socket Options ==================== */

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

  if (ttl < 1 || ttl > 255)
    {
      SOCKET_ERROR_MSG ("Invalid TTL value: %d (must be 1-255)", ttl);
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

  return opt;
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
  SocketCommon_setcloexec_with_error (socket->base, enable, SocketDgram_Failed);
}

int
SocketDgram_getttl (T socket)
{
  int socket_family;
  int ttl = 0;
  assert (socket);

  socket_family
      = SocketCommon_get_family (socket->base, true, SocketDgram_Failed);

  if (socket_family == SOCKET_AF_INET)
    {
      if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                      SOCKET_IPPROTO_IP, SOCKET_IP_TTL, &ttl,
                                      SocketDgram_Failed)
          < 0)
        RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  else if (socket_family == SOCKET_AF_INET6)
    {
      if (SocketCommon_getoption_int (
              SocketBase_fd (socket->base), SOCKET_IPPROTO_IPV6,
              SOCKET_IPV6_UNICAST_HOPS, &ttl, SocketDgram_Failed)
          < 0)
        RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  else
    {
      SOCKET_ERROR_MSG ("Unsupported address family for TTL");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return ttl;
}

/* ==================== State/Accessor Functions ==================== */

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

  if (getpeername (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
                   &len)
      == 0)
    return 1;
  return 0;
}

int
SocketDgram_isbound (T socket)
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof (addr);
  assert (socket);

  if (socket->base->localaddr != NULL)
    return 1;

  if (getsockname (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
                   &len)
      == 0)
    return SocketCommon_check_bound_by_family (&addr);

  return 0;
}

/* ==================== Bind/Connect Operations ==================== */

/* Operation type for dgram_try_addresses */
typedef enum
{
  DGRAM_OP_BIND,
  DGRAM_OP_CONNECT
} DgramOpType;

/**
 * dgram_try_addresses - Try operation on resolved addresses
 * @socket: Datagram socket
 * @res: Resolved address list
 * @socket_family: Socket address family filter
 * @op: Operation type (DGRAM_OP_BIND or DGRAM_OP_CONNECT)
 *
 * Returns: 0 on success, -1 if all addresses failed
 * Thread-safe: Yes (operates on single socket)
 */
static int
dgram_try_addresses (T socket, struct addrinfo *res, int socket_family,
                     DgramOpType op)
{
  struct addrinfo *rp;
  int fd = SocketBase_fd (socket->base);

  for (rp = res; rp != NULL; rp = rp->ai_next)
    {
      if (socket_family != SOCKET_AF_UNSPEC && rp->ai_family != socket_family)
        continue;

      /* IPv6 dual-stack setup for bind only */
      if (op == DGRAM_OP_BIND && rp->ai_family == SOCKET_AF_INET6
          && socket_family == SOCKET_AF_INET6)
        {
          int no = 0;
          setsockopt (fd, SOCKET_IPPROTO_IPV6, SOCKET_IPV6_V6ONLY, &no,
                      sizeof (no));
        }

      int result = (op == DGRAM_OP_BIND)
                       ? bind (fd, rp->ai_addr, rp->ai_addrlen)
                       : connect (fd, rp->ai_addr, rp->ai_addrlen);

      if (result == 0)
        {
          memcpy (&socket->base->remote_addr, rp->ai_addr, rp->ai_addrlen);
          socket->base->remote_addrlen = rp->ai_addrlen;
          return 0;
        }
    }
  return -1;
}

void
SocketDgram_bind (T socket, const char *host, int port)
{
  struct addrinfo hints, *res = NULL;
  int socket_family;

  assert (socket);
  SocketCommon_validate_port (port, SocketDgram_Failed);
  host = SocketCommon_normalize_wildcard_host (host);
  if (host)
    SocketCommon_validate_hostname (host, SocketDgram_Failed);

  SocketCommon_setup_hints (&hints, SOCKET_DGRAM_TYPE, SOCKET_AI_PASSIVE);
  SocketCommon_resolve_address (host, port, &hints, &res, SocketDgram_Failed,
                                SOCKET_AF_UNSPEC, 1);

  socket_family
      = SocketCommon_get_family (socket->base, false, SocketDgram_Failed);
  if (dgram_try_addresses (socket, res, socket_family, DGRAM_OP_BIND) == 0)
    {
      SocketCommon_update_local_endpoint (socket->base);
      freeaddrinfo (res);
      return;
    }

  SocketCommon_format_bind_error (host, port);
  freeaddrinfo (res);
  RAISE_MODULE_ERROR (SocketDgram_Failed);
}

void
SocketDgram_connect (T socket, const char *host, int port)
{
  struct addrinfo hints, *res = NULL;
  int socket_family;

  assert (socket);
  assert (host);
  SocketCommon_validate_port (port, SocketDgram_Failed);
  SocketCommon_validate_hostname (host, SocketDgram_Failed);

  SocketCommon_setup_hints (&hints, SOCKET_DGRAM_TYPE, 0);
  SocketCommon_resolve_address (host, port, &hints, &res, SocketDgram_Failed,
                                SOCKET_AF_UNSPEC, 1);

  socket_family
      = SocketCommon_get_family (socket->base, false, SocketDgram_Failed);
  if (dgram_try_addresses (socket, res, socket_family, DGRAM_OP_CONNECT) == 0)
    {
      SocketCommon_update_local_endpoint (socket->base);
      freeaddrinfo (res);
      return;
    }

  SOCKET_ERROR_FMT ("Failed to connect to %.*s:%d", SOCKET_ERROR_MAX_HOSTNAME,
                    host, port);
  freeaddrinfo (res);
  RAISE_MODULE_ERROR (SocketDgram_Failed);
}

/* ==================== Scatter/Gather I/O ==================== */

ssize_t
SocketDgram_sendv (T socket, const struct iovec *iov, int iovcnt)
{
  ssize_t result;
  size_t total_len;

  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);
  if (total_len > SAFE_UDP_SIZE)
    {
      SOCKET_ERROR_MSG ("Sendv total %zu > SAFE_UDP_SIZE %zu", total_len,
                        SAFE_UDP_SIZE);
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }

  result = writev (SocketBase_fd (socket->base), iov, iovcnt);
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
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

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
  volatile size_t total_sent = 0;
  ssize_t sent;

  assert (socket);
  assert (buf);
  assert (len > 0);

  TRY while (total_sent < len)
  {
    sent = SocketDgram_send (socket, ptr + total_sent, len - total_sent);
    if (sent == 0)
      return (ssize_t)total_sent;
    total_sent += (size_t)sent;
  }
  EXCEPT (SocketDgram_Failed)
  RERAISE;
  END_TRY;

  return (ssize_t)total_sent;
}

ssize_t
SocketDgram_recvall (T socket, void *buf, size_t len)
{
  char *ptr = (char *)buf;
  volatile size_t total_received = 0;
  ssize_t received;

  assert (socket);
  assert (buf);
  assert (len > 0);

  TRY while (total_received < len)
  {
    received
        = SocketDgram_recv (socket, ptr + total_received, len - total_received);
    if (received == 0)
      return (ssize_t)total_received;
    total_received += (size_t)received;
  }
  EXCEPT (SocketDgram_Failed)
  RERAISE;
  END_TRY;

  return (ssize_t)total_received;
}

ssize_t
SocketDgram_sendvall (T socket, const struct iovec *iov, int iovcnt)
{
  struct iovec *iov_copy = NULL;
  volatile size_t total_sent = 0;
  size_t total_len;
  ssize_t sent;
  int i;

  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);

  iov_copy = calloc ((size_t)iovcnt, sizeof (struct iovec));
  if (!iov_copy)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate iovec copy");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  memcpy (iov_copy, iov, (size_t)iovcnt * sizeof (struct iovec));

  TRY while (total_sent < total_len)
  {
    int active_iovcnt = 0;
    struct iovec *active_iov = NULL;

    for (i = 0; i < iovcnt; i++)
      {
        if (iov_copy[i].iov_len > 0)
          {
            active_iov = &iov_copy[i];
            active_iovcnt = iovcnt - i;
            break;
          }
      }
    if (active_iov == NULL)
      break;

    sent = SocketDgram_sendv (socket, active_iov, active_iovcnt);
    if (sent == 0)
      {
        free (iov_copy);
        return (ssize_t)total_sent;
      }
    total_sent += (size_t)sent;
    SocketCommon_advance_iov (iov_copy, iovcnt, (size_t)sent);
  }
  EXCEPT (SocketDgram_Failed)
  free (iov_copy);
  RERAISE;
  END_TRY;

  free (iov_copy);
  return (ssize_t)total_sent;
}

ssize_t
SocketDgram_recvvall (T socket, struct iovec *iov, int iovcnt)
{
  struct iovec *iov_copy = NULL;
  volatile size_t total_received = 0;
  size_t total_len;
  ssize_t received;
  int i;

  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);

  iov_copy = calloc ((size_t)iovcnt, sizeof (struct iovec));
  if (!iov_copy)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate iovec copy");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  memcpy (iov_copy, iov, (size_t)iovcnt * sizeof (struct iovec));

  TRY while (total_received < total_len)
  {
    int active_iovcnt = 0;
    struct iovec *active_iov = NULL;

    for (i = 0; i < iovcnt; i++)
      {
        if (iov_copy[i].iov_len > 0)
          {
            active_iov = &iov_copy[i];
            active_iovcnt = iovcnt - i;
            break;
          }
      }
    if (active_iov == NULL)
      break;

    received = SocketDgram_recvv (socket, active_iov, active_iovcnt);
    if (received == 0)
      {
        for (i = 0; i < iovcnt; i++)
          {
            if (iov_copy[i].iov_base != iov[i].iov_base)
              {
                size_t copied
                    = (char *)iov_copy[i].iov_base - (char *)iov[i].iov_base;
                iov[i].iov_len -= copied;
                iov[i].iov_base = (char *)iov[i].iov_base + copied;
              }
          }
        free (iov_copy);
        return (ssize_t)total_received;
      }
    total_received += (size_t)received;
    SocketCommon_advance_iov (iov_copy, iovcnt, (size_t)received);
  }

  for (i = 0; i < iovcnt; i++)
    {
      if (iov_copy[i].iov_base != iov[i].iov_base)
        {
          size_t copied
              = (char *)iov_copy[i].iov_base - (char *)iov[i].iov_base;
          iov[i].iov_len -= copied;
          iov[i].iov_base = (char *)iov[i].iov_base + copied;
        }
    }
  EXCEPT (SocketDgram_Failed)
  free (iov_copy);
  RERAISE;
  END_TRY;

  free (iov_copy);
  return (ssize_t)total_received;
}

#undef T
