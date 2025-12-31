/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include "dns/SocketDNS.h"
#include "socket/Socket-private.h"
#include "socket/Socket.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

#if SOCKET_CONNECT_HAPPY_EYEBALLS
#include "socket/SocketHappyEyeballs.h"
#endif

#define T Socket_T

SOCKET_DECLARE_MODULE_EXCEPTION (SocketConnect);

#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketConnect, e)

static void
store_remote_addr (T socket, const struct sockaddr *addr, socklen_t addrlen)
{
  memcpy (&socket->base->remote_addr, addr, addrlen);
  socket->base->remote_addrlen = addrlen;
}

static int
socket_wait_for_connect (T socket, int timeout_ms)
{
  assert (socket);
  assert (timeout_ms >= 0);

  int fd = SocketBase_fd (socket->base);
  struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
  int result = socket_poll_eintr_retry (&pfd, timeout_ms);

  if (result < 0)
    return -1;

  if (result == 0)
    {
      errno = ETIMEDOUT;
      return -1;
    }

  return socket_check_so_error (fd);
}


static int
socket_connect_with_poll_wait (T socket,
                               const struct sockaddr *addr,
                               socklen_t addrlen,
                               int timeout_ms)
{
  if (connect (SocketBase_fd (socket->base), addr, addrlen) == 0
      || errno == EISCONN)
    {
      store_remote_addr (socket, addr, addrlen);
      return 0;
    }

  int saved_errno = errno;

  if (saved_errno == EINPROGRESS || saved_errno == EINTR)
    {
      if (socket_wait_for_connect (socket, timeout_ms) == 0)
        {
          store_remote_addr (socket, addr, addrlen);
          return 0;
        }
      saved_errno = errno;
    }

  errno = saved_errno;
  return -1;
}

static const char *
socket_get_connect_error_msg (int saved_errno)
{
  switch (saved_errno)
    {
    case ECONNREFUSED:
      return SOCKET_ECONNREFUSED;
    case ENETUNREACH:
      return SOCKET_ENETUNREACH;
    case ETIMEDOUT:
      return SOCKET_ETIMEDOUT;
    default:
      return "Connect failed";
    }
}

static void
socket_handle_connect_error (const char *host, int port)
{
  SocketMetrics_increment (SOCKET_METRIC_SOCKET_CONNECT_FAILURE, 1);
  SOCKET_ERROR_FMT ("%s: %.*s:%d",
                    socket_get_connect_error_msg (errno),
                    SOCKET_ERROR_MAX_HOSTNAME,
                    host,
                    port);
}

static void
socket_cache_remote_endpoint (T socket)
{
  if (SocketCommon_cache_endpoint (
          SocketBase_arena (socket->base),
          (struct sockaddr *)&socket->base->remote_addr,
          socket->base->remote_addrlen,
          &socket->base->remoteaddr,
          &socket->base->remoteport)
      != 0)
    {
      socket->base->remoteaddr = NULL;
      socket->base->remoteport = 0;
    }
}

static void
socket_emit_connect_event (T socket)
{
  SocketEvent_emit_connect (Socket_fd (socket),
                            SocketBase_remoteaddr (socket->base),
                            SocketBase_remoteport (socket->base),
                            SocketBase_localaddr (socket->base),
                            SocketBase_localport (socket->base));
}

static void
socket_handle_successful_connect (T socket)
{
  SocketMetrics_increment (SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 1);
  SocketCommon_update_local_endpoint (socket->base);
  socket_cache_remote_endpoint (socket);
  socket_emit_connect_event (socket);
}

static int
connect_attempt_immediate (T socket,
                           const struct sockaddr *addr,
                           socklen_t addrlen)
{
  if (connect (SocketBase_fd (socket->base), addr, addrlen) == 0
      || errno == EINPROGRESS || errno == EISCONN)
    {
      store_remote_addr (socket, addr, addrlen);
      return 0;
    }
  return -1;
}

static int
connect_setup_nonblock (T socket, int *original_flags)
{
  int fd = SocketBase_fd (socket->base);
  *original_flags = fcntl (fd, F_GETFL);
  if (*original_flags < 0)
    return -1;

  if ((*original_flags & O_NONBLOCK) == 0)
    {
      if (fcntl (fd, F_SETFL, *original_flags | O_NONBLOCK) < 0)
        return -1;
    }
  return 0;
}

static int
connect_wait_completion (T socket,
                         const struct sockaddr *addr,
                         socklen_t addrlen,
                         int timeout_ms,
                         int original_flags)
{
  int restore_blocking = (original_flags & O_NONBLOCK) == 0;
  int result
      = socket_connect_with_poll_wait (socket, addr, addrlen, timeout_ms);

  if (restore_blocking)
    socket_common_restore_blocking_mode (
        SocketBase_fd (socket->base), original_flags, "SocketConnect");

  return result;
}

static int
try_connect_address (T socket,
                     const struct sockaddr *addr,
                     socklen_t addrlen,
                     int timeout_ms)
{
  int original_flags;

  assert (socket);
  assert (addr);

  if (timeout_ms <= 0)
    return connect_attempt_immediate (socket, addr, addrlen);

  if (connect_setup_nonblock (socket, &original_flags) < 0)
    return -1;

  return connect_wait_completion (
      socket, addr, addrlen, timeout_ms, original_flags);
}

static int
try_connect_resolved_addresses (T socket,
                                struct addrinfo *res,
                                int socket_family,
                                int timeout_ms)
{
  struct addrinfo *rp;
  int saved_errno = 0;

  for (rp = res; rp != NULL; rp = rp->ai_next)
    {
      if (socket_family != AF_UNSPEC && rp->ai_family != socket_family)
        continue;

      if (try_connect_address (socket, rp->ai_addr, rp->ai_addrlen, timeout_ms)
          == 0)
        return 0;
      saved_errno = errno;
    }

  errno = saved_errno;
  return -1;
}

static void
connect_resolve_address (const char *host,
                         int port,
                         int socket_family,
                         struct addrinfo **res)
{
  if (SocketCommon_resolve_address (
          host, port, NULL, res, Socket_Failed, socket_family, 0)
      != 0)
    errno = EAI_FAIL;
}

static void
connect_try_addresses (T sock,
                       struct addrinfo *res,
                       int socket_family,
                       int timeout_ms)
{
  int saved_errno;

  if (try_connect_resolved_addresses (sock, res, socket_family, timeout_ms)
      == 0)
    {
      socket_handle_successful_connect (sock);
      return;
    }

  saved_errno = errno;
  if (SocketError_is_retryable_errno (saved_errno))
    {
      errno = saved_errno;
      return;
    }

  socket_handle_connect_error ("resolved", 0);
  RAISE_MODULE_ERROR (Socket_Failed);
}

static void
connect_validate_params (T socket, const char *host, int port)
{
  assert (socket);
  assert (host);
  (void)socket;
  SocketCommon_validate_host_not_null (host, Socket_Failed);
  SocketCommon_validate_port (port, Socket_Failed);
}

static void
connect_execute (T sock, struct addrinfo *res, int socket_family)
{
  int timeout_ms = sock->base->timeouts.connect_timeout_ms;
  connect_try_addresses (sock, res, socket_family, timeout_ms);
}

#if SOCKET_CONNECT_HAPPY_EYEBALLS
static int
socket_is_hostname (const char *host)
{
  struct in_addr addr4;
  struct in6_addr addr6;

  if (inet_pton (AF_INET, host, &addr4) == 1)
    return 0;
  if (inet_pton (AF_INET6, host, &addr6) == 1)
    return 0;
  return 1;
}

static void
he_configure (T socket, SocketHE_Config_T *config)
{
  SocketHappyEyeballs_config_defaults (config);
  if (socket->base->timeouts.connect_timeout_ms > 0)
    config->total_timeout_ms = socket->base->timeouts.connect_timeout_ms;
}

static Socket_T
he_attempt_connect (const char *host, int port, SocketHE_Config_T *config)
{
  Socket_T he_socket = NULL;

  TRY
  {
    he_socket = SocketHappyEyeballs_connect (host, port, config);
  }
  EXCEPT (SocketHE_Failed)
  {
    SOCKET_RAISE_MSG (SocketConnect,
                      Socket_Failed,
                      "Happy Eyeballs connection failed to %s:%d",
                      host,
                      port);
  }
  END_TRY;

  return he_socket;
}

static void
he_transfer_fd (T socket, Socket_T he_socket)
{
  int fd_old = socket->base->fd;
  if (fd_old >= 0)
    close (fd_old);

  socket->base->fd = he_socket->base->fd;
  store_remote_addr (socket,
                     (const struct sockaddr *)&he_socket->base->remote_addr,
                     he_socket->base->remote_addrlen);

  he_socket->base->fd = -1;
  Socket_free (&he_socket);
}

/* NOTE: This function performs Happy Eyeballs connection racing which
 * requires creating new sockets. The original socket's fd is closed and
 * replaced with the winning connection's fd. Socket options set on the
 * original socket are NOT preserved.
 *
 * For applications that need to preserve socket options, use
 * SocketHappyEyeballs_connect() directly instead.
 */
static int
socket_connect_happy_eyeballs (T socket, const char *host, int port)
{
  SocketHE_Config_T config;
  Socket_T he_socket;

  if (!socket_is_hostname (host))
    return 0;

  he_configure (socket, &config);
  he_socket = he_attempt_connect (host, port, &config);

  if (!he_socket)
    return 0;

  he_transfer_fd (socket, he_socket);
  socket_handle_successful_connect (socket);
  return 1;
}
#endif

void
Socket_connect (T socket, const char *host, int port)
{
  struct addrinfo *res = NULL;
  volatile T vsock = socket;
  int socket_family;

  connect_validate_params (socket, host, port);

#if SOCKET_CONNECT_HAPPY_EYEBALLS
  if (socket_connect_happy_eyeballs (socket, host, port))
    return;
#endif

  socket_family = SocketCommon_get_socket_family (socket->base);

  TRY
  {
    connect_resolve_address (host, port, socket_family, &res);
    if (!res)
      {
        errno = EAI_FAIL;
        RETURN;
      }
    connect_execute ((T)vsock, res, socket_family);
    SocketCommon_free_addrinfo (res);
  }
  EXCEPT (Socket_Failed)
  {
    int saved_errno = errno;
    SocketCommon_free_addrinfo (res);
    if (SocketError_is_retryable_errno (saved_errno))
      {
        errno = saved_errno;
        RETURN;
      }
    errno = saved_errno;
    RERAISE;
  }
  END_TRY;
}

void
Socket_connect_with_addrinfo (T socket, struct addrinfo *res)
{
  int socket_family;

  assert (socket);
  assert (res);

  socket_family = SocketCommon_get_socket_family (socket->base);

  if (try_connect_resolved_addresses (
          socket, res, socket_family, socket->base->timeouts.connect_timeout_ms)
      == 0)
    {
      socket_handle_successful_connect (socket);
      return;
    }

  socket_handle_connect_error ("resolved", 0);
  RAISE_MODULE_ERROR (Socket_Failed);
}

Request_T
Socket_connect_async (SocketDNS_T dns, T socket, const char *host, int port)
{
  Request_T req;

  assert (dns);
  assert (socket);

  SocketCommon_validate_host_not_null (host, Socket_Failed);
  SocketCommon_validate_port (port, Socket_Failed);

  req = SocketDNS_resolve (dns, host, port, NULL, NULL);
  if (socket->base->timeouts.dns_timeout_ms > 0)
    SocketDNS_request_settimeout (
        dns, req, socket->base->timeouts.dns_timeout_ms);
  return req;
}

void
Socket_connect_async_cancel (SocketDNS_T dns, Request_T req)
{
  assert (dns);

  if (req)
    SocketDNS_cancel (dns, req);
}

#undef T
