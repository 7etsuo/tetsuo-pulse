/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>

#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "core/SocketConfig.h"
#define SOCKET_LOG_COMPONENT "SocketConvenience"
#include "core/SocketUtil.h"
#include "socket/Socket-private.h"
#include "socket/Socket.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

#define T Socket_T

SOCKET_DECLARE_MODULE_EXCEPTION (SocketConvenience);

#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketConvenience, e)

static inline int
is_connect_in_progress_error (int err)
{
  return err == EINPROGRESS || err == EINTR || err == EAGAIN
         || err == EWOULDBLOCK;
}

static int
get_socket_flags (int fd, int *flags_out)
{
  int flags;

  assert (flags_out != NULL);

  flags = fcntl (fd, F_GETFL);
  if (flags < 0)
    {
      SOCKET_ERROR_FMT ("Failed to get socket flags");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  *flags_out = flags;
  return 0;
}

static int
set_nonblocking_mode (int fd, int original_flags)
{
  if (fcntl (fd, F_SETFL, original_flags | O_NONBLOCK) < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set non-blocking mode");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  return 0;
}


static int
check_connect_result (int fd, const char *context_path)
{
  if (socket_check_so_error (fd) < 0)
    {
      SOCKET_ERROR_FMT (
          "Connect to %.*s failed", SOCKET_ERROR_MAX_HOSTNAME, context_path);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return 0;
}

static int
validate_unix_path (const char *path, size_t max_path_len)
{
  size_t path_len = strlen (path);

  if (path_len == 0 || path_len >= max_path_len)
    {
      SOCKET_ERROR_MSG ("Invalid Unix socket path length: %zu", path_len);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return 0;
}

static void
setup_unix_address (struct sockaddr_un *addr, const char *path)
{
  size_t path_len = strlen (path);

  memset (addr, 0, sizeof (*addr));
  addr->sun_family = AF_UNIX;

  if (path[0] == '@')
    {
      addr->sun_path[0] = '\0';
      memcpy (addr->sun_path + 1, path + 1, path_len - 1);
    }
  else
    {
      memcpy (addr->sun_path, path, path_len);
    }
}

static void
wait_for_unix_connect (int fd, const char *path, int timeout_ms)
{
  struct pollfd pfd;
  SOCKET_INIT_POLLFD (pfd, fd, POLLOUT);
  int poll_result = socket_poll_eintr_retry (&pfd, timeout_ms);

  if (poll_result < 0)
    {
      SOCKET_ERROR_FMT ("poll() failed during Unix connect");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  if (poll_result == 0)
    {
      errno = ETIMEDOUT;
      SOCKET_ERROR_MSG ("%s: Unix connect to %.*s",
                        SOCKET_ETIMEDOUT,
                        SOCKET_ERROR_MAX_HOSTNAME,
                        path);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  check_connect_result (fd, path);
}

static int
try_unix_connect (int fd, const struct sockaddr_un *addr, const char *path)
{
  int result = connect (fd, (const struct sockaddr *)addr, sizeof (*addr));

  if (result == 0 || errno == EISCONN)
    return 1;

  if (!is_connect_in_progress_error (errno))
    {
      SOCKET_ERROR_FMT (
          "Unix connect to %.*s failed", SOCKET_ERROR_MAX_HOSTNAME, path);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return 0;
}

static int
parse_ip_address (const char *ip_address,
                  struct sockaddr_storage *addr,
                  socklen_t *addrlen,
                  int port)
{
  struct sockaddr_in *addr4;
  struct sockaddr_in6 *addr6;

  assert (ip_address != NULL);
  assert (addr != NULL);
  assert (addrlen != NULL);

  memset (addr, 0, sizeof (*addr));

  addr4 = (struct sockaddr_in *)addr;
  if (inet_pton (AF_INET, ip_address, &addr4->sin_addr) == 1)
    {
      addr4->sin_family = AF_INET;
      addr4->sin_port = htons ((uint16_t)port);
      *addrlen = sizeof (struct sockaddr_in);
      return 0;
    }

  addr6 = (struct sockaddr_in6 *)addr;
  if (inet_pton (AF_INET6, ip_address, &addr6->sin6_addr) == 1)
    {
      addr6->sin6_family = AF_INET6;
      addr6->sin6_port = htons ((uint16_t)port);
      *addrlen = sizeof (struct sockaddr_in6);
      return 0;
    }

  SOCKET_ERROR_MSG ("Invalid IP address (not IPv4 or IPv6): %.*s",
                    SOCKET_ERROR_MAX_HOSTNAME,
                    ip_address);
  RAISE_MODULE_ERROR (Socket_Failed);

  return -1;
}

static void
with_nonblocking_scope (int fd,
                        int enable,
                        volatile int *original_flags,
                        volatile int *need_restore)
{
  assert (fd >= 0);
  assert (original_flags != NULL);
  assert (need_restore != NULL);

  if (!enable)
    {
      if (*need_restore)
        {
          socket_common_restore_blocking_mode (
              fd, (int)*original_flags, SOCKET_LOG_COMPONENT);
          *need_restore = 0;
        }
      return;
    }

  int flags_copy;
  get_socket_flags (fd, &flags_copy);
  *original_flags = flags_copy;
  if ((flags_copy & O_NONBLOCK) == 0)
    {
      set_nonblocking_mode (fd, flags_copy);
      *need_restore = 1;
    }
  else
    {
      *need_restore = 0;
    }
}

T
Socket_listen_tcp (const char *host, int port, int backlog)
{
  T server = NULL;

  assert (port >= 0 && port <= SOCKET_MAX_PORT);
  assert (backlog > 0);

  TRY
  {
    server = Socket_new (AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr (server);
    Socket_bind (server, host, port);
    Socket_listen (server, backlog);
  }
  EXCEPT (Socket_Failed)
  {
    if (server)
      Socket_free (&server);
    RERAISE;
  }
  END_TRY;

  return server;
}

T
Socket_connect_tcp (const char *host, int port, int timeout_ms)
{
  T client = NULL;

  assert (host != NULL);
  assert (port > 0 && port <= SOCKET_MAX_PORT);
  assert (timeout_ms >= 0);

  TRY
  {
    client = Socket_new (AF_INET, SOCK_STREAM, 0);

    if (timeout_ms > 0)
      {
        SocketTimeouts_T timeouts = { 0 };
        Socket_timeouts_get (client, &timeouts);
        timeouts.connect_timeout_ms = timeout_ms;
        Socket_timeouts_set (client, &timeouts);
      }

    Socket_connect (client, host, port);
  }
  EXCEPT (Socket_Failed)
  {
    if (client)
      Socket_free (&client);
    RERAISE;
  }
  END_TRY;

  return client;
}

static int
accept_poll_for_connection (int fd, int timeout_ms)
{
  struct pollfd pfd;
  int poll_result;

  SOCKET_INIT_POLLFD (pfd, fd, POLLIN);
  poll_result = socket_poll_eintr_retry (&pfd, timeout_ms);
  if (poll_result < 0)
    {
      SOCKET_ERROR_FMT ("poll() failed in accept_timeout");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  return poll_result;
}

T
Socket_accept_timeout (T socket, int timeout_ms)
{
  volatile T client = NULL;
  int fd = Socket_fd (socket);
  assert (socket);

  if (timeout_ms == -1)
    {
      TRY
      {
        client = Socket_accept (socket);
      }
      EXCEPT (Socket_Failed)
      {
        RERAISE;
      }
      END_TRY;
      return client;
    }

  int original_flags;
  volatile int need_restore = 0;
  with_nonblocking_scope (fd, 1, &original_flags, &need_restore);

  TRY
  {
    int do_accept = 1;

    if (timeout_ms > 0 && accept_poll_for_connection (fd, timeout_ms) == 0)
      do_accept = 0;

    if (do_accept)
      client = Socket_accept (socket);
  }
  FINALLY
  {
    with_nonblocking_scope (fd, 0, &original_flags, &need_restore);
  }
  END_TRY;

  return client;
}

int
Socket_connect_nonblocking (T socket, const char *ip_address, int port)
{
  struct sockaddr_storage addr;
  socklen_t addrlen = 0;
  int fd;
  int result;

  assert (socket);
  assert (ip_address != NULL);
  assert (port > 0 && port <= SOCKET_MAX_PORT);

  fd = Socket_fd (socket);

  parse_ip_address (ip_address, &addr, &addrlen, port);
  Socket_setnonblocking (socket);
  result = connect (fd, (struct sockaddr *)&addr, addrlen);

  if (result == 0)
    {
      return 0;
    }

  if (errno == EINPROGRESS || errno == EINTR)
    {
      return 1;
    }

  SOCKET_ERROR_FMT (
      "Connect to %.*s:%d failed", SOCKET_ERROR_MAX_HOSTNAME, ip_address, port);
  RAISE_MODULE_ERROR (Socket_Failed);
}

T
Socket_listen_unix (const char *path, int backlog)
{
  T server = NULL;

  assert (path != NULL);
  assert (backlog > 0);

  TRY
  {
    server = Socket_new (AF_UNIX, SOCK_STREAM, 0);
    Socket_bind_unix (server, path);
    Socket_listen (server, backlog);
  }
  EXCEPT (Socket_Failed)
  {
    if (server)
      Socket_free (&server);
    RERAISE;
  }
  END_TRY;

  return server;
}

/* For abstract namespace sockets (Linux), '@' prefix becomes '\0' */
void
Socket_connect_unix_timeout (T socket, const char *path, int timeout_ms)
{
  struct sockaddr_un addr;
  int fd;
  volatile int original_flags = 0;
  volatile int need_restore = 0;

  assert (socket);
  assert (path != NULL);
  assert (timeout_ms >= 0);

  fd = Socket_fd (socket);
  validate_unix_path (path, sizeof (addr.sun_path));
  setup_unix_address (&addr, path);

  if (timeout_ms == 0)
    {
      Socket_connect_unix (socket, path);
      return;
    }

  with_nonblocking_scope (fd, 1, &original_flags, &need_restore);

  if (try_unix_connect (fd, &addr, path))
    {
      with_nonblocking_scope (fd, 0, &original_flags, &need_restore);
      return;
    }

  TRY
  {
    wait_for_unix_connect (fd, path, timeout_ms);
  }
  FINALLY
  {
    with_nonblocking_scope (fd, 0, &original_flags, &need_restore);
  }
  END_TRY;
}

#undef T
