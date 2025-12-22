/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * Socket.c - Core socket lifecycle and basic operations
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketMetrics.h"
#include "dns/SocketDNS.h"
#include "socket/Socket.h"
#define SOCKET_LOG_COMPONENT "Socket"
#include "core/SocketUtil.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"
#include "socket/SocketIO.h"

#include "socket/Socket-private.h"

#include <sys/stat.h>
#include <sys/un.h>

/* For TCP_INFO (Linux-specific RTT stats) - netinet/tcp.h included via SocketConfig.h */

#if SOCKET_HAS_TLS
#include "tls/SocketTLS-private.h" /* For tls_cleanup_alpn_temp etc. */
#include <openssl/ssl.h>
#endif

#define T Socket_T

/* Shared live count tracker - see SocketLiveCount.h */
static struct SocketLiveCount socket_live_tracker
    = SOCKETLIVECOUNT_STATIC_INIT;

#define socket_live_increment()                                               \
  SocketLiveCount_increment (&socket_live_tracker)
#define socket_live_decrement()                                               \
  SocketLiveCount_decrement (&socket_live_tracker)

const Except_T Socket_Failed = { &Socket_Failed, "Socket operation failed" };
const Except_T Socket_Closed = { &Socket_Closed, "Socket closed" };

SOCKET_DECLARE_MODULE_EXCEPTION (Socket);

#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (Socket, e)

int
Socket_error_is_retryable (int err)
{
  return SocketError_is_retryable_errno (err);
}

int
Socket_ignore_sigpipe (void)
{
  struct sigaction sa;

  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = SIG_IGN;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;

  return sigaction (SIGPIPE, &sa, NULL);
}

static void
cache_remote_endpoint (SocketBase_T base, const struct sockaddr *addr,
                       socklen_t addrlen)
{
  if (SocketCommon_cache_endpoint (SocketBase_arena (base), addr, addrlen,
                                   &base->remoteaddr, &base->remoteport)
      != 0)
    {
      base->remoteaddr = NULL;
      base->remoteport = 0;
    }
}

static T
socket_alloc (Arena_T arena, const char *alloc_type)
{
  (void)alloc_type;
  T sock = Arena_calloc (arena, 1, sizeof (struct Socket_T), __FILE__, __LINE__);
  atomic_store_explicit (&sock->freed, 0, memory_order_relaxed);
  return sock;
}

static SocketBase_T
socket_alloc_base (Arena_T arena, const char *alloc_type)
{
  (void)alloc_type;
  return Arena_calloc (arena, 1, sizeof (struct SocketBase_T),
                       __FILE__, __LINE__);
}

#if SOCKET_HAS_TLS
void
socket_init_tls_fields (Socket_T sock)
{
  sock->tls_ctx = NULL;
  sock->tls_ssl = NULL;
  sock->tls_enabled = 0;
  sock->tls_handshake_done = 0;
  sock->tls_shutdown_done = 0;
  sock->tls_last_handshake_state = 0;
  sock->tls_sni_hostname = NULL;
  sock->tls_read_buf = NULL;
  sock->tls_write_buf = NULL;
  sock->tls_read_buf_len = 0;
  sock->tls_write_buf_len = 0;
  sock->tls_timeouts = (SocketTimeouts_T){ 0 };
  sock->tls_renegotiation_count = 0;

  sock->tls_ktls_enabled = 0;
  sock->tls_ktls_tx_active = 0;
  sock->tls_ktls_rx_active = 0;
}

static void
socket_cleanup_tls (Socket_T s)
{
  if (s->tls_ssl)
    {
      SSL *tls_ssl = (SSL *)s->tls_ssl;
      tls_cleanup_alpn_temp (tls_ssl); /* Free ALPN temp if stored */
      SSL_free (tls_ssl);
      s->tls_ssl = NULL;
    }
}

#endif /* SOCKET_HAS_TLS */

static void
socket_init_after_alloc (T sock)
{
  sock->base->stats.create_time_ms = Socket_get_monotonic_ms ();
  sock->base->stats.connect_time_ms = 0;
  sock->base->stats.last_recv_time_ms = 0;
  sock->base->stats.last_send_time_ms = 0;
  sock->base->stats.bytes_sent = 0;
  sock->base->stats.bytes_received = 0;
  sock->base->stats.packets_sent = 0;
  sock->base->stats.packets_received = 0;
  sock->base->stats.send_errors = 0;
  sock->base->stats.recv_errors = 0;
  sock->base->stats.rtt_us = -1;
  sock->base->stats.rtt_var_us = -1;

#if SOCKET_HAS_TLS
  socket_init_tls_fields (sock);
#endif

  socket_live_increment ();
  SocketMetrics_update_peak_if_needed (Socket_debug_live_count ());
}

static int
get_socket_type (int fd, int *type_out)
{
  socklen_t opt_len = sizeof (*type_out);
  return getsockopt (fd, SOL_SOCKET, SO_TYPE, type_out, &opt_len);
}

static void
validate_fd_is_socket (int fd)
{
  int type;
  if (get_socket_type (fd, &type) < 0)
    SOCKET_RAISE_FMT (Socket, Socket_Failed,
                      "Invalid file descriptor (not a socket): fd=%d", fd);
}

static T
allocate_socket_from_fd (Arena_T arena, int fd)
{
  volatile T sock = NULL;

  TRY
  {
    sock = socket_alloc (arena, "sock for new_from_fd");
    ((T)sock)->base = socket_alloc_base (arena, "base for new_from_fd");
  }
  EXCEPT (Arena_Failed)
  {
    Arena_dispose (&arena);
    RAISE_MODULE_ERROR (Socket_Failed);
  }
  END_TRY;

  ((T)sock)->base->arena = arena;
  SocketCommon_init_base (((T)sock)->base, fd, AF_UNSPEC, 0, 0, Socket_Failed);
  return (T)sock;
}

static void
setup_socket_nonblocking (T socket)
{
  int fd = SocketBase_fd (socket->base);
  int flags = fcntl (fd, F_GETFL, 0);
  if (flags < 0)
    {
      Socket_free (&socket);
      SOCKET_RAISE_FMT (Socket, Socket_Failed,
                        "Failed to get socket flags for fd=%d", fd);
    }

  if (fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      Socket_free (&socket);
      SOCKET_RAISE_FMT (Socket, Socket_Failed,
                        "Failed to set non-blocking mode for fd=%d", fd);
    }
}

T
Socket_new (int domain, int type, int protocol)
{
  volatile SocketBase_T base = NULL;
  volatile T sock = NULL;

  TRY base = SocketCommon_new_base (domain, type, protocol);
  EXCEPT (Arena_Failed)
  RAISE_MODULE_ERROR (Socket_Failed);
  END_TRY;

  if (!base || !SocketBase_arena ((SocketBase_T)base))
    SOCKET_RAISE_MSG (Socket, Socket_Failed,
                      "Invalid base from new_base (null arena)");

  TRY sock = socket_alloc (SocketBase_arena ((SocketBase_T)base), "socket");
  EXCEPT (Arena_Failed)
  {
    SocketCommon_free_base ((SocketBase_T *)&base);
    RAISE_MODULE_ERROR (Socket_Failed);
  }
  END_TRY;

  ((T)sock)->base = (SocketBase_T)base;

  socket_init_after_alloc ((T)sock);

  return (T)sock;
}

void
Socket_free (T *socket)
{
  T s = *socket;
  if (!s)
    return;

  int was_first
      = (atomic_exchange_explicit (&s->freed, 1, memory_order_acq_rel) == 0);
  *socket = NULL;

  if (!was_first)
    return;

#if SOCKET_HAS_TLS
  socket_cleanup_tls(s);
#endif

  SocketCommon_free_base (&s->base);
  socket_live_decrement ();
}

T
Socket_new_from_fd (int fd)
{
  Arena_T arena;

  assert (fd >= 0);

  validate_fd_is_socket (fd);

  arena = Arena_new ();
  if (!arena)
    SOCKET_RAISE_MSG (Socket, Socket_Failed,
                      SOCKET_ENOMEM ": Cannot create arena for new_from_fd");

  T sock = allocate_socket_from_fd (arena, fd);

  socket_init_after_alloc (sock);
  setup_socket_nonblocking (sock);
  return sock;
}

ssize_t
Socket_send (T socket, const void *buf, size_t len)
{
  return socket_send_internal (socket, buf, len, SOCKET_MSG_NOSIGNAL);
}

ssize_t
Socket_recv (T socket, void *buf, size_t len)
{
  return socket_recv_internal (socket, buf, len, 0);
}

void
Socket_listen (Socket_T socket, int backlog)
{
  assert (socket);
  if (backlog <= 0)
    SOCKET_RAISE_MSG (Socket, Socket_Failed,
                      "Invalid backlog value: %d (must be > 0)", backlog);

  if (backlog > SOCKET_MAX_LISTEN_BACKLOG)
    backlog = SOCKET_MAX_LISTEN_BACKLOG;

  if (listen (SocketBase_fd (socket->base), backlog) < 0)
    SOCKET_RAISE_FMT (Socket, Socket_Failed,
                      "Failed to listen on socket (backlog=%d)", backlog);
}

int
Socket_debug_live_count (void)
{
  return SocketLiveCount_get (&socket_live_tracker);
}

static inline bool
unix_is_abstract_path (const char *path)
{
  return path && path[0] == '@';
}

static int
unix_validate_path (const char *path, size_t path_len)
{
  if (path_len > sizeof (struct sockaddr_un)
                     - offsetof (struct sockaddr_un, sun_path) - 1)
    {
      SOCKET_ERROR_MSG ("Unix socket path too long (max %zu characters)",
                        sizeof (struct sockaddr_un)
                            - offsetof (struct sockaddr_un, sun_path) - 1);
      return -1;
    }

  if (strstr (path, "/../") || strcmp (path, "..") == 0
      || strncmp (path, "../", 3) == 0
      || (path_len >= 3 && strcmp (path + path_len - 3, "/..") == 0))
    {
      SOCKET_ERROR_MSG (
          "Invalid Unix socket path: directory traversal detected");
      return -1;
    }

  return 0;
}

static void
unix_unlink_stale (const char *path)
{
  struct stat st;
  if (stat (path, &st) == 0 && S_ISSOCK (st.st_mode) && unlink (path) < 0)
    SOCKET_RAISE_MSG (Socket, Socket_Failed,
                      "Failed to unlink stale socket %s", path);
}

static void
unix_setup_abstract_socket (struct sockaddr_un *addr, const char *path,
                            size_t path_len)
{
  size_t name_len = path_len > 0 ? path_len - 1 : 0;
  size_t max_name_len = sizeof (addr->sun_path) - 1;
  if (name_len > max_name_len)
    name_len = max_name_len;

  addr->sun_path[0] = '\0';
  if (name_len > 0)
    memcpy (addr->sun_path + 1, path + 1, name_len);
}

static void
unix_setup_regular_socket (struct sockaddr_un *addr, const char *path,
                           size_t path_len)
{
  size_t max_path_len = sizeof (addr->sun_path) - 1;
  if (path_len > max_path_len)
    path_len = max_path_len;

  memcpy (addr->sun_path, path, path_len);
  addr->sun_path[path_len] = '\0';
}

static void
unix_setup_sockaddr (struct sockaddr_un *addr, const char *path)
{
  size_t path_len;

  assert (addr);
  assert (path);

  path_len = strlen (path);
  memset (addr, 0, sizeof (*addr));
  addr->sun_family = AF_UNIX;

  if (path[0] == '@')
    unix_setup_abstract_socket (addr, path, path_len);
  else
    unix_setup_regular_socket (addr, path, path_len);
}

void
Socket_bind_unix (Socket_T socket, const char *path)
{
  struct sockaddr_un addr;
  size_t path_len;

  assert (socket);
  assert (path);

  path_len = strlen (path);

  if (unix_validate_path (path, path_len) < 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  if (!unix_is_abstract_path (path))
    unix_unlink_stale (path);

  unix_setup_sockaddr (&addr, path);

  if (bind (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
            sizeof (addr))
      < 0)
    SOCKET_RAISE_FMT (Socket, Socket_Failed,
                      "Failed to bind Unix socket to %s", path);

  SocketCommon_update_local_endpoint (socket->base);
}

void
Socket_connect_unix (Socket_T socket, const char *path)
{
  struct sockaddr_un addr;
  size_t path_len;

  assert (socket);
  assert (path);

  path_len = strlen (path);

  if (unix_validate_path (path, path_len) < 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  unix_setup_sockaddr (&addr, path);

  if (connect (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
               sizeof (addr))
      < 0)
    {
      if (errno == ENOENT)
        SOCKET_RAISE_FMT (Socket, Socket_Failed,
                          "Unix socket does not exist: %s", path);
      else if (errno == ECONNREFUSED)
        SOCKET_RAISE_FMT (Socket, Socket_Failed, SOCKET_ECONNREFUSED ": %s",
                          path);
      else
        SOCKET_RAISE_FMT (Socket, Socket_Failed,
                          "Failed to connect to Unix socket %s", path);
    }

  memcpy (&socket->base->remote_addr, &addr, sizeof (addr));
  socket->base->remote_addrlen = sizeof (addr);
  SocketCommon_update_local_endpoint (socket->base);
}

int
Socket_isconnected (T socket)
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof (addr);

  assert (socket);
  memset (&addr, 0, sizeof (addr));

  if (socket->base->remoteaddr != NULL)
    return 1;

  if (getpeername (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
                   &len)
      == 0)
    {
      if (socket->base->remoteaddr == NULL
          && SocketBase_arena (socket->base) != NULL)
        cache_remote_endpoint (socket->base, (struct sockaddr *)&addr, len);
      return 1;
    }

  if (errno == ENOTCONN)
    return 0;

  return 0;
}

int
Socket_isbound (T socket)
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof (addr);

  assert (socket);
  memset (&addr, 0, sizeof (addr));

  if (socket->base->localaddr != NULL)
    return 1;

  if (getsockname (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
                   &len)
      == 0)
    return SocketCommon_check_bound_by_family (&addr);

  return 0;
}

int
Socket_islistening (T socket)
{
  assert (socket);

  if (!Socket_isbound (socket))
    return 0;

  if (Socket_isconnected (socket))
    return 0;

  {
    int error = 0;
    socklen_t error_len = sizeof (error);

    if (getsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET, SO_ERROR,
                    &error, &error_len)
        == 0)
      {
        if (error != 0 && error != ENOTCONN)
          return 0;
      }
  }

  return 1;
}

int
Socket_fd (const T socket)
{
  assert (socket);
  return SocketBase_fd (socket->base);
}

const char *
Socket_getpeeraddr (const T socket)
{
  assert (socket);
  return socket->base->remoteaddr ? socket->base->remoteaddr : "(unknown)";
}

int
Socket_getpeerport (const T socket)
{
  assert (socket);
  return socket->base->remoteport;
}

const char *
Socket_getlocaladdr (const T socket)
{
  assert (socket);
  return socket->base->localaddr ? socket->base->localaddr : "(unknown)";
}

int
Socket_getlocalport (const T socket)
{
  assert (socket);
  return socket->base->localport;
}

static int
is_common_bind_error (int err)
{
  return err == EADDRINUSE || err == EACCES || err == EADDRNOTAVAIL
         || err == EAFNOSUPPORT;
}

static void
bind_resolve_address (const char *host, int port, int socket_family,
                      struct addrinfo **res)
{
  if (SocketCommon_resolve_address (host, port, NULL, res, Socket_Failed,
                                    socket_family, 0)
      != 0)
    errno = EAI_FAIL;
}

static void
bind_try_addresses (T sock, struct addrinfo *res, int socket_family)
{
  int bind_result = SocketCommon_try_bind_resolved_addresses (
      sock->base, res, socket_family, Socket_Failed);

  if (bind_result == 0)
    {
      SocketCommon_update_local_endpoint (sock->base);
      return;
    }

  int saved_errno = errno;
  if (is_common_bind_error (saved_errno))
    {
      errno = saved_errno;
      return;
    }

  SocketCommon_format_bind_error (NULL, 0);
  RAISE_MODULE_ERROR (Socket_Failed);
}

void
Socket_bind (T socket, const char *host, int port)
{
  struct addrinfo *res = NULL;
  int socket_family;
  volatile T vsock = socket;

  assert (socket);

  SocketCommon_validate_port (port, Socket_Failed);
  host = SocketCommon_normalize_wildcard_host (host);
  socket_family = SocketCommon_get_socket_family (socket->base);

  TRY
  {
    bind_resolve_address (host, port, socket_family, &res);
    if (!res)
      RETURN;

    bind_try_addresses ((T)vsock, res, socket_family);

    SocketCommon_free_addrinfo (res);
  }
  EXCEPT (Socket_Failed)
  {
    int saved_errno = errno;
    SocketCommon_free_addrinfo (res);
    if (is_common_bind_error (saved_errno))
      {
        errno = saved_errno;
        return;
      }
    errno = saved_errno;
    RERAISE;
  }
  END_TRY;
}

void
Socket_bind_with_addrinfo (T socket, struct addrinfo *res)
{
  int socket_family;

  assert (socket);
  assert (res);

  socket_family = SocketCommon_get_socket_family (socket->base);

  if (SocketCommon_try_bind_resolved_addresses (socket->base, res,
                                                socket_family, Socket_Failed)
      == 0)
    return;

  SocketCommon_format_bind_error (NULL, 0);
  RAISE_MODULE_ERROR (Socket_Failed);
}

Request_T
Socket_bind_async (SocketDNS_T dns, T socket, const char *host, int port)
{
  struct addrinfo hints, *res = NULL;

  assert (dns);
  assert (socket);

  SocketCommon_validate_port (port, Socket_Failed);
  host = SocketCommon_normalize_wildcard_host (host);

  if (host == NULL)
    {
      SocketCommon_setup_hints (&hints, SOCKET_STREAM_TYPE, SOCKET_AI_PASSIVE);
      if (SocketCommon_resolve_address (NULL, port, &hints, &res,
                                        Socket_Failed, SOCKET_AF_UNSPEC, 1)
          != 0)
        RAISE_MODULE_ERROR (Socket_Failed);

      return SocketDNS_create_completed_request (dns, res, port);
    }

  {
    Request_T req = SocketDNS_resolve (dns, host, port, NULL, NULL);
    if (socket->base->timeouts.dns_timeout_ms > 0)
      SocketDNS_request_settimeout (dns, req,
                                    socket->base->timeouts.dns_timeout_ms);
    return req;
  }
}

void
Socket_bind_async_cancel (SocketDNS_T dns, Request_T req)
{
  assert (dns);

  if (req)
    SocketDNS_cancel (dns, req);
}

static int accept_connection (T socket, struct sockaddr_storage *addr,
                              socklen_t *addrlen);
static T create_accepted_socket (int newfd,
                                 const struct sockaddr_storage *addr,
                                 socklen_t addrlen);

static Arena_T
accept_create_arena (int newfd)
{
  volatile Arena_T arena = NULL;

  TRY arena = Arena_new ();
  EXCEPT (Arena_Failed)
  {
    SAFE_CLOSE (newfd);
    SOCKET_RAISE_MSG (Socket, Socket_Failed,
                      SOCKET_ENOMEM ": Cannot allocate arena");
  }
  END_TRY;

  return (Arena_T)arena;
}

static T
accept_alloc_socket (Arena_T arena)
{
  volatile T newsocket = NULL;

  TRY newsocket = socket_alloc (arena, "accepted socket");
  EXCEPT (Arena_Failed)
  {
    Arena_dispose (&arena);
    RAISE_MODULE_ERROR (Socket_Failed);
  }
  END_TRY;

  return (T)newsocket;
}

static SocketBase_T
accept_alloc_base (Arena_T arena)
{
  volatile SocketBase_T base = NULL;

  TRY base = socket_alloc_base (arena, "accepted base");
  EXCEPT (Arena_Failed)
  {
    Arena_dispose (&arena);
    RAISE_MODULE_ERROR (Socket_Failed);
  }
  END_TRY;

  return (SocketBase_T)base;
}

static int
accept_infer_socket_type (int newfd, Arena_T arena)
{
  int type_opt;

  if (get_socket_type (newfd, &type_opt) < 0)
    {
      Arena_dispose (&arena);
      SAFE_CLOSE (newfd);
      SOCKET_RAISE_FMT (Socket, Socket_Failed, "Failed to get SO_TYPE");
    }
  return type_opt;
}

static void
accept_init_socket (T newsocket, SocketBase_T base, Arena_T arena, int newfd,
                    const struct sockaddr_storage *addr, socklen_t addrlen,
                    int type_opt)
{
  int domain = ((const struct sockaddr *)addr)->sa_family;

  newsocket->base = base;
  base->arena = arena;
  base->fd = newfd;

  SocketCommon_init_base (base, newfd, domain, type_opt, 0, Socket_Failed);

  memcpy (&base->remote_addr, addr, addrlen);
  base->remote_addrlen = addrlen;
  base->remoteaddr = NULL;
  base->remoteport = 0;
  base->localaddr = NULL;
  base->localport = 0;

  socket_init_after_alloc (newsocket);
}

static int
accept_connection (T socket, struct sockaddr_storage *addr, socklen_t *addrlen)
{
  int newfd;

#if SOCKET_HAS_ACCEPT4
  newfd = accept4 (SocketBase_fd (socket->base), (struct sockaddr *)addr,
                   addrlen, SOCKET_SOCK_CLOEXEC);
#else
  newfd = accept (SocketBase_fd (socket->base), (struct sockaddr *)addr,
                  addrlen);
#endif

  if (newfd < 0)
    {
      if (socketio_is_wouldblock ())
        return -1;
      SOCKET_RAISE_FMT (Socket, Socket_Failed, "Failed to accept connection");
    }

#if !SOCKET_HAS_ACCEPT4
  if (SocketCommon_setcloexec (newfd, 1) < 0)
    {
      SAFE_CLOSE (newfd);
      SOCKET_RAISE_FMT (Socket, Socket_Failed,
                        "Failed to set close-on-exec flag");
    }
#endif

  return newfd;
}

static T
create_accepted_socket (int newfd, const struct sockaddr_storage *addr,
                        socklen_t addrlen)
{
  Arena_T arena = accept_create_arena (newfd);
  T newsocket = accept_alloc_socket (arena);
  SocketBase_T base = accept_alloc_base (arena);
  int type_opt = accept_infer_socket_type (newfd, arena);

  accept_init_socket (newsocket, base, arena, newfd, addr, addrlen, type_opt);

  return newsocket;
}

T
Socket_accept (T socket)
{
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof (addr);
  int newfd = -1;
  T newsocket = NULL;

  assert (socket);
  memset (&addr, 0, sizeof (addr));

  TRY
  {
    newfd = accept_connection (socket, &addr, &addrlen);
    if (newfd < 0)
      RETURN NULL;

    newsocket = create_accepted_socket (newfd, &addr, addrlen);
    cache_remote_endpoint (newsocket->base, (struct sockaddr *)&addr, addrlen);

    SocketCommon_update_local_endpoint (newsocket->base);
    SocketEvent_emit_accept (
        SocketBase_fd (newsocket->base), newsocket->base->remoteaddr,
        newsocket->base->remoteport, newsocket->base->localaddr,
        newsocket->base->localport);

    RETURN newsocket;
  }
  EXCEPT (Socket_Failed)
  {
    if (newfd >= 0)
      SAFE_CLOSE (newfd);
    RERAISE;
  }
  END_TRY;
  return NULL;
}

static void
socketpair_validate_type (int type)
{
  if (type != SOCK_STREAM && type != SOCK_DGRAM)
    SOCKET_RAISE_MSG (Socket, Socket_Failed,
                      "Invalid socket type for socketpair: %d (must be "
                      "SOCK_STREAM or SOCK_DGRAM)",
                      type);
}

static void
socketpair_create_fds (int type, int sv[2])
{
#if SOCKET_HAS_SOCK_CLOEXEC
  if (socketpair (AF_UNIX, type | SOCKET_SOCK_CLOEXEC, 0, sv) < 0)
#else
  if (socketpair (AF_UNIX, type, 0, sv) < 0)
#endif
    SOCKET_RAISE_FMT (Socket, Socket_Failed,
                      "Failed to create socket pair (type=%d)", type);

#if !SOCKET_HAS_SOCK_CLOEXEC
  SocketCommon_set_cloexec_fd (sv[0], true, Socket_Failed);
  SocketCommon_set_cloexec_fd (sv[1], true, Socket_Failed);
#endif
}

static Arena_T
socketpair_allocate_socket (int fd, int type, Socket_T *out_socket)
{
  Arena_T arena = Arena_new ();
  volatile Socket_T sock = NULL;

  if (!arena)
    SOCKET_RAISE_MSG (Socket, Socket_Failed,
                      SOCKET_ENOMEM ": Cannot allocate arena for socket pair");

  TRY
  {
    sock = socket_alloc (arena, "socket pair");
    ((Socket_T)sock)->base = socket_alloc_base (arena, "socket pair base");
  }
  EXCEPT (Arena_Failed)
  {
    Arena_dispose (&arena);
    RAISE_MODULE_ERROR (Socket_Failed);
  }
  END_TRY;

  ((Socket_T)sock)->base->arena = arena;
  SocketCommon_init_base (((Socket_T)sock)->base, fd, AF_UNIX, type, 0, Socket_Failed);
  ((Socket_T)sock)->base->remoteaddr = NULL;

  socket_init_after_alloc ((Socket_T)sock);

  *out_socket = (Socket_T)sock;
  return arena;
}

static void
socketpair_cleanup_socket (Socket_T sock, int fd)
{
  if (sock)
    {
#if SOCKET_HAS_TLS
      socket_cleanup_tls (sock);
#endif
      SocketCommon_free_base (&sock->base);
      socket_live_decrement ();
    }
  else if (fd >= 0)
    {
      SAFE_CLOSE (fd);
    }
}

void
SocketPair_new (int type, Socket_T *socket1, Socket_T *socket2)
{
  int sv[2] = { -1, -1 };
  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;

  assert (socket1);
  assert (socket2);

  socketpair_validate_type (type);
  socketpair_create_fds (type, sv);

  TRY
  {
    (void)socketpair_allocate_socket (sv[0], type, &sock1);
    sv[0] = -1;

    (void)socketpair_allocate_socket (sv[1], type, &sock2);
    sv[1] = -1;

    *socket1 = sock1;
    *socket2 = sock2;
    sock1 = NULL;
    sock2 = NULL;
  }
  EXCEPT (Socket_Failed)
  {
    socketpair_cleanup_socket (sock2, sv[1]);
    socketpair_cleanup_socket (sock1, sv[0]);
    RERAISE;
  }
  END_TRY;
}

#ifdef SO_PEERCRED
static int
socket_get_ucred (const Socket_T socket, struct ucred *cred)
{
  socklen_t len = sizeof (*cred);
  return getsockopt (SocketBase_fd (socket->base), SOL_SOCKET, SO_PEERCRED,
                     cred, &len);
}
#endif

static int
socket_get_ucred_field (const Socket_T socket, int field)
{
  assert (socket);
#ifdef SO_PEERCRED
  struct ucred cred;
  if (socket_get_ucred (socket, &cred) == 0)
    {
      switch (field)
        {
        case 0:
          return cred.pid;
        case 1:
          return (int)cred.uid;
        case 2:
          return (int)cred.gid;
        }
    }
#else
  (void)field;
#endif
  return -1;
}

int
Socket_getpeerpid (const Socket_T socket)
{
  return socket_get_ucred_field (socket, 0);
}

int
Socket_getpeeruid (const Socket_T socket)
{
  return socket_get_ucred_field (socket, 1);
}

int
Socket_getpeergid (const Socket_T socket)
{
  return socket_get_ucred_field (socket, 2);
}

void
Socket_setbandwidth (T socket, size_t bytes_per_sec)
{
  assert (socket);
  assert (socket->base);

  if (bytes_per_sec == 0)
    {
      if (socket->bandwidth_limiter)
        socket->bandwidth_limiter = NULL;
      return;
    }

  if (socket->bandwidth_limiter)
    SocketRateLimit_configure (socket->bandwidth_limiter, bytes_per_sec,
                               bytes_per_sec);
  else
    {
      TRY socket->bandwidth_limiter = SocketRateLimit_new (
          SocketBase_arena (socket->base), bytes_per_sec, bytes_per_sec);
      EXCEPT (SocketRateLimit_Failed)
      RAISE_MODULE_ERROR (Socket_Failed);
      END_TRY;
    }
}

size_t
Socket_getbandwidth (T socket)
{
  assert (socket);

  if (!socket->bandwidth_limiter)
    return 0;

  return SocketRateLimit_get_rate (socket->bandwidth_limiter);
}

ssize_t
Socket_send_limited (T socket, const void *buf, size_t len)
{
  size_t allowed;

  assert (socket);
  assert (buf || len == 0);

  if (!socket->bandwidth_limiter)
    return Socket_send (socket, buf, len);

  if (SocketRateLimit_try_acquire (socket->bandwidth_limiter, len))
    return Socket_send (socket, buf, len);

  allowed = SocketRateLimit_available (socket->bandwidth_limiter);
  if (allowed == 0)
    return 0;

  if (SocketRateLimit_try_acquire (socket->bandwidth_limiter, allowed))
    return Socket_send (socket, buf, allowed);

  return 0;
}

ssize_t
Socket_recv_limited (T socket, void *buf, size_t len)
{
  ssize_t received;
  size_t allowed;

  assert (socket);
  assert (buf || len == 0);

  if (!socket->bandwidth_limiter)
    return Socket_recv (socket, buf, len);

  allowed = SocketRateLimit_available (socket->bandwidth_limiter);
  if (allowed == 0)
    return 0;

  if (allowed < len)
    len = allowed;

  received = Socket_recv (socket, buf, len);

  if (received > 0)
    SocketRateLimit_try_acquire (socket->bandwidth_limiter, (size_t)received);

  return received;
}

int64_t
Socket_bandwidth_wait_ms (T socket, size_t bytes)
{
  assert (socket);

  if (!socket->bandwidth_limiter)
    return 0;

  return SocketRateLimit_wait_time_ms (socket->bandwidth_limiter, bytes);
}

void
Socket_getstats (const T socket, SocketStats_T *stats)
{
  assert (socket);
  assert (stats);

  pthread_mutex_lock (&socket->base->mutex);
  *stats = socket->base->stats;
  pthread_mutex_unlock (&socket->base->mutex);

#if defined(__linux__) && defined(TCP_INFO)
  {
    struct tcp_info info;
    socklen_t info_len = sizeof (info);

    if (getsockopt (SocketBase_fd (socket->base), IPPROTO_TCP, TCP_INFO, &info,
                    &info_len)
        == 0)
      {
        stats->rtt_us = (int32_t)info.tcpi_rtt;
        stats->rtt_var_us = (int32_t)info.tcpi_rttvar;
      }
    else
      {
        stats->rtt_us = -1;
        stats->rtt_var_us = -1;
      }
  }
#else
  stats->rtt_us = -1;
  stats->rtt_var_us = -1;
#endif
}

void
Socket_resetstats (T socket)
{
  int64_t create_time;

  assert (socket);

  pthread_mutex_lock (&socket->base->mutex);
  create_time = socket->base->stats.create_time_ms;
  memset (&socket->base->stats, 0, sizeof (SocketStats_T));
  socket->base->stats.create_time_ms = create_time;
  socket->base->stats.rtt_us = -1;
  socket->base->stats.rtt_var_us = -1;
  pthread_mutex_unlock (&socket->base->mutex);
}

int
Socket_probe (const T socket, int timeout_ms)
{
  int fd;
  int error;
  socklen_t error_len;
  struct pollfd pfd;
  char peek_buf;
  ssize_t peek_result;
  int poll_timeout;

  assert (socket);

  fd = SocketBase_fd (socket->base);
  if (fd < 0)
    return 0;

  error = 0;
  error_len = sizeof (error);
  if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0)
    return 0;

  if (error != 0)
    return 0;

  poll_timeout = (timeout_ms < 0) ? 0 : timeout_ms;
  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;

  if (poll (&pfd, 1, poll_timeout) < 0)
    {
      if (errno == EINTR)
        return 1;
      return 0;
    }

  if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
    return 0;

  if (pfd.revents & POLLIN)
    {
      peek_result = recv (fd, &peek_buf, 1, MSG_PEEK | MSG_DONTWAIT);
      if (peek_result == 0)
        return 0;
      if (peek_result < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        return 0;
    }

  return 1;
}

int
Socket_get_error (const T socket)
{
  int fd;
  int error = 0;
  socklen_t error_len = sizeof (error);

  assert (socket);

  fd = SocketBase_fd (socket->base);
  if (fd < 0)
    return EBADF;

  if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0)
    return errno;

  return error;
}

int
Socket_is_readable (const T socket)
{
  int fd;
  struct pollfd pfd;

  assert (socket);

  fd = SocketBase_fd (socket->base);
  if (fd < 0)
    return -1;

  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;

  if (poll (&pfd, 1, 0) < 0)
    return -1;

  if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
    return -1;

  return (pfd.revents & POLLIN) ? 1 : 0;
}

int
Socket_is_writable (const T socket)
{
  int fd;
  struct pollfd pfd;

  assert (socket);

  fd = SocketBase_fd (socket->base);
  if (fd < 0)
    return -1;

  pfd.fd = fd;
  pfd.events = POLLOUT;
  pfd.revents = 0;

  if (poll (&pfd, 1, 0) < 0)
    return -1;

  if (pfd.revents & (POLLERR | POLLNVAL))
    return -1;

  return (pfd.revents & POLLOUT) ? 1 : 0;
}

#ifdef __linux__
int
Socket_get_tcp_info (const T socket, SocketTCPInfo *info)
{
  int fd;
  struct tcp_info kernel_info;
  socklen_t info_len = sizeof (kernel_info);

  assert (socket);
  assert (info);

  fd = SocketBase_fd (socket->base);
  if (fd < 0)
    return -1;

  memset (&kernel_info, 0, sizeof (kernel_info));

  if (getsockopt (fd, IPPROTO_TCP, TCP_INFO, &kernel_info, &info_len) < 0)
    return -1;

  memset (info, 0, sizeof (*info));

  info->state = kernel_info.tcpi_state;
  info->ca_state = kernel_info.tcpi_ca_state;
  info->retransmits = kernel_info.tcpi_retransmits;
  info->probes = kernel_info.tcpi_probes;
  info->backoff = kernel_info.tcpi_backoff;

  info->options = kernel_info.tcpi_options;
  info->snd_wscale = kernel_info.tcpi_snd_wscale;
  info->rcv_wscale = kernel_info.tcpi_rcv_wscale;

  info->rto_us = kernel_info.tcpi_rto;
  info->ato_us = kernel_info.tcpi_ato;
  info->snd_mss = kernel_info.tcpi_snd_mss;
  info->rcv_mss = kernel_info.tcpi_rcv_mss;

  info->unacked = kernel_info.tcpi_unacked;
  info->sacked = kernel_info.tcpi_sacked;
  info->lost = kernel_info.tcpi_lost;
  info->retrans = kernel_info.tcpi_retrans;
  info->fackets = kernel_info.tcpi_fackets;

  info->last_data_sent_ms = kernel_info.tcpi_last_data_sent;
  info->last_ack_sent_ms = kernel_info.tcpi_last_ack_sent;
  info->last_data_recv_ms = kernel_info.tcpi_last_data_recv;
  info->last_ack_recv_ms = kernel_info.tcpi_last_ack_recv;

  info->pmtu = kernel_info.tcpi_pmtu;
  info->rcv_ssthresh = kernel_info.tcpi_rcv_ssthresh;
  info->rtt_us = kernel_info.tcpi_rtt;
  info->rttvar_us = kernel_info.tcpi_rttvar;
  info->snd_ssthresh = kernel_info.tcpi_snd_ssthresh;
  info->snd_cwnd = kernel_info.tcpi_snd_cwnd;
  info->advmss = kernel_info.tcpi_advmss;
  info->reordering = kernel_info.tcpi_reordering;

  info->rcv_rtt_us = kernel_info.tcpi_rcv_rtt;
  info->rcv_space = kernel_info.tcpi_rcv_space;

  info->total_retrans = kernel_info.tcpi_total_retrans;

#ifdef HAVE_TCP_INFO_PACING_RATE
  info->pacing_rate = kernel_info.tcpi_pacing_rate;
  info->max_pacing_rate = kernel_info.tcpi_max_pacing_rate;
#endif

#ifdef HAVE_TCP_INFO_BYTES_ACKED
  info->bytes_acked = kernel_info.tcpi_bytes_acked;
  info->bytes_received = kernel_info.tcpi_bytes_received;
#endif

#ifdef HAVE_TCP_INFO_SEGS_OUT
  info->segs_out = kernel_info.tcpi_segs_out;
  info->segs_in = kernel_info.tcpi_segs_in;
#endif

#ifdef HAVE_TCP_INFO_NOTSENT_BYTES
  info->notsent_bytes = kernel_info.tcpi_notsent_bytes;
  info->min_rtt_us = kernel_info.tcpi_min_rtt;
  info->data_segs_in = kernel_info.tcpi_data_segs_in;
  info->data_segs_out = kernel_info.tcpi_data_segs_out;
#endif

#ifdef HAVE_TCP_INFO_DELIVERY_RATE
  info->delivery_rate = kernel_info.tcpi_delivery_rate;
#endif

  return 0;
}
#endif /* __linux__ */

int32_t
Socket_get_rtt (const T socket)
{
#if defined(__linux__) && defined(TCP_INFO)
  int fd;
  struct tcp_info info;
  socklen_t info_len = sizeof (info);

  assert (socket);

  fd = SocketBase_fd (socket->base);
  if (fd < 0)
    return -1;

  if (getsockopt (fd, IPPROTO_TCP, TCP_INFO, &info, &info_len) < 0)
    return -1;

  return (int32_t)info.tcpi_rtt;
#else
  (void)socket;
  return -1;
#endif
}

int32_t
Socket_get_cwnd (const T socket)
{
#if defined(__linux__) && defined(TCP_INFO)
  int fd;
  struct tcp_info info;
  socklen_t info_len = sizeof (info);

  assert (socket);

  fd = SocketBase_fd (socket->base);
  if (fd < 0)
    return -1;

  if (getsockopt (fd, IPPROTO_TCP, TCP_INFO, &info, &info_len) < 0)
    return -1;

  return (int32_t)info.tcpi_snd_cwnd;
#else
  (void)socket;
  return -1;
#endif
}

#undef T
