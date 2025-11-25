/**
 * Socket.c - Socket abstraction layer (Core)
 *
 * Core socket lifecycle and basic operations. Extended operations are
 * implemented in separate modules for better organization.
 *
 * This file contains:
 * - Socket lifecycle management (new/free)
 * - Basic I/O operations (send/recv/sendall/recvall)
 * - Socket state queries (connected/bound/listening)
 * - Basic accessor functions
 * - Live count tracking for debugging
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

/* MSG_NOSIGNAL fallback for platforms without it (macOS, BSD).
 * Applications must call signal(SIGPIPE, SIG_IGN). See Socket.h. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig-limits.h"
#include "core/SocketConfig.h"
#include "dns/SocketDNS.h"
#include "socket/Socket.h"
#define SOCKET_LOG_COMPONENT "Socket"
#include "core/SocketError.h"
#include "core/SocketEvents.h"
#include "core/SocketMetrics.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"
#include "socket/SocketIO.h"

#include "socket/Socket-private.h"

#ifdef SOCKET_HAS_TLS
#include <openssl/ssl.h>
#endif

#define T Socket_T

static int socket_live_count = 0;
static pthread_mutex_t socket_live_count_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * socket_live_increment - Increment live socket count (thread-safe)
 * Thread-safe: Yes - protected by mutex
 */
void
socket_live_increment (void)
{
  pthread_mutex_lock (&socket_live_count_mutex);
  socket_live_count++;
  pthread_mutex_unlock (&socket_live_count_mutex);
}

/**
 * socket_live_decrement - Decrement live socket count (thread-safe)
 * Thread-safe: Yes - protected by mutex
 * Prevents TOCTOU race condition by atomically checking and decrementing
 */
void
socket_live_decrement (void)
{
  pthread_mutex_lock (&socket_live_count_mutex);
  if (socket_live_count > 0)
    socket_live_count--;
  pthread_mutex_unlock (&socket_live_count_mutex);
}

const Except_T Socket_Failed = { &Socket_Failed, "Socket operation failed" };
const Except_T Socket_Closed = { &Socket_Closed, "Socket closed" };

/* Thread-local exception for detailed error messages.
 * Prevents race conditions when multiple threads raise same exception. */
#ifdef _WIN32
static __declspec (thread) Except_T Socket_DetailedException;
#else
static __thread Except_T Socket_DetailedException;
#endif

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e)                                                 \
  do                                                                          \
    {                                                                         \
      Socket_DetailedException = (e);                                         \
      Socket_DetailedException.reason = socket_error_buf;                     \
      RAISE (Socket_DetailedException);                                       \
    }                                                                         \
  while (0)

/* Static helper functions */

/**
 * setup_peer_info - Set up peer address and port from getnameinfo result
 * @socket: Socket to set up
 * @addr: Address structure
 * @addrlen: Address length
 * Returns: 0 on success, -1 on failure
 */
static int
setup_peer_info (T socket, const struct sockaddr *addr, socklen_t addrlen)
{
  if (SocketCommon_cache_endpoint (SocketBase_arena (socket->base), addr,
                                   addrlen, &socket->base->remoteaddr,
                                   &socket->base->remoteport)
      != 0)
    {
      socket->base->remoteaddr = NULL;
      socket->base->remoteport = 0;
    }
  return 0;
}

T
Socket_new (int domain, int type, int protocol)
{
  SocketBase_T base = NULL;
  T sock;

  TRY base = SocketCommon_new_base (domain, type, protocol);
  EXCEPT (Arena_Failed)
  RAISE_MODULE_ERROR (Socket_Failed);
  END_TRY;

  if (!base || !SocketBase_arena (base))
    {
      SOCKET_ERROR_MSG ("Invalid base from new_base (null arena)");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  sock = Arena_calloc (SocketBase_arena (base), 1, sizeof (struct Socket_T),
                       __FILE__, __LINE__);
  if (!sock)
    {
      SocketCommon_free_base (&base);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate socket structure");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  sock->base = base;

#ifdef SOCKET_HAS_TLS
  /* Initialize TLS fields to defaults */
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
  sock->tls_timeouts = (SocketTimeouts_T){ 0 }; /* or copy from base? */
#endif

  /* Socket-specific live count */
  socket_live_increment ();

  return sock;
}

void
Socket_free (T *socket)
{
  T s = *socket;
  if (!s)
    return;

  *socket = NULL; /* Invalidate caller pointer before cleanup to avoid UB */

  /* Stream-specific cleanup (TLS) before base free */
#ifdef SOCKET_HAS_TLS
  if (s->tls_ssl)
    {
      SSL_free ((SSL *)s->tls_ssl);
      s->tls_ssl = NULL;
    }
    /* Add other TLS cleanup if necessary (e.g., ctx if owned per socket) */
#endif

  /* Common base cleanup: closes fd, disposes arena (frees s too) */
  SocketCommon_free_base (&s->base);

  /* Type-specific decrement */
  socket_live_decrement ();
  /* Caller pointer already invalidated earlier */
}

T
Socket_new_from_fd (int fd)
{
  T sock;
  Arena_T arena;
  int flags;

  assert (fd >= 0);

  /* Validate fd is a socket */
  int optval;
  socklen_t optlen = sizeof (optval);
  if (getsockopt (fd, SOL_SOCKET, SO_TYPE, &optval, &optlen) < 0)
    {
      SOCKET_ERROR_FMT ("Invalid file descriptor (not a socket): fd=%d", fd);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  arena = Arena_new ();
  if (!arena)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot create arena for new_from_fd");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  sock = Arena_calloc (arena, 1, sizeof (struct Socket_T), __FILE__, __LINE__);
  if (!sock)
    {
      Arena_dispose (&arena);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM
                        ": Cannot allocate sock for new_from_fd");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  sock->base = Arena_calloc (arena, 1, sizeof (struct SocketBase_T), __FILE__,
                             __LINE__);
  if (!sock->base)
    {
      Arena_dispose (&arena);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM
                        ": Cannot allocate base for new_from_fd");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  sock->base->arena = arena;
  sock->base->fd = fd;
  sock->base->domain = AF_UNSPEC; /* Detect if needed */
  sock->base->type = 0;           /* Detect */
  sock->base->protocol = 0;

  SocketCommon_init_base (sock->base, fd, sock->base->domain, sock->base->type,
                          0, Socket_Failed);

  /* Init TLS etc as in Socket_new */

  /* Set non-blocking mode (required for batch accept) */
  flags = fcntl (fd, F_GETFL, 0);
  if (flags < 0)
    {
      int saved_errno = errno;
      Socket_free (&sock);
      errno = saved_errno;
      SOCKET_ERROR_FMT ("Failed to get socket flags for fd=%d", fd);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  if (fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      int saved_errno = errno;
      Socket_free (&sock);
      errno = saved_errno;
      SOCKET_ERROR_FMT ("Failed to set non-blocking mode for fd=%d", fd);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

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

ssize_t
Socket_sendall (T socket, const void *buf, size_t len)
{
  const char *ptr = (const char *)buf;
  volatile size_t total_sent = 0;
  ssize_t sent;

  assert (socket);
  assert (buf);
  assert (len > 0);

  TRY while (total_sent < len)
  {
    sent = Socket_send (socket, ptr + total_sent, len - total_sent);
    if (sent == 0)
      {
        /* Would block (EAGAIN/EWOULDBLOCK) - return partial progress */
        return (ssize_t)total_sent;
      }
    total_sent += (size_t)sent;
  }
  EXCEPT (Socket_Closed)
  RERAISE;
  EXCEPT (Socket_Failed)
  RERAISE;
  END_TRY;

  return (ssize_t)total_sent;
}

ssize_t
Socket_recvall (T socket, void *buf, size_t len)
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
        = Socket_recv (socket, ptr + total_received, len - total_received);
    if (received == 0)
      {
        /* Would block (EAGAIN/EWOULDBLOCK) - return partial progress */
        return (ssize_t)total_received;
      }
    total_received += (size_t)received;
  }
  EXCEPT (Socket_Closed)
  RERAISE;
  EXCEPT (Socket_Failed)
  RERAISE;
  END_TRY;

  return (ssize_t)total_received;
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

int
Socket_isconnected (T socket)
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof (addr);

  assert (socket);

  /* Check if we have cached peer address */
  if (socket->base->remoteaddr != NULL)
    return 1;

  /* Use getpeername() to check connection state */
  if (getpeername (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
                   &len)
      == 0)
    {
      /* Socket is connected - update cached peer info if not already set */
      if (socket->base->remoteaddr == NULL
          && SocketBase_arena (socket->base) != NULL)
        {
          setup_peer_info (socket, (struct sockaddr *)&addr, len);
        }
      return 1;
    }

  /* Not connected or error occurred */
  if (errno == ENOTCONN)
    return 0;

  /* Other errors (EBADF, etc.) - treat as not connected */
  return 0;
}

int
Socket_isbound (T socket)
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof (addr);

  assert (socket);

  /* Check if we have cached local address */
  if (socket->base->localaddr != NULL)
    return 1;

  /* Use getsockname() to check binding state */
  if (getsockname (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
                   &len)
      == 0)
    {
      /* Socket is bound if getsockname succeeds */
      /* For IPv4/IPv6, check if we have a valid port (address can be wildcard)
       */
      if (addr.ss_family == AF_INET)
        {
          struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
          if (sin->sin_port != 0)
            return 1;
        }
      else if (addr.ss_family == AF_INET6)
        {
          struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
          if (sin6->sin6_port != 0)
            return 1;
        }
      else if (addr.ss_family == AF_UNIX)
        {
          /* Unix domain sockets are bound if getsockname succeeds */
          return 1;
        }
    }

  return 0;
}

int
Socket_islistening (T socket)
{
  assert (socket);

  /* Socket must be bound to be listening */
  if (!Socket_isbound (socket))
    return 0;

  /* Socket must not be connected to be listening */
  if (Socket_isconnected (socket))
    return 0;

  /* Additional check: verify socket is actually in listening state
   * by checking if accept() would work (non-blocking check) */
  {
    int error = 0;
    socklen_t error_len = sizeof (error);

    /* Check SO_ERROR - listening sockets should have no error */
    if (getsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET, SO_ERROR,
                    &error, &error_len)
        == 0)
      {
        /* If there's a connection error, socket might be in wrong state */
        if (error != 0 && error != ENOTCONN)
          return 0;
      }
  }

  return 1;
}

#undef T

/* ==================== Wrapper Functions for Split APIs ==================== */

void
Socket_listen (Socket_T socket, int backlog)
{
  if (backlog <= 0)
    {
      SOCKET_ERROR_MSG ("Invalid backlog value: %d (must be > 0)", backlog);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  if (backlog > SOCKET_MAX_LISTEN_BACKLOG)
    backlog = SOCKET_MAX_LISTEN_BACKLOG;

  if (listen (SocketBase_fd (socket->base), backlog) < 0)
    {
      SOCKET_ERROR_FMT ("Failed to listen on socket (backlog=%d)", backlog);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

int
socket_debug_live_count (void)
{
  int count;

  /* Thread-safe read of live socket count */
  pthread_mutex_lock (&socket_live_count_mutex);
  count = socket_live_count;
  pthread_mutex_unlock (&socket_live_count_mutex);

  return count;
}

/* ==================== Unix Domain Socket Wrappers ==================== */

void
Socket_bind_unix (Socket_T socket, const char *path)
{
  SocketUnix_bind (socket->base, path, Socket_Failed);
}

void
Socket_connect_unix (Socket_T socket, const char *path)
{
  SocketUnix_connect (socket->base, path, Socket_Failed);
}

int
Socket_debug_live_count (void)
{
  return socket_debug_live_count();
}
