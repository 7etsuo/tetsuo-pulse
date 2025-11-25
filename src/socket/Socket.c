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
/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(Socket);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(Socket, e)

/* Static helper functions */

#ifdef SOCKET_HAS_TLS
/**
 * socket_init_tls_fields - Initialize TLS fields to defaults
 * @sock: Socket instance to initialize
 *
 * Sets all TLS-related fields to safe default values (NULL/0).
 * Thread-safe: No (operates on single socket during construction)
 */
static void
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
}
#endif

/**
 * validate_fd_is_socket - Validate file descriptor is a socket
 * @fd: File descriptor to validate
 * Raises: Socket_Failed if fd is not a socket
 */
static void
validate_fd_is_socket (int fd)
{
  int optval;
  socklen_t optlen = sizeof (optval);
  if (getsockopt (fd, SOL_SOCKET, SO_TYPE, &optval, &optlen) < 0)
    {
      SOCKET_ERROR_FMT ("Invalid file descriptor (not a socket): fd=%d", fd);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

/**
 * allocate_socket_from_fd - Allocate socket structure from existing fd
 * @arena: Arena for allocations
 * @fd: File descriptor to wrap
 * Returns: Allocated socket structure
 * Raises: Socket_Failed on allocation failure
 */
static T
allocate_socket_from_fd (Arena_T arena, int fd)
{
  T sock;

  sock = Arena_calloc (arena, 1, sizeof (struct Socket_T), __FILE__, __LINE__);
  if (!sock)
    {
      Arena_dispose (&arena);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate sock for new_from_fd");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  sock->base = Arena_calloc (arena, 1, sizeof (struct SocketBase_T), __FILE__,
                             __LINE__);
  if (!sock->base)
    {
      Arena_dispose (&arena);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate base for new_from_fd");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  sock->base->arena = arena;
  sock->base->fd = fd;
  sock->base->domain = AF_UNSPEC; /* Detect if needed */
  sock->base->type = 0;           /* Detect */
  sock->base->protocol = 0;

  SocketCommon_init_base (sock->base, fd, sock->base->domain, sock->base->type,
                          0, Socket_Failed);

  return sock;
}

/**
 * setup_socket_nonblocking - Set socket to non-blocking mode
 * @socket: Socket to configure
 * Raises: Socket_Failed on failure
 */
static void
setup_socket_nonblocking (T socket)
{
  int flags = fcntl (SocketBase_fd (socket->base), F_GETFL, 0);
  if (flags < 0)
    {
      int saved_errno = errno;
      Socket_free (&socket);
      errno = saved_errno;
      SOCKET_ERROR_FMT ("Failed to get socket flags for fd=%d",
                        SocketBase_fd (socket->base));
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  if (fcntl (SocketBase_fd (socket->base), F_SETFL, flags | O_NONBLOCK) < 0)
    {
      int saved_errno = errno;
      Socket_free (&socket);
      errno = saved_errno;
      SOCKET_ERROR_FMT ("Failed to set non-blocking mode for fd=%d",
                        SocketBase_fd (socket->base));
      RAISE_MODULE_ERROR (Socket_Failed);
    }
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
  socket_init_tls_fields (sock);
#endif

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
  Arena_T arena;

  assert (fd >= 0);

  validate_fd_is_socket (fd);

  arena = Arena_new ();
  if (!arena)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot create arena for new_from_fd");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  T sock = allocate_socket_from_fd (arena, fd);

  /* Init TLS etc as in Socket_new */

  /* Set non-blocking mode (required for batch accept) */
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
