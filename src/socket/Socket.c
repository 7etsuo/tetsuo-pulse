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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
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
#include "socket/SocketLiveCount.h"

#include <sys/stat.h>
#include <sys/un.h>

#ifdef SOCKET_HAS_TLS
#include <openssl/ssl.h>
#endif

#define T Socket_T

/* Shared live count tracker - see SocketLiveCount.h */
static struct SocketLiveCount socket_live_tracker = SOCKETLIVECOUNT_STATIC_INIT;

#define socket_live_increment() SocketLiveCount_increment (&socket_live_tracker)
#define socket_live_decrement() SocketLiveCount_decrement (&socket_live_tracker)

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
 * Note: Exported for use by Socket-accept.c
 */
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

  /* init_base sets fd, domain, type, protocol and initializes all endpoints */
  SocketCommon_init_base (sock->base, fd, AF_UNSPEC, 0, 0, Socket_Failed);

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

/**
 * Socket_debug_live_count - Get count of live sockets (thread-safe)
 * Returns: Current number of live Socket_T instances
 * Thread-safe: Yes - protected by mutex
 */
int
Socket_debug_live_count (void)
{
  return SocketLiveCount_get (&socket_live_tracker);
}

/* ==================== Unix Domain Socket Operations ==================== */
/* Merged from SocketUnix.c */

/**
 * unix_is_abstract_path - Check if path is abstract namespace
 * @path: Unix socket path
 *
 * Returns: true if path starts with '@' (abstract namespace marker)
 */
static inline bool
unix_is_abstract_path (const char *path)
{
  return path && path[0] == '@';
}

/**
 * unix_validate_path - Validate Unix socket path length and security
 * @path: Path string
 * @path_len: Length of path
 *
 * Returns: 0 on valid, -1 on invalid (sets error message)
 */
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

  /* Check for directory traversal */
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

/**
 * unix_unlink_stale - Remove stale socket file if it exists
 * @path: Unix socket path
 *
 * Raises: Socket_Failed if unable to unlink existing socket file
 */
static void
unix_unlink_stale (const char *path)
{
  struct stat st;
  if (stat (path, &st) == 0)
    {
      if (S_ISSOCK (st.st_mode))
        {
          if (unlink (path) < 0)
            {
              SOCKET_ERROR_MSG ("Failed to unlink stale socket %s", path);
              RAISE_MODULE_ERROR (Socket_Failed);
            }
        }
    }
}

/**
 * unix_setup_abstract_socket - Setup abstract namespace socket address
 * @addr: Output sockaddr_un structure
 * @path: Unix socket path (starting with '@')
 * @path_len: Length of path
 */
static void
unix_setup_abstract_socket (struct sockaddr_un *addr, const char *path,
                            size_t path_len)
{
  /* Calculate the actual name length (excluding the '@' prefix) */
  size_t name_len = path_len > 0 ? path_len - 1 : 0;
  /* Ensure name fits in sun_path after the leading null byte */
  size_t max_name_len = sizeof (addr->sun_path) - 1;
  if (name_len > max_name_len)
    name_len = max_name_len;

  memset (addr, 0, sizeof (*addr));
  addr->sun_family = AF_UNIX;
  addr->sun_path[0] = '\0'; /* Abstract namespace marker */
  /* Skip the '@' prefix when copying to sun_path */
  if (name_len > 0)
    memcpy (addr->sun_path + 1, path + 1, name_len);
}

/**
 * unix_setup_regular_socket - Setup regular filesystem socket address
 * @addr: Output sockaddr_un structure
 * @path: Unix socket path
 * @path_len: Length of path
 */
static void
unix_setup_regular_socket (struct sockaddr_un *addr, const char *path,
                           size_t path_len)
{
  /* Ensure path fits in sun_path with null terminator */
  size_t max_path_len = sizeof (addr->sun_path) - 1;
  if (path_len > max_path_len)
    path_len = max_path_len;

  memset (addr, 0, sizeof (*addr));
  addr->sun_family = AF_UNIX;
  memcpy (addr->sun_path, path, path_len);
  addr->sun_path[path_len] = '\0';
}

/**
 * unix_setup_sockaddr - Initialize sockaddr_un from path
 * @addr: Output sockaddr_un structure
 * @path: Unix socket path (@ prefix for abstract)
 *
 * Returns: 0 on success
 */
static int
unix_setup_sockaddr (struct sockaddr_un *addr, const char *path)
{
  size_t path_len;

  assert (addr);
  assert (path);

  memset (addr, 0, sizeof (*addr));
  addr->sun_family = AF_UNIX;
  path_len = strlen (path);

  if (path[0] == '@')
    unix_setup_abstract_socket (addr, path, path_len);
  else
    unix_setup_regular_socket (addr, path, path_len);

  return 0;
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

  /* Unlink stale socket file for regular (non-abstract) paths */
  if (!unix_is_abstract_path (path))
    unix_unlink_stale (path);

  unix_setup_sockaddr (&addr, path);

  if (bind (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
            sizeof (addr))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to bind Unix socket to %s", path);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

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

  /* Validate path before use */
  if (unix_validate_path (path, path_len) < 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  if (unix_setup_sockaddr (&addr, path) != 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  if (connect (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
               sizeof (addr))
      < 0)
    {
      if (errno == ENOENT)
        SOCKET_ERROR_FMT ("Unix socket does not exist: %s", path);
      else if (errno == ECONNREFUSED)
        SOCKET_ERROR_FMT (SOCKET_ECONNREFUSED ": %s", path);
      else
        SOCKET_ERROR_FMT ("Failed to connect to Unix socket %s", path);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Update remote endpoint */
  memcpy (&socket->base->remote_addr, &addr, sizeof (addr));
  socket->base->remote_addrlen = sizeof (addr);
  SocketCommon_update_local_endpoint (socket->base);
}


/* ==================== State Queries ====================
 * Merged from Socket-state.c */

/* check_bound_* helpers moved to SocketCommon.h as inline functions:
 * - SocketCommon_check_bound_ipv4()
 * - SocketCommon_check_bound_ipv6()
 * - SocketCommon_check_bound_unix()
 * - SocketCommon_check_bound_by_family()
 */

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
      /* Socket is connected - cache peer info if not already set */
      if (socket->base->remoteaddr == NULL
          && SocketBase_arena (socket->base) != NULL)
        {
          /* Cache peer info from getpeername result (inline - single use) */
          if (SocketCommon_cache_endpoint (SocketBase_arena (socket->base),
                                           (struct sockaddr *)&addr, len,
                                           &socket->base->remoteaddr,
                                           &socket->base->remoteport)
              != 0)
            {
              socket->base->remoteaddr = NULL;
              socket->base->remoteport = 0;
            }
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
    return SocketCommon_check_bound_by_family (&addr);

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

/* ==================== Bind Operations ====================
 * Merged from Socket-bind.c */

/* Bind setup uses SocketCommon_validate_port and SocketCommon_setup_hints directly */

static int
is_common_bind_error (int err)
{
  return err == EADDRINUSE || err == EACCES || err == EADDRNOTAVAIL
         || err == EAFNOSUPPORT;
}

/* handle_bind_error removed - use SocketCommon_format_bind_error() instead */

/* ==================== Bind Operations ==================== */

/**
 * bind_resolve_address - Resolve hostname for binding
 * @sock: Socket instance (volatile-safe)
 * @host: Hostname to resolve (NULL for wildcard)
 * @port: Port number
 * @socket_family: Socket address family
 * @res: Output for resolved addresses
 *
 * Sets errno to EAI_FAIL on resolution failure without raising.
 */
static void
bind_resolve_address (T sock, const char *host, int port, int socket_family,
                      struct addrinfo **res)
{
  (void)sock; /* Used for consistency, family passed in */
  if (SocketCommon_resolve_address (host, port, NULL, res, Socket_Failed,
                                    socket_family, 0)
      != 0)
    {
      errno = EAI_FAIL;
      return;
    }
}

/**
 * bind_try_addresses - Attempt bind to resolved addresses
 * @sock: Socket instance (volatile-safe)
 * @res: Resolved address list
 * @socket_family: Socket address family
 *
 * Raises: Socket_Failed on non-common errors
 */
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
  volatile T vsock = socket; /* Preserve across exception boundaries */

  assert (socket);

  SocketCommon_validate_port (port, Socket_Failed);
  host = SocketCommon_normalize_wildcard_host (host);
  socket_family = SocketCommon_get_socket_family (socket->base);

  TRY
  {
    bind_resolve_address ((T)vsock, host, port, socket_family, &res);
    if (!res)
      return;

    bind_try_addresses ((T)vsock, res, socket_family);

    freeaddrinfo (res);
  }
  EXCEPT (Socket_Failed)
  {
    int saved_errno = errno;
    freeaddrinfo (res);
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
    {
      return;
    }

  SocketCommon_format_bind_error (NULL, 0);
  RAISE_MODULE_ERROR (Socket_Failed);
}

/* ==================== Async Bind Operations ==================== */

SocketDNS_Request_T
Socket_bind_async (SocketDNS_T dns, T socket, const char *host, int port)
{
  struct addrinfo hints, *res = NULL;

  assert (dns);
  assert (socket);

  /* Validate port using common validator for consistent error handling */
  SocketCommon_validate_port (port, Socket_Failed);

  /* Normalize wildcard addresses to NULL - use existing utility */
  host = SocketCommon_normalize_wildcard_host (host);

  /* For wildcard bind (NULL host), resolve synchronously and create completed
   * request */
  if (host == NULL)
    {
      SocketCommon_setup_hints (&hints, SOCKET_STREAM_TYPE, SOCKET_AI_PASSIVE);
      if (SocketCommon_resolve_address (NULL, port, &hints, &res,
                                        Socket_Failed, SOCKET_AF_UNSPEC, 1)
          != 0)
        RAISE_MODULE_ERROR (Socket_Failed);

      return SocketDNS_create_completed_request (dns, res, port);
    }

  /* For non-wildcard hosts, use async DNS resolution */
  {
    SocketDNS_Request_T req = SocketDNS_resolve (dns, host, port, NULL, NULL);
    if (socket->base->timeouts.dns_timeout_ms > 0)
      SocketDNS_request_settimeout (dns, req,
                                    socket->base->timeouts.dns_timeout_ms);
    return req;
  }
}

void
Socket_bind_async_cancel (SocketDNS_T dns, SocketDNS_Request_T req)
{
  assert (dns);

  if (req)
    SocketDNS_cancel (dns, req);
}

/* ==================== Accept Operations ====================
 * Merged from Socket-accept.c */

/* Forward declarations */
static int accept_connection (T socket, struct sockaddr_storage *addr,
                              socklen_t *addrlen);
static T create_accepted_socket (int newfd, const struct sockaddr_storage *addr,
                                 socklen_t addrlen);

/* ==================== Accept Helper Functions ==================== */

/**
 * accept_create_arena - Create arena for accepted socket
 * @newfd: File descriptor to close on failure
 *
 * Returns: New arena
 * Raises: Socket_Failed on allocation failure
 */
static Arena_T
accept_create_arena (int newfd)
{
  volatile Arena_T arena = NULL;
  int saved_errno;

  TRY arena = Arena_new ();
  EXCEPT (Arena_Failed)
  {
    saved_errno = errno;
    SAFE_CLOSE (newfd);
    errno = saved_errno;
    SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate arena");
    RAISE_MODULE_ERROR (Socket_Failed);
  }
  END_TRY;

  return (Arena_T)arena;
}

/**
 * accept_alloc_socket - Allocate socket structure from arena
 * @arena: Memory arena
 *
 * Returns: Allocated socket structure
 * Raises: Socket_Failed on allocation failure (disposes arena)
 */
static T
accept_alloc_socket (Arena_T arena)
{
  T newsocket = Arena_calloc (arena, 1, sizeof (struct Socket_T), __FILE__,
                              __LINE__);
  if (!newsocket)
    {
      Arena_dispose (&arena);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate socket structure");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  return newsocket;
}

/**
 * accept_alloc_base - Allocate base structure from arena
 * @arena: Memory arena
 *
 * Returns: Allocated base structure
 * Raises: Socket_Failed on allocation failure (disposes arena)
 */
static SocketBase_T
accept_alloc_base (Arena_T arena)
{
  SocketBase_T base = Arena_calloc (arena, 1, sizeof (struct SocketBase_T),
                                    __FILE__, __LINE__);
  if (!base)
    {
      Arena_dispose (&arena);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate base structure");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  return base;
}

/**
 * accept_infer_socket_type - Get SO_TYPE from accepted socket
 * @newfd: File descriptor
 * @arena: Arena for cleanup on failure
 *
 * Returns: Socket type (SOCK_STREAM, etc.)
 * Raises: Socket_Failed on getsockopt failure
 */
static int
accept_infer_socket_type (int newfd, Arena_T arena)
{
  int type_opt;
  socklen_t opt_len = sizeof (type_opt);

  if (getsockopt (newfd, SOL_SOCKET, SO_TYPE, &type_opt, &opt_len) < 0)
    {
      int saved_errno = errno;
      Arena_dispose (&arena);
      SAFE_CLOSE (newfd);
      errno = saved_errno;
      SOCKET_ERROR_MSG ("Failed to get SO_TYPE: %s", strerror (saved_errno));
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  return type_opt;
}

/**
 * accept_init_socket - Initialize accepted socket structure
 * @newsocket: Socket to initialize
 * @base: Base to attach
 * @arena: Memory arena
 * @newfd: File descriptor
 * @addr: Peer address
 * @addrlen: Address length
 * @type_opt: Socket type from SO_TYPE
 *
 * Initializes all socket fields and increments live count.
 */
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

#ifdef SOCKET_HAS_TLS
  socket_init_tls_fields (newsocket);
#endif

  socket_live_increment ();
}

/* ==================== Accept Connection ==================== */

/**
 * accept_connection - Accept a new connection
 * @socket: Listening socket
 * @addr: Output address structure
 * @addrlen: Input/output address length
 *
 * Returns: New file descriptor or -1 on EAGAIN/EWOULDBLOCK
 * Raises: Socket_Failed on other errors
 *
 * All accepted sockets have close-on-exec flag set by default.
 */
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
      SOCKET_ERROR_FMT ("Failed to accept connection");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

#if !SOCKET_HAS_ACCEPT4
  if (SocketCommon_setcloexec (newfd, 1) < 0)
    {
      int saved_errno = errno;
      SAFE_CLOSE (newfd);
      errno = saved_errno;
      SOCKET_ERROR_FMT ("Failed to set close-on-exec flag");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#endif

  return newfd;
}

/* ==================== Create Accepted Socket ==================== */

/**
 * create_accepted_socket - Create socket structure for accepted connection
 * @newfd: Accepted file descriptor
 * @addr: Peer address
 * @addrlen: Address length
 *
 * Returns: New socket instance
 * Raises: Socket_Failed on allocation or initialization failure
 *
 * Orchestrates arena creation, structure allocation, type inference,
 * and initialization via focused helper functions.
 */
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

  TRY
  {
    newfd = accept_connection (socket, &addr, &addrlen);
    if (newfd < 0)
      return NULL;

    newsocket = create_accepted_socket (newfd, &addr, addrlen);

    /* Cache peer info from accepted address (inline - single use) */
    if (SocketCommon_cache_endpoint (SocketBase_arena (newsocket->base),
                                     (struct sockaddr *)&addr, addrlen,
                                     &newsocket->base->remoteaddr,
                                     &newsocket->base->remoteport)
        != 0)
      {
        newsocket->base->remoteaddr = NULL;
        newsocket->base->remoteport = 0;
      }

    SocketCommon_update_local_endpoint (newsocket->base);
    SocketEvent_emit_accept (
        SocketBase_fd (newsocket->base), newsocket->base->remoteaddr,
        newsocket->base->remoteport, newsocket->base->localaddr,
        newsocket->base->localport);

    return newsocket;
  }
  EXCEPT (Socket_Failed)
  {
    if (newfd >= 0)
      SAFE_CLOSE (newfd);
    /* Assume create_accepted_socket handles partial cleanup */
    RERAISE;
  }
  END_TRY;
  /* Unreachable due to returns inside TRY or RERAISE in EXCEPT */
  return NULL;
}

/* ==================== Pair Operations ====================
 * Merged from Socket-pair.c */

/**
 * SocketPair_new - Create a pair of connected Unix domain sockets
 * @type: Socket type (SOCK_STREAM or SOCK_DGRAM)
 * @socket1: Output - first socket of the pair
 * @socket2: Output - second socket of the pair
 * Raises: Socket_Failed on error
 * Thread-safe: Yes (creates new sockets)
 * Note: Creates two connected Unix domain sockets for IPC.
 * Both sockets are ready to use - no bind/connect needed.
 * Typically used for parent-child or thread communication.
 * Only supports AF_UNIX (Unix domain sockets).
 */
void
SocketPair_new (int type, Socket_T *socket1, Socket_T *socket2)
{
  int sv[2];
  Socket_T sock1 = NULL;
  Socket_T sock2 = NULL;
  Arena_T arena1 = NULL;
  Arena_T arena2 = NULL;

  assert (socket1);
  assert (socket2);

  if (type != SOCK_STREAM && type != SOCK_DGRAM)
    {
      SOCKET_ERROR_MSG ("Invalid socket type for socketpair: %d (must be "
                        "SOCK_STREAM or SOCK_DGRAM)",
                        type);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

#if SOCKET_HAS_SOCK_CLOEXEC
  if (socketpair (AF_UNIX, type | SOCKET_SOCK_CLOEXEC, 0, sv) < 0)
#else
  if (socketpair (AF_UNIX, type, 0, sv) < 0)
#endif
    {
      SOCKET_ERROR_FMT ("Failed to create socket pair (type=%d)", type);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

#if !SOCKET_HAS_SOCK_CLOEXEC
  /* Fallback: Set CLOEXEC on both fds */
  SocketCommon_set_cloexec_fd (sv[0], true, Socket_Failed);
  SocketCommon_set_cloexec_fd (sv[1], true, Socket_Failed);
#endif

  TRY
    {
      /* Create arenas for both sockets */
      arena1 = Arena_new ();
      if (!arena1)
        {
          SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate arena for socket pair");
          RAISE_MODULE_ERROR (Socket_Failed);
        }

      arena2 = Arena_new ();
      if (!arena2)
        {
          Arena_dispose (&arena1);
          SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate arena for socket pair");
          RAISE_MODULE_ERROR (Socket_Failed);
        }

      /* Allocate socket structures from arenas */
      sock1 = Arena_calloc (arena1, 1, sizeof (struct Socket_T), __FILE__, __LINE__);
      if (!sock1)
        {
          Arena_dispose (&arena1);
          SOCKET_ERROR_MSG (SOCKET_ENOMEM
                            ": Cannot allocate socket1 structure for pair");
          RAISE_MODULE_ERROR (Socket_Failed);
        }

      sock1->base = Arena_calloc (arena1, 1, sizeof (struct SocketBase_T),
                                  __FILE__, __LINE__);
      if (!sock1->base)
        {
          Arena_dispose (&arena1);
          sock1 = NULL; /* Prevent double cleanup in outer handler */
          SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate base for socket1");
          RAISE_MODULE_ERROR (Socket_Failed);
        }

      sock1->base->arena = arena1;
      arena1 = NULL; /* Transfer ownership */

      SocketCommon_init_base (sock1->base, sv[0], AF_UNIX, type, 0, Socket_Failed);

      sock2 = Arena_calloc (arena2, 1, sizeof (struct Socket_T), __FILE__, __LINE__);
      if (!sock2)
        {
          SocketCommon_free_base (&sock1->base);
          sock1 = NULL;
          sock2 = NULL; /* Prevent double cleanup in outer handler */
          SOCKET_ERROR_MSG (SOCKET_ENOMEM
                            ": Cannot allocate socket2 structure for pair");
          RAISE_MODULE_ERROR (Socket_Failed);
        }

      sock2->base = Arena_calloc (arena2, 1, sizeof (struct SocketBase_T),
                                  __FILE__, __LINE__);
      if (!sock2->base)
        {
          SocketCommon_free_base (&sock1->base);
          Arena_dispose (&arena2);
          sock1 = NULL;
          sock2 = NULL; /* Prevent double cleanup in outer handler */
          arena2 = NULL;
          SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate base for socket2");
          RAISE_MODULE_ERROR (Socket_Failed);
        }

      sock2->base->arena = arena2;
      arena2 = NULL; /* Transfer ownership */

      SocketCommon_init_base (sock2->base, sv[1], AF_UNIX, type, 0, Socket_Failed);

      /* Mark as connected - peer info can be updated via getpeername if needed */
      sock1->base->remoteaddr = NULL;
      sock2->base->remoteaddr = NULL;

      *socket1 = sock1;
      *socket2 = sock2;
      sock1 = NULL;
      sock2 = NULL; /* Transfer ownership */
    }
  EXCEPT (Socket_Failed)
    {
      // Cleanup on error - reverse acquisition order: sock2 then sock1 then arenas.
      // Handles partial allocations where arenas may or may not be transferred.
      /* Cleanup sock2 (later acquired) */
      if (sock2)
        {
#ifdef SOCKET_HAS_TLS
          if (sock2->tls_ssl)
            {
              SSL_free ((SSL *)sock2->tls_ssl);
              sock2->tls_ssl = NULL;
            }
            /* Add other stream-specific cleanup here if needed */
#endif
          SocketCommon_free_base (&sock2->base);
          socket_live_decrement ();
          sock2 = NULL;
        }
      else if (sv[1] >= 0)
        {
          SAFE_CLOSE (sv[1]);
        }

      /* Cleanup sock1 */
      if (sock1)
        {
#ifdef SOCKET_HAS_TLS
          if (sock1->tls_ssl)
            {
              SSL_free ((SSL *)sock1->tls_ssl);
              sock1->tls_ssl = NULL;
            }
            /* Add other stream-specific cleanup here if needed */
#endif
          SocketCommon_free_base (&sock1->base);
          socket_live_decrement ();
          sock1 = NULL;
        }
      else if (sv[0] >= 0)
        {
          SAFE_CLOSE (sv[0]);
        }

      if (arena1)
        Arena_dispose (&arena1);
      if (arena2)
        Arena_dispose (&arena2);

      RERAISE;
    }
  END_TRY;
}

/* ==================== Peer Credentials ==================== */

#ifdef SO_PEERCRED
/**
 * socket_get_ucred - Get peer credentials from Unix domain socket
 * @socket: Socket instance
 * @cred: Output for ucred structure
 *
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Yes (operates on single socket)
 */
static int
socket_get_ucred (const Socket_T socket, struct ucred *cred)
{
  socklen_t len = sizeof (*cred);
  return getsockopt (SocketBase_fd (socket->base), SOL_SOCKET, SO_PEERCRED,
                     cred, &len);
}
#endif

int
Socket_getpeerpid (const Socket_T socket)
{
  assert (socket);
#ifdef SO_PEERCRED
  struct ucred cred;
  if (socket_get_ucred (socket, &cred) == 0)
    return cred.pid;
#endif
  return -1;
}

int
Socket_getpeeruid (const Socket_T socket)
{
  assert (socket);
#ifdef SO_PEERCRED
  struct ucred cred;
  if (socket_get_ucred (socket, &cred) == 0)
    return cred.uid;
#endif
  return -1;
}

int
Socket_getpeergid (const Socket_T socket)
{
  assert (socket);
#ifdef SO_PEERCRED
  struct ucred cred;
  if (socket_get_ucred (socket, &cred) == 0)
    return cred.gid;
#endif
  return -1;
}

#undef T
