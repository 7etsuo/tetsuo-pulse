/**
 * Socket.c - Socket abstraction layer
 */

/* Feature test macros for accept4() on Linux */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>

/* MSG_NOSIGNAL fallback for platforms without it (macOS, BSD).
 * Applications must call signal(SIGPIPE, SIG_IGN). See Socket.h. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#include "core/SocketConfig-limits.h"
#include "dns/SocketDNS.h"
#include "socket/Socket.h"
#define SOCKET_LOG_COMPONENT "Socket"
#include "core/SocketError.h"
#include "core/SocketEvents.h"
#include "core/SocketMetrics.h"
#include "socket/SocketCommon.h"
#include "socket/SocketCommon-private.h"
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
static void
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
static void
socket_live_decrement (void)
{
  pthread_mutex_lock (&socket_live_count_mutex);
  if (socket_live_count > 0)
    socket_live_count--;
  pthread_mutex_unlock (&socket_live_count_mutex);
}

static int
sanitize_timeout (int timeout_ms)
{
  if (timeout_ms < 0)
    return 0;
  return timeout_ms;
}

/* Port string buffer size for snprintf - 16 bytes sufficient for "65535" +
 * null */

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
#define RAISE_MODULE_ERROR(e) do { \
  Socket_DetailedException = (e); \
  Socket_DetailedException.reason = socket_error_buf; \
  RAISE(Socket_DetailedException); \
} while(0)

/* Struct definition moved to Socket-private.h */

/* Static helper functions */

/**
 * validate_port_number
 * Raises: Socket_Failed if port is invalid
 */
static void
validate_port_number (int port)
{
  SocketCommon_validate_port (port, Socket_Failed);
}

/**
 * validate_host_not_null
 * Raises: Socket_Failed if host is NULL
 */
static void
validate_host_not_null (const char *host)
{
  if (host == NULL)
    {
      SOCKET_ERROR_MSG ("Invalid host: NULL pointer");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

/**
 * setup_bind_hints
 */
static void
setup_bind_hints (struct addrinfo *hints)
{
  SocketCommon_setup_hints (hints, SOCKET_STREAM_TYPE, SOCKET_AI_PASSIVE);
}

/**
 * setup_connect_hints
 */
static void
setup_connect_hints (struct addrinfo *hints)
{
  SocketCommon_setup_hints (hints, SOCKET_STREAM_TYPE, 0);
}

/**
 * get_socket_family - Get socket's address family
 * @socket: Socket to query
 * Returns: Socket family or AF_UNSPEC on error
 * Uses SO_DOMAIN on Linux, falls back to getsockname() on other platforms.
 */
static int
get_socket_family (T socket)
{
  return SocketCommon_get_family (socket->base, false, Socket_Failed); /* No raise on fail */
}

/**
 * create_socket_fd - Create underlying socket file descriptor
 * @domain: Socket domain (AF_INET, AF_INET6, AF_UNIX)
 * @type: Socket type (SOCK_STREAM, SOCK_DGRAM)
 * @protocol: Socket protocol (usually 0)
 * Returns: Socket file descriptor or -1 on failure
 * Raises: Socket_Failed on socket creation failure
 * Note: All sockets are created with close-on-exec flag set by default.
 */


/**
 * allocate_socket_structure - Allocate and zero-initialize socket structure
 * @fd: File descriptor for cleanup on failure
 * Returns: Pointer to allocated socket structure or NULL on failure
 * Raises: Socket_Failed on allocation failure (cleans up fd)
 */


/**
 * initialize_socket_structure - Initialize socket structure fields
 * @socket: Socket to initialize
 * @fd: File descriptor to assign
 * Returns: Initialized socket structure
 */


/**
 * validate_socketpair_type - Validate socket type for socketpair creation
 * @type: Socket type to validate
 * Raises: Socket_Failed if invalid type (not SOCK_STREAM or SOCK_DGRAM)
 * Thread-safe: Yes
 */
static void
validate_socketpair_type (int type)
{
  if (type != SOCK_STREAM && type != SOCK_DGRAM)
    {
      SOCKET_ERROR_MSG ("Invalid socket type for socketpair: %d (must be "
                        "SOCK_STREAM or SOCK_DGRAM)",
                        type);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

/**
 * create_socketpair_fds - Create Unix domain socket pair file descriptors
 * @type: Socket type (SOCK_STREAM or SOCK_DGRAM)
 * @sv: Output array for the two file descriptors [2]
 * Raises: Socket_Failed on creation error
 * Thread-safe: Yes
 * Note: Sets SOCK_CLOEXEC flag if supported by platform
 */
static void
create_socketpair_fds (int type, int sv[2])
{
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
}

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
SocketPair_new (int type, T *socket1, T *socket2)
{
  int sv[2];
  T sock1 = NULL;
  T sock2 = NULL;
  Arena_T arena1 = NULL;
  Arena_T arena2 = NULL;

  assert (socket1);
  assert (socket2);

  validate_socketpair_type (type);

  create_socketpair_fds (type, sv);

  TRY
      /* Create arenas for both sockets */
      arena1
      = Arena_new ();
  EXCEPT (Arena_Failed)
    {
      int saved_errno = errno;
      SAFE_CLOSE (sv[0]);
      SAFE_CLOSE (sv[1]);
      errno = saved_errno;
      SOCKET_ERROR_MSG (SOCKET_ENOMEM
                        ": Cannot allocate arena for socket pair");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  END_TRY;

  TRY
    arena2 = Arena_new ();
  EXCEPT (Arena_Failed)
    {
      int saved_errno = errno;
      SAFE_CLOSE (sv[0]);
      SAFE_CLOSE (sv[1]);
      Arena_dispose (&arena1);
      errno = saved_errno;
      SOCKET_ERROR_MSG (SOCKET_ENOMEM
                        ": Cannot allocate arena for socket pair");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  END_TRY;

  TRY
    /* Allocate socket structures from arenas */
  sock1 = Arena_calloc (arena1, 1, sizeof (struct Socket_T), __FILE__, __LINE__);
  if (!sock1)
    {
      Arena_dispose (&arena1);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate socket1 structure for pair");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  sock1->base = Arena_calloc (arena1, 1, sizeof (struct SocketBase_T), __FILE__, __LINE__);
  if (!sock1->base)
    {
      Arena_dispose (&arena1);
      sock1 = NULL;  /* Prevent double cleanup in outer handler */
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
      sock2 = NULL;  /* Prevent double cleanup in outer handler */
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate socket2 structure for pair");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  sock2->base = Arena_calloc (arena2, 1, sizeof (struct SocketBase_T), __FILE__, __LINE__);
  if (!sock2->base)
    {
      SocketCommon_free_base (&sock1->base);
      Arena_dispose (&arena2);
      sock1 = NULL;
      sock2 = NULL;  /* Prevent double cleanup in outer handler */
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

  EXCEPT (Socket_Failed)
  /* Cleanup on error - reverse acquisition order: sock2 then sock1 then arenas.
   * Handles partial allocations where arenas may or may not be transferred. */
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
  END_TRY;
  /* Success path falls through for void function after setting outputs */
}

/**
 * create_socket_arena - Create arena for socket-related allocations
 * @fd: File descriptor for cleanup on failure
 * @sock: Socket structure for cleanup on failure
 * Returns: New arena or NULL on failure
 * Raises: Socket_Failed on arena creation failure (cleans up fd and sock)
 */


/* try_bind_address extracted to SocketCommon_try_bind_address (updates local endpoint) */

static int
socket_wait_for_connect (T socket, int timeout_ms)
{
  struct pollfd pfd;
  int result;
  int error = 0;
  socklen_t error_len = sizeof (error);

  assert (socket);
  assert (timeout_ms >= 0);

  pfd.fd = SocketBase_fd (socket->base);
  pfd.events = POLLOUT;
  pfd.revents = 0;

  while ((result = poll (&pfd, 1, timeout_ms)) < 0)
    {
      if (errno == EINTR)
        continue;
      return -1;
    }

  if (result == 0)
    {
      errno = ETIMEDOUT;
      return -1;
    }

  if (getsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET, SO_ERROR, &error, &error_len)
      < 0)
    return -1;

  if (error != 0)
    {
      errno = error;
      return -1;
    }

  return 0;
}

/**
 * try_connect_address - Try to connect socket to address
 * @socket: Socket to connect
 * @addr: Address to connect to
 * @addrlen: Address length
 * Returns: 0 on success or EINPROGRESS, -1 on failure
 */
static int
try_connect_address (T socket, const struct sockaddr *addr, socklen_t addrlen,
                     int timeout_ms)
{
  int saved_errno;
  int original_flags = -1;
  int restore_blocking = 0;

  assert (socket);
  assert (addr);

  if (timeout_ms <= 0)
    {
      if (connect (SocketBase_fd (socket->base), addr, addrlen) == 0 || errno == EINPROGRESS
          || errno == EISCONN)
        {
          memcpy (&socket->base->remote_addr, addr, addrlen);
          socket->base->remote_addrlen = addrlen;
          return 0;
        }
      return -1;
    }

  original_flags = fcntl (SocketBase_fd (socket->base), F_GETFL);
  if (original_flags < 0)
    return -1;

  if ((original_flags & O_NONBLOCK) == 0)
    {
      if (fcntl (SocketBase_fd (socket->base), F_SETFL, original_flags | O_NONBLOCK) < 0)
        return -1;
      restore_blocking = 1;
    }

  if (connect (SocketBase_fd (socket->base), addr, addrlen) == 0 || errno == EISCONN)
    {
      if (restore_blocking)
        {
          if (fcntl (SocketBase_fd (socket->base), F_SETFL, original_flags) < 0)
            {
              SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                               "Failed to restore blocking mode after connect "
                               "(fd=%d, errno=%d): %s",
                               SocketBase_fd (socket->base), errno, strerror (errno));
            }
        }
      memcpy (&socket->base->remote_addr, addr, addrlen);
      socket->base->remote_addrlen = addrlen;
      return 0;
    }

  saved_errno = errno;

  if (saved_errno == EINPROGRESS || saved_errno == EINTR)
    {
      if (socket_wait_for_connect (socket, timeout_ms) == 0)
        {
          if (restore_blocking)
            {
              if (fcntl (SocketBase_fd (socket->base), F_SETFL, original_flags) < 0)
                {
                  SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                                   "Failed to restore blocking mode after "
                                   "connect (fd=%d, errno=%d): %s",
                                   SocketBase_fd (socket->base), errno, strerror (errno));
                }
            }
          memcpy (&socket->base->remote_addr, addr, addrlen);
          socket->base->remote_addrlen = addrlen;
          return 0;
        }
      saved_errno = errno;
    }

  if (restore_blocking)
    {
      int restore_result = fcntl (SocketBase_fd (socket->base), F_SETFL, original_flags);
      if (restore_result < 0)
        {
          int restore_errno = errno;
          SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                           "Failed to restore blocking mode after connect "
                           "failure (fd=%d, errno=%d): %s",
                           SocketBase_fd (socket->base), restore_errno,
                           strerror (restore_errno));
        }
    }

  errno = saved_errno;
  return -1;
}

/**
 * handle_bind_error - Handle bind error and raise exception
 * @host: Host string for error message
 * @port: Port for error message
 */
static void
handle_bind_error (const char *host, int port)
{
  const char *safe_host = host ? host : "any";

  if (errno == EADDRINUSE)
    {
      SOCKET_ERROR_FMT (SOCKET_EADDRINUSE ": %.*s:%d",
                        SOCKET_ERROR_MAX_HOSTNAME, safe_host, port);
    }
  else if (errno == EACCES)
    {
      SOCKET_ERROR_FMT ("Permission denied to bind to port %d", port);
    }
  else
    {
      SOCKET_ERROR_FMT ("Failed to bind to %.*s:%d", SOCKET_ERROR_MAX_HOSTNAME,
                        safe_host, port);
    }
}

/**
 * handle_connect_error - Handle connect error and raise exception
 * @host: Host string for error message
 * @port: Port for error message
 */
static void
handle_connect_error (const char *host, int port)
{
  SocketMetrics_increment (SOCKET_METRIC_SOCKET_CONNECT_FAILURE, 1);

  if (errno == ECONNREFUSED)
    {
      SOCKET_ERROR_FMT (SOCKET_ECONNREFUSED ": %.*s:%d",
                        SOCKET_ERROR_MAX_HOSTNAME, host, port);
    }
  else if (errno == ENETUNREACH)
    {
      SOCKET_ERROR_FMT (SOCKET_ENETUNREACH ": %.*s", SOCKET_ERROR_MAX_HOSTNAME,
                        host);
    }
  else if (errno == ETIMEDOUT)
    {
      SOCKET_ERROR_FMT (SOCKET_ETIMEDOUT ": %.*s:%d",
                        SOCKET_ERROR_MAX_HOSTNAME, host, port);
    }
  else
    {
      SOCKET_ERROR_FMT ("Failed to connect to %.*s:%d",
                        SOCKET_ERROR_MAX_HOSTNAME, host, port);
    }
}

/**
 * allocate_peer_address - Allocate and copy peer address string
 * @newsocket: New socket to allocate for
 * @host: Host string to copy
 * Returns: 0 on success, -1 on failure
 * Raises: Socket_Failed on allocation failure
 */
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
  if (SocketCommon_cache_endpoint (SocketBase_arena (socket->base), addr, addrlen,
                                   &socket->base->remoteaddr, &socket->base->remoteport)
      != 0)
    {
      socket->base->remoteaddr = NULL;
      socket->base->remoteport = 0;
    }
  return 0;
}

/**
 * validate_unix_path - Validate Unix socket path
 * @path: Path string
 * @path_len: Path length to validate
 * Returns: 0 on success, -1 on failure
 */
/* validate_unix_path moved to SocketUnix.c */

/**
 * setup_abstract_unix_socket - Set up abstract namespace Unix socket
 * @addr: Output sockaddr_un structure
 * @path: Socket path starting with '@'
 * @path_len: Length of path
 * Returns: 0 on success, -1 on failure
 */
static int
setup_abstract_unix_socket (struct sockaddr_un *addr, const char *path,
                            size_t path_len)
{
  (void)addr;
  (void)path_len;
#ifdef __linux__
  if (SocketUnix_validate_unix_path (path, path_len) != 0)
    return -1;
  addr->sun_path[0] = '\0';
  memcpy (addr->sun_path + 1, path + 1, path_len - 1);
  return 0;
#else
  /* macOS/BSD don't support abstract sockets - log warning and fail */
  SocketLog_emitf (
      SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
      "Abstract namespace sockets (@%s) not supported on this platform; "
      "fall back to regular Unix socket or use filesystem path",
      path + 1);
  return -1;
#endif
}

/**
 * setup_regular_unix_socket - Set up regular filesystem Unix socket
 * @addr: Output sockaddr_un structure
 * @path: Socket path
 * @path_len: Length of path
 * Returns: 0 on success, -1 on failure
 */
static int
setup_regular_unix_socket (struct sockaddr_un *addr, const char *path,
                           size_t path_len)
{
  if (SocketUnix_validate_unix_path (path, path_len) != 0)
    return -1;
  strncpy (addr->sun_path, path, sizeof (addr->sun_path) - 1);
  addr->sun_path[sizeof (addr->sun_path) - 1] = '\0';
  return 0;
}

/**
 * setup_unix_sockaddr - Set up sockaddr_un structure for Unix domain socket
 * @addr: Output sockaddr_un structure
 * @path: Socket path (may start with '@' for abstract socket)
 * Returns: 0 on success, -1 on failure with errno set
 */
static int
setup_unix_sockaddr (struct sockaddr_un *addr, const char *path)
{
  size_t path_len;

  assert (addr);
  assert (path);

  memset (addr, 0, sizeof (*addr));
  addr->sun_family = SOCKET_AF_UNIX;
  path_len = strlen (path);

  if (path[0] == '@')
    return setup_abstract_unix_socket (addr, path, path_len);
  else
    return setup_regular_unix_socket (addr, path, path_len);
}

T
Socket_new (int domain, int type, int protocol)
{
  SocketBase_T base = NULL;
  T sock;

  TRY
    base = SocketCommon_new_base (domain, type, protocol);
  EXCEPT (Arena_Failed)
    RAISE_MODULE_ERROR (Socket_Failed);
  END_TRY;

  if (!base || !SocketBase_arena (base)) {
    SOCKET_ERROR_MSG ("Invalid base from new_base (null arena)");
    RAISE_MODULE_ERROR (Socket_Failed);
  }

  sock = Arena_calloc (SocketBase_arena (base), 1, sizeof (struct Socket_T), __FILE__, __LINE__);
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
  sock->tls_timeouts = (SocketTimeouts_T){0};  /* or copy from base? */
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

  *socket = NULL;  /* Invalidate caller pointer before cleanup to avoid UB */

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

/**
 * is_common_bind_error - Check if error is a common non-fatal bind error
 * @err: Error number from errno or SO_ERROR
 * Returns: 1 if common bind error (graceful failure), 0 otherwise
 * Thread-safe: Yes
 * Note: Allows caller to return without raising exception for expected errors
 * like port in use
 */
static int
is_common_bind_error (int err)
{
  return err == EADDRINUSE || err == EACCES || err == EADDRNOTAVAIL
         || err == EAFNOSUPPORT;
}

void
Socket_bind (T socket, const char *host, int port)
{
  struct addrinfo hints, *res = NULL;
  int socket_family;
  volatile Socket_T volatile_socket
      = socket; /* Preserve across exception boundaries */
  volatile int bind_result = -1;

  assert (socket);

  validate_port_number (port);
  host = SocketCommon_normalize_wildcard_host (host);
  setup_bind_hints (&hints);

  if (SocketCommon_resolve_address (host, port, &hints, &res, Socket_Failed,
                                    SOCKET_AF_UNSPEC, 0)
      != 0)
    {
      errno = EAI_FAIL;
      return;
    }

  socket_family = get_socket_family ((Socket_T)volatile_socket);

  TRY
  {
    bind_result = SocketCommon_try_bind_resolved_addresses (volatile_socket->base, res, socket_family, Socket_Failed);
    if (bind_result == 0)
      {
        SocketCommon_update_local_endpoint (volatile_socket->base);
        freeaddrinfo (res);
        return;
      }
  }
  EXCEPT (Socket_Failed)
  {
    // Preserve errno before freeaddrinfo() may modify it
    int saved_errno = errno;
    freeaddrinfo (res);
    // Graceful failure for common bind errors - check errno from the
    // underlying bind call
    if (is_common_bind_error (saved_errno))
      {
        errno = saved_errno; /* Restore errno for caller */
        return;              /* Caller can check errno */
      }
    // For unexpected errors, re-raise
    errno = saved_errno; /* Restore errno before re-raising */
    RERAISE;
  }
  END_TRY;

  // If bind failed, check errno for common errors before raising
  // Preserve errno before freeaddrinfo() may modify it
  int saved_errno = errno;
  freeaddrinfo (res);
  if (is_common_bind_error (saved_errno))
    {
      errno = saved_errno; /* Restore errno for caller */
      return;              /* Graceful failure - caller checks errno */
    }

  handle_bind_error (host, port);
  RAISE_MODULE_ERROR (Socket_Failed);
}

/**
 * validate_backlog - Validate listen backlog parameter
 * @backlog: Backlog value to validate
 * Raises: Socket_Failed if invalid
 */
static void
validate_backlog (int backlog)
{
  if (backlog <= 0)
    {
      SOCKET_ERROR_MSG ("Invalid backlog value: %d (must be > 0)", backlog);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

/**
 * enforce_backlog_limit - Enforce maximum backlog limit
 * @backlog: Backlog value to enforce
 * Returns: Enforced backlog value
 */
static int
enforce_backlog_limit (int backlog)
{
  if (backlog > SOCKET_MAX_LISTEN_BACKLOG)
    return SOCKET_MAX_LISTEN_BACKLOG;
  return backlog;
}

void
Socket_listen (T socket, int backlog)
{
  int result;

  assert (socket);
  validate_backlog (backlog);
  backlog = enforce_backlog_limit (backlog);

  result = listen (SocketBase_fd (socket->base), backlog);
  if (result < 0)
    {
      SOCKET_ERROR_FMT ("Failed to listen on socket (backlog=%d)", backlog);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

/**
 * accept_connection - Accept a new connection
 * @socket: Listening socket
 * @addr: Output address structure
 * @addrlen: Input/output address length
 * Returns: New file descriptor or -1 on error
 * Note: All accepted sockets have close-on-exec flag set by default.
 */
static int
accept_connection (T socket, struct sockaddr_storage *addr, socklen_t *addrlen)
{
  int newfd;

#if SOCKET_HAS_ACCEPT4
  /* Use accept4() with SOCK_CLOEXEC when available */
  newfd = accept4 (SocketBase_fd (socket->base), (struct sockaddr *)addr, addrlen,
                   SOCKET_SOCK_CLOEXEC);
#else
  newfd = accept (SocketBase_fd (socket->base), (struct sockaddr *)addr, addrlen);
#endif

  if (newfd < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return -1;
      SOCKET_ERROR_FMT ("Failed to accept connection");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

#if !SOCKET_HAS_ACCEPT4
  /* Fallback: Set CLOEXEC via fcntl on older systems */
  if (SocketCommon_setcloexec (newfd, 1) < 0)
    {
      int saved_errno = errno;
      SAFE_CLOSE (newfd);
      errno = saved_errno;
      SOCKET_ERROR_FMT ("Failed to set close-on-exec flag on accepted socket");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#endif

  return newfd;
}

/**
 * create_accepted_socket - Create socket structure for accepted connection
 * @newfd: Accepted file descriptor
 * @addr: Peer address
 * @addrlen: Address length
 * Returns: New socket or NULL on failure
 * Raises: Socket_Failed on allocation failure
 */
static T
create_accepted_socket (int newfd, const struct sockaddr_storage *addr,
                        socklen_t addrlen)
{
  Arena_T arena = NULL;
  T newsocket = NULL;
  SocketBase_T base = NULL;
  int domain;
  int type_opt;
  socklen_t opt_len = sizeof (type_opt);
  int protocol = 0;
  int saved_errno;

  TRY
    arena = Arena_new ();
  EXCEPT (Arena_Failed)
    {
      saved_errno = errno;
      SAFE_CLOSE (newfd);
      errno = saved_errno;
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate arena for accepted socket");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  END_TRY;

  newsocket = Arena_calloc (arena, 1, sizeof (struct Socket_T), __FILE__, __LINE__);
  if (!newsocket)
    {
      Arena_dispose (&arena);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate accepted socket structure");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  base = Arena_calloc (arena, 1, sizeof (struct SocketBase_T), __FILE__, __LINE__);
  if (!base)
    {
      Arena_dispose (&arena);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate base for accepted socket");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  newsocket->base = base;
  base->arena = arena;
  base->fd = newfd;

  /* Infer domain from peer address */
  domain = ((const struct sockaddr *)addr)->sa_family;

  /* Infer type from socket option */
  if (getsockopt (newfd, SOL_SOCKET, SO_TYPE, &type_opt, &opt_len) < 0)
    {
      saved_errno = errno;
      Arena_dispose (&arena);
      SAFE_CLOSE (newfd);
      errno = saved_errno;
      SOCKET_ERROR_MSG ("Failed to get SO_TYPE for accepted socket: %s", strerror (saved_errno));
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Initialize base with inferred values */
  SocketCommon_init_base (base, newfd, domain, type_opt, protocol, Socket_Failed);

  /* Set remote endpoint from accept addr */
  memcpy (&base->remote_addr, addr, addrlen);
  base->remote_addrlen = addrlen;

  /* Local endpoint already updated in init_base via update_local_endpoint */

  /* Reset cached strings/ports for remote (will be set in setup_peer_info later) */
  base->remoteaddr = NULL;
  base->remoteport = 0;
  base->localaddr = NULL;
  base->localport = 0;

#ifdef SOCKET_HAS_TLS
  /* Initialize TLS fields for accepted connection */
  newsocket->tls_ctx = NULL;
  newsocket->tls_ssl = NULL;
  newsocket->tls_enabled = 0;
  newsocket->tls_handshake_done = 0;
  newsocket->tls_shutdown_done = 0;
  newsocket->tls_last_handshake_state = 0;
  newsocket->tls_sni_hostname = NULL;
  newsocket->tls_read_buf = NULL;
  newsocket->tls_write_buf = NULL;
  newsocket->tls_read_buf_len = 0;
  newsocket->tls_write_buf_len = 0;
  newsocket->tls_timeouts = (SocketTimeouts_T){0};
#endif

  socket_live_increment ();

  return newsocket;
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
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate sock for new_from_fd");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  sock->base = Arena_calloc (arena, 1, sizeof (struct SocketBase_T), __FILE__, __LINE__);
  if (!sock->base)
    {
      Arena_dispose (&arena);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate base for new_from_fd");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  sock->base->arena = arena;
  sock->base->fd = fd;
  sock->base->domain = AF_UNSPEC; /* Detect if needed */
  sock->base->type = 0; /* Detect */
  sock->base->protocol = 0;

  SocketCommon_init_base (sock->base, fd, sock->base->domain, sock->base->type, 0, Socket_Failed);

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
    setup_peer_info (newsocket, (struct sockaddr *)&addr, addrlen);
    SocketCommon_update_local_endpoint (newsocket->base);
    SocketEvent_emit_accept (SocketBase_fd (newsocket->base), newsocket->base->remoteaddr,
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

/**
 * try_connect_resolved_addresses - Try connecting to resolved addresses
 * @socket: Socket to connect
 * @res: Resolved address list
 * @socket_family: Socket's address family
 * Returns: 0 on success, -1 on failure
 */
static int
try_connect_resolved_addresses (T socket, struct addrinfo *res,
                                int socket_family, int timeout_ms)
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

void
Socket_connect (T socket, const char *host, int port)
{
  struct addrinfo hints, *res = NULL;
  int socket_family;
  volatile Socket_T volatile_socket
      = socket; /* Preserve across exception boundaries */

  assert (socket);
  assert (host);

  validate_host_not_null (host);
  validate_port_number (port);
  setup_connect_hints (&hints);

  if (SocketCommon_resolve_address (host, port, &hints, &res, Socket_Failed,
                                    SOCKET_AF_UNSPEC, 0)
      != 0)
    { // Don't raise on resolve fail
      errno = EAI_FAIL;
      return;
    }

  socket_family = get_socket_family ((Socket_T)volatile_socket);

  TRY
  {
    if (try_connect_resolved_addresses ((Socket_T)volatile_socket, res,
                                        socket_family,
                                        volatile_socket->base->timeouts.connect_timeout_ms)
        == 0)
      {
        SocketMetrics_increment (SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 1);
        SocketCommon_update_local_endpoint (((Socket_T)volatile_socket)->base);
        setup_peer_info (volatile_socket,
                         (struct sockaddr *)&volatile_socket->base->remote_addr,
                         volatile_socket->base->remote_addrlen);
        SocketEvent_emit_connect (Socket_fd ((Socket_T)volatile_socket),
                                  SocketBase_remoteaddr (((Socket_T)volatile_socket)->base),
                                  SocketBase_remoteport (((Socket_T)volatile_socket)->base),
                                  SocketBase_localaddr (((Socket_T)volatile_socket)->base),
                                  SocketBase_localport (((Socket_T)volatile_socket)->base));
        freeaddrinfo (res);
        return;
      }
  }
  EXCEPT (Socket_Failed)
  {
    // Preserve errno before freeaddrinfo() may modify it
    int saved_errno = errno;
    freeaddrinfo (res);
    // Check errno and return gracefully for common connection errors
    if (saved_errno == ECONNREFUSED || saved_errno == ETIMEDOUT
        || saved_errno == ENETUNREACH || saved_errno == EHOSTUNREACH
        || saved_errno == ECONNABORTED)
      {
        errno = saved_errno; /* Restore errno for caller */
        return;              /* Caller can retry */
      }
    // For other errors, re-raise
    errno = saved_errno; /* Restore errno before re-raising */
    RERAISE;
  }
  END_TRY;

  // If connect failed, check errno for common errors before raising
  // Preserve errno before freeaddrinfo() may modify it
  int saved_errno = errno;
  freeaddrinfo (res);
  if (saved_errno == ECONNREFUSED || saved_errno == ETIMEDOUT
      || saved_errno == ENETUNREACH || saved_errno == EHOSTUNREACH
      || saved_errno == ECONNABORTED)
    {
      errno = saved_errno; /* Restore errno for caller */
      return;              /* Graceful failure - caller can retry */
    }

  handle_connect_error (host, port);
  RAISE_MODULE_ERROR (Socket_Failed);
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

/**
 * Socket_sendall - Send all data (handles partial sends)
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (> 0)
 * Returns: Total bytes sent (always equals len on success)
 * Raises: Socket_Closed on EPIPE/ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until all data is sent or an error occurs.
 * For non-blocking sockets, returns 0 if would block (EAGAIN/EWOULDBLOCK).
 * Use Socket_isconnected() to verify connection state before calling.
 */
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

/**
 * Socket_recvall - Receive all requested data (handles partial receives)
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (> 0)
 * Returns: Total bytes received (always equals len on success)
 * Raises: Socket_Closed on peer close (recv returns 0) or ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until len bytes are received or an error occurs.
 * For non-blocking sockets, returns 0 if would block (EAGAIN/EWOULDBLOCK).
 * Use Socket_isconnected() to verify connection state before calling.
 */
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

/* SocketCommon_calculate_total_iov_len removed: use SocketCommon_calculate_total_iov_len */

/* Local socket_advance_iov (renamed artifact) removed: use shared SocketCommon_advance_iov */

/**
 * Socket_sendv - Scatter/gather send (writev wrapper)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes sent (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on EPIPE/ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Sends data from multiple buffers in a single system call.
 * May send less than requested. Use Socket_sendvall() for guaranteed complete
 * send.
 */
ssize_t
Socket_sendv (T socket, const struct iovec *iov, int iovcnt)
{
  return socket_sendv_internal (socket, iov, iovcnt, 0);
}

/**
 * Socket_recvv - Scatter/gather receive (readv wrapper)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes received (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on peer close (recv returns 0) or ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Receives data into multiple buffers in a single system call.
 * May receive less than requested. Use Socket_recvvall() for guaranteed
 * complete receive.
 */
ssize_t
Socket_recvv (T socket, struct iovec *iov, int iovcnt)
{
  return socket_recvv_internal (socket, iov, iovcnt, 0);
}

/**
 * Socket_sendvall - Scatter/gather send all (handles partial sends)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes sent (always equals sum of all iov_len on success)
 * Raises: Socket_Closed on EPIPE/ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until all data from all buffers is sent or an error occurs.
 * For non-blocking sockets, returns partial progress if would block.
 * Use Socket_isconnected() to verify connection state before calling.
 */
ssize_t
Socket_sendvall (T socket, const struct iovec *iov, int iovcnt)
{
  Arena_T temp_arena = NULL;
  struct iovec *iov_copy = NULL;
  volatile size_t total_sent = 0;
  size_t total_len;
  ssize_t sent;
  int i;

  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

  /* Calculate total length */
  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);

  TRY temp_arena = Arena_new ();
  if (!temp_arena)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM
                        ": Cannot allocate temp arena for iov copy");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Allocate iovec copy from arena */
  iov_copy = ALLOC (temp_arena, (size_t)iovcnt * sizeof (struct iovec));
  memcpy (iov_copy, iov, (size_t)iovcnt * sizeof (struct iovec));

  while (total_sent < total_len)
    {
      /* Find first non-empty iovec */
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
        break; /* All buffers sent */

      sent = Socket_sendv (socket, active_iov, active_iovcnt);
      if (sent == 0)
        {
          /* Would block (EAGAIN/EWOULDBLOCK) - return partial progress */
          return (ssize_t)total_sent;
        }
      total_sent += (size_t)sent;
      SocketCommon_advance_iov (iov_copy, iovcnt, (size_t)sent);
    }
  EXCEPT (Socket_Closed)
  RERAISE;
  EXCEPT (Socket_Failed)
  RERAISE;
  FINALLY
  if (temp_arena)
    Arena_dispose (&temp_arena); /* Frees iov_copy automatically */
  END_TRY;

  return (ssize_t)total_sent;
}

/**
 * Socket_recvvall - Scatter/gather receive all (handles partial receives)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes received (always equals sum of all iov_len on success)
 * Raises: Socket_Closed on peer close (recv returns 0) or ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until all requested data is received into all buffers or an
 * error occurs. For non-blocking sockets, returns partial progress if would
 * block. Use Socket_isconnected() to verify connection state before calling.
 */
ssize_t
Socket_recvvall (T socket, struct iovec *iov, int iovcnt)
{
  Arena_T temp_arena = NULL;
  struct iovec *iov_copy = NULL;
  volatile size_t total_received = 0;
  size_t total_len;
  ssize_t received;
  int i;

  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

  /* Calculate total length */
  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);

  TRY temp_arena = Arena_new ();
  if (!temp_arena)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM
                        ": Cannot allocate temp arena for iov copy");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Allocate iovec copy from arena */
  iov_copy = ALLOC (temp_arena, (size_t)iovcnt * sizeof (struct iovec));
  memcpy (iov_copy, iov, (size_t)iovcnt * sizeof (struct iovec));

  while (total_received < total_len)
    {
      /* Find first non-empty iovec */
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
        break; /* All buffers filled */

      received = Socket_recvv (socket, active_iov, active_iovcnt);
      if (received == 0)
        {
          /* Would block (EAGAIN/EWOULDBLOCK) - return partial progress */
          /* Copy back partial data */
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
          return (ssize_t)total_received;
        }
      total_received += (size_t)received;
      SocketCommon_advance_iov (iov_copy, iovcnt, (size_t)received);
    }

  /* Copy back final data positions */
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
  EXCEPT (Socket_Closed)
  RERAISE;
  EXCEPT (Socket_Failed)
  RERAISE;
  FINALLY
  if (temp_arena)
    Arena_dispose (&temp_arena); /* Frees iov_copy automatically */
  END_TRY;

  return (ssize_t)total_received;
}

/**
 * socket_sendfile_linux - Linux sendfile()
 * @socket: Socket to send to
 * @file_fd: File descriptor to read from
 * @offset: File offset pointer (may be NULL)
 * @count: Bytes to transfer
 * Returns: Bytes transferred or -1 on error
 */
#if SOCKET_HAS_SENDFILE && defined(__linux__)
static ssize_t
socket_sendfile_linux (T socket, int file_fd, off_t *offset, size_t count)
{
  off_t off = offset ? *offset : 0;
  ssize_t result = sendfile (SocketBase_fd (socket->base), file_fd, &off, count);
  if (result >= 0 && offset)
    *offset = off;
  return result;
}
#endif

/**
 * socket_sendfile_bsd - BSD/macOS sendfile()
 * @socket: Socket to send to
 * @file_fd: File descriptor to read from
 * @offset: File offset pointer (may be NULL)
 * @count: Bytes to transfer
 * Returns: Bytes transferred or -1 on error
 */
#if SOCKET_HAS_SENDFILE                                                       \
    && (defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)   \
        || defined(__DragonFly__)                                             \
        || (defined(__APPLE__) && defined(__MACH__)))
static ssize_t
socket_sendfile_bsd (T socket, int file_fd, off_t *offset, size_t count)
{
  off_t len = (off_t)count;
  off_t off = offset ? *offset : 0;
  int result = sendfile (file_fd, SocketBase_fd (socket->base), off, &len, NULL, 0);
  if (result == 0)
    {
      if (offset)
        *offset = off + len;
      return (ssize_t)len;
    }
  return -1;
}
#endif

/**
 * socket_sendfile_fallback - Fallback using read/write
 * @socket: Socket to send to
 * @file_fd: File descriptor to read from
 * @offset: File offset pointer (may be NULL)
 * @count: Bytes to transfer
 * Returns: Bytes transferred or -1 on error
 * Note: Used when platform doesn't support sendfile() or as fallback
 */
static ssize_t
socket_sendfile_fallback (T socket, int file_fd, off_t *offset, size_t count)
{
  char buffer[SOCKET_SENDFILE_FALLBACK_BUFFER_SIZE] __attribute__((unused));
  volatile size_t total_sent = 0;
  ssize_t read_bytes, sent_bytes;

  if (offset && *offset != 0)
    {
      if (lseek (file_fd, *offset, SEEK_SET) < 0)
        return -1;
    }

  TRY while (total_sent < count)
  {
    size_t to_read = (count - total_sent < sizeof (buffer))
                         ? (count - total_sent)
                         : sizeof (buffer);
    read_bytes = read (file_fd, buffer, to_read);
    if (read_bytes <= 0)
      {
        if (read_bytes == 0)
          break; /* EOF */
        if (errno == EINTR)
          continue;
        return -1;
      }

    sent_bytes = Socket_send (socket, buffer, (size_t)read_bytes);
    if (sent_bytes == 0)
      {
        /* Would block - return partial progress */
        if (offset)
          *offset += (off_t)total_sent;
        return (ssize_t)total_sent;
      }
    total_sent += (size_t)sent_bytes;

    if ((size_t)read_bytes < to_read)
      break; /* EOF reached */
  }
  EXCEPT (Socket_Closed)
  if (offset)
    *offset += (off_t)total_sent;
  RERAISE;
  EXCEPT (Socket_Failed)
  if (offset)
    *offset += (off_t)total_sent;
  RERAISE;
  END_TRY;

  if (offset)
    *offset += (off_t)total_sent;
  return (ssize_t)total_sent;
}

/**
 * Socket_sendfile - Zero-copy file-to-socket transfer
 * @socket: Connected socket to send to
 * @file_fd: File descriptor to read from (must be a regular file)
 * @offset: File offset to start reading from (NULL for current position)
 * @count: Number of bytes to transfer (0 for entire file from offset)
 * Returns: Total bytes transferred (> 0) or 0 if would block
 * (EAGAIN/EWOULDBLOCK) Raises: Socket_Closed on EPIPE/ECONNRESET Raises:
 * Socket_Failed on other errors Thread-safe: Yes (operates on single socket)
 * Note: Uses platform-specific zero-copy mechanism (sendfile/splice).
 * Falls back to read/write loop on platforms without sendfile support.
 * TLS-enabled sockets automatically use read/write fallback since kernel
 * sendfile() cannot encrypt data. Performance will be reduced compared to
 * non-TLS sockets due to user-space encryption overhead.
 * May transfer less than requested. Use Socket_sendfileall() for guaranteed
 * complete transfer.
 */
ssize_t
Socket_sendfile (T socket, int file_fd, off_t *offset, size_t count)
{
  ssize_t result = -1;

  assert (socket);
  assert (file_fd >= 0);
  assert (count > 0);

#ifdef SOCKET_HAS_TLS
  /* TLS cannot use kernel sendfile() - must use fallback */
  if (socket_is_tls_enabled (socket))
    {
      result = socket_sendfile_fallback (socket, file_fd, offset, count);
    }
  else
#endif
#if SOCKET_HAS_SENDFILE && defined(__linux__)
    {
      result = socket_sendfile_linux (socket, file_fd, offset, count);
    }
#elif SOCKET_HAS_SENDFILE                                                     \
    && (defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)   \
        || defined(__DragonFly__)                                             \
        || (defined(__APPLE__) && defined(__MACH__)))
  {
    result = socket_sendfile_bsd (socket, file_fd, offset, count);
  }
#else
  {
    result = socket_sendfile_fallback (socket, file_fd, offset, count);
  }
#endif
  if (result < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      if (errno == EPIPE)
        {
          RAISE (Socket_Closed);
        }
      if (errno == ECONNRESET)
        {
          RAISE (Socket_Closed);
        }
      SOCKET_ERROR_FMT (
          "Zero-copy file transfer failed (file_fd=%d, count=%zu)", file_fd,
          count);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return result;
}

/**
 * Socket_sendfileall - Zero-copy file-to-socket transfer (handles partial
 * transfers)
 * @socket: Connected socket to send to
 * @file_fd: File descriptor to read from (must be a regular file)
 * @offset: File offset to start reading from (NULL for current position)
 * @count: Number of bytes to transfer (0 for entire file from offset)
 * Returns: Total bytes transferred (always equals count on success)
 * Raises: Socket_Closed on EPIPE/ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until all data is transferred or an error occurs.
 * For non-blocking sockets, returns partial progress if would block.
 * Uses platform-specific zero-copy mechanism when available.
 */
ssize_t
Socket_sendfileall (T socket, int file_fd, off_t *offset, size_t count)
{
  volatile size_t total_sent = 0;
  ssize_t sent;
  off_t current_offset = offset ? *offset : 0;

  assert (socket);
  assert (file_fd >= 0);
  assert (count > 0);

  TRY while (total_sent < count)
  {
    off_t *current_offset_ptr = offset ? &current_offset : NULL;
    size_t remaining = count - total_sent;

    sent = Socket_sendfile (socket, file_fd, current_offset_ptr, remaining);
    if (sent == 0)
      {
        /* Would block (EAGAIN/EWOULDBLOCK) - return partial progress */
        if (offset)
          *offset = current_offset;
        return (ssize_t)total_sent;
      }
    total_sent += (size_t)sent;
    if (offset)
      current_offset += (off_t)sent;
  }
  EXCEPT (Socket_Closed)
  if (offset)
    *offset = current_offset;
  RERAISE;
  EXCEPT (Socket_Failed)
  if (offset)
    *offset = current_offset;
  RERAISE;
  END_TRY;

  if (offset)
    *offset = current_offset;
  return (ssize_t)total_sent;
}

/**
 * Socket_sendmsg - Send message with ancillary data (sendmsg wrapper)
 * @socket: Connected socket
 * @msg: Message structure with data, address, and ancillary data
 * @flags: Message flags (MSG_NOSIGNAL, MSG_DONTWAIT, etc.)
 * Returns: Total bytes sent (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on EPIPE/ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Allows sending data with control messages (CMSG) for advanced features
 * like file descriptor passing, credentials, IP options, etc.
 * May send less than requested. Use Socket_sendmsgall() for guaranteed
 * complete send.
 */
ssize_t
Socket_sendmsg (T socket, const struct msghdr *msg, int flags)
{
  ssize_t result;

  assert (socket);
  assert (msg);

  result = sendmsg (SocketBase_fd (socket->base), msg, flags);
  if (result < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      if (errno == EPIPE)
        {
          RAISE (Socket_Closed);
        }
      if (errno == ECONNRESET)
        {
          RAISE (Socket_Closed);
        }
      SOCKET_ERROR_FMT ("sendmsg failed (flags=0x%x)", flags);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return result;
}

/**
 * Socket_recvmsg - Receive message with ancillary data (recvmsg wrapper)
 * @socket: Connected socket
 * @msg: Message structure for data, address, and ancillary data
 * @flags: Message flags (MSG_DONTWAIT, MSG_PEEK, etc.)
 * Returns: Total bytes received (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: Socket_Closed on peer close (recv returns 0) or ECONNRESET
 * Raises: Socket_Failed on other errors
 * Thread-safe: Yes (operates on single socket)
 * Note: Allows receiving data with control messages (CMSG) for advanced
 * features like file descriptor passing, credentials, IP options, etc. May
 * receive less than requested. Use Socket_recvmsgall() for guaranteed complete
 * receive.
 */
ssize_t
Socket_recvmsg (T socket, struct msghdr *msg, int flags)
{
  ssize_t result;

  assert (socket);
  assert (msg);

  result = recvmsg (SocketBase_fd (socket->base), msg, flags);
  if (result < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      if (errno == ECONNRESET)
        {
          RAISE (Socket_Closed);
        }
      SOCKET_ERROR_FMT ("recvmsg failed (flags=0x%x)", flags);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  else if (result == 0)
    {
      RAISE (Socket_Closed);
    }

  return result;
}

void
Socket_setnonblocking (T socket)
{
  SocketCommon_set_nonblock (socket->base, true, Socket_Failed);
}

void
Socket_setreuseaddr (T socket)
{
  int opt = 1;

  assert (socket);

  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET, SOCKET_SO_REUSEADDR, &opt,
                  sizeof (opt))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set SO_REUSEADDR");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

void
Socket_setreuseport (T socket)
{
  int opt = 1;

  assert (socket);

#if SOCKET_HAS_SO_REUSEPORT
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET, SOCKET_SO_REUSEPORT, &opt,
                  sizeof (opt))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set SO_REUSEPORT");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#else
  (void)opt;
  SOCKET_ERROR_MSG ("SO_REUSEPORT not supported on this platform");
  RAISE_MODULE_ERROR (Socket_Failed);
#endif
}

void
Socket_settimeout (T socket, int timeout_sec)
{
  struct timeval tv;

  assert (socket);

  /* Validate timeout */
  if (timeout_sec < 0)
    {
      SOCKET_ERROR_MSG ("Invalid timeout value: %d (must be >= 0)",
                        timeout_sec);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  tv.tv_sec = timeout_sec;
  tv.tv_usec = 0;

  /* Set timeouts */
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET, SOCKET_SO_RCVTIMEO, &tv,
                  sizeof (tv))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set receive timeout");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET, SOCKET_SO_SNDTIMEO, &tv,
                  sizeof (tv))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set send timeout");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

/**
 * socket_shutdown_mode_valid - Check shutdown mode value
 * @how: Shutdown mode
 * Returns: 1 if valid, 0 otherwise
 * Thread-safe: Yes
 */
static int
socket_shutdown_mode_valid (int how)
{
  return (how == SOCKET_SHUT_RD || how == SOCKET_SHUT_WR
          || how == SOCKET_SHUT_RDWR);
}

/**
 * Socket_shutdown - Disable further sends and/or receives
 * @socket: Connected socket
 * @how: Shutdown mode (SOCKET_SHUT_RD, SOCKET_SHUT_WR, SOCKET_SHUT_RDWR)
 * Raises: Socket_Failed on error
 */
void
Socket_shutdown (T socket, int how)
{
  assert (socket);

  if (!socket_shutdown_mode_valid (how))
    {
      SOCKET_ERROR_MSG ("Invalid shutdown mode: %d", how);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  if (shutdown (SocketBase_fd (socket->base), how) < 0)
    {
      if (errno == ENOTCONN)
        SOCKET_ERROR_FMT ("Socket is not connected (shutdown mode=%d)", how);
      else
        SOCKET_ERROR_FMT ("Failed to shutdown socket (mode=%d)", how);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  SocketMetrics_increment (SOCKET_METRIC_SOCKET_SHUTDOWN_CALL, 1);
}

/**
 * Socket_setcloexec - Control close-on-exec flag
 * @socket: Socket to modify
 * @enable: 1 to enable CLOEXEC, 0 to disable
 * Raises: Socket_Failed on error
 */
void
Socket_setcloexec (T socket, int enable)
{
  assert (socket);

  if (SocketCommon_setcloexec (SocketBase_fd (socket->base), enable) < 0)
    {
      SOCKET_ERROR_FMT ("Failed to %s close-on-exec flag",
                        enable ? "set" : "clear");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

void
Socket_timeouts_get (const T socket, SocketTimeouts_T *timeouts)
{
  assert (socket);
  assert (timeouts);

  *timeouts = socket->base->timeouts;
}

void
Socket_timeouts_set (T socket, const SocketTimeouts_T *timeouts)
{
  assert (socket);

  if (timeouts == NULL)
    {
      /* Thread-safe copy of default timeouts */
      pthread_mutex_lock (&socket_default_timeouts_mutex);
      socket->base->timeouts = socket_default_timeouts;
      pthread_mutex_unlock (&socket_default_timeouts_mutex);
      return;
    }

  socket->base->timeouts.connect_timeout_ms
      = sanitize_timeout (timeouts->connect_timeout_ms);
  socket->base->timeouts.dns_timeout_ms
      = sanitize_timeout (timeouts->dns_timeout_ms);
  socket->base->timeouts.operation_timeout_ms
      = sanitize_timeout (timeouts->operation_timeout_ms);
}

void
Socket_timeouts_getdefaults (SocketTimeouts_T *timeouts)
{
  assert (timeouts);

  /* Thread-safe copy of default timeouts */
  pthread_mutex_lock (&socket_default_timeouts_mutex);
  *timeouts = socket_default_timeouts;
  pthread_mutex_unlock (&socket_default_timeouts_mutex);
}

void
Socket_timeouts_setdefaults (const SocketTimeouts_T *timeouts)
{
  SocketTimeouts_T local;

  assert (timeouts);

  /* Thread-safe read-modify-write of default timeouts */
  pthread_mutex_lock (&socket_default_timeouts_mutex);
  local = socket_default_timeouts;
  pthread_mutex_unlock (&socket_default_timeouts_mutex);

  local.connect_timeout_ms = sanitize_timeout (timeouts->connect_timeout_ms);
  local.dns_timeout_ms = sanitize_timeout (timeouts->dns_timeout_ms);
  local.operation_timeout_ms
      = sanitize_timeout (timeouts->operation_timeout_ms);

  pthread_mutex_lock (&socket_default_timeouts_mutex);
  socket_default_timeouts = local;
  pthread_mutex_unlock (&socket_default_timeouts_mutex);
}

/**
 * validate_keepalive_parameters - Validate keepalive parameters
 * @idle: Idle timeout
 * @interval: Interval between probes
 * @count: Probe count
 * Raises: Socket_Failed if parameters are invalid
 */
static void
validate_keepalive_parameters (int idle, int interval, int count)
{
  if (idle <= 0 || interval <= 0 || count <= 0)
    {
      SOCKET_ERROR_MSG ("Invalid keepalive parameters (idle=%d, interval=%d, "
                        "count=%d): all must be > 0",
                        idle, interval, count);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

/**
 * enable_socket_keepalive - Enable keepalive on socket
 * @socket: Socket to configure
 * Raises: Socket_Failed on failure
 */
static void
enable_socket_keepalive (T socket)
{
  int opt = 1;
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET, SOCKET_SO_KEEPALIVE, &opt,
                  sizeof (opt))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to enable keepalive");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

/**
 * set_keepalive_idle_time - Set keepalive idle timeout
 * @socket: Socket to configure
 * @idle: Idle timeout in seconds
 * Raises: Socket_Failed on failure
 */
static void
set_keepalive_idle_time (T socket, int idle)
{
#ifdef TCP_KEEPIDLE
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPIDLE, &idle,
                  sizeof (idle))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set keepalive idle time");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#else
  (void)socket;
  (void)idle;
#endif
}

/**
 * set_keepalive_interval - Set keepalive probe interval
 * @socket: Socket to configure
 * @interval: Interval in seconds
 * Raises: Socket_Failed on failure
 */
static void
set_keepalive_interval (T socket, int interval)
{
#ifdef TCP_KEEPINTVL
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPINTVL,
                  &interval, sizeof (interval))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set keepalive interval");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#endif
}

/**
 * set_keepalive_count - Set keepalive probe count
 * @socket: Socket to configure
 * @count: Probe count
 * Raises: Socket_Failed on failure
 */
static void
set_keepalive_count (T socket, int count)
{
#ifdef TCP_KEEPCNT
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPCNT, &count,
                  sizeof (count))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set keepalive count");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#endif
}

void
Socket_setkeepalive (T socket, int idle, int interval, int count)
{
  assert (socket);
  validate_keepalive_parameters (idle, interval, count);
  enable_socket_keepalive (socket);
  set_keepalive_idle_time (socket, idle);
  set_keepalive_interval (socket, interval);
  set_keepalive_count (socket, count);
}

void
Socket_setnodelay (T socket, int nodelay)
{
  assert (socket);

  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP, SOCKET_TCP_NODELAY, &nodelay,
                  sizeof (nodelay))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set TCP_NODELAY");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

/**
 * Socket_gettimeout - Get socket timeout
 * @socket: Socket to query
 * Returns: Timeout in seconds (0 if disabled)
 * Raises: Socket_Failed on error
 * Note: Returns receive timeout (send timeout may differ)
 */
int
Socket_gettimeout (T socket)
{
  struct timeval tv;

  assert (socket);

  if (SocketCommon_getoption_timeval (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                                      SOCKET_SO_RCVTIMEO, &tv, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  return (int)tv.tv_sec;
}

/**
 * Socket_getkeepalive - Get TCP keepalive configuration
 * @socket: Socket to query
 * @idle: Output - idle timeout in seconds
 * @interval: Output - interval between probes in seconds
 * @count: Output - number of probes before declaring dead
 * Raises: Socket_Failed on error
 * Note: Returns 0 for parameters not supported on this platform.
 * On macOS, getsockopt() may return 0 or default values even after
 * successfully setting keepalive parameters. This is a known macOS quirk - the
 * options are set correctly, but getsockopt() doesn't always reflect the set
 * values.
 */
void
Socket_getkeepalive (T socket, int *idle, int *interval, int *count)
{
  int keepalive_enabled = 0;

  assert (socket);
  assert (idle);
  assert (interval);
  assert (count);

  /* Get SO_KEEPALIVE flag */
  if (SocketCommon_getoption_int (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                                  SOCKET_SO_KEEPALIVE, &keepalive_enabled,
                                  Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  if (!keepalive_enabled)
    {
      *idle = 0;
      *interval = 0;
      *count = 0;
      return;
    }

    /* Get TCP_KEEPIDLE */
#ifdef TCP_KEEPIDLE
  if (SocketCommon_getoption_int (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                                  SOCKET_TCP_KEEPIDLE, idle, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);
#else
  *idle = 0;
#endif

    /* Get TCP_KEEPINTVL */
#ifdef TCP_KEEPINTVL
  if (SocketCommon_getoption_int (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                                  SOCKET_TCP_KEEPINTVL, interval,
                                  Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);
#else
  *interval = 0;
#endif

    /* Get TCP_KEEPCNT */
#ifdef TCP_KEEPCNT
  if (SocketCommon_getoption_int (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                                  SOCKET_TCP_KEEPCNT, count, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);
#else
  *count = 0;
#endif
}

/**
 * Socket_getnodelay - Get TCP_NODELAY setting
 * @socket: Socket to query
 * Returns: 1 if Nagle's algorithm is disabled, 0 if enabled
 * Raises: Socket_Failed on error
 * Note: On macOS, getsockopt() may return 0 even after successfully setting
 * TCP_NODELAY to 1. This is a known macOS quirk - the option is set correctly,
 * but getsockopt() doesn't always reflect the set value.
 */
int
Socket_getnodelay (T socket)
{
  int nodelay = 0;

  assert (socket);

  if (SocketCommon_getoption_int (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                                  SOCKET_TCP_NODELAY, &nodelay, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  return nodelay;
}

/**
 * Socket_getrcvbuf - Get receive buffer size
 * @socket: Socket to query
 * Returns: Receive buffer size in bytes
 * Raises: Socket_Failed on error
 */
int
Socket_getrcvbuf (T socket)
{
  int bufsize = 0;

  assert (socket);

  if (SocketCommon_getoption_int (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                                  SOCKET_SO_RCVBUF, &bufsize, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  return bufsize;
}

/**
 * Socket_getsndbuf - Get send buffer size
 * @socket: Socket to query
 * Returns: Send buffer size in bytes
 * Raises: Socket_Failed on error
 */
int
Socket_getsndbuf (T socket)
{
  int bufsize = 0;

  assert (socket);

  if (SocketCommon_getoption_int (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                                  SOCKET_SO_SNDBUF, &bufsize, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  return bufsize;
}

/**
 * Socket_setrcvbuf - Set receive buffer size
 * @socket: Socket to modify
 * @size: Buffer size in bytes (> 0)
 * Raises: Socket_Failed on error
 * Note: The kernel may adjust the value to be within system limits.
 * Use Socket_getrcvbuf() to verify the actual size set.
 */
void
Socket_setrcvbuf (T socket, int size)
{
  assert (socket);
  assert (size > 0);

  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET, SOCKET_SO_RCVBUF, &size,
                  sizeof (size))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set SO_RCVBUF (size=%d)", size);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

/**
 * Socket_setsndbuf - Set send buffer size
 * @socket: Socket to modify
 * @size: Buffer size in bytes (> 0)
 * Raises: Socket_Failed on error
 * Note: The kernel may adjust the value to be within system limits.
 * Use Socket_getsndbuf() to verify the actual size set.
 */
void
Socket_setsndbuf (T socket, int size)
{
  assert (socket);
  assert (size > 0);

  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET, SOCKET_SO_SNDBUF, &size,
                  sizeof (size))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set SO_SNDBUF (size=%d)", size);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

/**
 * Socket_setcongestion - Set TCP congestion control algorithm
 * @socket: Socket to modify
 * @algorithm: Algorithm name (e.g., "cubic", "reno", "bbr")
 * Raises: Socket_Failed on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: Only available on Linux 2.6.13+. Common algorithms:
 * - "cubic" (default on many Linux systems)
 * - "reno" (classic TCP)
 * - "bbr" (Google BBR, Linux 4.9+)
 * - "bbr2" (BBR v2, Linux 4.20+)
 * Use Socket_getcongestion() to query current algorithm.
 */
void
Socket_setcongestion (T socket, const char *algorithm)
{
  assert (socket);
  assert (algorithm);

#if SOCKET_HAS_TCP_CONGESTION
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP, SOCKET_TCP_CONGESTION,
                  algorithm, strlen (algorithm) + 1)
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set TCP_CONGESTION (algorithm=%s)",
                        algorithm);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#else
  SOCKET_ERROR_MSG ("TCP_CONGESTION not supported on this platform");
  RAISE_MODULE_ERROR (Socket_Failed);
#endif
}

/**
 * Socket_getcongestion - Get TCP congestion control algorithm
 * @socket: Socket to query
 * @algorithm: Output buffer for algorithm name
 * @len: Buffer length
 * Returns: 0 on success, -1 on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: Only available on Linux 2.6.13+.
 * The algorithm name is written to the provided buffer.
 */
int
Socket_getcongestion (T socket, char *algorithm, size_t len)
{
  socklen_t optlen;

  assert (socket);
  assert (algorithm);
  assert (len > 0);

#if SOCKET_HAS_TCP_CONGESTION
  optlen = (socklen_t)len;
  if (getsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP, SOCKET_TCP_CONGESTION,
                  algorithm, &optlen)
      < 0)
    {
      return -1;
    }
  return 0;
#else
  (void)optlen;
  (void)len;
  return -1;
#endif
}

/**
 * Socket_setfastopen - Enable TCP Fast Open
 * @socket: Socket to modify
 * @enable: 1 to enable, 0 to disable
 * Raises: Socket_Failed on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: TCP Fast Open allows sending data in SYN packet.
 * Only available on Linux 3.7+, FreeBSD 10.0+, macOS 10.11+.
 * Must be set before connect() or listen().
 * Use Socket_getfastopen() to query current setting.
 */
void
Socket_setfastopen (T socket, int enable)
{
  int opt = enable ? 1 : 0;

  assert (socket);

#if SOCKET_HAS_TCP_FASTOPEN
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP, SOCKET_TCP_FASTOPEN, &opt,
                  sizeof (opt))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set TCP_FASTOPEN (enable=%d)", enable);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#else
  (void)opt;
  SOCKET_ERROR_MSG ("TCP_FASTOPEN not supported on this platform");
  RAISE_MODULE_ERROR (Socket_Failed);
#endif
}

/**
 * Socket_getfastopen - Get TCP Fast Open setting
 * @socket: Socket to query
 * Returns: 1 if enabled, 0 if disabled, -1 on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: Only available on platforms that support TCP Fast Open.
 */
int
Socket_getfastopen (T socket)
{
  int opt = 0;
  socklen_t optlen = sizeof (opt);

  assert (socket);

#if SOCKET_HAS_TCP_FASTOPEN
  if (getsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP, SOCKET_TCP_FASTOPEN, &opt,
                  &optlen)
      < 0)
    {
      return -1;
    }
  return opt;
#else
  return -1;
#endif
}

/**
 * Socket_setusertimeout - Set TCP user timeout
 * @socket: Socket to modify
 * @timeout_ms: Timeout in milliseconds (> 0)
 * Raises: Socket_Failed on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: TCP user timeout controls how long to wait for ACK before
 * closing connection. Only available on Linux 2.6.37+.
 * Use Socket_getusertimeout() to query current timeout.
 */
void
Socket_setusertimeout (T socket, unsigned int timeout_ms)
{
  assert (socket);
  assert (timeout_ms > 0);

#if SOCKET_HAS_TCP_USER_TIMEOUT
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP, SOCKET_TCP_USER_TIMEOUT,
                  &timeout_ms, sizeof (timeout_ms))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set TCP_USER_TIMEOUT (timeout_ms=%u)",
                        timeout_ms);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#else
  (void)timeout_ms;
  SOCKET_ERROR_MSG ("TCP_USER_TIMEOUT not supported on this platform");
  RAISE_MODULE_ERROR (Socket_Failed);
#endif
}

/**
 * Socket_getusertimeout - Get TCP user timeout
 * @socket: Socket to query
 * Returns: Timeout in milliseconds, or 0 on error or if not supported
 * Thread-safe: Yes (operates on single socket)
 * Note: Only available on Linux 2.6.37+.
 */
unsigned int
Socket_getusertimeout (T socket)
{
  unsigned int timeout_ms = 0;
  socklen_t optlen = sizeof (timeout_ms);

  assert (socket);

#if SOCKET_HAS_TCP_USER_TIMEOUT
  if (getsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP, SOCKET_TCP_USER_TIMEOUT,
                  &timeout_ms, &optlen)
      < 0)
    {
      return 0;
    }
  return timeout_ms;
#else
  (void)optlen;
  return 0;
#endif
}

/**
 * Socket_isconnected - Check if socket is connected
 * @socket: Socket to check
 * Returns: 1 if connected, 0 if not connected
 * Thread-safe: Yes (operates on single socket)
 * Note: Uses getpeername() to determine connection state.
 * For TCP sockets, checks if peer address is available.
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
  if (getpeername (SocketBase_fd (socket->base), (struct sockaddr *)&addr, &len) == 0)
    {
      /* Socket is connected - update cached peer info if not already set */
      if (socket->base->remoteaddr == NULL && SocketBase_arena (socket->base) != NULL)
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

/**
 * Socket_isbound - Check if socket is bound to an address
 * @socket: Socket to check
 * Returns: 1 if bound, 0 if not bound
 * Thread-safe: Yes (operates on single socket)
 * Note: Uses getsockname() to determine binding state.
 * A socket is bound if getsockname() succeeds and returns a valid address.
 * Wildcard addresses (0.0.0.0 or ::) still count as bound.
 */
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
  if (getsockname (SocketBase_fd (socket->base), (struct sockaddr *)&addr, &len) == 0)
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

/**
 * Socket_islistening - Check if socket is listening for connections
 * @socket: Socket to check
 * Returns: 1 if listening, 0 if not listening
 * Thread-safe: Yes (operates on single socket)
 * Note: Checks if socket is bound and not connected.
 * A socket is listening if it's bound but has no peer address.
 */
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
    if (getsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET, SO_ERROR, &error,
                    &error_len)
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

/**
 * handle_unix_bind_error - Handle Unix socket bind error
 * @path: Socket path
 */
static void
handle_unix_bind_error (const char *path)
{
  if (errno == EADDRINUSE)
    SOCKET_ERROR_FMT (SOCKET_EADDRINUSE ": %s", path);
  else if (errno == EACCES)
    SOCKET_ERROR_FMT ("Permission denied to bind to %s", path);
  else
    SOCKET_ERROR_FMT ("Failed to bind to Unix socket %s", path);
}

/**
 * perform_unix_bind - Perform Unix socket bind operation
 * @socket: Socket to bind
 * @addr: Address structure
 * @path: Path for error messages
 * Raises: Socket_Failed on failure
 */
static void
perform_unix_bind (T socket, const struct sockaddr_un *addr, const char *path)
{
  if (bind (SocketBase_fd (socket->base), (struct sockaddr *)addr, sizeof (*addr)) < 0)
    {
      handle_unix_bind_error (path);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

void
Socket_bind_unix (T socket, const char *path)
{
  struct sockaddr_un addr;

  assert (socket);
  assert (path);

  if (setup_unix_sockaddr (&addr, path) != 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  perform_unix_bind (socket, &addr, path);
  memcpy (&socket->base->remote_addr, &addr, sizeof (addr));
  socket->base->remote_addrlen = sizeof (addr);
  SocketCommon_update_local_endpoint (socket->base);
}

/**
 * handle_unix_connect_error - Handle Unix socket connect error
 * @path: Socket path
 */
static void
handle_unix_connect_error (const char *path)
{
  if (errno == ENOENT)
    SOCKET_ERROR_FMT ("Unix socket does not exist: %s", path);
  else if (errno == ECONNREFUSED)
    SOCKET_ERROR_FMT (SOCKET_ECONNREFUSED ": %s", path);
  else
    SOCKET_ERROR_FMT ("Failed to connect to Unix socket %s", path);
}

/**
 * perform_unix_connect - Perform Unix socket connect operation
 * @socket: Socket to connect
 * @addr: Address structure
 * @path: Path for error messages
 * Raises: Socket_Failed on failure
 */
static void
perform_unix_connect (T socket, const struct sockaddr_un *addr,
                      const char *path)
{
  if (connect (SocketBase_fd (socket->base), (struct sockaddr *)addr, sizeof (*addr)) < 0)
    {
      handle_unix_connect_error (path);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

void
Socket_connect_unix (T socket, const char *path)
{
  struct sockaddr_un addr;

  assert (socket);
  assert (path);

  if (setup_unix_sockaddr (&addr, path) != 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  perform_unix_connect (socket, &addr, path);
  memcpy (&socket->base->remote_addr, &addr, sizeof (addr));
  socket->base->remote_addrlen = sizeof (addr);
  SocketCommon_update_local_endpoint (socket->base);
}

int
Socket_getpeerpid (const T socket)
{
  assert (socket);

#ifdef SO_PEERCRED
  struct ucred cred;
  socklen_t len = sizeof (cred);

  if (getsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET, SOCKET_SO_PEERCRED, &cred,
                  &len)
      == 0)
    {
      return cred.pid;
    }
#endif

  return -1;
}

int
Socket_getpeeruid (const T socket)
{
  assert (socket);

#ifdef SO_PEERCRED
  struct ucred cred;
  socklen_t len = sizeof (cred);

  if (getsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET, SOCKET_SO_PEERCRED, &cred,
                  &len)
      == 0)
    {
      return cred.uid;
    }
#endif

  return -1;
}

int
Socket_getpeergid (const T socket)
{
  assert (socket);

#ifdef SO_PEERCRED
  struct ucred cred;
  socklen_t len = sizeof (cred);

  if (getsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET, SOCKET_SO_PEERCRED, &cred,
                  &len)
      == 0)
    {
      return cred.gid;
    }
#endif

  return -1;
}

SocketDNS_Request_T
Socket_bind_async (SocketDNS_T dns, T socket, const char *host, int port)
{
  struct addrinfo hints, *res = NULL;

  assert (dns);
  assert (socket);

  /* Validate port */
  if (!SOCKET_VALID_PORT (port))
    {
      SOCKET_ERROR_MSG (
          "Invalid port number: %d (must be 1-65535)",
          port);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Normalize wildcard addresses to NULL */
  if (host == NULL || strcmp (host, "0.0.0.0") == 0
      || strcmp (host, "::") == 0)
    {
      host = NULL;
    }

  /* For wildcard bind (NULL host), resolve synchronously and create completed
   * request */
  if (host == NULL)
    {
      setup_bind_hints (&hints);
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
      SocketDNS_request_settimeout (dns, req, socket->base->timeouts.dns_timeout_ms);
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

SocketDNS_Request_T
Socket_connect_async (SocketDNS_T dns, T socket, const char *host, int port)
{
  assert (dns);
  assert (socket);

  /* Validate host */
  if (host == NULL)
    {
      SOCKET_ERROR_MSG ("Invalid host: NULL pointer");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Validate port */
  if (!SOCKET_VALID_PORT (port))
    {
      SOCKET_ERROR_MSG (
          "Invalid port number: %d (must be 1-65535)",
          port);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Start async DNS resolution */
  {
    SocketDNS_Request_T req = SocketDNS_resolve (dns, host, port, NULL, NULL);
    if (socket->base->timeouts.dns_timeout_ms > 0)
      SocketDNS_request_settimeout (dns, req, socket->base->timeouts.dns_timeout_ms);
    return req;
  }
}

void
Socket_connect_async_cancel (SocketDNS_T dns, SocketDNS_Request_T req)
{
  assert (dns);

  if (req)
    SocketDNS_cancel (dns, req);
}

void
Socket_bind_with_addrinfo (T socket, struct addrinfo *res)
{
  int socket_family;

  assert (socket);
  assert (res);

  socket_family = get_socket_family (socket);

  if (SocketCommon_try_bind_resolved_addresses (socket->base, res, socket_family, Socket_Failed) == 0)
    {
      return;
    }

  handle_bind_error (NULL, 0);
  RAISE_MODULE_ERROR (Socket_Failed);
}

void
Socket_connect_with_addrinfo (T socket, struct addrinfo *res)
{
  int socket_family;

  assert (socket);
  assert (res);

  socket_family = get_socket_family (socket);

  if (try_connect_resolved_addresses (socket, res, socket_family,
                                      socket->base->timeouts.connect_timeout_ms)
      == 0)
    {
      SocketMetrics_increment (SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 1);
      setup_peer_info (socket, (struct sockaddr *)&socket->base->remote_addr,
                       socket->base->remote_addrlen);
      SocketEvent_emit_connect (SocketBase_fd (socket->base), socket->base->remoteaddr, socket->base->remoteport,
                                socket->base->localaddr, socket->base->localport);
      return;
    }

  handle_connect_error ("resolved", 0);
  RAISE_MODULE_ERROR (Socket_Failed);
}

#undef T

int
Socket_debug_live_count (void)
{
  int count;

  /* Thread-safe read of live socket count */
  pthread_mutex_lock (&socket_live_count_mutex);
  count = socket_live_count;
  pthread_mutex_unlock (&socket_live_count_mutex);

  return count;
}
