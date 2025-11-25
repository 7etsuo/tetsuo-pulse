/**
 * Socket-accept.c - Socket accept operations
 *
 * Implements socket accept operations including connection acceptance,
 * accepted socket creation, peer information setup, and event emission.
 * Provides the core server-side connection handling functionality.
 *
 * Features:
 * - Connection acceptance with close-on-exec flag setting
 * - Accepted socket structure creation with proper initialization
 * - Peer endpoint information caching and setup
 * - Local endpoint updates for accepted connections
 * - Event emission for connection acceptance
 * - Memory management using Arena allocation
 */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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


/* Thread-local exception for detailed error messages.
 * Prevents race conditions when multiple threads raise same exception. */
/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(Socket);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(Socket, e)

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
      if (errno == EAGAIN || errno == EWOULDBLOCK)
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

#undef T
