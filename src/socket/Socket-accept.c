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

/* Forward declarations for functions moved to other files */
static int accept_connection(T socket, struct sockaddr_storage *addr, socklen_t *addrlen);
static T create_accepted_socket(int newfd, const struct sockaddr_storage *addr, socklen_t addrlen);
static int setup_peer_info(T socket, const struct sockaddr *addr, socklen_t addrlen);

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

  TRY arena = Arena_new ();
  EXCEPT (Arena_Failed)
  {
    saved_errno = errno;
    SAFE_CLOSE (newfd);
    errno = saved_errno;
    SOCKET_ERROR_MSG (SOCKET_ENOMEM
                      ": Cannot allocate arena for accepted socket");
    RAISE_MODULE_ERROR (Socket_Failed);
  }
  END_TRY;

  newsocket
      = Arena_calloc (arena, 1, sizeof (struct Socket_T), __FILE__, __LINE__);
  if (!newsocket)
    {
      Arena_dispose (&arena);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM
                        ": Cannot allocate accepted socket structure");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  base = Arena_calloc (arena, 1, sizeof (struct SocketBase_T), __FILE__,
                       __LINE__);
  if (!base)
    {
      Arena_dispose (&arena);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM
                        ": Cannot allocate base for accepted socket");
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
      SOCKET_ERROR_MSG ("Failed to get SO_TYPE for accepted socket: %s",
                        strerror (saved_errno));
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Initialize base with inferred values */
  SocketCommon_init_base (base, newfd, domain, type_opt, protocol,
                          Socket_Failed);

  /* Set remote endpoint from accept addr */
  memcpy (&base->remote_addr, addr, addrlen);
  base->remote_addrlen = addrlen;

  /* Local endpoint already updated in init_base via update_local_endpoint */

  /* Reset cached strings/ports for remote (will be set in setup_peer_info
     * later) */
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
  newsocket->tls_timeouts = (SocketTimeouts_T){ 0 };
#endif

  socket_live_increment ();

  return newsocket;
}

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
