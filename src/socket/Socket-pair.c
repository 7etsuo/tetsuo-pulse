/**
 * Socket-pair.c - Socket pair and peer credential operations
 *
 * Implements Unix domain socket pair creation and peer credential access
 * functions. Provides secure IPC mechanisms with proper credential checking
 * and socket pair initialization.
 *
 * Features:
 * - Unix domain socket pair creation (SOCK_STREAM/SOCK_DGRAM)
 * - Automatic close-on-exec flag setting
 * - Peer process ID, user ID, and group ID access
 * - Thread-safe credential retrieval
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

int
Socket_getpeerpid (const Socket_T socket)
{
  assert (socket);

#ifdef SO_PEERCRED
  struct ucred cred;
  socklen_t len = sizeof (cred);

  if (getsockopt (SocketBase_fd (socket->base), SOL_SOCKET,
                  SO_PEERCRED, &cred, &len)
      == 0)
    {
      return cred.pid;
    }
#endif

  return -1;
}

int
Socket_getpeeruid (const Socket_T socket)
{
  assert (socket);

#ifdef SO_PEERCRED
  struct ucred cred;
  socklen_t len = sizeof (cred);

  if (getsockopt (SocketBase_fd (socket->base), SOL_SOCKET,
                  SO_PEERCRED, &cred, &len)
      == 0)
    {
      return cred.uid;
    }
#endif

  return -1;
}

int
Socket_getpeergid (const Socket_T socket)
{
  assert (socket);

#ifdef SO_PEERCRED
  struct ucred cred;
  socklen_t len = sizeof (cred);

  if (getsockopt (SocketBase_fd (socket->base), SOL_SOCKET,
                  SO_PEERCRED, &cred, &len)
      == 0)
    {
      return cred.gid;
    }
#endif

  return -1;
}

#undef T
