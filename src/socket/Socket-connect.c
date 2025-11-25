/**
 * Socket-connect.c - Socket connect operations
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements all socket connection operations including TCP and Unix domain
 * sockets. Provides synchronous connection with proper timeout handling and
 * address resolution.
 *
 * Features:
 * - Address resolution and validation
 * - Non-blocking connect with timeout
 * - Async DNS resolution integration
 * - Error classification and graceful handling
 * - Timeout support for DNS and connection operations
 *
 * Note: Poll/wait helpers are in Socket-connect-poll.c
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "core/SocketEvents.h"
#include "core/SocketMetrics.h"
#include "dns/SocketDNS.h"
#include "socket/Socket-private.h"
#include "socket/Socket.h"
#include "socket/SocketCommon.h"

#define T Socket_T

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketConnect);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketConnect, e)

/* Forward declarations for poll helpers (in Socket-connect-poll.c) */
extern int socket_wait_for_connect (T socket, int timeout_ms);
extern void socket_restore_blocking_mode (T socket, int original_flags,
                                          const char *operation);
extern int socket_connect_with_poll_wait (T socket, const struct sockaddr *addr,
                                          socklen_t addrlen, int timeout_ms);

/* Forward declarations for utility functions (in Socket-connect-util.c) */
extern const char *socket_get_connect_error_msg (int saved_errno);
extern void socket_handle_connect_error (const char *host, int port);
extern int socket_is_retriable_connect_error (int saved_errno);
extern void socket_cache_remote_endpoint (T socket);
extern void socket_emit_connect_event (T socket);
extern void socket_handle_successful_connect (T socket);

/* ==================== Connect Operations ==================== */

/**
 * connect_attempt_immediate - Attempt immediate connect without waiting
 * @socket: Socket instance
 * @addr: Address to connect to
 * @addrlen: Address length
 *
 * Returns: 0 on success, -1 if connect in progress or failed
 */
static int
connect_attempt_immediate (T socket, const struct sockaddr *addr,
                           socklen_t addrlen)
{
  if (connect (SocketBase_fd (socket->base), addr, addrlen) == 0
      || errno == EINPROGRESS || errno == EISCONN)
    {
      memcpy (&socket->base->remote_addr, addr, addrlen);
      socket->base->remote_addrlen = addrlen;
      return 0;
    }
  return -1;
}

/**
 * connect_setup_nonblock - Set socket to non-blocking mode for connect
 * @socket: Socket instance
 * @original_flags: Output for original fcntl flags
 *
 * Returns: 0 on success, -1 on failure
 */
static int
connect_setup_nonblock (T socket, int *original_flags)
{
  *original_flags = fcntl (SocketBase_fd (socket->base), F_GETFL);
  if (*original_flags < 0)
    return -1;

  if ((*original_flags & O_NONBLOCK) == 0)
    {
      if (fcntl (SocketBase_fd (socket->base), F_SETFL,
                 *original_flags | O_NONBLOCK)
          < 0)
        return -1;
    }
  return 0;
}

/**
 * connect_wait_completion - Wait for connect to complete and restore mode
 * @socket: Socket instance
 * @addr: Address being connected to
 * @addrlen: Address length
 * @timeout_ms: Timeout in milliseconds
 * @original_flags: Original fcntl flags for restoration
 *
 * Returns: 0 on success, -1 on failure
 */
static int
connect_wait_completion (T socket, const struct sockaddr *addr,
                         socklen_t addrlen, int timeout_ms, int original_flags)
{
  int restore_blocking = (original_flags & O_NONBLOCK) == 0;
  int result
      = socket_connect_with_poll_wait (socket, addr, addrlen, timeout_ms);

  if (restore_blocking)
    socket_restore_blocking_mode (socket, original_flags,
                                  result == 0 ? "connect" : "connect failure");

  return result;
}

/**
 * try_connect_address - Try connecting to a single address
 * @socket: Socket instance
 * @addr: Address to connect to
 * @addrlen: Address length
 * @timeout_ms: Timeout in milliseconds
 *
 * Returns: 0 on success, -1 on failure
 */
static int
try_connect_address (T socket, const struct sockaddr *addr, socklen_t addrlen,
                     int timeout_ms)
{
  assert (socket);
  assert (addr);

  if (timeout_ms <= 0)
    return connect_attempt_immediate (socket, addr, addrlen);

  int original_flags;
  if (connect_setup_nonblock (socket, &original_flags) < 0)
    return -1;

  return connect_wait_completion (socket, addr, addrlen, timeout_ms,
                                  original_flags);
}

/**
 * try_connect_resolved_addresses - Try connecting to resolved address list
 * @socket: Socket instance
 * @res: Resolved address list
 * @socket_family: Socket address family
 * @timeout_ms: Connection timeout in milliseconds
 *
 * Returns: 0 on success, -1 on failure (sets errno)
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

/* ==================== Connect Resolution ==================== */

/**
 * connect_resolve_address - Resolve hostname for connection
 * @sock: Socket instance
 * @host: Hostname to resolve
 * @port: Port number
 * @socket_family: Socket address family
 * @res: Output for resolved addresses
 *
 * Sets errno to EAI_FAIL on resolution failure without raising.
 */
static void
connect_resolve_address (T sock, const char *host, int port, int socket_family,
                         struct addrinfo **res)
{
  (void)sock; /* Used for consistency, family passed in */
  if (SocketCommon_resolve_address (host, port, NULL, res, Socket_Failed,
                                    socket_family, 0)
      != 0)
    errno = EAI_FAIL;
}

/**
 * connect_try_addresses - Attempt connection to resolved addresses
 * @sock: Socket instance
 * @res: Resolved address list
 * @socket_family: Socket address family
 * @timeout_ms: Connection timeout in milliseconds
 *
 * Raises: Socket_Failed on non-retriable errors
 */
static void
connect_try_addresses (T sock, struct addrinfo *res, int socket_family,
                       int timeout_ms)
{
  if (try_connect_resolved_addresses (sock, res, socket_family, timeout_ms)
      == 0)
    {
      socket_handle_successful_connect (sock);
      return;
    }

  int saved_errno = errno;
  if (socket_is_retriable_connect_error (saved_errno))
    {
      errno = saved_errno;
      return;
    }

  socket_handle_connect_error ("resolved", 0);
  RAISE_MODULE_ERROR (Socket_Failed);
}

/**
 * connect_validate_params - Validate connection parameters
 * @socket: Socket instance
 * @host: Hostname
 * @port: Port number
 */
static void
connect_validate_params (T socket, const char *host, int port)
{
  assert (socket);
  assert (host);
  SocketCommon_validate_host_not_null (host, Socket_Failed);
  SocketCommon_validate_port (port, Socket_Failed);
}

/**
 * connect_execute - Execute connection attempt
 * @sock: Socket instance
 * @res: Resolved address info
 * @socket_family: Socket address family
 */
static void
connect_execute (T sock, struct addrinfo *res, int socket_family)
{
  int timeout_ms = sock->base->timeouts.connect_timeout_ms;
  connect_try_addresses (sock, res, socket_family, timeout_ms);
}

/* ==================== Public Connect API ==================== */

void
Socket_connect (T socket, const char *host, int port)
{
  struct addrinfo *res = NULL;
  volatile T vsock = socket;
  int socket_family;

  connect_validate_params (socket, host, port);
  socket_family = SocketCommon_get_socket_family (socket->base);

  TRY
  {
    connect_resolve_address ((T)vsock, host, port, socket_family, &res);
    if (!res)
      {
        errno = EAI_FAIL;
        return;
      }
    connect_execute ((T)vsock, res, socket_family);
    freeaddrinfo (res);
  }
  EXCEPT (Socket_Failed)
  {
    int saved_errno = errno;
    freeaddrinfo (res);
    if (socket_is_retriable_connect_error (saved_errno))
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
Socket_connect_with_addrinfo (T socket, struct addrinfo *res)
{
  int socket_family;

  assert (socket);
  assert (res);

  socket_family = SocketCommon_get_socket_family (socket->base);

  if (try_connect_resolved_addresses (
          socket, res, socket_family,
          socket->base->timeouts.connect_timeout_ms)
      == 0)
    {
      socket_handle_successful_connect (socket);
      return;
    }

  socket_handle_connect_error ("resolved", 0);
  RAISE_MODULE_ERROR (Socket_Failed);
}

#undef T
