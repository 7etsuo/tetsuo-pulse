/**
 * Socket-connect.c - Socket connect operations
 *
 * Implements all socket connection operations including TCP and Unix domain
 * sockets. Provides synchronous and asynchronous connection with proper
 * timeout handling and address resolution.
 *
 * Features:
 * - Address resolution and validation
 * - Non-blocking connect with timeout
 * - Platform-specific connection logic
 * - Async DNS resolution integration
 * - Error classification and graceful handling
 * - Timeout support for DNS and connection operations
 */

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <assert.h>

#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "dns/SocketDNS.h"
#include "socket/Socket.h"
#include "core/SocketMetrics.h"
#include "socket/Socket-private.h"
#include "socket/SocketCommon.h"
#include "core/SocketEvents.h"

#define T Socket_T

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketConnect);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketConnect, e)

/* Forward declarations for functions moved to other files */

/* Forward declaration for socket_wait_for_connect */
static int socket_wait_for_connect (T socket, int timeout_ms);

/**
 * restore_blocking_mode - Restore socket blocking mode after operation
 * @socket: Socket instance
 * @original_flags: Original fcntl flags
 * @operation: Operation name for logging
 * Thread-safe: Yes (operates on single socket)
 */
static void
restore_blocking_mode (T socket, int original_flags, const char *operation)
{
  if (fcntl (SocketBase_fd (socket->base), F_SETFL, original_flags) < 0)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Failed to restore blocking mode after %s "
                       "(fd=%d, errno=%d): %s",
                       operation, SocketBase_fd (socket->base), errno,
                       strerror (errno));
    }
}

/**
 * connect_with_poll_wait - Perform connect with timeout using poll
 * @socket: Socket instance
 * @addr: Address to connect to
 * @addrlen: Address length
 * @timeout_ms: Timeout in milliseconds
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Yes (operates on single socket)
 */
static int
connect_with_poll_wait (T socket, const struct sockaddr *addr,
                       socklen_t addrlen, int timeout_ms)
{
  if (connect (SocketBase_fd (socket->base), addr, addrlen) == 0
      || errno == EISCONN)
    {
      memcpy (&socket->base->remote_addr, addr, addrlen);
      socket->base->remote_addrlen = addrlen;
      return 0;
    }

  int saved_errno = errno;

  if (saved_errno == EINPROGRESS || saved_errno == EINTR)
    {
      if (socket_wait_for_connect (socket, timeout_ms) == 0)
        {
          memcpy (&socket->base->remote_addr, addr, addrlen);
          socket->base->remote_addrlen = addrlen;
          return 0;
        }
      saved_errno = errno;
    }

  errno = saved_errno;
  return -1;
}

/* ==================== Connect Setup ==================== */

static void
setup_connect_hints (struct addrinfo *hints)
{
  SocketCommon_setup_hints (hints, SOCKET_STREAM_TYPE, 0);
}

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

  if (getsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET, SO_ERROR,
                  &error, &error_len)
      < 0)
    return -1;

  if (error != 0)
    {
      errno = error;
      return -1;
    }

  return 0;
}

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

/* ==================== Connect Success Handling ==================== */

/**
 * cache_remote_endpoint - Cache remote endpoint information
 * @socket: Socket instance
 *
 * Caches remote address and port strings in arena. Sets defensive
 * NULL values on failure.
 * Thread-safe: No (operates on single socket)
 */
static void
cache_remote_endpoint (T socket)
{
  if (SocketCommon_cache_endpoint (
          SocketBase_arena (socket->base),
          (struct sockaddr *)&socket->base->remote_addr,
          socket->base->remote_addrlen, &socket->base->remoteaddr,
          &socket->base->remoteport)
      != 0)
    {
      socket->base->remoteaddr = NULL;
      socket->base->remoteport = 0;
    }
}

/**
 * emit_connect_event - Emit socket connect event
 * @socket: Socket instance
 *
 * Emits connect event with local and remote endpoint information.
 * Thread-safe: Yes (event system is thread-safe)
 */
static void
emit_connect_event (T socket)
{
  SocketEvent_emit_connect (Socket_fd (socket),
                            SocketBase_remoteaddr (socket->base),
                            SocketBase_remoteport (socket->base),
                            SocketBase_localaddr (socket->base),
                            SocketBase_localport (socket->base));
}

/**
 * handle_successful_connect - Handle successful connection
 * @socket: Socket instance
 *
 * Updates metrics, endpoints, and emits connect event.
 * Thread-safe: Yes (individual operations are thread-safe)
 */
static void
handle_successful_connect (T socket)
{
  SocketMetrics_increment (SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 1);
  SocketCommon_update_local_endpoint (socket->base);
  cache_remote_endpoint (socket);
  emit_connect_event (socket);
}

/**
 * is_retriable_connect_error - Check if connect error is retriable
 * @saved_errno: Saved errno value
 *
 * Returns: 1 if error is retriable (caller should not raise), 0 otherwise
 */
static int
is_retriable_connect_error (int saved_errno)
{
  return saved_errno == ECONNREFUSED || saved_errno == ETIMEDOUT
         || saved_errno == ENETUNREACH || saved_errno == EHOSTUNREACH
         || saved_errno == ECONNABORTED;
}

/* ==================== Connect Operations ==================== */

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

static int
connect_wait_completion (T socket, const struct sockaddr *addr,
                        socklen_t addrlen, int timeout_ms, int original_flags)
{
  int restore_blocking = (original_flags & O_NONBLOCK) == 0;
  int result = connect_with_poll_wait (socket, addr, addrlen, timeout_ms);

  if (result == 0 && restore_blocking)
    {
      restore_blocking_mode (socket, original_flags, "connect");
    }
  else if (result != 0 && restore_blocking)
    {
      restore_blocking_mode (socket, original_flags, "connect failure");
    }

  return result;
}

static int
try_connect_address (T socket, const struct sockaddr *addr, socklen_t addrlen,
                     int timeout_ms)
{
  assert (socket);
  assert (addr);

  if (timeout_ms <= 0)
    {
      return connect_attempt_immediate (socket, addr, addrlen);
    }

  int original_flags;
  if (connect_setup_nonblock (socket, &original_flags) < 0)
    return -1;

  return connect_wait_completion (socket, addr, addrlen, timeout_ms,
                                 original_flags);
}

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

/**
 * connect_resolve_address - Resolve hostname for connection
 * @sock: Socket instance (volatile-safe)
 * @host: Hostname to resolve
 * @port: Port number
 * @res: Output for resolved addresses
 *
 * Sets errno to EAI_FAIL on resolution failure without raising.
 */
static void
connect_resolve_address (T sock, const char *host, int port,
                         struct addrinfo **res)
{
  int socket_family = SocketCommon_get_socket_family (sock->base);

  if (SocketCommon_resolve_address (host, port, NULL, res, Socket_Failed,
                                    socket_family, 0)
      != 0)
    {
      errno = EAI_FAIL;
      return;
    }
}

/**
 * connect_try_addresses - Attempt connection to resolved addresses
 * @sock: Socket instance (volatile-safe)
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
      handle_successful_connect (sock);
      return;
    }

  int saved_errno = errno;
  if (is_retriable_connect_error (saved_errno))
    {
      errno = saved_errno;
      return;
    }

  handle_connect_error ("resolved", 0);
  RAISE_MODULE_ERROR (Socket_Failed);
}

void
Socket_connect (T socket, const char *host, int port)
{
  struct addrinfo hints, *res = NULL;
  int socket_family;
  volatile T vsock = socket; /* Preserve across exception boundaries */

  assert (socket);
  assert (host);

  SocketCommon_validate_host_not_null (host, Socket_Failed);
  SocketCommon_validate_port (port, Socket_Failed);
  setup_connect_hints (&hints);

  TRY
  {
    connect_resolve_address ((T)vsock, host, port, &res);
    if (!res)
      {
        errno = EAI_FAIL;
        return;
      }

    socket_family = SocketCommon_get_socket_family (((T)vsock)->base);
    connect_try_addresses ((T)vsock, res, socket_family,
                           ((T)vsock)->base->timeouts.connect_timeout_ms);

    freeaddrinfo (res);
  }
  EXCEPT (Socket_Failed)
  {
    int saved_errno = errno;
    freeaddrinfo (res);
    if (is_retriable_connect_error (saved_errno))
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
      handle_successful_connect (socket);
      return;
    }

  handle_connect_error ("resolved", 0);
  RAISE_MODULE_ERROR (Socket_Failed);
}

/* ==================== Async Connect Operations ==================== */

#undef T
