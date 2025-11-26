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
 * - Poll/wait helpers for non-blocking connect
 * - Socket error checking after async connect
 * - Blocking mode restoration
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include "dns/SocketDNS.h"
#include "socket/Socket-private.h"
#include "socket/Socket.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

#if SOCKET_CONNECT_HAPPY_EYEBALLS
#include "socket/SocketHappyEyeballs.h"
#endif

#define T Socket_T

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketConnect);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketConnect, e)

/* ==================== Internal Helpers ==================== */

/**
 * store_remote_addr - Store remote address in socket base
 * @socket: Socket instance
 * @addr: Address to store
 * @addrlen: Address length
 *
 * Consolidates duplicate memcpy pattern for remote endpoint storage.
 */
static void
store_remote_addr (T socket, const struct sockaddr *addr, socklen_t addrlen)
{
  memcpy (&socket->base->remote_addr, addr, addrlen);
  socket->base->remote_addrlen = addrlen;
}

/* ==================== Poll/Wait Helpers ==================== */

/**
 * socket_wait_poll_with_retry - Wait for socket writability with EINTR retry
 * @fd: File descriptor
 * @timeout_ms: Timeout in milliseconds
 *
 * Returns: poll() result (0 on timeout, >0 on ready, -1 on error)
 * Thread-safe: Yes (operates on single fd)
 */
static int
socket_wait_poll_with_retry (int fd, int timeout_ms)
{
  struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
  int result;

  while ((result = poll (&pfd, 1, timeout_ms)) < 0 && errno == EINTR)
    continue;

  return result;
}

/**
 * socket_check_connect_error - Check SO_ERROR after async connect
 * @fd: File descriptor
 *
 * Returns: 0 on success, -1 on error (sets errno)
 * Thread-safe: Yes (operates on single fd)
 */
static int
socket_check_connect_error (int fd)
{
  int error = 0;
  socklen_t error_len = sizeof (error);

  if (getsockopt (fd, SOCKET_SOL_SOCKET, SO_ERROR, &error, &error_len) < 0)
    return -1;

  if (error != 0)
    {
      errno = error;
      return -1;
    }

  return 0;
}

/**
 * socket_wait_for_connect - Wait for connect to complete with timeout
 * @socket: Socket instance
 * @timeout_ms: Timeout in milliseconds
 *
 * Returns: 0 on success, -1 on failure (sets errno)
 * Thread-safe: Yes (operates on single socket)
 */
static int
socket_wait_for_connect (T socket, int timeout_ms)
{
  assert (socket);
  assert (timeout_ms >= 0);

  int fd = SocketBase_fd (socket->base);
  int result = socket_wait_poll_with_retry (fd, timeout_ms);

  if (result < 0)
    return -1;

  if (result == 0)
    {
      errno = ETIMEDOUT;
      return -1;
    }

  return socket_check_connect_error (fd);
}

/**
 * socket_restore_blocking_mode - Restore socket blocking mode after operation
 * @socket: Socket instance
 * @original_flags: Original fcntl flags to restore
 * @operation: Operation name for logging
 *
 * Thread-safe: Yes (operates on single socket)
 */
static void
socket_restore_blocking_mode (T socket, int original_flags,
                              const char *operation)
{
  int fd = SocketBase_fd (socket->base);
  if (fcntl (fd, F_SETFL, original_flags) < 0)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, "SocketConnect",
                       "Failed to restore blocking mode after %s "
                       "(fd=%d, errno=%d): %s",
                       operation, fd, errno, strerror (errno));
    }
}

/**
 * socket_connect_with_poll_wait - Perform connect with timeout using poll
 * @socket: Socket instance
 * @addr: Address to connect to
 * @addrlen: Address length
 * @timeout_ms: Timeout in milliseconds
 *
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Yes (operates on single socket)
 */
static int
socket_connect_with_poll_wait (T socket, const struct sockaddr *addr,
                               socklen_t addrlen, int timeout_ms)
{
  if (connect (SocketBase_fd (socket->base), addr, addrlen) == 0
      || errno == EISCONN)
    {
      store_remote_addr (socket, addr, addrlen);
      return 0;
    }

  int saved_errno = errno;

  if (saved_errno == EINPROGRESS || saved_errno == EINTR)
    {
      if (socket_wait_for_connect (socket, timeout_ms) == 0)
        {
          store_remote_addr (socket, addr, addrlen);
          return 0;
        }
      saved_errno = errno;
    }

  errno = saved_errno;
  return -1;
}

/* ==================== Connect Error/Success Utilities ==================== */

/**
 * socket_get_connect_error_msg - Get error prefix for connect failure
 * @saved_errno: Saved errno value
 *
 * Returns: Error message prefix string
 * Thread-safe: Yes (stateless)
 */
static const char *
socket_get_connect_error_msg (int saved_errno)
{
  switch (saved_errno)
    {
    case ECONNREFUSED:
      return SOCKET_ECONNREFUSED;
    case ENETUNREACH:
      return SOCKET_ENETUNREACH;
    case ETIMEDOUT:
      return SOCKET_ETIMEDOUT;
    default:
      return "Connect failed";
    }
}

/**
 * socket_is_retriable_connect_error - Check if connect error is retriable
 * @saved_errno: Saved errno value
 *
 * Returns: 1 if error is retriable (caller should not raise), 0 otherwise
 * Thread-safe: Yes (stateless)
 */
static int
socket_is_retriable_connect_error (int saved_errno)
{
  return saved_errno == ECONNREFUSED || saved_errno == ETIMEDOUT
         || saved_errno == ENETUNREACH || saved_errno == EHOSTUNREACH
         || saved_errno == ECONNABORTED;
}

/**
 * socket_handle_connect_error - Handle and log connect error
 * @host: Hostname for error message
 * @port: Port number for error message
 *
 * Thread-safe: Yes (metrics are thread-safe)
 */
static void
socket_handle_connect_error (const char *host, int port)
{
  SocketMetrics_increment (SOCKET_METRIC_SOCKET_CONNECT_FAILURE, 1);
  SOCKET_ERROR_FMT ("%s: %.*s:%d", socket_get_connect_error_msg (errno),
                    SOCKET_ERROR_MAX_HOSTNAME, host, port);
}

/**
 * socket_cache_remote_endpoint - Cache remote endpoint information
 * @socket: Socket instance
 *
 * Caches remote address and port strings in arena. Sets defensive
 * NULL values on failure.
 * Thread-safe: No (operates on single socket)
 */
static void
socket_cache_remote_endpoint (T socket)
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
 * socket_emit_connect_event - Emit socket connect event
 * @socket: Socket instance
 *
 * Emits connect event with local and remote endpoint information.
 * Thread-safe: Yes (event system is thread-safe)
 */
static void
socket_emit_connect_event (T socket)
{
  SocketEvent_emit_connect (Socket_fd (socket),
                            SocketBase_remoteaddr (socket->base),
                            SocketBase_remoteport (socket->base),
                            SocketBase_localaddr (socket->base),
                            SocketBase_localport (socket->base));
}

/**
 * socket_handle_successful_connect - Handle successful connection
 * @socket: Socket instance
 *
 * Updates metrics, endpoints, and emits connect event.
 * Thread-safe: Yes (individual operations are thread-safe)
 */
static void
socket_handle_successful_connect (T socket)
{
  SocketMetrics_increment (SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 1);
  SocketCommon_update_local_endpoint (socket->base);
  socket_cache_remote_endpoint (socket);
  socket_emit_connect_event (socket);
}

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
      store_remote_addr (socket, addr, addrlen);
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
  int fd = SocketBase_fd (socket->base);
  *original_flags = fcntl (fd, F_GETFL);
  if (*original_flags < 0)
    return -1;

  if ((*original_flags & O_NONBLOCK) == 0)
    {
      if (fcntl (fd, F_SETFL, *original_flags | O_NONBLOCK) < 0)
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

/* ==================== Happy Eyeballs Integration ==================== */

#if SOCKET_CONNECT_HAPPY_EYEBALLS
/**
 * socket_is_hostname - Check if string is hostname (not IP address)
 * @host: Host string to check
 *
 * Returns: 1 if hostname, 0 if IP address
 */
static int
socket_is_hostname (const char *host)
{
  struct in_addr addr4;
  struct in6_addr addr6;

  /* Check IPv4 */
  if (inet_pton (AF_INET, host, &addr4) == 1)
    return 0;

  /* Check IPv6 */
  if (inet_pton (AF_INET6, host, &addr6) == 1)
    return 0;

  return 1;
}

/**
 * socket_connect_happy_eyeballs - Connect using Happy Eyeballs algorithm
 * @socket: Socket instance (REPLACED on success - old socket closed)
 * @host: Hostname to connect to
 * @port: Port number
 *
 * Returns: 1 if connected, 0 if should fall back to normal connect
 * Raises: Socket_Failed on connection failure
 *
 * NOTE: This function performs Happy Eyeballs connection racing which
 * requires creating new sockets. The original socket's fd is closed and
 * replaced with the winning connection's fd. Socket options set on the
 * original socket are NOT preserved.
 *
 * For applications that need to preserve socket options, use
 * SocketHappyEyeballs_connect() directly instead.
 */
static int
socket_connect_happy_eyeballs (T socket, const char *host, int port)
{
  Socket_T he_socket;
  SocketHE_Config_T config;
  int fd_new, fd_old;

  /* Only use Happy Eyeballs for hostnames, not IP addresses */
  if (!socket_is_hostname (host))
    return 0;

  /* Configure Happy Eyeballs with socket's timeout */
  SocketHappyEyeballs_config_defaults (&config);
  if (socket->base->timeouts.connect_timeout_ms > 0)
    config.total_timeout_ms = socket->base->timeouts.connect_timeout_ms;

  TRY { he_socket = SocketHappyEyeballs_connect (host, port, &config); }
  EXCEPT (SocketHE_Failed)
  {
    /* Happy Eyeballs failed - propagate as Socket_Failed */
    SOCKET_ERROR_MSG ("Happy Eyeballs connection failed to %s:%d", host, port);
    RAISE_MODULE_ERROR (Socket_Failed);
  }
  END_TRY;

  if (!he_socket)
    return 0;

  /* Close the original socket's fd */
  fd_old = socket->base->fd;
  if (fd_old >= 0)
    {
      close (fd_old);
    }

  /* Transfer the winning fd to our socket */
  fd_new = he_socket->base->fd;
  socket->base->fd = fd_new;

  /* Copy remote address info */
  memcpy (&socket->base->remote_addr, &he_socket->base->remote_addr,
          sizeof (socket->base->remote_addr));
  socket->base->remote_addrlen = he_socket->base->remote_addrlen;

  /* Prevent he_socket from closing the fd we just took */
  he_socket->base->fd = -1;
  Socket_free (&he_socket);

  socket_handle_successful_connect (socket);
  return 1;
}
#endif /* SOCKET_CONNECT_HAPPY_EYEBALLS */

/* ==================== Public Connect API ==================== */

void
Socket_connect (T socket, const char *host, int port)
{
  struct addrinfo *res = NULL;
  volatile T vsock = socket;
  int socket_family;

  connect_validate_params (socket, host, port);

#if SOCKET_CONNECT_HAPPY_EYEBALLS
  /* Try Happy Eyeballs for hostname connections */
  if (socket_connect_happy_eyeballs (socket, host, port))
    return;
#endif

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

/* ==================== Async Connect Operations ==================== */

/**
 * Socket_connect_async - Start async DNS resolution for connect
 * @dns: DNS resolver instance
 * @socket: Socket to connect
 * @host: Hostname to resolve
 * @port: Port number
 *
 * Returns: DNS request handle for completion tracking
 * Raises: Socket_Failed on invalid parameters
 *
 * Caller should wait for DNS completion then call Socket_connect_with_addrinfo
 */
SocketDNS_Request_T
Socket_connect_async (SocketDNS_T dns, T socket, const char *host, int port)
{
  SocketDNS_Request_T req;

  assert (dns);
  assert (socket);

  /* Use common validation functions for consistent error handling */
  SocketCommon_validate_host_not_null (host, Socket_Failed);
  SocketCommon_validate_port (port, Socket_Failed);

  req = SocketDNS_resolve (dns, host, port, NULL, NULL);
  if (socket->base->timeouts.dns_timeout_ms > 0)
    SocketDNS_request_settimeout (dns, req,
                                  socket->base->timeouts.dns_timeout_ms);
  return req;
}

/**
 * Socket_connect_async_cancel - Cancel async DNS resolution
 * @dns: DNS resolver instance
 * @req: Request to cancel
 */
void
Socket_connect_async_cancel (SocketDNS_T dns, SocketDNS_Request_T req)
{
  assert (dns);

  if (req)
    SocketDNS_cancel (dns, req);
}

#undef T
