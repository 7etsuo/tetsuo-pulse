/**
 * Socket-bind.c - Socket bind operations
 *
 * Implements all socket binding operations including TCP, UDP, and Unix domain
 * sockets. Provides synchronous and asynchronous binding with proper error
 * handling and address resolution.
 *
 * Features:
 * - Address resolution and validation
 * - Platform-specific binding logic
 * - Async DNS resolution integration
 * - Error classification and graceful handling
 * - Timeout support for DNS operations
 */

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <assert.h>

#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "dns/SocketDNS.h"
#include "socket/Socket.h"
#include "core/SocketMetrics.h"
#include "socket/Socket-private.h"
#include "socket/SocketCommon.h"

#define T Socket_T

/* Thread-local exception for detailed error messages */
/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketBind);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketBind, e)

/* Bind setup uses SocketCommon_validate_port and SocketCommon_setup_hints directly */

static int
is_common_bind_error (int err)
{
  return err == EADDRINUSE || err == EACCES || err == EADDRNOTAVAIL
         || err == EAFNOSUPPORT;
}

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

  handle_bind_error (NULL, 0);
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

  handle_bind_error (NULL, 0);
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

#undef T
