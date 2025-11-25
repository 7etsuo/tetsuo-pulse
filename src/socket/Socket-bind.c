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
#ifdef _WIN32
static __declspec (thread) Except_T SocketBind_DetailedException;
#else
static __thread Except_T SocketBind_DetailedException;
#endif

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e)                                                 \
  do                                                                          \
    {                                                                         \
      SocketBind_DetailedException = (e);                                    \
      SocketBind_DetailedException.reason = socket_error_buf;                \
      RAISE (SocketBind_DetailedException);                                  \
    }                                                                         \
  while (0)

/* ==================== Validation ==================== */

static void
validate_port_number (int port)
{
  SocketCommon_validate_port (port, Socket_Failed);
}

/* ==================== Bind Setup ==================== */

static void
setup_bind_hints (struct addrinfo *hints)
{
  SocketCommon_setup_hints (hints, SOCKET_STREAM_TYPE, SOCKET_AI_PASSIVE);
}

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

static void
bind_resolve_address (T socket, const char *host, int port,
                     struct addrinfo **res, volatile Socket_T *volatile_socket)
{
  (void)socket; /* Suppress unused parameter warning */
  int socket_family = SocketCommon_get_socket_family ((*volatile_socket)->base);

  if (SocketCommon_resolve_address (host, port, NULL, res, Socket_Failed,
                                    socket_family, 0)
      != 0)
    {
      errno = EAI_FAIL;
      return;
    }
}

static void
bind_try_addresses (T socket, struct addrinfo *res, int socket_family,
                   volatile Socket_T *volatile_socket)
{
  (void)socket; /* Suppress unused parameter warning */
  int bind_result
      = SocketCommon_try_bind_resolved_addresses ((*volatile_socket)->base, res,
                                                 socket_family, Socket_Failed);
  if (bind_result == 0)
    {
      SocketCommon_update_local_endpoint ((*volatile_socket)->base);
      return;
    }

  /* If bind failed, check errno for common errors before raising */
  int saved_errno = errno;
  if (is_common_bind_error (saved_errno))
    {
      errno = saved_errno; /* Restore errno for caller */
      return;              /* Graceful failure - caller checks errno */
    }

  handle_bind_error (NULL, 0);
  RAISE_MODULE_ERROR (Socket_Failed);
}

void
Socket_bind (T socket, const char *host, int port)
{
  struct addrinfo hints, *res = NULL;
  int socket_family;
  volatile Socket_T volatile_socket
      = socket; /* Preserve across exception boundaries */

  assert (socket);

  validate_port_number (port);
  host = SocketCommon_normalize_wildcard_host (host);
  setup_bind_hints (&hints);

  TRY
  {
    bind_resolve_address (socket, host, port, &res, &volatile_socket);
    if (!res)
      return; /* Resolution failed */

    socket_family = SocketCommon_get_socket_family (((Socket_T)volatile_socket)->base);
    bind_try_addresses (socket, res, socket_family, &volatile_socket);

    freeaddrinfo (res);
  }
  EXCEPT (Socket_Failed)
  {
    // Preserve errno before freeaddrinfo() may modify it
    int saved_errno = errno;
    freeaddrinfo (res);
    // Check errno and return gracefully for common bind errors
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

  /* Validate port */
  if (!SOCKET_VALID_PORT (port))
    {
      SOCKET_ERROR_MSG ("Invalid port number: %d (must be 1-65535)", port);
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
