/**
 * Socket-connect-async.c - Asynchronous connect operations with DNS resolution
 *
 * Implements asynchronous connect operations that use DNS resolution for
 * hostname to IP address conversion. Provides non-blocking connection
 * establishment with timeout support and cancellation.
 *
 * Features:
 * - Asynchronous DNS resolution for hostnames
 * - Non-blocking connect with timeout support
 * - Connection cancellation
 * - Integration with SocketDNS for resolution
 * - Proper error handling and cleanup
 */

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "dns/SocketDNS.h"
#include "socket/Socket.h"
#include "socket/Socket-private.h"

#define T Socket_T

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketConnect);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketConnect, e)

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
      SOCKET_ERROR_MSG ("Invalid port number: %d (must be 1-65535)", port);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Start async DNS resolution */
  {
    SocketDNS_Request_T req = SocketDNS_resolve (dns, host, port, NULL, NULL);
    if (socket->base->timeouts.dns_timeout_ms > 0)
      SocketDNS_request_settimeout (dns, req,
                                    socket->base->timeouts.dns_timeout_ms);
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

#undef T