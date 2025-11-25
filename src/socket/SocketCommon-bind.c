/**
 * SocketCommon-bind.c - Bind operation helpers
 *
 * Contains bind-related operations and error handling
 * extracted from the main SocketCommon.c file.
 */

#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <assert.h>

#include "core/SocketConfig.h"
#define SOCKET_LOG_COMPONENT "SocketCommon"
#include "core/SocketError.h"
#include "core/SocketLog.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

/* Forward declarations for exception types */
extern const Except_T Socket_Failed;
extern const Except_T SocketDgram_Failed;

/* Thread-local exception for detailed error messages */
/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketCommon);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketCommon, e)

/**
 * SocketCommon_try_bind_address - Try bind to single address
 * (extracted/unified from Socket.c/Dgram.c)
 * @base: Base with fd (sets local endpoint on success)
 * @addr: Addr to bind
 * @addrlen: Len
 * @exc_type: Raise on fail
 * Returns: 0 success, -1 fail (raises fatal errors)
 * Caller should set SO_REUSEADDR before if needed
 */
int
SocketCommon_try_bind_address (SocketBase_T base, const struct sockaddr *addr,
                               socklen_t addrlen, Except_T exc_type)
{
  int fd = SocketBase_fd (base);
  int ret = bind (fd, addr, addrlen);
  if (ret == 0)
    {
      SocketCommon_update_local_endpoint (
          base); /* Update cached local addr/port */
      return 0;
    }

  /* Use handle for graceful */
  SocketCommon_handle_bind_error (errno, "unknown addr", exc_type);
  return -1;
}

/**
 * SocketCommon_try_bind_resolved_addresses - Try bind to list of addresses
 * from resolve
 * @base: Base with fd
 * @res: addrinfo list (caller frees)
 * @family: Preferred family or AF_UNSPEC
 * @exc_type: Raise on all fails
 * Returns: 0 success (bound to first viable), -1 all fail (raises)
 * Sets SO_REUSEADDR true before loop, updates local endpoint on success
 * Handles dual-stack, skips incompatible family
 * Type-specific: For stream calls listen after bind if needed (caller)
 */
int
SocketCommon_try_bind_resolved_addresses (SocketBase_T base,
                                          struct addrinfo *res, int family,
                                          Except_T exc_type)
{
  struct addrinfo *rp;

  /* Set SO_REUSEADDR for bind retries */
  SocketCommon_set_option_int (base, SOL_SOCKET, SO_REUSEADDR, 1, exc_type);

  for (rp = res; rp != NULL; rp = rp->ai_next)
    {
      if (family != AF_UNSPEC && rp->ai_family != family)
        continue; /* Skip incompatible */

      if (SocketCommon_try_bind_address (base, rp->ai_addr, rp->ai_addrlen,
                                         exc_type)
          == 0)
        {
          /* Caller owns res and MUST freeaddrinfo after call, success or
           * fail */
          return 0;
        }
    }

  SOCKET_ERROR_MSG ("Bind failed for all resolved addresses");
  RAISE_MODULE_ERROR (exc_type);
  return -1;
}

/**
 * SocketCommon_handle_bind_error - Handle bind errno (graceful for
 * non-fatal)
 * @err: errno from bind
 * @addr_str: Human addr for log
 * @exc_type: Raise for fatal
 * Returns: -1 non-fatal (log warn), raises fatal
 * Non-fatal: EADDRINUSE, EADDRNOTAVAIL, etc. - log, return -1 for retry
 */
int
SocketCommon_handle_bind_error (int err, const char *addr_str,
                                Except_T exc_type)
{
  if (err == EADDRINUSE)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Address %s already in use - retry later?", addr_str);
      return -1;
    }
  else if (err == EADDRNOTAVAIL)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, SOCKET_LOG_COMPONENT,
                       "Address %s not available on local machine", addr_str);
      return -1;
    }
  else if (err == EACCES || err == EPERM)
    {
      SOCKET_ERROR_FMT ("Permission denied binding %s (cap_net_bind_service?)",
                        addr_str);
      RAISE_MODULE_ERROR (exc_type);
    }
  else
    {
      SOCKET_ERROR_FMT ("Unexpected bind error for %s: %s", addr_str,
                        strerror (err));
      RAISE_MODULE_ERROR (exc_type);
    }
  return -1; /* Unreachable */
}
