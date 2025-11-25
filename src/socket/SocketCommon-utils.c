/**
 * SocketCommon-utils.c - Small utility functions for address resolution
 *
 * Contains small helper functions extracted from SocketCommon-resolve.c
 * to keep individual files under 400 lines.
 */

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#define SOCKET_LOG_COMPONENT "SocketCommon"
#include "core/SocketError.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketCommon);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketCommon, e)

/**
 * socketcommon_get_safe_host - Get safe hostname string for display
 * @host: Hostname string or NULL
 * Returns: Host string or "any" if NULL
 * Thread-safe: Yes
 */
const char *
socketcommon_get_safe_host (const char *host)
{
  return host ? host : "any";
}

/**
 * socketcommon_duplicate_address - Duplicate address string to arena
 * @arena: Arena for allocation
 * @addr_str: Address string to duplicate
 * Returns: Duplicated string or NULL on failure
 * Thread-safe: Yes (arena operations)
 */
static char *
socketcommon_duplicate_address (Arena_T arena, const char *addr_str)
{
  size_t addr_len;
  char *copy = NULL;

  assert (arena);
  assert (addr_str);

  addr_len = strlen (addr_str) + 1;
  copy = ALLOC (arena, addr_len);
  if (!copy)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate address buffer");
      return NULL;
    }
  memcpy (copy, addr_str, addr_len);
  return copy;
}

/**
 * socketcommon_parse_port_string - Parse port string to integer
 * @serv: Port string to parse
 * Returns: Port number or 0 on failure
 * Thread-safe: Yes
 */
static int
socketcommon_parse_port_string (const char *serv)
{
  char *endptr = NULL;
  long port_long = 0;

  assert (serv);

  errno = 0;
  port_long = strtol (serv, &endptr, 10);
  if (errno == 0 && endptr != serv && *endptr == '\0' && port_long >= 0
      && port_long <= SOCKET_MAX_PORT)
    return (int)port_long;
  return 0;
}

/**
 * socketcommon_convert_port_to_string - Convert port integer to string
 * @port: Port number
 * @port_str: Output buffer
 * @bufsize: Buffer size
 * Thread-safe: Yes
 */
void
socketcommon_convert_port_to_string (int port, char *port_str, size_t bufsize)
{
  int result;

  result = snprintf (port_str, bufsize, "%d", port);
  assert (result > 0 && result < (int)bufsize);
}

/**
 * SocketCommon_validate_hostname - Validate hostname length
 * @host: Hostname to validate
 * @exception_type: Exception type to raise on invalid hostname
 * Raises: Specified exception type if hostname is too long
 * Thread-safe: Yes
 */
void
SocketCommon_validate_hostname (const char *host, Except_T exception_type)
{
  if (socketcommon_validate_hostname_internal (host, 1, exception_type) != 0)
    return; /* Exception already raised */
}

/**
 * SocketCommon_cache_endpoint - Cache endpoint address and port from sockaddr
 * @arena: Arena for string allocation
 * @addr: Socket address to cache
 * @addrlen: Length of address
 * @addr_out: Output pointer for address string
 * @port_out: Output pointer for port number
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Yes (arena operations are thread-safe)
 */
int
SocketCommon_cache_endpoint (Arena_T arena, const struct sockaddr *addr,
                           socklen_t addrlen, char **addr_out, int *port_out)
{
  char host[SOCKET_NI_MAXHOST];
  char serv[SOCKET_NI_MAXSERV];
  char *copy = NULL;
  int result;

  assert (arena);
  assert (addr);
  assert (addr_out);
  assert (port_out);

  result
      = getnameinfo (addr, addrlen, host, sizeof (host), serv, sizeof (serv),
                     SOCKET_NI_NUMERICHOST | SOCKET_NI_NUMERICSERV);
  if (result != 0)
    {
      SOCKET_ERROR_MSG ("Failed to format socket address: %s",
                        gai_strerror (result));
      return -1;
    }

  copy = socketcommon_duplicate_address (arena, host);
  if (!copy)
    return -1;

  *addr_out = copy;
  *port_out = socketcommon_parse_port_string (serv);
  return 0;
}
