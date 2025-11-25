/**
 * SocketCommon-validate.c - Validation and IP utilities
 *
 * Contains validation functions, IP parsing, and CIDR operations
 * extracted from the main SocketCommon.c file.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

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
 * SocketCommon_validate_port - Validate port number is in valid range
 * @port: Port number to validate
 * @exception_type: Exception type to raise on invalid port
 * Raises: Specified exception type if port is invalid
 * Thread-safe: Yes
 */
void
SocketCommon_validate_port (int port, Except_T exception_type)
{
  if (!SOCKET_VALID_PORT (port))
    {
      SOCKET_ERROR_MSG (
          "Invalid port number: %d (must be 0-65535, 0 = OS-assigned)", port);
      RAISE_MODULE_ERROR (exception_type);
    }
}

/**
 * SocketCommon_validate_host_not_null - Validate host is not NULL
 * @host: Host string to validate
 * @exception_type: Exception type to raise on NULL host
 * Raises: Specified exception type if host is NULL
 * Thread-safe: Yes
 */
void
SocketCommon_validate_host_not_null (const char *host, Except_T exception_type)
{
  if (host == NULL)
    {
      SOCKET_ERROR_MSG ("Invalid host: NULL pointer");
      RAISE_MODULE_ERROR (exception_type);
    }
}

/**
 * SocketCommon_normalize_wildcard_host - Normalize wildcard host addresses to
 * NULL
 * @host: Host string to normalize
 * Returns: NULL if wildcard ("0.0.0.0" or "::"), original host otherwise
 * Thread-safe: Yes
 */
const char *
SocketCommon_normalize_wildcard_host (const char *host)
{
  if (host == NULL || strcmp (host, "0.0.0.0") == 0
      || strcmp (host, "::") == 0)
    return NULL;
  return host;
}

/**
 * SocketCommon_parse_ip - Validate and parse IP address string
 * @ip_str: IP address string to validate
 * @family: Output pointer for address family (SOCKET_AF_INET or
 * SOCKET_AF_INET6), can be NULL Returns: 1 if valid IP address, 0 if invalid
 * Thread-safe: Yes Note: Validates both IPv4 and IPv6 addresses. Sets family
 * to SOCKET_AF_INET for IPv4, SOCKET_AF_INET6 for IPv6, or AF_UNSPEC if
 * invalid.
 */
int
SocketCommon_parse_ip (const char *ip_str, int *family)
{
  struct in_addr addr4;
  struct in6_addr addr6;

  assert (ip_str);

  if (family)
    *family = AF_UNSPEC;

  /* Try IPv4 first */
  if (inet_pton (SOCKET_AF_INET, ip_str, &addr4) == 1)
    {
      if (family)
        *family = SOCKET_AF_INET;
      return 1;
    }

  /* Try IPv6 */
  if (inet_pton (SOCKET_AF_INET6, ip_str, &addr6) == 1)
    {
      if (family)
        *family = SOCKET_AF_INET6;
      return 1;
    }

  return 0;
}

/**
 * socketcommon_parse_cidr - Parse CIDR notation string
 * @cidr_str: CIDR notation string (e.g., "192.168.1.0/24")
 * @network: Output buffer for network address (4 or 16 bytes)
 * @prefix_len: Output pointer for prefix length
 * @family: Output pointer for address family
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Yes
 */
static int
socketcommon_parse_cidr (const char *cidr_str, unsigned char *network,
                         int *prefix_len, int *family)
{
  char *cidr_copy = NULL;
  char *slash = NULL;
  char *endptr = NULL;
  struct in_addr addr4;
  struct in6_addr addr6;
  long prefix_long;

  assert (cidr_str);
  assert (network);
  assert (prefix_len);
  assert (family);

  /* Make a copy for strtok */
  cidr_copy = strdup (cidr_str);
  if (!cidr_copy)
    return -1;

  /* Find the '/' separator */
  slash = strchr (cidr_copy, '/');
  if (!slash)
    {
      free (cidr_copy);
      return -1;
    }

  *slash = '\0';
  slash++;

  /* Parse prefix length */
  errno = 0;
  prefix_long = strtol (slash, &endptr, 10);
  if (errno != 0 || endptr == slash || *endptr != '\0' || prefix_long < 0)
    {
      free (cidr_copy);
      return -1;
    }

  /* Try IPv4 first */
  if (inet_pton (SOCKET_AF_INET, cidr_copy, &addr4) == 1)
    {
      if (prefix_long > 32)
        {
          free (cidr_copy);
          return -1;
        }
      memcpy (network, &addr4, 4);
      *prefix_len = (int)prefix_long;
      *family = SOCKET_AF_INET;
      free (cidr_copy);
      return 0;
    }

  /* Try IPv6 */
  if (inet_pton (SOCKET_AF_INET6, cidr_copy, &addr6) == 1)
    {
      if (prefix_long > 128)
        {
          free (cidr_copy);
          return -1;
        }
      memcpy (network, &addr6, 16);
      *prefix_len = (int)prefix_long;
      *family = SOCKET_AF_INET6;
      free (cidr_copy);
      return 0;
    }

  free (cidr_copy);
  return -1;
}

/**
 * socketcommon_apply_mask - Apply CIDR mask to IP address
 * @ip: IP address bytes (4 for IPv4, 16 for IPv6)
 * @prefix_len: Prefix length (0-32 for IPv4, 0-128 for IPv6)
 * @family: Address family (SOCKET_AF_INET or SOCKET_AF_INET6)
 * Thread-safe: Yes
 */
static void
socketcommon_apply_mask (unsigned char *ip, int prefix_len, int family)
{
  int addr_bytes = (family == SOCKET_AF_INET) ? 4 : 16;
  int bytes_to_mask = prefix_len / 8;
  int bits_to_mask = prefix_len % 8;

  /* Mask full bytes after prefix */
  for (int i = bytes_to_mask; i < addr_bytes; i++)
    ip[i] = 0;

  /* Mask partial byte at prefix boundary */
  if (bits_to_mask > 0 && bytes_to_mask < addr_bytes)
    ip[bytes_to_mask] &= (unsigned char)(0xFF << (8 - bits_to_mask));
}

/**
 * SocketCommon_cidr_match - Check if IP address matches CIDR range
 * @ip_str: IP address string to check
 * @cidr_str: CIDR notation string (e.g., "192.168.1.0/24" or "2001:db8::/"
 * SOCKET_TO_STRING(SOCKET_IPV6_MAX_PREFIX) ") Returns: 1 if IP matches CIDR
 * range, 0 if not, -1 on error Thread-safe: Yes Note: Supports both IPv4 and
 * IPv6 CIDR notation. Returns -1 if IP or CIDR string is invalid.
 */
int
SocketCommon_cidr_match (const char *ip_str, const char *cidr_str)
{
  unsigned char network[16] = { 0 };
  unsigned char ip[16] = { 0 };
  int prefix_len;
  int cidr_family;
  int ip_family;
  int i;

  assert (ip_str);
  assert (cidr_str);

  /* Parse CIDR notation */
  if (socketcommon_parse_cidr (cidr_str, network, &prefix_len, &cidr_family)
      != 0)
    return -1;

  /* Parse IP address */
  if (!SocketCommon_parse_ip (ip_str, &ip_family))
    return -1;

  /* Family must match */
  if (ip_family != cidr_family)
    return 0;

  /* Convert IP string to bytes */
  if (ip_family == SOCKET_AF_INET)
    {
      struct in_addr addr4;
      if (inet_pton (SOCKET_AF_INET, ip_str, &addr4) != 1)
        return -1;
      memcpy (ip, &addr4, 4);
    }
  else if (ip_family == SOCKET_AF_INET6)
    {
      struct in6_addr addr6;
      if (inet_pton (SOCKET_AF_INET6, ip_str, &addr6) != 1)
        return -1;
      memcpy (ip, &addr6, 16);
    }
  else
    {
      return -1;
    }

  /* Apply mask to IP */
  socketcommon_apply_mask (ip, prefix_len, ip_family);

  /* Compare network addresses - unified loop for IPv4/IPv6 */
  {
    int addr_bytes = (ip_family == SOCKET_AF_INET) ? 4 : 16;
    for (i = 0; i < addr_bytes; i++)
      {
        if (ip[i] != network[i])
          return 0;
      }
  }

  return 1;
}
