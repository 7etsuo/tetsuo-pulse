/**
 * SocketCommon.c - Common utilities shared between Socket and SocketDgram
 * modules
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#define SOCKET_LOG_COMPONENT "SocketCommon"
#include "core/SocketError.h"
#include "socket/SocketCommon.h"
#include "socket/SocketCommon-private.h"

/* Global defaults for socket timeouts - shared across modules */
SocketTimeouts_T socket_default_timeouts
    = { .connect_timeout_ms = SOCKET_DEFAULT_CONNECT_TIMEOUT_MS,
        .dns_timeout_ms = SOCKET_DEFAULT_DNS_TIMEOUT_MS,
        .operation_timeout_ms = SOCKET_DEFAULT_OPERATION_TIMEOUT_MS };
pthread_mutex_t socket_default_timeouts_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Forward declarations for exception types */
extern const Except_T Socket_Failed;
extern const Except_T SocketDgram_Failed;

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec (thread) Except_T SocketCommon_DetailedException;
#else
static __thread Except_T SocketCommon_DetailedException;
#endif

/* Macro to raise exception with detailed error message */
#define RAISE_SOCKETCOMMON_ERROR(exception)                                         \
  do                                                                          \
    {                                                                         \
      SocketCommon_DetailedException = (exception);                                 \
      SocketCommon_DetailedException.reason = socket_error_buf;                     \
      RAISE (SocketCommon_DetailedException);                                       \
    }                                                                         \
  while (0)

/**
 * socketcommon_get_safe_host
 * @host: Host string (may be NULL)
 * Thread-safe: Yes
 */
static const char *
socketcommon_get_safe_host (const char *host)
{
  return host ? host : "any";
}

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
 * socketcommon_validate_hostname_internal - Validate hostname length and
 * characters
 * @host: Hostname to validate
 * @use_exceptions: If true, raise exception; if false, return error code
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type if hostname invalid (if using exceptions)
 * Thread-safe: Yes
 */
static int
socketcommon_validate_hostname_internal (const char *host, int use_exceptions,
                                         Except_T exception_type)
{
  size_t host_len = host ? strlen (host) : 0;
  size_t i;

  if (host_len > SOCKET_ERROR_MAX_HOSTNAME)
    {
      SOCKET_ERROR_MSG ("Host name too long (max %d characters)",
                        SOCKET_ERROR_MAX_HOSTNAME);
      if (use_exceptions)
        RAISE_SOCKETCOMMON_ERROR (exception_type);
      return -1;
    }

  for (i = 0; i < host_len; i++)
    {
      char c = host[i];
      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == ':'
            || c == '%'))
        {
          SOCKET_ERROR_MSG ("Invalid character in hostname: '%c'", c);
          if (use_exceptions)
            RAISE_SOCKETCOMMON_ERROR (exception_type);
          return -1;
        }
    }

  return 0;
}

/**
 * socketcommon_convert_port_to_string - Convert port number to string
 * @port: Port number
 * @port_str: Output buffer for port string
 * @bufsize: Size of output buffer
 * Thread-safe: Yes
 */
static void
socketcommon_convert_port_to_string (int port, char *port_str, size_t bufsize)
{
  int result;

  result = snprintf (port_str, bufsize, "%d", port);
  assert (result > 0 && result < (int)bufsize);
}

/**
 * socketcommon_perform_getaddrinfo - Perform address resolution
 * @host: Hostname or IP address
 * @port_str: Port number as string
 * @hints: Addrinfo hints structure
 * @res: Output pointer to resolved addrinfo
 * @use_exceptions: If true, raise exception; if false, return error code
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type on failure (if using exceptions)
 * Thread-safe: Yes
 */
static int
socketcommon_perform_getaddrinfo (const char *host, const char *port_str,
                                  const struct addrinfo *hints,
                                  struct addrinfo **res, int use_exceptions,
                                  Except_T exception_type)
{
  int result;
  const char *safe_host;

  result = getaddrinfo (host, port_str, hints, res);
  if (result != 0)
    {
      safe_host = socketcommon_get_safe_host (host);
      SOCKET_ERROR_MSG ("Invalid host/IP address: %.*s (%s)",
                        SOCKET_ERROR_MAX_HOSTNAME, safe_host,
                        gai_strerror (result));
      if (use_exceptions)
        RAISE_SOCKETCOMMON_ERROR (exception_type);
      return -1;
    }
  return 0;
}

/**
 * socketcommon_find_matching_family - Find address matching socket family
 * @res: Resolved address list
 * @socket_family: Socket family to match
 * Returns: 1 if matching family found, 0 otherwise
 * Thread-safe: Yes
 */
static int
socketcommon_find_matching_family (struct addrinfo *res, int socket_family)
{
  struct addrinfo *rp;

  for (rp = res; rp != NULL; rp = rp->ai_next)
    {
      if (rp->ai_family == socket_family)
        return 1;
    }
  return 0;
}

/**
 * socketcommon_validate_address_family - Validate resolved address family
 * @res: Resolved address list
 * @socket_family: Socket family to match
 * @host: Hostname for error messages
 * @port: Port number for error messages
 * @use_exceptions: If true, raise exception; if false, return error code
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type if no matching family (if using exceptions)
 * Thread-safe: Yes
 */
static int
socketcommon_validate_address_family (struct addrinfo **res, int socket_family,
                                      const char *host, int port,
                                      int use_exceptions,
                                      Except_T exception_type)
{
  const char *safe_host;

  if (socket_family == SOCKET_AF_UNSPEC)
    return 0;

  if (socketcommon_find_matching_family (*res, socket_family))
    return 0;

  freeaddrinfo (*res);
  *res = NULL;

  safe_host = socketcommon_get_safe_host (host);
  SOCKET_ERROR_MSG ("No address found for family %d: %.*s:%d", socket_family,
                    SOCKET_ERROR_MAX_HOSTNAME, safe_host, port);
  if (use_exceptions)
    RAISE_SOCKETCOMMON_ERROR (exception_type);
  return -1;
}

/**
 * SocketCommon_setup_hints - Initialize addrinfo hints structure
 * @hints: Hints structure to initialize
 * @socktype: Socket type (SOCK_STREAM or SOCK_DGRAM)
 * @flags: Additional flags (0 for connect/sendto, AI_PASSIVE for bind)
 * Thread-safe: Yes
 */
void
SocketCommon_setup_hints (struct addrinfo *hints, int socktype, int flags)
{
  memset (hints, 0, sizeof (*hints));
  hints->ai_family = SOCKET_AF_UNSPEC;
  hints->ai_socktype = socktype;
  hints->ai_flags = flags;
  hints->ai_protocol = 0;
}

/**
 * SocketCommon_resolve_address - Resolve hostname/port to addrinfo structure
 * @host: Hostname or IP address (NULL for wildcard)
 * @port: Port number (1 to SOCKET_MAX_PORT)
 * @hints: Addrinfo hints structure
 * @res: Output pointer to resolved addrinfo
 * @exception_type: Exception type to raise on failure
 * @socket_family: Socket family to match (AF_UNSPEC if none)
 * @use_exceptions: If true, raise exceptions; if false, return error codes
 * Returns: 0 on success, -1 on failure (if not using exceptions)
 * Raises: Specified exception type on failure (if using exceptions)
 * Thread-safe: Yes
 */
int
SocketCommon_resolve_address (const char *host, int port,
                              const struct addrinfo *hints,
                              struct addrinfo **res, Except_T exception_type,
                              int socket_family, int use_exceptions)
{
  char port_str[SOCKET_PORT_STR_BUFSIZE];

  if (socketcommon_validate_hostname_internal (host, use_exceptions,
                                               exception_type)
      != 0)
    return -1;

  socketcommon_convert_port_to_string (port, port_str, sizeof (port_str));

  if (socketcommon_perform_getaddrinfo (host, port_str, hints, res,
                                        use_exceptions, exception_type)
      != 0)
    return -1;

  if (socketcommon_validate_address_family (res, socket_family, host, port,
                                            use_exceptions, exception_type)
      != 0)
    return -1;

  return 0;
}

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
          "Invalid port number: %d (must be 0-" SOCKET_TO_STRING (
              SOCKET_MAX_PORT) ", 0 = OS-assigned)",
          port);
      RAISE_SOCKETCOMMON_ERROR (exception_type);
    }
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

int
SocketCommon_setcloexec (int fd, int enable)
{
  int flags;
  int new_flags;

  assert (fd >= 0);

  flags = fcntl (fd, F_GETFD);
  if (flags < 0)
    return -1;

  if (enable)
    new_flags = flags | SOCKET_FD_CLOEXEC;
  else
    new_flags = flags & ~SOCKET_FD_CLOEXEC;

  if (new_flags == flags)
    return 0; /* Already in desired state */

  if (fcntl (fd, F_SETFD, new_flags) < 0)
    return -1;

  return 0;
}

int
SocketCommon_has_cloexec (int fd)
{
  int flags;

  assert (fd >= 0);

  flags = fcntl (fd, F_GETFD);
  if (flags < 0)
    return -1;

  return (flags & SOCKET_FD_CLOEXEC) ? 1 : 0;
}

/**
 * SocketCommon_getoption_int - Get integer socket option
 * @fd: File descriptor
 * @level: Option level (SOL_SOCKET, IPPROTO_TCP, etc.)
 * @optname: Option name (SO_KEEPALIVE, TCP_NODELAY, etc.)
 * @value: Output pointer for option value
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type on failure
 * Thread-safe: Yes (operates on single fd)
 */
int
SocketCommon_getoption_int (int fd, int level, int optname, int *value,
                            Except_T exception_type)
{
  socklen_t len = sizeof (*value);

  assert (fd >= 0);
  assert (value);

  if (getsockopt (fd, level, optname, value, &len) < 0)
    {
      SOCKET_ERROR_FMT ("Failed to get socket option (level=%d, optname=%d)",
                        level, optname);
      RAISE_SOCKETCOMMON_ERROR (exception_type);
      return -1;
    }

  return 0;
}

/**
 * SocketCommon_getoption_timeval - Get timeval socket option
 * @fd: File descriptor
 * @level: Option level (SOL_SOCKET)
 * @optname: Option name (SO_RCVTIMEO, SO_SNDTIMEO)
 * @tv: Output pointer for timeval structure
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type on failure
 * Thread-safe: Yes (operates on single fd)
 */
int
SocketCommon_getoption_timeval (int fd, int level, int optname,
                                struct timeval *tv, Except_T exception_type)
{
  socklen_t len = sizeof (*tv);

  assert (fd >= 0);
  assert (tv);

  if (getsockopt (fd, level, optname, tv, &len) < 0)
    {
      SOCKET_ERROR_FMT (
          "Failed to get socket timeout option (level=%d, optname=%d)", level,
          optname);
      RAISE_SOCKETCOMMON_ERROR (exception_type);
      return -1;
    }

  return 0;
}

/**
 * SocketCommon_reverse_lookup - Perform reverse DNS lookup (getnameinfo
 * wrapper)
 * @addr: Socket address to look up
 * @addrlen: Length of socket address
 * @host: Output buffer for hostname (NULL to skip)
 * @hostlen: Size of host buffer
 * @serv: Output buffer for service/port (NULL to skip)
 * @servlen: Size of service buffer
 * @flags: getnameinfo flags (NI_NUMERICHOST, NI_NAMEREQD, etc.)
 * @exception_type: Exception type to raise on failure
 * Returns: 0 on success, -1 on failure
 * Raises: Specified exception type on failure
 * Thread-safe: Yes
 * Note: Wrapper around getnameinfo() for reverse DNS lookups.
 * Use NI_NUMERICHOST flag to get numeric IP address instead of hostname.
 */
int
SocketCommon_reverse_lookup (const struct sockaddr *addr, socklen_t addrlen,
                             char *host, socklen_t hostlen, char *serv,
                             socklen_t servlen, int flags,
                             Except_T exception_type)
{
  int result;

  assert (addr);

  result = getnameinfo (addr, addrlen, host, hostlen, serv, servlen, flags);
  if (result != 0)
    {
      SOCKET_ERROR_MSG ("Reverse lookup failed: %s", gai_strerror (result));
      RAISE_SOCKETCOMMON_ERROR (exception_type);
      return -1;
    }

  return 0;
}

/**
 * SocketCommon_parse_ip - Validate and parse IP address string
 * @ip_str: IP address string to validate
 * @family: Output pointer for address family (AF_INET or AF_INET6), can be
 * NULL Returns: 1 if valid IP address, 0 if invalid Thread-safe: Yes Note:
 * Validates both IPv4 and IPv6 addresses. Sets family to AF_INET for IPv4,
 * AF_INET6 for IPv6, or AF_UNSPEC if invalid.
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
  if (inet_pton (AF_INET, ip_str, &addr4) == 1)
    {
      if (family)
        *family = AF_INET;
      return 1;
    }

  /* Try IPv6 */
  if (inet_pton (AF_INET6, ip_str, &addr6) == 1)
    {
      if (family)
        *family = AF_INET6;
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
  if (inet_pton (AF_INET, cidr_copy, &addr4) == 1)
    {
      if (prefix_long > 32)
        {
          free (cidr_copy);
          return -1;
        }
      memcpy (network, &addr4, 4);
      *prefix_len = (int)prefix_long;
      *family = AF_INET;
      free (cidr_copy);
      return 0;
    }

  /* Try IPv6 */
  if (inet_pton (AF_INET6, cidr_copy, &addr6) == 1)
    {
      if (prefix_long > SOCKET_IPV6_MAX_PREFIX)
        {
          free (cidr_copy);
          return -1;
        }
      memcpy (network, &addr6, 16);
      *prefix_len = (int)prefix_long;
      *family = AF_INET6;
      free (cidr_copy);
      return 0;
    }

  free (cidr_copy);
  return -1;
}

/**
 * socketcommon_apply_mask - Apply CIDR mask to IP address
 * @ip: IP address bytes (4 for IPv4, 16 for IPv6)
 * @prefix_len: Prefix length (" SOCKET_IPV4_PREFIX_RANGE " for IPv4, "
 * SOCKET_IPV6_PREFIX_RANGE " for IPv6)
 * @family: Address family (AF_INET or AF_INET6)
 * Thread-safe: Yes
 */
static void
socketcommon_apply_mask (unsigned char *ip, int prefix_len, int family)
{
  int bytes_to_mask;
  int bits_to_mask;
  int i;

  if (family == AF_INET)
    {
      bytes_to_mask = prefix_len / 8;
      bits_to_mask = prefix_len % 8;

      /* Mask full bytes */
      for (i = bytes_to_mask; i < 4; i++)
        ip[i] = 0;

      /* Mask partial byte */
      if (bits_to_mask > 0 && bytes_to_mask < 4)
        {
          unsigned char mask = (0xFF << (8 - bits_to_mask)) & 0xFF;
          ip[bytes_to_mask] &= mask;
        }
    }
  else if (family == AF_INET6)
    {
      bytes_to_mask = prefix_len / 8;
      bits_to_mask = prefix_len % 8;

      /* Mask full bytes */
      for (i = bytes_to_mask; i < 16; i++)
        ip[i] = 0;

      /* Mask partial byte */
      if (bits_to_mask > 0 && bytes_to_mask < 16)
        {
          unsigned char mask = (0xFF << (8 - bits_to_mask)) & 0xFF;
          ip[bytes_to_mask] &= mask;
        }
    }
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
  if (ip_family == AF_INET)
    {
      struct in_addr addr4;
      if (inet_pton (AF_INET, ip_str, &addr4) != 1)
        return -1;
      memcpy (ip, &addr4, 4);
    }
  else if (ip_family == AF_INET6)
    {
      struct in6_addr addr6;
      if (inet_pton (AF_INET6, ip_str, &addr6) != 1)
        return -1;
      memcpy (ip, &addr6, 16);
    }
  else
    {
      return -1;
    }

  /* Apply mask to IP */
  socketcommon_apply_mask (ip, prefix_len, ip_family);

  /* Compare network addresses */
  if (ip_family == AF_INET)
    {
      for (i = 0; i < 4; i++)
        {
          if (ip[i] != network[i])
            return 0;
        }
    }
  else if (ip_family == AF_INET6)
    {
      for (i = 0; i < 16; i++)
        {
          if (ip[i] != network[i])
            return 0;
        }
    }

  return 1;
}

#include "socket/SocketCommon-private.h"  /* Already included? Wait no, earlier we added after public */




/**
 * SocketCommon_create_fd - Create socket file descriptor with CLOEXEC
 * @domain: Address domain
 * @type: Socket type
 * @protocol: Protocol
 * @exc_type: Exception type to raise on failure
 * Returns: File descriptor on success, raises exception on failure
 * Note: Moved from Socket.c create_socket_fd and unified with Dgram logic
 * Thread-safe: Yes
 * Allocates: No memory allocation
 */
int
SocketCommon_create_fd (int domain, int type, int protocol, Except_T exc_type)
{
  int fd;

#if SOCKET_HAS_SOCK_CLOEXEC
  fd = socket (domain, type | SOCK_CLOEXEC, protocol);
#else
  fd = socket (domain, type, protocol);
#endif

  if (fd < 0)
    {
      SOCKET_ERROR_FMT (
          "Failed to create socket (domain=%d, type=%d, protocol=%d)", domain,
          type, protocol);
      RAISE_SOCKETCOMMON_ERROR (exc_type);
    }

#if !SOCKET_HAS_SOCK_CLOEXEC
  /* Fallback: Set CLOEXEC via fcntl */
  if (fcntl (fd, F_SETFD, FD_CLOEXEC) < 0)
    {
      int saved_errno = errno;
      SAFE_CLOSE (fd);
      errno = saved_errno;
      SOCKET_ERROR_MSG ("Failed to set close-on-exec flag");
      RAISE_SOCKETCOMMON_ERROR (exc_type);
    }
#endif

  return fd;
}

/**
 * SocketCommon_init_base - Initialize base structure fields
 * @base: Pointer to base to initialize
 * @fd: File descriptor to assign
 * @domain: Domain
 * @type: Type
 * @protocol: Protocol
 * Performs common initialization: set fd, clear addrs, set defaults for timeouts/metrics
 * Raises: exc_type on any error (though unlikely since no alloc)
 */
void
SocketCommon_init_base (SocketBase_T base, int fd, int domain, int type, int protocol, Except_T exc_type)
{
  (void) exc_type;
  base->fd = fd;
  base->domain = domain;
  base->type = type;
  base->protocol = protocol;
  
  base->remote_addrlen = sizeof (base->remote_addr);
  memset (&base->remote_addr, 0, sizeof (base->remote_addr));
  base->local_addrlen = 0;
  memset (&base->local_addr, 0, sizeof (base->local_addr));
  base->remoteaddr = NULL;
  base->remoteport = 0;
  base->localaddr = NULL;
  base->localport = 0;
  
  /* Copy default timeouts thread-safe */
  pthread_mutex_lock (&socket_default_timeouts_mutex);  /* Assume global or move to common */
  base->timeouts = socket_default_timeouts;
  pthread_mutex_unlock (&socket_default_timeouts_mutex);
  
  /* Metrics already zero from calloc */
  
  /* Update local endpoint info */
  SocketBase_update_local_endpoint (base);
}

/**
 * SocketCommon_new_base - Create and initialize new socket base
 * @domain: Address domain
 * @type: Socket type
 * @protocol: Protocol
 * Returns: Initialized SocketBase_T
 * Raises: exc_type on failure (alloc, fd create)
 * Allocates: Arena and base struct from arena
 * Resource Order: Arena -> fd
 */
SocketBase_T
SocketCommon_new_base (int domain, int type, int protocol)
{
  Arena_T arena;
  SocketBase_T base;
  int fd;
  Except_T exc_type = Socket_Failed;  /* Default, or param? For now default to Socket_Failed for base errors */

  arena = Arena_new ();
  /* Note: Arena_new either succeeds or raises Arena_Failed; never returns NULL */

  base = Arena_calloc (arena, 1, sizeof (struct SocketBase_T), __FILE__, __LINE__);
  if (!base)
    {
      Arena_dispose (&arena);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate base structure");
      RAISE_SOCKETCOMMON_ERROR (exc_type);
    }

  base->arena = arena;

  fd = SocketCommon_create_fd (domain, type, protocol, exc_type);
  SocketCommon_init_base (base, fd, domain, type, protocol, exc_type);

  return base;
}

/**
 * SocketCommon_free_base - Free socket base resources
 * @base: Pointer to base (set to NULL on return)
 * Cleanup: TLS not here (subtype), close fd, dispose arena (frees base)
 * Thread-safe: Yes for own resources
 * Note: Caller must cleanup subtype specific before calling this
 */
void
SocketCommon_free_base (SocketBase_T *base_ptr)
{
  SocketBase_T base = *base_ptr;
  if (!base)
    return;

  /* Mark fd closed */
  if (base->fd >= 0)
    {
      int fd = base->fd;
      base->fd = -1;
      SAFE_CLOSE (fd);
    }

  /* Free strings if any - but since arena dispose will free all */
  /* No need for individual free */

  /* Invalidate caller pointer before disposing arena to avoid writing to freed memory.
   * Copy arena pointer to local to safely dispose after potential free of base struct. */
  *base_ptr = NULL;
  Arena_T arena_to_dispose = base->arena;
  Arena_dispose (&arena_to_dispose);
}

/* Implement other helpers like update_local_endpoint */
void
SocketBase_update_local_endpoint (SocketBase_T base)
{
  socklen_t len = sizeof (base->local_addr);
  if (getsockname (base->fd, (struct sockaddr *)&base->local_addr, &len) == 0)
    {
      base->local_addrlen = len;
      /* Update string and port - extract from addr */
      /* ... code to set localaddr, localport using getnameinfo or inet_ntop */
      /* For now stub */
    }
  else
    {
      SOCKET_ERROR_MSG ("Failed to update local endpoint: %s", strerror(errno));
      /* Log warning, don't raise */
    }
}

int
SocketBase_fd (SocketBase_T base)
{
  return base ? base->fd : -1;
}

Arena_T
SocketBase_arena (SocketBase_T base)
{
  return base ? base->arena : NULL;
}

int
SocketBase_domain (SocketBase_T base)
{
  return base ? base->domain : AF_UNSPEC;
}

void
SocketBase_set_timeouts (SocketBase_T base, const SocketTimeouts_T *timeouts)
{
  if (base && timeouts)
    base->timeouts = *timeouts;
}

/**
 * SocketCommon_update_local_endpoint - Update local endpoint info from fd
 * @base: Base to update
 * Logs warning on failure, does not raise exception
 * Sets local_addr, local_addrlen, localaddr, localport
 * Allocates strings from base->arena
 */
void
SocketCommon_update_local_endpoint (SocketBase_T base)
{
  struct sockaddr_storage local;
  socklen_t len = sizeof (local);

  if (getsockname (SocketBase_fd (base), (struct sockaddr *)&local, &len) < 0)
    {
      SOCKET_ERROR_MSG ("Failed to update local endpoint: %s", strerror (errno));
      base->local_addrlen = 0;
      base->localaddr = NULL;
      base->localport = 0;
      return;
    }

  base->local_addr = local;
  base->local_addrlen = len;

  if (SocketCommon_cache_endpoint (SocketBase_arena (base), (struct sockaddr *)&local,
                                   len, &base->localaddr, &base->localport)
      != 0)
    {
      base->localaddr = NULL;
      base->localport = 0;
    }
}

/**
 * SocketCommon_get_family - Get socket address family from fd
 * @base: Base with fd
 * @raise_on_fail: If true, raise exc_type on failure; else return AF_UNSPEC
 * @exc_type: Exception for failure case
 * Returns: Address family or AF_UNSPEC
 * Thread-safe: Yes
 * Unifies duplicated logic from get_socket_family and get_dgram_socket_family
 */
int
SocketCommon_get_family (SocketBase_T base, bool raise_on_fail, Except_T exc_type)
{
  int family = AF_UNSPEC;
  socklen_t len = sizeof (family);

#if SOCKET_HAS_SO_DOMAIN
  if (getsockopt (SocketBase_fd (base), SOL_SOCKET, SO_DOMAIN, &family, &len) == 0)
    return family;
#endif

  /* Fallback getsockname */
  struct sockaddr_storage addr;
  len = sizeof (addr);
  if (getsockname (SocketBase_fd (base), (struct sockaddr *)&addr, &len) == 0)
    return addr.ss_family;

  if (raise_on_fail)
    {
      SOCKET_ERROR_MSG ("Failed to get socket family via SO_DOMAIN or getsockname");
      RAISE_SOCKETCOMMON_ERROR (exc_type);
    }

  return AF_UNSPEC;
}

/**
 * SocketCommon_set_option_int - Generic setsockopt for int options
 * @base: Base with fd
 * @level: SOL_SOCKET etc.
 * @optname: SO_REUSEADDR etc.
 * @value: int value (bool as 0/1)
 * @exc_type: Raise on fail
 * Handles common options, logs details
 */
void
SocketCommon_set_option_int (SocketBase_T base, int level, int optname, int value, Except_T exc_type)
{
  if (setsockopt (SocketBase_fd (base), level, optname, &value, sizeof (value)) < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set socket option level=%d optname=%d value=%d: %s",
                        level, optname, value, strerror (errno));
      RAISE_SOCKETCOMMON_ERROR (exc_type);
    }
}

void
SocketCommon_set_ttl (SocketBase_T base, int family, int ttl, Except_T exc_type)
{
  int level = 0, opt = 0;
  if (family == AF_INET)
    {
      level = IPPROTO_IP;
      opt = IP_TTL;
    }
  else if (family == AF_INET6)
    {
      level = IPPROTO_IPV6;
      opt = IPV6_UNICAST_HOPS;
    }
  else
    {
      SOCKET_ERROR_FMT ("Unsupported family %d for TTL", family);
      RAISE_SOCKETCOMMON_ERROR (exc_type);
    }

  SocketCommon_set_option_int (base, level, opt, ttl, exc_type);
}

void
SocketCommon_set_nonblock (SocketBase_T base, bool enable, Except_T exc_type)
{
  int flags = fcntl (SocketBase_fd (base), F_GETFL, 0);
  if (flags < 0)
    {
      SOCKET_ERROR_MSG ("Failed to get file flags");
      RAISE_SOCKETCOMMON_ERROR (exc_type);
    }

  if (enable)
    flags |= O_NONBLOCK;
  else
    flags &= ~O_NONBLOCK;

  if (fcntl (SocketBase_fd (base), F_SETFL, flags) < 0)
    {
      SOCKET_ERROR_MSG ("Failed to set non-blocking mode");
      RAISE_SOCKETCOMMON_ERROR (exc_type);
    }
}

/* Add more as extracted from plan */

