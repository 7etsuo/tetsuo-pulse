/**
 * SocketCommon-net.c - Network-specific common utilities
 *
 * Consolidated module for network-specific utilities including multicast,
 * validation, socket options, and address resolution.
 *
 * Features:
 * - Multicast join/leave operations (IPv4/IPv6)
 * - Port and hostname validation
 * - IP parsing and CIDR matching
 * - Socket option get/set operations
 * - File descriptor utilities (CLOEXEC, non-blocking)
 * - Address resolution and caching
 * - Reverse DNS lookup
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#define SOCKET_LOG_COMPONENT "SocketCommon"
#include "core/SocketError.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

SOCKET_DECLARE_MODULE_EXCEPTION (SocketCommon);

#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketCommon, e)

/* ==================== Validation Operations ==================== */

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

void
SocketCommon_validate_host_not_null (const char *host, Except_T exception_type)
{
  if (host == NULL)
    {
      SOCKET_ERROR_MSG ("Invalid host: NULL pointer");
      RAISE_MODULE_ERROR (exception_type);
    }
}

const char *
SocketCommon_normalize_wildcard_host (const char *host)
{
  if (host == NULL || strcmp (host, "0.0.0.0") == 0
      || strcmp (host, "::") == 0)
    return NULL;
  return host;
}

int
SocketCommon_parse_ip (const char *ip_str, int *family)
{
  struct in_addr addr4;
  struct in6_addr addr6;

  assert (ip_str);

  if (family)
    *family = AF_UNSPEC;

  if (inet_pton (SOCKET_AF_INET, ip_str, &addr4) == 1)
    {
      if (family)
        *family = SOCKET_AF_INET;
      return 1;
    }

  if (inet_pton (SOCKET_AF_INET6, ip_str, &addr6) == 1)
    {
      if (family)
        *family = SOCKET_AF_INET6;
      return 1;
    }

  return 0;
}

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

  cidr_copy = strdup (cidr_str);
  if (!cidr_copy)
    return -1;

  slash = strchr (cidr_copy, '/');
  if (!slash)
    {
      free (cidr_copy);
      return -1;
    }

  *slash = '\0';
  slash++;

  errno = 0;
  prefix_long = strtol (slash, &endptr, 10);
  if (errno != 0 || endptr == slash || *endptr != '\0' || prefix_long < 0)
    {
      free (cidr_copy);
      return -1;
    }

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

static void
socketcommon_apply_mask (unsigned char *ip, int prefix_len, int family)
{
  int addr_bytes = (family == SOCKET_AF_INET) ? 4 : 16;
  int bytes_to_mask = prefix_len / 8;
  int bits_to_mask = prefix_len % 8;

  for (int i = bytes_to_mask; i < addr_bytes; i++)
    ip[i] = 0;

  if (bits_to_mask > 0 && bytes_to_mask < addr_bytes)
    ip[bytes_to_mask] &= (unsigned char)(0xFF << (8 - bits_to_mask));
}

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

  if (socketcommon_parse_cidr (cidr_str, network, &prefix_len, &cidr_family)
      != 0)
    return -1;

  if (!SocketCommon_parse_ip (ip_str, &ip_family))
    return -1;

  if (ip_family != cidr_family)
    return 0;

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

  socketcommon_apply_mask (ip, prefix_len, ip_family);

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

/* ==================== Socket Option Operations ==================== */

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
      RAISE_MODULE_ERROR (exc_type);
    }

#if !SOCKET_HAS_SOCK_CLOEXEC
  if (fcntl (fd, F_SETFD, FD_CLOEXEC) < 0)
    {
      int saved_errno = errno;
      SAFE_CLOSE (fd);
      errno = saved_errno;
      SOCKET_ERROR_MSG ("Failed to set close-on-exec flag");
      RAISE_MODULE_ERROR (exc_type);
    }
#endif

  return fd;
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
    return 0;

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

void
SocketCommon_set_cloexec_fd (int fd, bool enable, Except_T exc_type)
{
  /* Delegate to low-level function and raise exception on failure */
  if (SocketCommon_setcloexec (fd, enable ? 1 : 0) < 0)
    {
      SOCKET_ERROR_FMT ("Failed to %s close-on-exec flag on fd %d",
                        enable ? "set" : "clear", fd);
      RAISE_MODULE_ERROR (exc_type);
    }
}

void
SocketCommon_set_nonblock (SocketBase_T base, bool enable, Except_T exc_type)
{
  int flags = fcntl (SocketBase_fd (base), F_GETFL, 0);
  if (flags < 0)
    {
      SOCKET_ERROR_MSG ("Failed to get file flags");
      RAISE_MODULE_ERROR (exc_type);
    }

  if (enable)
    flags |= O_NONBLOCK;
  else
    flags &= ~O_NONBLOCK;

  if (fcntl (SocketBase_fd (base), F_SETFL, flags) < 0)
    {
      SOCKET_ERROR_MSG ("Failed to set non-blocking mode");
      RAISE_MODULE_ERROR (exc_type);
    }
}

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
      RAISE_MODULE_ERROR (exception_type);
      return -1;
    }

  return 0;
}

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
      RAISE_MODULE_ERROR (exception_type);
      return -1;
    }

  return 0;
}

int
SocketCommon_get_family (SocketBase_T base, bool raise_on_fail,
                         Except_T exc_type)
{
  int family = AF_UNSPEC;
  socklen_t len = sizeof (family);

#if SOCKET_HAS_SO_DOMAIN
  if (getsockopt (SocketBase_fd (base), SOL_SOCKET, SO_DOMAIN, &family, &len)
      == 0)
    return family;
#endif

  struct sockaddr_storage addr;
  len = sizeof (addr);
  if (getsockname (SocketBase_fd (base), (struct sockaddr *)&addr, &len) == 0)
    return addr.ss_family;

  if (raise_on_fail)
    {
      SOCKET_ERROR_MSG (
          "Failed to get socket family via SO_DOMAIN or getsockname");
      RAISE_MODULE_ERROR (exc_type);
    }

  return AF_UNSPEC;
}

int
SocketCommon_get_socket_family (SocketBase_T base)
{
  Except_T dummy = { NULL, NULL };
  return SocketCommon_get_family (base, false, dummy);
}

void
SocketCommon_set_option_int (SocketBase_T base, int level, int optname,
                             int value, Except_T exc_type)
{
  if (setsockopt (SocketBase_fd (base), level, optname, &value, sizeof (value))
      < 0)
    {
      SOCKET_ERROR_FMT (
          "Failed to set socket option level=%d optname=%d value=%d: %s",
          level, optname, value, strerror (errno));
      RAISE_MODULE_ERROR (exc_type);
    }
}

void
SocketCommon_setreuseaddr (SocketBase_T base, Except_T exc_type)
{
  assert (base);
  SocketCommon_set_option_int (base, SOCKET_SOL_SOCKET, SOCKET_SO_REUSEADDR, 1,
                               exc_type);
}

void
SocketCommon_setreuseport (SocketBase_T base, Except_T exc_type)
{
  assert (base);

#if SOCKET_HAS_SO_REUSEPORT
  SocketCommon_set_option_int (base, SOCKET_SOL_SOCKET, SOCKET_SO_REUSEPORT, 1,
                               exc_type);
#else
  SOCKET_ERROR_MSG ("SO_REUSEPORT not supported on this platform");
  RAISE_MODULE_ERROR (exc_type);
#endif
}

void
SocketCommon_settimeout (SocketBase_T base, int timeout_sec, Except_T exc_type)
{
  struct timeval tv;

  assert (base);

  if (timeout_sec < 0)
    {
      SOCKET_ERROR_MSG ("Invalid timeout value: %d (must be >= 0)",
                        timeout_sec);
      RAISE_MODULE_ERROR (exc_type);
    }

  tv.tv_sec = timeout_sec;
  tv.tv_usec = 0;

  if (setsockopt (SocketBase_fd (base), SOCKET_SOL_SOCKET, SOCKET_SO_RCVTIMEO,
                  &tv, sizeof (tv))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set receive timeout");
      RAISE_MODULE_ERROR (exc_type);
    }

  if (setsockopt (SocketBase_fd (base), SOCKET_SOL_SOCKET, SOCKET_SO_SNDTIMEO,
                  &tv, sizeof (tv))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set send timeout");
      RAISE_MODULE_ERROR (exc_type);
    }
}

void
SocketCommon_setcloexec_with_error (SocketBase_T base, int enable,
                                    Except_T exc_type)
{
  assert (base);

  if (SocketCommon_setcloexec (SocketBase_fd (base), enable) < 0)
    {
      SOCKET_ERROR_FMT ("Failed to %s close-on-exec flag",
                        enable ? "set" : "clear");
      RAISE_MODULE_ERROR (exc_type);
    }
}

/* ==================== Address Resolution ==================== */

int
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
        RAISE_MODULE_ERROR (exception_type);
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
            RAISE_MODULE_ERROR (exception_type);
          return -1;
        }
    }

  return 0;
}

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
        RAISE_MODULE_ERROR (exception_type);
      return -1;
    }
  return 0;
}

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

  safe_host = socketcommon_get_safe_host (host);
  SOCKET_ERROR_MSG ("No address found for family %d: %.*s:%d", socket_family,
                    SOCKET_ERROR_MAX_HOSTNAME, safe_host, port);
  if (use_exceptions)
    RAISE_MODULE_ERROR (exception_type);
  return -1;
}

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

static struct addrinfo *
copy_single_addrinfo_node (const struct addrinfo *src)
{
  struct addrinfo *new_node = malloc (sizeof (struct addrinfo));
  if (!new_node)
    return NULL;

  memcpy (new_node, src, sizeof (struct addrinfo));
  new_node->ai_next = NULL;

  if (src->ai_addr && src->ai_addrlen > 0)
    {
      new_node->ai_addr = malloc (src->ai_addrlen);
      if (!new_node->ai_addr)
        {
          free (new_node);
          return NULL;
        }
      memcpy (new_node->ai_addr, src->ai_addr, src->ai_addrlen);
    }
  else
    {
      new_node->ai_addr = NULL;
      new_node->ai_addrlen = 0;
    }

  if (src->ai_canonname)
    {
      size_t len = strlen (src->ai_canonname) + 1;
      new_node->ai_canonname = malloc (len);
      if (!new_node->ai_canonname)
        {
          if (new_node->ai_addr)
            free (new_node->ai_addr);
          free (new_node);
          return NULL;
        }
      memcpy (new_node->ai_canonname, src->ai_canonname, len);
    }
  else
    {
      new_node->ai_canonname = NULL;
    }

  return new_node;
}

static void
free_partial_addrinfo_chain (struct addrinfo *head)
{
  if (head)
    freeaddrinfo (head);
}

struct addrinfo *
SocketCommon_copy_addrinfo (const struct addrinfo *src)
{
  struct addrinfo *head = NULL;
  struct addrinfo *tail = NULL;
  const struct addrinfo *p;

  if (!src)
    return NULL;

  p = src;
  while (p)
    {
      struct addrinfo *new_node = copy_single_addrinfo_node (p);
      if (!new_node)
        {
          free_partial_addrinfo_chain (head);
          return NULL;
        }

      if (!head)
        {
          head = tail = new_node;
        }
      else
        {
          tail->ai_next = new_node;
          tail = new_node;
        }
      p = p->ai_next;
    }

  return head;
}

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
      RAISE_MODULE_ERROR (exception_type);
      return -1;
    }

  return 0;
}

/* ==================== Multicast Operations ==================== */

static void
common_resolve_multicast_group (const char *group, struct addrinfo **res,
                                Except_T exc_type)
{
  struct addrinfo hints;
  int result;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = SOCKET_AF_UNSPEC;
  hints.ai_socktype = SOCKET_DGRAM_TYPE;
  hints.ai_flags = SOCKET_AI_NUMERICHOST;

  result = getaddrinfo (group, NULL, &hints, res);
  if (result != 0)
    {
      SOCKET_ERROR_MSG ("Invalid multicast group address: %s (%s)", group,
                        gai_strerror (result));
      RAISE_MODULE_ERROR (exc_type);
    }
}

static void
common_setup_ipv4_multicast_interface (struct ip_mreq *mreq,
                                       const char *interface,
                                       Except_T exc_type)
{
  if (interface)
    {
      if (inet_pton (SOCKET_AF_INET, interface, &mreq->imr_interface) <= 0)
        {
          SOCKET_ERROR_MSG ("Invalid interface address: %s", interface);
          RAISE_MODULE_ERROR (exc_type);
        }
    }
  else
    {
      mreq->imr_interface.s_addr = INADDR_ANY;
    }
}

static void
common_join_ipv4_multicast (SocketBase_T base, struct in_addr group_addr,
                            const char *interface, Except_T exc_type)
{
  struct ip_mreq mreq;
  memset (&mreq, 0, sizeof (mreq));
  mreq.imr_multiaddr = group_addr;
  common_setup_ipv4_multicast_interface (&mreq, interface, exc_type);

  if (setsockopt (SocketBase_fd (base), SOCKET_IPPROTO_IP,
                  SOCKET_IP_ADD_MEMBERSHIP, &mreq, sizeof (mreq))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to join IPv4 multicast group");
      RAISE_MODULE_ERROR (exc_type);
    }
}

static void
common_join_ipv6_multicast (SocketBase_T base, struct in6_addr group_addr,
                            Except_T exc_type)
{
  struct ipv6_mreq mreq6;
  memset (&mreq6, 0, sizeof (mreq6));
  mreq6.ipv6mr_multiaddr = group_addr;
  mreq6.ipv6mr_interface = SOCKET_MULTICAST_DEFAULT_INTERFACE;

  if (setsockopt (SocketBase_fd (base), SOCKET_IPPROTO_IPV6,
                  SOCKET_IPV6_ADD_MEMBERSHIP, &mreq6, sizeof (mreq6))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to join IPv6 multicast group");
      RAISE_MODULE_ERROR (exc_type);
    }
}

static void
common_leave_ipv4_multicast (SocketBase_T base, struct in_addr group_addr,
                             const char *interface, Except_T exc_type)
{
  struct ip_mreq mreq;
  memset (&mreq, 0, sizeof (mreq));
  mreq.imr_multiaddr = group_addr;
  common_setup_ipv4_multicast_interface (&mreq, interface, exc_type);

  if (setsockopt (SocketBase_fd (base), SOCKET_IPPROTO_IP,
                  SOCKET_IP_DROP_MEMBERSHIP, &mreq, sizeof (mreq))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to leave IPv4 multicast group");
      RAISE_MODULE_ERROR (exc_type);
    }
}

static void
common_leave_ipv6_multicast (SocketBase_T base, struct in6_addr group_addr,
                             Except_T exc_type)
{
  struct ipv6_mreq mreq6;
  memset (&mreq6, 0, sizeof (mreq6));
  mreq6.ipv6mr_multiaddr = group_addr;
  mreq6.ipv6mr_interface = SOCKET_MULTICAST_DEFAULT_INTERFACE;

  if (setsockopt (SocketBase_fd (base), SOCKET_IPPROTO_IPV6,
                  SOCKET_IPV6_DROP_MEMBERSHIP, &mreq6, sizeof (mreq6))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to leave IPv6 multicast group");
      RAISE_MODULE_ERROR (exc_type);
    }
}

void
SocketCommon_join_multicast (SocketBase_T base, const char *group,
                             const char *interface, Except_T exc_type)
{
  struct addrinfo *res = NULL;
  int family;

  assert (base);
  assert (group);

  common_resolve_multicast_group (group, &res, exc_type);

  family = SocketCommon_get_family (base, true, exc_type);

  if (family == SOCKET_AF_INET)
    {
      struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
      common_join_ipv4_multicast (base, sin->sin_addr, interface, exc_type);
    }
  else if (family == SOCKET_AF_INET6)
    {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)res->ai_addr;
      common_join_ipv6_multicast (base, sin6->sin6_addr, exc_type);
    }
  else
    {
      SOCKET_ERROR_MSG ("Unsupported address family %d for multicast", family);
      RAISE_MODULE_ERROR (exc_type);
    }

  freeaddrinfo (res);
}

void
SocketCommon_leave_multicast (SocketBase_T base, const char *group,
                              const char *interface, Except_T exc_type)
{
  struct addrinfo *res = NULL;
  int family;

  assert (base);
  assert (group);

  common_resolve_multicast_group (group, &res, exc_type);

  family = SocketCommon_get_family (base, true, exc_type);

  if (family == SOCKET_AF_INET)
    {
      struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
      common_leave_ipv4_multicast (base, sin->sin_addr, interface, exc_type);
    }
  else if (family == SOCKET_AF_INET6)
    {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)res->ai_addr;
      common_leave_ipv6_multicast (base, sin6->sin6_addr, exc_type);
    }
  else
    {
      SOCKET_ERROR_MSG ("Unsupported address family %d for multicast", family);
      RAISE_MODULE_ERROR (exc_type);
    }

  freeaddrinfo (res);
}

void
SocketCommon_set_ttl (SocketBase_T base, int family, int ttl,
                      Except_T exc_type)
{
  int level = 0, opt = 0;
  if (family == SOCKET_AF_INET)
    {
      level = IPPROTO_IP;
      opt = IP_TTL;
    }
  else if (family == SOCKET_AF_INET6)
    {
      level = IPPROTO_IPV6;
      opt = IPV6_UNICAST_HOPS;
    }
  else
    {
      SOCKET_ERROR_FMT ("Unsupported family %d for TTL", family);
      RAISE_MODULE_ERROR (exc_type);
    }

  SocketCommon_set_option_int (base, level, opt, ttl, exc_type);
}

