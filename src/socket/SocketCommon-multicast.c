/**
 * SocketCommon-multicast.c - Multicast operations
 *
 * Contains multicast join/leave operations for IPv4 and IPv6
 * extracted from the main SocketCommon.c file.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
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
 * common_resolve_multicast_group - Resolve multicast group address (private)
 * @group: Multicast group address
 * @res: Output resolved address info
 * @exc_type: Exception to raise on failure
 * Raises on resolution failure
 */
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

/**
 * common_setup_ipv4_multicast_interface - Setup IPv4 mreq interface (private)
 * @mreq: IP mreq structure
 * @interface: Interface IP or NULL
 * @exc_type: Raise on invalid
 */
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

/**
 * common_join_ipv4_multicast - Join IPv4 multicast (private)
 * @base: Socket base
 * @group_addr: Group addr
 * @interface: Interface or NULL
 * @exc_type: Raise on fail
 */
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

/**
 * common_join_ipv6_multicast - Join IPv6 multicast (private)
 * @base: Socket base
 * @group_addr: Group addr
 * @exc_type: Raise on fail
 * Note: Interface not used for IPv6 in basic impl (advanced needs if_index)
 */
static void
common_join_ipv6_multicast (SocketBase_T base, struct in6_addr group_addr,
                            Except_T exc_type)
{
  struct ipv6_mreq mreq6;
  memset (&mreq6, 0, sizeof (mreq6));
  mreq6.ipv6mr_multiaddr = group_addr;
  mreq6.ipv6mr_interface = SOCKET_MULTICAST_DEFAULT_INTERFACE; /* Default */

  if (setsockopt (SocketBase_fd (base), SOCKET_IPPROTO_IPV6,
                  SOCKET_IPV6_ADD_MEMBERSHIP, &mreq6, sizeof (mreq6))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to join IPv6 multicast group");
      RAISE_MODULE_ERROR (exc_type);
    }
}

/**
 * common_leave_ipv4_multicast - Leave IPv4 multicast (private)
 * Symmetric to join
 */
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

/**
 * common_leave_ipv6_multicast - Leave IPv6 multicast (private)
 */
static void
common_leave_ipv6_multicast (SocketBase_T base, struct in6_addr group_addr,
                             Except_T exc_type)
{
  struct ipv6_mreq mreq6;
  memset (&mreq6, 0, sizeof (mreq6));
  mreq6.ipv6mr_multiaddr = group_addr;
  mreq6.ipv6mr_interface = SOCKET_MULTICAST_DEFAULT_INTERFACE; /* Default */

  if (setsockopt (SocketBase_fd (base), SOCKET_IPPROTO_IPV6,
                  SOCKET_IPV6_DROP_MEMBERSHIP, &mreq6, sizeof (mreq6))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to leave IPv6 multicast group");
      RAISE_MODULE_ERROR (exc_type);
    }
}

/**
 * SocketCommon_join_multicast - Public join multicast
 */
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

/**
 * SocketCommon_leave_multicast - Public leave multicast
 * Symmetric to join
 */
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

/**
 * SocketCommon_set_ttl - Set TTL for multicast packets
 * @base: Socket base
 * @family: Address family (AF_INET or AF_INET6)
 * @ttl: TTL value
 * @exc_type: Exception to raise on failure
 */
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
