/**
 * SocketDgram-bind.c - UDP/datagram socket bind and connect operations
 *
 * Implements bind and connect operations for UDP sockets with address resolution
 * and proper error handling. Handles both IPv4 and IPv6 addresses with automatic
 * family selection.
 *
 * Features:
 * - Socket binding with hostname resolution
 * - Socket connecting with hostname resolution
 * - Address resolution helpers
 * - Platform-specific IPv6 handling
 * - Error classification and detailed reporting
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig-limits.h"
#include "core/SocketConfig.h"
#include "socket/SocketDgram.h"
#include "socket/SocketDgram-private.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#define SOCKET_LOG_COMPONENT "SocketDgram"
#include "core/SocketError.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"
#define T SocketDgram_T
/* Port string buffer size for snprintf */
/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketDgram);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketDgram, e)

/* Forward declarations for functions in other files */
void validate_dgram_port (int port);
void validate_dgram_hostname (const char *host);
int resolve_sendto_address (const char *host, int port, struct addrinfo **res);
ssize_t perform_sendto (T socket, const void *buf, size_t len, struct addrinfo *res);
ssize_t perform_recvfrom (T socket, void *buf, size_t len,
                  struct sockaddr_storage *addr, socklen_t *addrlen);
void extract_sender_info (const struct sockaddr_storage *addr, socklen_t addrlen,
                     char *host, size_t host_len, int *port);

/* Local helper functions */
static const char *normalize_dgram_host (const char *host);

/**
 * validate_dgram_port
 * Raises: SocketDgram_Failed if port is invalid
 */

void
validate_dgram_port (int port)
{
  SocketCommon_validate_port (port, SocketDgram_Failed);
}
/**
 * validate_dgram_hostname
 * Raises: SocketDgram_Failed if hostname too long
 */

void
validate_dgram_hostname (const char *host)
{
  SocketCommon_validate_hostname (host, SocketDgram_Failed);
}
/**
 * setup_sendto_hints
 */

static void
setup_sendto_hints (struct addrinfo *hints)
{
  SocketCommon_setup_hints (hints, SOCKET_DGRAM_TYPE, 0);
}

/**
 * resolve_sendto_address - Resolve address for sendto operation
 * @host: Hostname to resolve
 * @port: Port number
 * @res: Output resolved addresses
 * Returns: 0 on success, raises exception on failure
 * Raises: SocketDgram_Failed on resolution failure
 */
int
resolve_sendto_address (const char *host, int port, struct addrinfo **res)
{
  struct addrinfo hints;
  char port_str[SOCKET_PORT_STR_BUFSIZE];
  int result;
  result = snprintf (port_str, sizeof (port_str), "%d", port);
  assert (result > 0 && result < (int)sizeof (port_str));
  setup_sendto_hints (&hints);
  result = getaddrinfo (host, port_str, &hints, res);
  if (result != 0)
    {
      SOCKET_ERROR_MSG ("Invalid host/IP address: %.*s (%s)",
                        SOCKET_ERROR_MAX_HOSTNAME, host,
                        gai_strerror (result));
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return 0;
}

/**
 * perform_sendto - Send datagram to resolved address
 * @socket: Socket to send from
 * @buf: Data buffer
 * @len: Data length
 * @res: Resolved address info
 * Returns: Bytes sent or 0 on EAGAIN/EWOULDBLOCK
 * Raises: SocketDgram_Failed on send failure
 */
ssize_t
perform_sendto (T socket, const void *buf, size_t len, struct addrinfo *res)
{
  /** Enforce UDP sizing to avoid fragmentation and respect protocol
       limits */
  if (len > SAFE_UDP_SIZE)
    {
      // clang-format off
      SOCKET_ERROR_MSG ("Datagram len %zu > SAFE_UDP_SIZE %zu (risk of fragmentation; max allowed %zu)", len, SAFE_UDP_SIZE, UDP_MAX_PAYLOAD);
      // clang-format on
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  ssize_t sent = sendto (SocketBase_fd (socket->base), buf, len, 0,
                         res->ai_addr, res->ai_addrlen);
  if (sent < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      /* Note:
       * We can't include host/port in error since res is freed
       */
      SOCKET_ERROR_FMT ("Failed to send datagram");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return sent;
}

/**
 * perform_recvfrom - Receive datagram from socket
 * @socket: Socket to receive from
 * @buf: Data buffer
 * @len: Buffer length
 * @addr: Output sender address
 * @addrlen: Input/output address length
 * Returns: Bytes received or 0 on EAGAIN/EWOULDBLOCK
 * Raises: SocketDgram_Failed on receive failure
 */
ssize_t
perform_recvfrom (T socket, void *buf, size_t len,
                  struct sockaddr_storage *addr, socklen_t *addrlen)
{
  ssize_t received = recvfrom (SocketBase_fd (socket->base), buf, len, 0,
                               (struct sockaddr *)addr, addrlen);
  if (received < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      SOCKET_ERROR_FMT ("Failed to receive datagram");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return received;
}

/**
 * extract_sender_info - Extract sender address and port information
 * @addr: Sender address structure
 * @addrlen: Address length
 * @host: Output host buffer
 * @host_len: Host buffer length
 * @port: Output port pointer
 */
void
extract_sender_info (const struct sockaddr_storage *addr, socklen_t addrlen,
                     char *host, size_t host_len, int *port)
{
  char serv[SOCKET_NI_MAXSERV];
  int result;
  result = getnameinfo ((struct sockaddr *)addr, addrlen, host, host_len, serv,
                        SOCKET_NI_MAXSERV,
                        SOCKET_NI_NUMERICHOST | SOCKET_NI_NUMERICSERV);
  if (result == 0)
    {
      char *endptr;
      long port_long = strtol (serv, &endptr, 10);
      if (*endptr == '\0' && port_long > 0 && port_long <= SOCKET_MAX_PORT)
        {
          *port = (int)port_long;
        }
      else
        {
          *port = 0;
        }
    }
  else
    {
      /* Failed to get address info - set defaults */
      if (host_len > 0)
        host[0] = '\0';
      *port = 0;
    }
}

/**
 * setup_dgram_bind_hints
 */
static void
setup_dgram_bind_hints (struct addrinfo *hints)
{
  SocketCommon_setup_hints (hints, SOCKET_DGRAM_TYPE, SOCKET_AI_PASSIVE);
}

/**
 * setup_dgram_connect_hints
 */
static void
setup_dgram_connect_hints (struct addrinfo *hints)
{
  SocketCommon_setup_hints (hints, SOCKET_DGRAM_TYPE, 0);
}

/**
 * try_dgram_bind_addresses - Try binding datagram socket to resolved addresses
 * @socket: Socket to bind
 * @res: Resolved address list
 * @socket_family: Socket's address family
 * Returns: 0 on success, -1 on failure
 */
static int
try_dgram_bind_addresses (T socket, struct addrinfo *res, int socket_family)
{
  struct addrinfo *rp;
  for (rp = res; rp != NULL; rp = rp->ai_next)
    {
      if (socket_family != SOCKET_AF_UNSPEC && rp->ai_family != socket_family)
        continue;
      if (rp->ai_family == SOCKET_AF_INET6 && socket_family == SOCKET_AF_INET6)
        {
          int no = 0;
          setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_IPV6,
                      SOCKET_IPV6_V6ONLY, &no, sizeof (no));
        }
      if (bind (SocketBase_fd (socket->base), rp->ai_addr, rp->ai_addrlen)
          == 0)
        {
          memcpy (&socket->base->remote_addr, rp->ai_addr, rp->ai_addrlen);
          socket->base->remote_addrlen = rp->ai_addrlen;
          return 0;
        }
    }
  return -1;
}

/**
 * handle_dgram_bind_error - Handle datagram bind error
 * @host: Host string
 * @port: Port number
 */
static void
handle_dgram_bind_error (const char *host, int port)
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

/**
 * try_dgram_connect_addresses - Try connecting datagram socket to resolved
 * addresses
 * @socket: Socket to connect
 * @res: Resolved address list
 * @socket_family: Socket's address family
 * Returns: 0 on success, -1 on failure
 */
static int
try_dgram_connect_addresses (T socket, struct addrinfo *res, int socket_family)
{
  struct addrinfo *rp;
  for (rp = res; rp != NULL; rp = rp->ai_next)
    {
      if (socket_family != SOCKET_AF_UNSPEC && rp->ai_family != socket_family)
        continue;
      if (connect (SocketBase_fd (socket->base), rp->ai_addr, rp->ai_addrlen)
          == 0)
        {
          memcpy (&socket->base->remote_addr, rp->ai_addr, rp->ai_addrlen);
          socket->base->remote_addrlen = rp->ai_addrlen;
          return 0;
        }
    }
  return -1;
}

/**
 * get_dgram_socket_family
 * Uses SO_DOMAIN on Linux, falls back to getsockname() on other platforms.
 */
static int
get_dgram_socket_family (T socket)
{
  int family = SocketCommon_get_family (socket->base, false,
                                         SocketDgram_Failed); /* No raise on fail */
  return family;
}

void
SocketDgram_bind (T socket, const char *host, int port)
{
  struct addrinfo hints, *res = NULL;
  int socket_family;
  assert (socket);
  validate_dgram_port (port);
  host = normalize_dgram_host (host);
  if (host)
    validate_dgram_hostname (host);
  setup_dgram_bind_hints (&hints);
  SocketCommon_resolve_address (host, port, &hints, &res, SocketDgram_Failed,
                                SOCKET_AF_UNSPEC, 1);
  socket_family = get_dgram_socket_family (socket);
  if (try_dgram_bind_addresses (socket, res, socket_family) == 0)
    {
      SocketCommon_update_local_endpoint (socket->base);
      freeaddrinfo (res);
      return;
    }
  handle_dgram_bind_error (host, port);
  freeaddrinfo (res);
  RAISE_MODULE_ERROR (SocketDgram_Failed);
}

/**
 * handle_dgram_connect_error - Handle datagram connect error
 * @host: Host string
 * @port: Port number
 */
static void
handle_dgram_connect_error (const char *host, int port)
{
  SOCKET_ERROR_FMT ("Failed to connect to %.*s:%d", SOCKET_ERROR_MAX_HOSTNAME,
                    host, port);
}
void
SocketDgram_connect (T socket, const char *host, int port)
{
  struct addrinfo hints, *res = NULL;
  int socket_family;
  assert (socket);
  assert (host);
  validate_dgram_port (port);
  validate_dgram_hostname (host);
  setup_dgram_connect_hints (&hints);
  SocketCommon_resolve_address (host, port, &hints, &res, SocketDgram_Failed,
                                SOCKET_AF_UNSPEC, 1);
  socket_family = get_dgram_socket_family (socket);
  if (try_dgram_connect_addresses (socket, res, socket_family) == 0)
    {
      SocketCommon_update_local_endpoint (socket->base);
      freeaddrinfo (res);
      return;
    }
  handle_dgram_connect_error (host, port);
  freeaddrinfo (res);
  RAISE_MODULE_ERROR (SocketDgram_Failed);
}


/**
 * normalize_dgram_host - Normalize host for datagram binding
 * @host: Host string to normalize
 * Returns: NULL if wildcard, normalized host otherwise
 */
static const char *
normalize_dgram_host (const char *host)
{
  if (host != NULL && strcmp (host, "0.0.0.0") != 0
      && strcmp (host, "::") != 0)
    return host;
  return NULL;
}

#undef T
