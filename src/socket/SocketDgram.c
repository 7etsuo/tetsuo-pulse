/**
 * SocketDgram.c - UDP/datagram socket
 */
#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig-limits.h"
#include "core/SocketConfig.h"
#include "socket/SocketDgram.h"
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
const Except_T SocketDgram_Failed
    = { &SocketDgram_Failed, "Datagram socket operation failed" };
/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec (thread) Except_T SocketDgram_DetailedException;
#else
static __thread Except_T SocketDgram_DetailedException;
#endif

/** Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e)                                                 \
  do                                                                          \
    {                                                                         \
      SocketDgram_DetailedException = (e);                                    \
      SocketDgram_DetailedException.reason = socket_error_buf;                \
      RAISE (SocketDgram_DetailedException);                                  \
    }                                                                         \
  while (0)
static int dgram_live_count = 0;
static pthread_mutex_t dgram_live_count_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * dgram_live_increment - Increment live dgram count (thread-safe)
 */

static void
dgram_live_increment (void)
{
  pthread_mutex_lock (&dgram_live_count_mutex);
  dgram_live_count++;
  pthread_mutex_unlock (&dgram_live_count_mutex);
}
/**
 * dgram_live_decrement - Decrement live dgram count (thread-safe)
 */

static void
dgram_live_decrement (void)
{
  pthread_mutex_lock (&dgram_live_count_mutex);
  if (dgram_live_count > 0)
    dgram_live_count--;
  pthread_mutex_unlock (&dgram_live_count_mutex);
}
int
SocketDgram_debug_live_count (void)
{
  int count;
  pthread_mutex_lock (&dgram_live_count_mutex);
  count = dgram_live_count;
  pthread_mutex_unlock (&dgram_live_count_mutex);
  return count;
}
struct T
{
  SocketBase_T base; /* Embedded common base with fd, arena, endpoints,
                        timeouts, metrics */
  /* Datagram-specific fields can be added here if needed (e.g., multicast
   * groups, TTL cache) */
};

/**
 * validate_dgram_port
 * Raises: SocketDgram_Failed if port is invalid
 */

static void
validate_dgram_port (int port)
{
  SocketCommon_validate_port (port, SocketDgram_Failed);
}
/**
 * validate_dgram_hostname
 * Raises: SocketDgram_Failed if hostname too long
 */

static void
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
static int
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
static ssize_t
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
static ssize_t
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
static void
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
  return SocketCommon_get_family (socket->base, false,
                                  SocketDgram_Failed); /* No raise on fail */
}
T
SocketDgram_new (int domain, int protocol)
{
  SocketBase_T base = NULL;
  T sock;
  TRY base = SocketCommon_new_base (domain, SOCKET_DGRAM_TYPE, protocol);
  EXCEPT (Arena_Failed)
  RAISE_MODULE_ERROR (SocketDgram_Failed);
  EXCEPT (Socket_Failed)
  RAISE_MODULE_ERROR (SocketDgram_Failed);
  END_TRY;
  if (!base || !SocketBase_arena (base))
    {
      SOCKET_ERROR_MSG ("Invalid base from new_base (null arena)");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  sock = Arena_calloc (SocketBase_arena (base), 1, sizeof (struct T), __FILE__,
                       __LINE__);
  if (!sock)
    {
      SocketCommon_free_base (&base);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate dgram structure");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  sock->base = base;
  /* Datagram-specific initialization if needed e.g., ensure addrlen set,
   * but handled in base init */
  dgram_live_increment ();
  return sock;
}
void
SocketDgram_free (T *socket)
{
  T s = *socket;
  if (!s)
    return;
  assert (s);
  /* Datagram-specific cleanup if any (none currently) */
  dgram_live_decrement ();
  /* Common base cleanup */
  SocketCommon_free_base (&s->base);
  *socket = NULL;
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
ssize_t
SocketDgram_sendto (T socket, const void *buf, size_t len, const char *host,
                    int port)
{
  struct addrinfo *res = NULL;
  ssize_t sent;
  assert (socket);
  assert (buf);
  assert (len > 0);
  assert (host);
  validate_dgram_port (port);
  validate_dgram_hostname (host);
  resolve_sendto_address (host, port, &res);
  sent = perform_sendto (socket, buf, len, res);
  freeaddrinfo (res);
  return sent;
}
ssize_t
SocketDgram_recvfrom (T socket, void *buf, size_t len, char *host,
                      size_t host_len, int *port)
{
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof (addr);
  ssize_t received;
  assert (socket);
  assert (buf);
  assert (len > 0);
  received = perform_recvfrom (socket, buf, len, &addr, &addrlen);
  /* Get sender address and port if requested */
  if (host && host_len > 0 && port)
    {
      extract_sender_info (&addr, addrlen, host, host_len, port);
    }
  return received;
}
ssize_t
SocketDgram_send (T socket, const void *buf, size_t len)
{
  ssize_t sent;
  assert (socket);
  assert (buf);
  assert (len > 0);
  sent = send (SocketBase_fd (socket->base), buf, len, 0);
  if (sent < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      SOCKET_ERROR_FMT ("Failed to send datagram");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return sent;
}
ssize_t
SocketDgram_recv (T socket, void *buf, size_t len)
{
  ssize_t received;
  assert (socket);
  assert (buf);
  assert (len > 0);
  received = recv (SocketBase_fd (socket->base), buf, len, 0);
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
 * SocketDgram_sendall - Send all data (handles partial sends)
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (> 0)
 * Returns: Total bytes sent (always equals len on success)
 * Raises: SocketDgram_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until all data is sent or an error occurs.
 * For non-blocking sockets, returns 0 if would block (EAGAIN/EWOULDBLOCK).
 * Use SocketDgram_isconnected() to verify connection state before calling.
 */
ssize_t
SocketDgram_sendall (T socket, const void *buf, size_t len)
{
  const char *ptr = (const char *)buf;
  volatile size_t total_sent = 0;
  ssize_t sent;
  assert (socket);
  assert (buf);
  assert (len > 0);
  TRY while (total_sent < len)
  {
    sent = SocketDgram_send (socket, ptr + total_sent, len - total_sent);
    if (sent == 0)
      {
        /* Would block (EAGAIN / EWOULDBLOCK) - return partial progress */
        return (ssize_t)total_sent;
      }
    total_sent += (size_t)sent;
  }
  EXCEPT (SocketDgram_Failed)
  RERAISE;
  END_TRY;
  return (ssize_t)total_sent;
}

/**
 * SocketDgram_recvall - Receive all requested data (handles partial receives)
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (> 0)
 * Returns: Total bytes received (always equals len on success)
 * Raises: SocketDgram_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until len bytes are received or an error occurs.
 * For non-blocking sockets, returns 0 if would block (EAGAIN/EWOULDBLOCK).
 * Use SocketDgram_isconnected() to verify connection state before calling.
 */
ssize_t
SocketDgram_recvall (T socket, void *buf, size_t len)
{
  char *ptr = (char *)buf;
  volatile size_t total_received = 0;
  ssize_t received;
  assert (socket);
  assert (buf);
  assert (len > 0);
  TRY while (total_received < len)
  {
    received = SocketDgram_recv (socket, ptr + total_received,
                                 len - total_received);
    if (received == 0)
      {
        /* Would block (EAGAIN / EWOULDBLOCK) - return partial progress */
        return (ssize_t)total_received;
      }
    total_received += (size_t)received;
  }
  EXCEPT (SocketDgram_Failed)
  RERAISE;
  END_TRY;
  return (ssize_t)total_received;
}
/** dgram_calculate_total_iov_len (renamed) removed: use shared */
/** SocketCommon_calculate_total_iov_len */
/** dgram_advance_iov (renamed) removed: use shared
   SocketCommon_advance_iov */
/**
 * SocketDgram_sendv - Scatter/gather send (writev wrapper)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes sent (> 0) or 0 if would block
 * (EAGAIN/EWOULDBLOCK) Raises: SocketDgram_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: Sends data from multiple buffers in a single system call.
 * May send less than requested. Use SocketDgram_sendvall() for
 * guaranteed complete send.
 */

ssize_t
SocketDgram_sendv (T socket, const struct iovec *iov, int iovcnt)
{
  ssize_t result;
  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);
  /* Enforce UDP total payload sizing for sendv */
  size_t total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);
  if (total_len > SAFE_UDP_SIZE)
    {
      SOCKET_ERROR_MSG (
          "Sendv total %zu > SAFE_UDP_SIZE %zu (frag risk; max %zu)",
          total_len, SAFE_UDP_SIZE, UDP_MAX_PAYLOAD);
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  result = writev (SocketBase_fd (socket->base), iov, iovcnt);
  if (result < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      SOCKET_ERROR_FMT ("Scatter/gather send failed (iovcnt=%d)", iovcnt);
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return result;
}

/**
 * SocketDgram_recvv - Scatter/gather receive (readv wrapper)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes received (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: SocketDgram_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: Receives data into multiple buffers in a single system call.
 * May receive less than requested. Use SocketDgram_recvvall() for guaranteed
 * complete receive.
 */

ssize_t
SocketDgram_recvv (T socket, struct iovec *iov, int iovcnt)
{
  ssize_t result;
  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);
  result = readv (SocketBase_fd (socket->base), iov, iovcnt);
  if (result < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      SOCKET_ERROR_FMT ("Scatter/gather receive failed (iovcnt=%d)", iovcnt);
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return result;
}

/**
 * SocketDgram_sendvall - Scatter/gather send all (handles partial sends)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes sent (always equals sum of all iov_len on success)
 * Raises: SocketDgram_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until all data from all buffers is sent or an error occurs.
 * For non-blocking sockets, returns partial progress if would block.
 * Use SocketDgram_isconnected() to verify connection state before calling.
 */

ssize_t
SocketDgram_sendvall (T socket, const struct iovec *iov, int iovcnt)
{
  struct iovec *iov_copy = NULL;
  volatile size_t total_sent = 0;
  size_t total_len;
  ssize_t sent;
  int i;
  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);
  /* Calculate total length */
  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);
  /* Make a copy of iovec array for modification */
  iov_copy = calloc ((size_t)iovcnt, sizeof (struct iovec));
  if (!iov_copy)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate iovec copy");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  memcpy (iov_copy, iov, (size_t)iovcnt * sizeof (struct iovec));
  /* Make a copy of iovec array for modification */
  TRY while (total_sent < total_len)
  {
    /* Find first non-empty iovec */
    int active_iovcnt = 0;
    struct iovec *active_iov = NULL;
    for (i = 0; i < iovcnt; i++)
      {
        if (iov_copy[i].iov_len > 0)
          {
            active_iov = &iov_copy[i];
            active_iovcnt = iovcnt - i;
            break;
          }
      }
    if (active_iov == NULL)
      break;
    /* All buffers sent (partial) */
    sent = SocketDgram_sendv (socket, active_iov, active_iovcnt);
    if (sent == 0)
      {
        /* Would block (EAGAIN / EWOULDBLOCK) - return partial progress */
        free (iov_copy);
        return (ssize_t)total_sent;
      }
    total_sent += (size_t)sent;
    SocketCommon_advance_iov (iov_copy, iovcnt, (size_t)sent);
  }
  EXCEPT (SocketDgram_Failed)
  free (iov_copy);
  RERAISE;
  END_TRY;
  free (iov_copy);
  return (ssize_t)total_sent;
}

/**
 * SocketDgram_recvvall - Scatter/gather receive all (handles partial receives)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes received (always equals sum of all iov_len on success)
 * Raises: SocketDgram_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until all requested data is received into all buffers or an
 * error occurs. For non-blocking sockets, returns partial progress if would
 * block. Use SocketDgram_isconnected() to verify connection state before
 * calling.
 */

ssize_t
SocketDgram_recvvall (T socket, struct iovec *iov, int iovcnt)
{
  struct iovec *iov_copy = NULL;
  volatile size_t total_received = 0;
  size_t total_len;
  ssize_t received;
  int i;
  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);
  /* Calculate total length */
  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);
  /* Make a copy of iovec array for modification */
  iov_copy = calloc ((size_t)iovcnt, sizeof (struct iovec));
  if (!iov_copy)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate iovec copy");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  memcpy (iov_copy, iov, (size_t)iovcnt * sizeof (struct iovec));
  TRY while (total_received < total_len)
  {
    /* Find first non-empty iovec */
    int active_iovcnt = 0;
    struct iovec *active_iov = NULL;
    for (i = 0; i < iovcnt; i++)
      {
        if (iov_copy[i].iov_len > 0)
          {
            active_iov = &iov_copy[i];
            active_iovcnt = iovcnt - i;
            break;
          }
      }
    if (active_iov == NULL)
      break;
    /* All buffers filled (partial) */
    received = SocketDgram_recvv (socket, active_iov, active_iovcnt);
    if (received == 0)
      {
        /* Would block (EAGAIN / EWOULDBLOCK) - return partial progress: Copy
         * back partial data */
        for (i = 0; i < iovcnt; i++)
          {
            if (iov_copy[i].iov_base != iov[i].iov_base)
              {
                size_t copied
                    = (char *)iov_copy[i].iov_base - (char *)iov[i].iov_base;
                iov[i].iov_len -= copied;
                iov[i].iov_base = (char *)iov[i].iov_base + copied;
              }
          }
        free (iov_copy);
        return (ssize_t)total_received;
      }
    total_received += (size_t)received;
    SocketCommon_advance_iov (iov_copy, iovcnt, (size_t)received);
  }
  /* Copy back final data positions */
  for (i = 0; i < iovcnt; i++)
    {
      if (iov_copy[i].iov_base != iov[i].iov_base)
        {
          size_t copied
              = (char *)iov_copy[i].iov_base - (char *)iov[i].iov_base;
          iov[i].iov_len -= copied;
          iov[i].iov_base = (char *)iov[i].iov_base + copied;
        }
    }
  EXCEPT (SocketDgram_Failed)
  free (iov_copy);
  RERAISE;
  END_TRY;
  free (iov_copy);
  return (ssize_t)total_received;
}

void
SocketDgram_setnonblocking (T socket)
{
  assert (socket);
  SocketCommon_set_nonblock (socket->base, true, SocketDgram_Failed);
}

void
SocketDgram_setreuseaddr (T socket)
{
  assert (socket);
  SocketCommon_set_option_int (socket->base, SOCKET_SOL_SOCKET,
                               SOCKET_SO_REUSEADDR, 1, SocketDgram_Failed);
}

void
SocketDgram_setreuseport (T socket)
{
  assert (socket);
#if SOCKET_HAS_SO_REUSEPORT
  SocketCommon_set_option_int (socket->base, SOCKET_SOL_SOCKET,
                               SOCKET_SO_REUSEPORT, 1, SocketDgram_Failed);
#else /* SO_REUSEPORT not supported on this platform */
  SOCKET_ERROR_MSG ("SO_REUSEPORT not supported on this platform");
  RAISE_MODULE_ERROR (SocketDgram_Failed);
#endif
}

void
SocketDgram_setbroadcast (T socket, int enable)
{
  int optval = enable ? 1 : 0;
  assert (socket);
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                  SOCKET_SO_BROADCAST, &optval, sizeof (optval))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set SO_BROADCAST");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
}

void
SocketDgram_joinmulticast (T socket, const char *group, const char *interface)
{
  assert (socket);
  assert (group);
  SocketCommon_join_multicast (socket->base, group, interface,
                               SocketDgram_Failed);
}

void
SocketDgram_leavemulticast (T socket, const char *group, const char *interface)
{
  assert (socket);
  assert (group);
  SocketCommon_leave_multicast (socket->base, group, interface,
                                SocketDgram_Failed);
}

/**
 * get_socket_domain - Get socket domain/family (private helper)
 * Uses SO_DOMAIN on Linux, falls back to getsockname() on other platforms.
 * Raises: SocketDgram_Failed if getsockname() fails (only on error path).
 */

static int
get_socket_domain (T socket)
{
  return SocketCommon_get_family (
      socket->base, true,
      SocketDgram_Failed); /* raises on fail - comment removed to fix compiler
                              warning */
}

/**
 * set_ttl_by_family
 * Raises: SocketDgram_Failed on unsupported family or failure
 */

static void
set_ttl_by_family (T socket, int socket_family, int ttl)
{
  SocketCommon_set_ttl (socket->base, socket_family, ttl, SocketDgram_Failed);
}

/** validate_ttl_value - Validate TTL value range; raises on invalid */
static void
validate_ttl_value (int ttl)
{
  if (ttl < 1 || ttl > 255)
    {
      SOCKET_ERROR_MSG ("Invalid TTL value: %d (must be 1-255)", ttl);
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
}

void
SocketDgram_setttl (T socket, int ttl)
{
  int socket_family;
  assert (socket);
  validate_ttl_value (ttl);
  socket_family = get_socket_domain (socket);
  set_ttl_by_family (socket, socket_family, ttl);
}

void
SocketDgram_settimeout (T socket, int timeout_sec)
{
  struct timeval tv;
  assert (socket);
  tv.tv_sec = timeout_sec;
  tv.tv_usec = 0;
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                  SOCKET_SO_RCVTIMEO, &tv, sizeof (tv))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set receive timeout");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                  SOCKET_SO_SNDTIMEO, &tv, sizeof (tv))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set send timeout");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
}

int
SocketDgram_fd (const T socket)
{
  assert (socket);
  return SocketBase_fd (socket->base);
}

const char *
SocketDgram_getlocaladdr (const T socket)
{
  assert (socket);
  return socket->base->localaddr ? socket->base->localaddr : "(unknown)";
}

int
SocketDgram_getlocalport (const T socket)
{
  assert (socket);
  return socket->base->localport;
}

/**
 * SocketDgram_gettimeout - Get socket timeout
 * @socket: Socket to query
 * Returns: Timeout in seconds (0 if disabled)
 * Raises: SocketDgram_Failed on error
 * Note: Returns receive timeout (send timeout may differ)
 */

int
SocketDgram_gettimeout (T socket)
{
  struct timeval tv;
  assert (socket);
  if (SocketCommon_getoption_timeval (SocketBase_fd (socket->base),
                                      SOCKET_SOL_SOCKET, SOCKET_SO_RCVTIMEO,
                                      &tv, SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);
  return (int)tv.tv_sec;
}

/**
 * SocketDgram_getbroadcast - Get broadcast setting
 * @socket: Socket to query
 * Returns: 1 if broadcast is enabled, 0 if disabled
 * Raises: SocketDgram_Failed on error
 * Note: On macOS, getsockopt() may return 0 even after successfully setting
 * SO_BROADCAST to 1. This is a known macOS quirk - the option is set
 * correctly, but getsockopt() doesn't always reflect the set value.
 */

int
SocketDgram_getbroadcast (T socket)
{
  int broadcast = 0;
  assert (socket);
  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_SOL_SOCKET, SOCKET_SO_BROADCAST,
                                  &broadcast, SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);
  return broadcast;
}

/**
 * get_ipv4_ttl - Get IPv4 TTL
 * @socket: Socket to query
 * @ttl: Output pointer for TTL value
 * Raises: SocketDgram_Failed on failure
 */

static void
get_ipv4_ttl (T socket, int *ttl)
{
  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_IPPROTO_IP, SOCKET_IP_TTL, ttl,
                                  SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);
}

/**
 * get_ipv6_hop_limit - Get IPv6 hop limit
 * @socket: Socket to query
 * @ttl: Output pointer for hop limit value
 * Raises: SocketDgram_Failed on failure
 */

static void
get_ipv6_hop_limit (T socket, int *ttl)
{
  if (SocketCommon_getoption_int (
          SocketBase_fd (socket->base), SOCKET_IPPROTO_IPV6,
          SOCKET_IPV6_UNICAST_HOPS, ttl, SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);
}

/**
 * get_ttl_by_family - Get TTL by address family
 * @socket: Socket to query
 * @socket_family: Address family
 * @ttl: Output pointer for TTL value
 * Raises: SocketDgram_Failed on unsupported family or failure
 */

static void
get_ttl_by_family (T socket, int socket_family, int *ttl)
{
  if (socket_family == SOCKET_AF_INET)
    get_ipv4_ttl (socket, ttl);
  else if (socket_family == SOCKET_AF_INET6)
    get_ipv6_hop_limit (socket, ttl);
  else
    {
      SOCKET_ERROR_MSG ("Unsupported address family for TTL");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
}

/**
 * SocketDgram_getttl - Get time-to-live (hop limit)
 * @socket: Socket to query
 * Returns: TTL value (1 to SOCKET_MAX_TTL)
 * Raises: SocketDgram_Failed on error
 */

int
SocketDgram_getttl (T socket)
{
  int socket_family;
  int ttl = 0;
  assert (socket);
  socket_family = get_socket_domain (socket);
  get_ttl_by_family (socket, socket_family, &ttl);
  return ttl;
}

/**
 * SocketDgram_getrcvbuf - Get receive buffer size
 * @socket: Socket to query
 * Returns: Receive buffer size in bytes
 * Raises: SocketDgram_Failed on error
 */

int
SocketDgram_getrcvbuf (T socket)
{
  int bufsize = 0;
  assert (socket);
  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_SOL_SOCKET, SOCKET_SO_RCVBUF,
                                  &bufsize, SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);
  return bufsize;
}

/**
 * SocketDgram_getsndbuf - Get send buffer size
 * @socket: Socket to query
 * Returns: Send buffer size in bytes
 * Raises: SocketDgram_Failed on error
 */

int
SocketDgram_getsndbuf (T socket)
{
  int bufsize = 0;
  assert (socket);
  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_SOL_SOCKET, SOCKET_SO_SNDBUF,
                                  &bufsize, SocketDgram_Failed)
      < 0)
    RAISE_MODULE_ERROR (SocketDgram_Failed);
  return bufsize;
}

/**
 * SocketDgram_setcloexec - Control close-on-exec flag
 * @socket: Socket to modify
 * @enable: 1 to enable CLOEXEC, 0 to disable
 * Raises: SocketDgram_Failed on error
 */

void
SocketDgram_setcloexec (T socket, int enable)
{
  assert (socket);
  if (SocketCommon_setcloexec (SocketBase_fd (socket->base), enable) < 0)
    {
      SOCKET_ERROR_FMT ("Failed to %s close-on-exec flag",
                        enable ? "set" : "clear");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
}
/**
 * SocketDgram_isconnected - Check if datagram socket is connected
 * @socket: Socket to check
 * Returns: 1 if connected, 0 if not connected
 * Thread-safe: Yes (operates on single socket)
 * Note: Uses getpeername() to determine connection state.
 * For UDP sockets, "connected" means a default destination is set.
 */

int
SocketDgram_isconnected (T socket)
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof (addr);
  assert (socket);
  /* Use getpeername() to check connection state */
  if (getpeername (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
                   &len)
      == 0)
    return 1;
  /* Not connected or error occurred */
  if (errno == ENOTCONN)
    return 0;
  /* Other errors (EBADF, etc.) - treat as not connected */
  return 0;
}
/**
 * SocketDgram_isbound - Check if datagram socket is bound to an address
 * @socket: Socket to check
 * Returns: 1 if bound, 0 if not bound
 * Thread-safe: Yes (operates on single socket)
 * Note: Uses getsockname() to determine binding state.
 * A socket is bound if getsockname() succeeds and returns a valid address.
 * Wildcard addresses (0.0.0.0 or ::) still count as bound.
 */

int
SocketDgram_isbound (T socket)
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof (addr);
  assert (socket);
  /* Check if we have cached local address */
  if (socket->base->localaddr != NULL)
    return 1;
  /* Use getsockname() to check binding state */
  if (getsockname (SocketBase_fd (socket->base), (struct sockaddr *)&addr,
                   &len)
      == 0)
    {
      /* Socket is bound if getsockname succeeds. For IPv4/IPv6,
       * check if we have a valid port (address can be wildcard) */
      if (addr.ss_family == AF_INET)
        {
          struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
          if (sin->sin_port != 0)
            return 1;
        }
      else if (addr.ss_family == AF_INET6)
        {
          struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
          if (sin6->sin6_port != 0)
            return 1;
        }
    }
  return 0;
}
#undef T
