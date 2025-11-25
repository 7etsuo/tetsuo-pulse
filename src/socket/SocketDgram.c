/**
 * SocketDgram.c - UDP/datagram socket core
 *
 * Core lifecycle and basic I/O operations for UDP sockets. Provides fundamental
 * socket creation, destruction, and send/recv operations with proper error
 * handling and thread safety.
 *
 * Features:
 * - Socket lifecycle management (new/free/debug_live_count)
 * - Basic send/recv operations with timeout support
 * - Thread-safe live count tracking
 * - Exception-based error handling
 * - Memory management using Arena allocation
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

#undef T