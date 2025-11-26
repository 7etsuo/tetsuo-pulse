/**
 * SocketCommon.c - Common utilities shared between Socket and SocketDgram
 *
 * Consolidated module containing core functionality, bind helpers, I/O vector
 * utilities, and address resolution utilities.
 *
 * Features:
 * - Base lifecycle management (new/free/init)
 * - Global timeout defaults
 * - Accessor functions
 * - Bind operation helpers and error handling
 * - I/O vector operations with overflow protection
 * - Address resolution utilities
 * - Endpoint caching
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig.h"
#define SOCKET_LOG_COMPONENT "SocketCommon"
#include "core/SocketError.h"
#include "core/SocketLog.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

/* Global defaults for socket timeouts - shared across modules */
SocketTimeouts_T socket_default_timeouts
    = { .connect_timeout_ms = SOCKET_DEFAULT_CONNECT_TIMEOUT_MS,
        .dns_timeout_ms = SOCKET_DEFAULT_DNS_TIMEOUT_MS,
        .operation_timeout_ms = SOCKET_DEFAULT_OPERATION_TIMEOUT_MS };
pthread_mutex_t socket_default_timeouts_mutex = PTHREAD_MUTEX_INITIALIZER;

const Except_T SocketCommon_Failed
    = { &SocketCommon_Failed, "SocketCommon operation failed" };

SOCKET_DECLARE_MODULE_EXCEPTION (SocketCommon);

#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketCommon, e)

/* ==================== Timeout Utilities ==================== */

int
socketcommon_sanitize_timeout (int timeout_ms)
{
  if (timeout_ms < 0)
    return 0;
  return timeout_ms;
}

/* ==================== Base Lifecycle ==================== */

SocketBase_T
SocketCommon_new_base (int domain, int type, int protocol)
{
  Arena_T arena;
  SocketBase_T base;
  int fd;
  Except_T exc_type = Socket_Failed;

  arena = Arena_new ();

  base = Arena_calloc (arena, 1, sizeof (struct SocketBase_T), __FILE__,
                       __LINE__);
  if (!base)
    {
      Arena_dispose (&arena);
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate base structure");
      RAISE_MODULE_ERROR (exc_type);
    }

  base->arena = arena;

  fd = SocketCommon_create_fd (domain, type, protocol, exc_type);
  SocketCommon_init_base (base, fd, domain, type, protocol, exc_type);

  return base;
}

void
SocketCommon_free_base (SocketBase_T *base_ptr)
{
  SocketBase_T base = *base_ptr;
  if (!base)
    return;

  if (base->fd >= 0)
    {
      int fd = base->fd;
      base->fd = -1;
      SAFE_CLOSE (fd);
    }

  *base_ptr = NULL;
  Arena_T arena_to_dispose = base->arena;
  Arena_dispose (&arena_to_dispose);
}

void
SocketCommon_init_base (SocketBase_T base, int fd, int domain, int type,
                        int protocol, Except_T exc_type)
{
  (void)exc_type;
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

  pthread_mutex_lock (&socket_default_timeouts_mutex);
  base->timeouts = socket_default_timeouts;
  pthread_mutex_unlock (&socket_default_timeouts_mutex);
}

void
SocketCommon_update_local_endpoint (SocketBase_T base)
{
  struct sockaddr_storage local;
  socklen_t len = sizeof (local);

  if (getsockname (SocketBase_fd (base), (struct sockaddr *)&local, &len) < 0)
    {
      SOCKET_ERROR_MSG ("Failed to update local endpoint: %s",
                        strerror (errno));
      memset (&base->local_addr, 0, sizeof (base->local_addr));
      base->local_addrlen = 0;
      base->localaddr = NULL;
      base->localport = 0;
      return;
    }

  base->local_addr = local;
  base->local_addrlen = len;

  if (SocketCommon_cache_endpoint (SocketBase_arena (base),
                                   (struct sockaddr *)&local, len,
                                   &base->localaddr, &base->localport)
      != 0)
    {
      base->localaddr = NULL;
      base->localport = 0;
    }
}

/* ==================== Accessor Functions ==================== */

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

void
SocketCommon_timeouts_getdefaults (SocketTimeouts_T *timeouts)
{
  assert (timeouts);

  pthread_mutex_lock (&socket_default_timeouts_mutex);
  *timeouts = socket_default_timeouts;
  pthread_mutex_unlock (&socket_default_timeouts_mutex);
}

void
SocketCommon_timeouts_setdefaults (const SocketTimeouts_T *timeouts)
{
  SocketTimeouts_T local;

  assert (timeouts);

  pthread_mutex_lock (&socket_default_timeouts_mutex);
  local = socket_default_timeouts;
  pthread_mutex_unlock (&socket_default_timeouts_mutex);

  local.connect_timeout_ms
      = socketcommon_sanitize_timeout (timeouts->connect_timeout_ms);
  local.dns_timeout_ms
      = socketcommon_sanitize_timeout (timeouts->dns_timeout_ms);
  local.operation_timeout_ms
      = socketcommon_sanitize_timeout (timeouts->operation_timeout_ms);

  pthread_mutex_lock (&socket_default_timeouts_mutex);
  socket_default_timeouts = local;
  pthread_mutex_unlock (&socket_default_timeouts_mutex);
}

/* ==================== Address Resolution Hints ==================== */

void
SocketCommon_setup_hints (struct addrinfo *hints, int socktype, int flags)
{
  memset (hints, 0, sizeof (*hints));
  hints->ai_family = SOCKET_AF_UNSPEC;
  hints->ai_socktype = socktype;
  hints->ai_flags = flags;
  hints->ai_protocol = 0;
}

/* ==================== Bind Operations ==================== */

int
SocketCommon_try_bind_address (SocketBase_T base, const struct sockaddr *addr,
                               socklen_t addrlen, Except_T exc_type)
{
  int fd = SocketBase_fd (base);
  int ret = bind (fd, addr, addrlen);
  if (ret == 0)
    {
      SocketCommon_update_local_endpoint (base);
      return 0;
    }

  SocketCommon_handle_bind_error (errno, "unknown addr", exc_type);
  return -1;
}

int
SocketCommon_try_bind_resolved_addresses (SocketBase_T base,
                                          struct addrinfo *res, int family,
                                          Except_T exc_type)
{
  struct addrinfo *rp;

  SocketCommon_set_option_int (base, SOL_SOCKET, SO_REUSEADDR, 1, exc_type);

  for (rp = res; rp != NULL; rp = rp->ai_next)
    {
      if (family != AF_UNSPEC && rp->ai_family != family)
        continue;

      if (SocketCommon_try_bind_address (base, rp->ai_addr, rp->ai_addrlen,
                                         exc_type)
          == 0)
        {
          return 0;
        }
    }

  SOCKET_ERROR_MSG ("Bind failed for all resolved addresses");
  RAISE_MODULE_ERROR (exc_type);
  return -1;
}

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
  return -1;
}

void
SocketCommon_format_bind_error (const char *host, int port)
{
  const char *addr_str = host ? host : "any";

  switch (errno)
    {
    case EADDRINUSE:
      SOCKET_ERROR_MSG ("Address %s:%d already in use", addr_str, port);
      break;
    case EADDRNOTAVAIL:
      SOCKET_ERROR_MSG ("Address %s not available", addr_str);
      break;
    case EACCES:
    case EPERM:
      SOCKET_ERROR_MSG ("Permission denied binding to %s:%d", addr_str, port);
      break;
    case EAFNOSUPPORT:
      SOCKET_ERROR_MSG ("Address family not supported for %s", addr_str);
      break;
    default:
      SOCKET_ERROR_FMT ("Bind failed for %s:%d", addr_str, port);
      break;
    }
}

/* ==================== I/O Vector Operations ==================== */

size_t
SocketCommon_calculate_total_iov_len (const struct iovec *iov, int iovcnt)
{
  size_t total = 0;
  int i;

  if (!iov || iovcnt <= 0 || iovcnt > IOV_MAX)
    {
      SOCKET_ERROR_FMT ("Invalid iov params: iov=%p iovcnt=%d", (void *)iov,
                        iovcnt);
      RAISE_MODULE_ERROR (SocketCommon_Failed);
    }

  for (i = 0; i < iovcnt; i++)
    {
      if (iov[i].iov_len > SIZE_MAX - total)
        {
          SOCKET_ERROR_FMT ("iov[%d] overflow: total=%zu + len=%zu > SIZE_MAX",
                            i, total, iov[i].iov_len);
          RAISE_MODULE_ERROR (SocketCommon_Failed);
        }
      total += iov[i].iov_len;
    }

  return total;
}

void
SocketCommon_advance_iov (struct iovec *iov, int iovcnt, size_t bytes)
{
  size_t remaining = bytes;
  int i;
  size_t total_len;

  if (!iov || iovcnt <= 0 || iovcnt > IOV_MAX)
    {
      SOCKET_ERROR_FMT ("Invalid advance params: iov=%p iovcnt=%d bytes=%zu",
                        (void *)iov, iovcnt, bytes);
      RAISE_MODULE_ERROR (SocketCommon_Failed);
    }

  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);

  if (bytes > total_len)
    {
      SOCKET_ERROR_FMT ("Advance too far: bytes=%zu > total=%zu", bytes,
                        total_len);
      RAISE_MODULE_ERROR (SocketCommon_Failed);
    }

  for (i = 0; i < iovcnt && remaining > 0; i++)
    {
      if (remaining >= iov[i].iov_len)
        {
          remaining -= iov[i].iov_len;
          iov[i].iov_base = NULL;
          iov[i].iov_len = 0;
        }
      else
        {
          iov[i].iov_base = (char *)iov[i].iov_base + remaining;
          iov[i].iov_len -= remaining;
          remaining = 0;
        }
    }
}

/* ==================== Address Utilities ==================== */

const char *
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

void
socketcommon_convert_port_to_string (int port, char *port_str, size_t bufsize)
{
  int result;

  result = snprintf (port_str, bufsize, "%d", port);
  assert (result > 0 && result < (int)bufsize);
}

void
SocketCommon_validate_hostname (const char *host, Except_T exception_type)
{
  if (socketcommon_validate_hostname_internal (host, 1, exception_type) != 0)
    return;
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
