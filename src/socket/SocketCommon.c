/**
 * SocketCommon.c - Common utilities shared between Socket and SocketDgram
 * modules - Core functionality
 *
 * This file contains core functionality that remains after splitting larger
 * functions into separate modules. It includes base lifecycle management,
 * global defaults, and essential accessors.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
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

/* Global defaults for socket timeouts - shared across modules */
SocketTimeouts_T socket_default_timeouts
    = { .connect_timeout_ms = SOCKET_DEFAULT_CONNECT_TIMEOUT_MS,
        .dns_timeout_ms = SOCKET_DEFAULT_DNS_TIMEOUT_MS,
        .operation_timeout_ms = SOCKET_DEFAULT_OPERATION_TIMEOUT_MS };
pthread_mutex_t socket_default_timeouts_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Forward declarations for exception types */
extern const Except_T Socket_Failed;
extern const Except_T SocketDgram_Failed;

const Except_T SocketCommon_Failed
    = { &SocketCommon_Failed, "SocketCommon operation failed" };

/* Thread-local exception for detailed error messages */
/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketCommon);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketCommon, e)

/* Static timeout sanitizer function */
static int
sanitize_timeout (int timeout_ms)
{
  if (timeout_ms < 0)
    return 0;
  return timeout_ms;
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
  Except_T exc_type = Socket_Failed;

  arena = Arena_new ();
  /* Note: Arena_new either succeeds or raises Arena_Failed; never returns
   * NULL */

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

  /* Invalidate caller pointer before disposing arena to avoid writing to
   * freed memory. Copy arena pointer to local to safely dispose after
   * potential free of base struct. */
  *base_ptr = NULL;
  Arena_T arena_to_dispose = base->arena;
  Arena_dispose (&arena_to_dispose);
}

/**
 * SocketCommon_init_base - Initialize base structure fields
 * @base: Pointer to base to initialize
 * @fd: File descriptor to assign
 * @domain: Domain
 * @type: Type
 * @protocol: Protocol
 * Performs common initialization: set fd, clear addrs, set defaults for
 * timeouts/metrics Raises: exc_type on any error (though unlikely since no
 * alloc)
 */
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

  /* Copy default timeouts thread-safe */
  pthread_mutex_lock (&socket_default_timeouts_mutex);
  base->timeouts = socket_default_timeouts;
  pthread_mutex_unlock (&socket_default_timeouts_mutex);

  /* Metrics already zero from calloc */

  /* Don't update local endpoint during initialization - let it be lazy */
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

/* Accessor functions */

/**
 * SocketBase_fd - Get file descriptor from base
 * @base: Socket base
 * Returns: File descriptor or -1 if base is NULL
 */
int
SocketBase_fd (SocketBase_T base)
{
  return base ? base->fd : -1;
}

/**
 * SocketBase_arena - Get arena from base
 * @base: Socket base
 * Returns: Arena or NULL if base is NULL
 */
Arena_T
SocketBase_arena (SocketBase_T base)
{
  return base ? base->arena : NULL;
}

/**
 * SocketBase_domain - Get domain from base
 * @base: Socket base
 * Returns: Domain or AF_UNSPEC if base is NULL
 */
int
SocketBase_domain (SocketBase_T base)
{
  return base ? base->domain : AF_UNSPEC;
}

/**
 * SocketBase_set_timeouts - Set timeouts for base
 * @base: Socket base
 * @timeouts: Timeout configuration
 */
void
SocketBase_set_timeouts (SocketBase_T base, const SocketTimeouts_T *timeouts)
{
  if (base && timeouts)
    base->timeouts = *timeouts;
}

/**
 * SocketBase_update_local_endpoint - Update local endpoint info
 * @base: Base to update
 * Stub implementation that only calls getsockname to check if socket is bound,
 * but doesn't populate formatted fields. This avoids interfering with
 * Socket_isbound/Socket_islistening logic for unbound sockets.
 * Thread-safe: Yes (operates on single socket)
 */
void
SocketBase_update_local_endpoint (SocketBase_T base)
{
  socklen_t len = sizeof (base->local_addr);
  if (getsockname (base->fd, (struct sockaddr *)&base->local_addr, &len) == 0)
    {
      base->local_addrlen = len;
      /* Don't populate formatted fields here - let them be populated lazily
       * when actually requested (e.g., Socket_getlocaladdr) */
    }
  else
    {
      SOCKET_ERROR_MSG ("Failed to update local endpoint: %s",
                        strerror (errno));
      /* Reset all local endpoint fields on failure */
      memset (&base->local_addr, 0, sizeof (base->local_addr));
      base->local_addrlen = 0;
      base->localaddr = NULL;
      base->localport = 0;
    }
}

/**
 * SocketCommon_timeouts_getdefaults - Get global default timeouts
 * @timeouts: Output timeout structure containing current defaults
 * Returns: Nothing
 */
void
SocketCommon_timeouts_getdefaults (SocketTimeouts_T *timeouts)
{
  assert (timeouts);

  /* Thread-safe copy of default timeouts */
  pthread_mutex_lock (&socket_default_timeouts_mutex);
  *timeouts = socket_default_timeouts;
  pthread_mutex_unlock (&socket_default_timeouts_mutex);
}

/**
 * SocketCommon_timeouts_setdefaults - Set global default timeouts
 * @timeouts: New default timeout configuration
 * Returns: Nothing
 */
void
SocketCommon_timeouts_setdefaults (const SocketTimeouts_T *timeouts)
{
  SocketTimeouts_T local;

  assert (timeouts);

  /* Thread-safe read-modify-write of default timeouts */
  pthread_mutex_lock (&socket_default_timeouts_mutex);
  local = socket_default_timeouts;
  pthread_mutex_unlock (&socket_default_timeouts_mutex);

  local.connect_timeout_ms = sanitize_timeout (timeouts->connect_timeout_ms);
  local.dns_timeout_ms = sanitize_timeout (timeouts->dns_timeout_ms);
  local.operation_timeout_ms
      = sanitize_timeout (timeouts->operation_timeout_ms);

  pthread_mutex_lock (&socket_default_timeouts_mutex);
  socket_default_timeouts = local;
  pthread_mutex_unlock (&socket_default_timeouts_mutex);
}

