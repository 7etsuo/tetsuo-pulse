/**
 * Socket-options.c - Socket flag and timeout options
 *
 * Implements socket flag management (non-blocking, reuseaddr, reuseport,
 * cloexec) and timeout configuration including socket timeouts, timeout
 * API functions, and shutdown operations.
 *
 * Features:
 * - Socket flag operations (non-blocking, reuseaddr, reuseport, cloexec)
 * - Timeout configuration (set/get timeout)
 * - Socket timeout API (timeouts get/set/defaults)
 * - Socket shutdown operations
 * - Thread-safe timeout management
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <assert.h>
#include <unistd.h>

#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/Socket.h"
#include "core/SocketMetrics.h"
#include "socket/Socket-private.h"

#define T Socket_T

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketOptions);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketOptions, e)

/* Default timeouts are declared in SocketCommon.c */

/* sanitize_timeout is defined in SocketCommon.c - use extern declaration */
extern int socketcommon_sanitize_timeout (int timeout_ms);

/* ==================== Socket Flags ==================== */

void
Socket_setnonblocking (T socket)
{
  SocketCommon_set_nonblock (socket->base, true, Socket_Failed);
}

void
Socket_setreuseaddr (T socket)
{
  assert (socket);
  SocketCommon_setreuseaddr (socket->base, Socket_Failed);
}

void
Socket_setreuseport (T socket)
{
  assert (socket);
  SocketCommon_setreuseport (socket->base, Socket_Failed);
}

void
Socket_setcloexec (T socket, int enable)
{
  assert (socket);
  SocketCommon_setcloexec_with_error (socket->base, enable, Socket_Failed);
}

/* ==================== Timeout Operations ==================== */

void
Socket_settimeout (T socket, int timeout_sec)
{
  assert (socket);
  SocketCommon_settimeout (socket->base, timeout_sec, Socket_Failed);
}

int
Socket_gettimeout (T socket)
{
  struct timeval tv;

  assert (socket);

  if (SocketCommon_getoption_timeval (SocketBase_fd (socket->base),
                                      SOCKET_SOL_SOCKET, SOCKET_SO_RCVTIMEO,
                                      &tv, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  return (int)tv.tv_sec;
}

/* ==================== Socket Timeouts API ==================== */

void
Socket_timeouts_get (const T socket, SocketTimeouts_T *timeouts)
{
  assert (socket);
  assert (timeouts);

  *timeouts = socket->base->timeouts;
}

void
Socket_timeouts_set (T socket, const SocketTimeouts_T *timeouts)
{
  assert (socket);

  if (timeouts == NULL)
    {
      /* Thread-safe copy of default timeouts */
      pthread_mutex_lock (&socket_default_timeouts_mutex);
      socket->base->timeouts = socket_default_timeouts;
      pthread_mutex_unlock (&socket_default_timeouts_mutex);
      return;
    }

  socket->base->timeouts.connect_timeout_ms
      = socketcommon_sanitize_timeout (timeouts->connect_timeout_ms);
  socket->base->timeouts.dns_timeout_ms
      = socketcommon_sanitize_timeout (timeouts->dns_timeout_ms);
  socket->base->timeouts.operation_timeout_ms
      = socketcommon_sanitize_timeout (timeouts->operation_timeout_ms);
}

void
Socket_timeouts_getdefaults (SocketTimeouts_T *timeouts)
{
  assert (timeouts);

  /* Thread-safe copy of default timeouts */
  pthread_mutex_lock (&socket_default_timeouts_mutex);
  *timeouts = socket_default_timeouts;
  pthread_mutex_unlock (&socket_default_timeouts_mutex);
}

void
Socket_timeouts_setdefaults (const SocketTimeouts_T *timeouts)
{
  SocketTimeouts_T local;

  assert (timeouts);

  /* Thread-safe read-modify-write of default timeouts */
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

/* ==================== Shutdown ==================== */

static int
socket_shutdown_mode_valid (int how)
{
  return (how == SOCKET_SHUT_RD || how == SOCKET_SHUT_WR
          || how == SOCKET_SHUT_RDWR);
}

void
Socket_shutdown (T socket, int how)
{
  assert (socket);

  if (!socket_shutdown_mode_valid (how))
    {
      SOCKET_ERROR_MSG ("Invalid shutdown mode: %d", how);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  if (shutdown (SocketBase_fd (socket->base), how) < 0)
    {
      if (errno == ENOTCONN)
        SOCKET_ERROR_FMT ("Socket is not connected (shutdown mode=%d)", how);
      else
        SOCKET_ERROR_FMT ("Failed to shutdown socket (mode=%d)", how);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  SocketMetrics_increment (SOCKET_METRIC_SOCKET_SHUTDOWN_CALL, 1);
}

#undef T