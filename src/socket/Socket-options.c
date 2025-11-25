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

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec (thread) Except_T SocketOptions_DetailedException;
#else
static __thread Except_T SocketOptions_DetailedException;
#endif

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e)                                                 \
  do                                                                          \
    {                                                                         \
      SocketOptions_DetailedException = (e);                                  \
      SocketOptions_DetailedException.reason = socket_error_buf;             \
      RAISE (SocketOptions_DetailedException);                               \
    }                                                                         \
  while (0)

/* Default timeouts are declared in SocketCommon.c */

/* Static timeout sanitizer function */
static int
sanitize_timeout (int timeout_ms)
{
  if (timeout_ms < 0)
    return 0;
  return timeout_ms;
}

/* ==================== Socket Flags ==================== */

void
Socket_setnonblocking (T socket)
{
  SocketCommon_set_nonblock (socket->base, true, Socket_Failed);
}

void
Socket_setreuseaddr (T socket)
{
  int opt = 1;

  assert (socket);

  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                  SOCKET_SO_REUSEADDR, &opt, sizeof (opt))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set SO_REUSEADDR");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

void
Socket_setreuseport (T socket)
{
  int opt = 1;

  assert (socket);

#if SOCKET_HAS_SO_REUSEPORT
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                  SOCKET_SO_REUSEPORT, &opt, sizeof (opt))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set SO_REUSEPORT");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#else
  (void)opt;
  SOCKET_ERROR_MSG ("SO_REUSEPORT not supported on this platform");
  RAISE_MODULE_ERROR (Socket_Failed);
#endif
}

void
Socket_setcloexec (T socket, int enable)
{
  assert (socket);

  if (SocketCommon_setcloexec (SocketBase_fd (socket->base), enable) < 0)
    {
      SOCKET_ERROR_FMT ("Failed to %s close-on-exec flag",
                        enable ? "set" : "clear");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

/* ==================== Timeout Operations ==================== */

void
Socket_settimeout (T socket, int timeout_sec)
{
  struct timeval tv;

  assert (socket);

  /* Validate timeout */
  if (timeout_sec < 0)
    {
      SOCKET_ERROR_MSG ("Invalid timeout value: %d (must be >= 0)",
                        timeout_sec);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  tv.tv_sec = timeout_sec;
  tv.tv_usec = 0;

  /* Set timeouts */
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                  SOCKET_SO_RCVTIMEO, &tv, sizeof (tv))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set receive timeout");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                  SOCKET_SO_SNDTIMEO, &tv, sizeof (tv))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set send timeout");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
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
      = sanitize_timeout (timeouts->connect_timeout_ms);
  socket->base->timeouts.dns_timeout_ms
      = sanitize_timeout (timeouts->dns_timeout_ms);
  socket->base->timeouts.operation_timeout_ms
      = sanitize_timeout (timeouts->operation_timeout_ms);
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

  local.connect_timeout_ms = sanitize_timeout (timeouts->connect_timeout_ms);
  local.dns_timeout_ms = sanitize_timeout (timeouts->dns_timeout_ms);
  local.operation_timeout_ms
      = sanitize_timeout (timeouts->operation_timeout_ms);

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