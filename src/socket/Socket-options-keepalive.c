/**
 * Socket-options-keepalive.c - TCP keepalive configuration
 *
 * Implements TCP keepalive socket options including setting idle time,
 * interval, and count parameters. Provides comprehensive keepalive
 * configuration with proper validation and error handling.
 *
 * Features:
 * - Keepalive parameter validation
 * - Keepalive enable/disable operations
 * - Individual keepalive parameter setting (idle, interval, count)
 * - Keepalive parameter retrieval
 * - Platform-specific TCP keepalive options
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

/* ==================== Keepalive Operations ==================== */

static void
validate_keepalive_parameters (int idle, int interval, int count)
{
  if (idle <= 0 || interval <= 0 || count <= 0)
    {
      SOCKET_ERROR_MSG ("Invalid keepalive parameters (idle=%d, interval=%d, "
                        "count=%d): all must be > 0",
                        idle, interval, count);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

static void
enable_socket_keepalive (T socket)
{
  int opt = 1;
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_SOL_SOCKET,
                  SOCKET_SO_KEEPALIVE, &opt, sizeof (opt))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to enable keepalive");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
}

static void
set_keepalive_idle_time (T socket, int idle)
{
#ifdef TCP_KEEPIDLE
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_KEEPIDLE, &idle, sizeof (idle))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set keepalive idle time");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#endif
}

static void
set_keepalive_interval (T socket, int interval)
{
#ifdef TCP_KEEPINTVL
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_KEEPINTVL, &interval, sizeof (interval))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set keepalive interval");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#endif
}

static void
set_keepalive_count (T socket, int count)
{
#ifdef TCP_KEEPCNT
  if (setsockopt (SocketBase_fd (socket->base), SOCKET_IPPROTO_TCP,
                  SOCKET_TCP_KEEPCNT, &count, sizeof (count))
      < 0)
    {
      SOCKET_ERROR_FMT ("Failed to set keepalive count");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
#endif
}

void
Socket_setkeepalive (T socket, int idle, int interval, int count)
{
  assert (socket);
  validate_keepalive_parameters (idle, interval, count);
  enable_socket_keepalive (socket);
  set_keepalive_idle_time (socket, idle);
  set_keepalive_interval (socket, interval);
  set_keepalive_count (socket, count);
}

void
Socket_getkeepalive (T socket, int *idle, int *interval, int *count)
{
  int keepalive_enabled = 0;

  assert (socket);
  assert (idle);
  assert (interval);
  assert (count);

  /* Get SO_KEEPALIVE flag */
  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_SOL_SOCKET, SOCKET_SO_KEEPALIVE,
                                  &keepalive_enabled, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);

  if (!keepalive_enabled)
    {
      *idle = 0;
      *interval = 0;
      *count = 0;
      return;
    }

    /* Get TCP_KEEPIDLE */
#ifdef TCP_KEEPIDLE
  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPIDLE,
                                  idle, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);
#else
  *idle = 0;
#endif

    /* Get TCP_KEEPINTVL */
#ifdef TCP_KEEPINTVL
  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPINTVL,
                                  interval, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);
#else
  *interval = 0;
#endif

    /* Get TCP_KEEPCNT */
#ifdef TCP_KEEPCNT
  if (SocketCommon_getoption_int (SocketBase_fd (socket->base),
                                  SOCKET_IPPROTO_TCP, SOCKET_TCP_KEEPCNT,
                                  count, Socket_Failed)
      < 0)
    RAISE_MODULE_ERROR (Socket_Failed);
#else
  *count = 0;
#endif
}

#undef T
