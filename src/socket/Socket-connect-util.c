/**
 * Socket-connect-util.c - Socket connect utility functions
 *
 * Implements helper functions for socket connect operations including
 * error handling, success handling, and endpoint caching.
 *
 * Note: Main connect operations are in Socket-connect.c
 * Note: Poll/wait helpers are in Socket-connect-poll.c
 */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "core/SocketEvents.h"
#include "core/SocketMetrics.h"
#include "socket/Socket-private.h"
#include "socket/Socket.h"
#include "socket/SocketCommon.h"

#define T Socket_T

/* ==================== Connect Error Handling ==================== */

/**
 * socket_get_connect_error_msg - Get error prefix for connect failure
 * @saved_errno: Saved errno value
 *
 * Returns: Error message prefix string
 * Thread-safe: Yes (stateless)
 */
const char *
socket_get_connect_error_msg (int saved_errno)
{
  switch (saved_errno)
    {
    case ECONNREFUSED:
      return SOCKET_ECONNREFUSED;
    case ENETUNREACH:
      return SOCKET_ENETUNREACH;
    case ETIMEDOUT:
      return SOCKET_ETIMEDOUT;
    default:
      return "Connect failed";
    }
}

/**
 * socket_handle_connect_error - Handle and log connect error
 * @host: Hostname for error message
 * @port: Port number for error message
 *
 * Thread-safe: Yes (metrics are thread-safe)
 */
void
socket_handle_connect_error (const char *host, int port)
{
  SocketMetrics_increment (SOCKET_METRIC_SOCKET_CONNECT_FAILURE, 1);
  SOCKET_ERROR_FMT ("%s: %.*s:%d", socket_get_connect_error_msg (errno),
                    SOCKET_ERROR_MAX_HOSTNAME, host, port);
}

/**
 * socket_is_retriable_connect_error - Check if connect error is retriable
 * @saved_errno: Saved errno value
 *
 * Returns: 1 if error is retriable (caller should not raise), 0 otherwise
 * Thread-safe: Yes (stateless)
 */
int
socket_is_retriable_connect_error (int saved_errno)
{
  return saved_errno == ECONNREFUSED || saved_errno == ETIMEDOUT
         || saved_errno == ENETUNREACH || saved_errno == EHOSTUNREACH
         || saved_errno == ECONNABORTED;
}

/* ==================== Connect Success Handling ==================== */

/**
 * socket_cache_remote_endpoint - Cache remote endpoint information
 * @socket: Socket instance
 *
 * Caches remote address and port strings in arena. Sets defensive
 * NULL values on failure.
 * Thread-safe: No (operates on single socket)
 */
void
socket_cache_remote_endpoint (T socket)
{
  if (SocketCommon_cache_endpoint (
          SocketBase_arena (socket->base),
          (struct sockaddr *)&socket->base->remote_addr,
          socket->base->remote_addrlen, &socket->base->remoteaddr,
          &socket->base->remoteport)
      != 0)
    {
      socket->base->remoteaddr = NULL;
      socket->base->remoteport = 0;
    }
}

/**
 * socket_emit_connect_event - Emit socket connect event
 * @socket: Socket instance
 *
 * Emits connect event with local and remote endpoint information.
 * Thread-safe: Yes (event system is thread-safe)
 */
void
socket_emit_connect_event (T socket)
{
  SocketEvent_emit_connect (Socket_fd (socket),
                            SocketBase_remoteaddr (socket->base),
                            SocketBase_remoteport (socket->base),
                            SocketBase_localaddr (socket->base),
                            SocketBase_localport (socket->base));
}

/**
 * socket_handle_successful_connect - Handle successful connection
 * @socket: Socket instance
 *
 * Updates metrics, endpoints, and emits connect event.
 * Thread-safe: Yes (individual operations are thread-safe)
 */
void
socket_handle_successful_connect (T socket)
{
  SocketMetrics_increment (SOCKET_METRIC_SOCKET_CONNECT_SUCCESS, 1);
  SocketCommon_update_local_endpoint (socket->base);
  socket_cache_remote_endpoint (socket);
  socket_emit_connect_event (socket);
}

#undef T

