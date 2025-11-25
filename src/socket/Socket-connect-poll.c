/**
 * Socket-connect-poll.c - Poll/wait helpers for non-blocking connect
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * This file contains helper functions for waiting on non-blocking connect
 * operations using poll(). Separated from Socket-connect.c to keep files
 * under 400 lines.
 *
 * Features:
 * - Non-blocking connect wait with timeout
 * - Socket error checking after async connect
 * - Blocking mode restoration
 * - Poll with EINTR retry handling
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "core/SocketLog.h"
#include "socket/Socket-private.h"
#include "socket/SocketCommon-private.h"

#define T Socket_T

/**
 * socket_wait_poll_with_retry - Wait for socket writability with EINTR retry
 * @fd: File descriptor
 * @timeout_ms: Timeout in milliseconds
 *
 * Returns: poll() result (0 on timeout, >0 on ready, -1 on error)
 * Thread-safe: Yes (operates on single fd)
 */
int
socket_wait_poll_with_retry (int fd, int timeout_ms)
{
  struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
  int result;

  while ((result = poll (&pfd, 1, timeout_ms)) < 0 && errno == EINTR)
    continue;

  return result;
}

/**
 * socket_check_connect_error - Check SO_ERROR after async connect
 * @fd: File descriptor
 *
 * Returns: 0 on success, -1 on error (sets errno)
 * Thread-safe: Yes (operates on single fd)
 */
int
socket_check_connect_error (int fd)
{
  int error = 0;
  socklen_t error_len = sizeof (error);

  if (getsockopt (fd, SOCKET_SOL_SOCKET, SO_ERROR, &error, &error_len) < 0)
    return -1;

  if (error != 0)
    {
      errno = error;
      return -1;
    }

  return 0;
}

/**
 * socket_wait_for_connect - Wait for connect to complete with timeout
 * @socket: Socket instance
 * @timeout_ms: Timeout in milliseconds
 *
 * Returns: 0 on success, -1 on failure (sets errno)
 * Thread-safe: Yes (operates on single socket)
 */
int
socket_wait_for_connect (T socket, int timeout_ms)
{
  assert (socket);
  assert (timeout_ms >= 0);

  int fd = SocketBase_fd (socket->base);
  int result = socket_wait_poll_with_retry (fd, timeout_ms);

  if (result < 0)
    return -1;

  if (result == 0)
    {
      errno = ETIMEDOUT;
      return -1;
    }

  return socket_check_connect_error (fd);
}

/**
 * socket_restore_blocking_mode - Restore socket blocking mode after operation
 * @socket: Socket instance
 * @original_flags: Original fcntl flags to restore
 * @operation: Operation name for logging
 *
 * Thread-safe: Yes (operates on single socket)
 */
void
socket_restore_blocking_mode (T socket, int original_flags,
                              const char *operation)
{
  if (fcntl (SocketBase_fd (socket->base), F_SETFL, original_flags) < 0)
    {
      SocketLog_emitf (SOCKET_LOG_WARN, "SocketConnect",
                       "Failed to restore blocking mode after %s "
                       "(fd=%d, errno=%d): %s",
                       operation, SocketBase_fd (socket->base), errno,
                       strerror (errno));
    }
}

/**
 * socket_connect_with_poll_wait - Perform connect with timeout using poll
 * @socket: Socket instance
 * @addr: Address to connect to
 * @addrlen: Address length
 * @timeout_ms: Timeout in milliseconds
 *
 * Returns: 0 on success, -1 on failure
 * Thread-safe: Yes (operates on single socket)
 */
int
socket_connect_with_poll_wait (T socket, const struct sockaddr *addr,
                               socklen_t addrlen, int timeout_ms)
{
  if (connect (SocketBase_fd (socket->base), addr, addrlen) == 0
      || errno == EISCONN)
    {
      memcpy (&socket->base->remote_addr, addr, addrlen);
      socket->base->remote_addrlen = addrlen;
      return 0;
    }

  int saved_errno = errno;

  if (saved_errno == EINPROGRESS || saved_errno == EINTR)
    {
      if (socket_wait_for_connect (socket, timeout_ms) == 0)
        {
          memcpy (&socket->base->remote_addr, addr, addrlen);
          socket->base->remote_addrlen = addrlen;
          return 0;
        }
      saved_errno = errno;
    }

  errno = saved_errno;
  return -1;
}

#undef T

