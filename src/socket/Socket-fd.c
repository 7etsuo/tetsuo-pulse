/**
 * Socket-fd.c - File Descriptor Passing (SCM_RIGHTS)
 *
 * Implements file descriptor passing over Unix domain sockets using
 * SCM_RIGHTS ancillary data. This enables nginx-style worker process models,
 * zero-downtime restarts, and process isolation architectures.
 *
 * Features:
 * - Single FD passing (Socket_sendfd/Socket_recvfd)
 * - Multiple FD passing (Socket_sendfds/Socket_recvfds)
 * - Non-blocking support (returns 0 on EAGAIN/EWOULDBLOCK)
 * - Thread-safe error reporting
 * - Resource safety (closes leaked FDs on error)
 *
 * PLATFORM REQUIREMENTS:
 * - POSIX-compliant Unix domain sockets
 * - NOT available on Windows
 *
 * Reference: POSIX.1-2008, sendmsg/recvmsg with SCM_RIGHTS
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "core/Except.h"
#include "core/SocketConfig.h"
#define SOCKET_LOG_COMPONENT "Socket-fd"
#include "core/SocketUtil.h"
#include "socket/Socket-private.h"
#include "socket/Socket.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"

#define T Socket_T

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketFD);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketFD, e)

/* Dummy byte for data payload - SCM_RIGHTS requires at least 1 byte of data */
static const char FD_PASS_DUMMY_BYTE = '\x00';

/* ==================== Static Helpers ==================== */

/**
 * validate_unix_socket - Verify socket is AF_UNIX
 * @socket: Socket to validate
 *
 * Returns: 1 if valid Unix socket, raises exception otherwise
 * Raises: Socket_Failed if socket is NULL or not AF_UNIX
 *
 * SCM_RIGHTS only works with Unix domain sockets.
 * Thread-safe: Yes (reads immutable domain field)
 */
static int
validate_unix_socket (T socket)
{
  int domain;

  if (!socket || !socket->base)
    {
      SOCKET_ERROR_MSG ("NULL socket passed to FD passing function");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  domain = SocketBase_domain (socket->base);
  if (domain != AF_UNIX)
    {
      SOCKET_ERROR_FMT (
          "FD passing requires Unix domain socket (AF_UNIX), got domain=%d",
          domain);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return 1;
}

/**
 * validate_fd_to_pass - Validate file descriptor before passing
 * @fd: File descriptor to validate
 *
 * Returns: 1 if valid, raises exception otherwise
 * Raises: Socket_Failed if fd is invalid
 *
 * Validates that fd is a valid open file descriptor.
 * Thread-safe: Yes (uses fcntl which is thread-safe)
 */
static int
validate_fd_to_pass (int fd)
{
  if (fd < 0)
    {
      SOCKET_ERROR_FMT ("Invalid file descriptor to pass: fd=%d", fd);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Verify fd is valid using fcntl */
  if (fcntl (fd, F_GETFD) < 0)
    {
      SOCKET_ERROR_FMT ("File descriptor is not open: fd=%d", fd);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return 1;
}

/**
 * validate_fds_array - Validate array of file descriptors
 * @fds: Array of file descriptors
 * @count: Number of descriptors
 *
 * Returns: 1 if all valid, raises exception otherwise
 * Raises: Socket_Failed if any fd is invalid or count exceeds limit
 */
static int
validate_fds_array (const int *fds, size_t count)
{
  size_t i;

  if (!fds)
    {
      SOCKET_ERROR_MSG ("NULL fds array passed to FD passing function");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  if (count == 0)
    {
      SOCKET_ERROR_MSG ("FD count must be at least 1");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  if (count > SOCKET_MAX_FDS_PER_MSG)
    {
      SOCKET_ERROR_FMT ("FD count %zu exceeds maximum %d", count,
                        SOCKET_MAX_FDS_PER_MSG);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  for (i = 0; i < count; i++)
    {
      if (fds[i] < 0)
        {
          SOCKET_ERROR_FMT ("Invalid file descriptor at index %zu: fd=%d", i,
                            fds[i]);
          RAISE_MODULE_ERROR (Socket_Failed);
        }
    }

  return 1;
}

/**
 * close_received_fds - Close array of received file descriptors
 * @fds: Array of file descriptors
 * @count: Number of descriptors to close
 *
 * Used for cleanup on error paths to prevent fd leaks.
 * Thread-safe: Yes (close is thread-safe per fd)
 */
static void
close_received_fds (int *fds, size_t count)
{
  size_t i;
  for (i = 0; i < count; i++)
    {
      if (fds[i] >= 0)
        {
          SAFE_CLOSE (fds[i]);
          fds[i] = -1;
        }
    }
}

/**
 * is_wouldblock - Check if errno indicates would-block condition
 *
 * Returns: 1 if EAGAIN or EWOULDBLOCK, 0 otherwise
 */
static int
is_wouldblock (void)
{
  return (errno == EAGAIN || errno == EWOULDBLOCK);
}

/**
 * is_connection_error - Check if errno indicates connection closed/reset
 *
 * Returns: 1 if connection error, 0 otherwise
 */
static int
is_connection_error (void)
{
  return (errno == EPIPE || errno == ECONNRESET || errno == ENOTCONN);
}

/* ==================== Core FD Passing Implementation ==================== */

/**
 * socket_sendfds_internal - Internal implementation for sending FDs
 * @socket: Connected Unix domain socket
 * @fds: Array of file descriptors to send
 * @count: Number of file descriptors
 *
 * Returns: 1 on success, 0 on would-block
 * Raises: Socket_Failed on error, Socket_Closed on disconnect
 *
 * Uses sendmsg with SCM_RIGHTS control message to pass file descriptors.
 * A dummy byte is sent as data payload (required by Linux kernel).
 */
static int
socket_sendfds_internal (T socket, const int *fds, size_t count)
{
  struct msghdr msg;
  struct iovec iov;
  char dummy = FD_PASS_DUMMY_BYTE;
  ssize_t result;
  int fd;

  /* Control message buffer - stack allocated for performance
   * CMSG_SPACE accounts for alignment and header */
  char cmsg_buf[CMSG_SPACE (sizeof (int) * SOCKET_MAX_FDS_PER_MSG)];
  struct cmsghdr *cmsg;
  size_t cmsg_data_len;

  fd = SocketBase_fd (socket->base);

  /* Setup data payload - must send at least 1 byte */
  iov.iov_base = &dummy;
  iov.iov_len = sizeof (dummy);

  /* Initialize message header */
  memset (&msg, 0, sizeof (msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  /* Setup control message for SCM_RIGHTS */
  memset (cmsg_buf, 0, sizeof (cmsg_buf));
  cmsg_data_len = sizeof (int) * count;
  msg.msg_control = cmsg_buf;
  msg.msg_controllen = CMSG_SPACE (cmsg_data_len);

  cmsg = CMSG_FIRSTHDR (&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN (cmsg_data_len);

  /* Copy file descriptors into control message data */
  memcpy (CMSG_DATA (cmsg), fds, cmsg_data_len);

  /* Send message with SCM_RIGHTS */
  result = sendmsg (fd, &msg, MSG_NOSIGNAL);
  if (result < 0)
    {
      if (is_wouldblock ())
        return 0;
      if (is_connection_error ())
        RAISE (Socket_Closed);
      SOCKET_ERROR_FMT ("sendmsg with SCM_RIGHTS failed (count=%zu)", count);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return 1;
}

/**
 * socket_recvfds_internal - Internal implementation for receiving FDs
 * @socket: Connected Unix domain socket
 * @fds: Output array for received file descriptors
 * @max_count: Maximum number of FDs to receive
 * @received_count: Output for actual number of FDs received
 *
 * Returns: 1 on success, 0 on would-block
 * Raises: Socket_Failed on error, Socket_Closed on disconnect
 *
 * Uses recvmsg to receive SCM_RIGHTS control message with file descriptors.
 * On success, *received_count contains the actual number of FDs received.
 * Caller takes ownership of received FDs and must close them.
 */
static int
socket_recvfds_internal (T socket, int *fds, size_t max_count,
                         size_t *received_count)
{
  struct msghdr msg;
  struct iovec iov;
  char dummy;
  ssize_t result;
  int fd;
  size_t i;

  /* Control message buffer - stack allocated */
  char cmsg_buf[CMSG_SPACE (sizeof (int) * SOCKET_MAX_FDS_PER_MSG)];
  struct cmsghdr *cmsg;
  size_t num_fds;

  fd = SocketBase_fd (socket->base);

  /* Initialize output */
  *received_count = 0;
  for (i = 0; i < max_count; i++)
    fds[i] = -1;

  /* Setup data buffer - receive the dummy byte */
  iov.iov_base = &dummy;
  iov.iov_len = sizeof (dummy);

  /* Initialize message header */
  memset (&msg, 0, sizeof (msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  /* Setup control message buffer */
  memset (cmsg_buf, 0, sizeof (cmsg_buf));
  msg.msg_control = cmsg_buf;
  msg.msg_controllen = sizeof (cmsg_buf);

  /* Receive message */
  result = recvmsg (fd, &msg, 0);
  if (result < 0)
    {
      if (is_wouldblock ())
        return 0;
      if (is_connection_error ())
        RAISE (Socket_Closed);
      SOCKET_ERROR_FMT ("recvmsg for SCM_RIGHTS failed");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  else if (result == 0)
    {
      /* Peer closed connection */
      RAISE (Socket_Closed);
    }

  /* Check for truncated control message */
  if (msg.msg_flags & MSG_CTRUNC)
    {
      SOCKET_ERROR_MSG (
          "Control message truncated - FD array may be incomplete");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Extract file descriptors from control message */
  cmsg = CMSG_FIRSTHDR (&msg);
  while (cmsg != NULL)
    {
      if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
        {
          /* Calculate number of FDs in this control message */
          num_fds = (cmsg->cmsg_len - CMSG_LEN (0)) / sizeof (int);

          if (num_fds > max_count)
            {
              /* More FDs than we can handle - close extras to prevent leak */
              int *cmsg_fds = (int *)CMSG_DATA (cmsg);
              for (i = max_count; i < num_fds; i++)
                {
                  SAFE_CLOSE (cmsg_fds[i]);
                }
              SOCKET_ERROR_FMT (
                  "Received more FDs (%zu) than buffer can hold (%zu)", num_fds,
                  max_count);
              /* Close any FDs we already copied before raising */
              close_received_fds (fds, max_count);
              RAISE_MODULE_ERROR (Socket_Failed);
            }

          /* Copy received FDs to output array */
          memcpy (fds, CMSG_DATA (cmsg), num_fds * sizeof (int));
          *received_count = num_fds;

          /* Validate each received FD */
          for (i = 0; i < num_fds; i++)
            {
              if (fcntl (fds[i], F_GETFD) < 0)
                {
                  SOCKET_ERROR_FMT ("Received invalid FD at index %zu", i);
                  close_received_fds (fds, num_fds);
                  *received_count = 0;
                  RAISE_MODULE_ERROR (Socket_Failed);
                }
            }

          return 1;
        }
      cmsg = CMSG_NXTHDR (&msg, cmsg);
    }

  /* No SCM_RIGHTS message found - this is not an error, just no FDs sent */
  *received_count = 0;
  return 1;
}

/* ==================== Public API ==================== */

int
Socket_sendfd (T socket, int fd_to_pass)
{
  assert (socket);

  validate_unix_socket (socket);
  validate_fd_to_pass (fd_to_pass);

  return socket_sendfds_internal (socket, &fd_to_pass, 1);
}

int
Socket_recvfd (T socket, int *fd_received)
{
  size_t received_count = 0;
  int result;

  assert (socket);
  assert (fd_received);

  if (!fd_received)
    {
      SOCKET_ERROR_MSG ("NULL fd_received pointer");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  *fd_received = -1;
  validate_unix_socket (socket);

  result = socket_recvfds_internal (socket, fd_received, 1, &received_count);

  if (result == 1 && received_count == 0)
    {
      /* Message received but no FD was attached */
      *fd_received = -1;
    }

  return result;
}

int
Socket_sendfds (T socket, const int *fds, size_t count)
{
  assert (socket);
  /* Note: fds and count validated by validate_fds_array which raises exception */

  validate_unix_socket (socket);
  validate_fds_array (fds, count);

  return socket_sendfds_internal (socket, fds, count);
}

int
Socket_recvfds (T socket, int *fds, size_t max_count, size_t *received_count)
{
  assert (socket);
  assert (fds);
  assert (received_count);

  if (!fds)
    {
      SOCKET_ERROR_MSG ("NULL fds array pointer");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  if (!received_count)
    {
      SOCKET_ERROR_MSG ("NULL received_count pointer");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  if (max_count == 0)
    {
      SOCKET_ERROR_MSG ("max_count must be at least 1");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  if (max_count > SOCKET_MAX_FDS_PER_MSG)
    {
      SOCKET_ERROR_FMT ("max_count %zu exceeds maximum %d", max_count,
                        SOCKET_MAX_FDS_PER_MSG);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  validate_unix_socket (socket);

  return socket_recvfds_internal (socket, fds, max_count, received_count);
}

#undef T

