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
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
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

/* Declare module-specific exception for FD passing errors.
 * Uses SocketFD prefix to distinguish from general Socket errors. */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketFD);

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
    SOCKET_RAISE_MSG (SocketFD, Socket_Failed,
                      "NULL socket passed to FD passing function");

  domain = SocketBase_domain (socket->base);
  if (domain != AF_UNIX)
    SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                      "FD passing requires Unix domain socket (AF_UNIX), got "
                      "domain=%d",
                      domain);

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
    SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                      "Invalid file descriptor to pass: fd=%d", fd);

  /* Verify fd is valid using fcntl */
  if (fcntl (fd, F_GETFD) < 0)
    SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                      "File descriptor is not open: fd=%d", fd);

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
    SOCKET_RAISE_MSG (SocketFD, Socket_Failed,
                      "NULL fds array passed to FD passing function");

  if (count == 0)
    SOCKET_RAISE_MSG (SocketFD, Socket_Failed, "FD count must be at least 1");

  if (count > SOCKET_MAX_FDS_PER_MSG)
    SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                      "FD count %zu exceeds maximum %d", count,
                      SOCKET_MAX_FDS_PER_MSG);

  for (i = 0; i < count; i++)
    {
      if (fds[i] < 0)
        SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                          "Invalid file descriptor at index %zu: fd=%d", i,
                          fds[i]);
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
      SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                        "sendmsg with SCM_RIGHTS failed (count=%zu)", count);
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
      SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                        "recvmsg for SCM_RIGHTS failed");
    }
  else if (result == 0)
    {
      /* Peer closed connection */
      RAISE (Socket_Closed);
    }

  /* Check for truncated control message */
  if (msg.msg_flags & MSG_CTRUNC)
    SOCKET_RAISE_MSG (SocketFD, Socket_Failed,
                      "Control message truncated - FD array may be incomplete");

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
                SAFE_CLOSE (cmsg_fds[i]);

              /* Close any FDs we already copied before raising */
              close_received_fds (fds, max_count);
              SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                                "Received more FDs (%zu) than buffer can hold "
                                "(%zu)",
                                num_fds, max_count);
            }

          /* Copy received FDs to output array */
          memcpy (fds, CMSG_DATA (cmsg), num_fds * sizeof (int));
          *received_count = num_fds;

          /* Validate each received FD */
          for (i = 0; i < num_fds; i++)
            {
              if (fcntl (fds[i], F_GETFD) < 0)
                {
                  close_received_fds (fds, num_fds);
                  *received_count = 0;
                  SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                                    "Received invalid FD at index %zu", i);
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

/**
 * Socket_sendfd - Send single file descriptor over Unix socket
 * @socket: Connected Unix domain socket
 * @fd_to_pass: File descriptor to send
 *
 * Returns: 1 on success, 0 on would-block
 * Raises: Socket_Failed on error, Socket_Closed on disconnect
 *
 * Thread-safe: Yes (uses thread-local error buffers)
 */
int
Socket_sendfd (T socket, int fd_to_pass)
{
  validate_unix_socket (socket);
  validate_fd_to_pass (fd_to_pass);

  return socket_sendfds_internal (socket, &fd_to_pass, 1);
}

/**
 * Socket_recvfd - Receive single file descriptor from Unix socket
 * @socket: Connected Unix domain socket
 * @fd_received: Output pointer for received FD (set to -1 if no FD attached)
 *
 * Returns: 1 on success, 0 on would-block
 * Raises: Socket_Failed on error, Socket_Closed on disconnect
 *
 * Caller takes ownership of received FD and must close it.
 * Thread-safe: Yes (uses thread-local error buffers)
 */
int
Socket_recvfd (T socket, int *fd_received)
{
  size_t received_count = 0;
  int result;

  if (!fd_received)
    SOCKET_RAISE_MSG (SocketFD, Socket_Failed, "NULL fd_received pointer");

  *fd_received = -1;
  validate_unix_socket (socket);

  result = socket_recvfds_internal (socket, fd_received, 1, &received_count);

  /* Message received but no FD was attached - this is valid */
  if (result == 1 && received_count == 0)
    *fd_received = -1;

  return result;
}

/**
 * Socket_sendfds - Send multiple file descriptors over Unix socket
 * @socket: Connected Unix domain socket
 * @fds: Array of file descriptors to send
 * @count: Number of file descriptors (1 to SOCKET_MAX_FDS_PER_MSG)
 *
 * Returns: 1 on success, 0 on would-block
 * Raises: Socket_Failed on error, Socket_Closed on disconnect
 *
 * Thread-safe: Yes (uses thread-local error buffers)
 */
int
Socket_sendfds (T socket, const int *fds, size_t count)
{
  validate_unix_socket (socket);
  validate_fds_array (fds, count);

  return socket_sendfds_internal (socket, fds, count);
}

/**
 * Socket_recvfds - Receive multiple file descriptors from Unix socket
 * @socket: Connected Unix domain socket
 * @fds: Output array for received file descriptors
 * @max_count: Maximum FDs to receive (1 to SOCKET_MAX_FDS_PER_MSG)
 * @received_count: Output for actual number of FDs received
 *
 * Returns: 1 on success, 0 on would-block
 * Raises: Socket_Failed on error, Socket_Closed on disconnect
 *
 * Caller takes ownership of all received FDs and must close them.
 * Thread-safe: Yes (uses thread-local error buffers)
 */
int
Socket_recvfds (T socket, int *fds, size_t max_count, size_t *received_count)
{
  if (!fds)
    SOCKET_RAISE_MSG (SocketFD, Socket_Failed, "NULL fds array pointer");

  if (!received_count)
    SOCKET_RAISE_MSG (SocketFD, Socket_Failed, "NULL received_count pointer");

  if (max_count == 0)
    SOCKET_RAISE_MSG (SocketFD, Socket_Failed, "max_count must be at least 1");

  if (max_count > SOCKET_MAX_FDS_PER_MSG)
    SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                      "max_count %zu exceeds maximum %d", max_count,
                      SOCKET_MAX_FDS_PER_MSG);

  validate_unix_socket (socket);

  return socket_recvfds_internal (socket, fds, max_count, received_count);
}

#undef T

