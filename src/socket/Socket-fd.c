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


#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "core/Except.h"
#include "core/SocketConfig.h"
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
 * validate_fds - Validate array of file descriptors for passing
 * @fds: Array of file descriptors (or &fd for single)
 * @count: Number of descriptors (1 to SOCKET_MAX_FDS_PER_MSG)
 *
 * Comprehensive validation: non-null, count valid, each fd >=0 and open (fcntl).
 * Returns: 1 if valid
 * Raises: Socket_Failed on any issue
 * Thread-safe: Yes
 */
static int
validate_fds (const int *fds, size_t count)
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
      int fd = fds[i];
      if (fd < 0)
        SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                          "Invalid file descriptor at index %zu: fd=%d", i, fd);

      /* Verify fd is valid using fcntl */
      if (fcntl (fd, F_GETFD) < 0)
        SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                          "File descriptor is not open at index %zu: fd=%d", i, fd);
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

/* ==================== Error Handling Helpers ==================== */

/**
 * handle_fd_send_error - Handle sendmsg error for FD passing
 * @result: Result from sendmsg
 * @count: Number of FDs attempted to send (for error message)
 *
 * Returns: 1 on success (result >0), 0 on would-block, raises on error
 * Raises: Socket_Closed on connection error, Socket_Failed on other errors
 * Thread-safe: Yes
 */
static int
handle_fd_send_error (ssize_t result, size_t count)
{
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
 * handle_fd_recv_error - Handle recvmsg error for FD passing
 * @result: Result from recvmsg
 *
 * Returns: 1 on success (result >0), 0 on would-block, raises on error or EOF
 * Raises: Socket_Closed on EOF or connection error, Socket_Failed on other errors
 * Thread-safe: Yes
 */
static int
handle_fd_recv_error (ssize_t result)
{
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
  return 1;
}

/**
 * setup_fd_msg_data - Setup msghdr for FD passing (assumes iov pre-initialized)
 * @msg: msghdr to setup
 * @iov: iovec already set with valid base/len for dummy data
 *
 * Sets msg_iov, msg_iovlen, and zeroes msg.
 * Caller must initialize iov with dummy byte buffer before calling.
 * Thread-safe: Yes
 */
static void
setup_fd_msg_data (struct msghdr *msg, struct iovec *iov)
{
  memset (msg, 0, sizeof (*msg));
  msg->msg_iov = iov;
  msg->msg_iovlen = 1;
}

/**
 * setup_cmsg_buf - Setup control message buffer for FD passing
 * @buf: cmsg buffer (must be CMSG_SPACE(max) sized)
 * @buf_size: sizeof(buf)
 * @data_len: length of FD data (sizeof(int)*count)
 * @msg: msghdr to setup control
 *
 * Zeroes buf, sets msg_control and msg_controllen = CMSG_SPACE(data_len)
 * For recv, data_len ignored, uses buf_size.
 * No, for recv, data_len not known, so separate or param bool for send.
 * Wait, better separate functions.
 * Thread-safe: Yes
 */
static void
setup_send_cmsg_buf (char *buf, size_t buf_size, size_t data_len, struct msghdr *msg)
{
  memset (buf, 0, buf_size);
  msg->msg_control = buf;
  msg->msg_controllen = CMSG_SPACE (data_len);
}

static void
setup_recv_cmsg_buf (char *buf, size_t buf_size, struct msghdr *msg)
{
  memset (buf, 0, buf_size);
  msg->msg_control = buf;
  msg->msg_controllen = buf_size;
}

/**
 * build_rights_cmsg - Build SCM_RIGHTS control message header and data
 * @cmsg: cmsghdr pointer (from CMSG_FIRSTHDR)
 * @data_len: Length of FD data (sizeof(int)*count)
 * @fds: Array of FDs to copy into CMSG_DATA
 *
 * Sets cmsg fields and copies FDs into data area.
 * Thread-safe: Yes
 */
static void
build_rights_cmsg (struct cmsghdr *cmsg, size_t data_len, const int *fds)
{
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN (data_len);
  memcpy (CMSG_DATA (cmsg), fds, data_len);
}

/**
 * validate_received_fds - Validate and close on error for received FDs
 * @fds: Array of received FDs
 * @count: Number of FDs
 * @received_count: Pointer to count (set to 0 on error)
 *
 * Checks each fd >=0 and open via fcntl, closes all on any failure.
 * Raises on invalid, does not return on error.
 * Used after extract to ensure all FDs are usable.
 * Thread-safe: Yes
 */
static void
validate_received_fds (int *fds, size_t *received_count, size_t count)
{
  size_t i;
  for (i = 0; i < count; i++)
    {
      int fd = fds[i];
      if (fd < 0)
        {
          close_received_fds (fds, count);
          *received_count = 0;
          SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                            "Received invalid FD (<0) at index %zu", i);
        }
      if (fcntl (fd, F_GETFD) < 0)
        {
          close_received_fds (fds, count);
          *received_count = 0;
          SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                            "Received invalid FD (not open) at index %zu", i);
        }
    }
}

/**
 * extract_rights_fds - Extract and validate FDs from recvmsg control messages
 * @msg: msghdr from recvmsg
 * @fds: Output array for validated FDs
 * @max_count: Max FDs to extract/validate
 *
 * Processes first SCM_RIGHTS cmsg, extracts FDs to temp, validates (close invalid),
 * copies to fds if good, closes excess if >max.
 * Returns number of extracted FDs, or raises on error.
 * Improves safety by validating before writing to caller buffer.
 * Thread-safe: Yes
 */
static size_t
extract_rights_fds (const struct msghdr *msg, int *fds, size_t max_count)
{
  struct cmsghdr *cmsg = CMSG_FIRSTHDR ((struct msghdr *)msg);
  int temp_fds[SOCKET_MAX_FDS_PER_MSG];
  memset(temp_fds, -1, sizeof(temp_fds));  /* Initialize to invalid for safety */
  size_t total_fds = 0;

  while (cmsg != NULL)
    {
      if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
        {
          // Validate cmsg before calculation
          if (cmsg->cmsg_len < CMSG_LEN(0)) {
            SOCKET_RAISE_MSG (SocketFD, Socket_Failed, "Invalid SCM_RIGHTS cmsg_len too small");
          }
          size_t data_len = cmsg->cmsg_len - CMSG_LEN(0);
          if (data_len % sizeof(int) != 0) {
            SOCKET_RAISE_MSG (SocketFD, Socket_Failed, "Invalid SCM_RIGHTS data_len not multiple of sizeof(int)");
          }
          size_t this_num_fds = data_len / sizeof(int);
          if (this_num_fds == 0) {
            cmsg = CMSG_NXTHDR ((struct msghdr *)msg, cmsg);
            continue;
          }
          if (this_num_fds > SOCKET_MAX_FDS_PER_MSG) {
            int *cmsg_fds = (int *) CMSG_DATA (cmsg);
            close_received_fds (cmsg_fds, SOCKET_MAX_FDS_PER_MSG);
            SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                              "SCM_RIGHTS cmsg has too many fds (%zu > %d)", this_num_fds, SOCKET_MAX_FDS_PER_MSG);
          }

          int *cmsg_fds = (int *) CMSG_DATA (cmsg);
          size_t space_left = (sizeof(temp_fds) / sizeof(int)) - total_fds;
          size_t to_copy = (this_num_fds < space_left ? this_num_fds : space_left);
          if (to_copy > 0) {
            memcpy(temp_fds + total_fds, cmsg_fds, to_copy * sizeof(int));
            total_fds += to_copy;
          }
          // Close excess in this cmsg
          size_t excess_start = to_copy;
          if (this_num_fds > excess_start) {
            close_received_fds(cmsg_fds + excess_start, this_num_fds - excess_start);
          }
        }
      cmsg = CMSG_NXTHDR ((struct msghdr *)msg, cmsg);
    }

  // Now check total
  if (total_fds > max_count)
    {
      close_received_fds (temp_fds, total_fds);
      SOCKET_RAISE_FMT (SocketFD, Socket_Failed,
                        "Received total more FDs (%zu) than buffer can hold (%zu)",
                        total_fds, max_count);
    }

  /* Validate all accumulated FDs */
  size_t validated_count = total_fds;
  validate_received_fds (temp_fds, &validated_count, total_fds);  /* raises if invalid, closes all */

  /* All good, copy to output */
  memcpy (fds, temp_fds, validated_count * sizeof (int));
  // Set remaining to -1 for safety
  for (size_t i = validated_count; i < max_count; ++i) {
    fds[i] = -1;
  }
  return validated_count;
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
  int fd;

  /* Control message buffer - stack allocated for performance
   * CMSG_SPACE accounts for alignment and header */
  char cmsg_buf[CMSG_SPACE (sizeof (int) * SOCKET_MAX_FDS_PER_MSG)];
  size_t cmsg_data_len;

  fd = SocketBase_fd (socket->base);

  char dummy[1] = { FD_PASS_DUMMY_BYTE };
  iov.iov_base = dummy;
  iov.iov_len = sizeof (dummy[0]);

  setup_fd_msg_data (&msg, &iov);

  cmsg_data_len = sizeof (int) * count;
  setup_send_cmsg_buf (cmsg_buf, sizeof (cmsg_buf), cmsg_data_len, &msg);

  struct cmsghdr *cmsg = CMSG_FIRSTHDR (&msg);
  build_rights_cmsg (cmsg, cmsg_data_len, fds);

  /* Send message with SCM_RIGHTS */
  ssize_t result = sendmsg (fd, &msg, MSG_NOSIGNAL);
  return handle_fd_send_error (result, count);
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
  int fd;
  size_t i;

  /* Control message buffer - stack allocated */
  char cmsg_buf[CMSG_SPACE (sizeof (int) * SOCKET_MAX_FDS_PER_MSG)];

  fd = SocketBase_fd (socket->base);

  /* Initialize output */
  *received_count = 0;
  for (i = 0; i < max_count; i++)
    fds[i] = -1;

  char dummy[1] = { FD_PASS_DUMMY_BYTE };
  iov.iov_base = dummy;
  iov.iov_len = sizeof (dummy[0]);

  setup_fd_msg_data (&msg, &iov);
  setup_recv_cmsg_buf (cmsg_buf, sizeof (cmsg_buf), &msg);

  /* Receive message */
  ssize_t result = recvmsg (fd, &msg, 0);
  handle_fd_recv_error (result);

  /* Check for truncated control message */
  if (msg.msg_flags & MSG_CTRUNC)
    SOCKET_RAISE_MSG (SocketFD, Socket_Failed,
                      "Control message truncated - FD array may be incomplete");

  /* Check for data truncation - enforce protocol: only dummy byte expected */
  if (msg.msg_flags & MSG_TRUNC)
    SOCKET_RAISE_MSG (SocketFD, Socket_Failed,
                      "FD passing message data truncated - unexpected extra data from peer");

  /* Extract and validate FDs from control messages */
  size_t num_fds = extract_rights_fds (&msg, fds, max_count);
  *received_count = num_fds;
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
  validate_fds (&fd_to_pass, 1);

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

  if (!fd_received)
    SOCKET_RAISE_MSG (SocketFD, Socket_Failed, "NULL fd_received pointer");

  *fd_received = -1;
  validate_unix_socket (socket);

  return socket_recvfds_internal (socket, fd_received, 1, &received_count);
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
  validate_fds (fds, count);

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

