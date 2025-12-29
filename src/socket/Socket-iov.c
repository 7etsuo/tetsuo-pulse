/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

/**
 * Socket-iov.c - Extended I/O operations
 *
 * Implements scatter/gather I/O, sendfile operations, and advanced messaging.
 * Provides high-performance I/O primitives for socket operations.
 *
 * Features:
 * - Scatter/gather I/O (writev/readv)
 * - Zero-copy file transfer (sendfile/splice)
 * - Advanced messaging (sendmsg/recvmsg)
 * - Guaranteed completion functions (sendall/recvall)
 * - Platform-specific optimizations
 * - TLS-aware operations
 * - Memory-efficient buffering
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#ifdef __linux__
#include <fcntl.h>
#include <sys/sendfile.h>
#endif

#include "core/SocketConfig.h"
#include "core/SocketUtil.h"
#include "socket/Socket-private.h"
#include "socket/Socket.h"
#include "socket/SocketCommon.h"
#include "socket/SocketIO.h"

/**
 * Default chunk size for splice operations (64KB)
 * This provides good performance for socket-to-socket transfers
 */
#ifndef SOCKET_SPLICE_CHUNK_SIZE
#define SOCKET_SPLICE_CHUNK_SIZE 65536
#endif

#define T Socket_T

/* Generic step function typedefs to reduce code duplication in loop implementations */
typedef ssize_t (*SocketSendStepFn)(T socket, const void *buf, size_t len);
typedef ssize_t (*SocketRecvStepFn)(T socket, void *buf, size_t len);
typedef ssize_t (*SocketSendvStepFn)(T socket, const struct iovec *iov, int iovcnt);
typedef ssize_t (*SocketRecvvStepFn)(T socket, struct iovec *iov, int iovcnt);

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketIOV);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketIOV, e)

/* ==================== Scatter/Gather I/O ==================== */

/**
 * Note: socket_sendv_internal() and socket_recvv_internal() are TLS-aware
 * internal functions defined in SocketIO.c and declared in SocketIO.h.
 * They handle routing I/O through TLS when enabled, or raw sockets otherwise.
 */

ssize_t
Socket_sendv (T socket, const struct iovec *iov, int iovcnt)
{
  return socket_sendv_internal (socket, iov, iovcnt, 0);
}

ssize_t
Socket_recvv (T socket, struct iovec *iov, int iovcnt)
{
  return socket_recvv_internal (socket, iov, iovcnt, 0);
}

/* ==================== Sendfile Operations ==================== */

#if SOCKET_HAS_SENDFILE && defined(__linux__)
/**
 * socket_sendfile_linux - Linux-specific sendfile implementation
 * @socket: Socket to send on
 * @file_fd: File descriptor to read from
 * @offset: File offset (updated on success)
 * @count: Number of bytes to transfer
 *
 * Returns: Bytes transferred or -1 on error
 */
static ssize_t
socket_sendfile_linux (T socket, int file_fd, off_t *offset, size_t count)
{
  off_t off = offset ? *offset : 0;
  ssize_t result
      = sendfile (SocketBase_fd (socket->base), file_fd, &off, count);
  if (result >= 0 && offset)
    *offset = off;
  return result;
}
#endif

#if SOCKET_HAS_SENDFILE                                                       \
    && (defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)   \
        || defined(__DragonFly__)                                             \
        || (defined(__APPLE__) && defined(__MACH__)))
/**
 * socket_sendfile_bsd - BSD/macOS sendfile implementation
 * @socket: Socket to send on
 * @file_fd: File descriptor to read from
 * @offset: File offset (updated on success)
 * @count: Number of bytes to transfer
 *
 * Returns: Bytes transferred or -1 on error
 */
static ssize_t
socket_sendfile_bsd (T socket, int file_fd, off_t *offset, size_t count)
{
  off_t len = (off_t)count;
  off_t off = offset ? *offset : 0;
  int result
      = sendfile (file_fd, SocketBase_fd (socket->base), off, &len, NULL, 0);
  if (result == 0)
    {
      if (offset)
        *offset = off + len;
      return (ssize_t)len;
    }
  return -1;
}
#endif

/**
 * sendfile_seek_to_offset - Seek to offset in file for sendfile fallback
 * @file_fd: File descriptor
 * @offset: Offset to seek to (NULL or 0 means no seek)
 *
 * Returns: 0 on success, -1 on error
 */
static ssize_t
sendfile_seek_to_offset (int file_fd, off_t *offset)
{
  if (offset && *offset != 0)
    {
      if (lseek (file_fd, *offset, SEEK_SET) < 0)
        return -1;
    }
  return 0;
}

/**
 * sendfile_transfer_loop - Read/write loop for sendfile fallback
 * @socket: Socket to send on
 * @file_fd: File descriptor to read from
 * @offset: File offset (updated on partial completion)
 * @count: Number of bytes to transfer
 *
 * Returns: Bytes transferred (may be partial on would-block)
 * Raises: Socket_Closed, Socket_Failed on error
 */
static size_t
sendfile_transfer_loop (T socket, int file_fd, off_t *offset, size_t count)
{
  /* Stack-allocated transfer buffer (8KB default, balances throughput with
   * memory efficiency). See SocketConfig.h for buffer size rationale. */
  char buffer[SOCKET_SENDFILE_FALLBACK_BUFFER_SIZE];
  volatile size_t total_sent = 0;

  TRY
  {
    while (total_sent < count)
      {
        size_t to_read = (count - total_sent < sizeof (buffer))
                             ? (count - total_sent)
                             : sizeof (buffer);
        ssize_t read_bytes = read (file_fd, buffer, to_read);
        if (read_bytes <= 0)
          {
            if (read_bytes == 0)
              break; /* EOF */
            if (errno == EINTR)
              continue;
            return (size_t)-1;
          }

        ssize_t sent_bytes = Socket_send (socket, buffer, (size_t)read_bytes);
        if (sent_bytes == 0)
          {
            /* Would block - return partial progress */
            break;
          }
        total_sent += (size_t)sent_bytes;

        if ((size_t)read_bytes < to_read)
          break; /* EOF reached */
      }
  }
  EXCEPT (Socket_Closed)
  RERAISE;
  EXCEPT (Socket_Failed)
  RERAISE;
  FINALLY
  {
    if (offset)
      *offset += (off_t)total_sent;
  }
  END_TRY;

  return total_sent;
}

/**
 * socket_sendfile_fallback - Portable sendfile fallback implementation
 * @socket: Socket to send on
 * @file_fd: File descriptor to read from
 * @offset: File offset (updated on completion)
 * @count: Number of bytes to transfer
 *
 * Returns: Bytes transferred or -1 on error
 * Thread-safe: Yes (operates on single socket)
 *
 * Uses read/write loop when kernel sendfile() is unavailable.
 */
static ssize_t
socket_sendfile_fallback (T socket, int file_fd, off_t *offset, size_t count)
{
  if (sendfile_seek_to_offset (file_fd, offset) < 0)
    return -1;

  size_t result = sendfile_transfer_loop (socket, file_fd, offset, count);
  return (ssize_t)result;
}

ssize_t
Socket_sendfile (T socket, int file_fd, off_t *offset, size_t count)
{
  ssize_t result = -1;

  assert (socket);
  assert (file_fd >= 0);
  assert (count > 0);

#if SOCKET_HAS_TLS
  /* TLS cannot use kernel sendfile() - must use fallback */
  if (socket_is_tls_enabled (socket))
    {
      result = socket_sendfile_fallback (socket, file_fd, offset, count);
    }
  else
#endif
#if SOCKET_HAS_SENDFILE && defined(__linux__)
    {
      result = socket_sendfile_linux (socket, file_fd, offset, count);
    }
#elif SOCKET_HAS_SENDFILE                                                     \
    && (defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)   \
        || defined(__DragonFly__)                                             \
        || (defined(__APPLE__) && defined(__MACH__)))
  {
    result = socket_sendfile_bsd (socket, file_fd, offset, count);
  }
#else
  {
    result = socket_sendfile_fallback (socket, file_fd, offset, count);
  }
#endif

  if (result < 0)
    {
      if (socketio_is_wouldblock ())
        return 0;
      if (socketio_is_connection_closed_send ())
        RAISE (Socket_Closed);
      SOCKET_ERROR_FMT (
          "Zero-copy file transfer failed (file_fd=%d, count=%zu)", file_fd,
          count);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return result;
}

ssize_t
Socket_sendfileall (T socket, int file_fd, off_t *offset, size_t count)
{
  volatile size_t total_sent = 0;
  off_t current_offset = offset ? *offset : 0;

  assert (socket);
  assert (file_fd >= 0);
  assert (count > 0);

  TRY
  {
    while (total_sent < count)
      {
        off_t *current_offset_ptr = offset ? &current_offset : NULL;
        size_t remaining = count - total_sent;

        ssize_t sent
            = Socket_sendfile (socket, file_fd, current_offset_ptr, remaining);
        if (sent == 0)
          {
            /* Would block (EAGAIN/EWOULDBLOCK) - return partial progress */
            break;
          }
        total_sent += (size_t)sent;
        if (offset)
          current_offset += (off_t)sent;
      }
  }
  EXCEPT (Socket_Closed)
  RERAISE;
  EXCEPT (Socket_Failed)
  RERAISE;
  FINALLY
  {
    if (offset)
      *offset = current_offset;
  }
  END_TRY;

  return (ssize_t)total_sent;
}

/* ==================== Advanced Messaging ==================== */

ssize_t
Socket_sendmsg (T socket, const struct msghdr *msg, int flags)
{
  ssize_t result;

  assert (socket);
  assert (msg);

  /* Always add MSG_NOSIGNAL to suppress SIGPIPE on broken connections */
  result = sendmsg (SocketBase_fd (socket->base), msg, flags | MSG_NOSIGNAL);
  if (result < 0)
    {
      if (socketio_is_wouldblock ())
        return 0;
      if (socketio_is_connection_closed_send ())
        RAISE (Socket_Closed);
      SOCKET_ERROR_FMT ("sendmsg failed (flags=0x%x)", flags | MSG_NOSIGNAL);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return result;
}

ssize_t
Socket_recvmsg (T socket, struct msghdr *msg, int flags)
{
  ssize_t result;

  assert (socket);
  assert (msg);

  result = recvmsg (SocketBase_fd (socket->base), msg, flags);
  if (result < 0)
    {
      if (socketio_is_wouldblock ())
        return 0;
      if (socketio_is_connection_closed_recv ())
        RAISE (Socket_Closed);
      SOCKET_ERROR_FMT ("recvmsg failed (flags=0x%x)", flags);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  else if (result == 0)
    {
      RAISE (Socket_Closed);
    }

  return result;
}

/* ==================== Guaranteed Completion Functions ==================== */

/* Wrapper functions removed - using type-specific iteration functions instead */

/**
 * Socket_sendall - Send all data (handles partial sends)
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (> 0)
 *
 * Returns: Total bytes sent (equals len on success, partial on would-block)
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on error
 */
ssize_t
Socket_sendall (T socket, const void *buf, size_t len)
{
  size_t total_sent = 0;
  const char *data = buf;

  assert (socket);
  assert (buf);
  assert (len > 0);

  while (total_sent < len)
    {
      ssize_t sent = Socket_send (socket, data + total_sent, len - total_sent);
      if (sent == 0)
        {
          /* Would block (EAGAIN/EWOULDBLOCK) - return partial progress */
          return (ssize_t)total_sent;
        }
      total_sent += (size_t)sent;
    }

  return (ssize_t)total_sent;
}

/**
 * Socket_recvall - Receive all requested data (handles partial receives)
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (> 0)
 *
 * Returns: Total bytes received (equals len on success, partial on
 * would-block) Raises: Socket_Closed on peer close or ECONNRESET,
 * Socket_Failed on error
 */
ssize_t
Socket_recvall (T socket, void *buf, size_t len)
{
  size_t total_received = 0;
  char *data = buf;

  assert (socket);
  assert (buf);
  assert (len > 0);

  while (total_received < len)
    {
      ssize_t received
          = Socket_recv (socket, data + total_received, len - total_received);
      if (received == 0)
        {
          /* Would block (EAGAIN/EWOULDBLOCK) - return partial progress */
          return (ssize_t)total_received;
        }
      total_received += (size_t)received;
    }

  return (ssize_t)total_received;
}

/**
 * sendvall_iteration - Perform one sendv iteration
 * @socket: Socket to send on
 * @iov_copy: Copy of iovec array (modified)
 * @iovcnt: Number of iovec structures
 * @bytes_sent: Output for bytes sent this iteration
 *
 * Returns: 1 to continue, 0 to stop (would block or no active iov)
 */
static int
sendvall_iteration (T socket, struct iovec *iov_copy, int iovcnt,
                    ssize_t *bytes_sent)
{
  int active_iovcnt = 0;
  struct iovec *active_iov
      = SocketCommon_find_active_iov (iov_copy, iovcnt, &active_iovcnt);

  if (active_iov == NULL)
    return 0;

  *bytes_sent = Socket_sendv (socket, (const struct iovec *)active_iov, active_iovcnt);
  if (*bytes_sent == 0)
    return 0;

  SocketCommon_advance_iov (iov_copy, iovcnt, (size_t)*bytes_sent);
  return 1;
}

/**
 * recvvall_iteration - Perform one recvv iteration
 * @socket: Socket to receive on
 * @iov_copy: Copy of iovec array (modified)
 * @iovcnt: Number of iovec structures
 * @bytes_received: Output for bytes received this iteration
 *
 * Returns: 1 to continue, 0 to stop (would block or no active iov)
 */
static int
recvvall_iteration (T socket, struct iovec *iov_copy, int iovcnt,
                    ssize_t *bytes_received)
{
  int active_iovcnt = 0;
  struct iovec *active_iov
      = SocketCommon_find_active_iov (iov_copy, iovcnt, &active_iovcnt);

  if (active_iov == NULL)
    return 0;

  *bytes_received = Socket_recvv (socket, active_iov, active_iovcnt);
  if (*bytes_received == 0)
    return 0;

  SocketCommon_advance_iov (iov_copy, iovcnt, (size_t)*bytes_received);
  return 1;
}

ssize_t
Socket_sendvall (T socket, const struct iovec *iov, int iovcnt)
{
  struct iovec *iov_copy = NULL;
  volatile size_t total_sent = 0;
  volatile size_t total_len;
  volatile ssize_t sent;

  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

  /* SocketCommon_calculate_total_iov_len includes overflow protection and
   * raises SocketCommon_Failed if the sum of iov_len values would overflow
   * SIZE_MAX. This protects against integer overflow attacks where an attacker
   * crafts iovec arrays with very large iov_len values. */
  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);
  iov_copy = SocketCommon_alloc_iov_copy (iov, iovcnt, Socket_Failed);

  TRY
  {
    while (total_sent < total_len
           && sendvall_iteration (socket, iov_copy, iovcnt, (ssize_t *)&sent))
      total_sent += (size_t)sent;
  }
  EXCEPT (Socket_Closed)
  RERAISE;
  EXCEPT (Socket_Failed)
  RERAISE;
  FINALLY { free (iov_copy); }
  END_TRY;

  return (ssize_t)total_sent;
}

ssize_t
Socket_recvvall (T socket, struct iovec *iov, int iovcnt)
{
  struct iovec *iov_copy = NULL;
  volatile size_t total_received = 0;
  volatile size_t total_len;
  volatile ssize_t received;

  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

  /* SocketCommon_calculate_total_iov_len includes overflow protection and
   * raises SocketCommon_Failed if the sum of iov_len values would overflow
   * SIZE_MAX. This protects against integer overflow attacks where an attacker
   * crafts iovec arrays with very large iov_len values. */
  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);
  iov_copy = SocketCommon_alloc_iov_copy (iov, iovcnt, Socket_Failed);

  TRY
  {
    while (total_received < total_len
           && recvvall_iteration (socket, iov_copy, iovcnt, (ssize_t *)&received))
      total_received += (size_t)received;
  }
  EXCEPT (Socket_Closed)
  RERAISE;
  EXCEPT (Socket_Failed)
  RERAISE;
  FINALLY { free (iov_copy); }
  END_TRY;

  return (ssize_t)total_received;
}

/* ==================== I/O Operations with Timeout ==================== */

/**
 * get_remaining_timeout_ms - Get remaining time until deadline
 * @deadline_ms: Deadline timestamp from SocketTimeout_deadline_ms()
 *
 * Returns: Remaining milliseconds (may be negative if past deadline)
 */
static int64_t
get_remaining_timeout_ms (int64_t deadline_ms)
{
  return deadline_ms - Socket_get_monotonic_ms ();
}


/**
 * socket_send_with_timeout - Send with timeout helper
 * @socket: Connected socket
 * @buf: Data to send (const)
 * @len: Number of bytes to send
 * @timeout_ms: Timeout in milliseconds (>0 for deadline, -1 for block, 0 for none)
 *
 * Returns: Total bytes sent (may be < len on timeout)
 * Raises: Socket_Closed, Socket_Failed
 *
 * Type-safe send helper with proper const handling.
 */
static ssize_t
socket_send_with_timeout (T socket, const void *buf, size_t len, int timeout_ms)
{
  volatile size_t total_sent = 0;
  const char *ptr;
  int fd;
  volatile int64_t deadline_ms;
  int64_t remaining_ms;
  ssize_t result;

  assert (socket);
  assert (buf || len == 0);

  if (len == 0)
    return 0;

  fd = SocketBase_fd (socket->base);
  ptr = (const char *)buf;
  deadline_ms = SocketTimeout_deadline_ms (timeout_ms);

  TRY
  {
    while (total_sent < len)
      {
        /* Check remaining time */
        if (timeout_ms > 0)
          {
            remaining_ms = get_remaining_timeout_ms (deadline_ms);
            if (remaining_ms <= 0)
              break; /* Timeout */

            if (SocketCommon_wait_for_fd (fd, POLLOUT, (int)remaining_ms) <= 0)
              break; /* Timeout or error */
          }
        else if (timeout_ms == -1)
          {
            /* Block indefinitely */
            if (SocketCommon_wait_for_fd (fd, POLLOUT, -1) < 0)
              {
                SOCKET_ERROR_FMT ("poll() failed during send");
                RAISE_MODULE_ERROR (Socket_Failed);
              }
          }

        result = Socket_send (socket, ptr + total_sent, len - total_sent);
        if (result > 0)
          total_sent += (size_t)result;
        else if (result == 0)
          break; /* Would block */
      }
  }
  EXCEPT (Socket_Closed)
  RERAISE;
  EXCEPT (Socket_Failed)
  RERAISE;
  END_TRY;

  return (ssize_t)total_sent;
}

/**
 * socket_recv_with_timeout - Receive with timeout helper
 * @socket: Connected socket
 * @buf: Buffer for received data (non-const)
 * @len: Number of bytes to receive
 * @timeout_ms: Timeout in milliseconds (>0 for deadline, -1 for block, 0 for none)
 *
 * Returns: Total bytes received (may be < len on timeout or EOF)
 * Raises: Socket_Closed, Socket_Failed
 *
 * Type-safe receive helper with proper non-const handling.
 */
static ssize_t
socket_recv_with_timeout (T socket, void *buf, size_t len, int timeout_ms)
{
  volatile size_t total_received = 0;
  char *ptr;
  int fd;
  volatile int64_t deadline_ms;
  int64_t remaining_ms;
  ssize_t result;

  assert (socket);
  assert (buf || len == 0);

  if (len == 0)
    return 0;

  fd = SocketBase_fd (socket->base);
  ptr = (char *)buf;
  deadline_ms = SocketTimeout_deadline_ms (timeout_ms);

  TRY
  {
    while (total_received < len)
      {
        /* Check remaining time */
        if (timeout_ms > 0)
          {
            remaining_ms = get_remaining_timeout_ms (deadline_ms);
            if (remaining_ms <= 0)
              break; /* Timeout */

            if (SocketCommon_wait_for_fd (fd, POLLIN, (int)remaining_ms) <= 0)
              break; /* Timeout or error */
          }
        else if (timeout_ms == -1)
          {
            /* Block indefinitely */
            if (SocketCommon_wait_for_fd (fd, POLLIN, -1) < 0)
              {
                SOCKET_ERROR_FMT ("poll() failed during recv");
                RAISE_MODULE_ERROR (Socket_Failed);
              }
          }

        result = Socket_recv (socket, ptr + total_received, len - total_received);
        if (result > 0)
          total_received += (size_t)result;
        else if (result == 0)
          break; /* Would block or EOF */
      }
  }
  EXCEPT (Socket_Closed)
  RERAISE;
  EXCEPT (Socket_Failed)
  RERAISE;
  END_TRY;

  return (ssize_t)total_received;
}

/**
 * Socket_sendall_timeout - Send all data with timeout
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data
 * @timeout_ms: Timeout in milliseconds
 *
 * Returns: Total bytes sent (may be < len on timeout)
 * Raises: Socket_Closed, Socket_Failed
 */
ssize_t
Socket_sendall_timeout (T socket, const void *buf, size_t len, int timeout_ms)
{
  return socket_send_with_timeout (socket, buf, len, timeout_ms);
}

/**
 * Socket_recvall_timeout - Receive all data with timeout
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Number of bytes to receive
 * @timeout_ms: Timeout in milliseconds
 *
 * Returns: Total bytes received (may be < len on timeout or EOF)
 * Raises: Socket_Closed, Socket_Failed
 */
ssize_t
Socket_recvall_timeout (T socket, void *buf, size_t len, int timeout_ms)
{
  return socket_recv_with_timeout (socket, buf, len, timeout_ms);
}

/**
 * Socket_sendv_timeout - Scatter/gather send with timeout
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 * @timeout_ms: Timeout in milliseconds
 *
 * Returns: Total bytes sent
 * Raises: Socket_Closed, Socket_Failed
 */
ssize_t
Socket_sendv_timeout (T socket, const struct iovec *iov, int iovcnt,
                      int timeout_ms)
{
  int fd;

  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

  fd = SocketBase_fd (socket->base);

  /* Wait for socket to be writable */
  if (timeout_ms != 0)
    {
      int ready = SocketCommon_wait_for_fd (fd, POLLOUT, timeout_ms);
      if (ready == 0)
        return 0; /* Timeout */
      if (ready < 0)
        {
          SOCKET_ERROR_FMT ("poll() failed during sendv");
          RAISE_MODULE_ERROR (Socket_Failed);
        }
    }

  return socket_sendv_internal (socket, iov, iovcnt, 0);
}

/**
 * Socket_recvv_timeout - Scatter/gather receive with timeout
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 * @timeout_ms: Timeout in milliseconds
 *
 * Returns: Total bytes received
 * Raises: Socket_Closed, Socket_Failed
 */
ssize_t
Socket_recvv_timeout (T socket, struct iovec *iov, int iovcnt, int timeout_ms)
{
  int fd;

  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

  fd = SocketBase_fd (socket->base);

  /* Wait for socket to be readable */
  if (timeout_ms != 0)
    {
      int ready = SocketCommon_wait_for_fd (fd, POLLIN, timeout_ms);
      if (ready == 0)
        return 0; /* Timeout */
      if (ready < 0)
        {
          SOCKET_ERROR_FMT ("poll() failed during recvv");
          RAISE_MODULE_ERROR (Socket_Failed);
        }
    }

  return socket_recvv_internal (socket, iov, iovcnt, 0);
}

/* ==================== Advanced I/O Operations ==================== */

#ifdef __linux__

/**
 * close_pipe_fds - Close both ends of a pipe
 * @pipe_fds: Array of two file descriptors (read and write ends)
 *
 * Helper to ensure both pipe ends are always closed together.
 */
static void
close_pipe_fds (int pipe_fds[2])
{
  close (pipe_fds[0]);
  close (pipe_fds[1]);
}

/**
 * handle_splice_error - Handle splice system call errors
 * @saved_errno: The errno value from the failed splice call
 * @direction: Error message direction ("from socket" or "to socket")
 *
 * Returns: 0 if the error is EAGAIN/EWOULDBLOCK (would block)
 * Raises: Socket_Closed for connection errors, Socket_Failed for other errors
 */
static ssize_t
handle_splice_error (int saved_errno, const char *direction)
{
  if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK)
    return 0;

  if (saved_errno == EPIPE || saved_errno == ECONNRESET)
    {
      SOCKET_ERROR_MSG ("Connection closed during splice");
      RAISE_MODULE_ERROR (Socket_Closed);
    }

  SOCKET_ERROR_FMT ("splice() %s failed", direction);
  RAISE_MODULE_ERROR (Socket_Failed);
}

/**
 * Socket_splice - Zero-copy socket-to-socket transfer (Linux)
 * @socket_in: Source socket
 * @socket_out: Destination socket
 * @len: Maximum bytes to transfer (0 for default SOCKET_SPLICE_CHUNK_SIZE)
 *
 * Returns: Bytes transferred, 0 if would block, -1 if not supported
 * Raises: Socket_Closed, Socket_Failed
 */
ssize_t
Socket_splice (T socket_in, T socket_out, size_t len)
{
  int fd_in, fd_out;
  int pipe_fds[2];
  ssize_t spliced_in, spliced_out;
  size_t chunk_size;

  assert (socket_in);
  assert (socket_out);

  fd_in = SocketBase_fd (socket_in->base);
  fd_out = SocketBase_fd (socket_out->base);

  chunk_size = (len > 0) ? len : SOCKET_SPLICE_CHUNK_SIZE;

  /* Create pipe for intermediate buffer */
  if (pipe (pipe_fds) < 0)
    {
      int saved_errno = errno;
      if (saved_errno == EMFILE || saved_errno == ENFILE)
        SOCKET_ERROR_FMT ("pipe() failed: too many open file descriptors "
                          "(consider increasing ulimit)");
      else if (saved_errno == ENOMEM)
        SOCKET_ERROR_FMT ("pipe() failed: insufficient kernel memory");
      else
        SOCKET_ERROR_FMT ("pipe() failed for splice");
      errno = saved_errno;
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Splice from socket to pipe */
  spliced_in = splice (fd_in, NULL, pipe_fds[1], NULL, chunk_size,
                       SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

  if (spliced_in < 0)
    {
      int saved_errno = errno;
      close_pipe_fds (pipe_fds);
      return handle_splice_error (saved_errno, "from socket");
    }

  if (spliced_in == 0)
    {
      close_pipe_fds (pipe_fds);
      return 0;
    }

  /* Splice from pipe to socket */
  spliced_out = splice (pipe_fds[0], NULL, fd_out, NULL, (size_t)spliced_in,
                        SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

  close_pipe_fds (pipe_fds);

  if (spliced_out < 0)
    return handle_splice_error (errno, "to socket");

  return spliced_out;
}
#else
/* Non-Linux: splice not supported */
ssize_t
Socket_splice (T socket_in, T socket_out, size_t len)
{
  (void)socket_in;
  (void)socket_out;
  (void)len;
  return -1; /* Not supported */
}
#endif /* __linux__ */

/**
 * Socket_cork - Control TCP_CORK option
 * @socket: TCP socket
 * @enable: 1 to enable, 0 to disable
 *
 * Returns: 0 on success, -1 if not supported
 */
int
Socket_cork (T socket, int enable)
{
  int fd;
  int flag = enable ? 1 : 0;

  assert (socket);

  fd = SocketBase_fd (socket->base);

#if defined(__linux__) && defined(TCP_CORK)
  if (setsockopt (fd, IPPROTO_TCP, TCP_CORK, &flag, sizeof (flag)) < 0)
    return -1;
  return 0;
#elif (defined(__FreeBSD__) || defined(__APPLE__)) && defined(TCP_NOPUSH)
  if (setsockopt (fd, IPPROTO_TCP, TCP_NOPUSH, &flag, sizeof (flag)) < 0)
    return -1;
  return 0;
#else
  (void)fd;
  (void)flag;
  return -1; /* Not supported */
#endif
}

/**
 * Socket_peek - Peek at incoming data without consuming
 * @socket: Connected socket
 * @buf: Buffer for peeked data
 * @len: Maximum bytes to peek
 *
 * Returns: Bytes peeked, 0 if no data, or raises
 * Raises: Socket_Closed, Socket_Failed
 */
ssize_t
Socket_peek (T socket, void *buf, size_t len)
{
  int fd;
  ssize_t result;

  assert (socket);
  assert (buf || len == 0);

  if (len == 0)
    return 0;

  fd = SocketBase_fd (socket->base);

  do
    {
      result = recv (fd, buf, len, MSG_PEEK | MSG_DONTWAIT);
    }
  while (result < 0 && errno == EINTR);

  if (result < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      if (errno == ECONNRESET || errno == EPIPE)
        {
          SOCKET_ERROR_MSG ("Connection closed during peek");
          RAISE_MODULE_ERROR (Socket_Closed);
        }
      SOCKET_ERROR_FMT ("recv(MSG_PEEK) failed");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return result;
}

/* ==================== Socket Duplication ==================== */

/**
 * Socket_dup - Duplicate a socket
 * @socket: Socket to duplicate
 *
 * Returns: New Socket_T with duplicated fd
 * Raises: Socket_Failed on error
 */
T
Socket_dup (T socket)
{
  int new_fd;
  T new_socket;

  assert (socket);

  new_fd = dup (SocketBase_fd (socket->base));
  if (new_fd < 0)
    {
      SOCKET_ERROR_FMT ("dup() failed");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  new_socket = Socket_new_from_fd (new_fd);
  if (!new_socket)
    {
      close (new_fd);
      SOCKET_ERROR_MSG ("Failed to create socket from duplicated fd");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return new_socket;
}

/**
 * Socket_dup2 - Duplicate socket to specific fd
 * @socket: Socket to duplicate
 * @target_fd: Target file descriptor
 *
 * Returns: New Socket_T with fd = target_fd
 * Raises: Socket_Failed on error
 */
T
Socket_dup2 (T socket, int target_fd)
{
  int new_fd;
  T new_socket;

  assert (socket);
  assert (target_fd >= 0);

  new_fd = dup2 (SocketBase_fd (socket->base), target_fd);
  if (new_fd < 0)
    {
      SOCKET_ERROR_FMT ("dup2() failed");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  new_socket = Socket_new_from_fd (new_fd);
  if (!new_socket)
    {
      close (new_fd);
      SOCKET_ERROR_MSG ("Failed to create socket from dup2'd fd");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return new_socket;
}

#undef T
