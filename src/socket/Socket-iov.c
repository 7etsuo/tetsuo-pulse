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
 * Default chunk size for splice operations (64KB = 16 pages)
 *
 * This value was chosen because:
 * - Matches Linux default pipe buffer size (16 * PAGE_SIZE on x86-64)
 * - Aligns with typical TCP receive window size
 * - Balances memory usage vs throughput for socket-to-socket transfers
 * - Minimizes splice() system calls while avoiding excessive memory use
 *
 * Performance characteristics:
 * - Smaller values (<32KB): More syscalls, lower memory, worse throughput
 * - Larger values (>128KB): Better throughput, higher memory, diminishing
 * returns
 *
 * This can be overridden at compile time for specific workloads:
 *   -DSOCKET_SPLICE_CHUNK_SIZE=131072  (128KB for high-throughput proxies)
 *   -DSOCKET_SPLICE_CHUNK_SIZE=32768   (32KB for memory-constrained systems)
 */
#ifndef SOCKET_SPLICE_CHUNK_SIZE
#define SOCKET_SPLICE_CHUNK_SIZE 65536
#endif

#define T Socket_T

/* Generic step function typedefs to reduce code duplication in loop
 * implementations */
typedef ssize_t (*SocketSendStepFn) (T socket, const void *buf, size_t len);
typedef ssize_t (*SocketRecvStepFn) (T socket, void *buf, size_t len);
typedef ssize_t (*SocketSendvStepFn) (T socket,
                                      const struct iovec *iov,
                                      int iovcnt);
typedef ssize_t (*SocketRecvvStepFn) (T socket, struct iovec *iov, int iovcnt);

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketIOV);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketIOV, e)

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

/**
 * safe_add_off_t - Add to off_t with overflow checking
 * @offset: Pointer to offset to update (must not be NULL)
 * @increment: Value to add to offset
 *
 * Returns: 0 on success, -1 on overflow/underflow
 *
 * Safely adds increment to *offset with overflow detection. Uses compiler
 * builtin if available, otherwise performs manual bounds checking. This
 * prevents CWE-190 (Integer Overflow) which could cause data corruption
 * or security issues when handling large files.
 */
static int
safe_add_off_t (off_t *offset, off_t increment)
{
  assert (offset);

#if defined(__has_builtin) && __has_builtin(__builtin_add_overflow)
  /* Use compiler builtin for overflow detection (most reliable) */
  off_t new_offset;
  if (__builtin_add_overflow (*offset, increment, &new_offset))
    {
      SOCKET_ERROR_MSG ("File offset overflow: operation would exceed maximum "
                        "file offset");
      return -1;
    }
  *offset = new_offset;
  return 0;
#else
  /* Manual overflow check for systems without compiler builtins.
   * For signed addition, overflow occurs when:
   * - Both operands positive and sum exceeds maximum
   * - Both operands negative and sum goes below minimum
   * Safe to add if signs differ or result stays within bounds. */

  if (increment > 0)
    {
      /* Adding positive value - check for overflow.
       * Maximum value for signed type is 2^(bits-1) - 1 */
      off_t max_off_t = (off_t)((1ULL << (sizeof (off_t) * 8 - 1)) - 1);
      if (*offset > 0 && increment > max_off_t - *offset)
        {
          SOCKET_ERROR_MSG (
              "File offset overflow: operation would exceed maximum file "
              "offset");
          return -1;
        }
    }
  else if (increment < 0)
    {
      /* Adding negative value - check for underflow.
       * Minimum value for signed type is -2^(bits-1) */
      off_t min_off_t = (off_t)(-(1LL << (sizeof (off_t) * 8 - 1)));
      if (*offset < 0 && increment < min_off_t - *offset)
        {
          SOCKET_ERROR_MSG (
              "File offset underflow: operation would go below minimum file "
              "offset");
          return -1;
        }
    }
  /* else: increment is 0, no change needed */

  *offset += increment;
  return 0;
#endif
}

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

#if SOCKET_HAS_SENDFILE                                                     \
    && (defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) \
        || defined(__DragonFly__)                                           \
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
  /* Check for overflow when casting size_t to off_t (CWE-190).
   * On systems where sizeof(size_t) > sizeof(off_t), large values
   * could silently truncate, causing partial transfers. Calculate
   * max off_t using same pattern as safe_add_off_t(). */
  off_t max_off_t = (off_t)((1ULL << (sizeof (off_t) * 8 - 1)) - 1);
  if (count > (size_t)max_off_t)
    {
      errno = EOVERFLOW;
      return -1;
    }

  off_t len = (off_t)count;
  off_t off = offset ? *offset : 0;
  int result
      = sendfile (file_fd, SocketBase_fd (socket->base), off, &len, NULL, 0);

  /* Guard clause: early return on failure */
  if (result != 0)
    return -1;

  /* Handle offset update if provided */
  if (offset)
    {
      /* Use safe addition to prevent off_t overflow (CWE-190) */
      off_t new_offset = off;
      if (safe_add_off_t (&new_offset, len) < 0)
        {
          /* Overflow detected - return error */
          errno = EOVERFLOW;
          return -1;
        }
      *offset = new_offset;
    }

  /* Check for SSIZE_MAX overflow before cast (CWE-190).
   * If len > SSIZE_MAX, casting to ssize_t would wrap to negative,
   * causing caller to misinterpret success as error. */
  if (len > SSIZE_MAX)
    {
      errno = EOVERFLOW;
      return -1;
    }

  return (ssize_t)len;
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

        /* Handle read errors with guard clauses */
        if (read_bytes == 0)
          break; /* EOF */

        if (read_bytes < 0)
          {
            if (errno == EINTR)
              continue;        /* Interrupted - retry */
            return (size_t)-1; /* Actual error */
          }

        /* Normal path: data was read successfully */
        ssize_t sent_bytes = Socket_send (socket, buffer, (size_t)read_bytes);
        if (sent_bytes == 0)
          break; /* Would block - return partial progress */

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
      {
        /* Use safe addition to prevent off_t overflow (CWE-190).
         * On overflow, safe_add_off_t logs error but doesn't update offset,
         * leaving it at the last valid value. */
        (void)safe_add_off_t (offset, (off_t)total_sent);
      }
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
#elif SOCKET_HAS_SENDFILE                                                   \
    && (defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) \
        || defined(__DragonFly__)                                           \
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
          "Zero-copy file transfer failed (file_fd=%d, count=%zu)",
          file_fd,
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

        /* Guard clause: handle would-block early */
        if (sent == 0)
          break;

        total_sent += (size_t)sent;

        /* Guard clause: skip offset update if not tracking offset */
        if (!offset)
          continue;

        /* Guard clause: handle overflow and stop processing */
        if (safe_add_off_t (&current_offset, (off_t)sent) < 0)
          break;
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

/* Wrapper functions removed - using type-specific iteration functions instead
 */

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
sendvall_iteration (T socket,
                    struct iovec *iov_copy,
                    int iovcnt,
                    ssize_t *bytes_sent)
{
  int active_iovcnt = 0;
  struct iovec *active_iov
      = SocketCommon_find_active_iov (iov_copy, iovcnt, &active_iovcnt);

  if (active_iov == NULL)
    return 0;

  *bytes_sent
      = Socket_sendv (socket, (const struct iovec *)active_iov, active_iovcnt);
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
recvvall_iteration (T socket,
                    struct iovec *iov_copy,
                    int iovcnt,
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
  size_t total_len;
  ssize_t sent;

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
  FINALLY
  {
    free (iov_copy);
  }
  END_TRY;

  return (ssize_t)total_sent;
}

ssize_t
Socket_recvvall (T socket, struct iovec *iov, int iovcnt)
{
  struct iovec *iov_copy = NULL;
  volatile size_t total_received = 0;
  size_t total_len;
  ssize_t received;

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
    while (
        total_received < total_len
        && recvvall_iteration (socket, iov_copy, iovcnt, (ssize_t *)&received))
      total_received += (size_t)received;
  }
  EXCEPT (Socket_Closed)
  RERAISE;
  EXCEPT (Socket_Failed)
  RERAISE;
  FINALLY
  {
    free (iov_copy);
  }
  END_TRY;

  return (ssize_t)total_received;
}

/**
 * socket_wait_with_timeout - Wait for socket readiness with timeout handling
 * @fd: File descriptor to wait on
 * @events: Poll events (POLLIN or POLLOUT)
 * @timeout_ms: Original timeout value (>0 for deadline, -1 for block, 0 for
 * none)
 * @deadline_ms: Deadline timestamp from SocketTimeout_deadline_ms()
 * @op_name: Operation name for error messages ("send" or "recv")
 *
 * Returns: 1 if ready, 0 if timeout occurred
 * Raises: Socket_Failed if poll fails in blocking mode
 *
 * Centralizes timeout calculation and wait logic to eliminate duplication.
 */
static int
socket_wait_with_timeout (int fd,
                          short events,
                          int timeout_ms,
                          int64_t deadline_ms,
                          const char *op_name)
{
  int64_t remaining_ms;

  if (timeout_ms > 0)
    {
      remaining_ms = SocketTimeout_remaining_ms (deadline_ms);
      if (remaining_ms <= 0)
        return 0; /* Timeout */

      if (SocketCommon_wait_for_fd (fd, events, (int)remaining_ms) <= 0)
        return 0; /* Timeout or error */
    }
  else if (timeout_ms == -1)
    {
      /* Block indefinitely */
      if (SocketCommon_wait_for_fd (fd, events, -1) < 0)
        {
          SOCKET_ERROR_FMT ("poll() failed during %s", op_name);
          RAISE_MODULE_ERROR (Socket_Failed);
        }
    }

  return 1; /* Ready */
}


/**
 * SocketIOFn - Function pointer type for I/O operations
 * @socket: Socket instance
 * @buf: Buffer for data (void* for generic use)
 * @len: Number of bytes to transfer
 *
 * Returns: Number of bytes transferred, or 0 if would block
 * Raises: Socket_Closed, Socket_Failed
 *
 * Generic I/O function signature for send/recv operations.
 */
typedef ssize_t (*SocketIOFn) (T socket, void *buf, size_t len);

/**
 * socket_io_with_timeout - Generic I/O with timeout helper
 * @socket: Connected socket
 * @buf: Buffer for data (read or write)
 * @len: Number of bytes to transfer
 * @timeout_ms: Timeout in milliseconds (>0 for deadline, -1 for block, 0 for
 * none)
 * @poll_event: Poll event to wait for (POLLIN or POLLOUT)
 * @io_fn: I/O function to call (Socket_send or Socket_recv)
 * @op_name: Operation name for error messages ("send" or "recv")
 *
 * Returns: Total bytes transferred (may be < len on timeout or EOF)
 * Raises: Socket_Closed, Socket_Failed
 *
 * Centralized timeout I/O logic to eliminate duplication between send and recv.
 * Uses function pointer to abstract the actual I/O operation.
 */
static ssize_t
socket_io_with_timeout (T socket,
                        void *buf,
                        size_t len,
                        int timeout_ms,
                        short poll_event,
                        SocketIOFn io_fn,
                        const char *op_name)
{
  volatile size_t total = 0;
  char *ptr;
  int fd;
  volatile int64_t deadline_ms;
  ssize_t result;

  assert (socket);
  assert (buf || len == 0);
  assert (io_fn);

  if (len == 0)
    return 0;

  fd = SocketBase_fd (socket->base);
  ptr = (char *)buf;
  deadline_ms = SocketTimeout_deadline_ms (timeout_ms);

  TRY
  {
    while (total < len)
      {
        /* Wait for socket to be ready with timeout handling */
        if (!socket_wait_with_timeout (
                fd, poll_event, timeout_ms, deadline_ms, op_name))
          break; /* Timeout */

        result = io_fn (socket, ptr + total, len - total);
        if (result > 0)
          total += (size_t)result;
        else if (result == 0)
          break; /* Would block or EOF */
      }
  }
  EXCEPT (Socket_Closed)
  RERAISE;
  EXCEPT (Socket_Failed)
  RERAISE;
  END_TRY;

  return (ssize_t)total;
}

/**
 * socket_send_with_timeout - Send with timeout helper
 * @socket: Connected socket
 * @buf: Data to send (const)
 * @len: Number of bytes to send
 * @timeout_ms: Timeout in milliseconds (>0 for deadline, -1 for block, 0 for
 * none)
 *
 * Returns: Total bytes sent (may be < len on timeout)
 * Raises: Socket_Closed, Socket_Failed
 *
 * Type-safe send helper with proper const handling.
 */
static ssize_t
socket_send_with_timeout (T socket, const void *buf, size_t len, int timeout_ms)
{
  /* Cast away const for generic io_fn signature - Socket_send preserves const
   */
  return socket_io_with_timeout (socket,
                                 (void *)buf,
                                 len,
                                 timeout_ms,
                                 POLLOUT,
                                 (SocketIOFn)Socket_send,
                                 "send");
}

/**
 * socket_recv_with_timeout - Receive with timeout helper
 * @socket: Connected socket
 * @buf: Buffer for received data (non-const)
 * @len: Number of bytes to receive
 * @timeout_ms: Timeout in milliseconds (>0 for deadline, -1 for block, 0 for
 * none)
 *
 * Returns: Total bytes received (may be < len on timeout or EOF)
 * Raises: Socket_Closed, Socket_Failed
 *
 * Type-safe receive helper with proper non-const handling.
 */
static ssize_t
socket_recv_with_timeout (T socket, void *buf, size_t len, int timeout_ms)
{
  return socket_io_with_timeout (
      socket, buf, len, timeout_ms, POLLIN, (SocketIOFn)Socket_recv, "recv");
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
Socket_sendv_timeout (T socket,
                      const struct iovec *iov,
                      int iovcnt,
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
static void
splice_create_pipe (int pipe_fds[2])
{
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
}

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

  splice_create_pipe (pipe_fds);

  /* Splice from socket to pipe */
  spliced_in = splice (fd_in,
                       NULL,
                       pipe_fds[1],
                       NULL,
                       chunk_size,
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
  spliced_out = splice (pipe_fds[0],
                        NULL,
                        fd_out,
                        NULL,
                        (size_t)spliced_in,
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
