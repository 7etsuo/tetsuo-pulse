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

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/sendfile.h>
#endif

#ifdef __FreeBSD__
#include <sys/uio.h>
#endif

#include <assert.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/Socket.h"
#include "core/SocketMetrics.h"
#include "socket/SocketIO.h" /* TLS-aware I/O functions */
#include "socket/Socket-private.h"
#include "socket/SocketCommon.h"

#define T Socket_T

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketIOV);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketIOV, e)

/* ==================== Scatter/Gather I/O ==================== */

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

static size_t
sendfile_transfer_loop (T socket, int file_fd, off_t *offset, size_t count)
{
  char buffer[SOCKET_SENDFILE_FALLBACK_BUFFER_SIZE];
  volatile size_t total_sent = 0;
  ssize_t read_bytes, sent_bytes;

  TRY
    while (total_sent < count)
      {
        size_t to_read = (count - total_sent < sizeof (buffer))
                             ? (count - total_sent)
                             : sizeof (buffer);
        read_bytes = read (file_fd, buffer, to_read);
        if (read_bytes <= 0)
          {
            if (read_bytes == 0)
              break; /* EOF */
            if (errno == EINTR)
              continue;
            return (size_t)-1;
          }

        sent_bytes = Socket_send (socket, buffer, (size_t)read_bytes);
        if (sent_bytes == 0)
          {
            /* Would block - return partial progress */
            if (offset)
              *offset += (off_t)total_sent;
            return total_sent;
          }
        total_sent += (size_t)sent_bytes;

        if ((size_t)read_bytes < to_read)
          break; /* EOF reached */
      }
  EXCEPT (Socket_Closed)
    if (offset)
      *offset += (off_t)total_sent;
    RERAISE;
  EXCEPT (Socket_Failed)
    if (offset)
      *offset += (off_t)total_sent;
    RERAISE;
  END_TRY;

  if (offset)
    *offset += (off_t)total_sent;
  return total_sent;
}

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

#ifdef SOCKET_HAS_TLS
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
  ssize_t sent;
  off_t current_offset = offset ? *offset : 0;

  assert (socket);
  assert (file_fd >= 0);
  assert (count > 0);

  TRY
    while (total_sent < count)
      {
        off_t *current_offset_ptr = offset ? &current_offset : NULL;
        size_t remaining = count - total_sent;

        sent = Socket_sendfile (socket, file_fd, current_offset_ptr, remaining);
        if (sent == 0)
          {
            /* Would block (EAGAIN/EWOULDBLOCK) - return partial progress */
            if (offset)
              *offset = current_offset;
            return (ssize_t)total_sent;
          }
        total_sent += (size_t)sent;
        if (offset)
          current_offset += (off_t)sent;
      }
  EXCEPT (Socket_Closed)
    if (offset)
      *offset = current_offset;
    RERAISE;
  EXCEPT (Socket_Failed)
    if (offset)
      *offset = current_offset;
    RERAISE;
  END_TRY;

  if (offset)
    *offset = current_offset;
  return (ssize_t)total_sent;
}

/* ==================== Advanced Messaging ==================== */

ssize_t
Socket_sendmsg (T socket, const struct msghdr *msg, int flags)
{
  ssize_t result;

  assert (socket);
  assert (msg);

  result = sendmsg (SocketBase_fd (socket->base), msg, flags);
  if (result < 0)
    {
      if (socketio_is_wouldblock ())
        return 0;
      if (socketio_is_connection_closed_send ())
        RAISE (Socket_Closed);
      SOCKET_ERROR_FMT ("sendmsg failed (flags=0x%x)", flags);
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

/**
 * Socket_sendall - Send all data (handles partial sends)
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (> 0)
 * Returns: Total bytes sent (always equals len on success)
 * Raises: Socket_Closed on EPIPE/ECONNRESET, Socket_Failed on error
 */
ssize_t
Socket_sendall (T socket, const void *buf, size_t len)
{
  volatile size_t total_sent = 0;
  const char *data = buf;

  assert (socket);
  assert (buf);
  assert (len > 0);

  TRY while (total_sent < len)
  {
    ssize_t sent = Socket_send (socket, data + total_sent, len - total_sent);
    if (sent == 0)
      {
        /* Would block (EAGAIN/EWOULDBLOCK) - return partial progress */
        return (ssize_t)total_sent;
      }
    total_sent += (size_t)sent;
  }
  EXCEPT (Socket_Closed)
  RERAISE;
  EXCEPT (Socket_Failed)
  RERAISE;
  END_TRY;

  return (ssize_t)total_sent;
}

/**
 * Socket_recvall - Receive all requested data (handles partial receives)
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (> 0)
 * Returns: Total bytes received (always equals len on success)
 * Raises: Socket_Closed on peer close or ECONNRESET, Socket_Failed on error
 */
ssize_t
Socket_recvall (T socket, void *buf, size_t len)
{
  volatile size_t total_received = 0;
  char *data = buf;

  assert (socket);
  assert (buf);
  assert (len > 0);

  TRY while (total_received < len)
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
  EXCEPT (Socket_Closed)
  RERAISE;
  EXCEPT (Socket_Failed)
  RERAISE;
  END_TRY;

  return (ssize_t)total_received;
}

ssize_t
Socket_sendvall (T socket, const struct iovec *iov, int iovcnt)
{
  struct iovec *iov_copy = NULL;
  volatile size_t total_sent = 0;
  size_t total_len;
  ssize_t sent;
  int i;

  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);

  /* Allocate working copy for SocketCommon_advance_iov */
  iov_copy = calloc ((size_t)iovcnt, sizeof (struct iovec));
  if (!iov_copy)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate iovec copy");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  memcpy (iov_copy, iov, (size_t)iovcnt * sizeof (struct iovec));

  TRY while (total_sent < total_len)
  {
    struct iovec *active_iov = NULL;
    int active_iovcnt = 0;

    /* Find first non-empty iov buffer */
    for (i = 0; i < iovcnt; i++)
      {
        if (iov_copy[i].iov_len > 0)
          {
            active_iov = &iov_copy[i];
            active_iovcnt = iovcnt - i;
            break;
          }
      }
    if (active_iov == NULL)
      break;

    sent = Socket_sendv (socket, active_iov, active_iovcnt);
    if (sent == 0)
      {
        free (iov_copy);
        return (ssize_t)total_sent;
      }
    total_sent += (size_t)sent;
    SocketCommon_advance_iov (iov_copy, iovcnt, (size_t)sent);
  }
  EXCEPT (Socket_Closed)
  free (iov_copy);
  RERAISE;
  EXCEPT (Socket_Failed)
  free (iov_copy);
  RERAISE;
  END_TRY;

  free (iov_copy);
  return (ssize_t)total_sent;
}

ssize_t
Socket_recvvall (T socket, struct iovec *iov, int iovcnt)
{
  struct iovec *iov_copy = NULL;
  volatile size_t total_received = 0;
  size_t total_len;
  ssize_t received;
  int i;

  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);

  /* Allocate working copy for SocketCommon_advance_iov */
  iov_copy = calloc ((size_t)iovcnt, sizeof (struct iovec));
  if (!iov_copy)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate iovec copy");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  memcpy (iov_copy, iov, (size_t)iovcnt * sizeof (struct iovec));

  TRY while (total_received < total_len)
  {
    struct iovec *active_iov = NULL;
    int active_iovcnt = 0;

    /* Find first non-empty iov buffer */
    for (i = 0; i < iovcnt; i++)
      {
        if (iov_copy[i].iov_len > 0)
          {
            active_iov = &iov_copy[i];
            active_iovcnt = iovcnt - i;
            break;
          }
      }
    if (active_iov == NULL)
      break;

    received = Socket_recvv (socket, active_iov, active_iovcnt);
    if (received == 0)
      {
        free (iov_copy);
        return (ssize_t)total_received;
      }
    total_received += (size_t)received;
    SocketCommon_advance_iov (iov_copy, iovcnt, (size_t)received);
  }
  EXCEPT (Socket_Closed)
  free (iov_copy);
  RERAISE;
  EXCEPT (Socket_Failed)
  free (iov_copy);
  RERAISE;
  END_TRY;

  free (iov_copy);
  return (ssize_t)total_received;
}

#undef T
