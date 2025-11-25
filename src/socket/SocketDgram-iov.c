/**
 * SocketDgram-iov.c - UDP/datagram socket scatter/gather I/O
 *
 * Implements scatter/gather I/O operations for UDP sockets including sendv,
 * recvv, sendvall, and recvvall. Handles vector I/O with proper error handling
 * and UDP size constraints.
 *
 * Features:
 * - Scatter/gather send/receive operations
 * - All-or-nothing send/receive variants
 * - UDP size validation for fragmentation avoidance
 * - Memory-efficient temporary buffer management
 * - Platform-independent vector I/O
 */

#include "core/Arena.h"
#include "core/Except.h"
#include "core/SocketConfig-limits.h"
#include "core/SocketConfig.h"
#include "socket/SocketDgram.h"
#include "socket/SocketDgram-private.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#define SOCKET_LOG_COMPONENT "SocketDgram"
#include "core/SocketError.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"
#define T SocketDgram_T
/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketDgram);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketDgram, e)

/** dgram_calculate_total_iov_len (renamed) removed: use shared */
/** SocketCommon_calculate_total_iov_len */
/** dgram_advance_iov (renamed) removed: use shared
   SocketCommon_advance_iov */

ssize_t
SocketDgram_sendv (T socket, const struct iovec *iov, int iovcnt)
{
  ssize_t result;
  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);
  /* Enforce UDP total payload sizing for sendv */
  size_t total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);
  if (total_len > SAFE_UDP_SIZE)
    {
      SOCKET_ERROR_MSG (
          "Sendv total %zu > SAFE_UDP_SIZE %zu (frag risk; max %zu)",
          total_len, SAFE_UDP_SIZE, UDP_MAX_PAYLOAD);
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  result = writev (SocketBase_fd (socket->base), iov, iovcnt);
  if (result < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      SOCKET_ERROR_FMT ("Scatter/gather send failed (iovcnt=%d)", iovcnt);
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return result;
}

/**
 * SocketDgram_recvv - Scatter/gather receive (readv wrapper)
 * @socket: Connected socket
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures (> 0, <= IOV_MAX)
 * Returns: Total bytes received (> 0) or 0 if would block (EAGAIN/EWOULDBLOCK)
 * Raises: SocketDgram_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: Receives data into multiple buffers in a single system call.
 * May receive less than requested. Use SocketDgram_recvvall() for guaranteed
 * complete receive.
 */

ssize_t
SocketDgram_recvv (T socket, struct iovec *iov, int iovcnt)
{
  ssize_t result;
  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);
  result = readv (SocketBase_fd (socket->base), iov, iovcnt);
  if (result < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      SOCKET_ERROR_FMT ("Scatter/gather receive failed (iovcnt=%d)", iovcnt);
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  return result;
}

/**
 * SocketDgram_sendall - Send all data (handles partial sends)
 * @socket: Connected socket
 * @buf: Data to send
 * @len: Length of data (> 0)
 * Returns: Total bytes sent (always equals len on success)
 * Raises: SocketDgram_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until all data is sent or an error occurs.
 * For non-blocking sockets, returns 0 if would block (EAGAIN/EWOULDBLOCK).
 * Use SocketDgram_isconnected() to verify connection state before calling.
 */
ssize_t
SocketDgram_sendall (T socket, const void *buf, size_t len)
{
  const char *ptr = (const char *)buf;
  volatile size_t total_sent = 0;
  ssize_t sent;
  assert (socket);
  assert (buf);
  assert (len > 0);
  TRY while (total_sent < len)
  {
    sent = SocketDgram_send (socket, ptr + total_sent, len - total_sent);
    if (sent == 0)
      {
        /* Would block (EAGAIN / EWOULDBLOCK) - return partial progress */
        return (ssize_t)total_sent;
      }
    total_sent += (size_t)sent;
  }
  EXCEPT (SocketDgram_Failed)
  RERAISE;
  END_TRY;
  return (ssize_t)total_sent;
}

/**
 * SocketDgram_recvall - Receive all requested data (handles partial receives)
 * @socket: Connected socket
 * @buf: Buffer for received data
 * @len: Buffer size (> 0)
 * Returns: Total bytes received (always equals len on success)
 * Raises: SocketDgram_Failed on error
 * Thread-safe: Yes (operates on single socket)
 * Note: Loops until len bytes are received or an error occurs.
 * For non-blocking sockets, returns 0 if would block (EAGAIN/EWOULDBLOCK).
 * Use SocketDgram_isconnected() to verify connection state before calling.
 */
ssize_t
SocketDgram_recvall (T socket, void *buf, size_t len)
{
  char *ptr = (char *)buf;
  volatile size_t total_received = 0;
  ssize_t received;
  assert (socket);
  assert (buf);
  assert (len > 0);
  TRY while (total_received < len)
  {
    received
        = SocketDgram_recv (socket, ptr + total_received, len - total_received);
    if (received == 0)
      {
        /* Would block (EAGAIN / EWOULDBLOCK) - return partial progress */
        return (ssize_t)total_received;
      }
    total_received += (size_t)received;
  }
  EXCEPT (SocketDgram_Failed)
  RERAISE;
  END_TRY;
  return (ssize_t)total_received;
}

ssize_t
SocketDgram_sendvall (T socket, const struct iovec *iov, int iovcnt)
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
  /* Calculate total length */
  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);
  /* Make a copy of iovec array for modification */
  iov_copy = calloc ((size_t)iovcnt, sizeof (struct iovec));
  if (!iov_copy)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate iovec copy");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  memcpy (iov_copy, iov, (size_t)iovcnt * sizeof (struct iovec));
  /* Make a copy of iovec array for modification */
  TRY while (total_sent < total_len)
  {
    /* Find first non-empty iovec */
    int active_iovcnt = 0;
    struct iovec *active_iov = NULL;
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
    /* All buffers sent (partial) */
    sent = SocketDgram_sendv (socket, active_iov, active_iovcnt);
    if (sent == 0)
      {
        /* Would block (EAGAIN / EWOULDBLOCK) - return partial progress */
        free (iov_copy);
        return (ssize_t)total_sent;
      }
    total_sent += (size_t)sent;
    SocketCommon_advance_iov (iov_copy, iovcnt, (size_t)sent);
  }
  EXCEPT (SocketDgram_Failed)
  free (iov_copy);
  RERAISE;
  END_TRY;
  free (iov_copy);
  return (ssize_t)total_sent;
}

ssize_t
SocketDgram_recvvall (T socket, struct iovec *iov, int iovcnt)
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
  /* Calculate total length */
  total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);
  /* Make a copy of iovec array for modification */
  iov_copy = calloc ((size_t)iovcnt, sizeof (struct iovec));
  if (!iov_copy)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate iovec copy");
      RAISE_MODULE_ERROR (SocketDgram_Failed);
    }
  memcpy (iov_copy, iov, (size_t)iovcnt * sizeof (struct iovec));
  TRY while (total_received < total_len)
  {
    /* Find first non-empty iovec */
    int active_iovcnt = 0;
    struct iovec *active_iov = NULL;
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
    /* All buffers filled (partial) */
    received = SocketDgram_recvv (socket, active_iov, active_iovcnt);
    if (received == 0)
      {
        /* Would block (EAGAIN / EWOULDBLOCK) - return partial progress: Copy
         * back partial data */
        for (i = 0; i < iovcnt; i++)
          {
            if (iov_copy[i].iov_base != iov[i].iov_base)
              {
                size_t copied
                    = (char *)iov_copy[i].iov_base - (char *)iov[i].iov_base;
                iov[i].iov_len -= copied;
                iov[i].iov_base = (char *)iov[i].iov_base + copied;
              }
          }
        free (iov_copy);
        return (ssize_t)total_received;
      }
    total_received += (size_t)received;
    SocketCommon_advance_iov (iov_copy, iovcnt, (size_t)received);
  }
  /* Copy back final data positions */
  for (i = 0; i < iovcnt; i++)
    {
      if (iov_copy[i].iov_base != iov[i].iov_base)
        {
          size_t copied
              = (char *)iov_copy[i].iov_base - (char *)iov[i].iov_base;
          iov[i].iov_len -= copied;
          iov[i].iov_base = (char *)iov[i].iov_base + copied;
        }
    }
  EXCEPT (SocketDgram_Failed)
  free (iov_copy);
  RERAISE;
  END_TRY;
  free (iov_copy);
  return (ssize_t)total_received;
}

#undef T
