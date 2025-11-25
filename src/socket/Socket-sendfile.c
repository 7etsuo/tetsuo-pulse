/**
 * Socket-sendfile.c - Sendfile operations for efficient file transfer
 *
 * Implements sendfile system calls for efficient file transfer from file
 * descriptors to sockets. Provides platform-specific implementations with
 * proper error handling and TLS support. Includes sendfileall for guaranteed
 * complete file transfers.
 *
 * Features:
 * - Platform-specific sendfile implementations (Linux, BSD/macOS, fallback)
 * - TLS-aware sendfile operations
 * - Sendfileall for guaranteed complete transfers
 * - Memory-efficient zero-copy file transfer
 * - Error handling with detailed diagnostics
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/Socket.h"
#define SOCKET_LOG_COMPONENT "Socket"
#include "core/SocketError.h"
#include "socket/Socket-private.h"

#define T Socket_T

/* Forward declarations */
ssize_t socket_send_internal (T socket, const void *buf, size_t len, int flags);

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec (thread) Except_T SocketSendfile_DetailedException;
#else
static __thread Except_T SocketSendfile_DetailedException;
#endif

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e)                                                 \
  do                                                                          \
    {                                                                         \
      SocketSendfile_DetailedException = (e);                                 \
      SocketSendfile_DetailedException.reason = socket_error_buf;            \
      RAISE (SocketSendfile_DetailedException);                              \
    }                                                                         \
  while (0)

#ifdef __linux__
#include <sys/sendfile.h>
#define HAS_SENDFILE 1
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/uio.h>
#define HAS_SENDFILE 1
#endif

#ifndef HAS_SENDFILE
#define HAS_SENDFILE 0
#endif

/* ==================== Sendfile Platform Implementations ==================== */

#if HAS_SENDFILE

#if defined(__linux__)
/**
 * sendfile_linux - Linux sendfile implementation
 * @socket_fd: Destination socket file descriptor
 * @file_fd: Source file file descriptor
 * @offset: File offset (modified)
 * @count: Bytes to send
 *
 * Returns: Bytes sent or -1 on error
 */
static ssize_t
sendfile_linux (int socket_fd, int file_fd, off_t *offset, size_t count)
{
  return sendfile (socket_fd, file_fd, offset, count);
}
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
/**
 * sendfile_bsd - BSD/macOS sendfile implementation
 * @socket_fd: Destination socket file descriptor
 * @file_fd: Source file file descriptor
 * @offset: File offset (modified)
 * @count: Bytes to send
 *
 * Returns: Bytes sent or -1 on error
 */
static ssize_t
sendfile_bsd (int socket_fd, int file_fd, off_t *offset, size_t count)
{
  off_t len = (off_t)count;
  int result;

  result = sendfile (file_fd, socket_fd, *offset, &len, NULL, 0);
  if (result == 0)
    {
      *offset += len;
      return (ssize_t)len;
    }
  return -1;
}
#endif

#endif /* HAS_SENDFILE */

/**
 * socket_sendfile_internal - Internal sendfile implementation
 * @socket: Destination socket
 * @file_fd: Source file descriptor
 * @offset: File offset (modified on success)
 * @count: Bytes to send
 *
 * Returns: Bytes sent or 0 if would block
 */
static ssize_t
socket_sendfile_internal (T socket, int file_fd, off_t *offset, size_t count)
{
  assert (socket);
  assert (file_fd >= 0);
  assert (offset);
  assert (count > 0);

  int socket_fd = SocketBase_fd (socket->base);

#ifdef SOCKET_HAS_TLS
  if (socket->tls_enabled && socket->tls_ssl)
    {
      /* TLS path: read from file and use SSL_write */
      Arena_T arena = SocketBase_arena (socket->base);
      void *buf = Arena_calloc (arena, count, 1, __FILE__, __LINE__);
      if (!buf)
        {
          SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate buffer for TLS "
                                          "sendfile (count=%zu)",
                            count);
          RAISE_MODULE_ERROR (Socket_Failed);
        }

      /* Read from file */
      ssize_t read_result = pread (file_fd, buf, count, *offset);
      if (read_result < 0)
        {
          SOCKET_ERROR_FMT ("Failed to read file for TLS sendfile");
          RAISE_MODULE_ERROR (Socket_Failed);
        }
      if (read_result == 0)
        {
          /* EOF */
          return 0;
        }

      /* Send via TLS */
      ssize_t send_result = socket_send_internal (socket, buf, (size_t)read_result, 0);
      if (send_result > 0)
        {
          *offset += send_result;
        }

      return send_result;
    }
#endif

  /* Non-TLS path */
#if HAS_SENDFILE
  {
    ssize_t result;

#if defined(__linux__)
    result = sendfile_linux (socket_fd, file_fd, offset, count);
#elif defined(__APPLE__) || defined(__FreeBSD__)
    result = sendfile_bsd (socket_fd, file_fd, offset, count);
#endif

    if (result < 0)
      {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          return 0; /* Would block */
        if (errno == EPIPE)
          RAISE (Socket_Closed);
        if (errno == ECONNRESET)
          RAISE (Socket_Closed);
        SOCKET_ERROR_FMT ("Sendfile failed (file_fd=%d, count=%zu)", file_fd,
                          count);
        RAISE_MODULE_ERROR (Socket_Failed);
      }

    return result;
  }
#else
  /* Fallback implementation using read/write */
  {
    Arena_T arena = SocketBase_arena (socket->base);
    void *buf = Arena_calloc (arena, SOCKET_SENDFILE_BUFSIZE, 1, __FILE__,
                              __LINE__);
    if (!buf)
      {
        SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate buffer for "
                                        "sendfile fallback");
        RAISE_MODULE_ERROR (Socket_Failed);
      }

    size_t remaining = count;
    ssize_t total_sent = 0;

    while (remaining > 0)
      {
        size_t chunk = (remaining > SOCKET_SENDFILE_BUFSIZE)
                           ? SOCKET_SENDFILE_BUFSIZE
                           : remaining;

        /* Read from file */
        ssize_t read_result = pread (file_fd, buf, chunk, *offset);
        if (read_result < 0)
          {
            SOCKET_ERROR_FMT ("Failed to read file for sendfile fallback");
            RAISE_MODULE_ERROR (Socket_Failed);
          }
        if (read_result == 0)
          {
            /* EOF */
            break;
          }

        /* Send to socket */
        ssize_t send_result = socket_send_internal (socket, buf, (size_t)read_result, 0);
        if (send_result == 0)
          {
            /* Would block - return partial progress */
            return total_sent;
          }

        *offset += send_result;
        total_sent += send_result;
        remaining -= (size_t)send_result;
      }

    return total_sent;
  }
#endif /* HAS_SENDFILE */
}

#undef T
