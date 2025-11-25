/**
 * SocketIO-tls-iov.c - TLS scatter/gather I/O operations
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * TLS-specific scatter/gather (iovec) I/O implementations. These functions
 * emulate writev/readv for TLS connections by copying data through a
 * temporary buffer since OpenSSL doesn't support scatter/gather natively.
 *
 * Features:
 * - TLS scatter/gather send (writev emulation)
 * - TLS scatter/gather receive (readv emulation)
 * - Safe buffer copying with overflow protection
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/Socket-private.h"
#include "socket/SocketCommon.h"

#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

#define T Socket_T

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketIO_TLS_IOV);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR (SocketIO_TLS_IOV, e)

/* Forward declarations for TLS helper functions in SocketIO-tls.c */
extern SSL *socket_get_ssl (T socket);
extern int socket_handle_ssl_error (T socket, SSL *ssl, int ssl_result);
extern SSL *socket_validate_tls_ready (T socket);
extern int socket_is_recoverable_io_error (void);

/**
 * copy_iov_to_buffer - Copy iovec array to contiguous buffer
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 * @buffer: Destination buffer
 * @buffer_size: Size of destination buffer
 *
 * Returns: Total bytes copied
 * Raises: Socket_Failed if buffer too small
 * Thread-safe: Yes (operates on local data)
 */
static size_t
copy_iov_to_buffer (const struct iovec *iov, int iovcnt, void *buffer,
                    size_t buffer_size)
{
  size_t offset = 0;

  for (int i = 0; i < iovcnt; i++)
    {
      if (offset + iov[i].iov_len > buffer_size)
        {
          SOCKET_ERROR_MSG ("Buffer too small for iovec copy");
          RAISE_MODULE_ERROR (Socket_Failed);
        }
      memcpy ((char *)buffer + offset, iov[i].iov_base, iov[i].iov_len);
      offset += iov[i].iov_len;
    }

  return offset;
}

/**
 * distribute_buffer_to_iov - Distribute buffer data across iovec array
 * @buffer: Source buffer
 * @buffer_len: Length of data in buffer
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 *
 * Returns: Total bytes distributed
 * Thread-safe: Yes (operates on local data)
 */
static size_t
distribute_buffer_to_iov (const void *buffer, size_t buffer_len,
                          struct iovec *iov, int iovcnt)
{
  size_t remaining = buffer_len;
  size_t src_offset = 0;

  for (int i = 0; i < iovcnt && remaining > 0; i++)
    {
      size_t chunk = (remaining > iov[i].iov_len) ? iov[i].iov_len : remaining;
      memcpy (iov[i].iov_base, (char *)buffer + src_offset, chunk);
      src_offset += chunk;
      remaining -= chunk;
    }

  return buffer_len - remaining;
}

/**
 * socket_sendv_tls - TLS scatter/gather send implementation
 * @socket: Socket instance
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 *
 * Returns: Total bytes sent or 0 if would block
 * Raises: Socket_Failed or SocketTLS_Failed
 * Thread-safe: Yes (operates on single socket)
 */
ssize_t
socket_sendv_tls (T socket, const struct iovec *iov, int iovcnt)
{
  SSL *ssl = socket_validate_tls_ready (socket);
  size_t total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);

  Arena_T arena = SocketBase_arena (socket->base);
  void *temp_buf = Arena_calloc (arena, total_len, 1, __FILE__, __LINE__);
  if (!temp_buf)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate TLS sendv buffer");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  copy_iov_to_buffer (iov, iovcnt, temp_buf, total_len);

  int ssl_result = SSL_write (ssl, temp_buf, (int)total_len);

  if (ssl_result <= 0)
    {
      socket_handle_ssl_error (socket, ssl, ssl_result);
      if (socket_is_recoverable_io_error ())
        return 0;
      SOCKET_ERROR_FMT ("TLS sendv failed (iovcnt=%d)", iovcnt);
      RAISE_MODULE_ERROR (SocketTLS_Failed);
    }

  return (ssize_t)ssl_result;
}

/**
 * socket_recvv_tls - TLS scatter/gather receive implementation
 * @socket: Socket instance
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 *
 * Returns: Total bytes received or 0 if would block
 * Raises: Socket_Failed, SocketTLS_Failed, or Socket_Closed
 * Thread-safe: Yes (operates on single socket)
 */
ssize_t
socket_recvv_tls (T socket, struct iovec *iov, int iovcnt)
{
  SSL *ssl = socket_validate_tls_ready (socket);
  size_t total_capacity = SocketCommon_calculate_total_iov_len (iov, iovcnt);

  Arena_T arena = SocketBase_arena (socket->base);
  void *temp_buf = Arena_calloc (arena, total_capacity, 1, __FILE__, __LINE__);
  if (!temp_buf)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot allocate TLS recvv buffer");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  int ssl_result = SSL_read (ssl, temp_buf, (int)total_capacity);

  if (ssl_result <= 0)
    {
      socket_handle_ssl_error (socket, ssl, ssl_result);
      if (socket_is_recoverable_io_error ())
        return 0;
      if (ssl_result == 0 || errno == ECONNRESET)
        RAISE (Socket_Closed);
      SOCKET_ERROR_FMT ("TLS recvv failed (iovcnt=%d)", iovcnt);
      RAISE_MODULE_ERROR (SocketTLS_Failed);
    }

  return (ssize_t)distribute_buffer_to_iov (temp_buf, (size_t)ssl_result, iov,
                                            iovcnt);
}

#undef T

#endif /* SOCKET_HAS_TLS */

