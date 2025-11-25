/**
 * SocketIO-tls.c - TLS I/O operations for socket library
 *
 * TLS-specific scatter/gather I/O implementations and SSL error handling.
 * These functions provide TLS encryption/decryption for socket operations.
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/Socket-private.h"
#include "socket/SocketCommon.h"
#include "core/SocketError.h"

#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

#define T Socket_T

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketIO_TLS);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketIO_TLS, e)

#ifdef SOCKET_HAS_TLS

/**
 * copy_iov_to_buffer - Copy iovec array to contiguous buffer
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 * @buffer: Destination buffer
 * @buffer_size: Size of destination buffer
 * Returns: Total bytes copied
 * Raises: Socket_Failed if buffer too small
 */
static size_t
copy_iov_to_buffer (const struct iovec *iov, int iovcnt, void *buffer, size_t buffer_size)
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
 * Returns: Total bytes distributed
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
 * socket_get_ssl - Helper to get SSL object from socket
 * @socket: Socket instance
 *
 * Returns: SSL object or NULL if not available
 */
SSL *
socket_get_ssl (T socket)
{
  if (!socket || !socket->tls_enabled || !socket->tls_ssl)
    return NULL;
  return (SSL *)socket->tls_ssl;
}

/**
 * socket_handle_ssl_error - Helper to handle SSL error codes
 * @socket: Socket instance
 * @ssl: SSL object
 * @ssl_result: Result from SSL operation
 *
 * Returns: 0 on success, -1 on error (sets errno)
 * Thread-safe: Yes (operates on single socket)
 * Maps SSL error codes to errno values and updates socket state.
 * Used by TLS-aware I/O functions for consistent error handling.
 */
int
socket_handle_ssl_error (T socket, SSL *ssl, int ssl_result)
{
  int ssl_error = SSL_get_error (ssl, ssl_result);

  switch (ssl_error)
    {
    case SSL_ERROR_NONE:
      return 0; /* Success */

    case SSL_ERROR_SSL:
      /* Internal OpenSSL protocol error */
      errno = EPROTO;
      return -1;

    case SSL_ERROR_WANT_READ:
      socket->tls_handshake_done = 0; /* Handshake not complete */
      errno = EAGAIN;
      return -1;

    case SSL_ERROR_WANT_WRITE:
      socket->tls_handshake_done = 0; /* Handshake not complete */
      errno = EAGAIN;
      return -1;

    case SSL_ERROR_WANT_X509_LOOKUP:
      /* Certificate lookup needed - retry after loading certs */
      errno = EAGAIN;
      return -1;

    case SSL_ERROR_ZERO_RETURN:
      /* TLS connection closed cleanly */
      errno = ECONNRESET;
      return -1;

    case SSL_ERROR_SYSCALL:
      /* System call error - check errno */
      if (errno == 0)
        errno = ECONNRESET; /* EOF */
      return -1;

    case SSL_ERROR_WANT_CONNECT:
      /* Underlying BIO wants connect */
      socket->tls_handshake_done = 0;
      errno = EINPROGRESS;
      return -1;

    case SSL_ERROR_WANT_ACCEPT:
      /* Underlying BIO wants accept */
      socket->tls_handshake_done = 0;
      errno = EAGAIN;
      return -1;

    case SSL_ERROR_WANT_ASYNC:
    case SSL_ERROR_WANT_ASYNC_JOB:
      /* Async operation pending */
      errno = EAGAIN;
      return -1;

    case SSL_ERROR_WANT_CLIENT_HELLO_CB:
      /* Client Hello callback needed */
      errno = EAGAIN;
      return -1;

    case SSL_ERROR_WANT_RETRY_VERIFY:
      /* Retry verification */
      errno = EAGAIN;
      return -1;

    default:
      /* Unexpected SSL errors */
      errno = EPROTO;
      return -1;
    }
}

/**
 * socket_sendv_tls - TLS scatter/gather send implementation
 * @socket: Socket instance
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 * Returns: Total bytes sent or 0 if would block
 * Raises: Socket_Failed or SocketTLS_Failed
 */
ssize_t
socket_sendv_tls (T socket, const struct iovec *iov, int iovcnt)
{
  SSL *ssl = socket_get_ssl (socket);
  if (!ssl)
    {
      SOCKET_ERROR_MSG ("TLS enabled but SSL context is NULL");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Check if handshake is complete */
  if (!socket->tls_handshake_done)
    {
      SOCKET_ERROR_MSG ("TLS handshake not complete");
      RAISE_MODULE_ERROR (SocketTLS_HandshakeFailed);
    }

  /* Calculate total length with overflow protection */
  size_t total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);

  /* Allocate temp buffer from socket arena */
  Arena_T arena = SocketBase_arena (socket->base);
  void *temp_buf = Arena_calloc (arena, total_len, 1, __FILE__, __LINE__);
  if (!temp_buf)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot Arena_calloc temp buffer "
                                      "for TLS sendv (total_len=%zu)",
                        total_len);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Copy iovec data to temp buffer */
  copy_iov_to_buffer (iov, iovcnt, temp_buf, total_len);

  /* Use SSL_write() */
  int ssl_result = SSL_write (ssl, temp_buf, (int)total_len);

  if (ssl_result <= 0)
    {
      if (socket_handle_ssl_error (socket, ssl, ssl_result) < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0; /* Would block */
        }
    }

  if (ssl_result < 0)
    {
      SOCKET_ERROR_FMT ("TLS sendv failed (iovcnt=%d, total_len=%zu)",
                        iovcnt, total_len);
      RAISE_MODULE_ERROR (SocketTLS_Failed);
    }

  return (ssize_t)ssl_result;
}

/**
 * socket_recvv_tls - TLS scatter/gather receive implementation
 * @socket: Socket instance
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 * Returns: Total bytes received or 0 if would block
 * Raises: Socket_Failed, SocketTLS_Failed, or Socket_Closed
 */
ssize_t
socket_recvv_tls (T socket, struct iovec *iov, int iovcnt)
{
  SSL *ssl = socket_get_ssl (socket);
  if (!ssl)
    {
      SOCKET_ERROR_MSG ("TLS enabled but SSL context is NULL");
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Check if handshake is complete */
  if (!socket->tls_handshake_done)
    {
      SOCKET_ERROR_MSG ("TLS handshake not complete");
      RAISE_MODULE_ERROR (SocketTLS_HandshakeFailed);
    }

  /* Calculate total capacity */
  size_t total_capacity = SocketCommon_calculate_total_iov_len (iov, iovcnt);

  /* Allocate temp buffer from socket arena */
  Arena_T arena = SocketBase_arena (socket->base);
  void *temp_buf = Arena_calloc (arena, total_capacity, 1, __FILE__, __LINE__);
  if (!temp_buf)
    {
      SOCKET_ERROR_MSG (SOCKET_ENOMEM ": Cannot Arena_calloc temp buffer "
                                      "for TLS recvv (total_capacity=%zu)",
                        total_capacity);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  /* Read up to total capacity into temp buffer */
  int ssl_result = SSL_read (ssl, temp_buf, (int)total_capacity);

  if (ssl_result <= 0)
    {
      if (socket_handle_ssl_error (socket, ssl, ssl_result) < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0; /* Would block */
          if (errno == ECONNRESET)
            RAISE (Socket_Closed);
        }

      /* If we get here, it's an error that wasn't EAGAIN/ECONNRESET */
      if (ssl_result == 0)
        RAISE (Socket_Closed);

      SOCKET_ERROR_FMT ("TLS recvv failed (iovcnt=%d, capacity=%zu)",
                        iovcnt, total_capacity);
      RAISE_MODULE_ERROR (SocketTLS_Failed);
    }

  /* Distribute data across iovecs */
  return (ssize_t)distribute_buffer_to_iov (temp_buf, (size_t)ssl_result, iov, iovcnt);
}

#endif /* SOCKET_HAS_TLS */

#undef T
