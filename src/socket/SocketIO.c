/**
 * SocketIO.c - Internal I/O abstraction layer
 *
 * Implements the internal I/O operations for sockets, handling both
 * standard system calls (send/recv) and TLS operations (SSL_write/SSL_read).
 * This abstraction allows the upper layers to be agnostic of the underlying
 * transport security.
 *
 * Features:
 * - Transparent TLS support
 * - Scatter/gather I/O emulation for TLS
 * - Consistent error handling via exceptions
 * - Thread-safe operation
 */

#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/Socket-private.h"
#include "socket/Socket.h"
#include "socket/SocketIO.h"
#include "socket/SocketCommon.h"
#include "socket/SocketCommon-private.h"
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketIO"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec (thread) Except_T SocketIO_DetailedException;
#else
static __thread Except_T SocketIO_DetailedException;
#endif

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) do { \
  SocketIO_DetailedException = (e); \
  SocketIO_DetailedException.reason = socket_error_buf; \
  RAISE(SocketIO_DetailedException); \
} while(0)

#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

#define T Socket_T

/* Forward declaration */
extern int Socket_fd (const T socket);

#ifdef SOCKET_HAS_TLS

/**
 * socket_get_ssl - Helper to get SSL object from socket
 * @socket: Socket instance
 *
 * Returns: SSL object or NULL if not available
 */
static SSL *
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
 */
static int
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

#endif /* SOCKET_HAS_TLS */

/**
 * socket_send_internal - Internal send operation
 * @socket: Socket instance
 * @buf: Data to send
 * @len: Length of data
 * @flags: Send flags
 *
 * Returns: Bytes sent or 0 if would block
 */
ssize_t
socket_send_internal (T socket, const void *buf, size_t len, int flags)
{
  assert (socket);
  assert (buf);
  assert (len > 0);

#ifdef SOCKET_HAS_TLS
  if (socket->tls_enabled && socket->tls_ssl)
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

      /* Use SSL_write() for TLS */
      int ssl_result = SSL_write (ssl, buf, (int)len);

      if (ssl_result <= 0)
        {
          if (socket_handle_ssl_error (socket, ssl, ssl_result) < 0)
            {
              if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0; /* Would block */
                          /* Other errors will raise exception below */
            }
        }

      if (ssl_result < 0)
        {
          SOCKET_ERROR_FMT ("TLS send failed (len=%zu)", len);
          RAISE_MODULE_ERROR (SocketTLS_Failed);
        }

      return (ssize_t)ssl_result;
    }
#endif

  /* Non-TLS path: use standard send() */
  ssize_t result = send (Socket_fd (socket), buf, len, flags);

  if (result < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      if (errno == EPIPE)
        RAISE (Socket_Closed);
      if (errno == ECONNRESET)
        RAISE (Socket_Closed);
      SOCKET_ERROR_FMT ("Send failed (len=%zu)", len);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return result;
}

/**
 * socket_recv_internal - Internal receive operation
 * @socket: Socket instance
 * @buf: Buffer for received data
 * @len: Buffer size
 * @flags: Receive flags
 *
 * Returns: Bytes received or 0 if would block
 */
ssize_t
socket_recv_internal (T socket, void *buf, size_t len, int flags)
{
  assert (socket);
  assert (buf);
  assert (len > 0);

#ifdef SOCKET_HAS_TLS
  if (socket->tls_enabled && socket->tls_ssl)
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

      /* Use SSL_read() for TLS */
      int ssl_result = SSL_read (ssl, buf, (int)len);

      if (ssl_result <= 0)
        {
          if (socket_handle_ssl_error (socket, ssl, ssl_result) < 0)
            {
              if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0; /* Would block */
              if (errno == ECONNRESET)
                RAISE (Socket_Closed);
              /* Other errors will raise exception below */
            }
        }

      if (ssl_result < 0)
        {
          SOCKET_ERROR_FMT ("TLS receive failed (len=%zu)", len);
          RAISE_MODULE_ERROR (SocketTLS_Failed);
        }

      if (ssl_result == 0)
        {
          /* TLS connection closed cleanly */
          RAISE (Socket_Closed);
        }

      return (ssize_t)ssl_result;
    }
#endif

  /* Non-TLS path: use standard recv() */
  ssize_t result = recv (Socket_fd (socket), buf, len, flags);

  if (result < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      if (errno == ECONNRESET)
        RAISE (Socket_Closed);
      SOCKET_ERROR_FMT ("Receive failed (len=%zu)", len);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  else if (result == 0)
    {
      RAISE (Socket_Closed);
    }

  return result;
}

/**
 * socket_sendv_internal - Internal scatter/gather send
 * @socket: Socket instance
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 * @flags: Send flags
 *
 * Returns: Total bytes sent or 0 if would block
 */
ssize_t
socket_sendv_internal (T socket, const struct iovec *iov, int iovcnt,
                       int flags)
{
  (void)flags; /* Suppress unused parameter warning */

  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

#ifdef SOCKET_HAS_TLS
  if (socket->tls_enabled && socket->tls_ssl)
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

      /* Calculate total length with overflow protection via common helper (raises on error) */
      size_t total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);

      /* Allocate temp buffer from socket arena (security zero-init, lifecycle managed) */
      Arena_T arena = SocketBase_arena (socket->base);
      void *temp_buf = Arena_calloc (arena, total_len, 1, __FILE__, __LINE__);
      if (!temp_buf)
        {
          SOCKET_ERROR_MSG (SOCKET_ENOMEM
                            ": Cannot Arena_calloc temp buffer for TLS sendv (total_len=%zu)", total_len);
          RAISE_MODULE_ERROR (Socket_Failed);
        }

      /* Copy iovec data to temp buffer */
      size_t offset = 0;
      for (int i = 0; i < iovcnt; i++)
        {
          memcpy ((char *)temp_buf + offset, iov[i].iov_base, iov[i].iov_len);
          offset += iov[i].iov_len;
        }

      /* Use SSL_write() */
      int ssl_result = SSL_write (ssl, temp_buf, (int)total_len);

      /* Free temp buffer immediately */
      /* arena-managed temp_buf: no free needed */

      if (ssl_result <= 0)
        {
          if (socket_handle_ssl_error (socket, ssl, ssl_result) < 0)
            {
              if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0; /* Would block */
                          /* Other errors will raise exception below */
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
#endif

  /* Non-TLS path: use standard writev() */
  ssize_t result = writev (Socket_fd (socket), iov, iovcnt);
  if (result < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      if (errno == EPIPE)
        RAISE (Socket_Closed);
      if (errno == ECONNRESET)
        RAISE (Socket_Closed);
      SOCKET_ERROR_FMT ("Scatter/gather send failed (iovcnt=%d)", iovcnt);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return result;
}

/**
 * socket_recvv_internal - Internal scatter/gather receive
 * @socket: Socket instance
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 * @flags: Receive flags
 *
 * Returns: Total bytes received or 0 if would block
 */
ssize_t
socket_recvv_internal (T socket, struct iovec *iov, int iovcnt, int flags)
{
  (void)flags; /* Suppress unused parameter warning */

  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

#ifdef SOCKET_HAS_TLS
  if (socket->tls_enabled && socket->tls_ssl)
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

      /* Calculate total capacity with overflow protection */
      /* Calculate total capacity via common helper (raises on overflow/invalid) */
      size_t total_capacity = SocketCommon_calculate_total_iov_len (iov, iovcnt);

      /* Allocate temp buffer from socket arena (security zero-init) */
      Arena_T arena = SocketBase_arena (socket->base);
      void *temp_buf = Arena_calloc (arena, total_capacity, 1, __FILE__, __LINE__);
      if (!temp_buf)
        {
          SOCKET_ERROR_MSG (SOCKET_ENOMEM
                            ": Cannot Arena_calloc temp buffer for TLS recvv (total_capacity=%zu)", total_capacity);
          RAISE_MODULE_ERROR (Socket_Failed);
        }

      /* Read up to total capacity into temp buffer */
      int ssl_result = SSL_read (ssl, temp_buf, (int)total_capacity);

      if (ssl_result <= 0)
        {
          /* arena-managed temp_buf: no free needed */ /* Free before error handling */

          if (socket_handle_ssl_error (socket, ssl, ssl_result) < 0)
            {
              if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0; /* Would block */
              if (errno == ECONNRESET)
                RAISE (Socket_Closed);
              /* Other errors will raise exception below */
            }

          /* If we get here, it's an error that wasn't EAGAIN/ECONNRESET */
          if (ssl_result == 0)
            RAISE (Socket_Closed);

          SOCKET_ERROR_FMT ("TLS recvv failed (iovcnt=%d, capacity=%zu)",
                            iovcnt, total_capacity);
          RAISE_MODULE_ERROR (SocketTLS_Failed);
        }

      /* Distribute data across iovecs */
      size_t remaining = (size_t)ssl_result;
      size_t src_offset = 0;
      for (int i = 0; i < iovcnt && remaining > 0; i++)
        {
          size_t chunk
              = (remaining > iov[i].iov_len) ? iov[i].iov_len : remaining;
          memcpy (iov[i].iov_base, (char *)temp_buf + src_offset, chunk);
          src_offset += chunk;
          remaining -= chunk;
        }

      /* arena-managed temp_buf: no free needed */

      return (ssize_t)ssl_result;
    }
#endif

  /* Non-TLS path: use standard readv() */
  ssize_t result = readv (Socket_fd (socket), iov, iovcnt);
  if (result < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      if (errno == ECONNRESET)
        RAISE (Socket_Closed);
      SOCKET_ERROR_FMT ("Scatter/gather receive failed (iovcnt=%d)", iovcnt);
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  else if (result == 0)
    {
      RAISE (Socket_Closed);
    }

  return result;
}

/**
 * socket_is_tls_enabled - Check if TLS is enabled
 * @socket: Socket instance
 *
 * Returns: 1 if enabled, 0 otherwise
 */
int
socket_is_tls_enabled (T socket)
{
  assert (socket);
#ifdef SOCKET_HAS_TLS
  return socket->tls_enabled ? 1 : 0;
#else
  return 0;
#endif
}

/**
 * socket_tls_want_read - Check if TLS wants read
 * @socket: Socket instance
 *
 * Returns: 1 if want read, 0 otherwise
 */
int
socket_tls_want_read (T socket)
{
  assert (socket);
#ifdef SOCKET_HAS_TLS
  if (!socket->tls_enabled || !socket->tls_ssl)
    return 0;

  /* Check if handshake is in progress and wants read */
  if (!socket->tls_handshake_done)
    {
      return (socket->tls_last_handshake_state == TLS_HANDSHAKE_WANT_READ) ? 1
                                                                           : 0;
    }

  /* For established connections, SSL_pending indicates data available */
  SSL *ssl = socket_get_ssl (socket);
  if (ssl && SSL_pending (ssl) > 0)
    return 1;

  return 0;
#else
  return 0;
#endif
}

/**
 * socket_tls_want_write - Check if TLS wants write
 * @socket: Socket instance
 *
 * Returns: 1 if want write, 0 otherwise
 */
int
socket_tls_want_write (T socket)
{
  assert (socket);
#ifdef SOCKET_HAS_TLS
  if (!socket->tls_enabled || !socket->tls_ssl)
    return 0;

  /* Check if handshake is in progress and wants write */
  if (!socket->tls_handshake_done)
    {
      return (socket->tls_last_handshake_state == TLS_HANDSHAKE_WANT_WRITE)
                 ? 1
                 : 0;
    }

  return 0;
#else
  return 0;
#endif
}

#undef T
