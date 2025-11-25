/**
 * SocketIO-tls.c - TLS I/O operations for socket library
 *
 * TLS-specific scatter/gather I/O implementations and SSL error handling.
 * These functions provide TLS encryption/decryption for socket operations.
 */

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/Socket-private.h"
#include "socket/SocketCommon.h"

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

/* Forward declarations for internal functions */
static SSL *validate_tls_ready (T socket);
static int is_recoverable_tls_error (void);
SSL *socket_get_ssl (T socket);
int socket_handle_ssl_error (T socket, SSL *ssl, int ssl_result);

/**
 * validate_tls_ready - Validate TLS is ready for I/O
 * @socket: Socket instance
 *
 * Returns: SSL pointer if ready, raises exception otherwise
 * Thread-safe: Yes (operates on single socket)
 */
static SSL *
validate_tls_ready (T socket)
{
  SSL *ssl = socket_get_ssl (socket);
  if (!ssl)
    {
      SOCKET_ERROR_MSG ("TLS enabled but SSL context is NULL");
      RAISE_MODULE_ERROR (Socket_Failed);
    }
  if (!socket->tls_handshake_done)
    {
      SOCKET_ERROR_MSG ("TLS handshake not complete");
      RAISE_MODULE_ERROR (SocketTLS_HandshakeFailed);
    }
  return ssl;
}

/**
 * is_recoverable_tls_error - Check if errno indicates recoverable I/O
 *
 * Returns: 1 if EAGAIN/EWOULDBLOCK, 0 otherwise
 * Thread-safe: Yes (reads errno)
 */
static int
is_recoverable_tls_error (void)
{
  return errno == EAGAIN || errno == EWOULDBLOCK;
}

/**
 * socket_send_tls - TLS send operation
 * @socket: Socket instance with TLS enabled
 * @buf: Data to send
 * @len: Length of data
 *
 * Returns: Bytes sent or 0 if would block
 * Raises: SocketTLS_Failed on error
 * Thread-safe: Yes (operates on single socket)
 */
ssize_t
socket_send_tls (T socket, const void *buf, size_t len)
{
  SSL *ssl = validate_tls_ready (socket);
  int ssl_result = SSL_write (ssl, buf, (int)len);

  if (ssl_result <= 0)
    {
      socket_handle_ssl_error (socket, ssl, ssl_result);
      if (is_recoverable_tls_error ())
        return 0;
    }
  if (ssl_result < 0)
    {
      SOCKET_ERROR_FMT ("TLS send failed (len=%zu)", len);
      RAISE_MODULE_ERROR (SocketTLS_Failed);
    }
  return (ssize_t)ssl_result;
}

/**
 * socket_recv_tls - TLS receive operation
 * @socket: Socket instance with TLS enabled
 * @buf: Buffer for received data
 * @len: Buffer size
 *
 * Returns: Bytes received or 0 if would block
 * Raises: SocketTLS_Failed on error, Socket_Closed on disconnect
 * Thread-safe: Yes (operates on single socket)
 */
ssize_t
socket_recv_tls (T socket, void *buf, size_t len)
{
  SSL *ssl = validate_tls_ready (socket);
  int ssl_result = SSL_read (ssl, buf, (int)len);

  if (ssl_result <= 0)
    {
      socket_handle_ssl_error (socket, ssl, ssl_result);
      if (is_recoverable_tls_error ())
        return 0;
      if (errno == ECONNRESET)
        RAISE (Socket_Closed);
    }
  if (ssl_result < 0)
    {
      SOCKET_ERROR_FMT ("TLS receive failed (len=%zu)", len);
      RAISE_MODULE_ERROR (SocketTLS_Failed);
    }
  if (ssl_result == 0)
    RAISE (Socket_Closed);

  return (ssize_t)ssl_result;
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

/* socket_sendv_tls and socket_recvv_tls are in SocketIO-tls-iov.c */

#endif /* SOCKET_HAS_TLS */

#undef T
