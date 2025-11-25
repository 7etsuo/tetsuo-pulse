/**
 * SocketTLS-io.c - TLS I/O Operations
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements TLS send/recv wrappers using OpenSSL SSL_write/SSL_read.
 * Handles non-blocking behavior by returning 0 on WANT_READ/WRITE,
 * error mapping, and exception raising.
 *
 * Thread safety: No - per-socket operations
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include <assert.h>
#include <errno.h>

#define T SocketTLS_T

ssize_t
SocketTLS_send (Socket_T socket, const void *buf, size_t len)
{
  assert (socket);
  assert (buf);
  assert (len > 0);

  SSL *ssl = VALIDATE_TLS_IO_READY (socket, SocketTLS_Failed);
  int result = SSL_write (ssl, buf, (int)len);

  if (result > 0)
    {
      return (ssize_t)result;
    }
  else
    {
      TLSHandshakeState state = tls_handle_ssl_error (socket, ssl, result);
      if (state == TLS_HANDSHAKE_ERROR)
        {
          tls_format_openssl_error ("TLS send failed");
          RAISE_TLS_ERROR (SocketTLS_Failed);
        }
      errno = EAGAIN;
      return 0;
    }
}

ssize_t
SocketTLS_recv (Socket_T socket, void *buf, size_t len)
{
  assert (socket);
  assert (buf);
  assert (len > 0);

  SSL *ssl = VALIDATE_TLS_IO_READY (socket, SocketTLS_Failed);
  int result = SSL_read (ssl, buf, (int)len);

  if (result > 0)
    {
      return (ssize_t)result;
    }
  else if (result == 0)
    {
      RAISE (Socket_Closed);
      return -1; /* Unreachable - RAISE performs longjmp */
    }
  else
    {
      TLSHandshakeState state = tls_handle_ssl_error (socket, ssl, result);
      if (state == TLS_HANDSHAKE_ERROR)
        {
          tls_format_openssl_error ("TLS recv failed");
          RAISE_TLS_ERROR (SocketTLS_Failed);
        }
      errno = EAGAIN;
      return 0;
    }
}

#undef T

#endif /* SOCKET_HAS_TLS */
