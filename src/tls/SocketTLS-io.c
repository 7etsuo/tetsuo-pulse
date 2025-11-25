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
  SSL *ssl;
  int result;

  assert (socket);
  assert (buf);
  assert (len > 0);

  if (!socket->tls_enabled)
    {
      TLS_ERROR_MSG ("TLS not enabled on socket");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  if (!socket->tls_handshake_done)
    {
      TLS_ERROR_MSG ("TLS handshake not complete");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    {
      TLS_ERROR_MSG ("SSL object not available");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  result = SSL_write (ssl, buf, (int)len);

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
  SSL *ssl;
  int result;

  assert (socket);
  assert (buf);
  assert (len > 0);

  if (!socket->tls_enabled)
    {
      TLS_ERROR_MSG ("TLS not enabled on socket");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  if (!socket->tls_handshake_done)
    {
      TLS_ERROR_MSG ("TLS handshake not complete");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    {
      TLS_ERROR_MSG ("SSL object not available");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  result = SSL_read (ssl, buf, (int)len);

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
