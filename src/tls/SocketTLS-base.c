/**
 * SocketTLS-base.c - TLS Socket Wrapper
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements TLS/SSL integration for sockets using OpenSSL. Provides
 * transparent encryption/decryption via wrapper functions, non-blocking
 * handshake management, SNI support, and connection info queries.
 *
 * Thread safety: Functions are not thread-safe; each socket is
 * single-threaded. Uses thread-local error buffers for exception details.
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include "tls/SocketTLSContext.h"
#include <assert.h>
#include <string.h>

#define T SocketTLS_T

/* Exception definitions */
const Except_T SocketTLS_Failed = { &SocketTLS_Failed, "TLS operation failed" };
const Except_T SocketTLS_HandshakeFailed
    = { &SocketTLS_HandshakeFailed, "TLS handshake failed" };
const Except_T SocketTLS_VerifyFailed
    = { &SocketTLS_VerifyFailed, "TLS certificate verification failed" };
const Except_T SocketTLS_ProtocolError
    = { &SocketTLS_ProtocolError, "TLS protocol error" };
const Except_T SocketTLS_ShutdownFailed
    = { &SocketTLS_ShutdownFailed, "TLS shutdown failed" };

/* Thread-local error buffers */
#ifdef _WIN32
__declspec (thread) Except_T SocketTLS_DetailedException;
__declspec (thread) char tls_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
#else
__thread Except_T SocketTLS_DetailedException;
__thread char tls_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
#endif

/**
 * allocate_tls_buffers - Allocate TLS read/write buffers
 * @socket: Socket instance
 */
static void
allocate_tls_buffers (Socket_T socket)
{
  assert (socket);
  assert (SocketBase_arena (socket->base));

  if (!socket->tls_read_buf)
    {
      socket->tls_read_buf
          = Arena_alloc (SocketBase_arena (socket->base),
                         SOCKET_TLS_BUFFER_SIZE, __FILE__, __LINE__);
      socket->tls_read_buf_len = 0;
    }

  if (!socket->tls_write_buf)
    {
      socket->tls_write_buf
          = Arena_alloc (SocketBase_arena (socket->base),
                         SOCKET_TLS_BUFFER_SIZE, __FILE__, __LINE__);
      socket->tls_write_buf_len = 0;
    }
}

/**
 * free_tls_resources - Cleanup TLS resources
 * @socket: Socket instance
 */
static void
free_tls_resources (Socket_T socket)
{
  assert (socket);

  if (socket->tls_ssl)
    {
      SSL_set_app_data ((SSL *)socket->tls_ssl, NULL);
      SSL_free ((SSL *)socket->tls_ssl);
      socket->tls_ssl = NULL;
      socket->tls_ctx = NULL;
    }

  socket->tls_enabled = 0;
  socket->tls_handshake_done = 0;
  socket->tls_shutdown_done = 0;
  socket->tls_sni_hostname = NULL;
  socket->tls_read_buf = NULL;
  socket->tls_write_buf = NULL;
  socket->tls_read_buf_len = 0;
  socket->tls_write_buf_len = 0;
}

void
SocketTLS_enable (Socket_T socket, SocketTLSContext_T ctx)
{
  SSL *ssl;
  int fd;

  assert (socket);
  assert (ctx);
  assert (SocketTLSContext_get_ssl_ctx (ctx));

  if (socket->tls_enabled)
    {
      TLS_ERROR_MSG ("TLS already enabled on socket");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  fd = SocketBase_fd (socket->base);
  if (fd < 0)
    {
      TLS_ERROR_MSG ("Socket not connected (invalid file descriptor)");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  ssl = SSL_new ((SSL_CTX *)SocketTLSContext_get_ssl_ctx (ctx));
  if (!ssl)
    {
      TLS_ERROR_MSG ("Failed to create SSL object");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  if (SocketTLSContext_is_server (ctx))
    {
      SSL_set_accept_state (ssl);
    }
  else
    {
      SSL_set_connect_state (ssl);
    }

  if (SSL_set_fd (ssl, fd) != 1)
    {
      SSL_free (ssl);
      TLS_ERROR_MSG ("Failed to associate SSL with socket file descriptor");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  socket->tls_ssl = (void *)ssl;
  socket->tls_ctx = (void *)ctx;

  SSL_set_app_data (ssl, socket);

  allocate_tls_buffers (socket);

  socket->tls_enabled = 1;
  socket->tls_handshake_done = 0;
  socket->tls_shutdown_done = 0;
}

void
SocketTLS_set_hostname (Socket_T socket, const char *hostname)
{
  SSL *ssl;
  size_t hostname_len;

  assert (socket);
  assert (hostname);

  if (!socket->tls_enabled)
    {
      TLS_ERROR_MSG ("TLS not enabled on socket");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  hostname_len = strlen (hostname);
  if (hostname_len == 0 || hostname_len > SOCKET_TLS_MAX_SNI_LEN)
    {
      TLS_ERROR_FMT ("Invalid hostname length: %zu", hostname_len);
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  if (!tls_validate_hostname (hostname))
    {
      TLS_ERROR_MSG ("Invalid hostname format");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  socket->tls_sni_hostname = Arena_alloc (SocketBase_arena (socket->base),
                                          hostname_len + 1, __FILE__, __LINE__);
  if (!socket->tls_sni_hostname)
    {
      TLS_ERROR_MSG ("Failed to allocate hostname buffer");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  memcpy ((char *)socket->tls_sni_hostname, hostname, hostname_len + 1);

  ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    {
      TLS_ERROR_MSG ("SSL object not available");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  if (SSL_set_tlsext_host_name (ssl, hostname) != 1)
    {
      TLS_ERROR_MSG ("Failed to set SNI hostname");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  if (SSL_set1_host (ssl, hostname) != 1)
    {
      TLS_ERROR_MSG ("Failed to enable hostname verification");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }
}

TLSHandshakeState
SocketTLS_handshake (Socket_T socket)
{
  SSL *ssl;
  int result;

  assert (socket);

  if (!socket->tls_enabled)
    {
      TLS_ERROR_MSG ("TLS not enabled on socket");
      RAISE_TLS_ERROR (SocketTLS_HandshakeFailed);
    }

  if (socket->tls_handshake_done)
    {
      return TLS_HANDSHAKE_COMPLETE;
    }

  ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    {
      TLS_ERROR_MSG ("SSL object not available");
      RAISE_TLS_ERROR (SocketTLS_HandshakeFailed);
    }

  result = SSL_do_handshake (ssl);

  if (result == 1)
    {
      socket->tls_handshake_done = 1;
      socket->tls_last_handshake_state = TLS_HANDSHAKE_COMPLETE;
      return TLS_HANDSHAKE_COMPLETE;
    }
  else
    {
      TLSHandshakeState state = tls_handle_ssl_error (socket, ssl, result);

      if (state == TLS_HANDSHAKE_ERROR)
        {
          tls_format_openssl_error ("Handshake failed");
          RAISE_TLS_ERROR (SocketTLS_HandshakeFailed);
        }

      socket->tls_last_handshake_state = state;
      return state;
    }
}

void
SocketTLS_shutdown (Socket_T socket)
{
  SSL *ssl;
  int result;

  assert (socket);

  if (!socket->tls_enabled)
    {
      TLS_ERROR_MSG ("TLS not enabled on socket");
      RAISE_TLS_ERROR (SocketTLS_ShutdownFailed);
    }

  if (socket->tls_shutdown_done)
    {
      return;
    }

  ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    {
      TLS_ERROR_MSG ("SSL object not available");
      RAISE_TLS_ERROR (SocketTLS_ShutdownFailed);
    }

  result = SSL_shutdown (ssl);

  if (result == 1)
    {
      socket->tls_shutdown_done = 1;
      free_tls_resources (socket);
    }
  else if (result == 0)
    {
      return;
    }
  else
    {
      TLSHandshakeState state = tls_handle_ssl_error (socket, ssl, result);
      if (state == TLS_HANDSHAKE_ERROR)
        {
          RAISE_TLS_ERROR (SocketTLS_ShutdownFailed);
        }
    }
}

#undef T

#endif /* SOCKET_HAS_TLS */
