/**
 * SocketTLS.c - TLS Socket Integration
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements TLS/SSL integration for sockets using OpenSSL. Provides:
 * - Transparent encryption/decryption via wrapper functions
 * - Non-blocking handshake management
 * - SNI support and hostname verification
 * - Connection info queries (cipher, version, ALPN, etc.)
 * - TLS I/O operations (send/recv)
 *
 * Thread safety: Functions are not thread-safe; each socket is
 * single-threaded. Uses thread-local error buffers for exception details.
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS-private.h"
#include "tls/SocketTLSContext.h"
#include <assert.h>
#include <errno.h>
#include <openssl/x509_vfy.h>
#include <string.h>

#define T SocketTLS_T

/* ============================================================================
 * Exception Definitions
 * ============================================================================
 */

const Except_T SocketTLS_Failed = { &SocketTLS_Failed, "TLS operation failed" };
const Except_T SocketTLS_HandshakeFailed
    = { &SocketTLS_HandshakeFailed, "TLS handshake failed" };
const Except_T SocketTLS_VerifyFailed
    = { &SocketTLS_VerifyFailed, "TLS certificate verification failed" };
const Except_T SocketTLS_ProtocolError
    = { &SocketTLS_ProtocolError, "TLS protocol error" };
const Except_T SocketTLS_ShutdownFailed
    = { &SocketTLS_ShutdownFailed, "TLS shutdown failed" };

/* ============================================================================
 * Thread-Local Error Buffers
 * ============================================================================
 */

#ifdef _WIN32
__declspec (thread) Except_T SocketTLS_DetailedException;
__declspec (thread) char tls_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
#else
__thread Except_T SocketTLS_DetailedException;
__thread char tls_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
#endif

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

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

/* ============================================================================
 * TLS Enable and Configuration
 * ============================================================================
 */

/**
 * validate_tls_enable_preconditions - Validate socket is ready for TLS
 * @socket: Socket to validate
 *
 * Raises: SocketTLS_Failed if TLS already enabled or fd invalid
 */
static void
validate_tls_enable_preconditions (Socket_T socket)
{
  if (socket->tls_enabled)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "TLS already enabled on socket");

  int fd = SocketBase_fd (socket->base);
  if (fd < 0)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Socket not connected (invalid fd)");
}

/**
 * create_ssl_object - Create and configure SSL object from context
 * @ctx: TLS context
 *
 * Returns: Configured SSL object
 * Raises: SocketTLS_Failed on creation failure
 */
static SSL *
create_ssl_object (SocketTLSContext_T ctx)
{
  SSL *ssl = SSL_new ((SSL_CTX *)SocketTLSContext_get_ssl_ctx (ctx));
  if (!ssl)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Failed to create SSL object");

  if (SocketTLSContext_is_server (ctx))
    SSL_set_accept_state (ssl);
  else
    SSL_set_connect_state (ssl);

  return ssl;
}

/**
 * associate_ssl_with_fd - Associate SSL object with socket file descriptor
 * @ssl: SSL object
 * @fd: File descriptor
 *
 * Raises: SocketTLS_Failed on failure (frees SSL on error)
 */
static void
associate_ssl_with_fd (SSL *ssl, int fd)
{
  if (SSL_set_fd (ssl, fd) != 1)
    {
      SSL_free (ssl);
      RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Failed to associate SSL with fd");
    }
}

/**
 * finalize_tls_state - Set final TLS state on socket
 * @socket: Socket to configure
 * @ssl: SSL object to associate
 * @ctx: TLS context
 */
static void
finalize_tls_state (Socket_T socket, SSL *ssl, SocketTLSContext_T ctx)
{
  socket->tls_ssl = (void *)ssl;
  socket->tls_ctx = (void *)ctx;
  SSL_set_app_data (ssl, socket);
  allocate_tls_buffers (socket);

  socket->tls_enabled = 1;
  socket->tls_handshake_done = 0;
  socket->tls_shutdown_done = 0;
}

void
SocketTLS_enable (Socket_T socket, SocketTLSContext_T ctx)
{
  assert (socket);
  assert (ctx);
  assert (SocketTLSContext_get_ssl_ctx (ctx));

  validate_tls_enable_preconditions (socket);

  SSL *ssl = create_ssl_object (ctx);
  associate_ssl_with_fd (ssl, SocketBase_fd (socket->base));
  finalize_tls_state (socket, ssl, ctx);
}

/**
 * validate_hostname_nonempty - Validate hostname is non-empty
 * @hostname: Hostname to validate
 * @len: Length of hostname
 *
 * Raises: SocketTLS_Failed if empty
 *
 * Note: tls_validate_hostname() performs full RFC 6066 validation including
 * length limits. This check provides early exit for empty strings.
 */
static void
validate_hostname_nonempty (const char *hostname, size_t len)
{
  TLS_UNUSED (hostname);
  if (len == 0)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Hostname cannot be empty");
}

/**
 * copy_hostname_to_socket - Copy hostname to socket arena
 * @socket: Socket instance
 * @hostname: Hostname to copy
 * @len: Length of hostname
 */
static void
copy_hostname_to_socket (Socket_T socket, const char *hostname, size_t len)
{
  socket->tls_sni_hostname = Arena_alloc (SocketBase_arena (socket->base),
                                          len + 1, __FILE__, __LINE__);
  if (!socket->tls_sni_hostname)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Failed to allocate hostname buffer");

  memcpy ((char *)socket->tls_sni_hostname, hostname, len + 1);
}

/**
 * apply_sni_to_ssl - Apply SNI hostname to SSL connection
 * @ssl: SSL object
 * @hostname: Hostname for SNI
 *
 * Raises: SocketTLS_Failed on OpenSSL error
 */
static void
apply_sni_to_ssl (SSL *ssl, const char *hostname)
{
  if (SSL_set_tlsext_host_name (ssl, hostname) != 1)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Failed to set SNI hostname");

  if (SSL_set1_host (ssl, hostname) != 1)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Failed to enable hostname verification");
}

void
SocketTLS_set_hostname (Socket_T socket, const char *hostname)
{
  assert (socket);
  assert (hostname);

  REQUIRE_TLS_ENABLED (socket, SocketTLS_Failed);

  size_t hostname_len = strlen (hostname);
  validate_hostname_nonempty (hostname, hostname_len);

  if (!tls_validate_hostname (hostname))
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "Invalid hostname format or length");

  copy_hostname_to_socket (socket, hostname, hostname_len);

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    RAISE_TLS_ERROR_MSG (SocketTLS_Failed, "SSL object not available");

  apply_sni_to_ssl (ssl, hostname);
}

/* ============================================================================
 * TLS Handshake and Shutdown
 * ============================================================================
 */

TLSHandshakeState
SocketTLS_handshake (Socket_T socket)
{
  assert (socket);

  REQUIRE_TLS_ENABLED (socket, SocketTLS_HandshakeFailed);

  if (socket->tls_handshake_done)
    return TLS_HANDSHAKE_COMPLETE;

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    RAISE_TLS_ERROR_MSG (SocketTLS_HandshakeFailed, "SSL object not available");

  int result = SSL_do_handshake (ssl);
  if (result == 1)
    {
      socket->tls_handshake_done = 1;
      socket->tls_last_handshake_state = TLS_HANDSHAKE_COMPLETE;
      return TLS_HANDSHAKE_COMPLETE;
    }

  TLSHandshakeState state = tls_handle_ssl_error (socket, ssl, result);
  if (state == TLS_HANDSHAKE_ERROR)
    {
      tls_format_openssl_error ("Handshake failed");
      RAISE_TLS_ERROR (SocketTLS_HandshakeFailed);
    }

  socket->tls_last_handshake_state = state;
  return state;
}

void
SocketTLS_shutdown (Socket_T socket)
{
  assert (socket);

  REQUIRE_TLS_ENABLED (socket, SocketTLS_ShutdownFailed);

  if (socket->tls_shutdown_done)
    return;

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    RAISE_TLS_ERROR_MSG (SocketTLS_ShutdownFailed, "SSL object not available");

  int result = SSL_shutdown (ssl);
  if (result == 1)
    {
      socket->tls_shutdown_done = 1;
      free_tls_resources (socket);
    }
  else if (result < 0)
    {
      TLSHandshakeState state = tls_handle_ssl_error (socket, ssl, result);
      if (state == TLS_HANDSHAKE_ERROR)
        RAISE_TLS_ERROR (SocketTLS_ShutdownFailed);
    }
}

/* ============================================================================
 * TLS I/O Operations
 * ============================================================================
 */

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

/* ============================================================================
 * TLS Connection Information
 * ============================================================================
 */

const char *
SocketTLS_get_cipher (Socket_T socket)
{
  assert (socket);

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return NULL;

  const SSL_CIPHER *cipher = SSL_get_current_cipher (ssl);
  return cipher ? SSL_CIPHER_get_name (cipher) : NULL;
}

const char *
SocketTLS_get_version (Socket_T socket)
{
  assert (socket);

  SSL *ssl = tls_socket_get_ssl (socket);
  return ssl ? SSL_get_version (ssl) : NULL;
}

long
SocketTLS_get_verify_result (Socket_T socket)
{
  SSL *ssl;

  if (!socket || !socket->tls_enabled || !socket->tls_ssl
      || !socket->tls_handshake_done)
    {
      return X509_V_ERR_INVALID_CALL;
    }

  ssl = (SSL *)socket->tls_ssl;
  return SSL_get_verify_result (ssl);
}

const char *
SocketTLS_get_verify_error_string (Socket_T socket, char *buf, size_t size)
{
  if (!socket || !buf || size == 0)
    return NULL;

  long code = SocketTLS_get_verify_result (socket);
  if (code == X509_V_OK)
    return NULL;

  const char *code_str = X509_verify_cert_error_string (code);
  if (code_str)
    {
      strncpy (buf, code_str, size - 1);
      buf[size - 1] = '\0';
      return buf;
    }

  unsigned long err = ERR_get_error ();
  if (err)
    {
      ERR_error_string_n (err, buf, size);
      return buf;
    }

  strncpy (buf, "TLS verification failed (unknown error)", size - 1);
  buf[size - 1] = '\0';
  return buf;
}

int
SocketTLS_is_session_reused (Socket_T socket)
{
  assert (socket);

  SSL *ssl = tls_socket_get_ssl (socket);
  return ssl ? (SSL_session_reused (ssl) ? 1 : 0) : -1;
}

const char *
SocketTLS_get_alpn_selected (Socket_T socket)
{
  assert (socket);

  SSL *ssl = tls_socket_get_ssl (socket);
  if (!ssl)
    return NULL;

  const unsigned char *alpn_data;
  unsigned int alpn_len;
  SSL_get0_alpn_selected (ssl, &alpn_data, &alpn_len);

  if (!alpn_data || alpn_len == 0 || alpn_len > SOCKET_TLS_MAX_ALPN_LEN)
    return NULL;

  char *proto_copy = Arena_alloc (SocketBase_arena (socket->base),
                                  alpn_len + 1, __FILE__, __LINE__);
  if (!proto_copy)
    return NULL;

  memcpy (proto_copy, alpn_data, alpn_len);
  proto_copy[alpn_len] = '\0';
  return proto_copy;
}

#undef T

#endif /* SOCKET_HAS_TLS */

