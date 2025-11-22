/**
 * SocketTLS.c - TLS Socket Wrapper Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements TLS/SSL integration for sockets using OpenSSL. Provides
 * transparent encryption/decryption via wrapper functions
 * (SocketTLS_send/recv), non-blocking handshake management, SNI support, and
 * connection info queries. Uses opaque extension to Socket_T structure for TLS
 * state (ssl, buffers, flags).
 *
 * Key features:
 * - Non-blocking handshake compatible with SocketPoll
 * - Automatic buffer management via socket Arena
 * - Detailed exception handling with OpenSSL error mapping
 * - Session info (cipher, version, verify result, reuse)
 * - Graceful shutdown with resource cleanup
 *
 * Thread safety: Functions are not thread-safe; each socket is
 * single-threaded. Uses thread-local error buffers for exception details.
 *
 * Error handling: Raises SocketTLS_* exceptions with tls_error_buf details.
 * Integrates with core Except system.
 */

#ifdef SOCKET_HAS_TLS

#include "core/Arena.h"
#include "socket/Socket-private.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"
#include <assert.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string.h>

#define T SocketTLS_T

Except_T SocketTLS_Failed = { "TLS operation failed" };
Except_T SocketTLS_HandshakeFailed = { "TLS handshake failed" };
Except_T SocketTLS_VerifyFailed = { "TLS certificate verification failed" };
Except_T SocketTLS_ProtocolError = { "TLS protocol error" };
Except_T SocketTLS_ShutdownFailed = { "TLS shutdown failed" };

/* Thread-local exception for detailed TLS error messages
 * Prevents race conditions when multiple threads raise same exception. */
#ifdef _WIN32
static __declspec (thread) Except_T SocketTLS_DetailedException;
#else
static __thread Except_T SocketTLS_DetailedException;
#endif

/* TLS error buffer for detailed error messages */
#ifdef _WIN32
__declspec (thread) char tls_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
#else
__thread char tls_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
#endif

/* Macro to raise TLS exception with detailed error message */
#define RAISE_TLS_ERROR(exception)                                            \
  do                                                                          \
    {                                                                         \
      SocketTLS_DetailedException = (exception);                              \
      SocketTLS_DetailedException.reason = tls_error_buf;                     \
      RAISE (SocketTLS_DetailedException);                                    \
    }                                                                         \
  while (0)

/* Static helper functions */

/**
 * socket_get_ssl - Get SSL* from socket
 * @socket: Socket instance
 * Returns: SSL* pointer or NULL if not available
 */
static SSL *
socket_get_ssl (Socket_T socket)
{
  if (!socket || !socket->tls_enabled || !socket->tls_ssl)
    return NULL;
  return (SSL *)socket->tls_ssl;
}

/**
 * socket_handle_ssl_error - Map OpenSSL errors to TLSHandshakeState
 * @socket: Socket instance
 * @ssl: SSL object
 * @ssl_result: Result from SSL operation
 * Returns: TLSHandshakeState based on error
 * Sets errno appropriately for WANT_READ/WRITE
 */
static TLSHandshakeState
socket_handle_ssl_error (Socket_T socket, SSL *ssl, int ssl_result)
{
  int ssl_error = SSL_get_error (ssl, ssl_result);

  switch (ssl_error)
    {
    case SSL_ERROR_NONE:
      socket->tls_handshake_done = 1;
      return TLS_HANDSHAKE_COMPLETE;

    case SSL_ERROR_WANT_READ:
      socket->tls_handshake_done = 0;
      errno = EAGAIN;
      return TLS_HANDSHAKE_WANT_READ;

    case SSL_ERROR_WANT_WRITE:
      socket->tls_handshake_done = 0;
      errno = EAGAIN;
      return TLS_HANDSHAKE_WANT_WRITE;

    default:
      socket->tls_handshake_done = 0;
      return TLS_HANDSHAKE_ERROR;
    }
}

/**
 * socket_allocate_tls_buffers - Allocate TLS read/write buffers
 * @socket: Socket instance
 * Allocates buffers from socket arena for TLS operations
 */
static void
socket_allocate_tls_buffers (Socket_T socket)
{
  assert (socket);
  assert (socket->arena);

  /* Allocate read buffer */
  if (!socket->tls_read_buf)
    {
      socket->tls_read_buf = Arena_alloc (
          socket->arena, SOCKET_TLS_BUFFER_SIZE, __FILE__, __LINE__);
      socket->tls_read_buf_len = 0;
    }

  /* Allocate write buffer */
  if (!socket->tls_write_buf)
    {
      socket->tls_write_buf = Arena_alloc (
          socket->arena, SOCKET_TLS_BUFFER_SIZE, __FILE__, __LINE__);
      socket->tls_write_buf_len = 0;
    }
}

/**
 * socket_free_tls_resources - Cleanup TLS resources
 * @socket: Socket instance
 * Frees SSL object and clears TLS state
 */
static void
socket_free_tls_resources (Socket_T socket)
{
  assert (socket);

  /* Free SSL object */
  if (socket->tls_ssl)
    {
      SSL_free ((SSL *)socket->tls_ssl);
      socket->tls_ssl = NULL;
    }

  /* Clear TLS flags and state */
  socket->tls_enabled = 0;
  socket->tls_handshake_done = 0;
  socket->tls_shutdown_done = 0;

  /* Clear SNI hostname (allocated in arena, will be freed with arena) */
  socket->tls_sni_hostname = NULL;

  /* Clear buffer pointers (allocated in arena, will be freed with arena) */
  socket->tls_read_buf = NULL;
  socket->tls_write_buf = NULL;
  socket->tls_read_buf_len = 0;
  socket->tls_write_buf_len = 0;
}

/* Public TLS socket wrapper functions */

/**
 * SocketTLS_enable - Enable TLS on a socket
 * @socket: Socket instance to enable TLS on
 * @ctx: TLS context to use
 *
 * Enables TLS on the specified socket using the provided TLS context.
 * Creates an SSL object, associates it with the socket's file descriptor,
 * and initializes TLS state. The socket must be connected before calling this.
 *
 * Raises: SocketTLS_Failed on error
 * Thread-safe: No (modifies socket state)
 */
void
SocketTLS_enable (Socket_T socket, SocketTLSContext_T ctx)
{
  SSL *ssl;
  int fd;

  assert (socket);
  assert (ctx);
  assert (SocketTLSContext_get_ssl_ctx (ctx));

  /* Check if TLS is already enabled */
  if (socket->tls_enabled)
    {
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "TLS already enabled on socket");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  /* Get socket file descriptor */
  fd = socket->fd;
  if (fd < 0)
    {
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "Socket not connected (invalid file descriptor)");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  /* Create SSL object from context */
  ssl = SSL_new ((SSL_CTX *)SocketTLSContext_get_ssl_ctx (ctx));
  if (!ssl)
    {
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "Failed to create SSL object");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  /* Set connection state (client/server) */
  if (SocketTLSContext_is_server (ctx))
    {
      SSL_set_accept_state (ssl);
    }
  else
    {
      SSL_set_connect_state (ssl);
    }

  /* Associate SSL object with socket file descriptor */
  if (SSL_set_fd (ssl, fd) != 1)
    {
      SSL_free (ssl);
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "Failed to associate SSL with socket file descriptor");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  /* Store SSL object in socket */
  socket->tls_ssl = (void *)ssl;

  /* Allocate TLS buffers */
  socket_allocate_tls_buffers (socket);

  /* Set TLS flags */
  socket->tls_enabled = 1;
  socket->tls_handshake_done = 0;
  socket->tls_shutdown_done = 0;
}

/**
 * SocketTLS_set_hostname - Set SNI hostname for TLS connection
 * @socket: Socket instance
 * @hostname: Hostname for SNI (Server Name Indication)
 *
 * Sets the hostname for Server Name Indication (SNI) in TLS connections.
 * The hostname is stored in the socket's arena and set on the SSL object.
 * This should be called before handshake if SNI is needed.
 *
 * Raises: SocketTLS_Failed on error
 * Thread-safe: No (modifies socket state)
 */
void
SocketTLS_set_hostname (Socket_T socket, const char *hostname)
{
  SSL *ssl;
  size_t hostname_len;

  assert (socket);
  assert (hostname);

  /* Check if TLS is enabled */
  if (!socket->tls_enabled)
    {
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "TLS not enabled on socket");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  /* Validate hostname length */
  hostname_len = strlen (hostname);
  if (hostname_len == 0
      || hostname_len
             > SOCKET_TLS_MAX_SNI_LEN) /* SNI hostname limit per RFC 6066 */
    {
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "Invalid hostname length: %zu", hostname_len);
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  /* Allocate hostname string in socket arena */
  socket->tls_sni_hostname
      = Arena_alloc (socket->arena, hostname_len + 1, __FILE__, __LINE__);
  if (!socket->tls_sni_hostname)
    {
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "Failed to allocate hostname buffer");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  /* Copy hostname safely */
  memcpy ((char *)socket->tls_sni_hostname, hostname, hostname_len + 1);

  /* Get SSL object */
  ssl = socket_get_ssl (socket);
  if (!ssl)
    {
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "SSL object not available");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  /* Set SNI hostname on SSL object */
  if (SSL_set_tlsext_host_name (ssl, hostname) != 1)
    {
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "Failed to set SNI hostname");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }

  /* Enable automatic hostname checks */
  if (SSL_set1_host (ssl, hostname) != 1)
    {
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "Failed to enable hostname verification");
      RAISE_TLS_ERROR (SocketTLS_Failed);
    }
}

/**
 * SocketTLS_handshake - Perform TLS handshake
 * @socket: Socket instance
 *
 * Performs the TLS handshake on the socket. This function should be called
 * after enabling TLS and setting any required parameters (like hostname).
 * May need to be called multiple times if SSL_ERROR_WANT_READ/WRITE is
 * returned.
 *
 * Returns: TLSHandshakeState indicating handshake progress or completion
 * Raises: SocketTLS_HandshakeFailed on fatal errors
 * Thread-safe: No (modifies socket state)
 */
TLSHandshakeState
SocketTLS_handshake (Socket_T socket)
{
  SSL *ssl;
  int result;

  assert (socket);

  /* Check if TLS is enabled */
  if (!socket->tls_enabled)
    {
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "TLS not enabled on socket");
      RAISE_TLS_ERROR (SocketTLS_HandshakeFailed);
    }

  /* Check if handshake is already complete */
  if (socket->tls_handshake_done)
    {
      return TLS_HANDSHAKE_COMPLETE;
    }

  /* Get SSL object */
  ssl = socket_get_ssl (socket);
  if (!ssl)
    {
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "SSL object not available");
      RAISE_TLS_ERROR (SocketTLS_HandshakeFailed);
    }

  /* Perform handshake */
  result = SSL_do_handshake (ssl);

  /* Handle result */
  if (result == 1)
    {
      /* Handshake completed successfully */
      socket->tls_handshake_done = 1;
      socket->tls_last_handshake_state = TLS_HANDSHAKE_COMPLETE;
      return TLS_HANDSHAKE_COMPLETE;
    }
  else
    {
      /* Check for specific errors */
      TLSHandshakeState state = socket_handle_ssl_error (socket, ssl, result);

      if (state == TLS_HANDSHAKE_ERROR)
        {
          /* socket_handle_ssl_error doesn't set the detailed buffer for us,
           * so we should fetch the error from OpenSSL queue here if needed,
           * or ensure tls_error_buf is set. */
          unsigned long err = ERR_get_error ();
          if (err)
            {
              char msg[SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE];
              ERR_error_string_n (err, msg, sizeof (msg));
              snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                        "Handshake failed: %s", msg);
            }
          else
            {
              snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                        "Handshake failed");
            }
          RAISE_TLS_ERROR (SocketTLS_HandshakeFailed);
        }

      socket->tls_last_handshake_state = state; /* Store state for polling */
      return state;
    }
}

/**
 * SocketTLS_shutdown - Perform graceful TLS shutdown
 * @socket: Socket instance
 *
 * Performs a graceful TLS shutdown on the socket. This should be called
 * before closing the underlying socket to ensure proper TLS termination.
 * May need to be called multiple times to complete bidirectional shutdown.
 *
 * Raises: SocketTLS_ShutdownFailed on error
 * Thread-safe: No (modifies socket state)
 */
void
SocketTLS_shutdown (Socket_T socket)
{
  SSL *ssl;
  int result;

  assert (socket);

  /* Check if TLS is enabled */
  if (!socket->tls_enabled)
    {
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "TLS not enabled on socket");
      RAISE_TLS_ERROR (SocketTLS_ShutdownFailed);
    }

  /* Check if already shutdown */
  if (socket->tls_shutdown_done)
    {
      return; /* Already done */
    }

  /* Get SSL object */
  ssl = socket_get_ssl (socket);
  if (!ssl)
    {
      snprintf (tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE,
                "SSL object not available");
      RAISE_TLS_ERROR (SocketTLS_ShutdownFailed);
    }

  /* Perform shutdown */
  result = SSL_shutdown (ssl);

  if (result == 1)
    {
      /* Shutdown completed successfully */
      socket->tls_shutdown_done = 1;
      socket_free_tls_resources (socket);
    }
  else if (result == 0)
    {
      /* Shutdown is not yet complete - need another call */
      /* This is normal for bidirectional shutdown */
      return;
    }
  else
    {
      /* Check for specific errors */
      TLSHandshakeState state = socket_handle_ssl_error (socket, ssl, result);
      if (state == TLS_HANDSHAKE_ERROR)
        {
          RAISE_TLS_ERROR (SocketTLS_ShutdownFailed);
        }
      /* WANT_READ/WRITE are expected during shutdown */
    }
}

#undef T

#endif /* SOCKET_HAS_TLS */
