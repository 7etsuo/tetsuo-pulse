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
static int is_recoverable_tls_error (void);
SSL *socket_get_ssl (T socket);
int socket_handle_ssl_error (T socket, SSL *ssl, int ssl_result);

/**
 * socket_validate_tls_ready - Validate TLS is ready for I/O
 * @socket: Socket instance
 *
 * Returns: SSL pointer if ready, raises exception otherwise
 * Thread-safe: Yes (operates on single socket)
 * Note: Exported for use by SocketIO-tls-iov.c
 */
SSL *
socket_validate_tls_ready (T socket)
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
 * socket_is_recoverable_io_error - Check if errno indicates recoverable I/O
 *
 * Returns: 1 if EAGAIN/EWOULDBLOCK, 0 otherwise
 * Thread-safe: Yes (reads errno)
 * Note: Exported for use by SocketIO-tls-iov.c
 */
int
socket_is_recoverable_io_error (void)
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
  SSL *ssl = socket_validate_tls_ready (socket);
  int ssl_result = SSL_write (ssl, buf, (int)len);

  if (ssl_result <= 0)
    {
      socket_handle_ssl_error (socket, ssl, ssl_result);
      if (socket_is_recoverable_io_error ())
        return 0;
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
  SSL *ssl = socket_validate_tls_ready (socket);
  int ssl_result = SSL_read (ssl, buf, (int)len);

  if (ssl_result <= 0)
    {
      socket_handle_ssl_error (socket, ssl, ssl_result);
      if (socket_is_recoverable_io_error ())
        return 0;
      if (ssl_result == 0 || errno == ECONNRESET)
        RAISE (Socket_Closed);
      SOCKET_ERROR_FMT ("TLS receive failed (len=%zu)", len);
      RAISE_MODULE_ERROR (SocketTLS_Failed);
    }
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

/* ==================== SSL Error Mapping ==================== */

/**
 * SSLErrorMapping - Mapping from SSL error code to errno and state
 *
 * Provides data-driven error handling for SSL operations. Each entry
 * maps an SSL_ERROR_* code to the corresponding errno value and
 * indicates whether the error clears the handshake completion flag.
 */
typedef struct
{
  int ssl_error;       /**< SSL_ERROR_* constant */
  int mapped_errno;    /**< Corresponding errno value */
  int clears_handshake; /**< 1 if this error resets handshake_done */
} SSLErrorMapping;

/**
 * SSL error mapping table - data-driven error classification
 *
 * This table maps SSL error codes to errno values. Using a table instead
 * of a switch statement makes it easier to add new error codes and
 * ensures consistent handling across all TLS operations.
 */
static const SSLErrorMapping ssl_error_map[] = {
  { SSL_ERROR_NONE,              0,            0 },
  { SSL_ERROR_SSL,               EPROTO,       0 },
  { SSL_ERROR_WANT_READ,         EAGAIN,       1 },
  { SSL_ERROR_WANT_WRITE,        EAGAIN,       1 },
  { SSL_ERROR_WANT_X509_LOOKUP,  EAGAIN,       0 },
  { SSL_ERROR_ZERO_RETURN,       ECONNRESET,   0 },
  { SSL_ERROR_WANT_CONNECT,      EINPROGRESS,  1 },
  { SSL_ERROR_WANT_ACCEPT,       EAGAIN,       1 },
  { SSL_ERROR_WANT_ASYNC,        EAGAIN,       0 },
  { SSL_ERROR_WANT_ASYNC_JOB,    EAGAIN,       0 },
  { SSL_ERROR_WANT_CLIENT_HELLO_CB, EAGAIN,    0 },
  { SSL_ERROR_WANT_RETRY_VERIFY, EAGAIN,       0 },
};

#define SSL_ERROR_MAP_SIZE (sizeof (ssl_error_map) / sizeof (ssl_error_map[0]))

/**
 * ssl_lookup_error - Find mapping for SSL error code
 * @ssl_error: SSL_ERROR_* constant to look up
 *
 * Returns: Pointer to mapping entry, or NULL if not found
 */
static const SSLErrorMapping *
ssl_lookup_error (int ssl_error)
{
  for (size_t i = 0; i < SSL_ERROR_MAP_SIZE; i++)
    {
      if (ssl_error_map[i].ssl_error == ssl_error)
        return &ssl_error_map[i];
    }
  return NULL;
}

/**
 * ssl_handle_syscall_error - Handle SSL_ERROR_SYSCALL specially
 *
 * Returns: -1 (always an error)
 *
 * SSL_ERROR_SYSCALL requires special handling: if errno is 0,
 * the connection was closed (EOF). Otherwise, keep the existing errno.
 */
static int
ssl_handle_syscall_error (void)
{
  if (errno == 0)
    errno = ECONNRESET;
  return -1;
}

/**
 * socket_handle_ssl_error - Map SSL error codes to errno values
 * @socket: Socket instance
 * @ssl: SSL object
 * @ssl_result: Result from SSL operation
 *
 * Returns: 0 on SSL_ERROR_NONE, -1 on error (sets errno)
 * Thread-safe: Yes (operates on single socket)
 *
 * Uses data-driven mapping table to convert SSL error codes to
 * appropriate errno values. Updates socket handshake state when
 * SSL indicates the handshake needs to continue.
 */
int
socket_handle_ssl_error (T socket, SSL *ssl, int ssl_result)
{
  int ssl_error = SSL_get_error (ssl, ssl_result);
  const SSLErrorMapping *mapping;

  /* Handle syscall error specially - errno may already be set */
  if (ssl_error == SSL_ERROR_SYSCALL)
    return ssl_handle_syscall_error ();

  mapping = ssl_lookup_error (ssl_error);
  if (!mapping)
    {
      errno = EPROTO;
      return -1;
    }

  if (mapping->ssl_error == SSL_ERROR_NONE)
    return 0;

  if (mapping->clears_handshake)
    socket->tls_handshake_done = 0;

  errno = mapping->mapped_errno;
  return -1;
}

/* socket_sendv_tls and socket_recvv_tls are in SocketIO-tls-iov.c */

#endif /* SOCKET_HAS_TLS */

#undef T

