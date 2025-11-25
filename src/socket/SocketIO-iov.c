/**
 * SocketIO-iov.c - Scatter/gather I/O internal operations
 *
 * Implements internal scatter/gather I/O operations for socket communication,
 * handling both standard system calls (writev/readv) and TLS operations
 * (SSL_writev equivalent). Provides memory-efficient buffered I/O for
 * vector operations.
 *
 * Features:
 * - Scatter/gather send operations (sendv_internal)
 * - Scatter/gather receive operations (recvv_internal)
 * - TLS-aware vector I/O with temporary buffering
 * - Memory management using Arena allocation
 * - Platform-independent vector I/O abstraction
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "core/Arena.h"
#include "core/SocketConfig.h"
#include "core/SocketError.h"
#include "socket/Socket.h"
#include "socket/SocketIO.h"
#include "socket/Socket-private.h"
#include "socket/SocketCommon.h"

/* TLS includes - must be before T define */
#ifdef SOCKET_HAS_TLS
#include <openssl/err.h>
#include <openssl/ssl.h>

/* Forward declarations for TLS exceptions to avoid T conflict */
extern const Except_T SocketTLS_Failed;
extern const Except_T SocketTLS_HandshakeFailed;
#endif

#define T Socket_T

/* Thread-local exception for detailed error messages */
#ifdef _WIN32
static __declspec (thread) Except_T SocketIO_DetailedException;
#else
static __thread Except_T SocketIO_DetailedException;
#endif

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e)                                                 \
  do                                                                          \
    {                                                                         \
      SocketIO_DetailedException = (e);                                       \
      SocketIO_DetailedException.reason = socket_error_buf;                  \
      RAISE (SocketIO_DetailedException);                                    \
    }                                                                         \
  while (0)

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
 * @socket: SSL socket
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
#undef T
