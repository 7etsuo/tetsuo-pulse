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
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"
#include "socket/SocketIO.h"
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
/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketIO);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketIO, e)

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
/* TLS functions in SocketIO-tls.c */
extern int socket_handle_ssl_error (T socket, SSL *ssl, int ssl_result);
extern ssize_t socket_sendv_tls (T socket, const struct iovec *iov, int iovcnt);
extern ssize_t socket_recvv_tls (T socket, struct iovec *iov, int iovcnt);
extern SSL *socket_get_ssl (T socket);
extern ssize_t socket_send_tls (T socket, const void *buf, size_t len);
extern ssize_t socket_recv_tls (T socket, void *buf, size_t len);
#endif

/* ==================== Common I/O Error Helpers ==================== */

/**
 * is_wouldblock_error - Check if error indicates operation would block
 * Returns: 1 if EAGAIN/EWOULDBLOCK, 0 otherwise
 */
static inline int
is_wouldblock_error (void)
{
  return errno == EAGAIN || errno == EWOULDBLOCK;
}

/**
 * is_connection_closed_send - Check if send error indicates closed connection
 * Returns: 1 if EPIPE/ECONNRESET, 0 otherwise
 */
static inline int
is_connection_closed_send (void)
{
  return errno == EPIPE || errno == ECONNRESET;
}

/**
 * socket_send_raw - Raw socket send operation
 * @socket: Socket instance
 * @buf: Data to send
 * @len: Length of data
 * @flags: Send flags
 *
 * Returns: Bytes sent or 0 if would block
 * Raises: Socket_Failed, Socket_Closed
 */
static ssize_t
socket_send_raw (T socket, const void *buf, size_t len, int flags)
{
  ssize_t result = send (Socket_fd (socket), buf, len, flags);

  if (result < 0)
    {
      if (is_wouldblock_error ())
        return 0;
      if (is_connection_closed_send ())
        RAISE (Socket_Closed);
      SOCKET_ERROR_FMT ("Send failed (len=%zu)", len);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return result;
}

/**
 * socket_recv_raw - Raw socket receive operation
 * @socket: Socket instance
 * @buf: Buffer for received data
 * @len: Buffer size
 * @flags: Receive flags
 *
 * Returns: Bytes received or 0 if would block
 * Raises: Socket_Failed, Socket_Closed
 */
static ssize_t
socket_recv_raw (T socket, void *buf, size_t len, int flags)
{
  ssize_t result = recv (Socket_fd (socket), buf, len, flags);

  if (result < 0)
    {
      if (is_wouldblock_error ())
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
    return socket_send_tls (socket, buf, len);
#endif

  return socket_send_raw (socket, buf, len, flags);
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
    return socket_recv_tls (socket, buf, len);
#endif

  return socket_recv_raw (socket, buf, len, flags);
}



/**
 * socket_sendv_raw - Raw scatter/gather send implementation
 * @socket: Socket instance
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 * @flags: Send flags
 * Returns: Total bytes sent or 0 if would block
 * Raises: Socket_Failed
 */
static ssize_t
socket_sendv_raw (T socket, const struct iovec *iov, int iovcnt, int flags)
{
  (void)flags; /* Suppress unused parameter warning */
  ssize_t result = writev (Socket_fd (socket), iov, iovcnt);
  if (result < 0)
    {
      if (is_wouldblock_error ())
        return 0;
      if (is_connection_closed_send ())
        RAISE (Socket_Closed);
      SOCKET_ERROR_FMT ("Scatter/gather send failed (iovcnt=%d)", iovcnt);
      RAISE_MODULE_ERROR (Socket_Failed);
    }

  return result;
}


/**
 * socket_recvv_raw - Raw scatter/gather receive implementation
 * @socket: Socket instance
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 * @flags: Receive flags
 * Returns: Total bytes received or 0 if would block
 * Raises: Socket_Failed or Socket_Closed
 */
static ssize_t
socket_recvv_raw (T socket, struct iovec *iov, int iovcnt, int flags)
{
  (void)flags; /* Suppress unused parameter warning */
  ssize_t result = readv (Socket_fd (socket), iov, iovcnt);
  if (result < 0)
    {
      if (is_wouldblock_error ())
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
  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

#ifdef SOCKET_HAS_TLS
  if (socket->tls_enabled && socket->tls_ssl)
    return socket_sendv_tls (socket, iov, iovcnt);
#endif

  /* Non-TLS path: use standard writev() */
  return socket_sendv_raw (socket, iov, iovcnt, flags);
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
  assert (socket);
  assert (iov);
  assert (iovcnt > 0);
  assert (iovcnt <= IOV_MAX);

#ifdef SOCKET_HAS_TLS
  if (socket->tls_enabled && socket->tls_ssl)
    return socket_recvv_tls (socket, iov, iovcnt);
#endif

  /* Non-TLS path: use standard readv() */
  return socket_recvv_raw (socket, iov, iovcnt, flags);
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
 * Returns: 1 if want read, 0 otherwise
 */
int
socket_tls_want_read (T socket)
{
  assert (socket);
#ifdef SOCKET_HAS_TLS
  SSL *ssl = socket_get_ssl (socket);
  if (!ssl)
    return 0;
  if (!socket->tls_handshake_done)
    return socket->tls_last_handshake_state == TLS_HANDSHAKE_WANT_READ;
  return SSL_pending (ssl) > 0;
#else
  return 0;
#endif
}

/**
 * socket_tls_want_write - Check if TLS wants write
 * @socket: Socket instance
 * Returns: 1 if want write, 0 otherwise
 */
int
socket_tls_want_write (T socket)
{
  assert (socket);
#ifdef SOCKET_HAS_TLS
  if (!socket_get_ssl (socket))
    return 0;
  if (!socket->tls_handshake_done)
    return socket->tls_last_handshake_state == TLS_HANDSHAKE_WANT_WRITE;
  return 0;
#else
  return 0;
#endif
}

#undef T
