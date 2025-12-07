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

/* System headers first (GNU C style) */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>

/* Project headers */
#include "core/Arena.h"
#include "core/SocketUtil.h"
#include "socket/Socket-private.h"
#include "socket/Socket.h"
#include "socket/SocketCommon-private.h"
#include "socket/SocketCommon.h"
#include "socket/SocketIO.h"

#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketIO"

/* Thread-local exception for detailed error messages */
/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION (SocketIO);

/* Convenience macros for unified error+raise pattern */
#define RAISE_FMT(e, fmt, ...)                                                 \
  SOCKET_RAISE_FMT (SocketIO, e, fmt, ##__VA_ARGS__)
#define RAISE_MSG(e, fmt, ...)                                                 \
  SOCKET_RAISE_MSG (SocketIO, e, fmt, ##__VA_ARGS__)

#if SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "core/SocketCrypto.h"
#endif

#define T Socket_T

/* Forward declaration */
extern int Socket_fd (const T socket);

#if SOCKET_HAS_TLS
/* TLS helper functions - defined later in this file */
/* Note: Some functions are extern (declared in header), some are static */
static ssize_t socket_send_tls (T socket, const void *buf, size_t len);
static ssize_t socket_recv_tls (T socket, void *buf, size_t len);
static ssize_t socket_sendv_tls (T socket, const struct iovec *iov, int iovcnt);
static ssize_t socket_recvv_tls (T socket, struct iovec *iov, int iovcnt);
#endif

/* Common I/O error helpers are now inline in SocketIO.h:
 * - socketio_is_wouldblock()
 * - socketio_is_connection_closed_send()
 * - socketio_is_connection_closed_recv()
 */

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
      if (socketio_is_wouldblock ())
        return 0;
      if (socketio_is_connection_closed_send ())
        RAISE (Socket_Closed);
      RAISE_FMT (Socket_Failed, "Send failed (len=%zu)", len);
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
      if (socketio_is_wouldblock ())
        return 0;
      if (socketio_is_connection_closed_recv ())
        RAISE (Socket_Closed);
      RAISE_FMT (Socket_Failed, "Receive failed (len=%zu)", len);
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

#if SOCKET_HAS_TLS
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

#if SOCKET_HAS_TLS
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
 * @flags: Send flags (MSG_NOSIGNAL automatically added)
 * Returns: Total bytes sent or 0 if would block
 * Raises: Socket_Failed
 *
 * Uses sendmsg() instead of writev() to support MSG_NOSIGNAL for
 * SIGPIPE suppression. The flags parameter is OR'd with MSG_NOSIGNAL.
 */
static ssize_t
socket_sendv_raw (T socket, const struct iovec *iov, int iovcnt, int flags)
{
  struct msghdr msg;
  ssize_t result;

  memset (&msg, 0, sizeof (msg));
  msg.msg_iov = (struct iovec *)iov; /* Cast away const for msghdr */
  msg.msg_iovlen = (size_t)iovcnt;

  result = sendmsg (Socket_fd (socket), &msg, flags | MSG_NOSIGNAL);
  if (result < 0)
    {
      if (socketio_is_wouldblock ())
        return 0;
      if (socketio_is_connection_closed_send ())
        RAISE (Socket_Closed);
      RAISE_FMT (Socket_Failed, "Scatter/gather send failed (iovcnt=%d)",
                 iovcnt);
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
      if (socketio_is_wouldblock ())
        return 0;
      if (socketio_is_connection_closed_recv ())
        RAISE (Socket_Closed);
      RAISE_FMT (Socket_Failed, "Scatter/gather receive failed (iovcnt=%d)",
                 iovcnt);
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

  /* Runtime validation via common function (raises on invalid) */
  (void) SocketCommon_calculate_total_iov_len (iov, iovcnt);

#if SOCKET_HAS_TLS
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

  /* Runtime validation via common function (raises on invalid) */
  (void) SocketCommon_calculate_total_iov_len (iov, iovcnt);

#if SOCKET_HAS_TLS
  if (socket->tls_enabled && socket->tls_ssl)
    return socket_recvv_tls (socket, iov, iovcnt);
#endif

  /* Non-TLS path: use standard readv() */
  return socket_recvv_raw (socket, iov, iovcnt, flags);
}

/**
 * socket_is_tls_enabled - Check if TLS is enabled
 * @socket: Socket instance (read-only)
 *
 * Returns: 1 if enabled, 0 otherwise
 */
int
socket_is_tls_enabled (const T socket)
{
  assert (socket);
#if SOCKET_HAS_TLS
  return socket->tls_enabled ? 1 : 0;
#else
  return 0;
#endif
}

/**
 * socket_tls_want_read - Check if TLS wants read
 * @socket: Socket instance (read-only)
 * Returns: 1 if want read, 0 otherwise
 */
int
socket_tls_want_read (const T socket)
{
  assert (socket);
#if SOCKET_HAS_TLS
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
 * @socket: Socket instance (read-only)
 * Returns: 1 if want write, 0 otherwise
 */
int
socket_tls_want_write (const T socket)
{
  assert (socket);
#if SOCKET_HAS_TLS
  if (!socket_get_ssl (socket))
    return 0;
  if (!socket->tls_handshake_done)
    return socket->tls_last_handshake_state == TLS_HANDSHAKE_WANT_WRITE;
  return 0;
#else
  return 0;
#endif
}

/* ==================== TLS I/O Operations ==================== */
/* Merged from SocketIO-tls.c and SocketIO-tls-iov.c */

#if SOCKET_HAS_TLS

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

/* socket_is_recoverable_io_error removed - use socketio_is_wouldblock() */

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
  int ssl_error;        /**< SSL_ERROR_* constant */
  int mapped_errno;     /**< Corresponding errno value */
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
  { SSL_ERROR_NONE, 0, 0 },
  { SSL_ERROR_SSL, EPROTO, 0 },
  { SSL_ERROR_WANT_READ, EAGAIN, 1 },
  { SSL_ERROR_WANT_WRITE, EAGAIN, 1 },
  { SSL_ERROR_WANT_X509_LOOKUP, EAGAIN, 0 },
  { SSL_ERROR_ZERO_RETURN, ECONNRESET, 0 },
  { SSL_ERROR_WANT_CONNECT, EINPROGRESS, 1 },
  { SSL_ERROR_WANT_ACCEPT, EAGAIN, 1 },
  { SSL_ERROR_WANT_ASYNC, EAGAIN, 0 },
  { SSL_ERROR_WANT_ASYNC_JOB, EAGAIN, 0 },
  { SSL_ERROR_WANT_CLIENT_HELLO_CB, EAGAIN, 0 },
  { SSL_ERROR_WANT_RETRY_VERIFY, EAGAIN, 0 },
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

/**
 * socket_validate_tls_ready - Validate TLS is ready for I/O
 * @socket: Socket instance
 *
 * Returns: SSL pointer if ready, raises exception otherwise
 * Thread-safe: Yes (operates on single socket)
 */
SSL *
socket_validate_tls_ready (T socket)
{
  SSL *ssl = socket_get_ssl (socket);
  if (!ssl)
    RAISE_MSG (Socket_Failed, "TLS enabled but SSL context is NULL");
  if (!socket->tls_handshake_done)
    RAISE_MSG (SocketTLS_HandshakeFailed, "TLS handshake not complete");
  return ssl;
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
static ssize_t
socket_send_tls (T socket, const void *buf, size_t len)
{
  SSL *ssl = socket_validate_tls_ready (socket);

  /* Validate size fits in int to prevent truncation (SSL_write takes int) */
  if (len > INT_MAX)
    RAISE_FMT (SocketTLS_Failed, "TLS send size exceeds INT_MAX (len=%zu)",
               len);

  int ssl_result = SSL_write (ssl, buf, (int)len);

  if (ssl_result <= 0)
    {
      socket_handle_ssl_error (socket, ssl, ssl_result);
      if (socketio_is_wouldblock ())
        return 0;
      RAISE_FMT (SocketTLS_Failed, "TLS send failed (len=%zu)", len);
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
static ssize_t
socket_recv_tls (T socket, void *buf, size_t len)
{
  SSL *ssl = socket_validate_tls_ready (socket);

  /* Validate size fits in int to prevent truncation (SSL_read takes int) */
  if (len > INT_MAX)
    RAISE_FMT (SocketTLS_Failed, "TLS recv size exceeds INT_MAX (len=%zu)",
               len);

  int ssl_result = SSL_read (ssl, buf, (int)len);

  if (ssl_result <= 0)
    {
      socket_handle_ssl_error (socket, ssl, ssl_result);
      if (socketio_is_wouldblock ())
        return 0;
      if (ssl_result == 0 || errno == ECONNRESET)
        RAISE (Socket_Closed);
      RAISE_FMT (SocketTLS_Failed, "TLS receive failed (len=%zu)", len);
    }
  return (ssize_t)ssl_result;
}

/* ==================== TLS Scatter/Gather I/O ==================== */
/* Merged from SocketIO-tls-iov.c */

/**
 * copy_iov_to_buffer - Copy iovec array to contiguous buffer
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 * @buffer: Destination buffer
 * @buffer_size: Size of destination buffer
 *
 * Returns: Total bytes copied
 * Raises: Socket_Failed if buffer too small or overflow detected
 * Thread-safe: Yes (operates on local data)
 *
 * Security: Pre-validates total iovec size using SocketCommon_calculate_total_iov_len
 * which performs overflow-safe summation. This prevents integer overflow
 * attacks that could bypass the per-iteration buffer bounds check.
 */
static size_t
copy_iov_to_buffer (const struct iovec *iov, int iovcnt, void *buffer,
                    size_t buffer_size)
{
  size_t offset = 0;

  /* Pre-validate total size with overflow protection */
  size_t total = SocketCommon_calculate_total_iov_len (iov, iovcnt);
  if (total == 0 && iovcnt > 0)
    RAISE_MSG (Socket_Failed, "iovec total size overflow or invalid");
  if (total > buffer_size)
    RAISE_FMT (Socket_Failed, "Buffer too small for iovec (need %zu, have %zu)",
               total, buffer_size);

  /* Validate iov_base non-NULL for positive lengths */
  for (int i = 0; i < iovcnt; i++) {
    if (iov[i].iov_len > 0 && iov[i].iov_base == NULL) {
      RAISE_FMT (Socket_Failed, "iov[%d].iov_base is NULL with iov_len=%zu", i, iov[i].iov_len);
    }
  }

  for (int i = 0; i < iovcnt; i++)
    {
      memcpy ((char *)buffer + offset, iov[i].iov_base, iov[i].iov_len);
      offset += iov[i].iov_len;
    }

  return offset;
}

/**
 * distribute_buffer_to_iov - Distribute buffer data across iovec array
 * @buffer: Source buffer
 * @buffer_len: Length of data in buffer
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 *
 * Returns: Total bytes distributed
 * Thread-safe: Yes (operates on local data)
 */
static size_t
distribute_buffer_to_iov (const void *buffer, size_t buffer_len,
                          struct iovec *iov, int iovcnt)
{
  size_t remaining = buffer_len;
  size_t src_offset = 0;

  /* Pre-validate iov params and bases (symmetric to copy_iov_to_buffer) */
  if (!iov || iovcnt <= 0 || iovcnt > IOV_MAX) {
    RAISE_FMT (Socket_Failed, "Invalid distribute iov params: iovcnt=%d", iovcnt);
  }
  size_t total_capacity = SocketCommon_calculate_total_iov_len (iov, iovcnt);
  if (buffer_len > total_capacity) {
    RAISE_FMT (Socket_Failed, "buffer_len %zu exceeds iov capacity %zu", buffer_len, total_capacity);
  }
  for (int j = 0; j < iovcnt; j++) {
    if (iov[j].iov_len > 0 && iov[j].iov_base == NULL) {
      RAISE_FMT (Socket_Failed, "iov[%d].iov_base is NULL with iov_len=%zu", j, iov[j].iov_len);
    }
  }

  for (int i = 0; i < iovcnt && remaining > 0; i++)
    {
      size_t chunk
          = (remaining > iov[i].iov_len) ? iov[i].iov_len : remaining;
      memcpy (iov[i].iov_base, (char *)buffer + src_offset, chunk);
      src_offset += chunk;
      remaining -= chunk;
    }

  return buffer_len - remaining;
}

/**
 * socket_sendv_tls - TLS scatter/gather send implementation
 * @socket: Socket instance
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 *
 * Returns: Total bytes sent or 0 if would block
 * Raises: Socket_Failed or SocketTLS_Failed
 * Thread-safe: Yes (operates on single socket)
 */
static ssize_t
socket_sendv_tls (T socket, const struct iovec *iov, int iovcnt)
{
  SSL *ssl = socket_validate_tls_ready (socket);
  size_t total_len = SocketCommon_calculate_total_iov_len (iov, iovcnt);

  /* Validate total size fits in int to prevent truncation (SSL_write takes int) */
  if (total_len > INT_MAX)
    RAISE_FMT (SocketTLS_Failed,
               "TLS sendv size exceeds INT_MAX (total_len=%zu)", total_len);

  Arena_T arena = SocketBase_arena (socket->base);
  void *temp_buf = Arena_calloc (arena, total_len, 1, __FILE__, __LINE__);
  if (!temp_buf)
    RAISE_MSG (Socket_Failed, SOCKET_ENOMEM ": Cannot allocate TLS sendv buffer");

  copy_iov_to_buffer (iov, iovcnt, temp_buf, total_len);

  int ssl_result = SSL_write (ssl, temp_buf, (int)total_len);
  SocketCrypto_secure_clear (temp_buf, total_len);  /* Clear plaintext copy after encryption attempt */

  if (ssl_result <= 0)
    {
      socket_handle_ssl_error (socket, ssl, ssl_result);
      if (socketio_is_wouldblock ())
        return 0;
      RAISE_FMT (SocketTLS_Failed, "TLS sendv failed (iovcnt=%d)", iovcnt);
    }

  return (ssize_t)ssl_result;
}

/**
 * socket_recvv_tls - TLS scatter/gather receive implementation
 * @socket: Socket instance
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 *
 * Returns: Total bytes received or 0 if would block
 * Raises: Socket_Failed, SocketTLS_Failed, or Socket_Closed
 * Thread-safe: Yes (operates on single socket)
 */
static ssize_t
socket_recvv_tls (T socket, struct iovec *iov, int iovcnt)
{
  SSL *ssl = socket_validate_tls_ready (socket);
  size_t total_capacity = SocketCommon_calculate_total_iov_len (iov, iovcnt);

  /* Validate total size fits in int to prevent truncation (SSL_read takes int) */
  if (total_capacity > INT_MAX)
    RAISE_FMT (SocketTLS_Failed,
               "TLS recvv size exceeds INT_MAX (total_capacity=%zu)",
               total_capacity);

  Arena_T arena = SocketBase_arena (socket->base);
  void *temp_buf = Arena_calloc (arena, total_capacity, 1, __FILE__, __LINE__);
  if (!temp_buf)
    RAISE_MSG (Socket_Failed, SOCKET_ENOMEM ": Cannot allocate TLS recvv buffer");

  int ssl_result = SSL_read (ssl, temp_buf, (int)total_capacity);
  if (ssl_result > 0) {
    SocketCrypto_secure_clear (temp_buf, (size_t)ssl_result);  /* Clear decrypted data after copy to user buffers */
  }

  if (ssl_result <= 0)
    {
      socket_handle_ssl_error (socket, ssl, ssl_result);
      if (socketio_is_wouldblock ())
        return 0;
      if (ssl_result == 0 || errno == ECONNRESET)
        RAISE (Socket_Closed);
      RAISE_FMT (SocketTLS_Failed, "TLS recvv failed (iovcnt=%d)", iovcnt);
    }

  size_t copied = distribute_buffer_to_iov (temp_buf, (size_t)ssl_result, iov, iovcnt);
  SocketCrypto_secure_clear (temp_buf, (size_t)ssl_result);  /* Clear decrypted data from temp buffer after copying to user iov */
  return (ssize_t)copied;
}

#endif /* SOCKET_HAS_TLS */

#undef T
