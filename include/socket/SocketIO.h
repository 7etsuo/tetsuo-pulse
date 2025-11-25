#ifndef SOCKETIO_INCLUDED
#define SOCKETIO_INCLUDED

#include "socket/Socket.h"
#include <stddef.h>
#include <sys/uio.h>

#ifdef SOCKET_HAS_TLS
#include <openssl/ssl.h>
#endif

#define T Socket_T

/* Internal I/O abstraction - routes through TLS when enabled */

/**
 * socket_send_internal - Internal send operation (TLS-aware)
 * @socket: Socket instance
 * @buf: Data to send
 * @len: Length of data
 * @flags: Send flags (MSG_NOSIGNAL, etc.)
 * Returns: Bytes sent or 0 if would block
 * Raises: Socket_Failed or SocketTLS_Failed
 * Thread-safe: Yes (operates on single socket)
 * Routes through SSL_write() if TLS is enabled, otherwise uses send().
 * Handles partial sends and EAGAIN mapping.
 */
extern ssize_t socket_send_internal (T socket, const void *buf, size_t len,
                                     int flags);

/**
 * socket_recv_internal - Internal receive operation (TLS-aware)
 * @socket: Socket instance
 * @buf: Buffer for received data
 * @len: Buffer size
 * @flags: Receive flags
 * Returns: Bytes received or 0 if would block
 * Raises: Socket_Failed or SocketTLS_Failed, Socket_Closed on EOF
 * Thread-safe: Yes (operates on single socket)
 * Routes through SSL_read() if TLS is enabled, otherwise uses recv().
 * Maps SSL errors to errno (EAGAIN for WANT_READ/WRITE).
 */
extern ssize_t socket_recv_internal (T socket, void *buf, size_t len,
                                     int flags);

/**
 * socket_sendv_internal - Internal scatter/gather send (TLS-aware)
 * @socket: Socket instance
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 * @flags: Send flags
 * Returns: Total bytes sent or 0 if would block
 * Raises: Socket_Failed or SocketTLS_Failed
 * Thread-safe: Yes (operates on single socket)
 * For TLS: Copies iov to temp buffer, calls SSL_write().
 * For non-TLS: Uses writev() directly.
 * Allocates temp buffer via socket->arena if needed.
 */
extern ssize_t socket_sendv_internal (T socket, const struct iovec *iov,
                                      int iovcnt, int flags);

/**
 * socket_recvv_internal - Internal scatter/gather receive (TLS-aware)
 * @socket: Socket instance
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 * @flags: Receive flags
 * Returns: Total bytes received or 0 if would block
 * Raises: Socket_Failed or SocketTLS_Failed, Socket_Closed on EOF
 * Thread-safe: Yes (operates on single socket)
 * For TLS: Calls SSL_read() into first iov, advances manually.
 * For non-TLS: Uses readv() directly.
 */
extern ssize_t socket_recvv_internal (T socket, struct iovec *iov, int iovcnt,
                                      int flags);

/**
 * socket_is_tls_enabled - Check if TLS is enabled on socket
 * @socket: Socket instance
 * Returns: 1 if TLS is enabled, 0 otherwise
 * Thread-safe: Yes (read-only flag)
 */
extern int socket_is_tls_enabled (T socket);

/**
 * socket_tls_want_read - Check if TLS operation wants read
 * @socket: Socket instance
 * Returns: 1 if SSL_ERROR_WANT_READ pending, 0 otherwise
 * Thread-safe: Yes (read last SSL error)
 * Used by SocketPoll to adjust event masks during handshake.
 */
extern int socket_tls_want_read (T socket);

/**
 * socket_tls_want_write - Check if TLS operation wants write
 * @socket: Socket instance
 * Returns: 1 if SSL_ERROR_WANT_WRITE pending, 0 otherwise
 * Thread-safe: Yes (read last SSL error)
 * Used by SocketPoll to adjust event masks during handshake.
 */
extern int socket_tls_want_write (T socket);

#ifdef SOCKET_HAS_TLS
/**
 * socket_handle_ssl_error - Helper to handle SSL error codes
 * @socket: Socket instance
 * @ssl: SSL object
 * @ssl_result: Result from SSL operation
 * @returns: 0 on success, -1 on error (sets errno)
 * Thread-safe: Yes (operates on single socket)
 * Maps SSL error codes to errno values and updates socket state.
 * Used by TLS-aware I/O functions for consistent error handling.
 */
extern int socket_handle_ssl_error (T socket, SSL *ssl, int ssl_result);

/**
 * socket_get_ssl - Get SSL object from socket
 * @socket: Socket instance
 * Returns: SSL object or NULL if TLS not enabled
 * Thread-safe: Yes (read-only access)
 */
extern SSL *socket_get_ssl (T socket);

/**
 * socket_validate_tls_ready - Validate TLS is ready for I/O
 * @socket: Socket instance
 * Returns: SSL pointer if ready
 * Raises: Socket_Failed or SocketTLS_HandshakeFailed if not ready
 * Thread-safe: Yes (operates on single socket)
 * Shared helper for TLS I/O functions.
 */
extern SSL *socket_validate_tls_ready (T socket);
#endif

#undef T

#endif /* SOCKETIO_INCLUDED */
