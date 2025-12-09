/**
 * @file SocketIO.h
 * @ingroup core_io
 * @brief Internal I/O abstraction layer for socket operations with TLS
 * support.
 *
 * Provides internal I/O operations that automatically route through TLS
 * when enabled, or use raw socket operations otherwise. This abstraction
 * layer handles the complexity of TLS/non-TLS operation selection.
 *
 * @see Socket_send() for public send operations.
 * @see Socket_recv() for public receive operations.
 * @see @ref SocketTLS_T for enabling TLS on sockets.
 * @see @ref SocketAsync_T for async I/O integration.
 * @see @ref SocketPoll_T for event-driven I/O.
 */

#ifndef SOCKETIO_INCLUDED
#define SOCKETIO_INCLUDED

#include "socket/Socket.h"
#include <errno.h>
#include <stddef.h>
#include <sys/uio.h>

#if SOCKET_HAS_TLS
#include <openssl/ssl.h>
#endif

#define T Socket_T

/* Internal I/O abstraction - routes through TLS when enabled */

/**
 * @brief Internal send operation (TLS-aware)
 * @ingroup core_io
 * @param socket Socket instance
 * @param buf Data to send
 * @param len Length of data
 * @param flags Send flags (MSG_NOSIGNAL, etc.)
 * @return Number of bytes sent, or 0 if operation would block
 * (EAGAIN/EWOULDBLOCK).
 * @throws Socket_Failed on underlying socket errors such as invalid file
 * descriptor or network issues.
 * @throws SocketTLS_Failed on TLS encryption or write failures (#if
 * SOCKET_HAS_TLS).
 * @threadsafe Yes - operates on single socket.
 * @note Routes through SSL_write() if TLS is enabled, otherwise uses send().
 * @note Handles partial sends and EAGAIN mapping.
 *
 * @see Socket_send() for the public synchronous send interface.
 * @see socket_recv_internal() for the corresponding receive operation.
 * @see socket_sendv_internal() for scatter-gather send support.
 * @see @ref SocketTLS_Failed "SocketTLS_Failed" exception for TLS-specific
 * errors.
 */
extern ssize_t socket_send_internal (T socket, const void *buf, size_t len,
                                     int flags);

/**
 * @brief Internal receive operation (TLS-aware)
 * @ingroup core_io
 * @param socket Socket instance
 * @param buf Buffer for received data
 * @param len Buffer size
 * @param flags Receive flags
 * @return Number of bytes received, or 0 if would block (EAGAIN/EWOULDBLOCK)
 * or EOF (connection closed).
 * @throws Socket_Failed on underlying socket errors such as invalid file
 * descriptor or network issues.
 * @throws SocketTLS_Failed on TLS decryption or read failures (#if
 * SOCKET_HAS_TLS).
 * @throws Socket_Closed on connection closure detected by recv returning 0 or
 * ECONNRESET.
 * @threadsafe Yes - operates on single socket.
 * @note Routes through SSL_read() if TLS is enabled, otherwise uses recv().
 * @note Maps SSL errors to errno (EAGAIN for WANT_READ/WRITE).
 *
 * @see Socket_recv() for the public synchronous receive interface.
 * @see socket_send_internal() for the corresponding send operation.
 * @see socket_recvv_internal() for scatter-gather receive support.
 * @see SocketTLS_Failed exception for TLS-specific errors.
 * @see @ref Socket_Closed "Socket_Closed" on EOF detection.
 */
extern ssize_t socket_recv_internal (T socket, void *buf, size_t len,
                                     int flags);

/**
 * @brief Internal scatter/gather send (TLS-aware)
 * @ingroup core_io
 * @param socket Socket instance
 * @param iov Array of iovec structures
 * @param iovcnt Number of iovec structures
 * @param flags Send flags
 * @return Total number of bytes sent from iov buffers, or 0 if would block.
 * @throws Socket_Failed on underlying socket or vectored I/O errors.
 * @throws SocketTLS_Failed on TLS write failures or buffer allocation issues
 * (#if SOCKET_HAS_TLS).
 * @threadsafe Yes - operates on single socket.
 * @note For TLS: Copies iov to temp buffer, calls SSL_write().
 * @note For non-TLS: Uses writev() directly.
 * @note Allocates temp buffer via socket->arena if needed.
 *
 * @see Socket_sendv() for public vectored send interface.
 * @see socket_send_internal() for simple buffer send.
 * @see Arena_T for memory allocation details.
 * @see @ref SocketTLS_Failed "SocketTLS_Failed" for TLS errors.
 */
extern ssize_t socket_sendv_internal (T socket, const struct iovec *iov,
                                      int iovcnt, int flags);

/**
 * @brief Internal scatter/gather receive (TLS-aware)
 * @ingroup core_io
 * @param socket Socket instance
 * @param iov Array of iovec structures
 * @param iovcnt Number of iovec structures
 * @param flags Receive flags
 * @return Total number of bytes received into iov buffers, or 0 if would block
 * or EOF.
 * @throws Socket_Failed on underlying socket or vectored I/O errors.
 * @throws SocketTLS_Failed on TLS read failures (#if SOCKET_HAS_TLS).
 * @throws Socket_Closed on connection closure detected by readv returning 0 or
 * ECONNRESET.
 * @threadsafe Yes - operates on single socket.
 * @note For TLS: Calls SSL_read() into first iov, advances manually.
 * @note For non-TLS: Uses readv() directly.
 *
 * @see Socket_recvv() for public vectored receive interface.
 * @see socket_recv_internal() for simple buffer receive.
 * @see @ref Socket_Closed "Socket_Closed" on connection EOF.
 * @see @ref SocketTLS_Failed "SocketTLS_Failed" for TLS errors.
 */
extern ssize_t socket_recvv_internal (T socket, struct iovec *iov, int iovcnt,
                                      int flags);

/**
 * @brief Check if socket has TLS enabled.
 * @ingroup core_io
 * @param socket Socket to check.
 * @return 1 if TLS is enabled on the socket, 0 otherwise.
 * @threadsafe Yes - atomic read of socket state.
 * @see SocketTLS_enable() to enable TLS on a socket.
 * @see socket_tls_want_read() and socket_tls_want_write() for checking TLS
 * handshake needs.
 * @see @ref group__security for TLS module documentation.
 */
extern int socket_is_tls_enabled (const T socket);

/**
 * @brief Check if TLS wants to read more data for handshake or protocol.
 * @ingroup core_io
 * @param socket TLS-enabled socket to query.
 * @return 1 if TLS needs more input data, 0 otherwise.
 * @note Used in event loops to determine if POLL_READ should be enabled for
 * TLS sockets.
 * @threadsafe Yes - read-only access to TLS state.
 * @see SocketTLS_handshake() for performing TLS handshake.
 * @see socket_tls_want_write() for write readiness.
 * @see @ref SocketPoll_T for event system integration.
 * @see @ref group__security for TLS details.
 */
extern int socket_tls_want_read (const T socket);

/**
 * @brief Check if TLS wants to write more data for handshake or protocol.
 * @ingroup core_io
 * @param socket TLS-enabled socket to query.
 * @return 1 if TLS needs to output data, 0 otherwise.
 * @note Used in event loops to determine if POLL_WRITE should be enabled for
 * TLS sockets.
 * @threadsafe Yes - read-only access to TLS state.
 * @see SocketTLS_handshake() for performing TLS handshake.
 * @see socket_tls_want_read() for read readiness.
 * @see @ref SocketPoll_T for event system integration.
 * @see @ref group__security for TLS details.
 */
extern int socket_tls_want_write (const T socket);

#if SOCKET_HAS_TLS
/**
 * @brief Helper to handle SSL error codes
 * @ingroup core_io
 * @param socket Socket instance
 * @param ssl SSL object
 * @param ssl_result Result from SSL operation
 * @return 0 on success, -1 on error (sets errno)
 * @threadsafe Yes - operates on single socket.
 * @note Maps SSL error codes to errno values and updates socket state.
 * @note Used by TLS-aware I/O functions for consistent error handling.
 *
 * @see socket_send_internal() and socket_recv_internal() for usage examples.
 * @see SSL_get_error() OpenSSL documentation for error mapping details.
 * @see @ref SocketTLS_Failed "SocketTLS_Failed" for raised exceptions.
 */
extern int socket_handle_ssl_error (T socket, SSL *ssl, int ssl_result);

/**
 * @brief Get SSL object from socket
 * @ingroup core_io
 * @param socket Socket instance
 * @return SSL object or NULL if TLS not enabled
 * @threadsafe Yes - read-only access to socket state.
 *
 * @see socket_is_tls_enabled() to check TLS status before calling.
 * @see socket_validate_tls_ready() to ensure TLS readiness for I/O.
 * @see socket_handle_ssl_error() for handling errors with the SSL object.
 * @see @ref security "Security Module" for TLS integration.
 */
extern SSL *socket_get_ssl (T socket);

/**
 * @brief Validate TLS is ready for I/O
 * @ingroup core_io
 * @param socket Socket instance
 * @return SSL* pointer if TLS is fully ready for I/O operations.
 * @throws Socket_Failed if socket is invalid or TLS not enabled.
 * @throws SocketTLS_HandshakeFailed if TLS handshake is not complete or failed
 * (#if SOCKET_HAS_TLS).
 * @threadsafe Yes - operates on single socket.
 * @note Shared helper for TLS I/O functions.
 *
 * @see socket_send_internal() and similar for TLS readiness check.
 * @see SocketTLS_handshake() if manual handshake needed.
 * @see @ref SocketTLS_Failed "SocketTLS_Failed" or @ref Socket_Failed
 * "Socket_Failed" on error.
 */
extern SSL *socket_validate_tls_ready (T socket);
#endif

/* ==================== Common I/O Error Helpers ==================== */

/**
 * @brief Check if errno indicates operation would block
 * @ingroup core_io
 * @return 1 if EAGAIN/EWOULDBLOCK, 0 otherwise
 * @threadsafe Yes - reads errno (thread-local in POSIX).
 * @note Use this instead of inline errno checks for consistency.
 *
 * @see socketio_is_connection_closed_send() and
 * socketio_is_connection_closed_recv() for related error checks.
 * @see EAGAIN and EWOULDBLOCK in <errno.h> for details.
 */
static inline int
socketio_is_wouldblock (void)
{
  return errno == EAGAIN || errno == EWOULDBLOCK;
}

/**
 * @brief Check if send error indicates closed connection
 * @ingroup core_io
 * @return 1 if EPIPE/ECONNRESET, 0 otherwise
 * @threadsafe Yes - reads errno (thread-local in POSIX).
 * @note Use after send() failure to check for connection close.
 *
 * @see socketio_is_wouldblock() for non-blocking checks.
 * @see socketio_is_connection_closed_recv() for recv counterpart.
 * @see EPIPE and ECONNRESET in <errno.h>.
 */
static inline int
socketio_is_connection_closed_send (void)
{
  return errno == EPIPE || errno == ECONNRESET;
}

/**
 * @brief Check if recv error indicates closed connection
 * @ingroup core_io
 * @return 1 if ECONNRESET, 0 otherwise
 * @threadsafe Yes - reads errno (thread-local in POSIX).
 * @note Use after recv() failure to check for connection close.
 *
 * @see socketio_is_wouldblock() for non-blocking checks.
 * @see socketio_is_connection_closed_send() for send counterpart.
 * @see ECONNRESET in <errno.h>.
 */
static inline int
socketio_is_connection_closed_recv (void)
{
  return errno == ECONNRESET;
}

#undef T
#endif /* SOCKETIO_INCLUDED */
