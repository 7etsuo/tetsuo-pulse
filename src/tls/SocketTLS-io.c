/**
 * SocketTLS-io.c - TLS I/O Operations Implementation
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements TLS send/recv wrappers using OpenSSL SSL_write/SSL_read.
 * Handles non-blocking behavior by returning 0 on WANT_READ/WRITE,
 * error mapping, and exception raising.
 * Requires handshake complete and TLS enabled on socket.
 *
 * Thread safety: No - per-socket operations
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "socket/Socket-private.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#include <errno.h>

#define T SocketTLS_T

/* Thread-local exception for detailed TLS error messages
 * Prevents race conditions when multiple threads raise same exception. */
#ifdef _WIN32
static __declspec(thread) Except_T SocketTLS_DetailedException;
#else
static __thread Except_T SocketTLS_DetailedException;
#endif

/* TLS error buffer for detailed error messages */
#ifdef _WIN32
__declspec(thread) char tls_io_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
#else
__thread char tls_io_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
#endif

/* Macro to raise TLS exception with detailed error message */
#define RAISE_TLS_ERROR(exception)                                              \
    do                                                                          \
    {                                                                           \
        SocketTLS_DetailedException = (exception);                              \
        SocketTLS_DetailedException.reason = tls_io_error_buf;                  \
        RAISE(SocketTLS_DetailedException);                                     \
    }                                                                           \
    while (0)

/* Forward declaration for static helpers if needed */
static SSL *socket_get_ssl(Socket_T socket);

/* Include or define socket_get_ssl and socket_handle_ssl_error here or in base */
/* For now, duplicate for module independence, or #include "SocketTLS-private.h" */

static SSL *
socket_get_ssl(Socket_T socket)
{
    if (!socket || !socket->tls_enabled || !socket->tls_ssl)
        return NULL;
    return (SSL *)socket->tls_ssl;
}

static TLSHandshakeState
socket_handle_ssl_error(Socket_T socket, SSL *ssl, int ssl_result)
{
    int ssl_error = SSL_get_error(ssl, ssl_result);

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
 * SocketTLS_send - Send data over TLS connection
 * @socket: Socket instance
 * @buf: Data buffer to send
 * @len: Length of data to send
 *
 * Sends data over the established TLS connection. The handshake must be
 * complete before calling this function. Returns the number of bytes sent
 * or 0 if the operation would block (EAGAIN/EWOULDBLOCK).
 *
 * Returns: Number of bytes sent (0 if would block)
 * Raises: SocketTLS_Failed on error
 * Thread-safe: No (operates on socket)
 */
ssize_t
SocketTLS_send(Socket_T socket, const void *buf, size_t len)
{
    SSL *ssl;
    int result;

    assert(socket);
    assert(buf);
    assert(len > 0);

    /* Check if TLS is enabled */
    if (!socket->tls_enabled)
    {
        snprintf(tls_io_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "TLS not enabled on socket");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Check if handshake is complete */
    if (!socket->tls_handshake_done)
    {
        snprintf(tls_io_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "TLS handshake not complete");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Get SSL object */
    ssl = socket_get_ssl(socket);
    if (!ssl)
    {
        snprintf(tls_io_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "SSL object not available");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Send data */
    result = SSL_write(ssl, buf, (int)len);

    if (result > 0)
    {
        /* Data sent successfully */
        return (ssize_t)result;
    }
    else
    {
        /* Check for specific errors */
        TLSHandshakeState state = socket_handle_ssl_error(socket, ssl, result);
        if (state == TLS_HANDSHAKE_ERROR)
        {
            RAISE_TLS_ERROR(SocketTLS_Failed);
        }
        /* WANT_READ/WRITE means operation would block */
        errno = EAGAIN;
        return 0;
    }
}

/**
 * SocketTLS_recv - Receive data from TLS connection
 * @socket: Socket instance
 * @buf: Buffer to receive data into
 * @len: Maximum length to receive
 *
 * Receives data from the established TLS connection. The handshake must be
 * complete before calling this function. Returns the number of bytes received,
 * 0 if the operation would block, or raises Socket_Closed on clean shutdown.
 *
 * Returns: Number of bytes received (0 if would block)
 * Raises: SocketTLS_Failed on error, Socket_Closed on clean shutdown
 * Thread-safe: No (operates on socket)
 */
ssize_t
SocketTLS_recv(Socket_T socket, void *buf, size_t len)
{
    SSL *ssl;
    int result;

    assert(socket);
    assert(buf);
    assert(len > 0);

    /* Check if TLS is enabled */
    if (!socket->tls_enabled)
    {
        snprintf(tls_io_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "TLS not enabled on socket");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Check if handshake is complete */
    if (!socket->tls_handshake_done)
    {
        snprintf(tls_io_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "TLS handshake not complete");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Get SSL object */
    ssl = socket_get_ssl(socket);
    if (!ssl)
    {
        snprintf(tls_io_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "SSL object not available");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Receive data */
    result = SSL_read(ssl, buf, (int)len);

    if (result > 0)
    {
        /* Data received successfully */
        return (ssize_t)result;
    }
    else if (result == 0)
    {
        /* Clean shutdown by peer */
        RAISE(Socket_Closed);
    }
    else
    {
        /* Check for specific errors */
        TLSHandshakeState state = socket_handle_ssl_error(socket, ssl, result);
        if (state == TLS_HANDSHAKE_ERROR)
        {
            RAISE_TLS_ERROR(SocketTLS_Failed);
        }
        /* WANT_READ/WRITE means operation would block */
        errno = EAGAIN;
        return 0;
    }
    return -1; /* Unreachable */
}

#undef T

#endif /* SOCKET_HAS_TLS */