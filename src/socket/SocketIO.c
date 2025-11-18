#include "socket/SocketIO.h"
#include "socket/Socket.h"
#include "core/SocketError.h"
#include "core/SocketConfig.h"
#include <assert.h>

/* Thread-local exception for detailed error messages
 * Prevents race conditions when multiple threads raise same exception. */
#ifdef _WIN32
static __declspec(thread) Except_T SocketIO_DetailedException;
#else
static __thread Except_T SocketIO_DetailedException;
#endif

/* Macro to raise exception with detailed error message */
#define RAISE_SOCKETIO_ERROR(exception)                                          \
    do                                                                          \
    {                                                                           \
        SocketIO_DetailedException = (exception);                                \
        SocketIO_DetailedException.reason = socket_error_buf;                    \
        RAISE(SocketIO_DetailedException);                                     \
    } while (0)

#ifdef SOCKET_HAS_TLS
#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define T Socket_T

/* Forward declaration */
extern int Socket_fd(const T socket);

#ifdef SOCKET_HAS_TLS

/* Helper: Get SSL* from socket */
static SSL *socket_get_ssl(T socket)
{
    if (!socket || !socket->tls_enabled || !socket->tls_ssl)
        return NULL;
    return (SSL *)socket->tls_ssl;
}

/* Helper: Handle SSL error codes */
static int socket_handle_ssl_error(T socket, SSL *ssl, int ssl_result)
{
    int ssl_error = SSL_get_error(ssl, ssl_result);

    switch (ssl_error)
    {
    case SSL_ERROR_NONE:
        return 0;  /* Success */

    case SSL_ERROR_WANT_READ:
        socket->tls_handshake_done = 0;  /* Handshake not complete */
        errno = EAGAIN;
        return -1;

    case SSL_ERROR_WANT_WRITE:
        socket->tls_handshake_done = 0;  /* Handshake not complete */
        errno = EAGAIN;
        return -1;

    case SSL_ERROR_ZERO_RETURN:
        /* TLS connection closed cleanly */
        errno = ECONNRESET;
        return -1;

    case SSL_ERROR_SYSCALL:
        /* System call error - check errno */
        if (errno == 0)
            errno = ECONNRESET;  /* EOF */
        return -1;

    default:
        /* Other SSL errors */
        errno = EPROTO;
        return -1;
    }
}

#endif /* SOCKET_HAS_TLS */

ssize_t socket_send_internal(T socket, const void *buf, size_t len, int flags)
{
    assert(socket);
    assert(buf);
    assert(len > 0);

#ifdef SOCKET_HAS_TLS
    if (socket->tls_enabled && socket->tls_ssl)
    {
        SSL *ssl = socket_get_ssl(socket);
        if (!ssl)
        {
            SOCKET_ERROR_MSG("TLS enabled but SSL context is NULL");
            RAISE_SOCKETIO_ERROR(Socket_Failed);
        }

        /* Check if handshake is complete */
        if (!socket->tls_handshake_done)
        {
            SOCKET_ERROR_MSG("TLS handshake not complete");
            RAISE_SOCKETIO_ERROR(SocketTLS_HandshakeFailed);
        }

        /* Use SSL_write() for TLS */
        int ssl_result = SSL_write(ssl, buf, (int)len);

        if (ssl_result <= 0)
        {
            if (socket_handle_ssl_error(socket, ssl, ssl_result) < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return 0;  /* Would block */
                /* Other errors will raise exception below */
            }
        }

        if (ssl_result < 0)
        {
            SOCKET_ERROR_FMT("TLS send failed (len=%zu)", len);
            RAISE_TLS_ERROR(SocketTLS_Failed);
        }

        return (ssize_t)ssl_result;
    }
#endif

    /* Non-TLS path: use standard send() */
    ssize_t result = send(Socket_fd(socket), buf, len, flags);

    if (result < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        if (errno == EPIPE)
            RAISE(Socket_Closed);
        if (errno == ECONNRESET)
            RAISE(Socket_Closed);
        SOCKET_ERROR_FMT("Send failed (len=%zu)", len);
        RAISE_SOCKETIO_ERROR(Socket_Failed);
    }

    return result;
}

ssize_t socket_recv_internal(T socket, void *buf, size_t len, int flags)
{
    assert(socket);
    assert(buf);
    assert(len > 0);

#ifdef SOCKET_HAS_TLS
    if (socket->tls_enabled && socket->tls_ssl)
    {
        SSL *ssl = socket_get_ssl(socket);
        if (!ssl)
        {
            SOCKET_ERROR_MSG("TLS enabled but SSL context is NULL");
            RAISE_SOCKETIO_ERROR(Socket_Failed);
        }

        /* Check if handshake is complete */
        if (!socket->tls_handshake_done)
        {
            SOCKET_ERROR_MSG("TLS handshake not complete");
            RAISE_SOCKETIO_ERROR(SocketTLS_HandshakeFailed);
        }

        /* Use SSL_read() for TLS */
        int ssl_result = SSL_read(ssl, buf, (int)len);

        if (ssl_result <= 0)
        {
            if (socket_handle_ssl_error(socket, ssl, ssl_result) < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return 0;  /* Would block */
                if (errno == ECONNRESET)
                    RAISE(Socket_Closed);
                /* Other errors will raise exception below */
            }
        }

        if (ssl_result < 0)
        {
            SOCKET_ERROR_FMT("TLS receive failed (len=%zu)", len);
            RAISE_TLS_ERROR(SocketTLS_Failed);
        }

        if (ssl_result == 0)
        {
            /* TLS connection closed cleanly */
            RAISE(Socket_Closed);
        }

        return (ssize_t)ssl_result;
    }
#endif

    /* Non-TLS path: use standard recv() */
    ssize_t result = recv(Socket_fd(socket), buf, len, flags);

    if (result < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        if (errno == ECONNRESET)
            RAISE(Socket_Closed);
        SOCKET_ERROR_FMT("Receive failed (len=%zu)", len);
        RAISE_SOCKETIO_ERROR(Socket_Failed);
    }
    else if (result == 0)
    {
        RAISE(Socket_Closed);
    }

    return result;
}

ssize_t socket_sendv_internal(T socket, const struct iovec *iov, int iovcnt, int flags)
{
    (void)flags;  /* Suppress unused parameter warning */

    assert(socket);
    assert(iov);
    assert(iovcnt > 0);
    assert(iovcnt <= IOV_MAX);

#ifdef SOCKET_HAS_TLS
    if (socket->tls_enabled && socket->tls_ssl)
    {
        SSL *ssl = socket_get_ssl(socket);
        if (!ssl)
        {
            SOCKET_ERROR_MSG("TLS enabled but SSL context is NULL");
            RAISE_SOCKETIO_ERROR(Socket_Failed);
        }

        /* Check if handshake is complete */
        if (!socket->tls_handshake_done)
        {
            SOCKET_ERROR_MSG("TLS handshake not complete");
            RAISE_SOCKETIO_ERROR(SocketTLS_HandshakeFailed);
        }

        /* Calculate total length */
        size_t total_len = 0;
        for (int i = 0; i < iovcnt; i++)
        {
            total_len += iov[i].iov_len;
        }

        /* Allocate temp buffer from socket arena */
        void *temp_buf = Arena_alloc(socket->arena, total_len, __FILE__, __LINE__);
        if (!temp_buf)
        {
            SOCKET_ERROR_MSG(SOCKET_ENOMEM ": Cannot allocate temp buffer for TLS sendv");
            RAISE_SOCKETIO_ERROR(Socket_Failed);
        }

        /* Copy iovec data to temp buffer */
        size_t offset = 0;
        for (int i = 0; i < iovcnt; i++)
        {
            memcpy((char *)temp_buf + offset, iov[i].iov_base, iov[i].iov_len);
            offset += iov[i].iov_len;
        }

        /* Use SSL_write() */
        int ssl_result = SSL_write(ssl, temp_buf, (int)total_len);

        if (ssl_result <= 0)
        {
            if (socket_handle_ssl_error(socket, ssl, ssl_result) < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return 0;  /* Would block */
                /* Other errors will raise exception below */
            }
        }

        if (ssl_result < 0)
        {
            SOCKET_ERROR_FMT("TLS sendv failed (iovcnt=%d, total_len=%zu)", iovcnt, total_len);
            RAISE_TLS_ERROR(SocketTLS_Failed);
        }

        return (ssize_t)ssl_result;
    }
#endif

    /* Non-TLS path: use standard writev() */
    ssize_t result = writev(Socket_fd(socket), iov, iovcnt);
    if (result < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        if (errno == EPIPE)
            RAISE(Socket_Closed);
        if (errno == ECONNRESET)
            RAISE(Socket_Closed);
        SOCKET_ERROR_FMT("Scatter/gather send failed (iovcnt=%d)", iovcnt);
        RAISE_SOCKETIO_ERROR(Socket_Failed);
    }

    return result;
}

ssize_t socket_recvv_internal(T socket, struct iovec *iov, int iovcnt, int flags)
{
    (void)flags;  /* Suppress unused parameter warning */

    assert(socket);
    assert(iov);
    assert(iovcnt > 0);
    assert(iovcnt <= IOV_MAX);

#ifdef SOCKET_HAS_TLS
    if (socket->tls_enabled && socket->tls_ssl)
    {
        SSL *ssl = socket_get_ssl(socket);
        if (!ssl)
        {
            SOCKET_ERROR_MSG("TLS enabled but SSL context is NULL");
            RAISE_SOCKETIO_ERROR(Socket_Failed);
        }

        /* Check if handshake is complete */
        if (!socket->tls_handshake_done)
        {
            SOCKET_ERROR_MSG("TLS handshake not complete");
            RAISE_SOCKETIO_ERROR(SocketTLS_HandshakeFailed);
        }

        /* For TLS, read into first iovec and distribute manually */
        if (iovcnt == 1)
        {
            /* Single buffer - direct read */
            int ssl_result = SSL_read(ssl, iov[0].iov_base, (int)iov[0].iov_len);

            if (ssl_result <= 0)
            {
                if (socket_handle_ssl_error(socket, ssl, ssl_result) < 0)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        return 0;  /* Would block */
                    if (errno == ECONNRESET)
                        RAISE(Socket_Closed);
                    /* Other errors will raise exception below */
                }
            }

            if (ssl_result < 0)
            {
                SOCKET_ERROR_FMT("TLS recvv failed (iovcnt=%d)", iovcnt);
                RAISE_TLS_ERROR(SocketTLS_Failed);
            }

            if (ssl_result == 0)
            {
                RAISE(Socket_Closed);
            }

            return (ssize_t)ssl_result;
        }
        else
        {
            /* Multiple buffers - read into first, then distribute */
            size_t total_capacity = 0;
            for (int i = 0; i < iovcnt; i++)
            {
                total_capacity += iov[i].iov_len;
            }

            /* Read up to total capacity into first buffer */
            int ssl_result = SSL_read(ssl, iov[0].iov_base, (int)total_capacity);

            if (ssl_result <= 0)
            {
                if (socket_handle_ssl_error(socket, ssl, ssl_result) < 0)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        return 0;  /* Would block */
                    if (errno == ECONNRESET)
                        RAISE(Socket_Closed);
                    /* Other errors will raise exception below */
                }
            }

            if (ssl_result < 0)
            {
                SOCKET_ERROR_FMT("TLS recvv failed (iovcnt=%d, capacity=%zu)", iovcnt, total_capacity);
                RAISE_TLS_ERROR(SocketTLS_Failed);
            }

            if (ssl_result == 0)
            {
                RAISE(Socket_Closed);
            }

            /* Distribute data across iovecs */
            size_t remaining = (size_t)ssl_result;
            size_t src_offset = 0;
            for (int i = 0; i < iovcnt && remaining > 0; i++)
            {
                size_t chunk = (remaining > iov[i].iov_len) ? iov[i].iov_len : remaining;
                if (i > 0)
                {
                    memcpy(iov[i].iov_base, (char *)iov[0].iov_base + src_offset, chunk);
                }
                src_offset += chunk;
                remaining -= chunk;
            }

            return (ssize_t)ssl_result;
        }
    }
#endif

    /* Non-TLS path: use standard readv() */
    ssize_t result = readv(Socket_fd(socket), iov, iovcnt);
    if (result < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        if (errno == ECONNRESET)
            RAISE(Socket_Closed);
        SOCKET_ERROR_FMT("Scatter/gather receive failed (iovcnt=%d)", iovcnt);
        RAISE_SOCKETIO_ERROR(Socket_Failed);
    }
    else if (result == 0)
    {
        RAISE(Socket_Closed);
    }

    return result;
}

int socket_is_tls_enabled(T socket)
{
    assert(socket);
#ifdef SOCKET_HAS_TLS
    return socket->tls_enabled ? 1 : 0;
#else
    return 0;
#endif
}

int socket_tls_want_read(T socket)
{
    assert(socket);
#ifdef SOCKET_HAS_TLS
    if (!socket->tls_enabled || !socket->tls_ssl)
        return 0;

    /* Check if handshake is in progress and wants read */
    if (!socket->tls_handshake_done)
    {
        return (socket->tls_last_handshake_state == TLS_HANDSHAKE_WANT_READ) ? 1 : 0;
    }

    /* For established connections, SSL_pending indicates data available */
    SSL *ssl = socket_get_ssl(socket);
    if (ssl && SSL_pending(ssl) > 0)
        return 1;

    return 0;
#else
    return 0;
#endif
}

int socket_tls_want_write(T socket)
{
    assert(socket);
#ifdef SOCKET_HAS_TLS
    if (!socket->tls_enabled || !socket->tls_ssl)
        return 0;

    /* Check if handshake is in progress and wants write */
    if (!socket->tls_handshake_done)
    {
        return (socket->tls_last_handshake_state == TLS_HANDSHAKE_WANT_WRITE) ? 1 : 0;
    }

    return 0;
#else
    return 0;
#endif
}

#undef T
