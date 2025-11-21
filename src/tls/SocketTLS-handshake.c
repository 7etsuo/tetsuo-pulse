/**
 * SocketTLS-handshake.c - TLS Handshake and Setup Functions
 *
 * Part of the Socket Library
 * Following C Interfaces and Implementations patterns
 *
 * Implements TLS enable, SNI setup, handshake, and shutdown logic.
 * Manages SSL object lifecycle, buffer allocation, state flags.
 * Supports non-blocking operation via state returns.
 *
 * Dependencies: Duplicates some static helpers from base/io for independence.
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include "tls/SocketTLSContext.h"
#include "socket/Socket-private.h"
#include "core/Arena.h"
#include <openssl/ssl.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#define T SocketTLS_T

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

static void
socket_allocate_tls_buffers(Socket_T socket)
{
    assert(socket);
    assert(socket->arena);

    /* Allocate read buffer */
    if (!socket->tls_read_buf)
    {
        socket->tls_read_buf = Arena_alloc(socket->arena, SOCKET_TLS_BUFFER_SIZE, __FILE__, __LINE__);
        socket->tls_read_buf_len = 0;
    }

    /* Allocate write buffer */
    if (!socket->tls_write_buf)
    {
        socket->tls_write_buf = Arena_alloc(socket->arena, SOCKET_TLS_BUFFER_SIZE, __FILE__, __LINE__);
        socket->tls_write_buf_len = 0;
    }
}

static void
socket_free_tls_resources(Socket_T socket)
{
    assert(socket);

    /* Free SSL object */
    if (socket->tls_ssl)
    {
        SSL_free((SSL *)socket->tls_ssl);
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

/* Public functions ... */
void
SocketTLS_enable(Socket_T socket, SocketTLSContext_T ctx)
{
    SSL *ssl;
    int fd;

    assert(socket);
    assert(ctx);
    assert(SocketTLSContext_get_ssl_ctx(ctx));

    /* Check if TLS is already enabled */
    if (socket->tls_enabled)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "TLS already enabled on socket");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Get socket file descriptor */
    fd = socket->fd;
    if (fd < 0)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "Socket not connected (invalid file descriptor)");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Create SSL object from context */
    ssl = SSL_new((SSL_CTX *)SocketTLSContext_get_ssl_ctx(ctx));
    if (!ssl)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "Failed to create SSL object");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Set connection state (client/server) */
    if (SocketTLSContext_is_server(ctx))
    {
        SSL_set_accept_state(ssl);
    }
    else
    {
        SSL_set_connect_state(ssl);
    }

    /* Associate SSL object with socket file descriptor */
    if (SSL_set_fd(ssl, fd) != 1)
    {
        SSL_free(ssl);
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "Failed to associate SSL with socket file descriptor");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Store SSL object in socket */
    socket->tls_ssl = (void *)ssl;

    /* Allocate TLS buffers */
    socket_allocate_tls_buffers(socket);

    /* Set TLS flags */
    socket->tls_enabled = 1;
    socket->tls_handshake_done = 0;
    socket->tls_shutdown_done = 0;
}

void
SocketTLS_set_hostname(Socket_T socket, const char *hostname)
{
    SSL *ssl;
    size_t hostname_len;

    assert(socket);
    assert(hostname);

    /* Check if TLS is enabled */
    if (!socket->tls_enabled)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "TLS not enabled on socket");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Validate hostname length */
    hostname_len = strlen(hostname);
    if (hostname_len == 0 || hostname_len > SOCKET_TLS_MAX_SNI_LEN) /* SNI hostname limit per RFC 6066 */
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "Invalid hostname length: %zu", hostname_len);
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Allocate hostname string in socket arena */
    socket->tls_sni_hostname = Arena_alloc(socket->arena, hostname_len + 1, __FILE__, __LINE__);
    if (!socket->tls_sni_hostname)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "Failed to allocate hostname buffer");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Copy hostname safely */
    memcpy((char *)socket->tls_sni_hostname, hostname, hostname_len + 1);

    /* Get SSL object */
    ssl = socket_get_ssl(socket);
    if (!ssl)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "SSL object not available");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Set SNI hostname on SSL object */
    if (SSL_set_tlsext_host_name(ssl, hostname) != 1)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "Failed to set SNI hostname");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Enable automatic hostname checks */
    if (SSL_set1_host(ssl, hostname) != 1)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "Failed to enable hostname verification");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }
}

TLSHandshakeState
SocketTLS_handshake(Socket_T socket)
{
    SSL *ssl;
    int result;

    assert(socket);

    /* Check if TLS is enabled */
    if (!socket->tls_enabled)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "TLS not enabled on socket");
        RAISE_TLS_ERROR(SocketTLS_HandshakeFailed);
    }

    /* Check if handshake is already complete */
    if (socket->tls_handshake_done)
    {
        return TLS_HANDSHAKE_COMPLETE;
    }

    /* Get SSL object */
    ssl = socket_get_ssl(socket);
    if (!ssl)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "SSL object not available");
        RAISE_TLS_ERROR(SocketTLS_HandshakeFailed);
    }

    /* Perform handshake */
    result = SSL_do_handshake(ssl);

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
        TLSHandshakeState state = socket_handle_ssl_error(socket, ssl, result);
        
        if (state == TLS_HANDSHAKE_ERROR)
        {
            /* Fetch OpenSSL error details */
            unsigned long err = ERR_get_error();
            if (err) {
                char msg[SOCKET_TLS_OPENSSL_ERRSTR_BUFSIZE];
                ERR_error_string_n(err, msg, sizeof(msg));
                snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "Handshake failed: %s", msg);
            } else {
                snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "Handshake failed");
            }
            RAISE_TLS_ERROR(SocketTLS_HandshakeFailed);
        }

        socket->tls_last_handshake_state = state;  /* Store state for polling */
        return state;
    }
}

void
SocketTLS_shutdown(Socket_T socket)
{
    SSL *ssl;
    int result;

    assert(socket);

    /* Check if TLS is enabled */
    if (!socket->tls_enabled)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "TLS not enabled on socket");
        RAISE_TLS_ERROR(SocketTLS_ShutdownFailed);
    }

    /* Check if already shutdown */
    if (socket->tls_shutdown_done)
    {
        return; /* Already done */
    }

    /* Get SSL object */
    ssl = socket_get_ssl(socket);
    if (!ssl)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "SSL object not available");
        RAISE_TLS_ERROR(SocketTLS_ShutdownFailed);
    }

    /* Perform shutdown */
    result = SSL_shutdown(ssl);

    if (result == 1)
    {
        /* Shutdown completed successfully */
        socket->tls_shutdown_done = 1;
        socket_free_tls_resources(socket);
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
        TLSHandshakeState state = socket_handle_ssl_error(socket, ssl, result);
        if (state == TLS_HANDSHAKE_ERROR)
        {
            RAISE_TLS_ERROR(SocketTLS_ShutdownFailed);
        }
        /* WANT_READ/WRITE are expected during shutdown */
    }
}

#undef T

#endif /* SOCKET_HAS_TLS */