/**
 * SocketTLS.c - TLS/SSL Integration Module
 * Exception definitions and thread-local error handling for TLS operations.
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"
#include <assert.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

Except_T SocketTLS_Failed = {"TLS operation failed"};
Except_T SocketTLS_HandshakeFailed = {"TLS handshake failed"};
Except_T SocketTLS_VerifyFailed = {"TLS certificate verification failed"};
Except_T SocketTLS_ProtocolError = {"TLS protocol error"};
Except_T SocketTLS_ShutdownFailed = {"TLS shutdown failed"};

/* Thread-local exception for detailed TLS error messages
 * Prevents race conditions when multiple threads raise same exception. */
#ifdef _WIN32
static __declspec(thread) Except_T SocketTLS_DetailedException;
#else
static __thread Except_T SocketTLS_DetailedException;
#endif

/* TLS error buffer for detailed error messages */
#ifdef _WIN32
__declspec(thread) char tls_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
#else
__thread char tls_error_buf[SOCKET_TLS_ERROR_BUFSIZE];
#endif

/* Macro to raise TLS exception with detailed error message */
#define RAISE_TLS_ERROR(exception)                                              \
    do                                                                          \
    {                                                                           \
        SocketTLS_DetailedException = (exception);                              \
        SocketTLS_DetailedException.reason = tls_error_buf;                     \
        RAISE(SocketTLS_DetailedException);                                     \
    }                                                                           \
    while (0)

/* Static helper functions */

/**
 * socket_get_ssl - Get SSL* from socket
 * @socket: Socket instance
 * Returns: SSL* pointer or NULL if not available
 */
static SSL *socket_get_ssl(Socket_T socket)
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
static TLSHandshakeState socket_handle_ssl_error(Socket_T socket, SSL *ssl, int ssl_result)
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
 * socket_allocate_tls_buffers - Allocate TLS read/write buffers
 * @socket: Socket instance
 * Allocates buffers from socket arena for TLS operations
 */
static void socket_allocate_tls_buffers(Socket_T socket)
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

/**
 * socket_free_tls_resources - Cleanup TLS resources
 * @socket: Socket instance
 * Frees SSL object and clears TLS state
 */
static void socket_free_tls_resources(Socket_T socket)
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
void SocketTLS_enable(Socket_T socket, SocketTLSContext_T ctx)
{
    SSL *ssl;
    int fd;

    assert(socket);
    assert(ctx);
    assert(ctx->ssl_ctx);

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
    ssl = SSL_new(ctx->ssl_ctx);
    if (!ssl)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "Failed to create SSL object");
        RAISE_TLS_ERROR(SocketTLS_Failed);
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
void SocketTLS_set_hostname(Socket_T socket, const char *hostname)
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
    if (hostname_len == 0 || hostname_len > 253) /* RFC 1035 limit */
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

    /* Copy hostname */
    strcpy((char *)socket->tls_sni_hostname, hostname);

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
}

/**
 * SocketTLS_handshake - Perform TLS handshake
 * @socket: Socket instance
 *
 * Performs the TLS handshake on the socket. This function should be called
 * after enabling TLS and setting any required parameters (like hostname).
 * May need to be called multiple times if SSL_ERROR_WANT_READ/WRITE is returned.
 *
 * Returns: TLSHandshakeState indicating handshake progress or completion
 * Raises: SocketTLS_HandshakeFailed on fatal errors
 * Thread-safe: No (modifies socket state)
 */
TLSHandshakeState SocketTLS_handshake(Socket_T socket)
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
        socket->tls_last_handshake_state = state;  /* Store state for polling */
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
void SocketTLS_shutdown(Socket_T socket)
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
ssize_t SocketTLS_send(Socket_T socket, const void *buf, size_t len)
{
    SSL *ssl;
    int result;

    assert(socket);
    assert(buf);
    assert(len > 0);

    /* Check if TLS is enabled */
    if (!socket->tls_enabled)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "TLS not enabled on socket");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Check if handshake is complete */
    if (!socket->tls_handshake_done)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "TLS handshake not complete");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Get SSL object */
    ssl = socket_get_ssl(socket);
    if (!ssl)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "SSL object not available");
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
ssize_t SocketTLS_recv(Socket_T socket, void *buf, size_t len)
{
    SSL *ssl;
    int result;

    assert(socket);
    assert(buf);
    assert(len > 0);

    /* Check if TLS is enabled */
    if (!socket->tls_enabled)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "TLS not enabled on socket");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Check if handshake is complete */
    if (!socket->tls_handshake_done)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "TLS handshake not complete");
        RAISE_TLS_ERROR(SocketTLS_Failed);
    }

    /* Get SSL object */
    ssl = socket_get_ssl(socket);
    if (!ssl)
    {
        snprintf(tls_error_buf, SOCKET_TLS_ERROR_BUFSIZE, "SSL object not available");
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
}

/**
 * SocketTLS_get_cipher - Get the cipher suite used for the TLS connection
 * @socket: Socket instance
 *
 * Returns the name of the cipher suite negotiated for this TLS connection.
 * The handshake must be complete for this information to be available.
 *
 * Returns: Cipher suite name string, or NULL if not available
 * Thread-safe: No (reads socket state)
 */
const char *SocketTLS_get_cipher(Socket_T socket)
{
    SSL *ssl;
    const SSL_CIPHER *cipher;

    assert(socket);

    /* Check if TLS is enabled */
    if (!socket->tls_enabled)
    {
        return NULL;
    }

    /* Get SSL object */
    ssl = socket_get_ssl(socket);
    if (!ssl)
    {
        return NULL;
    }

    /* Get cipher information */
    cipher = SSL_get_current_cipher(ssl);
    if (!cipher)
    {
        return NULL;
    }

    return SSL_CIPHER_get_name(cipher);
}

/**
 * SocketTLS_get_version - Get the TLS protocol version used for the connection
 * @socket: Socket instance
 *
 * Returns the TLS protocol version string (e.g., "TLSv1.2", "TLSv1.3").
 * The handshake must be complete for this information to be available.
 *
 * Returns: TLS version string, or NULL if not available
 * Thread-safe: No (reads socket state)
 */
const char *SocketTLS_get_version(Socket_T socket)
{
    SSL *ssl;

    assert(socket);

    /* Check if TLS is enabled */
    if (!socket->tls_enabled)
    {
        return NULL;
    }

    /* Get SSL object */
    ssl = socket_get_ssl(socket);
    if (!ssl)
    {
        return NULL;
    }

    /* Get version information */
    return SSL_get_version(ssl);
}

/**
 * SocketTLS_get_verify_result - Get the certificate verification result
 * @socket: Socket instance
 *
 * Returns the result of certificate verification as defined by OpenSSL's
 * X509_V_* constants. X509_V_OK (0) means verification succeeded.
 * The handshake must be complete for this information to be available.
 *
 * Returns: Verification result code (X509_V_OK on success)
 * Thread-safe: No (reads socket state)
 */
int SocketTLS_get_verify_result(Socket_T socket)
{
    SSL *ssl;

    assert(socket);

    /* Check if TLS is enabled */
    if (!socket->tls_enabled)
    {
        return -1; /* Not applicable */
    }

    /* Get SSL object */
    ssl = socket_get_ssl(socket);
    if (!ssl)
    {
        return -1; /* Not available */
    }

    /* Get verification result */
    return SSL_get_verify_result(ssl);
}

/**
 * SocketTLS_is_session_reused - Check if the TLS session was reused
 * @socket: Socket instance
 *
 * Returns 1 if the current TLS session was resumed from a previous session
 * (session reuse), 0 if it's a new session. Session reuse improves performance
 * by avoiding full handshakes. The handshake must be complete for this
 * information to be available.
 *
 * Returns: 1 if session was reused, 0 if new session, -1 if not available
 * Thread-safe: No (reads socket state)
 */
int SocketTLS_is_session_reused(Socket_T socket)
{
    SSL *ssl;

    assert(socket);

    /* Check if TLS is enabled */
    if (!socket->tls_enabled)
    {
        return -1; /* Not applicable */
    }

    /* Get SSL object */
    ssl = socket_get_ssl(socket);
    if (!ssl)
    {
        return -1; /* Not available */
    }

    /* Check if session was reused */
    return SSL_session_reused(ssl) ? 1 : 0;
}

#endif /* SOCKET_HAS_TLS */
