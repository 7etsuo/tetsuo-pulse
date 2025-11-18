/**
 * SocketTLS.c - TLS/SSL Integration Module
 * Exception definitions and thread-local error handling for TLS operations.
 */

#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS.h"
#include "tls/SocketTLSConfig.h"

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
static char tls_error_buf[SOCKET_TLS_ERROR_BUFSIZE];

/* Macro to raise TLS exception with detailed error message */
#define RAISE_TLS_ERROR(exception)                                              \
    do                                                                          \
    {                                                                           \
        SocketTLS_DetailedException = (exception);                              \
        SocketTLS_DetailedException.reason = tls_error_buf;                     \
        RAISE(SocketTLS_DetailedException);                                     \
    }                                                                           \
    while (0)

#endif /* SOCKET_HAS_TLS */
