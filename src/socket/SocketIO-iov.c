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

/* Declare module-specific exception using centralized macros */
SOCKET_DECLARE_MODULE_EXCEPTION(SocketIO);

/* Macro to raise exception with detailed error message */
#define RAISE_MODULE_ERROR(e) SOCKET_RAISE_MODULE_ERROR(SocketIO, e)

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

#undef T
