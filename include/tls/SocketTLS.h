#ifndef SOCKETTLS_INCLUDED
#define SOCKETTLS_INCLUDED

#include "core/Except.h"
#include "socket/Socket.h"

#ifdef SOCKET_HAS_TLS

/* TLS error buffer for cross-module error reporting */
#ifdef _WIN32
extern __declspec(thread) char tls_error_buf[];
#else
extern __thread char tls_error_buf[];
#endif

#define T SocketTLS_T
typedef struct T *T;

/* TLS-specific exception types */
extern Except_T SocketTLS_Failed;              /* General TLS operation failure */
extern Except_T SocketTLS_HandshakeFailed;     /* TLS handshake failure */
extern Except_T SocketTLS_VerifyFailed;        /* Certificate verification failure */
extern Except_T SocketTLS_ProtocolError;       /* TLS protocol error */
extern Except_T SocketTLS_ShutdownFailed;      /* TLS shutdown failure */

/* TLS handshake state (for polling/integration) */
typedef enum {
    TLS_HANDSHAKE_NOT_STARTED = 0,
    TLS_HANDSHAKE_IN_PROGRESS = 1,
    TLS_HANDSHAKE_WANT_READ = 2,
    TLS_HANDSHAKE_WANT_WRITE = 3,
    TLS_HANDSHAKE_COMPLETE = 4,
    TLS_HANDSHAKE_ERROR = 5
} TLSHandshakeState;

/* TLS verification mode */
typedef enum {
    TLS_VERIFY_NONE = 0,
    TLS_VERIFY_PEER = 1,
    TLS_VERIFY_FAIL_IF_NO_PEER_CERT = 2,
    TLS_VERIFY_CLIENT_ONCE = 4
} TLSVerifyMode;

/* Forward declaration to avoid circular dependency */
typedef struct SocketTLSContext_T *SocketTLSContext_T;

/* TLS socket operations */
void SocketTLS_enable(Socket_T socket, SocketTLSContext_T ctx);
void SocketTLS_set_hostname(Socket_T socket, const char *hostname);
TLSHandshakeState SocketTLS_handshake(Socket_T socket);
void SocketTLS_shutdown(Socket_T socket);

/* TLS I/O operations */
ssize_t SocketTLS_send(Socket_T socket, const void *buf, size_t len);
ssize_t SocketTLS_recv(Socket_T socket, void *buf, size_t len);

/* TLS information */
const char *SocketTLS_get_cipher(Socket_T socket);
const char *SocketTLS_get_version(Socket_T socket);
int SocketTLS_get_verify_result(Socket_T socket);
int SocketTLS_is_session_reused(Socket_T socket);

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLS_INCLUDED */
