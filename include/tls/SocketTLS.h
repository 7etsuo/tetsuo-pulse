#ifndef SOCKETTLS_INCLUDED
#define SOCKETTLS_INCLUDED

#include "core/Except.h"
#include "socket/Socket.h"

#ifdef SOCKET_HAS_TLS

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

#include "tls/SocketTLSContext.h"

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLS_INCLUDED */
