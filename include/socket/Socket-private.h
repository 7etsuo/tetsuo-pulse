#ifndef SOCKET_PRIVATE_H_INCLUDED
#define SOCKET_PRIVATE_H_INCLUDED

#include "socket/Socket.h"
#include "core/Arena.h"
#include "core/SocketConfig.h"

/* Socket structure definition */
struct Socket_T
{
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    char *peeraddr; /* IPv4 or IPv6 address string */
    int peerport;
    char *localaddr;
    int localport;
    Arena_T arena;
    SocketTimeouts_T timeouts;

#ifdef SOCKET_HAS_TLS
    /* TLS-specific fields - allocated via arena when TLS is enabled */
    void *tls_ctx;              /* SSL_CTX* - opaque to avoid exposing OpenSSL */
    void *tls_ssl;              /* SSL* - opaque to avoid exposing OpenSSL */
    int tls_enabled;            /* Flag: 1 if TLS is active on this socket */
    int tls_handshake_done;     /* Flag: 1 if TLS handshake is complete */
    int tls_shutdown_done;      /* Flag: 1 if TLS shutdown is complete */
    int tls_last_handshake_state; /* Last TLSHandshakeState from handshake() */
    char *tls_sni_hostname;     /* SNI hostname (allocated in arena) */
    void *tls_read_buf;         /* TLS read buffer (allocated in arena) */
    void *tls_write_buf;        /* TLS write buffer (allocated in arena) */
    size_t tls_read_buf_len;    /* Current read buffer length */
    size_t tls_write_buf_len;   /* Current write buffer length */
    SocketTimeouts_T tls_timeouts; /* TLS-specific timeouts */
#endif
};

#endif /* SOCKET_PRIVATE_H_INCLUDED */

