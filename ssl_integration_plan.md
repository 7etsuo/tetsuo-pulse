# SSL/TLS integration plan

## Overview

This plan prepares the library for SSL/TLS integration while preserving existing functionality. It addresses:
- Socket structure extension for SSL context
- I/O path abstraction for TLS routing
- Async helper integration
- Zero-copy feature handling
- Pool lifecycle management
- Exception and configuration infrastructure
- Build system updates

---

## Phase 0: Foundation and preparation (Week 1)

### Task 0.1: Build system SSL library detection

Objective: Add optional OpenSSL/LibreSSL detection to CMakeLists.txt

Changes to `CMakeLists.txt`:

```cmake
# After liburing detection (around line 119), add:

# Detect OpenSSL/LibreSSL for TLS support (optional)
set(SOCKET_HAS_TLS OFF)
set(OPENSSL_LIBRARIES "")
if(ENABLE_TLS)
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        set(SOCKET_HAS_TLS ON)
        set(OPENSSL_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)
        add_definitions(-DSOCKET_HAS_TLS)
        message(STATUS "OpenSSL found - TLS support enabled")
    else()
        # Try LibreSSL as fallback
        find_library(CRYPTO_LIB crypto)
        find_library(SSL_LIB ssl)
        if(CRYPTO_LIB AND SSL_LIB)
            set(SOCKET_HAS_TLS ON)
            set(OPENSSL_LIBRARIES ${SSL_LIB} ${CRYPTO_LIB})
            add_definitions(-DSOCKET_HAS_TLS)
            message(STATUS "LibreSSL found - TLS support enabled")
        else()
            message(WARNING "TLS requested but no SSL library found (OpenSSL/LibreSSL)")
        endif()
    endif()
else()
    message(STATUS "TLS support disabled (use -DENABLE_TLS=ON to enable)")
endif()

# Update library targets to link SSL when available
if(SOCKET_HAS_TLS)
    target_link_libraries(socket_static pthread ${LIBURING_LIBRARIES} ${OPENSSL_LIBRARIES})
    target_link_libraries(socket_shared pthread ${LIBURING_LIBRARIES} ${OPENSSL_LIBRARIES})
else()
    target_link_libraries(socket_static pthread ${LIBURING_LIBRARIES})
    target_link_libraries(socket_shared pthread ${LIBURING_LIBRARIES})
endif()
```

New files:
- `include/tls/SocketTLSConfig.h` - TLS configuration constants

### Task 0.2: TLS configuration header

Create `include/tls/SocketTLSConfig.h`:

```c
#ifndef SOCKETTLSCONFIG_INCLUDED
#define SOCKETTLSCONFIG_INCLUDED

#ifdef SOCKET_HAS_TLS

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* TLS protocol version configuration */
#define SOCKET_TLS_MIN_VERSION TLS1_2_VERSION
#define SOCKET_TLS_MAX_VERSION 0  /* 0 = use highest available */

/* TLS handshake timeout defaults */
#ifndef SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS
#define SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS 30000  /* 30 seconds */
#endif

/* TLS read/write buffer sizes */
#ifndef SOCKET_TLS_BUFFER_SIZE
#define SOCKET_TLS_BUFFER_SIZE 16384  /* 16KB - typical TLS record size */
#endif

/* Maximum certificate chain depth */
#ifndef SOCKET_TLS_MAX_CERT_CHAIN_DEPTH
#define SOCKET_TLS_MAX_CERT_CHAIN_DEPTH 10
#endif

/* ALPN protocol string limits */
#ifndef SOCKET_TLS_MAX_ALPN_LEN
#define SOCKET_TLS_MAX_ALPN_LEN 255
#endif

/* SNI hostname length limit */
#ifndef SOCKET_TLS_MAX_SNI_LEN
#define SOCKET_TLS_MAX_SNI_LEN 255
#endif

/* TLS session cache size (number of sessions) */
#ifndef SOCKET_TLS_SESSION_CACHE_SIZE
#define SOCKET_TLS_SESSION_CACHE_SIZE 1000
#endif

/* TLS error buffer size for detailed error messages */
#ifndef SOCKET_TLS_ERROR_BUFSIZE
#define SOCKET_TLS_ERROR_BUFSIZE 512
#endif

/* Forward declarations */
typedef struct SSL_CTX SSL_CTX;
typedef struct SSL SSL;
typedef struct X509 X509;
typedef struct X509_STORE X509_STORE;

#else /* SOCKET_HAS_TLS not defined */

/* Stub definitions when TLS is disabled */
typedef void SSL_CTX;
typedef void SSL;
typedef void X509;
typedef void X509_STORE;

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLSCONFIG_INCLUDED */
```

---

## Phase 1: Core infrastructure (Week 2)

### Task 1.1: Extend Socket_T structure

Objective: Add TLS state fields to socket structure without breaking existing code

Changes to `src/socket/Socket.c`:

```c
/* Add after line 122, before closing brace: */
struct T
{
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    char *peeraddr;
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
    char *tls_sni_hostname;     /* SNI hostname (allocated in arena) */
    void *tls_read_buf;         /* TLS read buffer (allocated in arena) */
    void *tls_write_buf;        /* TLS write buffer (allocated in arena) */
    size_t tls_read_buf_len;    /* Current read buffer length */
    size_t tls_write_buf_len;   /* Current write buffer length */
    SocketTimeouts_T tls_timeouts; /* TLS-specific timeouts */
#endif
};
```

### Task 1.2: TLS exception types

Create `include/tls/SocketTLS.h` (foundation):

```c
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

/* TLS handshake state */
typedef enum
{
    TLS_HANDSHAKE_NOT_STARTED = 0,
    TLS_HANDSHAKE_IN_PROGRESS = 1,
    TLS_HANDSHAKE_WANT_READ = 2,
    TLS_HANDSHAKE_WANT_WRITE = 3,
    TLS_HANDSHAKE_COMPLETE = 4,
    TLS_HANDSHAKE_ERROR = 5
} TLSHandshakeState;

/* TLS verification mode */
typedef enum
{
    TLS_VERIFY_NONE = 0,
    TLS_VERIFY_PEER = 1,
    TLS_VERIFY_FAIL_IF_NO_PEER_CERT = 2,
    TLS_VERIFY_CLIENT_ONCE = 4
} TLSVerifyMode;

/* Forward declaration - full definition in implementation */
struct SocketTLSContext_T;
typedef struct SocketTLSContext_T *SocketTLSContext_T;

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLS_INCLUDED */
```

Create `src/tls/SocketTLS.c` (exception definitions):

```c
#ifdef SOCKET_HAS_TLS

#include "tls/SocketTLS.h"

Except_T SocketTLS_Failed = {"TLS operation failed"};
Except_T SocketTLS_HandshakeFailed = {"TLS handshake failed"};
Except_T SocketTLS_VerifyFailed = {"TLS certificate verification failed"};
Except_T SocketTLS_ProtocolError = {"TLS protocol error"};
Except_T SocketTLS_ShutdownFailed = {"TLS shutdown failed"};

/* Thread-local exception for detailed TLS error messages */
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
        RAISE(SocketTLS_DetailedException);                                    \
    }                                                                           \
    while (0)

#endif /* SOCKET_HAS_TLS */
```

### Task 1.3: I/O abstraction layer

Objective: Create internal I/O dispatch functions that route through TLS when enabled

Create `include/socket/SocketIO.h` (internal header):

```c
#ifndef SOCKETIO_INCLUDED
#define SOCKETIO_INCLUDED

#include "socket/Socket.h"
#include <stddef.h>
#include <sys/uio.h>

/* Internal I/O abstraction - routes through TLS when enabled */

/**
 * socket_send_internal - Internal send operation (TLS-aware)
 * @socket: Socket instance
 * @buf: Data to send
 * @len: Length of data
 * @flags: Send flags (MSG_NOSIGNAL, etc.)
 * Returns: Bytes sent or 0 if would block
 * Raises: Socket_Failed or SocketTLS_Failed
 * 
 * Routes through SSL_write() if TLS is enabled, otherwise uses send()
 */
ssize_t socket_send_internal(T socket, const void *buf, size_t len, int flags);

/**
 * socket_recv_internal - Internal receive operation (TLS-aware)
 * @socket: Socket instance
 * @buf: Buffer for received data
 * @len: Buffer size
 * @flags: Receive flags
 * Returns: Bytes received or 0 if would block
 * Raises: Socket_Failed or SocketTLS_Failed
 * 
 * Routes through SSL_read() if TLS is enabled, otherwise uses recv()
 */
ssize_t socket_recv_internal(T socket, void *buf, size_t len, int flags);

/**
 * socket_sendv_internal - Internal scatter/gather send (TLS-aware)
 * @socket: Socket instance
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 * @flags: Send flags
 * Returns: Total bytes sent or 0 if would block
 * Raises: Socket_Failed or SocketTLS_Failed
 * 
 * For TLS: Converts iovec to single buffer, then calls SSL_write()
 * For non-TLS: Uses writev() directly
 */
ssize_t socket_sendv_internal(T socket, const struct iovec *iov, int iovcnt, int flags);

/**
 * socket_recvv_internal - Internal scatter/gather receive (TLS-aware)
 * @socket: Socket instance
 * @iov: Array of iovec structures
 * @iovcnt: Number of iovec structures
 * @flags: Receive flags
 * Returns: Total bytes received or 0 if would block
 * Raises: Socket_Failed or SocketTLS_Failed
 * 
 * For TLS: Uses SSL_read() into first buffer, then distributes
 * For non-TLS: Uses readv() directly
 */
ssize_t socket_recvv_internal(T socket, struct iovec *iov, int iovcnt, int flags);

/**
 * socket_is_tls_enabled - Check if TLS is enabled on socket
 * @socket: Socket instance
 * Returns: 1 if TLS is enabled, 0 otherwise
 */
int socket_is_tls_enabled(T socket);

/**
 * socket_tls_want_read - Check if TLS operation wants read
 * @socket: Socket instance
 * Returns: 1 if SSL_ERROR_WANT_READ, 0 otherwise
 * 
 * Used by SocketPoll to determine when to wait for read events
 */
int socket_tls_want_read(T socket);

/**
 * socket_tls_want_write - Check if TLS operation wants write
 * @socket: Socket instance
 * Returns: 1 if SSL_ERROR_WANT_WRITE, 0 otherwise
 * 
 * Used by SocketPoll to determine when to wait for write events
 */
int socket_tls_want_write(T socket);

#endif /* SOCKETIO_INCLUDED */
```

Create `src/socket/SocketIO.c` (implementation):

```c
#include "socket/SocketIO.h"
#include "socket/Socket.h"
#include "core/SocketError.h"
#include "core/SocketConfig.h"

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
            RAISE_SOCKET_ERROR(Socket_Failed);
        }
        
        /* Check if handshake is complete */
        if (!socket->tls_handshake_done)
        {
            SOCKET_ERROR_MSG("TLS handshake not complete");
            RAISE_SOCKET_ERROR(SocketTLS_HandshakeFailed);
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
    ssize_t result = send(socket->fd, buf, len, flags);
    
    if (result < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        if (errno == EPIPE)
            RAISE(Socket_Closed);
        if (errno == ECONNRESET)
            RAISE(Socket_Closed);
        SOCKET_ERROR_FMT("Send failed (len=%zu)", len);
        RAISE_SOCKET_ERROR(Socket_Failed);
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
            RAISE_SOCKET_ERROR(Socket_Failed);
        }
        
        /* Check if handshake is complete */
        if (!socket->tls_handshake_done)
        {
            SOCKET_ERROR_MSG("TLS handshake not complete");
            RAISE_SOCKET_ERROR(SocketTLS_HandshakeFailed);
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
    ssize_t result = recv(socket->fd, buf, len, flags);
    
    if (result < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        if (errno == ECONNRESET)
            RAISE(Socket_Closed);
        SOCKET_ERROR_FMT("Receive failed (len=%zu)", len);
        RAISE_SOCKET_ERROR(Socket_Failed);
    }
    else if (result == 0)
    {
        RAISE(Socket_Closed);
    }
    
    return result;
}

/* Similar implementations for socket_sendv_internal and socket_recvv_internal */
/* (Full implementations would convert iovec arrays appropriately) */

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
    /* Check last SSL error - would need to track this */
    return 0;  /* Placeholder - full implementation tracks SSL_ERROR_WANT_READ */
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
    /* Check last SSL error - would need to track this */
    return 0;  /* Placeholder - full implementation tracks SSL_ERROR_WANT_WRITE */
#else
    return 0;
#endif
}

#undef T
```

### Task 1.4: Update Socket_send/recv to use abstraction

Changes to `src/socket/Socket.c`:

```c
/* Replace Socket_send() implementation (around line 1176): */
ssize_t Socket_send(T socket, const void *buf, size_t len)
{
    return socket_send_internal(socket, buf, len, SOCKET_MSG_NOSIGNAL);
}

/* Replace Socket_recv() implementation (around line 1204): */
ssize_t Socket_recv(T socket, void *buf, size_t len)
{
    return socket_recv_internal(socket, buf, len, 0);
}
```

Add include at top of `Socket.c`:

```c
#include "socket/SocketIO.h"  /* Add after other includes */
```

---

## Phase 2: TLS context and socket management (Week 3)

### Task 2.1: TLS context module

Create `include/tls/SocketTLSContext.h`:

```c
#ifndef SOCKETTLSCONTEXT_INCLUDED
#define SOCKETTLSCONTEXT_INCLUDED

#include "core/Arena.h"
#include "core/Except.h"
#include "tls/SocketTLS.h"

#ifdef SOCKET_HAS_TLS

#define T SocketTLSContext_T
typedef struct T *T;

/* TLS context creation */
T SocketTLSContext_new_server(const char *cert_file, const char *key_file, const char *ca_file);
T SocketTLSContext_new_client(const char *ca_file);

/* Certificate management */
void SocketTLSContext_load_certificate(T ctx, const char *cert_file, const char *key_file);
void SocketTLSContext_load_ca(T ctx, const char *ca_file);
void SocketTLSContext_set_verify_mode(T ctx, TLSVerifyMode mode);

/* Protocol configuration */
void SocketTLSContext_set_min_protocol(T ctx, int version);
void SocketTLSContext_set_max_protocol(T ctx, int version);
void SocketTLSContext_set_cipher_list(T ctx, const char *ciphers);

/* ALPN support */
void SocketTLSContext_set_alpn_protos(T ctx, const char **protos, size_t count);

/* Session management */
void SocketTLSContext_enable_session_cache(T ctx);
void SocketTLSContext_set_session_cache_size(T ctx, size_t size);

/* Context lifecycle */
void SocketTLSContext_free(T *ctx);

/* Internal: Get SSL_CTX* (for implementation use) */
void *SocketTLSContext_get_ssl_ctx(T ctx);

#undef T

#endif /* SOCKET_HAS_TLS */

#endif /* SOCKETTLSCONTEXT_INCLUDED */
```

### Task 2.2: TLS socket wrapper functions

Extend `include/tls/SocketTLS.h`:

```c
/* Add after exception types: */

/* TLS socket operations */
void SocketTLS_enable(T socket, SocketTLSContext_T ctx);
void SocketTLS_set_hostname(T socket, const char *hostname);
TLSHandshakeState SocketTLS_handshake(T socket);
void SocketTLS_shutdown(T socket);

/* TLS I/O operations */
ssize_t SocketTLS_send(T socket, const void *buf, size_t len);
ssize_t SocketTLS_recv(T socket, void *buf, size_t len);

/* TLS information */
const char *SocketTLS_get_cipher(T socket);
const char *SocketTLS_get_version(T socket);
int SocketTLS_get_verify_result(T socket);
int SocketTLS_is_session_reused(T socket);
```

---

## Phase 3: Integration with existing systems (Week 4)

### Task 3.1: SocketPoll TLS integration

Changes to `src/poll/SocketPoll.c`:

```c
/* Add TLS-aware event mask updates in SocketPoll_wait() */
/* When TLS handshake is in progress, adjust event masks based on SSL_ERROR_WANT_* */

/* Helper function to update poll events based on TLS state */
static void socketpoll_update_tls_events(T poll, Socket_T socket)
{
#ifdef SOCKET_HAS_TLS
    if (socket_is_tls_enabled(socket))
    {
        unsigned events = 0;
        
        if (socket_tls_want_read(socket))
            events |= POLL_READ;
        if (socket_tls_want_write(socket))
            events |= POLL_WRITE;
        
        if (events != 0)
        {
            /* Get current user data */
            void *user_data = socket_data_get(poll, socket);
            SocketPoll_mod(poll, socket, events, user_data);
        }
    }
#endif
}
```

### Task 3.2: SocketAsync TLS integration

Changes to `src/socket/SocketAsync.c`:

```c
/* Replace direct send/recv calls (around line 651) with: */
if (type == REQ_SEND)
{
    result = socket_send_internal(socket, send_buf, len, MSG_NOSIGNAL);
    /* ... error handling ... */
}
else
{
    result = socket_recv_internal(socket, recv_buf, len, 0);
    /* ... error handling ... */
}
```

Add include:
```c
#include "socket/SocketIO.h"
```

### Task 3.3: Zero-copy feature handling

Changes to `src/socket/Socket.c` - `Socket_sendfile()`:

```c
ssize_t Socket_sendfile(T socket, int file_fd, off_t *offset, size_t count)
{
    assert(socket);
    assert(file_fd >= 0);
    assert(count > 0);

#ifdef SOCKET_HAS_TLS
    /* TLS cannot use kernel sendfile() - must use fallback */
    if (socket_is_tls_enabled(socket))
    {
        /* Force fallback to read/write loop */
        return socket_sendfile_fallback(socket, file_fd, offset, count);
    }
#endif

    /* Existing sendfile implementation for non-TLS */
    /* ... */
}
```

Add documentation warning:
```c
/**
 * Socket_sendfile - Zero-copy file-to-socket transfer
 * ...
 * Note: TLS-enabled sockets automatically use read/write fallback
 * since kernel sendfile() cannot encrypt data. Performance will be
 * reduced compared to non-TLS sockets.
 */
```

### Task 3.4: SocketPool TLS integration

Changes to `src/pool/SocketPool.c`:

```c
/* Extend Connection structure (around line 57): */
struct Connection
{
    Socket_T socket;
    SocketBuf_T inbuf;
    SocketBuf_T outbuf;
    void *data;
    time_t last_activity;
    int active;
    struct Connection *hash_next;
    
#ifdef SOCKET_HAS_TLS
    SocketTLSContext_T tls_ctx;  /* TLS context for this connection */
    int tls_handshake_complete;   /* TLS handshake state */
#endif
};
```

Add TLS cleanup in `SocketPool_remove()`:

```c
void SocketPool_remove(T pool, Socket_T socket)
{
    /* ... existing code ... */
    
#ifdef SOCKET_HAS_TLS
    /* Cleanup TLS state if present */
    if (conn->tls_ctx)
    {
        /* TLS shutdown should happen before socket close */
        if (socket_is_tls_enabled(socket))
        {
            SocketTLS_shutdown(socket);
        }
    }
#endif
    
    /* ... rest of cleanup ... */
}
```

---

## Phase 4: Advanced features (Week 5)

### Task 4.1: ALPN/SNI support

- Implement `SocketTLS_set_hostname()` for SNI
- Implement ALPN protocol negotiation
- Add callbacks for ALPN selection

### Task 4.2: Certificate verification

- Custom verification callbacks
- CRL support
- OCSP stapling (if supported by backend)

### Task 4.3: Session resumption

- Session caching
- Session tickets
- Integration with SocketPool for session reuse

---

## Phase 5: Testing and documentation (Week 6)

### Task 5.1: Unit tests

- TLS context creation/destruction
- Handshake (client/server)
- Encrypted I/O operations
- Error handling
- Integration with SocketPoll
- Integration with SocketPool

### Task 5.2: Integration tests

- Full TLS client/server communication
- Non-blocking handshake with SocketPoll
- TLS with connection pooling
- Certificate validation
- ALPN negotiation

### Task 5.3: Documentation

- TLS module documentation
- API reference
- Usage examples
- Security best practices
- Performance considerations

---

## Implementation checklist

### Phase 0: Foundation
- [ ] Add OpenSSL detection to CMakeLists.txt
- [ ] Create SocketTLSConfig.h
- [ ] Add ENABLE_TLS build option
- [ ] Test build with/without TLS enabled

### Phase 1: Core infrastructure
- [ ] Extend Socket_T structure with TLS fields
- [ ] Create SocketTLS exception types
- [ ] Implement socket_send_internal()
- [ ] Implement socket_recv_internal()
- [ ] Implement socket_sendv_internal()
- [ ] Implement socket_recvv_internal()
- [ ] Update Socket_send() to use abstraction
- [ ] Update Socket_recv() to use abstraction
- [ ] Update Socket_sendv() to use abstraction
- [ ] Update Socket_recvv() to use abstraction

### Phase 2: TLS management
- [ ] Implement SocketTLSContext_new_server()
- [ ] Implement SocketTLSContext_new_client()
- [ ] Implement certificate loading
- [ ] Implement SocketTLS_enable()
- [ ] Implement SocketTLS_handshake()
- [ ] Implement SocketTLS_send()
- [ ] Implement SocketTLS_recv()
- [ ] Implement SocketTLS_shutdown()

### Phase 3: Integration
- [ ] Update SocketPoll for TLS events
- [ ] Update SocketAsync for TLS I/O
- [ ] Handle sendfile() with TLS
- [ ] Extend SocketPool Connection structure
- [ ] Add TLS cleanup to SocketPool

### Phase 4: Advanced features
- [ ] Implement SNI support
- [ ] Implement ALPN support
- [ ] Add certificate verification callbacks
- [ ] Implement session resumption

### Phase 5: Testing
- [ ] Unit tests for TLS context
- [ ] Unit tests for TLS handshake
- [ ] Unit tests for TLS I/O
- [ ] Integration tests
- [ ] Performance benchmarks
- [ ] Documentation

---

## Design decisions

1. Opaque TLS pointers: Use `void *` in Socket_T to avoid exposing OpenSSL types
2. Arena allocation: TLS buffers allocated via socket arena
3. Backward compatibility: Non-TLS sockets continue to work unchanged
4. Optional compilation: TLS code gated by `#ifdef SOCKET_HAS_TLS`
5. Exception integration: TLS errors use existing exception system
6. Event loop integration: TLS handshake integrates with SocketPoll

---

## Estimated timeline

- Phase 0: 3-5 days
- Phase 1: 7-10 days
- Phase 2: 7-10 days
- Phase 3: 5-7 days
- Phase 4: 5-7 days
- Phase 5: 5-7 days

Total: 6-8 weeks for full implementation

---

## Success criteria

1. TLS can be enabled/disabled at compile time
2. TLS sockets integrate with SocketPoll
3. TLS sockets work with SocketPool
4. Zero-copy features degrade gracefully with TLS
5. All existing tests pass without TLS enabled
6. Comprehensive TLS test suite passes
7. Documentation is complete
8. Performance is acceptable (within 10-15% of OpenSSL baseline)

This plan prepares the library for SSL/TLS integration while maintaining backward compatibility and following existing architectural patterns.