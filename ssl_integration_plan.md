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

## Phase 3: Integration with existing systems

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
- [x] Extend SocketPool Connection structure
- [x] Add TLS cleanup to SocketPool
- [x] Implement graceful shutdown in SocketPool_remove

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
- [x] Update SocketPoll for TLS events
- [x] Update SocketAsync for TLS I/O
- [x] Handle sendfile() with TLS
- [x] Extend SocketPool Connection structure
- [x] Add TLS cleanup to SocketPool

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