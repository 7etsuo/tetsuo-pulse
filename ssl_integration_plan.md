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

- [x] TLS context creation/destruction
- [x] Handshake (client/server)
- [x] Encrypted I/O operations
- [x] Error handling
- [x] Integration with SocketPoll
- [x] Integration with SocketPool

### Task 5.2: Integration tests

- [x] Full TLS client/server communication
- [x] Non-blocking handshake with SocketPoll
- [x] TLS with connection pooling
- [x] Certificate validation
- [x] ALPN negotiation

### Task 5.3: Documentation

- TLS module documentation
- API reference
- Usage examples
- Security best practices
- Performance considerations

---

## Implementation checklist

### Phase 0: Foundation
- [x] Add OpenSSL detection to CMakeLists.txt
- [x] Create SocketTLSConfig.h
- [x] Add ENABLE_TLS build option
- [x] Test build with/without TLS enabled

### Phase 1: Core infrastructure
- [x] Extend Socket_T structure with TLS fields
- [x] Create SocketTLS exception types
- [x] Implement socket_send_internal()
- [x] Implement socket_recv_internal()
- [x] Implement socket_sendv_internal()
- [x] Implement socket_recvv_internal()
- [x] Update Socket_send() to use abstraction
- [x] Update Socket_recv() to use abstraction
- [x] Update Socket_sendv() to use abstraction
- [x] Update Socket_recvv() to use abstraction

### Phase 2: TLS management
- [x] Implement SocketTLSContext_new_server()
- [x] Implement SocketTLSContext_new_client()
- [x] Implement certificate loading
- [x] Implement SocketTLS_enable()
- [x] Implement SocketTLS_handshake()
- [x] Implement SocketTLS_send()
- [x] Implement SocketTLS_recv()
- [x] Implement SocketTLS_shutdown()

### Phase 3: Integration
- [x] Update SocketPoll for TLS events
- [x] Update SocketAsync for TLS I/O
- [x] Handle sendfile() with TLS
- [x] Extend SocketPool Connection structure
- [x] Add TLS cleanup to SocketPool

### Phase 4: Advanced features
- [x] Implement SNI support
- [x] Implement ALPN support
- [ ] Add certificate verification callbacks
- [ ] Implement session resumption

### Phase 5: Testing
- [x] Unit tests for TLS context
- [x] Unit tests for TLS handshake
- [x] Unit tests for TLS I/O
- [x] Integration tests
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
