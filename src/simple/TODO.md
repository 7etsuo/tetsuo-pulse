# Simple API Implementation Status

## Completed Modules

- [x] **TCP/UDP** (`SocketSimple-tcp.h`) - Client, server, UDP send/recv
- [x] **TLS** (`SocketSimple-tls.h`) - TLS client and server
- [x] **DNS** (`SocketSimple-dns.h`) - Blocking DNS resolution
- [x] **HTTP** (`SocketSimple-http.h`) - HTTP client (GET/POST/PUT/DELETE)
- [x] **WebSocket** (`SocketSimple-ws.h`) - WebSocket client

## Completed Modules (continued)

### Phase 1: Foundation

- [x] **Pool** (`SocketSimple-pool.h`)
  - Connection pooling with rate limiting
  - Per-IP connection limits
  - Graceful shutdown (drain)
  - Pool statistics

- [x] **Poll** (`SocketSimple-poll.h`)
  - Event-driven I/O (epoll/kqueue/poll wrapper)
  - Socket registration and event waiting
  - Cross-platform backend abstraction

- [x] **Rate Limiting** (`SocketSimple-ratelimit.h`)
  - Token bucket rate limiter
  - Non-blocking and blocking acquire

### Phase 2: Networking

- [x] **Proxy** (`SocketSimple-proxy.h`)
  - SOCKS4/4a/5 support
  - HTTP CONNECT tunneling
  - Proxy URL parsing

## Completed Modules (continued)

### Phase 3: Application

- [x] **HTTP Server** (`SocketSimple-http-server.h`)
  - Request/response handling
  - Streaming responses
  - Graceful shutdown (drain)
  - Statistics and connection tracking

### Phase 4: Extensions

- [ ] **WebSocket Server** (`SocketSimple-ws.h`) - *Partially implemented*
  - [x] Server config (max frame/message size, UTF-8 validation)
  - [x] `Socket_simple_ws_is_upgrade()` - Detect upgrade requests
  - [ ] `Socket_simple_ws_accept()` - Accept from HTTP server request (TODO)
  - [ ] `Socket_simple_ws_accept_raw()` - Accept on raw sockets (TODO)
  - [ ] `Socket_simple_ws_reject()` - Reject upgrade (TODO)

- [x] **Security** (`SocketSimple-security.h`)
  - SYN flood protection with reputation system
  - IP tracking with per-IP connection limits
  - Whitelist/blacklist management
  - Statistics and cleanup

- [x] **Async DNS** (`SocketSimple-dns.h`)
  - Non-blocking DNS with callbacks
  - Polling mode for event loop integration
  - DNS cache control

## Implementation Notes

All modules follow these conventions:
- Opaque types: `SocketSimple_Module_T`
- Concrete structs: `SocketSimple_StructName` (no `_T`)
- Functions: `Socket_simple_module_verb()`
- Cleanup: `Socket_simple_module_free(Type *handle)` sets handle to NULL
- Errors: NULL/-1 on failure, use `Socket_simple_error()` for message
