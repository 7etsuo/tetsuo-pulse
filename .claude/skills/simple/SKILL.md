---
name: simple
description: Implement functionality in the Simple API layer (src/simple/) by wrapping existing core library modules from include/. Use when working on SocketSimple-*.c files, implementing simple layer features, or when the user mentions the "simple layer" or "simple API".
---

You are an expert C developer working on the Simple API layer of a high-performance socket library. Your task is to implement functionality in `src/simple/` by wrapping the existing core library—NEVER by reimplementing low-level operations.

## Critical Constraint: No Reinventing the Wheel

The `include/` directory contains a comprehensive, battle-tested API. Before writing ANY code, you MUST search for existing functionality. The core library already provides:

### Foundation (`include/core/`)
- **Arena.h**: Memory management with `Arena_new()`, `Arena_alloc()`, `Arena_dispose()`
- **Except.h**: Exception handling with `TRY/EXCEPT/FINALLY/END_TRY`, `RAISE()`
- **SocketRetry.h**: Backoff strategies (exponential, jitter)
- **SocketRateLimit.h**: Token bucket rate limiting
- **SocketTimer.h**: Timer scheduling integrated with event loop
- **SocketMetrics.h**: Counters, gauges, histograms for observability
- **SocketUtil.h**: Hashing, logging, error utilities

### Networking (`include/socket/`)
- **Socket.h**: TCP with `Socket_connect_tcp()`, `Socket_listen_tcp()`, `Socket_accept()`, `Socket_send()`, `Socket_recv()`, `Socket_sendall()`, `Socket_recvall()`, `Socket_probe()`, `Socket_settimeout()`
- **SocketDgram.h**: UDP with `SocketDgram_bind_udp()`, `SocketDgram_sendto()`, `SocketDgram_recvfrom()`, multicast, broadcast
- **SocketBuf.h**: Circular buffers with `SocketBuf_read()`, `SocketBuf_write()`, `SocketBuf_readline()`, zero-copy access
- **SocketAsync.h**: Async I/O patterns
- **SocketProxy.h**: SOCKS4/5, HTTP CONNECT tunneling
- **SocketReconnect.h**: Auto-reconnection with circuit breaker
- **SocketHappyEyeballs.h**: RFC 8305 dual-stack connection racing

### DNS (`include/dns/`)
- **SocketDNS.h**: Async DNS with `SocketDNS_resolve_sync()`, `SocketDNS_resolve()` (async), caching, custom nameservers

### Events (`include/poll/`)
- **SocketPoll.h**: Cross-platform multiplexing (epoll/kqueue/poll) with `SocketPoll_add()`, `SocketPoll_wait()`, timer integration

### Pooling (`include/pool/`)
- **SocketPool.h**: Connection pooling with `SocketPool_add()`, `SocketPool_get()`, health checks, rate limiting, graceful drain
- **SocketPoolHealth.h**: Circuit breaker for connection validation

### Security (`include/tls/`)
- **SocketTLS.h**: TLS 1.2/1.3 with `SocketTLS_enable()`, `SocketTLS_handshake()`, `SocketTLS_send()`, `SocketTLS_recv()`, certificate pinning
- **SocketTLSContext.h**: Context management with `SocketTLSContext_new_client()`, `SocketTLSContext_new_server()`
- **SocketDTLS.h**: DTLS for encrypted UDP
- **SocketSYNProtect.h**: SYN flood protection

**Note**: The Simple API's global HTTP client uses HTTP/1.1 only for blocking simplicity. For HTTP/2, use `Socket_simple_http_new_ex()` or the full `SocketHTTPClient` API.

### HTTP (`include/http/`)
- **SocketHTTP.h**: Headers, URI parsing, status codes, content negotiation
- **SocketHTTP1.h**: HTTP/1.1 parser
- **SocketHTTP2.h**: HTTP/2 with multiplexing, server push
- **SocketHPACK.h**: Header compression
- **SocketHTTPClient.h**: High-level HTTP client with connection pooling
- **SocketHTTPServer.h**: HTTP server with routing

### WebSocket (`include/socket/`)
- **SocketWS.h**: RFC 6455 WebSocket protocol

## Simple Layer Architecture

The Simple layer (`src/simple/`) is a **thin synchronous wrapper** that:
1. Converts exception-based errors → return codes (-1, 0, NULL)
2. Provides thread-local error state via `simple_set_error()` / `Socket_simple_error()`
3. Wraps opaque handles with metadata in `struct SocketSimple_Socket`

### Required Pattern for Every Function

```c
Socket_simple_clear_error();

// Validate arguments
if (!valid_args) {
    simple_set_error(SOCKET_SIMPLE_ERR_INVALID_ARG, "message");
    return NULL;  // or -1
}

// Use volatile for variables modified in TRY block
volatile Socket_T sock = NULL;

TRY {
    sock = CoreLibrary_function(args);  // DELEGATE to core library
}
EXCEPT (SpecificException) {
    simple_set_error(SOCKET_SIMPLE_ERR_CODE, "message");
    if (sock) Socket_free((Socket_T *)&sock);
    return NULL;
}
END_TRY;

return simple_create_handle(sock, ...);
```

### Error Codes Available
SOCKET_SIMPLE_ERR_OK, _SOCKET, _CONNECT, _BIND, _LISTEN, _ACCEPT, _SEND, _RECV, _CLOSED, _TIMEOUT, _DNS, _TLS, _TLS_HANDSHAKE, _TLS_VERIFY, _HTTP, _HTTP_PARSE, _WS, _WS_PROTOCOL, _WS_CLOSED, _MEMORY, _INVALID_ARG, _UNSUPPORTED, _IO

## Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Types | `ModuleName_T` | `Socket_T`, `SocketPool_T` |
| Public functions | `Module_Verb` | `Socket_bind`, `SocketPool_add` |
| Simple functions | `Socket_simple_verb` | `Socket_simple_connect` |
| Exceptions | `Module_ErrorType` | `Socket_Failed`, `SocketTLS_Failed` |

## Before Implementing ANY Feature

1. **Search `include/`** for existing functionality
2. **Read the core implementation** in `src/` to understand the API
3. **Wrap, don't reimplement** — your job is translation, not duplication
4. **Use the exception types** that already exist (Socket_Failed, SocketTLS_Failed, etc.)
5. **Delegate I/O** to Socket_send/recv, SocketBuf, or protocol-specific functions

## Examples of WRONG vs RIGHT

WRONG: Implementing your own timeout loop with `select()`
RIGHT: Use `Socket_settimeout()` or `Socket_probe()` which already exist

WRONG: Parsing HTTP headers manually
RIGHT: Use `SocketHTTP_Headers_T` and `SocketHTTP_Headers_get()`

WRONG: Implementing TLS handshake logic
RIGHT: Use `SocketTLS_enable()` + `SocketTLS_handshake_auto()`

WRONG: Writing DNS resolution with `getaddrinfo()` directly
RIGHT: Use `SocketDNS_resolve_sync()` which handles caching and thread safety

WRONG: Managing connection lifecycle manually
RIGHT: Use `SocketPool_T` for pooled connections

## Files to Reference

**Existing Simple implementations** (follow these patterns):
- `src/simple/SocketSimple-tcp.c` — TCP/UDP wrapper
- `src/simple/SocketSimple-tls.c` — TLS client wrapper
- `src/simple/SocketSimple-dns.c` — DNS wrapper
- `src/simple/SocketSimple-http.c` — HTTP client wrapper

**Internal definitions**:
- `src/simple/SocketSimple-internal.h` — Error state, handle structs

**Outstanding work**:
- `src/simple/TODO.md` — Implementation roadmap

## Build & Test

```bash
cmake -S . -B build -DENABLE_TLS=ON -DENABLE_SANITIZERS=ON
cmake --build build -j
cd build && ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ctest --output-on-failure
```

Remember: The core library has been carefully designed and tested. Your role is to expose it through a simpler synchronous API—not to rebuild it.
