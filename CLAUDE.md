# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Standard build
cmake -S . -B build
cmake --build build -j

# Run tests
cd build && ctest --output-on-failure

# Build with TLS support (auto-detects OpenSSL/LibreSSL)
cmake -S . -B build -DENABLE_TLS=ON

# Build with sanitizers (required for PRs)
cmake -S . -B build -DENABLE_SANITIZERS=ON
cd build && ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ctest --output-on-failure

# Build with fuzzing (requires Clang)
CC=clang cmake -S . -B build -DENABLE_FUZZING=ON

# Run single test
cd build && ./test_socket

# Generate documentation
cd build && make doc
```

## Build Options

| Option | Description |
|--------|-------------|
| `ENABLE_TLS` | Enable TLS/SSL support (default: ON) |
| `ENABLE_SANITIZERS` | Enable ASan + UBSan |
| `ENABLE_COVERAGE` | Enable gcov code coverage |
| `ENABLE_FUZZING` | Enable libFuzzer harnesses (requires Clang) |
| `BUILD_EXAMPLES` | Build example programs |

## Architecture Overview

This is a high-performance C socket library for POSIX systems with exception-based error handling.

### Module Organization

```
include/
├── core/       # Foundation: Arena (memory), Except (exceptions), utilities
├── socket/     # TCP/UDP/Unix sockets, buffers, async I/O, reconnection
├── dns/        # Async DNS resolution with thread pool
├── poll/       # Event polling (epoll/kqueue/poll backends)
├── pool/       # Connection pooling with rate limiting
├── tls/        # TLS/DTLS support (OpenSSL/LibreSSL)
├── http/       # HTTP/1.1, HTTP/2, HPACK, client/server APIs
└── test/       # Test framework

src/
├── core/       # Arena, Except, timers, rate limiting, crypto, UTF-8
├── socket/     # Socket ops, WebSocket (RFC 6455), proxy (SOCKS4/5, HTTP CONNECT)
├── dns/        # Async DNS internals
├── poll/       # Platform backends (SocketPoll_epoll.c, SocketPoll_kqueue.c)
├── pool/       # Connection pool, drain state machine
├── tls/        # TLS context, kTLS, DTLS, certificate pinning
├── http/       # HTTP parsing, HPACK codec, HTTP/2 framing
├── test/       # Test files (test_*.c)
└── fuzz/       # Fuzzing harnesses (fuzz_*.c)
```

### Key Design Patterns

**Exception-Based Error Handling**
```c
TRY {
    Socket_connect(socket, host, port);
} EXCEPT(Socket_Failed) {
    fprintf(stderr, "Error: %s\n", Socket_GetLastError());
} FINALLY {
    // Cleanup (always executed)
} END_TRY;
```

**Arena Memory Management** - Related objects share an arena for lifecycle management:
```c
Arena_T arena = Arena_new();
SocketPool_T pool = SocketPool_new(arena, maxconns, bufsize);
// Arena_dispose frees everything
```

**Opaque Types with T Macro Pattern**:
```c
#define T Socket_T
typedef struct T *T;
```

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Types | `ModuleName_T` | `Socket_T`, `Arena_T` |
| Public functions | `Module_Verb` | `Socket_bind`, `Arena_alloc` |
| Private functions | `lower_snake_case` | `socket_hash` |
| Constants | `MODULE_NAME` | `SOCKET_MAX_SIZE` |
| Exceptions | `Module_ErrorType` | `Socket_Failed` |

### Platform Backends

The poll backend is auto-selected at build time:
- **Linux**: epoll (`src/poll/SocketPoll_epoll.c`)
- **BSD/macOS**: kqueue (`src/poll/SocketPoll_kqueue.c`)
- **Fallback**: poll(2) (`src/poll/SocketPoll_poll.c`)

### Key Module Dependencies

```
Foundation (Arena, Except)
    └── Core I/O (Socket, SocketBuf, SocketDNS)
        └── Event System (SocketPoll, SocketTimer)
            └── Connection Mgmt (SocketPool, SocketReconnect)

Security (SocketTLS, SocketSYNProtect) requires Foundation + Core I/O
HTTP modules require Foundation + Core I/O + Security (optional)
```

## Code Style

- **C11 with GNU extensions** (`-D_GNU_SOURCE`)
- Compile with `-Wall -Wextra -Werror` (some warnings selectively disabled in CMakeLists.txt)
- Return type on separate line from function name
- Use `do { } while(0)` for multi-statement macros
- Include guards use `_INCLUDED` suffix: `#ifndef SOCKET_INCLUDED`
- Doxygen-style comments for public APIs

## Testing

All PRs must pass with sanitizers enabled:
```bash
cmake -B build -DENABLE_SANITIZERS=ON
cmake --build build -j
cd build && ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ctest --output-on-failure
```

Key test files map to modules:
- `test_socket` - TCP socket operations
- `test_socketdgram` - UDP sockets
- `test_socketpool` - Connection pooling
- `test_tls_integration` - TLS/SSL (when TLS enabled)
- `test_http2` - HTTP/2 protocol
- `test_websocket` - WebSocket (RFC 6455)

## Thread Safety

- Socket operations are thread-safe per socket (one thread per socket recommended)
- Error reporting uses thread-local storage
- Shared structures (SocketPoll, SocketPool) are mutex-protected
- DNS callbacks are invoked from worker threads, not main thread
