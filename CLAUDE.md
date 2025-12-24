# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## MANDATORY: Git Workflow for Code Changes

**BEFORE making ANY code changes** (implement, add, fix, refactor, modify), you MUST:

1. **Invoke `/git-workflow`** to set up proper git workflow
2. The skill will ensure you're on a feature branch (not main)
3. Only proceed with code changes AFTER git workflow confirms setup

**This is NOT optional.** The git-safety-check hook will block commits to main.

### Quick Reference

| Action | Command |
|--------|---------|
| Start new work | `/git-workflow` → creates issue + branch |
| Commit changes | `/git-workflow` → proper commit format |
| Create PR | `/git-workflow` → PR with correct template |

### Branch Naming

- Features: `issue-<num>-<description>`
- Fixes: `issue-<num>-fix-<description>`

### Commit Format

```
<type>: <description>

<body>

Fixes #<issue>
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`

**IMPORTANT**: Do NOT add "Generated with Claude Code", "Co-Authored-By: Claude", or any AI attribution to commit messages. Keep commits clean and professional.

## Build Commands

```bash
# Standard build (Debug)
cmake -S . -B build
cmake --build build -j$(nproc)

# Release build (optimized)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# Run tests (parallel)
cd build && ctest -j$(nproc) --output-on-failure

# Build with TLS support (auto-detects OpenSSL/LibreSSL)
cmake -S . -B build -DENABLE_TLS=ON

# Build with sanitizers (required for PRs)
cmake -S . -B build -DENABLE_SANITIZERS=ON
cmake --build build -j$(nproc)
cd build && ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ctest -j$(nproc) --output-on-failure

# Build with fuzzing (requires Clang)
CC=clang cmake -S . -B build -DENABLE_FUZZING=ON
cmake --build build --target fuzzers -j$(nproc)  # Build ALL fuzzers
# Or build individual fuzzer:
cmake --build build --target fuzz_socketbuf -j$(nproc)

# Build with io_uring (Linux only, requires liburing-dev)
cmake -S . -B build -DENABLE_IO_URING=ON

# Run single test
cd build && ./test_socket

# Run fuzzers (after ENABLE_FUZZING build)
cd build && ./fuzz_socketbuf corpus/socketbuf/ -fork=16 -max_len=4096

# List all available fuzzers (~130 harnesses)
ls build/fuzz_*

# Generate documentation
cd build && make -j$(nproc) doc
```

## Build Options

| Option | Description |
|--------|-------------|
| `ENABLE_TLS` | Enable TLS/SSL support (default: ON) |
| `ENABLE_SANITIZERS` | Enable ASan + UBSan |
| `ENABLE_TSAN` | Enable ThreadSanitizer (incompatible with ASan) |
| `ENABLE_COVERAGE` | Enable gcov code coverage |
| `ENABLE_FUZZING` | Enable libFuzzer harnesses (requires Clang) |
| `ENABLE_IO_URING` | Enable io_uring async I/O backend (Linux 5.1+, requires liburing) |
| `ENABLE_HTTP_COMPRESSION` | Enable gzip/deflate/brotli for HTTP |
| `BUILD_EXAMPLES` | Build example programs |

## Architecture Overview

This is a high-performance C socket library for POSIX systems with two API styles:
1. **Exception-based API** - Uses `TRY/EXCEPT/FINALLY` blocks for clean error propagation
2. **Simple API** - Return-code based convenience layer (no exceptions needed)

### Module Organization

```
include/
├── core/       # Foundation: Arena (memory), Except (exceptions), utilities
├── socket/     # TCP/UDP/Unix sockets, buffers, async I/O, reconnection
├── dns/        # Async DNS resolver (RFC 1035), DoT (RFC 7858), DoH (RFC 8484), DNSSEC (RFC 4033-4035)
├── poll/       # Event polling (epoll/kqueue/poll backends)
├── pool/       # Connection pooling with rate limiting
├── tls/        # TLS/DTLS support (OpenSSL/LibreSSL)
├── http/       # HTTP/1.1, HTTP/2, HPACK, client/server APIs
├── simple/     # Return-code based convenience API (no TRY/EXCEPT)
└── test/       # Test framework

src/
├── core/       # Arena, Except, timers, rate limiting, crypto, UTF-8
├── socket/     # Socket ops, WebSocket (RFC 6455), proxy (SOCKS4/5, HTTP CONNECT)
├── dns/        # Wire format, transport (UDP/TCP/DoT/DoH), cache, resolver, DNSSEC, cookies
├── poll/       # Platform backends (SocketPoll_epoll.c, SocketPoll_kqueue.c)
├── pool/       # Connection pool, drain state machine
├── tls/        # TLS context, kTLS, DTLS, certificate pinning
├── http/       # HTTP parsing, HPACK codec, HTTP/2 framing
├── simple/     # Simple API implementation wrapping core modules
├── test/       # Test files (test_*.c)
└── fuzz/       # Fuzzing harnesses (fuzz_*.c)
```

### Key Design Patterns

**Exception-Based Error Handling** - Variables modified in TRY blocks must be `volatile`:
```c
volatile int result = 0;
TRY {
    Socket_connect(socket, host, port);
    result = 1;
} EXCEPT(Socket_Failed) {
    fprintf(stderr, "Error: %s\n", Socket_GetLastError());
} FINALLY {
    // Cleanup (always executed, even on RERAISE)
} END_TRY;
```

**Simple API Alternative** - Return codes instead of exceptions:
```c
SocketSimple_Socket_T sock = Socket_simple_connect("example.com", 80);
if (!sock) {
    fprintf(stderr, "Error: %s\n", Socket_simple_error());
    return -1;
}
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
- **Linux (optional)**: io_uring for async I/O (`-DENABLE_IO_URING=ON`, requires kernel 5.1+)
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

## Automated Hooks

The project uses Claude Code hooks (`.claude/settings.json`) that run automatically:

| Hook | Trigger | Action |
|------|---------|--------|
| `git-safety-check.sh` | Before `git` commands | Blocks commits to main, force push to main |
| `pre-commit-sanitizer.sh` | Before `git commit` | Runs full test suite with ASan/UBSan |
| `volatile-check.sh` | After C file edits | Warns about exception safety issues |
| `build-check.sh` | After C file edits | Quick syntax check with gcc |

These hooks enforce the git workflow and catch common issues early.

## Testing

All PRs must pass with sanitizers enabled:
```bash
cmake -B build -DENABLE_SANITIZERS=ON
cmake --build build -j$(nproc)
cd build && ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ctest -j$(nproc) --output-on-failure

# Run a single test by name
cd build && ./test_socket

# Run with verbose output
cd build && ctest -V -R test_socket

# List all available tests
cd build && ctest -N
```

Test files are in `src/test/` and map to modules:
- `test_socket.c` - TCP socket operations
- `test_socketdgram.c` - UDP sockets
- `test_socketpool.c` - Connection pooling
- `test_tls_*.c` - TLS/SSL tests (integration, handshake, pinning, CRL, OCSP, kTLS, etc.)
- `test_dtls_*.c` - DTLS tests (basic, cookie exchange, MTU, integration)
- `test_http*.c` - HTTP/1.1 parser, HTTP/2, HPACK, client, server
- `test_websocket*.c` - WebSocket (RFC 6455), WebSocket-over-HTTP/2
- `test_proxy*.c` - SOCKS4/5, HTTP CONNECT proxy
- `test_dns_*.c` - DNS wire format, cache, transport, resolver, DoT, DoH, DNSSEC, cookies
- `test_except.c` - Exception handling framework
- `test_arena.c` - Memory arena management
- `test_async*.c` - Async I/O and io_uring tests

## Thread Safety

- Socket operations are thread-safe per socket (one thread per socket recommended)
- Error reporting uses thread-local storage (`__thread` / `__declspec(thread)`)
- Shared structures (SocketPoll, SocketPool) are mutex-protected
- DNS callbacks are invoked from worker threads, not main thread
- Exception stack (`Except_stack`) is thread-local - each thread has independent TRY context

## Exception Safety

When writing code with `TRY/EXCEPT/FINALLY`:
- Use `volatile` for variables modified inside TRY that are read after exception
- Use `RETURN` macro (not bare `return`) to properly unwind exception stack
- `FINALLY` always executes, even after `RERAISE`
- Avoid raising exceptions inside `FINALLY` blocks
- Use `RERAISE` to propagate caught exceptions to outer handlers

## DNS Module Features

The DNS module (`include/dns/`, `src/dns/`) provides comprehensive DNS resolution:

### Core Resolution (RFC 1035)
- Async resolver with query multiplexing
- UDP and TCP transport with automatic fallback
- Response caching with TTL support
- `/etc/resolv.conf` parsing

### Encrypted DNS
- **DNS-over-TLS (DoT)** - RFC 7858, RFC 8310 (opportunistic/strict modes)
- **DNS-over-HTTPS (DoH)** - RFC 8484 (POST/GET methods)

### Security Features
- **DNSSEC Validation** - RFC 4033, 4034, 4035 (chain of trust, NSEC/NSEC3)
- **DNS Cookies** - RFC 7873 (spoofing protection via EDNS0 option 10)
- **Extended DNS Errors** - RFC 8914 (25 detailed error codes via EDNS0 option 15)
- **Negative Caching** - RFC 2308 (proper NXDOMAIN/NODATA key tuples)
- **Dead Server Tracking** - RFC 2308 §7.2 (5-minute blacklist for unresponsive servers)

### EDNS0 Support (RFC 6891)
- OPT record validation (§6.1.1)
- Version negotiation and BADVERS handling (§6.1.3)
- UDP payload size fallback (§6.2.5)
- Option parsing framework for extensions

## io_uring Support (Linux 5.1+)

The async I/O module supports io_uring for high-performance networking:

### Build
```bash
cmake -S . -B build -DENABLE_IO_URING=ON
```

### Features
- **SQPOLL mode** - Kernel-side submission thread for reduced syscalls
- **Registered buffers** - Zero-copy I/O with fixed buffer sets
- **Batch submissions** - Amortize submission overhead across multiple ops
- **Poll integration** - Automatic eventfd integration with SocketPoll for timers
- **Graceful fallback** - Transparent degradation on unsupported systems

### Usage Pattern
```c
SocketAsync_T async = SocketAsync_new(arena, 256);
SocketAsync_enable_sqpoll(async);  /* Enable SQPOLL if available */

/* Batch multiple operations */
SocketAsync_send(async, sock1, data1, len1, 0, cb1, ud1);
SocketAsync_send(async, sock2, data2, len2, 0, cb2, ud2);
SocketAsync_submit_batch(async);  /* Submit all at once */
```

## GitHub CLI Workaround

The `gh issue view` command may fail with a GraphQL error about "Projects (classic)" deprecation:
```
GraphQL: Projects (classic) is being deprecated in favor of the new Projects experience
```

**Workaround**: Use `gh issue list --search` instead:
```bash
# Instead of: gh issue view 141 --repo 7etsuo/tetsuo-socket
# Use:
gh issue list --repo 7etsuo/tetsuo-socket --state all --search "141" --limit 5

# Or search by keyword:
gh issue list --repo 7etsuo/tetsuo-socket --state all --search "fuzz" --limit 20
```
