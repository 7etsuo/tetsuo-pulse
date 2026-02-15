# GitHub Copilot Instructions for Socket Library

## Project Overview

This is a high-performance, exception-driven socket toolkit for POSIX systems written in C11. The library provides a clean, modern API for TCP, UDP, Unix domain sockets, HTTP/1.1, HTTP/2, QUIC, WebSocket, and TLS/DTLS with comprehensive error handling, zero-copy I/O, and cross-platform event polling.

**Maturity Notice**: This library is functional and well-tested but newly released. It is appropriate for development, internal tooling, and controlled environments.

## Architecture and Design Principles

### Core Components

- **Core Infrastructure**: Exception handling (TRY/EXCEPT/FINALLY), arena memory management, circular buffer I/O
- **Networking Stack**: TCP/UDP sockets, Unix domain sockets, TLS/DTLS, proxy support (SOCKS4/5, HTTP CONNECT)
- **HTTP Protocol**: HTTP/1.1, HTTP/2, HPACK, QPACK, client/server implementations
- **QUIC Transport**: RFC 9000 compliant QUIC v1 with connection management, stream multiplexing, loss detection
- **WebSocket**: RFC 6455 compliant with permessage-deflate compression
- **DNS Resolution**: Async resolver with DNS-over-TLS, DNS-over-HTTPS, DNSSEC validation
- **Event System**: Cross-platform polling (epoll/kqueue/poll), async I/O (io_uring/kqueue AIO), timer management
- **Security**: SYN flood protection, rate limiting, request smuggling prevention

### Platform Support

- **Primary**: Linux (epoll, io_uring), BSD/macOS (kqueue)
- **Fallback**: poll(2) for other POSIX systems
- **NOT Windows-compatible** without significant adaptation layer

## Coding Standards

### Language and Compiler

- **C Standard**: C11 with GNU extensions (`-std=gnu11`)
- **Required Features**: POSIX threads (pthread), IPv6 kernel support
- **Compiler Flags**: `-Wall -Wextra -Werror -fno-delete-null-pointer-checks -D_GNU_SOURCE -pthread -fno-strict-aliasing -fPIC`

### Code Style

- **Formatting**: Use `.clang-format` configuration in repository root
- **Naming Conventions**:
  - Types: `PascalCase_T` suffix (e.g., `Socket_T`, `SocketHE_Config_T`)
  - Functions: `Module_functionName` (e.g., `Socket_new`, `Socket_connect`)
  - Constants: `UPPER_SNAKE_CASE` (e.g., `SOCKET_MAX_CONNECTIONS`)
  - Variables: `snake_case` or `camelCase` depending on context
- **Header Guards**: `MODULENAME_INCLUDED` pattern
- **File Headers**: Include MIT license header with Tetsuo AI copyright

### Error Handling

**Primary Pattern**: Exception-based error handling using `TRY/EXCEPT/FINALLY` macros

```c
TRY
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_bind(server, NULL, 8080);
    Socket_listen(server, 128);
EXCEPT(Socket_Failed)
    fprintf(stderr, "Error: %s\n", Socket_GetLastError());
FINALLY
    Socket_free(&server);
END_TRY;
```

**Secondary Pattern**: Simple API with return codes for convenience (no TRY/EXCEPT needed)

```c
Socket_T sock = Socket_new_simple(AF_INET, SOCK_STREAM, 0);
if (!sock) {
    fprintf(stderr, "Failed to create socket\n");
    return -1;
}
```

**Important**: 
- Use exception handling for complex control flow
- Provide simple API alternatives where appropriate
- Always clean up resources in FINALLY blocks or with explicit `_free()` calls

### Memory Management

- **Arena Allocator**: Use `Arena_alloc()` for temporary allocations that share lifecycle
- **Manual Cleanup**: Use `_free()` functions (e.g., `Socket_free()`, `Arena_free()`)
- **No Dynamic Reallocation**: Avoid `realloc()` in hot paths; use fixed-size buffers or arenas
- **Overflow Protection**: Check bounds before allocation; arena allocator includes overflow detection

### Documentation

- **Doxygen**: All public APIs must have Doxygen comments
- **Format**:
  ```c
  /**
   * @brief Brief one-line description.
   * @ingroup group_name
   * @param[in] param1 Description of input parameter.
   * @param[out] param2 Description of output parameter.
   * @return Description of return value.
   * @threadsafe Yes/No.
   *
   * Detailed description with usage examples.
   *
   * ## Usage Example
   * @code{.c}
   * Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
   * Socket_bind(sock, NULL, 8080);
   * @endcode
   */
  ```
- **README Updates**: Update feature lists when adding significant functionality
- **RFC References**: Include RFC numbers for protocol implementations (e.g., "RFC 9113" for HTTP/2)

## Build System

### CMake Configuration

- **Minimum Version**: CMake 3.10+
- **Build Types**: Debug (default), Release
- **Options**:
  - `ENABLE_TLS=ON/OFF` - Enable TLS/SSL support (requires OpenSSL/LibreSSL)
  - `ENABLE_SANITIZERS=ON/OFF` - Enable ASan + UBSan
  - `ENABLE_ASAN=ON/OFF` - Enable AddressSanitizer only
  - `ENABLE_UBSAN=ON/OFF` - Enable UndefinedBehaviorSanitizer only
  - `ENABLE_TSAN=ON/OFF` - Enable ThreadSanitizer (incompatible with ASan)
  - `ENABLE_COVERAGE=ON/OFF` - Enable code coverage with gcov
  - `ENABLE_FUZZING=ON/OFF` - Enable libFuzzer harnesses (requires Clang)
  - `ENABLE_IO_URING=ON/OFF` - Enable io_uring backend (Linux only)
  - `PREFER_IO_URING_POLL=ON/OFF` - Use io_uring instead of epoll (Linux only)

### Build Commands

```bash
# Standard build
cmake -S . -B build
cmake --build build -j

# Build with TLS and tests
cmake -S . -B build -DENABLE_TLS=ON
cmake --build build -j
cd build && ctest --output-on-failure

# Build with sanitizers (for development)
cmake -S . -B build -DENABLE_SANITIZERS=ON
cmake --build build -j

# Fuzzing build (requires Clang)
cmake -S . -B build -DENABLE_FUZZING=ON -DCMAKE_C_COMPILER=clang
cmake --build build -j
```

### Dependencies

- **Required**: CMake, C11 compiler, pthread
- **Optional**: 
  - OpenSSL 1.1.1+ or LibreSSL (for TLS/DTLS)
  - zlib (for HTTP compression, WebSocket permessage-deflate)
  - Doxygen (for API documentation)
  - Python3 (for gRPC codegen tests)
  - liburing (for io_uring on Linux)

## Testing

### Test Framework

- **Framework**: Custom test framework in `include/test/Test.h`
- **Macros**: `TEST()`, `ASSERT_EQ()`, `ASSERT_TRUE()`, `ASSERT_FALSE()`, `ASSERT_STREQ()`
- **Location**: Tests in `tests/` directory, organized by module
- **CTest Integration**: All tests registered with CTest

### Test Structure

```c
#include "test/Test.h"
#include "socket/Socket.h"

TEST(socket_creation_basic)
{
    Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
    ASSERT_TRUE(sock != NULL);
    Socket_free(&sock);
}

TEST(socket_bind_valid_port)
{
    Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
    TRY
        Socket_setreuseaddr(sock);
        Socket_bind(sock, NULL, 8080);
        ASSERT_TRUE(1); // Success
    EXCEPT(Socket_Failed)
        ASSERT_TRUE(0); // Should not reach here
    END_TRY;
    Socket_free(&sock);
}
```

### Running Tests

```bash
# All tests
cd build && ctest --output-on-failure

# Specific test pattern
ctest -R "socket_.*" --output-on-failure

# Parallel execution
ctest --output-on-failure -j$(nproc)

# Verbose output
ctest -V
```

### Test Coverage

- **Target**: Aim for high coverage on new code
- **Tool**: gcov/lcov with `ENABLE_COVERAGE=ON`
- **CI Integration**: Coverage reports generated in CI pipeline

## Security Requirements

### Input Validation

- **Network Input**: All network data is untrusted; validate lengths, ranges, and formats
- **Buffer Sizes**: Check buffer bounds before reads/writes
- **Integer Overflow**: Validate arithmetic operations on size/length values
- **UTF-8 Validation**: Use DFA-based validator for text data (WebSocket, HTTP headers)

### Protocol Security

- **TLS 1.3**: Default to TLS 1.3; allow 1.2 only when explicitly configured
- **DTLS 1.2+**: Minimum DTLS 1.2 for secure UDP
- **HTTP**: Prevent request smuggling with strict RFC-compliant parsing
- **DNS**: Use DNSSEC validation where possible; support DNS-over-TLS/HTTPS

### Rate Limiting and DoS Protection

- **SYN Flood**: Reputation scoring, throttling, kernel integration
- **Per-IP Limits**: Connection limits and rate limiting per client IP
- **Token Bucket**: Rate limiting algorithm for connections and bandwidth

### Secure Coding Practices

- **No `strcpy`/`sprintf`**: Use `strncpy`, `snprintf`, or bounded string operations
- **Constant-Time Comparisons**: Use `CRYPTO_memcmp()` for secrets
- **Secure Random**: Use `CRYPTO_random_bytes()` for cryptographic operations
- **Sanitizers**: Test with ASan, UBSan before merging

## Common Patterns

### Socket Creation and Cleanup

```c
// Exception-based pattern
Socket_T sock = NULL;
TRY
    sock = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_connect(sock, "example.com", 443);
    // ... use socket ...
EXCEPT(Socket_Failed)
    fprintf(stderr, "Socket error: %s\n", Socket_GetLastError());
FINALLY
    Socket_free(&sock); // Safe even if NULL
END_TRY;

// Simple pattern (return codes)
Socket_T sock = Socket_new_simple(AF_INET, SOCK_STREAM, 0);
if (!sock) return -1;
if (Socket_connect_simple(sock, "example.com", 443) < 0) {
    Socket_free(&sock);
    return -1;
}
// ... use socket ...
Socket_free(&sock);
```

### Arena Memory Management

```c
Arena_T arena = Arena_new(4096); // 4KB chunks
TRY
    // Allocate temporary buffers
    char *buf1 = Arena_alloc(arena, 1024);
    char *buf2 = Arena_alloc(arena, 2048);
    // ... use buffers ...
FINALLY
    Arena_free(&arena); // Frees all allocations at once
END_TRY;
```

### Circular Buffer I/O

```c
SocketCB_T *cb = SocketCB_new(8192); // 8KB circular buffer
TRY
    // Write data
    SocketCB_write(cb, data, datalen);
    
    // Read data
    char output[1024];
    size_t n = SocketCB_read(cb, output, sizeof(output));
FINALLY
    SocketCB_free(&cb);
END_TRY;
```

### Event Loop Pattern

```c
SocketPoll_T *poll = SocketPoll_new(POLL_MODE_EDGE_TRIGGERED);
TRY
    // Add socket to poll set
    SocketPoll_add(poll, sock, POLL_EVENT_READ);
    
    // Event loop
    while (running) {
        SocketPollEvent_T events[64];
        int n = SocketPoll_wait(poll, events, 64, 1000); // 1s timeout
        for (int i = 0; i < n; i++) {
            if (events[i].events & POLL_EVENT_READ) {
                // Handle read event
            }
        }
    }
FINALLY
    SocketPoll_free(&poll);
END_TRY;
```

## Protocol Implementation Guidelines

### HTTP

- **Parsing**: Use table-driven DFA for performance and security
- **Headers**: Case-insensitive, handle multiple values (e.g., `Set-Cookie`)
- **Chunked Encoding**: Support both reading and writing
- **Keep-Alive**: Default for HTTP/1.1; close connection on error
- **Compression**: Support gzip, deflate for `Content-Encoding`

### HTTP/2

- **Framing**: Binary framing with 9-byte header + payload
- **Streams**: Multiplexing with flow control (per-stream and connection-level)
- **HPACK**: Header compression with dynamic table management
- **Server Push**: Optional; implement with `PUSH_PROMISE` frames

### QUIC

- **Connection IDs**: Support rotation for connection migration
- **0-RTT**: Support early data with replay protection
- **Loss Detection**: RFC 9002 congestion control and loss recovery
- **Crypto**: AEAD encryption (AES-GCM, ChaCha20-Poly1305)

### WebSocket

- **Framing**: Support fragmented messages and control frames
- **Masking**: Client-to-server messages must be masked
- **UTF-8**: Validate text frames with incremental DFA
- **Compression**: permessage-deflate extension (RFC 7692)

## Git Workflow

### Commit Messages

- Follow conventional commits format
- Prefix with module name when applicable: `socket:`, `http:`, `quic:`, `test:`
- Example: `http: Add support for HTTP/2 server push`

### Branch Naming

- Feature branches: `feature/description`
- Bug fixes: `bugfix/issue-number-description`
- Security fixes: `security/cve-number-or-description`

### Pull Requests

- **Title**: Clear, concise description of change
- **Description**: Include motivation, approach, testing performed
- **Tests**: All PRs must include tests unless documentation-only
- **CI**: Must pass all CI checks (build, tests, sanitizers)
- **Review**: At least one approving review required

## CI/CD Pipeline

### Continuous Integration

- **Matrix**: Debug and Release builds on Ubuntu
- **Sanitizers**: ASan, UBSan, TSan builds
- **Coverage**: Code coverage reports with gcov
- **Fuzzing**: Continuous fuzzing with libFuzzer (when enabled)
- **gRPC Conformance**: Interop matrix tests for gRPC implementation

### Workflow Files

- `.github/workflows/ci.yml` - Main CI pipeline
- Scripts in `scripts/` for corpus generation, fuzzing, etc.

## Performance Considerations

### Hot Paths

- **Avoid Allocations**: Use stack buffers or pre-allocated pools in hot paths
- **Zero-Copy**: Use `sendfile()`, scatter/gather I/O where possible
- **Edge-Triggered Events**: Prefer edge-triggered mode for epoll/kqueue
- **Async I/O**: Use io_uring (Linux) or kqueue AIO (BSD/macOS) for better performance

### Optimization

- **Compiler Flags**: `-O3` for release builds
- **Alignment**: Natural alignment for structs; use `__attribute__((aligned(N)))` for cache-line alignment
- **Branch Prediction**: Use `__builtin_expect()` for hot paths (`likely()`/`unlikely()` macros)
- **Profiling**: Use `perf` (Linux) or `Instruments` (macOS) for profiling

## Debugging

### Sanitizers

Always test with sanitizers before merging:

```bash
# Address + Undefined Behavior Sanitizers
cmake -S . -B build -DENABLE_SANITIZERS=ON
cmake --build build -j
cd build && ctest --output-on-failure

# Thread Sanitizer (separate build)
cmake -S . -B build-tsan -DENABLE_TSAN=ON
cmake --build build-tsan -j
cd build-tsan && ctest --output-on-failure
```

### Debugging Flags

- **Debug Build**: Use `-DCMAKE_BUILD_TYPE=Debug` for debug symbols
- **Verbose Logging**: Enable verbose logging in test code
- **Core Dumps**: `ulimit -c unlimited` to enable core dumps

### Common Issues

- **Segmentation Faults**: Check buffer overruns, null pointer dereferences; run with ASan
- **Memory Leaks**: Use ASan leak detector or Valgrind
- **Race Conditions**: Test with TSan; check thread-safety of shared state
- **Undefined Behavior**: Run with UBSan to catch integer overflow, alignment issues, etc.

## Additional Resources

- **README.md**: Comprehensive documentation with examples
- **Doxyfile**: Doxygen configuration for API documentation
- **examples/**: Reference implementations for common use cases
- **tests/**: Extensive test suite demonstrating API usage
- **RFC Documents**: `rfc/` directory contains relevant RFC specifications

## Code Review Checklist

When reviewing or generating code, ensure:

- [ ] Code follows project style guide (clang-format)
- [ ] All public functions have Doxygen documentation
- [ ] Error handling uses TRY/EXCEPT/FINALLY or proper return codes
- [ ] Resources are properly cleaned up (no leaks)
- [ ] Tests added for new functionality
- [ ] Security considerations addressed (input validation, bounds checking)
- [ ] Thread-safety documented and verified
- [ ] Platform compatibility considered (Linux/BSD/macOS)
- [ ] No compiler warnings with `-Wall -Wextra -Werror`
- [ ] Sanitizers pass (ASan, UBSan)
- [ ] Performance impact considered for hot paths

## Special Notes for AI Assistants

- **Exception Handling**: This library uses setjmp/longjmp-based exceptions; do not confuse with C++ exceptions
- **Type Suffixes**: Types ending in `_T` are opaque pointers (e.g., `Socket_T`, `Arena_T`)
- **Module Prefixes**: Function names are prefixed with module name (e.g., `Socket_`, `Arena_`, `SocketPoll_`)
- **Platform Macros**: Use `#ifdef __linux__`, `#ifdef __APPLE__`, `#ifdef __FreeBSD__` for platform-specific code
- **Feature Macros**: Check `SOCKET_HAS_TLS`, `SOCKET_HAS_IO_URING` before using optional features
- **Warning Suppression**: Some warnings are intentionally suppressed (see CMakeLists.txt); don't re-enable without justification
- **License**: All new files must include MIT license header with Tetsuo AI copyright
