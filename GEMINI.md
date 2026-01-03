# tetsuo-socket

## Project Overview

`tetsuo-socket` is a high-performance, exception-driven socket toolkit for POSIX systems (Linux, BSD, macOS). It provides a clean, modern C API for network programming, supporting TCP, UDP, Unix domain sockets, HTTP/1.1, HTTP/2, WebSockets, and TLS/DTLS.

**Key Architectures:**
*   **Exception Handling:** Uses `TRY/EXCEPT/FINALLY` macros for clean error propagation, with an optional "Simple API" layer for return-code based usage.
*   **Event Loop:** Cross-platform polling abstraction (epoll on Linux, kqueue on BSD/macOS, poll fallback) and support for `io_uring` on Linux.
*   **Memory Management:** Arena-based allocation for efficiency and overflow protection.
*   **Zero-Copy I/O:** Circular buffers, scatter/gather I/O, and platform optimizations (sendfile, splice).

## Building and Running

The project uses **CMake**.

### Basic Build
```bash
cmake -S . -B build
cmake --build build -j
```

### Build Options
*   `-DENABLE_TLS=ON` (Default): Enable TLS/SSL (requires OpenSSL/LibreSSL).
*   `-DENABLE_SANITIZERS=ON`: Enable AddressSanitizer and UndefinedBehaviorSanitizer (Debug only).
*   `-DENABLE_IO_URING=ON`: Enable Linux `io_uring` support (requires liburing).
*   `-DENABLE_HTTP_COMPRESSION=ON`: Enable HTTP compression (requires zlib/brotli).
*   `-DENABLE_FUZZING=ON`: Enable libFuzzer targets (requires Clang).

### Running Tests
Standard tests:
```bash
cd build && ctest --output-on-failure
# Or: make test
```

Run specific test:
```bash
./build/test_socket
```

### Scripts
*   `scripts/local_ci.sh`: Runs a comprehensive local CI check (build, test, lint).
*   `scripts/build_fuzz.sh`: Helper to build fuzzing targets.
*   `scripts/coverage_report.sh`: Generates code coverage reports.

## Development Conventions

### Code Style
*   **Standard:** GNU C11.
*   **Formatting:** Follows `.clang-format`.
*   **Naming:**
    *   Types: `ModuleName_T` (e.g., `Socket_T`, `Arena_T`).
    *   Functions: `Module_Verb` (e.g., `Socket_bind`).
    *   Private: `lower_snake_case`.
    *   Constants: `MODULE_NAME` (e.g., `SOCKET_MAX_CONNECTIONS`).

### Error Handling
**Exception Style (Core):**
```c
TRY
    Socket_connect(socket, "example.com", 80);
EXCEPT(Socket_Failed)
    // Handle error
FINALLY
    Socket_free(&socket);
END_TRY;
```

**Simple Style (Wrapper):**
```c
if (Socket_simple_connect("example.com", 80) == NULL) {
    // Handle error
}
```

### Contribution Checklist
1.  Code must compile with `-Wall -Wextra -Werror`.
2.  Pass all tests with sanitizers enabled (`-DENABLE_SANITIZERS=ON`).
3.  Add tests for new features/fixes.
4.  Update documentation for API changes.
5.  Use `Arena` allocators for memory management where possible.
