# Contributing to Socket Library

Thank you for your interest in contributing to the Socket Library! This document provides guidelines and information for contributors.

## Table of Contents

- [Getting Started](#getting-started)
- [Code Style Guide](#code-style-guide)
- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Pull Request Process](#pull-request-process)
- [Issue Templates](#issue-templates)
- [Additional Guidelines](#additional-guidelines)

## Getting Started

We welcome contributions of all kinds:

- **Bug fixes** - Help us squash bugs
- **Features** - Implement new functionality
- **Documentation** - Improve docs, examples, and comments
- **Tests** - Expand test coverage
- **Performance** - Optimize critical paths

Before contributing, please:

1. Check existing issues and PRs to avoid duplicates
2. For major changes, open an issue first to discuss the approach
3. Read through this guide to understand our conventions

## Code Style Guide

This project follows **GNU C11 coding style** with specific conventions. All code must compile with `-Wall -Wextra -Werror` without warnings.

### Header Files

**Include Guards** - Use `_INCLUDED` suffix:

```c
#ifndef SOCKET_INCLUDED
#define SOCKET_INCLUDED

/* Header content */

#endif
```

**Module Documentation** - Include comprehensive documentation at the top of each header:

```c
/**
 * Module Name
 *
 * Detailed description of the module's purpose and features.
 *
 * Features:
 * - Feature 1
 * - Feature 2
 *
 * Usage example:
 *   // Code example
 */
```

### Functions

**Doxygen-Style Comments** - Document all public functions:

```c
/**
 * Socket_bind - Bind socket to address and port
 * @socket: Socket instance to bind
 * @host: Hostname or IP address (NULL for INADDR_ANY)
 * @port: Port number to bind to
 *
 * Returns: 0 on success
 * Raises: Socket_Failed on error
 *
 * This function binds the socket to the specified address.
 * WARNING: May block during DNS resolution if hostname provided.
 */
```

**Function Signatures** - Return type on separate line:

```c
int
Socket_bind(Socket_T socket, const char *host, int port)
{
    /* Implementation */
}
```

**Private Functions** - Use `static` for internal helpers:

```c
static unsigned
socket_hash(const Socket_T socket)
{
    /* Implementation */
}
```

### Macros

**Complex Macros** - Use `do { } while(0)` pattern:

```c
#define SAFE_CLOSE(fd)                                                         \
    do                                                                         \
    {                                                                          \
        if ((fd) >= 0)                                                         \
            close(fd);                                                         \
    }                                                                          \
    while (0)
```

**Constants** - Use ALL_CAPS with module prefix:

```c
#define SOCKET_MAX_CONNECTIONS 10000UL
#define SOCKET_DEFAULT_TIMEOUT 30000
```

**Parameter Safety** - Parenthesize all macro arguments:

```c
#define VALID_PORT(p) ((int)(p) > 0 && (int)(p) <= 65535)
```

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Types | `ModuleName_T` | `Socket_T`, `Arena_T` |
| Functions | `Module_Verb` | `Socket_bind`, `Arena_alloc` |
| Private functions | `lower_snake_case` | `socket_hash`, `translate_events` |
| Constants | `MODULE_NAME` | `SOCKET_MAX_SIZE` |
| Exceptions | `Module_ErrorType` | `Socket_Failed`, `SocketTLS_HandshakeFailed` |

### Opaque Types

Use the T macro pattern for public APIs:

```c
/* In header */
#define T Socket_T
typedef struct T *T;

/* In implementation */
struct T
{
    int fd;
    /* ... */
};
#undef T
```

### Error Handling

Use exception-based error handling with `TRY/EXCEPT/FINALLY`:

```c
TRY
{
    Socket_connect(socket, host, port);
    /* Operations that may fail */
}
EXCEPT(Socket_Failed)
{
    /* Handle error */
}
FINALLY
{
    /* Cleanup (always executed) */
}
END_TRY;
```

**Thread-Safe Error Reporting** - Use thread-local storage:

```c
/* Declare thread-local exception (once per module) */
SOCKET_DECLARE_MODULE_EXCEPTION(ModuleName);

/* Raise with detailed error */
SOCKET_RAISE_FMT(Socket, Socket_Failed, "bind to %s:%d failed", host, port);
```

## Development Setup

### Prerequisites

- **CMake** 3.10 or higher
- **C11 compiler** with GNU extensions (GCC or Clang recommended)
- **pthread** support
- **POSIX-compliant system** (Linux, BSD, macOS)
- **OpenSSL/LibreSSL** (optional, for TLS support)

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/7etsuo/tetsuo-socket.git
cd tetsuo-socket

# Create build directory
mkdir build && cd build

# Configure (Debug build by default)
cmake ..

# Build
make -j$(nproc)

# Run tests
make test
```

### Build Options

| Option | Description | Default |
|--------|-------------|---------|
| `CMAKE_BUILD_TYPE` | `Debug` or `Release` | `Debug` |
| `ENABLE_TLS` | Enable TLS/SSL support | `ON` |
| `ENABLE_SANITIZERS` | Enable ASan + UBSan | `OFF` |
| `ENABLE_ASAN` | Enable AddressSanitizer only | `OFF` |
| `ENABLE_UBSAN` | Enable UndefinedBehaviorSanitizer only | `OFF` |
| `ENABLE_COVERAGE` | Enable code coverage (gcov) | `OFF` |

Example with options:

```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON -DENABLE_TLS=ON
```

## Running Tests

### Standard Test Run

```bash
# Using CMake
cmake --build build --target test

# Using CTest directly
cd build && ctest --output-on-failure

# Using Make
cd build && make test
```

### With Sanitizers (Required for PRs)

All PRs must pass with AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
# Build with sanitizers
cmake -B build-sanitizer -DENABLE_SANITIZERS=ON
cmake --build build-sanitizer -j

# Run tests with sanitizer options
cd build-sanitizer
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:halt_on_error=1 ctest --output-on-failure
```

### With Code Coverage

```bash
# Build with coverage
cmake -B build-coverage -DENABLE_COVERAGE=ON
cmake --build build-coverage -j

# Run tests
cd build-coverage && ctest

# Generate coverage report (requires lcov)
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' '*/test/*' --output-file coverage.info
genhtml coverage.info --output-directory coverage-report
```

### Running Individual Tests

```bash
cd build

# Run specific test
./test_socket
./test_socketbuf
./test_tls_integration

# Run with verbose output
./test_socket 2>&1 | tee test.log
```

### Test Files

| Test | Description |
|------|-------------|
| `test_arena` | Memory arena allocation |
| `test_except` | Exception handling |
| `test_socket` | TCP socket operations |
| `test_socketbuf` | Buffer operations |
| `test_socketdgram` | UDP socket operations |
| `test_socketpoll` | Event polling |
| `test_socketpool` | Connection pooling |
| `test_socketdns` | Async DNS resolution |
| `test_happy_eyeballs` | RFC 8305 implementation |
| `test_reconnect` | Auto-reconnection |
| `test_tls_integration` | TLS/SSL operations |
| `test_threadsafety` | Thread safety |
| `test_integration` | Integration scenarios |

## Pull Request Process

### 1. Fork and Branch

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/YOUR_FORK/tetsuo-socket.git
cd tetsuo-socket
git checkout -b feature/your-feature-name
```

### 2. Make Changes

- Follow the [Code Style Guide](#code-style-guide)
- Add tests for new functionality
- Update documentation as needed
- Keep commits focused and atomic

### 3. Commit Messages

Use clear, descriptive commit messages:

```
<type>: <short summary>

<optional body with more details>

<optional footer with issue references>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, no logic change)
- `refactor`: Code refactoring
- `test`: Adding/updating tests
- `perf`: Performance improvement
- `chore`: Build/tooling changes

**Examples:**

```
feat: Add TCP Fast Open support to Socket_connect

Implements TCP_FASTOPEN socket option for Linux 3.7+, FreeBSD 10.0+,
and macOS 10.11+. Falls back gracefully on unsupported platforms.

Closes #42
```

```
fix: Handle EINTR correctly in SAFE_CLOSE macro

Per POSIX.1-2008, close() should not be retried on EINTR as the
file descriptor state is unspecified after EINTR return.
```

### 4. Pre-Submit Checklist

Before submitting your PR, ensure:

- [ ] Code compiles without warnings (`-Wall -Wextra -Werror`)
- [ ] All tests pass (`make test`)
- [ ] Tests pass with sanitizers (`ENABLE_SANITIZERS=ON`)
- [ ] New code has appropriate tests
- [ ] Documentation updated for API changes
- [ ] Commit messages follow conventions
- [ ] Branch is rebased on latest `main`

### 5. Submit PR

1. Push your branch to your fork
2. Open a Pull Request against `main`
3. Fill in the PR template
4. Wait for CI checks to pass
5. Address review feedback

### 6. Review Process

- PRs require at least one approval before merge
- CI must pass (tests, sanitizers, linting)
- Reviewers may request changes
- Once approved, maintainers will merge

## Issue Templates

### Bug Report

When reporting a bug, please include:

```markdown
## Bug Description
A clear description of what the bug is.

## Environment
- OS: [e.g., Ubuntu 22.04, macOS 14.0]
- Compiler: [e.g., GCC 12.2, Clang 15]
- Library version/commit: [e.g., v1.0.0 or commit hash]

## Steps to Reproduce
1. Step one
2. Step two
3. Step three

## Expected Behavior
What you expected to happen.

## Actual Behavior
What actually happened.

## Minimal Reproducible Example
```c
// Code that reproduces the issue
```

## Additional Context
- Error messages
- Stack traces
- Related issues
```

### Feature Request

When requesting a feature, please include:

```markdown
## Feature Description
A clear description of the feature you'd like.

## Use Case
Why do you need this feature? What problem does it solve?

## Proposed API
```c
// Suggested function signatures or usage examples
```

## Alternatives Considered
Other approaches you've considered.

## Additional Context
Any other relevant information.
```

## Additional Guidelines

### Thread Safety

- Socket operations are thread-safe per socket (one thread per socket recommended)
- Error reporting uses thread-local storage (safe for concurrent use)
- Shared data structures (SocketPoll, SocketPool) are mutex-protected
- Use `SOCKET_DECLARE_MODULE_EXCEPTION` for thread-safe exception handling

### Memory Management

- Use **arena allocation** for related objects
- Use `Arena_alloc` / `Arena_calloc` for allocations
- Use `Arena_dispose` to free entire contexts
- Always check for integer overflow before allocation
- Use `SocketBuf_secureclear` for sensitive data

### Platform Considerations

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | Primary | Full support, epoll backend |
| macOS | Supported | kqueue backend |
| BSD | Supported | kqueue backend |
| Windows | Not supported | Requires Winsock adaptation |

### Performance

- Use `sendfile()` for large file transfers (zero-copy)
- Use scatter/gather I/O for multi-buffer operations
- Event polling is O(1) with epoll/kqueue
- Connection pool lookups are O(1) with hash tables

### Security

- Never disable TLS certificate verification in production
- Use `SocketBuf_secureclear()` for sensitive data
- Validate all user input before passing to socket functions
- Be aware of DNS blocking (use async DNS for untrusted hostnames)

## Questions?

If you have questions about contributing:

1. Check existing documentation in `README.md` and `docs/`
2. Search existing issues
3. Open a discussion issue for general questions

Thank you for contributing!

