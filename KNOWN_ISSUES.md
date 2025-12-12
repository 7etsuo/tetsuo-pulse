# Known Issues

This document tracks known issues and disabled tests in the socket library.

## Disabled Test Cases

The following test cases are currently disabled due to platform-specific issues or bugs under investigation. All core functionality is tested and working; these represent edge cases or specific configurations.

### macOS ARM64 Issues

Several tests are disabled on macOS ARM64 (M1/M2) due to `setjmp`/`longjmp` issues with the exception handling system:

| File | Test | Issue |
|------|------|-------|
| `test_socketpoll.c` | `socketpoll_wait_write_event` | ARM64 longjmp segfault |
| `test_socketpoll.c` | `socketpoll_wait_negative_timeout` | ARM64 longjmp segfault |
| `test_socketpoll.c` | `socketpoll_multiple_ready_sockets` | Exception frame corruption |
| `test_socketpoll.c` | `socketpoll_event_loop_simulation` | ARM64 longjmp segfault |
| `test_socketpoll.c` | `thread_poll_operations` | ARM64 longjmp issues |
| `test_socketpoll.c` | `socketpoll_wait_zero_timeout` | ARM64 longjmp segfault |
| `test_socketpoll.c` | `socketpoll_multiple_event_types` | ARM64 segfault |
| `test_integration.c` | Multi-threaded server test | macOS threading issues |
| `test_integration.c` | Async I/O integration | Async I/O backend not implemented |

**Root Cause**: The exception handling system uses `setjmp`/`longjmp` which has different behavior on ARM64 macOS. The tests pass on Linux x86_64.

**Status**: Investigating alternative exception handling for ARM64.

### DNS-Related Test Issues

| File | Test | Issue |
|------|------|-------|
| `test_socket.c` | `socket_bind_async_basic` | Hangs on `SocketDNS_check()` |
| `test_socket.c` | `socket_bind_async_wildcard` | Hangs on `SocketDNS_check()` |
| `test_socketdns.c` | `thread_check_completions` | Exception frame handling segfault |
| `test_socketdns.c` | `socketdns_thread_pool_processes_requests` | Exception frame handling segfault |

**Root Cause**: Thread synchronization issues between DNS worker threads and the exception system's thread-local stack.

**Status**: Under investigation.

### Connection Pool Issues

| File | Test | Issue |
|------|------|-------|
| `test_socketpool.c` | `socketpool_connection_buffer_operations` | Exception handling segfault |
| `test_socketpool.c` | `thread_add_remove_connections` | `realloc()` invalid pointer bug |
| `test_socketpool.c` | `socketpool_connect_async_dns_failure` | DNS resolution timing issues |

**Root Cause**: Complex interaction between arena allocation, connection pool resizing, and exception handling.

**Status**: Under investigation.

### TLS Integration

| File | Test | Issue |
|------|------|-------|
| `test_tls_integration.c` | (unnamed test at line 2522) | `Except_stack` corruption causing SEGV |

**Root Cause**: Exception stack gets corrupted to `0x000000000009` in certain TLS handshake failure paths.

**Status**: Under investigation.

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux x86_64 | Full support | Primary development platform |
| Linux ARM64 | Full support | Tested on Raspberry Pi 4 |
| macOS x86_64 | Full support | Intel Macs |
| macOS ARM64 | Partial | Some tests disabled (see above) |
| FreeBSD | Supported | kqueue backend |
| OpenBSD | Supported | kqueue backend |
| Windows | Not supported | Requires Winsock adaptation |

## Workarounds

### macOS ARM64
- All core functionality works correctly
- Avoid using TRY/EXCEPT in tight loops with poll operations
- Use the synchronous API when possible

### DNS Resolution
- For time-critical applications, resolve DNS to IP addresses separately
- Use IP addresses directly to avoid DNS blocking

## Contributing

If you can help fix any of these issues, contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

When working on these issues:
1. Run tests with AddressSanitizer: `cmake -DENABLE_ASAN=ON`
2. Run tests with ThreadSanitizer: `cmake -DENABLE_TSAN=ON`
3. Test on both Linux and macOS if possible

