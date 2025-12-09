# Cross-Platform Polling Backends

The Socket library provides cross-platform I/O event multiplexing through an abstract backend interface in `SocketPoll_backend.h`. This allows optimal performance on different operating systems while maintaining a consistent API.

## Backend Selection

Backend selection occurs at compile-time via CMake platform detection:

- **epoll**: Selected on Linux kernels 2.6.8+ (default and recommended for Linux)
- **kqueue**: Selected on BSD/macOS systems
- **poll**: Fallback for other POSIX systems without epoll or kqueue

You can verify the active backend at runtime with `backend_name()` (internal) or through logging during `SocketPoll_new()`.

## Supported Backends

### epoll (Linux)

- **Header**: `src/poll/SocketPoll_epoll.c`
- **Mode**: Edge-triggered (EPOLLET) for efficiency
- **Performance**: O(1) add/mod/del/wait operations; scales to millions of file descriptors
- **Features**:
  - Supports level-triggered mode if needed
  - Handles EPOLLHUP, EPOLLERR automatically
  - Efficient for high-throughput servers
- **Limitations**: Linux-only; requires kernel support

### kqueue (BSD/macOS/FreeBSD)

- **Header**: `src/poll/SocketPoll_kqueue.c`
- **Mode**: Edge-triggered
- **Performance**: High-performance kernel event filtering; comparable to epoll
- **Features**:
  - Native support for signals, timers, files
  - EVFILT_READ/WRITE for socket events
  - Efficient change list processing
- **Limitations**: BSD/macOS only; different API from epoll/poll

### poll (POSIX Fallback)

- **Header**: `src/poll/SocketPoll_poll.c`
- **Mode**: Level-triggered
- **Performance**: O(n) per wait call; suitable for small to medium fd counts (<1024 recommended)
- **Features**:
  - Highly portable across POSIX systems
  - Simple implementation
  - No special kernel requirements
- **Limitations**: Less scalable for large fd sets; scans all fds each time

## Interface Contract

All backends implement the same abstract interface:

- `backend_new()`: Initialize backend with arena and maxevents
- `backend_add/mod/del()`: Register/modify/remove fds with events
- `backend_wait()`: Block for events with timeout
- `backend_get_event()`: Retrieve event details (fd, events)
- `backend_free()`: Cleanup resources

Validation macros like `VALIDATE_FD` and `VALIDATE_MAXEVENTS` ensure security.

Error handling uses standard POSIX `errno` values.

## Build Configuration

In `CMakeLists.txt`, backend detection:

```cmake
if(LINUX)
  # epoll backend
elseif(APPLE OR BSD)
  # kqueue backend
else()
  # poll backend
endif()
```

Enable with `-DENABLE_POLL=ON` (default).

## Usage Notes

- **Thread Safety**: Handled by `SocketPoll` layer mutexes; backends assume single-threaded access
- **EINTR Handling**: Internal retry logic for signal interrupts
- **Memory**: Events allocated from provided `Arena_T` for batch cleanup
- **Debugging**: Use `backend_name()` for logging active backend
- **Testing**: Unit tests verify equivalence across backends

## Portability Considerations

- **Windows**: Not supported; requires IOCP or WSAEventSelect backend (future work)
- **Embedded**: poll backend works on resource-constrained systems
- **Real-time**: Edge-triggered modes minimize wakeups

For integration with other modules:

- @ref event_system "Event System" for full polling API
- @ref core_io "Core I/O" for socket primitives
- @ref foundation "Foundation" for memory and exceptions

See also:
- @ref SocketPoll_T
- docs/ASYNC_IO.md for async I/O extensions
- docs/SIGNALS.md for signal handling in poll operations
