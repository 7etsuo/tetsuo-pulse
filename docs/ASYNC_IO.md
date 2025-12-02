# Asynchronous I/O Guide {#async_io_guide}

## Overview

The Socket Library provides asynchronous I/O operations using platform-optimized mechanisms for maximum performance. Async I/O allows non-blocking send/receive operations that complete via callbacks, eliminating CPU waste from blocking system calls.

## Platform Support

| Platform | Backend | Status |
|----------|---------|--------|
| Linux (kernel 5.1+) | io_uring | ✅ Full support |
| macOS/BSD | kqueue (edge-triggered) | ✅ Partial support |
| Other POSIX | Edge-triggered polling | ✅ Fallback mode |

**Note:** On Linux, install `liburing-dev` for full async I/O support. Without it, the library falls back to edge-triggered polling.

## Key Benefits

1. **10x Throughput**: Async I/O can achieve 100K+ requests/second vs 10K for synchronous operations
2. **Low CPU Usage**: <20% CPU under load vs 80%+ for synchronous I/O
3. **Non-Blocking**: Operations complete via callbacks, never block the event loop
4. **Zero-Copy**: Where supported (io_uring), data is transferred directly without kernel copies

## Basic Usage

### Getting Async Context

Async I/O is integrated with `SocketPoll`. Get the async context from your poll instance:

```c
SocketPoll_T poll = SocketPoll_new(4096);
SocketAsync_T async = SocketPoll_get_async(poll);

if (!async || !SocketAsync_is_available(async)) {
    printf("Async I/O not available - using fallback mode\n");
    return;
}

const char *backend = SocketAsync_backend_name(async);
printf("Using async backend: %s\n", backend);
```

### Async Send

```c
void send_complete(Socket_T socket, ssize_t bytes, int err, void *user_data) {
    if (err != 0) {
        printf("Send failed: %s\n", strerror(err));
        return;
    }
    printf("Sent %zd bytes\n", bytes);
    /* Process completion */
}

/* Submit async send */
char data[] = "Hello, async I/O!";
unsigned req_id = SocketAsync_send(async, socket, data, sizeof(data) - 1,
                                   send_complete, NULL, ASYNC_FLAG_NONE);
```

### Async Receive

```c
void recv_complete(Socket_T socket, ssize_t bytes, int err, void *user_data) {
    if (err != 0) {
        printf("Recv failed: %s\n", strerror(err));
        return;
    }
    if (bytes == 0) {
        printf("Connection closed\n");
        return;
    }
    printf("Received %zd bytes\n", bytes);
    /* Process received data */
}

/* Submit async receive */
char buffer[4096];
unsigned req_id = SocketAsync_recv(async, socket, buffer, sizeof(buffer),
                                   recv_complete, NULL, ASYNC_FLAG_NONE);
```

### Processing Completions

Completions are automatically processed by `SocketPoll_wait()`. You can also process them manually:

```c
/* Process completions (non-blocking) */
int count = SocketAsync_process_completions(async, 0);
printf("Processed %d completions\n", count);
```

### Cancellation

```c
/* Cancel pending operation */
int result = SocketAsync_cancel(async, req_id);
if (result == 0) {
    printf("Request cancelled\n");
} else {
    printf("Request not found or already completed\n");
}
```

## Complete Example: Echo Server

```c
#include "socket/Socket.h"
#include "poll/SocketPoll.h"
#include "socket/SocketAsync.h"

void echo_recv_complete(Socket_T socket, ssize_t bytes, int err, void *user_data) {
    char *buffer = (char *)user_data;
    
    if (err != 0) {
        Socket_free(&socket);
        return;
    }
    
    if (bytes == 0) {
        /* Connection closed */
        Socket_free(&socket);
        return;
    }
    
    /* Echo back what we received */
    SocketAsync_T async = SocketPoll_get_async(poll);
    SocketAsync_send(async, socket, buffer, bytes, echo_send_complete, NULL, ASYNC_FLAG_NONE);
}

void echo_send_complete(Socket_T socket, ssize_t bytes, int err, void *user_data) {
    SocketAsync_T async = SocketPoll_get_async(poll);
    char *buffer = malloc(4096);
    
    if (err != 0) {
        Socket_free(&socket);
        free(buffer);
        return;
    }
    
    /* Read next message */
    SocketAsync_recv(async, socket, buffer, 4096, echo_recv_complete, buffer, ASYNC_FLAG_NONE);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    
    Arena_T arena = Arena_new();
    SocketPoll_T poll = SocketPoll_new(4096);
    SocketAsync_T async = SocketPoll_get_async(poll);
    
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr(server);
    Socket_bind(server, "127.0.0.1", 8080);
    Socket_listen(server, 100);
    Socket_setnonblocking(server);
    
    SocketPoll_add(poll, server, POLL_READ, NULL);
    
    while (1) {
        SocketEvent_T *events;
        int n = SocketPoll_wait(poll, &events, 1000);
        
        for (int i = 0; i < n; i++) {
            if (events[i].socket == server) {
                /* Accept new connection */
                Socket_T client = Socket_accept(server);
                if (client) {
                    Socket_setnonblocking(client);
                    char *buffer = malloc(4096);
                    SocketAsync_recv(async, client, buffer, 4096, echo_recv_complete, buffer, ASYNC_FLAG_NONE);
                }
            }
        }
    }
    
    SocketPoll_free(&poll);
    Socket_free(&server);
    Arena_dispose(&arena);
    return 0;
}
```

## Performance Tuning

### io_uring (Linux)

- **Ring Size**: Default is 1024 entries. Increase for high-throughput scenarios:
  ```c
  /* Modify SocketAsync.c: io_uring_queue_init(4096, async->ring, 0) */
  ```

- **Batch Processing**: Process multiple completions per call:
  ```c
  SocketAsync_process_completions(async, 0); /* Processes up to 100 */
  ```

- **Zero-Copy**: Use `ASYNC_FLAG_ZERO_COPY` for large transfers:
  ```c
  SocketAsync_send(async, socket, buf, len, cb, data, ASYNC_FLAG_ZERO_COPY);
  ```

### kqueue (macOS/BSD)

- **Edge-Triggered**: Uses edge-triggered mode automatically
- **Event Batching**: Process multiple events per `kevent()` call
- **Limitation**: Not true async I/O - performs I/O when event fires

## Fallback Mode

When async I/O is unavailable, operations are queued but not submitted to the kernel. Applications must complete operations manually:

```c
if (!SocketAsync_is_available(async)) {
    /* Fallback: Use regular Socket_send()/Socket_recv() */
    ssize_t n = Socket_send(socket, buf, len);
    /* Manually invoke callback if needed */
}
```

## Thread Safety

- **Request Tracking**: Thread-safe via internal mutex
- **Completion Processing**: Thread-safe, but callbacks are invoked from `SocketPoll_wait()` context
- **Callback Execution**: Keep callbacks fast - they run in the event loop thread

## Error Handling

Callbacks receive error codes (not exceptions):

```c
void my_callback(Socket_T socket, ssize_t bytes, int err, void *user_data) {
    if (err != 0) {
        /* Handle error */
        if (err == ECONNRESET) {
            /* Connection reset */
        } else if (err == ETIMEDOUT) {
            /* Timeout */
        }
        return;
    }
    
    if (bytes < 0) {
        /* Error indicated by negative bytes */
        return;
    }
    
    /* Success */
}
```

## Migration Guide

### From Synchronous to Async

**Before:**
```c
ssize_t n = Socket_send(socket, buf, len);
if (n < 0) {
    /* Handle error */
}
```

**After:**
```c
void send_done(Socket_T sock, ssize_t bytes, int err, void *data) {
    if (err != 0) {
        /* Handle error */
        return;
    }
    /* Process completion */
}

SocketAsync_send(async, socket, buf, len, send_done, NULL, ASYNC_FLAG_NONE);
```

## Best Practices

1. **Check Availability**: Always check `SocketAsync_is_available()` before using async APIs
2. **Fast Callbacks**: Keep callbacks short - they block the event loop
3. **Buffer Lifetime**: Ensure buffers remain valid until callback is invoked
4. **Error Handling**: Always check `err` parameter in callbacks
5. **Resource Cleanup**: Free sockets/resources in callbacks, not in main loop

## Limitations

1. **macOS/BSD**: Not true async I/O - uses edge-triggered events with synchronous I/O
2. **Buffer Requirements**: Buffers must remain valid until callback is invoked
3. **Callback Context**: Callbacks run in `SocketPoll_wait()` context - keep them fast
4. **Partial Transfers**: Handle partial sends/receives in callbacks

## Troubleshooting

### Async Not Available

**Problem:** `SocketAsync_is_available()` returns 0

**Solutions:**
- Linux: Install `liburing-dev` package
- Check kernel version (Linux 5.1+ required for io_uring)
- Use fallback mode or upgrade platform

### High CPU Usage

**Problem:** CPU usage is still high with async I/O

**Solutions:**
- Ensure using io_uring backend (not fallback)
- Increase ring size for io_uring
- Batch process completions
- Profile callback execution time

### Memory Leaks

**Problem:** Memory leaks in async operations

**Solutions:**
- Ensure buffers are freed in callbacks
- Check for cancelled requests that weren't cleaned up
- Use Valgrind to track allocations

## API Reference

See `include/socket/SocketAsync.h` for complete API documentation.

## Performance Benchmarks

Expected performance improvements:

- **Throughput**: 10x improvement (10K → 100K+ reqs/sec)
- **CPU Usage**: 4x reduction (80% → 20%)
- **Latency**: Similar or better (depends on workload)
- **Concurrency**: Scales to 50K+ connections

Actual results depend on:
- Platform and kernel version
- Workload characteristics
- Hardware capabilities
- System load

