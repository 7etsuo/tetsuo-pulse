# Socket Library - Production-Ready C Network Programming

A robust, thread-safe socket library for C implementing best practices from "C Interfaces and Implementations" with comprehensive security enhancements.

## Features

### Core Functionality
- **Exception-based error handling** - Clean error handling without return code checking
- **Arena memory management** - Efficient allocation with automatic cleanup
- **Circular buffering** - Zero-copy I/O operations where possible
- **Event-driven I/O** - High-performance epoll-based event polling
- **Connection pooling** - Pre-allocated connections with O(1) lookup

### Security Enhancements
- **Integer overflow protection** - Safe arithmetic in all allocation paths
- **Format string safety** - Protected against format string attacks
- **Buffer overflow prevention** - Bounds checking and safe wraparound logic
- **Memory disclosure prevention** - Buffers are zero-initialized
- **Thread safety** - Comprehensive mutex protection for concurrent access
- **Resource leak prevention** - Proper cleanup in all error paths

### Network Features
- **DNS resolution** - Support for both hostnames and IP addresses
- **Timeout support** - Configurable send/receive timeouts
- **TCP keepalive** - Detect dead connections
- **Nagle control** - TCP_NODELAY support for low-latency applications
- **Non-blocking I/O** - Efficient event-driven programming

## Building

```bash
make clean
make
```

The build system uses pthread for thread safety. Ensure you have pthread development libraries installed.

## Usage Example

```c
#include "Arena.h"
#include "Socket.h"
#include "SocketPoll.h"
#include "SocketPool.h"

int main() {
    Arena_T arena = NULL;
    Socket_T server = NULL;
    SocketPoll_T poll = NULL;
    SocketPool_T pool = NULL;
    
    TRY
        // Create arena for memory management
        arena = Arena_new();
        if (!arena)
            RAISE(Socket_Failed);
            
        // Create and configure server socket
        server = Socket_new(AF_INET, SOCK_STREAM, 0);
        Socket_setreuseaddr(server);
        Socket_settimeout(server, 30);  // 30 second timeout
        Socket_bind(server, "0.0.0.0", 8080);
        Socket_listen(server, 128);
        Socket_setnonblocking(server);
        
        // Create event poller
        poll = SocketPoll_new(1000);
        SocketPoll_add(poll, server, POLL_READ, NULL);
        
        // Create connection pool
        pool = SocketPool_new(arena, 1000, 8192);
        
        // Event loop
        while (running) {
            SocketEvent_T *events;
            int n = SocketPoll_wait(poll, &events, 1000);
            
            for (int i = 0; i < n; i++) {
                if (events[i].socket == server) {
                    // Accept new connection
                    Socket_T client = Socket_accept(server);
                    if (client) {
                        Socket_setkeepalive(client, 60, 10, 6);
                        Connection_T conn = SocketPool_add(pool, client);
                        if (conn) {
                            SocketPoll_add(poll, client, POLL_READ, conn);
                        }
                    }
                } else {
                    // Handle client I/O
                    Connection_T conn = events[i].data;
                    // ... handle connection ...
                }
            }
        }
        
    EXCEPT(Socket_Failed)
        fprintf(stderr, "Socket error: %s\n", Socket_Failed.reason);
    FINALLY
        if (poll) SocketPoll_free(&poll);
        if (pool) SocketPool_free(&pool);
        if (server) Socket_free(&server);
        if (arena) Arena_dispose(&arena);
    END_TRY;
    
    return 0;
}
```

## API Reference

### Arena Memory Management

```c
Arena_T Arena_new(void);
void Arena_dispose(Arena_T *arena);
void *Arena_alloc(Arena_T arena, size_t nbytes, const char *file, int line);
void *Arena_calloc(Arena_T arena, size_t count, size_t nbytes, const char *file, int line);
void Arena_free(Arena_T arena);

// Convenience macros
#define ALLOC(arena, nbytes) Arena_alloc((arena), (nbytes), __FILE__, __LINE__)
#define CALLOC(arena, count, nbytes) Arena_calloc((arena), (count), (nbytes), __FILE__, __LINE__)
```

### Socket Operations

```c
// Creation and destruction
Socket_T Socket_new(int domain, int type, int protocol);
void Socket_free(Socket_T *socket);

// Server operations
void Socket_bind(Socket_T socket, const char *host, int port);
void Socket_listen(Socket_T socket, int backlog);
Socket_T Socket_accept(Socket_T socket);

// Client operations
void Socket_connect(Socket_T socket, const char *host, int port);

// I/O operations
int Socket_send(Socket_T socket, const void *buf, int len);
int Socket_recv(Socket_T socket, void *buf, int len);

// Configuration
void Socket_setnonblocking(Socket_T socket);
void Socket_setreuseaddr(Socket_T socket);
void Socket_settimeout(Socket_T socket, int timeout_sec);
void Socket_setkeepalive(Socket_T socket, int idle, int interval, int count);
void Socket_setnodelay(Socket_T socket, int nodelay);

// Accessors
int Socket_fd(Socket_T socket);
const char *Socket_getpeeraddr(Socket_T socket);
int Socket_getpeerport(Socket_T socket);
```

### Event Polling

```c
// Poll management
SocketPoll_T SocketPoll_new(int maxevents);
void SocketPoll_free(SocketPoll_T *poll);

// Socket monitoring
void SocketPoll_add(SocketPoll_T poll, Socket_T socket, unsigned events, void *data);
void SocketPoll_mod(SocketPoll_T poll, Socket_T socket, unsigned events, void *data);
void SocketPoll_del(SocketPoll_T poll, Socket_T socket);

// Event waiting
int SocketPoll_wait(SocketPoll_T poll, SocketEvent_T **events, int timeout);

// Event types
POLL_READ    // Data available for reading
POLL_WRITE   // Socket ready for writing
POLL_ERROR   // Error condition
POLL_HANGUP  // Disconnection
```

### Connection Pooling

```c
// Pool management
SocketPool_T SocketPool_new(Arena_T arena, size_t maxconns, size_t bufsize);
void SocketPool_free(SocketPool_T *pool);

// Connection operations
Connection_T *SocketPool_get(SocketPool_T pool, Socket_T socket);
Connection_T *SocketPool_add(SocketPool_T pool, Socket_T socket);
void SocketPool_remove(SocketPool_T pool, Socket_T socket);
void SocketPool_cleanup(SocketPool_T pool, time_t idle_timeout);

// Connection accessors
Socket_T Connection_socket(Connection_T *conn);
SocketBuf_T Connection_inbuf(Connection_T *conn);
SocketBuf_T Connection_outbuf(Connection_T *conn);
void *Connection_data(Connection_T *conn);
void Connection_setdata(Connection_T *conn, void *data);
time_t Connection_lastactivity(Connection_T *conn);
int Connection_isactive(Connection_T *conn);
```

### Circular Buffers

```c
// Buffer management
SocketBuf_T SocketBuf_new(Arena_T arena, size_t capacity);
void SocketBuf_free(SocketBuf_T *buf);

// I/O operations
size_t SocketBuf_write(SocketBuf_T buf, const void *data, size_t len);
size_t SocketBuf_read(SocketBuf_T buf, void *data, size_t len);
size_t SocketBuf_peek(SocketBuf_T buf, void *data, size_t len);
void SocketBuf_consume(SocketBuf_T buf, size_t len);

// Buffer status
size_t SocketBuf_available(SocketBuf_T buf);
size_t SocketBuf_space(SocketBuf_T buf);
int SocketBuf_empty(SocketBuf_T buf);
int SocketBuf_full(SocketBuf_T buf);
void SocketBuf_clear(SocketBuf_T buf);

// Zero-copy operations
const void *SocketBuf_readptr(SocketBuf_T buf, size_t *len);
void *SocketBuf_writeptr(SocketBuf_T buf, size_t *len);
void SocketBuf_written(SocketBuf_T buf, size_t len);
```

## Thread Safety

All modules are thread-safe when used properly:
- Arena allocations are protected by mutexes
- SocketPool operations are synchronized
- SocketPoll socket data mappings are protected
- Exception handling uses thread-local storage

## Error Handling

The library uses an exception system for error handling:

```c
TRY
    // Operations that might fail
EXCEPT(Socket_Failed)
    // Handle socket errors
EXCEPT(Socket_Closed)
    // Handle connection closed
FINALLY
    // Cleanup code (always executed)
END_TRY;
```

## Performance Considerations

- **O(1) connection lookup** via hash tables
- **Edge-triggered epoll** for scalability
- **Zero-copy buffer operations** where possible
- **Pre-allocated connection pools** to avoid allocation overhead
- **Arena allocation** for cache-friendly memory layout

## Security Considerations

- Always validate input from untrusted sources
- Use timeouts to prevent DoS attacks
- Consider implementing rate limiting
- Enable keepalive to detect dead connections
- The library is safe for concurrent use

## Platform Support

- Linux (primary platform, uses epoll)
- Requires POSIX threads (pthread)
- C99 compiler required
- Tested with GCC

## License

[Your license here]

## Contributing

[Your contribution guidelines here]
