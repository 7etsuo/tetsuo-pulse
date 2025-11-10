# Socket Library

High-performance, exception-driven socket toolkit for POSIX systems. Provides a clean, modern API for TCP, UDP, and Unix domain sockets with comprehensive error handling, zero-copy I/O, and cross-platform event polling.

## Features

### Core Capabilities
- **TCP Stream Sockets** - Full-featured TCP client/server support
- **UDP Datagram Sockets** - Connectionless and connected UDP modes
- **Unix Domain Sockets** - IPC sockets for local communication
- **Exception-Based Error Handling** - Clean error propagation with `TRY/EXCEPT/FINALLY`
- **Asynchronous DNS Resolution** - Non-blocking DNS with thread pool
- **Cross-Platform Event Polling** - epoll (Linux), kqueue (BSD/macOS), poll fallback
- **Connection Pooling** - Efficient connection management with buffers
- **Zero-Copy I/O** - Platform-optimized `sendfile()` and scatter/gather I/O
- **Advanced TCP Options** - Congestion control, Fast Open, user timeout

### Production-Ready Features
- Thread-safe error reporting
- Comprehensive timeout support
- Observability (logging, metrics, events)
- Memory-safe arena allocation
- Platform detection with graceful fallbacks

## Platform Requirements

- **POSIX-compliant system** (Linux, BSD, macOS)
- **IPv6 support** in kernel (for dual-stack sockets)
- **POSIX threads** (pthread) for thread-safe operations
- **NOT portable to Windows** without Winsock adaptation layer

## Quick Start

### Building

```bash
cmake -S . -B build
cmake --build build -j
cmake --build build --target test
```

### Basic TCP Server

```c
#include "socket/Socket.h"
#include "core/Except.h"
#include <signal.h>
#include <stdio.h>

int main(void)
{
    signal(SIGPIPE, SIG_IGN);  /* Required on macOS/BSD */
    
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    
    TRY
        Socket_bind(server, NULL, 8080);  /* Bind to any address */
        Socket_listen(server, 10);
        
        while (1) {
            Socket_T client = Socket_accept(server);
            if (client) {
                char buf[1024];
                ssize_t n = Socket_recv(client, buf, sizeof(buf) - 1);
                if (n > 0) {
                    buf[n] = '\0';
                    Socket_sendall(client, buf, n);
                }
                Socket_free(&client);
            }
        }
    EXCEPT(Socket_Failed)
        fprintf(stderr, "Error: %s\n", Socket_error());
    END_TRY;
    
    Socket_free(&server);
    return 0;
}
```

### Basic TCP Client

```c
#include "socket/Socket.h"
#include "core/Except.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    
    Socket_T client = Socket_new(AF_INET, SOCK_STREAM, 0);
    
    TRY
        Socket_connect(client, "127.0.0.1", 8080);
        
        const char *msg = "Hello, Server!";
        Socket_sendall(client, msg, strlen(msg));
        
        char buf[1024];
        ssize_t n = Socket_recvall(client, buf, strlen(msg));
        buf[n] = '\0';
        printf("Received: %s\n", buf);
    EXCEPT(Socket_Failed)
        fprintf(stderr, "Error: %s\n", Socket_error());
    EXCEPT(Socket_Closed)
        fprintf(stderr, "Connection closed\n");
    END_TRY;
    
    Socket_free(&client);
    return 0;
}
```

## Usage Patterns

### Error Handling

All socket operations use exception-based error handling:

```c
TRY
    Socket_connect(socket, "example.com", 80);
    Socket_sendall(socket, data, len);
EXCEPT(Socket_Failed)
    fprintf(stderr, "Socket error: %s\n", Socket_error());
    /* Handle error */
EXCEPT(Socket_Closed)
    fprintf(stderr, "Connection closed\n");
    /* Handle closure */
FINALLY
    /* Cleanup code always executes */
    Socket_free(&socket);
END_TRY;
```

### Non-Blocking I/O

```c
Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
Socket_setnonblocking(socket);

TRY
    Socket_connect(socket, "example.com", 80);
    /* connect() returns immediately */
    
    /* Use SocketPoll to wait for connection */
EXCEPT(Socket_Failed)
    /* Handle error */
END_TRY;
```

### Event-Driven Server with SocketPoll

```c
#include "socket/Socket.h"
#include "poll/SocketPoll.h"

Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
Socket_bind(server, NULL, 8080);
Socket_listen(server, 10);
Socket_setnonblocking(server);

SocketPoll_T poll = SocketPoll_new(100);
SocketPoll_add(poll, server, POLL_READ, NULL);

while (1) {
    SocketEvent_T events[10];
    int n = SocketPoll_wait(poll, events, 10, 1000);
    
    for (int i = 0; i < n; i++) {
        if (events[i].socket == server) {
            Socket_T client = Socket_accept(server);
            if (client) {
                Socket_setnonblocking(client);
                SocketPoll_add(poll, client, POLL_READ, client);
            }
        } else {
            /* Handle client I/O */
            Socket_T client = events[i].socket;
            char buf[1024];
            ssize_t n = Socket_recv(client, buf, sizeof(buf));
            if (n > 0) {
                Socket_sendall(client, buf, n);
            } else {
                SocketPoll_remove(poll, client);
                Socket_free(&client);
            }
        }
    }
}
```

### UDP Server

```c
#include "socket/SocketDgram.h"

SocketDgram_T server = SocketDgram_new(AF_INET, 0);
SocketDgram_bind(server, NULL, 5000);

char buffer[65536];
char sender_host[256];
int sender_port;

while (1) {
    ssize_t n = SocketDgram_recvfrom(server, buffer, sizeof(buffer),
                                     sender_host, sizeof(sender_host),
                                     &sender_port);
    if (n > 0) {
        /* Echo back to sender */
        SocketDgram_sendto(server, buffer, n, sender_host, sender_port);
    }
}
```

### Connection Pooling

```c
#include "pool/SocketPool.h"
#include "core/Arena.h"

Arena_T arena = Arena_new();
SocketPool_T pool = SocketPool_new(arena, 1000, 8192);

/* Add accepted socket to pool */
Socket_T client = Socket_accept(server);
Connection_T conn = SocketPool_add(pool, client);

/* Look up connection later */
Connection_T conn = SocketPool_get(pool, client);
SocketBuf_T input = Connection_input(conn);
SocketBuf_T output = Connection_output(conn);

/* Clean up idle connections periodically */
SocketPool_cleanup(pool, 300);  /* Remove idle > 300 seconds */
```

### Zero-Copy File Transfer

```c
int file_fd = open("largefile.bin", O_RDONLY);
off_t offset = 0;
ssize_t sent = Socket_sendfileall(socket, file_fd, &offset, file_size);
close(file_fd);
```

### Scatter/Gather I/O

```c
struct iovec iov[3];
iov[0].iov_base = header;
iov[0].iov_len = header_len;
iov[1].iov_base = body;
iov[1].iov_len = body_len;
iov[2].iov_base = footer;
iov[2].iov_len = footer_len;

ssize_t sent = Socket_sendvall(socket, iov, 3);
```

### Advanced TCP Options

```c
/* Set congestion control algorithm (Linux only) */
Socket_setcongestion(socket, "bbr");

/* Enable TCP Fast Open (Linux 3.7+, FreeBSD 10.0+, macOS 10.11+) */
Socket_setfastopen(socket, 1);

/* Set TCP user timeout (Linux 2.6.37+) */
Socket_setusertimeout(socket, 30000);  /* 30 seconds */

/* Adjust buffer sizes */
Socket_setrcvbuf(socket, 65536);
Socket_setsndbuf(socket, 65536);
```

### Asynchronous DNS Resolution

```c
#include "dns/SocketDNS.h"

SocketDNS_T dns = SocketDNS_new();
SocketPoll_T poll = SocketPoll_new(100);

/* Start async resolution */
SocketDNS_Request_T req = SocketDNS_resolve(dns, "example.com", 80, NULL, NULL);

/* Add DNS resolver to poll set */
int dns_fd = SocketDNS_pollfd(dns);
SocketPoll_add(poll, dns_fd, POLL_READ, dns);

/* In event loop */
SocketEvent_T events[10];
int n = SocketPoll_wait(poll, events, 10, 1000);
for (int i = 0; i < n; i++) {
    if (events[i].data == dns) {
        SocketDNS_check(dns);  /* Process completed requests */
        
        /* Get result */
        struct addrinfo *result = SocketDNS_getresult(req);
        if (result) {
            /* Use result for connection */
            Socket_connect_addrinfo(socket, result);
            freeaddrinfo(result);
        }
    }
}
```

## API Reference

### Core Modules

#### Socket (TCP Stream Sockets)

**Creation and Lifecycle:**
- `Socket_new()` - Create new socket
- `SocketPair_new()` - Create connected Unix domain socket pair
- `Socket_free()` - Free socket and close connection
- `Socket_fd()` - Get underlying file descriptor

**Connection Management:**
- `Socket_bind()` - Bind socket to address/port
- `Socket_listen()` - Start listening for connections
- `Socket_accept()` - Accept incoming connection
- `Socket_connect()` - Connect to remote host
- `Socket_shutdown()` - Shutdown connection
- `Socket_isconnected()` - Check connection state
- `Socket_isbound()` - Check bind state
- `Socket_islistening()` - Check listen state

**I/O Operations:**
- `Socket_send()` / `Socket_recv()` - Basic send/receive
- `Socket_sendall()` / `Socket_recvall()` - Complete send/receive (handles partial I/O)
- `Socket_sendv()` / `Socket_recvv()` - Scatter/gather I/O
- `Socket_sendvall()` / `Socket_recvvall()` - Complete scatter/gather I/O
- `Socket_sendfile()` / `Socket_sendfileall()` - Zero-copy file transfer
- `Socket_sendmsg()` / `Socket_recvmsg()` - Advanced message I/O with ancillary data

**Socket Options:**
- `Socket_setnonblocking()` - Enable non-blocking mode
- `Socket_setreuseaddr()` - Enable address reuse
- `Socket_setreuseport()` - Enable port reuse
- `Socket_settimeout()` - Set socket timeout
- `Socket_setkeepalive()` - Configure TCP keepalive
- `Socket_setnodelay()` - Disable Nagle's algorithm
- `Socket_setrcvbuf()` / `Socket_getrcvbuf()` - Receive buffer size
- `Socket_setsndbuf()` / `Socket_getsndbuf()` - Send buffer size
- `Socket_setcongestion()` / `Socket_getcongestion()` - TCP congestion control (Linux)
- `Socket_setfastopen()` / `Socket_getfastopen()` - TCP Fast Open
- `Socket_setusertimeout()` / `Socket_getusertimeout()` - TCP user timeout (Linux)

**Timeouts:**
- `Socket_timeouts_set()` - Set per-socket timeouts
- `Socket_timeouts_get()` - Get per-socket timeouts
- `Socket_timeouts_setdefaults()` - Set global default timeouts
- `Socket_timeouts_getdefaults()` - Get global default timeouts

#### SocketDgram (UDP Datagram Sockets)

**Creation:**
- `SocketDgram_new()` - Create UDP socket
- `SocketDgram_free()` - Free socket

**Connection Management:**
- `SocketDgram_bind()` - Bind socket
- `SocketDgram_connect()` - Connect socket (for send/recv)
- `SocketDgram_isconnected()` - Check connection state
- `SocketDgram_isbound()` - Check bind state

**I/O Operations:**
- `SocketDgram_sendto()` / `SocketDgram_recvfrom()` - Connectionless I/O
- `SocketDgram_send()` / `SocketDgram_recv()` - Connected I/O
- `SocketDgram_sendall()` / `SocketDgram_recvall()` - Complete I/O
- `SocketDgram_sendv()` / `SocketDgram_recvv()` - Scatter/gather I/O
- `SocketDgram_sendvall()` / `SocketDgram_recvvall()` - Complete scatter/gather

**Multicast/Broadcast:**
- `SocketDgram_setbroadcast()` - Enable broadcast
- `SocketDgram_join_multicast()` - Join multicast group
- `SocketDgram_leave_multicast()` - Leave multicast group
- `SocketDgram_setttl()` - Set TTL

#### SocketPoll (Event Polling)

- `SocketPoll_new()` - Create poll instance
- `SocketPoll_free()` - Free poll instance
- `SocketPoll_add()` - Add socket to poll set
- `SocketPoll_remove()` - Remove socket from poll set
- `SocketPoll_modify()` - Modify socket events
- `SocketPoll_wait()` - Wait for events
- `SocketPoll_get_backend()` - Get backend name (epoll/kqueue/poll)

#### SocketPool (Connection Pooling)

- `SocketPool_new()` - Create pool
- `SocketPool_free()` - Free pool
- `SocketPool_add()` - Add socket to pool
- `SocketPool_remove()` - Remove socket from pool
- `SocketPool_get()` - Look up connection
- `SocketPool_cleanup()` - Remove idle connections
- `Connection_socket()` - Get connection's socket
- `Connection_input()` - Get input buffer
- `Connection_output()` - Get output buffer
- `Connection_data()` - Get/set user data

#### SocketDNS (Asynchronous DNS)

- `SocketDNS_new()` - Create DNS resolver
- `SocketDNS_free()` - Free resolver
- `SocketDNS_resolve()` - Start async resolution
- `SocketDNS_getresult()` - Get resolution result
- `SocketDNS_cancel()` - Cancel resolution
- `SocketDNS_pollfd()` - Get poll file descriptor
- `SocketDNS_check()` - Process completed requests

### Exception Types

- `Socket_Failed` - General socket operation failure
- `Socket_Closed` - Connection closed by peer
- `SocketDgram_Failed` - UDP socket operation failure
- `SocketPoll_Failed` - Event polling failure
- `SocketPool_Failed` - Connection pool operation failure
- `SocketDNS_Failed` - DNS resolution failure

### Error Reporting

- `Socket_error()` - Get last error message (thread-local)
- `Socket_geterrno()` - Get last errno value
- `Socket_geterrorcode()` - Get structured error code

## Building

### Requirements

- CMake 3.10+
- C11 compiler with pthread support
- POSIX-compliant system

### Build Commands

```bash
# Configure
cmake -S . -B build

# Build
cmake --build build -j

# Run tests
cmake --build build --target test

# Install (optional)
cmake --install build --prefix /usr/local
```

### Build Options

- `CMAKE_BUILD_TYPE` - Debug or Release (default: Debug)
- Platform-specific backends are automatically detected

## Thread Safety

- **Socket operations** - Thread-safe per socket (one thread per socket recommended)
- **Error reporting** - Thread-local (safe for concurrent use)
- **SocketPoll** - Thread-safe (protected by mutexes)
- **SocketPool** - Thread-safe (protected by mutexes)
- **SocketDNS** - Thread-safe (uses thread pool)

## Memory Management

The library uses **arena allocation** for related objects. Sockets and their associated resources are managed through arenas, ensuring efficient memory usage and automatic cleanup.

```c
Arena_T arena = Arena_new();
Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
/* Socket uses arena internally */
Socket_free(&socket);  /* Frees socket and arena */
```

## Performance Considerations

- **Zero-copy I/O** - Uses platform-specific `sendfile()` when available
- **Scatter/gather I/O** - Efficient multi-buffer operations
- **Event polling** - O(1) event delivery with epoll/kqueue
- **Connection pooling** - O(1) lookup with hash tables
- **Non-blocking I/O** - Full support for async operations

## Examples

See `src/test/` directory for comprehensive usage examples:
- `test_socket.c` - TCP socket examples
- `test_socketdgram.c` - UDP socket examples
- `test_socketpoll.c` - Event polling examples
- `test_socketpool.c` - Connection pooling examples
- `test_socketdns.c` - Async DNS examples
- `test_integration.c` - Integration test scenarios

## Documentation

- **Release Notes** - See [RELEASE_NOTES.md](RELEASE_NOTES.md) for latest changes
- **Architecture** - See `.cursor/rules/` for detailed design patterns
- **API Documentation** - All functions include Doxygen-style comments

### Generating API Reference

To generate modern, beautiful HTML API documentation:

```bash
# Install Doxygen (if not already installed)
# Ubuntu/Debian: sudo apt-get install doxygen
# macOS: brew install doxygen

# Generate documentation (includes modern CSS theme)
cmake --build build --target doc
# or
make doc
# or directly
doxygen Doxyfile

# View documentation
open docs/html/index.html  # macOS
xdg-open docs/html/index.html  # Linux
```

**Features:**
- Modern, clean design with dark mode support
- Tree view navigation for easy browsing
- Enhanced search functionality
- Responsive layout for mobile devices
- Syntax highlighting for code examples
- Professional typography and spacing

The generated documentation will be in `docs/html/` directory with a modern CSS theme applied.

## License

See `LICENSE` (if provided) for usage details.
