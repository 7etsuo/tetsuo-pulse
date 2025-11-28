# Socket Library

High-performance, exception-driven socket toolkit for POSIX systems. Provides a clean, modern API for TCP, UDP, and Unix domain sockets with comprehensive error handling, zero-copy I/O, cross-platform event polling, and optional TLS 1.3 support.

## Features

### Core Capabilities
- **TCP Stream Sockets** - Full-featured TCP client/server with scatter/gather I/O
- **UDP Datagram Sockets** - Connectionless and connected modes with multicast/broadcast
- **Unix Domain Sockets** - IPC sockets with peer credential support (Linux)
- **TLS/SSL Support** - TLS 1.3-only by default with SNI, ALPN, session resumption, CRL/OCSP
- **Exception-Based Error Handling** - Clean error propagation with `TRY/EXCEPT/FINALLY`
- **Asynchronous DNS Resolution** - Non-blocking DNS with thread pool and timeouts
- **Cross-Platform Event Polling** - epoll (Linux), kqueue (BSD/macOS), poll fallback
- **Connection Pooling** - O(1) lookup, rate limiting, auto-reconnection, batch accept
- **Zero-Copy I/O** - Platform-optimized `sendfile()` and scatter/gather I/O
- **Happy Eyeballs (RFC 8305)** - Fast dual-stack IPv4/IPv6 connection racing
- **Automatic Reconnection** - Exponential backoff with circuit breaker pattern
- **Async I/O** - io_uring (Linux 5.1+), kqueue AIO (BSD/macOS), edge-triggered fallback

### Production-Ready Features
- **Thread-safe error reporting** with thread-local buffers
- **Observability** - Pluggable logging, metrics collection, event dispatching
- **Rate limiting** - Token bucket algorithm for connections and bandwidth
- **Timers** - One-shot and repeating timers with O(log n) min-heap
- **Per-socket bandwidth throttling** with event loop integration
- **Configurable timeouts** - Global defaults and per-socket overrides
- **Memory-safe arena allocation** with overflow protection
- **SIGPIPE handling** - Automatic (no application code required)

## Platform Requirements

- **POSIX-compliant system** (Linux, BSD, macOS)
- **IPv6 support** in kernel (for dual-stack sockets)
- **POSIX threads** (pthread) for thread-safe operations
- **C11 compiler** with GNU extensions
- **NOT portable to Windows** without Winsock adaptation layer

### Platform-Specific Features
| Feature | Linux | BSD/macOS | Fallback |
|---------|-------|-----------|----------|
| Event polling | epoll | kqueue | poll(2) |
| Async I/O | io_uring (5.1+) | kqueue AIO | edge-triggered |
| TCP Fast Open | 3.7+ | 10.0+/10.11+ | disabled |
| Congestion control | configurable | - | - |
| Peer credentials | SO_PEERCRED | - | - |

## Quick Start

### Building

```bash
# Basic build
cmake -S . -B build
cmake --build build -j

# Run tests
cmake --build build --target test

# Build with TLS support (auto-detects OpenSSL/LibreSSL)
cmake -S . -B build -DENABLE_TLS=ON

# Build with sanitizers for debugging
cmake -S . -B build -DENABLE_SANITIZERS=ON

# Build with code coverage
cmake -S . -B build -DENABLE_COVERAGE=ON
```

### Basic TCP Server

```c
#include "socket/Socket.h"
#include "core/Except.h"
#include <stdio.h>

int main(void)
{
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    
    TRY
        Socket_setreuseaddr(server);
        Socket_bind(server, NULL, 8080);
        Socket_listen(server, 128);
        
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
        fprintf(stderr, "Error: %s\n", Socket_GetLastError());
    END_TRY;
    
    Socket_free(&server);
    return 0;
}
```

### Basic TCP Client

```c
#include "socket/Socket.h"
#include "core/Except.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
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
        fprintf(stderr, "Error: %s\n", Socket_GetLastError());
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
    fprintf(stderr, "Socket error: %s\n", Socket_GetLastError());
EXCEPT(Socket_Closed)
    fprintf(stderr, "Connection closed\n");
FINALLY
    Socket_free(&socket);
END_TRY;
```

### Non-Blocking I/O with Event Polling

```c
#include "socket/Socket.h"
#include "poll/SocketPoll.h"

Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
Socket_setreuseaddr(server);
Socket_bind(server, NULL, 8080);
Socket_listen(server, 128);
Socket_setnonblocking(server);

SocketPoll_T poll = SocketPoll_new(1000);
SocketPoll_add(poll, server, POLL_READ, NULL);

while (1) {
    SocketEvent_T *events;
    int n = SocketPoll_wait(poll, &events, 1000);
    
    for (int i = 0; i < n; i++) {
        if (events[i].socket == server) {
            Socket_T client = Socket_accept(server);
            if (client) {
                Socket_setnonblocking(client);
                SocketPoll_add(poll, client, POLL_READ, client);
            }
        } else {
            Socket_T client = events[i].socket;
            char buf[1024];
            ssize_t bytes = Socket_recv(client, buf, sizeof(buf));
            if (bytes > 0) {
                Socket_sendall(client, buf, bytes);
            } else {
                SocketPoll_del(poll, client);
                Socket_free(&client);
            }
        }
    }
}

SocketPoll_free(&poll);
Socket_free(&server);
```

### UDP Server

```c
#include "socket/SocketDgram.h"

SocketDgram_T server = SocketDgram_new(AF_INET, 0);
SocketDgram_bind(server, NULL, 5000);

char buffer[65536];
char sender_host[46];
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

SocketDgram_free(&server);
```

### Connection Pooling with Rate Limiting

```c
#include "pool/SocketPool.h"
#include "core/Arena.h"

Arena_T arena = Arena_new();
SocketPool_T pool = SocketPool_new(arena, 10000, 8192);

/* Enable rate limiting: 100 connections/sec, burst of 50 */
SocketPool_setconnrate(pool, 100, 50);

/* Limit per-IP connections */
SocketPool_setmaxperip(pool, 10);

/* Rate-limited accept */
Socket_T client = SocketPool_accept_limited(pool, server);
if (client) {
    Connection_T conn = SocketPool_add(pool, client);
    SocketBuf_T input = Connection_inbuf(conn);
    SocketBuf_T output = Connection_outbuf(conn);
    /* ... use connection ... */
}

/* Batch accept for high-throughput servers */
Socket_T accepted[32];
int count = SocketPool_accept_batch(pool, server, 32, accepted);

/* Clean up idle connections */
SocketPool_cleanup(pool, 300);  /* Remove idle > 300 seconds */

SocketPool_free(&pool);
Arena_dispose(&arena);
```

### Happy Eyeballs Connection (RFC 8305)

```c
#include "socket/SocketHappyEyeballs.h"

/* Synchronous - races IPv6 and IPv4 for fastest connection */
Socket_T sock = SocketHappyEyeballs_connect("example.com", 443, NULL);
Socket_sendall(sock, "GET / HTTP/1.1\r\n\r\n", 18);
Socket_free(&sock);

/* Asynchronous - for event-driven applications */
SocketHE_Config_T config;
SocketHappyEyeballs_config_defaults(&config);
config.first_attempt_delay_ms = 250;  /* RFC 8305 default */
config.total_timeout_ms = 30000;

SocketHE_T he = SocketHappyEyeballs_start(dns, poll, "example.com", 443, &config);
while (!SocketHappyEyeballs_poll(he)) {
    int timeout = SocketHappyEyeballs_next_timeout_ms(he);
    SocketPoll_wait(poll, &events, timeout);
    SocketHappyEyeballs_process(he);
}
Socket_T result = SocketHappyEyeballs_result(he);
SocketHappyEyeballs_free(&he);
```

### Automatic Reconnection with Circuit Breaker

```c
#include "socket/SocketReconnect.h"

/* Configure reconnection policy */
SocketReconnect_Policy_T policy;
SocketReconnect_policy_defaults(&policy);
policy.initial_delay_ms = 100;
policy.max_delay_ms = 30000;
policy.multiplier = 2.0;
policy.jitter = 0.25;
policy.max_attempts = 10;
policy.circuit_failure_threshold = 5;
policy.circuit_reset_timeout_ms = 60000;

void on_state_change(SocketReconnect_T conn, SocketReconnect_State old, 
                     SocketReconnect_State new, void *data) {
    printf("State: %s -> %s\n", 
           SocketReconnect_state_name(old),
           SocketReconnect_state_name(new));
}

SocketReconnect_T conn = SocketReconnect_new("example.com", 443, 
                                             &policy, on_state_change, NULL);
SocketReconnect_connect(conn);

/* Event loop */
while (running) {
    int timeout = SocketReconnect_next_timeout_ms(conn);
    poll(&pfd, 1, timeout);
    SocketReconnect_process(conn);
    SocketReconnect_tick(conn);
    
    if (SocketReconnect_isconnected(conn)) {
        /* I/O with auto-reconnect on error */
        ssize_t n = SocketReconnect_send(conn, data, len);
    }
}

SocketReconnect_free(&conn);
```

### Asynchronous DNS Resolution

```c
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"

SocketDNS_T dns = SocketDNS_new();
SocketPoll_T poll = SocketPoll_new(100);

/* Configure DNS timeouts */
SocketDNS_settimeout(dns, 5000);  /* 5 second default timeout */

/* Start async resolution */
SocketDNS_Request_T req = SocketDNS_resolve(dns, "example.com", 80, NULL, NULL);

/* Per-request timeout override */
SocketDNS_request_settimeout(dns, req, 10000);

/* Add DNS to poll set */
int dns_fd = SocketDNS_pollfd(dns);
/* Use a wrapper socket or raw fd polling */

/* In event loop, check for completions */
SocketDNS_check(dns);

/* Get result */
struct addrinfo *result = SocketDNS_getresult(dns, req);
if (result) {
    Socket_connect_with_addrinfo(socket, result);
    freeaddrinfo(result);
} else {
    int error = SocketDNS_geterror(dns, req);
    fprintf(stderr, "DNS failed: %s\n", gai_strerror(error));
}

SocketDNS_free(&dns);
SocketPoll_free(&poll);
```

### Bandwidth Limiting

```c
#include "socket/Socket.h"

Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
Socket_connect(socket, "example.com", 80);

/* Enable bandwidth limiting: 1 MB/sec */
Socket_setbandwidth(socket, 1024 * 1024);

/* Rate-limited send */
ssize_t n = Socket_send_limited(socket, data, len);
if (n == 0) {
    /* Rate limited - wait before retry */
    int64_t wait_ms = Socket_bandwidth_wait_ms(socket, len);
    /* Use wait_ms as poll timeout */
}

/* Query current limit */
size_t limit = Socket_getbandwidth(socket);

Socket_free(&socket);
```

### Timers

```c
#include "poll/SocketPoll.h"
#include "core/SocketTimer.h"

SocketPoll_T poll = SocketPoll_new(100);

void timer_callback(void *userdata) {
    printf("Timer fired!\n");
}

/* One-shot timer (fires once after 5 seconds) */
SocketTimer_T timer = SocketTimer_add(poll, 5000, timer_callback, NULL);

/* Repeating timer (fires every 1 second) */
SocketTimer_T heartbeat = SocketTimer_add_repeating(poll, 1000, timer_callback, NULL);

/* Check remaining time */
int64_t remaining = SocketTimer_remaining(poll, timer);

/* Cancel timer */
SocketTimer_cancel(poll, heartbeat);

/* Timers fire automatically during SocketPoll_wait() */
SocketEvent_T *events;
int n = SocketPoll_wait(poll, &events, -1);

SocketPoll_free(&poll);
```

### Token Bucket Rate Limiting

```c
#include "core/SocketRateLimit.h"

/* Create rate limiter: 100 tokens/sec, burst capacity of 50 */
SocketRateLimit_T limiter = SocketRateLimit_new(NULL, 100, 50);

/* Try to acquire tokens (non-blocking) */
if (SocketRateLimit_try_acquire(limiter, 1)) {
    /* Allowed - proceed */
    handle_request();
} else {
    /* Rate limited - calculate wait time */
    int64_t wait_ms = SocketRateLimit_wait_time_ms(limiter, 1);
    if (wait_ms > 0) {
        /* Wait or reject */
    }
}

/* Query state */
size_t available = SocketRateLimit_available(limiter);
size_t rate = SocketRateLimit_get_rate(limiter);

/* Reconfigure at runtime */
SocketRateLimit_configure(limiter, 200, 100);

SocketRateLimit_free(&limiter);
```

### Zero-Copy File Transfer

```c
int file_fd = open("largefile.bin", O_RDONLY);
struct stat st;
fstat(file_fd, &st);

off_t offset = 0;
ssize_t sent = Socket_sendfileall(socket, file_fd, &offset, st.st_size);
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

/* Send all data atomically */
ssize_t sent = Socket_sendvall(socket, iov, 3);
```

### Unix Domain Sockets

```c
#include "socket/Socket.h"

/* Stream socket pair for IPC */
Socket_T sock1, sock2;
SocketPair_new(SOCK_STREAM, &sock1, &sock2);

/* Server socket */
Socket_T server = Socket_new(AF_UNIX, SOCK_STREAM, 0);
Socket_bind_unix(server, "/tmp/my.sock");
Socket_listen(server, 10);

/* Client connection */
Socket_T client = Socket_new(AF_UNIX, SOCK_STREAM, 0);
Socket_connect_unix(client, "/tmp/my.sock");

/* Get peer credentials (Linux only) */
int peer_pid = Socket_getpeerpid(accepted);
int peer_uid = Socket_getpeeruid(accepted);
int peer_gid = Socket_getpeergid(accepted);

/* Abstract namespace (Linux only - prefix with @) */
Socket_bind_unix(server, "@abstract-socket");
```

### Timeout Configuration

```c
#include "socket/Socket.h"

/* Set global default timeouts */
SocketTimeouts_T defaults = {
    .connect_timeout_ms = 30000,
    .dns_timeout_ms = 5000
};
Socket_timeouts_setdefaults(&defaults);

/* Per-socket timeout override */
Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
SocketTimeouts_T timeouts;
Socket_timeouts_get(socket, &timeouts);
timeouts.connect_timeout_ms = 10000;
Socket_timeouts_set(socket, &timeouts);

/* Legacy timeout (send/recv) */
Socket_settimeout(socket, 30);  /* 30 seconds */
```

### TLS/SSL Secure Communication

```c
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"

/* Create client TLS context */
SocketTLSContext_T ctx = SocketTLSContext_new_client("/etc/ssl/certs/ca-certificates.crt");

/* Configure ALPN protocols */
const char *protos[] = {"h2", "http/1.1"};
SocketTLSContext_set_alpn_protos(ctx, protos, 2);

/* Enable session caching for performance */
SocketTLSContext_enable_session_cache(ctx, 1000, 300);

/* Create and connect socket */
Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
Socket_connect(socket, "example.com", 443);

/* Enable TLS */
SocketTLS_enable(socket, ctx);
SocketTLS_set_hostname(socket, "example.com");  /* SNI + verification */

/* Perform handshake (with timeout) */
TLSHandshakeState state = SocketTLS_handshake_loop(socket, 10000);
if (state != TLS_HANDSHAKE_COMPLETE) {
    fprintf(stderr, "Handshake failed\n");
    /* Handle error */
}

/* Check negotiated protocol */
const char *alpn = SocketTLS_get_alpn_selected(socket);
printf("ALPN: %s\n", alpn ? alpn : "none");
printf("Cipher: %s\n", SocketTLS_get_cipher(socket));
printf("Version: %s\n", SocketTLS_get_version(socket));

/* Encrypted I/O */
SocketTLS_send(socket, "GET / HTTP/1.1\r\n\r\n", 18);
char buf[4096];
ssize_t n = SocketTLS_recv(socket, buf, sizeof(buf));

/* Graceful shutdown */
SocketTLS_shutdown(socket);
Socket_free(&socket);
SocketTLSContext_free(&ctx);
```

### TLS Server with SNI

```c
#include "tls/SocketTLSContext.h"

/* Create server context with primary certificate */
SocketTLSContext_T ctx = SocketTLSContext_new_server(
    "server.crt", "server.key", "ca-bundle.crt");

/* Add SNI certificates for virtual hosting */
SocketTLSContext_add_certificate(ctx, "www.example.com", 
                                  "www.crt", "www.key");
SocketTLSContext_add_certificate(ctx, "api.example.com",
                                  "api.crt", "api.key");

/* Enable client certificate verification */
SocketTLSContext_set_verify_mode(ctx, TLS_VERIFY_PEER);

/* Load CRL for revocation checking */
SocketTLSContext_load_crl(ctx, "/path/to/crl.pem");

/* Enable OCSP stapling */
unsigned char ocsp_response[4096];
size_t ocsp_len = load_ocsp_response(ocsp_response, sizeof(ocsp_response));
SocketTLSContext_set_ocsp_response(ctx, ocsp_response, ocsp_len);

/* Enable session tickets */
unsigned char ticket_key[80];
generate_ticket_key(ticket_key, sizeof(ticket_key));
SocketTLSContext_enable_session_tickets(ctx, ticket_key, sizeof(ticket_key));
```

### Observability

```c
#include "core/SocketUtil.h"

/* Custom logging callback */
void my_logger(void *userdata, SocketLogLevel level,
               const char *component, const char *message) {
    printf("[%s] %s: %s\n", SocketLog_levelname(level), component, message);
}
SocketLog_setcallback(my_logger, NULL);

/* Metrics collection */
SocketMetricsSnapshot snapshot;
SocketMetrics_getsnapshot(&snapshot);

printf("Connect successes: %llu\n", 
       SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_SOCKET_CONNECT_SUCCESS));
printf("DNS requests: %llu\n",
       SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_DNS_REQUEST_SUBMITTED));
printf("Pool connections: %llu\n",
       SocketMetrics_snapshot_value(&snapshot, SOCKET_METRIC_POOL_CONNECTIONS_ADDED));

/* Reset metrics */
SocketMetrics_reset();

/* Event callbacks */
void on_event(void *userdata, const SocketEventRecord *event) {
    switch (event->type) {
    case SOCKET_EVENT_CONNECTED:
        printf("Connected to %s:%d\n", 
               event->data.connection.peer_addr,
               event->data.connection.peer_port);
        break;
    case SOCKET_EVENT_DNS_TIMEOUT:
        printf("DNS timeout for %s\n", event->data.dns.host);
        break;
    }
}
SocketEvent_register(on_event, NULL);
```

### Advanced TCP Options

```c
/* Congestion control algorithm (Linux only) */
Socket_setcongestion(socket, "bbr");
char algo[16];
Socket_getcongestion(socket, algo, sizeof(algo));

/* TCP Fast Open (Linux 3.7+, FreeBSD 10.0+, macOS 10.11+) */
Socket_setfastopen(socket, 1);

/* TCP user timeout (Linux 2.6.37+) */
Socket_setusertimeout(socket, 30000);  /* 30 seconds */

/* TCP keepalive */
Socket_setkeepalive(socket, 60, 10, 5);  /* idle=60s, interval=10s, count=5 */

/* Disable Nagle's algorithm */
Socket_setnodelay(socket, 1);

/* Buffer sizes */
Socket_setrcvbuf(socket, 262144);
Socket_setsndbuf(socket, 262144);
```

## API Reference

### Core Modules

#### Arena (Memory Management)
- `Arena_new()` - Create new memory arena
- `Arena_dispose()` - Free arena and all allocations
- `Arena_alloc()` - Allocate from arena
- `Arena_calloc()` - Allocate zeroed memory

#### Except (Exception Handling)
- `TRY/EXCEPT/FINALLY/END_TRY` - Exception handling macros
- `RAISE()` - Raise an exception
- `RERAISE` - Re-raise current exception

#### SocketTimer (Timers)
- `SocketTimer_add()` - Add one-shot timer
- `SocketTimer_add_repeating()` - Add repeating timer
- `SocketTimer_cancel()` - Cancel pending timer
- `SocketTimer_remaining()` - Get time until expiry

#### SocketRateLimit (Rate Limiting)
- `SocketRateLimit_new()` - Create token bucket limiter
- `SocketRateLimit_free()` - Free limiter
- `SocketRateLimit_try_acquire()` - Try to consume tokens
- `SocketRateLimit_wait_time_ms()` - Calculate wait time
- `SocketRateLimit_available()` - Get available tokens
- `SocketRateLimit_configure()` - Reconfigure at runtime

### Socket Module (TCP Stream Sockets)

#### Creation and Lifecycle
- `Socket_new()` - Create new socket
- `Socket_new_from_fd()` - Create from existing file descriptor
- `SocketPair_new()` - Create connected Unix domain socket pair
- `Socket_free()` - Free socket and close connection
- `Socket_fd()` - Get underlying file descriptor

#### Connection Management
- `Socket_bind()` - Bind socket to address/port
- `Socket_listen()` - Start listening for connections
- `Socket_accept()` - Accept incoming connection
- `Socket_connect()` - Connect to remote host
- `Socket_shutdown()` - Shutdown connection
- `Socket_isconnected()` / `Socket_isbound()` / `Socket_islistening()` - State queries

#### I/O Operations
- `Socket_send()` / `Socket_recv()` - Basic send/receive
- `Socket_sendall()` / `Socket_recvall()` - Complete send/receive
- `Socket_sendv()` / `Socket_recvv()` - Scatter/gather I/O
- `Socket_sendvall()` / `Socket_recvvall()` - Complete scatter/gather
- `Socket_sendfile()` / `Socket_sendfileall()` - Zero-copy file transfer
- `Socket_sendmsg()` / `Socket_recvmsg()` - Advanced message I/O

#### Bandwidth Limiting
- `Socket_setbandwidth()` - Set bandwidth limit (bytes/sec)
- `Socket_getbandwidth()` - Get bandwidth limit
- `Socket_send_limited()` - Rate-limited send
- `Socket_recv_limited()` - Rate-limited receive
- `Socket_bandwidth_wait_ms()` - Get wait time for bandwidth

#### Socket Options
- `Socket_setnonblocking()` - Enable non-blocking mode
- `Socket_setreuseaddr()` / `Socket_setreuseport()` - Address/port reuse
- `Socket_settimeout()` / `Socket_gettimeout()` - Socket timeout
- `Socket_setkeepalive()` / `Socket_getkeepalive()` - TCP keepalive
- `Socket_setnodelay()` / `Socket_getnodelay()` - Nagle's algorithm
- `Socket_setrcvbuf()` / `Socket_setsndbuf()` - Buffer sizes
- `Socket_setcongestion()` / `Socket_getcongestion()` - Congestion control (Linux)
- `Socket_setfastopen()` / `Socket_getfastopen()` - TCP Fast Open
- `Socket_setusertimeout()` / `Socket_getusertimeout()` - TCP user timeout (Linux)
- `Socket_setcloexec()` - Close-on-exec flag

#### Timeout Configuration
- `Socket_timeouts_set()` / `Socket_timeouts_get()` - Per-socket timeouts
- `Socket_timeouts_setdefaults()` / `Socket_timeouts_getdefaults()` - Global defaults

#### Unix Domain Sockets
- `Socket_bind_unix()` - Bind to Unix socket path
- `Socket_connect_unix()` - Connect to Unix socket path
- `Socket_getpeerpid()` / `Socket_getpeeruid()` / `Socket_getpeergid()` - Peer credentials

#### Address Information
- `Socket_getpeeraddr()` / `Socket_getpeerport()` - Peer address
- `Socket_getlocaladdr()` / `Socket_getlocalport()` - Local address

### SocketDgram Module (UDP Datagram Sockets)

#### Creation
- `SocketDgram_new()` - Create UDP socket
- `SocketDgram_free()` - Free socket

#### Connection Management
- `SocketDgram_bind()` - Bind socket
- `SocketDgram_connect()` - Set default destination
- `SocketDgram_isconnected()` / `SocketDgram_isbound()` - State queries

#### I/O Operations
- `SocketDgram_sendto()` / `SocketDgram_recvfrom()` - Connectionless I/O
- `SocketDgram_send()` / `SocketDgram_recv()` - Connected I/O
- `SocketDgram_sendall()` / `SocketDgram_recvall()` - Complete I/O
- `SocketDgram_sendv()` / `SocketDgram_recvv()` - Scatter/gather I/O
- `SocketDgram_sendvall()` / `SocketDgram_recvvall()` - Complete scatter/gather

#### Multicast/Broadcast
- `SocketDgram_setbroadcast()` - Enable broadcast
- `SocketDgram_joinmulticast()` / `SocketDgram_leavemulticast()` - Multicast groups
- `SocketDgram_setttl()` / `SocketDgram_getttl()` - TTL/hop limit

### SocketPoll Module (Event Polling)

- `SocketPoll_new()` - Create poll instance
- `SocketPoll_free()` - Free poll instance
- `SocketPoll_add()` - Add socket to poll set
- `SocketPoll_mod()` - Modify socket events
- `SocketPoll_del()` - Remove socket from poll set
- `SocketPoll_wait()` - Wait for events
- `SocketPoll_setdefaulttimeout()` / `SocketPoll_getdefaulttimeout()` - Default timeout
- `SocketPoll_get_async()` - Get async I/O context

### SocketPool Module (Connection Pooling)

#### Pool Management
- `SocketPool_new()` - Create pool
- `SocketPool_free()` - Free pool
- `SocketPool_add()` - Add socket to pool
- `SocketPool_remove()` - Remove socket from pool
- `SocketPool_get()` - Look up connection
- `SocketPool_count()` - Get active connection count
- `SocketPool_cleanup()` - Remove idle connections
- `SocketPool_resize()` - Resize pool capacity
- `SocketPool_prewarm()` - Pre-allocate buffers

#### Rate Limiting
- `SocketPool_setconnrate()` / `SocketPool_getconnrate()` - Connection rate limit
- `SocketPool_setmaxperip()` / `SocketPool_getmaxperip()` - Per-IP limit
- `SocketPool_accept_allowed()` - Check if accepting allowed
- `SocketPool_accept_limited()` - Rate-limited accept
- `SocketPool_accept_batch()` - Batch accept
- `SocketPool_track_ip()` / `SocketPool_release_ip()` - IP tracking

#### Reconnection
- `SocketPool_set_reconnect_policy()` - Set default reconnection policy
- `SocketPool_enable_reconnect()` / `SocketPool_disable_reconnect()` - Per-connection
- `SocketPool_process_reconnects()` - Process reconnection state machines
- `SocketPool_reconnect_timeout_ms()` - Get next timeout

#### Async Connect
- `SocketPool_connect_async()` - Async connection with callback
- `SocketPool_prepare_connection()` - Prepare async connection

#### Connection Accessors
- `Connection_socket()` - Get connection's socket
- `Connection_inbuf()` / `Connection_outbuf()` - Get I/O buffers
- `Connection_data()` / `Connection_setdata()` - User data
- `Connection_lastactivity()` - Last activity time
- `Connection_isactive()` - Check if active
- `Connection_reconnect()` / `Connection_has_reconnect()` - Reconnection context

### SocketDNS Module (Asynchronous DNS)

- `SocketDNS_new()` - Create DNS resolver
- `SocketDNS_free()` - Free resolver
- `SocketDNS_resolve()` - Start async resolution
- `SocketDNS_getresult()` - Get resolution result
- `SocketDNS_geterror()` - Get error code
- `SocketDNS_cancel()` - Cancel resolution
- `SocketDNS_pollfd()` - Get poll file descriptor
- `SocketDNS_check()` - Process completed requests
- `SocketDNS_settimeout()` / `SocketDNS_gettimeout()` - Resolver timeout
- `SocketDNS_request_settimeout()` - Per-request timeout
- `SocketDNS_setmaxpending()` / `SocketDNS_getmaxpending()` - Queue capacity

### SocketHappyEyeballs Module (RFC 8305)

- `SocketHappyEyeballs_connect()` - Blocking Happy Eyeballs connect
- `SocketHappyEyeballs_start()` - Start async Happy Eyeballs
- `SocketHappyEyeballs_poll()` - Check if operation complete
- `SocketHappyEyeballs_process()` - Process events
- `SocketHappyEyeballs_result()` - Get winning socket
- `SocketHappyEyeballs_cancel()` - Cancel operation
- `SocketHappyEyeballs_free()` - Free context
- `SocketHappyEyeballs_state()` - Get current state
- `SocketHappyEyeballs_error()` - Get error message
- `SocketHappyEyeballs_config_defaults()` - Initialize config
- `SocketHappyEyeballs_next_timeout_ms()` - Get next timeout

### SocketReconnect Module (Automatic Reconnection)

- `SocketReconnect_new()` - Create reconnecting connection
- `SocketReconnect_free()` - Free context
- `SocketReconnect_connect()` - Start connecting
- `SocketReconnect_disconnect()` - Graceful disconnect
- `SocketReconnect_reset()` - Reset backoff/circuit breaker
- `SocketReconnect_socket()` - Get underlying socket
- `SocketReconnect_state()` - Get current state
- `SocketReconnect_isconnected()` - Check connection status
- `SocketReconnect_attempts()` / `SocketReconnect_failures()` - Statistics
- `SocketReconnect_pollfd()` - Get poll file descriptor
- `SocketReconnect_process()` - Process poll events
- `SocketReconnect_tick()` - Process timers
- `SocketReconnect_next_timeout_ms()` - Get next timeout
- `SocketReconnect_send()` / `SocketReconnect_recv()` - I/O with auto-reconnect
- `SocketReconnect_set_health_check()` - Custom health check
- `SocketReconnect_policy_defaults()` - Initialize policy
- `SocketReconnect_state_name()` - Get state name string

### SocketAsync Module (Asynchronous I/O)

- `SocketAsync_new()` - Create async context
- `SocketAsync_free()` - Free context
- `SocketAsync_send()` - Submit async send
- `SocketAsync_recv()` - Submit async receive
- `SocketAsync_cancel()` - Cancel pending operation
- `SocketAsync_process_completions()` - Process completions
- `SocketAsync_is_available()` - Check platform support
- `SocketAsync_backend_name()` - Get backend name

### SocketTLS Module (TLS/SSL)

#### TLS Operations
- `SocketTLS_enable()` - Enable TLS on socket
- `SocketTLS_set_hostname()` - Set SNI hostname
- `SocketTLS_handshake()` - Perform handshake step
- `SocketTLS_handshake_loop()` - Complete handshake with timeout
- `SocketTLS_shutdown()` - Graceful TLS shutdown
- `SocketTLS_send()` / `SocketTLS_recv()` - Encrypted I/O

#### TLS Information
- `SocketTLS_get_cipher()` - Get negotiated cipher
- `SocketTLS_get_version()` - Get TLS version
- `SocketTLS_get_verify_result()` - Get verification result
- `SocketTLS_get_verify_error_string()` - Get verification error
- `SocketTLS_is_session_reused()` - Check session resumption
- `SocketTLS_get_alpn_selected()` - Get negotiated ALPN protocol
- `SocketTLS_get_ocsp_status()` - Get OCSP status

### SocketTLSContext Module (TLS Context)

#### Context Creation
- `SocketTLSContext_new_server()` - Create server context
- `SocketTLSContext_new_client()` - Create client context
- `SocketTLSContext_free()` - Free context

#### Certificate Management
- `SocketTLSContext_load_certificate()` - Load cert/key pair
- `SocketTLSContext_add_certificate()` - Add SNI certificate
- `SocketTLSContext_load_ca()` - Load CA certificates
- `SocketTLSContext_set_verify_mode()` - Set verification policy
- `SocketTLSContext_set_verify_callback()` - Custom verification
- `SocketTLSContext_load_crl()` - Load CRL
- `SocketTLSContext_refresh_crl()` - Refresh CRL

#### OCSP Stapling
- `SocketTLSContext_set_ocsp_response()` - Set static OCSP response
- `SocketTLSContext_set_ocsp_gen_callback()` - Dynamic OCSP generation

#### Protocol Configuration
- `SocketTLSContext_set_min_protocol()` / `SocketTLSContext_set_max_protocol()` - TLS version
- `SocketTLSContext_set_cipher_list()` - Cipher suites

#### ALPN
- `SocketTLSContext_set_alpn_protos()` - Set ALPN protocols
- `SocketTLSContext_set_alpn_callback()` - Custom ALPN selection

#### Session Management
- `SocketTLSContext_enable_session_cache()` - Enable session caching
- `SocketTLSContext_set_session_cache_size()` - Set cache size
- `SocketTLSContext_get_cache_stats()` - Get cache statistics
- `SocketTLSContext_enable_session_tickets()` - Enable session tickets

### Observability

#### Logging
- `SocketLog_setcallback()` - Set custom log callback
- `SocketLog_getcallback()` - Get current callback
- `SocketLog_emit()` / `SocketLog_emitf()` - Emit log messages
- `SocketLog_levelname()` - Get level name string

#### Metrics
- `SocketMetrics_increment()` - Increment counter
- `SocketMetrics_getsnapshot()` - Get atomic snapshot
- `SocketMetrics_reset()` - Reset all metrics
- `SocketMetrics_name()` - Get metric name
- `SocketMetrics_count()` - Get total metric count

#### Events
- `SocketEvent_register()` / `SocketEvent_unregister()` - Event callbacks
- `SocketEvent_emit_accept()` / `SocketEvent_emit_connect()` - Emit events
- `SocketEvent_emit_dns_timeout()` / `SocketEvent_emit_poll_wakeup()`

### Error Reporting

- `Socket_GetLastError()` - Get last error message (thread-local)
- `Socket_geterrno()` - Get last errno value
- `Socket_geterrorcode()` - Get structured error code
- `Socket_get_monotonic_ms()` - Get monotonic time

### Exception Types

- `Socket_Failed` - General socket operation failure
- `Socket_Closed` - Connection closed by peer
- `SocketUnix_Failed` - Unix socket operation failure
- `SocketDgram_Failed` - UDP socket operation failure
- `SocketPoll_Failed` - Event polling failure
- `SocketPool_Failed` - Connection pool operation failure
- `SocketDNS_Failed` - DNS resolution failure
- `SocketHE_Failed` - Happy Eyeballs connection failure
- `SocketReconnect_Failed` - Reconnection operation failure
- `SocketTimer_Failed` - Timer operation failure
- `SocketRateLimit_Failed` - Rate limiter failure
- `SocketAsync_Failed` - Async I/O failure
- `SocketTLS_Failed` - General TLS operation failure
- `SocketTLS_HandshakeFailed` - TLS handshake failure
- `SocketTLS_VerifyFailed` - Certificate verification failure
- `SocketTLS_ProtocolError` - TLS protocol error
- `SocketTLS_ShutdownFailed` - TLS shutdown failure

## Building

### Requirements

- CMake 3.10+
- C11 compiler with GNU extensions and pthread support
- POSIX-compliant system
- OpenSSL 1.1.1+ or LibreSSL (optional, for TLS support)

### Build Commands

```bash
# Configure
cmake -S . -B build

# Build
cmake --build build -j

# Run tests
cmake --build build --target test
# or
cd build && ctest --output-on-failure

# Generate API documentation (requires Doxygen)
cmake --build build --target doc

# Install (optional)
cmake --install build --prefix /usr/local
```

### Build Options

| Option | Description | Default |
|--------|-------------|---------|
| `CMAKE_BUILD_TYPE` | Debug or Release | Debug |
| `ENABLE_TLS` | Enable TLS/SSL support | ON (auto-detect) |
| `ENABLE_SANITIZERS` | Enable ASan + UBSan | OFF |
| `ENABLE_ASAN` | Enable AddressSanitizer | OFF |
| `ENABLE_UBSAN` | Enable UndefinedBehaviorSanitizer | OFF |
| `ENABLE_COVERAGE` | Enable gcov coverage | OFF |

### Poll Backend Selection

The poll backend is automatically selected based on platform:
- **Linux** - epoll (fastest for Linux)
- **BSD/macOS** - kqueue
- **Other POSIX** - poll(2) fallback

## Thread Safety

- **Socket operations** - Thread-safe per socket (one thread per socket recommended)
- **Error reporting** - Thread-local (safe for concurrent use)
- **SocketPoll** - Thread-safe (protected by mutexes)
- **SocketPool** - Thread-safe (protected by mutexes)
- **SocketDNS** - Thread-safe (uses thread pool)
- **SocketTimer** - Thread-safe
- **SocketRateLimit** - Thread-safe (internal mutex)
- **Metrics/Logging** - Thread-safe (atomic operations)
- **SocketHappyEyeballs** - NOT thread-safe per instance
- **SocketReconnect** - NOT thread-safe per instance
- **TLS contexts** - Thread-safe after setup (read-only sharing)

## Memory Management

The library uses **arena allocation** for related objects. Sockets and their associated resources are managed through arenas, ensuring efficient memory usage and automatic cleanup.

```c
Arena_T arena = Arena_new();
Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
/* Socket uses arena internally */
Socket_free(&socket);  /* Frees socket and internal arena */
Arena_dispose(&arena); /* Free external arena if used */
```

## Performance Considerations

- **Zero-copy I/O** - Uses platform-specific `sendfile()` when available
- **Scatter/gather I/O** - Efficient multi-buffer operations via `writev()`/`readv()`
- **Event polling** - O(1) event delivery with epoll/kqueue
- **Connection pooling** - O(1) lookup with hash tables
- **Timers** - O(log n) insert/cancel with min-heap
- **Non-blocking I/O** - Full support for async operations
- **Session resumption** - TLS session caching reduces handshake overhead
- **Async I/O** - io_uring/kqueue for true async operations

## Examples

See `src/test/` directory for comprehensive usage examples:
- `test_socket.c` - TCP socket examples
- `test_socketdgram.c` - UDP socket examples
- `test_socketpoll.c` - Event polling examples
- `test_socketpool.c` - Connection pooling examples
- `test_socketdns.c` - Async DNS examples
- `test_happy_eyeballs.c` - RFC 8305 examples
- `test_reconnect.c` - Auto-reconnection examples
- `test_ratelimit.c` - Rate limiting examples
- `test_tls_integration.c` - TLS examples
- `test_integration.c` - Integration test scenarios

## Documentation

- **Release Notes** - See [RELEASE_NOTES.md](RELEASE_NOTES.md) for latest changes
- **Architecture** - See `.cursor/rules/` for detailed design patterns
- **API Documentation** - All functions include Doxygen-style comments

### Generating API Reference

```bash
# Install Doxygen
# Ubuntu/Debian: sudo apt-get install doxygen
# macOS: brew install doxygen

# Generate documentation
cmake --build build --target doc

# View documentation
xdg-open docs/html/index.html  # Linux
open docs/html/index.html      # macOS
```

## License

See `LICENSE` for usage details.
