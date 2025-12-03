# Socket Library

High-performance, exception-driven socket toolkit for POSIX systems. Provides a clean, modern C API for TCP, UDP, Unix domain sockets, HTTP/1.1, HTTP/2, WebSocket, and TLS/DTLS with comprehensive error handling, zero-copy I/O, and cross-platform event polling.

## Features

### Core Networking
- **TCP Stream Sockets** - Full-featured TCP client/server with scatter/gather I/O
- **UDP Datagram Sockets** - Connectionless and connected modes with multicast/broadcast
- **Unix Domain Sockets** - IPC sockets with peer credential support and file descriptor passing
- **TLS 1.3 Support** - Modern TLS with SNI, ALPN, session resumption, CRL/OCSP, certificate pinning
- **DTLS 1.2+ Support** - Secure UDP with cookie exchange for DoS protection

### HTTP Protocol Stack
- **HTTP/1.1** - Table-driven DFA parser (RFC 9112), chunked encoding, request smuggling prevention
- **HTTP/2** - Binary framing, stream multiplexing, flow control, server push (RFC 9113)
- **HPACK** - Header compression with static/dynamic tables, Huffman coding (RFC 7541)
- **HTTP Client** - Connection pooling, authentication (Basic/Digest/Bearer), cookies (RFC 6265)
- **HTTP Server** - Event-driven request handling, keep-alive, graceful shutdown

### WebSocket
- **RFC 6455 Compliant** - Full WebSocket protocol implementation
- **permessage-deflate** - Compression extension (RFC 7692) via zlib
- **Incremental UTF-8** - DFA-based text frame validation
- **Auto-Ping/Pong** - Configurable heartbeat with timer integration

### Proxy Tunneling
- **HTTP CONNECT** - Proxy tunneling with Basic authentication
- **SOCKS4/4a** - Legacy SOCKS support
- **SOCKS5** - RFC 1928/1929 with username/password authentication
- **Async API** - Non-blocking proxy connection with state machine

### Event System
- **Cross-Platform Polling** - epoll (Linux), kqueue (BSD/macOS), poll fallback
- **Edge-Triggered Mode** - High-performance event notification
- **Async I/O** - io_uring (Linux 5.1+), kqueue AIO (BSD/macOS)
- **Timers** - One-shot and repeating with O(log n) min-heap

### Connection Management
- **Connection Pooling** - O(1) lookup with hash tables, per-connection I/O buffers
- **Happy Eyeballs** - RFC 8305 dual-stack IPv4/IPv6 connection racing
- **Auto-Reconnection** - Exponential backoff with circuit breaker pattern
- **Graceful Shutdown** - Pool drain state machine with timeout guarantee

### Security Hardening
- **SYN Flood Protection** - Reputation scoring, throttling, kernel integration
- **Per-IP Tracking** - Connection limits and rate limiting per client
- **Rate Limiting** - Token bucket algorithm for connections and bandwidth
- **Request Smuggling Prevention** - Strict HTTP parsing with RFC compliance

### Infrastructure
- **Exception-Based Errors** - Clean error propagation with `TRY/EXCEPT/FINALLY`
- **Arena Memory Management** - Efficient allocation with overflow protection
- **Asynchronous DNS** - Non-blocking resolution with thread pool and timeouts
- **Zero-Copy I/O** - Platform-optimized `sendfile()` and scatter/gather I/O
- **Observability** - Pluggable logging, metrics collection, event dispatching
- **Cryptographic Utilities** - SHA-1/256, HMAC, Base64, secure random

## Platform Requirements

- **POSIX-compliant system** (Linux, BSD, macOS)
- **C11 compiler** with GNU extensions
- **POSIX threads** (pthread) for thread-safe operations
- **IPv6 support** in kernel (for dual-stack sockets)
- **NOT portable to Windows** without Winsock adaptation layer

### Platform-Specific Features

| Feature | Linux | BSD/macOS | Fallback |
|---------|-------|-----------|----------|
| Event polling | epoll | kqueue | poll(2) |
| Async I/O | io_uring (5.1+) | kqueue AIO | edge-triggered |
| TCP Fast Open | 3.7+ | 10.0+/10.11+ | disabled |
| Congestion control | configurable | - | - |
| Peer credentials | SO_PEERCRED | LOCAL_PEERCRED | - |
| SYN protection | TCP_DEFER_ACCEPT | SO_ACCEPTFILTER | userspace |

### TLS/DTLS Requirements

- **OpenSSL 1.1.1+** or **LibreSSL** with TLS 1.3 support
- TLS 1.3-only by default (configurable)
- DTLS 1.2 minimum for secure UDP

## Quick Start

### Building

```bash
# Basic build
cmake -S . -B build
cmake --build build -j

# Run tests
cd build && ctest --output-on-failure

# Build with TLS support (auto-detects OpenSSL/LibreSSL)
cmake -S . -B build -DENABLE_TLS=ON

# Build with sanitizers for debugging
cmake -S . -B build -DENABLE_SANITIZERS=ON

# Build with fuzzing support (requires Clang)
cmake -S . -B build -DENABLE_FUZZING=ON -DCMAKE_C_COMPILER=clang
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

### HTTP Client

```c
#include "http/SocketHTTPClient.h"

/* Simple GET request */
SocketHTTPClient_T client = SocketHTTPClient_new(NULL);
SocketHTTPClient_Response_T resp = SocketHTTPClient_get(client, "https://example.com/api");

printf("Status: %d\n", SocketHTTPClient_Response_status(resp));
printf("Body: %.*s\n", 
       (int)SocketHTTPClient_Response_body_len(resp),
       SocketHTTPClient_Response_body(resp));

SocketHTTPClient_Response_free(&resp);

/* Request builder pattern */
SocketHTTPClient_Request_T req = SocketHTTPClient_Request_new(client, "POST", "https://api.example.com/data");
SocketHTTPClient_Request_header(req, "Content-Type", "application/json");
SocketHTTPClient_Request_body(req, "{\"key\": \"value\"}", 16);
SocketHTTPClient_Request_timeout(req, 30000);

resp = SocketHTTPClient_Request_execute(req);
SocketHTTPClient_Request_free(&req);
SocketHTTPClient_Response_free(&resp);

/* Authentication */
SocketHTTPClient_setauth(client, HTTPCLIENT_AUTH_BASIC, "user", "password");

/* Cookie jar */
SocketHTTPClient_CookieJar_T jar = SocketHTTPClient_CookieJar_new(NULL);
SocketHTTPClient_set_cookie_jar(client, jar);

SocketHTTPClient_free(&client);
```

### HTTP Server

```c
#include "http/SocketHTTPServer.h"

void handle_request(SocketHTTPServer_Request_T req, SocketHTTPServer_Response_T resp, void *data)
{
    const char *method = SocketHTTPServer_Request_method(req);
    const char *uri = SocketHTTPServer_Request_uri(req);
    
    if (strcmp(method, "GET") == 0 && strcmp(uri, "/") == 0) {
        SocketHTTPServer_Response_status(resp, 200);
        SocketHTTPServer_Response_header(resp, "Content-Type", "text/html");
        SocketHTTPServer_Response_body(resp, "<h1>Hello World</h1>", 20);
    } else {
        SocketHTTPServer_Response_status(resp, 404);
        SocketHTTPServer_Response_body(resp, "Not Found", 9);
    }
    
    SocketHTTPServer_Response_send(resp);
}

SocketHTTPServer_Config config = HTTPSERVER_CONFIG_DEFAULTS;
config.port = 8080;
config.max_connections = 1000;

SocketHTTPServer_T server = SocketHTTPServer_new(NULL, &config);
SocketHTTPServer_set_handler(server, handle_request, NULL);
SocketHTTPServer_start(server);

/* Event loop */
while (running) {
    SocketHTTPServer_poll(server, 1000);
}

SocketHTTPServer_stop(server);
SocketHTTPServer_free(&server);
```

### WebSocket Client

```c
#include "socket/SocketWS.h"

Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
Socket_connect(sock, "echo.websocket.org", 80);

SocketWS_Config ws_config = SOCKETWS_CONFIG_DEFAULTS;
SocketWS_T ws = SocketWS_client_new(sock, "echo.websocket.org", "/", &ws_config);

/* Perform handshake */
TRY
    SocketWS_handshake(ws);
    
    /* Send text message */
    SocketWS_send_text(ws, "Hello, WebSocket!", 17);
    
    /* Receive message */
    SocketWS_Message msg;
    if (SocketWS_recv_message(ws, &msg) == WS_OK) {
        printf("Received: %.*s\n", (int)msg.len, msg.data);
        SocketWS_Message_free(&msg);
    }
    
    /* Graceful close */
    SocketWS_close(ws, WS_CLOSE_NORMAL, "Goodbye", 7);
EXCEPT(SocketWS_Failed)
    fprintf(stderr, "WebSocket error: %s\n", Socket_GetLastError());
END_TRY;

SocketWS_free(&ws);
Socket_free(&sock);
```

### WebSocket Server

```c
#include "socket/SocketWS.h"
#include "http/SocketHTTP1.h"

/* Check if request is WebSocket upgrade */
if (SocketWS_is_upgrade(headers)) {
    SocketWS_Config ws_config = SOCKETWS_CONFIG_DEFAULTS;
    SocketWS_T ws = SocketWS_server_accept(client_socket, headers, &ws_config);
    
    if (ws) {
        /* WebSocket connection established */
        while (SocketWS_state(ws) == WS_STATE_OPEN) {
            SocketWS_Message msg;
            int result = SocketWS_recv_message(ws, &msg);
            
            if (result == WS_OK) {
                /* Echo back */
                if (msg.opcode == WS_OPCODE_TEXT) {
                    SocketWS_send_text(ws, msg.data, msg.len);
                } else if (msg.opcode == WS_OPCODE_BINARY) {
                    SocketWS_send_binary(ws, msg.data, msg.len);
                }
                SocketWS_Message_free(&msg);
            }
        }
        SocketWS_free(&ws);
    }
} else {
    SocketWS_server_reject(client_socket, 400, "Bad Request");
}
```

### Proxy Tunneling

```c
#include "socket/SocketProxy.h"

/* SOCKS5 proxy configuration */
SocketProxy_Config proxy = {0};
proxy.type = SOCKET_PROXY_SOCKS5;
proxy.host = "proxy.example.com";
proxy.port = 1080;
proxy.username = "user";
proxy.password = "secret";

Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);

/* Connect through proxy (synchronous) */
SocketProxy_Result result = SocketProxy_connect(sock, &proxy, "target.example.com", 443);
if (result == PROXY_OK) {
    /* Socket is now tunneled - proceed with TLS handshake if needed */
    SocketTLS_enable(sock, tls_ctx);
    SocketTLS_handshake_loop(sock, 10000);
}

/* HTTP CONNECT proxy */
SocketProxy_Config http_proxy = {0};
http_proxy.type = SOCKET_PROXY_HTTP;
http_proxy.host = "httpproxy.example.com";
http_proxy.port = 8080;
http_proxy.username = "user";
http_proxy.password = "pass";

/* Asynchronous proxy connection */
SocketProxy_Conn_T conn = SocketProxy_Conn_new(sock, &http_proxy, "target.com", 443);
while (!SocketProxy_Conn_poll(conn)) {
    int timeout = SocketProxy_Conn_next_timeout_ms(conn);
    SocketPoll_wait(poll, &events, timeout);
    SocketProxy_Conn_process(conn);
}
result = SocketProxy_Conn_result(conn);
SocketProxy_Conn_free(&conn);
```

### DTLS (Secure UDP)

```c
#include "tls/SocketDTLS.h"
#include "tls/SocketDTLSContext.h"
#include "socket/SocketDgram.h"

/* DTLS Client */
SocketDgram_T sock = SocketDgram_new(AF_INET, 0);
SocketDgram_connect(sock, "server.example.com", 5684);

SocketDTLSContext_T ctx = SocketDTLSContext_new_client("ca-bundle.crt");
SocketDTLS_enable(sock, ctx);
SocketDTLS_set_hostname(sock, "server.example.com");

DTLSHandshakeState state = SocketDTLS_handshake_loop(sock, 5000);
if (state == DTLS_HANDSHAKE_COMPLETE) {
    /* Send encrypted datagram */
    SocketDTLS_send(sock, "Hello DTLS", 10);
    
    char buf[1024];
    ssize_t n = SocketDTLS_recv(sock, buf, sizeof(buf));
}

SocketDTLS_shutdown(sock);
SocketDgram_free(&sock);
SocketDTLSContext_free(&ctx);

/* DTLS Server with cookie exchange */
SocketDgram_T server = SocketDgram_new(AF_INET, 0);
SocketDgram_bind(server, "0.0.0.0", 5684);

SocketDTLSContext_T srv_ctx = SocketDTLSContext_new_server("cert.pem", "key.pem", NULL);
SocketDTLSContext_enable_cookie_exchange(srv_ctx);  /* DoS protection */
SocketDTLS_enable(server, srv_ctx);

/* Handle incoming connections with SocketDTLS_listen() */
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

### SYN Flood Protection

```c
#include "core/SocketSYNProtect.h"

SocketSYNProtect_Config config = SYNPROTECT_CONFIG_DEFAULTS;
config.max_connections_per_ip = 10;
config.connection_rate_limit = 100;
config.challenge_threshold = 0.5;  /* Reputation score threshold */
config.block_threshold = 0.2;

SocketSYNProtect_T protect = SocketSYNProtect_new(NULL, &config);

/* On each incoming connection */
struct sockaddr_in client_addr;
socklen_t addr_len = sizeof(client_addr);
int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);

SYNAction action = SocketSYNProtect_check(protect, &client_addr, addr_len);

switch (action) {
case SYN_ACTION_ALLOW:
    /* Accept connection normally */
    break;
case SYN_ACTION_THROTTLE:
    /* Accept but add delay */
    usleep(100000);
    break;
case SYN_ACTION_CHALLENGE:
    /* Send SYN cookie / challenge */
    break;
case SYN_ACTION_BLOCK:
    /* Reject connection */
    close(client_fd);
    break;
}

/* Report connection result for reputation update */
SocketSYNProtect_report(protect, &client_addr, addr_len, success);

/* Get statistics */
SocketSYNProtect_Stats stats;
SocketSYNProtect_stats(protect, &stats);

SocketSYNProtect_free(&protect);
```

### Graceful Shutdown

```c
#include "pool/SocketPool.h"

/* Non-blocking drain for event loops */
SocketPool_drain(pool, 30000);  /* Start 30s drain */
while (SocketPool_drain_poll(pool) > 0) {
    SocketPoll_wait(poll, &events, SocketPool_drain_remaining_ms(pool));
    /* Process remaining events, connections closing naturally */
}
SocketPool_free(&pool);

/* Blocking drain (convenience) */
int result = SocketPool_drain_wait(pool, 30000);
if (result < 0) {
    /* Timeout - connections were force-closed */
}

/* Health check for load balancers */
SocketPool_Health health = SocketPool_health(pool);
if (health == POOL_HEALTH_DRAINING) {
    /* Return 503 to load balancer */
}
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

### Unix Domain Sockets with FD Passing

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

/* File descriptor passing (SCM_RIGHTS) */
int fd_to_pass = open("/etc/passwd", O_RDONLY);
Socket_sendfd(sock1, fd_to_pass, "hello", 5);
close(fd_to_pass);

/* Receive passed FD */
int received_fd;
char buf[256];
ssize_t n = Socket_recvfd(sock2, &received_fd, buf, sizeof(buf));
/* received_fd is now a valid FD in this process */
close(received_fd);

/* Multiple FD passing */
int fds[3] = {fd1, fd2, fd3};
Socket_sendfds(sock1, fds, 3, "data", 4);

int received_fds[3];
int num_fds;
Socket_recvfds(sock2, received_fds, 3, &num_fds, buf, sizeof(buf));
```

### Cryptographic Utilities

```c
#include "core/SocketCrypto.h"

/* SHA-256 hash */
unsigned char hash[SOCKET_CRYPTO_SHA256_SIZE];
SocketCrypto_sha256(data, data_len, hash);

/* HMAC-SHA256 */
unsigned char mac[SOCKET_CRYPTO_SHA256_SIZE];
SocketCrypto_hmac_sha256(key, key_len, data, data_len, mac);

/* Base64 encoding */
size_t encoded_len = SocketCrypto_base64_encoded_size(data_len);
char *encoded = malloc(encoded_len);
SocketCrypto_base64_encode(data, data_len, encoded, encoded_len);

/* Cryptographically secure random */
unsigned char random_bytes[32];
SocketCrypto_random_bytes(random_bytes, sizeof(random_bytes));

/* Constant-time comparison (prevents timing attacks) */
if (SocketCrypto_secure_compare(expected, actual, len)) {
    /* Match */
}

/* Secure memory clearing */
SocketCrypto_secure_clear(password, password_len);
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

#### SocketCrypto (Cryptographic Utilities)
- `SocketCrypto_sha1()` / `SocketCrypto_sha256()` / `SocketCrypto_md5()` - Hash functions
- `SocketCrypto_hmac_sha256()` - HMAC message authentication
- `SocketCrypto_base64_encode()` / `SocketCrypto_base64_decode()` - Base64 encoding
- `SocketCrypto_hex_encode()` / `SocketCrypto_hex_decode()` - Hexadecimal encoding
- `SocketCrypto_random_bytes()` - Cryptographically secure random
- `SocketCrypto_secure_compare()` - Constant-time comparison
- `SocketCrypto_secure_clear()` - Secure memory clearing
- `SocketCrypto_websocket_key()` / `SocketCrypto_websocket_accept()` - WebSocket handshake

#### SocketUTF8 (UTF-8 Validation)
- `SocketUTF8_validate()` - One-shot validation
- `SocketUTF8_init()` / `_update()` / `_finish()` - Incremental validation
- `SocketUTF8_encode()` / `SocketUTF8_decode()` - Codepoint conversion

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

#### File Descriptor Passing (Unix Domain)
- `Socket_sendfd()` / `Socket_recvfd()` - Single FD passing
- `Socket_sendfds()` / `Socket_recvfds()` - Multiple FD passing

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

#### Graceful Shutdown
- `SocketPool_drain()` - Start non-blocking drain
- `SocketPool_drain_poll()` - Poll drain progress
- `SocketPool_drain_wait()` - Blocking drain
- `SocketPool_drain_force()` - Force-close all connections
- `SocketPool_drain_remaining_ms()` - Time until forced shutdown
- `SocketPool_state()` / `SocketPool_health()` - State queries
- `SocketPool_set_drain_callback()` - Completion callback

#### Reconnection
- `SocketPool_set_reconnect_policy()` - Set default reconnection policy
- `SocketPool_enable_reconnect()` / `SocketPool_disable_reconnect()` - Per-connection
- `SocketPool_process_reconnects()` - Process reconnection state machines
- `SocketPool_reconnect_timeout_ms()` - Get next timeout

#### Connection Accessors
- `Connection_socket()` - Get connection's socket
- `Connection_inbuf()` / `Connection_outbuf()` - Get I/O buffers
- `Connection_data()` / `Connection_setdata()` - User data
- `Connection_lastactivity()` - Last activity time
- `Connection_isactive()` - Check if active

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

### SocketProxy Module (Proxy Tunneling)

#### Configuration
- `SocketProxy_parse_url()` - Parse proxy URL (socks5://user:pass@host:port)

#### Synchronous API
- `SocketProxy_connect()` - Connect through proxy
- `SocketProxy_connect_tls()` - Connect through proxy with TLS to target

#### Asynchronous API
- `SocketProxy_Conn_new()` - Create async proxy connection
- `SocketProxy_Conn_free()` - Free connection
- `SocketProxy_Conn_poll()` - Check if complete
- `SocketProxy_Conn_process()` - Process events
- `SocketProxy_Conn_result()` - Get result
- `SocketProxy_Conn_next_timeout_ms()` - Get next timeout
- `SocketProxy_Conn_poll_events()` - Get poll events

### HTTP Modules

#### SocketHTTP (HTTP Core - RFC 9110)
- `SocketHTTP_method_*()` - Method utilities (safe, idempotent, cacheable)
- `SocketHTTP_status_*()` - Status code utilities
- `SocketHTTP_Headers_new()` / `_free()` - Header collection lifecycle
- `SocketHTTP_Headers_add()` / `_get()` / `_remove()` - Header management
- `SocketHTTP_URI_parse()` - RFC 3986 URI parsing
- `SocketHTTP_date_parse()` - HTTP-date parsing

#### SocketHTTP1 (HTTP/1.1 - RFC 9112)
- `SocketHTTP1_Parser_new()` / `_free()` - Parser lifecycle
- `SocketHTTP1_Parser_execute()` - Incremental parsing
- `SocketHTTP1_Parser_reset()` - Reset parser state
- `SocketHTTP1_serialize_request()` / `_response()` - Serialization
- `SocketHTTP1_chunk_encode()` / `_final()` - Chunked encoding

#### SocketHPACK (Header Compression - RFC 7541)
- `SocketHPACK_Encoder_new()` / `_free()` - Encoder lifecycle
- `SocketHPACK_Encoder_encode()` - Encode headers
- `SocketHPACK_Decoder_new()` / `_free()` - Decoder lifecycle
- `SocketHPACK_Decoder_decode()` - Decode headers
- `SocketHPACK_huffman_encode()` / `_decode()` - Huffman coding

#### SocketHTTP2 (HTTP/2 - RFC 9113)
- `SocketHTTP2_Conn_new()` / `_free()` - Connection lifecycle
- `SocketHTTP2_Conn_handshake()` - Connection preface exchange
- `SocketHTTP2_Conn_process()` - Frame processing
- `SocketHTTP2_Conn_settings()` / `_ping()` / `_goaway()` - Control frames
- `SocketHTTP2_Stream_new()` - Create stream
- `SocketHTTP2_Stream_send_headers()` / `_send_data()` - Send data
- `SocketHTTP2_Stream_recv_headers()` / `_recv_data()` - Receive data

#### SocketHTTPClient (HTTP Client API)
- `SocketHTTPClient_new()` / `_free()` - Client lifecycle
- `SocketHTTPClient_get()` / `_post()` / `_put()` / `_delete()` / `_head()` - Simple API
- `SocketHTTPClient_Request_new()` / `_execute()` - Request builder
- `SocketHTTPClient_Request_header()` / `_body()` / `_timeout()` - Request configuration
- `SocketHTTPClient_setauth()` - Authentication
- `SocketHTTPClient_CookieJar_*()` - Cookie management

#### SocketHTTPServer (HTTP Server API)
- `SocketHTTPServer_new()` / `_free()` - Server lifecycle
- `SocketHTTPServer_start()` / `_stop()` - Server control
- `SocketHTTPServer_set_handler()` - Set request handler
- `SocketHTTPServer_poll()` / `_process()` - Event loop
- `SocketHTTPServer_Request_*()` - Request accessors
- `SocketHTTPServer_Response_*()` - Response building

### SocketWS Module (WebSocket - RFC 6455)

#### Client API
- `SocketWS_client_new()` - Create WebSocket client
- `SocketWS_handshake()` - Perform handshake

#### Server API
- `SocketWS_is_upgrade()` - Check for WebSocket upgrade
- `SocketWS_server_accept()` - Accept WebSocket connection
- `SocketWS_server_reject()` - Reject upgrade request

#### Message I/O
- `SocketWS_send_text()` / `SocketWS_send_binary()` - Send messages
- `SocketWS_recv_message()` - Receive message
- `SocketWS_Message_free()` - Free message

#### Control Frames
- `SocketWS_ping()` / `SocketWS_pong()` - Ping/pong
- `SocketWS_close()` - Initiate close

#### Event Loop
- `SocketWS_pollfd()` - Get poll file descriptor
- `SocketWS_poll_events()` - Get poll events
- `SocketWS_process()` - Process events
- `SocketWS_state()` - Get connection state
- `SocketWS_free()` - Free connection

### TLS Modules

#### SocketTLS (TLS Operations)
- `SocketTLS_enable()` - Enable TLS on socket
- `SocketTLS_set_hostname()` - Set SNI hostname
- `SocketTLS_handshake()` - Perform handshake step
- `SocketTLS_handshake_loop()` - Complete handshake with timeout
- `SocketTLS_shutdown()` - Graceful TLS shutdown
- `SocketTLS_send()` / `SocketTLS_recv()` - Encrypted I/O
- `SocketTLS_get_cipher()` - Get negotiated cipher
- `SocketTLS_get_version()` - Get TLS version
- `SocketTLS_get_verify_result()` - Get verification result
- `SocketTLS_is_session_reused()` - Check session resumption
- `SocketTLS_get_alpn_selected()` - Get negotiated ALPN protocol

#### SocketTLSContext (TLS Context)
- `SocketTLSContext_new_server()` / `_new_client()` - Create context
- `SocketTLSContext_free()` - Free context
- `SocketTLSContext_load_certificate()` - Load cert/key pair
- `SocketTLSContext_add_certificate()` - Add SNI certificate
- `SocketTLSContext_load_ca()` - Load CA certificates
- `SocketTLSContext_set_verify_mode()` - Set verification policy
- `SocketTLSContext_load_crl()` / `_refresh_crl()` - CRL management
- `SocketTLSContext_set_ocsp_response()` - OCSP stapling
- `SocketTLSContext_set_alpn_protos()` - ALPN protocols
- `SocketTLSContext_enable_session_cache()` - Session caching
- `SocketTLSContext_enable_session_tickets()` - Session tickets

#### SocketDTLS (DTLS Operations)
- `SocketDTLS_enable()` - Enable DTLS on UDP socket
- `SocketDTLS_set_hostname()` - Set SNI hostname
- `SocketDTLS_handshake()` / `SocketDTLS_handshake_loop()` - Handshake
- `SocketDTLS_send()` / `SocketDTLS_recv()` - Encrypted I/O
- `SocketDTLS_shutdown()` - Graceful shutdown

#### SocketDTLSContext (DTLS Context)
- `SocketDTLSContext_new_server()` / `_new_client()` - Create context
- `SocketDTLSContext_free()` - Free context
- `SocketDTLSContext_enable_cookie_exchange()` - DoS protection

### Security Modules

#### SocketSYNProtect (SYN Flood Protection)
- `SocketSYNProtect_new()` / `_free()` - Lifecycle
- `SocketSYNProtect_check()` - Check connection (returns action)
- `SocketSYNProtect_report()` - Report connection result
- `SocketSYNProtect_stats()` - Get statistics
- `SocketSYNProtect_reset()` - Reset all state

#### SocketIPTracker (Per-IP Tracking)
- `SocketIPTracker_new()` / `_free()` - Lifecycle
- `SocketIPTracker_track()` - Track connection from IP
- `SocketIPTracker_release()` - Release connection
- `SocketIPTracker_count()` - Get connection count for IP
- `SocketIPTracker_allowed()` - Check if connection allowed
- `SocketIPTracker_cleanup()` - Remove stale entries

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

#### Core Exceptions
- `Socket_Failed` - General socket operation failure
- `Socket_Closed` - Connection closed by peer
- `SocketUnix_Failed` - Unix socket operation failure
- `SocketDgram_Failed` - UDP socket operation failure
- `SocketPoll_Failed` - Event polling failure
- `SocketPool_Failed` - Connection pool operation failure
- `SocketDNS_Failed` - DNS resolution failure
- `SocketTimer_Failed` - Timer operation failure
- `SocketRateLimit_Failed` - Rate limiter failure
- `SocketAsync_Failed` - Async I/O failure
- `SocketCrypto_Failed` - Cryptographic operation failure

#### Connection Exceptions
- `SocketHE_Failed` - Happy Eyeballs connection failure
- `SocketReconnect_Failed` - Reconnection operation failure
- `SocketProxy_Failed` - Proxy connection failure

#### TLS/DTLS Exceptions
- `SocketTLS_Failed` - General TLS operation failure
- `SocketTLS_HandshakeFailed` - TLS handshake failure
- `SocketTLS_VerifyFailed` - Certificate verification failure
- `SocketTLS_ProtocolError` - TLS protocol error
- `SocketTLS_ShutdownFailed` - TLS shutdown failure
- `SocketDTLS_Failed` - General DTLS operation failure
- `SocketDTLS_HandshakeFailed` - DTLS handshake failure
- `SocketDTLS_VerifyFailed` - DTLS certificate verification failure
- `SocketDTLS_CookieFailed` - DTLS cookie exchange failure
- `SocketDTLS_TimeoutExpired` - DTLS handshake timeout

#### HTTP Exceptions
- `SocketHTTP_ParseError` - HTTP parsing error
- `SocketHTTP_InvalidURI` - Invalid URI
- `SocketHTTP_InvalidHeader` - Invalid header
- `SocketHTTP1_ParseError` - HTTP/1.1 parsing error
- `SocketHPACK_Failed` - HPACK compression error
- `SocketHTTP2_ProtocolError` - HTTP/2 protocol error
- `SocketHTTP2_StreamError` - HTTP/2 stream error
- `SocketHTTP2_FlowControlError` - HTTP/2 flow control error
- `SocketHTTPClient_Failed` - HTTP client failure
- `SocketHTTPClient_Timeout` - HTTP client timeout
- `SocketHTTPClient_TLSError` - HTTP client TLS error
- `SocketHTTPServer_Failed` - HTTP server failure

#### WebSocket Exceptions
- `SocketWS_Failed` - WebSocket operation failure
- `SocketWS_ProtocolError` - WebSocket protocol error
- `SocketWS_Closed` - WebSocket connection closed

#### Security Exceptions
- `SocketSYNProtect_Failed` - SYN protection failure

## Building

### Requirements

- CMake 3.10+
- C11 compiler with GNU extensions and pthread support
- POSIX-compliant system
- OpenSSL 1.1.1+ or LibreSSL (optional, for TLS/DTLS support)
- zlib (optional, for HTTP compression and WebSocket permessage-deflate)

### Build Commands

```bash
# Configure
cmake -S . -B build

# Build
cmake --build build -j

# Run tests
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
| `ENABLE_TLS` | Enable TLS/DTLS support | ON (auto-detect) |
| `ENABLE_HTTP_COMPRESSION` | Enable gzip/deflate/brotli | OFF |
| `ENABLE_SANITIZERS` | Enable ASan + UBSan | OFF |
| `ENABLE_ASAN` | Enable AddressSanitizer only | OFF |
| `ENABLE_UBSAN` | Enable UndefinedBehaviorSanitizer only | OFF |
| `ENABLE_COVERAGE` | Enable gcov coverage | OFF |
| `ENABLE_FUZZING` | Enable fuzz testing (requires Clang) | OFF |

### Poll Backend Selection

The poll backend is automatically selected based on platform:
- **Linux** - epoll (fastest for Linux)
- **BSD/macOS** - kqueue
- **Other POSIX** - poll(2) fallback

### Async I/O Backend Selection

- **Linux 5.1+** - io_uring (true async)
- **BSD/macOS** - kqueue AIO
- **Fallback** - Edge-triggered polling

## Thread Safety

| Component | Thread Safety | Notes |
|-----------|---------------|-------|
| Socket operations | Per-socket | One thread per socket recommended |
| Error reporting | Thread-local | Safe for concurrent use |
| SocketPoll | Thread-safe | Protected by mutexes |
| SocketPool | Thread-safe | Protected by mutexes |
| SocketDNS | Thread-safe | Uses thread pool |
| SocketTimer | Thread-safe | Integrated with poll |
| SocketRateLimit | Thread-safe | Internal mutex |
| Metrics/Logging | Thread-safe | Atomic operations |
| SocketCrypto | Thread-safe | No global state |
| SocketUTF8 | Thread-safe | No global state |
| SocketHappyEyeballs | NOT thread-safe | One instance per thread |
| SocketReconnect | NOT thread-safe | One instance per thread |
| SocketProxy | NOT thread-safe | One instance per thread |
| SocketWS | NOT thread-safe | One instance per thread |
| HTTP/2 connections | NOT thread-safe | One instance per thread |
| HTTP client | Thread-safe | Request instances are NOT |
| HTTP server | NOT thread-safe | One instance per thread |
| TLS/DTLS contexts | Thread-safe | Read-only after setup |

## Memory Management

The library uses **arena allocation** for related objects. Sockets and their associated resources are managed through arenas, ensuring efficient memory usage and automatic cleanup.

```c
Arena_T arena = Arena_new();
Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);
/* Socket uses arena internally */
Socket_free(&socket);  /* Frees socket and internal arena */
Arena_dispose(&arena); /* Free external arena if used */
```

Key patterns:
- Use `Arena_alloc()` / `Arena_calloc()` for object lifecycle management
- Use `Arena_dispose()` to free entire contexts at once
- All arithmetic checked for integer overflow
- Use `SocketCrypto_secure_clear()` for sensitive data

## Performance Considerations

### I/O Performance
- **Zero-copy I/O** - Uses platform-specific `sendfile()` when available
- **Scatter/gather I/O** - Efficient multi-buffer operations via `writev()`/`readv()`
- **Event polling** - O(1) event delivery with epoll/kqueue
- **Edge-triggered mode** - Minimal syscall overhead

### Data Structures
- **Connection pooling** - O(1) lookup with hash tables
- **Timers** - O(log n) insert/cancel with min-heap
- **HPACK** - O(1) FIFO dynamic table with circular buffer

### Parsing
- **DFA-based parsing** - O(n) HTTP/1.1 and UTF-8 validation
- **Table-driven** - Minimal branch misprediction
- **Incremental** - Stream-friendly, no full buffering required

### Protocol Efficiency
- **HTTP/2 multiplexing** - Single connection for concurrent requests
- **HPACK compression** - Reduces header overhead by 85-90%
- **WebSocket framing** - 8-byte aligned XOR masking
- **Session resumption** - TLS/DTLS session caching reduces handshake overhead

### Async Operations
- **io_uring** - True async I/O on Linux 5.1+
- **Non-blocking DNS** - Thread pool prevents blocking
- **Happy Eyeballs** - Parallel connection attempts for minimal latency

## Testing and Quality

### Test Suite

The library includes comprehensive tests in `src/test/`:

| Category | Test Files |
|----------|------------|
| Core | `test_arena.c`, `test_except.c`, `test_crypto.c`, `test_utf8.c` |
| Socket | `test_socket.c`, `test_socketdgram.c`, `test_socketbuf.c` |
| Networking | `test_socketpoll.c`, `test_socketpool.c`, `test_socketdns.c` |
| Connection | `test_happy_eyeballs.c`, `test_reconnect.c`, `test_proxy.c` |
| HTTP | `test_http_core.c`, `test_http1_parser.c`, `test_hpack.c`, `test_http2.c` |
| WebSocket | `test_websocket.c`, `test_ws_integration.c` |
| TLS/DTLS | `test_tls_integration.c`, `test_dtls_integration.c` |
| Security | `test_synprotect.c`, `test_ratelimit.c`, `test_security.c` |
| Integration | `test_integration.c`, `test_http_integration.c`, `test_proxy_integration.c` |

### Fuzz Testing

24+ fuzz harnesses in `src/fuzz/` covering:
- HTTP/1.1 parser
- HTTP/2 frame parsing
- HPACK encoder/decoder
- WebSocket framing
- URI parsing
- UTF-8 validation
- TLS handshake

```bash
# Build with fuzzing
cmake -S . -B build -DENABLE_FUZZING=ON -DCMAKE_C_COMPILER=clang
cmake --build build

# Run parallel fuzzing
./scripts/run_fuzz_parallel.sh
```

### Sanitizers

All tests pass with:
- AddressSanitizer (ASan)
- UndefinedBehaviorSanitizer (UBSan)
- Valgrind memory checking

```bash
# Build with sanitizers
cmake -S . -B build -DENABLE_SANITIZERS=ON
cmake --build build
cd build && ctest --output-on-failure

# Valgrind
valgrind --leak-check=full --track-fds=yes \
    --suppressions=../valgrind.supp ./test_socket
```

### Continuous Integration

GitHub Actions pipeline (`.github/workflows/ci.yml`):

| Job | Platform | Description |
|-----|----------|-------------|
| `build` | Ubuntu | Debug and Release builds |
| `sanitizers` | Ubuntu | ASan, UBSan, combined |
| `valgrind` | Ubuntu | Memory leak checking |
| `macos` | macOS | kqueue backend testing |
| `macos-sanitizers` | macOS | Cross-platform sanitizers |
| `coverage` | Ubuntu | Code coverage with lcov |
| `static-analysis` | Ubuntu | cppcheck + clang-tidy |

## Documentation

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

### Additional Documentation

- **[RELEASE_NOTES.md](RELEASE_NOTES.md)** - Release history and changelog
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contribution guidelines
- **[docs/](docs/)** - Detailed feature documentation
  - `HTTP.md` - HTTP stack documentation
  - `WEBSOCKET.md` - WebSocket implementation details
  - `ASYNC_IO.md` - Async I/O patterns
  - `PROXY.md` - Proxy tunneling guide
  - `SECURITY.md` - Security features and hardening
  - `MIGRATION.md` - API migration guide

## License

See `LICENSE` for usage details.
