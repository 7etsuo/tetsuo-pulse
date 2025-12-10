# Socket Library

High-performance, exception-driven socket toolkit for POSIX systems. Provides a clean, modern C API for TCP, UDP, Unix domain sockets, HTTP/1.1, HTTP/2, WebSocket, and TLS/DTLS with comprehensive error handling, zero-copy I/O, and cross-platform event polling.

## Features

### Core Networking
- **TCP Stream Sockets** - Full-featured TCP client/server with scatter/gather I/O
- **UDP Datagram Sockets** - Connectionless and connected modes with multicast/broadcast
- **Unix Domain Sockets** - IPC sockets with peer credential support and file descriptor passing
- **TLS 1.3 Support** - Modern TLS with SNI, ALPN, session resumption, CRL/OCSP, certificate pinning, Certificate Transparency (CT)
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
- **Circular Buffer I/O** - Zero-copy buffering for network operations
- **Asynchronous I/O** - Platform-optimized async operations (io_uring/kqueue)
- **Asynchronous DNS** - Non-blocking resolution with thread pool and timeouts
- **UTF-8 Validation** - Security-focused UTF-8 processing for WebSocket text frames
- **Generic Retry Framework** - Exponential backoff with jitter for resilient operations
- **Per-IP Connection Tracking** - Connection limits and rate limiting per client IP
- **Zero-Copy I/O** - Platform-optimized `sendfile()` and scatter/gather I/O
- **Observability** - Pluggable logging, Prometheus/StatsD/JSON metrics export, event dispatching
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
        printf("Server listening on port 8080...\n");
        
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
        printf("Connected to server\n");
        
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

### Convenience Functions (One-Call Setup)

For common use cases, convenience functions simplify socket setup:

```c
#include "socket/Socket.h"
#include "socket/SocketDgram.h"

/* TCP Server - one call creates listening socket */
Socket_T server = Socket_listen_tcp("0.0.0.0", 8080, 128);
while (running) {
    Socket_T client = Socket_accept_timeout(server, 1000);  // 1s timeout
    if (client) handle_client(client);
}
Socket_free(&server);

/* TCP Client with timeout - one call connects */
Socket_T client = Socket_connect_tcp("api.example.com", 443, 5000);  // 5s timeout
Socket_sendall(client, request, len);
Socket_free(&client);

/* UDP Server - one call binds */
SocketDgram_T udp = SocketDgram_bind_udp("0.0.0.0", 5353);
SocketDgram_recvfrom(udp, buf, sizeof(buf), sender_ip, sizeof(sender_ip), &sender_port);
SocketDgram_free(&udp);

/* Unix Domain Server */
Socket_T unix_srv = Socket_listen_unix("/var/run/app.sock", 128);
Socket_free(&unix_srv);

/* Unix Domain Client with timeout */
Socket_T unix_cli = Socket_new(AF_UNIX, SOCK_STREAM, 0);
Socket_connect_unix_timeout(unix_cli, "/var/run/app.sock", 5000);
Socket_free(&unix_cli);

/* Non-blocking connect (for event loops) */
Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
int status = Socket_connect_nonblocking(sock, "192.168.1.1", 8080);
if (status == 1) {
    /* In progress - poll for POLL_WRITE then check Socket_isconnected() */
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
    if (Socket_error_is_retryable(Socket_geterrno()))
        /* Schedule retry with backoff */
    else
        fprintf(stderr, "Fatal error: %s\n", Socket_Failed.reason);
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
SocketHTTPClient_Response response = {0};

if (SocketHTTPClient_get(client, "https://example.com/api", &response) == 0) {
    printf("Status: %d\n", response.status_code);
    printf("Body: %.*s\n", (int)response.body_len, (char *)response.body);
}
SocketHTTPClient_Response_free(&response);

/* Request builder pattern */
SocketHTTPClient_Request_T req = SocketHTTPClient_Request_new(
    client, HTTP_METHOD_POST, "https://api.example.com/data");
SocketHTTPClient_Request_header(req, "Content-Type", "application/json");
SocketHTTPClient_Request_body(req, "{\"key\": \"value\"}", 16);
SocketHTTPClient_Request_timeout(req, 30000);

if (SocketHTTPClient_Request_execute(req, &response) == 0) {
    printf("POST Status: %d\n", response.status_code);
}
SocketHTTPClient_Request_free(&req);
SocketHTTPClient_Response_free(&response);

/* Cookie jar */
SocketHTTPClient_CookieJar_T jar = SocketHTTPClient_CookieJar_new();
SocketHTTPClient_set_cookie_jar(client, jar);

SocketHTTPClient_free(&client);
```

### HTTP Client Convenience Functions

```c
#include "http/SocketHTTPClient.h"

SocketHTTPClient_T client = SocketHTTPClient_new(NULL);

/* Download file from URL */
int ret = SocketHTTPClient_download(client, 
    "https://example.com/file.zip", "/tmp/file.zip");
if (ret == 0) {
    printf("Download complete\n");
} else if (ret == -1) {
    printf("HTTP error\n");
} else {
    printf("File error: %s\n", strerror(errno));
}

/* Upload file to URL */
int status = SocketHTTPClient_upload(client,
    "https://storage.example.com/files/upload.dat",
    "/path/to/local/file.dat");
if (status >= 200 && status < 300) {
    printf("Upload successful (HTTP %d)\n", status);
}

/* JSON API calls */
char *json_response = NULL;
size_t json_len;

/* GET JSON */
status = SocketHTTPClient_json_get(client,
    "https://api.example.com/users/123", &json_response, &json_len);
if (status == 200 && json_response) {
    printf("User data: %s\n", json_response);
    free(json_response);
}

/* POST JSON */
const char *request_body = "{\"name\": \"John\", \"email\": \"john@example.com\"}";
status = SocketHTTPClient_json_post(client,
    "https://api.example.com/users", request_body, &json_response, &json_len);
if (status == 201 && json_response) {
    printf("Created: %s\n", json_response);
    free(json_response);
}

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

### HTTP Server Middleware & Static Files

```c
#include "http/SocketHTTPServer.h"

/* Logging middleware */
int log_middleware(SocketHTTPServer_Request_T req, void *data) {
    printf("[%s] %s\n",
           SocketHTTP_method_name(SocketHTTPServer_Request_method(req)),
           SocketHTTPServer_Request_path(req));
    return 0;  /* Continue to next middleware/handler */
}

/* Authentication middleware */
int auth_middleware(SocketHTTPServer_Request_T req, void *data) {
    const char *token = SocketHTTPServer_Request_header(req, "Authorization");
    if (!token) {
        SocketHTTPServer_Request_status(req, 401);
        SocketHTTPServer_Request_body_data(req, "Unauthorized", 12);
        SocketHTTPServer_Request_finish(req);
        return 1;  /* Stop chain - request handled */
    }
    return 0;  /* Continue */
}

/* Custom error handler */
void error_handler(SocketHTTPServer_Request_T req, int code, void *data) {
    char body[256];
    snprintf(body, sizeof(body),
             "<html><body><h1>Error %d</h1></body></html>", code);
    SocketHTTPServer_Request_header(req, "Content-Type", "text/html");
    SocketHTTPServer_Request_body_data(req, body, strlen(body));
    SocketHTTPServer_Request_finish(req);
}

SocketHTTPServer_T server = SocketHTTPServer_new(NULL, &config);

/* Add middleware chain */
SocketHTTPServer_add_middleware(server, log_middleware, NULL);
SocketHTTPServer_add_middleware(server, auth_middleware, &auth_config);

/* Serve static files */
SocketHTTPServer_add_static_dir(server, "/static", "./public");
SocketHTTPServer_add_static_dir(server, "/assets", "/var/www/assets");

/* Set custom error pages */
SocketHTTPServer_set_error_handler(server, error_handler, NULL);

SocketHTTPServer_set_handler(server, handle_request, NULL);
SocketHTTPServer_start(server);
```

### HTTP/2 Stream Management

```c
#include "http/SocketHTTP2.h"

/* Check connection health with PING */
int rtt = SocketHTTP2_Conn_ping_wait(conn, 5000);
if (rtt >= 0) {
    printf("Connection alive, RTT: %d ms\n", rtt);
} else {
    printf("Connection dead or timeout\n");
}

/* Monitor concurrent streams */
uint32_t active = SocketHTTP2_Conn_get_concurrent_streams(conn);
printf("Active streams: %u\n", active);

/* Limit concurrent streams (sends SETTINGS frame) */
SocketHTTP2_Conn_set_max_concurrent(conn, 50);

/* Check peer's stream limit */
uint32_t peer_max = SocketHTTP2_Conn_get_peer_setting(conn, 
    SETTINGS_IDX_MAX_CONCURRENT_STREAMS);
printf("Peer allows %u concurrent streams\n", peer_max);
```

### WebSocket Client

```c
#include "socket/SocketWS.h"

/* One-liner WebSocket connection (new convenience API) */
SocketWS_T ws = SocketWS_connect("wss://echo.websocket.org", NULL);
if (ws) {
    /* Send and receive JSON messages */
    SocketWS_send_json(ws, "{\"type\": \"hello\", \"data\": \"world\"}");
    
    char *json = NULL;
    size_t len;
    if (SocketWS_recv_json(ws, &json, &len) == WS_OK) {
        printf("Received: %s\n", json);
        free(json);
    }
    
    /* Check ping latency */
    SocketWS_ping(ws, "test", 4);
    SocketWS_process(ws, POLLIN);  /* Wait for pong */
    int64_t rtt = SocketWS_get_ping_latency(ws);
    printf("Latency: %lld ms\n", (long long)rtt);
    
    SocketWS_close(ws, WS_CLOSE_NORMAL, "Goodbye", 7);
    SocketWS_free(&ws);
}

/* Traditional multi-step connection */
Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
Socket_connect(sock, "echo.websocket.org", 80);

SocketWS_Config ws_config = SOCKETWS_CONFIG_DEFAULTS;
SocketWS_T ws2 = SocketWS_client_new(sock, "echo.websocket.org", "/", &ws_config);

/* Enable compression before handshake */
SocketWS_CompressionOptions comp_opts;
SocketWS_compression_options_defaults(&comp_opts);
comp_opts.level = 9;  /* Maximum compression */
SocketWS_enable_compression(ws2, &comp_opts);

/* Perform handshake */
TRY
    SocketWS_handshake(ws2);
    
    /* Send text message */
    SocketWS_send_text(ws2, "Hello, WebSocket!", 17);
    
    /* Graceful close */
    SocketWS_close(ws2, WS_CLOSE_NORMAL, "Goodbye", 7);
EXCEPT(SocketWS_Failed)
    fprintf(stderr, "WebSocket error: %s\n", SocketWS_Failed.reason);
END_TRY;

SocketWS_free(&ws2);
Socket_free(&sock);
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

/* Rate-limited accept with error handling */
Socket_T client = SocketPool_accept_limited(pool, server);
if (client) {
    Connection_T conn = SocketPool_add(pool, client);
    if (conn) {
        SocketBuf_T input = Connection_inbuf(conn);
        SocketBuf_T output = Connection_outbuf(conn);
        /* ... use connection ... */
    } else {
        /* Pool full or other error - cleanup to avoid leaks */
        const char *ip = Socket_getpeeraddr(client);
        SocketPool_release_ip(pool, ip);
        Socket_free(&client);
    }
}

/* Batch accept for high-throughput servers */
Socket_T accepted[32];
int count = SocketPool_accept_batch(pool, server, 32, accepted);

/* Clean up idle connections */
SocketPool_cleanup(pool, 300);  /* Remove idle > 300 seconds */

SocketPool_free(&pool);
Arena_dispose(&arena);
```

### Connection Pool Statistics & Filtering

```c
#include "pool/SocketPool.h"

/* Get pool statistics */
SocketPool_Stats stats;
SocketPool_get_stats(pool, &stats);
printf("Active: %zu, Idle: %zu, Reuse rate: %.1f%%\n",
       stats.current_active, stats.current_idle, stats.reuse_rate * 100.0);

/* Convenience stat functions */
size_t active = SocketPool_get_active_count(pool);
size_t idle = SocketPool_get_idle_count(pool);
double hit_rate = SocketPool_get_hit_rate(pool);

/* Find connections matching criteria */
int is_from_subnet(Connection_T conn, void *data) {
    const char *subnet = (const char *)data;
    return strncmp(Socket_getpeeraddr(Connection_socket(conn)), subnet, 7) == 0;
}

/* Find first matching connection */
Connection_T conn = SocketPool_find(pool, is_from_subnet, "192.168");

/* Get all matching connections */
Connection_T matches[100];
size_t count = SocketPool_filter(pool, is_from_subnet, "192.168", matches, 100);
for (size_t i = 0; i < count; i++) {
    /* Process matching connections */
}

/* Register idle callback */
void on_idle(Connection_T conn, void *data) {
    printf("Connection went idle: %s\n",
           Socket_getpeeraddr(Connection_socket(conn)));
}
SocketPool_set_idle_callback(pool, on_idle, NULL);

/* Shrink pool to release unused memory */
size_t released = SocketPool_shrink(pool);
printf("Released %zu unused slots\n", released);

/* Reset statistics for new measurement window */
SocketPool_reset_stats(pool);
```

### Circular Buffer Operations

```c
#include "socket/SocketBuf.h"

Arena_T arena = Arena_new();
SocketBuf_T buf = SocketBuf_new(arena, 4096);

/* Basic read/write */
SocketBuf_write(buf, "Hello, World!\n", 14);
printf("Available: %zu bytes\n", SocketBuf_available(buf));

/* Search for patterns (useful for protocol parsing) */
ssize_t pos = SocketBuf_find(buf, "\n", 1);  /* Find newline */
if (pos >= 0) {
    printf("Newline at offset %zd\n", pos);
}

/* Read line-by-line */
char line[256];
ssize_t len;
while ((len = SocketBuf_readline(buf, line, sizeof(line))) > 0) {
    printf("Line: %s", line);  /* Includes '\n' */
}

/* Ensure space for large write */
if (SocketBuf_ensure(buf, 8192)) {
    /* Guaranteed 8KB write space */
    SocketBuf_write(buf, large_data, 8192);
}

/* Compact buffer for maximum contiguous space */
SocketBuf_compact(buf);
size_t contiguous;
void *ptr = SocketBuf_writeptr(buf, &contiguous);
/* contiguous now equals SocketBuf_space(buf) */

/* Scatter-gather I/O */
struct header hdr = {...};
char body[1024] = "...";
struct iovec iov[2] = {
    {.iov_base = &hdr, .iov_len = sizeof(hdr)},
    {.iov_base = body, .iov_len = strlen(body)}
};
SocketBuf_writev(buf, iov, 2);  /* Gather write */

struct header recv_hdr;
char recv_body[1024];
struct iovec recv_iov[2] = {
    {.iov_base = &recv_hdr, .iov_len = sizeof(recv_hdr)},
    {.iov_base = recv_body, .iov_len = sizeof(recv_body)}
};
SocketBuf_readv(buf, recv_iov, 2);  /* Scatter read */

/* Secure clear for sensitive data */
SocketBuf_secureclear(buf);

SocketBuf_release(&buf);
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

### Generic Retry Framework

```c
#include "core/SocketRetry.h"

/* Configure retry policy */
SocketRetry_Policy policy;
SocketRetry_policy_defaults(&policy);
policy.max_attempts = 5;
policy.initial_delay_ms = 100;
policy.max_delay_ms = 30000;
policy.multiplier = 2.0;
policy.jitter = 0.25;

/* Define operation to retry */
int connect_op(void *ctx, int attempt) {
    ConnectionCtx *c = ctx;
    return connect(c->fd, c->addr, c->addrlen) < 0 ? errno : 0;
}

/* Define retry decision callback */
int should_retry(int err, int attempt, void *ctx) {
    return SocketError_is_retryable_errno(err);
}

/* Execute with retries */
SocketRetry_T retry = SocketRetry_new(&policy);
int result = SocketRetry_execute(retry, connect_op, should_retry, &ctx);

/* Get statistics */
SocketRetry_Stats stats;
SocketRetry_get_stats(retry, &stats);
printf("Attempts: %d, Total delay: %lld ms\n", stats.attempts, stats.total_delay_ms);

SocketRetry_free(&retry);
```

### Asynchronous DNS Resolution

```c
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"

SocketDNS_T dns = SocketDNS_new();
SocketPoll_T poll = SocketPoll_new(100);

/* Configure DNS timeouts */
SocketDNS_settimeout(dns, 5000);  /* 5 second default timeout */

/* Configure DNS cache */
SocketDNS_cache_set_ttl(dns, 300);           /* 5 minute TTL */
SocketDNS_cache_set_max_entries(dns, 1000);  /* Max 1000 entries */
SocketDNS_prefer_ipv6(dns, 1);               /* Prefer IPv6 */

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

/* Monitor cache performance */
SocketDNS_CacheStats stats;
SocketDNS_cache_stats(dns, &stats);
printf("DNS cache hit rate: %.1f%% (%zu entries)\n",
       stats.hit_rate * 100.0, stats.current_size);

/* Clear cache when DNS records change */
SocketDNS_cache_clear(dns);

/* Remove specific entry */
SocketDNS_cache_remove(dns, "example.com");

SocketDNS_free(&dns);
SocketPoll_free(&poll);
```

### Asynchronous I/O (io_uring/kqueue)

```c
#include "socket/SocketAsync.h"
#include "poll/SocketPoll.h"

/* Check what backend is available */
if (SocketAsync_backend_available(ASYNC_BACKEND_IO_URING)) {
    printf("io_uring available - optimal async I/O\n");
} else if (SocketAsync_backend_available(ASYNC_BACKEND_KQUEUE)) {
    printf("kqueue available - good async I/O\n");
} else {
    printf("Using poll-based fallback\n");
}

/* Set preferred backend (optional) */
SocketAsync_set_backend(ASYNC_BACKEND_IO_URING);

/* Get async context from poll */
SocketPoll_T poll = SocketPoll_new(1024);
SocketAsync_T async = SocketPoll_get_async(poll);

/* Completion callback */
void io_complete(Socket_T socket, ssize_t bytes, int err, void *ud) {
    if (err) {
        printf("Error: %s\n", strerror(err));
        return;
    }
    printf("Transferred %zd bytes\n", bytes);
}

/* Submit async send */
unsigned req_id = SocketAsync_send(async, socket, buf, len,
                                   io_complete, userdata, ASYNC_FLAG_NONE);

/* Submit async recv */
req_id = SocketAsync_recv(async, socket, recv_buf, sizeof(recv_buf),
                          io_complete, userdata, ASYNC_FLAG_ZERO_COPY);

/* Batch submission for efficiency */
SocketAsync_Op ops[3] = {
    {sock1, 1, send_buf, NULL, len1, io_complete, ud1, ASYNC_FLAG_NONE, 0},
    {sock2, 0, NULL, recv_buf, len2, io_complete, ud2, ASYNC_FLAG_NONE, 0},
    {sock3, 1, send_buf2, NULL, len3, io_complete, ud3, ASYNC_FLAG_URGENT, 0}
};
int submitted = SocketAsync_submit_batch(async, ops, 3);
printf("Submitted %d operations\n", submitted);

/* Cancel specific operation */
SocketAsync_cancel(async, req_id);

/* Cancel all pending (during shutdown) */
int cancelled = SocketAsync_cancel_all(async);
printf("Cancelled %d pending ops\n", cancelled);

/* Check backend in use */
printf("Backend: %s, available: %s\n",
       SocketAsync_backend_name(async),
       SocketAsync_is_available(async) ? "yes" : "fallback");

/* Completions auto-processed in SocketPoll_wait() */
SocketEvent_T *events;
int n = SocketPoll_wait(poll, &events, 100);

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

### Connection Health & Probing

```c
#include "socket/Socket.h"

Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
Socket_connect(sock, "example.com", 80);

/* Quick health check (non-blocking) */
if (!Socket_probe(sock, 0)) {
    printf("Connection appears dead\n");
}

/* Health check with timeout (waits up to 100ms for response) */
if (!Socket_probe(sock, 100)) {
    printf("Connection lost, reconnecting...\n");
}

/* Check for pending socket errors (after non-blocking connect) */
int error = Socket_get_error(sock);
if (error != 0) {
    printf("Socket error: %s\n", strerror(error));
}

/* Check read/write readiness without blocking */
if (Socket_is_readable(sock) > 0) {
    char buf[1024];
    ssize_t n = Socket_recv(sock, buf, sizeof(buf));
}

if (Socket_is_writable(sock) > 0) {
    Socket_send(sock, "GET / HTTP/1.1\r\n\r\n", 18);
}

#ifdef __linux__
/* Get TCP stack statistics (Linux only) */
SocketTCPInfo info;
if (Socket_get_tcp_info(sock, &info) == 0) {
    printf("RTT: %.2f ms\n", info.rtt_us / 1000.0);
    printf("Congestion window: %u segments\n", info.snd_cwnd);
    printf("Retransmissions: %u\n", info.total_retrans);
    if (info.delivery_rate > 0) {
        printf("Delivery rate: %.2f Mbps\n", info.delivery_rate * 8.0 / 1e6);
    }
}
#endif

/* Simple RTT query (cross-platform, returns -1 if unavailable) */
int32_t rtt = Socket_get_rtt(sock);
if (rtt >= 0) {
    printf("RTT: %.2f ms\n", rtt / 1000.0);
}

/* Congestion window query (Linux only) */
int32_t cwnd = Socket_get_cwnd(sock);
if (cwnd >= 0) {
    printf("CWND: %d segments\n", cwnd);
}

Socket_free(&sock);
```

### I/O with Timeouts

```c
#include "socket/Socket.h"

Socket_T sock = Socket_connect_tcp("example.com", 80, 5000);

/* Send all data with timeout (returns bytes actually sent) */
ssize_t sent = Socket_sendall_timeout(sock, request, len, 10000);
if (sent < (ssize_t)len) {
    printf("Only sent %zd bytes before timeout\n", sent);
}

/* Receive with timeout (returns bytes received) */
char response[4096];
ssize_t n = Socket_recvall_timeout(sock, response, sizeof(response), 5000);
if (n > 0) {
    printf("Received %zd bytes\n", n);
}

/* Scatter/gather I/O with timeout */
struct iovec iov[2] = {
    {.iov_base = header, .iov_len = header_len},
    {.iov_base = body, .iov_len = body_len}
};
ssize_t sent_v = Socket_sendv_timeout(sock, iov, 2, 5000);

Socket_free(&sock);
```

### Advanced I/O Operations

```c
#include "socket/Socket.h"

/* Peek at data without consuming */
char peek_buf[16];
ssize_t peeked = Socket_peek(sock, peek_buf, sizeof(peek_buf));
if (peeked > 0) {
    printf("Peeked %zd bytes: protocol=%d\n", peeked, peek_buf[0]);
}

/* TCP cork for efficient message assembly */
Socket_cork(sock, 1);  /* Enable corking */
Socket_send(sock, headers, header_len);
Socket_send(sock, body, body_len);
Socket_cork(sock, 0);  /* Disable cork, flush all data */

#ifdef __linux__
/* Zero-copy socket-to-socket transfer (Linux only) */
ssize_t spliced = Socket_splice(client, upstream, 65536);
if (spliced > 0) {
    printf("Spliced %zd bytes\n", spliced);
} else if (spliced == 0) {
    /* Would block - poll for readiness */
} else {
    /* Not supported on this platform */
    char buf[4096];
    while ((n = Socket_recv(client, buf, sizeof(buf))) > 0) {
        Socket_sendall(upstream, buf, n);
    }
}
#endif
```

### Socket Duplication

```c
#include "socket/Socket.h"

Socket_T socket = Socket_connect_tcp("example.com", 80, 5000);

/* Duplicate socket for separate reader/writer threads */
Socket_T reader = socket;
Socket_T writer = Socket_dup(socket);

/* Now can be used in separate threads safely */
/* reader thread: Socket_recv(reader, ...) */
/* writer thread: Socket_send(writer, ...) */

/* Duplicate to specific fd (useful for exec) */
Socket_T sock_fd3 = Socket_dup2(socket, 3);
if (fork() == 0) {
    /* Child process can access socket on fd 3 */
    execl("/usr/bin/handler", "handler", NULL);
}

Socket_free(&writer);
Socket_free(&reader);
Socket_free(&sock_fd3);
```

### Timers

```c
#include "poll/SocketPoll.h"
#include "core/SocketTimer.h"

SocketPoll_T poll = SocketPoll_new(100);

/* Check which backend is in use */
printf("Backend: %s\n", SocketPoll_get_backend_name(poll));
// Output: "epoll" (Linux), "kqueue" (macOS/BSD), or "poll" (fallback)

void timer_callback(void *userdata) {
    printf("Timer fired!\n");
}

/* One-shot timer (fires once after 5 seconds) */
SocketTimer_T timer = SocketTimer_add(poll, 5000, timer_callback, NULL);

/* Repeating timer (fires every 1 second) */
SocketTimer_T heartbeat = SocketTimer_add_repeating(poll, 1000, timer_callback, NULL);

/* Check remaining time */
int64_t remaining = SocketTimer_remaining(poll, timer);

/* Reschedule timer with new delay (extends/shortens timeout) */
SocketTimer_reschedule(poll, timer, 10000);  /* Now fires in 10 seconds */

/* Pause and resume timers */
SocketTimer_pause(poll, heartbeat);   /* Stops firing, preserves remaining time */
/* ... do something ... */
SocketTimer_resume(poll, heartbeat);  /* Continues from where it paused */

/* Cancel timer */
SocketTimer_cancel(poll, heartbeat);

/* Modify events for registered sockets */
Socket_T sock = /* ... */;
SocketPoll_add(poll, sock, POLL_READ, NULL);
SocketPoll_modify_events(poll, sock, POLL_WRITE, 0);  /* Add write monitoring */
SocketPoll_modify_events(poll, sock, 0, POLL_WRITE);  /* Remove write monitoring */

/* List registered sockets */
Socket_T sockets[100];
int count = SocketPoll_get_registered_sockets(poll, sockets, 100);
printf("Monitoring %d sockets\n", count);

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

### TLS Session Resumption

```c
#include "tls/SocketTLS.h"

/* Save session for later resumption */
size_t session_len = 4096;
unsigned char session_data[4096];

if (SocketTLS_session_save(sock, session_data, &session_len) == 1) {
    /* Store session_data[:session_len] to disk/cache */
    write_session_to_cache(hostname, session_data, session_len);
}

/* Later: restore session for faster reconnect */
Socket_T sock2 = Socket_connect_tcp(hostname, port, 5000);
SocketTLS_enable(sock2, ctx);
SocketTLS_set_hostname(sock2, hostname);

/* Restore previously saved session */
unsigned char *cached_session = read_session_from_cache(hostname, &cached_len);
if (cached_session) {
    SocketTLS_session_restore(sock2, cached_session, cached_len);
    free(cached_session);
}

SocketTLS_handshake_auto(sock2);

/* Check if session was resumed (0-RTT or abbreviated handshake) */
if (SocketTLS_is_session_reused(sock2)) {
    printf("Session resumed - faster handshake!\n");
}
```

### TLS Certificate Information

```c
#include "tls/SocketTLS.h"

/* Get full certificate details */
SocketTLS_CertInfo info;
if (SocketTLS_get_peer_cert_info(sock, &info) == 1) {
    printf("Subject: %s\n", info.subject);
    printf("Issuer: %s\n", info.issuer);
    printf("Version: X.509v%d\n", info.version);
    printf("Serial: %s\n", info.serial);
    printf("Fingerprint: %s\n", info.fingerprint);
    printf("Valid from: %s", ctime(&info.not_before));
    printf("Valid until: %s", ctime(&info.not_after));
}

/* Quick certificate expiry check */
time_t expiry = SocketTLS_get_cert_expiry(sock);
if (expiry != (time_t)-1) {
    time_t now = time(NULL);
    int days_left = (expiry - now) / 86400;
    if (days_left < 30) {
        printf("Warning: Certificate expires in %d days!\n", days_left);
    }
}

/* Just get subject for logging */
char subject[256];
if (SocketTLS_get_cert_subject(sock, subject, sizeof(subject)) > 0) {
    printf("Connected to: %s\n", subject);
}
```

### TLS OCSP and Renegotiation

```c
#include "tls/SocketTLS.h"

/* Check OCSP stapling status */
int ocsp_status = SocketTLS_get_ocsp_response_status(sock);
switch (ocsp_status) {
    case 1:
        printf("Certificate verified via OCSP\n");
        break;
    case 0:
        printf("WARNING: Certificate REVOKED!\n");
        Socket_free(&sock);
        return;
    case -1:
        printf("No OCSP response (server doesn't support stapling)\n");
        break;
    case -2:
        printf("OCSP response verification failed\n");
        break;
}

/* Disable renegotiation for security (prevents DoS attacks) */
SocketTLS_disable_renegotiation(sock);

/* Or check for pending renegotiation requests */
int reneg = SocketTLS_check_renegotiation(sock);
if (reneg == 1) {
    printf("Renegotiation completed\n");
} else if (reneg == -1) {
    printf("Renegotiation rejected (disabled or TLS 1.3)\n");
}
```

### TLS Server with SNI and Certificate Pinning

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

/* Certificate pinning (client context) */
SocketTLSContext_T client_ctx = SocketTLSContext_new_client("ca-bundle.pem");
SocketTLSContext_add_pin_hex(client_ctx, 
    "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c");
SocketTLSContext_set_pin_enforcement(client_ctx, 1);  /* Strict mode */
```

### Certificate Transparency (CT)

```c
#include "tls/SocketTLSContext.h"

/* Enable Certificate Transparency validation (RFC 6962) */
SocketTLSContext_T ctx = SocketTLSContext_new_client("ca-bundle.pem");

/* Strict mode - fail if no valid SCTs */
SocketTLSContext_enable_ct(ctx, CT_VALIDATION_STRICT);

/* Or permissive mode - log but continue */
SocketTLSContext_enable_ct(ctx, CT_VALIDATION_PERMISSIVE);

/* Custom CT log list (optional) */
SocketTLSContext_set_ctlog_list_file(ctx, "/path/to/ctlogs.txt");

/* Query CT status */
if (SocketTLSContext_ct_enabled(ctx)) {
    CTValidationMode mode = SocketTLSContext_get_ct_mode(ctx);
    printf("CT validation: %s\n", 
           mode == CT_VALIDATION_STRICT ? "strict" : "permissive");
}
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
Socket_sendfd(sock1, fd_to_pass);
close(fd_to_pass);

/* Receive passed FD */
int received_fd;
Socket_recvfd(sock2, &received_fd);
/* received_fd is now a valid FD in this process */
close(received_fd);

/* Multiple FD passing */
int fds[3] = {fd1, fd2, fd3};
Socket_sendfds(sock1, fds, 3);

int received_fds[3];
size_t num_fds;
Socket_recvfds(sock2, received_fds, 3, &num_fds);
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

### Observability - Logging

```c
#include "core/SocketUtil.h"

/* Custom logging callback */
void my_logger(void *userdata, SocketLogLevel level,
               const char *component, const char *message) {
    printf("[%s] %s: %s\n", SocketLog_levelname(level), component, message);
}
SocketLog_setcallback(my_logger, NULL);

/* Set minimum log level */
SocketLog_setlevel(SOCKET_LOG_DEBUG);

/* Use convenience macros */
#define SOCKET_LOG_COMPONENT "MyApp"
SOCKET_LOG_INFO_MSG("Server started on port %d", port);
SOCKET_LOG_ERROR_MSG("Connection failed: %s", strerror(errno));

/* Correlation IDs for distributed tracing */
SocketLogContext ctx = {0};
strncpy(ctx.request_id, "req-12345", sizeof(ctx.request_id) - 1);
strncpy(ctx.trace_id, "trace-abcde", sizeof(ctx.trace_id) - 1);
SocketLog_setcontext(&ctx);
SOCKET_LOG_INFO_MSG("Processing request");  /* Includes correlation IDs */
SocketLog_clearcontext();
```

### Observability - Metrics

```c
#include "core/SocketMetrics.h"

/* Record metrics */
SocketMetrics_counter_inc(SOCKET_CTR_SOCKET_CREATED);
SocketMetrics_gauge_set(SOCKET_GAU_POOL_ACTIVE_CONNECTIONS, 42);
SocketMetrics_histogram_observe(SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS, 125.0);

/* Get percentiles */
double p99 = SocketMetrics_histogram_percentile(SOCKET_HIST_HTTP_CLIENT_REQUEST_LATENCY_MS, 99.0);

/* Export to Prometheus */
char buffer[65536];
size_t len = SocketMetrics_export_prometheus(buffer, sizeof(buffer));

/* Export to StatsD */
SocketMetrics_export_statsd(buffer, sizeof(buffer), "myapp.socket");

/* Export to JSON */
SocketMetrics_export_json(buffer, sizeof(buffer));

/* Get complete snapshot */
SocketMetrics_Snapshot snapshot;
SocketMetrics_get(&snapshot);

/* Reset metrics */
SocketMetrics_reset();

/* Socket count and peak tracking */
int current = SocketMetrics_get_socket_count();
int peak = SocketMetrics_get_peak_connections();
SocketMetrics_reset_peaks();  /* Reset high watermark */
```

### Per-Socket Statistics

Track I/O statistics for individual sockets:

```c
#include "socket/Socket.h"

Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
Socket_connect(sock, "example.com", 80);

/* ... send/recv operations ... */

/* Get per-socket statistics */
SocketStats_T stats;
Socket_getstats(sock, &stats);

printf("Bytes: %zu sent, %zu received\n",
       (size_t)stats.bytes_sent, (size_t)stats.bytes_received);
printf("Packets: %zu sent, %zu received\n",
       (size_t)stats.packets_sent, (size_t)stats.packets_received);
printf("Errors: %zu send, %zu recv\n",
       (size_t)stats.send_errors, (size_t)stats.recv_errors);
printf("Last activity: send=%lld ms, recv=%lld ms ago\n",
       (long long)(Socket_get_monotonic_ms() - stats.last_send_time_ms),
       (long long)(Socket_get_monotonic_ms() - stats.last_recv_time_ms));

/* RTT estimation (Linux only via TCP_INFO) */
if (stats.rtt_us >= 0) {
    printf("RTT: %.2f ms (var: %.2f ms)\n",
           stats.rtt_us / 1000.0, stats.rtt_var_us / 1000.0);
}

/* Reset statistics for next interval */
Socket_resetstats(sock);

Socket_free(&sock);
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

/* SYN flood protection */
Socket_setdeferaccept(socket, 10);  /* Wait 10s for data before accept() */
```

## Architecture

### Module Organization

```
include/
├── core/          # Foundation layer
│   ├── Arena.h          # Arena memory management
│   ├── Except.h         # Exception handling
│   ├── SocketConfig.h   # Configuration constants
│   ├── SocketCrypto.h   # Cryptographic utilities
│   ├── SocketIPTracker.h # Per-IP connection tracking
│   ├── SocketMetrics.h  # Production metrics (counters, gauges, histograms)
│   ├── SocketRateLimit.h # Token bucket rate limiting
│   ├── SocketRetry.h    # Generic retry with exponential backoff
│   ├── SocketSecurity.h # Security utilities
│   ├── SocketSYNProtect.h # SYN flood protection
│   ├── SocketTimer.h    # Timer management
│   ├── SocketUTF8.h     # UTF-8 validation
│   └── SocketUtil.h     # Logging, error handling, utilities
├── socket/        # Core I/O layer
│   ├── Socket.h         # TCP/Unix domain sockets
│   ├── SocketAsync.h    # Async I/O (io_uring/kqueue)
│   ├── SocketBuf.h      # Circular buffer
│   ├── SocketCommon.h   # Shared socket base
│   ├── SocketDgram.h    # UDP sockets
│   ├── SocketHappyEyeballs.h # RFC 8305 connection racing
│   ├── SocketIO.h       # I/O helpers
│   ├── SocketProxy.h    # HTTP CONNECT/SOCKS proxy
│   ├── SocketReconnect.h # Auto-reconnection
│   └── SocketWS.h       # WebSocket (RFC 6455)
├── dns/           # DNS layer
│   └── SocketDNS.h      # Async DNS resolution
├── poll/          # Event system
│   └── SocketPoll.h     # Cross-platform polling
├── pool/          # Connection management
│   └── SocketPool.h     # Connection pooling
├── tls/           # Security layer
│   ├── SocketTLS.h      # TLS operations
│   ├── SocketTLSContext.h # TLS context management
│   ├── SocketDTLS.h     # DTLS operations
│   └── SocketDTLSContext.h # DTLS context management
└── http/          # HTTP protocol stack
    ├── SocketHTTP.h     # HTTP core (RFC 9110)
    ├── SocketHTTP1.h    # HTTP/1.1 (RFC 9112)
    ├── SocketHPACK.h    # HPACK (RFC 7541)
    ├── SocketHTTP2.h    # HTTP/2 (RFC 9113)
    ├── SocketHTTPClient.h # HTTP client API
    └── SocketHTTPServer.h # HTTP server API
```

### Layered Architecture

1. **Foundation**: `Arena` (Memory), `Except` (Errors), `SocketCrypto` (Cryptographic primitives)
2. **Utilities**: `SocketUtil` (Logging, Metrics, Events, Error Handling), `SocketTimer`, `SocketRateLimit`, `SocketUTF8`, `SocketRetry`
3. **Base Abstraction**: `SocketCommon` (Shared base `SocketBase_T` for Socket/SocketDgram)
4. **Core I/O**: `Socket` (TCP/Unix), `SocketDgram` (UDP), `SocketBuf` (Buffers), `SocketIO` (I/O helpers)
5. **DNS**: `SocketDNS` (Async DNS with worker threads)
6. **Event System**: `SocketPoll` (epoll/kqueue/poll abstraction), `SocketAsync` (Async I/O integration)
7. **Connection Helpers**: `SocketHappyEyeballs` (RFC 8305), `SocketReconnect` (Auto-reconnection), `SocketProxy` (HTTP CONNECT, SOCKS4/5)
8. **Security**: `SocketSYNProtect` (SYN flood protection), `SocketIPTracker` (Per-IP limits)
9. **Application**: `SocketPool` (Connection management)
10. **TLS**: `SocketTLS` (TLS I/O), `SocketTLSContext` (Context management), `SocketDTLS`, `SocketDTLSContext`
11. **HTTP**: `SocketHTTP`, `SocketHTTP1`, `SocketHPACK`, `SocketHTTP2`, `SocketHTTPClient`, `SocketHTTPServer`
12. **WebSocket**: `SocketWS` (RFC 6455 with permessage-deflate)

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
| SocketRetry | NOT thread-safe | One instance per thread |
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

## Signal Handling

### SIGPIPE (Automatic)

**No application action required.** The library handles SIGPIPE internally:

| Platform | Mechanism | When Applied |
|----------|-----------|--------------|
| Linux/FreeBSD | `MSG_NOSIGNAL` flag | Every send operation |
| BSD/macOS | `SO_NOSIGPIPE` option | Socket creation time |

Applications do **NOT** need to call `signal(SIGPIPE, SIG_IGN)`.

For legacy code or defense-in-depth, an optional convenience function is provided:

```c
// Optional - not required
Socket_ignore_sigpipe();
```

### Graceful Shutdown

The library does **NOT** install signal handlers. Applications must handle shutdown signals themselves. Recommended pattern using the self-pipe trick:

```c
#include <signal.h>
#include <unistd.h>

static int signal_pipe[2];

/* Async-signal-safe handler - only writes to pipe */
static void shutdown_handler(int signo) {
    (void)signo;
    char byte = 1;
    (void)write(signal_pipe[1], &byte, 1);  /* write() is async-signal-safe */
}

int main(void) {
    pipe(signal_pipe);
    fcntl(signal_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(signal_pipe[1], F_SETFL, O_NONBLOCK);
    
    struct sigaction sa = {0};
    sa.sa_handler = shutdown_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    
    /* Add signal pipe to poll set */
    SocketPoll_add_fd(poll, signal_pipe[0], POLL_READ, NULL);
    
    /* In event loop, check for signal pipe readability */
    /* Then use SocketPool_drain() for graceful connection draining */
}
```

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

## Testing and Quality

### Test Suite

The library includes comprehensive tests in `src/test/`:

| Category | Test Files |
|----------|------------|
| Core | `test_arena.c`, `test_except.c`, `test_crypto.c`, `test_utf8.c`, `test_ratelimit.c` |
| Socket | `test_socket.c`, `test_socketdgram.c`, `test_socketbuf.c` |
| Networking | `test_socketpoll.c`, `test_socketpool.c`, `test_socketdns.c`, `test_socketerror.c` |
| Connection | `test_happy_eyeballs.c`, `test_reconnect.c`, `test_proxy.c`, `test_proxy_integration.c` |
| HTTP | `test_http_core.c`, `test_http1_parser.c`, `test_hpack.c`, `test_http2.c`, `test_http_client.c`, `test_http_integration.c`, `test_http2_integration.c` |
| WebSocket | `test_websocket.c`, `test_ws_integration.c` |
| TLS/DTLS | `test_tls_integration.c`, `test_tls_phase4.c`, `test_tls_pinning.c`, `test_dtls_integration.c` |
| Security | `test_synprotect.c`, `test_security.c`, `test_signals.c` |
| Integration | `test_integration.c`, `test_async.c`, `test_threadsafety.c`, `test_coverage.c` |

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

## Exception Types

### Core Exceptions
- `Socket_Failed` - General socket operation failure
- `Socket_Closed` - Connection closed by peer
- `SocketUnix_Failed` - Unix socket operation failure
- `SocketDgram_Failed` - UDP socket operation failure
- `SocketPoll_Failed` - Event polling failure
- `SocketPool_Failed` - Connection pool operation failure
- `SocketDNS_Failed` - DNS resolution failure
- `SocketTimer_Failed` - Timer operation failure
- `SocketRateLimit_Failed` - Rate limiter failure
- `SocketRetry_Failed` - Retry operation failure
- `SocketAsync_Failed` - Async I/O failure
- `SocketCrypto_Failed` - Cryptographic operation failure

### Connection Exceptions
- `SocketHE_Failed` - Happy Eyeballs connection failure
- `SocketReconnect_Failed` - Reconnection operation failure
- `SocketProxy_Failed` - Proxy connection failure

### TLS/DTLS Exceptions
- `SocketTLS_Failed` - General TLS operation failure
- `SocketTLS_HandshakeFailed` - TLS handshake failure
- `SocketTLS_VerifyFailed` - Certificate verification failure
- `SocketTLS_ProtocolError` - TLS protocol error
- `SocketTLS_ShutdownFailed` - TLS shutdown failure
- `SocketTLS_PinVerifyFailed` - Certificate pinning failure
- `SocketDTLS_Failed` - General DTLS operation failure
- `SocketDTLS_HandshakeFailed` - DTLS handshake failure
- `SocketDTLS_VerifyFailed` - DTLS certificate verification failure
- `SocketDTLS_CookieFailed` - DTLS cookie exchange failure
- `SocketDTLS_TimeoutExpired` - DTLS handshake timeout

### HTTP Exceptions
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
- `SocketHTTPClient_TLSFailed` - HTTP client TLS error
- `SocketHTTPClient_DNSFailed` - HTTP client DNS failure
- `SocketHTTPClient_ConnectFailed` - HTTP client connection failure
- `SocketHTTPClient_ProtocolError` - HTTP client protocol error
- `SocketHTTPClient_TooManyRedirects` - Too many redirects
- `SocketHTTPClient_ResponseTooLarge` - Response size limit exceeded
- `SocketHTTPServer_Failed` - HTTP server failure

### WebSocket Exceptions
- `SocketWS_Failed` - WebSocket operation failure
- `SocketWS_ProtocolError` - WebSocket protocol error
- `SocketWS_Closed` - WebSocket connection closed

### Security Exceptions
- `SocketSYNProtect_Failed` - SYN protection failure

## License

See `LICENSE` for usage details.
