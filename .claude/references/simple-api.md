# Simple API Reference

This document provides a complete reference for the Simple API layer - a return-code-based convenience wrapper over the exception-based socket library.

## Overview

The Simple API provides an easier-to-use interface that:
- Returns error codes instead of raising exceptions
- Uses `Socket_simple_error()` for human-readable error messages
- Uses `Socket_simple_code()` for programmatic error handling
- Wraps all core library modules with consistent patterns

Include with: `#include <simple/SocketSimple.h>`

## Error Handling

### Error Access Functions

```c
const char *Socket_simple_error(void);           /* Get error message (thread-local) */
int Socket_simple_errno(void);                   /* Get preserved errno */
SocketSimple_ErrorCode Socket_simple_code(void); /* Get error code enum */
int Socket_simple_is_retryable(void);            /* Check if EAGAIN/EINTR */
void Socket_simple_clear_error(void);            /* Clear error state */
```

### Error Codes

| Code | Description |
|------|-------------|
| `SOCKET_SIMPLE_OK` | Success |
| `SOCKET_SIMPLE_ERR_SOCKET` | General socket failure |
| `SOCKET_SIMPLE_ERR_CONNECT` | Connection failed |
| `SOCKET_SIMPLE_ERR_TIMEOUT` | Operation timed out |
| `SOCKET_SIMPLE_ERR_DNS` | DNS resolution failed |
| `SOCKET_SIMPLE_ERR_TLS` | General TLS error |
| `SOCKET_SIMPLE_ERR_TLS_HANDSHAKE` | TLS handshake failed |
| `SOCKET_SIMPLE_ERR_TLS_VERIFY` | Certificate verification failed |
| `SOCKET_SIMPLE_ERR_HTTP` | HTTP protocol error |
| `SOCKET_SIMPLE_ERR_WS` | WebSocket error |
| `SOCKET_SIMPLE_ERR_MEMORY` | Memory allocation failed |
| `SOCKET_SIMPLE_ERR_POOL_FULL` | Pool at capacity |
| `SOCKET_SIMPLE_ERR_PROXY` | Proxy connection failed |
| `SOCKET_SIMPLE_ERR_RATELIMIT` | Rate limit exceeded |

## TCP Socket Functions

### Client Connection

```c
/* Connect to TCP server */
SocketSimple_Socket_T Socket_simple_connect(const char *host, int port);
SocketSimple_Socket_T Socket_simple_connect_timeout(const char *host, int port, int timeout_ms);

/* Unix domain socket */
SocketSimple_Socket_T Socket_simple_connect_unix(const char *path);
```

### Server Functions

```c
SocketSimple_Socket_T Socket_simple_listen(const char *host, int port, int backlog);
SocketSimple_Socket_T Socket_simple_listen_unix(const char *path, int backlog);
SocketSimple_Socket_T Socket_simple_accept(SocketSimple_Socket_T server);
SocketSimple_Socket_T Socket_simple_accept_timeout(SocketSimple_Socket_T server, int timeout_ms);
```

### I/O Functions

```c
int Socket_simple_send(SocketSimple_Socket_T sock, const void *data, size_t len);
ssize_t Socket_simple_recv(SocketSimple_Socket_T sock, void *buf, size_t len);
ssize_t Socket_simple_recv_timeout(SocketSimple_Socket_T sock, void *buf, size_t len, int timeout_ms);
int Socket_simple_recv_all(SocketSimple_Socket_T sock, void *buf, size_t len);
ssize_t Socket_simple_recv_line(SocketSimple_Socket_T sock, char *buf, size_t maxlen);

/* Scatter-gather I/O */
ssize_t Socket_simple_sendv(SocketSimple_Socket_T sock, const struct iovec *iov, int iovcnt);
ssize_t Socket_simple_recvv(SocketSimple_Socket_T sock, struct iovec *iov, int iovcnt);
```

### Socket Options

```c
int Socket_simple_set_timeout(SocketSimple_Socket_T sock, int send_ms, int recv_ms);
int Socket_simple_set_nodelay(SocketSimple_Socket_T sock, int enable);
int Socket_simple_set_keepalive(SocketSimple_Socket_T sock, int enable, int idle_secs, int interval_secs, int count);
int Socket_simple_set_blocking(SocketSimple_Socket_T sock, int blocking);
int Socket_simple_set_sndbuf(SocketSimple_Socket_T sock, int size);
int Socket_simple_set_rcvbuf(SocketSimple_Socket_T sock, int size);
int Socket_simple_set_reuseaddr(SocketSimple_Socket_T sock, int enable);
int Socket_simple_set_reuseport(SocketSimple_Socket_T sock, int enable);
```

### Socket Info

```c
int Socket_simple_fd(SocketSimple_Socket_T sock);
int Socket_simple_is_connected(SocketSimple_Socket_T sock);
int Socket_simple_get_local_addr(SocketSimple_Socket_T sock, char *host, size_t host_len, int *port);
int Socket_simple_get_peer_addr(SocketSimple_Socket_T sock, char *host, size_t host_len, int *port);
int Socket_simple_get_peer_creds(SocketSimple_Socket_T sock, int *pid, int *uid, int *gid);
```

### Cleanup

```c
void Socket_simple_close(SocketSimple_Socket_T *sock);
```

## UDP Functions

```c
SocketSimple_Socket_T Socket_simple_udp_new(void);
SocketSimple_Socket_T Socket_simple_udp_bind(const char *host, int port);
int Socket_simple_udp_sendto(SocketSimple_Socket_T sock, const void *data, size_t len, const char *host, int port);
ssize_t Socket_simple_udp_recvfrom(SocketSimple_Socket_T sock, void *buf, size_t len, char *from_host, size_t host_len, int *from_port);

/* Connected UDP */
int Socket_simple_udp_connect(SocketSimple_Socket_T sock, const char *host, int port);
ssize_t Socket_simple_udp_send(SocketSimple_Socket_T sock, const void *data, size_t len);
ssize_t Socket_simple_udp_recv(SocketSimple_Socket_T sock, void *buf, size_t len);

/* Multicast */
int Socket_simple_udp_join_multicast(SocketSimple_Socket_T sock, const char *group, const char *iface);
int Socket_simple_udp_leave_multicast(SocketSimple_Socket_T sock, const char *group, const char *iface);
int Socket_simple_udp_set_multicast_ttl(SocketSimple_Socket_T sock, int ttl);
int Socket_simple_udp_set_broadcast(SocketSimple_Socket_T sock, int enable);
```

## TLS Functions

### Client

```c
SocketSimple_Socket_T Socket_simple_connect_tls(const char *host, int port);
SocketSimple_Socket_T Socket_simple_connect_tls_ex(const char *host, int port, const SocketSimple_TLSOptions *opts);
int Socket_simple_enable_tls(SocketSimple_Socket_T sock, const char *hostname);
int Socket_simple_enable_tls_ex(SocketSimple_Socket_T sock, const char *hostname, const SocketSimple_TLSOptions *opts);
```

### Server

```c
SocketSimple_Socket_T Socket_simple_listen_tls(const char *host, int port, int backlog, const char *cert_file, const char *key_file);
SocketSimple_Socket_T Socket_simple_accept_tls(SocketSimple_Socket_T server);
```

### TLS Info

```c
int Socket_simple_is_tls(SocketSimple_Socket_T sock);
const char *Socket_simple_get_alpn(SocketSimple_Socket_T sock);
const char *Socket_simple_get_tls_version(SocketSimple_Socket_T sock);
const char *Socket_simple_get_cipher(SocketSimple_Socket_T sock);
int Socket_simple_get_cert_info(SocketSimple_Socket_T sock, char *buf, size_t len);
int Socket_simple_get_cert_cn(SocketSimple_Socket_T sock, char *buf, size_t len);
```

### Session Resumption

```c
int Socket_simple_is_session_reused(SocketSimple_Socket_T sock);
int Socket_simple_session_save(SocketSimple_Socket_T sock, unsigned char *buf, size_t *len);
int Socket_simple_session_restore(SocketSimple_Socket_T sock, const unsigned char *buf, size_t len);
```

### TLS Options Structure

```c
typedef struct {
    int timeout_ms;          /* Connection timeout (0 = default 30s) */
    int verify_cert;         /* Verify server certificate (default: 1) */
    const char *ca_file;     /* Custom CA file path */
    const char *ca_path;     /* Custom CA directory */
    const char *client_cert; /* Client certificate path */
    const char *client_key;  /* Client private key path */
    const char *alpn;        /* ALPN protocols, comma-separated */
    int min_version;         /* Min TLS version: 0=default, 12=1.2, 13=1.3 */
} SocketSimple_TLSOptions;

void Socket_simple_tls_options_init(SocketSimple_TLSOptions *opts);
```

## HTTP Client Functions

### One-liner Requests

```c
int Socket_simple_http_get(const char *url, SocketSimple_HTTPResponse *response);
int Socket_simple_http_post(const char *url, const char *content_type, const void *body, size_t body_len, SocketSimple_HTTPResponse *response);
int Socket_simple_http_put(const char *url, const char *content_type, const void *body, size_t body_len, SocketSimple_HTTPResponse *response);
int Socket_simple_http_delete(const char *url, SocketSimple_HTTPResponse *response);
int Socket_simple_http_head(const char *url, SocketSimple_HTTPResponse *response);
int Socket_simple_http_patch(const char *url, const char *content_type, const void *body, size_t body_len, SocketSimple_HTTPResponse *response);
```

### Extended Requests (Custom Headers)

```c
int Socket_simple_http_get_ex(const char *url, const char **headers, SocketSimple_HTTPResponse *response);
int Socket_simple_http_post_ex(const char *url, const char **headers, const char *content_type, const void *body, size_t body_len, SocketSimple_HTTPResponse *response);
int Socket_simple_http_request(SocketSimple_HTTPMethod method, const char *url, const char **headers, const void *body, size_t body_len, const SocketSimple_HTTPOptions *opts, SocketSimple_HTTPResponse *response);
```

### JSON Convenience

```c
int Socket_simple_http_get_json(const char *url, char **json_out, size_t *json_len);
int Socket_simple_http_post_json(const char *url, const char *json_body, char **json_out, size_t *json_len);
int Socket_simple_http_put_json(const char *url, const char *json_body, char **json_out, size_t *json_len);
```

### File Operations

```c
int Socket_simple_http_download(const char *url, const char *filepath);
int Socket_simple_http_upload(const char *url, const char *filepath, const char *content_type);
```

### Reusable Client

```c
SocketSimple_HTTP_T Socket_simple_http_new(void);
SocketSimple_HTTP_T Socket_simple_http_new_ex(const SocketSimple_HTTPOptions *opts);
int Socket_simple_http_client_get(SocketSimple_HTTP_T client, const char *url, SocketSimple_HTTPResponse *response);
int Socket_simple_http_client_post(SocketSimple_HTTP_T client, const char *url, const char *content_type, const void *body, size_t body_len, SocketSimple_HTTPResponse *response);
void Socket_simple_http_free(SocketSimple_HTTP_T *client);
```

### Response Structure

```c
typedef struct {
    int status_code;      /* HTTP status code (200, 404, etc.) */
    char *body;           /* Response body (caller must free) */
    size_t body_len;      /* Body length */
    char *content_type;   /* Content-Type header (may be NULL) */
    char *location;       /* Location header for redirects (may be NULL) */
} SocketSimple_HTTPResponse;

void Socket_simple_http_response_free(SocketSimple_HTTPResponse *response);
```

## WebSocket Functions

### Connection

```c
SocketSimple_WS_T Socket_simple_ws_connect(const char *url);
SocketSimple_WS_T Socket_simple_ws_connect_ex(const char *url, const SocketSimple_WSOptions *opts);
```

### Sending

```c
int Socket_simple_ws_send_text(SocketSimple_WS_T ws, const char *text, size_t len);
int Socket_simple_ws_send_binary(SocketSimple_WS_T ws, const void *data, size_t len);
int Socket_simple_ws_send_json(SocketSimple_WS_T ws, const char *json);
int Socket_simple_ws_ping(SocketSimple_WS_T ws);
```

### Receiving

```c
int Socket_simple_ws_recv(SocketSimple_WS_T ws, SocketSimple_WSMessage *msg);
int Socket_simple_ws_recv_timeout(SocketSimple_WS_T ws, SocketSimple_WSMessage *msg, int timeout_ms);
```

### Close

```c
int Socket_simple_ws_close(SocketSimple_WS_T ws, int code, const char *reason);
void Socket_simple_ws_free(SocketSimple_WS_T *ws);
void Socket_simple_ws_message_free(SocketSimple_WSMessage *msg);
```

### Status

```c
int Socket_simple_ws_is_open(SocketSimple_WS_T ws);
const char *Socket_simple_ws_protocol(SocketSimple_WS_T ws);
int Socket_simple_ws_fd(SocketSimple_WS_T ws);
```

### Server-side

```c
int Socket_simple_ws_is_upgrade(const char *method, const char **headers);
SocketSimple_WS_T Socket_simple_ws_accept(void *http_req, const SocketSimple_WSServerConfig *config);
SocketSimple_WS_T Socket_simple_ws_accept_raw(void *sock, const char *ws_key, const SocketSimple_WSServerConfig *config);
void Socket_simple_ws_reject(void *http_req, int status, const char *reason);
```

## DNS Functions

### Blocking Resolution

```c
int Socket_simple_dns_resolve(const char *hostname, SocketSimple_DNSResult *result);
int Socket_simple_dns_resolve_timeout(const char *hostname, SocketSimple_DNSResult *result, int timeout_ms);
int Socket_simple_dns_lookup(const char *hostname, char *buf, size_t len);
int Socket_simple_dns_lookup4(const char *hostname, char *buf, size_t len);
int Socket_simple_dns_lookup6(const char *hostname, char *buf, size_t len);
int Socket_simple_dns_reverse(const char *ip, char *hostname, size_t len);
void Socket_simple_dns_result_free(SocketSimple_DNSResult *result);
```

### Async Resolution

```c
SocketSimple_DNS_T Socket_simple_dns_new(void);
void Socket_simple_dns_free(SocketSimple_DNS_T *dns);
void Socket_simple_dns_set_timeout(SocketSimple_DNS_T dns, int timeout_ms);
void Socket_simple_dns_prefer_ipv6(SocketSimple_DNS_T dns, int prefer_ipv6);

/* Callback mode */
int Socket_simple_dns_resolve_async(SocketSimple_DNS_T dns, const char *hostname, SocketSimple_DNSCallback callback, void *userdata);

/* Polling mode */
SocketSimple_DNSRequest_T Socket_simple_dns_resolve_start(SocketSimple_DNS_T dns, const char *hostname);
int Socket_simple_dns_pollfd(SocketSimple_DNS_T dns);
int Socket_simple_dns_check(SocketSimple_DNS_T dns);
int Socket_simple_dns_request_done(SocketSimple_DNSRequest_T req);
int Socket_simple_dns_request_result(SocketSimple_DNSRequest_T req, SocketSimple_DNSResult *result);
void Socket_simple_dns_request_cancel(SocketSimple_DNS_T dns, SocketSimple_DNSRequest_T req);
void Socket_simple_dns_request_free(SocketSimple_DNSRequest_T *req);

/* Cache control */
void Socket_simple_dns_cache_clear(SocketSimple_DNS_T dns);
void Socket_simple_dns_cache_set_ttl(SocketSimple_DNS_T dns, int ttl_seconds);
```

## Poll Functions

### Lifecycle

```c
SocketSimple_Poll_T Socket_simple_poll_new(int max_events);
void Socket_simple_poll_free(SocketSimple_Poll_T *poll);
```

### Socket Registration

```c
int Socket_simple_poll_add(SocketSimple_Poll_T poll, SocketSimple_Socket_T sock, int events, void *data);
int Socket_simple_poll_mod(SocketSimple_Poll_T poll, SocketSimple_Socket_T sock, int events, void *data);
int Socket_simple_poll_del(SocketSimple_Poll_T poll, SocketSimple_Socket_T sock);
```

### Event Waiting

```c
int Socket_simple_poll_wait(SocketSimple_Poll_T poll, SocketSimple_PollEvent *events, int max_events, int timeout_ms);
```

### Event Flags

```c
SOCKET_SIMPLE_POLL_READ   /* Socket is readable */
SOCKET_SIMPLE_POLL_WRITE  /* Socket is writable */
SOCKET_SIMPLE_POLL_ERROR  /* Socket has error */
SOCKET_SIMPLE_POLL_HANGUP /* Peer disconnected */
```

### Poll Info

```c
const char *Socket_simple_poll_backend(SocketSimple_Poll_T poll);
int Socket_simple_poll_count(SocketSimple_Poll_T poll);
```

## Connection Pool Functions

### Lifecycle

```c
SocketSimple_Pool_T Socket_simple_pool_new(int max_connections);
SocketSimple_Pool_T Socket_simple_pool_new_ex(const SocketSimple_PoolOptions *opts);
void Socket_simple_pool_free(SocketSimple_Pool_T *pool);
```

### Connection Management

```c
SocketSimple_Conn_T Socket_simple_pool_add(SocketSimple_Pool_T pool, SocketSimple_Socket_T sock);
SocketSimple_Conn_T Socket_simple_pool_get(SocketSimple_Pool_T pool, SocketSimple_Socket_T sock);
int Socket_simple_pool_remove(SocketSimple_Pool_T pool, SocketSimple_Socket_T sock);
int Socket_simple_pool_cleanup(SocketSimple_Pool_T pool, int max_idle_ms);
```

### Accept with Rate Limiting

```c
SocketSimple_Conn_T Socket_simple_pool_accept(SocketSimple_Pool_T pool, SocketSimple_Socket_T listener);
SocketSimple_Conn_T Socket_simple_pool_accept_limited(SocketSimple_Pool_T pool, SocketSimple_Socket_T listener);
int Socket_simple_pool_set_conn_rate(SocketSimple_Pool_T pool, int conns_per_sec);
int Socket_simple_pool_set_max_per_ip(SocketSimple_Pool_T pool, int max);
```

### Graceful Shutdown

```c
int Socket_simple_pool_drain(SocketSimple_Pool_T pool, int timeout_ms);
int Socket_simple_pool_drain_poll(SocketSimple_Pool_T pool);
int Socket_simple_pool_drain_wait(SocketSimple_Pool_T pool, int timeout_ms);
SocketSimple_PoolState Socket_simple_pool_state(SocketSimple_Pool_T pool);
```

### Statistics

```c
int Socket_simple_pool_get_stats(SocketSimple_Pool_T pool, SocketSimple_PoolStats *stats);
int Socket_simple_pool_count(SocketSimple_Pool_T pool);
```

### Connection Accessors

```c
SocketSimple_Socket_T Socket_simple_conn_socket(SocketSimple_Conn_T conn);
void *Socket_simple_conn_data(SocketSimple_Conn_T conn);
int Socket_simple_conn_set_data(SocketSimple_Conn_T conn, void *data);
uint64_t Socket_simple_conn_last_activity(SocketSimple_Conn_T conn);
int Socket_simple_conn_peer_ip(SocketSimple_Conn_T conn, char *buf, size_t len);
```

## Proxy Functions

### Configuration

```c
void Socket_simple_proxy_config_init(SocketSimple_ProxyConfig *config);
int Socket_simple_proxy_parse_url(const char *url, SocketSimple_ProxyConfig *config);
const char *Socket_simple_proxy_type_name(SocketSimple_ProxyType type);
```

### Connection

```c
SocketSimple_Socket_T Socket_simple_proxy_connect(const SocketSimple_ProxyConfig *config, const char *target_host, int target_port);
SocketSimple_Socket_T Socket_simple_proxy_connect_timeout(const SocketSimple_ProxyConfig *config, const char *target_host, int target_port, int timeout_ms);
SocketSimple_Socket_T Socket_simple_proxy_connect_tls(const SocketSimple_ProxyConfig *config, const char *target_host, int target_port);
int Socket_simple_proxy_tunnel(SocketSimple_Socket_T sock, const SocketSimple_ProxyConfig *config, const char *target_host, int target_port);
```

### Proxy Types

```c
SOCKET_SIMPLE_PROXY_NONE    /* Direct connection */
SOCKET_SIMPLE_PROXY_HTTP    /* HTTP CONNECT */
SOCKET_SIMPLE_PROXY_HTTPS   /* HTTP CONNECT over TLS */
SOCKET_SIMPLE_PROXY_SOCKS4  /* SOCKS4 (IP only) */
SOCKET_SIMPLE_PROXY_SOCKS4A /* SOCKS4a (hostname) */
SOCKET_SIMPLE_PROXY_SOCKS5  /* SOCKS5 full */
SOCKET_SIMPLE_PROXY_SOCKS5H /* SOCKS5 with remote DNS */
```

## Usage Patterns

### Simple TCP Client

```c
SocketSimple_Socket_T sock = Socket_simple_connect("example.com", 80);
if (!sock) {
    fprintf(stderr, "Error: %s\n", Socket_simple_error());
    return 1;
}
Socket_simple_send(sock, "GET / HTTP/1.0\r\n\r\n", 18);
char buf[4096];
ssize_t n = Socket_simple_recv(sock, buf, sizeof(buf));
Socket_simple_close(&sock);
```

### HTTPS Request

```c
SocketSimple_HTTPResponse resp;
if (Socket_simple_http_get("https://api.example.com/data", &resp) == 0) {
    printf("Status: %d\n", resp.status_code);
    printf("Body: %.*s\n", (int)resp.body_len, resp.body);
    Socket_simple_http_response_free(&resp);
} else {
    fprintf(stderr, "Error: %s\n", Socket_simple_error());
}
```

### WebSocket Client

```c
SocketSimple_WS_T ws = Socket_simple_ws_connect("wss://echo.websocket.org");
if (!ws) {
    fprintf(stderr, "Error: %s\n", Socket_simple_error());
    return 1;
}
Socket_simple_ws_send_text(ws, "Hello!", 6);
SocketSimple_WSMessage msg;
if (Socket_simple_ws_recv(ws, &msg) == 0) {
    printf("Received: %.*s\n", (int)msg.len, (char*)msg.data);
    Socket_simple_ws_message_free(&msg);
}
Socket_simple_ws_close(ws, 1000, NULL);
Socket_simple_ws_free(&ws);
```

### Event Loop Server

```c
SocketSimple_Socket_T server = Socket_simple_listen("0.0.0.0", 8080, 128);
SocketSimple_Poll_T poll = Socket_simple_poll_new(64);
Socket_simple_poll_add(poll, server, SOCKET_SIMPLE_POLL_READ, NULL);

SocketSimple_PollEvent events[64];
while (running) {
    int n = Socket_simple_poll_wait(poll, events, 64, 1000);
    for (int i = 0; i < n; i++) {
        if (events[i].sock == server) {
            SocketSimple_Socket_T client = Socket_simple_accept(server);
            Socket_simple_poll_add(poll, client, SOCKET_SIMPLE_POLL_READ, NULL);
        } else if (events[i].events & SOCKET_SIMPLE_POLL_READ) {
            /* Handle client data */
        }
    }
}
```

### Proxy Connection

```c
SocketSimple_ProxyConfig config;
Socket_simple_proxy_config_init(&config);
Socket_simple_proxy_parse_url("socks5://proxy:1080", &config);

SocketSimple_Socket_T sock = Socket_simple_proxy_connect_tls(&config, "api.example.com", 443);
if (sock) {
    Socket_simple_send(sock, request, strlen(request));
    /* ... */
    Socket_simple_close(&sock);
}
```
