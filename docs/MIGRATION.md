# Migration Guide {#migration_guide}

Guide for migrating to the Socket Library from other networking libraries.

---

## Migration from BSD Sockets

The Socket Library provides a higher-level abstraction over BSD sockets.

### Socket Creation

**BSD Sockets:**
```c
int fd = socket(AF_INET, SOCK_STREAM, 0);
if (fd < 0) {
    perror("socket");
    return -1;
}
```

**Socket Library:**
```c
TRY {
    Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
}
EXCEPT(Socket_Failed) {
    fprintf(stderr, "Error: %s\n", Socket_GetLastError());
}
END_TRY;
```

### Connecting

**BSD Sockets:**
```c
struct sockaddr_in addr;
memset(&addr, 0, sizeof(addr));
addr.sin_family = AF_INET;
addr.sin_port = htons(port);
inet_pton(AF_INET, host, &addr.sin_addr);

if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    perror("connect");
}
```

**Socket Library:**
```c
Socket_connect(sock, host, port);  /* Handles DNS too */
```

### Sending Data

**BSD Sockets:**
```c
ssize_t total = 0;
while (total < len) {
    ssize_t n = send(fd, buf + total, len - total, 0);
    if (n < 0) {
        if (errno == EINTR) continue;
        perror("send");
        break;
    }
    total += n;
}
```

**Socket Library:**
```c
Socket_sendall(sock, buf, len);  /* Handles partial sends and EINTR */
```

### Socket Options

**BSD Sockets:**
```c
int optval = 1;
setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

struct linger l = {1, 0};
setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
```

**Socket Library:**
```c
Socket_setreuseaddr(sock);
Socket_setlinger(sock, 1, 0);
```

### API Mapping (BSD -> Socket Library)

| BSD Sockets | Socket Library |
|-------------|----------------|
| `socket()` | `Socket_new()` |
| `close()` | `Socket_free()` |
| `connect()` | `Socket_connect()` |
| `bind()` | `Socket_bind()` |
| `listen()` | `Socket_listen()` |
| `accept()` | `Socket_accept()` |
| `send()` | `Socket_send()` |
| `recv()` | `Socket_recv()` |
| `sendall` (loop) | `Socket_sendall()` |
| `getsockname()` | `Socket_getlocaladdr()`, `Socket_getlocalport()` |
| `getpeername()` | `Socket_getpeeraddr()`, `Socket_getpeerport()` |
| `fcntl(O_NONBLOCK)` | `Socket_setnonblocking()` |
| `setsockopt(SO_REUSEADDR)` | `Socket_setreuseaddr()` |
| `setsockopt(TCP_NODELAY)` | `Socket_setnodelay()` |
| `setsockopt(SO_KEEPALIVE)` | `Socket_setkeepalive()` |
| `poll()` / `epoll` | `SocketPoll_T` |
| `sendfile()` | `Socket_sendfileall()` |
| `writev()` | `Socket_sendvall()` |

---

## Migration from libcurl

### Simple GET Request

**libcurl:**
```c
CURL *curl = curl_easy_init();
curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
CURLcode res = curl_easy_perform(curl);
curl_easy_cleanup(curl);
```

**Socket Library:**
```c
SocketHTTPClient_T client = SocketHTTPClient_new(NULL);
SocketHTTPClient_Response response;
SocketHTTPClient_get(client, "https://example.com", &response);
/* response.body contains data */
SocketHTTPClient_Response_free(&response);
SocketHTTPClient_free(&client);
```

### POST Request

**libcurl:**
```c
curl_easy_setopt(curl, CURLOPT_POST, 1L);
curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
```

**Socket Library:**
```c
SocketHTTPClient_post(client, url, "application/json", json, strlen(json), &response);
```

### Custom Headers

**libcurl:**
```c
struct curl_slist *headers = NULL;
headers = curl_slist_append(headers, "Content-Type: application/json");
headers = curl_slist_append(headers, "Authorization: Bearer token");
curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
```

**Socket Library:**
```c
SocketHTTPClient_Request_T req = SocketHTTPClient_Request_new(client, HTTP_METHOD_GET, url);
SocketHTTPClient_Request_header(req, "Content-Type", "application/json");
SocketHTTPClient_Request_header(req, "Authorization", "Bearer token");
SocketHTTPClient_Request_execute(req, &response);
```

### Proxy Configuration

**libcurl:**
```c
curl_easy_setopt(curl, CURLOPT_PROXY, "socks5://localhost:1080");
curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, "user:pass");
```

**Socket Library:**
```c
SocketProxy_Config proxy;
SocketProxy_parse_url("socks5://user:pass@localhost:1080", &proxy, NULL);
config.proxy = &proxy;
client = SocketHTTPClient_new(&config);
```

### Error Handling

**libcurl:**
```c
CURLcode res = curl_easy_perform(curl);
if (res != CURLE_OK) {
    fprintf(stderr, "Error: %s\n", curl_easy_strerror(res));
}
```

**Socket Library:**
```c
TRY {
    SocketHTTPClient_get(client, url, &response);
}
EXCEPT(SocketHTTPClient_Timeout) {
    fprintf(stderr, "Timeout\n");
}
EXCEPT(SocketHTTPClient_DNSFailed) {
    fprintf(stderr, "DNS error\n");
}
END_TRY;
```

### API Mapping (libcurl -> Socket Library)

| libcurl | Socket Library |
|---------|----------------|
| `curl_easy_init()` | `SocketHTTPClient_new()` |
| `curl_easy_cleanup()` | `SocketHTTPClient_free()` |
| `curl_easy_perform()` | `SocketHTTPClient_get/post/etc()` |
| `CURLOPT_URL` | Function parameter |
| `CURLOPT_TIMEOUT` | `config.request_timeout_ms` |
| `CURLOPT_CONNECTTIMEOUT` | `config.connect_timeout_ms` |
| `CURLOPT_FOLLOWLOCATION` | `config.follow_redirects` |
| `CURLOPT_MAXREDIRS` | `config.follow_redirects` |
| `CURLOPT_PROXY` | `config.proxy` |
| `CURLOPT_SSL_VERIFYPEER` | `config.verify_ssl` |
| `CURLOPT_HTTPHEADER` | `SocketHTTPClient_Request_header()` |

---

## Migration from libevent

### Event Loop

**libevent:**
```c
struct event_base *base = event_base_new();
struct event *ev = event_new(base, fd, EV_READ | EV_PERSIST, callback, arg);
event_add(ev, NULL);
event_base_dispatch(base);
```

**Socket Library:**
```c
SocketPoll_T poll = SocketPoll_new(1000);
SocketPoll_add(poll, socket, POLL_READ, userdata);

while (running) {
    SocketEvent_T events[100];
    int n = SocketPoll_wait(poll, events, 100, 1000);
    for (int i = 0; i < n; i++) {
        handle_event(events[i].socket, events[i].events, events[i].data);
    }
}
```

### Callback Style

**libevent:**
```c
void read_cb(evutil_socket_t fd, short events, void *arg) {
    char buf[1024];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
}
```

**Socket Library:**
```c
/* Event loop style - no callbacks needed */
for (int i = 0; i < n; i++) {
    if (events[i].events & POLL_READ) {
        char buf[1024];
        ssize_t n = Socket_recv(events[i].socket, buf, sizeof(buf));
    }
}
```

### Timers

**libevent:**
```c
struct event *timer = evtimer_new(base, timer_cb, arg);
struct timeval tv = {5, 0};
evtimer_add(timer, &tv);
```

**Socket Library:**
```c
SocketTimer_T timer = SocketTimer_new(arena);
SocketTimer_schedule(timer, 5000, timer_callback, userdata);
/* Process in poll loop */
```

### API Mapping (libevent -> Socket Library)

| libevent | Socket Library |
|----------|----------------|
| `event_base_new()` | `SocketPoll_new()` |
| `event_base_free()` | `SocketPoll_free()` |
| `event_new()` | `SocketPoll_add()` |
| `event_add()` | Automatic |
| `event_del()` | `SocketPoll_remove()` |
| `event_base_dispatch()` | `SocketPoll_wait()` loop |
| `EV_READ` | `POLL_READ` |
| `EV_WRITE` | `POLL_WRITE` |
| `evtimer_new()` | `SocketTimer_schedule()` |
| `bufferevent_*` | `SocketBuf_T` |

---

## Migration from libev

### Event Loop

**libev:**
```c
struct ev_loop *loop = ev_default_loop(0);
ev_io watcher;
ev_io_init(&watcher, callback, fd, EV_READ);
ev_io_start(loop, &watcher);
ev_run(loop, 0);
```

**Socket Library:**
```c
SocketPoll_T poll = SocketPoll_new(1000);
SocketPoll_add(poll, socket, POLL_READ, userdata);

while (running) {
    SocketEvent_T events[100];
    int n = SocketPoll_wait(poll, events, 100, 1000);
    /* Process events */
}
```

---

## Migration from OpenSSL Direct

### TLS Client

**OpenSSL:**
```c
SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
SSL *ssl = SSL_new(ctx);
SSL_set_fd(ssl, fd);
SSL_set_tlsext_host_name(ssl, hostname);
SSL_connect(ssl);
SSL_write(ssl, data, len);
SSL_read(ssl, buf, sizeof(buf));
SSL_shutdown(ssl);
SSL_free(ssl);
SSL_CTX_free(ctx);
```

**Socket Library:**
```c
SocketTLSContext_T ctx = SocketTLSContext_new_client(NULL);
SocketTLS_enable(sock, ctx);
SocketTLS_set_hostname(sock, hostname);
while (SocketTLS_handshake(sock) > 0) { }
SocketTLS_send(sock, data, len);
SocketTLS_recv(sock, buf, sizeof(buf));
SocketTLS_shutdown(sock);
Socket_free(&sock);
SocketTLSContext_free(&ctx);
```

### API Mapping (OpenSSL -> Socket Library)

| OpenSSL | Socket Library |
|---------|----------------|
| `SSL_CTX_new()` | `SocketTLSContext_new_client/server()` |
| `SSL_CTX_free()` | `SocketTLSContext_free()` |
| `SSL_new()` | `SocketTLS_enable()` |
| `SSL_set_fd()` | Automatic |
| `SSL_set_tlsext_host_name()` | `SocketTLS_set_hostname()` |
| `SSL_connect()` | `SocketTLS_handshake()` |
| `SSL_accept()` | `SocketTLS_handshake()` |
| `SSL_write()` | `SocketTLS_send()` |
| `SSL_read()` | `SocketTLS_recv()` |
| `SSL_shutdown()` | `SocketTLS_shutdown()` |
| `SSL_get_version()` | `SocketTLS_get_version()` |
| `SSL_get_cipher()` | `SocketTLS_get_cipher()` |

---

## Common Patterns

### Error Handling Pattern

**Other Libraries (error codes):**
```c
int result = some_function();
if (result < 0) {
    switch (errno) {
        case ETIMEDOUT: /* timeout */ break;
        case ECONNREFUSED: /* refused */ break;
        default: /* error */ break;
    }
}
```

**Socket Library (exceptions):**
```c
TRY {
    some_function();
}
EXCEPT(Socket_Timeout) {
    /* timeout */
}
EXCEPT(Socket_Failed) {
    /* error - Socket_GetLastError() for details */
}
END_TRY;
```

### Resource Cleanup Pattern

**Other Libraries:**
```c
Socket *sock = create_socket();
if (!sock) goto cleanup;

if (connect(sock) < 0) goto cleanup;
if (send(sock) < 0) goto cleanup;

cleanup:
    if (sock) free_socket(sock);
```

**Socket Library:**
```c
Socket_T sock = NULL;
TRY {
    sock = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_connect(sock, host, port);
    Socket_sendall(sock, data, len);
}
FINALLY {
    if (sock) Socket_free(&sock);
}
END_TRY;
```

---

## Key Differences

### Memory Management

- **Arena allocation** - Related objects allocated together
- **Automatic cleanup** - Arena_dispose() frees everything
- **No manual free** for individual objects in arena

### Error Handling

- **Exceptions** instead of error codes
- **Thread-local** error messages
- **Detailed context** in exceptions

### Thread Safety

- **Instance-based** - One instance per thread
- **Thread-local** storage for errors
- **No global state**

---

## Getting Started

1. **Replace socket creation** with `Socket_new()`
2. **Wrap operations** in TRY/EXCEPT blocks
3. **Use convenience functions** (sendall, setreuseaddr, etc.)
4. **Replace poll/select** with `SocketPoll_T`
5. **Use SocketHTTPClient** for HTTP instead of raw sockets
6. **Enable TLS** with `SocketTLS_enable()` for HTTPS

---

## See Also

- [HTTP Guide](@ref http_guide)
- [WebSocket Guide](@ref websocket_guide)
- [Security Guide](@ref security_guide)
- @ref Socket.h
- @ref SocketPoll.h

