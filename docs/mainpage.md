# Socket Library {#mainpage}

A modern C library for building high-performance networked applications. Production-ready with comprehensive support for TCP, UDP, Unix domain sockets, and TLS 1.3 security.

---

## Features

### Core Networking
- **TCP Stream Sockets** — Full client/server support with advanced TCP options
- **UDP Datagram Sockets** — Connectionless and connected modes, multicast support
- **Unix Domain Sockets** — High-performance IPC for local communication
- **TLS 1.3 Security** — Modern encryption via OpenSSL with SNI and ALPN

### Async & Event-Driven
- **Cross-Platform Polling** — epoll (Linux), kqueue (BSD/macOS), poll (fallback)
- **Asynchronous DNS** — Non-blocking resolution with thread pool
- **Happy Eyeballs (RFC 8305)** — Fast dual-stack connection racing
- **Auto-Reconnection** — Exponential backoff with circuit breaker

### Performance
- **Zero-Copy I/O** — Platform-optimized `sendfile()` and scatter/gather
- **Connection Pooling** — O(1) lookup with buffer management
- **Arena Allocation** — Memory-safe with automatic cleanup

---

## Quick Start

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build
```

---

## Examples

### TCP Echo Server

A simple server that echoes back whatever clients send.

```c
#include "socket/Socket.h"
#include "core/Except.h"
#include <signal.h>
#include <stdio.h>

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    
    TRY
        Socket_setreuseaddr(server);
        Socket_bind(server, NULL, 8080);
        Socket_listen(server, 10);
        printf("Listening on port 8080...\n");
        
        while (1) {
            Socket_T client = Socket_accept(server);
            if (client) {
                char buf[1024];
                ssize_t n = Socket_recv(client, buf, sizeof(buf) - 1);
                if (n > 0) {
                    buf[n] = '\0';
                    printf("Received: %s\n", buf);
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

---

### TCP Client

Connect to a server, send data, and receive a response.

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
        printf("Connected to server\n");
        
        const char *message = "Hello, Server!";
        Socket_sendall(client, message, strlen(message));
        
        char buf[1024];
        ssize_t n = Socket_recv(client, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("Server response: %s\n", buf);
        }
    EXCEPT(Socket_Failed)
        fprintf(stderr, "Connection error: %s\n", Socket_error());
    EXCEPT(Socket_Closed)
        fprintf(stderr, "Server closed connection\n");
    END_TRY;
    
    Socket_free(&client);
    return 0;
}
```

---

### Event-Driven Server (Non-Blocking)

Handle multiple clients concurrently using SocketPoll.

```c
#include "socket/Socket.h"
#include "poll/SocketPoll.h"
#include <signal.h>
#include <stdio.h>

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr(server);
    Socket_bind(server, NULL, 8080);
    Socket_listen(server, 128);
    Socket_setnonblocking(server);
    
    SocketPoll_T poll = SocketPoll_new(1024);
    SocketPoll_add(poll, server, POLL_READ, NULL);
    
    printf("Event server on port 8080 (%s backend)\n", 
           SocketPoll_get_backend(poll));
    
    while (1) {
        SocketEvent_T events[64];
        int n = SocketPoll_wait(poll, events, 64, 1000);
        
        for (int i = 0; i < n; i++) {
            Socket_T sock = events[i].socket;
            
            if (sock == server) {
                /* New connection */
                Socket_T client = Socket_accept(server);
                if (client) {
                    Socket_setnonblocking(client);
                    SocketPoll_add(poll, client, POLL_READ, client);
                    printf("Client connected (fd=%d)\n", Socket_fd(client));
                }
            } else {
                /* Client data */
                char buf[1024];
                ssize_t bytes = Socket_recv(sock, buf, sizeof(buf));
                
                if (bytes > 0) {
                    Socket_sendall(sock, buf, bytes);
                } else {
                    printf("Client disconnected (fd=%d)\n", Socket_fd(sock));
                    SocketPoll_remove(poll, sock);
                    Socket_free(&sock);
                }
            }
        }
    }
    
    SocketPoll_free(&poll);
    Socket_free(&server);
    return 0;
}
```

---

### UDP Echo Server

Connectionless datagram server.

```c
#include "socket/SocketDgram.h"
#include "core/Except.h"
#include <stdio.h>

int main(void)
{
    SocketDgram_T server = SocketDgram_new(AF_INET, 0);
    
    TRY
        SocketDgram_bind(server, NULL, 5000);
        printf("UDP server listening on port 5000\n");
        
        while (1) {
            char buf[65536];
            char sender_host[256];
            int sender_port;
            
            ssize_t n = SocketDgram_recvfrom(server, buf, sizeof(buf),
                                            sender_host, sizeof(sender_host),
                                            &sender_port);
            if (n > 0) {
                printf("From %s:%d - %zd bytes\n", sender_host, sender_port, n);
                SocketDgram_sendto(server, buf, n, sender_host, sender_port);
            }
        }
    EXCEPT(SocketDgram_Failed)
        fprintf(stderr, "UDP error: %s\n", Socket_error());
    END_TRY;
    
    SocketDgram_free(&server);
    return 0;
}
```

---

### UDP Client

Send and receive datagrams.

```c
#include "socket/SocketDgram.h"
#include "core/Except.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    SocketDgram_T client = SocketDgram_new(AF_INET, 0);
    
    TRY
        const char *message = "Hello UDP!";
        SocketDgram_sendto(client, message, strlen(message), 
                          "127.0.0.1", 5000);
        
        char buf[1024];
        char from_host[256];
        int from_port;
        
        ssize_t n = SocketDgram_recvfrom(client, buf, sizeof(buf),
                                        from_host, sizeof(from_host),
                                        &from_port);
        if (n > 0) {
            buf[n] = '\0';
            printf("Response from %s:%d: %s\n", from_host, from_port, buf);
        }
    EXCEPT(SocketDgram_Failed)
        fprintf(stderr, "Error: %s\n", Socket_error());
    END_TRY;
    
    SocketDgram_free(&client);
    return 0;
}
```

---

### TLS Client (Secure Connection)

Connect to an HTTPS server with TLS 1.3.

```c
#include "socket/Socket.h"
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"
#include "core/Except.h"
#include <signal.h>
#include <stdio.h>

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    
    /* Create TLS context with system CA certificates */
    SocketTLSContext_T ctx = SocketTLSContext_new_client(NULL);
    
    Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
    
    TRY
        Socket_connect(sock, "example.com", 443);
        
        /* Enable TLS and set SNI hostname */
        SocketTLS_enable(sock, ctx);
        SocketTLS_set_hostname(sock, "example.com");
        
        /* Perform handshake */
        while (SocketTLS_handshake(sock) != TLS_HANDSHAKE_COMPLETE) {
            /* For blocking sockets, this completes immediately */
        }
        
        printf("TLS %s established with %s\n",
               SocketTLS_get_version(sock),
               SocketTLS_get_cipher(sock));
        
        /* Send HTTP request */
        const char *request = "GET / HTTP/1.1\r\n"
                             "Host: example.com\r\n"
                             "Connection: close\r\n\r\n";
        SocketTLS_send(sock, request, strlen(request));
        
        /* Read response */
        char buf[4096];
        ssize_t n = SocketTLS_recv(sock, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("Response:\n%.500s...\n", buf);
        }
        
        SocketTLS_shutdown(sock);
    EXCEPT(SocketTLS_HandshakeFailed)
        fprintf(stderr, "TLS handshake failed: %s\n", Socket_error());
    EXCEPT(SocketTLS_VerifyFailed)
        fprintf(stderr, "Certificate verification failed\n");
    EXCEPT(Socket_Failed)
        fprintf(stderr, "Connection error: %s\n", Socket_error());
    END_TRY;
    
    Socket_free(&sock);
    SocketTLSContext_free(&ctx);
    return 0;
}
```

---

### Unix Domain Socket Server

High-performance local IPC.

```c
#include "socket/Socket.h"
#include "core/Except.h"
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    
    const char *socket_path = "/tmp/myapp.sock";
    
    /* Remove stale socket file */
    unlink(socket_path);
    
    Socket_T server = Socket_new(AF_UNIX, SOCK_STREAM, 0);
    
    TRY
        Socket_bind(server, socket_path, 0);
        Socket_listen(server, 10);
        printf("Unix socket server at %s\n", socket_path);
        
        while (1) {
            Socket_T client = Socket_accept(server);
            if (client) {
                char buf[1024];
                ssize_t n = Socket_recv(client, buf, sizeof(buf) - 1);
                if (n > 0) {
                    buf[n] = '\0';
                    printf("Received: %s\n", buf);
                    Socket_sendall(client, "OK", 2);
                }
                Socket_free(&client);
            }
        }
    EXCEPT(Socket_Failed)
        fprintf(stderr, "Error: %s\n", Socket_error());
    END_TRY;
    
    Socket_free(&server);
    unlink(socket_path);
    return 0;
}
```

---

### Happy Eyeballs (Fast Dual-Stack)

Race IPv4 and IPv6 for fastest connection (RFC 8305).

```c
#include "socket/SocketHappyEyeballs.h"
#include "core/Except.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    
    TRY
        /* Races IPv4/IPv6 and returns first successful connection */
        Socket_T sock = SocketHappyEyeballs_connect("google.com", 80, NULL);
        
        printf("Connected via %s\n", 
               Socket_family(sock) == AF_INET6 ? "IPv6" : "IPv4");
        
        const char *request = "GET / HTTP/1.0\r\nHost: google.com\r\n\r\n";
        Socket_sendall(sock, request, strlen(request));
        
        char buf[1024];
        ssize_t n = Socket_recv(sock, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("Response: %.100s...\n", buf);
        }
        
        Socket_free(&sock);
    EXCEPT(SocketHE_Failed)
        fprintf(stderr, "Connection failed: %s\n", Socket_error());
    END_TRY;
    
    return 0;
}
```

---

### Auto-Reconnecting Client

Resilient connection with exponential backoff.

```c
#include "socket/SocketReconnect.h"
#include "core/Except.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void on_state_change(SocketReconnect_T conn, 
                     SocketReconnect_State state, 
                     void *userdata)
{
    const char *states[] = {
        "DISCONNECTED", "CONNECTING", "CONNECTED", 
        "BACKOFF", "CIRCUIT_OPEN"
    };
    printf("State: %s\n", states[state]);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    
    /* Configure reconnection policy */
    SocketReconnect_Policy_T policy;
    SocketReconnect_policy_defaults(&policy);
    policy.max_attempts = 10;
    policy.initial_delay_ms = 100;
    policy.max_delay_ms = 30000;
    
    SocketReconnect_T conn = SocketReconnect_new(
        "127.0.0.1", 8080, &policy, on_state_change, NULL);
    
    /* Start connection */
    SocketReconnect_connect(conn);
    
    /* Simple event loop */
    while (1) {
        SocketReconnect_tick(conn);
        
        if (SocketReconnect_isconnected(conn)) {
            const char *msg = "ping";
            ssize_t n = SocketReconnect_send(conn, msg, strlen(msg));
            
            if (n > 0) {
                char buf[256];
                n = SocketReconnect_recv(conn, buf, sizeof(buf) - 1);
                if (n > 0) {
                    buf[n] = '\0';
                    printf("Response: %s\n", buf);
                }
            }
        }
        
        usleep(1000000); /* 1 second */
    }
    
    SocketReconnect_free(&conn);
    return 0;
}
```

---

### Connection Pool with Buffers

Efficiently manage multiple connections.

```c
#include "socket/Socket.h"
#include "pool/SocketPool.h"
#include "core/Arena.h"
#include "core/Except.h"
#include <signal.h>
#include <stdio.h>

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    
    Arena_T arena = Arena_new();
    SocketPool_T pool = SocketPool_new(arena, 1000, 8192);
    
    Socket_T server = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_setreuseaddr(server);
    Socket_bind(server, NULL, 8080);
    Socket_listen(server, 128);
    
    printf("Pool server on port 8080\n");
    
    TRY
        while (1) {
            Socket_T client = Socket_accept(server);
            if (!client) continue;
            
            /* Add to pool - automatically creates buffers */
            Connection_T conn = SocketPool_add(pool, client);
            
            /* Get connection's I/O buffers */
            SocketBuf_T input = Connection_input(conn);
            SocketBuf_T output = Connection_output(conn);
            
            /* Read into input buffer */
            ssize_t n = SocketBuf_read(input, Socket_fd(client));
            if (n > 0) {
                /* Copy input to output and send */
                size_t len = SocketBuf_readable(input);
                SocketBuf_append(output, SocketBuf_readptr(input), len);
                SocketBuf_flush(output, Socket_fd(client));
            }
            
            /* Look up connection later by socket */
            Connection_T found = SocketPool_get(pool, client);
            printf("Connection found: %s\n", found ? "yes" : "no");
            
            /* Remove and cleanup */
            SocketPool_remove(pool, client);
            Socket_free(&client);
        }
    EXCEPT(Socket_Failed)
        fprintf(stderr, "Error: %s\n", Socket_error());
    END_TRY;
    
    /* Cleanup idle connections older than 300 seconds */
    SocketPool_cleanup(pool, 300);
    
    SocketPool_free(&pool);
    Socket_free(&server);
    Arena_dispose(&arena);
    return 0;
}
```

---

### Async DNS Resolution

Non-blocking DNS lookup.

```c
#include "dns/SocketDNS.h"
#include "poll/SocketPoll.h"
#include <stdio.h>
#include <netdb.h>

int main(void)
{
    SocketDNS_T dns = SocketDNS_new();
    SocketPoll_T poll = SocketPoll_new(100);
    
    /* Start async resolution */
    SocketDNS_Request_T req = SocketDNS_resolve(
        dns, "example.com", 443, NULL, NULL);
    
    /* Get poll fd for DNS completion */
    int dns_fd = SocketDNS_pollfd(dns);
    /* Note: Add dns_fd to your poll set */
    
    printf("Resolving example.com...\n");
    
    /* Poll for completion */
    while (!SocketDNS_iscomplete(req)) {
        usleep(10000);
        SocketDNS_check(dns);
    }
    
    /* Get result */
    struct addrinfo *result = SocketDNS_getresult(req);
    if (result) {
        char host[256];
        getnameinfo(result->ai_addr, result->ai_addrlen,
                   host, sizeof(host), NULL, 0, NI_NUMERICHOST);
        printf("Resolved to: %s\n", host);
        freeaddrinfo(result);
    } else {
        printf("Resolution failed\n");
    }
    
    SocketDNS_free(&dns);
    SocketPoll_free(&poll);
    return 0;
}
```

---

### Zero-Copy File Transfer

Efficient file sending with sendfile().

```c
#include "socket/Socket.h"
#include "core/Except.h"
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <host> <file>\n", argv[0]);
        return 1;
    }
    
    signal(SIGPIPE, SIG_IGN);
    
    int file_fd = open(argv[2], O_RDONLY);
    if (file_fd < 0) {
        perror("open");
        return 1;
    }
    
    struct stat st;
    fstat(file_fd, &st);
    
    Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
    
    TRY
        Socket_connect(sock, argv[1], 8080);
        
        /* Zero-copy transfer - kernel sends directly from page cache */
        off_t offset = 0;
        ssize_t sent = Socket_sendfileall(sock, file_fd, &offset, st.st_size);
        
        printf("Sent %zd bytes (file size: %ld)\n", sent, st.st_size);
    EXCEPT(Socket_Failed)
        fprintf(stderr, "Error: %s\n", Socket_error());
    END_TRY;
    
    close(file_fd);
    Socket_free(&sock);
    return 0;
}
```

---

### Scatter/Gather I/O

Send multiple buffers efficiently with writev().

```c
#include "socket/Socket.h"
#include "core/Except.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    
    Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
    
    TRY
        Socket_connect(sock, "127.0.0.1", 8080);
        
        /* Prepare multiple buffers */
        char header[] = "HEADER:";
        char body[] = "This is the message body";
        char footer[] = ":END";
        
        struct iovec iov[3];
        iov[0].iov_base = header;
        iov[0].iov_len = strlen(header);
        iov[1].iov_base = body;
        iov[1].iov_len = strlen(body);
        iov[2].iov_base = footer;
        iov[2].iov_len = strlen(footer);
        
        /* Send all buffers in one syscall */
        ssize_t sent = Socket_sendvall(sock, iov, 3);
        printf("Sent %zd bytes across 3 buffers\n", sent);
        
    EXCEPT(Socket_Failed)
        fprintf(stderr, "Error: %s\n", Socket_error());
    END_TRY;
    
    Socket_free(&sock);
    return 0;
}
```

---

### Advanced TCP Options

Configure socket behavior for specific use cases.

```c
#include "socket/Socket.h"
#include <signal.h>
#include <stdio.h>

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    
    Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
    
    /* Disable Nagle's algorithm for low-latency */
    Socket_setnodelay(sock);
    
    /* Set buffer sizes */
    Socket_setsndbuf(sock, 256 * 1024);  /* 256KB send buffer */
    Socket_setrcvbuf(sock, 256 * 1024);  /* 256KB recv buffer */
    
    /* Enable keepalive */
    Socket_setkeepalive(sock, 60, 10, 5);  /* idle=60s, interval=10s, count=5 */
    
    /* Set timeouts */
    Socket_settimeout(sock, 30000);  /* 30 second timeout */
    
    /* Linux-specific: Set congestion control */
    #ifdef __linux__
    Socket_setcongestion(sock, "bbr");
    
    /* TCP Fast Open (client side) */
    Socket_setfastopen(sock, 1);
    
    /* TCP user timeout */
    Socket_setusertimeout(sock, 30000);
    #endif
    
    printf("Send buffer: %d\n", Socket_getsndbuf(sock));
    printf("Recv buffer: %d\n", Socket_getrcvbuf(sock));
    
    Socket_free(&sock);
    return 0;
}
```

---

## Header Files

| Header | Description |
|--------|-------------|
| [Socket.h](Socket_8h.html) | TCP stream sockets |
| [SocketDgram.h](SocketDgram_8h.html) | UDP datagram sockets |
| [SocketPoll.h](SocketPoll_8h.html) | Cross-platform event polling |
| [SocketPool.h](SocketPool_8h.html) | Connection pooling |
| [SocketDNS.h](SocketDNS_8h.html) | Async DNS resolution |
| [SocketHappyEyeballs.h](SocketHappyEyeballs_8h.html) | RFC 8305 implementation |
| [SocketReconnect.h](SocketReconnect_8h.html) | Auto-reconnection |
| [SocketTLS.h](SocketTLS_8h.html) | TLS 1.3 encryption |
| [SocketBuf.h](SocketBuf_8h.html) | I/O buffers |
| [Arena.h](Arena_8h.html) | Memory management |
| [Except.h](Except_8h.html) | Exception handling |

---

## Error Handling

All operations use exception-based error handling:

```c
TRY
    Socket_connect(socket, "example.com", 443);
    Socket_sendall(socket, data, len);
EXCEPT(Socket_Failed)
    fprintf(stderr, "Error: %s\n", Socket_error());
FINALLY
    Socket_free(&socket);
END_TRY;
```

### Exception Types

| Exception | Description |
|-----------|-------------|
| `Socket_Failed` | General socket operation failure |
| `Socket_Closed` | Connection closed by peer |
| `SocketDgram_Failed` | UDP operation failure |
| `SocketPoll_Failed` | Event polling error |
| `SocketDNS_Failed` | DNS resolution failure |
| `SocketHE_Failed` | Happy Eyeballs failure |
| `SocketTLS_Failed` | TLS operation error |
| `SocketTLS_HandshakeFailed` | TLS handshake failure |
| `SocketTLS_VerifyFailed` | Certificate verification failed |

---

## Platform Support

| Platform | Poll Backend | Status |
|----------|--------------|--------|
| Linux 2.6+ | epoll | Full support |
| BSD/macOS | kqueue | Full support |
| Other POSIX | poll | Fallback |

**Requirements:** POSIX-compliant system, C11 compiler, pthread support.

---

## Documentation

- **[Files](files.html)** — Header file reference
- **[Data Structures](annotated.html)** — Structs and types
- **[API Reference](globals.html)** — Complete function index
- **[Async I/O Guide](md_docs_2_a_s_y_n_c__i_o.html)** — io_uring patterns
