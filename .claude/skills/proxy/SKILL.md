---
name: proxy
description: SOCKS4/5 and HTTP CONNECT proxy protocol implementation patterns. Use when working on proxy tunneling, SOCKS authentication, or files in src/socket/SocketProxy*.c.
---

You are an expert C developer specializing in proxy protocol implementations including SOCKS4, SOCKS4a, SOCKS5, and HTTP CONNECT tunneling.

## Proxy Architecture

```
SocketProxy_T
    ├── Proxy Type (SOCKS4, SOCKS4a, SOCKS5, HTTP_CONNECT)
    ├── Proxy Credentials (username/password)
    ├── Target Address (final destination)
    └── State Machine (handshake phases)

Connection Flow:
    Client ──► Proxy Server ──► Target Server
         SOCKS/HTTP        TCP/TLS
         handshake         connection
```

## SOCKS4 Protocol

```c
// SOCKS4 Request (8+ bytes)
struct socks4_request {
    uint8_t version;      // 0x04
    uint8_t command;      // 0x01 = CONNECT, 0x02 = BIND
    uint16_t port;        // Network byte order
    uint32_t ip;          // Network byte order (NOT for SOCKS4a)
    char userid[];        // Null-terminated
};

// SOCKS4a extension: IP = 0.0.0.x, hostname after userid
// userid\0hostname\0

// SOCKS4 Response (8 bytes)
struct socks4_response {
    uint8_t null;         // 0x00
    uint8_t status;       // 0x5A = granted, 0x5B-0x5D = rejected
    uint16_t port;        // Bound port (for BIND)
    uint32_t ip;          // Bound IP (for BIND)
};

int socks4_connect(Socket_T sock, const char *host, int port) {
    uint8_t request[512];
    size_t len = 0;

    request[len++] = 0x04;  // Version
    request[len++] = 0x01;  // CONNECT

    // Port in network byte order
    request[len++] = (port >> 8) & 0xFF;
    request[len++] = port & 0xFF;

    // SOCKS4a: Use 0.0.0.1 to signal hostname follows
    request[len++] = 0x00;
    request[len++] = 0x00;
    request[len++] = 0x00;
    request[len++] = 0x01;

    // Empty userid
    request[len++] = 0x00;

    // Hostname (SOCKS4a)
    strcpy((char *)&request[len], host);
    len += strlen(host) + 1;

    Socket_send(sock, request, len, 0);

    // Read response
    uint8_t response[8];
    Socket_recv(sock, response, 8, 0);

    if (response[1] != 0x5A) {
        return -1;  // Rejected
    }
    return 0;
}
```

## SOCKS5 Protocol

### Phase 1: Authentication Negotiation

```c
// Client greeting
struct socks5_greeting {
    uint8_t version;      // 0x05
    uint8_t num_methods;
    uint8_t methods[];    // 0x00=None, 0x02=Username/Password
};

// Server choice
struct socks5_choice {
    uint8_t version;      // 0x05
    uint8_t method;       // Selected method or 0xFF (none acceptable)
};

int socks5_negotiate_auth(Socket_T sock, bool have_credentials) {
    uint8_t greeting[4];
    greeting[0] = 0x05;  // Version
    greeting[1] = have_credentials ? 2 : 1;  // Number of methods
    greeting[2] = 0x00;  // No auth
    if (have_credentials) {
        greeting[3] = 0x02;  // Username/password
    }

    Socket_send(sock, greeting, have_credentials ? 4 : 3, 0);

    uint8_t choice[2];
    Socket_recv(sock, choice, 2, 0);

    if (choice[0] != 0x05 || choice[1] == 0xFF) {
        return -1;  // No acceptable method
    }

    return choice[1];  // Return selected method
}
```

### Phase 2: Username/Password Authentication (RFC 1929)

```c
// Auth request
// [version=0x01][ulen][username][plen][password]

// Auth response
// [version=0x01][status] (0x00 = success)

int socks5_authenticate(Socket_T sock, const char *user, const char *pass) {
    uint8_t auth[515];
    size_t len = 0;

    auth[len++] = 0x01;  // Subnegotiation version

    size_t ulen = strlen(user);
    size_t plen = strlen(pass);

    if (ulen > 255 || plen > 255) return -1;

    auth[len++] = ulen;
    memcpy(&auth[len], user, ulen);
    len += ulen;

    auth[len++] = plen;
    memcpy(&auth[len], pass, plen);
    len += plen;

    Socket_send(sock, auth, len, 0);

    uint8_t response[2];
    Socket_recv(sock, response, 2, 0);

    return (response[1] == 0x00) ? 0 : -1;
}
```

### Phase 3: Connection Request

```c
// SOCKS5 Request
struct socks5_request {
    uint8_t version;      // 0x05
    uint8_t command;      // 0x01=CONNECT, 0x02=BIND, 0x03=UDP_ASSOCIATE
    uint8_t reserved;     // 0x00
    uint8_t addr_type;    // 0x01=IPv4, 0x03=Domain, 0x04=IPv6
    // Address: 4 bytes (IPv4), 1+N bytes (domain), 16 bytes (IPv6)
    // Port: 2 bytes (network order)
};

// SOCKS5 Response (same format as request)
// Status codes: 0x00=success, 0x01-0x08=various errors

int socks5_connect(Socket_T sock, const char *host, int port) {
    uint8_t request[262];
    size_t len = 0;

    request[len++] = 0x05;  // Version
    request[len++] = 0x01;  // CONNECT
    request[len++] = 0x00;  // Reserved

    // Domain name
    size_t hostlen = strlen(host);
    if (hostlen > 255) return -1;

    request[len++] = 0x03;  // Domain type
    request[len++] = hostlen;
    memcpy(&request[len], host, hostlen);
    len += hostlen;

    // Port
    request[len++] = (port >> 8) & 0xFF;
    request[len++] = port & 0xFF;

    Socket_send(sock, request, len, 0);

    // Response: version, status, reserved, addr_type, addr, port
    uint8_t response[262];
    Socket_recv(sock, response, 4, 0);  // Read header first

    if (response[0] != 0x05 || response[1] != 0x00) {
        return socks5_error_to_errno(response[1]);
    }

    // Skip bound address
    skip_socks5_address(sock, response[3]);

    return 0;
}
```

## HTTP CONNECT Tunnel

```c
// HTTP CONNECT is simpler - just HTTP request/response

int http_connect(Socket_T sock, const char *host, int port,
                 const char *proxy_user, const char *proxy_pass) {
    char request[1024];
    int len;

    if (proxy_user && proxy_pass) {
        // Basic authentication
        char credentials[256];
        snprintf(credentials, sizeof(credentials), "%s:%s", proxy_user, proxy_pass);

        char b64_creds[512];
        base64_encode(credentials, strlen(credentials), b64_creds);

        len = snprintf(request, sizeof(request),
            "CONNECT %s:%d HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Proxy-Authorization: Basic %s\r\n"
            "Proxy-Connection: Keep-Alive\r\n"
            "\r\n",
            host, port, host, port, b64_creds);
    } else {
        len = snprintf(request, sizeof(request),
            "CONNECT %s:%d HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Proxy-Connection: Keep-Alive\r\n"
            "\r\n",
            host, port, host, port);
    }

    Socket_send(sock, request, len, 0);

    // Read response line
    char response[1024];
    read_http_line(sock, response, sizeof(response));

    // Parse "HTTP/1.x 200 Connection established"
    int status_code;
    if (sscanf(response, "HTTP/%*d.%*d %d", &status_code) != 1) {
        return -1;
    }

    if (status_code != 200) {
        return -1;
    }

    // Skip headers until empty line
    while (read_http_line(sock, response, sizeof(response)) > 0) {
        if (response[0] == '\r' || response[0] == '\n') break;
    }

    return 0;  // Tunnel established
}
```

## Unified Proxy Interface

```c
typedef enum {
    PROXY_NONE,
    PROXY_SOCKS4,
    PROXY_SOCKS4A,
    PROXY_SOCKS5,
    PROXY_HTTP_CONNECT
} ProxyType;

typedef struct SocketProxy {
    ProxyType type;
    char *proxy_host;
    int proxy_port;
    char *username;      // Optional
    char *password;      // Optional
} *SocketProxy_T;

// High-level API
Socket_T Socket_connect_via_proxy(SocketProxy_T proxy,
                                   const char *target_host,
                                   int target_port) {
    // 1. Connect to proxy server
    Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
    Socket_connect(sock, proxy->proxy_host, proxy->proxy_port);

    // 2. Perform protocol-specific handshake
    int result;
    switch (proxy->type) {
        case PROXY_SOCKS4:
        case PROXY_SOCKS4A:
            result = socks4_connect(sock, target_host, target_port,
                                    proxy->type == PROXY_SOCKS4A);
            break;
        case PROXY_SOCKS5:
            result = socks5_full_handshake(sock, target_host, target_port,
                                            proxy->username, proxy->password);
            break;
        case PROXY_HTTP_CONNECT:
            result = http_connect(sock, target_host, target_port,
                                  proxy->username, proxy->password);
            break;
        default:
            RAISE(Socket_Failed);
    }

    if (result != 0) {
        Socket_free(&sock);
        RAISE(Socket_Failed);
    }

    return sock;  // Tunnel established, use normally
}
```

## Proxy Chaining

```c
// Connect through multiple proxies
Socket_T Socket_connect_via_chain(SocketProxy_T *chain, int chain_len,
                                   const char *target_host, int target_port) {
    Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);

    // Connect to first proxy
    Socket_connect(sock, chain[0]->proxy_host, chain[0]->proxy_port);

    // Tunnel through each proxy to the next
    for (int i = 0; i < chain_len - 1; i++) {
        tunnel_to(sock, chain[i], chain[i+1]->proxy_host, chain[i+1]->proxy_port);
    }

    // Final tunnel to target
    tunnel_to(sock, chain[chain_len-1], target_host, target_port);

    return sock;
}
```

## UDP ASSOCIATE (SOCKS5)

```c
// SOCKS5 can proxy UDP traffic
// 1. Establish TCP control connection
// 2. Send UDP ASSOCIATE request
// 3. Use returned UDP relay address
// 4. Encapsulate UDP packets with SOCKS5 header

struct socks5_udp_header {
    uint16_t reserved;    // 0x0000
    uint8_t fragment;     // 0x00 for complete datagram
    uint8_t addr_type;
    // Address and port follow
    // Then actual UDP payload
};
```

## Error Handling

```c
// SOCKS5 error codes
const char *socks5_strerror(uint8_t code) {
    switch (code) {
        case 0x00: return "Success";
        case 0x01: return "General SOCKS server failure";
        case 0x02: return "Connection not allowed by ruleset";
        case 0x03: return "Network unreachable";
        case 0x04: return "Host unreachable";
        case 0x05: return "Connection refused";
        case 0x06: return "TTL expired";
        case 0x07: return "Command not supported";
        case 0x08: return "Address type not supported";
        default:   return "Unknown error";
    }
}
```

## Security Considerations

1. **Credential protection**: Never log passwords, use secure memory
2. **DNS leaks**: Use SOCKS4a/5 with domain names to avoid local DNS
3. **TLS over proxy**: Establish TLS after tunnel is ready
4. **Proxy authentication**: SOCKS5 password is cleartext; use TLS to proxy
5. **Timeout handling**: Set reasonable timeouts for handshakes

## Files Reference

| File | Purpose |
|------|---------|
| `include/socket/SocketProxy.h` | Proxy API |
| `src/socket/SocketProxy.c` | Main implementation |
| `src/socket/SocketProxy-socks4.c` | SOCKS4/4a protocol |
| `src/socket/SocketProxy-socks5.c` | SOCKS5 protocol |
| `src/socket/SocketProxy-http.c` | HTTP CONNECT |
| `src/test/test_proxy.c` | Proxy tests |
