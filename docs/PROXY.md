# Proxy Guide {#proxy_guide}

Complete guide to proxy tunneling support in the Socket Library.

---

## Overview

The `SocketProxy` module provides transparent proxy tunneling for TCP connections:

- **HTTP CONNECT** (RFC 7231) - Standard HTTP proxy method
- **HTTPS CONNECT** - TLS-encrypted connection to proxy
- **SOCKS4** - Legacy protocol, IPv4 only
- **SOCKS4a** - SOCKS4 with hostname resolution at proxy
- **SOCKS5** (RFC 1928) - Modern protocol with authentication
- **SOCKS5H** - SOCKS5 with hostname resolution at proxy

---

## Quick Start

### SOCKS5 Proxy

```c
#include "socket/SocketProxy.h"

SocketProxy_Config proxy;
SocketProxy_config_defaults(&proxy);
proxy.type = SOCKET_PROXY_SOCKS5;
proxy.host = "proxy.example.com";
proxy.port = 1080;

/* Connect through proxy */
Socket_T sock = SocketProxy_connect(&proxy, "target.example.com", 443);

/* Now tunneled to target - perform TLS if needed */
```

### With Authentication

```c
proxy.username = "user";
proxy.password = "secret";
```

### Using URL Parser

```c
SocketProxy_Config proxy;
SocketProxy_parse_url("socks5://user:pass@proxy.example.com:1080", &proxy, NULL);

Socket_T sock = SocketProxy_connect(&proxy, "target.example.com", 443);
```

---

## Proxy Types

### HTTP CONNECT

Standard method for HTTP proxies (port 8080 default):

```c
proxy.type = SOCKET_PROXY_HTTP;
proxy.host = "proxy.corp.com";
proxy.port = 8080;
proxy.username = "user";      /* Optional Basic auth */
proxy.password = "password";
```

**How it works:**
1. Connect to proxy server
2. Send `CONNECT target:port HTTP/1.1`
3. Receive `200 Connection established`
4. Tunnel is ready

### HTTPS CONNECT

Same as HTTP CONNECT, but with TLS to the proxy:

```c
proxy.type = SOCKET_PROXY_HTTPS;
/* Everything else same as HTTP */
```

Use when proxy requires encrypted connection (corporate proxies).

### SOCKS4

Legacy protocol, IPv4 only:

```c
proxy.type = SOCKET_PROXY_SOCKS4;
proxy.host = "socks.example.com";
proxy.port = 1080;  /* Default SOCKS port */
```

**Limitations:**
- IPv4 addresses only
- No authentication support
- Client must resolve hostname

### SOCKS4a

SOCKS4 with proxy-side DNS:

```c
proxy.type = SOCKET_PROXY_SOCKS4A;
```

Useful when target hostname shouldn't be resolved locally.

### SOCKS5 (RFC 1928)

Modern, full-featured protocol:

```c
proxy.type = SOCKET_PROXY_SOCKS5;
proxy.host = "socks.example.com";
proxy.port = 1080;
proxy.username = "user";      /* Optional */
proxy.password = "pass";
```

**Features:**
- IPv4 and IPv6 support
- Username/password authentication (RFC 1929)
- Client-side DNS resolution

### SOCKS5H

SOCKS5 with proxy-side DNS:

```c
proxy.type = SOCKET_PROXY_SOCKS5H;
```

Use when:
- Target hostname is internal to proxy network
- Want to hide DNS queries from local network
- Local DNS is unreliable

---

## Configuration

### Full Configuration Structure

```c
typedef struct SocketProxy_Config {
    SocketProxyType type;       /* Proxy protocol type */
    
    /* Proxy server */
    const char *host;           /* Proxy hostname or IP */
    int port;                   /* Proxy port (0 = default) */
    
    /* Authentication */
    const char *username;       /* For SOCKS5/HTTP auth */
    const char *password;       /* For SOCKS5/HTTP auth */
    
    /* HTTP CONNECT specific */
    SocketHTTP_Headers_T extra_headers;  /* Additional headers */
    
    /* Timeouts */
    int connect_timeout_ms;     /* Proxy connection timeout */
    int handshake_timeout_ms;   /* Protocol handshake timeout */
} SocketProxy_Config;
```

### Default Ports

| Type | Default Port |
|------|--------------|
| SOCKS4/4a/5/5H | 1080 |
| HTTP CONNECT | 8080 |
| HTTPS CONNECT | 8080 |

### URL Parser

Parse proxy URLs into configuration:

```c
SocketProxy_Config proxy;
int result = SocketProxy_parse_url(url, &proxy, arena);
```

**Supported URL formats:**
```
socks5://host:port
socks5://user:pass@host:port
socks5h://host:port
socks4://host:port
socks4a://host:port
http://host:port
http://user:pass@host:port
https://host:port
```

**Examples:**
```c
SocketProxy_parse_url("socks5://localhost:1080", &proxy, NULL);
SocketProxy_parse_url("socks5://admin:secret@proxy.local:1080", &proxy, NULL);
SocketProxy_parse_url("http://proxy.corp.com:8080", &proxy, NULL);
```

---

## Synchronous API

### Simple Connection

```c
Socket_T sock = SocketProxy_connect(&proxy, "target.com", 443);

if (sock) {
    /* Tunnel established */
    /* Perform TLS handshake if target is HTTPS */
    /* Use socket normally */
    Socket_free(&sock);
}
```

### Using Existing Socket

If you need control over socket creation:

```c
/* Create and connect to proxy manually */
Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
Socket_connect(sock, proxy.host, proxy.port);

/* Establish tunnel */
SocketProxy_Result result = SocketProxy_tunnel(sock, &proxy, "target.com", 443);

if (result == PROXY_OK) {
    /* Tunnel ready */
}
```

---

## Asynchronous API

For non-blocking operation in event loops:

### Starting Connection

```c
SocketProxy_Conn_T conn = SocketProxy_Conn_new(&proxy, "target.com", 443);
```

### Polling Progress

```c
/* Get file descriptor for polling */
int fd = SocketProxy_Conn_fd(conn);
unsigned events = SocketProxy_Conn_poll_events(conn);

/* Add to poll */
SocketPoll_add(poll, fd, events, conn);
```

### Processing Events

```c
while (!SocketProxy_Conn_poll(conn)) {
    /* Wait for events */
    SocketEvent_T events[10];
    int n = SocketPoll_wait(poll, events, 10, 
                            SocketProxy_Conn_next_timeout_ms(conn));
    
    /* Process */
    SocketProxy_Conn_process(conn);
}
```

### Getting Result

```c
if (SocketProxy_Conn_poll(conn)) {
    SocketProxy_Result result = SocketProxy_Conn_result(conn);
    
    if (result == PROXY_OK) {
        /* Get tunneled socket (ownership transferred) */
        Socket_T sock = SocketProxy_Conn_socket(conn);
        /* Use socket */
    } else {
        const char *error = SocketProxy_Conn_error(conn);
        printf("Failed: %s\n", error);
    }
}

SocketProxy_Conn_free(&conn);
```

### Cancellation

```c
/* Cancel in-progress operation */
SocketProxy_Conn_cancel(conn);
```

---

## Result Codes

```c
typedef enum {
    PROXY_OK = 0,                    /* Success */
    PROXY_IN_PROGRESS,               /* Async in progress */
    PROXY_ERROR,                     /* Generic error */
    PROXY_ERROR_CONNECT,             /* Can't connect to proxy */
    PROXY_ERROR_AUTH_REQUIRED,       /* Proxy needs auth */
    PROXY_ERROR_AUTH_FAILED,         /* Auth rejected */
    PROXY_ERROR_FORBIDDEN,           /* Target not allowed */
    PROXY_ERROR_HOST_UNREACHABLE,    /* Target unreachable */
    PROXY_ERROR_NETWORK_UNREACHABLE, /* Network unreachable */
    PROXY_ERROR_CONNECTION_REFUSED,  /* Target refused */
    PROXY_ERROR_TTL_EXPIRED,         /* TTL expired */
    PROXY_ERROR_PROTOCOL,            /* Protocol error */
    PROXY_ERROR_UNSUPPORTED,         /* Feature not supported */
    PROXY_ERROR_TIMEOUT,             /* Operation timed out */
    PROXY_ERROR_CANCELLED            /* User cancelled */
} SocketProxy_Result;
```

---

## TLS Over Proxy

For HTTPS targets through a proxy:

```c
/* Connect through proxy */
Socket_T sock = SocketProxy_connect(&proxy, "secure.example.com", 443);

/* Now establish TLS to target (not proxy) */
SocketTLSContext_T tls_ctx = SocketTLSContext_new_client(NULL);
SocketTLS_enable(sock, tls_ctx);
SocketTLS_set_hostname(sock, "secure.example.com");

while (SocketTLS_handshake(sock) > 0) { /* wait */ }

/* Now have end-to-end TLS through proxy tunnel */
SocketTLS_send(sock, request, len);
```

---

## HTTP Client Integration

The HTTP client supports proxy configuration:

```c
#include "http/SocketHTTPClient.h"

SocketProxy_Config proxy;
SocketProxy_parse_url("socks5://localhost:1080", &proxy, NULL);

SocketHTTPClient_Config config;
SocketHTTPClient_config_defaults(&config);
config.proxy = &proxy;

SocketHTTPClient_T client = SocketHTTPClient_new(&config);

/* All requests go through proxy */
SocketHTTPClient_get(client, "https://example.com", &response);
```

---

## Security Considerations

### Credential Handling

Credentials are cleared from memory after use:

```c
/* Library uses SocketCrypto_secure_clear() internally */
/* Credentials are never logged */
```

### DNS Privacy

| Type | Local DNS | Proxy DNS |
|------|-----------|-----------|
| SOCKS4 | Yes | No |
| SOCKS4a | No | Yes |
| SOCKS5 | Yes | No |
| SOCKS5H | No | Yes |
| HTTP CONNECT | Yes | No |

Use SOCKS5H or SOCKS4a when DNS queries should not leak locally.

### Response Validation

All proxy responses are strictly validated:
- HTTP response parsing uses strict mode
- SOCKS responses are bounds-checked
- Protocol violations raise errors

---

## Error Handling

```c
TRY {
    Socket_T sock = SocketProxy_connect(&proxy, target, port);
}
EXCEPT(SocketProxy_Failed) {
    /* Proxy operation failed */
}
EXCEPT(Socket_Failed) {
    /* Socket error */
}
END_TRY;
```

For async operations, check result codes:

```c
SocketProxy_Result result = SocketProxy_Conn_result(conn);
switch (result) {
case PROXY_OK:
    /* Success */
    break;
case PROXY_ERROR_AUTH_REQUIRED:
    /* Need to add credentials */
    break;
case PROXY_ERROR_AUTH_FAILED:
    /* Wrong credentials */
    break;
case PROXY_ERROR_FORBIDDEN:
    /* Proxy policy blocks target */
    break;
default:
    printf("Error: %s\n", SocketProxy_Conn_error(conn));
}
```

---

## Connection State Machine

```
IDLE ─────► CONNECTING_PROXY ─────► TLS_TO_PROXY (HTTPS only)
                  │                        │
                  ▼                        ▼
            HANDSHAKE_SEND ◄──────────────┘
                  │
                  ▼
            HANDSHAKE_RECV
                  │
                  ├────────► AUTH_SEND ────► AUTH_RECV
                  │                              │
                  ▼                              ▼
            CONNECTED ◄──────────────────────────┘
                  
    Any state ────► FAILED
    Any state ────► CANCELLED
```

---

## Best Practices

1. **Use SOCKS5H** for privacy-sensitive applications
2. **Set reasonable timeouts** - Proxies can be slow
3. **Handle authentication errors** - Prompt for credentials
4. **Verify TLS to target** - Proxy can't see encrypted content
5. **Consider proxy chains** - Connect through multiple proxies

---

## Thread Safety

- `SocketProxy_connect()` is thread-safe (creates internal resources)
- `SocketProxy_Conn_T` instances are NOT thread-safe
- URL parser with `arena=NULL` uses thread-local buffer

---

## See Also

- [HTTP Guide](@ref http_guide) - HTTP client proxy integration
- [Security Guide](@ref security_guide) - TLS configuration
- @ref SocketProxy.h - API reference

