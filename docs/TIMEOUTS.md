# Timeout Configuration Guide

This document describes the timeout architecture, configuration APIs, and best practices for the Socket Library.

## Overview

The Socket Library implements comprehensive timeout support across all operation phases:

| Phase | Description | Default (ms) | Configuration |
|-------|-------------|--------------|---------------|
| DNS Resolution | Name lookup via `getaddrinfo()` | 5000 | `dns_timeout_ms` |
| TCP Connect | Socket connection establishment | 30000 | `connect_timeout_ms` |
| TLS Handshake | SSL/TLS negotiation | 30000 | `operation_timeout_ms` or `SocketTLS_handshake_loop()` |
| Request/Response | HTTP request cycle | 60000 | HTTP client `request_timeout_ms` |
| Proxy Handshake | SOCKS/HTTP CONNECT | 30000 | `handshake_timeout_ms` |

## Timeout Architecture

### Timeout Hierarchy

Timeouts follow a precedence hierarchy from most specific to most general:

```
Per-Request Timeout (highest priority)
    ↓
Per-Socket Extended Timeouts (SocketTimeouts_Extended_T)
    ↓
Per-Socket Basic Timeouts (SocketTimeouts_T)
    ↓
Global Defaults (Socket_timeouts_setdefaults)
    ↓
Compile-Time Defaults (lowest priority)
```

### Basic Timeout Structure

The `SocketTimeouts_T` structure provides core timeout configuration:

```c
typedef struct SocketTimeouts
{
  int connect_timeout_ms;   /* TCP connect (0 = infinite) */
  int dns_timeout_ms;       /* DNS resolution (0 = infinite) */
  int operation_timeout_ms; /* General operations including TLS (0 = infinite) */
} SocketTimeouts_T;
```

### Extended Timeout Structure

For fine-grained control, use `SocketTimeouts_Extended_T`:

```c
typedef struct SocketTimeouts_Extended
{
  int dns_timeout_ms;       /* DNS resolution (0 = use basic) */
  int connect_timeout_ms;   /* TCP connect (0 = use basic) */
  int tls_timeout_ms;       /* TLS handshake (0 = use operation_timeout_ms) */
  int request_timeout_ms;   /* Full request cycle (HTTP client level) */
  int operation_timeout_ms; /* Fallback for unspecified phases */
} SocketTimeouts_Extended_T;
```

## Configuration APIs

### Setting Global Defaults

```c
#include "socket/Socket.h"

SocketTimeouts_T timeouts = {
  .connect_timeout_ms = 10000,   /* 10 seconds */
  .dns_timeout_ms = 5000,        /* 5 seconds */
  .operation_timeout_ms = 30000  /* 30 seconds */
};

Socket_timeouts_setdefaults(&timeouts);
```

### Per-Socket Configuration

```c
Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

/* Basic timeouts */
SocketTimeouts_T timeouts = {
  .connect_timeout_ms = 5000,
  .dns_timeout_ms = 2000,
  .operation_timeout_ms = 15000
};
Socket_timeouts_set(socket, &timeouts);

/* Extended timeouts (per-phase control) */
SocketTimeouts_Extended_T extended = {
  .dns_timeout_ms = 2000,
  .connect_timeout_ms = 5000,
  .tls_timeout_ms = 10000,
  .request_timeout_ms = 30000,
  .operation_timeout_ms = 15000
};
Socket_timeouts_set_extended(socket, &extended);
```

### Querying Current Timeouts

```c
SocketTimeouts_T timeouts;
Socket_timeouts_get(socket, &timeouts);
printf("Connect timeout: %d ms\n", timeouts.connect_timeout_ms);

SocketTimeouts_Extended_T extended;
Socket_timeouts_get_extended(socket, &extended);
printf("TLS timeout: %d ms\n", extended.tls_timeout_ms);
```

## Module-Specific Timeout Behavior

### Socket Connect (`Socket_connect`)

DNS resolution and TCP connect use socket-configured timeouts:

```c
Socket_T socket = Socket_new(AF_INET, SOCK_STREAM, 0);

SocketTimeouts_T timeouts = {
  .connect_timeout_ms = 5000,
  .dns_timeout_ms = 2000
};
Socket_timeouts_set(socket, &timeouts);

/* Both DNS and connect respect configured timeouts */
Socket_connect(socket, "example.com", 443);
```

### Happy Eyeballs (`SocketHappyEyeballs`)

RFC 8305 implementation with multiple timeout phases:

```c
SocketHE_Config_T config;
SocketHappyEyeballs_config_defaults(&config);

config.dns_timeout_ms = 3000;           /* DNS per-query timeout */
config.first_attempt_delay_ms = 250;    /* IPv6 → IPv4 fallback delay */
config.attempt_timeout_ms = 5000;       /* Per-attempt timeout */
config.total_timeout_ms = 30000;        /* Overall operation timeout */

Socket_T socket = SocketHappyEyeballs_connect("example.com", 443, &config);
```

**Timeout behavior:**
- DNS timeout limits the resolution phase
- `first_attempt_delay_ms` delays IPv4 fallback (RFC 8305 recommendation: 250ms)
- `attempt_timeout_ms` applies to each connection attempt
- `total_timeout_ms` caps the entire operation

### TLS Handshake (`SocketTLS`)

Two approaches for TLS timeout:

```c
/* Approach 1: Explicit timeout */
SocketTLS_enable(socket, tls_ctx);
SocketTLS_set_hostname(socket, "example.com");
TLSHandshakeState state = SocketTLS_handshake_loop(socket, 10000);

/* Approach 2: Use socket's operation_timeout_ms (recommended) */
SocketTLS_enable(socket, tls_ctx);
SocketTLS_set_hostname(socket, "example.com");
TLSHandshakeState state = SocketTLS_handshake_auto(socket);
```

`SocketTLS_handshake_auto()` automatically uses the socket's `operation_timeout_ms`, falling back to `SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS` (30 seconds).

### HTTP Client (`SocketHTTPClient`)

Comprehensive timeout configuration:

```c
SocketHTTPClient_Config config;
SocketHTTPClient_config_defaults(&config);

config.dns_timeout_ms = 5000;      /* DNS resolution */
config.connect_timeout_ms = 10000; /* TCP + TLS connection */
config.request_timeout_ms = 60000; /* Full request/response cycle */

SocketHTTPClient_T client = SocketHTTPClient_new(&config);
```

**Timeout coverage:**
- `dns_timeout_ms`: Passed to Happy Eyeballs for DNS resolution
- `connect_timeout_ms`: Used for TCP connection and TLS handshake
- `request_timeout_ms`: Overall request timeout (configured but enforcement may be limited in current implementation)

Per-request timeout override:

```c
SocketHTTPClient_Request_T req = SocketHTTPClient_Request_new(client, HTTP_METHOD_GET, url);
SocketHTTPClient_Request_timeout(req, 5000); /* 5 second timeout for this request */
```

### Proxy Tunneling (`SocketProxy`)

Separate timeouts for connection and handshake phases:

```c
SocketProxy_Config proxy = {
  .type = SOCKET_PROXY_SOCKS5,
  .host = "proxy.example.com",
  .port = 1080,
  .connect_timeout_ms = 5000,    /* Connecting to proxy server */
  .handshake_timeout_ms = 10000  /* SOCKS/HTTP CONNECT negotiation */
};
```

Async API timeout:

```c
SocketProxy_Conn_T conn = SocketProxy_connect_async(&proxy, target_host, target_port);

while (!SocketProxy_Conn_poll(conn)) {
  int timeout = SocketProxy_Conn_next_timeout_ms(conn);
  /* Use timeout in poll() */
  SocketProxy_Conn_process(conn);
}
```

## Timeout Helper Functions

The library provides helper functions for deadline-based timeout calculations:

```c
#include "core/SocketUtil.h"

/* Create a deadline */
int64_t deadline = SocketTimeout_deadline_ms(5000); /* 5 second deadline */

/* Check remaining time */
int64_t remaining = SocketTimeout_remaining_ms(deadline);
printf("Remaining: %lld ms\n", remaining);

/* Check if expired */
if (SocketTimeout_expired(deadline)) {
  /* Handle timeout */
}

/* Calculate poll timeout respecting deadline */
int poll_timeout = SocketTimeout_poll_timeout(1000, deadline);
poll(fds, nfds, poll_timeout);

/* Get current monotonic time */
int64_t now = SocketTimeout_now_ms();

/* Calculate elapsed time */
int64_t elapsed = SocketTimeout_elapsed_ms(start_time);
```

## Best Practices

### 1. Always Set Timeouts

Never rely on default infinite timeouts in production:

```c
/* BAD: No timeouts - can hang indefinitely */
Socket_connect(socket, hostname, port);

/* GOOD: Explicit timeouts */
SocketTimeouts_T timeouts = {
  .connect_timeout_ms = 10000,
  .dns_timeout_ms = 5000,
  .operation_timeout_ms = 30000
};
Socket_timeouts_set(socket, &timeouts);
Socket_connect(socket, hostname, port);
```

### 2. Use Appropriate Timeout Values

| Use Case | DNS | Connect | TLS | Request |
|----------|-----|---------|-----|---------|
| Interactive UI | 2-3s | 5s | 5s | 10s |
| Background Task | 5s | 10s | 10s | 60s |
| Batch Processing | 10s | 30s | 30s | 300s |
| Health Check | 1s | 2s | 2s | 5s |

### 3. Handle Timeout Errors Gracefully

```c
TRY {
  Socket_connect(socket, host, port);
}
EXCEPT(Socket_Failed) {
  if (errno == ETIMEDOUT) {
    /* Connection timeout - retry with backoff or fail */
  } else {
    /* Other connection error */
  }
}
END_TRY;
```

### 4. Use Deadline-Based Timeouts for Multi-Phase Operations

```c
int64_t deadline = SocketTimeout_deadline_ms(30000); /* 30s total */

/* DNS phase */
int dns_timeout = SocketTimeout_poll_timeout(5000, deadline);
/* ... perform DNS ... */

/* Connect phase */
int connect_timeout = SocketTimeout_remaining_ms(deadline);
if (connect_timeout <= 0) {
  /* Already exceeded deadline */
  return -1;
}
/* ... perform connect ... */

/* TLS phase */
int tls_timeout = SocketTimeout_remaining_ms(deadline);
SocketTLS_handshake_loop(socket, tls_timeout);
```

### 5. Consider Network Conditions

Adjust timeouts based on expected network conditions:

- **LAN**: Shorter timeouts (1-5 seconds)
- **WAN/Internet**: Moderate timeouts (5-30 seconds)
- **Mobile/Unreliable**: Longer timeouts with retries (30-60 seconds)
- **Satellite/High Latency**: Very long timeouts (60-120 seconds)

## Troubleshooting

### Timeout Not Being Enforced

1. Verify timeout is set before the operation
2. Check for 0 values (which mean "infinite" for basic timeouts)
3. Ensure the correct timeout field is used for the operation

### DNS Resolution Blocking

DNS resolution via `getaddrinfo()` can block indefinitely on some systems even with timeouts set. Mitigations:

1. Use `SocketDNS` async resolver for guaranteed timeout control
2. Use IP addresses directly to bypass DNS
3. Set system-level DNS timeout (`/etc/resolv.conf`)

### TLS Handshake Hanging

Use `SocketTLS_handshake_auto()` instead of `SocketTLS_handshake()` for automatic timeout enforcement:

```c
/* May hang if peer is unresponsive */
SocketTLS_handshake(socket);

/* Respects socket's operation_timeout_ms */
SocketTLS_handshake_auto(socket);
```

## Reference

### Compile-Time Defaults

```c
/* From SocketConfig.h */
#define SOCKET_DEFAULT_CONNECT_TIMEOUT_MS 30000
#define SOCKET_DEFAULT_DNS_TIMEOUT_MS 5000
#define SOCKET_DEFAULT_OPERATION_TIMEOUT_MS 0 /* infinite */
#define SOCKET_DEFAULT_TLS_TIMEOUT_MS 30000
#define SOCKET_DEFAULT_REQUEST_TIMEOUT_MS 60000

/* From SocketHappyEyeballs.h */
#define SOCKET_HE_DEFAULT_FIRST_ATTEMPT_DELAY_MS 250
#define SOCKET_HE_DEFAULT_ATTEMPT_TIMEOUT_MS 5000
#define SOCKET_HE_DEFAULT_TOTAL_TIMEOUT_MS 30000
#define SOCKET_HE_DEFAULT_DNS_TIMEOUT_MS 5000

/* From SocketTLSConfig.h */
#define SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS 30000

/* From SocketProxy.h */
#define SOCKET_PROXY_DEFAULT_CONNECT_TIMEOUT_MS 10000
#define SOCKET_PROXY_DEFAULT_HANDSHAKE_TIMEOUT_MS 30000
```

### Related APIs

- `Socket_timeouts_set()` / `Socket_timeouts_get()`
- `Socket_timeouts_set_extended()` / `Socket_timeouts_get_extended()`
- `Socket_timeouts_setdefaults()` / `Socket_timeouts_getdefaults()`
- `SocketTLS_handshake_loop()` / `SocketTLS_handshake_auto()`
- `SocketHappyEyeballs_config_defaults()` / `SocketHappyEyeballs_next_timeout_ms()`
- `SocketProxy_Conn_next_timeout_ms()`
- `SocketTimeout_*()` helper functions
