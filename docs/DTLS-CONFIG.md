# DTLS Configuration Guide {#dtls_config_guide}
**Brief**: DTLS 1.2+ configuration for secure UDP with cookie protection | **Tags**: `dtls`, `udp`, `configuration`, `security`, `cookies`

Detailed configuration guide for DTLS (Datagram TLS) in the Socket Library.

**Module Group**: Security | **Related Modules**: SocketDTLS, SocketDTLSContext, SocketDTLSConfig

---

## Overview

DTLS (Datagram Transport Layer Security) provides TLS-like security over unreliable datagram
transports like UDP. The Socket Library provides DTLS 1.2+ with cookie-based DoS protection,
modern cipher suites, and full async I/O support.

### DTLS vs TLS

| Feature | DTLS | TLS |
|---------|------|-----|
| Transport | UDP (unreliable) | TCP (reliable) |
| Message boundaries | Preserved | Stream-based |
| Order guarantee | None | Guaranteed |
| Delivery guarantee | None | Guaranteed |
| Handshake RTTs | 2 RTT (+ cookie) | 1-2 RTT |
| Use cases | VoIP, IoT, Gaming | HTTPS, API, DB |

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [DTLS Protocol Versions](#dtls-protocol-versions)
3. [Cookie Protection](#cookie-protection)
4. [Client Configuration](#client-configuration)
5. [Server Configuration](#server-configuration)
6. [MTU Configuration](#mtu-configuration)
7. [Handshake Management](#handshake-management)
8. [Session Resumption](#session-resumption)
9. [Certificate Configuration](#certificate-configuration)
10. [ALPN Protocol Negotiation](#alpn-protocol-negotiation)
11. [Event Loop Integration](#event-loop-integration)
12. [Troubleshooting](#troubleshooting)
13. [Security Checklist](#security-checklist)

---

## Quick Start

### DTLS Client

```c
#include "tls/SocketDTLS.h"
#include "tls/SocketDTLSContext.h"

// Create client context
SocketDTLSContext_T ctx = SocketDTLSContext_new_client("ca-bundle.pem");

// Create UDP socket and connect
SocketDgram_T sock = SocketDgram_new(AF_INET, 0);
SocketDgram_connect(sock, "example.com", 4433);

// Enable DTLS
SocketDTLS_enable(sock, ctx);
SocketDTLS_set_hostname(sock, "example.com");

// Complete handshake
DTLSHandshakeState state = SocketDTLS_handshake_loop(sock, 10000);
if (state == DTLS_HANDSHAKE_COMPLETE) {
    // Secure datagram I/O
    SocketDTLS_send(sock, "Hello DTLS", 10);
    
    char buf[1400];
    ssize_t n = SocketDTLS_recv(sock, buf, sizeof(buf));
}

// Cleanup
SocketDTLS_shutdown(sock);
SocketDgram_free(&sock);
```

### DTLS Server

```c
#include "tls/SocketDTLS.h"
#include "tls/SocketDTLSContext.h"

// Create server context with DoS protection
SocketDTLSContext_T ctx = SocketDTLSContext_new_server(
    "server.crt", "server.key", NULL);
SocketDTLSContext_enable_cookie_exchange(ctx);

// Create UDP socket and bind
SocketDgram_T sock = SocketDgram_new(AF_INET, 0);
SocketDgram_bind(sock, "0.0.0.0", 4433);

// Enable DTLS
SocketDTLS_enable(sock, ctx);

// Listen for ClientHello
DTLSHandshakeState state = SocketDTLS_listen(sock);

// Complete handshake (includes cookie exchange)
state = SocketDTLS_handshake_loop(sock, 30000);
if (state == DTLS_HANDSHAKE_COMPLETE) {
    // Handle secure datagrams
    char buf[1400];
    ssize_t n = SocketDTLS_recv(sock, buf, sizeof(buf));
    SocketDTLS_send(sock, "Response", 8);
}

// Cleanup
SocketDTLS_shutdown(sock);
SocketDgram_free(&sock);
```

---

## DTLS Protocol Versions

### Default: DTLS 1.2 Minimum

```c
// SocketDTLSConfig.h defaults
// DTLS 1.2 minimum is enforced for security
```

### Protocol Configuration

```c
// Allow only DTLS 1.2 (recommended)
SocketDTLSContext_set_min_protocol(ctx, DTLS1_2_VERSION);
SocketDTLSContext_set_max_protocol(ctx, DTLS1_2_VERSION);

// Allow DTLS 1.3 when available (future)
// SocketDTLSContext_set_max_protocol(ctx, DTLS1_3_VERSION);
```

### DTLS Version Security

| Version | Status | Notes |
|---------|--------|-------|
| DTLS 1.0 | Deprecated | Based on TLS 1.1, weak ciphers |
| DTLS 1.2 | **Recommended** | Based on TLS 1.2, AEAD ciphers |
| DTLS 1.3 | Future | RFC 9147, not widely deployed |

---

## Cookie Protection

Cookie exchange (RFC 6347 §4.2.1) prevents UDP amplification attacks.

### How Cookies Work

```
1. Client → Server: ClientHello (initial)
2. Server → Client: HelloVerifyRequest + Cookie
3. Client → Server: ClientHello + Cookie (proves reachability)
4. Server: Allocate state, continue handshake
```

### Enable Cookie Exchange

```c
// Create server context
SocketDTLSContext_T ctx = SocketDTLSContext_new_server(
    "server.crt", "server.key", NULL);

// Enable cookie protection (REQUIRED for public servers)
SocketDTLSContext_enable_cookie_exchange(ctx);
```

### Cookie Secret Management

```c
// Auto-generated secret (default)
SocketDTLSContext_enable_cookie_exchange(ctx);

// Or set shared secret for load-balanced clusters
unsigned char secret[32];  // SOCKET_DTLS_COOKIE_SECRET_LEN
RAND_bytes(secret, sizeof(secret));
SocketDTLSContext_set_cookie_secret(ctx, secret, sizeof(secret));
OPENSSL_cleanse(secret, sizeof(secret));  // Clear from stack

// Rotate secret periodically (e.g., hourly)
SocketDTLSContext_rotate_cookie_secret(ctx);
```

### Cookie Configuration Constants

```c
// From SocketDTLSConfig.h
#define SOCKET_DTLS_COOKIE_LEN            32    // Cookie size (bytes)
#define SOCKET_DTLS_COOKIE_SECRET_LEN     32    // Secret key size
#define SOCKET_DTLS_COOKIE_LIFETIME_SEC   60    // Cookie validity period
```

### Cookie Best Practices

1. **Always enable** on internet-facing servers
2. **Rotate secrets** every 1-24 hours
3. **Sync secrets** across load-balanced nodes
4. **Monitor** HelloVerifyRequest rate for attack detection

---

## Client Configuration

### Basic Client

```c
// System CAs for server verification
SocketDTLSContext_T ctx = SocketDTLSContext_new_client(NULL);

// Or explicit CA bundle
SocketDTLSContext_T ctx = SocketDTLSContext_new_client("ca-bundle.pem");
```

### Full-Featured Client

```c
SocketDTLSContext_T ctx = SocketDTLSContext_new_client("ca-bundle.pem");

// Verify server certificate
SocketDTLSContext_set_verify_mode(ctx, TLS_VERIFY_PEER);

// Set ALPN for protocol negotiation (e.g., CoAP)
const char *protos[] = {"coap"};
SocketDTLSContext_set_alpn_protos(ctx, protos, 1);

// Enable session resumption
SocketDTLSContext_enable_session_cache(ctx, 100, 3600);

// Configure MTU for path
SocketDTLSContext_set_mtu(ctx, 1400);

// Create socket and connect
SocketDgram_T sock = SocketDgram_new(AF_INET, 0);
SocketDgram_connect(sock, "coap.example.com", 5684);

// Enable DTLS with hostname verification
SocketDTLS_enable(sock, ctx);
SocketDTLS_set_hostname(sock, "coap.example.com");

// Perform handshake
TRY {
    DTLSHandshakeState state = SocketDTLS_handshake_loop(sock, 10000);
    if (state != DTLS_HANDSHAKE_COMPLETE) {
        RAISE(SocketDTLS_HandshakeFailed);
    }
    
    // Verify connection details
    printf("Version: %s\n", SocketDTLS_get_version(sock));
    printf("Cipher: %s\n", SocketDTLS_get_cipher(sock));
    printf("ALPN: %s\n", SocketDTLS_get_alpn_selected(sock));
    
} EXCEPT(SocketDTLS_HandshakeFailed) {
    log_error("DTLS handshake failed");
} EXCEPT(SocketDTLS_VerifyFailed) {
    log_error("Certificate verification failed");
} END_TRY;
```

---

## Server Configuration

### Minimal Server

```c
SocketDTLSContext_T ctx = SocketDTLSContext_new_server(
    "server.crt", "server.key", NULL);
SocketDTLSContext_enable_cookie_exchange(ctx);
```

### Production Server

```c
SocketDTLSContext_T ctx = SocketDTLSContext_new_server(
    "server.crt", "server.key", "client-ca.pem");

// DoS protection
SocketDTLSContext_enable_cookie_exchange(ctx);

// Set shared secret for cluster
unsigned char secret[32];
load_cluster_secret(secret, sizeof(secret));
SocketDTLSContext_set_cookie_secret(ctx, secret, sizeof(secret));
OPENSSL_cleanse(secret, sizeof(secret));

// Session resumption
SocketDTLSContext_enable_session_cache(ctx, 10000, 3600);

// Protocol negotiation
const char *protos[] = {"coap", "mqtt"};
SocketDTLSContext_set_alpn_protos(ctx, protos, 2);

// Timeouts
SocketDTLSContext_set_timeout(ctx, 1000, 60000);  // 1s initial, 60s max

// MTU
SocketDTLSContext_set_mtu(ctx, 1400);
```

### Require Client Certificates

```c
// mTLS for DTLS
SocketDTLSContext_T ctx = SocketDTLSContext_new_server(
    "server.crt", "server.key", "client-ca.pem");
SocketDTLSContext_set_verify_mode(ctx, 
    TLS_VERIFY_PEER | TLS_VERIFY_FAIL_IF_NO_PEER_CERT);
```

---

## MTU Configuration

### Importance of MTU

Incorrect MTU causes IP fragmentation or packet drops:

| MTU | Network | Notes |
|-----|---------|-------|
| 576 | Minimum IPv4 | Safe for any path |
| 1280 | Minimum IPv6 | Required for IPv6 |
| 1400 | Conservative | Accounts for overhead |
| 1472 | Ethernet (IPv4) | 1500 - IP(20) - UDP(8) |
| 1452 | Ethernet (IPv6) | 1500 - IPv6(40) - UDP(8) |
| 9000 | Jumbo frames | Data center networks |

### Configure MTU

```c
// Context-level (default for all sockets)
SocketDTLSContext_set_mtu(ctx, 1400);

// Per-socket override
SocketDTLS_set_mtu(sock, 576);  // Conservative for unknown path

// Query current MTU
size_t mtu = SocketDTLS_get_mtu(sock);
```

### Path MTU Discovery

```c
// Probe actual path MTU (application-level)
size_t mtu = 1472;
while (mtu > 576) {
    if (test_mtu_works(sock, mtu)) {
        break;
    }
    mtu -= 100;
}
SocketDTLS_set_mtu(sock, mtu - DTLS_OVERHEAD);
```

### MTU Configuration Constants

```c
// From SocketDTLSConfig.h
#define SOCKET_DTLS_MIN_MTU     576   // IPv4 minimum
#define SOCKET_DTLS_MAX_MTU     9000  // Jumbo frames
#define SOCKET_DTLS_DEFAULT_MTU 1400  // Conservative default
```

---

## Handshake Management

### Non-Blocking Handshake

```c
SocketDgram_setnonblocking(sock);

DTLSHandshakeState state = DTLS_HANDSHAKE_NOT_STARTED;
while (state != DTLS_HANDSHAKE_COMPLETE && 
       state != DTLS_HANDSHAKE_ERROR) {
    
    state = SocketDTLS_handshake(sock);
    
    switch (state) {
        case DTLS_HANDSHAKE_WANT_READ:
            poll_for_read(sock, timeout);
            break;
        case DTLS_HANDSHAKE_WANT_WRITE:
            poll_for_write(sock, timeout);
            break;
        case DTLS_HANDSHAKE_COOKIE_EXCHANGE:
            // Server: Cookie sent, wait for client echo
            poll_for_read(sock, cookie_timeout);
            break;
        case DTLS_HANDSHAKE_IN_PROGRESS:
            // Continue
            break;
        default:
            break;
    }
}
```

### Blocking Handshake with Timeout

```c
// Simple blocking handshake
DTLSHandshakeState state = SocketDTLS_handshake_loop(sock, 10000);

if (state == DTLS_HANDSHAKE_COMPLETE) {
    // Success
} else {
    // Check what went wrong
    if (state == DTLS_HANDSHAKE_ERROR) {
        long verify = SocketDTLS_get_verify_result(sock);
        log_error("Handshake failed, verify: %ld", verify);
    }
}
```

### Server: Listen for ClientHello

```c
// Wait for initial ClientHello
DTLSHandshakeState state = SocketDTLS_listen(sock);

switch (state) {
    case DTLS_HANDSHAKE_WANT_READ:
        // No ClientHello yet, poll again
        break;
    case DTLS_HANDSHAKE_COOKIE_EXCHANGE:
        // Cookie sent, wait for client response
        break;
    case DTLS_HANDSHAKE_IN_PROGRESS:
        // ClientHello received, continue handshake
        state = SocketDTLS_handshake_loop(sock, 30000);
        break;
}
```

### Handshake State Machine

```
                  ┌─────────────────────┐
                  │  NOT_STARTED        │
                  └──────────┬──────────┘
                             │ handshake()
                  ┌──────────▼──────────┐
                  │  IN_PROGRESS        │◄────────┐
                  └──────────┬──────────┘         │
                             │                     │
              ┌──────────────┼──────────────┐     │
              ▼              ▼              ▼     │
        ┌──────────┐  ┌──────────┐  ┌──────────┐ │
        │WANT_READ │  │WANT_WRITE│  │ COOKIE   │ │
        └────┬─────┘  └────┬─────┘  │ EXCHANGE │ │
             │              │        └────┬─────┘ │
             │  poll()      │  poll()     │ poll()│
             └──────────────┴─────────────┴───────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                              ▼
        ┌──────────┐                  ┌──────────┐
        │ COMPLETE │                  │  ERROR   │
        └──────────┘                  └──────────┘
```

---

## Session Resumption

### Enable Session Cache

```c
// Enable on context
SocketDTLSContext_enable_session_cache(ctx, 
    1000,    // Max sessions
    3600);   // Timeout (seconds)

// Check statistics
size_t hits, misses, stores;
SocketDTLSContext_get_cache_stats(ctx, &hits, &misses, &stores);
printf("Session cache: hits=%zu, misses=%zu, stores=%zu\n",
    hits, misses, stores);
```

### Session Resumption Benefits

- **1-RTT handshake** instead of 2-RTT
- **Reduced latency** for reconnections
- **Less server load** (no full key exchange)

### Verify Resumption

```c
DTLSHandshakeState state = SocketDTLS_handshake_loop(sock, 10000);
if (state == DTLS_HANDSHAKE_COMPLETE) {
    if (SocketDTLS_is_session_reused(sock)) {
        log_info("Session resumed (fast handshake)");
    } else {
        log_info("Full handshake performed");
    }
}
```

---

## Certificate Configuration

### Load Certificates

```c
// During context creation
SocketDTLSContext_T ctx = SocketDTLSContext_new_server(
    "server.crt", "server.key", "ca.pem");

// Or load separately
SocketDTLSContext_load_certificate(ctx, "server.crt", "server.key");
SocketDTLSContext_load_ca(ctx, "ca.pem");
```

### Cipher Suites

```c
// Use modern ciphers (default)
SocketDTLSContext_set_cipher_list(ctx, 
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305");
```

### Verification Mode

```c
// Client: Verify server
SocketDTLSContext_set_verify_mode(ctx, TLS_VERIFY_PEER);

// Server: Require client cert
SocketDTLSContext_set_verify_mode(ctx, 
    TLS_VERIFY_PEER | TLS_VERIFY_FAIL_IF_NO_PEER_CERT);
```

---

## ALPN Protocol Negotiation

### Configure ALPN

```c
// Server: Advertise supported protocols
const char *server_protos[] = {"coap", "mqtt", "custom"};
SocketDTLSContext_set_alpn_protos(ctx, server_protos, 3);

// Client: Request preferred protocols
const char *client_protos[] = {"coap"};
SocketDTLSContext_set_alpn_protos(ctx, client_protos, 1);
```

### Check Negotiated Protocol

```c
// After handshake
const char *selected = SocketDTLS_get_alpn_selected(sock);
if (selected) {
    printf("Negotiated protocol: %s\n", selected);
    if (strcmp(selected, "coap") == 0) {
        handle_coap(sock);
    } else if (strcmp(selected, "mqtt") == 0) {
        handle_mqtt(sock);
    }
} else {
    // No ALPN negotiated
    handle_default(sock);
}
```

---

## Event Loop Integration

### With SocketPoll

```c
#include "poll/SocketPoll.h"

SocketPoll_T poll = SocketPoll_new(100);

// Add DTLS socket to poll
int fd = SocketDgram_fd(sock);
SocketPoll_add(poll, fd, POLL_READ | POLL_WRITE, sock);

// Event loop
while (running) {
    SocketEvent_T events[10];
    int nfds = SocketPoll_wait(poll, events, 100);  // 100ms timeout
    
    for (int i = 0; i < nfds; i++) {
        SocketDgram_T sock = events[i].data;
        
        if (!SocketDTLS_is_handshake_done(sock)) {
            // Continue handshake
            DTLSHandshakeState state = SocketDTLS_handshake(sock);
            update_poll_events(poll, sock, state);
        } else {
            // Handle application data
            if (events[i].events & POLL_READ) {
                handle_dtls_read(sock);
            }
            if (events[i].events & POLL_WRITE) {
                handle_dtls_write(sock);
            }
        }
    }
    
    // Check for CRL refresh if configured
    // SocketTLSContext_crl_check_refresh(ctx);
}
```

### Update Poll Events

```c
void update_poll_events(SocketPoll_T poll, SocketDgram_T sock, 
                        DTLSHandshakeState state) {
    unsigned events = POLL_ERROR;
    
    switch (state) {
        case DTLS_HANDSHAKE_WANT_READ:
            events |= POLL_READ;
            break;
        case DTLS_HANDSHAKE_WANT_WRITE:
            events |= POLL_WRITE;
            break;
        case DTLS_HANDSHAKE_COOKIE_EXCHANGE:
            events |= POLL_READ;  // Wait for cookie echo
            break;
        case DTLS_HANDSHAKE_COMPLETE:
            events |= POLL_READ | POLL_WRITE;
            break;
        case DTLS_HANDSHAKE_ERROR:
            // Remove from poll, cleanup
            SocketPoll_del(poll, SocketDgram_fd(sock));
            return;
        default:
            events |= POLL_READ | POLL_WRITE;
            break;
    }
    
    SocketPoll_mod(poll, SocketDgram_fd(sock), events, sock);
}
```

---

## Troubleshooting

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `SocketDTLS_HandshakeFailed` | Protocol mismatch | Verify DTLS 1.2 support |
| `SocketDTLS_VerifyFailed` | Certificate invalid | Check CA bundle, hostname |
| `SocketDTLS_CookieFailed` | Cookie generation error | Check secret configuration |
| `SocketDTLS_TimeoutExpired` | Handshake too slow | Increase timeout or check network |
| Packet drops | MTU too large | Reduce MTU setting |
| Slow handshake | Retransmissions | Check network, increase timeout |

### Debug Information

```c
// After handshake or error
printf("DTLS enabled: %d\n", SocketDTLS_is_enabled(sock));
printf("Handshake done: %d\n", SocketDTLS_is_handshake_done(sock));
printf("Last state: %d\n", SocketDTLS_get_last_state(sock));
printf("Version: %s\n", SocketDTLS_get_version(sock));
printf("Cipher: %s\n", SocketDTLS_get_cipher(sock));
printf("Verify result: %ld\n", SocketDTLS_get_verify_result(sock));
printf("Session reused: %d\n", SocketDTLS_is_session_reused(sock));
printf("MTU: %zu\n", SocketDTLS_get_mtu(sock));
```

### Testing with OpenSSL

```bash
# DTLS server
openssl s_server -dtls -port 4433 -cert server.crt -key server.key

# DTLS client
openssl s_client -dtls -connect localhost:4433

# Test specific version
openssl s_client -dtls1_2 -connect localhost:4433

# Debug mode
openssl s_client -dtls -connect localhost:4433 -debug -msg
```

---

## Security Checklist

### Server

- [ ] Cookie exchange enabled (DoS protection)
- [ ] Cookie secret rotated regularly
- [ ] DTLS 1.2 minimum (no 1.0)
- [ ] Valid certificate from trusted CA
- [ ] Strong private key (RSA 2048+ or ECDSA P-256+)
- [ ] Modern cipher suites (AEAD + PFS)
- [ ] MTU configured appropriately
- [ ] Timeouts set to prevent resource exhaustion

### Client

- [ ] Certificate verification enabled
- [ ] Hostname verification (SNI)
- [ ] CA bundle or trust anchors configured
- [ ] Session resumption for performance
- [ ] Appropriate MTU for network path

### Cluster

- [ ] Cookie secrets synchronized
- [ ] Session cache shared or disabled
- [ ] Load balancer UDP session affinity
- [ ] Monitoring for handshake failures

### Monitoring

- [ ] Cookie verification rate (attack indicator)
- [ ] Handshake success/failure rate
- [ ] Session resumption rate
- [ ] Certificate expiration alerts

---

## Configuration Reference

### SocketDTLSConfig.h Constants

| Constant | Default | Description |
|----------|---------|-------------|
| `SOCKET_DTLS_MIN_MTU` | 576 | Minimum MTU (IPv4 minimum) |
| `SOCKET_DTLS_MAX_MTU` | 9000 | Maximum MTU (jumbo frames) |
| `SOCKET_DTLS_DEFAULT_MTU` | 1400 | Conservative default MTU |
| `SOCKET_DTLS_COOKIE_LEN` | 32 | Cookie length (HMAC-SHA256) |
| `SOCKET_DTLS_COOKIE_SECRET_LEN` | 32 | Cookie secret length |
| `SOCKET_DTLS_COOKIE_LIFETIME_SEC` | 60 | Cookie validity period |
| `SOCKET_DTLS_INITIAL_TIMEOUT_MS` | 1000 | Initial retransmission timeout |
| `SOCKET_DTLS_MAX_TIMEOUT_MS` | 60000 | Maximum retransmission timeout |

---

## See Also

- @ref SECURITY.md - General security guide
- @ref TLS-CONFIG.md - TLS configuration
- @ref SocketDTLSConfig.h - DTLS configuration constants
- @ref SocketDTLSContext.h - DTLS context management
- @ref SocketDTLS.h - DTLS socket operations
- @ref ASYNC_IO.md - Async I/O integration patterns
