---
name: tls
description: TLS/DTLS implementation patterns for this socket library. Use when working on src/tls/, include/tls/, TLS handshakes, certificates, ALPN, session resumption, or DTLS.
---

You are an expert C developer specializing in TLS 1.3 and DTLS implementation.

## TLS Architecture in This Codebase

```
SocketTLSContext_T (configuration, reusable)
    ↓
Socket_T + SocketTLS_enable() (per-connection TLS state)
    ↓
SocketTLS_handshake() (state machine)
    ↓
SocketTLS_send/recv() (encrypted I/O)
```

## Critical: TLS Handshake Exception Safety

TLS handshakes are the most fragile code path for exception handling. Follow these patterns exactly:

### Pattern 1: Non-Blocking Handshake with Poll Integration

```c
TLSHandshakeState state;
do {
    state = SocketTLS_handshake(sock);
    if (state == TLS_HANDSHAKE_WANT_READ) {
        SocketPoll_mod(poll, sock, POLL_READ);
        SocketPoll_wait(poll, events, timeout);
    } else if (state == TLS_HANDSHAKE_WANT_WRITE) {
        SocketPoll_mod(poll, sock, POLL_WRITE);
        SocketPoll_wait(poll, events, timeout);
    }
} while (state != TLS_HANDSHAKE_COMPLETE && state != TLS_HANDSHAKE_ERROR);
```

### Pattern 2: Blocking Handshake (Simple Cases)

```c
volatile Socket_T sock = NULL;
volatile SocketTLSContext_T ctx = NULL;

TRY {
    sock = Socket_connect_tcp(host, port, timeout_ms);
    ctx = SocketTLSContext_new_client(ca_file);

    SocketTLS_enable(sock, ctx);
    SocketTLS_set_hostname(sock, host);  // SNI
    SocketTLS_handshake_auto(sock);      // Blocks until complete
}
EXCEPT(SocketTLS_HandshakeFailed) {
    // Handle handshake failure
}
EXCEPT(SocketTLS_VerifyFailed) {
    // Handle certificate verification failure
}
FINALLY {
    // Cleanup in reverse order
    if (sock) Socket_free((Socket_T *)&sock);
    if (ctx) SocketTLSContext_free((SocketTLSContext_T *)&ctx);
}
END_TRY;
```

### Pattern 3: Avoid Nested TRY in Handshake Loops

**WRONG** - Causes exception stack corruption:
```c
while (!done) {
    TRY {
        TRY {
            SocketTLS_handshake(sock);
        }
        EXCEPT(...) { }
        END_TRY;
    }
    END_TRY;
}
```

**RIGHT** - Use error codes instead of exceptions in inner loop:
```c
static int do_handshake_poll_safe(Socket_T sock) {
    // Return error code, don't raise exception
    TLSHandshakeState state = SocketTLS_handshake(sock);
    if (state == TLS_HANDSHAKE_ERROR) return -1;
    if (state == TLS_HANDSHAKE_COMPLETE) return 0;
    return 1;  // Continue polling
}

TRY {
    int result;
    while ((result = do_handshake_poll_safe(sock)) > 0) {
        // Poll and retry
    }
    if (result < 0) RAISE(SocketTLS_HandshakeFailed);
}
END_TRY;
```

## TLS Context Configuration

```c
// Client context
SocketTLSContext_T ctx = SocketTLSContext_new_client(ca_file);
SocketTLSContext_set_min_protocol(ctx, TLS_1_3);
SocketTLSContext_set_verify_mode(ctx, SSL_VERIFY_PEER);

// Server context
SocketTLSContext_T ctx = SocketTLSContext_new_server(cert_file, key_file, ca_file);
SocketTLSContext_set_session_cache(ctx, 1000);  // Session resumption

// ALPN for HTTP/2
const char *alpn[] = {"h2", "http/1.1", NULL};
SocketTLSContext_set_alpn(ctx, alpn);

// Certificate pinning
SocketTLSContext_enable_cert_pinning(ctx, pin_sha256, pin_count);
```

## DTLS (Datagram TLS) Patterns

DTLS has additional complexity due to UDP:

```c
// Cookie exchange for DoS protection
SocketDTLSContext_T ctx = SocketDTLSContext_new_server(cert, key, ca);
SocketDTLSContext_enable_cookie_exchange(ctx);

// MTU handling
SocketDTLS_set_mtu(sock, 1400);  // Must account for DTLS overhead

// Retransmission is automatic but configurable
SocketDTLS_set_retransmit_timeout(sock, 1000, 60000);  // min/max ms
```

## Security Checklist

1. [ ] TLS version appropriate for use case (default: TLS 1.2 minimum for compatibility, TLS 1.3 max for security)
2. [ ] Certificate verification enabled (`SSL_VERIFY_PEER`)
3. [ ] Hostname verification via `SocketTLS_set_hostname()`
4. [ ] ALPN configured for protocol negotiation
5. [ ] Session resumption for performance
6. [ ] Graceful shutdown with `SocketTLS_shutdown()` or `SocketTLS_disable()`

## TLS Version Defaults

The library defaults to:
- **Minimum**: TLS 1.2 (`SOCKET_TLS_MIN_VERSION`) - for broad compatibility
- **Maximum**: TLS 1.3 (`SOCKET_TLS_MAX_VERSION`) - for best security when available

For high-security environments requiring TLS 1.3 only:
```c
SocketTLSConfig_T config;
SocketTLS_config_defaults(&config);
config.min_version = TLS1_3_VERSION;  // Require TLS 1.3
SocketTLSContext_T ctx = SocketTLSContext_new(&config);
```

Note: Some servers (e.g., httpbin.org) only support TLS 1.2, so TLS 1.3-only policy may cause connection failures.

## Files Reference

| File | Purpose |
|------|---------|
| `include/tls/SocketTLS.h` | Main TLS API |
| `include/tls/SocketTLSContext.h` | Context configuration |
| `include/tls/SocketDTLS.h` | DTLS for UDP |
| `src/tls/SocketTLS.c` | TLS implementation |
| `src/tls/SocketTLS-handshake.c` | Handshake state machine |
| `src/test/test_tls_*.c` | Test patterns to follow |
