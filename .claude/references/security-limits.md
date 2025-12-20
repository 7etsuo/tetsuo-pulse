# Security Limits Reference

This document contains all security constants and limits from `SocketSecurity.h` and other security-critical headers.

## Centralized Security Configuration (SocketSecurity.h)

All security limits are documented in `SocketSecurity.h` with their source headers:

| Category | Limit | Default | Source Header |
|----------|-------|---------|---------------|
| Memory | `SOCKET_SECURITY_MAX_ALLOCATION` | 256MB | SocketSecurity.h |
| Memory | `SOCKET_MAX_BUFFER_SIZE` | 1MB | SocketConfig.h |
| Memory | `ARENA_MAX_ALLOC_SIZE` | 100MB | SocketConfig.h |
| HTTP | `SOCKETHTTP_MAX_URI_LEN` | 8KB | SocketHTTP.h |
| HTTP | `SOCKETHTTP_MAX_HEADER_SIZE` | 64KB | SocketHTTP.h |
| HTTP | `SOCKETHTTP_MAX_HEADERS` | 100 | SocketHTTP.h |
| HTTP/1.1 | `SOCKETHTTP1_MAX_REQUEST_LINE` | 8KB | SocketHTTP1.h |
| HTTP/1.1 | `SOCKETHTTP1_MAX_CHUNK_SIZE` | 16MB | SocketHTTP1.h |
| HTTP/2 | `SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS` | 100 | SocketHTTP2.h |
| HTTP/2 | `SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE` | 16KB | SocketHTTP2.h |
| HPACK | `SOCKETHPACK_MAX_TABLE_SIZE` | 64KB | SocketHPACK.h |
| WebSocket | `SOCKETWS_MAX_FRAME_SIZE` | 16MB | SocketWS-private.h |
| WebSocket | `SOCKETWS_MAX_MESSAGE_SIZE` | 64MB | SocketWS-private.h |
| TLS | `SOCKET_TLS_MAX_CERT_CHAIN_DEPTH` | 10 | SocketTLSConfig.h |
| Rate Limit | `SOCKET_RATELIMIT_DEFAULT_CONN_PER_SEC` | 100/s | SocketConfig.h |
| Rate Limit | `SOCKET_RATELIMIT_DEFAULT_MAX_PER_IP` | 10 | SocketConfig.h |
| Connections | `SOCKET_MAX_CONNECTIONS` | 10000 | SocketConfig.h |
| Timeout | `SOCKET_DEFAULT_CONNECT_TIMEOUT_MS` | 30s | SocketConfig.h |
| Timeout | `SOCKET_DEFAULT_DNS_TIMEOUT_MS` | 5s | SocketConfig.h |
| Timeout | `SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS` | 30s | SocketTLSConfig.h |
| TLS | `SOCKET_TLS_BUFFER_SIZE` | 16KB | SocketTLSConfig.h |
| TLS | `SOCKET_TLS_MAX_SNI_LEN` | 255 | SocketTLSConfig.h |
| TLS | `SOCKET_TLS_MAX_ALPN_LEN` | 255 | SocketTLSConfig.h |
| TLS | `SOCKET_TLS_SESSION_CACHE_SIZE` | 1000 | SocketTLSConfig.h |
| UDP | `UDP_MAX_PAYLOAD` | 65507 bytes | SocketDgram.h |
| UDP | `SAFE_UDP_SIZE` | 1472 bytes | SocketDgram.h |
| Unix | `SOCKET_MAX_FDS_PER_MSG` | 253 | SocketConfig.h |

## Runtime Limit Query

```c
SocketSecurityLimits limits;
SocketSecurity_get_limits(&limits);
/* Now access: limits.max_allocation, limits.http_max_uri_length, etc. */
```

## Compile-Time Override

All limits can be overridden at compile time:

```c
#define SOCKET_SECURITY_MAX_ALLOCATION (128 * 1024 * 1024)  /* 128MB */
#include "core/SocketSecurity.h"
```

## Security Verification Functions

From `SocketSecurity.h`:

- `SocketSecurity_get_limits(&limits)` - Query all configured security limits at runtime
- `SocketSecurity_get_max_allocation()` - Get maximum safe allocation size
- `SocketSecurity_get_http_limits()` - Query HTTP-specific limits
- `SocketSecurity_get_ws_limits()` - Query WebSocket-specific limits
- `SocketSecurity_check_size(size)` - Validate allocation size against maximum
- `SocketSecurity_check_multiply(a, b, &result)` - Overflow-safe multiplication
- `SocketSecurity_check_add(a, b, &result)` - Overflow-safe addition
- `SocketSecurity_safe_multiply(a, b)` - Inline overflow-safe multiplication
- `SocketSecurity_safe_add(a, b)` - Inline overflow-safe addition
- `SocketSecurity_has_tls()` - Check if TLS support is compiled in
- `SocketSecurity_has_compression()` - Check if HTTP compression is available

## Security Validation Macros

From `SocketSecurity.h`:

- `SOCKET_SECURITY_VALID_SIZE(s)` - Validate size within safe limits
- `SOCKET_SECURITY_CHECK_OVERFLOW_MUL(a, b)` - Check multiplication overflow
- `SOCKET_SECURITY_CHECK_OVERFLOW_ADD(a, b)` - Check addition overflow

## TLS Security Configuration

From `SocketTLSConfig.h`:

### Protocol Versions:
- `SOCKET_TLS_MIN_VERSION` - TLS 1.3 only (TLS1_3_VERSION)
- `SOCKET_TLS_MAX_VERSION` - TLS 1.3 only (TLS1_3_VERSION)

### Cipher Suites (TLS 1.3):
- `SOCKET_TLS13_CIPHERSUITES` - Modern AEAD ciphers only:
  - TLS_AES_256_GCM_SHA384
  - TLS_CHACHA20_POLY1305_SHA256
  - TLS_AES_128_GCM_SHA256

### Buffer Sizes:
- `SOCKET_TLS_BUFFER_SIZE` - 16KB (matches TLS record size)
- `SOCKET_TLS_MAX_CERT_CHAIN_DEPTH` - 10 certificates

### Timeouts:
- `SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS` - 30 seconds

### Session Management:
- `SOCKET_TLS_SESSION_CACHE_SIZE` - 1000 sessions
- `SOCKET_TLS_SESSION_TIMEOUT_SEC` - 300 seconds (5 minutes)

## HTTP/1.1 Security Limits

From `SocketHTTP1.h`:

### Request/Response Limits:
- `SOCKETHTTP1_MAX_REQUEST_LINE` - 8KB
- `SOCKETHTTP1_MAX_HEADER_SIZE` - 64KB (total headers)
- `SOCKETHTTP1_MAX_CHUNK_SIZE` - 16MB
- `SOCKETHTTP1_MAX_TRAILER_SIZE` - 8KB
- `SOCKETHTTP1_MAX_CHUNK_EXT` - 1KB (chunk extensions)

### Configuration Structure:
```c
typedef struct {
    size_t max_request_line;    /* Default: 8KB */
    size_t max_header_size;      /* Default: 64KB */
    size_t max_chunk_size;       /* Default: 16MB */
    size_t max_trailer_size;     /* Default: 8KB */
} SocketHTTP1_Config;
```

## HTTP/2 Security Limits

From `SocketHTTP2.h`:

### Connection Limits:
- `SOCKETHTTP2_DEFAULT_MAX_CONCURRENT_STREAMS` - 100
- `SOCKETHTTP2_DEFAULT_MAX_FRAME_SIZE` - 16KB (min 16KB, max 16MB per RFC)
- `SOCKETHTTP2_DEFAULT_WINDOW_SIZE` - 65535 (initial flow control window)
- `SOCKETHTTP2_MAX_WINDOW_SIZE` - 2^31 - 1 (per RFC 9113)

### Configuration Structure:
```c
typedef struct {
    uint32_t max_concurrent_streams;  /* Default: 100 */
    uint32_t max_frame_size;          /* Default: 16KB, max: 16MB */
    uint32_t initial_window_size;     /* Default: 65535 */
    uint32_t max_header_list_size;    /* Default: unlimited (0) */
    int enable_push;                  /* Default: 0 (disabled) */
} SocketHTTP2_Config;
```

## HPACK Security Limits

From `SocketHPACK.h`:

### Table Limits:
- `SOCKETHPACK_MAX_TABLE_SIZE` - 64KB (default dynamic table size)
- `SOCKETHPACK_STATIC_TABLE_SIZE` - 61 entries (per RFC 7541)

### Decoder Limits:
```c
typedef struct {
    size_t max_table_size;        /* Default: 4096 bytes */
    size_t max_header_size;       /* Per-header limit */
    size_t max_header_list_size;  /* Total decoded size */
} SocketHPACK_DecoderConfig;
```

## WebSocket Security Limits

From `SocketWS-private.h`:

### Frame and Message Limits:
- `SOCKETWS_MAX_FRAME_SIZE` - 16MB (default)
- `SOCKETWS_MAX_MESSAGE_SIZE` - 64MB (default, reassembled)
- `SOCKETWS_MAX_FRAGMENTS` - 1000 (default fragment count)
- `SOCKETWS_MAX_CONTROL_FRAME_SIZE` - 125 bytes (per RFC 6455)

### Configuration Structure:
```c
typedef struct {
    WS_Role role;                 /* CLIENT or SERVER */
    size_t max_frame_size;        /* Default: 16MB */
    size_t max_message_size;      /* Default: 64MB */
    size_t max_fragments;         /* Default: 1000 */
    int validate_utf8;            /* Default: 1 (enabled) */
    int ping_interval_ms;         /* Default: 0 (disabled) */
    int pong_timeout_ms;          /* Default: 60000 (60s) */
} SocketWS_Config;
```

## Rate Limiting Configuration

From `SocketConfig.h` and `SocketRateLimit.h`:

### Connection Rate Limits:
- `SOCKET_RATELIMIT_DEFAULT_CONN_PER_SEC` - 100 connections/second
- `SOCKET_RATELIMIT_DEFAULT_BURST` - 200 (2x rate)

### Per-IP Limits:
- `SOCKET_RATELIMIT_DEFAULT_MAX_PER_IP` - 10 simultaneous connections

### Configuration:
```c
typedef struct {
    uint64_t tokens_per_sec;    /* Tokens added per second */
    uint64_t bucket_size;       /* Maximum burst capacity */
} SocketRateLimit_Config;
```

## SYN Protection Limits

From `SocketSYNProtect.h`:

### Tracking Limits:
- `SOCKET_SYN_MAX_TRACKED_IPS` - 10000 (default)
- `SOCKET_SYN_REPUTATION_WINDOW_SEC` - 300 (5 minutes)
- `SOCKET_SYN_ATTEMPT_RATE_LIMIT` - 10 attempts/minute

### Thresholds:
```c
typedef struct {
    double allow_threshold;      /* < 0.3: Allow immediately */
    double throttle_threshold;   /* 0.3-0.6: Add delay */
    double challenge_threshold;  /* 0.6-0.8: Require challenge */
    double block_threshold;      /* > 0.8: Block connection */
} SocketSYNProtect_Config;
```

## UDP/Datagram Limits

From `SocketDgram.h`:

### Payload Limits:
- `UDP_MAX_PAYLOAD` - 65507 bytes (theoretical maximum)
- `SAFE_UDP_SIZE` - 1472 bytes (recommended to avoid fragmentation)

Calculation for safe size:
- 1500 (Ethernet MTU) - 20 (IPv4 header) - 8 (UDP header) = 1472 bytes

## Unix Domain Socket Limits

From `SocketConfig.h`:

### File Descriptor Passing:
- `SOCKET_MAX_FDS_PER_MSG` - 253 (SCM_RIGHTS limit)

### Path Limits:
- Platform-specific: `sizeof(struct sockaddr_un.sun_path)` (usually 108 characters)

## DNS Resolution Limits

From `SocketDNS.h`:

### Queue Limits:
- `SOCKET_DNS_MAX_PENDING` - 1000 (default max pending requests)
- `SOCKET_DNS_DEFAULT_WORKERS` - 4 (thread pool size)

### Timeouts:
- `SOCKET_DEFAULT_DNS_TIMEOUT_MS` - 5000 (5 seconds)

## Connection Pool Limits

From `SocketPool.h`:

### Pool Capacity:
- `SOCKET_MAX_CONNECTIONS` - 10000 (default max connections)
- Application-defined based on resources

### Drain Timeouts:
- Configurable per drain operation (typically 30-60 seconds)

## Security Test Suite

The `src/test/test_security.c` file contains comprehensive security tests (33 tests):
- Integer overflow protection verification
- Buffer safety and bounds checking
- HTTP/1.1 request smuggling rejection
- Header injection prevention
- UTF-8 security validation (overlong, surrogates)
- Cryptographic security (secure_compare, secure_clear)
- Size limit enforcement

Run security tests with: `ctest -R test_security`
