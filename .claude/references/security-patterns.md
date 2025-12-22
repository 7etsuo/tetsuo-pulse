# Security Patterns Reference

This document contains security-focused implementation patterns and validation utilities from the socket library.

## SocketSecurity.h API

Centralized security limits and validation utilities (from `include/core/SocketSecurity.h`):

### Limit Query Functions:
- `SocketSecurity_get_limits(&limits)` - Query all configured security limits at runtime
- `SocketSecurity_get_max_allocation()` - Get maximum safe allocation size
- `SocketSecurity_get_http_limits()` - Query HTTP-specific limits
- `SocketSecurity_get_ws_limits()` - Query WebSocket-specific limits
- `SocketSecurity_has_tls()` - Check if TLS support is compiled in
- `SocketSecurity_has_compression()` - Check if HTTP compression is available

### Overflow Protection Functions:
- `SocketSecurity_check_size(size)` - Validate allocation size against maximum
- `SocketSecurity_check_multiply(a, b, &result)` - Overflow-safe multiplication (returns 1 if safe, 0 if overflow)
- `SocketSecurity_check_add(a, b, &result)` - Overflow-safe addition (returns 1 if safe, 0 if overflow)
- `SocketSecurity_safe_multiply(a, b)` - Inline overflow-safe multiplication (returns product or 0 on overflow)
- `SocketSecurity_safe_add(a, b)` - Inline overflow-safe addition (returns sum or SIZE_MAX on overflow)

### Validation Macros:
- `SOCKET_SECURITY_VALID_SIZE(s)` - Check size is within safe limits
- `SOCKET_SECURITY_CHECK_OVERFLOW_MUL(a, b)` - Inline multiplication overflow check
- `SOCKET_SECURITY_CHECK_OVERFLOW_ADD(a, b)` - Inline addition overflow check

## Safe Allocation Patterns

### Arena Allocation with Overflow Protection:
```c
/* Arena_alloc already includes overflow checking */
size_t elem_size = sizeof(MyStruct);
size_t count = user_input;  /* Potentially malicious */

/* Arena handles overflow internally - will raise Arena_Failed if overflow */
MyStruct *array = ALLOC(arena, count * elem_size);

/* For manual checking before allocation: */
size_t total_size;
if (!SocketSecurity_check_multiply(count, elem_size, &total_size)) {
    /* Overflow detected - reject */
    RAISE(Arena_Failed);
}
if (!SocketSecurity_check_size(total_size)) {
    /* Exceeds SOCKET_SECURITY_MAX_ALLOCATION - reject */
    RAISE(Arena_Failed);
}
```

### Buffer Size Validation:
```c
/* Validate buffer size before operations */
if (!SOCKET_SECURITY_VALID_SIZE(user_buffer_size)) {
    RAISE(Socket_Failed);
}

/* Or use function for complex validation */
if (!SocketSecurity_check_size(user_buffer_size)) {
    SOCKET_RAISE_MODULE_ERROR("Buffer size %zu exceeds maximum %zu",
                               user_buffer_size, SocketSecurity_get_max_allocation());
}
```

## Overflow-Safe Arithmetic

### Addition with Overflow Check:
```c
size_t new_size;
if (!SocketSecurity_check_add(current_size, increment, &new_size)) {
    /* Overflow detected */
    SOCKET_RAISE_MODULE_ERROR("Buffer growth would overflow");
}

/* Or inline macro version */
if (!SOCKET_SECURITY_CHECK_OVERFLOW_ADD(current_size, increment)) {
    SOCKET_RAISE_MODULE_ERROR("Buffer growth would overflow");
}
```

### Multiplication with Overflow Check:
```c
size_t total_size;
if (!SocketSecurity_check_multiply(elem_count, elem_size, &total_size)) {
    /* Overflow detected */
    SOCKET_RAISE_MODULE_ERROR("Allocation would overflow");
}

/* Or inline macro version */
if (!SOCKET_SECURITY_CHECK_OVERFLOW_MUL(elem_count, elem_size)) {
    SOCKET_RAISE_MODULE_ERROR("Allocation would overflow");
}
```

## Input Validation Macros

From `SocketConfig.h`:

### Port Validation:
```c
/* SOCKET_VALID_PORT(p) - Port range validation (1-65535) */
if (!SOCKET_VALID_PORT(port)) {
    SOCKET_RAISE_MODULE_ERROR("Invalid port %d (must be 1-65535)", port);
}
```

### Buffer Size Validation:
```c
/* SOCKET_VALID_BUFFER_SIZE(s) - Buffer size validation */
if (!SOCKET_VALID_BUFFER_SIZE(buffer_size)) {
    SOCKET_RAISE_MODULE_ERROR("Invalid buffer size %zu", buffer_size);
}
```

## Safe String Copy Patterns

### Use socket_util_safe_strncpy Instead of strncpy:
```c
/* NEVER use strncpy() directly - may not null-terminate */

/* WRONG - strncpy does NOT guarantee null-termination */
char buf[256];
strncpy(buf, user_input, sizeof(buf));  /* BUG: may not be null-terminated! */

/* CORRECT - socket_util_safe_strncpy always null-terminates */
char buf[256];
socket_util_safe_strncpy(buf, user_input, sizeof(buf));  /* Always safe */
```

### Safe IP Address Copy:
```c
/* Use socket_util_safe_copy_ip for IP address strings */
char ip_buf[SOCKET_IP_MAX_LEN];
socket_util_safe_copy_ip(ip_buf, client_ip, sizeof(ip_buf));
```

### Why strncpy is Dangerous:
- `strncpy(dest, src, n)` does NOT null-terminate if `strlen(src) >= n`
- This leads to buffer overread vulnerabilities when the string is used
- `socket_util_safe_strncpy` always null-terminates by copying at most `max_len-1` chars

## Cryptographic Security Patterns

### Constant-Time Comparison (Timing Attack Prevention):
```c
/* NEVER use memcmp() or strcmp() for secrets */

/* WRONG - vulnerable to timing attacks */
if (memcmp(computed_mac, received_mac, 32) == 0) {
    /* Accept */
}

/* CORRECT - constant-time comparison */
if (SocketCrypto_secure_compare(computed_mac, received_mac, 32) == 0) {
    /* Accept */
}
```

### Secure Memory Clearing:
```c
/* NEVER use memset() for sensitive data - may be optimized away */

/* WRONG - compiler may optimize away */
char password[256];
/* ... use password ... */
memset(password, 0, sizeof(password));

/* CORRECT - guaranteed not to be optimized away */
char password[256];
/* ... use password ... */
SocketCrypto_secure_clear(password, sizeof(password));
```

### Cryptographically Secure Random:
```c
/* NEVER use rand() or random() for security-critical values */

/* WRONG - predictable */
uint32_t session_id = rand();

/* CORRECT - cryptographically secure */
unsigned char nonce[16];
if (SocketCrypto_random_bytes(nonce, sizeof(nonce)) < 0) {
    SOCKET_RAISE_MODULE_ERROR("Failed to generate random bytes");
}
```

## Thread-Safe Error Handling

### Thread-Local Exception Pattern:
```c
/* Declare thread-local exception copy in implementation file */
SOCKET_DECLARE_MODULE_EXCEPTION(MyModule_Failed);

/* Use thread-safe error reporting */
SOCKET_RAISE_MODULE_ERROR("Operation failed: %s", reason);

/* NEVER directly modify global exception .reason field (race condition) */
```

### Thread-Local Error Buffers:
```c
/* Each module has thread-local error buffer */
static __thread char mymodule_error_buf[512];

/* Use MODULE_ERROR_FMT for formatted errors */
MODULE_ERROR_FMT(mymodule_error_buf, "Failed to connect to %s:%d", host, port);

/* Or MODULE_ERROR_MSG for simple messages */
MODULE_ERROR_MSG(mymodule_error_buf, "Connection timeout");
```

## Safe System Call Patterns

### SAFE_CLOSE Macro:
```c
/* Proper EINTR handling per POSIX.1-2008 */
SAFE_CLOSE(fd);  /* Automatically retries on EINTR */

/* NEVER use close() directly - may fail on EINTR */
```

### Thread-Safe Error Strings:
```c
/* Use Socket_safe_strerror() instead of strerror() */
const char *error_msg = Socket_safe_strerror(errno);
SOCKET_RAISE_MODULE_ERROR("Socket operation failed: %s", error_msg);
```

## HTTP/1.1 Request Smuggling Prevention

From `SocketHTTP1` parser:

### Content-Length / Transfer-Encoding Conflict:
```c
/* Parser REJECTS messages with BOTH Content-Length AND Transfer-Encoding */
/* This prevents CL.TE and TE.CL smuggling attacks (RFC 9112 Section 6.3) */

/* Parser enforces: EXACTLY one body length determination method */
```

### Multiple Content-Length Headers:
```c
/* Parser REJECTS multiple Content-Length headers with differing values */
/* Identical Content-Length headers are coalesced */
```

### Transfer-Encoding Validation:
```c
/* Parser only accepts "chunked" (case-insensitive) */
/* REJECTS: "chunked, identity", "chunked\x00malicious", etc. */
```

### Chunked Encoding Security:
```c
/* Chunk size has maximum limit (max_chunk_size config) */
/* Chunk extensions bounded by max_chunk_ext (default 1KB) */
/* Trailer headers validated same as regular headers */
/* Forbidden trailers rejected: Transfer-Encoding, Content-Length, etc. */
```

## HPACK Bomb Prevention

From `SocketHPACK` decoder:

### Dynamic Table Size Limits:
```c
/* max_table_size enforced (default 4096 bytes) */
/* SETTINGS_HEADER_TABLE_SIZE updates don't exceed limit */
/* Table size reduction properly evicts entries */
```

### Header Size Limits:
```c
/* max_header_size limits individual header size */
/* max_header_list_size limits total decoded header size */
/* Limits checked BEFORE allocation */
```

### Decompression Ratio Checks:
```c
/* Excessive expansion from compressed input rejected */
/* Decoded size bounded relative to encoded size */
```

## HTTP/2 Flow Control Security

From `SocketHTTP2` flow control:

### Window Overflow Prevention:
```c
/* http2_flow_update_send/recv() check for 2^31-1 overflow */
/* WINDOW_UPDATE exceeding max results in FLOW_CONTROL_ERROR */
```

### Window Exhaustion Protection:
```c
/* Initial window size (SETTINGS_INITIAL_WINDOW_SIZE) is reasonable */
/* Timeout on zero window prevents indefinite blocking */
/* Server doesn't hold unlimited buffered data */
```

## WebSocket Frame Security

From `SocketWS` frame handling:

### Masking Enforcement (RFC 6455):
```c
/* ALL client frames MUST be masked (mask bit = 1) */
/* Unmasked client frames cause connection close */

/* Server frames MUST NOT be masked (mask bit = 0) */
/* Masked server frames cause client to close connection */

/* Mask key generated with SocketCrypto_random_bytes() */
/* 8-byte aligned XOR masking for performance */
```

### Frame Validation:
```c
/* Only valid opcodes accepted (0x0-0x2, 0x8-0xA) */
/* Reserved opcodes (0x3-0x7, 0xB-0xF) cause protocol error */

/* Control frames (PING, PONG, CLOSE) <= 125 bytes */
/* Control frames not fragmented (FIN must be 1) */

/* RSV bits must be 0 unless extension negotiated */
/* RSV1 allowed only with permessage-deflate */
```

### UTF-8 Validation:
```c
/* ALL text frame payloads validated for UTF-8 */
/* SocketUTF8_update() used for incremental validation */
/* Invalid UTF-8 causes close with 1007 (Invalid Payload) */

/* Fragmented text validated across fragments */
/* Incomplete UTF-8 at fragment boundary handled correctly */
/* SocketUTF8_finish() called on final fragment */
```

## UTF-8 Security Validation

From `SocketUTF8` DFA-based validator:

### Overlong Encoding Detection:
```c
/* UTF8_OVERLONG result for overlong encodings */
/* All overlong variants detected (e.g., 0xC0 0x80 for NUL) */
/* Prevents directory traversal via overlong ../ */
/* Input is REJECTED, not normalized */
```

### Surrogate Pair Rejection:
```c
/* UTF8_SURROGATE result for UTF-16 surrogates (U+D800-U+DFFF) */
/* Surrogate pairs rejected in UTF-8 (invalid per standard) */
/* Lone surrogates detected */
```

### Invalid Code Point Rejection:
```c
/* UTF8_TOO_LARGE for code points > U+10FFFF */
/* Non-characters handled appropriately */
/* BOM (U+FEFF) handled if required */
```

## Proxy Security Patterns

From `SocketProxy`:

### Credential Handling:
```c
/* Credentials cleared with SocketCrypto_secure_clear() after use */
/* Passwords not logged or included in error messages */

SocketProxy_Config proxy;
proxy.username = "user";
proxy.password = "pass";

/* After connection established: */
SocketCrypto_secure_clear(proxy.password, strlen(proxy.password));
```

### URL Parsing Security:
```c
/* SocketProxy_parse_url() validates URL format */
/* Rejects malformed proxy URLs */
/* Credentials extracted safely without buffer overflows */
```

## State Machine Security

Patterns for all state machines (HTTP/2, WebSocket, Proxy, etc.):

### Valid Transition Enforcement:
```c
/* Only valid state transitions allowed */
/* Invalid transitions raise appropriate errors */
/* State machine cannot be forced into invalid state */
```

### Atomic Transitions:
```c
/* State transitions are atomic (thread-safe where needed) */
/* No TOCTOU race conditions in state checks */
/* State and associated data updated together */
```

### Terminal State Cleanup:
```c
/* Resources freed when entering terminal states */
/* Cleanup is idempotent (safe to call twice) */
/* Operations on terminated instances rejected */
```

## Callback Safety Patterns

### No Module Free from Callback:
```c
/* NEVER call Module_free() from within its own callback */
/* EXCEPTION: SocketPool_free() IS safe from SocketPool_DrainCallback */
```

### No Mutex Held During Callback:
```c
/* Mutexes are NOT held during callbacks (deadlock risk) */
/* Callback can safely acquire mutexes if needed */
```

### Thread Context:
```c
/* Callbacks execute in thread calling process() or SocketPoll_wait() */
/* Don't assume different thread context */
/* Check for thread-local state access in callbacks */
```

## Hash Table Security

### Collision Attack Mitigation:
```c
/* DJB2 hash is vulnerable to algorithmic complexity attacks */
/* Consider hash randomization (seed from CSPRNG) */
/* Implement maximum chain length limits */
/* Use Robin Hood hashing for bounded probe sequences */
```

### Hash Randomization Pattern:
```c
/* Generate random hash seed at initialization */
unsigned seed;
SocketCrypto_random_bytes((unsigned char *)&seed, sizeof(seed));

/* Mix seed into hash function */
unsigned hash = (djb2_hash(key) ^ seed) % table_size;
```

## DoS Protection Patterns

### Rate Limiting:
```c
/* Apply rate limiting at correct points */
SocketRateLimit_T limiter = SocketRateLimit_new(100, 200);  /* 100/s, burst 200 */

if (!SocketRateLimit_try_acquire(limiter, 1)) {
    /* Rate limit exceeded */
    uint64_t wait_ms = SocketRateLimit_wait_time_ms(limiter, 1);
    /* Return 429 Too Many Requests or delay */
}
```

### Per-IP Tracking:
```c
/* Track connections per IP address */
SocketIPTracker_T tracker = SocketIPTracker_new(10);  /* Max 10 per IP */

if (!SocketIPTracker_track(tracker, client_ip)) {
    /* Limit exceeded - reject connection */
}

/* On connection close: */
SocketIPTracker_release(tracker, client_ip);
```

### Circuit Breaker:
```c
/* Auto-reconnect with exponential backoff and circuit breaker */
SocketReconnect_Policy_T policy = {
    .initial_delay_ms = 100,
    .max_delay_ms = 60000,
    .backoff_factor = 2.0,
    .jitter_factor = 0.1,
    .circuit_failure_threshold = 5,
};
```

### SYN Flood Protection:
```c
/* Reputation-based SYN protection */
SocketSYNProtect_T syn_protect = SocketSYNProtect_new(&config, arena);

SYNAction action = SocketSYNProtect_check(syn_protect, client_ip);
switch (action) {
    case SYN_ACTION_ALLOW:
        /* Good reputation - accept immediately */
        break;
    case SYN_ACTION_THROTTLE:
        /* Medium reputation - add delay */
        break;
    case SYN_ACTION_CHALLENGE:
        /* Poor reputation - require proof-of-work */
        break;
    case SYN_ACTION_BLOCK:
        /* Bad reputation - reject */
        break;
}

/* After successful connection: */
SocketSYNProtect_record_success(syn_protect, client_ip);

/* After failed attempt: */
SocketSYNProtect_record_failure(syn_protect, client_ip);
```

## Timeout Security

### Monotonic Clock Usage:
```c
/* Use CLOCK_MONOTONIC for security-critical timing */
uint64_t start_ms = Socket_get_monotonic_ms();

/* ... operation ... */

uint64_t elapsed_ms = Socket_get_monotonic_ms() - start_ms;
if (elapsed_ms > timeout_ms) {
    /* Timeout */
}
```

### All Operations Have Timeouts:
```c
/* DNS resolution timeout */
SocketDNS_settimeout(5000);  /* 5 seconds */

/* Connection timeout */
Socket_settimeout(socket, SOCKET_DEFAULT_CONNECT_TIMEOUT_MS);

/* TLS handshake timeout */
SocketTLS_handshake_auto(socket);  /* Enforces SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS */

/* Pool drain timeout */
SocketPool_drain(pool, 30000);  /* 30 seconds */
```

## Resource Limit Enforcement

### Maximum Connections:
```c
/* Pool capacity enforced */
SocketPool_T pool = SocketPool_new(arena, SOCKET_MAX_CONNECTIONS, buffer_size);

if (!SocketPool_add(pool, socket)) {
    /* Pool full - reject connection */
    Socket_close(socket);
}
```

### Maximum Message Size:
```c
/* WebSocket message size limit */
config.max_message_size = 16 * 1024 * 1024;  /* 16MB */

/* Frame size validated BEFORE allocation */
if (frame_size > config.max_frame_size) {
    /* Oversized frame - close with 1009 */
    SocketWS_close(ws, WS_CLOSE_TOO_LARGE, "Frame too large");
}
```

### Maximum Pending Requests:
```c
/* DNS queue limit */
SocketDNS_setmaxpending(1000);

/* If queue full, reject new requests */
```
