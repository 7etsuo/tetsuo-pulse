# Security Guide {#security_guide}

Security best practices for applications using the Socket Library.

---

## TLS 1.3 Configuration

The library enforces TLS 1.3 as the minimum protocol version for maximum security.

### Default Configuration

```c
#include "tls/SocketTLSContext.h"

/* Client context with system CA certificates */
SocketTLSContext_T ctx = SocketTLSContext_new_client(NULL);

/* Server context with certificate */
SocketTLSContext_T ctx = SocketTLSContext_new_server(
    "/path/to/cert.pem",
    "/path/to/key.pem"
);
```

### TLS Settings (SocketTLSConfig.h)

```c
/* Minimum: TLS 1.3 only (no TLS 1.2 or below) */
#define SOCKET_TLS_MIN_VERSION TLS1_3_VERSION
#define SOCKET_TLS_MAX_VERSION TLS1_3_VERSION

/* Modern cipher suites with Perfect Forward Secrecy */
#define SOCKET_TLS13_CIPHERSUITES \
    "TLS_AES_256_GCM_SHA384:"     \
    "TLS_CHACHA20_POLY1305_SHA256:" \
    "TLS_AES_128_GCM_SHA256"
```

### Why TLS 1.3?

- **No legacy algorithms** - Only modern, secure ciphers
- **Faster handshakes** - 1-RTT, optional 0-RTT
- **Perfect Forward Secrecy** - Ephemeral keys always used
- **Encrypted certificates** - Better privacy
- **Simplified protocol** - Smaller attack surface

---

## Certificate Transparency (CT)

Certificate Transparency (RFC 6962) provides an auditable public log of certificates issued by CAs. The library supports CT verification for TLS clients to detect mis-issued or undetected certificates.

### Usage
```c
SocketTLSContext_T ctx = SocketTLSContext_new_client("ca-bundle.pem");

/* Enable strict CT validation (fail if no valid SCTs) */
SocketTLSContext_enable_ct(ctx, CT_VALIDATION_STRICT);

/* Or permissive (log but continue on missing/invalid SCTs) */
SocketTLSContext_enable_ct(ctx, CT_VALIDATION_PERMISSIVE);

/* Load custom trusted CT log list (overrides OpenSSL defaults) */
SocketTLSContext_set_ctlog_list_file(ctx, "/path/to/ctlogs.txt");

/* Query status */
if (SocketTLSContext_ct_enabled(ctx)) {
  CTValidationMode mode = SocketTLSContext_get_ct_mode(ctx);
  // mode == CT_VALIDATION_STRICT or PERMISSIVE
}
```

### Security Benefits
- **Mis-issuance Detection**: SCTs (Signed Certificate Timestamps) must be obtained from public logs before cert issuance.
- **CA Accountability**: Monitors CA behavior through public audits.
- **Integration**: Works with CRL/OCSP for full revocation/CT coverage. Errors reflected in `SocketTLS_get_verify_result`.
- **Modes**:
  - **Strict**: Handshake fails without valid SCTs (recommended for high-security).
  - **Permissive**: Logs issues (via OpenSSL error queue) but allows connection.

### Requirements
- OpenSSL 1.1.0+ with CT support (`SOCKET_HAS_CT_SUPPORT`).
- Client-only (server contexts raise `SocketTLS_Failed`).

### Custom Logs
OpenSSL uses built-in log list (Google, etc.). For custom (e.g., enterprise logs), provide a file with log descriptors (see OpenSSL `CTLOG_STORE_load_file` format). Validate paths with library checks (no traversal, length limits).

### Verification
- SCTs validated during cert chain check.
- Missing/invalid SCTs: `X509_V_ERR_NO_VALID_SCTS` or similar in verify result.
- Test: Use `openssl s_client -ct` or library tests (`ctest -R tls_ct`).

### Limits
- `SOCKET_TLS_MAX_SCT_LEN`: Max SCT size (config).
- Chain depth (`SOCKET_TLS_MAX_CERT_CHAIN_DEPTH`) applies to SCT-embedded certs.

Combine with pinning (`SocketTLSContext_add_pin_*`) for defense-in-depth.

## Certificate Pinning

Pin expected certificates to prevent MITM attacks:

### SPKI SHA256 Pinning

```c
#include "tls/SocketTLSContext.h"

/* Get pin from certificate */
/* openssl x509 -in cert.pem -pubkey -noout | \
   openssl pkey -pubin -outform DER | \
   openssl dgst -sha256 -binary | base64 */

const char *pin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/* Pin certificate */
if (SocketTLSContext_pin_certificate(ctx, pin) < 0) {
    /* Invalid pin format */
}

/* Add backup pin */
SocketTLSContext_pin_certificate(ctx, backup_pin);
```

### When to Use Pinning

- **Mobile apps** connecting to known servers
- **IoT devices** with fixed backend
- **High-security** applications
- **Certificate transparency** not sufficient

### Pin Rotation

Always include at least one backup pin for certificate rotation:

```c
/* Current certificate */
SocketTLSContext_pin_certificate(ctx, current_pin);

/* Backup/next certificate */
SocketTLSContext_pin_certificate(ctx, backup_pin);
```

---

## Input Validation

### Hostname Validation

```c
/* Always validate hostnames before use */
#define MAX_HOSTNAME_LEN 253

if (hostname == NULL || strlen(hostname) > MAX_HOSTNAME_LEN) {
    /* Reject invalid hostname */
}

/* Check for null bytes (injection) */
if (strlen(hostname) != strnlen(hostname, MAX_HOSTNAME_LEN + 1)) {
    /* Contains embedded null */
}
```

### Port Validation

```c
#define SOCKET_VALID_PORT(p) ((int)(p) > 0 && (int)(p) <= 65535)

if (!SOCKET_VALID_PORT(port)) {
    /* Invalid port */
}
```

### Buffer Size Validation

```c
/* Always check for overflow */
if (size > SIZE_MAX / 2) {
    /* Too large - would overflow */
}

/* Use library macros */
#define SOCKET_VALID_BUFFER_SIZE(s) \
    ((size_t)(s) >= SOCKET_MIN_BUFFER_SIZE && \
     (size_t)(s) <= SOCKET_MAX_BUFFER_SIZE)
```

---

## DNS Security

### Blocking DNS Warning

DNS resolution via `Socket_bind()` and `Socket_connect()` may block:

```c
/* WARNING: May block for 30+ seconds on DNS timeout */
Socket_connect(sock, "hostname.example.com", 80);

/* For non-blocking, resolve separately */
SocketDNS_T dns = SocketDNS_new();
SocketDNS_Request_T req = SocketDNS_resolve(dns, hostname, port, NULL, NULL);
/* Poll for completion */
```

### DNS DoS Prevention

Never use untrusted hostnames directly:

```c
/* BAD - attacker can cause 30+ second block */
Socket_connect(sock, user_provided_hostname, port);

/* BETTER - use async DNS with timeout */
SocketDNS_request_settimeout(req, 5000);  /* 5 second limit */

/* BEST - validate and use IP addresses */
if (inet_pton(AF_INET, user_input, &addr) > 0) {
    Socket_connect(sock, user_input, port);
}
```

---

## Credential Handling

### Secure Memory Clearing

Always clear sensitive data after use:

```c
#include "core/SocketCrypto.h"

char password[256];
/* ... use password ... */

/* Clear from memory (won't be optimized away) */
SocketCrypto_secure_clear(password, sizeof(password));
```

### The Library Does This Internally

- Proxy credentials cleared after handshake
- TLS session keys cleared on close
- HTTP auth tokens cleared after use

### Constant-Time Comparison

Prevent timing attacks when comparing secrets:

```c
/* BAD - timing leak */
if (strcmp(provided_token, expected_token) == 0) { }

/* GOOD - constant time */
if (SocketCrypto_secure_compare(provided, expected, len) == 0) {
    /* Match */
}
```

---

## DoS Protection

### SYN Flood Protection

For servers accepting many connections:

```c
#include "core/SocketSYNProtect.h"

/* Create protection instance */
SocketSYNProtect_T protect = SocketSYNProtect_new(arena);

/* Configure thresholds */
SocketSYNProtect_Config config = {
    .max_syn_per_second = 100,
    .max_half_open = 1000,
    .challenge_after = 50
};
SocketSYNProtect_configure(protect, &config);

/* Check before accept */
SocketSYNProtect_Action action = SocketSYNProtect_check(protect, client_addr);

switch (action) {
case SYN_ACTION_ALLOW:
    /* Accept normally */
    break;
case SYN_ACTION_THROTTLE:
    /* Accept with delay */
    break;
case SYN_ACTION_CHALLENGE:
    /* Require proof of work or additional validation */
    break;
case SYN_ACTION_BLOCK:
    /* Reject connection */
    break;
}
```

### Rate Limiting

Limit connection/request rates:

```c
#include "core/SocketRateLimit.h"

/* Create token bucket */
SocketRateLimit_T limiter = SocketRateLimit_new(
    100.0,   /* 100 tokens per second */
    1000     /* Burst of 1000 */
);

/* Try to acquire token */
if (!SocketRateLimit_try_acquire(limiter, 1)) {
    /* Rate limited - reject or delay */
}
```

### Per-IP Connection Limits

```c
#include "core/SocketIPTracker.h"

SocketIPTracker_T tracker = SocketIPTracker_new(arena);

/* Before accepting */
if (SocketIPTracker_get_count(tracker, client_addr) >= MAX_PER_IP) {
    /* Too many connections from this IP */
    close(client_fd);
    return;
}

SocketIPTracker_increment(tracker, client_addr);
```

---

## Thread Safety

### Thread-Local Error Buffers

Error messages use thread-local storage:

```c
/* Safe - each thread has own buffer */
const char *error = Socket_error();
```

### Exception Thread Safety

The library uses thread-local exception copies:

```c
/* Internal: Thread-safe exception pattern */
static __thread Except_T Module_DetailedException;

#define RAISE_MODULE_ERROR(exception)                \
    do {                                             \
        Module_DetailedException = (exception);      \
        Module_DetailedException.reason = error_buf; \
        RAISE(Module_DetailedException);             \
    } while (0)
```

### What's NOT Thread-Safe

- `Socket_T` instances - one socket per thread
- `SocketWS_T` instances - one WebSocket per thread
- `SocketHTTPClient_T` - use one per thread
- `SocketPoll_T` - one event loop per thread

---

## Exception Handling

### Always Handle Security Exceptions

```c
TRY {
    SocketTLS_handshake(sock);
}
EXCEPT(SocketTLS_HandshakeFailed) {
    /* TLS negotiation failed - don't continue */
    log_security_event("TLS handshake failed");
}
EXCEPT(SocketTLS_VerifyFailed) {
    /* Certificate invalid - potential MITM */
    log_security_event("Certificate verification failed");
}
END_TRY;
```

### Don't Ignore Verification Failures

```c
/* BAD - disabling verification */
config.verify_ssl = 0;  /* Never do this in production */

/* GOOD - handle failures appropriately */
EXCEPT(SocketTLS_VerifyFailed) {
    /* Log, alert, and abort */
}
```

---

## HTTP Security

### Request Smuggling Prevention

The HTTP/1.1 parser (SocketHTTP1) includes protections:

- Rejects both Content-Length AND Transfer-Encoding
- Rejects multiple differing Content-Length values
- Validates header names/values for injection
- Enforces strict parsing mode

### WebSocket Security

```c
/* Always validate Origin header on server */
const char *origin = SocketHTTP_Headers_get(headers, "Origin");
if (!is_allowed_origin(origin)) {
    SocketWS_server_reject(socket, 403, "Origin not allowed");
}

/* Validate subprotocols */
if (!is_supported_protocol(selected)) {
    SocketWS_close(ws, WS_CLOSE_PROTOCOL_ERROR, "Unsupported protocol");
}
```

### Cookie Security

```c
/* Set secure cookie attributes */
SocketHTTPClient_CookieJar_set_flags(jar, 
    COOKIE_FLAG_SECURE |     /* HTTPS only */
    COOKIE_FLAG_HTTPONLY |   /* No JavaScript access */
    COOKIE_FLAG_SAMESITE     /* Prevent CSRF */
);
```

### HTTP/2 Flow Control Hardening

HTTP/2 flow control now includes enhanced protections (see [HTTP.md#http2-flow-control-security-enhancements](HTTP.md#http2-flow-control-security-enhancements)):

- **Overflow Prevention**: 64-bit checks in window updates/adjustments cap at 2^31-1; errors trigger `FLOW_CONTROL_ERROR`.
- **Negative Window Rejection**: SETTINGS delta adjustments reject cases leading to <0 windows (RFC 9113 §6.5.2), closing connections.
- **Invalid Inputs**: Zero increments treated as `PROTOCOL_ERROR`; metrics track violations for attack detection.
- **Monitoring**: New counters (e.g., `SOCKET_CTR_HTTP2_FLOW_OVERFLOW`) via `SocketMetrics_get` for alerting.

Use with `SocketPool` rate limits to mitigate DoS. Fuzz-tested for robustness.

---

## File Descriptor Hygiene

### Safe Close

```c
/* Use SAFE_CLOSE to handle EINTR correctly */
SAFE_CLOSE(fd);

/* Per POSIX.1-2008: Don't retry close() on EINTR */
/* The fd state is unspecified - retrying may close wrong fd */
```

### Prevent FD Leaks

```c
TRY {
    Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
    /* ... operations ... */
}
FINALLY {
    if (sock) Socket_free(&sock);  /* Always clean up */
}
END_TRY;
```

---

## Audit Logging

### What to Log

- Connection attempts (source IP, port)
- Authentication failures
- Certificate verification failures
- Rate limiting triggers
- Protocol violations

### How to Log Safely

```c
/* Don't log sensitive data */
log_info("Connection from %s:%d", client_ip, client_port);

/* BAD - leaks credentials */
log_debug("Auth failed for user %s with password %s", user, pass);

/* GOOD - no credentials */
log_warn("Auth failed for user %s", user);
```

---

## Security Checklist

### Server Applications

- [ ] Use TLS 1.3 for all connections
- [ ] Validate all input (hostnames, ports, sizes)
- [ ] Implement rate limiting
- [ ] Enable SYN flood protection
- [ ] Per-IP connection limits
- [ ] Validate WebSocket Origin headers
- [ ] Log security events
- [ ] Set appropriate timeouts

### Client Applications

- [ ] Verify server certificates
- [ ] Consider certificate pinning
- [ ] Use async DNS for untrusted hostnames
- [ ] Clear credentials after use
- [ ] Handle TLS errors properly
- [ ] Set reasonable timeouts

### General

- [ ] Use exception handling everywhere
- [ ] Clean up resources in FINALLY blocks
- [ ] Don't disable security features
- [ ] Keep dependencies updated
- [ ] Review code for injection vulnerabilities

---

## TLS Configuration Best Practices

### Protocol Version

The library enforces TLS 1.3 only by default. **Do not weaken this**:

```c
/* Default: TLS 1.3 only - keep it this way */
#define SOCKET_TLS_MIN_VERSION TLS1_3_VERSION
#define SOCKET_TLS_MAX_VERSION TLS1_3_VERSION

/* BAD: Don't lower the minimum version */
// SocketTLSContext_set_min_protocol(ctx, TLS1_VERSION);  // INSECURE!
```

**Why TLS 1.3 only?**
- Removes all legacy vulnerable ciphers (RC4, DES, 3DES, etc.)
- No renegotiation (eliminates CVE-2009-3555 class attacks)
- Mandatory forward secrecy (all key exchanges are ephemeral)
- Encrypted handshake (protects certificate from passive observers)
- Faster: 1-RTT handshake, optional 0-RTT resumption

### Cipher Suite Configuration

The library uses secure TLS 1.3 cipher suites by default:

```c
/* Default: Modern AEAD ciphers with PFS */
#define SOCKET_TLS13_CIPHERSUITES \
    "TLS_AES_256_GCM_SHA384:"     \
    "TLS_CHACHA20_POLY1305_SHA256:" \
    "TLS_AES_128_GCM_SHA256"
```

All three ciphers provide:
- **AEAD encryption** (authenticated encryption with associated data)
- **256-bit or 128-bit keys** (both considered secure)
- **Perfect Forward Secrecy** (compromised long-term key doesn't decrypt past traffic)

### Certificate Verification

**Always verify server certificates in production**:

```c
/* Client: Enable verification */
SocketTLSContext_T ctx = SocketTLSContext_new_client("/etc/ssl/certs/ca-certificates.crt");
SocketTLSContext_set_verify_mode(ctx, TLS_VERIFY_PEER);

/* BAD: Never disable verification in production */
// SocketTLSContext_set_verify_mode(ctx, TLS_VERIFY_NONE);  // INSECURE!
```

### Mutual TLS (mTLS)

For high-security applications, require client certificates:

```c
/* Server: Require client certificate */
SocketTLSContext_T server_ctx = SocketTLSContext_new_server(
    "server.crt", "server.key", "ca.crt");
SocketTLSContext_set_verify_mode(server_ctx, TLS_VERIFY_FAIL_IF_NO_PEER_CERT);

/* Client: Provide certificate */
SocketTLSContext_T client_ctx = SocketTLSContext_new_client("ca.crt");
SocketTLSContext_load_certificate(client_ctx, "client.crt", "client.key");
```

### OCSP Stapling

Enable OCSP stapling for real-time revocation checking:

```c
/* Client: Request OCSP status */
SocketTLSContext_enable_ocsp_stapling(client_ctx);

/* After handshake, check status */
OCSPStatus status = SocketTLS_get_ocsp_status(socket);
if (status == OCSP_STATUS_REVOKED) {
    /* Certificate revoked - abort! */
    Socket_free(&socket);
}

/* Server: Provide OCSP response */
SocketTLSContext_set_ocsp_response(server_ctx, ocsp_response, ocsp_len);
```

### Certificate Transparency

Enable CT verification to detect misissued certificates:

```c
/* Client: Require valid SCTs */
SocketTLSContext_enable_ct(ctx, CT_VALIDATION_STRICT);

/* Or permissive mode (log but don't fail) */
SocketTLSContext_enable_ct(ctx, CT_VALIDATION_PERMISSIVE);
```

### Certificate Revocation Lists (CRL)

CRLs provide certificate revocation checking without online OCSP queries:

**Initial CRL Loading:**

```c
/* Load CRL from file or directory */
SocketTLSContext_load_crl(ctx, "/path/to/crl.pem");

/* CRL directory (OpenSSL hashed names required) */
SocketTLSContext_load_crl(ctx, "/etc/ssl/crls/");
```

**Manual CRL Refresh Workflow:**

CRLs have expiration dates and must be refreshed periodically:

```c
/* 1. Download updated CRL from CA's distribution point */
/* (Use curl, wget, or HTTP client to fetch from CDP URL) */

/* 2. Reload CRL into context */
SocketTLSContext_reload_crl(ctx, "/path/to/updated-crl.pem");

/* 3. Schedule next refresh before CRL expires */
/* Typically refresh at 50% of validity period */
```

**Automatic CRL Refresh:**

For production systems, configure automatic refresh:

```c
/* Enable automatic CRL refresh every 6 hours */
SocketTLSContext_set_crl_auto_refresh(ctx, "/path/to/crl.pem", 
                                       6 * 3600,  /* 6 hours */
                                       crl_refresh_callback,
                                       user_data);

/* Callback notifies application of refresh success/failure */
void crl_refresh_callback(SocketTLSContext_T ctx, const char *path,
                          int success, void *data) {
    if (!success) {
        log_error("CRL refresh failed for %s", path);
        /* Consider alerting or using cached CRL */
    }
}

/* Cancel auto-refresh when done */
SocketTLSContext_cancel_crl_auto_refresh(ctx);
```

**CRL Best Practices:**

- **Refresh frequency:** Check CRL's nextUpdate field; refresh at 50% of validity
- **Fallback:** Cache last known good CRL in case download fails
- **Delta CRLs:** Not currently supported; use complete CRLs
- **Multiple CRLs:** Call `load_crl()` multiple times for different issuers
- **CRL vs OCSP:** Use OCSP stapling for real-time checks; CRLs for offline validation

**Generating CRL Hash Links (for directory mode):**

```bash
# OpenSSL requires hashed symlinks for CRL directories
c_rehash /etc/ssl/crls/
# Or manually:
ln -s crl.pem $(openssl crl -hash -noout -in crl.pem).r0
```

### Session Resumption Security

Session resumption improves performance but has security considerations:

```c
/* Enable with appropriate timeout */
SocketTLSContext_enable_session_cache(ctx, 1000, 300);  /* 5 min timeout */

/* For high-security: disable session tickets */
/* (Session tickets encrypt session state with server key - if key
   is compromised, all past sessions can be decrypted) */
```

**Session Ticket Key Rotation:**
- Rotate session ticket keys regularly (every few hours)
- Use `SocketTLSContext_rotate_ticket_key()` for key rotation
- Old tickets become invalid after rotation

### Renegotiation Protection

TLS renegotiation is disabled by default (SSL_OP_NO_RENEGOTIATION):

```c
/* Renegotiation is automatically disabled for all contexts.
 * TLS 1.3 doesn't support renegotiation at all.
 * For TLS 1.2 (if ever enabled), renegotiation is blocked.
 *
 * Renegotiation vulnerabilities:
 * - CVE-2009-3555: Prefix injection attack
 * - Triple Handshake Attack
 * - DoS via repeated renegotiation
 */
```

### Private Key Protection

```c
/* Use strong key files with restricted permissions */
chmod 600 server.key  /* Owner read/write only */

/* Consider using encrypted keys */
/* The library will prompt for passphrase or use callback */

/* For production: Use HSM or key management service */
```

### TLS Security Checklist

**Server Configuration:**
- [ ] TLS 1.3 only (default)
- [ ] Valid certificate from trusted CA
- [ ] Strong private key (RSA 2048+ or ECDSA P-256+)
- [ ] OCSP stapling enabled
- [ ] Session ticket key rotation
- [ ] Certificate Transparency support

**Client Configuration:**
- [ ] Verify server certificates
- [ ] Use system CA bundle or explicit trust anchor
- [ ] Consider certificate pinning for known servers
- [ ] Enable OCSP stapling request
- [ ] Enable CT verification in strict mode

**Both:**
- [ ] Keep OpenSSL updated
- [ ] Monitor for new vulnerabilities
- [ ] Test with tools like testssl.sh or ssllabs.com
- [ ] Log TLS errors for security monitoring

---

## See Also

- @ref SocketTLSConfig.h - TLS configuration constants
- @ref SocketTLSContext.h - TLS context management
- @ref SocketTLS.h - TLS socket operations
- @ref SocketSYNProtect.h - DoS protection
- @ref SocketRateLimit.h - Rate limiting
- @ref SocketCrypto.h - Cryptographic utilities

