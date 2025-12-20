# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report security vulnerabilities through one of these methods:

1. **GitHub Security Advisory** (Preferred)
   - Go to the [Security tab](https://github.com/7etsuo/tetsuo-socket/security/advisories)
   - Click "Report a vulnerability"
   - Provide detailed information about the vulnerability

2. **Email**
   - Contact the maintainers directly via the email associated with the repository
   - Include "[SECURITY]" in the subject line

### What to Include

When reporting a vulnerability, please include:

- **Description**: A clear description of the vulnerability
- **Impact**: What an attacker could achieve by exploiting this vulnerability
- **Affected versions**: Which versions are affected
- **Reproduction steps**: Detailed steps to reproduce the issue
- **Proof of concept**: Code or commands that demonstrate the vulnerability (if possible)
- **Suggested fix**: If you have ideas on how to fix it (optional)

### Response Timeline

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Initial assessment**: We will provide an initial assessment within 7 days
- **Resolution**: We aim to release a fix within 30 days for critical vulnerabilities

### Disclosure Policy

- We follow coordinated disclosure practices
- We will credit reporters in the security advisory (unless they prefer to remain anonymous)
- We ask that you do not publicly disclose the vulnerability until we have released a fix

## Security Best Practices

When using this library, we recommend:

### TLS Configuration
- Use TLS 1.3 (default in this library - enforced via `SOCKET_TLS_MIN_VERSION`)
- Enable certificate verification in production (`TLS_VERIFY_PEER`)
- Use certificate pinning for sensitive applications (`SocketTLSContext_add_pin*()`)
- Regularly update CA certificates and CRLs (`SocketTLSContext_load_crl()`, `SocketTLSContext_set_crl_auto_refresh()`)
- Enable Certificate Transparency verification (`SocketTLSContext_enable_ct()`)
- Enable OCSP Must-Staple for maximum revocation checking (`SocketTLSContext_set_ocsp_must_staple()`)

### DTLS Configuration
- Use DTLS 1.2+ (enforced via `SOCKET_DTLS_MIN_VERSION`)
- Enable cookie exchange for DoS protection (`SocketDTLSContext_enable_cookie_exchange()`)
- Rotate cookie secrets periodically (`SocketDTLSContext_rotate_cookie_secret()`)
- Configure appropriate MTU for network conditions (`SocketDTLSContext_set_mtu()`)

### Input Validation
- Validate all user input before passing to socket functions
- Use async DNS for untrusted hostnames to avoid blocking (`SocketDNS_resolve()`)
- Set appropriate timeouts for all operations
- Validate file paths for certificate/key loading to prevent path traversal

### Memory Safety
- Use `SocketBuf_secureclear()` for buffers containing sensitive data
- Use `SocketCrypto_secure_clear()` for cryptographic material
- Properly dispose of arenas to prevent memory leaks
- Handle exceptions appropriately with TRY/EXCEPT/FINALLY

### Network Security
- Enable SYN flood protection for public-facing servers (`SocketSYNProtect_new()`)
- Configure appropriate rate limits (`SocketRateLimit_new()`, `SocketPool_setconnrate()`)
- Use connection pooling with proper cleanup
- Enable kTLS offload for high-performance scenarios (`SocketTLS_enable_ktls()`)

### HTTP Server Security
- **Slowloris Attack Prevention**: Configure comprehensive timeout enforcement in `SocketHTTPServer_Config`:
  - `tls_handshake_timeout_ms` (default: 10s) - Prevents slow TLS handshake attacks
  - `request_read_timeout_ms` (default: 30s) - Limits total time to read request headers and body
  - `keepalive_timeout_ms` (default: 60s) - Closes idle keep-alive connections
  - `response_write_timeout_ms` (default: 60s) - Limits response transmission time
  - `max_connection_lifetime_ms` (default: 300s) - Defense-in-depth timeout for all states
- Enforce resource limits via `SocketHTTPServer_Config`:
  - `max_header_size` (default: 64KB) - Prevents header bomb attacks
  - `max_body_size` (default: 10MB) - Prevents large payload DoS
  - `max_connections` (default: 1000) - Global connection limit
  - `max_connections_per_client` (default: 100) - Per-IP connection limit
  - `max_concurrent_requests` (default: 100) - HTTP/2 stream limit

### HTTP/2 Server Security
- Prefer **TLS + ALPN** for HTTP/2. Configure ALPN to include `"h2"` (and `"http/1.1"` as fallback) and use `SocketHTTPServer_Config.tls_context`.
- Treat **h2c upgrade (cleartext HTTP/2)** as advanced/opt-in. Only enable with `SocketHTTPServer_Config.enable_h2c_upgrade = 1` on trusted networks or behind a reverse proxy; do not expose h2c on the open internet unless you understand the risks.
- Be cautious with **HTTP/2 server push** (`SocketHTTPServer_Request_push()`): it consumes bandwidth and can be abused if overused.
- Validate and bound **trailers** (HTTP/2) like normal headers; trailers are untrusted input.

### WebSocket Security (HTTP/1.1 vs HTTP/2)
- HTTP/1.1 WebSocket upgrade (RFC 6455) is supported via `SocketHTTPServer_Request_upgrade_websocket()`.
- WebSockets over HTTP/2 (RFC 8441 / Extended CONNECT) are **not fully supported** yet (no stream-backed `SocketWS_T`). Prefer RFC 6455 upgrade over HTTP/1.1/HTTPS for now.

### Forward Secrecy
- Use TLS 1.3 KeyUpdate for long-lived connections (`SocketTLS_request_key_update()`)
- Rotate session ticket keys periodically (`SocketTLSContext_rotate_session_ticket_key()`)

## Security Features

This library includes comprehensive security features:

### TLS/DTLS Security (Complete December 2025)
- **TLS 1.3 Enforcement**: Secure by default - TLS 1.3-only mode with fallback support
- **DTLS 1.2+ Support**: Secure datagram transport with DoS protection
- **Certificate Pinning**: SPKI SHA256 pinning with constant-time comparison (`SocketCrypto_secure_compare()`)
- **Certificate Transparency**: RFC 6962 SCT verification (permissive/strict modes)
- **OCSP Stapling**: Server-side static/dynamic and client-side verification
- **OCSP Must-Staple**: RFC 7633 enforcement (DISABLED/AUTO/ALWAYS modes)
- **CRL Management**: Manual loading and auto-refresh with path security validation
- **Custom Verification Callbacks**: Application-specific certificate validation
- **Custom Certificate Lookup**: HSM/PKCS#11 and database integration support
- **Session Resumption**: TLS 1.3 PSK and session ticket support with secure key rotation
- **ALPN Protocol Negotiation**: RFC 7301 compliant with validation
- **SNI Support**: Virtual hosting with per-hostname certificates
- **kTLS Offload**: Kernel TLS for high-performance encryption (Linux 4.13+)
- **0-RTT Early Data**: TLS 1.3 early data with replay protection warnings
- **TLS 1.3 KeyUpdate**: Forward secrecy key rotation for long-lived connections
- **Renegotiation Control**: DoS protection with configurable limits (TLS 1.2)

### DTLS-Specific Security
- **Cookie Exchange**: RFC 6347 DoS protection with HMAC-SHA256 cookies
- **Cookie Secret Rotation**: Automatic grace period for pending handshakes
- **Retransmission Handling**: OpenSSL-managed DTLS retransmission
- **MTU Configuration**: Configurable MTU with bounds validation (576-9000 bytes)

### Memory Security
- **Secure Memory Clearing**: `SocketCrypto_secure_clear()` prevents compiler optimization
- **Key Material Protection**: `OPENSSL_cleanse()` for ticket keys, cookie secrets
- **Buffer Security**: `SocketBuf_secureclear()` for sensitive network data
- **SNI Hostname Clearing**: Secure erasure of connection metadata
- **Arena-Based Allocation**: Lifecycle management prevents leaks

### Timing Attack Prevention
- **Constant-Time Comparison**: `SocketCrypto_secure_compare()` for all security tokens
- **Certificate Pin Verification**: O(n) full scan regardless of match position
- **Cookie Verification**: Constant-time HMAC comparison

### Input Validation
- **Path Traversal Prevention**: Rejects "..", control characters, symlinks
- **File Size Limits**: DoS protection for cert/key/CRL files
- **Hostname Validation**: RFC 1123/6066 compliant validation
- **ALPN Validation**: RFC 7301 printable ASCII enforcement

### DoS Protection
- **SYN Flood Protection**: IP reputation tracking with sliding window
- **DTLS Cookie Exchange**: Prevents UDP amplification attacks
- **Rate Limiting**: Token bucket with configurable burst
- **Connection Limits**: Per-IP tracking with automatic cleanup
- **HTTP Server Slowloris Protection**: Multi-layered timeout enforcement
  - TLS handshake timeout prevents slow TLS negotiation attacks
  - Header parsing timeout prevents slow header attacks
  - HTTP/2 idle connection timeout prevents resource exhaustion
  - Global connection lifetime timeout (defense-in-depth)
- **CRL Refresh Intervals**: Minimum 60 seconds prevents refresh storms
- **Renegotiation Limits**: Maximum 3 per connection (TLS 1.2)

### Integer Overflow Protection
- Safe arithmetic throughout with SIZE_MAX/2 checks
- Buffer size validation via `SOCKET_VALID_BUFFER_SIZE`

## Threat Model Coverage

| Threat | Protection | Implementation |
|--------|------------|----------------|
| MITM | TLS 1.3 + cert verification + SPKI pinning | `SocketTLSContext-pinning.c` |
| Downgrade | TLS1.3_VERSION min + SSL_OP_NO_RENEGOTIATION | `SocketTLSContext-core.c` |
| DoS | DTLS cookies, file limits, rate limiting | `SocketDTLS-cookie.c`, `SocketSYNProtect.c` |
| Slowloris | Multi-layered timeout enforcement (TLS, headers, HTTP/2, lifetime) | `SocketHTTPServer.c` |
| Timing | `SocketCrypto_secure_compare()` everywhere | `SocketCrypto.c`, pinning, cookies |
| Memory Disclosure | `SocketCrypto_secure_clear()`, `OPENSSL_cleanse()` | All buffer/key cleanup paths |
| Replay | 0-RTT warnings, session freshness checks | `SocketTLSContext-session.c` |

For detailed security documentation, see [docs/SECURITY.md](docs/SECURITY.md) and [docs/TLS-CONFIG.md](docs/TLS-CONFIG.md).

