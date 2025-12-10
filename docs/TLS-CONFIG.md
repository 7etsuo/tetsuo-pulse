# TLS Configuration Guide {#tls_config_guide}
**Brief**: Comprehensive TLS 1.3 configuration with security best practices | **Tags**: `tls`, `tls1.3`, `configuration`, `security`, `certificates`

Detailed configuration guide for TLS/SSL in the Socket Library.

**Module Group**: Security | **Related Modules**: SocketTLS, SocketTLSContext, SocketTLSConfig

---

## Overview

The Socket Library provides a secure-by-default TLS implementation with TLS 1.3 enforcement,
modern cipher suites, and comprehensive certificate management. This guide covers configuration
options, security best practices, and deployment patterns.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [TLS 1.3 Enforcement Rationale](#tls-13-enforcement-rationale)
3. [Cipher Suite Configuration](#cipher-suite-configuration)
4. [Certificate Management](#certificate-management)
5. [Client Configuration](#client-configuration)
6. [Server Configuration](#server-configuration)
7. [Mutual TLS (mTLS)](#mutual-tls-mtls)
8. [Certificate Pinning](#certificate-pinning)
9. [OCSP and Revocation](#ocsp-and-revocation)
10. [CRL Management](#crl-management)
11. [Certificate Transparency](#certificate-transparency)
12. [Session Management](#session-management)
13. [Advanced Configuration](#advanced-configuration)
14. [Troubleshooting](#troubleshooting)
15. [Security Checklist](#security-checklist)

---

## Quick Start

### TLS Client (5 Lines)

```c
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"

// Create client context with system CAs
SocketTLSContext_T ctx = SocketTLSContext_new_client(NULL);

// Connect and enable TLS
Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
Socket_connect(sock, "example.com", 443);
SocketTLS_enable(sock, ctx);
SocketTLS_set_hostname(sock, "example.com");

// Complete handshake
SocketTLS_handshake_auto(sock);

// Secure I/O
SocketTLS_send(sock, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", 40);

// Cleanup
SocketTLS_shutdown(sock);
Socket_free(&sock);
SocketTLSContext_free(&ctx);
```

### TLS Server (10 Lines)

```c
#include "tls/SocketTLS.h"
#include "tls/SocketTLSContext.h"

// Create server context with certificate
SocketTLSContext_T ctx = SocketTLSContext_new_server(
    "server.crt", "server.key", NULL);

// Setup listener
Socket_T listener = Socket_new(AF_INET, SOCK_STREAM, 0);
Socket_bind(listener, "0.0.0.0", 443);
Socket_listen(listener, 128);

// Accept and secure connection
Socket_T client = Socket_accept(listener);
SocketTLS_enable(client, ctx);
SocketTLS_handshake_auto(client);

// Secure I/O
char buf[4096];
ssize_t n = SocketTLS_recv(client, buf, sizeof(buf));

// Cleanup
SocketTLS_shutdown(client);
Socket_free(&client);
SocketTLSContext_free(&ctx);
```

---

## TLS 1.3 Enforcement Rationale

### Why TLS 1.3 Only?

The library enforces TLS 1.3 as the minimum and maximum protocol version:

```c
// Default configuration (SocketTLSConfig.h)
#define SOCKET_TLS_MIN_VERSION TLS1_3_VERSION
#define SOCKET_TLS_MAX_VERSION TLS1_3_VERSION
```

### Security Benefits

| Feature | TLS 1.3 | TLS 1.2 | Impact |
|---------|---------|---------|--------|
| Forward Secrecy | **Mandatory** | Optional | Protects past traffic if keys compromised |
| Cipher Suites | AEAD only | CBC/RC4 allowed | Eliminates padding oracle attacks |
| Renegotiation | Removed | Vulnerable | Prevents CVE-2009-3555 class attacks |
| Handshake | Encrypted | Plaintext | Protects certificates from passive observers |
| Round-Trips | 1-RTT | 2-RTT | 50% faster connection establishment |
| 0-RTT | Optional | N/A | Sub-RTT data transmission |

### Eliminated Vulnerabilities

TLS 1.3 removes these legacy attack vectors:

- **POODLE** (CVE-2014-3566): SSL 3.0 padding oracle
- **BEAST** (CVE-2011-3389): CBC IV chaining attack
- **Lucky13** (CVE-2013-0169): CBC timing attack
- **SWEET32** (CVE-2016-2183): 64-bit block cipher collision
- **ROBOT** (CVE-2017-13099): RSA key exchange attack
- **DROWN** (CVE-2016-0800): SSLv2 cross-protocol attack
- **Logjam** (CVE-2015-4000): DHE export downgrade
- **FREAK** (CVE-2015-0204): RSA export downgrade

### Legacy Compatibility (NOT RECOMMENDED)

If you **must** support TLS 1.2 for legacy systems:

```c
// Compile-time override (before including header)
#define SOCKET_TLS_MIN_VERSION TLS1_2_VERSION
#include "tls/SocketTLSConfig.h"

// Or runtime override
SocketTLSConfig_T config;
SocketTLS_config_defaults(&config);
config.min_version = TLS1_2_VERSION;
SocketTLSContext_T ctx = SocketTLSContext_new(&config);

// Or per-context override
SocketTLSContext_set_min_protocol(ctx, TLS1_2_VERSION);
```

**Warning**: TLS 1.2 requires careful cipher suite selection. Use only ECDHE+AEAD suites.

---

## Cipher Suite Configuration

### Default TLS 1.3 Cipher Suites

```c
#define SOCKET_TLS13_CIPHERSUITES \
    "TLS_AES_256_GCM_SHA384:"        \
    "TLS_CHACHA20_POLY1305_SHA256:"  \
    "TLS_AES_128_GCM_SHA256"
```

### Cipher Priority Rationale

| Priority | Cipher Suite | Key Size | Rationale |
|----------|-------------|----------|-----------|
| 1 | TLS_AES_256_GCM_SHA384 | 256-bit | Maximum security, AES-NI accelerated |
| 2 | TLS_CHACHA20_POLY1305_SHA256 | 256-bit | Timing-attack resistant, mobile-friendly |
| 3 | TLS_AES_128_GCM_SHA256 | 128-bit | Fallback, still highly secure |

### Custom Cipher Order

```c
// Prefer ChaCha20 for devices without AES hardware acceleration
#define SOCKET_TLS13_CIPHERSUITES \
    "TLS_CHACHA20_POLY1305_SHA256:"  \
    "TLS_AES_256_GCM_SHA384:"        \
    "TLS_AES_128_GCM_SHA256"

// Maximum security only (no fallback)
#define SOCKET_TLS13_CIPHERSUITES "TLS_AES_256_GCM_SHA384"

// Runtime configuration
SocketTLSContext_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384");
```

### Validation

Validate cipher strings before deployment:

```c
if (SocketTLSContext_validate_ciphersuites(cipher_string)) {
    SocketTLSContext_set_ciphersuites(ctx, cipher_string);
} else {
    log_error("Invalid cipher suite configuration");
}
```

---

## Certificate Management

### Loading Server Certificates

```c
// During context creation
SocketTLSContext_T ctx = SocketTLSContext_new_server(
    "server.crt",     // Certificate chain (PEM)
    "server.key",     // Private key (PEM)
    "ca-bundle.pem"   // Optional: CAs for client auth
);

// Or load separately
SocketTLSContext_T ctx = SocketTLSContext_new(NULL);
SocketTLSContext_load_certificate(ctx, "server.crt", "server.key");
```

### Certificate Chain Format

Your certificate file should contain the full chain:

```
-----BEGIN CERTIFICATE-----
[Your server certificate]
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
[Intermediate CA certificate]
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
[Root CA certificate - optional]
-----END CERTIFICATE-----
```

### SNI Virtual Hosting

Host multiple domains with different certificates:

```c
// Create context with default certificate
SocketTLSContext_T ctx = SocketTLSContext_new_server(
    "default.crt", "default.key", NULL);

// Add certificates for specific hostnames
SocketTLSContext_add_certificate(ctx, "www.example.com", 
    "example.crt", "example.key");
SocketTLSContext_add_certificate(ctx, "api.example.com",
    "api.crt", "api.key");
SocketTLSContext_add_certificate(ctx, "*.example.com",
    "wildcard.crt", "wildcard.key");
```

### Private Key Security

```bash
# Recommended file permissions
chmod 600 server.key
chown root:ssl-cert server.key

# Generate strong keys
# RSA 4096-bit
openssl genrsa -out server.key 4096

# ECDSA P-384 (recommended for performance)
openssl ecparam -genkey -name secp384r1 -out server.key
```

---

## Client Configuration

### Basic Client with Verification

```c
// Use system CA certificates
SocketTLSContext_T ctx = SocketTLSContext_new_client(NULL);

// Or specify CA bundle
SocketTLSContext_T ctx = SocketTLSContext_new_client("/etc/ssl/certs/ca-certificates.crt");

// Enable strict verification (default)
SocketTLSContext_set_verify_mode(ctx, TLS_VERIFY_PEER);
```

### Client with Full Security

```c
SocketTLSContext_T ctx = SocketTLSContext_new_client("ca-bundle.pem");

// Enable all security features
SocketTLSContext_enable_ocsp_stapling(ctx);
SocketTLSContext_enable_ct(ctx, CT_VALIDATION_STRICT);
SocketTLSContext_add_pin_from_cert(ctx, "expected-server.crt");

// Connect with hostname verification
Socket_T sock = Socket_new(AF_INET, SOCK_STREAM, 0);
Socket_connect(sock, "secure.example.com", 443);
SocketTLS_enable(sock, ctx);
SocketTLS_set_hostname(sock, "secure.example.com");  // SNI + verification

TRY {
    SocketTLS_handshake_auto(sock);
    
    // Verify all checks passed
    long verify = SocketTLS_get_verify_result(sock);
    if (verify != X509_V_OK) {
        RAISE(SocketTLS_VerifyFailed);
    }
    
    // Check OCSP status
    int ocsp = SocketTLS_get_ocsp_response_status(sock);
    if (ocsp == 0) {  // Revoked
        log_error("Certificate revoked via OCSP");
        RAISE(SocketTLS_VerifyFailed);
    }
    
    // Connection is secure
    printf("Connected via %s using %s\n",
        SocketTLS_get_version(sock),
        SocketTLS_get_cipher(sock));
    
} EXCEPT(SocketTLS_VerifyFailed) {
    log_error("Certificate verification failed: %s", tls_error_buf);
} END_TRY;
```

---

## Server Configuration

### Production Server Setup

```c
SocketTLSContext_T ctx = SocketTLSContext_new_server(
    "server.crt", "server.key", NULL);

// Enable session resumption for performance
SocketTLSContext_set_session_id_context(ctx, 
    (unsigned char *)"myapp-v1", 8);
SocketTLSContext_enable_session_cache(ctx, 10000, 3600);

// Enable session tickets with secure key
unsigned char ticket_key[80];
if (RAND_bytes(ticket_key, sizeof(ticket_key)) == 1) {
    SocketTLSContext_enable_session_tickets(ctx, ticket_key, sizeof(ticket_key));
    OPENSSL_cleanse(ticket_key, sizeof(ticket_key));
}

// Enable OCSP stapling
unsigned char *ocsp_response = load_ocsp_response("ocsp.der", &ocsp_len);
SocketTLSContext_set_ocsp_response(ctx, ocsp_response, ocsp_len);

// Configure ALPN for HTTP/2
const char *protos[] = {"h2", "http/1.1"};
SocketTLSContext_set_alpn_protos(ctx, protos, 2);
```

### High-Performance Server

```c
// Accept connections efficiently
while (running) {
    Socket_T client = Socket_accept(listener);
    if (!client) continue;
    
    Socket_setnonblocking(client);
    SocketTLS_enable(client, ctx);
    
    // Non-blocking handshake
    TLSHandshakeState state = SocketTLS_handshake(client);
    if (state == TLS_HANDSHAKE_WANT_READ || 
        state == TLS_HANDSHAKE_WANT_WRITE) {
        // Add to event loop for completion
        add_to_poll(client, state);
    } else if (state == TLS_HANDSHAKE_COMPLETE) {
        // Handle immediately
        handle_secure_connection(client);
    } else {
        // Handshake failed
        Socket_free(&client);
    }
}
```

---

## Mutual TLS (mTLS)

Require client certificates for authentication:

### Server Configuration

```c
// Server requires client certificate
SocketTLSContext_T server_ctx = SocketTLSContext_new_server(
    "server.crt", "server.key", "client-ca.pem");

// Fail if client doesn't provide certificate
SocketTLSContext_set_verify_mode(server_ctx, 
    TLS_VERIFY_PEER | TLS_VERIFY_FAIL_IF_NO_PEER_CERT);

// After handshake, get client identity
SocketTLS_CertInfo info;
if (SocketTLS_get_peer_cert_info(client, &info) == 1) {
    printf("Client: %s\n", info.subject);
    printf("Issued by: %s\n", info.issuer);
    printf("Valid until: %s", ctime(&info.not_after));
}
```

### Client Configuration

```c
// Client provides certificate
SocketTLSContext_T client_ctx = SocketTLSContext_new_client("server-ca.pem");
SocketTLSContext_load_certificate(client_ctx, "client.crt", "client.key");
```

### Example mTLS Workflow

```c
// Server: Accept mTLS connection
Socket_T client = Socket_accept(listener);
SocketTLS_enable(client, server_ctx);

TRY {
    SocketTLS_handshake_auto(client);
    
    // Get authenticated client identity
    SocketTLS_CertInfo info;
    if (SocketTLS_get_peer_cert_info(client, &info) == 1) {
        // Extract CN for authorization
        char *cn = extract_cn(info.subject);
        if (!is_authorized(cn)) {
            log_warn("Unauthorized client: %s", cn);
            RAISE(SocketTLS_VerifyFailed);
        }
        log_info("Authenticated client: %s", cn);
    }
    
    // Process authenticated request
    handle_authenticated_request(client);
    
} EXCEPT(SocketTLS_VerifyFailed) {
    log_error("Client authentication failed");
} FINALLY {
    SocketTLS_shutdown(client);
    Socket_free(&client);
} END_TRY;
```

---

## Certificate Pinning

Prevent MITM attacks by pinning expected certificates:

### Add Pins from Certificates

```c
// Pin the expected server certificate
SocketTLSContext_add_pin_from_cert(ctx, "server.crt");

// Add backup pin for rotation
SocketTLSContext_add_pin_from_cert(ctx, "server-backup.crt");

// Enable strict enforcement
SocketTLSContext_set_pin_enforcement(ctx, 1);
```

### Add Pins by Hash

```c
// Generate pin hash:
// openssl x509 -in cert.pem -pubkey -noout | \
//   openssl pkey -pubin -outform DER | \
//   openssl dgst -sha256 -hex

const char *pin = "a1b2c3d4e5f6...";  // 64 hex characters
SocketTLSContext_add_pin_hex(ctx, pin);
```

### Pin Rotation Best Practices

```c
// Always include backup pins
SocketTLSContext_add_pin_from_cert(ctx, "current.crt");
SocketTLSContext_add_pin_from_cert(ctx, "backup.crt");   // Different key
SocketTLSContext_add_pin_from_cert(ctx, "future.crt");   // Next rotation

// Before rotation:
// 1. Deploy backup.crt to servers
// 2. Update clients to pin new cert
// 3. Rotate primary cert to backup

// Monitor pin matches
if (SocketTLSContext_get_pin_count(ctx) < 2) {
    log_warn("Only one pin configured - add backup!");
}
```

---

## OCSP and Revocation

### Client: Request OCSP Stapling

```c
SocketTLSContext_T ctx = SocketTLSContext_new_client("ca.pem");
SocketTLSContext_enable_ocsp_stapling(ctx);

// After handshake
int status = SocketTLS_get_ocsp_response_status(sock);
switch (status) {
    case 1:  // GOOD
        log_info("Certificate verified via OCSP");
        break;
    case 0:  // REVOKED
        log_error("Certificate REVOKED!");
        // Abort connection
        break;
    case -1: // NO RESPONSE
        log_warn("No OCSP response from server");
        // Consider fallback to CRL or reject
        break;
    case -2: // VERIFICATION FAILED
        log_error("OCSP response verification failed");
        break;
}
```

### Server: Static OCSP Response

```c
// Load pre-fetched OCSP response
unsigned char *ocsp_der = load_file("ocsp.der", &ocsp_len);
SocketTLSContext_set_ocsp_response(ctx, ocsp_der, ocsp_len);
free(ocsp_der);
```

### Server: Dynamic OCSP Generation

```c
OCSP_RESPONSE *ocsp_gen_callback(SSL *ssl, void *arg) {
    OcspCache *cache = (OcspCache *)arg;
    
    // Get server certificate for lookup
    X509 *cert = SSL_get_certificate(ssl);
    if (!cert) return NULL;
    
    // Return cached response (freshly allocated copy)
    const unsigned char *cached_der;
    size_t cached_len;
    if (ocsp_cache_get(cache, cert, &cached_der, &cached_len)) {
        const unsigned char *p = cached_der;
        return d2i_OCSP_RESPONSE(NULL, &p, cached_len);
    }
    
    return NULL;  // No response available
}

SocketTLSContext_set_ocsp_gen_callback(ctx, ocsp_gen_callback, ocsp_cache);
```

---

## CRL Management

### Load CRL

```c
// Single CRL file
SocketTLSContext_load_crl(ctx, "/path/to/crl.pem");

// CRL directory (requires hashed symlinks)
SocketTLSContext_load_crl(ctx, "/etc/ssl/crls/");
```

### Auto-Refresh CRL

```c
void crl_callback(SocketTLSContext_T ctx, const char *path,
                  int success, void *data) {
    if (success) {
        log_info("CRL refreshed: %s", path);
    } else {
        log_error("CRL refresh failed: %s", path);
        alert_ops_team("CRL refresh failure");
    }
}

// Refresh every 6 hours
SocketTLSContext_set_crl_auto_refresh(ctx, "/path/to/crl.pem",
    6 * 3600, crl_callback, NULL);

// In event loop
while (running) {
    // ... handle events ...
    SocketTLSContext_crl_check_refresh(ctx);
}

// Cleanup
SocketTLSContext_cancel_crl_auto_refresh(ctx);
```

### CRL Best Practices

1. **Refresh interval**: Set to 50% of CRL validity period
2. **Fallback**: Cache last known good CRL
3. **Monitoring**: Alert on refresh failures
4. **Hash directory**: Use `c_rehash` for CRL directories

```bash
# Generate CRL hash links
c_rehash /etc/ssl/crls/

# Or manually
ln -s crl.pem $(openssl crl -hash -noout -in crl.pem).r0
```

---

## Certificate Transparency

### Enable CT Verification

```c
// Strict mode: Fail without valid SCTs
SocketTLSContext_enable_ct(ctx, CT_VALIDATION_STRICT);

// Permissive mode: Log but don't fail
SocketTLSContext_enable_ct(ctx, CT_VALIDATION_PERMISSIVE);

// Check status
if (SocketTLSContext_ct_enabled(ctx)) {
    CTValidationMode mode = SocketTLSContext_get_ct_mode(ctx);
}
```

### Custom CT Log List

```c
// Load custom trusted CT logs
SocketTLSContext_set_ctlog_list_file(ctx, "/path/to/ctlogs.conf");
```

### CT Requirements

- OpenSSL 1.1.0+ with CT support (`SOCKET_HAS_CT_SUPPORT`)
- Client contexts only (servers don't verify SCTs)
- Certificates must have valid SCTs embedded or via TLS extension

---

## Session Management

### Enable Session Cache

```c
// Set session ID context (required for isolation)
SocketTLSContext_set_session_id_context(ctx,
    (unsigned char *)"myapp-prod", 10);

// Enable cache: 10000 sessions, 1 hour timeout
SocketTLSContext_enable_session_cache(ctx, 10000, 3600);
```

### Session Tickets

```c
// Generate secure ticket key (80 bytes)
unsigned char key[80];
RAND_bytes(key, sizeof(key));

// Enable tickets
SocketTLSContext_enable_session_tickets(ctx, key, sizeof(key));
OPENSSL_cleanse(key, sizeof(key));

// Rotate key periodically (e.g., every 12 hours)
void rotate_ticket_key(void *arg) {
    SocketTLSContext_T ctx = arg;
    unsigned char new_key[80];
    RAND_bytes(new_key, sizeof(new_key));
    SocketTLSContext_rotate_session_ticket_key(ctx, new_key, sizeof(new_key));
    OPENSSL_cleanse(new_key, sizeof(new_key));
}
```

### Client Session Resumption

```c
// Save session after handshake
unsigned char session_data[4096];
size_t session_len = sizeof(session_data);

// Wait for session ticket (TLS 1.3)
SocketTLS_recv(sock, buf, sizeof(buf));

if (SocketTLS_session_save(sock, session_data, &session_len) == 1) {
    save_to_cache(host, session_data, session_len);
}

// Restore session on reconnect
session_len = sizeof(session_data);
if (load_from_cache(host, session_data, &session_len)) {
    SocketTLS_enable(sock, ctx);
    SocketTLS_session_restore(sock, session_data, session_len);
    SocketTLS_handshake_auto(sock);
    
    if (SocketTLS_is_session_reused(sock)) {
        log_info("Session resumed (1-RTT handshake)");
    }
}
```

---

## Advanced Configuration

### Custom Verification Callback

```c
int my_verify(int preverify_ok, X509_STORE_CTX *x509_ctx,
              SocketTLSContext_T tls_ctx, Socket_T socket,
              void *user_data) {
    // Custom validation logic
    X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    
    // Example: Reject certs expiring within 7 days
    if (depth == 0) {
        time_t now = time(NULL);
        time_t expiry = SocketTLS_get_cert_expiry(socket);
        if (expiry - now < 7 * 86400) {
            log_warn("Certificate expires in < 7 days");
            return 0;  // Reject
        }
    }
    
    return preverify_ok;
}

SocketTLSContext_set_verify_callback(ctx, my_verify, NULL);
```

### HSM/Database Certificate Lookup

```c
X509 *hsm_lookup(X509_STORE_CTX *ctx, const X509_NAME *name, void *data) {
    HSMSession *session = (HSMSession *)data;
    
    // Query HSM for certificate
    char subject[256];
    X509_NAME_oneline((X509_NAME *)name, subject, sizeof(subject));
    
    unsigned char *cert_der = NULL;
    size_t cert_len = 0;
    if (!hsm_find_cert(session, subject, &cert_der, &cert_len)) {
        return NULL;
    }
    
    // Parse and return (caller frees)
    const unsigned char *p = cert_der;
    X509 *cert = d2i_X509(NULL, &p, cert_len);
    free(cert_der);
    return cert;
}

SocketTLSContext_set_cert_lookup_callback(ctx, hsm_lookup, hsm_session);
```

### Timeout Configuration

```c
// Override default handshake timeout
#define SOCKET_TLS_DEFAULT_HANDSHAKE_TIMEOUT_MS 10000  // 10s

// Override default shutdown timeout
#define SOCKET_TLS_DEFAULT_SHUTDOWN_TIMEOUT_MS 2000    // 2s

// Override poll interval
#define SOCKET_TLS_POLL_INTERVAL_MS 50                 // 50ms
```

---

## Troubleshooting

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `SocketTLS_VerifyFailed` | Certificate verification failed | Check CA bundle, hostname, expiry |
| `SocketTLS_HandshakeFailed` | Protocol/cipher mismatch | Verify TLS 1.3 support |
| `SSL_ERROR_WANT_READ/WRITE` | Non-blocking I/O | Use handshake_loop() or poll |
| `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT` | Missing intermediate CA | Include full chain in cert file |
| `X509_V_ERR_CERT_HAS_EXPIRED` | Certificate expired | Renew certificate |

### Debug Logging

```c
// Check detailed error
TRY {
    SocketTLS_handshake_auto(sock);
} EXCEPT(SocketTLS_Failed) {
    printf("Error: %s\n", tls_error_buf);
    printf("Verify result: %ld\n", SocketTLS_get_verify_result(sock));
    
    char verify_err[256];
    SocketTLS_get_verify_error_string(sock, verify_err, sizeof(verify_err));
    printf("Verify error: %s\n", verify_err);
} END_TRY;
```

### Testing with OpenSSL

```bash
# Test server connection
openssl s_client -connect localhost:443 -tls1_3

# Test with specific cipher
openssl s_client -connect localhost:443 -ciphersuites TLS_AES_256_GCM_SHA384

# Check certificate chain
openssl s_client -connect localhost:443 -showcerts

# Test OCSP stapling
openssl s_client -connect localhost:443 -status
```

---

## Security Checklist

### Server

- [ ] TLS 1.3 only (no fallback to 1.2)
- [ ] Strong certificate (RSA 2048+ or ECDSA P-256+)
- [ ] Full certificate chain included
- [ ] Private key permissions 0600
- [ ] OCSP stapling enabled
- [ ] Session ticket key rotation
- [ ] Session ID context set
- [ ] ALPN configured for HTTP/2

### Client

- [ ] Certificate verification enabled
- [ ] System CA bundle or explicit trust anchors
- [ ] Hostname verification (SNI)
- [ ] OCSP stapling requested
- [ ] Certificate Transparency enabled
- [ ] Certificate pinning for known servers

### Both

- [ ] TLS 1.3 cipher suites only (AEAD + PFS)
- [ ] Error handling for all TLS exceptions
- [ ] Timeouts configured
- [ ] Logging for security events
- [ ] Regular testing with ssllabs.com or testssl.sh

---

## See Also

- @ref SECURITY.md - General security guide
- @ref DTLS-CONFIG.md - DTLS configuration
- @ref SocketTLSConfig.h - TLS configuration constants
- @ref SocketTLSContext.h - TLS context management
- @ref SocketTLS.h - TLS socket operations
