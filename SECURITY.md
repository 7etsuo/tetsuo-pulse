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
- Use TLS 1.3 (default in this library)
- Enable certificate verification in production
- Use certificate pinning for sensitive applications
- Regularly update CA certificates

### Input Validation
- Validate all user input before passing to socket functions
- Use async DNS for untrusted hostnames to avoid blocking
- Set appropriate timeouts for all operations

### Memory Safety
- Use `SocketBuf_secureclear()` for buffers containing sensitive data
- Properly dispose of arenas to prevent memory leaks
- Handle exceptions appropriately with TRY/EXCEPT/FINALLY

### Network Security
- Enable SYN flood protection for public-facing servers
- Configure appropriate rate limits
- Use connection pooling with proper cleanup

## Security Features

This library includes several security features:

- **TLS 1.3 Enforcement**: Secure by default TLS configuration
- **Certificate Pinning**: SPKI SHA256 pinning support
- **OCSP Stapling**: Real-time certificate revocation checking
- **SYN Flood Protection**: Built-in DDoS mitigation
- **Secure Memory Clearing**: Sensitive data wiping
- **Integer Overflow Protection**: Safe arithmetic throughout

For detailed security documentation, see [docs/SECURITY.md](docs/SECURITY.md).

