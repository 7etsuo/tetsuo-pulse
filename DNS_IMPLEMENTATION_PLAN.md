# DNS Resolver Implementation Plan

**23 Issues · 12 RFCs · Zero External Dependencies**

## Phase 1: Wire Format Foundation

Build the DNS message encoding/decoding layer.

```
#128 Header ──────┐
                  ├──► #130 Question
#129 Names ───────┤
      │           │
      │           └──► #131 RR Parsing ───┬──► #132 A/AAAA
      │                      │            ├──► #133 CNAME
      └──────────────────────┘            └──► #149 SOA
```

| Order | Issue | Description | Dependencies |
|-------|-------|-------------|--------------|
| 1 | #128 | DNS message header encoding/decoding (RFC 1035 §4.1.1) | (none) |
| | | • ID, flags (QR, OPCODE, RCODE) | |
| | | • Section counts (QD, AN, NS, AR) | |
| | | • 12 bytes, network byte order | |
| 2 | #129 | Domain name encoding/decoding (RFC 1035 §4.1.2, §4.1.4) | (none) |
| | | • Label format (length + data) | |
| | | • Compression pointers (0xC0) | |
| | | • Max label 63, max name 255 bytes | |
| | | • Case-insensitive comparison | |
| 3 | #130 | Question section encoding (RFC 1035 §4.1.2) | #128, #129 |
| | | • QNAME (domain name) | |
| | | • QTYPE (A=1, AAAA=28, etc.) | |
| | | • QCLASS (IN=1) | |
| 4 | #131 | Resource record parsing (RFC 1035 §4.1.3) | #129 |
| | | • NAME, TYPE, CLASS, TTL, RDLENGTH | |
| | | • Generic RDATA extraction | |
| | | • Handle compressed names | |
| 5 | #132 | A and AAAA RDATA parsing (RFC 1035 §3.4.1, RFC 3596) | #131 |
| | | • A: 4-byte IPv4 address | |
| | | • AAAA: 16-byte IPv6 address | |
| 6 | #133 | CNAME RDATA parsing (RFC 1035 §3.3.1) | #129, #131 |
| | | • Canonical name (domain name) | |
| | | • Chain following logic | |
| 7 | #149 | SOA RDATA parsing (RFC 1035 §3.3.13) | #129, #131 |
| | | • MNAME, RNAME (domain names) | |
| | | • SERIAL, REFRESH, RETRY, EXPIRE | |
| | | • MINIMUM (negative cache TTL) | |

---

## Phase 2: Transport Layer

Implement UDP/TCP communication with nameservers.

```
#134 UDP ──────► #135 TCP
   │
   └──────────► #143 EDNS0
```

| Order | Issue | Description | Dependencies |
|-------|-------|-------------|--------------|
| 8 | #134 | UDP transport (RFC 1035 §4.2.1) | #128-#132 |
| | | • Send query to port 53 | |
| | | • Max 512 bytes (without EDNS0) | |
| | | • Non-blocking I/O | |
| | | • Detect TC (truncation) bit | |
| 9 | #135 | TCP transport fallback (RFC 1035 §4.2.2) | #134 |
| | | • 2-byte length prefix | |
| | | • Used when UDP truncated | |
| | | • Connection reuse | |
| 10 | #143 | EDNS0 for larger UDP (RFC 6891) | #131, #134 |
| | | • OPT pseudo-RR (TYPE=41) | |
| | | • Advertise 4096 byte buffer | |
| | | • Extended RCODE support | |
| | | • Avoid TCP fallback in most cases | |

---

## Phase 3: Resolver Core

Implement the async resolver with caching.

```
#136 resolv.conf ────┐
                     │
#149 SOA ──► #137 Cache ──┬──► #138 Async Resolver ──┬──► #145 Retry
                          │           │              │
#134 UDP ─────────────────┘           │              └──► #144 Validation
                                      │
                                      ▼
                                ★ BENCHMARK ★
```

| Order | Issue | Description | Dependencies |
|-------|-------|-------------|--------------|
| 11 | #136 | /etc/resolv.conf parsing | (none) - parallel OK |
| | | • nameserver directives | |
| | | • search domains | |
| | | • options (timeout, attempts, ndots) | |
| 12 | #137 | DNS cache with TTL (RFC 1035 §7.4, RFC 2308) | #131, #149 |
| | | • Hash table for O(1) lookup | |
| | | • TTL-based expiration | |
| | | • Negative caching (NXDOMAIN) | |
| | | • LRU eviction, thread-safe | |
| 13 | #138 | Async resolver with multiplexing (RFC 1035 §7) | #134, #136, #137 |
| | | • Event loop integration | |
| | | • Query ID management | |
| | | • Multiple queries in flight | |
| | | • CNAME chain following | |
| 14 | #145 | Retry with exponential backoff (RFC 1035 §4.2.1, §7.2) | #138 |
| | | • Configurable initial timeout | |
| | | • Exponential backoff (2x) | |
| | | • Nameserver rotation | |
| 15 | #144 | Response validation & security | #138 |
| | | • Query/response ID matching | |
| | | • QNAME/QTYPE verification | |
| | | • Bailiwick checking | |
| | | • Source port randomization | |
| | | • TTL capping (max 1 week) | |

---

## Phase 4: Integration

Connect resolver to HTTP client and HappyEyeballs.

```
#138 Resolver ──► #140 IP Fast Path ──► #139 HappyEyeballs
                                               │
                                               ▼
                                       ★ COMPARE TO LIBCURL ★
```

| Order | Issue | Description | Dependencies |
|-------|-------|-------------|--------------|
| 16 | #140 | Numeric IP address fast path | #138 |
| | | • Detect IPv4/IPv6 literals | |
| | | • Skip DNS for IP addresses | |
| | | • inet_pton() validation | |
| 17 | #139 | HappyEyeballs integration (RFC 8305) | #138, #140 |
| | | • Parallel A + AAAA queries | |
| | | • Connection racing | |
| | | • Replace getaddrinfo() calls | |

---

## Phase 5: EDNS0 Security Extensions

Add DNS Cookies and Extended Error reporting.

```
#143 EDNS0 ──┬──► #150 DNS Cookies
             │
             └──► #151 Extended DNS Errors
```

| Order | Issue | Description | Dependencies |
|-------|-------|-------------|--------------|
| 18 | #150 | DNS Cookies (RFC 7873) | #143 |
| | | • Client cookie (8 bytes) | |
| | | • Server cookie caching | |
| | | • Anti-spoofing protection | |
| | | • BADCOOKIE handling | |
| 19 | #151 | Extended DNS Errors (RFC 8914) | #143 |
| | | • 24 error codes | |
| | | • DNSSEC failure details | |
| | | • Human-readable EXTRA-TEXT | |
| | | • Better debugging | |

---

## Phase 6: Encrypted DNS

Add DNS-over-TLS and DNS-over-HTTPS for privacy.

```
#135 TCP ──────► #146 DNS-over-TLS (port 853)

#138 Resolver ─► #147 DNS-over-HTTPS
```

| Order | Issue | Description | Dependencies |
|-------|-------|-------------|--------------|
| 20 | #146 | DNS-over-TLS (RFC 7858) | #135, #138, SocketTLS |
| | | • TLS on port 853 | |
| | | • Opportunistic or strict mode | |
| | | • Connection reuse | |
| | | • SPKI pinning support | |
| 21 | #147 | DNS-over-HTTPS (RFC 8484) | #138, SocketHTTPClient |
| | | • POST with application/dns-message | |
| | | • GET with base64url encoding | |
| | | • HTTP/2 multiplexing | |
| | | • Cache-Control integration | |

---

## Phase 7: DNSSEC Validation

Cryptographic verification of DNS responses.

```
#131 RR Parsing ──┐
                  │
#137 Cache ───────┼──► #148 DNSSEC Validation
                  │
#138 Resolver ────┘
```

| Order | Issue | Description | Dependencies |
|-------|-------|-------------|--------------|
| 22 | #148 | DNSSEC validation (RFC 4033, 4034, 4035, 5155) | #131, #137, #138 |
| | | • DNSKEY, RRSIG, DS record parsing | |
| | | • RSA/SHA-256, ECDSA verification | |
| | | • Chain of trust from root | |
| | | • NSEC/NSEC3 denial proofs | |
| | | • SECURE/INSECURE/BOGUS states | |

---

## Phase 8: Quality Assurance

Comprehensive testing and fuzzing.

```
All Issues ──────► #141 Tests and Fuzzing
```

| Order | Issue | Description | Dependencies |
|-------|-------|-------------|--------------|
| 23 | #141 | Comprehensive tests and fuzzing | All above |
| | | • Unit tests per module | |
| | | • Integration tests | |
| | | • libFuzzer harnesses | |
| | | • Malformed packet handling | |
| | | • Compression bomb detection | |

---

## Milestones

| Milestone | After Issue | Status |
|-----------|-------------|--------|
| Can send/receive DNS queries | #134 (UDP) | Basic functionality |
| Working async resolver | #138 (Resolver) | **BENCHMARK vs libcurl** |
| Full HappyEyeballs integration | #139 (HE) | **PRODUCTION READY** |
| Privacy-enabled resolver | #147 (DoH) | Encrypted DNS |
| Cryptographically verified DNS | #148 (DNSSEC) | **COMPLETE** |

---

## RFC Documents (12)

| RFC | Title |
|-----|-------|
| rfc1035.txt | Domain Names - Implementation and Specification (Core) |
| rfc2308.txt | Negative Caching of DNS Queries |
| rfc3596.txt | DNS Extensions to Support IPv6 (AAAA) |
| rfc4033.txt | DNS Security Introduction and Requirements |
| rfc4034.txt | Resource Records for DNS Security Extensions |
| rfc4035.txt | Protocol Modifications for DNS Security Extensions |
| rfc5155.txt | NSEC3 Hashed Authenticated Denial of Existence |
| rfc6891.txt | Extension Mechanisms for DNS (EDNS0) |
| rfc7858.txt | Specification for DNS over TLS |
| rfc7873.txt | Domain Name System (DNS) Cookies |
| rfc8484.txt | DNS Queries over HTTPS (DoH) |
| rfc8914.txt | Extended DNS Errors |

---

## Quick Reference

### Issue Numbers by Phase

- **Phase 1 (Wire Format):** #128, #129, #130, #131, #132, #133, #149
- **Phase 2 (Transport):** #134, #135, #143
- **Phase 3 (Resolver):** #136, #137, #138, #145, #144
- **Phase 4 (Integration):** #140, #139
- **Phase 5 (EDNS0 Ext):** #150, #151
- **Phase 6 (Encrypted):** #146, #147
- **Phase 7 (DNSSEC):** #148
- **Phase 8 (Testing):** #141

### Files to Create

```
include/dns/
├── SocketDNSWire.h        # Wire format (Phase 1)
├── SocketDNSTransport.h   # UDP/TCP (Phase 2)
├── SocketDNSConfig.h      # resolv.conf (Phase 3)
├── SocketDNSCache.h       # Cache (Phase 3)
├── SocketDNSResolver.h    # Async resolver (Phase 3)
├── SocketDNSCookie.h      # Cookies (Phase 5)
├── SocketDNSError.h       # Extended errors (Phase 5)
├── SocketDNSoverTLS.h     # DoT (Phase 6)
├── SocketDNSoverHTTPS.h   # DoH (Phase 6)
└── SocketDNSSEC.h         # DNSSEC (Phase 7)

src/dns/
├── SocketDNSWire.c
├── SocketDNSTransport.c
├── SocketDNSConfig.c
├── SocketDNSCache.c
├── SocketDNSResolver.c
├── SocketDNSCookie.c
├── SocketDNSError.c
├── SocketDNSoverTLS.c
├── SocketDNSoverHTTPS.c
├── SocketDNSSEC.c
└── SocketDNSSECCrypto.c
```
