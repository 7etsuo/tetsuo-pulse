# Security-Focused Review - Socket Library

Perform a comprehensive security analysis specifically tailored for the socket library that processes network data and potentially untrusted input. Focus on identifying vulnerabilities that could lead to exploitation, data corruption, or privilege escalation.

**Key Security References:**
- `include/core/SocketSecurity.h` - Centralized security limits and validation utilities
- `src/test/test_security.c` - Comprehensive security test suite (33 tests)
- `src/fuzz/` - Fuzzing harnesses (130+) for attack surface testing
- `.claude/references/security-limits.md` - Complete security limits table
- `.claude/references/security-patterns.md` - Established security patterns

## Security Review Process

1. **Static Analysis**: Scan for known unsafe function patterns, identify all input points, trace data flow from input to vulnerable operations
2. **Control Flow Analysis**: Trace all error paths for resource leaks, verify all input validation points, check all bounds checks
3. **Data Flow Analysis**: Track network-controlled data through the codebase, identify all uses of network input, verify sanitization at input boundaries
4. **Attack Surface Mapping**: Identify all external interfaces, map input sources to processing functions, identify potential injection points
5. **Protocol-Specific Analysis**: HTTP/1.1 smuggling, HPACK bombs, HTTP/2 flow control, TLS validation, WebSocket masking, QUIC packet protection, DNS spoofing/poisoning
6. **Concurrency Analysis**: Identify shared mutable state, check mutex acquisition order, verify callback safety
7. **Resource Exhaustion Analysis**: Identify unbounded allocations, check for maximum limits, verify timeouts

## Security Categories

### 1. Identify Unsafe String Functions

**Dangerous Functions to Flag**:
- **strcpy()** - No bounds checking, use `strncpy()` with explicit null termination
- **strcat()** - No bounds checking, use `strncat()` with size limits
- **sprintf()** - Vulnerable to buffer overflow, use `snprintf()` with size limits
- **gets()** - Always unsafe, never use
- **scanf() family** - Use with extreme caution, prefer `fgets()` + parsing
- **strtok()** - Not thread-safe, verify `strtok_r()` is used instead

**Safe Alternatives Analysis**:
- **strncpy()** - Verify proper null termination after all uses
- **snprintf()** - Verify size parameter matches buffer size (check return value)
- **strtok_r()** - Confirm thread-safe version is used consistently
- **fgets()** - Verify buffer size matches actual buffer allocation
- **Socket Library**: Verify `MODULE_ERROR_FMT`/`MODULE_ERROR_MSG` use `snprintf` correctly

### 2. Check Input Validation

**Network Input Validation**:
- Socket addresses: Invalid formats, length validation, port range (1-65535)
- DNS hostnames: Length limits, valid characters, DNS injection prevention
- Socket data: Buffer size limits, received data length validation

**Parser Input Validation**:
- Address parsing: Port validation, IP format, hostname before DNS
- Buffer operations: Size checks before writes, circular buffer bounds, overflow protection

**Function Parameter Validation**:
- NULL pointer checks before dereferencing (use `assert()` for programming errors)
- Validate integer parameters are within expected ranges
- Check array indices are within bounds
- Validate socket file descriptors (>= 0)

### 3. Review Integer Overflow Risks

**Canonical Overflow-Safe Functions (SocketSecurity.h)**:
See `.claude/references/security-limits.md` for complete documentation.

- **SocketSecurity_check_multiply(a, b, &result)** - Returns 1 if safe, 0 if overflow
- **SocketSecurity_check_add(a, b, &result)** - Returns 1 if safe, 0 if overflow
- **SocketSecurity_safe_multiply(a, b)** - Returns product or 0 on overflow
- **SocketSecurity_safe_add(a, b)** - Returns sum or SIZE_MAX on overflow
- **SocketSecurity_check_size(size)** - Validates against SOCKET_SECURITY_MAX_ALLOCATION

**Arithmetic Operations**:
- Addition: Buffer size calculations, use `SocketSecurity_check_add()`
- Multiplication: `sizeof(type) * count`, use `SocketSecurity_check_multiply()`
- Subtraction: Check for underflow in size calculations

**Type Conversion Risks**:
- Signed/Unsigned: Implicit conversions, port numbers vs size_t
- Width Mismatches: int vs size_t, potential truncation

### 4. Analyze Network I/O Security

**Socket Creation Security**:
- Address Family Validation: Only AF_INET, AF_INET6, AF_UNIX
- Socket Options: Verify correct settings, validate timeouts

**Socket Operations Security**:
- Bind/Listen: Port validation (1-65535), privileged ports (< 1024)
- Accept: Validate accepted socket, connection limits
- Connect: Hostname/DNS validation, DNS spoofing protection
- Send/Receive: Buffer size validation, partial I/O handling

**DNS Resolution Security**:
- Hostname Validation: Length limits, DNS injection attempts
- Resolution Timeout: Verify DNS doesn't hang indefinitely

**Buffer Management Security**:
- Circular Buffer Safety: Bounds checking, overflow protection
- Dynamic Buffer Growth: Overflow checks, maximum size limits

**UDP Socket Security (`SocketDgram`)**:
- Datagram Size Validation: `UDP_MAX_PAYLOAD` (65507) limit, `SAFE_UDP_SIZE` (1472)
- Connectionless Security: Source address validation, amplification attacks

**Unix Domain Socket Security**:
- Path Security: Absolute paths, stale socket file handling, path length limits
- Credential Passing: `SO_PEERCRED` usage, UID/GID validation
- File Permission Security: Socket file permissions, `umask` considerations

### 5. Check for Potential Injection Points

**DNS Injection**:
- Hostname Injection: Sanitize user-provided hostnames, validate format
- DNS Response Validation: Verify responses, check for spoofing

**Path Injection (Unix Domain Sockets)**:
- Socket Path Validation: Prevent path traversal (`../`, `//`, `~`), symlink attacks

**Format String Injection**:
- Error Message Formatting: Verify all format strings are literal, not user-controlled
- Flag any user input used as format string

**Buffer Injection**:
- Stack/Heap Buffer Overflows: Verify bounds checking before all writes, check for off-by-one errors

### 6. Thread Safety Security

**Race Conditions**:
- Shared Resource Access: Verify mutex protection, check for unprotected critical sections
- Arena Thread Safety: Per-arena mutex protection, thread-local error buffers

**Exception Safety**:
- Exception Thread Safety: Thread-local `Except_stack`, verify `SOCKET_RAISE_MODULE_ERROR` pattern
- **NEVER directly modify global exception `.reason` field** (race condition)

**Live Count Tracking**:
- Socket Leak Detection: Verify `SocketLiveCount_increment/decrement` are balanced
- Check `Socket_debug_live_count()` returns 0 after cleanup

### 7. TLS Security Analysis

**TLS Protocol Hardening**:
- Version Enforcement: TLS1.3-only, no fallback to legacy protocols
- Cipher Suite Security: Modern ciphers only, ECDHE key exchange (PFS), AES-GCM or ChaCha20-Poly1305

**Certificate Validation**:
- Certificate Verification: `TLS_VERIFY_PEER`, hostname verification, chain depth limits
- Revocation Checking: CRL support, OCSP stapling
- Custom Verification: Review `SocketTLSVerifyCallback` implementations

**SNI and ALPN Security**:
- SNI: Verify hostname length limits, check for injection
- ALPN: Verify protocol string length limits, check for injection

**Session Management Security**:
- Session Caching: Size limits, timeout configuration
- Session Tickets: Verify ticket key length (80 bytes), encryption key management, rotation

**TLS Handshake Security**:
- Handshake State Machine: Verify state transitions, timeout enforcement
- Non-Blocking Handshake: Handle `WANT_READ`/`WANT_WRITE`, prevent infinite loops

**TLS Disable Security (STARTTLS Reversal)**:
- **SocketTLS_disable() Security**: Verify TLS buffers securely cleared via `SocketCrypto_secure_clear()`
- Check SSL object properly freed, validate socket state reset
- Confirm ALPN temporary data cleaned up

**DTLS Security**:
- Cookie Verification: Use `SocketCrypto_hmac_sha256()`, constant-time verification
- Replay Protection: Anti-replay window, sequence number handling
- Fragmentation: Bounded reassembly, timeout enforcement

### 8. Rate Limiting and DoS Protection

**Token Bucket Rate Limiting (`SocketRateLimit`)**:
- Configuration Validation: Verify `tokens_per_sec` and `bucket_size` are reasonable
- Bypass Prevention: Check `SocketRateLimit_try_acquire()` cannot be bypassed
- Clock Manipulation: Verify `CLOCK_MONOTONIC` usage

**Per-IP Connection Tracking (`SocketIPTracker`)**:
- IP Address Validation: Safe IP parsing (IPv4 and IPv6)
- Limit Enforcement: Verify `max_per_ip` limits enforced
- Resource Exhaustion: Check hash table size limits, memory growth bounded

**Circuit Breaker Pattern (`SocketReconnect`)**:
- State Machine Security: Atomic state transitions, verify thresholds
- Backoff Security: Exponential backoff, jitter prevents synchronized retries

**Bandwidth Limiting**:
- Token Bucket for Bandwidth: Verify rate enforcement, overflow protection
- Bypass Prevention: Verify bandwidth limiting can't be bypassed

### 9. Secure Memory Handling

**Secure Memory Clearing**:
- Buffer Cleanup: Verify `SocketBuf_secureclear()` used for sensitive data
- Connection Pool Security: Verify buffers cleared on removal
- Compiler Optimization: Verify secure clear not optimized away

**Sensitive Data Identification**:
- TLS Keys and Certificates: Private keys cleared after use
- Authentication Data: Credentials cleared after authentication

### 10. Time-Based Security

**Monotonic Clock Usage**:
- Time Source Security: Verify `CLOCK_MONOTONIC` for security-critical timing
- Use `Socket_get_monotonic_ms()` for rate limiting, timeouts, elapsed time
- Time Manipulation Prevention: Timeouts can't be bypassed by clock changes

**Timer Security (`SocketTimer`)**:
- Timer Management: Min-heap handles edge cases
- Timer Overflow: Check for integer overflow, verify timer IDs don't wrap unsafely

**Timeout Security**:
- DNS Resolution Timeouts: Verify timeouts enforced
- Connection Timeouts: Verify blocking operations have timeouts
- TLS Handshake Timeouts: Verify timeout enforcement, slow-loris protection

### 11. Async DNS Security

**Thread Pool Security**:
- Worker Thread Safety: Verify error handling, resource leaks
- Queue Security: Verify request queue bounds, overflow handling

**DNS Result Handling**:
- Result Ownership: Verify `freeaddrinfo()` called
- Result Validation: Check returned addresses are valid

**Signal Pipe Security**:
- Pipe Handling: Verify pipe created safely, signal bytes consumed

### 12. Happy Eyeballs (RFC 8305) Security

**State Machine Security**:
- State Transitions: Verify correct transitions, safe cancellation handling
- Concurrent Connection Racing: Verify no socket leaks, losing connections closed

**Timeout Security**:
- Connection Attempt Delays: Verify first attempt delay (250ms), timeouts enforced

**Resource Management**:
- Address Cleanup: Verify `freeaddrinfo()` called
- Socket Cleanup: Verify all attempted sockets closed except winner

### 13. HTTP/1.1 Parser Security (RFC 9112) - CRITICAL

**Request Smuggling Prevention (RFC 9112 Section 6.3)**:
- **Content-Length/Transfer-Encoding Conflict**: Verify parser REJECTS messages with BOTH
- **Multiple Content-Length Headers**: Verify parser REJECTS multiple with differing values
- **Transfer-Encoding Validation**: Verify only "chunked" accepted

**Header Injection Prevention**:
- Header Name Validation: Only valid token characters, no CRLF injection
- Header Value Validation: No bare CR or LF, validate obs-fold handling
- Request Line Validation: Verify HTTP method, request-target, version strictly validated

**Chunked Transfer Encoding Security**:
- Chunk Size Parsing: Verify maximum limit enforced, integer overflow checks
- Chunk Extension Security: Verify extensions bounded in length
- Trailer Security: Verify trailer headers validated, size limits, forbidden headers rejected

**Parser Limits and DoS Prevention**:
See `.claude/references/security-limits.md` for configurable limits.

**Parser State Machine Security**:
- State Transitions: Verify correct transitions, error states properly terminate
- Incremental Parsing: Verify handles partial data safely, no buffer overread

### 14. HPACK Security (RFC 7541)

**HPACK Bomb Prevention**:
- Dynamic Table Size Limits: Verify `max_table_size` enforced
- Header Size Limits: Verify limits checked BEFORE allocation
- Decompression Ratio Attacks: Check for excessive expansion

**Integer Coding Security**:
- Variable-Length Integer Overflow: Verify overflow checks, continuation byte count bounded

**Huffman Coding Security**:
- Huffman Decoding Attacks: Verify output bounded, padding validated

**Index Reference Security**:
- Static Table Bounds: Verify indices 1-61 enforced
- Dynamic Table Bounds: Verify indices within current table size

### 15. HTTP/2 Security (RFC 9113)

**Flow Control Attacks**:
- Window Exhaustion DoS: Verify server can't be starved
- Window Overflow Prevention: Verify 2^31-1 overflow checks
- Zero Window Attacks: Check for infinite wait, timeout handling

**Stream Multiplexing Attacks**:
- MAX_CONCURRENT_STREAMS Enforcement: Verify limit enforced
- Stream ID Validation: Verify odd for client, even for server, strictly increasing
- **Rapid Reset Attack (CVE-2023-44487)**: Verify RST_STREAM flood protection

**SETTINGS Attacks**:
- SETTINGS Flood Prevention: Verify rate limiting
- Malicious SETTINGS Values: Verify bounds checked

**Frame Layer Security**:
- Frame Size Validation: Verify length checks, padding validation
- CONTINUATION Attack Prevention: Verify bounded CONTINUATION count
- PING Flood Prevention: Verify PING rate limited
- GOAWAY Handling: Verify last_stream_id respected

**Server Push Security**:
- PUSH_PROMISE Validation: Verify `SETTINGS_ENABLE_PUSH` checked
- Push Exhaustion: Verify doesn't exhaust MAX_CONCURRENT_STREAMS

**h2c Upgrade Security**:
- Cleartext Upgrade Validation: Verify well-formed upgrade request
- Downgrade Prevention: Verify ALPN negotiation for h2 over TLS

### 16. Cryptographic Security (`SocketCrypto`)

**Constant-Time Operations**:
- Timing Attack Prevention: Verify `SocketCrypto_secure_compare()` is constant-time
- Usage Verification: Verify all auth checks use `secure_compare()`

**Secure Random Generation**:
- CSPRNG Security: Verify `SocketCrypto_random_bytes()` uses OpenSSL `RAND_bytes()`
- Random Usage: Verify session tokens, nonces use cryptographic random

**Secure Memory Clearing**:
- Compiler Optimization Prevention: Verify `SocketCrypto_secure_clear()` won't be optimized away
- Clearing Coverage: Verify private keys, session keys, intermediate values cleared

**Hash Function Security**:
- Algorithm Selection: Verify SHA-256 for security-critical hashing
- HMAC Security: Verify proper key lengths, constant-time verification

**WebSocket Security (RFC 6455)**:
- Handshake Key Validation: Verify accept computation correct
- Key Generation: Verify CSPRNG used for 16-byte key

### 17. WebSocket Security (RFC 6455) - `SocketWS`

**Frame Masking Security (RFC 6455 Section 5.3)**:
- Client-to-Server Masking: Verify ALL client frames masked, `SocketCrypto_random_bytes()` used
- Server-to-Client Masking: Verify server frames NOT masked
- Masking Implementation: Verify 8-byte aligned XOR, mask key never reused

**Frame Validation Security**:
- Opcode Validation: Verify only valid opcodes accepted
- Control Frame Limits: Verify <= 125 bytes, not fragmented
- Reserved Bits (RSV1-3): Verify RSV bits are 0 unless extension negotiated

**Fragmentation Security**:
- Fragment Reassembly Limits: Verify `max_fragments` and `max_message_size` enforced
- Fragment Ordering: Verify continuation frames follow initial fragment
- Resource Exhaustion: Check for DoS via many small fragments

**Close Handshake Security**:
- Close Code Validation: Verify valid close codes
- Close Handshake Completion: Verify timeout on completion
- Abnormal Closure: Check 1006 never sent over wire

**UTF-8 Validation Security**:
- Text Frame Validation: Verify ALL text frames validated for UTF-8
- Fragmented Text Validation: Verify validation spans fragments
- Close Reason Validation: Verify close reason validated for UTF-8

**Handshake Security**:
- Client Handshake: Verify `Sec-WebSocket-Key` is 16 random bytes, constant-time accept validation
- Server Handshake: Verify key validated, accept computed correctly
- Subprotocol Negotiation: Verify only offered subprotocols selected

**permessage-deflate Security (RFC 7692)**:
- Compression Bomb Prevention: Verify decompressed size bounded
- Context Takeover: Verify setting respected
- Window Bits Validation: Verify negotiation (8-15)

**DoS Protection**:
- Frame Size Limits: Verify `max_frame_size` validated BEFORE allocation
- Message Size Limits: Verify `max_message_size` tracked during fragmentation
- PING Flood Prevention: Verify PING rate limited

### 18. UTF-8 Validation Security (`SocketUTF8`)

**Overlong Encoding Attacks**:
- Overlong Sequence Detection: Verify `UTF8_OVERLONG` returned
- Security Impact: Overlong encodings can bypass security filters, verify input rejected

**Surrogate Pair Validation**:
- Surrogate Detection: Verify `UTF8_SURROGATE` for U+D800-U+DFFF
- Security Impact: Surrogates in UTF-8 indicate encoding confusion attacks

**Invalid Code Point Rejection**:
- Code Point Bounds: Verify `UTF8_TOO_LARGE` for > U+10FFFF
- DFA Completeness: Verify DFA handles all invalid byte sequences

**Incremental Validation Security**:
- Streaming Validation: Verify `SocketUTF8_update()` handles split sequences
- State Reset: Verify no state leakage between validations

### 19. SYN Flood Protection (`SocketSYNProtect`)

**Implemented Mitigations**:
- CIDR Validation: `parse_cidr_notation` uses `strtol` with endptr validation
- Whitelist Efficiency: Single IP parse per check, byte-based matching
- Arena Safety: Eviction disabled in arena mode, hard cap at `max_tracked_ips`
- Metrics: Active-only counts for blocked IPs
- Hash Randomization: `hash_seed` in config, mixed into DJB2

**Connection Attempt Tracking**:
- IP-Based Tracking: Per-IP counting, reputation, LRU
- Attempt Rate Limiting: Rate-limited per IP, burst handling

**Reputation Scoring**:
- Score Calculation: Range 0.0-1.0, decay over time
- Score-Based Actions: ALLOW, THROTTLE, CHALLENGE, BLOCK

**Kernel Integration**:
- TCP_DEFER_ACCEPT (Linux), SO_ACCEPTFILTER (BSD), SYN Cookies

### 20. Connection Pool Security (`SocketPool`)

**Connection Slot Exhaustion**:
- Pool Capacity: Verify maximum connection limit
- Idle Connection Cleanup: Verify timeout enforced

**Buffer Security**:
- Buffer Reuse: Verify `SocketBuf_secureclear()` called before reuse
- Per-Connection Buffer Limits: Verify bounded

**Graceful Shutdown Security**:
- Drain State Machine: Verify correct transitions, timeout enforced
- Force Close: Verify no connection leaks
- **Callback Safety**: `SocketPool_free()` IS safe from drain callback

**Thread Safety**:
- Mutex Protection: Verify all pool operations mutex-protected

### 21. State Machine Security

**State Transition Security**:
- Valid Transition Enforcement: Verify only valid transitions allowed
- Atomic Transitions: Verify thread-safe where needed, check for TOCTOU

**Terminal State Handling**:
- Resource Cleanup: Verify resources freed on terminal states
- Post-Terminal Access: Verify operations on terminated state rejected

**Modules with State Machines**:
- SocketHappyEyeballs, SocketReconnect, SocketTLS, SocketSYNProtect, SocketPool, SocketHTTP1_Parser, SocketHTTP2, SocketProxy, SocketWS
- SocketQUICConnection, SocketQUICStream, SocketQUICHandshake, SocketQUICMigration
- SocketDNSResolver, SocketDNSTransport

### 22. Callback Security

**Re-Entrancy Attacks**:
- Callback-During-Callback: Verify no re-entrant calls, check for stack overflow
- Module Destruction from Callback: **NEVER** call `Module_free()` from callback (EXCEPTION: `SocketPool_free()` IS safe from drain callback)

**Callback Thread Safety**:
- Execution Context: Callbacks execute in thread calling `process()` or `SocketPoll_wait()`
- Mutex Holding: Verify mutexes NOT held during callbacks (deadlock risk)

**Callback Registration Security**:
- Function Pointer Validation: Verify NULL handled
- Userdata Lifetime: Verify pointer remains valid

### 23. Hash Table Security

**Hash Collision DoS**:
- DJB2 Hash Security: Vulnerable to algorithmic complexity attacks
- Mitigation Strategies: Hash randomization, maximum chain length limits

**Hash Table Limit Enforcement**:
- Size Limits: Verify maximum size limits, memory exhaustion checks
- Entry Cleanup: Verify stale entries removed

**Case-Insensitive Hashing**:
- HTTP Header Hashing: Verify `socket_util_hash_djb2_ci()` correctly case-insensitive

### 24. Compression Security (If ENABLE_HTTP_COMPRESSION)

**Decompression Bomb Prevention**:
- Expansion Ratio Limits: Verify decompressed size bounded
- Memory Allocation: Verify bounded, check for overflow

**BREACH-Style Attacks**:
- Compression Oracle: Document that BREACH mitigation is application responsibility
- Mitigation Documentation: Add random padding, separate secrets

**Supported Algorithms**:
- gzip/deflate (zlib), Brotli (libbrotli)

### 25. QUIC Security (RFC 9000, 9001, 9002)

**Packet Protection Security**:
- Initial Packet Protection: Verify salt and key derivation correct (RFC 9001 §5.2)
- Header Protection: Verify sample extraction and mask application
- Key Update Security: Verify old keys cleared, timing attack prevention

**Variable-Length Integer Security**:
- Integer Overflow Prevention: Verify `SocketQUICVarInt` bounds checks
- Maximum Value Enforcement: Verify 2^62-1 limit enforced
- Continuation Byte Limits: Verify maximum 8 bytes for encoding

**Connection ID Security**:
- CID Collision Prevention: Verify random generation, uniqueness checks
- CID Pool Exhaustion: Verify pool size limits, NEW_CONNECTION_ID rate limiting
- Retire Prior To: Verify sequence number handling, no double-retire

**Stream Security**:
- Stream ID Validation: Verify odd/even rules for client/server
- Stream Limit Enforcement: Verify MAX_STREAMS respected
- FIN Handling: Verify data offset doesn't exceed final size

**Flow Control Security**:
- Window Overflow Prevention: Verify 2^62-1 limits enforced
- Blocked Stream Handling: Verify BLOCKED frames rate-limited
- Initial Window Validation: Verify transport parameter bounds

**Handshake Security**:
- Retry Token Validation: Verify AEAD integrity check
- Address Validation: Verify token-based validation for 0-RTT
- Version Downgrade Prevention: Verify version negotiation integrity

**Loss Detection Security (RFC 9002)**:
- ACK Delay Manipulation: Verify max_ack_delay enforced
- Spurious Retransmission: Verify PTO calculation correct
- Amplification Attack Prevention: Verify 3x limit before address validation

**Migration Security**:
- Path Challenge/Response: Verify `SocketCrypto_random_bytes()` for challenges
- Connection Migration Validation: Verify path validation before use
- NAT Rebinding: Verify proper handling of address changes

**Error Handling Security**:
- Error Code Validation: Verify valid error codes (0-0x1ff for QUIC)
- CONNECTION_CLOSE Handling: Verify reason phrase length limits
- Immediate Close: Verify draining period respected

### 26. DNS Security (RFC 1035, 4033-4035, 7858, 8484)

**DNS Wire Format Security**:
- Name Compression Security: Verify pointer loop detection
- Label Length Validation: Verify 63-byte label limit, 255-byte name limit
- EDNS0 Buffer Size: Verify advertised size reasonable

**DNS Cache Poisoning Prevention**:
- Transaction ID Randomization: Verify `SocketCrypto_random_bytes()` for TXID
- Source Port Randomization: Verify random ephemeral ports
- QNAME Validation: Verify response matches query

**DNSSEC Validation Security (RFC 4033-4035)**:
- Chain of Trust: Verify trust anchor validation, DS/DNSKEY chaining
- Signature Verification: Verify RRSIG algorithm support, expiration checks
- NSEC/NSEC3 Security: Verify denial of existence proofs
- Algorithm Support: Verify RSA, ECDSA, Ed25519 support

**DNS-over-TLS Security (RFC 7858)**:
- Certificate Validation: Verify TLS certificate checks
- Opportunistic vs Strict Mode: Verify mode enforcement (RFC 8310)
- Connection Pooling: Verify idle timeout, connection limits

**DNS-over-HTTPS Security (RFC 8484)**:
- HTTPS Validation: Verify TLS/certificate requirements
- Content-Type Validation: Verify `application/dns-message`
- POST vs GET Security: Verify method handling
- HTTP/2 Multiplexing: Verify stream limits respected

**DNS Cookies Security (RFC 7873)**:
- Client Cookie Generation: Verify random 8-byte cookies
- Server Cookie Validation: Verify HMAC verification
- Cookie Freshness: Verify timestamp validation

**Negative Caching Security (RFC 2308)**:
- NXDOMAIN Caching: Verify SOA minimum TTL handling
- NODATA Caching: Verify correct key tuple (QNAME, QTYPE, QCLASS)
- Aggressive Negative Caching: Verify NSEC/NSEC3 range validation

**Extended DNS Errors Security (RFC 8914)**:
- Error Code Validation: Verify valid EDE codes (0-24)
- Extra Text Handling: Verify length limits on EXTRA-TEXT

**Dead Server Tracking (RFC 2308 §7.2)**:
- Blacklist Duration: Verify 5-minute default timeout
- Recovery Detection: Verify successful query clears blacklist

**Resolver DoS Prevention**:
- Query Rate Limiting: Verify queries-per-second limits
- Outstanding Query Limits: Verify maximum pending queries
- Response Size Limits: Verify maximum DNS message size

### 27. Centralized Security Configuration (SocketSecurity.h)

See `.claude/references/security-limits.md` for complete security limits table.

**Runtime Limit Query**:
```c
SocketSecurityLimits limits;
SocketSecurity_get_limits(&limits);
```

**Security Test Suite**:
Run: `ctest -R test_security` for comprehensive security tests (33 tests).

## Security Review Output Format

For each security issue found, provide:

1. **Severity**: Critical / High / Medium / Low
2. **Vulnerability Type**: Buffer Overflow / Integer Overflow / Injection / Request Smuggling / DoS / etc.
3. **Location**: File name and line number(s)
4. **Issue**: Clear description of the security vulnerability
5. **Attack Vector**: How an attacker could exploit this
6. **Impact**: What could happen if exploited
7. **Recommendation**: Specific fix with secure code example
8. **Reference**: Link to secure pattern in `.claude/references/security-patterns.md` or RFC/CVE

## Priority Focus Areas

1. **Critical**:
   - Buffer overflows, HTTP request smuggling, TLS configuration errors, Injection vulnerabilities
   - Integer overflows in network operations, HPACK bombs, HTTP/2 flow control attacks
   - Rapid reset attacks (CVE-2023-44487), WebSocket masking violations, Compression bombs
   - QUIC packet protection failures, QUIC amplification attacks, DNS cache poisoning

2. **High**:
   - Input validation gaps, DNS security issues, Thread safety / race conditions
   - Rate limiting bypass, Timing attacks, State machine manipulation, Callback re-entrancy
   - QUIC connection ID exhaustion, DNSSEC validation bypass, DoT/DoH downgrade attacks

3. **Medium**:
   - Resource leaks, Unsafe string functions, Missing bounds checks
   - Secure memory clearing, Hash collision DoS, UTF-8 validation bypasses
   - QUIC flow control manipulation, DNS negative cache poisoning

4. **Low**:
   - Style issues, Minor validation improvements, Defensive programming

## Security Verification Commands

```bash
# Run security-specific tests
ctest -R test_security --output-on-failure

# Run full test suite with sanitizers
cmake -B build -DENABLE_SANITIZERS=ON
cmake --build build
cd build && ctest --output-on-failure

# Run fuzzing (requires Clang)
cmake -B build -DENABLE_FUZZING=ON -DCMAKE_C_COMPILER=clang
cmake --build build
./scripts/run_fuzz_parallel.sh

# Valgrind memory checking
valgrind --leak-check=full --track-fds=yes ./build/test_security
```

Provide a prioritized security assessment with exploitability analysis for each vulnerability found, focusing on network-specific attack vectors and socket library usage patterns.
